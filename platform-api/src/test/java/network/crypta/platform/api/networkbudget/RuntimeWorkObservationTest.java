package network.crypta.platform.api.networkbudget;

import java.util.ArrayList;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RuntimeWorkObservationTest {
  @Test
  void externallyConstructedSnapshotCannotBeChangedThroughItsSourceList() {
    var observation = new RuntimeWorkObservation();
    observation.recordEvent(RuntimeWorkObservation.Kind.TICK_ENTERED);
    var events = new ArrayList<>(observation.snapshot().events());
    var snapshot = new RuntimeWorkObservation.Snapshot(1, 1, 0, events);

    events.clear();

    var snapshotEvents = snapshot.events();
    assertEquals(1, snapshotEvents.size());
    assertThrows(UnsupportedOperationException.class, snapshotEvents::clear);
  }

  @Test
  void scopeExhaustionMakesHistoryIncompleteWithoutPublishingIdentifiers() {
    var observation = new RuntimeWorkObservation();
    assertEquals(1, observation.scope(AppNetworkBudgetScope.GLOBAL));
    for (int index = 0; index < 1024; index++) {
      assertEquals(index + 2, observation.scope("app-" + index));
    }

    assertEquals(0, observation.scope("overflow-app"));
    assertEquals(Long.MAX_VALUE, observation.snapshot().dropped());
    assertEquals(2, observation.scope("app-0"));
  }

  @Test
  void snapshotReportsDroppedHistoryAndPreservesDetachedSequence() {
    var observation = new RuntimeWorkObservation();
    observation.recordEvent(RuntimeWorkObservation.Kind.TICK_ENTERED);
    var detached = observation.snapshot();

    for (int index = 0; index < RuntimeWorkObservation.CAPACITY; index++) {
      observation.recordEvent(RuntimeWorkObservation.Kind.TICK_COMPLETED);
    }
    var snapshot = observation.snapshot();

    assertEquals(1, detached.events().size());
    assertEquals(1, detached.lastSequence());
    assertEquals(RuntimeWorkObservation.CAPACITY, snapshot.events().size());
    assertEquals(1, snapshot.dropped());
    assertEquals(2, snapshot.events().getFirst().sequence());
    assertTrue(
        snapshot.events().getLast().elapsedNanos() >= snapshot.events().getFirst().elapsedNanos());
  }
}
