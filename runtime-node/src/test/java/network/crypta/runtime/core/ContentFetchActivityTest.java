package network.crypta.runtime.core;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class ContentFetchActivityTest {
  @Test
  void tracksConcurrentCallsAndReleasesBothCompletionKinds() {
    ContentFetchActivity activity = new ContentFetchActivity();
    long first = activity.enter();
    long second = activity.enter();
    assertEquals(2, activity.snapshot().inFlightOperations());
    activity.exit(first, true);
    activity.exit(second, false);
    var result = activity.snapshot();
    assertEquals(0, result.inFlightOperations());
    assertEquals(2, result.startedOperations());
    assertEquals(1, result.successfulOperations());
    assertEquals(1, result.failedOperations());
    assertEquals(4, result.sequence());
    assertEquals(0, result.oldestActiveAgeMillis());
    assertFalse(result.truncated());
  }

  @Test
  void trackingOverflowRemainsExplicitAfterAllCallsExit() {
    ContentFetchActivity activity = new ContentFetchActivity();
    for (int index = 0; index < 1025; index++) activity.enter();
    assertTrue(activity.snapshot().truncated());
    for (long token = 1; token <= 1025; token++) activity.exit(token, false);
    assertEquals(0, activity.snapshot().inFlightOperations());
    assertTrue(activity.snapshot().truncated());
  }
}
