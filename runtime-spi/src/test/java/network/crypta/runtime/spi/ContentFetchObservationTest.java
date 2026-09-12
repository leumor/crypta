package network.crypta.runtime.spi;

import java.util.Map;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class ContentFetchObservationTest {
  @Test
  void legacyFetchPortExplicitlyReportsUnsupportedObservation() {
    ContentFetchPort port = _ -> null;
    assertFalse(port.observation().known());
  }

  @Test
  void rejectsIllegalCountsAndInconsistentLifecycleTotals() {
    assertThrows(
        IllegalArgumentException.class,
        () -> new ContentFetchObservation(true, "epoch", 1, 1, -1, 0, 0, 0, 0, false));
    assertThrows(
        IllegalArgumentException.class,
        () -> new ContentFetchObservation(true, "epoch", 1, 1, 1, 0, 0, 0, 0, false));
  }

  @Test
  void fixedManagementReadsHaveNumericMetricsWithoutRawRuntimeInventory() {
    Map<String, Object> snapshot = JvmResourceObservation.capture();
    assertEquals("fixed-management-beans-v1", snapshot.get("collector"));
    Map<?, ?> metrics = (Map<?, ?>) snapshot.get("metrics");
    assertEquals(9, metrics.size());
    for (Object value : metrics.values()) {
      assertTrue(value == null || value instanceof Number);
      if (value instanceof Number number) assertTrue(number.longValue() >= 0);
    }
    assertTrue(
        ((Number) metrics.get("heapCommittedBytes")).longValue()
            >= ((Number) metrics.get("heapUsedBytes")).longValue());
    assertFalse(snapshot.containsKey("commandLine"));
  }
}
