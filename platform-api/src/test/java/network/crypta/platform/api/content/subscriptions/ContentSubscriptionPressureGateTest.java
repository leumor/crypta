package network.crypta.platform.api.content.subscriptions;

import network.crypta.runtime.spi.ContentFetchObservation;
import network.crypta.runtime.spi.ContentFetchPort;
import network.crypta.runtime.spi.QueuePersistenceStatusSnapshot;
import network.crypta.runtime.spi.QueueSupportPort;
import network.crypta.runtime.spi.RequestQueuePort;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
class ContentSubscriptionPressureGateTest {
  @Test
  void legacyAssessmentConstructor_whenAllowed_expectUnknownWithoutContention() {
    var assessment = new ContentSubscriptionPressureGate.PressureAssessment(true, null, null, null);

    assertTrue(assessment.allowed());
    assertFalse(assessment.known());
    assertFalse(assessment.contention());
    assertNull(assessment.status());
    assertNull(assessment.errorCode());
    assertNull(assessment.message());
  }

  @Test
  void legacyAssessmentConstructor_whenBlocked_expectKnownAvailabilityDenial() {
    var assessment =
        new ContentSubscriptionPressureGate.PressureAssessment(
            false, ContentSubscriptionStatus.QUEUE_PRESSURE, "queue_pressure", "Unavailable");

    assertFalse(assessment.allowed());
    assertTrue(assessment.known());
    assertFalse(assessment.contention());
    assertEquals(ContentSubscriptionStatus.QUEUE_PRESSURE, assessment.status());
    assertEquals("queue_pressure", assessment.errorCode());
    assertEquals("Unavailable", assessment.message());
  }

  @Test
  void assess_whenOwnerCrossesHighAndLowWater_expectContentionHysteresis() {
    ContentFetchPort owner = mock(ContentFetchPort.class);
    when(owner.observation()).thenReturn(sample(3), sample(2), sample(1));
    ContentSubscriptionPressureGate gate =
        new ContentSubscriptionPressureGate(null, null, owner, 3, 1);

    var high = gate.assess();
    var middle = gate.assess();
    var low = gate.assess();

    assertFalse(high.allowed());
    assertTrue(high.known());
    assertTrue(high.contention());
    assertEquals("content_fetch_contention", high.errorCode());
    assertFalse(middle.allowed());
    assertTrue(low.allowed());
    assertFalse(
        low.known(), "Absent availability ports remain unknown even after contention clears");
  }

  @Test
  void assess_whenOwnerUnavailableOrThrows_expectAllowedButUnknown() {
    ContentFetchPort owner = mock(ContentFetchPort.class);
    when(owner.observation())
        .thenReturn(ContentFetchObservation.unavailable())
        .thenThrow(new IllegalStateException("private failure"));
    ContentSubscriptionPressureGate gate =
        new ContentSubscriptionPressureGate(null, null, owner, 1, 0);

    var missing = gate.assess();
    var failed = gate.assess();

    assertTrue(missing.allowed());
    assertFalse(missing.known());
    assertTrue(failed.allowed());
    assertFalse(failed.known());
  }

  @Test
  void assess_whenPolicyDisabled_expectLegacyAdmissionDespiteOwnerContention() {
    ContentFetchPort owner = mock(ContentFetchPort.class);
    when(owner.observation()).thenReturn(sample(100));
    ContentSubscriptionPressureGate gate =
        new ContentSubscriptionPressureGate(null, null, owner, 0, 0);

    var result = gate.assess();

    assertTrue(result.allowed());
    assertFalse(result.known());
  }

  private static ContentFetchObservation sample(long active) {
    return new ContentFetchObservation(
        true, "test-epoch", 1, System.currentTimeMillis(), active, 10, active, 0, 0, false);
  }

  @Test
  void assess_whenNoPressurePortsArePresent_expectAllowed() {
    ContentSubscriptionPressureGate gate = new ContentSubscriptionPressureGate(null, null);

    ContentSubscriptionPressureGate.PressureAssessment assessment = gate.assess();

    assertTrue(assessment.allowed());
    assertFalse(assessment.known());
    assertNull(assessment.status());
    assertNull(assessment.errorCode());
  }

  @Test
  void assess_whenQueueBackendDisabled_expectRuntimeUnavailable() {
    QueueSupportPort queueSupportPort = mock(QueueSupportPort.class);
    when(queueSupportPort.isQueueBackendEnabled()).thenReturn(false);
    ContentSubscriptionPressureGate gate =
        new ContentSubscriptionPressureGate(queueSupportPort, null);

    ContentSubscriptionPressureGate.PressureAssessment assessment = gate.assess();

    assertFalse(assessment.allowed());
    assertEquals(ContentSubscriptionStatus.RUNTIME_UNAVAILABLE, assessment.status());
    assertEquals("runtime_unavailable", assessment.errorCode());
  }

  @Test
  void assess_whenQueuePersistenceIsAwaitingPassword_expectQueuePressure() {
    QueueSupportPort queueSupportPort = mock(QueueSupportPort.class);
    when(queueSupportPort.isQueueBackendEnabled()).thenReturn(true);
    when(queueSupportPort.persistenceStatus())
        .thenReturn(new QueuePersistenceStatusSnapshot(true, false, null, null));
    ContentSubscriptionPressureGate gate =
        new ContentSubscriptionPressureGate(queueSupportPort, null);

    ContentSubscriptionPressureGate.PressureAssessment assessment = gate.assess();

    assertFalse(assessment.allowed());
    assertEquals(ContentSubscriptionStatus.QUEUE_PRESSURE, assessment.status());
    assertEquals("queue_pressure", assessment.errorCode());
  }

  @Test
  void assess_whenQueuePersistenceIsStopping_expectQueuePressure() {
    QueueSupportPort queueSupportPort = mock(QueueSupportPort.class);
    when(queueSupportPort.isQueueBackendEnabled()).thenReturn(true);
    when(queueSupportPort.persistenceStatus())
        .thenReturn(new QueuePersistenceStatusSnapshot(false, true, null, null));
    ContentSubscriptionPressureGate gate =
        new ContentSubscriptionPressureGate(queueSupportPort, null);

    ContentSubscriptionPressureGate.PressureAssessment assessment = gate.assess();

    assertFalse(assessment.allowed());
    assertEquals(ContentSubscriptionStatus.QUEUE_PRESSURE, assessment.status());
    assertEquals("queue_pressure", assessment.errorCode());
  }

  @Test
  void assess_whenQueuePersistenceDatabaseIsKilled_expectQueuePressure() {
    QueueSupportPort queueSupportPort = mock(QueueSupportPort.class);
    when(queueSupportPort.isQueueBackendEnabled()).thenReturn(true);
    when(queueSupportPort.persistenceStatus())
        .thenReturn(new QueuePersistenceStatusSnapshot(false, false, null, null));
    RequestQueuePort requestQueuePort = mock(RequestQueuePort.class);
    when(requestQueuePort.isPersistenceDatabaseKilled()).thenReturn(true);
    ContentSubscriptionPressureGate gate =
        new ContentSubscriptionPressureGate(queueSupportPort, requestQueuePort);

    ContentSubscriptionPressureGate.PressureAssessment assessment = gate.assess();

    assertFalse(assessment.allowed());
    assertEquals(ContentSubscriptionStatus.QUEUE_PRESSURE, assessment.status());
    assertEquals("queue_pressure", assessment.errorCode());
  }

  @Test
  void assess_whenPressurePortsThrow_expectAllowedWithConservativeTickLimits() {
    QueueSupportPort queueSupportPort = mock(QueueSupportPort.class);
    when(queueSupportPort.isQueueBackendEnabled()).thenThrow(new IllegalStateException("boom"));
    RequestQueuePort requestQueuePort = mock(RequestQueuePort.class);
    when(requestQueuePort.isPersistenceDatabaseKilled())
        .thenThrow(new IllegalStateException("boom"));
    ContentSubscriptionPressureGate gate =
        new ContentSubscriptionPressureGate(queueSupportPort, requestQueuePort);

    ContentSubscriptionPressureGate.PressureAssessment assessment = gate.assess();

    assertTrue(assessment.allowed());
    assertFalse(assessment.known());
    assertNull(assessment.status());
    assertNull(assessment.errorCode());
  }
}
