package network.crypta.platform.api.content.subscriptions;

import network.crypta.platform.api.networkbudget.RuntimeWorkObservation;
import network.crypta.runtime.spi.ContentFetchObservation;
import network.crypta.runtime.spi.ContentFetchPort;
import network.crypta.runtime.spi.QueuePersistenceStatusSnapshot;
import network.crypta.runtime.spi.QueueSupportPort;
import network.crypta.runtime.spi.RequestQueuePort;

/**
 * Conservative runtime-pressure gate for content subscription polls.
 *
 * <p>The gate uses only stable SPI signals. It does not parse queue HTML and does not expose queue
 * contents in summaries or evidence. Unknown pressure is treated as acceptable because the
 * scheduler's per-tick limits already bound network work. Clear shutdown or unavailable signals are
 * converted into safe subscription statuses so due records back off instead of retrying in a tight
 * loop.
 *
 * <p>The legacy availability policy is stateless; optional contention admission retains hysteresis.
 * A scheduler tick may create one assessment and apply it to several due subscriptions, but each
 * assessment samples current queue availability and, when explicitly enabled, bounded fetch
 * activity. If a port throws while being probed, the gate allows the tick to continue under the
 * scheduler's configured limits rather than treating an unknown signal as a permanent outage.
 */
public final class ContentSubscriptionPressureGate {
  private final ContentFetchPort contentFetchPort;
  private final Configuration configuration;
  private final Object assessmentLock = new Object();
  private boolean congested;
  private RuntimeWorkObservation observation;

  void setObservation(RuntimeWorkObservation observation) {
    this.observation = observation;
  }

  private final QueueSupportPort queueSupportPort;
  private final RequestQueuePort requestQueuePort;

  /**
   * Creates a pressure gate from optional queue SPI dependencies.
   *
   * <p>Both ports are optional because not every runtime embedding exposes the same queue-pressure
   * signals. A {@code null} port means that signal is unknown, not that the scheduler should be
   * disabled.
   *
   * @param queueSupportPort optional queue support port for backend and persistence state
   * @param requestQueuePort optional request queue port for database-killed state
   */
  public ContentSubscriptionPressureGate(
      QueueSupportPort queueSupportPort, RequestQueuePort requestQueuePort) {
    this(queueSupportPort, requestQueuePort, null, 0, 0);
  }

  /**
   * Creates an explicitly configured bounded-content-fetch contention gate.
   *
   * <p>A zero threshold preserves legacy availability-only admission. A positive threshold blocks
   * when actual executing content-fetch calls reach the threshold, then resumes at or below the
   * low-water count. This is port-call contention, not native queue backlog or OS resource
   * pressure. Unknown, malformed or throwing observations preserve bounded legacy admission and
   * remain unknown.
   *
   * @param queueSupportPort optional availability port
   * @param requestQueuePort optional persistence port
   * @param contentFetchPort actual bounded fetch owner
   * @param maximumInFlight high-water executing-call threshold, zero disables this policy
   * @param resumeAtOrBelow low-water executing-call threshold
   */
  public ContentSubscriptionPressureGate(
      QueueSupportPort queueSupportPort,
      RequestQueuePort requestQueuePort,
      ContentFetchPort contentFetchPort,
      int maximumInFlight,
      int resumeAtOrBelow) {
    if (maximumInFlight < 0
        || maximumInFlight > 1024
        || resumeAtOrBelow < 0
        || (maximumInFlight > 0 && resumeAtOrBelow >= maximumInFlight)) {
      throw new IllegalArgumentException("Invalid bounded content fetch pressure thresholds");
    }
    this.queueSupportPort = queueSupportPort;
    this.requestQueuePort = requestQueuePort;
    this.contentFetchPort = contentFetchPort;
    this.configuration = new Configuration(maximumInFlight, resumeAtOrBelow);
  }

  /**
   * Loads opt-in local operator contention thresholds; malformed settings disable the policy.
   *
   * @param queueSupportPort actual queue availability port
   * @param requestQueuePort actual persistence port
   * @param contentFetchPort actual bounded fetch owner
   * @return configured gate, with legacy behavior by default
   */
  public static ContentSubscriptionPressureGate fromSystem(
      QueueSupportPort queueSupportPort,
      RequestQueuePort requestQueuePort,
      ContentFetchPort contentFetchPort) {
    int high = setting("CRYPTAD_CONTENT_SUBSCRIPTIONS_PRESSURE_MAX_IN_FLIGHT");
    int low = setting("CRYPTAD_CONTENT_SUBSCRIPTIONS_PRESSURE_RESUME_AT_OR_BELOW");
    if (high < 0 || high > 1024 || low < 0 || (high > 0 && low >= high)) {
      high = 0;
      low = 0;
    }
    return new ContentSubscriptionPressureGate(
        queueSupportPort, requestQueuePort, contentFetchPort, high, low);
  }

  private static int setting(String name) {
    try {
      String value = System.getenv(name);
      return value == null ? 0 : Integer.parseInt(value);
    } catch (NumberFormatException _) {
      return 0;
    }
  }

  /**
   * Returns effective policy thresholds in executing bounded-fetch operations.
   *
   * @return effective policy thresholds in executing bounded-fetch operations
   */
  public Configuration configuration() {
    return configuration;
  }

  /**
   * Effective opt-in admission policy, independent of availability and resource observations.
   *
   * @param maximumInFlight high-water count, zero disables contention gating
   * @param resumeAtOrBelow low-water count for resumption
   */
  public record Configuration(int maximumInFlight, int resumeAtOrBelow) {}

  /**
   * Assesses whether a scheduler tick may attempt due subscription polls.
   *
   * <p>The method blocks only on clear signals: disabled queue backend, queue persistence awaiting
   * a password, queue persistence stopping, a killed persistence database, or the explicitly
   * configured bounded-fetch contention threshold. It does not inspect request details, parse queue
   * pages, or return raw runtime failures. When a probe throws, the result is allowed so the
   * scheduler remains bounded by its per-tick and per-app limits.
   *
   * @return safe pressure assessment for the current scheduler tick
   */
  public PressureAssessment assess() {
    synchronized (assessmentLock) {
      return assessLocked();
    }
  }

  private PressureAssessment assessLocked() {
    PressureAssessment support = assessQueueSupport();
    if (!support.allowed()) {
      return support;
    }
    boolean known = support.known() && requestQueuePort != null;
    if (requestQueuePort != null) {
      try {
        if (requestQueuePort.isPersistenceDatabaseKilled()) {
          return PressureAssessment.blocked(
              ContentSubscriptionStatus.QUEUE_PRESSURE,
              "queue_pressure",
              "Subscription poll skipped because queue persistence is unavailable.");
        }
      } catch (RuntimeException _) {
        known = false;
      }
    }
    return configuration.maximumInFlight() > 0
        ? assessContention(known)
        : PressureAssessment.allow(known);
  }

  private PressureAssessment assessQueueSupport() {
    if (queueSupportPort == null) {
      return PressureAssessment.allow(false);
    }
    try {
      if (!queueSupportPort.isQueueBackendEnabled()) {
        return PressureAssessment.blocked(
            ContentSubscriptionStatus.RUNTIME_UNAVAILABLE,
            "runtime_unavailable",
            "Subscription poll skipped because the queue backend is unavailable.");
      }
      QueuePersistenceStatusSnapshot status = queueSupportPort.persistenceStatus();
      if (status != null && (status.stopping() || status.awaitingPassword())) {
        return PressureAssessment.blocked(
            ContentSubscriptionStatus.QUEUE_PRESSURE,
            "queue_pressure",
            "Subscription poll skipped because queue persistence is not ready.");
      }
      return PressureAssessment.allow(status != null);
    } catch (RuntimeException _) {
      return PressureAssessment.allow(false);
    }
  }

  private PressureAssessment assessContention(boolean availabilityKnown) {
    try {
      ContentFetchObservation sample =
          contentFetchPort == null ? null : contentFetchPort.observation();
      if (sample == null || !sample.known() || sample.truncated()) {
        return PressureAssessment.allow(false);
      }
      if (sample.inFlightOperations() >= configuration.maximumInFlight()) {
        congested = true;
      } else if (sample.inFlightOperations() <= configuration.resumeAtOrBelow()) {
        congested = false;
      }
      recordContention(sample);
      if (congested) {
        return new PressureAssessment(
            false,
            ContentSubscriptionStatus.QUEUE_PRESSURE,
            "content_fetch_contention",
            "Subscription poll skipped because bounded content fetch capacity is busy.",
            true,
            true);
      }
      return PressureAssessment.allow(availabilityKnown);
    } catch (RuntimeException _) {
      return PressureAssessment.allow(false);
    }
  }

  private void recordContention(ContentFetchObservation sample) {
    if (observation != null) {
      observation.pressure(
          congested
              ? RuntimeWorkObservation.Kind.PRESSURE_CONTENTION_BLOCKED
              : RuntimeWorkObservation.Kind.PRESSURE_KNOWN_CLEAR,
          sample);
    }
  }

  /**
   * Result from one pressure-gate assessment.
   *
   * <p>When {@link #allowed()} is {@code true}, the status, error code, and message are {@code
   * null}. When it is {@code false}, scheduler code writes the supplied safe values to still-due
   * subscriptions and schedules a bounded retry. The assessment never carries queue HTML, request
   * bodies, store paths, tokens, or raw exception text.
   *
   * @param allowed whether due polls may proceed during this scheduler tick
   * @param status status to record for skipped due subscriptions, or {@code null}
   * @param errorCode stable error code for skipped subscriptions, or {@code null}
   * @param message safe message for skipped subscriptions, or {@code null}
   * @param known whether the assessed signal is known rather than permissive fallback
   * @param contention whether denial comes from actual executing bounded-fetch calls
   */
  public record PressureAssessment(
      boolean allowed,
      ContentSubscriptionStatus status,
      String errorCode,
      String message,
      boolean known,
      boolean contention) {
    /** Preserves the legacy constructor without granting a known-clear evidence claim. */
    public PressureAssessment(
        boolean allowed, ContentSubscriptionStatus status, String errorCode, String message) {
      this(allowed, status, errorCode, message, !allowed, false);
    }

    static PressureAssessment allow(boolean known) {
      return new PressureAssessment(true, null, null, null, known, false);
    }

    static PressureAssessment blocked(
        ContentSubscriptionStatus status, String errorCode, String message) {
      return new PressureAssessment(false, status, errorCode, message);
    }
  }
}
