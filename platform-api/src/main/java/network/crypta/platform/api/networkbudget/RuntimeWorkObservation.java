package network.crypta.platform.api.networkbudget;

import java.time.Instant;
import java.util.ArrayDeque;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import network.crypta.runtime.spi.ContentFetchObservation;

/**
 * Bounded process-local causal observations shared by scheduling and network admission.
 *
 * <p>Recording performs no file or network I/O and accepts only fixed event labels and numeric
 * values. Records contain no app identities, sources, payloads, paths or exception text. Sequence
 * numbers establish ordering within this instance; wall time is informational. An overwritten
 * record increments {@code dropped}, so a consumer cannot mistake a truncated history for complete
 * accounting. Snapshots are detached and intended only for authenticated local operator reads.
 *
 * <p>Construction creates an empty recorder with a new monotonic time origin. Mutations and
 * snapshots serialize on this instance; callers must retain the same recorder to correlate events.
 * Saturated identifiers and scope exhaustion mark coverage incomplete rather than wrapping.
 */
public final class RuntimeWorkObservation {
  /** Maximum retained records; sampling cannot grow the journal. */
  public static final int CAPACITY = 4096;

  private final ArrayDeque<Event> events = new ArrayDeque<>();
  private final long originNanos = System.nanoTime();
  private long sequence;
  private long dropped;
  private long operationSequence;
  private final Map<String, Long> scopes = new LinkedHashMap<>();

  /** Fixed causal event vocabulary; an empty completed tick is not a completed fetch. */
  public enum Kind {
    /** The background executor invoked a pass; useful work is not implied. */
    EXECUTOR_TICK,
    /** An enabled pass acquired the no-overlap guard. */
    TICK_ENTERED,
    /** A pass reached final cleanup, including passes that failed or did no work. */
    TICK_COMPLETED,
    /** A competing pass found the no-overlap guard already held. */
    TICK_ALREADY_RUNNING,
    /** A required observation or scheduler store could not be read. */
    STORE_UNAVAILABLE,
    /** A subscription was excluded because it is paused. */
    PAUSED,
    /** A subscription was excluded by its poll timing or other skip state. */
    NOT_DUE,
    /** A subscription passed the scheduler snapshot due check. */
    DUE,
    /** Due work was skipped after reaching the per-tick fetch limit. */
    TICK_LIMIT,
    /** Due work lacked an installed application with the required capabilities. */
    CAPABILITY_DENIED,
    /** The assessed signal was known clear; owner samples carry source metadata. */
    PRESSURE_KNOWN_CLEAR,
    /** The signal was unavailable; permissive admission is not evidence of health. */
    PRESSURE_UNKNOWN,
    /** Queue or persistence availability denied scheduler admission. */
    PRESSURE_AVAILABILITY_BLOCKED,
    /** The configured executing-fetch threshold denied scheduler admission. */
    PRESSURE_CONTENTION_BLOCKED,
    /** A due subscription was skipped under the tick pressure assessment. */
    PRESSURE_SKIP,
    /** A budget availability check began without acquiring capacity. */
    BUDGET_CHECK,
    /** A request began reserving rate and concurrency capacity. */
    BUDGET_RESERVE,
    /** A request began acquiring and charging budget capacity. */
    BUDGET_ACQUIRE,
    /** An applicable fixed-window rate limit denied admission. */
    BUDGET_RATE_DENIED,
    /** An applicable process-local concurrency limit denied admission. */
    BUDGET_CONCURRENCY_DENIED,
    /** All required family reservations were acquired. */
    BUDGET_RESERVED,
    /** The composed budget acquisition or reservation commit completed. */
    BUDGET_COMMITTED,
    /** The operation released its process-local budget holds. */
    BUDGET_RELEASED,
    /** Durable usage was read for the specified family, scope and fixed window. */
    RATE_OBSERVED,
    /** Durable usage was charged in the specified family, scope and fixed window. */
    RATE_CHARGED,
    /** Rate capacity was held pending reservation commit. */
    RATE_RESERVED,
    /** A process-local rate hold was released without resetting durable usage. */
    RATE_RESERVATION_RELEASED,
    /** A family concurrency slot was acquired. */
    CONCURRENCY_HELD,
    /** A family concurrency slot was released. */
    CONCURRENCY_RELEASED,
    /** The subscription service is invoking the bounded content-fetch port. */
    FETCH_INVOKED,
    /** The subscription fetch succeeded. */
    FETCH_SUCCEEDED,
    /** The subscription fetch failed. */
    FETCH_FAILED,
    /** A failed or skipped poll recorded its next retry time. */
    RETRY_SCHEDULED,
    /** A successful poll recorded its next due time. */
    NEXT_DUE
  }

  /**
   * Returns new process-local causal operation identifier, or zero on exhausted counter range.
   *
   * @return new process-local causal operation identifier, or zero on exhausted counter range
   */
  public synchronized long nextOperation() {
    if (operationSequence == Long.MAX_VALUE) {
      dropped = Long.MAX_VALUE;
      return 0;
    }
    return ++operationSequence;
  }

  /**
   * Allocates bounded opaque scope labels. No app identifier or hash is emitted.
   *
   * @param appId private normalized scope
   * @return one for global, two or greater for an application, zero on exhausted capacity
   */
  public synchronized long scope(String appId) {
    if (AppNetworkBudgetScope.GLOBAL.equals(appId)) {
      return 1;
    }
    Long existing = scopes.get(appId);
    if (existing != null) {
      return existing;
    }
    if (scopes.size() == 1024) {
      dropped = Long.MAX_VALUE;
      return 0;
    }
    long label = scopes.size() + 2L;
    scopes.put(appId, label);
    return label;
  }

  /**
   * Records a fixed event without an operation or numeric measurement.
   *
   * @param kind fixed event kind
   */
  public void recordEvent(Kind kind) {
    recordEvent(kind, null, 0, 0);
  }

  /**
   * Records a fixed event and bounded numeric metadata.
   *
   * @param kind fixed event kind
   * @param operation budget family/operation, or {@code null} for scheduler events
   * @param windowStartEpochSecond fixed-window start for rate events; otherwise zero
   * @param value count for rate events, due epoch seconds for timing events, otherwise zero
   */
  public synchronized void recordEvent(
      Kind kind, AppNetworkBudgetOperation operation, long windowStartEpochSecond, long value) {
    recordEvent(kind, operation, windowStartEpochSecond, value, 0, 0);
  }

  /**
   * Records an operation-correlated family transition; scope labels are instance-local.
   *
   * @param kind fixed event kind
   * @param operation budget family, or {@code null} when not applicable
   * @param windowStartEpochSecond fixed-window start in epoch seconds, or zero
   * @param value event-specific count or epoch-second timing value
   * @param operationId identifier from {@link #nextOperation()}, or zero when not applicable
   * @param scope opaque label from {@link #scope(String)}, or zero when not applicable
   * @throws NullPointerException if {@code kind} is null
   */
  public synchronized void recordEvent(
      Kind kind,
      AppNetworkBudgetOperation operation,
      long windowStartEpochSecond,
      long value,
      long operationId,
      long scope) {
    append(
        kind,
        operation,
        windowStartEpochSecond,
        value,
        new Context(operationId, scope, null, 0, 0));
  }

  /**
   * Records the actual owner sample used for a contention assessment, without request inventory.
   *
   * <p>An invalid owner UUID records {@link Kind#PRESSURE_UNKNOWN} instead of exposing its value.
   * The caller must assess the sample's known/truncated flags before selecting the event kind.
   *
   * @param kind assessment event to associate with a valid owner sample
   * @param sample detached owner counters and sample identity
   * @throws NullPointerException if the sample, its epoch, or the accepted event kind is null
   */
  public synchronized void pressure(Kind kind, ContentFetchObservation sample) {
    String epoch;
    try {
      epoch = UUID.fromString(sample.epoch()).toString();
    } catch (IllegalArgumentException _) {
      recordEvent(Kind.PRESSURE_UNKNOWN);
      return;
    }
    append(
        kind,
        null,
        0,
        sample.inFlightOperations(),
        new Context(0, 0, epoch, sample.sequence(), sample.sampledAtEpochMillis()));
  }

  private void append(
      Kind kind,
      AppNetworkBudgetOperation operation,
      long windowStartEpochSecond,
      long value,
      Context context) {
    Objects.requireNonNull(kind, "kind");
    if (sequence == Long.MAX_VALUE) {
      dropped = Long.MAX_VALUE;
      return;
    }
    if (events.size() == CAPACITY) {
      events.removeFirst();
      if (dropped < Long.MAX_VALUE) {
        dropped++;
      }
    }
    events.addLast(
        new Event(
            ++sequence,
            Instant.now(),
            System.nanoTime() - originNanos,
            kind,
            operation,
            windowStartEpochSecond,
            value,
            context.operationId(),
            context.scope(),
            context.sourceEpoch(),
            context.sourceSequence(),
            context.sourceSampledAtEpochMillis()));
  }

  /**
   * Returns detached bounded history, with explicit cumulative truncation count.
   *
   * @return detached bounded history, with explicit cumulative truncation count
   */
  public synchronized Snapshot snapshot() {
    return new Snapshot(1, sequence, dropped, List.copyOf(events));
  }

  /**
   * One safe process-local event. Elapsed time uses monotonic nanoseconds; wall time uses UTC.
   *
   * @param sequence strictly increasing instance-local sequence
   * @param observedAt actual recording wall time
   * @param elapsedNanos monotonic elapsed nanoseconds since collector creation
   * @param kind fixed event kind
   * @param operation budget operation/family or null
   * @param windowStartEpochSecond original rate window, or zero when inapplicable
   * @param value documented count/time for the event kind
   * @param operationId process-local admission correlation, zero if inapplicable
   * @param scope opaque process-local family scope; one is global, two or more are app scopes
   * @param sourceEpoch exact contention owner UUID, or null when inapplicable
   * @param sourceSequence contention owner transition sequence
   * @param sourceSampledAtEpochMillis actual gate sample wall time in milliseconds
   */
  public record Event(
      long sequence,
      Instant observedAt,
      long elapsedNanos,
      Kind kind,
      AppNetworkBudgetOperation operation,
      long windowStartEpochSecond,
      long value,
      long operationId,
      long scope,
      String sourceEpoch,
      long sourceSequence,
      long sourceSampledAtEpochMillis) {}

  /**
   * Detached bounded history. Any dropped records make complete-history claims unavailable.
   *
   * @param version collector format version
   * @param lastSequence last issued sequence
   * @param dropped cumulative overwritten records, saturating at the maximum long value
   * @param events oldest-first retained events
   */
  public record Snapshot(int version, long lastSequence, long dropped, List<Event> events) {
    /**
     * Detaches event storage even when a caller constructs a snapshot from a mutable list.
     *
     * @throws NullPointerException if the list or any event is null
     */
    public Snapshot {
      events = List.copyOf(events);
    }
  }

  private record Context(
      long operationId,
      long scope,
      String sourceEpoch,
      long sourceSequence,
      long sourceSampledAtEpochMillis) {}
}
