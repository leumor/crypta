package network.crypta.platform.api.networkbudget;

import java.time.Instant;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

/**
 * Closeable reservation for a composed app-network operation.
 *
 * <p>Reservations are used when a workflow must prove that one budget family has capacity before it
 * starts work charged to another family. Trust Graph import-by-URI is the motivating example: the
 * handler must hold Trust Graph import concurrency while it performs a bounded content fetch, but
 * it must not durably consume Trust Graph import rate quota when the content fetch is rejected.
 *
 * <p>An allowed reservation may hold process-local concurrency and in-memory rate capacity. Call
 * {@link #commit()} only when the reserved operation is actually about to run; commit converts the
 * in-memory rate hold into the normal durable fixed-window rate counter. Closing the reservation
 * releases any uncommitted in-memory hold and all process-local concurrency. Closing is required
 * and idempotent.
 *
 * <p>Denied reservations contain the same safe public metadata as {@link AppNetworkBudgetDecision}
 * and hold no capacity. They never expose raw source URIs, fetched content, request bodies, queue
 * output, tokens, private insert material, signatures, app-data values, or filesystem paths.
 */
public final class AppNetworkBudgetReservation implements AutoCloseable {
  private final AppNetworkBudgetDecision decision;
  private final long observationId;
  private final Supplier<AppNetworkBudgetDecision> commitAction;
  private final Runnable closeAction;
  private final AtomicBoolean closed = new AtomicBoolean();
  private final AtomicReference<AppNetworkBudgetDecision> commitDecision = new AtomicReference<>();

  AppNetworkBudgetReservation(
      AppNetworkBudgetDecision decision,
      Supplier<AppNetworkBudgetDecision> commitAction,
      Runnable closeAction) {
    this(decision, commitAction, closeAction, 0);
  }

  AppNetworkBudgetReservation(
      AppNetworkBudgetDecision decision,
      Supplier<AppNetworkBudgetDecision> commitAction,
      Runnable closeAction,
      long observationId) {
    this.observationId = observationId;
    this.decision = Objects.requireNonNull(decision, "decision");
    this.commitAction = Objects.requireNonNull(commitAction, "commitAction");
    this.closeAction = Objects.requireNonNull(closeAction, "closeAction");
  }

  /**
   * Returns process-local causal reservation identifier, zero for an uninstrumented embedding.
   *
   * @return process-local causal reservation identifier, zero for an uninstrumented embedding
   */
  public long observationId() {
    return observationId;
  }

  /**
   * Creates an inert reservation for reduced embeddings that intentionally omit budgeting.
   *
   * <p>The returned reservation is allowed, commits as a no-op, and closes as a no-op. Production
   * runtime routes should obtain reservations from {@link AppNetworkBudgetService#reserve(String,
   * AppNetworkBudgetOperation)} so capacity is actually checked and held.
   *
   * @param appId authenticated app id or reserved internal scope associated with the operation
   * @param operation operation that would have been reserved by a full runtime
   * @param decidedAt timestamp to attach to the safe no-op decision
   * @return allowed reservation that does not mutate budget counters
   */
  public static AppNetworkBudgetReservation noop(
      String appId, AppNetworkBudgetOperation operation, Instant decidedAt) {
    AppNetworkBudgetDecision decision =
        AppNetworkBudgetDecision.allowed(
            AppNetworkBudgetScope.normalize(appId),
            Objects.requireNonNull(operation, "operation"),
            Objects.requireNonNull(decidedAt, "decidedAt"),
            AppNetworkBudgetLease.noop());
    return new AppNetworkBudgetReservation(decision, () -> decision, () -> {});
  }

  /**
   * Returns whether the reservation may proceed to prerequisite work.
   *
   * @return {@code true} when capacity was reserved, otherwise {@code false}
   */
  public boolean allowed() {
    return decision.allowed();
  }

  /**
   * Returns the safe decision metadata for this reservation.
   *
   * <p>Callers use this decision to surface a denied reservation through the same error envelope as
   * regular budget acquisition. For allowed reservations, the decision documents the reservation
   * time and operation; callers should still use {@link #commit()} before running the reserved
   * operation.
   *
   * @return immutable safe budget decision metadata
   */
  public AppNetworkBudgetDecision decision() {
    return decision;
  }

  /**
   * Converts the in-memory rate reservation into durable rate usage.
   *
   * <p>Commit is intentionally separate from reservation. A content-fetch denial can close the
   * reservation without charging the Trust Graph import rate counter, while a successful fetch
   * calls this method immediately before parsing and importing the trust statement. The method is
   * idempotent for callers that accidentally repeat cleanup paths; only the first call can mutate
   * budget state.
   *
   * @return allowed decision when durable rate usage was charged, or denied safe metadata
   */
  public synchronized AppNetworkBudgetDecision commit() {
    if (!decision.allowed()) {
      return decision;
    }
    AppNetworkBudgetDecision previousDecision = commitDecision.get();
    if (previousDecision != null) {
      return previousDecision;
    }
    if (closed.get()) {
      return AppNetworkBudgetDecision.denied(
          503,
          decision.appId(),
          decision.operation(),
          "network_budget_unavailable",
          "App network budget reservation is unavailable.",
          decision.decidedAt(),
          null);
    }
    AppNetworkBudgetDecision result = Objects.requireNonNull(commitAction.get(), "commitDecision");
    commitDecision.set(result);
    return result;
  }

  @Override
  public synchronized void close() {
    if (closed.compareAndSet(false, true)) {
      closeAction.run();
    }
  }
}
