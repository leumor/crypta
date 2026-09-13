package network.crypta.platform.api.networkbudget;

import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Shared deterministic app-network budget service.
 *
 * <p>The service combines durable fixed-window rate counters with process-local concurrency
 * counters. It is intentionally small and JDK-only: callers ask for a decision before starting a
 * network-initiating operation and close the returned lease in a {@code finally} block or
 * try-with-resources. Durable records contain only safe app ids, operation labels, counts, decision
 * labels, and timestamps.
 *
 * <p>The service is synchronized because each decision may read counters, check active leases,
 * update durable metadata, and return a lease whose close action later releases process-local
 * counts. Rate counters are durable fixed windows; concurrency counters are deliberately in-process
 * and reset when the node restarts. That trade-off keeps normal routing cheap while still
 * preventing long-lived app workflows from bypassing foreground content-fetch, subscription, and
 * Trust Graph import limits.
 *
 * <p>Several operations charge more than one budget family. Subscription polls and manual refreshes
 * charge subscription limits and the global content-fetch family. Trust Graph import by URI charges
 * Trust Graph import budget in the handler and content-fetch budget through the content fetch
 * operation. Store failures fail closed with safe metadata instead of resetting quota.
 */
public final class AppNetworkBudgetService {
  private static final String PARAM_OPERATION = "operation";
  private static final String ERROR_NETWORK_BUDGET_UNAVAILABLE = "network_budget_unavailable";
  private static final String MESSAGE_NETWORK_BUDGET_UNAVAILABLE =
      "App network budget service is unavailable.";
  private static final String GLOBAL_SCOPE_ID = AppNetworkBudgetScope.GLOBAL;
  private static final Duration MINUTE_WINDOW = Duration.ofMinutes(1);
  private static final Duration HOUR_WINDOW = Duration.ofHours(1);

  private final RuntimeWorkObservation observation = new RuntimeWorkObservation();
  private final AppNetworkBudgetStore store;
  private final AppNetworkBudgetConfig config;
  private final Clock clock;
  private final Map<String, Integer> activeLeases = new LinkedHashMap<>();
  private final Map<String, Integer> pendingRateReservations = new LinkedHashMap<>();

  /**
   * Creates a service using the system UTC clock.
   *
   * <p>Production runtime wiring normally uses this constructor with a file-backed store beneath
   * the app-platform data directory. The service reads the clock only while evaluating decisions,
   * so the instance can be shared by content routes, subscription services, and Trust Graph routes.
   *
   * @param store durable safe counter store used for fixed-window rate records
   * @param config finite budget configuration used for every decision
   */
  public AppNetworkBudgetService(AppNetworkBudgetStore store, AppNetworkBudgetConfig config) {
    this(store, config, Clock.systemUTC());
  }

  /**
   * Creates a service with deterministic time for tests.
   *
   * <p>Tests and deterministic offline certification checks use this constructor to advance fixed
   * windows without sleeping. The supplied store is still authoritative for rate counters, while
   * active leases remain process-local state inside this service instance.
   *
   * @param store durable safe counter store used for fixed-window rate records
   * @param config finite budget configuration used for every decision
   * @param clock clock used for fixed-window boundaries and decision timestamps
   */
  public AppNetworkBudgetService(
      AppNetworkBudgetStore store, AppNetworkBudgetConfig config, Clock clock) {
    this.store = Objects.requireNonNull(store, "store");
    this.config = Objects.requireNonNull(config, "config");
    this.clock = Objects.requireNonNull(clock, "clock");
  }

  /**
   * Returns bounded causal observations shared with the subscription scheduler.
   *
   * <p>This is an intentional mutable producer collaborator for trusted native composition.
   * Returning a detached copy would split admission and fetch ordering into unrelated event
   * sequences. Operator readers receive only detached snapshots; app/browser routes never receive
   * this collaborator.
   *
   * @return bounded causal observations shared with the subscription scheduler
   */
  public RuntimeWorkObservation observation() {
    return observation;
  }

  /**
   * Returns normalized effective budget configuration.
   *
   * @return normalized effective budget configuration
   */
  public AppNetworkBudgetConfig configuration() {
    return config;
  }

  /**
   * Reads operator diagnostics without confusing a failed store read with zero usage.
   *
   * <p>The returned family snapshots are private operator data containing app scopes. They must not
   * be exported as public telemetry. Active and reserved counts sum family holds, not requests.
   *
   * @return detached diagnostic result with explicit validity and sample time
   */
  public synchronized Diagnostics diagnostics() {
    try {
      List<AppNetworkBudgetSnapshot> usage =
          store.observe(4096).stream().map(this::snapshotFor).toList();
      return new Diagnostics(
          true,
          clock.instant(),
          usage,
          activeLeases.values().stream().mapToLong(Integer::longValue).sum(),
          pendingRateReservations.values().stream().mapToLong(Integer::longValue).sum());
    } catch (IOException _) {
      observation.recordEvent(RuntimeWorkObservation.Kind.STORE_UNAVAILABLE);
      return new Diagnostics(
          false,
          clock.instant(),
          List.of(),
          activeLeases.values().stream().mapToLong(Integer::longValue).sum(),
          pendingRateReservations.values().stream().mapToLong(Integer::longValue).sum());
    }
  }

  /**
   * Private operator diagnostic snapshot; unavailable durable usage is never a zero measurement.
   *
   * @param valid whether durable usage enumeration succeeded
   * @param observedAt sample time
   * @param usage private family/window snapshots, empty when unavailable
   * @param activeFamilyLeases process-local held concurrency summed across families
   * @param reservedFamilyRates process-local uncommitted rate holds summed across families/windows
   */
  public record Diagnostics(
      boolean valid,
      Instant observedAt,
      List<AppNetworkBudgetSnapshot> usage,
      long activeFamilyLeases,
      long reservedFamilyRates) {
    /** Copies private usage rows so callers cannot mutate an issued diagnostic snapshot. */
    public Diagnostics {
      usage = List.copyOf(usage);
    }
  }

  /**
   * Attempts to acquire budget for one app operation.
   *
   * <p>Denied decisions fail closed with a safe status and message. Store read/write failures
   * return a service-unavailable decision rather than leaking path or exception details.
   *
   * <p>Callers must request budget after validating app-facing source strings and bounds, but
   * before invoking runtime network ports. If the returned decision is allowed, callers must close
   * the lease after the bounded network work completes or fails. If the decision is denied, callers
   * should surface only its stable status, error code, message, and retry timestamp.
   *
   * @param appId authenticated app id or reserved internal scope to charge
   * @param operation requested network operation and budget family
   * @return allowed decision with a closeable lease or denied decision with safe failure metadata
   */
  public synchronized AppNetworkBudgetDecision acquire(
      String appId, AppNetworkBudgetOperation operation) {
    long operationId = observation.nextOperation();
    String normalizedAppId = AppNetworkBudgetScope.normalize(appId);
    AppNetworkBudgetOperation checkedOperation = Objects.requireNonNull(operation, PARAM_OPERATION);
    observation.recordEvent(
        RuntimeWorkObservation.Kind.BUDGET_ACQUIRE,
        checkedOperation,
        0,
        0,
        operationId,
        observation.scope(normalizedAppId));
    Instant now = clock.instant();
    List<RateLimit> rateLimits = rateLimits(normalizedAppId, checkedOperation);
    List<ConcurrencyLimit> concurrencyLimits = concurrencyLimits(normalizedAppId, checkedOperation);
    try {
      AppNetworkBudgetDecision concurrencyDecision =
          concurrencyDecision(normalizedAppId, checkedOperation, now, concurrencyLimits);
      if (!concurrencyDecision.allowed()) {
        recordConcurrencyDenial(normalizedAppId, checkedOperation, now, rateLimits);
        observation.recordEvent(
            RuntimeWorkObservation.Kind.BUDGET_CONCURRENCY_DENIED,
            checkedOperation,
            0,
            0,
            operationId,
            observation.scope(normalizedAppId));
        return concurrencyDecision;
      }
      AppNetworkBudgetDecision rateDecision =
          rateDecision(normalizedAppId, checkedOperation, now, rateLimits);
      if (!rateDecision.allowed()) {
        observation.recordEvent(
            RuntimeWorkObservation.Kind.BUDGET_RATE_DENIED,
            operation,
            0,
            0,
            operationId,
            observation.scope(normalizedAppId));
        return rateDecision;
      }
      for (RateLimit limit : rateLimits) {
        AppNetworkBudgetUsage previous = usage(limit, now);
        observation.recordEvent(
            RuntimeWorkObservation.Kind.RATE_OBSERVED,
            limit.operation(),
            previous.windowStart().getEpochSecond(),
            previous.count(),
            operationId,
            observation.scope(limit.appId()));
        AppNetworkBudgetUsage charged = previous.allowedAt(now);
        store.write(charged);
        observation.recordEvent(
            RuntimeWorkObservation.Kind.RATE_CHARGED,
            limit.operation(),
            charged.windowStart().getEpochSecond(),
            charged.count(),
            operationId,
            observation.scope(limit.appId()));
      }
      for (ConcurrencyLimit limit : concurrencyLimits) {
        activeLeases.merge(limit.key(), 1, Integer::sum);
        observation.recordEvent(
            RuntimeWorkObservation.Kind.CONCURRENCY_HELD,
            limit.operation(),
            0,
            activeLeases.get(limit.key()),
            operationId,
            observation.scope(limit.appId()));
      }
      observation.recordEvent(
          RuntimeWorkObservation.Kind.BUDGET_COMMITTED,
          checkedOperation,
          0,
          0,
          operationId,
          observation.scope(normalizedAppId));
      return AppNetworkBudgetDecision.allowed(
          normalizedAppId,
          checkedOperation,
          now,
          new AppNetworkBudgetLease(() -> release(concurrencyLimits, operationId)));
    } catch (IOException _) {
      observation.recordEvent(RuntimeWorkObservation.Kind.STORE_UNAVAILABLE);
      return AppNetworkBudgetDecision.denied(
          503,
          normalizedAppId,
          checkedOperation,
          ERROR_NETWORK_BUDGET_UNAVAILABLE,
          MESSAGE_NETWORK_BUDGET_UNAVAILABLE,
          now,
          null);
    }
  }

  /**
   * Checks whether an operation would be allowed without consuming rate or concurrency budget.
   *
   * <p>This is a preflight decision for composed operations that need to fail before starting an
   * expensive or separately budgeted prerequisite. It reads the same fixed-window counters and
   * process-local concurrency counters as {@link #acquire(String, AppNetworkBudgetOperation)}, but
   * it does not increment durable counters, record denial metadata, or reserve a concurrency lease.
   * Callers that proceed after an allowed preflight must still call {@link #acquire(String,
   * AppNetworkBudgetOperation)} immediately before the operation being charged, because another
   * request can consume the budget after the preflight decision.
   *
   * <p>Store read failures still fail closed with {@code network_budget_unavailable}. The returned
   * allowed decision carries only a no-op lease, which is safe to close but does not grant
   * capacity.
   *
   * @param appId authenticated app id or reserved internal scope to check
   * @param operation requested network operation and budget family
   * @return non-mutating allowed or denied decision with safe failure metadata
   */
  public synchronized AppNetworkBudgetDecision check(
      String appId, AppNetworkBudgetOperation operation) {
    long operationId = observation.nextOperation();
    String normalizedAppId = AppNetworkBudgetScope.normalize(appId);
    AppNetworkBudgetOperation checkedOperation = Objects.requireNonNull(operation, PARAM_OPERATION);
    observation.recordEvent(
        RuntimeWorkObservation.Kind.BUDGET_CHECK,
        checkedOperation,
        0,
        0,
        operationId,
        observation.scope(normalizedAppId));
    Instant now = clock.instant();
    List<RateLimit> rateLimits = rateLimits(normalizedAppId, checkedOperation);
    List<ConcurrencyLimit> concurrencyLimits = concurrencyLimits(normalizedAppId, checkedOperation);
    try {
      AppNetworkBudgetDecision concurrencyDecision =
          concurrencyDecision(normalizedAppId, checkedOperation, now, concurrencyLimits);
      if (!concurrencyDecision.allowed()) {
        observation.recordEvent(
            RuntimeWorkObservation.Kind.BUDGET_CONCURRENCY_DENIED,
            checkedOperation,
            0,
            0,
            operationId,
            observation.scope(normalizedAppId));
        return concurrencyDecision;
      }
      AppNetworkBudgetDecision rateDecision =
          rateCheckDecision(normalizedAppId, checkedOperation, now, rateLimits);
      if (!rateDecision.allowed()) {
        observation.recordEvent(
            RuntimeWorkObservation.Kind.BUDGET_RATE_DENIED,
            operation,
            0,
            0,
            operationId,
            observation.scope(normalizedAppId));
        return rateDecision;
      }
      return AppNetworkBudgetDecision.allowed(
          normalizedAppId, checkedOperation, now, AppNetworkBudgetLease.noop());
    } catch (IOException _) {
      observation.recordEvent(RuntimeWorkObservation.Kind.STORE_UNAVAILABLE);
      return AppNetworkBudgetDecision.denied(
          503,
          normalizedAppId,
          checkedOperation,
          ERROR_NETWORK_BUDGET_UNAVAILABLE,
          MESSAGE_NETWORK_BUDGET_UNAVAILABLE,
          now,
          null);
    }
  }

  /**
   * Reserves budget capacity for a composed operation without durably consuming rate quota.
   *
   * <p>The reservation checks the same rate and concurrency limits as {@link #acquire(String,
   * AppNetworkBudgetOperation)}. When allowed, it records process-local concurrency and an
   * in-memory rate hold, then returns a closeable reservation. The rate hold prevents other
   * requests handled by this service instance from overbooking the fixed-window quota while the
   * prerequisite work runs. Durable rate counters are written only when the caller invokes {@link
   * AppNetworkBudgetReservation#commit()}.
   *
   * <p>This method is for short composed workflows that need fail-closed admission before starting
   * separately budgeted work. Callers must close the returned reservation in a try-with-resources
   * block so rejected prerequisite work releases the held capacity.
   *
   * @param appId authenticated app id or reserved internal scope to reserve
   * @param operation requested network operation and budget family
   * @return allowed reservation with held capacity or denied reservation with safe metadata
   */
  public synchronized AppNetworkBudgetReservation reserve(
      String appId, AppNetworkBudgetOperation operation) {
    long operationId = observation.nextOperation();
    String normalizedAppId = AppNetworkBudgetScope.normalize(appId);
    AppNetworkBudgetOperation checkedOperation = Objects.requireNonNull(operation, PARAM_OPERATION);
    observation.recordEvent(
        RuntimeWorkObservation.Kind.BUDGET_RESERVE,
        checkedOperation,
        0,
        0,
        operationId,
        observation.scope(normalizedAppId));
    Instant now = clock.instant();
    List<RateLimit> rateLimits = rateLimits(normalizedAppId, checkedOperation);
    List<ConcurrencyLimit> concurrencyLimits = concurrencyLimits(normalizedAppId, checkedOperation);
    try {
      AppNetworkBudgetDecision concurrencyDecision =
          concurrencyDecision(normalizedAppId, checkedOperation, now, concurrencyLimits);
      if (!concurrencyDecision.allowed()) {
        recordConcurrencyDenial(normalizedAppId, checkedOperation, now, rateLimits);
        observation.recordEvent(
            RuntimeWorkObservation.Kind.BUDGET_CONCURRENCY_DENIED,
            checkedOperation,
            0,
            0,
            operationId,
            observation.scope(normalizedAppId));
        return deniedReservation(concurrencyDecision);
      }
      AppNetworkBudgetDecision rateDecision =
          rateCheckDecision(normalizedAppId, checkedOperation, now, rateLimits);
      if (!rateDecision.allowed()) {
        observation.recordEvent(
            RuntimeWorkObservation.Kind.BUDGET_RATE_DENIED,
            checkedOperation,
            0,
            0,
            operationId,
            observation.scope(normalizedAppId));
        return deniedReservation(rateDecision);
      }
      List<String> rateReservationKeys = reserveRateCapacity(rateLimits, now, operationId);
      for (ConcurrencyLimit limit : concurrencyLimits) {
        activeLeases.merge(limit.key(), 1, Integer::sum);
        observation.recordEvent(
            RuntimeWorkObservation.Kind.CONCURRENCY_HELD,
            limit.operation(),
            0,
            activeLeases.get(limit.key()),
            operationId,
            observation.scope(limit.appId()));
      }
      observation.recordEvent(
          RuntimeWorkObservation.Kind.BUDGET_RESERVED,
          checkedOperation,
          0,
          0,
          operationId,
          observation.scope(normalizedAppId));
      AtomicBoolean rateReservationActive = new AtomicBoolean(true);
      AppNetworkBudgetDecision decision =
          AppNetworkBudgetDecision.allowed(
              normalizedAppId, checkedOperation, now, AppNetworkBudgetLease.noop());
      return new AppNetworkBudgetReservation(
          decision,
          () ->
              commitReservation(
                  normalizedAppId,
                  checkedOperation,
                  rateReservationKeys,
                  rateReservationActive,
                  operationId),
          () ->
              releaseReservation(
                  concurrencyLimits, rateReservationKeys, rateReservationActive, operationId),
          operationId);
    } catch (IOException _) {
      observation.recordEvent(RuntimeWorkObservation.Kind.STORE_UNAVAILABLE);
      return deniedReservation(
          AppNetworkBudgetDecision.denied(
              503,
              normalizedAppId,
              checkedOperation,
              ERROR_NETWORK_BUDGET_UNAVAILABLE,
              MESSAGE_NETWORK_BUDGET_UNAVAILABLE,
              now,
              null));
    }
  }

  /**
   * Returns safe snapshots for currently stored counters.
   *
   * <p>Snapshots are intended for operator diagnostics and release evidence. They expose normalized
   * app ids, operation labels, counts, configured limits, timestamps, and stable decision labels
   * only. If the store cannot enumerate records, the method returns an empty list rather than
   * leaking an exception or filesystem detail.
   *
   * @return deterministic safe snapshots sorted by app id and operation label
   */
  public synchronized List<AppNetworkBudgetSnapshot> snapshots() {
    try {
      return store.listAll().stream()
          .map(this::snapshotFor)
          .sorted(
              Comparator.comparing(AppNetworkBudgetSnapshot::appId)
                  .thenComparing(snapshot -> snapshot.operation().jsonValue()))
          .toList();
    } catch (IOException _) {
      observation.recordEvent(RuntimeWorkObservation.Kind.STORE_UNAVAILABLE);
      return List.of();
    }
  }

  private AppNetworkBudgetSnapshot snapshotFor(AppNetworkBudgetUsage usage) {
    return new AppNetworkBudgetSnapshot(
        usage.appId(),
        usage.operation(),
        usage.windowStart(),
        usage.window().toSeconds(),
        usage.count(),
        configuredLimit(usage.appId(), usage.operation()),
        usage.lastDecisionAt(),
        usage.lastDecision(),
        usage.nextAvailableAt());
  }

  private AppNetworkBudgetDecision concurrencyDecision(
      String appId,
      AppNetworkBudgetOperation operation,
      Instant now,
      List<ConcurrencyLimit> concurrencyLimits) {
    for (ConcurrencyLimit limit : concurrencyLimits) {
      if (activeLeases.getOrDefault(limit.key(), 0) >= limit.limit()) {
        return AppNetworkBudgetDecision.denied(
            429,
            appId,
            operation,
            concurrencyErrorCode(operation),
            concurrencyMessage(operation),
            now,
            null);
      }
    }
    return AppNetworkBudgetDecision.allowed(appId, operation, now, AppNetworkBudgetLease.noop());
  }

  private AppNetworkBudgetDecision rateCheckDecision(
      String appId, AppNetworkBudgetOperation operation, Instant now, List<RateLimit> rateLimits)
      throws IOException {
    for (RateLimit limit : rateLimits) {
      AppNetworkBudgetUsage usage = usage(limit, now);
      if (usage.count() + pendingRateReservations(limit, usage.windowStart()) >= limit.limit()) {
        Instant nextAvailableAt = usage.windowStart().plus(usage.window());
        return AppNetworkBudgetDecision.denied(
            429,
            appId,
            operation,
            rateErrorCode(operation),
            rateMessage(operation),
            now,
            nextAvailableAt);
      }
    }
    return AppNetworkBudgetDecision.allowed(appId, operation, now, AppNetworkBudgetLease.noop());
  }

  private AppNetworkBudgetDecision rateDecision(
      String appId, AppNetworkBudgetOperation operation, Instant now, List<RateLimit> rateLimits)
      throws IOException {
    for (RateLimit limit : rateLimits) {
      AppNetworkBudgetUsage usage = usage(limit, now);
      if (usage.count() + pendingRateReservations(limit, usage.windowStart()) >= limit.limit()) {
        Instant nextAvailableAt = usage.windowStart().plus(usage.window());
        store.write(usage.deniedAt(now, "rate_limited", nextAvailableAt));
        return AppNetworkBudgetDecision.denied(
            429,
            appId,
            operation,
            rateErrorCode(operation),
            rateMessage(operation),
            now,
            nextAvailableAt);
      }
    }
    return AppNetworkBudgetDecision.allowed(appId, operation, now, AppNetworkBudgetLease.noop());
  }

  private AppNetworkBudgetUsage usage(RateLimit limit, Instant now) throws IOException {
    Instant windowStart = truncate(now, limit.window());
    return store
        .read(limit.appId(), limit.operation())
        .orElseGet(
            () ->
                AppNetworkBudgetUsage.empty(
                    limit.appId(), limit.operation(), windowStart, limit.window()))
        .inWindow(windowStart, limit.window());
  }

  private void recordConcurrencyDenial(
      String appId, AppNetworkBudgetOperation operation, Instant now, List<RateLimit> rateLimits)
      throws IOException {
    for (RateLimit limit : rateLimits) {
      if (limit.appId().equals(appId) && limit.operation() == operation) {
        store.write(usage(limit, now).deniedAt(now, "concurrency_limited", null));
        return;
      }
    }
  }

  private List<String> reserveRateCapacity(
      List<RateLimit> rateLimits, Instant now, long operationId) {
    ArrayList<String> reservationKeys = new ArrayList<>(rateLimits.size());
    for (RateLimit limit : rateLimits) {
      String key = rateReservationKey(limit, truncate(now, limit.window()));
      pendingRateReservations.merge(key, 1, Integer::sum);
      observation.recordEvent(
          RuntimeWorkObservation.Kind.RATE_RESERVED,
          limit.operation(),
          truncate(now, limit.window()).getEpochSecond(),
          pendingRateReservations.get(key),
          operationId,
          observation.scope(limit.appId()));
      reservationKeys.add(key);
    }
    return reservationKeys;
  }

  private synchronized AppNetworkBudgetDecision commitReservation(
      String appId,
      AppNetworkBudgetOperation operation,
      List<String> rateReservationKeys,
      AtomicBoolean rateReservationActive,
      long operationId) {
    Instant now = clock.instant();
    if (rateReservationActive.compareAndSet(true, false)) {
      releasePendingRateReservations(rateReservationKeys, operationId);
    }
    List<RateLimit> rateLimits = rateLimits(appId, operation);
    try {
      AppNetworkBudgetDecision rateDecision = rateDecision(appId, operation, now, rateLimits);
      if (!rateDecision.allowed()) {
        observation.recordEvent(
            RuntimeWorkObservation.Kind.BUDGET_RATE_DENIED,
            operation,
            0,
            0,
            operationId,
            observation.scope(appId));
        return rateDecision;
      }
      for (RateLimit limit : rateLimits) {
        AppNetworkBudgetUsage previous = usage(limit, now);
        observation.recordEvent(
            RuntimeWorkObservation.Kind.RATE_OBSERVED,
            limit.operation(),
            previous.windowStart().getEpochSecond(),
            previous.count(),
            operationId,
            observation.scope(limit.appId()));
        AppNetworkBudgetUsage charged = previous.allowedAt(now);
        store.write(charged);
        observation.recordEvent(
            RuntimeWorkObservation.Kind.RATE_CHARGED,
            limit.operation(),
            charged.windowStart().getEpochSecond(),
            charged.count(),
            operationId,
            observation.scope(limit.appId()));
      }
      observation.recordEvent(
          RuntimeWorkObservation.Kind.BUDGET_COMMITTED,
          operation,
          0,
          0,
          operationId,
          observation.scope(appId));
      return AppNetworkBudgetDecision.allowed(appId, operation, now, AppNetworkBudgetLease.noop());
    } catch (IOException _) {
      observation.recordEvent(RuntimeWorkObservation.Kind.STORE_UNAVAILABLE);
      return AppNetworkBudgetDecision.denied(
          503,
          appId,
          operation,
          ERROR_NETWORK_BUDGET_UNAVAILABLE,
          MESSAGE_NETWORK_BUDGET_UNAVAILABLE,
          now,
          null);
    }
  }

  private static AppNetworkBudgetReservation deniedReservation(AppNetworkBudgetDecision decision) {
    return new AppNetworkBudgetReservation(decision, () -> decision, () -> {});
  }

  private synchronized void release(List<ConcurrencyLimit> limits, long operationId) {
    for (ConcurrencyLimit limit : limits) {
      activeLeases.computeIfPresent(limit.key(), (_, count) -> count <= 1 ? null : count - 1);
      observation.recordEvent(
          RuntimeWorkObservation.Kind.CONCURRENCY_RELEASED,
          limit.operation(),
          0,
          activeLeases.getOrDefault(limit.key(), 0),
          operationId,
          observation.scope(limit.appId()));
    }
    observation.recordEvent(
        RuntimeWorkObservation.Kind.BUDGET_RELEASED, null, 0, 0, operationId, 0);
  }

  private synchronized void releaseReservation(
      List<ConcurrencyLimit> concurrencyLimits,
      List<String> rateReservationKeys,
      AtomicBoolean rateReservationActive,
      long operationId) {
    if (rateReservationActive.compareAndSet(true, false)) {
      releasePendingRateReservations(rateReservationKeys, operationId);
    }
    release(concurrencyLimits, operationId);
  }

  private void releasePendingRateReservations(List<String> reservationKeys, long operationId) {
    for (String key : reservationKeys) {
      pendingRateReservations.computeIfPresent(key, (_, count) -> count <= 1 ? null : count - 1);
      String[] identity = key.split("\\n", 3);
      observation.recordEvent(
          RuntimeWorkObservation.Kind.RATE_RESERVATION_RELEASED,
          AppNetworkBudgetOperation.fromJsonValue(identity[1]),
          Instant.parse(identity[2]).getEpochSecond(),
          pendingRateReservations.getOrDefault(key, 0),
          operationId,
          observation.scope(identity[0]));
    }
  }

  private int pendingRateReservations(RateLimit limit, Instant windowStart) {
    return pendingRateReservations.getOrDefault(rateReservationKey(limit, windowStart), 0);
  }

  private static String rateReservationKey(RateLimit limit, Instant windowStart) {
    return AppNetworkBudgetScope.normalize(limit.appId())
        + '\n'
        + limit.operation().jsonValue()
        + '\n'
        + windowStart;
  }

  private List<RateLimit> rateLimits(String appId, AppNetworkBudgetOperation operation) {
    ArrayList<RateLimit> limits = new ArrayList<>();
    switch (operation) {
      case FOREGROUND_CONTENT_FETCH, TRUST_GRAPH_IMPORT_URI -> {
        limits.add(
            new RateLimit(
                appId,
                AppNetworkBudgetOperation.FOREGROUND_CONTENT_FETCH,
                MINUTE_WINDOW,
                config.foregroundContentFetchPerAppPerMinute()));
        limits.add(contentFetchGlobalRateLimit());
      }
      case SUBSCRIPTION_POLL, SUBSCRIPTION_MANUAL_REFRESH -> {
        limits.add(
            new RateLimit(
                appId,
                AppNetworkBudgetOperation.SUBSCRIPTION_POLL,
                HOUR_WINDOW,
                config.subscriptionPollPerAppPerHour()));
        limits.add(
            new RateLimit(
                GLOBAL_SCOPE_ID,
                AppNetworkBudgetOperation.SUBSCRIPTION_POLL,
                HOUR_WINDOW,
                config.subscriptionPollGlobalPerHour()));
        limits.add(contentFetchGlobalRateLimit());
      }
      case TRUST_GRAPH_IMPORT -> {
        limits.add(
            new RateLimit(
                appId,
                AppNetworkBudgetOperation.TRUST_GRAPH_IMPORT,
                HOUR_WINDOW,
                config.trustGraphImportPerAppPerHour()));
        limits.add(
            new RateLimit(
                GLOBAL_SCOPE_ID,
                AppNetworkBudgetOperation.TRUST_GRAPH_IMPORT,
                HOUR_WINDOW,
                config.trustGraphImportGlobalPerHour()));
      }
      case CONTENT_FETCH_GLOBAL -> limits.add(contentFetchGlobalRateLimit());
    }
    return limits;
  }

  private List<ConcurrencyLimit> concurrencyLimits(
      String appId, AppNetworkBudgetOperation operation) {
    ArrayList<ConcurrencyLimit> limits = new ArrayList<>();
    switch (operation) {
      case FOREGROUND_CONTENT_FETCH, TRUST_GRAPH_IMPORT_URI -> {
        limits.add(
            new ConcurrencyLimit(
                appId,
                AppNetworkBudgetOperation.FOREGROUND_CONTENT_FETCH,
                config.foregroundContentFetchConcurrentPerApp()));
        limits.add(contentFetchGlobalConcurrencyLimit());
      }
      case SUBSCRIPTION_POLL, SUBSCRIPTION_MANUAL_REFRESH -> {
        limits.add(
            new ConcurrencyLimit(
                appId,
                AppNetworkBudgetOperation.SUBSCRIPTION_POLL,
                config.subscriptionPollConcurrentPerApp()));
        limits.add(
            new ConcurrencyLimit(
                GLOBAL_SCOPE_ID,
                AppNetworkBudgetOperation.SUBSCRIPTION_POLL,
                config.subscriptionPollConcurrentGlobal()));
        limits.add(contentFetchGlobalConcurrencyLimit());
      }
      case TRUST_GRAPH_IMPORT -> {
        limits.add(
            new ConcurrencyLimit(
                appId,
                AppNetworkBudgetOperation.TRUST_GRAPH_IMPORT,
                config.trustGraphImportConcurrentPerApp()));
        limits.add(
            new ConcurrencyLimit(
                GLOBAL_SCOPE_ID,
                AppNetworkBudgetOperation.TRUST_GRAPH_IMPORT,
                config.trustGraphImportConcurrentGlobal()));
      }
      case CONTENT_FETCH_GLOBAL -> limits.add(contentFetchGlobalConcurrencyLimit());
    }
    return limits;
  }

  private RateLimit contentFetchGlobalRateLimit() {
    return new RateLimit(
        GLOBAL_SCOPE_ID,
        AppNetworkBudgetOperation.CONTENT_FETCH_GLOBAL,
        MINUTE_WINDOW,
        config.foregroundContentFetchGlobalPerMinute());
  }

  private ConcurrencyLimit contentFetchGlobalConcurrencyLimit() {
    return new ConcurrencyLimit(
        GLOBAL_SCOPE_ID,
        AppNetworkBudgetOperation.CONTENT_FETCH_GLOBAL,
        config.foregroundContentFetchConcurrentGlobal());
  }

  private int configuredLimit(String appId, AppNetworkBudgetOperation operation) {
    boolean global = AppNetworkBudgetScope.GLOBAL.equals(appId);
    return switch (operation) {
      case FOREGROUND_CONTENT_FETCH -> config.foregroundContentFetchPerAppPerMinute();
      case CONTENT_FETCH_GLOBAL, TRUST_GRAPH_IMPORT_URI ->
          config.foregroundContentFetchGlobalPerMinute();
      case SUBSCRIPTION_POLL ->
          global ? config.subscriptionPollGlobalPerHour() : config.subscriptionPollPerAppPerHour();
      case SUBSCRIPTION_MANUAL_REFRESH -> config.subscriptionPollPerAppPerHour();
      case TRUST_GRAPH_IMPORT ->
          global ? config.trustGraphImportGlobalPerHour() : config.trustGraphImportPerAppPerHour();
    };
  }

  private static Instant truncate(Instant now, Duration window) {
    long seconds = window.toSeconds();
    long epochSecond = now.getEpochSecond();
    return Instant.ofEpochSecond(Math.floorDiv(epochSecond, seconds) * seconds);
  }

  private static String rateErrorCode(AppNetworkBudgetOperation operation) {
    return switch (operation) {
      case FOREGROUND_CONTENT_FETCH, TRUST_GRAPH_IMPORT_URI, CONTENT_FETCH_GLOBAL ->
          "content_fetch_budget_exhausted";
      case SUBSCRIPTION_POLL, SUBSCRIPTION_MANUAL_REFRESH ->
          "content_subscription_budget_exhausted";
      case TRUST_GRAPH_IMPORT -> "trust_graph_import_budget_exhausted";
    };
  }

  private static String concurrencyErrorCode(AppNetworkBudgetOperation operation) {
    return switch (operation) {
      case SUBSCRIPTION_POLL, SUBSCRIPTION_MANUAL_REFRESH ->
          "content_subscription_concurrency_limited";
      case TRUST_GRAPH_IMPORT -> "trust_graph_import_concurrency_limited";
      default -> "network_budget_concurrency_limited";
    };
  }

  private static String rateMessage(AppNetworkBudgetOperation operation) {
    return switch (operation) {
      case SUBSCRIPTION_POLL, SUBSCRIPTION_MANUAL_REFRESH ->
          "Content subscription network budget is exhausted.";
      case TRUST_GRAPH_IMPORT -> "Trust Graph import budget is exhausted.";
      default -> "Content fetch budget is exhausted.";
    };
  }

  private static String concurrencyMessage(AppNetworkBudgetOperation operation) {
    return switch (operation) {
      case SUBSCRIPTION_POLL, SUBSCRIPTION_MANUAL_REFRESH ->
          "Content subscription network budget concurrency is exhausted.";
      case TRUST_GRAPH_IMPORT -> "Trust Graph import concurrency budget is exhausted.";
      default -> "App network budget concurrency is exhausted.";
    };
  }

  private record RateLimit(
      String appId, AppNetworkBudgetOperation operation, Duration window, int limit) {}

  private record ConcurrencyLimit(String appId, AppNetworkBudgetOperation operation, int limit) {
    String key() {
      return AppNetworkBudgetScope.normalize(appId) + '\n' + operation.jsonValue();
    }
  }
}
