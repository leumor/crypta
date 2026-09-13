package network.crypta.platform.api.content.subscriptions;

import java.io.IOException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Random;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Collectors;
import network.crypta.platform.api.PlatformApiException;
import network.crypta.platform.api.networkbudget.RuntimeWorkObservation;
import network.crypta.platform.apphost.AppHost;
import network.crypta.platform.apphost.InstalledAppSnapshot;

/**
 * Conservative background scheduler for app-owned USK content subscriptions.
 *
 * <p>The scheduler owns timing, due checks, pressure gating, installed-app capability checks, and
 * non-overlapping execution. Fetching, dedupe, and persistence are delegated to {@link
 * ContentSubscriptionService} so manual refreshes and background polls share one safe metadata
 * path. The scheduler never persists raw fetched content and never reads queue HTML.
 *
 * <p>Tests normally call {@link #tick(Instant)} with a fixed clock instant. Runtime wiring may call
 * {@link #start()} to create a single daemon-thread executor that performs the same pass at a fixed
 * delay after startup jitter. Each pass snapshots subscriptions, skips records that are paused or
 * not due, applies app capability and queue-pressure checks, and processes at most the configured
 * per-tick fetch limit. An atomic guard ensures a slow poll cannot overlap the next pass.
 */
public final class ContentSubscriptionScheduler {
  private static final System.Logger LOG =
      System.getLogger(ContentSubscriptionScheduler.class.getName());
  private static final String MESSAGE_APP_UNAVAILABLE =
      "Subscription poll skipped because the app is not installed or lacks required capabilities.";

  private final AppHost appHost;
  private final ContentSubscriptionService service;
  private final ContentSubscriptionSchedulerConfig config;
  private final ContentSubscriptionPressureGate pressureGate;
  private final Clock clock;
  private final Random random;
  private final AtomicBoolean running = new AtomicBoolean();
  private ScheduledExecutorService executor;
  private ScheduledFuture<?> scheduledTask;

  /**
   * Creates a scheduler using the system clock and nondeterministic jitter.
   *
   * <p>This constructor is intended for runtime wiring. It uses the UTC system clock for background
   * due checks and a {@link SecureRandom} source for startup and retry jitter. Tests should use the
   * overload that accepts explicit clock and random instances.
   *
   * @param appHost AppHost used to verify installed apps and manifest capabilities
   * @param service content subscription service that owns polling and persistence
   * @param config scheduler limits, timings, and enablement switch
   * @param pressureGate conservative queue and runtime pressure gate
   * @throws NullPointerException if any required dependency is {@code null}
   */
  public ContentSubscriptionScheduler(
      AppHost appHost,
      ContentSubscriptionService service,
      ContentSubscriptionSchedulerConfig config,
      ContentSubscriptionPressureGate pressureGate) {
    this(appHost, service, config, pressureGate, Clock.systemUTC(), new SecureRandom());
  }

  /**
   * Creates a scheduler with deterministic time and randomness for tests.
   *
   * <p>Supplying both the clock and jitter source makes due-time behavior reproducible. The
   * scheduler still uses the same no-overlap guard and service calls as production, so tests can
   * exercise queue pressure, backoff, app uninstall, and per-tick limit behavior without starting a
   * background thread.
   *
   * @param appHost AppHost used to verify installed apps and manifest capabilities
   * @param service content subscription service that owns polling and persistence
   * @param config scheduler limits, timings, and enablement switch
   * @param pressureGate conservative queue and runtime pressure gate
   * @param clock scheduler clock used by {@link #runDueTasksOnce()}
   * @param random jitter source used by background startup scheduling
   * @throws NullPointerException if any required dependency is {@code null}
   */
  public ContentSubscriptionScheduler(
      AppHost appHost,
      ContentSubscriptionService service,
      ContentSubscriptionSchedulerConfig config,
      ContentSubscriptionPressureGate pressureGate,
      Clock clock,
      Random random) {
    this.appHost = Objects.requireNonNull(appHost, "appHost");
    this.service = Objects.requireNonNull(service, "service");
    this.config = Objects.requireNonNull(config, "config");
    this.pressureGate = Objects.requireNonNull(pressureGate, "pressureGate");
    service.setPressureConfiguration(pressureGate.configuration());
    pressureGate.setObservation(service.observation());
    this.clock = Objects.requireNonNull(clock, "clock");
    this.random = Objects.requireNonNull(random, "random");
  }

  /**
   * Returns shared bounded causal observations; manual and executor ticks are distinct.
   *
   * @return shared bounded causal observations; manual and executor ticks are distinct
   */
  public RuntimeWorkObservation observation() {
    return service.observation();
  }

  /**
   * Starts the optional background executor when enabled.
   *
   * <p>The method is synchronized and idempotent. Calling it while the scheduler is disabled or
   * already started has no effect. When it starts successfully, the executor runs as a daemon
   * thread with startup delay plus jitter, then repeats with the configured fixed delay.
   */
  public synchronized void start() {
    if (!config.enabled() || executor != null) {
      return;
    }
    executor =
        Executors.newSingleThreadScheduledExecutor(
            runnable -> {
              Thread thread = new Thread(runnable, "Cryptad-ContentSubscriptionScheduler");
              thread.setDaemon(true);
              return thread;
            });
    long initialDelaySeconds = config.initialDelay().plus(jitter()).toSeconds();
    long pollSeconds = Math.max(1L, config.schedulerPollInterval().toSeconds());
    scheduledTask =
        executor.scheduleWithFixedDelay(
            this::runDueTasksOnceSafely, initialDelaySeconds, pollSeconds, TimeUnit.SECONDS);
  }

  /**
   * Runs one scheduler pass with the configured clock.
   *
   * <p>This method does not require the background executor to be started. It is useful for manual
   * runtime probes and tests that want the configured clock but still need the same no-overlap
   * guard and aggregate result that a scheduled pass would produce.
   *
   * @return deterministic tick result for the configured clock instant
   */
  public ContentSubscriptionSchedulerTickResult runDueTasksOnce() {
    return tick(clock.instant());
  }

  /**
   * Runs one deterministic non-overlapping scheduler pass.
   *
   * <p>The tick lists durable subscriptions, computes due work for the supplied instant, rechecks
   * app installation and required capabilities, applies runtime pressure, and delegates each
   * allowed poll to the service. If another pass is already running, this method returns a {@code
   * running} result instead of blocking or starting overlapping detached fetches.
   *
   * @param now scheduler time used for due checks, state updates, and backoff calculations
   * @return aggregate result for the pass, with safe counters and messages only
   * @throws NullPointerException if {@code now} is {@code null}
   */
  public ContentSubscriptionSchedulerTickResult tick(Instant now) {
    Instant checkedNow = Objects.requireNonNull(now, "now");
    if (!config.enabled()) {
      return ContentSubscriptionSchedulerTickResult.disabled(checkedNow);
    }
    if (!running.compareAndSet(false, true)) {
      observation().recordEvent(RuntimeWorkObservation.Kind.TICK_ALREADY_RUNNING);
      return ContentSubscriptionSchedulerTickResult.alreadyRunning(checkedNow);
    }
    observation().recordEvent(RuntimeWorkObservation.Kind.TICK_ENTERED);
    try {
      return runTick(checkedNow);
    } finally {
      observation().recordEvent(RuntimeWorkObservation.Kind.TICK_COMPLETED);
      running.set(false);
    }
  }

  /**
   * Stops the background executor if one was started.
   *
   * <p>The method cancels the scheduled task, asks the executor to shut down immediately, and
   * leaves deterministic foreground ticks available for callers that still hold a reference. It is
   * safe to call more than once and is used by runtime shutdown hooks.
   */
  public synchronized void close() {
    if (executor == null) {
      return;
    }
    if (scheduledTask != null) {
      scheduledTask.cancel(true);
      scheduledTask = null;
    }
    executor.shutdownNow();
    executor = null;
  }

  private void runDueTasksOnceSafely() {
    observation().recordEvent(RuntimeWorkObservation.Kind.EXECUTOR_TICK);
    try {
      runDueTasksOnce();
    } catch (RuntimeException exception) {
      LOG.log(System.Logger.Level.WARNING, "Content subscription scheduler pass failed", exception);
    }
  }

  private ContentSubscriptionSchedulerTickResult runTick(Instant now) {
    List<ContentSubscription> subscriptions;
    try {
      subscriptions = service.listAllForScheduler();
    } catch (PlatformApiException _) {
      observation().recordEvent(RuntimeWorkObservation.Kind.STORE_UNAVAILABLE);
      return new ContentSubscriptionSchedulerTickResult(
          now,
          ContentSubscriptionStatus.BACKOFF,
          0,
          1,
          0,
          now.plus(config.failureBackoff()),
          "Content subscription metadata could not be listed.");
    }
    if (subscriptions.isEmpty()) {
      return new ContentSubscriptionSchedulerTickResult(
          now,
          ContentSubscriptionStatus.SCHEDULED,
          0,
          0,
          0,
          null,
          "No content subscriptions are configured.");
    }
    Map<String, InstalledAppSnapshot> installedApps = installedAppsById();
    ContentSubscriptionPressureGate.PressureAssessment pressure = pressureGate.assess();
    observation().recordEvent(pressureObservationKind(pressure));
    int attempted = 0;
    int failures = 0;
    int skipped = 0;
    Instant nextDueAt = null;
    for (ContentSubscription subscription : subscriptions) {
      if (subscription.shouldSkipPollAt(now)) {
        observation()
            .recordEvent(
                subscription.status() == ContentSubscriptionStatus.PAUSED
                    ? RuntimeWorkObservation.Kind.PAUSED
                    : RuntimeWorkObservation.Kind.NOT_DUE);
        skipped++;
        nextDueAt = earliest(nextDueAt, subscription.nextCheckAt());
      } else if (attempted >= config.perTickFetchLimit()) {
        observation().recordEvent(RuntimeWorkObservation.Kind.DUE);
        observation().recordEvent(RuntimeWorkObservation.Kind.TICK_LIMIT);
        skipped++;
        nextDueAt = earliest(nextDueAt, now);
      } else if (!appMayRefresh(installedApps.get(subscription.appId()))) {
        observation().recordEvent(RuntimeWorkObservation.Kind.DUE);
        observation().recordEvent(RuntimeWorkObservation.Kind.CAPABILITY_DENIED);
        ContentSubscription skippedSubscription =
            service.schedulerSkip(
                subscription,
                now,
                ContentSubscriptionStatus.RUNTIME_UNAVAILABLE,
                "runtime_unavailable",
                MESSAGE_APP_UNAVAILABLE);
        failures++;
        skipped++;
        nextDueAt = earliest(nextDueAt, skippedSubscription.nextCheckAt());
      } else if (!pressure.allowed()) {
        observation().recordEvent(RuntimeWorkObservation.Kind.DUE);
        observation().recordEvent(RuntimeWorkObservation.Kind.PRESSURE_SKIP);
        ContentSubscription skippedSubscription =
            service.schedulerSkip(
                subscription, now, pressure.status(), pressure.errorCode(), pressure.message());
        failures++;
        skipped++;
        nextDueAt = earliest(nextDueAt, skippedSubscription.nextCheckAt());
      } else {
        observation().recordEvent(RuntimeWorkObservation.Kind.DUE);
        SchedulerPollOutcome outcome = pollDueSubscription(subscription, now);
        attempted += outcome.attempted();
        failures += outcome.failures();
        skipped += outcome.skipped();
        nextDueAt = earliest(nextDueAt, outcome.nextDueAt());
      }
    }
    return new ContentSubscriptionSchedulerTickResult(
        now,
        aggregateStatus(attempted, failures),
        attempted,
        failures,
        skipped,
        nextDueAt,
        aggregateMessage(attempted, failures, skipped));
  }

  private static RuntimeWorkObservation.Kind pressureObservationKind(
      ContentSubscriptionPressureGate.PressureAssessment pressure) {
    if (!pressure.allowed()) {
      if (pressure.contention()) {
        return RuntimeWorkObservation.Kind.PRESSURE_CONTENTION_BLOCKED;
      }
      return RuntimeWorkObservation.Kind.PRESSURE_AVAILABILITY_BLOCKED;
    }
    if (pressure.known()) {
      return RuntimeWorkObservation.Kind.PRESSURE_KNOWN_CLEAR;
    }
    return RuntimeWorkObservation.Kind.PRESSURE_UNKNOWN;
  }

  private SchedulerPollOutcome pollDueSubscription(ContentSubscription subscription, Instant now) {
    ContentSubscription result = service.schedulerPoll(subscription, now);
    if (result.status() == ContentSubscriptionStatus.BUDGET_EXHAUSTED) {
      return new SchedulerPollOutcome(0, 1, 1, result.nextCheckAt());
    }
    if (result.status() == ContentSubscriptionStatus.BACKOFF) {
      return new SchedulerPollOutcome(1, 1, 0, result.nextCheckAt());
    }
    return new SchedulerPollOutcome(1, 0, 0, result.nextCheckAt());
  }

  private Map<String, InstalledAppSnapshot> installedAppsById() {
    try {
      return appHost.listInstalled().stream()
          .sorted(Comparator.comparing(InstalledAppSnapshot::appId))
          .collect(Collectors.toMap(InstalledAppSnapshot::appId, app -> app, (left, _) -> left));
    } catch (IOException | RuntimeException _) {
      return Map.of();
    }
  }

  private static boolean appMayRefresh(InstalledAppSnapshot app) {
    if (app == null) {
      return false;
    }
    List<String> permissions = app.manifest().permissions();
    return permissions.contains(ContentSubscriptionService.CAPABILITY_CONTENT_SUBSCRIBE)
        && permissions.contains(ContentSubscriptionService.CAPABILITY_CONTENT_FETCH);
  }

  private static ContentSubscriptionStatus aggregateStatus(int attempted, int failures) {
    if (failures > 0) {
      return ContentSubscriptionStatus.BACKOFF;
    }
    return attempted == 0 ? ContentSubscriptionStatus.SCHEDULED : ContentSubscriptionStatus.SUCCESS;
  }

  private static String aggregateMessage(int attempted, int failures, int skipped) {
    if (failures > 0) {
      return "Content subscription scheduler pass completed with failures.";
    }
    if (attempted == 0 && skipped == 0) {
      return "No content subscriptions are configured.";
    }
    if (attempted == 0) {
      return "No content subscription poll was due.";
    }
    return "Content subscription scheduler pass completed.";
  }

  private Duration jitter() {
    long jitterSeconds = config.jitter().toSeconds();
    if (jitterSeconds <= 0L) {
      return Duration.ZERO;
    }
    long exclusiveBound = jitterSeconds == Long.MAX_VALUE ? Long.MAX_VALUE : jitterSeconds + 1L;
    return Duration.ofSeconds(random.nextLong(exclusiveBound));
  }

  private static Instant earliest(Instant left, Instant right) {
    if (left == null) {
      return right;
    }
    if (right == null) {
      return left;
    }
    return left.isBefore(right) ? left : right;
  }

  private record SchedulerPollOutcome(
      int attempted, int failures, int skipped, Instant nextDueAt) {}
}
