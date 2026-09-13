package network.crypta.platform.api.content.subscriptions;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Random;
import network.crypta.platform.api.PlatformApiException;
import network.crypta.platform.api.PlatformApiParameters;
import network.crypta.platform.api.networkbudget.AppNetworkBudgetDecision;
import network.crypta.platform.api.networkbudget.AppNetworkBudgetOperation;
import network.crypta.platform.api.networkbudget.AppNetworkBudgetReservation;
import network.crypta.platform.api.networkbudget.AppNetworkBudgetService;
import network.crypta.platform.api.networkbudget.RuntimeWorkObservation;
import network.crypta.platform.apphost.manifest.AppManifest;
import network.crypta.runtime.spi.BoundedContentFetchRequest;
import network.crypta.runtime.spi.BoundedContentFetchResult;
import network.crypta.runtime.spi.ContentFetchException;
import network.crypta.runtime.spi.ContentFetchPort;

/**
 * App-scoped service for durable bounded USK content subscriptions.
 *
 * <p>The service owns request validation, app scoping, metadata persistence, foreground refreshes,
 * scheduler-delegated polls, dedupe, and redaction. It stores only subscription metadata and fetch
 * result summaries; raw fetched content is digested and then discarded. API routes are responsible
 * for checking app principals and manifest capabilities before calling the app-facing methods,
 * while the scheduler uses the package-private methods to re-read current durable state before it
 * writes poll or skip results.
 *
 * <p>Every public method is synchronized because the current store contract is small and
 * file-oriented. The lock keeps create, pause, resume, delete, manual refresh, and scheduler
 * updates from overwriting one another inside this service. Store implementations still own their
 * own on-disk atomicity and recovery behavior.
 */
public final class ContentSubscriptionService {
  /**
   * Manifest capability for app-owned durable USK subscription metadata and controls.
   *
   * <p>Routes require this capability before an app can list, create, inspect, pause, resume,
   * refresh, or delete its subscriptions. The scheduler also checks it before polling after
   * restart.
   */
  public static final String CAPABILITY_CONTENT_SUBSCRIBE = "content.subscribe";

  /**
   * Manifest capability required whenever subscription creation or refresh can fetch content.
   *
   * <p>A subscription is a durable background fetch grant, so creation, manual refresh, and
   * scheduler polls require this capability in addition to {@link #CAPABILITY_CONTENT_SUBSCRIBE}.
   */
  public static final String CAPABILITY_CONTENT_FETCH = "content.fetch";

  private static final String DEFAULT_ERROR_CODE = "content_subscription_failed";
  private static final String PURPOSE = "content-subscription";
  private static final HexFormat HEX = HexFormat.of();

  private final RuntimeWorkObservation observation;
  private volatile ContentSubscriptionPressureGate.Configuration pressureConfiguration;
  private final ContentSubscriptionStore store;
  private final ContentFetchPort contentFetchPort;
  private final ContentSubscriptionSchedulerConfig config;
  private final AppNetworkBudgetService networkBudgetService;
  private final Clock clock;
  private final Random random;

  /**
   * Creates a service using system UTC time and secure random subscription ids.
   *
   * <p>This constructor is intended for runtime wiring. It uses UTC timestamps for durable metadata
   * and a {@link SecureRandom} source for opaque subscription ids and jitter. Tests should use the
   * overload with explicit clock and random instances.
   *
   * @param store durable metadata store for subscription records
   * @param contentFetchPort bounded runtime fetch port used for polls
   * @param config scheduler and app-facing request limits
   * @throws NullPointerException if any dependency is {@code null}
   */
  public ContentSubscriptionService(
      ContentSubscriptionStore store,
      ContentFetchPort contentFetchPort,
      ContentSubscriptionSchedulerConfig config) {
    this(store, contentFetchPort, config, null, Clock.systemUTC(), new SecureRandom());
  }

  /**
   * Creates a service using system UTC time, secure random subscription ids, and shared budgets.
   *
   * @param store durable metadata store for subscription records
   * @param contentFetchPort bounded runtime fetch port used for polls
   * @param config scheduler and app-facing request limits
   * @param networkBudgetService optional shared app-network budget service
   */
  public ContentSubscriptionService(
      ContentSubscriptionStore store,
      ContentFetchPort contentFetchPort,
      ContentSubscriptionSchedulerConfig config,
      AppNetworkBudgetService networkBudgetService) {
    this(
        store,
        contentFetchPort,
        config,
        networkBudgetService,
        Clock.systemUTC(),
        new SecureRandom());
  }

  /**
   * Creates a service with deterministic time and id randomness for tests.
   *
   * <p>The supplied clock drives API-visible timestamps, manual refresh timing, and scheduler state
   * transitions delegated through this service. The random source is used only for generated
   * subscription ids and bounded jitter, so deterministic tests can control both.
   *
   * @param store durable metadata store for subscription records
   * @param contentFetchPort bounded runtime fetch port used for polls
   * @param config scheduler and app-facing request limits
   * @param clock clock used for API actions and state transitions
   * @param random random source used for id generation and jitter
   * @throws NullPointerException if any dependency is {@code null}
   */
  public ContentSubscriptionService(
      ContentSubscriptionStore store,
      ContentFetchPort contentFetchPort,
      ContentSubscriptionSchedulerConfig config,
      Clock clock,
      Random random) {
    this(store, contentFetchPort, config, null, clock, random);
  }

  /**
   * Creates a service with deterministic time, id randomness, and optional shared budgets.
   *
   * @param store durable metadata store for subscription records
   * @param contentFetchPort bounded runtime fetch port used for polls
   * @param config scheduler and app-facing request limits
   * @param networkBudgetService optional shared app-network budget service
   * @param clock clock used for API actions and state transitions
   * @param random random source used for id generation and jitter
   */
  public ContentSubscriptionService(
      ContentSubscriptionStore store,
      ContentFetchPort contentFetchPort,
      ContentSubscriptionSchedulerConfig config,
      AppNetworkBudgetService networkBudgetService,
      Clock clock,
      Random random) {
    this.store = Objects.requireNonNull(store, "store");
    this.contentFetchPort = Objects.requireNonNull(contentFetchPort, "contentFetchPort");
    this.config = Objects.requireNonNull(config, "config");
    this.networkBudgetService = networkBudgetService;
    this.observation =
        networkBudgetService == null
            ? new RuntimeWorkObservation()
            : networkBudgetService.observation();
    this.clock = Objects.requireNonNull(clock, "clock");
    this.random = Objects.requireNonNull(random, "random");
  }

  /**
   * Returns bounded causal observations shared with the scheduler and budget service.
   *
   * <p>This intentionally returns the trusted native producer collaborator, so scheduler and budget
   * transitions share one causal sequence. Operator transport returns detached snapshots instead;
   * neither app principals nor browser principals can access the recording collaborator.
   *
   * @return bounded causal observations shared with the scheduler and budget service
   */
  public RuntimeWorkObservation observation() {
    return observation;
  }

  /**
   * Returns captured scheduler pressure policy, or null when no scheduler was constructed.
   *
   * @return captured scheduler pressure policy, or null when no scheduler was constructed
   */
  public ContentSubscriptionPressureGate.Configuration pressureConfiguration() {
    return pressureConfiguration;
  }

  void setPressureConfiguration(ContentSubscriptionPressureGate.Configuration configuration) {
    pressureConfiguration = configuration;
  }

  /**
   * Returns effective normalized subscription timing and limits.
   *
   * @return effective normalized subscription timing and limits
   */
  public ContentSubscriptionSchedulerConfig configuration() {
    return config;
  }

  /**
   * Lists subscriptions owned by one app.
   *
   * <p>The result is scoped to the normalized app id and contains only summary maps produced by the
   * durable subscription records. Raw fetched content, runtime fetch URIs, store paths, queue HTML,
   * and raw daemon exceptions are never included.
   *
   * @param appId app principal id supplied by the platform API route
   * @return safe summaries for subscriptions owned by the app
   * @throws PlatformApiException if the app id is invalid or the store cannot be read
   */
  public synchronized List<Map<String, Object>> list(String appId) {
    return listSubscriptions(appId).stream()
        .map(ContentSubscriptionService::summaryValues)
        .toList();
  }

  /**
   * Creates one app-owned USK subscription.
   *
   * <p>The request parser accepts only {@code USK@...} or {@code crypta:USK@...} sources and
   * applies configured byte, timeout, and poll-interval bounds before the record is written. The
   * method does not fetch content synchronously; it schedules the first due time using startup
   * delay and jitter. Per-app and global limits are enforced against durable records.
   *
   * @param appId app principal id supplied by the platform API route
   * @param parameters decoded form parameters from the create request body
   * @return safe subscription summary for the newly stored subscription
   * @throws PlatformApiException if validation fails, limits are reached, or the store is
   *     unavailable
   */
  public synchronized Map<String, Object> create(
      String appId, Map<String, List<String>> parameters) {
    String normalizedAppId = AppManifest.normalizeAppId(appId);
    ContentSubscriptionRequest request = parseCreateRequest(parameters);
    List<ContentSubscription> appSubscriptions = listSubscriptions(normalizedAppId);
    if (appSubscriptions.size() >= config.perAppSubscriptionLimit()) {
      throw new PlatformApiException(
          429,
          "content_subscription_limit_exceeded",
          "The app has reached its content subscription limit.");
    }
    if (listAllForScheduler().size() >= config.globalSubscriptionLimit()) {
      throw new PlatformApiException(
          429,
          "content_subscription_limit_exceeded",
          "The node has reached its content subscription limit.");
    }
    Instant now = clock.instant();
    ContentSubscription subscription =
        ContentSubscription.create(
            newSubscriptionId(),
            normalizedAppId,
            request.label(),
            request.source().sourceUri(),
            request.policy(),
            now,
            now.plus(config.initialDelay()).plus(jitter()));
    write(subscription);
    return summaryValues(subscription);
  }

  /**
   * Reads one app-owned subscription.
   *
   * <p>The lookup normalizes the app id and validates the subscription id as a single safe path
   * segment before reading the store. A subscription owned by another app is indistinguishable from
   * a missing subscription to preserve app scoping.
   *
   * @param appId app principal id supplied by the platform API route
   * @param subscriptionId subscription id path segment from the request
   * @return safe subscription summary for the owned record
   * @throws PlatformApiException if the subscription is missing or the store cannot be read
   */
  public synchronized Map<String, Object> get(String appId, String subscriptionId) {
    return summaryValues(requireOwned(appId, subscriptionId));
  }

  /**
   * Manually refreshes one app-owned subscription.
   *
   * <p>Manual refresh uses the same bounded detached fetch, digest calculation, resolved-edition
   * extraction, dedupe, and redaction path as a scheduler poll. The returned summary reflects
   * either the successful metadata update or a safe failure/backoff state.
   *
   * @param appId app principal id supplied by the platform API route
   * @param subscriptionId subscription id path segment from the request
   * @return safe subscription summary after the attempted refresh
   * @throws PlatformApiException if the subscription is missing or metadata cannot be persisted
   */
  public synchronized Map<String, Object> refresh(String appId, String subscriptionId) {
    return summaryValues(
        pollSubscription(
            requireOwned(appId, subscriptionId),
            clock.instant(),
            AppNetworkBudgetOperation.SUBSCRIPTION_MANUAL_REFRESH));
  }

  /**
   * Pauses one app-owned subscription.
   *
   * <p>Pausing disables scheduler polls and clears the next due time while preserving prior safe
   * fetch metadata. A paused subscription remains visible to its owning app and can be resumed
   * later without recreating the source record.
   *
   * @param appId app principal id supplied by the platform API route
   * @param subscriptionId subscription id path segment from the request
   * @return safe subscription summary after the pause is persisted
   * @throws PlatformApiException if the subscription is missing or the store cannot be written
   */
  public synchronized Map<String, Object> pause(String appId, String subscriptionId) {
    ContentSubscription paused = requireOwned(appId, subscriptionId).withPaused(clock.instant());
    write(paused);
    return summaryValues(paused);
  }

  /**
   * Resumes one app-owned subscription and makes it immediately due.
   *
   * <p>Resume re-enables scheduler polls and sets the next due time to the current service clock
   * instant. The scheduler may still delay the actual fetch because of per-tick limits, app
   * capability changes, queue pressure, or no-overlap protection.
   *
   * @param appId app principal id supplied by the platform API route
   * @param subscriptionId subscription id path segment from the request
   * @return safe subscription summary after the resuming is persisted
   * @throws PlatformApiException if the subscription is missing or the store cannot be written
   */
  public synchronized Map<String, Object> resume(String appId, String subscriptionId) {
    ContentSubscription resumed = requireOwned(appId, subscriptionId).withResumed(clock.instant());
    write(resumed);
    return summaryValues(resumed);
  }

  /**
   * Clears failure and backoff metadata without fetching content.
   *
   * <p>This operator recovery path leaves the source URI, last successful digest, edition, and
   * content metadata intact. It does not call the runtime fetch port and therefore does not consume
   * app-network budget. Enabled subscriptions become due immediately; paused subscriptions remain
   * paused so operators can decide when to resume them.
   *
   * @param appId app id that owns the subscription
   * @param subscriptionId subscription id path segment from the request
   * @return safe subscription summary after the metadata reset is persisted
   */
  public synchronized Map<String, Object> resetBackoff(String appId, String subscriptionId) {
    ContentSubscription reset =
        requireOwned(appId, subscriptionId).withBackoffReset(clock.instant());
    write(reset);
    return summaryValues(reset);
  }

  /**
   * Makes one enabled subscription due immediately without fetching content.
   *
   * <p>The scheduler still owns the next actual fetch and may skip it because of queue pressure,
   * app capability changes, no-overlap protection, or network budget policy. This method performs
   * only a metadata update and never calls the runtime fetch port.
   *
   * @param appId app id that owns the subscription
   * @param subscriptionId subscription id path segment from the request
   * @return safe subscription summary after the next due time is updated
   */
  public synchronized Map<String, Object> rescheduleNow(String appId, String subscriptionId) {
    ContentSubscription rescheduled =
        requireOwned(appId, subscriptionId).withRescheduledNow(clock.instant());
    write(rescheduled);
    return summaryValues(rescheduled);
  }

  /**
   * Deletes one app-owned subscription.
   *
   * <p>The durable record is removed from the store before a deleted-state summary is returned. The
   * summary gives callers a deterministic response body without leaving a deleted record for future
   * scheduler ticks.
   *
   * @param appId app principal id supplied by the platform API route
   * @param subscriptionId subscription id path segment from the request
   * @return safe summary of the deleted subscription
   * @throws PlatformApiException if the subscription is missing or the store cannot delete it
   */
  public synchronized Map<String, Object> delete(String appId, String subscriptionId) {
    ContentSubscription existing = requireOwned(appId, subscriptionId);
    try {
      store.delete(existing.appId(), existing.subscriptionId());
    } catch (IOException _) {
      throw storeFailed();
    }
    return summaryValues(existing.withDeleted(clock.instant()));
  }

  /**
   * Clears all subscription metadata for an app after uninstall.
   *
   * <p>This method is intended for app lifecycle cleanup, not for app-facing routes. Callers that
   * have already completed a destructive uninstall can treat failures as best-effort cleanup
   * failures and log them without changing the uninstallation result.
   *
   * @param appId app id whose subscriptions should be removed
   * @throws PlatformApiException if the app id is invalid or the store cleanup fails
   */
  public synchronized void clearAppState(String appId) {
    try {
      store.deleteAllForApp(AppManifest.normalizeAppId(appId));
    } catch (IOException _) {
      throw storeFailed();
    }
  }

  /**
   * Lists all durable subscription summaries for a trusted local operator view.
   *
   * <p>The app-facing route family intentionally scopes reads to the authenticated app principal.
   * The Web Shell beta dashboard needs a host/operator inventory across installed apps, so this
   * method exposes the same safe summary projection for every durable record in deterministic
   * app/subscription order. It still omits runtime fetch URIs, raw fetched content, store paths,
   * queue output, and daemon exception text.
   *
   * @return safe summaries for all durable subscriptions
   * @throws PlatformApiException if the store cannot be read
   */
  public synchronized List<Map<String, Object>> listAllForOperator() {
    return listAllForScheduler().stream().map(ContentSubscriptionService::summaryValues).toList();
  }

  synchronized List<ContentSubscription> listAllForScheduler() {
    try {
      return store.listAll().stream()
          .sorted(
              Comparator.comparing(ContentSubscription::appId)
                  .thenComparing(ContentSubscription::subscriptionId))
          .toList();
    } catch (IOException _) {
      throw storeFailed();
    }
  }

  synchronized ContentSubscription schedulerPoll(ContentSubscription subscription, Instant now) {
    ContentSubscription current =
        readOptional(subscription.appId(), subscription.subscriptionId()).orElse(null);
    if (current == null) {
      return subscription.withDeleted(now);
    }
    if (current.shouldSkipPollAt(now)) {
      return current;
    }
    return pollSubscription(current, now, AppNetworkBudgetOperation.SUBSCRIPTION_POLL);
  }

  synchronized ContentSubscription schedulerSkip(
      ContentSubscription subscription,
      Instant now,
      ContentSubscriptionStatus status,
      String errorCode,
      String message) {
    ContentSubscription current =
        readOptional(subscription.appId(), subscription.subscriptionId()).orElse(null);
    if (current == null) {
      return subscription.withDeleted(now);
    }
    if (current.shouldSkipPollAt(now)) {
      return current;
    }
    ContentSubscription skipped =
        current.withSkipped(now, nextAfterFailure(now, current), status, errorCode, message);
    write(skipped);
    observation.recordEvent(
        RuntimeWorkObservation.Kind.RETRY_SCHEDULED,
        null,
        0,
        skipped.nextCheckAt().getEpochSecond());
    return skipped;
  }

  private ContentSubscription pollSubscription(
      ContentSubscription subscription, Instant now, AppNetworkBudgetOperation operation) {
    try (var budgetReservation = reserveBudget(subscription.appId(), operation)) {
      AppNetworkBudgetDecision budgetDecision = budgetReservation.decision();
      if (!budgetDecision.allowed()) {
        ContentSubscription skipped =
            subscription.withSkipped(
                now,
                nextAfterBudgetDenied(now, subscription, budgetDecision),
                ContentSubscriptionStatus.BUDGET_EXHAUSTED,
                budgetDecision.errorCode(),
                budgetDecision.message());
        write(skipped);
        return skipped;
      }
      ContentSubscription running = subscription.withRunning(now);
      write(running);
      AppNetworkBudgetDecision committedBudget = budgetReservation.commit();
      if (!committedBudget.allowed()) {
        ContentSubscription skipped =
            running.withSkipped(
                now,
                nextAfterBudgetDenied(now, running, committedBudget),
                ContentSubscriptionStatus.BUDGET_EXHAUSTED,
                committedBudget.errorCode(),
                committedBudget.message());
        write(skipped);
        return skipped;
      }
      return fetchAndRecordResult(running, now, operation, budgetReservation.observationId());
    }
  }

  private ContentSubscription fetchAndRecordResult(
      ContentSubscription running,
      Instant now,
      AppNetworkBudgetOperation operation,
      long operationId) {
    try {
      observation.recordEvent(
          RuntimeWorkObservation.Kind.FETCH_INVOKED, operation, 0, 0, operationId, 0);
      BoundedContentFetchResult result =
          contentFetchPort.fetchContent(
              new BoundedContentFetchRequest(
                  running.runtimeFetchUri(),
                  running.policy().maxBytes(),
                  running.policy().timeout(),
                  PURPOSE));
      byte[] bytes = result.bytes();
      if (bytes.length > running.policy().maxBytes()) {
        ContentSubscription failed =
            running.withFailure(
                now,
                nextAfterFailure(now, running),
                "content_fetch_too_large",
                "Subscription fetch exceeded the configured byte bound.");
        write(failed);
        observation.recordEvent(
            RuntimeWorkObservation.Kind.FETCH_FAILED, operation, 0, 0, operationId, 0);
        observation.recordEvent(
            RuntimeWorkObservation.Kind.RETRY_SCHEDULED,
            operation,
            0,
            failed.nextCheckAt().getEpochSecond());
        return failed;
      }
      String resolvedUri = ContentSubscriptionSource.sanitizeResolvedUri(result.resolvedUri());
      Long resolvedEdition = ContentSubscriptionSource.resolvedUskEdition(result.resolvedUri());
      String digest = sha256(bytes);
      boolean changed = contentChanged(running, resolvedUri, resolvedEdition, digest);
      ContentSubscription success =
          running.withSuccess(
              now,
              now.plus(running.policy().pollInterval()).plus(jitter()),
              resolvedUri,
              resolvedEdition,
              digest,
              bytes.length,
              changed);
      write(success);
      observation.recordEvent(
          RuntimeWorkObservation.Kind.FETCH_SUCCEEDED, operation, 0, 0, operationId, 0);
      observation.recordEvent(
          RuntimeWorkObservation.Kind.NEXT_DUE,
          operation,
          0,
          success.nextCheckAt().getEpochSecond());
      return success;
    } catch (ContentFetchException exception) {
      ContentSubscription failed =
          running.withFailure(
              now,
              nextAfterFailure(now, running),
              mappedFetchErrorCode(exception),
              "Subscription fetch failed.");
      write(failed);
      observation.recordEvent(
          RuntimeWorkObservation.Kind.FETCH_FAILED, operation, 0, 0, operationId, 0);
      observation.recordEvent(
          RuntimeWorkObservation.Kind.RETRY_SCHEDULED,
          operation,
          0,
          failed.nextCheckAt().getEpochSecond());
      return failed;
    } catch (RuntimeException _) {
      ContentSubscription failed =
          running.withFailure(
              now,
              nextAfterFailure(now, running),
              DEFAULT_ERROR_CODE,
              "Subscription fetch failed.");
      write(failed);
      observation.recordEvent(
          RuntimeWorkObservation.Kind.FETCH_FAILED, operation, 0, 0, operationId, 0);
      observation.recordEvent(
          RuntimeWorkObservation.Kind.RETRY_SCHEDULED,
          operation,
          0,
          failed.nextCheckAt().getEpochSecond());
      return failed;
    }
  }

  private AppNetworkBudgetReservation reserveBudget(
      String appId, AppNetworkBudgetOperation operation) {
    if (networkBudgetService == null) {
      return AppNetworkBudgetReservation.noop(
          AppManifest.normalizeAppId(appId), operation, clock.instant());
    }
    return networkBudgetService.reserve(appId, operation);
  }

  private Instant nextAfterBudgetDenied(
      Instant now, ContentSubscription subscription, AppNetworkBudgetDecision decision) {
    Instant backoffNext = nextAfterFailure(now, subscription);
    Instant budgetNext = decision.nextAvailableAt();
    if (budgetNext == null) {
      return backoffNext;
    }
    return budgetNext.isAfter(backoffNext) ? budgetNext : backoffNext;
  }

  private ContentSubscriptionRequest parseCreateRequest(Map<String, List<String>> parameters) {
    String label = PlatformApiParameters.requireString(parameters, "label");
    String rawUri = PlatformApiParameters.requireString(parameters, "uri");
    ContentSubscriptionSource source = ContentSubscriptionSource.normalizeSourceUri(rawUri);
    ContentSubscriptionPolicy policy =
        new ContentSubscriptionPolicy(
            Duration.ofSeconds(
                readPositiveLong(
                    parameters,
                    "pollIntervalSeconds",
                    config.defaultPollInterval().toSeconds(),
                    config.maximumPollInterval().toSeconds(),
                    config.minimumPollInterval().toSeconds())),
            readPositiveLong(
                parameters, "maxBytes", config.defaultMaxBytes(), config.hardMaxBytes(), 1L),
            Duration.ofMillis(
                readPositiveLong(
                    parameters,
                    "timeoutMillis",
                    config.defaultTimeout().toMillis(),
                    config.hardTimeout().toMillis(),
                    1L)));
    return new ContentSubscriptionRequest(label, source, policy);
  }

  private static Map<String, Object> summaryValues(ContentSubscription subscription) {
    return ContentSubscriptionSummary.from(subscription).values();
  }

  private List<ContentSubscription> listSubscriptions(String appId) {
    try {
      return store.listForApp(AppManifest.normalizeAppId(appId));
    } catch (IOException _) {
      throw storeFailed();
    }
  }

  private ContentSubscription requireOwned(String appId, String subscriptionId) {
    return readOptional(appId, subscriptionId)
        .orElseThrow(
            () ->
                new PlatformApiException(
                    404, "content_subscription_not_found", "Content subscription not found."));
  }

  private java.util.Optional<ContentSubscription> readOptional(
      String appId, String subscriptionId) {
    try {
      return store.read(
          AppManifest.normalizeAppId(appId),
          ContentSubscription.requireSubscriptionId(subscriptionId));
    } catch (IOException _) {
      throw storeFailed();
    }
  }

  private void write(ContentSubscription subscription) {
    try {
      store.write(subscription);
    } catch (IOException _) {
      throw storeFailed();
    }
  }

  private String newSubscriptionId() {
    byte[] bytes = new byte[12];
    random.nextBytes(bytes);
    return "sub-" + HEX.formatHex(bytes);
  }

  private Instant nextAfterFailure(Instant now, ContentSubscription subscription) {
    return now.plus(failureBackoff(subscription.failureCount() + 1)).plus(jitter());
  }

  private Duration failureBackoff(int failureCount) {
    long baseSeconds = Math.max(1L, config.failureBackoff().toSeconds());
    long maxSeconds = Math.max(baseSeconds, config.maximumFailureBackoff().toSeconds());
    long delay = baseSeconds;
    for (int index = 1; index < failureCount && delay < maxSeconds; index++) {
      if (delay > maxSeconds / 2L) {
        delay = maxSeconds;
      } else {
        delay *= 2L;
      }
    }
    return Duration.ofSeconds(Math.min(delay, maxSeconds));
  }

  private Duration jitter() {
    long jitterSeconds = config.jitter().toSeconds();
    if (jitterSeconds <= 0L) {
      return Duration.ZERO;
    }
    long exclusiveBound = jitterSeconds == Long.MAX_VALUE ? Long.MAX_VALUE : jitterSeconds + 1L;
    return Duration.ofSeconds(random.nextLong(exclusiveBound));
  }

  private static boolean contentChanged(
      ContentSubscription subscription, String resolvedUri, Long edition, String digest) {
    if (subscription.contentSha256() == null) {
      return true;
    }
    boolean digestUnchanged = Objects.equals(subscription.contentSha256(), digest);
    boolean resolvedUnchanged =
        Objects.equals(subscription.lastSeenResolvedUri(), resolvedUri)
            && Objects.equals(subscription.lastSeenEdition(), edition);
    return !(digestUnchanged && resolvedUnchanged);
  }

  private static String sha256(byte[] bytes) {
    try {
      return HEX.formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    } catch (NoSuchAlgorithmException exception) {
      throw new IllegalStateException("SHA-256 is unavailable", exception);
    }
  }

  private static String mappedFetchErrorCode(ContentFetchException exception) {
    return switch (exception.errorCode()) {
      case ContentFetchException.CATALOG_FETCH_TIMEOUT -> "content_fetch_timeout";
      case ContentFetchException.CATALOG_FETCH_TOO_LARGE -> "content_fetch_too_large";
      case ContentFetchException.INVALID_CATALOG_SOURCE -> "invalid_content_uri";
      default -> "content_fetch_failed";
    };
  }

  private static long readPositiveLong(
      Map<String, List<String>> parameters,
      String name,
      long defaultValue,
      long hardLimit,
      long floor) {
    String raw = PlatformApiParameters.readOptionalString(parameters, name);
    if (raw == null || raw.isBlank()) {
      return Math.max(defaultValue, floor);
    }
    long value;
    try {
      value = Long.parseLong(raw.trim());
    } catch (NumberFormatException _) {
      throw invalidPositiveInteger(name);
    }
    if (value < floor || value <= 0L) {
      throw invalidPositiveInteger(name);
    }
    if (value > hardLimit) {
      throw new PlatformApiException(
          400,
          "invalid_query_parameter",
          "Query parameter '" + name + "' exceeds the supported app-facing limit.");
    }
    return value;
  }

  private static PlatformApiException invalidPositiveInteger(String name) {
    return new PlatformApiException(
        400,
        "invalid_query_parameter",
        "Query parameter '" + name + "' must be a positive integer within the supported range.");
  }

  private static PlatformApiException storeFailed() {
    return new PlatformApiException(
        503,
        "content_subscription_store_failed",
        "Content subscription metadata store is unavailable.");
  }
}
