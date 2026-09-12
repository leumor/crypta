package network.crypta.platform.api.content.subscriptions;

import java.time.Duration;
import java.util.Map;
import java.util.Objects;

/**
 * Local limits and timing policy for app-owned content subscriptions.
 *
 * <p>The defaults are conservative and intentionally small. A node may poll due USK subscriptions
 * in the background, but each poll is still a bounded detached content fetch with a per-app limit,
 * global limit, per-tick limit, minimum poll interval, jitter, and bounded failure backoff.
 * Configuration values loaded from the process environment are local operator controls, not part of
 * the app-facing platform contract.
 *
 * <p>Only a small set of values is currently configurable through system properties or environment
 * variables. The remaining ceilings are fixed defaults so this feature stays a bounded subscription
 * scheduler rather than a crawler. The constructor normalizes related ceilings upward or downward
 * where needed, for example by ensuring the global limit is never lower than the per-app limit.
 *
 * @param enabled whether the optional background scheduler may start automatically
 * @param initialDelay delay before new subscriptions and background startup become due
 * @param schedulerPollInterval fixed delay between background due-work passes
 * @param defaultPollInterval default interval assigned to new subscriptions
 * @param minimumPollInterval minimum accepted per-subscription poll interval
 * @param maximumPollInterval maximum accepted per-subscription poll interval
 * @param jitter maximum random delay added to due times and failure backoff
 * @param failureBackoff first retry delay after a failed or pressure-skipped poll
 * @param maximumFailureBackoff maximum retry delay after repeated failures
 * @param perAppSubscriptionLimit maximum durable subscriptions one app may own
 * @param globalSubscriptionLimit maximum durable subscriptions across all apps
 * @param perTickFetchLimit maximum due subscriptions fetched in one scheduler tick
 * @param defaultMaxBytes default detached fetch byte bound for new subscriptions
 * @param hardMaxBytes maximum accepted detached fetch byte bound
 * @param defaultTimeout default detached fetch timeout for new subscriptions
 * @param hardTimeout maximum accepted detached fetch timeout
 */
public record ContentSubscriptionSchedulerConfig(
    boolean enabled,
    Duration initialDelay,
    Duration schedulerPollInterval,
    Duration defaultPollInterval,
    Duration minimumPollInterval,
    Duration maximumPollInterval,
    Duration jitter,
    Duration failureBackoff,
    Duration maximumFailureBackoff,
    int perAppSubscriptionLimit,
    int globalSubscriptionLimit,
    int perTickFetchLimit,
    long defaultMaxBytes,
    long hardMaxBytes,
    Duration defaultTimeout,
    Duration hardTimeout) {
  /**
   * System property used to enable or disable the background subscription scheduler.
   *
   * <p>Accepted values are {@code true}, {@code false}, {@code 1}, and {@code 0}. Invalid values
   * leave the default in force, and this property takes precedence over the matching environment
   * variable.
   */
  public static final String ENABLED_PROPERTY = "cryptad.content.subscriptions.scheduler.enabled";

  /**
   * Environment variable used to enable or disable the background subscription scheduler.
   *
   * <p>The value is read only when {@link #ENABLED_PROPERTY} is absent or blank. Unknown values are
   * ignored so a malformed environment does not silently disable app subscriptions.
   */
  public static final String ENABLED_ENV = "CRYPTAD_CONTENT_SUBSCRIPTIONS_SCHEDULER_ENABLED";

  /**
   * System property for the scheduler startup delay in seconds.
   *
   * <p>The delay may be zero but not negative. It controls the initial background start and the
   * first due time assigned to newly created subscriptions.
   */
  public static final String INITIAL_DELAY_PROPERTY =
      "cryptad.content.subscriptions.scheduler.initialDelaySeconds";

  /**
   * Environment variable for the scheduler startup delay in seconds.
   *
   * <p>The value is used only when the matching system property is absent. Invalid or negative
   * values fall back to the conservative default.
   */
  public static final String INITIAL_DELAY_ENV =
      "CRYPTAD_CONTENT_SUBSCRIPTIONS_SCHEDULER_INITIAL_DELAY_SECONDS";

  /**
   * System property for the scheduler wakeup interval in seconds.
   *
   * <p>This controls how often the optional background executor asks for due work. It does not
   * override per-subscription poll intervals or per-tick fetch limits.
   */
  public static final String SCHEDULER_POLL_INTERVAL_PROPERTY =
      "cryptad.content.subscriptions.scheduler.pollIntervalSeconds";

  /**
   * Environment variable for the scheduler wakeup interval in seconds.
   *
   * <p>Positive whole seconds are accepted. Blank, zero, negative, or non-numeric values keep the
   * default scheduler wakeup interval.
   */
  public static final String SCHEDULER_POLL_INTERVAL_ENV =
      "CRYPTAD_CONTENT_SUBSCRIPTIONS_SCHEDULER_POLL_INTERVAL_SECONDS";

  /**
   * System property for the minimum accepted subscription poll interval in seconds.
   *
   * <p>Creation requests below this floor are clamped or rejected by the service. The floor
   * protects the node from app requests that would turn subscriptions into high-frequency polling.
   */
  public static final String MINIMUM_POLL_INTERVAL_PROPERTY =
      "cryptad.content.subscriptions.minimumPollIntervalSeconds";

  /**
   * Environment variable for the minimum accepted subscription poll interval in seconds.
   *
   * <p>The value participates in the same normalization as the system property and cannot make the
   * maximum poll interval lower than the minimum.
   */
  public static final String MINIMUM_POLL_INTERVAL_ENV =
      "CRYPTAD_CONTENT_SUBSCRIPTIONS_MINIMUM_POLL_INTERVAL_SECONDS";

  /**
   * System property for the per-app subscription limit.
   *
   * <p>The limit counts durable records owned by a single app id. It is enforced before creation
   * and continues to matter across node restarts because subscriptions are persisted.
   */
  public static final String PER_APP_LIMIT_PROPERTY = "cryptad.content.subscriptions.perAppLimit";

  /**
   * Environment variable for the per-app subscription limit.
   *
   * <p>Positive integers are accepted. The global limit is normalized so it is at least as large as
   * the configured per-app limit.
   */
  public static final String PER_APP_LIMIT_ENV = "CRYPTAD_CONTENT_SUBSCRIPTIONS_PER_APP_LIMIT";

  /**
   * System property for the global subscription limit.
   *
   * <p>The limit caps all durable subscription records, regardless of app owner. It keeps stale or
   * abusive app state from consuming unbounded scheduler work.
   */
  public static final String GLOBAL_LIMIT_PROPERTY = "cryptad.content.subscriptions.globalLimit";

  /**
   * Environment variable for the global subscription limit.
   *
   * <p>Positive integers are accepted. If the configured value is below the per-app limit, the
   * constructor raises it to the per-app limit to preserve a coherent configuration.
   */
  public static final String GLOBAL_LIMIT_ENV = "CRYPTAD_CONTENT_SUBSCRIPTIONS_GLOBAL_LIMIT";

  /**
   * System property for the per-tick fetch limit.
   *
   * <p>This value bounds detached fetch attempts per scheduler pass. It is the main pressure
   * control used when queue pressure is unknown but no stable runtime signal says polling must
   * stop.
   */
  public static final String PER_TICK_LIMIT_PROPERTY =
      "cryptad.content.subscriptions.scheduler.perTickFetchLimit";

  /**
   * Environment variable for the per-tick fetch limit.
   *
   * <p>Positive integers are accepted. The limit applies to deterministic test ticks and to the
   * optional background executor in the same way.
   */
  public static final String PER_TICK_LIMIT_ENV =
      "CRYPTAD_CONTENT_SUBSCRIPTIONS_SCHEDULER_PER_TICK_FETCH_LIMIT";

  /** Operator-only maximum jitter in seconds; zero is allowed for synthetic integration. */
  public static final String JITTER_ENV = "CRYPTAD_CONTENT_SUBSCRIPTIONS_SCHEDULER_JITTER_SECONDS";

  /** Operator-only first failure retry in seconds; must be positive. */
  public static final String FAILURE_BACKOFF_ENV =
      "CRYPTAD_CONTENT_SUBSCRIPTIONS_FAILURE_BACKOFF_SECONDS";

  /** Operator-only maximum failure retry in seconds; normalized to at least the first retry. */
  public static final String MAXIMUM_FAILURE_BACKOFF_ENV =
      "CRYPTAD_CONTENT_SUBSCRIPTIONS_MAXIMUM_FAILURE_BACKOFF_SECONDS";

  private static final ContentSubscriptionSchedulerConfig DEFAULT =
      new ContentSubscriptionSchedulerConfig(
          true,
          Duration.ofMinutes(5),
          Duration.ofMinutes(1),
          Duration.ofMinutes(30),
          Duration.ofMinutes(5),
          Duration.ofHours(24),
          Duration.ofMinutes(1),
          Duration.ofMinutes(5),
          Duration.ofHours(1),
          16,
          256,
          4,
          262_144L,
          1_048_576L,
          Duration.ofSeconds(30),
          Duration.ofSeconds(60));

  /**
   * Creates a validated scheduler configuration.
   *
   * <p>All durations except startup delay and jitter must be positive. Startup delay and jitter may
   * be zero, which is useful for deterministic tests. The constructor also normalizes dependent
   * limits so callers cannot accidentally create a configuration whose default poll interval sits
   * outside the configured range or whose hard fetch ceilings are lower than the defaults.
   *
   * @throws NullPointerException if any duration component is {@code null}
   * @throws IllegalArgumentException if required durations, counters, or byte limits are
   *     nonpositive
   */
  public ContentSubscriptionSchedulerConfig {
    requireNonNegative(initialDelay, "initialDelay");
    requirePositive(schedulerPollInterval, "schedulerPollInterval");
    requirePositive(defaultPollInterval, "defaultPollInterval");
    requirePositive(minimumPollInterval, "minimumPollInterval");
    requirePositive(maximumPollInterval, "maximumPollInterval");
    requireNonNegative(jitter, "jitter");
    requirePositive(failureBackoff, "failureBackoff");
    requirePositive(maximumFailureBackoff, "maximumFailureBackoff");
    requirePositive(defaultTimeout, "defaultTimeout");
    requirePositive(hardTimeout, "hardTimeout");
    if (maximumPollInterval.compareTo(minimumPollInterval) < 0) {
      maximumPollInterval = minimumPollInterval;
    }
    if (defaultPollInterval.compareTo(minimumPollInterval) < 0) {
      defaultPollInterval = minimumPollInterval;
    }
    if (defaultPollInterval.compareTo(maximumPollInterval) > 0) {
      defaultPollInterval = maximumPollInterval;
    }
    if (maximumFailureBackoff.compareTo(failureBackoff) < 0) {
      maximumFailureBackoff = failureBackoff;
    }
    if (hardTimeout.compareTo(defaultTimeout) < 0) {
      hardTimeout = defaultTimeout;
    }
    if (perAppSubscriptionLimit <= 0
        || globalSubscriptionLimit <= 0
        || perTickFetchLimit <= 0
        || defaultMaxBytes <= 0
        || hardMaxBytes <= 0) {
      throw new IllegalArgumentException("subscription limits must be positive");
    }
    if (globalSubscriptionLimit < perAppSubscriptionLimit) {
      globalSubscriptionLimit = perAppSubscriptionLimit;
    }
    if (hardMaxBytes < defaultMaxBytes) {
      hardMaxBytes = defaultMaxBytes;
    }
  }

  /**
   * Returns the default conservative configuration.
   *
   * <p>The default enables the scheduler but keeps startup delayed, polling coarse, detached
   * fetches bounded, and per-tick work small. Tests that need different timing should construct an
   * explicit config instead of mutating this shared record.
   *
   * @return immutable default scheduler configuration
   */
  public static ContentSubscriptionSchedulerConfig defaults() {
    return DEFAULT;
  }

  /**
   * Loads locally configured values from system properties and environment variables.
   *
   * <p>System properties take precedence over environment variables. Malformed local values are
   * ignored in favor of defaults so a typo does not produce a partially initialized scheduler. The
   * method does not read app manifests or durable subscription state.
   *
   * @return immutable scheduler configuration for the current process
   */
  public static ContentSubscriptionSchedulerConfig loadFromSystem() {
    return from(System.getProperties(), System.getenv());
  }

  static ContentSubscriptionSchedulerConfig from(
      Map<?, ?> properties, Map<String, String> environment) {
    Objects.requireNonNull(properties, "properties");
    Objects.requireNonNull(environment, "environment");
    ContentSubscriptionSchedulerConfig defaults = defaults();
    String configuredEnabled =
        configuredValue(properties, environment, ENABLED_PROPERTY, ENABLED_ENV);
    boolean schedulerEnabled = defaults.enabled();
    if ("true".equalsIgnoreCase(configuredEnabled) || "1".equals(configuredEnabled)) {
      schedulerEnabled = true;
    } else if ("false".equalsIgnoreCase(configuredEnabled) || "0".equals(configuredEnabled)) {
      schedulerEnabled = false;
    }
    return new ContentSubscriptionSchedulerConfig(
        schedulerEnabled,
        durationSetting(
            properties,
            environment,
            INITIAL_DELAY_PROPERTY,
            INITIAL_DELAY_ENV,
            defaults.initialDelay(),
            false),
        durationSetting(
            properties,
            environment,
            SCHEDULER_POLL_INTERVAL_PROPERTY,
            SCHEDULER_POLL_INTERVAL_ENV,
            defaults.schedulerPollInterval(),
            true),
        defaults.defaultPollInterval(),
        durationSetting(
            properties,
            environment,
            MINIMUM_POLL_INTERVAL_PROPERTY,
            MINIMUM_POLL_INTERVAL_ENV,
            defaults.minimumPollInterval(),
            true),
        defaults.maximumPollInterval(),
        durationSetting(
            properties,
            environment,
            "cryptad.content.subscriptions.scheduler.jitterSeconds",
            JITTER_ENV,
            defaults.jitter(),
            false),
        durationSetting(
            properties,
            environment,
            "cryptad.content.subscriptions.failureBackoffSeconds",
            FAILURE_BACKOFF_ENV,
            defaults.failureBackoff(),
            true),
        durationSetting(
            properties,
            environment,
            "cryptad.content.subscriptions.maximumFailureBackoffSeconds",
            MAXIMUM_FAILURE_BACKOFF_ENV,
            defaults.maximumFailureBackoff(),
            true),
        integerSetting(
            properties,
            environment,
            PER_APP_LIMIT_PROPERTY,
            PER_APP_LIMIT_ENV,
            defaults.perAppSubscriptionLimit()),
        integerSetting(
            properties,
            environment,
            GLOBAL_LIMIT_PROPERTY,
            GLOBAL_LIMIT_ENV,
            defaults.globalSubscriptionLimit()),
        integerSetting(
            properties,
            environment,
            PER_TICK_LIMIT_PROPERTY,
            PER_TICK_LIMIT_ENV,
            defaults.perTickFetchLimit()),
        defaults.defaultMaxBytes(),
        defaults.hardMaxBytes(),
        defaults.defaultTimeout(),
        defaults.hardTimeout());
  }

  private static void requirePositive(Duration value, String name) {
    Objects.requireNonNull(value, name);
    if (value.isZero() || value.isNegative()) {
      throw new IllegalArgumentException(name + " must be positive");
    }
  }

  private static void requireNonNegative(Duration value, String name) {
    Objects.requireNonNull(value, name);
    if (value.isNegative()) {
      throw new IllegalArgumentException(name + " must be non-negative");
    }
  }

  private static Duration durationSetting(
      Map<?, ?> properties,
      Map<String, String> environment,
      String propertyName,
      String environmentName,
      Duration defaultValue,
      boolean positive) {
    String value = configuredValue(properties, environment, propertyName, environmentName);
    if (value == null) {
      return defaultValue;
    }
    try {
      long seconds = Long.parseLong(value);
      if (positive ? seconds <= 0L : seconds < 0L) {
        return defaultValue;
      }
      return Duration.ofSeconds(seconds);
    } catch (RuntimeException _) {
      return defaultValue;
    }
  }

  private static int integerSetting(
      Map<?, ?> properties,
      Map<String, String> environment,
      String propertyName,
      String environmentName,
      int defaultValue) {
    String value = configuredValue(properties, environment, propertyName, environmentName);
    if (value == null) {
      return defaultValue;
    }
    try {
      int parsed = Integer.parseInt(value);
      return parsed > 0 ? parsed : defaultValue;
    } catch (NumberFormatException _) {
      return defaultValue;
    }
  }

  private static String configuredValue(
      Map<?, ?> properties, Map<String, String> environment, String propertyName, String envName) {
    Object propertyValue = properties.get(propertyName);
    if (propertyValue != null && !propertyValue.toString().isBlank()) {
      return propertyValue.toString().trim();
    }
    String environmentValue = environment.get(envName);
    return environmentValue == null || environmentValue.isBlank() ? null : environmentValue.trim();
  }
}
