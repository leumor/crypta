package network.crypta.platform.api.content.subscriptions;

import java.time.Duration;
import java.util.Map;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("java:S100")
class ContentSubscriptionSchedulerConfigTest {
  @Test
  void from_whenShortProfileConfigured_expectEffectiveJitterAndNormalizedBackoff() {
    var config =
        ContentSubscriptionSchedulerConfig.from(
            Map.of(),
            Map.of(
                ContentSubscriptionSchedulerConfig.JITTER_ENV, "0",
                ContentSubscriptionSchedulerConfig.FAILURE_BACKOFF_ENV, "2",
                ContentSubscriptionSchedulerConfig.MAXIMUM_FAILURE_BACKOFF_ENV, "1"));

    assertEquals(Duration.ZERO, config.jitter());
    assertEquals(Duration.ofSeconds(2), config.failureBackoff());
    assertEquals(Duration.ofSeconds(2), config.maximumFailureBackoff());
  }

  @Test
  void from_whenInvalidShortProfileConfigured_expectConservativeDefaults() {
    var config =
        ContentSubscriptionSchedulerConfig.from(
            Map.of(),
            Map.of(
                ContentSubscriptionSchedulerConfig.JITTER_ENV, "-1",
                ContentSubscriptionSchedulerConfig.FAILURE_BACKOFF_ENV, "0",
                ContentSubscriptionSchedulerConfig.MAXIMUM_FAILURE_BACKOFF_ENV, "invalid"));

    assertEquals(Duration.ofMinutes(1), config.jitter());
    assertEquals(Duration.ofMinutes(5), config.failureBackoff());
    assertEquals(Duration.ofHours(1), config.maximumFailureBackoff());
  }

  @Test
  void from_whenPropertiesAndEnvironmentConfigured_expectPropertiesOverrideEnvironment() {
    Map<String, String> properties =
        Map.of(
            ContentSubscriptionSchedulerConfig.ENABLED_PROPERTY,
            "false",
            ContentSubscriptionSchedulerConfig.INITIAL_DELAY_PROPERTY,
            "7",
            ContentSubscriptionSchedulerConfig.SCHEDULER_POLL_INTERVAL_PROPERTY,
            "11",
            ContentSubscriptionSchedulerConfig.MINIMUM_POLL_INTERVAL_PROPERTY,
            "13",
            ContentSubscriptionSchedulerConfig.PER_APP_LIMIT_PROPERTY,
            "5",
            ContentSubscriptionSchedulerConfig.GLOBAL_LIMIT_PROPERTY,
            "3",
            ContentSubscriptionSchedulerConfig.PER_TICK_LIMIT_PROPERTY,
            "2");
    Map<String, String> environment =
        Map.of(
            ContentSubscriptionSchedulerConfig.ENABLED_ENV,
            "true",
            ContentSubscriptionSchedulerConfig.INITIAL_DELAY_ENV,
            "99",
            ContentSubscriptionSchedulerConfig.GLOBAL_LIMIT_ENV,
            "99");

    ContentSubscriptionSchedulerConfig config =
        ContentSubscriptionSchedulerConfig.from(properties, environment);

    assertFalse(config.enabled());
    assertEquals(Duration.ofSeconds(7), config.initialDelay());
    assertEquals(Duration.ofSeconds(11), config.schedulerPollInterval());
    assertEquals(Duration.ofSeconds(13), config.minimumPollInterval());
    assertEquals(5, config.perAppSubscriptionLimit());
    assertEquals(5, config.globalSubscriptionLimit());
    assertEquals(2, config.perTickFetchLimit());
  }

  @Test
  void from_whenInvalidConfiguredValues_expectDefaultsRemainInForce() {
    ContentSubscriptionSchedulerConfig defaults = ContentSubscriptionSchedulerConfig.defaults();
    Map<String, String> properties =
        Map.of(
            ContentSubscriptionSchedulerConfig.ENABLED_PROPERTY,
            "maybe",
            ContentSubscriptionSchedulerConfig.INITIAL_DELAY_PROPERTY,
            "-1",
            ContentSubscriptionSchedulerConfig.SCHEDULER_POLL_INTERVAL_PROPERTY,
            "0",
            ContentSubscriptionSchedulerConfig.MINIMUM_POLL_INTERVAL_PROPERTY,
            "not-a-number",
            ContentSubscriptionSchedulerConfig.PER_APP_LIMIT_PROPERTY,
            "-7",
            ContentSubscriptionSchedulerConfig.GLOBAL_LIMIT_PROPERTY,
            "0",
            ContentSubscriptionSchedulerConfig.PER_TICK_LIMIT_PROPERTY,
            "not-a-number");

    ContentSubscriptionSchedulerConfig config =
        ContentSubscriptionSchedulerConfig.from(properties, Map.of());

    assertEquals(defaults.enabled(), config.enabled());
    assertEquals(defaults.initialDelay(), config.initialDelay());
    assertEquals(defaults.schedulerPollInterval(), config.schedulerPollInterval());
    assertEquals(defaults.minimumPollInterval(), config.minimumPollInterval());
    assertEquals(defaults.perAppSubscriptionLimit(), config.perAppSubscriptionLimit());
    assertEquals(defaults.globalSubscriptionLimit(), config.globalSubscriptionLimit());
    assertEquals(defaults.perTickFetchLimit(), config.perTickFetchLimit());
  }

  @Test
  void constructor_whenConfiguredCeilingsAreBelowDefaults_expectCeilingsNormalizeUpward() {
    ContentSubscriptionSchedulerConfig config =
        new ContentSubscriptionSchedulerConfig(
            true,
            Duration.ZERO,
            Duration.ofSeconds(1),
            Duration.ofSeconds(5),
            Duration.ofSeconds(10),
            Duration.ofSeconds(7),
            Duration.ZERO,
            Duration.ofSeconds(30),
            Duration.ofSeconds(10),
            8,
            3,
            1,
            512L,
            128L,
            Duration.ofSeconds(5),
            Duration.ofSeconds(1));

    assertEquals(Duration.ofSeconds(10), config.defaultPollInterval());
    assertEquals(Duration.ofSeconds(10), config.maximumPollInterval());
    assertEquals(Duration.ofSeconds(30), config.maximumFailureBackoff());
    assertEquals(8, config.globalSubscriptionLimit());
    assertEquals(512L, config.hardMaxBytes());
    assertEquals(Duration.ofSeconds(5), config.hardTimeout());
  }

  @Test
  void constructor_whenLimitsAreNonPositive_expectIllegalArgumentException() {
    Duration zeroDuration = Duration.ZERO;
    Duration minimumPollInterval = Duration.ofSeconds(5);
    Duration defaultPollInterval = Duration.ofSeconds(5);
    Duration maximumPollInterval = Duration.ofSeconds(10);
    Duration schedulerPollInterval = Duration.ofSeconds(1);
    Duration maximumFailureBackoff = Duration.ofSeconds(2);
    Duration hardTimeout = Duration.ofSeconds(1);
    Duration fetchTimeout = Duration.ofSeconds(1);

    assertThrows(
        IllegalArgumentException.class,
        () ->
            new ContentSubscriptionSchedulerConfig(
                true,
                zeroDuration,
                zeroDuration,
                minimumPollInterval,
                defaultPollInterval,
                maximumPollInterval,
                zeroDuration,
                schedulerPollInterval,
                maximumFailureBackoff,
                1,
                1,
                1,
                1L,
                1L,
                hardTimeout,
                fetchTimeout));
  }
}
