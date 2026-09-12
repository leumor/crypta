package network.crypta.platform.api.content.subscriptions;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayDeque;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import network.crypta.platform.api.networkbudget.AppNetworkBudgetConfig;
import network.crypta.platform.api.networkbudget.AppNetworkBudgetOperation;
import network.crypta.platform.api.networkbudget.AppNetworkBudgetService;
import network.crypta.platform.api.networkbudget.InMemoryAppNetworkBudgetStore;
import network.crypta.platform.api.networkbudget.RuntimeWorkObservation;
import network.crypta.platform.appdist.AppUiMode;
import network.crypta.platform.apphost.AppHost;
import network.crypta.platform.apphost.InstalledAppPaths;
import network.crypta.platform.apphost.InstalledAppSnapshot;
import network.crypta.platform.apphost.manifest.AppManifest;
import network.crypta.runtime.spi.BoundedContentFetchRequest;
import network.crypta.runtime.spi.BoundedContentFetchResult;
import network.crypta.runtime.spi.ContentFetchObservation;
import network.crypta.runtime.spi.ContentFetchPort;
import network.crypta.runtime.spi.QueueSupportPort;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings({"java:S100"})
class ContentSubscriptionSchedulerTest {
  private static final String APP_ID = "feed-reader";
  private static final int GLOBAL_SUBSCRIPTION_LIMIT = 4;
  private static final Instant NOW = Instant.parse("2026-05-24T12:00:00Z");
  private static final String SOURCE = "USK@example/feed/7/feed.json";
  private static final List<String> SUBSCRIPTION_CAPABILITIES =
      List.of(
          ContentSubscriptionService.CAPABILITY_CONTENT_FETCH,
          ContentSubscriptionService.CAPABILITY_CONTENT_SUBSCRIBE);

  @TempDir Path tempDir;

  @Test
  void tick_whenSubscriptionIsDue_expectOneBoundedFetchAndUpdatedMetadata() throws IOException {
    RecordingFetchPort fetchPort = new RecordingFetchPort();
    fetchPort.enqueue("feed body", "USK@example/feed/7/feed.json");
    ContentSubscriptionService service = service(fetchPort, config(Duration.ZERO, 2, 2));
    service.create(APP_ID, createParams(SOURCE, "Daily feed"));
    ContentSubscriptionScheduler scheduler =
        scheduler(
            appHost(installed(SUBSCRIPTION_CAPABILITIES)), service, config(Duration.ZERO, 2, 2));

    ContentSubscriptionSchedulerTickResult result = scheduler.tick(NOW);

    assertEquals(ContentSubscriptionStatus.SUCCESS, result.status());
    assertEquals(1, result.pollsAttempted());
    assertEquals(1, fetchPort.calls);
    Map<String, Object> summary = service.list(APP_ID).getFirst();
    assertEquals("success", summary.get("status"));
    assertEquals(7L, summary.get("lastSeenEdition"));
    assertEquals(9L, summary.get("bytesLength"));
    assertEquals(1, summary.get("updateCount"));
  }

  @Test
  void tick_whenSubscriptionIsNotDue_expectFetchSkipped() throws IOException {
    RecordingFetchPort fetchPort = new RecordingFetchPort();
    ContentSubscriptionSchedulerConfig config = config(Duration.ofMinutes(10), 2, 2);
    ContentSubscriptionService service = service(fetchPort, config);
    service.create(APP_ID, createParams(SOURCE, "Daily feed"));
    ContentSubscriptionScheduler scheduler =
        scheduler(appHost(installed(SUBSCRIPTION_CAPABILITIES)), service, config);

    ContentSubscriptionSchedulerTickResult result = scheduler.tick(NOW);

    assertEquals(ContentSubscriptionStatus.SCHEDULED, result.status());
    assertEquals(0, result.pollsAttempted());
    assertEquals(0, fetchPort.calls);
  }

  @Test
  void tick_whenSubscriptionIsPaused_expectFetchSkipped() throws IOException {
    RecordingFetchPort fetchPort = new RecordingFetchPort();
    ContentSubscriptionSchedulerConfig config = config(Duration.ZERO, 2, 2);
    ContentSubscriptionService service = service(fetchPort, config);
    String subscriptionId =
        (String) service.create(APP_ID, createParams(SOURCE, "Daily feed")).get("subscriptionId");
    service.pause(APP_ID, subscriptionId);
    ContentSubscriptionScheduler scheduler =
        scheduler(appHost(installed(SUBSCRIPTION_CAPABILITIES)), service, config);

    ContentSubscriptionSchedulerTickResult result = scheduler.tick(NOW);

    assertEquals(ContentSubscriptionStatus.SCHEDULED, result.status());
    assertEquals(0, result.pollsAttempted());
    assertEquals(0, fetchPort.calls);
  }

  @Test
  void tick_whenPerTickLimitReached_expectOnlyLimitFetched() throws IOException {
    RecordingFetchPort fetchPort = new RecordingFetchPort();
    fetchPort.enqueue("one", "USK@example/feed/7/feed.json");
    fetchPort.enqueue("two", "USK@example/second/7/feed.json");
    ContentSubscriptionSchedulerConfig config = config(Duration.ZERO, 4, 1);
    ContentSubscriptionService service = service(fetchPort, config);
    service.create(APP_ID, createParams(SOURCE, "Daily feed"));
    service.create(APP_ID, createParams("USK@example/second/7/feed.json", "Second feed"));
    ContentSubscriptionScheduler scheduler =
        scheduler(appHost(installed(SUBSCRIPTION_CAPABILITIES)), service, config);

    ContentSubscriptionSchedulerTickResult result = scheduler.tick(NOW);

    assertEquals(ContentSubscriptionStatus.SUCCESS, result.status());
    assertEquals(1, result.pollsAttempted());
    assertEquals(1, fetchPort.calls);
  }

  @Test
  void tick_whenAppLacksRequiredCapabilities_expectSafeSkippedStatus() throws IOException {
    RecordingFetchPort fetchPort = new RecordingFetchPort();
    ContentSubscriptionSchedulerConfig config = config(Duration.ZERO, 2, 2);
    ContentSubscriptionService service = service(fetchPort, config);
    service.create(APP_ID, createParams(SOURCE, "Daily feed"));
    ContentSubscriptionScheduler scheduler =
        scheduler(
            appHost(installed(List.of(ContentSubscriptionService.CAPABILITY_CONTENT_SUBSCRIBE))),
            service,
            config);

    ContentSubscriptionSchedulerTickResult result = scheduler.tick(NOW);

    assertEquals(ContentSubscriptionStatus.BACKOFF, result.status());
    assertEquals(0, result.pollsAttempted());
    assertEquals(0, fetchPort.calls);
    Map<String, Object> summary = service.list(APP_ID).getFirst();
    assertEquals("runtime_unavailable", summary.get("lastErrorCode"));
    assertEquals("runtime_unavailable", summary.get("status"));
  }

  @Test
  void tick_whenQueueBackendUnavailable_expectSafePressureSkip() throws IOException {
    RecordingFetchPort fetchPort = new RecordingFetchPort();
    ContentSubscriptionSchedulerConfig config = config(Duration.ZERO, 2, 2);
    ContentSubscriptionService service = service(fetchPort, config);
    service.create(APP_ID, createParams(SOURCE, "Daily feed"));
    QueueSupportPort queueSupportPort = mock(QueueSupportPort.class);
    when(queueSupportPort.isQueueBackendEnabled()).thenReturn(false);
    ContentSubscriptionScheduler scheduler =
        new ContentSubscriptionScheduler(
            appHost(installed(SUBSCRIPTION_CAPABILITIES)),
            service,
            config,
            new ContentSubscriptionPressureGate(queueSupportPort, null),
            Clock.fixed(NOW, ZoneOffset.UTC),
            new Random(0));

    ContentSubscriptionSchedulerTickResult result = scheduler.tick(NOW);

    assertEquals(ContentSubscriptionStatus.BACKOFF, result.status());
    assertEquals(0, result.pollsAttempted());
    assertEquals(0, fetchPort.calls);
    Map<String, Object> summary = service.list(APP_ID).getFirst();
    assertEquals("runtime_unavailable", summary.get("lastErrorCode"));
    assertEquals("runtime_unavailable", summary.get("status"));
  }

  @Test
  void tick_whenQueuePressureSkipsPoll_expectBudgetNotConsumed() throws IOException {
    RecordingFetchPort fetchPort = new RecordingFetchPort();
    ContentSubscriptionSchedulerConfig config = config(Duration.ZERO, 2, 2);
    AppNetworkBudgetService budgetService = subscriptionBudget();
    ContentSubscriptionService service = service(fetchPort, config, budgetService);
    String subscriptionId =
        (String) service.create(APP_ID, createParams(SOURCE, "Daily feed")).get("subscriptionId");
    QueueSupportPort queueSupportPort = mock(QueueSupportPort.class);
    when(queueSupportPort.isQueueBackendEnabled()).thenReturn(false);
    ContentSubscriptionScheduler scheduler =
        new ContentSubscriptionScheduler(
            appHost(installed(SUBSCRIPTION_CAPABILITIES)),
            service,
            config,
            new ContentSubscriptionPressureGate(queueSupportPort, null),
            Clock.fixed(NOW, ZoneOffset.UTC),
            new Random(0));

    ContentSubscriptionSchedulerTickResult skipped = scheduler.tick(NOW);
    fetchPort.enqueue("feed body", "USK@example/feed/7/feed.json");
    Map<String, Object> refreshed = service.refresh(APP_ID, subscriptionId);

    assertEquals(ContentSubscriptionStatus.BACKOFF, skipped.status());
    assertEquals(0, skipped.pollsAttempted());
    assertEquals("success", refreshed.get("status"));
    assertEquals(1, fetchPort.calls);
  }

  @Test
  void tick_whenAlreadyRunning_expectNoOverlappingFetch() throws Exception {
    BlockingFetchPort fetchPort = new BlockingFetchPort();
    ContentSubscriptionSchedulerConfig config = config(Duration.ZERO, 2, 2);
    ContentSubscriptionService service = service(fetchPort, config);
    service.create(APP_ID, createParams(SOURCE, "Daily feed"));
    ContentSubscriptionScheduler scheduler =
        scheduler(appHost(installed(SUBSCRIPTION_CAPABILITIES)), service, config);
    AtomicReference<ContentSubscriptionSchedulerTickResult> firstResult = new AtomicReference<>();
    Thread firstTick = new Thread(() -> firstResult.set(scheduler.tick(NOW)), "first-test-tick");

    firstTick.start();
    assertTrue(fetchPort.started.await(5, TimeUnit.SECONDS));
    ContentSubscriptionSchedulerTickResult overlapping = scheduler.tick(NOW);
    fetchPort.release.countDown();
    firstTick.join(5000);

    assertEquals(ContentSubscriptionStatus.RUNNING, overlapping.status());
    assertEquals(ContentSubscriptionStatus.SUCCESS, firstResult.get().status());
    assertEquals(1, fetchPort.calls);
  }

  @Test
  void tick_whenPressureAndRateExhaustionCoincide_expectNoBudgetEntryOrFetch() throws IOException {
    RecordingFetchPort fetchPort = new RecordingFetchPort();
    var config = config(Duration.ZERO, 2, 2);
    var budget = subscriptionBudget();
    budget.acquire(APP_ID, AppNetworkBudgetOperation.SUBSCRIPTION_POLL).lease().close();
    var service = service(fetchPort, config, budget);
    service.create(APP_ID, createParams(SOURCE, "Feed"));
    var queue = mock(QueueSupportPort.class);
    when(queue.isQueueBackendEnabled()).thenReturn(false);
    var scheduler =
        new ContentSubscriptionScheduler(
            appHost(installed(SUBSCRIPTION_CAPABILITIES)),
            service,
            config,
            new ContentSubscriptionPressureGate(queue, null),
            Clock.fixed(NOW, ZoneOffset.UTC),
            new Random(0));
    long before = budget.observation().snapshot().lastSequence();
    var usageBefore = budget.snapshots();

    scheduler.tick(NOW);
    var kinds =
        budget.observation().snapshot().events().stream()
            .filter(event -> event.sequence() > before)
            .map(RuntimeWorkObservation.Event::kind)
            .toList();

    assertTrue(kinds.contains(RuntimeWorkObservation.Kind.DUE));
    assertTrue(kinds.contains(RuntimeWorkObservation.Kind.PRESSURE_SKIP));
    assertFalse(kinds.contains(RuntimeWorkObservation.Kind.BUDGET_RESERVE));
    assertFalse(kinds.contains(RuntimeWorkObservation.Kind.BUDGET_COMMITTED));
    assertEquals(usageBefore, budget.snapshots());
    assertEquals(0, fetchPort.calls);
  }

  @Test
  void tick_whenPressureClears_expectBackoffRespectedThenOrderedUsefulRecovery()
      throws IOException {
    RecordingFetchPort fetchPort = new RecordingFetchPort();
    var config = config(Duration.ZERO, 2, 2);
    var budget = subscriptionBudget();
    var service = service(fetchPort, config, budget);
    service.create(APP_ID, createParams(SOURCE, "Feed"));
    var queue = mock(QueueSupportPort.class);
    when(queue.isQueueBackendEnabled()).thenReturn(false);
    var scheduler =
        new ContentSubscriptionScheduler(
            appHost(installed(SUBSCRIPTION_CAPABILITIES)),
            service,
            config,
            new ContentSubscriptionPressureGate(queue, null),
            Clock.fixed(NOW, ZoneOffset.UTC),
            new Random(0));
    scheduler.tick(NOW);
    when(queue.isQueueBackendEnabled()).thenReturn(true);
    scheduler.tick(NOW.plusSeconds(4));
    assertEquals(0, fetchPort.calls);
    fetchPort.enqueue("feed", "USK@example/feed/7/feed.json");
    long before = budget.observation().snapshot().lastSequence();

    scheduler.tick(NOW.plusSeconds(5));
    var kinds =
        budget.observation().snapshot().events().stream()
            .filter(event -> event.sequence() > before)
            .map(RuntimeWorkObservation.Event::kind)
            .toList();

    assertEquals(1, fetchPort.calls);
    assertTrue(
        kinds.indexOf(RuntimeWorkObservation.Kind.BUDGET_RESERVED)
            < kinds.indexOf(RuntimeWorkObservation.Kind.BUDGET_COMMITTED));
    assertTrue(
        kinds.indexOf(RuntimeWorkObservation.Kind.BUDGET_COMMITTED)
            < kinds.indexOf(RuntimeWorkObservation.Kind.FETCH_INVOKED));
    assertTrue(
        kinds.indexOf(RuntimeWorkObservation.Kind.FETCH_SUCCEEDED)
            < kinds.indexOf(RuntimeWorkObservation.Kind.BUDGET_RELEASED));
    assertEquals(0, budget.diagnostics().activeFamilyLeases());
    assertEquals(0, budget.diagnostics().reservedFamilyRates());
  }

  @Test
  void executor_whenCancelledDuringFetch_expectBudgetReleasedAndNoOverlappingRestart()
      throws Exception {
    CountDownLatch entered = new CountDownLatch(1);
    CountDownLatch cancelled = new CountDownLatch(1);
    ContentFetchPort fetch =
        _ -> {
          entered.countDown();
          try {
            new CountDownLatch(1).await();
            throw new AssertionError("Unreachable");
          } catch (InterruptedException _) {
            Thread.currentThread().interrupt();
            cancelled.countDown();
            throw new IllegalStateException("Owned fetch cancelled");
          }
        };
    var config = config(Duration.ZERO, 2, 2);
    var budget = subscriptionBudget();
    var service = service(fetch, config, budget);
    service.create(APP_ID, createParams(SOURCE, "Feed"));
    var scheduler = scheduler(appHost(installed(SUBSCRIPTION_CAPABILITIES)), service, config);

    try {
      scheduler.start();
      scheduler.start();
      assertTrue(entered.await(5, TimeUnit.SECONDS));
      scheduler.close();
      assertTrue(cancelled.await(5, TimeUnit.SECONDS));
      // Taking the service lock waits for the interrupted fetch and its reservation cleanup.
      service.list(APP_ID);
      assertEquals(0, budget.diagnostics().activeFamilyLeases());
      assertEquals(0, budget.diagnostics().reservedFamilyRates());
      assertEquals(
          1,
          budget.observation().snapshot().events().stream()
              .filter(event -> event.kind() == RuntimeWorkObservation.Kind.FETCH_INVOKED)
              .count());
      scheduler.start();
      scheduler.close();
      assertEquals(0, budget.diagnostics().activeFamilyLeases());
    } finally {
      scheduler.close();
    }
  }

  @Test
  void tick_whenContentionAndBudgetExhaustionCoincide_expectExactOwnerSampleBeforeSkip()
      throws IOException {
    var fetch = new RecordingFetchPort();
    var config = config(Duration.ZERO, 2, 2);
    var budget = subscriptionBudget();
    budget.acquire(APP_ID, AppNetworkBudgetOperation.SUBSCRIPTION_POLL).lease().close();
    var service = service(fetch, config, budget);
    service.create(APP_ID, createParams(SOURCE, "Feed"));
    var owner = mock(ContentFetchPort.class);
    String epoch = "a3816c21-7d7d-4d6c-bad8-e47991bb78d5";
    when(owner.observation())
        .thenReturn(new ContentFetchObservation(true, epoch, 17, 123456789, 1, 10, 3, 2, 0, false));
    var scheduler =
        new ContentSubscriptionScheduler(
            appHost(installed(SUBSCRIPTION_CAPABILITIES)),
            service,
            config,
            new ContentSubscriptionPressureGate(null, null, owner, 1, 0),
            Clock.fixed(NOW, ZoneOffset.UTC),
            new Random(0));
    long before = budget.observation().snapshot().lastSequence();

    scheduler.tick(NOW);

    var events =
        budget.observation().snapshot().events().stream()
            .filter(event -> event.sequence() > before)
            .toList();
    var assessment =
        events.stream()
            .filter(event -> epoch.equals(event.sourceEpoch()))
            .findFirst()
            .orElseThrow();
    assertEquals(RuntimeWorkObservation.Kind.PRESSURE_CONTENTION_BLOCKED, assessment.kind());
    assertEquals(17, assessment.sourceSequence());
    assertEquals(123456789, assessment.sourceSampledAtEpochMillis());
    assertEquals(1, assessment.value());
    assertTrue(
        assessment.sequence()
            < events.stream()
                .filter(event -> event.kind() == RuntimeWorkObservation.Kind.PRESSURE_SKIP)
                .findFirst()
                .orElseThrow()
                .sequence());
    assertFalse(
        events.stream()
            .anyMatch(event -> event.kind() == RuntimeWorkObservation.Kind.BUDGET_RESERVE));
    assertEquals(0, fetch.calls);
  }

  @Test
  void tick_whenMultipleSubscriptionsDue_expectOneOwnerAssessmentForWholeTick() throws IOException {
    var fetch = new RecordingFetchPort();
    var config = config(Duration.ZERO, 2, 2);
    var service = service(fetch, config);
    service.create(APP_ID, createParams(SOURCE, "First"));
    service.create(APP_ID, createParams("USK@example/second/7/feed.json", "Second"));
    fetch.enqueue("first", "USK@example/feed/7/feed.json");
    fetch.enqueue("second", "USK@example/second/7/feed.json");
    var owner = mock(ContentFetchPort.class);
    when(owner.observation())
        .thenReturn(
            new ContentFetchObservation(
                true,
                "a3816c21-7d7d-4d6c-bad8-e47991bb78d5",
                1,
                System.currentTimeMillis(),
                0,
                0,
                0,
                0,
                0,
                false));
    var scheduler =
        new ContentSubscriptionScheduler(
            appHost(installed(SUBSCRIPTION_CAPABILITIES)),
            service,
            config,
            new ContentSubscriptionPressureGate(null, null, owner, 1, 0),
            Clock.fixed(NOW, ZoneOffset.UTC),
            new Random(0));

    scheduler.tick(NOW);

    verify(owner, times(1)).observation();
    assertEquals(2, fetch.calls);
  }

  private ContentSubscriptionScheduler scheduler(
      AppHost appHost,
      ContentSubscriptionService service,
      ContentSubscriptionSchedulerConfig config) {
    return new ContentSubscriptionScheduler(
        appHost,
        service,
        config,
        new ContentSubscriptionPressureGate(null, null),
        Clock.fixed(NOW, ZoneOffset.UTC),
        new Random(0));
  }

  private static ContentSubscriptionService service(
      ContentFetchPort fetchPort, ContentSubscriptionSchedulerConfig config) {
    return service(fetchPort, config, null);
  }

  private static ContentSubscriptionService service(
      ContentFetchPort fetchPort,
      ContentSubscriptionSchedulerConfig config,
      AppNetworkBudgetService budgetService) {
    return new ContentSubscriptionService(
        new InMemoryContentSubscriptionStore(),
        fetchPort,
        config,
        budgetService,
        Clock.fixed(NOW, ZoneOffset.UTC),
        new Random(0));
  }

  private static AppNetworkBudgetService subscriptionBudget() {
    return new AppNetworkBudgetService(
        new InMemoryAppNetworkBudgetStore(),
        new AppNetworkBudgetConfig(20, 100, 2, 16, 1, 1024, 1, 8, 120, 1024, 1, 8),
        Clock.fixed(NOW, ZoneOffset.UTC));
  }

  private AppHost appHost(InstalledAppSnapshot... installedApps) throws IOException {
    AppHost appHost = mock(AppHost.class);
    when(appHost.listInstalled()).thenReturn(List.of(installedApps));
    return appHost;
  }

  private InstalledAppSnapshot installed(List<String> permissions) {
    AppManifest manifest =
        new AppManifest(
            1,
            APP_ID,
            "Feed Reader",
            "1.0.0",
            "bin/run.sh",
            AppUiMode.NONE,
            null,
            permissions,
            null,
            null);
    return new InstalledAppSnapshot(
        manifest,
        new InstalledAppPaths(
            APP_ID,
            tempDir.resolve("installed").resolve(APP_ID),
            tempDir.resolve("data").resolve(APP_ID),
            tempDir.resolve("cache").resolve(APP_ID),
            tempDir.resolve("run").resolve(APP_ID)));
  }

  private static Map<String, List<String>> createParams(String source, String label) {
    return Map.of(
        "label",
        List.of(label),
        "uri",
        List.of(source),
        "pollIntervalSeconds",
        List.of("5"),
        "maxBytes",
        List.of("256"),
        "timeoutMillis",
        List.of("1000"));
  }

  private static ContentSubscriptionSchedulerConfig config(
      Duration initialDelay, int perAppLimit, int perTickLimit) {
    return new ContentSubscriptionSchedulerConfig(
        true,
        initialDelay,
        Duration.ofSeconds(1),
        Duration.ofSeconds(10),
        Duration.ofSeconds(5),
        Duration.ofHours(1),
        Duration.ZERO,
        Duration.ofSeconds(5),
        Duration.ofSeconds(30),
        perAppLimit,
        GLOBAL_SUBSCRIPTION_LIMIT,
        perTickLimit,
        256L,
        1024L,
        Duration.ofSeconds(1),
        Duration.ofSeconds(5));
  }

  private static class RecordingFetchPort implements ContentFetchPort {
    private final ArrayDeque<BoundedContentFetchResult> results = new ArrayDeque<>();
    protected int calls;

    @Override
    public BoundedContentFetchResult fetchContent(BoundedContentFetchRequest request) {
      calls++;
      return results.removeFirst();
    }

    void enqueue(String body, String resolvedUri) {
      results.addLast(
          new BoundedContentFetchResult(
              body.getBytes(StandardCharsets.UTF_8), requestUri(resolvedUri), resolvedUri, "ok"));
    }

    private static String requestUri(String resolvedUri) {
      return resolvedUri.contains("second") ? "USK@example/second/7/feed.json" : SOURCE;
    }
  }

  private static final class BlockingFetchPort extends RecordingFetchPort {
    private final CountDownLatch started = new CountDownLatch(1);
    private final CountDownLatch release = new CountDownLatch(1);

    @Override
    public BoundedContentFetchResult fetchContent(BoundedContentFetchRequest request) {
      calls++;
      started.countDown();
      try {
        assertTrue(release.await(5, TimeUnit.SECONDS));
      } catch (InterruptedException exception) {
        Thread.currentThread().interrupt();
        throw new AssertionError(exception);
      }
      return new BoundedContentFetchResult(
          "feed body".getBytes(StandardCharsets.UTF_8), request.uri(), request.uri(), "ok");
    }
  }
}
