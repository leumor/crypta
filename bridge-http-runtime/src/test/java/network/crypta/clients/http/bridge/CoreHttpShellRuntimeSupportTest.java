package network.crypta.clients.http.bridge;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;
import network.crypta.client.FetchContext;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.client.InsertContext.CompatibilityMode;
import network.crypta.clients.http.BrowseContentClient;
import network.crypta.clients.http.ContentToadlet;
import network.crypta.clients.http.FProxyFetchTracker;
import network.crypta.clients.http.FProxyToadlet;
import network.crypta.clients.http.HttpShellBrowseBootstrap;
import network.crypta.clients.http.HttpShellRuntimeSupport;
import network.crypta.clients.http.InsertCompatibilityModes;
import network.crypta.clients.http.LegacyFProxyBrowseRouteRegistrar;
import network.crypta.clients.http.PushDataManagerHandle;
import network.crypta.clients.http.Toadlet;
import network.crypta.clients.http.bookmark.BookmarkManager;
import network.crypta.clients.http.bridge.bookmark.CoreBookmarkRuntimeSupport;
import network.crypta.clients.http.updateableelements.PushDataManager;
import network.crypta.config.PersistentConfig;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.ProgramDirectory;
import network.crypta.node.RequestStarter;
import network.crypta.node.SecurityLevelListener;
import network.crypta.node.SecurityLevels.NETWORK_THREAT_LEVEL;
import network.crypta.node.SecurityLevels.PHYSICAL_THREAT_LEVEL;
import network.crypta.node.SecurityLevels;
import network.crypta.node.SemiOrderedShutdownHook;
import network.crypta.node.subsystem.NodeNetworkSubsystem;
import network.crypta.platform.appcatalog.AppCatalogBundleVerificationContext;
import network.crypta.platform.appcatalog.AppCatalogBundleVerificationPolicy;
import network.crypta.platform.appcatalog.AppCatalogBundleVerificationResult;
import network.crypta.platform.appcatalog.AppCatalogManager;
import network.crypta.platform.appcatalog.CatalogPublisherAuthorizationException;
import network.crypta.platform.appcatalog.CatalogScopedPublisherVerificationPolicy;
import network.crypta.platform.appcatalog.FileCatalogPublisherBindingStore;
import network.crypta.platform.appcatalog.TrustedReviewerKeys;
import network.crypta.platform.appdist.AppBundleSignature;
import network.crypta.platform.appdist.AppBundleSigner;
import network.crypta.platform.appdist.AppBundleVerifier;
import network.crypta.platform.appdist.AppDistributionException;
import network.crypta.platform.appdist.TrustedAppKey;
import network.crypta.platform.appdist.TrustedAppKeyLifecycle;
import network.crypta.platform.appdist.TrustedAppKeyPolicy;
import network.crypta.platform.appdist.TrustedAppKeys;
import network.crypta.platform.apphost.AppBundleVerificationException;
import network.crypta.platform.apphost.AppHost;
import network.crypta.platform.apphost.AppHostConfigurationException;
import network.crypta.platform.apphost.AppHostLayout;
import network.crypta.platform.apphost.InstalledAppPaths;
import network.crypta.platform.apphost.RunningAppSnapshot;
import network.crypta.platform.apphost.manifest.AppManifest;
import network.crypta.platform.apphost.manifest.AppManifestParser;
import network.crypta.platform.apphost.runtime.LocalProcessAppHost;
import network.crypta.runtime.alerts.UserAlertManager;
import network.crypta.runtime.alerts.UserAlertSurface;
import network.crypta.runtime.services.NodeServicesSubsystem;
import network.crypta.runtime.spi.RandomnessPort;
import network.crypta.runtime.spi.RuntimePorts;
import network.crypta.support.Ticker;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class CoreHttpShellRuntimeSupportTest {
  private static final String TRUSTED_KEY_ID = "local-dev";
  private static final String CATALOG_KEY_ID = "stable-catalog";

  @Test
  void constructor_whenCoreIsNull_throwsNullPointerException() {
    assertThrows(NullPointerException.class, () -> new CoreHttpShellRuntimeSupport(null));
  }

  @Test
  void composeCatalogBundlePolicies_whenInstallPolicyRejects_expectRejectedAfterScopedCheck()
      throws Exception {
    AppCatalogBundleVerificationPolicy installPolicy =
        mock(AppCatalogBundleVerificationPolicy.class);
    AppCatalogBundleVerificationPolicy scopedPolicy =
        mock(AppCatalogBundleVerificationPolicy.class);
    AppCatalogBundleVerificationContext context = mock(AppCatalogBundleVerificationContext.class);
    Path stagedBundle = Path.of("staged-bundle");
    doThrow(new IOException("pilot approval rejected"))
        .when(installPolicy)
        .verify(context, stagedBundle);
    AppCatalogBundleVerificationPolicy composed =
        CoreHttpShellRuntimeSupport.composeCatalogBundleVerificationPolicies(
            installPolicy, scopedPolicy);

    IOException exception =
        assertThrows(IOException.class, () -> composed.verify(context, stagedBundle));

    assertEquals("pilot approval rejected", exception.getMessage());
    verify(scopedPolicy).verify(context, stagedBundle);
  }

  @Test
  void composeCatalogBundlePolicies_whenBothAuthorize_expectScopedIdentityRetained()
      throws Exception {
    AppCatalogBundleVerificationPolicy installPolicy =
        mock(AppCatalogBundleVerificationPolicy.class);
    AppCatalogBundleVerificationPolicy scopedPolicy =
        mock(AppCatalogBundleVerificationPolicy.class);
    AppCatalogBundleVerificationContext context = mock(AppCatalogBundleVerificationContext.class);
    AppCatalogBundleVerificationResult scopedResult =
        mock(AppCatalogBundleVerificationResult.class);
    Path stagedBundle = Path.of("staged-bundle");
    when(scopedPolicy.verify(context, stagedBundle)).thenReturn(scopedResult);
    AppCatalogBundleVerificationPolicy composed =
        CoreHttpShellRuntimeSupport.composeCatalogBundleVerificationPolicies(
            installPolicy, scopedPolicy);

    AppCatalogBundleVerificationResult result = composed.verify(context, stagedBundle);

    assertSame(scopedResult, result);
    verify(installPolicy).verify(context, stagedBundle);
    verify(scopedPolicy).verify(context, stagedBundle);
  }

  @ParameterizedTest
  @EnumSource(
      value = TrustedAppKeyLifecycle.class,
      names = {"RETIRING", "RETIRED", "REVOKED"})
  void composeCatalogBundlePolicies_whenPublisherInactive_expectTypedDenialBeforeBaseVerifier(
      TrustedAppKeyLifecycle lifecycle, @TempDir Path tempDir) throws Exception {
    KeyPair publisher = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    Path bundle = stageSignedApp(tempDir.resolve("bundle"), publisher);
    TrustedAppKey key = new TrustedAppKey(TRUSTED_KEY_ID, "Ed25519", publisher.getPublic());
    TrustedAppKeys keys =
        TrustedAppKeys.ofPolicies(
            new TrustedAppKeyPolicy(key, lifecycle, Instant.MIN, Instant.MAX));
    CatalogScopedPublisherVerificationPolicy scoped =
        new CatalogScopedPublisherVerificationPolicy(
            new FileCatalogPublisherBindingStore(tempDir.resolve("scopes")),
            () -> keys,
            TrustedAppKeys::of,
            TrustedReviewerKeys::of,
            Clock.systemUTC(),
            null,
            CatalogScopedPublisherVerificationPolicy.CatalogSignerTrustMode.ROLE_SEPARATED);
    AppCatalogBundleVerificationPolicy base =
        root -> AppBundleVerifier.requireSigned(keys).verify(root);
    AppCatalogBundleVerificationPolicy composed =
        CoreHttpShellRuntimeSupport.composeCatalogBundleVerificationPolicies(base, scoped);
    AppCatalogBundleVerificationContext context = mock(AppCatalogBundleVerificationContext.class);

    assertThrows(
        CatalogPublisherAuthorizationException.class, () -> composed.verify(context, bundle));

    Files.writeString(bundle.resolve(AppBundleSignature.SIGNATURE_FILE_NAME), "malformed");
    assertThrows(AppDistributionException.class, () -> composed.verify(context, bundle));
  }

  @Test
  void runtimePorts_whenCoreProvidesPorts_returnsSamePorts() {
    NodeClientCore core = mock(NodeClientCore.class);
    RuntimePorts runtimePorts = mock(RuntimePorts.class);
    when(core.getRuntimePorts()).thenReturn(runtimePorts);
    CoreHttpShellRuntimeSupport runtimeSupport = runtimeSupport(core);

    RuntimePorts actualRuntimePorts = runtimeSupport.runtimePorts();

    assertSame(runtimePorts, actualRuntimePorts);
  }

  @Test
  void config_whenNodeProvidesConfig_returnsSameConfig() {
    NodeClientCore core = mock(NodeClientCore.class);
    Node node = mock(Node.class);
    PersistentConfig config = mock(PersistentConfig.class);
    when(core.getNode()).thenReturn(node);
    when(node.getConfig()).thenReturn(config);
    CoreHttpShellRuntimeSupport runtimeSupport = runtimeSupport(core);

    PersistentConfig actualConfig = (PersistentConfig) runtimeSupport.config();

    assertSame(config, actualConfig);
  }

  @Test
  void ticker_whenNodeProvidesTicker_returnsSameTicker() {
    NodeClientCore core = mock(NodeClientCore.class);
    Node node = mock(Node.class);
    NodeNetworkSubsystem network = mock(NodeNetworkSubsystem.class);
    Ticker ticker = mock(Ticker.class);
    when(core.getNode()).thenReturn(node);
    when(node.network()).thenReturn(network);
    when(network.ticker()).thenReturn(ticker);
    CoreHttpShellRuntimeSupport runtimeSupport = runtimeSupport(core);

    Ticker actualTicker = runtimeSupport.ticker();

    assertSame(ticker, actualTicker);
  }

  @Test
  void userAlerts_whenCoreProvidesAlerts_returnsSameAlerts() {
    NodeClientCore core = mock(NodeClientCore.class);
    UserAlertManager alerts = mock(UserAlertManager.class);
    when(core.getAlerts()).thenReturn(alerts);
    CoreHttpShellRuntimeSupport runtimeSupport = runtimeSupport(core);

    UserAlertSurface actualAlerts = runtimeSupport.userAlerts();

    assertSame(alerts, actualAlerts);
  }

  @Test
  void formPassword_whenCoreProvidesPassword_returnsSamePassword() {
    NodeClientCore core = mock(NodeClientCore.class);
    when(core.getFormPassword()).thenReturn("secret-token");
    CoreHttpShellRuntimeSupport runtimeSupport = runtimeSupport(core);

    String formPassword = runtimeSupport.formPassword();

    assertEquals("secret-token", formPassword);
  }

  @Test
  void insertCompatibilityModes_whenInvoked_returnsDetachedOrderedModeNames() {
    CoreHttpShellRuntimeSupport runtimeSupport = runtimeSupport(mock(NodeClientCore.class));

    InsertCompatibilityModes actualModes = runtimeSupport.insertCompatibilityModes();

    List<String> expectedModeNames =
        Arrays.stream(CompatibilityMode.values())
            .map(CompatibilityMode::intern)
            .filter(mode -> mode != CompatibilityMode.COMPAT_UNKNOWN)
            .map(CompatibilityMode::name)
            .distinct()
            .toList();
    assertEquals(expectedModeNames, actualModes.supportedModeNames());
    assertEquals(CompatibilityMode.COMPAT_DEFAULT.intern().name(), actualModes.defaultModeName());
  }

  @ParameterizedTest
  @ValueSource(booleans = {false, true})
  void allowUploadFrom_whenCoreReturnsDecision_propagatesDecision(boolean allowed) {
    NodeClientCore core = mock(NodeClientCore.class);
    File uploadTarget = new File("allowed-upload.txt");
    when(core.allowUploadFrom(uploadTarget)).thenReturn(allowed);
    CoreHttpShellRuntimeSupport runtimeSupport = runtimeSupport(core);

    boolean uploadAllowed = runtimeSupport.allowUploadFrom(uploadTarget);

    assertEquals(allowed, uploadAllowed);
  }

  @Test
  void storeConfig_whenInvoked_storesConfig() {
    NodeClientCore core = mock(NodeClientCore.class);
    Node node = mock(Node.class);
    PersistentConfig config = mock(PersistentConfig.class);
    when(core.getNode()).thenReturn(node);
    when(node.getConfig()).thenReturn(config);
    CoreHttpShellRuntimeSupport runtimeSupport = runtimeSupport(core);

    runtimeSupport.storeConfig();

    verify(config).store();
  }

  @Test
  void canRedirectToWizard_whenUsingCoreRuntime_returnsTrue() {
    CoreHttpShellRuntimeSupport runtimeSupport = runtimeSupport(mock(NodeClientCore.class));

    boolean canRedirect = runtimeSupport.canRedirectToWizard();

    assertTrue(canRedirect);
  }

  @Test
  void addNetworkThreatLevelListener_whenListenerIsNull_throwsNullPointerException() {
    CoreHttpShellRuntimeSupport runtimeSupport = runtimeSupport(mock(NodeClientCore.class));

    assertThrows(
        NullPointerException.class, () -> runtimeSupport.addNetworkThreatLevelListener(null));
  }

  @Test
  void addPhysicalThreatLevelListener_whenListenerIsNull_throwsNullPointerException() {
    CoreHttpShellRuntimeSupport runtimeSupport = runtimeSupport(mock(NodeClientCore.class));

    assertThrows(
        NullPointerException.class, () -> runtimeSupport.addPhysicalThreatLevelListener(null));
  }

  @Test
  void appHost_whenConstructedFromCore_usesCurrentNodeDirectories(@TempDir Path tempDir) {
    NodeClientCore core = mock(NodeClientCore.class);
    Node node = mock(Node.class);
    ProgramDirectory nodeDir = mock(ProgramDirectory.class);
    ProgramDirectory runDir = mock(ProgramDirectory.class);
    SemiOrderedShutdownHook shutdownHook = mock(SemiOrderedShutdownHook.class);
    Path expectedDataDir = tempDir.resolve("node");
    Path expectedCacheDir = tempDir.resolve("persistent-temp");
    Path expectedRunDir = tempDir.resolve("run");
    when(core.getNode()).thenReturn(node);
    when(node.nodeDir()).thenReturn(nodeDir);
    when(node.runDir()).thenReturn(runDir);
    when(nodeDir.dir()).thenReturn(expectedDataDir.toFile());
    when(runDir.dir()).thenReturn(expectedRunDir.toFile());
    when(core.getPersistentTempDir()).thenReturn(expectedCacheDir.toFile());

    CoreHttpShellRuntimeSupport runtimeSupport;
    try (MockedStatic<SemiOrderedShutdownHook> shutdownHooks =
        mockStatic(SemiOrderedShutdownHook.class)) {
      stubShutdownHookLookup(shutdownHooks, shutdownHook);
      runtimeSupport = new CoreHttpShellRuntimeSupport(core);
    }

    LocalProcessAppHost appHost =
        assertInstanceOf(LocalProcessAppHost.class, runtimeSupport.appHost());
    AppHostLayout layout = readLayout(appHost);
    assertEquals(expectedDataDir.toAbsolutePath(), layout.dataDir());
    assertEquals(expectedCacheDir.toAbsolutePath(), layout.cacheDir());
    assertEquals(expectedRunDir.toAbsolutePath(), layout.runDir());
    assertNotNull(runtimeSupport.appUpdateScheduler());
    assertNotNull(runtimeSupport.appUpdateService());
    verify(shutdownHook, times(2)).addEarlyJob(any(Thread.class));
  }

  @Test
  void appDataService_whenConstructedFromCore_usesHostManagedStoreRoot(@TempDir Path tempDir) {
    NodeClientCore core = mock(NodeClientCore.class);
    Node node = mock(Node.class);
    ProgramDirectory nodeDir = mock(ProgramDirectory.class);
    ProgramDirectory runDir = mock(ProgramDirectory.class);
    SemiOrderedShutdownHook shutdownHook = mock(SemiOrderedShutdownHook.class);
    Path nodeDataDir = tempDir.resolve("node");
    Path cacheDir = tempDir.resolve("persistent-temp");
    Path runDataDir = tempDir.resolve("run");
    when(core.getNode()).thenReturn(node);
    when(node.nodeDir()).thenReturn(nodeDir);
    when(node.runDir()).thenReturn(runDir);
    when(nodeDir.dir()).thenReturn(nodeDataDir.toFile());
    when(runDir.dir()).thenReturn(runDataDir.toFile());
    when(core.getPersistentTempDir()).thenReturn(cacheDir.toFile());

    CoreHttpShellRuntimeSupport runtimeSupport;
    try (MockedStatic<SemiOrderedShutdownHook> shutdownHooks =
        mockStatic(SemiOrderedShutdownHook.class)) {
      stubShutdownHookLookup(shutdownHooks, shutdownHook);
      runtimeSupport = new CoreHttpShellRuntimeSupport(core);
    }

    runtimeSupport
        .appDataService()
        .putRecord(
            "feed-reader",
            Map.of(
                "namespace",
                List.of("ui-state"),
                "key",
                List.of("startup"),
                "schemaVersion",
                List.of("1"),
                "contentType",
                List.of("application/json"),
                "valueJson",
                List.of("{}")));

    assertTrue(Files.exists(nodeDataDir.resolve("apps").resolve("durable-app-data")));
    assertFalse(
        Files.exists(
            nodeDataDir
                .resolve("apps")
                .resolve("data")
                .resolve("feed-reader")
                .resolve(".cryptad-app-data")));
    verify(shutdownHook, times(2)).addEarlyJob(any(Thread.class));
  }

  @Test
  void appVaultService_whenVaultStorageUnavailable_expectRuntimeStartsWithVaultUnavailable(
      @TempDir Path tempDir) throws IOException {
    NodeClientCore core = mock(NodeClientCore.class);
    Node node = mock(Node.class);
    ProgramDirectory nodeDir = mock(ProgramDirectory.class);
    ProgramDirectory runDir = mock(ProgramDirectory.class);
    SemiOrderedShutdownHook shutdownHook = mock(SemiOrderedShutdownHook.class);
    Path nodeDataDir = tempDir.resolve("node");
    Path cacheDir = tempDir.resolve("persistent-temp");
    Path runDataDir = tempDir.resolve("run");
    Files.createDirectories(nodeDataDir.resolve("apps"));
    Files.writeString(nodeDataDir.resolve("apps").resolve("vault"), "not-a-directory");
    when(core.getNode()).thenReturn(node);
    when(node.nodeDir()).thenReturn(nodeDir);
    when(node.runDir()).thenReturn(runDir);
    when(nodeDir.dir()).thenReturn(nodeDataDir.toFile());
    when(runDir.dir()).thenReturn(runDataDir.toFile());
    when(core.getPersistentTempDir()).thenReturn(cacheDir.toFile());

    CoreHttpShellRuntimeSupport runtimeSupport;
    try (MockedStatic<SemiOrderedShutdownHook> shutdownHooks =
        mockStatic(SemiOrderedShutdownHook.class)) {
      stubShutdownHookLookup(shutdownHooks, shutdownHook);
      runtimeSupport = new CoreHttpShellRuntimeSupport(core);
    }

    assertNotNull(runtimeSupport.appHost());
    assertNull(runtimeSupport.appVaultService());
    assertNotNull(runtimeSupport.appUpdateScheduler());
    assertNotNull(runtimeSupport.appUpdateService());
    verify(shutdownHook, times(2)).addEarlyJob(any(Thread.class));
  }

  @Test
  void appHost_whenConstructedFromCore_expectUnsignedInstallRejectedByProductionPolicy(
      @TempDir Path tempDir) throws IOException {
    NodeClientCore core = mock(NodeClientCore.class);
    Node node = mock(Node.class);
    ProgramDirectory nodeDir = mock(ProgramDirectory.class);
    ProgramDirectory runDir = mock(ProgramDirectory.class);
    SemiOrderedShutdownHook shutdownHook = mock(SemiOrderedShutdownHook.class);
    Path nodeDataDir = tempDir.resolve("node");
    Path cacheDir = tempDir.resolve("persistent-temp");
    Path runDataDir = tempDir.resolve("run");
    when(core.getNode()).thenReturn(node);
    when(node.nodeDir()).thenReturn(nodeDir);
    when(node.runDir()).thenReturn(runDir);
    when(nodeDir.dir()).thenReturn(nodeDataDir.toFile());
    when(runDir.dir()).thenReturn(runDataDir.toFile());
    when(core.getPersistentTempDir()).thenReturn(cacheDir.toFile());
    Path stagedDir = stageUnsignedApp(tempDir.resolve("staged"));

    CoreHttpShellRuntimeSupport runtimeSupport;
    try (MockedStatic<SemiOrderedShutdownHook> shutdownHooks =
        mockStatic(SemiOrderedShutdownHook.class)) {
      stubShutdownHookLookup(shutdownHooks, shutdownHook);
      runtimeSupport = new CoreHttpShellRuntimeSupport(core);
    }

    AppBundleVerificationException exception =
        assertThrows(
            AppBundleVerificationException.class,
            () -> runtimeSupport.appHost().installFromDirectory(stagedDir));

    assertEquals("missing signature sidecar", exception.getMessage());
  }

  @Test
  void appHost_whenAllowUnsignedAndCaseVariantSidecarPresent_expectSignedVerificationRequired(
      @TempDir Path tempDir) throws IOException {
    NodeClientCore core = mock(NodeClientCore.class);
    Node node = mock(Node.class);
    ProgramDirectory nodeDir = mock(ProgramDirectory.class);
    ProgramDirectory runDir = mock(ProgramDirectory.class);
    SemiOrderedShutdownHook shutdownHook = mock(SemiOrderedShutdownHook.class);
    Path nodeDataDir = tempDir.resolve("node");
    Path cacheDir = tempDir.resolve("persistent-temp");
    Path runDataDir = tempDir.resolve("run");
    when(core.getNode()).thenReturn(node);
    when(node.nodeDir()).thenReturn(nodeDir);
    when(node.runDir()).thenReturn(runDir);
    when(nodeDir.dir()).thenReturn(nodeDataDir.toFile());
    when(runDir.dir()).thenReturn(runDataDir.toFile());
    when(core.getPersistentTempDir()).thenReturn(cacheDir.toFile());
    Path stagedDir = stageUnsignedApp(tempDir.resolve("staged"));
    Files.writeString(stagedDir.resolve("CRYPTAD-APP.DIGESTS"), "stale-digest");
    String previousAllowUnsigned = System.getProperty("cryptad.apphost.allowUnsigned");

    try {
      System.setProperty("cryptad.apphost.allowUnsigned", "true");

      CoreHttpShellRuntimeSupport runtimeSupport;
      try (MockedStatic<SemiOrderedShutdownHook> shutdownHooks =
          mockStatic(SemiOrderedShutdownHook.class)) {
        stubShutdownHookLookup(shutdownHooks, shutdownHook);
        runtimeSupport = new CoreHttpShellRuntimeSupport(core);
      }

      AppBundleVerificationException exception =
          assertThrows(
              AppBundleVerificationException.class,
              () -> runtimeSupport.appHost().installFromDirectory(stagedDir));

      assertEquals("missing signature sidecar", exception.getMessage());
    } finally {
      restoreSystemProperty("cryptad.apphost.allowUnsigned", previousAllowUnsigned);
    }
  }

  @Test
  void appHost_whenTrustedKeyConfigured_expectSignedInstallAccepted(@TempDir Path tempDir)
      throws Exception {
    NodeClientCore core = mock(NodeClientCore.class);
    Node node = mock(Node.class);
    ProgramDirectory nodeDir = mock(ProgramDirectory.class);
    ProgramDirectory runDir = mock(ProgramDirectory.class);
    SemiOrderedShutdownHook shutdownHook = mock(SemiOrderedShutdownHook.class);
    Path nodeDataDir = tempDir.resolve("node");
    Path cacheDir = tempDir.resolve("persistent-temp");
    Path runDataDir = tempDir.resolve("run");
    when(core.getNode()).thenReturn(node);
    when(node.nodeDir()).thenReturn(nodeDir);
    when(node.runDir()).thenReturn(runDir);
    when(nodeDir.dir()).thenReturn(nodeDataDir.toFile());
    when(runDir.dir()).thenReturn(runDataDir.toFile());
    when(core.getPersistentTempDir()).thenReturn(cacheDir.toFile());
    KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    Path stagedDir = stageSignedApp(tempDir.resolve("staged-signed"), keyPair);
    String previousKeyId = System.getProperty("cryptad.apphost.trustedKeyId");
    String previousPublicKey = System.getProperty("cryptad.apphost.trustedPublicKeyBase64");

    try {
      System.setProperty("cryptad.apphost.trustedKeyId", TRUSTED_KEY_ID);
      System.setProperty(
          "cryptad.apphost.trustedPublicKeyBase64",
          Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));

      CoreHttpShellRuntimeSupport runtimeSupport;
      try (MockedStatic<SemiOrderedShutdownHook> shutdownHooks =
          mockStatic(SemiOrderedShutdownHook.class)) {
        stubShutdownHookLookup(shutdownHooks, shutdownHook);
        runtimeSupport = new CoreHttpShellRuntimeSupport(core);
      }

      assertEquals(
          "demo-app", runtimeSupport.appHost().installFromDirectory(stagedDir).manifest().appId());
    } finally {
      restoreSystemProperty("cryptad.apphost.trustedKeyId", previousKeyId);
      restoreSystemProperty("cryptad.apphost.trustedPublicKeyBase64", previousPublicKey);
    }
  }

  @Test
  void appHost_whenInstalledSignerBecomesRevoked_expectNextLaunchRejected(@TempDir Path tempDir)
      throws Exception {
    KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    Path trustedKeysFile = tempDir.resolve("app-trusted-keys.properties");
    writeLifecycleTrustedKeysFile(trustedKeysFile, keyPair, "active");
    Path stagedDir = stageSignedApp(tempDir.resolve("staged-revocation"), keyPair);
    String previousTrustedKeysFile = System.getProperty("cryptad.apphost.trustedKeysFile");
    String previousCatalogKeysFile = System.getProperty("cryptad.appcatalog.trustedKeysFile");

    try {
      System.setProperty("cryptad.apphost.trustedKeysFile", trustedKeysFile.toString());
      System.clearProperty("cryptad.appcatalog.trustedKeysFile");
      CoreHttpShellRuntimeSupport runtimeSupport = managedRuntimeSupport(tempDir);
      runtimeSupport.appHost().installFromDirectory(stagedDir);
      writeLifecycleTrustedKeysFile(trustedKeysFile, keyPair, "revoked");

      AppBundleVerificationException exception =
          assertThrows(
              AppBundleVerificationException.class,
              () -> runtimeSupport.appHost().start("demo-app"));

      assertEquals(
          "trusted key is not authorized for historical bundle verification: " + TRUSTED_KEY_ID,
          exception.getMessage());
      assertTrue(runtimeSupport.appHost().status("demo-app").isEmpty());
    } finally {
      restoreSystemProperty("cryptad.apphost.trustedKeysFile", previousTrustedKeysFile);
      restoreSystemProperty("cryptad.appcatalog.trustedKeysFile", previousCatalogKeysFile);
    }
  }

  @Test
  void appCatalog_whenRoleSpecificRegistryConfigured_expectTrustSeparatedFromAppHost(
      @TempDir Path tempDir) throws Exception {
    KeyPair catalogKeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    KeyPair appKeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    Path catalogKeysFile = tempDir.resolve("catalog-trusted-keys.properties");
    writeTrustedKeysFile(catalogKeysFile, CATALOG_KEY_ID, catalogKeyPair);
    Path stagedDir = stageSignedApp(tempDir.resolve("staged-role-specific"), appKeyPair);
    String previousCatalogKeysFile = System.getProperty("cryptad.appcatalog.trustedKeysFile");
    String previousKeyId = System.getProperty("cryptad.apphost.trustedKeyId");
    String previousPublicKey = System.getProperty("cryptad.apphost.trustedPublicKeyBase64");

    try {
      System.setProperty("cryptad.appcatalog.trustedKeysFile", catalogKeysFile.toString());
      System.setProperty("cryptad.apphost.trustedKeyId", TRUSTED_KEY_ID);
      System.setProperty(
          "cryptad.apphost.trustedPublicKeyBase64",
          Base64.getEncoder().encodeToString(appKeyPair.getPublic().getEncoded()));

      CoreHttpShellRuntimeSupport runtimeSupport = managedRuntimeSupport(tempDir);

      assertTrue(runtimeSupport.appCatalogManager().hasTrustedCatalogKey(CATALOG_KEY_ID));
      assertFalse(runtimeSupport.appCatalogManager().hasTrustedCatalogKey(TRUSTED_KEY_ID));
      assertEquals(
          "demo-app", runtimeSupport.appHost().installFromDirectory(stagedDir).manifest().appId());
    } finally {
      restoreSystemProperty("cryptad.appcatalog.trustedKeysFile", previousCatalogKeysFile);
      restoreSystemProperty("cryptad.apphost.trustedKeyId", previousKeyId);
      restoreSystemProperty("cryptad.apphost.trustedPublicKeyBase64", previousPublicKey);
    }
  }

  @Test
  void appHost_whenBoundedPilotConfigurationPresent_expectExactExternalSubjectOnly(
      @TempDir Path tempDir) throws Exception {
    KeyPair stableKeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    KeyPair catalogKeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    KeyPair publisherKeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    Path normalRegistry = tempDir.resolve("normal-stable-keys.properties");
    Path catalogRegistry = tempDir.resolve("catalog-keys.properties");
    Path pilotRegistry = tempDir.resolve("pilot-keys.properties");
    writeTrustedKeysFile(normalRegistry, "stable-first-party", stableKeyPair);
    writeTrustedKeysFile(catalogRegistry, CATALOG_KEY_ID, catalogKeyPair);
    writeTrustedKeysFile(pilotRegistry, "external-publisher", publisherKeyPair);
    Path approved =
        stageSignedApp(
            tempDir.resolve("approved-external"),
            "demo-app",
            publisherKeyPair,
            "external-publisher");
    Path stableApp =
        stageLongRunningSignedApp(tempDir.resolve("stable-first-party"), stableKeyPair);
    Path stableAppAfterCleanup =
        stageSignedApp(
            tempDir.resolve("stable-first-party-after-cleanup"),
            "stable-app-after-cleanup",
            stableKeyPair,
            "stable-first-party");
    Path unrelated =
        stageSignedApp(
            tempDir.resolve("unrelated-external"),
            "unrelated-app",
            publisherKeyPair,
            "external-publisher");
    Path approvalFile = tempDir.resolve("pilot-publisher-approval.json");
    writePilotApproval(
        approvalFile,
        publisherKeyPair,
        approved,
        sha256(normalRegistry),
        sha256(catalogRegistry),
        sha256(pilotRegistry));
    Map<String, String> properties =
        Map.of(
            "cryptad.apphost.trustedKeysFile", normalRegistry.toString(),
            "cryptad.appcatalog.trustedKeysFile", catalogRegistry.toString(),
            "cryptad.apphost.pilot.id", "pilot-294",
            "cryptad.apphost.pilot.nodeId", "node-294",
            "cryptad.apphost.pilot.approvalFile", approvalFile.toString(),
            "cryptad.apphost.pilot.approvalDigest", sha256(approvalFile),
            "cryptad.apphost.pilot.trustedKeysFile", pilotRegistry.toString());

    try (var _ = SystemPropertyScope.set(properties)) {
      CoreHttpShellRuntimeSupport runtimeSupport = managedRuntimeSupport(tempDir);

      assertEquals(
          "demo-app", runtimeSupport.appHost().installFromDirectory(approved).manifest().appId());
      assertEquals(
          "stable-app",
          runtimeSupport.appHost().installFromDirectory(stableApp).manifest().appId());
      AppBundleVerificationException unrelatedFailure =
          assertThrows(
              AppBundleVerificationException.class,
              () -> runtimeSupport.appHost().installFromDirectory(unrelated));

      assertTrue(unrelatedFailure.getMessage().contains("does not authorize this app id"));
      Files.delete(pilotRegistry);
      assertTrue(runtimeSupport.appCatalogManager().hasTrustedCatalogKey(CATALOG_KEY_ID));
      assertEquals(
          "stable-app-after-cleanup",
          runtimeSupport.appHost().installFromDirectory(stableAppAfterCleanup).manifest().appId());
      runtimeSupport.appHost().start("stable-app");
      runtimeSupport.appHost().stop("stable-app");
      assertThrows(
          AppHostConfigurationException.class, () -> runtimeSupport.appHost().start("demo-app"));
    }
  }

  @Test
  void appHost_whenPilotConfigurationIsPartial_expectBootstrapRejected(@TempDir Path tempDir) {
    try (var _ = SystemPropertyScope.set(Map.of("cryptad.apphost.pilot.id", "pilot-294"))) {
      IllegalStateException exception =
          assertThrows(IllegalStateException.class, () -> managedRuntimeSupport(tempDir));

      assertTrue(exception.getMessage().contains("incomplete"));
    }
  }

  @Test
  void appHost_whenPilotRegistryReusesCatalogKeyId_expectConfigurationRejected(
      @TempDir Path tempDir) throws Exception {
    KeyPair stableKeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    KeyPair catalogKeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    KeyPair publisherKeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    Path normalRegistry = tempDir.resolve("normal-stable-keys.properties");
    Path catalogRegistry = tempDir.resolve("catalog-overlapping-id.properties");
    Path pilotRegistry = tempDir.resolve("pilot-overlapping-id.properties");
    writeTrustedKeysFile(normalRegistry, "stable-first-party", stableKeyPair);
    writeTrustedKeysFile(catalogRegistry, "external-publisher", catalogKeyPair);
    writeTrustedKeysFile(pilotRegistry, "external-publisher", publisherKeyPair);
    Path approved =
        stageSignedApp(
            tempDir.resolve("approved-overlapping-id"),
            "demo-app",
            publisherKeyPair,
            "external-publisher");
    Path approvalFile = tempDir.resolve("pilot-overlapping-id-approval.json");
    writePilotApproval(
        approvalFile,
        publisherKeyPair,
        approved,
        sha256(normalRegistry),
        sha256(catalogRegistry),
        sha256(pilotRegistry));

    try (var _ =
        SystemPropertyScope.set(
            pilotProperties(normalRegistry, catalogRegistry, pilotRegistry, approvalFile))) {
      IllegalStateException failure =
          assertThrows(IllegalStateException.class, () -> managedRuntimeSupport(tempDir));

      assertEquals(
          "Failed to authenticate persistent pilot trust configuration.", failure.getMessage());
    }
  }

  @Test
  void appHost_whenPilotRegistryReusesCatalogPublicKey_expectConfigurationRejected(
      @TempDir Path tempDir) throws Exception {
    KeyPair stableKeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    KeyPair sharedKeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    Path normalRegistry = tempDir.resolve("normal-stable-keys.properties");
    Path catalogRegistry = tempDir.resolve("catalog-overlapping-key.properties");
    Path pilotRegistry = tempDir.resolve("pilot-overlapping-key.properties");
    writeTrustedKeysFile(normalRegistry, "stable-first-party", stableKeyPair);
    writeTrustedKeysFile(catalogRegistry, CATALOG_KEY_ID, sharedKeyPair);
    writeTrustedKeysFile(pilotRegistry, "external-publisher", sharedKeyPair);
    Path approved =
        stageSignedApp(
            tempDir.resolve("approved-overlapping-key"),
            "demo-app",
            sharedKeyPair,
            "external-publisher");
    Path approvalFile = tempDir.resolve("pilot-overlapping-key-approval.json");
    writePilotApproval(
        approvalFile,
        sharedKeyPair,
        approved,
        sha256(normalRegistry),
        sha256(catalogRegistry),
        sha256(pilotRegistry));

    try (var _ =
        SystemPropertyScope.set(
            pilotProperties(normalRegistry, catalogRegistry, pilotRegistry, approvalFile))) {
      IllegalStateException failure =
          assertThrows(IllegalStateException.class, () -> managedRuntimeSupport(tempDir));

      assertEquals(
          "Failed to authenticate persistent pilot trust configuration.", failure.getMessage());
    }
  }

  @Test
  void appHost_whenPilotRegistryBytesDifferFromApproval_expectDigestMismatchRejected(
      @TempDir Path tempDir) throws Exception {
    KeyPair stableKeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    KeyPair catalogKeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    KeyPair publisherKeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    KeyPair substitutedKeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    Path normalRegistry = tempDir.resolve("normal-stable-keys.properties");
    Path catalogRegistry = tempDir.resolve("catalog-keys.properties");
    Path pilotRegistry = tempDir.resolve("pilot-substituted.properties");
    writeTrustedKeysFile(normalRegistry, "stable-first-party", stableKeyPair);
    writeTrustedKeysFile(catalogRegistry, CATALOG_KEY_ID, catalogKeyPair);
    writeTrustedKeysFile(pilotRegistry, "external-publisher", publisherKeyPair);
    Path approved =
        stageSignedApp(
            tempDir.resolve("approved-before-substitution"),
            "demo-app",
            publisherKeyPair,
            "external-publisher");
    Path approvalFile = tempDir.resolve("pilot-before-substitution-approval.json");
    writePilotApproval(
        approvalFile,
        publisherKeyPair,
        approved,
        sha256(normalRegistry),
        sha256(catalogRegistry),
        sha256(pilotRegistry));
    writeTrustedKeysFile(pilotRegistry, "substituted-publisher", substitutedKeyPair);

    try (var _ =
        SystemPropertyScope.set(
            pilotProperties(normalRegistry, catalogRegistry, pilotRegistry, approvalFile))) {
      CoreHttpShellRuntimeSupport runtimeSupport = managedRuntimeSupport(tempDir);

      AppHostConfigurationException exception =
          assertThrows(
              AppHostConfigurationException.class,
              () -> runtimeSupport.appHost().installFromDirectory(approved));

      assertEquals("pilot registry digest differs from the approval", exception.getMessage());
    }
  }

  @Test
  void appCatalog_whenCatalogRegistryBytesChangeAfterBootstrap_expectDigestMismatchRejected(
      @TempDir Path tempDir) throws Exception {
    KeyPair stableKeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    KeyPair catalogKeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    KeyPair publisherKeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    KeyPair substitutedCatalogKeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    Path normalRegistry = tempDir.resolve("normal-stable-keys.properties");
    Path catalogRegistry = tempDir.resolve("catalog-keys.properties");
    Path pilotRegistry = tempDir.resolve("pilot-keys.properties");
    writeTrustedKeysFile(normalRegistry, "stable-first-party", stableKeyPair);
    writeTrustedKeysFile(catalogRegistry, CATALOG_KEY_ID, catalogKeyPair);
    writeTrustedKeysFile(pilotRegistry, "external-publisher", publisherKeyPair);
    Path approved =
        stageSignedApp(
            tempDir.resolve("approved-before-catalog-substitution"),
            "demo-app",
            publisherKeyPair,
            "external-publisher");
    Path approvalFile = tempDir.resolve("catalog-substitution-approval.json");
    writePilotApproval(
        approvalFile,
        publisherKeyPair,
        approved,
        sha256(normalRegistry),
        sha256(catalogRegistry),
        sha256(pilotRegistry));

    try (var _ =
        SystemPropertyScope.set(
            pilotProperties(normalRegistry, catalogRegistry, pilotRegistry, approvalFile))) {
      CoreHttpShellRuntimeSupport runtimeSupport = managedRuntimeSupport(tempDir);
      writeTrustedKeysFile(catalogRegistry, "substituted-catalog", substitutedCatalogKeyPair);
      AppCatalogManager catalogManager = runtimeSupport.appCatalogManager();

      IllegalStateException catalogFailure =
          assertThrows(
              IllegalStateException.class,
              () -> catalogManager.hasTrustedCatalogKey("substituted-catalog"));
      AppHostConfigurationException installFailure =
          assertThrows(
              AppHostConfigurationException.class,
              () -> runtimeSupport.appHost().installFromDirectory(approved));

      assertEquals(
          "Failed to load authenticated pilot catalog trust.", catalogFailure.getMessage());
      assertEquals(
          "catalog registry digest differs from the approval", installFailure.getMessage());
    }
  }

  @Test
  void appHost_whenPilotApprovalIsExpired_expectStableTrustRemainsAvailable(@TempDir Path tempDir)
      throws Exception {
    KeyPair stableKeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    KeyPair catalogKeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    KeyPair publisherKeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    Path normalRegistry = tempDir.resolve("normal-stable-keys.properties");
    Path catalogRegistry = tempDir.resolve("catalog-keys.properties");
    Path pilotRegistry = tempDir.resolve("pilot-keys.properties");
    writeTrustedKeysFile(normalRegistry, "stable-first-party", stableKeyPair);
    writeTrustedKeysFile(catalogRegistry, CATALOG_KEY_ID, catalogKeyPair);
    writeTrustedKeysFile(pilotRegistry, "external-publisher", publisherKeyPair);
    Path externalApp =
        stageSignedApp(
            tempDir.resolve("expired-external"),
            "demo-app",
            publisherKeyPair,
            "external-publisher");
    Path stableApp =
        stageSignedApp(
            tempDir.resolve("stable-with-expired-pilot"),
            "stable-app",
            stableKeyPair,
            "stable-first-party");
    Path approvalFile = tempDir.resolve("expired-pilot-approval.json");
    writePilotApproval(
        approvalFile,
        publisherKeyPair,
        externalApp,
        sha256(normalRegistry),
        sha256(catalogRegistry),
        sha256(pilotRegistry),
        Instant.now().minusSeconds(7200),
        Instant.now().minusSeconds(3600));

    try (var _ =
        SystemPropertyScope.set(
            pilotProperties(normalRegistry, catalogRegistry, pilotRegistry, approvalFile))) {
      CoreHttpShellRuntimeSupport runtimeSupport = managedRuntimeSupport(tempDir);

      assertEquals(
          "stable-app",
          runtimeSupport.appHost().installFromDirectory(stableApp).manifest().appId());
      assertTrue(runtimeSupport.appCatalogManager().hasTrustedCatalogKey(CATALOG_KEY_ID));
      AppHostConfigurationException failure =
          assertThrows(
              AppHostConfigurationException.class,
              () -> runtimeSupport.appHost().installFromDirectory(externalApp));

      assertTrue(failure.getMessage().contains("validity window"));
    }
  }

  @Test
  void appCatalog_whenRoleSpecificRegistryReusesAppHostKeyId_expectConfigurationRejected(
      @TempDir Path tempDir) throws Exception {
    KeyPair catalogKeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    KeyPair appKeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    Path catalogKeysFile = tempDir.resolve("catalog-overlapping-id.properties");
    writeTrustedKeysFile(catalogKeysFile, TRUSTED_KEY_ID, catalogKeyPair);
    Path stagedDir = stageSignedApp(tempDir.resolve("staged-overlapping-id"), appKeyPair);
    String previousCatalogKeysFile = System.getProperty("cryptad.appcatalog.trustedKeysFile");
    String previousKeyId = System.getProperty("cryptad.apphost.trustedKeyId");
    String previousPublicKey = System.getProperty("cryptad.apphost.trustedPublicKeyBase64");

    try {
      System.setProperty("cryptad.appcatalog.trustedKeysFile", catalogKeysFile.toString());
      System.setProperty("cryptad.apphost.trustedKeyId", TRUSTED_KEY_ID);
      System.setProperty(
          "cryptad.apphost.trustedPublicKeyBase64",
          Base64.getEncoder().encodeToString(appKeyPair.getPublic().getEncoded()));
      CoreHttpShellRuntimeSupport runtimeSupport = managedRuntimeSupport(tempDir);
      AppCatalogManager appCatalogManager = runtimeSupport.appCatalogManager();

      IllegalStateException catalogFailure =
          assertThrows(
              IllegalStateException.class,
              () -> appCatalogManager.hasTrustedCatalogKey(TRUSTED_KEY_ID));
      AppHostConfigurationException bundleFailure =
          assertThrows(
              AppHostConfigurationException.class,
              () -> runtimeSupport.appHost().installFromDirectory(stagedDir));

      assertEquals(
          "Trusted catalog and app signing key registries must be role-distinct.",
          catalogFailure.getMessage());
      assertEquals(catalogFailure.getMessage(), bundleFailure.getMessage());
    } finally {
      restoreSystemProperty("cryptad.appcatalog.trustedKeysFile", previousCatalogKeysFile);
      restoreSystemProperty("cryptad.apphost.trustedKeyId", previousKeyId);
      restoreSystemProperty("cryptad.apphost.trustedPublicKeyBase64", previousPublicKey);
    }
  }

  @Test
  void appCatalog_whenRoleSpecificRegistryReusesAppHostPublicKey_expectConfigurationRejected(
      @TempDir Path tempDir) throws Exception {
    KeyPair sharedKeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    Path catalogKeysFile = tempDir.resolve("catalog-overlapping-key.properties");
    writeTrustedKeysFile(catalogKeysFile, CATALOG_KEY_ID, sharedKeyPair);
    String previousCatalogKeysFile = System.getProperty("cryptad.appcatalog.trustedKeysFile");
    String previousKeyId = System.getProperty("cryptad.apphost.trustedKeyId");
    String previousPublicKey = System.getProperty("cryptad.apphost.trustedPublicKeyBase64");

    try {
      System.setProperty("cryptad.appcatalog.trustedKeysFile", catalogKeysFile.toString());
      System.setProperty("cryptad.apphost.trustedKeyId", TRUSTED_KEY_ID);
      System.setProperty(
          "cryptad.apphost.trustedPublicKeyBase64",
          Base64.getEncoder().encodeToString(sharedKeyPair.getPublic().getEncoded()));
      CoreHttpShellRuntimeSupport runtimeSupport = managedRuntimeSupport(tempDir);
      AppCatalogManager appCatalogManager = runtimeSupport.appCatalogManager();

      IllegalStateException exception =
          assertThrows(
              IllegalStateException.class,
              () -> appCatalogManager.hasTrustedCatalogKey(CATALOG_KEY_ID));

      assertEquals(
          "Trusted catalog and app signing key registries must be role-distinct.",
          exception.getMessage());
    } finally {
      restoreSystemProperty("cryptad.appcatalog.trustedKeysFile", previousCatalogKeysFile);
      restoreSystemProperty("cryptad.apphost.trustedKeyId", previousKeyId);
      restoreSystemProperty("cryptad.apphost.trustedPublicKeyBase64", previousPublicKey);
    }
  }

  @Test
  void appCatalog_whenRoleSpecificRegistryMalformed_expectFailureWithoutAppHostFallback(
      @TempDir Path tempDir) throws Exception {
    KeyPair appKeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    Path malformedCatalogKeysFile = tempDir.resolve("malformed-catalog-trusted-keys.properties");
    Files.writeString(
        malformedCatalogKeysFile, "trusted.keys.version=unsupported\n", StandardCharsets.UTF_8);
    String previousCatalogKeysFile = System.getProperty("cryptad.appcatalog.trustedKeysFile");
    String previousKeyId = System.getProperty("cryptad.apphost.trustedKeyId");
    String previousPublicKey = System.getProperty("cryptad.apphost.trustedPublicKeyBase64");

    try {
      System.setProperty("cryptad.appcatalog.trustedKeysFile", malformedCatalogKeysFile.toString());
      System.setProperty("cryptad.apphost.trustedKeyId", TRUSTED_KEY_ID);
      System.setProperty(
          "cryptad.apphost.trustedPublicKeyBase64",
          Base64.getEncoder().encodeToString(appKeyPair.getPublic().getEncoded()));
      CoreHttpShellRuntimeSupport runtimeSupport = managedRuntimeSupport(tempDir);
      AppCatalogManager appCatalogManager = runtimeSupport.appCatalogManager();

      IllegalStateException exception =
          assertThrows(
              IllegalStateException.class,
              () -> appCatalogManager.hasTrustedCatalogKey(TRUSTED_KEY_ID));

      assertEquals("Failed to load trusted catalog keys file.", exception.getMessage());
    } finally {
      restoreSystemProperty("cryptad.appcatalog.trustedKeysFile", previousCatalogKeysFile);
      restoreSystemProperty("cryptad.apphost.trustedKeyId", previousKeyId);
      restoreSystemProperty("cryptad.apphost.trustedPublicKeyBase64", previousPublicKey);
    }
  }

  @Test
  void appCatalog_whenRoleSpecificRegistryAbsent_expectLegacyAppHostTrustFallback(
      @TempDir Path tempDir) throws Exception {
    KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    Path stagedDir = stageSignedApp(tempDir.resolve("staged-legacy-fallback"), keyPair);
    String previousCatalogKeysFile = System.getProperty("cryptad.appcatalog.trustedKeysFile");
    String previousKeyId = System.getProperty("cryptad.apphost.trustedKeyId");
    String previousPublicKey = System.getProperty("cryptad.apphost.trustedPublicKeyBase64");

    try {
      System.clearProperty("cryptad.appcatalog.trustedKeysFile");
      System.setProperty("cryptad.apphost.trustedKeyId", TRUSTED_KEY_ID);
      System.setProperty(
          "cryptad.apphost.trustedPublicKeyBase64",
          Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
      CoreHttpShellRuntimeSupport runtimeSupport = managedRuntimeSupport(tempDir);

      assertTrue(runtimeSupport.appCatalogManager().hasTrustedCatalogKey(TRUSTED_KEY_ID));
      assertEquals(
          "demo-app", runtimeSupport.appHost().installFromDirectory(stagedDir).manifest().appId());
    } finally {
      restoreSystemProperty("cryptad.appcatalog.trustedKeysFile", previousCatalogKeysFile);
      restoreSystemProperty("cryptad.apphost.trustedKeyId", previousKeyId);
      restoreSystemProperty("cryptad.apphost.trustedPublicKeyBase64", previousPublicKey);
    }
  }

  @Test
  void appHost_whenTrustedPublicKeyFileContainsRawDer_expectSignedInstallAccepted(
      @TempDir Path tempDir) throws Exception {
    NodeClientCore core = mock(NodeClientCore.class);
    Node node = mock(Node.class);
    ProgramDirectory nodeDir = mock(ProgramDirectory.class);
    ProgramDirectory runDir = mock(ProgramDirectory.class);
    SemiOrderedShutdownHook shutdownHook = mock(SemiOrderedShutdownHook.class);
    Path nodeDataDir = tempDir.resolve("node");
    Path cacheDir = tempDir.resolve("persistent-temp");
    Path runDataDir = tempDir.resolve("run");
    when(core.getNode()).thenReturn(node);
    when(node.nodeDir()).thenReturn(nodeDir);
    when(node.runDir()).thenReturn(runDir);
    when(nodeDir.dir()).thenReturn(nodeDataDir.toFile());
    when(runDir.dir()).thenReturn(runDataDir.toFile());
    when(core.getPersistentTempDir()).thenReturn(cacheDir.toFile());
    KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    Path stagedDir = stageSignedApp(tempDir.resolve("staged-raw-der"), keyPair);
    Path publicKeyFile = tempDir.resolve("public-key.der");
    Files.write(publicKeyFile, keyPair.getPublic().getEncoded());
    String previousKeyId = System.getProperty("cryptad.apphost.trustedKeyId");
    String previousPublicKey = System.getProperty("cryptad.apphost.trustedPublicKeyBase64");
    String previousPublicKeyFile = System.getProperty("cryptad.apphost.trustedPublicKeyFile");

    try {
      System.setProperty("cryptad.apphost.trustedKeyId", TRUSTED_KEY_ID);
      System.clearProperty("cryptad.apphost.trustedPublicKeyBase64");
      System.setProperty("cryptad.apphost.trustedPublicKeyFile", publicKeyFile.toString());

      CoreHttpShellRuntimeSupport runtimeSupport;
      try (MockedStatic<SemiOrderedShutdownHook> shutdownHooks =
          mockStatic(SemiOrderedShutdownHook.class)) {
        stubShutdownHookLookup(shutdownHooks, shutdownHook);
        runtimeSupport = new CoreHttpShellRuntimeSupport(core);
      }

      assertEquals(
          "demo-app", runtimeSupport.appHost().installFromDirectory(stagedDir).manifest().appId());
    } finally {
      restoreSystemProperty("cryptad.apphost.trustedKeyId", previousKeyId);
      restoreSystemProperty("cryptad.apphost.trustedPublicKeyBase64", previousPublicKey);
      restoreSystemProperty("cryptad.apphost.trustedPublicKeyFile", previousPublicKeyFile);
    }
  }

  @Test
  void appHost_whenTrustedKeysFileIsUnreadable_expectBootstrapSucceedsAndInstallFailsOnDemand(
      @TempDir Path tempDir) throws Exception {
    NodeClientCore core = mock(NodeClientCore.class);
    Node node = mock(Node.class);
    ProgramDirectory nodeDir = mock(ProgramDirectory.class);
    ProgramDirectory runDir = mock(ProgramDirectory.class);
    SemiOrderedShutdownHook shutdownHook = mock(SemiOrderedShutdownHook.class);
    Path nodeDataDir = tempDir.resolve("node");
    Path cacheDir = tempDir.resolve("persistent-temp");
    Path runDataDir = tempDir.resolve("run");
    when(core.getNode()).thenReturn(node);
    when(node.nodeDir()).thenReturn(nodeDir);
    when(node.runDir()).thenReturn(runDir);
    when(nodeDir.dir()).thenReturn(nodeDataDir.toFile());
    when(runDir.dir()).thenReturn(runDataDir.toFile());
    when(core.getPersistentTempDir()).thenReturn(cacheDir.toFile());
    Path stagedDir = stageUnsignedApp(tempDir.resolve("staged"));
    String previousTrustedKeysFile = System.getProperty("cryptad.apphost.trustedKeysFile");

    try {
      System.setProperty(
          "cryptad.apphost.trustedKeysFile",
          tempDir.resolve("missing-trusted-keys.properties").toString());

      CoreHttpShellRuntimeSupport runtimeSupport;
      try (MockedStatic<SemiOrderedShutdownHook> shutdownHooks =
          mockStatic(SemiOrderedShutdownHook.class)) {
        stubShutdownHookLookup(shutdownHooks, shutdownHook);
        runtimeSupport = new CoreHttpShellRuntimeSupport(core);
      }

      AppHostConfigurationException exception =
          assertThrows(
              AppHostConfigurationException.class,
              () -> runtimeSupport.appHost().installFromDirectory(stagedDir));

      assertEquals("Failed to load trusted app keys file.", exception.getMessage());
    } finally {
      restoreSystemProperty("cryptad.apphost.trustedKeysFile", previousTrustedKeysFile);
    }
  }

  @Test
  void appHost_whenTrustedKeyIdDuplicatesTrustedKeysFile_expectInstallFailsWithVerificationError(
      @TempDir Path tempDir) throws Exception {
    NodeClientCore core = mock(NodeClientCore.class);
    Node node = mock(Node.class);
    ProgramDirectory nodeDir = mock(ProgramDirectory.class);
    ProgramDirectory runDir = mock(ProgramDirectory.class);
    SemiOrderedShutdownHook shutdownHook = mock(SemiOrderedShutdownHook.class);
    Path nodeDataDir = tempDir.resolve("node");
    Path cacheDir = tempDir.resolve("persistent-temp");
    Path runDataDir = tempDir.resolve("run");
    when(core.getNode()).thenReturn(node);
    when(node.nodeDir()).thenReturn(nodeDir);
    when(node.runDir()).thenReturn(runDir);
    when(nodeDir.dir()).thenReturn(nodeDataDir.toFile());
    when(runDir.dir()).thenReturn(runDataDir.toFile());
    when(core.getPersistentTempDir()).thenReturn(cacheDir.toFile());
    Path stagedDir = stageUnsignedApp(tempDir.resolve("staged"));
    KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    Path trustedKeysFile = tempDir.resolve("trusted-keys.properties");
    Files.writeString(
        trustedKeysFile,
        """
        trusted.keys.version=1
        key.0.id=%s
        key.0.algorithm=Ed25519
        key.0.public.key.base64=%s
        """
            .formatted(
                TRUSTED_KEY_ID,
                Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded())),
        StandardCharsets.UTF_8);
    String previousTrustedKeysFile = System.getProperty("cryptad.apphost.trustedKeysFile");
    String previousKeyId = System.getProperty("cryptad.apphost.trustedKeyId");
    String previousPublicKey = System.getProperty("cryptad.apphost.trustedPublicKeyBase64");

    try {
      System.setProperty("cryptad.apphost.trustedKeysFile", trustedKeysFile.toString());
      System.setProperty("cryptad.apphost.trustedKeyId", TRUSTED_KEY_ID);
      System.setProperty(
          "cryptad.apphost.trustedPublicKeyBase64",
          Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));

      CoreHttpShellRuntimeSupport runtimeSupport;
      try (MockedStatic<SemiOrderedShutdownHook> shutdownHooks =
          mockStatic(SemiOrderedShutdownHook.class)) {
        stubShutdownHookLookup(shutdownHooks, shutdownHook);
        runtimeSupport = new CoreHttpShellRuntimeSupport(core);
      }

      AppHostConfigurationException exception =
          assertThrows(
              AppHostConfigurationException.class,
              () -> runtimeSupport.appHost().installFromDirectory(stagedDir));

      assertEquals("duplicate trusted key id: " + TRUSTED_KEY_ID, exception.getMessage());
    } finally {
      restoreSystemProperty("cryptad.apphost.trustedKeysFile", previousTrustedKeysFile);
      restoreSystemProperty("cryptad.apphost.trustedKeyId", previousKeyId);
      restoreSystemProperty("cryptad.apphost.trustedPublicKeyBase64", previousPublicKey);
    }
  }

  @Test
  void appHost_whenTrustedPublicKeyConfiguredWithoutKeyId_expectInstallFailsWithVerificationError(
      @TempDir Path tempDir) throws Exception {
    NodeClientCore core = mock(NodeClientCore.class);
    Node node = mock(Node.class);
    ProgramDirectory nodeDir = mock(ProgramDirectory.class);
    ProgramDirectory runDir = mock(ProgramDirectory.class);
    SemiOrderedShutdownHook shutdownHook = mock(SemiOrderedShutdownHook.class);
    Path nodeDataDir = tempDir.resolve("node");
    Path cacheDir = tempDir.resolve("persistent-temp");
    Path runDataDir = tempDir.resolve("run");
    when(core.getNode()).thenReturn(node);
    when(node.nodeDir()).thenReturn(nodeDir);
    when(node.runDir()).thenReturn(runDir);
    when(nodeDir.dir()).thenReturn(nodeDataDir.toFile());
    when(runDir.dir()).thenReturn(runDataDir.toFile());
    when(core.getPersistentTempDir()).thenReturn(cacheDir.toFile());
    Path stagedDir = stageUnsignedApp(tempDir.resolve("staged"));
    KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    String previousKeyId = System.getProperty("cryptad.apphost.trustedKeyId");
    String previousPublicKey = System.getProperty("cryptad.apphost.trustedPublicKeyBase64");
    String previousPublicKeyFile = System.getProperty("cryptad.apphost.trustedPublicKeyFile");

    try {
      System.clearProperty("cryptad.apphost.trustedKeyId");
      System.setProperty(
          "cryptad.apphost.trustedPublicKeyBase64",
          Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
      System.clearProperty("cryptad.apphost.trustedPublicKeyFile");

      CoreHttpShellRuntimeSupport runtimeSupport;
      try (MockedStatic<SemiOrderedShutdownHook> shutdownHooks =
          mockStatic(SemiOrderedShutdownHook.class)) {
        stubShutdownHookLookup(shutdownHooks, shutdownHook);
        runtimeSupport = new CoreHttpShellRuntimeSupport(core);
      }

      AppHostConfigurationException exception =
          assertThrows(
              AppHostConfigurationException.class,
              () -> runtimeSupport.appHost().installFromDirectory(stagedDir));

      assertEquals(
          "Trusted app public key material requires trusted app key id.", exception.getMessage());
    } finally {
      restoreSystemProperty("cryptad.apphost.trustedKeyId", previousKeyId);
      restoreSystemProperty("cryptad.apphost.trustedPublicKeyBase64", previousPublicKey);
      restoreSystemProperty("cryptad.apphost.trustedPublicKeyFile", previousPublicKeyFile);
    }
  }

  @Test
  void appHost_whenConflictingTrustedPublicKeyInputsProvided_expectConfigurationFailure(
      @TempDir Path tempDir) throws Exception {
    NodeClientCore core = mock(NodeClientCore.class);
    Node node = mock(Node.class);
    ProgramDirectory nodeDir = mock(ProgramDirectory.class);
    ProgramDirectory runDir = mock(ProgramDirectory.class);
    SemiOrderedShutdownHook shutdownHook = mock(SemiOrderedShutdownHook.class);
    Path nodeDataDir = tempDir.resolve("node");
    Path cacheDir = tempDir.resolve("persistent-temp");
    Path runDataDir = tempDir.resolve("run");
    when(core.getNode()).thenReturn(node);
    when(node.nodeDir()).thenReturn(nodeDir);
    when(node.runDir()).thenReturn(runDir);
    when(nodeDir.dir()).thenReturn(nodeDataDir.toFile());
    when(runDir.dir()).thenReturn(runDataDir.toFile());
    when(core.getPersistentTempDir()).thenReturn(cacheDir.toFile());
    Path stagedDir = stageUnsignedApp(tempDir.resolve("staged"));
    KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    Path publicKeyFile = tempDir.resolve("public.pem");
    Files.writeString(
        publicKeyFile,
        Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()),
        StandardCharsets.UTF_8);
    String previousKeyId = System.getProperty("cryptad.apphost.trustedKeyId");
    String previousPublicKey = System.getProperty("cryptad.apphost.trustedPublicKeyBase64");
    String previousPublicKeyFile = System.getProperty("cryptad.apphost.trustedPublicKeyFile");

    try {
      System.setProperty("cryptad.apphost.trustedKeyId", TRUSTED_KEY_ID);
      System.setProperty(
          "cryptad.apphost.trustedPublicKeyBase64",
          Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
      System.setProperty("cryptad.apphost.trustedPublicKeyFile", publicKeyFile.toString());

      CoreHttpShellRuntimeSupport runtimeSupport;
      try (MockedStatic<SemiOrderedShutdownHook> shutdownHooks =
          mockStatic(SemiOrderedShutdownHook.class)) {
        stubShutdownHookLookup(shutdownHooks, shutdownHook);
        runtimeSupport = new CoreHttpShellRuntimeSupport(core);
      }

      AppHostConfigurationException exception =
          assertThrows(
              AppHostConfigurationException.class,
              () -> runtimeSupport.appHost().installFromDirectory(stagedDir));

      assertEquals(
          "Trusted app public key material must be configured by base64 or file, not both.",
          exception.getMessage());
    } finally {
      restoreSystemProperty("cryptad.apphost.trustedKeyId", previousKeyId);
      restoreSystemProperty("cryptad.apphost.trustedPublicKeyBase64", previousPublicKey);
      restoreSystemProperty("cryptad.apphost.trustedPublicKeyFile", previousPublicKeyFile);
    }
  }

  @ParameterizedTest
  @MethodSource("networkThreatLevelMappings")
  void addNetworkThreatLevelListener_whenSecurityLevelsChange_mapsDetachedEnums(
      NETWORK_THREAT_LEVEL oldLevel,
      HttpShellRuntimeSupport.NetworkThreatLevel expectedOldLevel,
      NETWORK_THREAT_LEVEL newLevel,
      HttpShellRuntimeSupport.NetworkThreatLevel expectedNewLevel) {
    NetworkListenerContext context = newNetworkListenerContext();
    AtomicReference<HttpShellRuntimeSupport.NetworkThreatLevel> actualOldLevel =
        new AtomicReference<>();
    AtomicReference<HttpShellRuntimeSupport.NetworkThreatLevel> actualNewLevel =
        new AtomicReference<>();

    context.runtimeSupport.addNetworkThreatLevelListener(
        (capturedOldLevel, capturedNewLevel) -> {
          actualOldLevel.set(capturedOldLevel);
          actualNewLevel.set(capturedNewLevel);
        });

    assertNotNull(context.listener.get());

    context.listener.get().onChange(oldLevel, newLevel);

    assertEquals(expectedOldLevel, actualOldLevel.get());
    assertEquals(expectedNewLevel, actualNewLevel.get());
  }

  @ParameterizedTest
  @MethodSource("physicalThreatLevelMappings")
  void addPhysicalThreatLevelListener_whenSecurityLevelsChange_mapsDetachedEnums(
      PHYSICAL_THREAT_LEVEL oldLevel,
      HttpShellRuntimeSupport.PhysicalThreatLevel expectedOldLevel,
      PHYSICAL_THREAT_LEVEL newLevel,
      HttpShellRuntimeSupport.PhysicalThreatLevel expectedNewLevel) {
    PhysicalListenerContext context = newPhysicalListenerContext();
    AtomicReference<HttpShellRuntimeSupport.PhysicalThreatLevel> actualOldLevel =
        new AtomicReference<>();
    AtomicReference<HttpShellRuntimeSupport.PhysicalThreatLevel> actualNewLevel =
        new AtomicReference<>();

    context.runtimeSupport.addPhysicalThreatLevelListener(
        (capturedOldLevel, capturedNewLevel) -> {
          actualOldLevel.set(capturedOldLevel);
          actualNewLevel.set(capturedNewLevel);
        });

    assertNotNull(context.listener.get());

    context.listener.get().onChange(oldLevel, newLevel);

    assertEquals(expectedOldLevel, actualOldLevel.get());
    assertEquals(expectedNewLevel, actualNewLevel.get());
  }

  @Test
  void createBrowseBootstrap_whenInvoked_constructsDependenciesAndReturnsBootstrap() {
    NodeClientCore core = mock(NodeClientCore.class);
    UserAlertManager alerts = mock(UserAlertManager.class);
    HighLevelSimpleClient client = mock(HighLevelSimpleClient.class);
    FetchContext fetchContext = mock(FetchContext.class);
    RuntimePorts bootstrapRuntimePorts = mock(RuntimePorts.class);
    AtomicReference<List<Object>> bookmarkManagerArguments = new AtomicReference<>();
    AtomicReference<List<Object>> fetchTrackerArguments = new AtomicReference<>();
    AtomicReference<List<Object>> browseRootArguments = new AtomicReference<>();
    when(core.getAlerts()).thenReturn(alerts);
    when(core.makeClient(RequestStarter.INTERACTIVE_PRIORITY_CLASS, true, true)).thenReturn(client);
    when(client.getFetchContext()).thenReturn(fetchContext);
    CoreHttpShellRuntimeSupport runtimeSupport = runtimeSupport(core);

    try (MockedConstruction<BookmarkManager> bookmarkManagers =
            mockConstruction(
                BookmarkManager.class,
                (_, invocation) ->
                    bookmarkManagerArguments.set(List.copyOf(invocation.arguments())));
        MockedConstruction<FProxyFetchTracker> fetchTrackers =
            mockConstruction(
                FProxyFetchTracker.class,
                (_, invocation) -> fetchTrackerArguments.set(List.copyOf(invocation.arguments())));
        MockedConstruction<FProxyToadlet> fproxies =
            mockConstruction(
                FProxyToadlet.class,
                (_, invocation) -> browseRootArguments.set(List.copyOf(invocation.arguments())))) {
      HttpShellBrowseBootstrap bootstrap = runtimeSupport.createBrowseBootstrap(true);

      assertEquals(1, bookmarkManagers.constructed().size());
      assertEquals(1, fetchTrackers.constructed().size());
      assertEquals(1, fproxies.constructed().size());
      assertInstanceOf(CoreBookmarkRuntimeSupport.class, bookmarkManagerArguments.get().get(0));
      assertSame(alerts, bookmarkManagerArguments.get().get(1));
      assertEquals(Boolean.TRUE, bookmarkManagerArguments.get().get(2));
      assertSame(fetchContext, fetchTrackerArguments.get().get(0));
      assertInstanceOf(CoreFProxyRuntimeSupport.class, fetchTrackerArguments.get().get(1));
      assertNotNull(fetchTrackerArguments.get().get(2));
      assertInstanceOf(BrowseContentClient.class, browseRootArguments.get().get(0));
      assertInstanceOf(CoreFProxyRuntimeSupport.class, browseRootArguments.get().get(1));
      assertSame(fetchTrackers.constructed().getFirst(), browseRootArguments.get().get(2));
      assertSame(bookmarkManagers.constructed().getFirst(), bootstrap.bookmarkManager());
      assertSame(runtimeSupport.appHost(), bootstrap.appHost());
      assertSame(fproxies.constructed().getFirst(), bootstrap.browseRoot());
      assertContentToadlet(fproxies.constructed().getFirst());
      LegacyFProxyBrowseRouteRegistrar browseRouteRegistrar =
          assertInstanceOf(
              LegacyFProxyBrowseRouteRegistrar.class, bootstrap.browseRouteRegistrar());
      assertInstanceOf(BrowseContentClient.class, readRegistrarClient(browseRouteRegistrar));
      verify(core, never()).getRuntimePorts();
      verifyNoInteractions(bootstrapRuntimePorts);
      verify(core, never()).getEndpoints();
    }
  }

  @Test
  void createBrowseBootstrap_whenInitializerInvoked_seedsSharedForceLinkRandom() {
    NodeClientCore core = mock(NodeClientCore.class);
    UserAlertManager alerts = mock(UserAlertManager.class);
    HighLevelSimpleClient client = mock(HighLevelSimpleClient.class);
    FetchContext fetchContext = mock(FetchContext.class);
    RuntimePorts runtimePorts = mock(RuntimePorts.class);
    RandomnessPort randomnessPort = mock(RandomnessPort.class);
    when(core.getAlerts()).thenReturn(alerts);
    when(core.makeClient(RequestStarter.INTERACTIVE_PRIORITY_CLASS, true, true)).thenReturn(client);
    when(client.getFetchContext()).thenReturn(fetchContext);
    when(runtimePorts.randomness()).thenReturn(randomnessPort);
    CoreHttpShellRuntimeSupport runtimeSupport = runtimeSupport(core);

    try (var _ = mockConstruction(BookmarkManager.class)) {
      HttpShellBrowseBootstrap bootstrap = runtimeSupport.createBrowseBootstrap(true);

      bootstrap.sharedShellInitializer().accept(runtimePorts);
    }

    ArgumentCaptor<byte[]> randomCaptor = ArgumentCaptor.forClass(byte[].class);
    verify(runtimePorts).randomness();
    verify(randomnessPort).fillSecureRandom(randomCaptor.capture());
    assertEquals(32, randomCaptor.getValue().length);
  }

  @Test
  void createPushDataManagerHandle_whenInvoked_constructsConcreteBrowseManager() {
    NodeClientCore core = mock(NodeClientCore.class);
    Ticker ticker = mock(Ticker.class);
    CoreHttpShellRuntimeSupport runtimeSupport = runtimeSupport(core);

    try (MockedConstruction<PushDataManager> pushManagers =
        mockConstruction(
            PushDataManager.class,
            (_, invocation) -> assertSame(ticker, invocation.arguments().getFirst()))) {
      PushDataManagerHandle handle = runtimeSupport.createPushDataManagerHandle(ticker);

      assertEquals(1, pushManagers.constructed().size());
      assertSame(pushManagers.constructed().getFirst(), handle);
    }
  }

  @Test
  void createPushDataManagerHandle_whenTickerNull_throwsNullPointerException() {
    CoreHttpShellRuntimeSupport runtimeSupport = runtimeSupport(mock(NodeClientCore.class));

    assertThrows(
        NullPointerException.class, () -> runtimeSupport.createPushDataManagerHandle(null));
  }

  @Test
  void createAppHostShutdownJob_whenAppsRunning_stopsEachRunningApp() throws Exception {
    AppHost appHost = mock(AppHost.class);
    when(appHost.listRunning())
        .thenReturn(List.of(runningAppSnapshot("alpha"), runningAppSnapshot("beta")));
    when(appHost.stop("alpha")).thenReturn(true);
    doThrow(new IOException("boom")).when(appHost).stop("beta");

    Thread shutdownJob = CoreHttpShellRuntimeSupport.createAppHostShutdownJob(appHost);
    shutdownJob.start();
    shutdownJob.join();

    verify(appHost).stop("alpha");
    verify(appHost).stop("beta");
  }

  private static Stream<Arguments> networkThreatLevelMappings() {
    return Stream.of(
        Arguments.of(
            NETWORK_THREAT_LEVEL.LOW,
            HttpShellRuntimeSupport.NetworkThreatLevel.LOW,
            NETWORK_THREAT_LEVEL.NORMAL,
            HttpShellRuntimeSupport.NetworkThreatLevel.NORMAL),
        Arguments.of(
            NETWORK_THREAT_LEVEL.NORMAL,
            HttpShellRuntimeSupport.NetworkThreatLevel.NORMAL,
            NETWORK_THREAT_LEVEL.HIGH,
            HttpShellRuntimeSupport.NetworkThreatLevel.HIGH),
        Arguments.of(
            NETWORK_THREAT_LEVEL.HIGH,
            HttpShellRuntimeSupport.NetworkThreatLevel.HIGH,
            NETWORK_THREAT_LEVEL.MAXIMUM,
            HttpShellRuntimeSupport.NetworkThreatLevel.MAXIMUM),
        Arguments.of(
            NETWORK_THREAT_LEVEL.MAXIMUM,
            HttpShellRuntimeSupport.NetworkThreatLevel.MAXIMUM,
            NETWORK_THREAT_LEVEL.LOW,
            HttpShellRuntimeSupport.NetworkThreatLevel.LOW));
  }

  private static Stream<Arguments> physicalThreatLevelMappings() {
    return Stream.of(
        Arguments.of(
            PHYSICAL_THREAT_LEVEL.LOW,
            HttpShellRuntimeSupport.PhysicalThreatLevel.LOW,
            PHYSICAL_THREAT_LEVEL.NORMAL,
            HttpShellRuntimeSupport.PhysicalThreatLevel.NORMAL),
        Arguments.of(
            PHYSICAL_THREAT_LEVEL.NORMAL,
            HttpShellRuntimeSupport.PhysicalThreatLevel.NORMAL,
            PHYSICAL_THREAT_LEVEL.HIGH,
            HttpShellRuntimeSupport.PhysicalThreatLevel.HIGH),
        Arguments.of(
            PHYSICAL_THREAT_LEVEL.HIGH,
            HttpShellRuntimeSupport.PhysicalThreatLevel.HIGH,
            PHYSICAL_THREAT_LEVEL.MAXIMUM,
            HttpShellRuntimeSupport.PhysicalThreatLevel.MAXIMUM),
        Arguments.of(
            PHYSICAL_THREAT_LEVEL.MAXIMUM,
            HttpShellRuntimeSupport.PhysicalThreatLevel.MAXIMUM,
            PHYSICAL_THREAT_LEVEL.LOW,
            HttpShellRuntimeSupport.PhysicalThreatLevel.LOW));
  }

  private static NetworkListenerContext newNetworkListenerContext() {
    NodeClientCore core = mock(NodeClientCore.class);
    Node node = mock(Node.class);
    NodeServicesSubsystem services = mock(NodeServicesSubsystem.class);
    SecurityLevels securityLevels = mock(SecurityLevels.class);
    AtomicReference<SecurityLevelListener<NETWORK_THREAT_LEVEL>> listener = new AtomicReference<>();
    when(core.getNode()).thenReturn(node);
    when(node.services()).thenReturn(services);
    when(services.securityLevels()).thenReturn(securityLevels);
    doAnswer(
            invocation -> {
              listener.set(invocation.getArgument(0));
              return null;
            })
        .when(securityLevels)
        .addNetworkThreatLevelListener(any());
    return new NetworkListenerContext(runtimeSupport(core), listener);
  }

  private static PhysicalListenerContext newPhysicalListenerContext() {
    NodeClientCore core = mock(NodeClientCore.class);
    Node node = mock(Node.class);
    NodeServicesSubsystem services = mock(NodeServicesSubsystem.class);
    SecurityLevels securityLevels = mock(SecurityLevels.class);
    AtomicReference<SecurityLevelListener<PHYSICAL_THREAT_LEVEL>> listener =
        new AtomicReference<>();
    when(core.getNode()).thenReturn(node);
    when(node.services()).thenReturn(services);
    when(services.securityLevels()).thenReturn(securityLevels);
    doAnswer(
            invocation -> {
              listener.set(invocation.getArgument(0));
              return null;
            })
        .when(securityLevels)
        .addPhysicalThreatLevelListener(any());
    return new PhysicalListenerContext(runtimeSupport(core), listener);
  }

  private static CoreHttpShellRuntimeSupport runtimeSupport(NodeClientCore core) {
    return new CoreHttpShellRuntimeSupport(core, mock(AppHost.class));
  }

  private static BrowseContentClient readRegistrarClient(
      LegacyFProxyBrowseRouteRegistrar registrar) {
    try {
      Field field = registrar.getClass().getDeclaredField("client");
      field.setAccessible(true);
      return (BrowseContentClient) field.get(registrar);
    } catch (ReflectiveOperationException e) {
      throw new LinkageError("Failed reading field 'client'", e);
    }
  }

  private static AppHostLayout readLayout(LocalProcessAppHost appHost) {
    try {
      Field field = appHost.getClass().getDeclaredField("layout");
      field.setAccessible(true);
      return (AppHostLayout) field.get(appHost);
    } catch (ReflectiveOperationException e) {
      throw new LinkageError("Failed reading field 'layout'", e);
    }
  }

  private static RunningAppSnapshot runningAppSnapshot(String appId) {
    AppManifest manifest =
        new AppManifest(
            1,
            appId,
            "Demo App",
            "1.0.0",
            "bin/launch",
            "/",
            List.of("network.access"),
            1024L,
            512L);
    InstalledAppPaths paths =
        new InstalledAppPaths(
            appId,
            Path.of("build", "test-runtime", "apphost", "installed", appId).toAbsolutePath(),
            Path.of("build", "test-runtime", "apphost", "data", appId).toAbsolutePath(),
            Path.of("build", "test-runtime", "apphost", "cache", appId).toAbsolutePath(),
            Path.of("build", "test-runtime", "apphost", "run", appId).toAbsolutePath());
    return new RunningAppSnapshot(
        manifest, paths, "token-" + appId, 4242L, Instant.parse("2024-01-02T03:04:05Z"));
  }

  private static Path stageUnsignedApp(Path stagedDir) throws IOException {
    Path binDir = Files.createDirectories(stagedDir.resolve("bin"));
    Path launcher = binDir.resolve("launch.sh");
    Files.writeString(
        launcher,
        """
        #!/bin/sh
        exit 0
        """,
        StandardCharsets.UTF_8);
    Files.writeString(
        stagedDir.resolve(AppManifestParser.MANIFEST_FILE_NAME),
        """
        manifest.version=1
        app.id=demo-app
        app.name=Demo App
        app.version=1.0.0
        app.exec=bin/launch.sh
        app.ui.entry=/
        app.permissions=network.access
        quota.data.bytes=1024
        quota.cache.bytes=512
        """,
        StandardCharsets.UTF_8);
    return stagedDir;
  }

  private static Path stageSignedApp(Path stagedDir, KeyPair keyPair) throws IOException {
    Path unsigned = stageUnsignedApp(stagedDir);
    AppBundleSigner.sign(unsigned, TRUSTED_KEY_ID, keyPair.getPrivate());
    return unsigned;
  }

  private static Path stageSignedApp(Path stagedDir, String appId, KeyPair keyPair, String keyId)
      throws IOException {
    Path unsigned = stageUnsignedApp(stagedDir);
    String manifest =
        Files.readString(unsigned.resolve(AppManifestParser.MANIFEST_FILE_NAME))
            .replace("app.id=demo-app", "app.id=" + appId);
    Files.writeString(
        unsigned.resolve(AppManifestParser.MANIFEST_FILE_NAME), manifest, StandardCharsets.UTF_8);
    AppBundleSigner.sign(unsigned, keyId, keyPair.getPrivate());
    return unsigned;
  }

  private static Path stageLongRunningSignedApp(Path stagedDir, KeyPair keyPair)
      throws IOException {
    Path unsigned = stageUnsignedApp(stagedDir);
    String manifest =
        Files.readString(unsigned.resolve(AppManifestParser.MANIFEST_FILE_NAME))
            .replace("app.id=demo-app", "app.id=stable-app");
    Files.writeString(
        unsigned.resolve(AppManifestParser.MANIFEST_FILE_NAME), manifest, StandardCharsets.UTF_8);
    Files.writeString(
        unsigned.resolve("bin").resolve("launch.sh"),
        "#!/bin/sh\nsleep 30\n",
        StandardCharsets.UTF_8);
    AppBundleSigner.sign(unsigned, "stable-first-party", keyPair.getPrivate());
    return unsigned;
  }

  private static void writePilotApproval(
      Path file,
      KeyPair publisherKeyPair,
      Path approvedBundle,
      String normalRegistryDigest,
      String catalogRegistryDigest,
      String pilotRegistryDigest)
      throws Exception {
    writePilotApproval(
        file,
        publisherKeyPair,
        approvedBundle,
        normalRegistryDigest,
        catalogRegistryDigest,
        pilotRegistryDigest,
        Instant.now().minusSeconds(300),
        Instant.now().plusSeconds(3600));
  }

  private static void writePilotApproval(
      Path file,
      KeyPair publisherKeyPair,
      Path approvedBundle,
      String normalRegistryDigest,
      String catalogRegistryDigest,
      String pilotRegistryDigest,
      Instant validFrom,
      Instant validUntil)
      throws Exception {
    String signatureDigest = sha256(approvedBundle.resolve("cryptad-app.signature"));
    Files.writeString(
        file,
        """
        {"schemaVersion":1,"kind":"stable-1.0-pilot-publisher-key-approval","pilotId":"pilot-294","appId":"demo-app","provenance":{},"publisherKeyId":"external-publisher","publisherFingerprint":"%s","sourceRepositoryIdentity":"github.com/external/pilot","handoffDigest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","pilotNodeId":"node-294","nodeAttestationFingerprint":"sha256:2222222222222222222222222222222222222222222222222222222222222222","normalStableRegistryDigest":"%s","catalogRegistryDigest":"%s","pilotRegistryDigest":"%s","permittedSubjects":[{"version":"1.0.0","bundleDigest":"sha256:3333333333333333333333333333333333333333333333333333333333333333","bundleSignatureDigest":"%s"},{"version":"2.0.0","bundleDigest":"sha256:4444444444444444444444444444444444444444444444444444444444444444","bundleSignatureDigest":"sha256:5555555555555555555555555555555555555555555555555555555555555555"},{"version":"3.0.0","bundleDigest":"sha256:6666666666666666666666666666666666666666666666666666666666666666","bundleSignatureDigest":"sha256:7777777777777777777777777777777777777777777777777777777777777777"}],"allowedOperations":["install","update","caution-update","rollback","cleanup"],"validFrom":"%s","validUntil":"%s","revoked":false,"cleanupRequired":true,"approvalAuthorityKeyId":"reviewer-294","receiptDigest":"sha256:8888888888888888888888888888888888888888888888888888888888888888","signatureBase64":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="}
        """
            .formatted(
                sha256(publisherKeyPair.getPublic().getEncoded()),
                normalRegistryDigest,
                catalogRegistryDigest,
                pilotRegistryDigest,
                signatureDigest,
                validFrom,
                validUntil),
        StandardCharsets.UTF_8);
  }

  private static Map<String, String> pilotProperties(
      Path normalRegistry, Path catalogRegistry, Path pilotRegistry, Path approvalFile)
      throws Exception {
    return Map.of(
        "cryptad.apphost.trustedKeysFile", normalRegistry.toString(),
        "cryptad.appcatalog.trustedKeysFile", catalogRegistry.toString(),
        "cryptad.apphost.pilot.id", "pilot-294",
        "cryptad.apphost.pilot.nodeId", "node-294",
        "cryptad.apphost.pilot.approvalFile", approvalFile.toString(),
        "cryptad.apphost.pilot.approvalDigest", sha256(approvalFile),
        "cryptad.apphost.pilot.trustedKeysFile", pilotRegistry.toString());
  }

  private static String sha256(Path file) throws Exception {
    return sha256(Files.readAllBytes(file));
  }

  private static String sha256(byte[] value) throws Exception {
    return "sha256:" + HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));
  }

  private static CoreHttpShellRuntimeSupport managedRuntimeSupport(Path root) {
    NodeClientCore core = mock(NodeClientCore.class);
    Node node = mock(Node.class);
    ProgramDirectory nodeDir = mock(ProgramDirectory.class);
    ProgramDirectory runDir = mock(ProgramDirectory.class);
    SemiOrderedShutdownHook shutdownHook = mock(SemiOrderedShutdownHook.class);
    when(core.getNode()).thenReturn(node);
    when(node.nodeDir()).thenReturn(nodeDir);
    when(node.runDir()).thenReturn(runDir);
    when(nodeDir.dir()).thenReturn(root.resolve("node").toFile());
    when(runDir.dir()).thenReturn(root.resolve("run").toFile());
    when(core.getPersistentTempDir()).thenReturn(root.resolve("persistent-temp").toFile());
    try (MockedStatic<SemiOrderedShutdownHook> shutdownHooks =
        mockStatic(SemiOrderedShutdownHook.class)) {
      stubShutdownHookLookup(shutdownHooks, shutdownHook);
      return new CoreHttpShellRuntimeSupport(core);
    }
  }

  private static void writeTrustedKeysFile(Path file, String keyId, KeyPair keyPair)
      throws IOException {
    Files.writeString(
        file,
        String.join(
            "\n",
            "trusted.keys.version=1",
            "key.0.id=" + keyId,
            "key.0.algorithm=Ed25519",
            "key.0.public.key.base64="
                + Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()),
            ""),
        StandardCharsets.UTF_8);
  }

  private static void writeLifecycleTrustedKeysFile(Path file, KeyPair keyPair, String status)
      throws IOException {
    Files.writeString(
        file,
        String.join(
            "\n",
            "trusted.keys.version=2",
            "key.0.id=" + TRUSTED_KEY_ID,
            "key.0.algorithm=Ed25519",
            "key.0.public.key.base64="
                + Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()),
            "key.0.status=" + status,
            "key.0.valid.from=2020-01-01T00:00:00Z",
            "key.0.valid.until=2100-01-01T00:00:00Z",
            ""),
        StandardCharsets.UTF_8);
  }

  private static void stubShutdownHookLookup(
      MockedStatic<SemiOrderedShutdownHook> shutdownHooks, SemiOrderedShutdownHook shutdownHook) {
    shutdownHooks
        .when(() -> assertNotSame(shutdownHook, SemiOrderedShutdownHook.get()))
        .thenReturn(shutdownHook);
  }

  private static void restoreSystemProperty(String name, String value) {
    if (value == null) {
      System.clearProperty(name);
    } else {
      System.setProperty(name, value);
    }
  }

  private static void assertContentToadlet(Toadlet toadlet) {
    assertInstanceOf(
        ContentToadlet.class,
        toadlet,
        toadlet.getClass().getName() + " must extend ContentToadlet");
  }

  private record NetworkListenerContext(
      CoreHttpShellRuntimeSupport runtimeSupport,
      AtomicReference<SecurityLevelListener<NETWORK_THREAT_LEVEL>> listener) {}

  private record PhysicalListenerContext(
      CoreHttpShellRuntimeSupport runtimeSupport,
      AtomicReference<SecurityLevelListener<PHYSICAL_THREAT_LEVEL>> listener) {}

  private static final class SystemPropertyScope implements AutoCloseable {
    private final Map<String, String> previousValues;

    private SystemPropertyScope(Map<String, String> values) {
      Map<String, String> previous = new java.util.LinkedHashMap<>();
      values.forEach(
          (name, value) -> {
            previous.put(name, System.getProperty(name));
            System.setProperty(name, value);
          });
      previousValues = previous;
    }

    private static SystemPropertyScope set(Map<String, String> values) {
      return new SystemPropertyScope(values);
    }

    @Override
    public void close() {
      previousValues.forEach(CoreHttpShellRuntimeSupportTest::restoreSystemProperty);
    }
  }
}
