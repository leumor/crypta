package network.crypta.clients.http.bridge;

import java.io.File;
import java.io.IOException;
import java.nio.channels.Channels;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;
import network.crypta.client.InsertContext.CompatibilityMode;
import network.crypta.clients.http.BrowseContentClient;
import network.crypta.clients.http.FProxyFetchTracker;
import network.crypta.clients.http.FProxyToadlet;
import network.crypta.clients.http.HttpShellBrowseBootstrap;
import network.crypta.clients.http.HttpShellRuntimeSupport;
import network.crypta.clients.http.InsertCompatibilityModes;
import network.crypta.clients.http.LegacyFProxyBrowseRouteRegistrar;
import network.crypta.clients.http.PushDataManagerHandle;
import network.crypta.clients.http.SimpleToadletServer;
import network.crypta.clients.http.bookmark.BookmarkManager;
import network.crypta.clients.http.bridge.bookmark.CoreBookmarkRuntimeSupport;
import network.crypta.clients.http.updateableelements.PushDataManager;
import network.crypta.config.Config;
import network.crypta.node.NodeClientCore;
import network.crypta.node.RequestClientBuilder;
import network.crypta.node.RequestPriorityClasses;
import network.crypta.node.SecurityLevels.NETWORK_THREAT_LEVEL;
import network.crypta.node.SecurityLevels.PHYSICAL_THREAT_LEVEL;
import network.crypta.node.SemiOrderedShutdownHook;
import network.crypta.platform.api.appdata.AppDataService;
import network.crypta.platform.api.appdata.AppDataStoreConfig;
import network.crypta.platform.api.appdata.FileAppDataStore;
import network.crypta.platform.api.appservices.AppServiceCoordinator;
import network.crypta.platform.api.appservices.FileAppServiceGrantStore;
import network.crypta.platform.api.appservices.TrustGraphScoreAppServiceAdapter;
import network.crypta.platform.api.appupdates.AppUpdateFederationAuthority;
import network.crypta.platform.api.appupdates.AppUpdateScheduler;
import network.crypta.platform.api.appupdates.AppUpdateSchedulerConfig;
import network.crypta.platform.api.appupdates.AppUpdateSchedulerStore;
import network.crypta.platform.api.appupdates.AppUpdateService;
import network.crypta.platform.api.appupdates.FileAppUpdateSchedulerStore;
import network.crypta.platform.api.content.subscriptions.ContentSubscriptionPressureGate;
import network.crypta.platform.api.content.subscriptions.ContentSubscriptionScheduler;
import network.crypta.platform.api.content.subscriptions.ContentSubscriptionSchedulerConfig;
import network.crypta.platform.api.content.subscriptions.ContentSubscriptionService;
import network.crypta.platform.api.content.subscriptions.ContentSubscriptionStore;
import network.crypta.platform.api.content.subscriptions.FileContentSubscriptionStore;
import network.crypta.platform.api.networkbudget.AppNetworkBudgetConfig;
import network.crypta.platform.api.networkbudget.AppNetworkBudgetService;
import network.crypta.platform.api.networkbudget.FileAppNetworkBudgetStore;
import network.crypta.platform.api.trust.TrustGraphApiHandler;
import network.crypta.platform.appcatalog.AppCatalogBundleVerificationContext;
import network.crypta.platform.appcatalog.AppCatalogBundleVerificationPolicy;
import network.crypta.platform.appcatalog.AppCatalogBundleVerificationResult;
import network.crypta.platform.appcatalog.AppCatalogManager.TrustedKeyProvider;
import network.crypta.platform.appcatalog.AppCatalogManager;
import network.crypta.platform.appcatalog.AppCatalogSourceStore;
import network.crypta.platform.appcatalog.CatalogScopedPublisherVerificationPolicy;
import network.crypta.platform.appcatalog.CatalogScopedReviewerPolicy;
import network.crypta.platform.appcatalog.FileCatalogPublisherBindingStore;
import network.crypta.platform.appcatalog.FileCatalogReviewerScopeStore;
import network.crypta.platform.appcatalog.FileFederatedCatalogConflictResolutionStore;
import network.crypta.platform.appcatalog.FileFederatedCatalogTrustStore;
import network.crypta.platform.appcatalog.FilePendingCatalogDiscoveryStore;
import network.crypta.platform.appcatalog.TrustedReviewerKeysLoader;
import network.crypta.platform.appdist.AppBundleSignature;
import network.crypta.platform.appdist.AppBundleVerification;
import network.crypta.platform.appdist.AppBundleVerifier;
import network.crypta.platform.appdist.AppDistributionException;
import network.crypta.platform.appdist.TrustedAppKey;
import network.crypta.platform.appdist.TrustedAppKeys;
import network.crypta.platform.apphost.AppBundleVerificationException;
import network.crypta.platform.apphost.AppHost;
import network.crypta.platform.apphost.AppHostConfigurationException;
import network.crypta.platform.apphost.AppHostLayout;
import network.crypta.platform.apphost.AppInstallVerificationPolicy;
import network.crypta.platform.apphost.InstalledAppOrigin;
import network.crypta.platform.apphost.PilotPublisherApprovalReader;
import network.crypta.platform.apphost.PilotPublisherVerificationPolicy;
import network.crypta.platform.apphost.RunningAppSnapshot;
import network.crypta.platform.apphost.runtime.LocalProcessAppHost;
import network.crypta.platform.appvault.AppVaultService;
import network.crypta.platform.trustgraph.FileTrustGraphStore;
import network.crypta.runtime.alerts.UserAlertSurface;
import network.crypta.runtime.spi.RuntimePorts;
import network.crypta.support.Ticker;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Adapts {@link NodeClientCore} to the narrow runtime surface used by {@link SimpleToadletServer}.
 *
 * <p>This record keeps the remaining HTTP-shell coupling inside the adapter-owned HTTP bridge layer
 * instead of letting the server reach directly into the daemon core. Callers normally create one
 * instance during a server bootstrap and then treat it as an immutable delegate. The adapter is
 * intentionally HTTP-local rather than a reusable platform API: it still exposes alerts, config
 * storage, upload permission checks, AppHost access, and browse bootstrap work because those
 * behaviors remain part of the HTTP shell in the current architecture.
 *
 * @param core daemon core that backs delegated shell services and browse bootstrap wiring
 * @param appHost shared AppHost instance used by the platform control plane
 * @param appCatalogManager shared signed app-catalog manager used by the platform control plane
 * @param appUpdateService shared app-update service used by update routes and scheduler
 * @param appUpdateScheduler optional background app-update scheduler
 * @param contentSubscriptionService optional content subscription service used by subscription
 *     routes and scheduler
 * @param contentSubscriptionScheduler optional background content subscription scheduler
 * @param appDataService shared durable app-data service used by Platform API app-data routes
 * @param trustGraphApiHandler shared durable trust graph handler used by Platform API trust routes
 * @param appServiceCoordinator shared app-service coordinator used by Platform API service routes
 * @param appNetworkBudgetService shared app-network budget service used by Platform API network
 *     routes
 * @param appVaultService shared app vault used by the platform control plane
 */
public record CoreHttpShellRuntimeSupport(
    NodeClientCore core,
    AppHost appHost,
    AppCatalogManager appCatalogManager,
    AppUpdateService appUpdateService,
    AppUpdateScheduler appUpdateScheduler,
    ContentSubscriptionService contentSubscriptionService,
    ContentSubscriptionScheduler contentSubscriptionScheduler,
    AppDataService appDataService,
    TrustGraphApiHandler trustGraphApiHandler,
    AppServiceCoordinator appServiceCoordinator,
    AppNetworkBudgetService appNetworkBudgetService,
    AppVaultService appVaultService)
    implements network.crypta.runtime.http.HttpShellRuntimeSupport, HttpShellRuntimeSupport {
  private static final Logger LOG = LoggerFactory.getLogger(CoreHttpShellRuntimeSupport.class);
  private static final String APPHOST_ALLOW_UNSIGNED_PROPERTY = "cryptad.apphost.allowUnsigned";
  private static final String APPHOST_ALLOW_UNSIGNED_ENV = "CRYPTAD_APPHOST_ALLOW_UNSIGNED";
  private static final String TRUSTED_KEYS_FILE_PROPERTY = "cryptad.apphost.trustedKeysFile";
  private static final String TRUSTED_KEYS_FILE_ENV = "CRYPTAD_APPHOST_TRUSTED_KEYS_FILE";
  private static final String CATALOG_TRUSTED_KEYS_FILE_PROPERTY =
      "cryptad.appcatalog.trustedKeysFile";
  private static final String CATALOG_TRUSTED_KEYS_FILE_ENV =
      "CRYPTAD_APPCATALOG_TRUSTED_KEYS_FILE";
  private static final String TRUSTED_KEY_ID_PROPERTY = "cryptad.apphost.trustedKeyId";
  private static final String TRUSTED_KEY_ID_ENV = "CRYPTAD_APPHOST_TRUSTED_KEY_ID";
  private static final String TRUSTED_PUBLIC_KEY_BASE64_PROPERTY =
      "cryptad.apphost.trustedPublicKeyBase64";
  private static final String TRUSTED_PUBLIC_KEY_BASE64_ENV =
      "CRYPTAD_APPHOST_TRUSTED_PUBLIC_KEY_BASE64";
  private static final String TRUSTED_PUBLIC_KEY_FILE_PROPERTY =
      "cryptad.apphost.trustedPublicKeyFile";
  private static final String TRUSTED_PUBLIC_KEY_FILE_ENV =
      "CRYPTAD_APPHOST_TRUSTED_PUBLIC_KEY_FILE";
  private static final String PILOT_ID_PROPERTY = "cryptad.apphost.pilot.id";
  private static final String PILOT_ID_ENV = "CRYPTAD_APPHOST_PILOT_ID";
  private static final String PILOT_NODE_ID_PROPERTY = "cryptad.apphost.pilot.nodeId";
  private static final String PILOT_NODE_ID_ENV = "CRYPTAD_APPHOST_PILOT_NODE_ID";
  private static final String PILOT_APPROVAL_FILE_PROPERTY = "cryptad.apphost.pilot.approvalFile";
  private static final String PILOT_APPROVAL_FILE_ENV = "CRYPTAD_APPHOST_PILOT_APPROVAL_FILE";
  private static final String PILOT_APPROVAL_DIGEST_PROPERTY =
      "cryptad.apphost.pilot.approvalDigest";
  private static final String PILOT_APPROVAL_DIGEST_ENV = "CRYPTAD_APPHOST_PILOT_APPROVAL_DIGEST";
  private static final String PILOT_TRUSTED_KEYS_FILE_PROPERTY =
      "cryptad.apphost.pilot.trustedKeysFile";
  private static final String PILOT_TRUSTED_KEYS_FILE_ENV =
      "CRYPTAD_APPHOST_PILOT_TRUSTED_KEYS_FILE";
  private static final String NORMAL_STABLE_ROLE_LABEL = "normal Stable";
  private static final String CATALOG_AUTHORITY_ROLE_LABEL = "catalog authority";
  private static final String TRUST_CONFIGURATION_ERROR_MESSAGE =
      "Failed to load trusted app verification configuration.";
  private static final AtomicBoolean LEGACY_CATALOG_TRUST_WARNING_EMITTED = new AtomicBoolean();

  /**
   * Creates a core-backed HTTP runtime adapter.
   *
   * <p>The supplied daemon core must stay valid for the lifetime of the surrounding HTTP shell.
   * This adapter retains the reference and delegates every runtime operation to it.
   *
   * @param core daemon core that supplies the shell-level runtime services
   * @throws NullPointerException if {@code core} is {@code null}
   */
  public CoreHttpShellRuntimeSupport(NodeClientCore core) {
    this(Objects.requireNonNull(core, "core"), createManagedAppServices(core));
  }

  private CoreHttpShellRuntimeSupport(NodeClientCore core, AppPlatformServices services) {
    this(
        core,
        services.appHost(),
        services.appCatalogManager(),
        services.appUpdateService(),
        services.appUpdateScheduler(),
        services.contentSubscriptionService(),
        services.contentSubscriptionScheduler(),
        services.appDataService(),
        services.trustGraphApiHandler(),
        services.appServiceCoordinator(),
        services.appNetworkBudgetService(),
        services.appVaultService());
  }

  /**
   * Creates a core-backed HTTP runtime adapter with an explicit AppHost.
   *
   * @param core daemon core that supplies the shell-level runtime services
   * @param appHost shared AppHost instance used by the platform control plane
   * @throws NullPointerException if {@code core} or {@code appHost} is {@code null}
   */
  public CoreHttpShellRuntimeSupport(NodeClientCore core, AppHost appHost) {
    this(core, appHost, null, null);
  }

  /**
   * Creates a core-backed HTTP runtime adapter with explicit app platform services.
   *
   * @param core daemon core that supplies the shell-level runtime services
   * @param appHost shared AppHost instance used by the platform control plane
   * @param appCatalogManager shared app-catalog manager, or {@code null} when unavailable
   * @throws NullPointerException if {@code core} or {@code appHost} is {@code null}
   */
  @SuppressWarnings("unused")
  public CoreHttpShellRuntimeSupport(
      NodeClientCore core, AppHost appHost, AppCatalogManager appCatalogManager) {
    this(core, appHost, appCatalogManager, null);
  }

  /**
   * Creates a core-backed HTTP runtime adapter with explicit app platform services.
   *
   * @param core daemon core that supplies the shell-level runtime services
   * @param appHost shared AppHost instance used by the platform control plane
   * @param appCatalogManager shared app-catalog manager, or {@code null} when unavailable
   * @param appVaultService shared app-vault service, or {@code null} when unavailable
   * @throws NullPointerException if {@code core} or {@code appHost} is {@code null}
   */
  public CoreHttpShellRuntimeSupport(
      NodeClientCore core,
      AppHost appHost,
      AppCatalogManager appCatalogManager,
      AppVaultService appVaultService) {
    this(
        core,
        appHost,
        appCatalogManager,
        appCatalogManager == null
            ? null
            : new AppUpdateService(appHost, appCatalogManager, appVaultService),
        null,
        null,
        null,
        null,
        null,
        null,
        null,
        appVaultService);
  }

  /**
   * Creates a core-backed HTTP runtime adapter with explicit app-platform services.
   *
   * @param core daemon core that supplies the shell-level runtime services
   * @param appHost shared AppHost instance used by the platform control plane
   * @param appCatalogManager shared app-catalog manager, or {@code null} when unavailable
   * @param appUpdateService shared app-update lifecycle service, or {@code null} when unavailable
   * @param appUpdateScheduler optional background app-update scheduler
   * @param appVaultService shared app-vault service, or {@code null} when unavailable
   * @throws NullPointerException if {@code core} or {@code appHost} is {@code null}
   */
  @SuppressWarnings("unused")
  public CoreHttpShellRuntimeSupport(
      NodeClientCore core,
      AppHost appHost,
      AppCatalogManager appCatalogManager,
      AppUpdateService appUpdateService,
      AppUpdateScheduler appUpdateScheduler,
      AppVaultService appVaultService) {
    this(
        core,
        appHost,
        appCatalogManager,
        appUpdateService,
        appUpdateScheduler,
        null,
        null,
        null,
        null,
        null,
        null,
        appVaultService);
  }

  /**
   * Creates a core-backed HTTP runtime adapter with explicit app-platform services.
   *
   * @param core daemon core that supplies the shell-level runtime services
   * @param appHost shared AppHost instance used by the platform control plane
   * @param appCatalogManager shared app-catalog manager, or {@code null} when unavailable
   * @param appUpdateService shared app-update lifecycle service, or {@code null} when unavailable
   * @param appUpdateScheduler optional background app-update scheduler
   * @param contentSubscriptionService optional content subscription service
   * @param contentSubscriptionScheduler optional background content subscription scheduler
   * @param appVaultService shared app-vault service, or {@code null} when unavailable
   * @throws NullPointerException if {@code core} or {@code appHost} is {@code null}
   */
  @SuppressWarnings("unused")
  public CoreHttpShellRuntimeSupport(
      NodeClientCore core,
      AppHost appHost,
      AppCatalogManager appCatalogManager,
      AppUpdateService appUpdateService,
      AppUpdateScheduler appUpdateScheduler,
      ContentSubscriptionService contentSubscriptionService,
      ContentSubscriptionScheduler contentSubscriptionScheduler,
      AppVaultService appVaultService) {
    this(
        core,
        appHost,
        appCatalogManager,
        appUpdateService,
        appUpdateScheduler,
        contentSubscriptionService,
        contentSubscriptionScheduler,
        null,
        null,
        null,
        null,
        appVaultService);
  }

  /**
   * Creates a core-backed HTTP runtime adapter with explicit app-platform services.
   *
   * @param core daemon core that supplies the shell-level runtime services
   * @param appHost shared AppHost instance used by the platform control plane
   * @param appCatalogManager shared app-catalog manager, or {@code null} when unavailable
   * @param appUpdateService shared app-update lifecycle service, or {@code null} when unavailable
   * @param appUpdateScheduler optional background app-update scheduler
   * @param contentSubscriptionService optional content subscription service
   * @param contentSubscriptionScheduler optional background content subscription scheduler
   * @param appDataService shared durable app-data service, or {@code null} when unavailable
   * @param trustGraphApiHandler shared durable trust graph handler, or {@code null} when
   *     unavailable
   * @param appVaultService shared app-vault service, or {@code null} when unavailable
   * @throws NullPointerException if {@code core} or {@code appHost} is {@code null}
   */
  @SuppressWarnings("unused")
  public CoreHttpShellRuntimeSupport(
      NodeClientCore core,
      AppHost appHost,
      AppCatalogManager appCatalogManager,
      AppUpdateService appUpdateService,
      AppUpdateScheduler appUpdateScheduler,
      ContentSubscriptionService contentSubscriptionService,
      ContentSubscriptionScheduler contentSubscriptionScheduler,
      AppDataService appDataService,
      TrustGraphApiHandler trustGraphApiHandler,
      AppVaultService appVaultService) {
    this(
        core,
        appHost,
        appCatalogManager,
        appUpdateService,
        appUpdateScheduler,
        contentSubscriptionService,
        contentSubscriptionScheduler,
        appDataService,
        trustGraphApiHandler,
        null,
        null,
        appVaultService);
  }

  /**
   * Creates a core-backed HTTP runtime adapter with explicit app-platform services.
   *
   * @param core daemon core that supplies the shell-level runtime services
   * @param appHost shared AppHost instance used by the platform control plane
   * @param appCatalogManager shared app-catalog manager, or {@code null} when unavailable
   * @param appUpdateService shared app-update lifecycle service, or {@code null} when unavailable
   * @param appUpdateScheduler optional background app-update scheduler
   * @param contentSubscriptionService optional content subscription service
   * @param contentSubscriptionScheduler optional background content subscription scheduler
   * @param appDataService shared durable app-data service, or {@code null} when unavailable
   * @param trustGraphApiHandler shared durable trust graph handler, or {@code null} when
   *     unavailable
   * @param appServiceCoordinator shared app-service coordinator, or {@code null} when unavailable
   * @param appNetworkBudgetService shared app-network budget service, or {@code null} when
   *     unavailable
   * @param appVaultService shared app-vault service, or {@code null} when unavailable
   * @throws NullPointerException if {@code core} or {@code appHost} is {@code null}
   */
  public CoreHttpShellRuntimeSupport(
      NodeClientCore core,
      AppHost appHost,
      AppCatalogManager appCatalogManager,
      AppUpdateService appUpdateService,
      AppUpdateScheduler appUpdateScheduler,
      ContentSubscriptionService contentSubscriptionService,
      ContentSubscriptionScheduler contentSubscriptionScheduler,
      AppDataService appDataService,
      TrustGraphApiHandler trustGraphApiHandler,
      AppServiceCoordinator appServiceCoordinator,
      AppNetworkBudgetService appNetworkBudgetService,
      AppVaultService appVaultService) {
    this.core = Objects.requireNonNull(core, "core");
    this.appHost = Objects.requireNonNull(appHost, "appHost");
    this.appCatalogManager = appCatalogManager;
    this.appUpdateService = appUpdateService;
    this.appUpdateScheduler = appUpdateScheduler;
    this.contentSubscriptionService = contentSubscriptionService;
    this.contentSubscriptionScheduler = contentSubscriptionScheduler;
    this.appDataService = appDataService;
    this.trustGraphApiHandler = trustGraphApiHandler;
    this.appServiceCoordinator = appServiceCoordinator;
    this.appNetworkBudgetService = appNetworkBudgetService;
    this.appVaultService = appVaultService;
  }

  @Override
  public RuntimePorts runtimePorts() {
    return core.getRuntimePorts();
  }

  @Override
  public Config config() {
    return core.getNode().getConfig();
  }

  @Override
  public Ticker ticker() {
    return core.getNode().network().ticker();
  }

  @Override
  public PushDataManagerHandle createPushDataManagerHandle(Ticker ticker) {
    return new PushDataManager(Objects.requireNonNull(ticker, "ticker"));
  }

  @Override
  public UserAlertSurface userAlerts() {
    return core.getAlerts();
  }

  @Override
  public String formPassword() {
    return core.getFormPassword();
  }

  @Override
  public boolean allowUploadFrom(File filename) {
    return core.allowUploadFrom(filename);
  }

  @Override
  public void storeConfig() {
    config().store();
  }

  @Override
  public InsertCompatibilityModes insertCompatibilityModes() {
    return new InsertCompatibilityModes(
        Arrays.stream(CompatibilityMode.values())
            .map(CompatibilityMode::intern)
            .filter(mode -> mode != CompatibilityMode.COMPAT_UNKNOWN)
            .map(CompatibilityMode::name)
            .distinct()
            .toList(),
        CompatibilityMode.COMPAT_DEFAULT.intern().name());
  }

  @Override
  public boolean canRedirectToWizard() {
    return true;
  }

  @Override
  public void addNetworkThreatLevelListener(ThreatLevelListener<NetworkThreatLevel> listener) {
    Objects.requireNonNull(listener);
    core.getNode()
        .services()
        .securityLevels()
        .addNetworkThreatLevelListener(
            (oldLevel, newLevel) ->
                listener.onChange(
                    mapNetworkThreatLevel(oldLevel), mapNetworkThreatLevel(newLevel)));
  }

  @Override
  public void addPhysicalThreatLevelListener(ThreatLevelListener<PhysicalThreatLevel> listener) {
    Objects.requireNonNull(listener);
    core.getNode()
        .services()
        .securityLevels()
        .addPhysicalThreatLevelListener(
            (oldLevel, newLevel) ->
                listener.onChange(
                    mapPhysicalThreatLevel(oldLevel), mapPhysicalThreatLevel(newLevel)));
  }

  @Override
  public HttpShellBrowseBootstrap createBrowseBootstrap(boolean publicGatewayMode) {
    BookmarkManager bookmarkManager =
        new BookmarkManager(
            new CoreBookmarkRuntimeSupport(core), core.getAlerts(), publicGatewayMode);
    BrowseContentClient client =
        new CoreBrowseContentClient(
            core.makeClient(RequestPriorityClasses.INTERACTIVE_PRIORITY_CLASS, true, true));
    FProxyFetchTracker fetchTracker =
        new FProxyFetchTracker(
            client.getFetchContext(),
            new CoreFProxyRuntimeSupport(core),
            new RequestClientBuilder().realTime().build());
    return HttpShellBrowseBootstrap.create(
        bookmarkManager,
        appHost,
        FProxyToadlet.create(client, new CoreFProxyRuntimeSupport(core), fetchTracker),
        new LegacyFProxyBrowseRouteRegistrar(client),
        CoreHttpShellRuntimeSupport::initializeFProxySharedState);
  }

  private static void initializeFProxySharedState(RuntimePorts runtimePorts) {
    FProxyToadlet.initializeSharedRandom(
        Objects.requireNonNull(runtimePorts, "runtimePorts").randomness());
  }

  /**
   * Maps daemon network threat levels into the detached enum used by the HTTP shell.
   *
   * @param threatLevel daemon threat level reported by node security listeners
   * @return matching HTTP-local threat level value for shell callbacks
   */
  private static NetworkThreatLevel mapNetworkThreatLevel(NETWORK_THREAT_LEVEL threatLevel) {
    return switch (threatLevel) {
      case LOW -> NetworkThreatLevel.LOW;
      case NORMAL -> NetworkThreatLevel.NORMAL;
      case HIGH -> NetworkThreatLevel.HIGH;
      case MAXIMUM -> NetworkThreatLevel.MAXIMUM;
    };
  }

  /**
   * Maps daemon physical threat levels into the detached enum used by the HTTP shell.
   *
   * @param threatLevel daemon threat level reported by node security listeners
   * @return matching HTTP-local threat level value for shell callbacks
   */
  private static PhysicalThreatLevel mapPhysicalThreatLevel(PHYSICAL_THREAT_LEVEL threatLevel) {
    return switch (threatLevel) {
      case LOW -> PhysicalThreatLevel.LOW;
      case NORMAL -> PhysicalThreatLevel.NORMAL;
      case HIGH -> PhysicalThreatLevel.HIGH;
      case MAXIMUM -> PhysicalThreatLevel.MAXIMUM;
    };
  }

  /**
   * Creates the shared AppHost instance and registers its shutdown cleanup.
   *
   * @param core daemon core that exposes the current node and temp-directory layout
   * @return managed AppHost instance rooted in the current node layout
   */
  private static AppPlatformServices createManagedAppServices(NodeClientCore core) {
    AppPlatformServices services = createAppPlatformServices(core);
    SemiOrderedShutdownHook.get()
        .addEarlyJob(createAppUpdateSchedulerShutdownJob(services.appUpdateScheduler()));
    registerContentSubscriptionSchedulerShutdownJob(services.contentSubscriptionScheduler());
    SemiOrderedShutdownHook.get().addEarlyJob(createAppHostShutdownJob(services.appHost()));
    return services;
  }

  private static void registerContentSubscriptionSchedulerShutdownJob(
      ContentSubscriptionScheduler contentSubscriptionScheduler) {
    if (contentSubscriptionScheduler != null) {
      SemiOrderedShutdownHook.get()
          .addEarlyJob(createContentSubscriptionSchedulerShutdownJob(contentSubscriptionScheduler));
    }
  }

  /**
   * Creates the single AppHost instance shared by the current HTTP bridge.
   *
   * <p>The host is rooted in the live node/core directories that the current daemon instance has
   * already selected. That keeps app installs, cache data, and run files attached to this node
   * rather than a fresh global directory lookup that could ignore per-instance overrides.
   *
   * @param core daemon core that exposes the current node and temp-directory layout
   * @return long-lived AppHost instance rooted in the current node layout
   */
  private static AppPlatformServices createAppPlatformServices(NodeClientCore core) {
    AppHostLayout layout =
        new AppHostLayout(
            core.getNode().nodeDir().dir().toPath(),
            core.getPersistentTempDir().toPath(),
            core.getNode().runDir().dir().toPath());
    AppHostTrustConfiguration trustConfiguration = readTrustConfiguration();
    warnWhenCatalogTrustUsesLegacyFallback(trustConfiguration);
    AppInstallVerificationPolicy installVerificationPolicy =
        createInstallVerificationPolicy(trustConfiguration);
    LocalProcessAppHost appHost = new LocalProcessAppHost(layout, installVerificationPolicy);
    AppCatalogManager appCatalogManager =
        createAppCatalogManager(
            layout, trustConfiguration, installVerificationPolicy, core.getRuntimePorts());
    configureCatalogOriginRetention(appHost, appCatalogManager);
    AppVaultService appVaultService = createAppVaultService(layout);
    AppDataService appDataService = createAppDataService(layout, appHost);
    AppNetworkBudgetService appNetworkBudgetService = createAppNetworkBudgetService(layout);
    AppUpdateService appUpdateService =
        new AppUpdateService(appHost, appCatalogManager, appVaultService, appDataService);
    if (Boolean.getBoolean("cryptad.appCatalogFederationEnabled")) {
      Path federationRoot = layout.dataDir().resolve("apps");
      FileFederatedCatalogTrustStore catalogTrustStore =
          new FileFederatedCatalogTrustStore(federationRoot.resolve("catalog-trust"));
      FileCatalogPublisherBindingStore publisherBindingStore =
          new FileCatalogPublisherBindingStore(
              federationRoot.resolve("catalog-publisher-bindings"));
      appUpdateService.setCatalogScopedReviewerPolicy(
          new CatalogScopedReviewerPolicy(
              new FileCatalogReviewerScopeStore(federationRoot.resolve("catalog-reviewer-scopes")),
              catalogTrustStore));
      appUpdateService.setFederatedCatalogConflictPolicy(
          new AppUpdateFederationAuthority(
              catalogTrustStore,
              publisherBindingStore,
              new FileFederatedCatalogConflictResolutionStore(
                  federationRoot.resolve("catalog-conflict-resolutions"))));
    }
    AppUpdateSchedulerConfig schedulerConfig = AppUpdateSchedulerConfig.loadFromSystem();
    AppUpdateScheduler appUpdateScheduler =
        createAppUpdateScheduler(
            layout, appHost, appCatalogManager, appUpdateService, schedulerConfig);
    appUpdateService.setSchedulerSummaryProvider(appUpdateScheduler::summary);
    appUpdateService.setSchedulerStateCleaner(appUpdateScheduler::clearAppState);
    if (schedulerConfig.enabled()) {
      appUpdateScheduler.start();
    }
    ContentSubscriptionSchedulerConfig contentSchedulerConfig =
        ContentSubscriptionSchedulerConfig.loadFromSystem();
    ContentSubscriptionService contentSubscriptionService =
        createContentSubscriptionService(
            layout, core.getRuntimePorts(), contentSchedulerConfig, appNetworkBudgetService);
    ContentSubscriptionScheduler contentSubscriptionScheduler =
        createContentSubscriptionScheduler(
            appHost, contentSubscriptionService, contentSchedulerConfig, core.getRuntimePorts());
    if (contentSubscriptionScheduler != null && contentSchedulerConfig.enabled()) {
      contentSubscriptionScheduler.start();
    }
    TrustGraphApiHandler trustGraphApiHandler =
        createTrustGraphApiHandler(layout, appNetworkBudgetService);
    AppServiceCoordinator appServiceCoordinator =
        createAppServiceCoordinator(layout, appHost, trustGraphApiHandler);
    return new AppPlatformServices(
        appHost,
        appCatalogManager,
        appUpdateService,
        appUpdateScheduler,
        contentSubscriptionService,
        contentSubscriptionScheduler,
        appDataService,
        trustGraphApiHandler,
        appServiceCoordinator,
        appNetworkBudgetService,
        appVaultService);
  }

  private static void configureCatalogOriginRetention(
      LocalProcessAppHost appHost, AppCatalogManager appCatalogManager) {
    try {
      appHost.setCatalogOriginRetention(
          new AppHost.CatalogOriginRetention() {
            @Override
            public void retain(List<InstalledAppOrigin> origins) throws IOException {
              appCatalogManager.retainOriginRevisionPins(originRevisions(origins));
            }

            @Override
            public void reconcile(List<InstalledAppOrigin> origins) throws IOException {
              appCatalogManager.reconcileOriginRevisionPins(originRevisions(origins));
            }
          });
    } catch (IOException exception) {
      throw new IllegalStateException(
          "Catalog origin revision retention could not be initialized.", exception);
    }
  }

  private static List<AppCatalogManager.OriginRevision> originRevisions(
      List<InstalledAppOrigin> origins) {
    return origins.stream()
        .map(
            origin ->
                new AppCatalogManager.OriginRevision(
                    origin.catalogId(),
                    origin.catalogRevisionDigestSha256(),
                    origin.catalogSignerKeyId(),
                    origin.appId()))
        .toList();
  }

  private static AppVaultService createAppVaultService(AppHostLayout layout) {
    try {
      return AppVaultService.open(layout.dataDir().resolve("apps").resolve("vault"));
    } catch (IOException _) {
      LOG.warn("App vault initialization failed; vault Platform API routes will be unavailable.");
      return null;
    }
  }

  /**
   * Creates the signed app-catalog manager for the current node layout.
   *
   * <p>The catalog store is kept under the AppHost data tree so catalog source metadata follows the
   * same node-specific storage root as installed apps. Runtime content fetch support is optional
   * for tests and older bridge wiring; when it is unavailable the manager still supports local and
   * HTTP catalog sources and reports Crypta fetch unavailability through its own error path.
   *
   * @param layout node-specific AppHost directory layout
   * @param trustConfiguration configured catalog and bundle trust inputs
   * @param runtimePorts runtime service ports, or {@code null} when not available
   * @return app-catalog manager wired to the current node storage and runtime fetch port
   */
  private static AppCatalogManager createAppCatalogManager(
      AppHostLayout layout,
      AppHostTrustConfiguration trustConfiguration,
      AppInstallVerificationPolicy installVerificationPolicy,
      RuntimePorts runtimePorts) {
    AppCatalogSourceStore catalogSourceStore =
        new AppCatalogSourceStore(layout.dataDir().resolve("apps").resolve("catalogs"));
    TrustedKeyProvider trustedCatalogKeys = () -> loadTrustedCatalogKeys(trustConfiguration);
    AppCatalogBundleVerificationPolicy bundlePolicy =
        stagedBundle -> verifyCatalogBundle(installVerificationPolicy, stagedBundle);
    if (Boolean.getBoolean("cryptad.appCatalogFederationEnabled")) {
      FileFederatedCatalogTrustStore trustStore =
          new FileFederatedCatalogTrustStore(
              layout.dataDir().resolve("apps").resolve("catalog-trust"));
      AppCatalogBundleVerificationPolicy scopedPublisherPolicy =
          new CatalogScopedPublisherVerificationPolicy(
              new FileCatalogPublisherBindingStore(
                  layout.dataDir().resolve("apps").resolve("catalog-publisher-bindings")),
              () -> loadFederatedPublisherKeys(trustConfiguration),
              trustedCatalogKeys,
              TrustedReviewerKeysLoader::loadFromSystem,
              Clock.systemUTC(),
              trustStore,
              usesLegacyCatalogTrustFallback(trustConfiguration)
                  ? CatalogScopedPublisherVerificationPolicy.CatalogSignerTrustMode
                      .LEGACY_SHARED_APPHOST_REGISTRY
                  : CatalogScopedPublisherVerificationPolicy.CatalogSignerTrustMode.ROLE_SEPARATED);
      bundlePolicy = composeCatalogBundleVerificationPolicies(bundlePolicy, scopedPublisherPolicy);
      FilePendingCatalogDiscoveryStore pendingDiscoveryStore =
          new FilePendingCatalogDiscoveryStore(
              layout.dataDir().resolve("apps").resolve("catalog-discovery-pending"));
      return runtimePorts == null
          ? AppCatalogManager.withFederatedTrustAndDiscoveryPolicy(
              catalogSourceStore,
              trustedCatalogKeys,
              bundlePolicy,
              trustStore,
              pendingDiscoveryStore,
              trustedCatalogKeys)
          : AppCatalogManager.withFederatedTrustAndDiscoveryPolicy(
              catalogSourceStore,
              trustedCatalogKeys,
              bundlePolicy,
              trustStore,
              pendingDiscoveryStore,
              trustedCatalogKeys,
              runtimePorts.contentFetch());
    }
    return runtimePorts == null
        ? AppCatalogManager.withBundleVerificationPolicy(
            catalogSourceStore, trustedCatalogKeys, bundlePolicy)
        : AppCatalogManager.withBundleVerificationPolicy(
            catalogSourceStore, trustedCatalogKeys, bundlePolicy, runtimePorts.contentFetch());
  }

  private static void verifyCatalogBundle(
      AppInstallVerificationPolicy installVerificationPolicy, Path stagedBundle)
      throws IOException {
    try {
      installVerificationPolicy.verifyCopiedBundle(stagedBundle);
    } catch (AppBundleVerificationException exception) {
      throw new AppDistributionException(exception.getMessage(), exception);
    }
  }

  static AppCatalogBundleVerificationPolicy composeCatalogBundleVerificationPolicies(
      AppCatalogBundleVerificationPolicy installPolicy,
      AppCatalogBundleVerificationPolicy scopedPublisherPolicy) {
    AppCatalogBundleVerificationPolicy checkedInstallPolicy =
        Objects.requireNonNull(installPolicy, "installPolicy");
    AppCatalogBundleVerificationPolicy checkedScopedPolicy =
        Objects.requireNonNull(scopedPublisherPolicy, "scopedPublisherPolicy");
    return new AppCatalogBundleVerificationPolicy() {
      @Override
      public void verify(Path stagedBundleDirectory) throws IOException {
        checkedScopedPolicy.verify(stagedBundleDirectory);
        checkedInstallPolicy.verify(stagedBundleDirectory);
      }

      @Override
      public AppCatalogBundleVerificationResult verify(
          AppCatalogBundleVerificationContext context, Path stagedBundleDirectory)
          throws IOException {
        AppCatalogBundleVerificationResult result =
            checkedScopedPolicy.verify(context, stagedBundleDirectory);
        checkedInstallPolicy.verify(context, stagedBundleDirectory);
        return result;
      }
    };
  }

  private static AppUpdateScheduler createAppUpdateScheduler(
      AppHostLayout layout,
      AppHost appHost,
      AppCatalogManager appCatalogManager,
      AppUpdateService appUpdateService,
      AppUpdateSchedulerConfig schedulerConfig) {
    AppUpdateSchedulerStore schedulerStore =
        new FileAppUpdateSchedulerStore(
            layout.dataDir().resolve("apps").resolve("update-scheduler"));
    return new AppUpdateScheduler(
        appHost, appCatalogManager, appUpdateService, schedulerConfig, schedulerStore);
  }

  private static ContentSubscriptionService createContentSubscriptionService(
      AppHostLayout layout,
      RuntimePorts runtimePorts,
      ContentSubscriptionSchedulerConfig schedulerConfig,
      AppNetworkBudgetService appNetworkBudgetService) {
    if (runtimePorts == null || runtimePorts.contentFetch() == null) {
      LOG.warn(
          "Content fetch runtime port is unavailable; content subscription Platform API routes will"
              + " be unavailable.");
      return null;
    }
    ContentSubscriptionStore store =
        new FileContentSubscriptionStore(
            layout.dataDir().resolve("apps").resolve("content-subscriptions"));
    return new ContentSubscriptionService(
        store, runtimePorts.contentFetch(), schedulerConfig, appNetworkBudgetService);
  }

  private static ContentSubscriptionScheduler createContentSubscriptionScheduler(
      AppHost appHost,
      ContentSubscriptionService contentSubscriptionService,
      ContentSubscriptionSchedulerConfig schedulerConfig,
      RuntimePorts runtimePorts) {
    if (contentSubscriptionService == null) {
      return null;
    }
    ContentSubscriptionPressureGate pressureGate =
        runtimePorts == null
            ? new ContentSubscriptionPressureGate(null, null)
            : new ContentSubscriptionPressureGate(
                runtimePorts.queueSupport(), runtimePorts.requestQueue());
    return new ContentSubscriptionScheduler(
        appHost, contentSubscriptionService, schedulerConfig, pressureGate);
  }

  private static AppDataService createAppDataService(AppHostLayout layout, AppHost appHost) {
    AppDataStoreConfig config = AppDataStoreConfig.loadFromSystem();
    Path storeRoot = layout.dataDir().resolve("apps").resolve("durable-app-data");
    return new AppDataService(new FileAppDataStore(storeRoot, config), appHost, config, true);
  }

  private static AppNetworkBudgetService createAppNetworkBudgetService(AppHostLayout layout) {
    return new AppNetworkBudgetService(
        new FileAppNetworkBudgetStore(layout.dataDir().resolve("apps").resolve("network-budget")),
        AppNetworkBudgetConfig.loadFromSystem());
  }

  private static TrustGraphApiHandler createTrustGraphApiHandler(
      AppHostLayout layout, AppNetworkBudgetService appNetworkBudgetService) {
    try {
      Path appPlatformDataRoot = layout.dataDir();
      Path storeRoot = appPlatformDataRoot.resolve("apps").resolve("trust-graph");
      return new TrustGraphApiHandler(
          new FileTrustGraphStore(storeRoot, appPlatformDataRoot),
          java.time.Clock.systemUTC(),
          appNetworkBudgetService);
    } catch (RuntimeException _) {
      LOG.warn(
          "Trust graph store initialization failed; trust graph Platform API routes will report"
              + " service unavailable.");
      return TrustGraphApiHandler.unavailable();
    }
  }

  private static AppServiceCoordinator createAppServiceCoordinator(
      AppHostLayout layout, AppHost appHost, TrustGraphApiHandler trustGraphApiHandler) {
    Path storeRoot = layout.dataDir().resolve("apps").resolve("app-services");
    return new AppServiceCoordinator(
        appHost,
        new FileAppServiceGrantStore(storeRoot),
        java.time.Clock.systemUTC(),
        java.util.List.of(new TrustGraphScoreAppServiceAdapter(trustGraphApiHandler)));
  }

  private static AppInstallVerificationPolicy createInstallVerificationPolicy(
      AppHostTrustConfiguration trustConfiguration) {
    if (trustConfiguration.pilot().configured()) {
      return createPilotInstallVerificationPolicy(trustConfiguration);
    }
    AppInstallVerificationPolicy.CopiedBundleIdentityVerifier newBundleVerifier =
        copiedBundleDirectory ->
            verifyBundleAgainstConfiguredTrust(copiedBundleDirectory, trustConfiguration, false);
    AppInstallVerificationPolicy.CopiedBundleIdentityVerifier historicalBundleVerifier =
        copiedBundleDirectory ->
            verifyBundleAgainstConfiguredTrust(copiedBundleDirectory, trustConfiguration, true);
    return trustConfiguration.allowUnsigned()
        ? AppInstallVerificationPolicy.allowUnsignedForDevelopmentOnlyWithIdentity(
            newBundleVerifier, historicalBundleVerifier)
        : AppInstallVerificationPolicy.requireSignedWithIdentity(
            newBundleVerifier, historicalBundleVerifier);
  }

  private static AppInstallVerificationPolicy createPilotInstallVerificationPolicy(
      AppHostTrustConfiguration trustConfiguration) {
    requireCompletePilotConfiguration(trustConfiguration);
    PilotTrustConfiguration pilot = trustConfiguration.pilot();
    PilotPublisherVerificationPolicy.Approval approval;
    try {
      approval = loadPilotRoutingApproval(pilot);
      requireAuthenticatedPersistentPilotRegistries(trustConfiguration, approval);
    } catch (IOException | RuntimeException exception) {
      throw new IllegalStateException(
          "Failed to authenticate persistent pilot trust configuration.", exception);
    }
    return AppInstallVerificationPolicy.requireSignedWithIdentity(
        copiedBundle ->
            verifyBundleAgainstPilotOrStableTrust(
                copiedBundle, trustConfiguration, pilot, approval, false),
        copiedBundle ->
            verifyBundleAgainstPilotOrStableTrust(
                copiedBundle, trustConfiguration, pilot, approval, true));
  }

  private static PilotPublisherVerificationPolicy.Approval loadPilotRoutingApproval(
      PilotTrustConfiguration pilot) throws IOException {
    PilotPublisherVerificationPolicy.Approval approval =
        PilotPublisherApprovalReader.read(Path.of(pilot.approvalFile()), pilot.approvalDigest());
    if (!pilot.pilotId().equals(approval.pilotId())) {
      throw new AppHostConfigurationException("pilot publisher approval is bound to another pilot");
    }
    if (!pilot.pilotNodeId().equals(approval.pilotNodeId())) {
      throw new AppHostConfigurationException(
          "pilot publisher approval is bound to another pilot node");
    }
    return approval;
  }

  private static AppBundleVerification verifyBundleAgainstPilotOrStableTrust(
      Path copiedBundle,
      AppHostTrustConfiguration trustConfiguration,
      PilotTrustConfiguration pilot,
      PilotPublisherVerificationPolicy.Approval approval,
      boolean historicalVerification)
      throws IOException {
    AppBundleSignature signature =
        AppBundleVerifier.read(copiedBundle.resolve(AppBundleSignature.SIGNATURE_FILE_NAME));
    if (approval.publisherKeyId().equals(signature.keyId())) {
      AppInstallVerificationPolicy pilotPolicy =
          loadPilotInstallVerificationPolicy(trustConfiguration, pilot);
      if (historicalVerification) {
        return pilotPolicy.verifyHistoricalCopiedBundle(copiedBundle);
      }
      return pilotPolicy.verifyCopiedBundle(copiedBundle);
    }
    TrustedRegistrySnapshot normalRegistry =
        loadExactTrustedRegistry(
            Path.of(trustConfiguration.trustedKeysFile()), NORMAL_STABLE_ROLE_LABEL);
    requireRegistryDigest(
        normalRegistry,
        approval.normalStableRegistryDigest(),
        "normal Stable registry digest differs from the pilot approval");
    requireRegistryExcludesPublisher(normalRegistry.keys(), approval, NORMAL_STABLE_ROLE_LABEL);
    AppBundleVerifier verifier =
        historicalVerification
            ? AppBundleVerifier.requireSignedForHistoricalVerification(normalRegistry.keys())
            : AppBundleVerifier.requireSigned(normalRegistry.keys());
    return verifier.verify(copiedBundle);
  }

  private static void requireCompletePilotConfiguration(
      AppHostTrustConfiguration trustConfiguration) {
    PilotTrustConfiguration pilot = trustConfiguration.pilot();
    if (!pilot.complete()) {
      throw new IllegalStateException("Pilot AppHost trust configuration is incomplete.");
    }
    if (trustConfiguration.allowUnsigned()) {
      throw new IllegalStateException(
          "Pilot AppHost trust cannot be combined with unsigned development mode.");
    }
    if (trustConfiguration.trustedKeysFile() == null) {
      throw new IllegalStateException(
          "Pilot AppHost trust requires a file-backed normal Stable registry.");
    }
    if (trustConfiguration.catalogTrustedKeysFile() == null) {
      throw new IllegalStateException(
          "Pilot AppHost trust requires a role-specific PR-293 catalog registry.");
    }
    if (trustConfiguration.keyId() != null
        || trustConfiguration.publicKeyBase64() != null
        || trustConfiguration.publicKeyFile() != null) {
      throw new IllegalStateException(
          "Pilot AppHost trust does not permit direct additions to the normal Stable registry.");
    }
  }

  private static AppInstallVerificationPolicy loadPilotInstallVerificationPolicy(
      AppHostTrustConfiguration trustConfiguration, PilotTrustConfiguration pilot)
      throws IOException {
    PilotPublisherVerificationPolicy.Approval approval = loadPilotRoutingApproval(pilot);
    PilotRegistrySnapshots registries = loadPilotRegistrySnapshots(trustConfiguration);
    return PilotPublisherVerificationPolicy.create(
        pilot.pilotId(),
        pilot.pilotNodeId(),
        approval,
        new PilotPublisherVerificationPolicy.Registries(
            registries.normalStable().keys(),
            registries.normalStable().digest(),
            registries.catalog().keys(),
            registries.catalog().digest(),
            registries.pilot().keys(),
            registries.pilot().digest()));
  }

  private static PersistentPilotRegistrySnapshots requireAuthenticatedPersistentPilotRegistries(
      AppHostTrustConfiguration trustConfiguration,
      PilotPublisherVerificationPolicy.Approval approval)
      throws IOException {
    TrustedRegistrySnapshot normalRegistry =
        loadExactTrustedRegistry(
            Path.of(trustConfiguration.trustedKeysFile()), NORMAL_STABLE_ROLE_LABEL);
    TrustedRegistrySnapshot catalogRegistry =
        loadExactTrustedRegistry(
            Path.of(trustConfiguration.catalogTrustedKeysFile()), CATALOG_AUTHORITY_ROLE_LABEL);
    requireRegistryDigest(
        normalRegistry,
        approval.normalStableRegistryDigest(),
        "normal Stable registry digest differs from the pilot approval");
    requireRegistryDigest(
        catalogRegistry,
        approval.catalogRegistryDigest(),
        "catalog registry digest differs from the pilot approval");
    try {
      normalRegistry.keys().requireDisjointFrom(catalogRegistry.keys());
    } catch (IllegalArgumentException exception) {
      throw new AppHostConfigurationException(
          "Normal Stable and catalog signing key registries must be role-distinct.", exception);
    }
    requireRegistryExcludesPublisher(normalRegistry.keys(), approval, NORMAL_STABLE_ROLE_LABEL);
    requireRegistryExcludesPublisher(
        catalogRegistry.keys(), approval, CATALOG_AUTHORITY_ROLE_LABEL);
    return new PersistentPilotRegistrySnapshots(normalRegistry, catalogRegistry);
  }

  private static void requireRegistryDigest(
      TrustedRegistrySnapshot registry, String expectedDigest, String message)
      throws AppHostConfigurationException {
    if (!expectedDigest.equals(registry.digest())) {
      throw new AppHostConfigurationException(message);
    }
  }

  private static void requireRegistryExcludesPublisher(
      TrustedAppKeys keys, PilotPublisherVerificationPolicy.Approval approval, String registryRole)
      throws AppHostConfigurationException {
    if (keys.keyIds().contains(approval.publisherKeyId())) {
      throw new AppHostConfigurationException(
          registryRole + " registry reuses the pilot publisher key id");
    }
    for (String keyId : keys.keyIds()) {
      TrustedAppKey key =
          keys.find(keyId)
              .orElseThrow(
                  () -> new AppHostConfigurationException(registryRole + " registry changed"));
      if (approval.publisherFingerprintSha256().equals(sha256(key.publicKey().getEncoded()))) {
        throw new AppHostConfigurationException(
            registryRole + " registry reuses the pilot publisher public key");
      }
    }
  }

  private static PilotRegistrySnapshots loadPilotRegistrySnapshots(
      AppHostTrustConfiguration trustConfiguration) throws IOException {
    TrustedRegistrySnapshot normalRegistry =
        loadExactTrustedRegistry(
            Path.of(trustConfiguration.trustedKeysFile()), NORMAL_STABLE_ROLE_LABEL);
    TrustedRegistrySnapshot catalogRegistry =
        loadExactTrustedRegistry(
            Path.of(trustConfiguration.catalogTrustedKeysFile()), CATALOG_AUTHORITY_ROLE_LABEL);
    TrustedRegistrySnapshot pilotRegistry =
        loadExactTrustedRegistry(
            Path.of(trustConfiguration.pilot().trustedKeysFile()), "pilot publisher");
    try {
      normalRegistry.keys().requireDisjointFrom(catalogRegistry.keys());
      normalRegistry.keys().requireDisjointFrom(pilotRegistry.keys());
      catalogRegistry.keys().requireDisjointFrom(pilotRegistry.keys());
    } catch (IllegalArgumentException exception) {
      throw new AppHostConfigurationException(
          "Normal Stable, catalog, and pilot signing key registries must be role-distinct.",
          exception);
    }
    return new PilotRegistrySnapshots(normalRegistry, catalogRegistry, pilotRegistry);
  }

  private static TrustedRegistrySnapshot loadExactTrustedRegistry(Path configuredPath, String role)
      throws IOException {
    Path path = requireRegularNonSymlinkFile(configuredPath, role + " trusted-key registry");
    byte[] registryBytes;
    try (var input =
        Channels.newInputStream(
            Files.newByteChannel(path, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS))) {
      registryBytes = input.readAllBytes();
    }
    return new TrustedRegistrySnapshot(TrustedAppKeys.load(registryBytes), sha256(registryBytes));
  }

  private static Path requireRegularNonSymlinkFile(Path input, String description)
      throws AppHostConfigurationException {
    Path lexical = Objects.requireNonNull(input, "input").toAbsolutePath().normalize();
    Path current = lexical.getRoot();
    for (Path component : lexical) {
      current = current == null ? component : current.resolve(component);
      if (Files.isSymbolicLink(current)) {
        throw new AppHostConfigurationException(description + " must not use symbolic links");
      }
    }
    if (!Files.isRegularFile(lexical, LinkOption.NOFOLLOW_LINKS)) {
      throw new AppHostConfigurationException(description + " must be a regular file");
    }
    return lexical;
  }

  private static String sha256(byte[] bytes) {
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      return "sha256:" + HexFormat.of().formatHex(digest.digest(bytes));
    } catch (NoSuchAlgorithmException exception) {
      throw new IllegalStateException("SHA-256 is unavailable", exception);
    }
  }

  private static AppBundleVerification verifyBundleAgainstConfiguredTrust(
      Path copiedBundleDirectory,
      AppHostTrustConfiguration trustConfiguration,
      boolean historicalVerification)
      throws IOException {
    if (trustConfiguration.allowUnsigned()
        && AppBundleVerifier.isDistributionSidecarFree(copiedBundleDirectory)) {
      return AppBundleVerification.unsigned();
    }
    AppBundleVerifier verifier;
    try {
      verifier = createBundleVerifier(trustConfiguration, historicalVerification);
    } catch (RuntimeException exception) {
      throw new AppHostConfigurationException(
          messageOrTrustConfigurationDefault(exception), exception);
    }
    return verifier.verify(copiedBundleDirectory);
  }

  private static AppBundleVerifier createBundleVerifier(
      AppHostTrustConfiguration trustConfiguration, boolean historicalVerification) {
    TrustedAppKeys trustedKeys = loadTrustedAppKeys(trustConfiguration);
    if (historicalVerification) {
      return AppBundleVerifier.requireSignedForHistoricalVerification(trustedKeys);
    }
    return trustConfiguration.allowUnsigned()
        ? AppBundleVerifier.allowUnsignedForDevelopmentOnly(trustedKeys)
        : AppBundleVerifier.requireSigned(trustedKeys);
  }

  private static AppHostTrustConfiguration readTrustConfiguration() {
    return new AppHostTrustConfiguration(
        allowUnsignedBundles(),
        configuredValue(TRUSTED_KEYS_FILE_PROPERTY, TRUSTED_KEYS_FILE_ENV),
        configuredValue(CATALOG_TRUSTED_KEYS_FILE_PROPERTY, CATALOG_TRUSTED_KEYS_FILE_ENV),
        configuredValue(TRUSTED_KEY_ID_PROPERTY, TRUSTED_KEY_ID_ENV),
        configuredValue(TRUSTED_PUBLIC_KEY_BASE64_PROPERTY, TRUSTED_PUBLIC_KEY_BASE64_ENV),
        configuredValue(TRUSTED_PUBLIC_KEY_FILE_PROPERTY, TRUSTED_PUBLIC_KEY_FILE_ENV),
        new PilotTrustConfiguration(
            configuredValue(PILOT_ID_PROPERTY, PILOT_ID_ENV),
            configuredValue(PILOT_NODE_ID_PROPERTY, PILOT_NODE_ID_ENV),
            configuredValue(PILOT_APPROVAL_FILE_PROPERTY, PILOT_APPROVAL_FILE_ENV),
            configuredValue(PILOT_APPROVAL_DIGEST_PROPERTY, PILOT_APPROVAL_DIGEST_ENV),
            configuredValue(PILOT_TRUSTED_KEYS_FILE_PROPERTY, PILOT_TRUSTED_KEYS_FILE_ENV)));
  }

  private static boolean allowUnsignedBundles() {
    String configuredValue =
        configuredValue(APPHOST_ALLOW_UNSIGNED_PROPERTY, APPHOST_ALLOW_UNSIGNED_ENV);
    return Boolean.parseBoolean(configuredValue);
  }

  private static TrustedAppKeys loadTrustedAppKeys(AppHostTrustConfiguration trustConfiguration) {
    return loadRoleSpecificTrustedKeys(trustConfiguration).bundleKeys();
  }

  private static TrustedAppKeys loadFederatedPublisherKeys(
      AppHostTrustConfiguration trustConfiguration) {
    if (!trustConfiguration.pilot().configured()) {
      return loadTrustedAppKeys(trustConfiguration);
    }
    try {
      requireCompletePilotConfiguration(trustConfiguration);
      PilotRegistrySnapshots registries = loadPilotRegistrySnapshots(trustConfiguration);
      return registries.normalStable().keys().plus(registries.pilot().keys());
    } catch (IOException | RuntimeException exception) {
      throw new IllegalStateException(
          "Failed to load role-separated Stable and PR-294 publisher trust.", exception);
    }
  }

  private static TrustedAppKeys loadConfiguredAppKeys(
      AppHostTrustConfiguration trustConfiguration) {
    TrustedAppKeys trustedKeys =
        loadTrustedKeysFileIfConfigured(trustConfiguration.trustedKeysFile());
    rejectPartialDirectTrustedKeyConfiguration(trustConfiguration);
    if (trustConfiguration.keyId() == null) {
      return trustedKeys;
    }
    return trustedKeys.plus(
        loadDirectTrustedKey(
            trustConfiguration.keyId(),
            trustConfiguration.publicKeyBase64(),
            trustConfiguration.publicKeyFile()));
  }

  private static TrustedAppKeys loadTrustedCatalogKeys(
      AppHostTrustConfiguration trustConfiguration) {
    if (trustConfiguration.pilot().configured()) {
      try {
        requireCompletePilotConfiguration(trustConfiguration);
        PilotPublisherVerificationPolicy.Approval approval =
            loadPilotRoutingApproval(trustConfiguration.pilot());
        return requireAuthenticatedPersistentPilotRegistries(trustConfiguration, approval)
            .catalog()
            .keys();
      } catch (IOException | RuntimeException exception) {
        throw new IllegalStateException(
            "Failed to load authenticated pilot catalog trust.", exception);
      }
    }
    return loadRoleSpecificTrustedKeys(trustConfiguration).catalogKeys();
  }

  private static RoleSpecificTrustedKeys loadRoleSpecificTrustedKeys(
      AppHostTrustConfiguration trustConfiguration) {
    TrustedAppKeys bundleKeys = loadConfiguredAppKeys(trustConfiguration);
    if (trustConfiguration.catalogTrustedKeysFile() == null) {
      return new RoleSpecificTrustedKeys(bundleKeys, bundleKeys);
    }
    TrustedAppKeys catalogKeys;
    try {
      catalogKeys = TrustedAppKeys.load(Path.of(trustConfiguration.catalogTrustedKeysFile()));
    } catch (IOException | RuntimeException exception) {
      throw new IllegalStateException("Failed to load trusted catalog keys file.", exception);
    }
    try {
      catalogKeys.requireDisjointFrom(bundleKeys);
    } catch (RuntimeException exception) {
      throw new IllegalStateException(
          "Trusted catalog and app signing key registries must be role-distinct.", exception);
    }
    return new RoleSpecificTrustedKeys(bundleKeys, catalogKeys);
  }

  private static void warnWhenCatalogTrustUsesLegacyFallback(
      AppHostTrustConfiguration trustConfiguration) {
    if (usesLegacyCatalogTrustFallback(trustConfiguration)
        && LEGACY_CATALOG_TRUST_WARNING_EMITTED.compareAndSet(false, true)) {
      LOG.warn(
          "Catalog signature verification is using the deprecated AppHost trusted-key fallback;"
              + " configure cryptad.appcatalog.trustedKeysFile.");
    }
  }

  private static boolean usesLegacyCatalogTrustFallback(
      AppHostTrustConfiguration trustConfiguration) {
    return !trustConfiguration.pilot().configured()
        && trustConfiguration.catalogTrustedKeysFile() == null;
  }

  private static void rejectPartialDirectTrustedKeyConfiguration(
      AppHostTrustConfiguration trustConfiguration) {
    if (trustConfiguration.keyId() == null
        && (trustConfiguration.publicKeyBase64() != null
            || trustConfiguration.publicKeyFile() != null)) {
      throw new IllegalStateException(
          "Trusted app public key material requires trusted app key id.");
    }
  }

  private static TrustedAppKeys loadTrustedKeysFileIfConfigured(String configuredPath) {
    if (configuredPath == null) {
      return TrustedAppKeys.empty();
    }
    try {
      return TrustedAppKeys.load(Path.of(configuredPath));
    } catch (IOException e) {
      throw new IllegalStateException("Failed to load trusted app keys file.", e);
    }
  }

  private static TrustedAppKey loadDirectTrustedKey(
      String keyId, String publicKeyBase64, String publicKeyFile) {
    if (publicKeyBase64 == null && publicKeyFile == null) {
      throw new IllegalStateException("Trusted app key id requires trusted public key material.");
    }
    if (publicKeyBase64 != null && publicKeyFile != null) {
      throw new IllegalStateException(
          "Trusted app public key material must be configured by base64 or file, not both.");
    }
    try {
      return publicKeyFile != null
          ? decodeTrustedPublicKeyFile(keyId, Path.of(publicKeyFile))
          : TrustedAppKey.ed25519(keyId, publicKeyBase64);
    } catch (IOException e) {
      throw new IllegalStateException("Failed to load trusted app public key.", e);
    }
  }

  private static TrustedAppKey decodeTrustedPublicKeyFile(String keyId, Path file)
      throws IOException {
    byte[] rawBytes = Files.readAllBytes(file.toAbsolutePath().normalize());
    try {
      return TrustedAppKey.ed25519(keyId, new String(rawBytes, StandardCharsets.UTF_8));
    } catch (AppDistributionException | IllegalArgumentException _) {
      return TrustedAppKey.ed25519(keyId, rawBytes);
    }
  }

  private static String configuredValue(String propertyName, String environmentName) {
    String propertyValue = System.getProperty(propertyName);
    if (propertyValue != null && !propertyValue.isBlank()) {
      return propertyValue.trim();
    }
    String environmentValue = System.getenv(environmentName);
    return environmentValue == null || environmentValue.isBlank() ? null : environmentValue.trim();
  }

  private static String messageOrTrustConfigurationDefault(Throwable failure) {
    String message = failure.getMessage();
    return message == null || message.isBlank() ? TRUST_CONFIGURATION_ERROR_MESSAGE : message;
  }

  private record AppHostTrustConfiguration(
      boolean allowUnsigned,
      String trustedKeysFile,
      String catalogTrustedKeysFile,
      String keyId,
      String publicKeyBase64,
      String publicKeyFile,
      PilotTrustConfiguration pilot) {}

  private record PilotTrustConfiguration(
      String pilotId,
      String pilotNodeId,
      String approvalFile,
      String approvalDigest,
      String trustedKeysFile) {
    private boolean configured() {
      return pilotId != null
          || pilotNodeId != null
          || approvalFile != null
          || approvalDigest != null
          || trustedKeysFile != null;
    }

    private boolean complete() {
      return pilotId != null
          && pilotNodeId != null
          && approvalFile != null
          && approvalDigest != null
          && trustedKeysFile != null;
    }
  }

  private record TrustedRegistrySnapshot(TrustedAppKeys keys, String digest) {}

  private record PersistentPilotRegistrySnapshots(
      TrustedRegistrySnapshot normalStable, TrustedRegistrySnapshot catalog) {}

  private record PilotRegistrySnapshots(
      TrustedRegistrySnapshot normalStable,
      TrustedRegistrySnapshot catalog,
      TrustedRegistrySnapshot pilot) {}

  private record RoleSpecificTrustedKeys(TrustedAppKeys bundleKeys, TrustedAppKeys catalogKeys) {}

  private record AppPlatformServices(
      AppHost appHost,
      AppCatalogManager appCatalogManager,
      AppUpdateService appUpdateService,
      AppUpdateScheduler appUpdateScheduler,
      ContentSubscriptionService contentSubscriptionService,
      ContentSubscriptionScheduler contentSubscriptionScheduler,
      AppDataService appDataService,
      TrustGraphApiHandler trustGraphApiHandler,
      AppServiceCoordinator appServiceCoordinator,
      AppNetworkBudgetService appNetworkBudgetService,
      AppVaultService appVaultService) {}

  /**
   * Creates the shutdown job that stops any AppHost-managed child processes on node exit.
   *
   * <p>The shared AppHost is otherwise only reachable through the HTTP runtime support. Registering
   * this early shutdown job keeps app processes from surviving node shutdown and leaving stale run
   * state behind for the next boot.
   *
   * @param appHost shared AppHost instance used by the platform control plane
   * @return unstarted shutdown thread suitable for {@link SemiOrderedShutdownHook}
   */
  static Thread createAppHostShutdownJob(AppHost appHost) {
    Objects.requireNonNull(appHost, "appHost");
    return new Thread(() -> stopRunningAppsOnShutdown(appHost), "Shutdown AppHost");
  }

  static Thread createAppUpdateSchedulerShutdownJob(AppUpdateScheduler appUpdateScheduler) {
    Objects.requireNonNull(appUpdateScheduler, "appUpdateScheduler");
    return new Thread(appUpdateScheduler::close, "Shutdown AppUpdateScheduler");
  }

  static Thread createContentSubscriptionSchedulerShutdownJob(
      ContentSubscriptionScheduler contentSubscriptionScheduler) {
    Objects.requireNonNull(contentSubscriptionScheduler, "contentSubscriptionScheduler");
    return new Thread(contentSubscriptionScheduler::close, "Shutdown ContentSubscriptionScheduler");
  }

  private static void stopRunningAppsOnShutdown(AppHost appHost) {
    for (RunningAppSnapshot runningApp : appHost.listRunning()) {
      stopRunningAppOnShutdown(appHost, runningApp);
    }
  }

  private static void stopRunningAppOnShutdown(AppHost appHost, RunningAppSnapshot runningApp) {
    try {
      appHost.stop(runningApp.appId());
    } catch (IOException e) {
      LOG.warn("Failed to stop app during shutdown: {}", runningApp.appId(), e);
    } catch (RuntimeException e) {
      LOG.warn("Unexpected app shutdown failure: {}", runningApp.appId(), e);
    }
  }
}
