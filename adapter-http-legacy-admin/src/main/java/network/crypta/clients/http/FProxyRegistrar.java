package network.crypta.clients.http;

import java.io.IOException;
import java.util.Arrays;
import network.crypta.clients.http.updater.CoreActionToadlet;
import network.crypta.config.Config;
import network.crypta.config.SubConfig;
import network.crypta.platform.api.PlatformApiSharedAppServices;
import network.crypta.platform.appdist.AppUiMode;
import network.crypta.platform.apphost.AppHost;
import network.crypta.platform.apphost.InstalledAppSnapshot;
import network.crypta.platform.appui.AppBrowserSessionStore;
import network.crypta.platform.webshell.routes.WebShellPaths;
import network.crypta.runtime.spi.RuntimePorts;
import network.crypta.runtime.spi.TransferAccessPort;

import static network.crypta.runtime.updater.UpdaterPaths.CORE_UPDATE_PATH;

/**
 * Registers the legacy HTTP route set while delegating browse-owned publication through a seam.
 *
 * <p>This helper centralizes the remaining admin-owned wiring of the legacy HTTP user interface
 * after daemon-only composition has already happened elsewhere. It preserves the historical route
 * and menu order while delegating concrete browse/FProxy route publication to the neutral {@link
 * LegacyHttpBrowseRouteRegistrar} seam at the exact points where those browse-owned routes used to
 * be instantiated inline. Callers invoke it once during node startup to ensure all public endpoints
 * for queue management, configuration, alerts, maintenance flows, and browse-owned insertions are
 * available before handling requests.
 *
 * <p>Responsibilities include:
 *
 * <ul>
 *   <li>Registering the admin-owned navigation menus under canonical categories.
 *   <li>Instantiating functional toadlets for downloads, uploads, security, chat, stats,
 *       connectivity, first-time wizard flows, and core updates.
 *   <li>Delegating browse-owned registration phases to the browse registrar without changing order.
 * </ul>
 *
 * <p>Thread-safety: registration is expected to run on a single startup thread; no internal state
 * is retained after setup. Mutability is limited to injecting constructed toadlets into the server.
 */
final class FProxyRegistrar {
  private static final String QUEUE_MANAGER_APP_ID = "queue-manager";
  private static final String QUEUE_MANAGER_URL =
      LegacyAdminRetirementRegistry.require("queue-downloads").replacementUrl();
  private static final String SHELL_PEERS_URL =
      LegacyAdminRetirementRegistry.require("friends").replacementUrl();
  private static final String SHELL_CONFIG_URL =
      LegacyAdminRetirementRegistry.require("config").replacementUrl();
  private static final String LEGACY_STATUS_URL = "/alerts/";

  private FProxyRegistrar() {}

  /**
   * Builds and registers the full FProxy toadlet set if the environment supports it.
   *
   * <p>The method assumes the root browse toadlet, interactive client, and runtime ports have
   * already been assembled by the caller and then registers every relevant route with the provided
   * server. Registration order aligns with the existing legacy shell behavior: browse-owned phases
   * are delegated through the browse registrar, with admin-owned routes published in between. This
   * method must be called exactly once during startup; it performs no deduplication and assumes the
   * server is empty.
   *
   * @param dependencies prebuilt shell dependencies required to register the FProxy HTTP surface
   * @param server toadlet server that exposes HTTP endpoints; expected to be in registration phase.
   */
  static void maybeCreateFProxyEtc(
      FProxyRegistrarDependencies dependencies, SimpleToadletServer server) {
    RuntimePorts runtimePorts = dependencies.runtimePorts();
    Config config = dependencies.config();
    TransferAccessPort transferAccess = runtimePorts.transferAccess();
    LegacyHttpBrowseRouteRegistrar browseRouteRegistrar = dependencies.browseRouteRegistrar();
    LegacyHttpBrowseRouteRegistrarContext browseContext = dependencies.browseContext();
    InsertCompatibilityModes insertCompatibilityModes = dependencies.insertCompatibilityModes();

    browseRouteRegistrar.registerRoutes(
        LegacyHttpBrowseRouteRegistrar.Phase.ROOT_MENU, browseContext, server);
    LinkEnabledCallback webShellPrimary = webShellPrimary(server);
    LinkEnabledCallback queueManagerAvailable = queueManagerAvailable(dependencies.appHost());
    server.registerMenu(
        QUEUE_MANAGER_URL,
        LegacyHttpCategories.CATEGORY_QUEUE,
        "FProxyToadlet.categoryTitleQueue",
        null,
        false,
        queueManagerAvailable,
        queueManagerAvailable);
    server.registerMenu(
        SHELL_PEERS_URL,
        LegacyHttpCategories.CATEGORY_FRIENDS,
        "FProxyToadlet.categoryTitleFriends",
        null,
        true,
        webShellPrimary,
        webShellPrimary);
    server.registerMenu("/chat/", "FProxyToadlet.categoryChat", "FProxyToadlet.categoryTitleChat");
    server.registerMenu(
        WebShellPaths.SHELL_ROOT,
        LegacyHttpCategories.CATEGORY_STATUS,
        "FProxyToadlet.categoryTitleStatus",
        LEGACY_STATUS_URL,
        webShellPrimary);
    server.registerMenu(
        SHELL_CONFIG_URL,
        LegacyHttpCategories.CATEGORY_CONFIG,
        "FProxyToadlet.categoryTitleConfig",
        SecurityLevelsToadlet.PATH,
        webShellPrimary);

    browseRouteRegistrar.registerRoutes(
        LegacyHttpBrowseRouteRegistrar.Phase.INTRO_ROUTES, browseContext, server);

    UserAlertsToadlet alerts = new UserAlertsToadlet();
    server.register(
        alerts,
        legacyNavigationRegistration(
            LegacyHttpCategories.CATEGORY_STATUS,
            LEGACY_STATUS_URL,
            "FProxyToadlet.alertsTitle",
            "FProxyToadlet.alerts",
            true,
            null));

    QueueToadlet downloadToadlet =
        new QueueToadlet(
            false,
            new QueueToadletRuntimePorts(
                runtimePorts.queuePage(),
                runtimePorts.transferAccess(),
                runtimePorts.queueDownload(),
                runtimePorts.queueInsert(),
                runtimePorts.queueMutation(),
                runtimePorts.queueSupport(),
                runtimePorts.queueCompletion(),
                runtimePorts.darknetConnections(),
                runtimePorts.darknetMessaging(),
                insertCompatibilityModes));
    server.register(
        downloadToadlet,
        legacyNavigationRegistration(
            LegacyHttpCategories.CATEGORY_QUEUE,
            QueueToadlet.PATH_DOWNLOADS,
            "FProxyToadlet.downloadsTitle",
            "FProxyToadlet.downloads",
            false,
            downloadToadlet));
    LocalDownloadDirectoryToadlet localDownloadDirectoryToadlet =
        new LocalDownloadDirectoryToadlet(transferAccess, QueueToadlet.PATH_DOWNLOADS);
    server.register(
        localDownloadDirectoryToadlet,
        ToadletRegistration.basic(null, localDownloadDirectoryToadlet.path(), true, false));
    QueueToadlet uploadToadlet =
        new QueueToadlet(
            true,
            new QueueToadletRuntimePorts(
                runtimePorts.queuePage(),
                runtimePorts.transferAccess(),
                runtimePorts.queueDownload(),
                runtimePorts.queueInsert(),
                runtimePorts.queueMutation(),
                runtimePorts.queueSupport(),
                runtimePorts.queueCompletion(),
                runtimePorts.darknetConnections(),
                runtimePorts.darknetMessaging(),
                insertCompatibilityModes));
    server.register(
        uploadToadlet,
        legacyNavigationRegistration(
            LegacyHttpCategories.CATEGORY_QUEUE,
            QueueToadlet.PATH_UPLOADS,
            "FProxyToadlet.uploadsTitle",
            "FProxyToadlet.uploads",
            false,
            uploadToadlet));

    FileInsertWizardToadlet fiw =
        new FileInsertWizardToadlet(
            new FileInsertWizardToadletRuntimePorts(
                runtimePorts.securityLevels(), insertCompatibilityModes));
    server.register(
        fiw,
        legacyNavigationRegistration(
            LegacyHttpCategories.CATEGORY_QUEUE,
            FileInsertWizardToadlet.PATH,
            "FProxyToadlet.uploadFileWizardTitle",
            "FProxyToadlet.uploadFileWizard",
            false,
            fiw));
    uploadToadlet.setFIW(fiw);

    LocalFileInsertToadlet localFileInsertToadlet = new LocalFileInsertToadlet(transferAccess);
    server.register(
        localFileInsertToadlet,
        ToadletRegistration.basic(null, LocalFileInsertToadlet.INSERT_BROWSE_PATH, true, false));

    browseRouteRegistrar.registerRoutes(
        LegacyHttpBrowseRouteRegistrar.Phase.QUEUE_FILTER_ROUTES, browseContext, server);

    SymlinkerToadlet symlinkToadlet = new SymlinkerToadlet(runtimePorts.toadletSymlinks());
    server.register(symlinkToadlet, ToadletRegistration.basic(null, "/sl/", true, false));

    SecurityLevelsToadletRuntimePorts securityLevelsToadletRuntimePorts =
        new SecurityLevelsToadletRuntimePorts(runtimePorts.securityLevels(), runtimePorts.config());
    SecurityLevelsToadlet seclevels = new SecurityLevelsToadlet(securityLevelsToadletRuntimePorts);
    server.register(
        seclevels,
        legacyNavigationRegistration(
            LegacyHttpCategories.CATEGORY_CONFIG,
            SecurityLevelsToadlet.PATH,
            "FProxyToadlet.seclevelsTitle",
            "FProxyToadlet.seclevels",
            true,
            null));

    ConfigToadletRuntimePorts configToadletRuntimePorts =
        new ConfigToadletRuntimePorts(
            runtimePorts.config(), runtimePorts.transferAccess(), runtimePorts.lifecycle());
    SubConfig[] sc = config.getConfigs();
    Arrays.sort(sc);

    for (SubConfig cfg : sc) {
      String prefix = cfg.getPrefix();
      if (prefix.equals("security-levels")) continue;
      LocalDirectoryConfigToadlet localDirectoryConfigToadlet =
          new LocalDirectoryConfigToadlet(transferAccess, LegacyHttpPaths.CONFIG_PATH + prefix);
      ConfigToadlet configtoadlet =
          new ConfigToadlet(
              localDirectoryConfigToadlet.path(), config, cfg, configToadletRuntimePorts);
      server.register(
          configtoadlet,
          legacyNavigationRegistration(
              LegacyHttpCategories.CATEGORY_CONFIG,
              LegacyHttpPaths.CONFIG_PATH + prefix,
              "ConfigToadlet." + prefix,
              "ConfigToadlet.title." + prefix,
              true,
              configtoadlet));
      server.register(
          localDirectoryConfigToadlet,
          ToadletRegistration.basic(null, localDirectoryConfigToadlet.path(), true, false));
    }

    browseRouteRegistrar.registerRoutes(
        LegacyHttpBrowseRouteRegistrar.Phase.POST_CONFIG_ROUTES, browseContext, server);

    CoreActionToadlet coreActionToadlet = new CoreActionToadlet(runtimePorts.coreUpdateAction());
    server.register(
        coreActionToadlet, ToadletRegistration.basic(null, CORE_UPDATE_PATH, true, false));

    ConnectionsToadletRuntimePorts connectionsToadletRuntimePorts =
        new ConnectionsToadletRuntimePorts(
            runtimePorts.connectionsPage(),
            runtimePorts.peer(),
            runtimePorts.nodeInfo(),
            runtimePorts.config(),
            runtimePorts.connectionsSupport(),
            runtimePorts.lifecycle());

    DarknetConnectionsToadlet friendsToadlet =
        new DarknetConnectionsToadlet(
            connectionsToadletRuntimePorts, runtimePorts.darknetConnections());
    server.register(
        friendsToadlet,
        legacyNavigationRegistration(
            LegacyHttpCategories.CATEGORY_FRIENDS,
            LegacyHttpPaths.FRIENDS_PATH,
            "FProxyToadlet.friendsTitle",
            "FProxyToadlet.friends",
            true,
            null));

    DarknetAddRefToadlet addRefToadlet =
        new DarknetAddRefToadlet(
            runtimePorts.connectionsSupport(), runtimePorts.nodeInfo(), friendsToadlet);
    server.register(
        addRefToadlet,
        legacyNavigationRegistration(
            LegacyHttpCategories.CATEGORY_FRIENDS,
            "/addfriend/",
            "FProxyToadlet.addFriendTitle",
            "FProxyToadlet.addFriend",
            true,
            null));

    OpennetConnectionsToadlet opennetToadlet =
        new OpennetConnectionsToadlet(connectionsToadletRuntimePorts);
    server.register(
        opennetToadlet,
        legacyNavigationRegistration(
            LegacyHttpCategories.CATEGORY_STATUS,
            "/strangers/",
            "FProxyToadlet.opennetTitle",
            "FProxyToadlet.opennet",
            true,
            opennetToadlet));

    ChatForumsToadlet chatForumsToadlet = new ChatForumsToadlet();
    server.register(
        chatForumsToadlet,
        legacyNavigationRegistration(
            "FProxyToadlet.categoryChat",
            "/chat/",
            "FProxyToadlet.chatForumsTitle",
            "FProxyToadlet.chatForums",
            true,
            chatForumsToadlet));

    LocalFileN2NMToadlet localFileN2NMToadlet = new LocalFileN2NMToadlet(transferAccess);
    N2NTMToadlet n2ntmToadlet = new N2NTMToadlet(runtimePorts, localFileN2NMToadlet);
    server.register(n2ntmToadlet, ToadletRegistration.basic(null, "/send_n2ntm/", true, true));
    server.register(
        localFileN2NMToadlet,
        ToadletRegistration.basic(null, LocalFileN2NMToadlet.BROWSE_PATH, true, false));

    browseRouteRegistrar.registerRoutes(
        LegacyHttpBrowseRouteRegistrar.Phase.POST_MESSAGING_ROUTES, browseContext, server);

    WebShellToadlet webShellToadlet = new WebShellToadlet();
    server.register(
        webShellToadlet,
        legacyNavigationRegistration(
            LegacyHttpCategories.CATEGORY_STATUS,
            WebShellPaths.SHELL_ROOT,
            "FProxyToadlet.webShellTitle",
            "FProxyToadlet.webShell",
            true,
            webShellPrimary));

    if (dependencies.appHost()
        instanceof network.crypta.platform.apphost.runtime.LocalProcessAppHost localHost) {
      java.net.URI mailEndpoint = java.net.URI.create(server.getLocalAdminURL()).resolve("/api/v1");
      if ("http".equals(mailEndpoint.getScheme())
          && java.util.Set.of("127.0.0.1", "[::1]", "::1").contains(mailEndpoint.getHost())) {
        localHost.setMailPlatformApiEndpoint(mailEndpoint);
      }
    }

    AppBrowserSessionStore appBrowserSessionStore =
        new AppBrowserSessionStore(dependencies.appHost());
    AppUiLoopbackOriginServer appUiOriginServer =
        new AppUiLoopbackOriginServer(
            dependencies.appHost(),
            appBrowserSessionStore,
            server.getLocalAdminURL(),
            server::isFProxyJavascriptEnabled);
    Runtime.getRuntime()
        .addShutdownHook(new Thread(appUiOriginServer::close, "Cryptad-AppUi-Origin-Shutdown"));
    AppUiToadlet appUiToadlet =
        new AppUiToadlet(dependencies.appHost(), appBrowserSessionStore, appUiOriginServer);
    server.register(appUiToadlet, ToadletRegistration.basic(null, appUiToadlet.path(), true, true));

    PlatformApiToadlet platformApiToadlet =
        new PlatformApiToadlet(
            runtimePorts,
            dependencies.appHost(),
            dependencies.appCatalogManager(),
            PlatformApiSharedAppServices.of(
                dependencies.appVaultService(),
                dependencies.appUpdateService(),
                dependencies.contentSubscriptionService(),
                dependencies.appDataService(),
                dependencies.trustGraphApiHandler(),
                dependencies.appServiceCoordinator(),
                dependencies.appNetworkBudgetService()),
            appBrowserSessionStore,
            appUiOriginServer);
    server.register(
        platformApiToadlet,
        ToadletRegistration.basic(null, PlatformApiToadlet.MOUNT_PATH, true, true));

    browseRouteRegistrar.registerRoutes(
        LegacyHttpBrowseRouteRegistrar.Phase.POST_PLATFORM_API_ROUTES, browseContext, server);

    StatisticsToadlet statisticsToadlet = new StatisticsToadlet(runtimePorts.statistics());
    server.register(
        statisticsToadlet,
        legacyNavigationRegistration(
            LegacyHttpCategories.CATEGORY_STATUS,
            "/stats/",
            "FProxyToadlet.statsTitle",
            "FProxyToadlet.stats",
            true,
            null));

    DiagnosticToadlet diagnosticToadlet = new DiagnosticToadlet(runtimePorts.diagnostic());
    server.register(
        diagnosticToadlet,
        legacyNavigationRegistration(
            LegacyHttpCategories.CATEGORY_STATUS,
            "/diagnostic/",
            "FProxyToadlet.diagnosticTitle",
            "FProxyToadlet.diagnostic",
            true,
            null));

    ConnectivityToadlet connectivityToadlet = new ConnectivityToadlet(runtimePorts.connectivity());
    server.register(
        connectivityToadlet,
        legacyNavigationRegistration(
            LegacyHttpCategories.CATEGORY_STATUS,
            ConnectivityToadlet.CONNECTIVITY_PATH,
            "ConnectivityToadlet.connectivityTitle",
            "ConnectivityToadlet.connectivity",
            true,
            null));

    TranslationToadlet translationToadlet = new TranslationToadlet();
    server.register(
        translationToadlet,
        legacyNavigationRegistration(
            LegacyHttpCategories.CATEGORY_CONFIG,
            TranslationToadlet.TOADLET_URL,
            "TranslationToadlet.title",
            "TranslationToadlet.titleLong",
            true,
            null));

    FirstTimeWizardToadlet firstTimeWizardToadlet =
        new FirstTimeWizardToadlet(
            config, new FirstTimeWizardToadletRuntimePorts(runtimePorts.firstTimeWizard()));
    server.register(
        firstTimeWizardToadlet,
        ToadletRegistration.basic(null, FirstTimeWizardToadlet.TOADLET_URL, true, false));

    FirstTimeWizardNewToadlet firstTimeWizardNewToadlet =
        new FirstTimeWizardNewToadlet(runtimePorts.firstTimeWizard());
    server.register(
        firstTimeWizardNewToadlet,
        ToadletRegistration.basic(null, FirstTimeWizardNewToadlet.TOADLET_URL, true, false));

    SimpleHelpToadlet simpleHelpToadlet = new SimpleHelpToadlet();
    server.register(simpleHelpToadlet, ToadletRegistration.basic(null, "/help/", true, false));

    browseRouteRegistrar.registerRoutes(
        LegacyHttpBrowseRouteRegistrar.Phase.TAIL_ROUTES, browseContext, server);
  }

  private static ToadletRegistration legacyNavigationRegistration(
      String menu,
      String urlPrefix,
      String name,
      String title,
      boolean fullOnly,
      LinkEnabledCallback callback) {
    if (LegacyAdminRetirementRegistry.shouldPromoteInLegacyNavigation(urlPrefix)) {
      return ToadletRegistration.menuLink(menu, urlPrefix, true, name, title, fullOnly, callback);
    }
    return ToadletRegistration.basic(null, urlPrefix, true, fullOnly);
  }

  private static LinkEnabledCallback webShellPrimary(SimpleToadletServer server) {
    return ignored -> WebShellPaths.SHELL_ROOT.equals(server.primaryUiRoot());
  }

  private static LinkEnabledCallback queueManagerAvailable(AppHost appHost) {
    return ctx -> {
      if (ctx == null
          || !ctx.isAllowedFullAccess()
          || !ctx.getContainer().isFProxyJavascriptEnabled()) {
        return false;
      }
      try {
        return appHost
            .describe(QUEUE_MANAGER_APP_ID)
            .map(InstalledAppSnapshot::manifest)
            .map(manifest -> manifest.uiMode() == AppUiMode.STATIC)
            .orElse(false);
      } catch (IOException _) {
        return false;
      }
    };
  }
}
