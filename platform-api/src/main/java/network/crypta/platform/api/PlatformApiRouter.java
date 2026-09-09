package network.crypta.platform.api;

import java.util.List;
import java.util.Map;
import network.crypta.platform.api.config.ConfigApiHandler;
import network.crypta.platform.api.peers.PeersApiHandler;
import network.crypta.platform.api.queue.QueueApiHandler;
import network.crypta.platform.api.security.SecurityLevelsApiHandler;
import network.crypta.platform.appcatalog.AppCatalogManager;
import network.crypta.platform.apphost.AppHost;
import network.crypta.platform.appui.AppUiOriginRegistry;
import network.crypta.platform.appvault.AppVaultService;
import network.crypta.runtime.spi.LegacyAdminUsagePort;
import network.crypta.runtime.spi.RuntimePorts;

/**
 * Routes transport-neutral Platform API requests onto detached runtime ports.
 *
 * <p>The router keeps the Platform API v1 surface small and predictable. It accepts one request
 * descriptor, validates the method and relative path beneath {@link
 * PlatformApiPaths#API_V1_PREFIX}, delegates to the relevant endpoint family, and emits a JSON
 * response with stable status codes for malformed requests and missing resources.
 */
public final class PlatformApiRouter {
  /** Logger used for unexpected failures that escape endpoint-specific validation. */
  private static final System.Logger LOG = System.getLogger(PlatformApiRouter.class.getName());

  /** Shared 405 message for routes that only support GET. */
  private static final String GET_ONLY_MESSAGE = "Platform API v1 supports GET requests only.";

  /** Shared 405 message for routes that only support POST. */
  private static final String POST_ONLY_MESSAGE = "Platform API v1 supports POST requests only.";

  /** Handler for the {@code /peers/...} endpoint family. */
  private final PeersApiHandler peersApiHandler;

  /** Handler for the {@code /config} endpoint. */
  private final ConfigApiHandler configApiHandler;

  /** Handler for the {@code /security-levels} endpoint. */
  private final SecurityLevelsApiHandler securityLevelsApiHandler;

  /** Handler for the {@code /queue/...} endpoint family. */
  private final QueueApiHandler queueApiHandler;

  /** Routes daemon-operational endpoint families. */
  private final PlatformApiOperationalRoutes operationalRoutes;

  /** Routes host/operator-only beta dashboard and recovery endpoint families. */
  private final PlatformApiOperatorRoutes operatorRoutes;

  /** Routes local Trust Graph Preview endpoint families. */
  private final PlatformApiTrustGraphRoutes trustGraphRoutes;

  private final PlatformApiMailRoutes mailRoutes;

  /** Routes app, app-catalog, app-update, and vault endpoint families. */
  private final PlatformApiAppRoutes appRoutes;

  /** Routes foreground content fetch and durable content subscription endpoint families. */
  private final PlatformApiContentRoutes contentRoutes;

  /** Routes durable app-owned data endpoint families. */
  private final PlatformApiAppDataRoutes appDataRoutes;

  /** Routes local app-service discovery, grant, and invocation endpoint families. */
  private final PlatformApiAppServiceRoutes appServiceRoutes;

  /** Bounded process-local audit log for app-originated authorization decisions. */
  private final AppAuditLog appAuditLog;

  /**
   * Creates a router backed by the supplied runtime ports.
   *
   * @param runtimePorts detached runtime-port aggregate used to resolve API requests
   * @throws NullPointerException if {@code runtimePorts} is {@code null}
   */
  @SuppressWarnings("unused")
  public PlatformApiRouter(RuntimePorts runtimePorts) {
    this(runtimePorts, null, null);
  }

  /**
   * Creates a router backed by the supplied runtime ports and AppHost instance.
   *
   * @param runtimePorts detached runtime-port aggregate used to resolve API requests
   * @param appHost detached AppHost used by the app-management endpoint family
   * @throws NullPointerException if {@code runtimePorts} is {@code null}
   */
  public PlatformApiRouter(RuntimePorts runtimePorts, AppHost appHost) {
    this(runtimePorts, appHost, null);
  }

  /**
   * Creates a router backed by runtime ports, AppHost, and signed app catalogs.
   *
   * @param runtimePorts detached runtime-port aggregate used to resolve API requests
   * @param appHost detached AppHost used by app lifecycle and catalog install/update routes
   * @param appCatalogManager signed catalog manager used by the catalog endpoint family
   * @throws NullPointerException if {@code runtimePorts} is {@code null}
   */
  public PlatformApiRouter(
      RuntimePorts runtimePorts, AppHost appHost, AppCatalogManager appCatalogManager) {
    this(runtimePorts, appHost, appCatalogManager, null);
  }

  /**
   * Creates a router backed by runtime ports, AppHost, signed app catalogs, and optional
   * legacy-admin usage diagnostics.
   *
   * @param runtimePorts detached runtime-port aggregate used to resolve API requests
   * @param appHost detached AppHost used by app lifecycle and catalog install/update routes
   * @param appCatalogManager signed catalog manager used by the catalog endpoint family
   * @param legacyAdminUsage optional process-local legacy admin usage source
   * @throws NullPointerException if {@code runtimePorts} is {@code null}
   */
  public PlatformApiRouter(
      RuntimePorts runtimePorts,
      AppHost appHost,
      AppCatalogManager appCatalogManager,
      LegacyAdminUsagePort legacyAdminUsage) {
    this(
        runtimePorts,
        appHost,
        appCatalogManager,
        legacyAdminUsage,
        new AppAuditLog(),
        AppUiOriginRegistry.sameOriginOnly());
  }

  /**
   * Creates a router backed by runtime ports, AppHost, signed catalogs, diagnostics, and app UI
   * origin metadata.
   *
   * @param runtimePorts detached runtime-port aggregate used to resolve API requests
   * @param appHost detached AppHost used by app lifecycle and catalog install/update routes
   * @param appCatalogManager signed catalog manager used by the catalog endpoint family
   * @param legacyAdminUsage optional process-local legacy admin usage source
   * @param appUiOriginRegistry registry used to publish isolated app UI launch URLs
   */
  @SuppressWarnings("unused")
  public PlatformApiRouter(
      RuntimePorts runtimePorts,
      AppHost appHost,
      AppCatalogManager appCatalogManager,
      LegacyAdminUsagePort legacyAdminUsage,
      AppUiOriginRegistry appUiOriginRegistry) {
    this(
        runtimePorts,
        appHost,
        appCatalogManager,
        legacyAdminUsage,
        appUiOriginRegistry,
        PlatformApiSharedAppServices.none());
  }

  /**
   * Creates a router backed by runtime ports, app services, origin metadata, and the app vault.
   *
   * @param runtimePorts detached runtime-port aggregate used to resolve API requests
   * @param appHost detached AppHost used by app lifecycle and catalog install/update routes
   * @param appCatalogManager signed catalog manager used by the catalog endpoint family
   * @param legacyAdminUsage optional process-local legacy admin usage source
   * @param appUiOriginRegistry registry used to publish isolated app UI launch URLs
   * @param appVaultService optional app-vault service used by vault endpoint families
   */
  public PlatformApiRouter(
      RuntimePorts runtimePorts,
      AppHost appHost,
      AppCatalogManager appCatalogManager,
      LegacyAdminUsagePort legacyAdminUsage,
      AppUiOriginRegistry appUiOriginRegistry,
      AppVaultService appVaultService) {
    this(
        runtimePorts,
        appHost,
        appCatalogManager,
        legacyAdminUsage,
        appUiOriginRegistry,
        PlatformApiSharedAppServices.withVault(appVaultService));
  }

  /**
   * Creates a router backed by runtime ports and shared app-platform services.
   *
   * <p>This overload lets runtime composition pass the same optional app-platform services used by
   * background schedulers into the request router. That keeps manual requests, scheduler-triggered
   * work, policy state, staged plans, and subscription metadata attached to shared service
   * instances. Constructors used by unit tests and alternate embeddings continue to create no
   * scheduler threads and may omit the service group.
   *
   * @param runtimePorts detached runtime-port aggregate used to resolve API requests
   * @param appHost detached AppHost used by app lifecycle and catalog install/update routes
   * @param appCatalogManager signed catalog manager used by the catalog endpoint family
   * @param legacyAdminUsage optional process-local legacy admin usage source
   * @param appUiOriginRegistry registry used to publish isolated app UI launch URLs
   * @param sharedAppServices optional app-platform services also used by background schedulers
   */
  public PlatformApiRouter(
      RuntimePorts runtimePorts,
      AppHost appHost,
      AppCatalogManager appCatalogManager,
      LegacyAdminUsagePort legacyAdminUsage,
      AppUiOriginRegistry appUiOriginRegistry,
      PlatformApiSharedAppServices sharedAppServices) {
    this(
        runtimePorts,
        appHost,
        appCatalogManager,
        legacyAdminUsage,
        new AppAuditLog(),
        appUiOriginRegistry,
        sharedAppServices);
  }

  PlatformApiRouter(
      RuntimePorts runtimePorts,
      AppHost appHost,
      AppCatalogManager appCatalogManager,
      LegacyAdminUsagePort legacyAdminUsage,
      AppAuditLog appAuditLog) {
    this(
        runtimePorts,
        appHost,
        appCatalogManager,
        legacyAdminUsage,
        appAuditLog,
        AppUiOriginRegistry.sameOriginOnly(),
        PlatformApiSharedAppServices.none());
  }

  PlatformApiRouter(
      RuntimePorts runtimePorts,
      AppHost appHost,
      AppCatalogManager appCatalogManager,
      LegacyAdminUsagePort legacyAdminUsage,
      AppAuditLog appAuditLog,
      AppUiOriginRegistry appUiOriginRegistry) {
    this(
        runtimePorts,
        appHost,
        appCatalogManager,
        legacyAdminUsage,
        appAuditLog,
        appUiOriginRegistry,
        PlatformApiSharedAppServices.none());
  }

  @SuppressWarnings("unused")
  PlatformApiRouter(
      RuntimePorts runtimePorts,
      AppHost appHost,
      AppCatalogManager appCatalogManager,
      LegacyAdminUsagePort legacyAdminUsage,
      AppAuditLog appAuditLog,
      AppUiOriginRegistry appUiOriginRegistry,
      AppVaultService appVaultService) {
    this(
        runtimePorts,
        appHost,
        appCatalogManager,
        legacyAdminUsage,
        appAuditLog,
        appUiOriginRegistry,
        PlatformApiSharedAppServices.withVault(appVaultService));
  }

  PlatformApiRouter(
      RuntimePorts runtimePorts,
      AppHost appHost,
      AppCatalogManager appCatalogManager,
      LegacyAdminUsagePort legacyAdminUsage,
      AppAuditLog appAuditLog,
      AppUiOriginRegistry appUiOriginRegistry,
      PlatformApiSharedAppServices appServices) {
    RuntimePorts checkedRuntimePorts = requireNonNull(runtimePorts, "runtimePorts");
    this.appAuditLog = requireNonNull(appAuditLog, "appAuditLog");
    requireNonNull(appUiOriginRegistry, "appUiOriginRegistry");
    PlatformApiSharedAppServices checkedAppServices = requireNonNull(appServices, "appServices");
    AppVaultService appVaultService = checkedAppServices.vaultService();
    operationalRoutes = new PlatformApiOperationalRoutes(checkedRuntimePorts, legacyAdminUsage);
    peersApiHandler =
        new PeersApiHandler(checkedRuntimePorts.peer(), checkedRuntimePorts.darknetConnections());
    configApiHandler = new ConfigApiHandler(checkedRuntimePorts.config());
    securityLevelsApiHandler =
        new SecurityLevelsApiHandler(
            checkedRuntimePorts.securityLevels(),
            checkedRuntimePorts.config(),
            checkedRuntimePorts.firstTimeWizard());
    queueApiHandler =
        new QueueApiHandler(
            checkedRuntimePorts.queuePage(),
            checkedRuntimePorts.queueMutation(),
            checkedRuntimePorts.queueDownload(),
            checkedRuntimePorts.queueInsert(),
            checkedRuntimePorts.queueSupport(),
            checkedRuntimePorts.queueCompletion());
    trustGraphRoutes =
        PlatformApiTrustGraphRoutes.from(checkedAppServices, checkedRuntimePorts.contentFetch());
    appRoutes =
        new PlatformApiAppRoutes(
            new PlatformApiAppRoutes.RouteDependencies(
                appHost,
                appCatalogManager,
                this.appAuditLog,
                appUiOriginRegistry,
                operationalRoutes::currentCryptaVersion),
            new PlatformApiAppRoutes.SharedServices(
                appVaultService,
                checkedAppServices.updateService(),
                checkedAppServices.contentSubscriptionService(),
                checkedAppServices.appDataService(),
                checkedAppServices.appServiceCoordinator()));
    operatorRoutes =
        new PlatformApiOperatorRoutes(
            new PlatformApiOperatorRoutes.RouteDependencies(
                checkedRuntimePorts,
                appHost,
                appCatalogManager,
                legacyAdminUsage,
                this.appAuditLog,
                appUiOriginRegistry,
                operationalRoutes::currentCryptaVersion),
            checkedAppServices,
            appRoutes,
            trustGraphRoutes.trustGraphApiHandler());
    contentRoutes =
        new PlatformApiContentRoutes(
            checkedRuntimePorts,
            checkedAppServices.contentSubscriptionService(),
            checkedAppServices.networkBudgetService());
    mailRoutes = new PlatformApiMailRoutes(appHost, appVaultService);
    appDataRoutes = new PlatformApiAppDataRoutes(checkedAppServices.appDataService());
    appServiceRoutes =
        new PlatformApiAppServiceRoutes(
            checkedAppServices.appServiceCoordinator(), appRoutes.consentService());
  }

  /**
   * Routes one request and returns the corresponding JSON response.
   *
   * <p>Known request validation failures are converted into structured error responses. Unexpected
   * runtime failures are allowed to propagate so the transport-specific bridge can log them and map
   * them onto a generic {@code 500} response.
   *
   * @param request transport-neutral request metadata to route
   * @return JSON response for the routed endpoint
   */
  public PlatformApiResponse route(PlatformApiRequest request) {
    PlatformApiRequest checkedRequest = requireNonNull(request, "request");
    PlatformApiAuthorizationDecision authorization =
        PlatformApiCapabilities.authorize(checkedRequest);
    if (!authorization.allowed()) {
      PlatformApiResponse response =
          PlatformApiResponse.error(
              403, "forbidden", "App principal lacks the required Platform API capability.");
      appAuditLog.appendDecision(
          checkedRequest,
          authorization,
          AppAuditDecision.DENIED,
          response.statusCode(),
          authorization.reasonCode());
      return response;
    }

    try {
      PlatformApiResponse response = routeInternal(checkedRequest);
      appAuditLog.appendDecision(
          checkedRequest,
          authorization,
          AppAuditDecision.ALLOWED,
          response.statusCode(),
          "route_completed");
      return response;
    } catch (RuntimeException e) {
      PlatformApiResponse structuredFailure =
          structuredFailureResponse(checkedRequest, authorization, e);
      if (structuredFailure != null) {
        return structuredFailure;
      }
      LOG.log(System.Logger.Level.ERROR, "Unexpected Platform API failure", e);
      PlatformApiResponse response =
          PlatformApiResponse.error(500, "internal_error", "Unexpected platform API failure.");
      appAuditLog.appendDecision(
          checkedRequest,
          authorization,
          AppAuditDecision.ALLOWED,
          response.statusCode(),
          "internal_error");
      return response;
    }
  }

  private PlatformApiResponse structuredFailureResponse(
      PlatformApiRequest checkedRequest,
      PlatformApiAuthorizationDecision authorization,
      RuntimeException exception) {
    if (exception instanceof PlatformApiException platformException) {
      return structuredFailureResponse(
          checkedRequest,
          authorization,
          platformException.statusCode(),
          platformException.errorCode(),
          platformException.getMessage());
    }
    if (PlatformApiVaultRouter.isVaultException(exception)) {
      return structuredFailureResponse(
          checkedRequest,
          authorization,
          PlatformApiVaultRouter.statusCode(exception),
          PlatformApiVaultRouter.errorCode(exception),
          exception.getMessage());
    }
    return null;
  }

  private PlatformApiResponse structuredFailureResponse(
      PlatformApiRequest checkedRequest,
      PlatformApiAuthorizationDecision authorization,
      int statusCode,
      String errorCode,
      String message) {
    PlatformApiResponse response = PlatformApiResponse.error(statusCode, errorCode, message);
    appAuditLog.appendDecision(
        checkedRequest, authorization, AppAuditDecision.ALLOWED, response.statusCode(), errorCode);
    return response;
  }

  /**
   * Performs method and path validation after null checking has already completed.
   *
   * @param request non-null transport-neutral request metadata
   * @return JSON response for the routed endpoint or a structured error response
   */
  private PlatformApiResponse routeInternal(PlatformApiRequest request) {
    List<String> segments = request.pathSegments();
    if (segments.isEmpty()) {
      throw new PlatformApiException(404, "not_found", "Platform API route not found.");
    }

    String firstSegment = segments.getFirst();
    return switch (firstSegment) {
      case "platform" -> routePlatformRequest(segments, request);
      case "app-catalogs" -> appRoutes.routeAppCatalogsRequest(segments, request);
      case "app-review" -> appRoutes.routeAppReviewRequest(segments, request);
      case "apps" -> appRoutes.routeAppsRequest(segments, request);
      case "mail" -> mailRoutes.route(request);
      case "app-vault" -> appRoutes.routeAppVaultRequest(segments, request);
      case "identity-vault" -> appRoutes.routeIdentityVaultRequest(segments, request);
      case "queue" -> routeQueueRequest(segments, request);
      case "content" -> contentRoutes.route(segments, request);
      case "app-data" -> appDataRoutes.route(segments, request);
      case "app-services" -> appServiceRoutes.route(segments, request);
      case "consent" -> appRoutes.routeConsentRequest(segments, request);
      case "operator" -> operatorRoutes.route(segments, request);
      case "trust-graph" -> trustGraphRoutes.route(segments, request);
      case "node", "connectivity", "diagnostics", "updates", "wizard", "alerts" ->
          operationalRoutes.route(segments, request);
      case "peers" -> routePeersRequest(segments, request);
      case "config" -> routeConfigRequest(segments, request);
      case "security-levels" -> routeSecurityLevelsRequest(segments, request);
      default -> routeUnknownRequest(request);
    };
  }

  private PlatformApiResponse routePlatformRequest(
      List<String> segments, PlatformApiRequest request) {
    if (segments.size() == 2 && "contract".equals(segments.get(1))) {
      if (!"GET".equals(request.method())) {
        return methodNotAllowed("GET", GET_ONLY_MESSAGE);
      }
      return PlatformApiResponse.ok(
          PlatformApiContractJson.envelope(
              PlatformApiContract.current(), PlatformApiBaselineRegistry.current()));
    }
    throw new PlatformApiException(404, "not_found", "Platform API route not found.");
  }

  private PlatformApiResponse routeUnknownRequest(PlatformApiRequest request) {
    if (!"GET".equals(request.method())) {
      return methodNotAllowed("GET", GET_ONLY_MESSAGE);
    }
    throw new PlatformApiException(404, "not_found", "Platform API route not found.");
  }

  /**
   * Routes requests beneath the {@code /config} endpoint family.
   *
   * @param segments decoded path segments relative to the Platform API mount point
   * @param request full request metadata, including query parameters
   * @return JSON response for the selected configuration endpoint
   */
  private PlatformApiResponse routeConfigRequest(
      List<String> segments, PlatformApiRequest request) {
    return switch (segments.size()) {
      case 1 -> routeConfigRoot(request);
      case 2 -> routeConfigAction(segments.get(1), request);
      default -> throw new PlatformApiException(404, "not_found", "Platform API route not found.");
    };
  }

  private PlatformApiResponse routeConfigRoot(PlatformApiRequest request) {
    if (!"GET".equals(request.method())) {
      return methodNotAllowed("GET", GET_ONLY_MESSAGE);
    }
    return PlatformApiResponse.ok(configApiHandler.exportConfig(request.queryParameters()));
  }

  private PlatformApiResponse routeConfigAction(String action, PlatformApiRequest request) {
    if ("overrides".equals(action)) {
      if (!"POST".equals(request.method())) {
        return methodNotAllowed("POST", POST_ONLY_MESSAGE);
      }
      return PlatformApiResponse.ok(configApiHandler.applyOverrides(request.queryParameters()));
    }
    if ("persist".equals(action)) {
      if (!"POST".equals(request.method())) {
        return methodNotAllowed("POST", POST_ONLY_MESSAGE);
      }
      return PlatformApiResponse.ok(configApiHandler.persist());
    }
    throw new PlatformApiException(404, "not_found", "Platform API route not found.");
  }

  /**
   * Routes requests beneath the {@code /security-levels} endpoint family.
   *
   * @param segments decoded path segments relative to the Platform API mount point
   * @param request full request metadata, including query parameters
   * @return JSON response for the selected security-levels endpoint
   */
  private PlatformApiResponse routeSecurityLevelsRequest(
      List<String> segments, PlatformApiRequest request) {
    return switch (segments.size()) {
      case 1 -> routeSecurityLevelsRoot(request);
      case 2 -> routeSecurityLevelsAction(segments.get(1), request);
      default -> throw new PlatformApiException(404, "not_found", "Platform API route not found.");
    };
  }

  private PlatformApiResponse routeSecurityLevelsRoot(PlatformApiRequest request) {
    if (!"GET".equals(request.method())) {
      return methodNotAllowed("GET", GET_ONLY_MESSAGE);
    }
    return PlatformApiResponse.ok(securityLevelsApiHandler.snapshot());
  }

  private PlatformApiResponse routeSecurityLevelsAction(String action, PlatformApiRequest request) {
    if ("network-warning".equals(action)) {
      if (!"GET".equals(request.method())) {
        return methodNotAllowed("GET", GET_ONLY_MESSAGE);
      }
      return PlatformApiResponse.ok(
          securityLevelsApiHandler.networkThreatLevelWarning(request.queryParameters()));
    }
    if ("network".equals(action)) {
      if (!"POST".equals(request.method())) {
        return methodNotAllowed("POST", POST_ONLY_MESSAGE);
      }
      return PlatformApiResponse.ok(
          securityLevelsApiHandler.setNetworkThreatLevel(request.queryParameters()));
    }
    if ("physical".equals(action)) {
      if (!"POST".equals(request.method())) {
        return methodNotAllowed("POST", POST_ONLY_MESSAGE);
      }
      return PlatformApiResponse.ok(
          securityLevelsApiHandler.setPhysicalThreatLevel(request.queryParameters()));
    }
    throw new PlatformApiException(404, "not_found", "Platform API route not found.");
  }

  /**
   * Routes requests beneath the {@code /queue} endpoint family.
   *
   * @param segments decoded path segments relative to the Platform API mount point
   * @param request full request metadata, including query parameters
   * @return JSON response for the selected queue endpoint
   */
  private PlatformApiResponse routeQueueRequest(List<String> segments, PlatformApiRequest request) {
    return switch (segments.size()) {
      case 1 -> routeQueueRoot(request);
      case 2 -> routeQueueResource(segments.get(1), request);
      case 3 -> routeQueueAction(segments.get(1), segments.get(2), request);
      default -> throw new PlatformApiException(404, "not_found", "Platform API route not found.");
    };
  }

  /**
   * Routes the queue snapshot endpoint at {@code /queue}.
   *
   * @param request full request metadata, including query parameters
   * @return JSON response containing one detached queue snapshot
   */
  private PlatformApiResponse routeQueueRoot(PlatformApiRequest request) {
    if (!"GET".equals(request.method())) {
      return methodNotAllowed("GET", GET_ONLY_MESSAGE);
    }
    return PlatformApiResponse.ok(queueApiHandler.snapshot(request.queryParameters()));
  }

  /**
   * Routes queue resources such as count, keys, and direct-download creation.
   *
   * @param resource second path segment beneath {@code /queue}
   * @param request full request metadata, including query parameters
   * @return JSON response for the selected queue resource
   */
  private PlatformApiResponse routeQueueResource(String resource, PlatformApiRequest request) {
    return switch (resource) {
      case "count" -> routeQueueCount(request);
      case "keys" -> routeQueueKeys(request);
      case "app-document-status" -> {
        if (!"GET".equals(request.method())
            || !"mail-prototype".equals(request.principal().appId())
            || request.principal().authSource() != PlatformApiAuthSource.APP_TOKEN) {
          throw new PlatformApiException(403, "forbidden", "App process required.");
        }
        yield PlatformApiResponse.ok(
            queueApiHandler.appDocumentStatus(
                requireAppPrincipalId(request), request.queryParameters()));
      }
      case "downloads" -> routeQueueDownloads(request);
      default -> throw new PlatformApiException(404, "not_found", "Platform API route not found.");
    };
  }

  /**
   * Routes queue snapshot count requests.
   *
   * @param request full request metadata, including query parameters
   * @return JSON response containing one detached count snapshot
   */
  private PlatformApiResponse routeQueueCount(PlatformApiRequest request) {
    if (!"GET".equals(request.method())) {
      return methodNotAllowed("GET", GET_ONLY_MESSAGE);
    }
    return PlatformApiResponse.ok(queueApiHandler.count(request.queryParameters()));
  }

  /**
   * Routes queue key-export requests.
   *
   * @param request full request metadata, including query parameters
   * @return JSON response containing the detached queue key export
   */
  private PlatformApiResponse routeQueueKeys(PlatformApiRequest request) {
    if (!"GET".equals(request.method())) {
      return methodNotAllowed("GET", GET_ONLY_MESSAGE);
    }
    return PlatformApiResponse.ok(queueApiHandler.keys(request.queryParameters()));
  }

  /**
   * Routes direct-download creation requests.
   *
   * @param request full request metadata, including query parameters
   * @return JSON response describing the newly queued direct download
   */
  private PlatformApiResponse routeQueueDownloads(PlatformApiRequest request) {
    if (!"POST".equals(request.method())) {
      return methodNotAllowed("POST", POST_ONLY_MESSAGE);
    }
    return PlatformApiResponse.created(
        queueApiHandler.createDirectDownload(request.queryParameters()));
  }

  /**
   * Routes queue mutation actions beneath {@code /queue/...}.
   *
   * @param resource second path segment beneath {@code /queue}
   * @param action queue action segment
   * @param request full request metadata, including query parameters
   * @return JSON response for the selected queue mutation
   */
  private PlatformApiResponse routeQueueAction(
      String resource, String action, PlatformApiRequest request) {
    if (!"POST".equals(request.method())) {
      return methodNotAllowed("POST", POST_ONLY_MESSAGE);
    }
    if ("inserts".equals(resource)) {
      return switch (action) {
        case "file" ->
            PlatformApiResponse.created(
                queueApiHandler.createLocalFileInsert(request.queryParameters()));
        case "directory" ->
            PlatformApiResponse.created(
                queueApiHandler.createLocalDirectoryInsert(request.queryParameters()));
        case "app-document" ->
            PlatformApiResponse.created(
                queueApiHandler.createAppDocumentInsert(
                    requireAppPrincipalId(request), request.queryParameters()));
        default ->
            throw new PlatformApiException(404, "not_found", "Platform API route not found.");
      };
    }
    if ("requests".equals(resource)) {
      return switch (action) {
        case "remove" ->
            PlatformApiResponse.ok(queueApiHandler.removeRequests(request.queryParameters()));
        case "restart" ->
            PlatformApiResponse.ok(queueApiHandler.restartRequests(request.queryParameters()));
        case "priority" ->
            PlatformApiResponse.ok(queueApiHandler.changePriority(request.queryParameters()));
        default ->
            throw new PlatformApiException(404, "not_found", "Platform API route not found.");
      };
    }
    if ("cleanup".equals(resource)) {
      return switch (action) {
        case "uploads" ->
            PlatformApiResponse.ok(queueApiHandler.cleanupUploads(request.queryParameters()));
        case "downloads" ->
            PlatformApiResponse.ok(queueApiHandler.cleanupDownloads(request.queryParameters()));
        default ->
            throw new PlatformApiException(404, "not_found", "Platform API route not found.");
      };
    }
    throw new PlatformApiException(404, "not_found", "Platform API route not found.");
  }

  private static String requireAppPrincipalId(PlatformApiRequest request) {
    if (!request.principal().isApp()) {
      throw new PlatformApiException(
          403, "forbidden", "This Platform API route requires an app principal.");
    }
    return request.principal().appId();
  }

  /**
   * Routes requests beneath the {@code /peers} endpoint family.
   *
   * @param segments decoded path segments relative to the Platform API mount point
   * @param request full request metadata, including query parameters
   * @return JSON response for either the peer list or one peer detail endpoint
   * @throws PlatformApiException if the path does not identify a supported peers endpoint
   */
  private PlatformApiResponse routePeersRequest(List<String> segments, PlatformApiRequest request) {
    return switch (segments.size()) {
      case 1 -> routePeersRoot(request);
      case 2 -> routePeerResource(segments.get(1), request);
      case 3 -> routePeerAction(segments.get(1), segments.get(2), request);
      default -> throw new PlatformApiException(404, "not_found", "Platform API route not found.");
    };
  }

  /**
   * Routes either the raw peer collection export or the shell summary view at {@code /peers}.
   *
   * @param request full request metadata, including query parameters
   * @return JSON response containing the requested peer collection view
   */
  private PlatformApiResponse routePeersRoot(PlatformApiRequest request) {
    if (!"GET".equals(request.method())) {
      return methodNotAllowed("GET", GET_ONLY_MESSAGE);
    }
    String view = PlatformApiParameters.readOptionalString(request.queryParameters(), "view");
    if (view != null) {
      if ("summary".equals(view)) {
        return PlatformApiResponse.ok(peersApiHandler.roster());
      }
      throw new PlatformApiException(
          400, "invalid_query_parameter", "Query parameter 'view' must be 'summary'.");
    }
    return PlatformApiResponse.ok(peersApiHandler.list(request.queryParameters()));
  }

  /**
   * Routes either the add-peer endpoint or one raw peer resource.
   *
   * @param resource second path segment beneath {@code /peers}
   * @param request full request metadata, including query parameters
   * @return JSON response for the selected peer endpoint
   */
  private PlatformApiResponse routePeerResource(String resource, PlatformApiRequest request) {
    if ("add".equals(resource) && "POST".equals(request.method())) {
      return PlatformApiResponse.created(peersApiHandler.add(request.queryParameters()));
    }

    if (!"GET".equals(request.method())) {
      return methodNotAllowed("GET", GET_ONLY_MESSAGE);
    }
    return PlatformApiResponse.ok(peersApiHandler.get(resource, request.queryParameters()));
  }

  /**
   * Routes peer mutations beneath {@code /peers/{peerIdentity}/...}.
   *
   * @param peerIdentity exact peer identity segment
   * @param action peer action segment
   * @param request full request metadata, including query parameters
   * @return JSON response for the selected peer mutation
   */
  private PlatformApiResponse routePeerAction(
      String peerIdentity, String action, PlatformApiRequest request) {
    if (!"POST".equals(request.method())) {
      return methodNotAllowed("POST", POST_ONLY_MESSAGE);
    }
    return switch (action) {
      case "settings" ->
          PlatformApiResponse.ok(
              peersApiHandler.updateSettings(peerIdentity, request.queryParameters()));
      case "note" ->
          PlatformApiResponse.ok(
              peersApiHandler.updateNote(peerIdentity, request.queryParameters()));
      case "remove" ->
          PlatformApiResponse.ok(peersApiHandler.remove(peerIdentity, request.queryParameters()));
      default -> throw new PlatformApiException(404, "not_found", "Platform API route not found.");
    };
  }

  private static <T> T requireNonNull(T value, String parameterName) {
    if (value == null) {
      throw new NullPointerException(parameterName);
    }
    return value;
  }

  /**
   * Creates a structured 405 response with a stable Allow header.
   *
   * @param allow allowed methods for the current route
   * @param message human-readable error message
   * @return structured platform API response
   */
  private static PlatformApiResponse methodNotAllowed(String allow, String message) {
    return PlatformApiResponse.error(405, Map.of("Allow", allow), "method_not_allowed", message);
  }
}
