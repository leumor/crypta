package network.crypta.clients.http;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import network.crypta.platform.api.PlatformApiException;
import network.crypta.platform.api.PlatformApiPaths;
import network.crypta.platform.api.PlatformApiPrincipal;
import network.crypta.platform.api.PlatformApiRequest;
import network.crypta.platform.api.PlatformApiResponse;
import network.crypta.platform.api.PlatformApiRouter;
import network.crypta.platform.api.PlatformApiSharedAppServices;
import network.crypta.platform.api.appupdates.AppUpdateService;
import network.crypta.platform.appcatalog.AppCatalogManager;
import network.crypta.platform.apphost.AppHost;
import network.crypta.platform.apphost.AppTokenPrincipal;
import network.crypta.platform.appui.AppBrowserSession;
import network.crypta.platform.appui.AppBrowserSessionVerifier;
import network.crypta.platform.appui.AppUiOriginBinding;
import network.crypta.platform.appui.AppUiOriginMode;
import network.crypta.platform.appui.AppUiOriginRegistry;
import network.crypta.platform.appvault.AppVaultService;
import network.crypta.runtime.spi.RuntimePorts;
import network.crypta.support.MultiValueTable;
import network.crypta.support.URLDecoder;
import network.crypta.support.URLEncodedFormatException;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.HTTPRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Thin legacy-HTTP bridge for Platform API v1.
 *
 * <p>This toadlet keeps all transport-neutral routing and JSON construction inside {@code
 * :platform-api}. Its responsibility is limited to enforcing the existing full-access expectation
 * for host/operator routes, authenticating AppHost launch-token headers when present, translating
 * legacy HTTP request state into a {@link PlatformApiRequest}, and writing the resulting JSON back
 * through the legacy HTTP shell.
 */
@SuppressWarnings("unused")
public final class PlatformApiToadlet extends Toadlet {
  /** Versioned mount path for the legacy HTTP bridge. */
  public static final String MOUNT_PATH = PlatformApiPaths.API_V1_PREFIX;

  /**
   * Logger for unexpected bridge failures that occur before the router can serialize a response.
   */
  private static final Logger LOG = LoggerFactory.getLogger(PlatformApiToadlet.class);

  /** JSON media type advertised for every Platform API response emitted through the bridge. */
  private static final String JSON_CONTENT_TYPE = "application/json; charset=UTF-8";

  /** Legacy maximum accepted size for one URL-encoded request body. */
  private static final long MAX_URL_ENCODED_BODY_LENGTH = 1024L * 1024L;

  private static final String URL_ENCODED_CONTENT_TYPE = "application/x-www-form-urlencoded";

  private static final String APP_TOKEN_HEADER = "x-crypta-app-token";
  private static final String APP_SESSION_HEADER = "x-crypta-app-session";
  private static final String AUTHORIZATION_HEADER = "authorization";
  private static final String ORIGIN_HEADER = "origin";
  private static final String ACCESS_CONTROL_REQUEST_METHOD_HEADER =
      "access-control-request-method";
  private static final String ACCESS_CONTROL_REQUEST_HEADERS_HEADER =
      "access-control-request-headers";
  private static final String ACCESS_CONTROL_ALLOW_ORIGIN_HEADER = "Access-Control-Allow-Origin";
  private static final String ACCESS_CONTROL_ALLOW_METHODS_HEADER = "Access-Control-Allow-Methods";
  private static final String ACCESS_CONTROL_ALLOW_HEADERS_HEADER = "Access-Control-Allow-Headers";
  private static final String ACCESS_CONTROL_MAX_AGE_HEADER = "Access-Control-Max-Age";
  private static final String VARY_HEADER = "Vary";
  private static final String ALLOWED_CORS_METHODS = "GET, POST, PUT, PATCH, DELETE";
  private static final String ALLOWED_CORS_HEADERS = "X-Crypta-App-Session, Accept, Content-Type";
  private static final String CORS_VARY_VALUE =
      "Origin, Access-Control-Request-Method, Access-Control-Request-Headers";
  private static final String BEARER_PREFIX = "bearer";
  private static final String DELETE_METHOD = "DELETE";
  private static final String PATCH_METHOD = "PATCH";
  private static final String PUT_METHOD = "PUT";
  private static final String ALERTS_SEGMENT = "alerts";
  private static final String APP_CATALOGS_SEGMENT = "app-catalogs";
  private static final String APP_SERVICES_SEGMENT = "app-services";
  private static final String CONSENT_SEGMENT = "consent";
  private static final String FORM_PASSWORD_PARAMETER = "formPassword";
  private static final String GRANT_BUNDLES_SEGMENT = "grant-bundles";
  private static final String GRANTS_SEGMENT = "grants";
  private static final String IDENTITY_VAULT_SEGMENT = "identity-vault";
  private static final String MIRRORS_SEGMENT = "mirrors";
  private static final String OPERATOR_SEGMENT = "operator";
  private static final int MAX_PLATFORM_API_FORM_FIELD_LENGTH = QueueToadlet.MAX_KEY_LENGTH;
  private static final String CONFIG_SEGMENT = "config";
  private static final String CONTENT_SEGMENT = "content";
  private static final String PEERS_SEGMENT = "peers";
  private static final String QUEUE_SEGMENT = "queue";
  private static final String SECURITY_LEVELS_SEGMENT = "security-levels";
  private static final String TRUST_GRAPH_SEGMENT = "trust-graph";
  private static final String UPDATES_SEGMENT = "updates";
  private static final String WIZARD_SEGMENT = "wizard";
  private static final String APPROVE_ACTION = "approve";
  private static final String REMOVE_ACTION = "remove";

  /**
   * Transport-neutral router that owns endpoint selection, validation, and JSON payload creation.
   */
  private final PlatformApiRouter router;

  /** Optional AppHost used to authenticate process-originated app launch tokens. */
  private final AppHost appHost;

  /** Optional verifier used to authenticate browser-originated app sessions. */
  private final AppBrowserSessionVerifier appBrowserSessionVerifier;

  /** Registry of isolated app UI origins allowed to use browser-session CORS. */
  private final AppUiOriginRegistry appUiOriginRegistry;

  /**
   * Creates a platform API toadlet backed by the supplied runtime ports.
   *
   * @param runtimePorts detached runtime ports exposed to the platform API leaf
   */
  public PlatformApiToadlet(RuntimePorts runtimePorts) {
    this(
        new PlatformApiRouter(runtimePorts, null, null, LegacyAdminUsageRecorder.defaultRecorder()),
        null,
        null,
        AppUiOriginRegistry.sameOriginOnly());
  }

  /**
   * Creates a platform API toadlet backed by runtime ports and AppHost.
   *
   * @param runtimePorts detached runtime ports exposed to the platform API leaf
   * @param appHost detached AppHost exposed through the app-management control surface
   */
  public PlatformApiToadlet(RuntimePorts runtimePorts, AppHost appHost) {
    this(
        new PlatformApiRouter(
            runtimePorts, appHost, null, LegacyAdminUsageRecorder.defaultRecorder()),
        appHost,
        null,
        AppUiOriginRegistry.sameOriginOnly());
  }

  /**
   * Creates a platform API toadlet backed by runtime ports, AppHost, and signed catalogs.
   *
   * @param runtimePorts detached runtime ports exposed to the platform API leaf
   * @param appHost detached AppHost exposed through app lifecycle and catalog install routes
   * @param appCatalogManager signed app-catalog manager exposed through catalog routes
   */
  public PlatformApiToadlet(
      RuntimePorts runtimePorts, AppHost appHost, AppCatalogManager appCatalogManager) {
    this(
        new PlatformApiRouter(
            runtimePorts, appHost, appCatalogManager, LegacyAdminUsageRecorder.defaultRecorder()),
        appHost,
        null,
        AppUiOriginRegistry.sameOriginOnly());
  }

  /**
   * Creates a platform API toadlet backed by runtime ports, AppHost, signed catalogs, and browser
   * app-session verification.
   *
   * @param runtimePorts detached runtime ports exposed to the platform API leaf
   * @param appHost detached AppHost exposed through app lifecycle and catalog install routes
   * @param appCatalogManager signed app-catalog manager exposed through catalog routes
   * @param appBrowserSessionVerifier verifier shared with the app-owned UI bootstrap route
   */
  public PlatformApiToadlet(
      RuntimePorts runtimePorts,
      AppHost appHost,
      AppCatalogManager appCatalogManager,
      AppBrowserSessionVerifier appBrowserSessionVerifier) {
    this(
        runtimePorts,
        appHost,
        appCatalogManager,
        appBrowserSessionVerifier,
        AppUiOriginRegistry.sameOriginOnly());
  }

  /**
   * Creates a platform API toadlet backed by runtime ports, AppHost, signed catalogs, browser
   * sessions, and app UI origin metadata.
   *
   * @param runtimePorts detached runtime ports exposed to the platform API leaf
   * @param appHost detached AppHost exposed through app lifecycle and catalog install routes
   * @param appCatalogManager signed app-catalog manager exposed through catalog routes
   * @param appBrowserSessionVerifier verifier shared with the app-owned UI bootstrap route
   * @param appUiOriginRegistry registry of active isolated app UI origins
   */
  public PlatformApiToadlet(
      RuntimePorts runtimePorts,
      AppHost appHost,
      AppCatalogManager appCatalogManager,
      AppBrowserSessionVerifier appBrowserSessionVerifier,
      AppUiOriginRegistry appUiOriginRegistry) {
    this(
        runtimePorts,
        appHost,
        appCatalogManager,
        PlatformApiSharedAppServices.none(),
        appBrowserSessionVerifier,
        appUiOriginRegistry);
  }

  /**
   * Creates a platform API toadlet backed by app services, browser sessions, origins, and vault.
   *
   * @param runtimePorts detached runtime ports exposed to the platform API leaf
   * @param appHost detached AppHost exposed through app lifecycle and catalog install routes
   * @param appCatalogManager signed app-catalog manager exposed through catalog routes
   * @param appUpdateService shared app-update service used by scheduler and update routes
   * @param appBrowserSessionVerifier verifier shared with the app-owned UI bootstrap route
   * @param appUiOriginRegistry registry of active isolated app UI origins
   * @param appVaultService shared app-vault service for vault endpoint families
   */
  public PlatformApiToadlet(
      RuntimePorts runtimePorts,
      AppHost appHost,
      AppCatalogManager appCatalogManager,
      AppUpdateService appUpdateService,
      AppBrowserSessionVerifier appBrowserSessionVerifier,
      AppUiOriginRegistry appUiOriginRegistry,
      AppVaultService appVaultService) {
    this(
        runtimePorts,
        appHost,
        appCatalogManager,
        PlatformApiSharedAppServices.of(appVaultService, appUpdateService, null),
        appBrowserSessionVerifier,
        appUiOriginRegistry);
  }

  /**
   * Creates a platform API toadlet backed by shared app-platform services, browser sessions, and
   * origins.
   *
   * <p>The shared service group keeps router composition aligned with runtime-owned schedulers
   * without growing this bridge constructor every time a new app-platform service is added. Reduced
   * embeddings may pass {@link PlatformApiSharedAppServices#none()}.
   *
   * @param runtimePorts detached runtime ports exposed to the platform API leaf
   * @param appHost detached AppHost exposed through app lifecycle and catalog install routes
   * @param appCatalogManager signed app-catalog manager exposed through catalog routes
   * @param sharedAppServices optional app-platform services shared with runtime schedulers
   * @param appBrowserSessionVerifier verifier shared with the app-owned UI bootstrap route
   * @param appUiOriginRegistry registry of active isolated app UI origins
   */
  public PlatformApiToadlet(
      RuntimePorts runtimePorts,
      AppHost appHost,
      AppCatalogManager appCatalogManager,
      PlatformApiSharedAppServices sharedAppServices,
      AppBrowserSessionVerifier appBrowserSessionVerifier,
      AppUiOriginRegistry appUiOriginRegistry) {
    this(
        new PlatformApiRouter(
            runtimePorts,
            appHost,
            appCatalogManager,
            LegacyAdminUsageRecorder.defaultRecorder(),
            appUiOriginRegistry,
            sharedAppServices),
        appHost,
        appBrowserSessionVerifier,
        appUiOriginRegistry);
  }

  /**
   * Creates a platform API toadlet backed by an already constructed router.
   *
   * <p>This constructor exists for tests and narrow composition sites that need to inject a router
   * with controlled behavior. Production wiring normally uses {@link
   * #PlatformApiToadlet(RuntimePorts, AppHost)} so the bridge owns router creation.
   *
   * @param router transport-neutral router that handles request validation and response generation
   */
  PlatformApiToadlet(PlatformApiRouter router) {
    this(router, null, null);
  }

  PlatformApiToadlet(PlatformApiRouter router, AppHost appHost) {
    this(router, appHost, null);
  }

  PlatformApiToadlet(
      PlatformApiRouter router,
      AppHost appHost,
      AppBrowserSessionVerifier appBrowserSessionVerifier) {
    this(router, appHost, appBrowserSessionVerifier, AppUiOriginRegistry.sameOriginOnly());
  }

  PlatformApiToadlet(
      PlatformApiRouter router,
      AppHost appHost,
      AppBrowserSessionVerifier appBrowserSessionVerifier,
      AppUiOriginRegistry appUiOriginRegistry) {
    super();
    this.router = Objects.requireNonNull(router, "router");
    this.appHost = appHost;
    this.appBrowserSessionVerifier = appBrowserSessionVerifier;
    this.appUiOriginRegistry = Objects.requireNonNull(appUiOriginRegistry, "appUiOriginRegistry");
  }

  @Override
  public void handleMethodGET(URI uri, HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException, RedirectException {
    writePlatformApiResponse("GET", uri, request, ctx);
  }

  /**
   * Routes POST requests through the Platform API router.
   *
   * @param uri request target as seen by the legacy HTTP shell
   * @param request decoded legacy HTTP request wrapper
   * @param ctx current toadlet context, including full-access enforcement state
   * @throws ToadletContextClosedException if the client disconnects while the reply is being sent
   * @throws IOException if the legacy HTTP shell fails while writing the response
   */
  public void handleMethodPOST(URI uri, HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    writePlatformApiResponse("POST", uri, request, ctx);
  }

  /**
   * Returns a JSON {@code 405} error for unsupported HEAD requests in extended-method mode.
   *
   * <p>When the legacy HTTP shell is configured to dispatch HEAD explicitly, this bridge still
   * routes the request through the Platform API router so method handling stays consistent with GET
   * and POST. The bridge then suppresses the response body while preserving the JSON content type
   * and reported content length.
   *
   * @param uri request target as seen by the legacy HTTP shell
   * @param request decoded legacy HTTP request wrapper
   * @param ctx current toadlet context, including full-access enforcement state
   * @throws ToadletContextClosedException if the client disconnects while the reply is being sent
   * @throws IOException if the legacy HTTP shell fails while writing the response headers
   */
  public void handleMethodHEAD(URI uri, HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    writePlatformApiResponse("HEAD", uri, request, ctx, false);
  }

  /**
   * Returns a JSON {@code 405} error for unsupported OPTIONS requests.
   *
   * <p>The bridge forwards OPTIONS through the router when the legacy shell dispatches it. That
   * keeps the Platform API method advertisement consistent with the mounted v1 contract.
   *
   * @param uri request target as seen by the legacy HTTP shell
   * @param request decoded legacy HTTP request wrapper
   * @param ctx current toadlet context, including full-access enforcement state
   * @throws ToadletContextClosedException if the client disconnects while the reply is being sent
   * @throws IOException if the legacy HTTP shell fails while writing the response
   */
  public void handleMethodOPTIONS(URI uri, HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    CorsRequest cors = CorsRequest.from(request);
    if (cors.preflight()) {
      writeCorsPreflightResponse(cors, ctx);
      return;
    }
    writePlatformApiResponse("OPTIONS", uri, request, ctx);
  }

  /**
   * Returns a JSON {@code 405} error for unsupported PUT requests.
   *
   * @param uri request target as seen by the legacy HTTP shell
   * @param request decoded legacy HTTP request wrapper
   * @param ctx current toadlet context, including full-access enforcement state
   * @throws ToadletContextClosedException if the client disconnects while the reply is being sent
   * @throws IOException if the legacy HTTP shell fails while writing the response
   */
  public void handleMethodPUT(URI uri, HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    writePlatformApiResponse(PUT_METHOD, uri, request, ctx);
  }

  /**
   * Routes DELETE requests through the Platform API router.
   *
   * @param uri request target as seen by the legacy HTTP shell
   * @param request decoded legacy HTTP request wrapper
   * @param ctx current toadlet context, including full-access enforcement state
   * @throws ToadletContextClosedException if the client disconnects while the reply is being sent
   * @throws IOException if the legacy HTTP shell fails while writing the response
   */
  public void handleMethodDELETE(URI uri, HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    writePlatformApiResponse(DELETE_METHOD, uri, request, ctx);
  }

  /**
   * Routes PATCH requests through the Platform API router.
   *
   * @param uri request target as seen by the legacy HTTP shell
   * @param request decoded legacy HTTP request wrapper
   * @param ctx current toadlet context, including full-access enforcement state
   * @throws ToadletContextClosedException if the client disconnects while the reply is being sent
   * @throws IOException if the legacy HTTP shell fails while writing the response
   */
  public void handleMethodPATCH(URI uri, HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    writePlatformApiResponse(PATCH_METHOD, uri, request, ctx);
  }

  /**
   * Returns a JSON {@code 405} error for unsupported TRACE requests.
   *
   * @param uri request target as seen by the legacy HTTP shell
   * @param request decoded legacy HTTP request wrapper
   * @param ctx current toadlet context, including full-access enforcement state
   * @throws ToadletContextClosedException if the client disconnects while the reply is being sent
   * @throws IOException if the legacy HTTP shell fails while writing the response
   */
  public void handleMethodTRACE(URI uri, HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    writePlatformApiResponse("TRACE", uri, request, ctx);
  }

  @Override
  public String path() {
    return MOUNT_PATH;
  }

  /**
   * Keeps the container from applying its POST-only password gate ahead of the bridge.
   *
   * <p>The bridge enforces the legacy form password explicitly after it has checked full-access
   * permissions, which preserves the Platform API's JSON {@code 403} behavior for non-full-access
   * callers and extends the same password requirement to DELETE.
   */
  @Override
  public boolean allowPOSTWithoutPassword() {
    return true;
  }

  /**
   * Routes a request through the Platform API and writes the resulting JSON response.
   *
   * <p>This overload emits the response body normally. HEAD requests use the lower-level overload
   * to suppress the body while still reporting the encoded content length.
   *
   * @param method HTTP method name forwarded into the Platform API router
   * @param uri request target supplied by the legacy HTTP shell
   * @param request decoded legacy HTTP request wrapper
   * @param ctx current toadlet context used for access checks and reply writes
   * @throws ToadletContextClosedException if the client disconnects while the reply is being sent
   * @throws IOException if the legacy HTTP shell fails while writing the response
   */
  private void writePlatformApiResponse(
      String method, URI uri, HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    writePlatformApiResponse(method, uri, request, ctx, true);
  }

  /**
   * Routes a request through the Platform API and writes either a full or header-only reply.
   *
   * <p>Legacy HTTP integration keeps host/operator full-access enforcement at the bridge boundary.
   * Mutating host/operator requests then pass through the legacy form-password check before the
   * bridge converts them into a transport-neutral {@link PlatformApiRequest}. App-token and app
   * browser-session requests skip that host/operator form guard and carry a token-free app
   * principal into the router, where manifest capability enforcement happens centrally. Unexpected
   * runtime failures are converted into a structured {@code 500} response so callers keep the
   * Platform API JSON contract even when the bridge logs the underlying error.
   *
   * @param method HTTP method name forwarded into the Platform API router
   * @param uri request target supplied by the legacy HTTP shell
   * @param request decoded legacy HTTP request wrapper
   * @param ctx current toadlet context used for access checks and reply writes
   * @param includeBody {@code true} to send the encoded JSON body, {@code false} for header-only
   *     replies such as HEAD
   * @throws ToadletContextClosedException if the client disconnects while the reply is being sent
   * @throws IOException if the legacy HTTP shell fails while writing the response
   */
  private void writePlatformApiResponse(
      String method, URI uri, HTTPRequest request, ToadletContext ctx, boolean includeBody)
      throws ToadletContextClosedException, IOException {
    PlatformApiResponse response;
    CorsRequest cors = CorsRequest.from(request);
    try {
      response = resolveAndRoutePlatformApiRequest(method, uri, request, ctx, cors);
    } catch (URLEncodedFormatException _) {
      response =
          PlatformApiResponse.error(
              400, "invalid_path", "Request path contains malformed percent-encoding.");
    } catch (PlatformApiException e) {
      response = PlatformApiResponse.error(e.statusCode(), e.errorCode(), e.getMessage());
    } catch (RuntimeException e) {
      LOG.error("Platform API request failed for path {}", requestPath(uri), e);
      response =
          PlatformApiResponse.error(500, "internal_error", "Unexpected platform API failure.");
    }
    if (response == null) {
      return;
    }
    writeJsonReply(ctx, responseWithCors(response, cors), includeBody);
  }

  /**
   * Resolves the request principal, enforces bridge-local host guards, and routes the API request.
   *
   * <p>The caller wraps this method in the Platform API error guard so unexpected failures in token
   * authentication, host access checks, form-password checks, request conversion, or router
   * dispatch all produce the same structured JSON error contract.
   *
   * @param method HTTP method name forwarded into the Platform API router
   * @param uri request target supplied by the legacy HTTP shell
   * @param request decoded legacy HTTP request wrapper
   * @param ctx current toadlet context used for access checks
   * @return Platform API response to write, or {@code null} when a bridge-local guard already wrote
   *     the response
   * @throws ToadletContextClosedException if the client disconnects while a guard response is sent
   * @throws IOException if the legacy HTTP shell fails while writing a guard response
   * @throws URLEncodedFormatException if the request path contains malformed percent-encoding
   */
  private PlatformApiResponse resolveAndRoutePlatformApiRequest(
      String method, URI uri, HTTPRequest request, ToadletContext ctx, CorsRequest cors)
      throws ToadletContextClosedException, IOException, URLEncodedFormatException {
    PrincipalResolution principalResolution = resolvePrincipal(request, cors);
    if (principalResolution.failureResponse() != null) {
      return principalResolution.failureResponse();
    }
    PlatformApiPrincipal principal = principalResolution.principal();

    if (!principal.isApp() && !ctx.isAllowedFullAccess()) {
      return PlatformApiResponse.error(403, "forbidden", "Full access is required.");
    }
    if (!principal.isApp() && !authorizeMutationRequest(method, uri, request, ctx)) {
      return null;
    }

    return router.route(toPlatformApiRequest(method, uri, request, principal));
  }

  /**
   * Returns whether the current request targets one of the mutating app-management routes.
   *
   * <p>The legacy shell only auto-checks form passwords for POST before dispatch. The Platform API
   * bridge keeps full-access checks ahead of password checks and applies the same legacy password
   * guard to every currently supported Platform API mutation or resource-consuming POST family.
   * DELETE remains relevant only for installed-app removal, while the current config,
   * security-levels, updater, content fetch, wizard, queue, peer, and app actions use POST.
   *
   * @param method HTTP method name forwarded into the router
   * @param uri request target supplied by the legacy HTTP shell
   * @return {@code true} when the request must present the legacy form password
   */
  private static boolean requiresFormPassword(String method, URI uri) {
    if (!requiresFormPasswordEligibleMethod(method)) {
      return false;
    }

    List<String> pathSegments = decodeRelativeApiPath(uri);
    if (pathSegments.isEmpty()) {
      return false;
    }
    if ("apps".equals(pathSegments.getFirst())) {
      return requiresAppsFormPassword(method, pathSegments);
    }
    return requiresNonAppFormPassword(method, pathSegments);
  }

  /**
   * Returns whether the current request method participates in the legacy form-password guard.
   *
   * @param method HTTP method name forwarded into the router
   * @return {@code true} when the bridge should inspect the request path for a mutating route
   */
  private static boolean requiresFormPasswordEligibleMethod(String method) {
    return "POST".equals(method)
        || DELETE_METHOD.equals(method)
        || PATCH_METHOD.equals(method)
        || PUT_METHOD.equals(method);
  }

  /**
   * Decodes one relative API path while treating malformed percent-encoding as a non-matching
   * mutation route.
   *
   * @param uri request target supplied by the legacy HTTP shell
   * @return decoded relative API path, or an empty list when decoding fails
   */
  private static List<String> decodeRelativeApiPath(URI uri) {
    try {
      return relativeApiPath(requestPath(uri));
    } catch (URLEncodedFormatException _) {
      return List.of();
    }
  }

  /**
   * Returns whether the current request targets one of the mutating app-management routes.
   *
   * @param method HTTP method name forwarded into the router
   * @param pathSegments decoded path segments beneath the Platform API mount point
   * @return {@code true} when the request must present the legacy form password
   */
  private static boolean requiresAppsFormPassword(String method, List<String> pathSegments) {
    if (DELETE_METHOD.equals(method)) {
      return pathSegments.size() == 2;
    }
    if (pathSegments.size() == 2 && "install".equals(pathSegments.get(1))) {
      return true;
    }
    if ("POST".equals(method)
        && pathSegments.size() == 4
        && UPDATES_SEGMENT.equals(pathSegments.get(2))) {
      return true;
    }
    return pathSegments.size() == 3
        && ("start".equals(pathSegments.get(2))
            || "stop".equals(pathSegments.get(2))
            || "update".equals(pathSegments.get(2)));
  }

  /**
   * Returns whether the current request targets one of the non-app routes protected by the
   * form-password guard.
   *
   * @param method HTTP method name forwarded into the router
   * @param pathSegments decoded path segments beneath the Platform API mount point
   * @return {@code true} when the request must present the legacy form password
   */
  private static boolean requiresNonAppFormPassword(String method, List<String> pathSegments) {
    return requiresQueueFormPassword(method, pathSegments)
        || requiresContentFormPassword(method, pathSegments)
        || requiresPeersFormPassword(method, pathSegments)
        || requiresAppCatalogsFormPassword(method, pathSegments)
        || requiresConfigFormPassword(method, pathSegments)
        || requiresSecurityLevelsFormPassword(method, pathSegments)
        || requiresUpdatesFormPassword(method, pathSegments)
        || requiresAppServicesFormPassword(method, pathSegments)
        || requiresConsentFormPassword(method, pathSegments)
        || requiresOperatorFormPassword(method, pathSegments)
        || requiresIdentityVaultFormPassword(method, pathSegments)
        || requiresTrustGraphFormPassword(method, pathSegments)
        || requiresAlertsFormPassword(method, pathSegments)
        || requiresWizardFormPassword(method, pathSegments);
  }

  private static boolean requiresContentFormPassword(String method, List<String> pathSegments) {
    return "POST".equals(method)
        && pathSegments.size() == 2
        && CONTENT_SEGMENT.equals(pathSegments.getFirst())
        && "fetch".equals(pathSegments.get(1));
  }

  private static boolean requiresIdentityVaultFormPassword(
      String method, List<String> pathSegments) {
    if (pathSegments.isEmpty() || !IDENTITY_VAULT_SEGMENT.equals(pathSegments.getFirst())) {
      return false;
    }
    if ("POST".equals(method)) {
      return pathSegments.size() == 2
          && ("identities".equals(pathSegments.get(1))
              || GRANTS_SEGMENT.equals(pathSegments.get(1)));
    }
    if (PATCH_METHOD.equals(method) || DELETE_METHOD.equals(method)) {
      return pathSegments.size() == 3
          && ("identities".equals(pathSegments.get(1))
              || GRANTS_SEGMENT.equals(pathSegments.get(1)));
    }
    return false;
  }

  private static boolean requiresAppServicesFormPassword(String method, List<String> pathSegments) {
    if (!"POST".equals(method)
        || pathSegments.isEmpty()
        || !APP_SERVICES_SEGMENT.equals(pathSegments.getFirst())) {
      return false;
    }
    if (pathSegments.size() == 2) {
      return GRANT_BUNDLES_SEGMENT.equals(pathSegments.get(1));
    }
    if (pathSegments.size() != 4) {
      return false;
    }
    if (GRANTS_SEGMENT.equals(pathSegments.get(1))) {
      return APPROVE_ACTION.equals(pathSegments.get(3)) || "revoke".equals(pathSegments.get(3));
    }
    return GRANT_BUNDLES_SEGMENT.equals(pathSegments.get(1))
        && (APPROVE_ACTION.equals(pathSegments.get(3))
            || "reject".equals(pathSegments.get(3))
            || "renew".equals(pathSegments.get(3)));
  }

  private static boolean requiresConsentFormPassword(String method, List<String> pathSegments) {
    return "POST".equals(method)
        && pathSegments.size() == 2
        && CONSENT_SEGMENT.equals(pathSegments.getFirst())
        && (APPROVE_ACTION.equals(pathSegments.get(1))
            || "reject".equals(pathSegments.get(1))
            || "defer".equals(pathSegments.get(1))
            || "update-preview".equals(pathSegments.get(1)));
  }

  private static boolean requiresOperatorFormPassword(String method, List<String> pathSegments) {
    if (!"POST".equals(method)
        || pathSegments.size() < 3
        || !OPERATOR_SEGMENT.equals(pathSegments.getFirst())) {
      return false;
    }
    return switch (pathSegments.get(1)) {
      case "app-data" -> requiresOperatorAppDataFormPassword(pathSegments);
      case "recovery" -> requiresOperatorRecoveryFormPassword(pathSegments);
      case "catalog-federation" -> requiresCatalogFederationFormPassword(pathSegments);
      case "apps" -> requiresOperatorAppsFormPassword(pathSegments);
      case "subscriptions" -> requiresOperatorSubscriptionsFormPassword(pathSegments);
      default -> false;
    };
  }

  private static boolean requiresOperatorAppDataFormPassword(List<String> pathSegments) {
    return switch (pathSegments.get(2)) {
      case "backups" -> pathSegments.size() == 3;
      case "restore" ->
          pathSegments.size() == 3
              || (pathSegments.size() == 4 && "plan".equals(pathSegments.get(3)));
      default -> false;
    };
  }

  private static boolean requiresOperatorRecoveryFormPassword(List<String> pathSegments) {
    return pathSegments.size() == 3
        && ("plan".equals(pathSegments.get(2)) || "execute".equals(pathSegments.get(2)));
  }

  private static boolean requiresCatalogFederationFormPassword(List<String> pathSegments) {
    return switch (pathSegments.size()) {
      case 3 -> "discovery".equals(pathSegments.get(2));
      case 4 -> requiresCatalogTrustLifecycleFormPassword(pathSegments.get(3));
      case 5 -> requiresCatalogFederationActionFormPassword(pathSegments);
      default -> false;
    };
  }

  private static boolean requiresCatalogTrustLifecycleFormPassword(String action) {
    return switch (action) {
      case "trust", "suspend", "revoke", REMOVE_ACTION -> true;
      default -> false;
    };
  }

  private static boolean requiresCatalogFederationActionFormPassword(List<String> pathSegments) {
    return ("discovery".equals(pathSegments.get(2)) && "discard".equals(pathSegments.get(4)))
        || ("conflicts".equals(pathSegments.get(2)) && "resolve".equals(pathSegments.get(4)));
  }

  private static boolean requiresOperatorAppsFormPassword(List<String> pathSegments) {
    return pathSegments.size() == 5
        && "catalog-origin".equals(pathSegments.get(3))
        && "switch-preview".equals(pathSegments.get(4));
  }

  private static boolean requiresOperatorSubscriptionsFormPassword(List<String> pathSegments) {
    return pathSegments.size() == 5
        && ("refresh".equals(pathSegments.get(4))
            || "reset-backoff".equals(pathSegments.get(4))
            || "reschedule-now".equals(pathSegments.get(4))
            || "pause".equals(pathSegments.get(4))
            || "resume".equals(pathSegments.get(4)));
  }

  private static boolean requiresTrustGraphFormPassword(String method, List<String> pathSegments) {
    if (pathSegments.isEmpty() || !TRUST_GRAPH_SEGMENT.equals(pathSegments.getFirst())) {
      return false;
    }
    if ("POST".equals(method)) {
      return pathSegments.size() == 2
          && ("anchors".equals(pathSegments.get(1))
              || "import".equals(pathSegments.get(1))
              || "import-uri".equals(pathSegments.get(1)));
    }
    return DELETE_METHOD.equals(method)
        && pathSegments.size() == 3
        && "anchors".equals(pathSegments.get(1));
  }

  /**
   * Returns whether the current request targets a mutating signed app-catalog route.
   *
   * @param method HTTP method name forwarded into the router
   * @param pathSegments decoded path segments beneath the Platform API mount point
   * @return {@code true} when the request must present the legacy form password
   */
  private static boolean requiresAppCatalogsFormPassword(String method, List<String> pathSegments) {
    if (pathSegments.isEmpty() || !APP_CATALOGS_SEGMENT.equals(pathSegments.getFirst())) {
      return false;
    }
    if (DELETE_METHOD.equals(method)) {
      return requiresAppCatalogsDeleteFormPassword(pathSegments);
    }
    if (!"POST".equals(method)) {
      return false;
    }
    return requiresAppCatalogsPostFormPassword(pathSegments);
  }

  private static boolean requiresAppCatalogsDeleteFormPassword(List<String> pathSegments) {
    return pathSegments.size() == 2
        || (pathSegments.size() == 4 && MIRRORS_SEGMENT.equals(pathSegments.get(2)));
  }

  private static boolean requiresAppCatalogsPostFormPassword(List<String> pathSegments) {
    return switch (pathSegments.size()) {
      case 2 -> "add".equals(pathSegments.get(1));
      case 3 ->
          "refresh".equals(pathSegments.get(2)) || MIRRORS_SEGMENT.equals(pathSegments.get(2));
      case 4 -> requiresFourSegmentAppCatalogPostFormPassword(pathSegments);
      case 5 -> requiresAppCatalogInstallOrUpdateFormPassword(pathSegments);
      default -> false;
    };
  }

  private static boolean requiresFourSegmentAppCatalogPostFormPassword(List<String> pathSegments) {
    return ("recommended".equals(pathSegments.get(1)) && "add".equals(pathSegments.get(3)))
        || MIRRORS_SEGMENT.equals(pathSegments.get(2))
        || ("operations".equals(pathSegments.get(2))
            && ("refresh-primary".equals(pathSegments.get(3))
                || "rollback".equals(pathSegments.get(3))
                || "emergency-refresh".equals(pathSegments.get(3))));
  }

  private static boolean requiresAppCatalogInstallOrUpdateFormPassword(List<String> pathSegments) {
    return "apps".equals(pathSegments.get(2))
        && ("install".equals(pathSegments.get(4)) || "update".equals(pathSegments.get(4)));
  }

  /**
   * Returns whether the current request targets one of the mutating queue routes.
   *
   * @param method HTTP method name forwarded into the router
   * @param pathSegments decoded path segments beneath the Platform API mount point
   * @return {@code true} when the request must present the legacy form password
   */
  private static boolean requiresQueueFormPassword(String method, List<String> pathSegments) {
    if (!"POST".equals(method)
        || pathSegments.isEmpty()
        || !QUEUE_SEGMENT.equals(pathSegments.getFirst())) {
      return false;
    }
    if (pathSegments.size() == 2 && "downloads".equals(pathSegments.get(1))) {
      return true;
    }
    if (pathSegments.size() != 3) {
      return false;
    }
    if ("requests".equals(pathSegments.get(1))) {
      return REMOVE_ACTION.equals(pathSegments.get(2))
          || "restart".equals(pathSegments.get(2))
          || "priority".equals(pathSegments.get(2));
    }
    if ("inserts".equals(pathSegments.get(1))) {
      return "file".equals(pathSegments.get(2)) || "directory".equals(pathSegments.get(2));
    }
    return "cleanup".equals(pathSegments.get(1))
        && ("uploads".equals(pathSegments.get(2)) || "downloads".equals(pathSegments.get(2)));
  }

  /**
   * Returns whether the current request targets one of the mutating peer routes.
   *
   * @param method HTTP method name forwarded into the router
   * @param pathSegments decoded path segments beneath the Platform API mount point
   * @return {@code true} when the request must present the legacy form password
   */
  private static boolean requiresPeersFormPassword(String method, List<String> pathSegments) {
    if (!"POST".equals(method)
        || pathSegments.isEmpty()
        || !PEERS_SEGMENT.equals(pathSegments.getFirst())) {
      return false;
    }
    if (pathSegments.size() == 2) {
      return "add".equals(pathSegments.get(1));
    }
    return pathSegments.size() == 3
        && ("settings".equals(pathSegments.get(2))
            || "note".equals(pathSegments.get(2))
            || REMOVE_ACTION.equals(pathSegments.get(2)));
  }

  /**
   * Returns whether the current request targets one of the mutating config routes.
   *
   * @param method HTTP method name forwarded into the router
   * @param pathSegments decoded path segments beneath the Platform API mount point
   * @return {@code true} when the request must present the legacy form password
   */
  private static boolean requiresConfigFormPassword(String method, List<String> pathSegments) {
    return "POST".equals(method)
        && pathSegments.size() == 2
        && CONFIG_SEGMENT.equals(pathSegments.getFirst())
        && ("overrides".equals(pathSegments.get(1)) || "persist".equals(pathSegments.get(1)));
  }

  /**
   * Returns whether the current request targets one of the mutating security-level routes.
   *
   * @param method HTTP method name forwarded into the router
   * @param pathSegments decoded path segments beneath the Platform API mount point
   * @return {@code true} when the request must present the legacy form password
   */
  private static boolean requiresSecurityLevelsFormPassword(
      String method, List<String> pathSegments) {
    return "POST".equals(method)
        && pathSegments.size() == 2
        && SECURITY_LEVELS_SEGMENT.equals(pathSegments.getFirst())
        && ("network".equals(pathSegments.get(1)) || "physical".equals(pathSegments.get(1)));
  }

  /**
   * Returns whether the current request targets the mutating updater download route.
   *
   * @param method HTTP method name forwarded into the router
   * @param pathSegments decoded path segments beneath the Platform API mount point
   * @return {@code true} when the request must present the legacy form password
   */
  private static boolean requiresUpdatesFormPassword(String method, List<String> pathSegments) {
    return "POST".equals(method)
        && pathSegments.size() == 3
        && UPDATES_SEGMENT.equals(pathSegments.getFirst())
        && "core".equals(pathSegments.get(1))
        && "download".equals(pathSegments.get(2));
  }

  /**
   * Returns whether the current request targets the mutating alerts dismissal route.
   *
   * @param method HTTP method name forwarded into the router
   * @param pathSegments decoded path segments beneath the Platform API mount point
   * @return {@code true} when the request must present the legacy form password
   */
  private static boolean requiresAlertsFormPassword(String method, List<String> pathSegments) {
    return "POST".equals(method)
        && pathSegments.size() == 3
        && ALERTS_SEGMENT.equals(pathSegments.getFirst())
        && "dismiss".equals(pathSegments.get(2));
  }

  /**
   * Returns whether the current request targets the mutating first-time-wizard route.
   *
   * @param method HTTP method name forwarded into the router
   * @param pathSegments decoded path segments beneath the Platform API mount point
   * @return {@code true} when the request must present the legacy form password
   */
  private static boolean requiresWizardFormPassword(String method, List<String> pathSegments) {
    return "POST".equals(method)
        && pathSegments.size() == 3
        && WIZARD_SEGMENT.equals(pathSegments.getFirst())
        && "first-time".equals(pathSegments.get(1))
        && "apply".equals(pathSegments.get(2));
  }

  /**
   * Enforces the legacy form-password requirement for mutating requests.
   *
   * <p>The bridge handles failures itself so callers always receive structured JSON {@code 403}
   * responses instead of legacy redirects.
   *
   * @param method HTTP method name forwarded into the router
   * @param uri request target supplied by the legacy HTTP shell
   * @param request decoded legacy HTTP request wrapper
   * @param ctx current toadlet context used for password validation and response writes
   * @return {@code true} when the request is authorized to mutate state
   * @throws ToadletContextClosedException if the client disconnects while an auth failure is sent
   * @throws IOException if the legacy HTTP shell fails while writing the auth failure
   */
  private boolean authorizeMutationRequest(
      String method, URI uri, HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    if (!requiresFormPassword(method, uri)) {
      return true;
    }
    if (ctx.hasFormPassword(request)) {
      return true;
    }
    writeJsonReply(
        ctx, PlatformApiResponse.error(403, "forbidden", "Valid form password is required."), true);
    return false;
  }

  /**
   * Converts legacy HTTP request state into the transport-neutral Platform API request model.
   *
   * <p>Query parameters preserve encounter order and repeated values so the router can apply its
   * own validation without depending on the legacy HTTP request type. The bridge excludes the
   * legacy admin {@code formPassword} from that map. It also lifts scalar form fields from request
   * parts into the same map so the transport-neutral router can handle urlencoded and multipart
   * admin submissions without learning legacy HTTP request details. Uploaded-file bodies stay out
   * of that map because Platform API v1 still treats file transfer payloads as adapter-local
   * concerns.
   *
   * @param method HTTP method name forwarded into the router
   * @param uri request target supplied by the legacy HTTP shell
   * @param request decoded legacy HTTP request wrapper
   * @return immutable Platform API request built from the method, relative path, and query values
   * @throws URLEncodedFormatException if the request path contains malformed percent-encoding
   */
  private PlatformApiRequest toPlatformApiRequest(
      String method, URI uri, HTTPRequest request, PlatformApiPrincipal principal)
      throws URLEncodedFormatException {
    LinkedHashMap<String, List<String>> queryParameters =
        LinkedHashMap.newLinkedHashMap(request.getParameterNames().size());
    for (String parameterName : request.getParameterNames()) {
      if (FORM_PASSWORD_PARAMETER.equals(parameterName)) {
        continue;
      }
      queryParameters.put(parameterName, List.of(request.getMultipleParam(parameterName)));
    }
    copyBodyParametersIfPresent(request, queryParameters);
    return new PlatformApiRequest(
        method, relativeApiPath(requestPath(uri)), queryParameters, principal);
  }

  private PrincipalResolution resolvePrincipal(HTTPRequest request, CorsRequest cors) {
    String directToken = directAppTokenFromHeader(request);
    if (directToken != null) {
      return authenticateExplicitAppToken(directToken);
    }

    String bearerToken = bearerTokenFromAuthorization(request);
    if (bearerToken != null) {
      PrincipalResolution bearerPrincipal = authenticateBearerToken(bearerToken);
      if (bearerPrincipal != null) {
        return bearerPrincipal;
      }
    }

    String browserSessionToken = appSessionFromHeader(request);
    if (browserSessionToken != null) {
      return authenticateBrowserSession(browserSessionToken, cors);
    }
    if (cors.fromRegisteredAppOrigin(appUiOriginRegistry)) {
      cors.allowIfRegistered(cors.origin(), appUiOriginRegistry);
      return unauthenticatedAppBrowserSession(
          "App browser session is required for app-origin Platform API requests.");
    }
    return hostOperatorPrincipal();
  }

  private static PrincipalResolution unauthenticatedAppToken(String message) {
    return new PrincipalResolution(
        null, PlatformApiResponse.error(401, "invalid_app_token", message));
  }

  private static PrincipalResolution unauthenticatedAppBrowserSession(String message) {
    return new PrincipalResolution(
        null, PlatformApiResponse.error(401, "invalid_app_browser_session", message));
  }

  private static PrincipalResolution hostOperatorPrincipal() {
    return new PrincipalResolution(PlatformApiPrincipal.hostOperator(), null);
  }

  /**
   * Authenticates a token from the app-specific header.
   *
   * <p>{@code X-Crypta-App-Token} is an explicit app-token assertion, so blank, stale, unknown, or
   * unavailable token validation returns a structured authentication failure.
   *
   * @param token token value after header normalization
   * @return app principal for a live token, or an authentication failure response
   */
  private PrincipalResolution authenticateExplicitAppToken(String token) {
    if (appHost == null) {
      return unauthenticatedAppToken("App token authentication is unavailable.");
    }
    Optional<AppTokenPrincipal> appPrincipal = appHost.authenticateLaunchToken(token);
    return appPrincipal
        .map(PlatformApiToadlet::appTokenPrincipal)
        .orElseGet(() -> unauthenticatedAppToken("Invalid app token."));
  }

  /**
   * Authenticates a Bearer token when it matches a live app token.
   *
   * <p>{@code Authorization: Bearer} is intentionally opportunistic because the same header is also
   * used by reverse proxies and shared HTTP client configurations for unrelated host/operator
   * credentials. A matching live AppHost token becomes an app principal. A non-matching Bearer
   * value does not immediately become host/operator because the request may also carry an explicit
   * app browser session. After that session gets a chance to authenticate, unmatched Bearer values
   * keep the existing host/operator path instead of converting the request into a failed app-token
   * attempt. Lookup failures are allowed to propagate to the guarded Platform API error path so a
   * token-bearing request cannot silently widen into a host/operator principal when AppHost state
   * is unavailable.
   *
   * @param token bearer token value after header normalization
   * @return app principal for a live token, otherwise {@code null}
   */
  private PrincipalResolution authenticateBearerToken(String token) {
    if (appHost == null) {
      return null;
    }
    Optional<AppTokenPrincipal> appPrincipal = appHost.authenticateLaunchToken(token);
    return appPrincipal.map(PlatformApiToadlet::appTokenPrincipal).orElse(null);
  }

  private static PrincipalResolution appTokenPrincipal(AppTokenPrincipal principal) {
    return new PrincipalResolution(
        PlatformApiPrincipal.appToken(
            principal.appId(), principal.permissions(), principal.launchId()),
        null);
  }

  private PrincipalResolution authenticateBrowserSession(String token, CorsRequest cors) {
    if (appBrowserSessionVerifier == null) {
      return unauthenticatedAppBrowserSession("App browser session authentication is unavailable.");
    }
    Optional<AppBrowserSession> session = appBrowserSessionVerifier.verify(token);
    if (session.isEmpty()) {
      cors.allowIfRegistered(cors.origin(), appUiOriginRegistry);
      return unauthenticatedAppBrowserSession("Invalid app browser session.");
    }
    return session
        .map(value -> appBrowserSessionPrincipal(value, cors))
        .orElseGet(() -> unauthenticatedAppBrowserSession("Invalid app browser session."));
  }

  private PrincipalResolution appBrowserSessionPrincipal(
      AppBrowserSession session, CorsRequest cors) {
    PrincipalResolution originFailure = validateBrowserSessionOrigin(session, cors);
    if (originFailure != null) {
      return originFailure;
    }
    cors.allowIfRegistered(session.expectedOrigin(), appUiOriginRegistry);
    return new PrincipalResolution(
        PlatformApiPrincipal.appBrowserSession(
            session.appId(), session.permissions(), session.expectedOrigin(), session.originMode()),
        null);
  }

  private PrincipalResolution validateBrowserSessionOrigin(
      AppBrowserSession session, CorsRequest cors) {
    if (session.originMode() == AppUiOriginMode.ISOLATED_LOOPBACK) {
      if (requestOriginDiffersFromSession(session, cors)) {
        cors.allowIfRegistered(cors.origin(), appUiOriginRegistry);
        return originMismatch("App browser session origin does not match the request origin.");
      }
      Optional<AppUiOriginBinding> binding = appUiOriginRegistry.bindingForOrigin(cors.origin());
      if (binding.isEmpty()
          || !binding.get().appId().equals(session.appId())
          || !binding.get().isolatedAndActive()) {
        cors.allowIfRegistered(cors.origin(), appUiOriginRegistry);
        return originMismatch("App browser origin is not currently registered for this app.");
      }
      return null;
    }
    if (cors.fromRegisteredAppOrigin(appUiOriginRegistry)) {
      cors.allowIfRegistered(cors.origin(), appUiOriginRegistry);
      return originMismatch(
          "Same-origin fallback app browser session cannot be used from an isolated app origin.");
    }
    if (requestOriginConflictsWithFallbackSession(session, cors)) {
      cors.allowIfRegistered(cors.origin(), appUiOriginRegistry);
      return originMismatch("App browser session origin does not match the request origin.");
    }
    return null;
  }

  private static boolean requestOriginDiffersFromSession(
      AppBrowserSession session, CorsRequest cors) {
    return cors.origin() == null || !cors.origin().equals(session.expectedOrigin());
  }

  private static boolean requestOriginConflictsWithFallbackSession(
      AppBrowserSession session, CorsRequest cors) {
    return cors.origin() != null
        && session.expectedOrigin() != null
        && requestOriginDiffersFromSession(session, cors);
  }

  private static PrincipalResolution originMismatch(String message) {
    return new PrincipalResolution(
        null, PlatformApiResponse.error(403, "origin_mismatch", message));
  }

  private static String directAppTokenFromHeader(HTTPRequest request) {
    String directToken = request.getHeader(APP_TOKEN_HEADER);
    return directToken == null ? null : directToken.trim();
  }

  private static String appSessionFromHeader(HTTPRequest request) {
    String token = request.getHeader(APP_SESSION_HEADER);
    return token == null ? null : token.trim();
  }

  private static String bearerTokenFromAuthorization(HTTPRequest request) {
    String authorization = request.getHeader(AUTHORIZATION_HEADER);
    if (authorization == null) {
      return null;
    }
    String trimmed = authorization.trim();
    if (trimmed.length() < BEARER_PREFIX.length()
        || !trimmed.regionMatches(true, 0, BEARER_PREFIX, 0, BEARER_PREFIX.length())) {
      return null;
    }
    if (trimmed.length() == BEARER_PREFIX.length()) {
      return "";
    }
    if (!Character.isWhitespace(trimmed.charAt(BEARER_PREFIX.length()))) {
      return null;
    }
    return trimmed.substring(BEARER_PREFIX.length()).trim();
  }

  private record PrincipalResolution(
      PlatformApiPrincipal principal, PlatformApiResponse failureResponse) {}

  /**
   * Copies body-backed form values into the query-like parameter map when present.
   *
   * <p>This keeps the bridge compatible with legacy-authenticated form submissions while preserving
   * the transport-neutral request model expected by the Platform API router. Existing query-string
   * values win when the same name appears in both places. Urlencoded bodies are reparsed from the
   * raw payload so repeated values survive intact; multipart uploads continue to use scalar parts,
   * with uploaded-file bodies skipped because the Platform API request model is still text-only in
   * this phase.
   *
   * @param request decoded legacy HTTP request wrapper
   * @param queryParameters query-like parameter map being assembled for the router
   */
  private static void copyBodyParametersIfPresent(
      HTTPRequest request, Map<String, List<String>> queryParameters) {
    Bucket rawData = request.getRawData();
    if (rawData == null) {
      return;
    }
    if (isUrlEncodedBodyRequest(request)) {
      mergeUrlEncodedBodyParameters(rawData, queryParameters);
      return;
    }
    copyScalarFormPartsIfPresent(request, queryParameters);
  }

  private static boolean isUrlEncodedBodyRequest(HTTPRequest request) {
    String contentType = request.getHeader("content-type");
    return contentType != null
        && contentType.regionMatches(
            true, 0, URL_ENCODED_CONTENT_TYPE, 0, URL_ENCODED_CONTENT_TYPE.length());
  }

  private static void mergeUrlEncodedBodyParameters(
      Bucket rawData, Map<String, List<String>> queryParameters) {
    if (rawData.size() > MAX_URL_ENCODED_BODY_LENGTH) {
      throw new PlatformApiException(
          400, "invalid_request_body", "URL-encoded request body exceeds the 1048576 byte limit.");
    }
    Map<String, List<String>> bodyParameters;
    try (var input = rawData.getInputStream()) {
      if (input == null) {
        return;
      }
      String body = new String(input.readAllBytes(), StandardCharsets.US_ASCII);
      bodyParameters = HTTPRequestImpl.parseUriParameters(body, true);
    } catch (IOException e) {
      throw new IllegalStateException("Failed to read Platform API form body.", e);
    }
    for (Map.Entry<String, List<String>> entry : bodyParameters.entrySet()) {
      if (FORM_PASSWORD_PARAMETER.equals(entry.getKey())
          || queryParameters.containsKey(entry.getKey())) {
        continue;
      }
      queryParameters.put(entry.getKey(), List.copyOf(entry.getValue()));
    }
  }

  private static void copyScalarFormPartsIfPresent(
      HTTPRequest request, Map<String, List<String>> queryParameters) {
    String[] partNames = request.getParts();
    if (partNames == null) {
      return;
    }
    for (String partName : partNames) {
      if (FORM_PASSWORD_PARAMETER.equals(partName)
          || queryParameters.containsKey(partName)
          || request.getUploadedFile(partName) != null) {
        continue;
      }
      queryParameters.put(
          partName,
          List.of(request.getPartAsStringFailsafe(partName, MAX_PLATFORM_API_FORM_FIELD_LENGTH)));
    }
  }

  /**
   * Splits the mounted request path into decoded Platform API path segments.
   *
   * <p>The bridge trims the API mount prefix, preserves encoded slashes until segment boundaries
   * are determined, and then decodes each segment independently. That allows peer identifiers and
   * similar values to contain {@code /} when they were percent-encoded in the incoming request.
   *
   * @param requestPath raw request path as received from the URI before query parsing
   * @return immutable list of decoded path segments relative to {@link #MOUNT_PATH}
   * @throws URLEncodedFormatException if any segment contains malformed percent-encoding
   */
  private static List<String> relativeApiPath(String requestPath) throws URLEncodedFormatException {
    String relativePath = requestPath;
    if (requestPath.startsWith(MOUNT_PATH)) {
      relativePath = requestPath.substring(MOUNT_PATH.length());
    } else {
      String withoutTrailingSlash = MOUNT_PATH.substring(0, MOUNT_PATH.length() - 1);
      if (requestPath.equals(withoutTrailingSlash)) {
        relativePath = "";
      }
    }
    if (relativePath.isEmpty()) {
      return List.of();
    }
    List<String> pathSegments = new ArrayList<>();
    int segmentStart = 0;
    while (segmentStart < relativePath.length()) {
      int nextSeparator = relativePath.indexOf('/', segmentStart);
      String segment =
          nextSeparator >= 0
              ? relativePath.substring(segmentStart, nextSeparator)
              : relativePath.substring(segmentStart);
      if (!segment.isEmpty()) {
        pathSegments.add(URLDecoder.decode(segment, false));
      }
      if (nextSeparator < 0) {
        break;
      }
      segmentStart = nextSeparator + 1;
    }
    return List.copyOf(pathSegments);
  }

  /**
   * Returns the raw request path when available so encoded path separators remain intact.
   *
   * @param uri request target supplied by the legacy HTTP shell
   * @return raw path if present, otherwise the decoded URI path as a fallback
   */
  private static String requestPath(URI uri) {
    String rawPath = uri.getRawPath();
    return rawPath != null ? rawPath : uri.getPath();
  }

  private void writeCorsPreflightResponse(CorsRequest cors, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    if (!cors.preflightAllowed(appUiOriginRegistry)) {
      writeJsonReply(
          ctx,
          PlatformApiResponse.error(
              403, "origin_mismatch", "App browser origin is not allowed for Platform API CORS."),
          true);
      return;
    }
    MultiValueTable<String, String> headers = new MultiValueTable<>();
    addCorsHeaders(headers, cors.origin());
    headers.put(ACCESS_CONTROL_MAX_AGE_HEADER, "600");
    ctx.sendReplyHeaders(204, "No Content", headers, null, 0L, true);
  }

  private static PlatformApiResponse responseWithCors(
      PlatformApiResponse response, CorsRequest cors) {
    if (cors.allowedResponseOrigin() == null) {
      return response;
    }
    LinkedHashMap<String, String> headers =
        LinkedHashMap.newLinkedHashMap(response.headers().size() + 3);
    headers.putAll(response.headers());
    headers.put(ACCESS_CONTROL_ALLOW_ORIGIN_HEADER, cors.allowedResponseOrigin());
    headers.put(VARY_HEADER, "Origin");
    return new PlatformApiResponse(
        response.statusCode(), response.reasonPhrase(), headers, response.body());
  }

  private static void addCorsHeaders(MultiValueTable<String, String> headers, String origin) {
    headers.put(ACCESS_CONTROL_ALLOW_ORIGIN_HEADER, origin);
    headers.put(VARY_HEADER, CORS_VARY_VALUE);
    headers.put(ACCESS_CONTROL_ALLOW_METHODS_HEADER, ALLOWED_CORS_METHODS);
    headers.put(ACCESS_CONTROL_ALLOW_HEADERS_HEADER, ALLOWED_CORS_HEADERS);
  }

  /**
   * Writes the Platform API response back through the legacy HTTP shell.
   *
   * <p>The bridge preserves router-supplied headers such as {@code Allow} and always advertises the
   * Platform API JSON media type. HEAD responses suppress the body while still reporting the
   * encoded byte length so clients can probe the endpoint without downloading the payload.
   *
   * @param ctx the current toadlet context used to send headers and body bytes
   * @param response transport-neutral Platform API response returned by the router
   * @param includeBody {@code true} to send the encoded JSON body, {@code false} for header-only
   *     replies
   * @throws ToadletContextClosedException if the client disconnects while the reply is being sent
   * @throws IOException if the legacy HTTP shell fails while writing the response
   */
  private void writeJsonReply(ToadletContext ctx, PlatformApiResponse response, boolean includeBody)
      throws ToadletContextClosedException, IOException {
    MultiValueTable<String, String> headers = null;
    if (!response.headers().isEmpty()) {
      headers = new MultiValueTable<>();
      response.headers().forEach(headers::put);
    }
    ReplyHeaders replyHeaders =
        ReplyHeaders.of(response.statusCode(), response.reasonPhrase(), JSON_CONTENT_TYPE, headers);
    if (includeBody) {
      writeReply(ctx, replyHeaders, response.body());
      return;
    }

    byte[] body = response.body().getBytes(StandardCharsets.UTF_8);
    ctx.sendReplyHeaders(
        replyHeaders.code(),
        replyHeaders.description(),
        replyHeaders.headers(),
        replyHeaders.mimeType(),
        body.length);
  }

  private static final class CorsRequest {
    private final String origin;
    private final String requestedMethod;
    private final String requestedHeaders;
    private String allowedResponseOrigin;

    private CorsRequest(String origin, String requestedMethod, String requestedHeaders) {
      this.origin = normalizedHeader(origin);
      this.requestedMethod = normalizedHeader(requestedMethod);
      this.requestedHeaders = normalizedHeader(requestedHeaders);
    }

    private static CorsRequest from(HTTPRequest request) {
      return new CorsRequest(
          request.getHeader(ORIGIN_HEADER),
          request.getHeader(ACCESS_CONTROL_REQUEST_METHOD_HEADER),
          request.getHeader(ACCESS_CONTROL_REQUEST_HEADERS_HEADER));
    }

    private String origin() {
      return origin;
    }

    private String allowedResponseOrigin() {
      return allowedResponseOrigin;
    }

    private boolean preflight() {
      return origin != null && requestedMethod != null;
    }

    private boolean preflightAllowed(AppUiOriginRegistry registry) {
      return registry.isRegisteredOrigin(origin)
          && allowedCorsMethod(requestedMethod)
          && allowedCorsHeaders(requestedHeaders);
    }

    private boolean fromRegisteredAppOrigin(AppUiOriginRegistry registry) {
      return origin != null && registry.isRegisteredOrigin(origin);
    }

    private void allowIfRegistered(String expectedOrigin, AppUiOriginRegistry registry) {
      if (origin == null
          || !origin.equals(expectedOrigin)
          || !registry.isRegisteredOrigin(origin)) {
        return;
      }
      allowedResponseOrigin = origin;
    }

    private static boolean allowedCorsMethod(String method) {
      return "GET".equalsIgnoreCase(method)
          || "POST".equalsIgnoreCase(method)
          || PUT_METHOD.equalsIgnoreCase(method)
          || PATCH_METHOD.equalsIgnoreCase(method)
          || DELETE_METHOD.equalsIgnoreCase(method);
    }

    private static boolean allowedCorsHeaders(String requestedHeaders) {
      if (requestedHeaders == null || requestedHeaders.isBlank()) {
        return true;
      }
      int start = 0;
      while (start <= requestedHeaders.length()) {
        int comma = requestedHeaders.indexOf(',', start);
        String normalized =
            (comma < 0
                    ? requestedHeaders.substring(start)
                    : requestedHeaders.substring(start, comma))
                .trim();
        if (!normalized.isEmpty() && !allowedCorsHeader(normalized)) {
          return false;
        }
        if (comma < 0) {
          break;
        }
        start = comma + 1;
      }
      return true;
    }

    private static boolean allowedCorsHeader(String header) {
      return APP_SESSION_HEADER.equalsIgnoreCase(header)
          || "accept".equalsIgnoreCase(header)
          || "content-type".equalsIgnoreCase(header);
    }

    private static String normalizedHeader(String value) {
      if (value == null || value.isBlank()) {
        return null;
      }
      return value.trim();
    }
  }
}
