package network.crypta.clients.http;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import network.crypta.platform.api.PlatformApiAuthSource;
import network.crypta.platform.api.PlatformApiPrincipalType;
import network.crypta.platform.api.PlatformApiRequest;
import network.crypta.platform.api.PlatformApiResponse;
import network.crypta.platform.api.PlatformApiRouter;
import network.crypta.platform.apphost.AppHost;
import network.crypta.platform.apphost.AppTokenPrincipal;
import network.crypta.platform.appui.AppBrowserSession;
import network.crypta.platform.appui.AppBrowserSessionVerifier;
import network.crypta.platform.appui.AppUiOriginBinding;
import network.crypta.platform.appui.AppUiOriginMode;
import network.crypta.platform.appui.AppUiOriginRegistry;
import network.crypta.platform.appui.AppUiOriginStatus;
import network.crypta.support.MultiValueTable;
import network.crypta.support.SimpleReadOnlyArrayBucket;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.HTTPRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PlatformApiToadletTest {

  @Mock private PlatformApiRouter router;
  @Mock private AppHost appHost;
  @Mock private AppBrowserSessionVerifier appBrowserSessionVerifier;
  @Mock private ToadletContext ctx;
  @Mock private HTTPRequest request;
  @Mock private Bucket requestBody;

  private PlatformApiToadlet toadlet;

  @BeforeEach
  void setUp() {
    toadlet = new PlatformApiToadlet(router);
    lenient().when(request.getHeader("x-crypta-app-token")).thenReturn(null);
    lenient().when(request.getHeader("x-crypta-app-session")).thenReturn(null);
    lenient().when(request.getHeader("authorization")).thenReturn(null);
    lenient().when(request.getHeader("origin")).thenReturn(null);
    lenient().when(request.getHeader("access-control-request-method")).thenReturn(null);
    lenient().when(request.getHeader("access-control-request-headers")).thenReturn(null);
  }

  @Test
  void handleMethodGET_whenAppTokenHeaderAuthenticates_routesAppPrincipalRequest()
      throws Exception {
    toadlet = new PlatformApiToadlet(router, appHost);
    when(request.getHeader("x-crypta-app-token")).thenReturn("secret-token");
    when(appHost.authenticateLaunchToken("secret-token"))
        .thenReturn(Optional.of(new AppTokenPrincipal("alpha", List.of("queue.read"))));
    when(request.getParameterNames()).thenReturn(List.of());
    when(router.route(any(PlatformApiRequest.class)))
        .thenReturn(PlatformApiResponse.ok(Map.of("ok", true)));

    toadlet.handleMethodGET(URI.create("http://localhost/api/v1/queue"), request, ctx);

    ArgumentCaptor<PlatformApiRequest> captor = ArgumentCaptor.forClass(PlatformApiRequest.class);
    verify(router).route(captor.capture());
    assertEquals("alpha", captor.getValue().principal().appId());
    assertEquals(List.of("queue.read"), captor.getValue().principal().permissions());
    verify(ctx, never()).isAllowedFullAccess();
  }

  @Test
  void handleMethodGET_whenBearerTokenAuthenticates_routesAppPrincipalRequest() throws Exception {
    toadlet = new PlatformApiToadlet(router, appHost);
    when(request.getHeader("authorization")).thenReturn("Bearer secret-token");
    when(appHost.authenticateLaunchToken("secret-token"))
        .thenReturn(Optional.of(new AppTokenPrincipal("alpha", List.of("node.read"))));
    when(request.getParameterNames()).thenReturn(List.of());
    when(router.route(any(PlatformApiRequest.class)))
        .thenReturn(PlatformApiResponse.ok(Map.of("ok", true)));

    toadlet.handleMethodGET(URI.create("http://localhost/api/v1/node/greeting"), request, ctx);

    ArgumentCaptor<PlatformApiRequest> captor = ArgumentCaptor.forClass(PlatformApiRequest.class);
    verify(router).route(captor.capture());
    assertEquals("alpha", captor.getValue().principal().appId());
    assertEquals(List.of("node.read"), captor.getValue().principal().permissions());
  }

  @Test
  void handleMethodGET_whenBearerTokenAndBrowserSessionProvided_routesProcessTokenPrincipal()
      throws Exception {
    toadlet = new PlatformApiToadlet(router, appHost, appBrowserSessionVerifier);
    when(request.getHeader("authorization")).thenReturn("Bearer process-token");
    lenient().when(request.getHeader("x-crypta-app-session")).thenReturn("browser-session");
    when(appHost.authenticateLaunchToken("process-token"))
        .thenReturn(Optional.of(new AppTokenPrincipal("alpha", List.of("node.read"))));
    when(request.getParameterNames()).thenReturn(List.of());
    when(router.route(any(PlatformApiRequest.class)))
        .thenReturn(PlatformApiResponse.ok(Map.of("ok", true)));

    toadlet.handleMethodGET(URI.create("http://localhost/api/v1/node/greeting"), request, ctx);

    ArgumentCaptor<PlatformApiRequest> captor = ArgumentCaptor.forClass(PlatformApiRequest.class);
    verify(router).route(captor.capture());
    assertEquals(PlatformApiPrincipalType.APP, captor.getValue().principal().type());
    assertEquals(PlatformApiAuthSource.APP_TOKEN, captor.getValue().principal().authSource());
    assertEquals("alpha", captor.getValue().principal().appId());
    verifyNoInteractions(appBrowserSessionVerifier);
  }

  @Test
  void handleMethodGET_whenBearerTokenDoesNotAuthenticate_routesHostOperatorRequest()
      throws Exception {
    toadlet = new PlatformApiToadlet(router, appHost);
    when(request.getHeader("authorization")).thenReturn("Bearer proxy-token");
    when(appHost.authenticateLaunchToken("proxy-token")).thenReturn(Optional.empty());
    when(ctx.isAllowedFullAccess()).thenReturn(true);
    when(request.getParameterNames()).thenReturn(List.of());
    when(router.route(any(PlatformApiRequest.class)))
        .thenReturn(PlatformApiResponse.ok(Map.of("ok", true)));

    toadlet.handleMethodGET(URI.create("http://localhost/api/v1/node/greeting"), request, ctx);

    ArgumentCaptor<PlatformApiRequest> captor = ArgumentCaptor.forClass(PlatformApiRequest.class);
    verify(router).route(captor.capture());
    assertEquals("HOST_OPERATOR", captor.getValue().principal().type().name());
    verify(ctx).isAllowedFullAccess();
  }

  @Test
  void handleMethodGET_whenAppBrowserSessionHeaderAuthenticates_routesBrowserPrincipalRequest()
      throws Exception {
    toadlet = new PlatformApiToadlet(router, appHost, appBrowserSessionVerifier);
    when(request.getHeader("x-crypta-app-session")).thenReturn("browser-session");
    when(appBrowserSessionVerifier.verify("browser-session"))
        .thenReturn(Optional.of(alphaBrowserSession(List.of("queue.read"))));
    when(request.getParameterNames()).thenReturn(List.of());
    when(router.route(any(PlatformApiRequest.class)))
        .thenReturn(PlatformApiResponse.ok(Map.of("ok", true)));

    toadlet.handleMethodGET(URI.create("http://localhost/api/v1/queue"), request, ctx);

    ArgumentCaptor<PlatformApiRequest> captor = ArgumentCaptor.forClass(PlatformApiRequest.class);
    verify(router).route(captor.capture());
    assertEquals(PlatformApiPrincipalType.APP_BROWSER, captor.getValue().principal().type());
    assertEquals(
        PlatformApiAuthSource.APP_BROWSER_SESSION, captor.getValue().principal().authSource());
    assertEquals("alpha", captor.getValue().principal().appId());
    assertEquals(List.of("queue.read"), captor.getValue().principal().permissions());
    verify(ctx, never()).isAllowedFullAccess();
  }

  @Test
  void handleMethodGET_whenOriginBoundAppSessionMatchesRegisteredOrigin_expectCorsPrincipal()
      throws Exception {
    AppUiOriginBinding binding = isolatedBinding("alpha", 12345);
    toadlet =
        new PlatformApiToadlet(router, appHost, appBrowserSessionVerifier, registryWith(binding));
    when(request.getHeader("origin")).thenReturn(binding.origin());
    when(request.getHeader("x-crypta-app-session")).thenReturn("browser-session");
    when(appBrowserSessionVerifier.verify("browser-session"))
        .thenReturn(Optional.of(alphaBrowserSession(List.of("queue.read"), binding.origin())));
    when(request.getParameterNames()).thenReturn(List.of());
    when(router.route(any(PlatformApiRequest.class)))
        .thenReturn(PlatformApiResponse.ok(Map.of("ok", true)));

    toadlet.handleMethodGET(URI.create("http://localhost/api/v1/queue"), request, ctx);

    ArgumentCaptor<PlatformApiRequest> captor = ArgumentCaptor.forClass(PlatformApiRequest.class);
    verify(router).route(captor.capture());
    assertEquals(PlatformApiPrincipalType.APP_BROWSER, captor.getValue().principal().type());
    assertEquals(binding.origin(), captor.getValue().principal().expectedOrigin());
    assertEquals(AppUiOriginMode.ISOLATED_LOOPBACK, captor.getValue().principal().originMode());
    ReplyHeadersCapture replyHeaders = captureReplyHeaders();
    assertEquals(binding.origin(), replyHeaders.headers().getFirst("Access-Control-Allow-Origin"));
    assertEquals("Origin", replyHeaders.headers().getFirst("Vary"));
    verify(ctx, never()).isAllowedFullAccess();
  }

  @Test
  void handleMethodGET_whenOriginBoundAppSessionMismatchesOrigin_expect403WithCors()
      throws Exception {
    AppUiOriginBinding alphaBinding = isolatedBinding("alpha", 12345);
    AppUiOriginBinding betaBinding = isolatedBinding("beta", 12346);
    toadlet =
        new PlatformApiToadlet(
            router, appHost, appBrowserSessionVerifier, registryWith(alphaBinding, betaBinding));
    when(request.getHeader("origin")).thenReturn(betaBinding.origin());
    when(request.getHeader("x-crypta-app-session")).thenReturn("browser-session");
    when(appBrowserSessionVerifier.verify("browser-session"))
        .thenReturn(Optional.of(alphaBrowserSession(List.of("queue.read"), alphaBinding.origin())));

    toadlet.handleMethodGET(URI.create("http://localhost/api/v1/queue"), request, ctx);

    verifyNoInteractions(router);
    ReplyHeadersCapture replyHeaders = captureReplyHeaders();
    assertEquals(403, replyHeaders.statusCode());
    assertEquals(
        betaBinding.origin(), replyHeaders.headers().getFirst("Access-Control-Allow-Origin"));
    BodyWriteCapture bodyWrite = captureBodyWrite();
    assertEquals(
        "{\"error\":{\"code\":\"origin_mismatch\",\"message\":\"App browser session origin does"
            + " not match the request origin.\"}}",
        bodyWrite.bodyText());
    verify(ctx, never()).isAllowedFullAccess();
  }

  @Test
  void handleMethodGET_whenFallbackSessionUsedFromRegisteredAppOrigin_expect403WithCors()
      throws Exception {
    AppUiOriginBinding binding = isolatedBinding("alpha", 12345);
    toadlet =
        new PlatformApiToadlet(router, appHost, appBrowserSessionVerifier, registryWith(binding));
    when(request.getHeader("origin")).thenReturn(binding.origin());
    when(request.getHeader("x-crypta-app-session")).thenReturn("browser-session");
    when(appBrowserSessionVerifier.verify("browser-session"))
        .thenReturn(Optional.of(alphaBrowserSession(List.of("queue.read"))));

    toadlet.handleMethodGET(URI.create("http://localhost/api/v1/queue"), request, ctx);

    verifyNoInteractions(router);
    ReplyHeadersCapture replyHeaders = captureReplyHeaders();
    assertEquals(403, replyHeaders.statusCode());
    assertEquals(binding.origin(), replyHeaders.headers().getFirst("Access-Control-Allow-Origin"));
    BodyWriteCapture bodyWrite = captureBodyWrite();
    assertEquals(
        "{\"error\":{\"code\":\"origin_mismatch\",\"message\":\"Same-origin fallback app browser"
            + " session cannot be used from an isolated app origin.\"}}",
        bodyWrite.bodyText());
    verify(ctx, never()).isAllowedFullAccess();
  }

  @Test
  void handleMethodGET_whenRegisteredAppOriginOmitsSession_expect401WithoutHostFallback()
      throws Exception {
    AppUiOriginBinding binding = isolatedBinding("alpha", 12345);
    toadlet =
        new PlatformApiToadlet(router, appHost, appBrowserSessionVerifier, registryWith(binding));
    when(request.getHeader("origin")).thenReturn(binding.origin());

    toadlet.handleMethodGET(URI.create("http://localhost/api/v1/queue"), request, ctx);

    verifyNoInteractions(router);
    ReplyHeadersCapture replyHeaders = captureReplyHeaders();
    assertEquals(401, replyHeaders.statusCode());
    assertEquals(binding.origin(), replyHeaders.headers().getFirst("Access-Control-Allow-Origin"));
    BodyWriteCapture bodyWrite = captureBodyWrite();
    assertEquals(
        "{\"error\":{\"code\":\"invalid_app_browser_session\",\"message\":\"App browser session"
            + " is required for app-origin Platform API requests.\"}}",
        bodyWrite.bodyText());
    verify(ctx, never()).isAllowedFullAccess();
  }

  @Test
  void handleMethodPOST_whenAppBrowserSessionAndUnrelatedBearer_routesBrowserPrincipalRequest()
      throws Exception {
    toadlet = new PlatformApiToadlet(router, appHost, appBrowserSessionVerifier);
    when(request.getHeader("authorization")).thenReturn("Bearer proxy-token");
    when(request.getHeader("x-crypta-app-session")).thenReturn("browser-session");
    when(appHost.authenticateLaunchToken("proxy-token")).thenReturn(Optional.empty());
    when(appBrowserSessionVerifier.verify("browser-session"))
        .thenReturn(Optional.of(alphaBrowserSession(List.of("queue.write"))));
    when(request.getParameterNames()).thenReturn(List.of("identifier"));
    when(request.getMultipleParam("identifier")).thenReturn(new String[] {"download-1"});
    when(router.route(any(PlatformApiRequest.class))).thenReturn(PlatformApiResponse.ok(Map.of()));

    toadlet.handleMethodPOST(
        URI.create("http://localhost/api/v1/queue/requests/remove"), request, ctx);

    ArgumentCaptor<PlatformApiRequest> captor = ArgumentCaptor.forClass(PlatformApiRequest.class);
    verify(router).route(captor.capture());
    assertEquals(PlatformApiPrincipalType.APP_BROWSER, captor.getValue().principal().type());
    assertEquals(
        PlatformApiAuthSource.APP_BROWSER_SESSION, captor.getValue().principal().authSource());
    assertEquals("alpha", captor.getValue().principal().appId());
    assertEquals(List.of("queue.write"), captor.getValue().principal().permissions());
    verify(ctx, never()).isAllowedFullAccess();
    verify(ctx, never()).hasFormPassword(request);
  }

  @Test
  void handleMethodGET_whenAppBrowserSessionInvalid_expect401WithoutTokenLeak() throws Exception {
    toadlet = new PlatformApiToadlet(router, appHost, appBrowserSessionVerifier);
    when(request.getHeader("x-crypta-app-session")).thenReturn("browser-session");
    when(appBrowserSessionVerifier.verify("browser-session")).thenReturn(Optional.empty());

    toadlet.handleMethodGET(URI.create("http://localhost/api/v1/queue"), request, ctx);

    verifyNoInteractions(router);
    verify(ctx, never()).isAllowedFullAccess();
    ReplyHeadersCapture replyHeaders = captureReplyHeaders();
    assertEquals(401, replyHeaders.statusCode());
    assertEquals("Unauthorized", replyHeaders.reasonPhrase());
    BodyWriteCapture bodyWrite = captureBodyWrite();
    assertEquals(
        "{\"error\":{\"code\":\"invalid_app_browser_session\",\"message\":\"Invalid app browser"
            + " session.\"}}",
        bodyWrite.bodyText());
    assertFalse(bodyWrite.bodyText().contains("browser-session"));
  }

  @Test
  void handleMethodGET_whenAppBrowserSessionVerifierUnavailable_expect401WithoutHostFallback()
      throws Exception {
    when(request.getHeader("x-crypta-app-session")).thenReturn("browser-session");

    toadlet.handleMethodGET(URI.create("http://localhost/api/v1/queue"), request, ctx);

    verifyNoInteractions(router);
    verify(ctx, never()).isAllowedFullAccess();
    ReplyHeadersCapture replyHeaders = captureReplyHeaders();
    assertEquals(401, replyHeaders.statusCode());
    BodyWriteCapture bodyWrite = captureBodyWrite();
    assertEquals(
        "{\"error\":{\"code\":\"invalid_app_browser_session\",\"message\":\"App browser session"
            + " authentication is unavailable.\"}}",
        bodyWrite.bodyText());
    assertFalse(bodyWrite.bodyText().contains("browser-session"));
  }

  @Test
  void handleMethodPOST_whenAppBrowserSessionAuthenticates_skipsHostFormPassword()
      throws Exception {
    toadlet = new PlatformApiToadlet(router, appHost, appBrowserSessionVerifier);
    when(request.getHeader("x-crypta-app-session")).thenReturn("browser-session");
    when(appBrowserSessionVerifier.verify("browser-session"))
        .thenReturn(Optional.of(alphaBrowserSession(List.of("queue.write"))));
    when(request.getParameterNames()).thenReturn(List.of("identifier"));
    when(request.getMultipleParam("identifier")).thenReturn(new String[] {"download-1"});
    when(router.route(any(PlatformApiRequest.class))).thenReturn(PlatformApiResponse.ok(Map.of()));

    toadlet.handleMethodPOST(
        URI.create("http://localhost/api/v1/queue/requests/remove"), request, ctx);

    ArgumentCaptor<PlatformApiRequest> captor = ArgumentCaptor.forClass(PlatformApiRequest.class);
    verify(router).route(captor.capture());
    assertEquals(PlatformApiPrincipalType.APP_BROWSER, captor.getValue().principal().type());
    assertEquals(List.of("queue.write"), captor.getValue().principal().permissions());
    verify(ctx, never()).isAllowedFullAccess();
    verify(ctx, never()).hasFormPassword(request);
  }

  @Test
  void handleMethodGET_whenAppTokenAndBrowserSessionProvided_routesProcessTokenPrincipal()
      throws Exception {
    toadlet = new PlatformApiToadlet(router, appHost, appBrowserSessionVerifier);
    when(request.getHeader("x-crypta-app-token")).thenReturn("process-token");
    lenient().when(request.getHeader("x-crypta-app-session")).thenReturn("browser-session");
    when(appHost.authenticateLaunchToken("process-token"))
        .thenReturn(Optional.of(new AppTokenPrincipal("alpha", List.of("node.read"))));
    when(request.getParameterNames()).thenReturn(List.of());
    when(router.route(any(PlatformApiRequest.class)))
        .thenReturn(PlatformApiResponse.ok(Map.of("ok", true)));

    toadlet.handleMethodGET(URI.create("http://localhost/api/v1/node/greeting"), request, ctx);

    ArgumentCaptor<PlatformApiRequest> captor = ArgumentCaptor.forClass(PlatformApiRequest.class);
    verify(router).route(captor.capture());
    assertEquals(PlatformApiPrincipalType.APP, captor.getValue().principal().type());
    assertEquals(PlatformApiAuthSource.APP_TOKEN, captor.getValue().principal().authSource());
    verifyNoInteractions(appBrowserSessionVerifier);
  }

  @Test
  void handleMethodGET_whenBearerTokenLookupFails_expectJson500WithoutHostFallback()
      throws Exception {
    toadlet = new PlatformApiToadlet(router, appHost);
    when(request.getHeader("authorization")).thenReturn("Bearer proxy-token");
    when(appHost.authenticateLaunchToken("proxy-token"))
        .thenThrow(new IllegalStateException("apphost state unavailable"));

    toadlet.handleMethodGET(URI.create("http://localhost/api/v1/node/greeting"), request, ctx);

    verifyNoInteractions(router);
    verify(ctx, never()).isAllowedFullAccess();
    ReplyHeadersCapture replyHeaders = captureReplyHeaders();
    assertEquals(500, replyHeaders.statusCode());
    assertEquals("Internal Server Error", replyHeaders.reasonPhrase());
    BodyWriteCapture bodyWrite = captureBodyWrite();
    assertEquals(
        "{\"error\":{\"code\":\"internal_error\",\"message\":\"Unexpected platform API"
            + " failure.\"}}",
        bodyWrite.bodyText());
    assertFalse(bodyWrite.bodyText().contains("proxy-token"));
  }

  @Test
  void handleMethodGET_whenTokenOnlyAppearsInQuery_routesHostRequestWithoutTokenAuth()
      throws Exception {
    toadlet = new PlatformApiToadlet(router, appHost);
    when(ctx.isAllowedFullAccess()).thenReturn(true);
    when(request.getParameterNames()).thenReturn(List.of("token"));
    when(request.getMultipleParam("token")).thenReturn(new String[] {"secret-token"});
    when(router.route(any(PlatformApiRequest.class)))
        .thenReturn(PlatformApiResponse.ok(Map.of("ok", true)));

    toadlet.handleMethodGET(
        URI.create("http://localhost/api/v1/node/greeting?token=secret-token"), request, ctx);

    ArgumentCaptor<PlatformApiRequest> captor = ArgumentCaptor.forClass(PlatformApiRequest.class);
    verify(router).route(captor.capture());
    assertEquals("HOST_OPERATOR", captor.getValue().principal().type().name());
    assertEquals(Map.of("token", List.of("secret-token")), captor.getValue().queryParameters());
    verify(appHost, never()).authenticateLaunchToken(any());
  }

  @Test
  void handleMethodGET_whenAppTokenInvalid_expect401WithoutTokenLeak() throws Exception {
    toadlet = new PlatformApiToadlet(router, appHost);
    when(request.getHeader("x-crypta-app-token")).thenReturn("secret-token");
    when(appHost.authenticateLaunchToken("secret-token")).thenReturn(Optional.empty());

    toadlet.handleMethodGET(URI.create("http://localhost/api/v1/node/greeting"), request, ctx);

    verifyNoInteractions(router);
    ReplyHeadersCapture replyHeaders = captureReplyHeaders();
    assertEquals(401, replyHeaders.statusCode());
    assertEquals("Unauthorized", replyHeaders.reasonPhrase());
    BodyWriteCapture bodyWrite = captureBodyWrite();
    assertEquals(
        "{\"error\":{\"code\":\"invalid_app_token\",\"message\":\"Invalid app token.\"}}",
        bodyWrite.bodyText());
    assertFalse(bodyWrite.bodyText().contains("secret-token"));
  }

  @Test
  void handleMethodGET_whenAppTokenAuthenticationFails_expectJson500WithoutRouting()
      throws Exception {
    toadlet = new PlatformApiToadlet(router, appHost);
    when(request.getHeader("x-crypta-app-token")).thenReturn("secret-token");
    when(appHost.authenticateLaunchToken("secret-token"))
        .thenThrow(new IllegalStateException("apphost unavailable"));

    toadlet.handleMethodGET(URI.create("http://localhost/api/v1/node/greeting"), request, ctx);

    verifyNoInteractions(router);
    verify(ctx, never()).isAllowedFullAccess();
    ReplyHeadersCapture replyHeaders = captureReplyHeaders();
    assertEquals(500, replyHeaders.statusCode());
    assertEquals("Internal Server Error", replyHeaders.reasonPhrase());
    BodyWriteCapture bodyWrite = captureBodyWrite();
    assertEquals(
        "{\"error\":{\"code\":\"internal_error\",\"message\":\"Unexpected platform API"
            + " failure.\"}}",
        bodyWrite.bodyText());
    assertFalse(bodyWrite.bodyText().contains("secret-token"));
  }

  @Test
  void handleMethodGET_whenAppTokenProvidedButAppHostUnavailable_expect401WithoutRouting()
      throws Exception {
    when(request.getHeader("x-crypta-app-token")).thenReturn("secret-token");

    toadlet.handleMethodGET(URI.create("http://localhost/api/v1/node/greeting"), request, ctx);

    verifyNoInteractions(router);
    verify(ctx, never()).isAllowedFullAccess();
    ReplyHeadersCapture replyHeaders = captureReplyHeaders();
    assertEquals(401, replyHeaders.statusCode());
    assertEquals("Unauthorized", replyHeaders.reasonPhrase());
    BodyWriteCapture bodyWrite = captureBodyWrite();
    assertEquals(
        "{\"error\":{\"code\":\"invalid_app_token\",\"message\":\"App token authentication is"
            + " unavailable.\"}}",
        bodyWrite.bodyText());
    assertFalse(bodyWrite.bodyText().contains("secret-token"));
  }

  @Test
  void handleMethodGET_whenAppTokenHeaderBlank_expect401WithoutRouting() throws Exception {
    toadlet = new PlatformApiToadlet(router, appHost);
    when(request.getHeader("x-crypta-app-token")).thenReturn("   ");
    when(appHost.authenticateLaunchToken("")).thenReturn(Optional.empty());

    toadlet.handleMethodGET(URI.create("http://localhost/api/v1/node/greeting"), request, ctx);

    verifyNoInteractions(router);
    verify(ctx, never()).isAllowedFullAccess();
    verify(appHost).authenticateLaunchToken("");
    ReplyHeadersCapture replyHeaders = captureReplyHeaders();
    assertEquals(401, replyHeaders.statusCode());
    BodyWriteCapture bodyWrite = captureBodyWrite();
    assertEquals(
        "{\"error\":{\"code\":\"invalid_app_token\",\"message\":\"Invalid app token.\"}}",
        bodyWrite.bodyText());
  }

  @Test
  void handleMethodGET_whenAuthorizationHeaderIsMalformedBearer_expectHostOperatorRequest()
      throws Exception {
    toadlet = new PlatformApiToadlet(router, appHost);
    when(request.getHeader("authorization")).thenReturn("BearerToken secret-token");
    when(ctx.isAllowedFullAccess()).thenReturn(true);
    when(request.getParameterNames()).thenReturn(List.of());
    when(router.route(any(PlatformApiRequest.class)))
        .thenReturn(PlatformApiResponse.ok(Map.of("ok", true)));

    toadlet.handleMethodGET(URI.create("http://localhost/api/v1/node/greeting"), request, ctx);

    ArgumentCaptor<PlatformApiRequest> captor = ArgumentCaptor.forClass(PlatformApiRequest.class);
    verify(router).route(captor.capture());
    assertEquals("HOST_OPERATOR", captor.getValue().principal().type().name());
    verify(appHost, never()).authenticateLaunchToken(any());
  }

  @Test
  void handleMethodGET_whenPeerIdentifierContainsEncodedSlash_routesDecodedIdentifier()
      throws Exception {
    when(ctx.isAllowedFullAccess()).thenReturn(true);
    when(request.getParameterNames()).thenReturn(List.of());
    when(router.route(any(PlatformApiRequest.class)))
        .thenReturn(PlatformApiResponse.ok(Map.of("peer", "alice/bob")));

    toadlet.handleMethodGET(URI.create("http://localhost/api/v1/peers/alice%2Fbob"), request, ctx);

    ArgumentCaptor<PlatformApiRequest> captor = ArgumentCaptor.forClass(PlatformApiRequest.class);
    verify(router).route(captor.capture());
    assertEquals("GET", captor.getValue().method());
    assertEquals(List.of("peers", "alice/bob"), captor.getValue().pathSegments());
    assertEquals(Map.of(), captor.getValue().queryParameters());
    verify(request, never()).getParts();
  }

  @Test
  void handleMethodPOST_whenAppInstallRequested_routesDecodedInstallRequest() throws Exception {
    when(ctx.isAllowedFullAccess()).thenReturn(true);
    when(ctx.hasFormPassword(request)).thenReturn(true);
    when(request.getParameterNames()).thenReturn(List.of("stagedDir"));
    when(request.getMultipleParam("stagedDir")).thenReturn(new String[] {"/tmp/staged"});
    when(router.route(any(PlatformApiRequest.class))).thenReturn(PlatformApiResponse.ok(Map.of()));

    toadlet.handleMethodPOST(URI.create("http://localhost/api/v1/apps/install"), request, ctx);

    verify(router)
        .route(
            new PlatformApiRequest(
                "POST", List.of("apps", "install"), Map.of("stagedDir", List.of("/tmp/staged"))));
  }

  @Test
  void handleMethodPOST_whenAppInstallUsesFormPart_routesInstallRequest() throws Exception {
    when(ctx.isAllowedFullAccess()).thenReturn(true);
    when(ctx.hasFormPassword(request)).thenReturn(true);
    when(request.getParameterNames()).thenReturn(List.of());
    when(request.getRawData()).thenReturn(requestBody);
    when(request.getParts()).thenReturn(new String[] {"stagedDir"});
    when(request.getPartAsStringFailsafe("stagedDir", QueueToadlet.MAX_KEY_LENGTH))
        .thenReturn("/tmp/staged");
    when(router.route(any(PlatformApiRequest.class))).thenReturn(PlatformApiResponse.ok(Map.of()));

    toadlet.handleMethodPOST(URI.create("http://localhost/api/v1/apps/install"), request, ctx);

    verify(router)
        .route(
            new PlatformApiRequest(
                "POST", List.of("apps", "install"), Map.of("stagedDir", List.of("/tmp/staged"))));
  }

  @Test
  void handleMethodPOST_whenAppUpdateRequested_routesDecodedUpdateRequest() throws Exception {
    when(ctx.isAllowedFullAccess()).thenReturn(true);
    when(ctx.hasFormPassword(request)).thenReturn(true);
    when(request.getParameterNames()).thenReturn(List.of("stagedDir"));
    when(request.getMultipleParam("stagedDir")).thenReturn(new String[] {"/tmp/staged"});
    when(router.route(any(PlatformApiRequest.class))).thenReturn(PlatformApiResponse.ok(Map.of()));

    toadlet.handleMethodPOST(URI.create("http://localhost/api/v1/apps/alpha/update"), request, ctx);

    verify(router)
        .route(
            new PlatformApiRequest(
                "POST",
                List.of("apps", "alpha", "update"),
                Map.of("stagedDir", List.of("/tmp/staged"))));
  }

  @Test
  void handleMethodPOST_whenAppUpdateUsesFormPart_routesUpdateRequest() throws Exception {
    when(ctx.isAllowedFullAccess()).thenReturn(true);
    when(ctx.hasFormPassword(request)).thenReturn(true);
    when(request.getParameterNames()).thenReturn(List.of());
    when(request.getRawData()).thenReturn(requestBody);
    when(request.getParts()).thenReturn(new String[] {"stagedDir"});
    when(request.getPartAsStringFailsafe("stagedDir", QueueToadlet.MAX_KEY_LENGTH))
        .thenReturn("/tmp/staged");
    when(router.route(any(PlatformApiRequest.class))).thenReturn(PlatformApiResponse.ok(Map.of()));

    toadlet.handleMethodPOST(URI.create("http://localhost/api/v1/apps/alpha/update"), request, ctx);

    verify(router)
        .route(
            new PlatformApiRequest(
                "POST",
                List.of("apps", "alpha", "update"),
                Map.of("stagedDir", List.of("/tmp/staged"))));
  }

  @Test
  void handleMethodPOST_whenQueueRemoveRequested_routesDecodedMutationRequest() throws Exception {
    when(ctx.isAllowedFullAccess()).thenReturn(true);
    when(ctx.hasFormPassword(request)).thenReturn(true);
    when(request.getParameterNames()).thenReturn(List.of("identifier-0", "identifier-1"));
    when(request.getMultipleParam("identifier-0")).thenReturn(new String[] {"download-1"});
    when(request.getMultipleParam("identifier-1")).thenReturn(new String[] {"download-2"});
    when(router.route(any(PlatformApiRequest.class))).thenReturn(PlatformApiResponse.ok(Map.of()));

    toadlet.handleMethodPOST(
        URI.create("http://localhost/api/v1/queue/requests/remove"), request, ctx);

    verify(router)
        .route(
            new PlatformApiRequest(
                "POST",
                List.of("queue", "requests", "remove"),
                Map.of(
                    "identifier-0", List.of("download-1"),
                    "identifier-1", List.of("download-2"))));
  }

  @Test
  void handleMethodPOST_whenQueueRemoveUsesFormParts_routesDecodedMutationRequest()
      throws Exception {
    when(ctx.isAllowedFullAccess()).thenReturn(true);
    when(ctx.hasFormPassword(request)).thenReturn(true);
    when(request.getParameterNames()).thenReturn(List.of());
    when(request.getRawData()).thenReturn(requestBody);
    when(request.getParts()).thenReturn(new String[] {"identifier-0", "identifier-1"});
    when(request.getPartAsStringFailsafe("identifier-0", QueueToadlet.MAX_KEY_LENGTH))
        .thenReturn("download-1");
    when(request.getPartAsStringFailsafe("identifier-1", QueueToadlet.MAX_KEY_LENGTH))
        .thenReturn("download-2");
    when(router.route(any(PlatformApiRequest.class))).thenReturn(PlatformApiResponse.ok(Map.of()));

    toadlet.handleMethodPOST(
        URI.create("http://localhost/api/v1/queue/requests/remove"), request, ctx);

    verify(router)
        .route(
            new PlatformApiRequest(
                "POST",
                List.of("queue", "requests", "remove"),
                Map.of(
                    "identifier-0", List.of("download-1"),
                    "identifier-1", List.of("download-2"))));
    verify(request).getPartAsStringFailsafe("identifier-0", QueueToadlet.MAX_KEY_LENGTH);
    verify(request).getPartAsStringFailsafe("identifier-1", QueueToadlet.MAX_KEY_LENGTH);
  }

  @Test
  void handleMethodPOST_whenQueueRemoveUsesRepeatedUrlEncodedBody_routesAllIdentifiers()
      throws Exception {
    when(ctx.isAllowedFullAccess()).thenReturn(true);
    when(ctx.hasFormPassword(request)).thenReturn(true);
    when(request.getParameterNames()).thenReturn(List.of());
    when(request.getHeader("content-type")).thenReturn("application/x-www-form-urlencoded");
    when(request.getRawData())
        .thenReturn(
            new SimpleReadOnlyArrayBucket(
                "identifier=download-1&identifier=download-2".getBytes(StandardCharsets.US_ASCII)));
    when(router.route(any(PlatformApiRequest.class))).thenReturn(PlatformApiResponse.ok(Map.of()));

    toadlet.handleMethodPOST(
        URI.create("http://localhost/api/v1/queue/requests/remove"), request, ctx);

    verify(router)
        .route(
            new PlatformApiRequest(
                "POST",
                List.of("queue", "requests", "remove"),
                Map.of("identifier", List.of("download-1", "download-2"))));
    verify(request, never()).getParts();
  }

  @Test
  void handleMethodPOST_whenDiscoveryImportUsesRepeatedEndorsements_routesEveryValue()
      throws Exception {
    when(ctx.isAllowedFullAccess()).thenReturn(true);
    when(ctx.hasFormPassword(request)).thenReturn(true);
    when(request.getParameterNames()).thenReturn(List.of());
    when(request.getHeader("content-type")).thenReturn("application/x-www-form-urlencoded");
    when(request.getRawData())
        .thenReturn(
            new SimpleReadOnlyArrayBucket(
                ("descriptorBase64=descriptor"
                        + "&endorsementBase64=endorsement-one"
                        + "&endorsementBase64=endorsement-two")
                    .getBytes(StandardCharsets.US_ASCII)));
    when(router.route(any(PlatformApiRequest.class))).thenReturn(PlatformApiResponse.ok(Map.of()));

    toadlet.handleMethodPOST(
        URI.create("http://localhost/api/v1/operator/catalog-federation/discovery"), request, ctx);

    verify(router)
        .route(
            new PlatformApiRequest(
                "POST",
                List.of("operator", "catalog-federation", "discovery"),
                Map.of(
                    "descriptorBase64", List.of("descriptor"),
                    "endorsementBase64", List.of("endorsement-one", "endorsement-two"))));
    verify(request, never()).getParts();
  }

  @Test
  void handleMethodPOST_whenUrlEncodedBodyOverlapsQuery_expectQueryValuesPreserved()
      throws Exception {
    when(ctx.isAllowedFullAccess()).thenReturn(true);
    when(ctx.hasFormPassword(request)).thenReturn(true);
    when(request.getParameterNames()).thenReturn(List.of("expectedMimeType"));
    when(request.getMultipleParam("expectedMimeType")).thenReturn(new String[] {"text/html"});
    when(request.getHeader("content-type"))
        .thenReturn("application/x-www-form-urlencoded; charset=UTF-8");
    when(request.getRawData())
        .thenReturn(
            new SimpleReadOnlyArrayBucket(
                ("fetchUri=KSK@direct-download&expectedMimeType=text/plain&filterData=on"
                        + "&formPassword=secret")
                    .getBytes(StandardCharsets.US_ASCII)));
    when(router.route(any(PlatformApiRequest.class))).thenReturn(PlatformApiResponse.ok(Map.of()));

    toadlet.handleMethodPOST(URI.create("http://localhost/api/v1/queue/downloads"), request, ctx);

    verify(router)
        .route(
            new PlatformApiRequest(
                "POST",
                List.of("queue", "downloads"),
                Map.of(
                    "expectedMimeType", List.of("text/html"),
                    "fetchUri", List.of("KSK@direct-download"),
                    "filterData", List.of("on"))));
    verify(request, never()).getParts();
  }

  @Test
  void handleMethodPOST_whenUrlEncodedBodyExceedsLegacyLimit_expectJson400WithoutRouting()
      throws Exception {
    byte[] oversizedBody = new byte[1024 * 1024 + 1];
    Arrays.fill(oversizedBody, (byte) 'a');

    when(ctx.isAllowedFullAccess()).thenReturn(true);
    when(ctx.hasFormPassword(request)).thenReturn(true);
    when(request.getParameterNames()).thenReturn(List.of());
    when(request.getHeader("content-type")).thenReturn("application/x-www-form-urlencoded");
    when(request.getRawData()).thenReturn(new SimpleReadOnlyArrayBucket(oversizedBody));

    toadlet.handleMethodPOST(URI.create("http://localhost/api/v1/queue/downloads"), request, ctx);

    verifyNoInteractions(router);
    ReplyHeadersCapture replyHeaders = captureReplyHeaders();
    assertEquals(400, replyHeaders.statusCode());
    assertEquals("Bad Request", replyHeaders.reasonPhrase());
    assertEquals("application/json; charset=UTF-8", replyHeaders.mimeType());
    BodyWriteCapture bodyWrite = captureBodyWrite();
    assertEquals(
        "{\"error\":{\"code\":\"invalid_request_body\",\"message\":\"URL-encoded request body"
            + " exceeds the 1048576 byte limit.\"}}",
        bodyWrite.bodyText());
  }

  @Test
  void handleMethodPOST_whenQueueDownloadUsesFormParts_routesDecodedCreationRequest()
      throws Exception {
    when(ctx.isAllowedFullAccess()).thenReturn(true);
    when(ctx.hasFormPassword(request)).thenReturn(true);
    when(request.getParameterNames()).thenReturn(List.of());
    when(request.getRawData()).thenReturn(requestBody);
    when(request.getParts())
        .thenReturn(new String[] {"fetchUri", "filterData", "expectedMimeType"});
    when(request.getPartAsStringFailsafe("fetchUri", QueueToadlet.MAX_KEY_LENGTH))
        .thenReturn("KSK@direct-download");
    when(request.getPartAsStringFailsafe("filterData", QueueToadlet.MAX_KEY_LENGTH))
        .thenReturn("on");
    when(request.getPartAsStringFailsafe("expectedMimeType", QueueToadlet.MAX_KEY_LENGTH))
        .thenReturn("text/plain");
    when(router.route(any(PlatformApiRequest.class))).thenReturn(PlatformApiResponse.ok(Map.of()));

    toadlet.handleMethodPOST(URI.create("http://localhost/api/v1/queue/downloads"), request, ctx);

    verify(router)
        .route(
            new PlatformApiRequest(
                "POST",
                List.of("queue", "downloads"),
                Map.of(
                    "fetchUri", List.of("KSK@direct-download"),
                    "filterData", List.of("on"),
                    "expectedMimeType", List.of("text/plain"))));
    verify(request).getPartAsStringFailsafe("fetchUri", QueueToadlet.MAX_KEY_LENGTH);
  }

  @Test
  void handleMethodPOST_whenPeerAddRequested_routesDecodedAddRequest() throws Exception {
    when(ctx.isAllowedFullAccess()).thenReturn(true);
    when(ctx.hasFormPassword(request)).thenReturn(true);
    when(request.getParameterNames())
        .thenReturn(List.of("referenceText", "trust", "visibility", "privateNoteText"));
    when(request.getMultipleParam("referenceText"))
        .thenReturn(
            new String[] {
"""
identity=peer-123
lastGoodVersion=1
myName=Alice
physical.udp=127.0.0.1:9481
End
"""
            });
    when(request.getMultipleParam("trust")).thenReturn(new String[] {"NORMAL"});
    when(request.getMultipleParam("visibility")).thenReturn(new String[] {"YES"});
    when(request.getMultipleParam("privateNoteText")).thenReturn(new String[] {"friend note"});
    when(router.route(any(PlatformApiRequest.class))).thenReturn(PlatformApiResponse.ok(Map.of()));

    toadlet.handleMethodPOST(URI.create("http://localhost/api/v1/peers/add"), request, ctx);

    verify(router)
        .route(
            new PlatformApiRequest(
                "POST",
                List.of("peers", "add"),
                Map.of(
                    "referenceText",
                        List.of(
                            """
                            identity=peer-123
                            lastGoodVersion=1
                            myName=Alice
                            physical.udp=127.0.0.1:9481
                            End
                            """),
                    "trust", List.of("NORMAL"),
                    "visibility", List.of("YES"),
                    "privateNoteText", List.of("friend note"))));
  }

  @Test
  void handleMethodPOST_whenPeerSettingsRequested_routesDecodedMutationRequest() throws Exception {
    when(ctx.isAllowedFullAccess()).thenReturn(true);
    when(ctx.hasFormPassword(request)).thenReturn(true);
    when(request.getParameterNames()).thenReturn(List.of("trust", "visibility"));
    when(request.getMultipleParam("trust")).thenReturn(new String[] {"HIGH"});
    when(request.getMultipleParam("visibility")).thenReturn(new String[] {"NAME_ONLY"});
    when(router.route(any(PlatformApiRequest.class))).thenReturn(PlatformApiResponse.ok(Map.of()));

    toadlet.handleMethodPOST(
        URI.create("http://localhost/api/v1/peers/peer%2F123/settings"), request, ctx);

    verify(router)
        .route(
            new PlatformApiRequest(
                "POST",
                List.of("peers", "peer/123", "settings"),
                Map.of("trust", List.of("HIGH"), "visibility", List.of("NAME_ONLY"))));
  }

  @Test
  void handleMethodPOST_whenPeerNoteUsesFormPart_routesDecodedMutationRequest() throws Exception {
    when(ctx.isAllowedFullAccess()).thenReturn(true);
    when(ctx.hasFormPassword(request)).thenReturn(true);
    when(request.getParameterNames()).thenReturn(List.of());
    when(request.getRawData()).thenReturn(requestBody);
    when(request.getParts()).thenReturn(new String[] {"noteText"});
    when(request.getPartAsStringFailsafe("noteText", QueueToadlet.MAX_KEY_LENGTH))
        .thenReturn("updated note");
    when(router.route(any(PlatformApiRequest.class))).thenReturn(PlatformApiResponse.ok(Map.of()));

    toadlet.handleMethodPOST(
        URI.create("http://localhost/api/v1/peers/peer-123/note"), request, ctx);

    verify(router)
        .route(
            new PlatformApiRequest(
                "POST",
                List.of("peers", "peer-123", "note"),
                Map.of("noteText", List.of("updated note"))));
    verify(request).getPartAsStringFailsafe("noteText", QueueToadlet.MAX_KEY_LENGTH);
  }

  @Test
  void handleMethodPOST_whenAlertDismissRequested_routesDecodedMutationRequest() throws Exception {
    when(ctx.isAllowedFullAccess()).thenReturn(true);
    when(ctx.hasFormPassword(request)).thenReturn(true);
    when(request.getParameterNames()).thenReturn(List.of());
    when(router.route(any(PlatformApiRequest.class))).thenReturn(PlatformApiResponse.ok(Map.of()));

    toadlet.handleMethodPOST(
        URI.create("http://localhost/api/v1/alerts/-17/dismiss"), request, ctx);

    verify(router)
        .route(new PlatformApiRequest("POST", List.of("alerts", "-17", "dismiss"), Map.of()));
  }

  @Test
  void handleMethodPOST_whenQueueMutationPasswordMissing_expectJson403WithoutRouting()
      throws Exception {
    when(ctx.isAllowedFullAccess()).thenReturn(true);
    when(ctx.hasFormPassword(request)).thenReturn(false);

    toadlet.handleMethodPOST(
        URI.create("http://localhost/api/v1/queue/requests/remove"), request, ctx);

    verifyNoInteractions(router);
    ReplyHeadersCapture replyHeaders = captureReplyHeaders();
    assertEquals(403, replyHeaders.statusCode());
    assertEquals("Forbidden", replyHeaders.reasonPhrase());
    assertEquals("application/json; charset=UTF-8", replyHeaders.mimeType());
    BodyWriteCapture bodyWrite = captureBodyWrite();
    assertEquals(
        "{\"error\":{\"code\":\"forbidden\",\"message\":\"Valid form password is required.\"}}",
        bodyWrite.bodyText());
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "http://localhost/api/v1/queue/inserts/file",
        "http://localhost/api/v1/queue/inserts/directory",
      })
  void handleMethodPOST_whenQueueInsertPasswordMissing_expectJson403WithoutRouting(
      String requestUri) throws Exception {
    when(ctx.isAllowedFullAccess()).thenReturn(true);
    when(ctx.hasFormPassword(request)).thenReturn(false);

    toadlet.handleMethodPOST(URI.create(requestUri), request, ctx);

    verifyNoInteractions(router);
    assertForbiddenBody();
  }

  @Test
  void handleMethodPOST_whenPeerMutationPasswordMissing_expectJson403WithoutRouting()
      throws Exception {
    when(ctx.isAllowedFullAccess()).thenReturn(true);
    when(ctx.hasFormPassword(request)).thenReturn(false);

    toadlet.handleMethodPOST(
        URI.create("http://localhost/api/v1/peers/peer-123/remove"), request, ctx);

    verifyNoInteractions(router);
    ReplyHeadersCapture replyHeaders = captureReplyHeaders();
    assertEquals(403, replyHeaders.statusCode());
    assertEquals("Forbidden", replyHeaders.reasonPhrase());
    assertEquals("application/json; charset=UTF-8", replyHeaders.mimeType());
    BodyWriteCapture bodyWrite = captureBodyWrite();
    assertEquals(
        "{\"error\":{\"code\":\"forbidden\",\"message\":\"Valid form password is required.\"}}",
        bodyWrite.bodyText());
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "http://localhost/api/v1/config/overrides",
        "http://localhost/api/v1/security-levels/network",
        "http://localhost/api/v1/updates/core/download",
        "http://localhost/api/v1/content/fetch",
        "http://localhost/api/v1/alerts/42/dismiss",
        "http://localhost/api/v1/wizard/first-time/apply",
        "http://localhost/api/v1/app-catalogs/recommended/crypta-first-party-beta/add",
        "http://localhost/api/v1/operator/app-data/backups",
        "http://localhost/api/v1/operator/app-data/restore/plan",
        "http://localhost/api/v1/operator/app-data/restore",
        "http://localhost/api/v1/operator/recovery/plan",
        "http://localhost/api/v1/operator/recovery/execute",
        "http://localhost/api/v1/operator/subscriptions/feed-reader/sub-123/refresh",
        "http://localhost/api/v1/operator/subscriptions/feed-reader/sub-123/reset-backoff",
        "http://localhost/api/v1/operator/subscriptions/feed-reader/sub-123/reschedule-now",
      })
  void handleMethodPOST_whenProtectedMutationPasswordMissing_expectJson403WithoutRouting(
      String requestUri) throws Exception {
    when(ctx.isAllowedFullAccess()).thenReturn(true);
    when(ctx.hasFormPassword(request)).thenReturn(false);

    toadlet.handleMethodPOST(URI.create(requestUri), request, ctx);

    verifyNoInteractions(router);
    verify(ctx, never()).checkFormPassword(request, URI.create(requestUri).getPath());
    assertForbiddenBody();
  }

  @Test
  void handleMethodPOST_whenNonAppsRoute_expectRouterJson405WithoutPasswordCheck()
      throws Exception {
    when(ctx.isAllowedFullAccess()).thenReturn(true);
    when(request.getParameterNames()).thenReturn(List.of());
    PlatformApiResponse response =
        PlatformApiResponse.error(
            405,
            Map.of("Allow", "GET"),
            "method_not_allowed",
            "Platform API v1 supports GET requests only.");
    when(router.route(any(PlatformApiRequest.class))).thenReturn(response);

    toadlet.handleMethodPOST(URI.create("http://localhost/api/v1/node/greeting"), request, ctx);

    verify(router).route(new PlatformApiRequest("POST", List.of("node", "greeting"), Map.of()));
    verify(ctx, never()).checkFormPassword(request, "/api/v1/node/greeting");
    ReplyHeadersCapture replyHeaders = captureReplyHeaders();
    assertEquals(405, replyHeaders.statusCode());
    assertEquals("Method Not Allowed", replyHeaders.reasonPhrase());
    assertEquals("GET", replyHeaders.headers().getFirst("Allow"));
    BodyWriteCapture bodyWrite = captureBodyWrite();
    assertEquals(response.body(), bodyWrite.bodyText());
  }

  @Test
  void handleMethodPOST_whenMalformedAppsPath_expectRouterJson404WithoutPasswordCheck()
      throws Exception {
    when(ctx.isAllowedFullAccess()).thenReturn(true);
    when(request.getParameterNames()).thenReturn(List.of());
    PlatformApiResponse response =
        PlatformApiResponse.error(404, "not_found", "Platform API route not found.");
    when(router.route(any(PlatformApiRequest.class))).thenReturn(response);

    toadlet.handleMethodPOST(
        URI.create("http://localhost/api/v1/apps/alpha/restart"), request, ctx);

    verify(router)
        .route(new PlatformApiRequest("POST", List.of("apps", "alpha", "restart"), Map.of()));
    verify(ctx, never()).checkFormPassword(request, "/api/v1/apps/alpha/restart");
    ReplyHeadersCapture replyHeaders = captureReplyHeaders();
    assertEquals(404, replyHeaders.statusCode());
    assertEquals("Not Found", replyHeaders.reasonPhrase());
    BodyWriteCapture bodyWrite = captureBodyWrite();
    assertEquals(response.body(), bodyWrite.bodyText());
  }

  @Test
  void findSupportedMethods_whenPlatformApiToadlet_expectAllBridgeHandledMethods() {
    Set<String> methods = Set.copyOf(Arrays.asList(toadlet.findSupportedMethods().split(", ")));

    assertEquals(
        Set.of("DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT", "TRACE"), methods);
  }

  @Test
  void handleMethodOPTIONS_whenUnsupportedVerb_expectRouterBackedJson405() throws Exception {
    when(ctx.isAllowedFullAccess()).thenReturn(true);
    when(request.getParameterNames()).thenReturn(List.of());
    PlatformApiResponse response =
        PlatformApiResponse.error(
            405,
            Map.of("Allow", "GET"),
            "method_not_allowed",
            "Platform API v1 supports GET requests only.");
    when(router.route(any(PlatformApiRequest.class))).thenReturn(response);

    toadlet.handleMethodOPTIONS(URI.create("http://localhost/api/v1/node/greeting"), request, ctx);

    verify(router).route(new PlatformApiRequest("OPTIONS", List.of("node", "greeting"), Map.of()));
    ReplyHeadersCapture replyHeaders = captureReplyHeaders();
    assertEquals(405, replyHeaders.statusCode());
    assertEquals("Method Not Allowed", replyHeaders.reasonPhrase());
    assertEquals("GET", replyHeaders.headers().getFirst("Allow"));
    assertEquals("application/json; charset=UTF-8", replyHeaders.mimeType());
    assertEquals(response.body().getBytes(StandardCharsets.UTF_8).length, replyHeaders.length());
    BodyWriteCapture bodyWrite = captureBodyWrite();
    assertEquals(0, bodyWrite.offset());
    assertEquals(response.body().getBytes(StandardCharsets.UTF_8).length, bodyWrite.length());
    assertEquals(response.body(), bodyWrite.bodyText());
  }

  @Test
  void handleMethodOPTIONS_whenRegisteredAppOriginPreflightsSessionHeader_expectCors204()
      throws Exception {
    AppUiOriginBinding binding = isolatedBinding("alpha", 12345);
    toadlet =
        new PlatformApiToadlet(router, appHost, appBrowserSessionVerifier, registryWith(binding));
    when(request.getHeader("origin")).thenReturn(binding.origin());
    when(request.getHeader("access-control-request-method")).thenReturn("POST");
    when(request.getHeader("access-control-request-headers"))
        .thenReturn("X-Crypta-App-Session, Content-Type");

    toadlet.handleMethodOPTIONS(URI.create("http://localhost/api/v1/queue"), request, ctx);

    verifyNoInteractions(router);
    ReplyHeadersCapture replyHeaders = captureForcedReplyHeaders();
    assertEquals(204, replyHeaders.statusCode());
    assertEquals("No Content", replyHeaders.reasonPhrase());
    assertEquals(binding.origin(), replyHeaders.headers().getFirst("Access-Control-Allow-Origin"));
    assertEquals(
        "GET, POST, PUT, PATCH, DELETE",
        replyHeaders.headers().getFirst("Access-Control-Allow-Methods"));
    assertEquals(
        "X-Crypta-App-Session, Accept, Content-Type",
        replyHeaders.headers().getFirst("Access-Control-Allow-Headers"));
    assertEquals("600", replyHeaders.headers().getFirst("Access-Control-Max-Age"));
    verify(ctx, never()).writeData(any(byte[].class), anyInt(), anyInt());
  }

  @ParameterizedTest
  @ValueSource(strings = {"PUT", "PATCH"})
  void handleMethodOPTIONS_whenRegisteredAppOriginPreflightsWriteMethod_expectCors204(String method)
      throws Exception {
    AppUiOriginBinding binding = isolatedBinding("alpha", 12345);
    toadlet =
        new PlatformApiToadlet(router, appHost, appBrowserSessionVerifier, registryWith(binding));
    when(request.getHeader("origin")).thenReturn(binding.origin());
    when(request.getHeader("access-control-request-method")).thenReturn(method);
    when(request.getHeader("access-control-request-headers"))
        .thenReturn("X-Crypta-App-Session, Content-Type");

    toadlet.handleMethodOPTIONS(
        URI.create("http://localhost/api/v1/app-vault/secrets/demo"), request, ctx);

    verifyNoInteractions(router);
    ReplyHeadersCapture replyHeaders = captureForcedReplyHeaders();
    assertEquals(204, replyHeaders.statusCode());
    assertEquals(binding.origin(), replyHeaders.headers().getFirst("Access-Control-Allow-Origin"));
    assertEquals(
        "GET, POST, PUT, PATCH, DELETE",
        replyHeaders.headers().getFirst("Access-Control-Allow-Methods"));
  }

  @Test
  void handleMethodOPTIONS_whenPreflightRequestsAppProcessTokenHeader_expect403() throws Exception {
    AppUiOriginBinding binding = isolatedBinding("alpha", 12345);
    toadlet =
        new PlatformApiToadlet(router, appHost, appBrowserSessionVerifier, registryWith(binding));
    when(request.getHeader("origin")).thenReturn(binding.origin());
    when(request.getHeader("access-control-request-method")).thenReturn("POST");
    when(request.getHeader("access-control-request-headers")).thenReturn("X-Crypta-App-Token");

    toadlet.handleMethodOPTIONS(URI.create("http://localhost/api/v1/queue"), request, ctx);

    verifyNoInteractions(router);
    ReplyHeadersCapture replyHeaders = captureReplyHeaders();
    assertEquals(403, replyHeaders.statusCode());
    BodyWriteCapture bodyWrite = captureBodyWrite();
    assertEquals(
        "{\"error\":{\"code\":\"origin_mismatch\",\"message\":\"App browser origin is not allowed"
            + " for Platform API CORS.\"}}",
        bodyWrite.bodyText());
  }

  @Test
  void handleMethodHEAD_whenUnsupportedVerb_expectHeaderOnly405() throws Exception {
    when(ctx.isAllowedFullAccess()).thenReturn(true);
    when(request.getParameterNames()).thenReturn(List.of());
    PlatformApiResponse response =
        PlatformApiResponse.error(
            405,
            Map.of("Allow", "GET"),
            "method_not_allowed",
            "Platform API v1 supports GET requests only.");
    when(router.route(any(PlatformApiRequest.class))).thenReturn(response);

    toadlet.handleMethodHEAD(URI.create("http://localhost/api/v1/node/greeting"), request, ctx);

    verify(router).route(new PlatformApiRequest("HEAD", List.of("node", "greeting"), Map.of()));
    ReplyHeadersCapture replyHeaders = captureReplyHeaders();
    assertEquals(405, replyHeaders.statusCode());
    assertEquals("Method Not Allowed", replyHeaders.reasonPhrase());
    assertEquals("GET", replyHeaders.headers().getFirst("Allow"));
    assertEquals("application/json; charset=UTF-8", replyHeaders.mimeType());
    assertEquals(response.body().getBytes(StandardCharsets.UTF_8).length, replyHeaders.length());
    verify(ctx, never()).writeData(any(byte[].class), anyInt(), anyInt());
  }

  @Test
  void handleMethodDELETE_whenAppRemovalRequested_routesDecodedDeleteRequest() throws Exception {
    when(ctx.isAllowedFullAccess()).thenReturn(true);
    when(ctx.hasFormPassword(request)).thenReturn(true);
    when(request.getParameterNames()).thenReturn(List.of());
    when(router.route(any(PlatformApiRequest.class))).thenReturn(PlatformApiResponse.ok(Map.of()));

    toadlet.handleMethodDELETE(URI.create("http://localhost/api/v1/apps/alpha"), request, ctx);

    verify(router).route(new PlatformApiRequest("DELETE", List.of("apps", "alpha"), Map.of()));
    verify(ctx, never()).checkFormPassword(request, "/api/v1/apps/alpha");
  }

  @Test
  void handleMethodPOST_whenFullAccessMissing_expectJson403WithoutRouting() throws Exception {
    when(ctx.isAllowedFullAccess()).thenReturn(false);

    toadlet.handleMethodPOST(URI.create("http://localhost/api/v1/apps/install"), request, ctx);

    verifyNoInteractions(router);
    ReplyHeadersCapture replyHeaders = captureReplyHeaders();
    assertEquals(403, replyHeaders.statusCode());
    assertEquals("Forbidden", replyHeaders.reasonPhrase());
    assertEquals("application/json; charset=UTF-8", replyHeaders.mimeType());
    BodyWriteCapture bodyWrite = captureBodyWrite();
    assertEquals(
        "{\"error\":{\"code\":\"forbidden\",\"message\":\"Full access is required.\"}}",
        bodyWrite.bodyText());
  }

  @Test
  void handleMethodPOST_whenFormPasswordMissing_expectJson403WithoutRouting() throws Exception {
    when(ctx.isAllowedFullAccess()).thenReturn(true);
    when(ctx.hasFormPassword(request)).thenReturn(false);

    toadlet.handleMethodPOST(URI.create("http://localhost/api/v1/apps/install"), request, ctx);

    verifyNoInteractions(router);
    verify(ctx, never()).checkFormPassword(request, "/api/v1/apps/install");
    ReplyHeadersCapture replyHeaders = captureReplyHeaders();
    assertEquals(403, replyHeaders.statusCode());
    assertEquals("Forbidden", replyHeaders.reasonPhrase());
    assertEquals("application/json; charset=UTF-8", replyHeaders.mimeType());
    BodyWriteCapture bodyWrite = captureBodyWrite();
    assertEquals(
        "{\"error\":{\"code\":\"forbidden\",\"message\":\"Valid form password is required.\"}}",
        bodyWrite.bodyText());
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "http://localhost/api/v1/apps/alpha/updates/check",
        "http://localhost/api/v1/apps/alpha/updates/stage",
        "http://localhost/api/v1/apps/alpha/updates/apply",
        "http://localhost/api/v1/apps/alpha/updates/rollback",
        "http://localhost/api/v1/apps/alpha/updates/policy",
      })
  void handleMethodPOST_whenAppUpdateMutationPasswordMissing_expectJson403WithoutRouting(
      String requestUri) throws Exception {
    URI uri = URI.create(requestUri);
    assertTrue(uri.getPath().contains("/apps/alpha/updates/"));
    when(ctx.isAllowedFullAccess()).thenReturn(true);
    when(ctx.hasFormPassword(request)).thenReturn(false);

    toadlet.handleMethodPOST(uri, request, ctx);

    verifyNoInteractions(router);
    verify(ctx, never()).checkFormPassword(request, uri.getPath());
    assertForbiddenBody();
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "http://localhost/api/v1/operator/catalog-federation/alpha/trust",
        "http://localhost/api/v1/operator/catalog-federation/alpha/suspend",
        "http://localhost/api/v1/operator/catalog-federation/alpha/revoke",
        "http://localhost/api/v1/operator/catalog-federation/alpha/remove",
        "http://localhost/api/v1/operator/catalog-federation/alpha/publisher-scope-revoke",
        "http://localhost/api/v1/operator/catalog-federation/alpha/reviewer-scope-revoke",
        "http://localhost/api/v1/operator/catalog-federation/discovery",
        "http://localhost/api/v1/operator/catalog-federation/discovery/descriptor-alpha/discard",
      })
  void handleMethodPOST_whenCatalogFederationMutationPasswordMissing_expectJson403WithoutRouting(
      String requestUri) throws Exception {
    URI uri = URI.create(requestUri);
    when(ctx.isAllowedFullAccess()).thenReturn(true);
    when(ctx.hasFormPassword(request)).thenReturn(false);

    toadlet.handleMethodPOST(uri, request, ctx);

    verifyNoInteractions(router);
    verify(ctx, never()).checkFormPassword(request, uri.getPath());
    assertForbiddenBody();
  }

  @Test
  void handleMethodPOST_whenSourceSwitchPreviewPasswordMissing_expectJson403WithoutRouting()
      throws Exception {
    URI uri =
        URI.create("http://localhost/api/v1/operator/apps/alpha/catalog-origin/switch-preview");
    when(ctx.isAllowedFullAccess()).thenReturn(true);
    when(ctx.hasFormPassword(request)).thenReturn(false);

    toadlet.handleMethodPOST(uri, request, ctx);

    verifyNoInteractions(router);
    verify(ctx, never()).checkFormPassword(request, uri.getPath());
    assertForbiddenBody();
  }

  @Test
  void handleMethodDELETE_whenFormPasswordMissing_expectJson403WithoutRouting() throws Exception {
    when(ctx.isAllowedFullAccess()).thenReturn(true);
    when(ctx.hasFormPassword(request)).thenReturn(false);

    toadlet.handleMethodDELETE(URI.create("http://localhost/api/v1/apps/alpha"), request, ctx);

    verifyNoInteractions(router);
    verify(ctx, never()).checkFormPassword(request, "/api/v1/apps/alpha");
    ReplyHeadersCapture replyHeaders = captureReplyHeaders();
    assertEquals(403, replyHeaders.statusCode());
    assertEquals("Forbidden", replyHeaders.reasonPhrase());
    assertEquals("application/json; charset=UTF-8", replyHeaders.mimeType());
    BodyWriteCapture bodyWrite = captureBodyWrite();
    assertEquals(
        "{\"error\":{\"code\":\"forbidden\",\"message\":\"Valid form password is required.\"}}",
        bodyWrite.bodyText());
  }

  @Test
  void handleMethodDELETE_whenQueryFormPasswordProvided_expectJson403WithoutRouting()
      throws Exception {
    when(ctx.isAllowedFullAccess()).thenReturn(true);
    when(ctx.hasFormPassword(request)).thenReturn(false);

    toadlet.handleMethodDELETE(
        URI.create("http://localhost/api/v1/apps/alpha?formPassword=secret"), request, ctx);

    verifyNoInteractions(router);
    verify(ctx, never()).checkFormPassword(request, "/api/v1/apps/alpha");
    verify(ctx, never()).getFormPassword();
    verify(request, never()).getParam("formPassword");
    ReplyHeadersCapture replyHeaders = captureReplyHeaders();
    assertEquals(403, replyHeaders.statusCode());
    assertEquals("Forbidden", replyHeaders.reasonPhrase());
    assertEquals("application/json; charset=UTF-8", replyHeaders.mimeType());
    BodyWriteCapture bodyWrite = captureBodyWrite();
    assertEquals(
        "{\"error\":{\"code\":\"forbidden\",\"message\":\"Valid form password is required.\"}}",
        bodyWrite.bodyText());
  }

  private ReplyHeadersCapture captureReplyHeaders() throws Exception {
    ArgumentCaptor<Integer> statusCode = ArgumentCaptor.forClass(Integer.class);
    ArgumentCaptor<String> reasonPhrase = ArgumentCaptor.forClass(String.class);
    ArgumentCaptor<MultiValueTable<String, String>> headers = multiValueTableCaptor();
    ArgumentCaptor<String> mimeType = ArgumentCaptor.forClass(String.class);
    ArgumentCaptor<Long> length = ArgumentCaptor.forClass(Long.class);

    verify(ctx)
        .sendReplyHeaders(
            statusCode.capture(),
            reasonPhrase.capture(),
            headers.capture(),
            mimeType.capture(),
            length.capture());

    return new ReplyHeadersCapture(
        statusCode.getValue(),
        reasonPhrase.getValue(),
        headers.getValue(),
        mimeType.getValue(),
        length.getValue());
  }

  private ReplyHeadersCapture captureForcedReplyHeaders() throws Exception {
    ArgumentCaptor<Integer> statusCode = ArgumentCaptor.forClass(Integer.class);
    ArgumentCaptor<String> reasonPhrase = ArgumentCaptor.forClass(String.class);
    ArgumentCaptor<MultiValueTable<String, String>> headers = multiValueTableCaptor();
    ArgumentCaptor<String> mimeType = ArgumentCaptor.forClass(String.class);
    ArgumentCaptor<Long> length = ArgumentCaptor.forClass(Long.class);
    ArgumentCaptor<Boolean> forceDisableJavascript = ArgumentCaptor.forClass(Boolean.class);

    verify(ctx)
        .sendReplyHeaders(
            statusCode.capture(),
            reasonPhrase.capture(),
            headers.capture(),
            mimeType.capture(),
            length.capture(),
            forceDisableJavascript.capture());

    return new ReplyHeadersCapture(
        statusCode.getValue(),
        reasonPhrase.getValue(),
        headers.getValue(),
        mimeType.getValue(),
        length.getValue());
  }

  @SuppressWarnings("unchecked")
  private static ArgumentCaptor<MultiValueTable<String, String>> multiValueTableCaptor() {
    return (ArgumentCaptor<MultiValueTable<String, String>>)
        (ArgumentCaptor<?>) ArgumentCaptor.forClass(MultiValueTable.class);
  }

  private BodyWriteCapture captureBodyWrite() throws Exception {
    ArgumentCaptor<byte[]> body = ArgumentCaptor.forClass(byte[].class);
    ArgumentCaptor<Integer> offset = ArgumentCaptor.forClass(Integer.class);
    ArgumentCaptor<Integer> length = ArgumentCaptor.forClass(Integer.class);

    verify(ctx).writeData(body.capture(), offset.capture(), length.capture());

    return new BodyWriteCapture(
        new String(body.getValue(), StandardCharsets.UTF_8), offset.getValue(), length.getValue());
  }

  private void assertForbiddenBody() throws Exception {
    ReplyHeadersCapture replyHeaders = captureReplyHeaders();
    assertEquals(403, replyHeaders.statusCode());
    assertEquals("Forbidden", replyHeaders.reasonPhrase());
    assertEquals("application/json; charset=UTF-8", replyHeaders.mimeType());
    BodyWriteCapture bodyWrite = captureBodyWrite();
    assertEquals(
        "{\"error\":{\"code\":\"forbidden\",\"message\":\"Valid form password is required.\"}}",
        bodyWrite.bodyText());
  }

  private static AppBrowserSession alphaBrowserSession(List<String> permissions) {
    Instant issuedAt = Instant.parse("2026-04-28T10:00:00Z");
    return new AppBrowserSession("alpha", permissions, issuedAt, issuedAt.plusSeconds(3600));
  }

  private static AppBrowserSession alphaBrowserSession(
      List<String> permissions, String expectedOrigin) {
    Instant issuedAt = Instant.parse("2026-04-28T10:00:00Z");
    return new AppBrowserSession(
        "alpha",
        permissions,
        issuedAt,
        issuedAt.plusSeconds(3600),
        expectedOrigin,
        AppUiOriginMode.ISOLATED_LOOPBACK);
  }

  private static AppUiOriginBinding isolatedBinding(String appId, int port) {
    String origin = "http://127.0.0.1:" + port;
    return new AppUiOriginBinding(
        appId,
        AppUiOriginMode.ISOLATED_LOOPBACK,
        AppUiOriginStatus.ACTIVE,
        origin,
        origin + "/",
        origin + "/static/",
        origin + "/static/",
        "http://127.0.0.1:8888/api/v1/",
        "http://127.0.0.1:8888/app/node/",
        "/apps/" + appId + "/",
        null);
  }

  private static AppUiOriginRegistry registryWith(AppUiOriginBinding... bindings) {
    return new AppUiOriginRegistry() {
      @Override
      public Optional<AppUiOriginBinding> bindingForApp(String appId) {
        return Arrays.stream(bindings).filter(binding -> binding.appId().equals(appId)).findFirst();
      }

      @Override
      public Optional<AppUiOriginBinding> bindingForOrigin(String origin) {
        return Arrays.stream(bindings)
            .filter(binding -> origin != null && origin.equals(binding.origin()))
            .findFirst();
      }
    };
  }

  private record ReplyHeadersCapture(
      int statusCode,
      String reasonPhrase,
      MultiValueTable<String, String> headers,
      String mimeType,
      long length) {}

  private record BodyWriteCapture(String bodyText, int offset, int length) {}
}
