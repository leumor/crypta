package network.crypta.clients.http;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import network.crypta.platform.api.PlatformApiRouter;
import network.crypta.platform.appdist.AppUiMode;
import network.crypta.platform.apphost.AppHost;
import network.crypta.platform.apphost.AppTokenPrincipal;
import network.crypta.platform.apphost.InstalledAppPaths;
import network.crypta.platform.apphost.InstalledAppSnapshot;
import network.crypta.platform.apphost.manifest.AppManifest;
import network.crypta.platform.appui.AppBrowserSessionStore;
import network.crypta.platform.appui.AppUiOrigin;
import network.crypta.platform.appui.AppUiOriginBinding;
import network.crypta.platform.appui.AppUiOriginRegistry;
import network.crypta.platform.appvault.AppVaultService;
import network.crypta.runtime.spi.RuntimePorts;
import network.crypta.support.MultiValueTable;
import network.crypta.support.api.HTTPRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Answers;
import org.mockito.ArgumentCaptor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Actual HTTP bridge, router, browser-session store and vault admission with mocked host lifecycle.
 * Request/context objects model the parsed transport boundary; no socket, browser or child process
 * execution is claimed by this suite.
 */
class MailHttpAdmissionTest {
  private static final String MAIL = "mail-prototype";
  private static final String OTHER = "other-app";
  private static final String CURRENT_TOKEN = "PUBLIC-SYNTHETIC-CURRENT-PROCESS-CANARY";
  private static final String OLD_TOKEN = "PUBLIC-SYNTHETIC-OLD-PROCESS-CANARY";
  private static final String CANARY = "PUBLIC-SYNTHETIC-PRIVATE-MAIL-CONTENT-CANARY";
  private static final List<String> PERMISSIONS =
      List.of(
          "mail.control",
          "vault.identities.create",
          "vault.mail.sign",
          "vault.mail.open",
          "vault.mail.storage");
  @TempDir Path root;
  private final MutableClock clock = new MutableClock();
  private final AtomicBoolean oldLaunchActive = new AtomicBoolean(true);
  private AppVaultService vault;
  private AppBrowserSessionStore sessions;
  private PlatformApiToadlet bridge;
  private String mailSession;
  private String otherSession;
  private String mailOrigin;
  private String otherOrigin;

  @BeforeEach
  void setUp() throws Exception {
    var host = mock(AppHost.class);
    var mail = installed(MAIL);
    var other = installed(OTHER);
    when(host.describe(MAIL)).thenReturn(Optional.of(mail));
    when(host.describe(OTHER)).thenReturn(Optional.of(other));
    var current = new AppTokenPrincipal(MAIL, PERMISSIONS, "current-launch", "0.1.0");
    var old = new AppTokenPrincipal(MAIL, PERMISSIONS, "old-launch", "0.1.0");
    when(host.currentLaunch(MAIL))
        .thenAnswer(_ -> Optional.of(oldLaunchActive.get() ? old : current));
    when(host.authenticateLaunchToken(anyString()))
        .thenAnswer(
            invocation -> {
              String token = invocation.getArgument(0);
              if (OLD_TOKEN.equals(token) && oldLaunchActive.get()) return Optional.of(old);
              if (CURRENT_TOKEN.equals(token) && !oldLaunchActive.get())
                return Optional.of(current);
              return Optional.empty();
            });
    var mailBinding = binding(mail, 19001);
    var otherBinding = binding(other, 19002);
    var origins = origins(List.of(mailBinding, otherBinding));
    // Inject only the clock through the existing test constructor; token generation and expiry
    // verification remain the production AppBrowserSessionStore implementation.
    var constructor =
        AppBrowserSessionStore.class.getDeclaredConstructor(
            AppHost.class, Clock.class, SecureRandom.class, Duration.class, int.class);
    constructor.setAccessible(true);
    sessions = constructor.newInstance(host, clock, new SecureRandom(), Duration.ofHours(1), 8);
    mailSession = sessions.issue(mail, mailBinding).token();
    otherSession = sessions.issue(other, otherBinding).token();
    mailOrigin = mailBinding.origin();
    otherOrigin = otherBinding.origin();
    vault = AppVaultService.open(root.resolve("vault"));
    RuntimePorts ports =
        mock(
            RuntimePorts.class,
            invocation -> {
              Object value = Answers.RETURNS_DEFAULTS.answer(invocation);
              if (value != null || invocation.getMethod().getReturnType().isPrimitive())
                return value;
              Class<?> type = invocation.getMethod().getReturnType();
              return type.isInterface() ? mock(type) : null;
            });
    var router = new PlatformApiRouter(ports, host, null, null, origins, vault);
    bridge = new PlatformApiToadlet(router, host, sessions, origins);
  }

  private static AppUiOriginRegistry origins(List<AppUiOriginBinding> bindings) {
    return new AppUiOriginRegistry() {
      @Override
      public Optional<AppUiOriginBinding> bindingForApp(String app) {
        return bindings.stream().filter(value -> value.appId().equals(app)).findFirst();
      }

      @Override
      public Optional<AppUiOriginBinding> bindingForOrigin(String origin) {
        return bindings.stream().filter(value -> value.origin().equals(origin)).findFirst();
      }
    };
  }

  @Test
  void ownBrowserReachesBrokerButHostileAndOtherOriginsCannotSubmitOrCreateVaultIdentity()
      throws Exception {
    for (var headers :
        List.of(
            Map.of("x-crypta-app-session", mailSession, "origin", "https://hostile.invalid"),
            Map.of("x-crypta-app-session", mailSession, "origin", otherOrigin),
            Map.of("x-crypta-app-session", otherSession, "origin", otherOrigin),
            Map.of("x-crypta-app-session", mailSession))) {
      assertDenied(call("command", headers, command()), 403);
      assertDenied(
          call(
              "create-identity",
              headers,
              Map.of("kind", "mail-signing-v1", "payloadBase64", encodedCanary())),
          403);
      assertNoMutation();
    }
    var accepted =
        call(
            "command",
            Map.of("x-crypta-app-session", mailSession, "origin", mailOrigin),
            command());
    assertEquals(200, accepted.status());
    assertTrue(accepted.body().contains("requestId"));
    var polled = call("poll", Map.of("x-crypta-app-token", OLD_TOKEN), Map.of());
    assertEquals(200, polled.status());
    assertTrue(polled.body().contains(encodedCanary()));
    var idMatch =
        java.util.regex.Pattern.compile("\"requestId\":\"([^\"]+)\"").matcher(accepted.body());
    assertTrue(idMatch.find());
    String requestId = idMatch.group(1);
    assertEquals(
        200,
        call(
                "reply",
                Map.of("x-crypta-app-token", OLD_TOKEN),
                Map.of("requestId", requestId, "payloadBase64", encodedCanary()))
            .status());
    for (var headers :
        List.of(
            Map.of("x-crypta-app-session", otherSession, "origin", otherOrigin),
            Map.of("x-crypta-app-session", mailSession, "origin", "https://hostile.invalid"))) {
      assertDenied(call("result", headers, Map.of("requestId", requestId)), 403);
    }
    var result =
        call(
            "result",
            Map.of("x-crypta-app-session", mailSession, "origin", mailOrigin),
            Map.of("requestId", requestId));
    assertEquals(200, result.status());
    assertTrue(result.body().contains(encodedCanary()));
    assertTrue(vault.listIdentities().isEmpty());
  }

  @Test
  void expiredRealSessionAndStaleLaunchCredentialFailBeforeBrokerOrVaultMutation()
      throws Exception {
    assertTrue(sessions.verify(mailSession).isPresent());
    assertEquals(200, call("poll", Map.of("x-crypta-app-token", OLD_TOKEN), Map.of()).status());
    clock.time = clock.time.plusSeconds(3600);
    oldLaunchActive.set(false);

    for (var headers :
        List.of(
            Map.of("x-crypta-app-session", mailSession, "origin", mailOrigin),
            Map.of("x-crypta-app-token", OLD_TOKEN),
            Map.of("authorization", "Bearer " + OLD_TOKEN, "origin", mailOrigin))) {
      assertDenied(call("command", headers, command()), 401);
      assertDenied(
          call(
              "create-identity",
              headers,
              Map.of("kind", "mail-signing-v1", "payloadBase64", encodedCanary())),
          401);
      assertNoMutation();
    }
    assertFalse(sessions.verify(mailSession).isPresent());
    var created =
        call(
            "create-identity",
            Map.of("x-crypta-app-token", CURRENT_TOKEN),
            Map.of("kind", "mail-signing-v1"));
    assertEquals(200, created.status());
    assertEquals(1, vault.listIdentities().size());
  }

  @Test
  void ownBrowserCannotInvokePrivateCryptoAndDeniedFramesDoNotEchoCanaries() throws Exception {
    var headers = Map.of("x-crypta-app-session", mailSession, "origin", mailOrigin);
    for (String operation : List.of("sign", "open", "seal-storage", "open-storage")) {
      assertDenied(
          call(operation, headers, Map.of("identityId", CANARY, "payloadBase64", encodedCanary())),
          403);
      assertNoMutation();
    }
  }

  private void assertNoMutation() throws Exception {
    assertTrue(vault.listIdentities().isEmpty());
    String token = oldLaunchActive.get() ? OLD_TOKEN : CURRENT_TOKEN;
    var polled = call("poll", Map.of("x-crypta-app-token", token), Map.of());
    assertEquals(200, polled.status());
    assertTrue(polled.body().contains("idle"), polled.body());
    assertFalse(polled.body().contains("requestId"));
  }

  private void assertDenied(Reply reply, int status) {
    assertEquals(status, reply.status(), reply.body());
    assertFalse(reply.body().contains(CANARY));
    assertFalse(reply.body().contains(encodedCanary()));
    for (String secret :
        List.of(mailSession, otherSession, CURRENT_TOKEN, OLD_TOKEN, root.toString()))
      assertFalse(reply.body().contains(secret));
    assertFalse(reply.body().contains("payloadBase64"));
    assertFalse(reply.body().contains("requestId"));
  }

  private Reply call(String action, Map<String, String> headers, Map<String, String> parameters)
      throws Exception {
    var request = mock(HTTPRequest.class);
    when(request.getHeader(anyString()))
        .thenAnswer(invocation -> headers.get(invocation.getArgument(0, String.class)));
    when(request.getParameterNames()).thenReturn(List.copyOf(parameters.keySet()));
    when(request.getMultipleParam(anyString()))
        .thenAnswer(
            invocation -> new String[] {parameters.get(invocation.getArgument(0, String.class))});
    var context = mock(ToadletContext.class);
    bridge.handleMethodPOST(
        URI.create("http://127.0.0.1:8888/api/v1/mail/" + action), request, context);
    var status = ArgumentCaptor.forClass(Integer.class);
    var reason = ArgumentCaptor.forClass(String.class);
    @SuppressWarnings("unchecked")
    ArgumentCaptor<MultiValueTable<String, String>> responseHeaders =
        (ArgumentCaptor<MultiValueTable<String, String>>)
            (ArgumentCaptor<?>) ArgumentCaptor.forClass(MultiValueTable.class);
    verify(context)
        .sendReplyHeaders(
            status.capture(),
            reason.capture(),
            responseHeaders.capture(),
            org.mockito.ArgumentMatchers.anyString(),
            org.mockito.ArgumentMatchers.anyLong());
    var bytes = ArgumentCaptor.forClass(byte[].class);
    var offset = ArgumentCaptor.forClass(Integer.class);
    var length = ArgumentCaptor.forClass(Integer.class);
    verify(context).writeData(bytes.capture(), offset.capture(), length.capture());
    return new Reply(
        status.getValue(),
        new String(bytes.getValue(), offset.getValue(), length.getValue(), StandardCharsets.UTF_8));
  }

  private InstalledAppSnapshot installed(String app) throws Exception {
    var manifest =
        new AppManifest(
            1,
            app,
            "Synthetic Mail admission",
            "0.1.0",
            "bin/launch.sh",
            AppUiMode.STATIC,
            "index.html",
            PERMISSIONS,
            null,
            null);
    var paths =
        new InstalledAppPaths(
            app,
            root.resolve(app + "-installed"),
            root.resolve(app + "-data"),
            root.resolve(app + "-cache"),
            root.resolve(app + "-run"));
    Files.createDirectories(paths.installedRoot());
    return new InstalledAppSnapshot(manifest, paths);
  }

  private static AppUiOriginBinding binding(InstalledAppSnapshot app, int port) {
    return AppUiOriginBinding.isolatedLoopback(
        app.manifest(),
        AppUiOrigin.loopback(app.appId(), port),
        "http://127.0.0.1:8888/api/v1/",
        "http://127.0.0.1:8888/app/node/");
  }

  private static Map<String, String> command() {
    return Map.of("command", "status", "payloadBase64", encodedCanary());
  }

  private static String encodedCanary() {
    return Base64.getEncoder()
        .encodeToString(("{\"note\":\"" + CANARY + "\"}").getBytes(StandardCharsets.UTF_8));
  }

  private record Reply(int status, String body) {}

  private static final class MutableClock extends Clock {
    Instant time = Instant.parse("2026-09-10T12:00:00Z");

    @Override
    public ZoneId getZone() {
      return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(ZoneId zone) {
      return this;
    }

    @Override
    public Instant instant() {
      return time;
    }
  }
}
