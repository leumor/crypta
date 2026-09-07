package network.crypta.platform.api;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;
import network.crypta.crypt.mail.MailWire;
import network.crypta.platform.apphost.AppHost;
import network.crypta.platform.apphost.AppTokenPrincipal;
import network.crypta.platform.appui.AppUiOriginRegistry;
import network.crypta.platform.appvault.AppIdentityKind;
import network.crypta.platform.appvault.AppIdentityRecord;
import network.crypta.platform.appvault.AppVaultService;
import network.crypta.runtime.spi.RuntimePorts;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Answers;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Route and real-vault checks; mocked lifecycle is not child-process or origin-transport evidence.
 */
class PlatformApiMailRoutesTest {
  private static final String APP = "mail-prototype";
  private static final List<String> PERMISSIONS =
      List.of(
          "mail.control",
          "vault.identities.create",
          "vault.mail.sign",
          "vault.mail.open",
          "vault.mail.storage");
  @TempDir Path root;
  private AppHost host;
  private AppVaultService vault;
  private PlatformApiRouter router;

  @BeforeEach
  void setUp() throws Exception {
    host = mock(AppHost.class);
    launch("current", PERMISSIONS);
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
    router =
        new PlatformApiRouter(ports, host, null, null, AppUiOriginRegistry.sameOriginOnly(), vault);
  }

  @Test
  void ownBrowserCanExchangeFixedCommandsWithCurrentProcessOnly() {
    var submitted =
        call(browser(APP), "command", Map.of("command", "status", "payloadBase64", "e30="));
    assertEquals(200, submitted.statusCode(), submitted.body());
    String id = field(submitted, "requestId");
    var polled = call(process(APP, "current", PERMISSIONS), "poll", Map.of());
    assertEquals(200, polled.statusCode(), polled.body());
    assertEquals(id, field(polled, "requestId"));
    assertEquals(403, call(browser("other-app"), "result", Map.of("requestId", id)).statusCode());
    assertEquals(
        403,
        call(
                process(APP, "old", PERMISSIONS),
                "reply",
                Map.of("requestId", id, "payloadBase64", "e30="))
            .statusCode());
    assertEquals(
        200,
        call(
                process(APP, "current", PERMISSIONS),
                "reply",
                Map.of("requestId", id, "payloadBase64", "e30="))
            .statusCode());
    var result = call(browser(APP), "result", Map.of("requestId", id));
    assertEquals("complete", field(result, "status"));
    assertEquals("e30=", field(result, "payloadBase64"));
    assertFalse(result.body().contains("current"));
    assertFalse(result.body().contains("privateKey"));
    assertEquals(409, call(browser(APP), "result", Map.of("requestId", id)).statusCode());
  }

  @Test
  void browserAndOtherAppCannotUsePrivateMailRoutes() {
    for (String action :
        List.of(
            "create-identity", "sign", "open", "seal-storage", "open-storage", "poll", "reply")) {
      assertEquals(403, call(browser(APP), action, Map.of()).statusCode(), action);
      assertEquals(
          403,
          call(process("other-app", "current", PERMISSIONS), action, Map.of()).statusCode(),
          action);
    }
    assertEquals(
        403,
        call(browser("other-app"), "command", Map.of("command", "status", "payloadBase64", ""))
            .statusCode());
    assertEquals(
        403,
        call(
                process(APP, "current", PERMISSIONS),
                "command",
                Map.of("command", "status", "payloadBase64", ""))
            .statusCode());
    assertTrue(vault.listIdentities().isEmpty());
  }

  @Test
  void stoppedReplacedAndPermissionChangedLaunchesCannotUseVault() {
    var request = Map.of("kind", AppIdentityKind.MAIL_STORAGE_V1.jsonValue());
    assertEquals(
        403, call(process(APP, "old", PERMISSIONS), "create-identity", request).statusCode());
    assertEquals(
        403,
        call(PlatformApiPrincipal.appToken(APP, PERMISSIONS), "create-identity", request)
            .statusCode());
    launch("current", List.of("mail.control"));
    assertEquals(
        403, call(process(APP, "current", PERMISSIONS), "create-identity", request).statusCode());
    when(host.currentLaunch(APP)).thenReturn(Optional.empty());
    assertEquals(
        403, call(process(APP, "current", PERMISSIONS), "create-identity", request).statusCode());
    assertTrue(vault.listIdentities().isEmpty());
  }

  @Test
  void currentProcessCreatesSignsAndProtectsStateWithoutExportingKeys() {
    var principal = process(APP, "current", PERMISSIONS);
    var signingCreated =
        call(
            principal,
            "create-identity",
            Map.of("kind", AppIdentityKind.MAIL_SIGNING_V1.jsonValue()));
    assertEquals(200, signingCreated.statusCode(), signingCreated.body());
    var created =
        call(
            principal,
            "create-identity",
            Map.of("kind", AppIdentityKind.MAIL_STORAGE_V1.jsonValue()));
    assertEquals(200, created.statusCode(), created.body());
    String storage = field(created, "identityId");
    assertFalse(created.body().contains("privateKey"));
    assertFalse(created.body().contains("seed"));
    byte[] text = "public synthetic state".getBytes(StandardCharsets.UTF_8);
    var sealed = call(principal, "seal-storage", payload(storage, text));
    assertEquals(200, sealed.statusCode(), sealed.body());
    var opened =
        call(
            principal,
            "open-storage",
            payload(storage, Base64.getDecoder().decode(field(sealed, "payloadBase64"))));
    assertEquals(200, opened.statusCode(), opened.body());
    assertEquals(Base64.getEncoder().encodeToString(text), field(opened, "payloadBase64"));
    AppIdentityRecord signing = vault.getIdentityForApp(APP, field(signingCreated, "identityId"));
    byte[] unsigned = message(signing);
    var signed = call(principal, "sign", payload(signing.identityId(), unsigned));
    assertEquals(200, signed.statusCode(), signed.body());
    byte[] wrapper = Base64.getDecoder().decode(field(signed, "payloadBase64"));
    assertTrue(
        MailWire.verify(
            MailWire.unbase64(signing.publicSummary().get("publicKeyBase64"), 32),
            MailWire.preimage(MailWire.MESSAGE, unsigned),
            MailWire.signature(wrapper)));
  }

  @Test
  void genericSigningPermissionAndRevokedGrantCannotDecryptState() {
    vault.createMailIdentity(APP, AppIdentityKind.MAIL_SIGNING_V1);
    var identity = vault.createMailIdentity(APP, AppIdentityKind.MAIL_STORAGE_V1);
    byte[] sealed = vault.sealStorage(APP, identity.identityId(), new byte[] {1, 2, 3});
    List<String> generic = List.of("vault.identities.use");
    launch("current", generic);
    assertEquals(
        403,
        call(
                process(APP, "current", generic),
                "open-storage",
                payload(identity.identityId(), sealed))
            .statusCode());
    launch("current", PERMISSIONS);
    vault.revokeGrantsForApp(APP);
    var denied =
        call(
            process(APP, "current", PERMISSIONS),
            "open-storage",
            payload(identity.identityId(), sealed));
    assertEquals(503, denied.statusCode(), denied.body());
    assertTrue(denied.body().contains("key_unavailable"), denied.body());
    assertFalse(denied.body().contains("AQID"));
  }

  @Test
  void stoppedWorkerNeverFallsBackToDaemonMailboxHandling() {
    when(host.currentLaunch(APP)).thenReturn(Optional.empty());
    assertEquals(
        409,
        call(browser(APP), "command", Map.of("command", "status", "payloadBase64", ""))
            .statusCode());
    assertEquals(
        409,
        call(browser(APP), "command", Map.of("command", "http://127.0.0.1", "payloadBase64", ""))
            .statusCode());
  }

  @Test
  void unknownQueryFieldsCannotExpandTheFixedChannel() {
    var response =
        call(
            browser(APP),
            "command",
            Map.of("command", "status", "payloadBase64", "", "endpoint", "http://127.0.0.1"));
    assertEquals(403, response.statusCode(), response.body());
    var identity =
        call(
            process(APP, "current", PERMISSIONS),
            "create-identity",
            Map.of("kind", AppIdentityKind.MAIL_SIGNING_V1.jsonValue(), "path", "/tmp/unused"));
    assertEquals(403, identity.statusCode(), identity.body());
    assertTrue(vault.listIdentities().isEmpty());
  }

  @Test
  void stopAfterPrivateOperationPreventsResponseRelease() {
    vault.createMailIdentity(APP, AppIdentityKind.MAIL_SIGNING_V1);
    var storage = vault.createMailIdentity(APP, AppIdentityKind.MAIL_STORAGE_V1);
    byte[] text = "public synthetic response fence".getBytes(StandardCharsets.UTF_8);
    byte[] envelope = vault.sealStorage(APP, storage.identityId(), text);
    when(host.currentLaunch(APP))
        .thenReturn(
            Optional.of(new AppTokenPrincipal(APP, PERMISSIONS, "current", "0.1.0")),
            Optional.empty());
    var response =
        call(
            process(APP, "current", PERMISSIONS),
            "open-storage",
            payload(storage.identityId(), envelope));
    assertEquals(403, response.statusCode(), response.body());
    assertFalse(response.body().contains(Base64.getEncoder().encodeToString(text)));
    assertFalse(response.body().contains("payloadBase64"));
  }

  private void launch(String id, List<String> permissions) {
    when(host.currentLaunch(APP))
        .thenReturn(Optional.of(new AppTokenPrincipal(APP, permissions, id, "0.1.0")));
  }

  private static PlatformApiPrincipal browser(String app) {
    return PlatformApiPrincipal.appBrowserSession(app, PERMISSIONS);
  }

  private static PlatformApiPrincipal process(String app, String launch, List<String> permissions) {
    return PlatformApiPrincipal.appToken(app, permissions, launch);
  }

  private PlatformApiResponse call(
      PlatformApiPrincipal principal, String action, Map<String, String> values) {
    var query = new LinkedHashMap<String, List<String>>();
    values.forEach((k, v) -> query.put(k, List.of(v)));
    return router.route(new PlatformApiRequest("POST", List.of("mail", action), query, principal));
  }

  private static Map<String, String> payload(String identity, byte[] bytes) {
    return Map.of(
        "identityId", identity, "payloadBase64", Base64.getEncoder().encodeToString(bytes));
  }

  private static String field(PlatformApiResponse response, String name) {
    var matcher =
        Pattern.compile("\"" + Pattern.quote(name) + "\":\"([^\"]*)\"").matcher(response.body());
    assertTrue(matcher.find(), response.body());
    return matcher.group(1);
  }

  private static byte[] message(AppIdentityRecord signing) {
    var m = new LinkedHashMap<String, String>();
    m.put("profile", MailWire.MESSAGE);
    m.put("messageId", "01".repeat(16));
    m.put("sender", signing.fingerprint());
    m.put("senderAccount", signing.publicSummary().get("account"));
    m.put("senderEpoch", "1");
    m.put("recipient", "02".repeat(32));
    m.put("recipientAccount", "03".repeat(16));
    m.put("recipientEpoch", "1");
    m.put("created", "100");
    m.put("expires", "200");
    m.put("subject", "Public synthetic subject");
    m.put("body", "Public synthetic body");
    m.put("format", "text/plain");
    return MailWire.messagePayload(m);
  }
}
