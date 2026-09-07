package network.crypta.platform.devtools.devserver;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpContext;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpPrincipal;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import network.crypta.platform.api.PlatformApiBaselineRegistry;
import network.crypta.platform.api.PlatformApiContract;
import network.crypta.platform.api.PlatformApiContractJson;
import network.crypta.platform.appdist.AppDistributionException;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class MockPlatformApiFixturesTest {
  @TempDir private Path tempDir;

  @Test
  void profileRoute_whenVerifiedBySdk_expectSignedAppAndIdentityBinding() throws Exception {
    boolean nodeAvailable;
    try {
      Process probe = new ProcessBuilder("node", "--version").start();
      nodeAvailable = probe.waitFor(5, TimeUnit.SECONDS) && probe.exitValue() == 0;
      if (probe.isAlive()) probe.destroyForcibly();
    } catch (IOException _) {
      nodeAvailable = false;
    }
    Assumptions.assumeTrue(nodeAvailable, "Node.js is required for SDK behavior tests.");
    Path sdk = tempDir.resolve("sdk.js");
    try (InputStream resource =
        getClass().getResourceAsStream("/network/crypta/platform/sdk/js/crypta-platform.js")) {
      Files.copy(java.util.Objects.requireNonNull(resource), sdk);
    }
    Path script = tempDir.resolve("verify.cjs");
    Files.writeString(
        script,
        """
        const fs = require('node:fs');
        const vm = require('node:vm');
        const assert = require('node:assert/strict');
        const {webcrypto} = require('node:crypto');
        const context = {TextEncoder, TextDecoder, Uint8Array,
          window: {crypto: webcrypto, atob, TextEncoder}};
        vm.createContext(context);
        vm.runInContext(fs.readFileSync(process.argv[2], 'utf8'), context);
        (async () => {
          const response = JSON.parse(fs.readFileSync(process.argv[3], 'utf8'));
          assert.equal(response.mock, true);
          const document = await context.window.CryptaPlatform.profile.verifyDocument(response.profileDocument);
          assert.equal(document.profile.appId, process.argv[4]);
          assert.equal(document.profile.identityId, 'local-profile');
          assert.equal(document.profile.displayName, 'Local Profile');
          document.profile.displayName = 'Not signed';
          await assert.rejects(() => context.window.CryptaPlatform.profile.verifyDocument(document));
        })().catch(error => { console.error(error); process.exitCode = 1; });
        """);
    for (String appId : java.util.List.of("profile-publisher", "social-inbox")) {
      MockPlatformApiFixtures fixtures =
          new MockPlatformApiFixtures(tempDir, appId, "Synthetic App", "1.0");
      MockPlatformApi api = new MockPlatformApi("mock-session"::equals, fixtures);
      TestHttpExchange exchange =
          TestHttpExchange.post(
              "/api/v1/app-vault/identities/local-profile/profile-document",
              "displayName=Local+Profile");
      api.handle(exchange);
      assertEquals(200, exchange.responseCode());
      assertEquals(fixtures.profileDocument("local-profile"), exchange.responseBody());
      Path response = tempDir.resolve(appId + ".json");
      Files.writeString(response, exchange.responseBody());
      Path log = tempDir.resolve(appId + ".log");
      Process process =
          new ProcessBuilder("node", script.toString(), sdk.toString(), response.toString(), appId)
              .redirectErrorStream(true)
              .redirectOutput(log.toFile())
              .start();
      boolean finished = process.waitFor(30, TimeUnit.SECONDS);
      if (!finished) process.destroyForcibly();
      assertTrue(finished, "SDK verification timed out.");
      assertEquals(0, process.exitValue(), Files.readString(log));
    }
  }

  @Test
  void appsCurrent_whenFixtureMissing_expectDefaultWithEscapedAppPlaceholders() throws Exception {
    Files.createDirectories(tempDir);
    MockPlatformApiFixtures fixtures =
        new MockPlatformApiFixtures(tempDir, "sample-app", "Name \"One\"", "0.1\\beta");

    String json = fixtures.appsCurrent();

    assertTrue(json.contains("\"appId\":\"sample-app\""));
    assertTrue(json.contains("\"name\":\"Name \\\"One\\\"\""));
    assertTrue(json.contains("\"version\":\"0.1\\\\beta\""));
  }

  @Test
  void platformContract_whenFixtureMissing_expectCurrentContractEnvelope() throws Exception {
    Files.createDirectories(tempDir);
    MockPlatformApiFixtures fixtures =
        new MockPlatformApiFixtures(tempDir, "sample-app", "Sample App", "0.1.0");
    MockPlatformApi api = new MockPlatformApi("mock-session"::equals, fixtures);
    TestHttpExchange contractRequest = TestHttpExchange.get();

    api.handle(contractRequest);
    String body = contractRequest.responseBody();

    assertEquals(200, contractRequest.responseCode());
    assertEquals(
        PlatformApiContractJson.writeEnvelope(
            PlatformApiContract.current(), PlatformApiBaselineRegistry.current()),
        body);
    assertTrue(body.contains("\"generatedBy\""));
    assertTrue(body.contains("\"stabilityPolicy\""));
    assertTrue(body.contains("\"capabilities\""));
    assertTrue(body.contains("\"endpoints\""));
    assertTrue(body.contains("\"baselineRegistrySummary\""));
    assertTrue(body.contains("\"supportedBaselines\""));
    assertTrue(body.contains("\"id\":\"1.0\""));
    assertFalse(body.contains("browserSessionToken"));
    assertFalse(body.contains("privateKey"));
    assertFalse(body.contains("/work/"));
  }

  @Test
  void platformContract_whenFixtureContainsRouteTemplates_expectAccepted() throws Exception {
    String contract = PlatformApiContractJson.writeEnvelope(PlatformApiContract.current());
    Files.writeString(tempDir.resolve("platform-contract.json"), contract, StandardCharsets.UTF_8);
    MockPlatformApiFixtures fixtures =
        new MockPlatformApiFixtures(tempDir, "sample-app", "Sample App", "0.1.0");

    String json = fixtures.platformContract();

    assertEquals(contract, json);
    assertTrue(json.contains("\"routeTemplate\":\"/platform/contract\""));
  }

  @Test
  void platformContract_whenFixtureContainsNonRouteAbsolutePath_expectRejected() throws Exception {
    String contract =
        PlatformApiContractJson.writeEnvelope(PlatformApiContract.current())
            .replace("\"generatedBy\":\"cryptad\"", "\"generatedBy\":\"/Users/alice/cryptad\"");
    Files.writeString(tempDir.resolve("platform-contract.json"), contract, StandardCharsets.UTF_8);
    MockPlatformApiFixtures fixtures =
        new MockPlatformApiFixtures(tempDir, "sample-app", "Sample App", "0.1.0");

    AppDistributionException exception =
        assertThrows(AppDistributionException.class, fixtures::platformContract);

    assertTrue(exception.getMessage().contains("fixture output contains an absolute local path"));
  }

  @Test
  void platformContract_whenFixtureRouteTemplateContainsLocalPath_expectRejected()
      throws Exception {
    String contract =
        PlatformApiContractJson.writeEnvelope(PlatformApiContract.current())
            .replace(
                "\"routeTemplate\":\"/platform/contract\"",
                "\"routeTemplate\":\"/home/alice/.crypta/private-route\"");
    Files.writeString(tempDir.resolve("platform-contract.json"), contract, StandardCharsets.UTF_8);
    MockPlatformApiFixtures fixtures =
        new MockPlatformApiFixtures(tempDir, "sample-app", "Sample App", "0.1.0");

    AppDistributionException exception =
        assertThrows(AppDistributionException.class, fixtures::platformContract);

    assertTrue(exception.getMessage().contains("fixture output contains an absolute local path"));
  }

  @Test
  void appVaultAndDocumentMocks_whenDefaultsRequested_expectDeterministicSafeResponses()
      throws Exception {
    Files.createDirectories(tempDir);
    MockPlatformApiFixtures fixtures =
        new MockPlatformApiFixtures(tempDir, "sample-app", "Sample App", "0.1.0");

    String identities = fixtures.vaultIdentities();
    String profileDocument = fixtures.profileDocument("local-profile");
    String socialMessage = fixtures.socialMessage("local-profile");
    MockPlatformApi api = new MockPlatformApi("mock-session"::equals, fixtures);
    TestHttpExchange createdIdentity =
        TestHttpExchange.post(
            "/api/v1/app-vault/identities",
            "label=Local+Profile&scopes=metadata.read%2Csign.domain-separated");
    TestHttpExchange socialMessagePost =
        TestHttpExchange.post(
            "/api/v1/app-vault/identities/local-profile/social-message",
            "body=Hello+from+the+mock+route");
    TestHttpExchange appDocumentInsert =
        TestHttpExchange.post(
            "/api/v1/queue/inserts/app-document",
            "insertUri=CHK%40sample&identifier=profile-local&documentBase64=e30%3D");
    api.handle(createdIdentity);
    api.handle(socialMessagePost);
    api.handle(appDocumentInsert);
    String createdIdentityBody = createdIdentity.responseBody();
    String socialMessageBody = socialMessagePost.responseBody();
    String appDocumentInsertBody = appDocumentInsert.responseBody();

    assertTrue(identities.contains("\"identityId\":\"local-profile\""));
    assertTrue(
        identities.contains("\"usageScopes\":[\"metadata.read\",\"sign.domain-separated\"]"));
    assertEquals(201, createdIdentity.responseCode());
    assertTrue(createdIdentityBody.contains("\"action\":\"app-vault.identities.create\""));
    assertTrue(createdIdentityBody.contains("\"identityId\":\"mock-created-profile\""));
    assertTrue(profileDocument.contains("\"action\":\"app-vault.identities.profile-document\""));
    assertTrue(profileDocument.contains("\"identityId\":\"local-profile\""));
    assertTrue(
        profileDocument.contains(
            "\"fingerprint\":\"06e3fd8fda29bb60ab59557de61edb0aecdb231134be30e75b455f8e1b792fa9\""));
    assertTrue(socialMessage.contains("\"action\":\"app-vault.identities.social-message\""));
    assertTrue(socialMessage.contains("\"type\":\"crypta.social.message.v1\""));
    assertTrue(socialMessage.contains("\"identityId\":\"local-profile\""));
    assertTrue(
        socialMessage.contains(
            "\"messageId\":\"msg-1270c1caf9a8c647f1b3292b53740e1cf401e229cf8034cf2ecdb528ad75e714\""));
    assertFalse(socialMessage.contains("mock-social-message"));
    assertEquals(200, socialMessagePost.responseCode());
    assertTrue(socialMessageBody.contains("\"action\":\"app-vault.identities.social-message\""));
    assertTrue(socialMessageBody.contains("\"domain\":\"crypta.social.message.v1\""));
    assertTrue(socialMessageBody.contains("\"identityId\":\"local-profile\""));
    assertTrue(
        socialMessageBody.contains(
            "\"messageId\":\"msg-1270c1caf9a8c647f1b3292b53740e1cf401e229cf8034cf2ecdb528ad75e714\""));
    assertEquals(200, appDocumentInsert.responseCode());
    assertTrue(appDocumentInsertBody.contains("\"action\":\"queue.inserts.app-document\""));
    assertTrue(appDocumentInsertBody.contains("\"uri\":\"CHK@mock-app-document\""));
    assertFalse(profileDocument.contains("privateKey"));
    assertFalse(socialMessageBody.contains("privateKey"));
    assertFalse(socialMessageBody.contains("browserSessionToken"));
    assertFalse(appDocumentInsertBody.contains("browserSessionToken"));
  }

  @Test
  void trustGraphMocks_whenDefaultsRequested_expectDeterministicPreviewResponses()
      throws Exception {
    Files.createDirectories(tempDir);
    MockPlatformApiFixtures fixtures =
        new MockPlatformApiFixtures(tempDir, "trust-graph", "Trust Graph Preview", "0.1.0");

    String status = fixtures.trustGraphStatus();
    String anchors = fixtures.trustGraphAnchors();
    String score = fixtures.trustGraphScore();
    String statement = fixtures.trustStatement("local-profile");

    assertTrue(status.contains("\"service\":\"trust-graph-preview\""));
    assertTrue(status.contains("\"completeWot\":false"));
    assertTrue(anchors.contains("\"issuerFingerprint\":\"mock-profile-fingerprint\""));
    assertTrue(score.contains("\"status\":\"trusted\""));
    assertTrue(score.contains("\"contributingEvidenceCount\":1"));
    assertTrue(statement.contains("\"trustStatement\":{\"identity\""));
    assertTrue(statement.contains("\"action\":\"app-vault.identities.trust-statement\""));
    assertTrue(statement.contains("\"type\":\"crypta.trust.statement.v1\""));
    assertTrue(statement.contains("\"appId\":\"trust-graph\""));
    assertFalse(statement.startsWith("{\"identity\""));
    assertFalse(status.contains("browserSessionToken"));
    assertFalse(anchors.contains("privateKey"));
    assertFalse(score.contains("rawRequestBody"));
    assertFalse(statement.contains("privateKey"));
    assertFalse(statement.contains("/work/"));
  }

  @Test
  void socialMessagePost_whenBodyMissing_expectDeterministicBadRequest() throws Exception {
    Files.createDirectories(tempDir);
    MockPlatformApiFixtures fixtures =
        new MockPlatformApiFixtures(tempDir, "sample-app", "Sample App", "0.1.0");
    MockPlatformApi api = new MockPlatformApi("mock-session"::equals, fixtures);
    TestHttpExchange socialMessagePost =
        TestHttpExchange.post(
            "/api/v1/app-vault/identities/local-profile/social-message", "subject=Missing+body");

    api.handle(socialMessagePost);
    String responseBody = socialMessagePost.responseBody();

    assertEquals(400, socialMessagePost.responseCode());
    assertTrue(responseBody.contains("\"code\":\"invalid_mock_form\""));
    assertTrue(responseBody.contains("Missing required form field 'body'"));
    assertFalse(responseBody.contains("browserSessionToken"));
    assertFalse(responseBody.contains("privateKey"));
  }

  @Test
  void node_whenFixtureContainsAbsoluteUnixPath_expectRejected() throws Exception {
    Files.writeString(
        tempDir.resolve("node.json"),
        "{\"path\":\"/Users/alice/private/node.json\"}",
        StandardCharsets.UTF_8);
    MockPlatformApiFixtures fixtures =
        new MockPlatformApiFixtures(tempDir, "sample-app", "Sample App", "0.1.0");

    AppDistributionException exception =
        assertThrows(AppDistributionException.class, fixtures::node);

    assertTrue(exception.getMessage().contains("fixture output contains an absolute local path"));
  }

  @Test
  void queue_whenFixtureDirectoryIsSymlink_expectRejected() throws Exception {
    Path realFixtureDir = tempDir.resolve("fixtures");
    Path linkedFixtureDir = tempDir.resolve("linked-fixtures");
    Files.createDirectories(realFixtureDir);
    try {
      Files.createSymbolicLink(linkedFixtureDir, realFixtureDir);
    } catch (UnsupportedOperationException | SecurityException exception) {
      org.junit.jupiter.api.Assumptions.assumeTrue(
          false, "symlink creation unavailable: " + exception.getMessage());
    }
    MockPlatformApiFixtures fixtures =
        new MockPlatformApiFixtures(linkedFixtureDir, "sample-app", "Sample App", "0.1.0");

    AppDistributionException exception =
        assertThrows(AppDistributionException.class, fixtures::queue);

    assertTrue(exception.getMessage().contains("fixture directory must be a real directory"));
    assertFalse(Files.exists(realFixtureDir.resolve("queue.json")));
  }

  private static final class TestHttpExchange extends HttpExchange {
    private final Headers requestHeaders = new Headers();
    private final Headers responseHeaders = new Headers();
    private final Map<String, Object> attributes = new HashMap<>();
    private final String method;
    private final URI requestUri;
    private InputStream requestBody;
    private OutputStream responseBody = new ByteArrayOutputStream();
    private int responseCode;

    private TestHttpExchange(String method, String path, String body) {
      this.method = method;
      this.requestUri = URI.create(path);
      this.requestBody = new ByteArrayInputStream(body.getBytes(StandardCharsets.UTF_8));
      requestHeaders.add(MockPlatformApi.SESSION_HEADER, "mock-session");
    }

    private static TestHttpExchange get() {
      return new TestHttpExchange("GET", "/api/v1/platform/contract", "");
    }

    private static TestHttpExchange post(String path, String body) {
      return new TestHttpExchange("POST", path, body);
    }

    private int responseCode() {
      return responseCode;
    }

    private String responseBody() {
      if (responseBody instanceof ByteArrayOutputStream buffer) {
        return buffer.toString(StandardCharsets.UTF_8);
      }
      throw new IllegalStateException("Test response body is not backed by an in-memory buffer.");
    }

    @Override
    public Headers getRequestHeaders() {
      return requestHeaders;
    }

    @Override
    public Headers getResponseHeaders() {
      return responseHeaders;
    }

    @Override
    public URI getRequestURI() {
      return requestUri;
    }

    @Override
    public String getRequestMethod() {
      return method;
    }

    @Override
    public HttpContext getHttpContext() {
      throw new UnsupportedOperationException();
    }

    @Override
    public void close() {
      closeStream(requestBody);
      closeStream(responseBody);
    }

    @Override
    public InputStream getRequestBody() {
      return requestBody;
    }

    @Override
    public OutputStream getResponseBody() {
      return responseBody;
    }

    @Override
    public void sendResponseHeaders(int responseCode, long responseLength) {
      this.responseCode = responseCode;
    }

    @Override
    public InetSocketAddress getRemoteAddress() {
      return InetSocketAddress.createUnresolved("127.0.0.1", 1);
    }

    @Override
    public int getResponseCode() {
      return responseCode;
    }

    @Override
    public InetSocketAddress getLocalAddress() {
      return InetSocketAddress.createUnresolved("127.0.0.1", 2);
    }

    @Override
    public String getProtocol() {
      return "HTTP/1.1";
    }

    @Override
    public Object getAttribute(String name) {
      return attributes.get(name);
    }

    @Override
    public void setAttribute(String name, Object value) {
      attributes.put(name, value);
    }

    @Override
    public void setStreams(InputStream input, OutputStream output) {
      if (input != null) {
        requestBody = input;
      }
      if (output != null) {
        responseBody = output;
      }
    }

    @Override
    public HttpPrincipal getPrincipal() {
      return null;
    }

    private static void closeStream(Closeable stream) {
      try {
        stream.close();
      } catch (IOException exception) {
        throw new UncheckedIOException(exception);
      }
    }
  }
}
