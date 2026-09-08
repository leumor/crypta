package network.crypta.apps.mail;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import network.crypta.crypt.mail.MailWire;
import network.crypta.platform.api.json.PlatformApiJsonWriter;
import network.crypta.platform.api.mail.MailWorkerBroker;
import network.crypta.platform.appdist.AppBundleSigner;
import network.crypta.platform.appdist.AppBundleVerifier;
import network.crypta.platform.appdist.TrustedAppKey;
import network.crypta.platform.appdist.TrustedAppKeys;
import network.crypta.platform.apphost.AppHostLayout;
import network.crypta.platform.apphost.AppInstallVerificationPolicy;
import network.crypta.platform.apphost.RunningAppSnapshot;
import network.crypta.platform.apphost.runtime.LocalProcessAppHost;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Real JVM workers and independent vaults with explicitly simulated CHK transport. */
class MailWorkerProcessTest {
  @TempDir Path root;

  @Test
  void malformedCommandsReturnBoundedFailureWithoutStoppingOrMutatingWorker() throws Exception {
    Map<String, byte[]> network = new ConcurrentHashMap<>();
    try (Endpoint endpoint = new Endpoint(root.resolve("invalid-command"), network)) {
      endpoint.start();
      assertEquals("ready", endpoint.command("initialize", Map.of()).get("status"));
      long pid = endpoint.child.pid();
      String backup = endpoint.command("backup", Map.of()).get("backup");
      endpoint.privateCanaries.add("MALFORMED_PRIVATE_CANARY");
      for (String json :
          java.util.List.of(
              "{\"unused\":[null]}",
              "{\"unused\":[null,\"MALFORMED_PRIVATE_CANARY\"]}",
              "{\"unused\":{\"nested\":null}}",
              "{\"unused\":null}",
              "{\"unused\":false}",
              "{\"unused\":1}",
              "[]",
              "null",
              "{\"unused\":[",
              "{\"a\":\"x\",\"a\":\"y\"}")) {
        assertEquals(
            Map.of("status", "invalid"),
            endpoint.rawCommand("status", json.getBytes(StandardCharsets.UTF_8)));
        assertEquals("ready", endpoint.command("status", Map.of()).get("status"));
        assertEquals(pid, endpoint.host.status("mail-prototype").orElseThrow().pid());
      }
      assertEquals(
          Map.of("status", "invalid"),
          endpoint.rawCommand("status", new byte[] {(byte) 0xc3, 0x28}));
      assertTrue(
          backup.equals(endpoint.command("backup", Map.of()).get("backup")),
          "Invalid command changed private state.");
      assertTrue(network.isEmpty());
    }
  }

  @Test
  void twoIndependentWorkersExchangeLiteralMailRestartDeduplicateAndReply() throws Exception {
    Map<String, byte[]> simulatedNetwork = new ConcurrentHashMap<>();
    String canary = "PUBLIC SYNTHETIC MAIL TEST <script>neverExecute()</script> \u2603";
    try (Endpoint alice = new Endpoint(root.resolve("alice"), simulatedNetwork);
        Endpoint bob = new Endpoint(root.resolve("bob"), simulatedNetwork)) {
      alice.start();
      bob.start();
      assertNotEquals(alice.child.pid(), bob.child.pid());
      assertNotEquals(ProcessHandle.current().pid(), alice.child.pid());
      alice.command("initialize", Map.of());
      bob.command("initialize", Map.of());
      String aliceCard = alice.command("export-contact", Map.of()).get("card");
      String bobCard = bob.command("export-contact", Map.of()).get("card");
      String bobFingerprint = approve(alice, bobCard);
      String aliceFingerprint = approve(bob, aliceCard);
      assertTrue(simulatedNetwork.isEmpty());

      String reference = send(alice, bobFingerprint, "Synthetic subject", canary);
      assertFalse(simulatedNetwork.isEmpty());
      assertTrue(
          simulatedNetwork.values().stream()
              .noneMatch(bytes -> new String(bytes, StandardCharsets.UTF_8).contains(canary)));
      Map<String, String> accepted =
          bob.command("import-reference", Map.of("reference", reference, "confirmed", "yes"));
      assertEquals("accepted", accepted.get("status"));
      Map<String, String> read =
          bob.command("read", Map.of("messageId", accepted.get("messageId")));
      assertEquals(canary, read.get("body"));
      assertEquals("text/plain", read.get("format"));
      assertEquals("verified-local-copy", read.get("status"));
      assertNotEquals(
          "accepted",
          alice
              .command("import-reference", Map.of("reference", reference, "confirmed", "yes"))
              .get("status"));

      bob.restart();
      bob.updateAndRollback();
      assertEquals(
          "duplicate",
          bob.command("import-reference", Map.of("reference", reference, "confirmed", "yes"))
              .get("status"));
      assertEquals(
          canary, bob.command("read", Map.of("messageId", accepted.get("messageId"))).get("body"));
      String replyReference =
          send(bob, aliceFingerprint, "Synthetic reply", "PUBLIC SYNTHETIC REPLY");
      Map<String, String> reply =
          alice.command(
              "import-reference", Map.of("reference", replyReference, "confirmed", "yes"));
      assertEquals("accepted", reply.get("status"));
      assertEquals(
          "PUBLIC SYNTHETIC REPLY",
          alice.command("read", Map.of("messageId", reply.get("messageId"))).get("body"));
    }
  }

  @Test
  void killedWorkerRecoversSealedCommitAndUncertainInsertionWithoutResealing() throws Exception {
    int scenario = 0;
    for (String faultPath : java.util.List.of("/app-data/records", "/queue/inserts/app-document")) {
      Map<String, byte[]> network = new ConcurrentHashMap<>();
      Path scenarioRoot = root.resolve("publication-crash-" + scenario++);
      try (Endpoint sender = new Endpoint(scenarioRoot.resolve("sender"), network);
          Endpoint recipient = new Endpoint(scenarioRoot.resolve("recipient"), network)) {
        sender.start();
        recipient.start();
        sender.command("initialize", Map.of());
        recipient.command("initialize", Map.of());
        String recipientFingerprint =
            approve(sender, recipient.command("export-contact", Map.of()).get("card"));
        approve(recipient, sender.command("export-contact", Map.of()).get("card"));
        sender.command(
            "save-draft",
            Map.of(
                "fingerprint",
                recipientFingerprint,
                "subject",
                "Public synthetic crash case",
                "body",
                "PUBLIC SYNTHETIC CRASH RECOVERY CANARY"));
        Map<String, String> preview = sender.command("preview-send", Map.of());
        BackendBarrier barrier = new BackendBarrier(faultPath, "POST");
        sender.barrier = barrier;
        String request =
            sender.broker.submit(
                "confirm-send",
                MailWire.base64(MailWire.encode(Map.of("approval", preview.get("approval")))));
        try {
          assertTrue(
              barrier.entered.await(10, TimeUnit.SECONDS),
              "Publication fault point was not reached.");
          Map<String, String> committed = sender.backend.privateState();
          String outboxKey =
              committed.keySet().stream()
                  .filter(key -> key.startsWith("outbox."))
                  .findFirst()
                  .orElseThrow();
          String operation = outboxKey.substring("outbox.".length());
          Map<String, String> outbox =
              MailWire.decode(committed.get(outboxKey).getBytes(StandardCharsets.UTF_8), 131072);
          byte[] sealed = Base64.getDecoder().decode(outbox.get("envelope"));
          assertEquals("sealed", outbox.get("state"));
          assertEquals(faultPath.equals("/app-data/records") ? 0 : 1, network.size());
          String oldToken = sender.child.token();
          Path log = sender.child.paths().processLogFile();
          Path installed = sender.child.paths().installedRoot();
          ProcessHandle process = ProcessHandle.of(sender.child.pid()).orElseThrow();
          assertTrue(process.destroyForcibly());
          process.onExit().get(10, TimeUnit.SECONDS);
          long reconciliationDeadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
          while (sender.host.currentLaunch("mail-prototype").isPresent()
              && System.nanoTime() < reconciliationDeadline) Thread.sleep(10);
          assertTrue(sender.host.currentLaunch("mail-prototype").isEmpty());
          assertTrue(sender.host.authenticateLaunchToken(oldToken).isEmpty());
          sender.assertSafeRuntimeDiagnostics(log, installed);
          sender.child = null;
          barrier.release.countDown();
          assertTrue(barrier.finished.await(10, TimeUnit.SECONDS));
          sender.barrier = null;
          assertThrows(IllegalStateException.class, () -> sender.broker.result(request));
          sender.start();
          Map<String, String> recovered = sender.command("status", Map.of());
          assertEquals("1", recovered.get("outbox"));
          assertTrue(
              operation.equals(recovered.get("operations")),
              "Committed operation identity changed across process death.");
          Map<String, String> retried = sender.command("retry", Map.of("operation", operation));
          if ("queued".equals(retried.get("status")))
            retried = sender.command("retry", Map.of("operation", operation));
          assertEquals("inserted", retried.get("status"));
          assertEquals(1, sender.backend.insertionBytes.size());
          assertTrue(
              java.util.Arrays.equals(sealed, sender.backend.insertionBytes.getFirst()),
              "Restart changed committed ciphertext.");
          Map<String, String> importInput =
              Map.of("reference", retried.get("reference"), "confirmed", "yes");
          assertEquals(
              "accepted", recipient.command("import-reference", importInput).get("status"));
          assertEquals(
              "duplicate", recipient.command("import-reference", importInput).get("status"));
        } finally {
          barrier.release.countDown();
          sender.barrier = null;
        }
      }
    }
  }

  @Test
  void stopWhileVaultOrDataResponseReentersHostDoesNotDeadlockAndRejectsOldReply()
      throws Exception {
    for (String blockedPath :
        java.util.List.of("/mail/open-storage", "/app-data/records/mail-state/dataset")) {
      try (Endpoint endpoint =
          new Endpoint(
              root.resolve("race-" + blockedPath.substring(blockedPath.lastIndexOf('/') + 1)),
              new ConcurrentHashMap<>())) {
        endpoint.start();
        endpoint.command("initialize", Map.of());
        String oldToken = endpoint.child.token();
        BackendBarrier barrier = new BackendBarrier(blockedPath);
        endpoint.barrier = barrier;
        String requestId = endpoint.broker.submit("status", "e30=");
        assertTrue(
            barrier.entered.await(10, TimeUnit.SECONDS),
            "Actual backend operation did not enter barrier.");
        var hostHeld = new java.util.concurrent.CountDownLatch(1);
        try (var stopping = Executors.newSingleThreadExecutor()) {
          var stopped =
              stopping.submit(
                  () -> {
                    synchronized (endpoint.host) {
                      hostHeld.countDown();
                      assertTrue(barrier.reentryAttempted.await(10, TimeUnit.SECONDS));
                      endpoint.stop();
                    }
                    return true;
                  });
          assertTrue(hostHeld.await(10, TimeUnit.SECONDS));
          barrier.release.countDown();
          assertTrue(
              stopped.get(15, TimeUnit.SECONDS), "Stop deadlocked with backend host re-entry.");
          assertTrue(barrier.finished.await(10, TimeUnit.SECONDS));
          assertThrows(
              IllegalStateException.class,
              () -> endpoint.broker.result(requestId),
              "Stopped launch must not return a private command result.");
          var stale =
              java.net.http.HttpRequest.newBuilder(
                      java.net.URI.create(
                          "http://127.0.0.1:"
                              + endpoint.server.getAddress().getPort()
                              + "/api/v1/mail/reply"))
                  .header("X-Crypta-App-Token", oldToken)
                  .POST(
                      java.net.http.HttpRequest.BodyPublishers.ofString(
                          "requestId=" + requestId + "&payloadBase64=e30%3D"))
                  .timeout(java.time.Duration.ofSeconds(5))
                  .build();
          try (var client = java.net.http.HttpClient.newHttpClient()) {
            assertEquals(
                403,
                client
                    .send(stale, java.net.http.HttpResponse.BodyHandlers.discarding())
                    .statusCode());
          }
        } finally {
          barrier.release.countDown();
        }
      }
    }
  }

  private static final class BackendBarrier {
    final String path;
    final String method;
    final java.util.concurrent.CountDownLatch entered = new java.util.concurrent.CountDownLatch(1);
    final java.util.concurrent.CountDownLatch release = new java.util.concurrent.CountDownLatch(1);
    final java.util.concurrent.CountDownLatch reentryAttempted =
        new java.util.concurrent.CountDownLatch(1);
    final java.util.concurrent.CountDownLatch finished = new java.util.concurrent.CountDownLatch(1);

    BackendBarrier(String path) {
      this(path, null);
    }

    BackendBarrier(String path, String method) {
      this.path = path;
      this.method = method;
    }
  }

  private static String approve(Endpoint endpoint, String card) throws Exception {
    Map<String, String> inspected = endpoint.command("import-contact", Map.of("card", card));
    assertEquals("compare-fingerprint-out-of-band", inspected.get("status"));
    String fingerprint = inspected.get("fingerprint");
    assertEquals(
        "contact-approved",
        endpoint.command("approve-contact", Map.of("fingerprint", fingerprint)).get("status"));
    return fingerprint;
  }

  private static String send(Endpoint endpoint, String fingerprint, String subject, String body)
      throws Exception {
    assertEquals(
        "draft",
        endpoint
            .command(
                "save-draft", Map.of("fingerprint", fingerprint, "subject", subject, "body", body))
            .get("status"));
    Map<String, String> preview = endpoint.command("preview-send", Map.of());
    assertEquals(body, preview.get("body"));
    Map<String, String> queued =
        endpoint.command("confirm-send", Map.of("approval", preview.get("approval")));
    assertEquals("queued", queued.get("status"));
    Map<String, String> inserted =
        endpoint.command("retry", Map.of("operation", queued.get("operation")));
    assertEquals("inserted", inserted.get("status"));
    return inserted.get("reference");
  }

  private static final class Endpoint implements AutoCloseable {
    final Path directory;
    private final MailTestBackend backend;
    final HttpServer server;
    final java.util.concurrent.ExecutorService executor = Executors.newFixedThreadPool(4);
    final MailWorkerBroker broker;
    final LocalProcessAppHost host;
    final java.security.KeyPair publisherKey;
    final Path signedBundle;
    RunningAppSnapshot child;
    volatile BackendBarrier barrier;
    final java.util.Set<String> privateCanaries = ConcurrentHashMap.newKeySet();

    Endpoint(Path directory, Map<String, byte[]> network) throws Exception {
      this.directory = directory;
      Files.createDirectories(directory);
      backend =
          new MailTestBackend(directory.resolve("vault"), directory.resolve("dataset"), network);
      server = HttpServer.create(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0), 4);
      Path staged = Path.of(System.getProperty("mailPrototype.stageDir"));
      Path copied = directory.resolve("signed-bundle");
      signedBundle = copied;
      try (var paths = Files.walk(staged)) {
        for (Path source : paths.toList()) {
          assertFalse(Files.isSymbolicLink(source));
          Path destination = copied.resolve(staged.relativize(source));
          if (Files.isDirectory(source)) Files.createDirectories(destination);
          else Files.copy(source, destination, java.nio.file.StandardCopyOption.COPY_ATTRIBUTES);
        }
      }
      var key = java.security.KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
      publisherKey = key;
      String keyId = "mail-process-test-publisher";
      AppBundleSigner.sign(copied, keyId, key.getPrivate());
      TrustedAppKeys keys = TrustedAppKeys.of(new TrustedAppKey(keyId, "Ed25519", key.getPublic()));
      AppBundleVerifier verifier = AppBundleVerifier.requireSigned(keys);
      host =
          new LocalProcessAppHost(
              new AppHostLayout(
                  directory.resolve("host-data"),
                  directory.resolve("host-cache"),
                  directory.resolve("host-run")),
              AppInstallVerificationPolicy.requireSigned(
                  verifier::verify, path -> AppBundleVerifier.verifyHistorical(path, keys)));
      host.setMailPlatformApiEndpoint(
          java.net.URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/api/v1"));
      host.installFromDirectory(copied);
      broker = new MailWorkerBroker(host);
      server.setExecutor(executor);
      server.createContext("/api/v1", this::handle);
      server.start();
    }

    void start() throws IOException {
      child = host.start("mail-prototype");
      privateCanaries.add(child.token());
      assertTrue(host.authenticateLaunchToken(child.token()).isPresent());
    }

    private static Path stageBuildRoot() {
      Path stage = Path.of(System.getProperty("mailPrototype.stageDir"));
      Path bundles = java.util.Objects.requireNonNull(stage.getParent());
      return java.util.Objects.requireNonNull(bundles.getParent());
    }

    void restart() throws Exception {
      stop();
      start();
    }

    void updateAndRollback() throws Exception {
      String originalVersion = child.manifest().appVersion();
      String originalLaunch = host.currentLaunch("mail-prototype").orElseThrow().launchId();
      Path candidate = directory.resolve("signed-update");
      try (var paths = Files.walk(signedBundle)) {
        for (Path source : paths.toList()) {
          Path destination = candidate.resolve(signedBundle.relativize(source));
          if (Files.isDirectory(source)) Files.createDirectories(destination);
          else Files.copy(source, destination, java.nio.file.StandardCopyOption.COPY_ATTRIBUTES);
        }
      }
      Path manifest = candidate.resolve("cryptad-app.properties");
      String updatedVersion = originalVersion + ".1";
      String text = Files.readString(manifest);
      String originalField = "app.version=" + originalVersion + "\n";
      assertTrue(text.contains(originalField));
      Files.writeString(
          manifest, text.replace(originalField, "app.version=" + updatedVersion + "\n"));
      AppBundleSigner.sign(candidate, "mail-process-test-publisher", publisherKey.getPrivate());
      stop();
      host.updateFromDirectory("mail-prototype", candidate);
      start();
      assertEquals(updatedVersion, child.manifest().appVersion());
      String updatedLaunch = host.currentLaunch("mail-prototype").orElseThrow().launchId();
      assertNotEquals(originalLaunch, updatedLaunch);
      assertEquals("ready", command("status", Map.of()).get("status"));
      stop();
      host.rollback("mail-prototype");
      start();
      assertEquals(originalVersion, child.manifest().appVersion());
      assertNotEquals(updatedLaunch, host.currentLaunch("mail-prototype").orElseThrow().launchId());
    }

    Map<String, String> command(String command, Map<String, String> payload) throws Exception {
      recordCanaries(payload);
      return rawCommand(command, MailWire.encode(payload));
    }

    Map<String, String> rawCommand(String command, byte[] payload) throws Exception {
      String requestId = broker.submit(command, Base64.getEncoder().encodeToString(payload));
      long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(29);
      while (System.nanoTime() < deadline) {
        var encoded = broker.result(requestId);
        if (encoded.isPresent()) {
          Map<String, String> result =
              MailWire.decode(Base64.getDecoder().decode(encoded.get()), 393216);
          recordCanaries(result);
          return result;
        }
        Thread.sleep(10);
      }
      throw new IllegalStateException("Private worker result deadline exceeded.");
    }

    void handle(HttpExchange exchange) throws IOException {
      try (exchange) {
        int status = 200;
        Map<String, Object> response;
        var authenticated =
            host.authenticateLaunchToken(
                exchange.getRequestHeaders().getFirst("X-Crypta-App-Token"));
        if (authenticated.isEmpty()) {
          status = 403;
          response = Map.of("error", "denied");
        } else {
          String path = exchange.getRequestURI().getPath().substring("/api/v1".length());
          Map<String, String> parameters = parameters(exchange);
          try {
            if ("/mail/poll".equals(path)) {
              var next = broker.poll(authenticated.orElseThrow().launchId());
              response =
                  Map.of(
                      "mail",
                      next.<Object>map(
                              frame ->
                                  Map.of(
                                      "requestId",
                                      frame.requestId(),
                                      "command",
                                      frame.command(),
                                      "payloadBase64",
                                      frame.payloadBase64()))
                          .orElse(Map.of("status", "idle")));
            } else if ("/mail/reply".equals(path)) {
              broker.reply(
                  authenticated.orElseThrow().launchId(),
                  parameters.get("requestId"),
                  parameters.get("payloadBase64"));
              response = Map.of("mail", Map.of("status", "completed"));
            } else {
              synchronized (backend) {
                response = backend.request(exchange.getRequestMethod(), path, parameters);
                BackendBarrier activeBarrier = barrier;
                if (activeBarrier != null
                    && activeBarrier.path.equals(path)
                    && (activeBarrier.method == null
                        || activeBarrier.method.equals(exchange.getRequestMethod()))) {
                  activeBarrier.entered.countDown();
                  try {
                    if (!activeBarrier.release.await(10, TimeUnit.SECONDS))
                      throw new MailFailure("unavailable");
                    activeBarrier.reentryAttempted.countDown();
                    if (host.currentLaunch("mail-prototype").isEmpty())
                      throw new MailFailure("key-unavailable");
                  } catch (InterruptedException exception) {
                    Thread.currentThread().interrupt();
                    throw new MailFailure("unavailable");
                  } finally {
                    activeBarrier.finished.countDown();
                  }
                }
              }
            }
          } catch (MailFailure failure) {
            status = "not-found".equals(failure.getMessage()) ? 404 : 403;
            response = Map.of("error", "unavailable");
          } catch (RuntimeException failure) {
            status = 500;
            response = Map.of("error", "invalid");
          }
        }
        byte[] bytes = PlatformApiJsonWriter.write(response).getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        exchange.getResponseBody().write(bytes);
      }
    }

    private static Map<String, String> parameters(HttpExchange exchange) throws IOException {
      String form =
          "GET".equals(exchange.getRequestMethod())
              ? exchange.getRequestURI().getRawQuery()
              : new String(exchange.getRequestBody().readNBytes(786433), StandardCharsets.UTF_8);
      Map<String, String> result = new LinkedHashMap<>();
      if (form == null || form.isEmpty()) return result;
      for (String field : form.split("&")) {
        String[] pair = field.split("=", 2);
        result.put(
            URLDecoder.decode(pair[0], StandardCharsets.UTF_8),
            pair.length == 2 ? URLDecoder.decode(pair[1], StandardCharsets.UTF_8) : "");
      }
      return result;
    }

    void stop() throws Exception {
      if (child == null) return;
      String oldToken = child.token();
      Path processLog = child.paths().processLogFile();
      assertTrue(host.stop("mail-prototype"));
      assertTrue(host.authenticateLaunchToken(oldToken).isEmpty());
      assertTrue(host.currentLaunch("mail-prototype").isEmpty());
      if (Files.size(processLog) != 0) {
        Path privateLog = stageBuildRoot().resolve("private-worker-runtime.log");
        Files.copy(processLog, privateLog, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        if (Files.getFileStore(privateLog).supportsFileAttributeView("posix")) {
          Files.setPosixFilePermissions(
              privateLog, java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));
        }
      }
      assertSafeRuntimeDiagnostics(processLog, child.paths().installedRoot());
      child = null;
    }

    private void recordCanaries(Map<String, String> values) {
      for (String key :
          java.util.List.of(
              "body",
              "subject",
              "card",
              "fingerprint",
              "recipientFingerprint",
              "reference",
              "backup")) {
        String value = values.get(key);
        if (value != null && value.length() >= 8) privateCanaries.add(value);
      }
    }

    private void assertSafeRuntimeDiagnostics(Path processLog, Path installedRoot)
        throws IOException {
      String raw = Files.readString(processLog);
      assertFalse(
          privateCanaries.stream().anyMatch(raw::contains),
          "Private value entered worker process log.");
      java.util.List<String> lines = raw.lines().filter(line -> !line.isBlank()).toList();
      if (lines.isEmpty()) return;
      Path bcJar;
      try (var files = Files.list(installedRoot.resolve("lib"))) {
        bcJar =
            files
                .filter(
                    path ->
                        java.util.Objects.requireNonNull(path.getFileName())
                            .toString()
                            .startsWith("bcprov-lts8on-"))
                .findFirst()
                .orElseThrow();
      }
      java.util.List<String> expected =
          java.util.List.of(
              "WARNING: A restricted method in java.lang.System has been called",
              "WARNING: java.lang.System::load has been called by"
                  + " org.bouncycastle.crypto.NativeLoader$2 in an unnamed module ("
                  + bcJar.toUri().toURL().toExternalForm()
                  + ")",
              "WARNING: Use --enable-native-access=ALL-UNNAMED to avoid a warning for callers in"
                  + " this module",
              "WARNING: Restricted methods will be blocked in a future release unless native access"
                  + " is enabled");
      assertTrue(
          lines.equals(expected), "Unexpected worker diagnostic; inspect private local artifact.");
    }

    @Override
    public void close() throws Exception {
      try {
        stop();
      } finally {
        server.stop(0);
        executor.shutdownNow();
      }
    }
  }
}
