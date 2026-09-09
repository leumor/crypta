package network.crypta.platform.sdk.js;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;
import java.util.Objects;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Experimental Mail SDK coverage separate from the frozen five-profile consumer review suite. */
@SuppressWarnings("java:S100")
class MailSdkTest {
  @TempDir private Path tempDir;

  @Test
  void mailCommand_whenHttpOrBodyStalls_expectOverallAbortAndSubsequentRecovery() throws Exception {
    String script;
    try (var resource =
        Objects.requireNonNull(getClass().getResourceAsStream("/mail-command-deadline.cjs"))) {
      script = new String(resource.readAllBytes(), StandardCharsets.UTF_8);
    }
    for (String stage :
        List.of(
            "bootstrap-headers",
            "bootstrap-body",
            "submission-headers",
            "submission-body",
            "result-headers",
            "result-body",
            "refresh-headers",
            "refresh-body",
            "polling")) {
      runSdkNode("const stalledStage = '" + stage + "';\n" + script);
    }
  }

  @Test
  void mailCommand_whenCallerCancels_expectNoSubmissionOrAbortedBody() throws Exception {
    runSdkNode(
        """
        enqueueBootstrap();
        await CryptaPlatform.bootstrap.load({ appId: "feed-reader" });
        const cancelled = new AbortController();
        cancelled.abort();
        await assert.rejects(CryptaPlatform.mail.command("status", {}, { signal: cancelled.signal }), /Mail command cancelled/);
        assert.strictEqual(calls.length, 1);
        const caller = new AbortController();
        let reached;
        const reading = new Promise(resolve => { reached = resolve; });
        let bodySignal;
        const watchdog = setTimeout(() => { console.error("Cancellation did not complete"); process.exit(1); }, 10000);
        context.fetch = async (url, options) => ({
          ok: true,
          json: () => new Promise((resolve, reject) => {
            bodySignal = options.signal;
            options.signal.addEventListener("abort", () => reject(options.signal.reason), { once: true });
            reached();
          })
        });
        const rejected = assert.rejects(CryptaPlatform.mail.command("status", {}, { signal: caller.signal }), /Mail command cancelled/);
        await reading;
        caller.abort();
        await rejected;
        assert.ok(bodySignal.aborted);
        clearTimeout(watchdog);
        """);
  }

  @Test
  void mailCancellationDoesNotAbortAnotherCallersSharedBootstrap() throws Exception {
    runSdkNode(
        """
        let finishShared;
        let reached;
        const reading = new Promise(resolve => { reached = resolve; });
        let fetches = 0;
        const watchdog = setTimeout(() => { console.error("Shared bootstrap did not finish"); process.exit(1); }, 10000);
        context.fetch = (url, options) => {
          fetches++;
          if (!options.signal) return new Promise(resolve => { finishShared = resolve; });
          return Promise.resolve({ ok: true, json: () => new Promise((resolve, reject) => {
            options.signal.addEventListener("abort", () => reject(options.signal.reason), { once: true });
            reached();
          }) });
        };
        const shared = CryptaPlatform.bootstrap.load({ appId: "feed-reader" });
        const caller = new AbortController();
        const rejected = assert.rejects(CryptaPlatform.mail.command("status", {}, { signal: caller.signal }), /Mail command cancelled/);
        await reading;
        assert.strictEqual(fetches, 2);
        caller.abort();
        await rejected;
        finishShared({ ok: true, json: async () => bootstrap });
        assert.strictEqual((await shared).appId, "feed-reader");
        assert.strictEqual(CryptaPlatform.bootstrap.current().appId, "feed-reader");
        clearTimeout(watchdog);
        """);
  }

  @Test
  void mailCommand_whenUnsupportedOrSdkOnlyLoaded_expectNoNetwork() throws Exception {
    runSdkNode(
        """
        assert.strictEqual(calls.length, 0);
        await assert.rejects(() => CryptaPlatform.mail.command("open-storage", {}), /Unsupported Mail command/);
        await assert.rejects(() => CryptaPlatform.mail.command("http://127.0.0.1/private", {}), /Unsupported Mail command/);
        await assert.rejects(() => CryptaPlatform.mail.command("save-draft", { body: "雪".repeat(93334) }), /too large/);
        assert.strictEqual(calls.length, 0);
        assert.strictEqual(responses.length, 0);
        """);
  }

  @Test
  void mailCommand_whenUnicodeRoundTrip_expectFixedPathsAndBrowserSessionOnly() throws Exception {
    runSdkNode(
        """
        bootstrap.appId = "mail-prototype";
        context.window.location.pathname = "/apps/mail-prototype/static/index.html";
        context.window.location.href = "http://127.0.0.1:3000/apps/mail-prototype/static/index.html";
        enqueueBootstrap();
        await CryptaPlatform.bootstrap.load({ appId: "mail-prototype" });
        const payload = { subject: "雪", body: "<script>literal</script> 👋" };
        const expected = { status: "verified-local-copy", subject: payload.subject, body: payload.body };
        enqueueResponse(url => url === "http://127.0.0.1:8181/api/v1/mail/command",
          { mail: { requestId: "request-public-synthetic" } });
        enqueueResponse(url => url === "http://127.0.0.1:8181/api/v1/mail/result",
          { mail: { status: "complete", payloadBase64: Buffer.from(JSON.stringify(expected), "utf8").toString("base64") } });

        const actual = await CryptaPlatform.mail.command("read", payload);

        assert.deepStrictEqual(JSON.parse(JSON.stringify(actual)), expected);
        assert.strictEqual(calls.length, 3);
        const command = decodeFormBody(calls[1]);
        assert.strictEqual(command.get("command"), "read");
        assert.deepStrictEqual(JSON.parse(Buffer.from(command.get("payloadBase64"), "base64").toString("utf8")), payload);
        assert.strictEqual(decodeFormBody(calls[2]).get("requestId"), "request-public-synthetic");
        for (const call of calls.slice(1)) {
          assert.strictEqual(call.method, "POST");
          assert.strictEqual(headerValue(call.headers, "X-Crypta-App-Session"), "session-token");
          assert.strictEqual(headerValue(call.headers, "X-Crypta-App-Token"), null);
          assert.strictEqual(headerValue(call.headers, "Authorization"), null);
          assert.strictEqual(call.credentials, "omit");
          assert.strictEqual(String(call.body).includes("session-token"), false);
          assert.strictEqual(String(call.body).includes("CRYPTAD_APP_TOKEN"), false);
        }
        """);
  }

  @Test
  void mailCommand_whenEncodedBoundsOrMalformedUtf8_expectBoundedRejection() throws Exception {
    runSdkNode(
        """
        enqueueBootstrap();
        await CryptaPlatform.bootstrap.load({ appId: "feed-reader" });
        const prefixBytes = Buffer.byteLength(JSON.stringify({ value: "" }), "utf8");
        const bounded = { value: "x".repeat(280000 - prefixBytes) };
        enqueueResponse(url => url.endsWith("/api/v1/mail/command"), { mail: { requestId: "bounded" } });
        enqueueResponse(url => url.endsWith("/api/v1/mail/result"),
          { mail: { status: "complete", payloadBase64: "e30=" } });
        await CryptaPlatform.mail.command("restore", bounded);
        const encoded = decodeFormBody(calls[1]).get("payloadBase64");
        assert.strictEqual(Buffer.from(encoded, "base64").length, 280000);
        assert.ok(encoded.length <= 393216);
        const count = calls.length;
        await assert.rejects(() => CryptaPlatform.mail.command("restore", { value: bounded.value + "x" }), /too large/);
        assert.strictEqual(calls.length, count);
        enqueueResponse(url => url.endsWith("/api/v1/mail/command"), { mail: { requestId: "oversized" } });
        enqueueResponse(url => url.endsWith("/api/v1/mail/result"),
          { mail: { status: "complete", payloadBase64: "A".repeat(393220) } });
        await assert.rejects(() => CryptaPlatform.mail.command("status", {}), /response is too large/);
        enqueueResponse(url => url.endsWith("/api/v1/mail/command"), { mail: { requestId: "invalid-utf8" } });
        enqueueResponse(url => url.endsWith("/api/v1/mail/result"),
          { mail: { status: "complete", payloadBase64: Buffer.from([0xc3, 0x28]).toString("base64") } });
        await assert.rejects(() => CryptaPlatform.mail.command("read", {}), /encoding|encoded|valid/i);
        assert.strictEqual(responses.length, 0);
        """);
  }

  private void runSdkNode(String scriptBody) throws Exception {
    CryptaPlatformSdkResourceTest.runSdkNode(tempDir, scriptBody);
  }
}
