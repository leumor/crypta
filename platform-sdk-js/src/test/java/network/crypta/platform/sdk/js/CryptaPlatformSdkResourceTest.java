package network.crypta.platform.sdk.js;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class CryptaPlatformSdkResourceTest {
  private static final String SDK_RESOURCE_PATH =
      "/network/crypta/platform/sdk/js/crypta-platform.js";

  @TempDir private Path tempDir;

  @Test
  void contentProfileConformance_whenProductionConsumersRun_expectPinnedCorpusAgreement()
      throws Exception {
    Assumptions.assumeTrue(nodeAvailable(), "Node.js is required for SDK behavior tests.");
    Path root = Path.of("").toAbsolutePath();
    while (root != null && !Files.isRegularFile(root.resolve("settings.gradle.kts"))) {
      root = root.getParent();
    }
    assertNotNull(root, "Repository root is required for conformance execution.");
    Process process =
        new ProcessBuilder(
                "node",
                root.resolve("platform-sdk-js/src/test/resources/content-profile-conformance.cjs")
                    .toString(),
                root.toString())
            .redirectErrorStream(true)
            .start();
    boolean finished = process.waitFor(30, TimeUnit.SECONDS);
    if (!finished) {
      process.destroyForcibly();
    }
    String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
    assertTrue(finished, output);
    assertEquals(0, process.exitValue(), output);
  }

  @Test
  void classpathResource_whenSdkRequested_expectPublicBrowserSurface() throws IOException {
    String script = readSdkScript();

    assertTrue(script.contains("window.CryptaPlatform"));
    assertTrue(script.contains("bootstrap:"));
    assertTrue(script.contains("api:"));
    assertTrue(script.contains("queue:"));
    assertTrue(script.contains("content:"));
    assertTrue(script.contains("contentFormats,"));
    assertTrue(script.contains("subscriptions: Object.freeze({"));
    assertTrue(script.contains("data:"));
    assertTrue(script.contains("records: Object.freeze({"));
    assertTrue(script.contains("namespaces: Object.freeze({"));
    assertTrue(script.contains("feed:"));
    assertTrue(script.contains("trust:"));
    assertTrue(script.contains("services: Object.freeze({"));
    assertTrue(script.contains("vault:"));
    assertTrue(script.contains("profile:"));
    assertTrue(script.contains("dom:"));
    assertTrue(script.contains("sanitizeFragment"));
    assertTrue(script.contains("browserSessionToken"));
    assertTrue(script.contains("X-Crypta-App-Session"));
    assertTrue(script.contains("invalid_app_browser_session"));
    assertTrue(script.contains("origin_mismatch"));
    assertTrue(script.contains("sessionRefreshRequired"));
    assertTrue(script.contains("credentials: \"omit\""));
  }

  @Test
  void classpathResource_whenBootstrapRequested_expectIsolatedOriginBootstrapFlow()
      throws IOException {
    String script = readSdkScript();

    assertTrue(
        script.contains("const bootstrapResourcePath = \".well-known/cryptad-bootstrap.json\";"));
    assertTrue(script.contains("const bootstrapNonceHeader = \"X-Crypta-App-Bootstrap-Nonce\";"));
    assertTrue(
        script.contains("const bootstrapNonceFragmentParameter = \"cryptadBootstrapNonce\";"));
    assertTrue(script.contains("function bootstrapHeaders()"));
    assertTrue(script.contains("headers[bootstrapNonceHeader] = nonce;"));
    assertTrue(script.contains("function bootstrapNonceFromHash(hash)"));
    assertTrue(script.contains("function bootstrapUrls(appId)"));
    assertTrue(script.contains("const rootBootstrapUrl = `/${bootstrapResourcePath}`;"));
    assertTrue(script.contains("if (!appId || !legacyAdminAppPath(appId))"));
    assertTrue(script.contains("function legacyAdminAppPath(appId)"));
    assertTrue(script.contains("if (index + 1 >= urls.length)"));
    assertTrue(
        script.contains(
            "throw new Error(\"Bootstrap response did not include a Cryptad app id.\")"));
    assertTrue(script.contains("copyStringField(source, bootstrap, \"platformApiRoot\");"));
    assertTrue(script.contains("copyStringField(source, bootstrap, \"uiOrigin\");"));
  }

  @Test
  void classpathResource_whenApiRequested_expectAbsoluteApiRootAndSessionRefreshFlow()
      throws IOException {
    String script = readSdkScript();

    assertTrue(script.contains("function fetchApiGet"));
    assertFalse(script.contains("return new URL(value, window.location.origin);"));
    assertTrue(script.contains("return new URL(value, rootUrl);"));
    assertTrue(script.contains("function refreshBootstrap(options)"));
    assertTrue(script.contains("function refreshBootstrapForMutation"));
    assertTrue(script.contains("currentBrowserSessionLive()"));
    assertTrue(script.contains("function browserSessionExpiresAtMillis(bootstrap)"));
    assertTrue(script.contains("Date.parse(value)"));
    assertTrue(script.contains("await refreshBootstrap(requestOptions);"));
    assertTrue(script.contains("return fetchApiGet(path, requestOptions);"));
    assertTrue(script.contains("await refreshBootstrapForMutation(requestOptions);"));
    assertTrue(script.contains("function fetchFormMutation(method, path, body, requestOptions)"));
    assertTrue(
        script.contains("return await fetchFormMutation(method, path, body, requestOptions);"));
    assertTrue(script.contains("return fetchFormMutation(method, path, body, requestOptions);"));
    assertTrue(
        script.contains(
            "hostname.startsWith(\"[\") && hostname.endsWith(\"]\") ? hostname.slice(1, -1)"));
    assertTrue(script.contains("normalizedHostname === \"::1\""));
    assertTrue(script.contains("normalizedHostname === \"0:0:0:0:0:0:0:1\""));
  }

  @Test
  void classpathResource_whenSdkRequested_expectNoHostCredentialsOrPersistentStorage()
      throws IOException {
    String script = readSdkScript();

    assertFalse(script.contains("formPassword"));
    assertFalse(script.contains("CRYPTAD_APP_TOKEN"));
    assertFalse(script.contains("localStorage"));
    assertFalse(script.contains("sessionStorage"));
    // Public received signatures are confined to verification, not credential transport helpers.
    String withoutProfileVerifier =
        script.substring(0, script.indexOf("  async function verifyProfileDocument("))
            + script.substring(script.indexOf("  function parseFeedSnapshot("));
    assertFalse(withoutProfileVerifier.contains("signatureBase64"));
    assertFalse(script.contains("privateKey"));
  }

  @Test
  void classpathResource_whenVaultRequested_expectMetadataOnlyBrowserHelpers() throws IOException {
    String script = readSdkScript();

    assertVaultMetadataBrowserHelperFragments(script);
    assertNoVaultPrivateBrowserHelpers(script);
  }

  @Test
  void classpathResource_whenJsonDocumentHelpersRequested_expectEncodedFormMutations()
      throws IOException {
    String script = readSdkScript();

    assertJsonDocumentHelperFragments(script);
    assertNoRawMutationFetches(script);
  }

  @Test
  void classpathResource_whenTrustHelpersRequested_expectBrowserSafeTrustSurface()
      throws IOException {
    String script = readSdkScript();

    assertTrue(script.contains("const trustStatementContentType = contentFormats.trustStatement"));
    assertTrue(
        script.contains("const trustStatementTargetFilename = contentFormats.trustStatement"));
    assertTrue(script.contains("function trustStatus(options)"));
    assertTrue(script.contains("function listTrustAnchors(options)"));
    assertTrue(script.contains("function addTrustAnchor(request, options)"));
    assertTrue(script.contains("function removeTrustAnchor(fingerprintOrOptions, options)"));
    assertTrue(script.contains("function importTrustStatement(request, options)"));
    assertTrue(script.contains("function previewTrustImport(request, options)"));
    assertTrue(script.contains("function importTrustUri(request, options)"));
    assertTrue(script.contains("function trustAudit(request, options)"));
    assertTrue(script.contains("function trustSubjects(options)"));
    assertTrue(script.contains("function trustStatements(request, options)"));
    assertTrue(script.contains("function trustScore(request, options)"));
    assertTrue(script.contains("function publishTrustStatement(options)"));
    assertTrue(script.contains("function fetchAndImportTrustStatement(request, options)"));
    assertTrue(script.contains("function createTrustSubscription(options)"));
    assertTrue(script.contains("\"trust-graph/score\""));
    assertTrue(script.contains("\"trust-graph/import\""));
    assertTrue(script.contains("\"trust-graph/import-preview\""));
    assertTrue(script.contains("\"trust-graph/import-preview-uri\""));
    assertTrue(script.contains("\"trust-graph/import-uri\""));
    assertTrue(script.contains("\"trust-graph/audit\""));
    assertTrue(script.contains("/trust-statement`"));
  }

  @Test
  void classpathResource_whenContentFormatsRequested_expectVersionedProfileMetadata()
      throws Exception {
    String script = readSdkScript();

    assertTrue(script.contains("const contentFormats = Object.freeze({"));
    assertTrue(script.contains("profileDocument: Object.freeze({"));
    assertTrue(script.contains("feedSnapshot: Object.freeze({"));
    assertTrue(script.contains("trustStatement: Object.freeze({"));
    assertTrue(script.contains("socialMessage: Object.freeze({"));
    assertTrue(script.contains("socialOutbox: Object.freeze({"));
    assertTrue(script.contains("unknownFieldPolicy: \"reject_unknown_fields\""));

    runSdkNode(
        """
        assert.equal(CryptaPlatform.contentFormats.profileDocument.schema, "crypta.profile.v1");
        assert.equal(
          CryptaPlatform.contentFormats.profileDocument.contentType,
          "application/vnd.crypta.profile+json");
        assert.equal(CryptaPlatform.contentFormats.profileDocument.signingDomain, "profile.publish.v1");
        assert.equal(CryptaPlatform.contentFormats.feedSnapshot.type, "crypta.feed.snapshot.v1");
        assert.equal(
          CryptaPlatform.contentFormats.feedSnapshot.contentType,
          "application/vnd.crypta.feed+json");
        assert.equal(
          CryptaPlatform.contentFormats.trustStatement.signingDomain,
          "crypta.trust.statement.v1");
        assert.equal(CryptaPlatform.contentFormats.socialMessage.type, "crypta.social.message.v1");
        assert.equal(
          CryptaPlatform.contentFormats.socialOutbox.defaultFilename,
          "social-outbox.json");
        assert.equal(CryptaPlatform.contentFormats.feedSnapshot.maxDocumentBytes, 65536);
        assert.equal(CryptaPlatform.contentFormats.socialOutbox.maxDocumentBytes, 65536);
        CryptaPlatform.contentFormats.feedSnapshot.type = "drift";
        assert.equal(CryptaPlatform.contentFormats.feedSnapshot.type, "crypta.feed.snapshot.v1");
        """);
  }

  @Test
  void classpathResource_whenAppServicesRequested_expectRoutesAndFormFields() throws Exception {
    String script = readSdkScript();

    assertTrue(script.contains("function listAppServices(options)"));
    assertTrue(script.contains("function getAppService(providerAppId, serviceId, options)"));
    assertTrue(script.contains("function listAppServiceGrants(options)"));
    assertTrue(script.contains("function listAppServiceDependencies(options)"));
    assertTrue(script.contains("function getAppServiceDependencies(consumerAppId, options)"));
    assertTrue(script.contains("function listAppServiceBundles(options)"));
    assertTrue(script.contains("function requestAppServiceBundle(request, options)"));
    assertTrue(script.contains("function approveAppServiceBundle(bundleIdOrOptions, options)"));
    assertTrue(script.contains("function rejectAppServiceBundle(bundleIdOrOptions, options)"));
    assertTrue(script.contains("function renewAppServiceBundle(bundleIdOrOptions, options)"));
    assertTrue(script.contains("function normalizeAppServiceBundleMutation(source)"));
    assertTrue(script.contains("function apiPostHostForm(path, formDataOrParams, options)"));
    assertTrue(script.contains("function requestAppServiceGrant(request, options)"));
    assertTrue(script.contains("function revokeAppServiceGrant(grantIdOrOptions, options)"));
    assertTrue(
        script.contains("function invokeAppService(providerAppId, serviceId, request, options)"));
    assertTrue(script.contains("\"app-services/grants\""));
    assertTrue(script.contains("\"app-services/dependencies\""));
    assertTrue(script.contains("\"app-services/grant-bundles\""));
    assertTrue(script.contains("normalizeAppServiceBundleRequest(source)"));
    assertTrue(script.contains("normalizeAppServiceGrantRequest(source)"));
    assertTrue(script.contains("normalizeAppServiceInvocation(source)"));
    assertTrue(script.contains("appServiceSegment(value, description)"));

    runSdkNode(
        """
        enqueueBootstrap();
        enqueueResponse(
          (url, options) => {
            const parsed = new URL(url);
            return parsed.pathname === "/api/v1/app-services"
              && options.method === "GET";
          },
          { services: [{ serviceId: "trust.score" }], requests: [] });
        enqueueResponse(
          (url, options) => {
            const parsed = new URL(url);
            return parsed.pathname === "/api/v1/app-services/trust-graph/services/trust.score"
              && options.method === "GET";
          },
          { service: { serviceId: "trust.score" } });
        enqueueResponse(
          (url, options) => {
            const parsed = new URL(url);
            return parsed.pathname === "/api/v1/app-services/grants"
              && options.method === "GET";
          },
          { grants: [] });
        enqueueResponse(
          (url, options) => {
            const parsed = new URL(url);
            return parsed.pathname === "/api/v1/app-services/grants"
              && options.method === "POST";
          },
          { grant: { grantId: "asg-111111111111111111111111", status: "pending" } });
        enqueueResponse(
          (url, options) => {
            const parsed = new URL(url);
            return parsed.pathname === "/api/v1/app-services/trust-graph/services/trust.score/invoke"
              && options.method === "POST";
          },
          { serviceCall: { status: "ok", result: { score: 0.5 } } });
        enqueueResponse(
          (url, options) => {
            const parsed = new URL(url);
            return parsed.pathname === "/api/v1/app-services/grants/asg-111111111111111111111111/revoke"
              && options.method === "POST";
          },
          { grant: { status: "revoked" } });
        enqueueResponse(
          (url, options) => {
            const parsed = new URL(url);
            return parsed.pathname === "/api/v1/app-services/dependencies"
              && options.method === "GET";
          },
          { dependencyGraph: { apps: [], edges: [] } });
        enqueueResponse(
          (url, options) => {
            const parsed = new URL(url);
            return parsed.pathname === "/api/v1/app-services/dependencies/consumers/social-inbox"
              && options.method === "GET";
          },
          { dependencyGraph: { apps: [{ appId: "social-inbox" }], edges: [] } });
        enqueueResponse(
          (url, options) => {
            const parsed = new URL(url);
            return parsed.pathname === "/api/v1/app-services/grant-bundles"
              && options.method === "GET";
          },
          { bundles: [] });
        enqueueResponse(
          (url, options) => {
            const parsed = new URL(url);
            return parsed.pathname === "/api/v1/app-services/grant-bundles"
              && options.method === "POST";
          },
          { bundle: { bundleId: "asb-111111111111111111111111", status: "pending" } });
        enqueueResponse(
          (url, options) => {
            const parsed = new URL(url);
            return parsed.pathname === "/api/v1/app-services/grant-bundles/asb-111111111111111111111111/approve"
              && options.method === "POST";
          },
          { bundle: { status: "approved" } });
        enqueueResponse(
          (url, options) => {
            const parsed = new URL(url);
            return parsed.pathname === "/api/v1/app-services/grant-bundles/asb-111111111111111111111111/reject"
              && options.method === "POST";
          },
          { bundle: { status: "rejected" } });
        enqueueResponse(
          (url, options) => {
            const parsed = new URL(url);
            return parsed.pathname === "/api/v1/app-services/grant-bundles/asb-111111111111111111111111/renew"
              && options.method === "POST";
          },
          { bundle: { status: "approved", renewedAt: "2026-05-24T12:00:00Z" } });

        const listed = await CryptaPlatform.services.list();
        const service = await CryptaPlatform.services.get("trust-graph", "trust.score");
        const grants = await CryptaPlatform.services.grants.list();
        const requested = await CryptaPlatform.services.grants.request({
          providerAppId: "trust-graph",
          serviceId: "trust.score",
          scopes: ["score.read"],
          contexts: ["message-author"],
          purpose: "Annotate message authors."
        });
        const invoked = await CryptaPlatform.services.invoke("trust-graph", "trust.score", {
          subjectKind: "identity",
          subjectUri: "crypta:identity:alice",
          context: "message-author",
          scope: "score.read"
        });
        const revoked = await CryptaPlatform.services.grants.revoke("asg-111111111111111111111111");
        const dependencies = await CryptaPlatform.services.dependencies.list();
        const ownDependencies = await CryptaPlatform.services.dependencies.get("social-inbox");
        const bundles = await CryptaPlatform.services.bundles.list();
        const bundle = await CryptaPlatform.services.bundles.request({
          consumerAppId: "social-inbox",
          bundleAlias: "trust-annotations",
          includeOptional: true,
          purpose: "Review Trust score annotations."
        });
        const approvedBundle = await CryptaPlatform.services.bundles.approve(
          "asb-111111111111111111111111",
          { formPassword: "operator-password" });
        const rejectedBundle = await CryptaPlatform.services.bundles.reject({
          bundleId: "asb-111111111111111111111111",
          formPassword: "operator-password"
        });
        const renewedBundle = await CryptaPlatform.services.bundles.renew(
          "asb-111111111111111111111111",
          { formPassword: "operator-password" });

        assert.equal(listed.services[0].serviceId, "trust.score");
        assert.equal(service.service.serviceId, "trust.score");
        assert.equal(grants.grants.length, 0);
        assert.equal(requested.grant.status, "pending");
        assert.equal(invoked.serviceCall.status, "ok");
        assert.equal(revoked.grant.status, "revoked");
        assert.equal(dependencies.dependencyGraph.apps.length, 0);
        assert.equal(ownDependencies.dependencyGraph.apps[0].appId, "social-inbox");
        assert.equal(bundles.bundles.length, 0);
        assert.equal(bundle.bundle.status, "pending");
        assert.equal(approvedBundle.bundle.status, "approved");
        assert.equal(rejectedBundle.bundle.status, "rejected");
        assert.equal(renewedBundle.bundle.renewedAt, "2026-05-24T12:00:00Z");
        const requestParams = decodeFormBody(calls[4]);
        assert.equal(requestParams.get("providerAppId"), "trust-graph");
        assert.equal(requestParams.get("serviceId"), "trust.score");
        assert.equal(requestParams.get("scopes"), "score.read");
        assert.equal(requestParams.get("contexts"), "message-author");
        assert.equal(requestParams.get("purpose"), "Annotate message authors.");
        const invokeParams = decodeFormBody(calls[5]);
        assert.equal(invokeParams.get("subjectKind"), "identity");
        assert.equal(invokeParams.get("subjectUri"), "crypta:identity:alice");
        assert.equal(invokeParams.get("context"), "message-author");
        assert.equal(invokeParams.get("scope"), "score.read");
        assert.equal(headerValue(calls[5].headers, "X-Crypta-App-Session"), "session-token");
        assert.equal(calls[5].credentials, "omit");
        const bundleParams = decodeFormBody(calls[10]);
        assert.equal(bundleParams.get("consumerAppId"), "social-inbox");
        assert.equal(bundleParams.get("bundleAlias"), "trust-annotations");
        assert.equal(bundleParams.get("includeOptional"), "true");
        assert.equal(bundleParams.get("purpose"), "Review Trust score annotations.");
        const approveParams = decodeFormBody(calls[11]);
        assert.equal(approveParams.get("formPassword"), "operator-password");
        assert.equal(headerValue(calls[11].headers, "X-Crypta-App-Session"), null);
        const rejectParams = decodeFormBody(calls[12]);
        assert.equal(rejectParams.get("formPassword"), "operator-password");
        assert.equal(headerValue(calls[12].headers, "X-Crypta-App-Session"), null);
        const renewParams = decodeFormBody(calls[13]);
        assert.equal(renewParams.get("formPassword"), "operator-password");
        assert.equal(headerValue(calls[13].headers, "X-Crypta-App-Session"), null);
        """);
  }

  @Test
  void classpathResource_whenAppServiceInvokeHasServiceSpecificParams_expectForwardedAsForm()
      throws Exception {
    runSdkNode(
        """
        enqueueBootstrap();
        enqueueResponse(
          (url, options) => {
            const parsed = new URL(url);
            return parsed.pathname === "/api/v1/app-services/profile-app/services/profile.lookup/invoke"
              && options.method === "POST";
          },
          { serviceCall: { status: "ok", result: { profileId: "alice" } } });

        const invoked = await CryptaPlatform.services.invoke("profile-app", "profile.lookup", {
          scope: "profile.read",
          profileId: "alice",
          includeMeta: true,
          limit: 2,
          tags: ["local", "trusted"],
          appId: "feed-reader",
          force: true
        });

        assert.equal(invoked.serviceCall.result.profileId, "alice");
        const params = decodeFormBody(calls[1]);
        assert.equal(params.get("scope"), "profile.read");
        assert.equal(params.get("profileId"), "alice");
        assert.equal(params.get("includeMeta"), "true");
        assert.equal(params.get("limit"), "2");
        assert.deepEqual(params.getAll("tags"), ["local", "trusted"]);
        assert.equal(params.has("subjectKind"), false);
        assert.equal(params.has("subjectUri"), false);
        assert.equal(params.has("context"), false);
        assert.equal(params.has("appId"), false);
        assert.equal(params.has("force"), false);
        assert.equal(headerValue(calls[1].headers, "X-Crypta-App-Session"), "session-token");
        assert.equal(calls[1].credentials, "omit");
        """);
  }

  @Test
  void classpathResource_whenContentFetchRequested_expectSessionHeaderUsed() throws Exception {
    runSdkNode(
        """
        enqueueBootstrap();
        enqueueResponse(
          (url, options) => {
            const parsed = new URL(url);
            return parsed.pathname === "/api/v1/content/fetch"
              && options.method === "POST";
          },
          { contentText: "feed text", requestedUri: "CHK@feed", bytesLength: 9, format: "text" });

        const response = await CryptaPlatform.content.fetchText({ uri: "CHK@feed", maxBytes: 4096 });

        assert.equal(response.contentText, "feed text");
        assert.equal(calls.length, 2);
        assert.equal(calls[1].method, "POST");
        assert.equal(headerValue(calls[1].headers, "X-Crypta-App-Session"), "session-token");
        assert.match(
          headerValue(calls[1].headers, "Content-Type"),
          /^application\\/x-www-form-urlencoded/);
        const params = decodeFormBody(calls[1]);
        assert.equal(params.get("uri"), "CHK@feed");
        assert.equal(params.get("maxBytes"), "4096");
        assert.equal(params.get("format"), "text");
        assert.equal(calls[1].credentials, "omit");
        """);
  }

  @Test
  void classpathResource_whenContentSubscriptionRequested_expectRoutesAndFormFields()
      throws Exception {
    runSdkNode(
        """
        enqueueBootstrap();
        enqueueResponse(
          (url, options) => {
            const parsed = new URL(url);
            return parsed.pathname === "/api/v1/content/subscriptions"
              && options.method === "POST";
          },
          { subscription: { subscriptionId: "sub-alpha" } });
        enqueueResponse(
          (url, options) => {
            const parsed = new URL(url);
            return parsed.pathname === "/api/v1/content/subscriptions"
              && options.method === "GET";
          },
          { subscriptions: [] });
        enqueueResponse(
          (url, options) => {
            const parsed = new URL(url);
            return parsed.pathname === "/api/v1/content/subscriptions/sub-alpha"
              && options.method === "GET";
          },
          { subscription: { subscriptionId: "sub-alpha" } });
        enqueueResponse(
          (url, options) => {
            const parsed = new URL(url);
            return parsed.pathname === "/api/v1/content/subscriptions/sub-alpha/refresh"
              && options.method === "POST";
          },
          { subscription: { status: "success" } });
        enqueueResponse(
          (url, options) => {
            const parsed = new URL(url);
            return parsed.pathname === "/api/v1/content/subscriptions/sub-alpha/pause"
              && options.method === "POST";
          },
          { subscription: { status: "paused" } });
        enqueueResponse(
          (url, options) => {
            const parsed = new URL(url);
            return parsed.pathname === "/api/v1/content/subscriptions/sub-alpha/resume"
              && options.method === "POST";
          },
          { subscription: { status: "scheduled" } });
        enqueueResponse(
          (url, options) => {
            const parsed = new URL(url);
            return parsed.pathname === "/api/v1/content/subscriptions/sub-alpha"
              && options.method === "DELETE";
          },
          { subscription: { status: "deleted" } });

        const created = await CryptaPlatform.content.subscriptions.create({
          uri: "crypta:USK@example/feed/7/feed.json",
          label: "Daily feed",
          pollIntervalSeconds: 300,
          maxBytes: 262144,
          timeoutMillis: 30000,
          headers: { "X-Custom": "value" }
        });
        const createParams = decodeFormBody(calls[1]);
        assert.equal(created.subscription.subscriptionId, "sub-alpha");
        assert.equal(createParams.get("uri"), "crypta:USK@example/feed/7/feed.json");
        assert.equal(createParams.get("label"), "Daily feed");
        assert.equal(createParams.get("pollIntervalSeconds"), "300");
        assert.equal(createParams.get("maxBytes"), "262144");
        assert.equal(createParams.get("timeoutMillis"), "30000");
        assert.equal(headerValue(calls[1].headers, "X-Custom"), "value");
        assert.equal(headerValue(calls[1].headers, "X-Crypta-App-Session"), "session-token");

        await CryptaPlatform.content.subscriptions.list();
        await CryptaPlatform.content.subscriptions.get("sub-alpha");
        await CryptaPlatform.content.subscriptions.refresh("sub-alpha");
        await CryptaPlatform.content.subscriptions.pause({ subscriptionId: "sub-alpha" });
        await CryptaPlatform.content.subscriptions.resume("sub-alpha");
        await CryptaPlatform.content.subscriptions.remove("sub-alpha");

        assert.equal(calls.length, 8);
        assert.throws(
          () => CryptaPlatform.content.subscriptions.get("../secret"),
          /normalized local path segment/);
        """);
  }

  @Test
  void classpathResource_whenAppDataHelpersRequested_expectRoutesAndFormFields() throws Exception {
    runSdkNode(
        """
        enqueueBootstrap();
        enqueueResponse(
          (url, options) => {
            const parsed = new URL(url);
            return parsed.pathname === "/api/v1/app-data/records"
              && options.method === "POST";
          },
          { record: { namespace: "ui-state", key: "settings", valueText: "{\\"theme\\":\\"dark\\"}" } });
        enqueueResponse(
          (url, options) => {
            const parsed = new URL(url);
            return parsed.pathname === "/api/v1/app-data/records/ui-state/settings"
              && options.method === "GET";
          },
          { record: { namespace: "ui-state", key: "settings", valueText: "{\\"theme\\":\\"dark\\"}" } });
        enqueueResponse(
          (url, options) => {
            const parsed = new URL(url);
            return parsed.pathname === "/api/v1/app-data/namespaces/ui-state/schema"
              && options.method === "POST";
          },
          { namespace: { namespace: "ui-state", schemaVersion: 2 } });
        enqueueResponse(
          (url, options) => {
            const parsed = new URL(url);
            return parsed.pathname === "/api/v1/app-data/export"
              && parsed.searchParams.get("namespace") === "ui-state"
              && options.method === "GET";
          },
          { export: { payloadBase64: "eyJleHBvcnRWZXJzaW9uIjoxfQ" } });
        enqueueResponse(
          (url, options) => {
            const parsed = new URL(url);
            return parsed.pathname === "/api/v1/app-data/import"
              && options.method === "POST";
          },
          { import: { imported: true, recordCount: 1 } });
        enqueueResponse(
          (url, options) => {
            const parsed = new URL(url);
            return parsed.pathname === "/api/v1/app-data/import"
              && options.method === "POST";
          },
          { import: { imported: true, recordCount: 1 } });

        const stored = await CryptaPlatform.data.records.putJson({
          namespace: "ui-state",
          key: "settings",
          schemaVersion: 1,
          value: { theme: "dark" },
          headers: { "X-Custom": "value" }
        });
        assert.equal(stored.namespace, "ui-state");
        const putParams = decodeFormBody(calls[1]);
        assert.equal(putParams.get("namespace"), "ui-state");
        assert.equal(putParams.get("key"), "settings");
        assert.equal(putParams.get("schemaVersion"), "1");
        assert.equal(putParams.get("contentType"), "application/json");
        assert.deepStrictEqual(JSON.parse(putParams.get("valueJson")), { theme: "dark" });
        assert.equal(headerValue(calls[1].headers, "X-Crypta-App-Session"), "session-token");
        assert.equal(headerValue(calls[1].headers, "X-Custom"), "value");

        const value = await CryptaPlatform.data.records.getJson("ui-state", "settings");
        assert.equal(value.theme, "dark");

        const namespace = await CryptaPlatform.data.namespaces.migrate("ui-state", {
          fromSchemaVersion: 1,
          toSchemaVersion: 2,
          summary: "settings migration"
        });
        assert.equal(namespace.schemaVersion, 2);
        const migrationParams = decodeFormBody(calls[3]);
        assert.equal(migrationParams.get("fromSchemaVersion"), "1");
        assert.equal(migrationParams.get("toSchemaVersion"), "2");
        assert.equal(migrationParams.get("summary"), "settings migration");

        const exported = await CryptaPlatform.data.export({ namespace: "ui-state" });
        assert.equal(exported.payloadBase64, "eyJleHBvcnRWZXJzaW9uIjoxfQ");

        const imported = await CryptaPlatform.data.import(exported, { mode: "merge" });
        assert.equal(imported.imported, true);
        const importParams = decodeFormBody(calls[5]);
        assert.equal(importParams.get("mode"), "merge");
        assert.equal(importParams.get("payloadBase64"), "eyJleHBvcnRWZXJzaW9uIjoxfQ");

        await CryptaPlatform.data.import({ exportVersion: 1, records: [] }, { mode: "merge" });
        const importJsonParams = decodeFormBody(calls[6]);
        assert.deepStrictEqual(
          JSON.parse(Buffer.from(importJsonParams.get("payloadBase64"), "base64").toString("utf8")),
          { exportVersion: 1, records: [] });

        assert.throws(
          () => CryptaPlatform.data.records.get("ui-state", "../secret"),
          /normalized local path segment/);
        """);
  }

  @Test
  void classpathResource_whenFeedParserReceivesCanonicalJson_expectNormalizedSnapshot()
      throws Exception {
    runSdkNode(
        """
        context.executed = false;
        const snapshot = CryptaPlatform.feed.parseSnapshot(JSON.stringify({
          type: "crypta.feed.snapshot.v1",
          title: " Example Feed ",
          updatedAt: " 2026-05-16T00:00:00Z ",
          source: {
            uri: " USK@feed ",
            resolvedUri: " USK@feed/42/feed.json "
          },
          author: {
            name: " Alice ",
            profileUri: " USK@alice/profile.json "
          },
          items: [{
            id: " entry-1 ",
            title: " Hello ",
            summary: " <script>globalThis.executed = true;</script> ",
            uri: " CHK@entry ",
            tags: [" beta ", "alpha", "alpha", ""]
          }]
        }));

        assert.deepStrictEqual(JSON.parse(JSON.stringify(snapshot)), {
          type: "crypta.feed.snapshot.v1",
          title: "Example Feed",
          updatedAt: "2026-05-16T00:00:00Z",
          source: {
            uri: "USK@feed",
            resolvedUri: "USK@feed/42/feed.json"
          },
          author: {
            name: "Alice",
            profileUri: "USK@alice/profile.json"
          },
          items: [{
            id: "entry-1",
            title: "Hello",
            summary: "<script>globalThis.executed = true;</script>",
            uri: "CHK@entry",
            tags: ["alpha", "beta"]
          }]
        });
        assert.equal(context.executed, false);
        assert.equal(Object.hasOwn(snapshot.items[0], "contentHtml"), false);
        """);
  }

  @Test
  void classpathResource_whenFeedParserReceivesInvalidSnapshot_expectRejection() throws Exception {
    runSdkNode(
        """
        assert.throws(
          () => CryptaPlatform.feed.parseSnapshot(JSON.stringify({
            type: "wrong",
            items: []
          })),
          /Feed snapshot type must be crypta\\.feed\\.snapshot\\.v1/);

        assert.throws(
          () => CryptaPlatform.feed.parseSnapshot(JSON.stringify({
            type: "crypta.feed.snapshot.v1",
            items: Array.from({ length: 101 }, () => ({}))
          })),
          /at most 100 items/);

        assert.throws(
          () => CryptaPlatform.feed.parseSnapshot(JSON.stringify({
            type: "crypta.feed.snapshot.v1",
            title: "Feed",
            unsupported: "field",
            items: []
          })),
          /Feed snapshot field unsupported is not supported/);

        assert.throws(
          () => CryptaPlatform.feed.parseSnapshot(JSON.stringify({
            type: "crypta.feed.snapshot.v1",
            items: [{ title: "Entry", contentHtml: "<b>unsafe</b>" }]
          })),
          /Feed item field contentHtml is not supported/);

        assert.throws(
          () => CryptaPlatform.feed.parseSnapshot(JSON.stringify({
            type: "crypta.feed.snapshot.v1",
            title: "x".repeat(70000),
            items: []
          })),
          /Feed snapshot document is too large/);
        """);
  }

  @Test
  void classpathResource_whenFeedSnapshotPublished_expectAppDocumentOptions() throws Exception {
    runSdkNode(
        """
        enqueueBootstrap();
        enqueueResponse(
          (url, options) => {
            const parsed = new URL(url);
            return parsed.pathname === "/api/v1/queue/inserts/app-document"
              && options.method === "POST";
          },
          { requestId: "insert-1" });

        const result = await CryptaPlatform.feed.publishSnapshot({
          insertUri: "USK@feed",
          identifier: "feed-root",
          snapshot: {
            type: "crypta.feed.snapshot.v1",
            title: " Feed ",
            items: []
          },
          contentType: "text/plain",
          targetFilename: "unsafe.html",
          compress: true,
          headers: { "X-Custom": "value" }
        });

        assert.equal(result.requestId, "insert-1");
        assert.equal(calls.length, 2);
        const post = calls[1];
        assert.equal(headerValue(post.headers, "X-Crypta-App-Session"), "session-token");
        assert.equal(headerValue(post.headers, "X-Custom"), "value");
        assert.match(
          headerValue(post.headers, "Content-Type"),
          /^application\\/x-www-form-urlencoded/);

        const params = decodeFormBody(post);
        assert.equal(params.get("insertUri"), "USK@feed");
        assert.equal(params.get("identifier"), "feed-root");
        assert.equal(params.get("contentType"), "application/vnd.crypta.feed+json");
        assert.equal(params.get("targetFilename"), "feed.json");
        assert.equal(params.get("compress"), "true");

        const documentJson = Buffer.from(params.get("documentBase64"), "base64").toString("utf8");
        assert.deepStrictEqual(JSON.parse(documentJson), {
          type: "crypta.feed.snapshot.v1",
          title: "Feed",
          source: {},
          author: {},
          items: []
        });
        """);
  }

  @Test
  void classpathResource_whenTrustScoreRequested_expectScoreRouteAndQueryParams() throws Exception {
    runSdkNode(
        """
        enqueueBootstrap();
        enqueueResponse(
          (url, options) => {
            const parsed = new URL(url);
            return parsed.pathname === "/api/v1/trust-graph/score"
              && parsed.searchParams.get("subjectKind") === "profile"
              && parsed.searchParams.get("subjectUri") === "USK@alice/profile.json"
              && parsed.searchParams.get("context") === "profile"
              && parsed.searchParams.get("includeEvidence") === "true"
              && options.method === "GET";
          },
          { score: { status: "trusted", score: 42, confidence: 73 } });

        const result = await CryptaPlatform.trust.score({
          subjectKind: "profile",
          subjectUri: "USK@alice/profile.json",
          context: "profile",
          includeEvidence: true
        });

        assert.equal(result.status, "trusted");
        assert.equal(result.score, 42);
        assert.equal(calls.length, 2);
        assert.equal(headerValue(calls[1].headers, "X-Crypta-App-Session"), "session-token");
        assert.equal(calls[1].credentials, "omit");
        """);
  }

  @Test
  void classpathResource_whenTrustImportPreviewRequested_expectDocumentAliasesUriAliasAndUriRoute()
      throws Exception {
    runSdkNode(
        """
        enqueueBootstrap();
        enqueueResponse(
          (url, options) => {
            const parsed = new URL(url);
            return parsed.pathname === "/api/v1/trust-graph/import-preview"
              && options.method === "POST";
          },
          { importPreview: { candidateCount: 1, sourceUriKind: "content-uri" } });
        enqueueResponse(
          (url, options) => {
            const parsed = new URL(url);
            return parsed.pathname === "/api/v1/trust-graph/import-preview"
              && options.method === "POST";
          },
          { importPreview: { candidateCount: 1, sourceUriKind: "content-uri" } });
        enqueueResponse(
          (url, options) => {
            const parsed = new URL(url);
            return parsed.pathname === "/api/v1/trust-graph/import-preview"
              && options.method === "POST";
          },
          { importPreview: { candidateCount: 1, sourceUriKind: "content-uri" } });
        enqueueResponse(
          (url, options) => {
            const parsed = new URL(url);
            return parsed.pathname === "/api/v1/trust-graph/import-preview-uri"
              && options.method === "POST";
          },
          { importPreview: { candidateCount: 1, sourceUriKind: "content-uri" } });

        const pasted = await CryptaPlatform.trust.previewImport({
          document: "{\\"type\\":\\"crypta.trust.statement.v1\\"}",
          uri: "crypta:CHK@source-metadata",
          sourceLabel: "Pasted statement"
        });
        assert.equal(pasted.candidateCount, 1);
        const pastedParams = decodeFormBody(calls[1]);
        assert.equal(pastedParams.get("document"), "{\\"type\\":\\"crypta.trust.statement.v1\\"}");
        assert.equal(pastedParams.get("sourceUri"), "crypta:CHK@source-metadata");
        assert.equal(pastedParams.has("uri"), false);
        assert.equal(pastedParams.get("sourceLabel"), "Pasted statement");

        const trustStatementAlias = await CryptaPlatform.trust.previewImport({
          trustStatement: "{\\"type\\":\\"crypta.trust.statement.v1\\",\\"id\\":\\"trust-statement-alias\\"}",
          sourceLabel: "Trust statement alias"
        });
        assert.equal(trustStatementAlias.candidateCount, 1);
        const trustStatementParams = decodeFormBody(calls[2]);
        assert.equal(
          trustStatementParams.get("document"),
          "{\\"type\\":\\"crypta.trust.statement.v1\\",\\"id\\":\\"trust-statement-alias\\"}");
        assert.equal(trustStatementParams.has("uri"), false);
        assert.equal(trustStatementParams.get("sourceLabel"), "Trust statement alias");

        const textAlias = await CryptaPlatform.trust.previewImport({
          text: "{\\"type\\":\\"crypta.trust.statement.v1\\",\\"id\\":\\"text-alias\\"}",
          sourceLabel: "Text alias"
        });
        assert.equal(textAlias.candidateCount, 1);
        const textParams = decodeFormBody(calls[3]);
        assert.equal(
          textParams.get("document"),
          "{\\"type\\":\\"crypta.trust.statement.v1\\",\\"id\\":\\"text-alias\\"}");
        assert.equal(textParams.has("uri"), false);
        assert.equal(textParams.get("sourceLabel"), "Text alias");

        const fetched = await CryptaPlatform.trust.previewImport({
          uri: "crypta:CHK@statement",
          maxBytes: 4096
        });
        assert.equal(fetched.candidateCount, 1);
        const fetchedParams = decodeFormBody(calls[4]);
        assert.equal(fetchedParams.get("uri"), "crypta:CHK@statement");
        assert.equal(fetchedParams.has("document"), false);
        assert.equal(fetchedParams.get("maxBytes"), "4096");
        """);
  }

  @Test
  void classpathResource_whenTrustExchangeHelpersRequested_expectRoutesAndFormFields()
      throws Exception {
    runSdkNode(
        """
        enqueueBootstrap();
        enqueueResponse(
          (url, options) => {
            const parsed = new URL(url);
            return parsed.pathname === "/api/v1/trust-graph/import-uri"
              && options.method === "POST";
          },
          { importResult: { documentFingerprint: "doc-1", payloadHash: "payload-1" } });
        enqueueResponse(
          (url, options) => {
            const parsed = new URL(url);
            return parsed.pathname === "/api/v1/trust-graph/audit"
              && parsed.searchParams.get("limit") === "5"
              && options.method === "GET";
          },
          { audit: [{ eventType: "statement_imported_from_uri" }] });
        enqueueResponse(
          (url, options) => {
            const parsed = new URL(url);
            return parsed.pathname === "/api/v1/content/subscriptions"
              && options.method === "POST";
          },
          { subscription: { subscriptionId: "trust-sub" } });

        const imported = await CryptaPlatform.trust.importUri({
          uri: "crypta:CHK@statement",
          sourceLabel: "Fetched statement",
          maxBytes: 4096,
          headers: { "X-Custom": "value" }
        });
        assert.equal(imported.documentFingerprint, "doc-1");
        const importParams = decodeFormBody(calls[1]);
        assert.equal(importParams.get("uri"), "crypta:CHK@statement");
        assert.equal(importParams.get("sourceLabel"), "Fetched statement");
        assert.equal(importParams.get("maxBytes"), "4096");
        assert.equal(headerValue(calls[1].headers, "X-Custom"), "value");

        const audit = await CryptaPlatform.trust.audit.list({ limit: 5 });
        assert.equal(audit[0].eventType, "statement_imported_from_uri");

        const subscription = await CryptaPlatform.trust.exchange.subscriptions.create({
          uri: "USK@example/trust/1/trust.json"
        });
        const subscriptionParams = decodeFormBody(calls[3]);
        assert.equal(subscription.subscription.subscriptionId, "trust-sub");
        assert.equal(subscriptionParams.get("uri"), "USK@example/trust/1/trust.json");
        assert.equal(subscriptionParams.get("label"), "Trust statement subscription");
        """);
  }

  @Test
  void classpathResource_whenTrustStatementPublished_expectAppDocumentDefaults() throws Exception {
    runSdkNode(
        """
        enqueueBootstrap();
        enqueueResponse(
          (url, options) => {
            const parsed = new URL(url);
            return parsed.pathname === "/api/v1/trust-graph/import"
              && options.method === "POST";
          },
          {
            importResult: {
              documentFingerprint: "doc-prepared",
              payloadHash: "payload-prepared",
              signatureVerified: true,
              source: "local-import"
            }
          });
        enqueueResponse(
          (url, options) => {
            const parsed = new URL(url);
            return parsed.pathname === "/api/v1/queue/inserts/app-document"
              && options.method === "POST";
          },
          { requestId: "trust-insert-1" });
        enqueueResponse(
          (url, options) => {
            const parsed = new URL(url);
            return parsed.pathname === "/api/v1/trust-graph/import"
              && options.method === "POST";
          },
          {
            importResult: {
              documentFingerprint: "doc-published",
              payloadHash: "payload-published",
              signatureVerified: true,
              source: "local-publish"
            }
          });

        const result = await CryptaPlatform.trust.publishStatement({
          insertUri: "USK@trust",
          identifier: "trust-root",
          statement: {
            trustStatement: {
              identity: { identityId: "issuer", publicKeyFingerprint: "fingerprint", appId: "trust-graph" },
              payloadHash: "metadata-wrapper-hash",
              domain: "crypta.trust.statement.v1",
              trustStatement: {
                type: "crypta.trust.statement.v1",
                payload: {
                  issuer: { identityId: "issuer", publicKeyFingerprint: "fingerprint" },
                  subject: { kind: "profile", uri: "USK@alice/profile.json" },
                  context: "profile",
                  score: 50,
                  confidence: 80,
                  issuedAt: "2026-05-16T00:00:00Z"
                },
                signature: { algorithm: "app-vault-ed25519-preview", domain: "crypta.trust.statement.v1", value: "fixture" }
              }
            }
          },
          contentType: "text/plain",
          targetFilename: "unsafe.json"
        });

        assert.equal(result.requestId, "trust-insert-1");
        assert.equal(result.queue.requestId, "trust-insert-1");
        assert.equal(result.documentFingerprint, "doc-published");
        assert.equal(result.payloadHash, "payload-published");
        assert.equal(result.signatureVerified, true);
        assert.equal(calls.length, 4);
        const params = decodeFormBody(calls[2]);
        assert.equal(params.get("insertUri"), "USK@trust");
        assert.equal(params.get("identifier"), "trust-root");
        assert.equal(params.get("contentType"), "application/vnd.crypta.trust+json");
        assert.equal(params.get("targetFilename"), "trust.json");
        const documentJson = Buffer.from(params.get("documentBase64"), "base64").toString("utf8");
        const document = JSON.parse(documentJson);
        assert.equal(document.type, "crypta.trust.statement.v1");
        assert.equal(document.signature.value, "fixture");
        assert.equal(document.payloadHash, undefined);
        const preparedImportParams = decodeFormBody(calls[1]);
        assert.equal(preparedImportParams.get("source"), "local-import");
        assert.equal(preparedImportParams.get("sourceLabel"), "Prepared statement for publish");
        const publishImportParams = decodeFormBody(calls[3]);
        assert.equal(publishImportParams.get("source"), "local-publish");
        assert.equal(publishImportParams.get("sourceLabel"), "Published statement");
        const importedDocument = JSON.parse(publishImportParams.get("document"));
        assert.equal(importedDocument.type, "crypta.trust.statement.v1");
        assert.equal(importedDocument.signature.value, "fixture");
        """);
  }

  @Test
  void classpathResource_whenTrustPublishImportFails_expectQueueInsertNotCreated()
      throws Exception {
    runSdkNode(
        """
        enqueueBootstrap();
        enqueueResponse(
          (url, options) => {
            const parsed = new URL(url);
            return parsed.pathname === "/api/v1/trust-graph/import"
              && options.method === "POST";
          },
          {
            error: {
              code: "trust_graph_store_unavailable",
              message: "Trust graph store is unavailable."
            }
          },
          503,
          "Service Unavailable");

        let failed = false;
        try {
          await CryptaPlatform.trust.publishStatement({
            insertUri: "USK@trust",
            identifier: "trust-root",
            statement: {
              type: "crypta.trust.statement.v1",
              payload: {
                issuer: { identityId: "issuer", publicKeyFingerprint: "fingerprint" },
                subject: { kind: "profile", uri: "USK@alice/profile.json" },
                context: "profile",
                score: 50,
                confidence: 80,
                issuedAt: "2026-05-16T00:00:00Z"
              },
              signature: { algorithm: "app-vault-ed25519-preview", domain: "crypta.trust.statement.v1", value: "fixture" }
            }
          });
        } catch (error) {
          failed = true;
          assert.equal(error.code, "trust_graph_store_unavailable");
        }

        assert.equal(failed, true);
        assert.equal(calls.length, 2);
        assert.equal(new URL(calls[1].url).pathname, "/api/v1/trust-graph/import");
        const importParams = decodeFormBody(calls[1]);
        assert.equal(importParams.get("source"), "local-import");
        """);
  }

  @Test
  void classpathResource_whenTrustPublishQueueFails_expectLocalPublishNotRecorded()
      throws Exception {
    runSdkNode(
        """
        enqueueBootstrap();
        enqueueResponse(
          (url, options) => {
            const parsed = new URL(url);
            return parsed.pathname === "/api/v1/trust-graph/import"
              && options.method === "POST";
          },
          {
            importResult: {
              documentFingerprint: "doc-prepared",
              payloadHash: "payload-prepared",
              signatureVerified: true,
              source: "local-import"
            }
          });
        enqueueResponse(
          (url, options) => {
            const parsed = new URL(url);
            return parsed.pathname === "/api/v1/queue/inserts/app-document"
              && options.method === "POST";
          },
          {
            error: {
              code: "invalid_insert_uri",
              message: "Invalid insert URI."
            }
          },
          400,
          "Bad Request");

        let failed = false;
        try {
          await CryptaPlatform.trust.publishStatement({
            insertUri: "USK@trust",
            identifier: "trust-root",
            statement: {
              type: "crypta.trust.statement.v1",
              payload: {
                issuer: { identityId: "issuer", publicKeyFingerprint: "fingerprint" },
                subject: { kind: "profile", uri: "USK@alice/profile.json" },
                context: "profile",
                score: 50,
                confidence: 80,
                issuedAt: "2026-05-16T00:00:00Z"
              },
              signature: { algorithm: "app-vault-ed25519-preview", domain: "crypta.trust.statement.v1", value: "fixture" }
            }
          });
        } catch (error) {
          failed = true;
          assert.equal(error.code, "invalid_insert_uri");
        }

        assert.equal(failed, true);
        assert.equal(calls.length, 3);
        const importParams = decodeFormBody(calls[1]);
        assert.equal(importParams.get("source"), "local-import");
        const queueParams = decodeFormBody(calls[2]);
        assert.equal(queueParams.get("insertUri"), "USK@trust");
        assert.equal(
          calls.filter((call) => String(call.url).includes("/api/v1/trust-graph/import")).length,
          1);
        """);
  }

  @Test
  void classpathResource_whenTrustPublishFinalImportFails_expectQueueResultReturned()
      throws Exception {
    runSdkNode(
        """
        enqueueBootstrap();
        enqueueResponse(
          (url, options) => {
            const parsed = new URL(url);
            return parsed.pathname === "/api/v1/trust-graph/import"
              && options.method === "POST";
          },
          {
            importResult: {
              documentFingerprint: "doc-prepared",
              payloadHash: "payload-prepared",
              signatureVerified: true,
              source: "local-import"
            }
          });
        enqueueResponse(
          (url, options) => {
            const parsed = new URL(url);
            return parsed.pathname === "/api/v1/queue/inserts/app-document"
              && options.method === "POST";
          },
          { requestId: "trust-insert-queued" });
        enqueueResponse(
          (url, options) => {
            const parsed = new URL(url);
            return parsed.pathname === "/api/v1/trust-graph/import"
              && options.method === "POST";
          },
          {
            error: {
              code: "trust_graph_store_unavailable",
              message: "Trust graph store is unavailable."
            }
          },
          503,
          "Service Unavailable");

        const result = await CryptaPlatform.trust.publishStatement({
          insertUri: "USK@trust",
          identifier: "trust-root",
          statement: {
            type: "crypta.trust.statement.v1",
            payload: {
              issuer: { identityId: "issuer", publicKeyFingerprint: "fingerprint" },
              subject: { kind: "profile", uri: "USK@alice/profile.json" },
              context: "profile",
              score: 50,
              confidence: 80,
              issuedAt: "2026-05-16T00:00:00Z"
            },
            signature: { algorithm: "app-vault-ed25519-preview", domain: "crypta.trust.statement.v1", value: "fixture" }
          }
        });

        assert.equal(result.requestId, "trust-insert-queued");
        assert.equal(result.documentFingerprint, "doc-prepared");
        assert.equal(result.source, "local-import");
        assert.equal(result.localPublishImportError.code, "trust_graph_store_unavailable");
        assert.equal(
          result.localPublishImportError.message,
          "Trust statement was queued, but local publish metadata could not be refreshed.");
        assert.equal(calls.length, 4);
        const preparedImportParams = decodeFormBody(calls[1]);
        assert.equal(preparedImportParams.get("source"), "local-import");
        const publishImportParams = decodeFormBody(calls[3]);
        assert.equal(publishImportParams.get("source"), "local-publish");
        """);
  }

  @Test
  void classpathResource_whenSerializedTrustStatementResponsePublished_expectInnerDocument()
      throws Exception {
    runSdkNode(
        """
        enqueueBootstrap();
        enqueueResponse(
          (url, options) => {
            const parsed = new URL(url);
            return parsed.pathname === "/api/v1/trust-graph/import"
              && options.method === "POST";
          },
          {
            importResult: {
              documentFingerprint: "doc-prepared-serialized",
              payloadHash: "payload-prepared-serialized",
              signatureVerified: true,
              source: "local-import"
            }
          });
        enqueueResponse(
          (url, options) => {
            const parsed = new URL(url);
            return parsed.pathname === "/api/v1/queue/inserts/app-document"
              && options.method === "POST";
          },
          { requestId: "trust-insert-serialized" });
        enqueueResponse(
          (url, options) => {
            const parsed = new URL(url);
            return parsed.pathname === "/api/v1/trust-graph/import"
              && options.method === "POST";
          },
          {
            importResult: {
              documentFingerprint: "doc-serialized",
              payloadHash: "payload-serialized",
              signatureVerified: true,
              source: "local-publish"
            }
          });

        const signedResponse = JSON.stringify({
          identity: { identityId: "issuer", publicKeyFingerprint: "fingerprint", appId: "trust-graph" },
          payloadHash: "metadata-wrapper-hash",
          domain: "crypta.trust.statement.v1",
          trustStatement: {
            type: "crypta.trust.statement.v1",
            payload: {
              issuer: { identityId: "issuer", publicKeyFingerprint: "fingerprint" },
              subject: { kind: "profile", uri: "USK@alice/profile.json" },
              context: "profile",
              score: 50,
              confidence: 80,
              issuedAt: "2026-05-16T00:00:00Z"
            },
            signature: { algorithm: "app-vault-ed25519-preview", domain: "crypta.trust.statement.v1", value: "fixture" }
          }
        });

        const result = await CryptaPlatform.trust.publishStatement({
          insertUri: "USK@trust",
          identifier: "trust-root",
          statement: signedResponse
        });

        assert.equal(result.requestId, "trust-insert-serialized");
        assert.equal(result.documentFingerprint, "doc-serialized");
        const params = decodeFormBody(calls[2]);
        assert.equal(params.get("contentType"), "application/vnd.crypta.trust+json");
        assert.equal(params.get("targetFilename"), "trust.json");
        const documentJson = Buffer.from(params.get("documentBase64"), "base64").toString("utf8");
        const document = JSON.parse(documentJson);
        assert.equal(document.type, "crypta.trust.statement.v1");
        assert.equal(document.signature.value, "fixture");
        assert.equal(document.payloadHash, undefined);
        const preparedImportParams = decodeFormBody(calls[1]);
        assert.equal(preparedImportParams.get("source"), "local-import");
        const publishImportParams = decodeFormBody(calls[3]);
        assert.equal(publishImportParams.get("source"), "local-publish");
        const importedDocument = JSON.parse(publishImportParams.get("document"));
        assert.equal(importedDocument.type, "crypta.trust.statement.v1");
        assert.equal(importedDocument.signature.value, "fixture");
        """);
  }

  @Test
  void classpathResource_whenTrustExchangePublishSignsStatement_expectVaultQueueAndImport()
      throws Exception {
    runSdkNode(
        """
        enqueueBootstrap();
        enqueueResponse(
          (url, options) => {
            const parsed = new URL(url);
            return parsed.pathname === "/api/v1/app-vault/identities/issuer/trust-statement"
              && options.method === "POST";
          },
          {
            trustStatement: {
              type: "crypta.trust.statement.v1",
              payload: {
                issuer: { identityId: "issuer", publicKeyFingerprint: "fingerprint" },
                subject: { kind: "profile", uri: "USK@alice/profile.json" },
                context: "profile",
                score: 50,
                confidence: 80,
                issuedAt: "2026-05-16T00:00:00Z"
              },
              signature: {
                algorithm: "app-vault-ed25519-preview",
                domain: "crypta.trust.statement.v1",
                value: "fixture"
              }
            }
          });
        enqueueResponse(
          (url, options) => {
            const parsed = new URL(url);
            return parsed.pathname === "/api/v1/trust-graph/import"
              && options.method === "POST";
          },
          {
            importResult: {
              documentFingerprint: "doc-prepared-signed",
              payloadHash: "payload-prepared-signed",
              signatureVerified: true,
              source: "local-import"
            }
          });
        enqueueResponse(
          (url, options) => {
            const parsed = new URL(url);
            return parsed.pathname === "/api/v1/queue/inserts/app-document"
              && options.method === "POST";
          },
          { requestId: "trust-insert-signed" });
        enqueueResponse(
          (url, options) => {
            const parsed = new URL(url);
            return parsed.pathname === "/api/v1/trust-graph/import"
              && options.method === "POST";
          },
          {
            importResult: {
              documentFingerprint: "doc-signed",
              payloadHash: "payload-signed",
              signatureVerified: true,
              source: "local-publish"
            }
          });

        const result = await CryptaPlatform.trust.exchange.publish({
          identityId: "issuer",
          subjectKind: "profile",
          subjectUri: "USK@alice/profile.json",
          context: "profile",
          score: 50,
          confidence: 80,
          reason: "known publisher",
          insertUri: "USK@trust",
          identifier: "trust-root"
        });

        assert.equal(result.requestId, "trust-insert-signed");
        assert.equal(result.documentFingerprint, "doc-signed");
        const vaultParams = decodeFormBody(calls[1]);
        assert.equal(vaultParams.get("subjectKind"), "profile");
        assert.equal(vaultParams.get("subjectUri"), "USK@alice/profile.json");
        assert.equal(vaultParams.get("context"), "profile");
        assert.equal(vaultParams.get("score"), "50");
        assert.equal(vaultParams.get("confidence"), "80");
        const preparedImportParams = decodeFormBody(calls[2]);
        assert.equal(preparedImportParams.get("source"), "local-import");
        const importedDocument = JSON.parse(preparedImportParams.get("document"));
        assert.equal(importedDocument.type, "crypta.trust.statement.v1");
        assert.equal(importedDocument.signature.value, "fixture");
        const queueParams = decodeFormBody(calls[3]);
        assert.equal(queueParams.get("insertUri"), "USK@trust");
        assert.equal(queueParams.get("identifier"), "trust-root");
        assert.equal(queueParams.get("contentType"), "application/vnd.crypta.trust+json");
        const publishImportParams = decodeFormBody(calls[4]);
        assert.equal(publishImportParams.get("source"), "local-publish");
        """);
  }

  @Test
  void classpathResource_whenTrustStatementSigned_expectBoundedVaultRoute() throws Exception {
    runSdkNode(
        """
        enqueueBootstrap();
        enqueueResponse(
          (url, options) => {
            const parsed = new URL(url);
            return parsed.pathname === "/api/v1/app-vault/identities/trust-id/trust-statement"
              && options.method === "POST";
          },
          { trustStatement: { type: "crypta.trust.statement.v1" } });

        const result = await CryptaPlatform.vault.identities.createTrustStatement("trust-id", {
          subjectKind: "profile",
          subjectUri: "USK@alice/profile.json",
          context: "profile",
          score: 50,
          confidence: 80,
          reason: "known publisher",
          tags: ["local", "preview"],
          expiresAt: "2026-11-16T00:00:00Z"
        });

        assert.equal(result.trustStatement.type, "crypta.trust.statement.v1");
        const params = decodeFormBody(calls[1]);
        assert.equal(params.get("subjectKind"), "profile");
        assert.equal(params.get("subjectUri"), "USK@alice/profile.json");
        assert.equal(params.get("context"), "profile");
        assert.equal(params.get("score"), "50");
        assert.equal(params.get("confidence"), "80");
        assert.equal(params.get("tags"), "local,preview");
        assert.equal(params.get("expiresAt"), "2026-11-16T00:00:00Z");
        """);
  }

  @Test
  void classpathResource_whenSocialMessageSigned_expectBoundedVaultRoute() throws Exception {
    runSdkNode(
        """
        enqueueBootstrap();
        enqueueResponse(
          (url, options) => {
            const parsed = new URL(url);
            return parsed.pathname === "/api/v1/app-vault/identities/social-id/social-message"
              && options.method === "POST";
          },
          {
            socialMessage: {
              identity: { identityId: "social-id" },
              payloadHash: "hash",
              domain: "crypta.social.message.v1",
              socialMessage: { type: "crypta.social.message.v1" }
            }
          });

        const result = await CryptaPlatform.vault.identities.createSocialMessageDocument("social-id", {
          channel: "general",
          subject: "Hello",
          body: "Plain text body",
          authorLabel: "Ada",
          profileUri: "USK@example/profile/1/profile.json",
          replyTo: "msg-parent",
          recipientFingerprint: "recipient",
          tags: ["social", "preview"]
        });

        assert.equal(result.socialMessage.type, "crypta.social.message.v1");
        assert.equal(result.identity.identityId, "social-id");
        assert.equal(result.domain, "crypta.social.message.v1");
        const params = decodeFormBody(calls[1]);
        assert.equal(params.get("channel"), "general");
        assert.equal(params.get("subject"), "Hello");
        assert.equal(params.get("body"), "Plain text body");
        assert.equal(params.get("authorLabel"), "Ada");
        assert.equal(params.get("profileUri"), "USK@example/profile/1/profile.json");
        assert.equal(params.get("replyTo"), "msg-parent");
        assert.equal(params.get("recipientFingerprint"), "recipient");
        assert.equal(params.get("tags"), "social,preview");
        assert.equal(params.has("purpose"), false);
        assert.equal(params.has("domain"), false);
        assert.equal(params.has("payloadBase64"), false);
        """);
  }

  @Test
  void classpathResource_whenAppIdCanonicalizationRequested_expectComparisonUsesNormalizedIds()
      throws IOException {
    String script = readSdkScript();

    int requestedNormalization =
        script.indexOf("const requestedAppId = rawAppId ? normalizeAppId(rawAppId) : null;");
    int fetchWithNormalizedId = script.indexOf("fetchBootstrap(requestedAppId)");
    int bootstrapNormalization =
        script.indexOf("bootstrap.appId = normalizeAppId(bootstrap.appId);");
    int normalizedComparison =
        script.indexOf("bootstrap.appId && appId && bootstrap.appId !== appId");

    assertTrue(script.contains("const appIdPattern = /^[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?$/;"));
    assertTrue(script.contains("const normalized = appId.trim().toLowerCase();"));
    assertTrue(
        script.contains("const requestedAppId = rawAppId ? normalizeAppId(rawAppId) : null;"));
    assertTrue(script.contains("bootstrap.appId = normalizeAppId(bootstrap.appId);"));
    assertTrue(requestedNormalization >= 0);
    assertTrue(fetchWithNormalizedId > requestedNormalization);
    assertTrue(bootstrapNormalization >= 0);
    assertTrue(normalizedComparison > bootstrapNormalization);
  }

  private static String readSdkScript() throws IOException {
    try (InputStream stream =
        CryptaPlatformSdkResourceTest.class.getResourceAsStream(SDK_RESOURCE_PATH)) {
      assertNotNull(stream, "SDK resource must be available on the module classpath.");
      return new String(stream.readAllBytes(), StandardCharsets.UTF_8);
    }
  }

  private static void assertJsonDocumentHelperFragments(String script) {
    String[] expectedFragments = {
      "function insertAppDocument(options)",
      "function fetchText(uriOrOptions, options)",
      "function fetchBase64(uriOrOptions, options)",
      "function createContentSubscription(options)",
      "function contentSubscriptionPathSegment(value, description)",
      "\"content/fetch\"",
      "\"content/subscriptions\"",
      "normalizeContentFetchParams(source, format)",
      "normalizeContentSubscriptionCreate(source)",
      "\"queue/inserts/app-document\"",
      "function normalizeAppDocumentInsert(options)",
      "params.set(\"documentBase64\"",
      "copyStringParamAs(options, params, \"mimeType\", \"contentType\");",
      "jsonDocumentBase64(document, \"App document\")",
      "function jsonDocumentBase64(value, description)",
      "JSON.stringify(value)",
      "function utf8Base64(value)",
      "new TextEncoder().encode(value)",
      "return btoa(binary);",
      "function publishProfile(options)",
      "const profileDocumentResponse = await createProfileDocument(",
      "function profilePublishInsertOptions(source, document)",
      "options.identifier = `profile-${vaultPathSegment(source.identityId)}`;",
      "options.targetFilename = contentFormats.profileDocument.defaultFilename;",
      "options.contentType = contentFormats.profileDocument.contentType;",
      "insertAppDocument(",
      "profile: Object.freeze({",
      "publish: publishProfile"
    };
    for (String expectedFragment : expectedFragments) {
      assertTrue(
          script.contains(expectedFragment),
          () -> "Expected fragment missing: " + expectedFragment);
    }
  }

  private static void assertVaultMetadataBrowserHelperFragments(String script) {
    String[] expectedFragments = {
      "function listVaultIdentities(options)",
      "return apiGet(\"app-vault/identities\", options);",
      "function getVaultIdentity(identityId, options)",
      "function listVaultGrants(options)",
      "return apiGet(\"app-vault/grants\", options);",
      "function requestVaultGrant(request, options)",
      "return apiPostForm(\"app-vault/grants/request\"",
      "function normalizeVaultGrantRequest(request)",
      "function createVaultIdentity(options)",
      "return apiPostForm(",
      "\"app-vault/identities\"",
      "function createProfileDocument(identityId, profile, options)",
      "function createSocialMessageDocument(identityIdOrOptions, message, options)",
      "function createTrustStatement(identityIdOrOptions, payload, options)",
      "function normalizeProfileDocument(profile)",
      "function normalizeSocialMessageDocument(message)",
      "function normalizeTrustStatementPayload(source)",
      "copyStringParam(source, params, \"displayName\");",
      "copyStringParam(source, params, \"recipientFingerprint\");",
      "appendTagsParam(source.tags, params);",
      "/profile-document`",
      "/social-message`",
      "function normalizeVaultGrantScope(scope)",
      "normalized !== \"sign.domain-separated\"",
      "identities: Object.freeze({",
      "create: createVaultIdentity",
      "createProfileDocument",
      "createSocialMessageDocument",
      "createTrustStatement",
      "grants: Object.freeze({"
    };
    for (String expectedFragment : expectedFragments) {
      assertTrue(
          script.contains(expectedFragment),
          () -> "Expected vault helper fragment missing: " + expectedFragment);
    }
  }

  private static void assertNoVaultPrivateBrowserHelpers(String script) {
    String[] forbiddenFragments = {"app-vault/secrets", "useIdentity"};
    for (String forbiddenFragment : forbiddenFragments) {
      assertFalse(
          script.contains(forbiddenFragment),
          () -> "Forbidden vault helper fragment present: " + forbiddenFragment);
    }
  }

  private static void assertNoRawMutationFetches(String script) {
    String[] forbiddenFragments = {
      "fetch(apiUrl(\"queue/inserts/app-document\"", "fetch(apiUrl(\"app-vault/identities\""
    };
    for (String forbiddenFragment : forbiddenFragments) {
      assertFalse(
          script.contains(forbiddenFragment),
          () -> "Forbidden fragment present: " + forbiddenFragment);
    }
  }

  @Test
  void insertPlainText_whenMarkupAndUnicode_expectExactUtf8AndNewChkOnly() throws Exception {
    runSdkNode(
        """
        enqueueBootstrap();
        await CryptaPlatform.bootstrap.load({ appId: "feed-reader" });
        enqueueResponse((url) => url.endsWith("/queue/inserts/app-document"), { outcome: "queued" });
        const text = "<script>alert('literal')</script>\\r\\n雪\\n";
        await CryptaPlatform.content.insertPlainText({ text, identifier: "test-text", insertUri: "USK@ignored" });
        const body = decodeFormBody(calls[calls.length - 1]);
        assert.strictEqual(Buffer.from(body.get("documentBase64"), "base64").toString("utf8"), text);
        assert.strictEqual(body.get("insertUri"), "CHK@");
        assert.strictEqual(body.get("contentType"), "text/plain; charset=utf-8");
        assert.strictEqual(body.get("targetFilename"), "draft.txt");
        assert.strictEqual(body.has("sourcePath"), false);
        const count = calls.length;
        assert.throws(() => CryptaPlatform.content.insertPlainText({ text: "雪".repeat(21846) }));
        assert.strictEqual(calls.length, count);
        """);
  }

  @Test
  void putRecord_whenGuardedDraftPreview_expectCompleteFenceParameters() throws Exception {
    runSdkNode(
        """
        enqueueBootstrap();
        await CryptaPlatform.bootstrap.load({ appId: "feed-reader" });
        enqueueResponse((url) => url.endsWith("/app-data/records"), { record: { previewId: "preview" } });
        await CryptaPlatform.data.records.put({ namespace: "sharesite-drafts", key: "dataset",
          schemaVersion: 1, valueJson: "{}", ifMatchSha256: "absent", writeIntent: "preview",
          writePreviewId: "preview", writeMode: "import", backupReady: "true" });
        const body = decodeFormBody(calls[calls.length - 1]);
        for (const [key, value] of Object.entries({ ifMatchSha256: "absent", writeIntent: "preview",
          writePreviewId: "preview", writeMode: "import", backupReady: "true" })) {
          assert.strictEqual(body.get(key), value);
        }
        """);
  }

  private void runSdkNode(String scriptBody) throws Exception {
    Assumptions.assumeTrue(nodeAvailable(), "Node.js is required for SDK behavior tests.");
    Path sdkScript = tempDir.resolve("crypta-platform.js");
    Path harness = tempDir.resolve("sdk-harness.js");
    Files.writeString(sdkScript, readSdkScript(), StandardCharsets.UTF_8);
    Files.writeString(harness, nodeHarness(scriptBody), StandardCharsets.UTF_8);

    Process process = new ProcessBuilder("node", harness.toString(), sdkScript.toString()).start();
    boolean finished = process.waitFor(10, TimeUnit.SECONDS);
    if (!finished) {
      process.destroyForcibly();
    }
    String output =
        new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8)
            + new String(process.getErrorStream().readAllBytes(), StandardCharsets.UTF_8);
    assertTrue(finished, output);
    assertEquals(0, process.exitValue(), output);
  }

  private static boolean nodeAvailable() {
    try {
      Process process = new ProcessBuilder("node", "--version").start();
      boolean finished = process.waitFor(5, TimeUnit.SECONDS);
      if (!finished) {
        process.destroyForcibly();
        return false;
      }
      return process.exitValue() == 0;
    } catch (IOException _) {
      return false;
    } catch (InterruptedException _) {
      Thread.currentThread().interrupt();
      return false;
    }
  }

  private static String nodeHarness(String scriptBody) {
    return """
    const fs = require("fs");
    const vm = require("vm");
    const assert = require("assert");
    const { TextDecoder, TextEncoder } = require("util");

    class SimpleHeaders {
      constructor(init = {}) {
        this.values = new Map();
        if (typeof init.forEach === "function") {
          init.forEach((value, key) => this.set(key, value));
        } else if (Array.isArray(init)) {
          init.forEach(([key, value]) => this.set(key, value));
        } else {
          Object.entries(init).forEach(([key, value]) => this.set(key, value));
        }
      }

      set(name, value) {
        this.values.set(String(name).toLowerCase(), String(value));
      }

      get(name) {
        return this.values.get(String(name).toLowerCase()) || null;
      }

      has(name) {
        return this.values.has(String(name).toLowerCase());
      }

      forEach(callback) {
        this.values.forEach((value, key) => callback(value, key));
      }
    }

    class MockResponse {
      constructor(status, body, statusText = "OK") {
        this.status = status;
        this.statusText = statusText;
        this.ok = status >= 200 && status < 300;
        this.body = body;
      }

      async json() {
        return this.body;
      }
    }

    const HeadersImpl = global.Headers || SimpleHeaders;
    const calls = [];
    const responses = [];
    const bootstrap = {
      appId: "feed-reader",
      name: "Feed Reader",
      platformApiRoot: "http://127.0.0.1:8181/api/v1/",
      browserSessionToken: "session-token",
      browserSessionExpiresAt: "2999-01-01T00:00:00Z"
    };

    function enqueueResponse(matcher, body, status = 200, statusText = "OK") {
      responses.push({ matcher, body, status, statusText });
    }

    function enqueueBootstrap() {
      enqueueResponse((url) => url.endsWith("/.well-known/cryptad-bootstrap.json"), bootstrap);
    }

    function headerValue(headers, name) {
      if (!headers) {
        return null;
      }
      if (typeof headers.get === "function") {
        return headers.get(name);
      }
      return headers[name] || headers[name.toLowerCase()] || null;
    }

    function decodeFormBody(call) {
      return new URLSearchParams(call.body || "");
    }

    const context = {
      console,
      URL,
      URLSearchParams,
      TextEncoder,
      TextDecoder,
      Headers: HeadersImpl,
      btoa: (value) => Buffer.from(value, "binary").toString("base64"),
      atob: (value) => Buffer.from(value, "base64").toString("binary"),
      DOMParser: class {
        constructor() {
          throw new Error("DOMParser must not be used by feed helpers.");
        }
      },
      document: {
        createDocumentFragment() {
          throw new Error("document must not be used by feed helpers.");
        }
      },
      window: {
        location: {
          href: "http://127.0.0.1:3000/apps/feed-reader/static/index.html",
          pathname: "/apps/feed-reader/static/index.html",
          hash: ""
        }
      }
    };

    context.fetch = async (url, options = {}) => {
      const call = {
        url: String(url),
        method: options.method || "GET",
        headers: options.headers,
        body: options.body,
        credentials: options.credentials
      };
      calls.push(call);
      const response = responses.shift();
      assert.ok(response, `unexpected fetch: ${call.method} ${call.url}`);
      assert.ok(
        response.matcher(call.url, options),
        `unexpected fetch: ${call.method} ${call.url}`);
      return new MockResponse(response.status, response.body, response.statusText);
    };

    vm.createContext(context);
    const sdk = fs.readFileSync(process.argv[2], "utf8");
    vm.runInContext(sdk, context, { filename: "crypta-platform.js" });
    const CryptaPlatform = context.window.CryptaPlatform;

    (async () => {
    """
        + scriptBody
        + """
        })().catch((error) => {
          console.error(error && error.stack ? error.stack : error);
          process.exit(1);
        });
        """;
  }
}
