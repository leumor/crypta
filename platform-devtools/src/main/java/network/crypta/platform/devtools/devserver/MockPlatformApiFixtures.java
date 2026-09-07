package network.crypta.platform.devtools.devserver;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import network.crypta.platform.api.PlatformApiBaselineRegistry;
import network.crypta.platform.api.PlatformApiContract;
import network.crypta.platform.api.PlatformApiContractJson;
import network.crypta.platform.api.PlatformApiEndpointDescriptor;
import network.crypta.platform.api.contentformats.CanonicalJson;
import network.crypta.platform.appdist.AppDistributionException;

/**
 * Loads deterministic mock Platform API JSON fixtures.
 *
 * <p>The dev server can serve built-in fixture JSON or developer-provided JSON files from a single
 * fixture directory. Built-ins keep scaffolded apps useful without setup, while file fixtures let
 * tests and local demos exercise specific queue, vault, node, and current-app states. Fixture
 * values remain static for the life of the request; mutation routes return acknowledgements rather
 * than modifying fixture files.
 *
 * <p>When reading developer fixtures, this class refuses symlink fixture directories, symlink
 * files, non-regular files, path traversal outside the fixture directory, and JSON strings that
 * contain obvious absolute local paths. That keeps mock output from leaking workstation paths into
 * browser-visible responses or app test reports.
 */
final class MockPlatformApiFixtures {
  private static final String PROFILE_SIGNATURE_ALGORITHM = "Ed25519";
  private static final String PLATFORM_CONTRACT_FIXTURE = "platform-contract.json";
  private static final Pattern QUOTED_UNIX_ABSOLUTE_PATH = Pattern.compile("\"(/[^\"]*)\"");
  private static final Pattern QUOTED_WINDOWS_ABSOLUTE_PATH =
      Pattern.compile("\"[A-Za-z]:\\\\\\\\[^\"]*\"");

  /** Built-in Platform API contract fixture derived from the same source as the live route. */
  private static final String DEFAULT_PLATFORM_CONTRACT =
      PlatformApiContractJson.writeEnvelope(
          PlatformApiContract.current(), PlatformApiBaselineRegistry.current());

  /**
   * Route templates that may appear as quoted Unix-style strings in custom contract fixtures.
   *
   * <p>This allow-list is derived from the trusted in-process contract, not from the developer
   * fixture being scanned. That keeps route templates from weakening the local path leak guard.
   */
  private static final Set<String> DEFAULT_PLATFORM_CONTRACT_ROUTE_TEMPLATES =
      PlatformApiContract.current().endpoints().stream()
          .map(PlatformApiEndpointDescriptor::routeTemplate)
          .collect(java.util.stream.Collectors.toUnmodifiableSet());

  /** Built-in JSON fixtures keyed by the optional fixture file names accepted by the CLI. */
  private static final Map<String, String> DEFAULTS =
      Map.ofEntries(
          Map.entry(
              "node.json",
              """
              {"nodeName":"Crypta local dev","status":"mock","apiVersion":"v1"}
              """),
          Map.entry(
              "queue.json",
              """
              {"page":"downloads","requests":[{"id":"mock-download-1","name":"Example download","state":"running","priority":"normal"},{"id":"mock-insert-1","name":"Example insert","state":"queued","priority":"low"}],"contentHtml":"<p>Mock queue data</p>"}
              """),
          Map.entry(
              "vault-identities.json",
              """
              {"identities":[{"identityId":"local-profile","id":"local-profile","label":"Local Profile","displayName":"Local Profile","kind":"mock","status":"available","fingerprint":"mock-profile-fingerprint","usageScopes":["metadata.read","sign.domain-separated"]}]}
              """),
          Map.entry(
              "vault-grants.json",
              """
              {"grants":[{"id":"grant-local-profile","identityId":"local-profile","scopes":["metadata.read"],"status":"mock-granted"}]}
              """),
          Map.entry(
              "apps-current.json",
              """
              {"appId":"${APP_ID}","name":"${APP_NAME}","version":"${APP_VERSION}","mode":"mock-dev"}
              """),
          Map.entry(PLATFORM_CONTRACT_FIXTURE, DEFAULT_PLATFORM_CONTRACT),
          Map.entry(
              "content-subscriptions.json",
              """
              {"subscriptions":[{"subscriptionId":"mock-trust-subscription","id":"mock-trust-subscription","uri":"USK@mock/trust/0/trust.json","label":"Trust statement subscription","status":"active","lastKnownEdition":0,"mock":true}]}
              """),
          Map.entry(
              "content-subscription.json",
              """
              {"subscription":{"subscriptionId":"mock-trust-subscription","id":"mock-trust-subscription","uri":"USK@mock/trust/0/trust.json","label":"Trust statement subscription","status":"active","lastKnownEdition":0,"mock":true}}
              """),
          Map.entry(
              "trust-graph-status.json",
              """
              {"trustGraph":{"available":true,"service":"trust-graph-preview","documentType":"crypta.trust.statement.v1","contentType":"application/vnd.crypta.trust+json","statementCount":1,"anchorCount":1,"auditCount":1,"durable":true,"storeType":"mock-file","limits":{"maxStatements":1000,"maxAnchors":100,"maxAuditEntries":512,"maxStoredDocumentBytes":65536},"scoring":"mock-direct-local-anchor","completeWot":false,"mock":true}}
              """),
          Map.entry(
              "trust-graph-anchors.json",
              """
              {"anchors":[{"issuerFingerprint":"mock-profile-fingerprint","label":"Local Profile","source":"manual","addedAt":"2026-05-17T00:00:00Z"}]}
              """),
          Map.entry(
              "trust-graph-score.json",
              """
              {"score":{"subject":{"kind":"profile","uri":"USK@mock/profile.json"},"context":"profile","status":"trusted","score":50,"confidence":80,"evidenceCount":1,"contributingEvidenceCount":1,"evidence":[{"issuerFingerprint":"mock-profile-fingerprint","score":50,"confidence":80,"issuedAt":"2026-05-16T00:00:00Z","contributing":true,"source":"mock-fixture"}],"mock":true}}
              """),
          Map.entry(
              "trust-graph-audit.json",
              """
              {"audit":[{"eventType":"statement_imported_from_uri","timestamp":"2026-05-17T00:00:00Z","documentFingerprint":"mock-document-fingerprint","payloadHash":"mock-payload-hash","source":"content-fetch","sourceSummary":"CHK@redacted","signatureVerified":true,"statusCode":"ok"}]}
              """));

  /** Deterministic app-owned identity creation response. */
  static final String CREATED_IDENTITY_RESPONSE =
      """
      {"identity":{"identityId":"mock-created-profile","id":"mock-created-profile","label":"Mock Created Profile","displayName":"Mock Created Profile","kind":"mock","status":"available","usageScopes":["metadata.read","sign.domain-separated"]},"mock":true,"action":"app-vault.identities.create"}
      """;

  /** Deterministic acknowledgement for an app JSON document insert request. */
  static final String APP_DOCUMENT_INSERT_RESPONSE =
      """
      {"status":"ok","mock":true,"action":"queue.inserts.app-document","identifier":"mock-app-document","uri":"CHK@mock-app-document"}
      """;

  /** Deterministic bounded content-fetch response containing a mock trust statement document. */
  static final String CONTENT_FETCH_TRUST_STATEMENT_RESPONSE =
      """
      {"requestedUri":"CHK@mock-trust-statement","resolvedUri":"CHK@mock-trust-statement","format":"text","bytesLength":445,"contentText":"{\\"type\\":\\"crypta.trust.statement.v1\\",\\"payload\\":{\\"issuer\\":{\\"identityId\\":\\"local-profile\\",\\"publicKeyFingerprint\\":\\"mock-profile-fingerprint\\"},\\"subject\\":{\\"kind\\":\\"profile\\",\\"uri\\":\\"USK@mock/profile.json\\"},\\"context\\":\\"profile\\",\\"score\\":50,\\"confidence\\":80,\\"issuedAt\\":\\"2026-05-16T00:00:00Z\\"},\\"signature\\":{\\"algorithm\\":\\"app-vault-ed25519-preview\\",\\"domain\\":\\"crypta.trust.statement.v1\\",\\"value\\":\\"mock-preview-signature\\"}}","mock":true}
      """;

  /** Deterministic redacted trust graph import response. */
  static final String TRUST_GRAPH_IMPORT_RESPONSE =
      """
      {"importResult":{"status":"imported","source":"mock","documentFingerprint":"mock-document-fingerprint","payloadHash":"mock-payload-hash","signatureVerified":true,"importedAt":"2026-05-17T00:00:00Z","updatedAt":"2026-05-17T00:00:00Z","mock":true}}
      """;

  /** Optional normalized directory containing user-supplied JSON fixture files. */
  private final Path fixtureDir;

  /** App id used to fill placeholders in the current-app fixture. */
  private final String appId;

  /** App display name used to fill placeholders in the current-app fixture. */
  private final String appName;

  /** App version used to fill placeholders in the current-app fixture. */
  private final String appVersion;

  /**
   * Creates a fixture provider for one staged app.
   *
   * @param fixtureDir optional fixture directory supplied by the developer
   * @param appId app id used by default current-app responses
   * @param appName app display name used by default current-app responses
   * @param appVersion app version used by default current-app responses
   */
  MockPlatformApiFixtures(Path fixtureDir, String appId, String appName, String appVersion) {
    this.fixtureDir = fixtureDir == null ? null : fixtureDir.toAbsolutePath().normalize();
    this.appId = appId;
    this.appName = appName;
    this.appVersion = appVersion;
  }

  /**
   * Returns node metadata fixture JSON.
   *
   * @return fixture-backed or built-in node JSON
   * @throws IOException if fixture loading fails
   */
  String node() throws IOException {
    return fixture("node.json");
  }

  /**
   * Returns queue listing fixture JSON.
   *
   * @return fixture-backed or built-in queue JSON
   * @throws IOException if fixture loading fails
   */
  String queue() throws IOException {
    return fixture("queue.json");
  }

  /**
   * Returns app-vault identity listing fixture JSON.
   *
   * @return fixture-backed or built-in identity JSON with safe mock data
   * @throws IOException if fixture loading fails
   */
  String vaultIdentities() throws IOException {
    return fixture("vault-identities.json");
  }

  /**
   * Returns app-vault grant listing fixture JSON.
   *
   * @return fixture-backed or built-in grant JSON with safe mock data
   * @throws IOException if fixture loading fails
   */
  String vaultGrants() throws IOException {
    return fixture("vault-grants.json");
  }

  /**
   * Returns current-app metadata fixture JSON.
   *
   * @return fixture-backed or built-in current-app JSON after placeholder replacement
   * @throws IOException if fixture loading fails
   */
  String appsCurrent() throws IOException {
    return fixture("apps-current.json");
  }

  /**
   * Returns Platform API contract metadata fixture JSON.
   *
   * @return fixture-backed or built-in contract JSON with the stable 1.0 baseline
   * @throws IOException if fixture loading fails
   */
  String platformContract() throws IOException {
    return fixture(PLATFORM_CONTRACT_FIXTURE);
  }

  /**
   * Returns content subscription listing fixture JSON.
   *
   * @return fixture-backed or built-in subscription list JSON
   * @throws IOException if fixture loading fails
   */
  String contentSubscriptions() throws IOException {
    return fixture("content-subscriptions.json");
  }

  /**
   * Returns one content subscription fixture JSON.
   *
   * @return fixture-backed or built-in subscription JSON
   * @throws IOException if fixture loading fails
   */
  String contentSubscription() throws IOException {
    return fixture("content-subscription.json");
  }

  /**
   * Returns Trust Graph Preview status fixture JSON.
   *
   * @return fixture-backed or built-in trust graph status JSON
   * @throws IOException if fixture loading fails
   */
  String trustGraphStatus() throws IOException {
    return fixture("trust-graph-status.json");
  }

  /**
   * Returns local trust-anchor fixture JSON.
   *
   * @return fixture-backed or built-in anchor list JSON
   * @throws IOException if fixture loading fails
   */
  String trustGraphAnchors() throws IOException {
    return fixture("trust-graph-anchors.json");
  }

  /**
   * Returns deterministic Trust Graph Preview score JSON.
   *
   * @return fixture-backed or built-in score JSON
   * @throws IOException if fixture loading fails
   */
  String trustGraphScore() throws IOException {
    return fixture("trust-graph-score.json");
  }

  /**
   * Returns deterministic redacted Trust Graph Preview audit JSON.
   *
   * @return fixture-backed or built-in trust graph audit JSON
   * @throws IOException if fixture loading fails
   */
  String trustGraphAudit() throws IOException {
    return fixture("trust-graph-audit.json");
  }

  /**
   * Builds a deterministic signed profile preview using a publicly known test identity.
   *
   * <p>The signature binds the configured app and requested identity using the v1 AppVault frame.
   * It supports local SDK verification only and conveys no operational identity or trust. No
   * persistent signing key is created.
   *
   * @param identityId identity id segment supplied in the route
   * @return compact JSON response with path-free, token-free profile document metadata
   */
  String profileDocument(String identityId) {
    // RFC 8032 section 7.1 test-1 public seed: deliberately public, never an operational key.
    byte[] privateKey =
        HexFormat.of()
            .parseHex(
                "302e020100300506032b6570042204209d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    byte[] publicKey =
        HexFormat.of()
            .parseHex(
                "302a300506032b6570032100d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    Map<String, Object> profile = new LinkedHashMap<>();
    profile.put("schema", "crypta.profile.v1");
    profile.put("appId", appId);
    profile.put("identityId", identityId);
    profile.put("displayName", "Local Profile");
    profile.put("bio", "Mock profile document");
    profile.put("tags", List.of("local", "mock"));
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      String payloadHash = HexFormat.of().formatHex(digest.digest(CanonicalJson.bytes(profile)));
      String fingerprint = HexFormat.of().formatHex(digest.digest(publicKey));
      String preimage =
          "CryptaAppVault:v1:" + appId + ":" + identityId + ":profile.publish.v1:" + payloadHash;
      Signature signer = Signature.getInstance(PROFILE_SIGNATURE_ALGORITHM);
      signer.initSign(
          KeyFactory.getInstance(PROFILE_SIGNATURE_ALGORITHM)
              .generatePrivate(new PKCS8EncodedKeySpec(privateKey)));
      signer.update(preimage.getBytes(StandardCharsets.UTF_8));
      Map<String, Object> identity = new LinkedHashMap<>();
      identity.put("identityId", identityId);
      identity.put("fingerprint", fingerprint);
      identity.put("algorithm", PROFILE_SIGNATURE_ALGORITHM);
      identity.put("publicKeyBase64", Base64.getEncoder().encodeToString(publicKey));
      Map<String, Object> signature = new LinkedHashMap<>();
      signature.put("scope", "sign.domain-separated");
      signature.put("purpose", "profile.publish.v1");
      signature.put("payloadSha256", payloadHash);
      signature.put("domainSeparatedPayload", preimage);
      signature.put("signatureBase64", Base64.getEncoder().encodeToString(signer.sign()));
      Map<String, Object> document = new LinkedHashMap<>();
      document.put("schema", "crypta.profile.v1");
      document.put("profile", profile);
      document.put("identity", identity);
      document.put("signature", signature);
      Map<String, Object> response = new LinkedHashMap<>();
      response.put("profileDocument", document);
      response.put("mock", true);
      response.put("action", "app-vault.identities.profile-document");
      return new String(CanonicalJson.bytes(response), StandardCharsets.UTF_8);
    } catch (GeneralSecurityException exception) {
      throw new IllegalStateException("Mock profile signing is unavailable.", exception);
    }
  }

  /**
   * Builds a deterministic trust-statement preview response for a mock identity.
   *
   * @param identityId identity id segment supplied in the route
   * @return compact JSON response with public trust statement metadata only
   */
  String trustStatement(String identityId) {
    String escapedIdentityId = Json.escape(identityId);
    return "{\"trustStatement\":{\"identity\":{\"identityId\":\""
        + escapedIdentityId
        + "\",\"publicKeyFingerprint\":\"mock-profile-fingerprint\",\"publicKeyBase64\":\"mock-public-key-base64\",\"appId\":\""
        + Json.escape(appId)
        + "\"},\"payloadHash\":\"5e1ec6f9a9a04cb4738f711bd49a9b25f6f0d5565d3c0845eb55b443f086c53a"
        + "\",\"domain\":\"crypta.trust.statement.v1\",\"trustStatement\":{\"type\":\"crypta.trust.statement.v1\","
        + "\"payload\":{\"issuer\":{\"identityId\":\""
        + escapedIdentityId
        + "\",\"publicKeyFingerprint\":\"mock-profile-fingerprint\",\"publicKeyBase64\":\"mock-public-key-base64\"},\"subject\":{\"kind\":\"profile\","
        + "\"uri\":\"USK@mock/profile.json\"},\"context\":\"profile\",\"score\":50,\"confidence\":80,"
        + "\"issuedAt\":\"2026-05-16T00:00:00Z\"},\"signature\":{\"algorithm\":\"app-vault-ed25519-preview\","
        + "\"domain\":\"crypta.trust.statement.v1\",\"value\":\"mock-preview-signature\"}},\"mock\":true,"
        + "\"action\":\"app-vault.identities.trust-statement\"}}";
  }

  /**
   * Builds a deterministic social-message preview response for a mock identity.
   *
   * @param identityId identity id segment supplied in the route
   * @return compact JSON response with public social message metadata only
   */
  String socialMessage(String identityId) {
    String escapedIdentityId = Json.escape(identityId);
    String escapedAppId = Json.escape(appId);
    String payloadHash = "1270c1caf9a8c647f1b3292b53740e1cf401e229cf8034cf2ecdb528ad75e714";
    String messageId = "msg-" + payloadHash;
    return "{\"socialMessage\":{\"identity\":{\"identityId\":\""
        + escapedIdentityId
        + "\",\"publicKeyFingerprint\":\"mock-profile-fingerprint\",\"publicKeyBase64\":\"bW9jay1wdWJsaWMta2V5\",\"appId\":\""
        + escapedAppId
        + "\"},\"payloadHash\":\""
        + payloadHash
        + "\",\"domain\":\"crypta.social.message.v1\",\"socialMessage\":{\"type\":\"crypta.social.message.v1\","
        + "\"message\":{\"appId\":\""
        + escapedAppId
        + "\",\"identityId\":\""
        + escapedIdentityId
        + "\",\"authorFingerprint\":\"mock-profile-fingerprint\",\"messageId\":\""
        + messageId
        + "\",\"createdAt\":\"2026-05-16T00:00:00Z\",\"channel\":\"general\",\"subject\":\"Mock"
        + " social message\",\"body\":\"Mock social message body\","
        + "\"format\":\"text/plain\",\"tags\":[\"local\",\"mock\"]},"
        + "\"signature\":{\"algorithm\":\"Ed25519\",\"domain\":\"crypta.social.message.v1\","
        + "\"payloadHash\":\""
        + payloadHash
        + "\",\"publicKeyFingerprint\":\"mock-profile-fingerprint\","
        + "\"publicKeyBase64\":\"bW9jay1wdWJsaWMta2V5\","
        + "\"signatureBase64\":\"bW9jay1zaWduYXR1cmU=\"}},\"mock\":true,"
        + "\"action\":\"app-vault.identities.social-message\"}}";
  }

  /**
   * Builds a deterministic mutation acknowledgement.
   *
   * @param action stable action label for the route that accepted the mutation
   * @return compact JSON acknowledgement with no persistent state change
   */
  String mutation(String action) {
    return "{\"status\":\"ok\",\"mock\":true,\"action\":\"" + Json.escape(action) + "\"}";
  }

  /**
   * Loads a named fixture from disk when present, otherwise uses the built-in default.
   *
   * @param name fixture file name such as {@code queue.json}
   * @return fixture JSON after placeholder replacement and whitespace trimming
   * @throws IOException if a present fixture is unsafe or cannot be read
   */
  private String fixture(String name) throws IOException {
    String json = fixtureDir == null ? null : readFixture(name);
    if (json == null) {
      json = DEFAULTS.get(name);
    }
    return applyAppPlaceholders(json.strip());
  }

  /**
   * Reads one user fixture file from the configured fixture directory.
   *
   * @param name file name selected from the supported fixture list
   * @return fixture text, or {@code null} when the file is absent
   * @throws IOException if the directory or file is unsafe or unreadable
   */
  private String readFixture(String name) throws IOException {
    if (!Files.isDirectory(fixtureDir, LinkOption.NOFOLLOW_LINKS)
        || Files.isSymbolicLink(fixtureDir)) {
      throw new AppDistributionException("fixture directory must be a real directory");
    }
    Path file = fixtureDir.resolve(name).normalize();
    if (!file.startsWith(fixtureDir) || !Files.exists(file, LinkOption.NOFOLLOW_LINKS)) {
      return null;
    }
    if (Files.isSymbolicLink(file) || !Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) {
      throw new AppDistributionException("fixture file must be a regular file: " + name);
    }
    String text = Files.readString(file, StandardCharsets.UTF_8);
    rejectLocalPathLeaks(text, name);
    return text;
  }

  /**
   * Rejects fixture JSON that appears to expose absolute local filesystem paths.
   *
   * @param text fixture text read from disk
   * @param name fixture file name used in diagnostics
   * @throws AppDistributionException if a quoted Unix or Windows absolute path is detected
   */
  private static void rejectLocalPathLeaks(String text, String name)
      throws AppDistributionException {
    Set<String> allowedUnixPaths =
        PLATFORM_CONTRACT_FIXTURE.equals(name)
            ? DEFAULT_PLATFORM_CONTRACT_ROUTE_TEMPLATES
            : Set.of();
    Matcher unixPath = QUOTED_UNIX_ABSOLUTE_PATH.matcher(text);
    while (unixPath.find()) {
      if (!allowedUnixPaths.contains(unixPath.group(1))) {
        throw new AppDistributionException(
            "fixture output contains an absolute local path: " + name);
      }
    }
    if (QUOTED_WINDOWS_ABSOLUTE_PATH.matcher(text).find()) {
      throw new AppDistributionException("fixture output contains an absolute local path: " + name);
    }
  }

  /**
   * Replaces app metadata placeholders in fixture JSON.
   *
   * @param json fixture JSON that may contain {@code ${APP_ID}}, {@code ${APP_NAME}}, or {@code
   *     ${APP_VERSION}}
   * @return fixture JSON with placeholders replaced by escaped app metadata
   */
  private String applyAppPlaceholders(String json) {
    return json.replace("${APP_ID}", Json.escape(appId))
        .replace("${APP_NAME}", Json.escape(appName))
        .replace("${APP_VERSION}", Json.escape(appVersion));
  }

  /** Small JSON string escaper for mock response values. */
  static final class Json {
    /** Prevents construction of this stateless JSON helper. */
    private Json() {}

    /**
     * Escapes one string for inclusion in mock JSON responses.
     *
     * @param value raw value to escape
     * @return escaped JSON string content without surrounding quote characters
     */
    static String escape(String value) {
      StringBuilder out = new StringBuilder(value.length());
      for (int index = 0; index < value.length(); index++) {
        char c = value.charAt(index);
        switch (c) {
          case '"' -> out.append("\\\"");
          case '\\' -> out.append("\\\\");
          case '\b' -> out.append("\\b");
          case '\f' -> out.append("\\f");
          case '\n' -> out.append("\\n");
          case '\r' -> out.append("\\r");
          case '\t' -> out.append("\\t");
          default -> {
            if (c < 0x20) {
              out.append(String.format("\\u%04x", (int) c));
            } else {
              out.append(c);
            }
          }
        }
      }
      return out.toString();
    }
  }
}
