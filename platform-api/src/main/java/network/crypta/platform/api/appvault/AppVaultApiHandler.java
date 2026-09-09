package network.crypta.platform.api.appvault;

import java.time.Clock;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import network.crypta.platform.api.PlatformApiException;
import network.crypta.platform.api.PlatformApiParameters;
import network.crypta.platform.appvault.AppIdentityGrant;
import network.crypta.platform.appvault.AppIdentityGrantScope;
import network.crypta.platform.appvault.AppIdentityKind;
import network.crypta.platform.appvault.AppIdentityRecord;
import network.crypta.platform.appvault.AppIdentityUsageRequest;
import network.crypta.platform.appvault.AppIdentityUsageResult;
import network.crypta.platform.appvault.AppSecretRecord;
import network.crypta.platform.appvault.AppVaultService;
import network.crypta.platform.trustgraph.TrustDocumentTypes;
import network.crypta.platform.trustgraph.TrustGraphException;
import network.crypta.platform.trustgraph.TrustSignatureEnvelope;
import network.crypta.platform.trustgraph.TrustStatementDocument;

/**
 * Handles app-principal Platform API calls for vault secrets, identities, and grant requests.
 *
 * <p>This handler is deliberately transport-neutral: the router has already authenticated the
 * caller and checked the published capability descriptor before any method here runs. The handler
 * still receives the normalized app id from that principal and passes it through to {@link
 * AppVaultService}, so every secret, identity listing, and identity-use operation remains bound to
 * the calling app rather than to a request-supplied app id.
 *
 * <p>The app-facing surface separates process-only secret and signing operations from browser-safe
 * metadata workflows. Secret reads return a value only for routes that the contract exposes to app
 * process principals. Browser-visible identity and grant-request helpers return public metadata or
 * an operator-review status and never create grants, return private keys, or echo raw secret
 * values.
 *
 * @see AppVaultService
 */
public final class AppVaultApiHandler {
  private static final String FIELD_APP_ID = "appId";
  private static final String FIELD_CREATED_AT = "createdAt";
  private static final String FIELD_IDENTITY_ID = "identityId";
  private static final String FIELD_PUBLIC_KEY_BASE64 = "publicKeyBase64";
  private static final String FIELD_REASON = "reason";
  private static final String FIELD_UPDATED_AT = "updatedAt";
  private static final String PARAM_KIND = "kind";
  private static final String PARAM_LABEL = "label";
  private static final String PARAM_PURPOSE = "purpose";
  private static final String PARAM_SCOPE = "scope";
  private static final String PARAM_SCOPES = "scopes";
  private static final String PARAM_SECRET_KIND = "secretKind";
  private static final String PARAM_VALUE_BASE64 = "valueBase64";
  private static final String PARAM_VALUE_UTF8 = "valueUtf8";

  private final AppVaultService appVaultService;
  private final Clock clock;

  /**
   * Creates an app-facing vault handler backed by the shared local vault service.
   *
   * <p>The handler keeps no mutable request state of its own. All persistence, audit, redaction,
   * and grant checks remain in the vault service so HTTP, tests, and future transports observe the
   * same behavior.
   *
   * @param appVaultService shared vault service used for all storage and authorization checks
   */
  public AppVaultApiHandler(AppVaultService appVaultService) {
    this.appVaultService = Objects.requireNonNull(appVaultService, "appVaultService");
    this.clock = Clock.systemUTC();
  }

  /**
   * Lists redacted metadata for the calling app's secrets.
   *
   * <p>The response contains only {@link AppSecretRecord} metadata rendered as JSON-compatible
   * maps. It does not include plaintext, ciphertext, envelope paths, or wrapping-key information.
   * The vault service also rejects the call while uninstall cleanup has left app access blocked.
   *
   * @param appId authenticated app principal id supplied by the router, not request data
   * @return JSON-compatible secret summaries safe for status and list responses
   */
  public List<Map<String, Object>> listSecrets(String appId) {
    appVaultService.requireAppAccessAllowed(appId);
    return appVaultService.listSecrets(appId).stream()
        .map(AppVaultApiHandler::secretSummary)
        .toList();
  }

  /**
   * Stores or replaces one app-owned secret value.
   *
   * <p>Callers provide either {@code valueBase64} or {@code valueUtf8}; {@code valueBase64} wins
   * when both are present. Query parameters with the {@code metadata.} prefix become caller-visible
   * metadata after key normalization and sensitive-key redaction. The returned map describes the
   * stored record and intentionally omits the value that was just written.
   *
   * @param appId authenticated app principal id supplied by the router, not request data
   * @param secretName path-safe secret name segment from the request path
   * @param queryParameters decoded request parameters containing value and optional metadata
   * @return JSON-compatible redacted metadata for the stored secret record
   */
  public Map<String, Object> putSecret(
      String appId, String secretName, Map<String, List<String>> queryParameters) {
    appVaultService.requireAppAccessAllowed(appId);
    byte[] value = readSecretValue(queryParameters);
    String secretKind =
        Objects.requireNonNullElse(
            PlatformApiParameters.readOptionalString(queryParameters, PARAM_SECRET_KIND),
            "generic");
    AppSecretRecord secretRecord =
        appVaultService.putSecret(appId, secretName, secretKind, value, metadata(queryParameters));
    return secretSummary(secretRecord);
  }

  /**
   * Reads one app-owned secret value for an app process principal.
   *
   * <p>The response wraps the redacted metadata under {@code secret} and the plaintext under {@code
   * valueBase64}. The API uses Base64 for the value so arbitrary bytes can be returned without
   * relying on character encoding, while keeping raw secret text out of public logs and status
   * summaries.
   *
   * @param appId authenticated app principal id supplied by the router, not request data
   * @param secretName path-safe secret name segment from the request path
   * @return JSON-compatible secret response with metadata and Base64-encoded value
   */
  public Map<String, Object> readSecret(String appId, String secretName) {
    appVaultService.requireAppAccessAllowed(appId);
    byte[] value = appVaultService.readSecretValue(appId, secretName);
    AppSecretRecord secretRecord = appVaultService.getSecretRecord(appId, secretName);
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(2);
    json.put("secret", secretSummary(secretRecord));
    json.put(PARAM_VALUE_BASE64, Base64.getEncoder().encodeToString(value));
    return json;
  }

  /**
   * Deletes one app-owned secret.
   *
   * <p>Deletion is scoped to the authenticated app id. The response reports the requested app id,
   * normalized secret name, and whether an existing record was removed; it never returns the
   * previous value.
   *
   * @param appId authenticated app principal id supplied by the router, not request data
   * @param secretName path-safe secret name segment from the request path
   * @return JSON-compatible deletion result without the former secret value
   */
  public Map<String, Object> deleteSecret(String appId, String secretName) {
    appVaultService.requireAppAccessAllowed(appId);
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(3);
    json.put(FIELD_APP_ID, appId);
    json.put("secretName", secretName);
    json.put("deleted", appVaultService.deleteSecret(appId, secretName));
    return json;
  }

  /**
   * Lists vault identities visible to the calling app.
   *
   * <p>Visibility is grant-aware and app-id-bound. App-owned identities are still represented
   * through their active grants, so revocation or uninstall cleanup removes them from this
   * app-facing view. Each entry is public metadata only: private signing material and local vault
   * paths remain inside the service. The experimental Mail owner fails closed when any retained
   * Mail identity lacks current authority, rather than interpreting a filtered empty list as a new
   * account. Its preflight and listing share the vault monitor.
   *
   * @param appId authenticated app principal id supplied by the router, not request data
   * @return JSON-compatible identity metadata visible to the calling app
   */
  public List<Map<String, Object>> listIdentities(String appId) {
    appVaultService.requireAppAccessAllowed(appId);
    if ("mail-prototype".equals(appId)) {
      synchronized (appVaultService) {
        appVaultService.requireMailIdentityAuthority(appId);
        return appVaultService.listIdentitiesForApp(appId).stream()
            .map(AppVaultApiHandler::identitySummary)
            .toList();
      }
    }
    return appVaultService.listIdentitiesForApp(appId).stream()
        .map(AppVaultApiHandler::identitySummary)
        .toList();
  }

  /**
   * Creates an app-owned identity.
   *
   * <p>The app id from the principal becomes the owner app id on the new identity. If the request
   * omits {@code kind}, the handler asks for the v1 local Ed25519 signing kind. Requested {@code
   * scopes} are parsed before storage so unsupported local-signing scopes fail without creating
   * private material.
   *
   * @param appId authenticated app principal id supplied by the router, not request data
   * @param queryParameters decoded request parameters with optional kind, label, and scopes
   * @return JSON-compatible public metadata for the newly created identity
   */
  public Map<String, Object> createIdentity(
      String appId, Map<String, List<String>> queryParameters) {
    appVaultService.requireAppAccessAllowed(appId);
    AppIdentityKind kind =
        AppIdentityKind.fromJsonValue(
            Objects.requireNonNullElse(
                PlatformApiParameters.readOptionalString(queryParameters, PARAM_KIND),
                AppIdentityKind.LOCAL_ED25519_SIGNING.jsonValue()));
    String label = PlatformApiParameters.readOptionalString(queryParameters, PARAM_LABEL);
    Set<AppIdentityGrantScope> scopes = parseScopes(queryParameters);
    return identitySummary(appVaultService.createAppOwnedIdentity(appId, kind, label, scopes));
  }

  /**
   * Reads one identity visible to the calling app.
   *
   * <p>The vault service checks visibility before exposing whether the identity exists. A caller
   * without a current app-bound grant receives the same denial behavior for missing and ungranted
   * identities, which prevents identity-id probing through this route.
   *
   * @param appId authenticated app principal id supplied by the router, not request data
   * @param identityId identity id segment from the request path
   * @return JSON-compatible identity metadata visible to the calling app
   */
  public Map<String, Object> getIdentity(String appId, String identityId) {
    appVaultService.requireAppAccessAllowed(appId);
    return identitySummary(appVaultService.getIdentityForApp(appId, identityId));
  }

  /**
   * Uses one granted identity for a bounded operation.
   *
   * <p>The v1 live operation is domain-separated Ed25519 signing. The handler parses the requested
   * scope, purpose, and Base64 payload, then delegates grant, size, operation-kind, and audit
   * checks to the vault service. The result contains a signature, public key metadata, and the
   * domain separated payload string; it never contains private key bytes.
   *
   * @param appId authenticated app principal id supplied by the router, not request data
   * @param identityId identity id segment from the request path
   * @param queryParameters decoded request parameters containing purpose, payload, and scope
   * @return JSON-compatible identity-use result with public key data and signature
   */
  public Map<String, Object> useIdentity(
      String appId, String identityId, Map<String, List<String>> queryParameters) {
    appVaultService.requireAppAccessAllowed(appId);
    AppIdentityGrantScope scope =
        AppIdentityGrantScope.fromJsonValue(
            Objects.requireNonNullElse(
                PlatformApiParameters.readOptionalString(queryParameters, PARAM_SCOPE),
                AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED.jsonValue()));
    String purpose = PlatformApiParameters.requireString(queryParameters, PARAM_PURPOSE);
    byte[] payload =
        decodeBase64(PlatformApiParameters.requireString(queryParameters, "payloadBase64"));
    return usageResultSummary(
        appVaultService.useIdentity(
            new AppIdentityUsageRequest(appId, identityId, scope, purpose, payload)));
  }

  /**
   * Builds and signs one bounded Crypta profile document for a visible app identity.
   *
   * <p>This route is the browser-safe profile-publishing companion to the process-only generic
   * identity-use route. It accepts only the documented profile fields, fixes the signing scope and
   * purpose, canonicalizes the unsigned profile payload with stable JSON field order, and delegates
   * to the vault service for the actual grant check and domain-separated signature.
   *
   * @param appId authenticated app principal id supplied by the router, not request data
   * @param identityId identity id segment from the request path
   * @param queryParameters decoded request parameters containing profile fields
   * @return signed profile document with public verification material only
   */
  public Map<String, Object> createProfileDocument(
      String appId, String identityId, Map<String, List<String>> queryParameters) {
    appVaultService.requireAppAccessAllowed(appId);
    AppIdentityRecord identity = appVaultService.getIdentityForApp(appId, identityId);
    ProfileDocumentRequest profile =
        ProfileDocumentRequest.fromQuery(appId, identity.identityId(), queryParameters);
    AppIdentityUsageResult usageResult =
        appVaultService.useIdentity(
            new AppIdentityUsageRequest(
                appId,
                identity.identityId(),
                AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED,
                ProfileDocumentRequest.SIGNING_PURPOSE,
                profile.canonicalBytes()));
    return SignedProfileDocumentBuilder.build(profile, identity, usageResult);
  }

  /**
   * Builds and signs one bounded Trust Graph Preview statement.
   *
   * <p>This browser-safe route signs only the documented trust statement payload shape with the
   * fixed trust statement domain. It returns public identity metadata, the payload hash, domain,
   * and the public trust statement document; it never exposes private key material, generic signing
   * inputs, local vault paths, or request bodies.
   *
   * @param appId authenticated app principal id supplied by the router
   * @param identityId identity id segment from the request path
   * @param queryParameters decoded trust-statement request parameters
   * @return public signed trust statement response
   */
  public Map<String, Object> createTrustStatement(
      String appId, String identityId, Map<String, List<String>> queryParameters) {
    appVaultService.requireAppAccessAllowed(appId);
    AppIdentityRecord identity = appVaultService.getIdentityForApp(appId, identityId);
    TrustStatementRequest trustStatementRequest;
    try {
      trustStatementRequest =
          TrustStatementRequest.fromQuery(
              appId,
              identity.identityId(),
              identity.fingerprint(),
              identity.publicSummary().get(FIELD_PUBLIC_KEY_BASE64),
              queryParameters,
              clock);
    } catch (TrustGraphException exception) {
      throw new PlatformApiException(400, exception.errorCode(), exception.getMessage());
    }
    AppIdentityUsageResult usageResult =
        appVaultService.signDomainSeparatedPayload(
            new AppIdentityUsageRequest(
                appId,
                identity.identityId(),
                AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED,
                TrustStatementRequest.SIGNING_PURPOSE,
                trustStatementRequest.canonicalBytes()));
    TrustStatementDocument document =
        new TrustStatementDocument(
            TrustDocumentTypes.TRUST_STATEMENT_V1,
            trustStatementRequest.payload(),
            new TrustSignatureEnvelope(
                TrustDocumentTypes.APP_VAULT_ED25519_PREVIEW_ALGORITHM,
                TrustDocumentTypes.TRUST_STATEMENT_V1,
                usageResult.signatureBase64()));
    LinkedHashMap<String, Object> response = LinkedHashMap.newLinkedHashMap(4);
    LinkedHashMap<String, Object> identityJson = LinkedHashMap.newLinkedHashMap(4);
    identityJson.put(FIELD_IDENTITY_ID, identity.identityId());
    identityJson.put("publicKeyFingerprint", identity.fingerprint());
    identityJson.put(FIELD_PUBLIC_KEY_BASE64, usageResult.publicKeyBase64());
    identityJson.put(FIELD_APP_ID, appId);
    response.put("identity", identityJson);
    response.put("payloadHash", usageResult.payloadSha256());
    response.put("domain", TrustDocumentTypes.TRUST_STATEMENT_V1);
    response.put("trustStatement", document.toJson());
    return response;
  }

  /**
   * Builds and signs one bounded Social Inbox Preview message.
   *
   * <p>This browser-safe route is the social/mail migration counterpart to the profile-document and
   * trust-statement routes. It signs only the documented plain-text social message shape with the
   * fixed {@code crypta.social.message.v1} domain, uses the server clock for {@code createdAt}, and
   * returns public verification material only. It never accepts caller-selected signing purposes,
   * raw payload bytes, generic identity-use parameters, private key material, local vault paths, or
   * request bodies.
   *
   * @param appId authenticated app principal id supplied by the router
   * @param identityId identity id segment from the request path
   * @param queryParameters decoded social-message request parameters
   * @return public signed social message response
   */
  public Map<String, Object> createSocialMessage(
      String appId, String identityId, Map<String, List<String>> queryParameters) {
    appVaultService.requireAppAccessAllowed(appId);
    AppIdentityRecord identity = appVaultService.getIdentityForApp(appId, identityId);
    SocialMessageRequest socialMessageRequest =
        SocialMessageRequest.fromQuery(
            appId, identity.identityId(), identity.fingerprint(), queryParameters, clock);
    AppIdentityUsageResult usageResult =
        appVaultService.signDomainSeparatedPayload(
            new AppIdentityUsageRequest(
                appId,
                identity.identityId(),
                AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED,
                SocialMessageRequest.SIGNING_PURPOSE,
                socialMessageRequest.canonicalBytes()));
    LinkedHashMap<String, Object> response = LinkedHashMap.newLinkedHashMap(4);
    LinkedHashMap<String, Object> identityJson = LinkedHashMap.newLinkedHashMap(4);
    identityJson.put(FIELD_IDENTITY_ID, identity.identityId());
    identityJson.put("publicKeyFingerprint", identity.fingerprint());
    identityJson.put(FIELD_PUBLIC_KEY_BASE64, usageResult.publicKeyBase64());
    identityJson.put(FIELD_APP_ID, appId);
    response.put("identity", identityJson);
    response.put("payloadHash", usageResult.payloadSha256());
    response.put("domain", SocialMessageRequest.SIGNING_PURPOSE);
    response.put(
        "socialMessage",
        SignedSocialMessageDocumentBuilder.build(socialMessageRequest, identity, usageResult));
    return response;
  }

  /**
   * Lists grants for the calling app.
   *
   * <p>This app-facing list omits retained revoked grants from previous installations.
   * Host/operator management routes can still inspect those records, but a fresh installation with
   * the same app id should not learn historical grant metadata before the operator grants access
   * again.
   *
   * @param appId authenticated app principal id supplied by the router, not request data
   * @return JSON-compatible active or otherwise app-visible grant metadata
   */
  public List<Map<String, Object>> listGrants(String appId) {
    appVaultService.requireAppAccessAllowed(appId);
    return appVaultService.listAppVisibleGrantsForApp(appId).stream()
        .map(AppVaultApiHandler::grantSummary)
        .toList();
  }

  /**
   * Creates a token-free grant-request status for operator review flows.
   *
   * <p>The request route is safe for browser app principals because it does not mutate vault grant
   * state. It echoes the requested identity id, scopes, and reason as an operator-review status so
   * Web Shell or another host UI can collect an explicit grant later through the management route.
   *
   * @param appId authenticated app principal id supplied by the router, not request data
   * @param queryParameters decoded request parameters describing the requested identity grant
   * @return JSON-compatible metadata-only grant-request status for operator review
   */
  public Map<String, Object> requestGrant(String appId, Map<String, List<String>> queryParameters) {
    appVaultService.requireAppAccessAllowed(appId);
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(6);
    json.put("status", "operator_review_required");
    json.put(FIELD_APP_ID, appId);
    json.put(
        FIELD_IDENTITY_ID, PlatformApiParameters.requireString(queryParameters, FIELD_IDENTITY_ID));
    json.put(
        PARAM_SCOPES,
        parseScopes(queryParameters).stream().map(AppIdentityGrantScope::jsonValue).toList());
    json.put(FIELD_REASON, PlatformApiParameters.readOptionalString(queryParameters, FIELD_REASON));
    json.put("secretMaterialIncluded", false);
    return json;
  }

  private static Map<String, Object> secretSummary(AppSecretRecord secretRecord) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(8);
    json.put(FIELD_APP_ID, secretRecord.appId());
    json.put("secretName", secretRecord.secretName());
    json.put(PARAM_SECRET_KIND, secretRecord.secretKind());
    json.put(FIELD_CREATED_AT, secretRecord.createdAt().toString());
    json.put(FIELD_UPDATED_AT, secretRecord.updatedAt().toString());
    json.put(
        "lastUsedAt",
        secretRecord.lastUsedAt() == null ? null : secretRecord.lastUsedAt().toString());
    json.put("sizeClass", secretRecord.sizeClass());
    json.put("metadata", secretRecord.metadata());
    return json;
  }

  private static Map<String, Object> identitySummary(AppIdentityRecord identity) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(9);
    json.put(FIELD_IDENTITY_ID, identity.identityId());
    json.put("kind", identity.kind().jsonValue());
    json.put(PARAM_LABEL, identity.label());
    json.put("ownerAppId", identity.ownerAppId());
    json.put(FIELD_CREATED_AT, identity.createdAt().toString());
    json.put(FIELD_UPDATED_AT, identity.updatedAt().toString());
    json.put("publicSummary", identity.publicSummary());
    json.put("fingerprint", identity.fingerprint());
    json.put(
        "usageScopes",
        identity.usageScopes().stream().map(AppIdentityGrantScope::jsonValue).toList());
    return json;
  }

  private static Map<String, Object> grantSummary(AppIdentityGrant grant) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(11);
    json.put("grantId", grant.grantId());
    json.put(FIELD_IDENTITY_ID, grant.identityId());
    json.put(FIELD_APP_ID, grant.appId());
    json.put(PARAM_SCOPES, grant.scopes().stream().map(AppIdentityGrantScope::jsonValue).toList());
    json.put("status", grant.status().jsonValue());
    json.put(FIELD_CREATED_AT, grant.createdAt().toString());
    json.put(FIELD_UPDATED_AT, grant.updatedAt().toString());
    json.put("expiresAt", grant.expiresAt() == null ? null : grant.expiresAt().toString());
    json.put("grantedBy", grant.grantedBy());
    json.put(FIELD_REASON, grant.reason());
    json.put("sourceReviewReceiptId", grant.sourceReviewReceiptId());
    return json;
  }

  private static Map<String, Object> usageResultSummary(AppIdentityUsageResult result) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(8);
    json.put(FIELD_IDENTITY_ID, result.identityId());
    json.put(PARAM_SCOPE, result.scope().jsonValue());
    json.put("algorithm", result.algorithm());
    json.put("fingerprint", result.fingerprint());
    json.put(FIELD_PUBLIC_KEY_BASE64, result.publicKeyBase64());
    json.put("payloadSha256", result.payloadSha256());
    json.put("domainSeparatedPayload", result.domainSeparatedPayload());
    json.put("signatureBase64", result.signatureBase64());
    return json;
  }

  private static Map<String, String> metadata(Map<String, List<String>> queryParameters) {
    LinkedHashMap<String, String> metadata = LinkedHashMap.newLinkedHashMap(4);
    for (Map.Entry<String, List<String>> entry : queryParameters.entrySet()) {
      if (entry.getKey().startsWith("metadata.")) {
        if (entry.getValue().size() != 1) {
          throw invalidQuery("Metadata query parameters must not be repeated.");
        }
        metadata.put(entry.getKey().substring("metadata.".length()), entry.getValue().getFirst());
      }
    }
    return Map.copyOf(metadata);
  }

  private static Set<AppIdentityGrantScope> parseScopes(Map<String, List<String>> queryParameters) {
    String raw = PlatformApiParameters.readOptionalString(queryParameters, PARAM_SCOPES);
    if (raw == null || raw.isBlank()) {
      return Set.of();
    }
    TreeSet<AppIdentityGrantScope> scopes = new TreeSet<>();
    for (String part : raw.split(",", -1)) {
      String trimmed = part.trim();
      if (trimmed.isEmpty()) {
        throw invalidQuery("Query parameter '" + PARAM_SCOPES + "' must not contain empty scopes.");
      }
      scopes.add(AppIdentityGrantScope.fromJsonValue(trimmed));
    }
    return Set.copyOf(scopes);
  }

  private static byte[] readSecretValue(Map<String, List<String>> queryParameters) {
    String valueBase64 =
        PlatformApiParameters.readOptionalString(queryParameters, PARAM_VALUE_BASE64);
    if (valueBase64 != null) {
      return decodeBase64(valueBase64);
    }
    String valueUtf8 = PlatformApiParameters.readOptionalString(queryParameters, PARAM_VALUE_UTF8);
    if (valueUtf8 != null) {
      return valueUtf8.getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }
    throw invalidQuery("Missing required query parameter 'valueBase64'.");
  }

  private static byte[] decodeBase64(String value) {
    try {
      return Base64.getDecoder().decode(value);
    } catch (IllegalArgumentException _) {
      throw invalidQuery("Base64 query parameter is invalid.");
    }
  }

  private static PlatformApiException invalidQuery(String message) {
    return new PlatformApiException(400, "invalid_query_parameter", message);
  }
}
