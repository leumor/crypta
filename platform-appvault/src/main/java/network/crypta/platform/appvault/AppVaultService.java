package network.crypta.platform.appvault;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;

/**
 * Platform-managed vault service for app-scoped secrets, identities, and grants.
 *
 * <p>The service is the transport-neutral authority for PR-219 vault behavior. Platform API
 * handlers, app lifecycle hooks, tests, and future callers use this class rather than reading vault
 * files directly. It enforces app-id binding, grant checks, redaction, envelope AAD validation,
 * uninstall access blocks, and recent in-memory audit events.
 *
 * <p>All public methods are synchronized because the file-backed v1 store has no separate
 * transactional coordinator. Synchronization keeps related metadata, envelope, grant, and audit
 * operations ordered within one service instance. It is not a distributed lock and does not provide
 * cross-process concurrency guarantees.
 *
 * <p>The at-rest protection is exactly the configured {@link AppVaultKeyProvider} plus AES-GCM
 * envelopes. The default opener uses a local host key file with strict permissions when the host
 * supports them; it does not claim hardware-backed or master-password protection.
 */
public final class AppVaultService {
  /**
   * Maximum plaintext secret value accepted by v1.
   *
   * <p>The limit keeps the vault focused on small credentials and private app configuration rather
   * than bulk data storage. Larger app data should use the app's normal data directory or a
   * purpose-built content store.
   */
  public static final int MAX_SECRET_BYTES = 64 * 1024;

  /**
   * Maximum identity usage payload accepted by v1 signing operations.
   *
   * <p>The local Ed25519 path signs a domain-separated string containing the payload hash, not the
   * raw payload. The bound keeps request memory use predictable and prevents the identity-use route
   * from becoming a general large-object hashing service.
   */
  public static final int MAX_USAGE_PAYLOAD_BYTES = 32 * 1024;

  private static final int MAX_AUDIT_EVENTS = 256;
  private static final char[] HEX = "0123456789abcdef".toCharArray();
  private static final Set<AppIdentityGrantScope> DEFAULT_LOCAL_SIGNING_SCOPES =
      Set.of(AppIdentityGrantScope.METADATA_READ, AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED);
  private static final SecureRandom DEFAULT_SECURE_RANDOM = new SecureRandom();
  private static final String ALGORITHM_ED25519 = "Ed25519";
  private static final String AUDIT_OUTCOME_ALLOWED = "allowed";
  private static final String AUDIT_OUTCOME_MISSING = "missing";
  private static final String AUDIT_REASON_APP_UNINSTALL = "app_uninstall";
  private static final String AUDIT_TARGET_GRANT = "grant";
  private static final String AUDIT_TARGET_IDENTITY = "identity";
  private static final String AUDIT_TARGET_SECRET = "secret";

  private final AppVaultStore store;
  private final AppVaultKeyProvider keyProvider;
  private final SecureRandom secureRandom;
  private final Deque<AppVaultAuditEvent> auditEvents = new ArrayDeque<>();

  /**
   * Opens a local app vault rooted in the supplied directory.
   *
   * <p>The method initializes the directory layout, opens or creates the local wrapping key, and
   * verifies that key material can be loaded before returning. Callers that treat the vault as
   * optional can catch {@link IOException} and omit vault routes while leaving the rest of the node
   * available.
   *
   * @param root local vault root under the node's app-platform data directory
   * @return initialized vault service ready for secret and identity operations
   * @throws IOException if the root, metadata directories, or local key cannot be prepared
   */
  public static AppVaultService open(Path root) throws IOException {
    SecureRandom secureRandom = DEFAULT_SECURE_RANDOM;
    AppVaultPaths paths = new AppVaultPaths(root);
    AppVaultStore store = new AppVaultStore(paths);
    store.initialize();
    LocalAppVaultKeyProvider keyProvider =
        new LocalAppVaultKeyProvider(paths.keyFile(), secureRandom);
    keyProvider.currentKey();
    return new AppVaultService(store, keyProvider, secureRandom);
  }

  /**
   * Creates a vault service with explicit store and key provider.
   *
   * <p>This constructor is primarily used by tests and by future runtime composition that supplies
   * a different key provider. The service assumes the store has already been initialized and that
   * the key provider can decrypt envelopes written under the same vault root.
   *
   * @param store file-backed store used for metadata, envelopes, grants, and access blocks
   * @param keyProvider key provider used for envelope encryption and decryption
   * @param secureRandom random source for nonces, identity ids, grant ids, and signatures
   */
  public AppVaultService(
      AppVaultStore store, AppVaultKeyProvider keyProvider, SecureRandom secureRandom) {
    this.store = Objects.requireNonNull(store, "store");
    this.keyProvider = Objects.requireNonNull(keyProvider, "keyProvider");
    this.secureRandom = Objects.requireNonNull(secureRandom, "secureRandom");
  }

  /**
   * Stores or replaces one app-owned secret value.
   *
   * <p>The secret belongs only to {@code appId}. Caller metadata is redacted before persistence,
   * and the encrypted value is bound to app id, secret name, kind, and creation timestamp as AAD.
   * The returned record is safe for metadata responses and does not contain plaintext or
   * ciphertext.
   *
   * @param appId authenticated app id that owns the secret
   * @param secretName app-local path-safe secret name
   * @param secretKind caller-supplied kind label for metadata views
   * @param value plaintext value bytes to encrypt and store
   * @param metadata caller-supplied metadata, or {@code null} for no metadata
   * @return redacted metadata record for the stored secret
   */
  public synchronized AppSecretRecord putSecret(
      String appId,
      String secretName,
      String secretKind,
      byte[] value,
      Map<String, String> metadata) {
    requireAppAccessAllowed(appId);
    byte[] plaintext = boundedSecretValue(value);
    try {
      AppSecretRecord secretRecord =
          store.prepareSecretRecord(
              appId,
              secretName,
              secretKind,
              plaintext.length,
              metadata == null ? Map.of() : metadata);
      AppVaultEnvelope envelope =
          AppVaultEnvelope.encrypt(
              plaintext,
              AppVaultMetadata.secretAad(
                  secretRecord.appId(),
                  secretRecord.secretName(),
                  secretRecord.secretKind(),
                  secretRecord.createdAt()),
              keyProvider.currentKey(),
              secureRandom);
      store.writeSecret(secretRecord, envelope);
      appendAudit(
          secretRecord.appId(),
          "secret.write",
          AUDIT_TARGET_SECRET,
          secretRecord.secretName(),
          AUDIT_OUTCOME_ALLOWED,
          "stored");
      return secretRecord;
    } catch (IOException exception) {
      throw storageFailure("Failed to store secret.", exception);
    }
  }

  /**
   * Lists redacted secret metadata for one app.
   *
   * <p>The list operation returns metadata only. It does not read or decrypt value envelopes and
   * does not include raw values, ciphertext, local paths, or key identifiers.
   *
   * @param appId app id whose app-owned secrets should be listed
   * @return immutable list of redacted secret metadata records
   */
  public synchronized List<AppSecretRecord> listSecrets(String appId) {
    try {
      return store.listSecrets(appId);
    } catch (IOException exception) {
      throw storageFailure("Failed to list secrets.", exception);
    }
  }

  /**
   * Reads one redacted secret metadata record.
   *
   * <p>The method checks uninstall access blocks before reading and fails with a stable {@code
   * secret_not_found} error when the record is absent. Use {@link #readSecretValue(String, String)}
   * for authorized process-only plaintext reads.
   *
   * @param appId app id that owns the secret
   * @param secretName app-local secret name
   * @return redacted metadata record for the requested secret
   */
  public synchronized AppSecretRecord getSecretRecord(String appId, String secretName) {
    requireAppAccessAllowed(appId);
    try {
      AppSecretRecord secretRecord = store.readSecretRecord(appId, secretName);
      if (secretRecord == null) {
        throw new AppVaultException(404, "secret_not_found", "Secret not found.");
      }
      return secretRecord;
    } catch (IOException exception) {
      throw storageFailure("Failed to read secret metadata.", exception);
    }
  }

  /**
   * Reads one secret plaintext value for an authorized app process.
   *
   * <p>The service decrypts the envelope only after the metadata record is found and its AAD is
   * recomputed from the current metadata. Successful reads update {@code lastUsedAt} and append a
   * value-free audit event. The returned byte array is a new plaintext value for the caller to
   * handle in memory.
   *
   * @param appId app id that owns the secret
   * @param secretName app-local secret name
   * @return decrypted plaintext bytes for the secret value
   */
  public synchronized byte[] readSecretValue(String appId, String secretName) {
    requireAppAccessAllowed(appId);
    try {
      AppSecretRecord secretRecord = getSecretRecord(appId, secretName);
      AppVaultEnvelope envelope =
          store.readSecretEnvelope(secretRecord.appId(), secretRecord.secretName());
      byte[] plaintext =
          envelope.decrypt(
              AppVaultMetadata.secretAad(
                  secretRecord.appId(),
                  secretRecord.secretName(),
                  secretRecord.secretKind(),
                  secretRecord.createdAt()),
              keyProvider.currentKey());
      store.markSecretUsed(secretRecord, Instant.now());
      appendAudit(
          secretRecord.appId(),
          "secret.read",
          AUDIT_TARGET_SECRET,
          secretRecord.secretName(),
          AUDIT_OUTCOME_ALLOWED,
          "read");
      return plaintext;
    } catch (IOException exception) {
      throw storageFailure("Failed to read secret value.", exception);
    }
  }

  /**
   * Deletes one app-owned secret.
   *
   * <p>Deletion removes both metadata and the encrypted envelope when present. Missing records are
   * reported as {@code false} and still produce a value-free audit event.
   *
   * @param appId app id that owns the secret
   * @param secretName app-local secret name
   * @return {@code true} when a stored record was removed
   */
  public synchronized boolean deleteSecret(String appId, String secretName) {
    requireAppAccessAllowed(appId);
    try {
      boolean deleted = store.deleteSecret(appId, secretName);
      appendAudit(
          AppVaultPaths.normalizeAppId(appId),
          "secret.delete",
          AUDIT_TARGET_SECRET,
          AppVaultPaths.normalizeSecretName(secretName),
          deleted ? AUDIT_OUTCOME_ALLOWED : AUDIT_OUTCOME_MISSING,
          deleted ? "deleted" : "not_found");
      return deleted;
    } catch (IOException exception) {
      throw storageFailure("Failed to delete secret.", exception);
    }
  }

  /**
   * Deletes all app-owned secrets for one app, without exposing their names or values.
   *
   * <p>This lifecycle helper is used during uninstall cleanup. It reports only whether any secret
   * tree was removed; it deliberately avoids enumerating secret names in the public result.
   *
   * @param appId app id whose app-owned secrets should be purged
   * @return {@code true} when app-owned secret storage existed and was removed
   */
  public synchronized boolean deleteSecretsForApp(String appId) {
    String normalizedAppId = AppVaultPaths.normalizeAppId(appId);
    try {
      boolean deleted = store.deleteSecretsForApp(normalizedAppId);
      appendAudit(
          normalizedAppId,
          "secret.purge",
          "app",
          normalizedAppId,
          deleted ? AUDIT_OUTCOME_ALLOWED : AUDIT_OUTCOME_MISSING,
          deleted ? AUDIT_REASON_APP_UNINSTALL : "no_app_secrets");
      return deleted;
    } catch (IOException exception) {
      throw storageFailure("Failed to delete app secrets.", exception);
    }
  }

  /**
   * Creates an app-owned identity and its initial self-grant.
   *
   * <p>The identity owner is the normalized app id. After the identity metadata and private
   * envelope are stored, the service creates an app-bound grant for the requested or default usage
   * scopes. If grant persistence fails, the just-created identity is rolled back so failed calls do
   * not accumulate orphaned private material.
   *
   * @param appId authenticated app id that will own the identity
   * @param kind requested identity kind, currently live only for local Ed25519 signing
   * @param label optional display label, or a default label when blank
   * @param requestedScopes requested usage scopes, or defaults when empty
   * @return public metadata for the created identity
   */
  public synchronized AppIdentityRecord createAppOwnedIdentity(
      String appId,
      AppIdentityKind kind,
      String label,
      Set<AppIdentityGrantScope> requestedScopes) {
    requireAppAccessAllowed(appId);
    String ownerAppId = AppVaultPaths.normalizeAppId(appId);
    AppIdentityRecord identityRecord = createIdentity(kind, label, ownerAppId, requestedScopes);
    try {
      grantIdentity(
          identityRecord.identityId(),
          ownerAppId,
          scopesOrDefault(requestedScopes, identityRecord.usageScopes()),
          "app:" + ownerAppId,
          "app-owned identity grant",
          null,
          null);
    } catch (AppVaultException exception) {
      rollbackAppOwnedIdentityCreation(identityRecord, exception);
      throw exception;
    }
    return identityRecord;
  }

  /**
   * Creates an operator-managed identity.
   *
   * <p>The optional owner app id is metadata only; it does not grant app access by itself.
   * Operators must still create explicit grants before apps can list or use the identity.
   *
   * @param kind requested identity kind, currently live only for local Ed25519 signing
   * @param label optional display label, or a default label when blank
   * @param ownerAppId optional owner app id recorded on the identity
   * @param scopes requested usage scopes, or defaults when empty
   * @return public metadata for the created identity
   */
  public synchronized AppIdentityRecord createOperatorIdentity(
      AppIdentityKind kind, String label, String ownerAppId, Set<AppIdentityGrantScope> scopes) {
    return createIdentity(kind, label, ownerAppId, scopes);
  }

  /**
   * Lists identities visible to one app through active metadata-read grants.
   *
   * <p>Visibility is determined by current grant records, not by identity ownership alone. Revoked,
   * inactive, expired, or non-metadata grants are ignored. Missing identities referenced by stale
   * grants are skipped so a partially cleaned store does not expose broken entries.
   *
   * @param appId app id whose visible identity metadata should be listed
   * @return immutable list of public identity metadata records visible to the app
   */
  public synchronized List<AppIdentityRecord> listIdentitiesForApp(String appId) {
    requireAppAccessAllowed(appId);
    String normalizedAppId = AppVaultPaths.normalizeAppId(appId);
    try {
      Set<String> visibleIds = new TreeSet<>();
      Instant now = Instant.now();
      for (AppIdentityGrant grant : store.listGrants()) {
        if (normalizedAppId.equals(grant.appId())
            && grant.scopes().contains(AppIdentityGrantScope.METADATA_READ)
            && grant.activeAt(now)) {
          visibleIds.add(grant.identityId());
        }
      }
      ArrayList<AppIdentityRecord> identities = new ArrayList<>();
      for (String identityId : visibleIds) {
        AppIdentityRecord identity = store.readIdentity(identityId);
        if (identity != null) {
          identities.add(identity);
        }
      }
      return List.copyOf(identities);
    } catch (IOException exception) {
      throw storageFailure("Failed to list identities.", exception);
    }
  }

  /**
   * Lists all identities for operator management.
   *
   * <p>The operator view includes app-owned and operator-managed identities, but each record
   * remains public metadata. Private key envelopes are not loaded or returned by this method.
   *
   * @return immutable list of all public identity metadata records
   */
  public synchronized List<AppIdentityRecord> listIdentities() {
    try {
      return store.listIdentities();
    } catch (IOException exception) {
      throw storageFailure("Failed to list identities.", exception);
    }
  }

  /**
   * Reads one identity visible to an app.
   *
   * <p>The method first builds the app-visible identity set from active metadata-read grants. A
   * missing identity id and an ungranted identity id both return the same not-found error to avoid
   * app-facing identity existence probing.
   *
   * @param appId app id requesting identity metadata
   * @param identityId identity id requested by the app
   * @return public identity metadata visible to the app
   */
  public synchronized AppIdentityRecord getIdentityForApp(String appId, String identityId) {
    String normalizedIdentityId = AppVaultPaths.normalizeIdentityId(identityId);
    return listIdentitiesForApp(appId).stream()
        .filter(identity -> normalizedIdentityId.equals(identity.identityId()))
        .findFirst()
        .orElseThrow(() -> new AppVaultException(404, "identity_not_found", "Identity not found."));
  }

  /**
   * Reads one identity for operator management.
   *
   * <p>Host/operator reads are not filtered by app grants. The returned metadata is still redacted
   * and contains no private envelope or local path information.
   *
   * @param identityId identity id to read from the vault store
   * @return public identity metadata for the requested identity
   */
  public synchronized AppIdentityRecord getIdentity(String identityId) {
    try {
      AppIdentityRecord identity = store.readIdentity(identityId);
      if (identity == null) {
        throw new AppVaultException(404, "identity_not_found", "Identity not found.");
      }
      return identity;
    } catch (IOException exception) {
      throw storageFailure("Failed to read identity.", exception);
    }
  }

  /**
   * Deletes one identity and revokes grants that target it.
   *
   * <p>The method first marks all grants for the identity as revoked, then removes the identity
   * metadata and private envelope. It is intended for explicit operator management; uninstall
   * cleanup uses {@link #deleteAppOwnedIdentitiesForApp(String)} for app-owned identity purging.
   *
   * @param identityId identity id to delete
   * @return {@code true} when an identity record was removed
   */
  public synchronized boolean deleteIdentity(String identityId) {
    String normalizedIdentityId = AppVaultPaths.normalizeIdentityId(identityId);
    try {
      for (AppIdentityGrant grant : store.listGrants()) {
        if (normalizedIdentityId.equals(grant.identityId())) {
          store.writeGrant(grant.withStatus(AppIdentityGrantStatus.REVOKED, Instant.now()));
        }
      }
      return store.deleteIdentity(normalizedIdentityId);
    } catch (IOException exception) {
      throw storageFailure("Failed to delete identity.", exception);
    }
  }

  /**
   * Deletes all identities owned by an app and revokes grants that target them.
   *
   * <p>This uninstalls helper revokes grants before deleting each identity so cleanup can be
   * retried safely after partial failures. It returns the public metadata for identities actually
   * removed, not private material.
   *
   * @param appId app id whose app-owned identities should be purged
   * @return immutable list of public metadata records for deleted identities
   */
  public synchronized List<AppIdentityRecord> deleteAppOwnedIdentitiesForApp(String appId) {
    String normalizedAppId = AppVaultPaths.normalizeAppId(appId);
    ArrayList<AppIdentityRecord> deleted = new ArrayList<>();
    try {
      for (AppIdentityRecord identity : store.listIdentities()) {
        if (!normalizedAppId.equals(identity.ownerAppId())) {
          continue;
        }
        revokeGrantsForDeletedIdentities(Set.of(identity.identityId()));
        if (store.deleteIdentity(identity.identityId())) {
          deleted.add(identity);
          appendAudit(
              normalizedAppId,
              "identity.delete",
              AUDIT_TARGET_IDENTITY,
              identity.identityId(),
              AUDIT_OUTCOME_ALLOWED,
              AUDIT_REASON_APP_UNINSTALL);
        }
      }
      return List.copyOf(deleted);
    } catch (IOException exception) {
      throw storageFailure("Failed to delete app-owned identities.", exception);
    }
  }

  /**
   * Grants one identity to one app.
   *
   * <p>When {@code scopes} is empty, the identity's supported scopes become the grant scopes. API
   * operator routes reject omitted scopes before reaching this service, while internal app-owned
   * identity creation uses the defaulting behavior deliberately. Requested scopes must be supported
   * by the identity kind.
   *
   * @param identityId identity id to grant
   * @param appId app id that may use the grant
   * @param scopes requested grant scopes, or identity defaults when empty
   * @param grantedBy optional operator or automation label
   * @param reason optional operator-visible reason for the grant
   * @param expiresAt optional grant expiry instant
   * @param sourceReviewReceiptId optional trusted review receipt id associated with the grant
   * @return persisted active grant record
   */
  public synchronized AppIdentityGrant grantIdentity(
      String identityId,
      String appId,
      Set<AppIdentityGrantScope> scopes,
      String grantedBy,
      String reason,
      Instant expiresAt,
      String sourceReviewReceiptId) {
    AppIdentityRecord identity = getIdentity(identityId);
    Set<AppIdentityGrantScope> normalizedScopes = scopesOrDefault(scopes, identity.usageScopes());
    if (!identity.usageScopes().containsAll(normalizedScopes)) {
      throw new AppVaultException(
          400, "unsupported_grant_scope", "Identity does not support requested scope.");
    }
    Instant now = Instant.now();
    AppIdentityGrant grant =
        new AppIdentityGrant(
            "grant-" + randomId(),
            identity.identityId(),
            appId,
            normalizedScopes,
            AppIdentityGrantStatus.ACTIVE,
            now,
            now,
            expiresAt,
            grantedBy,
            reason,
            sourceReviewReceiptId);
    try {
      store.writeGrant(grant);
      appendAudit(
          grant.appId(),
          "grant.create",
          AUDIT_TARGET_GRANT,
          grant.grantId(),
          AUDIT_OUTCOME_ALLOWED,
          "granted");
      return grant;
    } catch (IOException exception) {
      throw storageFailure("Failed to store identity grant.", exception);
    }
  }

  /**
   * Lists all grants recorded for one app.
   *
   * <p>This service-level view includes active, inactive, expired, and revoked grants. Use {@link
   * #listAppVisibleGrantsForApp(String)} for app-facing responses that should hide retained revoked
   * grants from previous installations.
   *
   * @param appId app id whose grants should be listed
   * @return immutable list of grants bound to the app id
   */
  public synchronized List<AppIdentityGrant> listGrantsForApp(String appId) {
    String normalizedAppId = AppVaultPaths.normalizeAppId(appId);
    return listGrants().stream().filter(grant -> normalizedAppId.equals(grant.appId())).toList();
  }

  /**
   * Lists non-revoked grants visible to an app principal.
   *
   * <p>The method filters out revoked retained grant records so a same-id reinstall cannot inspect
   * historical shared-identity grants before a fresh operator action. Inactive and expired grants
   * may still be returned so app details can explain why access is unavailable.
   *
   * @param appId app id whose app-facing grant metadata should be listed
   * @return immutable list of non-revoked grants visible to the app
   */
  public synchronized List<AppIdentityGrant> listAppVisibleGrantsForApp(String appId) {
    return listGrantsForApp(appId).stream()
        .filter(grant -> grant.status() != AppIdentityGrantStatus.REVOKED)
        .toList();
  }

  /**
   * Lists all identity grants.
   *
   * <p>This operator-oriented view includes retained revoked records. It validates grant metadata
   * as it reads so copied or malformed grant files fail through stable vault errors instead of
   * being used for authorization.
   *
   * @return immutable list of all grant records in the vault store
   */
  public synchronized List<AppIdentityGrant> listGrants() {
    try {
      return store.listGrants();
    } catch (IOException exception) {
      throw storageFailure("Failed to list identity grants.", exception);
    }
  }

  /**
   * Updates grant status.
   *
   * <p>The update preserves scopes, expiry, identity id, app id, and operator metadata while
   * changing the lifecycle status and timestamp. Missing grants produce a stable not-found error.
   *
   * @param grantId durable grant id to update
   * @param status replacement grant lifecycle status
   * @return updated persisted grant record
   */
  public synchronized AppIdentityGrant updateGrantStatus(
      String grantId, AppIdentityGrantStatus status) {
    try {
      AppIdentityGrant grant = store.readGrant(grantId);
      if (grant == null) {
        throw new AppVaultException(404, "grant_not_found", "Identity grant not found.");
      }
      AppIdentityGrant updated = grant.withStatus(status, Instant.now());
      store.writeGrant(updated);
      appendAudit(
          updated.appId(),
          "grant.status",
          AUDIT_TARGET_GRANT,
          updated.grantId(),
          AUDIT_OUTCOME_ALLOWED,
          status.jsonValue());
      return updated;
    } catch (IOException exception) {
      throw storageFailure("Failed to update identity grant.", exception);
    }
  }

  /**
   * Revokes one grant.
   *
   * <p>Revocation is implemented as a status update to keep the durable record available for
   * operator audit.
   *
   * @param grantId durable grant id to revoke
   */
  public synchronized void revokeGrant(String grantId) {
    updateGrantStatus(grantId, AppIdentityGrantStatus.REVOKED);
  }

  /**
   * Revokes all retained identity grants for one app.
   *
   * <p>This lifecycle helper is used during uninstall cleanup so a future installation with the
   * same app id cannot inherit shared-identity access. Grant records may remain for operator
   * history, but app principal list calls hide revoked records.
   *
   * @param appId app id whose non-revoked grants should be revoked
   */
  public synchronized void revokeGrantsForApp(String appId) {
    String normalizedAppId = AppVaultPaths.normalizeAppId(appId);
    Instant now = Instant.now();
    try {
      for (AppIdentityGrant grant : store.listGrants()) {
        if (normalizedAppId.equals(grant.appId())
            && grant.status() != AppIdentityGrantStatus.REVOKED) {
          AppIdentityGrant updated = grant.withStatus(AppIdentityGrantStatus.REVOKED, now);
          store.writeGrant(updated);
          appendAudit(
              updated.appId(),
              "grant.revoke",
              AUDIT_TARGET_GRANT,
              updated.grantId(),
              AUDIT_OUTCOME_ALLOWED,
              AUDIT_REASON_APP_UNINSTALL);
        }
      }
    } catch (IOException exception) {
      throw storageFailure("Failed to revoke app identity grants.", exception);
    }
  }

  /**
   * Uses a granted identity for one bounded operation.
   *
   * <p>The v1 live operation is local Ed25519 domain-separated signing. The service checks the app
   * access block, active grant, identity kind, requested scope, and payload bound before decrypting
   * private material. It signs only the vault-defined domain string containing app id, identity id,
   * purpose, and payload hash, then returns public verification data and the signature.
   *
   * @param request immutable identity-use request from an app principal route
   * @return public result containing algorithm, fingerprint, payload hash, domain string, and
   *     signature
   */
  public synchronized AppIdentityUsageResult useIdentity(AppIdentityUsageRequest request) {
    return useIdentity(request, false);
  }

  /**
   * Uses a granted identity to sign an already domain-separated bounded payload.
   *
   * <p>This internal service method is intended for Platform API document builders that own and
   * validate a fixed payload format before calling the vault, such as the Trust Graph Preview
   * trust-statement route. It is not exposed as a generic browser-safe signing endpoint. The caller
   * must provide bytes that already include the document domain separator; the vault still performs
   * app access, grant, identity-kind, scope, and size checks before private material is decrypted.
   *
   * @param request immutable identity-use request whose payload is the exact domain-separated bytes
   *     to sign
   * @return public result containing algorithm, fingerprint, payload hash, signed payload text, and
   *     signature
   */
  public synchronized AppIdentityUsageResult signDomainSeparatedPayload(
      AppIdentityUsageRequest request) {
    return useIdentity(request, true);
  }

  private AppIdentityUsageResult useIdentity(
      AppIdentityUsageRequest request, boolean signRequestPayload) {
    requireAppAccessAllowed(request.appId());
    requireGrant(request);
    AppIdentityRecord identity = getIdentity(request.identityId());
    if (identity.kind() != AppIdentityKind.LOCAL_ED25519_SIGNING
        || request.scope() != AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED) {
      throw new AppVaultException(
          409, "identity_operation_unsupported", "Identity operation is unsupported.");
    }
    if (request.payload().length > MAX_USAGE_PAYLOAD_BYTES) {
      throw new AppVaultException(
          400, "usage_payload_too_large", "Identity usage payload is too large.");
    }
    try {
      byte[] privateKeyBytes =
          store
              .readIdentityPrivateEnvelope(identity.identityId())
              .decrypt(AppVaultMetadata.identityAad(identity), keyProvider.currentKey());
      PrivateKey privateKey =
          KeyFactory.getInstance(ALGORITHM_ED25519)
              .generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
      String payloadHash = sha256Hex(request.payload());
      String domainSeparatedPayload =
          signRequestPayload
              ? new String(request.payload(), StandardCharsets.UTF_8)
              : "CryptaAppVault:v1:"
                  + request.appId()
                  + ":"
                  + request.identityId()
                  + ":"
                  + request.purpose()
                  + ":"
                  + payloadHash;
      Signature signature = Signature.getInstance(ALGORITHM_ED25519);
      signature.initSign(privateKey, secureRandom);
      signature.update(
          signRequestPayload ? request.payload() : AppVaultEnvelope.utf8(domainSeparatedPayload));
      AppIdentityUsageResult result =
          new AppIdentityUsageResult(
              identity.identityId(),
              request.scope(),
              ALGORITHM_ED25519,
              identity.fingerprint(),
              identity.publicSummary().getOrDefault("publicKeyBase64", ""),
              payloadHash,
              domainSeparatedPayload,
              Base64.getEncoder().encodeToString(signature.sign()));
      appendAudit(
          request.appId(),
          "identity.use",
          AUDIT_TARGET_IDENTITY,
          identity.identityId(),
          AUDIT_OUTCOME_ALLOWED,
          request.scope().jsonValue());
      return result;
    } catch (GeneralSecurityException exception) {
      throw new AppVaultException(500, "identity_use_failed", "Identity use failed.", exception);
    } catch (IOException exception) {
      throw storageFailure("Failed to use identity.", exception);
    }
  }

  /**
   * Disables or narrows active grants for permissions an updated manifest no longer declares.
   *
   * <p>App updates call this after the new manifest is committed. Metadata-read scopes are retained
   * only when {@code vault.identities.read} remains declared. Generic use scopes require {@code
   * vault.identities.use}; Mail scopes require their exact {@code vault.mail.*} capabilities.
   * Mixed-scope grants are narrowed instead of fully disabled when at least one scope is still
   * allowed.
   *
   * @param appId updated app id
   * @param newManifestPermissions permissions declared by the newly installed manifest
   */
  public synchronized void disableGrantsForRemovedVaultPermissions(
      String appId, Set<String> newManifestPermissions) {
    String normalizedAppId = AppVaultPaths.normalizeAppId(appId);
    for (AppIdentityGrant grant : listGrantsForApp(normalizedAppId)) {
      if (grant.status() != AppIdentityGrantStatus.ACTIVE) {
        continue;
      }
      Set<AppIdentityGrantScope> retainedScopes =
          scopesAllowedByManifest(grant.scopes(), newManifestPermissions);
      if (retainedScopes.isEmpty()) {
        updateGrantStatus(grant.grantId(), AppIdentityGrantStatus.INACTIVE);
      } else if (!retainedScopes.equals(grant.scopes())) {
        updateGrantScopes(grant, retainedScopes);
      }
    }
  }

  /**
   * Returns retained vault status for one app without secret values.
   *
   * <p>The status map is intended for host/operator app summaries. It includes counts, redacted
   * secret names, active grant counts, uninstall-retention flags, and recent value-free audit
   * events. App-readable app summaries should filter this down to availability only.
   *
   * @param appId app id whose vault status should be summarized
   * @return JSON-compatible status map without secret values or private key material
   */
  public synchronized Map<String, Object> appStatus(String appId) {
    String normalizedAppId = AppVaultPaths.normalizeAppId(appId);
    LinkedHashMap<String, Object> status = LinkedHashMap.newLinkedHashMap(8);
    List<AppSecretRecord> secrets = listSecrets(normalizedAppId);
    List<AppIdentityGrant> grants = listGrantsForApp(normalizedAppId);
    long activeGrants = grants.stream().filter(grant -> grant.activeAt(Instant.now())).count();
    boolean accessBlocked = appAccessBlocked(normalizedAppId);
    status.put("appId", normalizedAppId);
    status.put("appOwnedSecrets", secrets.size());
    status.put("secretNames", secrets.stream().map(AppSecretRecord::secretName).toList());
    status.put("identityGrants", grants.size());
    status.put("activeIdentityGrants", activeGrants);
    status.put("retainedAfterUninstall", accessBlocked);
    status.put("appAccessDisabled", accessBlocked);
    status.put(
        "recentAudit",
        recentAuditForApp(normalizedAppId, 8).stream().map(AppVaultService::auditJson).toList());
    return status;
  }

  /**
   * Disables app-facing vault access for an app id until cleanup fully completes.
   *
   * <p>The durable access block is written before uninstall commits so failures default to denying
   * future same-id installs from inheriting stale secrets or grants. The reason code is used only
   * for audit/status context and should not contain raw secret material.
   *
   * @param appId app id whose app-facing vault access should be blocked
   * @param reasonCode stable Reason code for audit and operator status
   */
  public synchronized void disableAppAccess(String appId, String reasonCode) {
    String normalizedAppId = AppVaultPaths.normalizeAppId(appId);
    try {
      store.writeAppAccessBlock(normalizedAppId, reasonCode);
      appendAudit(
          normalizedAppId,
          "app.access.disable",
          "app",
          normalizedAppId,
          AUDIT_OUTCOME_ALLOWED,
          reasonCode == null || reasonCode.isBlank() ? "unspecified" : reasonCode);
    } catch (IOException exception) {
      throw storageFailure("Failed to disable app vault access.", exception);
    }
  }

  /**
   * Clears a previous app-facing vault access block after cleanup has completed.
   *
   * <p>Callers should clear the block only after app-owned secrets are purged, app-owned identities
   * are removed, and app-bound grants are revoked. Clearing without cleanup can allow a
   * reinstallation to regain old vault state.
   *
   * @param appId app id whose access block should be removed
   * @return {@code true} when an existing block was cleared
   */
  public synchronized boolean clearAppAccessBlock(String appId) {
    String normalizedAppId = AppVaultPaths.normalizeAppId(appId);
    try {
      boolean cleared = store.clearAppAccessBlock(normalizedAppId);
      appendAudit(
          normalizedAppId,
          "app.access.enable",
          "app",
          normalizedAppId,
          cleared ? AUDIT_OUTCOME_ALLOWED : AUDIT_OUTCOME_MISSING,
          cleared ? "cleanup_complete" : "not_blocked");
      return cleared;
    } catch (IOException exception) {
      throw storageFailure("Failed to clear app vault access block.", exception);
    }
  }

  /**
   * Returns whether app-facing vault access is disabled for one app id.
   *
   * <p>A blocked app id should not be allowed to list, read, write, create, or use app-facing vault
   * material until cleanup completes or an operator resolves retained state.
   *
   * @param appId app id to check
   * @return {@code true} when a durable access block exists
   */
  public synchronized boolean appAccessBlocked(String appId) {
    return store.appAccessBlocked(AppVaultPaths.normalizeAppId(appId));
  }

  /**
   * Returns whether uninstalled-app vault cleanup still has retained state to remove.
   *
   * <p>The check is used to make DELETE retries recoverable even after the app host no longer has
   * an installed app record. It reports retained secrets, app-owned identities, app-bound grants,
   * or an access block that still needs cleanup.
   *
   * @param appId app id to inspect for retained vault state
   * @return {@code true} when cleanup should be retried or surfaced to the operator
   */
  public synchronized boolean hasRetainedAppState(String appId) {
    try {
      return store.hasRetainedAppState(AppVaultPaths.normalizeAppId(appId));
    } catch (IOException exception) {
      throw storageFailure("Failed to read retained app vault state.", exception);
    }
  }

  /**
   * Requires that an app id is not blocked after an incomplete uninstall cleanup.
   *
   * <p>App-facing operations call this before touching secrets, identities, or grants. A blocked
   * app receives a stable denial and an audit event instead of being allowed to inspect retained
   * state.
   *
   * @param appId app id making an app-facing vault request
   */
  public synchronized void requireAppAccessAllowed(String appId) {
    String normalizedAppId = AppVaultPaths.normalizeAppId(appId);
    if (!appAccessBlocked(normalizedAppId)) {
      return;
    }
    appendAudit(
        normalizedAppId,
        "app.access",
        "app",
        normalizedAppId,
        "denied",
        "app_vault_access_disabled");
    throw new AppVaultException(
        403, "app_vault_access_disabled", "App vault access is disabled pending operator cleanup.");
  }

  /**
   * Returns recent vault audit events for one app.
   *
   * <p>The audit buffer is in-memory and bounded. Results are newest-first, filtered to the
   * normalized app id, and never include secret values or private key material. A non-positive
   * limit returns an empty list.
   *
   * @param appId app id whose recent events should be returned
   * @param limit maximum number of newest matching events to return
   * @return immutable newest-first audit event list for the app
   */
  public synchronized List<AppVaultAuditEvent> recentAuditForApp(String appId, int limit) {
    String normalizedAppId = AppVaultPaths.normalizeAppId(appId);
    if (limit <= 0) {
      return List.of();
    }
    ArrayList<AppVaultAuditEvent> matches = new ArrayList<>();
    var descending = auditEvents.descendingIterator();
    while (descending.hasNext() && matches.size() < limit) {
      AppVaultAuditEvent event = descending.next();
      if (normalizedAppId.equals(event.appId())) {
        matches.add(event);
      }
    }
    return List.copyOf(matches);
  }

  /**
   * Creates an independently generated experimental Mail identity with its narrow self-grant.
   * Central API authorization must restrict this entry point to the live Mail process.
   *
   * @param appId authenticated owning app
   * @param kind dedicated Mail signing, recipient or storage kind
   * @return public metadata, never private material
   */
  public synchronized AppIdentityRecord createMailIdentity(String appId, AppIdentityKind kind) {
    return mailOperations().create(appId, kind);
  }

  /**
   * Signs a validated contact or message payload with the dedicated Mail signing identity.
   *
   * @param appId authenticated owning app
   * @param identityId retained signing identity
   * @param payload canonical unsigned Mail payload
   * @return complete signed wrapper
   */
  public synchronized byte[] signMail(String appId, String identityId, byte[] payload) {
    return mailOperations().sign(appId, identityId, payload);
  }

  /**
   * Authenticates and opens a bounded network envelope for the retained recipient identity. The
   * worker must still verify the inner sender signature, recipient binding and contact policy.
   *
   * @param appId authenticated owning app
   * @param identityId retained recipient identity
   * @param envelope complete encrypted network envelope
   * @return authenticated plaintext for the authorized process
   */
  public synchronized byte[] openMail(String appId, String identityId, byte[] envelope) {
    return mailOperations().open(appId, identityId, envelope, false);
  }

  /**
   * Protects bounded app-owned state with the separate retained local-storage identity.
   *
   * @param appId authenticated owning app
   * @param identityId retained storage identity
   * @param plaintext complete bounded state
   * @return storage envelope, never valid as a network Mail envelope
   */
  public synchronized byte[] sealStorage(String appId, String identityId, byte[] plaintext) {
    return mailOperations().sealStorage(appId, identityId, plaintext);
  }

  /**
   * Authenticates and opens state under the separate local-storage purpose and identity.
   *
   * @param appId authenticated owning app
   * @param identityId retained storage identity
   * @param envelope complete encrypted storage envelope
   * @return authenticated private app state
   */
  public synchronized byte[] openStorage(String appId, String identityId, byte[] envelope) {
    return mailOperations().open(appId, identityId, envelope, true);
  }

  private MailVaultOperations mailOperations() {
    return new MailVaultOperations(this, store, keyProvider, secureRandom);
  }

  private AppIdentityRecord createIdentity(
      AppIdentityKind kind,
      String label,
      String ownerAppId,
      Set<AppIdentityGrantScope> requestedScopes) {
    Objects.requireNonNull(kind, "kind");
    if (kind != AppIdentityKind.LOCAL_ED25519_SIGNING) {
      throw new AppVaultException(
          409, "identity_kind_unsupported", "Identity kind is not live in v1.");
    }
    Set<AppIdentityGrantScope> scopes = localSigningScopesOrDefault(requestedScopes);
    try {
      KeyPairGenerator generator = KeyPairGenerator.getInstance(ALGORITHM_ED25519);
      KeyPair keyPair = generator.generateKeyPair();
      PublicKey publicKey = keyPair.getPublic();
      String identityId = "id-" + randomId();
      Instant now = Instant.now();
      String publicKeyBase64 = Base64.getEncoder().encodeToString(publicKey.getEncoded());
      AppIdentityRecord identityRecord =
          new AppIdentityRecord(
              identityId,
              kind,
              label == null || label.isBlank() ? "Local signing identity" : label,
              ownerAppId,
              now,
              now,
              Map.of("algorithm", ALGORITHM_ED25519, "publicKeyBase64", publicKeyBase64),
              sha256Hex(publicKey.getEncoded()),
              scopes);
      AppVaultEnvelope envelope =
          AppVaultEnvelope.encrypt(
              keyPair.getPrivate().getEncoded(),
              AppVaultMetadata.identityAad(identityRecord),
              keyProvider.currentKey(),
              secureRandom);
      store.writeIdentity(identityRecord, envelope);
      appendAudit(
          identityRecord.ownerAppId(),
          "identity.create",
          AUDIT_TARGET_IDENTITY,
          identityId,
          AUDIT_OUTCOME_ALLOWED,
          kind.jsonValue());
      return identityRecord;
    } catch (GeneralSecurityException exception) {
      throw new AppVaultException(
          500, "identity_create_failed", "Identity creation failed.", exception);
    } catch (IOException exception) {
      throw storageFailure("Failed to store identity.", exception);
    }
  }

  private void requireGrant(AppIdentityUsageRequest request) {
    Instant now = Instant.now();
    for (AppIdentityGrant grant : listGrantsForApp(request.appId())) {
      if (grant.identityId().equals(request.identityId())
          && grant.scopes().contains(request.scope())
          && grant.activeAt(now)) {
        return;
      }
    }
    appendAudit(
        request.appId(),
        "identity.use",
        AUDIT_TARGET_IDENTITY,
        request.identityId(),
        "denied",
        "grant_denied");
    throw new AppVaultException(
        403, "identity_grant_denied", "Identity grant does not allow this operation.");
  }

  private void revokeGrantsForDeletedIdentities(Set<String> identityIds) throws IOException {
    if (identityIds.isEmpty()) {
      return;
    }
    Instant now = Instant.now();
    for (AppIdentityGrant grant : store.listGrants()) {
      if (identityIds.contains(grant.identityId())
          && grant.status() != AppIdentityGrantStatus.REVOKED) {
        AppIdentityGrant updated = grant.withStatus(AppIdentityGrantStatus.REVOKED, now);
        store.writeGrant(updated);
        appendAudit(
            updated.appId(),
            "grant.revoke",
            AUDIT_TARGET_GRANT,
            updated.grantId(),
            AUDIT_OUTCOME_ALLOWED,
            "app_owned_identity_deleted");
      }
    }
  }

  private void rollbackAppOwnedIdentityCreation(
      AppIdentityRecord identityRecord, AppVaultException originalFailure) {
    try {
      revokeGrantsForDeletedIdentities(Set.of(identityRecord.identityId()));
    } catch (AppVaultException | IOException rollbackFailure) {
      originalFailure.addSuppressed(rollbackFailure);
    }
    try {
      if (store.deleteIdentity(identityRecord.identityId())) {
        appendAudit(
            identityRecord.ownerAppId(),
            "identity.delete",
            AUDIT_TARGET_IDENTITY,
            identityRecord.identityId(),
            AUDIT_OUTCOME_ALLOWED,
            "create_grant_failed");
      }
    } catch (IOException rollbackFailure) {
      originalFailure.addSuppressed(rollbackFailure);
    }
  }

  private static Set<AppIdentityGrantScope> scopesOrDefault(
      Set<AppIdentityGrantScope> scopes, Set<AppIdentityGrantScope> defaultScopes) {
    if (scopes == null || scopes.isEmpty()) {
      return Set.copyOf(defaultScopes);
    }
    return Set.copyOf(new TreeSet<>(scopes));
  }

  private static Set<AppIdentityGrantScope> localSigningScopesOrDefault(
      Set<AppIdentityGrantScope> scopes) {
    Set<AppIdentityGrantScope> normalizedScopes =
        scopesOrDefault(scopes, DEFAULT_LOCAL_SIGNING_SCOPES);
    if (!DEFAULT_LOCAL_SIGNING_SCOPES.containsAll(normalizedScopes)) {
      throw new AppVaultException(
          400,
          "unsupported_grant_scope",
          "Local signing identity does not support requested scope.");
    }
    return normalizedScopes;
  }

  private void updateGrantScopes(AppIdentityGrant grant, Set<AppIdentityGrantScope> scopes) {
    AppIdentityGrant updated = grant.withScopes(scopes, Instant.now());
    try {
      store.writeGrant(updated);
      appendAudit(
          updated.appId(),
          "grant.scopes",
          AUDIT_TARGET_GRANT,
          updated.grantId(),
          AUDIT_OUTCOME_ALLOWED,
          "permissions_removed");
    } catch (IOException exception) {
      throw storageFailure("Failed to update identity grant scopes.", exception);
    }
  }

  private static Set<AppIdentityGrantScope> scopesAllowedByManifest(
      Set<AppIdentityGrantScope> scopes, Set<String> permissions) {
    TreeSet<AppIdentityGrantScope> retained = new TreeSet<>();
    for (AppIdentityGrantScope scope : scopes) {
      String capability =
          switch (scope) {
            case METADATA_READ -> "vault.identities.read";
            case MAIL_SIGN -> "vault.mail.sign";
            case MAIL_OPEN -> "vault.mail.open";
            case MAIL_STORAGE -> "vault.mail.storage";
            default -> "vault.identities.use";
          };
      if (permissions.contains(capability)) {
        retained.add(scope);
      }
    }
    return Set.copyOf(retained);
  }

  private static byte[] boundedSecretValue(byte[] value) {
    byte[] plaintext = Objects.requireNonNull(value, "value").clone();
    if (plaintext.length > MAX_SECRET_BYTES) {
      throw new AppVaultException(400, "secret_too_large", "Secret value is too large.");
    }
    return plaintext;
  }

  private String randomId() {
    byte[] bytes = new byte[16];
    secureRandom.nextBytes(bytes);
    return hex(bytes);
  }

  private void appendAudit(
      String appId,
      String operation,
      String targetType,
      String targetId,
      String outcome,
      String reasonCode) {
    auditEvents.addLast(
        new AppVaultAuditEvent(
            Instant.now(), appId, operation, targetType, targetId, outcome, reasonCode));
    while (auditEvents.size() > MAX_AUDIT_EVENTS) {
      auditEvents.removeFirst();
    }
  }

  private static Map<String, Object> auditJson(AppVaultAuditEvent event) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(7);
    json.put("timestamp", event.timestamp().toString());
    json.put("appId", event.appId());
    json.put("operation", event.operation());
    json.put("targetType", event.targetType());
    json.put("targetId", event.targetId());
    json.put("outcome", event.outcome());
    json.put("reasonCode", event.reasonCode());
    return json;
  }

  private static AppVaultException storageFailure(String message, IOException exception) {
    return new AppVaultException(500, "vault_storage_failed", message, exception);
  }

  private static String sha256Hex(byte[] value) {
    try {
      return hex(MessageDigest.getInstance("SHA-256").digest(value));
    } catch (GeneralSecurityException exception) {
      throw new IllegalStateException("SHA-256 unavailable", exception);
    }
  }

  private static String hex(byte[] bytes) {
    char[] chars = new char[bytes.length * 2];
    for (int index = 0; index < bytes.length; index++) {
      int value = bytes[index] & 0xff;
      chars[index * 2] = HEX[value >>> 4];
      chars[index * 2 + 1] = HEX[value & 0x0f];
    }
    return new String(chars);
  }
}
