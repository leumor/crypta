package network.crypta.platform.appvault;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import network.crypta.crypt.mail.MailHpke;
import network.crypta.crypt.mail.MailWire;

/**
 * Typed experimental Mail cryptography under the owning vault service monitor.
 *
 * <p>Every entry point rechecks the fixed owner app and the relevant retained identity/grants.
 * Callers in the API layer must separately enforce a current process principal and manifest
 * capability; this helper has no browser/session or AppHost transport context. It must be called
 * while holding the owning {@link AppVaultService} monitor.
 *
 * <p>Signing, incoming decryption and local-storage protection use independently generated keys
 * with distinct purposes. Private bytes are read from encrypted vault storage for one operation and
 * erased in finally blocks. Plaintext is visible to this trusted daemon/vault endpoint; key
 * non-exportability does not protect against its compromise. Mailbox and contact-trust decisions
 * remain with the app process, and these methods do not perform network I/O.
 */
final class MailVaultOperations {
  /** Only app permitted to own or invoke these Mail identities. */
  private static final String APP = "mail-prototype";

  /** Public identity summary field containing the raw key in canonical Base64. */
  private static final String PUBLIC_KEY_BASE64 = "publicKeyBase64";

  /** Public identity summary field binding separate purpose keys to one account. */
  private static final String ACCOUNT = "account";

  /** Immutable key epoch in the authoritative public identity summary. */
  private static final String EPOCH = "epoch";

  /** Key role and HPKE purpose reserved for private local state. */
  private static final String STORAGE_ROLE = "storage";

  /** Separate application signature domain for vault-created local state. */
  private static final String STORAGE_AUTH_DOMAIN = "crypta.mail.storage-auth.v1";

  /** Required version marker for writer-authenticated storage envelopes. */
  private static final String AUTHENTICATION = "authentication";

  /** Canonical Base64 writer signature field, always last. */
  private static final String SIGNATURE = "signature";

  /** Complete encoded storage bound, including the writer authentication fields. */
  private static final int MAX_STORAGE_ENVELOPE = 196608;

  /** Closed field set and canonical order of the vault-authenticated storage format. */
  private static final List<String> STORAGE_FIELDS =
      List.of(
          "profile",
          "kem",
          "kdf",
          "aead",
          "selector",
          "enc",
          "ciphertext",
          AUTHENTICATION,
          SIGNATURE);

  /** Authoritative identity lifecycle and grants, accessed under its monitor. */
  private final AppVaultService service;

  /** Existing encrypted vault identity store. */
  private final AppVaultStore store;

  /** Existing vault protection-key provider. */
  private final AppVaultKeyProvider keys;

  /** Secure source for independent keys and random identifiers. */
  private final SecureRandom random;

  /**
   * Uses the existing encrypted vault store under the caller-held vault service monitor.
   *
   * @param service authoritative identity lifecycle and grant checks
   * @param store encrypted identity metadata and private envelopes
   * @param keys existing local vault protection key provider
   * @param random cryptographically secure independent key and identifier source
   */
  MailVaultOperations(
      AppVaultService service, AppVaultStore store, AppVaultKeyProvider keys, SecureRandom random) {
    this.service = service;
    this.store = store;
    this.keys = keys;
    this.random = random;
  }

  /**
   * Checks all retained Mail authority without exposing grant-hidden identity metadata.
   *
   * @param app authenticated Mail app identifier
   * @throws AppVaultException if any retained Mail identity lacks current metadata/purpose
   *     authority
   */
  void requireIdentityAuthority(String app) {
    requireApp(app);
    for (AppIdentityRecord retained : service.listIdentities()) {
      if (APP.equals(retained.ownerAppId())
          && (retained.kind() == AppIdentityKind.MAIL_SIGNING_V1
              || retained.kind() == AppIdentityKind.MAIL_RECIPIENT_V1
              || retained.kind() == AppIdentityKind.MAIL_STORAGE_V1)) {
        // App-visible listings omit revoked, expired and metadata-hidden retained identities.
        // Do not mistake a filtered listing for permission to replace retained account material.
        authorize(app, retained.identityId(), retained.kind());
      }
    }
  }

  /**
   * Creates an independent purpose identity and its narrow owner grant.
   *
   * <p>At most three retained identities per Mail kind are allowed, and generated metadata uses
   * epoch one. Recipient/storage creation binds to the sole currently authorized Mail signer;
   * signing identities receive a fresh random account identifier. This primitive does not implement
   * rotation or repair revoked grants. A failed grant attempts to delete the just-stored identity.
   *
   * @param app authenticated Mail app identifier
   * @param kind dedicated signing, recipient or storage identity kind
   * @return public metadata with the retained account binding
   * @throws AppVaultException if authority, account uniqueness or retained-key quota fails
   */
  AppIdentityRecord create(String app, AppIdentityKind kind) {
    requireApp(app);
    String role = role(kind);
    requireIdentityAuthority(app);
    if (service.listIdentities().stream()
            .filter(i -> APP.equals(i.ownerAppId()) && i.kind() == kind)
            .count()
        >= 3) {
      throw new AppVaultException(409, "mail_key_quota", "Mail retained-key limit reached.");
    }
    byte[] privateKey = new byte[32];
    random.nextBytes(privateKey);
    try {
      byte[] publicKey =
          kind == AppIdentityKind.MAIL_SIGNING_V1
              ? MailWire.signingPublicKey(privateKey)
              : MailHpke.publicKey(privateKey);
      byte[] randomId = new byte[16];
      random.nextBytes(randomId);
      String id = "id-" + HexFormat.of().formatHex(randomId);
      Instant now = Instant.now();
      Map<String, String> summary = new LinkedHashMap<>();
      summary.put("algorithm", kind == AppIdentityKind.MAIL_SIGNING_V1 ? "Ed25519" : "X25519");
      summary.put(PUBLIC_KEY_BASE64, MailWire.base64(publicKey));
      summary.put(EPOCH, "1");
      summary.put("role", role);
      if (kind == AppIdentityKind.MAIL_SIGNING_V1) {
        random.nextBytes(randomId);
        summary.put(ACCOUNT, HexFormat.of().formatHex(randomId));
      } else {
        var signers =
            service.listIdentitiesForApp(APP).stream()
                .filter(i -> i.kind() == AppIdentityKind.MAIL_SIGNING_V1)
                .filter(
                    i ->
                        service.listGrantsForApp(APP).stream()
                            .anyMatch(
                                g ->
                                    g.identityId().equals(i.identityId())
                                        && g.activeAt(Instant.now())
                                        && g.scopes().contains(AppIdentityGrantScope.MAIL_SIGN)))
                .toList();
        if (signers.size() != 1) throw denied();
        summary.put(ACCOUNT, signers.getFirst().publicSummary().get(ACCOUNT));
      }
      Set<AppIdentityGrantScope> scopes = Set.of(AppIdentityGrantScope.METADATA_READ, scope(kind));
      AppIdentityRecord identity =
          new AppIdentityRecord(
              id,
              kind,
              "Experimental Mail " + role,
              APP,
              now,
              now,
              summary,
              MailWire.fingerprint(role, publicKey),
              scopes);
      store.writeIdentity(
          identity,
          AppVaultEnvelope.encrypt(
              privateKey, AppVaultMetadata.identityAad(identity), keys.currentKey(), random));
      grantCreatedIdentity(id, scopes);
      return identity;
    } catch (IOException _) {
      throw unavailable();
    } finally {
      Arrays.fill(privateKey, (byte) 0);
    }
  }

  /**
   * Grants the new identity's purpose scopes, deleting the identity if granting fails.
   *
   * @param id newly persisted identity to authorize or remove on failure
   * @param scopes exact metadata/purpose scopes granted to the fixed Mail owner
   */
  private void grantCreatedIdentity(String id, Set<AppIdentityGrantScope> scopes) {
    try {
      service.grantIdentity(id, APP, scopes, APP, "Dedicated Mail purpose", null, null);
    } catch (RuntimeException failure) {
      service.deleteIdentity(id);
      throw failure;
    }
  }

  /**
   * Validates exact Mail framing and the actual signing identity before signing.
   *
   * @param app authenticated Mail app identifier
   * @param id retained signing identity identifier
   * @param payload canonical unsigned contact or message bytes
   * @return complete signed wrapper
   * @throws AppVaultException if authorization, claims or payload validation fails
   */
  byte[] sign(String app, String id, byte[] payload) {
    AppIdentityRecord identity = authorize(app, id, AppIdentityKind.MAIL_SIGNING_V1);
    try {
      Map<String, String> fields = MailWire.decode(payload, 32768);
      String domain = fields.get("profile");
      byte[] preimage = MailWire.preimage(domain, payload);
      if (MailWire.CONTACT.equals(domain)) {
        requireEqual(identity.fingerprint(), fields.get("signingFingerprint"));
        requireEqual(identity.publicSummary().get(PUBLIC_KEY_BASE64), fields.get("signingKey"));
        requireEqual(identity.publicSummary().get(ACCOUNT), fields.get(ACCOUNT));
        requireEqual("1", fields.get("signingEpoch"));
        requireEqual("1", fields.get("recipientEpoch"));
        AppIdentityRecord recipient =
            service.listIdentitiesForApp(APP).stream()
                .filter(
                    i ->
                        i.kind() == AppIdentityKind.MAIL_RECIPIENT_V1
                            && i.fingerprint().equals(fields.get("recipientFingerprint")))
                .findFirst()
                .orElseThrow(MailVaultOperations::denied);
        authorize(app, recipient.identityId(), AppIdentityKind.MAIL_RECIPIENT_V1);
        requireEqual(identity.publicSummary().get(ACCOUNT), recipient.publicSummary().get(ACCOUNT));
        requireEqual(recipient.publicSummary().get(PUBLIC_KEY_BASE64), fields.get("recipientKey"));
      } else {
        requireEqual(identity.fingerprint(), fields.get("sender"));
        requireEqual(identity.publicSummary().get(ACCOUNT), fields.get("senderAccount"));
        requireEqual("1", fields.get("senderEpoch"));
      }
      byte[] privateKey = privateBytes(identity);
      try {
        return MailWire.signed(payload, MailWire.sign(privateKey, preimage));
      } finally {
        Arrays.fill(privateKey, (byte) 0);
        Arrays.fill(preimage, (byte) 0);
      }
    } catch (IllegalArgumentException _) {
      throw invalid();
    }
  }

  /**
   * Opens a fixed-purpose envelope under current grants and retained account binding.
   *
   * <p>Network opening authenticates the HPKE envelope, validates the complete inner message
   * structure and checks the recipient account/key epoch. It checks signature encoding but does not
   * verify the sender signature, contact pin, freshness or replay history. The worker must complete
   * those checks before accepting or displaying the message. Storage opening first verifies the
   * complete envelope's writer signature against the same account's authorized retained signer,
   * then uses a distinct HPKE domain and returns opaque local-state plaintext. Unsigned storage is
   * rejected; HPKE base-mode integrity alone does not establish local provenance.
   *
   * @param app authenticated Mail app identifier
   * @param id retained recipient or storage identity identifier
   * @param envelope complete encrypted envelope
   * @param storage true for private app state, false for incoming network Mail
   * @return authenticated plaintext; network sender trust still requires worker verification
   * @throws AppVaultException if keys, authority, cryptographic checks or recipient claims fail
   */
  byte[] open(String app, String id, byte[] envelope, boolean storage) {
    AppIdentityRecord identity =
        authorize(
            app, id, storage ? AppIdentityKind.MAIL_STORAGE_V1 : AppIdentityKind.MAIL_RECIPIENT_V1);
    try {
      if (storage) envelope = verifyStorage(identity, envelope);
      else MailWire.decode(envelope, 65536);
    } catch (IllegalArgumentException _) {
      throw invalid();
    }
    byte[] privateKey = privateBytes(identity);
    try {
      byte[] opened =
          MailHpke.open(
              storage ? STORAGE_ROLE : "network", identity.fingerprint(), privateKey, envelope);
      if (!storage) {
        boolean valid = false;
        byte[] payload = null;
        try {
          payload = MailWire.signedPayload(opened);
          var fields = MailWire.decode(payload, 32768);
          MailWire.messagePayload(fields);
          MailWire.signature(opened);
          requireEqual(identity.fingerprint(), fields.get("recipient"));
          requireEqual(identity.publicSummary().get(ACCOUNT), fields.get("recipientAccount"));
          requireEqual("1", fields.get("recipientEpoch"));
          valid = true;
        } finally {
          if (payload != null) Arrays.fill(payload, (byte) 0);
          if (!valid) Arrays.fill(opened, (byte) 0);
        }
      }
      return opened;
    } catch (IllegalArgumentException _) {
      throw invalid();
    } finally {
      Arrays.fill(privateKey, (byte) 0);
    }
  }

  /**
   * Encrypts bounded state under the storage identity and authenticates the complete ciphertext.
   *
   * <p>The same account's retained Mail signer signs a fixed storage-only preimage after
   * encryption. Both purpose grants are required; this operation never signs caller-supplied
   * ciphertext.
   *
   * @param app authenticated Mail app identifier
   * @param id retained storage identity identifier
   * @param plaintext complete private state bytes
   * @return local-storage envelope that is invalid in the network Mail domain
   * @throws AppVaultException if authorization or size checks fail
   */
  byte[] sealStorage(String app, String id, byte[] plaintext) {
    AppIdentityRecord identity = authorize(app, id, AppIdentityKind.MAIL_STORAGE_V1);
    AppIdentityRecord signer = storageSigner(identity);
    byte[] privateKey = privateBytes(signer);
    try {
      byte[] encrypted =
          MailHpke.seal(
              STORAGE_ROLE,
              identity.fingerprint(),
              MailWire.unbase64(identity.publicSummary().get(PUBLIC_KEY_BASE64), 32),
              plaintext);
      byte[] signature = MailWire.sign(privateKey, storagePreimage(identity, signer, encrypted));
      var fields = MailWire.decode(encrypted, MAX_STORAGE_ENVELOPE);
      fields.put(AUTHENTICATION, STORAGE_AUTH_DOMAIN);
      fields.put(SIGNATURE, MailWire.base64(signature));
      byte[] authenticated = MailWire.encode(fields);
      if (authenticated.length > MAX_STORAGE_ENVELOPE) throw invalid();
      return authenticated;
    } catch (IllegalArgumentException _) {
      throw invalid();
    } finally {
      Arrays.fill(privateKey, (byte) 0);
    }
  }

  /**
   * Verifies writer provenance before any storage private-key access or plaintext release.
   *
   * @param storage authorized storage identity supplying authoritative account/key bindings
   * @param envelope complete bounded authenticated storage object
   * @return canonical underlying HPKE envelope, only after signature verification
   */
  private byte[] verifyStorage(AppIdentityRecord storage, byte[] envelope) {
    var fields = MailWire.ordered(MailWire.decode(envelope, MAX_STORAGE_ENVELOPE), STORAGE_FIELDS);
    if (!Arrays.equals(envelope, MailWire.encode(fields))) throw invalid();
    requireEqual(STORAGE_AUTH_DOMAIN, fields.remove(AUTHENTICATION));
    byte[] signature = MailWire.unbase64(fields.remove(SIGNATURE), 64);
    byte[] encrypted = MailWire.encode(fields);
    AppIdentityRecord signer = storageSigner(storage);
    if (!MailWire.verify(
        MailWire.unbase64(signer.publicSummary().get(PUBLIC_KEY_BASE64), 32),
        storagePreimage(storage, signer, encrypted),
        signature)) throw invalid();
    return encrypted;
  }

  /**
   * Selects the sole same-account signer from retained metadata and rechecks its current grant.
   *
   * @param storage authorized storage identity
   * @return current authorized same-account Mail signer
   */
  private AppIdentityRecord storageSigner(AppIdentityRecord storage) {
    var signers =
        service.listIdentities().stream()
            .filter(i -> APP.equals(i.ownerAppId()) && i.kind() == AppIdentityKind.MAIL_SIGNING_V1)
            .filter(
                i -> storage.publicSummary().get(ACCOUNT).equals(i.publicSummary().get(ACCOUNT)))
            .toList();
    if (signers.size() != 1) throw unavailable();
    return authorize(APP, signers.getFirst().identityId(), AppIdentityKind.MAIL_SIGNING_V1);
  }

  /**
   * Frames the complete ciphertext with authoritative local identity bindings in a distinct domain.
   *
   * @param storage authorized storage identity
   * @param signer authorized same-account signer
   * @param encrypted canonical seven-field HPKE envelope
   * @return domain, LF, canonical binding object, LF and exact encrypted envelope bytes
   */
  private static byte[] storagePreimage(
      AppIdentityRecord storage, AppIdentityRecord signer, byte[] encrypted) {
    var binding = new LinkedHashMap<String, String>();
    binding.put("app", APP);
    binding.put(ACCOUNT, storage.publicSummary().get(ACCOUNT));
    binding.put("storageId", storage.identityId());
    binding.put("storageEpoch", storage.publicSummary().get(EPOCH));
    binding.put("storageFingerprint", storage.fingerprint());
    binding.put("signingId", signer.identityId());
    binding.put("signingEpoch", signer.publicSummary().get(EPOCH));
    binding.put("signingFingerprint", signer.fingerprint());
    byte[] prefix = (STORAGE_AUTH_DOMAIN + "\n").getBytes(StandardCharsets.UTF_8);
    byte[] metadata = MailWire.encode(binding);
    return ByteBuffer.allocate(prefix.length + metadata.length + 1 + encrypted.length)
        .put(prefix)
        .put(metadata)
        .put((byte) '\n')
        .put(encrypted)
        .array();
  }

  /**
   * Requires current app, identity kind, owner and unexpired purpose grant.
   *
   * @param app authenticated Mail app identifier
   * @param id retained identity or record identifier
   * @param kind dedicated Mail identity kind
   * @return authorized retained identity metadata
   */
  private AppIdentityRecord authorize(String app, String id, AppIdentityKind kind) {
    requireApp(app);
    AppIdentityRecord identity;
    try {
      identity = service.getIdentityForApp(app, id);
    } catch (AppVaultException failure) {
      if (failure.statusCode() == 404) throw unavailable();
      throw failure;
    }
    if (!APP.equals(identity.ownerAppId()) || identity.kind() != kind) throw denied();
    if (service.listGrantsForApp(APP).stream()
        .noneMatch(
            g ->
                g.identityId().equals(id)
                    && g.activeAt(Instant.now())
                    && g.scopes().contains(scope(kind)))) throw denied();
    return identity;
  }

  /**
   * Requires the fixed Mail owner and current app-vault access.
   *
   * @param app authenticated Mail app identifier
   */
  private void requireApp(String app) {
    if (!APP.equals(app)) throw denied();
    service.requireAppAccessAllowed(app);
  }

  /**
   * Decrypts retained private bytes for one authorized identity; the caller must erase its copy.
   *
   * @param identity authorized retained identity metadata
   * @return new private-key byte array requiring caller erasure
   */
  private byte[] privateBytes(AppIdentityRecord identity) {
    try {
      byte[] result =
          store
              .readIdentityPrivateEnvelope(identity.identityId())
              .decrypt(AppVaultMetadata.identityAad(identity), keys.currentKey());
      if (result.length != 32) {
        Arrays.fill(result, (byte) 0);
        throw unavailable();
      }
      return result;
    } catch (IOException _) {
      throw unavailable();
    }
  }

  /**
   * Selects the independent key role for a dedicated Mail identity kind.
   *
   * @param kind dedicated Mail identity kind
   * @return fixed signing, recipient or storage role
   */
  private static String role(AppIdentityKind kind) {
    return switch (kind) {
      case MAIL_SIGNING_V1 -> "signing";
      case MAIL_RECIPIENT_V1 -> "recipient";
      case MAIL_STORAGE_V1 -> STORAGE_ROLE;
      default -> throw denied();
    };
  }

  /**
   * Selects the narrow private-operation grant for an identity kind.
   *
   * @param kind dedicated Mail identity kind
   * @return required private-operation scope
   */
  private static AppIdentityGrantScope scope(AppIdentityKind kind) {
    return switch (kind) {
      case MAIL_SIGNING_V1 -> AppIdentityGrantScope.MAIL_SIGN;
      case MAIL_RECIPIENT_V1 -> AppIdentityGrantScope.MAIL_OPEN;
      case MAIL_STORAGE_V1 -> AppIdentityGrantScope.MAIL_STORAGE;
      default -> throw denied();
    };
  }

  /**
   * Rejects an identity claim that differs from authoritative metadata.
   *
   * @param expected required authoritative value or delimiter
   * @param actual caller-provided identity claim
   */
  private static void requireEqual(String expected, String actual) {
    if (expected == null || !expected.equals(actual)) throw invalid();
  }

  /**
   * Creates a bounded authorization failure.
   *
   * @return bounded denial exception
   */
  private static AppVaultException denied() {
    return new AppVaultException(403, "mail_identity_denied", "Mail identity operation denied.");
  }

  /**
   * Creates a bounded format or cryptographic failure.
   *
   * @return bounded rejection exception
   */
  private static AppVaultException invalid() {
    return new AppVaultException(400, "mail_operation_rejected", "Mail operation rejected.");
  }

  /**
   * Creates a retained-key recovery failure without exposing vault details.
   *
   * @return bounded retained-key failure
   */
  private static AppVaultException unavailable() {
    return new AppVaultException(503, "key_unavailable", "Retained Mail key is unavailable.");
  }
}
