package network.crypta.platform.appvault;

import java.io.IOException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import network.crypta.crypt.mail.MailHpke;
import network.crypta.crypt.mail.MailWire;

/** Typed experimental Mail operations; invoked only under the owning vault service lock. */
final class MailVaultOperations {
  /** Only app permitted to own or invoke these Mail identities. */
  private static final String APP = "mail-prototype";

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
   * Creates an independent purpose identity and its narrow owner grant.
   *
   * @param app authenticated Mail app identifier
   * @param kind dedicated signing, recipient or storage identity kind
   * @return public metadata with the retained account binding
   * @throws AppVaultException if authority, account uniqueness or retained-key quota fails
   */
  AppIdentityRecord create(String app, AppIdentityKind kind) {
    requireApp(app);
    String role = role(kind);
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
      summary.put("publicKeyBase64", MailWire.base64(publicKey));
      summary.put("epoch", "1");
      summary.put("role", role);
      if (kind == AppIdentityKind.MAIL_SIGNING_V1) {
        random.nextBytes(randomId);
        summary.put("account", HexFormat.of().formatHex(randomId));
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
        summary.put("account", signers.getFirst().publicSummary().get("account"));
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
      try {
        service.grantIdentity(id, APP, scopes, APP, "Dedicated Mail purpose", null, null);
      } catch (RuntimeException failure) {
        service.deleteIdentity(id);
        throw failure;
      }
      return identity;
    } catch (IOException failure) {
      throw unavailable();
    } finally {
      Arrays.fill(privateKey, (byte) 0);
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
        requireEqual(identity.publicSummary().get("publicKeyBase64"), fields.get("signingKey"));
        requireEqual(identity.publicSummary().get("account"), fields.get("account"));
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
        requireEqual(
            identity.publicSummary().get("account"), recipient.publicSummary().get("account"));
        requireEqual(recipient.publicSummary().get("publicKeyBase64"), fields.get("recipientKey"));
      } else {
        requireEqual(identity.fingerprint(), fields.get("sender"));
        requireEqual(identity.publicSummary().get("account"), fields.get("senderAccount"));
        requireEqual("1", fields.get("senderEpoch"));
      }
      byte[] privateKey = privateBytes(identity);
      try {
        return MailWire.signed(payload, MailWire.sign(privateKey, preimage));
      } finally {
        Arrays.fill(privateKey, (byte) 0);
        Arrays.fill(preimage, (byte) 0);
      }
    } catch (IllegalArgumentException failure) {
      throw invalid();
    }
  }

  /**
   * Opens a fixed-purpose envelope under current grants and retained account binding.
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
      MailWire.decode(envelope, storage ? 196608 : 65536);
    } catch (IllegalArgumentException failure) {
      throw invalid();
    }
    byte[] privateKey = privateBytes(identity);
    try {
      byte[] opened =
          MailHpke.open(
              storage ? "storage" : "network", identity.fingerprint(), privateKey, envelope);
      if (!storage) {
        boolean valid = false;
        byte[] payload = null;
        try {
          payload = MailWire.signedPayload(opened);
          var fields = MailWire.decode(payload, 32768);
          MailWire.messagePayload(fields);
          MailWire.signature(opened);
          requireEqual(identity.fingerprint(), fields.get("recipient"));
          requireEqual(identity.publicSummary().get("account"), fields.get("recipientAccount"));
          requireEqual("1", fields.get("recipientEpoch"));
          valid = true;
        } finally {
          if (payload != null) Arrays.fill(payload, (byte) 0);
          if (!valid) Arrays.fill(opened, (byte) 0);
        }
      }
      return opened;
    } catch (IllegalArgumentException failure) {
      throw invalid();
    } finally {
      Arrays.fill(privateKey, (byte) 0);
    }
  }

  /**
   * Protects bounded state under the distinct retained local-storage identity.
   *
   * @param app authenticated Mail app identifier
   * @param id retained storage identity identifier
   * @param plaintext complete private state bytes
   * @return local-storage envelope that is invalid in the network Mail domain
   * @throws AppVaultException if authorization or size checks fail
   */
  byte[] sealStorage(String app, String id, byte[] plaintext) {
    AppIdentityRecord identity = authorize(app, id, AppIdentityKind.MAIL_STORAGE_V1);
    try {
      return MailHpke.seal(
          "storage",
          identity.fingerprint(),
          MailWire.unbase64(identity.publicSummary().get("publicKeyBase64"), 32),
          plaintext);
    } catch (IllegalArgumentException failure) {
      throw invalid();
    }
  }

  /**
   * Requires current app, identity kind, owner and unexpired purpose grant.
   *
   * @param app authenticated Mail app identifier
   * @param id retained identity or record identifier
   * @param kind dedicated Mail identity kind
   * @return authorized current identity or launch metadata
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
    } catch (IOException failure) {
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
      case MAIL_STORAGE_V1 -> "storage";
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
