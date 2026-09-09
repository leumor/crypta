package network.crypta.platform.appvault;

import java.util.Locale;
import java.util.Objects;

/**
 * Persistent identity kinds understood by the app vault.
 *
 * <p>The kind controls how private material is created, stored, and used. Local Ed25519 signing
 * supports the existing v1 operations; dedicated experimental Mail kinds support only typed Mail
 * operations. Publisher and external-reference vocabulary remains reserved. Unsupported kinds never
 * silently expose raw protocol keys to apps.
 */
public enum AppIdentityKind {
  /**
   * Local Ed25519 signing identity backed by encrypted PKCS#8 private key material.
   *
   * <p>This is the live v1 implementation. Apps can receive signatures through the vault service
   * when an active grant permits domain-separated signing.
   */
  LOCAL_ED25519_SIGNING("local-ed25519-signing"),

  /** Dedicated experimental Mail pure Ed25519 seed, usable only by typed Mail signing. */
  MAIL_SIGNING_V1("mail-signing-v1"),

  /** Dedicated experimental Mail X25519 recipient key for the fixed network HPKE suite. */
  MAIL_RECIPIENT_V1("mail-recipient-v1"),

  /** Dedicated experimental Mail X25519 key for local storage, separate from network use. */
  MAIL_STORAGE_V1("mail-storage-v1"),

  /**
   * Reserved model kind for future Crypta publisher identities.
   *
   * <p>The vault records the vocabulary now, but it does not implement SSK/USK publisher key
   * generation or use in this PR.
   */
  CRYPTA_PUBLISHER_PLACEHOLDER("crypta-publisher-placeholder"),

  /**
   * Metadata-only external identity reference.
   *
   * <p>This kind is intended for future integrations where the vault tracks an operator-granted
   * external identity without storing local signing material.
   */
  EXTERNAL_REFERENCE("external-reference");

  private final String jsonValue;

  AppIdentityKind(String jsonValue) {
    this.jsonValue = jsonValue;
  }

  /**
   * Returns the manifest/API spelling for this identity kind.
   *
   * <p>The returned spelling is used in Platform API JSON, vault metadata files, and developer
   * documentation. It is stable across restarts and should not be derived from enum names.
   *
   * @return stable lower-case identity-kind value for public APIs
   */
  public String jsonValue() {
    return jsonValue;
  }

  /**
   * Parses a public identity-kind value.
   *
   * <p>Parsing accepts surrounding whitespace and case variants. Unknown values are mapped to the
   * vault's stable unsupported-kind error, which keeps malformed requests and corrupted metadata on
   * the same redacted error path.
   *
   * @param value identity-kind text from an API request or store file
   * @return matching identity kind from the persistent vocabulary
   */
  public static AppIdentityKind fromJsonValue(String value) {
    String normalized = Objects.requireNonNull(value, "value").trim().toLowerCase(Locale.ROOT);
    for (AppIdentityKind kind : values()) {
      if (kind.jsonValue.equals(normalized)) {
        return kind;
      }
    }
    throw new AppVaultException(400, "unsupported_identity_kind", "Unsupported identity kind.");
  }
}
