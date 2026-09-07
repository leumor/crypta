package network.crypta.platform.appvault;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

/**
 * Builds canonical metadata for AEAD binding and public metadata redaction.
 *
 * <p>The vault authenticates selected immutable metadata as AES-GCM additional authenticated data.
 * That prevents a secret envelope or identity private envelope from being copied under a different
 * app id, secret name, identity id, or kind without detection. The canonical form is deterministic
 * UTF-8 text with sorted keys and a version prefix.
 *
 * <p>This helper also normalizes caller-supplied secret metadata before it is stored. Metadata keys
 * remain visible so apps and operators can understand a record, but values for credential-like keys
 * are replaced with a redaction marker before persistence and before public status responses.
 */
public final class AppVaultMetadata {
  /**
   * Marker used when public metadata needs to retain a key but suppress its value.
   *
   * <p>The marker is written to metadata properties instead of the sensitive value. It is therefore
   * not a reversible mask and should not be treated as encrypted secret storage.
   */
  public static final String REDACTED_VALUE = "<redacted>";

  private AppVaultMetadata() {}

  /**
   * Builds canonical AAD for one secret value.
   *
   * <p>The returned bytes bind the encrypted value to the owning app, secret name, caller-supplied
   * kind, and original creation timestamp. Updating mutable metadata does not change this AAD, but
   * changing any bound field requires writing a new envelope.
   *
   * @param appId owner app id associated with the secret record
   * @param secretName normalized secret name associated with the envelope
   * @param secretKind caller-supplied secret kind stored in metadata
   * @param createdAt original creation timestamp stored in metadata
   * @return deterministic UTF-8 AAD bytes for AES-GCM authentication
   */
  public static byte[] secretAad(
      String appId, String secretName, String secretKind, Instant createdAt) {
    return canonical(
        Map.of(
            "type", "secret",
            "appId", AppVaultPaths.normalizeAppId(appId),
            "secretName", AppVaultPaths.normalizeSecretName(secretName),
            "secretKind", secretKind,
            "createdAt", createdAt.toString()));
  }

  /**
   * Builds canonical AAD for one identity private key envelope.
   *
   * <p>The returned bytes bind private key material to the identity id, kind, optional owner app
   * id, and creation timestamp. Label, update timestamp, and public summary are intentionally
   * excluded for existing identity kinds because they can change without replacing the private key.
   * Experimental Mail kinds additionally bind their immutable account, role, epoch, public key and
   * fingerprint; changing that metadata cannot silently reassign an existing private key.
   *
   * @param identity record whose immutable fields bind the private envelope
   * @return deterministic UTF-8 AAD bytes for AES-GCM authentication
   */
  public static byte[] identityAad(AppIdentityRecord identity) {
    if (identity.kind() == AppIdentityKind.MAIL_SIGNING_V1
        || identity.kind() == AppIdentityKind.MAIL_RECIPIENT_V1
        || identity.kind() == AppIdentityKind.MAIL_STORAGE_V1) {
      Map<String, String> fields = new TreeMap<>();
      fields.put("type", "mail-identity-private-v1");
      fields.put("identityId", identity.identityId());
      fields.put("kind", identity.kind().jsonValue());
      fields.put("ownerAppId", Objects.requireNonNullElse(identity.ownerAppId(), ""));
      fields.put("createdAt", identity.createdAt().toString());
      fields.put("fingerprint", identity.fingerprint());
      identity.publicSummary().forEach((key, value) -> fields.put("public." + key, value));
      return canonical(fields);
    }
    return canonical(
        Map.of(
            "type",
            "identity-private",
            "identityId",
            identity.identityId(),
            "kind",
            identity.kind().jsonValue(),
            "ownerAppId",
            identity.ownerAppId() == null ? "" : identity.ownerAppId(),
            "createdAt",
            identity.createdAt().toString()));
  }

  private static byte[] canonical(Map<String, String> values) {
    TreeMap<String, String> sorted = new TreeMap<>(values);
    StringBuilder builder = new StringBuilder("CryptaAppVaultAAD:v1\n");
    for (Map.Entry<String, String> entry : sorted.entrySet()) {
      builder.append(entry.getKey()).append('=').append(entry.getValue()).append('\n');
    }
    return builder.toString().getBytes(StandardCharsets.UTF_8);
  }

  /**
   * Returns public secret metadata with sensitive-looking values redacted.
   *
   * <p>Keys are trimmed and validated as small path-safe identifiers. Values under keys that look
   * like tokens, passwords, authorization headers, cookies, private keys, seeds, recovery phrases,
   * or mnemonic phrases are replaced with {@link #REDACTED_VALUE}. Non-sensitive values are copied
   * as provided, with {@code null} normalized to an empty string.
   *
   * @param metadata caller-supplied metadata from the app-vault API
   * @return immutable metadata safe for list/status responses and on-disk metadata files
   */
  public static Map<String, String> redactSecretMetadata(Map<String, String> metadata) {
    if (metadata == null || metadata.isEmpty()) {
      return Map.of();
    }
    LinkedHashMap<String, String> redacted = LinkedHashMap.newLinkedHashMap(metadata.size());
    for (Map.Entry<String, String> entry : metadata.entrySet()) {
      String key = normalizeMetadataKey(entry.getKey());
      String value = Objects.requireNonNullElse(entry.getValue(), "");
      redacted.put(key, isSensitiveKey(key) ? REDACTED_VALUE : value);
    }
    return Map.copyOf(redacted);
  }

  private static String normalizeMetadataKey(String value) {
    String key = Objects.requireNonNull(value, "metadata key").trim();
    if (!key.matches("[A-Za-z0-9_.-]{1,64}")) {
      throw new AppVaultException(400, "invalid_vault_metadata", "Invalid vault metadata.");
    }
    return key;
  }

  private static boolean isSensitiveKey(String key) {
    String normalized = key.toLowerCase(Locale.ROOT);
    String compact = compactMetadataKey(normalized);
    return normalized.contains("secret")
        || normalized.contains("token")
        || normalized.contains("password")
        || normalized.contains("credential")
        || normalized.contains("private")
        || normalized.endsWith("key")
        || isAuthorizationMetadataKey(compact)
        || isCookieMetadataKey(compact)
        || isSeedRecoveryMetadataKey(compact);
  }

  private static String compactMetadataKey(String key) {
    return key.replace("_", "").replace("-", "").replace(".", "");
  }

  private static boolean isAuthorizationMetadataKey(String compactKey) {
    return compactKey.equals("proxyauthorization")
        || compactKey.equals("wwwauthenticate")
        || compactKey.equals("proxyauthenticate")
        || compactKey.endsWith("authorization");
  }

  private static boolean isCookieMetadataKey(String compactKey) {
    return compactKey.equals("setcookie") || compactKey.endsWith("cookie");
  }

  private static boolean isSeedRecoveryMetadataKey(String compactKey) {
    return compactKey.contains("seed")
        || compactKey.contains("recoveryphrase")
        || compactKey.contains("mnemonic");
  }
}
