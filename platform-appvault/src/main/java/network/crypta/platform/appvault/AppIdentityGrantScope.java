package network.crypta.platform.appvault;

import java.util.Locale;
import java.util.Objects;

/**
 * Operation names that can appear on an app-bound identity grant.
 *
 * <p>Scopes are intentionally narrower than manifest capabilities. A manifest capability such as
 * {@code vault.identities.use} says an app may call the identity-use route at all; a grant scope
 * says which operation that app may perform with one specific identity. The vault checks both
 * layers for identity use so operator grants cannot be reused across apps or across unrelated
 * operations.
 *
 * <p>Some enum values are reserved for future content-reference applications. The live v1 local
 * Ed25519 signing implementation accepts metadata reads and domain-separated signing only.
 * Dedicated experimental Mail identities accept their distinct typed operation scopes; generic
 * signing authorization never grants Mail decryption. Other scopes remain reserved vocabulary.
 */
public enum AppIdentityGrantScope {
  /**
   * Read public identity metadata without authorizing signing or publishing.
   *
   * <p>This scope backs browser-safe identity list and detail workflows. It exposes labels,
   * fingerprints, and public summaries, not private key material.
   */
  METADATA_READ("metadata.read"),

  /** Sign only validated experimental Mail contact or message preimages. */
  MAIL_SIGN("mail.sign"),

  /** Open only the fixed experimental network Mail envelope with its recipient key. */
  MAIL_OPEN("mail.open"),

  /** Seal and open app-owned storage using the separate experimental storage domain. */
  MAIL_STORAGE("mail.storage"),

  /**
   * Sign a domain-separated payload without exposing private key material.
   *
   * <p>The v1 local Ed25519 identity kind supports this scope. The service signs a vault-defined
   * domain string that includes app id, identity id, purpose, and payload hash.
   */
  SIGN_DOMAIN_SEPARATED("sign.domain-separated"),

  /**
   * Reserved future scope for content publishing identities.
   *
   * <p>PR-219 models this vocabulary but does not implement Crypta publisher key use. Requests for
   * unsupported live identity kinds fail before private material is stored or used.
   */
  PUBLISH_CONTENT("publish.content"),

  /**
   * Reserved future scope for profile publishing workflows.
   *
   * <p>The scope is kept distinct from general content publishing so future apps can grant profile
   * updates without also granting arbitrary content publication.
   */
  PUBLISH_PROFILE("publish.profile"),

  /**
   * Use a metadata-only external identity reference.
   *
   * <p>This scope is intended for identities that point at operator-managed external systems rather
   * than local private keys. The v1 local signing implementation does not perform this operation.
   */
  USE_EXTERNAL_REFERENCE("use.external-reference");

  private final String jsonValue;

  AppIdentityGrantScope(String jsonValue) {
    this.jsonValue = jsonValue;
  }

  /**
   * Returns the public grant-scope value.
   *
   * <p>The returned value is the exact spelling used in manifests, Platform API query parameters,
   * grant store files, and contract documentation.
   *
   * @return stable lower-case grant-scope text for JSON and properties files
   */
  public String jsonValue() {
    return jsonValue;
  }

  /**
   * Parses a grant-scope value.
   *
   * <p>Parsing is case-insensitive after trimming surrounding whitespace, but the canonical value
   * returned by {@link #jsonValue()} is always lower-case. Unknown values become stable vault
   * errors so API callers and store readers do not fail with generic enum exceptions.
   *
   * @param value grant-scope text from a request or store file
   * @return matching grant scope from the supported persistent vocabulary
   */
  public static AppIdentityGrantScope fromJsonValue(String value) {
    String normalized = Objects.requireNonNull(value, "value").trim().toLowerCase(Locale.ROOT);
    for (AppIdentityGrantScope scope : values()) {
      if (scope.jsonValue.equals(normalized)) {
        return scope;
      }
    }
    throw new AppVaultException(
        400, "unsupported_grant_scope", "Unsupported identity grant scope.");
  }
}
