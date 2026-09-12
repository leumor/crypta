package network.crypta.platform.appcatalog;

import java.time.Instant;
import java.util.Objects;

/**
 * Exact host-local request that can only revoke an existing publisher or reviewer authorization.
 *
 * <p>The expected digest is checked under the store's exclusive mutation fence. All key, subject,
 * channel, and original approval fields remain unchanged; this request cannot import or activate
 * authority. Callers must enforce the host-operator boundary before invoking the store.
 *
 * @param catalogId existing catalog whose scope is narrowed
 * @param scopeId existing publisher-binding or reviewer-scope identifier
 * @param expectedDigestSha256 exact current record self-digest, without an algorithm prefix
 * @param changedAt local operator decision time
 * @param reason bounded local audit reason
 * @param operatorId bounded local operator identity
 */
public record CatalogScopeRevocation(
    String catalogId,
    String scopeId,
    String expectedDigestSha256,
    Instant changedAt,
    String reason,
    String operatorId) {
  /**
   * Validates one exact revocation request without reading or modifying policy.
   *
   * @param catalogId existing catalog identifier, normalized using {@link AppCatalog}
   * @param scopeId existing scope identifier using the local policy identifier grammar
   * @param expectedDigestSha256 current record digest as 64 lowercase hexadecimal characters
   * @param changedAt non-null local decision time; checked against the record when applied
   * @param reason nonblank single-line audit reason, at most 512 characters
   * @param operatorId nonblank single-line operator identity, at most 128 characters
   * @throws NullPointerException if {@code changedAt} is null
   * @throws AppCatalogException if an identifier, digest, or audit text is invalid
   */
  public CatalogScopeRevocation {
    catalogId = AppCatalog.normalizeCatalogId(catalogId);
    scopeId =
        FederatedPolicyRecordSupport.requireId(
            scopeId, "scope id", FederatedPolicyRecordSupport.LOCAL_ID);
    expectedDigestSha256 =
        FederatedPolicyRecordSupport.requireDigest(expectedDigestSha256, "expected scope digest");
    Objects.requireNonNull(changedAt, "changedAt");
    reason = FederatedPolicyRecordSupport.requireText(reason, "reason", 512);
    operatorId = FederatedPolicyRecordSupport.requireText(operatorId, "operator id", 128);
  }

  /**
   * Rejects stale requests and attempts to select a different existing catalog.
   *
   * @param actualCatalogId catalog identifier from the current stored record
   * @param actualDigest self-digest of the current stored record
   * @param updatedAt last mutation time of that record; an equal decision time is permitted
   * @throws AppCatalogException if the catalog or digest differs, or the decision predates the
   *     record
   */
  void requireCurrent(String actualCatalogId, String actualDigest, Instant updatedAt) {
    if (!catalogId.equals(actualCatalogId)
        || !expectedDigestSha256.equals(actualDigest)
        || changedAt.isBefore(updatedAt)) {
      throw rejected();
    }
  }

  /**
   * Returns the fixed failure used for absent, stale, or terminal scope requests.
   *
   * @return a new exception with the {@code catalog_scope_changed} reason code
   */
  static AppCatalogException rejected() {
    return new AppCatalogException(
        "catalog_scope_changed", "The selected local scope is unavailable or changed.");
  }
}
