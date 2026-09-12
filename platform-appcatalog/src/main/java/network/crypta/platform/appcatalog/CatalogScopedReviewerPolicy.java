package network.crypta.platform.appcatalog;

import java.io.IOException;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import network.crypta.platform.appdist.PublicKeyFingerprint;

/**
 * Applies local catalog/app reviewer scope after existing receipt and lifecycle verification.
 *
 * <p>The existing reviewer registry remains authoritative for public keys, key lifecycle, receipt
 * signatures, and receipt revocation. This policy adds a second local decision: the authenticated
 * reviewer identity must appear in an active scope for the exact catalog and optional app, and the
 * accepted reviewer-set digest must match.
 *
 * <p>Routine and historical evaluations use distinct lifecycle semantics. A suspended scope may
 * authorize an exact rollback but cannot authorize a new install or update. Retained authorization
 * objects hold the scope-store read lease and immutable reviewer registry snapshot through the host
 * commit. The policy never imports keys or scope declarations from catalog content.
 */
public final class CatalogScopedReviewerPolicy {
  /** Stable status returned when no effective local reviewer scope exists. */
  private static final String REVIEWER_SCOPE_MISSING = "reviewer_scope_missing";

  /** Store containing host-owned catalog and app reviewer scopes. */
  private final FileCatalogReviewerScopeStore scopeStore;

  /** Optional provider for catalog trust bindings and accepted policy-set digests. */
  private final CatalogTrustBindingProvider catalogTrustBindings;

  /** Resolves the current local trust binding for one normalized catalog. */
  @FunctionalInterface
  private interface CatalogTrustBindingProvider {
    /**
     * Finds the trust binding for one exact catalog.
     *
     * @param catalogId normalized catalog identifier
     * @return current binding, or an empty value when none exists
     * @throws IOException if local trust policy cannot be read safely
     */
    Optional<FederatedCatalogTrustBinding> findByCatalogId(String catalogId) throws IOException;
  }

  /**
   * Creates a policy backed by the given host-owned scope store.
   *
   * @param scopeStore host-owned catalog reviewer-scope store
   */
  public CatalogScopedReviewerPolicy(FileCatalogReviewerScopeStore scopeStore) {
    this(scopeStore, null);
  }

  /**
   * Creates a policy that also enforces the catalog trust record's reviewer-policy digest.
   *
   * @param scopeStore host-owned catalog reviewer-scope store
   * @param catalogTrustStore optional local catalog trust-binding store
   */
  public CatalogScopedReviewerPolicy(
      FileCatalogReviewerScopeStore scopeStore, FileFederatedCatalogTrustStore catalogTrustStore) {
    this.scopeStore = Objects.requireNonNull(scopeStore, "scopeStore");
    this.catalogTrustBindings =
        catalogTrustStore == null ? null : catalogTrustStore::findByCatalogId;
  }

  /**
   * Narrows an existing host-owned scope through the same store used for commit authorization.
   *
   * @param request exact host-operator revocation request
   * @return persisted terminal scope
   * @throws IOException if native policy persistence fails
   */
  public CatalogReviewerScope revoke(CatalogScopeRevocation request) throws IOException {
    return scopeStore.revoke(request);
  }

  /**
   * Evaluates existing reviewer trust and then requires an exact active local federation scope.
   *
   * <p>The reviewer registry remains authoritative for public keys, lifecycle, policy constraints,
   * receipt revocation, and signature verification. This method never installs a catalog-declared
   * key. Its result separately reports whether that verified identity is accepted for this local
   * catalog/app scope and exact reviewer-set transparency digest.
   *
   * @param catalogId normalized authenticated source catalog identifier
   * @param entry authenticated catalog entry containing the review receipt
   * @param reviewerSetDigestSha256 exact accepted reviewer-set evidence digest
   * @param trustedReviewerKeys current local reviewer-key registry
   * @param reviewPolicy local receipt acceptance policy
   * @param now local verification instant
   * @return combined receipt and local-scope verification
   * @throws IOException if local reviewer scope or catalog trust state cannot be read
   */
  public Verification evaluate(
      String catalogId,
      AppCatalogEntry entry,
      String reviewerSetDigestSha256,
      TrustedReviewerKeys trustedReviewerKeys,
      AppReviewPolicy reviewPolicy,
      Instant now)
      throws IOException {
    return evaluate(
        catalogId, entry, reviewerSetDigestSha256, trustedReviewerKeys, reviewPolicy, now, false);
  }

  /**
   * Evaluates an exact retained receipt under historical reviewer-scope lifecycle semantics.
   *
   * <p>Cryptographic receipt verification and the reviewer registry remain current and fail closed.
   * Only the local scope lifecycle differs from routine work: an exact suspended scope may
   * authorize rollback, while pending, revoked, and removed scopes remain blocked.
   *
   * @param catalogId normalized authenticated source catalog identifier
   * @param entry authenticated retained catalog entry and receipt
   * @param reviewerSetDigestSha256 exact retained reviewer-set evidence digest
   * @param trustedReviewerKeys current local reviewer-key registry
   * @param reviewPolicy local receipt acceptance policy
   * @param now local historical-verification instant
   * @return combined receipt and historical local-scope verification
   * @throws IOException if local reviewer scope or catalog trust state cannot be read
   */
  public Verification evaluateHistorical(
      String catalogId,
      AppCatalogEntry entry,
      String reviewerSetDigestSha256,
      TrustedReviewerKeys trustedReviewerKeys,
      AppReviewPolicy reviewPolicy,
      Instant now)
      throws IOException {
    return evaluate(
        catalogId, entry, reviewerSetDigestSha256, trustedReviewerKeys, reviewPolicy, now, true);
  }

  /**
   * Evaluates and retains an exact routine reviewer authorization through a host mutation.
   *
   * <p>The scope-store read lease is acquired before evaluation, preventing lifecycle or scope
   * replacement until the returned authorization closes. The immutable reviewer registry snapshot
   * is retained with the exact receipt decision used at the commit boundary.
   *
   * @param catalogId normalized authenticated source catalog identifier
   * @param entry authenticated catalog entry and receipt
   * @param trustedReviewerKeys current local reviewer-key registry snapshot
   * @param reviewPolicy local receipt acceptance policy
   * @param now local routine-verification instant
   * @return retained routine verification, registry snapshot, and store lease
   * @throws IOException if reviewer policy cannot be read or retained safely
   */
  public RoutineAuthorization retainAuthorization(
      String catalogId,
      AppCatalogEntry entry,
      TrustedReviewerKeys trustedReviewerKeys,
      AppReviewPolicy reviewPolicy,
      Instant now)
      throws IOException {
    try (var leaseTransfer = new AuthorizationLeaseTransfer(scopeStore.retainAuthorization())) {
      TrustedReviewerKeys registrySnapshot =
          Objects.requireNonNullElse(trustedReviewerKeys, TrustedReviewerKeys.empty());
      Verification verification = evaluate(catalogId, entry, registrySnapshot, reviewPolicy, now);
      return new RoutineAuthorization(verification, registrySnapshot, leaseTransfer.transfer());
    }
  }

  /**
   * Evaluates and retains an exact historical reviewer authorization through host rollback.
   *
   * <p>The scope-store read lease is acquired before evaluation, preventing lifecycle or scope
   * replacement through the store until the returned authorization closes. The immutable reviewer
   * registry snapshot is retained with the decision, including its key lifecycle and exact receipt
   * revocation set, so the callback cannot accidentally rebind the decision to a later registry
   * instance while the rollback is in flight.
   *
   * @param catalogId normalized authenticated source catalog identifier
   * @param entry authenticated retained catalog entry and receipt
   * @param trustedReviewerKeys current local reviewer-key registry snapshot
   * @param reviewPolicy local receipt acceptance policy
   * @param now local historical-verification instant
   * @return retained historical verification, registry snapshot, and store lease
   * @throws IOException if reviewer policy cannot be read or retained safely
   */
  public HistoricalAuthorization retainHistoricalAuthorization(
      String catalogId,
      AppCatalogEntry entry,
      TrustedReviewerKeys trustedReviewerKeys,
      AppReviewPolicy reviewPolicy,
      Instant now)
      throws IOException {
    try (var leaseTransfer = new AuthorizationLeaseTransfer(scopeStore.retainAuthorization())) {
      TrustedReviewerKeys registrySnapshot =
          Objects.requireNonNullElse(trustedReviewerKeys, TrustedReviewerKeys.empty());
      Verification verification =
          evaluateHistorical(catalogId, entry, registrySnapshot, reviewPolicy, now);
      return new HistoricalAuthorization(verification, registrySnapshot, leaseTransfer.transfer());
    }
  }

  /**
   * Evaluates receipt trust and one exact routine or historical scope.
   *
   * @param catalogId normalized authenticated source catalog identifier
   * @param entry authenticated catalog entry and receipt
   * @param reviewerSetDigestSha256 exact accepted reviewer-set digest
   * @param trustedReviewerKeys current local reviewer-key registry
   * @param reviewPolicy local receipt acceptance policy
   * @param now local verification instant
   * @param historical whether suspended historical scope is permitted
   * @return combined receipt and local-scope verification
   * @throws IOException if local reviewer or catalog policy cannot be read
   */
  private Verification evaluate(
      String catalogId,
      AppCatalogEntry entry,
      String reviewerSetDigestSha256,
      TrustedReviewerKeys trustedReviewerKeys,
      AppReviewPolicy reviewPolicy,
      Instant now,
      boolean historical)
      throws IOException {
    Objects.requireNonNull(entry, "entry");
    TrustedReviewerKeys keys =
        Objects.requireNonNullElse(trustedReviewerKeys, TrustedReviewerKeys.empty());
    AppReviewTrustDecision reviewDecision =
        AppReviewReceiptVerifier.evaluate(entry, keys, reviewPolicy, now);
    Optional<CatalogReviewerScope> effective = scopeStore.findEffective(catalogId, entry.appId());
    if (!reviewDecision.trusted()) {
      return new Verification(
          reviewDecision,
          false,
          effective.map(CatalogReviewerScope::scopeId).orElse(""),
          "",
          effective.map(CatalogReviewerScope::policySemanticDigestSha256).orElse(""),
          "review_untrusted");
    }
    CatalogReviewerScope scope = effective.orElse(null);
    if (scope == null) {
      return new Verification(reviewDecision, false, "", "", "", REVIEWER_SCOPE_MISSING);
    }
    TrustedReviewerKey reviewerKey = keys.find(reviewDecision.reviewerKeyId()).orElse(null);
    if (reviewerKey == null) {
      return new Verification(
          reviewDecision,
          false,
          scope.scopeId(),
          scope.selfDigest(),
          scope.policySemanticDigestSha256(),
          "reviewer_registry_changed");
    }
    String fingerprint = PublicKeyFingerprint.sha256(reviewerKey.publicKey());
    String reviewerSetDigest =
        FederatedPolicyRecordSupport.requireDigest(reviewerSetDigestSha256, "reviewer set digest");
    boolean authorized =
        historical
            ? scope.authorizesHistorical(
                catalogId, entry.appId(), reviewerKey.keyId(), fingerprint, reviewerSetDigest)
            : scope.authorizes(
                catalogId, entry.appId(), reviewerKey.keyId(), fingerprint, reviewerSetDigest);
    if (authorized && !catalogAccepts(scope)) {
      return new Verification(
          reviewDecision,
          false,
          scope.scopeId(),
          scope.selfDigest(),
          scope.policySemanticDigestSha256(),
          "catalog_reviewer_policy_mismatch");
    }
    return new Verification(
        reviewDecision,
        authorized,
        scope.scopeId(),
        scope.selfDigest(),
        scope.policySemanticDigestSha256(),
        authorized ? "authorized" : "reviewer_scope_rejected");
  }

  /**
   * Evaluates against the exact reviewer-set digest retained in the effective local scope.
   *
   * @param catalogId normalized authenticated source catalog identifier
   * @param entry authenticated catalog entry and receipt
   * @param trustedReviewerKeys current local reviewer-key registry
   * @param reviewPolicy local receipt acceptance policy
   * @param now local routine-verification instant
   * @return combined receipt and routine local-scope verification
   * @throws IOException if local reviewer or catalog policy cannot be read
   */
  public Verification evaluate(
      String catalogId,
      AppCatalogEntry entry,
      TrustedReviewerKeys trustedReviewerKeys,
      AppReviewPolicy reviewPolicy,
      Instant now)
      throws IOException {
    Optional<CatalogReviewerScope> effective = scopeStore.findEffective(catalogId, entry.appId());
    if (effective.isEmpty()) {
      AppReviewTrustDecision reviewDecision =
          AppReviewReceiptVerifier.evaluate(entry, trustedReviewerKeys, reviewPolicy, now);
      return new Verification(reviewDecision, false, "", "", "", REVIEWER_SCOPE_MISSING);
    }
    return evaluate(
        catalogId,
        entry,
        effective.orElseThrow().acceptedReviewerSetDigestSha256(),
        trustedReviewerKeys,
        reviewPolicy,
        now);
  }

  /**
   * Evaluates historical authorization using the effective scope's exact reviewer-set digest.
   *
   * @param catalogId normalized authenticated source catalog identifier
   * @param entry authenticated retained catalog entry and receipt
   * @param trustedReviewerKeys current local reviewer-key registry
   * @param reviewPolicy local receipt acceptance policy
   * @param now local historical-verification instant
   * @return combined receipt and historical local-scope verification
   * @throws IOException if local reviewer or catalog policy cannot be read
   */
  public Verification evaluateHistorical(
      String catalogId,
      AppCatalogEntry entry,
      TrustedReviewerKeys trustedReviewerKeys,
      AppReviewPolicy reviewPolicy,
      Instant now)
      throws IOException {
    Optional<CatalogReviewerScope> effective = scopeStore.findEffective(catalogId, entry.appId());
    if (effective.isEmpty()) {
      AppReviewTrustDecision reviewDecision =
          AppReviewReceiptVerifier.evaluate(entry, trustedReviewerKeys, reviewPolicy, now);
      return new Verification(reviewDecision, false, "", "", "", REVIEWER_SCOPE_MISSING);
    }
    return evaluateHistorical(
        catalogId,
        entry,
        effective.orElseThrow().acceptedReviewerSetDigestSha256(),
        trustedReviewerKeys,
        reviewPolicy,
        now);
  }

  /**
   * Checks whether catalog trust accepts the current reviewer policy-set digest.
   *
   * @param scope effective reviewer scope being evaluated
   * @return {@code true} when compatibility mode applies or policy digests match
   * @throws IOException if catalog trust or reviewer policy cannot be read
   */
  private boolean catalogAccepts(CatalogReviewerScope scope) throws IOException {
    if (catalogTrustBindings == null) {
      return true;
    }
    Optional<String> expected =
        catalogTrustBindings
            .findByCatalogId(scope.catalogId())
            .flatMap(FederatedCatalogTrustBinding::reviewerPolicyDigest);
    return expected.filter(scopeStore.policyDigest(scope.catalogId())::equals).isPresent();
  }

  /** Closes a newly acquired lease unless ownership is transferred to a returned authorization. */
  private static final class AuthorizationLeaseTransfer implements AutoCloseable {
    /** Lease still owned by this transfer helper, or {@code null} after transfer. */
    private FileCatalogReviewerScopeStore.AuthorizationLease lease;

    /**
     * Creates a transfer helper that initially owns the supplied lease.
     *
     * @param lease newly acquired scope-store authorization lease
     */
    private AuthorizationLeaseTransfer(FileCatalogReviewerScopeStore.AuthorizationLease lease) {
      this.lease = Objects.requireNonNull(lease, "lease");
    }

    /**
     * Transfers lease ownership to the returned retained authorization.
     *
     * @return authorization lease formerly owned by this helper
     */
    private FileCatalogReviewerScopeStore.AuthorizationLease transfer() {
      FileCatalogReviewerScopeStore.AuthorizationLease transferred = lease;
      lease = null;
      return transferred;
    }

    @Override
    public void close() {
      if (lease != null) {
        lease.close();
      }
    }
  }

  /**
   * Safe combined receipt-verification and local-scope result.
   *
   * @param reviewDecision cryptographic and global-lifecycle review-receipt decision
   * @param authorized whether exact local catalog and app scope also authorizes the reviewer
   * @param scopeId local reviewer-scope identifier, empty when no scope authorized the receipt
   * @param scopeDigestSha256 exact local reviewer-scope record digest, empty when unavailable
   * @param policySemanticDigestSha256 catalog-independent accepted reviewer-policy digest
   * @param status bounded reason code suitable for operator-facing summaries
   */
  public record Verification(
      AppReviewTrustDecision reviewDecision,
      boolean authorized,
      String scopeId,
      String scopeDigestSha256,
      String policySemanticDigestSha256,
      String status) {
    /** Validates a redacted immutable scope decision. */
    public Verification {
      Objects.requireNonNull(reviewDecision, "reviewDecision");
      Objects.requireNonNull(scopeId, "scopeId");
      Objects.requireNonNull(scopeDigestSha256, "scopeDigestSha256");
      Objects.requireNonNull(policySemanticDigestSha256, "policySemanticDigestSha256");
      status = FederatedPolicyRecordSupport.requireText(status, "reviewer scope status", 64);
      if (!policySemanticDigestSha256.isBlank()) {
        policySemanticDigestSha256 =
            FederatedPolicyRecordSupport.requireDigest(
                policySemanticDigestSha256, "reviewer policy semantic digest");
      }
      if (authorized
          && (scopeId.isBlank()
              || scopeDigestSha256.isBlank()
              || policySemanticDigestSha256.isBlank())) {
        throw new IllegalArgumentException("authorized reviewer scope requires policy identity");
      }
    }
  }

  /**
   * Retained historical reviewer decision and the immutable registry snapshot that produced it.
   *
   * @param verification exact receipt and local-scope decision
   * @param reviewerKeysSnapshot immutable key-lifecycle and receipt-revocation registry
   * @param authorization same-thread scope-store lease
   */
  public record HistoricalAuthorization(
      Verification verification,
      TrustedReviewerKeys reviewerKeysSnapshot,
      FileCatalogReviewerScopeStore.AuthorizationLease authorization)
      implements AutoCloseable {
    /** Validates one retained reviewer decision. */
    public HistoricalAuthorization {
      Objects.requireNonNull(verification, "verification");
      Objects.requireNonNull(reviewerKeysSnapshot, "reviewerKeysSnapshot");
      Objects.requireNonNull(authorization, "authorization");
    }

    /** Releases the retained reviewer-scope policy. */
    @Override
    public void close() {
      authorization.close();
    }
  }

  /**
   * Retained routine reviewer decision and the immutable registry snapshot that produced it.
   *
   * @param verification exact receipt and active local-scope decision
   * @param reviewerKeysSnapshot immutable key-lifecycle and receipt-revocation registry
   * @param authorization same-thread scope-store lease
   */
  public record RoutineAuthorization(
      Verification verification,
      TrustedReviewerKeys reviewerKeysSnapshot,
      FileCatalogReviewerScopeStore.AuthorizationLease authorization)
      implements AutoCloseable {
    /** Validates one retained reviewer decision. */
    public RoutineAuthorization {
      Objects.requireNonNull(verification, "verification");
      Objects.requireNonNull(reviewerKeysSnapshot, "reviewerKeysSnapshot");
      Objects.requireNonNull(authorization, "authorization");
    }

    /** Releases the retained reviewer-scope policy. */
    @Override
    public void close() {
      authorization.close();
    }
  }
}
