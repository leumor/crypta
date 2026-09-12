package network.crypta.platform.appcatalog;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.util.Objects;
import network.crypta.platform.appdist.AppBundleSignature;
import network.crypta.platform.appdist.AppBundleVerification;
import network.crypta.platform.appdist.AppBundleVerifier;
import network.crypta.platform.appdist.PublicKeyFingerprint;
import network.crypta.platform.appdist.TrustedAppKey;
import network.crypta.platform.appdist.TrustedAppKeys;

/**
 * Verifies catalog bundles against explicit catalog/app-scoped publisher bindings.
 *
 * <p>The policy parses the signature metadata and rejects known inactive publisher keys as scope
 * conflicts before generic bundle verification. It then verifies the bundle signature through the
 * existing trusted app-key registry and requires exactly one active local publisher binding for the
 * authenticated catalog, app, channel, key ID, and key fingerprint. It also compares the
 * binding-store aggregate digest with the digest accepted by the catalog trust binding.
 *
 * <p>Publisher, catalog signer, and reviewer registries remain role-separated. A narrowly labeled
 * legacy mode permits the catalog and publisher registry objects to be shared, but it does not
 * create publisher authorization. The policy reloads keys and local bindings for each operation;
 * instances hold service references and a clock rather than cached authorization decisions.
 */
public final class CatalogScopedPublisherVerificationPolicy
    implements AppCatalogBundleVerificationPolicy {
  /** Closed catalog-signer registry modes for publisher role-separation checks. */
  public enum CatalogSignerTrustMode {
    /** Catalog signers come from a dedicated registry and must be disjoint from publishers. */
    ROLE_SEPARATED,
    /** Deprecated compatibility mode sharing the AppHost registry for catalog verification. */
    LEGACY_SHARED_APPHOST_REGISTRY
  }

  /** Store containing host-owned catalog/app publisher bindings. */
  private final FileCatalogPublisherBindingStore bindingStore;

  /** Provider for the current bundle-publisher key registry. */
  private final AppCatalogManager.TrustedKeyProvider publisherKeys;

  /** Provider for the current catalog-signing key registry. */
  private final AppCatalogManager.TrustedKeyProvider catalogSignerKeys;

  /** Provider for the current reviewer-key registry used in role separation. */
  private final ReviewerKeyProvider reviewerKeys;

  /** Clock used for key lifecycle and publisher-binding validity decisions. */
  private final Clock clock;

  /** Optional provider for catalog trust bindings and policy-set digests. */
  private final CatalogTrustBindingProvider catalogTrustBindings;

  /** Explicit mode controlling catalog-to-publisher registry separation. */
  private final CatalogSignerTrustMode catalogSignerTrustMode;

  /** Resolves the current local trust binding for one normalized catalog. */
  @FunctionalInterface
  private interface CatalogTrustBindingProvider {
    /**
     * Finds the trust binding for one exact catalog.
     *
     * @param catalogId normalized catalog identifier
     * @return current binding, or an empty value when no binding exists
     * @throws IOException if local trust policy cannot be read safely
     */
    java.util.Optional<FederatedCatalogTrustBinding> findByCatalogId(String catalogId)
        throws IOException;
  }

  /** Reloads the node-local reviewer registry for each authorization decision. */
  @FunctionalInterface
  public interface ReviewerKeyProvider {
    /**
     * Returns the current reviewer public-key and lifecycle registry.
     *
     * @return current non-null reviewer-key registry
     * @throws IOException if configured reviewer-key material cannot be read
     */
    TrustedReviewerKeys trustedReviewerKeys() throws IOException;
  }

  /**
   * Creates a policy with an explicit catalog-signer registry mode.
   *
   * <p>The legacy shared-registry mode relaxes only publisher-to-catalog registry disjointness. It
   * does not make registry membership a publisher authorization and does not relax reviewer role
   * separation, the exact catalog/app publisher binding, or the catalog policy-set digest.
   *
   * @param bindingStore host-owned catalog/app publisher binding store
   * @param publisherKeys provider for current bundle-publisher keys
   * @param catalogSignerKeys provider for current catalog-signing keys
   * @param reviewerKeys provider for current reviewer keys
   * @param clock clock used for lifecycle and validity decisions
   * @param catalogTrustStore optional local catalog trust-binding store
   * @param catalogSignerTrustMode explicit registry separation mode
   */
  public CatalogScopedPublisherVerificationPolicy(
      FileCatalogPublisherBindingStore bindingStore,
      AppCatalogManager.TrustedKeyProvider publisherKeys,
      AppCatalogManager.TrustedKeyProvider catalogSignerKeys,
      ReviewerKeyProvider reviewerKeys,
      Clock clock,
      FileFederatedCatalogTrustStore catalogTrustStore,
      CatalogSignerTrustMode catalogSignerTrustMode) {
    this.bindingStore = Objects.requireNonNull(bindingStore, "bindingStore");
    this.publisherKeys = Objects.requireNonNull(publisherKeys, "publisherKeys");
    this.catalogSignerKeys = Objects.requireNonNull(catalogSignerKeys, "catalogSignerKeys");
    this.reviewerKeys = Objects.requireNonNull(reviewerKeys, "reviewerKeys");
    this.clock = Objects.requireNonNull(clock, "clock");
    this.catalogTrustBindings =
        catalogTrustStore == null ? null : catalogTrustStore::findByCatalogId;
    this.catalogSignerTrustMode =
        Objects.requireNonNull(catalogSignerTrustMode, "catalogSignerTrustMode");
  }

  /** Rejects verification without the authenticated catalog/app context. */
  @Override
  public void verify(Path stagedBundleDirectory) throws IOException {
    Objects.requireNonNull(stagedBundleDirectory, "stagedBundleDirectory");
    throw new IOException("catalog-scoped publisher verification requires catalog/app context");
  }

  /** Verifies the bundle and its exact active local catalog/app publisher authorization. */
  @Override
  public AppCatalogBundleVerificationResult verify(
      AppCatalogBundleVerificationContext context, Path stagedBundleDirectory) throws IOException {
    AppCatalogBundleVerificationContext checkedContext = Objects.requireNonNull(context, "context");
    Path stagedRoot = Objects.requireNonNull(stagedBundleDirectory, "stagedBundleDirectory");
    TrustedAppKeys appKeys = publisherKeys.trustedKeys();
    TrustedAppKeys catalogKeys = catalogSignerKeys.trustedKeys();
    TrustedReviewerKeys reviewers = reviewerKeys.trustedReviewerKeys();
    try {
      if (catalogSignerTrustMode == CatalogSignerTrustMode.ROLE_SEPARATED) {
        appKeys.requireDisjointFrom(catalogKeys);
      } else if (!sameRegistry(appKeys, catalogKeys)) {
        throw new IllegalArgumentException(
            "legacy catalog trust requires the exact shared AppHost registry");
      }
      reviewers.requireDisjointFrom(appKeys);
      reviewers.requireDisjointFrom(catalogKeys);
    } catch (IllegalArgumentException exception) {
      throw new IOException("catalog federation role separation failed", exception);
    }

    Instant now = clock.instant();
    AppBundleSignature signature =
        AppBundleVerifier.read(stagedRoot.resolve(AppBundleSignature.SIGNATURE_FILE_NAME));
    if (appKeys.findPolicy(signature.keyId()).isPresent()
        && appKeys.findActiveForVerification(signature.keyId(), now).isEmpty()) {
      throw new CatalogPublisherAuthorizationException();
    }
    AppBundleVerification verification =
        AppBundleVerifier.requireSigned(appKeys).verify(stagedRoot);
    TrustedAppKey publisherKey =
        appKeys
            .findActiveForVerification(verification.keyId(), now)
            .orElseThrow(CatalogPublisherAuthorizationException::new);
    String fingerprint = PublicKeyFingerprint.sha256(publisherKey.publicKey());
    CatalogPublisherBinding binding =
        bindingStore
            .findAuthorization(
                checkedContext.catalogId(),
                checkedContext.entry().appId(),
                verification.keyId(),
                fingerprint,
                checkedContext.entry().productionMetadata().channel(),
                now)
            .orElseThrow(CatalogPublisherAuthorizationException::new);
    requireCatalogPolicyDigest(checkedContext.catalogId());
    return new AppCatalogBundleVerificationResult(
        verification.keyId(),
        fingerprint,
        binding.bindingId(),
        binding.selfDigest(),
        true,
        verification.signedContentDigestSha256());
  }

  /**
   * Reports whether two key registries contain the same keyed public material.
   *
   * @param left first trusted app-key registry
   * @param right second trusted app-key registry
   * @return {@code true} when registry identities and keys are equivalent
   */
  private static boolean sameRegistry(TrustedAppKeys left, TrustedAppKeys right) {
    return left.keyIds().equals(right.keyIds())
        && left.keyIds().stream()
            .allMatch(keyId -> left.findPolicy(keyId).equals(right.findPolicy(keyId)));
  }

  /**
   * Requires the binding-store policy digest accepted by the catalog trust binding.
   *
   * @param catalogId normalized authenticated catalog identifier
   * @throws IOException if catalog policy is absent, changed, or unreadable
   */
  private void requireCatalogPolicyDigest(String catalogId) throws IOException {
    if (catalogTrustBindings == null) {
      return;
    }
    FederatedCatalogTrustBinding catalogBinding =
        catalogTrustBindings
            .findByCatalogId(catalogId)
            .orElseThrow(CatalogPublisherAuthorizationException::new);
    if (catalogBinding
        .publisherPolicyDigest()
        .filter(bindingStore.policyDigest(catalogId)::equals)
        .isEmpty()) {
      throw new CatalogPublisherAuthorizationException();
    }
  }
}
