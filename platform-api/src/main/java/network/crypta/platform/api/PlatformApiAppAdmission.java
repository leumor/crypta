package network.crypta.platform.api;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import network.crypta.platform.appdist.AppApiCompatibilityMetadata;

/**
 * Applies the shared contract and named-baseline policy before an app runtime mutation.
 *
 * <p>Install, update, source-switch, and start paths call this class so that they interpret an
 * app's contract range and named stable baseline consistently. The checks are deliberately separate
 * from authorization: a successful admission decision never supplies a capability, changes the app
 * principal, or bypasses consent and sandbox policy. Legacy manifests that never declared an API
 * compatibility target retain their established behavior, while explicit stable declarations are
 * checked against both the active baseline registry and the integer contract range.
 *
 * <p>The class is stateless and thread-safe. Summaries describe static contract compatibility, not
 * observed runtime behavior or protected release evidence.
 */
public final class PlatformApiAppAdmission {
  private static final String FIELD_STATUS = "status";

  private PlatformApiAppAdmission() {}

  /**
   * Returns the current static compatibility summary without granting any app capability.
   *
   * <p>The result uses the node's current contract and baseline registry. It is suitable for
   * bounded review and operator displays, but callers must not represent it as a runtime test. A
   * {@code null} metadata value follows the legacy undeclared-app policy; the supplied permission
   * names remain manifest claims and are never converted into authorization. The returned map is
   * immutable and uses the verifier's deterministic field and finding order.
   *
   * @param metadata the app's parsed compatibility declaration, or {@code null} for undeclared
   *     legacy metadata
   * @param permissions the capabilities declared by the app manifest
   * @return an immutable, deterministic summary of static compatibility findings
   */
  public static Map<String, Object> summarize(
      AppApiCompatibilityMetadata metadata, Collection<String> permissions) {
    return PlatformApiContractVerifier.summarize(
        metadata,
        permissions,
        PlatformApiContract.current(),
        PlatformApiBaselineRegistry.current());
  }

  /**
   * Returns a static summary with the exact strict runtime-admission verdict.
   *
   * <p>This method preserves the detailed verifier output while normalizing baseline and
   * baseline-root range failures to the status strings consumed by existing install and update
   * policy. It does not mutate the app or the registry. Undeclared legacy metadata retains the
   * ordinary summary status, while unsupported baselines and stable capability violations become
   * blocking statuses. Callers can therefore display the same outcome that a subsequent admission
   * check will enforce without attempting the mutation.
   *
   * @param metadata the app's parsed compatibility declaration, or {@code null} when undeclared
   * @param permissions the capabilities declared by the app manifest
   * @return an immutable summary whose status matches runtime admission policy
   */
  public static Map<String, Object> summarizeAdmission(
      AppApiCompatibilityMetadata metadata, Collection<String> permissions) {
    AppApiCompatibilityMetadata effective =
        metadata == null ? AppApiCompatibilityMetadata.undeclared() : metadata;
    LinkedHashMap<String, Object> summary = new LinkedHashMap<>(summarize(effective, permissions));
    if (!effective.declared()) {
      return java.util.Collections.unmodifiableMap(summary);
    }
    PlatformApiContractVerifier.CompatibilityVerificationResult verification =
        strictVerification(effective, permissions);
    if (unsupportedBaseline(verification)) {
      summary.put(FIELD_STATUS, "unsupported-baseline");
    } else if (baselineDeclarationRejected(effective, verification)
        || stableCapabilityDeclarationRejected(effective, verification)) {
      summary.put(FIELD_STATUS, "incompatible");
    }
    return java.util.Collections.unmodifiableMap(summary);
  }

  /**
   * Rejects an app whose declared contract range or stable baseline cannot run on this node.
   *
   * <p>Legacy undeclared apps preserve their existing admission behavior. Experimental apps may
   * inspect a candidate baseline as preview-only, but their permissions and the existing
   * experimental opt-in policy remain authoritative. The method performs no installation, update,
   * process start, consent, or permission mutation; it is a guard that callers invoke immediately
   * before those operations. A successful return establishes only static compatibility with the
   * current contract and supported baseline registry.
   *
   * @param metadata the app's parsed compatibility declaration, or {@code null} when undeclared
   * @param permissions the capabilities declared by the app manifest
   * @throws PlatformApiException if an explicit baseline or contract-range declaration is not
   *     admissible on the current node
   */
  public static void requireCurrentCompatibility(
      AppApiCompatibilityMetadata metadata, Collection<String> permissions) {
    requireCompatibility(
        metadata,
        permissions,
        PlatformApiContract.current(),
        PlatformApiBaselineRegistry.current());
  }

  /**
   * Applies the normal runtime admission rules to an explicitly authenticated static target.
   *
   * <p>The caller authenticates the snapshot and complete registry. This method grants no
   * permissions and deliberately preserves the runtime warning for an exceeded tested maximum.
   *
   * @param metadata signed manifest compatibility declarations
   * @param permissions signed manifest permission names
   * @param contract exact selected target contract
   * @param registry exact selected target baseline registry
   * @throws PlatformApiException when the target rejects the declaration
   */
  public static void requireCompatibility(
      AppApiCompatibilityMetadata metadata,
      Collection<String> permissions,
      PlatformApiContract contract,
      PlatformApiBaselineRegistry registry) {
    Objects.requireNonNull(contract, "contract");
    Objects.requireNonNull(registry, "registry");
    AppApiCompatibilityMetadata effective =
        metadata == null ? AppApiCompatibilityMetadata.undeclared() : metadata;
    if (!effective.declared()) {
      return;
    }
    PlatformApiContractVerifier.CompatibilityVerificationResult verification =
        PlatformApiContractVerifier.verify(effective, permissions, contract, registry, true);
    if (unsupportedBaseline(verification)) {
      throw new PlatformApiException(
          409,
          "unsupported_platform_api_baseline",
          "The app targets a Platform API baseline that this node does not actively support.");
    }
    String reviewStatus =
        String.valueOf(
            PlatformApiContractVerifier.summarize(effective, permissions, contract, registry)
                .get(FIELD_STATUS));
    if (baselineDeclarationRejected(effective, verification)
        || stableCapabilityDeclarationRejected(effective, verification)
        || "below_minimum".equals(reviewStatus)
        || "incompatible".equals(reviewStatus)) {
      throw new PlatformApiException(
          409,
          "incompatible_platform_api_contract",
          "The app compatibility declaration is not admissible on this Platform API contract.");
    }
  }

  /**
   * Rejects compatibility metadata that a catalog explicitly attributes to a different manifest.
   *
   * <p>Old catalog schemas may omit API compatibility metadata entirely, so an undeclared catalog
   * value remains advisory and the signed bundle manifest is authoritative. When a catalog names a
   * target baseline, that baseline and its stability target must reproduce the signed manifest
   * declaration; callers must not consent to one named-baseline subject and install another. When a
   * legacy catalog explicitly names stable target stability without a baseline, its effective
   * {@code 1.0} target must also match. Other catalog compatibility hints remain advisory, while
   * runtime admission always evaluates the signed manifest itself.
   *
   * @param catalogMetadata compatibility metadata authenticated by the catalog
   * @param manifestMetadata compatibility metadata authenticated by the signed bundle
   * @throws PlatformApiException if an explicitly cataloged target differs from the manifest
   */
  public static void requireCatalogDeclarationMatchesManifest(
      AppApiCompatibilityMetadata catalogMetadata, AppApiCompatibilityMetadata manifestMetadata) {
    AppApiCompatibilityMetadata catalog =
        catalogMetadata == null ? AppApiCompatibilityMetadata.undeclared() : catalogMetadata;
    AppApiCompatibilityMetadata manifest =
        manifestMetadata == null ? AppApiCompatibilityMetadata.undeclared() : manifestMetadata;
    if (!catalog.declared()) {
      return;
    }
    if (catalogDeclarationMismatch(catalog, manifest)) {
      throw new PlatformApiException(
          400,
          "invalid_app_bundle",
          "Catalog Platform API compatibility metadata differs from the signed app manifest.");
    }
  }

  private static boolean catalogDeclarationMismatch(
      AppApiCompatibilityMetadata catalog, AppApiCompatibilityMetadata manifest) {
    boolean targetBaselineMismatch =
        !Objects.equals(catalog.targetBaseline(), manifest.targetBaseline());
    boolean stabilityMismatch =
        catalog.targetStabilityDeclared()
            && (!manifest.targetStabilityDeclared()
                || catalog.targetStability() != manifest.targetStability());
    boolean namedBaselineMismatch =
        catalog.targetBaselineDeclared()
            && (!manifest.targetBaselineDeclared()
                || targetBaselineMismatch
                || catalog.targetStabilityDeclared() != manifest.targetStabilityDeclared()
                || catalog.targetStability() != manifest.targetStability());
    boolean legacyStableBaselineMismatch =
        catalog.targetStabilityDeclared()
            && catalog.targetStability() == AppApiCompatibilityMetadata.TargetStability.STABLE
            && targetBaselineMismatch;
    return stabilityMismatch || namedBaselineMismatch || legacyStableBaselineMismatch;
  }

  private static PlatformApiContractVerifier.CompatibilityVerificationResult strictVerification(
      AppApiCompatibilityMetadata metadata, Collection<String> permissions) {
    return PlatformApiContractVerifier.verify(
        metadata,
        permissions,
        PlatformApiContract.current(),
        PlatformApiBaselineRegistry.current(),
        true);
  }

  private static boolean unsupportedBaseline(
      PlatformApiContractVerifier.CompatibilityVerificationResult verification) {
    return verification.findings().stream()
        .map(PlatformApiContractVerifier.CompatibilityFinding::code)
        .anyMatch(
            code ->
                code.equals("target_baseline_unknown")
                    || code.equals("target_baseline_inactive")
                    || code.equals("target_baseline_end_of_support")
                    || code.equals("target_baseline_malformed"));
  }

  private static boolean baselineDeclarationRejected(
      AppApiCompatibilityMetadata metadata,
      PlatformApiContractVerifier.CompatibilityVerificationResult verification) {
    return verification.findings().stream()
        .map(PlatformApiContractVerifier.CompatibilityFinding::code)
        .anyMatch(
            code ->
                code.equals("target_baseline_outside_contract_range")
                    || (metadata.targetBaselineDeclared()
                        && code.equals("api_target_stability_missing")));
  }

  private static boolean stableCapabilityDeclarationRejected(
      AppApiCompatibilityMetadata metadata,
      PlatformApiContractVerifier.CompatibilityVerificationResult verification) {
    if (metadata.targetStability() != AppApiCompatibilityMetadata.TargetStability.STABLE) {
      return false;
    }
    return verification.findings().stream()
        .map(PlatformApiContractVerifier.CompatibilityFinding::code)
        .anyMatch(
            code ->
                code.equals("unknown_manifest_permission")
                    || code.equals("unknown_optional_capability"));
  }
}
