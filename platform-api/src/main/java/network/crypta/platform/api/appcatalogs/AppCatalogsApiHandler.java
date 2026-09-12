package network.crypta.platform.api.appcatalogs;

import java.io.IOException;
import java.lang.reflect.Method;
import java.net.URI;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Supplier;
import network.crypta.platform.api.PlatformApiAppAdmission;
import network.crypta.platform.api.PlatformApiException;
import network.crypta.platform.api.PlatformApiParameters;
import network.crypta.platform.api.appupdates.CatalogSourceSwitchConsent;
import network.crypta.platform.appcatalog.AppCatalogChangelog;
import network.crypta.platform.appcatalog.AppCatalogCompatibilityMetadata;
import network.crypta.platform.appcatalog.AppCatalogEntry;
import network.crypta.platform.appcatalog.AppCatalogException;
import network.crypta.platform.appcatalog.AppCatalogInstallPlan;
import network.crypta.platform.appcatalog.AppCatalogKeyRotationPlan;
import network.crypta.platform.appcatalog.AppCatalogKeyRotationStatus;
import network.crypta.platform.appcatalog.AppCatalogMaintenanceMetadata.BackupRestoreSupport;
import network.crypta.platform.appcatalog.AppCatalogMaintenanceMetadata.DataSchemaPolicy;
import network.crypta.platform.appcatalog.AppCatalogMaintenanceMetadata.DeprecationPolicy;
import network.crypta.platform.appcatalog.AppCatalogMaintenanceMetadata.MigrationPolicy;
import network.crypta.platform.appcatalog.AppCatalogMaintenanceMetadata.SecurityPolicy;
import network.crypta.platform.appcatalog.AppCatalogMaintenanceMetadata.SupportLevel;
import network.crypta.platform.appcatalog.AppCatalogMaintenanceMetadata;
import network.crypta.platform.appcatalog.AppCatalogManager;
import network.crypta.platform.appcatalog.AppCatalogMirror;
import network.crypta.platform.appcatalog.AppCatalogMirrorHealth;
import network.crypta.platform.appcatalog.AppCatalogMirrorId;
import network.crypta.platform.appcatalog.AppCatalogOriginContext;
import network.crypta.platform.appcatalog.AppCatalogProductionMetadata;
import network.crypta.platform.appcatalog.AppCatalogReviewMetadata;
import network.crypta.platform.appcatalog.AppCatalogRollbackCandidate;
import network.crypta.platform.appcatalog.AppCatalogSecurityAdvisory;
import network.crypta.platform.appcatalog.AppCatalogSecurityDecision;
import network.crypta.platform.appcatalog.AppCatalogSecurityPolicy;
import network.crypta.platform.appcatalog.AppCatalogSecurityStatus;
import network.crypta.platform.appcatalog.AppCatalogSourceSnapshot;
import network.crypta.platform.appcatalog.AppCatalogVerifiedRevision;
import network.crypta.platform.appcatalog.AppCatalogVersionDenylistEntry;
import network.crypta.platform.appcatalog.AppReviewPolicy;
import network.crypta.platform.appcatalog.AppReviewReceipt;
import network.crypta.platform.appcatalog.AppReviewReceiptVerifier;
import network.crypta.platform.appcatalog.AppReviewTransparencyEventKind;
import network.crypta.platform.appcatalog.AppReviewTransparencyLog;
import network.crypta.platform.appcatalog.AppReviewTransparencyQuery;
import network.crypta.platform.appcatalog.AppReviewTransparencyVerificationResult;
import network.crypta.platform.appcatalog.AppReviewTrustDecision;
import network.crypta.platform.appcatalog.CatalogPublisherAuthorizationException;
import network.crypta.platform.appcatalog.CatalogScopedReviewerPolicy;
import network.crypta.platform.appcatalog.RecommendedAppCatalog;
import network.crypta.platform.appcatalog.RecommendedAppCatalogs;
import network.crypta.platform.appcatalog.TrustedReviewerKeySummary;
import network.crypta.platform.appcatalog.TrustedReviewerKeys;
import network.crypta.platform.appcatalog.TrustedReviewerKeysLoader;
import network.crypta.platform.appcatalog.TrustedReviewerRegistrySummary;
import network.crypta.platform.appdist.AppApiCompatibilityMetadata;
import network.crypta.platform.appdist.AppDataNamespaceSchema;
import network.crypta.platform.appdist.AppDataSchemaContract;
import network.crypta.platform.apphost.AppBundleVerificationException;
import network.crypta.platform.apphost.AppHost;
import network.crypta.platform.apphost.AppHostException;
import network.crypta.platform.apphost.InstalledAppOrigin;
import network.crypta.platform.apphost.InstalledAppSnapshot;
import network.crypta.platform.apphost.RunningAppSnapshot;
import network.crypta.platform.apphost.manifest.AppManifest;
import network.crypta.platform.apphost.manifest.AppManifestParser;
import network.crypta.platform.appui.AppUiPaths;
import network.crypta.platform.appvault.AppVaultException;
import network.crypta.platform.appvault.AppVaultService;

/**
 * Signed app-catalog endpoint family for Platform API v1.
 *
 * <p>The handler exposes catalog source management, catalog app listing, and install/update actions
 * while preserving the existing local staged-directory app routes. Catalog install and update first
 * obtain a verified temporary stage from {@link AppCatalogManager}, then call the same AppHost
 * methods used by the local app API. That keeps bundle verification and mutable directory semantics
 * centralized in AppHost.
 *
 * <p>Instances are transport-neutral. The router supplies decoded path and query values, and this
 * class returns JSON-compatible maps and lists that the shared Platform API JSON writer can encode.
 * Catalog failures stay expressed with stable machine-readable catalog codes, while AppHost
 * failures are translated to the same app lifecycle contracts used by local install and update
 * endpoints. The handler does not keep mutable request state; the shared {@link AppCatalogManager}
 * and {@link AppHost} own persistence, staging, and lifecycle decisions.
 */
public final class AppCatalogsApiHandler {
  private static final System.Logger LOG = System.getLogger(AppCatalogsApiHandler.class.getName());
  private static final PreparedPlanConsentVerifier NO_PREPARED_PLAN_CONSENT_VERIFIER = (_, _) -> {};

  private static final String APP_ALREADY_INSTALLED_PREFIX = "app already installed: ";
  private static final String APP_NOT_INSTALLED_PREFIX = "app is not installed: ";
  private static final String CANNOT_UPDATE_RUNNING_APP_PREFIX = "cannot update a running app: ";
  private static final String INSTALL_FAILED_MESSAGE = "Failed to install catalog app.";
  private static final String UPDATE_FAILED_MESSAGE = "Failed to update catalog app.";
  private static final String SOURCE_SWITCH_CONSENT_PARAMETER = "sourceSwitchConsent";
  private static final String INVALID_APP_BUNDLE_ERROR_CODE = "invalid_app_bundle";
  private static final String APPHOST_BUNDLE_VALIDATION_MESSAGE =
      "Catalog app bundle failed AppHost validation.";
  private static final String VERSION_STATUS_NOT_INSTALLED = "not_installed";
  private static final String VERSION_STATUS_INSTALLED = "installed";
  private static final String VERSION_STATUS_CURRENT = "current";
  private static final String VERSION_STATUS_DIFFERENT = "different";
  private static final String VERSION_STATUS_UNKNOWN = "unknown";
  private static final String VERSION_FIELD = "version";
  private static final String CONFIGURED_FIELD = "configured";
  private static final String COMPATIBILITY_NOT_DECLARED = "not_declared";
  private static final String COMPATIBILITY_SATISFIED = "satisfied";
  private static final String COMPATIBILITY_NOT_SATISFIED = "not_satisfied";
  private static final String COMPATIBILITY_UNKNOWN = "unknown";
  private static final String SOURCE_FIELD = "source";
  private static final String SOURCE_TYPE_FIELD = "sourceType";
  private static final String SOURCE_KIND_FIELD = "sourceKind";
  private static final String CATALOG_ID_FIELD = "catalogId";
  private static final String APP_ID_FIELD = "appId";
  private static final String API_COMPATIBILITY_FIELD = "apiCompatibility";
  private static final String REDACTED_FIELD = "redacted";
  private static final String REDACTED_VALUE = "<redacted>";
  private static final String REMOVED_FIELD = "removed";
  private static final String SIGNATURE_KEY_ID_FIELD = "signatureKeyId";
  private static final String MIRROR_ID_FIELD = "mirrorId";
  private static final String MIRROR_VALUE = "mirror";
  private static final String PRIORITY_FIELD = "priority";
  private static final String ENABLED_FIELD = "enabled";
  private static final String REVISION_DIGEST_FIELD = "revisionDigest";
  private static final String REASON_FIELD = "reason";
  private static final String INSTALLED_FIELD = VERSION_STATUS_INSTALLED;
  private static final String INSTALLED_VERSION_FIELD = "installedVersion";
  private static final String LAST_ATTEMPT_AT_FIELD = "lastAttemptAt";
  private static final String LAST_SUCCESSFUL_REFRESH_AT_FIELD = "lastSuccessfulRefreshAt";
  private static final String LAST_FETCH_STATUS_FIELD = "lastFetchStatus";
  private static final String LAST_FETCH_ERROR_CODE_FIELD = "lastFetchErrorCode";
  private static final String LAST_FETCH_ERROR_MESSAGE_FIELD = "lastFetchErrorMessage";
  private static final String LAST_RESOLVED_URI_FIELD = "lastResolvedUri";
  private static final String FETCH_STATUS_SUCCESS = "success";
  private static final String FIELD_WARNINGS = "warnings";
  private static final String VAULT_GRANT_CLEANUP_WARNING =
      "Vault grant cleanup failed and requires operator review.";
  private static final String PARAM_REVIEW_ACKNOWLEDGED = "reviewAcknowledged";
  private static final String PARAM_SECURITY_ACKNOWLEDGED = "securityAcknowledged";
  private static final String REVIEW_TRUST_FIELD = "reviewTrust";
  private static final String SECURITY_DECISION_FIELD = "securityDecision";
  private static final String BLOCKS_INSTALL_FIELD = "blocksInstall";
  private static final String BLOCKS_UPDATE_FIELD = "blocksUpdate";
  private static final String REVIEWER_KEY_ID_FIELD = "reviewerKeyId";
  private static final String STATUS_FIELD = "status";
  private static final String SUMMARY_FIELD = "summary";
  private static final String ADVISORY_FIELD = "advisory";
  private static final String REPLACEMENT_APP_ID_FIELD = "replacementAppId";
  private static final String SAFE_UNINSTALL_GUIDANCE_FIELD = "safeUninstallGuidance";
  private static final String REVIEWER_REGISTRY_COUNTS_FIELD = "counts";
  private static final String REVIEWER_REVOKED_COUNT_FIELD = "revoked";
  private static final String ERROR_APP_REVIEW_MISSING = "app_review_missing";
  private static final String ERROR_APP_REVIEW_UNTRUSTED = "app_review_untrusted";
  private static final String ERROR_APP_REVIEW_REJECTED = "app_review_rejected";
  private static final String ERROR_APP_REVIEW_MISMATCH = "app_review_mismatch";
  private static final String ERROR_APP_REVIEW_EXPIRED = "app_review_expired";
  private static final String ERROR_APP_SECURITY_ACKNOWLEDGEMENT_REQUIRED =
      "app_security_acknowledgement_required";
  private static final String ERROR_APP_SECURITY_BLOCKED = "app_security_blocked";
  private static final String ERROR_APP_SECURITY_DENYLISTED = "app_security_denylisted";
  private static final String ERROR_APP_DATA_MIGRATION_LIFECYCLE_REQUIRED =
      "app_data_migration_lifecycle_required";
  private static final String ERROR_RECOMMENDED_CATALOG_NOT_FOUND = "recommended_catalog_not_found";
  private static final String ERROR_RECOMMENDED_CATALOG_ALREADY_CONFIGURED =
      "recommended_catalog_already_configured";
  private static final String ERROR_RECOMMENDED_CATALOG_SOURCE_MISSING =
      "recommended_catalog_source_missing";
  private static final String ERROR_RECOMMENDED_CATALOG_TRUSTED_KEY_MISSING =
      "recommended_catalog_trusted_key_missing";
  private static final String ERROR_RECOMMENDED_CATALOG_INVALID_CONFIGURATION =
      "recommended_catalog_invalid_configuration";
  private static final String MISSING_SOURCE_CONFIGURATION = "source";
  private static final String MISSING_TRUSTED_CATALOG_KEY_CONFIGURATION = "trusted_catalog_key";

  private final AppCatalogManager catalogManager;
  private final AppHost appHost;
  private final Supplier<String> currentCryptaVersionSupplier;
  private final AppReviewPolicy reviewPolicy;
  private final ReviewerKeysProvider reviewerKeysProvider;
  private final AppVaultService appVaultService;
  private final Supplier<List<RecommendedAppCatalog>> recommendedCatalogsSupplier;
  private CatalogScopedReviewerPolicy catalogScopedReviewerPolicy;
  private PreparedPlanConflictVerifier preparedPlanConflictVerifier;
  private PreparedPlanPolicyAuthorizer preparedPlanPolicyAuthorizer;

  /**
   * Creates a handler backed by a catalog manager and shared AppHost.
   *
   * <p>The supplied catalog manager is expected to use the same trusted-key policy as the AppHost
   * verification policy for PR-195. The handler performs no global lookup and does not cache
   * trusted keys itself, which lets runtime composition reload key material between requests when
   * configured to do so.
   *
   * @param catalogManager signed catalog manager owned by runtime composition
   * @param appHost shared AppHost used for final install and update operations
   */
  @SuppressWarnings("unused")
  public AppCatalogsApiHandler(AppCatalogManager catalogManager, AppHost appHost) {
    this(catalogManager, appHost, () -> null);
  }

  /**
   * Creates a handler backed by a catalog manager, AppHost, and node-version supplier.
   *
   * <p>The version supplier is used only for advisory compatibility metadata in read responses. It
   * is not involved in catalog signature verification, artifact staging, or install/update
   * decisions.
   *
   * @param catalogManager signed catalog manager owned by runtime composition
   * @param appHost shared AppHost used for final install and update operations
   * @param currentCryptaVersionSupplier current node version supplier for compatibility display
   */
  public AppCatalogsApiHandler(
      AppCatalogManager catalogManager,
      AppHost appHost,
      Supplier<String> currentCryptaVersionSupplier) {
    this(catalogManager, appHost, currentCryptaVersionSupplier, null);
  }

  /**
   * Creates a handler backed by catalog services and optional vault lifecycle integration.
   *
   * @param catalogManager signed catalog manager owned by runtime composition
   * @param appHost shared AppHost used for final install and update operations
   * @param currentCryptaVersionSupplier current node version supplier for compatibility display
   * @param appVaultService optional app-vault service used to disable grants after permission
   *     removal
   */
  public AppCatalogsApiHandler(
      AppCatalogManager catalogManager,
      AppHost appHost,
      Supplier<String> currentCryptaVersionSupplier,
      AppVaultService appVaultService) {
    this(
        catalogManager,
        appHost,
        currentCryptaVersionSupplier,
        AppReviewPolicy.loadFromSystem(),
        trustedReviewerKeysFromSystem(),
        appVaultService);
  }

  /**
   * Creates a handler with explicit review policy and reviewer-key provider.
   *
   * @param catalogManager signed catalog manager owned by runtime composition
   * @param appHost shared AppHost used for final install and update operations
   * @param currentCryptaVersionSupplier current node version supplier for compatibility display
   * @param reviewPolicy local review policy for install/update gates
   * @param reviewerKeysProvider provider for trusted reviewer keys
   */
  public AppCatalogsApiHandler(
      AppCatalogManager catalogManager,
      AppHost appHost,
      Supplier<String> currentCryptaVersionSupplier,
      AppReviewPolicy reviewPolicy,
      ReviewerKeysProvider reviewerKeysProvider) {
    this(
        catalogManager,
        appHost,
        currentCryptaVersionSupplier,
        reviewPolicy,
        reviewerKeysProvider,
        null);
  }

  /**
   * Creates a handler with explicit review policy, reviewer-key provider, and optional vault.
   *
   * @param catalogManager signed catalog manager owned by runtime composition
   * @param appHost shared AppHost used for final install and update operations
   * @param currentCryptaVersionSupplier current node version supplier for compatibility display
   * @param reviewPolicy local review policy for install/update gates
   * @param reviewerKeysProvider provider for trusted reviewer keys
   * @param appVaultService optional app-vault service used to disable grants after permission
   *     removal
   */
  public AppCatalogsApiHandler(
      AppCatalogManager catalogManager,
      AppHost appHost,
      Supplier<String> currentCryptaVersionSupplier,
      AppReviewPolicy reviewPolicy,
      ReviewerKeysProvider reviewerKeysProvider,
      AppVaultService appVaultService) {
    this(
        catalogManager,
        appHost,
        currentCryptaVersionSupplier,
        reviewPolicy,
        reviewerKeysProvider,
        appVaultService,
        RecommendedAppCatalogs::fromSystem);
  }

  /**
   * Creates a handler with explicit recommendation and review collaborators.
   *
   * <p>Tests and controlled embeddings use this constructor to provide deterministic recommended
   * catalog descriptors without relying on process-wide system properties. Runtime composition
   * normally uses {@link RecommendedAppCatalogs#fromSystem()} through the shorter constructors.
   *
   * @param catalogManager signed catalog manager owned by runtime composition
   * @param appHost shared AppHost used for final install and update operations
   * @param currentCryptaVersionSupplier current node version supplier for compatibility display
   * @param reviewPolicy local review policy for install/update gates
   * @param reviewerKeysProvider provider for trusted reviewer keys
   * @param appVaultService optional app-vault service used to disable grants after permission
   *     removal
   * @param recommendedCatalogsSupplier supplier for configured recommended catalog descriptors
   */
  public AppCatalogsApiHandler(
      AppCatalogManager catalogManager,
      AppHost appHost,
      Supplier<String> currentCryptaVersionSupplier,
      AppReviewPolicy reviewPolicy,
      ReviewerKeysProvider reviewerKeysProvider,
      AppVaultService appVaultService,
      Supplier<List<RecommendedAppCatalog>> recommendedCatalogsSupplier) {
    this.catalogManager = Objects.requireNonNull(catalogManager, "catalogManager");
    this.appHost = Objects.requireNonNull(appHost, "appHost");
    this.currentCryptaVersionSupplier =
        Objects.requireNonNull(currentCryptaVersionSupplier, "currentCryptaVersionSupplier");
    this.reviewPolicy = Objects.requireNonNull(reviewPolicy, "reviewPolicy");
    this.reviewerKeysProvider =
        Objects.requireNonNull(reviewerKeysProvider, "reviewerKeysProvider");
    this.appVaultService = appVaultService;
    this.recommendedCatalogsSupplier =
        Objects.requireNonNull(recommendedCatalogsSupplier, "recommendedCatalogsSupplier");
  }

  private static ReviewerKeysProvider trustedReviewerKeysFromSystem() {
    return TrustedReviewerKeysLoader::loadFromSystem;
  }

  /** Supplies trusted reviewer keys for independent review-receipt checks. */
  @FunctionalInterface
  public interface ReviewerKeysProvider {
    /**
     * Returns local trusted reviewer keys.
     *
     * @return trusted reviewer registry
     * @throws IOException if configured key material cannot be read
     */
    TrustedReviewerKeys trustedReviewerKeys() throws IOException;
  }

  /** Verifies consent against a prepared catalog plan entry before install or update commits. */
  @FunctionalInterface
  public interface PreparedPlanConsentVerifier {
    /**
     * Verifies that the prepared plan entry still matches the approved operator consent snapshot.
     *
     * @param catalogId catalog identifier attached to the prepared plan
     * @param entry prepared catalog entry
     */
    void verify(String catalogId, AppCatalogEntry entry);
  }

  /** Applies the shared exact-subject federation conflict authority to a prepared plan. */
  @FunctionalInterface
  public interface PreparedPlanConflictVerifier {
    /**
     * Rejects a prepared plan unless the current complete catalog subject set permits it.
     *
     * @param plan exact retained catalog plan proposed for mutation
     * @param installed current installed snapshot, or {@code null} when it could not be inspected
     * @param explicitSourceSwitchAuthorized whether exact source-switch consent was verified
     */
    void verify(
        AppCatalogInstallPlan plan,
        InstalledAppSnapshot installed,
        boolean explicitSourceSwitchAuthorized);
  }

  /** Retains conflict, publisher, and reviewer policy through a prepared AppHost mutation. */
  @FunctionalInterface
  public interface PreparedPlanPolicyAuthorizer {
    /**
     * Revalidates and retains all non-catalog policy for the exact target origin.
     *
     * @param plan exact retained catalog plan proposed for mutation
     * @param installed current installed snapshot, or {@code null} for a new installation
     * @param targetOrigin exact provenance AppHost will commit with the bundle
     * @param explicitSourceSwitchAuthorized whether exact source-switch consent was verified
     * @return composite lease retained through durable host commit or compensation
     * @throws IOException if the local policy cannot be read or retained
     */
    AppHost.CatalogMutationAuthorizationLease authorize(
        AppCatalogInstallPlan plan,
        InstalledAppSnapshot installed,
        InstalledAppOrigin targetOrigin,
        boolean explicitSourceSwitchAuthorized)
        throws IOException;
  }

  /** Applies the same host-owned reviewer-scope policy used by lifecycle updates. */
  public void setCatalogScopedReviewerPolicy(CatalogScopedReviewerPolicy policy) {
    this.catalogScopedReviewerPolicy = Objects.requireNonNull(policy, "policy");
  }

  /** Supplies the same digest-bound conflict authority used by lifecycle catalog updates. */
  public void setPreparedPlanConflictVerifier(PreparedPlanConflictVerifier verifier) {
    this.preparedPlanConflictVerifier = Objects.requireNonNull(verifier, "verifier");
  }

  /** Supplies conflict, publisher, and reviewer authorization retained through direct commits. */
  public void setPreparedPlanPolicyAuthorizer(PreparedPlanPolicyAuthorizer authorizer) {
    this.preparedPlanPolicyAuthorizer = Objects.requireNonNull(authorizer, "authorizer");
  }

  /**
   * Lists configured catalog sources.
   *
   * <p>Every stored catalog is re-read through the manager, which re-verifies the persisted catalog
   * sidecars before exposing metadata. A corrupt or no-longer-trusted catalog therefore returns a
   * catalog error instead of stale cached data.
   *
   * @return JSON-compatible catalog source summaries in manager-defined order
   */
  public List<Map<String, Object>> listCatalogs() {
    try {
      return catalogManager.listCatalogs().stream().map(this::summarizeCatalog).toList();
    } catch (AppCatalogException exception) {
      throw catalogFailure(exception);
    } catch (IOException _) {
      throw internalError("Failed to list app catalogs.");
    }
  }

  /**
   * Lists operator-visible recommended catalog descriptors.
   *
   * <p>This read path does not fetch remote catalog bytes and does not mutate configured sources.
   * It combines the recommendation provider with the current configured-catalog ids and trusted-key
   * hints so the Web Shell can show whether the first-party beta onboarding card is ready to add,
   * already configured, or missing runtime configuration.
   *
   * @return JSON-compatible recommended catalog summaries
   */
  public List<Map<String, Object>> listRecommendedCatalogs() {
    List<RecommendedAppCatalog> recommendedCatalogs = recommendedCatalogs();
    try {
      Set<String> configuredIds = configuredCatalogIds();
      return recommendedCatalogs.stream()
          .map(recommended -> summarizeRecommendedCatalog(recommended, configuredIds))
          .toList();
    } catch (AppCatalogException exception) {
      throw catalogFailure(exception);
    } catch (IOException _) {
      throw internalError("Failed to list recommended app catalogs.");
    }
  }

  /**
   * Adds one recommended catalog through the verified signed-catalog path.
   *
   * <p>The method never installs apps. It checks that the recommendation exists, has a configured
   * source, has its trusted catalog key hint present in the current trusted-key registry, and is
   * not already configured. The final mutation delegates to {@link
   * AppCatalogManager#addSource(String, String)}, which fetches and verifies the signed catalog
   * before persisting it and enforces that the authenticated catalog id matches the selected
   * recommendation.
   *
   * @param catalogId recommended catalog id from the request path
   * @return JSON-compatible summary for the newly stored and verified catalog
   */
  public Map<String, Object> addRecommended(String catalogId) {
    RecommendedAppCatalog recommended = recommendedCatalog(catalogId);
    if (recommended.sourceDisplayUri().isEmpty()) {
      throw new PlatformApiException(
          400,
          ERROR_RECOMMENDED_CATALOG_SOURCE_MISSING,
          "Recommended catalog source is not configured.");
    }
    try {
      if (configuredCatalogIds().contains(recommended.catalogId())) {
        throw new PlatformApiException(
            409,
            ERROR_RECOMMENDED_CATALOG_ALREADY_CONFIGURED,
            "Recommended catalog is already configured.");
      }
      if (!trustedCatalogKeyConfigured(recommended)) {
        throw new PlatformApiException(
            400,
            ERROR_RECOMMENDED_CATALOG_TRUSTED_KEY_MISSING,
            "Recommended catalog trusted key is not configured.");
      }
      return summarizeCatalog(
          catalogManager.addSource(
              recommended.sourceDisplayUri().orElseThrow(), recommended.catalogId()));
    } catch (AppCatalogException exception) {
      throw catalogFailure(exception);
    } catch (IOException _) {
      throw internalError("Failed to add recommended app catalog.");
    }
  }

  /**
   * Adds a signed catalog source and returns the verified catalog summary.
   *
   * <p>The {@code source} parameter may name a local file, a {@code file:} URI, an HTTPS URI, or a
   * loopback HTTP URI accepted by the catalog source policy. Adding is intentionally eager: the
   * source is fetched, its signature is checked, the catalog is parsed, and only then is the source
   * persisted.
   *
   * @param queryParameters decoded request query or form parameters containing {@code source}
   * @return JSON-compatible summary for the newly stored and verified catalog
   */
  public Map<String, Object> add(Map<String, List<String>> queryParameters) {
    String source = PlatformApiParameters.requireString(queryParameters, SOURCE_FIELD);
    String expectedCatalogId =
        PlatformApiParameters.readOptionalString(queryParameters, "expectedCatalogId");
    try {
      return summarizeCatalog(
          expectedCatalogId == null
              ? catalogManager.addSource(source)
              : catalogManager.addSource(source, expectedCatalogId));
    } catch (AppCatalogException exception) {
      throw catalogFailure(exception);
    } catch (IOException _) {
      throw internalError("Failed to add app catalog.");
    }
  }

  private List<RecommendedAppCatalog> recommendedCatalogs() {
    try {
      return List.copyOf(recommendedCatalogsSupplier.get());
    } catch (AppCatalogException _) {
      throw new PlatformApiException(
          400,
          ERROR_RECOMMENDED_CATALOG_INVALID_CONFIGURATION,
          "Recommended catalog configuration is invalid.");
    }
  }

  private RecommendedAppCatalog recommendedCatalog(String catalogId) {
    String normalizedCatalogId;
    try {
      normalizedCatalogId =
          network.crypta.platform.appcatalog.AppCatalog.normalizeCatalogId(catalogId);
    } catch (AppCatalogException _) {
      throw recommendedCatalogNotFound();
    }
    return recommendedCatalogs().stream()
        .filter(recommended -> recommended.catalogId().equals(normalizedCatalogId))
        .findFirst()
        .orElseThrow(AppCatalogsApiHandler::recommendedCatalogNotFound);
  }

  private static PlatformApiException recommendedCatalogNotFound() {
    return new PlatformApiException(
        404, ERROR_RECOMMENDED_CATALOG_NOT_FOUND, "Recommended catalog not found.");
  }

  private Set<String> configuredCatalogIds() throws IOException {
    return Set.copyOf(catalogManager.configuredCatalogIds());
  }

  private Map<String, Object> summarizeRecommendedCatalog(
      RecommendedAppCatalog recommended, Set<String> configuredCatalogIds) {
    boolean configured = configuredCatalogIds.contains(recommended.catalogId());
    boolean trustedCatalogKeyConfigured = trustedCatalogKeyConfigured(recommended);
    List<String> missingConfiguration =
        missingRecommendedCatalogConfiguration(recommended, trustedCatalogKeyConfigured);
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(14);
    json.put(CATALOG_ID_FIELD, recommended.catalogId());
    json.put("name", recommended.name());
    json.put("description", recommended.description());
    json.put("channel", recommended.channel());
    json.put("defaultEntryChannel", "stable");
    json.put("availableEntryChannels", List.of("stable", "beta", "nightly", "deprecated"));
    json.put(SOURCE_KIND_FIELD, recommended.sourceKind().orElse(null));
    json.put(SOURCE_FIELD, redactedRecommendedSource(recommended));
    json.put("sourceConfigured", recommended.configured());
    json.put(CONFIGURED_FIELD, configured);
    json.put("trustedCatalogKeyId", recommended.trustedCatalogKeyId().orElse(null));
    json.put("trustedCatalogKeyConfigured", trustedCatalogKeyConfigured);
    json.put("reviewerPolicyHint", recommended.reviewerPolicyHint().orElse(null));
    json.put("canAdd", !configured && missingConfiguration.isEmpty());
    json.put("missingConfiguration", missingConfiguration);
    json.put(FIELD_WARNINGS, recommendedWarnings(configured, missingConfiguration));
    return json;
  }

  private boolean trustedCatalogKeyConfigured(RecommendedAppCatalog recommended) {
    Optional<String> trustedCatalogKeyId = recommended.trustedCatalogKeyId();
    if (trustedCatalogKeyId.isEmpty()) {
      return false;
    }
    try {
      return catalogManager.hasTrustedCatalogKey(trustedCatalogKeyId.orElseThrow());
    } catch (AppCatalogException | IOException _) {
      return false;
    }
  }

  private static List<String> missingRecommendedCatalogConfiguration(
      RecommendedAppCatalog recommended, boolean trustedCatalogKeyConfigured) {
    ArrayList<String> missing = new ArrayList<>(2);
    if (recommended.sourceDisplayUri().isEmpty()) {
      missing.add(MISSING_SOURCE_CONFIGURATION);
    }
    if (!trustedCatalogKeyConfigured) {
      missing.add(MISSING_TRUSTED_CATALOG_KEY_CONFIGURATION);
    }
    return List.copyOf(missing);
  }

  private static List<String> recommendedWarnings(boolean configured, List<String> missing) {
    ArrayList<String> warnings = new ArrayList<>();
    if (configured) {
      warnings.add(ERROR_RECOMMENDED_CATALOG_ALREADY_CONFIGURED);
    }
    for (String missingItem : missing) {
      warnings.add("missing_" + missingItem);
    }
    return List.copyOf(warnings);
  }

  private static String redactedRecommendedSource(RecommendedAppCatalog recommended) {
    Optional<String> source = recommended.sourceDisplayUri();
    if (source.isEmpty()) {
      return null;
    }
    Optional<String> sourceKind = recommended.sourceKind();
    if (sourceKind.isPresent() && "crypta".equals(sourceKind.orElseThrow())) {
      return "crypta:<configured>";
    }
    if (sourceKind.isPresent() && "file".equals(sourceKind.orElseThrow())) {
      return "file:<configured>";
    }
    URI uri = URI.create(source.orElseThrow());
    if (uri.getQuery() == null) {
      return uri.toString();
    }
    try {
      return new URI(
              uri.getScheme(),
              null,
              uri.getHost(),
              uri.getPort(),
              uri.getPath(),
              REDACTED_VALUE,
              null)
          .toString();
    } catch (java.net.URISyntaxException _) {
      return uri.getScheme() + "://<configured>";
    }
  }

  /**
   * Removes one configured catalog source.
   *
   * <p>Removal deletes the locally configured source record and cached catalog sidecars. It does
   * not uninstall apps that were previously installed from that catalog, because installed app
   * lifecycle remains owned by the app endpoints.
   *
   * @param catalogId catalog identifier from the request path
   * @return JSON-compatible removal summary containing the requested id and removal flag
   */
  public Map<String, Object> remove(String catalogId) {
    try {
      catalogManager.remove(catalogId);
      LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(2);
      json.put(CATALOG_ID_FIELD, catalogId);
      json.put(REMOVED_FIELD, true);
      return json;
    } catch (AppCatalogException exception) {
      throw catalogFailure(exception);
    } catch (IOException _) {
      throw internalError("Failed to remove app catalog.");
    }
  }

  /**
   * Refreshes one configured catalog source.
   *
   * <p>Refresh reuses the stored source URI, fetches fresh catalog sidecars, verifies the
   * signature, and rejects the result if the authenticated catalog id no longer matches the
   * configured id. A failed refresh leaves the previous stored sidecars in place.
   *
   * @param catalogId catalog identifier from the request path
   * @return JSON-compatible summary for the refreshed catalog
   */
  public Map<String, Object> refresh(String catalogId) {
    try {
      return summarizeCatalog(catalogManager.refresh(catalogId));
    } catch (AppCatalogException exception) {
      throw catalogFailure(exception);
    } catch (IOException _) {
      throw internalError("Failed to refresh app catalog.");
    }
  }

  /** Refreshes only the primary catalog source, without using mirrors as fallback transports. */
  public Map<String, Object> refreshPrimaryOnly(String catalogId) {
    try {
      return summarizeCatalog(catalogManager.refreshPrimaryOnly(catalogId));
    } catch (AppCatalogException exception) {
      throw catalogFailure(exception);
    } catch (IOException _) {
      throw internalError("Failed to refresh primary app catalog source.");
    }
  }

  /** Returns source and mirror health for one catalog. */
  public Map<String, Object> health(String catalogId) {
    try {
      AppCatalogSourceSnapshot snapshot = catalogById(catalogId);
      List<AppCatalogMirrorHealth> health = catalogManager.sourceHealth(catalogId);
      AppCatalogMirrorHealth activeHealth =
          latestSuccessfulHealth(health).orElseGet(health::getFirst);
      LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(11);
      json.put(CATALOG_ID_FIELD, snapshot.catalogId());
      json.put(STATUS_FIELD, lastFetchStatus(snapshot));
      json.put("primarySource", sourceHealthEntry(health.getFirst()));
      json.put("sourceHealth", health.stream().map(this::sourceHealthEntry).toList());
      json.put(
          "mirrors",
          catalogManager.listMirrors(catalogId).stream().map(this::summarizeMirror).toList());
      json.put("fallbackUsed", fallbackUsed(health));
      json.put("activeSourceId", activeHealth.id().value());
      json.put("verifiedRevision", activeHealth.lastCatalogDigest().orElse(null));
      json.put("catalogDigest", activeHealth.lastCatalogDigest().orElse(null));
      json.put(SIGNATURE_KEY_ID_FIELD, snapshot.signatureKeyId().orElse(null));
      json.put(REDACTED_FIELD, true);
      return json;
    } catch (AppCatalogException exception) {
      throw catalogFailure(exception);
    } catch (IOException _) {
      throw internalError("Failed to read app catalog health.");
    }
  }

  /** Lists mirrors for one catalog. */
  public Map<String, Object> mirrors(String catalogId) {
    try {
      LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(3);
      json.put(CATALOG_ID_FIELD, catalogId);
      json.put(
          "mirrors",
          catalogManager.listMirrors(catalogId).stream().map(this::summarizeMirror).toList());
      json.put(REDACTED_FIELD, true);
      return json;
    } catch (AppCatalogException exception) {
      throw catalogFailure(exception);
    } catch (IOException _) {
      throw internalError("Failed to list catalog mirrors.");
    }
  }

  /** Adds one mirror to a catalog. */
  public Map<String, Object> addMirror(
      String catalogId, Map<String, List<String>> queryParameters) {
    String source = PlatformApiParameters.requireString(queryParameters, SOURCE_FIELD);
    String mirrorId = PlatformApiParameters.readOptionalString(queryParameters, MIRROR_ID_FIELD);
    int priority = optionalPositivePriority(queryParameters);
    boolean enabled = PlatformApiParameters.readBoolean(queryParameters, ENABLED_FIELD, true);
    try {
      AppCatalogMirror mirror =
          catalogManager.addMirror(catalogId, mirrorId, source, priority, enabled);
      LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(3);
      json.put(CATALOG_ID_FIELD, catalogId);
      json.put(MIRROR_VALUE, summarizeMirror(mirror));
      json.put(REDACTED_FIELD, true);
      return json;
    } catch (AppCatalogException exception) {
      throw catalogFailure(exception);
    } catch (IOException _) {
      throw internalError("Failed to add catalog mirror.");
    }
  }

  /** Updates one catalog mirror. */
  public Map<String, Object> updateMirror(
      String catalogId, String mirrorId, Map<String, List<String>> queryParameters) {
    String source = PlatformApiParameters.readOptionalString(queryParameters, SOURCE_FIELD);
    Integer priority = optionalPriority(queryParameters);
    Boolean enabled = PlatformApiParameters.readOptionalBoolean(queryParameters, ENABLED_FIELD);
    try {
      AppCatalogMirror mirror =
          catalogManager.updateMirror(catalogId, mirrorId, source, priority, enabled);
      LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(3);
      json.put(CATALOG_ID_FIELD, catalogId);
      json.put(MIRROR_VALUE, summarizeMirror(mirror));
      json.put(REDACTED_FIELD, true);
      return json;
    } catch (AppCatalogException exception) {
      throw catalogFailure(exception);
    } catch (IOException _) {
      throw internalError("Failed to update catalog mirror.");
    }
  }

  /** Removes one catalog mirror. */
  public Map<String, Object> removeMirror(String catalogId, String mirrorId) {
    try {
      catalogManager.removeMirror(catalogId, mirrorId);
      LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(4);
      json.put(CATALOG_ID_FIELD, catalogId);
      json.put(MIRROR_ID_FIELD, mirrorId);
      json.put(REMOVED_FIELD, true);
      json.put(REDACTED_FIELD, true);
      return json;
    } catch (AppCatalogException exception) {
      throw catalogFailure(exception);
    } catch (IOException _) {
      throw internalError("Failed to remove catalog mirror.");
    }
  }

  /** Lists catalog rollback candidates. */
  public Map<String, Object> rollbackCandidates(String catalogId) {
    try {
      LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(3);
      json.put(CATALOG_ID_FIELD, catalogId);
      json.put(
          "revisions",
          catalogManager.rollbackCandidates(catalogId).stream()
              .map(this::summarizeRollbackCandidate)
              .toList());
      json.put(REDACTED_FIELD, true);
      return json;
    } catch (AppCatalogException exception) {
      throw catalogFailure(exception);
    } catch (IOException _) {
      throw internalError("Failed to list catalog rollback candidates.");
    }
  }

  /** Executes catalog rollback to a retained verified revision. */
  public Map<String, Object> rollback(String catalogId, Map<String, List<String>> queryParameters) {
    String revisionDigest =
        PlatformApiParameters.requireString(queryParameters, REVISION_DIGEST_FIELD);
    String reason = PlatformApiParameters.readOptionalString(queryParameters, REASON_FIELD);
    String normalizedReason = normalizedRollbackReason(reason);
    try {
      LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(5);
      json.put(CATALOG_ID_FIELD, catalogId);
      json.put("rolledBack", true);
      json.put(
          "catalog", summarizeCatalog(catalogManager.rollback(catalogId, revisionDigest, reason)));
      json.put(REASON_FIELD, normalizedReason);
      json.put(REDACTED_FIELD, true);
      return json;
    } catch (AppCatalogException exception) {
      throw catalogFailure(exception);
    } catch (IOException _) {
      throw internalError("Failed to roll back app catalog.");
    }
  }

  /** Returns catalog signing-key rotation status. */
  public Map<String, Object> keyRotationStatus(String catalogId) {
    try {
      return summarizeKeyRotation(catalogManager.keyRotationStatus(catalogId));
    } catch (AppCatalogException exception) {
      throw catalogFailure(exception);
    } catch (IOException _) {
      throw internalError("Failed to read catalog key rotation status.");
    }
  }

  /** Runs an emergency advisory refresh through the normal signed-catalog gates. */
  public Map<String, Object> emergencyRefresh(String catalogId) {
    try {
      AppCatalogSecurityPolicy beforePolicy = securityPolicyOrEmpty(catalogId);
      AppCatalogSourceSnapshot after = catalogManager.emergencyRefresh(catalogId);
      AppCatalogSecurityPolicy afterPolicy = catalogManager.securityPolicy(catalogId);
      List<AppCatalogMirrorHealth> health = catalogManager.sourceHealth(catalogId);
      LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(9);
      json.put(CATALOG_ID_FIELD, after.catalogId());
      json.put(STATUS_FIELD, lastFetchStatus(after));
      json.put("activeSourceId", activeSourceId(health));
      json.put("fallbackUsed", fallbackUsed(health));
      json.put(
          REVISION_DIGEST_FIELD,
          latestSuccessfulHealth(health)
              .flatMap(AppCatalogMirrorHealth::lastCatalogDigest)
              .orElse(null));
      json.put("advisoryIdsAdded", advisoryIdsAdded(beforePolicy, afterPolicy));
      json.put("denylistEntriesAdded", denylistEntriesAdded(beforePolicy, afterPolicy));
      json.put(LAST_ATTEMPT_AT_FIELD, after.lastAttemptAt().toString());
      json.put(REDACTED_FIELD, true);
      return json;
    } catch (AppCatalogException exception) {
      throw catalogFailure(exception);
    } catch (IOException _) {
      throw internalError("Failed to run emergency catalog refresh.");
    }
  }

  private AppCatalogSecurityPolicy securityPolicyOrEmpty(String catalogId) throws IOException {
    try {
      return catalogManager.securityPolicy(catalogId);
    } catch (AppCatalogException _) {
      return AppCatalogSecurityPolicy.EMPTY;
    }
  }

  /**
   * Lists apps in one catalog.
   *
   * <p>The response preserves the catalog-declared app order and adds local AppHost state for each
   * entry. Bundle URI, digest, and size metadata remain visible so operators can inspect what a
   * catalog would download before installing or updating.
   *
   * @param catalogId catalog identifier from the request path
   * @return JSON-compatible app entries enriched with local installed/running state
   */
  public List<Map<String, Object>> listApps(String catalogId) {
    try {
      return catalogManager.listApps(catalogId).stream()
          .map(entry -> summarizeEntry(catalogId, entry))
          .toList();
    } catch (AppCatalogException exception) {
      throw catalogFailure(exception);
    } catch (IOException _) {
      throw internalError("Failed to list catalog apps.");
    }
  }

  /**
   * Describes one app in a catalog.
   *
   * <p>The app id is resolved through the verified catalog, not directly through AppHost. That
   * keeps {@code app_not_found} distinct from an installed-app lookup failure and lets callers
   * inspect a catalog entry even when the app is not installed locally.
   *
   * @param catalogId catalog identifier from the request path
   * @param appId catalog app identifier from the request path
   * @return JSON-compatible app entry enriched with local installed/running state
   */
  public Map<String, Object> getApp(String catalogId, String appId) {
    try {
      return summarizeEntry(catalogId, catalogManager.getApp(catalogId, appId));
    } catch (AppCatalogException exception) {
      throw catalogFailure(exception);
    } catch (IOException _) {
      throw internalError("Failed to read catalog app.");
    }
  }

  /**
   * Returns catalog app metadata for update consent without blocking corrupt-install repair.
   *
   * <p>The catalog update mutation intentionally allows AppHost to repair an installed app whose
   * manifest is unreadable by applying a valid signed catalog bundle. Consent preview and
   * validation must preserve that repair path, so this summary is conservative when the installed
   * manifest cannot be read: it avoids exposing the raw failure, treats the app as locally present
   * with an unknown version, and reports catalog permissions as added.
   *
   * @param catalogId catalog identifier from the request path
   * @param appId catalog app identifier from the request path
   * @return JSON-compatible app entry suitable for catalog update consent
   */
  public Map<String, Object> getAppForCatalogUpdateConsent(String catalogId, String appId) {
    try {
      return summarizeEntry(catalogId, catalogManager.getApp(catalogId, appId), true);
    } catch (AppCatalogException exception) {
      throw catalogFailure(exception);
    } catch (IOException _) {
      throw internalError("Failed to read catalog app.");
    }
  }

  /**
   * Summarizes a prepared catalog plan entry for a final consent digest check.
   *
   * <p>The installation/update routes call this after the catalog manager has downloaded and
   * verified the candidate bundle. The resulting summary uses the same redacted, path-free shape as
   * catalog preview responses so the consent layer can reject stale approvals when prepared
   * metadata no longer matches the operator-reviewed snapshot.
   *
   * @param catalogId catalog identifier attached to the prepared plan
   * @param entry prepared catalog entry
   * @param tolerateInstalledReadFailure whether corrupt installed manifests should remain
   *     repairable through update
   * @return path-free catalog entry summary suitable for consent digesting
   */
  public Map<String, Object> summarizePreparedPlanForConsent(
      String catalogId, AppCatalogEntry entry, boolean tolerateInstalledReadFailure) {
    return summarizeEntry(catalogId, entry, tolerateInstalledReadFailure);
  }

  /**
   * Returns redacted app-review governance state.
   *
   * @return review policy, reviewer registry, and transparency-log status
   */
  public Map<String, Object> governance() {
    TrustedReviewerKeys keys = trustedReviewerKeysOrEmpty();
    AppReviewTransparencyLog log = reviewTransparencyLog();
    AppReviewTransparencyVerificationResult verification = log.verify();
    LinkedHashMap<String, Object> transparency = LinkedHashMap.newLinkedHashMap(4);
    transparency.put(CONFIGURED_FIELD, log.configured());
    transparency.put("recordCount", log.recordCount());
    transparency.put("latestRecordHash", log.latestRecordHash());
    transparency.put("verified", verification.verified());
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(3);
    json.put("reviewPolicyMode", reviewPolicy.mode().jsonValue());
    json.put("trustedReviewerRegistry", keys.summary().toJsonValue());
    json.put("transparencyLog", transparency);
    return json;
  }

  /**
   * Returns redacted trusted-reviewer key summaries.
   *
   * @return reviewer-key list and registry summary
   */
  public Map<String, Object> reviewerKeys() {
    TrustedReviewerKeys keys = trustedReviewerKeysOrEmpty();
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(2);
    json.put(
        "keys", keys.summaries().stream().map(TrustedReviewerKeySummary::toJsonValue).toList());
    json.put("registry", keys.summary().toJsonValue());
    return json;
  }

  /**
   * Returns a compact operator-facing security response summary.
   *
   * <p>The summary aggregates signed catalog security-policy metadata with local reviewer
   * governance counts. It intentionally exposes only bounded advisory ids, exact app versions,
   * catalog signing key ids, reviewer lifecycle counts, and recovery labels. It does not include
   * raw catalog bytes, signatures, public key bytes, private keys, catalog sources, local store
   * paths, staged bundle paths, raw receipt bodies, or fetched content.
   *
   * @return safe security response state for operator dashboard and Web Shell rendering
   */
  public Map<String, Object> securityResponseSummary() {
    try {
      List<AppCatalogSourceSnapshot> catalogs = catalogManager.listCatalogs();
      ArrayList<Map<String, Object>> activeAdvisories = new ArrayList<>();
      ArrayList<Map<String, Object>> denylistedVersions = new ArrayList<>();
      ArrayList<Map<String, Object>> catalogSigningKeys = new ArrayList<>();
      for (AppCatalogSourceSnapshot snapshot : catalogs) {
        AppCatalogSecurityPolicy policy = catalogManager.securityPolicy(snapshot.catalogId());
        activeAdvisories.addAll(securityResponseAdvisories(snapshot.catalogId(), policy));
        denylistedVersions.addAll(securityResponseDenylist(snapshot.catalogId(), policy));
        catalogSigningKeys.add(securityResponseCatalogKey(snapshot));
      }
      TrustedReviewerRegistrySummary registry = trustedReviewerKeysOrEmpty().summary();
      Map<String, Object> registryJson = registry.toJsonValue();
      int revokedReviewerKeys = revokedReviewerCount(registryJson);
      int revokedReceipts = registry.receiptRevocationCount();

      Map<String, Object> securityDrills = securityDrillsReadinessSummary();
      LinkedHashMap<String, Object> summary = LinkedHashMap.newLinkedHashMap(11);
      summary.put("activeAdvisoryCount", activeAdvisories.size());
      summary.put("denylistedVersionCount", denylistedVersions.size());
      summary.put("installedVulnerableAppCount", "unavailable");
      summary.put("revokedReviewerKeyCount", revokedReviewerKeys);
      summary.put("revokedReceiptCount", revokedReceipts);
      summary.put("catalogSigningKeyCount", catalogSigningKeys.size());
      summary.put(
          "catalogKeyRotationStatus",
          catalogSigningKeys.stream().anyMatch(key -> key.get("keyId") == null)
              ? VERSION_STATUS_UNKNOWN
              : CONFIGURED_FIELD);
      summary.put(
          "emergencyReplacementGuidanceAvailable",
          emergencyReplacementGuidanceAvailable(activeAdvisories, denylistedVersions));
      summary.put("supportRedactionStatus", "required");
      summary.put("securityDrillsStatus", securityDrills.get(STATUS_FIELD));
      summary.put("securityDrillsLastStatus", securityDrills.get("lastStatus"));

      LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(8);
      json.put(
          STATUS_FIELD,
          securityResponseStatus(
              activeAdvisories, denylistedVersions, revokedReviewerKeys, revokedReceipts));
      json.put(SUMMARY_FIELD, summary);
      json.put("activeAdvisories", List.copyOf(activeAdvisories));
      json.put("denylistedVersions", List.copyOf(denylistedVersions));
      json.put("reviewerGovernance", registryJson);
      json.put("catalogSigningKeys", List.copyOf(catalogSigningKeys));
      json.put("securityDrills", securityDrills);
      json.put("operatorActions", securityResponseOperatorActions());
      json.put("supportGuidance", "Use redacted support bundle preview before sharing evidence.");
      return json;
    } catch (AppCatalogException exception) {
      throw catalogFailure(exception);
    } catch (IOException _) {
      throw internalError("Failed to read app catalog security response state.");
    }
  }

  /**
   * Returns one bounded transparency-log page.
   *
   * @param queryParameters decoded query parameters
   * @return redacted transparency page
   */
  public Map<String, Object> transparencyLog(Map<String, List<String>> queryParameters) {
    return reviewTransparencyLog().page(transparencyQuery(queryParameters)).toJsonValue();
  }

  /**
   * Verifies the local transparency-log hash chain.
   *
   * @return redacted verification result
   */
  public Map<String, Object> verifyTransparencyLog() {
    return reviewTransparencyLog().verify().toJsonValue();
  }

  private static List<Map<String, Object>> securityResponseAdvisories(
      String catalogId, AppCatalogSecurityPolicy policy) {
    return policy.advisories().stream()
        .filter(AppCatalogsApiHandler::securityResponseAdvisoryIsCurrent)
        .map(advisory -> securityResponseAdvisory(catalogId, advisory.toJsonValue()))
        .toList();
  }

  private static boolean securityResponseAdvisoryIsCurrent(
      network.crypta.platform.appcatalog.AppCatalogSecurityAdvisoryRecord advisory) {
    return advisory.status() == AppCatalogSecurityStatus.ACTIVE
        || advisory.status() == AppCatalogSecurityStatus.PUBLISHED;
  }

  private static Map<String, Object> securityResponseAdvisory(
      String catalogId, Map<String, Object> advisory) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(12);
    json.put(CATALOG_ID_FIELD, catalogId);
    json.put("id", advisory.get("id"));
    json.put("title", advisory.get("title"));
    json.put("severity", advisory.get("severity"));
    json.put(STATUS_FIELD, advisory.get(STATUS_FIELD));
    json.put("action", advisory.get("action"));
    json.put(SUMMARY_FIELD, advisory.get(SUMMARY_FIELD));
    json.put("publishedAt", advisory.get("publishedAt"));
    json.put("updatedAt", advisory.get("updatedAt"));
    json.put(REPLACEMENT_APP_ID_FIELD, advisory.get(REPLACEMENT_APP_ID_FIELD));
    json.put(SAFE_UNINSTALL_GUIDANCE_FIELD, advisory.get(SAFE_UNINSTALL_GUIDANCE_FIELD));
    json.put("uri", advisory.get("uri"));
    return json;
  }

  private static List<Map<String, Object>> securityResponseDenylist(
      String catalogId, AppCatalogSecurityPolicy policy) {
    return policy.denylist().stream()
        .map(entry -> securityResponseDenylistEntry(catalogId, entry.toJsonValue()))
        .toList();
  }

  private static boolean emergencyReplacementGuidanceAvailable(
      List<Map<String, Object>> activeAdvisories, List<Map<String, Object>> denylistedVersions) {
    return activeAdvisories.stream()
            .anyMatch(advisory -> nonEmptyString(advisory.get(REPLACEMENT_APP_ID_FIELD)))
        || denylistedVersions.stream()
            .anyMatch(denylist -> nonEmptyString(denylist.get(REPLACEMENT_APP_ID_FIELD)));
  }

  private static Map<String, Object> securityResponseDenylistEntry(
      String catalogId, Map<String, Object> denylistEntry) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(8);
    json.put(CATALOG_ID_FIELD, catalogId);
    json.put("id", denylistEntry.get("id"));
    json.put(APP_ID_FIELD, denylistEntry.get(APP_ID_FIELD));
    json.put(VERSION_FIELD, denylistEntry.get(VERSION_FIELD));
    json.put("advisoryId", denylistEntry.get("advisoryId"));
    json.put(REASON_FIELD, denylistEntry.get(REASON_FIELD));
    json.put(REPLACEMENT_APP_ID_FIELD, denylistEntry.get(REPLACEMENT_APP_ID_FIELD));
    json.put(SAFE_UNINSTALL_GUIDANCE_FIELD, denylistEntry.get(SAFE_UNINSTALL_GUIDANCE_FIELD));
    return json;
  }

  private static Map<String, Object> securityResponseCatalogKey(AppCatalogSourceSnapshot snapshot) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(4);
    json.put(CATALOG_ID_FIELD, snapshot.catalogId());
    json.put("keyId", snapshot.signatureKeyId().orElse(null));
    json.put(
        "rotationStatus",
        snapshot.signatureKeyId().isPresent() ? VERSION_STATUS_CURRENT : VERSION_STATUS_UNKNOWN);
    json.put("lastVerifiedAt", snapshot.lastSuccessfulRefreshAt().toString());
    return json;
  }

  private static String securityResponseStatus(
      List<Map<String, Object>> activeAdvisories,
      List<Map<String, Object>> denylistedVersions,
      int revokedReviewerKeys,
      int revokedReceipts) {
    if (!denylistedVersions.isEmpty()) {
      return "denylist_active";
    }
    if (!activeAdvisories.isEmpty()) {
      return "advisory_active";
    }
    if (revokedReviewerKeys > 0 || revokedReceipts > 0) {
      return "reviewer_revocation_active";
    }
    return "clear";
  }

  private static int revokedReviewerCount(Map<String, Object> registryJson) {
    Object counts = registryJson.get(REVIEWER_REGISTRY_COUNTS_FIELD);
    if (counts instanceof Map<?, ?> map) {
      Object value = map.get(REVIEWER_REVOKED_COUNT_FIELD);
      if (value instanceof Number number) {
        return number.intValue();
      }
    }
    return 0;
  }

  private static List<Map<String, Object>> securityResponseOperatorActions() {
    return List.of(
        securityResponseAction("refresh-catalog", "Refresh affected catalog"),
        securityResponseAction("review-governance", "Inspect reviewer governance"),
        securityResponseAction("support-bundle-preview", "Create redacted support preview"),
        securityResponseAction("export-before-uninstall", "Export before uninstall"));
  }

  private static Map<String, Object> securityResponseAction(String id, String label) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(2);
    json.put("id", id);
    json.put("label", label);
    return json;
  }

  private static Map<String, Object> securityDrillsReadinessSummary() {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(8);
    json.put(STATUS_FIELD, "release_artifact_required");
    json.put("lastStatus", "not_loaded");
    json.put("summaryAvailable", false);
    json.put("promotionReady", false);
    json.put("requiredScenarioCount", 7);
    json.put("redactionStatus", "not_loaded");
    json.put("artifactKind", "cryptad-security-response-drills-summary");
    json.put(
        SUMMARY_FIELD,
        "Release certification verifies security drills from redacted artifacts; no raw drill"
            + " artifacts are uploaded to this node.");
    return json;
  }

  private static boolean nonEmptyString(Object value) {
    return value instanceof String text && !text.isBlank();
  }

  /**
   * Returns review history for one catalog app.
   *
   * @param catalogId catalog identifier
   * @param appId app identifier
   * @return current review metadata, local trust decision, reviewer summary, and log records
   */
  public Map<String, Object> reviewHistory(String catalogId, String appId) {
    try {
      AppCatalogEntry entry = catalogManager.getApp(catalogId, appId);
      AppReviewTrustDecision decision = reviewTrust(entry);
      AppReviewTransparencyQuery query =
          new AppReviewTransparencyQuery(
              AppReviewTransparencyQuery.DEFAULT_LIMIT, null, entry.appId(), catalogId, null, null);
      LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(7);
      json.put(CATALOG_ID_FIELD, catalogId);
      json.put(APP_ID_FIELD, entry.appId());
      json.put("catalogVersion", entry.version());
      json.put(INSTALLED_VERSION_FIELD, installedVersion(entry.appId()));
      json.put("review", summarizeReview(entry.review()));
      json.put(REVIEW_TRUST_FIELD, reviewTrustSummary(catalogId, entry, decision));
      json.put("reviewerKey", reviewerKeySummary(decision.reviewerKeyId()));
      json.put("transparencyLog", reviewTransparencyLog().page(query).toJsonValue());
      json.put("trustDelta", reviewTrustDelta(entry, decision));
      return json;
    } catch (AppCatalogException exception) {
      throw catalogFailure(exception);
    } catch (IOException _) {
      throw internalError("Failed to read catalog app review history.");
    }
  }

  /**
   * Installs one catalog app through AppHost.
   *
   * <p>The method first confirms that the catalog entry exists and that the app is not already
   * installed. It then asks the manager to download, digest-check, extract, and verify the signed
   * bundle before delegating the final copy into the managed app tree to AppHost. Scratch cleanup
   * runs after the mutation and is logged if it fails so cleanup trouble does not mask a committed
   * installation.
   *
   * @param catalogId catalog identifier from the request path
   * @param appId catalog app identifier from the request path
   * @return installed app summary without launch tokens or staging paths
   */
  public Map<String, Object> install(String catalogId, String appId) {
    return install(catalogId, appId, Map.of());
  }

  /**
   * Installs one catalog app through AppHost with optional review acknowledgement.
   *
   * @param catalogId catalog identifier from the request path
   * @param appId catalog app identifier from the request path
   * @param queryParameters decoded request query parameters
   * @return installed app summary without launch tokens or staging paths
   */
  public Map<String, Object> install(
      String catalogId, String appId, Map<String, List<String>> queryParameters) {
    return install(catalogId, appId, queryParameters, NO_PREPARED_PLAN_CONSENT_VERIFIER);
  }

  /**
   * Validates the fast catalog-install state preconditions without preparing or installing a
   * bundle.
   *
   * <p>Consent-gated transport routes call this before asking for approval so impossible
   * installations retain the same conflict and catalog lookup errors as the mutation path. The full
   * {@link #install(String, String, Map, PreparedPlanConsentVerifier)} method rechecks these
   * conditions before it mutates state.
   *
   * @param catalogId catalog identifier from the request path
   * @param appId catalog app identifier from the request path
   */
  public void requireInstallPreconditions(String catalogId, String appId) {
    try {
      AppCatalogEntry entry = catalogManager.getApp(catalogId, appId);
      if (appHost.describe(entry.appId()).isPresent()) {
        throw conflict(APP_ALREADY_INSTALLED_PREFIX + entry.appId());
      }
      requireScopedReviewerAuthorization(catalogId, entry);
    } catch (AppCatalogException exception) {
      throw catalogFailure(exception);
    } catch (IOException _) {
      throw internalError(INSTALL_FAILED_MESSAGE);
    }
  }

  /**
   * Installs one catalog app with optional acknowledgement and prepared-plan consent verification.
   *
   * @param catalogId catalog identifier from the request path
   * @param appId catalog app identifier from the request path
   * @param queryParameters decoded request query parameters
   * @param preparedPlanConsentVerifier verifier invoked after bundle preparation and before install
   * @return installed app summary without launch tokens or staging paths
   */
  public Map<String, Object> install(
      String catalogId,
      String appId,
      Map<String, List<String>> queryParameters,
      PreparedPlanConsentVerifier preparedPlanConsentVerifier) {
    Objects.requireNonNull(preparedPlanConsentVerifier, "preparedPlanConsentVerifier");
    String normalizedAppId;
    AppReviewTrustDecision initialReviewTrust;
    AppCatalogSecurityDecision initialSecurityDecision;
    boolean reviewAcknowledged = reviewAcknowledged(queryParameters);
    boolean securityAcknowledged = securityAcknowledged(queryParameters);
    try {
      AppCatalogEntry entry = catalogManager.getApp(catalogId, appId);
      normalizedAppId = entry.appId();
      if (appHost.describe(normalizedAppId).isPresent()) {
        throw conflict(APP_ALREADY_INSTALLED_PREFIX + normalizedAppId);
      }
      initialSecurityDecision = targetSecurityDecision(catalogId, entry);
      requireSecurityGate(initialSecurityDecision, securityAcknowledged, true);
      initialReviewTrust = reviewTrust(entry);
      requireScopedReviewerAuthorization(catalogId, entry);
      recordReviewGate(
          AppReviewTransparencyEventKind.REVIEW_GATE_INSTALL,
          catalogId,
          entry,
          initialReviewTrust,
          reviewAcknowledged,
          "catalog_entry");
      requireReviewGate(initialReviewTrust, reviewAcknowledged, true);
    } catch (AppCatalogException exception) {
      throw catalogFailure(exception);
    } catch (IOException _) {
      throw internalError(INSTALL_FAILED_MESSAGE);
    }
    AppCatalogInstallPlan plan = null;
    try {
      plan = catalogManager.prepareInstallPlan(catalogId, normalizedAppId);
      preparedPlanConsentVerifier.verify(plan.catalogId(), plan.entry());
      AppCatalogSecurityDecision preparedSecurityDecision =
          targetSecurityDecision(plan.catalogId(), plan.entry());
      requireSecurityGate(
          preparedSecurityDecision,
          securityAcknowledgementStillApplies(
              initialSecurityDecision, preparedSecurityDecision, securityAcknowledged),
          true);
      AppReviewTrustDecision preparedReviewTrust = reviewTrust(plan.entry());
      requireScopedReviewerAuthorization(plan.catalogId(), plan.entry());
      recordReviewGate(
          AppReviewTransparencyEventKind.REVIEW_GATE_INSTALL,
          catalogId,
          plan.entry(),
          preparedReviewTrust,
          reviewAcknowledged,
          "prepared_plan");
      requireReviewGate(
          preparedReviewTrust,
          reviewAcknowledgementStillApplies(
              initialReviewTrust, preparedReviewTrust, reviewAcknowledged),
          true);
      catalogManager.verifyInstallPlan(plan);
      requirePlatformApiAdmission(plan);
      InstalledAppOrigin origin = catalogOrigin(plan, preparedReviewTrust);
      InstalledAppSnapshot installed =
          origin == null
              ? appHost.installFromDirectory(plan.stagedBundleDirectory())
              : appHost.installCatalogFromDirectory(
                  plan.stagedBundleDirectory(),
                  origin,
                  catalogMutationAuthorization(plan, null, false));
      return summarizeInstalledApp(installed.manifest());
    } catch (AppCatalogException exception) {
      throw catalogFailure(exception);
    } catch (AppHostException exception) {
      throw installFailure(exception);
    } catch (CatalogPublisherAuthorizationException _) {
      throw publisherScopeConflict();
    } catch (IOException _) {
      throw internalError(INSTALL_FAILED_MESSAGE);
    } finally {
      cleanUpPlan(plan);
    }
  }

  /**
   * Builds a path-free, digest-bound preview for switching an installed app's catalog or publisher.
   *
   * <p>The preview performs the normal catalog download and publisher verification but does not
   * mutate AppHost, local trust, or catalog state. The returned consent digest commits the exact
   * current origin and target catalog revision, bundle, publisher, and trust policy. A later change
   * invalidates it deterministically.
   *
   * @param catalogId proposed target catalog
   * @param appId installed app to inspect
   * @return operator-safe source-switch preview
   */
  public Map<String, Object> sourceSwitchPreview(String catalogId, String appId) {
    if (!catalogManager.federationEnabled()) {
      throw new PlatformApiException(
          503,
          "catalog_federation_unavailable",
          "Federated catalog trust is not enabled on this node.");
    }
    AppCatalogInstallPlan plan = null;
    try {
      plan = catalogManager.prepareInstallPlan(catalogId, appId);
      catalogManager.verifyInstallPlan(plan);
      AppManifest targetManifest = requirePlatformApiAdmission(plan);
      CatalogSourceSwitchConsent.Decision decision = sourceSwitchDecision(plan);
      LinkedHashMap<String, Object> preview = new LinkedHashMap<>();
      preview.put(APP_ID_FIELD, plan.entry().appId());
      preview.put("currentCatalogId", decision.currentOrigin().catalogId());
      preview.put("targetCatalogId", plan.catalogId());
      preview.put("targetVersion", plan.entry().version());
      preview.put("targetBundleSha256", plan.entry().bundleSha256());
      preview.put("targetPublisherKeyId", plan.bundleVerification().publisherKeyId());
      preview.put(
          "targetPublisherFingerprintSha256",
          plan.bundleVerification().publisherKeyFingerprintSha256());
      preview.put("catalogSwitch", decision.catalogSwitch());
      preview.put("publisherSwitch", decision.publisherSwitch());
      preview.put("requiresExplicitConsent", decision.requiresExplicitConsent());
      preview.put("currentOriginDigestSha256", decision.currentOrigin().selfDigestSha256());
      preview.put("targetCatalogTrustDigestSha256", decision.target().trustBindingDigestSha256());
      preview.put("targetPublisherPolicyDigestSha256", decision.targetPublisherPolicyDigest());
      preview.put("consentDigestSha256", decision.consentDigestSha256());
      preview.put("backupAndMigrationChecksRequired", decision.requiresExplicitConsent());
      preview.put(
          API_COMPATIBILITY_FIELD,
          PlatformApiAppAdmission.summarizeAdmission(
              targetManifest.apiCompatibility(), targetManifest.permissions()));
      return preview;
    } catch (AppCatalogException exception) {
      throw catalogFailure(exception);
    } catch (CatalogPublisherAuthorizationException _) {
      throw publisherScopeConflict();
    } catch (IOException _) {
      throw internalError("Source-switch preview could not be prepared.");
    } finally {
      cleanUpPlan(plan);
    }
  }

  private static PlatformApiException publisherScopeConflict() {
    return new PlatformApiException(
        409,
        "catalog_publisher_scope_rejected",
        "Current local publisher scope does not authorize this catalog operation.");
  }

  private SourceSwitchAuthorization requireSourceSwitchConsent(
      AppCatalogInstallPlan plan, Map<String, List<String>> queryParameters) throws IOException {
    if (!isFederationScoped(plan)) {
      return SourceSwitchAuthorization.withoutCurrentOrigin();
    }
    Optional<InstalledAppOrigin> current = appHost.catalogOrigin(plan.entry().appId());
    if (current.isEmpty()) {
      return SourceSwitchAuthorization.withoutCurrentOrigin();
    }
    CatalogSourceSwitchConsent.Decision decision =
        sourceSwitchDecision(plan, current.orElseThrow());
    if (!decision.requiresExplicitConsent()) {
      return SourceSwitchAuthorization.forCurrentOrigin(current.orElseThrow());
    }
    String supplied =
        PlatformApiParameters.readOptionalString(queryParameters, SOURCE_SWITCH_CONSENT_PARAMETER);
    if (!decision.consentDigestSha256().equals(supplied)) {
      throw new PlatformApiException(
          409,
          "catalog_source_switch_consent_required",
          "Catalog or publisher source switching requires an exact operator preview and consent.");
    }
    return SourceSwitchAuthorization.forCurrentOrigin(current.orElseThrow(), true);
  }

  private CatalogSourceSwitchConsent.Decision sourceSwitchDecision(AppCatalogInstallPlan plan)
      throws IOException {
    InstalledAppOrigin current =
        appHost
            .catalogOrigin(plan.entry().appId())
            .orElseThrow(
                () ->
                    new PlatformApiException(
                        409,
                        "catalog_origin_not_found",
                        "Installed catalog origin is required for source-switch preview."));
    return sourceSwitchDecision(plan, current);
  }

  private CatalogSourceSwitchConsent.Decision sourceSwitchDecision(
      AppCatalogInstallPlan plan, InstalledAppOrigin current) {
    try {
      return CatalogSourceSwitchConsent.evaluate(plan, current);
    } catch (IllegalArgumentException _) {
      throw new PlatformApiException(
          409,
          "catalog_origin_context_missing",
          "Prepared catalog plan has no authenticated origin context.");
    }
  }

  /**
   * Updates one installed app from a catalog entry through AppHost.
   *
   * <p>The update path refuses running apps before staging remote data and fails fast when the app
   * is clearly not installed. If the installed manifest is unreadable, the method still lets
   * AppHost attempt the update so a valid catalog bundle can repair a damaged installation. The
   * staged bundle follows the same catalog digest, extraction, and signed-bundle verification path
   * as install.
   *
   * @param catalogId catalog identifier from the request path
   * @param appId catalog app identifier from the request path
   * @return updated installed app summary without launch tokens or staging paths
   */
  public Map<String, Object> update(String catalogId, String appId) {
    return update(catalogId, appId, Map.of());
  }

  /**
   * Updates one installed app from a catalog entry with optional review acknowledgement.
   *
   * @param catalogId catalog identifier from the request path
   * @param appId catalog app identifier from the request path
   * @param queryParameters decoded request query parameters
   * @return updated installed app summary without launch tokens or staging paths
   */
  public Map<String, Object> update(
      String catalogId, String appId, Map<String, List<String>> queryParameters) {
    return update(catalogId, appId, queryParameters, NO_PREPARED_PLAN_CONSENT_VERIFIER);
  }

  /**
   * Validates the fast catalog-update state preconditions without preparing or updating a bundle.
   *
   * <p>Consent-gated transport routes call this before asking for approval so impossible updates
   * retain the same running-app, missing-app, and catalog lookup errors as the mutation path. The
   * full {@link #update(String, String, Map, PreparedPlanConsentVerifier)} method rechecks these
   * conditions before it mutates state.
   *
   * @param catalogId catalog identifier from the request path
   * @param appId catalog app identifier from the request path
   */
  public void requireUpdatePreconditions(String catalogId, String appId) {
    String normalizedAppId;
    try {
      AppCatalogEntry entry = catalogManager.getApp(catalogId, appId);
      normalizedAppId = entry.appId();
      requireScopedReviewerAuthorization(catalogId, entry);
    } catch (AppCatalogException exception) {
      throw catalogFailure(exception);
    } catch (IOException _) {
      throw internalError(UPDATE_FAILED_MESSAGE);
    }
    if (appHost.status(normalizedAppId).isPresent()) {
      throw conflict(CANNOT_UPDATE_RUNNING_APP_PREFIX + normalizedAppId);
    }
    try {
      if (appHost.describe(normalizedAppId).isEmpty()) {
        throw new PlatformApiException(404, "app_not_found", "App not found.");
      }
    } catch (IOException _) {
      // Allow AppHost to repair installs whose manifest is unreadable.
    }
  }

  /**
   * Updates one installed app with optional acknowledgement and prepared-plan consent verification.
   *
   * @param catalogId catalog identifier from the request path
   * @param appId catalog app identifier from the request path
   * @param queryParameters decoded request query parameters
   * @param preparedPlanConsentVerifier verifier invoked after bundle preparation and before update
   * @return updated installed app summary without launch tokens or staging paths
   */
  public Map<String, Object> update(
      String catalogId,
      String appId,
      Map<String, List<String>> queryParameters,
      PreparedPlanConsentVerifier preparedPlanConsentVerifier) {
    Objects.requireNonNull(preparedPlanConsentVerifier, "preparedPlanConsentVerifier");
    String normalizedAppId;
    AppCatalogEntry entry;
    try {
      entry = catalogManager.getApp(catalogId, appId);
      normalizedAppId = entry.appId();
    } catch (AppCatalogException exception) {
      throw catalogFailure(exception);
    } catch (IOException _) {
      throw internalError(UPDATE_FAILED_MESSAGE);
    }
    if (appHost.status(normalizedAppId).isPresent()) {
      throw conflict(CANNOT_UPDATE_RUNNING_APP_PREFIX + normalizedAppId);
    }
    InstalledAppSnapshot installed = null;
    try {
      Optional<InstalledAppSnapshot> described = appHost.describe(normalizedAppId);
      if (described.isEmpty()) {
        throw new PlatformApiException(404, "app_not_found", "App not found.");
      }
      installed = described.orElseThrow();
    } catch (IOException _) {
      // Allow AppHost to repair installs whose manifest is unreadable.
    }
    AppReviewTrustDecision initialReviewTrust = reviewTrust(entry);
    requireScopedReviewerAuthorization(catalogId, entry);
    boolean reviewAcknowledged = reviewAcknowledged(queryParameters);
    AppCatalogSecurityDecision initialSecurityDecision = targetSecurityDecision(catalogId, entry);
    boolean securityAcknowledged = securityAcknowledged(queryParameters);
    requireSecurityGate(initialSecurityDecision, securityAcknowledged, false);
    recordReviewGate(
        AppReviewTransparencyEventKind.REVIEW_GATE_UPDATE,
        catalogId,
        entry,
        initialReviewTrust,
        reviewAcknowledged,
        "catalog_entry");
    requireReviewGate(initialReviewTrust, reviewAcknowledged, false);
    AppCatalogInstallPlan plan = null;
    try {
      plan = catalogManager.prepareInstallPlan(catalogId, normalizedAppId);
      preparedPlanConsentVerifier.verify(plan.catalogId(), plan.entry());
      SourceSwitchAuthorization sourceSwitchAuthorization =
          requireSourceSwitchConsent(plan, queryParameters);
      AppCatalogSecurityDecision preparedSecurityDecision =
          targetSecurityDecision(plan.catalogId(), plan.entry());
      requireSecurityGate(
          preparedSecurityDecision,
          securityAcknowledgementStillApplies(
              initialSecurityDecision, preparedSecurityDecision, securityAcknowledged),
          false);
      AppReviewTrustDecision preparedReviewTrust = reviewTrust(plan.entry());
      requireScopedReviewerAuthorization(plan.catalogId(), plan.entry());
      recordReviewGate(
          AppReviewTransparencyEventKind.REVIEW_GATE_UPDATE,
          catalogId,
          plan.entry(),
          preparedReviewTrust,
          reviewAcknowledged,
          "prepared_plan");
      requireReviewGate(
          preparedReviewTrust,
          reviewAcknowledgementStillApplies(
              initialReviewTrust, preparedReviewTrust, reviewAcknowledged),
          false);
      catalogManager.verifyInstallPlan(plan);
      requirePlatformApiAdmission(plan);
      requireLifecycleForSchemaChangingSourceSwitch(
          installed, plan, sourceSwitchAuthorization.explicitSwitch());
      InstalledAppOrigin origin =
          catalogOrigin(
              plan,
              preparedReviewTrust,
              sourceSwitchAuthorization.expectedCurrentOrigin().orElse(null));
      InstalledAppSnapshot updated =
          origin == null
              ? appHost.updateFromDirectory(normalizedAppId, plan.stagedBundleDirectory())
              : appHost.updateCatalogFromDirectory(
                  normalizedAppId,
                  plan.stagedBundleDirectory(),
                  origin,
                  sourceSwitchAuthorization.expectedCurrentOriginExpectation(),
                  catalogMutationAuthorization(
                      plan, installed, sourceSwitchAuthorization.explicitSwitch()));
      boolean vaultCleanupSucceeded = disableVaultGrantsRemovedByUpdate(updated);
      Map<String, Object> summary = summarizeInstalledApp(updated.manifest());
      if (!vaultCleanupSucceeded) {
        summary.put(FIELD_WARNINGS, List.of(VAULT_GRANT_CLEANUP_WARNING));
      }
      return summary;
    } catch (AppCatalogException exception) {
      throw catalogFailure(exception);
    } catch (AppHostException exception) {
      throw updateFailure(normalizedAppId, exception);
    } catch (CatalogPublisherAuthorizationException _) {
      throw publisherScopeConflict();
    } catch (IOException _) {
      throw internalError(UPDATE_FAILED_MESSAGE);
    } finally {
      cleanUpPlan(plan);
    }
  }

  private InstalledAppOrigin catalogOrigin(
      AppCatalogInstallPlan plan, AppReviewTrustDecision reviewTrust) {
    return catalogOrigin(plan, reviewTrust, null);
  }

  private AppHost.CatalogMutationAuthorization catalogMutationAuthorization(
      AppCatalogInstallPlan plan,
      InstalledAppSnapshot installed,
      boolean explicitSourceSwitchAuthorized) {
    return targetOrigin -> {
      AppCatalogManager.CatalogTrustAuthorization authorization =
          catalogManager.authorizeInstallPlanForMutation(plan);
      boolean transferred = false;
      try {
        requirePreparedPlanConflictAuthorization(plan, installed, explicitSourceSwitchAuthorized);
        AppHost.CatalogMutationAuthorizationLease scopedPolicyAuthorization =
            retainPreparedPlanPolicyAuthorization(
                plan, installed, targetOrigin, explicitSourceSwitchAuthorized);
        transferred = true;
        return () -> {
          try {
            scopedPolicyAuthorization.close();
          } finally {
            authorization.close();
          }
        };
      } finally {
        if (!transferred) {
          authorization.close();
        }
      }
    };
  }

  private AppHost.CatalogMutationAuthorizationLease retainPreparedPlanPolicyAuthorization(
      AppCatalogInstallPlan plan,
      InstalledAppSnapshot installed,
      InstalledAppOrigin targetOrigin,
      boolean explicitSourceSwitchAuthorized)
      throws IOException {
    if (!catalogManager.federationEnabled()) {
      return () -> {};
    }
    if (preparedPlanPolicyAuthorizer == null) {
      throw new PlatformApiException(
          503,
          "catalog_federation_unavailable",
          "Federated catalog publisher and reviewer policy is unavailable.");
    }
    return preparedPlanPolicyAuthorizer.authorize(
        plan, installed, targetOrigin, explicitSourceSwitchAuthorized);
  }

  private void requirePreparedPlanConflictAuthorization(
      AppCatalogInstallPlan plan,
      InstalledAppSnapshot installed,
      boolean explicitSourceSwitchAuthorized) {
    if (!catalogManager.federationEnabled()) {
      return;
    }
    if (preparedPlanConflictVerifier == null) {
      throw new PlatformApiException(
          503,
          "catalog_federation_conflict_policy_unavailable",
          "Federated catalog conflict policy is unavailable.");
    }
    preparedPlanConflictVerifier.verify(plan, installed, explicitSourceSwitchAuthorized);
  }

  private static void requireLifecycleForSchemaChangingSourceSwitch(
      InstalledAppSnapshot installed, AppCatalogInstallPlan plan, boolean explicitSwitch) {
    if (!explicitSwitch) {
      return;
    }
    AppManifest target;
    try {
      target =
          AppManifestParser.parse(
              plan.stagedBundleDirectory().resolve(AppManifestParser.MANIFEST_FILE_NAME));
    } catch (IOException _) {
      throw new PlatformApiException(
          400, INVALID_APP_BUNDLE_ERROR_CODE, "Catalog app bundle manifest is invalid.");
    }
    if (installed == null) {
      throw migrationLifecycleRequired();
    }
    if (schemaTargetsDiffer(
        installed.manifest().dataSchemaContract(), target.dataSchemaContract())) {
      throw migrationLifecycleRequired();
    }
  }

  private static AppManifest requirePlatformApiAdmission(AppCatalogInstallPlan plan) {
    AppManifest manifest;
    try {
      manifest =
          AppManifestParser.parse(
              plan.stagedBundleDirectory().resolve(AppManifestParser.MANIFEST_FILE_NAME));
    } catch (IOException _) {
      throw new PlatformApiException(
          400, INVALID_APP_BUNDLE_ERROR_CODE, "Catalog app bundle manifest is invalid.");
    }
    PlatformApiAppAdmission.requireCatalogDeclarationMatchesManifest(
        plan.entry().compatibility().apiCompatibility(), manifest.apiCompatibility());
    PlatformApiAppAdmission.requireCurrentCompatibility(
        manifest.apiCompatibility(), manifest.permissions());
    return manifest;
  }

  private static boolean schemaTargetsDiffer(
      AppDataSchemaContract installed, AppDataSchemaContract target) {
    return !Objects.equals(installed.currentSchemaVersion(), target.currentSchemaVersion())
        || !schemaTargets(installed).equals(schemaTargets(target));
  }

  private static Map<String, Integer> schemaTargets(AppDataSchemaContract contract) {
    LinkedHashMap<String, Integer> targets = new LinkedHashMap<>();
    for (AppDataNamespaceSchema namespace : contract.namespaces()) {
      targets.put(namespace.namespace(), namespace.currentSchemaVersion());
    }
    return Map.copyOf(targets);
  }

  private static PlatformApiException migrationLifecycleRequired() {
    return new PlatformApiException(
        409,
        ERROR_APP_DATA_MIGRATION_LIFECYCLE_REQUIRED,
        "Catalog source switches with changed or unreadable schema state require the app-update "
            + "stage/apply lifecycle.");
  }

  private InstalledAppOrigin catalogOrigin(
      AppCatalogInstallPlan plan,
      AppReviewTrustDecision reviewTrust,
      InstalledAppOrigin expectedCurrentOrigin) {
    AppCatalogOriginContext catalog = plan.originContext().orElse(null);
    if (catalog == null || !catalog.federationScoped() || !catalogManager.federationEnabled()) {
      return null;
    }
    String previousOriginDigest =
        expectedCurrentOrigin == null ? null : expectedCurrentOrigin.selfDigestSha256();
    String receiptFingerprint =
        plan.entry().reviewReceipt().map(AppReviewReceipt::fingerprintSha256).orElse("");
    var publisher = plan.bundleVerification();
    return InstalledAppOrigin.create(
        plan.entry().appId(),
        plan.entry().version(),
        plan.entry().bundleSha256(),
        catalog.catalogId(),
        catalog.catalogSignerKeyId(),
        catalog.catalogSignerFingerprintSha256(),
        catalog.catalogRevisionDigestSha256(),
        publisher.publisherKeyId(),
        publisher.publisherKeyFingerprintSha256(),
        publisher.signedContentDigestSha256(),
        receiptFingerprint,
        reviewTrust.status().jsonValue(),
        catalog.trustBindingId(),
        catalog.trustBindingDigestSha256(),
        publisher.authorizationPolicyDigestSha256(),
        catalog.reviewerPolicyDigestSha256(),
        Instant.now(),
        previousOriginDigest);
  }

  private boolean isFederationScoped(AppCatalogInstallPlan plan) {
    return catalogManager.federationEnabled()
        && plan.originContext().filter(AppCatalogOriginContext::federationScoped).isPresent();
  }

  private static void cleanUpPlan(AppCatalogInstallPlan plan) {
    if (plan == null) {
      return;
    }
    try {
      plan.close();
    } catch (IOException exception) {
      LOG.log(
          System.Logger.Level.WARNING, "Failed to clean catalog app scratch directory", exception);
    }
  }

  private boolean disableVaultGrantsRemovedByUpdate(InstalledAppSnapshot updated) {
    if (appVaultService == null) {
      return true;
    }
    try {
      appVaultService.disableGrantsForRemovedVaultPermissions(
          updated.appId(), new LinkedHashSet<>(updated.manifest().permissions()));
      return true;
    } catch (AppVaultException exception) {
      LOG.log(
          System.Logger.Level.WARNING,
          "Catalog update applied but vault grant cleanup failed: " + exception.errorCode());
      return false;
    }
  }

  private AppReviewTrustDecision reviewTrust(AppCatalogEntry entry) {
    return AppReviewReceiptVerifier.evaluate(
        entry, trustedReviewerKeysOrEmpty(), reviewPolicy, Instant.now());
  }

  private Map<String, Object> reviewTrustSummary(String catalogId, AppCatalogEntry entry) {
    return reviewTrustSummary(catalogId, entry, reviewTrust(entry));
  }

  private Map<String, Object> reviewTrustSummary(
      String catalogId, AppCatalogEntry entry, AppReviewTrustDecision decision) {
    if (catalogScopedReviewerPolicy == null) {
      if (!catalogManager.federationEnabled()) {
        return decision.toJsonValue();
      }
      LinkedHashMap<String, Object> unavailable = new LinkedHashMap<>(decision.toJsonValue());
      unavailable.put("federationScopeAuthorized", false);
      unavailable.put("federationScopeStatus", "reviewer_scope_policy_unavailable");
      unavailable.put("reviewerScopeId", null);
      unavailable.put("reviewerScopeDigestSha256", null);
      unavailable.put("trusted", false);
      unavailable.put("positive", false);
      unavailable.put(BLOCKS_INSTALL_FIELD, true);
      unavailable.put(BLOCKS_UPDATE_FIELD, true);
      unavailable.put("blocksPolicyApply", true);
      return java.util.Collections.unmodifiableMap(unavailable);
    }
    try {
      CatalogScopedReviewerPolicy.Verification scoped =
          catalogScopedReviewerPolicy.evaluate(
              catalogId, entry, trustedReviewerKeysOrEmpty(), reviewPolicy, Instant.now());
      LinkedHashMap<String, Object> json = new LinkedHashMap<>(decision.toJsonValue());
      json.put("federationScopeAuthorized", scoped.authorized());
      json.put("federationScopeStatus", scoped.status());
      json.put("reviewerScopeId", scoped.scopeId().isBlank() ? null : scoped.scopeId());
      json.put(
          "reviewerScopeDigestSha256",
          scoped.scopeDigestSha256().isBlank() ? null : scoped.scopeDigestSha256());
      if (!scoped.authorized()) {
        json.put("trusted", false);
        json.put("positive", false);
        json.put(BLOCKS_INSTALL_FIELD, true);
        json.put(BLOCKS_UPDATE_FIELD, true);
        json.put("blocksPolicyApply", true);
      }
      return java.util.Collections.unmodifiableMap(json);
    } catch (IOException _) {
      throw internalError("Local catalog reviewer scope could not be read.");
    }
  }

  private void requireScopedReviewerAuthorization(String catalogId, AppCatalogEntry entry) {
    if (catalogScopedReviewerPolicy == null) {
      if (catalogManager.federationEnabled()) {
        throw new PlatformApiException(
            503,
            "catalog_federation_unavailable",
            "Federated catalog reviewer policy is unavailable.");
      }
      return;
    }
    try {
      CatalogScopedReviewerPolicy.Verification verification =
          catalogScopedReviewerPolicy.evaluate(
              catalogId, entry, trustedReviewerKeysOrEmpty(), reviewPolicy, Instant.now());
      if (!verification.authorized()) {
        throw new PlatformApiException(
            409,
            "catalog_reviewer_scope_required",
            "The review receipt is not authorized by the local catalog reviewer scope.");
      }
    } catch (IOException _) {
      throw internalError("Local catalog reviewer scope could not be read.");
    }
  }

  private AppCatalogSecurityDecision securityDecision(String catalogId, AppCatalogEntry entry) {
    try {
      AppCatalogSecurityDecision decision =
          catalogManager.securityDecision(catalogId, entry.appId());
      return decision == null ? AppCatalogSecurityDecision.OK : decision;
    } catch (AppCatalogException exception) {
      throw catalogFailure(exception);
    } catch (IOException _) {
      throw internalError("Failed to read catalog app security policy.");
    }
  }

  private AppCatalogSecurityDecision targetSecurityDecision(
      String catalogId, AppCatalogEntry entry) {
    return AppCatalogSecurityDecision.combine(
        List.of(
            securityDecision(catalogId, entry),
            installedSecurityDecision(entry.appId(), entry.version())));
  }

  private AppCatalogSecurityDecision installedSecurityDecision(String appId, String version) {
    if (version == null || version.isBlank()) {
      return AppCatalogSecurityDecision.OK;
    }
    try {
      AppCatalogSecurityDecision decision =
          catalogManager.installedSecurityDecision(appId, version);
      return decision == null ? AppCatalogSecurityDecision.OK : decision;
    } catch (AppCatalogException exception) {
      throw catalogFailure(exception);
    } catch (IOException _) {
      throw internalError("Failed to read installed app security policy.");
    }
  }

  private void recordReviewGate(
      AppReviewTransparencyEventKind kind,
      String catalogId,
      AppCatalogEntry entry,
      AppReviewTrustDecision decision,
      boolean reviewAcknowledged,
      String phase) {
    reviewTransparencyLog()
        .recordCatalogDecision(
            kind,
            catalogId,
            entry,
            decision,
            List.of("phase=" + phase, "reviewAcknowledged=" + reviewAcknowledged));
  }

  private TrustedReviewerKeys trustedReviewerKeysOrEmpty() {
    try {
      return reviewerKeysProvider.trustedReviewerKeys();
    } catch (AppCatalogException | IOException _) {
      return TrustedReviewerKeys.empty();
    }
  }

  private AppReviewTransparencyLog reviewTransparencyLog() {
    AppReviewTransparencyLog log = catalogManager.reviewTransparencyLog();
    return log == null ? AppReviewTransparencyLog.disabled() : log;
  }

  private Map<String, Object> reviewerKeySummary(String reviewerKeyId) {
    if (reviewerKeyId == null || reviewerKeyId.isBlank()) {
      return Map.of();
    }
    return trustedReviewerKeysOrEmpty()
        .find(reviewerKeyId)
        .map(key -> TrustedReviewerKeySummary.from(key).toJsonValue())
        .orElseGet(Map::of);
  }

  private String installedVersion(String appId) {
    InstalledAppSnapshot installed = installed(appId);
    return installed == null ? null : installed.manifest().appVersion();
  }

  private Map<String, Object> reviewTrustDelta(
      AppCatalogEntry entry, AppReviewTrustDecision decision) {
    String installedVersion = installedVersion(entry.appId());
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(6);
    json.put(INSTALLED_VERSION_FIELD, installedVersion);
    json.put("catalogVersion", entry.version());
    json.put(
        "versionChanged", installedVersion != null && !installedVersion.equals(entry.version()));
    json.put(REVIEWER_KEY_ID_FIELD, decision.reviewerKeyId());
    json.put("reviewerKeyStatus", decision.reviewerKeyStatus());
    json.put("trustStatus", decision.status().jsonValue());
    json.put("policyId", decision.policyId());
    json.put("policyVersion", decision.policyVersion());
    return json;
  }

  private static AppReviewTransparencyQuery transparencyQuery(
      Map<String, List<String>> queryParameters) {
    int limit = parseLimit(PlatformApiParameters.readOptionalString(queryParameters, "limit"));
    String cursor = PlatformApiParameters.readOptionalString(queryParameters, "cursor");
    String appId = PlatformApiParameters.readOptionalString(queryParameters, APP_ID_FIELD);
    String catalogId = PlatformApiParameters.readOptionalString(queryParameters, CATALOG_ID_FIELD);
    String reviewerKeyId =
        PlatformApiParameters.readOptionalString(queryParameters, REVIEWER_KEY_ID_FIELD);
    String kindText = PlatformApiParameters.readOptionalString(queryParameters, "kind");
    AppReviewTransparencyEventKind kind = null;
    if (kindText != null && !kindText.isBlank()) {
      try {
        kind = AppReviewTransparencyEventKind.parse(kindText);
      } catch (AppCatalogException _) {
        throw new PlatformApiException(
            400, "invalid_query_parameter", "kind is not a supported transparency event kind.");
      }
    }
    return new AppReviewTransparencyQuery(limit, cursor, appId, catalogId, reviewerKeyId, kind);
  }

  private static int parseLimit(String value) {
    if (value == null || value.isBlank()) {
      return AppReviewTransparencyQuery.DEFAULT_LIMIT;
    }
    try {
      return Integer.parseInt(value.trim());
    } catch (NumberFormatException _) {
      throw new PlatformApiException(
          400, "invalid_query_parameter", "limit must be a positive integer.");
    }
  }

  private static void requireReviewGate(
      AppReviewTrustDecision decision, boolean reviewAcknowledged, boolean install) {
    Map<String, Object> reviewTrust = decision.toJsonValue();
    String blockField = install ? BLOCKS_INSTALL_FIELD : BLOCKS_UPDATE_FIELD;
    String action = install ? "Install" : "Update";
    if (Boolean.TRUE.equals(reviewTrust.get(blockField))) {
      throw new PlatformApiException(
          409, reviewGateFailureCode(reviewTrust), action + " blocked by app review policy.");
    }
    if (Boolean.TRUE.equals(reviewTrust.get("requiresAcknowledgement")) && !reviewAcknowledged) {
      throw new PlatformApiException(
          409,
          reviewGateFailureCode(reviewTrust),
          action + " requires explicit acknowledgement of the review trust decision.");
    }
  }

  private static void requireSecurityGate(
      AppCatalogSecurityDecision decision, boolean securityAcknowledged, boolean install) {
    Map<String, Object> securityDecision = decision.toJsonValue();
    String action = install ? "Install" : "Update";
    if (ERROR_APP_SECURITY_DENYLISTED.equals(securityGateFailureCode(securityDecision))) {
      throw new PlatformApiException(
          409, ERROR_APP_SECURITY_DENYLISTED, action + " blocked by app security denylist.");
    }
    String blockField = install ? BLOCKS_INSTALL_FIELD : BLOCKS_UPDATE_FIELD;
    if (Boolean.TRUE.equals(securityDecision.get(blockField))) {
      throw new PlatformApiException(
          409, ERROR_APP_SECURITY_BLOCKED, action + " blocked by app security policy.");
    }
    if (Boolean.TRUE.equals(securityDecision.get("requiresAcknowledgement"))
        && !securityAcknowledged) {
      throw new PlatformApiException(
          409,
          ERROR_APP_SECURITY_ACKNOWLEDGEMENT_REQUIRED,
          action + " requires explicit acknowledgement of the security advisory.");
    }
  }

  private static boolean reviewAcknowledgementStillApplies(
      AppReviewTrustDecision initialDecision,
      AppReviewTrustDecision preparedDecision,
      boolean reviewAcknowledged) {
    return reviewAcknowledged && initialDecision.equals(preparedDecision);
  }

  private static boolean securityAcknowledgementStillApplies(
      AppCatalogSecurityDecision initialDecision,
      AppCatalogSecurityDecision preparedDecision,
      boolean securityAcknowledged) {
    return securityAcknowledged && initialDecision.equals(preparedDecision);
  }

  private static String securityGateFailureCode(Map<String, Object> securityDecision) {
    Object statusValue = securityDecision.get(STATUS_FIELD);
    if ("denylisted".equals(statusValue)) {
      return ERROR_APP_SECURITY_DENYLISTED;
    }
    return ERROR_APP_SECURITY_BLOCKED;
  }

  private static String reviewGateFailureCode(Map<String, Object> reviewTrust) {
    Object statusValue = reviewTrust.get(STATUS_FIELD);
    if (!(statusValue instanceof String status)) {
      return ERROR_APP_REVIEW_UNTRUSTED;
    }
    return switch (status) {
      case "missing_receipt", "publisher_claim_only", "not_configured" -> ERROR_APP_REVIEW_MISSING;
      case "artifact_mismatch", "app_mismatch" -> ERROR_APP_REVIEW_MISMATCH;
      case "expired", "reviewer_expired", "retired_reviewer" -> ERROR_APP_REVIEW_EXPIRED;
      case "trusted_rejected" -> ERROR_APP_REVIEW_REJECTED;
      default -> ERROR_APP_REVIEW_UNTRUSTED;
    };
  }

  private Map<String, Object> summarizeCatalog(AppCatalogSourceSnapshot snapshot) {
    String sourceKind = sourceKind(snapshot);
    String refreshedAt = snapshot.refreshedAt().toString();
    String lastSuccessfulRefreshAt =
        timestampField(snapshot, LAST_SUCCESSFUL_REFRESH_AT_FIELD, refreshedAt);
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(16);
    json.put(CATALOG_ID_FIELD, snapshot.catalogId());
    json.put("name", snapshot.name());
    json.put(SOURCE_FIELD, snapshot.sourceUri().toString());
    json.put("sourceDisplay", redactedCatalogSource(snapshot.sourceUri().toString(), sourceKind));
    json.put(SOURCE_TYPE_FIELD, sourceKind);
    json.put(SOURCE_KIND_FIELD, sourceKind);
    json.put("generatedAt", snapshot.generatedAt().toString());
    json.put("appCount", snapshot.appCount());
    json.put("addedAt", snapshot.addedAt().toString());
    json.put("refreshedAt", refreshedAt);
    json.put(LAST_ATTEMPT_AT_FIELD, timestampField(snapshot, LAST_ATTEMPT_AT_FIELD, refreshedAt));
    json.put(LAST_SUCCESSFUL_REFRESH_AT_FIELD, lastSuccessfulRefreshAt);
    json.put(LAST_FETCH_STATUS_FIELD, lastFetchStatus(snapshot));
    json.put(LAST_FETCH_ERROR_CODE_FIELD, stringField(snapshot, LAST_FETCH_ERROR_CODE_FIELD, null));
    json.put(
        LAST_FETCH_ERROR_MESSAGE_FIELD,
        stringField(snapshot, LAST_FETCH_ERROR_MESSAGE_FIELD, null));
    json.put(
        LAST_RESOLVED_URI_FIELD,
        stringField(snapshot, LAST_RESOLVED_URI_FIELD, snapshot.sourceUri().toString()));
    json.put(
        "lastResolvedDisplay",
        redactedCatalogSource(
            stringField(snapshot, LAST_RESOLVED_URI_FIELD, snapshot.sourceUri().toString()),
            sourceKind));
    json.put(SIGNATURE_KEY_ID_FIELD, snapshot.signatureKeyId().orElse(null));
    return json;
  }

  private AppCatalogSourceSnapshot catalogById(String catalogId) throws IOException {
    return catalogManager.catalog(catalogId);
  }

  private Map<String, Object> summarizeMirror(AppCatalogMirror mirror) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(8);
    json.put(MIRROR_ID_FIELD, mirror.id().value());
    json.put("role", mirror.role().metadataValue());
    json.put(SOURCE_KIND_FIELD, mirror.sourceKind().name().toLowerCase(Locale.ROOT));
    json.put(
        "sourceDisplay",
        redactedCatalogSource(mirror.source().displayUri(), mirror.sourceKind().name()));
    json.put(PRIORITY_FIELD, mirror.priority());
    json.put(ENABLED_FIELD, mirror.enabled());
    json.put("addedAt", mirror.addedAt().toString());
    json.put(REDACTED_FIELD, true);
    return json;
  }

  private Map<String, Object> sourceHealthEntry(AppCatalogMirrorHealth health) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(14);
    json.put("sourceId", health.id().value());
    json.put("role", health.role().metadataValue());
    json.put(LAST_FETCH_STATUS_FIELD, health.lastFetchStatus().metadataValue());
    json.put(LAST_ATTEMPT_AT_FIELD, health.lastAttemptAt().map(Instant::toString).orElse(null));
    json.put(
        LAST_SUCCESSFUL_REFRESH_AT_FIELD,
        health.lastSuccessfulRefreshAt().map(Instant::toString).orElse(null));
    json.put(LAST_FETCH_ERROR_CODE_FIELD, health.lastFetchErrorCode().orElse(null));
    json.put(LAST_FETCH_ERROR_MESSAGE_FIELD, health.lastFetchErrorMessage().orElse(null));
    json.put(LAST_RESOLVED_URI_FIELD, null);
    json.put("lastResolvedDisplay", redactedResolvedHealthSource(health));
    json.put("lastCatalogDigest", health.lastCatalogDigest().orElse(null));
    json.put("lastSignatureKeyId", health.lastSignatureKeyId().orElse(null));
    json.put("lastGeneratedAt", health.lastGeneratedAt().map(Instant::toString).orElse(null));
    json.put("lastRollbackReason", health.lastRollbackReason().orElse(null));
    json.put(REDACTED_FIELD, true);
    return json;
  }

  private Map<String, Object> summarizeRollbackCandidate(AppCatalogRollbackCandidate candidate) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(5);
    json.put("revision", summarizeRevision(candidate.revision()));
    json.put("eligible", candidate.eligible());
    json.put(REASON_FIELD, candidate.reason().orElse(null));
    json.put(VERSION_STATUS_CURRENT, candidate.revision().current());
    json.put(REDACTED_FIELD, true);
    return json;
  }

  private Map<String, Object> summarizeRevision(AppCatalogVerifiedRevision revision) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(16);
    json.put(REVISION_DIGEST_FIELD, revision.revisionDigest());
    json.put(CATALOG_ID_FIELD, revision.catalogId());
    json.put("catalogName", revision.catalogName());
    json.put("generatedAt", revision.generatedAt().toString());
    json.put("verifiedAt", revision.verifiedAt().toString());
    json.put("sourceId", revision.sourceId().value());
    json.put("sourceRole", revision.sourceRole().metadataValue());
    json.put("resolvedDisplay", redactedCatalogSource(revision.resolvedUri().orElse(null), null));
    json.put(SIGNATURE_KEY_ID_FIELD, revision.signatureKeyId());
    json.put("appCount", revision.appCount());
    json.put("advisoryCount", revision.advisoryCount());
    json.put("denylistCount", revision.denylistCount());
    json.put("channels", revision.channels());
    json.put(VERSION_STATUS_CURRENT, revision.current());
    json.put("rollbackReason", revision.rollbackReason().orElse(null));
    json.put(REDACTED_FIELD, true);
    return json;
  }

  private Map<String, Object> summarizeKeyRotation(AppCatalogKeyRotationStatus status) {
    AppCatalogKeyRotationPlan plan = status.plan();
    LinkedHashMap<String, Object> planJson = LinkedHashMap.newLinkedHashMap(4);
    planJson.put("nextKeyId", plan.nextKeyId().orElse(null));
    planJson.put("startsAt", plan.startsAt().map(Instant::toString).orElse(null));
    planJson.put("endsAt", plan.endsAt().map(Instant::toString).orElse(null));
    planJson.put("message", plan.message().orElse(null));
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(7);
    json.put(STATUS_FIELD, status.status());
    json.put("currentKeyId", status.currentKeyId().orElse(null));
    json.put("previousKeyId", status.previousKeyId().orElse(null));
    json.put("currentKeyTrusted", status.currentKeyTrusted());
    json.put("plan", planJson);
    json.put("blockerReasons", status.blockerReasons());
    json.put(REDACTED_FIELD, true);
    return json;
  }

  private static boolean fallbackUsed(List<AppCatalogMirrorHealth> health) {
    return latestSuccessfulHealth(health)
        .map(entry -> MIRROR_VALUE.equals(entry.role().metadataValue()))
        .orElse(false);
  }

  private static String activeSourceId(List<AppCatalogMirrorHealth> health) {
    return latestSuccessfulHealth(health)
        .map(entry -> entry.id().value())
        .orElse(AppCatalogMirrorId.PRIMARY.value());
  }

  private static Optional<AppCatalogMirrorHealth> latestSuccessfulHealth(
      List<AppCatalogMirrorHealth> health) {
    return health.stream()
        .filter(entry -> entry.lastSuccessfulRefreshAt().isPresent())
        .max(Comparator.comparing(entry -> entry.lastSuccessfulRefreshAt().orElse(Instant.EPOCH)));
  }

  private static List<String> advisoryIdsAdded(
      AppCatalogSecurityPolicy beforePolicy, AppCatalogSecurityPolicy afterPolicy) {
    Set<String> before =
        beforePolicy.advisories().stream()
            .map(advisory -> String.valueOf(advisory.toJsonValue().get("id")))
            .collect(java.util.stream.Collectors.toSet());
    return afterPolicy.advisories().stream()
        .map(advisory -> String.valueOf(advisory.toJsonValue().get("id")))
        .filter(id -> !before.contains(id))
        .toList();
  }

  private static int denylistEntriesAdded(
      AppCatalogSecurityPolicy beforePolicy, AppCatalogSecurityPolicy afterPolicy) {
    Set<String> before =
        beforePolicy.denylist().stream()
            .map(AppCatalogsApiHandler::denylistIdentity)
            .collect(java.util.stream.Collectors.toSet());
    long added =
        afterPolicy.denylist().stream()
            .map(AppCatalogsApiHandler::denylistIdentity)
            .filter(identity -> !before.contains(identity))
            .distinct()
            .count();
    return Math.toIntExact(added);
  }

  private static String denylistIdentity(AppCatalogVersionDenylistEntry entry) {
    return entry.id() + '\n' + entry.appId() + '\n' + entry.version();
  }

  private static Integer optionalPriority(Map<String, List<String>> queryParameters) {
    String value = PlatformApiParameters.readOptionalString(queryParameters, PRIORITY_FIELD);
    if (value == null || value.isBlank()) {
      return null;
    }
    try {
      return Integer.valueOf(value);
    } catch (NumberFormatException _) {
      throw new PlatformApiException(
          400, "invalid_query_parameter", PRIORITY_FIELD + " must be an integer.");
    }
  }

  private static int optionalPositivePriority(Map<String, List<String>> queryParameters) {
    Integer value = optionalPriority(queryParameters);
    if (value == null) {
      return 0;
    }
    if (value <= 0) {
      throw new PlatformApiException(
          400, "invalid_query_parameter", PRIORITY_FIELD + " must be positive.");
    }
    return value;
  }

  private static String normalizedRollbackReason(String reason) {
    if (reason == null || reason.isBlank()) {
      return null;
    }
    return reason.trim();
  }

  private static String redactedResolvedHealthSource(AppCatalogMirrorHealth health) {
    return redactedCatalogSource(health.lastResolvedUri().orElse(null), null);
  }

  private static String redactedCatalogSource(String rawSource, String sourceKind) {
    if (rawSource == null || rawSource.isBlank()) {
      return null;
    }
    String normalizedKind = sourceKind == null ? "" : sourceKind.toLowerCase(Locale.ROOT);
    String normalizedSource = rawSource.toLowerCase(Locale.ROOT);
    if ("file".equals(normalizedKind) || normalizedSource.startsWith("file:")) {
      return "file:<configured>";
    }
    if ("crypta".equals(normalizedKind)
        || normalizedSource.startsWith("crypta:")
        || normalizedSource.startsWith("usk@")
        || normalizedSource.startsWith("ssk@")
        || normalizedSource.startsWith("chk@")) {
      return "crypta:<configured>";
    }
    try {
      URI uri = URI.create(rawSource);
      if (uri.getQuery() == null && uri.getUserInfo() == null) {
        return uri.toString();
      }
      return new URI(
              uri.getScheme(),
              null,
              uri.getHost(),
              uri.getPort(),
              uri.getPath(),
              uri.getQuery() == null ? null : REDACTED_VALUE,
              null)
          .toString();
    } catch (Exception _) {
      return REDACTED_VALUE;
    }
  }

  private static String sourceKind(AppCatalogSourceSnapshot snapshot) {
    String explicitKind = stringField(snapshot, SOURCE_KIND_FIELD, null);
    if (explicitKind != null) {
      return explicitKind.toLowerCase(Locale.ROOT);
    }
    String scheme = snapshot.sourceUri().getScheme();
    return scheme == null || scheme.isBlank()
        ? VERSION_STATUS_UNKNOWN
        : scheme.toLowerCase(Locale.ROOT);
  }

  private static String timestampField(
      AppCatalogSourceSnapshot snapshot, String accessorName, String fallback) {
    Object value = snapshotAccessorValue(snapshot, accessorName);
    if (value == null) {
      return fallback;
    }
    if (value instanceof Instant instant) {
      return instant.toString();
    }
    String text = value.toString();
    return text.isBlank() ? fallback : text;
  }

  private static String stringField(
      AppCatalogSourceSnapshot snapshot, String accessorName, String fallback) {
    Object value = snapshotAccessorValue(snapshot, accessorName);
    if (value == null) {
      return fallback;
    }
    String text = value instanceof Enum<?> enumValue ? enumValue.name() : value.toString();
    text = text.trim();
    return text.isEmpty() ? fallback : text;
  }

  private static String lastFetchStatus(AppCatalogSourceSnapshot snapshot) {
    return stringField(snapshot, LAST_FETCH_STATUS_FIELD, FETCH_STATUS_SUCCESS)
        .toLowerCase(Locale.ROOT);
  }

  private static Object snapshotAccessorValue(
      AppCatalogSourceSnapshot snapshot, String accessorName) {
    try {
      Method method = snapshot.getClass().getMethod(accessorName);
      Object value = method.invoke(snapshot);
      if (value instanceof Optional<?> optional) {
        return optional.orElse(null);
      }
      return value;
    } catch (ReflectiveOperationException | SecurityException _) {
      return null;
    }
  }

  private Map<String, Object> summarizeEntry(String catalogId, AppCatalogEntry entry) {
    return summarizeEntry(catalogId, entry, false);
  }

  private Map<String, Object> summarizeEntry(
      String catalogId, AppCatalogEntry entry, boolean tolerateInstalledReadFailure) {
    InstalledSummary installedSummary =
        installedForSummary(entry.appId(), tolerateInstalledReadFailure);
    InstalledAppSnapshot installed = installedSummary.snapshot();
    RunningAppSnapshot running = appHost.status(entry.appId()).orElse(null);
    String installedVersion = installed == null ? null : installed.manifest().appVersion();
    boolean installedPresent = installed != null || installedSummary.readFailed();
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(29);
    json.put(APP_ID_FIELD, entry.appId());
    json.put("name", entry.name());
    json.put(VERSION_FIELD, entry.version());
    json.put(SUMMARY_FIELD, entry.summary());
    json.put("homepage", entry.homepage().map(URI::toString).orElse(null));
    json.put(SOURCE_FIELD, entry.source().map(URI::toString).orElse(null));
    json.put("license", entry.license().orElse(null));
    json.put("categories", entry.categories());
    json.put("channel", entry.productionMetadata().channel().catalogValue());
    json.put("supportStatus", entry.productionMetadata().supportStatus().catalogValue());
    json.put("maintenance", summarizeMaintenance(entry.maintenanceMetadata()));
    json.put("deprecation", summarizeDeprecation(entry.productionMetadata()));
    json.put("securityAdvisories", summarizeSecurityAdvisories(entry.productionMetadata()));
    json.put(SECURITY_DECISION_FIELD, targetSecurityDecision(catalogId, entry).toJsonValue());
    json.put(
        "installedSecurityDecision",
        installed == null
            ? AppCatalogSecurityDecision.OK.toJsonValue()
            : installedSecurityDecision(entry.appId(), installedVersion).toJsonValue());
    json.put("review", summarizeReview(entry.review()));
    json.put("thirdPartyReview", summarizeThirdPartyReview(entry.review()));
    json.put(REVIEW_TRUST_FIELD, reviewTrustSummary(catalogId, entry));
    json.put("permissions", entry.permissions());
    json.put("permissionRationales", entry.permissionRationales());
    json.put("compatibility", summarizeCompatibility(entry.compatibility()));
    json.put(
        API_COMPATIBILITY_FIELD,
        apiCompatibility(entry.compatibility().apiCompatibility(), entry.permissions()));
    json.put("changelog", summarizeChangelog(entry.changelog()));
    json.put("screenshots", entry.screenshots().stream().map(URI::toString).toList());
    json.put("bundle", summarizeBundle(entry));
    json.put(INSTALLED_FIELD, installedPresent);
    json.put("installedState", installedState(installedSummary, installed));
    json.put(INSTALLED_VERSION_FIELD, installedVersion);
    json.put(
        "versionDifferent", versionDifferent(entry.version(), installedVersion, installedPresent));
    json.put(
        "updateAvailable",
        updateAvailable(entry.version(), installedVersion, installedPresent).orElse(null));
    json.put("versionStatus", versionStatus(entry.version(), installedVersion, installedPresent));
    json.put("permissionDelta", summarizePermissionDelta(entry.permissions(), installed));
    json.put("running", running != null);
    json.put("pid", running == null ? null : running.pid());
    json.put("startedAt", running == null ? null : running.startedAt().toString());
    return json;
  }

  private InstalledAppSnapshot installed(String appId) {
    return installedForSummary(appId, false).snapshot();
  }

  private static String installedState(
      InstalledSummary installedSummary, InstalledAppSnapshot installed) {
    if (installedSummary.readFailed()) {
      return "unreadable_manifest";
    }
    return installed == null ? VERSION_STATUS_NOT_INSTALLED : VERSION_STATUS_INSTALLED;
  }

  private InstalledSummary installedForSummary(String appId, boolean tolerateReadFailure) {
    try {
      return new InstalledSummary(appHost.describe(appId).orElse(null), false);
    } catch (IOException _) {
      if (tolerateReadFailure) {
        return new InstalledSummary(null, true);
      }
      throw internalError("Failed to read installed apps.");
    }
  }

  private record InstalledSummary(InstalledAppSnapshot snapshot, boolean readFailed) {}

  private static Map<String, Object> summarizeBundle(AppCatalogEntry entry) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(4);
    json.put("uri", entry.bundleUri().toString());
    json.put("type", entry.bundleType());
    json.put("sizeBytes", entry.bundleSizeBytes());
    json.put("sha256", entry.bundleSha256());
    return json;
  }

  private static Map<String, Object> summarizeReview(AppCatalogReviewMetadata review) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(3);
    json.put(STATUS_FIELD, review.status().catalogValue());
    json.put("note", review.note().orElse(null));
    json.put(ADVISORY_FIELD, true);
    return json;
  }

  private static Map<String, Object> summarizeThirdPartyReview(AppCatalogReviewMetadata review) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(13);
    json.put(STATUS_FIELD, review.status().catalogValue());
    json.put("submissionId", review.submissionId().orElse(null));
    json.put("submissionSha256", review.submissionSha256().orElse(null));
    json.put("preReviewStatus", review.preReviewStatus().orElse(null));
    json.put("preReviewSha256", review.preReviewSha256().orElse(null));
    json.put(REVIEWER_KEY_ID_FIELD, review.reviewerKeyId().orElse(null));
    json.put("reviewerPolicy", review.reviewerPolicy().orElse(null));
    json.put("receiptFingerprintSha256", review.receiptFingerprintSha256().orElse(null));
    json.put("decisionReasonSha256", review.decisionReasonSha256().orElse(null));
    json.put("resubmissionOf", review.resubmissionOf().orElse(null));
    json.put("nonProduction", review.nonProduction());
    json.put("hasSubmissionMetadata", review.hasSubmissionReviewFields());
    json.put(ADVISORY_FIELD, true);
    return json;
  }

  private Map<String, Object> summarizeCompatibility(
      AppCatalogCompatibilityMetadata compatibility) {
    String minimumVersion = compatibility.minimumCryptaVersion();
    String maximumVersion = compatibility.maximumCryptaVersion();
    String currentVersion = currentCryptaVersion();
    CompatibilityResult result =
        compatibilityResult(minimumVersion, maximumVersion, currentVersion);
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(7);
    json.put("minimumCryptaVersion", minimumVersion);
    json.put("maximumCryptaVersion", maximumVersion);
    json.put("currentCryptaVersion", currentVersion);
    json.put(COMPATIBILITY_SATISFIED, result.satisfied());
    json.put(ADVISORY_FIELD, true);
    json.put(STATUS_FIELD, result.status());
    return json;
  }

  private static Map<String, Object> summarizeDeprecation(AppCatalogProductionMetadata metadata) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(3);
    json.put(STATUS_FIELD, metadata.deprecationStatus().catalogValue());
    json.put("message", metadata.deprecationMessage().orElse(null));
    json.put(REPLACEMENT_APP_ID_FIELD, metadata.replacementAppId().orElse(null));
    return json;
  }

  private static Map<String, Object> summarizeMaintenance(AppCatalogMaintenanceMetadata metadata) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(9);
    json.put("owner", metadata.owner().orElse(null));
    json.put("ownerUri", metadata.ownerUri().map(URI::toString).orElse(null));
    json.put("supportLevel", metadata.supportLevel().map(SupportLevel::catalogValue).orElse(null));
    json.put(
        "dataSchemaPolicy",
        metadata.dataSchemaPolicy().map(DataSchemaPolicy::catalogValue).orElse(null));
    json.put(
        "migrationPolicy",
        metadata.migrationPolicy().map(MigrationPolicy::catalogValue).orElse(null));
    json.put(
        "backupRestore",
        metadata.backupRestore().map(BackupRestoreSupport::catalogValue).orElse(null));
    json.put(
        "securityPolicy", metadata.securityPolicy().map(SecurityPolicy::catalogValue).orElse(null));
    json.put(
        "deprecationPolicy",
        metadata.deprecationPolicy().map(DeprecationPolicy::catalogValue).orElse(null));
    json.put("supportUri", metadata.supportUri().map(URI::toString).orElse(null));
    return json;
  }

  private static List<Map<String, Object>> summarizeSecurityAdvisories(
      AppCatalogProductionMetadata metadata) {
    return metadata.securityAdvisories().stream()
        .map(AppCatalogsApiHandler::summarizeSecurityAdvisory)
        .toList();
  }

  private static Map<String, Object> summarizeSecurityAdvisory(
      AppCatalogSecurityAdvisory advisory) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(2);
    json.put("id", advisory.id());
    json.put("uri", advisory.uri().toString());
    return json;
  }

  private static Map<String, Object> summarizeChangelog(AppCatalogChangelog changelog) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(2);
    json.put(SUMMARY_FIELD, changelog.summary().orElse(null));
    json.put("uri", changelog.uri().map(URI::toString).orElse(null));
    return json;
  }

  private static Map<String, Object> summarizePermissionDelta(
      List<String> catalogPermissions, InstalledAppSnapshot installed) {
    Set<String> catalog = new LinkedHashSet<>(catalogPermissions);
    Set<String> local =
        installed == null ? Set.of() : new LinkedHashSet<>(installed.manifest().permissions());
    List<String> added = new ArrayList<>();
    List<String> removed = new ArrayList<>();
    List<String> unchanged = new ArrayList<>();
    for (String permission : catalog) {
      if (local.contains(permission)) {
        unchanged.add(permission);
      } else {
        added.add(permission);
      }
    }
    for (String permission : local) {
      if (!catalog.contains(permission)) {
        removed.add(permission);
      }
    }
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(3);
    json.put("added", List.copyOf(added));
    json.put(REMOVED_FIELD, List.copyOf(removed));
    json.put("unchanged", List.copyOf(unchanged));
    return json;
  }

  private String currentCryptaVersion() {
    try {
      String value = currentCryptaVersionSupplier.get();
      return value == null || value.isBlank() ? null : value;
    } catch (RuntimeException _) {
      return null;
    }
  }

  private static boolean versionDifferent(
      String catalogVersion, String installedVersion, boolean installed) {
    if (!installed) {
      return false;
    }
    if (catalogVersion == null || installedVersion == null) {
      return false;
    }
    return !catalogVersion.equals(installedVersion);
  }

  private static Optional<Boolean> updateAvailable(
      String catalogVersion, String installedVersion, boolean installed) {
    if (!installed) {
      return Optional.of(false);
    }
    if (catalogVersion == null || installedVersion == null) {
      return Optional.empty();
    }
    if (catalogVersion.equals(installedVersion)) {
      return Optional.of(false);
    }
    Integer comparison = compareDottedNumericVersions(catalogVersion, installedVersion);
    return comparison == null ? Optional.empty() : Optional.of(comparison > 0);
  }

  private static String versionStatus(
      String catalogVersion, String installedVersion, boolean installed) {
    if (!installed) {
      return VERSION_STATUS_NOT_INSTALLED;
    }
    if (catalogVersion == null || installedVersion == null) {
      return VERSION_STATUS_UNKNOWN;
    }
    return versionDifferent(catalogVersion, installedVersion, true)
        ? VERSION_STATUS_DIFFERENT
        : VERSION_STATUS_CURRENT;
  }

  private static CompatibilityResult compatibilityResult(
      String minimumVersion, String maximumVersion, String currentVersion) {
    if (minimumVersion == null && maximumVersion == null) {
      return new CompatibilityResult(true, COMPATIBILITY_NOT_DECLARED);
    }
    if (currentVersion == null) {
      return new CompatibilityResult(null, COMPATIBILITY_UNKNOWN);
    }
    Integer minimumComparison =
        minimumVersion == null
            ? Integer.valueOf(0)
            : compareDottedNumericVersions(currentVersion, minimumVersion);
    Integer maximumComparison =
        maximumVersion == null
            ? Integer.valueOf(0)
            : compareDottedNumericVersions(currentVersion, maximumVersion);
    if (minimumComparison == null || maximumComparison == null) {
      return new CompatibilityResult(null, COMPATIBILITY_UNKNOWN);
    }
    boolean satisfied = minimumComparison >= 0 && maximumComparison <= 0;
    return new CompatibilityResult(
        satisfied, satisfied ? COMPATIBILITY_SATISFIED : COMPATIBILITY_NOT_SATISFIED);
  }

  private static Integer compareDottedNumericVersions(String left, String right) {
    List<Integer> leftParts = parseDottedNumericVersion(left);
    List<Integer> rightParts = parseDottedNumericVersion(right);
    if (leftParts.isEmpty() || rightParts.isEmpty()) {
      return null;
    }
    int count = Math.max(leftParts.size(), rightParts.size());
    for (int index = 0; index < count; index++) {
      int leftPart = index < leftParts.size() ? leftParts.get(index) : 0;
      int rightPart = index < rightParts.size() ? rightParts.get(index) : 0;
      if (leftPart != rightPart) {
        return Integer.compare(leftPart, rightPart);
      }
    }
    return 0;
  }

  private static List<Integer> parseDottedNumericVersion(String version) {
    if (version == null || version.isBlank()) {
      return List.of();
    }
    String[] tokens = version.trim().split("\\.", -1);
    List<Integer> parts = new ArrayList<>(tokens.length);
    for (String token : tokens) {
      if (token.isBlank() || !token.chars().allMatch(Character::isDigit)) {
        return List.of();
      }
      try {
        parts.add(Integer.parseInt(token));
      } catch (NumberFormatException _) {
        return List.of();
      }
    }
    return List.copyOf(parts);
  }

  private static Map<String, Object> apiCompatibility(
      AppApiCompatibilityMetadata metadata, List<String> permissions) {
    return PlatformApiAppAdmission.summarizeAdmission(metadata, permissions);
  }

  private static boolean reviewAcknowledged(Map<String, List<String>> queryParameters) {
    String value =
        PlatformApiParameters.readOptionalString(queryParameters, PARAM_REVIEW_ACKNOWLEDGED);
    if (value == null || value.isBlank()) {
      return false;
    }
    if ("true".equalsIgnoreCase(value.trim())) {
      return true;
    }
    if ("false".equalsIgnoreCase(value.trim())) {
      return false;
    }
    throw new PlatformApiException(
        400, "invalid_query_parameter", PARAM_REVIEW_ACKNOWLEDGED + " must be 'true' or 'false'.");
  }

  private static boolean securityAcknowledged(Map<String, List<String>> queryParameters) {
    String value =
        PlatformApiParameters.readOptionalString(queryParameters, PARAM_SECURITY_ACKNOWLEDGED);
    if (value == null || value.isBlank()) {
      return false;
    }
    if ("true".equalsIgnoreCase(value.trim())) {
      return true;
    }
    if ("false".equalsIgnoreCase(value.trim())) {
      return false;
    }
    throw new PlatformApiException(
        400,
        "invalid_query_parameter",
        PARAM_SECURITY_ACKNOWLEDGED + " must be 'true' or 'false'.");
  }

  private static Map<String, Object> summarizeInstalledApp(AppManifest manifest) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(13);
    json.put(APP_ID_FIELD, manifest.appId());
    json.put("name", manifest.appName());
    json.put(VERSION_FIELD, manifest.appVersion());
    json.put("uiMode", manifest.uiMode().manifestValue());
    json.put("uiEntry", manifest.uiEntry());
    json.put("uiUrl", AppUiPaths.uiUrl(manifest));
    json.put("permissions", manifest.permissions());
    json.put(
        API_COMPATIBILITY_FIELD,
        apiCompatibility(manifest.apiCompatibility(), manifest.permissions()));
    json.put(INSTALLED_FIELD, true);
    json.put("running", false);
    json.put("pid", null);
    json.put("startedAt", null);
    return json;
  }

  private PlatformApiException catalogFailure(AppCatalogException exception) {
    return switch (exception.errorCode()) {
      case "catalog_not_found", "app_not_found" ->
          new PlatformApiException(404, exception.errorCode(), exception.getMessage());
      case "catalog_conflict" ->
          new PlatformApiException(409, exception.errorCode(), exception.getMessage());
      case "catalog_fetch_unavailable", "artifact_fetch_unavailable" ->
          new PlatformApiException(503, exception.errorCode(), exception.getMessage());
      case "catalog_fetch_failed", "artifact_download_failed" ->
          new PlatformApiException(502, exception.errorCode(), exception.getMessage());
      default -> new PlatformApiException(400, exception.errorCode(), exception.getMessage());
    };
  }

  private PlatformApiException installFailure(AppHostException exception) {
    if (isAlreadyInstalledFailure(exception)) {
      return conflict(alreadyInstalledMessage(exception));
    }
    if (exception instanceof AppBundleVerificationException) {
      return new PlatformApiException(
          400, INVALID_APP_BUNDLE_ERROR_CODE, "Catalog app bundle failed trusted verification.");
    }
    if (isInvalidAppBundleFailure(exception)) {
      return new PlatformApiException(
          400, INVALID_APP_BUNDLE_ERROR_CODE, APPHOST_BUNDLE_VALIDATION_MESSAGE);
    }
    return internalError(INSTALL_FAILED_MESSAGE);
  }

  private PlatformApiException updateFailure(String appId, AppHostException exception) {
    if (exception instanceof AppHostException.CatalogOriginChangedException) {
      return new PlatformApiException(
          409,
          "catalog_source_switch_consent_required",
          "Installed catalog origin changed; prepare and approve a new source-switch preview.");
    }
    if (isRunningUpdateFailure(exception) || appHost.status(appId).isPresent()) {
      return conflict(CANNOT_UPDATE_RUNNING_APP_PREFIX + appId);
    }
    if (isMissingAppFailure(exception)) {
      return new PlatformApiException(404, "app_not_found", "App not found.");
    }
    if (exception instanceof AppBundleVerificationException) {
      return new PlatformApiException(
          400, INVALID_APP_BUNDLE_ERROR_CODE, "Catalog app bundle failed trusted verification.");
    }
    if (isInvalidAppBundleFailure(exception)) {
      return new PlatformApiException(
          400, INVALID_APP_BUNDLE_ERROR_CODE, APPHOST_BUNDLE_VALIDATION_MESSAGE);
    }
    return internalError(UPDATE_FAILED_MESSAGE);
  }

  private static boolean isInvalidAppBundleFailure(AppHostException failure) {
    if (failure instanceof network.crypta.platform.apphost.manifest.AppManifestException) {
      return true;
    }
    String message = failure.getMessage();
    if (message == null || message.isBlank()) {
      return false;
    }
    return message.startsWith("stagedAppDirectory ")
        || message.startsWith("staging directory ")
        || message.startsWith("copied manifest ")
        || message.startsWith("copied app.exec ")
        || message.startsWith("app.ui.entry ")
        || message.startsWith("app.exec ")
        || message.startsWith("staged app bundle ");
  }

  private static boolean isAlreadyInstalledFailure(AppHostException failure) {
    String message = failure.getMessage();
    return message != null && message.startsWith(APP_ALREADY_INSTALLED_PREFIX);
  }

  private static boolean isRunningUpdateFailure(AppHostException failure) {
    String message = failure.getMessage();
    return message != null && message.startsWith(CANNOT_UPDATE_RUNNING_APP_PREFIX);
  }

  private static boolean isMissingAppFailure(AppHostException failure) {
    String message = failure.getMessage();
    return message != null && message.startsWith(APP_NOT_INSTALLED_PREFIX);
  }

  private static PlatformApiException conflict(String message) {
    return new PlatformApiException(409, "app_conflict", message);
  }

  private static PlatformApiException internalError(String message) {
    return new PlatformApiException(500, "internal_error", message);
  }

  private static String alreadyInstalledMessage(Throwable failure) {
    String message = failure.getMessage();
    return message == null || message.isBlank() ? "App already installed." : message;
  }

  private record SourceSwitchAuthorization(
      Optional<InstalledAppOrigin> expectedCurrentOrigin, boolean explicitSwitch) {
    private SourceSwitchAuthorization {
      Objects.requireNonNull(expectedCurrentOrigin, "expectedCurrentOrigin");
    }

    private static SourceSwitchAuthorization withoutCurrentOrigin() {
      return new SourceSwitchAuthorization(Optional.empty(), false);
    }

    private static SourceSwitchAuthorization forCurrentOrigin(InstalledAppOrigin current) {
      return forCurrentOrigin(current, false);
    }

    private static SourceSwitchAuthorization forCurrentOrigin(
        InstalledAppOrigin current, boolean explicitSwitch) {
      return new SourceSwitchAuthorization(
          Optional.of(Objects.requireNonNull(current, VERSION_STATUS_CURRENT)), explicitSwitch);
    }

    private AppHost.CatalogOriginExpectation expectedCurrentOriginExpectation() {
      return expectedCurrentOrigin
          .map(InstalledAppOrigin::selfDigestSha256)
          .map(AppHost.CatalogOriginExpectation::matching)
          .orElseGet(AppHost.CatalogOriginExpectation::absent);
    }
  }

  private record CompatibilityResult(Boolean satisfied, String status) {}
}
