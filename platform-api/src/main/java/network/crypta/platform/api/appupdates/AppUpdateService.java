package network.crypta.platform.api.appupdates;

import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Deque;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import network.crypta.platform.api.PlatformApiAppAdmission;
import network.crypta.platform.api.PlatformApiException;
import network.crypta.platform.api.appdata.AppDataService;
import network.crypta.platform.api.appdata.AppDataUpdateSnapshot;
import network.crypta.platform.appcatalog.AppCatalogChannel;
import network.crypta.platform.appcatalog.AppCatalogEntry;
import network.crypta.platform.appcatalog.AppCatalogException;
import network.crypta.platform.appcatalog.AppCatalogInstallPlan;
import network.crypta.platform.appcatalog.AppCatalogManager;
import network.crypta.platform.appcatalog.AppReviewPolicy;
import network.crypta.platform.appcatalog.CatalogScopeRevocation;
import network.crypta.platform.appcatalog.CatalogScopedReviewerPolicy;
import network.crypta.platform.appcatalog.TrustedReviewerKeys;
import network.crypta.platform.apphost.AppBundleVerificationException;
import network.crypta.platform.apphost.AppHost;
import network.crypta.platform.apphost.AppHostException;
import network.crypta.platform.apphost.InstalledAppOrigin;
import network.crypta.platform.apphost.InstalledAppSnapshot;
import network.crypta.platform.apphost.RunningAppSnapshot;
import network.crypta.platform.apphost.manifest.AppManifest;
import network.crypta.platform.appvault.AppVaultService;

import static network.crypta.platform.api.appupdates.AppUpdateDigestSupport.securityDecisionDigest;

/**
 * Coordinates conservative app update checks, staging, apply, policy, history, and rollback.
 *
 * <p>The service deliberately stays above signed catalog and AppHost primitives. Catalog entries
 * are still verified by {@link AppCatalogManager}; immutable bundle replacement and rollback remain
 * AppHost responsibilities. This layer stores only display-safe update lifecycle metadata and keeps
 * temporary staging paths private.
 *
 * <p>All public methods are synchronized because the current implementation keeps lifecycle state
 * in memory: pending staged plans, last-check summaries, recent history, cached candidates, and
 * local policy. The service revalidates cached candidates against the current installed manifest
 * and against the prepared catalog plan before applying. This protects operators from stale review
 * metadata, catalog refresh races, and updates performed through the legacy immediate endpoints.
 *
 * <p>The lifecycle is intentionally conservative. Default policy is manual, running apps are not
 * stopped unless the request allows restart choreography, and rollback restores only the immutable
 * installed bundle retained by AppHost. Mutable app data, cache, run directories, app tokens,
 * browser-session tokens, catalog scratch paths, and private catalog URIs are never exposed in
 * summaries.
 *
 * @see AppCatalogManager
 * @see AppHost
 */
public final class AppUpdateService {
  private static final int MAX_HISTORY_ENTRIES = 20;
  private static final String STATUS_SUCCESS = "success";
  private static final String STATUS_FAILED = "failed";
  private static final String ACTION_CHECK = "check";
  private static final String ACTION_STAGE = "stage";
  private static final String ACTION_APPLY = "apply";
  private static final String ACTION_ROLLBACK = "rollback";
  private static final String EVENT_STATUS_POLICY_PREFIX = "policy_";
  private static final String EVENT_STATUS_BLOCKED_SUFFIX = "_blocked:";
  private static final String APP_NOT_INSTALLED_PREFIX = "app is not installed: ";
  private static final String CANNOT_UPDATE_RUNNING_APP_PREFIX = "cannot update a running app: ";
  private static final String CANNOT_ROLLBACK_RUNNING_APP_PREFIX =
      "cannot rollback a running app: ";
  private static final String ROLLBACK_RECORD_NOT_AVAILABLE_PREFIX =
      "rollback record is not available: ";
  private static final String ERROR_APP_RUNNING = "app_running";
  private static final String ERROR_UPDATE_NOT_AVAILABLE = "update_not_available";
  private static final String ERROR_UPDATE_NOT_STAGED = "update_not_staged";
  private static final String ERROR_UPDATE_INCOMPATIBLE = "update_incompatible";
  private static final String ERROR_UPDATE_POLICY_BLOCKED = "update_policy_blocked";
  private static final String ERROR_CHANNEL_POLICY_BLOCKED = "channel_policy_blocked";
  private static final String ERROR_CONSENT_REQUIRED = "consent_required";
  private static final String ERROR_UPDATE_CANDIDATE_CHANGED = "update_candidate_changed";
  private static final String ERROR_CATALOG_SOURCE_SWITCH_CONSENT_REQUIRED =
      "catalog_source_switch_consent_required";
  private static final String ERROR_ROLLBACK_NOT_AVAILABLE = "rollback_not_available";
  private static final String ERROR_ROLLBACK_APP_RUNNING = "rollback_app_running";
  private static final String ERROR_ROLLBACK_FAILED = "rollback_failed";
  private static final String ERROR_ROLLBACK_BUNDLE_VERIFICATION_FAILED =
      "rollback_bundle_verification_failed";
  private static final String ERROR_ROLLBACK_RESTART_FAILED = "rollback_restart_failed";
  private static final String ERROR_HEALTH_CHECK_FAILED = "health_check_failed";
  private static final String ERROR_UPDATE_FAILED = "update_failed";
  private static final String ERROR_STAGE_FAILED = "stage_failed";
  private static final String ERROR_APP_DATA_MIGRATION_MISSING =
      AppUpdateMigrationPlanner.ERROR_MISSING_MIGRATION;
  private static final String ERROR_APP_DATA_MIGRATION_DRY_RUN_FAILED =
      "app_data_migration_dry_run_failed";
  private static final String ERROR_APP_DATA_MIGRATION_APPLY_FAILED =
      "app_data_migration_apply_failed";
  private static final String ERROR_APP_DATA_MIGRATION_REVIEW_REQUIRED =
      "app_data_migration_review_required";
  private static final String ERROR_APP_DATA_MIGRATION_REQUIRES_STOPPED =
      "app_data_migration_requires_stopped";
  private static final String ERROR_APP_DATA_MIGRATION_SANDBOX_UNAVAILABLE =
      "app_data_migration_sandbox_unavailable";
  private static final String ERROR_APP_DATA_SNAPSHOT_FAILED = "app_data_snapshot_failed";
  private static final String ERROR_APP_DATA_RESTORE_FAILED = "app_data_restore_failed";
  private static final String ERROR_INVALID_UPDATE_OPTION = "invalid_update_option";
  private static final String ERROR_INVALID_APP_BUNDLE = "invalid_app_bundle";
  private static final String ERROR_APP_REVIEW_MISSING = "app_review_missing";
  private static final String ERROR_APP_REVIEW_UNTRUSTED = "app_review_untrusted";
  private static final String ERROR_APP_REVIEW_REJECTED = "app_review_rejected";
  private static final String ERROR_APP_REVIEW_MISMATCH = "app_review_mismatch";
  private static final String ERROR_APP_REVIEW_EXPIRED = "app_review_expired";
  private static final String ERROR_CATALOG_ROLLBACK_TRUST_BLOCKED =
      "catalog_rollback_trust_blocked";
  private static final String ERROR_APP_SECURITY_ACKNOWLEDGEMENT_REQUIRED =
      "app_security_acknowledgement_required";
  private static final String ERROR_APP_SECURITY_BLOCKED = "app_security_blocked";
  private static final String ERROR_APP_SECURITY_DENYLISTED = "app_security_denylisted";
  private static final String POLICY_SECURITY_ACKNOWLEDGEMENT_REQUIRED =
      "security_acknowledgement_required";
  private static final String POLICY_SECURITY_BLOCKED = "security_policy_blocked";
  private static final String POLICY_SECURITY_DENYLIST_BLOCKED = "security_denylist_blocked";
  private static final String MESSAGE_APPLY_FAILED = "Failed to apply staged update.";
  private static final String MESSAGE_APPLY_VAULT_CLEANUP_FAILED =
      "Staged update applied; vault grant cleanup failed and requires operator review.";
  private static final String MESSAGE_STAGE_FAILED = "Failed to stage update candidate.";
  private static final String MESSAGE_ROLLBACK_FAILED = "Rollback failed.";
  private static final String MESSAGE_STAGED_UPDATE_NO_LONGER_MATCHES =
      "Staged update no longer matches the installed app version.";
  private static final String MESSAGE_APP_DATA_MIGRATION_DRY_RUN_FAILED =
      "App-data migration dry-run failed.";
  private static final String VERSION_EQUAL = "equal";
  private static final String JSON_APP_ID = "appId";
  private static final String JSON_STATUS = "status";
  private static final String JSON_AVAILABLE = "available";
  private static final String JSON_STAGED_AT = "stagedAt";
  private static final String JSON_REVIEW_TRUST = "reviewTrust";
  private static final String JSON_REQUIRES_ACKNOWLEDGEMENT = "requiresAcknowledgement";
  private static final String JSON_BLOCKS_UPDATE = "blocksUpdate";
  private static final String JSON_BLOCKS_POLICY_APPLY = "blocksPolicyApply";
  private static final String JSON_BLOCKS_AUTOMATIC_APPLY = "blocksAutomaticApply";
  private static final String JSON_MESSAGE = "message";
  private static final String JSON_CATALOG_ID = "catalogId";

  private final AppHost appHost;
  private final AppCatalogManager catalogManager;
  private final AppUpdateCatalogAuthority catalogAuthority;
  private final AppVaultService appVaultService;
  private final AppDataService appDataService;
  private final AppDataMigrationRunner migrationRunner;
  private SchedulerSummaryProvider schedulerSummaryProvider;
  private final AtomicReference<AppUpdateFederationAuthority> federatedConflictPolicy =
      new AtomicReference<>();
  private SchedulerStateCleaner schedulerStateCleaner = _ -> {};
  private final Map<String, AppUpdatePolicy> policies = new LinkedHashMap<>();
  private final Map<String, AppUpdateCandidate> candidates = new LinkedHashMap<>();
  private final Map<String, StagedUpdate> stagedUpdates = new LinkedHashMap<>();
  private final Map<String, LastCheck> lastChecks = new LinkedHashMap<>();
  private final Map<String, Deque<AppUpdateHistoryEntry>> history = new LinkedHashMap<>();

  private static AppUpdateDependencies defaultDependencies(
      AppVaultService appVaultService, AppDataService appDataService) {
    return new AppUpdateDependencies(
        AppReviewPolicy.loadFromSystem(),
        AppUpdateReviewAuthority.systemReviewerKeysProvider(),
        appVaultService,
        appDataService,
        AppDataMigrationRunner.localProcess(),
        AppUpdateService::disabledSchedulerSummary);
  }

  private static AppUpdateDependencies reviewedDependencies(
      AppReviewPolicy reviewPolicy,
      ReviewerKeysProvider reviewerKeysProvider,
      AppVaultService appVaultService,
      AppDataMigrationRunner migrationRunner,
      SchedulerSummaryProvider schedulerSummaryProvider) {
    return new AppUpdateDependencies(
        reviewPolicy,
        reviewerKeysProvider,
        appVaultService,
        null,
        migrationRunner,
        schedulerSummaryProvider);
  }

  /**
   * Creates an app-update service backed by signed catalogs and AppHost.
   *
   * <p>The service does not own process execution or catalog verification. It coordinates the two
   * existing subsystems and stores only path-free lifecycle summaries. Callers should normally keep
   * one service instance for the router lifetime so staged plans and recent history remain
   * consistent across update requests.
   *
   * @param appHost AppHost used for installed state, apply, start, stop, and rollback
   * @param catalogManager signed catalog manager used for candidate discovery and staging
   */
  public AppUpdateService(AppHost appHost, AppCatalogManager catalogManager) {
    this(appHost, catalogManager, (AppVaultService) null);
  }

  /**
   * Creates an app-update service with optional vault grant lifecycle integration.
   *
   * @param appHost AppHost used for installed state, apply, start, stop, and rollback
   * @param catalogManager signed catalog manager used for candidate discovery and staging
   * @param appVaultService optional app-vault service used to disable grants after permission
   *     removal
   */
  public AppUpdateService(
      AppHost appHost, AppCatalogManager catalogManager, AppVaultService appVaultService) {
    this(appHost, catalogManager, appVaultService, null);
  }

  /**
   * Creates an app-update service with optional vault and app-data integration.
   *
   * @param appHost AppHost used for installed state, apply, start, stop, and rollback
   * @param catalogManager signed catalog manager used for candidate discovery and staging
   * @param appVaultService optional app-vault service used to disable grants after permission
   *     removal
   * @param appDataService optional durable app-data service used for migration snapshots
   */
  public AppUpdateService(
      AppHost appHost,
      AppCatalogManager catalogManager,
      AppVaultService appVaultService,
      AppDataService appDataService) {
    this(appHost, catalogManager, defaultDependencies(appVaultService, appDataService));
  }

  /**
   * Creates an app-update service with explicit review policy and reviewer-key provider.
   *
   * @param appHost AppHost used for installed state, apply, start, stop, and rollback
   * @param catalogManager signed catalog manager used for candidate discovery and staging
   * @param reviewPolicy local review policy
   * @param reviewerKeysProvider provider for trusted reviewer keys
   */
  public AppUpdateService(
      AppHost appHost,
      AppCatalogManager catalogManager,
      AppReviewPolicy reviewPolicy,
      ReviewerKeysProvider reviewerKeysProvider) {
    this(appHost, catalogManager, reviewPolicy, reviewerKeysProvider, null);
  }

  /**
   * Creates an app-update service with explicit review policy, reviewer keys, and optional vault.
   *
   * @param appHost AppHost used for installed state, apply, start, stop, and rollback
   * @param catalogManager signed catalog manager used for candidate discovery and staging
   * @param reviewPolicy local review policy
   * @param reviewerKeysProvider provider for trusted reviewer keys
   * @param appVaultService optional app-vault service used to disable grants after permission
   *     removal
   */
  public AppUpdateService(
      AppHost appHost,
      AppCatalogManager catalogManager,
      AppReviewPolicy reviewPolicy,
      ReviewerKeysProvider reviewerKeysProvider,
      AppVaultService appVaultService) {
    this(
        appHost,
        catalogManager,
        reviewedDependencies(
            reviewPolicy,
            reviewerKeysProvider,
            appVaultService,
            AppDataMigrationRunner.localProcess(),
            AppUpdateService::disabledSchedulerSummary));
  }

  /**
   * Creates an app-update service with explicit review policy, reviewer keys, vault, and scheduler
   * summaries.
   *
   * <p>The scheduler provider is deliberately injected instead of started by the service
   * constructor. Runtime composition can create one shared service, create the scheduler around
   * that service, and then attach {@link AppUpdateScheduler#summary(String)} so API summaries and
   * background checks describe the same lifecycle state. Unit tests can keep the provider disabled
   * unless they are explicitly testing scheduler metadata.
   *
   * @param appHost AppHost used for installed state, apply, start, stop, and rollback
   * @param catalogManager signed catalog manager used for candidate discovery and staging
   * @param reviewPolicy local review policy
   * @param reviewerKeysProvider provider for trusted reviewer keys
   * @param appVaultService optional app-vault service used to disable grants after permission
   *     removal
   * @param schedulerSummaryProvider provider for path-free scheduler state
   */
  public AppUpdateService(
      AppHost appHost,
      AppCatalogManager catalogManager,
      AppReviewPolicy reviewPolicy,
      ReviewerKeysProvider reviewerKeysProvider,
      AppVaultService appVaultService,
      SchedulerSummaryProvider schedulerSummaryProvider) {
    this(
        appHost,
        catalogManager,
        reviewedDependencies(
            reviewPolicy,
            reviewerKeysProvider,
            appVaultService,
            AppDataMigrationRunner.localProcess(),
            schedulerSummaryProvider));
  }

  /**
   * Creates an app-update service with explicit optional dependencies.
   *
   * @param appHost AppHost used for installed state, apply, start, stop, and rollback
   * @param catalogManager signed catalog manager used for candidate discovery and staging
   * @param dependencies review, app-data, migration-runner, vault, and scheduler integrations
   */
  public AppUpdateService(
      AppHost appHost, AppCatalogManager catalogManager, AppUpdateDependencies dependencies) {
    this.appHost = Objects.requireNonNull(appHost, "appHost");
    this.catalogManager = Objects.requireNonNull(catalogManager, "catalogManager");
    AppUpdateDependencies checkedDependencies =
        Objects.requireNonNull(dependencies, "dependencies");
    this.catalogAuthority =
        new AppUpdateCatalogAuthority(
            appHost,
            catalogManager,
            checkedDependencies.reviewPolicy(),
            checkedDependencies.reviewerKeysProvider());
    this.appVaultService = checkedDependencies.appVaultService();
    this.appDataService = checkedDependencies.appDataService();
    this.migrationRunner = checkedDependencies.migrationRunner();
    this.schedulerSummaryProvider = checkedDependencies.schedulerSummaryProvider();
  }

  /**
   * Supplies trusted reviewer keys for review-receipt verification.
   *
   * <p>The provider exists so unit tests and embedders can inject ephemeral reviewer keys without
   * using process-wide system properties or environment variables.
   */
  @FunctionalInterface
  public interface ReviewerKeysProvider {
    /**
     * Returns trusted reviewer keys for the current request.
     *
     * @return local trusted reviewer keys
     * @throws IOException if configured key material cannot be read
     */
    TrustedReviewerKeys trustedReviewerKeys() throws IOException;
  }

  /**
   * Supplies path-free scheduler metadata for update summaries.
   *
   * <p>The update service owns lifecycle state, while the optional background scheduler owns
   * scheduler timestamps, backoff, and failure counters. This provider keeps the two lifecycles
   * loosely coupled: services constructed for unit tests or alternate embeddings can use the
   * disabled default, and the HTTP runtime can attach its durable scheduler after both objects are
   * constructed.
   */
  @FunctionalInterface
  public interface SchedulerSummaryProvider {
    /**
     * Returns path-free scheduler state for one installed app.
     *
     * @param appId normalized app id
     * @return JSON-compatible scheduler summary
     */
    Map<String, Object> schedulerSummary(String appId);
  }

  /**
   * Clears path-free scheduler metadata for an app whose update lifecycle state is being reset.
   *
   * <p>The background scheduler owns durable scheduler timestamps and backoff state. This callback
   * lets uninstall and missing-app cleanup reset that scheduler-owned metadata together with the
   * service-owned candidate, policy, staged, and history state.
   */
  @FunctionalInterface
  public interface SchedulerStateCleaner {
    /**
     * Clears scheduler metadata for one app.
     *
     * @param appId normalized app id
     */
    void clearSchedulerState(String appId);
  }

  /**
   * Optional integrations used by advanced AppUpdateService embeddings and tests.
   *
   * <p>Most callers should use the shorter constructors, which load the local review policy,
   * trusted reviewer keys, process migration runner, and disabled scheduler summary provider from
   * the daemon defaults. This record is for compositions that already own those dependencies, such
   * as the HTTP runtime after it creates a shared scheduler, or tests that need a deterministic
   * migration runner. The vault and app-data services remain nullable because they are optional
   * subsystem integrations; the other dependencies are required for safe update decisions.
   *
   * @param reviewPolicy local app-review policy
   * @param reviewerKeysProvider provider for trusted reviewer keys
   * @param appVaultService optional vault integration used to disable removed grants
   * @param appDataService optional durable app-data integration used by update migrations
   * @param migrationRunner app-data migration command runner
   * @param schedulerSummaryProvider path-free scheduler summary provider
   */
  public record AppUpdateDependencies(
      AppReviewPolicy reviewPolicy,
      ReviewerKeysProvider reviewerKeysProvider,
      AppVaultService appVaultService,
      AppDataService appDataService,
      AppDataMigrationRunner migrationRunner,
      SchedulerSummaryProvider schedulerSummaryProvider) {
    /** Creates validated AppUpdateService dependencies. */
    public AppUpdateDependencies {
      Objects.requireNonNull(reviewPolicy, "reviewPolicy");
      Objects.requireNonNull(reviewerKeysProvider, "reviewerKeysProvider");
      Objects.requireNonNull(migrationRunner, "migrationRunner");
      Objects.requireNonNull(schedulerSummaryProvider, "schedulerSummaryProvider");
    }
  }

  /**
   * Attaches the scheduler summary provider used by later update summaries.
   *
   * <p>The method is synchronized to coordinate with the service's summary path. It changes only
   * display metadata; it does not start background work, check catalogs, stage updates, apply
   * bundles, or alter per-app update policy.
   *
   * @param schedulerSummaryProvider provider for scheduler state
   */
  public synchronized void setSchedulerSummaryProvider(
      SchedulerSummaryProvider schedulerSummaryProvider) {
    this.schedulerSummaryProvider =
        Objects.requireNonNull(schedulerSummaryProvider, "schedulerSummaryProvider");
  }

  /** Attaches the host-owned catalog/app reviewer-scope policy used by later candidate checks. */
  public synchronized void setCatalogScopedReviewerPolicy(
      CatalogScopedReviewerPolicy catalogScopedReviewerPolicy) {
    catalogAuthority.setScopedReviewerPolicy(catalogScopedReviewerPolicy);
    candidates.clear();
    for (String appId : List.copyOf(stagedUpdates.keySet())) {
      closeStage(appId);
    }
  }

  /** Returns the shared local reviewer-scope policy for direct catalog mutation gates. */
  public synchronized Optional<CatalogScopedReviewerPolicy> catalogScopedReviewerPolicy() {
    return catalogAuthority.scopedReviewerPolicy();
  }

  /** Attaches the host-owned exact-subject conflict policy used by later candidate checks. */
  public synchronized void setFederatedCatalogConflictPolicy(
      AppUpdateFederationAuthority federationAuthority) {
    federatedConflictPolicy.set(Objects.requireNonNull(federationAuthority, "federationAuthority"));
    candidates.clear();
  }

  /**
   * Revokes an exact existing scope through the shared native authorization stores.
   *
   * <p>This host-operator operation accepts no replacement authorization. App principals cannot
   * reach it through the app API; the operator router enforces principal and federation guards.
   *
   * @param kind either publisher or reviewer
   * @param request exact current record and bounded audit decision
   * @return path-free acknowledgement of the terminal scope change
   * @throws IOException if policy persistence fails
   */
  public Map<String, Object> revokeCatalogScope(String kind, CatalogScopeRevocation request)
      throws IOException {
    String selfDigest;
    if ("publisher".equals(kind)) {
      selfDigest = requireFederatedConflictPolicy().revokePublisherScope(request).selfDigest();
    } else if ("reviewer".equals(kind)) {
      selfDigest =
          catalogScopedReviewerPolicy()
              .orElseThrow(
                  () ->
                      lifecycleFailure(
                          503,
                          "catalog_federation_unavailable",
                          "Catalog federation is unavailable."))
              .revoke(request)
              .selfDigest();
    } else {
      throw lifecycleFailure(400, "invalid_request", "Scope kind is invalid.");
    }
    return Map.of(
        JSON_CATALOG_ID,
        request.catalogId(),
        "scopeId",
        request.scopeId(),
        "scopeKind",
        kind,
        JSON_STATUS,
        "revoked",
        "previousDigestSha256",
        request.expectedDigestSha256(),
        "selfDigestSha256",
        selfDigest);
  }

  /** Returns the exact current cross-catalog conflict set for one app namespace. */
  public synchronized Map<String, Object> federatedConflict(String appId) {
    String normalizedAppId = AppCatalogEntry.normalizeAppId(appId);
    return requireFederatedConflictPolicy()
        .conflicts()
        .summary(currentFederatedConflictCandidates(normalizedAppId), this::conflictSecurityDigest);
  }

  /** Records one operator decision only when it binds the exact current conflict subjects. */
  public synchronized Map<String, Object> resolveFederatedConflict(
      String appId,
      String expectedConflictId,
      String expectedSubjectSetDigest,
      String kind,
      String catalogId,
      String publisherFingerprint,
      String reason) {
    String normalizedAppId = AppCatalogEntry.normalizeAppId(appId);
    Map<String, Object> summary =
        requireFederatedConflictPolicy()
            .conflicts()
            .resolve(
                currentFederatedConflictCandidates(normalizedAppId),
                this::conflictSecurityDigest,
                AppUpdateFederationAuthority.conflictResolutionRequest(
                    expectedConflictId,
                    expectedSubjectSetDigest,
                    kind,
                    catalogId,
                    publisherFingerprint,
                    reason));
    candidates.remove(normalizedAppId);
    closeStage(normalizedAppId);
    return summary;
  }

  /**
   * Applies the lifecycle service's exact-subject conflict authority to a direct catalog mutation.
   *
   * <p>The caller invokes this from the AppHost mutation-authorization boundary after the retained
   * catalog plan has been reverified. Every currently authenticated catalog subject for the app is
   * classified, and any stored resolution must bind the exact current conflict set and select this
   * exact plan. Legacy nodes retain their existing direct mutation behavior.
   *
   * @param selectedPlan exact retained plan proposed by the direct catalog route
   * @param installed installed snapshot when the current manifest could be inspected
   */
  public void requireDirectCatalogMutationAllowed(
      AppCatalogInstallPlan selectedPlan, InstalledAppSnapshot installed) {
    requireDirectCatalogMutationAllowed(selectedPlan, installed, false);
  }

  /**
   * Applies the exact-subject conflict authority with an already verified source-switch decision.
   *
   * <p>The explicit-switch flag is accepted only for an applicable {@code
   * EXPLICIT_SOURCE_SWITCH_REQUIRED} resolution that binds the complete current conflict set and
   * contains the selected plan's exact catalog subject. The caller must set it only after checking
   * the digest produced by the source-switch preview.
   *
   * @param selectedPlan exact retained plan proposed for mutation
   * @param installed installed snapshot when the current manifest could be inspected
   * @param explicitSourceSwitchAuthorized whether exact source-switch consent was verified
   */
  public void requireDirectCatalogMutationAllowed(
      AppCatalogInstallPlan selectedPlan,
      InstalledAppSnapshot installed,
      boolean explicitSourceSwitchAuthorized) {
    Objects.requireNonNull(selectedPlan, "selectedPlan");
    if (!catalogManager.federationEnabled()) {
      return;
    }
    List<AppUpdateCandidate> subjects =
        catalogAuthority.catalogConflictCandidates(selectedPlan.entry().appId(), installed);
    AppUpdateCandidate selected =
        conflictCandidateFor(selectedPlan.catalogId(), selectedPlan.entry(), installed);
    boolean selectedIsInstalledOrigin = selectedIsInstalledOrigin(selected);
    if (!requireFederatedConflictPolicy()
        .conflicts()
        .authorizes(
            subjects,
            selected,
            selectedIsInstalledOrigin,
            explicitSourceSwitchAuthorized,
            this::conflictSecurityDigest)) {
      throw lifecycleFailure(
          409,
          "catalog_conflict_unresolved",
          "The current cross-catalog conflict decision does not authorize this exact subject.");
    }
  }

  private AppHost.CatalogMutationAuthorizationLease retainDirectCatalogConflictAuthorization(
      AppCatalogInstallPlan selectedPlan,
      InstalledAppSnapshot installed,
      boolean explicitSourceSwitchAuthorized)
      throws IOException {
    List<AppUpdateCandidate> conflictCandidates =
        catalogAuthority.catalogConflictCandidates(selectedPlan.entry().appId(), installed);
    AppUpdateFederationAuthority policy = requireFederatedConflictPolicy();
    AppUpdateCandidate selected =
        conflictCandidateFor(selectedPlan.catalogId(), selectedPlan.entry(), installed);
    return policy
        .conflicts()
        .retainAuthorization(
            conflictCandidates,
            selected,
            selectedIsInstalledOrigin(selected),
            explicitSourceSwitchAuthorized,
            this::conflictSecurityDigest);
  }

  /**
   * Retains the exact conflict, publisher, and reviewer policies for a direct catalog host
   * mutation.
   *
   * <p>The caller must already retain the catalog-manager authorization lease. The returned lease
   * keeps the local conflict decision and both independent scoped policy stores stable until
   * AppHost has durably committed or compensated the bundle/provenance mutation. Publisher and
   * reviewer authorization leases are acquired before the complete cross-catalog subject set is
   * constructed, so a nonselected catalog cannot change either policy between classification and
   * retention.
   *
   * @param plan exact retained catalog plan proposed for mutation
   * @param installed current installed snapshot, empty for a new installation
   * @param targetOrigin exact provenance that AppHost will commit with the bundle
   * @return composite same-thread lease for conflict, publisher, and reviewer policy
   * @throws IOException if local policy cannot be read or retained
   */
  public AppHost.CatalogMutationAuthorizationLease retainDirectCatalogPolicyAuthorization(
      AppCatalogInstallPlan plan, InstalledAppSnapshot installed, InstalledAppOrigin targetOrigin)
      throws IOException {
    return retainDirectCatalogPolicyAuthorization(plan, installed, targetOrigin, false);
  }

  /** Retains conflict, publisher, and reviewer policy through one exact direct host mutation. */
  public AppHost.CatalogMutationAuthorizationLease retainDirectCatalogPolicyAuthorization(
      AppCatalogInstallPlan plan,
      InstalledAppSnapshot installed,
      InstalledAppOrigin targetOrigin,
      boolean explicitSourceSwitchAuthorized)
      throws IOException {
    Objects.requireNonNull(plan, "plan");
    InstalledAppOrigin checkedOrigin = Objects.requireNonNull(targetOrigin, "targetOrigin");
    if (!catalogManager.federationEnabled()) {
      return () -> {};
    }
    AppUpdateFederationAuthority policy = requireFederatedConflictPolicy();
    AppHost.CatalogMutationAuthorizationLease publisherAuthorization =
        policy.retainRoutinePublisherAuthorization(plan, checkedOrigin);
    boolean publisherTransferred = false;
    try {
      AppHost.CatalogMutationAuthorizationLease reviewerAuthorization =
          retainRoutineReviewerAuthorization(plan, checkedOrigin, installed == null);
      boolean reviewerTransferred = false;
      try {
        AppHost.CatalogMutationAuthorizationLease conflictAuthorization =
            retainDirectCatalogConflictAuthorization(
                plan, installed, explicitSourceSwitchAuthorized);
        publisherTransferred = true;
        reviewerTransferred = true;
        return compositeAuthorizationLease(
            conflictAuthorization, reviewerAuthorization, publisherAuthorization);
      } finally {
        if (!reviewerTransferred) {
          reviewerAuthorization.close();
        }
      }
    } finally {
      if (!publisherTransferred) {
        publisherAuthorization.close();
      }
    }
  }

  private static AppHost.CatalogMutationAuthorizationLease compositeAuthorizationLease(
      AppHost.CatalogMutationAuthorizationLease conflictAuthorization,
      AppHost.CatalogMutationAuthorizationLease reviewerAuthorization,
      AppHost.CatalogMutationAuthorizationLease publisherAuthorization) {
    return () -> {
      try {
        conflictAuthorization.close();
      } finally {
        try {
          reviewerAuthorization.close();
        } finally {
          publisherAuthorization.close();
        }
      }
    };
  }

  /**
   * Attaches the scheduler-state cleanup callback used when app update state is cleared.
   *
   * <p>The callback is separate from summary rendering so embeddings that do not start a background
   * scheduler can keep the default no-op, while the HTTP runtime can remove durable scheduler
   * metadata for uninstalled apps.
   *
   * @param schedulerStateCleaner callback that clears scheduler metadata for an app
   */
  public synchronized void setSchedulerStateCleaner(SchedulerStateCleaner schedulerStateCleaner) {
    this.schedulerStateCleaner =
        Objects.requireNonNull(schedulerStateCleaner, "schedulerStateCleaner");
  }

  /**
   * Discards all local update lifecycle state for an app removed outside this service.
   *
   * <p>The existing app-management endpoint owns uninstall. When it removes an app, this method
   * closes any retained catalog staging plan and clears cached update metadata so catalog scratch
   * storage cannot leak and a later reinstall cannot inherit a stale reviewed candidate. The method
   * intentionally removes local policy, last-check, and history records as well because they
   * describe the removed installation rather than a future app with the same id.
   *
   * @param appId app id whose update state should be removed
   */
  public synchronized void clearAppState(String appId) {
    String normalizedAppId = normalizeInstalledAppId(appId);
    closeStage(normalizedAppId);
    candidates.remove(normalizedAppId);
    policies.remove(normalizedAppId);
    lastChecks.remove(normalizedAppId);
    history.remove(normalizedAppId);
    schedulerStateCleaner.clearSchedulerState(normalizedAppId);
  }

  /**
   * Returns the current update lifecycle summary for one app.
   *
   * <p>The summary includes the installed version, running state, policy, candidate, staged update,
   * rollback availability, last check, scheduler state, and recent history. It also performs
   * stale-state cleanup: if the app was updated or removed outside this service, incompatible
   * staged plans are closed before the response is built.
   *
   * @param appId app id from the request path
   * @return path-free update summary safe for Platform API responses
   */
  public synchronized Map<String, Object> summary(String appId) {
    String normalizedAppId = normalizeInstalledAppId(appId);
    InstalledAppSnapshot installed = requireInstalled(normalizedAppId);
    return summary(normalizedAppId, installed);
  }

  /**
   * Detects the current catalog update candidate for operator consent without following policy.
   *
   * <p>This path is used by the unified consent preview. It refreshes and stores the same path-free
   * candidate summary as {@link #check(String, boolean)}, but it deliberately does not invoke
   * policy-driven stage or apply. Consent review therefore cannot cause an unattended update as a
   * side effect.
   *
   * @param appId app id from the request path
   * @param refreshCatalogs whether to refresh catalog sidecars before detection
   * @return path-free update summary with the detected candidate
   */
  public synchronized Map<String, Object> preview(String appId, boolean refreshCatalogs) {
    String normalizedAppId = normalizeInstalledAppId(appId);
    InstalledAppSnapshot installed = requireInstalled(normalizedAppId);
    AppUpdateCandidate candidate = detectCandidate(normalizedAppId, installed, refreshCatalogs);
    candidates.put(normalizedAppId, candidate);
    invalidateStaleStage(normalizedAppId, candidate);
    return summary(normalizedAppId, installed);
  }

  /**
   * Detects the current catalog update candidate without mutating candidate or staged state.
   *
   * <p>GET consent previews use this path so an operator refresh cannot invalidate an existing
   * staged update or write cached candidate state without the form-password guard. The response
   * still includes the currently staged summary, last check, scheduler status, and history, but the
   * candidate object comes from a fresh in-memory detection pass.
   *
   * @param appId app id from the request path
   * @return path-free update summary with the detected candidate and no state writes
   */
  public synchronized Map<String, Object> previewReadOnly(String appId) {
    String normalizedAppId = normalizeInstalledAppId(appId);
    InstalledAppSnapshot installed = requireInstalled(normalizedAppId);
    AppUpdateCandidate candidate = detectCandidate(normalizedAppId, installed, false);
    return summaryReadOnly(normalizedAppId, installed, candidate);
  }

  /**
   * Detects the current catalog update candidate and prepares migration metadata for consent.
   *
   * <p>This method may prepare and immediately close the candidate install plan so it can inspect
   * the signed target manifest and build the same path-free migration summary that staging later
   * revalidates. It does not stage, dry-run, apply, retain catalog scratch paths, or change update
   * policy. Transport bridges should expose this only through form-password guarded host/operator
   * routes because preparing the candidate can consume catalog and bundle resources.
   *
   * @param appId app id from the request path
   * @param refreshCatalogs whether to refresh catalog sidecars before detection
   * @return path-free update summary with consent-ready migration metadata when available
   */
  public synchronized Map<String, Object> previewForConsent(String appId, boolean refreshCatalogs) {
    String normalizedAppId = normalizeInstalledAppId(appId);
    InstalledAppSnapshot installed = requireInstalled(normalizedAppId);
    AppUpdateCandidate candidate = detectCandidate(normalizedAppId, installed, refreshCatalogs);
    candidate = candidateWithConsentMigrationPlan(normalizedAppId, installed, candidate);
    candidates.put(normalizedAppId, candidate);
    invalidateStaleStage(normalizedAppId, candidate);
    return summary(normalizedAppId, installed);
  }

  /**
   * Detects the current catalog update candidate and applies the configured policy.
   *
   * <p>Candidate detection starts from verified catalog snapshots. If refresh is requested, catalog
   * refresh failures are contained to that catalog and the last known verified snapshot remains in
   * use. The method records both successful and failed attempts in {@code lastCheck}. Policy may
   * stage or apply an eligible candidate, but manual policy only records the candidate.
   *
   * @param appId app id from the request path
   * @param refreshCatalogs whether to refresh catalog sidecars before detection
   * @return path-free update summary after detection and policy handling
   */
  public synchronized Map<String, Object> check(String appId, boolean refreshCatalogs) {
    String normalizedAppId = normalizeInstalledAppId(appId);
    Instant checkedAt = Instant.now();
    AppUpdateCandidate candidate = null;
    try {
      InstalledAppSnapshot installed = requireInstalled(normalizedAppId);
      candidate = detectCandidate(normalizedAppId, installed, refreshCatalogs);
      candidates.put(normalizedAppId, candidate);
      invalidateStaleStage(normalizedAppId, candidate);
      followPolicyAfterCheck(normalizedAppId, installed, candidate);
      recordLastCheck(normalizedAppId, checkedAt, null, null);
      appendHistory(
          normalizedAppId,
          ACTION_CHECK,
          STATUS_SUCCESS,
          candidate.catalogId(),
          candidate.targetVersion(),
          null,
          "Update candidate check completed.");
      return summary(normalizedAppId, requireInstalled(normalizedAppId));
    } catch (PlatformApiException exception) {
      recordLastCheck(
          normalizedAppId, checkedAt, exception.errorCode(), "Update candidate check failed.");
      appendHistory(
          normalizedAppId,
          ACTION_CHECK,
          STATUS_FAILED,
          candidate == null ? null : candidate.catalogId(),
          candidate == null ? null : candidate.targetVersion(),
          exception.errorCode(),
          "Update candidate check failed.");
      throw exception;
    }
  }

  /**
   * Stages a verified catalog update candidate for later explicit apply.
   *
   * <p>Staging uses {@link AppCatalogManager#prepareInstallPlan(String, String)} so the catalog
   * manager still owns download, extraction, signature verification, and scratch cleanup. The
   * prepared plan must match the reviewed candidate metadata before it is retained. The returned
   * summary never includes the staged directory or catalog scratch path.
   *
   * @param appId app id from the request path
   * @return path-free update summary after a verified candidate is staged
   */
  public synchronized Map<String, Object> stage(String appId) {
    return stage(appId, false);
  }

  /**
   * Stages a verified catalog update candidate with an explicit review acknowledgement option.
   *
   * @param appId app id from the request path
   * @param reviewAcknowledged whether the operator acknowledged an untrusted review decision
   * @return path-free update summary after a verified candidate is staged
   */
  public synchronized Map<String, Object> stage(String appId, boolean reviewAcknowledged) {
    return stage(appId, reviewAcknowledged, false);
  }

  /**
   * Stages a verified catalog update candidate with explicit review and migration acknowledgement
   * options.
   *
   * @param appId app id from the request path
   * @param reviewAcknowledged whether the operator acknowledged an untrusted review decision
   * @param migrationAcknowledged whether the operator acknowledged rollback-incompatible migration
   *     risk
   * @return path-free update summary after a verified candidate is staged
   */
  public synchronized Map<String, Object> stage(
      String appId, boolean reviewAcknowledged, boolean migrationAcknowledged) {
    return stage(appId, reviewAcknowledged, false, migrationAcknowledged);
  }

  /**
   * Stages a verified catalog update candidate with explicit review, security, and migration
   * acknowledgement options.
   *
   * @param appId app id from the request path
   * @param reviewAcknowledged whether the operator acknowledged an untrusted review decision
   * @param securityAcknowledged whether the operator acknowledged warning-level security advisory
   * @param migrationAcknowledged whether the operator acknowledged rollback-incompatible migration
   *     risk
   * @return path-free update summary after a verified candidate is staged
   */
  public synchronized Map<String, Object> stage(
      String appId,
      boolean reviewAcknowledged,
      boolean securityAcknowledged,
      boolean migrationAcknowledged) {
    return stage(appId, reviewAcknowledged, securityAcknowledged, migrationAcknowledged, null);
  }

  /**
   * Stages a verified candidate with an exact source-switch consent digest when one is required.
   */
  public synchronized Map<String, Object> stage(
      String appId,
      boolean reviewAcknowledged,
      boolean securityAcknowledged,
      boolean migrationAcknowledged,
      String sourceSwitchConsent) {
    return stage(
        appId,
        reviewAcknowledged,
        securityAcknowledged,
        migrationAcknowledged,
        sourceSwitchConsent,
        null);
  }

  /** Stages an explicitly selected catalog candidate under an exact source-switch consent. */
  public synchronized Map<String, Object> stage(
      String appId,
      boolean reviewAcknowledged,
      boolean securityAcknowledged,
      boolean migrationAcknowledged,
      String sourceSwitchConsent,
      String targetCatalogId) {
    String normalizedAppId = normalizeInstalledAppId(appId);
    InstalledAppSnapshot installed = requireInstalled(normalizedAppId);
    AppUpdateCandidate candidate =
        targetCatalogId == null
            ? candidateOrDetect(normalizedAppId, installed)
            : explicitSourceSwitchCandidate(
                normalizedAppId, installed, targetCatalogId, sourceSwitchConsent);
    try {
      requireStageableCandidate(
          candidate, reviewAcknowledged, securityAcknowledged, targetCatalogId != null);
      catalogAuthority.recordUpdateGate(candidate, "explicit_stage_allowed");
    } catch (PlatformApiException exception) {
      catalogAuthority.recordUpdateGate(
          candidate, "explicit_stage_blocked:" + exception.errorCode());
      throw exception;
    }
    stageCandidate(
        normalizedAppId,
        installed,
        candidate,
        migrationAcknowledged,
        sourceSwitchConsent,
        targetCatalogId != null);
    return summary(normalizedAppId, installed);
  }

  private AppUpdateCandidate explicitSourceSwitchCandidate(
      String appId,
      InstalledAppSnapshot installed,
      String targetCatalogId,
      String sourceSwitchConsent) {
    if (sourceSwitchConsent == null || sourceSwitchConsent.isBlank()) {
      throw lifecycleFailure(
          409,
          ERROR_CATALOG_SOURCE_SWITCH_CONSENT_REQUIRED,
          "An explicit target catalog requires an exact source-switch preview.");
    }
    if (installedCatalogOrigin(appId).isEmpty()) {
      throw lifecycleFailure(
          409,
          ERROR_CATALOG_SOURCE_SWITCH_CONSENT_REQUIRED,
          "An explicit target catalog requires an installed catalog origin and exact preview.");
    }
    String normalizedTarget;
    try {
      normalizedTarget = CatalogSourceSwitchConsent.normalizeTargetCatalogId(targetCatalogId);
    } catch (AppCatalogException _) {
      throw lifecycleFailure(400, "invalid_catalog_id", "Target catalog ID is invalid.");
    }
    AppUpdateCandidate selected =
        catalogAuthority.explicitCatalogCandidate(
            appId, installed, policyFor(appId), normalizedTarget);
    if (selected == null) {
      throw lifecycleFailure(
          409,
          "catalog_source_switch_target_unavailable",
          "The explicitly selected target catalog is unavailable for this app.");
    }
    candidates.put(appId, selected);
    return selected;
  }

  /**
   * Applies the currently staged update candidate.
   *
   * <p>Apply refuses stale staged plans, incompatible candidates, and running apps unless restart
   * choreography was explicitly requested. When restart and process health are requested, a launch
   * failure or missing running status is treated as a health failure; optional rollback is
   * attempted only after AppHost has committed the new bundle and reports a rollback record.
   * Successful apply clears staged state and records an applied candidate.
   *
   * @param appId app id from the request path
   * @param options apply options decoded from query parameters
   * @return path-free update summary after apply or post-apply cleanup
   */
  public synchronized Map<String, Object> apply(String appId, ApplyOptions options) {
    String normalizedAppId = normalizeInstalledAppId(appId);
    InstalledAppSnapshot installed = requireInstalled(normalizedAppId);
    StagedUpdate staged = requireStagedUpdate(normalizedAppId);
    boolean wasRunning =
        validateApplyRequestAndRecordGate(normalizedAppId, staged, installed, options);

    InstalledAppSnapshot updated = null;
    HealthFailureState healthFailureState = new HealthFailureState();
    AppDataUpdateSnapshot appDataSnapshot = null;
    AppDataService.UpdateMigrationWriteBarrier appDataWriteBarrier = null;
    AppDataMigrationPlan migrationPlan = staged.migrationPlan();
    boolean vaultCleanupFailed;
    try {
      if (wasRunning) {
        appHost.stop(normalizedAppId);
      }
      verifyStageStillMatchesInstalledForApply(normalizedAppId, staged, installed);
      verifyStagedBundleBeforeApply(staged);
      AppManifest targetManifest = stagedManifestForApplyOrReject(staged);
      revalidateSourceSwitchAuthorizationForApply(normalizedAppId, staged);
      requireCurrentStagedReviewDecision(normalizedAppId, staged);
      if (shouldHoldApplyMigrationWriteBarrier(targetManifest)) {
        appDataWriteBarrier = beginUpdateMigrationWriteBarrier(normalizedAppId);
      }
      migrationPlan =
          refreshMigrationPlanForApply(normalizedAppId, staged, installed, targetManifest);
      if (migrationPlan.required()) {
        if (appDataWriteBarrier == null) {
          appDataWriteBarrier = beginUpdateMigrationWriteBarrier(normalizedAppId);
        }
        appDataSnapshot = createUpdateSnapshot(normalizedAppId);
        migrationPlan = migrationPlan.withSnapshotCreated();
      }
      requireCurrentStagedReviewDecision(normalizedAppId, staged);
      InstalledAppOrigin targetOrigin = catalogOrigin(staged);
      updated =
          targetOrigin == null
              ? appHost.updateFromDirectory(normalizedAppId, staged.stagedBundleDirectory())
              : appHost.updateCatalogFromDirectory(
                  normalizedAppId,
                  staged.stagedBundleDirectory(),
                  targetOrigin,
                  staged.sourceSwitchAuthorization().expectedCurrentOriginExpectation(),
                  catalogMutationAuthorization(
                      staged.plan(),
                      staged
                          .sourceSwitchAuthorization()
                          .approvedConsentDigestSha256()
                          .isPresent()));
      if (migrationPlan.required()) {
        runApplyMigrationOrRollback(
            normalizedAppId, updated, migrationPlan, appDataSnapshot, healthFailureState);
        migrationPlan = migrationPlan.applied();
      }
      if (options.restart()) {
        startOrTreatAsHealthFailure(normalizedAppId, options, healthFailureState);
      }
      verifyHealthOrRollback(normalizedAppId, options, healthFailureState);
      discardUpdateSnapshot(appDataSnapshot);
      vaultCleanupFailed = !disableVaultGrantsAfterCommittedUpdate(updated, healthFailureState);
      closeStage(normalizedAppId);
      candidates.put(normalizedAppId, appliedCandidate(staged.candidate(), updated, migrationPlan));
      appendHistory(
          normalizedAppId,
          ACTION_APPLY,
          STATUS_SUCCESS,
          staged.candidate().catalogId(),
          staged.candidate().targetVersion(),
          null,
          vaultCleanupFailed ? MESSAGE_APPLY_VAULT_CLEANUP_FAILED : "Staged update applied.");
      catalogAuthority.recordPolicyApplyGate(staged.candidate(), "explicit_apply_applied");
      return summary(normalizedAppId, updated);
    } catch (PlatformApiException exception) {
      handlePlatformApplyFailure(
          new ApplyFailureContext(
              normalizedAppId,
              staged,
              wasRunning,
              installed,
              updated,
              healthFailureState,
              appDataSnapshot,
              migrationPlan));
      recordApplyFailure(normalizedAppId, staged.candidate(), exception.errorCode());
      throw exception;
    } catch (AppHostException exception) {
      PlatformApiException mapped =
          handleAppHostApplyFailure(
              new ApplyFailureContext(
                  normalizedAppId,
                  staged,
                  wasRunning,
                  installed,
                  updated,
                  healthFailureState,
                  appDataSnapshot,
                  migrationPlan),
              exception);
      recordApplyFailure(normalizedAppId, staged.candidate(), mapped.errorCode());
      throw mapped;
    } catch (IOException _) {
      handleIoApplyFailure(
          new ApplyFailureContext(
              normalizedAppId,
              staged,
              wasRunning,
              installed,
              updated,
              healthFailureState,
              appDataSnapshot,
              migrationPlan));
      recordApplyFailure(normalizedAppId, staged.candidate(), ERROR_UPDATE_FAILED);
      throw lifecycleFailure(500, ERROR_UPDATE_FAILED, MESSAGE_APPLY_FAILED);
    } finally {
      closeUpdateMigrationWriteBarrier(appDataWriteBarrier);
    }
  }

  private boolean validateApplyRequestAndRecordGate(
      String appId, StagedUpdate staged, InstalledAppSnapshot installed, ApplyOptions options) {
    try {
      boolean wasRunning = validateApplyRequest(appId, staged, installed, options);
      catalogAuthority.recordPolicyApplyGate(staged.candidate(), "explicit_apply_allowed");
      return wasRunning;
    } catch (PlatformApiException exception) {
      catalogAuthority.recordPolicyApplyGate(
          staged.candidate(), "explicit_apply_blocked:" + exception.errorCode());
      throw exception;
    }
  }

  private void handlePlatformApplyFailure(ApplyFailureContext context) {
    closeStage(context.appId());
    if (shouldRestoreSnapshotAfterRollback(context)) {
      restoreSnapshotOrThrow(
          context.appId(), context.appDataSnapshot(), context.healthFailureState());
    }
    if (context.updated() != null) {
      restartOriginalAfterCommittedRollbackApplyFailure(context);
      disableVaultGrantsAfterCommittedUpdate(context.updated(), context.healthFailureState());
      updateCandidateAfterPostApplyFailure(
          context.appId(),
          context.staged().candidate(),
          context.updated(),
          context.healthFailureState(),
          context.migrationPlan());
      return;
    }
    restartOriginalAfterUncommittedApplyFailure(
        context.appId(), context.wasRunning(), context.original(), null);
  }

  private boolean shouldRestoreSnapshotAfterRollback(ApplyFailureContext context) {
    return context.updated() != null
        && context.healthFailureState().rollbackCommitted()
        && !context.healthFailureState().appDataRestored()
        && context.appDataSnapshot() != null;
  }

  private PlatformApiException handleAppHostApplyFailure(
      ApplyFailureContext context, AppHostException exception) {
    restartOriginalAfterUncommittedApplyFailure(
        context.appId(), context.wasRunning(), context.original(), context.updated());
    return appHostApplyFailure(
        context.appId(),
        context.staged(),
        context.updated(),
        context.healthFailureState(),
        context.migrationPlan(),
        exception);
  }

  private void handleIoApplyFailure(ApplyFailureContext context) {
    if (context.updated() != null) {
      disableVaultGrantsAfterCommittedUpdate(context.updated(), context.healthFailureState());
      closeStage(context.appId());
      updateCandidateAfterPostApplyFailure(
          context.appId(),
          context.staged().candidate(),
          context.updated(),
          context.healthFailureState(),
          context.migrationPlan());
      return;
    }
    restartOriginalAfterUncommittedApplyFailure(
        context.appId(), context.wasRunning(), context.original(), null);
  }

  private StagedUpdate requireStagedUpdate(String appId) {
    StagedUpdate staged = stagedUpdates.get(appId);
    if (staged == null) {
      throw lifecycleFailure(409, ERROR_UPDATE_NOT_STAGED, "No staged update is available.");
    }
    return staged;
  }

  private boolean validateApplyRequest(
      String appId, StagedUpdate staged, InstalledAppSnapshot installed, ApplyOptions options) {
    if (!staged.candidate().eligibleByDefault() && !stagedExplicitSameVersionSwitch(staged)) {
      throw lifecycleFailure(
          409, ERROR_UPDATE_POLICY_BLOCKED, "The staged update is not eligible by default.");
    }
    requireCurrentStagedSecurityDecision(appId, staged);
    if (stageDiffersFromInstalled(staged, installed)) {
      closeStage(appId);
      candidates.remove(appId);
      appendHistory(
          appId,
          ACTION_APPLY,
          STATUS_FAILED,
          staged.candidate().catalogId(),
          staged.candidate().targetVersion(),
          ERROR_UPDATE_CANDIDATE_CHANGED,
          MESSAGE_STAGED_UPDATE_NO_LONGER_MATCHES);
      throw lifecycleFailure(
          409,
          ERROR_UPDATE_CANDIDATE_CHANGED,
          "Installed app version changed since the update was staged.");
    }
    AppDataMigrationPlan migrationPlan = staged.migrationPlan();
    if (!migrationPlan.readyForApply()) {
      String errorCode =
          migrationPlan.blockReason() == null
              ? ERROR_APP_DATA_MIGRATION_DRY_RUN_FAILED
              : migrationPlan.blockReason();
      throw lifecycleFailure(409, errorCode, "App-data migration is not ready to apply.");
    }
    boolean wasRunning = appHost.status(appId).isPresent();
    if (wasRunning && !options.restart()) {
      throw lifecycleFailure(409, ERROR_APP_RUNNING, "App must be stopped before update.");
    }
    if (!options.restart() && options.healthCheck() == HealthCheckMode.PROCESS) {
      throw lifecycleFailure(
          400, ERROR_INVALID_UPDATE_OPTION, "healthCheck=process requires restart=true.");
    }
    return wasRunning;
  }

  private void requireCurrentStagedSecurityDecision(String appId, StagedUpdate staged) {
    Map<String, Object> currentDecision =
        targetSecurityDecision(staged.candidate().catalogId(), staged.entry());
    if (stagedSecurityDecisionStillAllowsApply(staged, currentDecision)) {
      return;
    }
    closeStage(appId);
    candidates.remove(appId);
    String errorCode =
        securityGateRequiresOperator(currentDecision)
            ? securityGateFailureCode(currentDecision)
            : ERROR_UPDATE_CANDIDATE_CHANGED;
    appendHistory(
        appId,
        ACTION_APPLY,
        STATUS_FAILED,
        staged.candidate().catalogId(),
        staged.candidate().targetVersion(),
        errorCode,
        "Staged update security policy changed before apply.");
    throw lifecycleFailure(
        409, errorCode, "Staged update security policy changed; check for updates again.");
  }

  private void requireCurrentStagedReviewDecision(String appId, StagedUpdate staged) {
    Map<String, Object> currentDecision =
        reviewTrust(staged.candidate().catalogId(), staged.entry());
    if (staged.candidate().reviewTrust().equals(currentDecision)) {
      return;
    }
    closeStage(appId);
    candidates.remove(appId);
    boolean requiresOperator =
        Boolean.TRUE.equals(currentDecision.get(JSON_BLOCKS_UPDATE))
            || Boolean.TRUE.equals(currentDecision.get(JSON_BLOCKS_POLICY_APPLY))
            || Boolean.TRUE.equals(currentDecision.get(JSON_REQUIRES_ACKNOWLEDGEMENT));
    String errorCode =
        requiresOperator ? reviewGateFailureCode(currentDecision) : ERROR_UPDATE_CANDIDATE_CHANGED;
    appendHistory(
        appId,
        ACTION_APPLY,
        STATUS_FAILED,
        staged.candidate().catalogId(),
        staged.candidate().targetVersion(),
        errorCode,
        "Staged update reviewer policy changed before apply.");
    throw lifecycleFailure(
        409, errorCode, "Staged update reviewer policy changed; check for updates again.");
  }

  private static boolean stagedSecurityDecisionStillAllowsApply(
      StagedUpdate staged, Map<String, Object> currentDecision) {
    boolean securityDecisionUnchanged =
        staged.candidate().securityDecision().equals(currentDecision);
    return securityDecisionUnchanged
        && (securityDecisionAllowsAutomaticApply(currentDecision)
            || !Boolean.TRUE.equals(currentDecision.get(JSON_BLOCKS_UPDATE)));
  }

  private void verifyStageStillMatchesInstalledForApply(
      String appId, StagedUpdate staged, InstalledAppSnapshot installed) {
    if (stageDiffersFromInstalled(staged, installed)) {
      closeStage(appId);
      candidates.remove(appId);
      appendHistory(
          appId,
          ACTION_APPLY,
          STATUS_FAILED,
          staged.candidate().catalogId(),
          staged.candidate().targetVersion(),
          ERROR_UPDATE_CANDIDATE_CHANGED,
          MESSAGE_STAGED_UPDATE_NO_LONGER_MATCHES);
      throw lifecycleFailure(
          409,
          ERROR_UPDATE_CANDIDATE_CHANGED,
          "Installed app version changed since the update was staged.");
    }
  }

  private AppDataMigrationPlan refreshMigrationPlanForApply(
      String appId,
      StagedUpdate staged,
      InstalledAppSnapshot installed,
      AppManifest targetManifest) {
    AppDataMigrationPlan refreshedPlan =
        AppUpdateMigrationPlanner.buildPlan(
            appDataService, appId, installed.manifest(), targetManifest);
    requireApplicableMigrationPlan(staged.migrationPlan(), refreshedPlan, targetManifest);
    if (refreshedPlan.required()) {
      AppDataMigrationRunner.MigrationExecutionResult dryRunResult =
          runApplyDryRunOrReject(staged, refreshedPlan, targetManifest);
      if (!dryRunResult.success()) {
        throw lifecycleFailure(
            409,
            ERROR_APP_DATA_MIGRATION_DRY_RUN_FAILED,
            MESSAGE_APP_DATA_MIGRATION_DRY_RUN_FAILED);
      }
      verifyStagedBundleAfterApplyDryRun(staged);
    }
    return refreshedPlan;
  }

  private boolean shouldHoldApplyMigrationWriteBarrier(AppManifest targetManifest) {
    return appDataService != null && targetManifest.dataSchemaContract().declared();
  }

  private void verifyStagedBundleBeforeApply(StagedUpdate staged) {
    try {
      catalogManager.verifyInstallPlan(staged.plan);
    } catch (AppCatalogException exception) {
      throw catalogFailure(exception);
    } catch (IOException _) {
      throw lifecycleFailure(500, ERROR_UPDATE_FAILED, MESSAGE_APPLY_FAILED);
    }
  }

  private void verifyStagedBundleAfterApplyDryRun(StagedUpdate staged) {
    verifyStagedBundleBeforeApply(staged);
  }

  private AppManifest stagedManifestForApplyOrReject(StagedUpdate staged) {
    try {
      AppManifest manifest = AppUpdateBundleSupport.readManifest(staged.stagedBundleDirectory());
      requireStagedPlatformApiAdmission(staged.entry(), manifest);
      return manifest;
    } catch (IOException _) {
      throw lifecycleFailure(
          400, ERROR_INVALID_APP_BUNDLE, "Staged app bundle manifest is invalid.");
    }
  }

  private void requireApplicableMigrationPlan(
      AppDataMigrationPlan stagedPlan,
      AppDataMigrationPlan refreshedPlan,
      AppManifest targetManifest) {
    if (refreshedPlan.hasBlocker()) {
      throw lifecycleFailure(
          409, refreshedPlan.blockReason(), "App-data migration plan blocks this update.");
    }
    if (refreshedPlan.operatorReviewRequired()
        && !acknowledgedMigrationStepsMatch(stagedPlan, refreshedPlan)) {
      throw lifecycleFailure(
          409,
          ERROR_APP_DATA_MIGRATION_REVIEW_REQUIRED,
          "App-data migration requires explicit operator acknowledgement.");
    }
    requireMigrationExecutionAllowed(refreshedPlan, targetManifest);
  }

  private static boolean acknowledgedMigrationStepsMatch(
      AppDataMigrationPlan stagedPlan, AppDataMigrationPlan refreshedPlan) {
    return stagedPlan.operatorReviewRequired()
        && stagedPlan.namespaces().equals(refreshedPlan.namespaces());
  }

  private AppDataMigrationRunner.MigrationExecutionResult runApplyDryRunOrReject(
      StagedUpdate staged, AppDataMigrationPlan migrationPlan, AppManifest targetManifest) {
    try (AppDataMigrationRunner.MigrationDataAccess dataAccess =
        migrationDataAccess(staged.candidate().appId(), targetManifest)) {
      return migrationRunner.run(
          staged.stagedBundleDirectory(),
          migrationPlan,
          AppDataMigrationRunner.Mode.DRY_RUN,
          dataAccess);
    } catch (IOException | PlatformApiException _) {
      throw lifecycleFailure(
          409, ERROR_APP_DATA_MIGRATION_DRY_RUN_FAILED, MESSAGE_APP_DATA_MIGRATION_DRY_RUN_FAILED);
    }
  }

  private AppDataUpdateSnapshot createUpdateSnapshot(String appId) {
    if (appDataService == null) {
      throw lifecycleFailure(
          409,
          ERROR_APP_DATA_SNAPSHOT_FAILED,
          "App-data migration cannot snapshot durable app data.");
    }
    try {
      return appDataService.createUpdateSnapshot(appId);
    } catch (PlatformApiException exception) {
      String errorCode =
          "app_data_snapshot_too_large".equals(exception.errorCode())
              ? exception.errorCode()
              : ERROR_APP_DATA_SNAPSHOT_FAILED;
      throw lifecycleFailure(409, errorCode, "App-data update snapshot could not be created.");
    }
  }

  private AppDataService.UpdateMigrationWriteBarrier beginUpdateMigrationWriteBarrier(
      String appId) {
    if (appDataService == null) {
      throw lifecycleFailure(
          409,
          ERROR_APP_DATA_SNAPSHOT_FAILED,
          "App-data migration cannot block durable app-data writes.");
    }
    return appDataService.beginUpdateMigrationWriteBarrier(appId);
  }

  private static void closeUpdateMigrationWriteBarrier(
      AppDataService.UpdateMigrationWriteBarrier barrier) {
    if (barrier != null) {
      barrier.close();
    }
  }

  private void runApplyMigrationOrRollback(
      String appId,
      InstalledAppSnapshot updated,
      AppDataMigrationPlan migrationPlan,
      AppDataUpdateSnapshot snapshot,
      HealthFailureState healthFailureState) {
    AppDataMigrationRunner.MigrationExecutionResult result;
    try (AppDataMigrationRunner.MigrationDataAccess dataAccess = migrationDataAccess(appId)) {
      result =
          migrationRunner.run(
              updated.paths().installedRoot(),
              migrationPlan,
              AppDataMigrationRunner.Mode.APPLY,
              dataAccess);
    } catch (IOException | PlatformApiException _) {
      rollbackAndRestoreSnapshot(appId, snapshot, healthFailureState);
      throw lifecycleFailure(
          409,
          ERROR_APP_DATA_MIGRATION_APPLY_FAILED,
          "App-data migration apply failed; bundle rollback was attempted.");
    }
    if (result.success()) {
      return;
    }
    rollbackAndRestoreSnapshot(appId, snapshot, healthFailureState);
    throw lifecycleFailure(
        409,
        ERROR_APP_DATA_MIGRATION_APPLY_FAILED,
        "App-data migration apply failed; bundle rollback was attempted.");
  }

  private void rollbackAndRestoreSnapshot(
      String appId, AppDataUpdateSnapshot snapshot, HealthFailureState healthFailureState) {
    try {
      InstalledAppSnapshot rolledBack = invokeRollback(appId);
      healthFailureState.markRollbackCommitted(rolledBack);
    } catch (IOException _) {
      healthFailureState.markRollbackFailed();
      throw lifecycleFailure(
          500,
          ERROR_ROLLBACK_FAILED,
          "App-data migration failed and automatic bundle rollback failed.");
    }
    restoreSnapshotOrThrow(appId, snapshot, healthFailureState);
  }

  private void restoreSnapshotOrThrow(
      String appId, AppDataUpdateSnapshot snapshot, HealthFailureState healthFailureState) {
    if (snapshot == null || appDataService == null) {
      return;
    }
    try {
      appDataService.restoreUpdateSnapshot(appId, snapshot);
      healthFailureState.markAppDataRestored();
    } catch (PlatformApiException _) {
      throw lifecycleFailure(
          500,
          ERROR_APP_DATA_RESTORE_FAILED,
          "Bundle rollback completed, but app-data snapshot restore failed.");
    }
  }

  private void discardUpdateSnapshot(AppDataUpdateSnapshot snapshot) {
    if (snapshot != null && appDataService != null) {
      appDataService.discardUpdateSnapshot(snapshot);
    }
  }

  private void recordApplyFailure(String appId, AppUpdateCandidate candidate, String errorCode) {
    appendHistory(
        appId,
        ACTION_APPLY,
        STATUS_FAILED,
        candidate.catalogId(),
        candidate.targetVersion(),
        errorCode,
        MESSAGE_APPLY_FAILED);
    catalogAuthority.recordPolicyApplyGate(candidate, "apply_failed:" + errorCode);
  }

  private PlatformApiException appHostApplyFailure(
      String appId,
      StagedUpdate staged,
      InstalledAppSnapshot updated,
      HealthFailureState healthFailureState,
      AppDataMigrationPlan migrationPlan,
      AppHostException exception) {
    if (updated != null) {
      closeStage(appId);
      updateCandidateAfterPostApplyFailure(
          appId, staged.candidate(), updated, healthFailureState, migrationPlan);
      return lifecycleFailure(500, ERROR_UPDATE_FAILED, MESSAGE_APPLY_FAILED);
    }
    if (exception instanceof AppHostException.CatalogOriginChangedException) {
      clearRejectedStage(appId);
      return staleSourceSwitchAuthorization();
    }
    if (isRunningUpdateFailure(exception) || appHost.status(appId).isPresent()) {
      return lifecycleFailure(409, ERROR_APP_RUNNING, "App must be stopped before update.");
    }
    if (isMissingAppFailure(exception)) {
      clearAppState(appId);
      return appNotFound();
    }
    if (isSignedBundleVerificationFailure(exception) || isInvalidAppBundleFailure(exception)) {
      clearRejectedStage(appId);
      return lifecycleFailure(
          400, ERROR_INVALID_APP_BUNDLE, "Staged app bundle failed AppHost validation.");
    }
    return lifecycleFailure(500, ERROR_UPDATE_FAILED, MESSAGE_APPLY_FAILED);
  }

  private void clearRejectedStage(String appId) {
    closeStage(appId);
    candidates.remove(appId);
  }

  /**
   * Restores the previous installed bundle retained by AppHost.
   *
   * <p>Rollback operates on the immutable installed bundle only. App data, cache, and run
   * directories remain attached to the app id and are not reverted. A running app blocks rollback
   * unless restart choreography is explicitly allowed. If the bundle restore commits but the
   * post-rollback restart fails, the method reports that restart failure while leaving stale staged
   * update state cleared.
   *
   * @param appId app id from the request path
   * @param restart whether the service may stop and restart a running app
   * @return path-free update summary after rollback completes
   */
  public synchronized Map<String, Object> rollback(String appId, boolean restart) {
    String normalizedAppId = normalizeInstalledAppId(appId);
    Optional<RunningAppSnapshot> running = appHost.status(normalizedAppId);
    boolean wasRunning = running.isPresent();
    InstalledAppSnapshot original =
        running
            .map(snapshot -> new InstalledAppSnapshot(snapshot.manifest(), snapshot.paths()))
            .orElse(null);
    if (wasRunning && !restart) {
      throw lifecycleFailure(
          409, ERROR_ROLLBACK_APP_RUNNING, "App must be stopped before rollback.");
    }
    if (wasRunning) {
      requireRollbackAvailableBeforeStop(normalizedAppId);
    }
    try {
      if (wasRunning) {
        appHost.stop(normalizedAppId);
      }
      InstalledAppSnapshot rolledBack = invokeRollback(normalizedAppId);
      closeStage(normalizedAppId);
      candidates.remove(normalizedAppId);
      if (wasRunning) {
        startAfterRollback(normalizedAppId, rolledBack);
      }
      appendHistory(
          normalizedAppId,
          ACTION_ROLLBACK,
          STATUS_SUCCESS,
          null,
          rolledBack.manifest().appVersion(),
          null,
          "Previous app bundle restored.");
      return summary(normalizedAppId, rolledBack);
    } catch (AppHostException exception) {
      restartOriginalAfterUncommittedRollbackFailure(normalizedAppId, wasRunning, original);
      PlatformApiException mapped = appHostRollbackFailure(exception);
      recordRollbackFailure(normalizedAppId, mapped.errorCode());
      throw mapped;
    } catch (IOException _) {
      restartOriginalAfterUncommittedRollbackFailure(normalizedAppId, wasRunning, original);
      recordRollbackFailure(normalizedAppId, ERROR_ROLLBACK_FAILED);
      throw lifecycleFailure(500, ERROR_ROLLBACK_FAILED, MESSAGE_ROLLBACK_FAILED);
    }
  }

  private void requireRollbackAvailableBeforeStop(String appId) {
    try {
      if (rollbackAvailable(appId)) {
        return;
      }
    } catch (PlatformApiException exception) {
      recordRollbackFailure(appId, exception.errorCode());
      throw exception;
    }
    recordRollbackFailure(appId, ERROR_ROLLBACK_NOT_AVAILABLE);
    throw lifecycleFailure(404, ERROR_ROLLBACK_NOT_AVAILABLE, "Rollback is not available.");
  }

  private boolean disableVaultGrantsRemovedByUpdate(InstalledAppSnapshot updated) {
    return AppUpdateVaultAuthority.disableRemovedGrants(appVaultService, updated);
  }

  private boolean disableVaultGrantsAfterCommittedUpdate(
      InstalledAppSnapshot updated, HealthFailureState healthFailureState) {
    if (healthFailureState.rollbackCommitted()) {
      return true;
    }
    return disableVaultGrantsRemovedByUpdate(updated);
  }

  private void restartOriginalAfterUncommittedApplyFailure(
      String appId,
      boolean wasRunning,
      InstalledAppSnapshot original,
      InstalledAppSnapshot updated) {
    if (updated != null) {
      return;
    }
    restartOriginalAfterUncommittedFailure(
        appId,
        wasRunning,
        original,
        ACTION_APPLY,
        ERROR_UPDATE_FAILED,
        "Update failed before replacement, and original app restart failed.");
  }

  private void restartOriginalAfterCommittedRollbackApplyFailure(ApplyFailureContext context) {
    if (!context.healthFailureState().rollbackCommitted()) {
      return;
    }
    restartRestoredAfterCommittedApplyFailure(
        context.appId(), context.wasRunning(), context.healthFailureState().rolledBackSnapshot());
  }

  private void restartRestoredAfterCommittedApplyFailure(
      String appId, boolean wasRunning, InstalledAppSnapshot rolledBack) {
    if (!wasRunning || appHost.status(appId).isPresent()) {
      return;
    }
    try {
      requireCurrentCompatibility(rolledBack);
      appHost.start(appId);
    } catch (PlatformApiException exception) {
      appendHistory(
          appId,
          ACTION_APPLY,
          STATUS_FAILED,
          null,
          rolledBack.manifest().appVersion(),
          exception.errorCode(),
          "Update rollback restored the previous bundle, but Platform API compatibility blocked"
              + " its restart.");
    } catch (IOException _) {
      appendHistory(
          appId,
          ACTION_APPLY,
          STATUS_FAILED,
          null,
          rolledBack.manifest().appVersion(),
          ERROR_UPDATE_FAILED,
          "Update failed after replacement, rollback succeeded, and original app restart failed.");
    }
  }

  private void restartOriginalAfterUncommittedRollbackFailure(
      String appId, boolean wasRunning, InstalledAppSnapshot original) {
    restartOriginalAfterUncommittedFailure(
        appId,
        wasRunning,
        original,
        ACTION_ROLLBACK,
        ERROR_ROLLBACK_FAILED,
        "Rollback failed before restore, and original app restart failed.");
  }

  private void restartOriginalAfterUncommittedFailure(
      String appId,
      boolean wasRunning,
      InstalledAppSnapshot original,
      String action,
      String errorCode,
      String message) {
    if (!wasRunning || appHost.status(appId).isPresent()) {
      return;
    }
    try {
      requireCurrentCompatibility(Objects.requireNonNull(original, "original"));
      appHost.start(appId);
    } catch (PlatformApiException exception) {
      appendHistory(
          appId,
          action,
          STATUS_FAILED,
          null,
          original.manifest().appVersion(),
          exception.errorCode(),
          "Recovery kept the original bundle stopped because Platform API compatibility blocked"
              + " its restart.");
    } catch (IOException _) {
      appendHistory(appId, action, STATUS_FAILED, null, null, errorCode, message);
    }
  }

  private static PlatformApiException appHostRollbackFailure(AppHostException exception) {
    if (exception instanceof AppBundleVerificationException) {
      return lifecycleFailure(
          409,
          ERROR_ROLLBACK_BUNDLE_VERIFICATION_FAILED,
          "Retained app bundle verification blocks rollback.");
    }
    if (exception instanceof AppHostException.CatalogRollbackAuthorizationException) {
      return lifecycleFailure(
          409,
          ERROR_CATALOG_ROLLBACK_TRUST_BLOCKED,
          "Rollback is blocked by current local catalog trust policy.");
    }
    if (isRunningRollbackFailure(exception)) {
      return lifecycleFailure(
          409, ERROR_ROLLBACK_APP_RUNNING, "App must be stopped before rollback.");
    }
    if (isMissingAppFailure(exception)) {
      return appNotFound();
    }
    if (isRollbackRecordUnavailableFailure(exception)) {
      return lifecycleFailure(404, ERROR_ROLLBACK_NOT_AVAILABLE, "Rollback is not available.");
    }
    return lifecycleFailure(500, ERROR_ROLLBACK_FAILED, MESSAGE_ROLLBACK_FAILED);
  }

  private void startAfterRollback(String appId, InstalledAppSnapshot rolledBack) {
    try {
      requireCurrentCompatibility(rolledBack);
      appHost.start(appId);
    } catch (PlatformApiException exception) {
      appendHistory(
          appId,
          ACTION_ROLLBACK,
          STATUS_FAILED,
          null,
          rolledBack.manifest().appVersion(),
          exception.errorCode(),
          "Previous app bundle restored, but Platform API compatibility blocked its restart.");
      throw exception;
    } catch (IOException _) {
      appendHistory(
          appId,
          ACTION_ROLLBACK,
          STATUS_FAILED,
          null,
          rolledBack.manifest().appVersion(),
          ERROR_ROLLBACK_RESTART_FAILED,
          "Previous app bundle restored, but restart failed.");
      throw lifecycleFailure(
          500, ERROR_ROLLBACK_RESTART_FAILED, "Previous app bundle restored, but restart failed.");
    }
  }

  private static void requireCurrentCompatibility(InstalledAppSnapshot installed) {
    PlatformApiAppAdmission.requireCurrentCompatibility(
        installed.manifest().apiCompatibility(), installed.manifest().permissions());
  }

  private void recordRollbackFailure(String appId, String errorCode) {
    appendHistory(
        appId, ACTION_ROLLBACK, STATUS_FAILED, null, null, errorCode, MESSAGE_ROLLBACK_FAILED);
  }

  /**
   * Returns the current policy for one app.
   *
   * <p>The policy is local administrative state. Reading it requires the app to exist, but it does
   * not touch catalogs or staged bundle directories. Missing apps clear stale lifecycle state
   * before a not-found response is returned.
   *
   * @param appId app id from the request path
   * @return path-free policy summary for the installed app
   */
  public synchronized Map<String, Object> policy(String appId) {
    String normalizedAppId = normalizeInstalledAppId(appId);
    requireInstalled(normalizedAppId);
    return policyFor(normalizedAppId).toJsonValue();
  }

  /**
   * Updates the policy for one app.
   *
   * <p>This method only changes the local policy value. It does not immediately check catalogs,
   * stage a candidate, apply a bundle, or restart an app. Route authorization keeps policy changes
   * host/operator-only so app principals cannot grant themselves update automation.
   *
   * @param appId app id from the request path
   * @param mode new policy mode selected by the operator
   */
  public synchronized void setPolicy(String appId, AppUpdatePolicyMode mode) {
    setPolicy(appId, mode, AppUpdatePolicy.DEFAULT_ALLOWED_CHANNELS);
  }

  /**
   * Updates the policy and automatic channel selection for one app.
   *
   * @param appId app id from the request path
   * @param mode new policy mode selected by the operator
   * @param allowedChannels catalog channels eligible for automatic staging/apply
   * @return path-free policy summary after the policy is stored
   */
  public synchronized Map<String, Object> setPolicy(
      String appId, AppUpdatePolicyMode mode, java.util.Set<AppCatalogChannel> allowedChannels) {
    String normalizedAppId = normalizeInstalledAppId(appId);
    requireInstalled(normalizedAppId);
    AppUpdatePolicy policy = new AppUpdatePolicy(mode, allowedChannels);
    policies.put(normalizedAppId, policy);
    candidates.remove(normalizedAppId);
    return policy.toJsonValue();
  }

  private void followPolicyAfterCheck(
      String appId, InstalledAppSnapshot installed, AppUpdateCandidate candidate) {
    AppUpdatePolicy policy = policyFor(appId);
    if (policy.mode() == AppUpdatePolicyMode.MANUAL || !candidate.eligibleByDefault()) {
      return;
    }
    if (!candidate.eligibleForAutomaticStage()) {
      appendAutomaticStageBlockHistory(appId, candidate, policy.mode());
      return;
    }
    if (policy.mode() == AppUpdatePolicyMode.STAGE) {
      followStagePolicyAfterCheck(appId, installed, candidate);
      return;
    }
    followApplyWhenStoppedPolicyAfterCheck(appId, installed, candidate);
  }

  private void appendAutomaticStageBlockHistory(
      String appId, AppUpdateCandidate candidate, AppUpdatePolicyMode policyMode) {
    if (securityGateRequiresOperator(candidate)) {
      appendSecurityGateHistory(appId, automaticAction(policyMode), candidate);
    } else if (reviewGateRequiresOperator(candidate)) {
      appendReviewGateHistory(appId, automaticAction(policyMode), candidate);
    } else if (candidate.materialConsentBlocksAutomaticStage()) {
      appendMaterialConsentHistory(appId, automaticAction(policyMode), candidate);
    } else {
      appendChannelPolicyHistory(appId, policyMode, candidate);
    }
  }

  private void followStagePolicyAfterCheck(
      String appId, InstalledAppSnapshot installed, AppUpdateCandidate candidate) {
    if (reviewGateRequiresOperator(candidate)) {
      appendReviewGateHistory(appId, ACTION_STAGE, candidate);
      return;
    }
    stageCandidateForAutomaticPolicy(appId, installed, candidate, ACTION_STAGE);
  }

  private void followApplyWhenStoppedPolicyAfterCheck(
      String appId, InstalledAppSnapshot installed, AppUpdateCandidate candidate) {
    if (appHost.status(appId).isPresent()) {
      appendPolicyApplyRunningHistory(appId, candidate);
      return;
    }
    if (!candidate.reviewTrustAllowsAutomaticApply()) {
      appendReviewGateHistory(appId, ACTION_APPLY, candidate);
      return;
    }
    if (!securityDecisionAllowsAutomaticApply(candidate.securityDecision())) {
      appendSecurityGateHistory(appId, ACTION_APPLY, candidate);
      return;
    }
    if (!candidate.apiCompatibilityAllowsAutomaticApply()) {
      appendCompatibilityGateHistory(appId, candidate);
      catalogAuthority.recordPolicyApplyGate(
          candidate, "policy_apply_blocked:" + ERROR_UPDATE_INCOMPATIBLE);
      return;
    }
    if (!stageCandidateForAutomaticPolicy(appId, installed, candidate, ACTION_APPLY)) {
      return;
    }
    apply(appId, ApplyOptions.policyDefault());
  }

  private void appendPolicyApplyRunningHistory(String appId, AppUpdateCandidate candidate) {
    appendHistory(
        appId,
        ACTION_APPLY,
        STATUS_FAILED,
        candidate.catalogId(),
        candidate.targetVersion(),
        ERROR_APP_RUNNING,
        "Policy skipped apply because the app is running.");
    catalogAuthority.recordPolicyApplyGate(candidate, "policy_apply_skipped:" + ERROR_APP_RUNNING);
  }

  private boolean stageCandidateForAutomaticPolicy(
      String appId,
      InstalledAppSnapshot installed,
      AppUpdateCandidate candidate,
      String automaticAction) {
    try {
      stageCandidate(appId, installed, candidate, false, null, false);
      return true;
    } catch (PlatformApiException exception) {
      if (isAutomaticPolicyMigrationSkip(exception.errorCode())) {
        appendAutomaticPolicyMigrationSkipHistory(appId, automaticAction, candidate, exception);
        return false;
      }
      throw exception;
    }
  }

  private void appendAutomaticPolicyMigrationSkipHistory(
      String appId,
      String automaticAction,
      AppUpdateCandidate candidate,
      PlatformApiException exception) {
    if (ERROR_APP_DATA_MIGRATION_REVIEW_REQUIRED.equals(exception.errorCode())) {
      appendMaterialConsentHistory(appId, automaticAction, candidate);
    }
  }

  private static boolean isAutomaticPolicyMigrationSkip(String errorCode) {
    return ERROR_APP_DATA_MIGRATION_MISSING.equals(errorCode)
        || ERROR_APP_DATA_MIGRATION_DRY_RUN_FAILED.equals(errorCode)
        || ERROR_APP_DATA_MIGRATION_REVIEW_REQUIRED.equals(errorCode)
        || ERROR_APP_DATA_MIGRATION_REQUIRES_STOPPED.equals(errorCode)
        || ERROR_APP_DATA_MIGRATION_SANDBOX_UNAVAILABLE.equals(errorCode);
  }

  private void stageCandidate(
      String appId,
      InstalledAppSnapshot installed,
      AppUpdateCandidate candidate,
      boolean migrationAcknowledged,
      String sourceSwitchConsent,
      boolean explicitTargetSelected) {
    if (candidateDiffersFromInstalled(candidate, installed)) {
      closeStage(appId);
      candidates.remove(appId);
      appendHistory(
          appId,
          ACTION_STAGE,
          STATUS_FAILED,
          candidate.catalogId(),
          candidate.targetVersion(),
          ERROR_UPDATE_CANDIDATE_CHANGED,
          "Candidate no longer matches the installed app version.");
      catalogAuthority.recordUpdateGate(
          candidate, "stage_blocked:" + ERROR_UPDATE_CANDIDATE_CHANGED);
      throw lifecycleFailure(
          409,
          ERROR_UPDATE_CANDIDATE_CHANGED,
          "Installed app version changed since candidate detection.");
    }
    boolean explicitConflictResolution =
        requireNoCurrentFederatedConflictBeforeStage(
            appId, installed, candidate, explicitTargetSelected);
    try (StagePlanLease planLease = prepareStagePlanLease(appId, candidate)) {
      AppCatalogInstallPlan plan = planLease.plan();
      if (planDiffersFromCandidate(candidate, installed, plan)) {
        rejectChangedStagePlan(appId, candidate);
      }
      SourceSwitchAuthorization sourceSwitchAuthorization =
          requirePinnedPublisherForStage(appId, candidate, plan, sourceSwitchConsent);
      if (explicitConflictResolution
          && sourceSwitchAuthorization.approvedConsentDigestSha256().isEmpty()) {
        throw lifecycleFailure(
            409,
            ERROR_CATALOG_SOURCE_SWITCH_CONSENT_REQUIRED,
            "The explicit conflict resolution requires an exact source-switch preview.");
      }
      if (explicitTargetSelected
          && isSameVersionSourceSwitchCandidate(candidate)
          && sourceSwitchAuthorization.approvedConsentDigestSha256().isEmpty()) {
        throw lifecycleFailure(
            409,
            ERROR_CATALOG_SOURCE_SWITCH_CONSENT_REQUIRED,
            "A same-version source switch requires an exact source-switch preview.");
      }
      verifyStagedBundleBeforeStageDryRun(appId, candidate, plan);
      AppManifest targetManifest = stagedManifestOrReject(appId, candidate, plan);
      AppDataMigrationPlan migrationPlan =
          AppUpdateMigrationPlanner.buildPlan(
              appDataService, appId, installed.manifest(), targetManifest);
      requireStageableMigrationPlan(appId, candidate, migrationPlan, migrationAcknowledged, plan);
      requireStoppedForStageDryRun(appId, candidate, migrationPlan, plan);
      requireStageableMigrationExecution(appId, candidate, migrationPlan, targetManifest, plan);
      if (migrationPlan.required()) {
        AppDataMigrationRunner.MigrationExecutionResult dryRunResult =
            runStageDryRunOrReject(appId, candidate, plan, migrationPlan, targetManifest);
        if (!dryRunResult.success()) {
          throw lifecycleFailure(
              409,
              ERROR_APP_DATA_MIGRATION_DRY_RUN_FAILED,
              MESSAGE_APP_DATA_MIGRATION_DRY_RUN_FAILED);
        }
      }
      AppUpdateCandidate stagedCandidate = candidateWithMigrationPlan(candidate, migrationPlan);
      closeStage(appId);
      stagedUpdates.put(
          appId,
          new StagedUpdate(
              stagedCandidate,
              planLease.release(),
              migrationPlan,
              sourceSwitchAuthorization,
              Instant.now()));
      appendHistory(
          appId,
          ACTION_STAGE,
          STATUS_SUCCESS,
          stagedCandidate.catalogId(),
          stagedCandidate.targetVersion(),
          null,
          "Verified update candidate staged.");
      catalogAuthority.recordUpdateGate(stagedCandidate, "stage_staged");
    }
  }

  private boolean requireNoCurrentFederatedConflictBeforeStage(
      String appId,
      InstalledAppSnapshot installed,
      AppUpdateCandidate candidate,
      boolean explicitTargetSelected) {
    if (!catalogManager.federationEnabled()) {
      return false;
    }
    List<AppUpdateCandidate> currentSubjects =
        catalogAuthority.catalogCandidates(appId, installed, policyFor(appId), false);
    AppUpdateCandidate conflictDecision = unresolvedCrossCatalogConflict(currentSubjects);
    if (conflictDecision == null) {
      return false;
    }
    if (conflictDecision.status() == AppUpdateCandidateStatus.BLOCKED) {
      if (exactDuplicatePreservesInstalledOrigin(currentSubjects, candidate)) {
        candidates.put(appId, candidate);
        return false;
      }
      if (explicitTargetSelected
          && exactExplicitSourceSwitchResolutionAllows(currentSubjects, candidate)) {
        candidates.put(appId, candidate);
        return true;
      }
      candidates.put(appId, conflictDecision);
      recordStageFailure(appId, candidate, ERROR_UPDATE_NOT_AVAILABLE);
      throw lifecycleFailure(
          409,
          ERROR_UPDATE_NOT_AVAILABLE,
          "Current cross-catalog conflict state blocks staging; check for updates again.");
    }
    if (!sameCatalogCandidateSubject(candidate, conflictDecision)
        && !exactDuplicatePreservesInstalledOrigin(currentSubjects, candidate)) {
      rejectChangedStagePlan(appId, candidate);
    }
    candidates.put(appId, candidate);
    return false;
  }

  private boolean exactDuplicatePreservesInstalledOrigin(
      List<AppUpdateCandidate> matches, AppUpdateCandidate selected) {
    AppUpdateFederationAuthority policy = federatedConflictPolicy.get();
    return policy != null
        && policy
            .conflicts()
            .exactDuplicatePreservesInstalledOrigin(
                matches,
                selected,
                selectedIsInstalledOrigin(selected),
                this::conflictSecurityDigest);
  }

  private static boolean sameCatalogCandidateSubject(
      AppUpdateCandidate left, AppUpdateCandidate right) {
    return AppUpdateConflictAuthority.sameCandidate(left, right);
  }

  private SourceSwitchAuthorization requirePinnedPublisherForStage(
      String appId,
      AppUpdateCandidate candidate,
      AppCatalogInstallPlan plan,
      String sourceSwitchConsent) {
    Optional<InstalledAppOrigin> current = installedCatalogOrigin(appId);
    if (current.isEmpty()) {
      if (sourceSwitchConsent != null && !sourceSwitchConsent.isBlank()) {
        recordStageFailure(appId, candidate, ERROR_CATALOG_SOURCE_SWITCH_CONSENT_REQUIRED);
        closePlan(plan);
        throw staleSourceSwitchAuthorization();
      }
      return SourceSwitchAuthorization.withoutCurrentOrigin();
    }
    InstalledAppOrigin origin = current.orElseThrow();
    CatalogSourceSwitchConsent.Decision decision;
    try {
      decision = CatalogSourceSwitchConsent.evaluate(plan, origin);
    } catch (IllegalArgumentException _) {
      recordStageFailure(appId, candidate, ERROR_CATALOG_SOURCE_SWITCH_CONSENT_REQUIRED);
      closePlan(plan);
      throw lifecycleFailure(
          409,
          ERROR_CATALOG_SOURCE_SWITCH_CONSENT_REQUIRED,
          "Catalog source switching requires an authenticated target origin.");
    }
    if (!decision.requiresExplicitConsent()) {
      return SourceSwitchAuthorization.forCurrentOrigin(origin, null);
    }
    if (decision.consentDigestSha256().equals(sourceSwitchConsent)) {
      return SourceSwitchAuthorization.forCurrentOrigin(origin, decision.consentDigestSha256());
    }
    recordStageFailure(appId, candidate, ERROR_CATALOG_SOURCE_SWITCH_CONSENT_REQUIRED);
    closePlan(plan);
    throw lifecycleFailure(
        409,
        ERROR_CATALOG_SOURCE_SWITCH_CONSENT_REQUIRED,
        "Catalog or publisher switching requires an exact operator source-switch preview.");
  }

  private void revalidateSourceSwitchAuthorizationForApply(String appId, StagedUpdate staged) {
    SourceSwitchAuthorization authorization = staged.sourceSwitchAuthorization();
    InstalledAppOrigin current = installedCatalogOrigin(appId).orElse(null);
    if (!authorization.matches(current)) {
      throw staleSourceSwitchAuthorization();
    }
    if (current == null) {
      return;
    }
    CatalogSourceSwitchConsent.Decision decision;
    try {
      decision = CatalogSourceSwitchConsent.evaluate(staged.plan(), current);
    } catch (IllegalArgumentException _) {
      throw staleSourceSwitchAuthorization();
    }
    if (decision.requiresExplicitConsent()
        && !authorization
            .approvedConsentDigestSha256()
            .equals(Optional.of(decision.consentDigestSha256()))) {
      throw staleSourceSwitchAuthorization();
    }
  }

  private static PlatformApiException staleSourceSwitchAuthorization() {
    return lifecycleFailure(
        409,
        ERROR_CATALOG_SOURCE_SWITCH_CONSENT_REQUIRED,
        "Installed catalog origin changed; prepare and approve a new source-switch preview.");
  }

  private void rejectChangedStagePlan(String appId, AppUpdateCandidate candidate) {
    closeStage(appId);
    candidates.remove(appId);
    appendHistory(
        appId,
        ACTION_STAGE,
        STATUS_FAILED,
        candidate.catalogId(),
        candidate.targetVersion(),
        ERROR_UPDATE_CANDIDATE_CHANGED,
        "Prepared catalog plan no longer matches the reviewed candidate.");
    catalogAuthority.recordUpdateGate(candidate, "stage_blocked:" + ERROR_UPDATE_CANDIDATE_CHANGED);
    throw lifecycleFailure(
        409,
        ERROR_UPDATE_CANDIDATE_CHANGED,
        "Catalog candidate changed since review; check for updates again.");
  }

  private void verifyStagedBundleBeforeStageDryRun(
      String appId, AppUpdateCandidate candidate, AppCatalogInstallPlan plan) {
    try {
      catalogManager.verifyInstallPlan(plan);
    } catch (AppCatalogException exception) {
      recordStageFailure(appId, candidate, exception.errorCode());
      throw catalogFailure(exception);
    } catch (IOException _) {
      recordStageFailure(appId, candidate, ERROR_STAGE_FAILED);
      throw lifecycleFailure(500, ERROR_STAGE_FAILED, MESSAGE_STAGE_FAILED);
    }
  }

  private StagePlanLease prepareStagePlanLease(String appId, AppUpdateCandidate candidate) {
    try {
      return new StagePlanLease(catalogManager.prepareInstallPlan(candidate.catalogId(), appId));
    } catch (AppCatalogException exception) {
      recordStageFailure(appId, candidate, exception.errorCode());
      throw catalogFailure(exception);
    } catch (IOException _) {
      recordStageFailure(appId, candidate, ERROR_STAGE_FAILED);
      throw lifecycleFailure(500, ERROR_STAGE_FAILED, MESSAGE_STAGE_FAILED);
    }
  }

  private AppManifest stagedManifestOrReject(
      String appId, AppUpdateCandidate candidate, AppCatalogInstallPlan plan) {
    try {
      AppManifest manifest = AppUpdateBundleSupport.readManifest(plan.stagedBundleDirectory());
      requireStagedPlatformApiAdmission(plan.entry(), manifest);
      return manifest;
    } catch (PlatformApiException exception) {
      recordStageFailure(appId, candidate, exception.errorCode());
      closePlan(plan);
      throw exception;
    } catch (IOException _) {
      recordStageFailure(appId, candidate, ERROR_INVALID_APP_BUNDLE);
      closePlan(plan);
      throw lifecycleFailure(
          400, ERROR_INVALID_APP_BUNDLE, "Staged app bundle manifest is invalid.");
    }
  }

  private static void requireStagedPlatformApiAdmission(
      AppCatalogEntry entry, AppManifest manifest) {
    PlatformApiAppAdmission.requireCatalogDeclarationMatchesManifest(
        entry.compatibility().apiCompatibility(), manifest.apiCompatibility());
    PlatformApiAppAdmission.requireCurrentCompatibility(
        manifest.apiCompatibility(), manifest.permissions());
  }

  private void requireStageableMigrationPlan(
      String appId,
      AppUpdateCandidate candidate,
      AppDataMigrationPlan migrationPlan,
      boolean migrationAcknowledged,
      AppCatalogInstallPlan plan) {
    if (migrationPlan.hasBlocker()) {
      candidates.put(appId, candidateWithMigrationPlan(candidate, migrationPlan));
      recordStageFailure(appId, candidate, migrationPlan.blockReason());
      closePlan(plan);
      throw lifecycleFailure(
          409, migrationPlan.blockReason(), "App-data migration plan blocks this update.");
    }
    if (migrationPlan.operatorReviewRequired() && !migrationAcknowledged) {
      AppDataMigrationPlan blockedPlan =
          AppDataMigrationPlan.blocked(
              AppDataMigrationPlan.STATUS_ROLLBACK_INCOMPATIBLE,
              migrationPlan.currentSchemaVersion(),
              migrationPlan.targetSchemaVersion(),
              migrationPlan.namespaces(),
              true,
              ERROR_APP_DATA_MIGRATION_REVIEW_REQUIRED);
      candidates.put(appId, candidateWithMigrationPlan(candidate, blockedPlan));
      recordStageFailure(appId, candidate, ERROR_APP_DATA_MIGRATION_REVIEW_REQUIRED);
      closePlan(plan);
      throw lifecycleFailure(
          409,
          ERROR_APP_DATA_MIGRATION_REVIEW_REQUIRED,
          "App-data migration requires explicit operator acknowledgement.");
    }
  }

  private void requireStoppedForStageDryRun(
      String appId,
      AppUpdateCandidate candidate,
      AppDataMigrationPlan migrationPlan,
      AppCatalogInstallPlan plan) {
    if (!migrationPlan.requiresStopped() || appHost.status(appId).isEmpty()) {
      return;
    }
    AppDataMigrationPlan blockedPlan =
        AppDataMigrationPlan.blocked(
            AppDataMigrationPlan.STATUS_REQUIRES_STOPPED,
            migrationPlan.currentSchemaVersion(),
            migrationPlan.targetSchemaVersion(),
            migrationPlan.namespaces(),
            migrationPlan.operatorReviewRequired(),
            ERROR_APP_DATA_MIGRATION_REQUIRES_STOPPED);
    candidates.put(appId, candidateWithMigrationPlan(candidate, blockedPlan));
    recordStageFailure(appId, candidate, ERROR_APP_DATA_MIGRATION_REQUIRES_STOPPED);
    closePlan(plan);
    throw lifecycleFailure(
        409,
        ERROR_APP_DATA_MIGRATION_REQUIRES_STOPPED,
        "App-data migration requires the app to be stopped before dry-run.");
  }

  private void requireStageableMigrationExecution(
      String appId,
      AppUpdateCandidate candidate,
      AppDataMigrationPlan migrationPlan,
      AppManifest targetManifest,
      AppCatalogInstallPlan plan) {
    if (AppUpdateMigrationPlanner.migrationExecutionAllowed(migrationPlan, targetManifest)) {
      return;
    }
    AppDataMigrationPlan blockedPlan =
        AppDataMigrationPlan.blocked(
            AppDataMigrationPlan.STATUS_SANDBOX_UNAVAILABLE,
            migrationPlan.currentSchemaVersion(),
            migrationPlan.targetSchemaVersion(),
            migrationPlan.namespaces(),
            migrationPlan.operatorReviewRequired(),
            ERROR_APP_DATA_MIGRATION_SANDBOX_UNAVAILABLE);
    candidates.put(appId, candidateWithMigrationPlan(candidate, blockedPlan));
    recordStageFailure(appId, candidate, ERROR_APP_DATA_MIGRATION_SANDBOX_UNAVAILABLE);
    closePlan(plan);
    throw lifecycleFailure(
        409,
        ERROR_APP_DATA_MIGRATION_SANDBOX_UNAVAILABLE,
        "App-data migration runner cannot enforce the requested app sandbox.");
  }

  private void requireMigrationExecutionAllowed(
      AppDataMigrationPlan migrationPlan, AppManifest targetManifest) {
    if (AppUpdateMigrationPlanner.migrationExecutionAllowed(migrationPlan, targetManifest)) {
      return;
    }
    throw lifecycleFailure(
        409,
        ERROR_APP_DATA_MIGRATION_SANDBOX_UNAVAILABLE,
        "App-data migration runner cannot enforce the requested app sandbox.");
  }

  private AppDataMigrationRunner.MigrationExecutionResult runStageDryRunOrReject(
      String appId,
      AppUpdateCandidate candidate,
      AppCatalogInstallPlan plan,
      AppDataMigrationPlan migrationPlan,
      AppManifest targetManifest) {
    try (AppDataMigrationRunner.MigrationDataAccess dataAccess =
        migrationDataAccess(appId, targetManifest)) {
      AppDataMigrationRunner.MigrationExecutionResult result =
          migrationRunner.run(
              plan.stagedBundleDirectory(),
              migrationPlan,
              AppDataMigrationRunner.Mode.DRY_RUN,
              dataAccess);
      if (!result.success()) {
        recordMigrationDryRunFailure(appId, candidate, migrationPlan);
      }
      return result;
    } catch (IOException | PlatformApiException _) {
      recordMigrationDryRunFailure(appId, candidate, migrationPlan);
      closePlan(plan);
      throw lifecycleFailure(
          409, ERROR_APP_DATA_MIGRATION_DRY_RUN_FAILED, MESSAGE_APP_DATA_MIGRATION_DRY_RUN_FAILED);
    }
  }

  private void recordMigrationDryRunFailure(
      String appId, AppUpdateCandidate candidate, AppDataMigrationPlan migrationPlan) {
    recordStageFailure(appId, candidate, ERROR_APP_DATA_MIGRATION_DRY_RUN_FAILED);
    candidates.put(appId, candidateWithMigrationPlan(candidate, migrationPlan.withDryRunFailed()));
  }

  private AppDataMigrationRunner.MigrationDataAccess migrationDataAccess(String appId)
      throws IOException {
    return migrationDataAccess(appId, false, null);
  }

  private AppDataMigrationRunner.MigrationDataAccess migrationDataAccess(
      String appId, AppManifest targetManifest) throws IOException {
    Objects.requireNonNull(targetManifest, "targetManifest");
    return migrationDataAccess(appId, true, targetManifest.dataQuotaBytes());
  }

  private AppDataMigrationRunner.MigrationDataAccess migrationDataAccess(
      String appId, boolean useTargetManifestQuota, Long targetDataQuotaBytes) throws IOException {
    if (appDataService == null) {
      throw lifecycleFailure(
          409,
          ERROR_APP_DATA_SNAPSHOT_FAILED,
          "App-data migration cannot access durable app data.");
    }
    return new AppDataServiceMigrationDataAccess(
        appId, appDataService, useTargetManifestQuota, targetDataQuotaBytes);
  }

  private static final class AppDataServiceMigrationDataAccess
      implements AppDataMigrationRunner.MigrationDataAccess {
    private final String appId;
    private final AppDataService appDataService;
    private final boolean useTargetManifestQuota;
    private final Long targetDataQuotaBytes;
    private final Path root;
    private final Map<String, byte[]> dryRunPayloadsByNamespace = new LinkedHashMap<>();

    private AppDataServiceMigrationDataAccess(
        String appId,
        AppDataService appDataService,
        boolean useTargetManifestQuota,
        Long targetDataQuotaBytes)
        throws IOException {
      this.appId = Objects.requireNonNull(appId, JSON_APP_ID);
      this.appDataService = Objects.requireNonNull(appDataService, "appDataService");
      this.useTargetManifestQuota = useTargetManifestQuota;
      this.targetDataQuotaBytes = targetDataQuotaBytes;
      root =
          Files.createTempDirectory(
              "crypta-app-data-migration-", secureScratchDirectoryAttributes());
    }

    @Override
    public AppDataMigrationRunner.StepDataFiles prepare(
        AppDataMigrationPlan.NamespaceStep step, AppDataMigrationRunner.Mode mode)
        throws IOException {
      Objects.requireNonNull(mode, "mode");
      Path stepDirectory = Files.createTempDirectory(root, "step-" + step.stepId() + "-");
      Path inputPayload = stepDirectory.resolve("input.json");
      Path outputPayload = stepDirectory.resolve("output.json");
      byte[] payload =
          mode == AppDataMigrationRunner.Mode.DRY_RUN
              ? dryRunPayloadsByNamespace.computeIfAbsent(
                  step.namespace(),
                  namespace -> appDataService.exportUpdateMigrationPayload(appId, namespace))
              : appDataService.exportUpdateMigrationPayload(appId, step.namespace());
      Files.write(inputPayload, payload);
      return new AppDataMigrationRunner.StepDataFiles(inputPayload, outputPayload);
    }

    @Override
    public void complete(
        AppDataMigrationPlan.NamespaceStep step,
        AppDataMigrationRunner.Mode mode,
        AppDataMigrationRunner.StepDataFiles files)
        throws IOException {
      byte[] outputPayload = readOutputPayload(files.outputPayload());
      if (mode == AppDataMigrationRunner.Mode.DRY_RUN) {
        byte[] advancedPayload = advanceDryRunPayload(step, outputPayload);
        dryRunPayloadsByNamespace.put(step.namespace(), advancedPayload);
        preflightProjectedDryRunPayloads();
        return;
      }
      appDataService.importUpdateMigrationPayload(
          appId, step.namespace(), step.fromSchemaVersion(), step.toSchemaVersion(), outputPayload);
      appDataService.recordUpdateMigration(
          appId,
          step.namespace(),
          step.fromSchemaVersion(),
          step.toSchemaVersion(),
          step.description());
    }

    private byte[] advanceDryRunPayload(AppDataMigrationPlan.NamespaceStep step, byte[] payload) {
      if (useTargetManifestQuota) {
        return appDataService.advanceUpdateMigrationDryRunPayload(
            appId,
            step.namespace(),
            step.fromSchemaVersion(),
            step.toSchemaVersion(),
            step.description(),
            payload,
            targetDataQuotaBytes);
      }
      return appDataService.advanceUpdateMigrationDryRunPayload(
          appId,
          step.namespace(),
          step.fromSchemaVersion(),
          step.toSchemaVersion(),
          step.description(),
          payload);
    }

    private void preflightProjectedDryRunPayloads() {
      if (useTargetManifestQuota) {
        appDataService.preflightUpdateMigrationDryRunPayloads(
            appId, dryRunPayloadsByNamespace.values(), targetDataQuotaBytes);
        return;
      }
      appDataService.preflightUpdateMigrationDryRunPayloads(
          appId, dryRunPayloadsByNamespace.values());
    }

    @Override
    public void close() {
      try {
        deleteRecursively(root);
      } catch (IOException _) {
        // Migration scratch cleanup is best effort; command success is reported separately.
      }
    }

    private byte[] readOutputPayload(Path outputPayload) throws IOException {
      if (Files.isSymbolicLink(outputPayload)
          || !Files.isRegularFile(outputPayload, LinkOption.NOFOLLOW_LINKS)) {
        throw new IOException("migration output payload is missing");
      }
      long payloadBytes = Files.size(outputPayload);
      if (payloadBytes > appDataService.maxUpdateMigrationPayloadBytes()) {
        throw new PlatformApiException(
            400, "app_data_import_too_large", "App-data import exceeds the configured limit.");
      }
      return Files.readAllBytes(outputPayload);
    }

    private static void deleteRecursively(Path root) throws IOException {
      if (root == null || !Files.exists(root)) {
        return;
      }
      List<Path> paths;
      try (java.util.stream.Stream<Path> stream = Files.walk(root)) {
        paths = stream.sorted(Comparator.reverseOrder()).toList();
      }
      for (Path path : paths) {
        Files.deleteIfExists(path);
      }
    }

    private static FileAttribute<?>[] secureScratchDirectoryAttributes() {
      if (!FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
        return new FileAttribute<?>[0];
      }
      Set<PosixFilePermission> ownerOnly =
          EnumSet.of(
              PosixFilePermission.OWNER_READ,
              PosixFilePermission.OWNER_WRITE,
              PosixFilePermission.OWNER_EXECUTE);
      return new FileAttribute<?>[] {PosixFilePermissions.asFileAttribute(ownerOnly)};
    }
  }

  private AppUpdateCandidate candidateWithMigrationPlan(
      AppUpdateCandidate candidate, AppDataMigrationPlan migrationPlan) {
    return copyCandidate(
        candidate,
        candidate.status(),
        candidate.apiCompatibility(),
        candidate.permissionDelta(),
        migrationPlan);
  }

  private AppUpdateCandidate candidateWithStagedManifest(
      AppUpdateCandidate candidate,
      InstalledAppSnapshot installed,
      AppCatalogEntry entry,
      AppManifest targetManifest,
      AppDataMigrationPlan migrationPlan) {
    PlatformApiAppAdmission.requireCatalogDeclarationMatchesManifest(
        entry.compatibility().apiCompatibility(), targetManifest.apiCompatibility());
    Map<String, Object> apiCompatibility =
        PlatformApiAppAdmission.summarizeAdmission(
            targetManifest.apiCompatibility(), targetManifest.permissions());
    AppUpdateCandidateStatus status =
        apiCompatibilityBlocksUpdate(apiCompatibility)
            ? AppUpdateCandidateStatus.INCOMPATIBLE
            : candidate.status();
    Map<String, Object> permissionDelta =
        AppUpdateCandidate.permissionDelta(
            targetManifest.permissions(), installed.manifest().permissions());
    return copyCandidate(candidate, status, apiCompatibility, permissionDelta, migrationPlan);
  }

  private static AppUpdateCandidate copyCandidate(
      AppUpdateCandidate candidate,
      AppUpdateCandidateStatus status,
      Map<String, Object> apiCompatibility,
      Map<String, Object> permissionDelta,
      AppDataMigrationPlan migrationPlan) {
    return new AppUpdateCandidate(
        candidate.appId(),
        candidate.catalogId(),
        candidate.catalogSourceId(),
        candidate.installedVersion(),
        candidate.targetVersion(),
        status,
        candidate.versionComparison(),
        candidate.channel(),
        candidate.supportStatus(),
        candidate.deprecation(),
        candidate.securityAdvisories(),
        candidate.securityDecision(),
        candidate.channelPolicyAllowed(),
        candidate.policyBlockReason(),
        candidate.bundleSha256(),
        candidate.bundleSizeBytes(),
        candidate.bundleType(),
        candidate.review(),
        candidate.reviewTrust(),
        apiCompatibility,
        permissionDelta,
        migrationPlan.toJsonValue(),
        candidate.running(),
        candidate.detectedAt());
  }

  private AppUpdateCandidate candidateWithConsentMigrationPlan(
      String appId, InstalledAppSnapshot installed, AppUpdateCandidate candidate) {
    if (!candidate.eligibleByDefault() || updateGateBlocksConsentPreparation(candidate)) {
      return candidate;
    }
    AppCatalogInstallPlan plan = null;
    try {
      plan = catalogManager.prepareInstallPlan(candidate.catalogId(), appId);
      if (planDiffersFromCandidate(candidate, installed, plan)) {
        throw lifecycleFailure(
            409,
            ERROR_UPDATE_CANDIDATE_CHANGED,
            "Catalog candidate changed since consent preview generation.");
      }
      AppManifest targetManifest = stagedManifestForConsentPreview(plan);
      AppDataMigrationPlan migrationPlan =
          AppUpdateMigrationPlanner.buildPlan(
                  appDataService, appId, installed.manifest(), targetManifest)
              .withoutDryRunResult();
      return candidateWithStagedManifest(
          candidate, installed, plan.entry(), targetManifest, migrationPlan);
    } catch (AppCatalogException exception) {
      throw catalogFailure(exception);
    } catch (IOException _) {
      throw lifecycleFailure(
          400, ERROR_INVALID_APP_BUNDLE, "Candidate app bundle manifest is invalid.");
    } finally {
      if (plan != null) {
        closePlan(plan);
      }
    }
  }

  private static boolean updateGateBlocksConsentPreparation(AppUpdateCandidate candidate) {
    return Boolean.TRUE.equals(candidate.securityDecision().get(JSON_BLOCKS_UPDATE))
        || Boolean.TRUE.equals(candidate.reviewTrust().get(JSON_BLOCKS_UPDATE));
  }

  private static AppManifest stagedManifestForConsentPreview(AppCatalogInstallPlan plan)
      throws IOException {
    return AppUpdateBundleSupport.readManifest(plan.stagedBundleDirectory());
  }

  private AppUpdateCandidate candidateOrDetect(String appId, InstalledAppSnapshot installed) {
    if (catalogManager.federationEnabled()) {
      AppUpdateCandidate candidate = detectCandidate(appId, installed, false);
      candidates.put(appId, candidate);
      return candidate;
    }
    return candidates.computeIfAbsent(appId, _ -> detectCandidate(appId, installed, false));
  }

  private void recordStageFailure(String appId, AppUpdateCandidate candidate, String errorCode) {
    appendHistory(
        appId,
        ACTION_STAGE,
        STATUS_FAILED,
        candidate.catalogId(),
        candidate.targetVersion(),
        errorCode,
        MESSAGE_STAGE_FAILED);
    catalogAuthority.recordUpdateGate(candidate, "stage_failed:" + errorCode);
  }

  private AppUpdateCandidate detectCandidate(
      String appId, InstalledAppSnapshot installed, boolean refreshCatalogs) {
    List<AppUpdateCandidate> matches =
        catalogAuthority.catalogCandidates(appId, installed, policyFor(appId), refreshCatalogs);
    return selectBestCandidate(
        appId, installed, matches, installedCatalogOrigin(appId).orElse(null));
  }

  private AppUpdateCandidate conflictCandidateFor(
      String catalogId, AppCatalogEntry entry, InstalledAppSnapshot installed) {
    return catalogAuthority.conflictCandidate(catalogId, entry, installed);
  }

  private Optional<InstalledAppOrigin> installedCatalogOrigin(String appId) {
    if (!catalogManager.federationEnabled()) {
      return Optional.empty();
    }
    try {
      return appHost.catalogOrigin(appId);
    } catch (IOException _) {
      throw lifecycleFailure(
          500, "catalog_origin_read_failed", "Installed catalog origin could not be inspected.");
    }
  }

  private AppUpdateCandidate selectBestCandidate(
      String appId,
      InstalledAppSnapshot installed,
      List<AppUpdateCandidate> matches,
      InstalledAppOrigin installedOrigin) {
    if (matches.isEmpty()) {
      AppUpdateCandidate none = noneCandidate(appId, installed);
      return installedOrigin != null ? none.blockedByUnavailableCatalogOrigin() : none;
    }
    if (installedOrigin != null) {
      AppUpdateCandidate pinned =
          selectPinnedOriginCandidate(appId, installed, matches, installedOrigin);
      AppUpdateCandidate conflict = unresolvedCrossCatalogConflict(matches);
      if (conflict != null
          && conflict.status() == AppUpdateCandidateStatus.BLOCKED
          && !exactDuplicatePreservesInstalledOrigin(matches, pinned)) {
        return conflict;
      }
      return pinned;
    }
    if (!catalogManager.federationEnabled()) {
      return matches.stream()
          .max(AppUpdateService::compareLegacyCandidates)
          .orElseGet(() -> noneCandidate(appId, installed));
    }
    AppUpdateCandidate conflict = unresolvedCrossCatalogConflict(matches);
    if (conflict != null) {
      return conflict;
    }
    return matches.stream()
        .max(AppUpdateService::compareCandidates)
        .orElseGet(() -> noneCandidate(appId, installed));
  }

  private AppUpdateCandidate selectPinnedOriginCandidate(
      String appId,
      InstalledAppSnapshot installed,
      List<AppUpdateCandidate> matches,
      InstalledAppOrigin installedOrigin) {
    List<AppUpdateCandidate> pinnedMatches =
        matches.stream()
            .filter(candidate -> installedOrigin.catalogId().equals(candidate.catalogId()))
            .toList();
    if (!pinnedMatches.isEmpty()) {
      return pinnedMatches.stream()
          .max(AppUpdateService::compareCandidates)
          .orElseGet(() -> noneCandidate(appId, installed));
    }
    return matches.stream()
        .max(AppUpdateService::compareCandidates)
        .orElseGet(() -> noneCandidate(appId, installed))
        .blockedByUnavailableCatalogOrigin();
  }

  private AppUpdateCandidate unresolvedCrossCatalogConflict(List<AppUpdateCandidate> matches) {
    if (matches.isEmpty()) {
      return null;
    }
    AppUpdateFederationAuthority policy = federatedConflictPolicy.get();
    if (policy == null) {
      return hasMultipleCatalogs(matches) ? blockedCatalogConflict(matches) : null;
    }
    return policy.conflicts().decision(matches, this::conflictSecurityDigest);
  }

  private static boolean hasMultipleCatalogs(List<AppUpdateCandidate> matches) {
    return matches.stream().map(AppUpdateCandidate::catalogId).distinct().count() > 1;
  }

  private List<AppUpdateCandidate> currentFederatedConflictCandidates(String appId) {
    if (!catalogManager.federationEnabled()) {
      throw lifecycleFailure(
          503, "catalog_federation_unavailable", "Catalog federation is not enabled on this node.");
    }
    try {
      InstalledAppSnapshot installed = appHost.describe(appId).orElse(null);
      return catalogAuthority.catalogConflictCandidates(appId, installed);
    } catch (IOException _) {
      throw lifecycleFailure(
          500,
          "catalog_conflict_policy_unavailable",
          "The current catalog conflict policy could not be authenticated.");
    }
  }

  private AppUpdateFederationAuthority requireFederatedConflictPolicy() {
    AppUpdateFederationAuthority policy = federatedConflictPolicy.get();
    if (policy == null) {
      throw lifecycleFailure(
          503,
          "catalog_conflict_policy_unavailable",
          "Federated catalog conflict policy is unavailable.");
    }
    return policy;
  }

  private boolean exactExplicitSourceSwitchResolutionAllows(
      List<AppUpdateCandidate> matches, AppUpdateCandidate selected) {
    AppUpdateFederationAuthority policy = federatedConflictPolicy.get();
    return policy != null
        && policy
            .conflicts()
            .explicitSourceSwitchAllows(matches, selected, this::conflictSecurityDigest);
  }

  private static AppUpdateCandidate blockedCatalogConflict(List<AppUpdateCandidate> candidates) {
    return candidates
        .getFirst()
        .blockedByCatalogConflict("multiple_catalog_origins_require_an_exact_local_resolution");
  }

  private static int compareCandidates(AppUpdateCandidate left, AppUpdateCandidate right) {
    int rankComparison = Integer.compare(candidateRank(left), candidateRank(right));
    if (rankComparison != 0) {
      return rankComparison;
    }
    int channelPolicyComparison =
        Integer.compare(channelPolicyRank(left), channelPolicyRank(right));
    if (channelPolicyComparison != 0) {
      return channelPolicyComparison;
    }
    int stageabilityComparison = Integer.compare(stageabilityRank(left), stageabilityRank(right));
    if (stageabilityComparison != 0) {
      return stageabilityComparison;
    }
    Integer versionComparison =
        compareDottedNumericVersions(left.targetVersion(), right.targetVersion());
    if (versionComparison != null && versionComparison != 0) {
      return versionComparison;
    }
    return Integer.compare(
        reviewTrustRank(left.reviewTrust()), reviewTrustRank(right.reviewTrust()));
  }

  private static int compareLegacyCandidates(AppUpdateCandidate left, AppUpdateCandidate right) {
    int policyComparison = compareCandidates(left, right);
    if (policyComparison != 0) {
      return policyComparison;
    }
    int catalogComparison = left.catalogId().compareTo(right.catalogId());
    if (catalogComparison != 0) {
      return catalogComparison;
    }
    return left.catalogSourceId().compareTo(right.catalogSourceId());
  }

  private static int candidateRank(AppUpdateCandidate candidate) {
    return switch (candidate.status()) {
      case AVAILABLE -> 50;
      case AMBIGUOUS -> 40;
      case INCOMPATIBLE -> 35;
      case NOT_NEWER -> 20;
      case NONE -> 10;
      case STAGED, BLOCKED, APPLIED, ROLLBACK_AVAILABLE, ROLLBACK_IN_PROGRESS, FAILED -> 0;
    };
  }

  private static int channelPolicyRank(AppUpdateCandidate candidate) {
    return candidate.channelPolicyAllowed() && candidate.policyBlockReason() == null ? 1 : 0;
  }

  private static int stageabilityRank(AppUpdateCandidate candidate) {
    Map<String, Object> securityDecision = candidate.securityDecision();
    if (Boolean.TRUE.equals(securityDecision.get(JSON_BLOCKS_UPDATE))
        || Boolean.TRUE.equals(securityDecision.get(JSON_BLOCKS_AUTOMATIC_APPLY))) {
      return 0;
    }
    if (Boolean.TRUE.equals(securityDecision.get(JSON_REQUIRES_ACKNOWLEDGEMENT))) {
      return 1;
    }
    Map<String, Object> reviewTrust = candidate.reviewTrust();
    if (Boolean.TRUE.equals(reviewTrust.get(JSON_BLOCKS_UPDATE))
        || Boolean.TRUE.equals(reviewTrust.get(JSON_BLOCKS_POLICY_APPLY))) {
      return 0;
    }
    if (Boolean.TRUE.equals(reviewTrust.get(JSON_REQUIRES_ACKNOWLEDGEMENT))) {
      return 1;
    }
    return 2;
  }

  private static int reviewTrustRank(Map<String, Object> reviewTrust) {
    int rank = 0;
    if (!Boolean.TRUE.equals(reviewTrust.get(JSON_BLOCKS_UPDATE))) {
      rank += 1000;
    }
    if (!Boolean.TRUE.equals(reviewTrust.get(JSON_REQUIRES_ACKNOWLEDGEMENT))) {
      rank += 100;
    }
    Object statusValue = reviewTrust.get(JSON_STATUS);
    if (!(statusValue instanceof String status)) {
      return rank;
    }
    return rank
        + switch (status) {
          case "trusted_reviewed" -> 80;
          case "trusted_caution" -> 60;
          case "publisher_claim_only" -> 40;
          case "missing_receipt", "not_configured" -> 30;
          case "unknown_reviewer",
              "revoked_receipt",
              "retired_reviewer",
              "revoked_reviewer",
              "reviewer_not_yet_valid",
              "reviewer_expired",
              "review_policy_mismatch",
              "invalid_signature",
              "artifact_mismatch",
              "app_mismatch",
              "expired" ->
              20;
          default -> 0;
        };
  }

  private Map<String, Object> reviewTrust(String catalogId, AppCatalogEntry entry) {
    return catalogAuthority.reviewTrust(catalogId, entry);
  }

  private Map<String, Object> securityDecision(String catalogId, String appId) {
    return catalogAuthority.catalogSecurityDecision(catalogId, appId);
  }

  private String conflictSecurityDigest(AppUpdateCandidate candidate) {
    return securityDecisionDigest(securityDecision(candidate.catalogId(), candidate.appId()));
  }

  private boolean selectedIsInstalledOrigin(AppUpdateCandidate selected) {
    return installedCatalogOrigin(selected.appId())
        .filter(origin -> origin.catalogId().equals(selected.catalogId()))
        .isPresent();
  }

  private Map<String, Object> installedSecurityDecision(String appId, String version) {
    return catalogAuthority.installedSecurityDecision(appId, version);
  }

  private Map<String, Object> targetSecurityDecision(String catalogId, AppCatalogEntry entry) {
    return catalogAuthority.targetSecurityDecision(catalogId, entry);
  }

  private void recordPolicyReviewGate(String action, AppUpdateCandidate candidate, String phase) {
    if (ACTION_STAGE.equals(action)) {
      catalogAuthority.recordUpdateGate(candidate, phase);
    } else {
      catalogAuthority.recordPolicyApplyGate(candidate, phase);
    }
  }

  private AppUpdateCandidate noneCandidate(String appId, InstalledAppSnapshot installed) {
    return catalogAuthority.none(appId, installed);
  }

  private static boolean apiCompatibilityBlocksUpdate(Map<String, Object> apiCompatibility) {
    String apiStatus = String.valueOf(apiCompatibility.get(JSON_STATUS));
    return "below_minimum".equals(apiStatus)
        || "incompatible".equals(apiStatus)
        || "unsupported-baseline".equals(apiStatus);
  }

  static Integer compareDottedNumericVersions(String left, String right) {
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

  private static void requireStageableCandidate(
      AppUpdateCandidate candidate,
      boolean reviewAcknowledged,
      boolean securityAcknowledged,
      boolean explicitTargetSelected) {
    if (candidate.status() == AppUpdateCandidateStatus.INCOMPATIBLE) {
      throw lifecycleFailure(
          409, ERROR_UPDATE_INCOMPATIBLE, "Candidate is incompatible with this Platform API.");
    }
    if (!candidate.eligibleByDefault()
        && !(explicitTargetSelected && isSameVersionSourceSwitchCandidate(candidate))) {
      throw lifecycleFailure(
          409, ERROR_UPDATE_NOT_AVAILABLE, "No safely newer update candidate is available.");
    }
    requireSecurityGate(candidate.securityDecision(), securityAcknowledged);
    requireReviewGate(candidate.reviewTrust(), reviewAcknowledged);
  }

  private static boolean isSameVersionSourceSwitchCandidate(AppUpdateCandidate candidate) {
    return candidate.status() == AppUpdateCandidateStatus.NONE
        && VERSION_EQUAL.equals(candidate.versionComparison())
        && !apiCompatibilityBlocksUpdate(candidate.apiCompatibility());
  }

  private static boolean stagedExplicitSameVersionSwitch(StagedUpdate staged) {
    return isSameVersionSourceSwitchCandidate(staged.candidate())
        && staged.sourceSwitchAuthorization().expectedCurrentOrigin().isPresent()
        && staged.sourceSwitchAuthorization().approvedConsentDigestSha256().isPresent();
  }

  private static void requireSecurityGate(
      Map<String, Object> securityDecision, boolean securityAcknowledged) {
    if (Boolean.TRUE.equals(securityDecision.get(JSON_BLOCKS_UPDATE))) {
      throw lifecycleFailure(
          409,
          securityGateFailureCode(securityDecision),
          "Update blocked by catalog security policy.");
    }
    if (Boolean.TRUE.equals(securityDecision.get(JSON_REQUIRES_ACKNOWLEDGEMENT))
        && !securityAcknowledged) {
      throw lifecycleFailure(
          409,
          ERROR_APP_SECURITY_ACKNOWLEDGEMENT_REQUIRED,
          "Update requires explicit acknowledgement of the security advisory.");
    }
  }

  private static void requireReviewGate(
      Map<String, Object> reviewTrust, boolean reviewAcknowledged) {
    if (Boolean.TRUE.equals(reviewTrust.get(JSON_BLOCKS_UPDATE))) {
      throw lifecycleFailure(
          409, reviewGateFailureCode(reviewTrust), "Update blocked by app review policy.");
    }
    if (Boolean.TRUE.equals(reviewTrust.get(JSON_REQUIRES_ACKNOWLEDGEMENT))
        && !reviewAcknowledged) {
      throw lifecycleFailure(
          409,
          reviewGateFailureCode(reviewTrust),
          "Update requires explicit acknowledgement of the review trust decision.");
    }
  }

  private static boolean reviewGateRequiresOperator(AppUpdateCandidate candidate) {
    Map<String, Object> reviewTrust = candidate.reviewTrust();
    return Boolean.TRUE.equals(reviewTrust.get(JSON_BLOCKS_UPDATE))
        || Boolean.TRUE.equals(reviewTrust.get(JSON_BLOCKS_POLICY_APPLY))
        || Boolean.TRUE.equals(reviewTrust.get(JSON_REQUIRES_ACKNOWLEDGEMENT));
  }

  private static boolean securityGateRequiresOperator(AppUpdateCandidate candidate) {
    return securityGateRequiresOperator(candidate.securityDecision());
  }

  private static boolean securityGateRequiresOperator(Map<String, Object> securityDecision) {
    return Boolean.TRUE.equals(securityDecision.get(JSON_BLOCKS_UPDATE))
        || Boolean.TRUE.equals(securityDecision.get(JSON_BLOCKS_AUTOMATIC_APPLY))
        || Boolean.TRUE.equals(securityDecision.get(JSON_REQUIRES_ACKNOWLEDGEMENT));
  }

  private static boolean securityDecisionAllowsAutomaticApply(
      Map<String, Object> securityDecision) {
    return !Boolean.TRUE.equals(securityDecision.get(JSON_BLOCKS_UPDATE))
        && !Boolean.TRUE.equals(securityDecision.get(JSON_BLOCKS_AUTOMATIC_APPLY))
        && !Boolean.TRUE.equals(securityDecision.get(JSON_REQUIRES_ACKNOWLEDGEMENT));
  }

  private void appendReviewGateHistory(String appId, String action, AppUpdateCandidate candidate) {
    appendHistory(
        appId,
        action,
        STATUS_FAILED,
        candidate.catalogId(),
        candidate.targetVersion(),
        reviewGateFailureCode(candidate.reviewTrust()),
        "Policy skipped update because no trusted positive review receipt verified.");
    recordPolicyReviewGate(
        action,
        candidate,
        policyBlockedEventStatus(action, reviewGateFailureCode(candidate.reviewTrust())));
  }

  private void appendChannelPolicyHistory(
      String appId, AppUpdatePolicyMode mode, AppUpdateCandidate candidate) {
    String action = mode == AppUpdatePolicyMode.APPLY_WHEN_STOPPED ? ACTION_APPLY : ACTION_STAGE;
    appendHistory(
        appId,
        action,
        STATUS_FAILED,
        candidate.catalogId(),
        candidate.targetVersion(),
        ERROR_CHANNEL_POLICY_BLOCKED,
        "Policy skipped update because the catalog channel is not allowed.");
    recordPolicyReviewGate(
        action, candidate, policyBlockedEventStatus(action, ERROR_CHANNEL_POLICY_BLOCKED));
  }

  private void appendMaterialConsentHistory(
      String appId, String action, AppUpdateCandidate candidate) {
    appendHistory(
        appId,
        action,
        STATUS_FAILED,
        candidate.catalogId(),
        candidate.targetVersion(),
        ERROR_CONSENT_REQUIRED,
        "Policy skipped update because material consent is required.");
    recordPolicyReviewGate(
        action, candidate, policyBlockedEventStatus(action, ERROR_CONSENT_REQUIRED));
  }

  private static String policyBlockedEventStatus(String action, String errorCode) {
    return EVENT_STATUS_POLICY_PREFIX + action + EVENT_STATUS_BLOCKED_SUFFIX + errorCode;
  }

  private void appendSecurityGateHistory(
      String appId, String action, AppUpdateCandidate candidate) {
    appendHistory(
        appId,
        action,
        STATUS_FAILED,
        candidate.catalogId(),
        candidate.targetVersion(),
        automaticSecurityGateFailureCode(candidate.securityDecision()),
        "Policy skipped update because catalog security policy requires operator action.");
  }

  private void appendCompatibilityGateHistory(String appId, AppUpdateCandidate candidate) {
    appendHistory(
        appId,
        ACTION_APPLY,
        STATUS_FAILED,
        candidate.catalogId(),
        candidate.targetVersion(),
        ERROR_UPDATE_INCOMPATIBLE,
        "Policy skipped apply because Platform API compatibility is not compatible.");
  }

  private static String reviewGateFailureCode(Map<String, Object> reviewTrust) {
    Object statusValue = reviewTrust.get(JSON_STATUS);
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

  private static String securityGateFailureCode(Map<String, Object> securityDecision) {
    Object statusValue = securityDecision.get(JSON_STATUS);
    if ("denylisted".equals(statusValue)) {
      return ERROR_APP_SECURITY_DENYLISTED;
    }
    if (Boolean.TRUE.equals(securityDecision.get(JSON_BLOCKS_UPDATE))) {
      return ERROR_APP_SECURITY_BLOCKED;
    }
    if (Boolean.TRUE.equals(securityDecision.get(JSON_REQUIRES_ACKNOWLEDGEMENT))) {
      return ERROR_APP_SECURITY_ACKNOWLEDGEMENT_REQUIRED;
    }
    return ERROR_APP_SECURITY_BLOCKED;
  }

  private static String automaticSecurityGateFailureCode(Map<String, Object> securityDecision) {
    Object statusValue = securityDecision.get(JSON_STATUS);
    if ("denylisted".equals(statusValue)) {
      return POLICY_SECURITY_DENYLIST_BLOCKED;
    }
    if (Boolean.TRUE.equals(securityDecision.get(JSON_BLOCKS_UPDATE))
        || Boolean.TRUE.equals(securityDecision.get(JSON_BLOCKS_AUTOMATIC_APPLY))) {
      return POLICY_SECURITY_BLOCKED;
    }
    if (Boolean.TRUE.equals(securityDecision.get(JSON_REQUIRES_ACKNOWLEDGEMENT))) {
      return POLICY_SECURITY_ACKNOWLEDGEMENT_REQUIRED;
    }
    return POLICY_SECURITY_BLOCKED;
  }

  private static String automaticAction(AppUpdatePolicyMode mode) {
    return mode == AppUpdatePolicyMode.APPLY_WHEN_STOPPED ? ACTION_APPLY : ACTION_STAGE;
  }

  private Map<String, Object> summary(String appId, InstalledAppSnapshot installed) {
    invalidateStaleSummaryState(appId, installed);
    return summaryJson(appId, installed, candidateSummary(appId, installed));
  }

  private Map<String, Object> summaryReadOnly(
      String appId, InstalledAppSnapshot installed, AppUpdateCandidate candidate) {
    return summaryJson(appId, installed, candidate.toJsonValue());
  }

  private Map<String, Object> summaryJson(
      String appId, InstalledAppSnapshot installed, Map<String, Object> candidate) {
    boolean running = appHost.status(appId).isPresent();
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(10);
    json.put(JSON_APP_ID, appId);
    json.put("installedVersion", installed.manifest().appVersion());
    json.put("running", running);
    json.put("policy", policyFor(appId).toJsonValue());
    json.put("candidate", candidate);
    json.put(
        "installedSecurityDecision",
        installedSecurityDecision(appId, installed.manifest().appVersion()));
    json.put("staged", stagedSummary(appId));
    json.put(ACTION_ROLLBACK, rollbackSummary(appId));
    json.put("lastCheck", lastCheckSummary(appId));
    json.put("scheduler", schedulerSummaryProvider.schedulerSummary(appId));
    json.put("history", historySummary(appId));
    return json;
  }

  private Map<String, Object> candidateSummary(String appId, InstalledAppSnapshot installed) {
    AppUpdateCandidate candidate = candidates.get(appId);
    return candidate == null
        ? noneCandidate(appId, installed).toJsonValue()
        : candidate.toJsonValue();
  }

  private Map<String, Object> stagedSummary(String appId) {
    StagedUpdate staged = stagedUpdates.get(appId);
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(12);
    if (staged == null) {
      json.put(JSON_STATUS, "none");
      json.put(JSON_AVAILABLE, false);
      json.put(JSON_STAGED_AT, null);
      json.put("expiresAt", null);
      json.put("durable", false);
      json.put("reason", "not_staged");
      return json;
    }
    AppUpdateCandidate candidate = staged.candidate();
    json.put(JSON_STATUS, AppUpdateCandidateStatus.STAGED.jsonValue());
    json.put(JSON_AVAILABLE, true);
    json.put(JSON_APP_ID, appId);
    json.put(JSON_CATALOG_ID, candidate.catalogId());
    json.put("catalogSourceId", candidate.catalogSourceId());
    json.put("targetVersion", candidate.targetVersion());
    json.put("channel", candidate.channel());
    json.put("supportStatus", candidate.supportStatus());
    json.put("deprecation", candidate.deprecation());
    json.put("securityAdvisories", candidate.securityAdvisories());
    json.put("securityDecision", candidate.securityDecision());
    json.put("bundleSha256", candidate.bundleSha256());
    json.put("bundleSizeBytes", candidate.bundleSizeBytes());
    json.put("review", candidate.review());
    json.put(JSON_REVIEW_TRUST, candidate.reviewTrust());
    json.put("apiCompatibility", candidate.apiCompatibility());
    json.put("permissionDelta", candidate.permissionDelta());
    json.put("dataMigration", candidate.dataMigration());
    json.put(JSON_STAGED_AT, staged.stagedAt().toString());
    json.put("expiresAt", null);
    json.put("durable", false);
    return json;
  }

  private Map<String, Object> rollbackSummary(String appId) {
    return AppUpdateFederationAuthority.rollbackSummary(appHost, appId);
  }

  private Map<String, Object> lastCheckSummary(String appId) {
    LastCheck lastCheck = lastChecks.get(appId);
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(4);
    json.put("checkedAt", lastCheck == null ? null : lastCheck.checkedAt().toString());
    json.put(JSON_STATUS, lastCheck == null ? "never" : lastCheck.status());
    json.put("errorCode", lastCheck == null ? null : lastCheck.errorCode());
    json.put(JSON_MESSAGE, lastCheck == null ? null : lastCheck.message());
    return json;
  }

  private static Map<String, Object> disabledSchedulerSummary(String appId) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(11);
    json.put(JSON_APP_ID, appId);
    json.put("enabled", false);
    json.put(JSON_STATUS, AppUpdateSchedulerStatus.DISABLED.jsonValue());
    json.put("lastCheckAt", null);
    json.put("nextCheckAt", null);
    json.put("lastResult", AppUpdateSchedulerState.RESULT_NONE);
    json.put("lastFailureAt", null);
    json.put("failureCount", 0);
    json.put("lastErrorCode", null);
    json.put(JSON_MESSAGE, "Background scheduler is not configured for this service.");
    json.put("concurrency", "per-app-serialized");
    return json;
  }

  private List<Map<String, Object>> historySummary(String appId) {
    Deque<AppUpdateHistoryEntry> entries = history.get(appId);
    if (entries == null || entries.isEmpty()) {
      return List.of();
    }
    return entries.stream().map(AppUpdateHistoryEntry::toJsonValue).toList();
  }

  private AppUpdatePolicy policyFor(String appId) {
    return policies.getOrDefault(appId, AppUpdatePolicy.DEFAULT);
  }

  private AppUpdateCandidate appliedCandidate(
      AppUpdateCandidate candidate,
      InstalledAppSnapshot updated,
      AppDataMigrationPlan migrationPlan) {
    return new AppUpdateCandidate(
        candidate.appId(),
        candidate.catalogId(),
        candidate.catalogSourceId(),
        candidate.installedVersion(),
        updated.manifest().appVersion(),
        AppUpdateCandidateStatus.APPLIED,
        candidate.versionComparison(),
        candidate.channel(),
        candidate.supportStatus(),
        candidate.deprecation(),
        candidate.securityAdvisories(),
        candidate.securityDecision(),
        candidate.channelPolicyAllowed(),
        candidate.policyBlockReason(),
        candidate.bundleSha256(),
        candidate.bundleSizeBytes(),
        candidate.bundleType(),
        candidate.review(),
        candidate.reviewTrust(),
        candidate.apiCompatibility(),
        candidate.permissionDelta(),
        migrationPlan.toJsonValue(),
        appHost.status(candidate.appId()).isPresent(),
        Instant.now());
  }

  private boolean planDiffersFromCandidate(
      AppUpdateCandidate candidate, InstalledAppSnapshot installed, AppCatalogInstallPlan plan) {
    return catalogAuthority.planDiffers(candidate, installed, plan);
  }

  private void updateCandidateAfterPostApplyFailure(
      String appId,
      AppUpdateCandidate stagedCandidate,
      InstalledAppSnapshot updated,
      HealthFailureState healthFailureState,
      AppDataMigrationPlan migrationPlan) {
    if (healthFailureState.rollbackCommitted()) {
      candidates.remove(appId);
      return;
    }
    if (healthFailureState.rollbackFailed() && migrationPlan.required()) {
      candidates.put(
          appId,
          failedCandidate(stagedCandidate, updated, migrationPlan.failed(ERROR_ROLLBACK_FAILED)));
      return;
    }
    candidates.put(appId, appliedCandidate(stagedCandidate, updated, migrationPlan));
  }

  private AppUpdateCandidate failedCandidate(
      AppUpdateCandidate candidate,
      InstalledAppSnapshot updated,
      AppDataMigrationPlan migrationPlan) {
    return new AppUpdateCandidate(
        candidate.appId(),
        candidate.catalogId(),
        candidate.catalogSourceId(),
        candidate.installedVersion(),
        updated.manifest().appVersion(),
        AppUpdateCandidateStatus.FAILED,
        candidate.versionComparison(),
        candidate.channel(),
        candidate.supportStatus(),
        candidate.deprecation(),
        candidate.securityAdvisories(),
        candidate.securityDecision(),
        candidate.channelPolicyAllowed(),
        candidate.policyBlockReason(),
        candidate.bundleSha256(),
        candidate.bundleSizeBytes(),
        candidate.bundleType(),
        candidate.review(),
        candidate.reviewTrust(),
        candidate.apiCompatibility(),
        candidate.permissionDelta(),
        migrationPlan.toJsonValue(),
        appHost.status(candidate.appId()).isPresent(),
        Instant.now());
  }

  private void startOrTreatAsHealthFailure(
      String appId, ApplyOptions options, HealthFailureState healthFailureState)
      throws IOException {
    try {
      appHost.start(appId);
    } catch (IOException exception) {
      if (options.healthCheck() == HealthCheckMode.PROCESS) {
        failProcessHealthCheck(appId, options, healthFailureState);
      }
      throw exception;
    }
  }

  private void verifyHealthOrRollback(
      String appId, ApplyOptions options, HealthFailureState healthFailureState) {
    if (options.healthCheck() == HealthCheckMode.NONE) {
      return;
    }
    if (appHost.status(appId).isPresent()) {
      return;
    }
    failProcessHealthCheck(appId, options, healthFailureState);
  }

  private void failProcessHealthCheck(
      String appId, ApplyOptions options, HealthFailureState healthFailureState) {
    if (options.rollbackOnHealthFailure() && rollbackAvailable(appId)) {
      try {
        InstalledAppSnapshot rolledBack = invokeRollback(appId);
        healthFailureState.markRollbackCommitted(rolledBack);
      } catch (IOException _) {
        throw lifecycleFailure(
            500,
            ERROR_ROLLBACK_FAILED,
            "Process health check failed and automatic rollback failed.");
      }
    }
    throw lifecycleFailure(409, ERROR_HEALTH_CHECK_FAILED, "Process health check failed.");
  }

  private boolean rollbackAvailable(String appId) {
    return AppUpdateFederationAuthority.rollbackAvailable(appHost, appId);
  }

  private InstalledAppSnapshot invokeRollback(String appId) throws IOException {
    if (appHost.rollbackRequiresCatalogAuthorization(appId)) {
      return appHost.rollback(appId, this::authorizeCatalogRollback);
    }
    return appHost.rollback(appId);
  }

  private AppHost.CatalogMutationAuthorizationLease authorizeCatalogRollback(
      InstalledAppOrigin origin) throws IOException {
    try {
      AppUpdateFederationAuthority policy =
          Objects.requireNonNull(
              federatedConflictPolicy.get(), "federated catalog rollback policy is not configured");
      AppCatalogManager.HistoricalAppOriginAuthorization catalogAuthorization =
          policy.authorizeHistoricalCatalog(catalogManager, origin);
      boolean authorizationsTransferred = false;
      try {
        AppHost.CatalogMutationAuthorizationLease publisherAuthorization =
            policy.retainHistoricalPublisherAuthorization(origin, catalogAuthorization.entry());
        try (var reviewerTransfer =
            new HistoricalReviewerAuthorizationTransfer(
                retainHistoricalReviewerAuthorization(origin, catalogAuthorization.entry()))) {
          AppHost.CatalogMutationAuthorizationLease reviewerAuthorization =
              reviewerTransfer.transfer();
          AppHost.CatalogMutationAuthorizationLease combinedAuthorization =
              () -> {
                try {
                  reviewerAuthorization.close();
                } finally {
                  try {
                    publisherAuthorization.close();
                  } finally {
                    catalogAuthorization.authorization().close();
                  }
                }
              };
          authorizationsTransferred = true;
          return combinedAuthorization;
        } finally {
          if (!authorizationsTransferred) {
            publisherAuthorization.close();
          }
        }
      } finally {
        if (!authorizationsTransferred) {
          catalogAuthorization.authorization().close();
        }
      }
    } catch (IOException | RuntimeException exception) {
      throw catalogRollbackAuthorizationFailure(exception);
    }
  }

  private static AppHostException.CatalogRollbackAuthorizationException
      catalogRollbackAuthorizationFailure(Exception cause) {
    if (cause instanceof AppHostException.CatalogRollbackAuthorizationException authorization) {
      return authorization;
    }
    return new AppHostException.CatalogRollbackAuthorizationException(cause);
  }

  /** Closes a reviewer lease unless ownership transfers to the AppHost mutation callback. */
  private static final class HistoricalReviewerAuthorizationTransfer implements AutoCloseable {
    private AppHost.CatalogMutationAuthorizationLease authorization;

    private HistoricalReviewerAuthorizationTransfer(
        AppHost.CatalogMutationAuthorizationLease authorization) {
      this.authorization = Objects.requireNonNull(authorization, "authorization");
    }

    private AppHost.CatalogMutationAuthorizationLease transfer() {
      AppHost.CatalogMutationAuthorizationLease transferred = authorization;
      authorization = null;
      return transferred;
    }

    @Override
    public void close() {
      if (authorization != null) {
        authorization.close();
      }
    }
  }

  private AppHost.CatalogMutationAuthorizationLease retainRoutineReviewerAuthorization(
      AppCatalogInstallPlan plan, InstalledAppOrigin targetOrigin, boolean install)
      throws IOException {
    return catalogAuthority.retainRoutineAuthorization(plan, targetOrigin, install);
  }

  private AppHost.CatalogMutationAuthorizationLease retainHistoricalReviewerAuthorization(
      InstalledAppOrigin origin, AppCatalogEntry entry) throws IOException {
    return catalogAuthority.retainHistoricalAuthorization(origin, entry);
  }

  private InstalledAppOrigin catalogOrigin(StagedUpdate staged) {
    return AppUpdateFederationAuthority.installedOrigin(
        staged.plan(),
        staged.candidate(),
        staged.sourceSwitchAuthorization().expectedCurrentOriginDigestSha256().orElse(null),
        catalogManager.federationEnabled());
  }

  private AppHost.CatalogMutationAuthorization catalogMutationAuthorization(
      AppCatalogInstallPlan plan, boolean explicitSourceSwitchAuthorized) {
    return targetOrigin -> {
      AppHost.CatalogMutationAuthorizationLease authorization =
          requireFederatedConflictPolicy().retainCatalogPlanAuthorization(catalogManager, plan);
      boolean transferred = false;
      try {
        InstalledAppSnapshot currentInstalled = appHost.describe(plan.entry().appId()).orElse(null);
        if (currentInstalled == null) {
          throw new AppHostException(APP_NOT_INSTALLED_PREFIX + plan.entry().appId());
        }
        AppHost.CatalogMutationAuthorizationLease scopedPolicyAuthorization =
            retainDirectCatalogPolicyAuthorization(
                plan, currentInstalled, targetOrigin, explicitSourceSwitchAuthorized);
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

  private InstalledAppSnapshot requireInstalled(String appId) {
    try {
      Optional<InstalledAppSnapshot> installed = appHost.describe(appId);
      if (installed.isPresent()) {
        return installed.get();
      }
      clearStateForMissingApp(appId);
      throw appNotFound();
    } catch (IOException _) {
      throw lifecycleFailure(500, "app_read_failed", "Failed to read installed app.");
    }
  }

  private void clearStateForMissingApp(String appId) {
    clearAppState(appId);
  }

  private static PlatformApiException appNotFound() {
    return new PlatformApiException(404, "app_not_found", "App not found.");
  }

  private static String normalizeInstalledAppId(String appId) {
    try {
      return AppManifest.normalizeAppId(appId);
    } catch (IllegalArgumentException _) {
      throw new PlatformApiException(
          400, "invalid_app_id", "App identifier is not a valid AppHost id.");
    }
  }

  private void invalidateStaleStage(String appId, AppUpdateCandidate candidate) {
    StagedUpdate staged = stagedUpdates.get(appId);
    if (staged == null) {
      return;
    }
    if (!sameStagedCandidate(staged.candidate(), candidate)) {
      closeStage(appId);
      appendHistory(
          appId,
          ACTION_STAGE,
          STATUS_FAILED,
          candidate.catalogId(),
          candidate.targetVersion(),
          "staged_candidate_invalidated",
          "Previous staged update no longer matches the catalog candidate.");
    }
  }

  private void invalidateStaleSummaryState(String appId, InstalledAppSnapshot installed) {
    StagedUpdate staged = stagedUpdates.get(appId);
    if (staged != null && stageDiffersFromInstalled(staged, installed)) {
      AppUpdateCandidate stagedCandidate = staged.candidate();
      closeStage(appId);
      appendHistory(
          appId,
          ACTION_STAGE,
          STATUS_FAILED,
          stagedCandidate.catalogId(),
          stagedCandidate.targetVersion(),
          ERROR_UPDATE_CANDIDATE_CHANGED,
          MESSAGE_STAGED_UPDATE_NO_LONGER_MATCHES);
    }
    AppUpdateCandidate candidate = candidates.get(appId);
    if (candidate != null && candidateDiffersFromInstalled(candidate, installed)) {
      candidates.remove(appId);
    }
  }

  private boolean stageDiffersFromInstalled(StagedUpdate staged, InstalledAppSnapshot installed) {
    return candidateDiffersFromInstalled(staged.candidate(), installed)
        || planDiffersFromCandidate(staged.candidate(), installed, staged.plan);
  }

  private static boolean candidateDiffersFromInstalled(
      AppUpdateCandidate candidate, InstalledAppSnapshot installed) {
    String installedVersion = installed.manifest().appVersion();
    if (candidate.status() == AppUpdateCandidateStatus.APPLIED) {
      return !candidate.targetVersion().equals(installedVersion);
    }
    if (candidate.status() == AppUpdateCandidateStatus.FAILED
        && candidate.targetVersion().equals(installedVersion)) {
      return false;
    }
    return !candidate.installedVersion().equals(installedVersion)
        || !candidateInstalledPermissions(candidate).equals(permissionSet(installed));
  }

  private static java.util.Set<String> candidateInstalledPermissions(AppUpdateCandidate candidate) {
    java.util.LinkedHashSet<String> permissions = new java.util.LinkedHashSet<>();
    permissions.addAll(deltaPermissions(candidate.permissionDelta(), "unchanged"));
    permissions.addAll(deltaPermissions(candidate.permissionDelta(), "removed"));
    return java.util.Collections.unmodifiableSet(permissions);
  }

  private static java.util.Set<String> permissionSet(InstalledAppSnapshot installed) {
    return java.util.Collections.unmodifiableSet(
        new java.util.LinkedHashSet<>(installed.manifest().permissions()));
  }

  private static List<String> deltaPermissions(Map<String, Object> permissionDelta, String key) {
    Object value = permissionDelta.get(key);
    if (!(value instanceof List<?> values)) {
      return List.of();
    }
    java.util.ArrayList<String> permissions = new java.util.ArrayList<>(values.size());
    for (Object item : values) {
      if (item instanceof String permission) {
        permissions.add(permission);
      }
    }
    return List.copyOf(permissions);
  }

  private static boolean sameStagedCandidate(
      AppUpdateCandidate stagedCandidate, AppUpdateCandidate currentCandidate) {
    return stagedCandidate.appId().equals(currentCandidate.appId())
        && stagedCandidate.catalogId().equals(currentCandidate.catalogId())
        && stagedCandidate.catalogSourceId().equals(currentCandidate.catalogSourceId())
        && stagedCandidate.installedVersion().equals(currentCandidate.installedVersion())
        && stagedCandidate.targetVersion().equals(currentCandidate.targetVersion())
        && stagedCandidate.status() == currentCandidate.status()
        && stagedCandidate.versionComparison().equals(currentCandidate.versionComparison())
        && stagedCandidate.channel().equals(currentCandidate.channel())
        && stagedCandidate.supportStatus().equals(currentCandidate.supportStatus())
        && stagedCandidate.deprecation().equals(currentCandidate.deprecation())
        && stagedCandidate.securityAdvisories().equals(currentCandidate.securityAdvisories())
        && stagedCandidate.securityDecision().equals(currentCandidate.securityDecision())
        && stagedCandidate.bundleSha256().equals(currentCandidate.bundleSha256())
        && stagedCandidate.bundleSizeBytes() == currentCandidate.bundleSizeBytes()
        && stagedCandidate.bundleType().equals(currentCandidate.bundleType())
        && stagedCandidate.review().equals(currentCandidate.review())
        && stagedCandidate.reviewTrust().equals(currentCandidate.reviewTrust())
        && stagedCandidate.apiCompatibility().equals(currentCandidate.apiCompatibility())
        && stagedCandidate.permissionDelta().equals(currentCandidate.permissionDelta());
  }

  private void closeStage(String appId) {
    StagedUpdate staged = stagedUpdates.remove(appId);
    if (staged != null) {
      closePlan(staged.plan);
    }
  }

  private static void closePlan(AppCatalogInstallPlan plan) {
    if (plan == null) {
      return;
    }
    try {
      plan.close();
    } catch (IOException _) {
      // A failed cleanup must not expose or promote the private staging path.
    }
  }

  private void appendHistory(
      String appId,
      String action,
      String status,
      String catalogId,
      String targetVersion,
      String errorCode,
      String message) {
    Deque<AppUpdateHistoryEntry> entries =
        history.computeIfAbsent(appId, _ -> new ArrayDeque<>(MAX_HISTORY_ENTRIES));
    entries.addFirst(
        new AppUpdateHistoryEntry(
            Instant.now(), action, status, catalogId, targetVersion, errorCode, message));
    while (entries.size() > MAX_HISTORY_ENTRIES) {
      entries.removeLast();
    }
  }

  private void recordLastCheck(String appId, Instant checkedAt, String errorCode, String message) {
    lastChecks.put(appId, new LastCheck(checkedAt, errorCode, message));
  }

  private static PlatformApiException catalogFailure(AppCatalogException exception) {
    return switch (exception.errorCode()) {
      case "catalog_not_found", "app_not_found" ->
          new PlatformApiException(404, exception.errorCode(), exception.getMessage());
      case "catalog_conflict" ->
          new PlatformApiException(409, exception.errorCode(), exception.getMessage());
      case "catalog_fetch_unavailable" ->
          new PlatformApiException(503, exception.errorCode(), exception.getMessage());
      case "catalog_fetch_failed" ->
          new PlatformApiException(502, exception.errorCode(), exception.getMessage());
      default -> new PlatformApiException(400, exception.errorCode(), exception.getMessage());
    };
  }

  private static boolean isRunningUpdateFailure(AppHostException exception) {
    String message = exception.getMessage();
    return message != null && message.startsWith(CANNOT_UPDATE_RUNNING_APP_PREFIX);
  }

  private static boolean isRunningRollbackFailure(AppHostException exception) {
    String message = exception.getMessage();
    return message != null && message.startsWith(CANNOT_ROLLBACK_RUNNING_APP_PREFIX);
  }

  private static boolean isMissingAppFailure(AppHostException exception) {
    String message = exception.getMessage();
    return message != null && message.startsWith(APP_NOT_INSTALLED_PREFIX);
  }

  private static boolean isRollbackRecordUnavailableFailure(AppHostException exception) {
    String message = exception.getMessage();
    return message != null && message.startsWith(ROLLBACK_RECORD_NOT_AVAILABLE_PREFIX);
  }

  private static boolean isSignedBundleVerificationFailure(AppHostException exception) {
    return AppUpdateBundleSupport.isSignedBundleVerificationFailure(exception);
  }

  private static boolean isInvalidAppBundleFailure(AppHostException exception) {
    return AppUpdateBundleSupport.isInvalidBundleFailure(exception);
  }

  private static PlatformApiException lifecycleFailure(
      int statusCode, String errorCode, String message) {
    return new PlatformApiException(statusCode, errorCode, message);
  }

  /**
   * Supported process health check modes for apply.
   *
   * <p>Health checks are intentionally limited in this first lifecycle version. The service can
   * either skip post-apply health verification or require that AppHost can observe a running
   * process after an explicit restart. App-provided HTTP health endpoints are outside this enum and
   * can be added later without changing the existing meanings.
   */
  public enum HealthCheckMode {
    /**
     * Do not perform a post-apply health check.
     *
     * <p>The service still reports apply failures from AppHost. It simply does not start or inspect
     * a process for health after replacement.
     */
    NONE,

    /**
     * Treat a readable running process state as the v1 health check.
     *
     * <p>This mode is valid only when restart is requested, because a stopped app cannot satisfy a
     * process health check without launching a new process.
     */
    PROCESS
  }

  /**
   * Apply options decoded by the API handler.
   *
   * <p>The options are request-scoped and do not change the stored app update policy. They describe
   * whether the service may stop/start the app for this apply, whether process health should be
   * verified after restart, and whether a committed update should be rolled back when that health
   * check fails. The service validates combinations that cannot work, such as process health
   * without restart, before replacing the bundle.
   *
   * @param restart whether this applies request may stop and start the app
   * @param healthCheck post-apply health check mode requested by the caller
   * @param rollbackOnHealthFailure whether a committed update should roll back after health failure
   */
  public record ApplyOptions(
      boolean restart, HealthCheckMode healthCheck, boolean rollbackOnHealthFailure) {
    /**
     * Creates validated apply options.
     *
     * <p>Only the health check enum requires structural validation here. Cross-field validation is
     * performed by {@link #apply(String, ApplyOptions)} because it needs current app state.
     */
    public ApplyOptions {
      Objects.requireNonNull(healthCheck, "healthCheck");
    }

    static ApplyOptions policyDefault() {
      return new ApplyOptions(false, HealthCheckMode.NONE, false);
    }
  }

  private record StagedUpdate(
      AppUpdateCandidate candidate,
      AppCatalogInstallPlan plan,
      AppDataMigrationPlan migrationPlan,
      SourceSwitchAuthorization sourceSwitchAuthorization,
      Instant stagedAt) {
    private StagedUpdate {
      Objects.requireNonNull(candidate, "candidate");
      Objects.requireNonNull(plan, "plan");
      Objects.requireNonNull(migrationPlan, "migrationPlan");
      Objects.requireNonNull(sourceSwitchAuthorization, "sourceSwitchAuthorization");
      Objects.requireNonNull(stagedAt, JSON_STAGED_AT);
    }

    private Path stagedBundleDirectory() {
      return plan.stagedBundleDirectory();
    }

    private AppCatalogEntry entry() {
      return plan.entry();
    }
  }

  private record SourceSwitchAuthorization(
      Optional<InstalledAppOrigin> expectedCurrentOrigin,
      Optional<String> approvedConsentDigestSha256) {
    private SourceSwitchAuthorization {
      Objects.requireNonNull(expectedCurrentOrigin, "expectedCurrentOrigin");
      Objects.requireNonNull(approvedConsentDigestSha256, "approvedConsentDigestSha256");
    }

    private static SourceSwitchAuthorization withoutCurrentOrigin() {
      return new SourceSwitchAuthorization(Optional.empty(), Optional.empty());
    }

    private static SourceSwitchAuthorization forCurrentOrigin(
        InstalledAppOrigin current, String approvedConsentDigestSha256) {
      return new SourceSwitchAuthorization(
          Optional.of(Objects.requireNonNull(current, "current")),
          Optional.ofNullable(approvedConsentDigestSha256));
    }

    private Optional<String> expectedCurrentOriginDigestSha256() {
      return expectedCurrentOrigin.map(InstalledAppOrigin::selfDigestSha256);
    }

    private AppHost.CatalogOriginExpectation expectedCurrentOriginExpectation() {
      return expectedCurrentOriginDigestSha256()
          .map(AppHost.CatalogOriginExpectation::matching)
          .orElseGet(AppHost.CatalogOriginExpectation::absent);
    }

    private boolean matches(InstalledAppOrigin current) {
      return expectedCurrentOriginDigestSha256()
          .equals(Optional.ofNullable(current).map(InstalledAppOrigin::selfDigestSha256));
    }
  }

  private static final class StagePlanLease implements AutoCloseable {
    private AppCatalogInstallPlan plan;

    private StagePlanLease(AppCatalogInstallPlan plan) {
      this.plan = Objects.requireNonNull(plan, "plan");
    }

    private AppCatalogInstallPlan plan() {
      return Objects.requireNonNull(plan, "plan");
    }

    private AppCatalogInstallPlan release() {
      AppCatalogInstallPlan retainedPlan = plan();
      plan = null;
      return retainedPlan;
    }

    @Override
    public void close() {
      closePlan(plan);
      plan = null;
    }
  }

  private record ApplyFailureContext(
      String appId,
      StagedUpdate staged,
      boolean wasRunning,
      InstalledAppSnapshot original,
      InstalledAppSnapshot updated,
      HealthFailureState healthFailureState,
      AppDataUpdateSnapshot appDataSnapshot,
      AppDataMigrationPlan migrationPlan) {
    private ApplyFailureContext {
      Objects.requireNonNull(appId, JSON_APP_ID);
      Objects.requireNonNull(staged, "staged");
      Objects.requireNonNull(original, "original");
      Objects.requireNonNull(healthFailureState, "healthFailureState");
      Objects.requireNonNull(migrationPlan, "migrationPlan");
    }
  }

  private record LastCheck(Instant checkedAt, String errorCode, String message) {
    private LastCheck {
      Objects.requireNonNull(checkedAt, "checkedAt");
    }

    private String status() {
      return errorCode == null ? STATUS_SUCCESS : STATUS_FAILED;
    }
  }

  private static final class HealthFailureState {
    private boolean rollbackCommitted;
    private boolean appDataRestored;
    private boolean rollbackFailed;
    private InstalledAppSnapshot rolledBackSnapshot;

    private boolean rollbackCommitted() {
      return rollbackCommitted;
    }

    private boolean appDataRestored() {
      return appDataRestored;
    }

    private boolean rollbackFailed() {
      return rollbackFailed;
    }

    private InstalledAppSnapshot rolledBackSnapshot() {
      return Objects.requireNonNull(rolledBackSnapshot, "rolledBackSnapshot");
    }

    private void markRollbackCommitted(InstalledAppSnapshot rolledBackSnapshot) {
      this.rolledBackSnapshot = Objects.requireNonNull(rolledBackSnapshot, "rolledBackSnapshot");
      rollbackCommitted = true;
    }

    private void markAppDataRestored() {
      appDataRestored = true;
    }

    private void markRollbackFailed() {
      rollbackFailed = true;
    }
  }
}
