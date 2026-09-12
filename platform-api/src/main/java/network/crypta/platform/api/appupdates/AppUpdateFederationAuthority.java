package network.crypta.platform.api.appupdates;

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import network.crypta.platform.api.PlatformApiException;
import network.crypta.platform.appcatalog.AppCatalogChannel;
import network.crypta.platform.appcatalog.AppCatalogEntry;
import network.crypta.platform.appcatalog.AppCatalogException;
import network.crypta.platform.appcatalog.AppCatalogInstallPlan;
import network.crypta.platform.appcatalog.AppCatalogManager;
import network.crypta.platform.appcatalog.AppCatalogOriginContext;
import network.crypta.platform.appcatalog.CatalogPublisherBinding;
import network.crypta.platform.appcatalog.CatalogScopeRevocation;
import network.crypta.platform.appcatalog.FederatedCatalogConflictEngine;
import network.crypta.platform.appcatalog.FederatedCatalogTrustBinding;
import network.crypta.platform.appcatalog.FileCatalogPublisherBindingStore;
import network.crypta.platform.appcatalog.FileFederatedCatalogConflictResolutionStore;
import network.crypta.platform.appcatalog.FileFederatedCatalogTrustStore;
import network.crypta.platform.apphost.AppHost;
import network.crypta.platform.apphost.AppHostException;
import network.crypta.platform.apphost.AppRollbackRecord;
import network.crypta.platform.apphost.InstalledAppOrigin;

/**
 * Owns the local federation stores used by app-update conflict and publisher authorization.
 *
 * <p>The update lifecycle coordinates candidate selection and AppHost mutations, while this class
 * keeps catalog trust bindings and catalog/app-scoped publisher bindings behind one role-specific
 * boundary. It constructs conflict subjects only from an active catalog binding and exactly one
 * active publisher binding. It also retains publisher-store leases through routine update commits
 * and historical rollbacks.
 *
 * <p>Instances contain no catalog or publisher key material. They reference host-owned stores and
 * never infer trust from catalog content. Callers must combine the returned publisher lease with
 * the independent catalog, reviewer, and conflict-resolution leases before executable bytes are
 * committed. The class is thread-safe to the extent provided by those file-backed stores.
 */
public final class AppUpdateFederationAuthority {
  /** Error code returned when current publisher authorization no longer matches the target. */
  private static final String ERROR_PUBLISHER_AUTHORIZATION_CHANGED =
      "catalog_publisher_authorization_changed";

  /** Store containing explicit catalog-ID and signer trust bindings. */
  private final FileFederatedCatalogTrustStore catalogTrustStore;

  /** Store containing catalog/app-scoped publisher authorization. */
  private final FileCatalogPublisherBindingStore publisherBindingStore;

  /** Authority that classifies and retains exact local conflict decisions. */
  private final AppUpdateConflictAuthority conflictAuthority;

  /**
   * Creates one update authority over the node's host-owned federation stores.
   *
   * <p>The constructor does not read or mutate the stores. Each authorization method reads the
   * current policy and, where required, retains the store's same-thread lease until the caller
   * closes it. Supplying the stores explicitly prevents catalog refresh content from replacing the
   * local trust or publisher policy used by the update lifecycle.
   *
   * @param catalogTrustStore exact catalog-ID and signer trust bindings
   * @param publisherBindingStore catalog/app-scoped publisher authorization bindings
   * @param conflictResolutionStore exact-subject local conflict resolutions
   */
  public AppUpdateFederationAuthority(
      FileFederatedCatalogTrustStore catalogTrustStore,
      FileCatalogPublisherBindingStore publisherBindingStore,
      FileFederatedCatalogConflictResolutionStore conflictResolutionStore) {
    this.catalogTrustStore = Objects.requireNonNull(catalogTrustStore, "catalogTrustStore");
    this.publisherBindingStore =
        Objects.requireNonNull(publisherBindingStore, "publisherBindingStore");
    this.conflictAuthority =
        new AppUpdateConflictAuthority(
            this, Objects.requireNonNull(conflictResolutionStore, "conflictResolutionStore"));
  }

  /**
   * Returns the conflict authority sharing these federation stores.
   *
   * @return cross-catalog conflict authority for the update lifecycle
   */
  AppUpdateConflictAuthority conflicts() {
    return conflictAuthority;
  }

  /**
   * Creates an exact local conflict-resolution request.
   *
   * @param expectedConflictId conflict identifier presented to the operator
   * @param expectedSubjectSetDigest exact digest of the presented subjects
   * @param kind requested closed local resolution kind
   * @param catalogId optional catalog selected by the resolution
   * @param publisherFingerprint optional publisher selected by the resolution
   * @param reason bounded operator audit reason
   * @return validated request consumed by the conflict authority
   */
  static AppUpdateConflictAuthority.ResolutionRequest conflictResolutionRequest(
      String expectedConflictId,
      String expectedSubjectSetDigest,
      String kind,
      String catalogId,
      String publisherFingerprint,
      String reason) {
    return new AppUpdateConflictAuthority.ResolutionRequest(
        expectedConflictId,
        expectedSubjectSetDigest,
        kind,
        catalogId,
        publisherFingerprint,
        reason);
  }

  /**
   * Returns a bounded summary of AppHost rollback availability.
   *
   * @param appHost host service containing rollback state
   * @param appId exact installed application identifier
   * @return stable JSON-compatible rollback summary
   */
  static Map<String, Object> rollbackSummary(AppHost appHost, String appId) {
    AppRollbackRecord rollbackRecord;
    String statusErrorCode = null;
    String statusMessage = null;
    try {
      rollbackRecord = appHost.rollbackStatus(appId).orElse(null);
    } catch (IOException _) {
      rollbackRecord = null;
      statusErrorCode = "rollback_failed";
      statusMessage = "Rollback state could not be inspected.";
    }
    boolean available = rollbackRecord != null;
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(8);
    json.put("available", available);
    json.put("status", statusErrorCode == null ? rollbackStatus(available) : "failed");
    json.put("appId", appId);
    json.put("createdAt", null);
    json.put("previousVersion", rollbackRecord == null ? null : rollbackRecord.appVersion());
    json.put("previousName", rollbackRecord == null ? null : rollbackRecord.appName());
    json.put("replacedVersion", null);
    json.put("retentionLimit", 1);
    json.put("scope", "bundle_only");
    json.put("errorCode", statusErrorCode);
    json.put("message", statusMessage);
    return json;
  }

  /**
   * Reports whether AppHost retains a rollback bundle for an application.
   *
   * @param appHost host service containing rollback state
   * @param appId exact installed application identifier
   * @return {@code true} when a retained rollback bundle exists
   */
  static boolean rollbackAvailable(AppHost appHost, String appId) {
    try {
      return appHost.rollbackStatus(appId).isPresent();
    } catch (IOException _) {
      throw new PlatformApiException(
          500, "rollback_failed", "Rollback state could not be inspected.");
    }
  }

  /**
   * Maps rollback availability to its bounded API status.
   *
   * @param rollbackAvailable whether a retained rollback bundle exists
   * @return {@code available} or {@code none}
   */
  private static String rollbackStatus(boolean rollbackAvailable) {
    return rollbackAvailable ? "available" : "none";
  }

  /**
   * Revokes an exact publisher scope in the existing host-owned authorization store.
   *
   * @param request expected-current host-operator request
   * @return persisted terminal publisher binding
   * @throws IOException if current policy cannot be safely persisted
   */
  public CatalogPublisherBinding revokePublisherScope(CatalogScopeRevocation request)
      throws IOException {
    return publisherBindingStore.revoke(request);
  }

  /**
   * Creates one conflict subject from current catalog and publisher policy.
   *
   * @param candidate authenticated catalog update candidate
   * @param reviewPolicyDigest catalog-independent reviewer-policy digest
   * @param securityDecisionDigest catalog-local security-decision digest
   * @param metadataDigest conflict-relevant candidate metadata digest
   * @return trusted conflict subject and catalog-local priority
   */
  SubjectSelection conflictSubject(
      AppUpdateCandidate candidate,
      String reviewPolicyDigest,
      String securityDecisionDigest,
      String metadataDigest) {
    try {
      FederatedCatalogTrustBinding catalogBinding =
          catalogTrustStore
              .findByCatalogId(candidate.catalogId())
              .filter(binding -> binding.status() == FederatedCatalogTrustBinding.Status.ACTIVE)
              .orElseThrow(
                  () ->
                      new AppCatalogException(
                          "catalog_trust_required", "active catalog trust binding is required"));
      AppCatalogChannel channel = AppCatalogChannel.parse(candidate.channel(), "candidate.channel");
      if (!catalogBinding.allowedChannels().contains(channel)) {
        throw new AppCatalogException(
            "catalog_channel_not_trusted", "catalog channel is outside the local trust binding");
      }
      List<CatalogPublisherBinding> publishers =
          publisherBindingStore.findActiveForScope(
              candidate.catalogId(), candidate.appId(), channel, candidate.detectedAt());
      if (publishers.size() != 1) {
        throw new AppCatalogException(
            "catalog_publisher_scope_ambiguous",
            "exactly one active publisher binding is required for conflict selection");
      }
      CatalogPublisherBinding publisher = publishers.getFirst();
      FederatedCatalogConflictEngine.Subject subject =
          new FederatedCatalogConflictEngine.Subject(
              candidate.catalogId(),
              catalogBinding.selfDigest(),
              candidate.appId(),
              candidate.targetVersion(),
              candidate.bundleSha256(),
              candidate.bundleType(),
              publisher.publisherKeyFingerprintSha256(),
              publisherLineageDigest(
                  publisher,
                  publisherBindingStore.findLineageForScope(
                      candidate.catalogId(), candidate.appId(), channel)),
              reviewPolicyDigest,
              securityDecisionDigest,
              metadataDigest);
      return new SubjectSelection(subject, catalogBinding.localPriority());
    } catch (IOException exception) {
      throw new AppCatalogException(
          "catalog_conflict_policy_unavailable",
          "catalog conflict policy could not be read",
          exception);
    }
  }

  /**
   * Retains historical publisher authorization for an exact rollback origin.
   *
   * @param origin retained installed-origin provenance
   * @param entry retained catalog entry matching the rollback bundle
   * @return lease retaining historical publisher policy through commit
   * @throws IOException if current publisher policy cannot be read safely
   */
  AppHost.CatalogMutationAuthorizationLease retainHistoricalPublisherAuthorization(
      InstalledAppOrigin origin, AppCatalogEntry entry) throws IOException {
    FederatedCatalogTrustBinding catalogBinding =
        catalogTrustStore
            .findByCatalogId(origin.catalogId())
            .orElseThrow(AppHostException.CatalogRollbackAuthorizationException::new);
    String expectedPolicyDigest =
        catalogBinding
            .publisherPolicyDigest()
            .orElseThrow(AppHostException.CatalogRollbackAuthorizationException::new);
    AppCatalogChannel channel = entry.productionMetadata().channel();
    return new PublisherAuthorizationLease(
        publisherBindingStore.retainHistoricalAuthorization(
            origin.catalogId(),
            expectedPolicyDigest,
            origin.appId(),
            origin.publisherKeyId(),
            origin.publisherKeyFingerprintSha256(),
            channel,
            origin.installedAt()));
  }

  /**
   * Authorizes exact retained provenance under current historical catalog policy.
   *
   * @param catalogManager manager containing current catalog trust policy
   * @param origin retained installed-origin provenance
   * @return historical catalog authorization and retained catalog entry
   * @throws IOException if catalog or retained-revision state cannot be read
   */
  AppCatalogManager.HistoricalAppOriginAuthorization authorizeHistoricalCatalog(
      AppCatalogManager catalogManager, InstalledAppOrigin origin) throws IOException {
    AppCatalogOriginContext catalogOrigin =
        new AppCatalogOriginContext(
            origin.catalogId(),
            origin.catalogSignerKeyId(),
            origin.catalogSignerFingerprintSha256(),
            origin.catalogRevisionDigestSha256(),
            origin.catalogTrustBindingId(),
            origin.catalogTrustBindingDigestSha256(),
            "",
            "",
            true);
    return catalogManager.authorizeHistoricalAppOriginForRollback(
        catalogOrigin, origin.appId(), origin.appVersion(), origin.bundleSha256());
  }

  /**
   * Retains publisher authorization for a routine install or update commit.
   *
   * @param plan exact reverified catalog install plan
   * @param targetOrigin provenance that will accompany the committed bundle
   * @return lease retaining the exact publisher binding through commit
   * @throws IOException if publisher policy cannot be read or retained safely
   */
  AppHost.CatalogMutationAuthorizationLease retainRoutinePublisherAuthorization(
      AppCatalogInstallPlan plan, InstalledAppOrigin targetOrigin) throws IOException {
    var publisher = plan.bundleVerification();
    if (!publisher.catalogScoped()
        || !plan.catalogId().equals(targetOrigin.catalogId())
        || !plan.entry().appId().equals(targetOrigin.appId())
        || !plan.entry().version().equals(targetOrigin.appVersion())
        || !plan.entry().bundleSha256().equals(targetOrigin.bundleSha256())
        || !publisher.publisherKeyId().equals(targetOrigin.publisherKeyId())
        || !publisher
            .publisherKeyFingerprintSha256()
            .equals(targetOrigin.publisherKeyFingerprintSha256())
        || !publisher
            .signedContentDigestSha256()
            .equals(targetOrigin.signedContentDigestSha256())) {
      throw publisherAuthorizationChanged(
          "The exact catalog publisher authorization changed before commit.");
    }
    FederatedCatalogTrustBinding catalogBinding =
        catalogTrustStore
            .findByCatalogId(plan.catalogId())
            .orElseThrow(
                () ->
                    publisherAuthorizationChanged(
                        "The catalog publisher policy is no longer authorized."));
    String expectedPolicyDigest =
        catalogBinding
            .publisherPolicyDigest()
            .orElseThrow(
                () ->
                    publisherAuthorizationChanged(
                        "The catalog publisher policy is no longer authorized."));
    if (!publisher
        .authorizationPolicyDigestSha256()
        .equals(targetOrigin.publisherPolicyDigestSha256())) {
      throw publisherAuthorizationChanged(
          "The selected catalog publisher binding changed before commit.");
    }
    return new PublisherAuthorizationLease(
        publisherBindingStore.retainAuthorization(
            plan.catalogId(),
            expectedPolicyDigest,
            plan.entry().appId(),
            publisher,
            plan.entry().productionMetadata().channel(),
            Instant.now()));
  }

  /**
   * Retains catalog trust authorization for an exact reverified plan.
   *
   * @param catalogManager manager containing current catalog trust policy
   * @param plan exact retained installation plan being committed
   * @return lease retaining catalog authorization through commit
   * @throws IOException if catalog trust state cannot be read safely
   */
  AppHost.CatalogMutationAuthorizationLease retainCatalogPlanAuthorization(
      AppCatalogManager catalogManager, AppCatalogInstallPlan plan) throws IOException {
    AppCatalogManager.CatalogTrustAuthorization authorization =
        catalogManager.authorizeInstallPlanForMutation(plan);
    return authorization::close;
  }

  /**
   * Creates host-owned provenance for a federation-scoped catalog plan.
   *
   * @param plan exact verified catalog install plan
   * @param candidate lifecycle candidate whose review result was presented
   * @param previousOriginDigest optional digest of the previous origin record
   * @param federationEnabled whether federation enforcement is currently enabled
   * @return exact installed origin, or {@code null} for a compatibility plan
   */
  static InstalledAppOrigin installedOrigin(
      AppCatalogInstallPlan plan,
      AppUpdateCandidate candidate,
      String previousOriginDigest,
      boolean federationEnabled) {
    AppCatalogOriginContext catalog = plan.originContext().orElse(null);
    if (catalog == null || !catalog.federationScoped() || !federationEnabled) {
      return null;
    }
    String receiptFingerprint = CatalogSourceSwitchConsent.reviewReceiptFingerprint(plan);
    Object reviewStatus = candidate.reviewTrust().get("status");
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
        reviewStatus == null ? "unknown" : reviewStatus.toString(),
        catalog.trustBindingId(),
        catalog.trustBindingDigestSha256(),
        publisher.authorizationPolicyDigestSha256(),
        catalog.reviewerPolicyDigestSha256(),
        Instant.now(),
        previousOriginDigest);
  }

  /**
   * Computes a stable digest over the publisher key lineage identifiers.
   *
   * @param binding exact publisher binding selected for the candidate
   * @param lineageBindings locally authorized bindings that can connect the selected key lineage
   * @return lowercase SHA-256 lineage digest
   */
  private static String publisherLineageDigest(
      CatalogPublisherBinding binding, List<CatalogPublisherBinding> lineageBindings) {
    Map<String, CatalogPublisherBinding> bindingsByKeyId = new HashMap<>();
    lineageBindings.forEach(
        candidate -> bindingsByKeyId.put(candidate.publisherKeyId(), candidate));
    bindingsByKeyId.put(binding.publisherKeyId(), binding);
    ArrayDeque<String> pending = new ArrayDeque<>();
    HashSet<String> visited = new HashSet<>();
    TreeSet<String> fingerprints = new TreeSet<>();
    pending.add(binding.publisherKeyId());
    while (!pending.isEmpty()) {
      String keyId = pending.removeFirst();
      if (visited.add(keyId)) {
        addPublisherLineage(keyId, bindingsByKeyId, pending, fingerprints);
      }
    }
    return AppUpdateDigestSupport.sha256(String.join("\n", fingerprints) + "\n");
  }

  /**
   * Adds one known publisher key and its directly declared lineage neighbors to the traversal.
   *
   * @param keyId publisher key identifier currently being visited
   * @param bindingsByKeyId locally authorized publisher bindings indexed by key identifier
   * @param pending traversal queue that receives unvisited lineage neighbors
   * @param fingerprints collected publisher fingerprints that define the connected lineage
   */
  private static void addPublisherLineage(
      String keyId,
      Map<String, CatalogPublisherBinding> bindingsByKeyId,
      Deque<String> pending,
      Set<String> fingerprints) {
    CatalogPublisherBinding current = bindingsByKeyId.get(keyId);
    if (current == null) {
      return;
    }
    fingerprints.add(current.publisherKeyFingerprintSha256());
    current.predecessorKeyId().filter(bindingsByKeyId::containsKey).ifPresent(pending::addLast);
    current.successorKeyId().filter(bindingsByKeyId::containsKey).ifPresent(pending::addLast);
    for (CatalogPublisherBinding candidate : bindingsByKeyId.values()) {
      if (candidate.predecessorKeyId().filter(keyId::equals).isPresent()
          || candidate.successorKeyId().filter(keyId::equals).isPresent()) {
        pending.addLast(candidate.publisherKeyId());
      }
    }
  }

  /**
   * Creates the conflict response for changed publisher authorization.
   *
   * @param message bounded operator-facing reason
   * @return stable publisher-authorization-changed exception
   */
  private static PlatformApiException publisherAuthorizationChanged(String message) {
    return new PlatformApiException(409, ERROR_PUBLISHER_AUTHORIZATION_CHANGED, message);
  }

  /**
   * Adapts a publisher-store authorization lease to the AppHost contract.
   *
   * @param authorization retained publisher-store authorization
   */
  private record PublisherAuthorizationLease(
      FileCatalogPublisherBindingStore.AuthorizationLease authorization)
      implements AppHost.CatalogMutationAuthorizationLease {
    /** Validates the retained publisher authorization. */
    private PublisherAuthorizationLease {
      Objects.requireNonNull(authorization, "authorization");
    }

    @Override
    public void close() {
      authorization.close();
    }
  }

  /**
   * Carries a trusted conflict subject with its catalog's local priority.
   *
   * @param subject canonical conflict-engine subject
   * @param localPriority operator-configured catalog priority
   */
  record SubjectSelection(FederatedCatalogConflictEngine.Subject subject, int localPriority) {
    /** Validates the canonical conflict subject. */
    SubjectSelection {
      Objects.requireNonNull(subject, "subject");
    }
  }
}
