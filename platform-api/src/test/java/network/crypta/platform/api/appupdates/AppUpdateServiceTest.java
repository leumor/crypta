package network.crypta.platform.api.appupdates;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import network.crypta.platform.api.PlatformApiContract;
import network.crypta.platform.api.PlatformApiException;
import network.crypta.platform.api.appdata.AppDataService;
import network.crypta.platform.api.appdata.AppDataStore;
import network.crypta.platform.api.appdata.AppDataStoreConfig;
import network.crypta.platform.api.appdata.InMemoryAppDataStore;
import network.crypta.platform.appcatalog.AppCatalogBundleVerificationResult;
import network.crypta.platform.appcatalog.AppCatalogChangelog;
import network.crypta.platform.appcatalog.AppCatalogChannel;
import network.crypta.platform.appcatalog.AppCatalogCompatibilityMetadata;
import network.crypta.platform.appcatalog.AppCatalogDeprecationStatus;
import network.crypta.platform.appcatalog.AppCatalogEntry;
import network.crypta.platform.appcatalog.AppCatalogException;
import network.crypta.platform.appcatalog.AppCatalogFetchStatus;
import network.crypta.platform.appcatalog.AppCatalogInstallPlan;
import network.crypta.platform.appcatalog.AppCatalogManager;
import network.crypta.platform.appcatalog.AppCatalogOriginContext;
import network.crypta.platform.appcatalog.AppCatalogProductionMetadata;
import network.crypta.platform.appcatalog.AppCatalogReviewMetadata;
import network.crypta.platform.appcatalog.AppCatalogReviewStatus;
import network.crypta.platform.appcatalog.AppCatalogSecurityAction;
import network.crypta.platform.appcatalog.AppCatalogSecurityAdvisory;
import network.crypta.platform.appcatalog.AppCatalogSecurityDecision;
import network.crypta.platform.appcatalog.AppCatalogSecurityDecisionStatus;
import network.crypta.platform.appcatalog.AppCatalogSecuritySeverity;
import network.crypta.platform.appcatalog.AppCatalogSourceSnapshot;
import network.crypta.platform.appcatalog.AppCatalogSupportStatus;
import network.crypta.platform.appcatalog.AppReviewPolicy;
import network.crypta.platform.appcatalog.AppReviewPolicyMode;
import network.crypta.platform.appcatalog.AppReviewReceipt;
import network.crypta.platform.appcatalog.AppReviewReceiptPayload;
import network.crypta.platform.appcatalog.AppReviewReceiptSigner;
import network.crypta.platform.appcatalog.AppReviewReceiptStatus;
import network.crypta.platform.appcatalog.AppReviewReceiptVerifier;
import network.crypta.platform.appcatalog.AppReviewTransparencyEventKind;
import network.crypta.platform.appcatalog.AppReviewTransparencyLog;
import network.crypta.platform.appcatalog.AppReviewTrustDecision;
import network.crypta.platform.appcatalog.CatalogPublisherAuthorizationException;
import network.crypta.platform.appcatalog.CatalogPublisherBinding;
import network.crypta.platform.appcatalog.CatalogScopedReviewerPolicy;
import network.crypta.platform.appcatalog.FederatedCatalogConflictEngine;
import network.crypta.platform.appcatalog.FederatedCatalogTrustBinding;
import network.crypta.platform.appcatalog.FileCatalogPublisherBindingStore;
import network.crypta.platform.appcatalog.FileFederatedCatalogConflictResolutionStore;
import network.crypta.platform.appcatalog.FileFederatedCatalogTrustStore;
import network.crypta.platform.appcatalog.TrustedReviewerKey;
import network.crypta.platform.appcatalog.TrustedReviewerKeys;
import network.crypta.platform.appdist.AppApiCompatibilityMetadata.TargetStability;
import network.crypta.platform.appdist.AppApiCompatibilityMetadata;
import network.crypta.platform.appdist.AppBundleSigner;
import network.crypta.platform.appdist.AppBundleVerifier;
import network.crypta.platform.appdist.AppRestartPolicy;
import network.crypta.platform.appdist.AppUiMode;
import network.crypta.platform.appdist.TrustedAppKey;
import network.crypta.platform.appdist.TrustedAppKeys;
import network.crypta.platform.apphost.AppBundleVerificationException;
import network.crypta.platform.apphost.AppDiskUsageScanner;
import network.crypta.platform.apphost.AppHost;
import network.crypta.platform.apphost.AppHostException;
import network.crypta.platform.apphost.AppRollbackRecord;
import network.crypta.platform.apphost.InstalledAppOrigin;
import network.crypta.platform.apphost.InstalledAppPaths;
import network.crypta.platform.apphost.InstalledAppSnapshot;
import network.crypta.platform.apphost.RunningAppSnapshot;
import network.crypta.platform.apphost.manifest.AppManifest;
import network.crypta.platform.apphost.manifest.AppManifestException;
import network.crypta.platform.apphost.manifest.AppManifestParser;
import network.crypta.platform.apphost.sandbox.AppSandboxPolicy;
import network.crypta.platform.appvault.AppIdentityGrant;
import network.crypta.platform.appvault.AppIdentityGrantScope;
import network.crypta.platform.appvault.AppIdentityGrantStatus;
import network.crypta.platform.appvault.AppIdentityKind;
import network.crypta.platform.appvault.AppIdentityRecord;
import network.crypta.platform.appvault.AppVaultService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.invocation.Invocation;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockingDetails;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings({"java:S100", "unchecked"})
class AppUpdateServiceTest {
  private static final String APP_ID = "queue-manager";
  private static final String APP_NAME = "Queue Manager";
  private static final String CATALOG_ID = "core";
  private static final String DIGEST =
      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
  private static final String INSTALLED_VERSION = "1.0.0";
  private static final String UPDATE_VERSION = "1.1.0";
  private static final String EXTERNAL_VERSION = "1.2.0";
  private static final String QUEUE_READ_PERMISSION = "queue.read";
  private static final String CANDIDATE = "candidate";
  private static final String STAGED = "staged";
  private static final String ROLLBACK = "rollback";
  private static final String AVAILABLE = "available";
  private static final String STATUS = "status";
  private static final String SECURITY_DECISION = "securityDecision";
  private static final String VERSION_COMPARISON = "versionComparison";
  private static final String TARGET_VERSION = "targetVersion";
  private static final String INSTALLED_VERSION_FIELD = "installedVersion";
  private static final String OPERATOR_ACTION_REQUIRED = "operatorActionRequired";
  private static final String ERROR_CODE = "errorCode";
  private static final String MESSAGE = "message";
  private static final String FAILED = "failed";
  private static final String APPLIED = "applied";
  private static final String UPDATE_CANDIDATE_CHANGED = "update_candidate_changed";
  private static final String APP_NOT_FOUND = "app_not_found";
  private static final String ROLLBACK_FAILED = "rollback_failed";
  private static final String ROLLBACK_MANIFEST_BROKEN = "rollback manifest broken";
  private static final String FEEDS_NAMESPACE = "feeds";
  private static final String SUBSCRIPTIONS_KEY = "subscriptions";
  private static final String REVIEWER_KEY_ID = "crypta-first-party-review";
  private static final String REVIEW_POLICY_ID = "crypta-app-review-v1";
  private static final String REVIEW_POLICY_VERSION = "1";
  private static final Instant REVIEWED_AT = Instant.parse("2026-05-01T00:00:00Z");
  private static final AppUpdateService.ApplyOptions APPLY_NO_RESTART_NO_HEALTH =
      new AppUpdateService.ApplyOptions(false, AppUpdateService.HealthCheckMode.NONE, false);
  private static final AppUpdateService.ApplyOptions APPLY_NO_RESTART_PROCESS_HEALTH =
      new AppUpdateService.ApplyOptions(false, AppUpdateService.HealthCheckMode.PROCESS, false);
  private static final AppUpdateService.ApplyOptions APPLY_RESTART_NO_HEALTH =
      new AppUpdateService.ApplyOptions(true, AppUpdateService.HealthCheckMode.NONE, false);
  private static final AppUpdateService.ApplyOptions APPLY_RESTART_PROCESS_HEALTH =
      new AppUpdateService.ApplyOptions(true, AppUpdateService.HealthCheckMode.PROCESS, false);
  private static final AppUpdateService.ApplyOptions APPLY_RESTART_PROCESS_HEALTH_ROLLBACK =
      new AppUpdateService.ApplyOptions(true, AppUpdateService.HealthCheckMode.PROCESS, true);

  @Mock private AppHost appHost;
  @Mock private AppCatalogManager catalogManager;

  @TempDir private Path tempDir;

  @Test
  void check_whenManualPolicyFindsNewerCatalogVersion_expectCandidateOnly() throws Exception {
    AppUpdateService service =
        serviceWithInstalled(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID))
        .thenReturn(List.of(entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED)));

    Map<String, Object> summary = service.check(APP_ID, false);

    Map<String, Object> candidate = (Map<String, Object>) summary.get(CANDIDATE);
    Map<String, Object> staged = (Map<String, Object>) summary.get(STAGED);
    assertEquals("manual", ((Map<?, ?>) summary.get("policy")).get("mode"));
    assertEquals(AVAILABLE, candidate.get(STATUS));
    assertEquals("newer", candidate.get(VERSION_COMPARISON));
    assertEquals(UPDATE_VERSION, candidate.get(TARGET_VERSION));
    assertEquals(false, staged.get(AVAILABLE));
    assertEquals(AppCatalogSecurityDecision.OK.toJsonValue(), candidate.get(SECURITY_DECISION));
    assertEquals(
        AppCatalogSecurityDecision.OK.toJsonValue(), summary.get("installedSecurityDecision"));
    verifyNoInstallPlanPreparation();
    verify(appHost, never()).updateFromDirectory(any(), any());
  }

  @Test
  void summary_whenInstalledVersionIsDenylisted_expectExactSecurityDecision() throws Exception {
    AppUpdateService service =
        serviceWithInstalled(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    AppCatalogSecurityDecision decision = denylistedSecurityDecision();
    when(catalogManager.installedSecurityDecision(APP_ID, INSTALLED_VERSION)).thenReturn(decision);

    Map<String, Object> summary = service.summary(APP_ID);

    assertEquals(decision.toJsonValue(), summary.get("installedSecurityDecision"));
  }

  @ParameterizedTest
  @EnumSource(
      value = AppUpdatePolicyMode.class,
      names = {"STAGE", "APPLY_WHEN_STOPPED"})
  void check_whenAutomaticPolicyRequiresReview_expectMatchingTransparencyEvent(
      AppUpdatePolicyMode mode) throws Exception {
    AppUpdateService service =
        serviceWithInstalled(
            INSTALLED_VERSION,
            List.of(QUEUE_READ_PERMISSION),
            new AppReviewPolicy(AppReviewPolicyMode.REQUIRE_TRUSTED_REVIEW),
            TrustedReviewerKeys::empty);
    AppReviewTransparencyLog transparencyLog = mock(AppReviewTransparencyLog.class);
    when(catalogManager.reviewTransparencyLog()).thenReturn(transparencyLog);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID))
        .thenReturn(List.of(entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED)));
    service.setPolicy(APP_ID, mode);
    AppReviewTransparencyEventKind expectedKind =
        mode == AppUpdatePolicyMode.STAGE
            ? AppReviewTransparencyEventKind.REVIEW_GATE_UPDATE
            : AppReviewTransparencyEventKind.REVIEW_GATE_POLICY_APPLY;

    service.check(APP_ID, false);

    verify(transparencyLog).recordReviewTrustMap(eq(expectedKind), any(), any(), any());
    verifyNoInstallPlanPreparation();
    verify(appHost, never()).updateFromDirectory(any(), any());
  }

  @Test
  void check_whenCatalogSecurityDecisionWarns_expectCandidateIncludesSecurityDecision()
      throws Exception {
    AppUpdateService service =
        serviceWithInstalled(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID))
        .thenReturn(List.of(entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED)));
    when(catalogManager.securityDecision(CATALOG_ID, APP_ID)).thenReturn(warningSecurityDecision());

    Map<String, Object> summary = service.check(APP_ID, false);

    Map<String, Object> candidate = (Map<String, Object>) summary.get(CANDIDATE);
    Map<String, Object> securityDecision = (Map<String, Object>) candidate.get(SECURITY_DECISION);
    assertEquals("warning", securityDecision.get(STATUS));
    assertEquals("warn", securityDecision.get("action"));
    assertEquals(true, securityDecision.get("requiresAcknowledgement"));
    assertEquals(true, securityDecision.get("blocksAutomaticApply"));
    assertEquals(true, candidate.get(OPERATOR_ACTION_REQUIRED));
  }

  @Test
  void stage_whenSecurityWarningIsNotAcknowledged_expectStableSecurityAckError() throws Exception {
    AppUpdateService service =
        serviceWithInstalled(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID))
        .thenReturn(List.of(entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED)));
    when(catalogManager.securityDecision(CATALOG_ID, APP_ID)).thenReturn(warningSecurityDecision());

    service.check(APP_ID, false);
    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> service.stage(APP_ID));

    assertEquals(409, exception.statusCode());
    assertEquals("app_security_acknowledgement_required", exception.errorCode());
    verifyNoInstallPlanPreparation();
  }

  @Test
  void stage_whenSecurityDecisionIsDenylisted_expectStableSecurityError() throws Exception {
    AppUpdateService service =
        serviceWithInstalled(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID))
        .thenReturn(List.of(entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED)));
    when(catalogManager.securityDecision(CATALOG_ID, APP_ID))
        .thenReturn(denylistedSecurityDecision());

    service.check(APP_ID, false);
    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> service.stage(APP_ID, false, true, false));

    assertEquals(409, exception.statusCode());
    assertEquals("app_security_denylisted", exception.errorCode());
    verifyNoInstallPlanPreparation();
  }

  @Test
  void check_whenTargetVersionDenylistedByConfiguredCatalog_expectCandidateCarriesDenylist()
      throws Exception {
    AppUpdateService service =
        serviceWithInstalled(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID))
        .thenReturn(List.of(entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED)));
    when(catalogManager.installedSecurityDecision(APP_ID, INSTALLED_VERSION))
        .thenReturn(AppCatalogSecurityDecision.OK);
    when(catalogManager.installedSecurityDecision(APP_ID, UPDATE_VERSION))
        .thenReturn(denylistedSecurityDecision());

    Map<String, Object> summary = service.check(APP_ID, false);

    Map<String, Object> candidate = (Map<String, Object>) summary.get(CANDIDATE);
    Map<String, Object> securityDecision = (Map<String, Object>) candidate.get(SECURITY_DECISION);
    assertEquals("denylisted", securityDecision.get(STATUS));
    assertEquals("denylist", securityDecision.get("action"));
    assertEquals(true, securityDecision.get("blocksUpdate"));
    assertEquals(true, candidate.get(OPERATOR_ACTION_REQUIRED));

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> service.stage(APP_ID, false, true, false));

    assertEquals(409, exception.statusCode());
    assertEquals("app_security_denylisted", exception.errorCode());
    verifyNoInstallPlanPreparation();
  }

  @Test
  void stage_whenCachedCandidateTargetVersionBecomesDenylisted_expectCandidateChangedFailure()
      throws Exception {
    AppUpdateService service =
        serviceWithInstalled(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    AppCatalogEntry entry = entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED);
    AppCatalogInstallPlan plan = plan(entry);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID)).thenReturn(List.of(entry));
    when(catalogManager.installedSecurityDecision(APP_ID, INSTALLED_VERSION))
        .thenReturn(AppCatalogSecurityDecision.OK);
    when(catalogManager.installedSecurityDecision(APP_ID, UPDATE_VERSION))
        .thenReturn(AppCatalogSecurityDecision.OK, denylistedSecurityDecision());
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID)).thenReturn(plan);
    service.check(APP_ID, false);

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> service.stage(APP_ID));

    assertEquals(409, exception.statusCode());
    assertEquals(UPDATE_CANDIDATE_CHANGED, exception.errorCode());
    assertEquals(false, ((Map<?, ?>) service.summary(APP_ID).get(STAGED)).get(AVAILABLE));
    assertFalse(Files.exists(plan.scratchDirectory()));
    verify(appHost, never()).updateFromDirectory(any(), any());
  }

  @Test
  void stage_whenSecurityDecisionWarnsAndBlocksUpdate_expectStableSecurityBlockedError()
      throws Exception {
    AppUpdateService service =
        serviceWithInstalled(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID))
        .thenReturn(List.of(entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED)));
    when(catalogManager.securityDecision(CATALOG_ID, APP_ID))
        .thenReturn(blockUpdateAndWarningSecurityDecision());
    when(catalogManager.installedSecurityDecision(APP_ID, INSTALLED_VERSION))
        .thenReturn(AppCatalogSecurityDecision.OK);
    when(catalogManager.installedSecurityDecision(APP_ID, UPDATE_VERSION))
        .thenReturn(AppCatalogSecurityDecision.OK);

    service.check(APP_ID, false);
    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> service.stage(APP_ID));

    assertEquals(409, exception.statusCode());
    assertEquals("app_security_blocked", exception.errorCode());
    verifyNoInstallPlanPreparation();
  }

  @Test
  void check_whenStagePolicySecurityDecisionWarnsAndBlocksUpdate_expectPolicyBlockedHistory()
      throws Exception {
    AppUpdateService service =
        serviceWithInstalled(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID))
        .thenReturn(List.of(entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED)));
    when(catalogManager.securityDecision(CATALOG_ID, APP_ID))
        .thenReturn(blockUpdateAndWarningSecurityDecision());
    when(catalogManager.installedSecurityDecision(APP_ID, INSTALLED_VERSION))
        .thenReturn(AppCatalogSecurityDecision.OK);
    when(catalogManager.installedSecurityDecision(APP_ID, UPDATE_VERSION))
        .thenReturn(AppCatalogSecurityDecision.OK);
    service.setPolicy(APP_ID, AppUpdatePolicyMode.STAGE);

    Map<String, Object> summary = service.check(APP_ID, false);

    Map<String, Object> historyEntry =
        ((List<Map<String, Object>>) summary.get("history"))
            .stream()
                .filter(entryJson -> "stage".equals(entryJson.get("action")))
                .findFirst()
                .orElseThrow();
    assertEquals("security_policy_blocked", historyEntry.get(ERROR_CODE));
    verifyNoInstallPlanPreparation();
  }

  @Test
  void check_whenCatalogVersionIsEqual_expectNoUpdateCandidate() throws Exception {
    AppUpdateService service =
        serviceWithInstalled(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID))
        .thenReturn(List.of(entry(INSTALLED_VERSION, AppCatalogReviewStatus.REVIEWED)));

    Map<String, Object> candidate =
        (Map<String, Object>) service.check(APP_ID, false).get(CANDIDATE);

    assertEquals("none", candidate.get(STATUS));
    assertEquals("equal", candidate.get(VERSION_COMPARISON));
    assertEquals(false, candidate.get(OPERATOR_ACTION_REQUIRED));
  }

  @Test
  void check_whenEqualBetaBlockedByStableOnlyPolicy_expectNoOperatorActionRequired()
      throws Exception {
    AppUpdateService service =
        serviceWithInstalled(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID))
        .thenReturn(
            List.of(
                entry(
                    INSTALLED_VERSION,
                    AppCatalogReviewStatus.REVIEWED,
                    compatibleApiMetadata(),
                    productionMetadata(AppCatalogChannel.BETA))));
    service.setPolicy(APP_ID, AppUpdatePolicyMode.STAGE);

    Map<String, Object> candidate =
        (Map<String, Object>) service.check(APP_ID, false).get(CANDIDATE);

    assertEquals("none", candidate.get(STATUS));
    assertEquals("equal", candidate.get(VERSION_COMPARISON));
    assertEquals("channel_policy_blocked", candidate.get("policyBlockReason"));
    assertEquals(false, candidate.get(OPERATOR_ACTION_REQUIRED));
  }

  @Test
  void check_whenEqualCatalogVersionRequiresFuturePlatformApi_expectNoUpdateCandidate()
      throws Exception {
    AppUpdateService service =
        serviceWithInstalled(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    AppApiCompatibilityMetadata futureContract = futureApiMetadata();
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID))
        .thenReturn(
            List.of(entry(INSTALLED_VERSION, AppCatalogReviewStatus.REVIEWED, futureContract)));

    Map<String, Object> candidate =
        (Map<String, Object>) service.check(APP_ID, false).get(CANDIDATE);

    assertEquals("none", candidate.get(STATUS));
    assertEquals("equal", candidate.get(VERSION_COMPARISON));
    assertEquals(false, candidate.get(OPERATOR_ACTION_REQUIRED));
  }

  @Test
  void check_whenStrictReviewPolicyAndEqualCatalogVersion_expectNoOperatorActionRequired()
      throws Exception {
    AppUpdateService service =
        serviceWithInstalled(
            INSTALLED_VERSION,
            List.of(QUEUE_READ_PERMISSION),
            new AppReviewPolicy(AppReviewPolicyMode.REQUIRE_TRUSTED_REVIEW),
            TrustedReviewerKeys::empty);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID))
        .thenReturn(List.of(entry(INSTALLED_VERSION, AppCatalogReviewStatus.REVIEWED)));

    Map<String, Object> candidate =
        (Map<String, Object>) service.check(APP_ID, false).get(CANDIDATE);

    assertEquals("none", candidate.get(STATUS));
    assertEquals("equal", candidate.get(VERSION_COMPARISON));
    assertEquals(false, candidate.get(OPERATOR_ACTION_REQUIRED));
  }

  @Test
  void check_whenCatalogVersionIsLower_expectNoOperatorActionRequired() throws Exception {
    AppUpdateService service = serviceWithInstalled(UPDATE_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID))
        .thenReturn(List.of(entry(INSTALLED_VERSION, AppCatalogReviewStatus.REVIEWED)));

    Map<String, Object> candidate =
        (Map<String, Object>) service.check(APP_ID, false).get(CANDIDATE);

    assertEquals("not_newer", candidate.get(STATUS));
    assertEquals("lower", candidate.get(VERSION_COMPARISON));
    assertEquals(false, candidate.get(OPERATOR_ACTION_REQUIRED));
  }

  @Test
  void check_whenLowerBetaBlockedByStableOnlyPolicy_expectNoOperatorActionRequired()
      throws Exception {
    AppUpdateService service = serviceWithInstalled(UPDATE_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID))
        .thenReturn(
            List.of(
                entry(
                    INSTALLED_VERSION,
                    AppCatalogReviewStatus.REVIEWED,
                    compatibleApiMetadata(),
                    productionMetadata(AppCatalogChannel.BETA))));
    service.setPolicy(APP_ID, AppUpdatePolicyMode.STAGE);

    Map<String, Object> candidate =
        (Map<String, Object>) service.check(APP_ID, false).get(CANDIDATE);

    assertEquals("not_newer", candidate.get(STATUS));
    assertEquals("lower", candidate.get(VERSION_COMPARISON));
    assertEquals("channel_policy_blocked", candidate.get("policyBlockReason"));
    assertEquals(false, candidate.get(OPERATOR_ACTION_REQUIRED));
  }

  @Test
  void check_whenLowerCatalogVersionRequiresFuturePlatformApi_expectNotNewerCandidate()
      throws Exception {
    AppUpdateService service = serviceWithInstalled(UPDATE_VERSION, List.of(QUEUE_READ_PERMISSION));
    AppApiCompatibilityMetadata futureContract = futureApiMetadata();
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID))
        .thenReturn(
            List.of(entry(INSTALLED_VERSION, AppCatalogReviewStatus.REVIEWED, futureContract)));

    Map<String, Object> candidate =
        (Map<String, Object>) service.check(APP_ID, false).get(CANDIDATE);

    assertEquals("not_newer", candidate.get(STATUS));
    assertEquals("lower", candidate.get(VERSION_COMPARISON));
    assertEquals(false, candidate.get(OPERATOR_ACTION_REQUIRED));
  }

  @Test
  void check_whenCatalogVersionIsAmbiguous_expectOperatorActionRequired() throws Exception {
    AppUpdateService service =
        serviceWithInstalled(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID))
        .thenReturn(List.of(entry("1.0-beta", AppCatalogReviewStatus.REVIEWED)));

    Map<String, Object> candidate =
        (Map<String, Object>) service.check(APP_ID, false).get(CANDIDATE);

    assertEquals("ambiguous", candidate.get(STATUS));
    assertEquals("ambiguous", candidate.get(VERSION_COMPARISON));
    assertEquals(true, candidate.get(OPERATOR_ACTION_REQUIRED));
  }

  @Test
  void check_whenMultipleCatalogsHaveAvailableUpdates_expectUnresolvedConflictBlocked()
      throws Exception {
    AppUpdateService service =
        serviceWithInstalled(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    enableFederation(service);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog("alpha"), catalog("beta")));
    when(catalogManager.listRoutineApps("alpha"))
        .thenReturn(List.of(entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED)));
    when(catalogManager.listRoutineApps("beta"))
        .thenReturn(List.of(entry("2.0.0", AppCatalogReviewStatus.REVIEWED)));

    Map<String, Object> candidate =
        (Map<String, Object>) service.check(APP_ID, false).get(CANDIDATE);

    assertEquals("blocked", candidate.get(STATUS));
    assertEquals("unresolved_cross_catalog_conflict", candidate.get("policyBlockReason"));
    assertEquals(true, candidate.get(OPERATOR_ACTION_REQUIRED));
  }

  @Test
  void check_whenOneFederatedCatalogChangesDuringEntryRead_expectOtherCatalogRemainsUsable()
      throws Exception {
    AppUpdateService service =
        serviceWithInstalled(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    enableFederation(service);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog("alpha"), catalog("beta")));
    when(catalogManager.listRoutineApps("alpha"))
        .thenThrow(new IOException("catalog trust changed after routine listing"));
    when(catalogManager.listRoutineApps("beta"))
        .thenReturn(List.of(entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED)));

    Map<String, Object> candidate =
        (Map<String, Object>) service.check(APP_ID, false).get(CANDIDATE);

    assertEquals(AVAILABLE, candidate.get(STATUS));
    assertEquals("beta", candidate.get("catalogId"));
    assertEquals(UPDATE_VERSION, candidate.get(TARGET_VERSION));
  }

  @Test
  void check_whenFederationHasNoScopedReviewerPolicy_expectFederationUnavailable()
      throws Exception {
    when(appHost.describe(APP_ID))
        .thenReturn(Optional.of(installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION))));
    AppUpdateService service = new AppUpdateService(appHost, catalogManager);
    when(catalogManager.federationEnabled()).thenReturn(true);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID))
        .thenReturn(List.of(entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED)));

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> service.check(APP_ID, false));

    assertEquals(503, exception.statusCode());
    assertEquals("catalog_federation_unavailable", exception.errorCode());
    assertInstallPlanNotPrepared();
  }

  @Test
  void check_whenOneFederatedCatalogHasNoActivePublisherBinding_expectSelectionBlocked()
      throws Exception {
    AppUpdateService service =
        serviceWithInstalled(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    enableFederation(service);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID))
        .thenReturn(List.of(entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED)));
    FileFederatedCatalogTrustStore trustStore = mock(FileFederatedCatalogTrustStore.class);
    FileCatalogPublisherBindingStore publisherStore = mock(FileCatalogPublisherBindingStore.class);
    FileFederatedCatalogConflictResolutionStore resolutionStore =
        mock(FileFederatedCatalogConflictResolutionStore.class);
    when(trustStore.findByCatalogId(CATALOG_ID))
        .thenReturn(Optional.of(federatedCatalogBinding(CATALOG_ID, 10)));
    service.setFederatedCatalogConflictPolicy(
        new AppUpdateFederationAuthority(trustStore, publisherStore, resolutionStore));

    Map<String, Object> candidate =
        (Map<String, Object>) service.check(APP_ID, false).get(CANDIDATE);

    assertEquals("blocked", candidate.get(STATUS));
    assertEquals("unresolved_cross_catalog_conflict", candidate.get("policyBlockReason"));
    Map<?, ?> review = (Map<?, ?>) candidate.get("review");
    assertEquals(
        "catalog_conflict_policy_could_not_be_authenticated", review.get("catalogConflictReason"));
    assertEquals(true, candidate.get(OPERATOR_ACTION_REQUIRED));
    assertInstallPlanNotPrepared();
  }

  @Test
  void check_whenOneFederatedCatalogHasActivePublisherBinding_expectUpdateAvailable()
      throws Exception {
    AppUpdateService service =
        serviceWithInstalled(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    enableFederation(service);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID))
        .thenReturn(List.of(entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED)));
    FileFederatedCatalogTrustStore trustStore = mock(FileFederatedCatalogTrustStore.class);
    FileCatalogPublisherBindingStore publisherStore = mock(FileCatalogPublisherBindingStore.class);
    FileFederatedCatalogConflictResolutionStore resolutionStore =
        mock(FileFederatedCatalogConflictResolutionStore.class);
    when(trustStore.findByCatalogId(CATALOG_ID))
        .thenReturn(Optional.of(federatedCatalogBinding(CATALOG_ID, 10)));
    CatalogPublisherBinding publisher = federatedPublisherBinding(CATALOG_ID);
    when(publisherStore.findActiveForScope(eq(CATALOG_ID), eq(APP_ID), any(), any()))
        .thenReturn(List.of(publisher));
    when(publisherStore.findLineageForScope(eq(CATALOG_ID), eq(APP_ID), any()))
        .thenReturn(List.of(publisher));
    service.setFederatedCatalogConflictPolicy(
        new AppUpdateFederationAuthority(trustStore, publisherStore, resolutionStore));

    Map<String, Object> candidate =
        (Map<String, Object>) service.check(APP_ID, false).get(CANDIDATE);

    assertEquals(AVAILABLE, candidate.get(STATUS));
    assertEquals(CATALOG_ID, candidate.get("catalogId"));
    assertNull(candidate.get("policyBlockReason"));
    assertInstallPlanNotPrepared();
  }

  @Test
  void stage_whenNewCatalogIntroducesHardConflict_expectCachedCandidateRejected() throws Exception {
    AppUpdateService service =
        serviceWithInstalled(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    enableFederation(service);
    when(catalogManager.listCatalogs())
        .thenReturn(
            List.of(catalog("alpha")),
            List.of(catalog("alpha"), catalog("beta")),
            List.of(catalog("alpha"), catalog("beta")));
    AppCatalogEntry original = entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED);
    when(catalogManager.listRoutineApps("alpha")).thenReturn(List.of(original));
    when(catalogManager.listRoutineApps("beta"))
        .thenReturn(List.of(withBundleDigest(original, "1".repeat(64))));
    Map<String, Object> checked = (Map<String, Object>) service.check(APP_ID, false).get(CANDIDATE);

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> service.stage(APP_ID, false, false, false));

    assertEquals(AVAILABLE, checked.get(STATUS));
    assertEquals("update_not_available", exception.errorCode());
    assertInstallPlanNotPrepared();
  }

  @Test
  void requireDirectCatalogMutationAllowed_whenPayloadConflictIsUnresolved_expectRejected()
      throws Exception {
    AppUpdateService service = new AppUpdateService(appHost, catalogManager);
    enableFederation(service);
    AppCatalogEntry selected = entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED);
    AppCatalogEntry conflicting = withBundleDigest(selected, "1".repeat(64));
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog("alpha"), catalog("beta")));
    when(catalogManager.listRoutineApps("alpha")).thenReturn(List.of(selected));
    when(catalogManager.listRoutineApps("beta")).thenReturn(List.of(conflicting));
    FileFederatedCatalogTrustStore trustStore = mock(FileFederatedCatalogTrustStore.class);
    FileCatalogPublisherBindingStore publisherStore = mock(FileCatalogPublisherBindingStore.class);
    FileFederatedCatalogConflictResolutionStore resolutionStore =
        mock(FileFederatedCatalogConflictResolutionStore.class);
    when(trustStore.findByCatalogId("alpha"))
        .thenReturn(Optional.of(federatedCatalogBinding("alpha", 20)));
    when(trustStore.findByCatalogId("beta"))
        .thenReturn(Optional.of(federatedCatalogBinding("beta", 10)));
    when(publisherStore.findActiveForScope(any(), any(), any(), any()))
        .thenAnswer(invocation -> List.of(federatedPublisherBinding(invocation.getArgument(0))));
    when(resolutionStore.lookup(any()))
        .thenReturn(
            new FileFederatedCatalogConflictResolutionStore.Lookup(
                FileFederatedCatalogConflictResolutionStore.LookupStatus.MISSING,
                Optional.empty()));
    service.setFederatedCatalogConflictPolicy(
        new AppUpdateFederationAuthority(trustStore, publisherStore, resolutionStore));
    try (AppCatalogInstallPlan plan = plan("alpha", selected)) {
      PlatformApiException exception =
          assertThrows(
              PlatformApiException.class,
              () -> service.requireDirectCatalogMutationAllowed(plan, null));

      assertEquals(409, exception.statusCode());
      assertEquals("catalog_conflict_unresolved", exception.errorCode());
    }
  }

  @Test
  void requireDirectCatalogMutationAllowed_whenPinnedOriginHasExactDuplicate_expectPinPreserved()
      throws Exception {
    AppUpdateService service = new AppUpdateService(appHost, catalogManager);
    enableFederation(service);
    when(appHost.catalogOrigin(APP_ID)).thenReturn(Optional.of(installedOrigin("alpha")));
    AppCatalogEntry duplicate = entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog("alpha"), catalog("beta")));
    when(catalogManager.listRoutineApps("alpha")).thenReturn(List.of(duplicate));
    when(catalogManager.listRoutineApps("beta")).thenReturn(List.of(duplicate));
    FileFederatedCatalogTrustStore trustStore = mock(FileFederatedCatalogTrustStore.class);
    FileCatalogPublisherBindingStore publisherStore = mock(FileCatalogPublisherBindingStore.class);
    FileFederatedCatalogConflictResolutionStore resolutionStore =
        mock(FileFederatedCatalogConflictResolutionStore.class);
    when(trustStore.findByCatalogId("alpha"))
        .thenReturn(Optional.of(federatedCatalogBinding("alpha", 10)));
    when(trustStore.findByCatalogId("beta"))
        .thenReturn(Optional.of(federatedCatalogBinding("beta", 10)));
    when(publisherStore.findActiveForScope(any(), any(), any(), any()))
        .thenAnswer(invocation -> List.of(federatedPublisherBinding(invocation.getArgument(0))));
    when(resolutionStore.lookup(any()))
        .thenReturn(
            new FileFederatedCatalogConflictResolutionStore.Lookup(
                FileFederatedCatalogConflictResolutionStore.LookupStatus.MISSING,
                Optional.empty()));
    service.setFederatedCatalogConflictPolicy(
        new AppUpdateFederationAuthority(trustStore, publisherStore, resolutionStore));

    InstalledAppSnapshot installed = installed(INSTALLED_VERSION, List.of());
    try (AppCatalogInstallPlan plan = federatedPlan("alpha", duplicate)) {
      assertDoesNotThrow(() -> service.requireDirectCatalogMutationAllowed(plan, installed));
    }
  }

  @Test
  void requireDirectCatalogMutationAllowed_whenExactDuplicateAllowed_expectSelectedCatalogAllowed()
      throws Exception {
    AppUpdateService service = new AppUpdateService(appHost, catalogManager);
    enableFederation(service);
    AppCatalogEntry duplicate = entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog("alpha"), catalog("beta")));
    when(catalogManager.listRoutineApps("alpha")).thenReturn(List.of(duplicate));
    when(catalogManager.listRoutineApps("beta")).thenReturn(List.of(duplicate));
    FileFederatedCatalogTrustStore trustStore = mock(FileFederatedCatalogTrustStore.class);
    FileCatalogPublisherBindingStore publisherStore = mock(FileCatalogPublisherBindingStore.class);
    FileFederatedCatalogConflictResolutionStore resolutionStore =
        mock(FileFederatedCatalogConflictResolutionStore.class);
    when(trustStore.findByCatalogId("alpha"))
        .thenReturn(Optional.of(federatedCatalogBinding("alpha", 20)));
    when(trustStore.findByCatalogId("beta"))
        .thenReturn(Optional.of(federatedCatalogBinding("beta", 10)));
    when(publisherStore.findActiveForScope(any(), any(), any(), any()))
        .thenAnswer(invocation -> List.of(federatedPublisherBinding(invocation.getArgument(0))));
    when(resolutionStore.lookup(any()))
        .thenAnswer(invocation -> applicableExactDuplicateLookup(invocation.getArgument(0)));
    service.setFederatedCatalogConflictPolicy(
        new AppUpdateFederationAuthority(trustStore, publisherStore, resolutionStore));

    try (AppCatalogInstallPlan plan = federatedPlan("beta", duplicate)) {
      assertDoesNotThrow(() -> service.requireDirectCatalogMutationAllowed(plan, null));
    }
  }

  @Test
  void check_whenExactDuplicateHasDistinctReviewerScopeRecords_expectUniqueLocalPrioritySelected()
      throws Exception {
    AppUpdateService service =
        serviceWithInstalled(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    enableFederation(service);
    AppCatalogEntry duplicate = entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog("alpha"), catalog("beta")));
    when(catalogManager.listRoutineApps("alpha")).thenReturn(List.of(duplicate));
    when(catalogManager.listRoutineApps("beta")).thenReturn(List.of(duplicate));
    FileFederatedCatalogTrustStore trustStore = mock(FileFederatedCatalogTrustStore.class);
    FileCatalogPublisherBindingStore publisherStore = mock(FileCatalogPublisherBindingStore.class);
    FileFederatedCatalogConflictResolutionStore resolutionStore =
        mock(FileFederatedCatalogConflictResolutionStore.class);
    when(trustStore.findByCatalogId("alpha"))
        .thenReturn(Optional.of(federatedCatalogBinding("alpha", 10)));
    when(trustStore.findByCatalogId("beta"))
        .thenReturn(Optional.of(federatedCatalogBinding("beta", 20)));
    when(publisherStore.findActiveForScope(any(), any(), any(), any()))
        .thenAnswer(invocation -> List.of(federatedPublisherBinding(invocation.getArgument(0))));
    when(resolutionStore.lookup(any()))
        .thenAnswer(invocation -> applicableExactDuplicateLookup(invocation.getArgument(0)));
    service.setFederatedCatalogConflictPolicy(
        new AppUpdateFederationAuthority(trustStore, publisherStore, resolutionStore));

    Map<String, Object> candidate =
        (Map<String, Object>) service.check(APP_ID, false).get(CANDIDATE);

    assertEquals(AVAILABLE, candidate.get(STATUS));
    assertEquals("beta", candidate.get("catalogId"));
    Map<?, ?> reviewTrust = (Map<?, ?>) candidate.get("reviewTrust");
    assertEquals("1".repeat(64), reviewTrust.get("reviewerScopeDigestSha256"));
    assertEquals(DIGEST, reviewTrust.get("reviewerPolicySemanticDigestSha256"));
  }

  @Test
  void federatedConflict_whenPublishersShareAuthenticatedRotationLineage_expectNoNamespaceConflict()
      throws Exception {
    AppUpdateService service = new AppUpdateService(appHost, catalogManager);
    enableFederation(service);
    AppCatalogEntry duplicate = entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog("alpha"), catalog("beta")));
    when(catalogManager.listRoutineApps("alpha")).thenReturn(List.of(duplicate));
    when(catalogManager.listRoutineApps("beta")).thenReturn(List.of(duplicate));
    FileFederatedCatalogTrustStore trustStore = mock(FileFederatedCatalogTrustStore.class);
    FileCatalogPublisherBindingStore publisherStore = mock(FileCatalogPublisherBindingStore.class);
    FileFederatedCatalogConflictResolutionStore resolutionStore =
        mock(FileFederatedCatalogConflictResolutionStore.class);
    when(trustStore.findByCatalogId("alpha"))
        .thenReturn(Optional.of(federatedCatalogBinding("alpha", 20)));
    when(trustStore.findByCatalogId("beta"))
        .thenReturn(Optional.of(federatedCatalogBinding("beta", 10)));
    CatalogPublisherBinding alphaCurrent =
        federatedPublisherBinding(
            "alpha",
            "publisher-a",
            "a".repeat(64),
            CatalogPublisherBinding.Status.ACTIVE,
            "x",
            "publisher-b");
    CatalogPublisherBinding alphaSuccessor =
        federatedPublisherBinding(
            "alpha",
            "publisher-b",
            "b".repeat(64),
            CatalogPublisherBinding.Status.SUSPENDED,
            "publisher-a",
            null);
    CatalogPublisherBinding betaCurrent =
        federatedPublisherBinding(
            "beta",
            "publisher-b",
            "b".repeat(64),
            CatalogPublisherBinding.Status.ACTIVE,
            "publisher-a",
            null);
    CatalogPublisherBinding betaPredecessor =
        federatedPublisherBinding(
            "beta",
            "publisher-a",
            "a".repeat(64),
            CatalogPublisherBinding.Status.SUSPENDED,
            "x",
            "publisher-b");
    when(publisherStore.findActiveForScope(eq("alpha"), any(), any(), any()))
        .thenReturn(List.of(alphaCurrent));
    when(publisherStore.findActiveForScope(eq("beta"), any(), any(), any()))
        .thenReturn(List.of(betaCurrent));
    when(publisherStore.findLineageForScope(eq("alpha"), any(), any()))
        .thenReturn(List.of(alphaCurrent, alphaSuccessor));
    when(publisherStore.findLineageForScope(eq("beta"), any(), any()))
        .thenReturn(List.of(betaCurrent, betaPredecessor));
    when(resolutionStore.lookup(any()))
        .thenReturn(
            new FileFederatedCatalogConflictResolutionStore.Lookup(
                FileFederatedCatalogConflictResolutionStore.LookupStatus.MISSING,
                Optional.empty()));
    service.setFederatedCatalogConflictPolicy(
        new AppUpdateFederationAuthority(trustStore, publisherStore, resolutionStore));

    Map<String, Object> summary = service.federatedConflict(APP_ID);

    assertTrue(((List<String>) summary.get("types")).contains("exact_duplicate"));
    assertFalse(((List<String>) summary.get("types")).contains("publisher_namespace_conflict"));
    assertEquals(false, summary.get("hard"));
  }

  @Test
  void stage_whenPinnedOriginHasHigherPriorityExactDuplicate_expectPinnedCandidateStaged()
      throws Exception {
    AppUpdateService service =
        serviceWithInstalled(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    enableFederation(service);
    when(appHost.catalogOrigin(APP_ID)).thenReturn(Optional.of(installedOrigin("alpha")));
    AppCatalogEntry duplicate = entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog("alpha"), catalog("beta")));
    when(catalogManager.listRoutineApps("alpha")).thenReturn(List.of(duplicate));
    when(catalogManager.listRoutineApps("beta")).thenReturn(List.of(duplicate));
    when(catalogManager.prepareInstallPlan("alpha", APP_ID))
        .thenReturn(federatedPlan("alpha", duplicate));
    FileFederatedCatalogTrustStore trustStore = mock(FileFederatedCatalogTrustStore.class);
    FileCatalogPublisherBindingStore publisherStore = mock(FileCatalogPublisherBindingStore.class);
    FileFederatedCatalogConflictResolutionStore resolutionStore =
        mock(FileFederatedCatalogConflictResolutionStore.class);
    when(trustStore.findByCatalogId("alpha"))
        .thenReturn(Optional.of(federatedCatalogBinding("alpha", 10)));
    when(trustStore.findByCatalogId("beta"))
        .thenReturn(Optional.of(federatedCatalogBinding("beta", 20)));
    when(publisherStore.findActiveForScope(any(), any(), any(), any()))
        .thenAnswer(invocation -> List.of(federatedPublisherBinding(invocation.getArgument(0))));
    when(resolutionStore.lookup(any()))
        .thenReturn(
            new FileFederatedCatalogConflictResolutionStore.Lookup(
                FileFederatedCatalogConflictResolutionStore.LookupStatus.MISSING,
                Optional.empty()));
    service.setFederatedCatalogConflictPolicy(
        new AppUpdateFederationAuthority(trustStore, publisherStore, resolutionStore));
    service.check(APP_ID, false);

    Map<String, Object> summary = service.stage(APP_ID);

    assertEquals(true, ((Map<?, ?>) summary.get(STAGED)).get(AVAILABLE));
    assertEquals("alpha", ((Map<?, ?>) summary.get(STAGED)).get("catalogId"));
  }

  @Test
  void federatedConflict_whenPayloadsDisagree_expectExactOperatorSubjectSet() throws Exception {
    AppUpdateService service = new AppUpdateService(appHost, catalogManager);
    enableFederation(service);
    AppCatalogEntry selected = entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog("alpha"), catalog("beta")));
    when(catalogManager.listRoutineApps("alpha")).thenReturn(List.of(selected));
    when(catalogManager.listRoutineApps("beta"))
        .thenReturn(List.of(withBundleDigest(selected, "1".repeat(64))));
    FileFederatedCatalogTrustStore trustStore = mock(FileFederatedCatalogTrustStore.class);
    FileCatalogPublisherBindingStore publisherStore = mock(FileCatalogPublisherBindingStore.class);
    FileFederatedCatalogConflictResolutionStore resolutionStore =
        mock(FileFederatedCatalogConflictResolutionStore.class);
    when(trustStore.findByCatalogId("alpha"))
        .thenReturn(Optional.of(federatedCatalogBinding("alpha", 20)));
    when(trustStore.findByCatalogId("beta"))
        .thenReturn(Optional.of(federatedCatalogBinding("beta", 10)));
    when(publisherStore.findActiveForScope(any(), any(), any(), any()))
        .thenAnswer(invocation -> List.of(federatedPublisherBinding(invocation.getArgument(0))));
    when(resolutionStore.lookup(any()))
        .thenReturn(
            new FileFederatedCatalogConflictResolutionStore.Lookup(
                FileFederatedCatalogConflictResolutionStore.LookupStatus.MISSING,
                Optional.empty()));
    service.setFederatedCatalogConflictPolicy(
        new AppUpdateFederationAuthority(trustStore, publisherStore, resolutionStore));

    Map<String, Object> summary = service.federatedConflict(APP_ID);

    assertTrue(summary.get("conflictId").toString().startsWith("catalog-conflict-"));
    assertEquals(64, summary.get("subjectSetDigestSha256").toString().length());
    assertEquals(true, summary.get("hard"));
    assertTrue(((List<String>) summary.get("types")).contains("same_version_payload_conflict"));
    assertEquals(2, ((List<Map<String, Object>>) summary.get("subjects")).size());
    assertEquals("missing", summary.get("resolutionStatus"));
    assertNull(summary.get("resolution"));
  }

  @Test
  void federatedConflict_whenCatalogSecurityPoliciesDisagree_expectLocalDecisionsRemainDistinct()
      throws Exception {
    AppUpdateService service = new AppUpdateService(appHost, catalogManager);
    enableFederation(service);
    AppCatalogEntry selected = entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog("alpha"), catalog("beta")));
    when(catalogManager.listRoutineApps("alpha")).thenReturn(List.of(selected));
    when(catalogManager.listRoutineApps("beta")).thenReturn(List.of(selected));
    when(catalogManager.securityDecision("alpha", APP_ID))
        .thenReturn(AppCatalogSecurityDecision.OK);
    when(catalogManager.securityDecision("beta", APP_ID)).thenReturn(warningSecurityDecision());
    when(catalogManager.installedSecurityDecision(APP_ID, UPDATE_VERSION))
        .thenReturn(warningSecurityDecision());
    FileFederatedCatalogTrustStore trustStore = mock(FileFederatedCatalogTrustStore.class);
    FileCatalogPublisherBindingStore publisherStore = mock(FileCatalogPublisherBindingStore.class);
    FileFederatedCatalogConflictResolutionStore resolutionStore =
        mock(FileFederatedCatalogConflictResolutionStore.class);
    when(trustStore.findByCatalogId("alpha"))
        .thenReturn(Optional.of(federatedCatalogBinding("alpha", 20)));
    when(trustStore.findByCatalogId("beta"))
        .thenReturn(Optional.of(federatedCatalogBinding("beta", 10)));
    when(publisherStore.findActiveForScope(any(), any(), any(), any()))
        .thenAnswer(invocation -> List.of(federatedPublisherBinding(invocation.getArgument(0))));
    when(resolutionStore.lookup(any()))
        .thenReturn(
            new FileFederatedCatalogConflictResolutionStore.Lookup(
                FileFederatedCatalogConflictResolutionStore.LookupStatus.MISSING,
                Optional.empty()));
    service.setFederatedCatalogConflictPolicy(
        new AppUpdateFederationAuthority(trustStore, publisherStore, resolutionStore));

    Map<String, Object> summary = service.federatedConflict(APP_ID);
    List<Map<String, Object>> subjects = (List<Map<String, Object>>) summary.get("subjects");

    assertTrue(((List<String>) summary.get("types")).contains("security_policy_disagreement"));
    assertEquals(true, summary.get("hard"));
    assertNotEquals(
        subjects.get(0).get("securityDecisionDigestSha256"),
        subjects.get(1).get("securityDecisionDigestSha256"));
  }

  @Test
  void resolveFederatedConflict_whenExactSubjectsMatch_expectDigestBoundDecisionStored()
      throws Exception {
    AppUpdateService service = new AppUpdateService(appHost, catalogManager);
    enableFederation(service);
    AppCatalogEntry selected = entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog("alpha"), catalog("beta")));
    when(catalogManager.listRoutineApps("alpha")).thenReturn(List.of(selected));
    when(catalogManager.listRoutineApps("beta"))
        .thenReturn(List.of(withBundleDigest(selected, "1".repeat(64))));
    FileFederatedCatalogTrustStore trustStore = mock(FileFederatedCatalogTrustStore.class);
    FileCatalogPublisherBindingStore publisherStore = mock(FileCatalogPublisherBindingStore.class);
    FileFederatedCatalogConflictResolutionStore resolutionStore =
        mock(FileFederatedCatalogConflictResolutionStore.class);
    when(trustStore.findByCatalogId("alpha"))
        .thenReturn(Optional.of(federatedCatalogBinding("alpha", 20)));
    when(trustStore.findByCatalogId("beta"))
        .thenReturn(Optional.of(federatedCatalogBinding("beta", 10)));
    when(publisherStore.findActiveForScope(any(), any(), any(), any()))
        .thenAnswer(invocation -> List.of(federatedPublisherBinding(invocation.getArgument(0))));
    when(resolutionStore.lookup(any()))
        .thenReturn(
            new FileFederatedCatalogConflictResolutionStore.Lookup(
                FileFederatedCatalogConflictResolutionStore.LookupStatus.MISSING,
                Optional.empty()));
    service.setFederatedCatalogConflictPolicy(
        new AppUpdateFederationAuthority(trustStore, publisherStore, resolutionStore));
    Map<String, Object> current = service.federatedConflict(APP_ID);

    String staleSubjectDigest = "0".repeat(64);
    String sourceSwitchResolution =
        FederatedCatalogConflictEngine.ResolutionKind.EXPLICIT_SOURCE_SWITCH_REQUIRED.name();
    PlatformApiException stale =
        assertThrows(
            PlatformApiException.class,
            () ->
                service.resolveFederatedConflict(
                    APP_ID,
                    "catalog-conflict-stale",
                    staleSubjectDigest,
                    sourceSwitchResolution,
                    null,
                    null,
                    "stale decision"));
    Map<String, Object> resolved =
        service.resolveFederatedConflict(
            APP_ID,
            current.get("conflictId").toString(),
            current.get("subjectSetDigestSha256").toString(),
            sourceSwitchResolution,
            null,
            null,
            "operator requires an exact source-switch preview");

    assertEquals("catalog_conflict_changed", stale.errorCode());
    assertEquals("applicable", resolved.get("resolutionStatus"));
    assertEquals(
        "explicit_source_switch_required",
        ((Map<String, Object>) resolved.get("resolution")).get("kind"));
    verify(resolutionStore).put(any(), any());
  }

  @Test
  void requireDirectCatalogMutationAllowed_whenExplicitResolutionAndConsent_expectExactPlanAllowed()
      throws Exception {
    AppUpdateService service = new AppUpdateService(appHost, catalogManager);
    enableFederation(service);
    AppCatalogEntry selected = entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED);
    AppCatalogEntry conflicting = withBundleDigest(selected, "1".repeat(64));
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog("alpha"), catalog("beta")));
    when(catalogManager.listRoutineApps("alpha")).thenReturn(List.of(selected));
    when(catalogManager.listRoutineApps("beta")).thenReturn(List.of(conflicting));
    FileFederatedCatalogTrustStore trustStore = mock(FileFederatedCatalogTrustStore.class);
    FileCatalogPublisherBindingStore publisherStore = mock(FileCatalogPublisherBindingStore.class);
    FileFederatedCatalogConflictResolutionStore resolutionStore =
        mock(FileFederatedCatalogConflictResolutionStore.class);
    when(trustStore.findByCatalogId("alpha"))
        .thenReturn(Optional.of(federatedCatalogBinding("alpha", 20)));
    when(trustStore.findByCatalogId("beta"))
        .thenReturn(Optional.of(federatedCatalogBinding("beta", 10)));
    when(publisherStore.findActiveForScope(any(), any(), any(), any()))
        .thenAnswer(invocation -> List.of(federatedPublisherBinding(invocation.getArgument(0))));
    when(resolutionStore.lookup(any()))
        .thenAnswer(
            invocation -> {
              FederatedCatalogConflictEngine.ConflictSet conflict = invocation.getArgument(0);
              FederatedCatalogConflictEngine.Resolution resolution =
                  new FederatedCatalogConflictEngine.Resolution(
                      conflict.conflictId(),
                      conflict.subjectSetDigest(),
                      FederatedCatalogConflictEngine.ResolutionKind.EXPLICIT_SOURCE_SWITCH_REQUIRED,
                      Optional.empty(),
                      Optional.empty(),
                      Instant.parse("2026-05-03T00:00:00Z"),
                      "operator requires exact source-switch consent",
                      null);
              return new FileFederatedCatalogConflictResolutionStore.Lookup(
                  FileFederatedCatalogConflictResolutionStore.LookupStatus.APPLICABLE,
                  Optional.of(resolution));
            });
    service.setFederatedCatalogConflictPolicy(
        new AppUpdateFederationAuthority(trustStore, publisherStore, resolutionStore));
    AppCatalogInstallPlan plan = plan("alpha", selected);

    PlatformApiException automatic =
        assertThrows(
            PlatformApiException.class,
            () -> service.requireDirectCatalogMutationAllowed(plan, null));
    service.requireDirectCatalogMutationAllowed(plan, null, true);

    assertEquals("catalog_conflict_unresolved", automatic.errorCode());
  }

  @Test
  void stage_whenExplicitTargetHasNoInstalledOrigin_expectHardConflictCannotBeBypassed()
      throws Exception {
    AppUpdateService service =
        serviceWithInstalled(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    enableFederation(service);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog("alpha"), catalog("beta")));
    when(catalogManager.listRoutineApps("alpha"))
        .thenReturn(List.of(entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED)));
    when(catalogManager.listRoutineApps("beta"))
        .thenReturn(List.of(entry("2.0.0", AppCatalogReviewStatus.REVIEWED)));

    Map<String, Object> candidate =
        (Map<String, Object>) service.check(APP_ID, false).get(CANDIDATE);
    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class,
            () -> service.stage(APP_ID, false, false, false, "arbitrary", "beta"));

    assertEquals("blocked", candidate.get(STATUS));
    assertEquals("unresolved_cross_catalog_conflict", candidate.get("policyBlockReason"));
    assertEquals("catalog_source_switch_consent_required", exception.errorCode());
    assertInstallPlanNotPrepared();
  }

  @Test
  void check_whenExactConflictResolutionPinsCatalog_expectSelectedBoundSubject() throws Exception {
    AppUpdateService service =
        serviceWithInstalled(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    enableFederation(service);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog("alpha"), catalog("beta")));
    when(catalogManager.listRoutineApps("alpha"))
        .thenReturn(List.of(entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED)));
    when(catalogManager.listRoutineApps("beta"))
        .thenReturn(List.of(entry("2.0.0", AppCatalogReviewStatus.REVIEWED)));
    FileFederatedCatalogTrustStore trustStore = mock(FileFederatedCatalogTrustStore.class);
    FileCatalogPublisherBindingStore publisherStore = mock(FileCatalogPublisherBindingStore.class);
    FileFederatedCatalogConflictResolutionStore resolutionStore =
        mock(FileFederatedCatalogConflictResolutionStore.class);
    when(trustStore.findByCatalogId("alpha"))
        .thenReturn(Optional.of(federatedCatalogBinding("alpha", 10)));
    when(trustStore.findByCatalogId("beta"))
        .thenReturn(Optional.of(federatedCatalogBinding("beta", 20)));
    when(publisherStore.findActiveForScope(any(), any(), any(), any()))
        .thenAnswer(invocation -> List.of(federatedPublisherBinding(invocation.getArgument(0))));
    when(resolutionStore.lookup(any()))
        .thenAnswer(
            invocation -> {
              FederatedCatalogConflictEngine.ConflictSet conflict = invocation.getArgument(0);
              FederatedCatalogConflictEngine.Resolution resolution =
                  new FederatedCatalogConflictEngine.Resolution(
                      conflict.conflictId(),
                      conflict.subjectSetDigest(),
                      FederatedCatalogConflictEngine.ResolutionKind.PIN_CATALOG,
                      Optional.of("beta"),
                      Optional.empty(),
                      Instant.parse("2026-05-03T00:00:00Z"),
                      "operator selected beta",
                      null);
              return new FileFederatedCatalogConflictResolutionStore.Lookup(
                  FileFederatedCatalogConflictResolutionStore.LookupStatus.APPLICABLE,
                  Optional.of(resolution));
            });
    service.setFederatedCatalogConflictPolicy(
        new AppUpdateFederationAuthority(trustStore, publisherStore, resolutionStore));

    Map<String, Object> candidate =
        (Map<String, Object>) service.check(APP_ID, false).get(CANDIDATE);

    assertEquals(AVAILABLE, candidate.get(STATUS));
    assertEquals("beta", candidate.get("catalogId"));
    assertEquals("2.0.0", candidate.get(TARGET_VERSION));
  }

  @Test
  void stage_whenExactResolutionRequiresSourceSwitch_expectConsentSelectsExactTarget()
      throws Exception {
    AppUpdateService service =
        serviceWithInstalled(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    enableFederation(service);
    InstalledAppOrigin current = installedOrigin("alpha");
    when(appHost.catalogOrigin(APP_ID)).thenReturn(Optional.of(current));
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog("alpha"), catalog("beta")));
    AppCatalogEntry alpha = entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED);
    AppCatalogEntry beta = entry("2.0.0", AppCatalogReviewStatus.REVIEWED);
    when(catalogManager.listRoutineApps("alpha")).thenReturn(List.of(alpha));
    when(catalogManager.listRoutineApps("beta")).thenReturn(List.of(beta));
    FileFederatedCatalogTrustStore trustStore = mock(FileFederatedCatalogTrustStore.class);
    FileCatalogPublisherBindingStore publisherStore = mock(FileCatalogPublisherBindingStore.class);
    FileFederatedCatalogConflictResolutionStore resolutionStore =
        mock(FileFederatedCatalogConflictResolutionStore.class);
    when(trustStore.findByCatalogId("alpha"))
        .thenReturn(Optional.of(federatedCatalogBinding("alpha", 20)));
    when(trustStore.findByCatalogId("beta"))
        .thenReturn(Optional.of(federatedCatalogBinding("beta", 10)));
    when(publisherStore.findActiveForScope(any(), any(), any(), any()))
        .thenAnswer(invocation -> List.of(federatedPublisherBinding(invocation.getArgument(0))));
    when(resolutionStore.lookup(any()))
        .thenAnswer(
            invocation -> {
              FederatedCatalogConflictEngine.ConflictSet conflict = invocation.getArgument(0);
              FederatedCatalogConflictEngine.Resolution resolution =
                  new FederatedCatalogConflictEngine.Resolution(
                      conflict.conflictId(),
                      conflict.subjectSetDigest(),
                      FederatedCatalogConflictEngine.ResolutionKind.EXPLICIT_SOURCE_SWITCH_REQUIRED,
                      Optional.empty(),
                      Optional.empty(),
                      Instant.parse("2026-05-03T00:00:00Z"),
                      "operator requires an explicit source switch",
                      null);
              return new FileFederatedCatalogConflictResolutionStore.Lookup(
                  FileFederatedCatalogConflictResolutionStore.LookupStatus.APPLICABLE,
                  Optional.of(resolution));
            });
    service.setFederatedCatalogConflictPolicy(
        new AppUpdateFederationAuthority(trustStore, publisherStore, resolutionStore));
    AppCatalogInstallPlan target =
        plan(
            "beta",
            beta,
            new AppCatalogBundleVerificationResult(
                "publisher-key", DIGEST, "publisher-binding-beta", DIGEST, true, DIGEST),
            new AppCatalogOriginContext(
                "beta",
                "catalog-key",
                DIGEST,
                "3".repeat(64),
                "binding-beta",
                DIGEST,
                DIGEST,
                DIGEST,
                true));
    when(catalogManager.prepareInstallPlan("beta", APP_ID)).thenReturn(target);
    Map<String, Object> automatic =
        (Map<String, Object>) service.check(APP_ID, false).get(CANDIDATE);
    String consent = CatalogSourceSwitchConsent.evaluate(target, current).consentDigestSha256();

    Map<String, Object> summary = service.stage(APP_ID, false, false, false, consent, "beta");

    assertEquals("blocked", automatic.get(STATUS));
    assertEquals(true, ((Map<?, ?>) summary.get(STAGED)).get(AVAILABLE));
    assertEquals("beta", ((Map<?, ?>) summary.get(STAGED)).get("catalogId"));
  }

  @Test
  void check_whenEqualVersionCatalogCollidesWithNewerCandidate_expectHardConflictBlocked()
      throws Exception {
    AppUpdateService service =
        serviceWithInstalled(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    enableFederation(service);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog("alpha"), catalog("beta")));
    when(catalogManager.listRoutineApps("alpha"))
        .thenReturn(List.of(entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED)));
    when(catalogManager.listRoutineApps("beta"))
        .thenReturn(List.of(entry(INSTALLED_VERSION, AppCatalogReviewStatus.REVIEWED)));
    FileFederatedCatalogTrustStore trustStore = mock(FileFederatedCatalogTrustStore.class);
    FileCatalogPublisherBindingStore publisherStore = mock(FileCatalogPublisherBindingStore.class);
    FileFederatedCatalogConflictResolutionStore resolutionStore =
        mock(FileFederatedCatalogConflictResolutionStore.class);
    when(trustStore.findByCatalogId("alpha"))
        .thenReturn(Optional.of(federatedCatalogBinding("alpha", 20)));
    when(trustStore.findByCatalogId("beta"))
        .thenReturn(Optional.of(federatedCatalogBinding("beta", 10)));
    when(publisherStore.findActiveForScope(any(), any(), any(), any()))
        .thenAnswer(
            invocation -> {
              String catalogId = invocation.getArgument(0);
              String fingerprint = "alpha".equals(catalogId) ? DIGEST : "1".repeat(64);
              return List.of(federatedPublisherBinding(catalogId, fingerprint));
            });
    when(resolutionStore.lookup(any()))
        .thenReturn(
            new FileFederatedCatalogConflictResolutionStore.Lookup(
                FileFederatedCatalogConflictResolutionStore.LookupStatus.MISSING,
                Optional.empty()));
    service.setFederatedCatalogConflictPolicy(
        new AppUpdateFederationAuthority(trustStore, publisherStore, resolutionStore));

    Map<String, Object> candidate =
        (Map<String, Object>) service.check(APP_ID, false).get(CANDIDATE);

    assertEquals("blocked", candidate.get(STATUS));
    assertEquals("unresolved_cross_catalog_conflict", candidate.get("policyBlockReason"));
    assertEquals(true, candidate.get(OPERATOR_ACTION_REQUIRED));
  }

  @Test
  void check_whenInstalledOriginIsPinnedButHardConflictExists_expectAutomationBlocked()
      throws Exception {
    AppUpdateService service =
        serviceWithInstalled(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    enableFederation(service);
    when(appHost.catalogOrigin(APP_ID)).thenReturn(Optional.of(installedOrigin("alpha")));
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog("alpha"), catalog("beta")));
    AppCatalogEntry pinned = entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED);
    AppCatalogEntry conflicting = withBundleDigest(pinned, "1".repeat(64));
    when(catalogManager.listRoutineApps("alpha")).thenReturn(List.of(pinned));
    when(catalogManager.listRoutineApps("beta")).thenReturn(List.of(conflicting));
    FileFederatedCatalogTrustStore trustStore = mock(FileFederatedCatalogTrustStore.class);
    FileCatalogPublisherBindingStore publisherStore = mock(FileCatalogPublisherBindingStore.class);
    FileFederatedCatalogConflictResolutionStore resolutionStore =
        mock(FileFederatedCatalogConflictResolutionStore.class);
    when(trustStore.findByCatalogId("alpha"))
        .thenReturn(Optional.of(federatedCatalogBinding("alpha", 20)));
    when(trustStore.findByCatalogId("beta"))
        .thenReturn(Optional.of(federatedCatalogBinding("beta", 10)));
    when(publisherStore.findActiveForScope(any(), any(), any(), any()))
        .thenAnswer(invocation -> List.of(federatedPublisherBinding(invocation.getArgument(0))));
    when(resolutionStore.lookup(any()))
        .thenReturn(
            new FileFederatedCatalogConflictResolutionStore.Lookup(
                FileFederatedCatalogConflictResolutionStore.LookupStatus.MISSING,
                Optional.empty()));
    service.setFederatedCatalogConflictPolicy(
        new AppUpdateFederationAuthority(trustStore, publisherStore, resolutionStore));

    Map<String, Object> candidate =
        (Map<String, Object>) service.check(APP_ID, false).get(CANDIDATE);

    assertEquals("blocked", candidate.get(STATUS));
    assertEquals("alpha", candidate.get("catalogId"));
    assertEquals("unresolved_cross_catalog_conflict", candidate.get("policyBlockReason"));
    assertEquals(true, candidate.get(OPERATOR_ACTION_REQUIRED));
  }

  @Test
  void check_whenLegacyMode_expectCandidateIsNotFederationPinned() throws Exception {
    AppUpdateService service =
        serviceWithInstalled(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog("beta")));
    when(catalogManager.listRoutineApps("beta"))
        .thenReturn(List.of(entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED)));

    Map<String, Object> candidate =
        (Map<String, Object>) service.check(APP_ID, false).get(CANDIDATE);

    assertEquals(AVAILABLE, candidate.get(STATUS));
    assertEquals("beta", candidate.get("catalogId"));
    verify(appHost, never()).catalogOrigin(APP_ID);
  }

  @Test
  void check_whenLegacyModeHasMultipleCatalogs_expectLegacySelectorRemainsAvailable()
      throws Exception {
    AppUpdateService service =
        serviceWithInstalled(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog("alpha"), catalog("beta")));
    when(catalogManager.listRoutineApps("alpha"))
        .thenReturn(List.of(entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED)));
    when(catalogManager.listRoutineApps("beta"))
        .thenReturn(List.of(entry("2.0.0", AppCatalogReviewStatus.REVIEWED)));

    Map<String, Object> candidate =
        (Map<String, Object>) service.check(APP_ID, false).get(CANDIDATE);

    assertEquals(AVAILABLE, candidate.get(STATUS));
    assertEquals("beta", candidate.get("catalogId"));
    assertEquals("2.0.0", candidate.get(TARGET_VERSION));
  }

  @Test
  void check_whenLegacyModeHasEqualCandidates_expectLegacyCatalogTieBreakIsPreserved()
      throws Exception {
    AppUpdateService service =
        serviceWithInstalled(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog("alpha"), catalog("beta")));
    AppCatalogEntry equalCandidate = entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED);
    when(catalogManager.listRoutineApps("alpha")).thenReturn(List.of(equalCandidate));
    when(catalogManager.listRoutineApps("beta")).thenReturn(List.of(equalCandidate));

    Map<String, Object> candidate =
        (Map<String, Object>) service.check(APP_ID, false).get(CANDIDATE);

    assertEquals(AVAILABLE, candidate.get(STATUS));
    assertEquals("beta", candidate.get("catalogId"));
    assertEquals(UPDATE_VERSION, candidate.get(TARGET_VERSION));
  }

  @Test
  void stage_whenPinnedCatalogChangesPublisher_expectExplicitSourceSwitchConsentRequired()
      throws Exception {
    AppUpdateService service =
        serviceWithInstalled(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    enableFederation(service);
    when(appHost.catalogOrigin(APP_ID)).thenReturn(Optional.of(installedOrigin("alpha")));
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog("alpha")));
    AppCatalogEntry update = entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED);
    when(catalogManager.listRoutineApps("alpha")).thenReturn(List.of(update));
    AppCatalogInstallPlan plan =
        plan(
            "alpha",
            update,
            new AppCatalogBundleVerificationResult(
                "publisher-next",
                "1".repeat(64),
                "publisher-binding",
                "2".repeat(64),
                true,
                "3".repeat(64)),
            null);
    when(catalogManager.prepareInstallPlan("alpha", APP_ID)).thenReturn(plan);
    service.check(APP_ID, false);

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> service.stage(APP_ID));

    assertEquals("catalog_source_switch_consent_required", exception.errorCode());
  }

  @Test
  void stage_whenPublisherKeyChangesAndFingerprintsAreUnavailable_expectConsentRequired()
      throws Exception {
    AppUpdateService service =
        serviceWithInstalled(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    enableFederation(service);
    InstalledAppOrigin current = installedOrigin("alpha", "publisher-current", "");
    when(appHost.catalogOrigin(APP_ID)).thenReturn(Optional.of(current));
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog("alpha")));
    AppCatalogEntry update = entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED);
    when(catalogManager.listRoutineApps("alpha")).thenReturn(List.of(update));
    AppCatalogInstallPlan plan =
        plan(
            "alpha",
            update,
            new AppCatalogBundleVerificationResult(
                "publisher-next", "", "legacy-custom-bundle-policy", "", false),
            new AppCatalogOriginContext(
                "alpha",
                "catalog-key",
                DIGEST,
                "3".repeat(64),
                "binding-1",
                DIGEST,
                DIGEST,
                DIGEST,
                true));
    when(catalogManager.prepareInstallPlan("alpha", APP_ID)).thenReturn(plan);
    service.check(APP_ID, false);

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> service.stage(APP_ID));

    assertEquals("catalog_source_switch_consent_required", exception.errorCode());
    assertTrue(CatalogSourceSwitchConsent.evaluate(plan, current).publisherSwitch());
  }

  @Test
  void stage_whenPublisherChangesWithExactPreviewConsent_expectCandidateStaged() throws Exception {
    AppUpdateService service =
        serviceWithInstalled(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    enableFederation(service);
    InstalledAppOrigin current = installedOrigin("alpha");
    when(appHost.catalogOrigin(APP_ID)).thenReturn(Optional.of(current));
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog("alpha")));
    AppCatalogEntry update = entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED);
    when(catalogManager.listRoutineApps("alpha")).thenReturn(List.of(update));
    AppCatalogInstallPlan plan =
        plan(
            "alpha",
            update,
            new AppCatalogBundleVerificationResult(
                "publisher-next",
                "1".repeat(64),
                "publisher-binding",
                "2".repeat(64),
                true,
                "3".repeat(64)),
            new AppCatalogOriginContext(
                "alpha",
                "catalog-key",
                DIGEST,
                "3".repeat(64),
                "binding-1",
                DIGEST,
                DIGEST,
                DIGEST,
                true));
    when(catalogManager.prepareInstallPlan("alpha", APP_ID)).thenReturn(plan);
    service.check(APP_ID, false);
    String consent = CatalogSourceSwitchConsent.evaluate(plan, current).consentDigestSha256();

    Map<String, Object> summary = service.stage(APP_ID, false, false, false, consent);

    assertEquals(true, ((Map<?, ?>) summary.get(STAGED)).get(AVAILABLE));
  }

  @Test
  void stage_whenSameVersionSourceSwitchHasExactPreview_expectCandidateStaged() throws Exception {
    AppUpdateService service =
        serviceWithInstalled(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    enableFederation(service);
    InstalledAppOrigin current = installedOrigin("alpha");
    when(appHost.catalogOrigin(APP_ID)).thenReturn(Optional.of(current));
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog("beta")));
    AppCatalogEntry target = entry(INSTALLED_VERSION, AppCatalogReviewStatus.REVIEWED);
    when(catalogManager.listRoutineApps("beta")).thenReturn(List.of(target));
    AppCatalogInstallPlan plan = federatedPlan("beta", target);
    when(catalogManager.prepareInstallPlan("beta", APP_ID)).thenReturn(plan);
    String consent = CatalogSourceSwitchConsent.evaluate(plan, current).consentDigestSha256();

    Map<String, Object> summary = service.stage(APP_ID, false, false, false, consent, "beta");

    Map<?, ?> staged = (Map<?, ?>) summary.get(STAGED);
    assertEquals(true, staged.get(AVAILABLE));
    assertEquals("beta", staged.get("catalogId"));
    assertEquals(INSTALLED_VERSION, staged.get(TARGET_VERSION));
  }

  @Test
  void stage_whenSameVersionTargetHasNoSourceSwitch_expectArbitraryConsentRejected()
      throws Exception {
    AppUpdateService service =
        serviceWithInstalled(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    enableFederation(service);
    when(appHost.catalogOrigin(APP_ID)).thenReturn(Optional.of(installedOrigin("alpha")));
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog("alpha")));
    AppCatalogEntry target = entry(INSTALLED_VERSION, AppCatalogReviewStatus.REVIEWED);
    when(catalogManager.listRoutineApps("alpha")).thenReturn(List.of(target));
    when(catalogManager.prepareInstallPlan("alpha", APP_ID))
        .thenReturn(federatedPlan("alpha", target));

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class,
            () -> service.stage(APP_ID, false, false, false, "arbitrary", "alpha"));

    assertEquals("catalog_source_switch_consent_required", exception.errorCode());
  }

  @Test
  void apply_whenCatalogOriginChangesAfterConsent_expectFreshPreviewRequired() throws Exception {
    AppUpdateService service =
        serviceWithInstalled(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    enableFederation(service);
    InstalledAppOrigin approvedCurrent = installedOrigin("alpha");
    when(appHost.catalogOrigin(APP_ID)).thenReturn(Optional.of(approvedCurrent));
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog("alpha")));
    AppCatalogEntry update = entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED);
    when(catalogManager.listRoutineApps("alpha")).thenReturn(List.of(update));
    AppCatalogInstallPlan plan =
        plan(
            "alpha",
            update,
            new AppCatalogBundleVerificationResult(
                "publisher-next",
                "1".repeat(64),
                "publisher-binding",
                "2".repeat(64),
                true,
                "3".repeat(64)),
            new AppCatalogOriginContext(
                "alpha",
                "catalog-key",
                DIGEST,
                "3".repeat(64),
                "binding-1",
                DIGEST,
                DIGEST,
                DIGEST,
                true));
    when(catalogManager.prepareInstallPlan("alpha", APP_ID)).thenReturn(plan);
    service.check(APP_ID, false);
    String consent =
        CatalogSourceSwitchConsent.evaluate(plan, approvedCurrent).consentDigestSha256();
    service.stage(APP_ID, false, false, false, consent);
    when(appHost.catalogOrigin(APP_ID)).thenReturn(Optional.of(installedOrigin("other")));

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class, () -> service.apply(APP_ID, APPLY_NO_RESTART_NO_HEALTH));

    assertEquals("catalog_source_switch_consent_required", exception.errorCode());
    verify(appHost, never()).updateFromDirectory(any(), any());
    verify(appHost, never()).updateCatalogFromDirectory(any(), any(), any(), any(), any());
  }

  @Test
  void apply_whenHardConflictAppearsAfterStage_expectMutationAuthorizationRejects()
      throws Exception {
    AppUpdateService service =
        serviceWithInstalled(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    enableFederation(service);
    InstalledAppOrigin current = installedOrigin("alpha");
    when(appHost.catalogOrigin(APP_ID)).thenReturn(Optional.of(current));
    when(catalogManager.listCatalogs())
        .thenReturn(
            List.of(catalog("alpha")),
            List.of(catalog("alpha")),
            List.of(catalog("alpha")),
            List.of(catalog("alpha"), catalog("beta")));
    AppCatalogEntry update = entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED);
    when(catalogManager.listRoutineApps("alpha")).thenReturn(List.of(update));
    when(catalogManager.listRoutineApps("beta"))
        .thenReturn(List.of(withBundleDigest(update, "1".repeat(64))));
    FileFederatedCatalogTrustStore trustStore = mock(FileFederatedCatalogTrustStore.class);
    FileCatalogPublisherBindingStore publisherStore = mock(FileCatalogPublisherBindingStore.class);
    FileFederatedCatalogConflictResolutionStore resolutionStore =
        mock(FileFederatedCatalogConflictResolutionStore.class);
    when(trustStore.findByCatalogId("alpha"))
        .thenReturn(Optional.of(federatedCatalogBinding("alpha", 20)));
    when(trustStore.findByCatalogId("beta"))
        .thenReturn(Optional.of(federatedCatalogBinding("beta", 10)));
    when(publisherStore.findActiveForScope(any(), any(), any(), any()))
        .thenAnswer(invocation -> List.of(federatedPublisherBinding(invocation.getArgument(0))));
    when(publisherStore.retainAuthorization(any(), any(), any(), any(), any(), any()))
        .thenReturn(() -> {});
    FileFederatedCatalogConflictResolutionStore.Lookup missingResolution =
        new FileFederatedCatalogConflictResolutionStore.Lookup(
            FileFederatedCatalogConflictResolutionStore.LookupStatus.MISSING, Optional.empty());
    when(resolutionStore.retainLookup(any()))
        .thenReturn(
            new FileFederatedCatalogConflictResolutionStore.RetainedLookup(
                missingResolution, () -> {}));
    service.setFederatedCatalogConflictPolicy(
        new AppUpdateFederationAuthority(trustStore, publisherStore, resolutionStore));
    AppCatalogInstallPlan plan =
        plan(
            "alpha",
            update,
            new AppCatalogBundleVerificationResult(
                "publisher-key", DIGEST, "publisher-binding", DIGEST, true, DIGEST),
            new AppCatalogOriginContext(
                "alpha",
                "catalog-key",
                DIGEST,
                "3".repeat(64),
                "binding-1",
                DIGEST,
                DIGEST,
                DIGEST,
                true));
    when(catalogManager.prepareInstallPlan("alpha", APP_ID)).thenReturn(plan);
    AppCatalogManager.CatalogTrustAuthorization catalogAuthorization = mock();
    when(catalogManager.authorizeInstallPlanForMutation(plan)).thenReturn(catalogAuthorization);
    when(appHost.updateCatalogFromDirectory(any(), any(), any(), any(), any()))
        .thenAnswer(
            invocation -> {
              AppHost.CatalogMutationAuthorization authorization = invocation.getArgument(4);
              InstalledAppOrigin target = invocation.getArgument(2);
              try (var _ = authorization.authorize(target)) {
                return installed(UPDATE_VERSION, List.of(QUEUE_READ_PERMISSION));
              }
            });
    service.check(APP_ID, false);
    service.stage(APP_ID);

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class, () -> service.apply(APP_ID, APPLY_NO_RESTART_NO_HEALTH));

    assertEquals(409, exception.statusCode());
    assertEquals("catalog_conflict_unresolved", exception.errorCode());
    verify(catalogAuthorization).close();
  }

  @Test
  void sourceSwitchConsent_whenCatalogSignerChanges_expectConsentDigestChanges() throws Exception {
    InstalledAppOrigin current = installedOrigin("alpha");
    AppCatalogEntry update = entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED);
    try (AppCatalogInstallPlan base = plan("alpha", update);
        AppCatalogInstallPlan firstSigner = planWithCatalogSigner(base, "catalog-key-a", DIGEST);
        AppCatalogInstallPlan secondSigner =
            planWithCatalogSigner(base, "catalog-key-b", "1".repeat(64))) {
      String firstDigest =
          CatalogSourceSwitchConsent.evaluate(firstSigner, current).consentDigestSha256();
      String secondDigest =
          CatalogSourceSwitchConsent.evaluate(secondSigner, current).consentDigestSha256();

      assertNotEquals(firstDigest, secondDigest);
    }
  }

  @Test
  void retainDirectCatalogPolicyAuthorization_whenPolicySetAndBindingDiffer_expectLeasesComposed()
      throws Exception {
    AppUpdateService service = new AppUpdateService(appHost, catalogManager);
    when(catalogManager.federationEnabled()).thenReturn(true);
    FileFederatedCatalogTrustStore trustStore = mock(FileFederatedCatalogTrustStore.class);
    FileCatalogPublisherBindingStore publisherStore = mock(FileCatalogPublisherBindingStore.class);
    FileFederatedCatalogConflictResolutionStore resolutionStore =
        mock(FileFederatedCatalogConflictResolutionStore.class);
    FederatedCatalogTrustBinding catalogBinding = mock(FederatedCatalogTrustBinding.class);
    when(catalogBinding.status()).thenReturn(FederatedCatalogTrustBinding.Status.ACTIVE);
    when(catalogBinding.allowedChannels()).thenReturn(Set.of(AppCatalogChannel.STABLE));
    when(catalogBinding.selfDigest()).thenReturn(DIGEST);
    when(catalogBinding.localPriority()).thenReturn(20);
    when(catalogBinding.publisherPolicyDigest()).thenReturn(Optional.of(DIGEST));
    when(trustStore.findByCatalogId("alpha")).thenReturn(Optional.of(catalogBinding));
    when(trustStore.findByCatalogId("beta"))
        .thenReturn(Optional.of(federatedCatalogBinding("beta", 10)));
    FileCatalogPublisherBindingStore.AuthorizationLease publisherAuthorization = mock();
    when(publisherStore.retainAuthorization(any(), any(), any(), any(), any(), any()))
        .thenReturn(publisherAuthorization);
    service.setFederatedCatalogConflictPolicy(
        new AppUpdateFederationAuthority(trustStore, publisherStore, resolutionStore));
    CatalogScopedReviewerPolicy reviewerPolicy = mock(CatalogScopedReviewerPolicy.class);
    AppReviewTrustDecision decision = mock(AppReviewTrustDecision.class);
    when(decision.trusted()).thenReturn(true);
    when(decision.positive()).thenReturn(true);
    when(decision.toJsonValue())
        .thenReturn(
            Map.of(
                "status", "trusted_reviewed",
                "trusted", true,
                "positive", true,
                "requiresAcknowledgement", false,
                "blocksInstall", false,
                "blocksUpdate", false,
                "blocksPolicyApply", false));
    CatalogScopedReviewerPolicy.Verification verification =
        new CatalogScopedReviewerPolicy.Verification(
            decision, true, "reviewer-scope", DIGEST, DIGEST, "authorized");
    network.crypta.platform.appcatalog.FileCatalogReviewerScopeStore.AuthorizationLease
        reviewerScopeAuthorization = mock();
    CatalogScopedReviewerPolicy.RoutineAuthorization reviewerAuthorization =
        new CatalogScopedReviewerPolicy.RoutineAuthorization(
            verification, TrustedReviewerKeys.empty(), reviewerScopeAuthorization);
    when(reviewerPolicy.retainAuthorization(any(), any(), any(), any(), any()))
        .thenReturn(reviewerAuthorization);
    when(reviewerPolicy.evaluate(any(), any(), any(), any(), any())).thenReturn(verification);
    service.setCatalogScopedReviewerPolicy(reviewerPolicy);
    AppCatalogEntry entry = entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog("alpha"), catalog("beta")));
    when(catalogManager.listRoutineApps("alpha")).thenReturn(List.of(entry));
    when(catalogManager.listRoutineApps("beta")).thenReturn(List.of(entry));
    when(publisherStore.findActiveForScope(any(), any(), any(), any()))
        .thenAnswer(invocation -> List.of(federatedPublisherBinding(invocation.getArgument(0))));
    FederatedCatalogConflictEngine.Resolution conflictResolution = mock();
    when(conflictResolution.kind())
        .thenReturn(FederatedCatalogConflictEngine.ResolutionKind.PIN_CATALOG);
    when(conflictResolution.catalogId()).thenReturn(Optional.of("alpha"));
    FileFederatedCatalogConflictResolutionStore.AuthorizationLease conflictAuthorization = mock();
    when(resolutionStore.retainLookup(any()))
        .thenReturn(
            new FileFederatedCatalogConflictResolutionStore.RetainedLookup(
                new FileFederatedCatalogConflictResolutionStore.Lookup(
                    FileFederatedCatalogConflictResolutionStore.LookupStatus.APPLICABLE,
                    Optional.of(conflictResolution)),
                conflictAuthorization));
    try (AppCatalogInstallPlan plan =
        plan(
            "alpha",
            entry,
            new AppCatalogBundleVerificationResult(
                "publisher-key", DIGEST, "publisher-binding", "2".repeat(64), true, DIGEST),
            new AppCatalogOriginContext(
                "alpha",
                "catalog-key",
                DIGEST,
                "3".repeat(64),
                "binding-alpha",
                DIGEST,
                DIGEST,
                DIGEST,
                true))) {
      InstalledAppOrigin targetOrigin =
          InstalledAppOrigin.create(
              APP_ID,
              UPDATE_VERSION,
              entry.bundleSha256(),
              "alpha",
              "catalog-key",
              DIGEST,
              "3".repeat(64),
              "publisher-key",
              DIGEST,
              DIGEST,
              "",
              "trusted_reviewed",
              "binding-alpha",
              DIGEST,
              "2".repeat(64),
              DIGEST,
              Instant.parse("2026-05-03T00:00:00Z"),
              null);

      try (var _ =
          service.retainDirectCatalogPolicyAuthorization(
              plan, installed(INSTALLED_VERSION, List.of()), targetOrigin)) {
        assertPolicyAuthorizationOrder(publisherStore, reviewerPolicy, resolutionStore);
        verify(publisherAuthorization, never()).close();
        verify(reviewerScopeAuthorization, never()).close();
        verify(conflictAuthorization, never()).close();
      }

      verify(reviewerScopeAuthorization).close();
      verify(publisherAuthorization).close();
      verify(conflictAuthorization).close();
    }
  }

  @Test
  void check_whenInstalledOriginCatalogUnavailable_expectExplicitOperatorBlock() throws Exception {
    AppUpdateService service =
        serviceWithInstalled(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    enableFederation(service);
    when(appHost.catalogOrigin(APP_ID)).thenReturn(Optional.of(installedOrigin("removed")));
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog("beta")));
    when(catalogManager.listRoutineApps("beta"))
        .thenReturn(List.of(entry("2.0.0", AppCatalogReviewStatus.REVIEWED)));

    Map<String, Object> candidate =
        (Map<String, Object>) service.check(APP_ID, false).get(CANDIDATE);

    assertEquals("blocked", candidate.get(STATUS));
    assertEquals("pinned_catalog_unavailable", candidate.get("policyBlockReason"));
    assertEquals(true, candidate.get(OPERATOR_ACTION_REQUIRED));
  }

  @Test
  void check_whenInstalledOriginHasNoCatalogEntry_expectExplicitOperatorBlock() throws Exception {
    AppUpdateService service =
        serviceWithInstalled(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(catalogManager.federationEnabled()).thenReturn(true);
    when(appHost.catalogOrigin(APP_ID)).thenReturn(Optional.of(installedOrigin("removed")));
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog("beta")));
    when(catalogManager.listRoutineApps("beta")).thenReturn(List.of());

    Map<String, Object> candidate =
        (Map<String, Object>) service.check(APP_ID, false).get(CANDIDATE);

    assertEquals("blocked", candidate.get(STATUS));
    assertEquals("pinned_catalog_unavailable", candidate.get("policyBlockReason"));
    assertEquals(true, candidate.get(OPERATOR_ACTION_REQUIRED));
  }

  @Test
  void stage_whenExplicitTargetNeedsNormalizationAndConsentMatches_expectAlternateStaged()
      throws Exception {
    AppUpdateService service =
        serviceWithInstalled(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    enableFederation(service);
    InstalledAppOrigin current = installedOrigin("removed");
    when(appHost.catalogOrigin(APP_ID)).thenReturn(Optional.of(current));
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog("beta")));
    AppCatalogEntry update = entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED);
    when(catalogManager.listRoutineApps("beta")).thenReturn(List.of(update));
    try (AppCatalogInstallPlan base = plan("beta", update);
        AppCatalogInstallPlan plan =
            planWithCatalogSigner(base, "beta-catalog-key", "1".repeat(64))) {
      when(catalogManager.prepareInstallPlan("beta", APP_ID)).thenReturn(plan);
      service.check(APP_ID, false);
      String consent = CatalogSourceSwitchConsent.evaluate(plan, current).consentDigestSha256();

      Map<String, Object> summary = service.stage(APP_ID, false, false, false, consent, " BeTa ");

      Map<String, Object> staged = (Map<String, Object>) summary.get(STAGED);
      assertEquals(true, staged.get(AVAILABLE));
      assertEquals("beta", staged.get("catalogId"));
    }
  }

  @Test
  void check_whenMultipleCatalogsDisagreeOnReviewTrust_expectUnresolvedConflictBlocked()
      throws Exception {
    InstalledAppSnapshot installed = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installed));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    KeyPair reviewerKeyPair = reviewerKeyPair();
    AppUpdateService service =
        new AppUpdateService(
            appHost,
            catalogManager,
            new AppReviewPolicy(AppReviewPolicyMode.REQUIRE_TRUSTED_REVIEW),
            () -> trustedReviewerKeys(reviewerKeyPair));
    enableFederation(service);
    AppCatalogEntry trustedEntry =
        reviewedUpdateEntryWithTrustedReceipt(compatibleApiMetadata(), reviewerKeyPair);
    AppCatalogEntry publisherOnlyEntry =
        entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED, compatibleApiMetadata());
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog("alpha"), catalog("beta")));
    when(catalogManager.listRoutineApps("alpha")).thenReturn(List.of(trustedEntry));
    when(catalogManager.listRoutineApps("beta")).thenReturn(List.of(publisherOnlyEntry));

    Map<String, Object> candidate =
        (Map<String, Object>) service.check(APP_ID, false).get(CANDIDATE);

    assertEquals("blocked", candidate.get(STATUS));
    assertEquals("alpha", candidate.get("catalogId"));
    assertEquals(UPDATE_VERSION, candidate.get(TARGET_VERSION));
    assertEquals("trusted_reviewed", ((Map<?, ?>) candidate.get("reviewTrust")).get(STATUS));
    assertEquals(true, candidate.get(OPERATOR_ACTION_REQUIRED));
  }

  @Test
  void check_whenCatalogsOfferCompetingVersions_expectUnresolvedConflictBlocked() throws Exception {
    InstalledAppSnapshot installed = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installed));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    KeyPair reviewerKeyPair = reviewerKeyPair();
    AppUpdateService service =
        new AppUpdateService(
            appHost,
            catalogManager,
            new AppReviewPolicy(AppReviewPolicyMode.REQUIRE_TRUSTED_REVIEW),
            () -> trustedReviewerKeys(reviewerKeyPair));
    enableFederation(service);
    AppCatalogEntry trustedEntry =
        reviewedUpdateEntryWithTrustedReceipt(compatibleApiMetadata(), reviewerKeyPair);
    AppCatalogEntry blockedNewerEntry =
        entry(EXTERNAL_VERSION, AppCatalogReviewStatus.REVIEWED, compatibleApiMetadata());
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog("alpha"), catalog("beta")));
    when(catalogManager.listRoutineApps("alpha")).thenReturn(List.of(trustedEntry));
    when(catalogManager.listRoutineApps("beta")).thenReturn(List.of(blockedNewerEntry));

    Map<String, Object> candidate =
        (Map<String, Object>) service.check(APP_ID, false).get(CANDIDATE);

    assertEquals("blocked", candidate.get(STATUS));
    assertEquals("alpha", candidate.get("catalogId"));
    assertEquals(UPDATE_VERSION, candidate.get(TARGET_VERSION));
    Map<String, Object> reviewTrust = (Map<String, Object>) candidate.get("reviewTrust");
    assertEquals("trusted_reviewed", reviewTrust.get(STATUS));
    assertEquals(false, reviewTrust.get("blocksUpdate"));
    assertEquals(true, candidate.get(OPERATOR_ACTION_REQUIRED));
  }

  @Test
  void check_whenWarnPolicyHasCrossCatalogConflict_expectCandidateNotAutoStaged() throws Exception {
    InstalledAppSnapshot installed = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installed));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    KeyPair reviewerKeyPair = reviewerKeyPair();
    AppUpdateService service =
        new AppUpdateService(
            appHost,
            catalogManager,
            new AppReviewPolicy(AppReviewPolicyMode.WARN_UNTRUSTED),
            () -> trustedReviewerKeys(reviewerKeyPair));
    enableFederation(service);
    AppCatalogEntry trustedEntry =
        reviewedUpdateEntryWithTrustedReceipt(compatibleApiMetadata(), reviewerKeyPair);
    AppCatalogEntry acknowledgementEntry =
        entry(EXTERNAL_VERSION, AppCatalogReviewStatus.REVIEWED, compatibleApiMetadata());
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog("alpha"), catalog("beta")));
    when(catalogManager.listRoutineApps("alpha")).thenReturn(List.of(trustedEntry));
    when(catalogManager.listRoutineApps("beta")).thenReturn(List.of(acknowledgementEntry));
    service.setPolicy(APP_ID, AppUpdatePolicyMode.STAGE);

    Map<String, Object> summary = service.check(APP_ID, false);

    Map<String, Object> candidate = (Map<String, Object>) summary.get(CANDIDATE);
    Map<String, Object> staged = (Map<String, Object>) summary.get(STAGED);
    assertEquals("blocked", candidate.get(STATUS));
    assertEquals("alpha", candidate.get("catalogId"));
    assertEquals(UPDATE_VERSION, candidate.get(TARGET_VERSION));
    assertEquals("trusted_reviewed", ((Map<?, ?>) candidate.get("reviewTrust")).get(STATUS));
    assertEquals(false, staged.get(AVAILABLE));
  }

  @Test
  void check_whenCatalogListingFails_expectLastCheckFailureRecorded() throws Exception {
    AppUpdateService service =
        serviceWithInstalled(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(catalogManager.listCatalogs()).thenThrow(new IOException("catalog store failed"));

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> service.check(APP_ID, false));

    assertEquals(500, exception.statusCode());
    assertEquals("catalog_list_failed", exception.errorCode());
    Map<String, Object> lastCheck = (Map<String, Object>) service.summary(APP_ID).get("lastCheck");
    assertEquals(FAILED, lastCheck.get(STATUS));
    assertEquals("catalog_list_failed", lastCheck.get(ERROR_CODE));
    assertEquals("Update candidate check failed.", lastCheck.get(MESSAGE));
    verifyNoInstallPlanPreparation();
  }

  @Test
  void check_whenPolicyStageFails_expectLastCheckFailureRecorded() throws Exception {
    KeyPair reviewerKeyPair = reviewerKeyPair();
    AppUpdateService service =
        serviceWithInstalled(
            INSTALLED_VERSION,
            List.of(QUEUE_READ_PERMISSION),
            AppReviewPolicy.DEFAULT,
            () -> trustedReviewerKeys(reviewerKeyPair));
    AppCatalogEntry entry =
        withTrustedReceipt(
            entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED, compatibleApiMetadata()),
            reviewerKeyPair);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID)).thenReturn(List.of(entry));
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID))
        .thenThrow(new IOException("stage failed"));
    service.setPolicy(APP_ID, AppUpdatePolicyMode.STAGE);

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> service.check(APP_ID, false));

    assertEquals(500, exception.statusCode());
    assertEquals("stage_failed", exception.errorCode());
    Map<String, Object> lastCheck = (Map<String, Object>) service.summary(APP_ID).get("lastCheck");
    assertEquals(FAILED, lastCheck.get(STATUS));
    assertEquals("stage_failed", lastCheck.get(ERROR_CODE));
    assertEquals("Update candidate check failed.", lastCheck.get(MESSAGE));
  }

  @Test
  void stage_whenCandidateRequiresFuturePlatformApi_expectStableIncompatibleFailure()
      throws Exception {
    AppUpdateService service =
        serviceWithInstalled(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    AppApiCompatibilityMetadata futureContract = futureApiMetadata();
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID))
        .thenReturn(
            List.of(entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED, futureContract)));
    service.check(APP_ID, false);

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> service.stage(APP_ID));

    assertEquals(409, exception.statusCode());
    assertEquals("update_incompatible", exception.errorCode());
    verifyNoInstallPlanPreparation();
  }

  @Test
  void stage_whenCatalogTargetsUnsupportedBaseline_expectBlockedBeforePlanPreparation()
      throws Exception {
    AppUpdateService service =
        serviceWithInstalled(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    AppApiCompatibilityMetadata unsupportedBaseline =
        new AppApiCompatibilityMetadata(
            1,
            PlatformApiContract.current().contractVersion(),
            List.of(),
            TargetStability.STABLE,
            true,
            "1.1",
            true,
            false,
            false);
    AppCatalogEntry catalogEntry =
        entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED, unsupportedBaseline);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID)).thenReturn(List.of(catalogEntry));
    service.check(APP_ID, false);

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> service.stage(APP_ID));

    assertEquals("update_incompatible", exception.errorCode());
    verifyNoInstallPlanPreparation();
  }

  @Test
  void stage_whenPreparedPlanNoLongerMatchesReviewedCandidate_expectCandidateChangedFailure()
      throws Exception {
    AppUpdateService service =
        serviceWithInstalled(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    AppCatalogEntry reviewedEntry = entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED);
    AppCatalogEntry changedEntry = entry(UPDATE_VERSION, AppCatalogReviewStatus.CAUTION);
    AppCatalogInstallPlan changedPlan = plan(changedEntry);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID)).thenReturn(List.of(reviewedEntry));
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID)).thenReturn(changedPlan);
    service.check(APP_ID, false);

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> service.stage(APP_ID));

    assertEquals(409, exception.statusCode());
    assertEquals(UPDATE_CANDIDATE_CHANGED, exception.errorCode());
    assertFalse(Files.exists(changedPlan.scratchDirectory()));
    verify(appHost, never()).updateFromDirectory(any(), any());
  }

  @Test
  void check_whenCatalogGateMetadataChangesAfterStage_expectStageInvalidated() throws Exception {
    AppUpdateService service =
        serviceWithInstalled(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    AppCatalogEntry compatibleEntry = entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED);
    AppApiCompatibilityMetadata futureContract = futureApiMetadata();
    AppCatalogEntry incompatibleEntry =
        entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED, futureContract);
    AppCatalogInstallPlan plan = plan(compatibleEntry);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID))
        .thenReturn(List.of(compatibleEntry), List.of(incompatibleEntry));
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID)).thenReturn(plan);
    service.stage(APP_ID);

    Map<String, Object> summary = service.check(APP_ID, false);

    assertEquals(false, ((Map<?, ?>) summary.get(STAGED)).get(AVAILABLE));
    assertEquals("incompatible", ((Map<?, ?>) summary.get(CANDIDATE)).get(STATUS));
    assertFalse(Files.exists(plan.scratchDirectory()));
    verify(appHost, never()).updateFromDirectory(any(), any());
  }

  @Test
  void previewReadOnly_whenDetectedCandidateDiffersFromStaged_expectStagedUpdateRetained()
      throws Exception {
    AppUpdateService service =
        serviceWithInstalled(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    AppCatalogEntry stagedEntry =
        entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED, compatibleApiMetadata());
    AppCatalogEntry newerEntry =
        entry(EXTERNAL_VERSION, AppCatalogReviewStatus.REVIEWED, compatibleApiMetadata());
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID))
        .thenReturn(List.of(stagedEntry))
        .thenReturn(List.of(newerEntry));
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID)).thenReturn(plan(stagedEntry));
    service.stage(APP_ID);

    Map<String, Object> summary = service.previewReadOnly(APP_ID);

    Map<String, Object> candidate = (Map<String, Object>) summary.get(CANDIDATE);
    Map<String, Object> staged = (Map<String, Object>) summary.get(STAGED);
    assertEquals(EXTERNAL_VERSION, candidate.get(TARGET_VERSION));
    assertEquals(true, staged.get(AVAILABLE));
    assertEquals(UPDATE_VERSION, staged.get(TARGET_VERSION));
  }

  @Test
  void check_whenPolicyIsStage_expectVerifiedCandidateStagedWithoutApply() throws Exception {
    KeyPair reviewerKeyPair = reviewerKeyPair();
    AppUpdateService service =
        serviceWithInstalled(
            INSTALLED_VERSION,
            List.of(QUEUE_READ_PERMISSION),
            AppReviewPolicy.DEFAULT,
            () -> trustedReviewerKeys(reviewerKeyPair));
    AppCatalogEntry entry =
        withTrustedReceipt(
            entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED, compatibleApiMetadata()),
            reviewerKeyPair);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID)).thenReturn(List.of(entry));
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID)).thenReturn(plan(entry));
    service.setPolicy(APP_ID, AppUpdatePolicyMode.STAGE);

    Map<String, Object> summary = service.check(APP_ID, false);

    Map<String, Object> staged = (Map<String, Object>) summary.get(STAGED);
    assertEquals(true, staged.get(AVAILABLE));
    assertEquals(STAGED, staged.get(STATUS));
    assertEquals(UPDATE_VERSION, staged.get(TARGET_VERSION));
    assertFalse(staged.toString().contains(tempDir.toString()));
    verify(appHost, never()).updateFromDirectory(any(), any());
  }

  @Test
  void check_whenStagePolicyMigrationRollbackIncompatible_expectCandidateRequiresOperatorReview()
      throws Exception {
    InstalledAppSnapshot installed = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installed));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    KeyPair reviewerKeyPair = reviewerKeyPair();
    AppUpdateService service =
        serviceWithAppData(
            appDataServiceWithFeedRecord(),
            (_, _, _, _) -> AppDataMigrationRunner.MigrationExecutionResult.passed(),
            reviewerKeyPair);
    AppCatalogEntry entry =
        withTrustedReceipt(
            entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED, compatibleApiMetadata()),
            reviewerKeyPair);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID)).thenReturn(List.of(entry));
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID))
        .thenReturn(planWithAppDataMigration(entry, false, true));
    service.setPolicy(APP_ID, AppUpdatePolicyMode.STAGE);

    Map<String, Object> summary = service.check(APP_ID, false);

    Map<String, Object> candidate = (Map<String, Object>) summary.get(CANDIDATE);
    Map<String, Object> migration = (Map<String, Object>) candidate.get("dataMigration");
    assertEquals(AVAILABLE, candidate.get(STATUS));
    assertEquals(false, candidate.get("autoStageAllowed"));
    assertEquals(true, candidate.get(OPERATOR_ACTION_REQUIRED));
    assertEquals("rollback_incompatible", migration.get(STATUS));
    assertEquals("app_data_migration_review_required", migration.get("blockReason"));
    assertEquals(true, migration.get("operatorReviewRequired"));
    assertEquals(List.of("app_data_migration"), candidate.get("materialConsentReasons"));
    assertEquals(false, ((Map<?, ?>) summary.get(STAGED)).get(AVAILABLE));
    assertEquals("success", ((Map<?, ?>) summary.get("lastCheck")).get(STATUS));
    Map<String, Object> historyEntry =
        ((List<Map<String, Object>>) summary.get("history"))
            .stream()
                .filter(entryJson -> "stage".equals(entryJson.get("action")))
                .findFirst()
                .orElseThrow();
    assertEquals("consent_required", historyEntry.get(ERROR_CODE));
    verify(appHost, never()).updateFromDirectory(any(), any());
  }

  @Test
  void previewForConsent_whenMigrationRollbackIncompatible_expectCandidateRequiresOperatorReview()
      throws Exception {
    InstalledAppSnapshot installed = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installed));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    AtomicBoolean runnerCalled = new AtomicBoolean(false);
    AppUpdateService service =
        serviceWithAppData(
            appDataServiceWithFeedRecord(),
            (_, _, _, _) -> {
              runnerCalled.set(true);
              return AppDataMigrationRunner.MigrationExecutionResult.passed();
            });
    AppCatalogEntry entry =
        entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED, compatibleApiMetadata());
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID)).thenReturn(List.of(entry));
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID))
        .thenReturn(planWithAppDataMigration(entry, false, true));

    Map<String, Object> summary = service.previewForConsent(APP_ID, false);

    Map<String, Object> candidate = (Map<String, Object>) summary.get(CANDIDATE);
    Map<String, Object> migration = (Map<String, Object>) candidate.get("dataMigration");
    assertFalse(runnerCalled.get());
    assertEquals(AVAILABLE, candidate.get(STATUS));
    assertEquals(false, candidate.get("autoStageAllowed"));
    assertEquals(true, candidate.get(OPERATOR_ACTION_REQUIRED));
    assertEquals("ready", migration.get(STATUS));
    assertEquals(true, migration.get("required"));
    assertEquals(true, migration.get("operatorReviewRequired"));
    assertNull(migration.get("blockReason"));
    assertNull(migration.get("dryRunStatus"));
    verify(appHost, never()).updateFromDirectory(any(), any());
  }

  @Test
  void previewForConsent_whenSecurityDecisionBlocksUpdate_expectDoesNotPrepareInstallPlan()
      throws Exception {
    AppUpdateService service =
        serviceWithInstalled(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID))
        .thenReturn(List.of(entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED)));
    when(catalogManager.securityDecision(CATALOG_ID, APP_ID))
        .thenReturn(blockUpdateAndWarningSecurityDecision());

    Map<String, Object> summary = service.previewForConsent(APP_ID, false);

    Map<String, Object> candidate = (Map<String, Object>) summary.get(CANDIDATE);
    Map<String, Object> securityDecision = (Map<String, Object>) candidate.get(SECURITY_DECISION);
    Map<String, Object> migration = (Map<String, Object>) candidate.get("dataMigration");
    assertEquals(AVAILABLE, candidate.get(STATUS));
    assertEquals("blocked", securityDecision.get(STATUS));
    assertEquals(true, securityDecision.get("blocksUpdate"));
    assertEquals("not_checked", migration.get(STATUS));
    verifyNoInstallPlanPreparation();
  }

  @Test
  void previewForConsent_whenCatalogAndStagedBaselineDiffer_expectInvalidBundle() throws Exception {
    AppUpdateService service =
        serviceWithInstalled(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    AppApiCompatibilityMetadata catalogCompatibility = declaredBaselineApiMetadata("1.0");
    AppCatalogEntry entry =
        entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED, catalogCompatibility);
    AppCatalogInstallPlan plan = plan(entry);
    Path manifest = plan.stagedBundleDirectory().resolve("cryptad-app.properties");
    Files.writeString(
        manifest,
        Files.readString(manifest, StandardCharsets.UTF_8)
            .replace("api.targetBaseline=1.0", "api.targetBaseline=1.1"),
        StandardCharsets.UTF_8);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID)).thenReturn(List.of(entry));
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID)).thenReturn(plan);

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> service.previewForConsent(APP_ID, false));

    assertEquals(400, exception.statusCode());
    assertEquals("invalid_app_bundle", exception.errorCode());
    assertFalse(Files.exists(plan.scratchDirectory()));
  }

  @Test
  void previewForConsent_whenLegacyCatalogOmitsApiTarget_expectStagedManifestSummary()
      throws Exception {
    AppUpdateService service =
        serviceWithInstalled(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    AppCatalogEntry entry = entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED);
    AppCatalogInstallPlan plan = plan(entry);
    Path manifest = plan.stagedBundleDirectory().resolve("cryptad-app.properties");
    Files.writeString(
        manifest,
        Files.readString(manifest, StandardCharsets.UTF_8)
            + "api.minimumVersion=1\n"
            + "api.maximumTestedVersion="
            + PlatformApiContract.current().contractVersion()
            + "\napi.targetStability=stable\n"
            + "api.targetBaseline=1.1\n",
        StandardCharsets.UTF_8);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID)).thenReturn(List.of(entry));
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID)).thenReturn(plan);

    Map<String, Object> summary = service.previewForConsent(APP_ID, false);

    Map<String, Object> candidate = (Map<String, Object>) summary.get(CANDIDATE);
    Map<String, Object> apiCompatibility = (Map<String, Object>) candidate.get("apiCompatibility");
    assertEquals("incompatible", candidate.get(STATUS));
    assertEquals("unsupported-baseline", apiCompatibility.get(STATUS));
    assertEquals("1.1", apiCompatibility.get("targetBaseline"));
    assertFalse(Files.exists(plan.scratchDirectory()));
  }

  @Test
  void check_whenStagePolicyMigrationPathMissing_expectCandidateSummaryWithoutCheckFailure()
      throws Exception {
    InstalledAppSnapshot installed = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installed));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    AtomicBoolean runnerCalled = new AtomicBoolean(false);
    KeyPair reviewerKeyPair = reviewerKeyPair();
    AppUpdateService service =
        serviceWithAppData(
            appDataServiceWithFeedRecord(),
            (_, _, _, _) -> {
              runnerCalled.set(true);
              return AppDataMigrationRunner.MigrationExecutionResult.passed();
            },
            reviewerKeyPair);
    AppCatalogEntry entry =
        withTrustedReceipt(
            entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED, compatibleApiMetadata()),
            reviewerKeyPair);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID)).thenReturn(List.of(entry));
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID))
        .thenReturn(planWithAppDataMigration(entry, true, false));
    service.setPolicy(APP_ID, AppUpdatePolicyMode.STAGE);

    Map<String, Object> summary = service.check(APP_ID, false);

    assertFalse(runnerCalled.get());
    assertEquals(false, ((Map<?, ?>) summary.get(STAGED)).get(AVAILABLE));
    assertEquals("success", ((Map<?, ?>) summary.get("lastCheck")).get(STATUS));
    Map<String, Object> candidate = (Map<String, Object>) summary.get(CANDIDATE);
    Map<String, Object> migration = (Map<String, Object>) candidate.get("dataMigration");
    assertEquals(AVAILABLE, candidate.get(STATUS));
    assertEquals(false, candidate.get("autoStageAllowed"));
    assertEquals(true, candidate.get(OPERATOR_ACTION_REQUIRED));
    assertEquals("missing_migration", migration.get(STATUS));
    assertEquals("app_data_migration_missing", migration.get("blockReason"));
    verify(appHost, never()).updateFromDirectory(any(), any());
  }

  @Test
  void check_whenStagePolicyMigrationDryRunFails_expectCandidateSummaryWithoutCheckFailure()
      throws Exception {
    InstalledAppSnapshot installed = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installed));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    AtomicBoolean runnerCalled = new AtomicBoolean(false);
    KeyPair reviewerKeyPair = reviewerKeyPair();
    AppUpdateService service =
        serviceWithAppData(
            appDataServiceWithFeedRecord(),
            (_, _, _, _) -> {
              runnerCalled.set(true);
              return AppDataMigrationRunner.MigrationExecutionResult.failed(2);
            },
            reviewerKeyPair);
    AppCatalogEntry entry =
        withTrustedReceipt(
            entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED, compatibleApiMetadata()),
            reviewerKeyPair);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID)).thenReturn(List.of(entry));
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID))
        .thenReturn(planWithAppDataMigration(entry, true, true));
    service.setPolicy(APP_ID, AppUpdatePolicyMode.STAGE);

    Map<String, Object> summary = service.check(APP_ID, false);

    assertTrue(runnerCalled.get());
    assertEquals(false, ((Map<?, ?>) summary.get(STAGED)).get(AVAILABLE));
    assertEquals("success", ((Map<?, ?>) summary.get("lastCheck")).get(STATUS));
    Map<String, Object> candidate = (Map<String, Object>) summary.get(CANDIDATE);
    Map<String, Object> migration = (Map<String, Object>) candidate.get("dataMigration");
    assertEquals(AVAILABLE, candidate.get(STATUS));
    assertEquals(false, candidate.get("autoStageAllowed"));
    assertEquals(true, candidate.get(OPERATOR_ACTION_REQUIRED));
    assertEquals("dry_run_failed", migration.get(STATUS));
    assertEquals("app_data_migration_dry_run_failed", migration.get("blockReason"));
    assertEquals("failed", migration.get("dryRunStatus"));
    verify(appHost, never()).updateFromDirectory(any(), any());
  }

  @Test
  void check_whenStagePolicyMigrationDryRunThrows_expectCandidateSummaryWithoutCheckFailure()
      throws Exception {
    InstalledAppSnapshot installed = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installed));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    AtomicBoolean runnerCalled = new AtomicBoolean(false);
    KeyPair reviewerKeyPair = reviewerKeyPair();
    AppUpdateService service =
        serviceWithAppData(
            appDataServiceWithFeedRecord(),
            (_, _, _, _) -> {
              runnerCalled.set(true);
              throw new IOException("missing migration output");
            },
            reviewerKeyPair);
    AppCatalogEntry entry =
        withTrustedReceipt(
            entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED, compatibleApiMetadata()),
            reviewerKeyPair);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID)).thenReturn(List.of(entry));
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID))
        .thenReturn(planWithAppDataMigration(entry, true, true));
    service.setPolicy(APP_ID, AppUpdatePolicyMode.STAGE);

    Map<String, Object> summary = service.check(APP_ID, false);

    assertTrue(runnerCalled.get());
    assertEquals(false, ((Map<?, ?>) summary.get(STAGED)).get(AVAILABLE));
    assertEquals("success", ((Map<?, ?>) summary.get("lastCheck")).get(STATUS));
    Map<String, Object> candidate = (Map<String, Object>) summary.get(CANDIDATE);
    Map<String, Object> migration = (Map<String, Object>) candidate.get("dataMigration");
    assertEquals(AVAILABLE, candidate.get(STATUS));
    assertEquals(false, candidate.get("autoStageAllowed"));
    assertEquals(true, candidate.get(OPERATOR_ACTION_REQUIRED));
    assertEquals("dry_run_failed", migration.get(STATUS));
    assertEquals("app_data_migration_dry_run_failed", migration.get("blockReason"));
    assertEquals("failed", migration.get("dryRunStatus"));
    verify(appHost, never()).updateFromDirectory(any(), any());
  }

  @Test
  void check_whenApplyWhenStoppedPolicyMigrationDryRunFails_expectCandidateSummaryWithoutApply()
      throws Exception {
    InstalledAppSnapshot installed = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installed));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    AtomicBoolean runnerCalled = new AtomicBoolean(false);
    KeyPair reviewerKeyPair = reviewerKeyPair();
    AppUpdateService service =
        serviceWithAppData(
            appDataServiceWithFeedRecord(),
            (_, _, _, _) -> {
              runnerCalled.set(true);
              return AppDataMigrationRunner.MigrationExecutionResult.failed(2);
            },
            reviewerKeyPair);
    AppCatalogEntry entry =
        withTrustedReceipt(
            entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED, compatibleApiMetadata()),
            reviewerKeyPair);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID)).thenReturn(List.of(entry));
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID))
        .thenReturn(planWithAppDataMigration(entry, true, true));
    service.setPolicy(APP_ID, AppUpdatePolicyMode.APPLY_WHEN_STOPPED);

    Map<String, Object> summary = service.check(APP_ID, false);

    assertTrue(runnerCalled.get());
    assertEquals(false, ((Map<?, ?>) summary.get(STAGED)).get(AVAILABLE));
    assertEquals("success", ((Map<?, ?>) summary.get("lastCheck")).get(STATUS));
    Map<String, Object> candidate = (Map<String, Object>) summary.get(CANDIDATE);
    Map<String, Object> migration = (Map<String, Object>) candidate.get("dataMigration");
    assertEquals(AVAILABLE, candidate.get(STATUS));
    assertEquals(false, candidate.get("autoApplyAllowed"));
    assertEquals(true, candidate.get(OPERATOR_ACTION_REQUIRED));
    assertEquals("dry_run_failed", migration.get(STATUS));
    assertEquals("app_data_migration_dry_run_failed", migration.get("blockReason"));
    verify(appHost, never()).updateFromDirectory(any(), any());
  }

  @Test
  void check_whenPolicyIsStageAndCandidateIsBeta_expectAutomaticStageBlocked() throws Exception {
    AppUpdateService service =
        serviceWithInstalled(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    AppCatalogEntry entry =
        entry(
            UPDATE_VERSION,
            AppCatalogReviewStatus.REVIEWED,
            compatibleApiMetadata(),
            productionMetadata(AppCatalogChannel.BETA));
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID)).thenReturn(List.of(entry));
    service.setPolicy(APP_ID, AppUpdatePolicyMode.STAGE);

    Map<String, Object> summary = service.check(APP_ID, false);

    Map<String, Object> candidate = (Map<String, Object>) summary.get(CANDIDATE);
    assertEquals(AVAILABLE, candidate.get(STATUS));
    assertEquals("beta", candidate.get("channel"));
    assertEquals(false, candidate.get("channelPolicyAllowed"));
    assertEquals("channel_policy_blocked", candidate.get("policyBlockReason"));
    assertEquals(false, candidate.get("autoStageAllowed"));
    assertEquals(true, candidate.get(OPERATOR_ACTION_REQUIRED));
    assertEquals(false, ((Map<?, ?>) summary.get(STAGED)).get(AVAILABLE));
    Map<String, Object> historyEntry =
        ((List<Map<String, Object>>) summary.get("history"))
            .stream()
                .filter(entryJson -> "stage".equals(entryJson.get("action")))
                .findFirst()
                .orElseThrow();
    assertEquals("channel_policy_blocked", historyEntry.get(ERROR_CODE));
    verifyNoInstallPlanPreparation();
  }

  @Test
  void check_whenSitePublisherMigrationUpdateAddsCapabilities_expectExplicitConsentBeforeApply()
      throws Exception {
    String siteId = "site-publisher";
    KeyPair signingKey = reviewerKeyPair();
    Path repository = Path.of("").toAbsolutePath();
    Path template = Path.of("apps/site-publisher/src/staged/cryptad-app.properties.template");
    while (repository != null && !Files.isRegularFile(repository.resolve(template))) {
      repository = repository.getParent();
    }
    assertNotNull(repository, "Site Publisher manifest template must be available");
    String currentMaximum =
        "api.maximumTestedVersion=" + PlatformApiContract.CURRENT_CONTRACT_VERSION;
    String currentTemplate =
        Files.readString(repository.resolve(template))
            .replaceAll("(?m)^api.maximumTestedVersion=[0-9]+$", currentMaximum);
    AppManifest target =
        signedSitePublisherFixture(
            tempDir.resolve("site-target"),
            currentTemplate.replace("${appVersion}", "3.1"),
            signingKey);
    AppManifest old =
        signedSitePublisherFixture(
            tempDir.resolve("site-old"),
            """
            manifest.version=1
            app.id=site-publisher
            app.name=Site Publisher
            app.version=3
            api.minimumVersion=3
            api.maximumTestedVersion=24
            api.targetStability=stable
            api.targetBaseline=1.0
            api.experimentalCapabilitiesAccepted=false
            app.exec=bin/site-publisher.sh
            app.ui.mode=static
            app.ui.entry=static/index.html
            app.permissions=queue.read,queue.write,content.insert
            quota.data.bytes=0
            quota.cache.bytes=0
            """
                .replace("api.maximumTestedVersion=24", currentMaximum),
            signingKey);
    InstalledAppSnapshot installed =
        new InstalledAppSnapshot(
            old,
            new InstalledAppPaths(
                siteId,
                tempDir.resolve("site-old"),
                tempDir.resolve("site-data"),
                tempDir.resolve("site-cache"),
                tempDir.resolve("site-run")));
    when(appHost.describe(siteId)).thenReturn(Optional.of(installed));
    when(appHost.status(siteId)).thenReturn(Optional.empty());
    AppUpdateService service =
        new AppUpdateService(
            appHost,
            catalogManager,
            AppReviewPolicy.DEFAULT,
            () -> trustedReviewerKeys(signingKey));
    AppCatalogEntry candidateEntry =
        withTrustedReceipt(
            new AppCatalogEntry(
                siteId,
                target.appName(),
                target.appVersion(),
                "Private plain-text drafts.",
                null,
                null,
                null,
                List.of(),
                new AppCatalogCompatibilityMetadata(null, target.apiCompatibility()),
                new AppCatalogReviewMetadata(AppCatalogReviewStatus.REVIEWED, null),
                AppCatalogChangelog.EMPTY,
                List.of(),
                AppCatalogProductionMetadata.DEFAULT,
                tempDir.resolve("site-publisher-3.1.zip").toUri(),
                DIGEST,
                1234L,
                AppCatalogEntry.ZIP_BUNDLE_TYPE,
                target.permissions(),
                Map.of()),
            signingKey);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID)).thenReturn(List.of(candidateEntry));
    service.setPolicy(siteId, AppUpdatePolicyMode.APPLY_WHEN_STOPPED);

    Map<String, Object> summary = service.check(siteId, false);

    Map<String, Object> candidate = (Map<String, Object>) summary.get(CANDIDATE);
    assertEquals("3", candidate.get(INSTALLED_VERSION_FIELD));
    assertEquals("3.1", candidate.get(TARGET_VERSION));
    assertEquals(AVAILABLE, candidate.get(STATUS));
    assertEquals(
        List.of("app.data.read", "app.data.write", "content.insert.app-document"),
        ((Map<?, ?>) candidate.get("permissionDelta")).get("added"));
    assertEquals(List.of("new_permission"), candidate.get("materialConsentReasons"));
    assertEquals(true, candidate.get(OPERATOR_ACTION_REQUIRED));
    assertEquals(false, candidate.get("autoStageAllowed"));
    assertEquals(false, candidate.get("autoApplyAllowed"));
    assertEquals(false, ((Map<?, ?>) summary.get(STAGED)).get(AVAILABLE));
    assertTrue(
        ((List<Map<String, Object>>) summary.get("history"))
            .stream().anyMatch(entry -> "consent_required".equals(entry.get(ERROR_CODE))));
    verifyNoInstallPlanPreparation();
    verify(appHost, never()).updateFromDirectory(eq(siteId), any());
    assertEquals(List.of("queue.read", "queue.write", "content.insert"), old.permissions());
  }

  private static AppManifest signedSitePublisherFixture(
      Path bundle, String manifest, KeyPair signingKey) throws IOException {
    Files.createDirectories(bundle.resolve("bin"));
    Files.createDirectories(bundle.resolve("static"));
    Files.writeString(bundle.resolve("cryptad-app.properties"), manifest);
    Files.writeString(bundle.resolve("bin/site-publisher.sh"), "#!/bin/sh\nexit 0\n");
    Files.writeString(bundle.resolve("static/index.html"), "<!doctype html><title>Fixture</title>");
    AppBundleSigner.sign(bundle, "site-test-key", signingKey.getPrivate());
    AppBundleVerifier.verify(
        bundle,
        TrustedAppKeys.of(
            TrustedAppKey.ed25519("site-test-key", signingKey.getPublic().getEncoded())));
    return AppManifestParser.parse(bundle.resolve("cryptad-app.properties"));
  }

  @Test
  void check_whenStagePolicyCandidateAddsPermission_expectConsentRequiredHistory()
      throws Exception {
    KeyPair reviewerKeyPair = reviewerKeyPair();
    AppUpdateService service =
        serviceWithInstalled(
            INSTALLED_VERSION,
            List.of(QUEUE_READ_PERMISSION),
            AppReviewPolicy.DEFAULT,
            () -> trustedReviewerKeys(reviewerKeyPair));
    AppCatalogEntry entry =
        withTrustedReceipt(
            entry(
                UPDATE_VERSION,
                AppCatalogReviewStatus.REVIEWED,
                compatibleApiMetadata(),
                AppCatalogProductionMetadata.DEFAULT,
                List.of(QUEUE_READ_PERMISSION, "content.fetch")),
            reviewerKeyPair);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID)).thenReturn(List.of(entry));
    service.setPolicy(APP_ID, AppUpdatePolicyMode.STAGE);

    Map<String, Object> summary = service.check(APP_ID, false);

    Map<String, Object> candidate = (Map<String, Object>) summary.get(CANDIDATE);
    assertEquals(AVAILABLE, candidate.get(STATUS));
    assertEquals(true, candidate.get("channelPolicyAllowed"));
    assertNull(candidate.get("policyBlockReason"));
    assertEquals(false, candidate.get("autoStageAllowed"));
    assertEquals(true, candidate.get(OPERATOR_ACTION_REQUIRED));
    assertEquals(List.of("new_permission"), candidate.get("materialConsentReasons"));
    assertEquals(false, ((Map<?, ?>) summary.get(STAGED)).get(AVAILABLE));
    Map<String, Object> historyEntry =
        ((List<Map<String, Object>>) summary.get("history"))
            .stream()
                .filter(entryJson -> "stage".equals(entryJson.get("action")))
                .findFirst()
                .orElseThrow();
    assertEquals("consent_required", historyEntry.get(ERROR_CODE));
    assertEquals(
        "Policy skipped update because material consent is required.", historyEntry.get(MESSAGE));
    verifyNoInstallPlanPreparation();
  }

  @Test
  void check_whenStagePolicyCandidateHasSecurityAdvisory_expectConsentRequiredHistory()
      throws Exception {
    KeyPair reviewerKeyPair = reviewerKeyPair();
    AppUpdateService service =
        serviceWithInstalled(
            INSTALLED_VERSION,
            List.of(QUEUE_READ_PERMISSION),
            AppReviewPolicy.DEFAULT,
            () -> trustedReviewerKeys(reviewerKeyPair));
    AppCatalogEntry entry =
        withTrustedReceipt(
            entry(
                UPDATE_VERSION,
                AppCatalogReviewStatus.REVIEWED,
                compatibleApiMetadata(),
                productionMetadataWithSecurityAdvisory()),
            reviewerKeyPair);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID)).thenReturn(List.of(entry));
    service.setPolicy(APP_ID, AppUpdatePolicyMode.STAGE);

    Map<String, Object> summary = service.check(APP_ID, false);

    Map<String, Object> candidate = (Map<String, Object>) summary.get(CANDIDATE);
    assertEquals(AVAILABLE, candidate.get(STATUS));
    assertEquals(true, candidate.get("channelPolicyAllowed"));
    assertNull(candidate.get("policyBlockReason"));
    assertEquals(false, candidate.get("autoStageAllowed"));
    assertEquals(true, candidate.get(OPERATOR_ACTION_REQUIRED));
    assertEquals(List.of("security_advisory"), candidate.get("materialConsentReasons"));
    assertEquals(false, ((Map<?, ?>) summary.get(STAGED)).get(AVAILABLE));
    Map<String, Object> historyEntry =
        ((List<Map<String, Object>>) summary.get("history"))
            .stream()
                .filter(entryJson -> "stage".equals(entryJson.get("action")))
                .findFirst()
                .orElseThrow();
    assertEquals("consent_required", historyEntry.get(ERROR_CODE));
    assertEquals(
        "Policy skipped update because material consent is required.", historyEntry.get(MESSAGE));
    verifyNoInstallPlanPreparation();
  }

  @Test
  void check_whenStableOnlyPolicySeesStableAndNewerBeta_expectStableCandidateAutoStaged()
      throws Exception {
    KeyPair reviewerKeyPair = reviewerKeyPair();
    AppUpdateService service =
        serviceWithInstalled(
            INSTALLED_VERSION,
            List.of(QUEUE_READ_PERMISSION),
            AppReviewPolicy.DEFAULT,
            () -> trustedReviewerKeys(reviewerKeyPair));
    AppCatalogEntry stableEntry =
        withTrustedReceipt(
            entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED, compatibleApiMetadata()),
            reviewerKeyPair);
    AppCatalogEntry betaEntry =
        withTrustedReceipt(
            entry(
                EXTERNAL_VERSION,
                AppCatalogReviewStatus.REVIEWED,
                compatibleApiMetadata(),
                productionMetadata(AppCatalogChannel.BETA)),
            reviewerKeyPair);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID)).thenReturn(List.of(stableEntry, betaEntry));
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID)).thenReturn(plan(stableEntry));
    service.setPolicy(APP_ID, AppUpdatePolicyMode.STAGE);

    Map<String, Object> summary = service.check(APP_ID, false);

    Map<String, Object> candidate = (Map<String, Object>) summary.get(CANDIDATE);
    assertEquals(UPDATE_VERSION, candidate.get(TARGET_VERSION));
    assertEquals("stable", candidate.get("channel"));
    assertEquals(true, candidate.get("channelPolicyAllowed"));
    assertNull(candidate.get("policyBlockReason"));
    assertEquals(true, candidate.get("autoStageAllowed"));
    assertEquals(true, ((Map<?, ?>) summary.get(STAGED)).get(AVAILABLE));
  }

  @Test
  void check_whenPolicyAllowsBeta_expectBetaCandidateRequiresConsent() throws Exception {
    KeyPair reviewerKeyPair = reviewerKeyPair();
    AppUpdateService service =
        serviceWithInstalled(
            INSTALLED_VERSION,
            List.of(QUEUE_READ_PERMISSION),
            AppReviewPolicy.DEFAULT,
            () -> trustedReviewerKeys(reviewerKeyPair));
    AppCatalogEntry entry =
        withTrustedReceipt(
            entry(
                UPDATE_VERSION,
                AppCatalogReviewStatus.REVIEWED,
                compatibleApiMetadata(),
                productionMetadata(AppCatalogChannel.BETA)),
            reviewerKeyPair);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID)).thenReturn(List.of(entry));
    service.setPolicy(
        APP_ID,
        AppUpdatePolicyMode.STAGE,
        Set.of(AppCatalogChannel.STABLE, AppCatalogChannel.BETA));

    Map<String, Object> summary = service.check(APP_ID, false);

    Map<String, Object> candidate = (Map<String, Object>) summary.get(CANDIDATE);
    assertEquals(true, candidate.get("channelPolicyAllowed"));
    assertNull(candidate.get("policyBlockReason"));
    assertEquals(false, candidate.get("autoStageAllowed"));
    assertEquals(true, candidate.get(OPERATOR_ACTION_REQUIRED));
    assertEquals(
        List.of("catalog_support_or_deprecation_change"), candidate.get("materialConsentReasons"));
    assertEquals(false, ((Map<?, ?>) summary.get(STAGED)).get(AVAILABLE));
    Map<String, Object> historyEntry =
        ((List<Map<String, Object>>) summary.get("history"))
            .stream()
                .filter(entryJson -> "stage".equals(entryJson.get("action")))
                .findFirst()
                .orElseThrow();
    assertEquals("consent_required", historyEntry.get(ERROR_CODE));
    assertEquals(
        "Policy skipped update because material consent is required.", historyEntry.get(MESSAGE));
    verifyNoInstallPlanPreparation();
  }

  @Test
  void check_whenBetaPolicyLaterBecomesStableOnly_expectCandidateNotStaged() throws Exception {
    KeyPair reviewerKeyPair = reviewerKeyPair();
    AppUpdateService service =
        serviceWithInstalled(
            INSTALLED_VERSION,
            List.of(QUEUE_READ_PERMISSION),
            AppReviewPolicy.DEFAULT,
            () -> trustedReviewerKeys(reviewerKeyPair));
    AppCatalogEntry entry =
        withTrustedReceipt(
            entry(
                UPDATE_VERSION,
                AppCatalogReviewStatus.REVIEWED,
                compatibleApiMetadata(),
                productionMetadata(AppCatalogChannel.BETA)),
            reviewerKeyPair);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID)).thenReturn(List.of(entry), List.of(entry));
    service.setPolicy(
        APP_ID,
        AppUpdatePolicyMode.STAGE,
        Set.of(AppCatalogChannel.STABLE, AppCatalogChannel.BETA));
    service.check(APP_ID, false);
    service.setPolicy(APP_ID, AppUpdatePolicyMode.STAGE);

    Map<String, Object> summary = service.check(APP_ID, false);

    Map<String, Object> candidate = (Map<String, Object>) summary.get(CANDIDATE);
    Map<String, Object> staged = (Map<String, Object>) summary.get(STAGED);
    assertEquals("channel_policy_blocked", candidate.get("policyBlockReason"));
    assertEquals(false, staged.get(AVAILABLE));
    verifyNoInstallPlanPreparation();
  }

  @Test
  void stage_whenCandidateIsBetaAndPolicyIsStableOnly_expectExplicitStageSucceeds()
      throws Exception {
    AppUpdateService service =
        serviceWithInstalled(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    AppCatalogEntry entry =
        entry(
            UPDATE_VERSION,
            AppCatalogReviewStatus.REVIEWED,
            compatibleApiMetadata(),
            productionMetadata(AppCatalogChannel.BETA));
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID)).thenReturn(List.of(entry));
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID)).thenReturn(plan(entry));

    Map<String, Object> summary = service.stage(APP_ID);

    assertEquals(true, ((Map<?, ?>) summary.get(STAGED)).get(AVAILABLE));
    assertEquals("beta", ((Map<?, ?>) summary.get(CANDIDATE)).get("channel"));
  }

  @Test
  void apply_whenExplicitBetaAppliedUnderStableOnlyPolicy_expectNoOperatorActionRequired()
      throws Exception {
    AppUpdateService service =
        serviceWithInstalled(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    AppCatalogEntry entry =
        entry(
            UPDATE_VERSION,
            AppCatalogReviewStatus.REVIEWED,
            compatibleApiMetadata(),
            productionMetadata(AppCatalogChannel.BETA));
    AppCatalogInstallPlan plan = plan(entry);
    InstalledAppSnapshot updated = installed(UPDATE_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID)).thenReturn(List.of(entry));
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID)).thenReturn(plan);
    when(appHost.updateFromDirectory(APP_ID, plan.stagedBundleDirectory())).thenReturn(updated);
    service.stage(APP_ID);

    Map<String, Object> summary = service.apply(APP_ID, APPLY_NO_RESTART_NO_HEALTH);

    Map<String, Object> candidate = (Map<String, Object>) summary.get(CANDIDATE);
    assertEquals(APPLIED, candidate.get(STATUS));
    assertEquals("channel_policy_blocked", candidate.get("policyBlockReason"));
    assertEquals(false, candidate.get(OPERATOR_ACTION_REQUIRED));
  }

  @Test
  void check_whenPolicyAllowsDeprecatedChannel_expectDeprecatedCandidateStillBlocked()
      throws Exception {
    AppUpdateService service =
        serviceWithInstalled(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    AppCatalogEntry entry =
        entry(
            UPDATE_VERSION,
            AppCatalogReviewStatus.REVIEWED,
            compatibleApiMetadata(),
            productionMetadata(AppCatalogChannel.DEPRECATED));
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID)).thenReturn(List.of(entry));
    service.setPolicy(
        APP_ID,
        AppUpdatePolicyMode.STAGE,
        Set.of(AppCatalogChannel.STABLE, AppCatalogChannel.DEPRECATED));

    Map<String, Object> summary = service.check(APP_ID, false);

    Map<String, Object> candidate = (Map<String, Object>) summary.get(CANDIDATE);
    assertEquals("deprecated", candidate.get("channel"));
    assertEquals(false, candidate.get("channelPolicyAllowed"));
    assertEquals("channel_policy_blocked", candidate.get("policyBlockReason"));
    assertEquals(false, ((Map<?, ?>) summary.get(STAGED)).get(AVAILABLE));
    verifyNoInstallPlanPreparation();
  }

  @Test
  void check_whenPolicyApplyWhenStopped_expectStagedCandidateApplied() throws Exception {
    InstalledAppSnapshot installed = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    InstalledAppSnapshot updated = installed(UPDATE_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.describe(APP_ID))
        .thenReturn(
            Optional.of(installed),
            Optional.of(installed),
            Optional.of(installed),
            Optional.of(updated));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    KeyPair reviewerKeyPair = reviewerKeyPair();
    AppUpdateService service =
        new AppUpdateService(
            appHost,
            catalogManager,
            AppReviewPolicy.DEFAULT,
            () -> trustedReviewerKeys(reviewerKeyPair));
    AppCatalogEntry entry =
        reviewedUpdateEntryWithTrustedReceipt(compatibleApiMetadata(), reviewerKeyPair);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID)).thenReturn(List.of(entry));
    AppCatalogInstallPlan plan = plan(entry);
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID)).thenReturn(plan);
    when(appHost.updateFromDirectory(APP_ID, plan.stagedBundleDirectory())).thenReturn(updated);
    service.setPolicy(APP_ID, AppUpdatePolicyMode.APPLY_WHEN_STOPPED);

    Map<String, Object> summary = service.check(APP_ID, false);

    assertEquals(UPDATE_VERSION, summary.get(INSTALLED_VERSION_FIELD));
    assertEquals(APPLIED, ((Map<?, ?>) summary.get(CANDIDATE)).get(STATUS));
    verify(appHost).updateFromDirectory(APP_ID, plan.stagedBundleDirectory());
  }

  @Test
  void check_whenPolicyApplyWhenStoppedAndAdvisoryReviewedWithoutReceipt_expectConsentRequired()
      throws Exception {
    InstalledAppSnapshot installed = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installed));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    AppUpdateService service =
        new AppUpdateService(
            appHost, catalogManager, AppReviewPolicy.DEFAULT, TrustedReviewerKeys::empty);
    AppCatalogEntry entry =
        entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED, compatibleApiMetadata());
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID)).thenReturn(List.of(entry));
    service.setPolicy(APP_ID, AppUpdatePolicyMode.APPLY_WHEN_STOPPED);

    Map<String, Object> summary = service.check(APP_ID, false);

    Map<String, Object> candidate = (Map<String, Object>) summary.get(CANDIDATE);
    Map<String, Object> reviewTrust = (Map<String, Object>) candidate.get("reviewTrust");
    assertEquals(INSTALLED_VERSION, summary.get(INSTALLED_VERSION_FIELD));
    assertEquals(AVAILABLE, candidate.get(STATUS));
    assertEquals(false, candidate.get("autoStageAllowed"));
    assertEquals(false, candidate.get("autoApplyAllowed"));
    assertEquals(true, candidate.get(OPERATOR_ACTION_REQUIRED));
    assertEquals(List.of("review_trust_delta"), candidate.get("materialConsentReasons"));
    assertEquals(false, ((Map<?, ?>) summary.get(STAGED)).get(AVAILABLE));
    assertEquals("publisher_claim_only", reviewTrust.get(STATUS));
    assertEquals(false, reviewTrust.get("positive"));
    Map<String, Object> historyEntry =
        ((List<Map<String, Object>>) summary.get("history"))
            .stream()
                .filter(entryJson -> "apply".equals(entryJson.get("action")))
                .findFirst()
                .orElseThrow();
    assertEquals("consent_required", historyEntry.get(ERROR_CODE));
    assertEquals(
        "Policy skipped update because material consent is required.", historyEntry.get(MESSAGE));
    verifyNoInstallPlanPreparation();
    verify(appHost, never()).updateFromDirectory(any(), any());
  }

  @Test
  void apply_whenInstalledVersionChangedAfterStage_expectStageInvalidatedAndApplyBlocked()
      throws Exception {
    InstalledAppSnapshot installed = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    InstalledAppSnapshot externallyUpdated =
        installed(EXTERNAL_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.describe(APP_ID))
        .thenReturn(
            Optional.of(installed), Optional.of(externallyUpdated), Optional.of(externallyUpdated));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    AppUpdateService service = new AppUpdateService(appHost, catalogManager);
    AppCatalogEntry entry = entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID)).thenReturn(List.of(entry));
    AppCatalogInstallPlan plan = plan(entry);
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID)).thenReturn(plan);
    service.stage(APP_ID);

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class, () -> service.apply(APP_ID, APPLY_NO_RESTART_NO_HEALTH));

    assertEquals(409, exception.statusCode());
    assertEquals(UPDATE_CANDIDATE_CHANGED, exception.errorCode());
    assertEquals(false, ((Map<?, ?>) service.summary(APP_ID).get(STAGED)).get(AVAILABLE));
    assertFalse(Files.exists(plan.scratchDirectory()));
    verify(appHost, never()).updateFromDirectory(any(), any());
  }

  @Test
  void apply_whenStagedTargetVersionBecomesDenylisted_expectStageInvalidatedAndApplyBlocked()
      throws Exception {
    AppUpdateService service =
        serviceWithInstalled(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    AppCatalogEntry entry = entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID)).thenReturn(List.of(entry));
    when(catalogManager.securityDecision(CATALOG_ID, APP_ID))
        .thenReturn(AppCatalogSecurityDecision.OK);
    when(catalogManager.installedSecurityDecision(APP_ID, INSTALLED_VERSION))
        .thenReturn(AppCatalogSecurityDecision.OK);
    when(catalogManager.installedSecurityDecision(APP_ID, UPDATE_VERSION))
        .thenReturn(
            AppCatalogSecurityDecision.OK,
            AppCatalogSecurityDecision.OK,
            AppCatalogSecurityDecision.OK,
            denylistedSecurityDecision());
    AppCatalogInstallPlan plan = plan(entry);
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID)).thenReturn(plan);
    service.stage(APP_ID);

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class, () -> service.apply(APP_ID, APPLY_NO_RESTART_NO_HEALTH));

    assertEquals(409, exception.statusCode());
    assertEquals("app_security_denylisted", exception.errorCode());
    assertEquals(false, ((Map<?, ?>) service.summary(APP_ID).get(STAGED)).get(AVAILABLE));
    assertFalse(Files.exists(plan.scratchDirectory()));
    verify(appHost, never()).updateFromDirectory(any(), any());
  }

  @Test
  void apply_whenStagedWarningDecisionStillApplies_expectCandidateApplied() throws Exception {
    InstalledAppSnapshot updated = installed(UPDATE_VERSION, List.of(QUEUE_READ_PERMISSION));
    AppUpdateService service =
        serviceWithInstalled(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    AppCatalogEntry entry = entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID)).thenReturn(List.of(entry));
    when(catalogManager.securityDecision(CATALOG_ID, APP_ID)).thenReturn(warningSecurityDecision());
    when(catalogManager.installedSecurityDecision(APP_ID, INSTALLED_VERSION))
        .thenReturn(AppCatalogSecurityDecision.OK);
    when(catalogManager.installedSecurityDecision(APP_ID, UPDATE_VERSION))
        .thenReturn(AppCatalogSecurityDecision.OK);
    AppCatalogInstallPlan plan = plan(entry);
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID)).thenReturn(plan);
    when(appHost.updateFromDirectory(APP_ID, plan.stagedBundleDirectory())).thenReturn(updated);
    service.stage(APP_ID, false, true, false);

    Map<String, Object> summary = service.apply(APP_ID, APPLY_NO_RESTART_NO_HEALTH);

    assertEquals(UPDATE_VERSION, summary.get(INSTALLED_VERSION_FIELD));
    verify(appHost).updateFromDirectory(APP_ID, plan.stagedBundleDirectory());
  }

  @Test
  void apply_whenVaultCleanupFailsAfterReplacement_expectStageClosedAndAppliedWarning()
      throws Exception {
    InstalledAppSnapshot installed =
        installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION, "vault.identities.use"));
    InstalledAppSnapshot updated = installed(UPDATE_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.describe(APP_ID))
        .thenReturn(Optional.of(installed), Optional.of(installed), Optional.of(updated));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    AppVaultService vaultService = AppVaultService.open(tempDir.resolve("vault"));
    AppIdentityRecord identity =
        vaultService.createOperatorIdentity(
            AppIdentityKind.LOCAL_ED25519_SIGNING,
            "Operator publisher",
            null,
            java.util.Set.of(AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED));
    AppIdentityGrant grant =
        vaultService.grantIdentity(
            identity.identityId(),
            APP_ID,
            java.util.Set.of(AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED),
            "operator",
            "test grant",
            null,
            null);
    Files.writeString(
        tempDir.resolve("vault").resolve("grants").resolve(grant.grantId() + ".properties"),
        "grantId="
            + grant.grantId()
            + "\nidentityId="
            + grant.identityId()
            + "\nappId="
            + grant.appId()
            + "\nscopes=sign.domain-separated\nstatus=not-a-status\ncreatedAt="
            + grant.createdAt()
            + "\nupdatedAt="
            + grant.updatedAt()
            + "\n");
    AppUpdateService service =
        new AppUpdateService(
            appHost,
            catalogManager,
            AppReviewPolicy.DEFAULT,
            TrustedReviewerKeys::empty,
            vaultService);
    AppCatalogEntry entry = entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID)).thenReturn(List.of(entry));
    AppCatalogInstallPlan plan = plan(entry);
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID)).thenReturn(plan);
    when(appHost.updateFromDirectory(APP_ID, plan.stagedBundleDirectory())).thenReturn(updated);
    service.stage(APP_ID);

    Map<String, Object> summary = service.apply(APP_ID, APPLY_NO_RESTART_NO_HEALTH);

    assertEquals(false, ((Map<?, ?>) summary.get(STAGED)).get(AVAILABLE));
    assertEquals(APPLIED, ((Map<?, ?>) summary.get(CANDIDATE)).get(STATUS));
    List<Map<String, Object>> history = (List<Map<String, Object>>) summary.get("history");
    assertEquals("success", history.getFirst().get(STATUS));
    assertEquals(
        "Staged update applied; vault grant cleanup failed and requires operator review.",
        history.getFirst().get(MESSAGE));
    assertFalse(Files.exists(plan.scratchDirectory()));
  }

  @Test
  void summary_whenInstalledVersionChangedAfterStage_expectStageInvalidatedAndCandidateCleared()
      throws Exception {
    InstalledAppSnapshot installed = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    InstalledAppSnapshot externallyUpdated =
        installed(EXTERNAL_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.describe(APP_ID))
        .thenReturn(Optional.of(installed), Optional.of(externallyUpdated));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    AppUpdateService service = new AppUpdateService(appHost, catalogManager);
    AppCatalogEntry entry = entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID)).thenReturn(List.of(entry));
    AppCatalogInstallPlan plan = plan(entry);
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID)).thenReturn(plan);
    service.stage(APP_ID);

    Map<String, Object> summary = service.summary(APP_ID);

    assertEquals(EXTERNAL_VERSION, summary.get(INSTALLED_VERSION_FIELD));
    assertEquals(false, ((Map<?, ?>) summary.get(STAGED)).get(AVAILABLE));
    assertEquals("none", ((Map<?, ?>) summary.get(CANDIDATE)).get(STATUS));
    assertEquals(
        EXTERNAL_VERSION, ((Map<?, ?>) summary.get(CANDIDATE)).get(INSTALLED_VERSION_FIELD));
    assertFalse(Files.exists(plan.scratchDirectory()));
    verify(appHost, never()).updateFromDirectory(any(), any());
  }

  @Test
  void summary_whenSameVersionManifestChangesAfterStage_expectStageInvalidatedAndCandidateCleared()
      throws Exception {
    InstalledAppSnapshot installed = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    InstalledAppSnapshot manifestChanged =
        installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION, "network.access"));
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installed), Optional.of(manifestChanged));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    AppUpdateService service = new AppUpdateService(appHost, catalogManager);
    AppCatalogEntry entry = entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID)).thenReturn(List.of(entry));
    AppCatalogInstallPlan plan = plan(entry);
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID)).thenReturn(plan);
    service.stage(APP_ID);

    Map<String, Object> summary = service.summary(APP_ID);

    assertEquals(INSTALLED_VERSION, summary.get(INSTALLED_VERSION_FIELD));
    assertEquals(false, ((Map<?, ?>) summary.get(STAGED)).get(AVAILABLE));
    assertEquals("none", ((Map<?, ?>) summary.get(CANDIDATE)).get(STATUS));
    assertFalse(Files.exists(plan.scratchDirectory()));
    verify(appHost, never()).updateFromDirectory(any(), any());
  }

  @Test
  void summary_whenAppUninstalledAfterStage_expectStageClosedAndCandidateCleared()
      throws Exception {
    InstalledAppSnapshot installed = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    InstalledAppSnapshot reinstalled = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.describe(APP_ID))
        .thenReturn(Optional.of(installed), Optional.empty(), Optional.of(reinstalled));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    AppUpdateService service = new AppUpdateService(appHost, catalogManager);
    AppCatalogEntry entry = entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID)).thenReturn(List.of(entry));
    AppCatalogInstallPlan plan = plan(entry);
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID)).thenReturn(plan);
    service.stage(APP_ID);

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> service.summary(APP_ID));

    assertEquals(404, exception.statusCode());
    assertEquals(APP_NOT_FOUND, exception.errorCode());
    assertFalse(Files.exists(plan.scratchDirectory()));
    Map<String, Object> summary = service.summary(APP_ID);
    assertEquals(false, ((Map<?, ?>) summary.get(STAGED)).get(AVAILABLE));
    assertEquals("none", ((Map<?, ?>) summary.get(CANDIDATE)).get(STATUS));
    verify(appHost, never()).updateFromDirectory(any(), any());
  }

  @Test
  void clearAppState_whenStageExists_expectScratchClosedAndStateReset() throws Exception {
    when(appHost.describe(APP_ID))
        .thenReturn(Optional.of(installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION))));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    AppUpdateService service = new AppUpdateService(appHost, catalogManager);
    AppCatalogEntry entry = entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID)).thenReturn(List.of(entry));
    try (AppCatalogInstallPlan plan = plan(entry)) {
      when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID)).thenReturn(plan);
      service.setPolicy(APP_ID, AppUpdatePolicyMode.STAGE);
      service.stage(APP_ID);

      service.clearAppState(APP_ID);

      Map<String, Object> summary = service.summary(APP_ID);
      assertFalse(Files.exists(plan.scratchDirectory()));
      assertEquals("manual", ((Map<?, ?>) summary.get("policy")).get("mode"));
      assertEquals(false, ((Map<?, ?>) summary.get(STAGED)).get(AVAILABLE));
      assertEquals("none", ((Map<?, ?>) summary.get(CANDIDATE)).get(STATUS));
      verify(appHost, never()).updateFromDirectory(any(), any());
    }
  }

  @Test
  void clearAppState_whenSchedulerCleanerAttached_expectSchedulerStateCleared() {
    AppUpdateService service = new AppUpdateService(appHost, catalogManager);
    AtomicReference<String> clearedAppId = new AtomicReference<>();
    service.setSchedulerStateCleaner(clearedAppId::set);

    service.clearAppState(APP_ID);

    assertEquals(APP_ID, clearedAppId.get());
  }

  @Test
  void apply_whenSameVersionManifestChangesAfterStage_expectStageInvalidatedAndApplyBlocked()
      throws Exception {
    InstalledAppSnapshot installed = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    InstalledAppSnapshot manifestChanged =
        installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION, "network.access"));
    when(appHost.describe(APP_ID))
        .thenReturn(
            Optional.of(installed), Optional.of(manifestChanged), Optional.of(manifestChanged));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    AppUpdateService service = new AppUpdateService(appHost, catalogManager);
    AppCatalogEntry entry = entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID)).thenReturn(List.of(entry));
    AppCatalogInstallPlan plan = plan(entry);
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID)).thenReturn(plan);
    service.stage(APP_ID);

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class, () -> service.apply(APP_ID, APPLY_NO_RESTART_NO_HEALTH));

    assertEquals(409, exception.statusCode());
    assertEquals(UPDATE_CANDIDATE_CHANGED, exception.errorCode());
    assertEquals(false, ((Map<?, ?>) service.summary(APP_ID).get(STAGED)).get(AVAILABLE));
    assertFalse(Files.exists(plan.scratchDirectory()));
    verify(appHost, never()).updateFromDirectory(any(), any());
  }

  @Test
  void apply_whenProcessHealthRequestedWithoutRestart_expectInvalidOptionBeforeReplacement()
      throws Exception {
    InstalledAppSnapshot installed = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installed));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    AppUpdateService service = new AppUpdateService(appHost, catalogManager);
    AppCatalogEntry entry = entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID)).thenReturn(List.of(entry));
    AppCatalogInstallPlan plan = plan(entry);
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID)).thenReturn(plan);
    service.stage(APP_ID);

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class,
            () -> service.apply(APP_ID, APPLY_NO_RESTART_PROCESS_HEALTH));

    assertEquals(400, exception.statusCode());
    assertEquals("invalid_update_option", exception.errorCode());
    assertEquals(true, ((Map<?, ?>) service.summary(APP_ID).get(STAGED)).get(AVAILABLE));
    verify(appHost, never()).updateFromDirectory(any(), any());
  }

  @Test
  void apply_whenRestartedRunningAppFailsBeforeReplacement_expectOriginalAppRestarted()
      throws Exception {
    InstalledAppSnapshot installed = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installed));
    when(appHost.status(APP_ID))
        .thenReturn(
            Optional.empty(), Optional.empty(), Optional.of(running(installed)), Optional.empty());
    AppUpdateService service = new AppUpdateService(appHost, catalogManager);
    AppCatalogEntry entry = entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID)).thenReturn(List.of(entry));
    try (AppCatalogInstallPlan plan = plan(entry)) {
      when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID)).thenReturn(plan);
      when(appHost.updateFromDirectory(APP_ID, plan.stagedBundleDirectory()))
          .thenThrow(new IOException("staged directory disappeared"));
      service.stage(APP_ID);

      PlatformApiException exception =
          assertThrows(
              PlatformApiException.class, () -> service.apply(APP_ID, APPLY_RESTART_NO_HEALTH));

      assertEquals(500, exception.statusCode());
      assertEquals("update_failed", exception.errorCode());
      assertEquals(true, ((Map<?, ?>) service.summary(APP_ID).get(STAGED)).get(AVAILABLE));
      verify(appHost).stop(APP_ID);
      verify(appHost).start(APP_ID);
    }
  }

  @Test
  void apply_whenOriginalBaselineBecomesUnsupported_expectFailureRecoveryLeavesItStopped()
      throws Exception {
    InstalledAppSnapshot installed =
        installedWithApiMetadata(List.of(QUEUE_READ_PERMISSION), unsupportedBaselineApiMetadata());
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installed));
    when(appHost.status(APP_ID))
        .thenReturn(
            Optional.empty(), Optional.empty(), Optional.of(running(installed)), Optional.empty());
    AppUpdateService service = new AppUpdateService(appHost, catalogManager);
    AppCatalogEntry entry = entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID)).thenReturn(List.of(entry));
    try (AppCatalogInstallPlan plan = plan(entry)) {
      when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID)).thenReturn(plan);
      when(appHost.updateFromDirectory(APP_ID, plan.stagedBundleDirectory()))
          .thenThrow(new IOException("staged directory disappeared"));
      service.stage(APP_ID);

      PlatformApiException exception =
          assertThrows(
              PlatformApiException.class, () -> service.apply(APP_ID, APPLY_RESTART_NO_HEALTH));

      assertEquals(500, exception.statusCode());
      assertEquals("update_failed", exception.errorCode());
      verify(appHost).stop(APP_ID);
      verify(appHost, never()).start(APP_ID);
    }
  }

  @Test
  void apply_whenRestartProcessHealthLaunchFails_expectRollbackAttempted() throws Exception {
    InstalledAppSnapshot installed = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    InstalledAppSnapshot updated = installed(UPDATE_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.describe(APP_ID))
        .thenReturn(Optional.of(installed), Optional.of(installed), Optional.of(installed));
    when(appHost.status(APP_ID))
        .thenReturn(
            Optional.empty(), Optional.empty(), Optional.of(running(installed)), Optional.empty());
    AppUpdateService service = new AppUpdateService(appHost, catalogManager);
    AppCatalogEntry entry = entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID)).thenReturn(List.of(entry));
    AppCatalogInstallPlan plan = plan(entry);
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID)).thenReturn(plan);
    when(appHost.updateFromDirectory(APP_ID, plan.stagedBundleDirectory())).thenReturn(updated);
    when(appHost.start(APP_ID)).thenThrow(new IOException("launch failed"));
    when(appHost.rollbackStatus(APP_ID))
        .thenReturn(Optional.of(new AppRollbackRecord(APP_ID, APP_NAME, INSTALLED_VERSION)));
    when(appHost.rollback(APP_ID)).thenReturn(installed);
    service.stage(APP_ID);

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class,
            () -> service.apply(APP_ID, APPLY_RESTART_PROCESS_HEALTH_ROLLBACK));

    assertEquals(409, exception.statusCode());
    assertEquals("health_check_failed", exception.errorCode());
    verify(appHost).stop(APP_ID);
    verify(appHost).updateFromDirectory(APP_ID, plan.stagedBundleDirectory());
    verify(appHost).rollback(APP_ID);
    Map<String, Object> summary = service.summary(APP_ID);
    assertEquals(false, ((Map<?, ?>) summary.get(STAGED)).get(AVAILABLE));
    assertEquals("none", ((Map<?, ?>) summary.get(CANDIDATE)).get(STATUS));
    assertFalse(Files.exists(plan.scratchDirectory()));
  }

  @Test
  void apply_whenHealthRollbackRestoresUnsupportedBaseline_expectRecoveryRestartBlocked()
      throws Exception {
    InstalledAppSnapshot installed =
        installedWithApiMetadata(List.of(QUEUE_READ_PERMISSION), unsupportedBaselineApiMetadata());
    InstalledAppSnapshot updated = installed(UPDATE_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.describe(APP_ID))
        .thenReturn(Optional.of(installed), Optional.of(installed), Optional.of(installed));
    when(appHost.status(APP_ID))
        .thenReturn(
            Optional.empty(), Optional.empty(), Optional.of(running(installed)), Optional.empty());
    AppUpdateService service = new AppUpdateService(appHost, catalogManager);
    AppCatalogEntry entry = entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID)).thenReturn(List.of(entry));
    AppCatalogInstallPlan plan = plan(entry);
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID)).thenReturn(plan);
    when(appHost.updateFromDirectory(APP_ID, plan.stagedBundleDirectory())).thenReturn(updated);
    when(appHost.start(APP_ID)).thenThrow(new IOException("updated bundle launch failed"));
    when(appHost.rollbackStatus(APP_ID))
        .thenReturn(Optional.of(new AppRollbackRecord(APP_ID, APP_NAME, INSTALLED_VERSION)));
    when(appHost.rollback(APP_ID)).thenReturn(installed);
    service.stage(APP_ID);

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class,
            () -> service.apply(APP_ID, APPLY_RESTART_PROCESS_HEALTH_ROLLBACK));

    assertEquals(409, exception.statusCode());
    assertEquals("health_check_failed", exception.errorCode());
    verify(appHost).rollback(APP_ID);
    verify(appHost, times(1)).start(APP_ID);
    Map<String, Object> summary = service.summary(APP_ID);
    assertEquals(false, ((Map<?, ?>) summary.get(STAGED)).get(AVAILABLE));
    assertEquals("none", ((Map<?, ?>) summary.get(CANDIDATE)).get(STATUS));
  }

  @Test
  void apply_whenVaultPermissionRemovedButHealthRollbackCommits_expectGrantRemainsActive()
      throws Exception {
    InstalledAppSnapshot installed =
        installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION, "vault.identities.use"));
    InstalledAppSnapshot updated = installed(UPDATE_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.describe(APP_ID))
        .thenReturn(Optional.of(installed), Optional.of(installed), Optional.of(installed));
    when(appHost.status(APP_ID))
        .thenReturn(
            Optional.empty(), Optional.empty(), Optional.of(running(installed)), Optional.empty());
    AppVaultService vaultService = AppVaultService.open(tempDir.resolve("vault"));
    AppIdentityRecord identity =
        vaultService.createOperatorIdentity(
            AppIdentityKind.LOCAL_ED25519_SIGNING,
            "Operator publisher",
            null,
            java.util.Set.of(AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED));
    AppIdentityGrant grant =
        vaultService.grantIdentity(
            identity.identityId(),
            APP_ID,
            java.util.Set.of(AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED),
            "operator",
            "test grant",
            null,
            null);
    AppUpdateService service =
        new AppUpdateService(
            appHost,
            catalogManager,
            AppReviewPolicy.DEFAULT,
            TrustedReviewerKeys::empty,
            vaultService);
    AppCatalogEntry entry = entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID)).thenReturn(List.of(entry));
    AppCatalogInstallPlan plan = plan(entry);
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID)).thenReturn(plan);
    when(appHost.updateFromDirectory(APP_ID, plan.stagedBundleDirectory())).thenReturn(updated);
    when(appHost.start(APP_ID)).thenThrow(new IOException("launch failed"));
    when(appHost.rollbackStatus(APP_ID))
        .thenReturn(Optional.of(new AppRollbackRecord(APP_ID, APP_NAME, INSTALLED_VERSION)));
    when(appHost.rollback(APP_ID)).thenReturn(installed);
    service.stage(APP_ID);

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class,
            () -> service.apply(APP_ID, APPLY_RESTART_PROCESS_HEALTH_ROLLBACK));

    assertEquals(409, exception.statusCode());
    assertEquals("health_check_failed", exception.errorCode());
    AppIdentityGrant retainedGrant = vaultService.listGrantsForApp(APP_ID).getFirst();
    assertEquals(grant.grantId(), retainedGrant.grantId());
    assertEquals(AppIdentityGrantStatus.ACTIVE, retainedGrant.status());
    assertEquals(
        java.util.Set.of(AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED), retainedGrant.scopes());
    assertFalse(Files.exists(plan.scratchDirectory()));
  }

  @Test
  void apply_whenHealthRollbackStatusCannotBeRead_expectRollbackFailure() throws Exception {
    InstalledAppSnapshot installed = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    InstalledAppSnapshot updated = installed(UPDATE_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.describe(APP_ID))
        .thenReturn(Optional.of(installed), Optional.of(installed), Optional.of(updated));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    AppUpdateService service = new AppUpdateService(appHost, catalogManager);
    AppCatalogEntry entry = entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID)).thenReturn(List.of(entry));
    AppCatalogInstallPlan plan = plan(entry);
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID)).thenReturn(plan);
    when(appHost.updateFromDirectory(APP_ID, plan.stagedBundleDirectory())).thenReturn(updated);
    when(appHost.start(APP_ID)).thenReturn(running(updated));
    when(appHost.rollbackStatus(APP_ID)).thenThrow(new IOException(ROLLBACK_MANIFEST_BROKEN));
    service.stage(APP_ID);

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class,
            () -> service.apply(APP_ID, APPLY_RESTART_PROCESS_HEALTH_ROLLBACK));

    assertEquals(ROLLBACK_FAILED, exception.errorCode());
    assertEquals(500, exception.statusCode());
    Map<String, Object> summary = service.summary(APP_ID);
    assertEquals(false, ((Map<?, ?>) summary.get(STAGED)).get(AVAILABLE));
    assertEquals(APPLIED, ((Map<?, ?>) summary.get(CANDIDATE)).get(STATUS));
    assertEquals(FAILED, ((Map<?, ?>) summary.get(ROLLBACK)).get(STATUS));
    verify(appHost, never()).rollback(eq(APP_ID), any(AppHost.CatalogRollbackAuthorization.class));
    assertFalse(Files.exists(plan.scratchDirectory()));
  }

  @Test
  void apply_whenProcessHealthFailsAfterReplacementWithoutRollback_expectCandidateMarkedApplied()
      throws Exception {
    InstalledAppSnapshot installed = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    InstalledAppSnapshot updated = installed(UPDATE_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.describe(APP_ID))
        .thenReturn(Optional.of(installed), Optional.of(installed), Optional.of(updated));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    AppUpdateService service = new AppUpdateService(appHost, catalogManager);
    AppCatalogEntry entry = entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID)).thenReturn(List.of(entry));
    AppCatalogInstallPlan plan = plan(entry);
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID)).thenReturn(plan);
    when(appHost.updateFromDirectory(APP_ID, plan.stagedBundleDirectory())).thenReturn(updated);
    when(appHost.start(APP_ID)).thenReturn(running(updated));
    service.stage(APP_ID);

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class, () -> service.apply(APP_ID, APPLY_RESTART_PROCESS_HEALTH));

    assertEquals(409, exception.statusCode());
    assertEquals("health_check_failed", exception.errorCode());
    Map<String, Object> summary = service.summary(APP_ID);
    assertEquals(false, ((Map<?, ?>) summary.get(STAGED)).get(AVAILABLE));
    assertEquals(APPLIED, ((Map<?, ?>) summary.get(CANDIDATE)).get(STATUS));
    verify(appHost, never()).rollback(eq(APP_ID), any(AppHost.CatalogRollbackAuthorization.class));
    assertFalse(Files.exists(plan.scratchDirectory()));
  }

  @Test
  void
      apply_whenMigrationAppliedThenProcessHealthFailsWithoutRollback_expectMigrationStatusPreserved()
          throws Exception {
    InstalledAppSnapshot installed = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    InstalledAppSnapshot updated = installed(UPDATE_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.describe(APP_ID))
        .thenReturn(Optional.of(installed), Optional.of(installed), Optional.of(updated));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    AppDataService appDataService = appDataServiceWithFeedRecord();
    List<AppDataMigrationRunner.Mode> modes = new java.util.ArrayList<>();
    AppUpdateService service =
        serviceWithAppData(appDataService, payloadRewritingMigrationRunner(modes));
    AppCatalogEntry entry =
        entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED, compatibleApiMetadata());
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID)).thenReturn(List.of(entry));
    AppCatalogInstallPlan plan = planWithAppDataMigration(entry, true, true);
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID)).thenReturn(plan);
    when(appHost.updateFromDirectory(APP_ID, plan.stagedBundleDirectory())).thenReturn(updated);
    when(appHost.start(APP_ID)).thenReturn(running(updated));
    service.stage(APP_ID);

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class, () -> service.apply(APP_ID, APPLY_RESTART_PROCESS_HEALTH));

    assertEquals(409, exception.statusCode());
    assertEquals("health_check_failed", exception.errorCode());
    assertEquals(
        List.of(
            AppDataMigrationRunner.Mode.DRY_RUN,
            AppDataMigrationRunner.Mode.DRY_RUN,
            AppDataMigrationRunner.Mode.APPLY),
        modes);
    Map<String, Object> summary = service.summary(APP_ID);
    Map<String, Object> candidate = (Map<String, Object>) summary.get(CANDIDATE);
    Map<String, Object> migration = (Map<String, Object>) candidate.get("dataMigration");
    assertEquals(APPLIED, candidate.get(STATUS));
    assertEquals("applied", migration.get(STATUS));
    assertEquals("passed", migration.get("applyStatus"));
    verify(appHost, never()).rollback(eq(APP_ID), any(AppHost.CatalogRollbackAuthorization.class));
    assertFalse(Files.exists(plan.scratchDirectory()));
  }

  @Test
  void apply_whenRestartWithoutHealthCheckFailsAfterReplacement_expectStageCleared()
      throws Exception {
    InstalledAppSnapshot installed = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    InstalledAppSnapshot updated = installed(UPDATE_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.describe(APP_ID))
        .thenReturn(Optional.of(installed), Optional.of(installed), Optional.of(updated));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    AppUpdateService service = new AppUpdateService(appHost, catalogManager);
    AppCatalogEntry entry = entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID)).thenReturn(List.of(entry));
    AppCatalogInstallPlan plan = plan(entry);
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID)).thenReturn(plan);
    when(appHost.updateFromDirectory(APP_ID, plan.stagedBundleDirectory())).thenReturn(updated);
    when(appHost.start(APP_ID)).thenThrow(new IOException("launch failed"));
    service.stage(APP_ID);

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class, () -> service.apply(APP_ID, APPLY_RESTART_NO_HEALTH));

    assertEquals(500, exception.statusCode());
    assertEquals("update_failed", exception.errorCode());
    Map<String, Object> summary = service.summary(APP_ID);
    assertEquals(false, ((Map<?, ?>) summary.get(STAGED)).get(AVAILABLE));
    assertEquals(APPLIED, ((Map<?, ?>) summary.get(CANDIDATE)).get(STATUS));
    assertFalse(Files.exists(plan.scratchDirectory()));
  }

  @Test
  void apply_whenAppStartsAfterPrecheck_expectConflictNotServerError() throws Exception {
    AppUpdateService service =
        serviceWithInstalled(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    AppCatalogEntry entry = entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID)).thenReturn(List.of(entry));
    AppCatalogInstallPlan plan = plan(entry);
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID)).thenReturn(plan);
    when(appHost.updateFromDirectory(APP_ID, plan.stagedBundleDirectory()))
        .thenThrow(new AppHostException("cannot update a running app: " + APP_ID));
    service.stage(APP_ID);

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class, () -> service.apply(APP_ID, APPLY_NO_RESTART_NO_HEALTH));

    assertEquals(409, exception.statusCode());
    assertEquals("app_running", exception.errorCode());
    assertEquals(true, ((Map<?, ?>) service.summary(APP_ID).get(STAGED)).get(AVAILABLE));
    assertTrue(Files.exists(plan.scratchDirectory()));
  }

  @Test
  void apply_whenAppIsUninstalledAfterPrecheck_expectNotFoundNotServerError() throws Exception {
    AppUpdateService service =
        serviceWithInstalled(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    AppCatalogEntry entry = entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID)).thenReturn(List.of(entry));
    AppCatalogInstallPlan plan = plan(entry);
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID)).thenReturn(plan);
    when(appHost.updateFromDirectory(APP_ID, plan.stagedBundleDirectory()))
        .thenThrow(new AppHostException("app is not installed: " + APP_ID));
    service.stage(APP_ID);

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class, () -> service.apply(APP_ID, APPLY_NO_RESTART_NO_HEALTH));

    assertEquals(404, exception.statusCode());
    assertEquals(APP_NOT_FOUND, exception.errorCode());
    Map<String, Object> summary = service.summary(APP_ID);
    assertEquals(false, ((Map<?, ?>) summary.get(STAGED)).get(AVAILABLE));
    assertEquals("none", ((Map<?, ?>) summary.get(CANDIDATE)).get(STATUS));
    assertFalse(Files.exists(plan.scratchDirectory()));
  }

  @Test
  void apply_whenAppHostRejectsStagedBundle_expectInvalidBundleNotServerError() throws Exception {
    AppUpdateService service =
        serviceWithInstalled(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    AppCatalogEntry entry = entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID)).thenReturn(List.of(entry));
    AppCatalogInstallPlan plan = plan(entry);
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID)).thenReturn(plan);
    when(appHost.updateFromDirectory(APP_ID, plan.stagedBundleDirectory()))
        .thenThrow(new AppManifestException("copied manifest is invalid"));
    service.stage(APP_ID);

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class, () -> service.apply(APP_ID, APPLY_NO_RESTART_NO_HEALTH));

    assertEquals(400, exception.statusCode());
    assertEquals("invalid_app_bundle", exception.errorCode());
    Map<String, Object> summary = service.summary(APP_ID);
    assertEquals(false, ((Map<?, ?>) summary.get(STAGED)).get(AVAILABLE));
    assertEquals("none", ((Map<?, ?>) summary.get(CANDIDATE)).get(STATUS));
    assertFalse(Files.exists(plan.scratchDirectory()));
  }

  @Test
  void check_whenPolicyApplyWhenStoppedAndReviewRequiresCaution_expectAutoApplyBlocked()
      throws Exception {
    AppUpdateService service =
        serviceWithInstalled(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID))
        .thenReturn(
            List.of(
                entry(UPDATE_VERSION, AppCatalogReviewStatus.CAUTION, compatibleApiMetadata())));
    service.setPolicy(APP_ID, AppUpdatePolicyMode.APPLY_WHEN_STOPPED);

    Map<String, Object> summary = service.check(APP_ID, false);

    Map<String, Object> candidate = (Map<String, Object>) summary.get(CANDIDATE);
    assertEquals(AVAILABLE, candidate.get(STATUS));
    assertEquals(false, candidate.get("autoApplyAllowed"));
    assertEquals(false, ((Map<?, ?>) summary.get(STAGED)).get(AVAILABLE));
    verifyNoInstallPlanPreparation();
    verify(appHost, never()).updateFromDirectory(any(), any());
  }

  @Test
  void check_whenPolicyApplyWhenStoppedRequiresTrustedReview_expectPublisherOnlyReviewBlocked()
      throws Exception {
    AppUpdateService service =
        serviceWithInstalled(
            INSTALLED_VERSION,
            List.of(QUEUE_READ_PERMISSION),
            new AppReviewPolicy(AppReviewPolicyMode.REQUIRE_TRUSTED_REVIEW_FOR_APPLY_WHEN_STOPPED),
            TrustedReviewerKeys::empty);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID))
        .thenReturn(
            List.of(
                entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED, compatibleApiMetadata())));
    service.setPolicy(APP_ID, AppUpdatePolicyMode.APPLY_WHEN_STOPPED);

    Map<String, Object> summary = service.check(APP_ID, false);

    Map<String, Object> candidate = (Map<String, Object>) summary.get(CANDIDATE);
    Map<String, Object> reviewTrust = (Map<String, Object>) candidate.get("reviewTrust");
    Map<String, Object> historyEntry =
        ((List<Map<String, Object>>) summary.get("history"))
            .stream()
                .filter(entry -> "apply".equals(entry.get("action")))
                .findFirst()
                .orElseThrow();
    assertEquals(AVAILABLE, candidate.get(STATUS));
    assertEquals(false, candidate.get("autoStageAllowed"));
    assertEquals(false, candidate.get("autoApplyAllowed"));
    assertEquals(true, candidate.get("blocksAutoUpdate"));
    assertEquals(true, candidate.get(OPERATOR_ACTION_REQUIRED));
    assertEquals(List.of("review_trust_delta"), candidate.get("materialConsentReasons"));
    assertEquals("publisher_claim_only", reviewTrust.get(STATUS));
    assertEquals(true, reviewTrust.get("blocksPolicyApply"));
    assertEquals("app_review_missing", historyEntry.get(ERROR_CODE));
    assertEquals(false, ((Map<?, ?>) summary.get(STAGED)).get(AVAILABLE));
    verifyNoInstallPlanPreparation();
    verify(appHost, never()).updateFromDirectory(any(), any());
  }

  @Test
  void check_whenStableAppRangeExcludes10Baseline_expectCandidateIncompatible() throws Exception {
    InstalledAppSnapshot installed = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installed));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    KeyPair reviewerKeyPair = reviewerKeyPair();
    AppUpdateService service =
        new AppUpdateService(
            appHost,
            catalogManager,
            AppReviewPolicy.DEFAULT,
            () -> trustedReviewerKeys(reviewerKeyPair));
    AppApiCompatibilityMetadata newerThanTested =
        new AppApiCompatibilityMetadata(1, 1, List.of(), TargetStability.STABLE, false);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID))
        .thenReturn(
            List.of(reviewedUpdateEntryWithTrustedReceipt(newerThanTested, reviewerKeyPair)));
    service.setPolicy(APP_ID, AppUpdatePolicyMode.APPLY_WHEN_STOPPED);

    Map<String, Object> summary = service.check(APP_ID, false);

    Map<String, Object> candidate = (Map<String, Object>) summary.get(CANDIDATE);
    assertEquals("incompatible", candidate.get(STATUS));
    assertEquals(false, candidate.get("autoApplyAllowed"));
    assertEquals("incompatible", ((Map<?, ?>) candidate.get("apiCompatibility")).get(STATUS));
    assertEquals(false, ((Map<?, ?>) summary.get(STAGED)).get(AVAILABLE));
    verifyNoInstallPlanPreparation();
    verify(appHost, never()).updateFromDirectory(any(), any());
  }

  @Test
  void check_whenPolicyApplyWhenStoppedAndAppRunning_expectApplySkipped() throws Exception {
    InstalledAppSnapshot installed = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installed));
    when(appHost.status(APP_ID)).thenReturn(Optional.of(running(installed)));
    AppUpdateService service = new AppUpdateService(appHost, catalogManager);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID))
        .thenReturn(
            List.of(
                entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED, compatibleApiMetadata())));
    service.setPolicy(APP_ID, AppUpdatePolicyMode.APPLY_WHEN_STOPPED);

    Map<String, Object> summary = service.check(APP_ID, false);

    assertEquals(false, ((Map<?, ?>) summary.get(STAGED)).get(AVAILABLE));
    assertEquals(true, ((Map<?, ?>) summary.get(CANDIDATE)).get("running"));
    verify(appHost, never()).updateFromDirectory(any(), any());
  }

  @Test
  void summary_whenRollbackRecordExists_expectPathFreeRollbackSummary() throws Exception {
    AppUpdateService service = serviceWithInstalled(UPDATE_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.rollbackStatus(APP_ID))
        .thenReturn(Optional.of(new AppRollbackRecord(APP_ID, APP_NAME, INSTALLED_VERSION)));

    Map<String, Object> summary = service.summary(APP_ID);

    Map<String, Object> rollback = (Map<String, Object>) summary.get(ROLLBACK);
    assertEquals(true, rollback.get(AVAILABLE));
    assertEquals(INSTALLED_VERSION, rollback.get("previousVersion"));
    assertEquals("bundle_only", rollback.get("scope"));
    assertFalse(summary.toString().contains(tempDir.toString()));
    assertFalse(summary.toString().contains("secret-token"));
  }

  @Test
  void summary_whenRollbackStatusFails_expectPathFreeFailureSummary() throws Exception {
    AppUpdateService service = serviceWithInstalled(UPDATE_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.rollbackStatus(APP_ID)).thenThrow(new IOException("bad rollback path"));

    Map<String, Object> summary = service.summary(APP_ID);

    Map<String, Object> rollback = (Map<String, Object>) summary.get(ROLLBACK);
    assertEquals(false, rollback.get(AVAILABLE));
    assertEquals(FAILED, rollback.get(STATUS));
    assertEquals(ROLLBACK_FAILED, rollback.get(ERROR_CODE));
    assertEquals("Rollback state could not be inspected.", rollback.get(MESSAGE));
    assertFalse(summary.toString().contains("bad rollback path"));
    assertFalse(summary.toString().contains(tempDir.toString()));
  }

  @Test
  void summary_whenSchedulerProviderConfigured_expectSchedulerSummaryReflected() throws Exception {
    AppUpdateService service = serviceWithInstalled(UPDATE_VERSION, List.of(QUEUE_READ_PERMISSION));
    service.setSchedulerSummaryProvider(
        appId ->
            Map.of(
                "appId",
                appId,
                "enabled",
                true,
                STATUS,
                "success",
                "lastCheckAt",
                "2026-05-12T00:00:00Z",
                "nextCheckAt",
                "2026-05-12T01:00:00Z",
                "lastResult",
                "success",
                "concurrency",
                "per-app-serialized"));

    Map<String, Object> summary = service.summary(APP_ID);

    Map<String, Object> scheduler = (Map<String, Object>) summary.get("scheduler");
    assertEquals(true, scheduler.get("enabled"));
    assertEquals("success", scheduler.get(STATUS));
    assertEquals("2026-05-12T00:00:00Z", scheduler.get("lastCheckAt"));
    assertEquals("2026-05-12T01:00:00Z", scheduler.get("nextCheckAt"));
    assertEquals("per-app-serialized", scheduler.get("concurrency"));
    assertFalse(summary.toString().contains(tempDir.toString()));
    assertFalse(summary.toString().contains("secret-token"));
  }

  @Test
  void rollback_whenLegacyHostHasNoCatalogOrigin_expectLegacyDispatchWithoutDescribePreflight()
      throws Exception {
    InstalledAppSnapshot rolledBack = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    when(appHost.rollbackRequiresCatalogAuthorization(APP_ID)).thenReturn(false);
    when(appHost.rollback(APP_ID)).thenReturn(rolledBack);
    AppUpdateService service = new AppUpdateService(appHost, catalogManager);

    Map<String, Object> summary = service.rollback(APP_ID, false);

    assertEquals(INSTALLED_VERSION, summary.get(INSTALLED_VERSION_FIELD));
    verify(appHost).rollback(APP_ID);
    verify(appHost, never()).rollback(eq(APP_ID), any(AppHost.CatalogRollbackAuthorization.class));
    verify(appHost, never()).describe(APP_ID);
  }

  @Test
  void rollback_whenRestartFailsAfterRestore_expectStateCleanedAndRestartFailureReported()
      throws Exception {
    InstalledAppSnapshot installed = installed(UPDATE_VERSION, List.of(QUEUE_READ_PERMISSION));
    InstalledAppSnapshot rolledBack = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.describe(APP_ID))
        .thenReturn(Optional.of(installed), Optional.of(installed), Optional.of(rolledBack));
    when(appHost.status(APP_ID))
        .thenReturn(
            Optional.empty(), Optional.empty(), Optional.of(running(installed)), Optional.empty());
    when(appHost.rollbackStatus(APP_ID))
        .thenReturn(Optional.of(new AppRollbackRecord(APP_ID, APP_NAME, INSTALLED_VERSION)));
    AppUpdateService service = new AppUpdateService(appHost, catalogManager);
    AppCatalogEntry entry = entry(EXTERNAL_VERSION, AppCatalogReviewStatus.REVIEWED);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID)).thenReturn(List.of(entry));
    AppCatalogInstallPlan plan = plan(entry);
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID)).thenReturn(plan);
    when(appHost.rollback(APP_ID)).thenReturn(rolledBack);
    when(appHost.start(APP_ID)).thenThrow(new IOException("restart failed"));
    service.stage(APP_ID);

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> service.rollback(APP_ID, true));

    assertEquals(500, exception.statusCode());
    assertEquals("rollback_restart_failed", exception.errorCode());
    Map<String, Object> summary = service.summary(APP_ID);
    assertEquals(false, ((Map<?, ?>) summary.get(STAGED)).get(AVAILABLE));
    assertEquals("none", ((Map<?, ?>) summary.get(CANDIDATE)).get(STATUS));
    assertFalse(Files.exists(plan.scratchDirectory()));
    verify(appHost).stop(APP_ID);
    verify(appHost).start(APP_ID);
  }

  @Test
  void rollback_whenRestoredBaselineIsUnsupported_expectBundleRemainsStopped() throws Exception {
    InstalledAppSnapshot installed = installed(UPDATE_VERSION, List.of(QUEUE_READ_PERMISSION));
    InstalledAppSnapshot rolledBack =
        installedWithApiMetadata(List.of(QUEUE_READ_PERMISSION), unsupportedBaselineApiMetadata());
    when(appHost.status(APP_ID)).thenReturn(Optional.of(running(installed)));
    when(appHost.rollbackStatus(APP_ID))
        .thenReturn(Optional.of(new AppRollbackRecord(APP_ID, APP_NAME, INSTALLED_VERSION)));
    when(appHost.rollback(APP_ID)).thenReturn(rolledBack);
    AppUpdateService service = new AppUpdateService(appHost, catalogManager);

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> service.rollback(APP_ID, true));

    assertEquals(409, exception.statusCode());
    assertEquals("unsupported_platform_api_baseline", exception.errorCode());
    verify(appHost).stop(APP_ID);
    verify(appHost).rollback(APP_ID);
    verify(appHost, never()).start(APP_ID);
  }

  @Test
  void rollback_whenStoppedAppUsesRestartFlag_expectBundleRestoredWithoutStart() throws Exception {
    InstalledAppSnapshot rolledBack = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    when(appHost.rollback(APP_ID)).thenReturn(rolledBack);
    AppUpdateService service = new AppUpdateService(appHost, catalogManager);

    Map<String, Object> summary = service.rollback(APP_ID, true);

    assertEquals(INSTALLED_VERSION, summary.get(INSTALLED_VERSION_FIELD));
    verify(appHost, never()).stop(APP_ID);
    verify(appHost, never()).start(APP_ID);
  }

  @Test
  void rollback_whenRunningAppHasNoRecord_expectUnavailableWithoutStop() throws Exception {
    InstalledAppSnapshot installed = installed(UPDATE_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.status(APP_ID)).thenReturn(Optional.of(running(installed)));
    when(appHost.rollbackStatus(APP_ID)).thenReturn(Optional.empty());
    AppUpdateService service = new AppUpdateService(appHost, catalogManager);

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> service.rollback(APP_ID, true));

    assertEquals(404, exception.statusCode());
    assertEquals("rollback_not_available", exception.errorCode());
    verify(appHost, never()).stop(APP_ID);
    verify(appHost, never()).rollback(eq(APP_ID), any(AppHost.CatalogRollbackAuthorization.class));
    verify(appHost, never()).start(APP_ID);
  }

  @Test
  void rollback_whenRunningAppRollbackStatusFails_expectFailureWithoutStop() throws Exception {
    InstalledAppSnapshot installed = installed(UPDATE_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.status(APP_ID)).thenReturn(Optional.of(running(installed)));
    when(appHost.rollbackStatus(APP_ID)).thenThrow(new IOException(ROLLBACK_MANIFEST_BROKEN));
    AppUpdateService service = new AppUpdateService(appHost, catalogManager);

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> service.rollback(APP_ID, true));

    assertEquals(ROLLBACK_FAILED, exception.errorCode());
    assertEquals(500, exception.statusCode());
    verify(appHost, never()).stop(APP_ID);
    verify(appHost, never()).rollback(eq(APP_ID), any(AppHost.CatalogRollbackAuthorization.class));
    verify(appHost, never()).start(APP_ID);
  }

  @Test
  void rollback_whenRollbackRecordCannotBeRestored_expectFailureNotUnavailable() throws Exception {
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    when(appHost.rollback(APP_ID)).thenThrow(new IOException(ROLLBACK_MANIFEST_BROKEN));
    AppUpdateService service = new AppUpdateService(appHost, catalogManager);

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> service.rollback(APP_ID, false));

    assertEquals(ROLLBACK_FAILED, exception.errorCode());
    assertEquals(500, exception.statusCode());
    verify(appHost).rollback(APP_ID);
  }

  @Test
  void rollback_whenRetainedBundleVerificationFails_expectTypedConflictWithoutPrivateDetails()
      throws Exception {
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    when(appHost.rollbackRequiresCatalogAuthorization(APP_ID)).thenReturn(true);
    when(appHost.rollback(eq(APP_ID), any(AppHost.CatalogRollbackAuthorization.class)))
        .thenThrow(
            new AppBundleVerificationException(
                "private-verification-canary /private/operator/bundle"));
    AppUpdateService service = new AppUpdateService(appHost, catalogManager);

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> service.rollback(APP_ID, false));

    assertEquals(409, exception.statusCode());
    assertEquals("rollback_bundle_verification_failed", exception.errorCode());
    assertEquals("Retained app bundle verification blocks rollback.", exception.getMessage());
    verify(appHost).rollback(eq(APP_ID), any(AppHost.CatalogRollbackAuthorization.class));
    verify(appHost, never()).rollback(APP_ID);
    verify(appHost, never()).stop(APP_ID);
    verify(appHost, never()).start(APP_ID);
  }

  @Test
  void rollback_whenFederatedOriginIsNoLongerAuthorized_expectTrustConflict() throws Exception {
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    when(appHost.rollbackRequiresCatalogAuthorization(APP_ID)).thenReturn(true);
    when(appHost.rollback(eq(APP_ID), any(AppHost.CatalogRollbackAuthorization.class)))
        .thenThrow(new AppHostException.CatalogRollbackAuthorizationException());
    AppUpdateService service = new AppUpdateService(appHost, catalogManager);

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> service.rollback(APP_ID, false));

    assertEquals(409, exception.statusCode());
    assertEquals("catalog_rollback_trust_blocked", exception.errorCode());
    verify(appHost).rollback(eq(APP_ID), any(AppHost.CatalogRollbackAuthorization.class));
    verify(appHost, never()).rollback(APP_ID);
  }

  @Test
  void rollback_whenFederationIsDisabledButRetainedOriginExists_expectTrustConflict()
      throws Exception {
    InstalledAppOrigin rollbackOrigin = installedOrigin(CATALOG_ID);
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    when(appHost.rollbackRequiresCatalogAuthorization(APP_ID)).thenReturn(true);
    when(appHost.rollback(eq(APP_ID), any(AppHost.CatalogRollbackAuthorization.class)))
        .thenAnswer(
            invocation -> {
              AppHost.CatalogRollbackAuthorization authorization = invocation.getArgument(1);
              try (var _ = authorization.authorize(rollbackOrigin)) {
                return installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
              }
            });
    AppUpdateService service = new AppUpdateService(appHost, catalogManager);

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> service.rollback(APP_ID, false));

    assertEquals(409, exception.statusCode());
    assertEquals("catalog_rollback_trust_blocked", exception.errorCode());
    verify(appHost).rollback(eq(APP_ID), any(AppHost.CatalogRollbackAuthorization.class));
    verify(appHost, never()).rollback(APP_ID);
  }

  @Test
  void rollback_whenCurrentReviewerScopeRejectsRetainedOrigin_expectNoRestore() throws Exception {
    KeyPair reviewerKeyPair = reviewerKeyPair();
    AppCatalogEntry retainedEntry =
        reviewedUpdateEntryWithTrustedReceipt(compatibleApiMetadata(), reviewerKeyPair);
    String receiptFingerprint = retainedEntry.reviewReceipt().orElseThrow().fingerprintSha256();
    InstalledAppOrigin rollbackOrigin =
        InstalledAppOrigin.create(
            APP_ID,
            retainedEntry.version(),
            retainedEntry.bundleSha256(),
            CATALOG_ID,
            "catalog-key",
            DIGEST,
            DIGEST,
            "publisher-key",
            DIGEST,
            DIGEST,
            receiptFingerprint,
            "trusted_reviewed",
            "binding-1",
            DIGEST,
            DIGEST,
            DIGEST,
            Instant.parse("2026-05-01T00:00:00Z"),
            null);
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    AppCatalogManager.CatalogTrustAuthorization catalogAuthorization = mock();
    when(catalogManager.authorizeHistoricalAppOriginForRollback(any(), any(), any(), any()))
        .thenReturn(
            new AppCatalogManager.HistoricalAppOriginAuthorization(
                retainedEntry, catalogAuthorization));
    FileFederatedCatalogTrustStore trustStore = mock(FileFederatedCatalogTrustStore.class);
    FileCatalogPublisherBindingStore publisherStore = mock(FileCatalogPublisherBindingStore.class);
    FileFederatedCatalogConflictResolutionStore resolutionStore =
        mock(FileFederatedCatalogConflictResolutionStore.class);
    FederatedCatalogTrustBinding catalogBinding = mock(FederatedCatalogTrustBinding.class);
    when(catalogBinding.publisherPolicyDigest()).thenReturn(Optional.of(DIGEST));
    when(trustStore.findByCatalogId(CATALOG_ID)).thenReturn(Optional.of(catalogBinding));
    FileCatalogPublisherBindingStore.AuthorizationLease publisherAuthorization = mock();
    when(publisherStore.retainHistoricalAuthorization(
            any(), any(), any(), any(), any(), any(), any()))
        .thenReturn(publisherAuthorization);
    CatalogScopedReviewerPolicy scopedPolicy = mock(CatalogScopedReviewerPolicy.class);
    AppReviewTrustDecision trustedDecision =
        AppReviewReceiptVerifier.evaluate(
            retainedEntry,
            trustedReviewerKeys(reviewerKeyPair),
            AppReviewPolicy.DEFAULT,
            Instant.now());
    when(scopedPolicy.retainHistoricalAuthorization(any(), any(), any(), any(), any()))
        .thenReturn(
            new CatalogScopedReviewerPolicy.HistoricalAuthorization(
                new CatalogScopedReviewerPolicy.Verification(
                    trustedDecision, false, "scope-1", DIGEST, DIGEST, "reviewer_scope_rejected"),
                TrustedReviewerKeys.empty(),
                () -> {}));
    when(appHost.rollbackRequiresCatalogAuthorization(APP_ID)).thenReturn(true);
    when(appHost.rollback(eq(APP_ID), any(AppHost.CatalogRollbackAuthorization.class)))
        .thenAnswer(
            invocation -> {
              AppHost.CatalogRollbackAuthorization authorization = invocation.getArgument(1);
              try (var _ = authorization.authorize(rollbackOrigin)) {
                return installed(retainedEntry.version(), List.of(QUEUE_READ_PERMISSION));
              }
            });
    AppUpdateService service = new AppUpdateService(appHost, catalogManager);
    service.setFederatedCatalogConflictPolicy(
        new AppUpdateFederationAuthority(trustStore, publisherStore, resolutionStore));
    service.setCatalogScopedReviewerPolicy(scopedPolicy);

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> service.rollback(APP_ID, false));

    assertEquals(409, exception.statusCode());
    assertEquals("catalog_rollback_trust_blocked", exception.errorCode());
    verify(appHost).rollback(eq(APP_ID), any(AppHost.CatalogRollbackAuthorization.class));
    verify(publisherAuthorization).close();
    verify(catalogAuthorization).close();
  }

  @Test
  void rollback_whenHistoricalPublisherRejects_expectCatalogAuthorizationReleased()
      throws Exception {
    AppCatalogEntry retainedEntry = entry(INSTALLED_VERSION, AppCatalogReviewStatus.REVIEWED);
    InstalledAppOrigin rollbackOrigin = installedOrigin(CATALOG_ID);
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    AppCatalogManager.CatalogTrustAuthorization catalogAuthorization = mock();
    when(catalogManager.authorizeHistoricalAppOriginForRollback(any(), any(), any(), any()))
        .thenReturn(
            new AppCatalogManager.HistoricalAppOriginAuthorization(
                retainedEntry, catalogAuthorization));
    FileFederatedCatalogTrustStore trustStore = mock(FileFederatedCatalogTrustStore.class);
    FileCatalogPublisherBindingStore publisherStore = mock(FileCatalogPublisherBindingStore.class);
    FileFederatedCatalogConflictResolutionStore resolutionStore =
        mock(FileFederatedCatalogConflictResolutionStore.class);
    FederatedCatalogTrustBinding catalogBinding = mock(FederatedCatalogTrustBinding.class);
    when(catalogBinding.publisherPolicyDigest()).thenReturn(Optional.of(DIGEST));
    when(trustStore.findByCatalogId(CATALOG_ID)).thenReturn(Optional.of(catalogBinding));
    when(publisherStore.retainHistoricalAuthorization(
            any(), any(), any(), any(), any(), any(), any()))
        .thenThrow(new IOException("historical publisher is revoked"));
    when(appHost.rollbackRequiresCatalogAuthorization(APP_ID)).thenReturn(true);
    when(appHost.rollback(eq(APP_ID), any(AppHost.CatalogRollbackAuthorization.class)))
        .thenAnswer(
            invocation -> {
              AppHost.CatalogRollbackAuthorization authorization = invocation.getArgument(1);
              try (var _ = authorization.authorize(rollbackOrigin)) {
                return installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
              }
            });
    AppUpdateService service = new AppUpdateService(appHost, catalogManager);
    service.setFederatedCatalogConflictPolicy(
        new AppUpdateFederationAuthority(trustStore, publisherStore, resolutionStore));

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> service.rollback(APP_ID, false));

    assertEquals(409, exception.statusCode());
    assertEquals("catalog_rollback_trust_blocked", exception.errorCode());
    verify(catalogAuthorization).close();
  }

  @Test
  void rollback_whenScopedPoliciesAuthorize_expectAllLeasesRetainedThroughHostCommit()
      throws Exception {
    KeyPair reviewerKeyPair = reviewerKeyPair();
    AppCatalogEntry retainedEntry =
        reviewedUpdateEntryWithTrustedReceipt(compatibleApiMetadata(), reviewerKeyPair);
    InstalledAppOrigin rollbackOrigin =
        InstalledAppOrigin.create(
            APP_ID,
            retainedEntry.version(),
            retainedEntry.bundleSha256(),
            CATALOG_ID,
            "catalog-key",
            DIGEST,
            DIGEST,
            "publisher-key",
            DIGEST,
            DIGEST,
            retainedEntry.reviewReceipt().orElseThrow().fingerprintSha256(),
            "trusted_reviewed",
            "binding-1",
            DIGEST,
            DIGEST,
            DIGEST,
            Instant.parse("2026-05-01T00:00:00Z"),
            null);
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    AppCatalogManager.CatalogTrustAuthorization catalogAuthorization = mock();
    when(catalogManager.authorizeHistoricalAppOriginForRollback(any(), any(), any(), any()))
        .thenReturn(
            new AppCatalogManager.HistoricalAppOriginAuthorization(
                retainedEntry, catalogAuthorization));
    FileFederatedCatalogTrustStore trustStore = mock(FileFederatedCatalogTrustStore.class);
    FileCatalogPublisherBindingStore publisherStore = mock(FileCatalogPublisherBindingStore.class);
    FileFederatedCatalogConflictResolutionStore resolutionStore =
        mock(FileFederatedCatalogConflictResolutionStore.class);
    FederatedCatalogTrustBinding catalogBinding = mock(FederatedCatalogTrustBinding.class);
    when(catalogBinding.publisherPolicyDigest()).thenReturn(Optional.of(DIGEST));
    when(trustStore.findByCatalogId(CATALOG_ID)).thenReturn(Optional.of(catalogBinding));
    FileCatalogPublisherBindingStore.AuthorizationLease publisherAuthorization = mock();
    when(publisherStore.retainHistoricalAuthorization(
            any(), any(), any(), any(), any(), any(), any()))
        .thenReturn(publisherAuthorization);
    CatalogScopedReviewerPolicy scopedPolicy = mock(CatalogScopedReviewerPolicy.class);
    AppReviewTrustDecision trustedDecision =
        AppReviewReceiptVerifier.evaluate(
            retainedEntry,
            trustedReviewerKeys(reviewerKeyPair),
            AppReviewPolicy.DEFAULT,
            Instant.now());
    network.crypta.platform.appcatalog.FileCatalogReviewerScopeStore.AuthorizationLease
        reviewerScopeAuthorization = mock();
    when(scopedPolicy.retainHistoricalAuthorization(any(), any(), any(), any(), any()))
        .thenReturn(
            new CatalogScopedReviewerPolicy.HistoricalAuthorization(
                new CatalogScopedReviewerPolicy.Verification(
                    trustedDecision, true, "scope-1", DIGEST, DIGEST, "authorized"),
                trustedReviewerKeys(reviewerKeyPair),
                reviewerScopeAuthorization));
    when(appHost.rollbackRequiresCatalogAuthorization(APP_ID)).thenReturn(true);
    when(appHost.rollback(eq(APP_ID), any(AppHost.CatalogRollbackAuthorization.class)))
        .thenAnswer(
            invocation -> {
              AppHost.CatalogRollbackAuthorization authorization = invocation.getArgument(1);
              AppHost.CatalogMutationAuthorizationLease lease =
                  authorization.authorize(rollbackOrigin);
              verify(catalogAuthorization, never()).close();
              verify(publisherAuthorization, never()).close();
              verify(reviewerScopeAuthorization, never()).close();
              lease.close();
              return installed(retainedEntry.version(), List.of(QUEUE_READ_PERMISSION));
            });
    AppUpdateService service = new AppUpdateService(appHost, catalogManager);
    service.setFederatedCatalogConflictPolicy(
        new AppUpdateFederationAuthority(trustStore, publisherStore, resolutionStore));
    service.setCatalogScopedReviewerPolicy(scopedPolicy);

    Map<String, Object> summary = service.rollback(APP_ID, false);

    assertEquals(retainedEntry.version(), summary.get(INSTALLED_VERSION_FIELD));
    verify(reviewerScopeAuthorization).close();
    verify(publisherAuthorization).close();
    verify(catalogAuthorization).close();
  }

  @Test
  void rollback_whenAppStartsBeforeRestore_expectConflictNotServerError() throws Exception {
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    when(appHost.rollback(APP_ID))
        .thenThrow(new AppHostException("cannot rollback a running app: " + APP_ID));
    AppUpdateService service = new AppUpdateService(appHost, catalogManager);

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> service.rollback(APP_ID, false));

    assertEquals(409, exception.statusCode());
    assertEquals("rollback_app_running", exception.errorCode());
  }

  @Test
  void rollback_whenAppIsUninstalledBeforeRestore_expectNotFoundNotServerError() throws Exception {
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    when(appHost.rollback(APP_ID))
        .thenThrow(new AppHostException("app is not installed: " + APP_ID));
    AppUpdateService service = new AppUpdateService(appHost, catalogManager);

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> service.rollback(APP_ID, false));

    assertEquals(404, exception.statusCode());
    assertEquals(APP_NOT_FOUND, exception.errorCode());
  }

  @Test
  void rollback_whenRecordIsRemovedBeforeRestore_expectUnavailableNotServerError()
      throws Exception {
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    when(appHost.rollback(APP_ID))
        .thenThrow(new AppHostException("rollback record is not available: " + APP_ID));
    AppUpdateService service = new AppUpdateService(appHost, catalogManager);

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> service.rollback(APP_ID, false));

    assertEquals(404, exception.statusCode());
    assertEquals("rollback_not_available", exception.errorCode());
  }

  @Test
  void stage_whenSchemaIncreaseHasNoMigrationStep_expectBlockedBeforeBundleReplacement()
      throws Exception {
    InstalledAppSnapshot installed = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installed));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    AppDataService appDataService = appDataServiceWithFeedRecord();
    AppUpdateService service =
        serviceWithAppData(
            appDataService,
            (_, _, _, _) -> AppDataMigrationRunner.MigrationExecutionResult.passed());
    AppCatalogEntry entry =
        entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED, compatibleApiMetadata());
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID)).thenReturn(List.of(entry));
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID))
        .thenReturn(planWithAppDataMigration(entry, true, false));

    service.check(APP_ID, false);
    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> service.stage(APP_ID));

    assertEquals("app_data_migration_missing", exception.errorCode());
    verify(appHost, never()).updateFromDirectory(any(), any());
    Map<String, Object> candidate = (Map<String, Object>) service.summary(APP_ID).get(CANDIDATE);
    Map<String, Object> migration = (Map<String, Object>) candidate.get("dataMigration");
    assertEquals("missing_migration", migration.get(STATUS));
    assertEquals("app_data_migration_missing", migration.get("blockReason"));
  }

  @Test
  void stage_whenTargetDeclaresNewNamespaceWithoutDurableData_expectNoMigrationRequired()
      throws Exception {
    InstalledAppSnapshot installed = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installed));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    AtomicBoolean runnerCalled = new AtomicBoolean(false);
    AppUpdateService service =
        serviceWithAppData(
            appDataServiceWithUiStateRecord(),
            (_, _, _, _) -> {
              runnerCalled.set(true);
              return AppDataMigrationRunner.MigrationExecutionResult.passed();
            });
    AppCatalogEntry entry =
        entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED, compatibleApiMetadata());
    AppCatalogInstallPlan plan = planWithAppDataMigration(entry, true, true);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID)).thenReturn(List.of(entry));
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID)).thenReturn(plan);

    service.check(APP_ID, false);
    Map<String, Object> stagedSummary = service.stage(APP_ID);

    assertFalse(runnerCalled.get());
    Map<String, Object> staged = (Map<String, Object>) stagedSummary.get(STAGED);
    assertEquals("not_required", ((Map<?, ?>) staged.get("dataMigration")).get(STATUS));
    verify(appHost, never()).updateFromDirectory(any(), any());
  }

  @Test
  void stage_whenMigrationPlanningFails_expectPreparedPlanClosed() throws Exception {
    InstalledAppSnapshot installed = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installed));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    AppDataStore store = mock(AppDataStore.class);
    when(store.listNamespaces(APP_ID)).thenThrow(new IOException("store unavailable"));
    AppDataService appDataService =
        new AppDataService(
            store,
            null,
            new AppDataStoreConfig(1024, 16, 4, 8192, 8192, 8),
            java.time.Clock.fixed(Instant.parse("2026-05-03T00:00:00Z"), java.time.ZoneOffset.UTC),
            new AppDiskUsageScanner());
    AppUpdateService service =
        serviceWithAppData(
            appDataService,
            (_, _, _, _) -> AppDataMigrationRunner.MigrationExecutionResult.passed());
    AppCatalogEntry entry =
        entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED, compatibleApiMetadata());
    AppCatalogInstallPlan plan = planWithAppDataMigration(entry, true, true);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID)).thenReturn(List.of(entry));
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID)).thenReturn(plan);

    service.check(APP_ID, false);
    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> service.stage(APP_ID));

    assertEquals("app_data_store_unavailable", exception.errorCode());
    assertFalse(Files.exists(plan.scratchDirectory()));
  }

  @Test
  void stage_whenStoppedRequiredMigrationAndAppRunning_expectBlockedBeforeDryRun()
      throws Exception {
    InstalledAppSnapshot installed = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installed));
    when(appHost.status(APP_ID)).thenReturn(Optional.of(running(installed)));
    AtomicBoolean runnerCalled = new AtomicBoolean(false);
    AppUpdateService service =
        serviceWithAppData(
            appDataServiceWithFeedRecord(),
            (_, _, _, _) -> {
              runnerCalled.set(true);
              return AppDataMigrationRunner.MigrationExecutionResult.passed();
            });
    AppCatalogEntry entry =
        entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED, compatibleApiMetadata());
    AppCatalogInstallPlan plan = planWithAppDataMigration(entry, true, true);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID)).thenReturn(List.of(entry));
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID)).thenReturn(plan);

    service.check(APP_ID, false);
    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> service.stage(APP_ID));

    assertEquals("app_data_migration_requires_stopped", exception.errorCode());
    assertFalse(runnerCalled.get());
    verify(appHost, never()).updateFromDirectory(any(), any());
    Map<String, Object> candidate = (Map<String, Object>) service.summary(APP_ID).get(CANDIDATE);
    Map<String, Object> migration = (Map<String, Object>) candidate.get("dataMigration");
    assertEquals("requires_stopped", migration.get(STATUS));
    assertEquals("app_data_migration_requires_stopped", migration.get("blockReason"));
    assertFalse(Files.exists(plan.scratchDirectory()));
  }

  @Test
  void check_whenPolicyStageAndStoppedRequiredMigrationRunning_expectCandidateSummary()
      throws Exception {
    InstalledAppSnapshot installed = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installed));
    when(appHost.status(APP_ID)).thenReturn(Optional.of(running(installed)));
    AtomicBoolean runnerCalled = new AtomicBoolean(false);
    KeyPair reviewerKeyPair = reviewerKeyPair();
    AppUpdateService service =
        serviceWithAppData(
            appDataServiceWithFeedRecord(),
            (_, _, _, _) -> {
              runnerCalled.set(true);
              return AppDataMigrationRunner.MigrationExecutionResult.passed();
            },
            reviewerKeyPair);
    service.setPolicy(APP_ID, AppUpdatePolicyMode.STAGE);
    AppCatalogEntry entry =
        withTrustedReceipt(
            entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED, compatibleApiMetadata()),
            reviewerKeyPair);
    AppCatalogInstallPlan plan = planWithAppDataMigration(entry, true, true);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID)).thenReturn(List.of(entry));
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID)).thenReturn(plan);

    Map<String, Object> summary = service.check(APP_ID, false);

    assertFalse(runnerCalled.get());
    assertEquals(false, ((Map<?, ?>) summary.get(STAGED)).get(AVAILABLE));
    Map<String, Object> candidate = (Map<String, Object>) summary.get(CANDIDATE);
    Map<String, Object> migration = (Map<String, Object>) candidate.get("dataMigration");
    assertEquals("requires_stopped", migration.get(STATUS));
    assertEquals("app_data_migration_requires_stopped", migration.get("blockReason"));
  }

  @Test
  void apply_whenMigrationRequiredAndRunnerPasses_expectSnapshotApplyAndSchemaMetadata()
      throws Exception {
    InstalledAppSnapshot installed = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    InstalledAppSnapshot updated = installed(UPDATE_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installed));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    AppDataService appDataService = appDataServiceWithFeedRecord();
    List<AppDataMigrationRunner.Mode> modes = new java.util.ArrayList<>();
    AppUpdateService service =
        serviceWithAppData(appDataService, payloadRewritingMigrationRunner(modes));
    AppCatalogEntry entry =
        entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED, compatibleApiMetadata());
    AppCatalogInstallPlan plan = planWithAppDataMigration(entry, true, true);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID)).thenReturn(List.of(entry));
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID)).thenReturn(plan);
    when(appHost.updateFromDirectory(APP_ID, plan.stagedBundleDirectory())).thenReturn(updated);

    service.check(APP_ID, false);
    Map<String, Object> stagedSummary = service.stage(APP_ID);
    Map<String, Object> staged = (Map<String, Object>) stagedSummary.get(STAGED);
    assertEquals("ready", ((Map<?, ?>) staged.get("dataMigration")).get(STATUS));
    Map<String, Object> applied = service.apply(APP_ID, APPLY_NO_RESTART_NO_HEALTH);

    assertEquals(
        List.of(
            AppDataMigrationRunner.Mode.DRY_RUN,
            AppDataMigrationRunner.Mode.DRY_RUN,
            AppDataMigrationRunner.Mode.APPLY),
        modes);
    assertEquals(
        2, appDataService.listNamespaceMetadataForUpdate(APP_ID).getFirst().schemaVersion());
    Map<String, Object> candidate = (Map<String, Object>) applied.get(CANDIDATE);
    assertEquals("applied", ((Map<?, ?>) candidate.get("dataMigration")).get(STATUS));
  }

  @Test
  void stage_whenTargetManifestRaisesDataQuota_expectDryRunUsesTargetQuota() throws Exception {
    InstalledAppSnapshot installedForSeed =
        installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION), Long.MAX_VALUE);
    Files.createDirectories(installedForSeed.paths().dataDir());
    Files.createDirectories(installedForSeed.paths().cacheDir());
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installedForSeed));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    AppDataService appDataService = appDataServiceWithHostQuota();
    InstalledAppSnapshot installedWithOldQuota =
        installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION), 1L);
    Files.createDirectories(installedWithOldQuota.paths().dataDir());
    Files.createDirectories(installedWithOldQuota.paths().cacheDir());
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installedWithOldQuota));
    List<AppDataMigrationRunner.Mode> modes = new java.util.ArrayList<>();
    AppUpdateService service =
        serviceWithAppData(appDataService, payloadRewritingMigrationRunner(modes));
    AppCatalogEntry entry =
        entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED, compatibleApiMetadata());
    AppCatalogInstallPlan plan =
        planWithAppDataMigration(entry, true, true, "quota.data.bytes=65536\n");
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID)).thenReturn(List.of(entry));
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID)).thenReturn(plan);

    service.check(APP_ID, false);
    Map<String, Object> stagedSummary = service.stage(APP_ID);

    Map<String, Object> staged = (Map<String, Object>) stagedSummary.get(STAGED);
    assertEquals("ready", ((Map<?, ?>) staged.get("dataMigration")).get(STATUS));
    assertEquals(List.of(AppDataMigrationRunner.Mode.DRY_RUN), modes);
    verify(appHost, never()).updateFromDirectory(any(), any());
  }

  @Test
  void apply_whenAppDataWriteAttemptsDuringMigrationWindow_expectWriteRejectedAndBarrierReleased()
      throws Exception {
    InstalledAppSnapshot installed = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    InstalledAppSnapshot updated = installed(UPDATE_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installed));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    AppDataService appDataService = appDataServiceWithFeedRecord();
    List<String> rejectedWriteErrors = new java.util.ArrayList<>();
    List<AppDataMigrationRunner.Mode> modes = new java.util.ArrayList<>();
    AppUpdateService service =
        serviceWithAppData(
            appDataService,
            (_, plan, mode, dataAccess) -> {
              modes.add(mode);
              if (mode == AppDataMigrationRunner.Mode.APPLY) {
                PlatformApiException blocked =
                    assertThrows(
                        PlatformApiException.class, () -> putRecordDuringMigration(appDataService));
                rejectedWriteErrors.add(blocked.errorCode());
              }
              rewriteMigrationPayloads(plan, mode, dataAccess);
              return AppDataMigrationRunner.MigrationExecutionResult.passed();
            });
    AppCatalogEntry entry =
        entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED, compatibleApiMetadata());
    AppCatalogInstallPlan plan = planWithAppDataMigration(entry, true, true);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID)).thenReturn(List.of(entry));
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID)).thenReturn(plan);
    when(appHost.updateFromDirectory(APP_ID, plan.stagedBundleDirectory())).thenReturn(updated);

    service.check(APP_ID, false);
    service.stage(APP_ID);
    service.apply(APP_ID, APPLY_NO_RESTART_NO_HEALTH);

    assertEquals(
        List.of(
            AppDataMigrationRunner.Mode.DRY_RUN,
            AppDataMigrationRunner.Mode.DRY_RUN,
            AppDataMigrationRunner.Mode.APPLY),
        modes);
    assertEquals(List.of("app_data_migration_in_progress"), rejectedWriteErrors);
    appDataService.putRecord(
        APP_ID,
        Map.of(
            "namespace",
            List.of("feeds"),
            "key",
            List.of("after-migration"),
            "schemaVersion",
            List.of("2"),
            "contentType",
            List.of("application/json"),
            "valueText",
            List.of("{\"count\":3}")));
    assertEquals(
        2, appDataService.listNamespaceMetadataForUpdate(APP_ID).getFirst().schemaVersion());
  }

  @Test
  void apply_whenAppDataWriteAttemptsDuringFinalMigrationDryRun_expectWriteRejected()
      throws Exception {
    InstalledAppSnapshot installed = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    InstalledAppSnapshot updated = installed(UPDATE_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installed));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    AppDataService appDataService = appDataServiceWithFeedRecord();
    List<AppDataMigrationRunner.Mode> modes = new java.util.ArrayList<>();
    List<String> rejectedWriteErrors = new java.util.ArrayList<>();
    int[] dryRuns = {0};
    AppUpdateService service =
        serviceWithAppData(
            appDataService,
            (_, plan, mode, dataAccess) -> {
              modes.add(mode);
              if (mode == AppDataMigrationRunner.Mode.DRY_RUN && ++dryRuns[0] == 2) {
                try {
                  appDataService.putRecord(
                      APP_ID,
                      Map.of(
                          "namespace",
                          List.of("feeds"),
                          "key",
                          List.of("final-dry-run"),
                          "schemaVersion",
                          List.of("1"),
                          "contentType",
                          List.of("application/json"),
                          "valueText",
                          List.of("{\"during\":\"final-dry-run\"}")));
                } catch (PlatformApiException exception) {
                  rejectedWriteErrors.add(exception.errorCode());
                }
              }
              for (AppDataMigrationPlan.NamespaceStep step : plan.namespaces()) {
                AppDataMigrationRunner.StepDataFiles files = dataAccess.prepare(step, mode);
                rewriteSchemaPayload(
                    files.inputPayload(),
                    files.outputPayload(),
                    step.fromSchemaVersion(),
                    step.toSchemaVersion());
                dataAccess.complete(step, mode, files);
              }
              return AppDataMigrationRunner.MigrationExecutionResult.passed();
            });
    AppCatalogEntry entry =
        entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED, compatibleApiMetadata());
    AppCatalogInstallPlan plan = planWithAppDataMigration(entry, true, true);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID)).thenReturn(List.of(entry));
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID)).thenReturn(plan);
    when(appHost.updateFromDirectory(APP_ID, plan.stagedBundleDirectory())).thenReturn(updated);

    service.check(APP_ID, false);
    service.stage(APP_ID);
    Map<String, Object> applied = service.apply(APP_ID, APPLY_NO_RESTART_NO_HEALTH);

    assertEquals(
        List.of(
            AppDataMigrationRunner.Mode.DRY_RUN,
            AppDataMigrationRunner.Mode.DRY_RUN,
            AppDataMigrationRunner.Mode.APPLY),
        modes);
    assertEquals(List.of("app_data_migration_in_progress"), rejectedWriteErrors);
    assertThrows(
        PlatformApiException.class,
        () -> appDataService.getRecord(APP_ID, "feeds", "final-dry-run"));
    Map<String, Object> candidate = (Map<String, Object>) applied.get(CANDIDATE);
    assertEquals("applied", ((Map<?, ?>) candidate.get("dataMigration")).get(STATUS));
  }

  @Test
  void apply_whenReviewerScopeRevokedDuringFinalDryRun_expectNoBundleMutation() throws Exception {
    InstalledAppSnapshot installed = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installed));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    AppDataService appDataService = appDataServiceWithFeedRecord();
    AtomicBoolean reviewerRevoked = new AtomicBoolean();
    AtomicInteger dryRuns = new AtomicInteger();
    List<AppDataMigrationRunner.Mode> modes = new java.util.ArrayList<>();
    AppUpdateService service =
        serviceWithAppData(
            appDataService,
            (_, migrationPlan, mode, dataAccess) -> {
              modes.add(mode);
              rewriteMigrationPayloads(migrationPlan, mode, dataAccess);
              if (mode == AppDataMigrationRunner.Mode.DRY_RUN && dryRuns.incrementAndGet() == 2) {
                reviewerRevoked.set(true);
              }
              return AppDataMigrationRunner.MigrationExecutionResult.passed();
            });
    AppCatalogEntry entry =
        entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED, compatibleApiMetadata());
    AppReviewTrustDecision reviewDecision =
        AppReviewReceiptVerifier.evaluate(
            entry, TrustedReviewerKeys.empty(), AppReviewPolicy.DEFAULT, Instant.now());
    CatalogScopedReviewerPolicy scopedPolicy = mock(CatalogScopedReviewerPolicy.class);
    when(scopedPolicy.evaluate(any(), any(), any(), any(), any()))
        .thenAnswer(
            _ ->
                reviewerRevoked.get()
                    ? new CatalogScopedReviewerPolicy.Verification(
                        reviewDecision, false, "scope-1", DIGEST, DIGEST, "reviewer_scope_rejected")
                    : new CatalogScopedReviewerPolicy.Verification(
                        reviewDecision, true, "scope-1", DIGEST, DIGEST, "authorized"));
    service.setCatalogScopedReviewerPolicy(scopedPolicy);
    AppCatalogInstallPlan plan = planWithAppDataMigration(entry, true, true);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID)).thenReturn(List.of(entry));
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID)).thenReturn(plan);

    service.check(APP_ID, false);
    service.stage(APP_ID);
    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class, () -> service.apply(APP_ID, APPLY_NO_RESTART_NO_HEALTH));

    assertEquals(409, exception.statusCode());
    assertEquals("app_review_untrusted", exception.errorCode());
    assertEquals(
        List.of(AppDataMigrationRunner.Mode.DRY_RUN, AppDataMigrationRunner.Mode.DRY_RUN), modes);
    verify(appHost, never()).updateFromDirectory(any(), any());
    verify(appHost, never()).updateCatalogFromDirectory(any(), any(), any(), any(), any());
    assertFalse(Files.exists(plan.scratchDirectory()));
  }

  @Test
  void apply_whenStagedMigrationBundleVerificationFails_expectDryRunBlockedBeforeRunner()
      throws Exception {
    InstalledAppSnapshot installed = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installed));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    AppDataService appDataService = appDataServiceWithFeedRecord();
    List<AppDataMigrationRunner.Mode> modes = new java.util.ArrayList<>();
    AppUpdateService service =
        serviceWithAppData(appDataService, payloadRewritingMigrationRunner(modes));
    AppCatalogEntry entry =
        entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED, compatibleApiMetadata());
    AppCatalogInstallPlan plan = planWithAppDataMigration(entry, true, true);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID)).thenReturn(List.of(entry));
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID)).thenReturn(plan);

    service.check(APP_ID, false);
    service.stage(APP_ID);
    modes.clear();
    doThrow(new AppCatalogException("invalid_app_bundle", "staged bundle tampered"))
        .when(catalogManager)
        .verifyInstallPlan(plan);
    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class, () -> service.apply(APP_ID, APPLY_NO_RESTART_NO_HEALTH));

    assertEquals("invalid_app_bundle", exception.errorCode());
    assertTrue(modes.isEmpty());
    verify(appHost, never()).updateFromDirectory(any(), any());
    assertFalse(Files.exists(plan.scratchDirectory()));
  }

  @Test
  void apply_whenMigrationDryRunMutatesStagedBundle_expectReverifiedBeforeInstall()
      throws Exception {
    InstalledAppSnapshot installed = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installed));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    AppDataService appDataService = appDataServiceWithFeedRecord();
    List<AppDataMigrationRunner.Mode> modes = new java.util.ArrayList<>();
    AppUpdateService service =
        serviceWithAppData(appDataService, stagedBundleMutatingMigrationRunner(modes));
    AppCatalogEntry entry =
        entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED, compatibleApiMetadata());
    AppCatalogInstallPlan plan = planWithAppDataMigration(entry, true, true);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID)).thenReturn(List.of(entry));
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID)).thenReturn(plan);
    doNothing()
        .doNothing()
        .doThrow(new AppCatalogException("invalid_app_bundle", "staged bundle tampered"))
        .when(catalogManager)
        .verifyInstallPlan(plan);

    service.check(APP_ID, false);
    service.stage(APP_ID);
    modes.clear();
    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class, () -> service.apply(APP_ID, APPLY_NO_RESTART_NO_HEALTH));

    assertEquals("invalid_app_bundle", exception.errorCode());
    assertEquals(List.of(AppDataMigrationRunner.Mode.DRY_RUN), modes);
    verify(appHost, never()).updateFromDirectory(any(), any());
    assertFalse(Files.exists(plan.scratchDirectory()));
  }

  @Test
  void stage_whenStagedMigrationBundleVerificationFails_expectDryRunBlockedBeforeRunner()
      throws Exception {
    InstalledAppSnapshot installed = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installed));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    AppDataService appDataService = appDataServiceWithFeedRecord();
    List<AppDataMigrationRunner.Mode> modes = new java.util.ArrayList<>();
    AppUpdateService service =
        serviceWithAppData(appDataService, payloadRewritingMigrationRunner(modes));
    AppCatalogEntry entry =
        entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED, compatibleApiMetadata());
    AppCatalogInstallPlan plan = planWithAppDataMigration(entry, true, true);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID)).thenReturn(List.of(entry));
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID)).thenReturn(plan);
    service.check(APP_ID, false);
    doThrow(new AppCatalogException("invalid_app_bundle", "staged bundle tampered"))
        .when(catalogManager)
        .verifyInstallPlan(plan);

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> service.stage(APP_ID));

    assertEquals("invalid_app_bundle", exception.errorCode());
    assertTrue(modes.isEmpty());
    verify(appHost, never()).updateFromDirectory(any(), any());
    assertFalse(Files.exists(plan.scratchDirectory()));
  }

  @ParameterizedTest
  @ValueSource(strings = {"prepare", "verify", "consent"})
  void update_whenPublisherScopeRevoked_expectPolicyConflictBeforeMigration(String phase)
      throws Exception {
    InstalledAppSnapshot installed = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installed));
    lenient().when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    AppDataService appDataService = appDataServiceWithFeedRecord();
    List<AppDataMigrationRunner.Mode> modes = new java.util.ArrayList<>();
    AppUpdateService service =
        serviceWithAppData(appDataService, payloadRewritingMigrationRunner(modes));
    AppCatalogEntry entry =
        entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED, compatibleApiMetadata());
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID)).thenReturn(List.of(entry));
    service.check(APP_ID, false);
    AppCatalogInstallPlan plan = null;
    if (phase.equals("verify")) {
      plan = planWithAppDataMigration(entry, true, true);
      when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID)).thenReturn(plan);
      doThrow(new CatalogPublisherAuthorizationException())
          .when(catalogManager)
          .verifyInstallPlan(plan);
    } else {
      when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID))
          .thenThrow(new CatalogPublisherAuthorizationException());
    }

    PlatformApiException exception =
        phase.equals("consent")
            ? assertThrows(
                PlatformApiException.class, () -> service.previewForConsent(APP_ID, false))
            : assertThrows(PlatformApiException.class, () -> service.stage(APP_ID));

    assertEquals(409, exception.statusCode());
    assertEquals("catalog_publisher_scope_rejected", exception.errorCode());
    assertTrue(modes.isEmpty());
    verify(appHost, never()).updateFromDirectory(any(), any());
    verify(appHost, never()).updateCatalogFromDirectory(any(), any(), any(), any(), any());
    if (plan != null) {
      assertFalse(Files.exists(plan.scratchDirectory()));
    }
  }

  @Test
  void stage_whenMigrationHasDeadEndBranch_expectCompletePathSelected() throws Exception {
    InstalledAppSnapshot installed = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installed));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    AppDataService appDataService = appDataServiceWithFeedRecord();
    List<AppDataMigrationRunner.Mode> modes = new java.util.ArrayList<>();
    AppUpdateService service =
        serviceWithAppData(appDataService, payloadRewritingMigrationRunner(modes));
    AppCatalogEntry entry =
        entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED, compatibleApiMetadata());
    AppCatalogInstallPlan plan = planWithDeadEndBranchAppDataMigration(entry);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID)).thenReturn(List.of(entry));
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID)).thenReturn(plan);

    service.check(APP_ID, false);
    Map<String, Object> stagedSummary = service.stage(APP_ID);

    Map<String, Object> staged = (Map<String, Object>) stagedSummary.get(STAGED);
    Map<String, Object> migration = (Map<String, Object>) staged.get("dataMigration");
    assertEquals("ready", migration.get(STATUS));
    assertEquals(List.of(AppDataMigrationRunner.Mode.DRY_RUN), modes);
    assertEquals(List.of("feeds-v1-v2", "feeds-v2-v4"), migrationStepIds(migration));
  }

  @Test
  void stage_whenCompatibleChainCompetesWithIncompatibleDirectStep_expectCompatiblePathSelected()
      throws Exception {
    InstalledAppSnapshot installed = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installed));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    AppUpdateService service =
        serviceWithAppData(appDataServiceWithFeedRecord(), payloadRewritingMigrationRunner());
    AppCatalogEntry entry =
        entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED, compatibleApiMetadata());
    AppCatalogInstallPlan plan = planWithCompatibleAlternativeAppDataMigration(entry);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID)).thenReturn(List.of(entry));
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID)).thenReturn(plan);

    service.check(APP_ID, false);
    Map<String, Object> stagedSummary = service.stage(APP_ID);

    Map<String, Object> staged = (Map<String, Object>) stagedSummary.get(STAGED);
    Map<String, Object> migration = (Map<String, Object>) staged.get("dataMigration");
    assertEquals("ready", migration.get(STATUS));
    assertEquals(false, migration.get("operatorReviewRequired"));
    assertEquals(List.of("feeds-v1-v2", "feeds-v2-v4"), migrationStepIds(migration));
  }

  @Test
  void apply_whenMigrationRunnerWritesPayload_expectRecordsImportedBeforeSchemaRecorded()
      throws Exception {
    InstalledAppSnapshot installed = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    InstalledAppSnapshot updated = installed(UPDATE_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installed));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    AppDataService appDataService = appDataServiceWithFeedRecord();
    List<AppDataMigrationRunner.Mode> modes = new java.util.ArrayList<>();
    AppUpdateService service =
        serviceWithAppData(appDataService, payloadRewritingMigrationRunner(modes));
    AppCatalogEntry entry =
        entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED, compatibleApiMetadata());
    AppCatalogInstallPlan plan = planWithAppDataMigration(entry, true, true);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID)).thenReturn(List.of(entry));
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID)).thenReturn(plan);
    when(appHost.updateFromDirectory(APP_ID, plan.stagedBundleDirectory())).thenReturn(updated);

    service.check(APP_ID, false);
    service.stage(APP_ID);
    Map<String, Object> applied = service.apply(APP_ID, APPLY_NO_RESTART_NO_HEALTH);

    assertEquals(
        2, appDataService.listNamespaceMetadataForUpdate(APP_ID).getFirst().schemaVersion());
    assertEquals(
        2, appDataService.getRecord(APP_ID, "feeds", "subscriptions").get("schemaVersion"));
    assertEquals(
        List.of(
            AppDataMigrationRunner.Mode.DRY_RUN,
            AppDataMigrationRunner.Mode.DRY_RUN,
            AppDataMigrationRunner.Mode.APPLY),
        modes);
    Map<String, Object> candidate = (Map<String, Object>) applied.get(CANDIDATE);
    assertEquals("applied", ((Map<?, ?>) candidate.get("dataMigration")).get(STATUS));
  }

  @Test
  void apply_whenMigrationCommandFails_expectBundleRollbackAttemptedOnce() throws Exception {
    InstalledAppSnapshot installed = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    InstalledAppSnapshot updated = installed(UPDATE_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installed));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    AppDataService appDataService = appDataServiceWithFeedRecord();
    AppUpdateService service =
        serviceWithAppData(appDataService, dryRunPassingApplyFailingMigrationRunner());
    AppCatalogEntry entry =
        entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED, compatibleApiMetadata());
    AppCatalogInstallPlan plan = planWithAppDataMigration(entry, true, true);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID)).thenReturn(List.of(entry));
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID)).thenReturn(plan);
    when(appHost.updateFromDirectory(APP_ID, plan.stagedBundleDirectory())).thenReturn(updated);
    when(appHost.rollback(APP_ID)).thenReturn(installed);

    service.check(APP_ID, false);
    service.stage(APP_ID);
    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class, () -> service.apply(APP_ID, APPLY_NO_RESTART_NO_HEALTH));

    assertEquals("app_data_migration_apply_failed", exception.errorCode());
    verify(appHost, times(1)).rollback(APP_ID);
    assertEquals(
        1, appDataService.listNamespaceMetadataForUpdate(APP_ID).getFirst().schemaVersion());
  }

  @Test
  void apply_whenRunningMigrationApplyFailsAndRollbackSucceeds_expectRolledBackAppRestarted()
      throws Exception {
    InstalledAppSnapshot installed = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    InstalledAppSnapshot updated = installed(UPDATE_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installed));
    when(appHost.status(APP_ID))
        .thenReturn(
            Optional.empty(),
            Optional.empty(),
            Optional.empty(),
            Optional.empty(),
            Optional.of(running(installed)),
            Optional.empty());
    AppDataService appDataService = appDataServiceWithFeedRecord();
    AppUpdateService service =
        serviceWithAppData(appDataService, dryRunPassingApplyFailingMigrationRunner());
    AppCatalogEntry entry =
        entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED, compatibleApiMetadata());
    AppCatalogInstallPlan plan = planWithAppDataMigration(entry, true, true);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID)).thenReturn(List.of(entry));
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID)).thenReturn(plan);
    when(appHost.updateFromDirectory(APP_ID, plan.stagedBundleDirectory())).thenReturn(updated);
    when(appHost.rollback(APP_ID)).thenReturn(installed);
    when(appHost.start(APP_ID)).thenReturn(running(installed));

    service.check(APP_ID, false);
    service.stage(APP_ID);
    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class, () -> service.apply(APP_ID, APPLY_RESTART_NO_HEALTH));

    assertEquals("app_data_migration_apply_failed", exception.errorCode());
    verify(appHost).stop(APP_ID);
    verify(appHost, times(1)).rollback(APP_ID);
    verify(appHost, times(1)).start(APP_ID);
    assertEquals(
        1, appDataService.listNamespaceMetadataForUpdate(APP_ID).getFirst().schemaVersion());
  }

  @Test
  void apply_whenMigrationApplyFailsAndBundleRollbackFails_expectMigrationFailurePreserved()
      throws Exception {
    InstalledAppSnapshot installed = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    InstalledAppSnapshot updated = installed(UPDATE_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.describe(APP_ID))
        .thenReturn(
            Optional.of(installed),
            Optional.of(installed),
            Optional.of(installed),
            Optional.of(installed),
            Optional.of(installed),
            Optional.of(updated));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    AppDataService appDataService = appDataServiceWithFeedRecord();
    AppUpdateService service =
        serviceWithAppData(
            appDataService,
            (_, plan, mode, dataAccess) -> {
              if (mode == AppDataMigrationRunner.Mode.DRY_RUN) {
                for (AppDataMigrationPlan.NamespaceStep step : plan.namespaces()) {
                  AppDataMigrationRunner.StepDataFiles files = dataAccess.prepare(step, mode);
                  rewriteSchemaPayload(
                      files.inputPayload(),
                      files.outputPayload(),
                      step.fromSchemaVersion(),
                      step.toSchemaVersion());
                  dataAccess.complete(step, mode, files);
                }
                return AppDataMigrationRunner.MigrationExecutionResult.passed();
              }
              return AppDataMigrationRunner.MigrationExecutionResult.failed(2);
            });
    AppCatalogEntry entry =
        entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED, compatibleApiMetadata());
    AppCatalogInstallPlan plan = planWithAppDataMigration(entry, true, true);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID)).thenReturn(List.of(entry));
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID)).thenReturn(plan);
    when(appHost.updateFromDirectory(APP_ID, plan.stagedBundleDirectory())).thenReturn(updated);
    when(appHost.rollback(APP_ID)).thenThrow(new IOException(ROLLBACK_MANIFEST_BROKEN));

    service.check(APP_ID, false);
    service.stage(APP_ID);
    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class, () -> service.apply(APP_ID, APPLY_NO_RESTART_NO_HEALTH));

    assertEquals(ROLLBACK_FAILED, exception.errorCode());
    assertEquals(500, exception.statusCode());
    verify(appHost, times(1)).rollback(APP_ID);
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(updated));
    Map<String, Object> summary = service.summary(APP_ID);
    assertEquals(false, ((Map<?, ?>) summary.get(STAGED)).get(AVAILABLE));
    Map<String, Object> candidate = (Map<String, Object>) summary.get(CANDIDATE);
    assertEquals(FAILED, candidate.get(STATUS));
    Map<String, Object> migration = (Map<String, Object>) candidate.get("dataMigration");
    assertEquals("failed", migration.get(STATUS));
    assertEquals(ROLLBACK_FAILED, migration.get("blockReason"));
    assertEquals("failed", migration.get("applyStatus"));
  }

  @Test
  void apply_whenChainedMigrationRunner_expectEachStepAppliedBeforeNextStep() throws Exception {
    InstalledAppSnapshot installed = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    InstalledAppSnapshot updated = installed(UPDATE_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installed));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    AppDataService appDataService = appDataServiceWithFeedRecord();
    List<AppDataMigrationRunner.Mode> modes = new java.util.ArrayList<>();
    AppUpdateService service =
        serviceWithAppData(appDataService, payloadRewritingMigrationRunner(modes));
    AppCatalogEntry entry =
        entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED, compatibleApiMetadata());
    AppCatalogInstallPlan plan = planWithChainedAppDataMigration(entry);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID)).thenReturn(List.of(entry));
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID)).thenReturn(plan);
    when(appHost.updateFromDirectory(APP_ID, plan.stagedBundleDirectory())).thenReturn(updated);

    service.check(APP_ID, false);
    service.stage(APP_ID);
    Map<String, Object> applied = service.apply(APP_ID, APPLY_NO_RESTART_NO_HEALTH);

    assertEquals(
        3, appDataService.listNamespaceMetadataForUpdate(APP_ID).getFirst().schemaVersion());
    assertEquals(
        3, appDataService.getRecord(APP_ID, "feeds", "subscriptions").get("schemaVersion"));
    assertEquals(
        List.of(
            AppDataMigrationRunner.Mode.DRY_RUN,
            AppDataMigrationRunner.Mode.DRY_RUN,
            AppDataMigrationRunner.Mode.APPLY),
        modes);
    Map<String, Object> candidate = (Map<String, Object>) applied.get(CANDIDATE);
    assertEquals("applied", ((Map<?, ?>) candidate.get("dataMigration")).get(STATUS));
  }

  @Test
  void apply_whenAppDataAppearsAfterStage_expectMigrationPlanRefreshedAndMigrationRuns()
      throws Exception {
    InstalledAppSnapshot installed = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    InstalledAppSnapshot updated = installed(UPDATE_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installed));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    AppDataService appDataService = appDataService();
    List<AppDataMigrationRunner.Mode> modes = new java.util.ArrayList<>();
    AppUpdateService service =
        serviceWithAppData(appDataService, payloadRewritingMigrationRunner(modes));
    AppCatalogEntry entry =
        entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED, compatibleApiMetadata());
    AppCatalogInstallPlan plan = planWithAppDataMigration(entry, true, true);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID)).thenReturn(List.of(entry));
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID)).thenReturn(plan);
    when(appHost.updateFromDirectory(APP_ID, plan.stagedBundleDirectory())).thenReturn(updated);

    service.check(APP_ID, false);
    Map<String, Object> stagedSummary = service.stage(APP_ID);
    Map<String, Object> staged = (Map<String, Object>) stagedSummary.get(STAGED);
    assertEquals("not_required", ((Map<?, ?>) staged.get("dataMigration")).get(STATUS));

    putFeedRecord(appDataService);
    Map<String, Object> applied = service.apply(APP_ID, APPLY_NO_RESTART_NO_HEALTH);

    assertEquals(
        List.of(AppDataMigrationRunner.Mode.DRY_RUN, AppDataMigrationRunner.Mode.APPLY), modes);
    assertEquals(
        2, appDataService.listNamespaceMetadataForUpdate(APP_ID).getFirst().schemaVersion());
    Map<String, Object> candidate = (Map<String, Object>) applied.get(CANDIDATE);
    assertEquals("applied", ((Map<?, ?>) candidate.get("dataMigration")).get(STATUS));
  }

  @Test
  void apply_whenAcknowledgedRollbackIncompatiblePlanRefreshesWithNewStep_expectReviewRequired()
      throws Exception {
    InstalledAppSnapshot installed = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installed));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    AppDataService appDataService = appDataServiceWithFeedRecord();
    List<AppDataMigrationRunner.Mode> modes = new java.util.ArrayList<>();
    AppUpdateService service =
        serviceWithAppData(appDataService, payloadRewritingMigrationRunner(modes));
    AppCatalogEntry entry =
        entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED, compatibleApiMetadata());
    AppCatalogInstallPlan plan = planWithRollbackIncompatibleTwoNamespaceAppDataMigration(entry);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID)).thenReturn(List.of(entry));
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID)).thenReturn(plan);

    service.check(APP_ID, false);
    Map<String, Object> stagedSummary = service.stage(APP_ID, false, true);
    Map<String, Object> staged = (Map<String, Object>) stagedSummary.get(STAGED);
    Map<String, Object> stagedMigration = (Map<String, Object>) staged.get("dataMigration");
    assertEquals(List.of("feeds-v1-v2"), migrationStepIds(stagedMigration));
    modes.clear();
    putAppDataRecord(appDataService, "archive", "items");
    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class, () -> service.apply(APP_ID, APPLY_NO_RESTART_NO_HEALTH));

    assertEquals("app_data_migration_review_required", exception.errorCode());
    assertTrue(modes.isEmpty());
    verify(appHost, never()).updateFromDirectory(any(), any());
  }

  @Test
  void
      apply_whenMigrationContractHasNoExistingDataAndWriteAppearsBeforeReplacement_expectWriteRejected()
          throws Exception {
    InstalledAppSnapshot installed = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    InstalledAppSnapshot updated = installed(UPDATE_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installed));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    AppDataService appDataService = appDataService();
    AtomicReference<String> rejectedWriteError = new AtomicReference<>();
    AppUpdateService service =
        serviceWithAppData(appDataService, payloadRewritingMigrationRunner());
    AppCatalogEntry entry =
        entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED, compatibleApiMetadata());
    AppCatalogInstallPlan plan = planWithAppDataMigration(entry, true, true);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID)).thenReturn(List.of(entry));
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID)).thenReturn(plan);
    when(appHost.updateFromDirectory(APP_ID, plan.stagedBundleDirectory()))
        .thenAnswer(
            _ -> {
              try {
                putFeedRecord(appDataService);
              } catch (PlatformApiException exception) {
                rejectedWriteError.set(exception.errorCode());
              }
              return updated;
            });

    service.check(APP_ID, false);
    Map<String, Object> stagedSummary = service.stage(APP_ID);
    Map<String, Object> staged = (Map<String, Object>) stagedSummary.get(STAGED);
    assertEquals("not_required", ((Map<?, ?>) staged.get("dataMigration")).get(STATUS));
    Map<String, Object> applied = service.apply(APP_ID, APPLY_NO_RESTART_NO_HEALTH);

    assertEquals("app_data_migration_in_progress", rejectedWriteError.get());
    assertTrue(appDataService.listNamespaceMetadataForUpdate(APP_ID).isEmpty());
    Map<String, Object> candidate = (Map<String, Object>) applied.get(CANDIDATE);
    assertEquals("not_required", ((Map<?, ?>) candidate.get("dataMigration")).get(STATUS));
    putFeedRecord(appDataService);
    assertEquals(1, appDataService.listNamespaceMetadataForUpdate(APP_ID).size());
  }

  @Test
  void apply_whenRunningMigrationSnapshotTooLarge_expectOriginalAppRestartedBeforeFailure()
      throws Exception {
    InstalledAppSnapshot installed = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installed));
    when(appHost.status(APP_ID))
        .thenReturn(
            Optional.empty(),
            Optional.empty(),
            Optional.empty(),
            Optional.of(running(installed)),
            Optional.empty());
    AppUpdateService service =
        serviceWithAppData(
            appDataServiceWithFeedRecord(1),
            (_, _, _, _) -> AppDataMigrationRunner.MigrationExecutionResult.passed());
    AppCatalogEntry entry =
        entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED, compatibleApiMetadata());
    AppCatalogInstallPlan plan = planWithAppDataMigration(entry, true, true);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID)).thenReturn(List.of(entry));
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID)).thenReturn(plan);

    service.stage(APP_ID);
    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class, () -> service.apply(APP_ID, APPLY_RESTART_NO_HEALTH));

    assertEquals("app_data_snapshot_too_large", exception.errorCode());
    verify(appHost).stop(APP_ID);
    verify(appHost).start(APP_ID);
    verify(appHost, never()).updateFromDirectory(any(), any());
  }

  @Test
  void stage_whenMigrationBundleRequestsSandbox_expectBlockedBeforeDryRun() throws Exception {
    InstalledAppSnapshot installed = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installed));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    AtomicBoolean runnerCalled = new AtomicBoolean(false);
    AppUpdateService service =
        serviceWithAppData(
            appDataServiceWithFeedRecord(),
            (_, _, _, _) -> {
              runnerCalled.set(true);
              return AppDataMigrationRunner.MigrationExecutionResult.passed();
            });
    AppCatalogEntry entry =
        entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED, compatibleApiMetadata());
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID)).thenReturn(List.of(entry));
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID))
        .thenReturn(
            planWithAppDataMigration(
                entry,
                true,
                true,
                """
                sandbox.mode=restricted-process
                sandbox.required=true
                """));

    service.check(APP_ID, false);
    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> service.stage(APP_ID));

    assertEquals("app_data_migration_sandbox_unavailable", exception.errorCode());
    assertFalse(runnerCalled.get());
    verify(appHost, never()).updateFromDirectory(any(), any());
    Map<String, Object> candidate = (Map<String, Object>) service.summary(APP_ID).get(CANDIDATE);
    Map<String, Object> migration = (Map<String, Object>) candidate.get("dataMigration");
    assertEquals("sandbox_unavailable", migration.get(STATUS));
    assertEquals("app_data_migration_sandbox_unavailable", migration.get("blockReason"));
  }

  @Test
  void stage_whenMigrationBundleRequestsOptionalSandbox_expectDryRunAndStage() throws Exception {
    InstalledAppSnapshot installed = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installed));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    AtomicBoolean runnerCalled = new AtomicBoolean(false);
    AppUpdateService service =
        serviceWithAppData(
            appDataServiceWithFeedRecord(),
            (_, _, _, _) -> {
              runnerCalled.set(true);
              return AppDataMigrationRunner.MigrationExecutionResult.passed();
            });
    AppCatalogEntry entry =
        entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED, compatibleApiMetadata());
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID)).thenReturn(List.of(entry));
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID))
        .thenReturn(
            planWithAppDataMigration(
                entry,
                true,
                true,
                """
                sandbox.mode=restricted-process
                sandbox.required=false
                """));

    service.check(APP_ID, false);
    Map<String, Object> summary = service.stage(APP_ID);

    assertTrue(runnerCalled.get());
    Map<String, Object> staged = (Map<String, Object>) summary.get(STAGED);
    assertEquals(true, staged.get(AVAILABLE));
    Map<String, Object> migration = (Map<String, Object>) staged.get("dataMigration");
    assertEquals("ready", migration.get(STATUS));
    assertNull(migration.get("blockReason"));
    verify(appHost, never()).updateFromDirectory(any(), any());
  }

  @Test
  void check_whenApplyWhenStoppedPolicySandboxMigration_expectCandidateSummaryWithoutApply()
      throws Exception {
    InstalledAppSnapshot installed = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installed));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    AtomicBoolean runnerCalled = new AtomicBoolean(false);
    KeyPair reviewerKeyPair = reviewerKeyPair();
    AppUpdateService service =
        serviceWithAppData(
            appDataServiceWithFeedRecord(),
            (_, _, _, _) -> {
              runnerCalled.set(true);
              return AppDataMigrationRunner.MigrationExecutionResult.passed();
            },
            reviewerKeyPair);
    service.setPolicy(APP_ID, AppUpdatePolicyMode.APPLY_WHEN_STOPPED);
    AppCatalogEntry entry =
        withTrustedReceipt(
            entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED, compatibleApiMetadata()),
            reviewerKeyPair);
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID)).thenReturn(List.of(entry));
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID))
        .thenReturn(
            planWithAppDataMigration(
                entry,
                true,
                true,
                """
                sandbox.mode=restricted-process
                sandbox.required=true
                """));

    Map<String, Object> summary = service.check(APP_ID, false);

    assertFalse(runnerCalled.get());
    assertEquals(false, ((Map<?, ?>) summary.get(STAGED)).get(AVAILABLE));
    assertEquals("success", ((Map<?, ?>) summary.get("lastCheck")).get(STATUS));
    Map<String, Object> candidate = (Map<String, Object>) summary.get(CANDIDATE);
    Map<String, Object> migration = (Map<String, Object>) candidate.get("dataMigration");
    assertEquals(AVAILABLE, candidate.get(STATUS));
    assertEquals(false, candidate.get("autoStageAllowed"));
    assertEquals(true, candidate.get(OPERATOR_ACTION_REQUIRED));
    assertEquals("sandbox_unavailable", migration.get(STATUS));
    assertEquals("app_data_migration_sandbox_unavailable", migration.get("blockReason"));
    verify(appHost, never()).updateFromDirectory(any(), any());
  }

  @Test
  void stage_whenMigrationRollbackIncompatibleWithoutAcknowledgement_expectReviewRequired()
      throws Exception {
    InstalledAppSnapshot installed = installed(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION));
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installed));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    AppUpdateService service =
        serviceWithAppData(
            appDataServiceWithFeedRecord(),
            (_, _, _, _) -> AppDataMigrationRunner.MigrationExecutionResult.passed());
    AppCatalogEntry entry =
        entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED, compatibleApiMetadata());
    when(catalogManager.listCatalogs()).thenReturn(List.of(catalog()));
    when(catalogManager.listRoutineApps(CATALOG_ID)).thenReturn(List.of(entry));
    when(catalogManager.prepareInstallPlan(CATALOG_ID, APP_ID))
        .thenReturn(planWithAppDataMigration(entry, false, true));

    service.check(APP_ID, false);
    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> service.stage(APP_ID));

    assertEquals("app_data_migration_review_required", exception.errorCode());
    Map<String, Object> candidate = (Map<String, Object>) service.summary(APP_ID).get(CANDIDATE);
    Map<String, Object> migration = (Map<String, Object>) candidate.get("dataMigration");
    assertEquals("rollback_incompatible", migration.get(STATUS));
    assertEquals(true, migration.get("operatorReviewRequired"));
  }

  private void verifyNoInstallPlanPreparation() {
    assertFalse(
        mockingDetails(catalogManager).getInvocations().stream()
            .map(invocation -> invocation.getMethod().getName())
            .anyMatch("prepareInstallPlan"::equals),
        "prepareInstallPlan should not be called");
  }

  private AppUpdateService serviceWithAppData(
      AppDataService appDataService, AppDataMigrationRunner migrationRunner) {
    return new AppUpdateService(
        appHost,
        catalogManager,
        new AppUpdateService.AppUpdateDependencies(
            AppReviewPolicy.DEFAULT,
            TrustedReviewerKeys::empty,
            null,
            appDataService,
            migrationRunner,
            _ -> Map.of()));
  }

  private AppUpdateService serviceWithAppData(
      AppDataService appDataService,
      AppDataMigrationRunner migrationRunner,
      KeyPair reviewerKeyPair) {
    return new AppUpdateService(
        appHost,
        catalogManager,
        new AppUpdateService.AppUpdateDependencies(
            AppReviewPolicy.DEFAULT,
            () -> trustedReviewerKeys(reviewerKeyPair),
            null,
            appDataService,
            migrationRunner,
            _ -> Map.of()));
  }

  private static AppDataMigrationRunner payloadRewritingMigrationRunner(
      List<AppDataMigrationRunner.Mode> modes) {
    return (_, plan, mode, dataAccess) -> {
      modes.add(mode);
      rewriteMigrationPayloads(plan, mode, dataAccess);
      return AppDataMigrationRunner.MigrationExecutionResult.passed();
    };
  }

  private static AppDataMigrationRunner payloadRewritingMigrationRunner() {
    return payloadRewritingMigrationRunner(new java.util.ArrayList<>());
  }

  private static AppDataMigrationRunner dryRunPassingApplyFailingMigrationRunner() {
    return (_, plan, mode, dataAccess) -> {
      if (mode == AppDataMigrationRunner.Mode.DRY_RUN) {
        rewriteMigrationPayloads(plan, mode, dataAccess);
        return AppDataMigrationRunner.MigrationExecutionResult.passed();
      }
      return AppDataMigrationRunner.MigrationExecutionResult.failed(2);
    };
  }

  private static AppDataMigrationRunner stagedBundleMutatingMigrationRunner(
      List<AppDataMigrationRunner.Mode> modes) {
    AtomicInteger dryRuns = new AtomicInteger();
    return (bundleRoot, plan, mode, dataAccess) -> {
      modes.add(mode);
      rewriteMigrationPayloads(plan, mode, dataAccess);
      if (mode == AppDataMigrationRunner.Mode.DRY_RUN && dryRuns.incrementAndGet() == 2) {
        Files.writeString(bundleRoot.resolve("tampered-after-apply-dry-run"), "changed");
      }
      return AppDataMigrationRunner.MigrationExecutionResult.passed();
    };
  }

  private static void rewriteMigrationPayloads(
      AppDataMigrationPlan plan,
      AppDataMigrationRunner.Mode mode,
      AppDataMigrationRunner.MigrationDataAccess dataAccess)
      throws IOException {
    for (AppDataMigrationPlan.NamespaceStep step : plan.namespaces()) {
      AppDataMigrationRunner.StepDataFiles files = dataAccess.prepare(step, mode);
      rewriteSchemaPayload(
          files.inputPayload(),
          files.outputPayload(),
          step.fromSchemaVersion(),
          step.toSchemaVersion());
      dataAccess.complete(step, mode, files);
    }
  }

  private static List<String> migrationStepIds(Map<String, Object> migration) {
    @SuppressWarnings("unchecked")
    List<Map<String, Object>> steps = (List<Map<String, Object>>) migration.get("namespaces");
    return steps.stream().map(step -> (String) step.get("stepId")).toList();
  }

  private static void rewriteSchemaPayload(
      Path inputPayload, Path outputPayload, int fromSchemaVersion, int toSchemaVersion)
      throws IOException {
    String content = Files.readString(inputPayload);
    int recordsOffset = content.indexOf("\"records\"");
    if (recordsOffset < 0) {
      Files.writeString(outputPayload, content);
      return;
    }
    String migratedRecords =
        content
            .substring(recordsOffset)
            .replace(
                "\"schemaVersion\":" + fromSchemaVersion, "\"schemaVersion\":" + toSchemaVersion);
    Files.writeString(outputPayload, content.substring(0, recordsOffset) + migratedRecords);
  }

  private static AppDataService appDataServiceWithFeedRecord() {
    return appDataServiceWithFeedRecord(8192);
  }

  private static AppDataService appDataServiceWithUiStateRecord() {
    AppDataService service = appDataService();
    service.putRecord(
        APP_ID,
        Map.of(
            "namespace",
            List.of("ui-state"),
            "key",
            List.of("view"),
            "schemaVersion",
            List.of("1"),
            "contentType",
            List.of("application/json"),
            "valueText",
            List.of("{\"selected\":true}")));
    return service;
  }

  private static AppDataService appDataServiceWithFeedRecord(int maxExportBytes) {
    AppDataService service = appDataService(maxExportBytes);
    putFeedRecord(service);
    return service;
  }

  private static AppDataService appDataService() {
    return appDataService(8192);
  }

  private static AppDataService appDataService(int maxExportBytes) {
    return new AppDataService(
        new InMemoryAppDataStore(),
        null,
        new AppDataStoreConfig(1024, 16, 4, maxExportBytes, 8192, 8),
        java.time.Clock.fixed(Instant.parse("2026-05-03T00:00:00Z"), java.time.ZoneOffset.UTC),
        new AppDiskUsageScanner());
  }

  private AppDataService appDataServiceWithHostQuota() {
    AppDataService service =
        new AppDataService(
            new InMemoryAppDataStore(),
            appHost,
            new AppDataStoreConfig(1024, 16, 4, 8192, 8192, 8),
            java.time.Clock.fixed(Instant.parse("2026-05-03T00:00:00Z"), java.time.ZoneOffset.UTC),
            new AppDiskUsageScanner(),
            true);
    putFeedRecord(service);
    return service;
  }

  private static void putFeedRecord(AppDataService service) {
    putAppDataRecord(service, FEEDS_NAMESPACE, SUBSCRIPTIONS_KEY);
  }

  private static void putRecordDuringMigration(AppDataService service) {
    putAppDataRecord(service, FEEDS_NAMESPACE, "during-migration", "{\"count\":2}");
  }

  private static void putAppDataRecord(AppDataService service, String namespace, String key) {
    putAppDataRecord(service, namespace, key, "{\"count\":1}");
  }

  private static void putAppDataRecord(
      AppDataService service, String namespace, String key, String valueText) {
    service.putRecord(
        APP_ID,
        Map.of(
            "namespace",
            List.of(namespace),
            "key",
            List.of(key),
            "schemaVersion",
            List.of("1"),
            "contentType",
            List.of("application/json"),
            "valueText",
            List.of(valueText)));
  }

  private AppUpdateService serviceWithInstalled(String version, List<String> permissions)
      throws Exception {
    return serviceWithInstalled(
        version, permissions, AppReviewPolicy.DEFAULT, TrustedReviewerKeys::empty);
  }

  private AppUpdateService serviceWithInstalled(
      String version,
      List<String> permissions,
      AppReviewPolicy reviewPolicy,
      AppUpdateService.ReviewerKeysProvider reviewerKeysProvider)
      throws Exception {
    InstalledAppSnapshot installed = installed(version, permissions);
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installed));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    return new AppUpdateService(appHost, catalogManager, reviewPolicy, reviewerKeysProvider);
  }

  private void enableFederation(AppUpdateService service) throws IOException {
    when(catalogManager.federationEnabled()).thenReturn(true);
    CatalogScopedReviewerPolicy reviewerPolicy = mock(CatalogScopedReviewerPolicy.class);
    AppReviewTrustDecision decision = mock(AppReviewTrustDecision.class);
    when(decision.toJsonValue())
        .thenReturn(
            Map.of(
                "status", "trusted_reviewed",
                "trusted", true,
                "positive", true,
                "requiresAcknowledgement", false,
                "blocksInstall", false,
                "blocksUpdate", false,
                "blocksPolicyApply", false));
    lenient().when(decision.trusted()).thenReturn(true);
    lenient().when(decision.positive()).thenReturn(true);
    CatalogScopedReviewerPolicy.Verification verification =
        new CatalogScopedReviewerPolicy.Verification(
            decision, true, "reviewer-scope-test", DIGEST, DIGEST, "authorized");
    when(reviewerPolicy.evaluate(any(), any(), any(), any(), any()))
        .thenAnswer(
            invocation -> {
              String catalogId = invocation.getArgument(0);
              String scopeDigest = "beta".equals(catalogId) ? "1".repeat(64) : DIGEST;
              return new CatalogScopedReviewerPolicy.Verification(
                  decision, true, "reviewer-scope-" + catalogId, scopeDigest, DIGEST, "authorized");
            });
    lenient()
        .when(reviewerPolicy.retainAuthorization(any(), any(), any(), any(), any()))
        .thenReturn(
            new CatalogScopedReviewerPolicy.RoutineAuthorization(
                verification, TrustedReviewerKeys.empty(), () -> {}));
    service.setCatalogScopedReviewerPolicy(reviewerPolicy);
  }

  private InstalledAppSnapshot installed(String version, List<String> permissions) {
    return installed(version, permissions, null);
  }

  private InstalledAppSnapshot installed(
      String version, List<String> permissions, Long quotaBytes) {
    AppManifest manifest =
        new AppManifest(
            1,
            APP_ID,
            APP_NAME,
            version,
            "bin/launch.sh",
            AppUiMode.NONE,
            null,
            permissions,
            quotaBytes,
            null);
    InstalledAppPaths paths =
        new InstalledAppPaths(
            APP_ID,
            tempDir.resolve("installed").resolve(APP_ID),
            tempDir.resolve("data").resolve(APP_ID),
            tempDir.resolve("cache").resolve(APP_ID),
            tempDir.resolve("run").resolve(APP_ID));
    return new InstalledAppSnapshot(manifest, paths);
  }

  private InstalledAppSnapshot installedWithApiMetadata(
      List<String> permissions, AppApiCompatibilityMetadata apiCompatibility) {
    AppManifest manifest =
        new AppManifest(
            1,
            APP_ID,
            APP_NAME,
            INSTALLED_VERSION,
            "bin/launch.sh",
            AppUiMode.NONE,
            null,
            permissions,
            apiCompatibility,
            null,
            null,
            AppSandboxPolicy.defaults(),
            AppRestartPolicy.NEVER,
            0,
            0L);
    InstalledAppPaths paths =
        new InstalledAppPaths(
            APP_ID,
            tempDir.resolve("installed").resolve(APP_ID),
            tempDir.resolve("data").resolve(APP_ID),
            tempDir.resolve("cache").resolve(APP_ID),
            tempDir.resolve("run").resolve(APP_ID));
    return new InstalledAppSnapshot(manifest, paths);
  }

  private RunningAppSnapshot running(InstalledAppSnapshot installed) {
    return new RunningAppSnapshot(
        installed.manifest(),
        installed.paths(),
        "secret-token",
        1234L,
        Instant.parse("2026-05-03T00:00:00Z"));
  }

  private static AppCatalogSourceSnapshot catalog() {
    return catalog(CATALOG_ID);
  }

  private static AppCatalogSourceSnapshot catalog(String catalogId) {
    Instant now = Instant.parse("2026-05-03T00:00:00Z");
    return new AppCatalogSourceSnapshot(
        catalogId,
        "Core Apps",
        URI.create("https://example.invalid/cryptad-app-catalog.properties"),
        now,
        1,
        now,
        now,
        now,
        now,
        AppCatalogFetchStatus.SUCCESS,
        Optional.empty(),
        Optional.empty(),
        Optional.of("https://example.invalid/cryptad-app-catalog.properties"),
        Optional.empty());
  }

  private static FederatedCatalogTrustBinding federatedCatalogBinding(
      String catalogId, int localPriority) {
    Instant now = Instant.parse("2026-05-03T00:00:00Z");
    return FederatedCatalogTrustBinding.create(
        "binding-" + catalogId,
        catalogId,
        Map.of("catalog-key", DIGEST),
        FederatedCatalogTrustBinding.Status.ACTIVE,
        Set.of(AppCatalogChannel.STABLE),
        localPriority,
        null,
        DIGEST,
        DIGEST,
        now.minusSeconds(60),
        now,
        "test binding",
        "test-operator");
  }

  private static CatalogPublisherBinding federatedPublisherBinding(String catalogId) {
    return federatedPublisherBinding(catalogId, DIGEST);
  }

  private static CatalogPublisherBinding federatedPublisherBinding(
      String catalogId, String publisherFingerprint) {
    Instant now = Instant.parse("2026-05-03T00:00:00Z");
    return CatalogPublisherBinding.create(
        "publisher-binding-" + catalogId,
        catalogId,
        APP_ID,
        "publisher-key",
        publisherFingerprint,
        CatalogPublisherBinding.Status.ACTIVE,
        Instant.parse("2025-01-01T00:00:00Z"),
        Instant.parse("2030-01-01T00:00:00Z"),
        null,
        null,
        Set.of(AppCatalogChannel.STABLE),
        "test approval",
        DIGEST,
        now.minusSeconds(3600),
        now,
        "test binding",
        "test-operator");
  }

  private static CatalogPublisherBinding federatedPublisherBinding(
      String catalogId,
      String publisherKeyId,
      String publisherFingerprint,
      CatalogPublisherBinding.Status status,
      String predecessorKeyId,
      String successorKeyId) {
    Instant now = Instant.parse("2026-05-03T00:00:00Z");
    return CatalogPublisherBinding.create(
        "publisher-binding-" + catalogId + '-' + publisherKeyId,
        catalogId,
        APP_ID,
        publisherKeyId,
        publisherFingerprint,
        status,
        Instant.parse("2025-01-01T00:00:00Z"),
        Instant.parse("2030-01-01T00:00:00Z"),
        predecessorKeyId,
        successorKeyId,
        Set.of(AppCatalogChannel.STABLE),
        "test approval",
        DIGEST,
        now.minusSeconds(3600),
        now,
        "test binding",
        "test-operator");
  }

  private static FileFederatedCatalogConflictResolutionStore.Lookup applicableExactDuplicateLookup(
      FederatedCatalogConflictEngine.ConflictSet conflictSet) {
    FederatedCatalogConflictEngine.Resolution resolution =
        new FederatedCatalogConflictEngine.Resolution(
            conflictSet.conflictId(),
            conflictSet.subjectSetDigest(),
            FederatedCatalogConflictEngine.ResolutionKind.ALLOW_EXACT_DUPLICATE,
            Optional.empty(),
            Optional.empty(),
            Instant.parse("2026-05-03T00:00:00Z"),
            "operator accepts exact duplicate evidence",
            null);
    return new FileFederatedCatalogConflictResolutionStore.Lookup(
        FileFederatedCatalogConflictResolutionStore.LookupStatus.APPLICABLE,
        Optional.of(resolution));
  }

  private static AppCatalogInstallPlan planWithCatalogSigner(
      AppCatalogInstallPlan plan, String signerKeyId, String signerFingerprint) {
    return new AppCatalogInstallPlan(
        plan.catalogId(),
        plan.entry(),
        plan.stagedBundleDirectory(),
        plan.scratchDirectory(),
        plan.bundleVerification(),
        Optional.of(
            new AppCatalogOriginContext(
                plan.catalogId(),
                signerKeyId,
                signerFingerprint,
                "3".repeat(64),
                "binding-1",
                DIGEST,
                DIGEST,
                DIGEST,
                true)));
  }

  private static InstalledAppOrigin installedOrigin(String catalogId) {
    return installedOrigin(catalogId, "publisher-key", DIGEST);
  }

  private static InstalledAppOrigin installedOrigin(
      String catalogId, String publisherKeyId, String publisherFingerprint) {
    return InstalledAppOrigin.create(
        APP_ID,
        INSTALLED_VERSION,
        DIGEST,
        catalogId,
        "catalog-key",
        DIGEST,
        DIGEST,
        publisherKeyId,
        publisherFingerprint,
        publisherFingerprint.isEmpty() ? "" : DIGEST,
        "",
        "reviewed",
        "binding-1",
        DIGEST,
        DIGEST,
        DIGEST,
        Instant.parse("2026-05-01T00:00:00Z"),
        null);
  }

  private static AppCatalogEntry entry(String version, AppCatalogReviewStatus reviewStatus) {
    return entry(version, reviewStatus, AppApiCompatibilityMetadata.undeclared());
  }

  private static AppApiCompatibilityMetadata compatibleApiMetadata() {
    return new AppApiCompatibilityMetadata(
        1,
        PlatformApiContract.current().contractVersion(),
        List.of(),
        TargetStability.STABLE,
        false);
  }

  private static AppApiCompatibilityMetadata futureApiMetadata() {
    int futureContractVersion = PlatformApiContract.current().contractVersion() + 1;
    return new AppApiCompatibilityMetadata(
        futureContractVersion, futureContractVersion, List.of(), TargetStability.STABLE, false);
  }

  private static AppApiCompatibilityMetadata unsupportedBaselineApiMetadata() {
    return declaredBaselineApiMetadata("1.1");
  }

  private static AppApiCompatibilityMetadata declaredBaselineApiMetadata(String baseline) {
    return new AppApiCompatibilityMetadata(
        1,
        PlatformApiContract.current().contractVersion(),
        List.of(),
        TargetStability.STABLE,
        true,
        baseline,
        true,
        false,
        true);
  }

  private static AppCatalogEntry entry(
      String version, AppCatalogReviewStatus reviewStatus, AppApiCompatibilityMetadata metadata) {
    return entry(version, reviewStatus, metadata, AppCatalogProductionMetadata.DEFAULT);
  }

  private static AppCatalogEntry entry(
      String version,
      AppCatalogReviewStatus reviewStatus,
      AppApiCompatibilityMetadata metadata,
      AppCatalogProductionMetadata productionMetadata) {
    return entry(
        version, reviewStatus, metadata, productionMetadata, List.of(QUEUE_READ_PERMISSION));
  }

  private static AppCatalogEntry entry(
      String version,
      AppCatalogReviewStatus reviewStatus,
      AppApiCompatibilityMetadata metadata,
      AppCatalogProductionMetadata productionMetadata,
      List<String> permissions) {
    return new AppCatalogEntry(
        APP_ID,
        APP_NAME,
        version,
        "Manage queues.",
        null,
        null,
        null,
        List.of(),
        new AppCatalogCompatibilityMetadata(null, metadata),
        new AppCatalogReviewMetadata(reviewStatus, null),
        AppCatalogChangelog.EMPTY,
        List.of(),
        productionMetadata,
        URI.create("file:///tmp/queue-manager-" + version + ".zip"),
        DIGEST,
        1234L,
        AppCatalogEntry.ZIP_BUNDLE_TYPE,
        permissions,
        Map.of());
  }

  private static AppCatalogEntry reviewedUpdateEntryWithTrustedReceipt(
      AppApiCompatibilityMetadata metadata, KeyPair reviewerKeyPair) {
    return withTrustedReceipt(
        entry(UPDATE_VERSION, AppCatalogReviewStatus.REVIEWED, metadata), reviewerKeyPair);
  }

  private static AppCatalogEntry withTrustedReceipt(
      AppCatalogEntry unsignedEntry, KeyPair reviewerKeyPair) {
    AppReviewReceipt receipt =
        AppReviewReceiptSigner.sign(reviewPayload(unsignedEntry), reviewerKeyPair.getPrivate());
    return new AppCatalogEntry(
        unsignedEntry.appId(),
        unsignedEntry.name(),
        unsignedEntry.version(),
        unsignedEntry.summary(),
        unsignedEntry.homepage().orElse(null),
        unsignedEntry.source().orElse(null),
        unsignedEntry.license().orElse(null),
        unsignedEntry.categories(),
        unsignedEntry.compatibility(),
        unsignedEntry.review(),
        receipt,
        unsignedEntry.changelog(),
        unsignedEntry.screenshots(),
        unsignedEntry.productionMetadata(),
        unsignedEntry.bundleUri(),
        unsignedEntry.bundleSha256(),
        unsignedEntry.bundleSizeBytes(),
        unsignedEntry.bundleType(),
        unsignedEntry.permissions(),
        unsignedEntry.permissionRationales());
  }

  private static AppCatalogEntry withBundleDigest(AppCatalogEntry entry, String bundleDigest) {
    return new AppCatalogEntry(
        entry.appId(),
        entry.name(),
        entry.version(),
        entry.summary(),
        entry.homepage().orElse(null),
        entry.source().orElse(null),
        entry.license().orElse(null),
        entry.categories(),
        entry.compatibility(),
        entry.review(),
        entry.reviewReceipt().orElse(null),
        entry.changelog(),
        entry.screenshots(),
        entry.productionMetadata(),
        entry.bundleUri(),
        bundleDigest,
        entry.bundleSizeBytes(),
        entry.bundleType(),
        entry.permissions(),
        entry.permissionRationales());
  }

  private static AppCatalogProductionMetadata productionMetadata(AppCatalogChannel channel) {
    AppCatalogSupportStatus supportStatus =
        channel == AppCatalogChannel.DEPRECATED
            ? AppCatalogSupportStatus.DEPRECATED
            : AppCatalogSupportStatus.SUPPORTED;
    AppCatalogDeprecationStatus deprecationStatus =
        channel == AppCatalogChannel.DEPRECATED
            ? AppCatalogDeprecationStatus.DEPRECATED
            : AppCatalogDeprecationStatus.NONE;
    return new AppCatalogProductionMetadata(
        channel,
        supportStatus,
        deprecationStatus,
        Optional.empty(),
        Optional.empty(),
        List.of(),
        true);
  }

  private static AppCatalogProductionMetadata productionMetadataWithSecurityAdvisory() {
    return new AppCatalogProductionMetadata(
        AppCatalogChannel.STABLE,
        AppCatalogSupportStatus.SUPPORTED,
        AppCatalogDeprecationStatus.NONE,
        Optional.empty(),
        Optional.empty(),
        List.of(
            new AppCatalogSecurityAdvisory(
                "ADV-1", URI.create("https://example.invalid/security/ADV-1"))),
        true);
  }

  private static AppReviewReceiptPayload reviewPayload(AppCatalogEntry entry) {
    return new AppReviewReceiptPayload(
        AppReviewReceiptPayload.RECEIPT_VERSION,
        entry.appId(),
        entry.version(),
        entry.bundleSha256(),
        entry.bundleSizeBytes(),
        Optional.empty(),
        REVIEW_POLICY_ID,
        REVIEW_POLICY_VERSION,
        AppReviewReceiptStatus.REVIEWED,
        REVIEWER_KEY_ID,
        REVIEWED_AT,
        Optional.empty(),
        Optional.empty(),
        Optional.empty(),
        Optional.empty(),
        Optional.empty());
  }

  private static TrustedReviewerKeys trustedReviewerKeys(KeyPair keyPair) {
    return TrustedReviewerKeys.of(
        TrustedReviewerKey.ed25519(
            REVIEWER_KEY_ID,
            keyPair.getPublic().getEncoded(),
            "Crypta First-Party Review",
            REVIEW_POLICY_ID));
  }

  private static AppCatalogSecurityDecision warningSecurityDecision() {
    return new AppCatalogSecurityDecision(
        AppCatalogSecurityDecisionStatus.WARNING,
        AppCatalogSecurityAction.WARN,
        AppCatalogSecuritySeverity.HIGH,
        List.of("CRYPTA-2026-0002"),
        true,
        false,
        false,
        true,
        null,
        null,
        List.of("Security advisory requires operator acknowledgement."));
  }

  private static AppCatalogSecurityDecision blockUpdateAndWarningSecurityDecision() {
    return new AppCatalogSecurityDecision(
        AppCatalogSecurityDecisionStatus.BLOCKED,
        AppCatalogSecurityAction.BLOCK_UPDATE,
        AppCatalogSecuritySeverity.CRITICAL,
        List.of("CRYPTA-2026-0002", "CRYPTA-2026-0003"),
        true,
        false,
        true,
        true,
        null,
        null,
        List.of("Security advisory requires operator acknowledgement."));
  }

  private static AppCatalogSecurityDecision denylistedSecurityDecision() {
    return new AppCatalogSecurityDecision(
        AppCatalogSecurityDecisionStatus.DENYLISTED,
        AppCatalogSecurityAction.DENYLIST,
        AppCatalogSecuritySeverity.CRITICAL,
        List.of("CRYPTA-2026-0001"),
        false,
        true,
        true,
        true,
        "Export app data before uninstalling.",
        APP_ID,
        List.of("Known vulnerable release."));
  }

  private static KeyPair reviewerKeyPair() throws NoSuchAlgorithmException {
    return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
  }

  private void assertInstallPlanNotPrepared() {
    assertTrue(recordedInvocations(catalogManager, "prepareInstallPlan").isEmpty());
  }

  private static void assertPolicyAuthorizationOrder(
      FileCatalogPublisherBindingStore publisherStore,
      CatalogScopedReviewerPolicy reviewerPolicy,
      FileFederatedCatalogConflictResolutionStore resolutionStore) {
    List<Invocation> publisherRetentions =
        recordedInvocations(publisherStore, "retainAuthorization");
    List<Invocation> reviewerRetentions =
        recordedInvocations(reviewerPolicy, "retainAuthorization");
    List<Invocation> reviewerEvaluations = recordedInvocations(reviewerPolicy, "evaluate");
    List<Invocation> publisherLookups = recordedInvocations(publisherStore, "findActiveForScope");
    List<Invocation> conflictRetentions = recordedInvocations(resolutionStore, "retainLookup");
    assertEquals(1, publisherRetentions.size());
    assertEquals(1, reviewerRetentions.size());
    assertEquals(3, reviewerEvaluations.size());
    assertEquals(2, publisherLookups.size());
    assertEquals(1, conflictRetentions.size());
    assertTrue(
        publisherRetentions.getFirst().getSequenceNumber()
            < reviewerRetentions.getFirst().getSequenceNumber());
    assertTrue(
        reviewerRetentions.getFirst().getSequenceNumber()
            < reviewerEvaluations.getFirst().getSequenceNumber());
    assertTrue(
        reviewerRetentions.getFirst().getSequenceNumber()
            < publisherLookups.getFirst().getSequenceNumber());
    assertTrue(
        Math.max(
                reviewerEvaluations.getLast().getSequenceNumber(),
                publisherLookups.getLast().getSequenceNumber())
            < conflictRetentions.getFirst().getSequenceNumber());
  }

  private static List<Invocation> recordedInvocations(Object mock, String methodName) {
    return mockingDetails(mock).getInvocations().stream()
        .filter(invocation -> invocation.getMethod().getName().equals(methodName))
        .toList();
  }

  private AppCatalogInstallPlan plan(AppCatalogEntry entry) throws IOException {
    return plan(CATALOG_ID, entry);
  }

  private AppCatalogInstallPlan plan(String catalogId, AppCatalogEntry entry) throws IOException {
    PlanDirectories directories = planDirectories(entry);
    return new AppCatalogInstallPlan(
        catalogId, entry, directories.stagedBundle(), directories.scratch());
  }

  private AppCatalogInstallPlan plan(
      String catalogId,
      AppCatalogEntry entry,
      AppCatalogBundleVerificationResult bundleVerification,
      AppCatalogOriginContext originContext)
      throws IOException {
    PlanDirectories directories = planDirectories(entry);
    return new AppCatalogInstallPlan(
        catalogId,
        entry,
        directories.stagedBundle(),
        directories.scratch(),
        bundleVerification,
        Optional.ofNullable(originContext));
  }

  private PlanDirectories planDirectories(AppCatalogEntry entry) throws IOException {
    Path scratch = tempDir.resolve("scratch-" + entry.version());
    Path staged = scratch.resolve("bundle");
    Files.createDirectories(staged);
    Files.writeString(
        staged.resolve("cryptad-app.properties"),
        """
        manifest.version=1
        app.id=%s
        app.name=%s
        app.version=%s
        app.exec=bin/launch.sh
        app.permissions=%s
        """
                .formatted(
                    entry.appId(),
                    entry.name(),
                    entry.version(),
                    String.join(",", entry.permissions()))
            + apiCompatibilityManifestFields(entry));
    return new PlanDirectories(staged, scratch);
  }

  private AppCatalogInstallPlan federatedPlan(String catalogId, AppCatalogEntry entry)
      throws IOException {
    return plan(
        catalogId,
        entry,
        new AppCatalogBundleVerificationResult(
            "publisher-key", DIGEST, "publisher-binding-" + catalogId, DIGEST, true, DIGEST),
        new AppCatalogOriginContext(
            catalogId,
            "catalog-key",
            DIGEST,
            "3".repeat(64),
            "binding-" + catalogId,
            DIGEST,
            DIGEST,
            DIGEST,
            true));
  }

  private record PlanDirectories(Path stagedBundle, Path scratch) {}

  private AppCatalogInstallPlan planWithAppDataMigration(
      AppCatalogEntry entry, boolean rollbackCompatible, boolean includeMigrationStep)
      throws IOException {
    return planWithAppDataMigration(entry, rollbackCompatible, includeMigrationStep, "");
  }

  private AppCatalogInstallPlan planWithAppDataMigration(
      AppCatalogEntry entry,
      boolean rollbackCompatible,
      boolean includeMigrationStep,
      String extraManifestFields)
      throws IOException {
    AppCatalogInstallPlan plan = plan(entry);
    String migrationFields =
        includeMigrationStep
            ? """
            app.data.migrations=feeds-v1-v2
            app.data.migration.feeds-v1-v2.namespace=feeds
            app.data.migration.feeds-v1-v2.from=1
            app.data.migration.feeds-v1-v2.to=2
            app.data.migration.feeds-v1-v2.command=bin/migrate-feed-data.sh
            app.data.migration.feeds-v1-v2.rollbackCompatible=%s
            app.data.migration.feeds-v1-v2.requiresStopped=true
            app.data.migration.feeds-v1-v2.description=Upgrade feed records to schema v2.
            """
                .formatted(Boolean.toString(rollbackCompatible))
            : "";
    Files.writeString(
        plan.stagedBundleDirectory().resolve("cryptad-app.properties"),
        """
        manifest.version=1
        app.id=%s
        app.name=%s
        app.version=%s
        app.exec=bin/launch.sh
        app.permissions=%s
        %s
        app.data.schema.current=2
        app.data.schema.namespaces=feeds
        app.data.schema.namespace.feeds.current=2
        %s
        """
                .formatted(
                    entry.appId(),
                    entry.name(),
                    entry.version(),
                    String.join(",", entry.permissions()),
                    extraManifestFields,
                    migrationFields)
            + apiCompatibilityManifestFields(entry));
    return plan;
  }

  private AppCatalogInstallPlan planWithRollbackIncompatibleTwoNamespaceAppDataMigration(
      AppCatalogEntry entry) throws IOException {
    AppCatalogInstallPlan plan = plan(entry);
    Files.writeString(
        plan.stagedBundleDirectory().resolve("cryptad-app.properties"),
        """
        manifest.version=1
        app.id=%s
        app.name=%s
        app.version=%s
        app.exec=bin/launch.sh
        app.permissions=%s
        app.data.schema.current=2
        app.data.schema.namespaces=feeds,archive
        app.data.schema.namespace.feeds.current=2
        app.data.schema.namespace.archive.current=2
        app.data.migrations=feeds-v1-v2,archive-v1-v2
        app.data.migration.feeds-v1-v2.namespace=feeds
        app.data.migration.feeds-v1-v2.from=1
        app.data.migration.feeds-v1-v2.to=2
        app.data.migration.feeds-v1-v2.command=bin/migrate-feed-data.sh
        app.data.migration.feeds-v1-v2.rollbackCompatible=false
        app.data.migration.feeds-v1-v2.requiresStopped=true
        app.data.migration.feeds-v1-v2.description=Upgrade feed records to schema v2.
        app.data.migration.archive-v1-v2.namespace=archive
        app.data.migration.archive-v1-v2.from=1
        app.data.migration.archive-v1-v2.to=2
        app.data.migration.archive-v1-v2.command=bin/migrate-feed-data.sh
        app.data.migration.archive-v1-v2.rollbackCompatible=false
        app.data.migration.archive-v1-v2.requiresStopped=true
        app.data.migration.archive-v1-v2.description=Upgrade archived feed records to schema v2.
        """
                .formatted(
                    entry.appId(),
                    entry.name(),
                    entry.version(),
                    String.join(",", entry.permissions()))
            + apiCompatibilityManifestFields(entry));
    return plan;
  }

  private AppCatalogInstallPlan planWithChainedAppDataMigration(AppCatalogEntry entry)
      throws IOException {
    AppCatalogInstallPlan plan = plan(entry);
    Files.writeString(
        plan.stagedBundleDirectory().resolve("cryptad-app.properties"),
        """
        manifest.version=1
        app.id=%s
        app.name=%s
        app.version=%s
        app.exec=bin/launch.sh
        app.permissions=%s
        app.data.schema.current=3
        app.data.schema.namespaces=feeds
        app.data.schema.namespace.feeds.current=3
        app.data.migrations=feeds-v1-v2,feeds-v2-v3
        app.data.migration.feeds-v1-v2.namespace=feeds
        app.data.migration.feeds-v1-v2.from=1
        app.data.migration.feeds-v1-v2.to=2
        app.data.migration.feeds-v1-v2.command=bin/migrate-feed-data.sh
        app.data.migration.feeds-v1-v2.rollbackCompatible=true
        app.data.migration.feeds-v1-v2.requiresStopped=true
        app.data.migration.feeds-v1-v2.description=Upgrade feed records to schema v2.
        app.data.migration.feeds-v2-v3.namespace=feeds
        app.data.migration.feeds-v2-v3.from=2
        app.data.migration.feeds-v2-v3.to=3
        app.data.migration.feeds-v2-v3.command=bin/migrate-feed-data.sh
        app.data.migration.feeds-v2-v3.rollbackCompatible=true
        app.data.migration.feeds-v2-v3.requiresStopped=true
        app.data.migration.feeds-v2-v3.description=Upgrade feed records to schema v3.
        """
                .formatted(
                    entry.appId(),
                    entry.name(),
                    entry.version(),
                    String.join(",", entry.permissions()))
            + apiCompatibilityManifestFields(entry));
    return plan;
  }

  private AppCatalogInstallPlan planWithDeadEndBranchAppDataMigration(AppCatalogEntry entry)
      throws IOException {
    return planWithBranchingAppDataMigration(
        entry,
        """
        app.data.migrations=feeds-v1-v3,feeds-v1-v2,feeds-v2-v4
        app.data.migration.feeds-v1-v3.namespace=feeds
        app.data.migration.feeds-v1-v3.from=1
        app.data.migration.feeds-v1-v3.to=3
        app.data.migration.feeds-v1-v3.command=bin/migrate-feed-data.sh
        app.data.migration.feeds-v1-v3.rollbackCompatible=true
        app.data.migration.feeds-v1-v3.requiresStopped=true
        app.data.migration.feeds-v1-v3.description=Dead-end feed records migration.
        app.data.migration.feeds-v1-v2.namespace=feeds
        app.data.migration.feeds-v1-v2.from=1
        app.data.migration.feeds-v1-v2.to=2
        app.data.migration.feeds-v1-v2.command=bin/migrate-feed-data.sh
        app.data.migration.feeds-v1-v2.rollbackCompatible=true
        app.data.migration.feeds-v1-v2.requiresStopped=true
        app.data.migration.feeds-v1-v2.description=Upgrade feed records to schema v2.
        app.data.migration.feeds-v2-v4.namespace=feeds
        app.data.migration.feeds-v2-v4.from=2
        app.data.migration.feeds-v2-v4.to=4
        app.data.migration.feeds-v2-v4.command=bin/migrate-feed-data.sh
        app.data.migration.feeds-v2-v4.rollbackCompatible=true
        app.data.migration.feeds-v2-v4.requiresStopped=true
        app.data.migration.feeds-v2-v4.description=Upgrade feed records to schema v4.
        """);
  }

  private AppCatalogInstallPlan planWithCompatibleAlternativeAppDataMigration(AppCatalogEntry entry)
      throws IOException {
    return planWithBranchingAppDataMigration(
        entry,
        """
        app.data.migrations=feeds-v1-v4,feeds-v1-v2,feeds-v2-v4
        app.data.migration.feeds-v1-v4.namespace=feeds
        app.data.migration.feeds-v1-v4.from=1
        app.data.migration.feeds-v1-v4.to=4
        app.data.migration.feeds-v1-v4.command=bin/migrate-feed-data.sh
        app.data.migration.feeds-v1-v4.rollbackCompatible=false
        app.data.migration.feeds-v1-v4.requiresStopped=true
        app.data.migration.feeds-v1-v4.description=Direct feed records migration.
        app.data.migration.feeds-v1-v2.namespace=feeds
        app.data.migration.feeds-v1-v2.from=1
        app.data.migration.feeds-v1-v2.to=2
        app.data.migration.feeds-v1-v2.command=bin/migrate-feed-data.sh
        app.data.migration.feeds-v1-v2.rollbackCompatible=true
        app.data.migration.feeds-v1-v2.requiresStopped=true
        app.data.migration.feeds-v1-v2.description=Upgrade feed records to schema v2.
        app.data.migration.feeds-v2-v4.namespace=feeds
        app.data.migration.feeds-v2-v4.from=2
        app.data.migration.feeds-v2-v4.to=4
        app.data.migration.feeds-v2-v4.command=bin/migrate-feed-data.sh
        app.data.migration.feeds-v2-v4.rollbackCompatible=true
        app.data.migration.feeds-v2-v4.requiresStopped=true
        app.data.migration.feeds-v2-v4.description=Upgrade feed records to schema v4.
        """);
  }

  private AppCatalogInstallPlan planWithBranchingAppDataMigration(
      AppCatalogEntry entry, String migrationFields) throws IOException {
    AppCatalogInstallPlan plan = plan(entry);
    Files.writeString(
        plan.stagedBundleDirectory().resolve("cryptad-app.properties"),
        """
        manifest.version=1
        app.id=%s
        app.name=%s
        app.version=%s
        app.exec=bin/launch.sh
        app.permissions=%s
        app.data.schema.current=4
        app.data.schema.namespaces=feeds
        app.data.schema.namespace.feeds.current=4
        %s
        """
                .formatted(
                    entry.appId(),
                    entry.name(),
                    entry.version(),
                    String.join(",", entry.permissions()),
                    migrationFields)
            + apiCompatibilityManifestFields(entry));
    return plan;
  }

  private static String apiCompatibilityManifestFields(AppCatalogEntry entry) {
    AppApiCompatibilityMetadata api = entry.compatibility().apiCompatibility();
    StringBuilder fields = new StringBuilder();
    if (api.minimumVersion() != null) {
      fields.append("api.minimumVersion=").append(api.minimumVersion()).append('\n');
    }
    if (api.maximumTestedVersion() != null) {
      fields.append("api.maximumTestedVersion=").append(api.maximumTestedVersion()).append('\n');
    }
    if (!api.optionalCapabilities().isEmpty()) {
      fields
          .append("api.optionalCapabilities=")
          .append(String.join(",", api.optionalCapabilities()))
          .append('\n');
    }
    if (api.targetStabilityDeclared()) {
      fields
          .append("api.targetStability=")
          .append(api.targetStability().manifestValue())
          .append('\n');
    }
    if (api.targetBaselineDeclared()) {
      fields.append("api.targetBaseline=").append(api.targetBaseline()).append('\n');
    }
    if (api.experimentalCapabilitiesAcceptedDeclared()) {
      fields
          .append("api.experimentalCapabilitiesAccepted=")
          .append(api.experimentalCapabilitiesAccepted())
          .append('\n');
    }
    return fields.toString();
  }
}
