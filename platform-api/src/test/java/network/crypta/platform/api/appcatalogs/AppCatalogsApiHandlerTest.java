package network.crypta.platform.api.appcatalogs;

import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import network.crypta.platform.api.PlatformApiException;
import network.crypta.platform.api.appupdates.CatalogSourceSwitchConsent;
import network.crypta.platform.appcatalog.AppCatalogBundleVerificationResult;
import network.crypta.platform.appcatalog.AppCatalogChangelog;
import network.crypta.platform.appcatalog.AppCatalogChannel;
import network.crypta.platform.appcatalog.AppCatalogCompatibilityMetadata;
import network.crypta.platform.appcatalog.AppCatalogDeprecationStatus;
import network.crypta.platform.appcatalog.AppCatalogEntry;
import network.crypta.platform.appcatalog.AppCatalogException;
import network.crypta.platform.appcatalog.AppCatalogFetchStatus;
import network.crypta.platform.appcatalog.AppCatalogInstallPlan;
import network.crypta.platform.appcatalog.AppCatalogMaintenanceMetadata;
import network.crypta.platform.appcatalog.AppCatalogManager;
import network.crypta.platform.appcatalog.AppCatalogMirror;
import network.crypta.platform.appcatalog.AppCatalogMirrorHealth;
import network.crypta.platform.appcatalog.AppCatalogMirrorId;
import network.crypta.platform.appcatalog.AppCatalogOriginContext;
import network.crypta.platform.appcatalog.AppCatalogProductionMetadata;
import network.crypta.platform.appcatalog.AppCatalogReviewMetadata;
import network.crypta.platform.appcatalog.AppCatalogReviewStatus;
import network.crypta.platform.appcatalog.AppCatalogSecurityAction;
import network.crypta.platform.appcatalog.AppCatalogSecurityAdvisory;
import network.crypta.platform.appcatalog.AppCatalogSecurityAdvisoryRecord;
import network.crypta.platform.appcatalog.AppCatalogSecurityDecision;
import network.crypta.platform.appcatalog.AppCatalogSecurityDecisionStatus;
import network.crypta.platform.appcatalog.AppCatalogSecurityPolicy;
import network.crypta.platform.appcatalog.AppCatalogSecuritySeverity;
import network.crypta.platform.appcatalog.AppCatalogSecurityStatus;
import network.crypta.platform.appcatalog.AppCatalogSource;
import network.crypta.platform.appcatalog.AppCatalogSourceRole;
import network.crypta.platform.appcatalog.AppCatalogSourceSnapshot;
import network.crypta.platform.appcatalog.AppCatalogSupportStatus;
import network.crypta.platform.appcatalog.AppCatalogVersionDenylistEntry;
import network.crypta.platform.appcatalog.AppReviewPolicy;
import network.crypta.platform.appcatalog.AppReviewPolicyMode;
import network.crypta.platform.appcatalog.AppReviewReceipt;
import network.crypta.platform.appcatalog.AppReviewReceiptPayload;
import network.crypta.platform.appcatalog.AppReviewReceiptSigner;
import network.crypta.platform.appcatalog.AppReviewReceiptStatus;
import network.crypta.platform.appcatalog.AppReviewTransparencyEventKind;
import network.crypta.platform.appcatalog.AppReviewTransparencyLog;
import network.crypta.platform.appcatalog.CatalogPublisherAuthorizationException;
import network.crypta.platform.appcatalog.CatalogScopedReviewerPolicy;
import network.crypta.platform.appcatalog.RecommendedAppCatalog;
import network.crypta.platform.appcatalog.RecommendedAppCatalogs;
import network.crypta.platform.appcatalog.TrustedReviewerKey;
import network.crypta.platform.appcatalog.TrustedReviewerKeyLifecycle;
import network.crypta.platform.appcatalog.TrustedReviewerKeyStatus;
import network.crypta.platform.appcatalog.TrustedReviewerKeys;
import network.crypta.platform.appdist.AppApiCompatibilityMetadata.TargetStability;
import network.crypta.platform.appdist.AppApiCompatibilityMetadata;
import network.crypta.platform.appdist.AppDataSchemaContract;
import network.crypta.platform.appdist.AppUiMode;
import network.crypta.platform.apphost.AppHost;
import network.crypta.platform.apphost.InstalledAppOrigin;
import network.crypta.platform.apphost.InstalledAppPaths;
import network.crypta.platform.apphost.InstalledAppSnapshot;
import network.crypta.platform.apphost.manifest.AppManifest;
import network.crypta.platform.apphost.manifest.AppManifestParser;
import network.crypta.platform.appvault.AppIdentityGrant;
import network.crypta.platform.appvault.AppIdentityGrantScope;
import network.crypta.platform.appvault.AppIdentityGrantStatus;
import network.crypta.platform.appvault.AppIdentityKind;
import network.crypta.platform.appvault.AppIdentityRecord;
import network.crypta.platform.appvault.AppVaultService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings({"java:S100", "unchecked", "resource"})
class AppCatalogsApiHandlerTest {
  private static final String APP_ID = "queue-manager";
  private static final String REVIEWER_KEY_ID = "crypta-first-party-review";
  private static final String REVIEW_POLICY_ID = "crypta-app-review-v1";
  private static final String REVIEW_POLICY_VERSION = "1";
  private static final String FIRST_PARTY_SOURCE =
      "crypta:USK@example/catalog/cryptad-app-catalog.properties";
  private static final String FIRST_PARTY_TRUSTED_KEY_ID = "first-party-catalog";
  private static final String GENERATED_AT_TEXT = "2026-04-24T12:00:00Z";
  private static final String REFRESHED_AT_TEXT = "2026-04-24T12:02:00Z";
  private static final String PRIMARY_REFRESHED_AT_TEXT = "2026-04-24T12:05:00Z";
  private static final String CORE_CATALOG_NAME = "Core Apps";
  private static final String CORE_CATALOG_SOURCE =
      "https://example.invalid/cryptad-app-catalog.properties";
  private static final String CATALOG_SOURCE_URI_TEXT = "https://catalog.example.invalid/catalog";
  private static final String CORE_CATALOG_KEY_ID = "core-catalog-key";
  private static final String PRIMARY_CATALOG_DIGEST = "sha256:primary";
  private static final String CATALOG_ID_FIELD = "catalogId";
  private static final String SOURCE_FIELD = "source";
  private static final String HTTPS_SOURCE_KIND = "https";
  private static final String SOURCE_KIND_FIELD = "sourceKind";
  private static final String STATUS_FIELD = "status";
  private static final String CHANNEL_FIELD = "channel";
  private static final String CONFIGURED_TEXT = "configured";
  private static final String TRUSTED_CATALOG_KEY_CONFIGURED_FIELD = "trustedCatalogKeyConfigured";
  private static final String CAN_ADD_FIELD = "canAdd";
  private static final String MISSING_CONFIGURATION_FIELD = "missingConfiguration";
  private static final String UNKNOWN_STATUS = "unknown";
  private static final String APP_ID_FIELD = "appId";
  private static final String REPLACEMENT_APP_ID_FIELD = "replacementAppId";
  private static final String ACTIVE_ADVISORIES_FIELD = "activeAdvisories";
  private static final String VERSION_FIELD = "version";
  private static final String CATALOG_VERSION = "1.2.0";
  private static final String INSTALLED_VERSION_FIELD = "installedVersion";
  private static final String INSTALLED_VERSION = "1.1.0";
  private static final String INSTALLED_TEXT = "installed";
  private static final String VERSION_DIFFERENT_FIELD = "versionDifferent";
  private static final String UPDATE_AVAILABLE_FIELD = "updateAvailable";
  private static final String VERSION_STATUS_FIELD = "versionStatus";
  private static final String DIFFERENT_STATUS = "different";
  private static final String CATEGORIES_FIELD = "categories";
  private static final String HOMEPAGE_FIELD = "homepage";
  private static final String LICENSE_FIELD = "license";
  private static final String SUPPORT_STATUS_FIELD = "supportStatus";
  private static final String SECURITY_ADVISORY_ID_0001 = "CRYPTA-2026-0001";
  private static final String SECURITY_ADVISORY_URI_0001 =
      "https://example.invalid/advisories/CRYPTA-2026-0001";
  private static final String ADVISORY_FIELD = "advisory";
  private static final String REVIEW_TRUST_FIELD = "reviewTrust";
  private static final String TRUSTED_FIELD = "trusted";
  private static final String POSITIVE_FIELD = "positive";
  private static final String BLOCKS_INSTALL_FIELD = "blocksInstall";
  private static final String QUEUE_READ_PERMISSION = "queue.read";
  private static final String QUEUE_WRITE_PERMISSION = "queue.write";
  private static final String CURRENT_CRYPTA_VERSION = "0.2.0";
  private static final String COMPATIBILITY_FIELD = "compatibility";
  private static final String MINIMUM_CRYPTA_VERSION_FIELD = "minimumCryptaVersion";
  private static final String CURRENT_CRYPTA_VERSION_FIELD = "currentCryptaVersion";
  private static final String SATISFIED_TEXT = "satisfied";
  private static final String SUMMARY_FIELD = "summary";
  private static final String NEWER_VERSION = "1.3.0";
  private static final String API_TEST_TRACE_LABEL = "api-test";
  private static final String ACTIVE_STATUS = "active";
  private static final String KEY_ID_FIELD = "keyId";
  private static final String REVIEWER_DISPLAY_NAME = "Crypta First-Party Review";
  private static final String ACTIVE_ADVISORY_COUNT_FIELD = "activeAdvisoryCount";
  private static final String DENYLISTED_VERSION_COUNT_FIELD = "denylistedVersionCount";
  private static final String REVOKED_REVIEWER_KEY_COUNT_FIELD = "revokedReviewerKeyCount";
  private static final String SECURITY_ADVISORY_ID_0002 = "CRYPTA-2026-0002";
  private static final String TRUSTED_REVIEWED_STATUS = "trusted_reviewed";
  private static final String APP_REVIEW_MISSING_ERROR = "app_review_missing";
  private static final String APP_SECURITY_DENYLISTED_ERROR = "app_security_denylisted";
  private static final String SOURCE_SWITCH_CONSENT_PARAMETER = "sourceSwitchConsent";
  private static final String BUNDLE_DIRECTORY = "bundle";
  private static final String EXPORT_BEFORE_REMOVAL_GUIDANCE = "Export app data before removal.";
  private static final String KNOWN_VULNERABLE_RELEASE = "Known vulnerable release.";
  private static final String SECURITY_POLICY_UPDATED_AT_TEXT = "2026-06-12T00:00:00Z";
  private static final String VAULT_DIRECTORY = "vault";
  private static final String QUEUE_MANAGER_NAME = "Queue Manager";
  private static final String QUEUE_MANAGER_SUMMARY = "Manage local Crypta transfer queues.";
  private static final String QUEUE_MANAGER_BUNDLE_URI =
      "https://example.invalid/apps/queue-manager.zip";
  private static final Instant REVIEWED_AT = Instant.parse("2026-05-01T00:00:00Z");

  @Mock private AppCatalogManager catalogManager;
  @Mock private AppHost appHost;

  @TempDir private Path tempDir;

  @Test
  void listCatalogs_whenSnapshotHasSourceUri_expectSourceKindAndSyncFields() throws Exception {
    AppCatalogsApiHandler handler = new AppCatalogsApiHandler(catalogManager, appHost, () -> null);
    Instant generatedAt = Instant.parse(GENERATED_AT_TEXT);
    Instant addedAt = Instant.parse("2026-04-24T12:01:00Z");
    Instant refreshedAt = Instant.parse(REFRESHED_AT_TEXT);
    AppCatalogSourceSnapshot snapshot =
        new AppCatalogSourceSnapshot(
            "core",
            CORE_CATALOG_NAME,
            URI.create(CORE_CATALOG_SOURCE),
            generatedAt,
            2,
            addedAt,
            refreshedAt,
            refreshedAt,
            refreshedAt,
            AppCatalogFetchStatus.SUCCESS,
            Optional.empty(),
            Optional.empty(),
            Optional.of(CORE_CATALOG_SOURCE),
            Optional.of(CORE_CATALOG_KEY_ID));
    when(catalogManager.listCatalogs()).thenReturn(List.of(snapshot));

    Map<String, Object> catalog = handler.listCatalogs().getFirst();

    assertEquals("core", catalog.get(CATALOG_ID_FIELD));
    assertEquals(CORE_CATALOG_NAME, catalog.get("name"));
    assertEquals(CORE_CATALOG_SOURCE, catalog.get(SOURCE_FIELD));
    assertEquals(HTTPS_SOURCE_KIND, catalog.get("sourceType"));
    assertEquals(HTTPS_SOURCE_KIND, catalog.get(SOURCE_KIND_FIELD));
    assertEquals(generatedAt.toString(), catalog.get("generatedAt"));
    assertEquals(2, catalog.get("appCount"));
    assertEquals(addedAt.toString(), catalog.get("addedAt"));
    assertEquals(refreshedAt.toString(), catalog.get("refreshedAt"));
    assertEquals(refreshedAt.toString(), catalog.get("lastAttemptAt"));
    assertEquals(refreshedAt.toString(), catalog.get("lastSuccessfulRefreshAt"));
    assertEquals("success", catalog.get("lastFetchStatus"));
    assertNull(catalog.get("lastFetchErrorCode"));
    assertNull(catalog.get("lastFetchErrorMessage"));
    assertEquals(CORE_CATALOG_SOURCE, catalog.get("lastResolvedUri"));
    assertEquals(CORE_CATALOG_KEY_ID, catalog.get("signatureKeyId"));
  }

  @Test
  void health_whenSourcesContainPathsAndTokens_expectOperationsOutputRedacted() throws Exception {
    AppCatalogsApiHandler handler = new AppCatalogsApiHandler(catalogManager, appHost, () -> null);
    Instant generatedAt = Instant.parse(GENERATED_AT_TEXT);
    Instant refreshedAt = Instant.parse(REFRESHED_AT_TEXT);
    String privatePathSource = tempDir.resolve("private/cryptad-app-catalog.properties").toString();
    AppCatalogSource privateSource = AppCatalogSource.parse(privatePathSource);
    AppCatalogSourceSnapshot snapshot =
        new AppCatalogSourceSnapshot(
            "core",
            CORE_CATALOG_NAME,
            privateSource.uri(),
            generatedAt,
            2,
            refreshedAt,
            refreshedAt,
            refreshedAt,
            refreshedAt,
            AppCatalogFetchStatus.SUCCESS,
            Optional.empty(),
            Optional.empty(),
            Optional.of(privateSource.resolvedCatalogFetchUri()),
            Optional.of(CORE_CATALOG_KEY_ID));
    AppCatalogMirror mirror =
        new AppCatalogMirror(
            AppCatalogMirrorId.parse("backup"),
            AppCatalogSourceRole.MIRROR,
            AppCatalogSource.parse(
                "https://mirror.example.invalid/cryptad-app-catalog.properties?token=secret"),
            1,
            true,
            refreshedAt);
    List<AppCatalogMirrorHealth> health =
        List.of(
            new AppCatalogMirrorHealth(
                AppCatalogMirrorId.PRIMARY,
                AppCatalogSourceRole.PRIMARY,
                AppCatalogFetchStatus.SUCCESS,
                Optional.of(refreshedAt),
                Optional.of(refreshedAt),
                Optional.empty(),
                Optional.empty(),
                Optional.of(privateSource.resolvedCatalogFetchUri()),
                Optional.of("sha256:active"),
                Optional.of(CORE_CATALOG_KEY_ID),
                Optional.of(generatedAt),
                Optional.of("rollback after incident")),
            new AppCatalogMirrorHealth(
                mirror.id(),
                mirror.role(),
                AppCatalogFetchStatus.FAILED,
                Optional.of(refreshedAt),
                Optional.empty(),
                Optional.of("catalog_fetch_failed"),
                Optional.of("fetch failed"),
                Optional.of(
                    "https://mirror.example.invalid/cryptad-app-catalog.properties?token=secret"),
                Optional.empty(),
                Optional.empty(),
                Optional.empty()));
    when(catalogManager.catalog("core")).thenReturn(snapshot);
    when(catalogManager.sourceHealth("core")).thenReturn(health);
    when(catalogManager.listMirrors("core"))
        .thenReturn(List.of(AppCatalogMirror.primary(privateSource, refreshedAt), mirror));

    Map<String, Object> response = handler.health("core");
    String rendered = response.toString();

    assertEquals("core", response.get(CATALOG_ID_FIELD));
    assertEquals("sha256:active", response.get("catalogDigest"));
    assertEquals(true, response.get("redacted"));
    List<Map<String, Object>> sourceHealth =
        (List<Map<String, Object>>) response.get("sourceHealth");
    assertEquals("rollback after incident", sourceHealth.getFirst().get("lastRollbackReason"));
    assertFalse(rendered.contains(tempDir.toString()));
    assertFalse(rendered.contains("secret"));
    assertFalse(rendered.contains("token="));
    assertTrue(rendered.contains("file:<configured>"));
  }

  @Test
  void health_whenMirrorSuccessIsOlderThanPrimarySuccess_expectPrimaryReportedActive()
      throws Exception {
    AppCatalogsApiHandler handler = new AppCatalogsApiHandler(catalogManager, appHost, () -> null);
    Instant generatedAt = Instant.parse(GENERATED_AT_TEXT);
    Instant mirrorRefreshedAt = Instant.parse(REFRESHED_AT_TEXT);
    Instant primaryRefreshedAt = Instant.parse(PRIMARY_REFRESHED_AT_TEXT);
    AppCatalogSource source = AppCatalogSource.parse(CATALOG_SOURCE_URI_TEXT);
    AppCatalogSourceSnapshot snapshot =
        new AppCatalogSourceSnapshot(
            "core",
            CORE_CATALOG_NAME,
            source.uri(),
            generatedAt,
            2,
            primaryRefreshedAt,
            primaryRefreshedAt,
            primaryRefreshedAt,
            primaryRefreshedAt,
            AppCatalogFetchStatus.SUCCESS,
            Optional.empty(),
            Optional.empty(),
            Optional.of(source.resolvedCatalogFetchUri()),
            Optional.of(CORE_CATALOG_KEY_ID));
    AppCatalogMirror mirror =
        new AppCatalogMirror(
            AppCatalogMirrorId.parse("backup"),
            AppCatalogSourceRole.MIRROR,
            AppCatalogSource.parse("https://mirror.example.invalid/catalog"),
            1,
            true,
            mirrorRefreshedAt);
    List<AppCatalogMirrorHealth> health =
        List.of(
            new AppCatalogMirrorHealth(
                AppCatalogMirrorId.PRIMARY,
                AppCatalogSourceRole.PRIMARY,
                AppCatalogFetchStatus.SUCCESS,
                Optional.of(primaryRefreshedAt),
                Optional.of(primaryRefreshedAt),
                Optional.empty(),
                Optional.empty(),
                Optional.of(source.resolvedCatalogFetchUri()),
                Optional.of(PRIMARY_CATALOG_DIGEST),
                Optional.of(CORE_CATALOG_KEY_ID),
                Optional.of(generatedAt)),
            new AppCatalogMirrorHealth(
                mirror.id(),
                mirror.role(),
                AppCatalogFetchStatus.SUCCESS,
                Optional.of(mirrorRefreshedAt),
                Optional.of(mirrorRefreshedAt),
                Optional.empty(),
                Optional.empty(),
                Optional.of(mirror.source().resolvedCatalogFetchUri()),
                Optional.of("sha256:mirror"),
                Optional.of(CORE_CATALOG_KEY_ID),
                Optional.of(generatedAt.minusSeconds(60))));
    when(catalogManager.catalog("core")).thenReturn(snapshot);
    when(catalogManager.sourceHealth("core")).thenReturn(health);
    when(catalogManager.listMirrors("core"))
        .thenReturn(List.of(AppCatalogMirror.primary(source, primaryRefreshedAt), mirror));

    Map<String, Object> response = handler.health("core");

    assertEquals(false, response.get("fallbackUsed"));
    assertEquals("primary", response.get("activeSourceId"));
    assertEquals(PRIMARY_CATALOG_DIGEST, response.get("catalogDigest"));
  }

  @Test
  void health_whenReadingOneCatalog_expectDoesNotListAllCatalogs() throws Exception {
    AppCatalogsApiHandler handler = new AppCatalogsApiHandler(catalogManager, appHost, () -> null);
    Instant generatedAt = Instant.parse(GENERATED_AT_TEXT);
    Instant refreshedAt = Instant.parse(PRIMARY_REFRESHED_AT_TEXT);
    AppCatalogSource source = AppCatalogSource.parse(CATALOG_SOURCE_URI_TEXT);
    AppCatalogSourceSnapshot snapshot =
        new AppCatalogSourceSnapshot(
            "core",
            CORE_CATALOG_NAME,
            source.uri(),
            generatedAt,
            2,
            refreshedAt,
            refreshedAt,
            refreshedAt,
            refreshedAt,
            AppCatalogFetchStatus.SUCCESS,
            Optional.empty(),
            Optional.empty(),
            Optional.of(source.resolvedCatalogFetchUri()),
            Optional.of(CORE_CATALOG_KEY_ID));
    List<AppCatalogMirrorHealth> health =
        List.of(
            new AppCatalogMirrorHealth(
                AppCatalogMirrorId.PRIMARY,
                AppCatalogSourceRole.PRIMARY,
                AppCatalogFetchStatus.SUCCESS,
                Optional.of(refreshedAt),
                Optional.of(refreshedAt),
                Optional.empty(),
                Optional.empty(),
                Optional.of(source.resolvedCatalogFetchUri()),
                Optional.of(PRIMARY_CATALOG_DIGEST),
                Optional.of(CORE_CATALOG_KEY_ID),
                Optional.of(generatedAt)));
    when(catalogManager.catalog("core")).thenReturn(snapshot);
    when(catalogManager.sourceHealth("core")).thenReturn(health);
    when(catalogManager.listMirrors("core"))
        .thenReturn(List.of(AppCatalogMirror.primary(source, refreshedAt)));

    Map<String, Object> response = handler.health("core");

    assertEquals("core", response.get(CATALOG_ID_FIELD));
    verify(catalogManager, never()).listCatalogs();
  }

  @Test
  void rollback_whenReasonSupplied_expectReasonReturnedAndDelegated() throws Exception {
    AppCatalogsApiHandler handler = new AppCatalogsApiHandler(catalogManager, appHost, () -> null);
    AppCatalogSourceSnapshot snapshot = firstPartyCatalogSnapshot();
    String rollbackReason = " operator rollback after bad publication ";
    when(catalogManager.rollback("core", PRIMARY_CATALOG_DIGEST, rollbackReason))
        .thenReturn(snapshot);

    Map<String, Object> response =
        handler.rollback(
            "core",
            Map.of(
                "revisionDigest",
                List.of(PRIMARY_CATALOG_DIGEST),
                "reason",
                List.of(rollbackReason)));

    assertEquals("core", response.get(CATALOG_ID_FIELD));
    assertEquals(true, response.get("rolledBack"));
    assertEquals("operator rollback after bad publication", response.get("reason"));
    verify(catalogManager).rollback("core", PRIMARY_CATALOG_DIGEST, rollbackReason);
  }

  @Test
  void emergencyRefresh_whenCachedPolicyCannotVerify_expectRefreshStillRuns() throws Exception {
    AppCatalogsApiHandler handler = new AppCatalogsApiHandler(catalogManager, appHost, () -> null);
    Instant generatedAt = Instant.parse(GENERATED_AT_TEXT);
    Instant refreshedAt = Instant.parse(PRIMARY_REFRESHED_AT_TEXT);
    AppCatalogSource source = AppCatalogSource.parse(CATALOG_SOURCE_URI_TEXT);
    AppCatalogSourceSnapshot snapshot =
        new AppCatalogSourceSnapshot(
            "core",
            CORE_CATALOG_NAME,
            source.uri(),
            generatedAt,
            2,
            refreshedAt,
            refreshedAt,
            refreshedAt,
            refreshedAt,
            AppCatalogFetchStatus.SUCCESS,
            Optional.empty(),
            Optional.empty(),
            Optional.of(source.resolvedCatalogFetchUri()),
            Optional.of(CORE_CATALOG_KEY_ID));
    List<AppCatalogMirrorHealth> health =
        List.of(
            new AppCatalogMirrorHealth(
                AppCatalogMirrorId.PRIMARY,
                AppCatalogSourceRole.PRIMARY,
                AppCatalogFetchStatus.SUCCESS,
                Optional.of(refreshedAt),
                Optional.of(refreshedAt),
                Optional.empty(),
                Optional.empty(),
                Optional.of(source.resolvedCatalogFetchUri()),
                Optional.of(PRIMARY_CATALOG_DIGEST),
                Optional.of(CORE_CATALOG_KEY_ID),
                Optional.of(generatedAt)));
    when(catalogManager.securityPolicy("core"))
        .thenThrow(new AppCatalogException("catalog_signature_untrusted", "cached key removed"))
        .thenReturn(AppCatalogSecurityPolicy.EMPTY);
    when(catalogManager.emergencyRefresh("core")).thenReturn(snapshot);
    when(catalogManager.sourceHealth("core")).thenReturn(health);

    Map<String, Object> response = handler.emergencyRefresh("core");

    assertEquals("success", response.get(STATUS_FIELD));
    assertEquals(false, response.get("fallbackUsed"));
    assertEquals("primary", response.get("activeSourceId"));
    verify(catalogManager).emergencyRefresh("core");
  }

  @Test
  void emergencyRefresh_whenDenylistEntryIsReplaced_expectAddedEntryCountByIdentity()
      throws Exception {
    AppCatalogsApiHandler handler = new AppCatalogsApiHandler(catalogManager, appHost, () -> null);
    Instant generatedAt = Instant.parse(GENERATED_AT_TEXT);
    Instant refreshedAt = Instant.parse(PRIMARY_REFRESHED_AT_TEXT);
    AppCatalogSource source = AppCatalogSource.parse(CATALOG_SOURCE_URI_TEXT);
    AppCatalogSourceSnapshot snapshot =
        new AppCatalogSourceSnapshot(
            "core",
            CORE_CATALOG_NAME,
            source.uri(),
            generatedAt,
            2,
            refreshedAt,
            refreshedAt,
            refreshedAt,
            refreshedAt,
            AppCatalogFetchStatus.SUCCESS,
            Optional.empty(),
            Optional.empty(),
            Optional.of(source.resolvedCatalogFetchUri()),
            Optional.of(CORE_CATALOG_KEY_ID));
    List<AppCatalogMirrorHealth> health =
        List.of(
            new AppCatalogMirrorHealth(
                AppCatalogMirrorId.PRIMARY,
                AppCatalogSourceRole.PRIMARY,
                AppCatalogFetchStatus.SUCCESS,
                Optional.of(refreshedAt),
                Optional.of(refreshedAt),
                Optional.empty(),
                Optional.empty(),
                Optional.of(source.resolvedCatalogFetchUri()),
                Optional.of(PRIMARY_CATALOG_DIGEST),
                Optional.of(CORE_CATALOG_KEY_ID),
                Optional.of(generatedAt)));
    AppCatalogSecurityPolicy beforePolicy = securityResponsePolicy();
    AppCatalogVersionDenylistEntry replacementDenylist =
        new AppCatalogVersionDenylistEntry(
            "deny-queue-1-3-0",
            APP_ID,
            NEWER_VERSION,
            SECURITY_ADVISORY_ID_0001,
            "New vulnerable release.",
            Optional.of(APP_ID),
            Optional.of(EXPORT_BEFORE_REMOVAL_GUIDANCE));
    AppCatalogSecurityPolicy afterPolicy =
        new AppCatalogSecurityPolicy(beforePolicy.advisories(), List.of(replacementDenylist));
    when(catalogManager.securityPolicy("core")).thenReturn(beforePolicy).thenReturn(afterPolicy);
    when(catalogManager.emergencyRefresh("core")).thenReturn(snapshot);
    when(catalogManager.sourceHealth("core")).thenReturn(health);

    Map<String, Object> response = handler.emergencyRefresh("core");

    assertEquals(1, response.get("denylistEntriesAdded"));
  }

  @Test
  void listRecommendedCatalogs_whenSourceAndTrustedKeyAreMissing_expectNotConfiguredStatus() {
    AppCatalogsApiHandler handler = handlerWithRecommended(List.of(recommended(null, null)));

    Map<String, Object> catalog = handler.listRecommendedCatalogs().getFirst();

    assertEquals(RecommendedAppCatalogs.FIRST_PARTY_BETA_CATALOG_ID, catalog.get(CATALOG_ID_FIELD));
    assertEquals("Crypta First-Party Beta Catalog", catalog.get("name"));
    assertEquals("beta", catalog.get(CHANNEL_FIELD));
    assertNull(catalog.get(SOURCE_KIND_FIELD));
    assertNull(catalog.get(SOURCE_FIELD));
    assertEquals(false, catalog.get("sourceConfigured"));
    assertEquals(false, catalog.get(CONFIGURED_TEXT));
    assertEquals(false, catalog.get(TRUSTED_CATALOG_KEY_CONFIGURED_FIELD));
    assertEquals(false, catalog.get(CAN_ADD_FIELD));
    assertEquals(
        List.of(SOURCE_FIELD, "trusted_catalog_key"), catalog.get(MISSING_CONFIGURATION_FIELD));
  }

  @Test
  void listRecommendedCatalogs_whenConfiguredAndTrusted_expectCanAddAndRedactedSource()
      throws Exception {
    AppCatalogsApiHandler handler =
        handlerWithRecommended(
            List.of(recommended(FIRST_PARTY_SOURCE, FIRST_PARTY_TRUSTED_KEY_ID)));
    when(catalogManager.hasTrustedCatalogKey(FIRST_PARTY_TRUSTED_KEY_ID)).thenReturn(true);

    Map<String, Object> catalog = handler.listRecommendedCatalogs().getFirst();

    assertEquals("crypta", catalog.get(SOURCE_KIND_FIELD));
    assertEquals("crypta:<configured>", catalog.get(SOURCE_FIELD));
    assertEquals(true, catalog.get("sourceConfigured"));
    assertEquals(true, catalog.get(TRUSTED_CATALOG_KEY_CONFIGURED_FIELD));
    assertEquals(true, catalog.get(CAN_ADD_FIELD));
    assertEquals(List.of(), catalog.get(MISSING_CONFIGURATION_FIELD));
    assertFalse(catalog.toString().contains("USK@example"));
  }

  @Test
  void listRecommendedCatalogs_whenHttpsSourceHasQuery_expectQueryRedacted() throws Exception {
    String sourceWithToken =
        "https://example.invalid/cryptad-app-catalog.properties?token=secret-value";
    AppCatalogsApiHandler handler =
        handlerWithRecommended(List.of(recommended(sourceWithToken, FIRST_PARTY_TRUSTED_KEY_ID)));
    when(catalogManager.hasTrustedCatalogKey(FIRST_PARTY_TRUSTED_KEY_ID)).thenReturn(true);

    Map<String, Object> catalog = handler.listRecommendedCatalogs().getFirst();

    assertEquals(HTTPS_SOURCE_KIND, catalog.get(SOURCE_KIND_FIELD));
    assertTrue(((String) catalog.get(SOURCE_FIELD)).contains("redacted"));
    assertFalse(catalog.toString().contains("secret-value"));
    assertFalse(catalog.toString().contains("token"));
  }

  @Test
  void listRecommendedCatalogs_whenFileSourceConfigured_expectPathRedacted() throws Exception {
    String source = tempDir.resolve("private/catalog.properties").toUri().toString();
    AppCatalogsApiHandler handler =
        handlerWithRecommended(List.of(recommended(source, FIRST_PARTY_TRUSTED_KEY_ID)));
    when(catalogManager.hasTrustedCatalogKey(FIRST_PARTY_TRUSTED_KEY_ID)).thenReturn(true);

    Map<String, Object> catalog = handler.listRecommendedCatalogs().getFirst();

    assertEquals("file", catalog.get(SOURCE_KIND_FIELD));
    assertEquals("file:<configured>", catalog.get(SOURCE_FIELD));
    assertFalse(catalog.toString().contains("catalog.properties"));
  }

  @Test
  void listRecommendedCatalogs_whenTrustedKeyLookupFails_expectMissingTrustedKeyStatus()
      throws Exception {
    AppCatalogsApiHandler handler =
        handlerWithRecommended(
            List.of(recommended(FIRST_PARTY_SOURCE, FIRST_PARTY_TRUSTED_KEY_ID)));
    when(catalogManager.hasTrustedCatalogKey(FIRST_PARTY_TRUSTED_KEY_ID))
        .thenThrow(new IOException("trusted key store unavailable"));

    Map<String, Object> catalog = handler.listRecommendedCatalogs().getFirst();

    assertEquals(false, catalog.get(TRUSTED_CATALOG_KEY_CONFIGURED_FIELD));
    assertEquals(false, catalog.get(CAN_ADD_FIELD));
    assertEquals(List.of("trusted_catalog_key"), catalog.get(MISSING_CONFIGURATION_FIELD));
    assertEquals(List.of("missing_trusted_catalog_key"), catalog.get("warnings"));
  }

  @Test
  void addRecommended_whenConfigurationIsReady_expectVerifiedAddSourceAndNoInstall()
      throws Exception {
    AppCatalogsApiHandler handler =
        handlerWithRecommended(
            List.of(recommended(FIRST_PARTY_SOURCE, FIRST_PARTY_TRUSTED_KEY_ID)));
    AppCatalogSourceSnapshot snapshot = firstPartyCatalogSnapshot();
    when(catalogManager.hasTrustedCatalogKey(FIRST_PARTY_TRUSTED_KEY_ID)).thenReturn(true);
    when(catalogManager.addSource(
            FIRST_PARTY_SOURCE, RecommendedAppCatalogs.FIRST_PARTY_BETA_CATALOG_ID))
        .thenReturn(snapshot);

    Map<String, Object> catalog =
        handler.addRecommended(RecommendedAppCatalogs.FIRST_PARTY_BETA_CATALOG_ID);

    assertEquals(RecommendedAppCatalogs.FIRST_PARTY_BETA_CATALOG_ID, catalog.get(CATALOG_ID_FIELD));
    verify(catalogManager)
        .addSource(FIRST_PARTY_SOURCE, RecommendedAppCatalogs.FIRST_PARTY_BETA_CATALOG_ID);
    verify(appHost, never()).installFromDirectory(any());
  }

  @Test
  void addRecommended_whenSourceIsMissing_expectStableSourceMissingError() {
    AppCatalogsApiHandler handler = handlerWithRecommended(List.of(recommended(null, null)));

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class,
            () -> handler.addRecommended(RecommendedAppCatalogs.FIRST_PARTY_BETA_CATALOG_ID));

    assertEquals(400, exception.statusCode());
    assertEquals("recommended_catalog_source_missing", exception.errorCode());
  }

  @Test
  void addRecommended_whenTrustedKeyIsMissing_expectStableTrustedKeyError() throws Exception {
    AppCatalogsApiHandler handler =
        handlerWithRecommended(
            List.of(recommended(FIRST_PARTY_SOURCE, FIRST_PARTY_TRUSTED_KEY_ID)));
    when(catalogManager.hasTrustedCatalogKey(FIRST_PARTY_TRUSTED_KEY_ID)).thenReturn(false);

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class,
            () -> handler.addRecommended(RecommendedAppCatalogs.FIRST_PARTY_BETA_CATALOG_ID));

    assertEquals(400, exception.statusCode());
    assertEquals("recommended_catalog_trusted_key_missing", exception.errorCode());
    verify(catalogManager, never()).addSource(any(), any());
  }

  @Test
  void addRecommended_whenAlreadyConfigured_expectStableAlreadyConfiguredError() throws Exception {
    AppCatalogsApiHandler handler =
        handlerWithRecommended(
            List.of(recommended(FIRST_PARTY_SOURCE, FIRST_PARTY_TRUSTED_KEY_ID)));
    when(catalogManager.configuredCatalogIds())
        .thenReturn(List.of(RecommendedAppCatalogs.FIRST_PARTY_BETA_CATALOG_ID));

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class,
            () -> handler.addRecommended(RecommendedAppCatalogs.FIRST_PARTY_BETA_CATALOG_ID));

    assertEquals(409, exception.statusCode());
    assertEquals("recommended_catalog_already_configured", exception.errorCode());
    verify(catalogManager, never()).addSource(any(), any());
  }

  @Test
  void addRecommended_whenIdIsUnknown_expectStableNotFoundError() {
    AppCatalogsApiHandler handler = handlerWithRecommended(List.of(recommended(null, null)));

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> handler.addRecommended(UNKNOWN_STATUS));

    assertEquals(404, exception.statusCode());
    assertEquals("recommended_catalog_not_found", exception.errorCode());
  }

  @Test
  void listCatalogs_whenCatalogSourceOrFetchFails_expectStableStatusCodes() throws Exception {
    assertCatalogFailureStatus("unsupported_catalog_source", 400);
    assertCatalogFailureStatus("invalid_catalog_source", 400);
    assertCatalogFailureStatus("catalog_fetch_unavailable", 503);
    assertCatalogFailureStatus("catalog_fetch_failed", 502);
    assertCatalogFailureStatus("invalid_catalog_signature", 400);
    assertCatalogFailureStatus("catalog_signature_missing", 400);
  }

  @Test
  void listApps_whenEntryHasStoreMetadataAndInstalledAppDiffers_expectReviewMetadata()
      throws Exception {
    Map<String, Object> app = listRichInstalledCatalogApp();

    assertEquals(
        Map.of(
            APP_ID_FIELD,
            APP_ID,
            VERSION_FIELD,
            CATALOG_VERSION,
            INSTALLED_VERSION_FIELD,
            INSTALLED_VERSION,
            INSTALLED_TEXT,
            true,
            VERSION_DIFFERENT_FIELD,
            true,
            UPDATE_AVAILABLE_FIELD,
            true,
            VERSION_STATUS_FIELD,
            DIFFERENT_STATUS),
        fields(
            app,
            APP_ID_FIELD,
            VERSION_FIELD,
            INSTALLED_VERSION_FIELD,
            INSTALLED_TEXT,
            VERSION_DIFFERENT_FIELD,
            UPDATE_AVAILABLE_FIELD,
            VERSION_STATUS_FIELD));
    assertEquals(
        Map.of(
            CATEGORIES_FIELD,
            List.of("productivity", "network"),
            HOMEPAGE_FIELD,
            "https://example.invalid/app",
            SOURCE_FIELD,
            "https://example.invalid/repo",
            LICENSE_FIELD,
            "MIT",
            CHANNEL_FIELD,
            "beta",
            SUPPORT_STATUS_FIELD,
            "experimental"),
        fields(
            app,
            CATEGORIES_FIELD,
            HOMEPAGE_FIELD,
            SOURCE_FIELD,
            LICENSE_FIELD,
            CHANNEL_FIELD,
            SUPPORT_STATUS_FIELD));
    Map<String, Object> maintenance = (Map<String, Object>) app.get("maintenance");
    assertEquals(
        Map.of(
            "owner",
            "crypta-core",
            "ownerUri",
            "https://example.invalid/crypta/owners/core",
            "supportLevel",
            "core",
            "dataSchemaPolicy",
            "stateless",
            "migrationPolicy",
            "none",
            "backupRestore",
            "not-applicable",
            "securityPolicy",
            "catalog-advisories",
            "deprecationPolicy",
            "none",
            "supportUri",
            "https://example.invalid/crypta/apps/queue-manager/support"),
        maintenance);
    Map<String, Object> deprecation = (Map<String, Object>) app.get("deprecation");
    assertEquals(
        Map.of(
            STATUS_FIELD,
            "deprecated",
            "message",
            "Use Queue Manager stable.",
            REPLACEMENT_APP_ID_FIELD,
            "queue-manager-stable"),
        deprecation);
    List<Map<String, Object>> advisories =
        (List<Map<String, Object>>) app.get("securityAdvisories");
    assertEquals(
        List.of(Map.of("id", SECURITY_ADVISORY_ID_0001, "uri", SECURITY_ADVISORY_URI_0001)),
        advisories);

    Map<String, Object> review = (Map<String, Object>) app.get("review");
    assertEquals(
        Map.of(
            STATUS_FIELD,
            "reviewed",
            "note",
            "Reviewed for local operator safety.",
            ADVISORY_FIELD,
            true),
        review);

    Map<String, Object> reviewTrust = (Map<String, Object>) app.get(REVIEW_TRUST_FIELD);
    assertEquals(
        Map.of(
            STATUS_FIELD,
            "publisher_claim_only",
            TRUSTED_FIELD,
            false,
            POSITIVE_FIELD,
            false,
            BLOCKS_INSTALL_FIELD,
            false,
            "blocksUpdate",
            false),
        fields(
            reviewTrust,
            STATUS_FIELD,
            TRUSTED_FIELD,
            POSITIVE_FIELD,
            BLOCKS_INSTALL_FIELD,
            "blocksUpdate"));
    assertFalse(app.toString().contains("PUBLIC KEY"));

    Map<String, Object> rationales = (Map<String, Object>) app.get("permissionRationales");
    assertEquals(
        Map.of(
            QUEUE_READ_PERMISSION,
            "Reads the local transfer queue.",
            QUEUE_WRITE_PERMISSION,
            "Lets the app manage queue entries."),
        rationales);
  }

  @Test
  void listApps_whenEntryHasStatusOnlySubmissionReview_expectSubmissionMetadataFlag()
      throws Exception {
    AppCatalogsApiHandler handler =
        new AppCatalogsApiHandler(catalogManager, appHost, () -> CURRENT_CRYPTA_VERSION);
    when(catalogManager.listApps("core")).thenReturn(List.of(statusOnlySubmissionCatalogEntry()));
    when(appHost.describe(APP_ID)).thenReturn(Optional.empty());
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());

    Map<String, Object> app = handler.listApps("core").getFirst();

    Map<String, Object> thirdPartyReview = (Map<String, Object>) app.get("thirdPartyReview");
    assertEquals("submitted", thirdPartyReview.get(STATUS_FIELD));
    assertEquals(true, thirdPartyReview.get("hasSubmissionMetadata"));
    assertNull(thirdPartyReview.get("submissionId"));
    assertNull(thirdPartyReview.get("submissionSha256"));
  }

  @Test
  void listApps_whenEntryHasStoreMetadataAndInstalledAppDiffers_expectCompatibilityAndChangelog()
      throws Exception {
    Map<String, Object> app = listRichInstalledCatalogApp();

    Map<String, Object> compatibility = (Map<String, Object>) app.get(COMPATIBILITY_FIELD);
    assertEquals("0.1.0", compatibility.get(MINIMUM_CRYPTA_VERSION_FIELD));
    assertEquals("0.9.99", compatibility.get("maximumCryptaVersion"));
    assertEquals(CURRENT_CRYPTA_VERSION, compatibility.get(CURRENT_CRYPTA_VERSION_FIELD));
    assertEquals(true, compatibility.get(SATISFIED_TEXT));
    assertEquals(true, compatibility.get(ADVISORY_FIELD));
    assertEquals(SATISFIED_TEXT, compatibility.get(STATUS_FIELD));
    Map<String, Object> changelog = (Map<String, Object>) app.get("changelog");
    assertEquals("Adds queue retry controls.", changelog.get(SUMMARY_FIELD));
    assertEquals("https://example.invalid/changelog.txt", changelog.get("uri"));
    assertEquals(List.of("https://example.invalid/shot-1.png"), app.get("screenshots"));
  }

  @Test
  void listApps_whenEntryHasStoreMetadataAndInstalledAppDiffers_expectPermissionDelta()
      throws Exception {
    Map<String, Object> app = listRichInstalledCatalogApp();

    Map<String, Object> delta = (Map<String, Object>) app.get("permissionDelta");
    assertEquals(List.of(QUEUE_WRITE_PERMISSION), delta.get("added"));
    assertEquals(List.of("network.access"), delta.get("removed"));
    assertEquals(List.of(QUEUE_READ_PERMISSION), delta.get("unchanged"));
  }

  @Test
  void listApps_whenMinimalCatalogEntryIsNotInstalled_expectBackwardCompatibleApiMetadata()
      throws Exception {
    AppCatalogsApiHandler handler = new AppCatalogsApiHandler(catalogManager, appHost, () -> null);
    when(catalogManager.listApps("core")).thenReturn(List.of(minimalCatalogEntry()));
    when(appHost.describe(APP_ID)).thenReturn(Optional.empty());
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());

    Map<String, Object> app = handler.listApps("core").getFirst();

    assertNull(app.get(HOMEPAGE_FIELD));
    assertNull(app.get(SOURCE_FIELD));
    assertNull(app.get(LICENSE_FIELD));
    assertEquals(List.of(), app.get(CATEGORIES_FIELD));
    assertEquals("stable", app.get(CHANNEL_FIELD));
    assertEquals("supported", app.get(SUPPORT_STATUS_FIELD));
    Map<String, Object> maintenance = (Map<String, Object>) app.get("maintenance");
    assertNull(maintenance.get("owner"));
    assertNull(maintenance.get("supportLevel"));
    assertNull(maintenance.get("supportUri"));
    assertEquals("none", ((Map<?, ?>) app.get("deprecation")).get(STATUS_FIELD));
    assertEquals(List.of(), app.get("securityAdvisories"));
    assertFalse((Boolean) app.get(INSTALLED_TEXT));
    assertEquals(false, app.get(VERSION_DIFFERENT_FIELD));
    assertEquals(false, app.get(UPDATE_AVAILABLE_FIELD));
    assertEquals("not_installed", app.get(VERSION_STATUS_FIELD));

    Map<String, Object> review = (Map<String, Object>) app.get("review");
    assertEquals("unreviewed", review.get(STATUS_FIELD));
    assertNull(review.get("note"));
    assertTrue((Boolean) review.get(ADVISORY_FIELD));

    Map<String, Object> reviewTrust = (Map<String, Object>) app.get(REVIEW_TRUST_FIELD);
    assertEquals("not_configured", reviewTrust.get(STATUS_FIELD));
    assertEquals(false, reviewTrust.get(TRUSTED_FIELD));

    Map<String, Object> compatibility = (Map<String, Object>) app.get(COMPATIBILITY_FIELD);
    assertNull(compatibility.get(MINIMUM_CRYPTA_VERSION_FIELD));
    assertNull(compatibility.get("maximumCryptaVersion"));
    assertNull(compatibility.get(CURRENT_CRYPTA_VERSION_FIELD));
    assertEquals(true, compatibility.get(SATISFIED_TEXT));
    assertEquals("not_declared", compatibility.get(STATUS_FIELD));
  }

  @Test
  void listApps_whenStableBaselineRootFallsOutsideDeclaredRange_expectIncompatibleSummary()
      throws Exception {
    AppCatalogsApiHandler handler = new AppCatalogsApiHandler(catalogManager, appHost, () -> null);
    AppApiCompatibilityMetadata metadata =
        new AppApiCompatibilityMetadata(
            23, 23, List.of(), TargetStability.STABLE, true, false, false);
    when(catalogManager.listApps("core"))
        .thenReturn(List.of(catalogEntryWithApiCompatibility(metadata)));
    when(appHost.describe(APP_ID)).thenReturn(Optional.empty());
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());

    Map<String, Object> app = handler.listApps("core").getFirst();

    Map<?, ?> compatibility = (Map<?, ?>) app.get("apiCompatibility");
    assertEquals("incompatible", compatibility.get(STATUS_FIELD));
  }

  @Test
  void listApps_whenCatalogSecurityDecisionExists_expectRedactedDecisionIncluded()
      throws Exception {
    AppCatalogsApiHandler handler = new AppCatalogsApiHandler(catalogManager, appHost, () -> null);
    when(catalogManager.listApps("core")).thenReturn(List.of(richCatalogEntry()));
    when(catalogManager.securityDecision("core", APP_ID)).thenReturn(denylistedSecurityDecision());
    when(appHost.describe(APP_ID)).thenReturn(Optional.empty());
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());

    Map<String, Object> app = handler.listApps("core").getFirst();

    Map<String, Object> securityDecision = (Map<String, Object>) app.get("securityDecision");
    assertEquals("denylisted", securityDecision.get(STATUS_FIELD));
    assertEquals("denylist", securityDecision.get("action"));
    assertEquals("critical", securityDecision.get("severity"));
    assertEquals(List.of(SECURITY_ADVISORY_ID_0001), securityDecision.get("advisoryIds"));
    assertEquals(true, securityDecision.get(BLOCKS_INSTALL_FIELD));
    assertFalse(securityDecision.toString().contains(tempDir.toString()));
  }

  @Test
  void listApps_whenTargetVersionDenylistedByConfiguredCatalog_expectRedactedDecisionIncluded()
      throws Exception {
    AppCatalogsApiHandler handler = new AppCatalogsApiHandler(catalogManager, appHost, () -> null);
    AppCatalogEntry entry = richCatalogEntry();
    when(catalogManager.listApps("core")).thenReturn(List.of(entry));
    when(catalogManager.installedSecurityDecision(APP_ID, entry.version()))
        .thenReturn(denylistedSecurityDecision());
    when(appHost.describe(APP_ID)).thenReturn(Optional.empty());
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());

    Map<String, Object> app = handler.listApps("core").getFirst();

    Map<String, Object> securityDecision = (Map<String, Object>) app.get("securityDecision");
    assertEquals("denylisted", securityDecision.get(STATUS_FIELD));
    assertEquals("denylist", securityDecision.get("action"));
    assertEquals(true, securityDecision.get(BLOCKS_INSTALL_FIELD));
  }

  @Test
  void listApps_whenInstalledVersionAndPermissionsMatchCatalog_expectCurrentVersionReview()
      throws Exception {
    AppCatalogsApiHandler handler =
        new AppCatalogsApiHandler(catalogManager, appHost, () -> CATALOG_VERSION);
    when(catalogManager.listApps("core")).thenReturn(List.of(richCatalogEntry()));
    when(appHost.describe(APP_ID))
        .thenReturn(
            Optional.of(
                installedSnapshot(
                    CATALOG_VERSION, List.of(QUEUE_READ_PERMISSION, QUEUE_WRITE_PERMISSION))));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());

    Map<String, Object> app = handler.listApps("core").getFirst();

    assertEquals(false, app.get(VERSION_DIFFERENT_FIELD));
    assertEquals(false, app.get(UPDATE_AVAILABLE_FIELD));
    assertEquals("current", app.get(VERSION_STATUS_FIELD));

    Map<String, Object> delta = (Map<String, Object>) app.get("permissionDelta");
    assertEquals(List.of(), delta.get("added"));
    assertEquals(List.of(), delta.get("removed"));
    assertEquals(List.of(QUEUE_READ_PERMISSION, QUEUE_WRITE_PERMISSION), delta.get("unchanged"));
  }

  @Test
  void listApps_whenInstalledVersionIsNewerThanCatalog_expectDifferenceWithoutUpdateAvailable()
      throws Exception {
    AppCatalogsApiHandler handler = new AppCatalogsApiHandler(catalogManager, appHost, () -> null);
    when(catalogManager.listApps("core"))
        .thenReturn(List.of(catalogEntryWithVersion(CATALOG_VERSION)));
    when(appHost.describe(APP_ID))
        .thenReturn(Optional.of(installedSnapshot(NEWER_VERSION, List.of(QUEUE_READ_PERMISSION))));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());

    Map<String, Object> app = handler.listApps("core").getFirst();

    assertEquals(true, app.get(VERSION_DIFFERENT_FIELD));
    assertEquals(false, app.get(UPDATE_AVAILABLE_FIELD));
    assertEquals(DIFFERENT_STATUS, app.get(VERSION_STATUS_FIELD));
  }

  @Test
  void listApps_whenDifferingVersionsAreNotComparable_expectUnknownUpdateAvailable()
      throws Exception {
    AppCatalogsApiHandler handler = new AppCatalogsApiHandler(catalogManager, appHost, () -> null);
    when(catalogManager.listApps("core")).thenReturn(List.of(catalogEntryWithVersion("1.2-beta")));
    when(appHost.describe(APP_ID))
        .thenReturn(
            Optional.of(installedSnapshot(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION))));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());

    Map<String, Object> app = handler.listApps("core").getFirst();

    assertEquals(true, app.get(VERSION_DIFFERENT_FIELD));
    assertNull(app.get(UPDATE_AVAILABLE_FIELD));
    assertEquals(DIFFERENT_STATUS, app.get(VERSION_STATUS_FIELD));
  }

  @Test
  void listApps_whenMinimumVersionExceedsCurrentVersion_expectNotSatisfiedCompatibility()
      throws Exception {
    AppCatalogsApiHandler handler =
        new AppCatalogsApiHandler(catalogManager, appHost, () -> CATALOG_VERSION);
    when(catalogManager.listApps("core"))
        .thenReturn(List.of(catalogEntryWithMinimumCryptaVersion(NEWER_VERSION)));
    when(appHost.describe(APP_ID)).thenReturn(Optional.empty());
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());

    Map<String, Object> app = handler.listApps("core").getFirst();

    Map<String, Object> compatibility = (Map<String, Object>) app.get(COMPATIBILITY_FIELD);
    assertEquals(NEWER_VERSION, compatibility.get(MINIMUM_CRYPTA_VERSION_FIELD));
    assertEquals(CATALOG_VERSION, compatibility.get(CURRENT_CRYPTA_VERSION_FIELD));
    assertEquals(false, compatibility.get(SATISFIED_TEXT));
    assertEquals("not_satisfied", compatibility.get(STATUS_FIELD));
  }

  @Test
  void listApps_whenCurrentVersionSupplierFails_expectUnknownCompatibility() throws Exception {
    AppCatalogsApiHandler handler =
        new AppCatalogsApiHandler(
            catalogManager,
            appHost,
            () -> {
              throw new IllegalStateException("runtime unavailable");
            });
    when(catalogManager.listApps("core"))
        .thenReturn(List.of(catalogEntryWithMinimumCryptaVersion("1.0.0")));
    when(appHost.describe(APP_ID)).thenReturn(Optional.empty());
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());

    Map<String, Object> app = handler.listApps("core").getFirst();

    Map<String, Object> compatibility = (Map<String, Object>) app.get(COMPATIBILITY_FIELD);
    assertEquals("1.0.0", compatibility.get(MINIMUM_CRYPTA_VERSION_FIELD));
    assertNull(compatibility.get(CURRENT_CRYPTA_VERSION_FIELD));
    assertNull(compatibility.get(SATISFIED_TEXT));
    assertEquals(UNKNOWN_STATUS, compatibility.get(STATUS_FIELD));
  }

  @Test
  void governance_whenReviewRegistryAndTransparencyLogConfigured_expectRedactedStatus()
      throws Exception {
    KeyPair reviewerKeyPair = reviewerKeyPair();
    AppReviewTransparencyLog log = AppReviewTransparencyLog.inMemory();
    log.recordReviewTrustMap(
        AppReviewTransparencyEventKind.REVIEW_TRUST_EVALUATED,
        reviewTrustMapSubject(CATALOG_VERSION, "0".repeat(64), 0L),
        trustedReviewTrustMap(),
        List.of(API_TEST_TRACE_LABEL));
    when(catalogManager.reviewTransparencyLog()).thenReturn(log);
    AppCatalogsApiHandler handler =
        new AppCatalogsApiHandler(
            catalogManager,
            appHost,
            () -> null,
            AppReviewPolicy.DEFAULT,
            () -> trustedReviewerKeys(reviewerKeyPair));

    Map<String, Object> governance = handler.governance();

    assertEquals(AppReviewPolicy.DEFAULT.mode().jsonValue(), governance.get("reviewPolicyMode"));
    Map<String, Object> registry = (Map<String, Object>) governance.get("trustedReviewerRegistry");
    assertEquals(true, registry.get(CONFIGURED_TEXT));
    Map<String, Object> counts = (Map<String, Object>) registry.get("counts");
    assertEquals(1, counts.get(ACTIVE_STATUS));
    assertEquals(0, counts.get("retired"));
    assertEquals(0, counts.get("revoked"));
    Map<String, Object> transparency = (Map<String, Object>) governance.get("transparencyLog");
    assertEquals(true, transparency.get(CONFIGURED_TEXT));
    assertEquals(1L, transparency.get("recordCount"));
    assertEquals(true, transparency.get("verified"));
    assertInstanceOf(String.class, transparency.get("latestRecordHash"));
    assertRedactsReviewerPublicKey(governance, reviewerKeyPair);
  }

  @Test
  void reviewerKeys_whenCalled_expectRedactedKeySummaries() throws Exception {
    KeyPair reviewerKeyPair = reviewerKeyPair();
    AppCatalogsApiHandler handler =
        new AppCatalogsApiHandler(
            catalogManager,
            appHost,
            () -> null,
            AppReviewPolicy.DEFAULT,
            () -> trustedReviewerKeys(reviewerKeyPair));

    Map<String, Object> response = handler.reviewerKeys();

    List<Map<String, Object>> keys = (List<Map<String, Object>>) response.get("keys");
    assertEquals(1, keys.size());
    Map<String, Object> key = keys.getFirst();
    assertEquals(REVIEWER_KEY_ID, key.get(KEY_ID_FIELD));
    assertEquals(REVIEWER_DISPLAY_NAME, key.get("displayName"));
    assertEquals("Ed25519", key.get("algorithm"));
    assertEquals(ACTIVE_STATUS, key.get(STATUS_FIELD));
    assertEquals(REVIEW_POLICY_ID, key.get("policyId"));
    assertFalse(key.containsKey("publicKey"));
    assertFalse(key.containsKey("publicKeyBase64"));
    assertRedactsReviewerPublicKey(response, reviewerKeyPair);
  }

  @Test
  void securityResponseSummary_whenCatalogHasEmergencyPolicy_expectBoundedStatus()
      throws Exception {
    KeyPair reviewerKeyPair = reviewerKeyPair();
    AppCatalogSourceSnapshot snapshot = firstPartyCatalogSnapshot();
    when(catalogManager.listCatalogs()).thenReturn(List.of(snapshot));
    when(catalogManager.securityPolicy(snapshot.catalogId())).thenReturn(securityResponsePolicy());
    AppCatalogsApiHandler handler =
        new AppCatalogsApiHandler(
            catalogManager,
            appHost,
            () -> null,
            AppReviewPolicy.DEFAULT,
            () -> revokedReviewerKeys(reviewerKeyPair));

    Map<String, Object> response = handler.securityResponseSummary();

    assertEquals("denylist_active", response.get(STATUS_FIELD));
    Map<String, Object> summary = (Map<String, Object>) response.get(SUMMARY_FIELD);
    assertEquals(1, summary.get(ACTIVE_ADVISORY_COUNT_FIELD));
    assertEquals(1, summary.get(DENYLISTED_VERSION_COUNT_FIELD));
    assertEquals("unavailable", summary.get("installedVulnerableAppCount"));
    assertEquals(1, summary.get(REVOKED_REVIEWER_KEY_COUNT_FIELD));
    assertEquals(CONFIGURED_TEXT, summary.get("catalogKeyRotationStatus"));
    assertEquals(true, summary.get("emergencyReplacementGuidanceAvailable"));
    assertEquals("required", summary.get("supportRedactionStatus"));
    assertEquals("release_artifact_required", summary.get("securityDrillsStatus"));
    assertEquals("not_loaded", summary.get("securityDrillsLastStatus"));
    Map<String, Object> securityDrills = (Map<String, Object>) response.get("securityDrills");
    assertEquals("cryptad-security-response-drills-summary", securityDrills.get("artifactKind"));
    assertEquals(7, securityDrills.get("requiredScenarioCount"));
    assertEquals(false, securityDrills.get("summaryAvailable"));
    Map<String, Object> advisory =
        ((List<Map<String, Object>>) response.get(ACTIVE_ADVISORIES_FIELD)).getFirst();
    assertEquals(SECURITY_ADVISORY_ID_0001, advisory.get("id"));
    assertEquals("published", advisory.get(STATUS_FIELD));
    Map<String, Object> denylist =
        ((List<Map<String, Object>>) response.get("denylistedVersions")).getFirst();
    assertEquals(APP_ID, denylist.get(APP_ID_FIELD));
    assertEquals(CATALOG_VERSION, denylist.get(VERSION_FIELD));
    Map<String, Object> catalogKey =
        ((List<Map<String, Object>>) response.get("catalogSigningKeys")).getFirst();
    assertEquals(FIRST_PARTY_TRUSTED_KEY_ID, catalogKey.get(KEY_ID_FIELD));
    assertEquals("current", catalogKey.get("rotationStatus"));
    assertFalse(response.toString().contains(FIRST_PARTY_SOURCE));
    assertFalse(response.toString().contains(tempDir.toString()));
    assertRedactsReviewerPublicKey(response, reviewerKeyPair);
  }

  @Test
  void securityResponseSummary_whenDenylistHasReplacementGuidance_expectGuidanceAvailable()
      throws Exception {
    AppCatalogSourceSnapshot snapshot = firstPartyCatalogSnapshot();
    when(catalogManager.listCatalogs()).thenReturn(List.of(snapshot));
    when(catalogManager.securityPolicy(snapshot.catalogId()))
        .thenReturn(denylistReplacementOnlySecurityResponsePolicy());
    AppCatalogsApiHandler handler =
        new AppCatalogsApiHandler(
            catalogManager,
            appHost,
            () -> null,
            AppReviewPolicy.DEFAULT,
            TrustedReviewerKeys::empty);

    Map<String, Object> response = handler.securityResponseSummary();

    assertEquals("denylist_active", response.get(STATUS_FIELD));
    Map<String, Object> summary = (Map<String, Object>) response.get(SUMMARY_FIELD);
    assertEquals(true, summary.get("emergencyReplacementGuidanceAvailable"));
    Map<String, Object> advisory =
        ((List<Map<String, Object>>) response.get(ACTIVE_ADVISORIES_FIELD)).getFirst();
    assertNull(advisory.get(REPLACEMENT_APP_ID_FIELD));
    Map<String, Object> denylist =
        ((List<Map<String, Object>>) response.get("denylistedVersions")).getFirst();
    assertEquals(APP_ID, denylist.get(REPLACEMENT_APP_ID_FIELD));
  }

  @Test
  void securityResponseSummary_whenReviewerRevokedWithoutCatalogPolicy_expectReviewerStatus()
      throws Exception {
    KeyPair reviewerKeyPair = reviewerKeyPair();
    AppCatalogSourceSnapshot snapshot = firstPartyCatalogSnapshot();
    when(catalogManager.listCatalogs()).thenReturn(List.of(snapshot));
    when(catalogManager.securityPolicy(snapshot.catalogId()))
        .thenReturn(AppCatalogSecurityPolicy.EMPTY);
    AppCatalogsApiHandler handler =
        new AppCatalogsApiHandler(
            catalogManager,
            appHost,
            () -> null,
            AppReviewPolicy.DEFAULT,
            () -> revokedReviewerKeys(reviewerKeyPair));

    Map<String, Object> response = handler.securityResponseSummary();

    assertEquals("reviewer_revocation_active", response.get(STATUS_FIELD));
    Map<String, Object> summary = (Map<String, Object>) response.get(SUMMARY_FIELD);
    assertEquals(0, summary.get(ACTIVE_ADVISORY_COUNT_FIELD));
    assertEquals(0, summary.get(DENYLISTED_VERSION_COUNT_FIELD));
    assertEquals(1, summary.get(REVOKED_REVIEWER_KEY_COUNT_FIELD));
    assertRedactsReviewerPublicKey(response, reviewerKeyPair);
  }

  @Test
  void securityResponseSummary_whenPublishedAdvisoryHasNoDenylist_expectAdvisoryStatus()
      throws Exception {
    AppCatalogSourceSnapshot snapshot = firstPartyCatalogSnapshotWithoutSigningKey();
    when(catalogManager.listCatalogs()).thenReturn(List.of(snapshot));
    when(catalogManager.securityPolicy(snapshot.catalogId()))
        .thenReturn(advisoryOnlySecurityResponsePolicy());
    AppCatalogsApiHandler handler =
        new AppCatalogsApiHandler(
            catalogManager,
            appHost,
            () -> null,
            AppReviewPolicy.DEFAULT,
            TrustedReviewerKeys::empty);

    Map<String, Object> response = handler.securityResponseSummary();

    assertEquals("advisory_active", response.get(STATUS_FIELD));
    Map<String, Object> summary = (Map<String, Object>) response.get(SUMMARY_FIELD);
    assertEquals(1, summary.get(ACTIVE_ADVISORY_COUNT_FIELD));
    assertEquals(0, summary.get(DENYLISTED_VERSION_COUNT_FIELD));
    assertEquals(0, summary.get(REVOKED_REVIEWER_KEY_COUNT_FIELD));
    assertEquals(UNKNOWN_STATUS, summary.get("catalogKeyRotationStatus"));
    Map<String, Object> advisory =
        ((List<Map<String, Object>>) response.get(ACTIVE_ADVISORIES_FIELD)).getFirst();
    assertEquals(SECURITY_ADVISORY_ID_0002, advisory.get("id"));
    assertEquals("published", advisory.get(STATUS_FIELD));
    Map<String, Object> catalogKey =
        ((List<Map<String, Object>>) response.get("catalogSigningKeys")).getFirst();
    assertNull(catalogKey.get(KEY_ID_FIELD));
    assertEquals(UNKNOWN_STATUS, catalogKey.get("rotationStatus"));
  }

  @Test
  void transparencyLog_whenFilteredByKind_expectPagedRedactedRecords() {
    AppReviewTransparencyLog log = AppReviewTransparencyLog.inMemory();
    log.recordReviewTrustMap(
        AppReviewTransparencyEventKind.REVIEW_TRUST_EVALUATED,
        reviewTrustMapSubject(CATALOG_VERSION, "0".repeat(64), 0L),
        trustedReviewTrustMap(),
        List.of(API_TEST_TRACE_LABEL));
    log.recordReviewTrustMap(
        AppReviewTransparencyEventKind.REVIEW_GATE_INSTALL,
        reviewTrustMapSubject(CATALOG_VERSION, "0".repeat(64), 0L),
        trustedReviewTrustMap(),
        List.of("phase=install"));
    when(catalogManager.reviewTransparencyLog()).thenReturn(log);
    AppCatalogsApiHandler handler =
        new AppCatalogsApiHandler(
            catalogManager,
            appHost,
            () -> null,
            AppReviewPolicy.DEFAULT,
            TrustedReviewerKeys::empty);

    Map<String, Object> page =
        handler.transparencyLog(
            Map.of("kind", List.of("review_gate_install"), "limit", List.of("1")));

    List<Map<String, Object>> records = (List<Map<String, Object>>) page.get("records");
    assertEquals(1, records.size());
    Map<String, Object> transparencyRecord = records.getFirst();
    assertEquals("review_gate_install", transparencyRecord.get("kind"));
    assertEquals(APP_ID, transparencyRecord.get(APP_ID_FIELD));
    assertEquals("core", transparencyRecord.get(CATALOG_ID_FIELD));
    assertEquals(TRUSTED_REVIEWED_STATUS, transparencyRecord.get("trustStatus"));
    assertFalse(page.toString().contains(tempDir.toString()));
  }

  @Test
  void transparencyLog_whenKindIsInvalid_expectBadRequest() {
    AppCatalogsApiHandler handler =
        new AppCatalogsApiHandler(
            catalogManager,
            appHost,
            () -> null,
            AppReviewPolicy.DEFAULT,
            TrustedReviewerKeys::empty);
    Map<String, List<String>> invalidKindQuery = Map.of("kind", List.of("not-a-kind"));

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> handler.transparencyLog(invalidKindQuery));

    assertEquals(400, exception.statusCode());
    assertEquals("invalid_query_parameter", exception.errorCode());
  }

  @Test
  void reviewHistory_whenTrustedReceiptExists_expectTrustReviewerAndTransparencyHistory()
      throws Exception {
    KeyPair reviewerKeyPair = reviewerKeyPair();
    AppCatalogEntry entry = richCatalogEntryWithTrustedReceipt(reviewerKeyPair);
    AppReviewTransparencyLog log = AppReviewTransparencyLog.inMemory();
    log.recordReviewTrustMap(
        AppReviewTransparencyEventKind.REVIEW_TRUST_EVALUATED,
        reviewTrustMapSubject(entry.version(), entry.bundleSha256(), entry.bundleSizeBytes()),
        trustedReviewTrustMap(),
        List.of(API_TEST_TRACE_LABEL));
    when(catalogManager.getApp("core", APP_ID)).thenReturn(entry);
    when(catalogManager.reviewTransparencyLog()).thenReturn(log);
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installedSnapshot()));
    AppCatalogsApiHandler handler =
        new AppCatalogsApiHandler(
            catalogManager,
            appHost,
            () -> null,
            AppReviewPolicy.DEFAULT,
            () -> trustedReviewerKeys(reviewerKeyPair));

    Map<String, Object> history = handler.reviewHistory("core", APP_ID);

    assertEquals("core", history.get(CATALOG_ID_FIELD));
    assertEquals(APP_ID, history.get(APP_ID_FIELD));
    assertEquals(CATALOG_VERSION, history.get("catalogVersion"));
    assertEquals(INSTALLED_VERSION, history.get(INSTALLED_VERSION_FIELD));
    Map<String, Object> reviewTrust = (Map<String, Object>) history.get(REVIEW_TRUST_FIELD);
    assertEquals(TRUSTED_REVIEWED_STATUS, reviewTrust.get(STATUS_FIELD));
    assertEquals(true, reviewTrust.get(TRUSTED_FIELD));
    assertEquals(true, reviewTrust.get(POSITIVE_FIELD));
    assertEquals(REVIEWER_KEY_ID, reviewTrust.get("reviewerKeyId"));
    assertEquals(ACTIVE_STATUS, reviewTrust.get("reviewerKeyStatus"));
    assertEquals(REVIEW_POLICY_VERSION, reviewTrust.get("policyVersion"));
    Map<String, Object> reviewerKey = (Map<String, Object>) history.get("reviewerKey");
    assertNotNull(reviewerKey);
    assertEquals(REVIEWER_KEY_ID, reviewerKey.get(KEY_ID_FIELD));
    assertEquals(ACTIVE_STATUS, reviewerKey.get(STATUS_FIELD));
    Map<String, Object> transparency = (Map<String, Object>) history.get("transparencyLog");
    List<Map<String, Object>> records = (List<Map<String, Object>>) transparency.get("records");
    assertEquals(1, records.size());
    assertEquals("review_trust_evaluated", records.getFirst().get("kind"));
    Map<String, Object> delta = (Map<String, Object>) history.get("trustDelta");
    assertEquals(true, delta.get("versionChanged"));
    assertEquals(TRUSTED_REVIEWED_STATUS, delta.get("trustStatus"));
    assertRedactsReviewerPublicKey(history, reviewerKeyPair);
  }

  @Test
  void install_whenPolicyRequiresTrustedReviewAndReceiptIsMissing_expectStableReviewError()
      throws Exception {
    AppCatalogsApiHandler handler =
        new AppCatalogsApiHandler(
            catalogManager,
            appHost,
            () -> null,
            new AppReviewPolicy(AppReviewPolicyMode.REQUIRE_TRUSTED_REVIEW),
            TrustedReviewerKeys::empty);
    when(catalogManager.getApp("core", APP_ID)).thenReturn(richCatalogEntry());
    when(appHost.describe(APP_ID)).thenReturn(Optional.empty());

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> handler.install("core", APP_ID));

    assertEquals(409, exception.statusCode());
    assertEquals(APP_REVIEW_MISSING_ERROR, exception.errorCode());
    assertFalse(exception.getMessage().contains(tempDir.toString()));
  }

  @Test
  void install_whenSignedManifestTargetsUnsupportedBaseline_expectMutationBlocked()
      throws Exception {
    AppCatalogsApiHandler handler =
        new AppCatalogsApiHandler(catalogManager, appHost, () -> CURRENT_CRYPTA_VERSION);
    AppCatalogEntry entry = minimalCatalogEntry();
    AppCatalogInstallPlan plan = plan(entry);
    Path manifest = plan.stagedBundleDirectory().resolve(AppManifestParser.MANIFEST_FILE_NAME);
    Files.writeString(
        manifest,
        Files.readString(manifest) + "api.targetStability=stable\n" + "api.targetBaseline=1.1\n");
    when(catalogManager.getApp("core", APP_ID)).thenReturn(entry);
    when(catalogManager.prepareInstallPlan("core", APP_ID)).thenReturn(plan);
    when(appHost.describe(APP_ID)).thenReturn(Optional.empty());

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> handler.install("core", APP_ID));

    assertEquals("unsupported_platform_api_baseline", exception.errorCode());
    verify(appHost, never()).installFromDirectory(any());
    verify(appHost, never()).installCatalogFromDirectory(any(), any(), any());
  }

  @Test
  void install_whenLegacyCatalogStableTargetDiffersFromManifest_expectMutationBlocked()
      throws Exception {
    AppCatalogsApiHandler handler =
        new AppCatalogsApiHandler(catalogManager, appHost, () -> CURRENT_CRYPTA_VERSION);
    AppApiCompatibilityMetadata catalogMetadata =
        new AppApiCompatibilityMetadata(
            19, 23, List.of(), TargetStability.STABLE, true, false, false);
    AppCatalogEntry entry = catalogEntryWithApiCompatibility(catalogMetadata);
    AppCatalogInstallPlan plan = plan(entry);
    when(catalogManager.getApp("core", APP_ID)).thenReturn(entry);
    when(catalogManager.prepareInstallPlan("core", APP_ID)).thenReturn(plan);
    when(appHost.describe(APP_ID)).thenReturn(Optional.empty());

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> handler.install("core", APP_ID));

    assertEquals("invalid_app_bundle", exception.errorCode());
    verify(appHost, never()).installFromDirectory(any());
    verify(appHost, never()).installCatalogFromDirectory(any(), any(), any());
  }

  @Test
  void install_whenFederatedConflictVerifierRejects_expectMutationBlockedInsideAuthorization()
      throws Exception {
    AppCatalogsApiHandler handler =
        new AppCatalogsApiHandler(catalogManager, appHost, () -> CURRENT_CRYPTA_VERSION);
    authorizeFederatedReviewerScope(handler);
    handler.setPreparedPlanConflictVerifier(
        (_, _, _) -> {
          throw new PlatformApiException(
              409, "catalog_conflict_unresolved", "Exact conflict resolution is required.");
        });
    AppCatalogEntry entry = richCatalogEntry();
    AppCatalogInstallPlan plan = federatedPlan(entry);
    AppCatalogManager.CatalogTrustAuthorization catalogAuthorization = mock();
    when(catalogManager.federationEnabled()).thenReturn(true);
    when(catalogManager.getApp("core", APP_ID)).thenReturn(entry);
    when(catalogManager.prepareInstallPlan("core", APP_ID)).thenReturn(plan);
    when(catalogManager.authorizeInstallPlanForMutation(plan)).thenReturn(catalogAuthorization);
    when(appHost.describe(APP_ID)).thenReturn(Optional.empty());
    when(appHost.installCatalogFromDirectory(any(), any(), any()))
        .thenAnswer(
            invocation -> {
              AppHost.CatalogMutationAuthorization authorization = invocation.getArgument(2);
              InstalledAppOrigin origin = invocation.getArgument(1);
              try (var _ = authorization.authorize(origin)) {
                return installedSnapshot();
              }
            });

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> handler.install("core", APP_ID));

    assertEquals("catalog_conflict_unresolved", exception.errorCode());
    verify(catalogAuthorization).close();
  }

  @Test
  void update_whenFederatedConflictVerifierRejects_expectMutationBlockedInsideAuthorization()
      throws Exception {
    AppCatalogsApiHandler handler =
        new AppCatalogsApiHandler(catalogManager, appHost, () -> CURRENT_CRYPTA_VERSION);
    authorizeFederatedReviewerScope(handler);
    handler.setPreparedPlanConflictVerifier(
        (_, _, _) -> {
          throw new PlatformApiException(
              409, "catalog_conflict_unresolved", "Exact conflict resolution is required.");
        });
    AppCatalogEntry entry = richCatalogEntry();
    AppCatalogInstallPlan plan = federatedPlan(entry);
    InstalledAppOrigin current =
        InstalledAppOrigin.create(
            APP_ID,
            INSTALLED_VERSION,
            "4".repeat(64),
            "core",
            "catalog-key",
            "b".repeat(64),
            "5".repeat(64),
            "publisher-key",
            "2".repeat(64),
            "6".repeat(64),
            "",
            TRUSTED_REVIEWED_STATUS,
            "catalog-binding",
            "d".repeat(64),
            "3".repeat(64),
            "f".repeat(64),
            Instant.parse(GENERATED_AT_TEXT),
            null);
    AppCatalogManager.CatalogTrustAuthorization catalogAuthorization = mock();
    when(catalogManager.federationEnabled()).thenReturn(true);
    when(catalogManager.getApp("core", APP_ID)).thenReturn(entry);
    when(catalogManager.prepareInstallPlan("core", APP_ID)).thenReturn(plan);
    when(catalogManager.authorizeInstallPlanForMutation(plan)).thenReturn(catalogAuthorization);
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installedSnapshot()));
    when(appHost.catalogOrigin(APP_ID)).thenReturn(Optional.of(current));
    when(appHost.updateCatalogFromDirectory(any(), any(), any(), any(), any()))
        .thenAnswer(
            invocation -> {
              AppHost.CatalogMutationAuthorization authorization = invocation.getArgument(4);
              InstalledAppOrigin target = invocation.getArgument(2);
              try (var _ = authorization.authorize(target)) {
                return installedSnapshot();
              }
            });

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> handler.update("core", APP_ID));

    assertEquals("catalog_conflict_unresolved", exception.errorCode());
    verify(catalogAuthorization).close();
  }

  @Test
  void install_whenFederatedPoliciesAuthorize_expectAllLeasesHeldThroughHostCommit()
      throws Exception {
    AppCatalogsApiHandler handler =
        new AppCatalogsApiHandler(catalogManager, appHost, () -> CURRENT_CRYPTA_VERSION);
    authorizeFederatedReviewerScope(handler);
    handler.setPreparedPlanConflictVerifier((_, _, _) -> {});
    AppHost.CatalogMutationAuthorizationLease scopedPolicyAuthorization = mock();
    handler.setPreparedPlanPolicyAuthorizer((_, _, _, _) -> scopedPolicyAuthorization);
    AppCatalogEntry entry = richCatalogEntry();
    AppCatalogInstallPlan plan = federatedPlan(entry);
    AppCatalogManager.CatalogTrustAuthorization catalogAuthorization = mock();
    when(catalogManager.federationEnabled()).thenReturn(true);
    when(catalogManager.getApp("core", APP_ID)).thenReturn(entry);
    when(catalogManager.prepareInstallPlan("core", APP_ID)).thenReturn(plan);
    when(catalogManager.authorizeInstallPlanForMutation(plan)).thenReturn(catalogAuthorization);
    when(appHost.describe(APP_ID)).thenReturn(Optional.empty());
    when(appHost.installCatalogFromDirectory(any(), any(), any()))
        .thenAnswer(
            invocation -> {
              AppHost.CatalogMutationAuthorization authorization = invocation.getArgument(2);
              InstalledAppOrigin origin = invocation.getArgument(1);
              AppHost.CatalogMutationAuthorizationLease lease = authorization.authorize(origin);
              verify(catalogAuthorization, never()).close();
              verify(scopedPolicyAuthorization, never()).close();
              lease.close();
              return installedSnapshot();
            });

    Map<String, Object> summary = handler.install("core", APP_ID);

    assertEquals(APP_ID, summary.get(APP_ID_FIELD));
    verify(scopedPolicyAuthorization).close();
    verify(catalogAuthorization).close();
  }

  @Test
  void install_whenReviewerIsGlobalButLocalCatalogScopeRejects_expectMutationBlocked()
      throws Exception {
    AppCatalogsApiHandler handler =
        new AppCatalogsApiHandler(catalogManager, appHost, () -> CURRENT_CRYPTA_VERSION);
    CatalogScopedReviewerPolicy scopedPolicy = mock(CatalogScopedReviewerPolicy.class);
    CatalogScopedReviewerPolicy.Verification verification =
        mock(CatalogScopedReviewerPolicy.Verification.class);
    when(verification.authorized()).thenReturn(false);
    when(scopedPolicy.evaluate(any(), any(), any(), any(), any())).thenReturn(verification);
    handler.setCatalogScopedReviewerPolicy(scopedPolicy);
    AppCatalogEntry entry = richCatalogEntry();
    when(catalogManager.getApp("core", APP_ID)).thenReturn(entry);
    when(appHost.describe(APP_ID)).thenReturn(Optional.empty());

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> handler.install("core", APP_ID));

    assertEquals("catalog_reviewer_scope_required", exception.errorCode());
    verify(catalogManager, never()).prepareInstallPlan(any(), any());
    verify(appHost, never()).installFromDirectory(any());
  }

  @Test
  void install_whenFederationHasNoScopedReviewerPolicy_expectFederationUnavailable()
      throws Exception {
    AppCatalogsApiHandler handler =
        new AppCatalogsApiHandler(catalogManager, appHost, () -> CURRENT_CRYPTA_VERSION);
    when(catalogManager.federationEnabled()).thenReturn(true);
    when(catalogManager.getApp("core", APP_ID)).thenReturn(richCatalogEntry());
    when(appHost.describe(APP_ID)).thenReturn(Optional.empty());

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> handler.install("core", APP_ID));

    assertEquals(503, exception.statusCode());
    assertEquals("catalog_federation_unavailable", exception.errorCode());
    verify(catalogManager, never()).prepareInstallPlan(any(), any());
    verify(appHost, never()).installFromDirectory(any());
  }

  @Test
  void install_whenCatalogSecurityDecisionIsDenylisted_expectStableSecurityError()
      throws Exception {
    AppCatalogsApiHandler handler = new AppCatalogsApiHandler(catalogManager, appHost, () -> null);
    when(catalogManager.getApp("core", APP_ID)).thenReturn(richCatalogEntry());
    when(catalogManager.securityDecision("core", APP_ID)).thenReturn(denylistedSecurityDecision());
    when(appHost.describe(APP_ID)).thenReturn(Optional.empty());

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> handler.install("core", APP_ID));

    assertEquals(409, exception.statusCode());
    assertEquals(APP_SECURITY_DENYLISTED_ERROR, exception.errorCode());
    verify(catalogManager, never()).prepareInstallPlan(any(), any());
    verify(appHost, never()).installFromDirectory(any());
  }

  @Test
  void install_whenTargetVersionDenylistedByConfiguredCatalog_expectStableSecurityError()
      throws Exception {
    AppCatalogsApiHandler handler = new AppCatalogsApiHandler(catalogManager, appHost, () -> null);
    AppCatalogEntry entry = richCatalogEntry();
    when(catalogManager.getApp("core", APP_ID)).thenReturn(entry);
    when(catalogManager.installedSecurityDecision(APP_ID, entry.version()))
        .thenReturn(denylistedSecurityDecision());
    when(appHost.describe(APP_ID)).thenReturn(Optional.empty());

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> handler.install("core", APP_ID));

    assertEquals(409, exception.statusCode());
    assertEquals(APP_SECURITY_DENYLISTED_ERROR, exception.errorCode());
    verify(catalogManager, never()).prepareInstallPlan(any(), any());
    verify(appHost, never()).installFromDirectory(any());
  }

  @Test
  void install_whenCatalogSecurityDecisionWarnsWithoutAcknowledgement_expectSecurityAckError()
      throws Exception {
    AppCatalogsApiHandler handler = new AppCatalogsApiHandler(catalogManager, appHost, () -> null);
    when(catalogManager.getApp("core", APP_ID)).thenReturn(richCatalogEntry());
    when(catalogManager.securityDecision("core", APP_ID)).thenReturn(warningSecurityDecision());
    when(appHost.describe(APP_ID)).thenReturn(Optional.empty());

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> handler.install("core", APP_ID));

    assertEquals(409, exception.statusCode());
    assertEquals("app_security_acknowledgement_required", exception.errorCode());
    verify(catalogManager, never()).prepareInstallPlan(any(), any());
    verify(appHost, never()).installFromDirectory(any());
  }

  @Test
  void update_whenTargetVersionDenylistedByConfiguredCatalog_expectStableSecurityError()
      throws Exception {
    AppCatalogsApiHandler handler = new AppCatalogsApiHandler(catalogManager, appHost, () -> null);
    AppCatalogEntry entry = richCatalogEntry();
    when(catalogManager.getApp("core", APP_ID)).thenReturn(entry);
    when(catalogManager.installedSecurityDecision(APP_ID, entry.version()))
        .thenReturn(denylistedSecurityDecision());
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installedSnapshot()));
    Map<String, List<String>> securityAcknowledgedQuery =
        Map.of("securityAcknowledged", List.of("true"));

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class,
            () -> handler.update("core", APP_ID, securityAcknowledgedQuery));

    assertEquals(409, exception.statusCode());
    assertEquals(APP_SECURITY_DENYLISTED_ERROR, exception.errorCode());
    verify(catalogManager, never()).prepareInstallPlan(any(), any());
    verify(appHost, never()).updateFromDirectory(any(), any());
  }

  @Test
  void install_whenPreparedPlanLosesTrustedReview_expectPlanReviewGateBlocks() throws Exception {
    KeyPair reviewerKeyPair = reviewerKeyPair();
    AppCatalogsApiHandler handler =
        new AppCatalogsApiHandler(
            catalogManager,
            appHost,
            () -> null,
            new AppReviewPolicy(AppReviewPolicyMode.REQUIRE_TRUSTED_REVIEW),
            () -> trustedReviewerKeys(reviewerKeyPair));
    AppCatalogEntry trustedEntry = richCatalogEntryWithTrustedReceipt(reviewerKeyPair);
    AppCatalogEntry refreshedEntryWithoutReceipt = richCatalogEntry();
    AppCatalogInstallPlan plan = plan(refreshedEntryWithoutReceipt);
    when(catalogManager.getApp("core", APP_ID)).thenReturn(trustedEntry);
    when(catalogManager.prepareInstallPlan("core", APP_ID)).thenReturn(plan);
    when(appHost.describe(APP_ID)).thenReturn(Optional.empty());

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> handler.install("core", APP_ID));

    assertEquals(409, exception.statusCode());
    assertEquals(APP_REVIEW_MISSING_ERROR, exception.errorCode());
    verify(appHost, never()).installFromDirectory(any());
  }

  @Test
  void update_whenPreparedPlanLosesTrustedReview_expectPlanReviewGateBlocks() throws Exception {
    KeyPair reviewerKeyPair = reviewerKeyPair();
    AppCatalogsApiHandler handler =
        new AppCatalogsApiHandler(
            catalogManager,
            appHost,
            () -> null,
            new AppReviewPolicy(AppReviewPolicyMode.REQUIRE_TRUSTED_REVIEW),
            () -> trustedReviewerKeys(reviewerKeyPair));
    AppCatalogEntry trustedEntry = richCatalogEntryWithTrustedReceipt(reviewerKeyPair);
    AppCatalogEntry refreshedEntryWithoutReceipt = richCatalogEntry();
    AppCatalogInstallPlan plan = plan(refreshedEntryWithoutReceipt);
    when(catalogManager.getApp("core", APP_ID)).thenReturn(trustedEntry);
    when(catalogManager.prepareInstallPlan("core", APP_ID)).thenReturn(plan);
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installedSnapshot()));

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> handler.update("core", APP_ID));

    assertEquals(409, exception.statusCode());
    assertEquals(APP_REVIEW_MISSING_ERROR, exception.errorCode());
    verify(appHost, never()).updateFromDirectory(any(), any());
  }

  @Test
  void install_whenAcknowledgedReviewTrustChangesAfterPlan_expectFreshAcknowledgementRequired()
      throws Exception {
    KeyPair reviewerKeyPair = reviewerKeyPair();
    AppCatalogsApiHandler handler =
        new AppCatalogsApiHandler(
            catalogManager,
            appHost,
            () -> null,
            new AppReviewPolicy(AppReviewPolicyMode.WARN_UNTRUSTED),
            () -> trustedReviewerKeys(reviewerKeyPair));
    AppCatalogEntry acknowledgedEntry = richCatalogEntry();
    AppCatalogEntry refreshedRejectedEntry =
        richCatalogEntryWithTrustedReceipt(reviewerKeyPair, AppReviewReceiptStatus.REJECTED);
    AppCatalogInstallPlan plan = plan(refreshedRejectedEntry);
    when(catalogManager.getApp("core", APP_ID)).thenReturn(acknowledgedEntry);
    when(catalogManager.prepareInstallPlan("core", APP_ID)).thenReturn(plan);
    when(appHost.describe(APP_ID)).thenReturn(Optional.empty());
    Map<String, List<String>> queryParameters = reviewAcknowledgedQuery();

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class, () -> handler.install("core", APP_ID, queryParameters));

    assertEquals(409, exception.statusCode());
    assertEquals("app_review_rejected", exception.errorCode());
    verify(appHost, never()).installFromDirectory(any());
  }

  @Test
  void update_whenAcknowledgedReviewTrustChangesAfterPlan_expectFreshAcknowledgementRequired()
      throws Exception {
    KeyPair reviewerKeyPair = reviewerKeyPair();
    AppCatalogsApiHandler handler =
        new AppCatalogsApiHandler(
            catalogManager,
            appHost,
            () -> null,
            new AppReviewPolicy(AppReviewPolicyMode.WARN_UNTRUSTED),
            () -> trustedReviewerKeys(reviewerKeyPair));
    AppCatalogEntry acknowledgedEntry = richCatalogEntry();
    AppCatalogEntry refreshedRejectedEntry =
        richCatalogEntryWithTrustedReceipt(reviewerKeyPair, AppReviewReceiptStatus.REJECTED);
    AppCatalogInstallPlan plan = plan(refreshedRejectedEntry);
    when(catalogManager.getApp("core", APP_ID)).thenReturn(acknowledgedEntry);
    when(catalogManager.prepareInstallPlan("core", APP_ID)).thenReturn(plan);
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installedSnapshot()));
    Map<String, List<String>> queryParameters = reviewAcknowledgedQuery();

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class, () -> handler.update("core", APP_ID, queryParameters));

    assertEquals(409, exception.statusCode());
    assertEquals("app_review_rejected", exception.errorCode());
    verify(appHost, never()).updateFromDirectory(any(), any());
  }

  @Test
  void update_whenCatalogUpdateRemovesVaultUsePermission_expectMatchingGrantInactive()
      throws Exception {
    AppVaultService vaultService = AppVaultService.open(tempDir.resolve(VAULT_DIRECTORY));
    AppIdentityRecord identity =
        vaultService.createOperatorIdentity(
            AppIdentityKind.LOCAL_ED25519_SIGNING,
            "Operator publisher",
            null,
            Set.of(AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED));
    AppIdentityGrant grant =
        vaultService.grantIdentity(
            identity.identityId(),
            APP_ID,
            Set.of(AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED),
            "operator",
            "test grant",
            null,
            null);
    AppCatalogsApiHandler handler =
        new AppCatalogsApiHandler(
            catalogManager,
            appHost,
            () -> null,
            new AppReviewPolicy(AppReviewPolicyMode.ADVISORY),
            TrustedReviewerKeys::empty,
            vaultService);
    AppCatalogEntry entry = richCatalogEntry();
    AppCatalogInstallPlan plan = plan(entry);
    when(catalogManager.getApp("core", APP_ID)).thenReturn(entry);
    when(catalogManager.prepareInstallPlan("core", APP_ID)).thenReturn(plan);
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    when(appHost.describe(APP_ID))
        .thenReturn(
            Optional.of(
                installedSnapshot(
                    INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION, "vault.identities.use"))));
    when(appHost.updateFromDirectory(APP_ID, plan.stagedBundleDirectory()))
        .thenReturn(
            installedSnapshot(
                CATALOG_VERSION, List.of(QUEUE_READ_PERMISSION, "vault.identities.read")));

    handler.update("core", APP_ID);

    assertEquals(
        AppIdentityGrantStatus.INACTIVE,
        vaultService.listGrantsForApp(APP_ID).stream()
            .filter(candidate -> candidate.grantId().equals(grant.grantId()))
            .findFirst()
            .orElseThrow()
            .status());
  }

  @Test
  void update_whenVaultGrantCleanupFailsAfterCatalogUpdate_expectWarning() throws Exception {
    AppVaultService vaultService = AppVaultService.open(tempDir.resolve(VAULT_DIRECTORY));
    AppIdentityRecord identity =
        vaultService.createOperatorIdentity(
            AppIdentityKind.LOCAL_ED25519_SIGNING,
            "Operator publisher",
            null,
            Set.of(AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED));
    AppIdentityGrant grant =
        vaultService.grantIdentity(
            identity.identityId(),
            APP_ID,
            Set.of(AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED),
            "operator",
            "test grant",
            null,
            null);
    Files.writeString(
        tempDir.resolve(VAULT_DIRECTORY).resolve("grants").resolve(grant.grantId() + ".properties"),
        """
        grantId=%s
        identityId=%s
        appId=%s
        scopes=sign.domain-separated
        status=not-a-status
        createdAt=%s
        updatedAt=%s
        """
            .formatted(
                grant.grantId(),
                grant.identityId(),
                grant.appId(),
                grant.createdAt(),
                grant.updatedAt()));
    AppCatalogsApiHandler handler =
        new AppCatalogsApiHandler(
            catalogManager,
            appHost,
            () -> null,
            new AppReviewPolicy(AppReviewPolicyMode.ADVISORY),
            TrustedReviewerKeys::empty,
            vaultService);
    AppCatalogEntry entry = richCatalogEntry();
    AppCatalogInstallPlan plan = plan(entry);
    when(catalogManager.getApp("core", APP_ID)).thenReturn(entry);
    when(catalogManager.prepareInstallPlan("core", APP_ID)).thenReturn(plan);
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    when(appHost.describe(APP_ID))
        .thenReturn(
            Optional.of(
                installedSnapshot(
                    INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION, "vault.identities.use"))));
    when(appHost.updateFromDirectory(APP_ID, plan.stagedBundleDirectory()))
        .thenReturn(
            installedSnapshot(
                CATALOG_VERSION, List.of(QUEUE_READ_PERMISSION, "vault.identities.read")));

    Map<String, Object> summary = handler.update("core", APP_ID);

    assertEquals(
        List.of("Vault grant cleanup failed and requires operator review."),
        summary.get("warnings"));
  }

  @Test
  void update_whenLocalPublisherScopeRevokedAfterPreview_expectTypedConflictWithoutMutation()
      throws Exception {
    AppCatalogsApiHandler handler =
        new AppCatalogsApiHandler(catalogManager, appHost, () -> CURRENT_CRYPTA_VERSION);
    authorizeFederatedReviewerScope(handler);
    when(catalogManager.getApp("core", APP_ID)).thenReturn(richCatalogEntry());
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installedSnapshot()));
    when(catalogManager.prepareInstallPlan("core", APP_ID))
        .thenThrow(new CatalogPublisherAuthorizationException());
    Map<String, List<String>> consent =
        Map.of(SOURCE_SWITCH_CONSENT_PARAMETER, List.of("a".repeat(64)));

    PlatformApiException failure =
        assertThrows(PlatformApiException.class, () -> handler.update("core", APP_ID, consent));

    assertEquals(409, failure.statusCode());
    assertEquals("catalog_publisher_scope_rejected", failure.errorCode());
    verify(appHost, never()).updateFromDirectory(any(), any());
    verify(appHost, never()).updateCatalogFromDirectory(any(), any(), any(), any(), any());
  }

  @Test
  void sourceSwitchPreview_whenScopeRejectedOrStorageFails_expectDistinctConflictAndIoFailure()
      throws Exception {
    AppCatalogsApiHandler handler =
        new AppCatalogsApiHandler(catalogManager, appHost, () -> CURRENT_CRYPTA_VERSION);
    when(catalogManager.federationEnabled()).thenReturn(true);
    when(catalogManager.prepareInstallPlan("core", APP_ID))
        .thenThrow(
            new CatalogPublisherAuthorizationException(),
            new IOException("private-storage-canary"));

    PlatformApiException rejected =
        assertThrows(PlatformApiException.class, () -> handler.sourceSwitchPreview("core", APP_ID));
    PlatformApiException storage =
        assertThrows(PlatformApiException.class, () -> handler.sourceSwitchPreview("core", APP_ID));

    assertEquals(409, rejected.statusCode());
    assertEquals("catalog_publisher_scope_rejected", rejected.errorCode());
    assertEquals(500, storage.statusCode());
    assertFalse(storage.getMessage().contains("private-storage-canary"));
  }

  @Test
  void update_whenCatalogOriginWouldSwitchWithoutBoundConsent_expectRejected() throws Exception {
    AppCatalogsApiHandler handler =
        new AppCatalogsApiHandler(catalogManager, appHost, () -> CURRENT_CRYPTA_VERSION);
    authorizeFederatedReviewerScope(handler);
    AppCatalogEntry entry = richCatalogEntry();
    Path scratch = tempDir.resolve("source-switch-scratch");
    Path staged = Files.createDirectories(scratch.resolve(BUNDLE_DIRECTORY));
    AppCatalogInstallPlan plan = sourceSwitchPlan(entry, staged, scratch);
    InstalledAppOrigin current = sourceSwitchCurrentOrigin();
    when(catalogManager.federationEnabled()).thenReturn(true);
    when(catalogManager.getApp("core", APP_ID)).thenReturn(entry);
    when(catalogManager.prepareInstallPlan("core", APP_ID)).thenReturn(plan);
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installedSnapshot()));
    when(appHost.catalogOrigin(APP_ID)).thenReturn(Optional.of(current));

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> handler.update("core", APP_ID));

    assertEquals("catalog_source_switch_consent_required", exception.errorCode());
    verify(appHost, never()).updateFromDirectory(any(), any());
  }

  @Test
  void update_whenOriginChangesInsideHostCommit_expectFreshSourceSwitchPreview() throws Exception {
    AppCatalogsApiHandler handler =
        new AppCatalogsApiHandler(catalogManager, appHost, () -> CURRENT_CRYPTA_VERSION);
    authorizeFederatedReviewerScope(handler);
    AppCatalogEntry entry = richCatalogEntry();
    Path scratch = tempDir.resolve("source-switch-race-scratch");
    Path staged = Files.createDirectories(scratch.resolve(BUNDLE_DIRECTORY));
    writeStagedManifest(staged, null);
    AppCatalogInstallPlan plan = sourceSwitchPlan(entry, staged, scratch);
    InstalledAppOrigin approvedCurrent = sourceSwitchCurrentOrigin();
    String consent =
        CatalogSourceSwitchConsent.evaluate(plan, approvedCurrent).consentDigestSha256();
    Map<String, List<String>> query = Map.of(SOURCE_SWITCH_CONSENT_PARAMETER, List.of(consent));
    when(catalogManager.federationEnabled()).thenReturn(true);
    when(catalogManager.getApp("core", APP_ID)).thenReturn(entry);
    when(catalogManager.prepareInstallPlan("core", APP_ID)).thenReturn(plan);
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installedSnapshot()));
    when(appHost.catalogOrigin(APP_ID)).thenReturn(Optional.of(approvedCurrent));
    when(appHost.updateCatalogFromDirectory(
            eq(APP_ID),
            eq(staged),
            any(),
            eq(AppHost.CatalogOriginExpectation.matching(approvedCurrent.selfDigestSha256())),
            any()))
        .thenThrow(
            new network.crypta.platform.apphost.AppHostException.CatalogOriginChangedException());

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> handler.update("core", APP_ID, query));

    assertEquals(409, exception.statusCode());
    assertEquals("catalog_source_switch_consent_required", exception.errorCode());
    verify(appHost)
        .updateCatalogFromDirectory(
            eq(APP_ID),
            eq(staged),
            any(),
            eq(AppHost.CatalogOriginExpectation.matching(approvedCurrent.selfDigestSha256())),
            any());
  }

  @Test
  void update_whenSourceSwitchChangesAppDataSchema_expectLifecycleRequired() throws Exception {
    AppCatalogsApiHandler handler =
        new AppCatalogsApiHandler(catalogManager, appHost, () -> CURRENT_CRYPTA_VERSION);
    authorizeFederatedReviewerScope(handler);
    AppCatalogEntry entry = richCatalogEntry();
    Path scratch = tempDir.resolve("source-switch-migration-scratch");
    Path staged = Files.createDirectories(scratch.resolve(BUNDLE_DIRECTORY));
    writeStagedManifest(staged, 2);
    AppCatalogInstallPlan plan = sourceSwitchPlan(entry, staged, scratch);
    InstalledAppOrigin approvedCurrent = sourceSwitchCurrentOrigin();
    String consent =
        CatalogSourceSwitchConsent.evaluate(plan, approvedCurrent).consentDigestSha256();
    Map<String, List<String>> query = Map.of(SOURCE_SWITCH_CONSENT_PARAMETER, List.of(consent));
    when(catalogManager.federationEnabled()).thenReturn(true);
    when(catalogManager.getApp("core", APP_ID)).thenReturn(entry);
    when(catalogManager.prepareInstallPlan("core", APP_ID)).thenReturn(plan);
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installedSnapshotWithSchema()));
    when(appHost.catalogOrigin(APP_ID)).thenReturn(Optional.of(approvedCurrent));

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> handler.update("core", APP_ID, query));

    assertEquals(409, exception.statusCode());
    assertEquals("app_data_migration_lifecycle_required", exception.errorCode());
    verify(appHost, never()).updateFromDirectory(any(), any());
    verify(appHost, never()).updateCatalogFromDirectory(any(), any(), any(), any(), any());
  }

  @Test
  void update_whenSourceSwitchCurrentSchemaIsUnreadable_expectLifecycleRequired() throws Exception {
    AppCatalogsApiHandler handler =
        new AppCatalogsApiHandler(catalogManager, appHost, () -> CURRENT_CRYPTA_VERSION);
    authorizeFederatedReviewerScope(handler);
    AppCatalogEntry entry = richCatalogEntry();
    Path scratch = tempDir.resolve("source-switch-unreadable-schema-scratch");
    Path staged = Files.createDirectories(scratch.resolve(BUNDLE_DIRECTORY));
    writeStagedManifest(staged, null);
    AppCatalogInstallPlan plan = sourceSwitchPlan(entry, staged, scratch);
    InstalledAppOrigin approvedCurrent = sourceSwitchCurrentOrigin();
    String consent =
        CatalogSourceSwitchConsent.evaluate(plan, approvedCurrent).consentDigestSha256();
    Map<String, List<String>> query = Map.of(SOURCE_SWITCH_CONSENT_PARAMETER, List.of(consent));
    when(catalogManager.federationEnabled()).thenReturn(true);
    when(catalogManager.getApp("core", APP_ID)).thenReturn(entry);
    when(catalogManager.prepareInstallPlan("core", APP_ID)).thenReturn(plan);
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    when(appHost.describe(APP_ID)).thenThrow(new IOException("installed manifest unreadable"));
    when(appHost.catalogOrigin(APP_ID)).thenReturn(Optional.of(approvedCurrent));

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> handler.update("core", APP_ID, query));

    assertEquals(409, exception.statusCode());
    assertEquals("app_data_migration_lifecycle_required", exception.errorCode());
    verify(appHost, never()).updateFromDirectory(any(), any());
    verify(appHost, never()).updateCatalogFromDirectory(any(), any(), any(), any(), any());
  }

  @Test
  void update_whenLegacyPlanHasTransientOriginContext_expectFederationPinningNotApplied()
      throws Exception {
    AppCatalogsApiHandler handler =
        new AppCatalogsApiHandler(catalogManager, appHost, () -> CURRENT_CRYPTA_VERSION);
    AppCatalogEntry entry = richCatalogEntry();
    Path scratch = tempDir.resolve("legacy-origin-context-scratch");
    Path staged = Files.createDirectories(scratch.resolve(BUNDLE_DIRECTORY));
    writeStagedManifest(staged, entry, null);
    AppCatalogInstallPlan plan =
        new AppCatalogInstallPlan(
            "core",
            entry,
            staged,
            scratch,
            new AppCatalogBundleVerificationResult(
                "publisher-legacy", "", "legacy-global-app-trust", "", false),
            Optional.of(
                new AppCatalogOriginContext(
                    "core",
                    "catalog-legacy",
                    "b".repeat(64),
                    "c".repeat(64),
                    "legacy-global-catalog-trust",
                    "",
                    "",
                    "",
                    false)));
    when(catalogManager.getApp("core", APP_ID)).thenReturn(entry);
    when(catalogManager.prepareInstallPlan("core", APP_ID)).thenReturn(plan);
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installedSnapshot()));
    when(appHost.updateFromDirectory(APP_ID, staged)).thenReturn(installedSnapshot());

    handler.update("core", APP_ID);

    verify(appHost).updateFromDirectory(APP_ID, staged);
    verify(appHost, never()).catalogOrigin(APP_ID);
    verify(appHost, never()).updateCatalogFromDirectory(any(), any(), any(), any(), any());
  }

  @Test
  void sourceSwitchPreview_whenFederationIsDisabled_expectRejectedBeforePreparation()
      throws Exception {
    AppCatalogsApiHandler handler =
        new AppCatalogsApiHandler(catalogManager, appHost, () -> CURRENT_CRYPTA_VERSION);

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> handler.sourceSwitchPreview("core", APP_ID));

    assertEquals(503, exception.statusCode());
    assertEquals("catalog_federation_unavailable", exception.errorCode());
    verify(catalogManager, never()).prepareInstallPlan(any(), any());
  }

  private Map<String, Object> listRichInstalledCatalogApp() throws Exception {
    AppCatalogsApiHandler handler =
        new AppCatalogsApiHandler(catalogManager, appHost, () -> CURRENT_CRYPTA_VERSION);
    when(catalogManager.listApps("core")).thenReturn(List.of(richCatalogEntry()));
    when(appHost.describe(APP_ID)).thenReturn(Optional.of(installedSnapshot()));
    when(appHost.status(APP_ID)).thenReturn(Optional.empty());

    return handler.listApps("core").getFirst();
  }

  private static Map<String, Object> fields(Map<String, Object> source, String... keys) {
    Map<String, Object> selected = new LinkedHashMap<>();
    for (String key : keys) {
      selected.put(key, source.get(key));
    }
    return selected;
  }

  private AppCatalogsApiHandler handlerWithRecommended(List<RecommendedAppCatalog> recommended) {
    return new AppCatalogsApiHandler(
        catalogManager,
        appHost,
        () -> null,
        AppReviewPolicy.DEFAULT,
        TrustedReviewerKeys::empty,
        null,
        () -> recommended);
  }

  private static RecommendedAppCatalog recommended(String source, String trustedKeyId) {
    return RecommendedAppCatalog.fromRawSource(
        RecommendedAppCatalogs.FIRST_PARTY_BETA_CATALOG_ID,
        "Crypta First-Party Beta Catalog",
        "First-party beta apps maintained by the Crypta project.",
        "beta",
        source,
        trustedKeyId,
        "first-party-review");
  }

  private static AppCatalogSourceSnapshot firstPartyCatalogSnapshot() {
    return firstPartyCatalogSnapshot(FIRST_PARTY_TRUSTED_KEY_ID);
  }

  private static AppCatalogSourceSnapshot firstPartyCatalogSnapshotWithoutSigningKey() {
    return firstPartyCatalogSnapshot(null);
  }

  private static AppCatalogSourceSnapshot firstPartyCatalogSnapshot(String signatureKeyId) {
    Instant generatedAt = Instant.parse(GENERATED_AT_TEXT);
    Instant addedAt = Instant.parse("2026-04-24T12:01:00Z");
    Instant refreshedAt = Instant.parse(REFRESHED_AT_TEXT);
    URI source = URI.create(FIRST_PARTY_SOURCE);
    return new AppCatalogSourceSnapshot(
        RecommendedAppCatalogs.FIRST_PARTY_BETA_CATALOG_ID,
        CORE_CATALOG_NAME,
        source,
        generatedAt,
        2,
        addedAt,
        refreshedAt,
        refreshedAt,
        refreshedAt,
        AppCatalogFetchStatus.SUCCESS,
        Optional.empty(),
        Optional.empty(),
        Optional.of(source.toString()),
        Optional.ofNullable(signatureKeyId));
  }

  private void assertCatalogFailureStatus(String code, int statusCode) throws Exception {
    reset(catalogManager);
    AppCatalogsApiHandler handler = new AppCatalogsApiHandler(catalogManager, appHost, () -> null);
    when(catalogManager.listCatalogs()).thenThrow(new AppCatalogException(code, "catalog failed"));

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, handler::listCatalogs);

    assertEquals(statusCode, exception.statusCode());
    assertEquals(code, exception.errorCode());
    assertEquals("catalog failed", exception.getMessage());
  }

  private AppCatalogEntry richCatalogEntry() {
    return new AppCatalogEntry(
        APP_ID,
        QUEUE_MANAGER_NAME,
        CATALOG_VERSION,
        QUEUE_MANAGER_SUMMARY,
        URI.create("https://example.invalid/app"),
        URI.create("https://example.invalid/repo"),
        "MIT",
        List.of("productivity", "network"),
        new AppCatalogCompatibilityMetadata("0.1.0", "0.9.99"),
        new AppCatalogReviewMetadata(
            AppCatalogReviewStatus.REVIEWED, "Reviewed for local operator safety."),
        new AppCatalogChangelog(
            Optional.of("Adds queue retry controls."),
            Optional.of(URI.create("https://example.invalid/changelog.txt"))),
        List.of(URI.create("https://example.invalid/shot-1.png")),
        productionMetadata(),
        maintenanceMetadata(),
        URI.create(QUEUE_MANAGER_BUNDLE_URI),
        "0".repeat(64),
        0L,
        AppCatalogEntry.ZIP_BUNDLE_TYPE,
        List.of(QUEUE_READ_PERMISSION, QUEUE_WRITE_PERMISSION),
        Map.of(
            QUEUE_READ_PERMISSION,
            "Reads the local transfer queue.",
            QUEUE_WRITE_PERMISSION,
            "Lets the app manage queue entries."));
  }

  private AppCatalogEntry richCatalogEntryWithTrustedReceipt(KeyPair reviewerKeyPair) {
    return richCatalogEntryWithTrustedReceipt(reviewerKeyPair, AppReviewReceiptStatus.REVIEWED);
  }

  private AppCatalogEntry statusOnlySubmissionCatalogEntry() {
    AppCatalogEntry entry = richCatalogEntry();
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
        new AppCatalogReviewMetadata(AppCatalogReviewStatus.SUBMITTED, null),
        entry.changelog(),
        entry.screenshots(),
        entry.productionMetadata(),
        entry.maintenanceMetadata(),
        entry.bundleUri(),
        entry.bundleSha256(),
        entry.bundleSizeBytes(),
        entry.bundleType(),
        entry.permissions(),
        entry.permissionRationales());
  }

  private AppCatalogEntry richCatalogEntryWithTrustedReceipt(
      KeyPair reviewerKeyPair, AppReviewReceiptStatus status) {
    AppCatalogEntry entry = richCatalogEntry();
    AppReviewReceipt receipt =
        AppReviewReceiptSigner.sign(reviewPayload(entry, status), reviewerKeyPair.getPrivate());
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
        receipt,
        entry.changelog(),
        entry.screenshots(),
        entry.productionMetadata(),
        entry.maintenanceMetadata(),
        entry.bundleUri(),
        entry.bundleSha256(),
        entry.bundleSizeBytes(),
        entry.bundleType(),
        entry.permissions(),
        entry.permissionRationales());
  }

  private static AppCatalogProductionMetadata productionMetadata() {
    return new AppCatalogProductionMetadata(
        AppCatalogChannel.BETA,
        AppCatalogSupportStatus.EXPERIMENTAL,
        AppCatalogDeprecationStatus.DEPRECATED,
        Optional.of("Use Queue Manager stable."),
        Optional.of("queue-manager-stable"),
        List.of(
            new AppCatalogSecurityAdvisory(
                SECURITY_ADVISORY_ID_0001, URI.create(SECURITY_ADVISORY_URI_0001))),
        true);
  }

  private static AppCatalogMaintenanceMetadata maintenanceMetadata() {
    return new AppCatalogMaintenanceMetadata(
        Optional.of("crypta-core"),
        Optional.of(URI.create("https://example.invalid/crypta/owners/core")),
        Optional.of(AppCatalogMaintenanceMetadata.SupportLevel.CORE),
        Optional.of(AppCatalogMaintenanceMetadata.DataSchemaPolicy.STATELESS),
        Optional.of(AppCatalogMaintenanceMetadata.MigrationPolicy.NONE),
        Optional.of(AppCatalogMaintenanceMetadata.BackupRestoreSupport.NOT_APPLICABLE),
        Optional.of(AppCatalogMaintenanceMetadata.SecurityPolicy.CATALOG_ADVISORIES),
        Optional.of(AppCatalogMaintenanceMetadata.DeprecationPolicy.NONE),
        Optional.of(URI.create("https://example.invalid/crypta/apps/queue-manager/support")),
        true);
  }

  private static AppReviewReceiptPayload reviewPayload(
      AppCatalogEntry entry, AppReviewReceiptStatus status) {
    return new AppReviewReceiptPayload(
        AppReviewReceiptPayload.RECEIPT_VERSION,
        entry.appId(),
        entry.version(),
        entry.bundleSha256(),
        entry.bundleSizeBytes(),
        Optional.empty(),
        REVIEW_POLICY_ID,
        REVIEW_POLICY_VERSION,
        status,
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
            REVIEWER_DISPLAY_NAME,
            REVIEW_POLICY_ID));
  }

  private static TrustedReviewerKeys revokedReviewerKeys(KeyPair keyPair) {
    return TrustedReviewerKeys.of(
        TrustedReviewerKey.ed25519(
            REVIEWER_KEY_ID,
            keyPair.getPublic().getEncoded(),
            REVIEWER_DISPLAY_NAME,
            REVIEW_POLICY_ID,
            REVIEW_POLICY_VERSION,
            TrustedReviewerKeyLifecycle.of(
                TrustedReviewerKeyStatus.REVOKED,
                null,
                null,
                Instant.parse(SECURITY_POLICY_UPDATED_AT_TEXT),
                "Reviewer key compromise drill.",
                null,
                null)));
  }

  private static AppCatalogSecurityPolicy securityResponsePolicy() {
    AppCatalogSecurityAdvisoryRecord advisory =
        new AppCatalogSecurityAdvisoryRecord(
            SECURITY_ADVISORY_ID_0001,
            URI.create(SECURITY_ADVISORY_URI_0001),
            "Queue Manager vulnerable release",
            AppCatalogSecuritySeverity.CRITICAL,
            AppCatalogSecurityStatus.PUBLISHED,
            AppCatalogSecurityAction.DENYLIST,
            "Upgrade to the reviewed replacement version.",
            Instant.parse("2026-06-11T00:00:00Z"),
            Instant.parse(SECURITY_POLICY_UPDATED_AT_TEXT),
            Optional.of(APP_ID),
            Optional.of(EXPORT_BEFORE_REMOVAL_GUIDANCE));
    AppCatalogVersionDenylistEntry denylist =
        new AppCatalogVersionDenylistEntry(
            "deny-queue-1-2-0",
            APP_ID,
            CATALOG_VERSION,
            advisory.id(),
            KNOWN_VULNERABLE_RELEASE,
            Optional.of(APP_ID),
            Optional.of(EXPORT_BEFORE_REMOVAL_GUIDANCE));
    return new AppCatalogSecurityPolicy(List.of(advisory), List.of(denylist));
  }

  private static AppCatalogSecurityPolicy advisoryOnlySecurityResponsePolicy() {
    AppCatalogSecurityAdvisoryRecord advisory =
        new AppCatalogSecurityAdvisoryRecord(
            SECURITY_ADVISORY_ID_0002,
            URI.create("https://example.invalid/advisories/CRYPTA-2026-0002"),
            "Queue Manager advisory only",
            AppCatalogSecuritySeverity.HIGH,
            AppCatalogSecurityStatus.PUBLISHED,
            AppCatalogSecurityAction.BLOCK_UPDATE,
            "Block updates until the reviewed replacement is available.",
            Instant.parse("2026-06-13T00:00:00Z"),
            Instant.parse("2026-06-13T12:00:00Z"),
            Optional.of(APP_ID),
            Optional.of("Keep installed data until a replacement is reviewed."));
    return new AppCatalogSecurityPolicy(List.of(advisory), List.of());
  }

  private static AppCatalogSecurityPolicy denylistReplacementOnlySecurityResponsePolicy() {
    AppCatalogSecurityAdvisoryRecord advisory =
        new AppCatalogSecurityAdvisoryRecord(
            SECURITY_ADVISORY_ID_0001,
            URI.create(SECURITY_ADVISORY_URI_0001),
            "Queue Manager vulnerable release",
            AppCatalogSecuritySeverity.CRITICAL,
            AppCatalogSecurityStatus.PUBLISHED,
            AppCatalogSecurityAction.DENYLIST,
            "Upgrade to the reviewed replacement version.",
            Instant.parse("2026-06-11T00:00:00Z"),
            Instant.parse(SECURITY_POLICY_UPDATED_AT_TEXT),
            Optional.empty(),
            Optional.of(EXPORT_BEFORE_REMOVAL_GUIDANCE));
    AppCatalogVersionDenylistEntry denylist =
        new AppCatalogVersionDenylistEntry(
            "deny-queue-1-2-0",
            APP_ID,
            CATALOG_VERSION,
            advisory.id(),
            KNOWN_VULNERABLE_RELEASE,
            Optional.of(APP_ID),
            Optional.of(EXPORT_BEFORE_REMOVAL_GUIDANCE));
    return new AppCatalogSecurityPolicy(List.of(advisory), List.of(denylist));
  }

  private static AppCatalogSecurityDecision denylistedSecurityDecision() {
    return new AppCatalogSecurityDecision(
        AppCatalogSecurityDecisionStatus.DENYLISTED,
        AppCatalogSecurityAction.DENYLIST,
        AppCatalogSecuritySeverity.CRITICAL,
        List.of(SECURITY_ADVISORY_ID_0001),
        false,
        true,
        true,
        true,
        "Export app data before uninstalling.",
        APP_ID,
        List.of(KNOWN_VULNERABLE_RELEASE));
  }

  private static AppCatalogSecurityDecision warningSecurityDecision() {
    return new AppCatalogSecurityDecision(
        AppCatalogSecurityDecisionStatus.WARNING,
        AppCatalogSecurityAction.WARN,
        AppCatalogSecuritySeverity.HIGH,
        List.of(SECURITY_ADVISORY_ID_0002),
        true,
        false,
        false,
        true,
        null,
        null,
        List.of("Security advisory requires operator acknowledgement."));
  }

  private static Map<String, List<String>> reviewAcknowledgedQuery() {
    return Map.of("reviewAcknowledged", List.of("true"));
  }

  private static Map<String, Object> trustedReviewTrustMap() {
    return Map.of(
        STATUS_FIELD,
        TRUSTED_REVIEWED_STATUS,
        TRUSTED_FIELD,
        true,
        POSITIVE_FIELD,
        true,
        "reviewerKeyId",
        REVIEWER_KEY_ID,
        "reviewerKeyStatus",
        ACTIVE_STATUS,
        "policyId",
        REVIEW_POLICY_ID,
        "policyVersion",
        REVIEW_POLICY_VERSION);
  }

  private static AppReviewTransparencyLog.ReviewTrustMapSubject reviewTrustMapSubject(
      String appVersion, String artifactSha256, long artifactSizeBytes) {
    return new AppReviewTransparencyLog.ReviewTrustMapSubject(
        APP_ID, appVersion, "core", artifactSha256, artifactSizeBytes);
  }

  private static void assertRedactsReviewerPublicKey(Object output, KeyPair reviewerKeyPair) {
    String encodedPublicKey =
        Base64.getEncoder().encodeToString(reviewerKeyPair.getPublic().getEncoded());
    String rendered = output.toString();
    assertFalse(rendered.contains(encodedPublicKey));
    assertFalse(rendered.contains("public.key.base64"));
  }

  private static KeyPair reviewerKeyPair() throws NoSuchAlgorithmException {
    return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
  }

  private AppCatalogInstallPlan plan(AppCatalogEntry entry) throws IOException {
    Path scratch = tempDir.resolve("scratch-" + entry.version());
    Path staged = scratch.resolve(BUNDLE_DIRECTORY);
    Files.createDirectories(staged);
    writeStagedManifest(staged, entry, null);
    return new AppCatalogInstallPlan("core", entry, staged, scratch);
  }

  private AppCatalogInstallPlan federatedPlan(AppCatalogEntry entry) throws IOException {
    AppCatalogInstallPlan legacy = plan(entry);
    return new AppCatalogInstallPlan(
        "core",
        entry,
        legacy.stagedBundleDirectory(),
        legacy.scratchDirectory(),
        new AppCatalogBundleVerificationResult(
            "publisher-key",
            "2".repeat(64),
            "publisher-binding",
            "3".repeat(64),
            true,
            "1".repeat(64)),
        Optional.of(
            new AppCatalogOriginContext(
                "core",
                "catalog-key",
                "b".repeat(64),
                "c".repeat(64),
                "catalog-binding",
                "d".repeat(64),
                "e".repeat(64),
                "f".repeat(64),
                true)));
  }

  private static AppCatalogInstallPlan sourceSwitchPlan(
      AppCatalogEntry entry, Path staged, Path scratch) {
    return new AppCatalogInstallPlan(
        "core",
        entry,
        staged,
        scratch,
        new AppCatalogBundleVerificationResult(
            "publisher-new",
            "2".repeat(64),
            "publisher-binding-new",
            "3".repeat(64),
            true,
            "1".repeat(64)),
        Optional.of(
            new AppCatalogOriginContext(
                "core",
                "catalog-new",
                "b".repeat(64),
                "c".repeat(64),
                "catalog-binding-new",
                "d".repeat(64),
                "e".repeat(64),
                "f".repeat(64),
                true)));
  }

  private static InstalledAppOrigin sourceSwitchCurrentOrigin() {
    return InstalledAppOrigin.create(
        APP_ID,
        INSTALLED_VERSION,
        "4".repeat(64),
        "other-catalog",
        "catalog-old",
        "5".repeat(64),
        "6".repeat(64),
        "publisher-old",
        "7".repeat(64),
        "0".repeat(64),
        "",
        TRUSTED_REVIEWED_STATUS,
        "catalog-binding-old",
        "8".repeat(64),
        "9".repeat(64),
        "a".repeat(64),
        Instant.parse(GENERATED_AT_TEXT),
        null);
  }

  private static void authorizeFederatedReviewerScope(AppCatalogsApiHandler handler)
      throws IOException {
    CatalogScopedReviewerPolicy policy = mock(CatalogScopedReviewerPolicy.class);
    CatalogScopedReviewerPolicy.Verification verification =
        mock(CatalogScopedReviewerPolicy.Verification.class);
    when(verification.authorized()).thenReturn(true);
    when(policy.evaluate(any(), any(), any(), any(), any())).thenReturn(verification);
    handler.setCatalogScopedReviewerPolicy(policy);
  }

  private void writeStagedManifest(Path staged, Integer schemaVersion) throws IOException {
    writeStagedManifest(staged, minimalCatalogEntry(), schemaVersion);
  }

  private void writeStagedManifest(Path staged, AppCatalogEntry entry, Integer schemaVersion)
      throws IOException {
    String schema = schemaVersion == null ? "" : "app.data.schema.current=" + schemaVersion + '\n';
    Files.writeString(
        staged.resolve("cryptad-app.properties"),
        """
        manifest.version=1
        app.id=%s
        app.name=%s
        app.version=%s
        app.exec=bin/launch.sh
        app.permissions=%s
        %s\
        """
            .formatted(
                entry.appId(),
                QUEUE_MANAGER_NAME,
                entry.version(),
                String.join(",", entry.permissions()),
                schema));
  }

  private AppCatalogEntry minimalCatalogEntry() {
    return catalogEntryWithVersion(CATALOG_VERSION);
  }

  private AppCatalogEntry catalogEntryWithApiCompatibility(
      AppApiCompatibilityMetadata apiCompatibility) {
    return new AppCatalogEntry(
        APP_ID,
        QUEUE_MANAGER_NAME,
        CATALOG_VERSION,
        QUEUE_MANAGER_SUMMARY,
        null,
        null,
        null,
        List.of(),
        new AppCatalogCompatibilityMetadata(null, null, apiCompatibility),
        AppCatalogReviewMetadata.EMPTY,
        AppCatalogChangelog.EMPTY,
        List.of(),
        URI.create(QUEUE_MANAGER_BUNDLE_URI),
        "0".repeat(64),
        0L,
        AppCatalogEntry.ZIP_BUNDLE_TYPE,
        List.of(QUEUE_READ_PERMISSION),
        Map.of());
  }

  private AppCatalogEntry catalogEntryWithVersion(String version) {
    return new AppCatalogEntry(
        APP_ID,
        QUEUE_MANAGER_NAME,
        version,
        QUEUE_MANAGER_SUMMARY,
        URI.create(QUEUE_MANAGER_BUNDLE_URI),
        "0".repeat(64),
        0L,
        AppCatalogEntry.ZIP_BUNDLE_TYPE,
        List.of(QUEUE_READ_PERMISSION));
  }

  private AppCatalogEntry catalogEntryWithMinimumCryptaVersion(String minimumCryptaVersion) {
    return new AppCatalogEntry(
        APP_ID,
        QUEUE_MANAGER_NAME,
        CATALOG_VERSION,
        QUEUE_MANAGER_SUMMARY,
        null,
        null,
        null,
        List.of(),
        new AppCatalogCompatibilityMetadata(minimumCryptaVersion),
        AppCatalogReviewMetadata.EMPTY,
        AppCatalogChangelog.EMPTY,
        List.of(),
        URI.create(QUEUE_MANAGER_BUNDLE_URI),
        "0".repeat(64),
        0L,
        AppCatalogEntry.ZIP_BUNDLE_TYPE,
        List.of(QUEUE_READ_PERMISSION),
        Map.of());
  }

  private InstalledAppSnapshot installedSnapshot() {
    return installedSnapshot(INSTALLED_VERSION, List.of(QUEUE_READ_PERMISSION, "network.access"));
  }

  private InstalledAppSnapshot installedSnapshot(String version, List<String> permissions) {
    AppManifest manifest =
        new AppManifest(
            1,
            APP_ID,
            QUEUE_MANAGER_NAME,
            version,
            "bin/launch.sh",
            AppUiMode.STATIC,
            "static/index.html",
            permissions,
            null,
            null);
    InstalledAppPaths paths =
        new InstalledAppPaths(
            APP_ID,
            tempDir.resolve(INSTALLED_TEXT).resolve(APP_ID),
            tempDir.resolve("data").resolve(APP_ID),
            tempDir.resolve("cache").resolve(APP_ID),
            tempDir.resolve("run").resolve(APP_ID));
    return new InstalledAppSnapshot(manifest, paths);
  }

  private InstalledAppSnapshot installedSnapshotWithSchema() {
    InstalledAppSnapshot base = installedSnapshot();
    AppManifest manifest = base.manifest();
    AppManifest withSchema =
        new AppManifest(
            manifest.manifestVersion(),
            manifest.appId(),
            manifest.appName(),
            manifest.appVersion(),
            manifest.execPathText(),
            manifest.uiMode(),
            manifest.uiEntry(),
            manifest.permissions(),
            manifest.apiCompatibility(),
            new AppDataSchemaContract(1, List.of(), List.of()),
            manifest.dataQuotaBytes(),
            manifest.cacheQuotaBytes(),
            manifest.sandboxPolicy(),
            manifest.restartPolicy(),
            manifest.restartMaxAttempts(),
            manifest.restartBackoffMillis());
    return new InstalledAppSnapshot(withSchema, base.paths());
  }
}
