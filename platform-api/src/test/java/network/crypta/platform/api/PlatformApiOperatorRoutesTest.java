package network.crypta.platform.api;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import network.crypta.platform.api.appdata.AppDataRecord;
import network.crypta.platform.api.appdata.AppDataService;
import network.crypta.platform.api.appdata.AppDataStoreConfig;
import network.crypta.platform.api.appdata.InMemoryAppDataStore;
import network.crypta.platform.api.appupdates.AppUpdateService;
import network.crypta.platform.api.content.subscriptions.ContentSubscriptionSchedulerConfig;
import network.crypta.platform.api.content.subscriptions.ContentSubscriptionService;
import network.crypta.platform.api.content.subscriptions.InMemoryContentSubscriptionStore;
import network.crypta.platform.api.json.PlatformApiJsonWriter;
import network.crypta.platform.api.networkbudget.AppNetworkBudgetConfig;
import network.crypta.platform.api.networkbudget.AppNetworkBudgetOperation;
import network.crypta.platform.api.networkbudget.AppNetworkBudgetService;
import network.crypta.platform.api.networkbudget.InMemoryAppNetworkBudgetStore;
import network.crypta.platform.appcatalog.AppCatalogChannel;
import network.crypta.platform.appcatalog.AppCatalogEntry;
import network.crypta.platform.appcatalog.AppCatalogManager.PendingCatalogDiscoveryEvidence;
import network.crypta.platform.appcatalog.AppCatalogManager;
import network.crypta.platform.appcatalog.CatalogScopeRevocation;
import network.crypta.platform.appcatalog.FederatedCatalogConflictEngine;
import network.crypta.platform.appcatalog.FederatedCatalogTrustBinding;
import network.crypta.platform.appcatalog.PendingCatalogDiscoveryRecommendation;
import network.crypta.platform.apphost.AppDiskUsageScanner;
import network.crypta.platform.apphost.AppHost;
import network.crypta.platform.apphost.InstalledAppOrigin;
import network.crypta.platform.appui.AppUiOriginRegistry;
import network.crypta.runtime.spi.BoundedContentFetchRequest;
import network.crypta.runtime.spi.BoundedContentFetchResult;
import network.crypta.runtime.spi.ContentFetchPort;
import network.crypta.runtime.spi.CoreSupportLifecycleSnapshot;
import network.crypta.runtime.spi.CoreSupportLifecycleStatus;
import network.crypta.runtime.spi.CoreUpdateActionPort;
import network.crypta.runtime.spi.DiagnosticReportSnapshot;
import network.crypta.runtime.spi.DiagnosticSectionSnapshot;
import network.crypta.runtime.spi.RuntimePorts;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Answers;
import org.mockito.ArgumentCaptor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
class PlatformApiOperatorRoutesTest {
  private static final String APP_ID = "feed-reader";
  private static final String BETA_DASHBOARD_SEGMENT = "beta-dashboard";
  private static final String FORM_FIELD_ASSIGNMENT = "form" + "Pass" + "word=secret-value";
  private static final String INTAKE_QUEUE_PROPERTY = "cryptad.appSubmissionIntakeDir";
  private static final String OPERATOR_SEGMENT = "operator";
  private static final String PARAM_PLAN_TOKEN = "planToken";
  private static final String SOURCE = "USK@example/feed/7/feed.json";
  private static final Instant NOW = Instant.parse("2026-05-24T12:00:00Z");
  private static final HexFormat HEX = HexFormat.of();

  @Test
  void route_whenSupportLifecycleRequested_expectReadOnlyFailClosedSnapshot() {
    PlatformApiRouter router = new PlatformApiRouter(runtimePorts());

    PlatformApiResponse response =
        router.route(request("GET", List.of("updates", "support-lifecycle"), Map.of()));
    PlatformApiResponse mutation =
        router.route(request("POST", List.of("updates", "support-lifecycle"), Map.of()));

    assertEquals(200, response.statusCode());
    assertTrue(response.body().contains("\"known\":false"));
    assertTrue(response.body().contains("\"runningStatus\":null"));
    assertTrue(response.body().contains("\"lifecycle_runtime_snapshot_unavailable\""));
    assertEquals(405, mutation.statusCode());
  }

  @Test
  void route_whenSupportLifecycleIsKnown_expectAuthenticatedOperatorProjection() {
    RuntimePorts ports = runtimePorts();
    CoreUpdateActionPort actionPort = mock(CoreUpdateActionPort.class);
    when(ports.coreUpdateAction()).thenReturn(actionPort);
    when(actionPort.supportLifecycleSnapshot()).thenReturn(revokedLifecycleSnapshot());
    PlatformApiRouter router = new PlatformApiRouter(ports);

    PlatformApiResponse response =
        router.route(request("GET", List.of("updates", "support-lifecycle"), Map.of()));

    assertEquals(200, response.statusCode());
    assertTrue(response.body().contains("\"known\":true"));
    assertTrue(response.body().contains("\"runningStatus\":\"revoked\""));
    assertTrue(response.body().contains("\"requiredReplacementBuild\":101"));
    assertTrue(response.body().contains("\"advisoryIds\":[\"CRYPTA-2026-001\"]"));
    assertTrue(response.body().contains("\"descriptorEdition\":2"));
  }

  @Test
  void route_whenAppPrincipalRequestsSupportLifecycle_expectOperatorOnlyDenial() {
    PlatformApiRouter router = new PlatformApiRouter(runtimePorts());
    List<String> route = List.of("updates", "support-lifecycle");
    List<String> permissions = List.of(PlatformApiCapabilities.UPDATES_READ);

    PlatformApiResponse appProcessResponse =
        router.route(
            request("GET", route, Map.of(), PlatformApiPrincipal.appToken(APP_ID, permissions)));
    PlatformApiResponse appBrowserResponse =
        router.route(
            request(
                "GET",
                route,
                Map.of(),
                PlatformApiPrincipal.appBrowserSession(APP_ID, permissions)));
    PlatformApiResponse appReadableCoreResponse =
        router.route(
            request(
                "GET",
                List.of("updates", "core"),
                Map.of(),
                PlatformApiPrincipal.appToken(APP_ID, permissions)));

    assertEquals(403, appProcessResponse.statusCode());
    assertTrue(appProcessResponse.body().contains("\"code\":\"forbidden\""));
    assertEquals(403, appBrowserResponse.statusCode());
    assertTrue(appBrowserResponse.body().contains("\"code\":\"forbidden\""));
    assertEquals(200, appReadableCoreResponse.statusCode());
    assertFalse(appReadableCoreResponse.body().contains("supportLifecycle"));
  }

  @Test
  void route_whenOperatorDashboardRequested_expectSectionShape() {
    PlatformApiRouter router = new PlatformApiRouter(runtimePorts());

    PlatformApiResponse response =
        router.route(request("GET", List.of(OPERATOR_SEGMENT, BETA_DASHBOARD_SEGMENT), Map.of()));

    assertEquals(200, response.statusCode());
    assertTrue(response.body().contains("\"overallStatus\""));
    assertTrue(response.body().contains("\"catalogs\""));
    assertTrue(response.body().contains("\"apps\""));
    assertTrue(response.body().contains("\"subscriptions\""));
    assertTrue(response.body().contains("\"trustGraph\""));
    assertTrue(response.body().contains("\"supportWarningCount\""));
    assertTrue(response.body().contains("\"coreSupportLifecycle\""));
    assertTrue(response.body().contains("\"platformApiCompatibility\""));
    assertTrue(response.body().contains("\"activeStableBaselines\":[\"1.0\"]"));
    assertTrue(response.body().contains("\"baselineRegistrySummary\""));
    assertTrue(response.body().contains("\"supportedBaselines\":[{\"id\":\"1.0\""));
    assertTrue(response.body().contains("\"status\":\"active\""));
    assertTrue(
        response
            .body()
            .contains("\"historyChainHealth\":\"bootstrap-only-not-release-authenticated\""));
    assertTrue(response.body().contains("no runtime compatibility observation is claimed"));
    assertTrue(response.body().contains("\"known\":false"));
  }

  @Test
  @SuppressWarnings("unchecked")
  void platformApiCompatibilitySnapshot_whenBaselineDeprecated_expectNotReportedAsActive() {
    PlatformApiBaselineRegistry current = PlatformApiBaselineRegistry.current();
    PlatformApiBaselineDefinition stable10 = current.definitions().getFirst();
    PlatformApiBaselineLineage previous = current.lineage().getLast();
    PlatformApiBaselineLineage deprecated =
        PlatformApiBaselineLineage.create(
            stable10.id(),
            stable10.definitionDigest(),
            PlatformApiBaselineStatus.DEPRECATED,
            PlatformApiBaselineEvidenceKind.PROTECTED_RELEASE,
            "f".repeat(64),
            previous.activationRelease(),
            previous.activationBuild(),
            previous.supportStartedRelease(),
            null,
            previous.lineageDigest());
    List<PlatformApiBaselineLineage> lineage = new java.util.ArrayList<>(current.lineage());
    lineage.add(deprecated);
    PlatformApiBaselineRegistry registry =
        PlatformApiBaselineRegistry.create(current.definitions(), lineage);

    Map<String, Object> snapshot =
        PlatformApiOperatorRoutes.platformApiCompatibilitySnapshot(
            PlatformApiContract.current(), registry);

    assertEquals(List.of(), snapshot.get("activeStableBaselines"));
    Map<String, Object> registrySummary =
        (Map<String, Object>) snapshot.get("baselineRegistrySummary");
    List<Map<String, Object>> supported =
        (List<Map<String, Object>>) registrySummary.get("supportedBaselines");
    assertEquals("1.0", supported.getFirst().get("id"));
    assertEquals("deprecated", supported.getFirst().get("status"));
  }

  @Test
  void route_whenOperatorRcDashboardRequested_expectRecoveryAndBudgetShape() {
    PlatformApiRouter router = new PlatformApiRouter(runtimePorts());

    PlatformApiResponse response =
        router.route(request("GET", List.of(OPERATOR_SEGMENT, "rc-dashboard"), Map.of()));

    assertEquals(200, response.statusCode());
    assertTrue(response.body().contains("\"dashboardKind\":\"operator-rc-recovery-dashboard\""));
    assertTrue(response.body().contains("\"operatorRcRecovery\""));
    assertTrue(response.body().contains("\"closedActionDispatch\":true"));
    assertTrue(response.body().contains("\"operatorRoutesInAppContract\":false"));
  }

  @Test
  void route_whenFederationSummaryRequested_expectLocalNonTransitiveTrustOnly() throws Exception {
    AppCatalogManager manager = mock(AppCatalogManager.class);
    when(manager.configuredCatalogIds()).thenReturn(List.of("community", "stale-source"));
    when(manager.federatedTrustBindings())
        .thenReturn(
            List.of(
                catalogTrustBinding(
                    Map.of(
                        "catalog-key-a", "f".repeat(64),
                        "catalog-key-b", "0".repeat(64)))));
    PlatformApiRouter router = new PlatformApiRouter(runtimePorts(), null, manager);

    PlatformApiResponse response =
        router.route(request("GET", List.of(OPERATOR_SEGMENT, "catalog-federation"), Map.of()));
    PlatformApiResponse appResponse =
        router.route(
            request(
                "GET",
                List.of(OPERATOR_SEGMENT, "catalog-federation"),
                Map.of(),
                PlatformApiPrincipal.appToken(APP_ID, List.of())));

    assertEquals(200, response.statusCode());
    assertTrue(response.body().contains("\"mode\":\"federated-local-trust\""));
    assertTrue(response.body().contains("\"catalogId\":\"community\""));
    assertTrue(response.body().contains("\"signerKeyIds\":[\"catalog-key-a\",\"catalog-key-b\"]"));
    assertTrue(
        response
            .body()
            .contains(
                "\"signerFingerprints\":[\"" + "f".repeat(64) + "\",\"" + "0".repeat(64) + "\"]"));
    assertTrue(
        response.body().contains("\"configuredCatalogIds\":[\"community\",\"stale-source\"]"));
    assertTrue(response.body().contains("\"configuredCatalogCount\":2"));
    assertTrue(response.body().contains("\"endorsementsAuthoritative\":false"));
    assertTrue(response.body().contains("\"transitiveTrust\":false"));
    assertEquals(403, appResponse.statusCode());
  }

  @Test
  void route_whenCatalogDiscoveryImported_expectPendingEvidenceOnly() throws Exception {
    AppCatalogManager manager = mock(AppCatalogManager.class);
    PendingCatalogDiscoveryRecommendation pending = pendingCatalogDiscovery();
    List<PendingCatalogDiscoveryEvidence> currentEvidence =
        List.of(
            new PendingCatalogDiscoveryEvidence(pending, true, pending.endorsementVerifications()));
    when(manager.federationEnabled()).thenReturn(true);
    when(manager.catalogDiscoveryEnabled()).thenReturn(true);
    when(manager.importCatalogDiscovery(any(byte[].class), eq(List.of()), any(Instant.class)))
        .thenReturn(pending);
    when(manager.currentPendingCatalogDiscoveries(any(Instant.class))).thenReturn(currentEvidence);
    PlatformApiRouter router = new PlatformApiRouter(runtimePorts(), null, manager);
    List<String> route = List.of(OPERATOR_SEGMENT, "catalog-federation", "discovery");
    Map<String, List<String>> parameters =
        Map.of(
            "descriptorBase64",
            List.of(
                Base64.getUrlEncoder()
                    .withoutPadding()
                    .encodeToString("{}".getBytes(StandardCharsets.UTF_8))));

    PlatformApiResponse imported = router.route(request("POST", route, parameters));
    PlatformApiResponse listed = router.route(request("GET", route, Map.of()));
    PlatformApiResponse appResponse =
        router.route(
            request("GET", route, Map.of(), PlatformApiPrincipal.appToken(APP_ID, List.of())));

    assertEquals(200, imported.statusCode());
    assertTrue(imported.body().contains("\"status\":\"pending\""));
    assertTrue(imported.body().contains("\"trustGranted\":false"));
    assertTrue(imported.body().contains("\"sourceConfigured\":false"));
    assertTrue(imported.body().contains("\"transitive\":false"));
    assertEquals(200, listed.statusCode());
    assertTrue(listed.body().contains("\"pendingCount\":1"));
    assertEquals(403, appResponse.statusCode());
  }

  @Test
  void route_whenCatalogDiscoveryUnavailableOrMalformed_expectClosedFailure() {
    AppCatalogManager unavailableManager = mock(AppCatalogManager.class);
    when(unavailableManager.federationEnabled()).thenReturn(true);
    PlatformApiRouter unavailableRouter =
        new PlatformApiRouter(runtimePorts(), null, unavailableManager);
    List<String> route = List.of(OPERATOR_SEGMENT, "catalog-federation", "discovery");
    AppCatalogManager availableManager = mock(AppCatalogManager.class);
    when(availableManager.federationEnabled()).thenReturn(true);
    when(availableManager.catalogDiscoveryEnabled()).thenReturn(true);
    PlatformApiRouter availableRouter =
        new PlatformApiRouter(runtimePorts(), null, availableManager);

    PlatformApiResponse unavailable = unavailableRouter.route(request("GET", route, Map.of()));
    PlatformApiResponse malformed =
        availableRouter.route(
            request("POST", route, Map.of("descriptorBase64", List.of("not base64!"))));

    assertEquals(503, unavailable.statusCode());
    assertTrue(unavailable.body().contains("\"code\":\"catalog_discovery_unavailable\""));
    assertEquals(400, malformed.statusCode());
    assertTrue(malformed.body().contains("\"code\":\"invalid_request\""));
  }

  @Test
  void route_whenPendingCatalogDiscoveryDiscarded_expectNoTrustMutation() throws Exception {
    AppCatalogManager manager = mock(AppCatalogManager.class);
    when(manager.federationEnabled()).thenReturn(true);
    when(manager.catalogDiscoveryEnabled()).thenReturn(true);
    when(manager.discardPendingCatalogDiscovery("descriptor-independent-beta")).thenReturn(true);
    PlatformApiRouter router = new PlatformApiRouter(runtimePorts(), null, manager);

    PlatformApiResponse response =
        router.route(
            request(
                "POST",
                List.of(
                    OPERATOR_SEGMENT,
                    "catalog-federation",
                    "discovery",
                    "descriptor-independent-beta",
                    "discard"),
                Map.of()));

    assertEquals(200, response.statusCode());
    assertTrue(response.body().contains("\"status\":\"discarded\""));
    assertTrue(response.body().contains("\"trustChanged\":false"));
    verify(manager, never()).putFederatedTrustBinding(any());
  }

  @Test
  void route_whenCatalogTrustSuspended_expectExplicitOperatorMutationOnly() throws Exception {
    AppCatalogManager manager = mock(AppCatalogManager.class);
    when(manager.federationEnabled()).thenReturn(true);
    FederatedCatalogTrustBinding suspended = suspendedCatalogTrustBinding();
    when(manager.transitionFederatedTrustBinding(
            eq("community"),
            eq(FederatedCatalogTrustBinding.Status.SUSPENDED),
            eq("incident review"),
            eq("host-operator"),
            any(Instant.class)))
        .thenReturn(suspended);
    PlatformApiRouter router = new PlatformApiRouter(runtimePorts(), null, manager);
    List<String> route = List.of(OPERATOR_SEGMENT, "catalog-federation", "community", "suspend");

    PlatformApiResponse response =
        router.route(request("POST", route, Map.of("reason", List.of("incident review"))));
    PlatformApiResponse appResponse =
        router.route(
            request(
                "POST",
                route,
                Map.of("reason", List.of("incident review")),
                PlatformApiPrincipal.appToken(APP_ID, List.of())));

    assertEquals(200, response.statusCode());
    assertTrue(response.body().contains("\"status\":\"suspended\""));
    assertEquals(403, appResponse.statusCode());
  }

  @Test
  void route_whenCatalogTrustApproved_expectExplicitBoundedLocalBinding() throws Exception {
    AppCatalogManager manager = mock(AppCatalogManager.class);
    when(manager.federationEnabled()).thenReturn(true);
    when(manager.federatedTrustBindings()).thenReturn(List.of());
    PlatformApiRouter router = new PlatformApiRouter(runtimePorts(), null, manager);
    List<String> route = List.of(OPERATOR_SEGMENT, "catalog-federation", "community", "trust");
    Map<String, List<String>> parameters =
        Map.of(
            "bindingId", List.of("binding-community"),
            "signerKeyId", List.of("community-catalog-2026"),
            "signerFingerprintSha256", List.of("1".repeat(64)),
            "channels", List.of("stable,beta"),
            "localPriority", List.of("100"),
            "reason", List.of("operator approval"));

    PlatformApiResponse response = router.route(request("POST", route, parameters));
    PlatformApiResponse appResponse =
        router.route(
            request("POST", route, parameters, PlatformApiPrincipal.appToken(APP_ID, List.of())));

    assertEquals(200, response.statusCode());
    assertTrue(response.body().contains("\"bindingId\":\"binding-community\""));
    assertTrue(response.body().contains("\"status\":\"active\""));
    assertEquals(403, appResponse.statusCode());
  }

  @Test
  void route_whenCatalogTrustApprovedWithRotatingSigners_expectCompleteSignerSetRetained()
      throws Exception {
    AppCatalogManager manager = mock(AppCatalogManager.class);
    when(manager.federationEnabled()).thenReturn(true);
    when(manager.federatedTrustBindings()).thenReturn(List.of(catalogTrustBinding()));
    PlatformApiRouter router = new PlatformApiRouter(runtimePorts(), null, manager);
    List<String> route = List.of(OPERATOR_SEGMENT, "catalog-federation", "community", "trust");
    Map<String, List<String>> parameters =
        Map.of(
            "bindingId", List.of("binding-1"),
            "signerKeyId", List.of("community-catalog-2026", "community-catalog-2027"),
            "signerFingerprintSha256", List.of("1".repeat(64), "2".repeat(64)),
            "channels", List.of("stable,beta"),
            "localPriority", List.of("100"),
            "reason", List.of("overlapping signer rotation"));

    PlatformApiResponse response = router.route(request("POST", route, parameters));

    ArgumentCaptor<FederatedCatalogTrustBinding> bindingCaptor =
        ArgumentCaptor.forClass(FederatedCatalogTrustBinding.class);
    verify(manager).putFederatedTrustBinding(bindingCaptor.capture());
    assertEquals(200, response.statusCode());
    assertEquals(
        Map.of(
            "community-catalog-2026", "1".repeat(64),
            "community-catalog-2027", "2".repeat(64)),
        bindingCaptor.getValue().signerFingerprints());
    assertEquals(NOW, bindingCaptor.getValue().createdAt());
  }

  @Test
  void route_whenCatalogSignerListsHaveDifferentSizes_expectRejected() {
    AppCatalogManager manager = mock(AppCatalogManager.class);
    when(manager.federationEnabled()).thenReturn(true);
    PlatformApiRouter router = new PlatformApiRouter(runtimePorts(), null, manager);
    List<String> route = List.of(OPERATOR_SEGMENT, "catalog-federation", "community", "trust");
    Map<String, List<String>> parameters =
        Map.of(
            "bindingId", List.of("binding-community"),
            "signerKeyId", List.of("community-catalog-2026", "community-catalog-2027"),
            "signerFingerprintSha256", List.of("1".repeat(64)),
            "channels", List.of("stable"),
            "localPriority", List.of("100"),
            "reason", List.of("invalid rotation"));

    PlatformApiResponse response = router.route(request("POST", route, parameters));

    assertEquals(400, response.statusCode());
  }

  @Test
  void route_whenMixedCaseCatalogTrustIsReapproved_expectNormalizedIdentityAndOriginalCreatedAt()
      throws Exception {
    AppCatalogManager manager = mock(AppCatalogManager.class);
    when(manager.federationEnabled()).thenReturn(true);
    when(manager.federatedTrustBindings()).thenReturn(List.of(catalogTrustBinding()));
    PlatformApiRouter router = new PlatformApiRouter(runtimePorts(), null, manager);
    List<String> route = List.of(OPERATOR_SEGMENT, "catalog-federation", "Community", "trust");
    Map<String, List<String>> parameters =
        Map.of(
            "bindingId", List.of("binding-1"),
            "signerKeyId", List.of("community-catalog-2026"),
            "signerFingerprintSha256", List.of("1".repeat(64)),
            "channels", List.of("stable,beta"),
            "localPriority", List.of("100"),
            "reason", List.of("operator reapproval"));

    PlatformApiResponse response = router.route(request("POST", route, parameters));

    ArgumentCaptor<FederatedCatalogTrustBinding> bindingCaptor =
        ArgumentCaptor.forClass(FederatedCatalogTrustBinding.class);
    verify(manager).putFederatedTrustBinding(bindingCaptor.capture());
    assertEquals(200, response.statusCode());
    assertEquals("community", bindingCaptor.getValue().catalogId());
    assertEquals(NOW, bindingCaptor.getValue().createdAt());
  }

  @Test
  void route_whenFederationDisabledAndTrustMutationRequested_expectUnavailable() {
    AppCatalogManager manager = mock(AppCatalogManager.class);
    PlatformApiRouter router = new PlatformApiRouter(runtimePorts(), null, manager);
    List<String> route = List.of(OPERATOR_SEGMENT, "catalog-federation", "community", "suspend");

    PlatformApiResponse response =
        router.route(request("POST", route, Map.of("reason", List.of("operator request"))));

    assertEquals(503, response.statusCode());
    assertTrue(response.body().contains("\"code\":\"catalog_federation_unavailable\""));
  }

  @Test
  void route_whenOperatorRevokesExactScope_expectBoundedRequestAndAppPrincipalDenied()
      throws Exception {
    AppCatalogManager manager = mock(AppCatalogManager.class);
    when(manager.federationEnabled()).thenReturn(true);
    AppUpdateService updates = mock(AppUpdateService.class);
    when(updates.revokeCatalogScope(eq("publisher"), any()))
        .thenReturn(Map.of("status", "revoked"));
    PlatformApiRouter router = routerWithUpdateService(mock(AppHost.class), manager, updates);
    List<String> path =
        List.of(OPERATOR_SEGMENT, "catalog-federation", "community", "publisher-scope-revoke");
    Map<String, List<String>> params =
        Map.of(
            "scopeId",
            List.of("s".repeat(128)),
            "expectedDigestSha256",
            List.of("a".repeat(64)),
            "reason",
            List.of("operator revocation"));

    PlatformApiResponse accepted = router.route(request("POST", path, params));
    PlatformApiResponse denied =
        router.route(
            request("POST", path, params, PlatformApiPrincipal.appToken(APP_ID, List.of())));

    assertEquals(200, accepted.statusCode());
    assertEquals(403, denied.statusCode());
    ArgumentCaptor<CatalogScopeRevocation> captured =
        ArgumentCaptor.forClass(CatalogScopeRevocation.class);
    verify(updates).revokeCatalogScope(eq("publisher"), captured.capture());
    assertEquals("community", captured.getValue().catalogId());
    assertEquals("s".repeat(128), captured.getValue().scopeId());
    assertEquals("a".repeat(64), captured.getValue().expectedDigestSha256());
    assertEquals("host-operator", captured.getValue().operatorId());
  }

  @Test
  void route_whenScopeDigestInvalidOrFederationDisabled_expectNoMutation() throws Exception {
    AppCatalogManager manager = mock(AppCatalogManager.class);
    AppUpdateService updates = mock(AppUpdateService.class);
    PlatformApiRouter router = routerWithUpdateService(mock(AppHost.class), manager, updates);
    List<String> path =
        List.of(OPERATOR_SEGMENT, "catalog-federation", "community", "reviewer-scope-revoke");
    Map<String, List<String>> params =
        Map.of(
            "scopeId",
            List.of("scope-community"),
            "expectedDigestSha256",
            List.of("private-canary"),
            "reason",
            List.of("operator revocation"));

    assertEquals(503, router.route(request("POST", path, params)).statusCode());
    when(manager.federationEnabled()).thenReturn(true);
    PlatformApiResponse invalid = router.route(request("POST", path, params));
    assertEquals(400, invalid.statusCode());
    assertFalse(invalid.body().contains("private-canary"));
    verify(updates, never()).revokeCatalogScope(any(), any());
  }

  @Test
  void route_whenCatalogConflictRequested_expectExactOperatorOnlySummary() {
    AppHost host = mock(AppHost.class);
    AppCatalogManager manager = mock(AppCatalogManager.class);
    AppUpdateService updateService = mock(AppUpdateService.class);
    when(manager.federationEnabled()).thenReturn(true);
    when(updateService.federatedConflict(APP_ID))
        .thenReturn(
            Map.of(
                "appId",
                APP_ID,
                "conflictId",
                "catalog-conflict-1234",
                "subjectSetDigestSha256",
                "1".repeat(64),
                "hard",
                true));
    PlatformApiRouter router = routerWithUpdateService(host, manager, updateService);
    List<String> route = List.of(OPERATOR_SEGMENT, "catalog-federation", "conflicts", APP_ID);

    PlatformApiResponse response = router.route(request("GET", route, Map.of()));
    PlatformApiResponse appResponse =
        router.route(
            request("GET", route, Map.of(), PlatformApiPrincipal.appToken(APP_ID, List.of())));

    assertEquals(200, response.statusCode());
    assertTrue(response.body().contains("\"conflictId\":\"catalog-conflict-1234\""));
    assertTrue(response.body().contains("\"subjectSetDigestSha256\":\"" + "1".repeat(64)));
    assertEquals(403, appResponse.statusCode());
  }

  @Test
  void route_whenExactCatalogConflictResolved_expectDigestBoundOperatorDecision() {
    AppHost host = mock(AppHost.class);
    AppCatalogManager manager = mock(AppCatalogManager.class);
    AppUpdateService updateService = mock(AppUpdateService.class);
    when(manager.federationEnabled()).thenReturn(true);
    when(updateService.resolveFederatedConflict(
            eq(APP_ID),
            eq("catalog-conflict-1234"),
            eq("1".repeat(64)),
            eq(
                FederatedCatalogConflictEngine.ResolutionKind.EXPLICIT_SOURCE_SWITCH_REQUIRED
                    .name()),
            isNull(),
            isNull(),
            eq("require exact switch consent")))
        .thenReturn(
            Map.of(
                "appId", APP_ID,
                "conflictId", "catalog-conflict-1234",
                "resolutionStatus", "applicable"));
    PlatformApiRouter router = routerWithUpdateService(host, manager, updateService);
    List<String> route =
        List.of(OPERATOR_SEGMENT, "catalog-federation", "conflicts", APP_ID, "resolve");
    Map<String, List<String>> parameters =
        Map.of(
            "conflictId", List.of("catalog-conflict-1234"),
            "subjectSetDigestSha256", List.of("1".repeat(64)),
            "kind", List.of("explicit-source-switch-required"),
            "reason", List.of("require exact switch consent"));

    PlatformApiResponse response = router.route(request("POST", route, parameters));

    assertEquals(200, response.statusCode());
    assertTrue(response.body().contains("\"resolutionStatus\":\"applicable\""));
  }

  @Test
  void route_whenCatalogOriginRequested_expectPathFreeOperatorOnlyProvenance() throws Exception {
    AppHost host = mock(AppHost.class);
    when(host.catalogOrigin(APP_ID)).thenReturn(Optional.of(installedOrigin()));
    PlatformApiRouter router = new PlatformApiRouter(runtimePorts(), host);
    List<String> route = List.of(OPERATOR_SEGMENT, "apps", APP_ID, "catalog-origin");

    PlatformApiResponse response = router.route(request("GET", route, Map.of()));
    PlatformApiResponse appResponse =
        router.route(
            request(
                "GET", route, Map.of(), PlatformApiPrincipal.appBrowserSession(APP_ID, List.of())));

    assertEquals(200, response.statusCode());
    assertTrue(response.body().contains("\"catalogId\":\"community\""));
    assertTrue(response.body().contains("\"catalogTrustBindingId\":\"binding-1\""));
    assertTrue(
        response.body().contains("\"signedContentDigestSha256\":\"" + "d".repeat(64) + "\""));
    assertFalse(response.body().contains("/tmp/"));
    assertEquals(403, appResponse.statusCode());
  }

  @Test
  void route_whenAppPrincipalRequestsSourceSwitchPreview_expectDeniedBeforePreparation() {
    AppHost host = mock(AppHost.class);
    AppCatalogManager manager = mock(AppCatalogManager.class);
    PlatformApiRouter router = new PlatformApiRouter(runtimePorts(), host, manager);
    List<String> route =
        List.of(OPERATOR_SEGMENT, "apps", APP_ID, "catalog-origin", "switch-preview");

    PlatformApiResponse response =
        router.route(
            request(
                "POST",
                route,
                Map.of("targetCatalogId", List.of("community")),
                PlatformApiPrincipal.appBrowserSession(APP_ID, List.of())));

    assertEquals(403, response.statusCode());
  }

  @Test
  void route_whenGetSourceSwitchPreview_expectPostOnlyWithoutPreparation() {
    AppHost host = mock(AppHost.class);
    AppCatalogManager manager = mock(AppCatalogManager.class);
    PlatformApiRouter router = new PlatformApiRouter(runtimePorts(), host, manager);
    List<String> route =
        List.of(OPERATOR_SEGMENT, "apps", APP_ID, "catalog-origin", "switch-preview");

    PlatformApiResponse response =
        router.route(request("GET", route, Map.of("targetCatalogId", List.of("community"))));

    assertEquals(405, response.statusCode());
    assertEquals("POST", response.headers().get("Allow"));
  }

  @Test
  void route_whenFederatedFallbackHasNoScopedReviewerPolicy_expectUnavailableBeforePreparation()
      throws Exception {
    AppHost host = mock(AppHost.class);
    AppCatalogManager manager = mock(AppCatalogManager.class);
    AppCatalogEntry entry = mock(AppCatalogEntry.class);
    when(entry.appId()).thenReturn(APP_ID);
    when(manager.federationEnabled()).thenReturn(true);
    when(manager.getApp("core", APP_ID)).thenReturn(entry);
    when(host.describe(APP_ID)).thenReturn(Optional.empty());
    PlatformApiRouter router = new PlatformApiRouter(runtimePorts(), host, manager);

    PlatformApiResponse response =
        router.route(
            request("POST", List.of("app-catalogs", "core", "apps", APP_ID, "install"), Map.of()));

    try (var _ = verify(manager, never()).prepareInstallPlan(any(), any())) {
      assertEquals(503, response.statusCode());
      assertTrue(response.body().contains("catalog_federation_unavailable"));
    }
  }

  @Test
  void route_whenAppSubmissionIntakeQueueConfigured_expectSafeOperatorSummary(@TempDir Path tempDir)
      throws Exception {
    Path records = tempDir.resolve("records");
    Files.createDirectories(records);
    Files.writeString(
        records.resolve("sub-hello.json"), intakeRecordJson(), StandardCharsets.UTF_8);
    Files.writeString(
        records.resolve("transparency-log.json"),
        intakeRecordJson("transparency-log", "1".repeat(64)),
        StandardCharsets.UTF_8);
    String previous = System.getProperty(INTAKE_QUEUE_PROPERTY);
    System.setProperty(INTAKE_QUEUE_PROPERTY, tempDir.toString());
    try {
      PlatformApiRouter router = new PlatformApiRouter(runtimePorts());

      PlatformApiResponse list =
          router.route(request("GET", List.of(OPERATOR_SEGMENT, "app-submissions"), Map.of()));
      PlatformApiResponse detail =
          router.route(
              request("GET", List.of(OPERATOR_SEGMENT, "app-submissions", "sub-hello"), Map.of()));
      PlatformApiResponse transparencyLogDetail =
          router.route(
              request(
                  "GET",
                  List.of(OPERATOR_SEGMENT, "app-submissions", "transparency-log"),
                  Map.of()));
      PlatformApiResponse transparencySummary =
          router.route(
              request(
                  "GET",
                  List.of(OPERATOR_SEGMENT, "app-submissions", "transparency", "summary"),
                  Map.of()));

      assertEquals(200, list.statusCode());
      assertTrue(list.body().contains("\"kind\":\"crypta-operator-app-submission-intake\""));
      assertTrue(list.body().contains("\"queueCount\":2"));
      assertTrue(list.body().contains("\"submissionId\":\"sub-hello\""));
      assertTrue(list.body().contains("\"operatorRoutesInAppContract\":false"));
      assertFalse(list.body().contains(tempDir.toString()));
      assertFalse(list.body().contains("raw-submission"));
      assertEquals(200, detail.statusCode());
      assertTrue(detail.body().contains("\"submission\""));
      assertTrue(detail.body().contains("\"appId\":\"hello-stable\""));
      assertFalse(detail.body().contains(tempDir.toString()));
      assertEquals(200, transparencyLogDetail.statusCode());
      assertTrue(transparencyLogDetail.body().contains("\"submission\""));
      assertTrue(transparencyLogDetail.body().contains("\"submissionId\":\"transparency-log\""));
      assertFalse(
          transparencyLogDetail
              .body()
              .contains("crypta-operator-app-submission-transparency-summary"));
      assertEquals(200, transparencySummary.statusCode());
      assertTrue(
          transparencySummary
              .body()
              .contains("\"kind\":\"crypta-operator-app-submission-transparency-summary\""));
      assertTrue(transparencySummary.body().contains("\"recordsWithTransparencyDigest\":1"));
      assertTrue(transparencySummary.body().contains("\"submissionIds\":[\"transparency-log\"]"));
    } finally {
      if (previous == null) {
        System.clearProperty(INTAKE_QUEUE_PROPERTY);
      } else {
        System.setProperty(INTAKE_QUEUE_PROPERTY, previous);
      }
    }
  }

  @Test
  void route_whenAppSubmissionIntakeRecordMalformed_expectUnavailable(@TempDir Path tempDir)
      throws Exception {
    Path records = tempDir.resolve("records");
    Files.createDirectories(records);
    Files.writeString(records.resolve("bad.json"), "{", StandardCharsets.UTF_8);
    String previous = System.getProperty(INTAKE_QUEUE_PROPERTY);
    System.setProperty(INTAKE_QUEUE_PROPERTY, tempDir.toString());
    try {
      PlatformApiRouter router = new PlatformApiRouter(runtimePorts());

      PlatformApiResponse list =
          router.route(request("GET", List.of(OPERATOR_SEGMENT, "app-submissions"), Map.of()));
      PlatformApiResponse transparencySummary =
          router.route(
              request(
                  "GET",
                  List.of(OPERATOR_SEGMENT, "app-submissions", "transparency", "summary"),
                  Map.of()));
      PlatformApiResponse detail =
          router.route(
              request("GET", List.of(OPERATOR_SEGMENT, "app-submissions", "bad"), Map.of()));

      assertEquals(503, list.statusCode());
      assertEquals(503, transparencySummary.statusCode());
      assertEquals(503, detail.statusCode());
      assertTrue(list.body().contains("\"code\":\"app_submission_intake_unavailable\""));
      assertTrue(
          transparencySummary.body().contains("\"code\":\"app_submission_intake_unavailable\""));
      assertTrue(detail.body().contains("\"code\":\"app_submission_intake_unavailable\""));
    } finally {
      if (previous == null) {
        System.clearProperty(INTAKE_QUEUE_PROPERTY);
      } else {
        System.setProperty(INTAKE_QUEUE_PROPERTY, previous);
      }
    }
  }

  @Test
  void route_whenAppPrincipalRequestsOperatorDashboard_expectForbiddenBeforeDispatch() {
    PlatformApiRouter router = new PlatformApiRouter(runtimePorts());

    PlatformApiResponse response =
        router.route(
            request(
                "GET",
                List.of(OPERATOR_SEGMENT, BETA_DASHBOARD_SEGMENT),
                Map.of(),
                PlatformApiPrincipal.appBrowserSession("alpha", List.of("apps.read"))));

    assertEquals(403, response.statusCode());
    assertTrue(response.body().contains("\"code\":\"forbidden\""));
  }

  @Test
  void route_whenAppPrincipalRequestsOperatorRcRecovery_expectForbiddenBeforeDispatch() {
    PlatformApiRouter router = new PlatformApiRouter(runtimePorts());

    PlatformApiResponse plan =
        router.route(
            request(
                "POST",
                List.of(OPERATOR_SEGMENT, "recovery", "plan"),
                Map.of("actionId", List.of("subscription.reset-backoff")),
                PlatformApiPrincipal.appBrowserSession("alpha", List.of("content.subscribe"))));
    PlatformApiResponse execute =
        router.route(
            request(
                "POST",
                List.of(OPERATOR_SEGMENT, "recovery", "execute"),
                Map.of("actionId", List.of("subscription.reset-backoff")),
                PlatformApiPrincipal.appBrowserSession("alpha", List.of("content.subscribe"))));

    assertEquals(403, plan.statusCode());
    assertEquals(403, execute.statusCode());
    assertTrue(plan.body().contains("\"code\":\"forbidden\""));
  }

  @Test
  void route_whenSupportBundleIncludesSensitiveDiagnostics_expectRedactedOutput() {
    RuntimePorts runtimePorts = runtimePorts();
    when(runtimePorts.diagnostic())
        .thenReturn(
            () ->
                new DiagnosticReportSnapshot(
                    List.of(
                        new DiagnosticSectionSnapshot(
                            "Sensitive:",
                            List.of(
                                "path /work/private/catalog",
                                "uri USK@example/private/0",
                                FORM_FIELD_ASSIGNMENT)))));
    PlatformApiRouter router = new PlatformApiRouter(runtimePorts);

    PlatformApiResponse response =
        router.route(request("GET", List.of(OPERATOR_SEGMENT, "support-bundle"), Map.of()));

    assertEquals(200, response.statusCode());
    assertFalse(response.body().contains("/work/private/catalog"));
    assertFalse(response.body().contains("USK@example/private/0"));
    assertFalse(response.body().contains(FORM_FIELD_ASSIGNMENT));
    assertFalse(response.body().contains("\"plainTextExport\""));
    assertFalse(response.body().contains("\"lines\""));
    assertTrue(response.body().contains("\"schemaVersion\":2"));
    assertTrue(response.body().contains("\"privacy\""));
    assertTrue(response.body().contains("\"supportDigest\""));
    assertTrue(response.body().contains("\"supportBundleVersion\":2"));
    assertTrue(response.body().contains("\"recoveryContext\""));
    assertTrue(response.body().contains("\"redactedLineCount\":3"));
    assertTrue(response.body().contains("\"redaction\":{\"status\":\"pass\""));
    assertTrue(response.body().contains("\"coreSupportLifecycle\""));
    assertTrue(response.body().contains("\"platformApiCompatibility\""));
    assertTrue(response.body().contains("\"activeStableBaselines\":[\"1.0\"]"));
    assertTrue(response.body().contains("\"baselineRegistrySummary\""));
    assertTrue(response.body().contains("\"protectedOperationState\":\"not-observed\""));
    assertTrue(response.body().contains("\"lifecycle_runtime_snapshot_unavailable\""));
  }

  @Test
  void supportBundleForExport_whenRouteFieldsAdded_expectDigestCoversFinalPayload() {
    LinkedHashMap<String, Object> serviceBundle = new LinkedHashMap<>();
    serviceBundle.put("kind", "cryptad-operator-support-bundle");
    serviceBundle.put("schemaVersion", 2);
    serviceBundle.put("supportDigest", Map.of("algorithm", "SHA-256", "digest", "0".repeat(64)));
    LinkedHashMap<String, Object> recoveryContext = new LinkedHashMap<>();
    recoveryContext.put("kind", "operator-recovery-context");
    recoveryContext.put("supportBundlePayloadPolicy", "metadata-only");

    Map<String, Object> exported =
        PlatformApiOperatorRoutes.supportBundleForExport(serviceBundle, recoveryContext);

    Map<String, Object> supportDigest = mapValue(exported.get("supportDigest"));
    LinkedHashMap<String, Object> digestInput = new LinkedHashMap<>(exported);
    digestInput.remove("supportDigest");
    assertEquals("SHA-256", supportDigest.get("algorithm"));
    assertEquals(2, exported.get("supportBundleVersion"));
    assertEquals(recoveryContext, exported.get("recoveryContext"));
    assertEquals(sha256(PlatformApiJsonWriter.write(digestInput)), supportDigest.get("digest"));
    assertNotEquals("0".repeat(64), supportDigest.get("digest"));
  }

  @Test
  void route_whenSupportBundlePreviewRequested_expectRedactionMetadataAndRecoveryContext() {
    PlatformApiRouter router = new PlatformApiRouter(runtimePorts());

    PlatformApiResponse response =
        router.route(
            request("GET", List.of(OPERATOR_SEGMENT, "support-bundle", "preview"), Map.of()));

    assertEquals(200, response.statusCode());
    assertTrue(response.body().contains("crypta-operator-support-bundle-preview"));
    assertTrue(response.body().contains("\"includedSections\""));
    assertTrue(response.body().contains("\"recoveryContext\""));
    assertFalse(response.body().contains("payloadBase64"));
  }

  @Test
  void route_whenRecoveryActionsRequested_expectClosedActionIdsWithoutPaths() {
    PlatformApiRouter router = new PlatformApiRouter(runtimePorts());

    PlatformApiResponse response =
        router.route(request("GET", List.of(OPERATOR_SEGMENT, "recovery", "actions"), Map.of()));

    assertEquals(200, response.statusCode());
    assertTrue(response.body().contains("\"actionId\":\"app.rollback\""));
    assertTrue(response.body().contains("\"actionId\":\"subscription.reset-backoff\""));
    assertTrue(response.body().contains("\"planRoute\":\"operator/recovery/plan\""));
    assertFalse(response.body().contains("\"path\""));
  }

  @Test
  void route_whenRecoveryExecuteHasUnknownAction_expectRejected() {
    PlatformApiRouter router = new PlatformApiRouter(runtimePorts());

    PlatformApiResponse response =
        router.route(
            request(
                "POST",
                List.of(OPERATOR_SEGMENT, "recovery", "execute"),
                Map.of("actionId", List.of("some/arbitrary/path"))));

    assertEquals(400, response.statusCode());
    assertTrue(response.body().contains("\"code\":\"unknown_recovery_action\""));
  }

  @Test
  void route_whenRecoveryExecuteMissingPlanToken_expectConflict() {
    PlatformApiRouter router = new PlatformApiRouter(runtimePorts());

    PlatformApiResponse response =
        router.route(
            request(
                "POST",
                List.of(OPERATOR_SEGMENT, "recovery", "execute"),
                Map.of("actionId", List.of("support-bundle.preview"))));

    assertEquals(409, response.statusCode());
    assertTrue(response.body().contains("\"code\":\"recovery_plan_required\""));
  }

  @Test
  void route_whenRecoveryExecuteHasArbitraryPathParameter_expectPathIgnored() {
    PlatformApiRouter router = new PlatformApiRouter(runtimePorts());
    Map<String, List<String>> parameters =
        Map.of(
            "actionId",
            List.of("support-bundle.preview"),
            "path",
            List.of("apps/feed-reader/updates/rollback"));
    PlatformApiResponse plan =
        router.route(request("POST", List.of(OPERATOR_SEGMENT, "recovery", "plan"), parameters));

    PlatformApiResponse response =
        router.route(
            request(
                "POST",
                List.of(OPERATOR_SEGMENT, "recovery", "execute"),
                Map.of(
                    "actionId",
                    List.of("support-bundle.preview"),
                    "path",
                    List.of("apps/feed-reader/updates/rollback"),
                    PARAM_PLAN_TOKEN,
                    List.of(planToken(plan.body())))));

    assertEquals(200, response.statusCode());
    assertTrue(response.body().contains("\"actionId\":\"support-bundle.preview\""));
    assertFalse(response.body().contains("apps/feed-reader/updates/rollback"));
  }

  @Test
  void route_whenRecoveryExecuteMissingConfirmationForDestructiveAction_expectConflict() {
    PlatformApiRouter router = new PlatformApiRouter(runtimePorts());
    Map<String, List<String>> parameters =
        Map.of("actionId", List.of("app.rollback"), "appId", List.of(APP_ID));
    PlatformApiResponse plan =
        router.route(request("POST", List.of(OPERATOR_SEGMENT, "recovery", "plan"), parameters));

    PlatformApiResponse response =
        router.route(
            request(
                "POST",
                List.of(OPERATOR_SEGMENT, "recovery", "execute"),
                Map.of(
                    "actionId",
                    List.of("app.rollback"),
                    "appId",
                    List.of(APP_ID),
                    PARAM_PLAN_TOKEN,
                    List.of(planToken(plan.body())))));

    assertEquals(409, response.statusCode());
    assertTrue(response.body().contains("\"code\":\"recovery_confirmation_required\""));
  }

  @Test
  void route_whenOperatorRefreshesSubscription_expectHostWrapperUsesSharedService() {
    RecordingFetchPort fetchPort = new RecordingFetchPort();
    ContentSubscriptionService service = service(fetchPort);
    String subscriptionId = (String) service.create(APP_ID, createParams()).get("subscriptionId");
    PlatformApiRouter router =
        new PlatformApiRouter(
            runtimePorts(),
            null,
            null,
            null,
            AppUiOriginRegistry.sameOriginOnly(),
            PlatformApiSharedAppServices.of(null, null, service));

    PlatformApiResponse response =
        router.route(
            request(
                "POST",
                List.of(OPERATOR_SEGMENT, "subscriptions", APP_ID, subscriptionId, "refresh"),
                Map.of()));

    assertEquals(200, response.statusCode());
    assertEquals(1, fetchPort.calls);
    assertTrue(response.body().contains("\"subscription\""));
    assertTrue(response.body().contains("\"lastSeenEdition\":7"));
    assertTrue(response.body().contains("\"sourceDisplay\":\"crypta:<redacted-content-uri>\""));
    assertTrue(response.body().contains("\"sourceDigest\""));
    assertFalse(response.body().contains("feed body"));
    assertFalse(response.body().contains("sourceUri"));
    assertFalse(response.body().contains("lastSeenResolvedUri"));
    assertFalse(response.body().contains(SOURCE));
  }

  @Test
  void route_whenOperatorResetsSubscriptionBackoff_expectNoFetchAndRedactedSummary() {
    RecordingFetchPort fetchPort = new RecordingFetchPort();
    ContentSubscriptionService service = service(fetchPort);
    String subscriptionId = (String) service.create(APP_ID, createParams()).get("subscriptionId");
    service.refresh(APP_ID, subscriptionId);
    PlatformApiRouter router =
        new PlatformApiRouter(
            runtimePorts(),
            null,
            null,
            null,
            AppUiOriginRegistry.sameOriginOnly(),
            PlatformApiSharedAppServices.of(null, null, service));
    Map<String, List<String>> parameters =
        Map.of(
            "actionId",
            List.of("subscription.reset-backoff"),
            "appId",
            List.of(APP_ID),
            "subscriptionId",
            List.of(subscriptionId));
    PlatformApiResponse plan =
        router.route(request("POST", List.of(OPERATOR_SEGMENT, "recovery", "plan"), parameters));

    PlatformApiResponse response =
        router.route(
            request(
                "POST",
                List.of(OPERATOR_SEGMENT, "recovery", "execute"),
                Map.of(
                    "actionId",
                    List.of("subscription.reset-backoff"),
                    "appId",
                    List.of(APP_ID),
                    "subscriptionId",
                    List.of(subscriptionId),
                    PARAM_PLAN_TOKEN,
                    List.of(planToken(plan.body())))));

    assertEquals(200, response.statusCode());
    assertEquals(1, fetchPort.calls);
    assertTrue(response.body().contains("\"status\":\"completed\""));
    assertTrue(response.body().contains("\"rawStatus\":\"scheduled\""));
    assertFalse(response.body().contains(SOURCE));
    assertFalse(response.body().contains("feed body"));
  }

  @Test
  void route_whenOperatorUsesLegacySubscriptionReschedule_expectNoFetch() {
    RecordingFetchPort fetchPort = new RecordingFetchPort();
    ContentSubscriptionService service = service(fetchPort);
    String subscriptionId = (String) service.create(APP_ID, createParams()).get("subscriptionId");
    PlatformApiRouter router =
        new PlatformApiRouter(
            runtimePorts(),
            null,
            null,
            null,
            AppUiOriginRegistry.sameOriginOnly(),
            PlatformApiSharedAppServices.of(null, null, service));

    PlatformApiResponse response =
        router.route(
            request(
                "POST",
                List.of(
                    OPERATOR_SEGMENT, "subscriptions", APP_ID, subscriptionId, "reschedule-now"),
                Map.of()));

    assertEquals(200, response.statusCode());
    assertEquals(0, fetchPort.calls);
    assertTrue(response.body().contains("\"rawStatus\":\"scheduled\""));
    assertFalse(response.body().contains(SOURCE));
  }

  @Test
  void route_whenDashboardHasSubscription_expectOperatorSummaryRedactsSourceAndAddsActions() {
    ContentSubscriptionService service = service(new RecordingFetchPort());
    service.create(APP_ID, createParams());
    PlatformApiRouter router =
        new PlatformApiRouter(
            runtimePorts(),
            null,
            null,
            null,
            AppUiOriginRegistry.sameOriginOnly(),
            PlatformApiSharedAppServices.of(null, null, service));

    PlatformApiResponse response =
        router.route(request("GET", List.of(OPERATOR_SEGMENT, BETA_DASHBOARD_SEGMENT), Map.of()));

    assertEquals(200, response.statusCode());
    assertTrue(response.body().contains("\"subscriptions\""));
    assertTrue(response.body().contains("\"status\":\"never-fetched\""));
    assertTrue(response.body().contains("\"sourceDisplay\":\"crypta:<redacted-content-uri>\""));
    assertTrue(response.body().contains("\"refresh-subscription\""));
    assertTrue(response.body().contains("\"reset-subscription-backoff\""));
    assertTrue(response.body().contains("\"reschedule-subscription-now\""));
    assertTrue(response.body().contains("\"operator/subscriptions/feed-reader/"));
    assertFalse(response.body().contains(SOURCE));
  }

  @Test
  void route_whenOperatorRequestsNetworkBudgets_expectSafeSnapshotsOnly() {
    AppNetworkBudgetService budgetService = networkBudgetService();
    budgetService
        .acquire(APP_ID, AppNetworkBudgetOperation.FOREGROUND_CONTENT_FETCH)
        .lease()
        .close();
    PlatformApiRouter router =
        new PlatformApiRouter(
            runtimePorts(),
            null,
            null,
            null,
            AppUiOriginRegistry.sameOriginOnly(),
            PlatformApiSharedAppServices.of(null, null, null, null, null, null, budgetService));

    PlatformApiResponse response =
        router.route(request("GET", List.of(OPERATOR_SEGMENT, "network-budgets"), Map.of()));

    assertEquals(200, response.statusCode());
    assertTrue(response.body().contains("\"kind\":\"crypta-operator-network-budgets\""));
    assertTrue(response.body().contains("\"operation\":\"foreground_content_fetch\""));
    assertFalse(response.body().contains(SOURCE));
    assertFalse(response.body().contains("/work/"));
  }

  @Test
  void route_whenAppPrincipalUsesOperatorSubscriptionWrapper_expectForbidden() {
    RecordingFetchPort fetchPort = new RecordingFetchPort();
    ContentSubscriptionService service = service(fetchPort);
    String subscriptionId = (String) service.create(APP_ID, createParams()).get("subscriptionId");
    PlatformApiRouter router =
        new PlatformApiRouter(
            runtimePorts(),
            null,
            null,
            null,
            AppUiOriginRegistry.sameOriginOnly(),
            PlatformApiSharedAppServices.of(null, null, service));

    PlatformApiResponse response =
        router.route(
            request(
                "POST",
                List.of(OPERATOR_SEGMENT, "subscriptions", APP_ID, subscriptionId, "pause"),
                Map.of(),
                PlatformApiPrincipal.appBrowserSession(APP_ID, List.of("content.subscribe"))));

    assertEquals(403, response.statusCode());
    assertEquals(0, fetchPort.calls);
  }

  @Test
  void route_whenOperatorUsesAppDataBackupRestore_expectSensitiveBackupAndMetadataPlan() {
    AppDataService source = appDataService();
    source.putRecord(APP_ID, appDataRecordParams("private-backup-record-value"));
    String backupPayloadBase64 =
        (String) source.exportBackup(Map.of("appId", List.of(APP_ID)), "test").get("payloadBase64");
    AppDataService target = appDataService();
    target.putRecord(APP_ID, appDataRecordParams("old"));
    PlatformApiRouter router =
        new PlatformApiRouter(
            runtimePorts(),
            null,
            null,
            null,
            AppUiOriginRegistry.sameOriginOnly(),
            PlatformApiSharedAppServices.of(null, null, null, target));

    PlatformApiResponse backupResponse =
        router.route(
            request(
                "POST",
                List.of(OPERATOR_SEGMENT, "app-data", "backups"),
                Map.of("appId", List.of(APP_ID))));
    PlatformApiResponse planResponse =
        router.route(
            request(
                "POST",
                List.of(OPERATOR_SEGMENT, "app-data", "restore", "plan"),
                Map.of("payloadBase64", List.of(backupPayloadBase64), "mode", List.of("merge"))));
    PlatformApiResponse restoreResponse =
        router.route(
            request(
                "POST",
                List.of(OPERATOR_SEGMENT, "app-data", "restore"),
                Map.of("payloadBase64", List.of(backupPayloadBase64), "mode", List.of("merge"))));

    assertEquals(200, backupResponse.statusCode());
    assertTrue(backupResponse.body().contains("crypta-app-data-backup"));
    assertTrue(
        backupResponse
            .body()
            .contains(
                java.util.Base64.getEncoder()
                    .encodeToString("old".getBytes(StandardCharsets.UTF_8))));
    assertEquals(200, planResponse.statusCode());
    assertTrue(planResponse.body().contains("\"restorePlan\""));
    assertTrue(planResponse.body().contains("\"would_merge\""));
    assertFalse(planResponse.body().contains("private-backup-record-value"));
    assertEquals(200, restoreResponse.statusCode());
    assertTrue(restoreResponse.body().contains("\"restoreResult\""));
    assertEquals(
        "private-backup-record-value",
        target.getRecord(APP_ID, "ui-state", "settings").get("valueText"));
  }

  @Test
  void route_whenOperatorUsesGetForAppDataBackup_expectMethodNotAllowedWithoutBackupPayload() {
    AppDataService service = appDataService();
    service.putRecord(APP_ID, appDataRecordParams("private-backup-record-value"));
    PlatformApiRouter router =
        new PlatformApiRouter(
            runtimePorts(),
            null,
            null,
            null,
            AppUiOriginRegistry.sameOriginOnly(),
            PlatformApiSharedAppServices.of(null, null, null, service));

    PlatformApiResponse response =
        router.route(
            request(
                "GET",
                List.of(OPERATOR_SEGMENT, "app-data", "backups"),
                Map.of("scope", List.of("all"))));

    assertEquals(405, response.statusCode());
    assertFalse(response.body().contains("crypta-app-data-backup"));
    assertFalse(response.body().contains("private-backup-record-value"));
  }

  @Test
  void route_whenAppPrincipalRequestsAppDataBackupRestore_expectForbidden() {
    PlatformApiRouter router =
        new PlatformApiRouter(
            runtimePorts(),
            null,
            null,
            null,
            AppUiOriginRegistry.sameOriginOnly(),
            PlatformApiSharedAppServices.of(null, null, null, appDataService()));
    PlatformApiPrincipal appPrincipal =
        PlatformApiPrincipal.appBrowserSession(
            APP_ID,
            List.of(
                AppDataService.CAPABILITY_APP_DATA_READ, AppDataService.CAPABILITY_APP_DATA_WRITE));

    PlatformApiResponse backup =
        router.route(
            request(
                "POST",
                List.of(OPERATOR_SEGMENT, "app-data", "backups"),
                Map.of("appId", List.of(APP_ID)),
                appPrincipal));
    PlatformApiResponse plan =
        router.route(
            request(
                "POST",
                List.of(OPERATOR_SEGMENT, "app-data", "restore", "plan"),
                Map.of("payloadBase64", List.of("ignored")),
                appPrincipal));
    PlatformApiResponse restore =
        router.route(
            request(
                "POST",
                List.of(OPERATOR_SEGMENT, "app-data", "restore"),
                Map.of("payloadBase64", List.of("ignored")),
                appPrincipal));

    assertEquals(403, backup.statusCode());
    assertEquals(403, plan.statusCode());
    assertEquals(403, restore.statusCode());
    assertFalse(backup.body().contains("payloadBase64"));
  }

  @Test
  void route_whenReducedRouterTrustGraphAnchorAdded_expectOperatorDashboardSeesAnchor() {
    PlatformApiRouter router = new PlatformApiRouter(runtimePorts());

    PlatformApiResponse anchorResponse =
        router.route(
            request(
                "POST",
                List.of("trust-graph", "anchors"),
                Map.of(
                    "issuerFingerprint",
                    List.of("fingerprint-operator"),
                    "label",
                    List.of("Operator"),
                    "source",
                    List.of("manual")),
                PlatformApiPrincipal.appBrowserSession(APP_ID, List.of("trust.write"))));
    PlatformApiResponse dashboardResponse =
        router.route(request("GET", List.of(OPERATOR_SEGMENT, BETA_DASHBOARD_SEGMENT), Map.of()));

    assertEquals(201, anchorResponse.statusCode());
    assertEquals(200, dashboardResponse.statusCode());
    assertTrue(dashboardResponse.body().contains("\"trustGraph\""));
    assertTrue(dashboardResponse.body().contains("\"anchorCount\":1"));
  }

  private static PlatformApiRequest request(
      String method, List<String> segments, Map<String, List<String>> params) {
    return request(method, segments, params, PlatformApiPrincipal.hostOperator());
  }

  private static PlatformApiRouter routerWithUpdateService(
      AppHost host, AppCatalogManager manager, AppUpdateService updateService) {
    return new PlatformApiRouter(
        runtimePorts(),
        host,
        manager,
        null,
        AppUiOriginRegistry.sameOriginOnly(),
        PlatformApiSharedAppServices.of(null, updateService, null));
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> mapValue(Object value) {
    return value instanceof Map<?, ?> map ? (Map<String, Object>) map : Map.of();
  }

  private static String sha256(String value) {
    try {
      return HEX.formatHex(
          MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
    } catch (NoSuchAlgorithmException exception) {
      throw new IllegalStateException("SHA-256 is unavailable", exception);
    }
  }

  private static String planToken(String body) {
    String marker = "\"" + PARAM_PLAN_TOKEN + "\":\"";
    int start = body.indexOf(marker);
    assertTrue(start >= 0, body);
    int valueStart = start + marker.length();
    int end = body.indexOf('"', valueStart);
    assertTrue(end > valueStart, body);
    return body.substring(valueStart, end);
  }

  private static PlatformApiRequest request(
      String method,
      List<String> segments,
      Map<String, List<String>> params,
      PlatformApiPrincipal principal) {
    return new PlatformApiRequest(method, segments, params, principal);
  }

  private static ContentSubscriptionService service(RecordingFetchPort fetchPort) {
    return new ContentSubscriptionService(
        new InMemoryContentSubscriptionStore(),
        fetchPort,
        config(),
        Clock.fixed(NOW, ZoneOffset.UTC),
        new SecureRandom());
  }

  private static Map<String, List<String>> createParams() {
    return Map.of(
        "label",
        List.of("Daily feed"),
        "uri",
        List.of(SOURCE),
        "pollIntervalSeconds",
        List.of("5"),
        "maxBytes",
        List.of("256"),
        "timeoutMillis",
        List.of("1000"));
  }

  private static ContentSubscriptionSchedulerConfig config() {
    return new ContentSubscriptionSchedulerConfig(
        true,
        Duration.ZERO,
        Duration.ofSeconds(1),
        Duration.ofSeconds(10),
        Duration.ofSeconds(5),
        Duration.ofHours(1),
        Duration.ZERO,
        Duration.ofSeconds(5),
        Duration.ofSeconds(30),
        4,
        8,
        2,
        256L,
        1024L,
        Duration.ofSeconds(1),
        Duration.ofSeconds(5));
  }

  private static AppDataService appDataService() {
    return new AppDataService(
        new InMemoryAppDataStore(),
        null,
        new AppDataStoreConfig(256, 16, 4, 8192, 8192, 8),
        Clock.fixed(NOW, ZoneOffset.UTC),
        new AppDiskUsageScanner());
  }

  private static AppNetworkBudgetService networkBudgetService() {
    return new AppNetworkBudgetService(
        new InMemoryAppNetworkBudgetStore(),
        new AppNetworkBudgetConfig(20, 100, 2, 16, 20, 1024, 1, 8, 120, 1024, 1, 8),
        Clock.fixed(NOW, ZoneOffset.UTC));
  }

  private static Map<String, List<String>> appDataRecordParams(String value) {
    return Map.of(
        "namespace",
        List.of("ui-state"),
        "key",
        List.of("settings"),
        "contentType",
        List.of(AppDataRecord.JSON_CONTENT_TYPE),
        "schemaVersion",
        List.of("1"),
        "valueText",
        List.of(value));
  }

  private static String intakeRecordJson() {
    return intakeRecordJson("sub-hello", null);
  }

  private static String intakeRecordJson(String submissionId, String transparencyLogDigest) {
    String sha256 = "0".repeat(64);
    String transparency =
        transparencyLogDigest == null
            ? ""
            : """
              "transparencyLogDigest":"%s",
            """
                .formatted(transparencyLogDigest);
    return """
    {
      "schemaVersion":1,
      "status":"submitted",
      "submissionId":"%s",
      "submissionDigest":"%s",
      "submissionType":"new_app",
      "appId":"hello-stable",
      "appVersion":"1.0.0",
      "bundleDigest":"%s",
      "manifestDigest":"%s",
      "apiTargetStability":"stable",
      "requestedPermissions":["queue.read"],
      "maintainerName":"Example Maintainer",
      "maintainerContactPublic":"https://example.invalid/contact",
      "sourceUrl":"https://example.invalid/source",
      "submittedAt":"2026-06-01T12:00:00Z",
      %s
      "nonProduction":false,
      "redactionStatus":"pass",
      "warnings":[],
      "auditEvents":[]
    }
    """
        .formatted(submissionId, sha256, sha256, sha256, transparency);
  }

  private static RuntimePorts runtimePorts() {
    return mock(
        RuntimePorts.class,
        invocation -> {
          Object defaultValue = Answers.RETURNS_DEFAULTS.answer(invocation);
          if (defaultValue != null || invocation.getMethod().getReturnType().isPrimitive()) {
            return defaultValue;
          }
          Class<?> returnType = invocation.getMethod().getReturnType();
          return returnType.isInterface() ? mock(returnType) : null;
        });
  }

  private static CoreSupportLifecycleSnapshot revokedLifecycleSnapshot() {
    return new CoreSupportLifecycleSnapshot(
        true,
        false,
        new CoreSupportLifecycleSnapshot.RunningBuild(
            100,
            CoreSupportLifecycleStatus.REVOKED,
            "2026-06-01T00:00:00Z",
            null,
            null,
            null,
            "2026-06-01T00:00:00Z",
            101,
            null,
            List.of("CRYPTA-2026-001"),
            List.of("critical-release-defect")),
        new CoreSupportLifecycleSnapshot.Recommendation(101, 101, true),
        new CoreSupportLifecycleSnapshot.DescriptorVerification(
            2L, "sha256:" + "a".repeat(64), "2026-06-01T00:05:00Z"),
        List.of("build_revoked"));
  }

  private static FederatedCatalogTrustBinding catalogTrustBinding() {
    return catalogTrustBinding(Map.of("catalog-key", "a".repeat(64)));
  }

  private static FederatedCatalogTrustBinding catalogTrustBinding(
      Map<String, String> signerFingerprints) {
    return bindingWithStatus(FederatedCatalogTrustBinding.Status.ACTIVE, signerFingerprints);
  }

  private static FederatedCatalogTrustBinding suspendedCatalogTrustBinding() {
    return bindingWithStatus(
        FederatedCatalogTrustBinding.Status.SUSPENDED, Map.of("catalog-key", "a".repeat(64)));
  }

  private static FederatedCatalogTrustBinding bindingWithStatus(
      FederatedCatalogTrustBinding.Status status, Map<String, String> signerFingerprints) {
    return FederatedCatalogTrustBinding.create(
        "binding-1",
        "community",
        signerFingerprints,
        status,
        Set.of(AppCatalogChannel.STABLE),
        10,
        null,
        "b".repeat(64),
        "c".repeat(64),
        NOW,
        NOW,
        "operator approval",
        "local-operator");
  }

  private static PendingCatalogDiscoveryRecommendation pendingCatalogDiscovery() {
    PendingCatalogDiscoveryRecommendation pending =
        mock(PendingCatalogDiscoveryRecommendation.class, Answers.RETURNS_DEEP_STUBS);
    var verification = pending.descriptorVerification();
    var descriptor = verification.descriptor();
    var content = descriptor.content();
    var display = content.display();
    var subject = content.subject();
    var transparency = content.transparency();
    var validity = content.validity();
    var issuer = content.issuer();
    when(pending.descriptorId()).thenReturn("descriptor-independent-beta");
    when(pending.catalogId()).thenReturn("independent-beta");
    when(display.name()).thenReturn("Independent beta");
    when(display.summary()).thenReturn("Public discovery metadata only");
    when(display.providerId()).thenReturn("independent-operator");
    when(subject.signerKeyId()).thenReturn("independent-catalog-signer");
    when(subject.signerFingerprintSha256()).thenReturn("0".repeat(64));
    when(subject.channels()).thenReturn(List.of("beta"));
    when(descriptor.authentication().selfDigestSha256()).thenReturn("1".repeat(64));
    when(issuer.issuerId()).thenReturn("independent-operator");
    when(issuer.keyId()).thenReturn("independent-catalog-operator");
    when(verification.issuerKeyFingerprintSha256()).thenReturn("2".repeat(64));
    when(validity.issuedAt()).thenReturn(NOW.minusSeconds(60));
    when(validity.expiresAt()).thenReturn(NOW.plusSeconds(3600));
    when(pending.importedAt()).thenReturn(NOW);
    when(transparency.reviewerSetDigestSha256()).thenReturn(Optional.empty());
    when(transparency.publisherPolicyDigestSha256()).thenReturn(Optional.empty());
    when(pending.endorsementVerifications()).thenReturn(List.of());
    when(pending.selfDigestSha256()).thenReturn("3".repeat(64));
    return pending;
  }

  private static InstalledAppOrigin installedOrigin() {
    String digest = "d".repeat(64);
    return InstalledAppOrigin.create(
        APP_ID,
        "1.0.0",
        digest,
        "community",
        "catalog-key",
        digest,
        digest,
        "publisher-key",
        digest,
        digest,
        "",
        "reviewed",
        "binding-1",
        digest,
        digest,
        digest,
        NOW,
        null);
  }

  private static final class RecordingFetchPort implements ContentFetchPort {
    private int calls;

    @Override
    public BoundedContentFetchResult fetchContent(BoundedContentFetchRequest request) {
      calls++;
      return new BoundedContentFetchResult(
          "feed body".getBytes(StandardCharsets.UTF_8), request.uri(), SOURCE, "ok");
    }
  }
}
