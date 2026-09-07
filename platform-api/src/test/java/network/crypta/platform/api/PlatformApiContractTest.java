package network.crypta.platform.api;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Stream;
import network.crypta.platform.api.json.PlatformApiJsonWriter;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class PlatformApiContractTest {
  private static final String CAP_APP_DATA_READ = PlatformApiCapabilities.APP_DATA_READ;
  private static final String CAP_APP_DATA_WRITE = PlatformApiCapabilities.APP_DATA_WRITE;
  private static final String CAP_APP_SERVICES_CALL = PlatformApiCapabilities.APP_SERVICES_CALL;
  private static final String CAP_APP_SERVICES_READ = PlatformApiCapabilities.APP_SERVICES_READ;
  private static final String CAP_CONTENT_FETCH = PlatformApiCapabilities.CONTENT_FETCH;
  private static final String CAP_CONTENT_SUBSCRIBE = PlatformApiCapabilities.CONTENT_SUBSCRIBE;
  private static final String CAP_TRUST_READ = PlatformApiCapabilities.TRUST_READ;
  private static final String CAP_TRUST_WRITE = PlatformApiCapabilities.TRUST_WRITE;
  private static final String FIELD_COMPATIBILITY_WINDOW = "compatibilityWindow";
  private static final String FIELD_STABLE_BASELINE = "stableBaseline";
  private static final String ROUTE_FAMILY_CONSENT = "consent";
  private static final String ROUTE_FAMILY_APP_SERVICES = "app-services";
  private static final String ROUTE_FAMILY_APP_VAULT = "app-vault";
  private static final String ROUTE_FAMILY_TRUST_GRAPH = "trust-graph";
  private static final String ROUTE_PREFIX_CONSENT = "/consent";
  private static final String ROUTE_POST_APP_SERVICES_GRANT_BUNDLES =
      "POST /app-services/grant-bundles";
  private static final String SEGMENT_DEPENDENCIES = "dependencies";
  private static final String SEGMENT_GRANT_BUNDLES = "grant-bundles";
  private static final Map<String, Integer> SINCE_VERSION_BY_EXACT_ROUTE =
      Map.ofEntries(
          Map.entry("/trust-graph/statements/{fingerprint}", 15),
          Map.entry("/trust-graph/import-uri", 10),
          Map.entry("/trust-graph/import-preview", 22),
          Map.entry("/trust-graph/import-preview-uri", 22),
          Map.entry("/trust-graph/audit", 10),
          Map.entry("/updates/support-lifecycle", 23),
          Map.entry("/app-vault/identities/{identityId}/social-message", 11),
          Map.entry("/app-vault/identities/{identityId}/trust-statement", 7),
          Map.entry("/queue/inserts/app-document", 5),
          Map.entry("/queue/app-document-status", 25),
          Map.entry("/app-vault/identities/{identityId}/profile-document", 5),
          Map.entry("/content/fetch", 6));
  private static final List<RouteVersionPrefix> SINCE_VERSION_BY_ROUTE_PREFIX =
      List.of(
          new RouteVersionPrefix("/mail/", 25),
          new RouteVersionPrefix(ROUTE_PREFIX_CONSENT, 21),
          new RouteVersionPrefix("/trust-graph/anchors/{fingerprint}/", 22),
          new RouteVersionPrefix("/trust-graph/statements/{fingerprint}/", 15),
          new RouteVersionPrefix("/app-services/dependencies", 16),
          new RouteVersionPrefix("/app-services/grant-bundles", 16),
          new RouteVersionPrefix("/app-services", 12),
          new RouteVersionPrefix("/trust-graph", 7),
          new RouteVersionPrefix("/content/subscriptions", 8),
          new RouteVersionPrefix("/app-data", 9),
          new RouteVersionPrefix("/app-vault", 3),
          new RouteVersionPrefix("/identity-vault", 3),
          new RouteVersionPrefix("/app-catalogs/{catalogId}/operations", 23),
          new RouteVersionPrefix("/app-catalogs/{catalogId}/mirrors", 23),
          new RouteVersionPrefix("/app-catalogs/recommended", 4),
          new RouteVersionPrefix("/apps/{appId}/updates", 2));

  @Test
  void current_whenNamedBaselineMetadataIsPublished_expectContractVersion25() {
    assertEquals(25, PlatformApiContract.CURRENT_CONTRACT_VERSION);
  }

  @Test
  void writeEnvelope_whenCalledRepeatedly_expectDeterministicContractJson() {
    String first = PlatformApiContractJson.writeEnvelope(PlatformApiContract.current());
    String second = PlatformApiContractJson.writeEnvelope(PlatformApiContract.current());

    assertEquals(first, second);
    assertTrue(
        first.startsWith(
            "{\"contract\":{\"apiVersion\":\"v1\",\"contractVersion\":"
                + PlatformApiContract.CURRENT_CONTRACT_VERSION));
    assertFalse(first.contains("CRYPTAD_APP_TOKEN"));
    assertFalse(first.contains("browserSessionToken"));
    assertFalse(first.contains("password"));
    assertFalse(first.contains("privateKey"));
    assertTrue(first.contains("\"compatibilityWindow\""));
    assertTrue(first.contains("\"previousSnapshotRequiredInProductionBeta\":true"));
    assertTrue(first.contains("\"criticalStableRemovalWaiverAllowed\":false"));
  }

  @Test
  void parse_whenReadingOwnSnapshot_expectRoundTripPreservesJson() {
    String json = PlatformApiContractJson.writeEnvelope(PlatformApiContract.current());

    PlatformApiContract parsed = PlatformApiContractJson.parse(json);

    assertEquals(json, PlatformApiContractJson.writeEnvelope(parsed));
  }

  @Test
  void parse_whenStableBaselineMetadataChanges_expectSnapshotRejected() {
    String json = PlatformApiContractJson.writeEnvelope(PlatformApiContract.current());
    String baselineVersion =
        "\"stableBaseline\":{\"name\":\"1.0\",\"contractVersion\":"
            + PlatformApiContract.PLATFORM_API_STABLE_BASELINE_CONTRACT_VERSION;
    assertTrue(json.contains(baselineVersion));
    String staleJson =
        json.replace(
            baselineVersion,
            "\"stableBaseline\":{\"name\":\"1.0\",\"contractVersion\":"
                + (PlatformApiContract.PLATFORM_API_STABLE_BASELINE_CONTRACT_VERSION - 1));

    IllegalArgumentException thrown =
        assertThrows(
            IllegalArgumentException.class, () -> PlatformApiContractJson.parse(staleJson));

    assertTrue(thrown.getMessage().contains(FIELD_STABLE_BASELINE), thrown.getMessage());
  }

  @Test
  void parse_whenCompatibilityWindowMetadataChanges_expectSnapshotRejected() {
    String json = PlatformApiContractJson.writeEnvelope(PlatformApiContract.current());
    String currentWindowVersion =
        "\"currentContractVersion\":" + PlatformApiContract.CURRENT_CONTRACT_VERSION;
    assertTrue(json.contains(currentWindowVersion));
    String staleJson = json.replace(currentWindowVersion, "\"currentContractVersion\":1");

    IllegalArgumentException thrown =
        assertThrows(
            IllegalArgumentException.class, () -> PlatformApiContractJson.parse(staleJson));

    assertTrue(thrown.getMessage().contains(FIELD_COMPATIBILITY_WINDOW), thrown.getMessage());
  }

  @Test
  void parse_whenCompatibilityWindowMissing_expectSnapshotRemainsReadable() {
    String json = PlatformApiContractJson.writeEnvelope(PlatformApiContract.current());
    String legacyJson = json.replaceFirst(",\"compatibilityWindow\":\\{[^}]+}", "");

    PlatformApiContract parsed = PlatformApiContractJson.parse(legacyJson);

    assertEquals(PlatformApiContract.CURRENT_CONTRACT_VERSION, parsed.contractVersion());
    assertEquals(
        PlatformApiCompatibilityWindow.POLICY_DOCUMENT,
        parsed.compatibilityWindow().policyDocument());
  }

  @Test
  void parse_whenStableBaselineMissingFromFutureSnapshot_expectSnapshotRejected() {
    String json =
        contractJsonWithoutStableBaseline(
            PlatformApiContract.PLATFORM_API_STABLE_BASELINE_CONTRACT_VERSION + 1);

    IllegalArgumentException thrown =
        assertThrows(IllegalArgumentException.class, () -> PlatformApiContractJson.parse(json));

    assertTrue(thrown.getMessage().contains(FIELD_STABLE_BASELINE), thrown.getMessage());
  }

  @Test
  void parse_whenStableBaselineMissingFromBaselineVersionSnapshot_expectSnapshotRemainsReadable() {
    int baselineContractVersion = PlatformApiContract.PLATFORM_API_STABLE_BASELINE_CONTRACT_VERSION;
    String json = contractJsonWithoutStableBaseline(baselineContractVersion);

    PlatformApiContract parsed = PlatformApiContractJson.parse(json);

    assertEquals(baselineContractVersion, parsed.contractVersion());
    assertEquals(
        PlatformApiContract.PLATFORM_API_STABLE_BASELINE_CONTRACT_VERSION,
        parsed.stableBaseline().contractVersion());
  }

  @Test
  void parse_whenStableBaselineMissingFromLegacySnapshot_expectSnapshotRemainsReadable() {
    int legacyContractVersion =
        PlatformApiContract.PLATFORM_API_STABLE_BASELINE_CONTRACT_VERSION - 1;
    String json = contractJsonWithoutStableBaseline(legacyContractVersion);

    PlatformApiContract parsed = PlatformApiContractJson.parse(json);

    assertEquals(legacyContractVersion, parsed.contractVersion());
    assertEquals(
        PlatformApiContract.PLATFORM_API_STABLE_BASELINE_CONTRACT_VERSION,
        parsed.stableBaseline().contractVersion());
  }

  @Test
  void current_whenReadingVersion_expectTypedApiAndContractVersion() {
    PlatformApiContractVersion version = PlatformApiContract.current().version();

    assertEquals("v1", version.apiVersion());
    assertEquals(PlatformApiContract.CURRENT_CONTRACT_VERSION, version.contractVersion());
  }

  @Test
  void current_whenInspectingStableBaseline_expectDeterministicAppFacingStableMetadata() {
    PlatformApiContract.StableBaseline baseline = PlatformApiContract.current().stableBaseline();

    assertEquals("1.0", baseline.name());
    assertEquals(
        PlatformApiContract.PLATFORM_API_STABLE_BASELINE_CONTRACT_VERSION,
        baseline.contractVersion());
    assertEquals(baseline.capabilities().size(), baseline.capabilityCount());
    assertEquals(baseline.endpoints().size(), baseline.endpointCount());
    assertEquals(
        List.of(
            CAP_APP_DATA_READ,
            CAP_APP_DATA_WRITE,
            CAP_CONTENT_FETCH,
            "content.insert",
            "content.insert.app-document",
            CAP_CONTENT_SUBSCRIBE,
            "platform.contract.read",
            "queue.read",
            "queue.write"),
        baseline.capabilities());
    assertFalse(baseline.capabilities().contains(CAP_TRUST_READ));
    assertFalse(baseline.capabilities().contains(CAP_APP_SERVICES_READ));
    assertTrue(baseline.endpoints().contains("POST /content/fetch"));
    assertTrue(baseline.endpoints().contains("POST /queue/inserts/app-document"));
    assertTrue(baseline.endpoints().contains("GET /platform/contract"));
    assertTrue(baseline.endpoints().contains("POST /queue/inserts/file"));
    assertFalse(
        baseline.endpoints().stream()
            .anyMatch(endpoint -> endpoint.contains(ROUTE_FAMILY_APP_VAULT)));
    assertFalse(
        baseline.endpoints().stream()
            .anyMatch(endpoint -> endpoint.contains(ROUTE_FAMILY_CONSENT)));
    assertFalse(baseline.endpoints().stream().anyMatch(endpoint -> endpoint.contains("operator")));
  }

  @Test
  void current_whenInspectingCompatibilityWindow_expectBetaSupportPolicyMetadata() {
    PlatformApiCompatibilityWindow window = PlatformApiContract.current().compatibilityWindow();

    assertEquals(PlatformApiCompatibilityWindow.CURRENT_SCHEMA_VERSION, window.schemaVersion());
    assertEquals(PlatformApiContract.PLATFORM_API_STABLE_BASELINE_NAME, window.baselineName());
    assertEquals(
        PlatformApiContract.PLATFORM_API_STABLE_BASELINE_CONTRACT_VERSION,
        window.baselineContractVersion());
    assertEquals(PlatformApiContract.CURRENT_CONTRACT_VERSION, window.currentContractVersion());
    assertEquals(PlatformApiCompatibilityWindowStatus.BETA, window.supportPhase());
    assertEquals(2, window.minimumDeprecationWindowContractVersions());
    assertEquals(2, window.minimumScheduledRemovalWindowContractVersions());
    assertTrue(window.stableRemovalRequiresNewBaseline());
    assertTrue(window.stableRemovalRequiresPreviousSnapshot());
    assertTrue(window.stableRemovalRequiresExplicitWaiver());
    assertFalse(window.criticalStableRemovalWaiverAllowed());
    assertTrue(window.experimentalGraduationRequiresReview());
    assertTrue(window.experimentalGraduationRequiresStableReferenceUpdate());
    assertTrue(window.previousSnapshotRequiredInProductionBeta());
    assertEquals("docs/platform-api-compatibility-support-window.md", window.policyDocument());
  }

  @Test
  void parse_whenCompatibilityWindowWeakensPolicy_expectRejected() {
    LinkedHashMap<String, Object> contract =
        new LinkedHashMap<>(PlatformApiContractJson.toJsonValue(PlatformApiContract.current()));
    Map<String, Object> window = compatibilityWindowField(contract);
    window.put("minimumDeprecationWindowContractVersions", 0);
    contract.put(FIELD_COMPATIBILITY_WINDOW, window);
    LinkedHashMap<String, Object> envelope = LinkedHashMap.newLinkedHashMap(1);
    envelope.put("contract", contract);
    String json = PlatformApiJsonWriter.write(envelope);

    IllegalArgumentException thrown =
        assertThrows(IllegalArgumentException.class, () -> PlatformApiContractJson.parse(json));

    assertTrue(thrown.getMessage().contains("canonical Platform API 1.0 support policy"));
  }

  @Test
  void constructor_whenContractVersionBumps_expectStableBaselineRemainsAnchoredToFrozenVersion() {
    PlatformApiContract contract =
        new PlatformApiContract(
            "v1",
            PlatformApiContract.CURRENT_CONTRACT_VERSION + 1,
            "test",
            "test policy",
            PlatformApiContract.current().capabilities(),
            PlatformApiContract.current().endpoints());

    assertEquals(PlatformApiContract.CURRENT_CONTRACT_VERSION + 1, contract.contractVersion());
    assertEquals(
        PlatformApiContract.PLATFORM_API_STABLE_BASELINE_CONTRACT_VERSION,
        contract.stableBaseline().contractVersion());
  }

  @Test
  void constructor_whenFutureStableEndpointExists_expectBaselineMembershipFrozen() {
    List<PlatformApiEndpointDescriptor> endpoints = endpointsWithFutureStableQueueView();

    PlatformApiContract contract =
        new PlatformApiContract(
            "v1",
            PlatformApiContract.CURRENT_CONTRACT_VERSION + 1,
            "test",
            "test policy",
            PlatformApiContract.current().capabilities(),
            endpoints);

    assertFalse(contract.stableBaseline().endpoints().contains("GET /queue/future"));
    assertEquals(
        PlatformApiContract.current().stableBaseline().endpoints(),
        contract.stableBaseline().endpoints());
  }

  @Test
  void current_whenInspectingCapabilities_expectRegistryMatchesDescriptors() {
    Set<String> descriptorNames = PlatformApiContract.current().capabilityNames();

    assertEquals(PlatformApiCapabilityRegistry.knownCapabilities(), descriptorNames);
    assertTrue(descriptorNames.contains("platform.contract.read"));
    assertEquals(new TreeSet<>(descriptorNames), descriptorNames);
    PlatformApiCapabilityDescriptor appDocumentInsertCapability =
        PlatformApiContract.current().capabilities().stream()
            .filter(capability -> capability.name().equals("content.insert.app-document"))
            .findFirst()
            .orElseThrow();
    assertEquals(5, appDocumentInsertCapability.sinceContractVersion());
    PlatformApiCapabilityDescriptor contentFetchCapability =
        PlatformApiContract.current().capabilities().stream()
            .filter(capability -> capability.name().equals(CAP_CONTENT_FETCH))
            .findFirst()
            .orElseThrow();
    assertEquals(6, contentFetchCapability.sinceContractVersion());
    PlatformApiCapabilityDescriptor contentSubscribeCapability =
        PlatformApiContract.current().capabilities().stream()
            .filter(capability -> capability.name().equals(CAP_CONTENT_SUBSCRIBE))
            .findFirst()
            .orElseThrow();
    assertEquals(8, contentSubscribeCapability.sinceContractVersion());
    PlatformApiCapabilityDescriptor appDataReadCapability =
        PlatformApiContract.current().capabilities().stream()
            .filter(capability -> capability.name().equals(CAP_APP_DATA_READ))
            .findFirst()
            .orElseThrow();
    assertEquals(9, appDataReadCapability.sinceContractVersion());
    PlatformApiCapabilityDescriptor appDataWriteCapability =
        PlatformApiContract.current().capabilities().stream()
            .filter(capability -> capability.name().equals(CAP_APP_DATA_WRITE))
            .findFirst()
            .orElseThrow();
    assertEquals(9, appDataWriteCapability.sinceContractVersion());
    PlatformApiCapabilityDescriptor appServicesReadCapability =
        PlatformApiContract.current().capabilities().stream()
            .filter(capability -> capability.name().equals(CAP_APP_SERVICES_READ))
            .findFirst()
            .orElseThrow();
    assertEquals(12, appServicesReadCapability.sinceContractVersion());
    PlatformApiCapabilityDescriptor appServicesCallCapability =
        PlatformApiContract.current().capabilities().stream()
            .filter(capability -> capability.name().equals(CAP_APP_SERVICES_CALL))
            .findFirst()
            .orElseThrow();
    assertEquals(12, appServicesCallCapability.sinceContractVersion());
    PlatformApiCapabilityDescriptor trustReadCapability =
        PlatformApiContract.current().capabilities().stream()
            .filter(capability -> capability.name().equals(CAP_TRUST_READ))
            .findFirst()
            .orElseThrow();
    assertEquals(7, trustReadCapability.sinceContractVersion());
    PlatformApiCapabilityDescriptor trustWriteCapability =
        PlatformApiContract.current().capabilities().stream()
            .filter(capability -> capability.name().equals(CAP_TRUST_WRITE))
            .findFirst()
            .orElseThrow();
    assertEquals(7, trustWriteCapability.sinceContractVersion());
  }

  @Test
  void current_whenInspectingEndpoints_expectDescriptorsReferenceKnownCapabilities() {
    Set<String> knownCapabilities = PlatformApiContract.current().capabilityNames();

    for (PlatformApiEndpointDescriptor endpoint : PlatformApiContract.current().endpoints()) {
      if (endpoint.appProcessAllowed() || endpoint.appBrowserAllowed()) {
        assertFalse(endpoint.requiredCapabilities().isEmpty(), endpoint.routeTemplate());
      }
      assertTrue(
          knownCapabilities.containsAll(endpoint.requiredCapabilities()), endpoint.routeTemplate());
      assertEquals(expectedSinceContractVersion(endpoint), endpoint.sinceContractVersion());
      assertEquals(expectedStability(endpoint), endpoint.stability(), endpoint.routeTemplate());
    }
  }

  @Test
  void current_whenAuthorizingEndpointSamples_expectAuthorizationUsesContractDescriptors() {
    for (PlatformApiEndpointDescriptor endpoint : PlatformApiContract.current().endpoints()) {
      PlatformApiRequest processRequest =
          appRequest(
              endpoint.method(),
              sampleSegments(endpoint.routeTemplate()),
              endpoint.requiredCapabilities());
      PlatformApiAuthorizationDecision processDecision =
          PlatformApiCapabilities.authorize(processRequest);
      PlatformApiRequest browserRequest =
          browserRequest(
              endpoint.method(),
              sampleSegments(endpoint.routeTemplate()),
              endpoint.requiredCapabilities());
      PlatformApiAuthorizationDecision browserDecision =
          PlatformApiCapabilities.authorize(browserRequest);

      assertEndpointAuthorization(endpoint, processDecision, endpoint.appProcessAllowed());
      assertEndpointAuthorization(endpoint, browserDecision, endpoint.appBrowserAllowed());
    }
  }

  @Test
  void current_whenInspectingIdentityCreateEndpoint_expectAppVaultSinceVersionAndBrowserAccess() {
    PlatformApiEndpointDescriptor endpoint =
        PlatformApiContract.current().endpoints().stream()
            .filter(
                descriptor ->
                    descriptor.method().equals("POST")
                        && descriptor.routeTemplate().equals("/app-vault/identities"))
            .findFirst()
            .orElseThrow();

    assertEquals(3, endpoint.sinceContractVersion());
    assertTrue(endpoint.appProcessAllowed());
    assertTrue(endpoint.appBrowserAllowed());
    assertEquals(List.of("vault.identities.create"), endpoint.requiredCapabilities());
  }

  @Test
  void current_whenInspectingContentFetchEndpoint_expectContractVersionAndBrowserAccess() {
    PlatformApiEndpointDescriptor endpoint =
        PlatformApiContract.current().endpoints().stream()
            .filter(
                descriptor ->
                    descriptor.method().equals("POST")
                        && descriptor.routeTemplate().equals("/content/fetch"))
            .findFirst()
            .orElseThrow();

    assertEquals(6, endpoint.sinceContractVersion());
    assertEquals("content", endpoint.routeFamily());
    assertEquals(CAP_CONTENT_FETCH, endpoint.actionLabel());
    assertTrue(endpoint.hostOperatorBypassAllowed());
    assertTrue(endpoint.appProcessAllowed());
    assertTrue(endpoint.appBrowserAllowed());
    assertEquals(List.of(CAP_CONTENT_FETCH), endpoint.requiredCapabilities());
  }

  @Test
  void current_whenInspectingSupportLifecycleEndpoint_expectHostOperatorOnlyAccess() {
    PlatformApiEndpointDescriptor endpoint =
        PlatformApiContract.current().endpoints().stream()
            .filter(
                descriptor ->
                    descriptor.method().equals("GET")
                        && descriptor.routeTemplate().equals("/updates/support-lifecycle"))
            .findFirst()
            .orElseThrow();

    assertEquals(23, endpoint.sinceContractVersion());
    assertEquals(PlatformApiStabilityLevel.OPERATOR_ONLY, endpoint.stability());
    assertTrue(endpoint.hostOperatorBypassAllowed());
    assertFalse(endpoint.appProcessAllowed());
    assertFalse(endpoint.appBrowserAllowed());
    assertEquals(List.of(PlatformApiCapabilities.UPDATES_READ), endpoint.requiredCapabilities());
  }

  @Test
  void current_whenInspectingContentSubscriptionEndpoints_expectContractV8AppScopedCapabilities() {
    Map<String, List<String>> expectedCapabilities =
        Map.of(
            "GET /content/subscriptions",
            List.of(CAP_CONTENT_SUBSCRIBE),
            "POST /content/subscriptions",
            List.of(CAP_CONTENT_FETCH, CAP_CONTENT_SUBSCRIBE),
            "GET /content/subscriptions/{subscriptionId}",
            List.of(CAP_CONTENT_SUBSCRIBE),
            "POST /content/subscriptions/{subscriptionId}/refresh",
            List.of(CAP_CONTENT_FETCH, CAP_CONTENT_SUBSCRIBE),
            "POST /content/subscriptions/{subscriptionId}/pause",
            List.of(CAP_CONTENT_SUBSCRIBE),
            "POST /content/subscriptions/{subscriptionId}/resume",
            List.of(CAP_CONTENT_SUBSCRIBE),
            "DELETE /content/subscriptions/{subscriptionId}",
            List.of(CAP_CONTENT_SUBSCRIBE));
    Set<String> seen = new TreeSet<>();

    for (PlatformApiEndpointDescriptor endpoint : PlatformApiContract.current().endpoints()) {
      String key = endpoint.method() + " " + endpoint.routeTemplate();
      if (!expectedCapabilities.containsKey(key)) {
        continue;
      }
      seen.add(key);
      assertEquals(8, endpoint.sinceContractVersion(), key);
      assertEquals("content", endpoint.routeFamily(), key);
      assertFalse(endpoint.hostOperatorBypassAllowed(), key);
      assertTrue(endpoint.appProcessAllowed(), key);
      assertTrue(endpoint.appBrowserAllowed(), key);
      assertEquals(expectedCapabilities.get(key), endpoint.requiredCapabilities(), key);
    }
    assertEquals(expectedCapabilities.keySet(), seen);
  }

  @Test
  void current_whenInspectingAppDataEndpoints_expectContractV9AppScopedCapabilities() {
    Map<String, List<String>> expectedCapabilities =
        Map.ofEntries(
            Map.entry("GET /app-data/status", List.of(CAP_APP_DATA_READ)),
            Map.entry("GET /app-data/namespaces", List.of(CAP_APP_DATA_READ)),
            Map.entry("GET /app-data/namespaces/{namespace}", List.of(CAP_APP_DATA_READ)),
            Map.entry("POST /app-data/namespaces/{namespace}/schema", List.of(CAP_APP_DATA_WRITE)),
            Map.entry("DELETE /app-data/namespaces/{namespace}", List.of(CAP_APP_DATA_WRITE)),
            Map.entry("GET /app-data/records", List.of(CAP_APP_DATA_READ)),
            Map.entry("GET /app-data/records/{namespace}/{key}", List.of(CAP_APP_DATA_READ)),
            Map.entry("POST /app-data/records", List.of(CAP_APP_DATA_WRITE)),
            Map.entry("DELETE /app-data/records/{namespace}/{key}", List.of(CAP_APP_DATA_WRITE)),
            Map.entry("GET /app-data/export", List.of(CAP_APP_DATA_READ)),
            Map.entry("POST /app-data/import", List.of(CAP_APP_DATA_WRITE)));
    Set<String> seen = new TreeSet<>();

    for (PlatformApiEndpointDescriptor endpoint : PlatformApiContract.current().endpoints()) {
      String key = endpoint.method() + " " + endpoint.routeTemplate();
      if (!expectedCapabilities.containsKey(key)) {
        continue;
      }
      seen.add(key);
      assertEquals(9, endpoint.sinceContractVersion(), key);
      assertEquals("app-data", endpoint.routeFamily(), key);
      assertFalse(endpoint.hostOperatorBypassAllowed(), key);
      assertTrue(endpoint.appProcessAllowed(), key);
      assertTrue(endpoint.appBrowserAllowed(), key);
      assertEquals(expectedCapabilities.get(key), endpoint.requiredCapabilities(), key);
    }
    assertEquals(expectedCapabilities.keySet(), seen);
  }

  @Test
  void current_whenInspectingTrustGraphEndpoints_expectContractV7Capabilities() {
    Map<String, List<String>> expectedCapabilities =
        Map.of(
            "GET /trust-graph/status",
            List.of(CAP_TRUST_READ),
            "GET /trust-graph/anchors",
            List.of(CAP_TRUST_READ),
            "POST /trust-graph/anchors",
            List.of(CAP_TRUST_WRITE),
            "DELETE /trust-graph/anchors/{fingerprint}",
            List.of(CAP_TRUST_WRITE),
            "POST /trust-graph/import",
            List.of(CAP_TRUST_WRITE),
            "GET /trust-graph/subjects",
            List.of(CAP_TRUST_READ),
            "GET /trust-graph/statements",
            List.of(CAP_TRUST_READ),
            "GET /trust-graph/score",
            List.of(CAP_TRUST_READ));
    Set<String> seen = new TreeSet<>();

    for (PlatformApiEndpointDescriptor endpoint : PlatformApiContract.current().endpoints()) {
      String key = endpoint.method() + " " + endpoint.routeTemplate();
      if (!expectedCapabilities.containsKey(key)) {
        continue;
      }
      seen.add(key);
      assertEquals(7, endpoint.sinceContractVersion(), key);
      assertEquals(ROUTE_FAMILY_TRUST_GRAPH, endpoint.routeFamily(), key);
      PlatformApiStabilityLevel expectedStability =
          expectedCapabilities.get(key).isEmpty()
              ? PlatformApiStabilityLevel.OPERATOR_ONLY
              : PlatformApiStabilityLevel.EXPERIMENTAL;
      assertEquals(expectedStability, endpoint.stability(), key);
      assertTrue(endpoint.appProcessAllowed(), key);
      assertTrue(endpoint.appBrowserAllowed(), key);
      assertEquals(expectedCapabilities.get(key), endpoint.requiredCapabilities(), key);
    }
    assertEquals(expectedCapabilities.keySet(), seen);
  }

  @Test
  void current_whenInspectingAppServiceEndpoints_expectContractV12AndV16Capabilities() {
    Map<String, List<String>> expectedCapabilities =
        Map.ofEntries(
            Map.entry("GET /app-services", List.of(CAP_APP_SERVICES_READ)),
            Map.entry("GET /app-services/audit", List.of()),
            Map.entry("GET /app-services/grants", List.of(CAP_APP_SERVICES_READ)),
            Map.entry("GET /app-services/dependencies", List.of(CAP_APP_SERVICES_READ)),
            Map.entry(
                "GET /app-services/dependencies/consumers/{consumerAppId}",
                List.of(CAP_APP_SERVICES_READ)),
            Map.entry("GET /app-services/grant-bundles", List.of(CAP_APP_SERVICES_READ)),
            Map.entry(ROUTE_POST_APP_SERVICES_GRANT_BUNDLES, List.of(CAP_APP_SERVICES_CALL)),
            Map.entry("POST /app-services/grant-bundles/{bundleId}/approve", List.of()),
            Map.entry("POST /app-services/grant-bundles/{bundleId}/reject", List.of()),
            Map.entry("POST /app-services/grant-bundles/{bundleId}/renew", List.of()),
            Map.entry("POST /app-services/grants", List.of(CAP_APP_SERVICES_CALL)),
            Map.entry("POST /app-services/grants/{grantId}/approve", List.of()),
            Map.entry("POST /app-services/grants/{grantId}/revoke", List.of(CAP_APP_SERVICES_CALL)),
            Map.entry("GET /app-services/{providerAppId}/services", List.of(CAP_APP_SERVICES_READ)),
            Map.entry(
                "GET /app-services/{providerAppId}/services/{serviceId}",
                List.of(CAP_APP_SERVICES_READ)),
            Map.entry(
                "POST /app-services/{providerAppId}/services/{serviceId}/invoke",
                List.of(CAP_APP_SERVICES_CALL)));
    Set<String> seen = new TreeSet<>();

    for (PlatformApiEndpointDescriptor endpoint : PlatformApiContract.current().endpoints()) {
      String key = endpoint.method() + " " + endpoint.routeTemplate();
      if (!expectedCapabilities.containsKey(key)) {
        continue;
      }
      seen.add(key);
      assertEquals(
          key.contains(SEGMENT_DEPENDENCIES) || key.contains(SEGMENT_GRANT_BUNDLES) ? 16 : 12,
          endpoint.sinceContractVersion(),
          key);
      assertEquals(ROUTE_FAMILY_APP_SERVICES, endpoint.routeFamily(), key);
      assertEquals(expectedCapabilities.get(key), endpoint.requiredCapabilities(), key);
      if (key.endsWith("/approve")
          || key.endsWith("/reject")
          || key.endsWith("/renew")
          || key.equals("GET /app-services/audit")) {
        assertEquals(PlatformApiStabilityLevel.OPERATOR_ONLY, endpoint.stability(), key);
        assertTrue(endpoint.hostOperatorBypassAllowed(), key);
        assertFalse(endpoint.appProcessAllowed(), key);
        assertFalse(endpoint.appBrowserAllowed(), key);
      } else if (key.equals("POST /app-services/grants")
          || key.equals(ROUTE_POST_APP_SERVICES_GRANT_BUNDLES)
          || key.equals("POST /app-services/{providerAppId}/services/{serviceId}/invoke")) {
        assertEquals(PlatformApiStabilityLevel.EXPERIMENTAL, endpoint.stability(), key);
        assertEquals(
            key.equals(ROUTE_POST_APP_SERVICES_GRANT_BUNDLES),
            endpoint.hostOperatorBypassAllowed(),
            key);
        assertTrue(endpoint.appProcessAllowed(), key);
        assertTrue(endpoint.appBrowserAllowed(), key);
      } else {
        assertEquals(PlatformApiStabilityLevel.EXPERIMENTAL, endpoint.stability(), key);
      }
    }
    assertEquals(expectedCapabilities.keySet(), seen);
  }

  @Test
  void current_whenInspectingConsentEndpoints_expectContractV21HostOperatorOnly() {
    Map<String, String> expectedActions =
        Map.ofEntries(
            Map.entry("GET /consent/install-preview", "consent.install-preview"),
            Map.entry("GET /consent/update-preview", "consent.update-preview.read"),
            Map.entry("POST /consent/update-preview", "consent.update-preview.refresh"),
            Map.entry("GET /consent/catalog-update-preview", "consent.catalog-update-preview"),
            Map.entry("GET /consent/service-grant-preview", "consent.service-grant-preview"),
            Map.entry("POST /consent/approve", "consent.approve"),
            Map.entry("POST /consent/reject", "consent.reject"),
            Map.entry("POST /consent/defer", "consent.defer"),
            Map.entry("GET /consent/audit", "consent.audit"));
    Set<String> seen = new TreeSet<>();

    for (PlatformApiEndpointDescriptor endpoint : PlatformApiContract.current().endpoints()) {
      String key = endpoint.method() + " " + endpoint.routeTemplate();
      if (!expectedActions.containsKey(key)) {
        continue;
      }
      seen.add(key);
      assertEquals(21, endpoint.sinceContractVersion(), key);
      assertEquals(ROUTE_FAMILY_CONSENT, endpoint.routeFamily(), key);
      assertEquals(expectedActions.get(key), endpoint.actionLabel(), key);
      assertEquals(List.of(), endpoint.requiredCapabilities(), key);
      assertEquals(PlatformApiStabilityLevel.OPERATOR_ONLY, endpoint.stability(), key);
      assertTrue(endpoint.hostOperatorBypassAllowed(), key);
      assertFalse(endpoint.appProcessAllowed(), key);
      assertFalse(endpoint.appBrowserAllowed(), key);
    }
    assertEquals(expectedActions.keySet(), seen);
  }

  @Test
  void current_whenInspectingCatalogOperationEndpoints_expectContractV23HostOperatorOnly() {
    Map<String, List<String>> expectedCapabilities =
        Map.ofEntries(
            Map.entry(
                "GET /app-catalogs/{catalogId}/mirrors",
                List.of(PlatformApiCapabilities.CATALOGS_READ)),
            Map.entry(
                "POST /app-catalogs/{catalogId}/mirrors",
                List.of(PlatformApiCapabilities.CATALOGS_MANAGE)),
            Map.entry(
                "POST /app-catalogs/{catalogId}/mirrors/{mirrorId}",
                List.of(PlatformApiCapabilities.CATALOGS_MANAGE)),
            Map.entry(
                "DELETE /app-catalogs/{catalogId}/mirrors/{mirrorId}",
                List.of(PlatformApiCapabilities.CATALOGS_MANAGE)),
            Map.entry(
                "GET /app-catalogs/{catalogId}/operations/health",
                List.of(PlatformApiCapabilities.CATALOGS_READ)),
            Map.entry(
                "GET /app-catalogs/{catalogId}/operations/revisions",
                List.of(PlatformApiCapabilities.CATALOGS_READ)),
            Map.entry(
                "GET /app-catalogs/{catalogId}/operations/key-rotation",
                List.of(PlatformApiCapabilities.CATALOGS_READ)),
            Map.entry(
                "POST /app-catalogs/{catalogId}/operations/refresh-primary",
                List.of(PlatformApiCapabilities.CATALOGS_MANAGE)),
            Map.entry(
                "POST /app-catalogs/{catalogId}/operations/rollback",
                List.of(PlatformApiCapabilities.CATALOGS_MANAGE)),
            Map.entry(
                "POST /app-catalogs/{catalogId}/operations/emergency-refresh",
                List.of(PlatformApiCapabilities.CATALOGS_MANAGE)));
    Set<String> seen = new TreeSet<>();

    for (PlatformApiEndpointDescriptor endpoint : PlatformApiContract.current().endpoints()) {
      String key = endpoint.method() + " " + endpoint.routeTemplate();
      if (!expectedCapabilities.containsKey(key)) {
        continue;
      }
      seen.add(key);
      assertEquals(23, endpoint.sinceContractVersion(), key);
      assertEquals("app-catalogs", endpoint.routeFamily(), key);
      assertEquals(expectedCapabilities.get(key), endpoint.requiredCapabilities(), key);
      assertEquals(PlatformApiStabilityLevel.OPERATOR_ONLY, endpoint.stability(), key);
      assertTrue(endpoint.hostOperatorBypassAllowed(), key);
      assertFalse(endpoint.appProcessAllowed(), key);
      assertFalse(endpoint.appBrowserAllowed(), key);
    }
    assertEquals(expectedCapabilities.keySet(), seen);
  }

  @Test
  void endpointFor_whenDependencyConsumerIdIsServices_expectDisambiguatedContractRoute() {
    PlatformApiContract contract = PlatformApiContract.current();

    PlatformApiEndpointDescriptor dependencyRead =
        contract.endpointFor(
            "GET",
            List.of(ROUTE_FAMILY_APP_SERVICES, SEGMENT_DEPENDENCIES, "consumers", "services"),
            PlatformApiPrincipalType.APP_BROWSER);
    PlatformApiEndpointDescriptor providerList =
        contract.endpointFor(
            "GET",
            List.of(ROUTE_FAMILY_APP_SERVICES, SEGMENT_DEPENDENCIES, "services"),
            PlatformApiPrincipalType.APP_BROWSER);

    assertNotNull(dependencyRead);
    assertNotNull(providerList);
    assertEquals(
        "/app-services/dependencies/consumers/{consumerAppId}", dependencyRead.routeTemplate());
    assertEquals("app-services.dependencies.read", dependencyRead.actionLabel());
    assertEquals(List.of(CAP_APP_SERVICES_READ), dependencyRead.requiredCapabilities());
    assertEquals("/app-services/{providerAppId}/services", providerList.routeTemplate());
    assertEquals("app-services.provider.list", providerList.actionLabel());
    assertEquals(List.of(CAP_APP_SERVICES_READ), providerList.requiredCapabilities());
  }

  @Test
  void current_whenInspectingTrustGraphExchangeEndpoints_expectContractV10Capabilities() {
    Map<String, List<String>> expectedCapabilities =
        Map.of(
            "POST /trust-graph/import-uri",
            List.of(CAP_CONTENT_FETCH, CAP_TRUST_WRITE),
            "GET /trust-graph/audit",
            List.of(CAP_TRUST_READ));
    Set<String> seen = new TreeSet<>();

    for (PlatformApiEndpointDescriptor endpoint : PlatformApiContract.current().endpoints()) {
      String key = endpoint.method() + " " + endpoint.routeTemplate();
      if (!expectedCapabilities.containsKey(key)) {
        continue;
      }
      seen.add(key);
      assertEquals(10, endpoint.sinceContractVersion(), key);
      assertEquals(ROUTE_FAMILY_TRUST_GRAPH, endpoint.routeFamily(), key);
      assertEquals(PlatformApiStabilityLevel.EXPERIMENTAL, endpoint.stability(), key);
      assertTrue(endpoint.appProcessAllowed(), key);
      assertTrue(endpoint.appBrowserAllowed(), key);
      assertEquals(expectedCapabilities.get(key), endpoint.requiredCapabilities(), key);
    }
    assertEquals(expectedCapabilities.keySet(), seen);
  }

  @Test
  void current_whenInspectingTrustGraphBetaHardeningEndpoints_expectContractV22Capabilities() {
    Map<String, List<String>> expectedCapabilities =
        Map.of(
            "POST /trust-graph/import-preview",
            List.of(CAP_TRUST_WRITE),
            "POST /trust-graph/import-preview-uri",
            List.of(CAP_CONTENT_FETCH, CAP_TRUST_WRITE),
            "POST /trust-graph/anchors/{fingerprint}/deprecate",
            List.of(CAP_TRUST_WRITE),
            "POST /trust-graph/anchors/{fingerprint}/revoke",
            List.of(CAP_TRUST_WRITE),
            "POST /trust-graph/anchors/{fingerprint}/reactivate",
            List.of(CAP_TRUST_WRITE));
    Set<String> seen = new TreeSet<>();

    for (PlatformApiEndpointDescriptor endpoint : PlatformApiContract.current().endpoints()) {
      String key = endpoint.method() + " " + endpoint.routeTemplate();
      if (!expectedCapabilities.containsKey(key)) {
        continue;
      }
      seen.add(key);
      assertEquals(22, endpoint.sinceContractVersion(), key);
      assertEquals(ROUTE_FAMILY_TRUST_GRAPH, endpoint.routeFamily(), key);
      assertEquals(PlatformApiStabilityLevel.EXPERIMENTAL, endpoint.stability(), key);
      assertTrue(endpoint.appProcessAllowed(), key);
      assertTrue(endpoint.appBrowserAllowed(), key);
      assertEquals(expectedCapabilities.get(key), endpoint.requiredCapabilities(), key);
    }
    assertEquals(expectedCapabilities.keySet(), seen);
  }

  @Test
  void current_whenInspectingTrustGraphRcLifecycleEndpoints_expectContractV15Capabilities() {
    Map<String, List<String>> expectedCapabilities =
        Map.of(
            "GET /trust-graph/statements/{fingerprint}",
            List.of(CAP_TRUST_READ),
            "POST /trust-graph/statements/{fingerprint}/deprecate",
            List.of(CAP_TRUST_WRITE),
            "POST /trust-graph/statements/{fingerprint}/revoke",
            List.of(CAP_TRUST_WRITE),
            "POST /trust-graph/statements/{fingerprint}/reactivate",
            List.of(CAP_TRUST_WRITE));
    Set<String> seen = new TreeSet<>();

    for (PlatformApiEndpointDescriptor endpoint : PlatformApiContract.current().endpoints()) {
      String key = endpoint.method() + " " + endpoint.routeTemplate();
      if (!expectedCapabilities.containsKey(key)) {
        continue;
      }
      seen.add(key);
      assertEquals(15, endpoint.sinceContractVersion(), key);
      assertEquals(ROUTE_FAMILY_TRUST_GRAPH, endpoint.routeFamily(), key);
      assertEquals(PlatformApiStabilityLevel.EXPERIMENTAL, endpoint.stability(), key);
      assertTrue(endpoint.appProcessAllowed(), key);
      assertTrue(endpoint.appBrowserAllowed(), key);
      assertEquals(expectedCapabilities.get(key), endpoint.requiredCapabilities(), key);
    }
    assertEquals(expectedCapabilities.keySet(), seen);
  }

  @Test
  void current_whenInspectingTrustStatementEndpoint_expectBoundedVaultCapabilities() {
    PlatformApiEndpointDescriptor endpoint =
        PlatformApiContract.current().endpoints().stream()
            .filter(
                descriptor ->
                    descriptor.method().equals("POST")
                        && descriptor
                            .routeTemplate()
                            .equals("/app-vault/identities/{identityId}/trust-statement"))
            .findFirst()
            .orElseThrow();

    assertEquals(7, endpoint.sinceContractVersion());
    assertEquals(ROUTE_FAMILY_APP_VAULT, endpoint.routeFamily());
    assertEquals("app-vault.identities.trust-statement", endpoint.actionLabel());
    assertTrue(endpoint.appProcessAllowed());
    assertTrue(endpoint.appBrowserAllowed());
    assertEquals(
        List.of(CAP_TRUST_WRITE, "vault.identities.read", "vault.identities.use"),
        endpoint.requiredCapabilities());
  }

  @Test
  void current_whenInspectingSocialMessageEndpoint_expectBoundedVaultCapabilities() {
    PlatformApiEndpointDescriptor endpoint =
        PlatformApiContract.current().endpoints().stream()
            .filter(
                descriptor ->
                    descriptor.method().equals("POST")
                        && descriptor
                            .routeTemplate()
                            .equals("/app-vault/identities/{identityId}/social-message"))
            .findFirst()
            .orElseThrow();

    assertEquals(11, endpoint.sinceContractVersion());
    assertEquals(ROUTE_FAMILY_APP_VAULT, endpoint.routeFamily());
    assertEquals("app-vault.identities.social-message", endpoint.actionLabel());
    assertTrue(endpoint.appProcessAllowed());
    assertTrue(endpoint.appBrowserAllowed());
    assertEquals(
        List.of("vault.identities.read", "vault.identities.use"), endpoint.requiredCapabilities());
  }

  private static void assertEndpointAuthorization(
      PlatformApiEndpointDescriptor endpoint,
      PlatformApiAuthorizationDecision decision,
      boolean principalAllowed) {
    if (principalAllowed) {
      assertTrue(decision.allowed(), endpoint.routeTemplate());
      assertEquals(endpoint.toAction(), decision.action(), endpoint.routeTemplate());
      return;
    }
    assertFalse(decision.allowed(), endpoint.routeTemplate());
    assertEquals("unmapped_route", decision.reasonCode(), endpoint.routeTemplate());
  }

  private static int expectedSinceContractVersion(PlatformApiEndpointDescriptor endpoint) {
    String routeTemplate = endpoint.routeTemplate();
    Integer exactVersion = SINCE_VERSION_BY_EXACT_ROUTE.get(routeTemplate);
    if (exactVersion != null) {
      return exactVersion;
    }
    for (RouteVersionPrefix prefix : SINCE_VERSION_BY_ROUTE_PREFIX) {
      if (routeTemplate.startsWith(prefix.routePrefix())) {
        return prefix.contractVersion();
      }
    }
    return 1;
  }

  private static PlatformApiStabilityLevel expectedStability(
      PlatformApiEndpointDescriptor endpoint) {
    if (endpoint.routeTemplate().startsWith("/mail/")
        || endpoint.routeTemplate().equals("/queue/app-document-status")) {
      return PlatformApiStabilityLevel.EXPERIMENTAL;
    }
    if (endpoint.routeTemplate().equals("/updates/support-lifecycle")) {
      return PlatformApiStabilityLevel.OPERATOR_ONLY;
    }
    if (endpoint.routeTemplate().startsWith("/trust-graph")
        || endpoint.routeTemplate().startsWith("/app-vault")
        || endpoint.routeTemplate().startsWith("/app-services")) {
      if (!endpoint.appProcessAllowed() && !endpoint.appBrowserAllowed()) {
        return PlatformApiStabilityLevel.OPERATOR_ONLY;
      }
      return PlatformApiStabilityLevel.EXPERIMENTAL;
    }
    if (endpoint.routeTemplate().startsWith("/identity-vault")) {
      return PlatformApiStabilityLevel.OPERATOR_ONLY;
    }
    if (endpoint.routeTemplate().startsWith(ROUTE_PREFIX_CONSENT)) {
      return PlatformApiStabilityLevel.OPERATOR_ONLY;
    }
    if (endpoint.routeTemplate().startsWith("/app-catalogs/{catalogId}/operations")
        || endpoint.routeTemplate().startsWith("/app-catalogs/{catalogId}/mirrors")) {
      return PlatformApiStabilityLevel.OPERATOR_ONLY;
    }
    return PlatformApiStabilityLevel.STABLE;
  }

  private static PlatformApiRequest appRequest(
      String method, List<String> segments, List<String> permissions) {
    return new PlatformApiRequest(
        method, segments, Map.of(), PlatformApiPrincipal.appToken("contract-test", permissions));
  }

  private static PlatformApiRequest browserRequest(
      String method, List<String> segments, List<String> permissions) {
    return new PlatformApiRequest(
        method,
        segments,
        Map.of(),
        PlatformApiPrincipal.appBrowserSession("contract-test", permissions));
  }

  private static List<String> sampleSegments(String routeTemplate) {
    String relative = routeTemplate.substring(1);
    if (relative.isEmpty()) {
      return List.of();
    }
    return Stream.of(relative.split("/", -1))
        .map(segment -> segment.startsWith("{") && segment.endsWith("}") ? "sample" : segment)
        .toList();
  }

  private static List<PlatformApiEndpointDescriptor> endpointsWithFutureStableQueueView() {
    java.util.ArrayList<PlatformApiEndpointDescriptor> endpoints =
        new java.util.ArrayList<>(PlatformApiContract.current().endpoints());
    endpoints.add(
        new PlatformApiEndpointDescriptor(
            "queue",
            "GET",
            "/queue/future",
            "queue.future",
            List.of(PlatformApiCapabilities.QUEUE_READ),
            true,
            true,
            true,
            PlatformApiStabilityLevel.STABLE,
            PlatformApiContract.PLATFORM_API_STABLE_BASELINE_CONTRACT_VERSION + 1,
            null,
            "Read a future queue view."));
    return endpoints;
  }

  private static Map<String, Object> compatibilityWindowField(Map<String, Object> source) {
    Object value = source.get(FIELD_COMPATIBILITY_WINDOW);
    Map<?, ?> field = assertInstanceOf(Map.class, value);
    LinkedHashMap<String, Object> copy = new LinkedHashMap<>();
    for (Map.Entry<?, ?> entry : field.entrySet()) {
      copy.put((String) entry.getKey(), entry.getValue());
    }
    return copy;
  }

  private static String contractJsonWithoutStableBaseline(int contractVersion) {
    LinkedHashMap<String, Object> contract =
        new LinkedHashMap<>(PlatformApiContractJson.toJsonValue(PlatformApiContract.current()));
    contract.put("contractVersion", contractVersion);
    contract.remove(FIELD_STABLE_BASELINE);
    contract.remove(FIELD_COMPATIBILITY_WINDOW);
    LinkedHashMap<String, Object> envelope = LinkedHashMap.newLinkedHashMap(1);
    envelope.put("contract", contract);
    return PlatformApiJsonWriter.write(envelope);
  }

  private record RouteVersionPrefix(String routePrefix, int contractVersion) {}
}
