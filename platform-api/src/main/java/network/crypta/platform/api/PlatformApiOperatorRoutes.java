package network.crypta.platform.api;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Supplier;
import java.util.regex.Pattern;
import network.crypta.platform.api.appcatalogs.AppCatalogsApiHandler;
import network.crypta.platform.api.appdata.AppDataService;
import network.crypta.platform.api.apps.AppsApiHandler;
import network.crypta.platform.api.appupdates.AppUpdateService;
import network.crypta.platform.api.content.subscriptions.ContentSubscriptionService;
import network.crypta.platform.api.diagnostics.DiagnosticsApiHandler;
import network.crypta.platform.api.operator.OperatorBetaDashboardService;
import network.crypta.platform.api.operator.recovery.OperatorRecoveryService;
import network.crypta.platform.api.trust.TrustGraphApiHandler;
import network.crypta.platform.appcatalog.AppCatalog;
import network.crypta.platform.appcatalog.AppCatalogChannel;
import network.crypta.platform.appcatalog.AppCatalogException;
import network.crypta.platform.appcatalog.AppCatalogManager.PendingCatalogDiscoveryEvidence;
import network.crypta.platform.appcatalog.AppCatalogManager;
import network.crypta.platform.appcatalog.AppSubmissionIntakeRecord;
import network.crypta.platform.appcatalog.AppSubmissionIntakeSummary;
import network.crypta.platform.appcatalog.CatalogScopeRevocation;
import network.crypta.platform.appcatalog.FederatedCatalogConflictEngine;
import network.crypta.platform.appcatalog.FederatedCatalogTrustBinding;
import network.crypta.platform.appcatalog.FileAppSubmissionIntakeStore;
import network.crypta.platform.appcatalog.PendingCatalogDiscoveryRecommendation;
import network.crypta.platform.apphost.AppHost;
import network.crypta.platform.apphost.InstalledAppOrigin;
import network.crypta.platform.appui.AppUiOriginRegistry;
import network.crypta.platform.appvault.AppVaultService;
import network.crypta.runtime.spi.CoreSupportLifecycleSnapshot;
import network.crypta.runtime.spi.CoreUpdateActionPort;
import network.crypta.runtime.spi.LegacyAdminUsagePort;
import network.crypta.runtime.spi.RuntimePorts;

/**
 * Routes host/operator-only beta dashboard and recovery endpoints.
 *
 * <p>This route family is intentionally local-management-only. It gives the desktop shell and
 * legacy admin bridge a compact view of beta app health, redacted support evidence, and manual
 * recovery actions for durable content subscriptions. App principals are already default-denied by
 * the capability matrix because these routes are not part of the app-facing contract; this class
 * still checks the principal defensively before returning dashboard, support-bundle, or
 * subscription-recovery responses.
 *
 * <p>Instances are request-router collaborators. They do not own background work or persistent
 * state; instead, they compose the existing app, catalog, diagnostics, trust graph, and
 * subscription services into operator-safe JSON envelopes. Missing optional services are reported
 * through stable Platform API errors so the operator dashboard can explain what is unavailable
 * without granting app-origin callers any new privileges.
 */
final class PlatformApiOperatorRoutes {
  private static final String HOST_OPERATOR = "host-operator";

  /** HTTP method accepted by read-only operator dashboard resources. */
  private static final String METHOD_GET = "GET";

  /** HTTP method accepted by operator recovery actions that mutate app-platform state. */
  private static final String METHOD_POST = "POST";

  /** Stable 405 response text for resources that are safe to read only. */
  private static final String GET_ONLY_MESSAGE = "Platform API v1 supports GET requests only.";

  /** Stable 405 response text for action routes that require an explicit POST. */
  private static final String POST_ONLY_MESSAGE = "Platform API v1 supports POST requests only.";

  private static final String GET_OR_POST_ONLY_MESSAGE =
      "Platform API v1 supports GET and POST requests only.";

  /** Path segment that identifies subscription recovery routes under the operator namespace. */
  private static final String SUBSCRIPTIONS_SEGMENT = "subscriptions";

  /** Path segment that identifies app-data backup and restore routes. */
  private static final String APP_DATA_SEGMENT = "app-data";

  /** Path segment that identifies typed RC recovery routes. */
  private static final String RECOVERY_SEGMENT = "recovery";

  /** Path segment that identifies local public-beta app submission intake diagnostics. */
  private static final String APP_SUBMISSIONS_SEGMENT = "app-submissions";

  private static final String CATALOG_FEDERATION_SEGMENT = "catalog-federation";
  private static final String DISCOVERY_SEGMENT = "discovery";
  private static final int MAX_DISCOVERY_DOCUMENT_BYTES = 64 * 1024;
  private static final int MAX_DISCOVERY_DOCUMENT_BASE64_CHARS = 90_000;

  /** Non-colliding sub-resource for local intake transparency-log summaries. */
  private static final String TRANSPARENCY_SEGMENT = "transparency";

  /** Leaf segment used by metadata-only operator summaries. */
  private static final String SUMMARY_SEGMENT = "summary";

  /** Shared JSON field for operator-visible warning summaries. */
  private static final String FIELD_WARNINGS = "warnings";

  private static final String FIELD_CATALOG_ID = "catalogId";
  private static final String FIELD_CHANNELS = "channels";
  private static final String FIELD_DISCOVERY_AVAILABLE = "discoveryAvailable";
  private static final String FIELD_PENDING_DISCOVERIES = "pendingDiscoveries";
  private static final String FIELD_PENDING_DISCOVERY_COUNT = "pendingDiscoveryCount";
  private static final String FIELD_PUBLISHER_POLICY_DIGEST_SHA256 = "publisherPolicyDigestSha256";
  private static final String FIELD_STATUS = "status";
  private static final String FIELD_TRANSITIVE = "transitive";
  private static final String FIELD_TRUST_GRANTED = "trustGranted";
  private static final String PARAMETER_DESCRIPTOR_BASE64 = "descriptorBase64";
  private static final String PARAMETER_REASON = "reason";
  private static final Pattern SHA256_PATTERN = Pattern.compile("[0-9a-f]{64}");
  private static final String WARNING_PENDING_CATALOG_DISCOVERY_UNAVAILABLE =
      "pending_catalog_discovery_unavailable";

  /** System property used to point operator routes at a local intake queue. */
  private static final String APP_SUBMISSION_INTAKE_DIR_PROPERTY = "cryptad.appSubmissionIntakeDir";

  /** Environment fallback used to point operator routes at a local intake queue. */
  private static final String APP_SUBMISSION_INTAKE_DIR_ENV = "CRYPTAD_APP_INTAKE_QUEUE_DIR";

  /** Builds redacted dashboard and support-bundle payloads from shared app-platform services. */
  private final OperatorBetaDashboardService dashboardService;

  /** Plans and executes closed allowlisted operator RC recovery actions. */
  private final OperatorRecoveryService recoveryService;

  /** Shared durable subscription service used by operator-initiated refresh and pause actions. */
  private final ContentSubscriptionService contentSubscriptionService;

  /** Shared app-data service used for operator backup and restore portability routes. */
  private final AppDataService appDataService;

  /** Path-free Cryptad version label included in backup manifests. */
  private final Supplier<String> currentCryptaVersion;

  /** Detached source for redacted last-known-good core support-lifecycle state. */
  private final CoreUpdateActionPort coreUpdateActionPort;

  private final AppHost appHost;
  private final AppCatalogManager appCatalogManager;
  private final AppCatalogsApiHandler appCatalogsApiHandler;
  private final AppUpdateService appUpdateService;

  /**
   * Required route-composition inputs that come from the top-level router.
   *
   * <p>The values mirror the runtime and AppHost collaborators already used by app-management
   * routes. Keeping them in one typed aggregate avoids long positional constructor calls while
   * preserving the same optional-service behavior: missing AppHost, catalog, diagnostics, or legacy
   * admin collaborators still produce unavailable dashboard sections instead of synthetic health.
   *
   * @param runtimePorts detached runtime-port aggregate used for diagnostics
   * @param appHost optional AppHost used for installed-app and catalog-install state
   * @param appCatalogManager optional signed catalog manager used for catalog evidence
   * @param legacyAdminUsage optional legacy-admin usage source included in diagnostics
   * @param appAuditLog bounded app-platform audit log shared with app route handlers
   * @param appUiOriginRegistry registry used to resolve app UI origin metadata
   * @param currentCryptaVersion supplier for the daemon version reported to catalog handlers
   */
  record RouteDependencies(
      RuntimePorts runtimePorts,
      AppHost appHost,
      AppCatalogManager appCatalogManager,
      LegacyAdminUsagePort legacyAdminUsage,
      AppAuditLog appAuditLog,
      AppUiOriginRegistry appUiOriginRegistry,
      Supplier<String> currentCryptaVersion) {}

  /**
   * Creates operator routes backed by the router's shared app-platform services.
   *
   * <p>The constructor mirrors the top-level router composition so operator support evidence is
   * collected from the same services that answer normal Platform API requests. Optional runtime
   * pieces may be {@code null}; the resulting dashboard records unavailable sections instead of
   * fabricating health, while action routes still fail closed when their backing service is absent.
   *
   * @param dependencies route-composition inputs owned by the top-level router
   * @param appServices optional shared services used by schedulers and request handlers
   * @param appRoutes app route collaborator that owns the shared app-update service
   * @param trustGraphApiHandler Trust Graph handler already used by the top-level Trust Graph
   *     routes
   */
  PlatformApiOperatorRoutes(
      RouteDependencies dependencies,
      PlatformApiSharedAppServices appServices,
      PlatformApiAppRoutes appRoutes,
      TrustGraphApiHandler trustGraphApiHandler) {
    AppVaultService appVaultService = appServices.vaultService();
    AppsApiHandler appsApiHandler =
        dependencies.appHost() == null
            ? null
            : new AppsApiHandler(
                dependencies.appHost(),
                dependencies.appAuditLog(),
                dependencies.appUiOriginRegistry(),
                appVaultService);
    appCatalogsApiHandler =
        dependencies.appHost() == null || dependencies.appCatalogManager() == null
            ? null
            : new AppCatalogsApiHandler(
                dependencies.appCatalogManager(),
                dependencies.appHost(),
                dependencies.currentCryptaVersion(),
                appVaultService);
    if (appCatalogsApiHandler != null && appServices.updateService() != null) {
      appServices
          .updateService()
          .catalogScopedReviewerPolicy()
          .ifPresent(appCatalogsApiHandler::setCatalogScopedReviewerPolicy);
      appCatalogsApiHandler.setPreparedPlanConflictVerifier(
          (plan, installed, explicitSourceSwitchAuthorized) ->
              appServices
                  .updateService()
                  .requireDirectCatalogMutationAllowed(
                      plan, installed, explicitSourceSwitchAuthorized));
      appCatalogsApiHandler.setPreparedPlanPolicyAuthorizer(
          (plan, installed, targetOrigin, explicitSourceSwitchAuthorized) ->
              appServices
                  .updateService()
                  .retainDirectCatalogPolicyAuthorization(
                      plan, installed, targetOrigin, explicitSourceSwitchAuthorized));
    }
    DiagnosticsApiHandler diagnosticsApiHandler =
        dependencies.runtimePorts().diagnostic() == null
            ? null
            : new DiagnosticsApiHandler(
                dependencies.runtimePorts().diagnostic(), dependencies.legacyAdminUsage());
    contentSubscriptionService = appServices.contentSubscriptionService();
    appDataService = appServices.appDataService();
    currentCryptaVersion = dependencies.currentCryptaVersion();
    coreUpdateActionPort = dependencies.runtimePorts().coreUpdateAction();
    appHost = dependencies.appHost();
    appCatalogManager = dependencies.appCatalogManager();
    appUpdateService = appServices.updateService();
    dashboardService =
        new OperatorBetaDashboardService(
            new OperatorBetaDashboardService.HandlerSources(
                appsApiHandler,
                appCatalogsApiHandler,
                appRoutes.appUpdateService(),
                diagnosticsApiHandler),
            new OperatorBetaDashboardService.AppStateSources(
                contentSubscriptionService,
                appServices.appDataService(),
                trustGraphApiHandler,
                appServices.appServiceCoordinator()));
    recoveryService =
        new OperatorRecoveryService(
            new OperatorRecoveryService.Dependencies(
                appsApiHandler,
                appCatalogsApiHandler,
                appRoutes.appUpdateService(),
                contentSubscriptionService,
                appDataService,
                trustGraphApiHandler,
                appServices.appServiceCoordinator(),
                appServices.networkBudgetService(),
                dashboardService,
                appRoutes::clearAppStateAfterUninstall,
                currentCryptaVersion,
                this::supportBundleWithoutRecoveryContext));
  }

  /**
   * Routes a request beneath the {@code /operator} Platform API namespace.
   *
   * <p>The method expects decoded path segments relative to the Platform API mount point. It always
   * verifies the caller is the host operator before dispatching so app-origin requests cannot probe
   * dashboard, support, or recovery resources through alternate paths. Unknown resources and
   * malformed paths use the same stable {@code 404 not_found} response as the rest of the router.
   *
   * @param segments decoded path segments beginning with the {@code operator} namespace
   * @param request full request metadata, including method, principal, and query parameters
   * @return JSON response for the selected operator resource or recovery action
   */
  PlatformApiResponse route(List<String> segments, PlatformApiRequest request) {
    requireHostOperator(request);
    return switch (segments.size()) {
      case 2 -> routeCollection(segments.get(1), request);
      case 3 -> routeThreeSegmentResource(segments, request);
      case 4 -> routeFourSegmentResource(segments, request);
      case 5 -> routeFiveSegmentResource(segments, request);
      default -> throw notFound();
    };
  }

  private PlatformApiResponse routeFiveSegmentResource(
      List<String> segments, PlatformApiRequest request) {
    if (CATALOG_FEDERATION_SEGMENT.equals(segments.get(1))
        && DISCOVERY_SEGMENT.equals(segments.get(2))
        && "discard".equals(segments.get(4))) {
      if (!METHOD_POST.equals(request.method())) {
        return methodNotAllowed(METHOD_POST, POST_ONLY_MESSAGE);
      }
      return PlatformApiResponse.ok(discardCatalogDiscovery(segments.get(3)));
    }
    if (CATALOG_FEDERATION_SEGMENT.equals(segments.get(1))
        && "conflicts".equals(segments.get(2))
        && "resolve".equals(segments.get(4))) {
      if (!METHOD_POST.equals(request.method())) {
        return methodNotAllowed(METHOD_POST, POST_ONLY_MESSAGE);
      }
      return PlatformApiResponse.ok(resolveCatalogConflict(segments.get(3), request));
    }
    if ("apps".equals(segments.get(1))
        && "catalog-origin".equals(segments.get(3))
        && "switch-preview".equals(segments.get(4))) {
      if (!METHOD_POST.equals(request.method())) {
        return methodNotAllowed(METHOD_POST, POST_ONLY_MESSAGE);
      }
      if (appCatalogsApiHandler == null) {
        throw new PlatformApiException(
            503, "catalog_federation_unavailable", "Catalog federation is unavailable.");
      }
      String targetCatalogId = requiredSingleParameter(request, "targetCatalogId", 128);
      return PlatformApiResponse.ok(
          appCatalogsApiHandler.sourceSwitchPreview(targetCatalogId, segments.get(2)));
    }
    return routeSubscriptionAction(segments, request);
  }

  /**
   * Routes read-only operator resources such as the dashboard and support bundle.
   *
   * @param resource resource segment immediately beneath {@code /operator}
   * @param request full request metadata used to validate the HTTP method
   * @return JSON response containing redacted operator support data
   */
  private PlatformApiResponse routeCollection(String resource, PlatformApiRequest request) {
    Supplier<Map<String, Object>> payload =
        switch (resource) {
          case "beta-dashboard" -> this::dashboard;
          case "rc-dashboard" -> this::rcDashboard;
          case "support-bundle" -> this::supportBundle;
          case "network-budgets" -> recoveryService::networkBudgets;
          case APP_SUBMISSIONS_SEGMENT -> this::appSubmissionIntakeSummary;
          case CATALOG_FEDERATION_SEGMENT -> this::catalogFederationSummary;
          default -> throw notFound();
        };
    if (!METHOD_GET.equals(request.method())) {
      return methodNotAllowed(METHOD_GET, GET_ONLY_MESSAGE);
    }
    return PlatformApiResponse.ok(payload.get());
  }

  private PlatformApiResponse routeThreeSegmentResource(
      List<String> segments, PlatformApiRequest request) {
    if (CATALOG_FEDERATION_SEGMENT.equals(segments.get(1))
        && DISCOVERY_SEGMENT.equals(segments.get(2))) {
      if (METHOD_GET.equals(request.method())) {
        return PlatformApiResponse.ok(catalogDiscoverySummary());
      }
      if (METHOD_POST.equals(request.method())) {
        return PlatformApiResponse.ok(importCatalogDiscovery(request));
      }
      return methodNotAllowed(METHOD_GET + ", " + METHOD_POST, GET_OR_POST_ONLY_MESSAGE);
    }
    if (APP_DATA_SEGMENT.equals(segments.get(1))) {
      return routeAppData(segments, request);
    }
    if ("support-bundle".equals(segments.get(1)) && "preview".equals(segments.get(2))) {
      if (!METHOD_GET.equals(request.method())) {
        return methodNotAllowed(METHOD_GET, GET_ONLY_MESSAGE);
      }
      return PlatformApiResponse.ok(recoveryService.supportBundlePreview(supportBundle()));
    }
    if (RECOVERY_SEGMENT.equals(segments.get(1))) {
      return routeRecovery(segments.get(2), request);
    }
    if (APP_SUBMISSIONS_SEGMENT.equals(segments.get(1))) {
      return routeAppSubmissionIntakeRecord(segments.get(2), request);
    }
    throw notFound();
  }

  private PlatformApiResponse routeFourSegmentResource(
      List<String> segments, PlatformApiRequest request) {
    if (CATALOG_FEDERATION_SEGMENT.equals(segments.get(1))) {
      if ("conflicts".equals(segments.get(2)) && METHOD_GET.equals(request.method())) {
        return PlatformApiResponse.ok(catalogConflict(segments.get(3)));
      }
      return routeCatalogFederationMutation(segments.get(2), segments.get(3), request);
    }
    if ("apps".equals(segments.get(1)) && "catalog-origin".equals(segments.get(3))) {
      if (!METHOD_GET.equals(request.method())) {
        return methodNotAllowed(METHOD_GET, GET_ONLY_MESSAGE);
      }
      return PlatformApiResponse.ok(catalogOrigin(segments.get(2)));
    }
    if (APP_SUBMISSIONS_SEGMENT.equals(segments.get(1))
        && TRANSPARENCY_SEGMENT.equals(segments.get(2))
        && SUMMARY_SEGMENT.equals(segments.get(3))) {
      if (!METHOD_GET.equals(request.method())) {
        return methodNotAllowed(METHOD_GET, GET_ONLY_MESSAGE);
      }
      return PlatformApiResponse.ok(appSubmissionTransparencySummary());
    }
    return routeAppDataRestore(segments, request);
  }

  private PlatformApiResponse revokeCatalogScope(
      String catalogId, String action, PlatformApiRequest request) {
    if (appUpdateService == null) {
      throw new PlatformApiException(
          503, "catalog_federation_unavailable", "Catalog federation is unavailable.");
    }
    String scopeId = requiredSingleParameter(request, "scopeId", 128);
    String expectedDigest = requiredSingleParameter(request, "expectedDigestSha256", 64);
    if (!scopeId.matches("[a-z0-9][a-z0-9._-]{0,127}") || !expectedDigest.matches("[0-9a-f]{64}")) {
      throw new PlatformApiException(
          400, "invalid_request", "Scope identity or expected digest is invalid.");
    }
    try {
      CatalogScopeRevocation revocation =
          new CatalogScopeRevocation(
              catalogId,
              scopeId,
              expectedDigest,
              Instant.now(),
              requiredSingleParameter(request, PARAMETER_REASON, 512),
              HOST_OPERATOR);
      return PlatformApiResponse.ok(
          appUpdateService.revokeCatalogScope(
              "publisher-scope-revoke".equals(action) ? "publisher" : "reviewer", revocation));
    } catch (AppCatalogException _) {
      throw new PlatformApiException(
          409, "catalog_scope_changed", "The selected local scope is unavailable or changed.");
    } catch (IOException _) {
      throw new PlatformApiException(
          500, "catalog_scope_write_failed", "Local scope state could not be updated.");
    }
  }

  private PlatformApiResponse routeCatalogFederationMutation(
      String catalogId, String action, PlatformApiRequest request) {
    if (!METHOD_POST.equals(request.method())) {
      return methodNotAllowed(METHOD_POST, POST_ONLY_MESSAGE);
    }
    if (appCatalogManager == null || !appCatalogManager.federationEnabled()) {
      throw new PlatformApiException(
          503, "catalog_federation_unavailable", "Catalog federation is unavailable.");
    }
    if ("publisher-scope-revoke".equals(action) || "reviewer-scope-revoke".equals(action)) {
      return revokeCatalogScope(catalogId, action, request);
    }
    if ("trust".equals(action)) {
      return PlatformApiResponse.ok(approveCatalogTrust(catalogId, request));
    }
    FederatedCatalogTrustBinding.Status status =
        switch (action) {
          case "suspend" -> FederatedCatalogTrustBinding.Status.SUSPENDED;
          case "revoke" -> FederatedCatalogTrustBinding.Status.REVOKED;
          case "remove" -> FederatedCatalogTrustBinding.Status.REMOVED;
          default -> throw notFound();
        };
    String reason = requiredSingleParameter(request, PARAMETER_REASON, 512);
    try {
      FederatedCatalogTrustBinding binding =
          appCatalogManager.transitionFederatedTrustBinding(
              catalogId, status, reason, HOST_OPERATOR, Instant.now());
      return PlatformApiResponse.ok(catalogTrustSummary(binding));
    } catch (AppCatalogException exception) {
      throw new PlatformApiException(409, exception.errorCode(), exception.getMessage());
    } catch (IOException _) {
      throw new PlatformApiException(
          500, "catalog_trust_write_failed", "Local catalog trust state could not be updated.");
    }
  }

  private Map<String, Object> catalogConflict(String appId) {
    try {
      return requireFederatedConflictService().federatedConflict(appId);
    } catch (AppCatalogException exception) {
      throw new PlatformApiException(400, exception.errorCode(), exception.getMessage());
    }
  }

  private Map<String, Object> resolveCatalogConflict(String appId, PlatformApiRequest request) {
    String conflictId = requiredSingleParameter(request, "conflictId", 128);
    String subjectSetDigest = requiredSingleParameter(request, "subjectSetDigestSha256", 64);
    if (!SHA256_PATTERN.matcher(subjectSetDigest).matches()) {
      throw new PlatformApiException(400, "invalid_request", "subjectSetDigestSha256 is invalid.");
    }
    FederatedCatalogConflictEngine.ResolutionKind kind = conflictResolutionKind(request);
    Optional<String> catalogId = optionalSingleParameter(request, FIELD_CATALOG_ID, 128);
    Optional<String> publisherFingerprint =
        optionalSingleParameter(request, "publisherFingerprintSha256", 64);
    publisherFingerprint.ifPresent(
        value -> {
          if (!SHA256_PATTERN.matcher(value).matches()) {
            throw new PlatformApiException(
                400, "invalid_request", "publisherFingerprintSha256 is invalid.");
          }
        });
    String reason = requiredSingleParameter(request, PARAMETER_REASON, 256);
    try {
      return requireFederatedConflictService()
          .resolveFederatedConflict(
              appId,
              conflictId,
              subjectSetDigest,
              kind.name(),
              catalogId.orElse(null),
              publisherFingerprint.orElse(null),
              reason);
    } catch (AppCatalogException exception) {
      throw new PlatformApiException(400, exception.errorCode(), exception.getMessage());
    }
  }

  private AppUpdateService requireFederatedConflictService() {
    if (appCatalogManager == null
        || !appCatalogManager.federationEnabled()
        || appUpdateService == null) {
      throw new PlatformApiException(
          503, "catalog_federation_unavailable", "Catalog federation is unavailable.");
    }
    return appUpdateService;
  }

  private static FederatedCatalogConflictEngine.ResolutionKind conflictResolutionKind(
      PlatformApiRequest request) {
    String raw = requiredSingleParameter(request, "kind", 64);
    try {
      return FederatedCatalogConflictEngine.ResolutionKind.valueOf(
          raw.replace('-', '_').toUpperCase(java.util.Locale.ROOT));
    } catch (IllegalArgumentException _) {
      throw new PlatformApiException(400, "invalid_request", "kind is invalid.");
    }
  }

  private Map<String, Object> approveCatalogTrust(String catalogId, PlatformApiRequest request) {
    String bindingId = requiredSingleParameter(request, "bindingId", 128);
    Map<String, String> signerFingerprints = parseCatalogSigners(request);
    Set<AppCatalogChannel> channels = parseCatalogChannels(request);
    int localPriority = parseLocalPriority(request);
    String reason = requiredSingleParameter(request, PARAMETER_REASON, 512);
    Optional<String> discoveryDigest = optionalDigestParameter(request, "discoveryDigestSha256");
    Optional<String> reviewerDigest =
        optionalDigestParameter(request, "reviewerPolicyDigestSha256");
    Optional<String> publisherDigest =
        optionalDigestParameter(request, FIELD_PUBLISHER_POLICY_DIGEST_SHA256);
    Instant now = Instant.now();
    try {
      String normalizedCatalogId = AppCatalog.normalizeCatalogId(catalogId);
      Optional<FederatedCatalogTrustBinding> existing =
          appCatalogManager.federatedTrustBindings().stream()
              .filter(binding -> binding.catalogId().equals(normalizedCatalogId))
              .findFirst();
      Instant createdAt = existing.map(FederatedCatalogTrustBinding::createdAt).orElse(now);
      FederatedCatalogTrustBinding binding =
          FederatedCatalogTrustBinding.create(
              bindingId,
              normalizedCatalogId,
              signerFingerprints,
              FederatedCatalogTrustBinding.Status.ACTIVE,
              channels,
              localPriority,
              discoveryDigest.orElse(null),
              reviewerDigest.orElse(null),
              publisherDigest.orElse(null),
              createdAt,
              now,
              reason,
              HOST_OPERATOR);
      appCatalogManager.putFederatedTrustBinding(binding);
      return catalogTrustSummary(binding);
    } catch (AppCatalogException exception) {
      throw new PlatformApiException(409, exception.errorCode(), exception.getMessage());
    } catch (IOException _) {
      throw new PlatformApiException(
          500, "catalog_trust_write_failed", "Local catalog trust state could not be updated.");
    }
  }

  private static Map<String, String> parseCatalogSigners(PlatformApiRequest request) {
    List<String> keyIds = requiredParameterValues(request, "signerKeyId", 128);
    List<String> fingerprints = requiredParameterValues(request, "signerFingerprintSha256", 64);
    if (keyIds.size() != fingerprints.size()) {
      throw new PlatformApiException(
          400,
          "invalid_request",
          "signerKeyId and signerFingerprintSha256 must contain the same number of values.");
    }
    LinkedHashMap<String, String> signers = new LinkedHashMap<>();
    for (int index = 0; index < keyIds.size(); index++) {
      String fingerprint = fingerprints.get(index);
      if (!SHA256_PATTERN.matcher(fingerprint).matches()
          || signers.putIfAbsent(keyIds.get(index), fingerprint) != null) {
        throw new PlatformApiException(
            400, "invalid_request", "The catalog signer set is invalid.");
      }
    }
    return Map.copyOf(signers);
  }

  private static List<String> requiredParameterValues(
      PlatformApiRequest request, String name, int maxCharacters) {
    List<String> values = request.queryParameters().get(name);
    if (values == null || values.isEmpty()) {
      throw new PlatformApiException(
          400, "invalid_request", "At least one " + name + " parameter is required.");
    }
    return values.stream().map(value -> requireParameterValue(value, name, maxCharacters)).toList();
  }

  private static String requireParameterValue(String raw, String name, int maxCharacters) {
    String value = raw.trim();
    if (value.isEmpty()
        || value.length() > maxCharacters
        || value.indexOf('\n') >= 0
        || value.indexOf('\r') >= 0) {
      throw new PlatformApiException(400, "invalid_request", name + " is invalid.");
    }
    return value;
  }

  private static Set<AppCatalogChannel> parseCatalogChannels(PlatformApiRequest request) {
    String raw = requiredSingleParameter(request, FIELD_CHANNELS, 128);
    java.util.LinkedHashSet<AppCatalogChannel> channels = new java.util.LinkedHashSet<>();
    for (String value : raw.split(",", -1)) {
      String normalized = value.trim();
      if (normalized.isEmpty()) {
        throw new PlatformApiException(400, "invalid_request", "channels is invalid.");
      }
      try {
        channels.add(AppCatalogChannel.valueOf(normalized.toUpperCase(java.util.Locale.ROOT)));
      } catch (IllegalArgumentException _) {
        throw new PlatformApiException(400, "invalid_request", "channels is invalid.");
      }
    }
    return Set.copyOf(channels);
  }

  private static int parseLocalPriority(PlatformApiRequest request) {
    String raw = requiredSingleParameter(request, "localPriority", 5);
    try {
      int priority = Integer.parseInt(raw);
      if (priority < 0 || priority > 10_000) {
        throw new NumberFormatException("priority outside range");
      }
      return priority;
    } catch (NumberFormatException _) {
      throw new PlatformApiException(400, "invalid_request", "localPriority is invalid.");
    }
  }

  private static Optional<String> optionalDigestParameter(PlatformApiRequest request, String name) {
    List<String> values = request.queryParameters().get(name);
    if (values == null || values.isEmpty()) {
      return Optional.empty();
    }
    if (values.size() != 1 || !SHA256_PATTERN.matcher(values.getFirst()).matches()) {
      throw new PlatformApiException(400, "invalid_request", name + " is invalid.");
    }
    return Optional.of(values.getFirst());
  }

  private static Optional<String> optionalSingleParameter(
      PlatformApiRequest request, String name, int maxCharacters) {
    List<String> values = request.queryParameters().get(name);
    if (values == null || values.isEmpty()) {
      return Optional.empty();
    }
    if (values.size() != 1) {
      throw new PlatformApiException(
          400, "invalid_request", "At most one " + name + " parameter is accepted.");
    }
    String value = values.getFirst().trim();
    if (value.isEmpty()
        || value.length() > maxCharacters
        || value.indexOf('\n') >= 0
        || value.indexOf('\r') >= 0) {
      throw new PlatformApiException(400, "invalid_request", name + " is invalid.");
    }
    return Optional.of(value);
  }

  private static String requiredSingleParameter(
      PlatformApiRequest request, String name, int maxCharacters) {
    List<String> values = request.queryParameters().get(name);
    if (values == null || values.size() != 1) {
      throw new PlatformApiException(
          400, "invalid_request", "Exactly one " + name + " parameter is required.");
    }
    String value = values.getFirst().trim();
    if (value.isEmpty()
        || value.length() > maxCharacters
        || value.indexOf('\n') >= 0
        || value.indexOf('\r') >= 0) {
      throw new PlatformApiException(400, "invalid_request", name + " is invalid.");
    }
    return value;
  }

  private Map<String, Object> catalogFederationSummary() {
    if (appCatalogManager == null) {
      throw new PlatformApiException(
          503, "catalog_federation_unavailable", "Catalog federation is unavailable.");
    }
    LinkedHashMap<String, Object> summary = new LinkedHashMap<>();
    try {
      List<String> configuredCatalogIds = appCatalogManager.configuredCatalogIds();
      summary.put("configuredCatalogIds", configuredCatalogIds);
      summary.put("configuredCatalogCount", configuredCatalogIds.size());
      List<Map<String, Object>> bindings =
          appCatalogManager.federatedTrustBindings().stream()
              .map(PlatformApiOperatorRoutes::catalogTrustSummary)
              .toList();
      summary.put("mode", "federated-local-trust");
      summary.put("bindings", bindings);
      summary.put("bindingCount", bindings.size());
      summary.put("endorsementsAuthoritative", false);
      summary.put("transitiveTrust", false);
      summary.put("discoveryUploadsLocalState", false);
    } catch (IllegalStateException _) {
      summary.put("mode", "legacy-global-compatibility");
      summary.put("bindings", List.of());
      summary.put("bindingCount", 0);
      summary.put("federationComplete", false);
      summary.put(FIELD_WARNINGS, List.of("explicit_local_catalog_bindings_not_configured"));
    } catch (IOException _) {
      throw new PlatformApiException(
          500, "catalog_trust_read_failed", "Local catalog trust state could not be read.");
    }
    appendCatalogDiscoverySummary(summary);
    return summary;
  }

  private void appendCatalogDiscoverySummary(Map<String, Object> summary) {
    if (!appCatalogManager.catalogDiscoveryEnabled()) {
      summary.put(FIELD_DISCOVERY_AVAILABLE, false);
      summary.put(FIELD_PENDING_DISCOVERY_COUNT, 0);
      summary.put(FIELD_PENDING_DISCOVERIES, List.of());
      return;
    }
    try {
      List<Map<String, Object>> pending = pendingCatalogDiscoverySummaries();
      summary.put(FIELD_DISCOVERY_AVAILABLE, true);
      summary.put(FIELD_PENDING_DISCOVERY_COUNT, pending.size());
      summary.put(FIELD_PENDING_DISCOVERIES, pending);
    } catch (IOException | AppCatalogException _) {
      summary.put(FIELD_DISCOVERY_AVAILABLE, false);
      summary.put(FIELD_PENDING_DISCOVERY_COUNT, 0);
      summary.put(FIELD_PENDING_DISCOVERIES, List.of());
      appendPendingDiscoveryUnavailableWarning(summary);
    }
  }

  private Map<String, Object> catalogDiscoverySummary() {
    requireCatalogDiscovery();
    try {
      List<Map<String, Object>> pending = pendingCatalogDiscoverySummaries();
      return Map.of(
          FIELD_STATUS,
          "local-pending-evidence",
          "pendingCount",
          pending.size(),
          "recommendations",
          pending,
          FIELD_TRUST_GRANTED,
          false,
          "sourceConfigured",
          false,
          FIELD_TRANSITIVE,
          false,
          "uploadsLocalState",
          false);
    } catch (IOException | AppCatalogException _) {
      throw new PlatformApiException(
          500,
          "catalog_discovery_read_failed",
          "Pending catalog discovery evidence could not be read.");
    }
  }

  private Map<String, Object> importCatalogDiscovery(PlatformApiRequest request) {
    requireCatalogDiscovery();
    byte[] descriptor = decodeDiscoveryDocument(request);
    List<byte[]> endorsements = decodeDiscoveryEndorsements(request);
    try {
      PendingCatalogDiscoveryRecommendation pending =
          appCatalogManager.importCatalogDiscovery(descriptor, endorsements, Instant.now());
      return pendingCatalogDiscoverySummary(
          new PendingCatalogDiscoveryEvidence(pending, true, pending.endorsementVerifications()));
    } catch (AppCatalogException exception) {
      throw new PlatformApiException(400, exception.errorCode(), exception.getMessage());
    } catch (IOException _) {
      throw new PlatformApiException(
          500,
          "catalog_discovery_write_failed",
          "Pending catalog discovery evidence could not be stored.");
    }
  }

  private Map<String, Object> discardCatalogDiscovery(String descriptorId) {
    requireCatalogDiscovery();
    try {
      if (!appCatalogManager.discardPendingCatalogDiscovery(descriptorId)) {
        throw new PlatformApiException(
            404,
            "catalog_discovery_not_found",
            "Pending catalog discovery evidence was not found.");
      }
      return Map.of(
          "descriptorId",
          descriptorId,
          FIELD_STATUS,
          "discarded",
          "trustChanged",
          false,
          "sourceChanged",
          false);
    } catch (AppCatalogException exception) {
      throw new PlatformApiException(400, exception.errorCode(), exception.getMessage());
    } catch (IOException _) {
      throw new PlatformApiException(
          500,
          "catalog_discovery_write_failed",
          "Pending catalog discovery evidence could not be discarded.");
    }
  }

  private void requireCatalogDiscovery() {
    if (appCatalogManager == null
        || !appCatalogManager.federationEnabled()
        || !appCatalogManager.catalogDiscoveryEnabled()) {
      throw new PlatformApiException(
          503, "catalog_discovery_unavailable", "Catalog discovery import is unavailable.");
    }
  }

  private List<Map<String, Object>> pendingCatalogDiscoverySummaries() throws IOException {
    return appCatalogManager.currentPendingCatalogDiscoveries(Instant.now()).stream()
        .map(PlatformApiOperatorRoutes::pendingCatalogDiscoverySummary)
        .toList();
  }

  private static Map<String, Object> pendingCatalogDiscoverySummary(
      PendingCatalogDiscoveryEvidence evidence) {
    PendingCatalogDiscoveryRecommendation pending = evidence.recommendation();
    var verification = pending.descriptorVerification();
    var descriptor = verification.descriptor();
    var content = descriptor.content();
    LinkedHashMap<String, Object> json = new LinkedHashMap<>();
    json.put("descriptorId", pending.descriptorId());
    json.put(FIELD_CATALOG_ID, pending.catalogId());
    json.put(FIELD_STATUS, "pending");
    json.put("descriptorStatus", evidence.descriptorActive() ? "active" : "inactive");
    json.put("name", content.display().name());
    json.put(SUMMARY_SEGMENT, content.display().summary());
    json.put("providerId", content.display().providerId());
    json.put("catalogSignerKeyId", content.subject().signerKeyId());
    json.put("catalogSignerFingerprintSha256", content.subject().signerFingerprintSha256());
    json.put(
        "sourceHints", content.subject().sourceHints().stream().map(Object::toString).toList());
    json.put(FIELD_CHANNELS, content.subject().channels());
    json.put("descriptorDigestSha256", descriptor.authentication().selfDigestSha256());
    json.put("issuerId", content.issuer().issuerId());
    json.put("issuerKeyId", content.issuer().keyId());
    json.put("issuerKeyFingerprintSha256", verification.issuerKeyFingerprintSha256());
    json.put("issuedAt", content.validity().issuedAt().toString());
    json.put("expiresAt", content.validity().expiresAt().toString());
    json.put("importedAt", pending.importedAt().toString());
    json.put(
        "reviewerSetDigestSha256", content.transparency().reviewerSetDigestSha256().orElse(null));
    json.put(
        FIELD_PUBLISHER_POLICY_DIGEST_SHA256,
        content.transparency().publisherPolicyDigestSha256().orElse(null));
    json.put("endorsementCount", pending.endorsementVerifications().size());
    json.put(
        "endorsements",
        evidence.endorsements().stream()
            .map(
                endorsement ->
                    Map.of(
                        "endorsementId",
                        endorsement.endorsement().content().endorsementId(),
                        "issuerId",
                        endorsement.endorsement().content().issuer().issuerId(),
                        "issuerKeyFingerprintSha256",
                        endorsement.issuerKeyFingerprintSha256(),
                        FIELD_STATUS,
                        endorsement.status().name().toLowerCase(java.util.Locale.ROOT),
                        "direct",
                        true,
                        FIELD_TRANSITIVE,
                        false,
                        FIELD_TRUST_GRANTED,
                        false))
            .toList());
    json.put(FIELD_TRUST_GRANTED, false);
    json.put("sourceConfigured", false);
    json.put(FIELD_TRANSITIVE, false);
    json.put("selfDigestSha256", pending.selfDigestSha256());
    return json;
  }

  private static List<byte[]> decodeDiscoveryEndorsements(PlatformApiRequest request) {
    List<String> values = request.queryParameters().getOrDefault("endorsementBase64", List.of());
    if (values.size() > PendingCatalogDiscoveryRecommendation.MAX_ENDORSEMENTS) {
      throw new PlatformApiException(
          400, "invalid_request", "At most eight direct endorsements are accepted.");
    }
    return values.stream()
        .map(value -> decodeDiscoveryDocument(value, "endorsementBase64"))
        .toList();
  }

  private static byte[] decodeDiscoveryDocument(PlatformApiRequest request) {
    List<String> values = request.queryParameters().get(PARAMETER_DESCRIPTOR_BASE64);
    if (values == null || values.isEmpty()) {
      throw new PlatformApiException(
          400,
          "invalid_request",
          "Exactly one " + PARAMETER_DESCRIPTOR_BASE64 + " parameter is required.");
    }
    if (values.size() != 1) {
      throw new PlatformApiException(
          400,
          "invalid_request",
          "Exactly one " + PARAMETER_DESCRIPTOR_BASE64 + " parameter is required.");
    }
    return decodeDiscoveryDocument(values.getFirst(), PARAMETER_DESCRIPTOR_BASE64);
  }

  private static byte[] decodeDiscoveryDocument(String encoded, String parameterName) {
    String value = encoded == null ? "" : encoded.trim();
    if (value.isEmpty() || value.length() > MAX_DISCOVERY_DOCUMENT_BASE64_CHARS) {
      throw new PlatformApiException(400, "invalid_request", parameterName + " is invalid.");
    }
    byte[] decoded;
    try {
      decoded = Base64.getDecoder().decode(value);
    } catch (IllegalArgumentException _) {
      try {
        decoded = Base64.getUrlDecoder().decode(value);
      } catch (IllegalArgumentException _) {
        throw new PlatformApiException(
            400, "invalid_request", parameterName + " must be valid Base64.");
      }
    }
    if (decoded.length == 0 || decoded.length > MAX_DISCOVERY_DOCUMENT_BYTES) {
      throw new PlatformApiException(
          400, "invalid_request", parameterName + " exceeds the bounded document size.");
    }
    return decoded;
  }

  private static void appendPendingDiscoveryUnavailableWarning(Map<String, Object> summary) {
    Object existing = summary.get(FIELD_WARNINGS);
    List<String> warnings =
        existing instanceof List<?> values
            ? values.stream().filter(String.class::isInstance).map(String.class::cast).toList()
            : List.of();
    ArrayList<String> updated = new ArrayList<>(warnings);
    if (!updated.contains(WARNING_PENDING_CATALOG_DISCOVERY_UNAVAILABLE)) {
      updated.add(WARNING_PENDING_CATALOG_DISCOVERY_UNAVAILABLE);
    }
    summary.put(FIELD_WARNINGS, List.copyOf(updated));
  }

  private Map<String, Object> catalogOrigin(String appId) {
    if (appHost == null) {
      throw new PlatformApiException(
          503, "apphost_unavailable", "Installed app provenance is unavailable.");
    }
    try {
      InstalledAppOrigin origin =
          appHost
              .catalogOrigin(appId)
              .orElseThrow(
                  () ->
                      new PlatformApiException(
                          404, "catalog_origin_not_found", "Catalog origin was not recorded."));
      LinkedHashMap<String, Object> json = new LinkedHashMap<>();
      json.put("appId", origin.appId());
      json.put("appVersion", origin.appVersion());
      json.put("bundleSha256", origin.bundleSha256());
      json.put(FIELD_CATALOG_ID, origin.catalogId());
      json.put("catalogSignerKeyId", origin.catalogSignerKeyId());
      json.put("catalogSignerFingerprintSha256", origin.catalogSignerFingerprintSha256());
      json.put("catalogRevisionDigestSha256", origin.catalogRevisionDigestSha256());
      json.put("publisherKeyId", origin.publisherKeyId());
      json.put("publisherKeyFingerprintSha256", origin.publisherKeyFingerprintSha256());
      json.put("signedContentDigestSha256", origin.signedContentDigestSha256());
      json.put("reviewReceiptFingerprintSha256", origin.reviewReceiptFingerprintSha256());
      json.put("reviewStatus", origin.reviewStatus());
      json.put("catalogTrustBindingId", origin.catalogTrustBindingId());
      json.put("catalogTrustBindingDigestSha256", origin.catalogTrustBindingDigestSha256());
      json.put(FIELD_PUBLISHER_POLICY_DIGEST_SHA256, origin.publisherPolicyDigestSha256());
      json.put("reviewerPolicyDigestSha256", origin.reviewerPolicyDigestSha256());
      json.put("installedAt", origin.installedAt().toString());
      json.put("previousOriginDigestSha256", origin.previousOriginDigestSha256().orElse(null));
      json.put("selfDigestSha256", origin.selfDigestSha256());
      return json;
    } catch (IOException _) {
      throw new PlatformApiException(
          500, "catalog_origin_read_failed", "Installed app provenance could not be read.");
    }
  }

  private static Map<String, Object> catalogTrustSummary(FederatedCatalogTrustBinding binding) {
    LinkedHashMap<String, Object> json = new LinkedHashMap<>();
    List<Map.Entry<String, String>> signers =
        binding.signerFingerprints().entrySet().stream()
            .sorted(Map.Entry.comparingByKey())
            .toList();
    json.put("bindingId", binding.bindingId());
    json.put(FIELD_CATALOG_ID, binding.catalogId());
    json.put(FIELD_STATUS, binding.status().name().toLowerCase(java.util.Locale.ROOT));
    json.put("signerKeyIds", signers.stream().map(Map.Entry::getKey).toList());
    json.put("signerFingerprints", signers.stream().map(Map.Entry::getValue).toList());
    json.put(
        FIELD_CHANNELS,
        binding.allowedChannels().stream()
            .map(channel -> channel.name().toLowerCase(java.util.Locale.ROOT))
            .sorted()
            .toList());
    json.put("localPriority", binding.localPriority());
    json.put("reviewerPolicyDigest", binding.reviewerPolicyDigest().orElse(null));
    json.put("publisherPolicyDigest", binding.publisherPolicyDigest().orElse(null));
    json.put("selfDigest", binding.selfDigest());
    return json;
  }

  private PlatformApiResponse routeAppSubmissionIntakeRecord(
      String submissionId, PlatformApiRequest request) {
    if (!METHOD_GET.equals(request.method())) {
      return methodNotAllowed(METHOD_GET, GET_ONLY_MESSAGE);
    }
    FileAppSubmissionIntakeStore store =
        appSubmissionIntakeStore()
            .orElseThrow(
                () ->
                    new PlatformApiException(
                        503,
                        "app_submission_intake_unconfigured",
                        "App submission intake queue is not configured."));
    AppSubmissionIntakeRecord intakeRecord;
    try {
      intakeRecord =
          store
              .load(submissionId)
              .orElseThrow(
                  () ->
                      new PlatformApiException(
                          404, "app_submission_not_found", "Submission intake record not found."));
    } catch (IOException | AppCatalogException _) {
      throw appSubmissionIntakeUnavailable();
    }
    return PlatformApiResponse.ok(envelope("submission", intakeRecord.toJsonValue()));
  }

  private PlatformApiResponse routeRecovery(String action, PlatformApiRequest request) {
    return switch (action) {
      case "actions" -> {
        if (!METHOD_GET.equals(request.method())) {
          yield methodNotAllowed(METHOD_GET, GET_ONLY_MESSAGE);
        }
        yield PlatformApiResponse.ok(envelope("actions", recoveryService.actions()));
      }
      case "plan" -> {
        if (!METHOD_POST.equals(request.method())) {
          yield methodNotAllowed(METHOD_POST, POST_ONLY_MESSAGE);
        }
        yield PlatformApiResponse.ok(
            envelope("plan", recoveryService.plan(request.queryParameters()).toJson()));
      }
      case "execute" -> {
        if (!METHOD_POST.equals(request.method())) {
          yield methodNotAllowed(METHOD_POST, POST_ONLY_MESSAGE);
        }
        yield PlatformApiResponse.ok(
            envelope("result", recoveryService.execute(request.queryParameters()).toJson()));
      }
      default -> throw notFound();
    };
  }

  private Map<String, Object> rcDashboard() {
    LinkedHashMap<String, Object> dashboard = LinkedHashMap.newLinkedHashMap(16);
    dashboard.putAll(dashboard());
    dashboard.put("dashboardKind", "operator-rc-recovery-dashboard");
    dashboard.put(
        "betaCompatibility",
        Map.of(
            "route",
            "operator/beta-dashboard",
            "retained",
            true,
            "operatorRoutesInAppContract",
            false));
    dashboard.put("operatorRcRecovery", recoveryService.dashboardState());
    dashboard.put("networkBudgets", recoveryService.networkBudgets());
    dashboard.put("supportBundlePreviewRoute", "operator/support-bundle/preview");
    return dashboard;
  }

  private Map<String, Object> supportBundle() {
    return supportBundleForExport(
        supportBundleWithoutRecoveryContext(), recoveryService.supportContext());
  }

  private Map<String, Object> dashboard() {
    LinkedHashMap<String, Object> dashboard = new LinkedHashMap<>(dashboardService.dashboard());
    dashboard.put("coreSupportLifecycle", lifecycleSnapshot());
    dashboard.put("platformApiCompatibility", platformApiCompatibilitySnapshot());
    return dashboard;
  }

  private Map<String, Object> supportBundleWithoutRecoveryContext() {
    LinkedHashMap<String, Object> bundle = new LinkedHashMap<>(dashboardService.supportBundle());
    bundle.put("coreSupportLifecycle", lifecycleSnapshot());
    bundle.put("platformApiCompatibility", platformApiCompatibilitySnapshot());
    bundle.put("supportDigest", OperatorBetaDashboardService.supportDigestForPayload(bundle));
    return bundle;
  }

  private static Map<String, Object> platformApiCompatibilitySnapshot() {
    return platformApiCompatibilitySnapshot(
        PlatformApiContract.current(), PlatformApiBaselineRegistry.current());
  }

  static Map<String, Object> platformApiCompatibilitySnapshot(
      PlatformApiContract contract, PlatformApiBaselineRegistry registry) {
    long stableDeprecations =
        contract.capabilities().stream()
                .filter(PlatformApiContract::isStableBaselineCapability)
                .filter(descriptor -> descriptor.deprecation() != null)
                .count()
            + contract.endpoints().stream()
                .filter(PlatformApiContract::isStableBaselineEndpoint)
                .filter(descriptor -> descriptor.deprecation() != null)
                .count();
    LinkedHashMap<String, Object> summary = LinkedHashMap.newLinkedHashMap(19);
    summary.put("urlApiVersion", contract.apiVersion());
    summary.put("contractVersion", contract.contractVersion());
    summary.put(
        "activeStableBaselines",
        registry.activeBaselineIds().stream().map(PlatformApiBaselineId::toString).toList());
    summary.put(
        "baselineRegistrySummary",
        PlatformApiContractJson.baselineRegistrySummaryToJsonValue(registry));
    summary.put("baselineRegistryDigest", registry.registryDigest());
    summary.put("supportPhase", contract.compatibilityWindow().supportPhase().jsonValue());
    summary.put(
        "supportWindowStartedRelease",
        contract.compatibilityWindow().supportWindowStartedRelease());
    summary.put("previousAuthenticatedReleaseRecord", null);
    summary.put("historyChainHealth", "bootstrap-only-not-release-authenticated");
    summary.put("candidateBaselineProposalCount", 0);
    summary.put("graduationBlockerCount", 0);
    summary.put("stableDeprecationCount", stableDeprecations);
    summary.put("appCompatibilityMatrixStatus", "not-generated");
    summary.put("installedAppRiskCount", null);
    summary.put("nextContractPreviewStatus", "not-generated");
    summary.put("evidenceFreshness", "repository-bootstrap-only");
    summary.put("protectedOperationState", "not-observed");
    summary.put("runtimeObservationStatus", "not-observed");
    summary.put(
        "evidenceBoundary",
        "Contract and baseline status is static metadata; no runtime compatibility observation is"
            + " claimed.");
    return java.util.Collections.unmodifiableMap(summary);
  }

  private Map<String, Object> lifecycleSnapshot() {
    CoreSupportLifecycleSnapshot snapshot = coreUpdateActionPort.supportLifecycleSnapshot();
    return (snapshot == null
            ? CoreSupportLifecycleSnapshot.unknown(
                -1, List.of("lifecycle_runtime_snapshot_unavailable"))
            : snapshot)
        .toJsonValue();
  }

  static Map<String, Object> supportBundleForExport(
      Map<String, Object> supportBundle, Map<String, Object> recoveryContext) {
    LinkedHashMap<String, Object> bundle = LinkedHashMap.newLinkedHashMap(12);
    bundle.putAll(supportBundle);
    bundle.put("supportBundleVersion", bundle.get("schemaVersion"));
    bundle.put("recoveryContext", recoveryContext);
    bundle.put("supportDigest", OperatorBetaDashboardService.supportDigestForPayload(bundle));
    return bundle;
  }

  private Map<String, Object> appSubmissionIntakeSummary() {
    Optional<FileAppSubmissionIntakeStore> maybeStore = appSubmissionIntakeStore();
    Map<String, Object> summary = appSubmissionIntakeBaseEnvelope(maybeStore.isPresent());
    if (maybeStore.isEmpty()) {
      summary.put("queueCount", 0);
      summary.put("submissions", List.of());
      summary.put(FIELD_WARNINGS, List.of("appSubmissionIntakeQueueNotConfigured"));
      return summary;
    }
    List<AppSubmissionIntakeSummary> submissions;
    try {
      submissions = maybeStore.orElseThrow().listSummaries();
    } catch (IOException | AppCatalogException _) {
      throw appSubmissionIntakeUnavailable();
    }
    summary.put("queueCount", submissions.size());
    summary.put(
        "submissions", submissions.stream().map(AppSubmissionIntakeSummary::toJsonValue).toList());
    summary.put(FIELD_WARNINGS, List.of());
    return summary;
  }

  private Map<String, Object> appSubmissionTransparencySummary() {
    Optional<FileAppSubmissionIntakeStore> maybeStore = appSubmissionIntakeStore();
    Map<String, Object> summary = appSubmissionIntakeBaseEnvelope(maybeStore.isPresent());
    summary.put("kind", "crypta-operator-app-submission-transparency-summary");
    if (maybeStore.isEmpty()) {
      summary.put("recordsWithTransparencyDigest", 0);
      summary.put(FIELD_WARNINGS, List.of("appSubmissionIntakeQueueNotConfigured"));
      return summary;
    }
    List<AppSubmissionIntakeSummary> submissions;
    try {
      submissions = maybeStore.orElseThrow().listSummaries();
    } catch (IOException | AppCatalogException _) {
      throw appSubmissionIntakeUnavailable();
    }
    summary.put(
        "recordsWithTransparencyDigest",
        submissions.stream().filter(item -> item.transparencyLogDigest() != null).count());
    summary.put(
        "submissionIds",
        submissions.stream()
            .filter(item -> item.transparencyLogDigest() != null)
            .map(AppSubmissionIntakeSummary::submissionId)
            .toList());
    summary.put(FIELD_WARNINGS, List.of());
    return summary;
  }

  private static Map<String, Object> appSubmissionIntakeBaseEnvelope(boolean configured) {
    LinkedHashMap<String, Object> envelope = LinkedHashMap.newLinkedHashMap(8);
    envelope.put("schemaVersion", 1);
    envelope.put("kind", "crypta-operator-app-submission-intake");
    envelope.put("configured", configured);
    envelope.put("route", "operator/app-submissions");
    envelope.put("operatorOnly", true);
    envelope.put("operatorRoutesInAppContract", false);
    return envelope;
  }

  private static Optional<FileAppSubmissionIntakeStore> appSubmissionIntakeStore() {
    String configured = System.getProperty(APP_SUBMISSION_INTAKE_DIR_PROPERTY);
    if (configured == null || configured.isBlank()) {
      configured = System.getenv(APP_SUBMISSION_INTAKE_DIR_ENV);
    }
    if (configured == null || configured.isBlank()) {
      return Optional.empty();
    }
    return Optional.of(new FileAppSubmissionIntakeStore(Path.of(configured)));
  }

  private static PlatformApiException appSubmissionIntakeUnavailable() {
    return new PlatformApiException(
        503, "app_submission_intake_unavailable", "App submission intake queue is unavailable.");
  }

  /**
   * Routes app-data backup creation and restore commit under {@code /operator/app-data}.
   *
   * @param segments decoded operator route segments
   * @param request full request metadata used to validate the method and query parameters
   * @return sensitive backup response containing an app-data backup bundle
   */
  private PlatformApiResponse routeAppData(List<String> segments, PlatformApiRequest request) {
    if (!APP_DATA_SEGMENT.equals(segments.get(1))) {
      throw notFound();
    }
    if ("backups".equals(segments.get(2))) {
      return routeAppDataBackup(request);
    }
    if ("restore".equals(segments.get(2))) {
      return routeAppDataRestoreCommit(request);
    }
    throw notFound();
  }

  private PlatformApiResponse routeAppDataBackup(PlatformApiRequest request) {
    if (!METHOD_POST.equals(request.method())) {
      return methodNotAllowed(METHOD_POST, POST_ONLY_MESSAGE);
    }
    if (appDataService == null) {
      throw new PlatformApiException(
          503, "app_data_service_unavailable", "App-data service is unavailable.");
    }
    return PlatformApiResponse.ok(
        appDataService.exportBackup(request.queryParameters(), currentCryptaVersion.get()));
  }

  private PlatformApiResponse routeAppDataRestoreCommit(PlatformApiRequest request) {
    if (!METHOD_POST.equals(request.method())) {
      return methodNotAllowed(METHOD_POST, POST_ONLY_MESSAGE);
    }
    if (appDataService == null) {
      throw new PlatformApiException(
          503, "app_data_service_unavailable", "App-data service is unavailable.");
    }
    return PlatformApiResponse.ok(appDataService.restoreBackup(request.queryParameters()));
  }

  /**
   * Routes app-data restore planning and commit under {@code /operator/app-data/restore}.
   *
   * @param segments decoded operator route segments
   * @param request full request metadata used to validate the method and form fields
   * @return metadata-only restore plan or result response
   */
  private PlatformApiResponse routeAppDataRestore(
      List<String> segments, PlatformApiRequest request) {
    if (!APP_DATA_SEGMENT.equals(segments.get(1)) || !"restore".equals(segments.get(2))) {
      throw notFound();
    }
    if (!METHOD_POST.equals(request.method())) {
      return methodNotAllowed(METHOD_POST, POST_ONLY_MESSAGE);
    }
    if (appDataService == null) {
      throw new PlatformApiException(
          503, "app_data_service_unavailable", "App-data service is unavailable.");
    }
    if ("plan".equals(segments.get(3))) {
      return PlatformApiResponse.ok(appDataService.planRestore(request.queryParameters()));
    }
    throw notFound();
  }

  /**
   * Routes operator-triggered recovery actions for durable content subscriptions.
   *
   * <p>These actions intentionally reuse {@link ContentSubscriptionService} rather than duplicating
   * subscription state handling in the dashboard layer. The response wraps the updated
   * operator-safe subscription summary in a stable envelope, and the service remains responsible
   * for validating app and subscription identifiers.
   *
   * @param segments decoded route segments for {@code /operator/subscriptions/{app}/{id}/{action}}
   * @param request full request metadata used to validate the HTTP method
   * @return JSON response containing the updated subscription summary
   */
  private PlatformApiResponse routeSubscriptionAction(
      List<String> segments, PlatformApiRequest request) {
    if (!SUBSCRIPTIONS_SEGMENT.equals(segments.get(1))) {
      throw notFound();
    }
    if (!METHOD_POST.equals(request.method())) {
      return methodNotAllowed(METHOD_POST, POST_ONLY_MESSAGE);
    }
    if (contentSubscriptionService == null) {
      throw new PlatformApiException(
          503,
          "content_subscription_service_unavailable",
          "Content subscription service is unavailable.");
    }

    String appId = segments.get(2);
    String subscriptionId = segments.get(3);
    String action = segments.get(4);
    Map<String, Object> subscription =
        switch (action) {
          case "refresh" -> contentSubscriptionService.refresh(appId, subscriptionId);
          case "pause" -> contentSubscriptionService.pause(appId, subscriptionId);
          case "resume" -> contentSubscriptionService.resume(appId, subscriptionId);
          case "reset-backoff" -> contentSubscriptionService.resetBackoff(appId, subscriptionId);
          case "reschedule-now" -> contentSubscriptionService.rescheduleNow(appId, subscriptionId);
          default -> throw notFound();
        };
    LinkedHashMap<String, Object> envelope = LinkedHashMap.newLinkedHashMap(1);
    envelope.put("subscription", dashboardService.operatorSubscriptionSummary(subscription));
    return PlatformApiResponse.ok(envelope);
  }

  /**
   * Rejects app principals before any operator-only evidence is assembled.
   *
   * @param request full request metadata containing the authenticated principal
   * @throws PlatformApiException when an app principal reaches an operator route
   */
  private static void requireHostOperator(PlatformApiRequest request) {
    if (request.principal().isApp()) {
      throw new PlatformApiException(
          403,
          "host_operator_required",
          "This Platform API route requires a host/operator principal.");
    }
  }

  /**
   * Creates a stable method-not-allowed response for operator route families.
   *
   * @param allow value for the response {@code Allow} header
   * @param message human-readable error message returned in the JSON body
   * @return Platform API error response with status {@code 405}
   */
  private static PlatformApiResponse methodNotAllowed(String allow, String message) {
    return PlatformApiResponse.error(405, Map.of("Allow", allow), "method_not_allowed", message);
  }

  /**
   * Creates the standard missing-route exception used by the Platform API router.
   *
   * @return exception that serializes to the stable {@code not_found} response shape
   */
  private static PlatformApiException notFound() {
    return new PlatformApiException(404, "not_found", "Platform API route not found.");
  }

  private static Map<String, Object> envelope(String key, Object value) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(1);
    json.put(key, value);
    return json;
  }
}
