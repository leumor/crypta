package network.crypta.platform.api;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;

/**
 * Deterministic compatibility contract for one Platform API surface.
 *
 * <p>The contract is the app-facing metadata artifact for Platform API v1. It names the current URL
 * API version, the integer compatibility contract version used by app manifests and catalogs, the
 * stable capability vocabulary, and the route/action descriptors used by app-principal
 * authorization. It intentionally contains no request bodies, query strings, local paths, command
 * lines, tokens, or private key material.
 *
 * <p>The current contract is process-local and immutable. Platform API authorization consults these
 * endpoint descriptors when app token or app browser-session principals make requests, while
 * developer tooling and release certification serialize the same model for offline compatibility
 * checks. That keeps the published contract and the authorization matrix tied to one descriptor
 * set.
 *
 * <p>All descriptor collections are copied during construction. Callers can safely retain a
 * contract instance, compare snapshots, or use it from multiple request threads without additional
 * synchronization.
 *
 * @param apiVersion URL API version such as {@code v1}
 * @param contractVersion integer app compatibility contract version
 * @param generatedBy stable producer label for snapshots
 * @param stabilityPolicy short human-readable stability policy
 * @param stableBaseline deterministic Platform API 1.0 stable app-facing baseline metadata
 * @param compatibilityWindow deterministic Platform API 1.0 compatibility-window policy metadata
 * @param capabilities deterministic public capability descriptors
 * @param endpoints deterministic public endpoint descriptors
 */
public record PlatformApiContract(
    String apiVersion,
    int contractVersion,
    String generatedBy,
    String stabilityPolicy,
    StableBaseline stableBaseline,
    PlatformApiCompatibilityWindow compatibilityWindow,
    List<PlatformApiCapabilityDescriptor> capabilities,
    List<PlatformApiEndpointDescriptor> endpoints) {
  /**
   * URL API version covered by the current app-facing contract.
   *
   * <p>This value describes the route prefix, for example {@code /api/v1}. It is intentionally
   * separate from {@link #CURRENT_CONTRACT_VERSION}, which is the compatibility version app
   * manifests and catalogs use for install and release-review decisions.
   */
  public static final String CURRENT_API_VERSION = "v1";

  /**
   * Integer compatibility contract version used by app manifests and catalogs.
   *
   * <p>The value increases when published app-facing Platform API compatibility metadata changes in
   * a way that tooling should be able to compare. Operator-only descriptors do not advance it. It
   * is not the Cryptad build number, and it is not the URL API version.
   */
  public static final int CURRENT_CONTRACT_VERSION = 25;

  /** Stable app-facing Platform API baseline name published in contract snapshots. */
  public static final String PLATFORM_API_STABLE_BASELINE_NAME = "1.0";

  /** Contract version whose stable descriptors define the Platform API 1.0 baseline. */
  public static final int PLATFORM_API_STABLE_BASELINE_CONTRACT_VERSION = 19;

  private static final Set<String> PLATFORM_API_STABLE_BASELINE_CAPABILITIES =
      Set.of(
          PlatformApiCapabilities.APP_DATA_READ,
          PlatformApiCapabilities.APP_DATA_WRITE,
          PlatformApiCapabilities.CONTENT_FETCH,
          PlatformApiCapabilities.CONTENT_INSERT,
          PlatformApiCapabilities.CONTENT_INSERT_APP_DOCUMENT,
          PlatformApiCapabilities.CONTENT_SUBSCRIBE,
          PlatformApiCapabilities.PLATFORM_CONTRACT_READ,
          PlatformApiCapabilities.QUEUE_READ,
          PlatformApiCapabilities.QUEUE_WRITE);

  private static final int INITIAL_CONTRACT_VERSION = 1;
  private static final int APP_UPDATE_LIFECYCLE_CONTRACT_VERSION = 2;
  private static final int APP_VAULT_CONTRACT_VERSION = 3;
  private static final int RECOMMENDED_CATALOG_CONTRACT_VERSION = 4;
  private static final int PROFILE_PUBLISHING_CONTRACT_VERSION = 5;
  private static final int CONTENT_FETCH_CONTRACT_VERSION = 6;
  private static final int TRUST_GRAPH_PREVIEW_CONTRACT_VERSION = 7;
  private static final int CONTENT_SUBSCRIPTIONS_CONTRACT_VERSION = 8;
  private static final int APP_DATA_STORE_CONTRACT_VERSION = 9;
  private static final int TRUST_GRAPH_EXCHANGE_CONTRACT_VERSION = 10;
  private static final int SOCIAL_MESSAGE_CONTRACT_VERSION = 11;
  private static final int APP_SERVICES_CONTRACT_VERSION = 12;
  private static final int TRUST_GRAPH_RC_SCOPE_CONTRACT_VERSION = 15;
  private static final int APP_SERVICE_DEPENDENCY_BUNDLES_CONTRACT_VERSION = 16;
  private static final int ECOSYSTEM_SECURITY_ADVISORY_CONTRACT_VERSION = 17;
  private static final int NETWORK_SCALE_BUDGET_CONTRACT_VERSION = 18;
  private static final int FIRST_PARTY_MAINTENANCE_CONTRACT_VERSION = 19;
  private static final int THIRD_PARTY_REVIEW_METADATA_CONTRACT_VERSION = 20;
  private static final int CONSENT_CONTRACT_VERSION = 21;
  private static final int TRUST_GRAPH_BETA_HARDENING_CONTRACT_VERSION = 22;
  private static final int CATALOG_OPERATIONS_CONTRACT_VERSION = 23;
  static final int NAMED_BASELINE_METADATA_CONTRACT_VERSION = 24;

  /**
   * Contract snapshot version that first records the operator-only support lifecycle descriptor.
   *
   * <p>Operator-only routes do not advance the app-facing compatibility version.
   */
  private static final int SUPPORT_LIFECYCLE_DESCRIPTOR_VERSION = 23;

  /**
   * Stable producer label written into generated contract snapshots.
   *
   * <p>The label identifies the contract source without embedding host-specific details. Snapshot
   * consumers can use it for display and provenance, but it is not intended as an authentication
   * mechanism.
   */
  public static final String GENERATED_BY = "cryptad";

  private static final String STABILITY_POLICY =
      "Stable endpoints and capabilities remain available within Platform API v1 contract version "
          + CURRENT_CONTRACT_VERSION
          + ". Contract version "
          + TRUST_GRAPH_RC_SCOPE_CONTRACT_VERSION
          + " adds local Trust Graph RC scope metadata, lifecycle statement routes, and bounded"
          + " contribution reason summaries"
          + ". Contract version "
          + APP_SERVICE_DEPENDENCY_BUNDLES_CONTRACT_VERSION
          + " adds app-service dependency graph and grant-bundle routes"
          + ". Contract version "
          + ECOSYSTEM_SECURITY_ADVISORY_CONTRACT_VERSION
          + " adds redacted ecosystem security advisory and revocation gate summaries"
          + ". Contract version "
          + NETWORK_SCALE_BUDGET_CONTRACT_VERSION
          + " adds app-visible network budget status and safe budget-exhausted errors for"
          + " content fetches, content subscriptions, and Trust Graph imports"
          + ". Contract version "
          + FIRST_PARTY_MAINTENANCE_CONTRACT_VERSION
          + " adds signed first-party maintenance policy metadata to catalog app summaries"
          + ". Contract version "
          + THIRD_PARTY_REVIEW_METADATA_CONTRACT_VERSION
          + " adds third-party submission review metadata to catalog app summaries"
          + ". Contract version "
          + CONSENT_CONTRACT_VERSION
          + " adds host/operator-only consent preview, decision, and audit route descriptors"
          + ". Contract version "
          + TRUST_GRAPH_BETA_HARDENING_CONTRACT_VERSION
          + " adds Trust Graph beta hardening import-preview and local-anchor lifecycle route"
          + " descriptors"
          + ". Contract version "
          + CATALOG_OPERATIONS_CONTRACT_VERSION
          + " adds signed catalog operations for mirrors, source health, rollback, key-rotation"
          + " status, and emergency advisory refresh"
          + ". Contract version "
          + NAMED_BASELINE_METADATA_CONTRACT_VERSION
          + " adds the named stable-baseline registry summary to public contract metadata"
          + ". The operator-only support-lifecycle descriptor does not advance the app-facing"
          + " compatibility version"
          + ". Endpoint descriptors retain the contract version where each route first appeared. "
          + "Experimental, deprecated, scheduled-for-removal, and internal entries are flagged for "
          + "developer tooling and release review before behavior changes.";

  private static final String ROUTE_FAMILY_APPS = "apps";
  private static final String ROUTE_FAMILY_APP_DATA = "app-data";
  private static final String ROUTE_FAMILY_APP_SERVICES = "app-services";
  private static final String ROUTE_FAMILY_APP_CATALOGS = "app-catalogs";
  private static final String ROUTE_FAMILY_APP_VAULT = "app-vault";
  private static final String ROUTE_FAMILY_CONFIG = "config";
  private static final String ROUTE_FAMILY_CONSENT = "consent";
  private static final String ROUTE_FAMILY_CONTENT = "content";
  private static final String ROUTE_FAMILY_IDENTITY_VAULT = "identity-vault";
  private static final String ROUTE_FAMILY_PEERS = "peers";
  private static final String ROUTE_FAMILY_QUEUE = "queue";
  private static final String ROUTE_FAMILY_SECURITY_LEVELS = "security-levels";
  private static final String ROUTE_FAMILY_TRUST_GRAPH = "trust-graph";
  private static final String ROUTE_FAMILY_UPDATES = "updates";
  private static final String ROUTE_APP_VAULT_SECRET = "/app-vault/secrets/{name}";
  private static final String ROUTE_IDENTITY_VAULT_GRANT = "/identity-vault/grants/{grantId}";
  private static final String METHOD_DELETE = "DELETE";
  private static final String METHOD_GET = "GET";
  private static final String METHOD_PATCH = "PATCH";
  private static final String METHOD_POST = "POST";
  private static final String METHOD_PUT = "PUT";
  private static final List<String> APP_CATALOG_UPDATE_MANAGE_CAPABILITIES =
      List.of(PlatformApiCapabilities.APPS_MANAGE, PlatformApiCapabilities.CATALOGS_MANAGE);

  private static final PlatformApiContract CURRENT =
      new PlatformApiContract(
          CURRENT_API_VERSION,
          CURRENT_CONTRACT_VERSION,
          GENERATED_BY,
          STABILITY_POLICY,
          null,
          null,
          capabilityDescriptors(),
          endpointDescriptors());

  /**
   * Creates a normalized immutable contract model.
   *
   * <p>The constructor validates only the structural rules that must hold for any contract
   * snapshot: text fields must be present, the contract version must be positive, descriptor
   * collections must be non-null, capability names must be unique, and every endpoint-required
   * capability must have a corresponding capability descriptor. It does not sort the supplied
   * descriptors; callers provide the intended deterministic order.
   */
  public PlatformApiContract {
    PlatformApiContractVersion version =
        new PlatformApiContractVersion(apiVersion, contractVersion);
    apiVersion = version.apiVersion();
    contractVersion = version.contractVersion();
    generatedBy = requireText(generatedBy, "generatedBy");
    stabilityPolicy = requireText(stabilityPolicy, "stabilityPolicy");
    capabilities = List.copyOf(Objects.requireNonNull(capabilities, "capabilities"));
    endpoints = List.copyOf(Objects.requireNonNull(endpoints, "endpoints"));
    requireEndpointCapabilitiesKnown(capabilities, endpoints);
    StableBaseline derivedBaseline = StableBaseline.fromDescriptors(capabilities, endpoints);
    stableBaseline = stableBaseline == null ? derivedBaseline : stableBaseline;
    stableBaseline.requireMatches(derivedBaseline);
    PlatformApiCompatibilityWindow defaultWindow =
        PlatformApiCompatibilityWindow.current(contractVersion);
    compatibilityWindow = compatibilityWindow == null ? defaultWindow : compatibilityWindow;
    requireCompatibilityWindowMatches(compatibilityWindow, contractVersion, stableBaseline);
  }

  /**
   * Creates a normalized contract model using the stable baseline derived from descriptors.
   *
   * <p>This overload preserves the pre-freeze constructor shape used by tests and offline tooling
   * that build synthetic contracts. New callers can pass an explicit baseline through the canonical
   * record constructor; it must match the descriptor-derived baseline.
   *
   * @param apiVersion URL API version such as {@code v1}
   * @param contractVersion integer app compatibility contract version
   * @param generatedBy stable producer label for snapshots
   * @param stabilityPolicy short human-readable stability policy
   * @param capabilities deterministic public capability descriptors
   * @param endpoints deterministic public endpoint descriptors
   */
  public PlatformApiContract(
      String apiVersion,
      int contractVersion,
      String generatedBy,
      String stabilityPolicy,
      List<PlatformApiCapabilityDescriptor> capabilities,
      List<PlatformApiEndpointDescriptor> endpoints) {
    this(
        apiVersion,
        contractVersion,
        generatedBy,
        stabilityPolicy,
        null,
        null,
        capabilities,
        endpoints);
  }

  /**
   * Creates a normalized contract model with explicit stable-baseline metadata.
   *
   * <p>This overload preserves the stable-freeze constructor shape used by tests and tooling before
   * compatibility-window policy metadata became first-class. The window policy is derived from the
   * contract version and current Platform API 1.0 defaults.
   *
   * @param apiVersion URL API version such as {@code v1}
   * @param contractVersion integer app compatibility contract version
   * @param generatedBy stable producer label for snapshots
   * @param stabilityPolicy short human-readable stability policy
   * @param stableBaseline deterministic Platform API 1.0 stable app-facing baseline metadata
   * @param capabilities deterministic public capability descriptors
   * @param endpoints deterministic public endpoint descriptors
   */
  public PlatformApiContract(
      String apiVersion,
      int contractVersion,
      String generatedBy,
      String stabilityPolicy,
      StableBaseline stableBaseline,
      List<PlatformApiCapabilityDescriptor> capabilities,
      List<PlatformApiEndpointDescriptor> endpoints) {
    this(
        apiVersion,
        contractVersion,
        generatedBy,
        stabilityPolicy,
        stableBaseline,
        null,
        capabilities,
        endpoints);
  }

  /**
   * Returns the process-local Platform API v1 contract.
   *
   * <p>The returned instance is shared and immutable. It is safe for request routing,
   * app-management summaries, developer CLI snapshots, and release-certification checks to reuse
   * the same object without defensive copying.
   *
   * @return deterministic current Platform API compatibility contract for this build
   */
  public static PlatformApiContract current() {
    return CURRENT;
  }

  /**
   * Returns the typed API and compatibility contract version pair for this contract.
   *
   * <p>The record form is useful for callers that need to pass the URL API version and integer
   * compatibility version together without implying they advance in lockstep. JSON serialization
   * still emits the two fields separately to preserve the public snapshot shape.
   *
   * @return validated version pair for this contract instance
   */
  public PlatformApiContractVersion version() {
    return new PlatformApiContractVersion(apiVersion, contractVersion);
  }

  /**
   * Returns all capability names in deterministic lexicographic order.
   *
   * <p>This helper is intended for linting, manifest validation, and drift tests that only need the
   * public capability vocabulary. The returned set is immutable and detached from the descriptor
   * list stored in the contract.
   *
   * @return immutable sorted capability vocabulary exposed to app manifests
   */
  public Set<String> capabilityNames() {
    TreeSet<String> names = new TreeSet<>();
    for (PlatformApiCapabilityDescriptor descriptor : capabilities) {
      names.add(descriptor.name());
    }
    return java.util.Collections.unmodifiableSet(names);
  }

  /**
   * Finds the contract endpoint matching one normalized request.
   *
   * <p>Routing code calls this method after it has decoded the request path below {@code /api/v1}.
   * The lookup is deliberately descriptor-based rather than hard-coded in the authorization layer,
   * so an endpoint added to the public contract is also the endpoint the app-principal matrix uses.
   * Host/operator authorization bypasses this app-principal lookup through the existing local-admin
   * model.
   *
   * @param method HTTP-style method name; it is normalized to upper case before matching
   * @param pathSegments decoded Platform API path segments beneath {@code /api/v1}
   * @param principalType principal type being authorized for this request
   * @return matching descriptor, or {@code null} when no app-visible contract entry matches
   */
  PlatformApiEndpointDescriptor endpointFor(
      String method, List<String> pathSegments, PlatformApiPrincipalType principalType) {
    String normalizedMethod = Objects.requireNonNull(method, "method").toUpperCase(Locale.ROOT);
    List<String> segments = List.copyOf(Objects.requireNonNull(pathSegments, "pathSegments"));
    for (PlatformApiEndpointDescriptor endpoint : endpoints) {
      if (endpoint.matches(normalizedMethod, segments) && endpoint.allowsPrincipal(principalType)) {
        return endpoint;
      }
    }
    return null;
  }

  /**
   * Returns capability descriptors keyed by capability name.
   *
   * <p>The map preserves the descriptor order from the contract list. Callers use it when verifying
   * manifest permissions or optional capabilities and need stability metadata for a known
   * capability name.
   *
   * @return deterministic immutable capability descriptor lookup by manifest capability name
   */
  Map<String, PlatformApiCapabilityDescriptor> capabilitiesByName() {
    LinkedHashMap<String, PlatformApiCapabilityDescriptor> byName =
        LinkedHashMap.newLinkedHashMap(capabilities.size());
    for (PlatformApiCapabilityDescriptor descriptor : capabilities) {
      byName.put(descriptor.name(), descriptor);
    }
    return java.util.Collections.unmodifiableMap(byName);
  }

  Map<String, PlatformApiEndpointDescriptor> stableBaselineEndpointsByIdentity() {
    LinkedHashMap<String, PlatformApiEndpointDescriptor> byIdentity = new LinkedHashMap<>();
    for (PlatformApiEndpointDescriptor endpoint : endpoints) {
      if (isStableBaselineEndpoint(endpoint)) {
        byIdentity.put(endpointIdentity(endpoint), endpoint);
      }
    }
    return java.util.Collections.unmodifiableMap(byIdentity);
  }

  static boolean isStableBaselineCapability(PlatformApiCapabilityDescriptor descriptor) {
    return descriptor.stability().isStableCompatibilityCovered()
        && descriptor.sinceContractVersion() <= PLATFORM_API_STABLE_BASELINE_CONTRACT_VERSION
        && PLATFORM_API_STABLE_BASELINE_CAPABILITIES.contains(descriptor.name());
  }

  static boolean isStableBaselineEndpoint(PlatformApiEndpointDescriptor descriptor) {
    return descriptor.stability().isStableCompatibilityCovered()
        && descriptor.sinceContractVersion() <= PLATFORM_API_STABLE_BASELINE_CONTRACT_VERSION
        && (descriptor.appProcessAllowed() || descriptor.appBrowserAllowed())
        && PLATFORM_API_STABLE_BASELINE_CAPABILITIES.containsAll(descriptor.requiredCapabilities());
  }

  private static void requireCompatibilityWindowMatches(
      PlatformApiCompatibilityWindow window, int contractVersion, StableBaseline stableBaseline) {
    if (!window.baselineName().equals(stableBaseline.name())
        || window.baselineContractVersion() != stableBaseline.contractVersion()) {
      throw new IllegalArgumentException(
          "compatibilityWindow baseline identity must match stableBaseline");
    }
    if (window.currentContractVersion() != contractVersion) {
      throw new IllegalArgumentException(
          "compatibilityWindow.currentContractVersion must match contractVersion");
    }
    if (!window.equals(PlatformApiCompatibilityWindow.current(contractVersion))) {
      throw new IllegalArgumentException(
          "compatibilityWindow must match the canonical Platform API 1.0 support policy");
    }
  }

  static String endpointIdentity(PlatformApiEndpointDescriptor endpoint) {
    return endpoint.method() + " " + endpoint.routeTemplate();
  }

  private static void requireEndpointCapabilitiesKnown(
      List<PlatformApiCapabilityDescriptor> capabilities,
      List<PlatformApiEndpointDescriptor> endpoints) {
    Set<String> names = new TreeSet<>();
    for (PlatformApiCapabilityDescriptor descriptor : capabilities) {
      if (!names.add(descriptor.name())) {
        throw new IllegalArgumentException("duplicate capability descriptor: " + descriptor.name());
      }
    }
    for (PlatformApiEndpointDescriptor endpoint : endpoints) {
      for (String capability : endpoint.requiredCapabilities()) {
        if (!names.contains(capability)) {
          throw new IllegalArgumentException(
              "endpoint references unknown capability: " + capability);
        }
      }
    }
  }

  private static List<PlatformApiCapabilityDescriptor> capabilityDescriptors() {
    return List.of(
        experimentalCapabilitySince(
            "mail.control", 25, "Use the fixed own-app Mail worker channel."),
        experimentalCapabilitySince(
            "vault.mail.sign", 25, "Sign bounded Mail contact and message objects in the vault."),
        experimentalCapabilitySince(
            "vault.mail.open",
            25,
            "Open fixed Mail network envelopes for the current Mail process."),
        experimentalCapabilitySince(
            "vault.mail.storage", 25, "Protect the Mail process private local dataset."),
        capability(PlatformApiCapabilities.ALERTS_READ, "Read current runtime alerts."),
        capability(PlatformApiCapabilities.ALERTS_WRITE, "Dismiss operator-visible alerts."),
        capability(
            PlatformApiCapabilities.APPS_MANAGE, "Install, update, start, stop, or remove apps."),
        capability(
            PlatformApiCapabilities.APPS_READ, "Read installed app summaries and diagnostics."),
        new PlatformApiCapabilityDescriptor(
            PlatformApiCapabilities.APP_DATA_READ,
            PlatformApiStabilityLevel.STABLE,
            APP_DATA_STORE_CONTRACT_VERSION,
            null,
            "Read bounded app-owned durable data records, namespace metadata, status, and"
                + " exports."),
        new PlatformApiCapabilityDescriptor(
            PlatformApiCapabilities.APP_DATA_WRITE,
            PlatformApiStabilityLevel.STABLE,
            APP_DATA_STORE_CONTRACT_VERSION,
            null,
            "Create, replace, delete, import, and migrate bounded app-owned durable data."),
        new PlatformApiCapabilityDescriptor(
            PlatformApiCapabilities.APP_SERVICES_CALL,
            PlatformApiStabilityLevel.EXPERIMENTAL,
            APP_SERVICES_CONTRACT_VERSION,
            null,
            "Request operator-approved local app-service grants and invoke approved bounded"
                + " services."),
        new PlatformApiCapabilityDescriptor(
            PlatformApiCapabilities.APP_SERVICES_READ,
            PlatformApiStabilityLevel.EXPERIMENTAL,
            APP_SERVICES_CONTRACT_VERSION,
            null,
            "Discover advertised local app services and read app-scoped service grants."),
        capability(
            PlatformApiCapabilities.CATALOGS_MANAGE,
            "Add, refresh, remove, install from, or update from app catalogs."),
        capability(
            PlatformApiCapabilities.CATALOGS_READ, "Read signed app-catalog sources and entries."),
        capability(PlatformApiCapabilities.CONFIG_READ, "Read configuration projections."),
        capability(
            PlatformApiCapabilities.CONFIG_WRITE, "Apply and persist configuration changes."),
        capability(PlatformApiCapabilities.CONNECTIVITY_READ, "Read connectivity diagnostics."),
        new PlatformApiCapabilityDescriptor(
            PlatformApiCapabilities.CONTENT_FETCH,
            PlatformApiStabilityLevel.STABLE,
            CONTENT_FETCH_CONTRACT_VERSION,
            null,
            "Fetch bounded Crypta content documents through app-facing network reads."),
        new PlatformApiCapabilityDescriptor(
            PlatformApiCapabilities.CONTENT_SUBSCRIBE,
            PlatformApiStabilityLevel.STABLE,
            CONTENT_SUBSCRIPTIONS_CONTRACT_VERSION,
            null,
            "Create and manage app-owned bounded USK content subscriptions."),
        capability(
            PlatformApiCapabilities.CONTENT_INSERT,
            "Create local file or directory insert requests."),
        new PlatformApiCapabilityDescriptor(
            PlatformApiCapabilities.CONTENT_INSERT_APP_DOCUMENT,
            PlatformApiStabilityLevel.STABLE,
            PROFILE_PUBLISHING_CONTRACT_VERSION,
            null,
            "Create app-generated document insert requests without local source paths."),
        capability(PlatformApiCapabilities.DIAGNOSTICS_READ, "Read runtime diagnostic reports."),
        capability(
            PlatformApiCapabilities.NODE_READ, "Read node identity, greeting, and reference data."),
        capability(PlatformApiCapabilities.PEERS_READ, "Read peer summaries and peer details."),
        capability(PlatformApiCapabilities.PEERS_WRITE, "Add, update, annotate, or remove peers."),
        capability(
            PlatformApiCapabilities.PLATFORM_CONTRACT_READ,
            "Read the public Platform API compatibility contract."),
        capability(
            PlatformApiCapabilities.QUEUE_READ,
            "Read queue pages, counts, keys, and completion state."),
        capability(
            PlatformApiCapabilities.QUEUE_WRITE,
            "Create downloads or mutate existing queue entries."),
        capability(
            PlatformApiCapabilities.SECURITY_READ, "Read security-level state and warnings."),
        capability(PlatformApiCapabilities.SECURITY_WRITE, "Change security-level settings."),
        experimentalCapabilitySince(
            PlatformApiCapabilities.TRUST_READ,
            TRUST_GRAPH_PREVIEW_CONTRACT_VERSION,
            "Read local Trust Graph RC status, anchors, subjects, statements, scores, lifecycle,"
                + " and bounded evidence."),
        experimentalCapabilitySince(
            PlatformApiCapabilities.TRUST_WRITE,
            TRUST_GRAPH_PREVIEW_CONTRACT_VERSION,
            "Import local trust statements and manage local Trust Graph RC anchors and statement"
                + " lifecycle policy."),
        capability(PlatformApiCapabilities.UPDATES_READ, "Read core update state."),
        capability(PlatformApiCapabilities.UPDATES_WRITE, "Trigger core update actions."),
        experimentalCapability(
            PlatformApiCapabilities.VAULT_IDENTITIES_CREATE,
            "Create app-owned vault identities without exposing private key material."),
        new PlatformApiCapabilityDescriptor(
            PlatformApiCapabilities.VAULT_IDENTITIES_MANAGE,
            PlatformApiStabilityLevel.OPERATOR_ONLY,
            APP_VAULT_CONTRACT_VERSION,
            null,
            "Manage vault identity grants through host/operator routes."),
        experimentalCapability(
            PlatformApiCapabilities.VAULT_IDENTITIES_READ,
            "Read vault identity metadata granted to the calling app."),
        experimentalCapability(
            PlatformApiCapabilities.VAULT_IDENTITIES_USE,
            "Use granted vault identities for approved bounded operations."),
        experimentalCapability(
            PlatformApiCapabilities.VAULT_SECRETS_READ,
            "Read app-owned secret values from the process-only vault API."),
        experimentalCapability(
            PlatformApiCapabilities.VAULT_SECRETS_WRITE,
            "Create, replace, or delete app-owned secret values through the process-only vault"
                + " API."),
        capability(PlatformApiCapabilities.WIZARD_READ, "Read first-time wizard state."),
        capability(PlatformApiCapabilities.WIZARD_WRITE, "Submit first-time wizard choices."));
  }

  private static List<PlatformApiEndpointDescriptor> endpointDescriptors() {
    EndpointBuilder builder = new EndpointBuilder();
    builder.get(
        "node",
        "/node/greeting",
        PlatformApiCapabilities.NODE_READ,
        PlatformApiCapabilities.NODE_READ,
        "Read the node greeting snapshot.");
    builder.get(
        "node",
        "/node/reference",
        PlatformApiCapabilities.NODE_READ,
        PlatformApiCapabilities.NODE_READ,
        "Read the node reference export.");
    builder.get(
        "connectivity",
        "/connectivity",
        PlatformApiCapabilities.CONNECTIVITY_READ,
        PlatformApiCapabilities.CONNECTIVITY_READ,
        "Read connectivity diagnostics.");
    builder.get(
        "diagnostics",
        "/diagnostics",
        PlatformApiCapabilities.DIAGNOSTICS_READ,
        PlatformApiCapabilities.DIAGNOSTICS_READ,
        "Read runtime diagnostic sections and plain-text export.");
    builder.get(
        "alerts",
        "/alerts",
        PlatformApiCapabilities.ALERTS_READ,
        PlatformApiCapabilities.ALERTS_READ,
        "Read current runtime alerts.");
    builder.post(
        "alerts",
        "/alerts/{alertId}/dismiss",
        "alerts.dismiss",
        List.of(PlatformApiCapabilities.ALERTS_WRITE),
        "Dismiss one operator-visible alert.");
    builder.get(
        ROUTE_FAMILY_CONFIG,
        "/config",
        PlatformApiCapabilities.CONFIG_READ,
        PlatformApiCapabilities.CONFIG_READ,
        "Read exported configuration projections.");
    builder.post(
        ROUTE_FAMILY_CONFIG,
        "/config/overrides",
        "config.overrides",
        List.of(PlatformApiCapabilities.CONFIG_WRITE),
        "Apply configuration overrides.");
    builder.post(
        ROUTE_FAMILY_CONFIG,
        "/config/persist",
        "config.persist",
        List.of(PlatformApiCapabilities.CONFIG_WRITE),
        "Persist current configuration values.");
    builder.get(
        ROUTE_FAMILY_SECURITY_LEVELS,
        "/security-levels",
        PlatformApiCapabilities.SECURITY_READ,
        PlatformApiCapabilities.SECURITY_READ,
        "Read security-level state.");
    builder.get(
        ROUTE_FAMILY_SECURITY_LEVELS,
        "/security-levels/network-warning",
        "security.network-warning",
        PlatformApiCapabilities.SECURITY_READ,
        "Read the network threat-level warning.");
    builder.post(
        ROUTE_FAMILY_SECURITY_LEVELS,
        "/security-levels/network",
        "security.network",
        List.of(PlatformApiCapabilities.SECURITY_WRITE),
        "Change the network threat level.");
    builder.post(
        ROUTE_FAMILY_SECURITY_LEVELS,
        "/security-levels/physical",
        "security.physical",
        List.of(PlatformApiCapabilities.SECURITY_WRITE),
        "Change the physical threat level.");
    builder.get(
        ROUTE_FAMILY_UPDATES,
        "/updates/core",
        PlatformApiCapabilities.UPDATES_READ,
        PlatformApiCapabilities.UPDATES_READ,
        "Read core update state.");
    builder.supportLifecycleGet();
    builder.post(
        ROUTE_FAMILY_UPDATES,
        "/updates/core/download",
        "updates.core.download",
        List.of(PlatformApiCapabilities.UPDATES_WRITE),
        "Start a core package download.");
    builder.get(
        "wizard",
        "/wizard/first-time",
        PlatformApiCapabilities.WIZARD_READ,
        PlatformApiCapabilities.WIZARD_READ,
        "Read first-time wizard state.");
    builder.post(
        "wizard",
        "/wizard/first-time/apply",
        "wizard.first-time.apply",
        List.of(PlatformApiCapabilities.WIZARD_WRITE),
        "Apply first-time wizard choices.");
    builder.get(
        ROUTE_FAMILY_QUEUE,
        "/queue",
        PlatformApiCapabilities.QUEUE_READ,
        PlatformApiCapabilities.QUEUE_READ,
        "Read the queue snapshot.");
    builder.get(
        ROUTE_FAMILY_QUEUE,
        "/queue/count",
        PlatformApiCapabilities.QUEUE_READ,
        PlatformApiCapabilities.QUEUE_READ,
        "Read queue counts.");
    builder.get(
        ROUTE_FAMILY_QUEUE,
        "/queue/keys",
        PlatformApiCapabilities.QUEUE_READ,
        PlatformApiCapabilities.QUEUE_READ,
        "Read queue key exports.");
    builder.post(
        ROUTE_FAMILY_QUEUE,
        "/queue/downloads",
        "queue.downloads.create",
        List.of(PlatformApiCapabilities.QUEUE_WRITE),
        "Create a direct download request.");
    builder.post(
        ROUTE_FAMILY_QUEUE,
        "/queue/inserts/file",
        "queue.inserts.file",
        List.of(PlatformApiCapabilities.CONTENT_INSERT, PlatformApiCapabilities.QUEUE_WRITE),
        "Create a local file insert request.");
    builder.post(
        ROUTE_FAMILY_QUEUE,
        "/queue/inserts/directory",
        "queue.inserts.directory",
        List.of(PlatformApiCapabilities.CONTENT_INSERT, PlatformApiCapabilities.QUEUE_WRITE),
        "Create a local directory insert request.");
    builder.queueAppDocumentPost();
    builder.contentFetchPost();
    builder.contentSubscriptionEndpoints();
    builder.appDataEndpoints();
    builder.appServiceEndpoints();
    builder.consentEndpoints();
    builder.trustGraphPreviewEndpoints();
    builder.post(
        ROUTE_FAMILY_QUEUE,
        "/queue/requests/remove",
        "queue.requests.remove",
        List.of(PlatformApiCapabilities.QUEUE_WRITE),
        "Remove queue requests.");
    builder.post(
        ROUTE_FAMILY_QUEUE,
        "/queue/requests/restart",
        "queue.requests.restart",
        List.of(PlatformApiCapabilities.QUEUE_WRITE),
        "Restart queue requests.");
    builder.post(
        ROUTE_FAMILY_QUEUE,
        "/queue/requests/priority",
        "queue.requests.priority",
        List.of(PlatformApiCapabilities.QUEUE_WRITE),
        "Change queue request priority.");
    builder.post(
        ROUTE_FAMILY_QUEUE,
        "/queue/cleanup/uploads",
        "queue.cleanup.uploads",
        List.of(PlatformApiCapabilities.QUEUE_WRITE),
        "Clean completed upload requests.");
    builder.post(
        ROUTE_FAMILY_QUEUE,
        "/queue/cleanup/downloads",
        "queue.cleanup.downloads",
        List.of(PlatformApiCapabilities.QUEUE_WRITE),
        "Clean completed download requests.");
    builder.get(
        ROUTE_FAMILY_PEERS,
        "/peers",
        PlatformApiCapabilities.PEERS_READ,
        PlatformApiCapabilities.PEERS_READ,
        "Read peer summaries.");
    builder.get(
        ROUTE_FAMILY_PEERS,
        "/peers/{peerId}",
        PlatformApiCapabilities.PEERS_READ,
        PlatformApiCapabilities.PEERS_READ,
        "Read one peer detail.");
    builder.post(
        ROUTE_FAMILY_PEERS,
        "/peers/add",
        "peers.add",
        List.of(PlatformApiCapabilities.PEERS_WRITE),
        "Add a peer.");
    builder.post(
        ROUTE_FAMILY_PEERS,
        "/peers/{peerId}/settings",
        "peers.settings",
        List.of(PlatformApiCapabilities.PEERS_WRITE),
        "Update peer settings.");
    builder.post(
        ROUTE_FAMILY_PEERS,
        "/peers/{peerId}/note",
        "peers.note",
        List.of(PlatformApiCapabilities.PEERS_WRITE),
        "Update a peer note.");
    builder.post(
        ROUTE_FAMILY_PEERS,
        "/peers/{peerId}/remove",
        "peers.remove",
        List.of(PlatformApiCapabilities.PEERS_WRITE),
        "Remove a peer.");
    builder.get(
        ROUTE_FAMILY_APPS,
        "/apps",
        PlatformApiCapabilities.APPS_READ,
        PlatformApiCapabilities.APPS_READ,
        "List installed apps.");
    builder.get(
        ROUTE_FAMILY_APPS,
        "/apps/{appId}",
        PlatformApiCapabilities.APPS_READ,
        PlatformApiCapabilities.APPS_READ,
        "Read one installed app summary.");
    builder.get(
        ROUTE_FAMILY_APPS,
        "/apps/{appId}/runtime",
        PlatformApiCapabilities.APPS_READ,
        PlatformApiCapabilities.APPS_READ,
        "Read token-free app runtime status.");
    builder.get(
        ROUTE_FAMILY_APPS,
        "/apps/{appId}/logs",
        PlatformApiCapabilities.APPS_READ,
        PlatformApiCapabilities.APPS_READ,
        "Read redacted app process logs.");
    builder.get(
        ROUTE_FAMILY_APPS,
        "/apps/{appId}/permissions",
        PlatformApiCapabilities.APPS_READ,
        PlatformApiCapabilities.APPS_READ,
        "Read app permissions and denied-count summary.");
    builder.get(
        ROUTE_FAMILY_APPS,
        "/apps/{appId}/audit",
        PlatformApiCapabilities.APPS_READ,
        PlatformApiCapabilities.APPS_READ,
        "Read bounded app audit entries.");
    builder.post(
        ROUTE_FAMILY_APPS,
        "/apps/install",
        "apps.install",
        List.of(PlatformApiCapabilities.APPS_MANAGE),
        "Install a staged app bundle.");
    builder.post(
        ROUTE_FAMILY_APPS,
        "/apps/{appId}/start",
        "apps.start",
        List.of(PlatformApiCapabilities.APPS_MANAGE),
        "Start an installed app.");
    builder.post(
        ROUTE_FAMILY_APPS,
        "/apps/{appId}/stop",
        "apps.stop",
        List.of(PlatformApiCapabilities.APPS_MANAGE),
        "Stop a running app.");
    builder.post(
        ROUTE_FAMILY_APPS,
        "/apps/{appId}/update",
        "apps.update",
        List.of(PlatformApiCapabilities.APPS_MANAGE),
        "Update an installed app from a staged bundle.");
    builder.appUpdateGet(
        "/apps/{appId}/updates",
        PlatformApiCapabilities.APPS_READ,
        "Read app update lifecycle status.");
    builder.appUpdatePost(
        "/apps/{appId}/updates/check",
        "apps.updates.check",
        APP_CATALOG_UPDATE_MANAGE_CAPABILITIES,
        "Check signed catalogs for an app update candidate.");
    builder.appUpdatePost(
        "/apps/{appId}/updates/stage",
        "apps.updates.stage",
        APP_CATALOG_UPDATE_MANAGE_CAPABILITIES,
        "Stage a verified app update candidate.");
    builder.appUpdatePost(
        "/apps/{appId}/updates/apply",
        "apps.updates.apply",
        APP_CATALOG_UPDATE_MANAGE_CAPABILITIES,
        "Apply a staged app update.");
    builder.appUpdatePost(
        "/apps/{appId}/updates/rollback",
        "apps.updates.rollback",
        List.of(PlatformApiCapabilities.APPS_MANAGE),
        "Restore the previous retained app bundle.");
    builder.appUpdateGet(
        "/apps/{appId}/updates/policy", "apps.updates.policy", "Read the app update policy.");
    builder.appUpdatePolicyPost();
    builder.delete(
        ROUTE_FAMILY_APPS,
        "/apps/{appId}",
        "apps.uninstall",
        List.of(PlatformApiCapabilities.APPS_MANAGE),
        "Uninstall a stopped app.");
    builder.get(
        ROUTE_FAMILY_APP_CATALOGS,
        "/app-catalogs",
        PlatformApiCapabilities.CATALOGS_READ,
        PlatformApiCapabilities.CATALOGS_READ,
        "List configured app catalogs.");
    builder.appCatalogRecommendationGet();
    builder.get(
        ROUTE_FAMILY_APP_CATALOGS,
        "/app-catalogs/{catalogId}/apps",
        PlatformApiCapabilities.CATALOGS_READ,
        PlatformApiCapabilities.CATALOGS_READ,
        "List apps in one catalog.");
    builder.get(
        ROUTE_FAMILY_APP_CATALOGS,
        "/app-catalogs/{catalogId}/apps/{appId}",
        PlatformApiCapabilities.CATALOGS_READ,
        PlatformApiCapabilities.CATALOGS_READ,
        "Read one catalog app entry.");
    builder.post(
        ROUTE_FAMILY_APP_CATALOGS,
        "/app-catalogs/add",
        "catalogs.add",
        List.of(PlatformApiCapabilities.CATALOGS_MANAGE),
        "Add a signed catalog source.");
    builder.appCatalogRecommendationPost();
    builder.post(
        ROUTE_FAMILY_APP_CATALOGS,
        "/app-catalogs/{catalogId}/refresh",
        "catalogs.refresh",
        List.of(PlatformApiCapabilities.CATALOGS_MANAGE),
        "Refresh one signed catalog source.");
    builder.catalogOperations();
    builder.delete(
        ROUTE_FAMILY_APP_CATALOGS,
        "/app-catalogs/{catalogId}",
        "catalogs.remove",
        List.of(PlatformApiCapabilities.CATALOGS_MANAGE),
        "Remove one signed catalog source.");
    builder.post(
        ROUTE_FAMILY_APP_CATALOGS,
        "/app-catalogs/{catalogId}/apps/{appId}/install",
        "catalogs.apps.install",
        List.of(PlatformApiCapabilities.CATALOGS_MANAGE),
        "Install an app from a signed catalog.");
    builder.post(
        ROUTE_FAMILY_APP_CATALOGS,
        "/app-catalogs/{catalogId}/apps/{appId}/update",
        "catalogs.apps.update",
        List.of(PlatformApiCapabilities.CATALOGS_MANAGE),
        "Update an app from a signed catalog.");
    builder.appVaultGet(
        "/app-vault/secrets",
        "app-vault.secrets.list",
        List.of(PlatformApiCapabilities.VAULT_SECRETS_READ),
        false,
        "List redacted metadata for app-owned secrets.");
    builder.appVaultPutSecret();
    builder.appVaultGet(
        ROUTE_APP_VAULT_SECRET,
        "app-vault.secrets.read",
        List.of(PlatformApiCapabilities.VAULT_SECRETS_READ),
        false,
        "Read one app-owned secret value for an app process principal.");
    builder.appVaultDeleteSecret();
    builder.appVaultGet(
        "/app-vault/identities",
        "app-vault.identities.list",
        List.of(PlatformApiCapabilities.VAULT_IDENTITIES_READ),
        true,
        "List vault identity metadata visible to the calling app.");
    builder.appVaultPost(
        "/app-vault/identities",
        "app-vault.identities.create",
        List.of(PlatformApiCapabilities.VAULT_IDENTITIES_CREATE),
        true,
        "Create an app-owned vault identity.");
    builder.appVaultGet(
        "/app-vault/identities/{identityId}",
        "app-vault.identities.read",
        List.of(PlatformApiCapabilities.VAULT_IDENTITIES_READ),
        true,
        "Read one vault identity metadata record visible to the calling app.");
    builder.appVaultPost(
        "/app-vault/identities/{identityId}/use",
        "app-vault.identities.use",
        List.of(PlatformApiCapabilities.VAULT_IDENTITIES_USE),
        false,
        "Use one granted vault identity for a bounded operation.");
    builder.appVaultProfileDocumentPost();
    builder.appVaultSocialMessagePost();
    builder.appVaultTrustStatementPost();
    builder.appVaultGet(
        "/app-vault/grants",
        "app-vault.grants.list",
        List.of(PlatformApiCapabilities.VAULT_IDENTITIES_READ),
        true,
        "List vault identity grants for the calling app.");
    builder.appVaultPost(
        "/app-vault/grants/request",
        "app-vault.grants.request",
        List.of(PlatformApiCapabilities.VAULT_IDENTITIES_READ),
        true,
        "Submit a token-free vault grant request for operator review.");
    builder.identityVaultGet(
        "/identity-vault/identities",
        "identity-vault.identities.list",
        "List vault identities for host/operator management.");
    builder.identityVaultPost(
        "/identity-vault/identities",
        "identity-vault.identities.create",
        "Create an operator-managed vault identity.");
    builder.identityVaultGet(
        "/identity-vault/identities/{identityId}",
        "identity-vault.identities.read",
        "Read one vault identity for host/operator management.");
    builder.identityVaultDelete(
        "/identity-vault/identities/{identityId}",
        "identity-vault.identities.delete",
        "Delete one vault identity and revoke its grants.");
    builder.identityVaultGet(
        "/identity-vault/grants",
        "identity-vault.grants.list",
        "List vault identity grants for host/operator management.");
    builder.identityVaultPost(
        "/identity-vault/grants",
        "identity-vault.grants.create",
        "Grant one vault identity to one app.");
    builder.identityVaultGrantStatusPatch();
    builder.identityVaultDelete(
        ROUTE_IDENTITY_VAULT_GRANT,
        "identity-vault.grants.revoke",
        "Revoke one vault identity grant.");
    builder.get(
        "platform",
        "/platform/contract",
        PlatformApiCapabilities.PLATFORM_CONTRACT_READ,
        PlatformApiCapabilities.PLATFORM_CONTRACT_READ,
        "Read the deterministic Platform API compatibility contract.");
    builder.endpoint(
        new EndpointSpec(
            "queue",
            "GET",
            "/queue/app-document-status",
            "queue.app-document-status",
            List.of("queue.read", "mail.control"),
            25,
            false,
            true,
            false,
            PlatformApiStabilityLevel.EXPERIMENTAL,
            "Read typed completion for one app-namespaced generated document insert."));
    builder.mailEndpoint("command", List.of("mail.control"), true, false);
    builder.mailEndpoint("result", List.of("mail.control"), true, false);
    builder.mailEndpoint("poll", List.of("mail.control"), false, true);
    builder.mailEndpoint("reply", List.of("mail.control"), false, true);
    builder.mailEndpoint(
        "create-identity",
        List.of(
            "vault.identities.create", "vault.mail.sign", "vault.mail.open", "vault.mail.storage"),
        false,
        true);
    builder.mailEndpoint("sign", List.of("vault.mail.sign"), false, true);
    builder.mailEndpoint("open", List.of("vault.mail.open"), false, true);
    builder.mailEndpoint("seal-storage", List.of("vault.mail.storage"), false, true);
    builder.mailEndpoint("open-storage", List.of("vault.mail.storage"), false, true);
    return builder.build();
  }

  private static PlatformApiCapabilityDescriptor capability(String name, String description) {
    return new PlatformApiCapabilityDescriptor(
        name, PlatformApiStabilityLevel.STABLE, INITIAL_CONTRACT_VERSION, null, description);
  }

  private static PlatformApiCapabilityDescriptor experimentalCapability(
      String name, String description) {
    return experimentalCapabilitySince(name, APP_VAULT_CONTRACT_VERSION, description);
  }

  private static PlatformApiCapabilityDescriptor experimentalCapabilitySince(
      String name, int sinceContractVersion, String description) {
    return new PlatformApiCapabilityDescriptor(
        name, PlatformApiStabilityLevel.EXPERIMENTAL, sinceContractVersion, null, description);
  }

  /**
   * Machine-readable Platform API stable app-facing baseline metadata.
   *
   * <p>The baseline name is a semantic app-authoring label such as {@code 1.0}; it is intentionally
   * separate from the integer contract version that changes when the Platform API compatibility
   * metadata changes. Capability names and endpoint identities are sorted and counted so release
   * certification can detect stable removals without depending on local filesystem paths or
   * generated report ordering.
   *
   * @param name stable baseline name, currently {@code 1.0}
   * @param contractVersion contract version whose stable descriptors define this baseline
   * @param capabilityCount number of stable app-facing capabilities in the baseline
   * @param endpointCount number of stable app-facing endpoints in the baseline
   * @param capabilities sorted stable app-facing capability names
   * @param endpoints sorted stable app-facing endpoint identities in {@code METHOD /path} form
   */
  public record StableBaseline(
      String name,
      int contractVersion,
      int capabilityCount,
      int endpointCount,
      List<String> capabilities,
      List<String> endpoints) {
    /** Creates a validated stable-baseline descriptor. */
    public StableBaseline {
      name = requireText(name, "stableBaseline.name");
      if (contractVersion <= 0) {
        throw new IllegalArgumentException("stableBaseline.contractVersion must be positive");
      }
      capabilities = sortedCopy(capabilities, "stableBaseline.capabilities");
      endpoints = sortedCopy(endpoints, "stableBaseline.endpoints");
      if (capabilityCount != capabilities.size()) {
        throw new IllegalArgumentException(
            "stableBaseline.capabilityCount must match capabilities size");
      }
      if (endpointCount != endpoints.size()) {
        throw new IllegalArgumentException(
            "stableBaseline.endpointCount must match endpoints size");
      }
    }

    private static StableBaseline fromDescriptors(
        List<PlatformApiCapabilityDescriptor> capabilities,
        List<PlatformApiEndpointDescriptor> endpoints) {
      List<String> stableCapabilities =
          stableBaselineCapabilityNames(capabilities, endpoints).stream().sorted().toList();
      List<String> stableEndpoints =
          endpoints.stream()
              .filter(PlatformApiContract::isStableBaselineEndpoint)
              .map(PlatformApiContract::endpointIdentity)
              .sorted()
              .toList();
      return new StableBaseline(
          PLATFORM_API_STABLE_BASELINE_NAME,
          PLATFORM_API_STABLE_BASELINE_CONTRACT_VERSION,
          stableCapabilities.size(),
          stableEndpoints.size(),
          stableCapabilities,
          stableEndpoints);
    }

    private static Set<String> stableBaselineCapabilityNames(
        List<PlatformApiCapabilityDescriptor> capabilities,
        List<PlatformApiEndpointDescriptor> endpoints) {
      Set<String> stableCapabilityNames =
          capabilities.stream()
              .filter(PlatformApiContract::isStableBaselineCapability)
              .map(PlatformApiCapabilityDescriptor::name)
              .collect(Collectors.toCollection(TreeSet::new));
      Set<String> baselineNames = new TreeSet<>();
      for (PlatformApiEndpointDescriptor endpoint : endpoints) {
        if (PlatformApiContract.isStableBaselineEndpoint(endpoint)) {
          for (String capability : endpoint.requiredCapabilities()) {
            if (stableCapabilityNames.contains(capability)) {
              baselineNames.add(capability);
            }
          }
        }
      }
      return baselineNames;
    }

    private void requireMatches(StableBaseline expected) {
      if (!equals(expected)) {
        throw new IllegalArgumentException(
            "stableBaseline must match stable app-facing descriptor membership");
      }
    }

    private static List<String> sortedCopy(List<String> values, String fieldName) {
      TreeSet<String> sorted = new TreeSet<>();
      for (String value : Objects.requireNonNull(values, fieldName)) {
        sorted.add(requireText(value, fieldName + " value"));
      }
      return List.copyOf(sorted);
    }
  }

  private static String requireText(String value, String fieldName) {
    String text = Objects.requireNonNull(value, fieldName).trim();
    if (text.isEmpty()) {
      throw new IllegalArgumentException(fieldName + " must not be blank");
    }
    return text;
  }

  private static final class EndpointBuilder {
    private final List<PlatformApiEndpointDescriptor> endpoints = new java.util.ArrayList<>();

    private void get(
        String family,
        String routeTemplate,
        String actionLabel,
        String capability,
        String description) {
      endpoint(
          new EndpointSpec(
              family,
              METHOD_GET,
              routeTemplate,
              actionLabel,
              List.of(capability),
              INITIAL_CONTRACT_VERSION,
              true,
              true,
              description));
    }

    private void supportLifecycleGet() {
      endpoint(
          new EndpointSpec(
              ROUTE_FAMILY_UPDATES,
              METHOD_GET,
              "/updates/support-lifecycle",
              PlatformApiCapabilities.UPDATES_READ,
              List.of(PlatformApiCapabilities.UPDATES_READ),
              SUPPORT_LIFECYCLE_DESCRIPTOR_VERSION,
              true,
              false,
              false,
              PlatformApiStabilityLevel.OPERATOR_ONLY,
              "Read the local authenticated Stable 1.0 support-lifecycle state."));
    }

    private void post(
        String family,
        String routeTemplate,
        String actionLabel,
        List<String> capabilities,
        String description) {
      endpoint(
          new EndpointSpec(
              family,
              METHOD_POST,
              routeTemplate,
              actionLabel,
              capabilities,
              INITIAL_CONTRACT_VERSION,
              true,
              true,
              description));
    }

    private void delete(
        String family,
        String routeTemplate,
        String actionLabel,
        List<String> capabilities,
        String description) {
      endpoint(
          new EndpointSpec(
              family,
              METHOD_DELETE,
              routeTemplate,
              actionLabel,
              capabilities,
              INITIAL_CONTRACT_VERSION,
              true,
              true,
              description));
    }

    private void appVaultGet(
        String routeTemplate,
        String actionLabel,
        List<String> capabilities,
        boolean appBrowserAllowed,
        String description) {
      appVaultEndpoint(
          METHOD_GET, routeTemplate, actionLabel, capabilities, appBrowserAllowed, description);
    }

    private void appVaultPost(
        String routeTemplate,
        String actionLabel,
        List<String> capabilities,
        boolean appBrowserAllowed,
        String description) {
      appVaultEndpoint(
          METHOD_POST, routeTemplate, actionLabel, capabilities, appBrowserAllowed, description);
    }

    private void appVaultPutSecret() {
      appVaultEndpoint(
          METHOD_PUT,
          ROUTE_APP_VAULT_SECRET,
          "app-vault.secrets.write",
          List.of(PlatformApiCapabilities.VAULT_SECRETS_WRITE),
          false,
          "Create or replace one app-owned secret value.");
    }

    private void appVaultDeleteSecret() {
      appVaultEndpoint(
          METHOD_DELETE,
          ROUTE_APP_VAULT_SECRET,
          "app-vault.secrets.delete",
          List.of(PlatformApiCapabilities.VAULT_SECRETS_WRITE),
          false,
          "Delete one app-owned secret without exposing the old value.");
    }

    private void identityVaultGet(String routeTemplate, String actionLabel, String description) {
      identityVaultEndpoint(METHOD_GET, routeTemplate, actionLabel, description);
    }

    private void identityVaultPost(String routeTemplate, String actionLabel, String description) {
      identityVaultEndpoint(METHOD_POST, routeTemplate, actionLabel, description);
    }

    private void identityVaultGrantStatusPatch() {
      identityVaultEndpoint(
          METHOD_PATCH,
          ROUTE_IDENTITY_VAULT_GRANT,
          "identity-vault.grants.status",
          "Change one vault grant status.");
    }

    private void identityVaultDelete(String routeTemplate, String actionLabel, String description) {
      identityVaultEndpoint(METHOD_DELETE, routeTemplate, actionLabel, description);
    }

    private void appUpdateGet(String routeTemplate, String actionLabel, String description) {
      endpoint(
          new EndpointSpec(
              ROUTE_FAMILY_APPS,
              METHOD_GET,
              routeTemplate,
              actionLabel,
              List.of(PlatformApiCapabilities.APPS_READ),
              APP_UPDATE_LIFECYCLE_CONTRACT_VERSION,
              true,
              true,
              description));
    }

    private void appUpdatePost(
        String routeTemplate, String actionLabel, List<String> capabilities, String description) {
      endpoint(
          new EndpointSpec(
              ROUTE_FAMILY_APPS,
              METHOD_POST,
              routeTemplate,
              actionLabel,
              capabilities,
              APP_UPDATE_LIFECYCLE_CONTRACT_VERSION,
              true,
              true,
              description));
    }

    private void appUpdatePolicyPost() {
      endpoint(
          new EndpointSpec(
              ROUTE_FAMILY_APPS,
              METHOD_POST,
              "/apps/{appId}/updates/policy",
              "apps.updates.policy",
              List.of(PlatformApiCapabilities.APPS_MANAGE),
              APP_UPDATE_LIFECYCLE_CONTRACT_VERSION,
              false,
              false,
              "Update the local app update policy."));
    }

    private void appCatalogRecommendationGet() {
      endpoint(
          new EndpointSpec(
              ROUTE_FAMILY_APP_CATALOGS,
              METHOD_GET,
              "/app-catalogs/recommended",
              "catalogs.recommended.list",
              List.of(PlatformApiCapabilities.CATALOGS_READ),
              RECOMMENDED_CATALOG_CONTRACT_VERSION,
              true,
              true,
              "List recommended app catalogs for operator onboarding."));
    }

    private void appCatalogRecommendationPost() {
      endpoint(
          new EndpointSpec(
              ROUTE_FAMILY_APP_CATALOGS,
              METHOD_POST,
              "/app-catalogs/recommended/{catalogId}/add",
              "catalogs.recommended.add",
              List.of(PlatformApiCapabilities.CATALOGS_MANAGE),
              RECOMMENDED_CATALOG_CONTRACT_VERSION,
              true,
              true,
              "Add one recommended signed catalog source."));
    }

    private void catalogOperations() {
      catalogOperationEndpoint(
          METHOD_GET,
          "/app-catalogs/{catalogId}/mirrors",
          "catalogs.mirrors.list",
          List.of(PlatformApiCapabilities.CATALOGS_READ),
          "List redacted mirror endpoints for one signed catalog.");
      catalogOperationEndpoint(
          METHOD_POST,
          "/app-catalogs/{catalogId}/mirrors",
          "catalogs.mirrors.add",
          List.of(PlatformApiCapabilities.CATALOGS_MANAGE),
          "Add one mirror transport endpoint to a signed catalog.");
      catalogOperationEndpoint(
          METHOD_POST,
          "/app-catalogs/{catalogId}/mirrors/{mirrorId}",
          "catalogs.mirrors.update",
          List.of(PlatformApiCapabilities.CATALOGS_MANAGE),
          "Update one mirror transport endpoint.");
      catalogOperationEndpoint(
          METHOD_DELETE,
          "/app-catalogs/{catalogId}/mirrors/{mirrorId}",
          "catalogs.mirrors.remove",
          List.of(PlatformApiCapabilities.CATALOGS_MANAGE),
          "Remove one mirror transport endpoint.");
      catalogOperationEndpoint(
          METHOD_GET,
          "/app-catalogs/{catalogId}/operations/health",
          "catalogs.operations.health",
          List.of(PlatformApiCapabilities.CATALOGS_READ),
          "Read primary and mirror health for one signed catalog.");
      catalogOperationEndpoint(
          METHOD_GET,
          "/app-catalogs/{catalogId}/operations/revisions",
          "catalogs.operations.revisions",
          List.of(PlatformApiCapabilities.CATALOGS_READ),
          "List retained verified revisions and rollback eligibility.");
      catalogOperationEndpoint(
          METHOD_GET,
          "/app-catalogs/{catalogId}/operations/key-rotation",
          "catalogs.operations.key-rotation",
          List.of(PlatformApiCapabilities.CATALOGS_READ),
          "Read operator-safe catalog signing-key rotation status.");
      catalogOperationEndpoint(
          METHOD_POST,
          "/app-catalogs/{catalogId}/operations/refresh-primary",
          "catalogs.operations.refresh-primary",
          List.of(PlatformApiCapabilities.CATALOGS_MANAGE),
          "Refresh only the primary catalog source.");
      catalogOperationEndpoint(
          METHOD_POST,
          "/app-catalogs/{catalogId}/operations/rollback",
          "catalogs.operations.rollback",
          List.of(PlatformApiCapabilities.CATALOGS_MANAGE),
          "Roll back to a retained verified catalog revision.");
      catalogOperationEndpoint(
          METHOD_POST,
          "/app-catalogs/{catalogId}/operations/emergency-refresh",
          "catalogs.operations.emergency-refresh",
          List.of(PlatformApiCapabilities.CATALOGS_MANAGE),
          "Run an immediate signed catalog refresh for advisory propagation.");
    }

    private void catalogOperationEndpoint(
        String method,
        String routeTemplate,
        String actionLabel,
        List<String> capabilities,
        String description) {
      endpoint(
          new EndpointSpec(
              ROUTE_FAMILY_APP_CATALOGS,
              method,
              routeTemplate,
              actionLabel,
              capabilities,
              CATALOG_OPERATIONS_CONTRACT_VERSION,
              true,
              false,
              false,
              PlatformApiStabilityLevel.OPERATOR_ONLY,
              description));
    }

    private void queueAppDocumentPost() {
      endpoint(
          new EndpointSpec(
              ROUTE_FAMILY_QUEUE,
              METHOD_POST,
              "/queue/inserts/app-document",
              "queue.inserts.app-document",
              List.of(
                  PlatformApiCapabilities.CONTENT_INSERT_APP_DOCUMENT,
                  PlatformApiCapabilities.QUEUE_WRITE),
              PROFILE_PUBLISHING_CONTRACT_VERSION,
              false,
              true,
              true,
              PlatformApiStabilityLevel.STABLE,
              "Create a bounded app-generated document insert request."));
    }

    private void contentFetchPost() {
      endpoint(
          new EndpointSpec(
              ROUTE_FAMILY_CONTENT,
              METHOD_POST,
              "/content/fetch",
              "content.fetch",
              List.of(PlatformApiCapabilities.CONTENT_FETCH),
              CONTENT_FETCH_CONTRACT_VERSION,
              true,
              true,
              "Fetch one bounded Crypta content document."));
    }

    private void contentSubscriptionEndpoints() {
      contentSubscriptionEndpoint(
          METHOD_GET,
          "/content/subscriptions",
          "content.subscriptions.list",
          List.of(PlatformApiCapabilities.CONTENT_SUBSCRIBE),
          "List app-owned USK content subscriptions.");
      contentSubscriptionEndpoint(
          METHOD_POST,
          "/content/subscriptions",
          "content.subscriptions.create",
          List.of(PlatformApiCapabilities.CONTENT_FETCH, PlatformApiCapabilities.CONTENT_SUBSCRIBE),
          "Create one app-owned bounded USK content subscription.");
      contentSubscriptionEndpoint(
          METHOD_GET,
          "/content/subscriptions/{subscriptionId}",
          "content.subscriptions.read",
          List.of(PlatformApiCapabilities.CONTENT_SUBSCRIBE),
          "Read one app-owned USK content subscription.");
      contentSubscriptionEndpoint(
          METHOD_POST,
          "/content/subscriptions/{subscriptionId}/refresh",
          "content.subscriptions.refresh",
          List.of(PlatformApiCapabilities.CONTENT_FETCH, PlatformApiCapabilities.CONTENT_SUBSCRIBE),
          "Refresh one app-owned USK content subscription.");
      contentSubscriptionEndpoint(
          METHOD_POST,
          "/content/subscriptions/{subscriptionId}/pause",
          "content.subscriptions.pause",
          List.of(PlatformApiCapabilities.CONTENT_SUBSCRIBE),
          "Pause one app-owned USK content subscription.");
      contentSubscriptionEndpoint(
          METHOD_POST,
          "/content/subscriptions/{subscriptionId}/resume",
          "content.subscriptions.resume",
          List.of(PlatformApiCapabilities.CONTENT_SUBSCRIBE),
          "Resume one app-owned USK content subscription.");
      contentSubscriptionEndpoint(
          METHOD_DELETE,
          "/content/subscriptions/{subscriptionId}",
          "content.subscriptions.delete",
          List.of(PlatformApiCapabilities.CONTENT_SUBSCRIBE),
          "Delete one app-owned USK content subscription.");
    }

    private void contentSubscriptionEndpoint(
        String method,
        String routeTemplate,
        String actionLabel,
        List<String> capabilities,
        String description) {
      endpoint(
          new EndpointSpec(
              ROUTE_FAMILY_CONTENT,
              method,
              routeTemplate,
              actionLabel,
              capabilities,
              CONTENT_SUBSCRIPTIONS_CONTRACT_VERSION,
              false,
              true,
              true,
              PlatformApiStabilityLevel.STABLE,
              description));
    }

    private void appDataEndpoints() {
      appDataEndpoint(
          METHOD_GET,
          "/app-data/status",
          "app-data.status",
          List.of(PlatformApiCapabilities.APP_DATA_READ),
          "Read durable app-data status, limits, and sanitized quota state.");
      appDataEndpoint(
          METHOD_GET,
          "/app-data/namespaces",
          "app-data.namespaces.list",
          List.of(PlatformApiCapabilities.APP_DATA_READ),
          "List durable app-data namespace metadata.");
      appDataEndpoint(
          METHOD_GET,
          "/app-data/namespaces/{namespace}",
          "app-data.namespaces.read",
          List.of(PlatformApiCapabilities.APP_DATA_READ),
          "Read one durable app-data namespace metadata record.");
      appDataEndpoint(
          METHOD_POST,
          "/app-data/namespaces/{namespace}/schema",
          "app-data.namespaces.schema",
          List.of(PlatformApiCapabilities.APP_DATA_WRITE),
          "Record one durable app-data schema migration metadata entry.");
      appDataEndpoint(
          METHOD_DELETE,
          "/app-data/namespaces/{namespace}",
          "app-data.namespaces.delete",
          List.of(PlatformApiCapabilities.APP_DATA_WRITE),
          "Delete one app-owned durable data namespace.");
      appDataEndpoint(
          METHOD_GET,
          "/app-data/records",
          "app-data.records.list",
          List.of(PlatformApiCapabilities.APP_DATA_READ),
          "List bounded durable app-data record summaries.");
      appDataEndpoint(
          METHOD_GET,
          "/app-data/records/{namespace}/{key}",
          "app-data.records.read",
          List.of(PlatformApiCapabilities.APP_DATA_READ),
          "Read one bounded durable app-data record.");
      appDataEndpoint(
          METHOD_POST,
          "/app-data/records",
          "app-data.records.write",
          List.of(PlatformApiCapabilities.APP_DATA_WRITE),
          "Create or replace one bounded durable app-data record.");
      appDataEndpoint(
          METHOD_DELETE,
          "/app-data/records/{namespace}/{key}",
          "app-data.records.delete",
          List.of(PlatformApiCapabilities.APP_DATA_WRITE),
          "Delete one bounded durable app-data record.");
      appDataEndpoint(
          METHOD_GET,
          "/app-data/export",
          "app-data.export",
          List.of(PlatformApiCapabilities.APP_DATA_READ),
          "Export bounded app-owned durable data for backup or migration.");
      appDataEndpoint(
          METHOD_POST,
          "/app-data/import",
          "app-data.import",
          List.of(PlatformApiCapabilities.APP_DATA_WRITE),
          "Import bounded app-owned durable data from a structured export payload.");
    }

    private void appDataEndpoint(
        String method,
        String routeTemplate,
        String actionLabel,
        List<String> capabilities,
        String description) {
      endpoint(
          new EndpointSpec(
              ROUTE_FAMILY_APP_DATA,
              method,
              routeTemplate,
              actionLabel,
              capabilities,
              APP_DATA_STORE_CONTRACT_VERSION,
              false,
              true,
              true,
              PlatformApiStabilityLevel.STABLE,
              description));
    }

    private void appServiceEndpoints() {
      appServiceEndpoint(
          new AppServiceEndpointSpec(
              METHOD_GET,
              "/app-services",
              "app-services.list",
              List.of(PlatformApiCapabilities.APP_SERVICES_READ),
              EndpointAccess.HOST_AND_APP_PRINCIPALS,
              "List advertised local app services and manifest-declared service requests."));
      appServiceEndpoint(
          new AppServiceEndpointSpec(
              METHOD_GET,
              "/app-services/audit",
              "app-services.audit",
              List.of(),
              EndpointAccess.HOST_OPERATOR_ONLY,
              "List recent redacted app-service grant and invocation audit events."));
      appServiceEndpoint(
          new AppServiceEndpointSpec(
              METHOD_GET,
              "/app-services/grants",
              "app-services.grants.list",
              List.of(PlatformApiCapabilities.APP_SERVICES_READ),
              EndpointAccess.HOST_AND_APP_PRINCIPALS,
              "List app-service grants visible to the caller."));
      appServiceEndpoint(
          new AppServiceEndpointSpec(
              METHOD_GET,
              "/app-services/dependencies",
              "app-services.dependencies.list",
              List.of(PlatformApiCapabilities.APP_SERVICES_READ),
              APP_SERVICE_DEPENDENCY_BUNDLES_CONTRACT_VERSION,
              EndpointAccess.HOST_AND_APP_PRINCIPALS,
              "List the caller-visible app-service dependency graph."));
      appServiceEndpoint(
          new AppServiceEndpointSpec(
              METHOD_GET,
              "/app-services/dependencies/consumers/{consumerAppId}",
              "app-services.dependencies.read",
              List.of(PlatformApiCapabilities.APP_SERVICES_READ),
              APP_SERVICE_DEPENDENCY_BUNDLES_CONTRACT_VERSION,
              EndpointAccess.HOST_AND_APP_PRINCIPALS,
              "Read dependency graph metadata for one consumer app."));
      appServiceEndpoint(
          new AppServiceEndpointSpec(
              METHOD_GET,
              "/app-services/grant-bundles",
              "app-services.grant-bundles.list",
              List.of(PlatformApiCapabilities.APP_SERVICES_READ),
              APP_SERVICE_DEPENDENCY_BUNDLES_CONTRACT_VERSION,
              EndpointAccess.HOST_AND_APP_PRINCIPALS,
              "List grant-bundle proposals visible to the caller."));
      appServiceEndpoint(
          new AppServiceEndpointSpec(
              METHOD_POST,
              "/app-services/grant-bundles",
              "app-services.grant-bundles.request",
              List.of(PlatformApiCapabilities.APP_SERVICES_CALL),
              APP_SERVICE_DEPENDENCY_BUNDLES_CONTRACT_VERSION,
              EndpointAccess.HOST_AND_APP_PRINCIPALS,
              "Request an operator-reviewed grant bundle for declared dependencies."));
      appServiceEndpoint(
          new AppServiceEndpointSpec(
              METHOD_POST,
              "/app-services/grant-bundles/{bundleId}/approve",
              "app-services.grant-bundles.approve",
              List.of(),
              APP_SERVICE_DEPENDENCY_BUNDLES_CONTRACT_VERSION,
              EndpointAccess.HOST_OPERATOR_ONLY,
              "Approve one pending app-service grant bundle."));
      appServiceEndpoint(
          new AppServiceEndpointSpec(
              METHOD_POST,
              "/app-services/grant-bundles/{bundleId}/reject",
              "app-services.grant-bundles.reject",
              List.of(),
              APP_SERVICE_DEPENDENCY_BUNDLES_CONTRACT_VERSION,
              EndpointAccess.HOST_OPERATOR_ONLY,
              "Reject one pending app-service grant bundle."));
      appServiceEndpoint(
          new AppServiceEndpointSpec(
              METHOD_POST,
              "/app-services/grant-bundles/{bundleId}/renew",
              "app-services.grant-bundles.renew",
              List.of(),
              APP_SERVICE_DEPENDENCY_BUNDLES_CONTRACT_VERSION,
              EndpointAccess.HOST_OPERATOR_ONLY,
              "Renew or revalidate one approved app-service grant bundle."));
      appServiceEndpoint(
          new AppServiceEndpointSpec(
              METHOD_POST,
              "/app-services/grants",
              "app-services.grants.request",
              List.of(PlatformApiCapabilities.APP_SERVICES_CALL),
              EndpointAccess.APP_PRINCIPALS_ONLY,
              "Request an operator-approved local app-service grant."));
      appServiceEndpoint(
          new AppServiceEndpointSpec(
              METHOD_POST,
              "/app-services/grants/{grantId}/approve",
              "app-services.grants.approve",
              List.of(),
              EndpointAccess.HOST_OPERATOR_ONLY,
              "Approve one pending app-service grant."));
      appServiceEndpoint(
          new AppServiceEndpointSpec(
              METHOD_POST,
              "/app-services/grants/{grantId}/revoke",
              "app-services.grants.revoke",
              List.of(PlatformApiCapabilities.APP_SERVICES_CALL),
              EndpointAccess.HOST_AND_APP_PRINCIPALS,
              "Revoke one app-service grant."));
      appServiceEndpoint(
          new AppServiceEndpointSpec(
              METHOD_GET,
              "/app-services/{providerAppId}/services",
              "app-services.provider.list",
              List.of(PlatformApiCapabilities.APP_SERVICES_READ),
              EndpointAccess.HOST_AND_APP_PRINCIPALS,
              "List services advertised by one installed provider app."));
      appServiceEndpoint(
          new AppServiceEndpointSpec(
              METHOD_GET,
              "/app-services/{providerAppId}/services/{serviceId}",
              "app-services.provider.read",
              List.of(PlatformApiCapabilities.APP_SERVICES_READ),
              EndpointAccess.HOST_AND_APP_PRINCIPALS,
              "Read one advertised local app-service descriptor."));
      appServiceEndpoint(
          new AppServiceEndpointSpec(
              METHOD_POST,
              "/app-services/{providerAppId}/services/{serviceId}/invoke",
              "app-services.invoke",
              List.of(PlatformApiCapabilities.APP_SERVICES_CALL),
              EndpointAccess.APP_PRINCIPALS_ONLY,
              "Invoke one bounded local app service through an active grant."));
    }

    private void consentEndpoints() {
      consentEndpoint(
          METHOD_GET,
          "/consent/install-preview",
          "consent.install-preview",
          "Preview material install consent for a catalog app.");
      consentEndpoint(
          METHOD_GET,
          "/consent/update-preview",
          "consent.update-preview.read",
          "Read a material update consent preview without refreshing catalogs.");
      consentEndpoint(
          METHOD_POST,
          "/consent/update-preview",
          "consent.update-preview.refresh",
          "Refresh catalogs and preview material update consent.");
      consentEndpoint(
          METHOD_GET,
          "/consent/catalog-update-preview",
          "consent.catalog-update-preview",
          "Preview catalog-backed update consent for a catalog app.");
      consentEndpoint(
          METHOD_GET,
          "/consent/service-grant-preview",
          "consent.service-grant-preview",
          "Preview material consent for one app-service grant bundle.");
      consentEndpoint(
          METHOD_POST,
          "/consent/approve",
          "consent.approve",
          "Approve one digest-bound consent request.");
      consentEndpoint(
          METHOD_POST,
          "/consent/reject",
          "consent.reject",
          "Reject one digest-bound consent request.");
      consentEndpoint(
          METHOD_POST,
          "/consent/defer",
          "consent.defer",
          "Defer one digest-bound consent request.");
      consentEndpoint(
          METHOD_GET,
          "/consent/audit",
          "consent.audit",
          "List recent redacted consent audit events.");
    }

    private void appServiceEndpoint(AppServiceEndpointSpec spec) {
      endpoint(
          new EndpointSpec(
              ROUTE_FAMILY_APP_SERVICES,
              spec.method(),
              spec.routeTemplate(),
              spec.actionLabel(),
              spec.capabilities(),
              spec.sinceContractVersion(),
              spec.access().hostOperatorBypassAllowed(),
              spec.access().appProcessAllowed(),
              spec.access().appBrowserAllowed(),
              spec.access().equals(EndpointAccess.HOST_OPERATOR_ONLY)
                  ? PlatformApiStabilityLevel.OPERATOR_ONLY
                  : PlatformApiStabilityLevel.EXPERIMENTAL,
              spec.description()));
    }

    private void consentEndpoint(
        String method, String routeTemplate, String actionLabel, String description) {
      endpoint(
          new EndpointSpec(
              ROUTE_FAMILY_CONSENT,
              method,
              routeTemplate,
              actionLabel,
              List.of(),
              CONSENT_CONTRACT_VERSION,
              true,
              false,
              false,
              PlatformApiStabilityLevel.OPERATOR_ONLY,
              description));
    }

    private void trustGraphPreviewEndpoints() {
      trustGraphGet(
          "/trust-graph/status", "trust-graph.status", "Read local Trust Graph Preview status.");
      trustGraphGet(
          "/trust-graph/anchors",
          "trust-graph.anchors.list",
          "List local Trust Graph Preview anchors.");
      trustGraphPost(
          "/trust-graph/anchors",
          "trust-graph.anchors.add",
          List.of(PlatformApiCapabilities.TRUST_WRITE),
          "Add or replace one local Trust Graph Preview anchor.");
      trustGraphAnchorDelete();
      trustGraphPost(
          "/trust-graph/import",
          "trust-graph.import",
          List.of(PlatformApiCapabilities.TRUST_WRITE),
          "Import one bounded trust statement into the local preview store.");
      trustGraphImportPreviewPost();
      trustGraphImportPreviewUriPost();
      trustGraphImportUriPost();
      trustGraphAuditGet();
      trustGraphGet(
          "/trust-graph/subjects",
          "trust-graph.subjects",
          "List subjects with imported trust statements.");
      trustGraphGet(
          "/trust-graph/statements",
          "trust-graph.statements",
          "List redacted imported trust statement summaries.");
      trustGraphStatementGet();
      trustGraphLifecyclePost(
          "/trust-graph/statements/{fingerprint}/deprecate",
          "trust-graph.statements.deprecate",
          "Mark one imported statement deprecated in local lifecycle policy.");
      trustGraphLifecyclePost(
          "/trust-graph/statements/{fingerprint}/revoke",
          "trust-graph.statements.revoke",
          "Mark one imported statement revoked in local lifecycle policy.");
      trustGraphLifecyclePost(
          "/trust-graph/statements/{fingerprint}/reactivate",
          "trust-graph.statements.reactivate",
          "Reactivate one imported statement in local lifecycle policy.");
      trustGraphAnchorLifecyclePost(
          "/trust-graph/anchors/{fingerprint}/deprecate",
          "trust-graph.anchors.deprecate",
          "Mark one local anchor deprecated in local lifecycle policy.");
      trustGraphAnchorLifecyclePost(
          "/trust-graph/anchors/{fingerprint}/revoke",
          "trust-graph.anchors.revoke",
          "Mark one local anchor revoked in local lifecycle policy.");
      trustGraphAnchorLifecyclePost(
          "/trust-graph/anchors/{fingerprint}/reactivate",
          "trust-graph.anchors.reactivate",
          "Reactivate one local anchor in local lifecycle policy.");
      trustGraphGet(
          "/trust-graph/score",
          "trust-graph.score",
          "Read a deterministic local Trust Graph Preview score.");
    }

    private void appVaultProfileDocumentPost() {
      endpoint(
          new EndpointSpec(
              ROUTE_FAMILY_APP_VAULT,
              METHOD_POST,
              "/app-vault/identities/{identityId}/profile-document",
              "app-vault.identities.profile-document",
              List.of(
                  PlatformApiCapabilities.VAULT_IDENTITIES_READ,
                  PlatformApiCapabilities.VAULT_IDENTITIES_USE),
              PROFILE_PUBLISHING_CONTRACT_VERSION,
              false,
              true,
              true,
              PlatformApiStabilityLevel.EXPERIMENTAL,
              "Create a signed bounded profile document for one app-visible vault identity."));
    }

    private void appVaultTrustStatementPost() {
      endpoint(
          new EndpointSpec(
              ROUTE_FAMILY_APP_VAULT,
              METHOD_POST,
              "/app-vault/identities/{identityId}/trust-statement",
              "app-vault.identities.trust-statement",
              List.of(
                  PlatformApiCapabilities.TRUST_WRITE,
                  PlatformApiCapabilities.VAULT_IDENTITIES_READ,
                  PlatformApiCapabilities.VAULT_IDENTITIES_USE),
              TRUST_GRAPH_PREVIEW_CONTRACT_VERSION,
              false,
              true,
              true,
              PlatformApiStabilityLevel.EXPERIMENTAL,
              "Create a signed bounded trust statement for one app-visible vault identity."));
    }

    private void appVaultSocialMessagePost() {
      endpoint(
          new EndpointSpec(
              ROUTE_FAMILY_APP_VAULT,
              METHOD_POST,
              "/app-vault/identities/{identityId}/social-message",
              "app-vault.identities.social-message",
              List.of(
                  PlatformApiCapabilities.VAULT_IDENTITIES_READ,
                  PlatformApiCapabilities.VAULT_IDENTITIES_USE),
              SOCIAL_MESSAGE_CONTRACT_VERSION,
              false,
              true,
              true,
              PlatformApiStabilityLevel.EXPERIMENTAL,
              "Create a signed bounded social message for one app-visible vault identity."));
    }

    private void endpoint(EndpointSpec spec) {
      endpoints.add(
          new PlatformApiEndpointDescriptor(
              spec.family(),
              spec.method(),
              spec.routeTemplate(),
              spec.actionLabel(),
              spec.capabilities(),
              spec.hostOperatorBypassAllowed(),
              spec.appProcessAllowed(),
              spec.appBrowserAllowed(),
              spec.stability(),
              spec.sinceContractVersion(),
              null,
              spec.description()));
    }

    private void trustGraphGet(String routeTemplate, String actionLabel, String description) {
      endpoint(
          new EndpointSpec(
              ROUTE_FAMILY_TRUST_GRAPH,
              METHOD_GET,
              routeTemplate,
              actionLabel,
              List.of(PlatformApiCapabilities.TRUST_READ),
              TRUST_GRAPH_PREVIEW_CONTRACT_VERSION,
              true,
              true,
              true,
              PlatformApiStabilityLevel.EXPERIMENTAL,
              description));
    }

    private void trustGraphStatementGet() {
      endpoint(
          new EndpointSpec(
              ROUTE_FAMILY_TRUST_GRAPH,
              METHOD_GET,
              "/trust-graph/statements/{fingerprint}",
              "trust-graph.statements.get",
              List.of(PlatformApiCapabilities.TRUST_READ),
              TRUST_GRAPH_RC_SCOPE_CONTRACT_VERSION,
              true,
              true,
              true,
              PlatformApiStabilityLevel.EXPERIMENTAL,
              "Read one redacted local Trust Graph RC statement summary."));
    }

    private void trustGraphPost(
        String routeTemplate, String actionLabel, List<String> capabilities, String description) {
      endpoint(
          new EndpointSpec(
              ROUTE_FAMILY_TRUST_GRAPH,
              METHOD_POST,
              routeTemplate,
              actionLabel,
              capabilities,
              TRUST_GRAPH_PREVIEW_CONTRACT_VERSION,
              true,
              true,
              true,
              PlatformApiStabilityLevel.EXPERIMENTAL,
              description));
    }

    private void trustGraphLifecyclePost(
        String routeTemplate, String actionLabel, String description) {
      endpoint(
          new EndpointSpec(
              ROUTE_FAMILY_TRUST_GRAPH,
              METHOD_POST,
              routeTemplate,
              actionLabel,
              List.of(PlatformApiCapabilities.TRUST_WRITE),
              TRUST_GRAPH_RC_SCOPE_CONTRACT_VERSION,
              true,
              true,
              true,
              PlatformApiStabilityLevel.EXPERIMENTAL,
              description));
    }

    private void trustGraphAnchorLifecyclePost(
        String routeTemplate, String actionLabel, String description) {
      endpoint(
          new EndpointSpec(
              ROUTE_FAMILY_TRUST_GRAPH,
              METHOD_POST,
              routeTemplate,
              actionLabel,
              List.of(PlatformApiCapabilities.TRUST_WRITE),
              TRUST_GRAPH_BETA_HARDENING_CONTRACT_VERSION,
              true,
              true,
              true,
              PlatformApiStabilityLevel.EXPERIMENTAL,
              description));
    }

    private void trustGraphAuditGet() {
      endpoint(
          new EndpointSpec(
              ROUTE_FAMILY_TRUST_GRAPH,
              METHOD_GET,
              "/trust-graph/audit",
              "trust-graph.audit",
              List.of(PlatformApiCapabilities.TRUST_READ),
              TRUST_GRAPH_EXCHANGE_CONTRACT_VERSION,
              true,
              true,
              true,
              PlatformApiStabilityLevel.EXPERIMENTAL,
              "List recent redacted Trust Graph Preview audit events."));
    }

    private void trustGraphImportUriPost() {
      endpoint(
          new EndpointSpec(
              ROUTE_FAMILY_TRUST_GRAPH,
              METHOD_POST,
              "/trust-graph/import-uri",
              "trust-graph.import-uri",
              List.of(PlatformApiCapabilities.CONTENT_FETCH, PlatformApiCapabilities.TRUST_WRITE),
              TRUST_GRAPH_EXCHANGE_CONTRACT_VERSION,
              true,
              true,
              true,
              PlatformApiStabilityLevel.EXPERIMENTAL,
              "Fetch, optionally preview-bind, and import one bounded trust statement from a Crypta"
                  + " content URI."));
    }

    private void trustGraphImportPreviewPost() {
      endpoint(
          new EndpointSpec(
              ROUTE_FAMILY_TRUST_GRAPH,
              METHOD_POST,
              "/trust-graph/import-preview",
              "trust-graph.import-preview",
              List.of(PlatformApiCapabilities.TRUST_WRITE),
              TRUST_GRAPH_BETA_HARDENING_CONTRACT_VERSION,
              true,
              true,
              true,
              PlatformApiStabilityLevel.EXPERIMENTAL,
              "Preview one bounded pasted trust statement import without mutating local graph"
                  + " state."));
    }

    private void trustGraphImportPreviewUriPost() {
      endpoint(
          new EndpointSpec(
              ROUTE_FAMILY_TRUST_GRAPH,
              METHOD_POST,
              "/trust-graph/import-preview-uri",
              "trust-graph.import-preview-uri",
              List.of(PlatformApiCapabilities.CONTENT_FETCH, PlatformApiCapabilities.TRUST_WRITE),
              TRUST_GRAPH_BETA_HARDENING_CONTRACT_VERSION,
              true,
              true,
              true,
              PlatformApiStabilityLevel.EXPERIMENTAL,
              "Fetch and preview one bounded trust statement import from a Crypta content URI"
                  + " without mutating local graph state."));
    }

    private void trustGraphAnchorDelete() {
      endpoint(
          new EndpointSpec(
              ROUTE_FAMILY_TRUST_GRAPH,
              METHOD_DELETE,
              "/trust-graph/anchors/{fingerprint}",
              "trust-graph.anchors.remove",
              List.of(PlatformApiCapabilities.TRUST_WRITE),
              TRUST_GRAPH_PREVIEW_CONTRACT_VERSION,
              true,
              true,
              true,
              PlatformApiStabilityLevel.EXPERIMENTAL,
              "Remove one local Trust Graph Preview anchor."));
    }

    private void appVaultEndpoint(
        String method,
        String routeTemplate,
        String actionLabel,
        List<String> capabilities,
        boolean appBrowserAllowed,
        String description) {
      endpoint(
          new EndpointSpec(
              ROUTE_FAMILY_APP_VAULT,
              method,
              routeTemplate,
              actionLabel,
              capabilities,
              APP_VAULT_CONTRACT_VERSION,
              false,
              true,
              appBrowserAllowed,
              PlatformApiStabilityLevel.EXPERIMENTAL,
              description));
    }

    private void identityVaultEndpoint(
        String method, String routeTemplate, String actionLabel, String description) {
      endpoint(
          new EndpointSpec(
              ROUTE_FAMILY_IDENTITY_VAULT,
              method,
              routeTemplate,
              actionLabel,
              List.of(PlatformApiCapabilities.VAULT_IDENTITIES_MANAGE),
              APP_VAULT_CONTRACT_VERSION,
              true,
              false,
              false,
              PlatformApiStabilityLevel.OPERATOR_ONLY,
              description));
    }

    private void mailEndpoint(
        String action, List<String> capabilities, boolean browser, boolean process) {
      endpoint(
          new EndpointSpec(
              "mail",
              "POST",
              "/mail/" + action,
              "mail." + action,
              capabilities,
              25,
              false,
              process,
              browser,
              PlatformApiStabilityLevel.EXPERIMENTAL,
              "Fixed experimental own-app Mail operation."));
    }

    private List<PlatformApiEndpointDescriptor> build() {
      return List.copyOf(endpoints);
    }
  }

  private record AppServiceEndpointSpec(
      String method,
      String routeTemplate,
      String actionLabel,
      List<String> capabilities,
      int sinceContractVersion,
      EndpointAccess access,
      String description) {
    private AppServiceEndpointSpec(
        String method,
        String routeTemplate,
        String actionLabel,
        List<String> capabilities,
        EndpointAccess access,
        String description) {
      this(
          method,
          routeTemplate,
          actionLabel,
          capabilities,
          APP_SERVICES_CONTRACT_VERSION,
          access,
          description);
    }

    private AppServiceEndpointSpec {
      capabilities = List.copyOf(capabilities);
      Objects.requireNonNull(access, "access");
    }
  }

  private record EndpointAccess(
      boolean hostOperatorBypassAllowed, boolean appProcessAllowed, boolean appBrowserAllowed) {
    private static final EndpointAccess APP_PRINCIPALS_ONLY = new EndpointAccess(false, true, true);
    private static final EndpointAccess HOST_AND_APP_PRINCIPALS =
        new EndpointAccess(true, true, true);
    private static final EndpointAccess HOST_OPERATOR_ONLY = new EndpointAccess(true, false, false);
  }

  private record EndpointSpec(
      String family,
      String method,
      String routeTemplate,
      String actionLabel,
      List<String> capabilities,
      int sinceContractVersion,
      boolean hostOperatorBypassAllowed,
      boolean appProcessAllowed,
      boolean appBrowserAllowed,
      PlatformApiStabilityLevel stability,
      String description) {
    private EndpointSpec(
        String family,
        String method,
        String routeTemplate,
        String actionLabel,
        List<String> capabilities,
        int sinceContractVersion,
        boolean appProcessAllowed,
        boolean appBrowserAllowed,
        String description) {
      this(
          family,
          method,
          routeTemplate,
          actionLabel,
          capabilities,
          sinceContractVersion,
          true,
          appProcessAllowed,
          appBrowserAllowed,
          PlatformApiStabilityLevel.STABLE,
          description);
    }

    private EndpointSpec {
      capabilities = List.copyOf(capabilities);
      Objects.requireNonNull(stability, "stability");
    }
  }
}
