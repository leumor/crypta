package network.crypta.platform.api;

import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class PlatformApiCapabilitiesTest {
  @Test
  void authorize_whenHostOperatorRequest_expectAllowedWithoutCapabilities() {
    PlatformApiAuthorizationDecision decision =
        PlatformApiCapabilities.authorize(
            new PlatformApiRequest("POST", List.of("config", "persist"), Map.of()));

    assertTrue(decision.allowed());
    assertEquals("host_operator", decision.reasonCode());
  }

  @Test
  void knownCapabilities_whenReadByDeveloperTooling_expectSortedRegistry() {
    assertEquals(
        List.of(
            "alerts.read",
            "alerts.write",
            "app.data.read",
            "app.data.write",
            "app.services.call",
            "app.services.read",
            "apps.manage",
            "apps.read",
            "catalogs.manage",
            "catalogs.read",
            "config.read",
            "config.write",
            "connectivity.read",
            "content.fetch",
            "content.insert",
            "content.insert.app-document",
            "content.subscribe",
            "diagnostics.read",
            "mail.control",
            "node.read",
            "peers.read",
            "peers.write",
            "platform.contract.read",
            "queue.read",
            "queue.write",
            "security.read",
            "security.write",
            "trust.read",
            "trust.write",
            "updates.read",
            "updates.write",
            "vault.identities.create",
            "vault.identities.manage",
            "vault.identities.read",
            "vault.identities.use",
            "vault.mail.open",
            "vault.mail.sign",
            "vault.mail.storage",
            "vault.secrets.read",
            "vault.secrets.write",
            "wizard.read",
            "wizard.write"),
        List.copyOf(PlatformApiCapabilityRegistry.knownCapabilities()));
  }

  @Test
  void knownCapabilities_whenCallerMutatesRegistry_expectUnsupportedOperation() {
    Set<String> knownCapabilities = PlatformApiCapabilityRegistry.knownCapabilities();
    Iterator<String> iterator = knownCapabilities.iterator();

    assertTrue(iterator.hasNext());
    assertThrows(UnsupportedOperationException.class, iterator::remove);
  }

  @Test
  void authorize_whenAppHasReadCapability_expectRepresentativeReadAllowed() {
    PlatformApiAuthorizationDecision decision =
        PlatformApiCapabilities.authorize(
            appRequest("GET", List.of("queue"), List.of("queue.read")));

    assertTrue(decision.allowed());
    assertEquals(List.of("queue.read"), decision.action().requiredCapabilities());
  }

  @Test
  void authorize_whenBrowserAppHasReadCapability_expectRepresentativeReadAllowed() {
    PlatformApiAuthorizationDecision decision =
        PlatformApiCapabilities.authorize(
            browserAppRequest("GET", List.of("queue"), List.of("queue.read")));

    assertTrue(decision.allowed());
    assertEquals(List.of("queue.read"), decision.action().requiredCapabilities());
  }

  @Test
  void authorize_whenBrowserAppLacksPeerWriteCapability_expectDenied() {
    PlatformApiAuthorizationDecision decision =
        PlatformApiCapabilities.authorize(
            browserAppRequest("POST", List.of("peers", "add"), List.of("peers.read")));

    assertFalse(decision.allowed());
    assertEquals("missing_capability", decision.reasonCode());
    assertEquals(List.of("peers.write"), decision.action().requiredCapabilities());
  }

  @Test
  void authorize_whenAppHasRequiredCapabilities_expectAllowed() {
    for (RouteCase routeCase : allowedRoutes()) {
      PlatformApiAuthorizationDecision decision =
          PlatformApiCapabilities.authorize(
              appRequest(routeCase.method(), routeCase.segments(), routeCase.capabilities()));

      assertTrue(decision.allowed(), routeCase.actionLabel());
      assertEquals("capability_present", decision.reasonCode(), routeCase.actionLabel());
      assertEquals(routeCase.endpointFamily(), decision.action().endpointFamily());
      assertEquals(routeCase.actionLabel(), decision.action().label());
      assertEquals(routeCase.capabilities(), decision.action().requiredCapabilities());
    }
  }

  @Test
  void authorize_whenAppInsertLacksContentInsert_expectDenied() {
    PlatformApiAuthorizationDecision decision =
        PlatformApiCapabilities.authorize(
            appRequest("POST", List.of("queue", "inserts", "file"), List.of("queue.write")));

    assertFalse(decision.allowed());
    assertEquals("missing_capability", decision.reasonCode());
    assertEquals(
        List.of("content.insert", "queue.write"), decision.action().requiredCapabilities());
  }

  @Test
  void authorize_whenAppHasOnlyAppDocumentInsertCapabilityForLocalFile_expectDenied() {
    PlatformApiAuthorizationDecision decision =
        PlatformApiCapabilities.authorize(
            appRequest(
                "POST",
                List.of("queue", "inserts", "file"),
                List.of("content.insert.app-document", "queue.write")));

    assertFalse(decision.allowed());
    assertEquals("missing_capability", decision.reasonCode());
    assertEquals(
        List.of("content.insert", "queue.write"), decision.action().requiredCapabilities());
  }

  @Test
  void authorize_whenAppUpdateLifecycleLacksCatalogManage_expectDenied() {
    PlatformApiAuthorizationDecision decision =
        PlatformApiCapabilities.authorize(
            appRequest(
                "POST", List.of("apps", "alpha", "updates", "stage"), List.of("apps.manage")));

    assertFalse(decision.allowed());
    assertEquals("missing_capability", decision.reasonCode());
    assertEquals(
        List.of("apps.manage", "catalogs.manage"), decision.action().requiredCapabilities());
  }

  @Test
  void authorize_whenBrowserAppRequestsRawSecret_expectDeniedByDefault() {
    PlatformApiAuthorizationDecision decision =
        PlatformApiCapabilities.authorize(
            browserAppRequest(
                "GET",
                List.of("app-vault", "secrets", "api-token"),
                List.of("vault.secrets.read")));

    assertFalse(decision.allowed());
    assertEquals("unmapped_route", decision.reasonCode());
  }

  @Test
  void authorize_whenAppHitsUnmappedRoute_expectDeniedByDefault() {
    PlatformApiAuthorizationDecision decision =
        PlatformApiCapabilities.authorize(
            appRequest("POST", List.of("node", "greeting"), List.of("node.read")));

    assertFalse(decision.allowed());
    assertEquals("unmapped_route", decision.reasonCode());
  }

  @Test
  void authorize_whenAppRouteIsUnmapped_expectDeniedByDefault() {
    for (UnmappedRouteCase routeCase : unmappedAppRoutes()) {
      PlatformApiAuthorizationDecision decision =
          PlatformApiCapabilities.authorize(
              appRequest(
                  routeCase.method(),
                  routeCase.segments(),
                  List.of("apps.manage", "node.read", "queue.write")));

      assertFalse(decision.allowed(), routeCase.segments().toString());
      assertEquals("unmapped_route", decision.reasonCode(), routeCase.segments().toString());
      assertEquals("unmapped", decision.action().requiredCapabilities().getFirst());
    }
  }

  private static List<RouteCase> allowedRoutes() {
    return List.of(
        route("GET", List.of("node", "greeting"), "node", "node.read", "node.read"),
        route("GET", List.of("node", "reference"), "node", "node.read", "node.read"),
        route(
            "GET",
            List.of("connectivity"),
            "connectivity",
            "connectivity.read",
            "connectivity.read"),
        route("GET", List.of("queue"), "queue", "queue.read", "queue.read"),
        route("GET", List.of("queue", "count"), "queue", "queue.read", "queue.read"),
        route("GET", List.of("queue", "keys"), "queue", "queue.read", "queue.read"),
        route("POST", List.of("content", "fetch"), "content", "content.fetch", "content.fetch"),
        route(
            "GET",
            List.of("content", "subscriptions"),
            "content",
            "content.subscriptions.list",
            "content.subscribe"),
        route(
            "POST",
            List.of("content", "subscriptions"),
            "content",
            "content.subscriptions.create",
            "content.fetch",
            "content.subscribe"),
        route(
            "GET",
            List.of("content", "subscriptions", "sub-sample"),
            "content",
            "content.subscriptions.read",
            "content.subscribe"),
        route(
            "POST",
            List.of("content", "subscriptions", "sub-sample", "refresh"),
            "content",
            "content.subscriptions.refresh",
            "content.fetch",
            "content.subscribe"),
        route(
            "POST",
            List.of("content", "subscriptions", "sub-sample", "pause"),
            "content",
            "content.subscriptions.pause",
            "content.subscribe"),
        route(
            "POST",
            List.of("content", "subscriptions", "sub-sample", "resume"),
            "content",
            "content.subscriptions.resume",
            "content.subscribe"),
        route(
            "DELETE",
            List.of("content", "subscriptions", "sub-sample"),
            "content",
            "content.subscriptions.delete",
            "content.subscribe"),
        route("GET", List.of("app-data", "status"), "app-data", "app-data.status", "app.data.read"),
        route(
            "GET",
            List.of("app-data", "namespaces"),
            "app-data",
            "app-data.namespaces.list",
            "app.data.read"),
        route(
            "GET",
            List.of("app-data", "namespaces", "ui-state"),
            "app-data",
            "app-data.namespaces.read",
            "app.data.read"),
        route(
            "POST",
            List.of("app-data", "namespaces", "ui-state", "schema"),
            "app-data",
            "app-data.namespaces.schema",
            "app.data.write"),
        route(
            "DELETE",
            List.of("app-data", "namespaces", "ui-state"),
            "app-data",
            "app-data.namespaces.delete",
            "app.data.write"),
        route(
            "GET",
            List.of("app-data", "records"),
            "app-data",
            "app-data.records.list",
            "app.data.read"),
        route(
            "GET",
            List.of("app-data", "records", "ui-state", "settings"),
            "app-data",
            "app-data.records.read",
            "app.data.read"),
        route(
            "POST",
            List.of("app-data", "records"),
            "app-data",
            "app-data.records.write",
            "app.data.write"),
        route(
            "DELETE",
            List.of("app-data", "records", "ui-state", "settings"),
            "app-data",
            "app-data.records.delete",
            "app.data.write"),
        route("GET", List.of("app-data", "export"), "app-data", "app-data.export", "app.data.read"),
        route(
            "POST", List.of("app-data", "import"), "app-data", "app-data.import", "app.data.write"),
        route(
            "GET",
            List.of("app-services"),
            "app-services",
            "app-services.list",
            "app.services.read"),
        route(
            "GET",
            List.of("app-services", "grants"),
            "app-services",
            "app-services.grants.list",
            "app.services.read"),
        route(
            "POST",
            List.of("app-services", "grants"),
            "app-services",
            "app-services.grants.request",
            "app.services.call"),
        route(
            "POST",
            List.of("app-services", "grants", "asg-0123456789abcdef01234567", "revoke"),
            "app-services",
            "app-services.grants.revoke",
            "app.services.call"),
        route(
            "GET",
            List.of("app-services", "trust-graph", "services"),
            "app-services",
            "app-services.provider.list",
            "app.services.read"),
        route(
            "GET",
            List.of("app-services", "trust-graph", "services", "trust.score"),
            "app-services",
            "app-services.provider.read",
            "app.services.read"),
        route(
            "POST",
            List.of("app-services", "trust-graph", "services", "trust.score", "invoke"),
            "app-services",
            "app-services.invoke",
            "app.services.call"),
        route(
            "POST",
            List.of("queue", "downloads"),
            "queue",
            "queue.downloads.create",
            "queue.write"),
        route(
            "POST",
            List.of("queue", "inserts", "file"),
            "queue",
            "queue.inserts.file",
            "content.insert",
            "queue.write"),
        route(
            "POST",
            List.of("queue", "inserts", "app-document"),
            "queue",
            "queue.inserts.app-document",
            "content.insert.app-document",
            "queue.write"),
        route(
            "POST",
            List.of("queue", "requests", "remove"),
            "queue",
            "queue.requests.remove",
            "queue.write"),
        route(
            "POST",
            List.of("queue", "cleanup", "uploads"),
            "queue",
            "queue.cleanup.uploads",
            "queue.write"),
        route("GET", List.of("peers"), "peers", "peers.read", "peers.read"),
        route("GET", List.of("peers", "peer-123"), "peers", "peers.read", "peers.read"),
        route("POST", List.of("peers", "add"), "peers", "peers.add", "peers.write"),
        route(
            "POST",
            List.of("peers", "peer-123", "settings"),
            "peers",
            "peers.settings",
            "peers.write"),
        route("GET", List.of("config"), "config", "config.read", "config.read"),
        route("POST", List.of("config", "overrides"), "config", "config.overrides", "config.write"),
        route(
            "GET", List.of("security-levels"), "security-levels", "security.read", "security.read"),
        route(
            "GET",
            List.of("security-levels", "network-warning"),
            "security-levels",
            "security.network-warning",
            "security.read"),
        route(
            "POST",
            List.of("security-levels", "network"),
            "security-levels",
            "security.network",
            "security.write"),
        route("GET", List.of("updates", "core"), "updates", "updates.read", "updates.read"),
        route(
            "POST",
            List.of("updates", "core", "download"),
            "updates",
            "updates.core.download",
            "updates.write"),
        route("GET", List.of("wizard", "first-time"), "wizard", "wizard.read", "wizard.read"),
        route(
            "POST",
            List.of("wizard", "first-time", "apply"),
            "wizard",
            "wizard.first-time.apply",
            "wizard.write"),
        route("GET", List.of("alerts"), "alerts", "alerts.read", "alerts.read"),
        route(
            "POST", List.of("alerts", "42", "dismiss"), "alerts", "alerts.dismiss", "alerts.write"),
        route("GET", List.of("diagnostics"), "diagnostics", "diagnostics.read", "diagnostics.read"),
        route(
            "GET",
            List.of("trust-graph", "status"),
            "trust-graph",
            "trust-graph.status",
            "trust.read"),
        route(
            "GET",
            List.of("trust-graph", "anchors"),
            "trust-graph",
            "trust-graph.anchors.list",
            "trust.read"),
        route(
            "POST",
            List.of("trust-graph", "anchors"),
            "trust-graph",
            "trust-graph.anchors.add",
            "trust.write"),
        route(
            "DELETE",
            List.of("trust-graph", "anchors", "issuer-fingerprint"),
            "trust-graph",
            "trust-graph.anchors.remove",
            "trust.write"),
        route(
            "POST",
            List.of("trust-graph", "import"),
            "trust-graph",
            "trust-graph.import",
            "trust.write"),
        route(
            "POST",
            List.of("trust-graph", "import-uri"),
            "trust-graph",
            "trust-graph.import-uri",
            "content.fetch",
            "trust.write"),
        route(
            "POST",
            List.of("trust-graph", "import-preview"),
            "trust-graph",
            "trust-graph.import-preview",
            "trust.write"),
        route(
            "POST",
            List.of("trust-graph", "import-preview-uri"),
            "trust-graph",
            "trust-graph.import-preview-uri",
            "content.fetch",
            "trust.write"),
        route(
            "GET",
            List.of("trust-graph", "audit"),
            "trust-graph",
            "trust-graph.audit",
            "trust.read"),
        route(
            "GET",
            List.of("trust-graph", "subjects"),
            "trust-graph",
            "trust-graph.subjects",
            "trust.read"),
        route(
            "GET",
            List.of("trust-graph", "statements"),
            "trust-graph",
            "trust-graph.statements",
            "trust.read"),
        route(
            "GET",
            List.of("trust-graph", "score"),
            "trust-graph",
            "trust-graph.score",
            "trust.read"),
        route("GET", List.of("apps"), "apps", "apps.read", "apps.read"),
        route("GET", List.of("apps", "alpha"), "apps", "apps.read", "apps.read"),
        route("GET", List.of("apps", "alpha", "runtime"), "apps", "apps.read", "apps.read"),
        route("GET", List.of("apps", "alpha", "logs"), "apps", "apps.read", "apps.read"),
        route("GET", List.of("apps", "alpha", "permissions"), "apps", "apps.read", "apps.read"),
        route("GET", List.of("apps", "alpha", "audit"), "apps", "apps.read", "apps.read"),
        route("GET", List.of("apps", "alpha", "updates"), "apps", "apps.read", "apps.read"),
        route(
            "GET",
            List.of("apps", "alpha", "updates", "policy"),
            "apps",
            "apps.updates.policy",
            "apps.read"),
        route(
            "POST",
            List.of("apps", "alpha", "updates", "check"),
            "apps",
            "apps.updates.check",
            "apps.manage",
            "catalogs.manage"),
        route(
            "POST",
            List.of("apps", "alpha", "updates", "stage"),
            "apps",
            "apps.updates.stage",
            "apps.manage",
            "catalogs.manage"),
        route(
            "POST",
            List.of("apps", "alpha", "updates", "apply"),
            "apps",
            "apps.updates.apply",
            "apps.manage",
            "catalogs.manage"),
        route(
            "POST",
            List.of("apps", "alpha", "updates", "rollback"),
            "apps",
            "apps.updates.rollback",
            "apps.manage"),
        route("POST", List.of("apps", "install"), "apps", "apps.install", "apps.manage"),
        route("DELETE", List.of("apps", "alpha"), "apps", "apps.uninstall", "apps.manage"),
        route("GET", List.of("app-catalogs"), "app-catalogs", "catalogs.read", "catalogs.read"),
        route(
            "GET",
            List.of("app-catalogs", "recommended"),
            "app-catalogs",
            "catalogs.recommended.list",
            "catalogs.read"),
        route(
            "GET",
            List.of("app-vault", "secrets"),
            "app-vault",
            "app-vault.secrets.list",
            "vault.secrets.read"),
        route(
            "PUT",
            List.of("app-vault", "secrets", "api-token"),
            "app-vault",
            "app-vault.secrets.write",
            "vault.secrets.write"),
        route(
            "GET",
            List.of("app-vault", "identities"),
            "app-vault",
            "app-vault.identities.list",
            "vault.identities.read"),
        route(
            "POST",
            List.of("app-vault", "identities"),
            "app-vault",
            "app-vault.identities.create",
            "vault.identities.create"),
        route(
            "POST",
            List.of("app-vault", "identities", "id-sample", "profile-document"),
            "app-vault",
            "app-vault.identities.profile-document",
            "vault.identities.read",
            "vault.identities.use"),
        route(
            "POST",
            List.of("app-vault", "identities", "id-sample", "social-message"),
            "app-vault",
            "app-vault.identities.social-message",
            "vault.identities.read",
            "vault.identities.use"),
        route(
            "POST",
            List.of("app-vault", "identities", "id-sample", "trust-statement"),
            "app-vault",
            "app-vault.identities.trust-statement",
            "trust.write",
            "vault.identities.read",
            "vault.identities.use"),
        route(
            "POST",
            List.of("app-vault", "identities", "id-sample", "use"),
            "app-vault",
            "app-vault.identities.use",
            "vault.identities.use"),
        route(
            "GET",
            List.of("platform", "contract"),
            "platform",
            "platform.contract.read",
            "platform.contract.read"),
        route(
            "GET",
            List.of("app-catalogs", "default", "apps"),
            "app-catalogs",
            "catalogs.read",
            "catalogs.read"),
        route(
            "GET",
            List.of("app-catalogs", "default", "apps", "alpha"),
            "app-catalogs",
            "catalogs.read",
            "catalogs.read"),
        route(
            "POST",
            List.of("app-catalogs", "add"),
            "app-catalogs",
            "catalogs.add",
            "catalogs.manage"),
        route(
            "POST",
            List.of("app-catalogs", "recommended", "crypta-first-party-beta", "add"),
            "app-catalogs",
            "catalogs.recommended.add",
            "catalogs.manage"),
        route(
            "POST",
            List.of("app-catalogs", "default", "apps", "alpha", "install"),
            "app-catalogs",
            "catalogs.apps.install",
            "catalogs.manage"),
        route(
            "DELETE",
            List.of("app-catalogs", "default"),
            "app-catalogs",
            "catalogs.remove",
            "catalogs.manage"));
  }

  private static List<UnmappedRouteCase> unmappedAppRoutes() {
    return List.of(
        new UnmappedRouteCase("POST", List.of("node", "greeting")),
        new UnmappedRouteCase("GET", List.of("node", "unknown")),
        new UnmappedRouteCase("GET", List.of("connectivity", "status")),
        new UnmappedRouteCase("GET", List.of("diagnostics", "heap")),
        new UnmappedRouteCase("PUT", List.of("queue", "requests", "remove")),
        new UnmappedRouteCase("GET", List.of("queue", "downloads")),
        new UnmappedRouteCase("GET", List.of("content", "fetch")),
        new UnmappedRouteCase("POST", List.of("content", "unknown")),
        new UnmappedRouteCase("PUT", List.of("app-data", "records")),
        new UnmappedRouteCase("GET", List.of("app-data", "import")),
        new UnmappedRouteCase("POST", List.of("app-data", "status")),
        new UnmappedRouteCase("GET", List.of("app-services", "audit")),
        new UnmappedRouteCase(
            "POST", List.of("app-services", "grants", "asg-0123456789abcdef01234567", "approve")),
        new UnmappedRouteCase("PUT", List.of("app-services", "grants")),
        new UnmappedRouteCase("PUT", List.of("trust-graph", "anchors")),
        new UnmappedRouteCase("GET", List.of("trust-graph", "import")),
        new UnmappedRouteCase("GET", List.of("trust-graph", "import-preview")),
        new UnmappedRouteCase("GET", List.of("trust-graph", "import-preview-uri")),
        new UnmappedRouteCase("POST", List.of("trust-graph", "score")),
        new UnmappedRouteCase("GET", List.of("queue", "requests", "remove")),
        new UnmappedRouteCase("POST", List.of("queue", "inserts", "unknown")),
        new UnmappedRouteCase("GET", List.of("peers", "peer-123", "settings")),
        new UnmappedRouteCase("GET", List.of("config", "overrides")),
        new UnmappedRouteCase("GET", List.of("config", "persist")),
        new UnmappedRouteCase("GET", List.of("security-levels", "network")),
        new UnmappedRouteCase("GET", List.of("updates", "core", "download")),
        new UnmappedRouteCase("GET", List.of("wizard", "first-time", "apply")),
        new UnmappedRouteCase("GET", List.of("alerts", "42", "dismiss")),
        new UnmappedRouteCase("GET", List.of("apps", "alpha", "start")),
        new UnmappedRouteCase("GET", List.of("apps", "alpha", "unknown")),
        new UnmappedRouteCase("POST", List.of("apps", "alpha", "logs")),
        new UnmappedRouteCase("POST", List.of("apps", "alpha", "updates", "policy")),
        new UnmappedRouteCase("GET", List.of("identity-vault", "identities")),
        new UnmappedRouteCase("GET", List.of("app-catalogs", "default")),
        new UnmappedRouteCase("GET", List.of("app-catalogs", "default", "refresh")),
        new UnmappedRouteCase("GET", List.of("app-catalogs", "default", "mirrors")),
        new UnmappedRouteCase("POST", List.of("app-catalogs", "default", "mirrors")),
        new UnmappedRouteCase("POST", List.of("app-catalogs", "default", "mirrors", "backup")),
        new UnmappedRouteCase("DELETE", List.of("app-catalogs", "default", "mirrors", "backup")),
        new UnmappedRouteCase("GET", List.of("app-catalogs", "default", "operations", "health")),
        new UnmappedRouteCase("GET", List.of("app-catalogs", "default", "operations", "revisions")),
        new UnmappedRouteCase(
            "GET", List.of("app-catalogs", "default", "operations", "key-rotation")),
        new UnmappedRouteCase(
            "POST", List.of("app-catalogs", "default", "operations", "refresh-primary")),
        new UnmappedRouteCase("POST", List.of("app-catalogs", "default", "operations", "rollback")),
        new UnmappedRouteCase(
            "POST", List.of("app-catalogs", "default", "operations", "emergency-refresh")),
        new UnmappedRouteCase(
            "GET", List.of("app-catalogs", "default", "apps", "alpha", "install")),
        new UnmappedRouteCase(
            "DELETE", List.of("app-catalogs", "default", "apps", "alpha", "install")));
  }

  private static RouteCase route(
      String method,
      List<String> segments,
      String endpointFamily,
      String actionLabel,
      String... capabilities) {
    return new RouteCase(method, segments, endpointFamily, actionLabel, List.of(capabilities));
  }

  private static PlatformApiRequest appRequest(
      String method, List<String> segments, List<String> permissions) {
    return new PlatformApiRequest(
        method, segments, Map.of(), PlatformApiPrincipal.appToken("demo-app", permissions));
  }

  private static PlatformApiRequest browserAppRequest(
      String method, List<String> segments, List<String> permissions) {
    return new PlatformApiRequest(
        method,
        segments,
        Map.of(),
        PlatformApiPrincipal.appBrowserSession("demo-app", permissions));
  }

  private record RouteCase(
      String method,
      List<String> segments,
      String endpointFamily,
      String actionLabel,
      List<String> capabilities) {}

  private record UnmappedRouteCase(String method, List<String> segments) {}
}
