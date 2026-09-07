package network.crypta.platform.api.appservices;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import network.crypta.platform.api.PlatformApiException;
import network.crypta.platform.api.trust.TrustGraphApiHandler;
import network.crypta.platform.trustgraph.InMemoryTrustGraphStore;
import network.crypta.platform.trustgraph.TrustStatementDocument;
import network.crypta.platform.trustgraph.TrustStatementParser;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TrustGraphScoreAppServiceAdapterTest {
  private static final String CONTEXT_MESSAGE_AUTHOR = "message-author";
  private static final String CONTEXT_PROFILE = "profile";
  private static final String PARAM_CONTEXT = "context";
  private static final String PARAM_SUBJECT_KIND = "subjectKind";
  private static final String PARAM_SUBJECT_URI = "subjectUri";
  private static final String SCOPE_SCORE_READ = "score.read";
  private static final String SUBJECT_URI_ALICE = "crypta:identity:alice";

  @Test
  void invoke_whenScoreRequested_expectRedactedScoreSummary() {
    TrustGraphScoreAppServiceAdapter adapter =
        new TrustGraphScoreAppServiceAdapter(new TrustGraphApiHandler());
    String subjectUri = SUBJECT_URI_ALICE;

    Map<String, Object> result =
        adapter.invoke(descriptor(), activeGrant(), invokeParams(subjectUri));

    assertEquals("identity", result.get(PARAM_SUBJECT_KIND));
    assertEquals(CONTEXT_MESSAGE_AUTHOR, result.get(PARAM_CONTEXT));
    assertTrue(result.get("subjectUriHash").toString().startsWith("sha256:"));
    assertFalse(result.toString().contains(subjectUri));
    assertFalse(result.toString().contains("statementBody"));
    assertEquals(false, result.get("completeWot"));
  }

  @Test
  void invoke_whenSubjectKindMalformed_expectBoundedValidationFailure() {
    TrustGraphScoreAppServiceAdapter adapter =
        new TrustGraphScoreAppServiceAdapter(new TrustGraphApiHandler());
    AppServiceDescriptor descriptor = descriptor();
    AppServiceGrant grant = activeGrant();
    Map<String, List<String>> params =
        Map.of(
            PARAM_SUBJECT_KIND,
            List.of("not a kind"),
            PARAM_SUBJECT_URI,
            List.of(SUBJECT_URI_ALICE),
            PARAM_CONTEXT,
            List.of(CONTEXT_MESSAGE_AUTHOR));

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> adapter.invoke(descriptor, grant, params));

    assertEquals(400, exception.statusCode());
  }

  @Test
  void invoke_whenGrantLacksScoreReadScope_expectScopeDenied() {
    TrustGraphScoreAppServiceAdapter adapter =
        new TrustGraphScoreAppServiceAdapter(new TrustGraphApiHandler());
    AppServiceDescriptor descriptor = descriptor();
    AppServiceGrant grant = activeGrant(List.of("profile.read"), List.of(CONTEXT_MESSAGE_AUTHOR));
    Map<String, List<String>> params = invokeParams(SUBJECT_URI_ALICE);

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> adapter.invoke(descriptor, grant, params));

    assertEquals(403, exception.statusCode());
    assertEquals("app_service_scope_denied", exception.errorCode());
  }

  @Test
  void invoke_whenGrantDoesNotCoverContext_expectContextDenied() {
    TrustGraphScoreAppServiceAdapter adapter =
        new TrustGraphScoreAppServiceAdapter(new TrustGraphApiHandler());
    AppServiceDescriptor descriptor = descriptor();
    AppServiceGrant grant = activeGrant(List.of(SCOPE_SCORE_READ), List.of(CONTEXT_PROFILE));
    Map<String, List<String>> params = invokeParams(SUBJECT_URI_ALICE);

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> adapter.invoke(descriptor, grant, params));

    assertEquals(403, exception.statusCode());
    assertEquals("app_service_context_denied", exception.errorCode());
  }

  @Test
  void invoke_whenDescriptorDoesNotAdvertiseContext_expectContextUnsupported() {
    TrustGraphScoreAppServiceAdapter adapter =
        new TrustGraphScoreAppServiceAdapter(new TrustGraphApiHandler());
    AppServiceDescriptor descriptor = descriptor(List.of(CONTEXT_PROFILE));
    AppServiceGrant grant = activeGrant();
    Map<String, List<String>> params = invokeParams(SUBJECT_URI_ALICE);

    PlatformApiException exception =
        assertThrows(PlatformApiException.class, () -> adapter.invoke(descriptor, grant, params));

    assertEquals(400, exception.statusCode());
    assertEquals("app_service_context_unsupported", exception.errorCode());
  }

  @Test
  void invoke_whenSignedAnchoredZeroComparedToEmptyStore_expectDistinctEvidenceStatus()
      throws Exception {
    Clock clock = Clock.fixed(Instant.parse("2026-09-06T00:00:00Z"), ZoneOffset.UTC);
    InMemoryTrustGraphStore store = new InMemoryTrustGraphStore(clock);
    TrustGraphScoreAppServiceAdapter adapter =
        new TrustGraphScoreAppServiceAdapter(new TrustGraphApiHandler(store, clock));
    Map<String, List<String>> params = invokeParams("synthetic-public-subject");
    Map<String, Object> absent = adapter.invoke(descriptor(), activeGrant(), params);
    TrustStatementDocument document;
    try (var resource =
        getClass().getResourceAsStream("/content-profile-conformance/v1/trust/minimal.json")) {
      document =
          TrustStatementParser.parse(
              new String(
                  java.util.Objects.requireNonNull(resource).readAllBytes(),
                  StandardCharsets.UTF_8));
    }
    store.addAnchor(document.payload().issuer().publicKeyFingerprint(), "Synthetic", "manual");
    store.importStatement(document, "manual", null, null);

    Map<String, Object> zero = adapter.invoke(descriptor(), activeGrant(), params);

    assertEquals("unknown", absent.get("status"));
    assertEquals(0, absent.get("contributingEvidenceCount"));
    assertEquals("mixed", zero.get("status"));
    assertEquals(0, zero.get("score"));
    assertEquals(1, zero.get("contributingEvidenceCount"));
    assertEquals(absent.get("subjectUriHash"), zero.get("subjectUriHash"));
    assertEquals(
        java.util.Set.of(
            "subjectKind",
            "subjectUriHash",
            "context",
            "status",
            "score",
            "confidence",
            "evidenceCount",
            "contributingEvidenceCount",
            "completeWot"),
        zero.keySet());
  }

  private static AppServiceDescriptor descriptor() {
    return descriptor(List.of(CONTEXT_MESSAGE_AUTHOR, CONTEXT_PROFILE));
  }

  private static AppServiceDescriptor descriptor(List<String> contexts) {
    return new AppServiceDescriptor(
        "trust-graph",
        "Trust Graph Preview",
        "1.0.0",
        "trust.score",
        "Trust Score Service",
        "1",
        "platform-adapter",
        "trust-graph.score",
        List.of(SCOPE_SCORE_READ),
        contexts,
        "Returns a redacted score summary.",
        "preview",
        true);
  }

  private static AppServiceGrant activeGrant() {
    return activeGrant(List.of(SCOPE_SCORE_READ), List.of(CONTEXT_MESSAGE_AUTHOR));
  }

  private static AppServiceGrant activeGrant(List<String> scopes, List<String> contexts) {
    Instant now = Instant.parse("2026-05-24T12:00:00Z");
    return new AppServiceGrant(
        "asg-111111111111111111111111",
        "social-inbox",
        "trust-graph",
        "trust.score",
        scopes,
        contexts,
        "Annotate message authors.",
        AppServiceGrantStatus.ACTIVE,
        now,
        now,
        now,
        null,
        null,
        0,
        null);
  }

  private static Map<String, List<String>> invokeParams(String subjectUri) {
    return Map.of(
        PARAM_SUBJECT_KIND,
        List.of("identity"),
        PARAM_SUBJECT_URI,
        List.of(subjectUri),
        PARAM_CONTEXT,
        List.of(CONTEXT_MESSAGE_AUTHOR));
  }
}
