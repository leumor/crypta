package network.crypta.platform.trustgraph;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class TrustGraphScorerTest {
  private static final Instant NOW = Instant.parse("2026-05-17T00:00:00Z");

  @Test
  void score_whenAnchoredZeroExists_expectMixedAndContributingInsteadOfUnknown() {
    InMemoryTrustGraphStore store = new InMemoryTrustGraphStore(Clock.fixed(NOW, ZoneOffset.UTC));
    TrustStatementDocument document = signedStatement(0, 100, "2026-05-16T00:00:00Z", null);
    store.addAnchor(fingerprint(document), "Synthetic", "manual");
    store.importStatement(document, "manual", null, null);

    TrustGraphScore score = scorer(store).score(query());

    assertEquals("mixed", score.status());
    assertEquals(0, score.score());
    assertEquals(1, score.contributingEvidenceCount());
  }

  @Test
  void score_whenExpiryEqualsClock_expectNonContributingAtExactBoundary() {
    InMemoryTrustGraphStore store = new InMemoryTrustGraphStore(Clock.fixed(NOW, ZoneOffset.UTC));
    TrustStatementDocument document =
        signedStatement(100, 100, "2026-05-16T00:00:00Z", NOW.toString());
    store.addAnchor(fingerprint(document), "Synthetic", "manual");
    store.importStatement(document, "manual", null, null);

    TrustGraphScore score = scorer(store).score(query());

    assertEquals("unknown", score.status());
    assertEquals(0, score.contributingEvidenceCount());
    assertTrue(score.evidence().getFirst().expired());
  }

  @Test
  void score_whenNoAnchorEvidenceExists_expectUnknownWithNonContributingEvidence() {
    InMemoryTrustGraphStore store = new InMemoryTrustGraphStore(Clock.fixed(NOW, ZoneOffset.UTC));
    store.importStatement(
        signedStatement(80, 50, "2026-05-16T00:00:00Z", null), "fetched", "CHK@example", "demo");

    TrustGraphScore score = scorer(store).score(query());

    assertEquals("unknown", score.status());
    assertEquals(0, score.score());
    assertEquals(0, score.confidence());
    assertEquals(1, score.evidenceCount());
    assertEquals(0, score.contributingEvidenceCount());
    assertFalse(score.evidence().getFirst().contributing());
    assertFalse(score.evidence().getFirst().anchored());
    assertEquals(List.of("unanchored"), score.evidence().getFirst().nonContributingReasons());
  }

  @Test
  void score_whenAnchorEvidenceExists_expectConfidenceWeightedAverage() {
    InMemoryTrustGraphStore store = new InMemoryTrustGraphStore(Clock.fixed(NOW, ZoneOffset.UTC));
    TrustStatementDocument first = signedStatement(100, 20, "2026-05-16T00:00:00Z", null);
    TrustStatementDocument second = signedStatement(0, 80, "2026-05-16T00:00:00Z", null);
    store.addAnchor(fingerprint(first), "Alice", "manual");
    store.addAnchor(fingerprint(second), "Bob", "manual");
    store.importStatement(first, "manual", null, null);
    store.importStatement(second, "manual", null, null);

    TrustGraphScore score = scorer(store).score(query());

    assertEquals("trusted", score.status());
    assertEquals(20, score.score());
    assertEquals(50, score.confidence());
    assertEquals(2, score.contributingEvidenceCount());
    assertTrue(score.evidence().stream().allMatch(TrustGraphEvidence::contributing));
    assertTrue(score.evidence().stream().allMatch(TrustGraphEvidence::signatureVerified));
  }

  @Test
  void score_whenExpiredAnchorStatementExists_expectIgnoredForScoreButShownAsEvidence() {
    InMemoryTrustGraphStore store = new InMemoryTrustGraphStore(Clock.fixed(NOW, ZoneOffset.UTC));
    TrustStatementDocument document =
        signedStatement(100, 100, "2026-01-01T00:00:00Z", "2026-02-01T00:00:00Z");
    store.addAnchor(fingerprint(document), "Alice", "manual");
    store.importStatement(document, "fetched", null, null);

    TrustGraphScore score = scorer(store).score(query());

    assertEquals("unknown", score.status());
    assertEquals(0, score.contributingEvidenceCount());
    assertEquals(1, score.evidenceCount());
    assertTrue(score.evidence().getFirst().expired());
    assertFalse(score.evidence().getFirst().contributing());
    assertEquals(List.of("expired"), score.evidence().getFirst().nonContributingReasons());
  }

  @Test
  void score_whenAnchorEvidenceHasZeroConfidence_expectRetainedButNonContributing() {
    InMemoryTrustGraphStore store = new InMemoryTrustGraphStore(Clock.fixed(NOW, ZoneOffset.UTC));
    TrustStatementDocument document = signedStatement(100, 0, "2026-05-16T00:00:00Z", null);
    store.addAnchor(fingerprint(document), "Alice", "manual");
    store.importStatement(document, "manual", null, null);

    TrustGraphScore score = scorer(store).score(query());

    assertEquals("unknown", score.status());
    assertEquals(0, score.score());
    assertEquals(0, score.confidence());
    assertEquals(1, score.evidenceCount());
    assertEquals(0, score.contributingEvidenceCount());
    assertFalse(score.evidence().getFirst().contributing());
  }

  @Test
  void score_whenOppositeAnchorEvidenceHasZeroConfidence_expectStatusUsesWeightedEvidenceOnly() {
    InMemoryTrustGraphStore store = new InMemoryTrustGraphStore(Clock.fixed(NOW, ZoneOffset.UTC));
    TrustStatementDocument first = signedStatement(80, 100, "2026-05-16T00:00:00Z", null);
    TrustStatementDocument second = signedStatement(-100, 0, "2026-05-16T00:00:00Z", null);
    store.addAnchor(fingerprint(first), "Alice", "manual");
    store.addAnchor(fingerprint(second), "Bob", "manual");
    store.importStatement(first, "manual", null, null);
    store.importStatement(second, "manual", null, null);

    TrustGraphScore score = scorer(store).score(query());

    assertEquals("trusted", score.status());
    assertEquals(80, score.score());
    assertEquals(100, score.confidence());
    assertEquals(2, score.evidenceCount());
    assertEquals(1, score.contributingEvidenceCount());
    assertTrue(score.evidence().getFirst().contributing());
    assertFalse(score.evidence().get(1).contributing());
  }

  @Test
  void importStatement_whenSameDocumentImportedTwice_expectIdempotentSummary() {
    InMemoryTrustGraphStore store = new InMemoryTrustGraphStore(Clock.fixed(NOW, ZoneOffset.UTC));
    TrustStatementDocument document = signedStatement(80, 50, "2026-05-16T00:00:00Z", null);

    TrustGraphImportResult first = store.importStatement(document, "manual", null, null);
    TrustGraphImportResult second = store.importStatement(document, "manual", null, null);

    assertTrue(first.imported());
    assertTrue(first.signatureVerified());
    assertFalse(second.imported());
    assertEquals(1, store.statementCount());
    assertFalse(first.toJson().toString().contains(document.signature().value()));
  }

  @Test
  void score_whenAnchoredStatementSignatureIsUnverified_expectEvidenceDoesNotContribute() {
    InMemoryTrustGraphStore store = new InMemoryTrustGraphStore(Clock.fixed(NOW, ZoneOffset.UTC));
    TrustStatementDocument signed = signedStatement(80, 50, "2026-05-16T00:00:00Z", null);
    TrustStatementDocument document =
        new TrustStatementDocument(
            signed.type(),
            signed.payload(),
            new TrustSignatureEnvelope(
                TrustDocumentTypes.APP_VAULT_ED25519_PREVIEW_ALGORITHM,
                TrustDocumentTypes.TRUST_STATEMENT_V1,
                "Zm9yZ2Vk"));
    store.addAnchor(fingerprint(document), "Alice", "manual");
    TrustGraphImportResult result = store.importStatement(document, "fetched", null, null);

    TrustGraphScore score = scorer(store).score(query());

    assertFalse(result.signatureVerified());
    assertEquals("unknown", score.status());
    assertEquals(0, score.contributingEvidenceCount());
    assertEquals(1, score.evidenceCount());
    assertFalse(score.evidence().getFirst().signatureVerified());
    assertFalse(score.evidence().getFirst().contributing());
    assertEquals(List.of("unverified"), score.evidence().getFirst().nonContributingReasons());
  }

  @Test
  void score_whenAnchoredStatementRevoked_expectLifecycleBlocksContribution() {
    InMemoryTrustGraphStore store = new InMemoryTrustGraphStore(Clock.fixed(NOW, ZoneOffset.UTC));
    TrustStatementDocument document = signedStatement(80, 50, "2026-05-16T00:00:00Z", null);
    store.addAnchor(fingerprint(document), "Alice", "manual");
    TrustGraphImportResult imported = store.importStatement(document, "manual", null, null);
    store.updateLifecycle(
        imported.documentFingerprint(),
        TrustStatementLifecycleStatus.REVOKED,
        "operator-revoked",
        "local policy",
        null,
        "trust-graph",
        "app");

    TrustGraphScore score = scorer(store).score(query());

    assertEquals("unknown", score.status());
    assertEquals(0, score.contributingEvidenceCount());
    assertEquals(1, score.evidenceCount());
    TrustGraphEvidence evidence = score.evidence().getFirst();
    assertTrue(evidence.anchored());
    assertTrue(evidence.signatureVerified());
    assertEquals(TrustStatementLifecycleStatus.REVOKED, evidence.lifecycleStatus());
    assertEquals(List.of("revoked"), evidence.nonContributingReasons());
    assertFalse(evidence.contributing());
  }

  @Test
  void score_whenAnchoredStatementDeprecated_expectLifecycleBlocksContribution() {
    InMemoryTrustGraphStore store = new InMemoryTrustGraphStore(Clock.fixed(NOW, ZoneOffset.UTC));
    TrustStatementDocument document = signedStatement(80, 50, "2026-05-16T00:00:00Z", null);
    store.addAnchor(fingerprint(document), "Alice", "manual");
    TrustGraphImportResult imported = store.importStatement(document, "manual", null, null);
    store.updateLifecycle(
        imported.documentFingerprint(),
        TrustStatementLifecycleStatus.DEPRECATED,
        "operator-deprecated",
        null,
        null,
        "trust-graph",
        "app");

    TrustGraphScore score = scorer(store).score(query());

    assertEquals("unknown", score.status());
    assertEquals(0, score.contributingEvidenceCount());
    TrustGraphEvidence evidence = score.evidence().getFirst();
    assertEquals(TrustStatementLifecycleStatus.DEPRECATED, evidence.lifecycleStatus());
    assertEquals(List.of("deprecated"), evidence.nonContributingReasons());
    assertFalse(evidence.contributing());
  }

  @Test
  void importStatement_whenDistinctImportsExceedLimit_expectOldestStatementEvicted() {
    InMemoryTrustGraphStore store =
        new InMemoryTrustGraphStore(Clock.fixed(NOW, ZoneOffset.UTC), 3);
    java.util.ArrayList<String> importedFingerprints = new java.util.ArrayList<>();
    for (int index = 0; index < 4; index++) {
      TrustStatementDocument document = signedStatement(80, 50, "2026-05-16T00:00:00Z", null);
      importedFingerprints.add(fingerprint(document));
      store.importStatement(document, "manual", null, null);
    }

    List<String> retainedFingerprints =
        store.statements().stream()
            .map(statement -> statement.document().payload().issuer().publicKeyFingerprint())
            .toList();

    assertEquals(3, store.statementCount());
    assertFalse(retainedFingerprints.contains(importedFingerprints.getFirst()));
    assertTrue(retainedFingerprints.contains(importedFingerprints.get(1)));
    assertTrue(retainedFingerprints.contains(importedFingerprints.get(2)));
    assertTrue(retainedFingerprints.contains(importedFingerprints.get(3)));
  }

  @Test
  void addAnchor_whenDistinctAnchorsExceedLimit_expectOldestAnchorEvicted() {
    InMemoryTrustGraphStore store =
        new InMemoryTrustGraphStore(Clock.fixed(NOW, ZoneOffset.UTC), 512, 3);
    for (int index = 0; index < 4; index++) {
      store.addAnchor("fingerprint-" + index, "Anchor " + index, "manual");
    }

    List<String> retainedFingerprints =
        store.anchors().stream().map(TrustAnchor::issuerFingerprint).toList();

    assertEquals(3, retainedFingerprints.size());
    assertFalse(retainedFingerprints.contains("fingerprint-0"));
    assertTrue(retainedFingerprints.contains("fingerprint-1"));
    assertTrue(retainedFingerprints.contains("fingerprint-2"));
    assertTrue(retainedFingerprints.contains("fingerprint-3"));
  }

  @Test
  void addAnchor_whenExistingAnchorUpdatedAtLimit_expectAnchorIsReplacedWithoutEviction() {
    InMemoryTrustGraphStore store =
        new InMemoryTrustGraphStore(Clock.fixed(NOW, ZoneOffset.UTC), 512, 2);
    store.addAnchor("fingerprint-1", "Original", "manual");
    store.addAnchor("fingerprint-2", "Other", "manual");

    TrustAnchor updated = store.addAnchor("fingerprint-1", "Updated", "profile");

    assertEquals(2, store.anchors().size());
    assertEquals("Updated", updated.label());
    assertTrue(store.isAnchor("fingerprint-1"));
    assertTrue(store.isAnchor("fingerprint-2"));
  }

  @Test
  void auditEvents_whenLimitIsLowerThanStoredCount_expectNewestFirstBoundedSnapshot() {
    InMemoryTrustGraphStore store = new InMemoryTrustGraphStore(Clock.fixed(NOW, ZoneOffset.UTC));
    store.appendAuditEvent(auditEvent("statement_imported", NOW, "first"));
    store.appendAuditEvent(auditEvent("anchor_added_or_replaced", NOW.plusSeconds(1), "second"));
    store.appendAuditEvent(auditEvent("statement_import_rejected", NOW.plusSeconds(2), "third"));

    List<TrustGraphAuditEvent> limited = store.auditEvents(2);
    List<TrustGraphAuditEvent> minimum = store.auditEvents(0);

    assertEquals(
        List.of("third", "second"),
        limited.stream().map(TrustGraphAuditEvent::statusCode).toList());
    assertEquals(List.of("third"), minimum.stream().map(TrustGraphAuditEvent::statusCode).toList());
    assertEquals(InMemoryTrustGraphStore.DEFAULT_MAX_STATEMENTS, store.config().maxStatements());
    assertEquals(InMemoryTrustGraphStore.DEFAULT_MAX_ANCHORS, store.config().maxAnchors());
  }

  @Test
  void importStatement_whenSourceUriIsNotCryptaContent_expectRejection() {
    InMemoryTrustGraphStore store = new InMemoryTrustGraphStore(Clock.fixed(NOW, ZoneOffset.UTC));
    TrustStatementDocument document = signedStatement(80, 50, "2026-05-16T00:00:00Z", null);

    TrustGraphException exception =
        assertThrows(
            TrustGraphException.class,
            () -> store.importStatement(document, "manual", "/tmp/trust.json", null));

    assertEquals("invalid_trust_statement", exception.errorCode());
  }

  @Test
  void importStatement_whenCryptaSourceUriIsValid_expectNormalizedScheme() {
    InMemoryTrustGraphStore store = new InMemoryTrustGraphStore(Clock.fixed(NOW, ZoneOffset.UTC));
    TrustStatementDocument document = signedStatement(80, 50, "2026-05-16T00:00:00Z", null);

    TrustGraphImportResult result =
        store.importStatement(document, "fetched", "Crypta:CHK@trust-statement", null);

    assertTrue(result.sourceUri().startsWith("CHK@sha256:"));
    assertEquals(64, result.sourceUriHash().length());
    assertEquals(result.sourceUri(), store.statements().getFirst().sourceUri());
    assertEquals(result.sourceUriHash(), store.statements().getFirst().sourceUriHash());
    assertFalse(result.sourceUri().contains("trust-statement"));
  }

  @Test
  void importStatement_whenCryptaSourceUriWrapsUnsupportedSource_expectRejection() {
    InMemoryTrustGraphStore store = new InMemoryTrustGraphStore(Clock.fixed(NOW, ZoneOffset.UTC));
    TrustStatementDocument document = signedStatement(80, 50, "2026-05-16T00:00:00Z", null);

    for (String sourceUri :
        List.of(
            "crypta:file:///tmp/key",
            "crypta:http://example.invalid/key",
            "crypta: CHK@trust-statement",
            "crypta:CHK@trust statement",
            "crypta:CHK@trust?token=secret")) {
      TrustGraphException exception =
          assertThrows(
              TrustGraphException.class,
              () -> store.importStatement(document, "fetched", sourceUri, null));
      assertEquals("invalid_trust_statement", exception.errorCode());
    }
  }

  @Test
  void score_whenManyStatementsMatch_expectEvidenceRowsAreBoundedButCountPreserved() {
    InMemoryTrustGraphStore store = new InMemoryTrustGraphStore(Clock.fixed(NOW, ZoneOffset.UTC));
    for (int index = 0; index < 30; index++) {
      store.importStatement(
          signedStatement(10, 10, "2026-05-16T00:00:00Z", null), "fetched", null, null);
    }

    TrustGraphScore score = scorer(store).score(query());

    assertEquals(30, score.evidenceCount());
    assertEquals(25, score.evidence().size());
    assertEquals(0, score.contributingEvidenceCount());
    assertTrue(score.evidenceTruncated());
    assertEquals(25, score.maxEvidenceRows());
  }

  private static TrustGraphScorer scorer(TrustGraphStore store) {
    return new TrustGraphScorer(store, Clock.fixed(NOW, ZoneOffset.UTC));
  }

  private static TrustGraphQuery query() {
    return new TrustGraphQuery(TrustSubjectKind.PROFILE, "USK@example/profile.json", "profile");
  }

  private static TrustGraphAuditEvent auditEvent(
      String eventType, Instant timestamp, String status) {
    return new TrustGraphAuditEvent(
        eventType,
        timestamp,
        "trust-graph",
        "document-" + status,
        "payload-" + status,
        "issuer-" + status,
        "profile",
        TrustStatementFingerprint.sha256Hex(
            ("USK@subject-" + status).getBytes(java.nio.charset.StandardCharsets.UTF_8)),
        "USK@sha256:0123456789abcdef",
        "manual",
        null,
        null,
        Boolean.TRUE,
        status);
  }

  private static TrustStatementDocument signedStatement(
      int score, int confidence, String issuedAt, String expiresAt) {
    try {
      KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
      String publicKeyBase64 = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
      String fingerprint = TrustStatementFingerprint.sha256Hex(keyPair.getPublic().getEncoded());
      TrustStatementPayload payload =
          new TrustStatementPayload(
              new TrustIssuer(
                  "issuer-" + fingerprint.substring(0, 12), fingerprint, publicKeyBase64, null),
              new TrustSubject(TrustSubjectKind.PROFILE, "USK@example/profile.json", null),
              "profile",
              score,
              confidence,
              null,
              List.of(),
              Instant.parse(issuedAt),
              expiresAt == null ? null : Instant.parse(expiresAt));
      Signature signer = Signature.getInstance("Ed25519");
      signer.initSign(keyPair.getPrivate());
      signer.update(TrustStatementCanonicalizer.canonicalPayloadBytes(payload));
      return new TrustStatementDocument(
          TrustDocumentTypes.TRUST_STATEMENT_V1,
          payload,
          new TrustSignatureEnvelope(
              TrustDocumentTypes.APP_VAULT_ED25519_PREVIEW_ALGORITHM,
              TrustDocumentTypes.TRUST_STATEMENT_V1,
              Base64.getEncoder().encodeToString(signer.sign())));
    } catch (GeneralSecurityException exception) {
      throw new AssertionError("Failed to create signed trust statement fixture.", exception);
    }
  }

  private static String fingerprint(TrustStatementDocument document) {
    return document.payload().issuer().publicKeyFingerprint();
  }
}
