package network.crypta.platform.trustgraph;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TrustStatementConformanceTest {
  @Test
  void fixedCorpus_whenParsedAndVerified_expectIndependentCanonicalAndPreimageBytes()
      throws IOException {
    Map<?, ?> manifest = ConformanceManifest.read();
    var seen = new HashSet<String>();
    for (Object raw : (List<?>) manifest.get("cases")) {
      Map<?, ?> row = (Map<?, ?>) raw;
      if (!"crypta.trust.statement.v1".equals(row.get("profileId"))) continue;
      String caseId = (String) row.get("caseId");
      assertTrue(seen.add(caseId), "Duplicate trust case");
      byte[] input = corpusBytes((String) row.get("inputFile"));
      assertEquals(((Number) row.get("inputSize")).longValue(), input.length, caseId);
      assertEquals(row.get("inputDigest"), sha256(input), caseId);
      byte[] expected = corpusBytes((String) row.get("expectedCanonicalBytesFile"));
      assertEquals(row.get("expectedCanonicalDigest"), sha256(expected), caseId);
      var document = TrustStatementParser.parse(new String(input, StandardCharsets.UTF_8));

      assertEquals("accepted", row.get("expectedParseOutcome"), caseId);
      assertArrayEquals(
          expected,
          TrustStatementCanonicalizer.canonicalPayloadJson(document.payload())
              .getBytes(StandardCharsets.UTF_8),
          caseId);
      assertArrayEquals(
          corpusBytes((String) row.get("expectedSignaturePreimageFile")),
          TrustStatementCanonicalizer.canonicalPayloadBytes(document.payload()),
          caseId);
      assertEquals("verified", row.get("expectedSignatureOutcome"), caseId);
      assertTrue(TrustStatementVerifier.isSignatureVerified(document), caseId);
      assertEquals(
          "expired".equals(row.get("expectedPolicyOutcome")),
          document.payload().expiredAt(Instant.parse((String) row.get("evaluationTime"))),
          caseId);
    }
    assertEquals(java.util.Set.of("trust-minimal", "trust-unicode", "trust-expired"), seen);
  }

  @Test
  void fixedCorpus_whenSignedValueOrFingerprintChanged_expectVerificationFailure()
      throws IOException {
    String original = text("minimal.json");
    var wrongScore = TrustStatementParser.parse(original.replace("\"score\":0", "\"score\":1"));
    String fingerprint =
        TrustStatementParser.parse(original).payload().issuer().publicKeyFingerprint();
    var wrongFingerprint =
        TrustStatementParser.parse(original.replace(fingerprint, "0".repeat(64)));

    assertFalse(TrustStatementVerifier.isSignatureVerified(wrongScore));
    assertFalse(TrustStatementVerifier.isSignatureVerified(wrongFingerprint));
  }

  @Test
  void fixedCorpus_whenDuplicateNullUnknownFractionOrVersionChanged_expectParseFailure()
      throws IOException {
    String original = text("minimal.json");
    for (String invalid :
        List.of(
            original.replace("\"score\":0", "\"score\":0,\"score\":1"),
            original.replace("\"score\":0", "\"score\":null"),
            original.replace("\"score\":0", "\"score\":0,\"unknown\":1"),
            original.replace("\"score\":0", "\"score\":1e0"),
            original.replace("crypta.trust.statement.v1", "crypta.trust.statement.v2"),
            original.replace("synthetic-public-subject", "\\uD800"))) {
      assertThrows(TrustGraphException.class, () -> TrustStatementParser.parse(invalid));
    }
  }

  @Test
  void fixedCorpus_whenIntegerLexicalsCrossNumericLimits_expectBoundedStrictNumbers()
      throws IOException {
    String original = text("minimal.json");
    for (String score : List.of("-100", "0", "100")) {
      var parsed =
          TrustStatementParser.parse(original.replace("\"score\":0", "\"score\":" + score));
      assertEquals(Integer.parseInt(score), parsed.payload().score());
    }
    for (String score :
        List.of(
            "-101",
            "101",
            "2147483647",
            "2147483648",
            "9007199254740991",
            "9007199254740992",
            "9223372036854775807",
            "9223372036854775808",
            "-9223372036854775809",
            "0.0",
            "1e0")) {
      String changed = original.replace("\"score\":0", "\"score\":" + score);
      assertThrows(TrustGraphException.class, () -> TrustStatementParser.parse(changed));
    }
  }

  @Test
  void fixedCorpus_whenExpiryCrossesNanosecondBoundary_expectSignatureIndependentPolicy()
      throws IOException {
    var parsed = TrustStatementParser.parse(text("expired.json"));
    Instant expiry = parsed.payload().expiresAt();
    assertTrue(TrustStatementVerifier.isSignatureVerified(parsed));
    assertFalse(parsed.payload().expiredAt(expiry.minusNanos(1)));
    assertTrue(parsed.payload().expiredAt(expiry));
    assertTrue(parsed.payload().expiredAt(expiry.plusNanos(1)));
  }

  private static String text(String name) throws IOException {
    return new String(bytes(name), StandardCharsets.UTF_8);
  }

  private static String sha256(byte[] value) {
    try {
      return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value));
    } catch (NoSuchAlgorithmException exception) {
      throw new AssertionError(exception);
    }
  }

  private static byte[] bytes(String name) throws IOException {
    return corpusBytes("trust/" + name);
  }

  private static byte[] corpusBytes(String name) throws IOException {
    assertFalse(name.contains(".."));
    assertFalse(name.startsWith("/"));
    try (var resource =
        TrustStatementConformanceTest.class.getResourceAsStream(
            "/content-profile-conformance/v1/" + name)) {
      return java.util.Objects.requireNonNull(resource, name).readAllBytes();
    }
  }
}
