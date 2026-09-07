package network.crypta.platform.trustgraph;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class TrustStatementVerifierTest {
  @Test
  void isSignatureVerified_whenStatementIsSignedByIssuerKey_expectTrue()
      throws GeneralSecurityException {
    SignedFixture fixture = signedFixture();

    boolean verified = TrustStatementVerifier.isSignatureVerified(fixture.document());

    assertTrue(verified);
  }

  @Test
  void isSignatureVerified_whenIssuerPublicKeyMissing_expectFalse()
      throws GeneralSecurityException {
    SignedFixture fixture = signedFixture();
    TrustStatementDocument withoutPublicKey =
        documentWithIssuer(fixture.document(), issuerWithoutPublicKey(fixture.document()));

    boolean verified = TrustStatementVerifier.isSignatureVerified(withoutPublicKey);

    assertFalse(verified);
  }

  @Test
  void isSignatureVerified_whenIssuerFingerprintDoesNotMatchKey_expectFalse()
      throws GeneralSecurityException {
    SignedFixture fixture = signedFixture();
    TrustStatementDocument wrongFingerprint =
        documentWithIssuer(
            fixture.document(),
            new TrustIssuer(
                "issuer-1",
                "wrong-fingerprint",
                fixture.document().payload().issuer().publicKeyBase64(),
                null));

    boolean verified = TrustStatementVerifier.isSignatureVerified(wrongFingerprint);

    assertFalse(verified);
  }

  @Test
  void isSignatureVerified_whenPayloadChangesAfterSigning_expectFalse()
      throws GeneralSecurityException {
    SignedFixture fixture = signedFixture();
    TrustStatementPayload payload = fixture.document().payload();
    TrustStatementDocument tampered =
        new TrustStatementDocument(
            fixture.document().type(),
            new TrustStatementPayload(
                payload.issuer(),
                payload.subject(),
                payload.context(),
                payload.score() + 1,
                payload.confidence(),
                payload.reason(),
                payload.tags(),
                payload.issuedAt(),
                payload.expiresAt()),
            fixture.document().signature());

    boolean verified = TrustStatementVerifier.isSignatureVerified(tampered);

    assertFalse(verified);
  }

  @Test
  void isSignatureVerified_whenSignatureIsMalformedBase64_expectFalse()
      throws GeneralSecurityException {
    SignedFixture fixture = signedFixture();
    TrustStatementDocument malformedSignature =
        new TrustStatementDocument(
            fixture.document().type(),
            fixture.document().payload(),
            new TrustSignatureEnvelope(
                TrustDocumentTypes.APP_VAULT_ED25519_PREVIEW_ALGORITHM,
                TrustDocumentTypes.TRUST_STATEMENT_V1,
                "not-base64!"));

    boolean verified = TrustStatementVerifier.isSignatureVerified(malformedSignature);

    assertFalse(verified);
  }

  @Test
  void parse_whenLoneSurrogateInSignedReason_expectRejectedBeforeUtf8Replacement()
      throws GeneralSecurityException {
    SignedFixture fixture = signedFixture();
    String json = TrustJson.write(fixture.document().toJson());
    String malformed = json.replace("known publisher", "\\uD800");

    assertThrows(TrustGraphException.class, () -> TrustStatementParser.parse(malformed));
  }

  @Test
  void construct_whenLoneSurrogateInReason_expectRejectedBeforeSigning()
      throws GeneralSecurityException {
    TrustStatementPayload payload = signedFixture().document().payload();
    TrustIssuer issuer = payload.issuer();
    TrustSubject subject = payload.subject();
    String context = payload.context();
    int score = payload.score();
    int confidence = payload.confidence();
    String malformedReason = String.valueOf((char) 0xD800);
    List<String> tags = payload.tags();
    Instant issuedAt = payload.issuedAt();
    Instant expiresAt = payload.expiresAt();

    assertThrows(
        TrustGraphException.class,
        () ->
            new TrustStatementPayload(
                issuer,
                subject,
                context,
                score,
                confidence,
                malformedReason,
                tags,
                issuedAt,
                expiresAt));
  }

  @Test
  void parse_whenHistoricalWhitespaceAndTimestampAliasesUsed_expectCanonicalSignatureStillValid()
      throws GeneralSecurityException {
    SignedFixture fixture = signedFixture();
    String lexicalAlias =
        TrustJson.write(fixture.document().toJson())
            .replace("known publisher", " known publisher ")
            .replace("2026-05-16T00:00:00Z", "2026-05-16T01:00:00+01:00");

    TrustStatementDocument parsed = TrustStatementParser.parse(lexicalAlias);

    assertTrue(TrustStatementVerifier.isSignatureVerified(parsed));
  }

  private static SignedFixture signedFixture() throws GeneralSecurityException {
    KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    String publicKeyBase64 = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
    String fingerprint = TrustStatementFingerprint.sha256Hex(keyPair.getPublic().getEncoded());
    TrustStatementPayload payload =
        new TrustStatementPayload(
            new TrustIssuer("issuer-1", fingerprint, publicKeyBase64, null),
            new TrustSubject(TrustSubjectKind.PROFILE, "USK@example/profile.json", null),
            "profile",
            50,
            80,
            "known publisher",
            List.of("local"),
            Instant.parse("2026-05-16T00:00:00Z"),
            Instant.parse("2026-11-16T00:00:00Z"));
    Signature signer = Signature.getInstance("Ed25519");
    signer.initSign(keyPair.getPrivate());
    signer.update(TrustStatementCanonicalizer.canonicalPayloadBytes(payload));
    TrustStatementDocument document =
        new TrustStatementDocument(
            TrustDocumentTypes.TRUST_STATEMENT_V1,
            payload,
            new TrustSignatureEnvelope(
                TrustDocumentTypes.APP_VAULT_ED25519_PREVIEW_ALGORITHM,
                TrustDocumentTypes.TRUST_STATEMENT_V1,
                Base64.getEncoder().encodeToString(signer.sign())));
    return new SignedFixture(document);
  }

  private static TrustStatementDocument documentWithIssuer(
      TrustStatementDocument source, TrustIssuer issuer) {
    TrustStatementPayload payload = source.payload();
    return new TrustStatementDocument(
        source.type(),
        new TrustStatementPayload(
            issuer,
            payload.subject(),
            payload.context(),
            payload.score(),
            payload.confidence(),
            payload.reason(),
            payload.tags(),
            payload.issuedAt(),
            payload.expiresAt()),
        source.signature());
  }

  private static TrustIssuer issuerWithoutPublicKey(TrustStatementDocument document) {
    TrustIssuer issuer = document.payload().issuer();
    return new TrustIssuer(issuer.identityId(), issuer.publicKeyFingerprint(), null);
  }

  private record SignedFixture(TrustStatementDocument document) {}
}
