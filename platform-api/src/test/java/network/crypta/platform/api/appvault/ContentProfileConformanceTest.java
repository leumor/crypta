package network.crypta.platform.api.appvault;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import network.crypta.platform.api.PlatformApiException;
import network.crypta.platform.api.contentformats.CanonicalJson;
import network.crypta.platform.appvault.AppIdentityGrantScope;
import network.crypta.platform.appvault.AppIdentityKind;
import network.crypta.platform.appvault.AppIdentityRecord;
import network.crypta.platform.appvault.AppIdentityUsageRequest;
import network.crypta.platform.appvault.AppIdentityUsageResult;
import network.crypta.platform.appvault.AppVaultException;
import network.crypta.platform.appvault.AppVaultService;
import network.crypta.platform.trustgraph.ConformanceManifest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ContentProfileConformanceTest {
  private static final String IDENTITY = "conformance-public-identity";
  private static final String PUBLIC_KEY =
      "302a300506032b6570032100d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
  // Public RFC 8032 section 7.1 test-1 seed. Never an operational identity.
  private static final String PRIVATE_KEY =
      "302e020100300506032b6570042204209d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
  private static final String FINGERPRINT =
      "06e3fd8fda29bb60ab59557de61edb0aecdb231134be30e75b455f8e1b792fa9";

  @Test
  void profileBuilderPreservesIndependentUnicodeAndSignatureVector() throws Exception {
    ProfileDocumentRequest request =
        ProfileDocumentRequest.fromQuery(
            "profile-publisher",
            IDENTITY,
            Map.of(
                "displayName",
                List.of("Synthetic Ålice 🚀 é"),
                "bio",
                List.of("Line one\nLine two"),
                "tags",
                List.of("second,first,second")));
    assertArrayEquals(vector("profile/canonical.json"), request.canonicalBytes());
    String preimage =
        "CryptaAppVault:v1:profile-publisher:"
            + IDENTITY
            + ":profile.publish.v1:"
            + hash(request.canonicalBytes());
    assertArrayEquals(vector("profile/preimage.bin"), preimage.getBytes(StandardCharsets.UTF_8));
    AppIdentityUsageResult usage = usage(request.canonicalBytes(), preimage);
    assertArrayEquals(
        vector("profile/document.json"),
        CanonicalJson.bytes(
            SignedProfileDocumentBuilder.build(request, identity("profile-publisher"), usage)));
    verifyAndRejectMutation(preimage.getBytes(StandardCharsets.UTF_8), usage.signatureBase64());
  }

  @Test
  void socialBuilderPreservesIndependentMessageIdAndSignatureVector() throws Exception {
    SocialMessageRequest request =
        SocialMessageRequest.fromQuery(
            "social-inbox",
            IDENTITY,
            FINGERPRINT,
            Map.of("body", List.of("Synthetic Ålice 🚀 é\n\t\"quoted\" \\")),
            Clock.fixed(Instant.parse("2026-06-01T00:00:00Z"), ZoneOffset.UTC));
    assertArrayEquals(vector("social/preimage.bin"), request.canonicalBytes());
    assertEquals(
        "crypta.social.message.v1\n"
            + new String(vector("social/canonical.json"), StandardCharsets.UTF_8),
        new String(request.canonicalBytes(), StandardCharsets.UTF_8));
    String preimage = new String(request.canonicalBytes(), StandardCharsets.UTF_8);
    AppIdentityUsageResult usage = usage(request.canonicalBytes(), preimage);
    assertArrayEquals(
        vector("social/document.json"),
        CanonicalJson.bytes(
            SignedSocialMessageDocumentBuilder.build(request, identity("social-inbox"), usage)));
    verifyAndRejectMutation(request.canonicalBytes(), usage.signatureBase64());
  }

  @Test
  void manifestGenerationCasesPreserveAllOptionalFieldsAtTheirLimits() throws Exception {
    Set<String> executed = new HashSet<>();
    for (Object value : (List<?>) ConformanceManifest.read().get("cases")) {
      Map<?, ?> row = (Map<?, ?>) value;
      if (!(row.get("generatorQuery") instanceof Map<?, ?> rawQuery)) {
        continue;
      }
      Map<String, List<String>> query = new LinkedHashMap<>();
      for (Map.Entry<?, ?> entry : rawQuery.entrySet()) {
        query.put(
            (String) entry.getKey(),
            ((List<?>) entry.getValue()).stream().map(String.class::cast).toList());
      }
      byte[] expectedPreimage = vector((String) row.get("expectedSignaturePreimageFile"));
      Map<String, Object> document;
      if (row.get("profileId").equals("crypta.profile.v1")) {
        ProfileDocumentRequest request =
            ProfileDocumentRequest.fromQuery("profile-publisher", IDENTITY, query);
        assertArrayEquals(
            vector((String) row.get("expectedCanonicalBytesFile")), request.canonicalBytes());
        String preimage =
            "CryptaAppVault:v1:profile-publisher:"
                + IDENTITY
                + ":profile.publish.v1:"
                + hash(request.canonicalBytes());
        assertArrayEquals(expectedPreimage, preimage.getBytes(StandardCharsets.UTF_8));
        document =
            SignedProfileDocumentBuilder.build(
                request, identity("profile-publisher"), usage(request.canonicalBytes(), preimage));
      } else {
        SocialMessageRequest request = social(query, IDENTITY, FINGERPRINT);
        assertArrayEquals(expectedPreimage, request.canonicalBytes());
        assertEquals(row.get("expectedMessageId"), request.messageId());
        document =
            SignedSocialMessageDocumentBuilder.build(
                request,
                identity("social-inbox"),
                usage(
                    request.canonicalBytes(),
                    new String(expectedPreimage, StandardCharsets.UTF_8)));
      }
      assertArrayEquals(vector((String) row.get("inputFile")), CanonicalJson.bytes(document));
      executed.add((String) row.get("caseId"));
    }
    assertEquals(
        Set.of(
            "profile-minimal",
            "profile-maximal-optionals",
            "social-maximal-optionals",
            "profile-unicode-whitespace-tags"),
        executed);
  }

  @Test
  void manifestBindsEveryInputAndGoldenToUniqueCaseIdentity() throws Exception {
    Map<?, ?> manifest = ConformanceManifest.read();
    assertEquals(1L, manifest.get("schemaVersion"));
    Set<String> ids = new HashSet<>();
    Set<String> profiles = new HashSet<>();
    for (Object value : (List<?>) manifest.get("cases")) {
      Map<?, ?> row = (Map<?, ?>) value;
      assertTrue(ids.add((String) row.get("caseId")), "Duplicate corpus case");
      profiles.add((String) row.get("profileId"));
      byte[] input = vector((String) row.get("inputFile"));
      assertEquals(((Number) row.get("inputSize")).longValue(), input.length);
      assertEquals(row.get("inputDigest"), hash(input));
      if (row.containsKey("expectedCanonicalBytesFile")) {
        assertEquals(
            row.get("expectedCanonicalDigest"),
            hash(vector((String) row.get("expectedCanonicalBytesFile"))));
      }
    }
    assertEquals(
        Set.of(
            "crypta.profile.v1",
            "crypta.feed.snapshot.v1",
            "crypta.trust.statement.v1",
            "crypta.social.message.v1",
            "crypta.social.outbox.v1"),
        profiles);
    assertTrue(ids.contains("profile-unicode-ordered"));
    assertTrue(ids.contains("social-unicode-ordered"));
  }

  @Test
  void realVaultSignsProfileFramingAndRejectsUngrantableUse(@TempDir Path temporary)
      throws Exception {
    AppVaultService vault = AppVaultService.open(temporary.resolve("vault"));
    AppIdentityRecord identity =
        vault.createOperatorIdentity(
            AppIdentityKind.LOCAL_ED25519_SIGNING,
            "Synthetic isolated runtime",
            null,
            Set.of(AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED));
    ProfileDocumentRequest request =
        ProfileDocumentRequest.fromQuery(
            "profile-publisher",
            identity.identityId(),
            Map.of("displayName", List.of("Synthetic")));
    AppIdentityUsageRequest operation =
        new AppIdentityUsageRequest(
            "profile-publisher",
            identity.identityId(),
            AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED,
            "profile.publish.v1",
            request.canonicalBytes());
    assertThrows(AppVaultException.class, () -> vault.useIdentity(operation));
    vault.grantIdentity(
        identity.identityId(),
        "profile-publisher",
        Set.of(AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED),
        "operator",
        "synthetic conformance",
        null,
        null);
    AppIdentityUsageResult result = vault.useIdentity(operation);
    String expected =
        "CryptaAppVault:v1:profile-publisher:"
            + identity.identityId()
            + ":profile.publish.v1:"
            + hash(request.canonicalBytes());
    assertEquals(expected, result.domainSeparatedPayload());
    assertEquals(hash(request.canonicalBytes()), result.payloadSha256());
    Signature verifier = Signature.getInstance("Ed25519");
    byte[] key = Base64.getDecoder().decode(result.publicKeyBase64());
    assertEquals(identity.fingerprint(), hash(key));
    verifier.initVerify(
        KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(key)));
    verifier.update(expected.getBytes(StandardCharsets.UTF_8));
    assertTrue(verifier.verify(Base64.getDecoder().decode(result.signatureBase64())));
    verifier.update(request.canonicalBytes());
    assertFalse(verifier.verify(Base64.getDecoder().decode(result.signatureBase64())));
    assertEquals(
        request.payload(),
        SignedProfileDocumentBuilder.build(request, identity, result).get("profile"));
  }

  @Test
  void realVaultSignsSocialPreimageWithoutProfileWrapping(@TempDir Path temporary)
      throws Exception {
    AppVaultService vault = AppVaultService.open(temporary.resolve("vault"));
    AppIdentityRecord identity =
        vault.createOperatorIdentity(
            AppIdentityKind.LOCAL_ED25519_SIGNING,
            "Synthetic isolated runtime",
            null,
            Set.of(AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED));
    vault.grantIdentity(
        identity.identityId(),
        "social-inbox",
        Set.of(AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED),
        "operator",
        "synthetic conformance",
        null,
        null);
    SocialMessageRequest request =
        social(
            Map.of("body", List.of("Public synthetic body")),
            identity.identityId(),
            identity.fingerprint());
    AppIdentityUsageRequest operation =
        new AppIdentityUsageRequest(
            "social-inbox",
            identity.identityId(),
            AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED,
            "crypta.social.message.v1",
            request.canonicalBytes());
    AppIdentityUsageResult result = vault.signDomainSeparatedPayload(operation);
    assertEquals(
        new String(request.canonicalBytes(), StandardCharsets.UTF_8),
        result.domainSeparatedPayload());
    Signature verifier = Signature.getInstance("Ed25519");
    verifier.initVerify(
        KeyFactory.getInstance("Ed25519")
            .generatePublic(
                new X509EncodedKeySpec(Base64.getDecoder().decode(result.publicKeyBase64()))));
    verifier.update(request.canonicalBytes());
    assertTrue(verifier.verify(Base64.getDecoder().decode(result.signatureBase64())));
    verifier.update(
        ("CryptaAppVault:v1:social-inbox:"
                + identity.identityId()
                + ":crypta.social.message.v1:"
                + result.payloadSha256())
            .getBytes(StandardCharsets.UTF_8));
    assertFalse(verifier.verify(Base64.getDecoder().decode(result.signatureBase64())));
  }

  @ParameterizedTest
  @ValueSource(strings = {"displayName", "bio", "website", "avatarUri", "contactUri"})
  void profileFieldBoundariesCountUtf16Units(String field) {
    int limit = field.equals("displayName") ? 80 : 512;
    Map<String, List<String>> input = new LinkedHashMap<>();
    input.put("displayName", List.of("Synthetic"));
    for (int length : new int[] {limit - 1, limit}) {
      input.put(field, List.of("é".repeat(length)));
      assertEquals(
          length,
          ((String)
                  ProfileDocumentRequest.fromQuery("profile-publisher", IDENTITY, input)
                      .payload()
                      .get(field))
              .length());
    }
    input.put(field, List.of("é".repeat(limit + 1)));
    assertThrows(
        PlatformApiException.class,
        () -> ProfileDocumentRequest.fromQuery("profile-publisher", IDENTITY, input));
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "authorLabel",
        "profileUri",
        "channel",
        "subject",
        "body",
        "replyTo",
        "recipientFingerprint"
      })
  void socialFieldBoundariesRejectOnlyAboveLimit(String field) {
    int limit =
        switch (field) {
          case "authorLabel" -> 80;
          case "profileUri", "replyTo" -> 512;
          case "channel" -> 64;
          case "subject" -> 160;
          case "body" -> 4096;
          default -> 128;
        };
    Map<String, List<String>> input = new LinkedHashMap<>();
    input.put("body", List.of("Synthetic"));
    for (int length : new int[] {limit - 1, limit}) {
      input.put(field, List.of("é".repeat(length)));
      assertEquals(
          length, ((String) social(input, IDENTITY, FINGERPRINT).message().get(field)).length());
    }
    input.put(field, List.of("é".repeat(limit + 1)));
    assertThrows(PlatformApiException.class, () -> social(input, IDENTITY, FINGERPRINT));
  }

  @Test
  void absentAndBlankOptionalsProduceFixedMinimalProfileBytes() {
    ProfileDocumentRequest request =
        ProfileDocumentRequest.fromQuery(
            "profile-publisher",
            IDENTITY,
            Map.of(
                "displayName", List.of("  Synthetic  "), "bio", List.of(" "), "tags", List.of("")));
    assertEquals(
        "{\"schema\":\"crypta.profile.v1\",\"appId\":\"profile-publisher\",\"identityId\":\"conformance-public-identity\",\"displayName\":\"Synthetic\"}",
        new String(request.canonicalBytes(), StandardCharsets.UTF_8));
  }

  @ParameterizedTest
  @ValueSource(strings = {"bad,,tag", "bad,", "x,x,x,x,x,x,x,x,x,x,x,x,x,x,x,x,x"})
  void profileRejectsMalformedOrTooManyTags(String tags) {
    Map<String, List<String>> input =
        Map.of("displayName", List.of("Synthetic"), "tags", List.of(tags));
    assertThrows(
        PlatformApiException.class,
        () -> ProfileDocumentRequest.fromQuery("profile-publisher", IDENTITY, input));
  }

  @ParameterizedTest
  @ValueSource(strings = {"purpose", "schema", "identityId", "payloadBase64", "appId"})
  void signingRequestsRejectCallerEnvelopeFields(String field) {
    Map<String, List<String>> profileInput =
        Map.of("displayName", List.of("Synthetic"), field, List.of("forged"));
    Map<String, List<String>> socialInput =
        Map.of("body", List.of("Synthetic"), field, List.of("forged"));
    assertThrows(
        PlatformApiException.class,
        () -> ProfileDocumentRequest.fromQuery("profile-publisher", IDENTITY, profileInput));
    assertThrows(PlatformApiException.class, () -> social(socialInput, IDENTITY, FINGERPRINT));
  }

  @ParameterizedTest
  @ValueSource(ints = {0xD800, 0xDC00, 0xDBFF})
  void malformedSurrogatesCannotBeSilentlyReplacedBeforeSigning(int codeUnit) {
    String malformed = Character.toString((char) codeUnit);
    Map<String, List<String>> displayNameInput = Map.of("displayName", List.of(malformed));
    Map<String, List<String>> bioInput =
        Map.of("displayName", List.of("Synthetic"), "bio", List.of(malformed));
    Map<String, List<String>> bodyInput = Map.of("body", List.of(malformed));
    Map<String, List<String>> subjectInput =
        Map.of("body", List.of("Synthetic"), "subject", List.of(malformed));
    assertThrows(
        PlatformApiException.class,
        () -> ProfileDocumentRequest.fromQuery("profile-publisher", IDENTITY, displayNameInput));
    assertThrows(
        PlatformApiException.class,
        () -> ProfileDocumentRequest.fromQuery("profile-publisher", IDENTITY, bioInput));
    assertThrows(PlatformApiException.class, () -> social(bodyInput, IDENTITY, FINGERPRINT));
    assertThrows(PlatformApiException.class, () -> social(subjectInput, IDENTITY, FINGERPRINT));
  }

  private static SocialMessageRequest social(
      Map<String, List<String>> input, String identity, String fingerprint) {
    return SocialMessageRequest.fromQuery(
        "social-inbox",
        identity,
        fingerprint,
        input,
        Clock.fixed(Instant.parse("2026-06-01T00:00:00Z"), ZoneOffset.UTC));
  }

  private static AppIdentityUsageResult usage(byte[] payload, String preimage) throws Exception {
    Signature signer = Signature.getInstance("Ed25519");
    signer.initSign(
        KeyFactory.getInstance("Ed25519")
            .generatePrivate(new PKCS8EncodedKeySpec(HexFormat.of().parseHex(PRIVATE_KEY))));
    signer.update(preimage.getBytes(StandardCharsets.UTF_8));
    return new AppIdentityUsageResult(
        IDENTITY,
        AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED,
        "Ed25519",
        FINGERPRINT,
        Base64.getEncoder().encodeToString(HexFormat.of().parseHex(PUBLIC_KEY)),
        hash(payload),
        preimage,
        Base64.getEncoder().encodeToString(signer.sign()));
  }

  private static AppIdentityRecord identity(String appId) {
    return new AppIdentityRecord(
        IDENTITY,
        AppIdentityKind.LOCAL_ED25519_SIGNING,
        "Synthetic public vector",
        appId,
        Instant.EPOCH,
        Instant.EPOCH,
        Map.of(),
        FINGERPRINT,
        Set.of(AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED));
  }

  private static void verifyAndRejectMutation(byte[] preimage, String signature) throws Exception {
    byte[] publicKey = HexFormat.of().parseHex(PUBLIC_KEY);
    assertEquals(FINGERPRINT, hash(publicKey));
    Signature verifier = Signature.getInstance("Ed25519");
    verifier.initVerify(
        KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(publicKey)));
    verifier.update(preimage);
    assertTrue(verifier.verify(Base64.getDecoder().decode(signature)));
    byte[] changed = preimage.clone();
    changed[changed.length - 1] ^= 1;
    verifier.update(changed);
    assertFalse(verifier.verify(Base64.getDecoder().decode(signature)));
  }

  private static String hash(byte[] bytes) throws Exception {
    return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
  }

  private static byte[] vector(String name) throws Exception {
    try (var stream =
        ContentProfileConformanceTest.class.getResourceAsStream(
            "/content-profile-conformance/v1/" + name)) {
      if (stream == null) {
        throw new IllegalStateException("Missing public conformance resource");
      }
      return stream.readAllBytes();
    }
  }
}
