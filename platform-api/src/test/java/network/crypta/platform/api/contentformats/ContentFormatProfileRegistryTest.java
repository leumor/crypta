package network.crypta.platform.api.contentformats;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import network.crypta.platform.api.content.ContentFetchPolicy;
import network.crypta.platform.trustgraph.TrustDocumentTypes;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class ContentFormatProfileRegistryTest {
  private static final String EXPECTED_PROFILE_DOCUMENT_ID = "crypta.profile.v1";
  private static final String EXPECTED_FEED_SNAPSHOT_ID = "crypta.feed.snapshot.v1";
  private static final String EXPECTED_TRUST_STATEMENT_ID = "crypta.trust.statement.v1";
  private static final String EXPECTED_SOCIAL_MESSAGE_ID = "crypta.social.message.v1";
  private static final String EXPECTED_SOCIAL_OUTBOX_ID = "crypta.social.outbox.v1";
  private static final String APPLICATION_JSON = "application/json";
  private static final String EXAMPLE_PROFILE_ID = "crypta.example.v1";

  @Test
  void profiles_whenListed_expectAllFirstPartyFormatDescriptorsInStableOrder() {
    List<ContentFormatProfile> profiles = ContentFormatProfileRegistry.profiles();

    assertEquals(
        List.of(
            EXPECTED_PROFILE_DOCUMENT_ID,
            EXPECTED_FEED_SNAPSHOT_ID,
            EXPECTED_TRUST_STATEMENT_ID,
            EXPECTED_SOCIAL_MESSAGE_ID,
            EXPECTED_SOCIAL_OUTBOX_ID,
            "crypta.mail.envelope.v1"),
        profiles.stream().map(ContentFormatProfile::id).toList());
    assertEquals(6, profiles.stream().map(ContentFormatProfile::id).distinct().count());
    assertTrue(profiles.stream().allMatch(profile -> profile.majorVersion() == 1));
    assertTrue(
        profiles.stream()
            .allMatch(
                profile ->
                    "reject_unknown_fields".equals(profile.versionPolicy().unknownFieldPolicy())));
  }

  @Test
  void profiles_whenMappedById_expectMimeFilenameSigningAndBounds() {
    Map<String, ContentFormatProfile> byId =
        ContentFormatProfileRegistry.profiles().stream()
            .collect(Collectors.toUnmodifiableMap(ContentFormatProfile::id, profile -> profile));

    assertProfile(
        byId.get(EXPECTED_PROFILE_DOCUMENT_ID),
        "application/vnd.crypta.profile+json",
        "profile.json",
        true,
        "profile.publish.v1",
        32 * 1024);
    assertProfile(
        byId.get(EXPECTED_FEED_SNAPSHOT_ID),
        "application/vnd.crypta.feed+json",
        "feed.json",
        false,
        null,
        null);
    assertProfile(
        byId.get(EXPECTED_TRUST_STATEMENT_ID),
        "application/vnd.crypta.trust+json",
        "trust.json",
        true,
        EXPECTED_TRUST_STATEMENT_ID,
        32 * 1024);
    assertProfile(
        byId.get(EXPECTED_SOCIAL_MESSAGE_ID),
        APPLICATION_JSON,
        null,
        true,
        EXPECTED_SOCIAL_MESSAGE_ID,
        32 * 1024);
    assertProfile(
        byId.get(EXPECTED_SOCIAL_OUTBOX_ID),
        "application/vnd.crypta.social.outbox+json",
        "social-outbox.json",
        false,
        null,
        null);
  }

  @Test
  void trustDocumentTypes_whenComparedWithRegistry_expectNoIdentifierDrift() {
    ContentFormatProfile profile = ContentFormatProfileRegistry.TRUST_STATEMENT;

    assertEquals(TrustDocumentTypes.TRUST_STATEMENT_V1, profile.id());
    assertEquals(TrustDocumentTypes.TRUST_STATEMENT_V1, profile.signingDomain());
    assertEquals(TrustDocumentTypes.TRUST_STATEMENT_CONTENT_TYPE, profile.contentType());
    assertEquals(TrustDocumentTypes.TRUST_STATEMENT_FILENAME, profile.defaultFilename());
  }

  @Test
  void findById_whenKnownAndUnknownIds_expectRegisteredProfileOrEmpty() {
    assertEquals(
        ContentFormatProfileRegistry.SOCIAL_MESSAGE,
        ContentFormatProfileRegistry.findById(EXPECTED_SOCIAL_MESSAGE_ID).orElseThrow());
    assertTrue(ContentFormatProfileRegistry.findById("crypta.social.message.v2").isEmpty());
  }

  @Test
  void
      contentFetchPolicy_whenComparedWithRegistry_expectDefaultFetchCoversGeneratedProfileBounds() {
    assertEquals(
        ContentFetchPolicy.DEFAULT_APP_FETCH_MAX_BYTES,
        ContentFormatProfileRegistry.FETCHED_DOCUMENT_MAX_BYTES);
    assertEquals(
        ContentFormatProfileRegistry.DEFAULT_APP_DOCUMENT_MAX_BYTES,
        ContentFormatProfileRegistry.FEED_SNAPSHOT.maxDocumentBytes());
    assertEquals(
        ContentFormatProfileRegistry.DEFAULT_APP_DOCUMENT_MAX_BYTES,
        ContentFormatProfileRegistry.SOCIAL_OUTBOX.maxDocumentBytes());
    assertTrue(
        ContentFetchPolicy.DEFAULT_APP_FETCH_MAX_BYTES
            >= ContentFormatProfileRegistry.FEED_SNAPSHOT.maxDocumentBytes());
    assertTrue(
        ContentFetchPolicy.DEFAULT_APP_FETCH_MAX_BYTES
            >= ContentFormatProfileRegistry.SOCIAL_OUTBOX.maxDocumentBytes());
  }

  @Test
  void validateMetadata_whenOversizedFutureOrDeprecated_expectRedactionSafeOutcomes() {
    ContentFormatProfile profile = ContentFormatProfileRegistry.SOCIAL_OUTBOX;

    ContentFormatValidationResult oversized =
        profile.validateMetadata(profile.id(), profile.maxDocumentBytes() + 1L);
    ContentFormatValidationResult future =
        profile.validateMetadata("crypta.social.outbox.v2", 1024);
    ContentFormatProfile deprecated =
        new ContentFormatProfile(
            EXAMPLE_PROFILE_ID,
            1,
            APPLICATION_JSON,
            "example.json",
            ContentFormatProfileStatus.DEPRECATED,
            1024,
            null,
            false,
            null,
            "deterministic_json",
            ContentFormatVersionPolicy.CONSERVATIVE_V1,
            "crypta.example.v2");

    assertFalse(oversized.accepted());
    assertEquals("oversized_document", oversized.errors().getFirst().code());
    assertFalse(future.accepted());
    assertEquals("unsupported_version", future.errors().getFirst().code());
    ContentFormatValidationResult deprecatedResult =
        deprecated.validateMetadata(deprecated.id(), 1);
    assertTrue(deprecatedResult.accepted());
    assertEquals("deprecated_version", deprecatedResult.warnings().getFirst().code());
    assertFalse(deprecatedResult.toString().contains("{\"type\""));
    assertFalse(deprecatedResult.toString().contains("signatureBase64"));
  }

  @Test
  void canonicalJson_whenDomainSeparated_expectCompactOrderedUtf8Bytes() {
    LinkedHashMap<String, Object> value = new LinkedHashMap<>();
    value.put("type", EXAMPLE_PROFILE_ID);
    value.put("count", 2);

    String canonical = CanonicalJson.write(value);
    String signedBytes =
        new String(
            CanonicalJson.domainSeparatedBytes(EXAMPLE_PROFILE_ID, value), StandardCharsets.UTF_8);

    assertEquals("{\"type\":\"crypta.example.v1\",\"count\":2}", canonical);
    assertEquals("crypta.example.v1\n{\"type\":\"crypta.example.v1\",\"count\":2}", signedBytes);
  }

  @Test
  void contentFormatProfile_whenSigningConfigurationInvalid_expectRejected() {
    IllegalArgumentException missingDomain = assertInvalidProfileWithSigning(true, null, 1024);
    IllegalArgumentException unsignedDomain =
        assertInvalidProfileWithSigning(false, EXAMPLE_PROFILE_ID, null);
    IllegalArgumentException unsignedPayloadLimit =
        assertInvalidProfileWithSigning(false, null, 1024);

    assertEquals("signed profiles require a signingDomain.", missingDomain.getMessage());
    assertEquals("unsigned profiles must not define a signingDomain.", unsignedDomain.getMessage());
    assertEquals(
        "unsigned profiles must not define maxSignedPayloadBytes.",
        unsignedPayloadLimit.getMessage());
  }

  @Test
  void contentFormatValidationResult_whenAcceptedContainsErrors_expectRejected() {
    ContentFormatValidationError error =
        new ContentFormatValidationError(
            "unsupported_version", EXAMPLE_PROFILE_ID, "Unsupported version.");
    List<ContentFormatValidationError> errors = List.of(error);
    List<ContentFormatValidationError> warnings = List.of();

    IllegalArgumentException exception =
        assertThrows(
            IllegalArgumentException.class,
            () -> new ContentFormatValidationResult(true, errors, warnings));

    assertEquals("Accepted validation results cannot contain errors.", exception.getMessage());
  }

  @Test
  void statusJsonValue_whenSerialized_expectLowercaseStableLabels() {
    assertEquals("stable", ContentFormatProfileStatus.STABLE.jsonValue());
    assertEquals("beta", ContentFormatProfileStatus.BETA.jsonValue());
    assertEquals("experimental", ContentFormatProfileStatus.EXPERIMENTAL.jsonValue());
    assertEquals("deprecated", ContentFormatProfileStatus.DEPRECATED.jsonValue());
  }

  @Test
  void mailEnvelopeIsSeparateExperimentalCiphertextProfile() {
    ContentFormatProfile mail = ContentFormatProfileRegistry.MAIL_ENVELOPE;
    assertEquals(network.crypta.crypt.mail.MailHpke.NETWORK_PROFILE, mail.id());
    assertEquals(ContentFormatProfileStatus.EXPERIMENTAL, mail.status());
    assertProfile(
        mail, "application/vnd.crypta.mail+json", "mail-envelope.json", false, null, null);
    assertEquals("strict_flat_json_hpke_authenticated_header", mail.canonicalizationKind());
    assertEquals(mail, ContentFormatProfileRegistry.findById(mail.id()).orElseThrow());
    assertTrue(ContentFormatProfileRegistry.findById("crypta.mail.envelope.v2").isEmpty());
    assertFalse(mail.validateMetadata(mail.id(), 65537).accepted());
    assertEquals(
        List.of(
            EXPECTED_PROFILE_DOCUMENT_ID,
            EXPECTED_FEED_SNAPSHOT_ID,
            EXPECTED_TRUST_STATEMENT_ID,
            EXPECTED_SOCIAL_MESSAGE_ID,
            EXPECTED_SOCIAL_OUTBOX_ID),
        ContentFormatProfileRegistry.profiles().subList(0, 5).stream()
            .map(ContentFormatProfile::id)
            .toList());
    assertEquals(
        List.of(
            ContentFormatProfileStatus.EXPERIMENTAL,
            ContentFormatProfileStatus.STABLE,
            ContentFormatProfileStatus.EXPERIMENTAL,
            ContentFormatProfileStatus.EXPERIMENTAL,
            ContentFormatProfileStatus.EXPERIMENTAL),
        ContentFormatProfileRegistry.profiles().subList(0, 5).stream()
            .map(ContentFormatProfile::status)
            .toList());
  }

  private static void assertProfile(
      ContentFormatProfile profile,
      String contentType,
      String defaultFilename,
      boolean signed,
      String signingDomain,
      Integer maxSignedPayloadBytes) {
    assertEquals(contentType, profile.contentType());
    assertEquals(defaultFilename, profile.defaultFilename());
    assertEquals(signed, profile.signed());
    assertEquals(signingDomain, profile.signingDomain());
    assertEquals(
        ContentFormatProfileRegistry.DEFAULT_APP_DOCUMENT_MAX_BYTES, profile.maxDocumentBytes());
    assertEquals(maxSignedPayloadBytes, profile.maxSignedPayloadBytes());
  }

  private static IllegalArgumentException assertInvalidProfileWithSigning(
      boolean signed, String signingDomain, Integer maxSignedPayloadBytes) {
    return assertThrows(
        IllegalArgumentException.class,
        () ->
            new ContentFormatProfile(
                EXAMPLE_PROFILE_ID,
                1,
                APPLICATION_JSON,
                "example.json",
                ContentFormatProfileStatus.EXPERIMENTAL,
                1024,
                maxSignedPayloadBytes,
                signed,
                signingDomain,
                "deterministic_json",
                ContentFormatVersionPolicy.CONSERVATIVE_V1,
                null));
  }
}
