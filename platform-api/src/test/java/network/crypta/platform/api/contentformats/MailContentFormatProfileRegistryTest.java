package network.crypta.platform.api.contentformats;

import java.util.List;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/** Additive Mail coverage separate from the original five-profile review subjects. */
class MailContentFormatProfileRegistryTest {
  @Test
  void mailEnvelopeIsSeparateExperimentalCiphertextProfile() {
    ContentFormatProfile mail = ContentFormatProfileRegistry.MAIL_ENVELOPE;
    assertEquals(network.crypta.crypt.mail.MailHpke.NETWORK_PROFILE, mail.id());
    assertEquals(ContentFormatProfileStatus.EXPERIMENTAL, mail.status());
    assertEquals("application/vnd.crypta.mail+json", mail.contentType());
    assertEquals("mail-envelope.json", mail.defaultFilename());
    assertFalse(mail.signed());
    assertNull(mail.signingDomain());
    assertNull(mail.maxSignedPayloadBytes());
    assertEquals(65536, mail.maxDocumentBytes());
    assertEquals("strict_flat_json_hpke_authenticated_header", mail.canonicalizationKind());
    assertEquals(mail, ContentFormatProfileRegistry.findById(mail.id()).orElseThrow());
    assertTrue(ContentFormatProfileRegistry.findById("crypta.mail.envelope.v2").isEmpty());
    assertFalse(mail.validateMetadata(mail.id(), 65537).accepted());
    assertEquals(
        List.of(
            "crypta.profile.v1",
            "crypta.feed.snapshot.v1",
            "crypta.trust.statement.v1",
            "crypta.social.message.v1",
            "crypta.social.outbox.v1"),
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
}
