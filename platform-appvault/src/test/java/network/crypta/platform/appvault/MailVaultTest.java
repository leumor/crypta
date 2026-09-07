package network.crypta.platform.appvault;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import network.crypta.crypt.mail.MailHpke;
import network.crypta.crypt.mail.MailWire;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Independent local vault tests; no network publication or endpoint security certification. */
class MailVaultTest {
  private static final String APP = "mail-prototype";
  @TempDir Path root;

  @Test
  void independentVaultsAuthenticateSenderAndDecryptOnlyAtRecipient() throws Exception {
    AppVaultService sender = open(root.resolve("sender"));
    AppVaultService recipient = open(root.resolve("recipient"));
    AppIdentityRecord signing = signing(sender);
    AppIdentityRecord receiver =
        recipient.createMailIdentity(APP, AppIdentityKind.MAIL_RECIPIENT_V1);
    byte[] payload = message(signing, receiver);

    byte[] signed = sender.signMail(APP, signing.identityId(), payload);
    byte[] envelope = MailHpke.seal("network", receiver.fingerprint(), publicKey(receiver), signed);
    byte[] opened = recipient.openMail(APP, receiver.identityId(), envelope);

    assertArrayEquals(signed, opened);
    assertTrue(
        MailWire.verify(
            publicKey(signing),
            MailWire.preimage(MailWire.MESSAGE, payload),
            MailWire.signature(opened)));
    assertFalse(new String(envelope, StandardCharsets.UTF_8).contains("public synthetic body"));
    AppIdentityRecord wrong = sender.createMailIdentity(APP, AppIdentityKind.MAIL_RECIPIENT_V1);
    assertThrows(AppVaultException.class, () -> sender.openMail(APP, wrong.identityId(), envelope));
    AppVaultService reopened = open(root.resolve("recipient"));
    assertArrayEquals(signed, reopened.openMail(APP, receiver.identityId(), envelope));
  }

  @Test
  void storageAndNetworkPurposesCannotBeSubstituted() throws Exception {
    AppVaultService vault = open(root.resolve("vault"));
    AppIdentityRecord storage = vault.createMailIdentity(APP, AppIdentityKind.MAIL_STORAGE_V1);
    AppIdentityRecord recipient = vault.createMailIdentity(APP, AppIdentityKind.MAIL_RECIPIENT_V1);
    byte[] plaintext = "synthetic private state".getBytes(StandardCharsets.UTF_8);

    byte[] sealed = vault.sealStorage(APP, storage.identityId(), plaintext);

    assertArrayEquals(plaintext, vault.openStorage(APP, storage.identityId(), sealed));
    assertThrows(
        AppVaultException.class, () -> vault.openMail(APP, recipient.identityId(), sealed));
    assertThrows(AppVaultException.class, () -> vault.openMail(APP, storage.identityId(), sealed));
    assertThrows(
        AppVaultException.class,
        () -> vault.openStorage("unrelated-app", storage.identityId(), sealed));
    assertThrows(AppVaultException.class, () -> vault.readSecretValue(APP, storage.identityId()));
  }

  @Test
  void grantRevocationExpiryAndGenericScopeDenyPrivateOperations() throws Exception {
    AppVaultService vault = open(root.resolve("vault"));
    AppIdentityRecord storage = vault.createMailIdentity(APP, AppIdentityKind.MAIL_STORAGE_V1);
    byte[] value = "state".getBytes(StandardCharsets.UTF_8);
    byte[] sealed = vault.sealStorage(APP, storage.identityId(), value);
    vault.revokeGrantsForApp(APP);
    vault.grantIdentity(
        storage.identityId(),
        APP,
        Set.of(AppIdentityGrantScope.METADATA_READ),
        "operator",
        "metadata only",
        null,
        null);
    assertThrows(
        AppVaultException.class, () -> vault.openStorage(APP, storage.identityId(), sealed));
    assertThrows(
        AppVaultException.class,
        () ->
            vault.grantIdentity(
                storage.identityId(),
                APP,
                Set.of(AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED),
                "operator",
                "invalid",
                null,
                null));
    vault.grantIdentity(
        storage.identityId(),
        APP,
        Set.of(AppIdentityGrantScope.MAIL_STORAGE),
        "operator",
        "expired",
        Instant.EPOCH,
        null);
    assertThrows(
        AppVaultException.class, () -> vault.openStorage(APP, storage.identityId(), sealed));
  }

  @Test
  void removedMailCapabilityCannotBeReplacedByGenericIdentityUse() throws Exception {
    AppVaultService vault = open(root.resolve("vault"));
    AppIdentityRecord storage = vault.createMailIdentity(APP, AppIdentityKind.MAIL_STORAGE_V1);
    vault.disableGrantsForRemovedVaultPermissions(
        APP, Set.of("vault.identities.read", "vault.identities.use"));
    assertThrows(
        AppVaultException.class, () -> vault.sealStorage(APP, storage.identityId(), new byte[0]));
  }

  @Test
  void contactSigningRequiresActualLocalRecipientAndAccountBinding() throws Exception {
    AppVaultService vault = open(root.resolve("vault"));
    AppIdentityRecord signing = signing(vault);
    AppIdentityRecord recipient = vault.createMailIdentity(APP, AppIdentityKind.MAIL_RECIPIENT_V1);
    Map<String, String> fields = contact(signing, recipient);
    byte[] payload = MailWire.contactPayload(fields);
    byte[] signed = vault.signMail(APP, signing.identityId(), payload);
    assertTrue(
        MailWire.verify(
            publicKey(signing),
            MailWire.preimage(MailWire.CONTACT, payload),
            MailWire.signature(signed)));
    fields.put("account", "ffffffffffffffffffffffffffffffff");
    byte[] substituted = MailWire.contactPayload(fields);
    assertThrows(
        AppVaultException.class, () -> vault.signMail(APP, signing.identityId(), substituted));
    AppVaultService other = open(root.resolve("other"));
    AppIdentityRecord otherRecipient =
        other.createMailIdentity(APP, AppIdentityKind.MAIL_RECIPIENT_V1);
    byte[] foreign = MailWire.contactPayload(contact(signing, otherRecipient));
    assertThrows(AppVaultException.class, () -> vault.signMail(APP, signing.identityId(), foreign));
  }

  @Test
  void senderEpochSubstitutionAndGenericSigningAreDenied() throws Exception {
    AppVaultService vault = open(root.resolve("vault"));
    AppIdentityRecord signing = signing(vault);
    AppIdentityRecord recipient = vault.createMailIdentity(APP, AppIdentityKind.MAIL_RECIPIENT_V1);
    Map<String, String> fields = MailWire.decode(message(signing, recipient), 32768);
    fields.put("senderEpoch", "2");
    byte[] changed = MailWire.messagePayload(fields);
    assertThrows(AppVaultException.class, () -> vault.signMail(APP, signing.identityId(), changed));
    assertThrows(
        AppVaultException.class,
        () ->
            vault.useIdentity(
                new AppIdentityUsageRequest(
                    APP,
                    signing.identityId(),
                    AppIdentityGrantScope.MAIL_SIGN,
                    "mail",
                    message(signing, recipient))));
  }

  @Test
  void keyLimitsAndUninstallNeverPretendDataOnlyBackupRecoversKeys() throws Exception {
    AppVaultService vault = open(root.resolve("vault"));
    AppIdentityRecord storage = vault.createMailIdentity(APP, AppIdentityKind.MAIL_STORAGE_V1);
    byte[] backup = vault.sealStorage(APP, storage.identityId(), new byte[0]);
    vault.createMailIdentity(APP, AppIdentityKind.MAIL_STORAGE_V1);
    vault.createMailIdentity(APP, AppIdentityKind.MAIL_STORAGE_V1);
    assertThrows(
        AppVaultException.class,
        () -> vault.createMailIdentity(APP, AppIdentityKind.MAIL_STORAGE_V1));
    assertEquals(4, vault.deleteAppOwnedIdentitiesForApp(APP).size());
    assertThrows(
        AppVaultException.class, () -> vault.openStorage(APP, storage.identityId(), backup));
    assertThrows(
        AppVaultException.class,
        () -> vault.createMailIdentity("unrelated", AppIdentityKind.MAIL_STORAGE_V1));
  }

  @Test
  void authenticatedVaultMetadataPreventsAccountReassignment() throws Exception {
    AppVaultService vault = open(root.resolve("vault"));
    AppIdentityRecord signing = signing(vault);
    Map<String, String> changedSummary = new LinkedHashMap<>(signing.publicSummary());
    changedSummary.put("account", "ffffffffffffffffffffffffffffffff");
    AppIdentityRecord substituted =
        new AppIdentityRecord(
            signing.identityId(),
            signing.kind(),
            signing.label(),
            signing.ownerAppId(),
            signing.createdAt(),
            signing.updatedAt(),
            changedSummary,
            signing.fingerprint(),
            signing.usageScopes());
    AppVaultKeyProvider.VaultKey wrappingKey =
        new AppVaultKeyProvider.VaultKey("synthetic-test", new byte[32]);
    AppVaultEnvelope envelope =
        AppVaultEnvelope.encrypt(
            new byte[32],
            AppVaultMetadata.identityAad(signing),
            wrappingKey,
            new java.security.SecureRandom());
    assertThrows(
        AppVaultException.class,
        () -> envelope.decrypt(AppVaultMetadata.identityAad(substituted), wrappingKey));
  }

  @Test
  void networkOpenRejectsWrongAccountEpochAndUnstructuredPlaintext() throws Exception {
    AppVaultService vault = open(root.resolve("account-bound"));
    AppIdentityRecord recipient = vault.createMailIdentity(APP, AppIdentityKind.MAIL_RECIPIENT_V1);
    AppIdentityRecord signing = signing(vault);
    var fields = MailWire.decode(message(signing, recipient), 32768);
    fields.put("recipientAccount", "ffffffffffffffffffffffffffffffff");
    byte[] wrongAccount =
        vault.signMail(APP, signing.identityId(), MailWire.messagePayload(fields));
    byte[] accountEnvelope =
        MailHpke.seal("network", recipient.fingerprint(), publicKey(recipient), wrongAccount);
    assertThrows(
        AppVaultException.class,
        () -> vault.openMail(APP, recipient.identityId(), accountEnvelope));
    fields.put("recipientAccount", recipient.publicSummary().get("account"));
    fields.put("recipientEpoch", "2");
    byte[] wrongEpoch = vault.signMail(APP, signing.identityId(), MailWire.messagePayload(fields));
    byte[] epochEnvelope =
        MailHpke.seal("network", recipient.fingerprint(), publicKey(recipient), wrongEpoch);
    assertThrows(
        AppVaultException.class, () -> vault.openMail(APP, recipient.identityId(), epochEnvelope));
    byte[] rawEnvelope =
        MailHpke.seal("network", recipient.fingerprint(), publicKey(recipient), new byte[0]);
    assertThrows(
        AppVaultException.class, () -> vault.openMail(APP, recipient.identityId(), rawEnvelope));
  }

  private static AppVaultService open(Path path) throws Exception {
    AppVaultService service = AppVaultService.open(path);
    if (service.listIdentities().isEmpty()) {
      service.createMailIdentity(APP, AppIdentityKind.MAIL_SIGNING_V1);
    }
    return service;
  }

  private static AppIdentityRecord signing(AppVaultService service) {
    return service.listIdentities().stream()
        .filter(i -> i.kind() == AppIdentityKind.MAIL_SIGNING_V1)
        .findFirst()
        .orElseThrow();
  }

  private static byte[] publicKey(AppIdentityRecord identity) {
    return MailWire.unbase64(identity.publicSummary().get("publicKeyBase64"), 32);
  }

  private static Map<String, String> contact(
      AppIdentityRecord signing, AppIdentityRecord recipient) {
    Map<String, String> fields = new LinkedHashMap<>();
    fields.put("profile", MailWire.CONTACT);
    fields.put("signingKey", MailWire.base64(publicKey(signing)));
    fields.put("signingFingerprint", signing.fingerprint());
    fields.put("account", signing.publicSummary().get("account"));
    fields.put("signingEpoch", "1");
    fields.put("recipientKey", MailWire.base64(publicKey(recipient)));
    fields.put("recipientFingerprint", recipient.fingerprint());
    fields.put("recipientEpoch", "1");
    fields.put("created", "100");
    fields.put("expires", "200");
    fields.put("suite", "32/1/1");
    return fields;
  }

  private static byte[] message(AppIdentityRecord signing, AppIdentityRecord recipient) {
    Map<String, String> fields = new LinkedHashMap<>();
    fields.put("profile", MailWire.MESSAGE);
    fields.put("messageId", "0123456789abcdef0123456789abcdef");
    fields.put("sender", signing.fingerprint());
    fields.put("senderAccount", signing.publicSummary().get("account"));
    fields.put("senderEpoch", "1");
    fields.put("recipient", recipient.fingerprint());
    fields.put("recipientAccount", recipient.publicSummary().get("account"));
    fields.put("recipientEpoch", "1");
    fields.put("created", "100");
    fields.put("expires", "200");
    fields.put("subject", "Public synthetic subject");
    fields.put("body", "public synthetic body");
    fields.put("format", "text/plain");
    return MailWire.messagePayload(fields);
  }
}
