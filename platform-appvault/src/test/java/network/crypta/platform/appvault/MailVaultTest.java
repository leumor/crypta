package network.crypta.platform.appvault;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Arrays;
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
    String wrongId = wrong.identityId();
    assertThrows(AppVaultException.class, () -> sender.openMail(APP, wrongId, envelope));
    AppVaultService reopened = open(root.resolve("recipient"));
    assertArrayEquals(signed, reopened.openMail(APP, receiver.identityId(), envelope));
  }

  @Test
  void publicStorageKeyCannotAuthenticateReplacementState() throws Exception {
    AppVaultService vault = open(root.resolve("vault"));
    AppIdentityRecord storage = vault.createMailIdentity(APP, AppIdentityKind.MAIL_STORAGE_V1);
    byte[] forged =
        MailHpke.seal(
            "storage",
            storage.fingerprint(),
            publicKey(storage),
            "forged public synthetic state".getBytes(StandardCharsets.UTF_8));
    String storageId = storage.identityId();

    assertThrows(AppVaultException.class, () -> vault.openStorage(APP, storageId, forged));
  }

  @Test
  void authenticatedStorageSurvivesReopenAndRejectsTamperingOrSignatureTransplants()
      throws Exception {
    AppVaultService vault = open(root.resolve("vault"));
    AppIdentityRecord storage = vault.createMailIdentity(APP, AppIdentityKind.MAIL_STORAGE_V1);
    String id = storage.identityId();
    byte[] plaintext = new byte[131072];
    Arrays.fill(plaintext, (byte) 's');
    byte[] sealed = vault.sealStorage(APP, id, plaintext);
    var fields = MailWire.decode(sealed, 196608);
    var other = MailWire.decode(vault.sealStorage(APP, id, new byte[0]), 196608);

    AppVaultService reopened = open(root.resolve("vault"));
    assertArrayEquals(plaintext, reopened.openStorage(APP, id, sealed));
    assertTrue(sealed.length <= 196608);
    for (String field : fields.keySet()) {
      var changed = new LinkedHashMap<>(fields);
      changed.put(field, field.equals("signature") ? other.get(field) : fields.get(field) + "A");
      byte[] tampered = MailWire.encode(changed);
      assertThrows(AppVaultException.class, () -> vault.openStorage(APP, id, tampered), field);
    }
    var extra = new LinkedHashMap<>(fields);
    extra.put("publicKeyBase64", MailWire.base64(publicKey(signing(vault))));
    byte[] unknownField = MailWire.encode(extra);
    assertThrows(AppVaultException.class, () -> vault.openStorage(APP, id, unknownField));
    var reordered = new LinkedHashMap<String, String>();
    reordered.put("signature", fields.get("signature"));
    reordered.putAll(fields);
    byte[] wrongOrder = MailWire.encode(reordered);
    assertThrows(AppVaultException.class, () -> vault.openStorage(APP, id, wrongOrder));
    String otherId = vault.createMailIdentity(APP, AppIdentityKind.MAIL_STORAGE_V1).identityId();
    assertThrows(AppVaultException.class, () -> vault.openStorage(APP, otherId, sealed));
  }

  @Test
  void storageSignatureBindsCompleteCiphertextAndAuthoritativeIdentityMetadata() throws Exception {
    AppVaultService vault = open(root.resolve("vault"));
    AppIdentityRecord signer = signing(vault);
    AppIdentityRecord storage = vault.createMailIdentity(APP, AppIdentityKind.MAIL_STORAGE_V1);
    byte[] sealed = vault.sealStorage(APP, storage.identityId(), new byte[0]);
    var fields = MailWire.decode(sealed, 196608);
    assertEquals("crypta.mail.storage-auth.v1", fields.remove("authentication"));
    byte[] signature = MailWire.unbase64(fields.remove("signature"), 64);
    String encrypted = new String(MailWire.encode(fields), StandardCharsets.UTF_8);
    var bindings = new LinkedHashMap<String, String>();
    bindings.put("app", APP);
    bindings.put("account", storage.publicSummary().get("account"));
    bindings.put("storageId", storage.identityId());
    bindings.put("storageEpoch", storage.publicSummary().get("epoch"));
    bindings.put("storageFingerprint", storage.fingerprint());
    bindings.put("signingId", signer.identityId());
    bindings.put("signingEpoch", signer.publicSummary().get("epoch"));
    bindings.put("signingFingerprint", signer.fingerprint());

    assertTrue(MailWire.verify(publicKey(signer), storageFrame(bindings, encrypted), signature));
    for (String field : bindings.keySet()) {
      var changed = new LinkedHashMap<>(bindings);
      changed.put(field, "substituted");
      assertFalse(
          MailWire.verify(publicKey(signer), storageFrame(changed, encrypted), signature), field);
    }
    assertFalse(
        MailWire.verify(publicKey(signer), storageFrame(bindings, encrypted + " "), signature));
  }

  private static byte[] storageFrame(Map<String, String> bindings, String encrypted) {
    return ("crypta.mail.storage-auth.v1\n"
            + new String(MailWire.encode(bindings), StandardCharsets.UTF_8)
            + "\n"
            + encrypted)
        .getBytes(StandardCharsets.UTF_8);
  }

  @Test
  void storageRequiresCurrentSameAccountSigningAuthorityAndHasNoPublicSigningOracle()
      throws Exception {
    AppVaultService vault = open(root.resolve("vault"));
    AppIdentityRecord storage = vault.createMailIdentity(APP, AppIdentityKind.MAIL_STORAGE_V1);
    String id = storage.identityId();
    String signingId = signing(vault).identityId();
    byte[] plaintext = "public synthetic state".getBytes(StandardCharsets.UTF_8);
    byte[] sealed = vault.sealStorage(APP, id, plaintext);
    byte[] storagePayload = MailWire.encode(Map.of("profile", "crypta.mail.storage-auth.v1"));
    assertThrows(AppVaultException.class, () -> vault.signMail(APP, signingId, storagePayload));

    vault.revokeGrantsForApp(APP);
    vault.grantIdentity(
        id,
        APP,
        Set.of(AppIdentityGrantScope.METADATA_READ, AppIdentityGrantScope.MAIL_STORAGE),
        "operator",
        "storage only",
        null,
        null);
    vault.grantIdentity(
        signingId,
        APP,
        Set.of(AppIdentityGrantScope.METADATA_READ),
        "operator",
        "signing metadata only",
        null,
        null);

    assertThrows(AppVaultException.class, () -> vault.sealStorage(APP, id, plaintext));
    assertThrows(AppVaultException.class, () -> vault.openStorage(APP, id, sealed));
    vault.grantIdentity(
        signingId,
        APP,
        Set.of(AppIdentityGrantScope.MAIL_SIGN),
        "operator",
        "expired signing",
        Instant.EPOCH,
        null);
    assertThrows(AppVaultException.class, () -> vault.openStorage(APP, id, sealed));
    vault.deleteIdentity(signingId);
    vault.createMailIdentity(APP, AppIdentityKind.MAIL_SIGNING_V1);
    assertThrows(AppVaultException.class, () -> vault.openStorage(APP, id, sealed));
    assertThrows(AppVaultException.class, () -> vault.sealStorage(APP, id, plaintext));
  }

  @Test
  void storageAndNetworkPurposesCannotBeSubstituted() throws Exception {
    AppVaultService vault = open(root.resolve("vault"));
    AppIdentityRecord storage = vault.createMailIdentity(APP, AppIdentityKind.MAIL_STORAGE_V1);
    AppIdentityRecord recipient = vault.createMailIdentity(APP, AppIdentityKind.MAIL_RECIPIENT_V1);
    String storageId = storage.identityId();
    String recipientId = recipient.identityId();
    byte[] plaintext = "synthetic private state".getBytes(StandardCharsets.UTF_8);

    byte[] sealed = vault.sealStorage(APP, storage.identityId(), plaintext);

    assertArrayEquals(plaintext, vault.openStorage(APP, storage.identityId(), sealed));
    assertThrows(AppVaultException.class, () -> vault.openMail(APP, recipientId, sealed));
    assertThrows(AppVaultException.class, () -> vault.openMail(APP, storageId, sealed));
    assertThrows(
        AppVaultException.class, () -> vault.openStorage("unrelated-app", storageId, sealed));
    assertThrows(AppVaultException.class, () -> vault.readSecretValue(APP, storageId));
  }

  @Test
  void grantRevocationExpiryAndGenericScopeDenyPrivateOperations() throws Exception {
    AppVaultService vault = open(root.resolve("vault"));
    AppIdentityRecord storage = vault.createMailIdentity(APP, AppIdentityKind.MAIL_STORAGE_V1);
    String storageId = storage.identityId();
    var genericSigningScope = Set.of(AppIdentityGrantScope.SIGN_DOMAIN_SEPARATED);
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
    assertThrows(AppVaultException.class, () -> vault.openStorage(APP, storageId, sealed));
    assertThrows(
        AppVaultException.class,
        () ->
            vault.grantIdentity(
                storageId, APP, genericSigningScope, "operator", "invalid", null, null));
    vault.grantIdentity(
        storage.identityId(),
        APP,
        Set.of(AppIdentityGrantScope.MAIL_STORAGE),
        "operator",
        "expired",
        Instant.EPOCH,
        null);
    assertThrows(AppVaultException.class, () -> vault.openStorage(APP, storageId, sealed));
  }

  @Test
  void removedMailCapabilityCannotBeReplacedByGenericIdentityUse() throws Exception {
    AppVaultService vault = open(root.resolve("vault"));
    AppIdentityRecord storage = vault.createMailIdentity(APP, AppIdentityKind.MAIL_STORAGE_V1);
    String storageId = storage.identityId();
    vault.disableGrantsForRemovedVaultPermissions(
        APP, Set.of("vault.identities.read", "vault.identities.use"));
    assertThrows(AppVaultException.class, () -> vault.sealStorage(APP, storageId, new byte[0]));
  }

  @Test
  void contactSigningRequiresActualLocalRecipientAndAccountBinding() throws Exception {
    AppVaultService vault = open(root.resolve("vault"));
    AppIdentityRecord signing = signing(vault);
    String signingId = signing.identityId();
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
    assertThrows(AppVaultException.class, () -> vault.signMail(APP, signingId, substituted));
    AppVaultService other = open(root.resolve("other"));
    AppIdentityRecord otherRecipient =
        other.createMailIdentity(APP, AppIdentityKind.MAIL_RECIPIENT_V1);
    byte[] foreign = MailWire.contactPayload(contact(signing, otherRecipient));
    assertThrows(AppVaultException.class, () -> vault.signMail(APP, signingId, foreign));
  }

  @Test
  void senderEpochSubstitutionAndGenericSigningAreDenied() throws Exception {
    AppVaultService vault = open(root.resolve("vault"));
    AppIdentityRecord signing = signing(vault);
    String signingId = signing.identityId();
    AppIdentityRecord recipient = vault.createMailIdentity(APP, AppIdentityKind.MAIL_RECIPIENT_V1);
    Map<String, String> fields = MailWire.decode(message(signing, recipient), 32768);
    fields.put("senderEpoch", "2");
    byte[] changed = MailWire.messagePayload(fields);
    assertThrows(AppVaultException.class, () -> vault.signMail(APP, signingId, changed));
    AppIdentityUsageRequest usageRequest =
        new AppIdentityUsageRequest(
            APP, signingId, AppIdentityGrantScope.MAIL_SIGN, "mail", message(signing, recipient));
    assertThrows(AppVaultException.class, () -> vault.useIdentity(usageRequest));
  }

  @Test
  void keyLimitsAndUninstallNeverPretendDataOnlyBackupRecoversKeys() throws Exception {
    AppVaultService vault = open(root.resolve("vault"));
    AppIdentityRecord storage = vault.createMailIdentity(APP, AppIdentityKind.MAIL_STORAGE_V1);
    String storageId = storage.identityId();
    byte[] backup = vault.sealStorage(APP, storage.identityId(), new byte[0]);
    vault.createMailIdentity(APP, AppIdentityKind.MAIL_STORAGE_V1);
    vault.createMailIdentity(APP, AppIdentityKind.MAIL_STORAGE_V1);
    assertThrows(
        AppVaultException.class,
        () -> vault.createMailIdentity(APP, AppIdentityKind.MAIL_STORAGE_V1));
    assertEquals(4, vault.deleteAppOwnedIdentitiesForApp(APP).size());
    assertThrows(AppVaultException.class, () -> vault.openStorage(APP, storageId, backup));
    assertThrows(
        AppVaultException.class,
        () -> vault.createMailIdentity("unrelated", AppIdentityKind.MAIL_STORAGE_V1));
  }

  @Test
  void authenticatedVaultMetadataPreventsAccountReassignment() throws Exception {
    AppVaultService vault = open(root.resolve("vault"));
    AppIdentityRecord signing = signing(vault);
    AppIdentityRecord substituted = withSubstitutedAccount(signing);
    AppVaultKeyProvider.VaultKey wrappingKey =
        new AppVaultKeyProvider.VaultKey("synthetic-test", new byte[32]);
    AppVaultEnvelope envelope =
        AppVaultEnvelope.encrypt(
            new byte[32],
            AppVaultMetadata.identityAad(signing),
            wrappingKey,
            new java.security.SecureRandom());
    byte[] substitutedAad = AppVaultMetadata.identityAad(substituted);
    assertThrows(AppVaultException.class, () -> envelope.decrypt(substitutedAad, wrappingKey));
  }

  @Test
  void networkOpenRejectsWrongAccountEpochAndUnstructuredPlaintext() throws Exception {
    AppVaultService vault = open(root.resolve("account-bound"));
    AppIdentityRecord recipient = vault.createMailIdentity(APP, AppIdentityKind.MAIL_RECIPIENT_V1);
    String recipientId = recipient.identityId();
    AppIdentityRecord signing = signing(vault);
    var fields = MailWire.decode(message(signing, recipient), 32768);
    fields.put("recipientAccount", "ffffffffffffffffffffffffffffffff");
    byte[] wrongAccount =
        vault.signMail(APP, signing.identityId(), MailWire.messagePayload(fields));
    byte[] accountEnvelope =
        MailHpke.seal("network", recipient.fingerprint(), publicKey(recipient), wrongAccount);
    assertThrows(AppVaultException.class, () -> vault.openMail(APP, recipientId, accountEnvelope));
    fields.put("recipientAccount", recipient.publicSummary().get("account"));
    fields.put("recipientEpoch", "2");
    byte[] wrongEpoch = vault.signMail(APP, signing.identityId(), MailWire.messagePayload(fields));
    byte[] epochEnvelope =
        MailHpke.seal("network", recipient.fingerprint(), publicKey(recipient), wrongEpoch);
    assertThrows(AppVaultException.class, () -> vault.openMail(APP, recipientId, epochEnvelope));
    byte[] rawEnvelope =
        MailHpke.seal("network", recipient.fingerprint(), publicKey(recipient), new byte[0]);
    assertThrows(AppVaultException.class, () -> vault.openMail(APP, recipientId, rawEnvelope));
  }

  @Test
  void retainedMailIdentityWithoutCurrentAuthorityPreventsReplacementCreation() throws Exception {
    for (String deniedState :
        new String[] {"revoked", "expired", "metadata-hidden", "purpose-denied"}) {
      AppVaultService vault = open(root.resolve(deniedState));
      AppIdentityRecord storage = vault.createMailIdentity(APP, AppIdentityKind.MAIL_STORAGE_V1);
      String storageId = storage.identityId();
      for (AppIdentityGrant grant : vault.listGrantsForApp(APP)) {
        if (grant.identityId().equals(storage.identityId())) vault.revokeGrant(grant.grantId());
      }
      switch (deniedState) {
        case "expired" ->
            vault.grantIdentity(
                storage.identityId(),
                APP,
                Set.of(AppIdentityGrantScope.METADATA_READ, AppIdentityGrantScope.MAIL_STORAGE),
                "operator",
                "Expired synthetic grant",
                Instant.EPOCH,
                null);
        case "metadata-hidden" ->
            vault.grantIdentity(
                storage.identityId(),
                APP,
                Set.of(AppIdentityGrantScope.MAIL_STORAGE),
                "operator",
                "Purpose only",
                null,
                null);
        case "purpose-denied" ->
            vault.grantIdentity(
                storage.identityId(),
                APP,
                Set.of(AppIdentityGrantScope.METADATA_READ),
                "operator",
                "Metadata only",
                null,
                null);
        default -> {
          // The revoked case keeps the existing revocation without granting replacement scopes.
        }
      }
      var identitiesBefore = vault.listIdentities();
      var grantsBefore = vault.listGrantsForApp(APP);
      assertThrows(AppVaultException.class, () -> vault.requireMailIdentityAuthority(APP));

      for (AppIdentityKind requested :
          new AppIdentityKind[] {
            AppIdentityKind.MAIL_SIGNING_V1,
            AppIdentityKind.MAIL_RECIPIENT_V1,
            AppIdentityKind.MAIL_STORAGE_V1
          }) {
        assertThrows(AppVaultException.class, () -> vault.createMailIdentity(APP, requested));
      }

      assertEquals(identitiesBefore, vault.listIdentities());
      assertEquals(grantsBefore, vault.listGrantsForApp(APP));
      assertThrows(AppVaultException.class, () -> vault.sealStorage(APP, storageId, new byte[0]));
    }
  }

  @Test
  void emptyAppVisibleIdentityListingDoesNotAuthorizeNewAccountAfterRevocation() throws Exception {
    AppVaultService vault = open(root.resolve("hidden-account"));
    vault.createMailIdentity(APP, AppIdentityKind.MAIL_RECIPIENT_V1);
    vault.createMailIdentity(APP, AppIdentityKind.MAIL_STORAGE_V1);
    vault.revokeGrantsForApp(APP);
    var identitiesBefore = vault.listIdentities();
    var grantsBefore = vault.listGrantsForApp(APP);
    assertTrue(vault.listIdentitiesForApp(APP).isEmpty());
    assertThrows(AppVaultException.class, () -> vault.requireMailIdentityAuthority(APP));

    assertThrows(
        AppVaultException.class,
        () -> vault.createMailIdentity(APP, AppIdentityKind.MAIL_SIGNING_V1));

    assertEquals(identitiesBefore, vault.listIdentities());
    assertEquals(grantsBefore, vault.listGrantsForApp(APP));
  }

  private static AppIdentityRecord withSubstitutedAccount(AppIdentityRecord signing) {
    Map<String, String> changedSummary = new LinkedHashMap<>(signing.publicSummary());
    changedSummary.put("account", "ffffffffffffffffffffffffffffffff");
    return new AppIdentityRecord(
        signing.identityId(),
        signing.kind(),
        signing.label(),
        signing.ownerAppId(),
        signing.createdAt(),
        signing.updatedAt(),
        changedSummary,
        signing.fingerprint(),
        signing.usageScopes());
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
