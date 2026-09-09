package network.crypta.crypt.mail;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Objects;
import org.bouncycastle.crypto.hpke.HPKE;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class MailCryptoTest {
  private static byte[] hex(String value) {
    return HexFormat.of().parseHex(value);
  }

  @Test
  void rfc9180AppendixA11MatchesPublishedEncapsulationAndCiphertext() throws Exception {
    HPKE hpke =
        new HPKE(
            HPKE.mode_base, HPKE.kem_X25519_SHA256, HPKE.kdf_HKDF_SHA256, HPKE.aead_AES_GCM128);
    var recipient =
        hpke.deriveKeyPair(hex("6db9df30aa07dd42ee5e8181afdb977e538f5e1fec8a06223f33f7013e525037"));
    var ephemeral =
        hpke.deriveKeyPair(hex("7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234"));
    byte[] info = hex("4f6465206f6e2061204772656369616e2055726e");
    byte[] aad = hex("436f756e742d30");
    byte[] plaintext = hex("4265617574792069732074727574682c20747275746820626561757479");
    byte[] expected =
        hex(
            "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a");
    var sender = hpke.setupBaseS(recipient.getPublic(), info, ephemeral);
    assertArrayEquals(
        hex("37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431"),
        sender.getEncapsulation());
    assertArrayEquals(expected, sender.seal(aad, plaintext));
    assertArrayEquals(
        plaintext, hpke.setupBaseR(sender.getEncapsulation(), recipient, info).open(aad, expected));
    assertThrows(
        Exception.class,
        () ->
            hpke.setupBaseR(sender.getEncapsulation(), recipient, new byte[] {1})
                .open(aad, expected));
  }

  @Test
  void rfc8032Section71EmptyMessageMatchesPublishedSignature() {
    byte[] seed = hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    byte[] publicKey = hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    byte[] signature =
        hex(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
    assertArrayEquals(publicKey, MailWire.signingPublicKey(seed));
    assertArrayEquals(signature, MailWire.sign(seed, new byte[0]));
    assertTrue(MailWire.verify(publicKey, new byte[0], signature));
    assertFalse(MailWire.verify(publicKey, new byte[] {1}, signature));
  }

  @Test
  void independentKeysFreshContextsAndPurposeIsolation() {
    byte[] recipient = MailHpke.generatePrivateKey();
    byte[] wrong = MailHpke.generatePrivateKey();
    byte[] publicKey = MailHpke.publicKey(recipient);
    String selector = MailWire.fingerprint("recipient", publicKey);
    byte[] text = "public synthetic test".getBytes(StandardCharsets.UTF_8);
    byte[] envelope = MailHpke.seal("network", selector, publicKey, text);
    assertArrayEquals(text, MailHpke.open("network", selector, recipient, envelope));
    assertFalse(Arrays.equals(envelope, MailHpke.seal("network", selector, publicKey, text)));
    assertThrows(
        IllegalArgumentException.class, () -> MailHpke.open("network", selector, wrong, envelope));
    String storageSelector = MailWire.fingerprint("storage", publicKey);
    assertThrows(
        IllegalArgumentException.class,
        () -> MailHpke.open("storage", storageSelector, recipient, envelope));
    for (String field :
        new String[] {"profile", "kem", "kdf", "aead", "selector", "enc", "ciphertext"}) {
      var altered = MailWire.decode(envelope, 65536);
      altered.compute(
          field,
          (_, value) -> {
            String original = Objects.requireNonNull(value, "Missing envelope field: " + field);
            return (original.charAt(0) == 'A' ? "B" : "A") + original.substring(1);
          });
      byte[] alteredEnvelope = MailWire.encode(altered);
      assertThrows(
          IllegalArgumentException.class,
          () -> MailHpke.open("network", selector, recipient, alteredEnvelope),
          field);
    }
    byte[] zero = new byte[32];
    String zeroSelector = MailWire.fingerprint("recipient", zero);
    assertThrows(
        IllegalArgumentException.class, () -> MailHpke.seal("network", zeroSelector, zero, text));
  }

  @Test
  void malformedOrNonCanonicalEncodingsAreRejected() {
    for (String text :
        new String[] {
          "{\"a\":\"1\",\"a\":\"2\"}",
          "{\"a\":null}",
          "{ \"a\":\"x\"}",
          "{\"a\":\"\\u0061\"}",
          "{\"a\":\"\\ud800\"}",
          "{\"a\":{}}"
        }) {
      byte[] encoded = text.getBytes(StandardCharsets.UTF_8);
      assertThrows(IllegalArgumentException.class, () -> MailWire.decode(encoded, 65536));
    }
    assertThrows(
        IllegalArgumentException.class,
        () -> MailWire.decode(new byte[] {(byte) 0xc0, (byte) 0xaf}, 65536));
    assertThrows(IllegalArgumentException.class, () -> MailWire.decimal("9223372036854775808"));
    assertThrows(IllegalArgumentException.class, () -> MailWire.decimal("01"));
    var map = new LinkedHashMap<String, String>();
    map.put("literal", "<script>😀\n");
    assertEquals(map, MailWire.decode(MailWire.encode(map), 128));
    map.put("literal", "\ud800");
    assertThrows(IllegalArgumentException.class, () -> MailWire.encode(map));
  }

  @Test
  void canonicalEscapesAndAdjacentSupplementaryCharactersPreserveExactBytes() {
    var fields = new LinkedHashMap<String, String>();
    fields.put("text", "😀𐀀x\"\\\n\u0000");
    byte[] expected = "{\"text\":\"😀𐀀x\\\"\\\\\\u000a\\u0000\"}".getBytes(StandardCharsets.UTF_8);

    assertArrayEquals(expected, MailWire.encode(fields));
    assertEquals(fields, MailWire.decode(expected, 128));
    for (String invalid : new String[] {"\ud800", "\udc00", "\ud800x", "😀\udc00"}) {
      fields.put("text", invalid);
      assertThrows(IllegalArgumentException.class, () -> MailWire.encode(fields));
    }
  }

  @Test
  void malformedEscapesAndTruncatedObjectsAreRejected() {
    for (String invalid :
        new String[] {
          "{\"x\":\"\\uZZZZ\"}",
          "{\"x\":\"\\u000A\"}",
          "{\"x\":\"\\n\"}",
          "{\"x\":\"\\/\"}",
          "{\"x\":\"\n\"}",
          "{\"x\":\"ok\",}",
          "{}{}"
        }) {
      byte[] bytes = invalid.getBytes(StandardCharsets.UTF_8);
      assertThrows(IllegalArgumentException.class, () -> MailWire.decode(bytes, 128));
    }
    byte[] complete = "{\"x\":\"\\u000a\",\"y\":\"ok\"}".getBytes(StandardCharsets.UTF_8);
    for (int length = 0; length < complete.length; length++) {
      byte[] truncated = Arrays.copyOf(complete, length);
      assertThrows(IllegalArgumentException.class, () -> MailWire.decode(truncated, 128));
    }
  }

  @Test
  void decimalRetainsAsciiOnlyCanonicalRange() {
    assertEquals(0L, MailWire.decimal("0"));
    assertEquals(Long.MAX_VALUE, MailWire.decimal("9223372036854775807"));
    for (String invalid : new String[] {"1١", "1１", "+1", "-1", "00", "1\n"}) {
      assertThrows(IllegalArgumentException.class, () -> MailWire.decimal(invalid));
    }
  }

  @Test
  void signedRecipientAndPayloadCannotBeSubstituted() {
    byte[] seed = hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    var fields = new LinkedHashMap<String, String>();
    fields.put("profile", MailWire.MESSAGE);
    fields.put("messageId", "01".repeat(16));
    fields.put("sender", MailWire.fingerprint("signing", MailWire.signingPublicKey(seed)));
    fields.put("senderAccount", "02".repeat(16));
    fields.put("senderEpoch", "1");
    fields.put("recipient", "03".repeat(32));
    fields.put("recipientAccount", "04".repeat(16));
    fields.put("recipientEpoch", "1");
    fields.put("created", "100");
    fields.put("expires", "200");
    fields.put("subject", "Public synthetic subject");
    fields.put("body", "<script>inert text</script>");
    fields.put("format", "text/plain");
    byte[] payload = MailWire.messagePayload(fields);
    byte[] preimage = MailWire.preimage(MailWire.MESSAGE, payload);
    byte[] signature = MailWire.sign(seed, preimage);
    byte[] wrapper = MailWire.signed(payload, signature);
    assertArrayEquals(payload, MailWire.signedPayload(wrapper));
    assertTrue(
        MailWire.verify(MailWire.signingPublicKey(seed), preimage, MailWire.signature(wrapper)));
    fields.put("recipient", "05".repeat(32));
    assertFalse(
        MailWire.verify(
            MailWire.signingPublicKey(seed),
            MailWire.preimage(MailWire.MESSAGE, MailWire.messagePayload(fields)),
            signature));
    fields.put("body", "a".repeat(16385));
    assertThrows(IllegalArgumentException.class, () -> MailWire.messagePayload(fields));
    fields.put("body", "ok");
    fields.put("unknown", "x");
    assertThrows(IllegalArgumentException.class, () -> MailWire.messagePayload(fields));
  }

  @Test
  void noncanonicalAndSmallOrderRecipientKeysAreRejected() {
    assertThrows(
        IllegalArgumentException.class, () -> MailWire.validateRecipientPublicKey(new byte[32]));
    byte[] identity = new byte[32];
    identity[0] = 1;
    assertThrows(
        IllegalArgumentException.class, () -> MailWire.validateRecipientPublicKey(identity));
    byte[] alias = MailHpke.publicKey(MailHpke.generatePrivateKey());
    alias[31] |= (byte) 128;
    assertThrows(IllegalArgumentException.class, () -> MailWire.validateRecipientPublicKey(alias));
    byte[] noncanonical = hex("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f");
    assertThrows(
        IllegalArgumentException.class, () -> MailWire.validateRecipientPublicKey(noncanonical));
  }

  @Test
  void publicReferenceSignedMessageMatchesPinnedBytes() throws Exception {
    byte[] vector;
    try (var input = getClass().getResourceAsStream("public-signed-message.json")) {
      assertNotNull(input);
      vector = input.readAllBytes();
    }
    assertEquals(
        "c6cbf1f9cc932ee50df63c75ada1e0edb6ae96b42bab430893feb4a05dad3ba5",
        HexFormat.of()
            .formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(vector)));
    byte[] payload = MailWire.signedPayload(vector);
    assertArrayEquals(payload, MailWire.messagePayload(MailWire.decode(payload, 32768)));
    byte[] preimage = MailWire.preimage(MailWire.MESSAGE, payload);
    assertTrue(
        MailWire.verify(
            hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"),
            preimage,
            MailWire.signature(vector)));
    assertArrayEquals(
        vector,
        MailWire.signed(
            payload,
            MailWire.sign(
                hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"),
                preimage)));
  }

  @Test
  void networkTransportValidationRequiresClosedCanonicalCiphertextEnvelope() {
    byte[] key = MailHpke.generatePrivateKey();
    byte[] pub = MailHpke.publicKey(key);
    byte[] envelope =
        MailHpke.seal("network", MailWire.fingerprint("recipient", pub), pub, new byte[] {1});
    assertDoesNotThrow(() -> MailHpke.validateNetworkEnvelope(envelope));
    for (String field :
        java.util.List.of("profile", "kem", "kdf", "aead", "selector", "enc", "ciphertext")) {
      var changed = MailWire.decode(envelope, 65536);
      changed.put(field, "invalid");
      byte[] changedEnvelope = MailWire.encode(changed);
      assertThrows(
          IllegalArgumentException.class,
          () -> MailHpke.validateNetworkEnvelope(changedEnvelope),
          field);
    }
    var changed = MailWire.decode(envelope, 65536);
    changed.put("body", "plaintext");
    byte[] plaintextEnvelope = MailWire.encode(changed);
    assertThrows(
        IllegalArgumentException.class, () -> MailHpke.validateNetworkEnvelope(plaintextEnvelope));
    assertThrows(
        IllegalArgumentException.class, () -> MailHpke.validateNetworkEnvelope(new byte[65537]));
    byte[] storage =
        MailHpke.seal("storage", MailWire.fingerprint("storage", pub), pub, new byte[] {1});
    assertThrows(IllegalArgumentException.class, () -> MailHpke.validateNetworkEnvelope(storage));
    // No claim of AEAD authentication: a structurally valid changed tag remains opaque here.
    var opaqueFields = MailWire.decode(envelope, 65536);
    byte[] opaque = java.util.Base64.getDecoder().decode(opaqueFields.get("ciphertext"));
    opaque[0] ^= 1;
    opaqueFields.put("ciphertext", MailWire.base64(opaque));
    MailHpke.validateNetworkEnvelope(MailWire.encode(opaqueFields));
  }

  @Test
  void validContactSignatureCannotAdmitInvalidRecipientKey() {
    byte[] seed = hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    byte[] signing = MailWire.signingPublicKey(seed);
    byte[] recipient = MailHpke.publicKey(MailHpke.generatePrivateKey());
    byte[] alias = recipient.clone();
    alias[31] |= (byte) 128;
    for (byte[] invalidKey :
        java.util.List.of(
            new byte[32],
            alias,
            hex("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"))) {
      var fields = new LinkedHashMap<String, String>();
      fields.put("profile", MailWire.CONTACT);
      fields.put("signingKey", MailWire.base64(signing));
      fields.put("signingFingerprint", MailWire.fingerprint("signing", signing));
      fields.put("account", "01".repeat(16));
      fields.put("signingEpoch", "1");
      fields.put("recipientKey", MailWire.base64(invalidKey));
      fields.put("recipientFingerprint", MailWire.fingerprint("recipient", invalidKey));
      fields.put("recipientEpoch", "1");
      fields.put("created", "100");
      fields.put("expires", "200");
      fields.put("suite", "32/1/1");
      byte[] payload = MailWire.encode(fields);
      byte[] preimage =
          (MailWire.CONTACT + "\n" + new String(payload, StandardCharsets.UTF_8))
              .getBytes(StandardCharsets.UTF_8);
      byte[] signature = MailWire.sign(seed, preimage);
      assertTrue(MailWire.verify(signing, preimage, signature), "pairing signature is valid");
      assertThrows(IllegalArgumentException.class, () -> MailWire.contactPayload(fields));
      assertThrows(
          IllegalArgumentException.class, () -> MailWire.preimage(MailWire.CONTACT, payload));
      String invalidSelector = MailWire.fingerprint("recipient", invalidKey);
      assertThrows(
          IllegalArgumentException.class,
          () -> MailHpke.seal("network", invalidSelector, invalidKey, new byte[] {1}));
    }
  }
}
