package network.crypta.crypt.mail;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.hpke.HPKE;

/** Single-use RFC 9180 base-mode contexts with fixed network and local-storage separation. */
public final class MailHpke {
  /** Experimental network envelope profile and exact HPKE info string. */
  public static final String NETWORK_PROFILE = "crypta.mail.envelope.v1";

  /** Maximum complete UTF-8 network envelope, including JSON and Base64 overhead. */
  public static final int MAX_NETWORK_ENVELOPE_BYTES = 65536;

  private static final String FIELD_PROFILE = "profile";
  private static final String FIELD_SELECTOR = "selector";
  private static final String FIELD_CIPHERTEXT = "ciphertext";
  private static final String NETWORK = "network";
  private static final String STORAGE = "storage";

  /** Exact ordered HPKE authenticated-header fields. */
  private static final List<String> HEADER =
      List.of(FIELD_PROFILE, "kem", "kdf", "aead", FIELD_SELECTOR);

  /** Exact ordered outer-envelope fields. */
  private static final List<String> FIELDS =
      List.of(FIELD_PROFILE, "kem", "kdf", "aead", FIELD_SELECTOR, "enc", FIELD_CIPHERTEXT);

  /** Prevents instances of the fixed-suite utility. */
  private MailHpke() {}

  /**
   * Creates the only supported HPKE suite, without algorithm negotiation.
   *
   * @return fresh fixed-suite HPKE facade
   */
  private static HPKE suite() {
    return new HPKE(
        HPKE.mode_base, HPKE.kem_X25519_SHA256, HPKE.kdf_HKDF_SHA256, HPKE.aead_AES_GCM128);
  }

  /**
   * Generates an independent X25519 private key using the maintained provider's secure randomness.
   *
   * @return new private 32-byte X25519 key
   */
  public static byte[] generatePrivateKey() {
    HPKE h = suite();
    return h.serializePrivateKey(h.generatePrivateKey().getPrivate());
  }

  /**
   * Derives the raw X25519 public key; private input must stay inside the vault.
   *
   * @param privateKey private 32-byte X25519 key, retained inside the vault
   * @return raw 32-byte X25519 public key
   * @throws IllegalArgumentException if the input violates the fixed Mail format or limits
   */
  public static byte[] publicKey(byte[] privateKey) {
    if (privateKey.length != 32) throw invalid();
    HPKE h = suite();
    return h.serializePublicKey(h.deserializePrivateKey(privateKey, null).getPublic());
  }

  /**
   * Selects the fixed profile and HPKE info domain for a purpose.
   *
   * @param purpose fixed network or local-storage purpose
   * @return fixed versioned profile domain
   */
  private static String profile(String purpose) {
    return switch (purpose) {
      case NETWORK -> NETWORK_PROFILE;
      case STORAGE -> "crypta.mail.storage.v1";
      default -> throw invalid();
    };
  }

  /**
   * Returns the plaintext byte limit before HPKE sealing.
   *
   * @param purpose fixed network or local-storage purpose
   * @return maximum plaintext bytes
   */
  private static int plaintextCap(String purpose) {
    profile(purpose);
    return NETWORK.equals(purpose) ? 45056 : 131072;
  }

  /**
   * Returns the complete encoded-envelope byte limit for the selected purpose.
   *
   * @param purpose fixed network or local-storage purpose
   * @return maximum complete envelope bytes
   */
  private static int envelopeCap(String purpose) {
    return NETWORK.equals(purpose) ? MAX_NETWORK_ENVELOPE_BYTES : 196608;
  }

  /**
   * Builds the exact fixed-suite authenticated header.
   *
   * @param purpose fixed network or local-storage purpose
   * @param selector role-qualified recipient fingerprint
   * @return ordered authenticated header fields
   */
  private static Map<String, String> header(String purpose, String selector) {
    if (selector == null || !selector.matches("[0-9a-f]{64}")) throw invalid();
    var m = new LinkedHashMap<String, String>();
    m.put(FIELD_PROFILE, profile(purpose));
    m.put("kem", "32");
    m.put("kdf", "1");
    m.put("aead", "1");
    m.put(FIELD_SELECTOR, selector);
    return m;
  }

  /**
   * Seals bounded bytes to a purpose-qualified public identity with a fresh one-message context.
   *
   * @param purpose network or storage; no other purpose is supported
   * @param selector role-qualified fingerprint of the actual public key
   * @param recipientPublic raw 32-byte recipient public key
   * @param plaintext complete bounded plaintext
   * @return complete canonical encrypted envelope
   * @throws IllegalArgumentException if the input violates the fixed Mail format or limits
   */
  public static byte[] seal(
      String purpose, String selector, byte[] recipientPublic, byte[] plaintext) {
    try {
      if (plaintext.length > plaintextCap(purpose)
          || recipientPublic.length != 32
          || !MailWire.fingerprint(NETWORK.equals(purpose) ? "recipient" : STORAGE, recipientPublic)
              .equals(selector)) throw invalid();
      MailWire.validateRecipientPublicKey(recipientPublic);
      var m = header(purpose, selector);
      byte[] aad = MailWire.encode(m);
      HPKE h = suite();
      var context =
          h.setupBaseS(
              h.deserializePublicKey(recipientPublic),
              profile(purpose).getBytes(StandardCharsets.UTF_8));
      byte[] ct = context.seal(aad, plaintext);
      m.put("enc", MailWire.base64(context.getEncapsulation()));
      m.put(FIELD_CIPHERTEXT, MailWire.base64(ct));
      byte[] result = MailWire.encode(m);
      if (result.length > envelopeCap(purpose)) throw invalid();
      return result;
    } catch (InvalidCipherTextException | RuntimeException _) {
      throw invalid();
    }
  }

  /**
   * Opens only the fixed purpose and actual identity; errors disclose no cryptographic internals.
   *
   * @param purpose network or storage; no other purpose is supported
   * @param selector role-qualified fingerprint of the actual public key
   * @param privateKey private 32-byte X25519 key, retained inside the vault
   * @param envelope complete canonical encrypted envelope
   * @return complete authenticated plaintext, never partial AEAD output
   * @throws IllegalArgumentException if the input violates the fixed Mail format or limits
   */
  public static byte[] open(String purpose, String selector, byte[] privateKey, byte[] envelope) {
    try {
      if (privateKey.length != 32
          || !MailWire.fingerprint(
                  NETWORK.equals(purpose) ? "recipient" : STORAGE, publicKey(privateKey))
              .equals(selector)) throw invalid();
      var m = MailWire.ordered(MailWire.decode(envelope, envelopeCap(purpose)), FIELDS);
      if (!java.util.Arrays.equals(envelope, MailWire.encode(m))) throw invalid();
      var expected = header(purpose, selector);
      for (String key : HEADER) if (!expected.get(key).equals(m.get(key))) throw invalid();
      byte[] enc = MailWire.unbase64(m.get("enc"), 32);
      MailWire.validateRecipientPublicKey(enc);
      String ctText = m.get(FIELD_CIPHERTEXT);
      byte[] ct = java.util.Base64.getDecoder().decode(ctText);
      if (ct.length < 16
          || ct.length > plaintextCap(purpose) + 16
          || !MailWire.base64(ct).equals(ctText)) throw invalid();
      HPKE h = suite();
      var context =
          h.setupBaseR(
              enc,
              h.deserializePrivateKey(privateKey, null),
              profile(purpose).getBytes(StandardCharsets.UTF_8));
      return context.open(MailWire.encode(expected), ct);
    } catch (InvalidCipherTextException | RuntimeException _) {
      throw invalid();
    }
  }

  /**
   * Validates the closed network envelope before ciphertext is admitted to transport.
   *
   * <p>This is structural validation only: it neither uses private keys nor proves authentication,
   * recipient authorization or sender trust. Actual recipient opening and inner verification remain
   * mandatory. Ciphertext contents are opaque to this operation.
   *
   * @param envelope complete canonical network envelope
   * @throws IllegalArgumentException if fields, suite, encodings or bounds are invalid
   */
  public static void validateNetworkEnvelope(byte[] envelope) {
    try {
      var fields = MailWire.ordered(MailWire.decode(envelope, MAX_NETWORK_ENVELOPE_BYTES), FIELDS);
      if (!java.util.Arrays.equals(envelope, MailWire.encode(fields))) throw invalid();
      var expected = header(NETWORK, fields.get(FIELD_SELECTOR));
      for (String key : HEADER) if (!expected.get(key).equals(fields.get(key))) throw invalid();
      MailWire.unbase64(fields.get("enc"), 32);
      String encoded = fields.get(FIELD_CIPHERTEXT);
      byte[] ciphertext = java.util.Base64.getDecoder().decode(encoded);
      if (ciphertext.length < 16
          || ciphertext.length > plaintextCap(NETWORK) + 16
          || !MailWire.base64(ciphertext).equals(encoded)) throw invalid();
    } catch (RuntimeException _) {
      throw invalid();
    }
  }

  /**
   * Creates a bounded format or cryptographic failure.
   *
   * @return bounded rejection exception
   */
  private static IllegalArgumentException invalid() {
    return new IllegalArgumentException("Mail cryptographic operation rejected.");
  }
}
