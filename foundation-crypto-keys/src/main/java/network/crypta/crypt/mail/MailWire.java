package network.crypta.crypt.mail;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;

/** Closed, canonical wire encoding and pure Ed25519 framing for experimental Mail. */
public final class MailWire {
  /** Experimental contact profile and signing domain. */
  public static final String CONTACT = "crypta.mail.contact.v1";

  /** Experimental message profile and signing domain. */
  public static final String MESSAGE = "crypta.mail.message.v1";

  /** Exact required contact field order. */
  public static final List<String> CONTACT_FIELDS =
      List.of(
          "profile",
          "signingKey",
          "signingFingerprint",
          "account",
          "signingEpoch",
          "recipientKey",
          "recipientFingerprint",
          "recipientEpoch",
          "created",
          "expires",
          "suite");

  /** Exact required message field order. */
  public static final List<String> MESSAGE_FIELDS =
      List.of(
          "profile",
          "messageId",
          "sender",
          "senderAccount",
          "senderEpoch",
          "recipient",
          "recipientAccount",
          "recipientEpoch",
          "created",
          "expires",
          "subject",
          "body",
          "format");

  /** Prevents instances of the canonical wire utility. */
  private MailWire() {}

  /**
   * Encodes ordered string fields with no Unicode normalization.
   *
   * @param fields complete string-valued fields; insertion order controls raw encoding
   * @return canonical UTF-8 bytes
   * @throws IllegalArgumentException if the input violates the fixed Mail format or limits
   */
  public static byte[] encode(Map<String, String> fields) {
    StringBuilder out = new StringBuilder("{");
    for (var entry : fields.entrySet()) {
      if (out.length() > 1) out.append(',');
      quote(out, entry.getKey());
      out.append(':');
      quote(out, entry.getValue());
    }
    return out.append('}').toString().getBytes(StandardCharsets.UTF_8);
  }

  /**
   * Appends canonical JSON string escaping while rejecting lone surrogates.
   *
   * @param out canonical output accumulator
   * @param text bounded input text
   */
  private static void quote(StringBuilder out, String text) {
    if (text == null) throw invalid();
    out.append('"');
    for (int i = 0; i < text.length(); i++) {
      char c = text.charAt(i);
      if (Character.isHighSurrogate(c)) {
        if (++i >= text.length() || !Character.isLowSurrogate(text.charAt(i))) throw invalid();
        out.append(c).append(text.charAt(i));
      } else if (Character.isLowSurrogate(c)) throw invalid();
      else if (c == '"' || c == '\\') out.append('\\').append(c);
      else if (c < 32) out.append(String.format(java.util.Locale.ROOT, "\\u%04x", (int) c));
      else out.append(c);
    }
    out.append('"');
  }

  /**
   * Strictly parses bounded canonical UTF-8 JSON; duplicate keys and alternate encodings fail.
   *
   * @param bytes encoded UTF-8 object
   * @param maximum maximum accepted encoded byte count
   * @return mutable insertion-ordered parsed fields
   * @throws IllegalArgumentException if the input violates the fixed Mail format or limits
   */
  public static Map<String, String> decode(byte[] bytes, int maximum) {
    if (bytes == null || bytes.length > maximum) throw invalid();
    try {
      String s =
          StandardCharsets.UTF_8
              .newDecoder()
              .onMalformedInput(CodingErrorAction.REPORT)
              .onUnmappableCharacter(CodingErrorAction.REPORT)
              .decode(ByteBuffer.wrap(bytes))
              .toString();
      Parser parser = new Parser(s);
      Map<String, String> result = parser.object();
      if (!Arrays.equals(bytes, encode(result))) throw invalid();
      return result;
    } catch (CharacterCodingException e) {
      throw invalid();
    }
  }

  /**
   * Requires an exact field set and returns fields in the protocol order.
   *
   * @param fields complete string-valued fields; insertion order controls raw encoding
   * @param names exact field names in canonical order
   * @return mutable fields arranged in canonical order
   * @throws IllegalArgumentException if the input violates the fixed Mail format or limits
   */
  public static Map<String, String> ordered(Map<String, String> fields, List<String> names) {
    if (fields.size() != names.size() || !fields.keySet().containsAll(names)) throw invalid();
    LinkedHashMap<String, String> result = new LinkedHashMap<>();
    for (String name : names) {
      if (fields.get(name) == null) throw invalid();
      result.put(name, fields.get(name));
    }
    return result;
  }

  /**
   * Validates and canonicalizes an unsigned contact pairing payload.
   *
   * @param fields complete string-valued fields; insertion order controls raw encoding
   * @return validated canonical contact bytes
   * @throws IllegalArgumentException if the input violates the fixed Mail format or limits
   */
  public static byte[] contactPayload(Map<String, String> fields) {
    var m = ordered(fields, CONTACT_FIELDS);
    if (!CONTACT.equals(m.get("profile")) || !"32/1/1".equals(m.get("suite"))) throw invalid();
    byte[] signing = unbase64(m.get("signingKey"), 32);
    byte[] recipient = unbase64(m.get("recipientKey"), 32);
    if (!org.bouncycastle.math.ec.rfc8032.Ed25519.validatePublicKeyFull(signing, 0))
      throw invalid();
    validateRecipientPublicKey(recipient);
    if (!fingerprint("signing", signing).equals(m.get("signingFingerprint"))
        || !fingerprint("recipient", recipient).equals(m.get("recipientFingerprint")))
      throw invalid();
    id(m.get("account"));
    positive(m.get("signingEpoch"));
    positive(m.get("recipientEpoch"));
    times(m);
    byte[] result = encode(m);
    if (result.length > 4096) throw invalid();
    return result;
  }

  /**
   * Validates and canonicalizes an unsigned message; temporal trust policy remains with the worker.
   *
   * @param fields complete string-valued fields; insertion order controls raw encoding
   * @return validated canonical message bytes
   * @throws IllegalArgumentException if the input violates the fixed Mail format or limits
   */
  public static byte[] messagePayload(Map<String, String> fields) {
    var m = ordered(fields, MESSAGE_FIELDS);
    if (!MESSAGE.equals(m.get("profile")) || !"text/plain".equals(m.get("format"))) throw invalid();
    id(m.get("messageId"));
    id(m.get("senderAccount"));
    id(m.get("recipientAccount"));
    fingerprintText(m.get("sender"));
    fingerprintText(m.get("recipient"));
    positive(m.get("senderEpoch"));
    positive(m.get("recipientEpoch"));
    times(m);
    if (m.get("subject").getBytes(StandardCharsets.UTF_8).length > 256
        || m.get("body").getBytes(StandardCharsets.UTF_8).length > 16384) throw invalid();
    byte[] result = encode(m);
    if (result.length > 32768) throw invalid();
    return result;
  }

  /**
   * Requires an expiry strictly after creation.
   *
   * @param m typed creation and expiry fields
   */
  private static void times(Map<String, String> m) {
    if (decimal(m.get("expires")) <= decimal(m.get("created"))) throw invalid();
  }

  /**
   * Requires a lowercase 128-bit identifier encoding.
   *
   * @param value encoded or parsed input value
   */
  private static void id(String value) {
    if (!value.matches("[0-9a-f]{32}")) throw invalid();
  }

  /**
   * Requires a lowercase 256-bit fingerprint encoding.
   *
   * @param value encoded or parsed input value
   */
  private static void fingerprintText(String value) {
    if (!value.matches("[0-9a-f]{64}")) throw invalid();
  }

  /**
   * Requires a positive canonical epoch number.
   *
   * @param value encoded or parsed input value
   */
  private static void positive(String value) {
    if (decimal(value) < 1) throw invalid();
  }

  /**
   * Parses canonical nonnegative signed-64-bit decimal.
   *
   * @param value value to encode or parse
   * @return nonnegative integer value
   * @throws IllegalArgumentException if the input violates the fixed Mail format or limits
   */
  public static long decimal(String value) {
    if (value == null || !value.matches("0|[1-9][0-9]{0,18}")) throw invalid();
    try {
      return Long.parseLong(value);
    } catch (NumberFormatException e) {
      throw invalid();
    }
  }

  /**
   * Encodes canonical padded Base64.
   *
   * @param value value to encode or parse
   * @return canonical padded Base64
   */
  public static String base64(byte[] value) {
    return Base64.getEncoder().encodeToString(value);
  }

  /**
   * Decodes a canonical Base64 value with an exact decoded length.
   *
   * @param value value to encode or parse
   * @param length required decoded byte length
   * @return decoded bytes of the required length
   * @throws IllegalArgumentException if the input violates the fixed Mail format or limits
   */
  public static byte[] unbase64(String value, int length) {
    try {
      if (value.length() != 4 * ((length + 2) / 3)) throw invalid();
      byte[] result = Base64.getDecoder().decode(value);
      if (result.length != length || !base64(result).equals(value)) throw invalid();
      return result;
    } catch (IllegalArgumentException e) {
      throw invalid();
    }
  }

  /**
   * Frames a validated payload with the fixed contact or message domain.
   *
   * @param domain fixed contact or message profile identifier
   * @param payload complete canonical unsigned payload
   * @return domain-separated signature input
   * @throws IllegalArgumentException if the input violates the fixed Mail format or limits
   */
  public static byte[] preimage(String domain, byte[] payload) {
    if (!CONTACT.equals(domain) && !MESSAGE.equals(domain)) throw invalid();
    byte[] canonical =
        CONTACT.equals(domain)
            ? contactPayload(decode(payload, 4096))
            : messagePayload(decode(payload, 32768));
    if (!Arrays.equals(canonical, payload)) throw invalid();
    byte[] prefix = (domain + "\n").getBytes(StandardCharsets.UTF_8);
    byte[] result = Arrays.copyOf(prefix, prefix.length + payload.length);
    System.arraycopy(payload, 0, result, prefix.length, payload.length);
    return result;
  }

  /**
   * Creates a bounded signed wrapper.
   *
   * @param payload complete canonical unsigned payload
   * @param signature 64-byte pure Ed25519 signature
   * @return canonical signed wrapper
   * @throws IllegalArgumentException if the input violates the fixed Mail format or limits
   */
  public static byte[] signed(byte[] payload, byte[] signature) {
    if (payload.length > 32768 || signature.length != 64) throw invalid();
    var m = new LinkedHashMap<String, String>();
    m.put("payload", base64(payload));
    m.put("signature", base64(signature));
    return encode(m);
  }

  /**
   * Requires the exact canonical signed-wrapper shape and field order.
   *
   * @param value encoded or parsed input value
   * @return validated signed-wrapper fields
   */
  private static Map<String, String> wrapper(byte[] value) {
    var m = ordered(decode(value, 45056), List.of("payload", "signature"));
    if (!Arrays.equals(value, encode(m))) throw invalid();
    return m;
  }

  /**
   * Extracts a signed payload; this operation does not establish authenticity.
   *
   * @param value value to encode or parse
   * @return unsigned payload bytes; not yet authenticated
   * @throws IllegalArgumentException if the input violates the fixed Mail format or limits
   */
  public static byte[] signedPayload(byte[] value) {
    String s = wrapper(value).get("payload");
    try {
      byte[] b = Base64.getDecoder().decode(s);
      if (b.length > 32768 || !base64(b).equals(s)) throw invalid();
      return b;
    } catch (IllegalArgumentException e) {
      throw invalid();
    }
  }

  /**
   * Extracts a structurally valid signature without verifying it.
   *
   * @param value value to encode or parse
   * @return signature bytes; not yet verified
   * @throws IllegalArgumentException if the input violates the fixed Mail format or limits
   */
  public static byte[] signature(byte[] value) {
    return unbase64(wrapper(value).get("signature"), 64);
  }

  /**
   * Rejects noncanonical X25519 encodings and public keys producing an all-zero agreement.
   *
   * @param key raw 32-byte public key
   * @throws IllegalArgumentException if the input violates the fixed Mail format or limits
   */
  public static void validateRecipientPublicKey(byte[] key) {
    if (key.length != 32 || (key[31] & 128) != 0) throw invalid();
    byte[] big = key.clone();
    for (int i = 0; i < 16; i++) {
      byte b = big[i];
      big[i] = big[31 - i];
      big[31 - i] = b;
    }
    if (new java.math.BigInteger(1, big)
            .compareTo(
                java.math.BigInteger.ONE.shiftLeft(255).subtract(java.math.BigInteger.valueOf(19)))
        >= 0) throw invalid();
    byte[] validationScalar = new byte[32];
    validationScalar[0] = 8;
    validationScalar[31] = 64;
    try {
      new org.bouncycastle.crypto.params.X25519PrivateKeyParameters(validationScalar)
          .generateSecret(
              new org.bouncycastle.crypto.params.X25519PublicKeyParameters(key), new byte[32], 0);
    } catch (RuntimeException e) {
      throw invalid();
    }
  }

  /**
   * Returns a role-qualified raw-key fingerprint.
   *
   * @param role signing, recipient, or storage key role
   * @param key raw 32-byte public key
   * @return lowercase 64-character role-qualified SHA-256 fingerprint
   * @throws IllegalArgumentException if the input violates the fixed Mail format or limits
   */
  public static String fingerprint(String role, byte[] key) {
    if (!List.of("signing", "recipient", "storage").contains(role) || key.length != 32)
      throw invalid();
    try {
      MessageDigest d = MessageDigest.getInstance("SHA-256");
      d.update((role + "\n").getBytes(StandardCharsets.UTF_8));
      return HexFormat.of().formatHex(d.digest(key));
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
  }

  /**
   * Derives an Ed25519 public key from its independent seed; callers must keep seeds private.
   *
   * @param seed private independent 32-byte Ed25519 seed, retained inside the vault
   * @return raw 32-byte Ed25519 public key
   */
  public static byte[] signingPublicKey(byte[] seed) {
    if (seed.length != 32) throw invalid();
    return new Ed25519PrivateKeyParameters(seed).generatePublicKey().getEncoded();
  }

  /**
   * Signs an already validated preimage; this primitive grants no app authorization.
   *
   * @param seed private independent 32-byte Ed25519 seed, retained inside the vault
   * @param preimage complete application-framed bytes
   * @return 64-byte Ed25519 signature
   */
  public static byte[] sign(byte[] seed, byte[] preimage) {
    if (seed.length != 32) throw invalid();
    Ed25519Signer s = new Ed25519Signer();
    s.init(true, new Ed25519PrivateKeyParameters(seed));
    s.update(preimage, 0, preimage.length);
    return s.generateSignature();
  }

  /**
   * Verifies a pure Ed25519 signature against a pinned raw public key.
   *
   * @param key raw 32-byte public key
   * @param preimage complete application-framed bytes
   * @param signature 64-byte pure Ed25519 signature
   * @return whether the signature verifies against the supplied key and bytes
   */
  public static boolean verify(byte[] key, byte[] preimage, byte[] signature) {
    if (key.length != 32
        || signature.length != 64
        || !org.bouncycastle.math.ec.rfc8032.Ed25519.validatePublicKeyFull(key, 0)) return false;
    try {
      Ed25519Signer s = new Ed25519Signer();
      s.init(false, new Ed25519PublicKeyParameters(key));
      s.update(preimage, 0, preimage.length);
      return s.verifySignature(signature);
    } catch (RuntimeException e) {
      return false;
    }
  }

  /**
   * Creates a bounded format or cryptographic failure.
   *
   * @return bounded rejection exception
   */
  private static IllegalArgumentException invalid() {
    return new IllegalArgumentException("Invalid mail encoding.");
  }

  /** Cursor parser for bounded, canonical, flat string-only JSON. */
  private static final class Parser {
    /** Bounded input text retained only while parsing. */
    private final String text;

    /** Next UTF-16 position in the bounded input. */
    private int pos;

    /**
     * Creates a cursor over the bounded canonical input.
     *
     * @param text bounded input text
     */
    Parser(String text) {
      this.text = text;
    }

    /**
     * Consumes the required next delimiter or rejects the input.
     *
     * @param c required delimiter
     */
    void expect(char c) {
      if (pos >= text.length() || text.charAt(pos++) != c) throw invalid();
    }

    /**
     * Parses the expected object shape.
     *
     * @return parsed object fields
     */
    Map<String, String> object() {
      var result = new LinkedHashMap<String, String>();
      expect('{');
      if (pos < text.length() && text.charAt(pos) == '}') {
        pos++;
      } else {
        while (true) {
          String k = string();
          expect(':');
          String v = string();
          if (result.putIfAbsent(k, v) != null) throw invalid();
          if (pos < text.length() && text.charAt(pos) == ',') {
            pos++;
            continue;
          }
          expect('}');
          break;
        }
      }
      if (pos != text.length()) throw invalid();
      return result;
    }

    /**
     * Parses one string without accepting noncanonical escape forms.
     *
     * @return decoded string
     */
    String string() {
      expect('"');
      StringBuilder out = new StringBuilder();
      while (pos < text.length()) {
        char c = text.charAt(pos++);
        if (c == '"') return out.toString();
        if (c == '\\') {
          if (pos >= text.length()) throw invalid();
          char e = text.charAt(pos++);
          if (e == '"' || e == '\\') out.append(e);
          else if (e == 'u') {
            if (pos + 4 > text.length()) throw invalid();
            try {
              out.append((char) Integer.parseInt(text.substring(pos, pos + 4), 16));
            } catch (NumberFormatException ex) {
              throw invalid();
            }
            pos += 4;
          } else throw invalid();
        } else {
          if (c < 32) throw invalid();
          out.append(c);
        }
      }
      throw invalid();
    }
  }
}
