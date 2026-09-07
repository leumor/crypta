package network.crypta.platform.api.appvault;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import network.crypta.platform.api.PlatformApiException;
import network.crypta.platform.api.PlatformApiParameters;
import network.crypta.platform.api.contentformats.CanonicalJson;
import network.crypta.platform.api.contentformats.ContentFormatProfileRegistry;

/**
 * Validated bounded social-message signing request for one app-visible vault identity.
 *
 * <p>The Social Inbox Preview uses this request type as the app-platform migration counterpart to
 * historical social and mail-like plugin surfaces. It accepts only a small plain-text message
 * schema, binds the message to the authenticated app id and AppVault identity selected by the
 * route, generates the timestamp from the server clock, and fixes the signing domain to {@link
 * #SIGNING_PURPOSE}. It is not a generic browser signing API and does not accept caller-selected
 * signing purposes, raw payloads, or private verification material.
 *
 * <p>The record is intentionally close to the wire contract for {@code crypta.social.message.v1}.
 * It stores normalized public fields only, never private identity material, local vault paths, app
 * process tokens, browser-session tokens, raw request bodies, or raw fetched documents. The route
 * should create instances through {@link #fromQuery(String, String, String, Map, Clock)} so app id
 * binding, field bounds, default values, tag parsing, server-clock timestamps, message-id
 * generation, and canonical JSON construction stay consistent across SDK users and first-party
 * reference apps.
 *
 * <p>Important validation behavior:
 *
 * <ul>
 *   <li>{@code body} is required, plain text, and may contain normal whitespace.
 *   <li>Single-line metadata fields are trimmed, length-bounded, and reject controls.
 *   <li>{@code format} may be omitted or {@code text/plain}; no HTML or rich text is accepted.
 *   <li>Unknown parameters fail closed so callers cannot smuggle alternate signing inputs.
 * </ul>
 *
 * @param appId authenticated app id supplied by the Platform API principal
 * @param identityId vault identity id already visible to the calling app
 * @param authorFingerprint public fingerprint from AppVault identity metadata
 * @param authorLabel optional public author label supplied by the app
 * @param profileUri optional public profile URI associated with the author
 * @param messageId stable id generated from the normalized message fields before signing
 * @param createdAt server-generated creation timestamp
 * @param channel bounded public channel label, defaulting to {@code general}
 * @param subject bounded public message subject
 * @param body bounded plain-text body
 * @param replyTo optional public reply target id or URI
 * @param recipientFingerprint optional public recipient fingerprint metadata
 * @param tags immutable ordered public tag list
 */
record SocialMessageRequest(
    String appId,
    String identityId,
    String authorFingerprint,
    String authorLabel,
    String profileUri,
    String messageId,
    Instant createdAt,
    String channel,
    String subject,
    String body,
    String replyTo,
    String recipientFingerprint,
    List<String> tags) {
  static final String TYPE = ContentFormatProfileRegistry.SOCIAL_MESSAGE_ID;
  static final String SIGNING_PURPOSE = TYPE;

  private static final int MAX_AUTHOR_LABEL_LENGTH = 80;
  private static final int MAX_BODY_LENGTH = 4096;
  private static final int MAX_CHANNEL_LENGTH = 64;
  private static final int MAX_MESSAGE_REFERENCE_LENGTH = 512;
  private static final int MAX_PROFILE_URI_LENGTH = 512;
  private static final int MAX_RECIPIENT_FINGERPRINT_LENGTH = 128;
  private static final int MAX_SUBJECT_LENGTH = 160;
  private static final int MAX_TAG_COUNT = 12;
  private static final int MAX_TAG_LENGTH = 32;
  private static final int MAX_SIGNED_PAYLOAD_BYTES =
      ContentFormatProfileRegistry.DEFAULT_SIGNED_PAYLOAD_MAX_BYTES;
  private static final String FORMAT_TEXT_PLAIN = "text/plain";
  private static final String PARAM_AUTHOR_LABEL = "authorLabel";
  private static final String PARAM_BODY = "body";
  private static final String PARAM_CHANNEL = "channel";
  private static final String PARAM_FORMAT = "format";
  private static final String PARAM_PROFILE_URI = "profileUri";
  private static final String PARAM_RECIPIENT_FINGERPRINT = "recipientFingerprint";
  private static final String PARAM_REPLY_TO = "replyTo";
  private static final String PARAM_SUBJECT = "subject";
  private static final String PARAM_TAGS = "tags";
  private static final String QUERY_PARAMETER_PREFIX = "Query parameter '";
  private static final Set<String> ALLOWED_PARAMETERS =
      Set.of(
          PARAM_AUTHOR_LABEL,
          PARAM_BODY,
          PARAM_CHANNEL,
          PARAM_FORMAT,
          PARAM_PROFILE_URI,
          PARAM_RECIPIENT_FINGERPRINT,
          PARAM_REPLY_TO,
          PARAM_SUBJECT,
          PARAM_TAGS);

  /**
   * Creates an immutable request record from already-normalized values.
   *
   * <p>The compact constructor copies tag state so later caller mutations cannot affect the
   * canonical bytes, generated message object, or signed response. Most callers should use {@link
   * #fromQuery(String, String, String, Map, Clock)} instead because this constructor does not
   * repeat route-level validation or generate a message id.
   */
  SocialMessageRequest {
    tags = List.copyOf(tags);
  }

  /**
   * Builds a validated social-message request from decoded form parameters.
   *
   * <p>The route has already authenticated the caller and resolved the AppVault identity. This
   * method rejects unknown parameters so browser callers cannot smuggle generic signing inputs such
   * as {@code purpose}, {@code domain}, or {@code payloadBase64}. The resulting request is safe to
   * canonicalize and pass to AppVault's internal fixed-domain signing path.
   *
   * <p>Defaults are applied before the message id is generated. Blank optional values are treated
   * as absent; blank {@code channel} becomes {@code general}, and blank {@code subject} becomes the
   * empty string. The message id is derived from the normalized message without a {@code messageId}
   * field, which makes it stable for the same app, identity, server timestamp, and public message
   * fields while avoiding caller-chosen identifiers.
   *
   * @param appId authenticated app id supplied by the Platform API principal
   * @param identityId app-visible vault identity selected by the route
   * @param authorFingerprint public fingerprint from the selected identity
   * @param queryParameters decoded social-message form parameters
   * @param clock server clock used for {@code createdAt}
   * @return normalized request ready for signing
   * @throws PlatformApiException when a required field is missing or any bound fails
   */
  static SocialMessageRequest fromQuery(
      String appId,
      String identityId,
      String authorFingerprint,
      Map<String, List<String>> queryParameters,
      Clock clock) {
    requireOnlyAllowedParameters(queryParameters);
    requireTextPlainFormat(queryParameters);
    Instant createdAt = clock.instant();
    String authorLabel =
        optionalBoundedText(queryParameters, PARAM_AUTHOR_LABEL, MAX_AUTHOR_LABEL_LENGTH, null);
    String profileUri =
        optionalBoundedText(queryParameters, PARAM_PROFILE_URI, MAX_PROFILE_URI_LENGTH, null);
    String channel =
        optionalBoundedText(queryParameters, PARAM_CHANNEL, MAX_CHANNEL_LENGTH, "general");
    String subject = optionalBoundedText(queryParameters, PARAM_SUBJECT, MAX_SUBJECT_LENGTH, "");
    String body = requiredBody(queryParameters);
    String replyTo =
        optionalBoundedText(queryParameters, PARAM_REPLY_TO, MAX_MESSAGE_REFERENCE_LENGTH, null);
    String recipientFingerprint =
        optionalBoundedText(
            queryParameters, PARAM_RECIPIENT_FINGERPRINT, MAX_RECIPIENT_FINGERPRINT_LENGTH, null);
    List<String> tags = readTags(queryParameters);
    String messageId =
        generatedMessageId(
            messagePayload(
                appId,
                identityId,
                authorFingerprint,
                authorLabel,
                profileUri,
                null,
                createdAt,
                channel,
                subject,
                body,
                replyTo,
                recipientFingerprint,
                tags));
    SocialMessageRequest request =
        new SocialMessageRequest(
            appId,
            identityId,
            authorFingerprint,
            authorLabel,
            profileUri,
            messageId,
            createdAt,
            channel,
            subject,
            body,
            replyTo,
            recipientFingerprint,
            tags);
    if (request.canonicalBytes().length > MAX_SIGNED_PAYLOAD_BYTES) {
      throw invalidQuery("Unsigned social message payload is too large.");
    }
    return request;
  }

  /**
   * Returns the public message payload in deterministic field order.
   *
   * <p>Optional fields are emitted only when present. The returned map is detached from this record
   * and may be serialized directly by Platform API response code. Field order is part of the
   * signing contract: verifiers and tests can rely on the insertion order produced here before the
   * JSON writer serializes the map.
   *
   * @return insertion-ordered public message object used inside the signed document
   */
  Map<String, Object> message() {
    return messagePayload(
        appId,
        identityId,
        authorFingerprint,
        authorLabel,
        profileUri,
        messageId,
        createdAt,
        channel,
        subject,
        body,
        replyTo,
        recipientFingerprint,
        tags);
  }

  /**
   * Returns the canonical bytes signed by AppVault for the bounded social message document.
   *
   * <p>The byte sequence starts with the fixed social-message domain followed by a canonical JSON
   * object containing the document type and public message payload. The signature metadata itself
   * is deliberately excluded to avoid circular signing. AppVault receives these bytes after the
   * route has performed capability checks; browser callers never supply or override the prefix.
   *
   * @return UTF-8 domain-separated canonical bytes for the bounded social message
   */
  byte[] canonicalBytes() {
    LinkedHashMap<String, Object> document = LinkedHashMap.newLinkedHashMap(2);
    document.put("type", TYPE);
    document.put("message", message());
    return CanonicalJson.domainSeparatedBytes(SIGNING_PURPOSE, document);
  }

  /**
   * Assembles the public message object with stable field order.
   *
   * <p>This helper is used twice: once without {@code messageId} to derive the stable id from the
   * normalized public fields, and once with {@code messageId} to build the signed document payload.
   * Optional fields are omitted when they are absent so empty UI controls do not become signed
   * placeholder strings.
   *
   * @param appId authenticated app id bound by the route
   * @param identityId resolved vault identity id used for signing
   * @param authorFingerprint public fingerprint from AppVault identity metadata
   * @param authorLabel optional public author label, or {@code null}
   * @param profileUri optional public profile URI, or {@code null}
   * @param messageId generated message id, or {@code null} during id derivation
   * @param createdAt server-clock timestamp to expose in the message
   * @param channel normalized public channel label
   * @param subject normalized public subject text
   * @param body bounded plain-text body
   * @param replyTo optional public reply reference, or {@code null}
   * @param recipientFingerprint optional public recipient fingerprint metadata, or {@code null}
   * @param tags immutable ordered public tag list
   * @return insertion-ordered message object ready for canonical JSON serialization
   */
  private static Map<String, Object> messagePayload(
      String appId,
      String identityId,
      String authorFingerprint,
      String authorLabel,
      String profileUri,
      String messageId,
      Instant createdAt,
      String channel,
      String subject,
      String body,
      String replyTo,
      String recipientFingerprint,
      List<String> tags) {
    LinkedHashMap<String, Object> message = LinkedHashMap.newLinkedHashMap(13);
    message.put("appId", appId);
    message.put("identityId", identityId);
    message.put("authorFingerprint", authorFingerprint);
    if (authorLabel != null) {
      message.put(PARAM_AUTHOR_LABEL, authorLabel);
    }
    if (profileUri != null) {
      message.put(PARAM_PROFILE_URI, profileUri);
    }
    if (messageId != null) {
      message.put("messageId", messageId);
    }
    message.put("createdAt", createdAt.toString());
    message.put(PARAM_CHANNEL, channel);
    message.put(PARAM_SUBJECT, subject);
    message.put(PARAM_BODY, body);
    message.put(PARAM_FORMAT, FORMAT_TEXT_PLAIN);
    if (replyTo != null) {
      message.put(PARAM_REPLY_TO, replyTo);
    }
    if (recipientFingerprint != null) {
      message.put(PARAM_RECIPIENT_FINGERPRINT, recipientFingerprint);
    }
    if (!tags.isEmpty()) {
      message.put(PARAM_TAGS, tags);
    }
    return message;
  }

  /**
   * Rejects every caller-supplied parameter outside the bounded social-message schema.
   *
   * <p>The allow-list is part of the browser-safety boundary. Parameters such as {@code purpose},
   * {@code domain}, {@code payloadBase64}, or future generic signing controls must fail before any
   * canonical bytes are built.
   *
   * @param queryParameters decoded route parameters supplied by the Platform API router
   * @throws PlatformApiException when any unsupported parameter name is present
   */
  private static void requireOnlyAllowedParameters(Map<String, List<String>> queryParameters) {
    for (String parameter : queryParameters.keySet()) {
      if (!ALLOWED_PARAMETERS.contains(parameter)) {
        throw invalidQuery(QUERY_PARAMETER_PREFIX + parameter + "' is not supported.");
      }
    }
  }

  /**
   * Validates the optional message format parameter.
   *
   * <p>The v1 route signs only plain text. A missing or blank value is accepted for SDK convenience
   * and normalized by the emitted message payload to {@code text/plain}; any other caller-supplied
   * format is rejected.
   *
   * @param queryParameters decoded route parameters supplied by the Platform API router
   * @throws PlatformApiException when {@code format} is not blank and not {@code text/plain}
   */
  private static void requireTextPlainFormat(Map<String, List<String>> queryParameters) {
    String format = PlatformApiParameters.readOptionalString(queryParameters, PARAM_FORMAT);
    if (format == null || format.isBlank()) {
      return;
    }
    if (!FORMAT_TEXT_PLAIN.equals(format.trim())) {
      throw invalidQuery(QUERY_PARAMETER_PREFIX + PARAM_FORMAT + "' must be text/plain.");
    }
  }

  /**
   * Reads and validates the required plain-text body.
   *
   * <p>The body is the only required caller text field. It may contain normal whitespace used by a
   * multiline text area, including line feed, carriage return, and tab, but rejects other ASCII
   * controls so the signed JSON, release evidence, and plain-text rendering path stay predictable.
   *
   * @param queryParameters decoded route parameters supplied by the Platform API router
   * @return original body text when it satisfies the route limits
   * @throws PlatformApiException when the body is missing, too large, or contains unsafe controls
   */
  private static String requiredBody(Map<String, List<String>> queryParameters) {
    String value = PlatformApiParameters.requireString(queryParameters, PARAM_BODY);
    if (value.length() > MAX_BODY_LENGTH) {
      throw invalidQuery(QUERY_PARAMETER_PREFIX + PARAM_BODY + "' is too long.");
    }
    if (containsControlCharacterExceptNormalWhitespace(value)) {
      throw invalidQuery(
          QUERY_PARAMETER_PREFIX
              + PARAM_BODY
              + "' must not contain control characters other than normal whitespace.");
    }
    return value;
  }

  /**
   * Reads one optional bounded text parameter.
   *
   * <p>Blank values are treated as absent and replaced with {@code defaultValue}. Nonblank values
   * are trimmed before length and single-line control-character validation.
   *
   * @param queryParameters decoded route parameters supplied by the Platform API router
   * @param name parameter name used in stable error messages
   * @param maxLength maximum accepted Java {@code char} length after trimming
   * @param defaultValue value returned when the parameter is absent or blank
   * @return trimmed value, or {@code defaultValue} when absent or blank
   * @throws PlatformApiException when the value is too long or contains disallowed controls
   */
  private static String optionalBoundedText(
      Map<String, List<String>> queryParameters, String name, int maxLength, String defaultValue) {
    String value = PlatformApiParameters.readOptionalString(queryParameters, name);
    if (value == null || value.isBlank()) {
      return defaultValue;
    }
    String trimmed = value.trim();
    if (trimmed.length() > maxLength) {
      throw invalidQuery(QUERY_PARAMETER_PREFIX + name + "' is too long.");
    }
    if (containsControlCharacter(trimmed)) {
      throw invalidQuery(QUERY_PARAMETER_PREFIX + name + "' must not contain control characters.");
    }
    return trimmed;
  }

  /**
   * Parses optional comma-separated public tag values.
   *
   * <p>The route accepts repeated {@code tags} parameters and comma-separated values within each
   * parameter. Empty segments are rejected so callers cannot sign ambiguous tag lists such as
   * {@code "social,,preview"}. The returned list preserves caller order after trimming and is
   * immutable before it is attached to the request record.
   *
   * @param queryParameters decoded route parameters supplied by the Platform API router
   * @return immutable ordered list of validated public social-message tags
   * @throws PlatformApiException when a tag is empty, too long, unsafe, or too numerous
   */
  private static List<String> readTags(Map<String, List<String>> queryParameters) {
    List<String> rawValues = queryParameters.get(PARAM_TAGS);
    if (rawValues == null || rawValues.isEmpty()) {
      return List.of();
    }
    ArrayList<String> tags = new ArrayList<>();
    for (String rawValue : rawValues) {
      appendTagsFromRawValue(tags, rawValue);
    }
    if (tags.size() > MAX_TAG_COUNT) {
      throw invalidQuery(QUERY_PARAMETER_PREFIX + PARAM_TAGS + "' contains too many tags.");
    }
    return List.copyOf(tags);
  }

  /**
   * Adds all comma-separated tags from one raw request value.
   *
   * <p>Blank repeated parameters are ignored, matching the optional-field behavior used elsewhere
   * in the request. Nonblank values are split with empty trailing segments preserved so malformed
   * input such as {@code "one,"} still fails validation.
   *
   * @param tags mutable accumulator preserving validated caller order
   * @param rawValue raw repeated request value, or {@code null}
   * @throws PlatformApiException when a split tag segment fails validation
   */
  private static void appendTagsFromRawValue(List<String> tags, String rawValue) {
    if (rawValue == null || rawValue.isBlank()) {
      return;
    }
    for (String rawTag : rawValue.split(",", -1)) {
      tags.add(validatedTag(rawTag.trim()));
    }
  }

  /**
   * Validates one trimmed public tag value.
   *
   * @param tag trimmed tag segment from a comma-separated request value
   * @return the original tag when it satisfies the social-message tag limits
   * @throws PlatformApiException when the tag is empty, too long, or contains controls
   */
  private static String validatedTag(String tag) {
    if (tag.isEmpty()) {
      throw invalidQuery(QUERY_PARAMETER_PREFIX + PARAM_TAGS + "' must not contain empty tags.");
    }
    if (tag.length() > MAX_TAG_LENGTH) {
      throw invalidQuery(
          QUERY_PARAMETER_PREFIX + PARAM_TAGS + "' contains a tag that is too long.");
    }
    if (containsControlCharacter(tag)) {
      throw invalidQuery(
          QUERY_PARAMETER_PREFIX + PARAM_TAGS + "' must not contain control characters.");
    }
    return tag;
  }

  /**
   * Generates the stable public message id from the normalized message without an id field.
   *
   * <p>The id is a {@code msg-} prefix plus the SHA-256 hex digest of the canonical JSON form of
   * {@code messageWithoutId}. Because the timestamp is server-generated, two otherwise identical
   * posts signed at different instants receive different ids.
   *
   * @param messageWithoutId insertion-ordered message object that deliberately omits {@code
   *     messageId}
   * @return deterministic {@code msg-} identifier for the normalized message fields
   */
  private static String generatedMessageId(Map<String, Object> messageWithoutId) {
    return "msg-"
        + sha256Hex(CanonicalJson.write(messageWithoutId).getBytes(StandardCharsets.UTF_8));
  }

  /**
   * Computes a lowercase SHA-256 hexadecimal digest.
   *
   * <p>SHA-256 is required by the Java platform. If the runtime cannot provide it, the method
   * throws an unchecked failure because the route cannot safely construct stable message ids.
   *
   * @param bytes canonical UTF-8 bytes to hash
   * @return lowercase hexadecimal SHA-256 digest string
   * @throws IllegalStateException when the Java runtime lacks SHA-256 support
   */
  private static String sha256Hex(byte[] bytes) {
    try {
      byte[] digest = MessageDigest.getInstance("SHA-256").digest(bytes);
      StringBuilder builder = new StringBuilder(digest.length * 2);
      for (byte value : digest) {
        builder.append(Character.forDigit((value >>> 4) & 0x0f, 16));
        builder.append(Character.forDigit(value & 0x0f, 16));
      }
      return builder.toString();
    } catch (NoSuchAlgorithmException exception) {
      throw new IllegalStateException("SHA-256 is unavailable.", exception);
    }
  }

  /**
   * Checks for ASCII controls or unpaired UTF-16 surrogates.
   *
   * <p>This stricter helper is used for single-line public metadata such as channel, subject, reply
   * references, recipient fingerprints, and tags. It rejects line breaks and tabs because those
   * fields are meant to remain compact labels or identifiers.
   *
   * @param value text value to scan
   * @return {@code true} when the value contains a disallowed control character
   */
  private static boolean containsControlCharacter(String value) {
    for (int index = 0;
        index < value.length();
        index += Character.isHighSurrogate(value.charAt(index)) ? 2 : 1) {
      char ch = value.charAt(index);
      if (Character.isHighSurrogate(ch)) {
        if (index + 1 >= value.length() || !Character.isLowSurrogate(value.charAt(index + 1))) {
          return true;
        }
        continue;
      }
      if (Character.isLowSurrogate(ch)) {
        return true;
      }
      if (ch < 0x20 || ch == 0x7f) {
        return true;
      }
    }
    return false;
  }

  /**
   * Checks for unpaired surrogates and ASCII controls while allowing normal text-area whitespace.
   *
   * <p>The body path uses this helper so users can compose multiline plain text. NUL, delete, and
   * other non-rendering controls still fail validation before the payload is signed.
   *
   * @param value text value to scan
   * @return {@code true} when the value contains a control character other than LF, CR, or tab
   */
  private static boolean containsControlCharacterExceptNormalWhitespace(String value) {
    for (int index = 0;
        index < value.length();
        index += Character.isHighSurrogate(value.charAt(index)) ? 2 : 1) {
      char ch = value.charAt(index);
      if (Character.isHighSurrogate(ch)) {
        if (index + 1 >= value.length() || !Character.isLowSurrogate(value.charAt(index + 1))) {
          return true;
        }
        continue;
      }
      if (Character.isLowSurrogate(ch)) {
        return true;
      }
      if ((ch < 0x20 || ch == 0x7f) && ch != '\n' && ch != '\r' && ch != '\t') {
        return true;
      }
    }
    return false;
  }

  /**
   * Creates the stable Platform API error used for social-message validation failures.
   *
   * @param message human-readable validation failure summary for the response body
   * @return bad-request exception with the social-message route's validation error code
   */
  private static PlatformApiException invalidQuery(String message) {
    return new PlatformApiException(400, "invalid_query_parameter", message);
  }
}
