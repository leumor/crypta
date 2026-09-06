package network.crypta.platform.api.appvault;

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
 * Validated unsigned Crypta profile document payload supplied by one app.
 *
 * <p>The profile document route accepts only this narrow, deterministic payload shape from browser
 * app principals. It does not accept arbitrary signing payloads or caller-selected signing
 * purposes; the route builds this profile object, canonicalizes it with stable field order, and
 * asks the vault to sign those bytes under the fixed profile-publishing purpose.
 *
 * <p>The record is intentionally close to the wire contract. It holds only normalized app-facing
 * fields, never private key material, local vault paths, app process tokens, or request bodies.
 * Text validation is strict by default: display names, URI-like fields, and tags reject control
 * characters, while the bio field permits line breaks because the reference app exposes it as a
 * multiline text area. Callers should create instances through {@link #fromQuery(String, String,
 * Map)} so size limits, canonical JSON generation, and tag parsing stay consistent with the
 * published Platform API route.
 *
 * @param appId authenticated app id bound by the Platform API principal, not request input
 * @param identityId target identity id after route lookup and app-visibility checks have passed
 * @param displayName required public profile display name, trimmed and length-bounded
 * @param bio optional multiline public biography, trimmed and length-bounded
 * @param website optional public website or profile URI text, trimmed and length-bounded
 * @param avatarUri optional public avatar URI text, trimmed and length-bounded
 * @param contactUri optional public contact URI text, trimmed and length-bounded
 * @param tags immutable public tag list parsed from comma-separated request values
 */
record ProfileDocumentRequest(
    String appId,
    String identityId,
    String displayName,
    String bio,
    String website,
    String avatarUri,
    String contactUri,
    List<String> tags) {
  static final String SCHEMA = ContentFormatProfileRegistry.PROFILE_DOCUMENT_ID;
  static final String SIGNING_PURPOSE =
      ContentFormatProfileRegistry.PROFILE_DOCUMENT_SIGNING_PURPOSE;

  private static final int MAX_DISPLAY_NAME_LENGTH = 80;
  private static final int MAX_BIO_LENGTH = 512;
  private static final int MAX_URI_LENGTH = 512;
  private static final int MAX_TAG_COUNT = 16;
  private static final int MAX_TAG_LENGTH = 32;
  private static final int MAX_UNSIGNED_PAYLOAD_BYTES =
      ContentFormatProfileRegistry.DEFAULT_SIGNED_PAYLOAD_MAX_BYTES;
  private static final String PARAM_AVATAR_URI = "avatarUri";
  private static final String PARAM_BIO = "bio";
  private static final String PARAM_CONTACT_URI = "contactUri";
  private static final String PARAM_DISPLAY_NAME = "displayName";
  private static final String PARAM_TAGS = "tags";
  private static final String PARAM_WEBSITE = "website";
  private static final String QUERY_PARAMETER_PREFIX = "Query parameter '";
  private static final Set<String> ALLOWED_PARAMETERS =
      Set.of(
          PARAM_AVATAR_URI,
          PARAM_BIO,
          PARAM_CONTACT_URI,
          PARAM_DISPLAY_NAME,
          PARAM_TAGS,
          PARAM_WEBSITE);

  /** Defensively copies tag state so later caller mutations cannot affect canonical bytes. */
  ProfileDocumentRequest {
    tags = List.copyOf(tags);
  }

  /**
   * Builds a validated profile request from decoded route query parameters.
   *
   * <p>The route has already authenticated the app and resolved the target identity. This method
   * binds those trusted values to caller-supplied profile fields, applies the v1 profile limits,
   * and verifies that the canonical unsigned payload remains below the route's total size cap. The
   * resulting record is safe to pass to the signed profile document builder and to the vault
   * identity-use call.
   *
   * @param appId authenticated app id supplied by the Platform API principal
   * @param identityId resolved profile identity id being used for signing
   * @param queryParameters decoded profile-document request parameters from the router
   * @return normalized profile request with deterministic canonical serialization
   * @throws PlatformApiException when a required field is missing or any profile limit fails
   */
  static ProfileDocumentRequest fromQuery(
      String appId, String identityId, Map<String, List<String>> queryParameters) {
    rejectUnsupportedParameters(queryParameters);
    ProfileDocumentRequest request =
        new ProfileDocumentRequest(
            appId,
            identityId,
            requiredDisplayName(queryParameters),
            optionalBio(queryParameters),
            optionalUriText(queryParameters, PARAM_WEBSITE),
            optionalUriText(queryParameters, PARAM_AVATAR_URI),
            optionalUriText(queryParameters, PARAM_CONTACT_URI),
            readTags(queryParameters));
    if (request.canonicalBytes().length > MAX_UNSIGNED_PAYLOAD_BYTES) {
      throw invalidQuery("Unsigned profile payload is too large.");
    }
    return request;
  }

  /**
   * Returns the unsigned profile payload in canonical field order.
   *
   * <p>The map order is part of the signed-data contract. Optional fields are emitted only when
   * present, and tags are emitted only when at least one tag survives parsing. The returned map is
   * a fresh insertion-ordered value each time, so callers can serialize it without retaining
   * mutable shared state from this record.
   *
   * @return insertion-ordered profile payload used as the signature input
   */
  Map<String, Object> payload() {
    LinkedHashMap<String, Object> profile = LinkedHashMap.newLinkedHashMap(8);
    profile.put("schema", SCHEMA);
    profile.put("appId", appId);
    profile.put("identityId", identityId);
    profile.put(PARAM_DISPLAY_NAME, displayName);
    if (bio != null) {
      profile.put(PARAM_BIO, bio);
    }
    if (website != null) {
      profile.put(PARAM_WEBSITE, website);
    }
    if (avatarUri != null) {
      profile.put(PARAM_AVATAR_URI, avatarUri);
    }
    if (contactUri != null) {
      profile.put(PARAM_CONTACT_URI, contactUri);
    }
    if (!tags.isEmpty()) {
      profile.put(PARAM_TAGS, tags);
    }
    return profile;
  }

  /**
   * Serializes the unsigned payload to deterministic UTF-8 JSON bytes.
   *
   * <p>The Platform API JSON writer provides stable object ordering for the map constructed by
   * {@link #payload()}. The bytes returned here are the exact bytes passed to {@code
   * AppVaultService.useIdentity(...)} for the profile-publishing signature operation.
   *
   * @return canonical UTF-8 JSON payload bytes for domain-separated signing
   */
  byte[] canonicalBytes() {
    return CanonicalJson.bytes(payload());
  }

  /**
   * Reads the required display-name text parameter.
   *
   * @param queryParameters decoded request parameter map from the router
   * @return trimmed parameter value with control characters rejected
   * @throws PlatformApiException when the value is absent, blank, too long, or unsafe
   */
  private static String requiredDisplayName(Map<String, List<String>> queryParameters) {
    String value = PlatformApiParameters.requireString(queryParameters, PARAM_DISPLAY_NAME).trim();
    if (value.isEmpty()) {
      throw invalidQuery(QUERY_PARAMETER_PREFIX + PARAM_DISPLAY_NAME + "' must not be blank.");
    }
    return boundedText(PARAM_DISPLAY_NAME, value, MAX_DISPLAY_NAME_LENGTH);
  }

  /**
   * Reads the optional bio text parameter, which may contain line breaks.
   *
   * <p>The profile bio uses this path because Profile Publisher presents it as a multiline field.
   * Only carriage return and line feed are accepted as controls; tabs, NUL, delete, and other
   * control characters still fail validation before the payload is signed.
   *
   * @param queryParameters decoded request parameter map from the router
   * @return trimmed multiline value, or {@code null} when absent or blank
   * @throws PlatformApiException when the value is too long or contains unsafe controls
   */
  private static String optionalBio(Map<String, List<String>> queryParameters) {
    String value = PlatformApiParameters.readOptionalString(queryParameters, PARAM_BIO);
    if (value == null || value.isBlank()) {
      return null;
    }
    return boundedBioText(value.trim());
  }

  /**
   * Reads one optional URI-like text parameter.
   *
   * <p>The v1 profile route deliberately treats these as bounded text rather than resolving or
   * dereferencing them. This keeps the route offline and avoids granting browser apps any network
   * or filesystem authority. Control characters are rejected so the value remains safe for JSON,
   * logs, and UI summaries.
   *
   * @param queryParameters decoded request parameter map from the router
   * @param name URI parameter name used in stable error messages
   * @return trimmed URI text, or {@code null} when absent or blank
   * @throws PlatformApiException when the value is too long or contains controls
   */
  private static String optionalUriText(Map<String, List<String>> queryParameters, String name) {
    String value = PlatformApiParameters.readOptionalString(queryParameters, name);
    if (value == null || value.isBlank()) {
      return null;
    }
    return boundedText(name, value.trim(), MAX_URI_LENGTH);
  }

  /**
   * Applies the common single-line text bounds.
   *
   * @param name parameter name used in stable error messages
   * @param value already-trimmed text value to validate
   * @param maxLength maximum accepted Java {@code char} length
   * @return the original value when it satisfies the route limits
   * @throws PlatformApiException when the value is too long or contains controls
   */
  private static String boundedText(String name, String value, int maxLength) {
    if (value.length() > maxLength) {
      throw invalidQuery(QUERY_PARAMETER_PREFIX + name + "' is too long.");
    }
    if (containsControlCharacter(value)) {
      throw invalidQuery(QUERY_PARAMETER_PREFIX + name + "' must not contain control characters.");
    }
    return value;
  }

  /**
   * Applies the multiline text bounds used by the profile bio.
   *
   * @param value already-trimmed text value to validate
   * @return the original value when it satisfies the route limits
   * @throws PlatformApiException when the value is too long or contains unsafe controls
   */
  private static String boundedBioText(String value) {
    if (value.length() > MAX_BIO_LENGTH) {
      throw invalidQuery(QUERY_PARAMETER_PREFIX + PARAM_BIO + "' is too long.");
    }
    if (containsControlCharacterExceptLineBreaks(value)) {
      throw invalidQuery(
          QUERY_PARAMETER_PREFIX
              + PARAM_BIO
              + "' must not contain control characters other than line breaks.");
    }
    return value;
  }

  /**
   * Parses the optional comma-separated tag parameter values.
   *
   * <p>The route accepts repeated {@code tags} parameters and comma-separated values within each
   * parameter. Empty tag segments are rejected so callers cannot accidentally sign ambiguous tag
   * lists such as {@code "crypta,,profile"}. The returned list is immutable and preserves caller
   * order after trimming.
   *
   * @param queryParameters decoded request parameter map from the router
   * @return immutable ordered list of validated public profile tags
   * @throws PlatformApiException when a tag is empty, too long, unsafe, or too numerous
   */
  private static List<String> readTags(Map<String, List<String>> queryParameters) {
    List<String> rawValues = queryParameters.get(PARAM_TAGS);
    if (rawValues == null || rawValues.isEmpty()) {
      return List.of();
    }
    ArrayList<String> tags = new ArrayList<>();
    for (String rawValue : rawValues) {
      if (rawValue == null || rawValue.isBlank()) {
        continue;
      }
      for (String rawTag : rawValue.split(",", -1)) {
        String tag = rawTag.trim();
        if (tag.isEmpty()) {
          throw invalidQuery(
              QUERY_PARAMETER_PREFIX + PARAM_TAGS + "' must not contain empty tags.");
        }
        tags.add(boundedText(PARAM_TAGS, tag, MAX_TAG_LENGTH));
      }
    }
    if (tags.size() > MAX_TAG_COUNT) {
      throw invalidQuery(QUERY_PARAMETER_PREFIX + PARAM_TAGS + "' contains too many tags.");
    }
    return List.copyOf(tags);
  }

  /**
   * Rejects caller-supplied fields outside the profile v1 schema before signing.
   *
   * <p>The app-vault profile route signs a fixed public profile payload. Unknown request parameters
   * fail closed so callers cannot smuggle alternate signing inputs, future fields, raw payloads, or
   * caller-selected purposes into the canonical bytes.
   *
   * @param queryParameters decoded profile-document request parameters
   * @throws PlatformApiException when any unsupported parameter name is present
   */
  private static void rejectUnsupportedParameters(Map<String, List<String>> queryParameters) {
    for (String parameter : queryParameters.keySet()) {
      if (!ALLOWED_PARAMETERS.contains(parameter)) {
        throw invalidQuery(QUERY_PARAMETER_PREFIX + parameter + "' is not supported.");
      }
    }
  }

  /**
   * Checks for ASCII controls or unpaired UTF-16 surrogates.
   *
   * @param value text value to scan without normalization
   * @return {@code true} when the value contains an ASCII control or delete character
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
   * Checks for unpaired surrogates and controls other than carriage return and line feed.
   *
   * @param value multiline text value to scan without normalization
   * @return {@code true} when the value contains a disallowed control character
   */
  private static boolean containsControlCharacterExceptLineBreaks(String value) {
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
      if ((ch < 0x20 && ch != '\n' && ch != '\r') || ch == 0x7f) {
        return true;
      }
    }
    return false;
  }

  /**
   * Creates the stable bad-request exception used by profile field validation.
   *
   * @param message human-readable route error message without request body content
   * @return Platform API exception carrying the stable profile-document error code
   */
  private static PlatformApiException invalidQuery(String message) {
    return new PlatformApiException(400, "invalid_query_parameter", message);
  }
}
