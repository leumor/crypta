package network.crypta.platform.trustgraph;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;

/**
 * Shared validation helpers for the bounded trust statement model.
 *
 * <p>The validator centralizes size, text, range, tag, and timestamp checks used by both parsed
 * documents and server-generated trust statements. It intentionally reports stable {@link
 * TrustGraphException} codes so Platform API handlers can translate caller mistakes into validation
 * responses instead of leaking parser details.
 *
 * <p>Validation is conservative: blank optional text is discarded, control characters are rejected,
 * timestamps must be ISO-8601 instants, and all untrusted user-provided collections are copied
 * before they reach the immutable model. The helpers do not perform signature verification; that is
 * the responsibility of {@link TrustStatementVerifier}.
 */
public final class TrustStatementValidator {
  /**
   * Maximum accepted UTF-8 document size for imported trust statement JSON.
   *
   * <p>The limit bounds request memory use before parsing and applies equally to pasted, fetched,
   * and mock-server imports.
   */
  public static final int MAX_DOCUMENT_BYTES = 64 * 1024;

  private static final int MIN_CONFIDENCE = 0;
  private static final int MIN_SCORE = -100;
  private static final int MAX_SCORE_OR_CONFIDENCE = 100;
  private static final int MAX_TAG_COUNT = 16;
  private static final int MAX_TAG_LENGTH = 32;

  private TrustStatementValidator() {}

  /**
   * Validates a complete statement and returns it for fluent callers.
   *
   * <p>Most invariants are enforced by the nested record constructors. This method exists as a
   * single post-parse validation hook so future document-level checks can be added without changing
   * parser call sites.
   *
   * @param document statement assembled from validated model parts
   * @return the same statement instance
   */
  public static TrustStatementDocument validate(TrustStatementDocument document) {
    return java.util.Objects.requireNonNull(document, "document");
  }

  /**
   * Validates a trust statement context label.
   *
   * @param context candidate context from a parsed or server-generated payload
   * @return normalized context value accepted by the preview format
   */
  static String requiredContext(String context) {
    String value = requiredText("context", context, 64);
    if (!TrustStatementPayload.ALLOWED_CONTEXTS.contains(value)) {
      throw new TrustGraphException(
          "invalid_trust_statement",
          "Field 'context' must be one of " + TrustStatementPayload.ALLOWED_CONTEXTS + ".");
    }
    return value;
  }

  /**
   * Requires a trust score to fall within the preview statement range.
   *
   * @param score candidate score
   */
  static void requireScore(int score) {
    requireRangeWithSharedMaximum("score", score, MIN_SCORE);
  }

  /**
   * Requires a confidence percentage to fall within the preview statement range.
   *
   * @param confidence candidate confidence
   */
  static void requireConfidence(int confidence) {
    requireRangeWithSharedMaximum("confidence", confidence, MIN_CONFIDENCE);
  }

  /**
   * Returns bounded text for a required field.
   *
   * @param fieldName public field name used in validation messages
   * @param value candidate text
   * @param maxLength maximum accepted character length after trimming
   * @return trimmed text
   */
  static String requiredText(String fieldName, String value, int maxLength) {
    String text = optionalText(fieldName, value, maxLength);
    if (text == null) {
      throw new TrustGraphException(
          "invalid_trust_statement", "Field '" + fieldName + "' is required.");
    }
    return text;
  }

  /**
   * Returns trimmed bounded text for an optional field.
   *
   * <p>Blank values are treated as omitted. Non-blank values are rejected when they exceed the
   * length bound or include unsafe control characters.
   *
   * @param fieldName public field name used in validation messages
   * @param value candidate text, or {@code null}
   * @param maxLength maximum accepted character length after trimming
   * @return trimmed text, or {@code null} when omitted
   */
  static String optionalText(String fieldName, String value, int maxLength) {
    if (value == null || value.isBlank()) {
      return null;
    }
    String text = value.trim();
    requireWellFormedUnicode(text);
    if (text.length() > maxLength) {
      throw new TrustGraphException(
          "invalid_trust_statement", "Field '" + fieldName + "' is too long.");
    }
    if (containsUnsafeControl(text)) {
      throw new TrustGraphException(
          "invalid_trust_statement",
          "Field '" + fieldName + "' must not contain control characters.");
    }
    return text;
  }

  /**
   * Validates and freezes a trust statement tag list.
   *
   * @param source caller-provided tag list, or {@code null}
   * @return immutable list of trimmed tags
   */
  static List<String> tags(List<String> source) {
    if (source == null || source.isEmpty()) {
      return List.of();
    }
    ArrayList<String> tags = new ArrayList<>();
    for (String raw : source) {
      String tag = optionalText("tags", raw, MAX_TAG_LENGTH);
      if (tag == null) {
        throw new TrustGraphException(
            "invalid_trust_statement", "Field 'tags' must not contain blank tags.");
      }
      tags.add(tag);
      if (tags.size() > MAX_TAG_COUNT) {
        throw new TrustGraphException(
            "invalid_trust_statement", "Field 'tags' contains too many tags.");
      }
    }
    return List.copyOf(tags);
  }

  /**
   * Parses an ISO-8601 instant field from parsed JSON.
   *
   * @param fieldName public field name used in validation messages
   * @param value parsed JSON value
   * @param required whether the field must be present
   * @return parsed instant, or {@code null} when optional and omitted
   */
  static Instant parseInstant(String fieldName, Object value, boolean required) {
    if (value == null) {
      if (required) {
        throw new TrustGraphException(
            "invalid_trust_statement", "Field '" + fieldName + "' is required.");
      }
      return null;
    }
    if (!(value instanceof String text) || text.isBlank()) {
      throw new TrustGraphException(
          "invalid_trust_statement", "Field '" + fieldName + "' must be an ISO-8601 instant.");
    }
    try {
      return Instant.parse(text.trim());
    } catch (DateTimeParseException _) {
      throw new TrustGraphException(
          "invalid_trust_statement", "Field '" + fieldName + "' must be an ISO-8601 instant.");
    }
  }

  private static boolean containsUnsafeControl(String value) {
    for (int index = 0; index < value.length(); index++) {
      char ch = value.charAt(index);
      if (Character.isISOControl(ch)) {
        return true;
      }
    }
    return false;
  }

  /** Rejects unpaired UTF-16 surrogates before UTF-8 signature encoding can replace them. */
  static void requireWellFormedUnicode(String value) {
    for (int index = 0;
        index < value.length();
        index += Character.isHighSurrogate(value.charAt(index)) ? 2 : 1) {
      char ch = value.charAt(index);
      if (Character.isHighSurrogate(ch)) {
        if (index + 1 >= value.length() || !Character.isLowSurrogate(value.charAt(index + 1))) {
          throw new TrustGraphException("invalid_trust_statement", "Malformed Unicode text.");
        }
      } else if (Character.isLowSurrogate(ch)) {
        throw new TrustGraphException("invalid_trust_statement", "Malformed Unicode text.");
      }
    }
  }

  private static void requireRangeWithSharedMaximum(String fieldName, int value, int min) {
    if (value < min || value > MAX_SCORE_OR_CONFIDENCE) {
      throw new TrustGraphException(
          "invalid_trust_statement",
          "Field '"
              + fieldName
              + "' must be between "
              + min
              + " and "
              + MAX_SCORE_OR_CONFIDENCE
              + ".");
    }
  }
}
