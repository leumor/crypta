package network.crypta.apps.mail;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Bounded nested JSON reader for trusted local Platform API responses, never the mail wire codec.
 */
final class MailApiJsonParser {
  /** Maximum accepted local JSON container nesting depth. */
  private static final int MAX_NESTING_DEPTH = 16;

  /** Bounded input text retained only while parsing. */
  private final String text;

  /** Next UTF-16 position in the local response. */
  private int index;

  /**
   * Creates a cursor over already bounded local response text.
   *
   * @param text bounded input text
   */
  private MailApiJsonParser(String text) {
    this.text = text;
  }

  /**
   * Parses a bounded app-data JSON value.
   *
   * <p>The returned object graph uses {@link Map}, {@link List}, {@link String}, {@link Boolean},
   * {@link Long}, and {@code null}. Callers remain responsible for validating the expected export
   * payload shape and applying app-data quota checks before any imported value is committed.
   *
   * @param text UTF-16 Java string containing UTF-8-decoded app-data JSON
   * @return parsed JSON value tree using platform-owned collection types
   * @throws IllegalArgumentException if the input is malformed or uses unsupported JSON number
   *     forms
   */
  static Object parse(String text) {
    if (text.length() > 1048576) throw error();
    return new MailApiJsonParser(text).parse();
  }

  /**
   * Parses one complete local JSON value and rejects trailing content.
   *
   * @return complete parsed JSON value
   */
  private Object parse() {
    Object value = parseValue(0);
    skipWhitespace();
    if (index != text.length()) {
      throw error();
    }
    return value;
  }

  /**
   * Dispatches a local JSON value according to its first token.
   *
   * @param depth current container nesting depth
   * @return parsed JSON value
   */
  private Object parseValue(int depth) {
    skipWhitespace();
    if (index >= text.length()) {
      throw error();
    }
    return switch (text.charAt(index)) {
      case '{' -> parseObject(depth);
      case '[' -> parseArray(depth);
      case '"' -> parseString();
      case 't' -> parseLiteral("true", Boolean.TRUE);
      case 'f' -> parseLiteral("false", Boolean.FALSE);
      case 'n' -> parseLiteral("null", null);
      default -> parseNumber();
    };
  }

  /**
   * Parses local JSON object members within the nesting limit.
   *
   * @param depth current container nesting depth
   * @return parsed object fields
   */
  private Map<String, Object> parseObject(int depth) {
    requireDepth(depth);
    expect('{');
    LinkedHashMap<String, Object> object = new LinkedHashMap<>();
    skipWhitespace();
    if (consume('}')) {
      return object;
    }
    do {
      skipWhitespace();
      String key = parseString();
      if (object.containsKey(key)) {
        throw error();
      }
      skipWhitespace();
      expect(':');
      object.put(key, parseValue(depth + 1));
      skipWhitespace();
    } while (consume(','));
    expect('}');
    return object;
  }

  /**
   * Parses an ordered local JSON array within the nesting limit.
   *
   * @param depth current container nesting depth
   * @return ordered parsed array
   */
  private List<Object> parseArray(int depth) {
    requireDepth(depth);
    expect('[');
    ArrayList<Object> array = new ArrayList<>();
    skipWhitespace();
    if (consume(']')) {
      return java.util.Collections.unmodifiableList(array);
    }
    do {
      array.add(parseValue(depth + 1));
      skipWhitespace();
    } while (consume(','));
    expect(']');
    return java.util.Collections.unmodifiableList(array);
  }

  /**
   * Rejects a container exceeding the nesting limit.
   *
   * @param depth current container nesting depth
   */
  private void requireDepth(int depth) {
    if (depth >= MAX_NESTING_DEPTH) {
      throw error();
    }
  }

  /**
   * Parses one local JSON string.
   *
   * @return decoded local JSON string
   */
  private String parseString() {
    expect('"');
    StringBuilder value = new StringBuilder();
    while (index < text.length()) {
      char ch = text.charAt(index++);
      if (ch == '"') {
        return value.toString();
      }
      if (ch == '\\') {
        value.append(parseEscape());
      } else if (ch < 0x20) {
        throw error();
      } else {
        value.append(ch);
      }
    }
    throw error();
  }

  /**
   * Decodes one supported JSON string escape.
   *
   * @return decoded escaped character
   */
  private char parseEscape() {
    if (index >= text.length()) {
      throw error();
    }
    char escaped = text.charAt(index++);
    return switch (escaped) {
      case '"', '\\', '/' -> escaped;
      case 'b' -> '\b';
      case 'f' -> '\f';
      case 'n' -> '\n';
      case 'r' -> '\r';
      case 't' -> '\t';
      case 'u' -> parseUnicodeEscape();
      default -> throw error();
    };
  }

  /**
   * Parses the four hexadecimal digits of a Unicode escape.
   *
   * @return decoded UTF-16 code unit
   */
  private char parseUnicodeEscape() {
    if (index + 4 > text.length()) {
      throw error();
    }
    int value = 0;
    for (int offset = 0; offset < 4; offset++) {
      int digit = Character.digit(text.charAt(index++), 16);
      if (digit < 0) {
        throw error();
      }
      value = (value << 4) | digit;
    }
    return (char) value;
  }

  /**
   * Consumes one exact JSON literal and returns its corresponding value.
   *
   * @param literal exact JSON literal spelling
   * @param value encoded or parsed input value
   * @return the supplied literal value
   */
  private Object parseLiteral(String literal, Object value) {
    if (!text.startsWith(literal, index)) {
      throw error();
    }
    index += literal.length();
    return value;
  }

  /**
   * Parses a supported signed integral JSON number.
   *
   * @return parsed signed 64-bit number
   */
  private Long parseNumber() {
    int start = index;
    if (consume('-') && index >= text.length()) {
      throw error();
    }
    if (consume('0')) {
      if (index < text.length() && isDigit(text.charAt(index))) {
        throw error();
      }
    } else {
      parseDigits();
    }
    if (index < text.length()
        && (text.charAt(index) == '.' || text.charAt(index) == 'e' || text.charAt(index) == 'E')) {
      throw error();
    }
    try {
      return Long.parseLong(text.substring(start, index));
    } catch (NumberFormatException _) {
      throw error();
    }
  }

  /** Consumes a nonempty decimal digit sequence. */
  private void parseDigits() {
    if (index >= text.length() || !isDigit(text.charAt(index))) {
      throw error();
    }
    while (index < text.length() && isDigit(text.charAt(index))) {
      index++;
    }
  }

  /** Advances past permitted JSON whitespace. */
  private void skipWhitespace() {
    while (index < text.length()) {
      char ch = text.charAt(index);
      if (ch == ' ' || ch == '\n' || ch == '\r' || ch == '\t') {
        index++;
      } else {
        return;
      }
    }
  }

  /**
   * Consumes the required next delimiter or rejects the input.
   *
   * @param expected required authoritative value or delimiter
   */
  private void expect(char expected) {
    if (!consume(expected)) {
      throw error();
    }
  }

  /**
   * Consumes the next character only when it matches.
   *
   * @param expected required authoritative value or delimiter
   * @return whether the character matched and was consumed
   */
  private boolean consume(char expected) {
    if (index < text.length() && text.charAt(index) == expected) {
      index++;
      return true;
    }
    return false;
  }

  /**
   * Recognizes an ASCII decimal digit.
   *
   * @param ch candidate character
   * @return whether the character is an ASCII digit
   */
  private static boolean isDigit(char ch) {
    return ch >= '0' && ch <= '9';
  }

  /**
   * Creates a bounded local JSON failure.
   *
   * @return bounded parsing exception
   */
  private static IllegalArgumentException error() {
    return new IllegalArgumentException("Invalid private API response.");
  }
}
