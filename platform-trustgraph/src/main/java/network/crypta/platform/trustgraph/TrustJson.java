package network.crypta.platform.trustgraph;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Small JSON parser/writer for the bounded trust graph document shapes.
 *
 * <p>The trust statement format is deliberately shallow and deterministic, so the preview module
 * uses a local JSON implementation instead of adding a broad dependency. The writer preserves map
 * iteration order and emits compact JSON for canonical payloads. The parser accepts only the JSON
 * value types needed by the model, rejects duplicate object members, rejects fractional numbers,
 * and bounds nesting depth.
 *
 * <p>This class is package-private because it is not a general-purpose JSON utility. Callers should
 * use {@link TrustStatementParser} and {@link TrustStatementCanonicalizer} rather than depending on
 * these low-level helpers directly.
 */
final class TrustJson {
  private static final int MAX_NESTING_DEPTH = 64;

  private TrustJson() {}

  /**
   * Parses one JSON value from text.
   *
   * @param text complete JSON text to parse
   * @return parsed value using maps, lists, strings, booleans, nulls, and integral numbers
   * @throws TrustGraphException when JSON is malformed or uses unsupported forms
   */
  static Object parse(String text) {
    return new Parser(text).parse();
  }

  /**
   * Writes one parsed value as compact deterministic JSON.
   *
   * @param value value tree made from supported JSON model types
   * @return compact JSON text with object order matching the input map iteration order
   * @throws TrustGraphException when a value type is not supported by the trust model writer
   */
  static String write(Object value) {
    StringBuilder out = new StringBuilder();
    appendValue(value, out);
    return out.toString();
  }

  private static void appendValue(Object value, StringBuilder out) {
    switch (value) {
      case null -> out.append("null");
      case String text -> appendString(text, out);
      case Boolean bool -> out.append(bool);
      case Integer integer -> out.append(integer);
      case Long longValue -> out.append(longValue);
      case Map<?, ?> map -> appendObject(map, out);
      case Iterable<?> iterable -> appendArray(iterable, out);
      default ->
          throw new TrustGraphException(
              "invalid_trust_json",
              "Unsupported JSON value type: " + value.getClass().getSimpleName() + ".");
    }
  }

  private static void appendObject(Map<?, ?> map, StringBuilder out) {
    out.append('{');
    boolean first = true;
    for (Map.Entry<?, ?> entry : map.entrySet()) {
      if (!(entry.getKey() instanceof String key)) {
        throw new TrustGraphException("invalid_trust_json", "JSON object keys must be strings.");
      }
      if (!first) {
        out.append(',');
      }
      appendString(key, out);
      out.append(':');
      appendValue(entry.getValue(), out);
      first = false;
    }
    out.append('}');
  }

  private static void appendArray(Iterable<?> values, StringBuilder out) {
    out.append('[');
    boolean first = true;
    for (Object value : values) {
      if (!first) {
        out.append(',');
      }
      appendValue(value, out);
      first = false;
    }
    out.append(']');
  }

  private static void appendString(String value, StringBuilder out) {
    out.append('"');
    for (int i = 0; i < value.length(); i++) {
      char ch = value.charAt(i);
      switch (ch) {
        case '"' -> out.append("\\\"");
        case '\\' -> out.append("\\\\");
        case '\b' -> out.append("\\b");
        case '\f' -> out.append("\\f");
        case '\n' -> out.append("\\n");
        case '\r' -> out.append("\\r");
        case '\t' -> out.append("\\t");
        default -> {
          if (ch < 0x20) {
            out.append(String.format("\\u%04x", (int) ch));
          } else {
            out.append(ch);
          }
        }
      }
    }
    out.append('"');
  }

  private static final class Parser {
    private final String text;
    private int index;

    private Parser(String text) {
      this.text = java.util.Objects.requireNonNull(text, "text");
    }

    private Object parse() {
      Object value = parseValue(0);
      skipWhitespace();
      if (index != text.length()) {
        throw error();
      }
      return value;
    }

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

    private Map<String, Object> parseObject(int depth) {
      requireDepth(depth);
      expect('{');
      LinkedHashMap<String, Object> map = new LinkedHashMap<>();
      skipWhitespace();
      if (consume('}')) {
        return map;
      }
      do {
        skipWhitespace();
        String key = parseString();
        skipWhitespace();
        expect(':');
        if (map.containsKey(key)) {
          throw duplicateKey();
        }
        map.put(key, parseValue(depth + 1));
        skipWhitespace();
      } while (consume(','));
      expect('}');
      return map;
    }

    private List<Object> parseArray(int depth) {
      requireDepth(depth);
      expect('[');
      ArrayList<Object> values = new ArrayList<>();
      skipWhitespace();
      if (consume(']')) {
        return values;
      }
      do {
        values.add(parseValue(depth + 1));
        skipWhitespace();
      } while (consume(','));
      expect(']');
      return values;
    }

    private void requireDepth(int depth) {
      if (depth >= MAX_NESTING_DEPTH) {
        throw error();
      }
    }

    private String parseString() {
      expect('"');
      StringBuilder value = new StringBuilder();
      while (index < text.length()) {
        char ch = text.charAt(index++);
        if (ch == '"') {
          TrustStatementValidator.requireWellFormedUnicode(value.toString());
          return value.toString();
        }
        if (ch == '\\') {
          value.append(parseEscape());
        } else {
          if (ch < 0x20) {
            throw error();
          }
          value.append(ch);
        }
      }
      throw error();
    }

    private char parseEscape() {
      if (index >= text.length()) {
        throw error();
      }
      char escaped = text.charAt(index++);
      return switch (escaped) {
        case '"' -> '"';
        case '\\' -> '\\';
        case '/' -> '/';
        case 'b' -> '\b';
        case 'f' -> '\f';
        case 'n' -> '\n';
        case 'r' -> '\r';
        case 't' -> '\t';
        case 'u' -> parseUnicodeEscape();
        default -> throw error();
      };
    }

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
        value = (value << 4) + digit;
      }
      return (char) value;
    }

    private Object parseLiteral(String literal, Object value) {
      if (!text.startsWith(literal, index)) {
        throw error();
      }
      index += literal.length();
      return value;
    }

    private Long parseNumber() {
      int start = index;
      consumeOptionalMinus();
      parseIntegerPart();
      if (index < text.length()
          && (text.charAt(index) == '.' || isExponentMarker(text.charAt(index)))) {
        throw error();
      }
      try {
        return Long.parseLong(text.substring(start, index));
      } catch (NumberFormatException _) {
        throw error();
      }
    }

    private void consumeOptionalMinus() {
      if (consume('-') && index >= text.length()) {
        throw error();
      }
    }

    private void parseIntegerPart() {
      if (consume('0')) {
        if (index < text.length() && isAsciiDigit(text.charAt(index))) {
          throw error();
        }
        return;
      }
      requireDigit();
      while (index < text.length() && isAsciiDigit(text.charAt(index))) {
        index++;
      }
    }

    private void requireDigit() {
      if (index >= text.length() || !isAsciiDigit(text.charAt(index))) {
        throw error();
      }
      index++;
    }

    private static boolean isAsciiDigit(char ch) {
      return ch >= '0' && ch <= '9';
    }

    private static boolean isExponentMarker(char ch) {
      return ch == 'e' || ch == 'E';
    }

    private void skipWhitespace() {
      while (index < text.length()) {
        char ch = text.charAt(index);
        if (ch != ' ' && ch != '\n' && ch != '\r' && ch != '\t') {
          return;
        }
        index++;
      }
    }

    private boolean consume(char expected) {
      if (index < text.length() && text.charAt(index) == expected) {
        index++;
        return true;
      }
      return false;
    }

    private void expect(char expected) {
      if (!consume(expected)) {
        throw error();
      }
    }

    private TrustGraphException error() {
      return new TrustGraphException(
          "invalid_trust_json", "Invalid trust JSON at offset " + index + ".");
    }

    private TrustGraphException duplicateKey() {
      return new TrustGraphException(
          "invalid_trust_json", "Duplicate JSON object members are not allowed.");
    }
  }
}
