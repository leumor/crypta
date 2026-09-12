package network.crypta.platform.devtools;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Reads the restricted JSON grammar used by the private federation selection handoff.
 *
 * <p>Objects preserve insertion order and reject duplicate keys. Objects and arrays contain at most
 * 64 members, strings contain at most 1,024 non-surrogate characters, and values with more than
 * eight enclosing containers are rejected. Empty containers require no nested value read. Numbers
 * are nonnegative decimal {@link Long} values without leading zeroes. Strings accept escaped
 * quotes, slashes, backslashes, and four-digit Unicode escapes, but reject control characters and
 * surrogate code units, including escaped ones.
 *
 * <p>This parser checks syntax and structural bounds only; callers bound the input size and
 * validate selection fields and authority separately. Each invocation owns its mutable cursor and
 * performs no I/O.
 */
final class FederationSelectionJson {
  /** Complete caller-supplied text; no copy or input-size check is performed here. */
  private final String input;

  /** Index of the next UTF-16 code unit to read. */
  private int offset;

  /**
   * Creates an invocation-local cursor at the beginning of the input.
   *
   * @param input non-null handoff text, already bounded by the caller
   */
  private FederationSelectionJson(String input) {
    this.input = input;
  }

  /**
   * Reads exactly one value followed only by JSON whitespace.
   *
   * @param input non-null handoff text, already bounded by the caller
   * @return a map, list, string, {@link Long}, {@link Boolean}, or {@code null}
   * @throws IllegalArgumentException if syntax or structural bounds are invalid, including numeric
   *     overflow reported as {@link NumberFormatException}
   * @throws NullPointerException if {@code input} is null
   */
  static Object parse(String input) {
    var parser = new FederationSelectionJson(input);
    Object result = parser.value(0);
    parser.whitespace();
    if (parser.offset != input.length()) throw invalid();
    return result;
  }

  /**
   * Reads a value after optional whitespace at the supplied nesting depth.
   *
   * @param depth number of enclosing containers; the root starts at zero
   * @return the decoded value, possibly {@code null}
   * @throws IllegalArgumentException if no valid bounded value remains or depth exceeds eight
   */
  private Object value(int depth) {
    whitespace();
    if (depth > 8 || offset == input.length()) throw invalid();
    return switch (input.charAt(offset)) {
      case '{' -> object(depth + 1);
      case '[' -> array(depth + 1);
      case '"' -> string();
      case 't' -> literal("true", Boolean.TRUE);
      case 'f' -> literal("false", Boolean.FALSE);
      case 'n' -> literal("null", null);
      default -> integer();
    };
  }

  /**
   * Reads an object from its opening brace, preserving key order and rejecting duplicate keys.
   *
   * @param depth nesting depth to apply to member values
   * @return a mutable map containing at most 64 entries
   * @throws IllegalArgumentException if the object or any member is invalid
   */
  private Map<String, Object> object(int depth) {
    offset++;
    var result = new LinkedHashMap<String, Object>();
    whitespace();
    if (consume('}')) return result;
    do {
      whitespace();
      String key = string();
      whitespace();
      require(':');
      if (result.containsKey(key) || result.size() >= 64) throw invalid();
      result.put(key, value(depth));
      whitespace();
    } while (consume(','));
    require('}');
    return result;
  }

  /**
   * Reads an array from its opening bracket.
   *
   * @param depth nesting depth to apply to elements
   * @return a mutable list containing at most 64 elements
   * @throws IllegalArgumentException if the array or any element is invalid
   */
  private List<Object> array(int depth) {
    offset++;
    var result = new ArrayList<>();
    whitespace();
    if (consume(']')) return result;
    do {
      if (result.size() >= 64) throw invalid();
      result.add(value(depth));
      whitespace();
    } while (consume(','));
    require(']');
    return result;
  }

  /**
   * Reads a quoted string using the handoff's restricted escapes and character bounds.
   *
   * @return the decoded string, excluding its surrounding quotes
   * @throws IllegalArgumentException if quoting, escaping, character validity, or length is invalid
   */
  private String string() {
    require('"');
    var result = new StringBuilder();
    while (offset < input.length()) {
      char character = input.charAt(offset++);
      if (character == '"') return result.toString();
      if (character == '\\') {
        if (offset == input.length()) throw invalid();
        character = input.charAt(offset++);
        character =
            switch (character) {
              case '"', '\\', '/' -> character;
              case 'u' -> unicode();
              default -> throw invalid();
            };
      }
      if (character < 0x20 || Character.isSurrogate(character) || result.length() >= 1024)
        throw invalid();
      result.append(character);
    }
    throw invalid();
  }

  /**
   * Decodes four hexadecimal digits after an already consumed Unicode escape marker.
   *
   * @return the decoded UTF-16 code unit; the string reader checks its admissibility
   * @throws IllegalArgumentException if fewer than four valid digits remain
   */
  private char unicode() {
    if (offset + 4 > input.length()) throw invalid();
    int result = 0;
    for (int count = 0; count < 4; count++) {
      int digit = Character.digit(input.charAt(offset++), 16);
      if (digit < 0) throw invalid();
      result = result * 16 + digit;
    }
    return (char) result;
  }

  /**
   * Consumes a fixed literal; the enclosing reader checks the following delimiter.
   *
   * @param token literal spelling to match at the cursor
   * @param value decoded value to return, possibly {@code null}
   * @return {@code value}
   * @throws IllegalArgumentException if the expected token is absent
   */
  private Object literal(String token, Object value) {
    if (!input.startsWith(token, offset)) throw invalid();
    offset += token.length();
    return value;
  }

  /**
   * Reads an unsigned decimal integer without leading zeroes.
   *
   * @return the decoded nonnegative value
   * @throws IllegalArgumentException if no digits remain or a leading zero precedes further digits
   * @throws NumberFormatException if the digits exceed the {@link Long} range
   */
  private Long integer() {
    int start = offset;
    while (offset < input.length() && input.charAt(offset) >= '0' && input.charAt(offset) <= '9')
      offset++;
    String number = input.substring(start, offset);
    if (number.isEmpty() || number.length() > 1 && number.startsWith("0")) throw invalid();
    return Long.valueOf(number);
  }

  /** Advances past spaces, tabs, carriage returns, and line feeds only. */
  private void whitespace() {
    while (offset < input.length() && " \t\r\n".indexOf(input.charAt(offset)) >= 0) offset++;
  }

  /**
   * Advances by one code unit only if it matches the expected character.
   *
   * @param character character to match
   * @return whether the character was consumed
   */
  private boolean consume(char character) {
    if (offset < input.length() && input.charAt(offset) == character) {
      offset++;
      return true;
    }
    return false;
  }

  /**
   * Requires and consumes a delimiter at the current cursor.
   *
   * @param character required character
   * @throws IllegalArgumentException if the character is absent
   */
  private void require(char character) {
    if (!consume(character)) throw invalid();
  }

  /**
   * Creates the fixed structural-error diagnostic without including private input text.
   *
   * @return a new exception describing invalid selection JSON
   */
  private static IllegalArgumentException invalid() {
    return new IllegalArgumentException("invalid federation selection JSON");
  }
}
