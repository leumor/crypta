package network.crypta.runtime.spi;

import java.util.Set;

/**
 * Immutable detached completion state for one exact persistent insert identifier.
 *
 * <p>The producing queue port is responsible for looking up the correct identifier and reporting
 * actual insertion state. This value checks only the allowed state vocabulary and a bounded,
 * printable CHK-prefixed reference; it does not parse or fetch the key, authenticate mail, or prove
 * delivery. The reference accessor is intended for authorized callers; {@link #toString()} redacts
 * it for diagnostics.
 *
 * @param state non-null missing, pending, inserted or failed; inserted never means delivered or
 *     read
 * @param reference successful CHK read reference, otherwise null; at most 2,048 printable ASCII
 *     characters without spaces
 */
public record QueueInsertStatus(String state, String reference) {
  /**
   * Validates bounded terminal state and prevents non-CHK/private URI disclosure.
   *
   * @param state fixed persistent-insert state
   * @param reference printable CHK reference only when insertion succeeded
   * @throws IllegalArgumentException if state and reference are inconsistent or out of bounds
   * @throws NullPointerException if state is null
   */
  public QueueInsertStatus {
    if (!Set.of("missing", "pending", "inserted", "failed").contains(state)) {
      throw new IllegalArgumentException("Invalid insert state.");
    }
    if ("inserted".equals(state)) {
      if (reference == null
          || reference.length() > 2048
          || !reference.startsWith("CHK@")
          || reference.chars().anyMatch(c -> c <= 32 || c >= 127)) {
        throw new IllegalArgumentException("Invalid insert reference.");
      }
    } else if (reference != null) {
      throw new IllegalArgumentException("Unexpected insert reference.");
    }
  }

  /** Returns a non-null diagnostic string with the reference redacted. */
  @SuppressWarnings(
      "NullableProblems") // This JDK-only module cannot import nullability annotations.
  @Override
  public String toString() {
    return "QueueInsertStatus[state=" + state + ", reference=<redacted>]";
  }
}
