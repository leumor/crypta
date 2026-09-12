package network.crypta.runtime.spi;

/**
 * Detached aggregate of bounded content-fetch calls, never native selector keys or queue entries.
 *
 * <p>Active age includes waiting and materialization in the port. It is not queue waiting age.
 * Counters belong to one port epoch; unavailable or truncated observations cannot prove coverage.
 *
 * @param known whether the owner supports this observation
 * @param epoch opaque owner lifetime identifier
 * @param sequence owner transition sequence
 * @param sampledAtEpochMillis collection wall time in milliseconds
 * @param inFlightOperations currently executing port calls
 * @param oldestActiveAgeMillis age of the oldest tracked executing call
 * @param startedOperations cumulative calls entered
 * @param successfulOperations cumulative calls returning successfully
 * @param failedOperations cumulative calls exiting exceptionally
 * @param truncated whether tracking capacity or counter range was exceeded
 */
public record ContentFetchObservation(
    boolean known,
    String epoch,
    long sequence,
    long sampledAtEpochMillis,
    long inFlightOperations,
    long oldestActiveAgeMillis,
    long startedOperations,
    long successfulOperations,
    long failedOperations,
    boolean truncated) {
  /**
   * Validates numeric domains; unsupported observations still carry an explicit known flag.
   *
   * <p>Known, untruncated samples must satisfy entered = successful + failed + in-flight. A
   * truncated sample retains nonnegative counters without asserting that lifecycle identity.
   *
   * @throws IllegalArgumentException if an epoch is null, a known epoch is blank, a numeric value
   *     is negative, or a known untruncated sample has inconsistent lifecycle totals
   */
  public ContentFetchObservation {
    if (epoch == null
        || (known && epoch.isBlank())
        || sequence < 0
        || sampledAtEpochMillis < 0
        || inFlightOperations < 0
        || oldestActiveAgeMillis < 0
        || startedOperations < 0
        || successfulOperations < 0
        || failedOperations < 0) {
      throw new IllegalArgumentException("Invalid content fetch observation");
    }
    if (known
        && !truncated
        && (successfulOperations > startedOperations
            || failedOperations > startedOperations - successfulOperations
            || inFlightOperations != startedOperations - successfulOperations - failedOperations)) {
      throw new IllegalArgumentException("Inconsistent content fetch observation");
    }
  }

  /**
   * Returns explicit unsupported metadata without implying a zero queue.
   *
   * @return an unknown sample stamped with current wall time; zero counters are placeholders
   */
  public static ContentFetchObservation unavailable() {
    return new ContentFetchObservation(
        false, "", 0, System.currentTimeMillis(), 0, 0, 0, 0, 0, false);
  }
}
