package network.crypta.runtime.core;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import network.crypta.runtime.spi.ContentFetchObservation;

/**
 * Bounded numeric lifecycle bookkeeping for one content-fetch port instance.
 *
 * <p>Construction creates an empty tracker and a fresh owner epoch. Entry, exit and snapshot reads
 * synchronize on the tracker. Each entry must be paired with exactly one exit, including failures
 * and cancellations; the fetch port owns that pairing. Tokens are internal correlation values, not
 * request identities. No content, URI or caller inventory is retained.
 *
 * <p>Only the first 1,024 simultaneously active calls retain start times. Exceeding that capacity
 * or saturating a counter permanently marks this epoch truncated, so its age and lifecycle totals
 * cannot prove complete coverage. Snapshots never clear counters or truncation state.
 */
final class ContentFetchActivity {
  /** Maximum simultaneous start-time entries retained for age measurement. */
  private static final int CAPACITY = 1024;

  /** Opaque identity of this tracker lifetime. */
  private final String epoch = UUID.randomUUID().toString();

  /** Internal entry tokens mapped to monotonic start times in nanoseconds. */
  private final Map<Long, Long> active = new HashMap<>();

  /** Saturating count of entry and exit transitions. */
  private long sequence;

  /** Saturating count of calls entered; also supplies internal tokens. */
  private long started;

  /** Saturating count of calls that exited successfully. */
  private long succeeded;

  /** Saturating count of calls that exited unsuccessfully. */
  private long failed;

  /** Calls entered but not yet paired with an exit. */
  private long inFlight;

  /** Sticky indication of lost start-time coverage or counter saturation. */
  private boolean truncated;

  /**
   * Accounts for a call before the port starts work, retaining its start time when capacity
   * permits.
   *
   * @return internal token to pass to exactly one matching {@link #exit(long, boolean)} call
   */
  synchronized long enter() {
    started = increment(started);
    sequence = increment(sequence);
    inFlight = increment(inFlight);
    long token = started;
    if (active.size() < CAPACITY) active.put(token, System.nanoTime());
    else truncated = true;
    return token;
  }

  /**
   * Completes a previously entered call without resetting any cumulative counter.
   *
   * @param token token returned by this tracker's matching entry; must not be reused
   * @param success whether the port completed normally rather than failing or being cancelled
   */
  synchronized void exit(long token, boolean success) {
    active.remove(token);
    inFlight--;
    if (success) succeeded = increment(succeeded);
    else failed = increment(failed);
    sequence = increment(sequence);
  }

  /**
   * Copies the current lifecycle counters and oldest retained active-call age.
   *
   * @return detached sample with wall time in epoch milliseconds and monotonic active age rounded
   *     down to milliseconds; no tracked active call gives age zero
   */
  synchronized ContentFetchObservation snapshot() {
    long now = System.nanoTime();
    long oldest = 0;
    for (long start : active.values()) oldest = Math.max(oldest, Math.max(0, now - start));
    return new ContentFetchObservation(
        true,
        epoch,
        sequence,
        System.currentTimeMillis(),
        inFlight,
        oldest / 1_000_000,
        started,
        succeeded,
        failed,
        truncated);
  }

  /**
   * Increments a lifecycle counter without allowing wraparound.
   *
   * @param value current nonnegative counter
   * @return incremented value, or the maximum long value with truncation marked
   */
  private long increment(long value) {
    if (value == Long.MAX_VALUE) {
      truncated = true;
      return value;
    }
    return value + 1;
  }
}
