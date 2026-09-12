package network.crypta.platform.api.networkbudget;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

/**
 * Durable storage contract for safe app-network budget counters.
 *
 * <p>The budget service uses this interface for fixed-window rate state only. Implementations must
 * persist normalized app ids or reserved scopes, operation labels, window timestamps, counts,
 * decision labels, and retry times. They must not persist request bodies, raw content keys, queue
 * output, app-data values, tokens, private insert material, raw Trust Graph statements, signatures,
 * or absolute local paths.
 *
 * <p>Direct reads are part of enforcement and should fail closed when a specific existing counter
 * is unreadable or malformed. Listing is primarily diagnostic and may skip bad records when that
 * lets safe records remain visible without exposing filesystem details.
 */
public interface AppNetworkBudgetStore {
  /**
   * Reads one usage record if present.
   *
   * <p>The distinction between an absent record and an unreadable record matters: absent counters
   * start a new fixed window, while unreadable or malformed existing counters should make the
   * caller fail closed. Implementations should therefore return empty only when the specific key
   * has no persisted state.
   *
   * @param appId normalized app id or reserved internal scope id to read
   * @param operation budget operation key associated with the stored counter
   * @return stored usage record, or empty when no record exists for the key
   * @throws IOException when an existing counter cannot be read safely
   */
  Optional<AppNetworkBudgetUsage> read(String appId, AppNetworkBudgetOperation operation)
      throws IOException;

  /**
   * Writes one usage record.
   *
   * <p>Writes replace the record for the normalized app or internal scope and operation. The usage
   * object already contains only safe metadata; implementations should keep filenames and container
   * paths derived from normalized scope and operation tokens, not from request text.
   *
   * @param usage safe usage metadata to persist for one budget key
   * @throws IOException when the store cannot durably write the record
   */
  void write(AppNetworkBudgetUsage usage) throws IOException;

  /**
   * Lists all readable usage records.
   *
   * <p>The returned list is used for snapshots and release evidence, not for enforcement of a
   * single operation. Implementations should return records in deterministic order when possible
   * and avoid leaking unreadable file names, raw file contents, or absolute root paths through
   * exceptions.
   *
   * @return safe usage metadata in deterministic order when supported
   * @throws IOException when the store root cannot be listed safely
   */
  List<AppNetworkBudgetUsage> listAll() throws IOException;

  /**
   * Lists a bounded, complete set for evidence without silently dropping unreadable records.
   *
   * <p>Legacy stores may leave this unsupported; the default fails closed. This does not change the
   * tolerant historical {@link #listAll()} contract.
   *
   * @param maximumEntries maximum inspected entries, not only successful records
   * @return complete bounded usage, including an empty list only for a known empty store
   * @throws IOException when unsupported, truncated, malformed or unreadable
   */
  default List<AppNetworkBudgetUsage> observe(int maximumEntries) throws IOException {
    throw new IOException("Budget observation unavailable");
  }
}
