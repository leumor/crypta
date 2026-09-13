package network.crypta.platform.api.networkbudget;

import java.io.IOException;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Process-local app-network budget store for deterministic tests and reduced embeddings.
 *
 * <p>This implementation keeps safe usage records in memory only. It follows the same normalized
 * key rules as the file-backed store, but it does not survive process restart and does not model
 * filesystem failures. Tests use it to exercise budget decisions with controlled clocks, while
 * reduced embeddings can use it when durable app-platform data is intentionally unavailable.
 */
public final class InMemoryAppNetworkBudgetStore implements AppNetworkBudgetStore {
  private final Map<String, AppNetworkBudgetUsage> records = new LinkedHashMap<>();

  /**
   * Creates an empty in-memory store.
   *
   * <p>The store starts without any usage records. Reads return empty until callers write safe
   * budget metadata through the shared store contract.
   */
  public InMemoryAppNetworkBudgetStore() {
    // State is initialized by the records field so tests get a clean store per instance.
  }

  @Override
  public synchronized Optional<AppNetworkBudgetUsage> read(
      String appId, AppNetworkBudgetOperation operation) {
    return Optional.ofNullable(records.get(key(appId, operation)));
  }

  @Override
  public synchronized void write(AppNetworkBudgetUsage usage) {
    records.put(key(usage.appId(), usage.operation()), usage);
  }

  @Override
  public synchronized List<AppNetworkBudgetUsage> listAll() throws IOException {
    return records.values().stream()
        .sorted(
            Comparator.comparing(AppNetworkBudgetUsage::appId)
                .thenComparing(usage -> usage.operation().jsonValue()))
        .toList();
  }

  @Override
  public synchronized List<AppNetworkBudgetUsage> observe(int maximumEntries) throws IOException {
    if (maximumEntries <= 0 || records.size() > maximumEntries) {
      throw new IOException("Budget observation unavailable");
    }
    return listAll();
  }

  private static String key(String appId, AppNetworkBudgetOperation operation) {
    return AppNetworkBudgetScope.normalize(appId) + '\n' + operation.jsonValue();
  }
}
