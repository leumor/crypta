package network.crypta.runtime.spi;

import java.lang.management.ManagementFactory;
import java.lang.management.MemoryUsage;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Fixed management reads of the calling JVM, with unavailable values represented by null.
 *
 * <p>Heap used includes uncollected objects. Platform thread count excludes virtual threads. GC
 * times are collector-reported elapsed milliseconds, not exact stop-the-world durations. No command
 * line, ObjectName, path, thread inventory, forced GC, or caller-selected operation is exposed.
 */
public final class JvmResourceObservation {
  private static final String HEAP_MAX_BYTES = "heapMaxBytes";

  private JvmResourceObservation() {}

  /**
   * Captures fixed numeric JVM metrics without changing runtime state.
   *
   * <p>The detached result contains the collector identifier, sample wall time, JVM start wall
   * time, a configuration map, a metrics map and a list of unavailable metric keys. Memory values
   * are bytes; platform threads and cumulative GC collections are counts; GC collection time is
   * cumulative milliseconds. Unsupported memory maxima and failed optional reads remain null. GC
   * totals remain unavailable if any selected collector lacks either count or time statistics, or
   * summing them overflows.
   *
   * <p>Reads are sequential, not an atomic JVM-wide snapshot. The returned maps are mutable copies
   * and contain no live management beans. Runtime identity reads precede optional collectors and
   * their failures propagate rather than producing a usable process epoch.
   *
   * @return bounded metadata and numeric values; unsupported readings are null
   * @throws SecurityException if access to the JVM runtime identity is denied
   */
  public static Map<String, Object> capture() {
    Map<String, Object> result = new LinkedHashMap<>();
    result.put("collector", "fixed-management-beans-v1");
    result.put("sampledAtEpochMillis", System.currentTimeMillis());
    result.put("jvmStartEpochMillis", ManagementFactory.getRuntimeMXBean().getStartTime());
    Map<String, Object> metrics = new LinkedHashMap<>();
    for (String key :
        new String[] {
          "heapUsedBytes",
          "heapCommittedBytes",
          HEAP_MAX_BYTES,
          "nonHeapUsedBytes",
          "nonHeapCommittedBytes",
          "nonHeapMaxBytes",
          "platformThreads",
          "gcCount",
          "gcTimeMillis"
        }) metrics.put(key, null);
    try {
      var bean = ManagementFactory.getMemoryMXBean();
      putMemory(metrics, "heap", bean.getHeapMemoryUsage());
      putMemory(metrics, "nonHeap", bean.getNonHeapMemoryUsage());
    } catch (RuntimeException _) {
      // The initialized null values preserve unsupported or denied reads.
    }
    try {
      metrics.put("platformThreads", ManagementFactory.getThreadMXBean().getThreadCount());
    } catch (RuntimeException _) {
      // Platform thread data is optional in reduced embeddings.
    }
    try {
      long count = 0;
      long millis = 0;
      boolean supported = !ManagementFactory.getGarbageCollectorMXBeans().isEmpty();
      for (var collector : ManagementFactory.getGarbageCollectorMXBeans()) {
        long nextCount = collector.getCollectionCount();
        long nextMillis = collector.getCollectionTime();
        if (nextCount < 0 || nextMillis < 0) supported = false;
        else {
          count = Math.addExact(count, nextCount);
          millis = Math.addExact(millis, nextMillis);
        }
      }
      if (supported) {
        metrics.put("gcCount", count);
        metrics.put("gcTimeMillis", millis);
      }
    } catch (RuntimeException _) {
      // Unsupported collectors and overflow remain unavailable, never zero.
    }
    result.put("configuration", configuration());
    result.put("metrics", metrics);
    result.put(
        "unavailable",
        metrics.entrySet().stream()
            .filter(e -> e.getValue() == null)
            .map(Map.Entry::getKey)
            .toList());
    return result;
  }

  private static Map<String, Object> configuration() {
    Map<String, Object> config = new LinkedHashMap<>();
    for (String key :
        new String[] {
          "javaVendor",
          "javaVersion",
          "vmName",
          "vmVersion",
          "garbageCollectors",
          "availableProcessors",
          "heapInitialBytes",
          HEAP_MAX_BYTES
        }) {
      config.put(key, null);
    }
    try {
      config.put("javaVendor", safeLabel(System.getProperty("java.vendor")));
      config.put("javaVersion", safeLabel(System.getProperty("java.version")));
      config.put("vmName", safeLabel(System.getProperty("java.vm.name")));
      config.put("vmVersion", safeLabel(System.getProperty("java.vm.version")));
      config.put("availableProcessors", Runtime.getRuntime().availableProcessors());
      MemoryUsage heap = ManagementFactory.getMemoryMXBean().getHeapMemoryUsage();
      config.put("heapInitialBytes", available(heap.getInit()));
      config.put(HEAP_MAX_BYTES, available(heap.getMax()));
      var collectors = ManagementFactory.getGarbageCollectorMXBeans();
      if (collectors.size() <= 32 && !collectors.isEmpty()) {
        var names = collectors.stream().map(bean -> safeLabel(bean.getName())).toList();
        if (names.stream().noneMatch(java.util.Objects::isNull)) {
          config.put("garbageCollectors", names);
        }
      }
    } catch (RuntimeException _) {
      // Fixed optional configuration reads remain explicitly unavailable.
    }
    return config;
  }

  private static String safeLabel(String value) {
    return value != null && value.matches("[A-Za-z0-9 ._()+-]{1,160}") ? value : null;
  }

  private static void putMemory(Map<String, Object> metrics, String prefix, MemoryUsage usage) {
    metrics.put(prefix + "UsedBytes", available(usage.getUsed()));
    metrics.put(prefix + "CommittedBytes", available(usage.getCommitted()));
    metrics.put(prefix + "MaxBytes", available(usage.getMax()));
  }

  private static Long available(long value) {
    return value < 0 ? null : value;
  }
}
