package network.crypta.platform.api.networkbudget;

import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.DirectoryIteratorException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.Properties;
import java.util.stream.Stream;

/**
 * File-backed store for app-network budget counters.
 *
 * <p>The layout is {@code <root>/<appId>/<operation>.properties}. App ids and operation labels are
 * path-safe. Request URIs, source labels, request bodies, fetched content, queue HTML, tokens,
 * private keys, signatures, app-data values, and local paths are never used as file names or stored
 * as property values.
 *
 * <p>Each write creates a temporary file in the target directory and then replaces the destination
 * file, using an atomic move when the filesystem supports it. Direct reads fail closed when the
 * specific counter file exists but cannot be parsed or does not match the requested key. Listing is
 * intentionally more tolerant: it skips malformed directories or records so operator diagnostics
 * can still report the remaining safe counters.
 *
 * <p>The store is synchronized because callers may share one instance across Platform API route
 * families. It does not lock across processes. Production runtime wiring uses one local node
 * process and treats the files as durable recovery metadata, not as a multi-process coordination
 * protocol.
 */
public final class FileAppNetworkBudgetStore implements AppNetworkBudgetStore {
  private static final String FILE_SUFFIX = ".properties";
  private static final String KEY_VERSION = "version";
  private static final String KEY_APP_ID = "appId";
  private static final String KEY_OPERATION = "operation";
  private static final String KEY_WINDOW_START = "windowStart";
  private static final String KEY_WINDOW_SECONDS = "windowSeconds";
  private static final String KEY_COUNT = "count";
  private static final String KEY_LAST_DECISION_AT = "lastDecisionAt";
  private static final String KEY_LAST_DECISION = "lastDecision";
  private static final String KEY_NEXT_AVAILABLE_AT = "nextAvailableAt";

  private final Path rootDirectory;

  /**
   * Creates a file-backed store rooted at the supplied directory.
   *
   * <p>The path is normalized once during construction. Callers should pass the dedicated
   * app-platform network-budget directory, typically under {@code data/apps/network-budget}. The
   * store derives all child paths from normalized budget scopes and operation labels.
   *
   * @param rootDirectory root directory for durable budget metadata
   */
  public FileAppNetworkBudgetStore(Path rootDirectory) {
    this.rootDirectory =
        java.util.Objects.requireNonNull(rootDirectory, "rootDirectory")
            .toAbsolutePath()
            .normalize();
  }

  @Override
  public synchronized Optional<AppNetworkBudgetUsage> read(
      String appId, AppNetworkBudgetOperation operation) throws IOException {
    Path file = usageFile(appId, operation);
    if (Files.notExists(file)) {
      return Optional.empty();
    }
    if (!Files.isRegularFile(file)) {
      throw counterUnavailable();
    }
    return Optional.of(readUsage(file, AppNetworkBudgetScope.normalize(appId), operation));
  }

  @Override
  public synchronized void write(AppNetworkBudgetUsage usage) throws IOException {
    Path file = usageFile(usage.appId(), usage.operation());
    Path parent = file.getParent();
    Files.createDirectories(parent);
    Properties properties = new Properties();
    properties.setProperty(KEY_VERSION, "1");
    properties.setProperty(KEY_APP_ID, usage.appId());
    properties.setProperty(KEY_OPERATION, usage.operation().jsonValue());
    properties.setProperty(KEY_WINDOW_START, usage.windowStart().toString());
    properties.setProperty(KEY_WINDOW_SECONDS, Long.toString(usage.window().toSeconds()));
    properties.setProperty(KEY_COUNT, Integer.toString(usage.count()));
    setInstant(properties, KEY_LAST_DECISION_AT, usage.lastDecisionAt());
    setLastDecision(properties, usage.lastDecision());
    setInstant(properties, KEY_NEXT_AVAILABLE_AT, usage.nextAvailableAt());
    Path tempFile = Files.createTempFile(parent, ".app-network-budget-", ".tmp");
    boolean moved = false;
    try {
      try (Writer writer = Files.newBufferedWriter(tempFile, StandardCharsets.UTF_8)) {
        properties.store(writer, "Cryptad app network budget metadata");
      }
      moveReplacing(tempFile, file);
      moved = true;
    } finally {
      if (!moved) {
        Files.deleteIfExists(tempFile);
      }
    }
  }

  @Override
  public synchronized List<AppNetworkBudgetUsage> listAll() throws IOException {
    if (!Files.isDirectory(rootDirectory)) {
      return List.of();
    }
    try (Stream<Path> appDirectories = Files.list(rootDirectory)) {
      return appDirectories
          .filter(Files::isDirectory)
          .sorted(Comparator.comparing(Path::toString))
          .flatMap(this::listAppDirectorySafely)
          .sorted(
              Comparator.comparing(AppNetworkBudgetUsage::appId)
                  .thenComparing(usage -> usage.operation().jsonValue()))
          .toList();
    }
  }

  @Override
  public synchronized List<AppNetworkBudgetUsage> observe(int maximumEntries) throws IOException {
    if (maximumEntries <= 0) {
      throw counterUnavailable();
    }
    if (Files.notExists(rootDirectory, LinkOption.NOFOLLOW_LINKS)) {
      return List.of();
    }
    if (!Files.isDirectory(rootDirectory, LinkOption.NOFOLLOW_LINKS)) {
      throw counterUnavailable();
    }
    ArrayList<AppNetworkBudgetUsage> result = new ArrayList<>();
    InspectionBudget budget = new InspectionBudget(maximumEntries);
    try (var directories = Files.newDirectoryStream(rootDirectory)) {
      for (Path directory : directories) {
        budget.visit();
        if (!Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS)) {
          throw counterUnavailable();
        }
        observeDirectory(directory, budget, result);
      }
    } catch (DirectoryIteratorException | IllegalArgumentException _) {
      throw counterUnavailable();
    }
    result.sort(
        Comparator.comparing(AppNetworkBudgetUsage::appId)
            .thenComparing(usage -> usage.operation().jsonValue()));
    return List.copyOf(result);
  }

  private void observeDirectory(
      Path directory, InspectionBudget budget, List<AppNetworkBudgetUsage> result)
      throws IOException {
    Path directoryName = directory.getFileName();
    if (directoryName == null) {
      throw counterUnavailable();
    }
    String appId = AppNetworkBudgetScope.normalize(directoryName.toString());
    try (var files = Files.newDirectoryStream(directory)) {
      for (Path file : files) {
        budget.visit();
        if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) {
          throw counterUnavailable();
        }
        Path fileName = file.getFileName();
        if (fileName == null) {
          throw counterUnavailable();
        }
        String filename = fileName.toString();
        if (filename.startsWith(".app-network-budget-") && filename.endsWith(".tmp")) {
          continue;
        }
        if (!filename.endsWith(FILE_SUFFIX)) {
          throw counterUnavailable();
        }
        AppNetworkBudgetOperation operation =
            AppNetworkBudgetOperation.fromJsonValue(
                filename.substring(0, filename.length() - FILE_SUFFIX.length()));
        result.add(readUsage(file, appId, operation, true));
      }
    }
  }

  private static final class InspectionBudget {
    private int remaining;

    private InspectionBudget(int remaining) {
      this.remaining = remaining;
    }

    private void visit() throws IOException {
      if (remaining-- <= 0) {
        throw counterUnavailable();
      }
    }
  }

  private Stream<AppNetworkBudgetUsage> listAppDirectorySafely(Path appDirectory) {
    String appId = appDirectory.getFileName().toString();
    try {
      AppNetworkBudgetScope.normalize(appId);
    } catch (RuntimeException _) {
      return Stream.empty();
    }
    try (Stream<Path> files = Files.list(appDirectory)) {
      return files
          .filter(Files::isRegularFile)
          .filter(path -> path.getFileName().toString().endsWith(FILE_SUFFIX))
          .sorted(Comparator.comparing(Path::toString))
          .map(path -> readUsageSafely(path, appId))
          .flatMap(Optional::stream)
          .toList()
          .stream();
    } catch (IOException _) {
      return Stream.empty();
    }
  }

  private Optional<AppNetworkBudgetUsage> readUsageSafely(Path file, String expectedAppId) {
    try {
      return Optional.of(readUsage(file, expectedAppId));
    } catch (IOException _) {
      return Optional.empty();
    }
  }

  private static Reader usageReader(Path file, boolean bounded) throws IOException {
    if (!bounded) {
      return Files.newBufferedReader(file, StandardCharsets.UTF_8);
    }
    byte[] bytes;
    try (var input = Files.newInputStream(file)) {
      bytes = input.readNBytes(8193);
    }
    if (bytes.length > 8192) {
      throw counterUnavailable();
    }
    return new StringReader(new String(bytes, StandardCharsets.UTF_8));
  }

  private AppNetworkBudgetUsage readUsage(Path file, String expectedAppId) throws IOException {
    return readUsage(file, expectedAppId, null);
  }

  private AppNetworkBudgetUsage readUsage(
      Path file, String expectedAppId, AppNetworkBudgetOperation expectedOperation)
      throws IOException {
    return readUsage(file, expectedAppId, expectedOperation, false);
  }

  private AppNetworkBudgetUsage readUsage(
      Path file, String expectedAppId, AppNetworkBudgetOperation expectedOperation, boolean bounded)
      throws IOException {
    if (!Files.isRegularFile(file)) {
      throw counterUnavailable();
    }
    Properties properties = new Properties();
    try (Reader reader = usageReader(file, bounded)) {
      properties.load(reader);
      if (!"1".equals(properties.getProperty(KEY_VERSION))) {
        throw counterUnavailable();
      }
      AppNetworkBudgetOperation operation =
          AppNetworkBudgetOperation.fromJsonValue(properties.getProperty(KEY_OPERATION));
      AppNetworkBudgetUsage usage =
          new AppNetworkBudgetUsage(
              properties.getProperty(KEY_APP_ID),
              operation,
              Instant.parse(properties.getProperty(KEY_WINDOW_START)),
              Duration.ofSeconds(Long.parseLong(properties.getProperty(KEY_WINDOW_SECONDS))),
              Integer.parseInt(properties.getProperty(KEY_COUNT)),
              instant(properties.getProperty(KEY_LAST_DECISION_AT)),
              properties.getProperty(KEY_LAST_DECISION),
              instant(properties.getProperty(KEY_NEXT_AVAILABLE_AT)));
      if (!expectedAppId.equals(usage.appId())) {
        throw counterUnavailable();
      }
      if (expectedOperation != null && expectedOperation != usage.operation()) {
        throw counterUnavailable();
      }
      return usage;
    } catch (RuntimeException | IOException exception) {
      throw counterUnavailable(exception);
    }
  }

  private Path usageFile(String appId, AppNetworkBudgetOperation operation) {
    String normalizedAppId = AppNetworkBudgetScope.normalize(appId);
    return rootDirectory.resolve(normalizedAppId).resolve(operation.jsonValue() + FILE_SUFFIX);
  }

  private static Instant instant(String value) {
    return value == null || value.isBlank() ? null : Instant.parse(value);
  }

  private static void setInstant(Properties properties, String key, Instant value) {
    if (value != null) {
      properties.setProperty(key, value.toString());
    }
  }

  private static void setLastDecision(Properties properties, String value) {
    if (value != null && !value.isBlank()) {
      properties.setProperty(KEY_LAST_DECISION, value);
    }
  }

  private static void moveReplacing(Path source, Path target) throws IOException {
    try {
      Files.move(
          source, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
    } catch (AtomicMoveNotSupportedException _) {
      Files.move(source, target, StandardCopyOption.REPLACE_EXISTING);
    }
  }

  private static IOException counterUnavailable() {
    return new IOException("App network budget metadata is unavailable.");
  }

  private static IOException counterUnavailable(Exception cause) {
    return new IOException("App network budget metadata is unavailable.", cause);
  }
}
