package network.crypta.platform.apphost.runtime;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Deque;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import network.crypta.fs.AppEnv;
import network.crypta.platform.appdist.AppBundleVerification;
import network.crypta.platform.appdist.AppRestartPolicy;
import network.crypta.platform.appdist.AppUiMode;
import network.crypta.platform.apphost.AppBundleVerificationException;
import network.crypta.platform.apphost.AppHost;
import network.crypta.platform.apphost.AppHostException;
import network.crypta.platform.apphost.AppHostLayout;
import network.crypta.platform.apphost.AppHostTokenRedactor;
import network.crypta.platform.apphost.AppInstallVerificationPolicy;
import network.crypta.platform.apphost.AppProcessLogSnapshot;
import network.crypta.platform.apphost.AppQuotaEnforcer;
import network.crypta.platform.apphost.AppQuotaPolicy;
import network.crypta.platform.apphost.AppQuotaStatus;
import network.crypta.platform.apphost.AppQuotaWarning;
import network.crypta.platform.apphost.AppRollbackRecord;
import network.crypta.platform.apphost.AppRuntimeState;
import network.crypta.platform.apphost.AppRuntimeStatusSnapshot;
import network.crypta.platform.apphost.AppTokenPrincipal;
import network.crypta.platform.apphost.AppUninstallOptions;
import network.crypta.platform.apphost.FileInstalledAppOriginStore;
import network.crypta.platform.apphost.InstalledAppOrigin;
import network.crypta.platform.apphost.InstalledAppPaths;
import network.crypta.platform.apphost.InstalledAppSnapshot;
import network.crypta.platform.apphost.OwnerOnlyFilePermissions;
import network.crypta.platform.apphost.RunningAppSnapshot;
import network.crypta.platform.apphost.manifest.AppManifest;
import network.crypta.platform.apphost.manifest.AppManifestException;
import network.crypta.platform.apphost.manifest.AppManifestParser;
import network.crypta.platform.apphost.sandbox.AppSandboxException;
import network.crypta.platform.apphost.sandbox.AppSandboxLaunchContext;
import network.crypta.platform.apphost.sandbox.AppSandboxLaunchPlan;
import network.crypta.platform.apphost.sandbox.AppSandboxPolicy;
import network.crypta.platform.apphost.sandbox.AppSandboxProviders;
import network.crypta.platform.apphost.sandbox.AppSandboxStatus;
import org.jetbrains.annotations.NotNull;

/**
 * Default AppHost implementation that launches installed apps out of process.
 *
 * <p>{@code LocalProcessAppHost} is the concrete AppHost v1 runtime that manages validated app
 * bundles on the local filesystem and launches them as child processes of the current daemon. It
 * owns the install-time copy flow, mutable directory preparation, launch environment injection,
 * process-tree tracking, shutdown escalation, and best-effort recovery for wrapper and daemonizing
 * launch patterns across supported platforms.
 *
 * <p>The implementation keeps the runtime state in memory only. It is intended to be the reusable
 * local execution core beneath future shell and transport layers, not a full sandbox or persistent
 * supervisor. It therefore does not attempt to restart recovery across daemon restarts, inspect
 * arbitrary descendant processes, or provide CPU, memory, and network isolation.
 */
public final class LocalProcessAppHost implements AppHost {
  private static final Duration DEFAULT_STOP_TIMEOUT = Duration.ofSeconds(5);
  private static final Duration DEFAULT_RESTART_STORM_WINDOW = Duration.ofMinutes(5);
  private static final int DEFAULT_RESTART_STORM_MAX_IN_WINDOW = 5;
  private static final RestartStormPolicy DEFAULT_RESTART_STORM_POLICY =
      new RestartStormPolicy(DEFAULT_RESTART_STORM_WINDOW, DEFAULT_RESTART_STORM_MAX_IN_WINDOW);
  private static final String TEMP_INSTALL_PREFIX = "app-install-";
  private static final String TEMP_UPDATE_BACKUP_PREFIX = TEMP_INSTALL_PREFIX + "backup-";
  private static final String TEMP_ROLLBACK_BACKUP_PREFIX = "app-rollback-backup-";
  private static final String LOCAL_DIRECTORY_NAME = "local";
  private static final String INSTALLED_APPS_DIR_LABEL = "installedAppsDir";
  private static final String ROLLBACK_APPS_DIR_LABEL = "rollbackAppsDir";
  private static final String MUTATION_TRANSACTIONS_DIR_LABEL = "mutationTransactionsDir";
  private static final String ACTIVE_TRANSACTION_SUFFIX = ".active";
  private static final String COMMITTED_TRANSACTION_PREFIX = ".committed-";
  private static final String PREPARING_TRANSACTION_PREFIX = ".preparing-";
  private static final String TRANSACTION_RECORD_FILE = "transaction.properties";
  private static final String TRANSACTION_CURRENT_BACKUP = "current-bundle";
  private static final String TRANSACTION_ROLLBACK_BACKUP = "rollback-bundle";
  private static final String TRANSACTION_ORIGIN_BACKUP = "origins";
  private static final String ORIGIN_PARAMETER = "origin";
  private static final String AUTHORIZATION_PARAMETER = "authorization";
  private static final String WINDOWS_SYSTEM32_DIRECTORY = "System32";
  private static final String PROC_ROOT = "/proc";
  private static final String APP_NOT_INSTALLED_PREFIX = "app is not installed: ";
  private static final String RESTART_BUNDLE_VERIFICATION_WARNING =
      "Installed app bundle verification failed; automatic restart was blocked.";
  private static final List<String> WINDOWS_ROOT_ENVIRONMENT_NAMES =
      List.of("SystemRoot", "SYSTEMROOT", "WINDIR");
  private static final int MAX_SHEBANG_PROBE_BYTES = 4096;
  private static final int DOS_HEADER_SIZE = 64;
  private static final int PE_POINTER_OFFSET = 0x3C;
  private static final int COFF_HEADER_SIZE = 24;
  private static final int IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002;
  private static final int IMAGE_FILE_DLL = 0x2000;
  static final TimingConfig DEFAULT_TIMING =
      new TimingConfig(
          Duration.ofSeconds(2),
          Duration.ofMillis(500),
          Duration.ofMillis(200),
          Duration.ofMillis(200),
          Duration.ofMillis(100),
          Duration.ofNanos(TimeUnit.MICROSECONDS.toNanos(100)),
          Duration.ofMillis(5),
          Duration.ofMillis(100));
  private static final List<String> BASE_UNIX_PATH_ENTRIES =
      List.of(
          Path.of("/usr", "bin").toString(),
          Path.of("/bin").toString(),
          Path.of("/usr", "sbin").toString(),
          Path.of("/sbin").toString(),
          Path.of("/usr", LOCAL_DIRECTORY_NAME, "bin").toString(),
          Path.of("/usr", LOCAL_DIRECTORY_NAME, "sbin").toString());
  private static final List<String> MAC_UNIX_PATH_ENTRIES =
      List.of(
          Path.of("/opt", "homebrew", "bin").toString(),
          Path.of("/opt", "homebrew", "sbin").toString(),
          Path.of("/opt", LOCAL_DIRECTORY_NAME, "bin").toString(),
          Path.of("/opt", LOCAL_DIRECTORY_NAME, "sbin").toString());
  private static final List<String> LINUX_UNIX_PATH_ENTRIES =
      List.of(
          Path.of("/home", "linuxbrew", ".linuxbrew", "bin").toString(),
          Path.of("/home", "linuxbrew", ".linuxbrew", "sbin").toString());
  private static final int TOKEN_BYTES = 32;

  private final AppHostLayout layout;
  private final Duration stopTimeout;
  private final SecureRandom secureRandom;
  private final AppEnv appEnv;
  private final TimingConfig timing;
  private final ManagedTreeDeleter managedTreeDeleter;
  private final AppInstallVerificationPolicy installVerificationPolicy;
  private final AppSandboxProviders sandboxProviders;
  private final AppQuotaEnforcer quotaEnforcer;
  private final Duration restartStormWindow;
  private final int restartStormMaxInWindow;
  private boolean persistentMutationsRecovered;
  private final Map<String, RunningProcess> runningApps = new ConcurrentHashMap<>();
  private final Map<String, String> launchIds = new ConcurrentHashMap<>();
  private java.net.URI mailPlatformApiEndpoint;

  /**
   * Sets the host-selected Mail API endpoint before launching Mail.
   *
   * @param endpoint HTTP loopback endpoint ending in /api/v1
   */
  public synchronized void setMailPlatformApiEndpoint(java.net.URI endpoint) {
    java.util.Objects.requireNonNull(endpoint, "endpoint");
    if (!"http".equals(endpoint.getScheme())
        || !java.util.Set.of("127.0.0.1", "[::1]", "::1").contains(endpoint.getHost())
        || endpoint.getPort() < 1
        || endpoint.getPort() > 65535
        || !"/api/v1".equals(endpoint.getPath())
        || endpoint.getQuery() != null
        || endpoint.getFragment() != null
        || endpoint.getUserInfo() != null
        || runningApps.containsKey("mail-prototype")) {
      throw new IllegalArgumentException("invalid_mail_endpoint");
    }
    mailPlatformApiEndpoint = endpoint;
  }

  @Override
  public synchronized Optional<AppTokenPrincipal> currentLaunch(String appId) {
    RunningProcess process = liveRunningProcess(appId);
    if (process == null || !launchIds.containsKey(appId)) return Optional.empty();
    RunningAppSnapshot snapshot = process.snapshot();
    return Optional.of(
        new AppTokenPrincipal(
            appId,
            snapshot.manifest().permissions(),
            launchIds.get(appId),
            snapshot.manifest().appVersion()));
  }

  private final Map<String, RuntimeRecord> runtimeRecords = new ConcurrentHashMap<>();
  private final Map<String, Deque<Instant>> automaticRestartAttempts = new ConcurrentHashMap<>();
  private final Set<String> explicitStopRequests = ConcurrentHashMap.newKeySet();
  private final FileInstalledAppOriginStore originStore;
  private AppHost.CatalogOriginRetention catalogOriginRetention =
      new AppHost.CatalogOriginRetention() {
        @Override
        public void retain(List<InstalledAppOrigin> ignored) {
          // Standalone hosts have no catalog store whose revision history needs retention.
        }

        @Override
        public void reconcile(List<InstalledAppOrigin> ignored) {
          // Standalone hosts have no catalog store whose obsolete pins need cleanup.
        }
      };
  private boolean catalogOriginRetentionPending;

  /**
   * Creates a host bound to the supplied layout.
   *
   * <p>This convenience constructor uses the default stop timeout, a fresh secure token generator,
   * and the ambient {@link AppEnv} for platform detection. It also rejects copied staged bundles
   * until an explicit signed-bundle verifier is wired in.
   *
   * @param layout filesystem layout managed by the host
   */
  @SuppressWarnings("unused")
  public LocalProcessAppHost(AppHostLayout layout) {
    this(
        layout,
        DEFAULT_STOP_TIMEOUT,
        new SecureRandom(),
        new AppEnv(),
        DEFAULT_TIMING,
        LocalProcessAppHost::deleteRecursively,
        AppInstallVerificationPolicy.rejectUnsignedByDefault());
  }

  /**
   * Creates a host bound to the supplied layout and copied-bundle verification policy.
   *
   * <p>This overload uses the default stop timeout, a fresh secure token generator, and the ambient
   * {@link AppEnv} for platform detection.
   *
   * @param layout filesystem layout managed by the host
   * @param installVerificationPolicy copied-bundle verification policy applied on install/update
   */
  public LocalProcessAppHost(
      AppHostLayout layout, AppInstallVerificationPolicy installVerificationPolicy) {
    this(
        layout,
        DEFAULT_STOP_TIMEOUT,
        new SecureRandom(),
        new AppEnv(),
        DEFAULT_TIMING,
        LocalProcessAppHost::deleteRecursively,
        installVerificationPolicy);
  }

  /**
   * Creates a host with an explicit stop timeout and token generator.
   *
   * <p>This overload is primarily useful for tests and controlled embeddings that need a
   * non-default shutdown policy or deterministic token generation while still using the ambient
   * platform environment. Production-facing defaults still reject unsigned copied bundles unless
   * the caller supplies an explicit development/test verification policy overload.
   *
   * @param layout filesystem layout managed by the host
   * @param stopTimeout bounded timeout used before force-killing a child process
   * @param secureRandom secure token generator for launch-token generation
   */
  public LocalProcessAppHost(
      AppHostLayout layout, Duration stopTimeout, SecureRandom secureRandom) {
    this(
        layout,
        stopTimeout,
        secureRandom,
        new AppEnv(),
        DEFAULT_TIMING,
        LocalProcessAppHost::deleteRecursively,
        AppInstallVerificationPolicy.rejectUnsignedByDefault());
  }

  /**
   * Creates a host with an explicit stop timeout, token generator, and verification policy.
   *
   * @param layout filesystem layout managed by the host
   * @param stopTimeout bounded timeout used before force-killing a child process
   * @param secureRandom secure token generator for launch-token generation
   * @param installVerificationPolicy copied-bundle verification policy applied on install/update
   */
  public LocalProcessAppHost(
      AppHostLayout layout,
      Duration stopTimeout,
      SecureRandom secureRandom,
      AppInstallVerificationPolicy installVerificationPolicy) {
    this(
        layout,
        stopTimeout,
        secureRandom,
        new AppEnv(),
        DEFAULT_TIMING,
        LocalProcessAppHost::deleteRecursively,
        installVerificationPolicy);
  }

  @SuppressWarnings("unused")
  LocalProcessAppHost(
      AppHostLayout layout, Duration stopTimeout, SecureRandom secureRandom, AppEnv appEnv) {
    this(
        layout,
        stopTimeout,
        secureRandom,
        appEnv,
        DEFAULT_TIMING,
        LocalProcessAppHost::deleteRecursively,
        AppInstallVerificationPolicy.rejectUnsignedByDefault());
  }

  @SuppressWarnings("unused")
  LocalProcessAppHost(
      AppHostLayout layout,
      Duration stopTimeout,
      SecureRandom secureRandom,
      AppEnv appEnv,
      TimingConfig timing) {
    this(
        layout,
        stopTimeout,
        secureRandom,
        appEnv,
        timing,
        LocalProcessAppHost::deleteRecursively,
        AppInstallVerificationPolicy.rejectUnsignedByDefault());
  }

  LocalProcessAppHost(
      AppHostLayout layout,
      Duration stopTimeout,
      SecureRandom secureRandom,
      AppEnv appEnv,
      TimingConfig timing,
      AppInstallVerificationPolicy installVerificationPolicy) {
    this(
        layout,
        stopTimeout,
        secureRandom,
        appEnv,
        timing,
        LocalProcessAppHost::deleteRecursively,
        installVerificationPolicy);
  }

  LocalProcessAppHost(
      AppHostLayout layout,
      Duration stopTimeout,
      SecureRandom secureRandom,
      AppEnv appEnv,
      TimingConfig timing,
      AppInstallVerificationPolicy installVerificationPolicy,
      RestartStormPolicy restartStormPolicy) {
    this(
        layout,
        stopTimeout,
        secureRandom,
        appEnv,
        timing,
        new HostDependencies(
            LocalProcessAppHost::deleteRecursively,
            installVerificationPolicy,
            AppSandboxProviders.defaults(appEnv),
            restartStormPolicy));
  }

  @SuppressWarnings("unused")
  LocalProcessAppHost(
      AppHostLayout layout,
      Duration stopTimeout,
      SecureRandom secureRandom,
      AppEnv appEnv,
      TimingConfig timing,
      ManagedTreeDeleter managedTreeDeleter) {
    this(
        layout,
        stopTimeout,
        secureRandom,
        appEnv,
        timing,
        managedTreeDeleter,
        AppInstallVerificationPolicy.rejectUnsignedByDefault());
  }

  LocalProcessAppHost(
      AppHostLayout layout,
      Duration stopTimeout,
      SecureRandom secureRandom,
      AppEnv appEnv,
      TimingConfig timing,
      ManagedTreeDeleter managedTreeDeleter,
      AppInstallVerificationPolicy installVerificationPolicy) {
    this(
        layout,
        stopTimeout,
        secureRandom,
        appEnv,
        timing,
        new HostDependencies(
            managedTreeDeleter,
            installVerificationPolicy,
            AppSandboxProviders.defaults(appEnv),
            DEFAULT_RESTART_STORM_POLICY));
  }

  LocalProcessAppHost(
      AppHostLayout layout,
      Duration stopTimeout,
      SecureRandom secureRandom,
      AppEnv appEnv,
      TimingConfig timing,
      AppInstallVerificationPolicy installVerificationPolicy,
      AppSandboxProviders sandboxProviders) {
    this(
        layout,
        stopTimeout,
        secureRandom,
        appEnv,
        timing,
        new HostDependencies(
            LocalProcessAppHost::deleteRecursively,
            installVerificationPolicy,
            sandboxProviders,
            DEFAULT_RESTART_STORM_POLICY));
  }

  private LocalProcessAppHost(
      AppHostLayout layout,
      Duration stopTimeout,
      SecureRandom secureRandom,
      AppEnv appEnv,
      TimingConfig timing,
      HostDependencies dependencies) {
    this.layout = Objects.requireNonNull(layout, "layout");
    this.originStore = new FileInstalledAppOriginStore(this.layout.appOriginProvenanceDir());
    this.stopTimeout = Objects.requireNonNull(stopTimeout, "stopTimeout");
    this.secureRandom = Objects.requireNonNull(secureRandom, "secureRandom");
    this.appEnv = Objects.requireNonNull(appEnv, "appEnv");
    this.timing = Objects.requireNonNull(timing, "timing");
    HostDependencies normalized = Objects.requireNonNull(dependencies, "dependencies");
    this.managedTreeDeleter =
        Objects.requireNonNull(normalized.managedTreeDeleter(), "managedTreeDeleter");
    this.installVerificationPolicy =
        Objects.requireNonNull(normalized.installVerificationPolicy(), "installVerificationPolicy");
    this.sandboxProviders =
        Objects.requireNonNull(normalized.sandboxProviders(), "sandboxProviders");
    this.quotaEnforcer = new AppQuotaEnforcer();
    RestartStormPolicy restartStormPolicy =
        Objects.requireNonNull(normalized.restartStormPolicy(), "restartStormPolicy");
    this.restartStormWindow = restartStormPolicy.restartStormWindow();
    this.restartStormMaxInWindow = restartStormPolicy.restartStormMaxInWindow();
    if (stopTimeout.isZero() || stopTimeout.isNegative()) {
      throw new IllegalArgumentException("stopTimeout must be positive");
    }
  }

  /**
   * Installs the catalog-revision retention coordinator and reconciles existing provenance.
   *
   * <p>Production composition calls this before exposing the host. Reconciliation runs inside the
   * host lifecycle monitor and is retried after interrupted persistent mutations.
   *
   * @param retention coordinator for the complete current-and-rollback origin snapshot
   * @throws IOException if transaction recovery or initial reconciliation fails
   */
  public synchronized void setCatalogOriginRetention(AppHost.CatalogOriginRetention retention)
      throws IOException {
    catalogOriginRetention = Objects.requireNonNull(retention, "retention");
    catalogOriginRetentionPending = true;
    ensurePersistentMutationsRecovered();
  }

  /**
   * Installs one app from a local staging directory.
   *
   * <p>The staging tree is treated as caller-controlled input. The host validates that tree and
   * copies it into a temporary managed location. It then parses the copied manifest, validates the
   * copied executable, provisions the mutable directories that belong to the derived app id, and
   * moves the copied bundle into place atomically when possible.
   *
   * @param stagedAppDirectory staging directory containing {@code cryptad-app.properties}
   * @return installed application snapshot describing the copied bundle and managed paths
   * @throws IOException if the staging tree is unsafe, the bundle is invalid, host-owned path
   *     boundaries are violated, or the copied bundle cannot be installed cleanly
   */
  @Override
  public synchronized InstalledAppSnapshot installFromDirectory(Path stagedAppDirectory)
      throws IOException {
    ensurePersistentMutationsRecovered();
    return installBundleFromDirectory(stagedAppDirectory, null);
  }

  private InstalledAppSnapshot installBundleFromDirectory(
      Path stagedAppDirectory, InstalledAppOrigin expectedOrigin) throws IOException {
    Path stagingRoot = normalizeExistingDirectory(stagedAppDirectory);
    rejectOverlappingInstallTree(stagingRoot, layout.installedAppsDir());
    Path installedAppsDir = layout.installedAppsDir();
    ensureManagedDirectory(layout.dataDir(), installedAppsDir, INSTALLED_APPS_DIR_LABEL);
    rejectOverlappingRollbackTree(stagingRoot, layout.rollbackAppsDir());
    Path temporaryInstallRoot = Files.createTempDirectory(installedAppsDir, TEMP_INSTALL_PREFIX);
    try {
      copyDirectoryTree(stagingRoot, temporaryInstallRoot);
      AppBundleVerification bundleVerification = verifyCopiedBundle(temporaryInstallRoot);
      AppManifest manifest = validateCopiedBundle(temporaryInstallRoot);
      if (expectedOrigin != null) {
        requireMatchingCatalogOrigin(manifest, bundleVerification, expectedOrigin);
      }
      InstalledAppPaths paths = layout.pathsFor(manifest.appId());
      rejectOverlappingMutableAppDirectories(stagingRoot, paths);
      if (Files.exists(paths.installedRoot())) {
        throw new AppHostException("app already installed: " + manifest.appId());
      }
      validateManagedMutableDirectories(paths);
      paths.ensureMutableDirectories();
      deleteRollbackRecordIfPresent(paths.appId());
      moveIntoPlace(temporaryInstallRoot, paths.installedRoot());
      return new InstalledAppSnapshot(manifest, paths);
    } catch (IOException | RuntimeException e) {
      deleteRecursively(temporaryInstallRoot);
      throw e;
    }
  }

  @Override
  public synchronized InstalledAppSnapshot installCatalogFromDirectory(
      Path stagedAppDirectory, InstalledAppOrigin origin) throws IOException {
    return installCatalogFromDirectory(stagedAppDirectory, origin, ignored -> () -> {});
  }

  @Override
  public synchronized InstalledAppSnapshot installCatalogFromDirectory(
      Path stagedAppDirectory,
      InstalledAppOrigin origin,
      AppHost.CatalogMutationAuthorization authorization)
      throws IOException {
    ensurePersistentMutationsRecovered();
    InstalledAppOrigin checked = Objects.requireNonNull(origin, ORIGIN_PARAMETER);
    AppHost.CatalogMutationAuthorization checkedAuthorization =
        Objects.requireNonNull(authorization, AUTHORIZATION_PARAMETER);
    FileInstalledAppOriginStore.State previous = originStore.snapshot(checked.appId());
    if (previous.current().isPresent() || previous.rollback().isPresent()) {
      throw new AppHostException("stale catalog origin exists for a new installation");
    }
    try (var _ =
        Objects.requireNonNull(
            checkedAuthorization.authorize(checked), "catalog mutation authorization lease")) {
      PersistentMutation mutation =
          beginPersistentMutation(
              checked.appId(), PersistentMutationOperation.CATALOG_INSTALL, previous);
      try {
        originStore.put(checked);
        InstalledAppSnapshot installed = installBundleFromDirectory(stagedAppDirectory, checked);
        requireMatchingCatalogOrigin(installed, checked);
        retainCatalogOriginRevisions();
        commitPersistentMutation(mutation);
        finishCatalogOriginRetention();
        return installed;
      } catch (IOException | RuntimeException failure) {
        abortPersistentMutationAndReconcile(mutation, failure);
        throw failure;
      }
    }
  }

  /**
   * Replaces one installed app bundle from a local staging directory.
   *
   * <p>The update flow deliberately reuses the installation model: the caller provides a local
   * staged directory, the host copies and validates that bundle under managed storage, and the
   * staged manifest must target the same normalized app id as the existing installation. Only the
   * immutable installed bundle root is replaced. The host-owned data, cache, and run directories
   * remain in place and are preserved.
   *
   * <p>AppHost v1 keeps replacement conservative and explicit. The target app must already be
   * installed and stopped before any filesystem mutation occurs.
   *
   * @param appId stable application identifier
   * @param stagedAppDirectory staging directory containing {@code cryptad-app.properties}
   * @return installed application snapshot describing the replaced bundle and preserved host paths
   * @throws IOException if the app is missing or still running, the staged bundle is invalid or
   *     targets a different app id, or the replacement cannot be completed safely
   */
  @Override
  public synchronized InstalledAppSnapshot updateFromDirectory(
      String appId, Path stagedAppDirectory) throws IOException {
    ensurePersistentMutationsRecovered();
    String normalizedAppId = InstalledAppPaths.normalizeAppId(appId);
    FileInstalledAppOriginStore.State previous = originStore.snapshot(normalizedAppId);
    boolean originTracked = previous.current().isPresent() || previous.rollback().isPresent();
    PreparedUpdateBundle prepared = prepareUpdateBundle(normalizedAppId, stagedAppDirectory, null);
    try {
      return commitGenericUpdate(prepared, previous, originTracked);
    } catch (IOException | RuntimeException failure) {
      discardPreparedUpdateBundle(prepared, failure);
      throw failure;
    }
  }

  private InstalledAppSnapshot commitGenericUpdate(
      PreparedUpdateBundle prepared,
      FileInstalledAppOriginStore.State previous,
      boolean originTracked)
      throws IOException {
    PersistentMutation mutation =
        beginPersistentMutation(
            prepared.normalizedAppId(), PersistentMutationOperation.GENERIC_UPDATE, previous);
    try {
      if (originTracked) {
        originStore.restore(
            prepared.normalizedAppId(),
            new FileInstalledAppOriginStore.State(Optional.empty(), previous.current()));
      }
      InstalledAppSnapshot updated = commitPreparedUpdateBundle(prepared);
      retainCatalogOriginRevisions();
      commitPersistentMutation(mutation);
      finishCatalogOriginRetention();
      return updated;
    } catch (IOException | RuntimeException failure) {
      abortPersistentMutationAndReconcile(mutation, failure);
      throw failure;
    }
  }

  private PreparedUpdateBundle prepareUpdateBundle(
      String normalizedAppId, Path stagedAppDirectory, InstalledAppOrigin expectedReplacementOrigin)
      throws IOException {
    Path stagingRoot = normalizeExistingDirectory(stagedAppDirectory);
    Path installedAppsDir = validateInstalledAppsDirectory();
    Path rollbackAppsDir = validateRollbackAppsDirectory();
    rejectOverlappingInstallTree(stagingRoot, installedAppsDir);
    rejectOverlappingRollbackTree(stagingRoot, rollbackAppsDir);
    InstalledAppPaths paths = layout.pathsFor(normalizedAppId);
    rejectOverlappingMutableAppDirectories(stagingRoot, paths);
    if (liveRunningProcess(normalizedAppId) != null) {
      throw new AppHostException("cannot update a running app: " + normalizedAppId);
    }
    if (!Files.isDirectory(paths.installedRoot(), LinkOption.NOFOLLOW_LINKS)) {
      throw new AppHostException(APP_NOT_INSTALLED_PREFIX + normalizedAppId);
    }
    validateManagedMutableDirectories(paths);

    Path temporaryInstallRoot = Files.createTempDirectory(installedAppsDir, TEMP_INSTALL_PREFIX);
    try {
      copyDirectoryTree(stagingRoot, temporaryInstallRoot);
      AppBundleVerification bundleVerification = verifyCopiedBundle(temporaryInstallRoot);
      AppManifest manifest = validateCopiedBundle(temporaryInstallRoot);
      requireMatchingUpdateTarget(normalizedAppId, manifest);
      if (expectedReplacementOrigin != null) {
        requireMatchingCatalogOrigin(manifest, bundleVerification, expectedReplacementOrigin);
      }
      paths.ensureMutableDirectories();
      Path ensuredRollbackAppsDir = ensureRollbackAppsDirectory();
      Path backupInstallRoot =
          temporaryManagedPath(installedAppsDir, TEMP_UPDATE_BACKUP_PREFIX + normalizedAppId + "-");
      Path rollbackRoot = rollbackRootFor(normalizedAppId);
      Path previousRollbackBackupRoot =
          temporaryManagedPath(
              ensuredRollbackAppsDir, TEMP_ROLLBACK_BACKUP_PREFIX + normalizedAppId + "-");
      return new PreparedUpdateBundle(
          normalizedAppId,
          temporaryInstallRoot,
          manifest,
          paths,
          backupInstallRoot,
          rollbackRoot,
          previousRollbackBackupRoot);
    } catch (IOException | RuntimeException e) {
      discardPreparedUpdateBundle(temporaryInstallRoot, e);
      throw e;
    }
  }

  private InstalledAppSnapshot commitPreparedUpdateBundle(PreparedUpdateBundle prepared)
      throws IOException {
    replaceInstalledBundle(
        prepared.paths().installedRoot(),
        prepared.replacementRoot(),
        prepared.backupInstallRoot(),
        prepared.rollbackRoot(),
        prepared.previousRollbackBackupRoot());
    cancelPendingRestartAfterAcceptedUpdate(prepared.normalizedAppId());
    return new InstalledAppSnapshot(prepared.manifest(), prepared.paths());
  }

  private static void discardPreparedUpdateBundle(
      PreparedUpdateBundle prepared, Throwable failure) {
    discardPreparedUpdateBundle(prepared.replacementRoot(), failure);
  }

  private static void discardPreparedUpdateBundle(Path replacementRoot, Throwable failure) {
    try {
      deleteScratchTreeIfPresent(replacementRoot);
    } catch (IOException cleanupFailure) {
      failure.addSuppressed(cleanupFailure);
    }
  }

  @Override
  public synchronized InstalledAppSnapshot updateCatalogFromDirectory(
      String appId, Path stagedAppDirectory, InstalledAppOrigin origin) throws IOException {
    ensurePersistentMutationsRecovered();
    String normalizedAppId = InstalledAppPaths.normalizeAppId(appId);
    Optional<String> currentOriginDigest =
        originStore.snapshot(normalizedAppId).current().map(InstalledAppOrigin::selfDigestSha256);
    AppHost.CatalogOriginExpectation expectedCurrentOrigin =
        currentOriginDigest
            .map(AppHost.CatalogOriginExpectation::matching)
            .orElseGet(AppHost.CatalogOriginExpectation::absent);
    return updateCatalogFromDirectory(
        normalizedAppId, stagedAppDirectory, origin, expectedCurrentOrigin);
  }

  @Override
  public synchronized InstalledAppSnapshot updateCatalogFromDirectory(
      String appId,
      Path stagedAppDirectory,
      InstalledAppOrigin origin,
      AppHost.CatalogOriginExpectation expectedCurrentOrigin)
      throws IOException {
    return updateCatalogFromDirectory(
        appId, stagedAppDirectory, origin, expectedCurrentOrigin, ignored -> () -> {});
  }

  @Override
  public synchronized InstalledAppSnapshot updateCatalogFromDirectory(
      String appId,
      Path stagedAppDirectory,
      InstalledAppOrigin origin,
      AppHost.CatalogOriginExpectation expectedCurrentOrigin,
      AppHost.CatalogMutationAuthorization authorization)
      throws IOException {
    ensurePersistentMutationsRecovered();
    String normalizedAppId = InstalledAppPaths.normalizeAppId(appId);
    InstalledAppOrigin checked = Objects.requireNonNull(origin, ORIGIN_PARAMETER);
    Optional<String> expected =
        Objects.requireNonNull(expectedCurrentOrigin, "expectedCurrentOrigin").digestSha256();
    AppHost.CatalogMutationAuthorization checkedAuthorization =
        Objects.requireNonNull(authorization, AUTHORIZATION_PARAMETER);
    if (!normalizedAppId.equals(checked.appId())) {
      throw new AppHostException("catalog origin app id does not match update target");
    }
    FileInstalledAppOriginStore.State previous = originStore.snapshot(normalizedAppId);
    Optional<String> actual = previous.current().map(InstalledAppOrigin::selfDigestSha256);
    if (!actual.equals(expected) || !checked.previousOriginDigestSha256().equals(expected)) {
      throw new AppHostException.CatalogOriginChangedException();
    }
    PreparedUpdateBundle prepared =
        prepareUpdateBundle(normalizedAppId, stagedAppDirectory, checked);
    try {
      return commitAuthorizedCatalogUpdate(prepared, checked, previous, checkedAuthorization);
    } catch (IOException | RuntimeException failure) {
      discardPreparedUpdateBundle(prepared, failure);
      throw failure;
    }
  }

  private InstalledAppSnapshot commitAuthorizedCatalogUpdate(
      PreparedUpdateBundle prepared,
      InstalledAppOrigin origin,
      FileInstalledAppOriginStore.State previous,
      AppHost.CatalogMutationAuthorization authorization)
      throws IOException {
    try (var _ =
        Objects.requireNonNull(
            authorization.authorize(origin), "catalog mutation authorization lease")) {
      return commitCatalogUpdate(prepared, origin, previous);
    }
  }

  private InstalledAppSnapshot commitCatalogUpdate(
      PreparedUpdateBundle prepared,
      InstalledAppOrigin origin,
      FileInstalledAppOriginStore.State previous)
      throws IOException {
    PersistentMutation mutation =
        beginPersistentMutation(
            prepared.normalizedAppId(), PersistentMutationOperation.CATALOG_UPDATE, previous);
    try {
      originStore.put(origin);
      InstalledAppSnapshot updated = commitPreparedUpdateBundle(prepared);
      requireMatchingCatalogOrigin(updated, origin);
      retainCatalogOriginRevisions();
      commitPersistentMutation(mutation);
      finishCatalogOriginRetention();
      return updated;
    } catch (IOException | RuntimeException failure) {
      abortPersistentMutationAndReconcile(mutation, failure);
      throw failure;
    }
  }

  private void requireMatchingCatalogOrigin(
      InstalledAppSnapshot installed, InstalledAppOrigin origin) throws IOException {
    AppBundleVerification verification =
        verifyHistoricalCopiedBundle(installed.paths().installedRoot());
    requireMatchingCatalogOrigin(installed.manifest(), verification, origin);
  }

  private void requireMatchingCatalogOrigin(
      AppManifest manifest, AppBundleVerification verification, InstalledAppOrigin origin)
      throws AppHostException {
    if (!manifest.appId().equals(origin.appId())
        || !manifest.appVersion().equals(origin.appVersion())) {
      throw new AppHostException("catalog origin does not match the committed app bundle");
    }
    if (!verification.signed()) {
      if (!installVerificationPolicy.allowsUnsignedForDevelopmentOnly()
          || !origin.publisherKeyFingerprintSha256().isEmpty()
          || !origin.signedContentDigestSha256().isEmpty()) {
        throw new AppHostException("catalog origin requires an exact signed app bundle");
      }
      return;
    }
    if (!origin.publisherKeyId().equals(verification.keyId())
        || !origin.publisherKeyFingerprintSha256().equals(verification.keyFingerprintSha256())
        || !origin.signedContentDigestSha256().equals(verification.signedContentDigestSha256())) {
      throw new AppHostException(
          "catalog origin does not match the verified publisher or signed bundle content");
    }
  }

  /**
   * Returns path-free metadata for one app's durable rollback bundle.
   *
   * @param appId stable application identifier
   * @return rollback metadata when a previous bundle exists
   * @throws IOException if the rollback tree cannot be inspected safely or the rollback manifest is
   *     invalid
   */
  @Override
  public synchronized Optional<AppRollbackRecord> rollbackStatus(String appId) throws IOException {
    ensurePersistentMutationsRecovered();
    String normalizedAppId = InstalledAppPaths.normalizeAppId(appId);
    validateInstalledAppsDirectory();
    validateRollbackAppsDirectory();
    Path rollbackRoot = rollbackRootFor(normalizedAppId);
    if (!Files.isDirectory(rollbackRoot, LinkOption.NOFOLLOW_LINKS)) {
      return Optional.empty();
    }
    AppManifest manifest = readInstalledManifest(rollbackRoot);
    requireMatchingUpdateTarget(normalizedAppId, manifest);
    return Optional.of(
        new AppRollbackRecord(normalizedAppId, manifest.appName(), manifest.appVersion()));
  }

  /**
   * Restores the previous installed bundle while preserving mutable app directories.
   *
   * @param appId stable application identifier
   * @return installed application snapshot after rollback
   * @throws IOException if the app is missing, running, has no rollback record, or the replacement
   *     cannot be completed safely
   */
  @Override
  public synchronized InstalledAppSnapshot rollback(String appId) throws IOException {
    return rollbackInternal(appId, null);
  }

  /**
   * Restores a retained catalog bundle after authorizing its exact host-selected origin.
   *
   * @param appId stable application identifier
   * @param authorization current local federation-policy authorization callback
   * @return installed application snapshot after rollback
   * @throws IOException if authorization, validation, or rollback fails
   */
  @Override
  public synchronized InstalledAppSnapshot rollback(
      String appId, AppHost.CatalogRollbackAuthorization authorization) throws IOException {
    return rollbackInternal(appId, Objects.requireNonNull(authorization, AUTHORIZATION_PARAMETER));
  }

  private InstalledAppSnapshot rollbackInternal(
      String appId, AppHost.CatalogRollbackAuthorization authorization) throws IOException {
    ensurePersistentMutationsRecovered();
    String normalizedAppId = InstalledAppPaths.normalizeAppId(appId);
    Path installedAppsDir = validateInstalledAppsDirectory();
    ensureRollbackAppsDirectory();
    InstalledAppPaths paths = layout.pathsFor(normalizedAppId);
    if (liveRunningProcess(normalizedAppId) != null) {
      throw new AppHostException("cannot rollback a running app: " + normalizedAppId);
    }
    if (!Files.isDirectory(paths.installedRoot(), LinkOption.NOFOLLOW_LINKS)) {
      throw new AppHostException(APP_NOT_INSTALLED_PREFIX + normalizedAppId);
    }
    Path rollbackRoot = rollbackRootFor(normalizedAppId);
    if (!Files.isDirectory(rollbackRoot, LinkOption.NOFOLLOW_LINKS)) {
      throw new AppHostException("rollback record is not available: " + normalizedAppId);
    }
    validateManagedMutableDirectories(paths);
    paths.ensureMutableDirectories();
    AppBundleVerification rollbackVerification = verifyHistoricalCopiedBundle(rollbackRoot);
    AppManifest rollbackManifest = validateCopiedBundle(rollbackRoot);
    requireMatchingUpdateTarget(normalizedAppId, rollbackManifest);
    Path currentInstallBackupRoot =
        temporaryManagedPath(installedAppsDir, TEMP_UPDATE_BACKUP_PREFIX + normalizedAppId + "-");

    FileInstalledAppOriginStore.State originState = originStore.snapshot(normalizedAppId);
    boolean originTracked = originState.current().isPresent() || originState.rollback().isPresent();
    AppHost.CatalogMutationAuthorizationLease rollbackAuthorization = () -> {};
    if (originState.rollback().isPresent()) {
      if (authorization == null) {
        throw new AppHostException.CatalogRollbackAuthorizationException();
      }
      InstalledAppOrigin rollbackOrigin = originState.rollback().orElseThrow();
      requireMatchingCatalogOrigin(rollbackManifest, rollbackVerification, rollbackOrigin);
      rollbackAuthorization =
          Objects.requireNonNull(
              authorization.authorize(rollbackOrigin), "catalog rollback authorization lease");
    }
    try (var _ = rollbackAuthorization) {
      PersistentMutation mutation =
          beginPersistentMutation(
              normalizedAppId, PersistentMutationOperation.ROLLBACK, originState);
      try {
        swapInstalledBundleWithRollback(
            paths.installedRoot(), rollbackRoot, currentInstallBackupRoot);
        if (originTracked) {
          originStore.swapRollback(normalizedAppId);
        }
        retainCatalogOriginRevisions();
        commitPersistentMutation(mutation);
        finishCatalogOriginRetention();
      } catch (IOException | RuntimeException failure) {
        abortPersistentMutationAndReconcile(mutation, failure);
        throw failure;
      }
    }
    cancelPendingRestartAfterAcceptedUpdate(normalizedAppId);
    return new InstalledAppSnapshot(rollbackManifest, paths);
  }

  @Override
  public synchronized void recordCatalogOrigin(InstalledAppOrigin origin) throws IOException {
    ensurePersistentMutationsRecovered();
    Objects.requireNonNull(origin, ORIGIN_PARAMETER);
    throw new AppHostException(
        "catalog origin must be committed with the corresponding bundle mutation");
  }

  @Override
  public synchronized Optional<InstalledAppOrigin> catalogOrigin(String appId) throws IOException {
    ensurePersistentMutationsRecovered();
    return originStore.find(InstalledAppPaths.normalizeAppId(appId));
  }

  @Override
  public synchronized boolean rollbackRequiresCatalogAuthorization(String appId)
      throws IOException {
    ensurePersistentMutationsRecovered();
    return originStore.snapshot(InstalledAppPaths.normalizeAppId(appId)).rollback().isPresent();
  }

  /**
   * Removes one installed app and its host-owned directories.
   *
   * <p>The host revalidates the managed installation tree before deletion and refuses to uninstall
   * a live app, so callers do not remove files that a running process is still using.
   *
   * @param appId stable application identifier
   * @throws IOException if the app is running, missing, outside the validated managed tree, or any
   *     owned files cannot be removed
   */
  @Override
  public synchronized void uninstall(String appId) throws IOException {
    uninstall(appId, AppUninstallOptions.removeAll());
  }

  @Override
  public synchronized void uninstall(String appId, AppUninstallOptions options) throws IOException {
    ensurePersistentMutationsRecovered();
    Objects.requireNonNull(options, "options");
    validateInstalledAppsDirectory();
    validateRollbackAppsDirectory();
    InstalledAppPaths paths = layout.pathsFor(appId);
    if (liveRunningProcess(paths.appId()) != null) {
      throw new AppHostException("cannot uninstall a running app: " + appId);
    }
    if (!Files.exists(paths.installedRoot())) {
      throw new AppHostException(APP_NOT_INSTALLED_PREFIX + appId);
    }

    FileInstalledAppOriginStore.State previousOrigin = originStore.snapshot(paths.appId());
    PersistentMutation mutation =
        beginPersistentMutation(
            paths.appId(), PersistentMutationOperation.UNINSTALL, previousOrigin);
    try {
      deleteRecursively(paths.installedRoot());
      deleteRollbackRecordIfPresent(paths.appId());
      originStore.remove(paths.appId());
      retainCatalogOriginRevisions();
      commitPersistentMutation(mutation);
      finishCatalogOriginRetention();
    } catch (IOException | RuntimeException failure) {
      abortPersistentMutationAndReconcile(mutation, failure);
      throw failure;
    }
    if (!options.preserveData()) {
      deleteRecursively(paths.dataDir());
    }
    deleteRecursively(paths.cacheDir());
    deleteRecursively(paths.runDir());
    runtimeRecords.remove(paths.appId());
    automaticRestartAttempts.remove(paths.appId());
    explicitStopRequests.remove(paths.appId());
  }

  /**
   * Lists all installed apps.
   *
   * <p>The result is built from the validated managed installation tree and sorted by directory
   * name. Temporary install leftovers and non-app entries are skipped so stale partial
   * installations do not poison the whole listing operation.
   *
   * @return installed application snapshots sorted by app id
   * @throws IOException if the managed installation tree cannot be validated or scanned safely
   */
  @Override
  public synchronized List<InstalledAppSnapshot> listInstalled() throws IOException {
    ensurePersistentMutationsRecovered();
    Path installedAppsDir = validateInstalledAppsDirectory();
    if (!Files.isDirectory(installedAppsDir, LinkOption.NOFOLLOW_LINKS)) {
      return List.of();
    }

    List<InstalledAppSnapshot> installed = new ArrayList<>();
    try (var children = Files.list(installedAppsDir)) {
      for (Path appRoot :
          children.sorted(Comparator.comparing(path -> path.getFileName().toString())).toList()) {
        if (shouldSkipInstalledEntry(appRoot)) {
          continue;
        }
        AppManifest manifest = readInstalledManifest(appRoot);
        installed.add(new InstalledAppSnapshot(manifest, layout.pathsFor(manifest.appId())));
      }
    }
    return List.copyOf(installed);
  }

  /**
   * Describes one installed app.
   *
   * @param appId stable application identifier
   * @return installed snapshot when present, or {@link Optional#empty()} when the app is not
   *     currently installed
   * @throws IOException if the managed installation tree cannot be validated, or the installed
   *     manifest cannot be read safely
   */
  @Override
  public synchronized Optional<InstalledAppSnapshot> describe(String appId) throws IOException {
    ensurePersistentMutationsRecovered();
    validateInstalledAppsDirectory();
    InstalledAppPaths paths = layout.pathsFor(appId);
    if (!Files.isDirectory(paths.installedRoot(), LinkOption.NOFOLLOW_LINKS)) {
      return Optional.empty();
    }
    return Optional.of(
        new InstalledAppSnapshot(readInstalledManifest(paths.installedRoot()), paths));
  }

  /** {@inheritDoc} */
  @Override
  public synchronized <T> T withVerifiedInstalledBundle(
      String appId, VerifiedBundleAction<T> action) throws IOException {
    InstalledAppSnapshot installed =
        describe(appId).orElseThrow(() -> new IOException("App is not installed."));
    AppBundleVerification verification =
        verifyHistoricalCopiedBundle(installed.paths().installedRoot());
    if (!verification.signed()
        || verification.keyFingerprintSha256() == null
        || verification.signedContentDigestSha256() == null) {
      throw new IOException("A complete verified signed bundle identity is required.");
    }
    return action.run(installed, verification);
  }

  /**
   * Starts one installed app as a child process.
   *
   * <p>Launch revalidates the installed manifest and executable. It recreates mutable directories
   * as needed, clears the previous process log, injects a fresh launch token into the child
   * environment, and then observes the launched process tree long enough to reject immediate
   * failures or capture a daemonized handoff.
   *
   * @param appId stable application identifier
   * @return running snapshot including the launch token, representative pid, and start timestamp
   * @throws IOException if the app is not installed, is already running, fails validation at launch
   *     time, or cannot be launched and tracked as a live process
   */
  @Override
  public synchronized RunningAppSnapshot start(String appId) throws IOException {
    ensurePersistentMutationsRecovered();
    String normalizedAppId = InstalledAppPaths.normalizeAppId(appId);
    if (liveRunningProcess(normalizedAppId) != null) {
      throw new AppHostException("app is already running: " + appId);
    }
    explicitStopRequests.remove(normalizedAppId);

    InstalledAppSnapshot installation =
        describe(normalizedAppId)
            .orElseThrow(() -> new AppHostException(APP_NOT_INSTALLED_PREFIX + appId));
    return launchInstalledApp(installation, 0, 0);
  }

  private RunningAppSnapshot launchInstalledApp(
      InstalledAppSnapshot installation, int restartCount, int currentRestartAttempt)
      throws IOException {
    String normalizedAppId = installation.appId();
    InstalledAppPaths paths = installation.paths();
    installVerificationPolicy.verifyHistoricalCopiedBundle(paths.installedRoot());
    validateManagedMutableDirectories(paths);
    paths.ensureMutableDirectories();
    quotaEnforcer.enforceLaunch(installation.manifest(), paths);
    prepareProcessLogFile(paths);

    Path executable =
        resolveBundleEntry(
            paths.installedRoot(), installation.manifest().execPath(), "installed app.exec");
    if (!Files.isRegularFile(executable, LinkOption.NOFOLLOW_LINKS)) {
      throw new AppHostException(
          "installed app.exec does not exist: " + installation.manifest().execPathText());
    }

    String token = generateToken();
    List<String> command = launchCommand(executable);
    Map<String, String> launchEnvironment = new LinkedHashMap<>();
    populateEnvironment(launchEnvironment, installation.manifest(), paths, token, appEnv);
    if ("mail-prototype".equals(normalizedAppId)) {
      if (mailPlatformApiEndpoint == null) throw new AppHostException("mail_endpoint_unavailable");
      launchEnvironment.put("CRYPTAD_MAIL_API_ENDPOINT", mailPlatformApiEndpoint.toASCIIString());
      if (Runtime.version().feature() < 25) throw new AppHostException("mail_java_unavailable");
      try {
        Path mailJava =
            appEnv
                .javaHome()
                .toRealPath()
                .resolve("bin")
                .resolve(appEnv.isWindows() ? "java.exe" : "java");
        if (!Files.isRegularFile(mailJava) || !Files.isExecutable(mailJava))
          throw new AppHostException("mail_java_unavailable");
        launchEnvironment.put("CRYPTAD_MAIL_JAVA", mailJava.toString());
      } catch (IOException | IllegalStateException exception) {
        throw new AppHostException("mail_java_unavailable");
      }
    }
    AppSandboxLaunchPlan launchPlan;
    try {
      launchPlan =
          sandboxProviders.prepareLaunch(
              new AppSandboxLaunchContext(
                  normalizedAppId,
                  paths.installedRoot(),
                  paths.dataDir(),
                  paths.cacheDir(),
                  paths.runDir(),
                  paths.processLogFile().getParent(),
                  command,
                  launchEnvironment,
                  paths.installedRoot(),
                  installation.manifest().sandboxPolicy(),
                  appEnv));
    } catch (AppSandboxException exception) {
      exception
          .sandboxStatus()
          .ifPresent(
              status ->
                  recordSandboxLaunchRejection(
                      normalizedAppId, paths, currentRestartAttempt, status));
      throw exception;
    }
    ProcessBuilder builder = new ProcessBuilder(launchPlan.command());
    builder.directory(launchPlan.workingDirectory().toFile());
    builder.redirectErrorStream(true);
    builder.redirectOutput(ProcessBuilder.Redirect.appendTo(paths.processLogFile().toFile()));
    builder.environment().clear();
    builder.environment().putAll(launchPlan.environment());

    Instant startedAt = Instant.now();
    Process process = builder.start();
    discardChildInput(process, normalizedAppId);
    List<ProcessHandle> startupProcessTree = observeStartupProcessTree(process, normalizedAppId);
    if (startupProcessTree.isEmpty()) {
      startupProcessTree = recoverStartupProcessTree(installation, token, startedAt, process);
    }
    if (startupProcessTree.isEmpty()) {
      recordProcessExit(
          normalizedAppId,
          new ProcessExitRecord(
              paths,
              processExitCode(process),
              Instant.now(),
              restartCount,
              currentRestartAttempt,
              token,
              launchPlan.sandboxStatus(),
              false,
              List.of()));
      throw startupFailure(normalizedAppId, process);
    }
    RunningAppSnapshot snapshot =
        new RunningAppSnapshot(
            installation.manifest(),
            paths,
            token,
            representativePid(
                startupProcessTree,
                process.pid(),
                preferDescendantPid(executable, startupProcessTree)),
            startedAt,
            launchPlan.sandboxStatus());
    CompletableFuture<Void> exitCleanup = new CompletableFuture<>();
    RunningProcess runningProcess =
        new RunningProcess(
            process,
            snapshot,
            exitCleanup,
            startupProcessTree,
            restartCount,
            currentRestartAttempt,
            startupRepresentativeProcessHandoff(process, startupProcessTree));
    launchIds.put(normalizedAppId, java.util.UUID.randomUUID().toString());
    runningApps.put(normalizedAppId, runningProcess);
    runtimeRecords.compute(
        normalizedAppId,
        (_, previousRecord) ->
            RuntimeRecord.running(snapshot, restartCount, currentRestartAttempt, previousRecord));
    StartupAcceptance startupAcceptance =
        acceptStartupRunningProcess(normalizedAppId, runningProcess, exitCleanup);
    if (startupAcceptance.runningProcess() == null) {
      throw startupFailure(normalizedAppId, process);
    }
    RunningProcess liveRunningProcess = startupAcceptance.runningProcess();
    if (startupAcceptance.restartScheduled()) {
      return liveRunningProcess.snapshot();
    }
    startTrackedProcessTreeObserver(normalizedAppId, process, exitCleanup);
    return liveRunningProcess.snapshot();
  }

  /**
   * Stops one running app if it is active.
   *
   * <p>The shutdown flow refreshes the tracked process tree, attempts graceful termination first,
   * escalates when needed, and performs a final re-scan before reporting success so that recovered
   * descendant processes are not left running silently.
   *
   * @param appId stable application identifier
   * @return {@code true} when a running process was found and stopped, or {@code false} when the
   *     host had no live process for that app id
   * @throws IOException if a running process tree cannot be shut down cleanly within the configured
   *     stop timeout
   */
  @Override
  public synchronized boolean stop(String appId) throws IOException {
    String normalizedAppId = InstalledAppPaths.normalizeAppId(appId);
    RunningProcess runningProcess = liveRunningProcess(normalizedAppId);
    if (runningProcess == null) {
      RuntimeRecord restartRecord = runtimeRecords.get(normalizedAppId);
      if (restartRecord != null && restartRecord.state() == AppRuntimeState.RESTARTING) {
        explicitStopRequests.add(normalizedAppId);
        runtimeRecords.put(normalizedAppId, restartRecord.stopped());
        return true;
      }
      return false;
    }
    explicitStopRequests.add(normalizedAppId);

    RunningProcess trackedRunningProcess =
        trackRunningProcessForStop(normalizedAppId, runningProcess);
    if (trackedRunningProcess == null) {
      return true;
    }
    trackedRunningProcess = stopWithEscalation(normalizedAppId, appId, trackedRunningProcess);
    if (trackedRunningProcess == null) {
      return true;
    }
    completeStop(normalizedAppId, appId, trackedRunningProcess);
    List<String> warnings = new ArrayList<>();
    RuntimeRecord exitRecord = runtimeRecords.get(normalizedAppId);
    if (exitRecord != null) {
      warnings.addAll(exitRecord.warnings());
    }
    warnings.addAll(processLogWarningMessages(trackedRunningProcess.snapshot().paths()));
    runtimeRecords.put(
        normalizedAppId,
        RuntimeRecord.stopped(trackedRunningProcess, warnings.stream().distinct().toList()));
    return true;
  }

  /**
   * Returns the current live process snapshot, if any.
   *
   * <p>This method refreshes the tracked runtime state before answering, so callers can still
   * observe a recovered descendant after the original launcher process has exited.
   *
   * @param appId stable application identifier
   * @return running snapshot when the host still tracks a live process for the app, or {@link
   *     Optional#empty()} otherwise
   */
  @Override
  public synchronized Optional<RunningAppSnapshot> status(String appId) {
    RunningProcess runningProcess = liveRunningProcess(InstalledAppPaths.normalizeAppId(appId));
    return runningProcess != null ? Optional.of(runningProcess.snapshot()) : Optional.empty();
  }

  /**
   * Lists all live child processes.
   *
   * <p>The returned list is built from the host's refreshed in-memory runtime view and sorted by
   * normalized app id for deterministic display and test assertions.
   *
   * @return immutable list of running snapshots sorted by app id
   */
  @Override
  public synchronized List<RunningAppSnapshot> listRunning() {
    List<RunningAppSnapshot> running = new ArrayList<>();
    List<String> appIds = new ArrayList<>(runningApps.keySet());
    appIds.sort(String::compareTo);
    for (String appId : appIds) {
      RunningProcess runningProcess = liveRunningProcess(appId);
      if (runningProcess != null) {
        running.add(runningProcess.snapshot());
      }
    }
    return List.copyOf(running);
  }

  /**
   * Returns inactive sandbox status using this host's configured provider registry.
   *
   * @param policy requested sandbox policy from an installed manifest
   * @return token-free inactive sandbox status for installed and stopped summaries
   */
  @Override
  public AppSandboxStatus inactiveSandboxStatus(AppSandboxPolicy policy) {
    return sandboxProviders.inactiveStatusFor(policy);
  }

  /**
   * Authenticates a launch token against refreshed live runtime state.
   *
   * @param token opaque launch token presented by an app process
   * @return token-free principal when the token belongs to a currently running app
   */
  @Override
  public synchronized Optional<AppTokenPrincipal> authenticateLaunchToken(String token) {
    if (token == null || token.isBlank()) {
      return Optional.empty();
    }
    List<String> appIds = new ArrayList<>(runningApps.keySet());
    appIds.sort(String::compareTo);
    for (String appId : appIds) {
      RunningProcess runningProcess = liveRunningProcess(appId);
      if (runningProcess != null && token.equals(runningProcess.snapshot().token())) {
        RunningAppSnapshot snapshot = runningProcess.snapshot();
        return Optional.of(
            new AppTokenPrincipal(
                snapshot.appId(),
                snapshot.manifest().permissions(),
                launchIds.getOrDefault(snapshot.appId(), ""),
                snapshot.manifest().appVersion()));
      }
    }
    return Optional.empty();
  }

  /**
   * Returns token-free runtime status for one installed app.
   *
   * @param appId stable application identifier
   * @return process-level runtime status snapshot
   * @throws IOException if the app is not installed or managed files cannot be inspected
   */
  @Override
  public synchronized AppRuntimeStatusSnapshot runtimeStatus(String appId) throws IOException {
    String normalizedAppId = InstalledAppPaths.normalizeAppId(appId);
    RunningProcess runningProcess = liveRunningProcess(normalizedAppId);
    if (runningProcess != null) {
      RuntimeRecord previousRecord = runtimeRecords.get(normalizedAppId);
      return statusSnapshot(
          normalizedAppId,
          runningProcess.snapshot().manifest(),
          RuntimeRecord.running(runningProcess, previousRecord));
    }
    InstalledAppSnapshot installed =
        describe(normalizedAppId)
            .orElseThrow(() -> new AppHostException(APP_NOT_INSTALLED_PREFIX + appId));
    RuntimeRecord runtimeRecord = runtimeRecords.get(normalizedAppId);
    AppSandboxStatus installedSandboxStatus =
        inactiveSandboxStatus(installed.manifest().sandboxPolicy());
    if (runtimeRecord == null) {
      runtimeRecord = RuntimeRecord.stopped(installed.paths(), installedSandboxStatus);
    }
    return statusSnapshot(
        normalizedAppId,
        installed.manifest(),
        runtimeRecord.withoutRunningProcess(installed.paths(), installedSandboxStatus));
  }

  /**
   * Lists token-free runtime status for installed apps.
   *
   * @return runtime status snapshots sorted by app id
   * @throws IOException if the installed-app tree cannot be read safely
   */
  @Override
  public synchronized List<AppRuntimeStatusSnapshot> listRuntimeStatus() throws IOException {
    List<AppRuntimeStatusSnapshot> statuses = new ArrayList<>();
    for (InstalledAppSnapshot installed : listInstalled()) {
      statuses.add(runtimeStatus(installed.appId()));
    }
    return List.copyOf(statuses);
  }

  /**
   * Reads a bounded, token-redacted tail of one app's process log.
   *
   * @param appId stable application identifier
   * @param maxBytes requested maximum bytes before clamping
   * @return redacted process-log tail snapshot
   * @throws IOException if the app is not installed or the log cannot be inspected safely
   */
  @Override
  public synchronized AppProcessLogSnapshot readProcessLogTail(String appId, int maxBytes)
      throws IOException {
    String normalizedAppId = InstalledAppPaths.normalizeAppId(appId);
    int boundedMaxBytes = boundedLogTailBytes(maxBytes);
    RunningProcess runningProcess = liveRunningProcess(normalizedAppId);
    InstalledAppPaths paths;
    AppManifest manifest;
    String token;
    if (runningProcess == null) {
      InstalledAppSnapshot installed =
          describe(normalizedAppId)
              .orElseThrow(() -> new AppHostException(APP_NOT_INSTALLED_PREFIX + appId));
      paths = installed.paths();
      manifest = installed.manifest();
      token = null;
    } else {
      paths = runningProcess.snapshot().paths();
      manifest = runningProcess.snapshot().manifest();
      token = runningProcess.snapshot().token();
    }
    RuntimeRecord runtimeRecord =
        runningProcess == null ? runtimeRecords.get(normalizedAppId) : null;
    if (token == null && runtimeRecord != null) {
      token = runtimeRecord.lastLaunchToken();
    }
    quotaEnforcer.enforceProcessLogLimit(paths, AppQuotaPolicy.fromManifest(manifest));
    return readProcessLogTail(normalizedAppId, paths, token, boundedMaxBytes);
  }

  private void prepareProcessLogFile(InstalledAppPaths paths) throws IOException {
    Files.deleteIfExists(paths.processLogFile());
    Files.createFile(paths.processLogFile());
    OwnerOnlyFilePermissions.hardenSensitiveFile(paths.processLogFile());
  }

  private AppRuntimeStatusSnapshot statusSnapshot(
      String appId, AppManifest manifest, RuntimeRecord runtimeRecord) throws IOException {
    AppQuotaStatus quotaStatus = quotaEnforcer.status(manifest, runtimeRecord.paths());
    LogMetadata log = logMetadata(runtimeRecord.paths());
    return new AppRuntimeStatusSnapshot(
        appId,
        runtimeRecord.state(),
        runtimeRecord.running(),
        runtimeRecord.pid(),
        runtimeRecord.startedAt(),
        runtimeRecord.lastExitAt(),
        runtimeRecord.lastExitCode(),
        runtimeRecord.restartCount(),
        runtimeRecord.currentRestartAttempt(),
        log.available(),
        log.sizeBytes(),
        runtimeRecord.sandboxStatus(),
        quotaStatus,
        runtimeRecord.warnings());
  }

  private static int boundedLogTailBytes(int maxBytes) {
    if (maxBytes <= 0) {
      throw new IllegalArgumentException("maxBytes must be positive");
    }
    return Math.min(maxBytes, AppHost.MAX_PROCESS_LOG_TAIL_BYTES);
  }

  private AppProcessLogSnapshot readProcessLogTail(
      String appId, InstalledAppPaths paths, String token, int maxBytes) throws IOException {
    Path logFile = paths.processLogFile();
    BasicFileAttributes attributes = processLogAttributes(logFile);
    if (attributes == null) {
      return new AppProcessLogSnapshot(appId, false, false, maxBytes, 0L, "", null);
    }
    long sizeBytes = attributes.size();
    int overlapBytes = AppHostTokenRedactor.redactionOverlapBytes(token, paths);
    int bytesToRead = logTailReadBytes(sizeBytes, maxBytes, overlapBytes);
    long startOffset = sizeBytes - bytesToRead;
    ByteBuffer buffer = ByteBuffer.allocate(bytesToRead);
    try (SeekableByteChannel channel =
        Files.newByteChannel(logFile, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
      channel.position(startOffset);
      while (buffer.hasRemaining()) {
        if (channel.read(buffer) < 0) {
          break;
        }
      }
    }
    buffer.flip();
    byte[] bytes = new byte[buffer.remaining()];
    buffer.get(bytes);
    String redactedText =
        AppHostTokenRedactor.redact(new String(bytes, StandardCharsets.UTF_8), token, paths);
    String text = boundedUtf8Tail(redactedText, maxBytes);
    return new AppProcessLogSnapshot(
        appId,
        true,
        sizeBytes > maxBytes,
        maxBytes,
        sizeBytes,
        text,
        attributes.lastModifiedTime().toInstant());
  }

  private static int logTailReadBytes(long sizeBytes, int maxBytes, int overlapBytes) {
    long requestedBytes = Math.min(sizeBytes, (long) maxBytes + overlapBytes);
    return Math.toIntExact(Math.min(requestedBytes, Integer.MAX_VALUE));
  }

  private static String boundedUtf8Tail(String text, int maxBytes) {
    byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
    if (bytes.length <= maxBytes) {
      return text;
    }
    return new String(bytes, bytes.length - maxBytes, maxBytes, StandardCharsets.UTF_8);
  }

  private static LogMetadata logMetadata(InstalledAppPaths paths) throws IOException {
    BasicFileAttributes attributes = processLogAttributes(paths.processLogFile());
    if (attributes == null) {
      return new LogMetadata(false, null);
    }
    return new LogMetadata(true, attributes.size());
  }

  private static BasicFileAttributes processLogAttributes(Path logFile) throws IOException {
    if (!Files.exists(logFile, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(logFile)) {
      return null;
    }
    BasicFileAttributes attributes =
        Files.readAttributes(logFile, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
    return attributes.isRegularFile() ? attributes : null;
  }

  private void recordProcessExit(String appId, ProcessExitRecord exitRecord) {
    List<String> warnings = new ArrayList<>(exitRecord.warnings());
    warnings.addAll(processLogWarningMessages(exitRecord.paths()));
    runtimeRecords.put(
        appId,
        new RuntimeRecord(
            exitRecord.paths(),
            exitState(exitRecord.exitCode(), exitRecord.explicitStop()),
            false,
            null,
            null,
            exitRecord.exitAt(),
            exitRecord.exitCode(),
            exitRecord.lastLaunchToken(),
            exitRecord.sandboxStatus(),
            exitRecord.restartCount(),
            exitRecord.currentRestartAttempt(),
            warnings.stream().distinct().toList()));
  }

  private static AppRuntimeState exitState(Integer exitCode, boolean explicitStop) {
    if (explicitStop) {
      return AppRuntimeState.STOPPED;
    }
    if (exitCode != null && exitCode == 0) {
      return AppRuntimeState.EXITED;
    }
    return AppRuntimeState.CRASHED;
  }

  private static Integer processExitCode(Process process) {
    try {
      return process.exitValue();
    } catch (IllegalThreadStateException _) {
      return null;
    }
  }

  private static Integer trackedAppExitCode(RunningProcess runningProcess) {
    if (runningProcess.isRepresentativeProcessHandoff()) {
      return null;
    }
    return processExitCode(runningProcess.process());
  }

  private static boolean startupRepresentativeProcessHandoff(
      Process process, List<ProcessHandle> startupProcessTree) {
    long rootPid = process.pid();
    return !isEffectivelyAlive(process.toHandle())
        && startupProcessTree.stream().anyMatch(processHandle -> processHandle.pid() != rootPid);
  }

  private AppManifest readInstalledManifest(Path installedRoot) throws IOException {
    Path manifestFile =
        resolveBundleEntry(
            installedRoot, Path.of(AppManifestParser.MANIFEST_FILE_NAME), "installed manifest");
    AppManifest manifest = AppManifestParser.parse(manifestFile);
    String installedDirectoryName = installedDirectoryNameOrThrow(installedRoot);
    if (!installedDirectoryName.equals(manifest.appId())) {
      throw new AppManifestException(
          "installed manifest app.id does not match directory name: " + installedDirectoryName);
    }
    return manifest;
  }

  private AppBundleVerification verifyCopiedBundle(Path copiedRoot) throws IOException {
    return installVerificationPolicy.verifyCopiedBundle(copiedRoot);
  }

  private AppBundleVerification verifyHistoricalCopiedBundle(Path copiedRoot) throws IOException {
    return installVerificationPolicy.verifyHistoricalCopiedBundle(copiedRoot);
  }

  private AppManifest validateCopiedBundle(Path copiedRoot) throws IOException {
    Path manifestFile =
        resolveBundleEntry(
            copiedRoot, Path.of(AppManifestParser.MANIFEST_FILE_NAME), "copied manifest");
    if (!Files.isRegularFile(manifestFile, LinkOption.NOFOLLOW_LINKS)) {
      throw new AppManifestException("missing manifest file: " + manifestFile);
    }
    AppManifest manifest = AppManifestParser.parse(manifestFile);
    Path copiedExecutable = resolveBundleEntry(copiedRoot, manifest.execPath(), "copied app.exec");
    if (!Files.isRegularFile(copiedExecutable, LinkOption.NOFOLLOW_LINKS)) {
      throw new AppHostException(
          "app.exec does not resolve to a file in copied bundle: " + manifest.execPathText());
    }
    validateCopiedStaticUiEntry(copiedRoot, manifest);
    validateLaunchableCopiedExecutable(copiedExecutable, manifest);
    return manifest;
  }

  private static void validateCopiedStaticUiEntry(Path copiedRoot, AppManifest manifest)
      throws IOException {
    if (manifest.uiMode() != AppUiMode.STATIC) {
      return;
    }
    Path copiedUiEntry =
        resolveBundleEntry(copiedRoot, manifest.staticUiEntryPath(), "app.ui.entry");
    if (!Files.isRegularFile(copiedUiEntry, LinkOption.NOFOLLOW_LINKS)) {
      throw new AppHostException(
          "app.ui.entry does not resolve to a file in copied bundle: " + manifest.uiEntry());
    }
  }

  private static void requireMatchingUpdateTarget(String requestedAppId, AppManifest manifest)
      throws AppManifestException {
    if (!requestedAppId.equals(manifest.appId())) {
      throw new AppManifestException(
          "staged manifest app.id does not match requested app.id: " + requestedAppId);
    }
  }

  private void validateLaunchableCopiedExecutable(Path copiedExecutable, AppManifest manifest)
      throws IOException {
    if (appEnv.isWindows()) {
      if (!isLaunchableWindowsExecutable(copiedExecutable)) {
        throw new AppHostException(
            "app.exec is not launchable on Windows: " + manifest.execPathText());
      }
      return;
    }
    if (!isInterpreterManagedPosixLauncher(copiedExecutable)
        && !Files.isExecutable(copiedExecutable)) {
      throw new AppHostException(
          "app.exec is not launchable on POSIX without execute permission: "
              + manifest.execPathText());
    }
  }

  private RunningProcess liveRunningProcess(String appId) {
    RunningProcess runningProcess = runningApps.get(appId);
    if (runningProcess == null) {
      return null;
    }
    RunningProcess refreshedRunningProcess = refreshRunningProcess(runningProcess);
    if (refreshedRunningProcess == null) {
      refreshedRunningProcess = recoverTrackedRunningProcess(runningProcess);
    }
    if (refreshedRunningProcess != null) {
      runningApps.replace(appId, runningProcess, refreshedRunningProcess);
      return refreshedRunningProcess;
    }
    if (runningApps.remove(appId, runningProcess)) {
      recordExitAndScheduleRestartIfNeeded(appId, runningProcess);
      runningProcess.exitCleanup().join();
    }
    return null;
  }

  private StartupAcceptance acceptStartupRunningProcess(
      String appId, RunningProcess runningProcess, CompletableFuture<Void> exitCleanup) {
    RunningProcess refreshedRunningProcess = refreshRunningProcess(runningProcess);
    if (refreshedRunningProcess == null) {
      refreshedRunningProcess = recoverTrackedRunningProcess(runningProcess);
    }
    if (refreshedRunningProcess != null) {
      runningApps.replace(appId, runningProcess, refreshedRunningProcess);
      return StartupAcceptance.live(refreshedRunningProcess);
    }
    if (runningApps.remove(appId, runningProcess)) {
      RunningProcess exitedRunningProcess = runningProcess.withObservedRootHandoff();
      recordExitAndScheduleRestartIfNeeded(appId, exitedRunningProcess);
      exitCleanup.complete(null);
      if (startupRestartScheduled(appId, exitedRunningProcess)) {
        return StartupAcceptance.restarting(exitedRunningProcess);
      }
    }
    return StartupAcceptance.failed();
  }

  private RunningProcess refreshRunningProcess(RunningProcess runningProcess) {
    return runningProcess.refresh(timing.trackedProcessPostExitCaptureGracePeriod());
  }

  private RunningProcess refreshRunningProcessFromTree(
      RunningProcess runningProcess, List<ProcessHandle> processTree) {
    return runningProcess.tryWithProcessTree(
        processTree, timing.trackedProcessPostExitCaptureGracePeriod());
  }

  private boolean startupRestartScheduled(String appId, RunningProcess runningProcess) {
    return runningProcess.isRepresentativeProcessHandoff()
        && hasScheduledRestartRecord(appId, runningProcess.currentRestartAttempt() + 1);
  }

  private void recordExitAndScheduleRestartIfNeeded(String appId, RunningProcess runningProcess) {
    boolean explicitStop = explicitStopRequests.contains(appId);
    Integer exitCode = trackedAppExitCode(runningProcess);
    Instant exitAt = Instant.now();
    List<String> warnings = processLogWarningMessages(runningProcess.snapshot().paths());
    if (shouldRestart(runningProcess, exitCode, explicitStop)) {
      int nextAttempt = runningProcess.currentRestartAttempt() + 1;
      if (!recordAutomaticRestartAttempt(appId, exitAt)) {
        List<String> blockedWarnings = new ArrayList<>(warnings);
        blockedWarnings.add(restartStormWarning().message());
        recordProcessExit(
            appId,
            ProcessExitRecord.fromRunningProcess(
                runningProcess, exitCode, exitAt, false, blockedWarnings));
        return;
      }
      runtimeRecords.put(
          appId, RuntimeRecord.restarting(runningProcess, exitCode, exitAt, nextAttempt, warnings));
      scheduleRestart(
          appId,
          nextAttempt,
          Duration.ofMillis(runningProcess.snapshot().manifest().restartBackoffMillis()));
      return;
    }
    recordProcessExit(
        appId,
        ProcessExitRecord.fromRunningProcess(
            runningProcess, exitCode, exitAt, explicitStop, warnings));
  }

  private void cancelPendingRestartAfterAcceptedUpdate(String appId) {
    RuntimeRecord runtimeRecord = runtimeRecords.get(appId);
    if (runtimeRecord != null && runtimeRecord.state() == AppRuntimeState.RESTARTING) {
      runtimeRecords.put(appId, runtimeRecord.stopped());
    }
  }

  private static boolean shouldRestart(
      RunningProcess runningProcess, Integer exitCode, boolean explicitStop) {
    AppManifest manifest = runningProcess.snapshot().manifest();
    return !explicitStop
        && isFailureExit(exitCode)
        && manifest.restartPolicy() == AppRestartPolicy.ON_FAILURE
        && runningProcess.currentRestartAttempt() < manifest.restartMaxAttempts();
  }

  private static boolean isFailureExit(Integer exitCode) {
    return exitCode == null || exitCode != 0;
  }

  private boolean recordAutomaticRestartAttempt(String appId, Instant now) {
    Deque<Instant> attempts =
        automaticRestartAttempts.computeIfAbsent(appId, _ -> new ArrayDeque<>());
    synchronized (attempts) {
      pruneRestartAttempts(attempts, now);
      if (attempts.size() >= restartStormMaxInWindow) {
        return false;
      }
      attempts.addLast(now);
      return true;
    }
  }

  private void pruneRestartAttempts(Deque<Instant> attempts, Instant now) {
    Instant earliestRetained = now.minus(restartStormWindow);
    while (!attempts.isEmpty() && attempts.peekFirst().isBefore(earliestRetained)) {
      attempts.removeFirst();
    }
  }

  private AppQuotaWarning restartStormWarning() {
    return AppQuotaWarning.restartStormBlocked(
        restartStormMaxInWindow, restartStormWindow.toMillis());
  }

  private List<String> processLogWarningMessages(InstalledAppPaths paths) {
    return quotaEnforcer
        .enforceProcessLogLimit(paths, AppQuotaPolicy.unlimited())
        .warnings()
        .stream()
        .map(AppQuotaWarning::message)
        .toList();
  }

  private static List<String> restartFailureWarnings(IOException failure) {
    String message = failure.getMessage();
    if (failure instanceof AppBundleVerificationException) {
      return List.of(RESTART_BUNDLE_VERIFICATION_WARNING);
    }
    if (message == null) {
      return List.of();
    }
    if (message.startsWith("app data quota exceeded: ")) {
      return List.of(AppQuotaWarning.dataQuotaExceeded().message());
    }
    if (message.startsWith("app cache quota exceeded: ")) {
      return List.of(AppQuotaWarning.cacheQuotaExceeded().message());
    }
    return List.of();
  }

  private void scheduleRestart(String appId, int restartAttempt, Duration backoff) {
    Thread.ofVirtual()
        .name("apphost-restart-", 0)
        .start(
            () -> {
              try {
                sleepBeforeRestart(backoff);
                restartIfStillScheduled(appId, restartAttempt);
              } catch (InterruptedException _) {
                Thread.currentThread().interrupt();
              }
            });
  }

  private static void sleepBeforeRestart(Duration backoff) throws InterruptedException {
    long sleepMillis = restartBackoffSleepMillis(backoff);
    if (sleepMillis == 0L) {
      return;
    }
    TimeUnit.MILLISECONDS.sleep(sleepMillis);
  }

  static long restartBackoffSleepMillis(Duration backoff) {
    if (backoff.isZero() || backoff.isNegative()) {
      return 0L;
    }
    try {
      return backoff.toMillis();
    } catch (ArithmeticException _) {
      return Long.MAX_VALUE;
    }
  }

  private synchronized void restartIfStillScheduled(String appId, int restartAttempt) {
    RuntimeRecord scheduledRecord = runtimeRecords.get(appId);
    if (scheduledRecord == null
        || scheduledRecord.state() != AppRuntimeState.RESTARTING
        || scheduledRecord.currentRestartAttempt() != restartAttempt) {
      return;
    }
    if (explicitStopRequests.contains(appId)) {
      runtimeRecords.put(appId, scheduledRecord.stopped());
      return;
    }
    if (liveRunningProcess(appId) != null) {
      return;
    }
    try {
      InstalledAppSnapshot installation =
          describe(appId).orElseThrow(() -> new AppHostException(APP_NOT_INSTALLED_PREFIX + appId));
      launchInstalledApp(installation, restartAttempt, restartAttempt);
    } catch (IOException e) {
      recordRestartLaunchFailureIfUnchanged(appId, scheduledRecord, Instant.now(), e);
    }
  }

  private void recordRestartLaunchFailureIfUnchanged(
      String appId, RuntimeRecord scheduledRecord, Instant failedAt, IOException failure) {
    if (scheduledRecord.equals(runtimeRecords.get(appId))) {
      runtimeRecords.put(
          appId,
          scheduledRecord.failedRestart(
              failedAt,
              restartFailureWarnings(failure),
              sandboxStatusAfterLaunchFailure(scheduledRecord, failure)));
    }
  }

  private void recordSandboxLaunchRejection(
      String appId,
      InstalledAppPaths paths,
      int currentRestartAttempt,
      AppSandboxStatus sandboxStatus) {
    if (hasScheduledRestartRecord(appId, currentRestartAttempt)) {
      return;
    }
    runtimeRecords.put(appId, RuntimeRecord.stopped(paths, sandboxStatus));
  }

  private boolean hasScheduledRestartRecord(String appId, int currentRestartAttempt) {
    if (currentRestartAttempt <= 0) {
      return false;
    }
    RuntimeRecord runtimeRecord = runtimeRecords.get(appId);
    return runtimeRecord != null
        && runtimeRecord.state() == AppRuntimeState.RESTARTING
        && runtimeRecord.currentRestartAttempt() == currentRestartAttempt;
  }

  private static AppSandboxStatus sandboxStatusAfterLaunchFailure(
      RuntimeRecord scheduledRecord, IOException failure) {
    if (failure instanceof AppSandboxException sandboxException) {
      return sandboxException.sandboxStatus().orElse(scheduledRecord.sandboxStatus());
    }
    return scheduledRecord.sandboxStatus();
  }

  private static Path normalizeExistingDirectory(Path directory) throws IOException {
    Objects.requireNonNull(directory, "stagedAppDirectory");
    Path normalized = directory.toAbsolutePath().normalize();
    if (!Files.isDirectory(normalized)) {
      throw new AppHostException("stagedAppDirectory must be an existing directory: " + normalized);
    }
    if (Files.isSymbolicLink(normalized) || isAliasedPathEntry(normalized)) {
      throw new AppHostException(
          "stagedAppDirectory must not be a symlink, reparse point, or alias: " + normalized);
    }
    return normalized;
  }

  private static void rejectOverlappingInstallTree(Path stagingRoot, Path installedAppsDir)
      throws IOException {
    if (pathsOverlap(stagingRoot, installedAppsDir)) {
      throw new AppHostException(
          "stagedAppDirectory must not overlap the installed app tree: " + stagingRoot);
    }
  }

  private static void rejectOverlappingRollbackTree(Path stagingRoot, Path rollbackAppsDir)
      throws IOException {
    if (pathsOverlap(stagingRoot, rollbackAppsDir)) {
      throw new AppHostException(
          "stagedAppDirectory must not overlap the rollback app tree: " + stagingRoot);
    }
  }

  private static void rejectOverlappingMutableAppDirectories(
      Path stagingRoot, InstalledAppPaths paths) throws IOException {
    rejectOverlappingManagedAppDirectory(stagingRoot, paths.dataDir(), "dataDir");
    rejectOverlappingManagedAppDirectory(stagingRoot, paths.cacheDir(), "cacheDir");
    rejectOverlappingManagedAppDirectory(stagingRoot, paths.runDir(), "runDir");
  }

  private static void rejectOverlappingManagedAppDirectory(
      Path stagingRoot, Path managedDirectory, String label) throws IOException {
    if (pathsOverlap(stagingRoot, managedDirectory)) {
      throw new AppHostException(
          "stagedAppDirectory must not overlap " + label + ": " + stagingRoot);
    }
  }

  private static boolean pathsOverlap(Path firstPath, Path secondPath) throws IOException {
    Path firstComparablePath = comparablePath(firstPath);
    Path secondComparablePath = comparablePath(secondPath);
    return firstComparablePath.startsWith(secondComparablePath)
        || secondComparablePath.startsWith(firstComparablePath);
  }

  private static void ensureManagedDirectory(Path baseDirectory, Path directory, String label)
      throws IOException {
    Path normalized = directory.toAbsolutePath().normalize();
    validateManagedPathPrefixes(baseDirectory, normalized, label);
    Deque<Path> missingSegments = new ArrayDeque<>();
    Path current = normalized;
    while (current != null && !Files.exists(current, LinkOption.NOFOLLOW_LINKS)) {
      Path fileName = current.getFileName();
      if (fileName != null) {
        missingSegments.push(fileName);
      }
      current = current.getParent();
    }
    if (current == null) {
      throw new AppHostException(label + " must resolve beneath an existing filesystem root");
    }
    validateManagedDirectoryEntry(current, label);
    while (!missingSegments.isEmpty()) {
      current = current.resolve(missingSegments.pop());
      Files.createDirectory(current);
    }
    validateManagedDirectoryEntry(normalized, label);
    if (!Files.isDirectory(normalized, LinkOption.NOFOLLOW_LINKS)) {
      throw new AppHostException(label + " must be a directory: " + normalized);
    }
  }

  private Path validateInstalledAppsDirectory() throws IOException {
    return validateManagedDirectory(layout.installedAppsDir(), INSTALLED_APPS_DIR_LABEL);
  }

  private Path ensureRollbackAppsDirectory() throws IOException {
    Path rollbackAppsDir = layout.rollbackAppsDir().toAbsolutePath().normalize();
    ensureManagedDirectory(layout.dataDir(), rollbackAppsDir, ROLLBACK_APPS_DIR_LABEL);
    return rollbackAppsDir;
  }

  private Path validateRollbackAppsDirectory() throws IOException {
    return validateManagedDirectory(layout.rollbackAppsDir(), ROLLBACK_APPS_DIR_LABEL);
  }

  private Path validateManagedDirectory(Path directory, String label) throws IOException {
    Path normalized = directory.toAbsolutePath().normalize();
    validateManagedPathPrefixes(layout.dataDir(), normalized, label);
    if (!Files.exists(normalized, LinkOption.NOFOLLOW_LINKS)) {
      return normalized;
    }
    validateManagedDirectoryEntry(normalized, label);
    if (!Files.isDirectory(normalized, LinkOption.NOFOLLOW_LINKS)) {
      throw new AppHostException(label + " must be a directory: " + normalized);
    }
    return normalized;
  }

  private static void validateManagedDirectoryEntry(Path entry, String label) throws IOException {
    if (Files.exists(entry, LinkOption.NOFOLLOW_LINKS)
        && (Files.isSymbolicLink(entry) || isAliasedPathEntry(entry))) {
      throw new AppHostException(
          label + " must not be a symlink, reparse point, or alias: " + entry);
    }
  }

  private void validateManagedMutableDirectories(InstalledAppPaths paths) throws IOException {
    validateManagedPathPrefixes(layout.dataDir(), paths.dataDir(), "dataDir");
    validateManagedPathPrefixes(layout.cacheDir(), paths.cacheDir(), "cacheDir");
    validateManagedPathPrefixes(layout.runDir(), paths.runDir(), "runDir");
  }

  private static void validateManagedPathPrefixes(Path baseDirectory, Path target, String label)
      throws IOException {
    Path normalizedBase = baseDirectory.toAbsolutePath().normalize();
    Path normalizedTarget = target.toAbsolutePath().normalize();
    if (!normalizedTarget.startsWith(normalizedBase)) {
      throw new AppHostException(label + " must stay under the managed base directory");
    }
    Path current = normalizedBase;
    if (Files.exists(current, LinkOption.NOFOLLOW_LINKS)) {
      validateManagedDirectoryEntry(current, label);
    }
    for (Path segment : normalizedBase.relativize(normalizedTarget)) {
      current = current.resolve(segment);
      if (!Files.exists(current, LinkOption.NOFOLLOW_LINKS)) {
        break;
      }
      validateManagedDirectoryEntry(current, label);
    }
  }

  private static boolean shouldSkipInstalledEntry(Path appRoot) {
    if (!Files.isDirectory(appRoot, LinkOption.NOFOLLOW_LINKS)) {
      return true;
    }
    if (isTemporaryInstallDirectory(appRoot)) {
      return true;
    }
    return !Files.isRegularFile(
        appRoot.resolve(AppManifestParser.MANIFEST_FILE_NAME), LinkOption.NOFOLLOW_LINKS);
  }

  private static boolean isTemporaryInstallDirectory(Path appRoot) {
    return fileNameText(appRoot).startsWith(TEMP_INSTALL_PREFIX);
  }

  private static Path comparablePath(Path path) throws IOException {
    Path normalized = path.toAbsolutePath().normalize();
    Deque<Path> missingSegments = new ArrayDeque<>();
    Path current = normalized;
    while (current != null && !Files.exists(current, LinkOption.NOFOLLOW_LINKS)) {
      Path fileName = current.getFileName();
      if (fileName != null) {
        missingSegments.push(fileName);
      }
      current = current.getParent();
    }
    if (current == null) {
      return normalized;
    }
    Path comparable = current.toRealPath();
    while (!missingSegments.isEmpty()) {
      comparable = comparable.resolve(missingSegments.pop());
    }
    return comparable.normalize();
  }

  private static Path resolveBundleEntry(Path bundleRoot, Path relativePath, String label)
      throws IOException {
    Path resolvedRoot = bundleRoot.toAbsolutePath().normalize();
    validateBundleEntry(resolvedRoot, label);
    Path current = resolvedRoot;
    for (Path segment : relativePath) {
      current = current.resolve(segment).normalize();
      validateBundleEntry(current, label);
    }
    return current;
  }

  private static void validateBundleEntry(Path entry, String label) throws IOException {
    if (Files.exists(entry, LinkOption.NOFOLLOW_LINKS)
        && (Files.isSymbolicLink(entry) || isAliasedPathEntry(entry))) {
      throw new AppHostException(
          label + " must not resolve through symlinks or reparse points: " + entry);
    }
  }

  private String generateToken() {
    byte[] tokenBytes = new byte[TOKEN_BYTES];
    secureRandom.nextBytes(tokenBytes);
    return HexFormat.of().formatHex(tokenBytes);
  }

  private List<ProcessHandle> observeStartupProcessTree(Process process, String appId)
      throws AppHostException {
    ProcessHandle rootHandle = process.toHandle();
    List<ProcessHandle> observedHandles = new ArrayList<>();
    long deadline = System.nanoTime() + timing.startupExitGracePeriod().toNanos();
    long captureDeadline = System.nanoTime() + timing.startupProcessCaptureWindow().toNanos();
    long handoffDeadline =
        captureDeadline + timing.startupPostCaptureHandoffGracePeriod().toNanos();
    while (System.nanoTime() < deadline) {
      observedHandles.addAll(snapshotProcessTree(startupSeedHandles(rootHandle, observedHandles)));
      long now = System.nanoTime();
      if (shouldStopStartupObservation(rootHandle, now, handoffDeadline)) {
        break;
      }
      waitForStartupObservation(process, appId, deadline, captureDeadline, now);
    }
    capturePostExitProcessTree(rootHandle, observedHandles, appId);
    observedHandles.addAll(snapshotProcessTree(List.of(rootHandle)));
    return aliveHandles(observedHandles);
  }

  private static boolean shouldStopStartupObservation(
      ProcessHandle rootHandle, long now, long handoffDeadline) {
    return !rootHandle.isAlive() || now >= handoffDeadline;
  }

  private void waitForStartupObservation(
      Process process, String appId, long deadline, long captureDeadline, long now)
      throws AppHostException {
    long remainingNanos = deadline - now;
    if (remainingNanos <= 0L) {
      return;
    }
    long pollIntervalNanos =
        now >= captureDeadline
            ? timing.startupHandoffPollInterval().toNanos()
            : timing.startupProcessPollInterval().toNanos();
    waitForProcess(process, Math.min(remainingNanos, pollIntervalNanos), appId);
  }

  private void waitForProcess(Process process, long timeoutNanos, String appId)
      throws AppHostException {
    try {
      process.waitFor(timeoutNanos, TimeUnit.NANOSECONDS);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new AppHostException("interrupted while starting app: " + appId, e);
    }
  }

  private static void waitForProcessExit(Process process, Duration timeout)
      throws InterruptedException {
    process.waitFor(timeout.toNanos(), TimeUnit.NANOSECONDS);
  }

  private static void discardChildInput(Process process, String appId) throws IOException {
    try {
      process.getOutputStream().close();
    } catch (IOException e) {
      process.destroyForcibly();
      throw new AppHostException("failed to close stdin for app: " + appId, e);
    }
  }

  private static AppHostException startupFailure(String appId, Process process) {
    return new AppHostException(
        "app exited during startup: " + appId + " (exitCode=" + process.exitValue() + ")");
  }

  private void startTrackedProcessTreeObserver(
      String appId, Process process, CompletableFuture<Void> exitCleanup) {
    Thread.ofVirtual()
        .name("apphost-process-observer-", 0)
        .start(
            () -> {
              try {
                observeTrackedProcessTreeUntilExit(appId, process);
              } finally {
                try {
                  recordObservedProcessExit(appId, process);
                } finally {
                  exitCleanup.complete(null);
                }
              }
            });
  }

  private List<ProcessHandle> recoverStartupProcessTree(
      InstalledAppSnapshot installation, String token, Instant startedAt, Process process)
      throws AppHostException {
    long deadline = System.nanoTime() + timing.trackedProcessPostExitCaptureGracePeriod().toNanos();
    while (true) {
      List<ProcessHandle> recoveredHandles =
          aliveHandles(
              recoverTrackedProcesses(
                  installation.manifest(),
                  installation.paths(),
                  token,
                  startedAt,
                  List.of(process.toHandle()),
                  ProcessHandle.allProcesses().toList()));
      if (!recoveredHandles.isEmpty() || System.nanoTime() >= deadline) {
        return recoveredHandles;
      }
      try {
        TimeUnit.NANOSECONDS.sleep(timing.startupProcessPollInterval().toNanos());
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        throw new AppHostException("interrupted while starting app: " + installation.appId(), e);
      }
    }
  }

  private void recordObservedProcessExit(String appId, Process process) {
    runningApps.computeIfPresent(
        appId,
        (ignoredAppId, runningProcess) -> {
          if (runningProcess.process() != process || runningProcess.isAlive()) {
            return runningProcess;
          }
          recordExitAndScheduleRestartIfNeeded(appId, runningProcess);
          return null;
        });
  }

  private void observeTrackedProcessTreeUntilExit(String appId, Process process) {
    long startupTrackingDeadline = System.nanoTime() + timing.startupExitGracePeriod().toNanos();
    try {
      while (true) {
        refreshObservedProcessTree(appId, process);
        boolean exited =
            process.waitFor(
                trackedProcessRefreshIntervalNanos(startupTrackingDeadline), TimeUnit.NANOSECONDS);
        if (exited) {
          capturePostExitProcessTreeHandoff(appId, process);
          observeTrackedHandoffProcessTreeUntilExit(appId, process);
          break;
        }
      }
    } catch (InterruptedException _) {
      Thread.currentThread().interrupt();
    } finally {
      refreshObservedProcessTree(appId, process);
    }
  }

  private void observeTrackedHandoffProcessTreeUntilExit(String appId, Process process)
      throws InterruptedException {
    while (observedProcessTreeStillAlive(appId, process)) {
      TimeUnit.NANOSECONDS.sleep(timing.trackedProcessRefreshInterval().toNanos());
      refreshObservedProcessTree(appId, process);
    }
  }

  private boolean observedProcessTreeStillAlive(String appId, Process process) {
    RunningProcess runningProcess = runningApps.get(appId);
    return runningProcess != null
        && runningProcess.process() == process
        && runningProcess.isAlive();
  }

  private void capturePostExitProcessTreeHandoff(String appId, Process process)
      throws InterruptedException {
    long deadline = System.nanoTime() + timing.trackedProcessPostExitCaptureGracePeriod().toNanos();
    while (System.nanoTime() < deadline) {
      refreshObservedProcessTree(appId, process);
      TimeUnit.NANOSECONDS.sleep(timing.startupProcessPollInterval().toNanos());
    }
    TimeUnit.NANOSECONDS.sleep(timing.startupProcessPollInterval().toNanos());
    refreshObservedProcessTree(appId, process);
  }

  private void capturePostExitProcessTree(
      ProcessHandle rootHandle, List<ProcessHandle> observedHandles, String appId)
      throws AppHostException {
    if (rootHandle.isAlive()) {
      return;
    }
    long deadline = System.nanoTime() + timing.trackedProcessPostExitCaptureGracePeriod().toNanos();
    while (System.nanoTime() < deadline) {
      observedHandles.addAll(snapshotProcessTree(startupSeedHandles(rootHandle, observedHandles)));
      try {
        TimeUnit.NANOSECONDS.sleep(timing.startupProcessPollInterval().toNanos());
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        throw new AppHostException("interrupted while starting app: " + appId, e);
      }
    }
  }

  private static List<ProcessHandle> startupSeedHandles(
      ProcessHandle rootHandle, List<ProcessHandle> observedHandles) {
    ArrayList<ProcessHandle> seedHandles = new ArrayList<>(observedHandles.size() + 1);
    seedHandles.add(rootHandle);
    seedHandles.addAll(observedHandles);
    return seedHandles;
  }

  private long trackedProcessRefreshIntervalNanos(long startupTrackingDeadline) {
    if (System.nanoTime() < startupTrackingDeadline) {
      return timing.startupProcessPollInterval().toNanos();
    }
    return timing.trackedProcessRefreshInterval().toNanos();
  }

  private void refreshObservedProcessTree(String appId, Process process) {
    runningApps.computeIfPresent(
        appId,
        (ignoredAppId, activeProcess) -> {
          if (activeProcess.process() != process) {
            return activeProcess;
          }
          RunningProcess refreshed = refreshRunningProcess(activeProcess);
          if (refreshed == null) {
            refreshed = recoverTrackedRunningProcess(activeProcess);
          }
          return refreshed != null ? refreshed : activeProcess;
        });
  }

  static void populateEnvironment(
      Map<String, String> environment,
      AppManifest manifest,
      InstalledAppPaths paths,
      String token,
      AppEnv appEnv) {
    environment.clear();
    populateBaseEnvironment(environment, appEnv);
    environment.put("CRYPTAD_APP_ID", manifest.appId());
    environment.put("CRYPTAD_APP_NAME", manifest.appName());
    environment.put("CRYPTAD_APP_VERSION", manifest.appVersion());
    environment.put("CRYPTAD_APP_DATA_DIR", paths.dataDir().toString());
    environment.put("CRYPTAD_APP_CACHE_DIR", paths.cacheDir().toString());
    environment.put("CRYPTAD_APP_RUN_DIR", paths.runDir().toString());
    environment.put("CRYPTAD_APP_TOKEN", token);
    environment.put("CRYPTAD_APP_PERMISSIONS", manifest.permissionsCsv());
    environment.put("CRYPTAD_APP_UI_MODE", manifest.uiMode().manifestValue());
    if (manifest.uiEntry() != null) {
      environment.put("CRYPTAD_APP_UI_ENTRY", manifest.uiEntry());
    }
  }

  private static void populateBaseEnvironment(Map<String, String> environment, AppEnv appEnv) {
    switch (appEnv.osKind()) {
      case WINDOWS -> populateWindowsBaseEnvironment(environment);
      case MAC, LINUX, OTHER -> environment.put("PATH", safeUnixPath(appEnv));
    }
  }

  private static void populateWindowsBaseEnvironment(Map<String, String> environment) {
    String systemRoot = resolveWindowsRoot();
    environment.put("SystemRoot", systemRoot);
    environment.put("SYSTEMROOT", systemRoot);
    environment.put("WINDIR", systemRoot);
    environment.put("ComSpec", windowsCommandInterpreter());
    environment.put("COMSPEC", windowsCommandInterpreter());
    environment.put(
        "PATH",
        String.join(
            ";",
            Path.of(systemRoot, WINDOWS_SYSTEM32_DIRECTORY).toString(),
            Path.of(systemRoot, WINDOWS_SYSTEM32_DIRECTORY, "WindowsPowerShell", "v1.0").toString(),
            systemRoot));
    copyHostEnvironmentValue(environment, "TEMP");
    copyHostEnvironmentValue(environment, "TMP");
  }

  static List<String> launchCommand(Path executable, AppEnv appEnv) throws IOException {
    return launchCommand(executable, appEnv, DEFAULT_TIMING);
  }

  private List<String> launchCommand(Path executable) throws IOException {
    return launchCommand(executable, appEnv, timing);
  }

  private static List<String> launchCommand(Path executable, AppEnv appEnv, TimingConfig timing)
      throws IOException {
    String executableText = executable.toString();
    if (appEnv.isWindows() && isWindowsBatchScript(executable)) {
      return List.of(
          windowsCommandInterpreter(), "/d", "/c", quoteWindowsBatchCommand(executableText));
    }
    if (!appEnv.isWindows()) {
      PosixLauncher posixLauncher = classifyPosixLauncher(executable);
      if (posixLauncher != null) {
        return posixLauncher.command(executable, timing);
      }
    }
    return List.of(executableText);
  }

  private static boolean isWindowsBatchScript(Path executable) {
    String fileName = fileNameLowercase(executable);
    return fileName.endsWith(".cmd") || fileName.endsWith(".bat");
  }

  private static boolean isLaunchableWindowsExecutable(Path executable) throws IOException {
    return isWindowsBatchScript(executable)
        || hasWindowsComExecutableSuffix(executable)
        || hasLaunchablePortableExecutable(executable);
  }

  private static boolean hasWindowsComExecutableSuffix(Path executable) {
    String fileName = fileNameLowercase(executable);
    return fileName.endsWith(".com");
  }

  private static boolean hasLaunchablePortableExecutable(Path executable) throws IOException {
    try (SeekableByteChannel channel = Files.newByteChannel(executable)) {
      if (channel.size() < DOS_HEADER_SIZE) {
        return false;
      }
      ByteBuffer dosHeader = ByteBuffer.allocate(DOS_HEADER_SIZE).order(ByteOrder.LITTLE_ENDIAN);
      if (channel.read(dosHeader) < DOS_HEADER_SIZE) {
        return false;
      }
      dosHeader.flip();
      if (dosHeader.get() != 'M' || dosHeader.get() != 'Z') {
        return false;
      }

      int peHeaderOffset = dosHeader.getInt(PE_POINTER_OFFSET);
      if (peHeaderOffset < DOS_HEADER_SIZE
          || channel.size() < (long) peHeaderOffset + COFF_HEADER_SIZE) {
        return false;
      }

      ByteBuffer coffHeader = ByteBuffer.allocate(COFF_HEADER_SIZE).order(ByteOrder.LITTLE_ENDIAN);
      channel.position(peHeaderOffset);
      if (channel.read(coffHeader) < COFF_HEADER_SIZE) {
        return false;
      }
      coffHeader.flip();
      if (coffHeader.get() != 'P'
          || coffHeader.get() != 'E'
          || coffHeader.get() != 0
          || coffHeader.get() != 0) {
        return false;
      }
      coffHeader.position(22);
      int characteristics = Short.toUnsignedInt(coffHeader.getShort());
      return (characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) != 0
          && (characteristics & IMAGE_FILE_DLL) == 0;
    }
  }

  private static String quoteWindowsBatchCommand(String executableText) {
    return "\"" + executableText + "\"";
  }

  private static boolean hasPosixShellScriptSuffix(Path executable) {
    String fileName = fileNameLowercase(executable);
    return fileName.endsWith(".sh");
  }

  private static PosixLauncher classifyPosixLauncher(Path executable) throws IOException {
    String shebang = readShebang(executable);
    if (shebang.isBlank()) {
      return hasPosixShellScriptSuffix(executable)
          ? new PosixLauncher(List.of(posixShellInterpreter()), true)
          : null;
    }
    List<String> interpreter = parseShebangInterpreter(shebang);
    return new PosixLauncher(interpreter, isPosixShellInterpreter(interpreter));
  }

  private static String readShebang(Path executable) throws IOException {
    try (var input = Files.newInputStream(executable)) {
      if (input.read() != '#' || input.read() != '!') {
        return "";
      }
      var shebangBytes = new ByteArrayOutputStream();
      for (int bytesRead = 2; bytesRead < MAX_SHEBANG_PROBE_BYTES; bytesRead++) {
        int nextByte = input.read();
        if (nextByte < 0 || nextByte == '\n' || nextByte == '\r') {
          break;
        }
        shebangBytes.write(nextByte);
      }
      return shebangBytes.toString(StandardCharsets.UTF_8).trim();
    }
  }

  private static List<String> parseShebangInterpreter(String shebang) throws AppHostException {
    int argumentOffset = firstWhitespaceOffset(shebang);
    if (argumentOffset < 0) {
      validateShebangInterpreter(shebang);
      return List.of(shebang);
    }
    String interpreter = shebang.substring(0, argumentOffset);
    validateShebangInterpreter(interpreter);
    String interpreterArgument = shebang.substring(argumentOffset).trim();
    if (interpreterArgument.isEmpty()) {
      return List.of(interpreter);
    }
    return List.of(interpreter, interpreterArgument);
  }

  private static boolean isInterpreterManagedPosixLauncher(Path executable) throws IOException {
    return classifyPosixLauncher(executable) != null;
  }

  private static boolean isPosixShellInterpreter(List<String> interpreter) {
    if (interpreter.isEmpty()) {
      return false;
    }
    String interpreterName = commandBasename(interpreter.getFirst());
    if (isKnownPosixShellName(interpreterName)) {
      return true;
    }
    if (!interpreterName.equals("env") || interpreter.size() < 2) {
      return false;
    }
    return envInvokesPosixShell(interpreter.get(1));
  }

  private static boolean envInvokesPosixShell(String argumentText) {
    String trimmed = argumentText.trim();
    if (trimmed.isEmpty()) {
      return false;
    }
    if (trimmed.startsWith("-S ")) {
      trimmed = trimmed.substring(3).trim();
    }
    return isKnownPosixShellName(commandBasename(firstToken(trimmed)));
  }

  private static boolean isKnownPosixShellName(String commandName) {
    return switch (commandName) {
      case "sh", "ash", "bash", "dash", "ksh", "mksh", "zsh" -> true;
      default -> false;
    };
  }

  private static String firstToken(String text) {
    int offset = firstWhitespaceOffset(text);
    return offset < 0 ? text : text.substring(0, offset);
  }

  private static void validateShebangInterpreter(String interpreter) throws AppHostException {
    if (commandBasename(interpreter).isEmpty()) {
      throw new AppHostException("invalid shebang interpreter: " + interpreter);
    }
  }

  private static String commandBasename(String command) {
    if (command.isBlank()) {
      return "";
    }
    Path fileName = Path.of(command).getFileName();
    if (fileName == null) {
      return "";
    }
    return fileName.toString().toLowerCase(Locale.ROOT);
  }

  private static String fileNameLowercase(Path path) {
    return fileNameText(path).toLowerCase(Locale.ROOT);
  }

  private static String fileNameText(Path path) {
    Path fileName = path.getFileName();
    return fileName == null ? "" : fileName.toString();
  }

  private static String installedDirectoryNameOrThrow(Path path) throws AppHostException {
    String fileName = fileNameText(path);
    if (fileName.isEmpty()) {
      throw new AppHostException("installed manifest root must not be a filesystem root: " + path);
    }
    return fileName;
  }

  private static int firstWhitespaceOffset(String text) {
    for (int i = 0; i < text.length(); i++) {
      if (Character.isWhitespace(text.charAt(i))) {
        return i;
      }
    }
    return -1;
  }

  private static String posixShellInterpreter() {
    return Path.of("/bin", "sh").toString();
  }

  private static String windowsCommandInterpreter() {
    return Path.of(resolveWindowsRoot(), WINDOWS_SYSTEM32_DIRECTORY, "cmd.exe").toString();
  }

  private static String safeUnixPath(AppEnv appEnv) {
    ArrayList<String> entries = new ArrayList<>(BASE_UNIX_PATH_ENTRIES);
    switch (appEnv.osKind()) {
      case MAC -> entries.addAll(MAC_UNIX_PATH_ENTRIES);
      case LINUX -> entries.addAll(LINUX_UNIX_PATH_ENTRIES);
      case OTHER -> {
        entries.addAll(MAC_UNIX_PATH_ENTRIES);
        entries.addAll(LINUX_UNIX_PATH_ENTRIES);
      }
      case WINDOWS -> throw new IllegalArgumentException("windows does not use a Unix PATH");
    }
    return String.join(":", entries);
  }

  private static String resolveWindowsRoot() {
    String systemRoot = firstNonBlankWindowsRootEnvironmentValue();
    return systemRoot != null ? systemRoot : "C:\\Windows";
  }

  private static String firstNonBlankWindowsRootEnvironmentValue() {
    for (String name : WINDOWS_ROOT_ENVIRONMENT_NAMES) {
      String value = System.getenv(name);
      if (value != null && !value.isBlank()) {
        return value;
      }
    }
    return null;
  }

  private static void copyHostEnvironmentValue(Map<String, String> environment, String name) {
    String value = System.getenv(name);
    if (value != null && !value.isBlank()) {
      environment.put(name, value);
    }
  }

  private Path temporaryManagedPath(Path parent, String prefix) throws IOException {
    for (int attempt = 0; attempt < 8; attempt++) {
      Path candidate = parent.resolve(prefix + generateToken());
      if (!Files.exists(candidate, LinkOption.NOFOLLOW_LINKS)) {
        return candidate;
      }
    }
    throw new AppHostException("failed to allocate temporary managed path under: " + parent);
  }

  private Path rollbackRootFor(String appId) {
    return layout.rollbackAppsDir().resolve(InstalledAppPaths.normalizeAppId(appId));
  }

  private void ensurePersistentMutationsRecovered() throws IOException {
    if (persistentMutationsRecovered && !catalogOriginRetentionPending) {
      return;
    }
    if (!persistentMutationsRecovered) {
      recoverPersistentMutations();
      persistentMutationsRecovered = true;
    }
    if (catalogOriginRetentionPending) {
      reconcileCatalogOriginRetention();
    }
  }

  private void recoverPersistentMutations() throws IOException {
    Path transactionRoot = layout.appMutationTransactionsDir();
    if (!Files.exists(transactionRoot, LinkOption.NOFOLLOW_LINKS)) {
      return;
    }
    validateManagedDirectory(transactionRoot, MUTATION_TRANSACTIONS_DIR_LABEL);
    try (var entries = Files.list(transactionRoot)) {
      for (Path entry :
          entries.sorted(Comparator.comparing(LocalProcessAppHost::fileNameText)).toList()) {
        recoverPersistentMutationEntry(entry);
      }
    }
  }

  private void recoverPersistentMutationEntry(Path entry) throws IOException {
    String name = fileNameText(entry);
    if (!Files.isDirectory(entry, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(entry)) {
      throw new AppHostException("app mutation transaction entry is unsafe");
    }
    if (name.endsWith(ACTIVE_TRANSACTION_SUFFIX)) {
      recoverActiveMutation(entry);
    } else if (name.startsWith(COMMITTED_TRANSACTION_PREFIX)
        || name.startsWith(PREPARING_TRANSACTION_PREFIX)) {
      deleteRecursively(entry);
    } else {
      throw new AppHostException("unknown app mutation transaction entry");
    }
  }

  private PersistentMutation beginPersistentMutation(
      String appId, PersistentMutationOperation operation, FileInstalledAppOriginStore.State before)
      throws IOException {
    ensurePersistentMutationsRecovered();
    String normalizedAppId = InstalledAppPaths.normalizeAppId(appId);
    Path transactionRoot = layout.appMutationTransactionsDir();
    ensureManagedDirectory(layout.dataDir(), transactionRoot, MUTATION_TRANSACTIONS_DIR_LABEL);
    Path active = transactionRoot.resolve(normalizedAppId + ACTIVE_TRANSACTION_SUFFIX);
    if (Files.exists(active, LinkOption.NOFOLLOW_LINKS)) {
      throw new AppHostException("app mutation transaction is already active");
    }
    Path preparing =
        Files.createTempDirectory(
            transactionRoot, PREPARING_TRANSACTION_PREFIX + normalizedAppId + "-");
    boolean currentPresent = false;
    boolean rollbackPresent = false;
    try {
      Path current = layout.pathsFor(normalizedAppId).installedRoot();
      if (Files.isDirectory(current, LinkOption.NOFOLLOW_LINKS)) {
        currentPresent = true;
        Path backup = preparing.resolve(TRANSACTION_CURRENT_BACKUP);
        Files.createDirectory(backup);
        copyDirectoryTree(current, backup);
      }
      Path rollback = rollbackRootFor(normalizedAppId);
      if (Files.isDirectory(rollback, LinkOption.NOFOLLOW_LINKS)) {
        rollbackPresent = true;
        Path backup = preparing.resolve(TRANSACTION_ROLLBACK_BACKUP);
        Files.createDirectory(backup);
        copyDirectoryTree(rollback, backup);
      }
      new FileInstalledAppOriginStore(preparing.resolve(TRANSACTION_ORIGIN_BACKUP))
          .restore(normalizedAppId, before);
      PersistentMutationRecord mutationRecord =
          new PersistentMutationRecord(
              normalizedAppId,
              operation,
              currentPresent,
              rollbackPresent,
              before.current().isPresent(),
              before.rollback().isPresent());
      Files.writeString(
          preparing.resolve(TRANSACTION_RECORD_FILE),
          mutationRecord.canonicalText(),
          StandardCharsets.UTF_8,
          StandardOpenOption.CREATE_NEW,
          StandardOpenOption.WRITE);
      moveIntoPlace(preparing, active);
      return new PersistentMutation(active, mutationRecord);
    } catch (IOException | RuntimeException failure) {
      try {
        deleteRecursively(preparing);
      } catch (IOException cleanupFailure) {
        failure.addSuppressed(cleanupFailure);
      }
      throw failure;
    }
  }

  private void commitPersistentMutation(PersistentMutation mutation) throws IOException {
    Path committed =
        mutation
            .activeDirectory()
            .getParent()
            .resolve(
                COMMITTED_TRANSACTION_PREFIX
                    + mutation.mutationRecord().appId()
                    + "-"
                    + generateToken());
    movePersistentMutationCommitIntoPlace(mutation.activeDirectory(), committed);
    try {
      managedTreeDeleter.deleteRecursively(committed);
    } catch (IOException _) {
      persistentMutationsRecovered = false;
      // The atomic rename is the commit point. A later recovery pass safely finishes cleanup.
    }
  }

  private void abortPersistentMutation(PersistentMutation mutation, Throwable failure) {
    try {
      recoverActiveMutation(mutation.activeDirectory());
    } catch (IOException recoveryFailure) {
      persistentMutationsRecovered = false;
      failure.addSuppressed(recoveryFailure);
    }
  }

  private void abortPersistentMutationAndReconcile(PersistentMutation mutation, Throwable failure) {
    abortPersistentMutation(mutation, failure);
    catalogOriginRetentionPending = true;
    if (Files.exists(mutation.activeDirectory(), LinkOption.NOFOLLOW_LINKS)) {
      return;
    }
    try {
      reconcileCatalogOriginRetention();
    } catch (IOException | RuntimeException reconciliationFailure) {
      failure.addSuppressed(reconciliationFailure);
    }
  }

  private void retainCatalogOriginRevisions() throws IOException {
    catalogOriginRetention.retain(retainedCatalogOrigins());
  }

  private void finishCatalogOriginRetention() {
    catalogOriginRetentionPending = true;
    try {
      reconcileCatalogOriginRetention();
    } catch (IOException | RuntimeException _) {
      // Live origins are already retained. Retry stale-pin cleanup before later persistent work.
    }
  }

  private void reconcileCatalogOriginRetention() throws IOException {
    catalogOriginRetentionPending = true;
    catalogOriginRetention.reconcile(retainedCatalogOrigins());
    catalogOriginRetentionPending = false;
  }

  private List<InstalledAppOrigin> retainedCatalogOrigins() throws IOException {
    return originStore.snapshotAll().values().stream()
        .flatMap(
            state ->
                java.util.stream.Stream.concat(state.current().stream(), state.rollback().stream()))
        .toList();
  }

  private void recoverActiveMutation(Path activeDirectory) throws IOException {
    PersistentMutationRecord mutationRecord = readPersistentMutationRecord(activeDirectory);
    String expectedName = mutationRecord.appId() + ACTIVE_TRANSACTION_SUFFIX;
    if (!expectedName.equals(fileNameText(activeDirectory))) {
      throw new AppHostException("app mutation transaction identity does not match directory");
    }
    FileInstalledAppOriginStore.State before =
        new FileInstalledAppOriginStore(activeDirectory.resolve(TRANSACTION_ORIGIN_BACKUP))
            .snapshot(mutationRecord.appId());
    if (before.current().isPresent() != mutationRecord.currentOriginPresent()
        || before.rollback().isPresent() != mutationRecord.rollbackOriginPresent()) {
      throw new AppHostException("app mutation transaction origin snapshot is incomplete");
    }
    restoreBundleSlot(
        activeDirectory.resolve(TRANSACTION_CURRENT_BACKUP),
        layout.pathsFor(mutationRecord.appId()).installedRoot(),
        mutationRecord.currentBundlePresent());
    restoreBundleSlot(
        activeDirectory.resolve(TRANSACTION_ROLLBACK_BACKUP),
        rollbackRootFor(mutationRecord.appId()),
        mutationRecord.rollbackBundlePresent());
    originStore.restore(mutationRecord.appId(), before);
    deleteRecursively(activeDirectory);
  }

  private void restoreBundleSlot(Path backup, Path canonical, boolean expectedPresent)
      throws IOException {
    Path parent = canonical.getParent();
    if (parent == null) {
      throw new AppHostException("app mutation bundle slot has no managed parent");
    }
    ensureManagedDirectory(layout.dataDir(), parent, "appMutationBundleParent");
    if (!expectedPresent) {
      if (Files.exists(backup, LinkOption.NOFOLLOW_LINKS)) {
        throw new AppHostException("unexpected app mutation bundle backup");
      }
      deleteScratchTreeIfPresent(canonical);
      return;
    }
    if (!Files.isDirectory(backup, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(backup)) {
      throw new AppHostException("required app mutation bundle backup is missing");
    }
    Path restored = Files.createTempDirectory(parent, TEMP_INSTALL_PREFIX + "recovery-");
    try {
      copyDirectoryTree(backup, restored);
      deleteScratchTreeIfPresent(canonical);
      moveIntoPlace(restored, canonical);
    } catch (IOException | RuntimeException failure) {
      deleteScratchTreeIfPresent(restored);
      throw failure;
    }
  }

  private static PersistentMutationRecord readPersistentMutationRecord(Path activeDirectory)
      throws IOException {
    Path recordPath = activeDirectory.resolve(TRANSACTION_RECORD_FILE);
    if (!Files.isRegularFile(recordPath, LinkOption.NOFOLLOW_LINKS)
        || Files.isSymbolicLink(recordPath)
        || Files.size(recordPath) > 4096) {
      throw new AppHostException("app mutation transaction record is unsafe");
    }
    LinkedHashMap<String, String> fields = new LinkedHashMap<>();
    for (String line : Files.readAllLines(recordPath, StandardCharsets.UTF_8)) {
      int separator = line.indexOf('=');
      if (separator <= 0 || line.indexOf('=', separator + 1) >= 0) {
        throw new AppHostException("invalid app mutation transaction record");
      }
      if (fields.putIfAbsent(line.substring(0, separator), line.substring(separator + 1)) != null) {
        throw new AppHostException("duplicate app mutation transaction property");
      }
    }
    try {
      int schemaVersion = Integer.parseInt(removeTransactionField(fields, "schemaVersion"));
      if (schemaVersion != 1) {
        throw new AppHostException("unsupported app mutation transaction schema version");
      }
      PersistentMutationRecord mutationRecord =
          new PersistentMutationRecord(
              removeTransactionField(fields, "appId"),
              PersistentMutationOperation.valueOf(
                  removeTransactionField(fields, "operation").toUpperCase(Locale.ROOT)),
              parseTransactionBoolean(fields, "currentBundlePresent"),
              parseTransactionBoolean(fields, "rollbackBundlePresent"),
              parseTransactionBoolean(fields, "currentOriginPresent"),
              parseTransactionBoolean(fields, "rollbackOriginPresent"));
      if (!fields.isEmpty()) {
        throw new AppHostException("unsupported app mutation transaction property");
      }
      return mutationRecord;
    } catch (IllegalArgumentException exception) {
      throw new AppHostException("invalid app mutation transaction record", exception);
    }
  }

  private static boolean parseTransactionBoolean(Map<String, String> fields, String name)
      throws AppHostException {
    String value = removeTransactionField(fields, name);
    if (!"true".equals(value) && !"false".equals(value)) {
      throw new AppHostException("invalid app mutation transaction boolean");
    }
    return Boolean.parseBoolean(value);
  }

  private static String removeTransactionField(Map<String, String> fields, String name)
      throws AppHostException {
    String value = fields.remove(name);
    if (value == null) {
      throw new AppHostException("missing app mutation transaction property");
    }
    return value;
  }

  private enum PersistentMutationOperation {
    CATALOG_INSTALL,
    CATALOG_UPDATE,
    GENERIC_UPDATE,
    ROLLBACK,
    UNINSTALL
  }

  private record PersistentMutation(
      Path activeDirectory, PersistentMutationRecord mutationRecord) {}

  private record PreparedUpdateBundle(
      String normalizedAppId,
      Path replacementRoot,
      AppManifest manifest,
      InstalledAppPaths paths,
      Path backupInstallRoot,
      Path rollbackRoot,
      Path previousRollbackBackupRoot) {}

  private record PersistentMutationRecord(
      String appId,
      PersistentMutationOperation operation,
      boolean currentBundlePresent,
      boolean rollbackBundlePresent,
      boolean currentOriginPresent,
      boolean rollbackOriginPresent) {
    private PersistentMutationRecord {
      appId = InstalledAppPaths.normalizeAppId(appId);
      Objects.requireNonNull(operation, "operation");
    }

    private String canonicalText() {
      return "schemaVersion=1\n"
          + "appId="
          + appId
          + '\n'
          + "operation="
          + operation.name().toLowerCase(Locale.ROOT)
          + '\n'
          + "currentBundlePresent="
          + currentBundlePresent
          + '\n'
          + "rollbackBundlePresent="
          + rollbackBundlePresent
          + '\n'
          + "currentOriginPresent="
          + currentOriginPresent
          + '\n'
          + "rollbackOriginPresent="
          + rollbackOriginPresent
          + '\n';
    }
  }

  private void deleteRollbackRecordIfPresent(String appId) throws IOException {
    Path rollbackAppsDir = validateRollbackAppsDirectory();
    if (!Files.exists(rollbackAppsDir, LinkOption.NOFOLLOW_LINKS)) {
      return;
    }
    Path rollbackRoot = rollbackRootFor(appId);
    if (Files.exists(rollbackRoot, LinkOption.NOFOLLOW_LINKS)) {
      deleteRecursively(rollbackRoot);
    }
  }

  private void replaceInstalledBundle(
      Path installedRoot,
      Path replacementRoot,
      Path backupRoot,
      Path rollbackRoot,
      Path previousRollbackBackupRoot)
      throws IOException {
    boolean previousRollbackMoved =
        movePreviousRollbackAside(rollbackRoot, previousRollbackBackupRoot);
    boolean installedMoved = false;
    try {
      moveIntoPlace(installedRoot, backupRoot);
      installedMoved = true;
      moveIntoPlace(replacementRoot, installedRoot);
      moveIntoPlace(backupRoot, rollbackRoot);
    } catch (IOException updateFailure) {
      if (installedMoved) {
        restoreInstalledBundle(installedRoot, backupRoot, updateFailure);
      }
      restorePreviousRollback(
          rollbackRoot, previousRollbackBackupRoot, previousRollbackMoved, updateFailure);
      throw updateFailure;
    }
    deleteBackupAfterSuccessfulReplacement(previousRollbackBackupRoot, previousRollbackMoved);
  }

  private void swapInstalledBundleWithRollback(
      Path installedRoot, Path rollbackRoot, Path currentInstallBackupRoot) throws IOException {
    moveIntoPlace(installedRoot, currentInstallBackupRoot);
    boolean rollbackMovedToInstalled = false;
    try {
      moveIntoPlace(rollbackRoot, installedRoot);
      rollbackMovedToInstalled = true;
      moveIntoPlace(currentInstallBackupRoot, rollbackRoot);
    } catch (IOException rollbackFailure) {
      if (rollbackMovedToInstalled) {
        try {
          moveIntoPlace(installedRoot, rollbackRoot);
        } catch (IOException restoreRollbackFailure) {
          rollbackFailure.addSuppressed(restoreRollbackFailure);
        }
      }
      restoreInstalledBundle(installedRoot, currentInstallBackupRoot, rollbackFailure);
      throw rollbackFailure;
    }
  }

  private static boolean movePreviousRollbackAside(Path rollbackRoot, Path backupRoot)
      throws IOException {
    if (!Files.exists(rollbackRoot, LinkOption.NOFOLLOW_LINKS)) {
      return false;
    }
    moveIntoPlace(rollbackRoot, backupRoot);
    return true;
  }

  private void deleteBackupAfterSuccessfulReplacement(Path backupRoot, boolean backupPresent) {
    if (!backupPresent) {
      return;
    }
    try {
      managedTreeDeleter.deleteRecursively(backupRoot);
    } catch (IOException _) {
      // The replacement is already committed; a skipped temp record is safer than a false failure.
    }
  }

  private static void restorePreviousRollback(
      Path rollbackRoot, Path backupRoot, boolean backupPresent, IOException updateFailure) {
    if (!backupPresent) {
      return;
    }
    try {
      deleteScratchTreeIfPresent(rollbackRoot);
    } catch (IOException cleanupFailure) {
      updateFailure.addSuppressed(cleanupFailure);
    }
    try {
      moveIntoPlace(backupRoot, rollbackRoot);
    } catch (IOException restoreFailure) {
      updateFailure.addSuppressed(restoreFailure);
    }
  }

  private static void restoreInstalledBundle(
      Path installedRoot, Path backupRoot, IOException updateFailure) {
    try {
      deleteScratchTreeIfPresent(installedRoot);
    } catch (IOException cleanupFailure) {
      updateFailure.addSuppressed(cleanupFailure);
    }
    try {
      moveIntoPlace(backupRoot, installedRoot);
    } catch (IOException restoreFailure) {
      updateFailure.addSuppressed(restoreFailure);
    }
  }

  private static void moveIntoPlace(Path source, Path destination) throws IOException {
    try {
      Files.move(source, destination, StandardCopyOption.ATOMIC_MOVE);
    } catch (AtomicMoveNotSupportedException _) {
      Files.move(source, destination);
    }
  }

  private static void movePersistentMutationCommitIntoPlace(Path active, Path committed)
      throws IOException {
    Files.move(active, committed, StandardCopyOption.ATOMIC_MOVE);
  }

  private static void copyDirectoryTree(Path sourceRoot, Path targetRoot) throws IOException {
    Path sourceRealRoot = sourceRoot.toRealPath();
    Set<Path> visitedRealDirectories = ConcurrentHashMap.newKeySet();
    Files.walkFileTree(
        sourceRoot,
        new SimpleFileVisitor<>() {
          @Override
          public @NotNull FileVisitResult preVisitDirectory(
              @NotNull Path dir, @NotNull BasicFileAttributes attrs) throws IOException {
            Path realDirectory = validateStagingEntry(sourceRoot, sourceRealRoot, dir);
            if (!visitedRealDirectories.add(realDirectory)) {
              throw new AppHostException(
                  "staging directory must not revisit directories via links or reparse points: "
                      + dir);
            }
            Files.createDirectories(targetRoot.resolve(sourceRoot.relativize(dir)));
            return FileVisitResult.CONTINUE;
          }

          @Override
          public @NotNull FileVisitResult visitFile(
              @NotNull Path file, @NotNull BasicFileAttributes attrs) throws IOException {
            validateStagingEntry(sourceRoot, sourceRealRoot, file);
            if (!attrs.isRegularFile()) {
              throw new AppHostException(
                  "staging directory must contain only regular files: " + file);
            }
            Files.copy(
                file,
                targetRoot.resolve(sourceRoot.relativize(file)),
                StandardCopyOption.COPY_ATTRIBUTES,
                StandardCopyOption.REPLACE_EXISTING);
            return FileVisitResult.CONTINUE;
          }
        });
  }

  private static Path validateStagingEntry(Path sourceRoot, Path sourceRealRoot, Path entry)
      throws IOException {
    if (entry.equals(sourceRoot)) {
      return sourceRealRoot;
    }
    if (Files.isSymbolicLink(entry)) {
      throw new AppHostException("staging directory must not contain symlinks: " + entry);
    }
    Path expectedRealPath = sourceRealRoot.resolve(sourceRoot.relativize(entry)).normalize();
    Path actualRealPath = entry.toRealPath();
    if (!actualRealPath.equals(expectedRealPath)) {
      throw new AppHostException(
          "staging directory must not contain links or reparse points: " + entry);
    }
    return actualRealPath;
  }

  private static void deleteScratchTreeIfPresent(Path root) throws IOException {
    if (!Files.exists(root, LinkOption.NOFOLLOW_LINKS)) {
      return;
    }
    deleteRecursively(root);
  }

  private static void deleteRecursively(Path root) throws IOException {
    if (!Files.exists(root, LinkOption.NOFOLLOW_LINKS)) {
      return;
    }
    Files.walkFileTree(
        root,
        new SimpleFileVisitor<>() {
          @Override
          public @NotNull FileVisitResult preVisitDirectory(
              @NotNull Path dir, @NotNull BasicFileAttributes attrs) throws IOException {
            if (isAliasedPathEntry(dir)) {
              Files.deleteIfExists(dir);
              return FileVisitResult.SKIP_SUBTREE;
            }
            return FileVisitResult.CONTINUE;
          }

          @Override
          public @NotNull FileVisitResult visitFile(
              @NotNull Path file, @NotNull BasicFileAttributes attrs) throws IOException {
            Files.deleteIfExists(file);
            return FileVisitResult.CONTINUE;
          }

          @Override
          public @NotNull FileVisitResult visitFileFailed(
              @NotNull Path file, @NotNull IOException exc) throws IOException {
            if (Files.exists(file, LinkOption.NOFOLLOW_LINKS) && isAliasedPathEntry(file)) {
              Files.deleteIfExists(file);
              return FileVisitResult.CONTINUE;
            }
            throw exc;
          }

          @Override
          public @NotNull FileVisitResult postVisitDirectory(@NotNull Path dir, IOException exc)
              throws IOException {
            if (exc != null) {
              throw exc;
            }
            Files.deleteIfExists(dir);
            return FileVisitResult.CONTINUE;
          }
        });
  }

  private static boolean isAliasedPathEntry(Path entry) throws IOException {
    if (Files.isSymbolicLink(entry)) {
      return true;
    }
    Path parent = entry.getParent();
    if (parent == null) {
      return false;
    }
    Path expectedRealPath = parent.toRealPath().resolve(entry.getFileName()).normalize();
    Path actualRealPath = entry.toRealPath();
    return !actualRealPath.equals(expectedRealPath);
  }

  private static void destroyProcessHandles(List<ProcessHandle> processHandles) {
    for (int i = processHandles.size() - 1; i >= 0; i--) {
      ProcessHandle processHandle = processHandles.get(i);
      if (processHandle.isAlive()) {
        processHandle.destroy();
      }
    }
  }

  private static void destroyProcessHandlesForcibly(List<ProcessHandle> processHandles) {
    for (int i = processHandles.size() - 1; i >= 0; i--) {
      ProcessHandle processHandle = processHandles.get(i);
      if (processHandle.isAlive()) {
        processHandle.destroyForcibly();
      }
    }
  }

  private static void destroyRootProcess(RunningProcess runningProcess) {
    if (runningProcess.process().isAlive()) {
      runningProcess.process().destroy();
    }
  }

  private static void destroyRootProcessForcibly(RunningProcess runningProcess) {
    if (runningProcess.process().isAlive()) {
      runningProcess.process().destroyForcibly();
    }
  }

  private static boolean waitForProcessTreeExit(List<ProcessHandle> processTree, Duration timeout)
      throws InterruptedException {
    long deadline = System.nanoTime() + timeout.toNanos();
    while (System.nanoTime() < deadline) {
      if (aliveHandles(processTree).isEmpty()) {
        return true;
      }
      TimeUnit.MILLISECONDS.sleep(10);
    }
    return aliveHandles(processTree).isEmpty();
  }

  private RunningProcess stopWithEscalation(
      String normalizedAppId, String appId, RunningProcess trackedRunningProcess)
      throws IOException {
    RunningProcess current = trackedRunningProcess;
    try {
      if (destroyDescendantsAndWaitForExit(current, descendantReapGracePeriod())) {
        return current;
      }
      current = refreshTrackedRunningProcess(normalizedAppId, current);
      if (current == null || destroyRootAndWaitForExit(current, stopTimeout)) {
        return current;
      }
      current = refreshTrackedRunningProcess(normalizedAppId, current);
      if (current == null || destroyDescendantsForciblyAndWaitForExit(current, stopTimeout)) {
        return current;
      }
      current = refreshTrackedRunningProcess(normalizedAppId, current);
      if (current == null) {
        return null;
      }
      return destroyRootForciblyAndWaitForExit(normalizedAppId, appId, current);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      boolean preserved = preserveRunningState(normalizedAppId, current);
      if (!preserved) {
        return null;
      }
      throw new AppHostException("interrupted while stopping app: " + appId, e);
    }
  }

  private Duration descendantReapGracePeriod() {
    return stopTimeout.compareTo(timing.descendantReapGracePeriodLimit()) > 0
        ? timing.descendantReapGracePeriodLimit()
        : stopTimeout;
  }

  private static boolean destroyDescendantsAndWaitForExit(
      RunningProcess runningProcess, Duration timeout) throws InterruptedException {
    destroyProcessHandles(descendantHandles(runningProcess));
    return waitForProcessTreeExit(runningProcess.processTree(), timeout);
  }

  private static boolean destroyRootAndWaitForExit(RunningProcess runningProcess, Duration timeout)
      throws InterruptedException {
    destroyRootProcess(runningProcess);
    return waitForProcessTreeExit(runningProcess.processTree(), timeout);
  }

  private static boolean destroyDescendantsForciblyAndWaitForExit(
      RunningProcess runningProcess, Duration timeout) throws InterruptedException {
    destroyProcessHandlesForcibly(descendantHandles(runningProcess));
    return waitForProcessTreeExit(runningProcess.processTree(), timeout);
  }

  private RunningProcess destroyRootForciblyAndWaitForExit(
      String normalizedAppId, String appId, RunningProcess runningProcess)
      throws IOException, InterruptedException {
    destroyRootProcessForcibly(runningProcess);
    waitForProcessExit(runningProcess.process(), stopTimeout);
    if (waitForProcessTreeExit(runningProcess.processTree(), stopTimeout)) {
      return runningProcess;
    }
    boolean preserved = preserveRunningState(normalizedAppId, runningProcess);
    if (!preserved) {
      return null;
    }
    throw new AppHostException("timed out stopping app: " + appId);
  }

  private void completeStop(
      String normalizedAppId, String appId, RunningProcess trackedRunningProcess)
      throws IOException {
    if (awaitTrackedProcessExit(normalizedAppId, appId, trackedRunningProcess) != null) {
      throw new AppHostException("timed out stopping app: " + appId);
    }
    trackedRunningProcess.exitCleanup().join();
    runningApps.remove(normalizedAppId, trackedRunningProcess);
  }

  private RunningProcess awaitTrackedProcessExit(
      String normalizedAppId, String appId, RunningProcess runningProcess) throws IOException {
    long deadline = System.nanoTime() + stopTimeout.toNanos();
    RunningProcess current = runningProcess;
    while (current != null) {
      current = refreshTrackedRunningProcess(normalizedAppId, current);
      if (current == null || System.nanoTime() >= deadline) {
        return current;
      }
      try {
        TimeUnit.NANOSECONDS.sleep(finalStopRefreshIntervalNanos(deadline));
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        boolean preserved = preserveRunningState(normalizedAppId, current);
        if (!preserved) {
          return null;
        }
        throw new AppHostException("interrupted while stopping app: " + appId, e);
      }
    }
    return null;
  }

  private long finalStopRefreshIntervalNanos(long deadline) {
    long remainingNanos = deadline - System.nanoTime();
    if (remainingNanos <= 0) {
      return 0;
    }
    return Math.min(remainingNanos, timing.trackedProcessRefreshInterval().toNanos());
  }

  private boolean preserveRunningState(String appId, RunningProcess runningProcess) {
    RunningProcess refreshedRunningProcess = refreshRunningProcess(runningProcess);
    if (refreshedRunningProcess == null) {
      runningApps.remove(appId, runningProcess);
      return false;
    }
    runningApps.put(appId, refreshedRunningProcess);
    return true;
  }

  private RunningProcess trackRunningProcessForStop(String appId, RunningProcess runningProcess) {
    List<ProcessHandle> processTree = runningProcess.processTree();
    RunningProcess trackedRunningProcess =
        refreshRunningProcessFromTree(runningProcess, processTree);
    if (trackedRunningProcess == null) {
      if (runningApps.remove(appId, runningProcess)) {
        recordProcessExit(
            appId,
            ProcessExitRecord.fromRunningProcess(
                runningProcess,
                trackedAppExitCode(runningProcess),
                Instant.now(),
                true,
                List.of()));
        runningProcess.exitCleanup().join();
      }
      return null;
    }
    runningApps.replace(appId, runningProcess, trackedRunningProcess);
    return trackedRunningProcess;
  }

  private RunningProcess refreshTrackedRunningProcess(String appId, RunningProcess runningProcess) {
    RunningProcess refreshedRunningProcess = refreshRunningProcess(runningProcess);
    if (refreshedRunningProcess == null) {
      refreshedRunningProcess = recoverTrackedRunningProcess(runningProcess);
    }
    if (refreshedRunningProcess != null) {
      runningApps.put(appId, refreshedRunningProcess);
      return refreshedRunningProcess;
    }
    if (runningApps.remove(appId, runningProcess)) {
      recordExitAndScheduleRestartIfNeeded(appId, runningProcess);
      runningProcess.exitCleanup().join();
    }
    return null;
  }

  private static List<ProcessHandle> snapshotProcessTree(List<ProcessHandle> seedHandles) {
    List<ProcessHandle> processTree = new ArrayList<>();
    for (ProcessHandle seedHandle : deduplicateHandles(seedHandles)) {
      processTree.add(seedHandle);
      seedHandle.descendants().forEach(processTree::add);
    }
    return deduplicateHandles(processTree);
  }

  private static List<ProcessHandle> aliveHandles(List<ProcessHandle> processHandles) {
    return deduplicateHandles(
        processHandles.stream().filter(LocalProcessAppHost::isEffectivelyAlive).toList());
  }

  private RunningProcess recoverTrackedRunningProcess(RunningProcess runningProcess) {
    List<ProcessHandle> recoveredHandles =
        new ArrayList<>(
            recoverTrackedProcesses(
                runningProcess.snapshot().manifest(),
                runningProcess.snapshot().paths(),
                runningProcess.snapshot().token(),
                runningProcess.snapshot().startedAt(),
                runningProcess.seedHandles(),
                ProcessHandle.allProcesses().toList()));
    recoveredHandles = aliveHandles(recoveredHandles);
    if (recoveredHandles.isEmpty()) {
      return null;
    }
    return refreshRunningProcessFromTree(runningProcess, recoveredHandles);
  }

  private List<ProcessHandle> recoverTrackedProcesses(
      AppManifest manifest,
      InstalledAppPaths paths,
      String token,
      Instant startedAt,
      List<ProcessHandle> trackedHandles,
      List<ProcessHandle> processCandidates) {
    List<ProcessHandle> recoveredHandles =
        new ArrayList<>(recoverTrackedDescendantProcesses(trackedHandles, processCandidates));
    recoveredHandles.addAll(findTokenTrackedProcesses(token, manifest.appId()));
    if (recoveredHandles.isEmpty() && appEnv.isWindows()) {
      recoveredHandles.addAll(
          recoverWindowsBundleProcesses(
              paths,
              manifest,
              startedAt,
              trackedHandles,
              processCandidates,
              timing.windowsBundleRecoveryWindow()));
    }
    return deduplicateHandles(recoveredHandles);
  }

  static List<ProcessHandle> recoverTrackedDescendantProcesses(
      List<ProcessHandle> trackedHandles, List<ProcessHandle> processCandidates) {
    List<Long> trackedPids =
        deduplicateHandles(trackedHandles).stream().map(ProcessHandle::pid).sorted().toList();
    if (trackedPids.isEmpty()) {
      return List.of();
    }
    Map<Long, List<ProcessHandle>> childrenByParentPid = new LinkedHashMap<>();
    for (ProcessHandle candidate : deduplicateHandles(processCandidates)) {
      if (!isEffectivelyAlive(candidate)) {
        continue;
      }
      candidate
          .parent()
          .ifPresent(
              parent ->
                  childrenByParentPid
                      .computeIfAbsent(parent.pid(), ignoredPid -> new ArrayList<>())
                      .add(candidate));
    }
    Deque<Long> pendingParentPids = new ArrayDeque<>(trackedPids);
    LinkedHashMap<Long, ProcessHandle> recoveredHandlesByPid = new LinkedHashMap<>();
    while (!pendingParentPids.isEmpty()) {
      long parentPid = pendingParentPids.removeFirst();
      for (ProcessHandle child : childrenByParentPid.getOrDefault(parentPid, List.of())) {
        if (recoveredHandlesByPid.putIfAbsent(child.pid(), child) == null) {
          pendingParentPids.addLast(child.pid());
        }
      }
    }
    return recoveredHandlesByPid.values().stream()
        .sorted(Comparator.comparingLong(ProcessHandle::pid))
        .toList();
  }

  static List<ProcessHandle> recoverWindowsBundleProcesses(
      InstalledAppPaths paths,
      AppManifest manifest,
      Instant startedAt,
      List<ProcessHandle> trackedHandles,
      List<ProcessHandle> processCandidates) {
    return recoverWindowsBundleProcesses(
        paths,
        manifest,
        startedAt,
        trackedHandles,
        processCandidates,
        DEFAULT_TIMING.windowsBundleRecoveryWindow());
  }

  private static List<ProcessHandle> recoverWindowsBundleProcesses(
      InstalledAppPaths paths,
      AppManifest manifest,
      Instant startedAt,
      List<ProcessHandle> trackedHandles,
      List<ProcessHandle> processCandidates,
      Duration windowsBundleRecoveryWindow) {
    Path installedRoot = paths.installedRoot().toAbsolutePath().normalize();
    Path executablePath = paths.executablePath(manifest).toAbsolutePath().normalize();
    List<Long> trackedPids =
        deduplicateHandles(trackedHandles).stream().map(ProcessHandle::pid).sorted().toList();
    return deduplicateHandles(
        processCandidates.stream()
            .filter(LocalProcessAppHost::isEffectivelyAlive)
            .filter(processHandle -> !trackedPids.contains(processHandle.pid()))
            .filter(
                processHandle ->
                    startedWithinWindowsRecoveryWindow(
                            processHandle, startedAt, windowsBundleRecoveryWindow)
                        && referencesInstalledBundle(processHandle, installedRoot, executablePath))
            .sorted(Comparator.comparingLong(ProcessHandle::pid))
            .toList());
  }

  private List<ProcessHandle> findTokenTrackedProcesses(String token, String appId) {
    List<ProcessHandle> procMatches = List.of();
    if (supportsProcEnvironmentScan()) {
      procMatches = findTokenTrackedProcessesFromProc(token, appId);
    }
    List<ProcessHandle> psMatches =
        appEnv.isWindows() || !procMatches.isEmpty()
            ? List.of()
            : findTokenTrackedProcessesWithPs(token, appId);
    return mergeTokenTrackedProcesses(procMatches, psMatches, appEnv);
  }

  private static List<ProcessHandle> findTokenTrackedProcessesFromProc(String token, String appId) {
    return ProcessHandle.allProcesses()
        .filter(LocalProcessAppHost::isEffectivelyAlive)
        .filter(processHandle -> hasAppHostToken(processHandle.pid(), token, appId))
        .sorted(Comparator.comparingLong(ProcessHandle::pid))
        .toList();
  }

  static List<ProcessHandle> mergeTokenTrackedProcesses(
      List<ProcessHandle> procMatches, List<ProcessHandle> psMatches, AppEnv appEnv) {
    List<ProcessHandle> deduplicatedProcMatches = deduplicateHandles(procMatches);
    if (!deduplicatedProcMatches.isEmpty() || appEnv.isWindows()) {
      return deduplicatedProcMatches;
    }
    return deduplicateHandles(psMatches);
  }

  private static List<ProcessHandle> findTokenTrackedProcessesWithPs(String token, String appId) {
    String psCommand = resolveTrustedPsCommand();
    if (psCommand == null) {
      return List.of();
    }
    for (List<String> command :
        List.of(
            List.of(psCommand, "eww", "-e", "-o", "pid=", "-o", "command="),
            List.of(psCommand, "eww", "-ax", "-o", "pid=", "-o", "command="))) {
      List<ProcessHandle> processes = findTokenTrackedProcessesWithPsCommand(command, token, appId);
      if (!processes.isEmpty()) {
        return processes;
      }
    }
    return List.of();
  }

  private static List<ProcessHandle> findTokenTrackedProcessesWithPsCommand(
      List<String> command, String token, String appId) {
    Process process;
    try {
      process = new ProcessBuilder(command).redirectErrorStream(true).start();
    } catch (IOException _) {
      return List.of();
    }
    try {
      List<ProcessHandle> processes = parseTokenTrackedProcesses(process, token, appId);
      if (!process.waitFor(5, TimeUnit.SECONDS)) {
        process.destroyForcibly();
        return List.of();
      }
      if (process.exitValue() != 0) {
        return List.of();
      }
      return processes;
    } catch (IOException | InterruptedException e) {
      if (e instanceof InterruptedException) {
        Thread.currentThread().interrupt();
      }
      process.destroyForcibly();
      return List.of();
    }
  }

  private static List<ProcessHandle> parseTokenTrackedProcesses(
      Process process, String token, String appId) throws IOException {
    List<ProcessHandle> processes = new ArrayList<>();
    try (var reader = process.inputReader(StandardCharsets.UTF_8)) {
      String line;
      while ((line = reader.readLine()) != null) {
        String trimmed = line.trim();
        if (trimmed.isEmpty()) {
          continue;
        }
        parsePsProcessHandle(trimmed, token, appId)
            .filter(LocalProcessAppHost::isEffectivelyAlive)
            .ifPresent(processes::add);
      }
    }
    processes.sort(Comparator.comparingLong(ProcessHandle::pid));
    return List.copyOf(processes);
  }

  private static Optional<ProcessHandle> parsePsProcessHandle(
      String line, String token, String appId) {
    int separator = firstWhitespaceOffset(line);
    if (separator < 0) {
      return Optional.empty();
    }
    String pidText = line.substring(0, separator).trim();
    String commandAndEnvironment = line.substring(separator).trim();
    if (!commandAndEnvironment.contains("CRYPTAD_APP_TOKEN=" + token)
        || !commandAndEnvironment.contains("CRYPTAD_APP_ID=" + appId)) {
      return Optional.empty();
    }
    try {
      long pid = Long.parseLong(pidText);
      return ProcessHandle.of(pid);
    } catch (NumberFormatException _) {
      return Optional.empty();
    }
  }

  private static String resolveTrustedPsCommand() {
    for (Path trustedDir :
        List.of(Path.of("/usr/bin"), Path.of("/bin"), Path.of("/usr/sbin"), Path.of("/sbin"))) {
      Path candidate = trustedDir.resolve("ps");
      if (Files.isExecutable(candidate)) {
        return candidate.toString();
      }
    }
    return null;
  }

  private static boolean startedWithinWindowsRecoveryWindow(
      ProcessHandle processHandle, Instant startedAt, Duration windowsBundleRecoveryWindow) {
    return processHandle
        .info()
        .startInstant()
        .map(
            candidateStartedAt ->
                !candidateStartedAt.isBefore(startedAt.minusSeconds(1))
                    && !candidateStartedAt.isAfter(startedAt.plus(windowsBundleRecoveryWindow)))
        .orElse(false);
  }

  private static boolean referencesInstalledBundle(
      ProcessHandle processHandle, Path installedRoot, Path executablePath) {
    String normalizedInstalledRoot = installedRoot.toString().toLowerCase(Locale.ROOT);
    String normalizedExecutablePath = executablePath.toString().toLowerCase(Locale.ROOT);
    ProcessHandle.Info info = processHandle.info();
    String normalizedCommand =
        info.command().map(command -> command.toLowerCase(Locale.ROOT)).orElse("");
    if (!normalizedCommand.isEmpty()
        && (normalizedCommand.equals(normalizedExecutablePath)
            || normalizedCommand.startsWith(normalizedInstalledRoot + "\\")
            || normalizedCommand.startsWith(normalizedInstalledRoot + "/"))) {
      return true;
    }
    String normalizedCommandLine =
        info.commandLine().map(commandLine -> commandLine.toLowerCase(Locale.ROOT)).orElse("");
    return !normalizedCommandLine.isEmpty()
        && (normalizedCommandLine.contains(normalizedExecutablePath)
            || normalizedCommandLine.contains(normalizedInstalledRoot));
  }

  private static boolean supportsProcEnvironmentScan() {
    return Files.isReadable(Path.of(PROC_ROOT, "self", "environ"));
  }

  private static boolean hasAppHostToken(long pid, String token, String appId) {
    Path environmentFile = Path.of(PROC_ROOT, Long.toString(pid), "environ");
    if (!Files.isReadable(environmentFile)) {
      return false;
    }
    try {
      String environment = Files.readString(environmentFile, StandardCharsets.UTF_8);
      return hasEnvironmentEntry(environment, "CRYPTAD_APP_TOKEN", token)
          && hasEnvironmentEntry(environment, "CRYPTAD_APP_ID", appId);
    } catch (IOException | RuntimeException _) {
      return false;
    }
  }

  private static boolean hasEnvironmentEntry(String environment, String name, String value) {
    String expectedEntry = name + "=" + value;
    int start = 0;
    while (start <= environment.length()) {
      int end = environment.indexOf('\0', start);
      if (end < 0) {
        end = environment.length();
      }
      if (end - start == expectedEntry.length()
          && environment.regionMatches(start, expectedEntry, 0, expectedEntry.length())) {
        return true;
      }
      if (end == environment.length()) {
        break;
      }
      start = end + 1;
    }
    return false;
  }

  private static List<ProcessHandle> descendantHandles(RunningProcess runningProcess) {
    long rootPid = runningProcess.process().pid();
    return aliveHandles(runningProcess.processTree()).stream()
        .filter(processHandle -> processHandle.pid() != rootPid)
        .toList();
  }

  private static List<ProcessHandle> deduplicateHandles(List<ProcessHandle> processHandles) {
    LinkedHashMap<Long, ProcessHandle> handlesByPid = new LinkedHashMap<>();
    for (ProcessHandle processHandle : processHandles) {
      handlesByPid.putIfAbsent(processHandle.pid(), processHandle);
    }
    return List.copyOf(handlesByPid.values());
  }

  private static boolean isEffectivelyAlive(ProcessHandle processHandle) {
    return processHandle.isAlive() && !isZombieProcess(processHandle);
  }

  private static boolean isZombieProcess(ProcessHandle processHandle) {
    Path statFile = Path.of(PROC_ROOT, Long.toString(processHandle.pid()), "stat");
    if (!Files.isReadable(statFile)) {
      return false;
    }
    try {
      String stat = Files.readString(statFile);
      int commandEnd = stat.lastIndexOf(')');
      return commandEnd >= 0
          && commandEnd + 2 < stat.length()
          && stat.charAt(commandEnd + 2) == 'Z';
    } catch (IOException _) {
      return false;
    }
  }

  private static boolean preferDescendantPid(Path executable, List<ProcessHandle> processTree) {
    if (!(isInterpreterManagedPosixLauncherUnchecked(executable)
        || isWindowsBatchScript(executable))) {
      return false;
    }
    return processTree.size() > 1;
  }

  private static boolean isInterpreterManagedPosixLauncherUnchecked(Path executable) {
    try {
      return isInterpreterManagedPosixLauncher(executable);
    } catch (IOException _) {
      return false;
    }
  }

  private record PosixLauncher(List<String> interpreter, boolean shellInterpreter) {
    private PosixLauncher {
      interpreter = List.copyOf(interpreter);
    }

    private List<String> command(Path executable, TimingConfig timing) {
      return shellInterpreter
          ? shellCommand(executable, timing)
          : directInterpreterCommand(executable);
    }

    private List<String> shellCommand(Path executable, TimingConfig timing) {
      List<String> command = new ArrayList<>(interpreter);
      command.add("-c");
      command.add(
          "trap 'sleep %s' EXIT%nset --%n. \"$0\"%n"
              .formatted(posixShellExitTrapDelaySeconds(timing)));
      command.add(executable.toString());
      return List.copyOf(command);
    }

    private List<String> directInterpreterCommand(Path executable) {
      List<String> command = new ArrayList<>(interpreter);
      command.add(executable.toString());
      return List.copyOf(command);
    }

    private static String posixShellExitTrapDelaySeconds(TimingConfig timing) {
      return String.format(
          Locale.ROOT, "%.3f", timing.startupProcessCaptureWindow().toMillis() / 1000.0d);
    }
  }

  @FunctionalInterface
  interface ManagedTreeDeleter {
    void deleteRecursively(Path root) throws IOException;
  }

  private record HostDependencies(
      ManagedTreeDeleter managedTreeDeleter,
      AppInstallVerificationPolicy installVerificationPolicy,
      AppSandboxProviders sandboxProviders,
      RestartStormPolicy restartStormPolicy) {}

  /**
   * Rolling-window policy used to suppress repeated automatic restart attempts.
   *
   * <p>The policy is host-side runtime configuration, not manifest metadata. A positive window and
   * positive restart count define how many automatic restarts may be attempted before AppHost
   * leaves the app stopped and reports a restart-storm warning.
   *
   * @param restartStormWindow positive rolling window used to count automatic restart attempts
   * @param restartStormMaxInWindow positive maximum attempts allowed within the rolling window
   */
  record RestartStormPolicy(Duration restartStormWindow, int restartStormMaxInWindow) {
    RestartStormPolicy {
      Objects.requireNonNull(restartStormWindow, "restartStormWindow");
      if (restartStormWindow.isZero() || restartStormWindow.isNegative()) {
        throw new IllegalArgumentException("restartStormWindow must be positive");
      }
      if (restartStormMaxInWindow <= 0) {
        throw new IllegalArgumentException("restartStormMaxInWindow must be positive");
      }
    }
  }

  record TimingConfig(
      Duration startupExitGracePeriod,
      Duration startupProcessCaptureWindow,
      Duration startupPostCaptureHandoffGracePeriod,
      Duration trackedProcessPostExitCaptureGracePeriod,
      Duration trackedProcessRefreshInterval,
      Duration startupProcessPollInterval,
      Duration startupHandoffPollInterval,
      Duration descendantReapGracePeriodLimit) {
    TimingConfig {
      Objects.requireNonNull(startupExitGracePeriod, "startupExitGracePeriod");
      Objects.requireNonNull(startupProcessCaptureWindow, "startupProcessCaptureWindow");
      Objects.requireNonNull(
          startupPostCaptureHandoffGracePeriod, "startupPostCaptureHandoffGracePeriod");
      Objects.requireNonNull(
          trackedProcessPostExitCaptureGracePeriod, "trackedProcessPostExitCaptureGracePeriod");
      Objects.requireNonNull(trackedProcessRefreshInterval, "trackedProcessRefreshInterval");
      Objects.requireNonNull(startupProcessPollInterval, "startupProcessPollInterval");
      Objects.requireNonNull(startupHandoffPollInterval, "startupHandoffPollInterval");
      Objects.requireNonNull(descendantReapGracePeriodLimit, "descendantReapGracePeriodLimit");
    }

    private Duration windowsBundleRecoveryWindow() {
      return startupExitGracePeriod.plus(trackedProcessPostExitCaptureGracePeriod);
    }
  }

  private static long representativePid(
      List<ProcessHandle> processTree, long preferredPid, boolean preferDescendantPid) {
    if (preferDescendantPid) {
      OptionalLong descendantPid =
          processTree.stream()
              .mapToLong(ProcessHandle::pid)
              .filter(pid -> pid != preferredPid)
              .min();
      if (descendantPid.isPresent()) {
        return descendantPid.orElseThrow();
      }
    }
    return processTree.stream()
        .filter(processHandle -> processHandle.pid() == preferredPid)
        .findFirst()
        .or(() -> processTree.stream().min(Comparator.comparingLong(ProcessHandle::pid)))
        .orElseThrow(() -> new IllegalArgumentException("processTree must not be empty"))
        .pid();
  }

  private record ProcessExitRecord(
      InstalledAppPaths paths,
      Integer exitCode,
      Instant exitAt,
      int restartCount,
      int currentRestartAttempt,
      String lastLaunchToken,
      AppSandboxStatus sandboxStatus,
      boolean explicitStop,
      List<String> warnings) {
    private ProcessExitRecord {
      warnings = List.copyOf(Objects.requireNonNull(warnings, "warnings"));
    }

    private static ProcessExitRecord fromRunningProcess(
        RunningProcess runningProcess,
        Integer exitCode,
        Instant exitAt,
        boolean explicitStop,
        List<String> warnings) {
      return new ProcessExitRecord(
          runningProcess.snapshot().paths(),
          exitCode,
          exitAt,
          runningProcess.restartCount(),
          runningProcess.currentRestartAttempt(),
          runningProcess.snapshot().token(),
          runningProcess.snapshot().sandboxStatus(),
          explicitStop,
          warnings);
    }
  }

  private record LogMetadata(boolean available, Long sizeBytes) {}

  private record RuntimeRecord(
      InstalledAppPaths paths,
      AppRuntimeState state,
      boolean running,
      Long pid,
      Instant startedAt,
      Instant lastExitAt,
      Integer lastExitCode,
      String lastLaunchToken,
      AppSandboxStatus sandboxStatus,
      int restartCount,
      int currentRestartAttempt,
      List<String> warnings) {
    private RuntimeRecord {
      warnings = List.copyOf(Objects.requireNonNull(warnings, "warnings"));
    }

    private static RuntimeRecord running(
        RunningProcess runningProcess, RuntimeRecord previousRecord) {
      return running(
          runningProcess.snapshot(),
          runningProcess.restartCount(),
          runningProcess.currentRestartAttempt(),
          previousRecord);
    }

    private static RuntimeRecord running(
        RunningAppSnapshot snapshot,
        int restartCount,
        int currentRestartAttempt,
        RuntimeRecord previousRecord) {
      return new RuntimeRecord(
          snapshot.paths(),
          AppRuntimeState.RUNNING,
          true,
          snapshot.pid(),
          snapshot.startedAt(),
          previousRecord == null ? null : previousRecord.lastExitAt(),
          previousRecord == null ? null : previousRecord.lastExitCode(),
          snapshot.token(),
          snapshot.sandboxStatus(),
          restartCount,
          currentRestartAttempt,
          List.of());
    }

    private static RuntimeRecord restarting(
        RunningProcess runningProcess,
        Integer exitCode,
        Instant exitAt,
        int restartAttempt,
        List<String> warnings) {
      return new RuntimeRecord(
          runningProcess.snapshot().paths(),
          AppRuntimeState.RESTARTING,
          false,
          null,
          null,
          exitAt,
          exitCode,
          runningProcess.snapshot().token(),
          runningProcess.snapshot().sandboxStatus(),
          runningProcess.restartCount(),
          restartAttempt,
          warnings);
    }

    private static RuntimeRecord stopped(InstalledAppPaths paths, AppSandboxStatus sandboxStatus) {
      return new RuntimeRecord(
          paths,
          AppRuntimeState.STOPPED,
          false,
          null,
          null,
          null,
          null,
          null,
          sandboxStatus,
          0,
          0,
          List.of());
    }

    private static RuntimeRecord stopped(RunningProcess runningProcess, List<String> warnings) {
      return new RuntimeRecord(
          runningProcess.snapshot().paths(),
          AppRuntimeState.STOPPED,
          false,
          null,
          null,
          Instant.now(),
          trackedAppExitCode(runningProcess),
          runningProcess.snapshot().token(),
          runningProcess.snapshot().sandboxStatus(),
          runningProcess.restartCount(),
          runningProcess.currentRestartAttempt(),
          warnings);
    }

    private RuntimeRecord stopped() {
      return new RuntimeRecord(
          paths,
          AppRuntimeState.STOPPED,
          false,
          null,
          null,
          lastExitAt,
          lastExitCode,
          lastLaunchToken,
          inactiveSandboxStatus(sandboxStatus),
          restartCount,
          currentRestartAttempt,
          warnings);
    }

    private RuntimeRecord failedRestart(
        Instant failedAt, List<String> additionalWarnings, AppSandboxStatus failedSandboxStatus) {
      List<String> mergedWarnings = new ArrayList<>(warnings);
      mergedWarnings.addAll(additionalWarnings);
      return new RuntimeRecord(
          paths,
          AppRuntimeState.CRASHED,
          false,
          null,
          null,
          failedAt,
          lastExitCode,
          lastLaunchToken,
          inactiveSandboxStatus(failedSandboxStatus),
          restartCount,
          currentRestartAttempt,
          mergedWarnings.stream().distinct().toList());
    }

    private RuntimeRecord withoutRunningProcess(
        InstalledAppPaths installedPaths, AppSandboxStatus installedSandboxStatus) {
      AppSandboxStatus refreshedSandboxStatus =
          sandboxPolicyMatches(installedSandboxStatus)
              ? inactiveSandboxStatus(sandboxStatus)
              : installedSandboxStatus;
      if (running) {
        return new RuntimeRecord(
            installedPaths,
            AppRuntimeState.STOPPED,
            false,
            null,
            null,
            lastExitAt,
            lastExitCode,
            lastLaunchToken,
            refreshedSandboxStatus,
            restartCount,
            currentRestartAttempt,
            warnings);
      }
      return paths.equals(installedPaths) && refreshedSandboxStatus.equals(sandboxStatus)
          ? this
          : withPathsAndSandboxStatus(installedPaths, refreshedSandboxStatus);
    }

    private boolean sandboxPolicyMatches(AppSandboxStatus installedSandboxStatus) {
      return sandboxStatus.mode() == installedSandboxStatus.mode()
          && sandboxStatus.required() == installedSandboxStatus.required();
    }

    private RuntimeRecord withPathsAndSandboxStatus(
        InstalledAppPaths installedPaths, AppSandboxStatus installedSandboxStatus) {
      return new RuntimeRecord(
          installedPaths,
          state,
          running,
          pid,
          startedAt,
          lastExitAt,
          lastExitCode,
          lastLaunchToken,
          running ? installedSandboxStatus : inactiveSandboxStatus(installedSandboxStatus),
          restartCount,
          currentRestartAttempt,
          warnings);
    }

    private static AppSandboxStatus inactiveSandboxStatus(AppSandboxStatus status) {
      if (!status.active()) {
        return status;
      }
      return new AppSandboxStatus(
          status.mode(),
          status.required(),
          status.supportLevel(),
          status.providerName(),
          false,
          "No sandbox restrictions are active because the app is not running; last launch provider"
              + " was "
              + status.providerName(),
          inactiveSandboxWarnings(status));
    }

    private static List<String> inactiveSandboxWarnings(AppSandboxStatus status) {
      ArrayList<String> inactiveWarnings = new ArrayList<>();
      inactiveWarnings.add("Sandbox restrictions are not active because the app is not running");
      for (String warning : status.warnings()) {
        inactiveWarnings.add(inactiveSandboxWarning(warning));
      }
      return inactiveWarnings.stream().distinct().toList();
    }

    private static String inactiveSandboxWarning(String warning) {
      return warning
          .replace("Filesystem sandbox active", "Last launch used filesystem sandbox")
          .replace(
              "Best-effort restricted local process launch active",
              "Last launch used best-effort restricted local process launch");
    }

    @Override
    public @NotNull String toString() {
      return "RuntimeRecord[paths="
          + paths
          + ", state="
          + state
          + ", running="
          + running
          + ", pid="
          + pid
          + ", startedAt="
          + startedAt
          + ", lastExitAt="
          + lastExitAt
          + ", lastExitCode="
          + lastExitCode
          + ", lastLaunchToken="
          + (lastLaunchToken == null ? null : AppHostTokenRedactor.REDACTED)
          + ", sandboxStatus="
          + sandboxStatus
          + ", restartCount="
          + restartCount
          + ", currentRestartAttempt="
          + currentRestartAttempt
          + ", warnings="
          + warnings
          + ']';
    }
  }

  private record StartupAcceptance(RunningProcess runningProcess, boolean restartScheduled) {
    private static StartupAcceptance live(RunningProcess runningProcess) {
      return new StartupAcceptance(runningProcess, false);
    }

    private static StartupAcceptance restarting(RunningProcess runningProcess) {
      return new StartupAcceptance(runningProcess, true);
    }

    private static StartupAcceptance failed() {
      return new StartupAcceptance(null, false);
    }
  }

  @SuppressWarnings("ClassCanBeRecord")
  private static final class RunningProcess {
    private static final long NO_ROOT_HANDOFF_CANDIDATE = -1L;

    private final Process process;
    private final RunningAppSnapshot snapshot;
    private final CompletableFuture<Void> exitCleanup;
    private final List<ProcessHandle> trackedHandles;
    private final int restartCount;
    private final int currentRestartAttempt;
    private final RootHandoffState rootHandoffState;

    private RunningProcess(
        Process process,
        RunningAppSnapshot snapshot,
        CompletableFuture<Void> exitCleanup,
        List<ProcessHandle> trackedHandles,
        int restartCount,
        int currentRestartAttempt,
        boolean representativeProcessHandoff) {
      this(
          process,
          snapshot,
          exitCleanup,
          trackedHandles,
          restartCount,
          currentRestartAttempt,
          new RootHandoffState(representativeProcessHandoff, NO_ROOT_HANDOFF_CANDIDATE));
    }

    private RunningProcess(
        Process process,
        RunningAppSnapshot snapshot,
        CompletableFuture<Void> exitCleanup,
        List<ProcessHandle> trackedHandles,
        int restartCount,
        int currentRestartAttempt,
        RootHandoffState rootHandoffState) {
      this.process = Objects.requireNonNull(process, "process");
      this.snapshot = Objects.requireNonNull(snapshot, "snapshot");
      this.exitCleanup = Objects.requireNonNull(exitCleanup, "exitCleanup");
      this.trackedHandles = List.copyOf(Objects.requireNonNull(trackedHandles, "trackedHandles"));
      this.restartCount = restartCount;
      this.currentRestartAttempt = currentRestartAttempt;
      this.rootHandoffState = Objects.requireNonNull(rootHandoffState, "rootHandoffState");
    }

    private Process process() {
      return process;
    }

    private RunningAppSnapshot snapshot() {
      return snapshot;
    }

    private CompletableFuture<Void> exitCleanup() {
      return exitCleanup;
    }

    private int restartCount() {
      return restartCount;
    }

    private int currentRestartAttempt() {
      return currentRestartAttempt;
    }

    private boolean isRepresentativeProcessHandoff() {
      return rootHandoffState.confirmed();
    }

    private RunningProcess withObservedRootHandoff() {
      if (isRepresentativeProcessHandoff()
          || !hasTrackedDescendant()
          || isEffectivelyAlive(process.toHandle())) {
        return this;
      }
      return new RunningProcess(
          process,
          snapshot,
          exitCleanup,
          trackedHandles,
          restartCount,
          currentRestartAttempt,
          true);
    }

    private boolean isAlive() {
      return !aliveHandles(processTree()).isEmpty();
    }

    private List<ProcessHandle> processTree() {
      return snapshotProcessTree(seedHandles());
    }

    private List<ProcessHandle> seedHandles() {
      List<ProcessHandle> seedHandles = new ArrayList<>();
      seedHandles.add(process.toHandle());
      seedHandles.addAll(trackedHandles);
      return deduplicateHandles(seedHandles);
    }

    private RunningProcess refresh(Duration rootHandoffConfirmationGrace) {
      List<ProcessHandle> currentProcessTree = aliveHandles(processTree());
      if (currentProcessTree.isEmpty()) {
        return null;
      }
      return tryWithAliveProcessTree(currentProcessTree, rootHandoffConfirmationGrace);
    }

    private RunningProcess tryWithProcessTree(
        List<ProcessHandle> newProcessTree, Duration rootHandoffConfirmationGrace) {
      List<ProcessHandle> aliveProcessTree = aliveHandles(newProcessTree);
      if (aliveProcessTree.isEmpty()) {
        return null;
      }
      return tryWithAliveProcessTree(aliveProcessTree, rootHandoffConfirmationGrace);
    }

    private RunningProcess tryWithAliveProcessTree(
        List<ProcessHandle> aliveProcessTree, Duration rootHandoffConfirmationGrace) {
      boolean rootProcessExited = rootProcessExited(aliveProcessTree);
      if (!rootProcessExited && !isEffectivelyAlive(process.toHandle())) {
        aliveProcessTree = withoutRootProcess(aliveProcessTree);
        if (aliveProcessTree.isEmpty()) {
          return null;
        }
        rootProcessExited = true;
      }
      RootHandoffState updatedRootHandoffState =
          rootHandoffState(rootProcessExited, rootHandoffConfirmationGrace);
      long updatedPid = representativePid(aliveProcessTree, snapshot.pid(), false);
      RunningAppSnapshot updatedSnapshot =
          updatedPid == snapshot.pid()
              ? snapshot
              : new RunningAppSnapshot(
                  snapshot.manifest(),
                  snapshot.paths(),
                  snapshot.token(),
                  updatedPid,
                  snapshot.startedAt(),
                  snapshot.sandboxStatus());
      if (trackedHandlePids().equals(handlePids(aliveProcessTree))
          && updatedPid == snapshot.pid()
          && updatedRootHandoffState.equals(rootHandoffState)) {
        return this;
      }
      return new RunningProcess(
          process,
          updatedSnapshot,
          exitCleanup,
          aliveProcessTree,
          restartCount,
          currentRestartAttempt,
          updatedRootHandoffState);
    }

    private RootHandoffState rootHandoffState(
        boolean rootProcessExited, Duration rootHandoffConfirmationGrace) {
      if (isRepresentativeProcessHandoff()) {
        return new RootHandoffState(true, NO_ROOT_HANDOFF_CANDIDATE);
      }
      if (!rootProcessExited) {
        return new RootHandoffState(false, NO_ROOT_HANDOFF_CANDIDATE);
      }
      // A clean wrapper can briefly leave stale descendant handles while it reaps a child.
      // Confirm the handoff only after the existing post-exit capture grace keeps seeing it.
      long candidateAtNanos = rootHandoffState.candidateAtNanos();
      long nowNanos = System.nanoTime();
      if (candidateAtNanos == NO_ROOT_HANDOFF_CANDIDATE) {
        candidateAtNanos = nowNanos;
      }
      if (rootHandoffCandidateExpired(candidateAtNanos, rootHandoffConfirmationGrace, nowNanos)) {
        return new RootHandoffState(true, NO_ROOT_HANDOFF_CANDIDATE);
      }
      return new RootHandoffState(false, candidateAtNanos);
    }

    private static boolean rootHandoffCandidateExpired(
        long candidateAtNanos, Duration rootHandoffConfirmationGrace, long nowNanos) {
      return nowNanos - candidateAtNanos >= rootHandoffConfirmationGrace.toNanos();
    }

    private boolean rootProcessExited(List<ProcessHandle> aliveProcessTree) {
      long rootPid = process.pid();
      return aliveProcessTree.stream().noneMatch(processHandle -> processHandle.pid() == rootPid);
    }

    private boolean hasTrackedDescendant() {
      long rootPid = process.pid();
      return trackedHandles.stream().anyMatch(processHandle -> processHandle.pid() != rootPid);
    }

    private List<ProcessHandle> withoutRootProcess(List<ProcessHandle> processTree) {
      long rootPid = process.pid();
      return processTree.stream().filter(processHandle -> processHandle.pid() != rootPid).toList();
    }

    private List<Long> trackedHandlePids() {
      return handlePids(trackedHandles);
    }

    private static List<Long> handlePids(List<ProcessHandle> processHandles) {
      return processHandles.stream().map(ProcessHandle::pid).sorted().toList();
    }

    private record RootHandoffState(boolean confirmed, long candidateAtNanos) {}
  }
}
