package network.crypta.platform.apphost.sandbox;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import network.crypta.fs.AppEnv;

/**
 * Builds a bubblewrap wrapper command for one AppHost child process launch.
 *
 * <p>The builder is intentionally deterministic and side-effect free. It produces a conservative
 * filesystem mount plan that keeps the installed app bundle read-only, exposes only AppHost-managed
 * mutable directories read-write, mounts the minimal POSIX runtime paths that commonly support
 * shell-script launchers, and appends the original app command only after bubblewrap's {@code --}
 * separator. Environment variables are not translated into command-line arguments, so launch tokens
 * remain in {@link ProcessBuilder#environment()}.
 *
 * <p>The generated namespace uses the same absolute source and destination paths for AppHost-owned
 * directories. That keeps existing app manifests and working-directory assumptions stable while the
 * namespace hides host paths that are not explicitly mounted. The class does not create
 * directories, inspect environment values, or execute bubblewrap; it only returns the command shape
 * that the provider can hand to AppHost. Debian-style {@code /etc/alternatives} command symlinks,
 * resolver configuration, public certificate trust stores, and fixed public JDK security
 * configuration files (including Debian symlink targets) are mounted narrowly when present so
 * launchers can resolve common tools and hostnames without exposing the rest of {@code /etc}.
 */
public final class BubblewrapCommandBuilder {
  private static final Path ROOT = Path.of("/");
  // Bubblewrap mounts an isolated tmpfs at this namespace destination; Java does not open the host
  // /tmp directory here.
  private static final String SANDBOX_TMPFS_DESTINATION = "/tmp";
  static final Path ETC_ALTERNATIVES = Path.of("/etc/alternatives");
  static final Path ETC_HOSTS = Path.of("/etc/hosts");
  static final Path ETC_NSSWITCH_CONF = Path.of("/etc/nsswitch.conf");
  static final Path ETC_RESOLV_CONF = Path.of("/etc/resolv.conf");
  static final Path ETC_SSL_CERTS = Path.of("/etc/ssl/certs");
  static final Path ETC_PKI_CA_TRUST = Path.of("/etc/pki/ca-trust");
  static final Path ETC_PKI_TLS_CERTS = Path.of("/etc/pki/tls/certs");
  static final Path LINUXBREW_PREFIX = Path.of("/home/linuxbrew/.linuxbrew");
  static final List<Path> DEFAULT_SYSTEM_READ_ONLY_PATHS =
      List.of(
          Path.of("/usr"),
          Path.of("/bin"),
          Path.of("/lib"),
          Path.of("/lib64"),
          ETC_ALTERNATIVES,
          ETC_HOSTS,
          ETC_NSSWITCH_CONF,
          ETC_RESOLV_CONF,
          ETC_SSL_CERTS,
          ETC_PKI_CA_TRUST,
          ETC_PKI_TLS_CERTS,
          LINUXBREW_PREFIX);

  private static final List<String> PUBLIC_JAVA_SECURITY_FILES =
      List.of(
          "conf/security/java.security",
          "conf/security/policy/unlimited/default_US_export.policy",
          "conf/security/policy/unlimited/default_local.policy",
          "conf/security/policy/limited/default_US_export.policy",
          "conf/security/policy/limited/default_local.policy",
          "conf/security/policy/limited/exempt_local.policy");
  private final List<Path> systemReadOnlyPaths;
  private final Path javaHome;

  /**
   * Creates the stateless command builder.
   *
   * <p>All launch-specific data is supplied to {@link #build(String, AppSandboxLaunchContext)}. A
   * single instance can therefore be shared across provider calls without synchronization or
   * retained launch state.
   */
  public BubblewrapCommandBuilder() {
    this(DEFAULT_SYSTEM_READ_ONLY_PATHS, new AppEnv().javaHome());
  }

  /**
   * Creates a command builder with an explicit read-only system path list.
   *
   * <p>This constructor is package-private for deterministic tests that need to verify mount-plan
   * behavior without relying on the CI host's filesystem layout.
   *
   * @param systemReadOnlyPaths host system paths considered for read-only bind mounts
   */
  BubblewrapCommandBuilder(Collection<Path> systemReadOnlyPaths) {
    this(systemReadOnlyPaths, null);
  }

  BubblewrapCommandBuilder(Collection<Path> systemReadOnlyPaths, Path javaHome) {
    this.javaHome = javaHome;
    this.systemReadOnlyPaths =
        List.copyOf(Objects.requireNonNull(systemReadOnlyPaths, "systemReadOnlyPaths"));
  }

  /**
   * Builds a complete bubblewrap command plan.
   *
   * <p>The returned command starts with the selected bubblewrap executable, adds process/session
   * cleanup flags, creates parent directories inside the namespace before bind mounts, and then
   * appends the original app command after {@code --}. The environment from the launch context is
   * intentionally absent from the argument list. AppHost passes it separately through {@link
   * ProcessBuilder#environment()} so values such as the app token are not visible through local
   * process command-line inspection.
   *
   * @param bubblewrapExecutable executable token selected by {@link BubblewrapAvailability}
   * @param context sensitive AppHost launch context for the child process start attempt
   * @return command plan containing the final command and mount metadata for tests
   */
  public CommandPlan build(String bubblewrapExecutable, AppSandboxLaunchContext context) {
    String executable = requireExecutable(bubblewrapExecutable);
    AppSandboxLaunchContext checkedContext = Objects.requireNonNull(context, "context");
    List<BindMount> bindMounts = bindMounts(checkedContext);
    List<Path> directoryMounts = directoryMounts(bindMounts);
    ArrayList<String> command = new ArrayList<>();
    command.add(executable);
    command.add("--die-with-parent");
    command.add("--new-session");
    command.add("--unshare-pid");
    command.add("--unshare-ipc");
    command.add("--tmpfs");
    command.add(SANDBOX_TMPFS_DESTINATION);
    command.add("--proc");
    command.add("/proc");
    command.add("--dev");
    command.add("/dev");
    appendDirectoryMounts(command, directoryMounts);
    appendBindMounts(command, bindMounts);
    command.add("--chdir");
    command.add(checkedContext.installDir().toString());
    command.add("--");
    command.addAll(checkedContext.command());
    return new CommandPlan(command, bindMounts, directoryMounts);
  }

  private List<BindMount> bindMounts(AppSandboxLaunchContext context) {
    ArrayList<BindMount> mounts = new ArrayList<>();
    for (Path systemPath : systemReadOnlyPaths) {
      if (Files.exists(systemPath)) {
        mounts.add(BindMount.readOnly(systemPath, systemPath));
      }
    }
    addJavaSecurityMounts(mounts);
    if ("mail-prototype".equals(context.appId())) addJavaRuntimeMounts(mounts);
    mounts.add(BindMount.readOnly(context.installDir(), context.installDir()));
    mounts.add(BindMount.readWrite(context.dataDir(), context.dataDir()));
    mounts.add(BindMount.readWrite(context.cacheDir(), context.cacheDir()));
    mounts.add(BindMount.readWrite(context.runDir(), context.runDir()));
    return List.copyOf(mounts);
  }

  private void addJavaSecurityMounts(List<BindMount> mounts) {
    if (javaHome == null) return;
    for (String relative : PUBLIC_JAVA_SECURITY_FILES) {
      Path file = javaHome.resolve(relative);
      try {
        if (!Files.isRegularFile(file)) continue;
        Path resolved = file.toRealPath();
        if (systemReadOnlyPaths.stream().noneMatch(resolved::startsWith)
            && mounts.stream().noneMatch(mount -> mount.destination().equals(resolved))) {
          mounts.add(BindMount.readOnly(resolved, resolved));
        }
      } catch (java.io.IOException _) {
        throw new IllegalStateException("Java security configuration unavailable");
      }
    }
  }

  /** Makes the host-selected runtime executable and modules visible without exposing its parent. */
  private void addJavaRuntimeMounts(List<BindMount> mounts) {
    if (javaHome == null) throw new IllegalStateException("Java runtime unavailable");
    try {
      Path home = javaHome.toRealPath();
      for (String directory : List.of("bin", "lib")) {
        Path destination = home.resolve(directory);
        Path source = destination.toRealPath();
        if (!Files.isDirectory(source)) throw new IllegalStateException("Java runtime unavailable");
        boolean destinationMounted =
            mounts.stream().anyMatch(mount -> destination.startsWith(mount.destination()));
        if (!destinationMounted) mounts.add(BindMount.readOnly(source, destination));
        else if (mounts.stream().noneMatch(mount -> source.startsWith(mount.destination())))
          mounts.add(BindMount.readOnly(source, source));
      }
    } catch (java.io.IOException _) {
      throw new IllegalStateException("Java runtime unavailable");
    }
  }

  private static List<Path> directoryMounts(Collection<BindMount> bindMounts) {
    Set<Path> directories = new LinkedHashSet<>();
    for (BindMount mount : bindMounts) {
      addParentDirectories(mount.destination(), directories);
    }
    return directories.stream()
        .sorted(Comparator.comparingInt(Path::getNameCount).thenComparing(Path::toString))
        .toList();
  }

  private static void addParentDirectories(Path destination, Set<Path> directories) {
    Path parent = destination.toAbsolutePath().normalize().getParent();
    while (parent != null && !ROOT.equals(parent) && !isSandboxTmpfsDestination(parent)) {
      directories.add(parent);
      parent = parent.getParent();
    }
  }

  private static boolean isSandboxTmpfsDestination(Path path) {
    return SANDBOX_TMPFS_DESTINATION.equals(path.toString());
  }

  private static void appendDirectoryMounts(List<String> command, List<Path> directoryMounts) {
    for (Path directory : directoryMounts) {
      command.add("--dir");
      command.add(directory.toString());
    }
  }

  private static void appendBindMounts(List<String> command, List<BindMount> bindMounts) {
    for (BindMount mount : bindMounts) {
      command.add(mount.access().flag());
      command.add(mount.source().toString());
      command.add(mount.destination().toString());
    }
  }

  private static String requireExecutable(String value) {
    String trimmed = Objects.requireNonNull(value, "bubblewrapExecutable").trim();
    if (trimmed.isEmpty()) {
      throw new IllegalArgumentException("bubblewrapExecutable must not be blank");
    }
    return trimmed;
  }

  /**
   * Bubblewrap bind mount access mode.
   *
   * <p>The enum is part of the generated command metadata rather than the public Platform API.
   * Tests use it to assert that the installed bundle remains read-only and only the AppHost-managed
   * mutable directories receive read-write mounts.
   */
  public enum MountAccess {
    /**
     * Read-only bind mount exposed with {@code --ro-bind}.
     *
     * <p>Use this for the installed application bundle and host runtime directories that are needed
     * only to execute POSIX launchers or interpreters.
     */
    READ_ONLY("--ro-bind"),

    /**
     * Read-write bind mount exposed with {@code --bind}.
     *
     * <p>Use this only for AppHost-managed per-app mutable directories such as data, cache, and run
     * locations.
     */
    READ_WRITE("--bind");

    private final String flag;

    MountAccess(String flag) {
      this.flag = flag;
    }

    private String flag() {
      return flag;
    }
  }

  /**
   * One bind mount in the generated bubblewrap filesystem plan.
   *
   * <p>Source and destination paths are normalized to absolute paths when the record is created.
   * The first implementation intentionally uses identical source and destination paths so app
   * working directories, launcher scripts, and AppHost-managed path contracts remain stable inside
   * the namespace. The access mode is the security-relevant part of the mount entry.
   *
   * @param source host source path used by bubblewrap
   * @param destination namespace destination path
   * @param access read-only or read-write access mode
   */
  public record BindMount(Path source, Path destination, MountAccess access) {
    /**
     * Creates a normalized bind mount entry.
     *
     * <p>The constructor performs only value normalization and validation. It does not check for
     * path existence because the builder already filters optional system paths and AppHost owns the
     * app directories supplied by the launch context.
     *
     * @param source host source path used by bubblewrap
     * @param destination namespace destination path
     * @param access read-only or read-write access mode
     */
    public BindMount {
      source = normalize(source, "source");
      destination = normalize(destination, "destination");
      Objects.requireNonNull(access, "access");
    }

    private static BindMount readOnly(Path source, Path destination) {
      return new BindMount(source, destination, MountAccess.READ_ONLY);
    }

    private static BindMount readWrite(Path source, Path destination) {
      return new BindMount(source, destination, MountAccess.READ_WRITE);
    }

    private static Path normalize(Path path, String label) {
      return Objects.requireNonNull(path, label).toAbsolutePath().normalize();
    }
  }

  /**
   * Complete generated bubblewrap launch shape.
   *
   * <p>The plan exposes the private command list that AppHost will execute and the structured mount
   * data that unit tests inspect. It is not public runtime status: command entries may contain host
   * paths, so callers must keep the object on the AppHost side of the API boundary.
   *
   * @param command final private command list for {@link ProcessBuilder}
   * @param bindMounts bind mounts used to construct the command
   * @param directoryMounts namespace directories created before bind mounts
   */
  public record CommandPlan(
      List<String> command, List<BindMount> bindMounts, List<Path> directoryMounts) {
    /**
     * Creates an immutable command plan.
     *
     * <p>The constructor defensively copies all list inputs so the provider can hand the command to
     * AppHost without retaining mutable caller-owned collections. The contained paths and command
     * strings are still launch-sensitive and should not be copied into public status text.
     *
     * @param command final private command list for {@link ProcessBuilder}
     * @param bindMounts bind mounts used to construct the command
     * @param directoryMounts namespace directories created before bind mounts
     */
    public CommandPlan {
      command = List.copyOf(Objects.requireNonNull(command, "command"));
      bindMounts = List.copyOf(Objects.requireNonNull(bindMounts, "bindMounts"));
      directoryMounts = List.copyOf(Objects.requireNonNull(directoryMounts, "directoryMounts"));
    }
  }
}
