package network.crypta.fs;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;
import java.util.regex.Pattern;

/**
 * Detects runtime platform characteristics and service/container execution modes for Cryptad.
 *
 * <p>This class is the single environment probe used by directory resolution and packaging logic to
 * keep OS- and deployment-specific decisions consistent. It encapsulates operating system
 * identification, service mode heuristics, container signals, CPU architecture normalization, and
 * simple executable discovery on {@code PATH}. The API is intentionally deterministic for tests:
 * callers can inject environment variables, OS metadata, username, and cgroup file readers rather
 * than depending on the ambient process state.
 *
 * <p>Detection responsibilities include:
 *
 * <ul>
 *   <li>Platform family mapping for Windows, macOS, Linux, and fallback environments.
 *   <li>Service-mode detection for systemd, Windows service sessions, and launchd contexts.
 *   <li>Container/sandbox hints for Docker, Flatpak, and Snap-aware behavior.
 * </ul>
 */
public final class AppEnv {
  private static final String CRYPTAD_SERVICE_ENV = "CRYPTAD_SERVICE";

  private final Map<String, String> env;
  private final String osName;
  private final String userName;
  private final Function<Path, String> fileReader;

  /** Broad OS family for the current runtime. */
  public enum OsKind {
    /** Microsoft Windows variants detected from the JVM OS name. */
    WINDOWS,
    /** Apple macOS and Darwin-based names detected from the JVM OS name. */
    MAC,
    /** Linux and Linux-like environments that are neither Windows nor macOS. */
    LINUX,
    /** Any runtime that does not match the supported Windows, macOS, or Linux families. */
    OTHER
  }

  /**
   * Immutable summary describing detected OS, CPU architecture, and package manager availability.
   *
   * <p>This record is returned by {@link #detectEnvironment()} as a compact transport object for UI
   * or decision logic. Architecture values are normalized to {@code amd64} or {@code arm64}, and
   * package managers are reported only when relevant on Linux platforms.
   *
   * @param os detected broad operating system family
   * @param arch normalized architecture label, currently {@code amd64} or {@code arm64}
   * @param availableManagers immutable list of package manager commands available on {@code PATH}
   */
  public record EnvDetection(OsKind os, String arch, List<String> availableManagers) {
    /**
     * Creates a validated environment summary.
     *
     * @param os detected broad operating system family
     * @param arch normalized architecture label, currently {@code amd64} or {@code arm64}
     * @param availableManagers package manager commands discovered for this environment
     */
    public EnvDetection {
      Objects.requireNonNull(os);
      Objects.requireNonNull(arch);
      availableManagers = List.copyOf(Objects.requireNonNull(availableManagers));
    }

    /**
     * Returns the detected operating system family.
     *
     * @return broad operating system family value
     */
    public OsKind getOs() {
      return os;
    }

    /**
     * Returns the normalized architecture label.
     *
     * @return architecture string, such as {@code amd64} or {@code arm64}
     */
    public String getArch() {
      return arch;
    }

    /**
     * Returns discovered package manager command names.
     *
     * @return immutable list of package manager commands visible on {@code PATH}
     */
    public List<String> getAvailableManagers() {
      return availableManagers;
    }
  }

  /**
   * Creates an environment detector backed by current process environment variables.
   *
   * <p>This convenience constructor uses JVM-provided OS and user properties and default file
   * reading behavior for cgroup inspection.
   */
  public AppEnv() {
    this(System.getenv());
  }

  /**
   * Creates an environment detector with explicit environment variables.
   *
   * <p>OS name and username are sourced from JVM system properties.
   *
   * @param env environment variables used for platform and mode detection
   */
  public AppEnv(Map<String, String> env) {
    this(env, systemPropertyOrEmpty("os.name"));
  }

  /**
   * Creates an environment detector with explicit environment variables and OS name.
   *
   * <p>Username is sourced from the JVM system property {@code user.name}.
   *
   * @param env environment variables used for platform and mode detection
   * @param osName raw operating system name used for OS-family matching
   */
  public AppEnv(Map<String, String> env, String osName) {
    this(env, osName, systemPropertyOrEmpty("user.name"));
  }

  /**
   * Creates an environment detector with an explicit environment, OS name, and username.
   *
   * <p>Cgroup file reads use the default helper that returns {@code null} when content is absent or
   * unreadable.
   *
   * @param env environment variables used for platform and mode detection
   * @param osName raw operating system name used for OS-family matching
   * @param userName username used by macOS service heuristics
   */
  public AppEnv(Map<String, String> env, String osName, String userName) {
    this(env, osName, userName, AppEnv::readIfExists);
  }

  /**
   * Creates an environment detector with fully injected dependencies.
   *
   * <p>This constructor is intended for tests and integration points that require deterministic
   * behavior independent of the host machine state.
   *
   * @param env environment variables used for platform and mode detection
   * @param osName raw operating system name used for OS-family matching, empty when {@code null}
   * @param userName username used by macOS service heuristics, empty when {@code null}
   * @param fileReader reader used to load cgroup markers for container detection
   */
  public AppEnv(
      Map<String, String> env, String osName, String userName, Function<Path, String> fileReader) {
    this.env = Objects.requireNonNull(env);
    this.osName = osName != null ? osName : "";
    this.userName = userName != null ? userName : "";
    this.fileReader = Objects.requireNonNull(fileReader);
  }

  /**
   * Returns the current JVM installation root for host-owned runtime integration.
   *
   * <p>This private filesystem location must not be copied into public diagnostics. Callers choose
   * explicit public runtime resources beneath this root; it is not app-selected path authority.
   *
   * @return normalized absolute Java runtime installation root
   * @throws IllegalStateException if the JVM does not provide its installation location
   */
  public Path javaHome() {
    String location = systemPropertyOrEmpty("java.home");
    if (location.isBlank()) throw new IllegalStateException("Java runtime location unavailable");
    return Path.of(location).toAbsolutePath().normalize();
  }

  /**
   * Reports whether the runtime OS name matches Windows-family identifiers.
   *
   * @return {@code true} when {@code os.name} contains a Windows marker, otherwise {@code false}
   */
  public boolean isWindows() {
    return osName.toLowerCase(Locale.ROOT).contains("win");
  }

  /**
   * Reports whether the runtime OS name matches macOS or Darwin identifiers.
   *
   * @return {@code true} when the OS name indicates macOS, otherwise {@code false}
   */
  public boolean isMac() {
    String lowered = osName.toLowerCase(Locale.ROOT);
    return lowered.contains("mac") || lowered.contains("darwin");
  }

  /**
   * Reports whether the runtime is treated as Linux.
   *
   * <p>This returns {@code true} when the environment is not identified as Windows or macOS.
   *
   * @return {@code true} for Linux-style environments, otherwise {@code false}
   */
  public boolean isLinux() {
    return !isWindows() && !isMac();
  }

  /**
   * Reports whether the process is running in a Flatpak sandbox.
   *
   * @return {@code true} when {@code FLATPAK_ID} is present, otherwise {@code false}
   */
  public boolean isFlatpak() {
    return env.containsKey("FLATPAK_ID");
  }

  /**
   * Reports whether the process is running in a Snap sandbox.
   *
   * @return {@code true} when {@code SNAP} is present, otherwise {@code false}
   */
  public boolean isSnap() {
    return env.containsKey("SNAP");
  }

  /**
   * Detects Docker/container runtime on Linux via cgroup markers.
   *
   * <p>Detection returns {@code true} immediately when {@code CRYPTAD_DOCKER=1} is set. Otherwise,
   * Linux environments read {@code /proc/1/cgroup} and look for common container markers such as
   * Docker, containerd, or Kubernetes pod cgroups.
   *
   * @return {@code true} when explicit override or cgroup markers indicate container runtime
   */
  public boolean isDocker() {
    if ("1".equals(env.get("CRYPTAD_DOCKER"))) {
      return true;
    }
    if (!isLinux()) {
      return false;
    }
    Path cgroupPath = Path.of("/proc/1/cgroup");
    if (!Files.exists(cgroupPath)) {
      return false;
    }
    String cgroup = fileReader.apply(cgroupPath);
    if (cgroup == null) {
      return false;
    }
    String s = cgroup.toLowerCase(Locale.ROOT);
    return s.contains("docker") || s.contains("containerd") || s.contains("kubepods");
  }

  /**
   * Reports whether Linux systemd service markers indicate service execution.
   *
   * <p>This method checks explicit override via {@code CRYPTAD_SERVICE=1} and known
   * systemd-provided directory environment variables.
   *
   * @return {@code true} when running as a systemd service, otherwise {@code false}
   */
  public boolean isSystemdService() {
    if (!isLinux()) {
      return false;
    }
    if ("1".equals(env.get(CRYPTAD_SERVICE_ENV))) {
      return true;
    }
    return env.containsKey("CONFIGURATION_DIRECTORY")
        || env.containsKey("STATE_DIRECTORY")
        || env.containsKey("CACHE_DIRECTORY")
        || env.containsKey("LOGS_DIRECTORY")
        || env.containsKey("RUNTIME_DIRECTORY");
  }

  /**
   * Reports whether Windows service heuristics indicate service execution.
   *
   * <p>This method checks explicit override via {@code CRYPTAD_SERVICE=1}, then inspects {@code
   * USERNAME} and {@code SESSIONNAME} for typical service values.
   *
   * @return {@code true} when running as a Windows service context, otherwise {@code false}
   */
  public boolean isWindowsService() {
    if (!isWindows()) {
      return false;
    }
    if ("1".equals(env.get(CRYPTAD_SERVICE_ENV))) {
      return true;
    }
    String user = uppercaseOrNull(env.get("USERNAME"));
    String session = uppercaseOrNull(env.get("SESSIONNAME"));
    return "SYSTEM".equals(user) || "SERVICES".equals(session);
  }

  /**
   * Reports whether macOS launchd-style service heuristics indicate service execution.
   *
   * <p>This method checks explicit override via {@code CRYPTAD_SERVICE=1}, then tests for root user
   * execution or presence of {@code LAUNCHD_JOB}.
   *
   * @return {@code true} when running as a macOS service context, otherwise {@code false}
   */
  public boolean isMacService() {
    if (!isMac()) {
      return false;
    }
    if ("1".equals(env.get(CRYPTAD_SERVICE_ENV))) {
      return true;
    }
    return "root".equals(userName) || env.containsKey("LAUNCHD_JOB");
  }

  /**
   * Resolves effective service mode using explicit override and platform-specific heuristics.
   *
   * <p>When the JVM property {@code cryptad.service.mode} is set to {@code service} or {@code
   * user}, that value takes precedence. Otherwise, this method combines generic and OS-specific
   * environment checks to infer service execution.
   *
   * @return {@code true} when service mode is active, otherwise {@code false}
   */
  public boolean isServiceMode() {
    String mode = System.getProperty("cryptad.service.mode");
    if (mode != null) {
      mode = mode.toLowerCase(Locale.ROOT);
      if ("service".equals(mode)) {
        return true;
      }
      if ("user".equals(mode)) {
        return false;
      }
    }
    return "1".equals(env.get(CRYPTAD_SERVICE_ENV))
        || isSystemdService()
        || isWindowsService()
        || isMacService();
  }

  /**
   * Returns the detected broad operating system family.
   *
   * @return OS family derived from the configured OS name
   */
  public OsKind osKind() {
    if (isWindows()) {
      return OsKind.WINDOWS;
    }
    if (isMac()) {
      return OsKind.MAC;
    }
    if (isLinux()) {
      return OsKind.LINUX;
    }
    return OsKind.OTHER;
  }

  /**
   * Returns a normalized CPU architecture label.
   *
   * <p>Architecture names containing {@code aarch64} or {@code arm64} map to {@code arm64}; all
   * other values currently map to {@code amd64}.
   *
   * @return normalized architecture label used by packaging logic
   */
  public String arch() {
    String prop = systemPropertyOrEmpty("os.arch").toLowerCase(Locale.ROOT);
    if (prop.contains("aarch64") || prop.contains("arm64")) {
      return "arm64";
    }
    return "amd64";
  }

  /**
   * Checks whether an executable command can be resolved from the current {@code PATH}.
   *
   * <p>Windows checks both the exact command and an additional {@code .exe} suffix candidate.
   *
   * @param cmd executable command name to search for
   * @return {@code true} when an executable candidate is found, otherwise {@code false}
   */
  public boolean onPath(String cmd) {
    String path = env.get("PATH");
    if (path == null) {
      return false;
    }
    char sep = File.pathSeparatorChar;
    boolean isWin = isWindows();
    Pattern pathSeparator = Pattern.compile(Pattern.quote(String.valueOf(sep)));
    String[] dirs = pathSeparator.split(path, 0);
    for (String dir : dirs) {
      File base = new File(dir, cmd);
      if (base.exists() && base.canExecute()) {
        return true;
      }
      if (isWin) {
        File withExe = new File(dir, cmd + ".exe");
        if (withExe.exists() && withExe.canExecute()) {
          return true;
        }
      }
    }
    return false;
  }

  /**
   * Returns the raw JVM operating system name used for OS-family detection.
   *
   * @return raw {@code os.name} value or an empty string when unavailable
   */
  public String osNameRaw() {
    return osName;
  }

  /**
   * Returns the raw JVM operating system version string.
   *
   * @return raw {@code os.version} value or an empty string when unavailable
   */
  public String osVersionRaw() {
    return systemPropertyOrEmpty("os.version");
  }

  /**
   * Detects package manager command availability by probing {@code PATH}.
   *
   * <p>Detection runs only for Linux-family environments and returns an immutable empty list on
   * other platforms. Commands are reported in probe order for known package tools.
   *
   * @return list containing discovered package manager commands for the current environment
   */
  public List<String> availableManagers() {
    if (!isLinux()) {
      return List.of();
    }
    List<String> managers = new ArrayList<>();
    if (onPath("flatpak")) {
      managers.add("flatpak");
    }
    if (onPath("snap")) {
      managers.add("snap");
    }
    if (onPath("dpkg")) {
      managers.add("dpkg");
    }
    if (onPath("rpm")) {
      managers.add("rpm");
    }
    return managers;
  }

  /**
   * Computes a compact summary of detected runtime environment characteristics.
   *
   * @return immutable environment summary containing OS family, architecture, and package managers
   */
  public EnvDetection detectEnvironment() {
    return new EnvDetection(osKind(), arch(), availableManagers());
  }

  private static String readIfExists(Path path) {
    try {
      if (Files.exists(path)) {
        return Files.readString(path);
      }
      return null;
    } catch (IOException _) {
      return null;
    }
  }

  private static String systemPropertyOrEmpty(String key) {
    String value = System.getProperty(key);
    return value != null ? value : "";
  }

  private static String uppercaseOrNull(String value) {
    return value == null ? null : value.toUpperCase(Locale.ROOT);
  }
}
