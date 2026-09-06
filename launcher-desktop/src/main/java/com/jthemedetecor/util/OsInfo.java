package com.jthemedetecor.util;

import io.github.g00fy2.versioncompare.Version;
import java.util.Locale;
import network.crypta.fs.AppEnv;
import org.jetbrains.annotations.NotNull;
import oshi.SystemInfo;
import oshi.software.os.OperatingSystem;
import oshi.util.PlatformEnum;

/**
 * Static helpers describing the current operating system and desktop environment.
 *
 * <p>This utility snapshots platform metadata from {@link AppEnv} and OSHI during class
 * initialization and exposes convenience predicates used by the vendored theme detectors. The
 * cached values keep repeated platform checks cheap and stable for the lifetime of the process,
 * which is enough for launcher theme-detection logic because the host operating system family and
 * version do not change while the JVM is running.
 *
 * <p>The helper focuses on detector selection rather than exhaustive platform introspection. It
 * combines AppEnv platform detection and OSHI version information with environment-variable checks
 * for Linux desktop environments and version comparisons for operating systems whose theme APIs
 * changed across major releases.
 */
public class OsInfo {
  private static final PlatformEnum PLATFORM_TYPE;
  private static final String FAMILY;
  private static final String VERSION;

  static {
    final SystemInfo systemInfo = new SystemInfo();
    final OperatingSystem osInfo = systemInfo.getOperatingSystem();
    final OperatingSystem.OSVersionInfo osVersionInfo = osInfo.getVersionInfo();

    PLATFORM_TYPE = detectPlatform(new AppEnv());
    FAMILY = osInfo.getFamily();
    VERSION = osVersionInfo.getVersion();
  }

  static PlatformEnum detectPlatform(AppEnv env) {
    return switch (env.osKind()) {
      case WINDOWS -> PlatformEnum.WINDOWS;
      case MAC -> PlatformEnum.MACOS;
      // AppEnv groups non-Windows/macOS hosts as Linux; retain OSHI's finer identities.
      case LINUX, OTHER -> PlatformEnum.getCurrentPlatform();
    };
  }

  /**
   * Returns whether the current host is Windows 10 or a newer Windows release.
   *
   * <p>This predicate is used to decide whether Windows registry-based dark-mode detection is
   * available.
   *
   * @return {@code true} when the current platform is Windows and its version is at least 10
   */
  public static boolean isWindows10OrLater() {
    return hasTypeAndVersionOrHigher(PlatformEnum.WINDOWS, "10");
  }

  /**
   * Returns whether the current host platform is Linux.
   *
   * @return {@code true} when OSHI reports the current platform as Linux
   */
  public static boolean isLinux() {
    return hasType(PlatformEnum.LINUX);
  }

  /**
   * Returns whether the current host is macOS Mojave or a newer macOS release.
   *
   * <p>Mojave introduced the system-wide dark-mode support used by the macOS detector.
   *
   * @return {@code true} when the current platform is macOS and its version is at least 10.14
   */
  public static boolean isMacOsMojaveOrLater() {
    return hasTypeAndVersionOrHigher(PlatformEnum.MACOS, "10.14");
  }

  /**
   * Returns the current Linux desktop-environment identifier from {@code XDG_CURRENT_DESKTOP}.
   *
   * <p>An empty string is returned when the environment variable is absent, so callers can perform
   * simple containment checks without additional null handling.
   *
   * @return the current desktop-environment name, or an empty string when it is unavailable
   */
  @NotNull
  public static String getCurrentLinuxDesktopEnvironmentName() {
    String currentDesktop = System.getenv("XDG_CURRENT_DESKTOP");
    return currentDesktop == null ? "" : currentDesktop;
  }

  /**
   * Returns whether the current Linux desktop environment appears to be GNOME.
   *
   * @return {@code true} when the platform is Linux and the desktop name contains {@code gnome}
   */
  public static boolean isGnome() {
    return isLinux()
        && getCurrentLinuxDesktopEnvironmentName().toLowerCase(Locale.ROOT).contains("gnome");
  }

  /**
   * Returns whether the current Linux desktop environment appears to be KDE.
   *
   * @return {@code true} when the platform is Linux and the desktop name contains {@code kde}
   */
  public static boolean isKde() {
    return isLinux()
        && getCurrentLinuxDesktopEnvironmentName()
            .toLowerCase(Locale.ROOT)
            .contains("KDE".toLowerCase(Locale.ROOT));
  }

  /**
   * Returns whether the current platform matches the supplied OSHI platform type.
   *
   * @param platformType platform enum to compare against the cached runtime platform
   * @return {@code true} when the cached runtime platform equals {@code platformType}
   */
  public static boolean hasType(PlatformEnum platformType) {
    return PLATFORM_TYPE.equals(platformType);
  }

  /**
   * Returns whether the cached operating-system version is at least the supplied version string.
   *
   * @param version minimum version required for the caller's feature gate
   * @return {@code true} when the cached operating-system version is greater than or equal to it
   */
  public static boolean isVersionAtLeast(String version) {
    return new Version(VERSION).isAtLeast(version);
  }

  /**
   * Returns whether both the platform type and minimum version requirements are satisfied.
   *
   * @param platformType platform enum that must match the current runtime
   * @param version minimum operating-system version required for the feature check
   * @return {@code true} when the runtime platform matches and its version is high enough
   */
  public static boolean hasTypeAndVersionOrHigher(PlatformEnum platformType, String version) {
    return hasType(platformType) && isVersionAtLeast(version);
  }

  /**
   * Returns the cached operating-system version string reported by OSHI.
   *
   * @return the runtime operating-system version captured during class initialization
   */
  public static String getVersion() {
    return VERSION;
  }

  /**
   * Returns the cached operating-system family reported by OSHI.
   *
   * @return the runtime operating-system family captured during class initialization
   */
  public static String getFamily() {
    return FAMILY;
  }

  private OsInfo() {}
}
