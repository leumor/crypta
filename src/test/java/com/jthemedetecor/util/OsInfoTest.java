package com.jthemedetecor.util;

import io.github.g00fy2.versioncompare.Version;
import java.util.Arrays;
import java.util.Locale;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import oshi.SystemInfo;
import oshi.software.os.OperatingSystem;
import oshi.util.PlatformEnum;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class OsInfoTest {
  private static final PlatformEnum CURRENT_PLATFORM = PlatformEnum.getCurrentPlatform();

  @ParameterizedTest
  @EnumSource(PlatformEnum.class)
  void hasType_whenComparedAgainstEachPlatform_expectCurrentPlatformMatch(PlatformEnum platform) {
    boolean expected = CURRENT_PLATFORM.equals(platform);

    boolean hasType = OsInfo.hasType(platform);

    assertEquals(expected, hasType);
  }

  @Test
  void getFamily_whenCalled_expectCurrentOperatingSystemFamily() {
    String expectedFamily = currentOperatingSystem().getFamily();

    String family = OsInfo.getFamily();

    assertEquals(expectedFamily, family);
  }

  @Test
  void getVersion_whenCalled_expectCurrentOperatingSystemVersion() {
    String expectedVersion = currentOperatingSystem().getVersionInfo().getVersion();

    String version = OsInfo.getVersion();

    assertEquals(expectedVersion, version);
  }

  @Test
  void getCurrentLinuxDesktopEnvironmentName_whenCalled_expectEnvironmentValueOrEmptyString() {
    String expectedDesktop = expectedDesktopEnvironmentName();

    String currentDesktop = OsInfo.getCurrentLinuxDesktopEnvironmentName();

    assertAll(
        () -> assertNotNull(currentDesktop), () -> assertEquals(expectedDesktop, currentDesktop));
  }

  @ParameterizedTest
  @MethodSource("versionCandidates")
  void isVersionAtLeast_whenComparedAgainstCandidate_expectOracleMatch(String versionCandidate) {
    boolean expected = new Version(OsInfo.getVersion()).isAtLeast(versionCandidate);

    boolean actual = OsInfo.isVersionAtLeast(versionCandidate);

    assertEquals(expected, actual);
  }

  @Test
  void hasTypeAndVersionOrHigher_whenCurrentPlatformAndVersion_expectTrue() {
    boolean hasRequiredPlatformAndVersion =
        OsInfo.hasTypeAndVersionOrHigher(CURRENT_PLATFORM, OsInfo.getVersion());

    assertTrue(hasRequiredPlatformAndVersion);
  }

  @Test
  void hasTypeAndVersionOrHigher_whenDifferentPlatform_expectFalse() {
    PlatformEnum differentPlatform = differentPlatform();

    boolean hasRequiredPlatformAndVersion =
        OsInfo.hasTypeAndVersionOrHigher(differentPlatform, OsInfo.getVersion());

    assertFalse(hasRequiredPlatformAndVersion);
  }

  @Test
  void isLinux_whenCalled_expectSameResultAsPlatformPredicate() {
    boolean expected = OsInfo.hasType(PlatformEnum.LINUX);

    boolean isLinux = OsInfo.isLinux();

    assertEquals(expected, isLinux);
  }

  @Test
  void isWindows10OrLater_whenCalled_expectSameResultAsSharedPredicate() {
    boolean expected = OsInfo.hasTypeAndVersionOrHigher(PlatformEnum.WINDOWS, "10");

    boolean isWindows10OrLater = OsInfo.isWindows10OrLater();

    assertEquals(expected, isWindows10OrLater);
  }

  @Test
  void isMacOsMojaveOrLater_whenCalled_expectSameResultAsSharedPredicate() {
    boolean expected = OsInfo.hasTypeAndVersionOrHigher(PlatformEnum.MACOS, "10.14");

    boolean isMacOsMojaveOrLater = OsInfo.isMacOsMojaveOrLater();

    assertEquals(expected, isMacOsMojaveOrLater);
  }

  @Test
  void isGnome_whenCalled_expectLinuxDesktopEnvironmentMatch() {
    boolean expected =
        OsInfo.isLinux()
            && expectedDesktopEnvironmentName().toLowerCase(Locale.ROOT).contains("gnome");

    boolean isGnome = OsInfo.isGnome();

    assertEquals(expected, isGnome);
  }

  @Test
  void isKde_whenCalled_expectLinuxDesktopEnvironmentMatch() {
    boolean expected =
        OsInfo.isLinux()
            && expectedDesktopEnvironmentName().toLowerCase(Locale.ROOT).contains("kde");

    boolean isKde = OsInfo.isKde();

    assertEquals(expected, isKde);
  }

  private static OperatingSystem currentOperatingSystem() {
    return new SystemInfo().getOperatingSystem();
  }

  private static String expectedDesktopEnvironmentName() {
    String currentDesktop = System.getenv("XDG_CURRENT_DESKTOP");
    return currentDesktop == null ? "" : currentDesktop;
  }

  private static Stream<String> versionCandidates() {
    return Stream.of(OsInfo.getVersion(), "0", "10", "10.14", "99999.0");
  }

  private static PlatformEnum differentPlatform() {
    return Arrays.stream(PlatformEnum.values())
        .filter(platform -> !CURRENT_PLATFORM.equals(platform))
        .findFirst()
        .orElseThrow();
  }
}
