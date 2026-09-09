package network.crypta.platform.apphost.sandbox;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import network.crypta.fs.AppEnv;
import network.crypta.platform.appdist.AppSandboxMode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class BubblewrapSandboxProviderTest {
  private static final String SECRET_TOKEN = "secret-token";

  @TempDir private Path tempDir;

  @Test
  void supports_whenLinuxAndBwrapAvailable_expectRestrictedProcessOnly() {
    BubblewrapSandboxProvider provider = provider(linux(), true);

    assertTrue(provider.supports(new AppSandboxPolicy(AppSandboxMode.RESTRICTED_PROCESS, false)));
    assertFalse(provider.supports(new AppSandboxPolicy(AppSandboxMode.NONE, false)));
    assertFalse(provider.supports(new AppSandboxPolicy(AppSandboxMode.WASM_PREVIEW, false)));
  }

  @Test
  void supports_whenMacOrWindows_expectNoBubblewrapSupport() {
    BubblewrapSandboxProvider macProvider = provider(new AppEnv(Map.of(), "Mac OS X"), true);
    BubblewrapSandboxProvider windowsProvider = provider(new AppEnv(Map.of(), "Windows 11"), true);

    assertFalse(
        macProvider.supports(new AppSandboxPolicy(AppSandboxMode.RESTRICTED_PROCESS, false)));
    assertFalse(
        windowsProvider.supports(new AppSandboxPolicy(AppSandboxMode.RESTRICTED_PROCESS, false)));
  }

  @Test
  void supports_whenOtherUnixHost_expectNoBubblewrapSupport() {
    BubblewrapSandboxProvider provider = provider(new AppEnv(Map.of(), "FreeBSD"), true);

    assertFalse(provider.supports(new AppSandboxPolicy(AppSandboxMode.RESTRICTED_PROCESS, false)));
  }

  @Test
  void supports_whenExecutablePresentButNamespacePreflightFails_expectNoBubblewrapSupport() {
    BubblewrapSandboxProvider provider = provider(linux(), true, false);

    assertFalse(provider.supports(new AppSandboxPolicy(AppSandboxMode.RESTRICTED_PROCESS, false)));
  }

  @Test
  void prepareLaunch_whenBubblewrapAvailable_expectEnforcedWrappedCommand() throws Exception {
    AppSandboxLaunchContext context =
        context(new AppSandboxPolicy(AppSandboxMode.RESTRICTED_PROCESS, true));

    AppSandboxLaunchPlan plan = provider(linux(), true).prepareLaunch(context);

    assertEquals("bwrap", plan.command().getFirst());
    int separator = plan.command().indexOf("--");
    assertTrue(separator > 0);
    assertEquals(context.command(), plan.command().subList(separator + 1, plan.command().size()));
    assertEquals(context.environment(), plan.environment());
    assertEquals(context.workingDirectory(), plan.workingDirectory());
    assertTrue(plan.command().contains("--die-with-parent"));
    assertTrue(plan.command().contains("--new-session"));
    assertTrue(plan.command().contains("--unshare-pid"));
    assertTrue(plan.command().contains("--unshare-ipc"));
    assertTrue(plan.command().contains("--ro-bind"));
    assertTrue(plan.command().contains("--bind"));
    assertFalse(plan.command().contains("--unshare-net"));
    assertEquals(AppSandboxSupportLevel.ENFORCED, plan.sandboxStatus().supportLevel());
    assertEquals(BubblewrapSandboxProvider.PROVIDER_NAME, plan.sandboxStatus().providerName());
    assertTrue(plan.sandboxStatus().active());
    String publicStatusText = plan.sandboxStatus().toString().toLowerCase(java.util.Locale.ROOT);
    assertTrue(publicStatusText.contains("not enforced"));
    assertFalse(publicStatusText.contains("cpu isolation"));
    assertFalse(publicStatusText.contains("memory isolation"));
    assertFalse(publicStatusText.contains("network isolation"));
  }

  @Test
  void prepareLaunch_whenExplicitExecutableConfigured_expectCommandUsesNormalizedExecutable()
      throws Exception {
    Path executable = tempDir.resolve("tools").resolve("bwrap");
    AppSandboxLaunchContext context =
        context(new AppSandboxPolicy(AppSandboxMode.RESTRICTED_PROCESS, true));
    BubblewrapSandboxProvider provider =
        new BubblewrapSandboxProvider(availability(linux(), executable.toString(), true, true));

    AppSandboxLaunchPlan plan = provider.prepareLaunch(context);

    assertEquals(executable.toAbsolutePath().normalize().toString(), plan.command().getFirst());
  }

  @Test
  void probe_whenExplicitExecutableIsRelative_expectUnavailablePathFreeReason() {
    BubblewrapAvailability.Result result =
        availability(linux(), "relative/bwrap", true, true).probe();

    assertFalse(result.available());
    assertEquals(
        "configured bubblewrap executable must be an absolute path", result.unavailableReason());
    assertFalse(result.unavailableReason().contains("relative/bwrap"));
  }

  @Test
  void prepareLaunch_whenContextContainsToken_expectCommandDoesNotExposeEnvironmentValues()
      throws Exception {
    AppSandboxLaunchContext context =
        context(new AppSandboxPolicy(AppSandboxMode.RESTRICTED_PROCESS, false));

    AppSandboxLaunchPlan plan = provider(linux(), true).prepareLaunch(context);

    String commandText = plan.command().toString();
    assertFalse(commandText.contains("CRYPTAD_APP_TOKEN"));
    assertFalse(commandText.contains(SECRET_TOKEN));
    assertFalse(commandText.contains("--setenv"));
    assertFalse(plan.sandboxStatus().toString().contains(SECRET_TOKEN));
    assertFalse(plan.sandboxStatus().toString().contains(tempDir.toString()));
  }

  @Test
  void commandBuilder_whenBuildingPlan_expectAppMountsUseExpectedAccess() {
    AppSandboxLaunchContext context =
        context(new AppSandboxPolicy(AppSandboxMode.RESTRICTED_PROCESS, false));
    BubblewrapCommandBuilder.CommandPlan plan =
        new BubblewrapCommandBuilder().build("bwrap", context);

    assertMount(plan, context.installDir(), BubblewrapCommandBuilder.MountAccess.READ_ONLY);
    assertMount(plan, context.dataDir(), BubblewrapCommandBuilder.MountAccess.READ_WRITE);
    assertMount(plan, context.cacheDir(), BubblewrapCommandBuilder.MountAccess.READ_WRITE);
    assertMount(plan, context.runDir(), BubblewrapCommandBuilder.MountAccess.READ_WRITE);
    assertFalse(
        plan.bindMounts().stream()
            .anyMatch(mount -> mount.source().equals(tempDir.resolve("daemon-private"))));
  }

  @Test
  void commandBuilder_whenBuildingPlan_expectDirectoryMountsPrecedeBindMounts() {
    AppSandboxLaunchContext context =
        context(new AppSandboxPolicy(AppSandboxMode.RESTRICTED_PROCESS, false));

    BubblewrapCommandBuilder.CommandPlan plan =
        new BubblewrapCommandBuilder().build("bwrap", context);

    assertTrue(
        plan.directoryMounts()
            .contains(context.installDir().toAbsolutePath().normalize().getParent()));
    int firstDirectoryMount = plan.command().indexOf("--dir");
    int firstReadOnlyBind = plan.command().indexOf("--ro-bind");
    int firstReadWriteBind = plan.command().indexOf("--bind");
    int firstBindMount = Math.min(firstReadOnlyBind, firstReadWriteBind);
    assertTrue(firstDirectoryMount > 0);
    assertTrue(firstDirectoryMount < firstBindMount);
  }

  @Test
  void commandBuilder_whenDebianJavaSecuritySymlinked_expectOnlyPublicFilesMountedReadOnly()
      throws IOException {
    Path javaHome = tempDir.resolve("usr/lib/jvm/java-25");
    Path configuration = tempDir.resolve("etc/java-25-openjdk");
    Files.createDirectories(javaHome.resolve("conf/security"));
    Files.createDirectories(configuration.resolve("security"));
    Path security =
        Files.writeString(
            configuration.resolve("security/java.security"), "crypto.policy=unlimited\n");
    Files.createSymbolicLink(
        javaHome.resolve("conf/security/java.security"), security.toAbsolutePath());
    Files.createDirectories(configuration.resolve("management"));
    Path password =
        Files.writeString(configuration.resolve("management/jmxremote.password"), "PRIVATE_CANARY");
    Files.createDirectories(javaHome.resolve("conf/management"));
    Files.createSymbolicLink(
        javaHome.resolve("conf/management/jmxremote.password"), password.toAbsolutePath());
    AppSandboxLaunchContext context =
        context(new AppSandboxPolicy(AppSandboxMode.RESTRICTED_PROCESS, false));

    var plan =
        new BubblewrapCommandBuilder(List.of(tempDir.resolve("usr")), javaHome)
            .build("bwrap", context);

    assertMount(plan, security.toRealPath(), BubblewrapCommandBuilder.MountAccess.READ_ONLY);
    assertFalse(plan.bindMounts().stream().anyMatch(mount -> mount.source().equals(configuration)));
    assertFalse(
        plan.bindMounts().stream()
            .anyMatch(mount -> mount.source().equals(configuration.getParent())));
    assertFalse(plan.bindMounts().stream().anyMatch(mount -> mount.source().equals(password)));
    assertFalse(plan.command().toString().contains("PRIVATE_CANARY"));
  }

  @Test
  void commandBuilder_whenAlternativesDirectoryAvailable_expectReadOnlyMountWithoutEtcBind()
      throws IOException {
    Path alternatives = tempDir.resolve("etc").resolve("alternatives");
    Files.createDirectories(alternatives);
    AppSandboxLaunchContext context =
        context(new AppSandboxPolicy(AppSandboxMode.RESTRICTED_PROCESS, false));

    BubblewrapCommandBuilder.CommandPlan plan =
        new BubblewrapCommandBuilder(List.of(alternatives)).build("bwrap", context);

    assertMount(plan, alternatives, BubblewrapCommandBuilder.MountAccess.READ_ONLY);
    Path etc = alternatives.getParent().toAbsolutePath().normalize();
    assertTrue(plan.directoryMounts().contains(etc));
    assertFalse(
        plan.bindMounts().stream()
            .anyMatch(mount -> mount.source().equals(etc) && mount.destination().equals(etc)));
  }

  @Test
  void commandBuilder_whenResolverFilesAvailable_expectReadOnlyMountsWithoutEtcBind()
      throws IOException {
    Path etc = tempDir.resolve("etc");
    Path hosts =
        Files.writeString(Files.createDirectories(etc).resolve("hosts"), "127.0.0.1 localhost\n");
    Path nsswitch = Files.writeString(etc.resolve("nsswitch.conf"), "hosts: files dns\n");
    Path resolv = Files.writeString(etc.resolve("resolv.conf"), "nameserver 127.0.0.53\n");
    Path certificates = Files.createDirectories(etc.resolve("ssl").resolve("certs"));
    AppSandboxLaunchContext context =
        context(new AppSandboxPolicy(AppSandboxMode.RESTRICTED_PROCESS, false));

    BubblewrapCommandBuilder.CommandPlan plan =
        new BubblewrapCommandBuilder(List.of(hosts, nsswitch, resolv, certificates))
            .build("bwrap", context);

    assertMount(plan, hosts, BubblewrapCommandBuilder.MountAccess.READ_ONLY);
    assertMount(plan, nsswitch, BubblewrapCommandBuilder.MountAccess.READ_ONLY);
    assertMount(plan, resolv, BubblewrapCommandBuilder.MountAccess.READ_ONLY);
    assertMount(plan, certificates, BubblewrapCommandBuilder.MountAccess.READ_ONLY);
    assertTrue(plan.directoryMounts().contains(etc.toAbsolutePath().normalize()));
    assertFalse(
        plan.bindMounts().stream()
            .anyMatch(
                mount ->
                    mount.source().equals(etc.toAbsolutePath().normalize())
                        && mount.destination().equals(etc.toAbsolutePath().normalize())));
  }

  @Test
  void commandBuilder_whenLinuxbrewPrefixAvailable_expectReadOnlyMountWithoutHomeBind()
      throws IOException {
    Path linuxbrew = tempDir.resolve("home").resolve("linuxbrew").resolve(".linuxbrew");
    Files.createDirectories(linuxbrew.resolve("bin"));
    AppSandboxLaunchContext context =
        context(new AppSandboxPolicy(AppSandboxMode.RESTRICTED_PROCESS, false));

    BubblewrapCommandBuilder.CommandPlan plan =
        new BubblewrapCommandBuilder(List.of(linuxbrew)).build("bwrap", context);

    assertMount(plan, linuxbrew, BubblewrapCommandBuilder.MountAccess.READ_ONLY);
    assertTrue(plan.directoryMounts().contains(linuxbrew.getParent()));
    assertFalse(
        plan.bindMounts().stream()
            .anyMatch(mount -> mount.source().equals(linuxbrew.getParent().getParent())));
  }

  @Test
  void commandBuilder_whenUsingDefaults_expectSystemResolverAndAlternativesConsidered() {
    assertTrue(
        BubblewrapCommandBuilder.DEFAULT_SYSTEM_READ_ONLY_PATHS.contains(
            BubblewrapCommandBuilder.ETC_ALTERNATIVES));
    assertTrue(
        BubblewrapCommandBuilder.DEFAULT_SYSTEM_READ_ONLY_PATHS.contains(
            BubblewrapCommandBuilder.ETC_HOSTS));
    assertTrue(
        BubblewrapCommandBuilder.DEFAULT_SYSTEM_READ_ONLY_PATHS.contains(
            BubblewrapCommandBuilder.ETC_NSSWITCH_CONF));
    assertTrue(
        BubblewrapCommandBuilder.DEFAULT_SYSTEM_READ_ONLY_PATHS.contains(
            BubblewrapCommandBuilder.ETC_RESOLV_CONF));
    assertTrue(
        BubblewrapCommandBuilder.DEFAULT_SYSTEM_READ_ONLY_PATHS.contains(
            BubblewrapCommandBuilder.ETC_SSL_CERTS));
    assertTrue(
        BubblewrapCommandBuilder.DEFAULT_SYSTEM_READ_ONLY_PATHS.contains(
            BubblewrapCommandBuilder.LINUXBREW_PREFIX));
  }

  @Test
  void commandBuilder_whenExecutableBlank_expectRejectsLaunchPlan() {
    AppSandboxLaunchContext context =
        context(new AppSandboxPolicy(AppSandboxMode.RESTRICTED_PROCESS, false));
    BubblewrapCommandBuilder commandBuilder = new BubblewrapCommandBuilder();

    assertThrows(IllegalArgumentException.class, () -> commandBuilder.build("  ", context));
  }

  @Test
  void prepareLaunch_whenBubblewrapUnavailable_expectPathFreeUnsupportedFailure() {
    AppSandboxLaunchContext context =
        context(new AppSandboxPolicy(AppSandboxMode.RESTRICTED_PROCESS, true));

    AppSandboxException exception =
        assertThrows(
            AppSandboxException.class, () -> provider(linux(), false).prepareLaunch(context));

    assertEquals("unsupported_sandbox", exception.errorCode());
    assertFalse(exception.getMessage().contains(SECRET_TOKEN));
    assertFalse(exception.getMessage().contains(tempDir.toString()));
    assertTrue(exception.sandboxStatus().isPresent());
  }

  private static void assertMount(
      BubblewrapCommandBuilder.CommandPlan plan,
      Path destination,
      BubblewrapCommandBuilder.MountAccess access) {
    Path normalized = destination.toAbsolutePath().normalize();
    assertTrue(
        plan.bindMounts().stream()
            .anyMatch(
                mount ->
                    mount.destination().equals(normalized)
                        && mount.source().equals(normalized)
                        && mount.access() == access),
        () -> "missing " + access + " mount for " + normalized);
  }

  private BubblewrapSandboxProvider provider(AppEnv appEnv, boolean available) {
    return provider(appEnv, available, available);
  }

  private BubblewrapSandboxProvider provider(
      AppEnv appEnv, boolean executableAvailable, boolean namespaceAvailable) {
    return new BubblewrapSandboxProvider(
        availability(appEnv, "", executableAvailable, namespaceAvailable));
  }

  private BubblewrapAvailability availability(
      AppEnv appEnv,
      String configuredExecutable,
      boolean executableAvailable,
      boolean namespaceAvailable) {
    return new BubblewrapAvailability(
        appEnv,
        configuredExecutable,
        new BubblewrapAvailability.ExecutableProbe() {
          @Override
          public boolean onPath(AppEnv ignoredAppEnv, String command) {
            return executableAvailable;
          }

          @Override
          public boolean isExecutable(Path executable) {
            return executableAvailable;
          }

          @Override
          public boolean sandboxPreflightFails(String executable) {
            return !namespaceAvailable;
          }
        });
  }

  @Test
  void mailRuntimeOutsideSystemPathsMountsOnlyExecutableLibrariesAndPublicSecurity()
      throws IOException {
    Path home = tempDir.resolve("private host/runtime with spaces");
    Files.createDirectories(home.resolve("bin"));
    Files.createDirectories(home.resolve("lib"));
    Files.createDirectories(home.resolve("conf/security"));
    Files.writeString(home.resolve("conf/security/java.security"), "crypto.policy=unlimited");
    Files.createDirectories(home.resolve("conf/management"));
    Path password = Files.writeString(home.resolve("conf/management/jmxremote.password"), "CANARY");
    var ordinary = context(new AppSandboxPolicy(AppSandboxMode.RESTRICTED_PROCESS, false));
    var mail =
        new AppSandboxLaunchContext(
            "mail-prototype",
            ordinary.installDir(),
            ordinary.dataDir(),
            ordinary.cacheDir(),
            ordinary.runDir(),
            ordinary.logDir(),
            ordinary.command(),
            Map.of("CRYPTAD_MAIL_JAVA", tempDir.resolve("untrusted/java").toString()),
            ordinary.workingDirectory(),
            ordinary.policy(),
            ordinary.appEnv());
    var builder = new BubblewrapCommandBuilder(List.of(), home);

    var plan = builder.build("bwrap", mail);

    assertMount(plan, home.resolve("bin"), BubblewrapCommandBuilder.MountAccess.READ_ONLY);
    assertMount(plan, home.resolve("lib"), BubblewrapCommandBuilder.MountAccess.READ_ONLY);
    assertMount(
        plan,
        home.resolve("conf/security/java.security"),
        BubblewrapCommandBuilder.MountAccess.READ_ONLY);
    assertFalse(
        plan.bindMounts().stream()
            .anyMatch(
                m ->
                    m.source().equals(home)
                        || m.source().equals(home.getParent())
                        || m.source().equals(home.resolve("conf"))
                        || m.source().equals(password)
                        || m.source().toString().contains("untrusted")));
    assertFalse(
        builder.build("bwrap", ordinary).bindMounts().stream()
            .anyMatch(
                m ->
                    m.source().equals(home.resolve("bin"))
                        || m.source().equals(home.resolve("lib"))));

    Path system = Files.createDirectories(tempDir.resolve("system-runtime"));
    Path linkedHome = Files.createDirectories(system.resolve("jdk"));
    Files.createDirectories(linkedHome.resolve("bin"));
    Path sharedLibraries = Files.createDirectories(tempDir.resolve("private-runtime-libraries"));
    Files.createSymbolicLink(linkedHome.resolve("lib"), sharedLibraries);
    var linkedPlan = new BubblewrapCommandBuilder(List.of(system), linkedHome).build("bwrap", mail);
    assertMount(linkedPlan, sharedLibraries, BubblewrapCommandBuilder.MountAccess.READ_ONLY);
    assertFalse(linkedPlan.bindMounts().stream().anyMatch(m -> m.source().equals(tempDir)));
  }

  @Test
  void externalRuntimeSecuritySymlinkIsMountedAtLookupPathEvenWithSystemTarget()
      throws IOException {
    Path home = Files.createDirectories(tempDir.resolve("external-jdk"));
    Path system = Files.createDirectories(tempDir.resolve("system"));
    Path security = Files.writeString(system.resolve("java.security"), "crypto.policy=unlimited");
    Path lookup = home.resolve("conf/security/java.security");
    Files.createDirectories(lookup.getParent());
    Files.createSymbolicLink(lookup, security);
    var context = context(new AppSandboxPolicy(AppSandboxMode.RESTRICTED_PROCESS, false));

    var plan = new BubblewrapCommandBuilder(List.of(system), home).build("bwrap", context);

    assertTrue(
        plan.bindMounts().stream()
            .anyMatch(
                m ->
                    m.source().equals(security)
                        && m.destination().equals(lookup)
                        && m.access() == BubblewrapCommandBuilder.MountAccess.READ_ONLY));
    assertFalse(
        plan.bindMounts().stream().anyMatch(m -> m.destination().equals(home.resolve("conf"))));
  }

  @Test
  void relocatedJavaWithSymlinkedSecurityStartsInsideRealSandbox() throws Exception {
    AppEnv appEnv = new AppEnv();
    var availability = new BubblewrapAvailability(appEnv).probe();
    assumeTrue(availability.available(), availability.unavailableReason());
    Path originalHome = appEnv.javaHome().toRealPath();
    Path home = Files.createDirectories(tempDir.resolve("private runtime/jdk"));
    Files.createDirectories(home.resolve("bin"));
    Files.copy(
        originalHome.resolve("bin/java"),
        home.resolve("bin/java"),
        StandardCopyOption.COPY_ATTRIBUTES);
    Files.createSymbolicLink(home.resolve("lib"), originalHome.resolve("lib"));
    Path publicConfiguration = Files.createDirectories(tempDir.resolve("public-security"));
    for (String relative :
        List.of(
            "java.security",
            "policy/unlimited/default_US_export.policy",
            "policy/unlimited/default_local.policy")) {
      Path source = publicConfiguration.resolve(relative);
      Files.createDirectories(source.getParent());
      Files.copy(originalHome.resolve("conf/security").resolve(relative), source);
      Path lookup = home.resolve("conf/security").resolve(relative);
      Files.createDirectories(lookup.getParent());
      Files.createSymbolicLink(lookup, source);
    }
    Path privateConfig = home.resolve("conf/management/jmxremote.password");
    Files.createDirectories(privateConfig.getParent());
    Files.writeString(privateConfig, "PRIVATE_CANARY");
    var ordinary = context(new AppSandboxPolicy(AppSandboxMode.RESTRICTED_PROCESS, false));
    for (Path directory :
        List.of(ordinary.installDir(), ordinary.dataDir(), ordinary.cacheDir(), ordinary.runDir()))
      Files.createDirectories(directory);
    Path probe = ordinary.installDir().resolve("SecurityProbe.java");
    Files.writeString(
        probe,
        """
        import java.nio.file.*;
        import java.security.*;
        class SecurityProbe {
          public static void main(String[] args) throws Exception {
            if (Security.getProperty("crypto.policy") == null || Files.exists(Path.of(args[0])))
              throw new AssertionError("Security configuration boundary failed");
            KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
            System.out.println("security-ready");
          }
        }
        """);
    var mail =
        new AppSandboxLaunchContext(
            "mail-prototype",
            ordinary.installDir(),
            ordinary.dataDir(),
            ordinary.cacheDir(),
            ordinary.runDir(),
            ordinary.logDir(),
            List.of(
                home.resolve("bin/java").toString(), probe.toString(), privateConfig.toString()),
            Map.of(),
            ordinary.workingDirectory(),
            ordinary.policy(),
            appEnv);
    var plan =
        new BubblewrapCommandBuilder(BubblewrapCommandBuilder.DEFAULT_SYSTEM_READ_ONLY_PATHS, home)
            .build(availability.executable(), mail);
    Path output = tempDir.resolve("java-probe.log");
    Process process =
        new ProcessBuilder(plan.command())
            .redirectErrorStream(true)
            .redirectOutput(output.toFile())
            .start();
    try {
      assertTrue(process.waitFor(30, TimeUnit.SECONDS), "Java probe timed out");
      assertEquals(0, process.exitValue(), Files.readString(output));
      assertTrue(Files.readString(output).contains("security-ready"));
    } finally {
      process.destroyForcibly();
    }
  }

  private AppSandboxLaunchContext context(AppSandboxPolicy policy) {
    return new AppSandboxLaunchContext(
        "sample-app",
        tempDir.resolve("installed").resolve("sample-app"),
        tempDir.resolve("data").resolve("sample-app"),
        tempDir.resolve("cache").resolve("sample-app"),
        tempDir.resolve("run").resolve("sample-app"),
        tempDir.resolve("run").resolve("sample-app"),
        List.of("bin/launch.sh", "--serve"),
        Map.of("CRYPTAD_APP_ID", "sample-app", "CRYPTAD_APP_TOKEN", SECRET_TOKEN),
        tempDir.resolve("installed").resolve("sample-app"),
        policy,
        linux());
  }

  private static AppEnv linux() {
    return new AppEnv(Map.of(), "Linux");
  }
}
