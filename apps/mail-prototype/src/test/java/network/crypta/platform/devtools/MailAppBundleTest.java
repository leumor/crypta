package network.crypta.platform.devtools;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;
import java.util.jar.JarFile;
import network.crypta.platform.appdist.AppApiCompatibilityMetadata.TargetStability;
import network.crypta.platform.apphost.manifest.AppManifestParser;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MailAppBundleTest {
  @TempDir Path temporary;

  @Test
  void stagedWorkerAndManifestRetainExperimentalProcessBoundary() throws Exception {
    Path staged = stage();
    var manifest = AppManifestParser.parse(staged.resolve("cryptad-app.properties"));
    assertEquals("mail-prototype", manifest.appId());
    assertEquals(TargetStability.EXPERIMENTAL, manifest.apiCompatibility().targetStability());
    assertTrue(manifest.apiCompatibility().experimentalCapabilitiesAccepted());
    assertTrue(manifest.permissions().contains("mail.control"));
    assertFalse(manifest.permissions().contains("vault.secrets.read"));
    assertFalse(manifest.permissions().contains("vault.identities.manage"));
    assertFalse(manifest.permissions().contains("app.services.call"));
    boolean workerFound = false;
    boolean hpkeFound = false;
    try (var jars = Files.list(staged.resolve("lib"))) {
      for (Path jar : jars.filter(path -> path.toString().endsWith(".jar")).toList()) {
        try (JarFile archive = new JarFile(jar.toFile())) {
          var worker = archive.getJarEntry("network/crypta/apps/mail/MailWorker.class");
          if (worker != null) {
            workerFound = true;
            try (var input = archive.getInputStream(worker)) {
              byte[] header = input.readNBytes(8);
              assertEquals(8, header.length);
              int major = ((header[6] & 255) << 8) | (header[7] & 255);
              assertTrue(major >= 69, "Worker requires Java 25 or later.");
            }
          }
          if (archive.getJarEntry("org/bouncycastle/crypto/hpke/HPKE.class") != null)
            hpkeFound = true;
        }
      }
    }
    assertTrue(workerFound, "Signed staged payload must contain the actual Java worker.");
    assertTrue(hpkeFound, "Signed staged payload must contain its HPKE runtime library.");
  }

  @Test
  void stagedUiPassesActualStrictOfflineCliLint() {
    StringWriter output = new StringWriter();
    int exit =
        CryptaAppCli.execute(
            new PrintWriter(output),
            new PrintWriter(output),
            "ui",
            "lint",
            "--bundle-dir",
            stage().toString(),
            "--strict");
    assertEquals(0, exit, output.toString());
  }

  @Test
  void actualUiScriptKeepsMarkupInertAndRequiresExplicitOperations() throws Exception {
    Path harness = temporary.resolve("mail-ui-behavior.cjs");
    try (var resource = getClass().getResourceAsStream("/mail-ui-behavior.cjs")) {
      assertNotNull(resource);
      Files.copy(resource, harness);
    }
    Process child =
        new ProcessBuilder("node", harness.toString(), stage().resolve("static/app.js").toString())
            .start();
    boolean finished = child.waitFor(20, TimeUnit.SECONDS);
    if (!finished) child.destroyForcibly();
    assertTrue(finished, "UI behavior harness timed out.");
    String output =
        new String(child.getInputStream().readAllBytes(), StandardCharsets.UTF_8)
            + new String(child.getErrorStream().readAllBytes(), StandardCharsets.UTF_8);
    assertEquals(0, child.exitValue(), output);
  }

  @Test
  void launcherUsesQuotedHostJavaAndIgnoresConflictingPathJava() throws Exception {
    org.junit.jupiter.api.Assumptions.assumeTrue(
        new network.crypta.fs.AppEnv().onPath("sh")
            && Files.getFileStore(temporary).supportsFileAttributeView("posix"),
        "POSIX launcher test requires an executable shell and POSIX file permissions.");
    Path bundle = Files.createDirectories(temporary.resolve("bundle with spaces"));
    Path bin = Files.createDirectories(bundle.resolve("bin"));
    Path launcher =
        Files.copy(stage().resolve("bin/mail-prototype.sh"), bin.resolve("mail-prototype.sh"));
    Path selected =
        Files.createDirectories(temporary.resolve("host runtime with spaces")).resolve("java");
    Files.writeString(selected, "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$MAIL_TEST_ARGUMENTS\"\n");
    Files.setPosixFilePermissions(
        selected, java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"));
    Path poisonDirectory = Files.createDirectories(temporary.resolve("poison-path"));
    Path poison = poisonDirectory.resolve("java");
    Files.writeString(
        poison, "#!/bin/sh\nprintf poisoned > \"$MAIL_TEST_POISON_MARKER\"\nexit 99\n");
    Files.setPosixFilePermissions(
        poison, java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"));
    Path arguments = temporary.resolve("selected-java-arguments");
    Path poisonMarker = temporary.resolve("poison-marker");
    ProcessBuilder builder = new ProcessBuilder("sh", launcher.toString());
    builder.directory(temporary.toFile());
    builder.environment().clear();
    builder.environment().put("PATH", poisonDirectory + ":/usr/bin:/bin");
    builder.environment().put("CRYPTAD_APP_TOKEN", "SYNTHETIC_PROCESS_TOKEN_CANARY");
    builder.environment().put("CRYPTAD_MAIL_API_ENDPOINT", "http://127.0.0.1:1/api/v1");
    builder.environment().put("CRYPTAD_MAIL_JAVA", selected.toString());
    builder.environment().put("MAIL_TEST_ARGUMENTS", arguments.toString());
    builder.environment().put("MAIL_TEST_POISON_MARKER", poisonMarker.toString());
    Process child = builder.start();
    try {
      assertTrue(
          child.waitFor(10, TimeUnit.SECONDS), "Launcher did not exit within its test deadline.");
      assertEquals(0, child.exitValue());
      assertFalse(Files.exists(poisonMarker), "Launcher executed Java selected by PATH.");
      var passedArguments = Files.readAllLines(arguments);
      assertEquals(3, passedArguments.size());
      assertEquals("-cp", passedArguments.get(0));
      assertTrue(passedArguments.get(1).endsWith("/*"));
      String classpathRoot =
          passedArguments.get(1).substring(0, passedArguments.get(1).length() - 2);
      assertTrue(
          Path.of(classpathRoot).normalize().equals(bundle.resolve("lib")),
          "Launcher classpath was not bundle-relative.");
      assertEquals("network.crypta.apps.mail.MailWorker", passedArguments.get(2));
      assertEquals(0, child.getInputStream().readAllBytes().length);
      assertEquals(0, child.getErrorStream().readAllBytes().length);
    } finally {
      child.destroyForcibly();
    }
  }

  @Test
  void launcherWithoutHostJavaFailsBeforeExecutingPathJava() throws Exception {
    org.junit.jupiter.api.Assumptions.assumeTrue(
        new network.crypta.fs.AppEnv().onPath("sh")
            && Files.getFileStore(temporary).supportsFileAttributeView("posix"),
        "POSIX launcher test requires an executable shell and POSIX file permissions.");
    Path poison = temporary.resolve("java");
    Path poisonMarker = temporary.resolve("poison-marker");
    Files.writeString(
        poison, "#!/bin/sh\nprintf poisoned > \"$MAIL_TEST_POISON_MARKER\"\nexit 99\n");
    Files.setPosixFilePermissions(
        poison, java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"));
    ProcessBuilder builder =
        new ProcessBuilder("sh", stage().resolve("bin/mail-prototype.sh").toString());
    builder.environment().clear();
    builder.environment().put("PATH", temporary + ":/usr/bin:/bin");
    builder.environment().put("CRYPTAD_APP_TOKEN", "SYNTHETIC_PROCESS_TOKEN_CANARY");
    builder.environment().put("CRYPTAD_MAIL_API_ENDPOINT", "http://127.0.0.1:1/api/v1");
    builder.environment().put("MAIL_TEST_POISON_MARKER", poisonMarker.toString());
    Process child = builder.start();
    try {
      assertTrue(child.waitFor(10, TimeUnit.SECONDS), "Launcher did not reject missing host Java.");
      assertTrue(child.exitValue() != 0);
      assertFalse(Files.exists(poisonMarker), "Missing host Java must not fall back to PATH.");
      String output =
          new String(child.getInputStream().readAllBytes(), StandardCharsets.UTF_8)
              + new String(child.getErrorStream().readAllBytes(), StandardCharsets.UTF_8);
      assertFalse(output.contains("SYNTHETIC_PROCESS_TOKEN_CANARY"));
      assertFalse(output.contains("http://127.0.0.1:1/api/v1"));
    } finally {
      child.destroyForcibly();
    }
  }

  private static Path stage() {
    return Path.of(System.getProperty("mailPrototype.stageDir"));
  }
}
