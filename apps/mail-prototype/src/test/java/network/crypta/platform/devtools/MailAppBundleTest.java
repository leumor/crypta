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

  private static Path stage() {
    return Path.of(System.getProperty("mailPrototype.stageDir"));
  }
}
