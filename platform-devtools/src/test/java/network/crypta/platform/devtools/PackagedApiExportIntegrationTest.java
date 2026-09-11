package network.crypta.platform.devtools;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import javax.tools.ToolProvider;
import network.crypta.platform.api.PackagedApiExport;
import network.crypta.platform.api.PlatformApiContract;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PackagedApiExportIntegrationTest {
  @TempDir Path temporary;

  @Test
  void export_whenEqualLabelsHaveDifferentCompiledSurfaces_expectPackageSpecificBytes()
      throws Exception {
    Path first = packageJar(false);
    Path second = packageJar(true);

    String original = execute(first, false);
    String changed = execute(second, false);

    assertTrue(original.contains("\\\"contractVersion\\\":26"));
    assertTrue(changed.contains("\\\"contractVersion\\\":26"));
    assertFalse(original.contains("/synthetic-mail/"));
    assertTrue(changed.contains("/synthetic-mail/"));
    assertNotEquals(original, changed);
    assertEquals(original, execute(first, true));
    assertEquals(changed, execute(second, true));
    Path historical = temporary.resolve("historical.jar");
    try (var archive = new java.util.jar.JarFile(first.toFile());
        var output = new JarOutputStream(Files.newOutputStream(historical))) {
      for (var member : archive.stream().toList()) {
        if (member.getName().endsWith("/PackagedApiExport.class")) continue;
        output.putNextEntry(new JarEntry(member.getName()));
        try (var input = archive.getInputStream(member)) {
          input.transferTo(output);
        }
        output.closeEntry();
      }
    }
    assertEquals(original, execute(historical, true));
  }

  private Path packageJar(boolean changed) throws Exception {
    Path apiClasses =
        Path.of(
            PlatformApiContract.class.getProtectionDomain().getCodeSource().getLocation().toURI());
    Path replacement = temporary.resolve(changed ? "changed" : "original");
    Files.createDirectories(replacement);
    if (changed) {
      Path repository = Path.of("").toAbsolutePath();
      while (!Files.isDirectory(repository.resolve("platform-api/src/main/java")))
        repository =
            java.util.Objects.requireNonNull(
                repository.getParent(), "repository source root missing");
      Path source =
          repository.resolve(
              "platform-api/src/main/java/network/crypta/platform/api/PlatformApiContract.java");
      String original = Files.readString(source);
      String modified = original.replace("\"/mail/\" + action", "\"/synthetic-mail/\" + action");
      assertNotEquals(original, modified);
      Path input = replacement.resolve("PlatformApiContract.java");
      Files.writeString(input, modified);
      assertEquals(
          0,
          ToolProvider.getSystemJavaCompiler()
              .run(
                  null,
                  null,
                  null,
                  "-proc:none",
                  "-classpath",
                  apiClasses.toString(),
                  "-d",
                  replacement.toString(),
                  input.toString()));
    }
    Path jar = temporary.resolve(changed ? "changed.jar" : "original.jar");
    try (var output = new JarOutputStream(Files.newOutputStream(jar))) {
      if (Files.isRegularFile(apiClasses)) {
        try (var archive = new java.util.jar.JarFile(apiClasses.toFile())) {
          for (var member :
              archive.stream().filter(entry -> entry.getName().endsWith(".class")).toList()) {
            output.putNextEntry(new JarEntry(member.getName()));
            Path alternate = replacement.resolve(member.getName());
            if (Files.isRegularFile(alternate)) Files.copy(alternate, output);
            else
              try (var input = archive.getInputStream(member)) {
                input.transferTo(output);
              }
            output.closeEntry();
          }
        }
      } else {
        try (var files = Files.walk(apiClasses)) {
          for (Path file :
              files.filter(path -> path.toString().endsWith(".class")).sorted().toList()) {
            String name = apiClasses.relativize(file).toString().replace(File.separatorChar, '/');
            Path alternate = replacement.resolve(name);
            output.putNextEntry(new JarEntry(name));
            Files.copy(Files.isRegularFile(alternate) ? alternate : file, output);
            output.closeEntry();
          }
        }
      }
    }
    return jar;
  }

  private String execute(Path jar, boolean historical) throws Exception {
    var command =
        new ArrayList<>(
            List.of(Path.of(System.getProperty("java.home"), "bin/java").toString(), "-cp"));
    if (historical) {
      String helper =
          Path.of(
                  HistoricalPackagedApiExport.class
                      .getProtectionDomain()
                      .getCodeSource()
                      .getLocation()
                      .toURI())
              .toString();
      String api =
          Path.of(
                  PlatformApiContract.class
                      .getProtectionDomain()
                      .getCodeSource()
                      .getLocation()
                      .toURI())
              .toString();
      command.add(helper + File.pathSeparator + api);
      command.add(HistoricalPackagedApiExport.class.getName());
      command.add(jar.toString());
    } else {
      command.add(jar.toString());
      command.add(PackagedApiExport.class.getName());
    }
    Path stdout = Files.createTempFile(temporary, "export-", ".json");
    Path stderr = Files.createTempFile(temporary, "export-", ".error");
    var builder =
        new ProcessBuilder(command).redirectOutput(stdout.toFile()).redirectError(stderr.toFile());
    builder.environment().clear();
    Process process = builder.start();
    try {
      assertTrue(process.waitFor(30, TimeUnit.SECONDS));
      assertEquals(0, process.exitValue(), Files.readString(stderr));
      assertTrue(Files.size(stdout) < 8 * 1024 * 1024);
      return Files.readString(stdout);
    } finally {
      process.destroyForcibly();
    }
  }
}
