package network.crypta.platform.devtools;

import java.io.File;
import java.lang.management.ManagementFactory;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import javax.tools.ToolProvider;
import network.crypta.platform.api.PackagedApiExport;
import network.crypta.platform.api.PlatformApiContract;
import network.crypta.platform.api.json.PlatformApiJsonWriter;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
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

  @Test
  void export_whenUnexpectedArgumentProvided_expectNoSnapshot() throws Exception {
    Path jar = packageJar(false);

    ExportResult result = invoke(jar, false, "unexpected");

    assertNotEquals(0, result.exitCode());
    assertEquals("", result.stdout());
    assertTrue(result.stderr().contains("packaged_api_export_arguments_rejected"));
  }

  @Test
  void historicalExport_whenNoArgumentProvided_expectBoundedFailure() throws Exception {
    Path jar = packageJar(false);

    ExportResult result = invoke(jar, true);

    assertHistoricalFailure(result);
  }

  @Test
  void historicalExport_whenExtraArgumentProvided_expectBoundedFailure() throws Exception {
    Path jar = packageJar(false);

    ExportResult result = invoke(jar, true, jar.toString(), "unexpected");

    assertHistoricalFailure(result);
  }

  @Test
  void historicalExport_whenPackageMissing_expectNoPrivatePathInFailure() throws Exception {
    Path missing = temporary.resolve("private-original-package.jar");

    ExportResult result = invoke(missing, true, missing.toString());

    assertHistoricalFailure(result);
  }

  @Test
  void historicalExport_whenArchiveMalformed_expectBoundedFailure() throws Exception {
    Path jar = temporary.resolve("malformed.jar");
    Files.writeString(jar, "private archive data");

    ExportResult result = invoke(jar, true, jar.toString());

    assertHistoricalFailure(result);
  }

  @Test
  void historicalExport_whenApiClassesAbsent_expectNoFallbackToHelperClasspath() throws Exception {
    Path jar = temporary.resolve("empty.jar");
    try (var output = new JarOutputStream(Files.newOutputStream(jar))) {
      output.finish();
    }

    ExportResult result = invoke(jar, true, jar.toString());

    assertHistoricalFailure(result);
  }

  @Test
  void historicalExport_whenManifestSelectsExternalClasses_expectBoundedFailure() throws Exception {
    Path dependency = packageJar(false);
    Path jar = temporary.resolve("external-classpath.jar");
    var manifest = new Manifest();
    manifest.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, "1.0");
    manifest.getMainAttributes().put(Attributes.Name.CLASS_PATH, dependency.toUri().toString());
    try (var output = new JarOutputStream(Files.newOutputStream(jar), manifest)) {
      output.finish();
    }

    ExportResult result = invoke(jar, true, jar.toString());

    assertHistoricalFailure(result);
  }

  @Test
  void historicalExport_whenManifestHasNoExternalClasspath_expectExactJsonProtocol()
      throws Exception {
    Path original = abiPackage(Abi.NORMAL);
    Path jar = temporary.resolve("manifest.jar");
    var manifest = new Manifest();
    manifest.getMainAttributes().put(Attributes.Name.MANIFEST_VERSION, "1.0");
    try (var source = new java.util.jar.JarFile(original.toFile());
        var output = new JarOutputStream(Files.newOutputStream(jar), manifest)) {
      for (var member : source.stream().toList()) {
        output.putNextEntry(new JarEntry(member.getName()));
        try (var input = source.getInputStream(member)) {
          input.transferTo(output);
        }
        output.closeEntry();
      }
    }

    ExportResult result = invoke(jar, true, jar.toString());

    assertExactProtocol(result);
  }

  @Test
  void export_whenSnapshotContainsWhitespace_expectExactJsonProtocol() throws Exception {
    Path jar = abiPackage(Abi.NORMAL);

    ExportResult result = invoke(jar, false);

    assertExactProtocol(result);
  }

  @Test
  void historicalExport_whenSnapshotContainsWhitespace_expectExactJsonProtocol() throws Exception {
    Path jar = abiPackage(Abi.NORMAL);

    ExportResult result = invoke(jar, true, jar.toString());

    assertExactProtocol(result);
  }

  @Test
  @EnabledOnOs({OS.LINUX, OS.MAC})
  void historicalExport_whenPackageIsSymlink_expectBoundedFailure() throws Exception {
    Path jar = abiPackage(Abi.NORMAL);
    Path link = temporary.resolve("linked.jar");
    Files.createSymbolicLink(link, jar);

    ExportResult result = invoke(link, true, link.toString());

    assertHistoricalFailure(result);
  }

  @Test
  void historicalExport_whenPackageIsDirectory_expectBoundedFailure() throws Exception {
    Path directory = Files.createDirectory(temporary.resolve("directory.jar"));

    ExportResult result = invoke(directory, true, directory.toString());

    assertHistoricalFailure(result);
  }

  @Test
  void historicalExport_whenStaticMethodMissing_expectBoundedFailure() throws Exception {
    Path jar = abiPackage(Abi.MISSING_METHOD);

    ExportResult result = invoke(jar, true, jar.toString());

    assertHistoricalFailure(result);
  }

  @Test
  void historicalExport_whenStaticMethodThrows_expectNoExceptionDetailLeak() throws Exception {
    Path jar = abiPackage(Abi.THROWING);

    ExportResult result = invoke(jar, true, jar.toString());

    assertHistoricalFailure(result);
  }

  @Test
  void historicalExport_whenClassInitializationFails_expectBoundedFailure() throws Exception {
    Path jar = abiPackage(Abi.INITIALIZER_ERROR);

    ExportResult result = invoke(jar, true, jar.toString());

    assertHistoricalFailure(result);
  }

  @Test
  void historicalExport_whenSerializerReturnsWrongType_expectBoundedFailure() throws Exception {
    Path jar = abiPackage(Abi.WRONG_RETURN);

    ExportResult result = invoke(jar, true, jar.toString());

    assertHistoricalFailure(result);
  }

  private static void assertExactProtocol(ExportResult result) {
    assertEquals(0, result.exitCode());
    assertEquals("", result.stderr());
    assertEquals(
        "{\"schemaVersion\":1,\"kind\":\"packaged-platform-api-export\","
            + "\"contractSnapshot\":\"{ \\\"contractVersion\\\": 19 }\\n\","
            + "\"baselineRegistry\":\"{ \\\"baseline\\\": \\\"1.0\\\" }\\n\"}"
            + System.lineSeparator(),
        result.stdout());
  }

  private enum Abi {
    NORMAL,
    MISSING_METHOD,
    THROWING,
    INITIALIZER_ERROR,
    WRONG_RETURN
  }

  private Path abiPackage(Abi abi) throws Exception {
    Path directory = Files.createDirectory(temporary.resolve("abi"));
    var sources = abiSources(abi);
    var arguments = new ArrayList<>(List.of("-proc:none", "-d", directory.toString()));
    for (var source : sources.entrySet()) {
      Path file = directory.resolve(source.getKey() + ".java");
      Files.writeString(
          file,
          "package network.crypta.platform.api; public final class "
              + source.getKey()
              + " { "
              + source.getValue()
              + " }");
      arguments.add(file.toString());
    }
    assertEquals(
        0,
        ToolProvider.getSystemJavaCompiler()
            .run(null, null, null, arguments.toArray(String[]::new)));
    Path jar = temporary.resolve("abi.jar");
    try (var output = new JarOutputStream(Files.newOutputStream(jar));
        var files = Files.walk(directory)) {
      for (Path file : files.filter(path -> path.toString().endsWith(".class")).sorted().toList()) {
        output.putNextEntry(
            new JarEntry(directory.relativize(file).toString().replace(File.separatorChar, '/')));
        Files.copy(file, output);
        output.closeEntry();
      }
      // Use the actual production exporter and JSON writer against the compiled fixture ABI.
      for (Class<?> type : List.of(PackagedApiExport.class, PlatformApiJsonWriter.class)) {
        String name = type.getName().replace('.', '/') + ".class";
        output.putNextEntry(new JarEntry(name));
        try (var input = Objects.requireNonNull(type.getResourceAsStream("/" + name))) {
          input.transferTo(output);
        }
        output.closeEntry();
      }
    }
    return jar;
  }

  private static Map<String, String> abiSources(Abi abi) {
    String factory =
        switch (abi) {
          case MISSING_METHOD -> "";
          case THROWING ->
              "public static PlatformApiContract current() { throw new"
                  + " IllegalStateException(\"private failure detail\"); }";
          default ->
              "public static PlatformApiContract current() { return new PlatformApiContract(); }";
        };
    String initializer =
        abi == Abi.INITIALIZER_ERROR
            ? "static { if (Boolean.parseBoolean(\"true\")) throw new LinkageError(\"private"
                + " initialization detail\"); }"
            : "";
    String envelope =
        abi == Abi.WRONG_RETURN
            ? "public static Object writeEnvelope(PlatformApiContract c,"
                + " PlatformApiBaselineRegistry r) { return Integer.valueOf(1); }"
            : "public static String writeEnvelope(PlatformApiContract c,"
                + " PlatformApiBaselineRegistry r) { return \"{ \\\"contractVersion\\\": 19 }\\n"
                + "\"; }";
    return Map.of(
        "PlatformApiContract", factory + initializer,
        "PlatformApiBaselineRegistry",
            "public static PlatformApiBaselineRegistry current() { return new"
                + " PlatformApiBaselineRegistry(); }",
        "PlatformApiContractJson",
            envelope
                + "public static String writeBaselineRegistry(PlatformApiBaselineRegistry r) {"
                + " return \"{ \\\"baseline\\\": \\\"1.0\\\" }\\n"
                + "\"; }");
  }

  private static void assertHistoricalFailure(ExportResult result) {
    assertEquals(1, result.exitCode());
    assertEquals("", result.stdout());
    assertEquals(
        "historical_package_export_abi_unsupported" + System.lineSeparator(), result.stderr());
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
    ExportResult result =
        invoke(jar, historical, historical ? new String[] {jar.toString()} : new String[0]);
    assertEquals(0, result.exitCode(), result.stderr());
    return result.stdout();
  }

  private record ExportResult(int exitCode, String stdout, String stderr) {}

  private static List<String> exporterCoverageArguments() {
    // Gradle instruments the test worker, not its child JVMs. Reuse its JaCoCo destination with
    // append enabled so child exits (including System.exit failures) join the owning test report.
    // Limit instrumentation to the real exporters: deliberately recompiled fixture API classes
    // must not contribute coverage or class-ID mismatches to the production API report.
    return ManagementFactory.getRuntimeMXBean().getInputArguments().stream()
        .filter(
            argument -> argument.startsWith("-javaagent:") && argument.contains("jacocoagent.jar="))
        .map(
            argument ->
                argument.replaceAll(",(?:includes|append)=[^,]*", "")
                    + ",append=true,includes=network.crypta.platform.api.PackagedApiExport:"
                    + "network.crypta.platform.devtools.HistoricalPackagedApiExport")
        .toList();
  }

  private ExportResult invoke(Path jar, boolean historical, String... arguments) throws Exception {
    var command =
        new ArrayList<>(List.of(Path.of(System.getProperty("java.home"), "bin/java").toString()));
    command.addAll(exporterCoverageArguments());
    command.add("-cp");
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
    } else {
      command.add(jar.toString());
      command.add(PackagedApiExport.class.getName());
    }
    command.addAll(List.of(arguments));
    Path stdout = Files.createTempFile(temporary, "export-", ".json");
    Path stderr = Files.createTempFile(temporary, "export-", ".error");
    var builder =
        new ProcessBuilder(command).redirectOutput(stdout.toFile()).redirectError(stderr.toFile());
    builder.environment().clear();
    Process process = builder.start();
    try {
      assertTrue(process.waitFor(30, TimeUnit.SECONDS));
      assertTrue(Files.size(stdout) < 8 * 1024 * 1024);
      assertTrue(Files.size(stderr) < 8 * 1024 * 1024);
      return new ExportResult(
          process.exitValue(), Files.readString(stdout), Files.readString(stderr));
    } finally {
      process.destroyForcibly();
    }
  }
}
