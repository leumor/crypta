package network.crypta.platform.devtools;

import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import network.crypta.platform.api.json.PlatformApiJsonWriter;

/**
 * Exports static API metadata from an original package that supports the fixed historical export
 * ABI.
 *
 * <p>The selected JAR supplies {@code PlatformApiContract}, {@code PlatformApiBaselineRegistry} and
 * {@code PlatformApiContractJson}. A dedicated classloader uses only the platform classloader as
 * its parent, excluding the helper's application classes. The adapter verifies the identity of each
 * defining classloader before invoking the fixed static methods. Missing ABI support fails closed;
 * there is no fallback to current API classes or a source rebuild.
 *
 * <p>The caller must authenticate and immutably stage the original JAR, isolate and bound this
 * process, and label the resulting observation {@code observed-from-original-package}. This adapter
 * does not itself prove original release provenance or that the snapshot was frozen at publication.
 * Run it as a separate Java 25 process: rejected inputs terminate the JVM with a nonzero status.
 */
public final class HistoricalPackagedApiExport {
  /** Prevents instantiation of this process-level export adapter. */
  private HistoricalPackagedApiExport() {}

  /**
   * Exports the selected JAR's native snapshot strings through four fixed static ABI calls.
   *
   * <p>The argument must identify a regular JAR file, not a symbolic link, and its manifest must
   * not declare {@code Class-Path}. The isolated classes must expose {@code current()} on the
   * contract and registry types and {@code writeEnvelope(contract, registry)} and {@code
   * writeBaselineRegistry} on the JSON serializer. The loader is closed after the export attempt.
   *
   * <p>On success, standard output receives one JSON envelope with schema version {@code 1}, kind
   * {@code packaged-platform-api-export}, and {@code contractSnapshot} and {@code baselineRegistry}
   * string fields, followed by a line terminator. Invalid arguments, I/O failures, reflective call
   * failures, runtime exceptions and linkage errors instead write the fixed diagnostic {@code
   * historical_package_export_abi_unsupported} to standard error and exit with status {@code 1}.
   * Callers must require successful process completion before accepting any output. Logging must
   * not decorate or redirect these protocol channels or disclose exception details and private
   * paths.
   *
   * @param arguments command-line array containing exactly one authenticated staged JAR path
   */
  @SuppressWarnings({"ReferenceEquality", "java:S106"})
  static void main(String[] arguments) {
    try {
      if (arguments.length != 1) throw new IllegalArgumentException();
      Path jar = Path.of(arguments[0]);
      if (!Files.isRegularFile(jar, LinkOption.NOFOLLOW_LINKS))
        throw new IllegalArgumentException();
      try (var archive = new java.util.jar.JarFile(jar.toFile())) {
        var manifest = archive.getManifest();
        if (manifest != null && manifest.getMainAttributes().getValue("Class-Path") != null) {
          throw new IllegalArgumentException();
        }
      }
      try (var loader =
          new URLClassLoader(
              new URL[] {jar.toUri().toURL()}, ClassLoader.getPlatformClassLoader())) {
        Class<?> contract = loader.loadClass("network.crypta.platform.api.PlatformApiContract");
        Class<?> registry =
            loader.loadClass("network.crypta.platform.api.PlatformApiBaselineRegistry");
        Class<?> json = loader.loadClass("network.crypta.platform.api.PlatformApiContractJson");
        if (contract.getClassLoader() != loader
            || registry.getClassLoader() != loader
            || json.getClassLoader() != loader) throw new IllegalArgumentException();
        Object target = contract.getMethod("current").invoke(null);
        Object baselines = registry.getMethod("current").invoke(null);
        String snapshot =
            (String)
                json.getMethod("writeEnvelope", contract, registry).invoke(null, target, baselines);
        String baseline =
            (String) json.getMethod("writeBaselineRegistry", registry).invoke(null, baselines);
        var output = new LinkedHashMap<String, Object>();
        output.put("schemaVersion", 1);
        output.put("kind", "packaged-platform-api-export");
        output.put("contractSnapshot", snapshot);
        output.put("baselineRegistry", baseline);
        System.out.println(PlatformApiJsonWriter.write(output));
      }
    } catch (ReflectiveOperationException
        | java.io.IOException
        | RuntimeException
        | LinkageError _) {
      System.err.println("historical_package_export_abi_unsupported");
      System.exit(1);
    }
  }
}
