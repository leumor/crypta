package network.crypta.platform.api;

import java.util.LinkedHashMap;
import network.crypta.platform.api.json.PlatformApiJsonWriter;

/**
 * Exports the packaged daemon's static Platform API contract and baseline registry as JSON.
 *
 * <p>This Java 25 command-line entry point accepts no options and starts no node. The output
 * envelope has schema version {@code 1}, kind {@code packaged-platform-api-export}, and two string
 * fields: {@code contractSnapshot} and {@code baselineRegistry}. Those strings retain the native
 * JSON serializers' text; consumers must not replace them with reserialized JSON when binding their
 * byte identities.
 *
 * <p>The caller must use only the authenticated selected package on the classpath and provide
 * process isolation, resource limits and archive identity verification. This exporter does not
 * authenticate its own executable or establish release eligibility. Its output describes the
 * classes actually loaded in this process.
 */
public final class PackagedApiExport {
  /** Prevents instantiation of this command-line entry point. */
  private PackagedApiExport() {}

  /**
   * Writes one JSON envelope followed by a line terminator to standard output.
   *
   * <p>The snapshot comes from {@link PlatformApiContract#current()} and the registry from {@link
   * PlatformApiBaselineRegistry#current()}. Standard output is the machine-readable export channel;
   * logger decoration or routing would change that protocol. The stream remains open. Output size
   * and execution time are bounded by the invoking process supervisor, not by this method.
   *
   * @param arguments non-null, empty command-line argument array
   * @throws IllegalArgumentException if any argument is supplied
   * @throws NullPointerException if {@code arguments} is {@code null}
   */
  @SuppressWarnings({"java:S106", "JavaPrintToLogpoint"})
  static void main(String[] arguments) {
    if (arguments.length != 0)
      throw new IllegalArgumentException("packaged_api_export_arguments_rejected");
    var contract = PlatformApiContract.current();
    var registry = PlatformApiBaselineRegistry.current();
    var result = new LinkedHashMap<String, Object>();
    result.put("schemaVersion", 1);
    result.put("kind", "packaged-platform-api-export");
    result.put("contractSnapshot", PlatformApiContractJson.writeEnvelope(contract, registry));
    result.put("baselineRegistry", PlatformApiContractJson.writeBaselineRegistry(registry));
    System.out.println(PlatformApiJsonWriter.write(result));
  }
}
