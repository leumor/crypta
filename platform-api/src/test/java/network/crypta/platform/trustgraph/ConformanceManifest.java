package network.crypta.platform.trustgraph;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/** Test-only access to the public synthetic manifest using the existing bounded JSON reader. */
public final class ConformanceManifest {
  private ConformanceManifest() {}

  /** Returns the manifest object; no fixture bytes are generated or rewritten. */
  public static Map<?, ?> read() throws IOException {
    try (var resource =
        ConformanceManifest.class.getResourceAsStream(
            "/content-profile-conformance/v1/manifest.json")) {
      return (Map<?, ?>)
          TrustJson.parse(
              new String(
                  java.util.Objects.requireNonNull(resource).readAllBytes(),
                  StandardCharsets.UTF_8));
    }
  }
}
