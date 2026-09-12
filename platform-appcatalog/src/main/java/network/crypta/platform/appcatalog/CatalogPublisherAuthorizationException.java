package network.crypta.platform.appcatalog;

import java.io.IOException;
import java.io.Serial;

/**
 * Expected denial when current local publisher scope no longer authorizes a catalog operation.
 *
 * <p>This checked distinction preserves existing verifier contracts while allowing operator routes
 * to report a conflict instead of disguising a revoked or changed policy as filesystem failure.
 * Messages contain no caller input, paths, or policy record contents.
 */
public final class CatalogPublisherAuthorizationException extends IOException {
  /** Serialization identity for this fixed diagnostic exception. */
  @Serial private static final long serialVersionUID = 1L;

  /** Creates the fixed, private-safe current-scope denial. */
  public CatalogPublisherAuthorizationException() {
    super("Current local publisher scope does not authorize this catalog operation.");
  }
}
