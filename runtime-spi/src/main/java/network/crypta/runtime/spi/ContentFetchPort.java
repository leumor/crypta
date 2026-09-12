package network.crypta.runtime.spi;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Objects;

/**
 * Runtime capability for fetching bounded content bytes from the node.
 *
 * <p>This port is intended for infrastructure flows that need to retrieve a small runtime-owned
 * document, such as a signed catalog, without depending on daemon URI, client, bucket, or fetch
 * classes. Callers must provide a strict byte limit and timeout for each request. Implementations
 * are responsible for enforcing those bounds before returning materialized bytes or streaming
 * content to a caller-owned destination.
 *
 * <p>The SPI stays JDK-only: request and result values contain strings, durations, byte arrays, and
 * checked exceptions only. URI parsing and network-specific behavior remain implementation details
 * of the daemon-backed adapter.
 *
 * <p>Implementations should avoid creating durable queue state for these requests unless their
 * runtime cannot fetch content any other way. A call should either return detached bytes, stream
 * bytes to the supplied destination, or throw a {@link ContentFetchException} with a stable code
 * that higher layers can map. The port is a transport bridge, not a trust boundary; callers that
 * fetch signed catalogs or bundles must still perform their own signature and digest checks.
 *
 * @see RuntimePorts#contentFetch()
 * @see BoundedContentFetchRequest
 * @see BoundedContentFetchResult
 */
public interface ContentFetchPort {
  /**
   * Returns a bounded, inventory-free observation of this port's executing calls.
   *
   * @return explicit unsupported metadata for legacy implementations, or an owner snapshot
   */
  default ContentFetchObservation observation() {
    return ContentFetchObservation.unavailable();
  }

  /**
   * Fetches one bounded content document.
   *
   * <p>The returned byte array is detached from the implementation's internal buffers. Failures are
   * reported through stable string error codes so higher layers can map them without depending on
   * daemon-specific exception enums. Implementations should honor the request timeout as an
   * end-to-end wait budget and should cancel or release runtime fetch resources when the budget is
   * exhausted.
   *
   * @param request bounded request describing URI, byte limit, timeout, and purpose
   * @return detached content bytes plus requested and resolved URI metadata
   * @throws ContentFetchException if the URI is invalid, the fetch times out, the byte limit is
   *     exceeded, or the runtime fetch fails
   */
  BoundedContentFetchResult fetchContent(BoundedContentFetchRequest request)
      throws ContentFetchException;

  /**
   * Fetches one bounded content document into a caller-owned stream.
   *
   * <p>This overload exists for larger infrastructure artifacts where materializing a full payload
   * on the JVM heap would be unsafe. Implementations should enforce {@link
   * BoundedContentFetchRequest#maxBytes()} before writing bytes beyond the limit and should not
   * close {@code destination}; the caller owns that stream and any validation layered around it.
   *
   * <p>The default implementation preserves source compatibility for simple test and embedding
   * ports by delegating to {@link #fetchContent(BoundedContentFetchRequest)} and writing the
   * detached bytes. Daemon-backed implementations that can expose bucket or file streams should
   * override this method.
   *
   * @param request bounded request describing URI, byte limit, timeout, and purpose
   * @param destination caller-owned destination for fetched bytes
   * @throws ContentFetchException if the URI is invalid, the fetch times out, the byte limit is
   *     exceeded, or the runtime fetch fails
   * @throws IOException if the destination cannot be written
   */
  default void fetchContent(BoundedContentFetchRequest request, OutputStream destination)
      throws ContentFetchException, IOException {
    Objects.requireNonNull(destination, "destination").write(fetchContent(request).bytes());
  }
}
