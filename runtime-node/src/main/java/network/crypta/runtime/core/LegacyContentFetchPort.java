package network.crypta.runtime.core;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.MalformedURLException;
import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import network.crypta.client.FetchContext;
import network.crypta.client.FetchException;
import network.crypta.client.FetchResult;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientGetCallback;
import network.crypta.client.async.ClientGetter;
import network.crypta.keys.FreenetURI;
import network.crypta.node.NodeClientCore;
import network.crypta.node.RequestClient;
import network.crypta.node.RequestStarter;
import network.crypta.runtime.spi.BoundedContentFetchRequest;
import network.crypta.runtime.spi.BoundedContentFetchResult;
import network.crypta.runtime.spi.ContentFetchException;
import network.crypta.runtime.spi.ContentFetchObservation;
import network.crypta.runtime.spi.ContentFetchPort;
import network.crypta.support.api.Bucket;
import network.crypta.support.io.ResumeFailedException;

/**
 * Daemon-backed implementation of the bounded runtime content-fetch SPI.
 *
 * <p>The adapter uses the existing non-persistent high-level client fetch layer, applies the
 * caller's byte limit to both output and intermediate data, and waits only for the caller-supplied
 * timeout. If the timeout expires, the underlying {@link ClientGetter} is canceled through the core
 * {@link ClientContext}. Successful payloads are materialized only after the fetch result size has
 * been checked against the requested maximum, and fetched buckets are freed on every materialized
 * outcome.
 *
 * <p>The port is intentionally narrow. It is used by infrastructure callers that need bounded
 * access to Crypta content, such as signed app catalog properties and signature sidecars, without
 * exposing daemon client classes through {@code runtime-spi}. Fetch redirects that report a newer
 * USK edition are followed within one overall timeout budget and a small redirect cap. The returned
 * resolved URI is diagnostic metadata only; signature verification remains the catalog trust
 * boundary.
 */
final class LegacyContentFetchPort implements ContentFetchPort {
  /**
   * Priority class used for bounded infrastructure fetches.
   *
   * <p>Catalog refreshes are operational maintenance, so they use the same priority family as
   * update work instead of interactive browsing.
   */
  private static final short FETCH_PRIORITY_CLASS = RequestStarter.UPDATE_PRIORITY_CLASS;

  /**
   * Maximum permanent redirects followed during one bounded fetch.
   *
   * <p>The cap prevents a redirect cycle from consuming the caller's whole timeout through
   * unbounded queue starts while still allowing normal USK edition advancement.
   */
  private static final int MAX_REDIRECTS = 8;

  /** Buffer size used when streaming fetched buckets into caller-owned destinations. */
  private static final int STREAM_BUFFER_BYTES = 64 * 1024;

  /** Node core used to create transient clients and cancel active getters on timeout. */
  private final NodeClientCore core;

  private final ContentFetchActivity activity = new ContentFetchActivity();

  @Override
  public ContentFetchObservation observation() {
    return activity.snapshot();
  }

  /**
   * Creates a content-fetch port bound to one node core.
   *
   * @param core daemon core that owns the high-level fetch client and client context
   */
  LegacyContentFetchPort(NodeClientCore core) {
    this.core = Objects.requireNonNull(core);
  }

  /**
   * {@inheritDoc}
   *
   * <p>This implementation parses the request URI as a daemon {@link FreenetURI}, starts a
   * non-persistent fetch, follows permanent redirects with an overall timeout budget, and returns a
   * defensive byte-array result. Invalid daemon URIs are reported as {@code
   * invalid_catalog_source}; timeouts and fetch failures use stable runtime SPI error codes.
   */
  @Override
  public BoundedContentFetchResult fetchContent(BoundedContentFetchRequest request)
      throws ContentFetchException {
    long token = activity.enter();
    boolean success = false;
    try {
      FetchOutcome outcome = fetchOutcome(request);
      byte[] bytes = materializeResult(request, outcome.result());
      String resolvedUri = outcome.resolvedUri() == null ? null : outcome.resolvedUri().toString();
      BoundedContentFetchResult result =
          new BoundedContentFetchResult(
              bytes, request.uri(), resolvedUri, "Fetched " + bytes.length + " bytes");
      success = true;
      return result;
    } finally {
      activity.exit(token, success);
    }
  }

  /**
   * {@inheritDoc}
   *
   * <p>This implementation streams the fetched daemon bucket directly into the caller-owned
   * destination after checking the bucket-reported size. The copy loop enforces the requested byte
   * limit again while reading, so an inaccurate bucket size cannot stream more than the caller
   * allowed.
   */
  @Override
  public void fetchContent(BoundedContentFetchRequest request, OutputStream destination)
      throws ContentFetchException, IOException {
    Objects.requireNonNull(destination, "destination");
    long token = activity.enter();
    boolean success = false;
    try {
      FetchOutcome outcome = fetchOutcome(request);
      streamResult(request, outcome.result(), destination);
      success = true;
    } finally {
      activity.exit(token, success);
    }
  }

  private FetchOutcome fetchOutcome(BoundedContentFetchRequest request)
      throws ContentFetchException {
    Objects.requireNonNull(request, "request");
    FreenetURI uri = parseUri(request);
    HighLevelSimpleClient client = core.makeClient(FETCH_PRIORITY_CLASS, false, false);
    RequestClient requestClient = (RequestClient) client;
    return fetchFollowingRedirects(request, client, requestClient, uri);
  }

  /**
   * Parses the JDK-only request URI into the daemon URI type.
   *
   * @param request bounded fetch request carrying the raw URI string
   * @return daemon URI suitable for the high-level client fetch layer
   * @throws ContentFetchException if the URI cannot be parsed by daemon URI rules
   */
  private static FreenetURI parseUri(BoundedContentFetchRequest request)
      throws ContentFetchException {
    try {
      return new FreenetURI(request.uri());
    } catch (MalformedURLException exception) {
      throw new ContentFetchException(
          ContentFetchException.INVALID_CATALOG_SOURCE,
          "Invalid content fetch URI for " + request.purpose(),
          exception);
    }
  }

  /**
   * Builds a fetch context that enforces the caller's byte bound.
   *
   * @param client high-level client that owns the default fetch context template
   * @param maxBytes maximum accepted output and temporary bytes for this fetch
   * @return fetch context configured for bounded unfiltered content retrieval
   */
  private static FetchContext boundedFetchContext(HighLevelSimpleClient client, long maxBytes) {
    FetchContext fetchContext = client.getFetchContext();
    fetchContext.setMaxOutputLength(maxBytes);
    fetchContext.setMaxTempLength(maxBytes);
    fetchContext.setFilterData(false);
    return fetchContext;
  }

  /**
   * Executes a bounded fetch and follows permanent redirects within one timeout budget.
   *
   * <p>Crypta USK fetches can report newer editions through {@link
   * FetchException.FetchExceptionMode#PERMANENT_REDIRECT}. This loop treats redirects with a
   * concrete {@link FetchException#newURI} as retry targets and preserves the original request's
   * timeout across all attempts. Other fetch failures are mapped to the runtime SPI error contract.
   *
   * @param request original bounded fetch request
   * @param client high-level client used to start transient fetches
   * @param requestClient request-client identity associated with callbacks
   * @param initialUri first daemon URI to fetch
   * @return fetch result and final daemon URI reported by the getter
   * @throws ContentFetchException if timeout, redirect limit, or non-redirect fetch failure occurs
   */
  private FetchOutcome fetchFollowingRedirects(
      BoundedContentFetchRequest request,
      HighLevelSimpleClient client,
      RequestClient requestClient,
      FreenetURI initialUri)
      throws ContentFetchException {
    long deadlineNanos = deadlineNanos(request.timeout());
    FreenetURI currentUri = initialUri;
    int redirects = 0;
    while (true) {
      FetchContext fetchContext = boundedFetchContext(client, request.maxBytes());
      FetchCompletionCallback callback = new FetchCompletionCallback(requestClient);
      ClientGetter getter;
      try {
        getter = startFetch(client, currentUri, request.maxBytes(), fetchContext, callback);
        FetchResult result = waitForResult(request, callback, getter, deadlineNanos);
        return new FetchOutcome(result, getter.getURI() == null ? currentUri : getter.getURI());
      } catch (FetchException exception) {
        FreenetURI redirectUri = redirectTarget(exception);
        if (redirectUri == null) {
          throw mapFetchException(exception);
        }
        if (redirects >= MAX_REDIRECTS) {
          throw new ContentFetchException(
              ContentFetchException.CATALOG_FETCH_FAILED,
              "Content fetch redirect limit exceeded for " + request.purpose(),
              exception);
        }
        redirects++;
        currentUri = redirectUri;
      }
    }
  }

  /**
   * Starts one transient high-level client fetch.
   *
   * @param client high-level client that owns fetch scheduling
   * @param uri daemon URI to fetch for this attempt
   * @param maxBytes maximum bytes accepted by the high-level fetch call
   * @param fetchContext context carrying output and temp byte limits
   * @param callback callback completed by the asynchronous fetch
   * @return getter handle used for cancellation and final URI reporting
   * @throws FetchException if the fetch cannot be queued or fails synchronously
   */
  private static ClientGetter startFetch(
      HighLevelSimpleClient client,
      FreenetURI uri,
      long maxBytes,
      FetchContext fetchContext,
      FetchCompletionCallback callback)
      throws FetchException {
    return client.fetch(uri, maxBytes, callback, fetchContext, FETCH_PRIORITY_CLASS);
  }

  /**
   * Waits for one asynchronous fetch attempt to complete.
   *
   * <p>The method cancels the getter on timeout or interruption. Fetch exceptions are rethrown so
   * the redirect loop can inspect permanent redirects before the failure is converted to the
   * runtime SPI error envelope.
   *
   * @param request original request, used for stable error messages
   * @param callback callback future completed by the high-level fetch layer
   * @param getter active getter that should be canceled when waiting stops early
   * @param deadlineNanos absolute {@link System#nanoTime()} deadline for the overall fetch
   * @return completed fetch result for the current attempt
   * @throws ContentFetchException if waiting times out, is interrupted, or fails unexpectedly
   * @throws FetchException if the fetch layer reports a fetch failure
   */
  private FetchResult waitForResult(
      BoundedContentFetchRequest request,
      FetchCompletionCallback callback,
      ClientGetter getter,
      long deadlineNanos)
      throws ContentFetchException, FetchException {
    long remainingNanos = remainingNanos(deadlineNanos);
    if (remainingNanos <= 0L) {
      getter.cancel(core.getClientContext());
      throw timeoutException(request, null);
    }
    try {
      return callback.result().get(remainingNanos, TimeUnit.NANOSECONDS);
    } catch (TimeoutException exception) {
      getter.cancel(core.getClientContext());
      throw timeoutException(request, exception);
    } catch (InterruptedException exception) {
      Thread.currentThread().interrupt();
      getter.cancel(core.getClientContext());
      throw new ContentFetchException(
          ContentFetchException.CATALOG_FETCH_FAILED,
          "Interrupted while fetching " + request.purpose(),
          exception);
    } catch (ExecutionException exception) {
      Throwable cause = exception.getCause();
      if (cause instanceof FetchException fetchException) {
        throw fetchException;
      }
      throw new ContentFetchException(
          ContentFetchException.CATALOG_FETCH_FAILED,
          "Failed fetching " + request.purpose(),
          cause);
    }
  }

  /**
   * Creates the stable timeout exception used by the runtime SPI.
   *
   * @param request original request, used to include the diagnostic purpose
   * @param cause optional timeout cause from the waiting operation
   * @return content-fetch exception with {@code catalog_fetch_timeout}
   */
  private static ContentFetchException timeoutException(
      BoundedContentFetchRequest request, Throwable cause) {
    return new ContentFetchException(
        ContentFetchException.CATALOG_FETCH_TIMEOUT,
        "Timed out fetching " + request.purpose(),
        cause);
  }

  /**
   * Materializes a bounded fetch result and always releases the source bucket.
   *
   * <p>The method checks both the bucket-reported size and the final byte-array length. The second
   * check protects against unusual bucket implementations whose size changes or reports
   * inaccurately while being read. The daemon bucket is owned through try-with-resources so
   * successful reads, oversized results, and I/O failures all release the bucket.
   *
   * @param request bounded request containing the maximum byte count and purpose
   * @param result daemon fetch result whose bucket is owned by this adapter
   * @return detached bytes from the fetch result
   * @throws ContentFetchException if the result is oversized or cannot be read
   */
  static byte[] materializeResult(BoundedContentFetchRequest request, FetchResult result)
      throws ContentFetchException {
    try (Bucket bucket = result.asBucket()) {
      long resultSize = bucket.size();
      if (resultSize > request.maxBytes()) {
        throw oversizedContentException(request);
      }
      byte[] bytes = result.asByteArray();
      if (bytes.length > request.maxBytes()) {
        throw oversizedContentException(request);
      }
      return bytes;
    } catch (IOException exception) {
      throw new ContentFetchException(
          ContentFetchException.CATALOG_FETCH_FAILED,
          "Failed reading fetched content for " + request.purpose(),
          exception);
    }
  }

  /**
   * Streams a bounded fetch result into a caller-owned destination and releases the source bucket.
   *
   * <p>The method checks the bucket-reported size before opening a stream, then enforces the same
   * byte limit while copying. The destination is flushed but not closed because it is owned by the
   * caller.
   *
   * @param request bounded request containing the maximum byte count and purpose
   * @param result daemon fetch result whose bucket is owned by this adapter
   * @param destination caller-owned output stream for fetched content
   * @return number of bytes written
   * @throws ContentFetchException if the result is oversized
   * @throws IOException if the result cannot be read or the destination cannot be written
   */
  static long streamResult(
      BoundedContentFetchRequest request, FetchResult result, OutputStream destination)
      throws ContentFetchException, IOException {
    Objects.requireNonNull(destination, "destination");
    try (Bucket bucket = result.asBucket()) {
      long resultSize = bucket.size();
      if (resultSize > request.maxBytes()) {
        throw oversizedContentException(request);
      }
      long bytesWritten = streamBucket(request, bucket, destination);
      destination.flush();
      return bytesWritten;
    }
  }

  private static long streamBucket(
      BoundedContentFetchRequest request, Bucket bucket, OutputStream destination)
      throws ContentFetchException, IOException {
    try (InputStream input = bucket.getInputStreamUnbuffered()) {
      if (input == null) {
        return 0L;
      }
      return copyBounded(request, input, destination);
    }
  }

  private static long copyBounded(
      BoundedContentFetchRequest request, InputStream input, OutputStream destination)
      throws ContentFetchException, IOException {
    byte[] buffer = new byte[STREAM_BUFFER_BYTES];
    long bytesWritten = 0L;
    int bytesRead;
    while ((bytesRead = input.read(buffer)) >= 0) {
      if (bytesRead == 0) {
        continue;
      }
      if (bytesRead > request.maxBytes() - bytesWritten) {
        throw oversizedContentException(request);
      }
      destination.write(buffer, 0, bytesRead);
      bytesWritten += bytesRead;
    }
    return bytesWritten;
  }

  private static ContentFetchException oversizedContentException(
      BoundedContentFetchRequest request) {
    return new ContentFetchException(
        ContentFetchException.CATALOG_FETCH_TOO_LARGE,
        "Fetched content exceeded " + request.maxBytes() + " bytes for " + request.purpose());
  }

  /**
   * Converts a non-redirect fetch failure into the runtime SPI error envelope.
   *
   * @param exception daemon fetch exception that should be exposed only through a stable code
   * @return content-fetch exception with a stable runtime SPI code
   */
  static ContentFetchException mapFetchException(FetchException exception) {
    if (isFetchLayerSizeFailure(exception)) {
      return new ContentFetchException(
          ContentFetchException.CATALOG_FETCH_TOO_LARGE,
          "Fetched content exceeded a configured byte bound.",
          exception);
    }
    return new ContentFetchException(
        ContentFetchException.CATALOG_FETCH_FAILED,
        "Content fetch failed: " + exception.getMessage(),
        exception);
  }

  private static boolean isFetchLayerSizeFailure(FetchException exception) {
    return exception.getMode() == FetchException.FetchExceptionMode.TOO_BIG
        || exception.getMode() == FetchException.FetchExceptionMode.TOO_BIG_METADATA;
  }

  /**
   * Extracts a retry target from a permanent redirect fetch exception.
   *
   * @param exception daemon fetch exception reported by the high-level client
   * @return redirected daemon URI, or {@code null} when the exception should not be retried
   */
  static FreenetURI redirectTarget(FetchException exception) {
    if (exception.mode == FetchException.FetchExceptionMode.PERMANENT_REDIRECT) {
      return exception.newURI;
    }
    return null;
  }

  /**
   * Computes the absolute timeout deadline for one bounded fetch request.
   *
   * @param timeout positive caller-supplied timeout duration
   * @return absolute {@link System#nanoTime()} deadline, saturated at {@link Long#MAX_VALUE}
   */
  private static long deadlineNanos(Duration timeout) {
    long now = System.nanoTime();
    long timeoutNanos = timeoutNanos(timeout);
    long safeNow = Math.max(now, 0L);
    if (timeoutNanos > Long.MAX_VALUE - safeNow) {
      return Long.MAX_VALUE;
    }
    return now + timeoutNanos;
  }

  /**
   * Converts a timeout duration to nanoseconds with saturation.
   *
   * @param timeout positive timeout duration from the request
   * @return timeout nanoseconds, or {@link Long#MAX_VALUE} when the duration overflows
   */
  private static long timeoutNanos(Duration timeout) {
    try {
      return timeout.toNanos();
    } catch (ArithmeticException _) {
      return Long.MAX_VALUE;
    }
  }

  /**
   * Returns the time remaining before an absolute deadline.
   *
   * @param deadlineNanos absolute {@link System#nanoTime()} deadline
   * @return non-negative remaining nanoseconds
   */
  private static long remainingNanos(long deadlineNanos) {
    return Math.max(deadlineNanos - System.nanoTime(), 0L);
  }

  /**
   * Completed fetch attempt and the URI that should be reported as resolved metadata.
   *
   * @param result daemon fetch result whose bucket still needs materialization and release
   * @param resolvedUri final URI reported by the getter, or the attempted URI as a fallback
   */
  private record FetchOutcome(FetchResult result, FreenetURI resolvedUri) {}

  /**
   * Callback bridge from the daemon fetch API to a {@link CompletableFuture}.
   *
   * <p>The high-level fetch API completes through callback methods, while the runtime SPI needs a
   * bounded synchronous return. This bridge stores only the request-client identity required by the
   * fetch layer and completes a future with either the {@link FetchResult} or the reported {@link
   * FetchException}. Persistent resume is rejected because these fetches are deliberately
   * transient.
   */
  private static final class FetchCompletionCallback implements ClientGetCallback {
    /** Request-client identity returned to the high-level fetch scheduler. */
    private final RequestClient requestClient;

    /** Future completed exactly once by success or failure callbacks. */
    private final CompletableFuture<FetchResult> result = new CompletableFuture<>();

    /**
     * Creates a callback bridge for one fetch attempt.
     *
     * @param requestClient request-client identity associated with the transient fetch
     */
    private FetchCompletionCallback(RequestClient requestClient) {
      this.requestClient = Objects.requireNonNull(requestClient);
    }

    /**
     * Returns the future completed by the fetch callbacks.
     *
     * @return future carrying a fetch result or fetch exception
     */
    private CompletableFuture<FetchResult> result() {
      return result;
    }

    @Override
    public void onSuccess(FetchResult result, ClientGetter state) {
      this.result.complete(result);
    }

    @Override
    public void onFailure(FetchException exception) {
      result.completeExceptionally(exception);
    }

    @Override
    public void onResume(ClientContext context) throws ResumeFailedException {
      throw new ResumeFailedException("Transient runtime content fetch cannot be resumed");
    }

    @Override
    public RequestClient getRequestClient() {
      return requestClient;
    }
  }
}
