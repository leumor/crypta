package network.crypta.runtime.spi;

/**
 * Exposes the narrow legacy queue-page read capability needed by the admin HTTP endpoints.
 *
 * <p>This port is intentionally page-oriented and transitional. The legacy queue pages still mix
 * large read-only traversal, sorting, and HTML-shaped rendering. Callers therefore request one
 * detached page snapshot or text export per route rather than a reusable queue domain model.
 *
 * <p>The port is read-only. It does not perform access control, does not model POST mutations, and
 * does not expose daemon-only or HTTP-owned types such as {@code NodeClientCore}, {@code
 * RequestStatus}, {@code HTMLNode}, or {@code ToadletContext}. Implementations may traverse the
 * live daemon state while producing one render, but callers receive only immutable JDK-only values
 * that are safe to retain for the lifetime of one request.
 *
 * <p>Typical callers are HTTP-layer adapters such as {@code QueueToadlet}. They parse request
 * intent, permissions, and request-context-only values locally, then delegate the heavy queue
 * traversal to this port. The returned snapshot can still contain a very small placeholder set for
 * request-scoped fragments, but it intentionally keeps the daemon-side traversal and sorting rules
 * behind one runtime boundary.
 *
 * @see QueuePageRequest
 * @see QueuePageSnapshot
 */
public interface QueuePagePort {
  /**
   * Returns one detached snapshot of the requested legacy queue page.
   *
   * <p>Implementations read the live queue state, partition requests into the same logical groups
   * shown by the legacy admin UI, and render one detached HTML-template fragment for the body of
   * the page. The caller remains responsible for HTTP response handling, access checks, and any
   * final placeholder substitution that depends on the request-local context.
   *
   * @param request detached render request describing which queue side to read, whether advanced
   *     mode is enabled, and which optional sort should be applied
   * @return immutable queue-page snapshot containing the page title and detached body template for
   *     one GET render
   * @throws RequestQueueUnavailableException if the runtime cannot read the persistent queue state
   */
  QueuePageSnapshot renderPage(QueuePageRequest request) throws RequestQueueUnavailableException;

  /**
   * Returns one detached snapshot of the queue count page.
   *
   * <p>This method serves the small read-only status page used by {@code countRequests.html}.
   * Implementations may compute queue counts from live request schedulers, but they still return
   * only detached strings, so the HTTP layer does not depend on daemon-owned queue types.
   *
   * @param uploads whether the upload queue path requested the count page instead of the downloads
   *     path
   * @return immutable count-page snapshot ready to be wrapped by the HTTP page shell
   * @throws RequestQueueUnavailableException if the runtime cannot read the required queue state
   */
  QueuePageSnapshot renderCountPage(boolean uploads) throws RequestQueueUnavailableException;

  /**
   * Returns the newline-separated URI list for the requested queue side.
   *
   * <p>The returned text matches the legacy admin export format used by {@code listKeys.txt}. Each
   * line contains one key suitable for read-only inspection or operator workflows that expect the
   * historical queue export shape.
   *
   * @param uploads whether the upload queue key-list path was requested instead of the downloads
   *     path
   * @return plain-text key list for the requested queue side, separated by newline characters
   * @throws RequestQueueUnavailableException if the runtime cannot read the persistent queue state
   */
  String renderKeyList(boolean uploads) throws RequestQueueUnavailableException;

  /**
   * Reads one exact upload identifier without rendering or parsing a queue page.
   *
   * @param identifier exact persistent queue identifier
   * @return coarse state and successful CHK read reference only
   * @throws RequestQueueUnavailableException if this runtime cannot provide typed status
   */
  default QueueInsertStatus readInsertStatus(String identifier)
      throws RequestQueueUnavailableException {
    throw new RequestQueueUnavailableException("Typed insert status unavailable.");
  }
}
