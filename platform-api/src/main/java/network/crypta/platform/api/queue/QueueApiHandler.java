package network.crypta.platform.api.queue;

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import network.crypta.crypt.mail.MailHpke;
import network.crypta.keys.FreenetURI;
import network.crypta.platform.api.PlatformApiException;
import network.crypta.platform.api.PlatformApiParameters;
import network.crypta.platform.api.contentformats.ContentFormatProfileRegistry;
import network.crypta.runtime.spi.QueueBrowserUploadInsertRequest;
import network.crypta.runtime.spi.QueueCompletionPort;
import network.crypta.runtime.spi.QueueDownloadPort;
import network.crypta.runtime.spi.QueueDownloadRejectedException;
import network.crypta.runtime.spi.QueueDownloadRequest;
import network.crypta.runtime.spi.QueueInsertFailureReason;
import network.crypta.runtime.spi.QueueInsertOptions;
import network.crypta.runtime.spi.QueueInsertOutcome;
import network.crypta.runtime.spi.QueueInsertPort;
import network.crypta.runtime.spi.QueueInsertRejectedException;
import network.crypta.runtime.spi.QueueLocalDirectoryInsertRequest;
import network.crypta.runtime.spi.QueueLocalFileInsertRequest;
import network.crypta.runtime.spi.QueueMutationPort;
import network.crypta.runtime.spi.QueuePagePort;
import network.crypta.runtime.spi.QueuePageRequest;
import network.crypta.runtime.spi.QueuePageSnapshot;
import network.crypta.runtime.spi.QueueSupportPort;
import network.crypta.runtime.spi.RequestQueueUnavailableException;
import network.crypta.support.MediaType;

/**
 * Serves the Platform API v1 queue control-plane surface.
 *
 * <p>This handler turns the detached queue runtime ports into one transport-neutral JSON API for
 * the Web Shell and any other local callers that need queue visibility or queue mutation access.
 * Reads still originate from the legacy page-oriented {@link QueuePagePort}, so the current read
 * model remains intentionally transitional: the handler wraps detached HTML snapshots in stable
 * JSON envelopes, strips request-local placeholders that belong only to the legacy HTTP shell, and
 * leaves the runtime traversal logic behind the existing SPI boundary.
 *
 * <p>Mutation requests already cross the detached ports more directly. This type validates the
 * supported request parameters, normalizes legacy queue form conventions such as repeated
 * identifiers and checkbox values, and preserves the established queue-backend error mapping.
 *
 * <p>It also keeps direct-download creation deliberately narrow. That leaves later queue phases
 * free to add richer insert flows without reworking the basic control-plane contract.
 */
public final class QueueApiHandler {
  private static final String MAIL_APP_ID = "mail-prototype";
  private static final String ALERT_SUMMARY_PLACEHOLDER = "<!--CRYPTA_ALERT_SUMMARY-->";
  private static final String COMPATIBILITY_MODE_CURRENT = "COMPAT_CURRENT";
  private static final String COMPATIBILITY_MODE_DEFAULT = "COMPAT_DEFAULT";
  private static final String FORM_PASSWORD_PLACEHOLDER = "<!--CRYPTA_QUEUE_FORM_PASSWORD-->";
  private static final String PANIC_BOX_PLACEHOLDER = "<!--CRYPTA_QUEUE_PANIC_BOX-->";
  private static final String FIELD_OPERATION = "operation";
  private static final String FIELD_IDENTIFIER_COUNT = "identifierCount";
  private static final String IDENTIFIER_PARAMETER_PREFIX = "identifier-";
  private static final String PARAMETER_COMPATIBILITY_MODE = "compatibilityMode";
  private static final String PARAMETER_COMPRESS = "compress";
  private static final String PARAMETER_CONTENT_TYPE = "contentType";
  private static final String PARAMETER_DISABLE_FILTER_DATA = "disableFilterData";
  private static final String PARAMETER_DOCUMENT_BASE64 = "documentBase64";
  private static final String PARAMETER_FETCH_URI = "fetchUri";
  private static final String PARAMETER_FILTER_DATA = "filterData";
  private static final String PARAMETER_IDENTIFIER = "identifier";
  private static final String PARAMETER_INSERT_URI = "insertUri";
  private static final String PARAMETER_OVERRIDE_SPLITFILE_CRYPTO_KEY =
      "overrideSplitfileCryptoKey";
  private static final String PARAMETER_PAGE = "page";
  private static final String PARAMETER_PRIORITY = "priority";
  private static final String PARAMETER_SOURCE_PATH = "sourcePath";
  private static final String PARAMETER_TARGET_FILENAME = "targetFilename";
  private static final short MINIMUM_PRIORITY_CLASS = 0;
  private static final short MAXIMUM_PRIORITY_CLASS = 6;
  private static final int MAX_APP_DOCUMENT_BYTES =
      ContentFormatProfileRegistry.DEFAULT_APP_DOCUMENT_MAX_BYTES;
  private static final String DEFAULT_APP_DOCUMENT_CONTENT_TYPE =
      ContentFormatProfileRegistry.PROFILE_DOCUMENT_CONTENT_TYPE;
  private static final String DEFAULT_APP_DOCUMENT_TARGET_FILENAME =
      ContentFormatProfileRegistry.PROFILE_DOCUMENT_DEFAULT_FILENAME;
  private static final String OPERATION_APP_DOCUMENT_INSERT = "create_app_document_insert";
  private static final String OPERATION_LOCAL_DIRECTORY_INSERT = "create_local_directory_insert";
  private static final String OPERATION_LOCAL_FILE_INSERT = "create_local_file_insert";
  private static final String QUERY_PARAMETER_PREFIX = "Query parameter '";
  private static final String REDACTED_RESPONSE_VALUE = "<redacted>";
  private static final String QUEUE_PAGE_DOWNLOADS = "downloads";
  private static final String QUEUE_PAGE_UPLOADS = "uploads";
  private static final String SOURCE_TYPE_APP_DOCUMENT = "app-document";
  private static final String SOURCE_TYPE_DIRECTORY = "directory";
  private static final String SOURCE_TYPE_FILE = "file";

  /** Detached queue snapshot read port. */
  private final QueuePagePort queuePagePort;

  /** Detached queue mutation port for already-existing requests. */
  private final QueueMutationPort queueMutationPort;

  /** Detached download-creation port for new direct downloads. */
  private final QueueDownloadPort queueDownloadPort;

  /** Detached insert-creation port for new local, directory, and generated-document inserts. */
  private final QueueInsertPort queueInsertPort;

  /** Detached queue support port used for availability checks. */
  private final QueueSupportPort queueSupportPort;

  /** Detached completion tracker startup hook used when a queue side is rendered. */
  private final QueueCompletionPort queueCompletionPort;

  /** Preparation service for bounded app-generated document uploads. */
  private final AppGeneratedDocumentStagingService appDocumentStagingService;

  /**
   * Creates a queue API handler backed by the existing queue runtime ports.
   *
   * <p>All ports are required because even the small initial queue surface spans detached reads,
   * existing-request mutations, direct-download creation, generated-document insert creation,
   * backend availability checks, and completion-tracker startup for rendered queue sides.
   *
   * @param queuePagePort detached queue snapshot read port used for queue pages and count views
   * @param queueMutationPort detached mutation port for already-existing queue requests
   * @param queueDownloadPort detached direct-download creation port for new download requests
   * @param queueInsertPort detached insert-creation port for new local, directory, and generated
   *     document inserts
   * @param queueSupportPort detached queue support port used for backend availability checks
   * @param queueCompletionPort detached completion-tracker startup hook for rendered queue sides
   * @throws NullPointerException if any required to be detached runtime port reference is {@code
   *     null}
   */
  public QueueApiHandler(
      QueuePagePort queuePagePort,
      QueueMutationPort queueMutationPort,
      QueueDownloadPort queueDownloadPort,
      QueueInsertPort queueInsertPort,
      QueueSupportPort queueSupportPort,
      QueueCompletionPort queueCompletionPort) {
    this(
        queuePagePort,
        queueMutationPort,
        queueDownloadPort,
        queueInsertPort,
        queueSupportPort,
        queueCompletionPort,
        new AppGeneratedDocumentStagingService());
  }

  /**
   * Creates a queue API handler backed by runtime ports and an app-document upload service.
   *
   * @param queuePagePort detached queue snapshot read port used for queue pages and count views
   * @param queueMutationPort detached mutation port for already-existing queue requests
   * @param queueDownloadPort detached direct-download creation port for new download requests
   * @param queueInsertPort detached insert-creation port for new local, directory, and generated
   *     document inserts
   * @param queueSupportPort detached queue support port used for backend availability checks
   * @param queueCompletionPort detached completion-tracker startup hook for rendered queue sides
   * @param appDocumentStagingService upload service for browser/app-generated document bytes
   * @throws NullPointerException if any required to be detached runtime port reference is {@code
   *     null}
   */
  public QueueApiHandler(
      QueuePagePort queuePagePort,
      QueueMutationPort queueMutationPort,
      QueueDownloadPort queueDownloadPort,
      QueueInsertPort queueInsertPort,
      QueueSupportPort queueSupportPort,
      QueueCompletionPort queueCompletionPort,
      AppGeneratedDocumentStagingService appDocumentStagingService) {
    this.queuePagePort = Objects.requireNonNull(queuePagePort, "queuePagePort");
    this.queueMutationPort = Objects.requireNonNull(queueMutationPort, "queueMutationPort");
    this.queueDownloadPort = Objects.requireNonNull(queueDownloadPort, "queueDownloadPort");
    this.queueInsertPort = Objects.requireNonNull(queueInsertPort, "queueInsertPort");
    this.queueSupportPort = Objects.requireNonNull(queueSupportPort, "queueSupportPort");
    this.queueCompletionPort = Objects.requireNonNull(queueCompletionPort, "queueCompletionPort");
    this.appDocumentStagingService =
        Objects.requireNonNull(appDocumentStagingService, "appDocumentStagingService");
  }

  /**
   * Returns one detached queue page snapshot as a JSON-compatible object.
   *
   * <p>The caller selects one queue side with {@code page} and may opt into the same advanced-mode
   * and sorting controls that the legacy queue page already understands. Successful reads also
   * ensure that the detached completion tracker is started for the rendered side so the shell sees
   * the same completion-aware runtime behavior as the legacy operator path.
   *
   * @param queryParameters decoded request parameters for the current API call, including page
   *     selection and optional advanced-mode or sorting fields
   * @return JSON-compatible queue page snapshot containing the selected side, detached title, and
   *     placeholder-free HTML fragment for shell rendering
   * @throws PlatformApiException if required parameters are missing, malformed, or the queue
   *     backend is currently unavailable
   */
  public Map<String, Object> snapshot(Map<String, List<String>> queryParameters) {
    QueueSide page = requireQueueSide(queryParameters);
    boolean advancedMode =
        PlatformApiParameters.readBoolean(queryParameters, "advancedMode", false);
    String sortBy = optionalString(queryParameters, "sortBy");
    boolean reversed = PlatformApiParameters.readBoolean(queryParameters, "reversed", false);
    ensureQueueReadable(page.uploads());

    QueuePageSnapshot snapshot =
        readQueuePage(
            () ->
                queuePagePort.renderPage(
                    new QueuePageRequest(page.uploads(), advancedMode, sortBy, reversed)));

    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(6);
    json.put("page", page.apiValue());
    json.put("pageTitle", snapshot.pageTitle());
    json.put("contentHtml", stripRuntimePlaceholders(snapshot.contentHtmlTemplate()));
    json.put("advancedMode", advancedMode);
    json.put("sortBy", sortBy);
    json.put("reversed", reversed);
    return json;
  }

  /**
   * Returns the detached queue count snapshot for one queue side.
   *
   * <p>The underlying runtime currently exposes only the download-side count view. This method
   * therefore rejects {@code page=uploads} instead of returning mislabeled data. When the count is
   * available, it is wrapped in the same small JSON envelope shape used by the other queue reads so
   * the shell can treat it as an auxiliary panel.
   *
   * @param queryParameters decoded request parameters for the current API call, including the
   *     required queue-side selector
   * @return JSON-compatible count snapshot for the download queue side
   * @throws PlatformApiException if the page selector is missing, unsupported, or the queue backend
   *     is currently unavailable
   */
  public Map<String, Object> count(Map<String, List<String>> queryParameters) {
    QueueSide page = requireQueueSide(queryParameters);
    if (page.uploads()) {
      throw invalidQuery(
          queryParameter(PARAMETER_PAGE) + " must be 'downloads' for this endpoint.");
    }
    ensureQueueReadable(false);

    QueuePageSnapshot snapshot = readQueuePage(() -> queuePagePort.renderCountPage(false));
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(3);
    json.put("page", page.apiValue());
    json.put("pageTitle", snapshot.pageTitle());
    json.put("contentHtml", stripRuntimePlaceholders(snapshot.contentHtmlTemplate()));
    return json;
  }

  /**
   * Returns the detached queue key export as a JSON list.
   *
   * <p>The runtime port still emits the key list as newline-delimited text. This method trims that
   * output into a stable JSON array, preserving the legacy queue-side split while giving the shell
   * and other callers a transport-neutral export shape that is easier to render or download.
   *
   * @param queryParameters decoded request parameters for the current API call, including the
   *     required queue-side selector
   * @return JSON-compatible queue key export containing the selected side, key count, and trimmed
   *     key list entries
   * @throws PlatformApiException if the page selector is missing, invalid, or the queue backend is
   *     currently unavailable
   */
  public Map<String, Object> keys(Map<String, List<String>> queryParameters) {
    QueueSide page = requireQueueSide(queryParameters);
    ensureQueueReadable(page.uploads());

    String rawKeyList = readKeyList(page.uploads());
    List<String> keys =
        rawKeyList.lines().map(String::trim).filter(line -> !line.isEmpty()).toList();

    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(3);
    json.put("page", page.apiValue());
    json.put("keyCount", keys.size());
    json.put("keys", keys);
    return json;
  }

  /**
   * Removes already-existing queue requests.
   *
   * <p>The request may identify selections either through repeated {@code identifier} parameters or
   * the numbered {@code identifier-*} fields emitted by the legacy queue tables. The handler
   * preserves the caller's row order before invoking the detached mutation port so downstream
   * partial-failure behavior stays aligned with the user's selection order.
   *
   * @param queryParameters decoded request parameters for the current API call, including one or
   *     more queue request identifiers
   * @return JSON-compatible mutation summary reporting the remove operation and identifier count
   * @throws PlatformApiException if no identifiers are supplied, if any identifier field is
   *     malformed, or if the queue backend is unavailable
   */
  public Map<String, Object> removeRequests(Map<String, List<String>> queryParameters) {
    List<String> identifiers = requireIdentifiers(queryParameters);
    ensureQueueBackendEnabled();
    mutateQueue(() -> queueMutationPort.removeRequests(identifiers));
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(2);
    json.put(FIELD_OPERATION, "remove");
    json.put(FIELD_IDENTIFIER_COUNT, identifiers.size());
    return json;
  }

  /**
   * Restarts already-existing queue requests.
   *
   * <p>This endpoint accepts the legacy restart checkbox conventions as well as normalized boolean
   * values. That keeps Web Shell submissions and transplanted legacy form payloads compatible while
   * still returning one explicit JSON summary that states whether filter bypass was requested.
   *
   * @param queryParameters decoded request parameters for the current API call, including one or
   *     more queue request identifiers and the optional disable-filter checkbox value
   * @return JSON-compatible mutation summary reporting the restart operation, identifier count, and
   *     normalized filter-bypass flag
   * @throws PlatformApiException if the identifiers are missing or malformed, if the checkbox value
   *     cannot be interpreted, or if the queue backend is unavailable
   */
  public Map<String, Object> restartRequests(Map<String, List<String>> queryParameters) {
    List<String> identifiers = requireIdentifiers(queryParameters);
    boolean disableFilterData = readCheckboxBoolean(queryParameters, PARAMETER_DISABLE_FILTER_DATA);
    ensureQueueBackendEnabled();
    mutateQueue(() -> queueMutationPort.restartRequests(identifiers, disableFilterData));

    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(3);
    json.put(FIELD_OPERATION, "restart");
    json.put(FIELD_IDENTIFIER_COUNT, identifiers.size());
    json.put(PARAMETER_DISABLE_FILTER_DATA, disableFilterData);
    return json;
  }

  /**
   * Changes the priority class of already-existing queue requests.
   *
   * <p>The handler validates the detached priority value before it reaches the runtime port. That
   * keeps malformed or out-of-range API calls from becoming misleading no-ops or backend failures
   * when the queue tries to re-register the affected requests with the scheduler.
   *
   * @param queryParameters decoded request parameters for the current API call, including one or
   *     more queue request identifiers and the requested detached priority class
   * @return JSON-compatible mutation summary reporting the change-priority operation, identifier
   *     count, and accepted priority class
   * @throws PlatformApiException if the identifiers are missing, if the priority is malformed or
   *     out of the supported range, or if the queue backend is unavailable
   */
  public Map<String, Object> changePriority(Map<String, List<String>> queryParameters) {
    List<String> identifiers = requireIdentifiers(queryParameters);
    short priority = requirePriority(queryParameters);
    ensureQueueBackendEnabled();
    mutateQueue(() -> queueMutationPort.changePriority(identifiers, priority));

    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(3);
    json.put(FIELD_OPERATION, "change_priority");
    json.put(FIELD_IDENTIFIER_COUNT, identifiers.size());
    json.put(PARAMETER_PRIORITY, priority);
    return json;
  }

  /**
   * Removes completed upload requests using the legacy cleanup semantics.
   *
   * <p>The current cleanup endpoints do not accept additional knobs. The query-parameter map is
   * still required, so this method shares the same transport-neutral entry shape as the other queue
   * mutations and can grow later without changing the router contract.
   *
   * @param queryParameters decoded request parameters for the current API call; currently present
   *     only to preserve the shared queue mutation shape
   * @return JSON-compatible cleanup summary identifying the legacy cleanup operation and upload
   *     target side
   * @throws NullPointerException if {@code queryParameters} is {@code null}
   * @throws PlatformApiException if the queue backend is unavailable when the cleanup runs
   */
  public Map<String, Object> cleanupUploads(Map<String, List<String>> queryParameters) {
    Objects.requireNonNull(queryParameters, "queryParameters");
    ensureQueueBackendEnabled();
    mutateQueue(queueMutationPort::removeFinishedUploads);
    return cleanupResult(QUEUE_PAGE_UPLOADS);
  }

  /**
   * Removes completed download requests using the legacy cleanup semantics.
   *
   * <p>This endpoint mirrors the legacy finished-download cleanup action and deliberately keeps the
   * detached JSON response small. Callers get a stable operation and target summary while the
   * runtime port retains the authoritative definition of what counts as a finished download entry.
   *
   * @param queryParameters decoded request parameters for the current API call; currently present
   *     only to preserve the shared queue mutation shape
   * @return JSON-compatible cleanup summary identifying the legacy cleanup operation and download
   *     target side
   * @throws NullPointerException if {@code queryParameters} is {@code null}
   * @throws PlatformApiException if the queue backend is unavailable when the cleanup runs
   */
  public Map<String, Object> cleanupDownloads(Map<String, List<String>> queryParameters) {
    Objects.requireNonNull(queryParameters, "queryParameters");
    ensureQueueBackendEnabled();
    mutateQueue(queueMutationPort::removeFinishedDownloads);
    return cleanupResult(QUEUE_PAGE_DOWNLOADS);
  }

  /**
   * Queues one new direct download using the existing detached download SPI.
   *
   * <p>This initial Platform API surface keeps direct-download creation intentionally narrow. It
   * always creates a persistent direct-return download and leaves browser uploads and local file or
   * directory insert flows on the legacy queue pages for now.
   *
   * <p>The caller may provide either {@code fetchUri} or the legacy {@code key} alias and may
   * optionally supply a MIME hint. The handler validates the URI syntax up front, normalizes the
   * filter checkbox, and then delegates to the detached runtime port with the fixed persistent
   * direct-return contract for this phase.
   *
   * @param queryParameters decoded request parameters for the current API call, including the
   *     required fetch URI and optional filter or MIME fields
   * @return JSON-compatible creation summary describing the queued direct download request
   * @throws PlatformApiException if the URI is missing or invalid, if the queue backend is
   *     unavailable, or if the runtime port rejects or fails the request
   */
  public Map<String, Object> createDirectDownload(Map<String, List<String>> queryParameters) {
    String fetchUri = requireFetchUri(queryParameters);
    boolean filterData = readCheckboxBoolean(queryParameters, PARAMETER_FILTER_DATA);
    String expectedMimeType = optionalString(queryParameters, "expectedMimeType");
    ensureQueueBackendEnabled();

    try {
      queueDownloadPort.enqueueDownload(
          new QueueDownloadRequest(
              fetchUri, filterData, expectedMimeType, "forever", "direct", null));
    } catch (QueueDownloadRejectedException _) {
      throw new PlatformApiException(
          409, "queue_download_rejected", "Direct download rejected by the queue backend.");
    } catch (RequestQueueUnavailableException _) {
      throw queueUnavailable();
    } catch (IOException _) {
      throw new PlatformApiException(500, "internal_error", "Failed to enqueue direct download.");
    }

    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(5);
    json.put(FIELD_OPERATION, "create_direct_download");
    json.put(PARAMETER_FETCH_URI, fetchUri);
    json.put(PARAMETER_FILTER_DATA, filterData);
    json.put("expectedMimeType", expectedMimeType);
    json.put("returnType", "direct");
    return json;
  }

  /**
   * Queues one new persistent insert backed by a local file path.
   *
   * <p>The handler validates the small Platform API surface up front, keeps compatibility-mode and
   * compression parsing inside the transport-neutral layer, and then delegates the actual access
   * checks plus request creation to the detached runtime insert port.
   *
   * <p>Two legacy queue semantics are preserved here because they directly affect the retrieval URI
   * users will see later. First, when the caller omits {@code contentType}, the handler infers one
   * from the local file name using Cryptad's MIME registry rather than the host JVM's platform MIME
   * tables. Second, when the insert URI already carries a doc name, the handler suppresses any
   * explicit target filename so the insert does not become a one-file manifest wrapper rooted below
   * an extra path segment. Compatibility-mode validation also comes from the runtime-facing queue
   * support port, so {@code COMPAT_CURRENT} and {@code COMPAT_DEFAULT} expand to whatever concrete
   * mode the live node currently treats as its queue insert default.
   *
   * @param queryParameters decoded request parameters for the current API call
   * @return JSON-compatible creation summary describing the local-file insert request
   * @throws PlatformApiException if required parameters are missing, malformed, rejected by the
   *     runtime, or the queue backend is unavailable
   */
  public Map<String, Object> createLocalFileInsert(Map<String, List<String>> queryParameters) {
    File sourceFile = requireSourcePath(queryParameters, false);
    String insertUri = PlatformApiParameters.requireString(queryParameters, PARAMETER_INSERT_URI);
    FreenetURI parsedInsertUri = requireInsertUri(insertUri);
    String identifier = PlatformApiParameters.requireString(queryParameters, PARAMETER_IDENTIFIER);
    String contentType = resolveContentType(queryParameters, sourceFile);
    String targetFilename = resolveTargetFilename(queryParameters, sourceFile, parsedInsertUri);
    QueueInsertOptions options = requireInsertOptions(queryParameters);
    ensureQueueBackendEnabled();

    QueueInsertOutcome outcome;
    try {
      outcome =
          queueInsertPort.enqueueLocalFileInsert(
              new QueueLocalFileInsertRequest(
                  sourceFile, insertUri, identifier, contentType, options, targetFilename));
    } catch (QueueInsertRejectedException e) {
      throw queueInsertRejected(SOURCE_TYPE_FILE, e);
    } catch (RequestQueueUnavailableException _) {
      throw queueUnavailable();
    } catch (IOException _) {
      throw new PlatformApiException(500, "internal_error", "Failed to enqueue local file insert.");
    }

    return insertCreationResult(
        OPERATION_LOCAL_FILE_INSERT,
        SOURCE_TYPE_FILE,
        sourceFile.getPath(),
        insertUri,
        identifier,
        outcome);
  }

  /**
   * Queues one new persistent insert backed by a local directory path.
   *
   * <p>The Platform API deliberately keeps directory insert creation narrow for this phase: callers
   * provide one local path plus the detached insert metadata, and the runtime insert port remains
   * authoritative for directory traversal, file-count limits, and queue registration.
   *
   * <p>Directory inserts still share the queue insert compatibility policy with the legacy HTTP
   * queue flow. The handler therefore validates the supplied compatibility mode against the live
   * queue support port instead of freezing a historical list of accepted names inside the Platform
   * API leaf. That keeps queue inserts, the Publisher surface, and the legacy queue forms aligned
   * when the runtime changes which historical modes are still accepted or which concrete mode the
   * node treats as its default.
   *
   * @param queryParameters decoded request parameters for the current API call
   * @return JSON-compatible creation summary describing the local-directory insert request
   * @throws PlatformApiException if required parameters are missing, malformed, rejected by the
   *     runtime, or the queue backend is unavailable
   */
  public Map<String, Object> createLocalDirectoryInsert(Map<String, List<String>> queryParameters) {
    File sourceDirectory = requireSourcePath(queryParameters, true);
    String insertUri = PlatformApiParameters.requireString(queryParameters, PARAMETER_INSERT_URI);
    requireInsertUri(insertUri);
    String identifier = PlatformApiParameters.requireString(queryParameters, PARAMETER_IDENTIFIER);
    QueueInsertOptions options = requireInsertOptions(queryParameters);
    ensureQueueBackendEnabled();

    QueueInsertOutcome outcome;
    try {
      outcome =
          queueInsertPort.enqueueLocalDirectoryInsert(
              new QueueLocalDirectoryInsertRequest(
                  sourceDirectory, insertUri, identifier, options));
    } catch (QueueInsertRejectedException e) {
      throw queueInsertRejected(SOURCE_TYPE_DIRECTORY, e);
    } catch (RequestQueueUnavailableException _) {
      throw queueUnavailable();
    } catch (IOException _) {
      throw new PlatformApiException(
          500, "internal_error", "Failed to enqueue local directory insert.");
    }

    return insertCreationResult(
        OPERATION_LOCAL_DIRECTORY_INSERT,
        SOURCE_TYPE_DIRECTORY,
        sourceDirectory.getPath(),
        insertUri,
        identifier,
        outcome);
  }

  /**
   * Queues one persistent insert backed by bounded app-generated document bytes.
   *
   * <p>The browser caller supplies Base64-encoded generated bytes rather than a local source path.
   * The handler validates size, UTF-8/JSON syntax for JSON content types, and queue metadata, then
   * hands detached bytes to the queue browser-upload path so the runtime can copy them into its
   * trusted persistent bucket storage. The public response redacts the synthetic source path.
   *
   * @param appId authenticated app id supplied by the app principal
   * @param queryParameters decoded request parameters for the app-document insert
   * @return JSON-compatible creation summary with a redacted source path
   * @throws PlatformApiException if required parameters are missing, malformed, or rejected
   */
  public Map<String, Object> createAppDocumentInsert(
      String appId, Map<String, List<String>> queryParameters) {
    String insertUri = PlatformApiParameters.requireString(queryParameters, PARAMETER_INSERT_URI);
    FreenetURI parsedInsertUri = requireInsertUri(insertUri);
    String identifier = PlatformApiParameters.requireString(queryParameters, PARAMETER_IDENTIFIER);
    if (MAIL_APP_ID.equals(appId) || identifier.startsWith("app-document-mail-prototype-")) {
      requireAppDocumentIdentifier(appId, identifier);
    }
    if (MAIL_APP_ID.equals(appId) && !"CHK@".equals(insertUri)) {
      throw new PlatformApiException(
          400, "mail_insert_target_invalid", "Mail inserts require CHK.");
    }
    byte[] document = decodeAppDocument(queryParameters);
    if (MAIL_APP_ID.equals(appId)) {
      try {
        MailHpke.validateNetworkEnvelope(document);
      } catch (IllegalArgumentException _) {
        throw new PlatformApiException(400, "mail_envelope_rejected", "Mail envelope rejected.");
      }
    }
    String contentType = resolveAppDocumentContentType(queryParameters);
    validateJsonDocumentIfNeeded(contentType, document);
    String targetFilename =
        Objects.requireNonNullElse(
            optionalString(queryParameters, PARAMETER_TARGET_FILENAME),
            DEFAULT_APP_DOCUMENT_TARGET_FILENAME);
    QueueInsertOptions options = requireAppDocumentInsertOptions(queryParameters);
    ensureQueueBackendEnabled();

    AppGeneratedDocumentStagingResult staged =
        appDocumentStagingService.stage(appId, targetFilename, contentType, document);
    QueueInsertOutcome outcome;
    try {
      String filenameForKey = resolveFilenameForKey(parsedInsertUri, staged.upload().filename());
      outcome =
          queueInsertPort.enqueueBrowserUploadInsert(
              new QueueBrowserUploadInsertRequest(
                  insertUri, identifier, staged.upload(), options, filenameForKey));
    } catch (QueueInsertRejectedException e) {
      throw queueInsertRejected(SOURCE_TYPE_APP_DOCUMENT, e);
    } catch (RequestQueueUnavailableException _) {
      throw queueUnavailable();
    } catch (IOException _) {
      throw new PlatformApiException(
          500, "internal_error", "Failed to enqueue app-document insert.");
    }

    return insertCreationResult(
        OPERATION_APP_DOCUMENT_INSERT,
        SOURCE_TYPE_APP_DOCUMENT,
        staged.publicSourcePath(),
        REDACTED_RESPONSE_VALUE,
        identifier,
        outcome);
  }

  private void ensureQueueReadable(boolean uploads) {
    ensureQueueBackendEnabled();
    queueCompletionPort.ensureTrackingStarted(uploads);
  }

  private void ensureQueueBackendEnabled() {
    if (!queueSupportPort.isQueueBackendEnabled()) {
      throw new PlatformApiException(
          409, "queue_backend_disabled", "Queue backend is currently disabled.");
    }
  }

  /**
   * Reads typed completion state for an app-namespaced generated-document operation.
   *
   * @param appId authenticated owning app id
   * @param parameters exact identifier parameter
   * @return bounded state and successful CHK reference, never a delivery/read receipt
   */
  public Map<String, Object> appDocumentStatus(String appId, Map<String, List<String>> parameters) {
    String identifier = PlatformApiParameters.requireString(parameters, PARAMETER_IDENTIFIER);
    requireAppDocumentIdentifier(appId, identifier);
    ensureQueueBackendEnabled();
    try {
      var status = queuePagePort.readInsertStatus(identifier);
      Map<String, Object> result = new LinkedHashMap<>();
      result.put("state", status.state());
      result.put("reference", status.reference());
      return result;
    } catch (RequestQueueUnavailableException _) {
      throw queueUnavailable();
    }
  }

  private static void requireAppDocumentIdentifier(String appId, String identifier) {
    String prefix = "app-document-" + appId + "-";
    if (!identifier.startsWith(prefix)
        || !identifier.substring(prefix.length()).matches("[0-9a-f]{32}")) {
      throw new PlatformApiException(
          403,
          "app_document_identifier_denied",
          "Generated-document identifier is not scoped to this app.");
    }
  }

  private QueuePageSnapshot readQueuePage(QueuePageReadOperation operation) {
    try {
      return operation.read();
    } catch (RequestQueueUnavailableException _) {
      throw queueUnavailable();
    }
  }

  private String readKeyList(boolean uploads) {
    try {
      return queuePagePort.renderKeyList(uploads);
    } catch (RequestQueueUnavailableException _) {
      throw queueUnavailable();
    }
  }

  private void mutateQueue(QueueMutationOperation operation) {
    try {
      operation.apply();
    } catch (RequestQueueUnavailableException _) {
      throw queueUnavailable();
    }
  }

  private static Map<String, Object> cleanupResult(String target) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(2);
    json.put(FIELD_OPERATION, "cleanup");
    json.put("target", target);
    return json;
  }

  private static QueueSide requireQueueSide(Map<String, List<String>> queryParameters) {
    String raw = PlatformApiParameters.requireString(queryParameters, PARAMETER_PAGE);
    return switch (raw) {
      case QUEUE_PAGE_DOWNLOADS -> QueueSide.DOWNLOADS;
      case QUEUE_PAGE_UPLOADS -> QueueSide.UPLOADS;
      default ->
          throw invalidQuery(
              queryParameter(PARAMETER_PAGE)
                  + " must be either '"
                  + QUEUE_PAGE_DOWNLOADS
                  + "' or '"
                  + QUEUE_PAGE_UPLOADS
                  + "'.");
    };
  }

  private static String requireFetchUri(Map<String, List<String>> queryParameters) {
    String fetchUri = optionalString(queryParameters, PARAMETER_FETCH_URI);
    if (fetchUri == null) {
      fetchUri = optionalString(queryParameters, "key");
    }
    if (fetchUri == null || fetchUri.isBlank()) {
      throw invalidQuery("Missing required query parameter '" + PARAMETER_FETCH_URI + "'.");
    }
    try {
      new FreenetURI(fetchUri);
    } catch (MalformedURLException _) {
      throw invalidQuery(queryParameter(PARAMETER_FETCH_URI) + " must be a valid fetch URI.");
    }
    return fetchUri;
  }

  private static File requireSourcePath(
      Map<String, List<String>> queryParameters, boolean expectDirectory) {
    String sourcePath = PlatformApiParameters.requireString(queryParameters, PARAMETER_SOURCE_PATH);
    File source = new File(sourcePath);
    if (source.exists()) {
      if (expectDirectory && !source.isDirectory()) {
        throw invalidQuery(
            queryParameter(PARAMETER_SOURCE_PATH)
                + " must refer to a local directory for this endpoint.");
      }
      if (!expectDirectory && !source.isFile()) {
        throw invalidQuery(
            queryParameter(PARAMETER_SOURCE_PATH)
                + " must refer to a local file for this endpoint.");
      }
    }
    return source;
  }

  private static FreenetURI requireInsertUri(String insertUri) {
    try {
      return new FreenetURI(insertUri);
    } catch (MalformedURLException _) {
      throw invalidQuery(queryParameter(PARAMETER_INSERT_URI) + " must be a valid insert URI.");
    }
  }

  private static String resolveTargetFilename(
      Map<String, List<String>> queryParameters, File sourceFile, FreenetURI insertUri) {
    String explicitTargetFilename = optionalString(queryParameters, PARAMETER_TARGET_FILENAME);
    return resolveFilenameForKey(
        insertUri, explicitTargetFilename == null ? sourceFile.getName() : explicitTargetFilename);
  }

  private static String resolveFilenameForKey(FreenetURI insertUri, String targetFilename) {
    return insertUri.getDocName() == null ? targetFilename : null;
  }

  private static String resolveContentType(
      Map<String, List<String>> queryParameters, File sourceFile) {
    String contentType = optionalString(queryParameters, PARAMETER_CONTENT_TYPE);
    if (contentType == null) {
      contentType = guessContentType(sourceFile.getName());
    }
    validateContentType(contentType);
    return contentType;
  }

  private static String guessContentType(String filename) {
    return MediaType.guessMIMEType(filename);
  }

  private static void validateContentType(String contentType) {
    try {
      new MediaType(contentType);
    } catch (MalformedURLException | NullPointerException _) {
      throw invalidQuery(
          queryParameter(PARAMETER_CONTENT_TYPE) + " must be a plausible MIME type.");
    }
  }

  private QueueInsertOptions requireInsertOptions(Map<String, List<String>> queryParameters) {
    rejectOverrideSplitfileCryptoKey(queryParameters);
    return new QueueInsertOptions(
        readCheckboxBoolean(queryParameters, PARAMETER_COMPRESS),
        requireCompatibilityMode(queryParameters),
        null);
  }

  private QueueInsertOptions requireAppDocumentInsertOptions(
      Map<String, List<String>> queryParameters) {
    rejectOverrideSplitfileCryptoKey(queryParameters);
    return new QueueInsertOptions(
        readCheckboxBoolean(queryParameters, PARAMETER_COMPRESS),
        requireCompatibilityModeWithDefault(queryParameters, COMPATIBILITY_MODE_CURRENT),
        null);
  }

  private String requireCompatibilityMode(Map<String, List<String>> queryParameters) {
    return requireCompatibilityModeWithDefault(queryParameters, null);
  }

  private String requireCompatibilityModeWithDefault(
      Map<String, List<String>> queryParameters, String defaultParameterValue) {
    String compatibilityMode = optionalString(queryParameters, PARAMETER_COMPATIBILITY_MODE);
    if (compatibilityMode == null) {
      if (defaultParameterValue == null) {
        throw invalidQuery(
            "Missing required query parameter '" + PARAMETER_COMPATIBILITY_MODE + "'.");
      }
      compatibilityMode = defaultParameterValue;
    }
    String defaultCompatibilityMode = queueSupportPort.defaultInsertCompatibilityMode();
    List<String> supportedCompatibilityModes = queueSupportPort.supportedInsertCompatibilityModes();
    if (COMPATIBILITY_MODE_CURRENT.equals(compatibilityMode)
        || COMPATIBILITY_MODE_DEFAULT.equals(compatibilityMode)) {
      return defaultCompatibilityMode;
    }
    if (supportedCompatibilityModes.contains(compatibilityMode)) {
      return compatibilityMode;
    }
    throw invalidQuery(
        queryParameter(PARAMETER_COMPATIBILITY_MODE)
            + " must be one of '"
            + COMPATIBILITY_MODE_CURRENT
            + "', '"
            + COMPATIBILITY_MODE_DEFAULT
            + "', or one of the concrete modes: "
            + String.join(", ", supportedCompatibilityModes)
            + ".");
  }

  private static void rejectOverrideSplitfileCryptoKey(Map<String, List<String>> queryParameters) {
    String overrideKey = optionalString(queryParameters, PARAMETER_OVERRIDE_SPLITFILE_CRYPTO_KEY);
    if (overrideKey != null) {
      throw invalidQuery(
          queryParameter(PARAMETER_OVERRIDE_SPLITFILE_CRYPTO_KEY)
              + " is not supported by this endpoint yet.");
    }
  }

  private static List<String> requireIdentifiers(Map<String, List<String>> queryParameters) {
    ArrayList<String> identifiers = new ArrayList<>();
    List<String> repeatedIdentifiers = queryParameters.get(PARAMETER_IDENTIFIER);
    if (repeatedIdentifiers != null) {
      for (String identifier : repeatedIdentifiers) {
        addIdentifier(identifiers, identifier);
      }
    }

    // Legacy queue pages emit numbered identifier-* fields; sort by suffix so HashMap-backed
    // request parsing does not scramble the caller's row order before the mutation port sees it.
    for (Map.Entry<String, List<String>> entry : sortedIdentifierEntries(queryParameters)) {
      if (entry.getValue().size() != 1) {
        throw invalidQuery(queryParameter(entry.getKey()) + " must not be repeated.");
      }
      addIdentifier(identifiers, entry.getValue().getFirst());
    }

    if (identifiers.isEmpty()) {
      throw invalidQuery("At least one queue request identifier must be selected.");
    }
    return List.copyOf(identifiers);
  }

  private static List<Map.Entry<String, List<String>>> sortedIdentifierEntries(
      Map<String, List<String>> queryParameters) {
    return queryParameters.entrySet().stream()
        .filter(entry -> entry.getKey().startsWith(IDENTIFIER_PARAMETER_PREFIX))
        .sorted(Map.Entry.comparingByKey(QueueApiHandler::compareIdentifierKeys))
        .toList();
  }

  private static int compareIdentifierKeys(String firstKey, String secondKey) {
    String firstSuffix = firstKey.substring(IDENTIFIER_PARAMETER_PREFIX.length());
    String secondSuffix = secondKey.substring(IDENTIFIER_PARAMETER_PREFIX.length());
    if (isDigitsOnly(firstSuffix) && isDigitsOnly(secondSuffix)) {
      int byLength = Integer.compare(firstSuffix.length(), secondSuffix.length());
      return byLength != 0 ? byLength : firstSuffix.compareTo(secondSuffix);
    }
    return firstSuffix.compareTo(secondSuffix);
  }

  private static boolean isDigitsOnly(String value) {
    for (int i = 0; i < value.length(); i++) {
      if (!Character.isDigit(value.charAt(i))) {
        return false;
      }
    }
    return !value.isEmpty();
  }

  private static void addIdentifier(List<String> identifiers, String identifier) {
    if (identifier == null || identifier.isBlank()) {
      throw invalidQuery("Queue request identifiers must not be blank.");
    }
    identifiers.add(identifier);
  }

  private static short requirePriority(Map<String, List<String>> queryParameters) {
    String raw = PlatformApiParameters.requireString(queryParameters, PARAMETER_PRIORITY);
    short priority;
    try {
      priority = Short.parseShort(raw);
    } catch (NumberFormatException _) {
      throw invalidQuery(queryParameter(PARAMETER_PRIORITY) + " must be a valid short integer.");
    }
    if (priority < MINIMUM_PRIORITY_CLASS || priority > MAXIMUM_PRIORITY_CLASS) {
      throw invalidQuery(
          queryParameter(PARAMETER_PRIORITY)
              + " must be between "
              + MINIMUM_PRIORITY_CLASS
              + " and "
              + MAXIMUM_PRIORITY_CLASS
              + ".");
    }
    return priority;
  }

  private static boolean readCheckboxBoolean(
      Map<String, List<String>> queryParameters, String name) {
    List<String> values = queryParameters.get(name);
    if (values == null || values.isEmpty()) {
      return false;
    }
    boolean anyTruthy = false;
    for (String raw : values) {
      if (raw == null || isTruthyCheckboxValue(raw, name)) {
        anyTruthy = true;
      } else if (!isFalseyCheckboxValue(raw)) {
        throw invalidQuery(
            queryParameter(name)
                + " must be a checkbox value or one of 'true', 'false', 'on', or 'off'.");
      }
    }
    return anyTruthy;
  }

  private static boolean isTruthyCheckboxValue(String raw, String name) {
    return raw.isBlank()
        || "true".equalsIgnoreCase(raw)
        || "on".equalsIgnoreCase(raw)
        || name.equals(raw);
  }

  private static boolean isFalseyCheckboxValue(String raw) {
    return "false".equalsIgnoreCase(raw) || "off".equalsIgnoreCase(raw);
  }

  private static String optionalString(Map<String, List<String>> queryParameters, String name) {
    String value = readSingleValue(queryParameters, name);
    if (value == null) {
      return null;
    }
    return value.isBlank() ? null : value;
  }

  private static String readSingleValue(Map<String, List<String>> queryParameters, String name) {
    List<String> values = queryParameters.get(name);
    if (values == null || values.isEmpty()) {
      return null;
    }
    if (values.size() > 1) {
      throw invalidQuery(queryParameter(name) + " must not be repeated.");
    }
    return values.getFirst();
  }

  private static String queryParameter(String name) {
    return QUERY_PARAMETER_PREFIX + name + "'";
  }

  private static Map<String, Object> insertCreationResult(
      String operation,
      String sourceType,
      String sourcePath,
      String insertUri,
      String identifier,
      QueueInsertOutcome outcome) {
    LinkedHashMap<String, Object> json = LinkedHashMap.newLinkedHashMap(6);
    json.put(FIELD_OPERATION, operation);
    json.put("sourceType", sourceType);
    json.put(PARAMETER_SOURCE_PATH, sourcePath);
    json.put(PARAMETER_INSERT_URI, insertUri);
    json.put(PARAMETER_IDENTIFIER, identifier);
    json.put("outcome", outcome.name());
    return json;
  }

  private static String stripRuntimePlaceholders(String contentHtmlTemplate) {
    return contentHtmlTemplate
        .replace(ALERT_SUMMARY_PLACEHOLDER, "")
        .replace(FORM_PASSWORD_PLACEHOLDER, "")
        .replace(PANIC_BOX_PLACEHOLDER, "");
  }

  private static PlatformApiException queueInsertRejected(
      String sourceType, QueueInsertRejectedException rejection) {
    QueueInsertFailureReason reason = rejection.reason();
    return new PlatformApiException(
        400,
        switch (reason) {
          case ACCESS_DENIED -> "queue_insert_rejected_access_denied";
          case SOURCE_NOT_FOUND -> "queue_insert_rejected_source_not_found";
          case TOO_MANY_FILES -> "queue_insert_rejected_too_many_files";
        },
        sourceDescription(sourceType)
            + " insert rejected by the queue backend: "
            + reason.name()
            + ".");
  }

  private static String sourceDescription(String sourceType) {
    if (SOURCE_TYPE_DIRECTORY.equals(sourceType)) {
      return "Local directory";
    }
    if (SOURCE_TYPE_APP_DOCUMENT.equals(sourceType)) {
      return "App-document";
    }
    return "Local file";
  }

  private static byte[] decodeAppDocument(Map<String, List<String>> queryParameters) {
    String documentBase64 =
        PlatformApiParameters.requirePresentString(queryParameters, PARAMETER_DOCUMENT_BASE64);
    if (documentBase64.length() > ((MAX_APP_DOCUMENT_BYTES + 2) / 3) * 4) {
      throw invalidQuery("Query parameter 'documentBase64' decodes to too many bytes.");
    }
    byte[] decoded;
    try {
      decoded = Base64.getDecoder().decode(documentBase64);
    } catch (IllegalArgumentException _) {
      throw invalidQuery("Query parameter 'documentBase64' must be valid Base64.");
    }
    if (decoded.length > MAX_APP_DOCUMENT_BYTES) {
      throw invalidQuery("Query parameter 'documentBase64' decodes to too many bytes.");
    }
    return decoded;
  }

  private static String resolveAppDocumentContentType(Map<String, List<String>> queryParameters) {
    String contentType =
        Objects.requireNonNullElse(
            optionalString(queryParameters, PARAMETER_CONTENT_TYPE),
            DEFAULT_APP_DOCUMENT_CONTENT_TYPE);
    validateContentType(contentType);
    return contentType;
  }

  private static void validateJsonDocumentIfNeeded(String contentType, byte[] document) {
    if (!isJsonContentType(contentType)) {
      return;
    }
    String text = decodeUtf8Document(document);
    try {
      JsonSyntaxValidator.validate(text);
    } catch (IllegalArgumentException _) {
      throw invalidQuery(
          "Query parameter 'documentBase64' must decode to valid JSON for JSON content types.");
    }
  }

  private static boolean isJsonContentType(String contentType) {
    String normalized = contentType.toLowerCase(java.util.Locale.ROOT);
    int parameterIndex = normalized.indexOf(';');
    String base =
        (parameterIndex >= 0 ? normalized.substring(0, parameterIndex) : normalized).trim();
    return base.equals("application/json") || base.endsWith("+json");
  }

  private static String decodeUtf8Document(byte[] document) {
    try {
      return StandardCharsets.UTF_8
          .newDecoder()
          .onMalformedInput(CodingErrorAction.REPORT)
          .onUnmappableCharacter(CodingErrorAction.REPORT)
          .decode(ByteBuffer.wrap(document))
          .toString();
    } catch (CharacterCodingException _) {
      throw invalidQuery("Query parameter 'documentBase64' must decode to UTF-8 JSON bytes.");
    }
  }

  private static PlatformApiException queueUnavailable() {
    return new PlatformApiException(
        409, "queue_unavailable", "Persistent request queue is currently unavailable.");
  }

  private static PlatformApiException invalidQuery(String message) {
    return new PlatformApiException(400, "invalid_query_parameter", message);
  }

  private enum QueueSide {
    DOWNLOADS(QUEUE_PAGE_DOWNLOADS, false),
    UPLOADS(QUEUE_PAGE_UPLOADS, true);

    private final String apiValue;
    private final boolean uploads;

    QueueSide(String apiValue, boolean uploads) {
      this.apiValue = apiValue;
      this.uploads = uploads;
    }

    private String apiValue() {
      return apiValue;
    }

    private boolean uploads() {
      return uploads;
    }
  }

  @FunctionalInterface
  private interface QueuePageReadOperation {
    QueuePageSnapshot read() throws RequestQueueUnavailableException;
  }

  @FunctionalInterface
  private interface QueueMutationOperation {
    void apply() throws RequestQueueUnavailableException;
  }
}
