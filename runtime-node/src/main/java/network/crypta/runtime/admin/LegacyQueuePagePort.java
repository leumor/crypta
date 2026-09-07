package network.crypta.runtime.admin;

import java.io.File;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import network.crypta.client.DefaultMIMETypes;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.FetchException;
import network.crypta.client.InsertContext;
import network.crypta.client.events.SplitfileProgressCounts;
import network.crypta.client.filter.ContentFilter;
import network.crypta.client.filter.FilterMIMEType;
import network.crypta.client.filter.KnownUnsafeContentTypeException;
import network.crypta.keys.FreenetURI;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.NodeClientCore;
import network.crypta.node.RequestStarter;
import network.crypta.node.SecurityLevels.PHYSICAL_THREAT_LEVEL;
import network.crypta.runtime.admin.queue.page.QueueCompressionState;
import network.crypta.runtime.admin.queue.page.QueuePageBackend;
import network.crypta.runtime.admin.queue.page.QueuePageDownloadView;
import network.crypta.runtime.admin.queue.page.QueuePageRequestView;
import network.crypta.runtime.admin.queue.page.QueuePageUploadDirView;
import network.crypta.runtime.admin.queue.page.QueuePageUploadFileView;
import network.crypta.runtime.admin.queue.page.QueuePageUploadView;
import network.crypta.runtime.admin.queue.page.QueueProgressCellContext;
import network.crypta.runtime.admin.queue.page.QueueProgressCellRenderer;
import network.crypta.runtime.spi.QueueInsertStatus;
import network.crypta.runtime.spi.QueuePagePort;
import network.crypta.runtime.spi.QueuePageRequest;
import network.crypta.runtime.spi.QueuePageSnapshot;
import network.crypta.runtime.spi.RequestQueueUnavailableException;
import network.crypta.support.Fields;
import network.crypta.support.HTMLNode;
import network.crypta.support.SizeUtil;
import network.crypta.support.TimeUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Renders the legacy queue GET/read path behind the runtime queue-page SPI.
 *
 * <p>This adapter keeps the heavy read-only queue traversal, partitioning, sorting, and HTML
 * fragment rendering in the daemon root module while returning detached snapshots to the HTTP
 * toadlet. The caller remains responsible for access checks, FCP-enabled checks, and injecting the
 * small request-context-only fragments such as alert summaries and form-password inputs.
 *
 * <p>Each render reads the current daemon state directly. The adapter does not cache queue data or
 * retain request-specific HTML trees between calls. That preserves the legacy queue page behavior
 * while moving live traversal logic behind the runtime-owned queue-page seam used by this adapter.
 *
 * <p>The class is intentionally internal to the root daemon module. It translates daemon-owned
 * request status objects into detached {@link QueuePageSnapshot} instances and plain-text key-list
 * exports, but it does not attempt to introduce a broader queue domain model in this migration.
 */
final class LegacyQueuePagePort implements QueuePagePort {
  private static final Logger LOG = LoggerFactory.getLogger(LegacyQueuePagePort.class);

  private static final String ATTR_CLASS = "class";
  private static final String ATTR_TYPE = "type";
  private static final String ATTR_NAME = "name";
  private static final String ATTR_VALUE = "value";
  private static final String ATTR_CHECKED = "checked";

  private static final String INPUT_TYPE_CHECKBOX = "checkbox";
  private static final String INPUT_TYPE_SUBMIT = "submit";
  private static final String INPUT_TYPE_HIDDEN = "hidden";
  private static final String TAG_INPUT = "input";
  private static final String TAG_LABEL = "label";
  private static final String TAG_TABLE = "table";

  private static final String INFOBOX_INFORMATION = "infobox-information";
  private static final String COMPLETED_REQUESTS = "completed_requests";
  private static final String FAILED_REQUESTS = "failed_requests";
  private static final String REQUESTS_IN_PROGRESS = "requests_in_progress";
  private static final String PRIORITY = "priority";
  private static final String STATUS_FAILED_UPLOAD = "failedU";
  private static final String UNKNOWN = "unknown";
  private static final String GROUPED_DOWNLOADS = "grouped-downloads";
  private static final String DOWNLOAD_FILES = "downloadFiles";
  private static final String BULK_DOWNLOADS = "bulkDownloads";
  private static final String TARGET = "target";
  private static final String RETURN_TYPE_DIRECT = "direct";
  private static final String FILTER_DATA = "filterData";
  private static final String FILTER_DATA_MESSAGE = "filterDataMessage";
  private static final String BULK_DOWNLOAD_SELECT_OPTION_DISK = "bulkDownloadSelectOptionDisk";
  private static final String BULK_DOWNLOAD_SELECT_OPTION_DIRECT = "bulkDownloadSelectOptionDirect";

  private static final String DELETE_REQUEST = "delete_request";
  private static final String REMOVE_REQUEST = "remove_request";
  private static final String REMOVE_FINISHED_UPLOADS_REQUEST = "remove_finished_uploads_request";
  private static final String REMOVE_FINISHED_DOWNLOADS_REQUEST =
      "remove_finished_downloads_request";
  private static final String RESTART_REQUEST = "restart_request";
  private static final String DISABLE_FILTER_DATA = "disableFilterData";
  private static final String IDENTIFIER_PREFIX = "identifier-";
  private static final String FILENAME_PREFIX = "filename-";
  private static final String KEY_PREFIX = "key-";
  private static final String COMPATIBILITY_MODE_FIELD = "compatibilityMode";
  private static final String INSERT_CONTEXT_COMPATIBILITY_MODE_PREFIX =
      "InsertContext.CompatibilityMode.";
  private static final String KEY_LIST_LOCATION = "listKeys.txt";
  private static final String FORM_PASSWORD_PLACEHOLDER = "<!--CRYPTA_QUEUE_FORM_PASSWORD-->";
  private static final String ALERT_SUMMARY_PLACEHOLDER = "<!--CRYPTA_ALERT_SUMMARY-->";
  private static final String PANIC_BOX_PLACEHOLDER = "<!--CRYPTA_QUEUE_PANIC_BOX-->";
  private static final String PROGRESS_LABEL = "progress";
  private static final String LAST_ACTIVITY_LABEL = "lastActivity";
  private static final String LAST_FAILURE_LABEL = "lastFailure";
  private static final int MAX_FILENAME_LENGTH = 1024 * 1024;

  private static final String DEFAULT_UPLOADS_SEGMENT = "uploads";
  private static final String DEFAULT_DOWNLOADS_SEGMENT = "downloads";
  private static final String PATH_UPLOADS =
      normalizePath(System.getProperty("queue.uploads.path", DEFAULT_UPLOADS_SEGMENT));
  private static final String PATH_DOWNLOADS =
      normalizePath(System.getProperty("crypta.fproxy.downloadsPath", DEFAULT_DOWNLOADS_SEGMENT));

  private static final String QUEUE_TOADLET_PREFIX = "QueueToadlet.";
  private static final char[] HEX_ARRAY = "0123456789abcdef".toCharArray();

  private final NodeClientCore core;
  private final QueuePageBackend queueBackend;

  /**
   * Creates the legacy queue-page adapter for one daemon instance.
   *
   * <p>The adapter keeps only the daemon core plus the runtime-owned queue-page backend. Queue
   * reads flow through the backend seam, while scheduler counts, security-level checks, and local
   * path selection still come from the client core.
   *
   * @param core daemon core that provides queue state, request schedulers, and lazy endpoint access
   * @param queueBackend runtime-owned queue-page backend used to read the current global queue
   * @throws NullPointerException if {@code core} is {@code null}
   */
  LegacyQueuePagePort(NodeClientCore core, QueuePageBackend queueBackend) {
    this.core = Objects.requireNonNull(core, "core");
    this.queueBackend = Objects.requireNonNull(queueBackend, "queueBackend");
  }

  /**
   * {@inheritDoc}
   *
   * <p>This implementation performs the full legacy GET-path read traversal, including request
   * partitioning, optional sorting, localized section assembly, and HTML-fragment generation. The
   * returned snapshot stays detached from daemon-owned types, so the HTTP layer can finish the page
   * without depending on live queue objects.
   */
  @Override
  public QueuePageSnapshot renderPage(QueuePageRequest request)
      throws RequestQueueUnavailableException {
    Objects.requireNonNull(request, "request");
    QueuePageRequestView[] reqs = globalRequests();
    QueuePartitions partitions = partitionRequests(reqs, request.uploads());
    if (!partitions.hasAny()) {
      return new QueuePageSnapshot(
          emptyPageTitle(request.uploads()), buildEmptyQueueContent(request.uploads()));
    }

    Comparator<QueuePageRequestView> jobComparator =
        createJobComparator(request.sortBy(), request.reversed());
    sortPartitions(partitions, jobComparator);
    logTotals(partitions);

    HTMLNode contentNode = new HTMLNode("#");
    addAlertSummaryPlaceholder(contentNode);
    addNavigationBar(contentNode, partitions, request.uploads());
    String[] priorityClasses = buildPriorityClasses();
    addLegend(contentNode, partitions, priorityClasses, request.advancedMode());
    addPanicBoxIfNeeded(contentNode);

    RequestTableContext tableContext =
        new RequestTableContext(request.advancedMode(), request.reversed(), priorityClasses);
    addCompletedSections(tableContext, contentNode, partitions, request.uploads());
    addFailureSections(tableContext, contentNode, partitions);
    addMimeFailureSections(tableContext, contentNode, partitions, jobComparator);
    addUncompletedSections(tableContext, contentNode, partitions);

    if (!request.uploads()) {
      contentNode.addChild(createBulkDownloadForm());
    }

    return new QueuePageSnapshot(
        buildPageName(partitions, request.uploads()), contentNode.generate());
  }

  /**
   * {@inheritDoc}
   *
   * <p>This implementation reads the current persistent and queued CHK counts from the request
   * schedulers and returns the same small status infobox that the legacy queue admin UI exposed for
   * the count subpage.
   */
  @Override
  public QueuePageSnapshot renderCountPage(boolean uploads) {
    long queued =
        core.getRequestStarters().chkFetchSchedulerBulk.countPersistentWaitingKeys()
            + core.getRequestStarters().chkFetchSchedulerRT.countPersistentWaitingKeys();
    LOG.debug("Total waiting CHKs: {}", queued);
    long reallyQueued =
        core.getRequestStarters().chkFetchSchedulerBulk.countQueuedRequests()
            + core.getRequestStarters().chkFetchSchedulerRT.countQueuedRequests();
    LOG.debug("Total queued CHK requests (including transient): {}", reallyQueued);

    HTMLNode contentNode = new HTMLNode("#");
    addAlertSummaryPlaceholder(contentNode);
    HTMLNode infoboxContent =
        addInfobox(INFOBOX_INFORMATION, "Queued requests status", contentNode, null, false);
    infoboxContent.addChild("p", "Total awaiting CHKs: " + queued);
    infoboxContent.addChild("p", "Total queued CHK requests: " + reallyQueued);
    return new QueuePageSnapshot(l10n("title"), contentNode.generate());
  }

  /**
   * {@inheritDoc}
   *
   * <p>This implementation iterates over the current global requests and emits one URI per line in
   * the historical {@code listKeys.txt} format. Upload entries without a resolved URI are skipped,
   * matching the legacy behavior.
   */
  @Override
  public String renderKeyList(boolean uploads) throws RequestQueueUnavailableException {
    QueuePageRequestView[] reqs = globalRequests();
    StringBuilder sb = new StringBuilder();
    for (QueuePageRequestView req : reqs) {
      if (!uploads && req instanceof QueuePageDownloadView get) {
        FreenetURI uri = get.getUri();
        sb.append(uri).append('\n');
      } else if (uploads && req instanceof QueuePageUploadView put) {
        FreenetURI uri = put.getFinalUri();
        if (uri != null) {
          sb.append(uri).append('\n');
        }
      }
    }
    return sb.toString();
  }

  @Override
  public QueueInsertStatus readInsertStatus(String identifier)
      throws RequestQueueUnavailableException {
    for (QueuePageRequestView request : globalRequests()) {
      if (request instanceof QueuePageUploadView upload
          && identifier.equals(upload.getIdentifier())) {
        if (upload.hasSucceeded()) {
          FreenetURI uri = upload.getFinalUri();
          if (uri != null && uri.isCHK()) {
            return new QueueInsertStatus("inserted", uri.toString());
          }
          return new QueueInsertStatus("failed", null);
        }
        return new QueueInsertStatus(upload.hasFinished() ? "failed" : "pending", null);
      }
    }
    return new QueueInsertStatus("missing", null);
  }

  /**
   * Returns the live global request array through the runtime-owned queue-page seam.
   *
   * <p>The backend owns protocol-specific lookup rules such as lazy endpoint resolution, absent
   * backends yielding an empty queue, and translation of persistence failures into the runtime SPI
   * exception used by the HTTP layer.
   *
   * @return current global requests, or an empty array if the queue backend is unavailable
   * @throws RequestQueueUnavailableException if the persistent request queue cannot be read
   */
  private QueuePageRequestView[] globalRequests() throws RequestQueueUnavailableException {
    return queueBackend.getGlobalRequests();
  }

  private void addAlertSummaryPlaceholder(HTMLNode contentNode) {
    contentNode.addChild("%", ALERT_SUMMARY_PLACEHOLDER);
  }

  private String buildEmptyQueueContent(boolean uploads) {
    HTMLNode contentNode = new HTMLNode("#");
    addAlertSummaryPlaceholder(contentNode);
    HTMLNode infoboxContent =
        addInfobox(
            INFOBOX_INFORMATION, l10n("globalQueueIsEmpty"), contentNode, "queue-empty", true);
    infoboxContent.addChild("#", l10n("noTaskOnGlobalQueue"));
    if (!uploads) {
      contentNode.addChild(createBulkDownloadForm());
    }
    return contentNode.generate();
  }

  private String emptyPageTitle(boolean uploads) {
    return l10n(uploads ? "titleUploads" : "titleDownloads");
  }

  private String[] buildPriorityClasses() {
    return new String[] {
      l10n("priority0"),
      l10n("priority1"),
      l10n("priority2"),
      l10n("priority3"),
      l10n("priority4"),
      l10n("priority5"),
      l10n("priority6")
    };
  }

  private QueuePartitions partitionRequests(QueuePageRequestView[] reqs, boolean uploads) {
    QueuePartitions partitions = new QueuePartitions();
    if (LOG.isDebugEnabled()) {
      LOG.debug("Request count: {}", reqs.length);
    }
    for (QueuePageRequestView req : reqs) {
      if (req instanceof QueuePageDownloadView download && !uploads) {
        handleDownloadPartition(download, partitions);
      } else if (req instanceof QueuePageUploadFileView upload && uploads) {
        handleUploadFilePartition(upload, partitions);
      } else if (req instanceof QueuePageUploadDirView upload && uploads) {
        handleUploadDirPartition(upload, partitions);
      }
    }
    return partitions;
  }

  private void handleUploadDirPartition(QueuePageUploadDirView upload, QueuePartitions partitions) {
    if (upload.hasSucceeded()) {
      partitions.completedDirUpload.add(upload);
    } else if (upload.hasFinished()) {
      partitions.failedDirUpload.add(upload);
    } else {
      short prio = upload.getPriority();
      if (prio < partitions.lowestQueuedPrio) {
        partitions.lowestQueuedPrio = prio;
      }
      partitions.uncompletedDirUpload.add(upload);
    }
    long size = upload.getTotalDataSize();
    if (size > 0) {
      partitions.totalQueuedUploadSize += size;
    }
    partitions.added = true;
  }

  private void handleUploadFilePartition(
      QueuePageUploadFileView upload, QueuePartitions partitions) {
    if (upload.hasSucceeded()) {
      partitions.completedUpload.add(upload);
    } else if (upload.hasFinished()) {
      partitions.failedUpload.add(upload);
    } else {
      short prio = upload.getPriority();
      if (prio < partitions.lowestQueuedPrio) {
        partitions.lowestQueuedPrio = prio;
      }
      partitions.uncompletedUpload.add(upload);
    }
    long size = upload.getDataSize();
    if (size > 0) {
      partitions.totalQueuedUploadSize += size;
    }
    partitions.added = true;
  }

  private void handleDownloadPartition(QueuePageDownloadView download, QueuePartitions partitions) {
    if (download.hasSucceeded()) {
      if (download.toTempSpace()) {
        partitions.completedDownloadToTemp.add(download);
      } else {
        partitions.completedDownloadToDisk.add(download);
      }
    } else if (download.hasFinished()) {
      handleFinishedDownload(download, partitions);
    } else {
      short prio = download.getPriority();
      if (prio < partitions.lowestQueuedPrio) {
        partitions.lowestQueuedPrio = prio;
      }
      partitions.uncompletedDownload.add(download);
      long size = download.getDataSize();
      if (size > 0) {
        partitions.totalQueuedDownloadSize += size;
      }
    }
    partitions.added = true;
  }

  private void handleFinishedDownload(QueuePageDownloadView download, QueuePartitions partitions) {
    FetchExceptionMode failureCode = download.getFailureCode();
    String mimeType = normalizeMimeType(download, failureCode);
    switch (failureCode) {
      case CONTENT_VALIDATION_UNKNOWN_MIME -> addUnknownMimeFailure(download, partitions, mimeType);
      case CONTENT_VALIDATION_BAD_MIME -> handleBadMimeFailure(download, partitions, mimeType);
      default -> partitions.failedDownload.add(download);
    }
  }

  private String normalizeMimeType(QueuePageDownloadView download, FetchExceptionMode failureCode) {
    String mimeType = download.getMimeType();
    if (mimeType == null
        && (failureCode == FetchExceptionMode.CONTENT_VALIDATION_UNKNOWN_MIME
            || failureCode == FetchExceptionMode.CONTENT_VALIDATION_BAD_MIME)) {
      if (LOG.isErrorEnabled()) {
        LOG.error(
            "MIME type is null but failure code is {} for {} : {}",
            FetchException.getMessage(failureCode),
            download.getIdentifier(),
            download.getUri());
      }
      return DefaultMIMETypes.DEFAULT_MIME_TYPE;
    }
    return mimeType;
  }

  private void addUnknownMimeFailure(
      QueuePageDownloadView download, QueuePartitions partitions, String mimeType) {
    String normalizedMimeType = ContentFilter.stripMIMEType(mimeType);
    partitions
        .failedUnknownMIMEType
        .computeIfAbsent(normalizedMimeType, _ -> new ArrayList<>())
        .add(download);
  }

  private void handleBadMimeFailure(
      QueuePageDownloadView download, QueuePartitions partitions, String mimeType) {
    String normalizedMimeType = ContentFilter.stripMIMEType(mimeType);
    FilterMIMEType type = ContentFilter.getMIMEType(normalizedMimeType);
    Map<String, List<QueuePageDownloadView>> bucket =
        type == null ? partitions.failedUnknownMIMEType : partitions.failedBadMIMEType;
    if (type == null) {
      LOG.error(
          "Bad MIME failure code yet MIME is {} which does not have a handler!",
          normalizedMimeType);
    }
    bucket.computeIfAbsent(normalizedMimeType, _ -> new ArrayList<>()).add(download);
  }

  private Comparator<QueuePageRequestView> createJobComparator(String sortBy, boolean reversed) {
    Comparator<QueuePageRequestView> baseComparator =
        switch (sortBy) {
          case "id" -> this::compareById;
          case "size" -> this::compareBySize;
          case PROGRESS_LABEL -> this::compareByProgress;
          case LAST_ACTIVITY_LABEL -> this::compareByLastActivity;
          case LAST_FAILURE_LABEL -> this::compareByLastFailure;
          case null, default -> this::compareByPriorityThenId;
        };
    return (first, second) -> {
      if (first == second) {
        return 0;
      }
      int result = baseComparator.compare(first, second);
      if (result == 0) {
        return 0;
      }
      return reversed ? -Integer.signum(result) : Integer.signum(result);
    };
  }

  private int compareById(QueuePageRequestView first, QueuePageRequestView second) {
    int result = first.getIdentifier().compareToIgnoreCase(second.getIdentifier());
    if (result == 0) {
      result = first.getIdentifier().compareTo(second.getIdentifier());
    }
    return result;
  }

  private int compareBySize(QueuePageRequestView first, QueuePageRequestView second) {
    return Fields.compare(first.getTotalBlocks(), second.getTotalBlocks());
  }

  private int compareByProgress(QueuePageRequestView first, QueuePageRequestView second) {
    boolean firstFinalized = first.isTotalFinalized();
    boolean secondFinalized = second.isTotalFinalized();
    if (firstFinalized && !secondFinalized) {
      return 1;
    }
    if (secondFinalized && !firstFinalized) {
      return -1;
    }
    double firstProgress = (double) first.getFetchedBlocks() / (double) first.getMinBlocks();
    double secondProgress = (double) second.getFetchedBlocks() / (double) second.getMinBlocks();
    return Fields.compare(firstProgress, secondProgress);
  }

  private int compareByLastActivity(QueuePageRequestView first, QueuePageRequestView second) {
    return Fields.compare(first.getLastSuccess(), second.getLastSuccess());
  }

  private int compareByLastFailure(QueuePageRequestView first, QueuePageRequestView second) {
    return Fields.compare(first.getLastFailure(), second.getLastFailure());
  }

  private int compareByPriorityThenId(QueuePageRequestView first, QueuePageRequestView second) {
    int result = Fields.compare(first.getPriority(), second.getPriority());
    if (result == 0) {
      result = first.getIdentifier().compareTo(second.getIdentifier());
    }
    return result;
  }

  private void sortPartitions(
      QueuePartitions partitions, Comparator<QueuePageRequestView> jobComparator) {
    partitions.completedDownloadToDisk.sort(jobComparator);
    partitions.completedDownloadToTemp.sort(jobComparator);
    partitions.completedUpload.sort(jobComparator);
    partitions.completedDirUpload.sort(jobComparator);
    partitions.failedDownload.sort(jobComparator);
    partitions.failedUpload.sort(jobComparator);
    partitions.failedDirUpload.sort(jobComparator);
    partitions.uncompletedDownload.sort(jobComparator);
    partitions.uncompletedUpload.sort(jobComparator);
    partitions.uncompletedDirUpload.sort(jobComparator);
  }

  private void logTotals(QueuePartitions partitions) {
    if (LOG.isDebugEnabled()) {
      LOG.debug(
          "Total queued downloads: {}", SizeUtil.formatSize(partitions.totalQueuedDownloadSize));
      LOG.debug("Total queued uploads: {}", SizeUtil.formatSize(partitions.totalQueuedUploadSize));
    }
  }

  private String buildPageName(QueuePartitions partitions, boolean uploads) {
    if (uploads) {
      return "("
          + (partitions.uncompletedDirUpload.size() + partitions.uncompletedUpload.size())
          + '/'
          + (partitions.failedDirUpload.size() + partitions.failedUpload.size())
          + '/'
          + (partitions.completedDirUpload.size() + partitions.completedUpload.size())
          + ") "
          + l10n("titleUploads");
    }
    return "("
        + partitions.uncompletedDownload.size()
        + '/'
        + partitions.failedDownload.size()
        + '/'
        + (partitions.completedDownloadToDisk.size() + partitions.completedDownloadToTemp.size())
        + ") "
        + l10n("titleDownloads");
  }

  private void addLegend(
      HTMLNode contentNode,
      QueuePartitions partitions,
      String[] priorityClasses,
      boolean advancedModeEnabled) {
    HTMLNode legendContent =
        addInfobox("legend", l10n("legend"), contentNode, "queue-legend", true);
    HTMLNode legendTable = legendContent.addChild(TAG_TABLE, ATTR_CLASS, "queue");
    HTMLNode legendRow = legendTable.addChild("tr");
    for (int i = 0; i < 7; i++) {
      if (i > RequestStarter.INTERACTIVE_PRIORITY_CLASS
          || advancedModeEnabled
          || i <= partitions.lowestQueuedPrio) {
        legendRow.addChild("td", ATTR_CLASS, PRIORITY + i, priorityClasses[i]);
      }
    }
  }

  private void addPanicBoxIfNeeded(HTMLNode contentNode) {
    contentNode.addChild("%", PANIC_BOX_PLACEHOLDER);
  }

  private void addCompletedSections(
      RequestTableContext tableContext,
      HTMLNode contentNode,
      QueuePartitions partitions,
      boolean uploads) {
    if (!partitions.completedDownloadToTemp.isEmpty()) {
      contentNode.addChild("a", "id", "completedDownloadToTemp");
      HTMLNode content =
          addInfobox(
              COMPLETED_REQUESTS,
              l10n(
                  "completedDinTempDirectory",
                  new String[] {"size"},
                  new String[] {String.valueOf(partitions.completedDownloadToTemp.size())}),
              contentNode,
              "request-completed",
              false);
      QueueColumn[] columns =
          tableContext.advancedModeEnabled
              ? new QueueColumn[] {
                QueueColumn.IDENTIFIER,
                QueueColumn.SIZE,
                QueueColumn.MIME_TYPE,
                QueueColumn.PERSISTENCE,
                QueueColumn.KEY,
                QueueColumn.COMPAT_MODE
              }
              : new QueueColumn[] {QueueColumn.SIZE, QueueColumn.KEY};
      content.addChild(
          createRequestTable(
              tableContext,
              partitions.completedDownloadToTemp,
              columns,
              "completed-temp",
              QueueType.COMPLETED_DOWNLOAD_TO_TEMP,
              uploads));
    }

    if (!partitions.completedDownloadToDisk.isEmpty()) {
      contentNode.addChild("a", "id", "completedDownloadToDisk");
      HTMLNode content =
          addInfobox(
              COMPLETED_REQUESTS,
              l10n(
                  "completedDinDownloadDirectory",
                  new String[] {"size"},
                  new String[] {String.valueOf(partitions.completedDownloadToDisk.size())}),
              contentNode,
              "request-completed",
              false);
      QueueColumn[] columns =
          tableContext.advancedModeEnabled
              ? new QueueColumn[] {
                QueueColumn.IDENTIFIER,
                QueueColumn.FILENAME,
                QueueColumn.SIZE,
                QueueColumn.MIME_TYPE,
                QueueColumn.PERSISTENCE,
                QueueColumn.KEY,
                QueueColumn.COMPAT_MODE
              }
              : new QueueColumn[] {QueueColumn.FILENAME, QueueColumn.SIZE, QueueColumn.KEY};
      content.addChild(
          createRequestTable(
              tableContext,
              partitions.completedDownloadToDisk,
              columns,
              "completed-disk",
              QueueType.COMPLETED_DOWNLOAD_TO_DISK,
              uploads));
    }

    if (!partitions.completedUpload.isEmpty()) {
      contentNode.addChild("a", "id", "completedUpload");
      HTMLNode content =
          addInfobox(
              COMPLETED_REQUESTS,
              l10n(
                  "completedU",
                  new String[] {"size"},
                  new String[] {String.valueOf(partitions.completedUpload.size())}),
              contentNode,
              "download-completed",
              false);
      QueueColumn[] columns =
          tableContext.advancedModeEnabled
              ? new QueueColumn[] {
                QueueColumn.IDENTIFIER,
                QueueColumn.FILENAME,
                QueueColumn.SIZE,
                QueueColumn.MIME_TYPE,
                QueueColumn.PERSISTENCE,
                QueueColumn.KEY
              }
              : new QueueColumn[] {QueueColumn.FILENAME, QueueColumn.SIZE, QueueColumn.KEY};
      content.addChild(
          createRequestTable(
              tableContext,
              partitions.completedUpload,
              columns,
              "completed-upload-file",
              QueueType.COMPLETED_UPLOAD,
              uploads));
    }

    if (!partitions.completedDirUpload.isEmpty()) {
      contentNode.addChild("a", "id", "completedDirUpload");
      HTMLNode content =
          addInfobox(
              COMPLETED_REQUESTS,
              l10n(
                  "completedUDirectory",
                  new String[] {"size"},
                  new String[] {String.valueOf(partitions.completedDirUpload.size())}),
              contentNode,
              "download-completed",
              false);
      QueueColumn[] columns =
          tableContext.advancedModeEnabled
              ? new QueueColumn[] {
                QueueColumn.IDENTIFIER,
                QueueColumn.FILES,
                QueueColumn.TOTAL_SIZE,
                QueueColumn.PERSISTENCE,
                QueueColumn.KEY
              }
              : new QueueColumn[] {QueueColumn.FILES, QueueColumn.TOTAL_SIZE, QueueColumn.KEY};
      content.addChild(
          createRequestTable(
              tableContext,
              partitions.completedDirUpload,
              columns,
              "completed-upload-dir",
              QueueType.COMPLETED_DIR_UPLOAD,
              uploads));
    }
  }

  private void addFailureSections(
      RequestTableContext tableContext, HTMLNode contentNode, QueuePartitions partitions) {
    QueueColumn[] advancedFailureColumns =
        new QueueColumn[] {
          QueueColumn.IDENTIFIER,
          QueueColumn.FILENAME,
          QueueColumn.SIZE,
          QueueColumn.MIME_TYPE,
          QueueColumn.PROGRESS,
          QueueColumn.REASON,
          QueueColumn.PERSISTENCE,
          QueueColumn.KEY
        };
    QueueColumn[] simpleFailureColumns =
        new QueueColumn[] {
          QueueColumn.FILENAME,
          QueueColumn.SIZE,
          QueueColumn.PROGRESS,
          QueueColumn.REASON,
          QueueColumn.KEY
        };

    if (!partitions.failedDownload.isEmpty()) {
      contentNode.addChild("a", "id", "failedDownload");
      HTMLNode failedContent =
          addInfobox(
              FAILED_REQUESTS,
              l10n(
                  "failedD",
                  new String[] {"size"},
                  new String[] {String.valueOf(partitions.failedDownload.size())}),
              contentNode,
              "download-failed",
              false);
      failedContent.addChild(
          createRequestTable(
              tableContext,
              partitions.failedDownload,
              tableContext.advancedModeEnabled ? advancedFailureColumns : simpleFailureColumns,
              "failed-download",
              QueueType.FAILED_DOWNLOAD,
              false));
    }

    if (!partitions.failedUpload.isEmpty()) {
      contentNode.addChild("a", "id", "failedUpload");
      HTMLNode failedContent =
          addInfobox(
              FAILED_REQUESTS,
              l10n(
                  STATUS_FAILED_UPLOAD,
                  new String[] {"size"},
                  new String[] {String.valueOf(partitions.failedUpload.size())}),
              contentNode,
              "upload-failed",
              false);
      failedContent.addChild(
          createRequestTable(
              tableContext,
              partitions.failedUpload,
              tableContext.advancedModeEnabled ? advancedFailureColumns : simpleFailureColumns,
              "failed-upload-file",
              QueueType.FAILED_UPLOAD,
              true));
    }

    if (!partitions.failedDirUpload.isEmpty()) {
      contentNode.addChild("a", "id", "failedDirUpload");
      HTMLNode failedContent =
          addInfobox(
              FAILED_REQUESTS,
              l10n(
                  STATUS_FAILED_UPLOAD,
                  new String[] {"size"},
                  new String[] {String.valueOf(partitions.failedDirUpload.size())}),
              contentNode,
              "upload-failed",
              false);
      QueueColumn[] columns =
          tableContext.advancedModeEnabled
              ? new QueueColumn[] {
                QueueColumn.IDENTIFIER,
                QueueColumn.FILES,
                QueueColumn.TOTAL_SIZE,
                QueueColumn.PROGRESS,
                QueueColumn.REASON,
                QueueColumn.PERSISTENCE,
                QueueColumn.KEY
              }
              : new QueueColumn[] {
                QueueColumn.FILES,
                QueueColumn.TOTAL_SIZE,
                QueueColumn.PROGRESS,
                QueueColumn.REASON,
                QueueColumn.KEY
              };
      failedContent.addChild(
          createRequestTable(
              tableContext,
              partitions.failedDirUpload,
              columns,
              "failed-upload-dir",
              QueueType.FAILED_DIR_UPLOAD,
              true));
    }
  }

  private void addMimeFailureSections(
      RequestTableContext tableContext,
      HTMLNode contentNode,
      QueuePartitions partitions,
      Comparator<QueuePageRequestView> jobComparator) {
    addBadMimeFailures(tableContext, contentNode, partitions, jobComparator);
    addUnknownMimeFailures(tableContext, contentNode, partitions, jobComparator);
  }

  private void addBadMimeFailures(
      RequestTableContext tableContext,
      HTMLNode contentNode,
      QueuePartitions partitions,
      Comparator<QueuePageRequestView> jobComparator) {
    String[] types = partitions.failedBadMIMEType.keySet().toArray(new String[0]);
    Arrays.sort(types);
    for (String type : types) {
      List<QueuePageDownloadView> getters = partitions.failedBadMIMEType.get(type);
      String atype = type.replace("-", "--").replace('/', '-');
      contentNode.addChild("a", "id", "failedDownload-badtype-" + atype);
      FilterMIMEType typeHandler = ContentFilter.getMIMEType(type);
      HTMLNode failedContent =
          addInfobox(
              FAILED_REQUESTS,
              l10n(
                  "failedDBadMIME",
                  new String[] {"size", "type"},
                  new String[] {String.valueOf(getters.size()), type}),
              contentNode,
              "download-failed-" + atype,
              false);
      KnownUnsafeContentTypeException e = new KnownUnsafeContentTypeException(typeHandler);
      failedContent.addChild("p", l10n("badMIMETypeIntro", "type", type));
      List<String> detail = e.details();
      if (detail != null && !detail.isEmpty()) {
        HTMLNode list = failedContent.addChild("ul");
        for (String s : detail) {
          list.addChild("li", s);
        }
      }
      failedContent.addChild("p", l10n("mimeProblemFetchAnyway"));
      getters.sort(jobComparator);
      QueueColumn[] columns =
          tableContext.advancedModeEnabled
              ? new QueueColumn[] {
                QueueColumn.IDENTIFIER,
                QueueColumn.FILENAME,
                QueueColumn.SIZE,
                QueueColumn.PERSISTENCE,
                QueueColumn.KEY
              }
              : new QueueColumn[] {QueueColumn.FILENAME, QueueColumn.SIZE, QueueColumn.KEY};
      failedContent.addChild(
          createRequestTable(
              tableContext,
              getters,
              columns,
              "failed-download-file-badmime",
              type,
              QueueType.FAILED_BAD_MIME_TYPE,
              false));
    }
  }

  private void addUnknownMimeFailures(
      RequestTableContext tableContext,
      HTMLNode contentNode,
      QueuePartitions partitions,
      Comparator<QueuePageRequestView> jobComparator) {
    String[] types = partitions.failedUnknownMIMEType.keySet().toArray(new String[0]);
    Arrays.sort(types);
    for (String type : types) {
      List<QueuePageDownloadView> getters = partitions.failedUnknownMIMEType.get(type);
      String atype = type.replace("-", "--").replace('/', '-');
      contentNode.addChild("a", "id", "failedDownload-unknowntype-" + atype);
      HTMLNode failedContent =
          addInfobox(
              FAILED_REQUESTS,
              l10n(
                  "failedDUnknownMIME",
                  new String[] {"size", "type"},
                  new String[] {String.valueOf(getters.size()), type}),
              contentNode,
              "download-failed-" + atype,
              false);
      failedContent.addChild(
          "p",
          NodeL10n.getBase().getString("UnknownContentTypeException.explanation", "type", type));
      failedContent.addChild("p", l10n("mimeProblemFetchAnyway"));
      getters.sort(jobComparator);
      QueueColumn[] columns =
          tableContext.advancedModeEnabled
              ? new QueueColumn[] {
                QueueColumn.IDENTIFIER,
                QueueColumn.FILENAME,
                QueueColumn.SIZE,
                QueueColumn.PERSISTENCE,
                QueueColumn.KEY
              }
              : new QueueColumn[] {QueueColumn.FILENAME, QueueColumn.SIZE, QueueColumn.KEY};
      failedContent.addChild(
          createRequestTable(
              tableContext,
              getters,
              columns,
              "failed-download-file-unknownmime",
              type,
              QueueType.FAILED_UNKNOWN_MIME_TYPE,
              false));
    }
  }

  private void addUncompletedSections(
      RequestTableContext tableContext, HTMLNode contentNode, QueuePartitions partitions) {
    if (!partitions.uncompletedDownload.isEmpty()) {
      contentNode.addChild("a", "id", "uncompletedDownload");
      HTMLNode content =
          addInfobox(
              REQUESTS_IN_PROGRESS,
              l10n(
                  "wipD",
                  new String[] {"size"},
                  new String[] {String.valueOf(partitions.uncompletedDownload.size())}),
              contentNode,
              "download-progressing",
              false);
      QueueColumn[] columns =
          tableContext.advancedModeEnabled
              ? new QueueColumn[] {
                QueueColumn.IDENTIFIER,
                QueueColumn.PRIORITY,
                QueueColumn.SIZE,
                QueueColumn.MIME_TYPE,
                QueueColumn.PROGRESS,
                QueueColumn.LAST_ACTIVITY,
                QueueColumn.PERSISTENCE,
                QueueColumn.FILENAME,
                QueueColumn.KEY,
                QueueColumn.COMPAT_MODE
              }
              : new QueueColumn[] {
                QueueColumn.PRIORITY,
                QueueColumn.SIZE,
                QueueColumn.PROGRESS,
                QueueColumn.LAST_ACTIVITY,
                QueueColumn.KEY
              };
      content.addChild(
          createRequestTable(
              tableContext,
              partitions.uncompletedDownload,
              columns,
              "uncompleted-download",
              QueueType.UNCOMPLETED_DOWNLOAD,
              false));
    }

    if (!partitions.uncompletedUpload.isEmpty()) {
      contentNode.addChild("a", "id", "uncompletedUpload");
      HTMLNode content =
          addInfobox(
              REQUESTS_IN_PROGRESS,
              l10n(
                  "wipU",
                  new String[] {"size"},
                  new String[] {String.valueOf(partitions.uncompletedUpload.size())}),
              contentNode,
              "upload-progressing",
              false);
      QueueColumn[] columns =
          tableContext.advancedModeEnabled
              ? new QueueColumn[] {
                QueueColumn.IDENTIFIER,
                QueueColumn.PRIORITY,
                QueueColumn.SIZE,
                QueueColumn.MIME_TYPE,
                QueueColumn.PROGRESS,
                QueueColumn.LAST_ACTIVITY,
                QueueColumn.PERSISTENCE,
                QueueColumn.FILENAME,
                QueueColumn.KEY
              }
              : new QueueColumn[] {
                QueueColumn.PRIORITY,
                QueueColumn.FILENAME,
                QueueColumn.SIZE,
                QueueColumn.PROGRESS,
                QueueColumn.LAST_ACTIVITY,
                QueueColumn.KEY
              };
      content.addChild(
          createRequestTable(
              tableContext,
              partitions.uncompletedUpload,
              columns,
              "uncompleted-upload-file",
              QueueType.UNCOMPLETED_UPLOAD,
              true));
    }

    if (!partitions.uncompletedDirUpload.isEmpty()) {
      contentNode.addChild("a", "id", "uncompletedDirUpload");
      HTMLNode content =
          addInfobox(
              REQUESTS_IN_PROGRESS,
              l10n(
                  "wipDU",
                  new String[] {"size"},
                  new String[] {String.valueOf(partitions.uncompletedDirUpload.size())}),
              contentNode,
              "download-progressing upload-progressing",
              false);
      QueueColumn[] columns =
          tableContext.advancedModeEnabled
              ? new QueueColumn[] {
                QueueColumn.IDENTIFIER,
                QueueColumn.FILES,
                QueueColumn.PRIORITY,
                QueueColumn.TOTAL_SIZE,
                QueueColumn.PROGRESS,
                QueueColumn.LAST_ACTIVITY,
                QueueColumn.PERSISTENCE,
                QueueColumn.KEY
              }
              : new QueueColumn[] {
                QueueColumn.PRIORITY,
                QueueColumn.FILES,
                QueueColumn.TOTAL_SIZE,
                QueueColumn.PROGRESS,
                QueueColumn.LAST_ACTIVITY,
                QueueColumn.KEY
              };
      content.addChild(
          createRequestTable(
              tableContext,
              partitions.uncompletedDirUpload,
              columns,
              "uncompleted-upload-dir",
              QueueType.UNCOMPLETED_DIR_UPLOAD,
              true));
    }
  }

  private void addNavigationBar(HTMLNode contentNode, QueuePartitions partitions, boolean uploads) {
    InfoboxParts infobox = createInfobox("navbar", l10n("requestNavigation"), null, false);
    HTMLNode navigationBar = infobox.outerNode;
    HTMLNode navigationContent = infobox.contentNode.addChild("ul");
    boolean includeNavigationBar = false;
    includeNavigationBar |=
        addNavigationItem(
            navigationContent,
            !partitions.completedDownloadToTemp.isEmpty(),
            "#completedDownloadToTemp",
            l10n(
                "completedDtoTemp",
                new String[] {"size"},
                new String[] {String.valueOf(partitions.completedDownloadToTemp.size())}));
    includeNavigationBar |=
        addNavigationItem(
            navigationContent,
            !partitions.completedDownloadToDisk.isEmpty(),
            "#completedDownloadToDisk",
            l10n(
                "completedDtoDisk",
                new String[] {"size"},
                new String[] {String.valueOf(partitions.completedDownloadToDisk.size())}));
    includeNavigationBar |=
        addNavigationItem(
            navigationContent,
            !partitions.completedUpload.isEmpty(),
            "#completedUpload",
            l10n(
                "completedU",
                new String[] {"size"},
                new String[] {String.valueOf(partitions.completedUpload.size())}));
    includeNavigationBar |=
        addNavigationItem(
            navigationContent,
            !partitions.completedDirUpload.isEmpty(),
            "#completedDirUpload",
            l10n(
                "completedDU",
                new String[] {"size"},
                new String[] {String.valueOf(partitions.completedDirUpload.size())}));
    includeNavigationBar |=
        addNavigationItem(
            navigationContent,
            !partitions.failedDownload.isEmpty(),
            "#failedDownload",
            l10n(
                "failedD",
                new String[] {"size"},
                new String[] {String.valueOf(partitions.failedDownload.size())}));
    includeNavigationBar |=
        addNavigationItem(
            navigationContent,
            !partitions.failedUpload.isEmpty(),
            "#failedUpload",
            l10n(
                STATUS_FAILED_UPLOAD,
                new String[] {"size"},
                new String[] {String.valueOf(partitions.failedUpload.size())}));
    includeNavigationBar |=
        addNavigationItem(
            navigationContent,
            !partitions.failedDirUpload.isEmpty(),
            "#failedDirUpload",
            l10n(
                "failedDU",
                new String[] {"size"},
                new String[] {String.valueOf(partitions.failedDirUpload.size())}));

    addNavigationMimeSections(navigationContent, partitions);

    includeNavigationBar |=
        addNavigationItem(
            navigationContent,
            !partitions.uncompletedDownload.isEmpty(),
            "#uncompletedDownload",
            l10n(
                "DinProgress",
                new String[] {"size"},
                new String[] {String.valueOf(partitions.uncompletedDownload.size())}));
    includeNavigationBar |=
        addNavigationItem(
            navigationContent,
            !partitions.uncompletedUpload.isEmpty(),
            "#uncompletedUpload",
            l10n(
                "UinProgress",
                new String[] {"size"},
                new String[] {String.valueOf(partitions.uncompletedUpload.size())}));
    includeNavigationBar |=
        addNavigationItem(
            navigationContent,
            !partitions.uncompletedDirUpload.isEmpty(),
            "#uncompletedDirUpload",
            l10n(
                "DUinProgress",
                new String[] {"size"},
                new String[] {String.valueOf(partitions.uncompletedDirUpload.size())}));
    includeNavigationBar |=
        addNavigationItem(
            navigationContent,
            partitions.totalQueuedDownloadSize > 0,
            null,
            l10n(
                "totalQueuedDownloads",
                "size",
                SizeUtil.formatSize(partitions.totalQueuedDownloadSize)));
    includeNavigationBar |=
        addNavigationItem(
            navigationContent,
            partitions.totalQueuedUploadSize > 0,
            null,
            l10n(
                "totalQueuedUploads",
                "size",
                SizeUtil.formatSize(partitions.totalQueuedUploadSize)));

    navigationContent.addChild("li").addChild("a", "href", KEY_LIST_LOCATION, l10n("openKeyList"));

    if (includeNavigationBar || uploads) {
      contentNode.addChild(navigationBar);
    }
  }

  private void addNavigationMimeSections(HTMLNode navigationContent, QueuePartitions partitions) {
    if (!partitions.failedUnknownMIMEType.isEmpty()) {
      String[] types = partitions.failedUnknownMIMEType.keySet().toArray(new String[0]);
      Arrays.sort(types);
      for (String type : types) {
        String atype = type.replace("-", "--").replace('/', '-');
        addNavigationItem(
            navigationContent,
            true,
            "#failedDownload-unknowntype-" + atype,
            l10n(
                "failedDUnknownMIME",
                new String[] {"size", "type"},
                new String[] {
                  String.valueOf(partitions.failedUnknownMIMEType.get(type).size()), type
                }));
      }
    }
    if (!partitions.failedBadMIMEType.isEmpty()) {
      String[] types = partitions.failedBadMIMEType.keySet().toArray(new String[0]);
      Arrays.sort(types);
      for (String type : types) {
        String atype = type.replace("-", "--").replace('/', '-');
        addNavigationItem(
            navigationContent,
            true,
            "#failedDownload-badtype-" + atype,
            l10n(
                "failedDBadMIME",
                new String[] {"size", "type"},
                new String[] {
                  String.valueOf(partitions.failedBadMIMEType.get(type).size()), type
                }));
      }
    }
  }

  private boolean addNavigationItem(
      HTMLNode navigationContent, boolean condition, String href, String text) {
    if (!condition) {
      return false;
    }
    HTMLNode li = navigationContent.addChild("li");
    if (href != null) {
      li.addChild("a", "href", href, text);
    } else {
      li.addChild("#", text);
    }
    return true;
  }

  private HTMLNode createBulkDownloadForm() {
    InfoboxParts infobox = createInfobox(null, l10n(DOWNLOAD_FILES), GROUPED_DOWNLOADS, true);
    HTMLNode downloadBox = infobox.outerNode;
    HTMLNode downloadForm = addFormChild(infobox.contentNode, PATH_DOWNLOADS, "queueDownloadForm");
    downloadForm.addChild("#", l10n("downloadFilesInstructions"));
    downloadForm.addChild("br");
    downloadForm.addChild(
        "textarea",
        new String[] {"id", "name", "cols", "rows"},
        new String[] {BULK_DOWNLOADS, BULK_DOWNLOADS, "120", "8"});
    downloadForm.addChild("br");
    PHYSICAL_THREAT_LEVEL threatLevel =
        core.getNode().services().securityLevels().getPhysicalThreatLevel();
    if (threatLevel == PHYSICAL_THREAT_LEVEL.HIGH
        || threatLevel == PHYSICAL_THREAT_LEVEL.MAXIMUM
        || core.isDownloadDisabled()) {
      downloadForm.addChild(
          TAG_INPUT,
          new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
          new String[] {INPUT_TYPE_HIDDEN, TARGET, RETURN_TYPE_DIRECT});
    } else if (threatLevel == PHYSICAL_THREAT_LEVEL.LOW) {
      downloadForm.addChild(
          TAG_INPUT,
          new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
          new String[] {INPUT_TYPE_HIDDEN, TARGET, "disk"});
      selectLocation(downloadForm);
    } else {
      downloadForm.addChild("br");
      downloadForm
          .addChild(
              TAG_INPUT,
              new String[] {ATTR_TYPE, ATTR_VALUE, ATTR_NAME, "id"},
              new String[] {"radio", "disk", TARGET, BULK_DOWNLOAD_SELECT_OPTION_DISK})
          .addChild(
              TAG_LABEL,
              new String[] {"for"},
              new String[] {BULK_DOWNLOAD_SELECT_OPTION_DISK},
              ' ' + l10n(BULK_DOWNLOAD_SELECT_OPTION_DISK) + ' ');
      selectLocation(downloadForm);
      downloadForm.addChild("br");
      downloadForm
          .addChild(
              TAG_INPUT,
              new String[] {ATTR_TYPE, ATTR_VALUE, ATTR_NAME, ATTR_CHECKED, "id"},
              new String[] {
                "radio",
                RETURN_TYPE_DIRECT,
                TARGET,
                ATTR_CHECKED,
                BULK_DOWNLOAD_SELECT_OPTION_DIRECT
              })
          .addChild(
              TAG_LABEL,
              new String[] {"for"},
              new String[] {BULK_DOWNLOAD_SELECT_OPTION_DIRECT},
              ' ' + l10n(BULK_DOWNLOAD_SELECT_OPTION_DIRECT) + ' ');
    }
    HTMLNode filterControl = downloadForm.addChild("div", l10n(FILTER_DATA));
    filterControl.addChild(
        TAG_INPUT,
        new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE, ATTR_CHECKED, "id"},
        new String[] {
          INPUT_TYPE_CHECKBOX, FILTER_DATA, FILTER_DATA, ATTR_CHECKED, FILTER_DATA_MESSAGE
        });
    filterControl.addChild(
        TAG_LABEL,
        new String[] {"for"},
        new String[] {FILTER_DATA_MESSAGE},
        l10n(FILTER_DATA_MESSAGE));
    downloadForm.addChild("br");
    downloadForm.addChild(
        TAG_INPUT,
        new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
        new String[] {INPUT_TYPE_SUBMIT, "insert", l10n("download")});
    return downloadBox;
  }

  private void selectLocation(HTMLNode node) {
    String downloadLocation = core.getDownloadsDir().getAbsolutePath();
    if (!core.allowDownloadTo(core.getDownloadsDir())) {
      downloadLocation = core.getAllowedDownloadDirs()[0].getAbsolutePath();
    }
    node.addChild(
        TAG_INPUT,
        new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE, "maxlength", "size"},
        new String[] {
          "text",
          "path",
          downloadLocation,
          Integer.toString(MAX_FILENAME_LENGTH),
          String.valueOf(downloadLocation.length())
        });
    node.addChild(
        TAG_INPUT,
        new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
        new String[] {INPUT_TYPE_SUBMIT, "select-location", l10n("browseToChange") + "..."});
  }

  private HTMLNode createRequestTable(
      RequestTableContext tableContext,
      List<? extends QueuePageRequestView> requests,
      QueueColumn[] columns,
      String id,
      QueueType queueType,
      boolean uploads) {
    return createRequestTable(tableContext, requests, columns, id, null, queueType, uploads);
  }

  private HTMLNode createRequestTable(
      RequestTableContext tableContext,
      List<? extends QueuePageRequestView> requests,
      QueueColumn[] columns,
      String id,
      String mimeType,
      QueueType queueType,
      boolean uploads) {
    boolean hasFriends = core.getNode().network().darknetConnections().length > 0;
    long now = System.currentTimeMillis();

    HTMLNode formDiv = new HTMLNode("div", ATTR_CLASS, "request-table-form");
    HTMLNode form =
        addFormChild(
            formDiv,
            path(uploads),
            "request-table-form-"
                + id
                + (tableContext.advancedModeEnabled ? "-advanced" : "-simple"));

    createRequestTableButtons(
        form,
        mimeType,
        hasFriends,
        tableContext.advancedModeEnabled,
        tableContext.priorityClasses,
        true,
        queueType);

    HTMLNode table = form.addChild(TAG_TABLE, ATTR_CLASS, "requests");
    HTMLNode headerRow = table.addChild("tr", ATTR_CLASS, "table-header");
    headerRow.addChild("th");
    addHeaderCells(headerRow, columns, tableContext.reversed);

    RowRenderContext rowContext =
        new RowRenderContext(
            tableContext.advancedModeEnabled, tableContext.priorityClasses, now, queueType);
    addRequestRows(table, requests, columns, rowContext);

    createRequestTableButtons(
        form,
        mimeType,
        hasFriends,
        tableContext.advancedModeEnabled,
        tableContext.priorityClasses,
        false,
        queueType);
    return formDiv;
  }

  private void addHeaderCells(HTMLNode headerRow, QueueColumn[] columns, boolean reversed) {
    for (QueueColumn column : columns) {
      headerRow.addChild(createHeaderCell(column, reversed));
    }
  }

  private HTMLNode createHeaderCell(QueueColumn column, boolean reversed) {
    HTMLNode headerCell = new HTMLNode("th");
    if (column.isSortable()) {
      headerCell
          .addChild("a", "href", column.sortHref(reversed))
          .addChild("#", l10n(column.labelKey()));
    } else {
      headerCell.addChild("#", l10n(column.labelKey()));
    }
    return headerCell;
  }

  private void addRequestRows(
      HTMLNode table,
      List<? extends QueuePageRequestView> requests,
      QueueColumn[] columns,
      RowRenderContext rowContext) {
    int index = 0;
    for (QueuePageRequestView clientRequest : requests) {
      HTMLNode requestRow =
          table.addChild("tr", ATTR_CLASS, PRIORITY + clientRequest.getPriority());
      requestRow.addChild(createCheckboxCell(clientRequest, index++));
      for (QueueColumn column : columns) {
        HTMLNode cell = createColumnCell(column, clientRequest, rowContext);
        if (cell != null) {
          requestRow.addChild(cell);
        }
      }
    }
  }

  private HTMLNode createColumnCell(
      QueueColumn column, QueuePageRequestView clientRequest, RowRenderContext rowContext) {
    return switch (column) {
      case IDENTIFIER ->
          createIdentifierCell(
              clientRequest.getUri(),
              clientRequest.getIdentifier(),
              clientRequest instanceof QueuePageUploadDirView);
      case SIZE -> createSizeCellForRequest(clientRequest, rowContext.advancedModeEnabled);
      case MIME_TYPE -> createMimeTypeCell(clientRequest);
      case PERSISTENCE ->
          createPersistenceCell(clientRequest.isPersistent(), clientRequest.isPersistentForever());
      case KEY -> createKeyCellForRequest(clientRequest);
      case FILENAME -> createFilenameCellForRequest(clientRequest);
      case PRIORITY -> createPriorityCell(clientRequest.getPriority(), rowContext.priorityClasses);
      case FILES -> createNumberCell(((QueuePageUploadDirView) clientRequest).getNumberOfFiles());
      case TOTAL_SIZE ->
          createSizeCell(
              ((QueuePageUploadDirView) clientRequest).getTotalDataSize(),
              true,
              rowContext.advancedModeEnabled);
      case PROGRESS ->
          createProgressCellForRequest(
              clientRequest, rowContext.advancedModeEnabled, rowContext.queueType.isUpload);
      case REASON -> createReasonCell(clientRequest.getFailureReason(false));
      case LAST_ACTIVITY -> createLastActivityCell(rowContext.now, clientRequest.getLastSuccess());
      case LAST_FAILURE -> createLastFailureCell(rowContext.now, clientRequest.getLastFailure());
      case COMPAT_MODE -> createCompatModeCellForRequest(clientRequest);
    };
  }

  private HTMLNode createReasonCell(String failureReason) {
    HTMLNode reasonCell = new HTMLNode("td", ATTR_CLASS, "request-reason");
    if (failureReason == null) {
      reasonCell.addChild("span", ATTR_CLASS, "failure_reason_unknown", l10n(UNKNOWN));
    } else {
      reasonCell.addChild("span", ATTR_CLASS, "failure_reason_is", failureReason);
    }
    return reasonCell;
  }

  private HTMLNode createNumberCell(int numberOfFiles) {
    HTMLNode numberCell = new HTMLNode("td", ATTR_CLASS, "request-files");
    numberCell.addChild("span", ATTR_CLASS, "number_of_files", String.valueOf(numberOfFiles));
    return numberCell;
  }

  private HTMLNode createFilenameCell(File filename) {
    HTMLNode filenameCell = new HTMLNode("td", ATTR_CLASS, "request-filename");
    if (filename != null) {
      filenameCell.addChild("span", ATTR_CLASS, "filename_is", filename.toString());
    } else {
      filenameCell.addChild("span", ATTR_CLASS, "filename_none", l10n("none"));
    }
    return filenameCell;
  }

  private HTMLNode createPriorityCell(short priorityClass, String[] priorityClasses) {
    HTMLNode priorityCell = new HTMLNode("td", ATTR_CLASS, "request-priority");
    if (priorityClass < 0 || priorityClass >= priorityClasses.length) {
      priorityCell.addChild("span", ATTR_CLASS, "priority_unknown", l10n(UNKNOWN));
    } else {
      priorityCell.addChild("span", ATTR_CLASS, "priority_is", priorityClasses[priorityClass]);
    }
    return priorityCell;
  }

  private HTMLNode createPriorityControl(
      String[] priorityClasses,
      boolean advancedModeEnabled,
      boolean isUpload,
      String controlSuffix) {
    short selectedPriorityClass = RequestStarter.BULK_SPLITFILE_PRIORITY_CLASS;
    HTMLNode priorityDiv = new HTMLNode("div", ATTR_CLASS, "request-priority nowrap");
    priorityDiv.addChild(
        TAG_INPUT,
        new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
        new String[] {
          INPUT_TYPE_SUBMIT,
          "change_priority" + controlSuffix,
          NodeL10n.getBase()
              .getString(
                  isUpload
                      ? QUEUE_TOADLET_PREFIX + "changeUploadPriorities"
                      : QUEUE_TOADLET_PREFIX + "changeDownloadPriorities")
        });
    HTMLNode prioritySelect = priorityDiv.addChild("select", ATTR_NAME, PRIORITY + controlSuffix);
    for (int p = 0; p < RequestStarter.NUMBER_OF_PRIORITY_CLASSES; p++) {
      if (p <= RequestStarter.INTERACTIVE_PRIORITY_CLASS && !advancedModeEnabled) {
        continue;
      }
      if (p == selectedPriorityClass) {
        prioritySelect.addChild(
            "option",
            new String[] {ATTR_VALUE, "selected"},
            new String[] {String.valueOf(p), "selected"},
            priorityClasses[p]);
      } else {
        prioritySelect.addChild("option", ATTR_VALUE, String.valueOf(p), priorityClasses[p]);
      }
    }
    return priorityDiv;
  }

  private HTMLNode createRecommendControl() {
    HTMLNode recommendDiv = new HTMLNode("div", ATTR_CLASS, "request-recommend");
    recommendDiv.addChild(
        TAG_INPUT,
        new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
        new String[] {INPUT_TYPE_SUBMIT, "recommend_request", l10n("recommendFilesToFriends")});
    return recommendDiv;
  }

  private HTMLNode createDeleteControl(String mimeType, QueueType queueType) {
    HTMLNode deleteDiv = new HTMLNode("div", ATTR_CLASS, "request-delete");
    if (queueType == QueueType.COMPLETED_DOWNLOAD_TO_TEMP) {
      deleteDiv.addChild(
          TAG_INPUT,
          new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
          new String[] {INPUT_TYPE_SUBMIT, DELETE_REQUEST, l10n("deleteFilesFromTemp")});
    } else if (!queueType.isCompleted) {
      deleteDiv.addChild(
          TAG_INPUT,
          new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
          new String[] {INPUT_TYPE_SUBMIT, REMOVE_REQUEST, l10n("cancelSelected")});
    } else {
      deleteDiv.addChild(
          TAG_INPUT,
          new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
          new String[] {INPUT_TYPE_SUBMIT, REMOVE_REQUEST, l10n("removeFilesFromList")});
    }
    if (queueType == QueueType.COMPLETED_DOWNLOAD_TO_DISK) {
      deleteDiv.addChild(
          TAG_INPUT,
          new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
          new String[] {
            INPUT_TYPE_SUBMIT, REMOVE_FINISHED_DOWNLOADS_REQUEST, l10n("removeFinishedDownloads")
          });
    }
    if (queueType == QueueType.COMPLETED_UPLOAD) {
      deleteDiv.addChild(
          TAG_INPUT,
          new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
          new String[] {
            INPUT_TYPE_SUBMIT, REMOVE_FINISHED_UPLOADS_REQUEST, l10n("removeFinishedUploads")
          });
    }
    if (queueType.isFailed) {
      deleteDiv.addChild(
          TAG_INPUT,
          new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
          new String[] {
            INPUT_TYPE_SUBMIT,
            RESTART_REQUEST,
            NodeL10n.getBase().getString(QUEUE_TOADLET_PREFIX + "restartSelected")
          });
      if (mimeType != null) {
        deleteDiv.addChild(
            TAG_INPUT,
            new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
            new String[] {INPUT_TYPE_CHECKBOX, DISABLE_FILTER_DATA, DISABLE_FILTER_DATA});
        deleteDiv.addChild("#", l10n("disableFilter", "type", mimeType));
      }
    }
    return deleteDiv;
  }

  private void createRequestTableButtons(
      HTMLNode form,
      String mimeType,
      boolean hasFriends,
      boolean advancedModeEnabled,
      String[] priorityClasses,
      boolean top,
      QueueType queueType) {
    form.addChild(createDeleteControl(mimeType, queueType));
    if (hasFriends && !queueCannotRecommend(queueType)) {
      form.addChild(createRecommendControl());
    }
    if (!(queueType.isFailed || queueType.isCompleted)) {
      form.addChild(
          createPriorityControl(
              priorityClasses, advancedModeEnabled, queueType.isUpload, top ? "_top" : "_bottom"));
    }
  }

  private boolean queueCannotRecommend(QueueType queueType) {
    return queueType.isUpload && !queueType.isCompleted;
  }

  private HTMLNode createCheckboxCell(QueuePageRequestView clientRequest, int counter) {
    HTMLNode cell = new HTMLNode("td", ATTR_CLASS, "checkbox-cell");
    cell.addChild(
        TAG_INPUT,
        new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
        new String[] {
          INPUT_TYPE_CHECKBOX, IDENTIFIER_PREFIX + counter, clientRequest.getIdentifier()
        });
    FreenetURI uri;
    long size = -1;
    if (clientRequest instanceof QueuePageDownloadView) {
      uri = clientRequest.getUri();
      size = clientRequest.getDataSize();
    } else if (clientRequest instanceof QueuePageUploadView status) {
      uri = status.getFinalUri();
      size = clientRequest.getDataSize();
    } else {
      uri = null;
    }
    if (uri != null) {
      cell.addChild(
          TAG_INPUT,
          new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
          new String[] {INPUT_TYPE_HIDDEN, KEY_PREFIX + counter, uri.toASCIIString()});
    }
    if (size != -1) {
      cell.addChild(
          TAG_INPUT,
          new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
          new String[] {INPUT_TYPE_HIDDEN, "size-" + counter, Long.toString(size)});
    }
    String filename = clientRequest.getPreferredFilenameSafe();
    if (filename != null) {
      cell.addChild(
          TAG_INPUT,
          new String[] {ATTR_TYPE, ATTR_NAME, ATTR_VALUE},
          new String[] {INPUT_TYPE_HIDDEN, FILENAME_PREFIX + counter, filename});
    }
    return cell;
  }

  private HTMLNode createIdentifierCell(FreenetURI uri, String identifier, boolean directory) {
    HTMLNode identifierCell = new HTMLNode("td", ATTR_CLASS, "request-identifier");
    if (uri != null) {
      identifierCell
          .addChild("span", ATTR_CLASS, "identifier_with_uri")
          .addChild("a", "href", "/" + uri + (directory ? "/" : ""), identifier);
    } else {
      identifierCell.addChild("span", ATTR_CLASS, "identifier_without_uri", identifier);
    }
    return identifierCell;
  }

  private HTMLNode createPersistenceCell(boolean persistent, boolean persistentForever) {
    HTMLNode persistenceCell = new HTMLNode("td", ATTR_CLASS, "request-persistence");
    if (persistentForever) {
      persistenceCell.addChild(
          "span", ATTR_CLASS, "persistence_forever", l10n("persistenceForever"));
    } else if (persistent) {
      persistenceCell.addChild("span", ATTR_CLASS, "persistence_reboot", l10n("persistenceReboot"));
    } else {
      persistenceCell.addChild("span", ATTR_CLASS, "persistence_none", l10n("persistenceNone"));
    }
    return persistenceCell;
  }

  private HTMLNode createTypeCell(String type) {
    HTMLNode typeCell = new HTMLNode("td", ATTR_CLASS, "request-type");
    if (type != null) {
      typeCell.addChild("span", ATTR_CLASS, "mimetype_is", type);
    } else {
      typeCell.addChild("span", ATTR_CLASS, "mimetype_unknown", l10n(UNKNOWN));
    }
    return typeCell;
  }

  private HTMLNode createSizeCell(long dataSize, boolean confirmed, boolean advancedModeEnabled) {
    HTMLNode sizeCell = new HTMLNode("td", ATTR_CLASS, "request-size");
    if (dataSize > 0 && (confirmed || advancedModeEnabled)) {
      sizeCell.addChild(
          "span",
          ATTR_CLASS,
          "filesize_is",
          (confirmed ? "" : ">= ") + SizeUtil.formatSize(dataSize) + (confirmed ? "" : " ??"));
    } else {
      sizeCell.addChild("span", ATTR_CLASS, "filesize_unknown", l10n(UNKNOWN));
    }
    return sizeCell;
  }

  private HTMLNode createKeyCell(FreenetURI uri, boolean addSlash) {
    HTMLNode keyCell = new HTMLNode("td", ATTR_CLASS, "request-key");
    if (uri != null) {
      keyCell
          .addChild("span", ATTR_CLASS, "key_is")
          .addChild(
              "a",
              "href",
              '/' + uri.toString() + (addSlash ? "/" : ""),
              uri.toShortString() + (addSlash ? "/" : ""));
    } else {
      keyCell.addChild("span", ATTR_CLASS, "key_unknown", l10n(UNKNOWN));
    }
    return keyCell;
  }

  private HTMLNode createLastActivityCell(long now, Instant lastActivity) {
    HTMLNode lastActivityCell = new HTMLNode("td", ATTR_CLASS, "request-last-activity");
    if (lastActivity == null) {
      lastActivityCell.addChild("i", l10n("lastActivity.unknown"));
    } else {
      lastActivityCell.addChild(
          "#",
          l10n("lastActivity.ago", "time", TimeUtil.formatTime(now - lastActivity.toEpochMilli())));
    }
    return lastActivityCell;
  }

  private HTMLNode createLastFailureCell(long now, Instant lastFailure) {
    HTMLNode lastFailureCell = new HTMLNode("td", ATTR_CLASS, "request-last-failure");
    if (lastFailure == null) {
      lastFailureCell.addChild("i", l10n("lastFailure.never"));
    } else {
      lastFailureCell.addChild(
          "#",
          l10n("lastFailure.ago", "time", TimeUtil.formatTime(now - lastFailure.toEpochMilli())));
    }
    return lastFailureCell;
  }

  private HTMLNode createSizeCellForRequest(
      QueuePageRequestView clientRequest, boolean advancedModeEnabled) {
    boolean isFinal =
        !(clientRequest instanceof QueuePageDownloadView) || clientRequest.isTotalFinalized();
    return createSizeCell(clientRequest.getDataSize(), isFinal, advancedModeEnabled);
  }

  private HTMLNode createMimeTypeCell(QueuePageRequestView clientRequest) {
    if (clientRequest instanceof QueuePageDownloadView downloadStatus) {
      return createTypeCell(downloadStatus.getMimeType());
    }
    if (clientRequest instanceof QueuePageUploadFileView uploadStatus) {
      return createTypeCell(uploadStatus.getMimeType());
    }
    return null;
  }

  private HTMLNode createKeyCellForRequest(QueuePageRequestView clientRequest) {
    if (clientRequest instanceof QueuePageDownloadView) {
      return createKeyCell(clientRequest.getUri(), false);
    }
    if (clientRequest instanceof QueuePageUploadFileView uploadStatus) {
      return createKeyCell(uploadStatus.getFinalUri(), false);
    }
    return createKeyCell(((QueuePageUploadDirView) clientRequest).getFinalUri(), true);
  }

  private HTMLNode createFilenameCellForRequest(QueuePageRequestView clientRequest) {
    if (clientRequest instanceof QueuePageDownloadView downloadStatus) {
      return createFilenameCell(downloadStatus.getDestFilename());
    }
    if (clientRequest instanceof QueuePageUploadFileView uploadStatus) {
      return createFilenameCell(uploadStatus.getOrigFilename());
    }
    return null;
  }

  private HTMLNode createProgressCellForRequest(
      QueuePageRequestView clientRequest, boolean advancedModeEnabled, boolean isUploadQueue) {
    QueueCompressionState compressing =
        clientRequest instanceof QueuePageUploadFileView uploadStatus
            ? uploadStatus.getCompressionState()
            : QueueCompressionState.WORKING;
    boolean finalizedTotal =
        clientRequest instanceof QueuePageUploadFileView || clientRequest.isTotalFinalized();
    QueueProgressCellContext progressContext =
        new QueueProgressCellContext(
            advancedModeEnabled, clientRequest.isStarted(), compressing, isUploadQueue);
    SplitfileProgressCounts progressCounts =
        new SplitfileProgressCounts(
            clientRequest.getTotalBlocks(),
            clientRequest.getFetchedBlocks(),
            clientRequest.getFailedBlocks(),
            clientRequest.getFatalyFailedBlocks(),
            clientRequest.getMinBlocks(),
            clientRequest.getMinBlocks(),
            finalizedTotal);
    return QueueProgressCellRenderer.createProgressCell(progressContext, progressCounts);
  }

  private HTMLNode createCompatModeCellForRequest(QueuePageRequestView clientRequest) {
    if (clientRequest instanceof QueuePageDownloadView downloadStatus) {
      return createCompatModeCell(downloadStatus);
    }
    return new HTMLNode("td");
  }

  private HTMLNode createCompatModeCell(QueuePageDownloadView get) {
    HTMLNode compatCell = new HTMLNode("td", ATTR_CLASS, "request-compat-mode");
    InsertContext.CompatibilityMode[] compat = get.getCompatibilityMode();
    if (!(compat[0] == InsertContext.CompatibilityMode.COMPAT_UNKNOWN
        && compat[1] == InsertContext.CompatibilityMode.COMPAT_UNKNOWN)) {
      if (compat[0] == compat[1]) {
        compatCell.addChild(
            "#",
            NodeL10n.getBase()
                .getString(INSERT_CONTEXT_COMPATIBILITY_MODE_PREFIX + compat[0].name()));
      } else {
        compatCell.addChild(
            "#",
            NodeL10n.getBase()
                    .getString(INSERT_CONTEXT_COMPATIBILITY_MODE_PREFIX + compat[0].name())
                + " - "
                + NodeL10n.getBase()
                    .getString(INSERT_CONTEXT_COMPATIBILITY_MODE_PREFIX + compat[1].name()));
      }
      byte[] overrideCryptoKey = get.getOverriddenSplitfileCryptoKey();
      if (overrideCryptoKey != null) {
        compatCell.addChild(
            "#", " - " + l10n("overriddenCryptoKeyInCompatCell") + ": " + toHex(overrideCryptoKey));
      }
      if (get.detectedDontCompress()) {
        compatCell.addChild("#", " (" + l10n("dontCompressInCompatCell") + ")");
      }
    }
    return compatCell;
  }

  private static String toHex(byte[] data) {
    char[] out = new char[data.length * 2];
    for (int i = 0; i < data.length; i++) {
      int v = data[i] & 0xFF;
      out[i * 2] = HEX_ARRAY[v >>> 4];
      out[i * 2 + 1] = HEX_ARRAY[v & 0x0F];
    }
    return new String(out);
  }

  private HTMLNode addInfobox(
      String category, String header, HTMLNode parent, String title, boolean isUnique) {
    InfoboxParts infobox = createInfobox(category, header, title, isUnique);
    parent.addChild(infobox.outerNode);
    return infobox.contentNode;
  }

  private InfoboxParts createInfobox(
      String category, String header, String title, boolean isUnique) {
    StringBuilder classes = new StringBuilder("infobox");
    if (category != null) {
      classes.append(' ').append(category);
    }
    if (title != null && !isUnique) {
      classes.append(' ').append(title);
    }
    HTMLNode infobox = new HTMLNode("div", ATTR_CLASS, classes.toString());
    if (title != null && isUnique) {
      infobox.addAttribute("id", title);
    }
    infobox.addChild("div", ATTR_CLASS, "infobox-header").addChild("#", header);
    HTMLNode contentNode = infobox.addChild("div", ATTR_CLASS, "infobox-content");
    return new InfoboxParts(infobox, contentNode);
  }

  private HTMLNode addFormChild(HTMLNode parentNode, String target, String id) {
    HTMLNode formNode =
        parentNode
            .addChild("div")
            .addChild(
                "form",
                new String[] {"action", "method", "enctype", "id", "accept-charset"},
                new String[] {target, "post", "multipart/form-data", id, "utf-8"});
    formNode.addChild("%", FORM_PASSWORD_PLACEHOLDER);
    return formNode;
  }

  private static String path(boolean uploads) {
    return uploads ? PATH_UPLOADS : PATH_DOWNLOADS;
  }

  private static String normalizePath(String rawPath) {
    String normalized = rawPath;
    if (!normalized.startsWith("/")) {
      normalized = '/' + normalized;
    }
    if (!normalized.endsWith("/")) {
      normalized = normalized + '/';
    }
    return normalized;
  }

  private enum QueueColumn {
    IDENTIFIER("identifier", "id"),
    SIZE("size", "size"),
    MIME_TYPE("mimeType", null),
    PERSISTENCE("persistence", null),
    KEY("key", null),
    FILENAME("fileName", null),
    PRIORITY(LegacyQueuePagePort.PRIORITY, null),
    FILES("files", null),
    TOTAL_SIZE("totalSize", null),
    PROGRESS(PROGRESS_LABEL, PROGRESS_LABEL),
    REASON("reason", null),
    LAST_ACTIVITY(LAST_ACTIVITY_LABEL, LAST_ACTIVITY_LABEL),
    LAST_FAILURE(LAST_FAILURE_LABEL, LAST_FAILURE_LABEL),
    COMPAT_MODE(COMPATIBILITY_MODE_FIELD, null);

    private final String labelKey;
    private final String sortKey;

    QueueColumn(String labelKey, String sortKey) {
      this.labelKey = labelKey;
      this.sortKey = sortKey;
    }

    private String labelKey() {
      return labelKey;
    }

    private boolean isSortable() {
      return sortKey != null;
    }

    private String sortHref(boolean reversed) {
      return reversed ? "?sortBy=" + sortKey : "?sortBy=" + sortKey + "&reversed";
    }
  }

  private enum QueueType {
    COMPLETED_DOWNLOAD_TO_TEMP(true, false, false),
    COMPLETED_DOWNLOAD_TO_DISK(true, false, false),
    COMPLETED_UPLOAD(true, false, true),
    COMPLETED_DIR_UPLOAD(true, false, true),
    FAILED_DOWNLOAD(false, true, false),
    FAILED_UPLOAD(false, true, true),
    FAILED_DIR_UPLOAD(false, true, true),
    FAILED_BAD_MIME_TYPE(false, true, false),
    FAILED_UNKNOWN_MIME_TYPE(false, true, false),
    UNCOMPLETED_DOWNLOAD(false, false, false),
    UNCOMPLETED_UPLOAD(false, false, true),
    UNCOMPLETED_DIR_UPLOAD(false, false, true);

    private final boolean isCompleted;
    private final boolean isFailed;
    private final boolean isUpload;

    QueueType(boolean isCompleted, boolean isFailed, boolean isUpload) {
      this.isCompleted = isCompleted;
      this.isFailed = isFailed;
      this.isUpload = isUpload;
    }
  }

  private static final class QueuePartitions {
    private final List<QueuePageDownloadView> completedDownloadToDisk = new ArrayList<>();
    private final List<QueuePageDownloadView> completedDownloadToTemp = new ArrayList<>();
    private final List<QueuePageUploadFileView> completedUpload = new ArrayList<>();
    private final List<QueuePageUploadDirView> completedDirUpload = new ArrayList<>();
    private final List<QueuePageDownloadView> failedDownload = new ArrayList<>();
    private final List<QueuePageUploadFileView> failedUpload = new ArrayList<>();
    private final List<QueuePageUploadDirView> failedDirUpload = new ArrayList<>();
    private final List<QueuePageDownloadView> uncompletedDownload = new ArrayList<>();
    private final List<QueuePageUploadFileView> uncompletedUpload = new ArrayList<>();
    private final List<QueuePageUploadDirView> uncompletedDirUpload = new ArrayList<>();
    private final Map<String, List<QueuePageDownloadView>> failedUnknownMIMEType = new HashMap<>();
    private final Map<String, List<QueuePageDownloadView>> failedBadMIMEType = new HashMap<>();
    private short lowestQueuedPrio = RequestStarter.PAUSED_PRIORITY_CLASS;
    private long totalQueuedDownloadSize;
    private long totalQueuedUploadSize;
    private boolean added;

    private boolean hasAny() {
      return added;
    }
  }

  @SuppressWarnings("ClassCanBeRecord")
  private static final class RequestTableContext {
    private final boolean advancedModeEnabled;
    private final boolean reversed;
    private final String[] priorityClasses;

    private RequestTableContext(
        boolean advancedModeEnabled, boolean reversed, String[] priorityClasses) {
      this.advancedModeEnabled = advancedModeEnabled;
      this.reversed = reversed;
      this.priorityClasses = priorityClasses;
    }
  }

  @SuppressWarnings("ClassCanBeRecord")
  private static final class RowRenderContext {
    private final boolean advancedModeEnabled;
    private final String[] priorityClasses;
    private final long now;
    private final QueueType queueType;

    private RowRenderContext(
        boolean advancedModeEnabled, String[] priorityClasses, long now, QueueType queueType) {
      this.advancedModeEnabled = advancedModeEnabled;
      this.priorityClasses = priorityClasses;
      this.now = now;
      this.queueType = queueType;
    }
  }

  private record InfoboxParts(HTMLNode outerNode, HTMLNode contentNode) {}

  private static String l10n(String key) {
    return NodeL10n.getBase().getString(QUEUE_TOADLET_PREFIX + key);
  }

  private static String l10n(String key, String pattern, String value) {
    return NodeL10n.getBase().getString(QUEUE_TOADLET_PREFIX + key, pattern, value);
  }

  private static String l10n(String key, String[] pattern, String[] value) {
    return NodeL10n.getBase().getString(QUEUE_TOADLET_PREFIX + key, pattern, value);
  }
}
