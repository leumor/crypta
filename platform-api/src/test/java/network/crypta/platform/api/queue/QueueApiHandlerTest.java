package network.crypta.platform.api.queue;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import network.crypta.crypt.mail.MailHpke;
import network.crypta.crypt.mail.MailWire;
import network.crypta.platform.api.PlatformApiException;
import network.crypta.runtime.spi.QueueBrowserUploadInsertRequest;
import network.crypta.runtime.spi.QueueCompletionPort;
import network.crypta.runtime.spi.QueueDownloadPort;
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
import network.crypta.runtime.spi.QueuePersistenceStatusSnapshot;
import network.crypta.runtime.spi.QueueSupportPort;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("java:S100")
class QueueApiHandlerTest {
  @Test
  void snapshot_whenRequested_expectDetachedHtmlWithoutLegacyRuntimePlaceholders() {
    RecordingQueuePagePort queuePagePort = new RecordingQueuePagePort();
    queuePagePort.pageSnapshot =
        new QueuePageSnapshot(
            "Downloads",
            "<div>before<!--CRYPTA_ALERT_SUMMARY--><!--CRYPTA_QUEUE_FORM_PASSWORD-->"
                + "<!--CRYPTA_QUEUE_PANIC_BOX-->after</div>");
    RecordingQueueCompletionPort queueCompletionPort = new RecordingQueueCompletionPort();
    QueueApiHandler handler =
        new QueueApiHandler(
            queuePagePort,
            new RecordingQueueMutationPort(),
            new RecordingQueueDownloadPort(),
            new RecordingQueueInsertPort(),
            new FixedQueueSupportPort(true),
            queueCompletionPort);

    Map<String, Object> snapshot =
        handler.snapshot(
            orderedParameters(
                Map.entry("page", List.of("downloads")),
                Map.entry("advancedMode", List.of("true")),
                Map.entry("sortBy", List.of("priority")),
                Map.entry("reversed", List.of("true"))));

    assertEquals(
        new QueuePageRequest(false, true, "priority", true), queuePagePort.lastPageRequest);
    assertEquals(List.of(false), queueCompletionPort.startedSides);
    assertEquals("downloads", snapshot.get("page"));
    assertEquals("Downloads", snapshot.get("pageTitle"));
    assertEquals("<div>beforeafter</div>", snapshot.get("contentHtml"));
    assertEquals(Boolean.TRUE, snapshot.get("advancedMode"));
    assertEquals("priority", snapshot.get("sortBy"));
    assertEquals(Boolean.TRUE, snapshot.get("reversed"));
  }

  @Test
  void count_whenUploadsRequested_expectBadRequest() {
    RecordingQueuePagePort queuePagePort = new RecordingQueuePagePort();
    RecordingQueueCompletionPort queueCompletionPort = new RecordingQueueCompletionPort();
    QueueApiHandler handler =
        new QueueApiHandler(
            queuePagePort,
            new RecordingQueueMutationPort(),
            new RecordingQueueDownloadPort(),
            new RecordingQueueInsertPort(),
            new FixedQueueSupportPort(true),
            queueCompletionPort);
    Map<String, List<String>> parameters = orderedParameters(Map.entry("page", List.of("uploads")));

    PlatformApiException error =
        assertThrows(PlatformApiException.class, () -> handler.count(parameters));

    assertEquals(400, error.statusCode());
    assertEquals("invalid_query_parameter", error.errorCode());
    assertEquals(
        "Query parameter 'page' must be 'downloads' for this endpoint.", error.getMessage());
    assertEquals(0, queuePagePort.countPageRequests);
    assertEquals(List.of(), queueCompletionPort.startedSides);
  }

  @Test
  void removeRequests_whenLegacyIdentifierParametersProvided_expectSelectionOrderPreserved() {
    RecordingQueueMutationPort queueMutationPort = new RecordingQueueMutationPort();
    QueueApiHandler handler =
        new QueueApiHandler(
            new RecordingQueuePagePort(),
            queueMutationPort,
            new RecordingQueueDownloadPort(),
            new RecordingQueueInsertPort(),
            new FixedQueueSupportPort(true),
            new RecordingQueueCompletionPort());

    Map<String, Object> result =
        handler.removeRequests(
            orderedParameters(
                Map.entry("identifier-0", List.of("download-1")),
                Map.entry("identifier-1", List.of("download-2"))));

    assertEquals(List.of("download-1", "download-2"), queueMutationPort.lastIdentifiers);
    assertEquals("remove", result.get("operation"));
    assertEquals(2, result.get("identifierCount"));
  }

  @Test
  void removeRequests_whenIdentifierFieldsOutOfOrder_expectSuffixOrderPreserved() {
    RecordingQueueMutationPort queueMutationPort = new RecordingQueueMutationPort();
    QueueApiHandler handler =
        new QueueApiHandler(
            new RecordingQueuePagePort(),
            queueMutationPort,
            new RecordingQueueDownloadPort(),
            new RecordingQueueInsertPort(),
            new FixedQueueSupportPort(true),
            new RecordingQueueCompletionPort());

    Map<String, Object> result =
        handler.removeRequests(
            orderedParameters(
                Map.entry("identifier-10", List.of("download-10")),
                Map.entry("identifier-2", List.of("download-2")),
                Map.entry("identifier-1", List.of("download-1"))));

    assertEquals(
        List.of("download-1", "download-2", "download-10"), queueMutationPort.lastIdentifiers);
    assertEquals("remove", result.get("operation"));
    assertEquals(3, result.get("identifierCount"));
  }

  @Test
  void removeRequests_whenRepeatedIdentifierParameterProvided_expectAllIdentifiersPreserved() {
    RecordingQueueMutationPort queueMutationPort = new RecordingQueueMutationPort();
    QueueApiHandler handler =
        new QueueApiHandler(
            new RecordingQueuePagePort(),
            queueMutationPort,
            new RecordingQueueDownloadPort(),
            new RecordingQueueInsertPort(),
            new FixedQueueSupportPort(true),
            new RecordingQueueCompletionPort());

    Map<String, Object> result =
        handler.removeRequests(
            orderedParameters(Map.entry("identifier", List.of("download-1", "download-2"))));

    assertEquals(List.of("download-1", "download-2"), queueMutationPort.lastIdentifiers);
    assertEquals("remove", result.get("operation"));
    assertEquals(2, result.get("identifierCount"));
  }

  @Test
  void createDirectDownload_whenRequested_expectDirectForeverQueueRequest() {
    RecordingQueueDownloadPort queueDownloadPort = new RecordingQueueDownloadPort();
    QueueApiHandler handler =
        new QueueApiHandler(
            new RecordingQueuePagePort(),
            new RecordingQueueMutationPort(),
            queueDownloadPort,
            new RecordingQueueInsertPort(),
            new FixedQueueSupportPort(true),
            new RecordingQueueCompletionPort());

    Map<String, Object> result =
        handler.createDirectDownload(
            orderedParameters(
                Map.entry("fetchUri", List.of("KSK@direct-download")),
                Map.entry("filterData", List.of("true")),
                Map.entry("expectedMimeType", List.of("text/plain"))));

    assertEquals(
        new QueueDownloadRequest(
            "KSK@direct-download", true, "text/plain", "forever", "direct", null),
        queueDownloadPort.lastRequest);
    assertEquals("create_direct_download", result.get("operation"));
    assertEquals("KSK@direct-download", result.get("fetchUri"));
    assertEquals(Boolean.TRUE, result.get("filterData"));
    assertEquals("text/plain", result.get("expectedMimeType"));
    assertEquals("direct", result.get("returnType"));
  }

  @Test
  void createDirectDownload_whenFilterDataCheckboxValuePresent_expectTrue() {
    RecordingQueueDownloadPort queueDownloadPort = new RecordingQueueDownloadPort();
    QueueApiHandler handler =
        new QueueApiHandler(
            new RecordingQueuePagePort(),
            new RecordingQueueMutationPort(),
            queueDownloadPort,
            new RecordingQueueInsertPort(),
            new FixedQueueSupportPort(true),
            new RecordingQueueCompletionPort());

    Map<String, Object> result =
        handler.createDirectDownload(
            orderedParameters(
                Map.entry("fetchUri", List.of("KSK@direct-download")),
                Map.entry("filterData", List.of("on"))));

    assertEquals(Boolean.TRUE, result.get("filterData"));
    assertEquals(Boolean.TRUE, queueDownloadPort.lastRequest.filterData());
  }

  @Test
  void createDirectDownload_whenFetchUriMalformed_expectBadRequest() {
    RecordingQueueDownloadPort queueDownloadPort = new RecordingQueueDownloadPort();
    QueueApiHandler handler =
        new QueueApiHandler(
            new RecordingQueuePagePort(),
            new RecordingQueueMutationPort(),
            queueDownloadPort,
            new RecordingQueueInsertPort(),
            new FixedQueueSupportPort(true),
            new RecordingQueueCompletionPort());
    Map<String, List<String>> parameters =
        orderedParameters(Map.entry("fetchUri", List.of("http://example.com/")));

    PlatformApiException error =
        assertThrows(PlatformApiException.class, () -> handler.createDirectDownload(parameters));

    assertEquals(400, error.statusCode());
    assertEquals("invalid_query_parameter", error.errorCode());
    assertEquals("Query parameter 'fetchUri' must be a valid fetch URI.", error.getMessage());
    assertNull(queueDownloadPort.lastRequest);
  }

  @Test
  void changePriority_whenPriorityMalformed_expectBadRequest() {
    QueueApiHandler handler =
        new QueueApiHandler(
            new RecordingQueuePagePort(),
            new RecordingQueueMutationPort(),
            new RecordingQueueDownloadPort(),
            new RecordingQueueInsertPort(),
            new FixedQueueSupportPort(true),
            new RecordingQueueCompletionPort());
    Map<String, List<String>> parameters =
        orderedParameters(
            Map.entry("identifier-0", List.of("download-1")),
            Map.entry("priority", List.of("fast")));

    PlatformApiException error =
        assertThrows(PlatformApiException.class, () -> handler.changePriority(parameters));

    assertEquals(400, error.statusCode());
    assertEquals("invalid_query_parameter", error.errorCode());
  }

  @Test
  void changePriority_whenPriorityWithinSupportedRange_expectMutationSummary() {
    RecordingQueueMutationPort queueMutationPort = new RecordingQueueMutationPort();
    QueueApiHandler handler =
        new QueueApiHandler(
            new RecordingQueuePagePort(),
            queueMutationPort,
            new RecordingQueueDownloadPort(),
            new RecordingQueueInsertPort(),
            new FixedQueueSupportPort(true),
            new RecordingQueueCompletionPort());
    Map<String, List<String>> parameters =
        orderedParameters(
            Map.entry("identifier-0", List.of("download-1")),
            Map.entry("identifier-1", List.of("download-2")),
            Map.entry("priority", List.of("3")));

    Map<String, Object> result = handler.changePriority(parameters);

    assertEquals(List.of("download-1", "download-2"), queueMutationPort.lastIdentifiers);
    assertEquals((short) 3, queueMutationPort.lastPriorityClass);
    assertEquals("change_priority", result.get("operation"));
    assertEquals(2, result.get("identifierCount"));
    assertEquals((short) 3, result.get("priority"));
  }

  @Test
  void changePriority_whenPriorityOutsideSupportedRange_expectBadRequest() {
    QueueApiHandler handler =
        new QueueApiHandler(
            new RecordingQueuePagePort(),
            new RecordingQueueMutationPort(),
            new RecordingQueueDownloadPort(),
            new RecordingQueueInsertPort(),
            new FixedQueueSupportPort(true),
            new RecordingQueueCompletionPort());
    Map<String, List<String>> parameters =
        orderedParameters(
            Map.entry("identifier-0", List.of("download-1")), Map.entry("priority", List.of("99")));

    PlatformApiException error =
        assertThrows(PlatformApiException.class, () -> handler.changePriority(parameters));

    assertEquals(400, error.statusCode());
    assertEquals("invalid_query_parameter", error.errorCode());
    assertEquals("Query parameter 'priority' must be between 0 and 6.", error.getMessage());
  }

  @Test
  void restartRequests_whenDisableFilterCheckboxValuePresent_expectTrue() {
    RecordingQueueMutationPort queueMutationPort = new RecordingQueueMutationPort();
    QueueApiHandler handler =
        new QueueApiHandler(
            new RecordingQueuePagePort(),
            queueMutationPort,
            new RecordingQueueDownloadPort(),
            new RecordingQueueInsertPort(),
            new FixedQueueSupportPort(true),
            new RecordingQueueCompletionPort());

    Map<String, Object> result =
        handler.restartRequests(
            orderedParameters(
                Map.entry("identifier-0", List.of("download-1")),
                Map.entry("disableFilterData", List.of("disableFilterData"))));

    assertEquals("restart", result.get("operation"));
    assertEquals(Boolean.TRUE, result.get("disableFilterData"));
    assertEquals(Boolean.TRUE, queueMutationPort.lastDisableFilterData);
  }

  @Test
  void restartRequests_whenDisableFilterCheckboxRepeated_expectTrue() {
    RecordingQueueMutationPort queueMutationPort = new RecordingQueueMutationPort();
    QueueApiHandler handler =
        new QueueApiHandler(
            new RecordingQueuePagePort(),
            queueMutationPort,
            new RecordingQueueDownloadPort(),
            new RecordingQueueInsertPort(),
            new FixedQueueSupportPort(true),
            new RecordingQueueCompletionPort());

    Map<String, Object> result =
        handler.restartRequests(
            orderedParameters(
                Map.entry("identifier-0", List.of("download-1")),
                Map.entry("disableFilterData", List.of("disableFilterData", "disableFilterData"))));

    assertEquals("restart", result.get("operation"));
    assertEquals(Boolean.TRUE, result.get("disableFilterData"));
    assertEquals(Boolean.TRUE, queueMutationPort.lastDisableFilterData);
  }

  @Test
  void createLocalFileInsert_whenRequested_expectDetachedLocalFileInsertRequest() {
    RecordingQueueInsertPort queueInsertPort = new RecordingQueueInsertPort();
    QueueApiHandler handler =
        new QueueApiHandler(
            new RecordingQueuePagePort(),
            new RecordingQueueMutationPort(),
            new RecordingQueueDownloadPort(),
            queueInsertPort,
            new FixedQueueSupportPort(true),
            new RecordingQueueCompletionPort());

    Map<String, Object> result =
        handler.createLocalFileInsert(
            orderedParameters(
                Map.entry("sourcePath", List.of("/tmp/publisher/file.txt")),
                Map.entry("insertUri", List.of("SSK@publisher-file")),
                Map.entry("identifier", List.of("publisher-file-1")),
                Map.entry("contentType", List.of("text/plain")),
                Map.entry("targetFilename", List.of("file.txt")),
                Map.entry("compatibilityMode", List.of("COMPAT_CURRENT")),
                Map.entry("compress", List.of("on"))));

    assertEquals(
        new QueueLocalFileInsertRequest(
            new File("/tmp/publisher/file.txt"),
            "SSK@publisher-file",
            "publisher-file-1",
            "text/plain",
            new QueueInsertOptions(true, "COMPAT_1468", null),
            "file.txt"),
        queueInsertPort.lastLocalFileRequest);
    assertEquals("create_local_file_insert", result.get("operation"));
    assertEquals("file", result.get("sourceType"));
    assertEquals("/tmp/publisher/file.txt", result.get("sourcePath"));
    assertEquals("SSK@publisher-file", result.get("insertUri"));
    assertEquals("publisher-file-1", result.get("identifier"));
    assertEquals("STARTED", result.get("outcome"));
  }

  @Test
  void createLocalFileInsert_whenTargetFilenameMissingAndInsertUriHasNoDocName_expectBasename() {
    RecordingQueueInsertPort queueInsertPort = new RecordingQueueInsertPort();
    QueueApiHandler handler =
        new QueueApiHandler(
            new RecordingQueuePagePort(),
            new RecordingQueueMutationPort(),
            new RecordingQueueDownloadPort(),
            queueInsertPort,
            new FixedQueueSupportPort(true),
            new RecordingQueueCompletionPort());

    handler.createLocalFileInsert(
        orderedParameters(
            Map.entry("sourcePath", List.of("/tmp/publisher/file.txt")),
            Map.entry("insertUri", List.of("CHK@")),
            Map.entry("identifier", List.of("publisher-file-1")),
            Map.entry("compatibilityMode", List.of("COMPAT_CURRENT"))));

    assertEquals("file.txt", queueInsertPort.lastLocalFileRequest.targetFilename());
    assertEquals("COMPAT_1468", queueInsertPort.lastLocalFileRequest.compatibilityMode());
  }

  @Test
  void createLocalFileInsert_whenContentTypeMissing_expectCryptadMimeInference() {
    RecordingQueueInsertPort queueInsertPort = new RecordingQueueInsertPort();
    QueueApiHandler handler =
        new QueueApiHandler(
            new RecordingQueuePagePort(),
            new RecordingQueueMutationPort(),
            new RecordingQueueDownloadPort(),
            queueInsertPort,
            new FixedQueueSupportPort(true),
            new RecordingQueueCompletionPort());

    handler.createLocalFileInsert(
        orderedParameters(
            Map.entry("sourcePath", List.of("/tmp/publisher/image.avif")),
            Map.entry("insertUri", List.of("CHK@")),
            Map.entry("identifier", List.of("publisher-file-1")),
            Map.entry("compatibilityMode", List.of("COMPAT_CURRENT"))));

    assertEquals("image/avif", queueInsertPort.lastLocalFileRequest.contentType());
  }

  @Test
  void createLocalFileInsert_whenTargetFilenameMissingAndInsertUriHasDocName_expectNoDefault() {
    RecordingQueueInsertPort queueInsertPort = new RecordingQueueInsertPort();
    QueueApiHandler handler =
        new QueueApiHandler(
            new RecordingQueuePagePort(),
            new RecordingQueueMutationPort(),
            new RecordingQueueDownloadPort(),
            queueInsertPort,
            new FixedQueueSupportPort(true),
            new RecordingQueueCompletionPort());

    handler.createLocalFileInsert(
        orderedParameters(
            Map.entry("sourcePath", List.of("/tmp/publisher/file.txt")),
            Map.entry("insertUri", List.of("KSK@site-name")),
            Map.entry("identifier", List.of("publisher-file-1")),
            Map.entry("compatibilityMode", List.of("COMPAT_CURRENT"))));

    assertNull(queueInsertPort.lastLocalFileRequest.targetFilename());
  }

  @Test
  void createLocalFileInsert_whenTargetFilenameProvidedAndInsertUriHasDocName_expectSuppressed() {
    RecordingQueueInsertPort queueInsertPort = new RecordingQueueInsertPort();
    QueueApiHandler handler =
        new QueueApiHandler(
            new RecordingQueuePagePort(),
            new RecordingQueueMutationPort(),
            new RecordingQueueDownloadPort(),
            queueInsertPort,
            new FixedQueueSupportPort(true),
            new RecordingQueueCompletionPort());

    handler.createLocalFileInsert(
        orderedParameters(
            Map.entry("sourcePath", List.of("/tmp/publisher/file.txt")),
            Map.entry("insertUri", List.of("KSK@site-name")),
            Map.entry("identifier", List.of("publisher-file-1")),
            Map.entry("targetFilename", List.of("ignored-name.txt")),
            Map.entry("compatibilityMode", List.of("COMPAT_CURRENT"))));

    assertNull(queueInsertPort.lastLocalFileRequest.targetFilename());
  }

  @Test
  void createLocalDirectoryInsert_whenRequested_expectDetachedLocalDirectoryInsertRequest() {
    RecordingQueueInsertPort queueInsertPort = new RecordingQueueInsertPort();
    queueInsertPort.nextOutcome = QueueInsertOutcome.IDENTIFIER_COLLISION;
    QueueApiHandler handler =
        new QueueApiHandler(
            new RecordingQueuePagePort(),
            new RecordingQueueMutationPort(),
            new RecordingQueueDownloadPort(),
            queueInsertPort,
            new FixedQueueSupportPort(true),
            new RecordingQueueCompletionPort());

    Map<String, Object> result =
        handler.createLocalDirectoryInsert(
            orderedParameters(
                Map.entry("sourcePath", List.of("/tmp/publisher/site")),
                Map.entry("insertUri", List.of("SSK@publisher-site")),
                Map.entry("identifier", List.of("publisher-dir-1")),
                Map.entry("compatibilityMode", List.of("COMPAT_1468")),
                Map.entry("compress", List.of("false"))));

    assertEquals(
        new QueueLocalDirectoryInsertRequest(
            new File("/tmp/publisher/site"),
            "SSK@publisher-site",
            "publisher-dir-1",
            new QueueInsertOptions(false, "COMPAT_1468", null)),
        queueInsertPort.lastLocalDirectoryRequest);
    assertEquals("create_local_directory_insert", result.get("operation"));
    assertEquals("directory", result.get("sourceType"));
    assertEquals("/tmp/publisher/site", result.get("sourcePath"));
    assertEquals("SSK@publisher-site", result.get("insertUri"));
    assertEquals("publisher-dir-1", result.get("identifier"));
    assertEquals("IDENTIFIER_COLLISION", result.get("outcome"));
  }

  @Test
  void createLocalFileInsert_whenSourcePathMissing_expectBadRequest() {
    QueueApiHandler handler =
        new QueueApiHandler(
            new RecordingQueuePagePort(),
            new RecordingQueueMutationPort(),
            new RecordingQueueDownloadPort(),
            new RecordingQueueInsertPort(),
            new FixedQueueSupportPort(true),
            new RecordingQueueCompletionPort());
    Map<String, List<String>> parameters =
        orderedParameters(
            Map.entry("insertUri", List.of("SSK@publisher-file")),
            Map.entry("identifier", List.of("publisher-file-1")),
            Map.entry("compatibilityMode", List.of("COMPAT_CURRENT")));

    PlatformApiException error =
        assertThrows(PlatformApiException.class, () -> handler.createLocalFileInsert(parameters));

    assertEquals(400, error.statusCode());
    assertEquals("invalid_query_parameter", error.errorCode());
    assertEquals("Missing required query parameter 'sourcePath'.", error.getMessage());
  }

  @Test
  void createLocalFileInsert_whenInsertUriMissing_expectBadRequest() {
    QueueApiHandler handler =
        new QueueApiHandler(
            new RecordingQueuePagePort(),
            new RecordingQueueMutationPort(),
            new RecordingQueueDownloadPort(),
            new RecordingQueueInsertPort(),
            new FixedQueueSupportPort(true),
            new RecordingQueueCompletionPort());
    Map<String, List<String>> parameters =
        orderedParameters(
            Map.entry("sourcePath", List.of("/tmp/publisher/file.txt")),
            Map.entry("identifier", List.of("publisher-file-1")),
            Map.entry("compatibilityMode", List.of("COMPAT_CURRENT")));

    PlatformApiException error =
        assertThrows(PlatformApiException.class, () -> handler.createLocalFileInsert(parameters));

    assertEquals(400, error.statusCode());
    assertEquals("invalid_query_parameter", error.errorCode());
    assertEquals("Missing required query parameter 'insertUri'.", error.getMessage());
  }

  @Test
  void createLocalFileInsert_whenIdentifierMissing_expectBadRequest() {
    QueueApiHandler handler =
        new QueueApiHandler(
            new RecordingQueuePagePort(),
            new RecordingQueueMutationPort(),
            new RecordingQueueDownloadPort(),
            new RecordingQueueInsertPort(),
            new FixedQueueSupportPort(true),
            new RecordingQueueCompletionPort());
    Map<String, List<String>> parameters =
        orderedParameters(
            Map.entry("sourcePath", List.of("/tmp/publisher/file.txt")),
            Map.entry("insertUri", List.of("SSK@publisher-file")),
            Map.entry("compatibilityMode", List.of("COMPAT_CURRENT")));

    PlatformApiException error =
        assertThrows(PlatformApiException.class, () -> handler.createLocalFileInsert(parameters));

    assertEquals(400, error.statusCode());
    assertEquals("invalid_query_parameter", error.errorCode());
    assertEquals("Missing required query parameter 'identifier'.", error.getMessage());
  }

  @Test
  void createLocalFileInsert_whenContentTypeMalformed_expectBadRequest() {
    RecordingQueueInsertPort queueInsertPort = new RecordingQueueInsertPort();
    QueueApiHandler handler =
        new QueueApiHandler(
            new RecordingQueuePagePort(),
            new RecordingQueueMutationPort(),
            new RecordingQueueDownloadPort(),
            queueInsertPort,
            new FixedQueueSupportPort(true),
            new RecordingQueueCompletionPort());
    Map<String, List<String>> parameters =
        orderedParameters(
            Map.entry("sourcePath", List.of("/tmp/publisher/file.txt")),
            Map.entry("insertUri", List.of("CHK@")),
            Map.entry("identifier", List.of("publisher-file-1")),
            Map.entry("contentType", List.of("textplain")),
            Map.entry("compatibilityMode", List.of("COMPAT_CURRENT")));

    PlatformApiException error =
        assertThrows(PlatformApiException.class, () -> handler.createLocalFileInsert(parameters));

    assertEquals(400, error.statusCode());
    assertEquals("invalid_query_parameter", error.errorCode());
    assertEquals(
        "Query parameter 'contentType' must be a plausible MIME type.", error.getMessage());
    assertNull(queueInsertPort.lastLocalFileRequest);
  }

  @Test
  void createLocalFileInsert_whenCompatibilityModeCurrent_expectRuntimeDefault() {
    RecordingQueueInsertPort queueInsertPort = new RecordingQueueInsertPort();
    QueueApiHandler handler =
        new QueueApiHandler(
            new RecordingQueuePagePort(),
            new RecordingQueueMutationPort(),
            new RecordingQueueDownloadPort(),
            queueInsertPort,
            new FixedQueueSupportPort(true, List.of("COMPAT_1255", "COMPAT_1416"), "COMPAT_1255"),
            new RecordingQueueCompletionPort());

    handler.createLocalFileInsert(
        orderedParameters(
            Map.entry("sourcePath", List.of("/tmp/publisher/file.txt")),
            Map.entry("insertUri", List.of("CHK@")),
            Map.entry("identifier", List.of("publisher-file-1")),
            Map.entry("compatibilityMode", List.of("COMPAT_CURRENT"))));

    assertEquals("COMPAT_1255", queueInsertPort.lastLocalFileRequest.compatibilityMode());
  }

  @Test
  void createLocalFileInsert_whenCompatibilityModeSupportedByRuntime_expectPassedThrough() {
    RecordingQueueInsertPort queueInsertPort = new RecordingQueueInsertPort();
    QueueApiHandler handler =
        new QueueApiHandler(
            new RecordingQueuePagePort(),
            new RecordingQueueMutationPort(),
            new RecordingQueueDownloadPort(),
            queueInsertPort,
            new FixedQueueSupportPort(true, List.of("COMPAT_1255", "COMPAT_1416"), "COMPAT_1255"),
            new RecordingQueueCompletionPort());

    handler.createLocalFileInsert(
        orderedParameters(
            Map.entry("sourcePath", List.of("/tmp/publisher/file.txt")),
            Map.entry("insertUri", List.of("CHK@")),
            Map.entry("identifier", List.of("publisher-file-1")),
            Map.entry("compatibilityMode", List.of("COMPAT_1416"))));

    assertEquals("COMPAT_1416", queueInsertPort.lastLocalFileRequest.compatibilityMode());
  }

  @Test
  void createLocalFileInsert_whenCompatibilityModeUnsupported_expectBadRequest() {
    QueueApiHandler handler =
        new QueueApiHandler(
            new RecordingQueuePagePort(),
            new RecordingQueueMutationPort(),
            new RecordingQueueDownloadPort(),
            new RecordingQueueInsertPort(),
            new FixedQueueSupportPort(true),
            new RecordingQueueCompletionPort());
    Map<String, List<String>> parameters =
        orderedParameters(
            Map.entry("sourcePath", List.of("/tmp/publisher/file.txt")),
            Map.entry("insertUri", List.of("CHK@")),
            Map.entry("identifier", List.of("publisher-file-1")),
            Map.entry("compatibilityMode", List.of("COMPAT_TYPO")));

    PlatformApiException error =
        assertThrows(PlatformApiException.class, () -> handler.createLocalFileInsert(parameters));

    assertEquals(400, error.statusCode());
    assertEquals("invalid_query_parameter", error.errorCode());
    assertEquals(
        "Query parameter 'compatibilityMode' must be one of 'COMPAT_CURRENT',"
            + " 'COMPAT_DEFAULT', or one of the concrete modes: COMPAT_1468,"
            + " COMPAT_1250_EXACT, COMPAT_1250, COMPAT_1251, COMPAT_1255, COMPAT_1416.",
        error.getMessage());
  }

  @Test
  void createLocalFileInsert_whenRejected_expectDeterministicPlatformApiException() {
    RecordingQueueInsertPort queueInsertPort = new RecordingQueueInsertPort();
    queueInsertPort.rejectedException =
        new QueueInsertRejectedException(QueueInsertFailureReason.ACCESS_DENIED, "denied");
    QueueApiHandler handler =
        new QueueApiHandler(
            new RecordingQueuePagePort(),
            new RecordingQueueMutationPort(),
            new RecordingQueueDownloadPort(),
            queueInsertPort,
            new FixedQueueSupportPort(true),
            new RecordingQueueCompletionPort());
    Map<String, List<String>> parameters =
        orderedParameters(
            Map.entry("sourcePath", List.of("/tmp/publisher/file.txt")),
            Map.entry("insertUri", List.of("SSK@publisher-file")),
            Map.entry("identifier", List.of("publisher-file-1")),
            Map.entry("compatibilityMode", List.of("COMPAT_CURRENT")));

    PlatformApiException error =
        assertThrows(PlatformApiException.class, () -> handler.createLocalFileInsert(parameters));

    assertEquals(400, error.statusCode());
    assertEquals("queue_insert_rejected_access_denied", error.errorCode());
    assertEquals(
        "Local file insert rejected by the queue backend: ACCESS_DENIED.", error.getMessage());
  }

  @Test
  void createAppDocumentInsert_whenLiteralOrEmptyText_expectExactUtf8NewChkUpload()
      throws Exception {
    for (String text : List.of("", "Unicode 雪\r\n<script>alert(1)</script>\n\r")) {
      RecordingQueueInsertPort port = new RecordingQueueInsertPort();
      QueueApiHandler handler =
          new QueueApiHandler(
              new RecordingQueuePagePort(),
              new RecordingQueueMutationPort(),
              new RecordingQueueDownloadPort(),
              port,
              new FixedQueueSupportPort(true),
              new RecordingQueueCompletionPort());
      var parameters =
          orderedParameters(
              Map.entry("insertUri", List.of("CHK@")),
              Map.entry("identifier", List.of("literal-draft")),
              Map.entry("contentType", List.of("text/plain; charset=utf-8")),
              Map.entry("targetFilename", List.of("draft.txt")),
              Map.entry(
                  "documentBase64",
                  List.of(
                      Base64.getEncoder().encodeToString(text.getBytes(StandardCharsets.UTF_8)))));

      handler.createAppDocumentInsert("site-publisher", parameters);

      assertEquals("CHK@", port.lastBrowserUploadRequest.insertUri());
      assertEquals(
          "text/plain; charset=utf-8", port.lastBrowserUploadRequest.upload().contentType());
      assertEquals("draft.txt", port.lastBrowserUploadRequest.filenameForKey());
      try (var input = port.lastBrowserUploadRequest.upload().openStream()) {
        assertEquals(text, new String(input.readAllBytes(), StandardCharsets.UTF_8));
      }
      assertNull(port.lastLocalFileRequest);
    }
  }

  @Test
  void createAppDocumentInsert_whenEmptyJson_expectValidationFailure() {
    QueueApiHandler handler =
        new QueueApiHandler(
            new RecordingQueuePagePort(),
            new RecordingQueueMutationPort(),
            new RecordingQueueDownloadPort(),
            new RecordingQueueInsertPort(),
            new FixedQueueSupportPort(true),
            new RecordingQueueCompletionPort());
    Map<String, List<String>> parameters =
        orderedParameters(
            Map.entry("insertUri", List.of("CHK@")),
            Map.entry("identifier", List.of("literal-draft")),
            Map.entry("documentBase64", List.of("")));

    assertThrows(
        PlatformApiException.class,
        () -> handler.createAppDocumentInsert("site-publisher", parameters));
  }

  @Test
  void createAppDocumentInsert_whenRequested_expectBrowserUploadInsertAndRedactedResponse()
      throws Exception {
    RecordingQueueInsertPort queueInsertPort = new RecordingQueueInsertPort();
    QueueApiHandler handler =
        new QueueApiHandler(
            new RecordingQueuePagePort(),
            new RecordingQueueMutationPort(),
            new RecordingQueueDownloadPort(),
            queueInsertPort,
            new FixedQueueSupportPort(true),
            new RecordingQueueCompletionPort());
    String documentJson = "{\"schema\":\"crypta.profile.v1\",\"displayName\":\"Ada\"}";

    Map<String, Object> result =
        handler.createAppDocumentInsert(
            "profile-publisher",
            orderedParameters(
                Map.entry("insertUri", List.of("CHK@")),
                Map.entry("identifier", List.of("profile-publish-1")),
                Map.entry(
                    "documentBase64",
                    List.of(
                        Base64.getEncoder()
                            .encodeToString(documentJson.getBytes(StandardCharsets.UTF_8))))));

    assertEquals("create_app_document_insert", result.get("operation"));
    assertEquals("app-document", result.get("sourceType"));
    assertEquals("<redacted>", result.get("sourcePath"));
    assertEquals("<redacted>", result.get("insertUri"));
    assertEquals("profile-publish-1", result.get("identifier"));
    assertEquals("STARTED", result.get("outcome"));
    assertEquals("profile-publish-1", queueInsertPort.lastBrowserUploadRequest.identifier());
    assertEquals("CHK@", queueInsertPort.lastBrowserUploadRequest.insertUri());
    assertEquals(
        "application/vnd.crypta.profile+json",
        queueInsertPort.lastBrowserUploadRequest.upload().contentType());
    assertEquals("profile.json", queueInsertPort.lastBrowserUploadRequest.upload().filename());
    assertEquals("profile.json", queueInsertPort.lastBrowserUploadRequest.filenameForKey());
    assertEquals("COMPAT_1468", queueInsertPort.lastBrowserUploadRequest.compatibilityMode());
    try (var input = queueInsertPort.lastBrowserUploadRequest.upload().openStream()) {
      assertEquals(documentJson, new String(input.readAllBytes(), StandardCharsets.UTF_8));
    }
    assertEquals(
        documentJson.getBytes(StandardCharsets.UTF_8).length,
        queueInsertPort.lastBrowserUploadRequest.upload().size());
    assertNull(queueInsertPort.lastLocalFileRequest);
  }

  @Test
  void createAppDocumentInsert_whenInsertUriHasDocName_expectFilenameForKeySuppressed() {
    RecordingQueueInsertPort queueInsertPort = new RecordingQueueInsertPort();
    QueueApiHandler handler =
        new QueueApiHandler(
            new RecordingQueuePagePort(),
            new RecordingQueueMutationPort(),
            new RecordingQueueDownloadPort(),
            queueInsertPort,
            new FixedQueueSupportPort(true),
            new RecordingQueueCompletionPort());
    String documentJson = "{\"schema\":\"crypta.profile.v1\",\"displayName\":\"Ada\"}";

    handler.createAppDocumentInsert(
        "profile-publisher",
        orderedParameters(
            Map.entry("insertUri", List.of("KSK@profile-name")),
            Map.entry("identifier", List.of("profile-publish-1")),
            Map.entry(
                "documentBase64",
                List.of(
                    Base64.getEncoder()
                        .encodeToString(documentJson.getBytes(StandardCharsets.UTF_8))))));

    assertEquals("profile.json", queueInsertPort.lastBrowserUploadRequest.upload().filename());
    assertNull(queueInsertPort.lastBrowserUploadRequest.filenameForKey());
  }

  @Test
  void createAppDocumentInsert_whenTargetFilenameNeedsTrimming_expectSanitizedQueueKeyHint() {
    RecordingQueueInsertPort queueInsertPort = new RecordingQueueInsertPort();
    QueueApiHandler handler =
        new QueueApiHandler(
            new RecordingQueuePagePort(),
            new RecordingQueueMutationPort(),
            new RecordingQueueDownloadPort(),
            queueInsertPort,
            new FixedQueueSupportPort(true),
            new RecordingQueueCompletionPort());

    handler.createAppDocumentInsert(
        "profile-publisher",
        orderedParameters(
            Map.entry("insertUri", List.of("CHK@")),
            Map.entry("identifier", List.of("profile-publish-1")),
            Map.entry("targetFilename", List.of("\nprofile.json  ")),
            Map.entry(
                "documentBase64",
                List.of(
                    Base64.getEncoder()
                        .encodeToString(
                            "{\"schema\":\"crypta.profile.v1\"}"
                                .getBytes(StandardCharsets.UTF_8))))));

    assertEquals("profile.json", queueInsertPort.lastBrowserUploadRequest.upload().filename());
    assertEquals("profile.json", queueInsertPort.lastBrowserUploadRequest.filenameForKey());
  }

  @Test
  void createAppDocumentInsert_whenBase64Invalid_expectBadRequest() {
    QueueApiHandler handler =
        new QueueApiHandler(
            new RecordingQueuePagePort(),
            new RecordingQueueMutationPort(),
            new RecordingQueueDownloadPort(),
            new RecordingQueueInsertPort(),
            new FixedQueueSupportPort(true),
            new RecordingQueueCompletionPort());
    Map<String, List<String>> parameters =
        orderedParameters(
            Map.entry("insertUri", List.of("CHK@")),
            Map.entry("identifier", List.of("profile-publish-1")),
            Map.entry("documentBase64", List.of("%%%")));

    PlatformApiException error =
        assertThrows(
            PlatformApiException.class,
            () -> handler.createAppDocumentInsert("profile-publisher", parameters));

    assertEquals(400, error.statusCode());
    assertEquals("invalid_query_parameter", error.errorCode());
    assertEquals("Query parameter 'documentBase64' must be valid Base64.", error.getMessage());
  }

  @Test
  void createAppDocumentInsert_whenDocumentTooLarge_expectBadRequest() {
    QueueApiHandler handler =
        new QueueApiHandler(
            new RecordingQueuePagePort(),
            new RecordingQueueMutationPort(),
            new RecordingQueueDownloadPort(),
            new RecordingQueueInsertPort(),
            new FixedQueueSupportPort(true),
            new RecordingQueueCompletionPort());
    byte[] oversized = new byte[(64 * 1024) + 1];
    String documentBase64 = Base64.getEncoder().encodeToString(oversized);
    Map<String, List<String>> parameters =
        orderedParameters(
            Map.entry("insertUri", List.of("CHK@")),
            Map.entry("identifier", List.of("profile-publish-1")),
            Map.entry("documentBase64", List.of(documentBase64)));

    PlatformApiException error =
        assertThrows(
            PlatformApiException.class,
            () -> handler.createAppDocumentInsert("profile-publisher", parameters));

    assertEquals(400, error.statusCode());
    assertEquals("invalid_query_parameter", error.errorCode());
    assertEquals("Query parameter 'documentBase64' decodes to too many bytes.", error.getMessage());
  }

  @Test
  void createAppDocumentInsert_whenJsonInvalid_expectBadRequest() {
    QueueApiHandler handler =
        new QueueApiHandler(
            new RecordingQueuePagePort(),
            new RecordingQueueMutationPort(),
            new RecordingQueueDownloadPort(),
            new RecordingQueueInsertPort(),
            new FixedQueueSupportPort(true),
            new RecordingQueueCompletionPort());
    String documentBase64 =
        Base64.getEncoder().encodeToString("{".getBytes(StandardCharsets.UTF_8));
    Map<String, List<String>> parameters =
        orderedParameters(
            Map.entry("insertUri", List.of("CHK@")),
            Map.entry("identifier", List.of("profile-publish-1")),
            Map.entry("documentBase64", List.of(documentBase64)));

    PlatformApiException error =
        assertThrows(
            PlatformApiException.class,
            () -> handler.createAppDocumentInsert("profile-publisher", parameters));

    assertEquals(400, error.statusCode());
    assertEquals("invalid_query_parameter", error.errorCode());
    assertEquals(
        "Query parameter 'documentBase64' must decode to valid JSON for JSON content types.",
        error.getMessage());
  }

  @Test
  void createAppDocumentInsert_whenJsonNumberUsesNonAsciiDigit_expectBadRequest() {
    QueueApiHandler handler =
        new QueueApiHandler(
            new RecordingQueuePagePort(),
            new RecordingQueueMutationPort(),
            new RecordingQueueDownloadPort(),
            new RecordingQueueInsertPort(),
            new FixedQueueSupportPort(true),
            new RecordingQueueCompletionPort());
    String nonAsciiDigitJson = "١";
    String documentBase64 =
        Base64.getEncoder().encodeToString(nonAsciiDigitJson.getBytes(StandardCharsets.UTF_8));
    Map<String, List<String>> parameters =
        orderedParameters(
            Map.entry("insertUri", List.of("CHK@")),
            Map.entry("identifier", List.of("profile-publish-1")),
            Map.entry("documentBase64", List.of(documentBase64)));

    PlatformApiException error =
        assertThrows(
            PlatformApiException.class,
            () -> handler.createAppDocumentInsert("profile-publisher", parameters));

    assertEquals(400, error.statusCode());
    assertEquals("invalid_query_parameter", error.errorCode());
    assertEquals(
        "Query parameter 'documentBase64' must decode to valid JSON for JSON content types.",
        error.getMessage());
  }

  @Test
  void createAppDocumentInsert_whenJsonNestingTooDeep_expectBadRequest() {
    QueueApiHandler handler =
        new QueueApiHandler(
            new RecordingQueuePagePort(),
            new RecordingQueueMutationPort(),
            new RecordingQueueDownloadPort(),
            new RecordingQueueInsertPort(),
            new FixedQueueSupportPort(true),
            new RecordingQueueCompletionPort());
    String deeplyNestedJson = "[".repeat(80) + "0" + "]".repeat(80);
    String documentBase64 =
        Base64.getEncoder().encodeToString(deeplyNestedJson.getBytes(StandardCharsets.UTF_8));
    Map<String, List<String>> parameters =
        orderedParameters(
            Map.entry("insertUri", List.of("CHK@")),
            Map.entry("identifier", List.of("profile-publish-1")),
            Map.entry("documentBase64", List.of(documentBase64)));

    PlatformApiException error =
        assertThrows(
            PlatformApiException.class,
            () -> handler.createAppDocumentInsert("profile-publisher", parameters));

    assertEquals(400, error.statusCode());
    assertEquals("invalid_query_parameter", error.errorCode());
    assertEquals(
        "Query parameter 'documentBase64' must decode to valid JSON for JSON content types.",
        error.getMessage());
  }

  @Test
  void createAppDocumentInsert_whenTargetFilenameIsPath_expectBadRequest() {
    QueueApiHandler handler =
        new QueueApiHandler(
            new RecordingQueuePagePort(),
            new RecordingQueueMutationPort(),
            new RecordingQueueDownloadPort(),
            new RecordingQueueInsertPort(),
            new FixedQueueSupportPort(true),
            new RecordingQueueCompletionPort());
    String documentBase64 =
        Base64.getEncoder().encodeToString("{}".getBytes(StandardCharsets.UTF_8));
    Map<String, List<String>> parameters =
        orderedParameters(
            Map.entry("insertUri", List.of("CHK@")),
            Map.entry("identifier", List.of("profile-publish-1")),
            Map.entry("targetFilename", List.of("../profile.json")),
            Map.entry("documentBase64", List.of(documentBase64)));

    PlatformApiException error =
        assertThrows(
            PlatformApiException.class,
            () -> handler.createAppDocumentInsert("profile-publisher", parameters));

    assertEquals(400, error.statusCode());
    assertEquals("invalid_query_parameter", error.errorCode());
    assertEquals(
        "Query parameter 'targetFilename' must be a filename, not a path.", error.getMessage());
  }

  @SafeVarargs
  private static Map<String, List<String>> orderedParameters(
      Map.Entry<String, List<String>>... entries) {
    LinkedHashMap<String, List<String>> parameters = LinkedHashMap.newLinkedHashMap(entries.length);
    for (Map.Entry<String, List<String>> entry : entries) {
      parameters.put(entry.getKey(), entry.getValue());
    }
    return parameters;
  }

  @Test
  void mailInsertionAcceptsOnlyBoundedNetworkEnvelopesBeforeStaging() throws Exception {
    RecordingQueueInsertPort port = new RecordingQueueInsertPort();
    QueueApiHandler handler =
        new QueueApiHandler(
            new RecordingQueuePagePort(),
            new RecordingQueueMutationPort(),
            new RecordingQueueDownloadPort(),
            port,
            new FixedQueueSupportPort(true),
            new RecordingQueueCompletionPort());
    byte[] key = MailHpke.publicKey(MailHpke.generatePrivateKey());
    byte[] storage =
        MailHpke.seal("storage", MailWire.fingerprint("storage", key), key, new byte[0]);
    var parameters =
        orderedParameters(
            Map.entry("insertUri", List.of("CHK@")),
            Map.entry(
                "identifier",
                List.of("app-document-mail-prototype-0123456789abcdef0123456789abcdef")),
            Map.entry("contentType", List.of("application/vnd.crypta.mail+json")));
    for (byte[] invalid :
        List.of(
            storage,
            "public synthetic plaintext".getBytes(StandardCharsets.UTF_8),
            "{}".getBytes(StandardCharsets.UTF_8))) {
      parameters.put("documentBase64", List.of(MailWire.base64(invalid)));
      var failure =
          assertThrows(
              PlatformApiException.class,
              () -> handler.createAppDocumentInsert("mail-prototype", parameters));
      assertEquals("mail_envelope_rejected", failure.errorCode());
      assertNull(port.lastBrowserUploadRequest);
    }
    byte[] network =
        MailHpke.seal("network", MailWire.fingerprint("recipient", key), key, new byte[0]);
    parameters.put("documentBase64", List.of(MailWire.base64(network)));

    handler.createAppDocumentInsert("mail-prototype", parameters);

    try (var input = port.lastBrowserUploadRequest.upload().openStream()) {
      org.junit.jupiter.api.Assertions.assertArrayEquals(network, input.readAllBytes());
    }
  }

  @Test
  void existingUnrelatedAppDocumentIdentifierRemainsAccepted() {
    RecordingQueueInsertPort port = new RecordingQueueInsertPort();
    QueueApiHandler handler =
        new QueueApiHandler(
            new RecordingQueuePagePort(),
            new RecordingQueueMutationPort(),
            new RecordingQueueDownloadPort(),
            port,
            new FixedQueueSupportPort(true),
            new RecordingQueueCompletionPort());
    var parameters =
        orderedParameters(
            Map.entry("insertUri", List.of("CHK@")),
            Map.entry("identifier", List.of("app-document-draft-1")),
            Map.entry("contentType", List.of("text/plain")),
            Map.entry("documentBase64", List.of("cHVibGljIHN5bnRoZXRpYw==")));

    handler.createAppDocumentInsert("unrelated-app", parameters);

    assertEquals("app-document-draft-1", port.lastBrowserUploadRequest.identifier());
  }

  @Test
  void unrelatedAppCannotClaimReservedMailOperationIdentifier() {
    RecordingQueueInsertPort port = new RecordingQueueInsertPort();
    QueueApiHandler handler =
        new QueueApiHandler(
            new RecordingQueuePagePort(),
            new RecordingQueueMutationPort(),
            new RecordingQueueDownloadPort(),
            port,
            new FixedQueueSupportPort(true),
            new RecordingQueueCompletionPort());
    var parameters =
        orderedParameters(
            Map.entry("insertUri", List.of("CHK@")),
            Map.entry(
                "identifier",
                List.of("app-document-mail-prototype-0123456789abcdef0123456789abcdef")),
            Map.entry("contentType", List.of("text/plain")),
            Map.entry("documentBase64", List.of("cHVibGljIHN5bnRoZXRpYw==")));

    var failure =
        assertThrows(
            PlatformApiException.class,
            () -> handler.createAppDocumentInsert("unrelated-app", parameters));

    assertEquals("app_document_identifier_denied", failure.errorCode());
    assertNull(port.lastBrowserUploadRequest);
  }

  @Test
  void appDocumentStatusChecksNamespaceAndReturnsTypedCompletion() {
    RecordingQueuePagePort page = new RecordingQueuePagePort();
    QueueApiHandler handler =
        new QueueApiHandler(
            page,
            new RecordingQueueMutationPort(),
            new RecordingQueueDownloadPort(),
            new RecordingQueueInsertPort(),
            new FixedQueueSupportPort(true),
            new RecordingQueueCompletionPort());
    String identifier = "app-document-mail-prototype-0123456789abcdef0123456789abcdef";
    var scopedParameters = Map.of("identifier", List.of(identifier));
    var unscopedParameters = Map.of("identifier", List.of("unscoped"));
    var status = handler.appDocumentStatus("mail-prototype", scopedParameters);
    assertEquals("inserted", status.get("state"));
    assertEquals("CHK@public-synthetic", status.get("reference"));
    assertThrows(
        PlatformApiException.class,
        () -> handler.appDocumentStatus("unrelated-app", scopedParameters));
    assertThrows(
        PlatformApiException.class,
        () -> handler.appDocumentStatus("mail-prototype", unscopedParameters));
  }

  private static final class RecordingQueuePagePort implements QueuePagePort {
    private QueuePageSnapshot pageSnapshot = new QueuePageSnapshot("Queue", "<div></div>");
    private QueuePageRequest lastPageRequest;
    private int countPageRequests;

    @Override
    public network.crypta.runtime.spi.QueueInsertStatus readInsertStatus(String identifier) {
      return new network.crypta.runtime.spi.QueueInsertStatus("inserted", "CHK@public-synthetic");
    }

    @Override
    public QueuePageSnapshot renderPage(QueuePageRequest request) {
      lastPageRequest = request;
      return pageSnapshot;
    }

    @Override
    public QueuePageSnapshot renderCountPage(boolean uploads) {
      countPageRequests++;
      return new QueuePageSnapshot("Count", "<div>count</div>");
    }

    @Override
    public String renderKeyList(boolean uploads) {
      return "CHK@alpha\nCHK@beta\n";
    }
  }

  private static final class RecordingQueueMutationPort implements QueueMutationPort {
    private List<String> lastIdentifiers = List.of();
    private boolean lastDisableFilterData;
    private short lastPriorityClass;

    @Override
    public void removeRequests(List<String> identifiers) {
      lastIdentifiers = identifiers;
    }

    @Override
    public void restartRequests(List<String> identifiers, boolean disableFilterData) {
      lastIdentifiers = identifiers;
      lastDisableFilterData = disableFilterData;
    }

    @Override
    public void changePriority(List<String> identifiers, short newPriorityClass) {
      lastIdentifiers = identifiers;
      lastPriorityClass = newPriorityClass;
    }

    @Override
    public void removeFinishedUploads() {
      throw new UnsupportedOperationException(
          "Queue cleanup is not exercised by this test double.");
    }

    @Override
    public void removeFinishedDownloads() {
      throw new UnsupportedOperationException(
          "Queue cleanup is not exercised by this test double.");
    }
  }

  private static final class RecordingQueueDownloadPort implements QueueDownloadPort {
    private QueueDownloadRequest lastRequest;

    @Override
    public boolean isDiskDownloadDisabled() {
      return false;
    }

    @Override
    public void enqueueDownload(QueueDownloadRequest request) {
      lastRequest = request;
    }
  }

  private static final class RecordingQueueInsertPort implements QueueInsertPort {
    private QueueBrowserUploadInsertRequest lastBrowserUploadRequest;
    private QueueLocalFileInsertRequest lastLocalFileRequest;
    private QueueLocalDirectoryInsertRequest lastLocalDirectoryRequest;
    private QueueInsertOutcome nextOutcome = QueueInsertOutcome.STARTED;
    private QueueInsertRejectedException rejectedException;

    @Override
    public QueueInsertOutcome enqueueBrowserUploadInsert(QueueBrowserUploadInsertRequest request)
        throws QueueInsertRejectedException {
      lastBrowserUploadRequest = request;
      if (rejectedException != null) {
        throw rejectedException;
      }
      return nextOutcome;
    }

    @Override
    public QueueInsertOutcome enqueueLocalFileInsert(QueueLocalFileInsertRequest request)
        throws QueueInsertRejectedException {
      lastLocalFileRequest = request;
      if (rejectedException != null) {
        throw rejectedException;
      }
      return nextOutcome;
    }

    @Override
    public QueueInsertOutcome enqueueLocalDirectoryInsert(QueueLocalDirectoryInsertRequest request)
        throws QueueInsertRejectedException {
      lastLocalDirectoryRequest = request;
      if (rejectedException != null) {
        throw rejectedException;
      }
      return nextOutcome;
    }
  }

  @SuppressWarnings("ClassCanBeRecord")
  private static final class FixedQueueSupportPort implements QueueSupportPort {
    private static final List<String> DEFAULT_SUPPORTED_INSERT_COMPATIBILITY_MODES =
        List.of(
            "COMPAT_1468",
            "COMPAT_1250_EXACT",
            "COMPAT_1250",
            "COMPAT_1251",
            "COMPAT_1255",
            "COMPAT_1416");

    private final boolean enabled;
    private final List<String> supportedInsertCompatibilityModes;
    private final String defaultInsertCompatibilityMode;

    private FixedQueueSupportPort(boolean enabled) {
      this(enabled, DEFAULT_SUPPORTED_INSERT_COMPATIBILITY_MODES, "COMPAT_1468");
    }

    private FixedQueueSupportPort(
        boolean enabled,
        List<String> supportedInsertCompatibilityModes,
        String defaultInsertCompatibilityMode) {
      this.enabled = enabled;
      this.supportedInsertCompatibilityModes = List.copyOf(supportedInsertCompatibilityModes);
      this.defaultInsertCompatibilityMode = defaultInsertCompatibilityMode;
    }

    @Override
    public boolean isQueueBackendEnabled() {
      return enabled;
    }

    @Override
    public List<String> supportedInsertCompatibilityModes() {
      return supportedInsertCompatibilityModes;
    }

    @Override
    public String defaultInsertCompatibilityMode() {
      return defaultInsertCompatibilityMode;
    }

    @Override
    public QueuePersistenceStatusSnapshot persistenceStatus() {
      return new QueuePersistenceStatusSnapshot(false, false, null, null);
    }

    @Override
    public void beginPanic() {
      throw new UnsupportedOperationException("Panic flows are not exercised by this test double.");
    }

    @Override
    public void finishPanic() {
      throw new UnsupportedOperationException("Panic flows are not exercised by this test double.");
    }
  }

  private static final class RecordingQueueCompletionPort implements QueueCompletionPort {
    private final List<Boolean> startedSides = new java.util.ArrayList<>();

    @Override
    public void ensureTrackingStarted(boolean uploads) {
      startedSides.add(uploads);
    }
  }
}
