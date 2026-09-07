package network.crypta.runtime.admin;

import java.io.File;
import java.lang.reflect.Field;
import java.net.MalformedURLException;
import network.crypta.client.async.ClientRequestScheduler;
import network.crypta.keys.FreenetURI;
import network.crypta.node.DarknetPeerNode;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.RequestStarterGroup;
import network.crypta.runtime.admin.queue.page.QueuePageBackend;
import network.crypta.runtime.admin.queue.page.QueuePageDownloadView;
import network.crypta.runtime.admin.queue.page.QueuePageRequestView;
import network.crypta.runtime.admin.queue.page.QueuePageUploadFileView;
import network.crypta.runtime.admin.queue.page.QueuePageUploadView;
import network.crypta.runtime.spi.QueuePageRequest;
import network.crypta.runtime.spi.QueuePageSnapshot;
import network.crypta.runtime.spi.RequestQueueUnavailableException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Answers;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@SuppressWarnings("java:S100")
class LegacyQueuePagePortTest {

  @Mock private NodeClientCore core;
  @Mock private QueuePageBackend queueBackend;

  @Mock(answer = Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Mock(answer = Answers.RETURNS_DEEP_STUBS)
  private RequestStarterGroup requestStarters;

  @Mock private ClientRequestScheduler chkFetchSchedulerBulk;
  @Mock private ClientRequestScheduler chkFetchSchedulerRT;

  private LegacyQueuePagePort port;

  @BeforeEach
  void setUp() throws Exception {
    when(core.getNode()).thenReturn(node);
    when(core.getRequestStarters()).thenReturn(requestStarters);
    when(node.network().darknetConnections()).thenReturn(new DarknetPeerNode[0]);
    setRequestStarterField("chkFetchSchedulerBulk", chkFetchSchedulerBulk);
    setRequestStarterField("chkFetchSchedulerRT", chkFetchSchedulerRT);
    port = new LegacyQueuePagePort(core, queueBackend);
  }

  @Test
  void renderPage_whenUploadQueueHasCompletedRequest_returnsDetachedHtmlSnapshot()
      throws Exception {
    QueuePageUploadFileView upload = org.mockito.Mockito.mock(QueuePageUploadFileView.class);
    when(upload.hasSucceeded()).thenReturn(true);
    when(upload.getIdentifier()).thenReturn("upload-1");
    when(upload.getPriority()).thenReturn((short) 2);
    when(upload.getOrigFilename()).thenReturn(new File("hello.txt"));
    when(upload.getPreferredFilenameSafe()).thenReturn("hello.txt");
    when(upload.getDataSize()).thenReturn(123L);
    when(upload.getFinalUri()).thenReturn(sampleUri());
    when(upload.getUri()).thenReturn(sampleUri());
    when(queueBackend.getGlobalRequests()).thenReturn(new QueuePageRequestView[] {upload});

    QueuePageSnapshot snapshot = port.renderPage(new QueuePageRequest(true, false, null, false));

    assertTrue(snapshot.pageTitle().contains("Uploads"));
    assertTrue(snapshot.contentHtmlTemplate().contains("upload-1"));
    assertTrue(snapshot.contentHtmlTemplate().contains("hello.txt"));
    assertTrue(snapshot.contentHtmlTemplate().contains("<!--CRYPTA_QUEUE_FORM_PASSWORD-->"));
  }

  @Test
  void renderCountPage_whenDownloadsRequested_returnsCountHtml() {
    when(chkFetchSchedulerBulk.countPersistentWaitingKeys()).thenReturn(2L);
    when(chkFetchSchedulerRT.countPersistentWaitingKeys()).thenReturn(3L);
    when(chkFetchSchedulerBulk.countQueuedRequests()).thenReturn(4L);
    when(chkFetchSchedulerRT.countQueuedRequests()).thenReturn(5L);

    QueuePageSnapshot snapshot = port.renderCountPage(false);

    assertTrue(snapshot.contentHtmlTemplate().contains("Total awaiting CHKs: 5"));
    assertTrue(snapshot.contentHtmlTemplate().contains("Total queued CHK requests: 9"));
  }

  @Test
  void renderPage_whenRequestIsNull_throwsNullPointerException() {
    assertThrows(NullPointerException.class, () -> port.renderPage(null));
  }

  @Test
  void renderPage_whenQueueBackendReturnsNoRequests_returnsEmptyDownloadsSnapshot()
      throws Exception {
    when(queueBackend.getGlobalRequests()).thenReturn(new QueuePageRequestView[0]);
    when(core.getDownloadsDir()).thenReturn(new File("downloads"));
    when(core.allowDownloadTo(any(File.class))).thenReturn(true);

    QueuePageSnapshot snapshot = port.renderPage(new QueuePageRequest(false, false, null, false));

    assertTrue(snapshot.pageTitle().contains("Downloads"));
    assertTrue(snapshot.contentHtmlTemplate().contains("queue-empty"));
    assertTrue(snapshot.contentHtmlTemplate().contains("queueDownloadForm"));
    assertTrue(snapshot.contentHtmlTemplate().contains("<!--CRYPTA_ALERT_SUMMARY-->"));
  }

  @Test
  void renderKeyList_whenDownloadsRequested_returnsOnlyDownloadUris() throws Exception {
    QueuePageDownloadView download = org.mockito.Mockito.mock(QueuePageDownloadView.class);
    QueuePageUploadView upload = org.mockito.Mockito.mock(QueuePageUploadView.class);
    FreenetURI downloadUri = sampleUri();
    FreenetURI uploadUri = sampleUri();
    when(download.getUri()).thenReturn(downloadUri);
    when(upload.getFinalUri()).thenReturn(uploadUri);
    when(queueBackend.getGlobalRequests())
        .thenReturn(new QueuePageRequestView[] {download, upload});

    String keyList = port.renderKeyList(false);

    assertEquals(downloadUri + "\n", keyList);
  }

  @Test
  void renderKeyList_whenUploadsRequested_skipsNullUploadUris() throws Exception {
    QueuePageDownloadView download = org.mockito.Mockito.mock(QueuePageDownloadView.class);
    QueuePageUploadView uploadWithUri = org.mockito.Mockito.mock(QueuePageUploadView.class);
    QueuePageUploadView uploadWithoutUri = org.mockito.Mockito.mock(QueuePageUploadView.class);
    FreenetURI uploadUri = sampleUri();
    when(download.getUri()).thenReturn(sampleUri());
    when(uploadWithUri.getFinalUri()).thenReturn(uploadUri);
    when(uploadWithoutUri.getFinalUri()).thenReturn(null);
    when(queueBackend.getGlobalRequests())
        .thenReturn(new QueuePageRequestView[] {download, uploadWithUri, uploadWithoutUri});

    String keyList = port.renderKeyList(true);

    assertEquals(uploadUri + "\n", keyList);
  }

  @Test
  void renderPage_whenQueueBackendUnavailable_propagatesRequestQueueUnavailableException()
      throws Exception {
    IllegalStateException cause = new IllegalStateException("queue disabled");
    RequestQueueUnavailableException failure =
        new RequestQueueUnavailableException("Persistent request queue unavailable", cause);
    when(queueBackend.getGlobalRequests()).thenThrow(failure);

    RequestQueueUnavailableException thrown =
        assertThrows(
            RequestQueueUnavailableException.class,
            () -> port.renderPage(new QueuePageRequest(false, false, null, false)));

    assertSame(cause, thrown.getCause());
  }

  @Test
  void queueBackendLookup_whenPortConstructed_defersBackendReadUntilMethodCall() throws Exception {
    verifyNoInteractions(queueBackend);
    when(queueBackend.getGlobalRequests()).thenReturn(new QueuePageRequestView[0]);

    port.renderKeyList(false);

    verify(queueBackend).getGlobalRequests();
  }

  @Test
  void typedInsertStatusUsesExactUploadAndOnlySuccessfulFinalChk() throws Exception {
    QueuePageUploadFileView upload = org.mockito.Mockito.mock(QueuePageUploadFileView.class);
    when(upload.getIdentifier()).thenReturn("owned-operation");
    when(queueBackend.getGlobalRequests()).thenReturn(new QueuePageRequestView[] {upload});
    assertEquals("missing", port.readInsertStatus("different-operation").state());
    assertEquals("pending", port.readInsertStatus("owned-operation").state());
    when(upload.hasFinished()).thenReturn(true);
    assertEquals("failed", port.readInsertStatus("owned-operation").state());
    when(upload.hasSucceeded()).thenReturn(true);
    when(upload.getFinalUri()).thenReturn(sampleUri());
    var status = port.readInsertStatus("owned-operation");
    assertEquals("inserted", status.state());
    assertEquals(sampleUri().toString(), status.reference());
    assertTrue(!status.toString().contains(sampleUri().toString()));
  }

  private FreenetURI sampleUri() {
    try {
      return new FreenetURI(
          "CHK@DTCDUmnkKFlrJi9UlDDVqXlktsIXvAJ~ZTseyx5cAZs,PmA2rLgWZKVyMXxSn-ZihSskPYDTY19uhrMwqDV-~Sk,AAICAAI/index_d51.xml");
    } catch (MalformedURLException e) {
      throw new AssertionError(e);
    }
  }

  private void setRequestStarterField(String fieldName, Object value) throws Exception {
    Field field = RequestStarterGroup.class.getField(fieldName);
    field.setAccessible(true);
    field.set(requestStarters, value);
  }
}
