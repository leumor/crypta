package network.crypta.runtime.core;

import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import network.crypta.client.FetchContext;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientGetter;
import network.crypta.keys.FreenetURI;
import network.crypta.node.NodeClientCore;
import network.crypta.node.RequestClient;
import network.crypta.runtime.spi.BoundedContentFetchRequest;
import network.crypta.runtime.spi.ContentFetchException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class LegacyContentFetchObservationTest {
  @Test
  void invalidNativeFetchReleasesActivityWithoutCallingCore() {
    NodeClientCore core = mock(NodeClientCore.class);
    LegacyContentFetchPort port = new LegacyContentFetchPort(core);
    var request = new BoundedContentFetchRequest("invalid-key", 32, Duration.ofSeconds(1), "test");
    assertThrows(ContentFetchException.class, () -> port.fetchContent(request));
    var result = port.observation();
    assertEquals(1, result.startedOperations());
    assertEquals(1, result.failedOperations());
    assertEquals(0, result.inFlightOperations());
    verifyNoInteractions(core);
  }

  @Test
  void interruptCancelsNativeGetterAndReleasesObservedActivity() throws Exception {
    NodeClientCore core = mock(NodeClientCore.class);
    HighLevelSimpleClient client =
        mock(HighLevelSimpleClient.class, withSettings().extraInterfaces(RequestClient.class));
    ClientGetter getter = mock(ClientGetter.class);
    ClientContext context = mock(ClientContext.class);
    FetchContext fetchContext = mock(FetchContext.class);
    when(core.getClientContext()).thenReturn(context);
    when(core.makeClient(anyShort(), eq(false), eq(false))).thenReturn(client);
    when(client.getFetchContext()).thenReturn(fetchContext);
    CountDownLatch started = new CountDownLatch(1);
    when(client.fetch(any(FreenetURI.class), anyLong(), any(), any(), anyShort()))
        .thenAnswer(
            _ -> {
              started.countDown();
              return getter;
            });
    LegacyContentFetchPort port = new LegacyContentFetchPort(core);
    var request =
        new BoundedContentFetchRequest(
            FreenetURI.EMPTY_CHK_URI.toString(), 32, Duration.ofSeconds(30), "test");
    AtomicReference<Throwable> outcome = new AtomicReference<>();
    Thread worker =
        Thread.ofPlatform()
            .unstarted(
                () -> {
                  try {
                    port.fetchContent(request);
                  } catch (Throwable failure) {
                    outcome.set(failure);
                  }
                });
    worker.start();
    try {
      assertTrue(started.await(5, TimeUnit.SECONDS));
      assertEquals(1, port.observation().inFlightOperations());
      worker.interrupt();
      worker.join(5000);
      assertFalse(worker.isAlive());
      assertInstanceOf(ContentFetchException.class, outcome.get());
      assertEquals(0, port.observation().inFlightOperations());
      assertEquals(1, port.observation().failedOperations());
      verify(getter).cancel(context);
    } finally {
      worker.interrupt();
      worker.join(5000);
    }
  }
}
