package network.crypta.platform.api.mail;

import java.util.List;
import java.util.Optional;
import network.crypta.platform.apphost.AppHost;
import network.crypta.platform.apphost.AppTokenPrincipal;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class MailWorkerBrokerTest {
  @Test
  void replyIsBoundToLaunchAndConsumedOnce() {
    AppHost host = mock(AppHost.class);
    when(host.currentLaunch("mail-prototype"))
        .thenReturn(
            Optional.of(new AppTokenPrincipal("mail-prototype", List.of(), "launch-one", "1")));
    MailWorkerBroker broker = new MailWorkerBroker(host);
    String request = broker.submit("status", "e30=");
    assertEquals(request, broker.poll("launch-one").orElseThrow().requestId());
    assertThrows(IllegalStateException.class, () -> broker.reply("other", request, "e30="));
    broker.reply("launch-one", request, "e30=");
    assertThrows(IllegalStateException.class, () -> broker.reply("launch-one", request, "e30="));
    assertEquals("e30=", broker.result(request).orElseThrow());
    assertThrows(IllegalStateException.class, () -> broker.result(request));
  }

  @Test
  void replacementAndStopDiscardOldFrames() {
    AppHost host = mock(AppHost.class);
    when(host.currentLaunch("mail-prototype"))
        .thenReturn(Optional.of(new AppTokenPrincipal("mail-prototype", List.of(), "old", "1")));
    MailWorkerBroker broker = new MailWorkerBroker(host);
    String request = broker.submit("status", "");
    when(host.currentLaunch("mail-prototype"))
        .thenReturn(Optional.of(new AppTokenPrincipal("mail-prototype", List.of(), "new", "2")));
    assertTrue(broker.poll("new").isEmpty());
    assertThrows(IllegalStateException.class, () -> broker.reply("old", request, ""));
    assertThrows(IllegalStateException.class, () -> broker.result(request));
    when(host.currentLaunch("mail-prototype")).thenReturn(Optional.empty());
    assertThrows(IllegalStateException.class, () -> broker.submit("status", ""));
  }

  @Test
  void deadlineDiscardsReplyAndFreesCapacity() {
    AppHost host = mock(AppHost.class);
    when(host.currentLaunch("mail-prototype"))
        .thenReturn(Optional.of(new AppTokenPrincipal("mail-prototype", List.of(), "launch", "1")));
    java.time.Clock clock = mock(java.time.Clock.class);
    when(clock.millis()).thenReturn(1000L);
    MailWorkerBroker broker = new MailWorkerBroker(host, clock);
    String request = broker.submit("status", "");
    broker.poll("launch");
    when(clock.millis()).thenReturn(31000L);
    assertThrows(IllegalStateException.class, () -> broker.reply("launch", request, ""));
    assertTrue(broker.poll("launch").isEmpty());
    assertNotNull(broker.submit("status", ""));
  }

  @Test
  void closedCommandsCanonicalFramesAndBackpressureAreEnforced() {
    AppHost host = mock(AppHost.class);
    when(host.currentLaunch("mail-prototype"))
        .thenReturn(Optional.of(new AppTokenPrincipal("mail-prototype", List.of(), "launch", "1")));
    MailWorkerBroker broker = new MailWorkerBroker(host);
    assertThrows(IllegalStateException.class, () -> broker.submit("http://127.0.0.1", ""));
    assertThrows(IllegalStateException.class, () -> broker.submit("status", "e30"));
    assertThrows(IllegalStateException.class, () -> broker.submit("status", "A".repeat(393217)));
    for (int count = 0; count < 4; count++) broker.submit("status", "");
    assertThrows(IllegalStateException.class, () -> broker.submit("status", ""));
    assertEquals("MailWorkerFrame[redacted]", broker.poll("launch").orElseThrow().toString());
  }
}
