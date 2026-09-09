package network.crypta.apps.mail;

import com.sun.net.httpserver.HttpServer;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Real loopback HTTP regressions for response deadlines, cancellation and bounded accumulation. */
class MailPlatformClientTest {
  @Test
  void stalledBodyTimesOutAndNextRequestStillCompletes() throws Exception {
    var headersSent = new CountDownLatch(1);
    var releaseServer = new CountDownLatch(1);
    HttpServer server =
        HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
    try (var serverTasks = Executors.newVirtualThreadPerTaskExecutor();
        var worker = Executors.newSingleThreadExecutor()) {
      server.setExecutor(serverTasks);
      server.createContext(
          "/api/v1/stall",
          exchange -> {
            try (exchange) {
              exchange.sendResponseHeaders(200, 100);
              exchange.getResponseBody().write('{');
              exchange.getResponseBody().flush();
              headersSent.countDown();
              try {
                assertTrue(releaseServer.await(10, TimeUnit.SECONDS));
              } catch (InterruptedException _) {
                Thread.currentThread().interrupt();
              }
            }
          });
      server.createContext(
          "/api/v1/ready",
          exchange -> {
            try (exchange) {
              byte[] body = "{\"status\":\"ready\"}".getBytes(StandardCharsets.UTF_8);
              exchange.sendResponseHeaders(200, body.length);
              exchange.getResponseBody().write(body);
            }
          });
      server.start();
      var client =
          new MailPlatformClient(endpoint(server), "synthetic-token", Duration.ofSeconds(1));
      Map<String, String> empty = Map.of();
      try {
        var stalled =
            worker.submit(
                () ->
                    assertThrows(MailFailure.class, () -> client.request("GET", "/stall", empty)));
        assertTrue(headersSent.await(5, TimeUnit.SECONDS));
        assertEquals("network-failed", stalled.get(5, TimeUnit.SECONDS).getMessage());
        assertEquals(1, releaseServer.getCount(), "Server must still be withholding the body.");
        var next = worker.submit(() -> client.request("GET", "/ready", Map.of()));
        assertEquals("ready", next.get(5, TimeUnit.SECONDS).get("status"));
      } finally {
        releaseServer.countDown();
        server.stop(0);
      }
    }
  }

  @Test
  void responseByteCapAppliesToChunkedBodiesAndErrors() throws Exception {
    HttpServer server =
        HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
    byte[] bounded =
        ("{\"v\":\"" + "x".repeat(1048576 - 8) + "\"}").getBytes(StandardCharsets.UTF_8);
    server.createContext(
        "/api/v1/bytes",
        exchange -> {
          try (exchange) {
            boolean oversized = !exchange.getRequestURI().getQuery().equals("size=bounded");
            exchange.sendResponseHeaders(oversized ? 500 : 200, 0);
            exchange.getResponseBody().write(bounded);
            if (oversized) exchange.getResponseBody().write(' ');
          }
        });
    server.start();
    try {
      var client = new MailPlatformClient(endpoint(server), "synthetic-token");
      assertEquals(
          1048576 - 8,
          ((String) client.request("GET", "/bytes", Map.of("size", "bounded")).get("v")).length());
      var oversized = Map.of("size", "oversized");
      var failure =
          assertThrows(MailFailure.class, () -> client.request("GET", "/bytes", oversized));
      assertEquals("quota", failure.getMessage());
    } finally {
      server.stop(0);
    }
  }

  private static String endpoint(HttpServer server) {
    return "http://127.0.0.1:" + server.getAddress().getPort() + "/api/v1";
  }
}
