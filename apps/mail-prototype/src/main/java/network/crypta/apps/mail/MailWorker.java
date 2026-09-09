package network.crypta.apps.mail;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import network.crypta.crypt.mail.MailWire;

/**
 * AppHost-managed Java process; private IPC uses authenticated API calls and never process logs.
 */
public final class MailWorker {
  private static final String STATUS = "status";
  private static final String INVALID = "invalid";

  /** Prevents instances of the process entry point. */
  private MailWorker() {}

  /**
   * Runs the bounded fixed worker channel until AppHost stops the process.
   *
   * <p>The endpoint and process token come from the verified AppHost launch environment. Private
   * request and response frames use authenticated API calls, never standard output or error logs.
   */
  static void main() {
    try {
      MailBackend backend =
          new MailPlatformClient(
              System.getenv("CRYPTAD_MAIL_API_ENDPOINT"), System.getenv("CRYPTAD_APP_TOKEN"));
      runWorker(backend, new MailMailbox(backend, Clock.systemUTC()));
    } catch (InterruptedException _) {
      Thread.currentThread().interrupt();
    } catch (RuntimeException _) {
      System.exit(2);
    }
  }

  /**
   * Runs serial, paced polls and cancels the current request when the entry thread is interrupted.
   */
  private static void runWorker(MailBackend backend, MailMailbox mailbox)
      throws InterruptedException {
    try (var scheduler = Executors.newSingleThreadScheduledExecutor()) {
      scheduler.scheduleWithFixedDelay(
          () -> pollAndReply(backend, mailbox), 0, 250, TimeUnit.MILLISECONDS);
      awaitSchedulerTermination(scheduler);
    }
  }

  /** Cancels active work before resource closure, including when waiting is interrupted. */
  private static void awaitSchedulerTermination(ScheduledExecutorService scheduler)
      throws InterruptedException {
    try {
      if (!scheduler.awaitTermination(Long.MAX_VALUE, TimeUnit.NANOSECONDS)) {
        throw new IllegalStateException("Worker scheduler termination deadline exceeded.");
      }
    } finally {
      scheduler.shutdownNow();
    }
  }

  /** Handles one broker poll; transient failures are retried at the next scheduled poll. */
  private static void pollAndReply(MailBackend backend, MailMailbox mailbox) {
    try {
      var frame =
          MailPlatformClient.object(backend.request("POST", "/mail/poll", Map.of()).get("mail"));
      if (frame.get("requestId") instanceof String requestId) {
        Map<String, String> response = executeCommand(mailbox, frame);
        backend.request(
            "POST",
            "/mail/reply",
            Map.of(
                "requestId",
                requestId,
                "payloadBase64",
                MailWire.base64(MailWire.encode(response))));
      }
    } catch (RuntimeException _) {
      // Keep the scheduled worker available without logging private frames or failure details.
    }
  }

  /**
   * Validates one complete command and contains malformed input within its bounded reply.
   *
   * @param mailbox process-owned mailbox
   * @param frame authenticated broker frame for the current launch
   * @return bounded validation failure or mailbox result, never parser diagnostics
   */
  private static Map<String, String> executeCommand(
      MailMailbox mailbox, Map<String, Object> frame) {
    var input = new LinkedHashMap<String, String>();
    String command;
    try {
      if (!(frame.get("command") instanceof String name)
          || !(frame.get("payloadBase64") instanceof String encoded)
          || encoded.length() > 393216) return Map.of(STATUS, INVALID);
      command = name;
      byte[] payload = java.util.Base64.getDecoder().decode(encoded);
      String json =
          StandardCharsets.UTF_8
              .newDecoder()
              .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
              .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
              .decode(java.nio.ByteBuffer.wrap(payload))
              .toString();
      var values = MailPlatformClient.object(MailApiJsonParser.parse(json));
      for (var entry : values.entrySet()) {
        if (!(entry.getValue() instanceof String value)) return Map.of(STATUS, INVALID);
        input.put(entry.getKey(), value);
      }
    } catch (RuntimeException | java.nio.charset.CharacterCodingException _) {
      return Map.of(STATUS, INVALID);
    }
    try {
      return mailbox.execute(command, input);
    } catch (RuntimeException _) {
      return Map.of(STATUS, "unavailable");
    }
  }
}
