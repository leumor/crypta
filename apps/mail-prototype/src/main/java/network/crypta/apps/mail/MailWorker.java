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
 *
 * <p>The Java 25 entry point obtains the endpoint and token only from the verified launch
 * environment. One scheduler thread owns serial mailbox calls and polls the fixed broker with a 250
 * ms delay after each completed attempt. Starting the worker does not itself send messages or
 * discover content; mailbox operations require an explicit own-app command.
 */
public final class MailWorker {
  /** Private response field carrying a bounded operation classification. */
  private static final String STATUS = "status";

  /** Bounded response classification for a malformed own-app command. */
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
   *
   * @param backend authenticated connection for broker and mailbox operations
   * @param mailbox process-owned state machine used only by the scheduler thread
   * @throws InterruptedException if the entry thread is interrupted while awaiting termination
   */
  private static void runWorker(MailBackend backend, MailMailbox mailbox)
      throws InterruptedException {
    try (var scheduler = Executors.newSingleThreadScheduledExecutor()) {
      scheduler.scheduleWithFixedDelay(
          () -> pollAndReply(backend, mailbox), 0, 250, TimeUnit.MILLISECONDS);
      awaitSchedulerTermination(scheduler);
    }
  }

  /**
   * Cancels active work before resource closure, including when waiting is interrupted.
   *
   * @param scheduler worker-owned executor awaiting termination
   * @throws InterruptedException if the waiting thread is interrupted, after requesting
   *     cancellation
   * @throws IllegalStateException if the termination wait exhausts its maximum nanosecond timeout
   */
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

  /**
   * Handles one broker poll; transient transport failures do not stop subsequent scheduled polls.
   *
   * <p>A failed reply is not automatically resubmitted. The broker deadline and mailbox's durable
   * operation state govern later explicit recovery; this method does not promise exactly-once
   * command execution or reply delivery.
   *
   * @param backend authenticated connection for the fixed poll/reply endpoints
   * @param mailbox process-owned state machine for the returned command
   */
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
