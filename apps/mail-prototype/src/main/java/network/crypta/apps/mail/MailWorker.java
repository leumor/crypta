package network.crypta.apps.mail;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.LinkedHashMap;
import java.util.Map;
import network.crypta.crypt.mail.MailWire;

/**
 * AppHost-managed Java process; private IPC uses authenticated API calls and never process logs.
 */
public final class MailWorker {
  /** Prevents instances of the process entry point. */
  private MailWorker() {}

  /**
   * Runs the bounded fixed worker channel until AppHost stops the process.
   *
   * <p>The endpoint and process token come from the verified AppHost launch environment. Private
   * request and response frames use authenticated API calls, never standard output or error logs.
   *
   * @param args unused; endpoints and credentials cannot be supplied through command arguments
   */
  public static void main(String[] args) {
    try {
      MailBackend backend =
          new MailPlatformClient(
              System.getenv("CRYPTAD_MAIL_API_ENDPOINT"), System.getenv("CRYPTAD_APP_TOKEN"));
      MailMailbox mailbox = new MailMailbox(backend, Clock.systemUTC());
      while (!Thread.currentThread().isInterrupted()) {
        try {
          var frame =
              MailPlatformClient.object(
                  backend.request("POST", "/mail/poll", Map.of()).get("mail"));
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
          } else Thread.sleep(100);
        } catch (RuntimeException exception) {
          Thread.sleep(250);
        }
      }
    } catch (InterruptedException exception) {
      Thread.currentThread().interrupt();
    } catch (RuntimeException exception) {
      System.exit(2);
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
          || encoded.length() > 393216) return Map.of("status", "invalid");
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
        if (!(entry.getValue() instanceof String value)) return Map.of("status", "invalid");
        input.put(entry.getKey(), value);
      }
    } catch (RuntimeException | java.nio.charset.CharacterCodingException exception) {
      return Map.of("status", "invalid");
    }
    try {
      return mailbox.execute(command, input);
    } catch (RuntimeException exception) {
      return Map.of("status", "unavailable");
    }
  }
}
