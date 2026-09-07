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
            String encoded = (String) frame.get("payloadBase64");
            if (encoded.length() > 393216) throw new MailFailure("quota");
            byte[] payload = java.util.Base64.getDecoder().decode(encoded);
            var values =
                MailPlatformClient.object(
                    MailApiJsonParser.parse(new String(payload, StandardCharsets.UTF_8)));
            var input = new LinkedHashMap<String, String>();
            for (var entry : values.entrySet()) {
              if (!(entry.getValue() instanceof String value)) throw new MailFailure("invalid");
              input.put(entry.getKey(), value);
            }
            Map<String, String> response;
            try {
              response = mailbox.execute((String) frame.get("command"), input);
            } catch (RuntimeException exception) {
              response = Map.of("status", "unavailable");
            }
            backend.request(
                "POST",
                "/mail/reply",
                Map.of(
                    "requestId",
                    requestId,
                    "payloadBase64",
                    MailWire.base64(MailWire.encode(response))));
          } else Thread.sleep(100);
        } catch (MailFailure | IllegalArgumentException exception) {
          Thread.sleep(250);
        }
      }
    } catch (InterruptedException exception) {
      Thread.currentThread().interrupt();
    } catch (RuntimeException exception) {
      System.exit(2);
    }
  }
}
