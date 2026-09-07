package network.crypta.apps.mail;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.Map;
import network.crypta.crypt.mail.MailWire;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Temporal/contact policy with independent production vault/data services and simulated transport.
 */
class MailMailboxPolicyTest {
  private static final Instant START = Instant.parse("2026-09-07T12:00:00Z");
  private static final long DAY = 86400;
  @TempDir Path root;
  private final Map<String, byte[]> network = new LinkedHashMap<>();

  @Test
  void expiredContactCannotBeImportedOrUsedForNewDraft() throws Exception {
    Party sender = party("sender", START);
    Party recipient = party("recipient", START);
    String fingerprint = pin(sender.mail(), recipient.mail());
    String card = recipient.mail().execute("export-contact", Map.of()).get("card");
    MailMailbox later = at(sender.backend(), START.plusSeconds(366 * DAY));
    byte[] before = sender.backend().storedBytes();

    assertStatus("expired-contact", later.execute("import-contact", Map.of("card", card)));
    assertStatus(
        "expired-contact",
        later.execute(
            "save-draft",
            Map.of(
                "fingerprint", fingerprint, "subject", "Public synthetic", "body", "Expired pin")));

    assertArrayEquals(before, sender.backend().storedBytes());
    assertTrue(network.isEmpty());
  }

  @Test
  void expiredAuthenticatedMessageDoesNotCreateReplayOrInboxState() throws Exception {
    Party sender = party("sender", START);
    Party recipient = party("recipient", START);
    String recipientFingerprint = pin(sender.mail(), recipient.mail());
    pin(recipient.mail(), sender.mail());
    Map<String, String> sent = send(sender.mail(), recipientFingerprint);
    MailMailbox later = at(recipient.backend(), START.plusSeconds(31 * DAY));
    byte[] before = recipient.backend().storedBytes();

    assertStatus("expired", receive(later, sent.get("reference")));

    assertArrayEquals(before, recipient.backend().storedBytes());
    assertEquals("0", later.execute("status", Map.of()).get("inbox"));
    assertTrue(
        recipient.backend().privateState().keySet().stream()
            .noneMatch(k -> k.startsWith("replay.")));
  }

  @Test
  void unknownSenderDoesNotGainTrustFromEnvelopeSignatureOrPoisonReplay() throws Exception {
    Party sender = party("sender", START);
    Party recipient = party("recipient", START);
    String fingerprint = pin(sender.mail(), recipient.mail());
    Map<String, String> sent = send(sender.mail(), fingerprint);
    byte[] before = recipient.backend().storedBytes();

    assertStatus("unknown-sender", receive(recipient.mail(), sent.get("reference")));
    assertArrayEquals(before, recipient.backend().storedBytes());
    pin(recipient.mail(), sender.mail());
    assertStatus("accepted", receive(recipient.mail(), sent.get("reference")));
  }

  @Test
  void senderOwnCardExpiryBoundsMessageEvenWhenRecipientCardLivesLonger() throws Exception {
    Party sender = party("sender", START);
    Party recipient = party("recipient", START.plusSeconds(340 * DAY));
    Instant sendingTime = START.plusSeconds(350 * DAY);
    MailMailbox currentSender = at(sender.backend(), sendingTime);
    MailMailbox currentRecipient = at(recipient.backend(), sendingTime);
    String fingerprint = pin(currentSender, currentRecipient);
    pin(currentRecipient, currentSender);

    Map<String, String> sent = send(currentSender, fingerprint);

    var signedMessage =
        MailWire.decode(MailWire.signedPayload(sender.backend().latestSigned), 32768);
    var senderCard =
        MailWire.decode(
            MailWire.signedPayload(
                currentSender
                    .execute("export-contact", Map.of())
                    .get("card")
                    .getBytes(StandardCharsets.UTF_8)),
            4096);
    assertEquals(senderCard.get("expires"), signedMessage.get("expires"));
    assertStatus("accepted", receive(currentRecipient, sent.get("reference")));
  }

  @Test
  void revokedRecipientPreventsBothNewEnqueueAndQueueRestartAcrossWorkerRestart() throws Exception {
    Party sender = party("sender", START);
    Party recipient = party("recipient", START);
    String fingerprint = pin(sender.mail(), recipient.mail());
    QueueGate gate = new QueueGate(sender.backend());
    MailMailbox worker = at(gate, START);
    assertStatus(
        "draft",
        worker.execute(
            "save-draft",
            Map.of(
                "fingerprint",
                fingerprint,
                "subject",
                "Public synthetic",
                "body",
                "Revocation pending send")));
    String approval = worker.execute("preview-send", Map.of()).get("approval");
    assertStatus(
        "network-unavailable", worker.execute("confirm-send", Map.of("approval", approval)));
    String operation = worker.execute("status", Map.of()).get("operations");
    assertEquals(1, gate.enqueueAttempts);
    assertStatus(
        "contact-revoked", worker.execute("revoke-contact", Map.of("fingerprint", fingerprint)));
    worker = at(gate, START);

    for (String queueState : new String[] {"missing", "failed"}) {
      gate.queueState = queueState;
      assertStatus("contact-revoked", worker.execute("retry", Map.of("operation", operation)));
    }

    assertEquals(1, gate.enqueueAttempts);
    assertEquals(0, gate.restartAttempts);
    assertTrue(network.isEmpty());
    assertStatus(
        "contact-revoked",
        worker.execute(
            "save-draft",
            Map.of(
                "fingerprint",
                fingerprint,
                "subject",
                "Public synthetic",
                "body",
                "No further sending")));
  }

  @Test
  void revokedSenderBlocksNewAcceptanceWhileVerifiedLocalCopyRemainsReadable() throws Exception {
    Party sender = party("sender", START);
    Party recipient = party("recipient", START);
    String recipientFingerprint = pin(sender.mail(), recipient.mail());
    String senderFingerprint = pin(recipient.mail(), sender.mail());
    Map<String, String> first = send(sender.mail(), recipientFingerprint);
    Map<String, String> accepted = receive(recipient.mail(), first.get("reference"));
    assertStatus("accepted", accepted);
    Map<String, String> second = send(sender.mail(), recipientFingerprint);
    assertStatus(
        "contact-revoked",
        recipient.mail().execute("revoke-contact", Map.of("fingerprint", senderFingerprint)));
    byte[] before = recipient.backend().storedBytes();

    assertStatus("contact-revoked", receive(recipient.mail(), second.get("reference")));
    assertArrayEquals(before, recipient.backend().storedBytes());
    assertStatus(
        "verified-local-copy",
        recipient.mail().execute("read", Map.of("messageId", accepted.get("messageId"))));
    assertEquals("1", recipient.mail().execute("status", Map.of()).get("inbox"));
  }

  private Party party(String name, Instant time) throws Exception {
    MailTestBackend backend =
        new MailTestBackend(root.resolve(name + "-vault"), root.resolve(name + "-data"), network);
    MailMailbox mailbox = at(backend, time);
    assertStatus("ready", mailbox.execute("initialize", Map.of()));
    return new Party(backend, mailbox);
  }

  private static MailMailbox at(MailBackend backend, Instant time) {
    return new MailMailbox(backend, Clock.fixed(time, ZoneOffset.UTC));
  }

  private static String pin(MailMailbox owner, MailMailbox contact) {
    Map<String, String> imported =
        owner.execute(
            "import-contact",
            Map.of("card", contact.execute("export-contact", Map.of()).get("card")));
    assertStatus("compare-fingerprint-out-of-band", imported);
    String fingerprint = imported.get("fingerprint");
    assertStatus(
        "contact-approved", owner.execute("approve-contact", Map.of("fingerprint", fingerprint)));
    return fingerprint;
  }

  private static Map<String, String> send(MailMailbox sender, String fingerprint) {
    assertStatus(
        "draft",
        sender.execute(
            "save-draft",
            Map.of(
                "fingerprint",
                fingerprint,
                "subject",
                "Public synthetic",
                "body",
                "Public synthetic policy message")));
    String approval = sender.execute("preview-send", Map.of()).get("approval");
    Map<String, String> queued = sender.execute("confirm-send", Map.of("approval", approval));
    assertStatus("queued", queued);
    Map<String, String> inserted =
        sender.execute("retry", Map.of("operation", queued.get("operation")));
    assertStatus("inserted", inserted);
    return inserted;
  }

  private static Map<String, String> receive(MailMailbox recipient, String reference) {
    return recipient.execute(
        "import-reference", Map.of("reference", reference, "confirmed", "yes"));
  }

  private static void assertStatus(String expected, Map<String, String> result) {
    assertEquals(expected, result.get("status"));
  }

  private record Party(MailTestBackend backend, MailMailbox mail) {}

  private static final class QueueGate implements MailBackend {
    private final MailTestBackend backend;
    private String queueState = "missing";
    private int enqueueAttempts;
    private int restartAttempts;

    QueueGate(MailTestBackend backend) {
      this.backend = backend;
    }

    @Override
    public Map<String, Object> request(String method, String path, Map<String, String> parameters) {
      if (path.equals("/queue/app-document-status")) return Map.of("state", queueState);
      if (path.equals("/queue/inserts/app-document")) {
        enqueueAttempts++;
        throw new MailFailure("network-unavailable");
      }
      if (path.equals("/queue/restart")) {
        restartAttempts++;
        throw new MailFailure("network-unavailable");
      }
      return backend.request(method, path, parameters);
    }
  }
}
