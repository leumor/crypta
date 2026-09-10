package network.crypta.apps.mail;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import network.crypta.crypt.mail.MailHpke;
import network.crypta.crypt.mail.MailWire;
import network.crypta.platform.api.PlatformApiPrincipal;
import network.crypta.platform.api.PlatformApiRequest;
import network.crypta.platform.api.PlatformApiRouter;
import network.crypta.runtime.spi.RuntimePorts;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Answers;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Temporal/contact policy with independent production vault/data services and simulated transport.
 */
class MailMailboxPolicyTest {
  private static final Instant START = Instant.parse("2026-09-07T12:00:00Z");
  private static final long DAY = 86400;
  @TempDir Path root;
  private final Map<String, byte[]> network = new LinkedHashMap<>();

  @Test
  void originalSealedMailSurvivesExplicitOwnAndRemoteContactRenewal() throws Exception {
    Party sender = party("history-sender", START);
    Party recipient = party("history-recipient", START);
    String recipientFingerprint = pin(sender.mail(), recipient.mail());
    String senderFingerprint = pin(recipient.mail(), sender.mail());
    var sent = send(sender.mail(), recipientFingerprint);
    byte[] ciphertext = network.get(sent.get("reference")).clone();
    MailMailbox laterSender = at(sender.backend(), START.plusSeconds(10));
    MailMailbox laterRecipient = at(recipient.backend(), START.plusSeconds(10));

    for (MailMailbox mailbox : List.of(laterSender, laterRecipient)) {
      var preview = mailbox.execute("preview-renew-contact", Map.of());
      assertStatus("preview", preview);
      assertStatus(
          "renewed",
          mailbox.execute(
              "confirm-renew-contact", Map.of("renewalToken", preview.get("renewalToken"))));
    }
    String renewedSender = laterSender.execute("export-contact", Map.of()).get("card");
    laterRecipient.execute("import-contact", Map.of("card", renewedSender));
    assertStatus(
        "contact-approved",
        laterRecipient.execute("approve-contact", Map.of("fingerprint", senderFingerprint)));

    assertStatus("accepted", receive(laterRecipient, sent.get("reference")));
    assertArrayEquals(ciphertext, network.get(sent.get("reference")));
    assertEquals(3, sender.backend().vault.listIdentities().size());
    assertEquals(3, recipient.backend().vault.listIdentities().size());

    // An authenticated dataset still cannot substitute another account's valid historical card.
    var malformed = recipient.backend().privateState();
    malformed.put(
        "own-card-history.0", sender.mail().execute("export-contact", Map.of()).get("card"));
    byte[] envelope =
        recipient
            .backend()
            .vault
            .sealStorage(
                MailTestBackend.APP, malformed.get("storageId"), MailWire.encode(malformed));
    var wrapper = new LinkedHashMap<String, String>();
    wrapper.put("storageId", malformed.get("storageId"));
    wrapper.put("envelope", MailWire.base64(envelope));
    recipient
        .backend()
        .request(
            "POST",
            "/app-data/records",
            Map.of(
                "namespace",
                "mail-state",
                "key",
                "dataset",
                "schemaVersion",
                "1",
                "contentType",
                "application/octet-stream",
                "valueBase64",
                MailWire.base64(MailWire.encode(wrapper))));
    assertStatus("invalid-contact-history", receive(laterRecipient, sent.get("reference")));
  }

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

  @Test
  void expiredRetryCannotEnqueueOrRestartAndPreservesCommittedCiphertext() throws Exception {
    for (String queueState : new String[] {"missing", "failed"}) {
      for (long beyondExpiry : new long[] {0, 1}) {
        String suffix = queueState + beyondExpiry;
        Party sender = party("sender-" + suffix, START);
        Party recipient = party("recipient-" + suffix, START);
        String fingerprint = pin(sender.mail(), recipient.mail());
        QueueGate gate = new QueueGate(sender.backend());
        String operation = sealWithoutPublishing(gate, fingerprint);
        long expiry = signedExpiry(sender.backend());
        byte[] before = sender.backend().storedBytes();
        gate.queueState = queueState;
        gate.rejectNetwork = false;
        MailMailbox later = at(gate, Instant.ofEpochSecond(expiry + beyondExpiry));

        assertStatus("expired", later.execute("retry", Map.of("operation", operation)));

        assertEquals(1, gate.enqueueAttempts);
        assertEquals(0, gate.restartAttempts);
        assertArrayEquals(before, sender.backend().storedBytes());
        assertTrue(sender.backend().insertionBytes.isEmpty());
      }
    }
    assertTrue(network.isEmpty());
  }

  @Test
  void failedInsertRetryReachesRegisteredRouterAndPreservesCiphertext() throws Exception {
    Party sender = party("sender-router", START);
    Party recipient = party("recipient-router", START);
    String fingerprint = pin(sender.mail(), recipient.mail());
    QueueGate gate = new QueueGate(sender.backend());
    String operation = sealWithoutPublishing(gate, fingerprint);
    String original = sender.backend().privateState().get("outbox." + operation);
    gate.queueState = "failed";
    RuntimePorts ports = mock(RuntimePorts.class, Answers.RETURNS_DEEP_STUBS);
    when(ports.queueSupport().isQueueBackendEnabled()).thenReturn(true);
    MailBackend routed = routeQueueMutations(ports, gate);

    assertStatus("queued", at(routed, START).execute("retry", Map.of("operation", operation)));

    verify(ports.queueMutation())
        .restartRequests(List.of("app-document-mail-prototype-" + operation), false);
    var before = MailWire.decode(original.getBytes(StandardCharsets.UTF_8), 131072);
    var after =
        MailWire.decode(
            sender
                .backend()
                .privateState()
                .get("outbox." + operation)
                .getBytes(StandardCharsets.UTF_8),
            131072);
    assertEquals(before.get("envelope"), after.get("envelope"));
    assertTrue(network.isEmpty());
  }

  @Test
  void unexpiredRetryStillEnqueuesOrRestartsWithoutResealing() throws Exception {
    for (String queueState : new String[] {"missing", "failed"}) {
      Party sender = party("sender-" + queueState, START);
      Party recipient = party("recipient-" + queueState, START);
      String fingerprint = pin(sender.mail(), recipient.mail());
      QueueGate gate = new QueueGate(sender.backend());
      String operation = sealWithoutPublishing(gate, fingerprint);
      String original = sender.backend().privateState().get("outbox." + operation);
      String envelope =
          MailWire.decode(original.getBytes(StandardCharsets.UTF_8), 131072).get("envelope");
      gate.queueState = queueState;
      gate.rejectNetwork = false;
      MailMailbox beforeExpiry =
          at(gate, Instant.ofEpochSecond(signedExpiry(sender.backend()) - 1));

      assertStatus("queued", beforeExpiry.execute("retry", Map.of("operation", operation)));

      assertEquals("missing".equals(queueState) ? 2 : 1, gate.enqueueAttempts);
      assertEquals("failed".equals(queueState) ? 1 : 0, gate.restartAttempts);
      var retained =
          MailWire.decode(
              sender
                  .backend()
                  .privateState()
                  .get("outbox." + operation)
                  .getBytes(StandardCharsets.UTF_8),
              131072);
      assertEquals(envelope, retained.get("envelope"));
      if ("missing".equals(queueState)) {
        assertArrayEquals(
            java.util.Base64.getDecoder().decode(envelope),
            sender.backend().insertionBytes.getFirst());
      }
    }
  }

  @Test
  void expiredRetryStillReportsKnownOrPreviouslyUncertainSuccessfulInsertion() throws Exception {
    Party sender = party("sender-known", START);
    Party recipient = party("recipient-known", START);
    String fingerprint = pin(sender.mail(), recipient.mail());
    Map<String, String> inserted = send(sender.mail(), fingerprint);
    MailMailbox expired =
        at(sender.backend(), Instant.ofEpochSecond(signedExpiry(sender.backend())));
    assertEquals(
        inserted, expired.execute("retry", Map.of("operation", inserted.get("operation"))));
    assertEquals(1, sender.backend().insertionBytes.size());

    Party uncertain = party("sender-uncertain", START);
    String contact = pin(uncertain.mail(), recipient.mail());
    assertStatus(
        "draft",
        uncertain
            .mail()
            .execute(
                "save-draft",
                Map.of(
                    "fingerprint",
                    contact,
                    "subject",
                    "Public synthetic",
                    "body",
                    "Uncertain completed publication")));
    String approval = uncertain.mail().execute("preview-send", Map.of()).get("approval");
    uncertain.backend().failInsertAfterCommit = true;
    assertStatus(
        "network-unavailable",
        uncertain.mail().execute("confirm-send", Map.of("approval", approval)));
    String operation = uncertain.mail().execute("status", Map.of()).get("operations");
    MailMailbox afterExpiry =
        at(uncertain.backend(), Instant.ofEpochSecond(signedExpiry(uncertain.backend()) + 1));

    Map<String, String> recovered = afterExpiry.execute("retry", Map.of("operation", operation));

    assertStatus("inserted", recovered);
    assertEquals(
        uncertain.backend().inserted.get("app-document-mail-prototype-" + operation),
        recovered.get("reference"));
    assertEquals(1, uncertain.backend().insertionBytes.size());
  }

  private static String sealWithoutPublishing(QueueGate gate, String fingerprint) {
    MailMailbox mailbox = at(gate, START);
    assertStatus(
        "draft",
        mailbox.execute(
            "save-draft",
            Map.of(
                "fingerprint",
                fingerprint,
                "subject",
                "Public synthetic",
                "body",
                "Bounded retry expiry")));
    String approval = mailbox.execute("preview-send", Map.of()).get("approval");
    assertStatus(
        "network-unavailable", mailbox.execute("confirm-send", Map.of("approval", approval)));
    return mailbox.execute("status", Map.of()).get("operations");
  }

  private static long signedExpiry(MailTestBackend backend) {
    return MailWire.decimal(
        MailWire.decode(MailWire.signedPayload(backend.latestSigned), 32768).get("expires"));
  }

  @Test
  void expiredRecipientCardRejectsValidSenderMessageWithoutAdmission() throws Exception {
    Party recipient = party("expired-recipient", START);
    Party sender = party("valid-sender", START.plusSeconds(340 * DAY));
    Instant receivingTime = START.plusSeconds(366 * DAY);
    MailMailbox receiver = at(recipient.backend(), receivingTime);
    pin(receiver, sender.mail());
    String reference =
        signedReference(
            sender, recipient, receivingTime.minusSeconds(DAY), receivingTime.plusSeconds(DAY), 1);
    byte[] before = recipient.backend().storedBytes();

    assertStatus("expired", receive(receiver, reference));

    assertArrayEquals(before, recipient.backend().storedBytes());
    assertEquals("0", receiver.execute("status", Map.of()).get("inbox"));
    assertTrue(
        recipient.backend().privateState().keySet().stream()
            .noneMatch(k -> k.startsWith("replay.")));
  }

  @Test
  void messagePredatingRecipientCreationIsRejectedButExactCreationBoundaryAccepts()
      throws Exception {
    Party sender = party("earlier-sender", START);
    Instant recipientCreated = START.plusSeconds(10 * DAY);
    Party recipient = party("later-recipient", recipientCreated);
    MailMailbox receiver = at(recipient.backend(), recipientCreated.plusSeconds(60));
    pin(receiver, sender.mail());
    Instant expiry = recipientCreated.plusSeconds(DAY);
    String tooEarly =
        signedReference(sender, recipient, recipientCreated.minusSeconds(1), expiry, 2);
    byte[] before = recipient.backend().storedBytes();

    assertStatus("expired", receive(receiver, tooEarly));
    assertArrayEquals(before, recipient.backend().storedBytes());
    String boundary = signedReference(sender, recipient, recipientCreated, expiry, 2);
    assertStatus("accepted", receive(receiver, boundary));
    assertEquals("1", receiver.execute("status", Map.of()).get("inbox"));
    assertEquals(
        1,
        recipient.backend().privateState().keySet().stream()
            .filter(k -> k.startsWith("replay."))
            .count());
  }

  @Test
  void messageBeyondRecipientExpiryIsRejectedButExactExpiryBoundaryAccepts() throws Exception {
    Party recipient = party("earlier-recipient", START);
    Party sender = party("later-sender", START.plusSeconds(340 * DAY));
    Instant creation = START.plusSeconds(364 * DAY);
    Instant recipientExpiry = START.plusSeconds(365 * DAY);
    MailMailbox receiver = at(recipient.backend(), creation.plusSeconds(60));
    pin(receiver, sender.mail());
    String tooLate =
        signedReference(sender, recipient, creation, recipientExpiry.plusSeconds(1), 3);
    byte[] before = recipient.backend().storedBytes();

    assertStatus("expired", receive(receiver, tooLate));
    assertArrayEquals(before, recipient.backend().storedBytes());
    String boundary = signedReference(sender, recipient, creation, recipientExpiry, 3);
    assertStatus("accepted", receive(receiver, boundary));
    assertEquals("1", receiver.execute("status", Map.of()).get("inbox"));
    assertEquals(
        1,
        recipient.backend().privateState().keySet().stream()
            .filter(k -> k.startsWith("replay."))
            .count());
  }

  private static MailBackend routeQueueMutations(RuntimePorts ports, MailBackend backend) {
    PlatformApiRouter router = new PlatformApiRouter(ports);
    return (method, path, parameters) -> {
      if (method.equals("POST") && path.startsWith("/queue/")) {
        Map<String, List<String>> form = new LinkedHashMap<>();
        parameters.forEach((key, value) -> form.put(key, List.of(value)));
        var response =
            router.route(
                new PlatformApiRequest(
                    method,
                    List.of(path.substring(1).split("/")),
                    form,
                    PlatformApiPrincipal.appToken("mail-prototype", List.of("queue.write"))));
        assertEquals(200, response.statusCode(), response.body());
        return Map.of();
      }
      return backend.request(method, path, parameters);
    };
  }

  private static String signedReference(
      Party sender, Party recipient, Instant created, Instant expires, int messageId) {
    var senderState = sender.backend().privateState();
    var senderCard =
        MailWire.decode(
            MailWire.signedPayload(senderState.get("ownCard").getBytes(StandardCharsets.UTF_8)),
            4096);
    var recipientCard =
        MailWire.decode(
            MailWire.signedPayload(
                recipient.backend().privateState().get("ownCard").getBytes(StandardCharsets.UTF_8)),
            4096);
    var message = new LinkedHashMap<String, String>();
    message.put("profile", MailWire.MESSAGE);
    message.put("messageId", String.format(java.util.Locale.ROOT, "%032x", messageId));
    message.put("sender", senderCard.get("signingFingerprint"));
    message.put("senderAccount", senderCard.get("account"));
    message.put("senderEpoch", senderCard.get("signingEpoch"));
    message.put("recipient", recipientCard.get("recipientFingerprint"));
    message.put("recipientAccount", recipientCard.get("account"));
    message.put("recipientEpoch", recipientCard.get("recipientEpoch"));
    message.put("created", Long.toString(created.getEpochSecond()));
    message.put("expires", Long.toString(expires.getEpochSecond()));
    message.put("subject", "Public synthetic validity test");
    message.put("body", "Valid signature and encryption with an adversarial validity interval.");
    message.put("format", "text/plain");
    byte[] signed =
        sender
            .backend()
            .vault
            .signMail(
                MailTestBackend.APP,
                senderState.get("signingId"),
                MailWire.messagePayload(message));
    byte[] encrypted =
        MailHpke.seal(
            "network",
            recipientCard.get("recipientFingerprint"),
            MailWire.unbase64(recipientCard.get("recipientKey"), 32),
            signed);
    return sender.backend().addEnvelope(encrypted);
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
    private boolean rejectNetwork = true;

    QueueGate(MailTestBackend backend) {
      this.backend = backend;
    }

    @Override
    public Map<String, Object> request(String method, String path, Map<String, String> parameters) {
      if (path.equals("/queue/app-document-status")) return Map.of("state", queueState);
      if (path.equals("/queue/inserts/app-document")) {
        enqueueAttempts++;
        if (rejectNetwork) throw new MailFailure("network-unavailable");
      }
      if (path.equals("/queue/requests/restart")) {
        restartAttempts++;
        if (rejectNetwork) throw new MailFailure("network-unavailable");
      }
      return backend.request(method, path, parameters);
    }
  }
}
