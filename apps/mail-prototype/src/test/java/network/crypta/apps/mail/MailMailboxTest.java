package network.crypta.apps.mail;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.Map;
import network.crypta.crypt.mail.MailHpke;
import network.crypta.crypt.mail.MailWire;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Local independent-vault/store integration; the shared map is explicitly a synthetic transport.
 */
class MailMailboxTest {
  @TempDir Path root;
  private final Clock clock = Clock.fixed(Instant.parse("2026-09-07T12:00:00Z"), ZoneOffset.UTC);
  private final Map<String, byte[]> network = new LinkedHashMap<>();
  private MailTestBackend a;
  private MailTestBackend b;
  private MailMailbox alice;
  private MailMailbox bob;
  private String aliceFingerprint;
  private String bobFingerprint;

  @BeforeEach
  void independentAccountsAndExplicitPins() throws Exception {
    a = new MailTestBackend(root.resolve("a-vault"), root.resolve("a-data/dataset"), network);
    b = new MailTestBackend(root.resolve("b-vault"), root.resolve("b-data/dataset"), network);
    alice = new MailMailbox(a, clock);
    bob = new MailMailbox(b, clock);
    assertStatus("ready", alice.execute("initialize", Map.of()));
    assertStatus("ready", bob.execute("initialize", Map.of()));
    aliceFingerprint = pin(bob, alice);
    bobFingerprint = pin(alice, bob);
    assertTrue(network.isEmpty());
    assertEquals(0, a.fetches + b.fetches);
  }

  @Test
  void independentSenderRecipientReadLiteralTextRestartDuplicateAndReply() throws Exception {
    String body = "<script>throw 'inert'</script> public synthetic text";
    Map<String, String> sent = send(alice, bobFingerprint, body);
    Map<String, String> accepted = receive(bob, sent.get("reference"));
    assertStatus("accepted", accepted);
    var read = bob.execute("read", Map.of("messageId", accepted.get("messageId")));
    assertEquals(body, read.get("body"));
    assertEquals("text/plain", read.get("format"));
    assertEquals("locally-pinned-at-acceptance", read.get("senderTrust"));
    assertFalse(new String(a.storedBytes(), StandardCharsets.UTF_8).contains(body));
    assertFalse(new String(b.storedBytes(), StandardCharsets.UTF_8).contains(body));
    assertFalse(new String(a.insertionBytes.getFirst(), StandardCharsets.UTF_8).contains(body));
    bob = new MailMailbox(new MailTestBackend(root.resolve("b-vault"), b.dataset, network), clock);
    assertStatus("duplicate", receive(bob, sent.get("reference")));
    Map<String, String> reply = send(bob, aliceFingerprint, "public synthetic reply");
    assertStatus("accepted", receive(alice, reply.get("reference")));
  }

  @Test
  void freshReencryptionDeduplicatesAndAuthenticatedIdConflictDoesNotOverwrite() {
    var sent = send(alice, bobFingerprint, "original synthetic text");
    byte[] signed = a.latestSigned.clone();
    var accepted = receive(bob, sent.get("reference"));
    var card = ownCard(bob);
    byte[] reencrypted =
        MailHpke.seal(
            "network",
            card.get("recipientFingerprint"),
            MailWire.unbase64(card.get("recipientKey"), 32),
            signed);
    assertFalse(java.util.Arrays.equals(a.insertionBytes.getFirst(), reencrypted));
    assertStatus("duplicate", receive(bob, a.addEnvelope(reencrypted)));
    var changed = new LinkedHashMap<>(MailWire.decode(MailWire.signedPayload(signed), 32768));
    changed.put("body", "different authenticated content");
    byte[] conflict =
        a.vault.signMail(
            MailTestBackend.APP,
            a.privateState().get("signingId"),
            MailWire.messagePayload(changed));
    byte[] envelope =
        MailHpke.seal(
            "network",
            card.get("recipientFingerprint"),
            MailWire.unbase64(card.get("recipientKey"), 32),
            conflict);
    assertStatus("conflict", receive(bob, a.addEnvelope(envelope)));
    assertEquals(
        "original synthetic text",
        bob.execute("read", Map.of("messageId", accepted.get("messageId"))).get("body"));
    assertEquals("1", bob.execute("status", Map.of()).get("inbox"));
  }

  @Test
  void malformedEnvelopeAndUnverifiedSignatureCannotPoisonReplay() {
    var sent = send(alice, bobFingerprint, "authentic synthetic message");
    byte[] signed = a.latestSigned.clone();
    byte[] invalidSignature = MailWire.signature(signed);
    invalidSignature[0] ^= 1;
    byte[] forged = MailWire.signed(MailWire.signedPayload(signed), invalidSignature);
    var card = ownCard(bob);
    byte[] envelope =
        MailHpke.seal(
            "network",
            card.get("recipientFingerprint"),
            MailWire.unbase64(card.get("recipientKey"), 32),
            forged);
    assertStatus("invalid", receive(bob, a.addEnvelope(envelope)));
    assertStatus("invalid", receive(bob, a.addEnvelope("{}".getBytes(StandardCharsets.UTF_8))));
    assertEquals("0", bob.execute("status", Map.of()).get("inbox"));
    assertStatus("accepted", receive(bob, sent.get("reference")));
  }

  @Test
  void uncertainEnqueueRecoversCommittedImmutableCiphertextWithoutNewSend() {
    prepare(alice, bobFingerprint, "synthetic crash recovery");
    String approval = alice.execute("preview-send", Map.of()).get("approval");
    a.failInsertAfterCommit = true;
    assertStatus(
        "network-unavailable", alice.execute("confirm-send", Map.of("approval", approval)));
    assertEquals(1, a.insertionBytes.size());
    byte[] original = a.insertionBytes.getFirst().clone();
    String operation = alice.execute("status", Map.of()).get("operations");
    alice = new MailMailbox(a, clock);
    assertStatus("inserted", alice.execute("retry", Map.of("operation", operation)));
    assertEquals(1, a.insertionBytes.size());
    assertArrayEquals(original, a.insertionBytes.getFirst());
    assertEquals("1", alice.execute("status", Map.of()).get("outbox"));
  }

  @Test
  void failedAtomicAcceptanceLeavesNoReplayEntryThenRetryAccepts() {
    var sent = send(alice, bobFingerprint, "atomic admission");
    byte[] before = b.storedBytes();
    b.failNextStore = true;
    assertStatus("store-unavailable", receive(bob, sent.get("reference")));
    assertArrayEquals(before, b.storedBytes());
    assertStatus("accepted", receive(bob, sent.get("reference")));
    assertStatus("duplicate", receive(bob, sent.get("reference")));
  }

  @Test
  void olderBackupMergesAvailableReplayEvidenceAndPausesReceiving() {
    String old = bob.execute("backup", Map.of()).get("backup");
    var sent = send(alice, bobFingerprint, "after backup synthetic text");
    assertStatus("accepted", receive(bob, sent.get("reference")));
    assertStatus(
        "recovery-paused", bob.execute("restore", Map.of("backup", old, "confirmed", "yes")));
    assertEquals(
        1, b.privateState().keySet().stream().filter(k -> k.startsWith("replay.")).count());
    assertEquals("0", bob.execute("status", Map.of()).get("inbox"));
    int fetches = b.fetches;
    assertStatus("recovery-paused", receive(bob, sent.get("reference")));
    assertEquals(fetches, b.fetches);
    bob = new MailMailbox(b, clock);
    assertEquals("paused-after-restore", bob.execute("status", Map.of()).get("recovery"));
  }

  @Test
  void missingStorageKeyBlocksRestoreAndInitializeWithoutEmptySuccess() {
    String backup = bob.execute("backup", Map.of()).get("backup");
    b.vault.deleteIdentity(b.privateState().get("storageId"));
    assertStatus("key-unavailable", bob.execute("status", Map.of()));
    assertStatus("key-unavailable", bob.execute("initialize", Map.of()));
    assertStatus(
        "key-unavailable", bob.execute("restore", Map.of("backup", backup, "confirmed", "yes")));
  }

  @Test
  void contactImportInvalidatesApprovalAndNetworkRequiresExplicitConsent() {
    prepare(alice, bobFingerprint, "requires a current approval");
    String approval = alice.execute("preview-send", Map.of()).get("approval");
    String card = bob.execute("export-contact", Map.of()).get("card");
    assertStatus(
        "compare-fingerprint-out-of-band", alice.execute("import-contact", Map.of("card", card)));
    assertStatus("approval-required", alice.execute("confirm-send", Map.of("approval", approval)));
    assertTrue(network.isEmpty());
    assertStatus(
        "network-consent-required",
        bob.execute("import-reference", Map.of("reference", "https://invalid")));
    assertStatus("invalid-reference", receive(bob, "http://127.0.0.1/private"));
    assertEquals(0, b.fetches);
  }

  @Test
  void oversizedDraftPreservesPriorCommittedState() {
    byte[] before = a.storedBytes();
    assertStatus(
        "quota",
        alice.execute(
            "save-draft",
            Map.of(
                "fingerprint", bobFingerprint, "subject", "oversized", "body", "x".repeat(16385))));
    assertArrayEquals(before, a.storedBytes());
    assertTrue(network.isEmpty());
  }

  @Test
  void fullInboxRejectsFurtherIntakeWithoutEvictingReplayEvidence() {
    var sent = send(alice, bobFingerprint, "bounded inbox synthetic fixture");
    assertStatus("accepted", receive(bob, sent.get("reference")));
    var message =
        new LinkedHashMap<>(MailWire.decode(MailWire.signedPayload(a.latestSigned), 32768));
    var card = ownCard(bob);
    String signingId = a.privateState().get("signingId");
    for (int i = 1; i < 16; i++) {
      message.put("messageId", String.format(java.util.Locale.ROOT, "%032x", i));
      byte[] signed =
          a.vault.signMail(MailTestBackend.APP, signingId, MailWire.messagePayload(message));
      byte[] envelope =
          MailHpke.seal(
              "network",
              card.get("recipientFingerprint"),
              MailWire.unbase64(card.get("recipientKey"), 32),
              signed);
      assertStatus("accepted", receive(bob, a.addEnvelope(envelope)));
    }
    byte[] before = b.storedBytes();
    int fetches = b.fetches;
    assertStatus("quota", receive(bob, sent.get("reference")));
    assertArrayEquals(before, b.storedBytes());
    assertEquals(fetches, b.fetches);
    assertEquals(
        16, b.privateState().keySet().stream().filter(k -> k.startsWith("replay.")).count());
  }

  private static String pin(MailMailbox receiver, MailMailbox owner) {
    var result =
        receiver.execute(
            "import-contact",
            Map.of("card", owner.execute("export-contact", Map.of()).get("card")));
    assertStatus("compare-fingerprint-out-of-band", result);
    assertStatus(
        "contact-approved",
        receiver.execute("approve-contact", Map.of("fingerprint", result.get("fingerprint"))));
    return result.get("fingerprint");
  }

  private static void prepare(MailMailbox sender, String fingerprint, String body) {
    assertStatus(
        "draft",
        sender.execute(
            "save-draft",
            Map.of(
                "fingerprint", fingerprint, "subject", "Public synthetic subject", "body", body)));
  }

  private static Map<String, String> send(MailMailbox sender, String fingerprint, String body) {
    prepare(sender, fingerprint, body);
    String approval = sender.execute("preview-send", Map.of()).get("approval");
    var queued = sender.execute("confirm-send", Map.of("approval", approval));
    assertStatus("queued", queued);
    var inserted = sender.execute("retry", Map.of("operation", queued.get("operation")));
    assertStatus("inserted", inserted);
    return inserted;
  }

  private static Map<String, String> receive(MailMailbox receiver, String reference) {
    return receiver.execute("import-reference", Map.of("reference", reference, "confirmed", "yes"));
  }

  private static Map<String, String> ownCard(MailMailbox owner) {
    return MailWire.decode(
        MailWire.signedPayload(
            owner.execute("export-contact", Map.of()).get("card").getBytes(StandardCharsets.UTF_8)),
        4096);
  }

  private static void assertStatus(String expected, Map<String, String> result) {
    assertEquals(expected, result.get("status"));
  }
}
