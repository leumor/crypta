package network.crypta.apps.mail;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import network.crypta.crypt.mail.MailWire;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.*;

/** Actual encoded-byte capacity and restore authority regression checks with real vault/storage. */
class MailMailboxBoundsTest {
  @TempDir Path root;
  private final Clock clock = Clock.fixed(Instant.parse("2026-09-07T12:00:00Z"), ZoneOffset.UTC);
  private MailTestBackend backend;
  private MailMailbox mailbox;
  private MailMailbox other;
  private String fingerprint;

  @BeforeEach
  void initializeSeparateAccountsAndPin() throws Exception {
    Map<String, byte[]> network = new LinkedHashMap<>();
    backend = new MailTestBackend(root.resolve("vault"), root.resolve("data"), network);
    mailbox = new MailMailbox(backend, clock);
    other =
        new MailMailbox(
            new MailTestBackend(root.resolve("other-vault"), root.resolve("other-data"), network),
            clock);
    status("ready", mailbox.execute("initialize", Map.of()));
    status("ready", other.execute("initialize", Map.of()));
    String card = other.execute("export-contact", Map.of()).get("card");
    fingerprint = mailbox.execute("import-contact", Map.of("card", card)).get("fingerprint");
    status(
        "contact-approved", mailbox.execute("approve-contact", Map.of("fingerprint", fingerprint)));
  }

  @Test
  void reorderedContactPayloadCannotReuseCanonicalSignature() {
    byte[] card =
        other.execute("export-contact", Map.of()).get("card").getBytes(StandardCharsets.UTF_8);
    var payload = MailWire.decode(MailWire.signedPayload(card), 4096);
    var keys = new ArrayList<>(payload.keySet());
    Collections.reverse(keys);
    var reordered = new LinkedHashMap<String, String>();
    for (String key : keys) reordered.put(key, payload.get(key));
    byte[] changed = MailWire.signed(MailWire.encode(reordered), MailWire.signature(card));
    var result =
        mailbox.execute(
            "import-contact", Map.of("card", new String(changed, StandardCharsets.UTF_8)));
    assertTrue(
        List.of("invalid", "invalid-contact").contains(result.get("status")), result.toString());
  }

  @Test
  void oldBackupCannotResurrectCurrentContactRevocation() {
    String backup = mailbox.execute("backup", Map.of()).get("backup");
    status(
        "contact-revoked", mailbox.execute("revoke-contact", Map.of("fingerprint", fingerprint)));
    status(
        "recovery-paused",
        mailbox.execute("restore", Map.of("confirmed", "yes", "backup", backup)));
    status(
        "contact-revoked",
        mailbox.execute(
            "save-draft",
            Map.of(
                "fingerprint", fingerprint, "subject", "synthetic", "body", "public synthetic")));
    assertTrue(backend.insertionBytes.isEmpty());
  }

  @Test
  void nearCapacityBackupAndRestoreFitActualPrivateFrames() throws Exception {
    // A private fixture filler controls exact encoded state bytes without publishing data.
    fillStateTo(112 * 1024 - 128);
    var backup = mailbox.execute("backup", Map.of());
    status("private-data-only-backup", backup);
    byte[] response = MailWire.encode(backup);
    assertTrue(MailWire.base64(response).length() <= 393216, "worker reply must fit broker");
    var restore = Map.of("confirmed", "yes", "backup", backup.get("backup"));
    byte[] request = MailWire.encode(restore);
    assertTrue(request.length <= 280000, "restore must fit the SDK JSON byte limit");
    assertTrue(MailWire.base64(request).length() <= 393216, "restore must fit the broker");
    status("recovery-paused", mailbox.execute("restore", restore));
    assertTrue(backend.storedBytes().length <= 262144);
  }

  @Test
  void pendingInsertionCanRecordReferenceAtReservedCompletionBoundary() throws Exception {
    status(
        "draft",
        mailbox.execute(
            "save-draft",
            Map.of(
                "fingerprint",
                fingerprint,
                "subject",
                "synthetic",
                "body",
                "public synthetic completion")));
    String approval = mailbox.execute("preview-send", Map.of()).get("approval");
    var queued = mailbox.execute("confirm-send", Map.of("approval", approval));
    status("queued", queued);
    fillStateTo(112 * 1024 - 256);
    var completed = mailbox.execute("retry", Map.of("operation", queued.get("operation")));
    status("inserted", completed);
    assertTrue(completed.get("reference").startsWith("CHK@"));
    assertEquals(1, backend.insertionBytes.size());
    assertTrue(MailWire.encode(backend.privateState()).length <= 112 * 1024);
  }

  @Test
  void escapedOversizeDraftRejectsBeforeReplacingSavedDraftOrApproval() {
    status(
        "draft",
        mailbox.execute(
            "save-draft",
            Map.of(
                "fingerprint",
                fingerprint,
                "subject",
                "Public synthetic",
                "body",
                "Retained draft")));
    var preview = mailbox.execute("preview-send", Map.of());
    status("approval-required", preview);
    byte[] before = backend.storedBytes();

    for (String body :
        List.of("\n".repeat(6000), "\n".repeat(5000), "\"".repeat(16384), "\\".repeat(16384))) {
      status(
          "quota",
          mailbox.execute(
              "save-draft",
              Map.of("fingerprint", fingerprint, "subject", "Public synthetic", "body", body)));
      assertArrayEquals(before, backend.storedBytes());
      assertTrue(backend.insertionBytes.isEmpty());
    }
    status("queued", mailbox.execute("confirm-send", Map.of("approval", preview.get("approval"))));
  }

  @Test
  void largestAcceptedEscapedDraftPreviewsSendsAndDecryptsAfterRestart() {
    String card = mailbox.execute("export-contact", Map.of()).get("card");
    String sender = other.execute("import-contact", Map.of("card", card)).get("fingerprint");
    status("contact-approved", other.execute("approve-contact", Map.of("fingerprint", sender)));
    String subject = "\t".repeat(256);
    int accepted = 0;
    int rejected = 6000;
    while (accepted + 1 < rejected) {
      int candidate = (accepted + rejected) / 2;
      var result =
          mailbox.execute(
              "save-draft",
              Map.of(
                  "fingerprint", fingerprint, "subject", subject, "body", "\n".repeat(candidate)));
      if ("draft".equals(result.get("status"))) accepted = candidate;
      else {
        status("quota", result);
        rejected = candidate;
      }
    }
    assertTrue(accepted > 2500);
    String body = "\n".repeat(accepted);
    status(
        "draft",
        mailbox.execute(
            "save-draft", Map.of("fingerprint", fingerprint, "subject", subject, "body", body)));
    mailbox = new MailMailbox(backend, clock);
    var preview = mailbox.execute("preview-send", Map.of());
    status("approval-required", preview);
    assertEquals(subject, preview.get("subject"));
    assertEquals(body, preview.get("body"));
    byte[] before = backend.storedBytes();
    status(
        "quota",
        mailbox.execute(
            "save-draft",
            Map.of("fingerprint", fingerprint, "subject", subject, "body", body + "\n")));
    assertArrayEquals(before, backend.storedBytes());

    var queued = mailbox.execute("confirm-send", Map.of("approval", preview.get("approval")));
    status("queued", queued);
    var inserted = mailbox.execute("retry", Map.of("operation", queued.get("operation")));
    status("inserted", inserted);
    var received =
        other.execute(
            "import-reference", Map.of("confirmed", "yes", "reference", inserted.get("reference")));
    status("accepted", received);
    var read = other.execute("read", Map.of("messageId", received.get("messageId")));
    assertEquals(subject, read.get("subject"));
    assertEquals(body, read.get("body"));
    assertEquals(1, backend.insertionBytes.size());
  }

  private void fillStateTo(int bytes) throws Exception {
    var state = new LinkedHashMap<>(backend.privateState());
    state.put("testCapacityFiller", "");
    int count = bytes - MailWire.encode(state).length;
    assertTrue(count > 0);
    state.put("testCapacityFiller", "x".repeat(count));
    assertEquals(bytes, MailWire.encode(state).length);
    byte[] envelope =
        backend.vault.sealStorage(
            MailTestBackend.APP, state.get("storageId"), MailWire.encode(state));
    var wrapper = new LinkedHashMap<String, String>();
    wrapper.put("storageId", state.get("storageId"));
    wrapper.put("envelope", MailWire.base64(envelope));
    backend.request(
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
  }

  private static void status(String expected, Map<String, String> result) {
    assertEquals(expected, result.get("status"), result.toString());
  }
}
