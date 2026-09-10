package network.crypta.apps.mail;

import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.LockSupport;
import network.crypta.crypt.mail.MailWire;
import network.crypta.platform.appvault.AppIdentityGrantScope;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Real vault/CAS renewal tests; no network transport or observed elapsed-time claim. */
class MailContactRenewalTest {
  @TempDir Path root;

  @Test
  void expiredOwnCardRenewsSameKeysWithSingleUseConsentAndNoNetworkMutation() throws Exception {
    var clock = new MutableClock();
    var backend = backend("alice");
    var mailbox = new MailMailbox(backend, clock);
    assertEquals("ready", mailbox.execute("initialize", Map.of()).get("status"));
    String oldCard = mailbox.execute("export-contact", Map.of()).get("card");
    clock.time = clock.time.plusSeconds(366 * 86400L);
    byte[] before = backend.storedBytes();

    var preview = mailbox.execute("preview-renew-contact", Map.of());
    assertEquals("preview", preview.get("status"));
    assertArrayEquals(before, backend.storedBytes());
    var input = Map.of("renewalToken", preview.get("renewalToken"));
    assertEquals("renewed", mailbox.execute("confirm-renew-contact", input).get("status"));

    String newCard = mailbox.execute("export-contact", Map.of()).get("card");
    assertNotEquals(oldCard, newCard);
    var oldFields = card(oldCard);
    var newFields = card(newCard);
    oldFields.remove("created");
    oldFields.remove("expires");
    newFields.remove("created");
    newFields.remove("expires");
    assertEquals(oldFields, newFields);
    assertEquals(3, backend.vault.listIdentities().size());
    assertEquals(0, backend.network.size());
    assertEquals(
        "renewal-approval-required", mailbox.execute("confirm-renew-contact", input).get("status"));
  }

  @Test
  void expiryDatasetChangeRestartAndRevocationDenyApprovalWithoutReplacement() throws Exception {
    for (String scenario : new String[] {"expiry", "dataset", "restart", "revoked"}) {
      var clock = new MutableClock();
      var backend = backend(scenario);
      var mailbox = new MailMailbox(backend, clock);
      mailbox.execute("initialize", Map.of());
      clock.time = clock.time.plusSeconds(1);
      var preview = mailbox.execute("preview-renew-contact", Map.of());
      assertEquals("preview", preview.get("status"));
      switch (scenario) {
        case "expiry" -> clock.time = clock.time.plusSeconds(30);
        case "dataset" -> {
          String own = mailbox.execute("export-contact", Map.of()).get("card");
          mailbox.execute("import-contact", Map.of("card", own));
        }
        case "restart" -> mailbox = new MailMailbox(backend, clock);
        case "revoked" ->
            backend.vault.revokeGrant(
                backend.vault.listGrantsForApp(MailTestBackend.APP).getFirst().grantId());
        default -> throw new AssertionError();
      }
      byte[] before = backend.storedBytes();
      String expected =
          scenario.equals("revoked") ? "key-unavailable" : "renewal-approval-required";
      assertEquals(
          expected,
          mailbox
              .execute("confirm-renew-contact", Map.of("renewalToken", preview.get("renewalToken")))
              .get("status"),
          scenario);
      assertArrayEquals(before, backend.storedBytes(), scenario);
      assertEquals(3, backend.vault.listIdentities().size());
    }
  }

  @Test
  void remoteRenewalRequiresExplicitApprovalAndInvalidatesSendPreview() throws Exception {
    var clock = new MutableClock();
    var alice = new MailMailbox(backend("sender"), clock);
    var bob = new MailMailbox(backend("recipient"), clock);
    alice.execute("initialize", Map.of());
    bob.execute("initialize", Map.of());
    String oldCard = bob.execute("export-contact", Map.of()).get("card");
    var imported = alice.execute("import-contact", Map.of("card", oldCard));
    String fingerprint = imported.get("fingerprint");
    alice.execute("approve-contact", Map.of("fingerprint", fingerprint));
    alice.execute(
        "save-draft",
        Map.of("fingerprint", fingerprint, "subject", "Synthetic", "body", "Renewal test"));
    var sendPreview = alice.execute("preview-send", Map.of());
    clock.time = clock.time.plusSeconds(1);
    var renewal = bob.execute("preview-renew-contact", Map.of());
    bob.execute("confirm-renew-contact", Map.of("renewalToken", renewal.get("renewalToken")));
    String renewed = bob.execute("export-contact", Map.of()).get("card");

    alice.execute("import-contact", Map.of("card", renewed));
    assertEquals(
        "contact-approved",
        alice.execute("approve-contact", Map.of("fingerprint", fingerprint)).get("status"));
    assertEquals(
        "approval-required",
        alice
            .execute("confirm-send", Map.of("approval", sendPreview.get("approval")))
            .get("status"));
    alice.execute("import-contact", Map.of("card", oldCard));
    assertEquals(
        "pin-change-blocked",
        alice.execute("approve-contact", Map.of("fingerprint", fingerprint)).get("status"));
  }

  @Test
  void historyCapacityDeniesRenewalWithoutEvictingPriorCards() throws Exception {
    var clock = new MutableClock();
    var backend = backend("capacity");
    var mailbox = new MailMailbox(backend, clock);
    mailbox.execute("initialize", Map.of());
    for (int index = 0; index < 3; index++) {
      clock.time = clock.time.plusSeconds(1);
      var preview = mailbox.execute("preview-renew-contact", Map.of());
      assertEquals("preview", preview.get("status"));
      assertEquals(
          "renewed",
          mailbox
              .execute("confirm-renew-contact", Map.of("renewalToken", preview.get("renewalToken")))
              .get("status"));
    }
    clock.time = clock.time.plusSeconds(1);
    byte[] before = backend.storedBytes();
    assertEquals(
        "contact-history-capacity",
        mailbox.execute("preview-renew-contact", Map.of()).get("status"));
    assertArrayEquals(before, backend.storedBytes());
    assertEquals(
        3,
        backend.privateState().keySet().stream()
            .filter(key -> key.startsWith("own-card-history."))
            .count());
  }

  @Test
  void expirationOrClockRollbackDuringStorageSealingCannotPublishRenewal() throws Exception {
    for (boolean backwards : new boolean[] {false, true}) {
      var clock = new MutableClock();
      var backend = backend("seal-clock-" + backwards);
      new MailMailbox(backend, clock).execute("initialize", Map.of());
      clock.time = clock.time.plusSeconds(1);
      MailBackend delayed =
          (method, path, parameters) -> {
            var result = backend.request(method, path, parameters);
            if (path.equals("/mail/seal-storage"))
              clock.time = clock.time.plusSeconds(backwards ? -1 : 30);
            return result;
          };
      var mailbox = new MailMailbox(delayed, clock);
      var preview = mailbox.execute("preview-renew-contact", Map.of());
      assertEquals("preview", preview.get("status"));
      var consent = Map.of("renewalToken", preview.get("renewalToken"));
      byte[] before = backend.storedBytes();

      assertEquals(
          "renewal-approval-required",
          mailbox.execute("confirm-renew-contact", consent).get("status"));

      assertArrayEquals(before, backend.storedBytes());
      assertEquals(
          "renewal-approval-required",
          mailbox.execute("confirm-renew-contact", consent).get("status"));
      assertEquals(3, backend.vault.listIdentities().size());
    }
  }

  @Test
  void independentlyExpiringRecipientPurposeIsRecheckedByVaultAfterStorageSealing()
      throws Exception {
    var clock = new MutableClock();
    var backend = backend("recipient-purpose-expiry");
    new MailMailbox(backend, clock).execute("initialize", Map.of());
    clock.time = clock.time.plusSeconds(1);
    String recipient = backend.privateState().get("recipientId");
    for (var grant : backend.vault.listGrantsForApp(MailTestBackend.APP)) {
      if (grant.identityId().equals(recipient)) backend.vault.revokeGrant(grant.grantId());
    }
    backend.vault.grantIdentity(
        recipient,
        MailTestBackend.APP,
        Set.of(AppIdentityGrantScope.METADATA_READ),
        "synthetic-test",
        "Independent metadata",
        null,
        null);
    Instant purposeExpiry = Instant.now().plusSeconds(5);
    backend.vault.grantIdentity(
        recipient,
        MailTestBackend.APP,
        Set.of(AppIdentityGrantScope.MAIL_OPEN),
        "synthetic-test",
        "Expiring recipient purpose",
        purposeExpiry,
        null);
    var grantSnapshot = backend.request("GET", "/app-vault/grants", Map.of());
    var sealed = new AtomicBoolean();
    MailBackend delayed =
        (method, path, parameters) -> {
          var result = backend.request(method, path, parameters);
          if (path.equals("/mail/seal-storage")) {
            sealed.set(true);
            // Real vault time controls purpose expiry; the worker's fake policy clock stays fixed.
            long deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(10);
            while (Instant.now().isBefore(purposeExpiry)) {
              if (Thread.currentThread().isInterrupted() || System.nanoTime() >= deadline)
                throw new AssertionError("Vault expiry wait did not complete");
              LockSupport.parkNanos(10_000_000L);
            }
          }
          return result;
        };
    var mailbox = new MailMailbox(delayed, clock);
    var preview = mailbox.execute("preview-renew-contact", Map.of());
    assertEquals("preview", preview.get("status"));
    byte[] before = backend.storedBytes();

    assertEquals(
        "key-unavailable",
        mailbox
            .execute("confirm-renew-contact", Map.of("renewalToken", preview.get("renewalToken")))
            .get("status"));

    assertArrayEquals(before, backend.storedBytes());
    assertTrue(sealed.get(), "Must reach storage sealing before testing the final purpose fence");
    assertEquals(grantSnapshot, backend.request("GET", "/app-vault/grants", Map.of()));
    assertEquals(3, backend.vault.listIdentities().size());
    assertEquals(
        recipient, backend.vault.getIdentityForApp(MailTestBackend.APP, recipient).identityId());
  }

  private MailTestBackend backend(String name) throws Exception {
    return new MailTestBackend(
        root.resolve(name + "-vault"), root.resolve(name + "-data"), new LinkedHashMap<>());
  }

  private static Map<String, String> card(String value) {
    return MailWire.decode(
        MailWire.signedPayload(value.getBytes(java.nio.charset.StandardCharsets.UTF_8)), 4096);
  }

  private static final class MutableClock extends Clock {
    Instant time = Instant.parse("2026-09-07T12:00:00Z");

    @Override
    public ZoneId getZone() {
      return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(ZoneId zone) {
      return this;
    }

    @Override
    public Instant instant() {
      return time;
    }
  }
}
