package network.crypta.apps.mail;

import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.Map;
import network.crypta.platform.appvault.AppIdentityKind;
import network.crypta.platform.appvault.AppIdentityRecord;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.*;

/** Restart recovery against durable independent vault and app-data stores. */
class MailInitializationTest {
  @TempDir Path root;
  private final Clock clock = Clock.fixed(Instant.parse("2026-09-07T12:00:00Z"), ZoneOffset.UTC);

  @Test
  void everySetupOperationCanFailBeforeOrAfterItsResponseWithoutOrphaningTheAccount()
      throws Exception {
    var baseline = backend(root.resolve("baseline"));
    var observed = new Faults(baseline, 0, false);
    assertEquals(
        "ready", new MailMailbox(observed, clock).execute("initialize", Map.of()).get("status"));
    assertEquals(7, observed.operations);
    for (boolean after : new boolean[] {false, true}) {
      for (int operation = 1; operation <= observed.operations; operation++) {
        Path installation = root.resolve("fault-" + operation + "-" + after);
        var initial = backend(installation);
        var faults = new Faults(initial, operation, after);
        assertEquals(
            "store-unavailable",
            new MailMailbox(faults, clock).execute("initialize", Map.of()).get("status"));
        var retained =
            initial.vault.listIdentities().stream().map(AppIdentityRecord::identityId).toList();

        // Reopen both durable stores, discarding every worker field and the lost response.
        var reopened = backend(installation);
        var restarted = new MailMailbox(reopened, clock);
        assertEquals("ready", restarted.execute("initialize", Map.of()).get("status"));
        var recovered =
            reopened.vault.listIdentities().stream().map(AppIdentityRecord::identityId).toList();
        assertEquals(3, recovered.size());
        assertTrue(recovered.containsAll(retained), "Recovery replaced a retained identity.");
        byte[] committed = reopened.storedBytes();
        assertEquals("1", reopened.privateState().get("schema"));
        assertEquals("ready", restarted.execute("initialize", Map.of()).get("status"));
        assertArrayEquals(committed, reopened.storedBytes());
        assertTrue(reopened.network.isEmpty());
      }
    }
  }

  @Test
  void completedMailboxWithMissingDataCannotBeReinitialized() throws Exception {
    var backend = backend(root);
    var mailbox = new MailMailbox(backend, clock);
    assertEquals("ready", mailbox.execute("initialize", Map.of()).get("status"));
    var retained = backend.vault.listIdentities();
    backend.data.deleteRecord(MailTestBackend.APP, "mail-state", "dataset");

    assertEquals(
        "recovery-required",
        new MailMailbox(backend, clock).execute("initialize", Map.of()).get("status"));
    assertEquals(retained, backend.vault.listIdentities());
  }

  @Test
  void unmarkedLegacyPartialSetupRemainsBlockedAndDoesNotMintKeys() throws Exception {
    var backend = backend(root);
    backend.vault.createMailIdentity(MailTestBackend.APP, AppIdentityKind.MAIL_SIGNING_V1);
    var retained = backend.vault.listIdentities();

    assertEquals(
        "recovery-required",
        new MailMailbox(backend, clock).execute("initialize", Map.of()).get("status"));
    assertEquals(retained, backend.vault.listIdentities());
  }

  @Test
  void ambiguousRetainedRolesInMarkedSetupRemainBlocked() throws Exception {
    var backend = backend(root);
    assertEquals(
        "store-unavailable",
        new MailMailbox(new Faults(backend, 2, true), clock)
            .execute("initialize", Map.of())
            .get("status"));
    backend.vault.createMailIdentity(MailTestBackend.APP, AppIdentityKind.MAIL_SIGNING_V1);
    byte[] marker = backend.storedBytes();

    assertEquals(
        "recovery-required",
        new MailMailbox(backend, clock).execute("initialize", Map.of()).get("status"));
    assertArrayEquals(marker, backend.storedBytes());
    assertEquals(2, backend.vault.listIdentities().size());
  }

  @Test
  void revokedKeysNeverBecomeReplacementAccountDuringSetupOrAfterDataLoss() throws Exception {
    for (boolean completed : new boolean[] {false, true}) {
      var backend = backend(root.resolve("revoked-" + completed));
      MailBackend setup = completed ? backend : new Faults(backend, 2, true);
      assertEquals(
          completed ? "ready" : "store-unavailable",
          new MailMailbox(setup, clock).execute("initialize", Map.of()).get("status"));
      if (completed) backend.data.deleteRecord(MailTestBackend.APP, "mail-state", "dataset");
      backend.vault.revokeGrantsForApp(MailTestBackend.APP);
      var identities = backend.vault.listIdentities();
      var grants = backend.vault.listGrantsForApp(MailTestBackend.APP);
      assertTrue(backend.vault.listIdentitiesForApp(MailTestBackend.APP).isEmpty());

      assertEquals(
          "key-unavailable",
          new MailMailbox(backend, clock).execute("initialize", Map.of()).get("status"));
      assertEquals(identities, backend.vault.listIdentities());
      assertEquals(grants, backend.vault.listGrantsForApp(MailTestBackend.APP));
      if (completed)
        assertThrows(
            network.crypta.platform.api.PlatformApiException.class,
            () -> backend.data.getRecord(MailTestBackend.APP, "mail-state", "dataset"));
    }
  }

  @Test
  void restoredRawSetupMarkerFlagsPersistentRecoveryEpochInsteadOfClaimingFreshHistory()
      throws Exception {
    var backend = backend(root);
    assertEquals(
        "store-unavailable",
        new MailMailbox(new Faults(backend, 2, true), clock)
            .execute("initialize", Map.of())
            .get("status"));
    var marker = backend.data.getRecord(MailTestBackend.APP, "mail-state", "dataset");
    var mailbox = new MailMailbox(backend, clock);
    var resumed = mailbox.execute("initialize", Map.of());
    String firstEpoch = resumed.get("initializationRecoveryEpoch");
    assertNotNull(firstEpoch);
    assertEquals(
        firstEpoch,
        new MailMailbox(backend, clock)
            .execute("status", Map.of())
            .get("initializationRecoveryEpoch"));
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
            (String) marker.get("valueBase64")));

    var recovered = new MailMailbox(backend, clock).execute("initialize", Map.of());

    assertEquals("ready", recovered.get("status"));
    assertNotNull(recovered.get("initializationRecoveryEpoch"));
    assertNotEquals(firstEpoch, recovered.get("initializationRecoveryEpoch"));
    assertTrue(recovered.get("note").contains("Prior replay history cannot be verified"));
    assertEquals(3, backend.vault.listIdentities().size());
  }

  private MailTestBackend backend(Path installation) throws Exception {
    return new MailTestBackend(
        installation.resolve("vault"), installation.resolve("data"), new LinkedHashMap<>());
  }

  private static final class Faults implements MailBackend {
    private final MailTestBackend delegate;
    private final int failAt;
    private final boolean after;
    private int operations;

    Faults(MailTestBackend delegate, int failAt, boolean after) {
      this.delegate = delegate;
      this.failAt = failAt;
      this.after = after;
    }

    @Override
    public Map<String, Object> request(String method, String path, Map<String, String> parameters) {
      boolean fail = "POST".equals(method) && ++operations == failAt;
      if (fail && !after) throw new MailFailure("store-unavailable");
      var result = delegate.request(method, path, parameters);
      if (fail) throw new MailFailure("store-unavailable");
      return result;
    }
  }
}
