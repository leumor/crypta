package network.crypta.platform.api.appvault;

import java.nio.file.Path;
import java.time.Instant;
import java.util.Set;
import network.crypta.platform.appvault.AppIdentityGrantScope;
import network.crypta.platform.appvault.AppIdentityKind;
import network.crypta.platform.appvault.AppVaultException;
import network.crypta.platform.appvault.AppVaultService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Mail identity-list preflight must not represent grant-hidden retained keys as an empty vault. */
class AppVaultApiHandlerTest {
  private static final String MAIL = "mail-prototype";
  @TempDir Path root;

  @Test
  void mailListWithRevokedExpiredOrMetadataHiddenIdentityFailsWithoutExposingIt() throws Exception {
    for (String state : new String[] {"revoked", "expired", "metadata-hidden"}) {
      AppVaultService vault = AppVaultService.open(root.resolve(state));
      var signing = vault.createMailIdentity(MAIL, AppIdentityKind.MAIL_SIGNING_V1);
      vault.revokeGrantsForApp(MAIL);
      if (state.equals("expired")) {
        vault.grantIdentity(
            signing.identityId(),
            MAIL,
            Set.of(AppIdentityGrantScope.METADATA_READ, AppIdentityGrantScope.MAIL_SIGN),
            "operator",
            "Expired synthetic authority",
            Instant.EPOCH,
            null);
      } else if (state.equals("metadata-hidden")) {
        vault.grantIdentity(
            signing.identityId(),
            MAIL,
            Set.of(AppIdentityGrantScope.MAIL_SIGN),
            "operator",
            "Synthetic purpose only",
            null,
            null);
      }
      var identities = vault.listIdentities();
      var grants = vault.listGrantsForApp(MAIL);
      AppVaultApiHandler handler = new AppVaultApiHandler(vault);
      assertTrue(vault.listIdentitiesForApp(MAIL).isEmpty());

      AppVaultException failure =
          assertThrows(AppVaultException.class, () -> handler.listIdentities(MAIL));

      assertEquals("key_unavailable", failure.errorCode());
      assertFalse(failure.getMessage().contains(signing.identityId()));
      assertFalse(failure.getMessage().contains(signing.fingerprint()));
      assertEquals(identities, vault.listIdentities());
      assertEquals(grants, vault.listGrantsForApp(MAIL));
      assertTrue(handler.listIdentities("unrelated-app").isEmpty());
    }
  }

  @Test
  void mailListAllowsActuallyEmptyVaultAndCurrentlyAuthorizedRetainedKeys() throws Exception {
    AppVaultService vault = AppVaultService.open(root.resolve("available"));
    AppVaultApiHandler handler = new AppVaultApiHandler(vault);
    assertTrue(handler.listIdentities(MAIL).isEmpty());
    vault.createMailIdentity(MAIL, AppIdentityKind.MAIL_SIGNING_V1);
    vault.createMailIdentity(MAIL, AppIdentityKind.MAIL_RECIPIENT_V1);
    vault.createMailIdentity(MAIL, AppIdentityKind.MAIL_STORAGE_V1);

    assertEquals(3, handler.listIdentities(MAIL).size());
  }
}
