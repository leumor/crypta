package network.crypta.platform.apphost.runtime;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicBoolean;
import network.crypta.platform.appdist.AppBundlePackager;
import network.crypta.platform.appdist.AppBundleSigner;
import network.crypta.platform.appdist.AppBundleVerifier;
import network.crypta.platform.appdist.TrustedAppKey;
import network.crypta.platform.appdist.TrustedAppKeys;
import network.crypta.platform.apphost.AppHost;
import network.crypta.platform.apphost.AppHostLayout;
import network.crypta.platform.apphost.AppInstallVerificationPolicy;
import network.crypta.platform.apphost.FileInstalledAppOriginStore;
import network.crypta.platform.apphost.InstalledAppOrigin;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Exercises owner transactions; catalog admission is covered by the packaged API integration. */
class CatalogMutationRecoveryTest {
  private static final String APP_ID = "recovery-fixture";
  private static final String HASH = "1".repeat(64);
  @TempDir Path temporary;
  private AppHostLayout layout;
  private KeyPair publisher;
  private AppBundleVerifier verifier;
  private AppInstallVerificationPolicy policy;

  @BeforeEach
  void setUp() throws Exception {
    layout =
        new AppHostLayout(
            temporary.resolve("data"), temporary.resolve("cache"), temporary.resolve("run"));
    publisher = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    verifier =
        AppBundleVerifier.requireSigned(
            TrustedAppKeys.of(
                TrustedAppKey.ed25519("publisher", publisher.getPublic().getEncoded())));
    policy =
        AppInstallVerificationPolicy.requireSignedWithIdentity(verifier::verify, verifier::verify);
  }

  @Test
  void install_whenRetentionInterruptsActiveMutation_expectUninstalledStateRecovered()
      throws Exception {
    Bundle initial = bundle("1", "catalog-a", null);
    Retention retention = new Retention();
    LocalProcessAppHost interrupted = host(retention);
    AtomicBoolean authorized = new AtomicBoolean();
    AtomicBoolean released = new AtomicBoolean();
    retention.interrupt = true;
    Path initialDirectory = initial.directory();
    InstalledAppOrigin initialOrigin = initial.origin();
    var installAuthorization = authorization(initialOrigin, authorized, released);

    assertThrows(
        SimulatedTermination.class,
        () ->
            interrupted.installCatalogFromDirectory(
                initialDirectory, initialOrigin, installAuthorization));

    assertTrue(authorized.get());
    assertTrue(released.get());
    assertTrue(Files.isDirectory(activeTransaction()));
    assertEquals(initial.origin(), origins().find(APP_ID).orElseThrow());
    assertEquals(tree(initial.directory()), tree(layout.pathsFor(APP_ID).installedRoot()));
    retention.interrupt = false;
    LocalProcessAppHost recovered = host(retention);
    assertTrue(recovered.describe(APP_ID).isEmpty());
    assertTrue(recovered.catalogOrigin(APP_ID).isEmpty());
    assertTrue(recovered.rollbackStatus(APP_ID).isEmpty());
    assertEquals(Set.of(), retention.pins);
    assertFalse(Files.exists(activeTransaction()));
  }

  @Test
  void update_whenRetentionInterruptsActiveMutation_expectExactCurrentAndRollbackRestored()
      throws Exception {
    interruptedReplacement("catalog-a");
  }

  @Test
  void sourceSwitch_whenRetentionInterruptsActiveMutation_expectOriginalCatalogAndPinsRestored()
      throws Exception {
    interruptedReplacement("catalog-b");
  }

  private void interruptedReplacement(String targetCatalog) throws Exception {
    Retention retention = new Retention();
    LocalProcessAppHost original = host(retention);
    Bundle initial = bundle("1", "catalog-a", null);
    original.installCatalogFromDirectory(initial.directory(), initial.origin());
    Bundle current = bundle("2", "catalog-a", initial.origin());
    original.updateCatalogFromDirectory(APP_ID, current.directory(), current.origin());
    Map<String, String> priorCurrent = tree(layout.pathsFor(APP_ID).installedRoot());
    Map<String, String> priorRollback = tree(layout.rollbackAppsDir().resolve(APP_ID));
    FileInstalledAppOriginStore.State priorOrigins = origins().snapshot(APP_ID);
    Set<InstalledAppOrigin> priorPins = retention.pins;
    Path data = layout.pathsFor(APP_ID).dataDir().resolve("shared-data-canary");
    Files.writeString(data, "shared data survives bundle recovery");
    Bundle attempted = bundle("3", targetCatalog, current.origin());
    LocalProcessAppHost interrupted = host(retention);
    AtomicBoolean authorized = new AtomicBoolean();
    AtomicBoolean released = new AtomicBoolean();
    retention.interrupt = true;
    Path attemptedDirectory = attempted.directory();
    InstalledAppOrigin attemptedOrigin = attempted.origin();
    var expectedOrigin =
        AppHost.CatalogOriginExpectation.matching(current.origin().selfDigestSha256());
    var updateAuthorization = authorization(attemptedOrigin, authorized, released);

    assertThrows(
        SimulatedTermination.class,
        () ->
            interrupted.updateCatalogFromDirectory(
                APP_ID, attemptedDirectory, attemptedOrigin, expectedOrigin, updateAuthorization));

    assertTrue(authorized.get());
    assertTrue(released.get());
    assertTrue(Files.isDirectory(activeTransaction()));
    assertEquals(attempted.origin(), origins().find(APP_ID).orElseThrow());
    assertNotEquals(priorCurrent, tree(layout.pathsFor(APP_ID).installedRoot()));
    assertEquals(tree(attempted.directory()), tree(layout.pathsFor(APP_ID).installedRoot()));
    retention.interrupt = false;
    LocalProcessAppHost recovered = host(retention);
    assertEquals(current.origin(), recovered.catalogOrigin(APP_ID).orElseThrow());
    assertEquals("2", recovered.describe(APP_ID).orElseThrow().manifest().appVersion());
    assertEquals("1", recovered.rollbackStatus(APP_ID).orElseThrow().appVersion());
    assertEquals(priorCurrent, tree(layout.pathsFor(APP_ID).installedRoot()));
    assertEquals(priorRollback, tree(layout.rollbackAppsDir().resolve(APP_ID)));
    assertEquals(priorOrigins, origins().snapshot(APP_ID));
    assertEquals(priorPins, retention.pins);
    assertEquals("shared data survives bundle recovery", Files.readString(data));
    assertFalse(Files.exists(activeTransaction()));
    // Recovery is stable on a second ordinary host construction, without rewriting origin records.
    assertEquals(current.origin(), host(retention).catalogOrigin(APP_ID).orElseThrow());
  }

  private static AppHost.CatalogMutationAuthorization authorization(
      InstalledAppOrigin expected, AtomicBoolean authorized, AtomicBoolean released) {
    return actual -> {
      assertEquals(expected, actual);
      authorized.set(true);
      return () -> released.set(true);
    };
  }

  private LocalProcessAppHost host(Retention retention) throws IOException {
    LocalProcessAppHost host = new LocalProcessAppHost(layout, policy);
    host.setCatalogOriginRetention(retention);
    return host;
  }

  private Bundle bundle(String version, String catalogId, InstalledAppOrigin previous)
      throws Exception {
    Path root = Files.createDirectory(temporary.resolve("bundle-" + version));
    Path bin = Files.createDirectory(root.resolve("bin"));
    Path executable = bin.resolve("launch.sh");
    Files.writeString(executable, "#!/bin/sh\nexit 0\n");
    if (Files.getFileStore(root).supportsFileAttributeView("posix")) {
      Files.setPosixFilePermissions(executable, PosixFilePermissions.fromString("rwx------"));
    }
    Files.createDirectory(root.resolve("static"));
    Files.writeString(root.resolve("static/index.html"), "Synthetic version " + version);
    Files.writeString(
        root.resolve("cryptad-app.properties"),
        "manifest.version=1\napp.id="
            + APP_ID
            + "\napp.name=Synthetic recovery fixture\napp.version="
            + version
            + "\napp.exec=bin/launch.sh\napp.ui.mode=static\napp.ui.entry=static/index.html\n");
    AppBundleSigner.sign(root, "publisher", publisher.getPrivate());
    var identity = verifier.verify(root);
    Path artifact = temporary.resolve("bundle-" + version + ".zip");
    AppBundlePackager.packageBundle(root, artifact);
    String bundleDigest =
        HexFormat.of()
            .formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(artifact)));
    InstalledAppOrigin origin =
        InstalledAppOrigin.create(
            APP_ID,
            version,
            bundleDigest,
            catalogId,
            catalogId + "-signer",
            HASH,
            version.repeat(64),
            identity.keyId(),
            identity.keyFingerprintSha256(),
            identity.signedContentDigestSha256(),
            HASH,
            "trusted_reviewed",
            catalogId + "-binding",
            HASH,
            HASH,
            HASH,
            Instant.parse("2026-09-11T00:00:00Z"),
            previous == null ? null : previous.selfDigestSha256());
    return new Bundle(root, origin);
  }

  private FileInstalledAppOriginStore origins() {
    return new FileInstalledAppOriginStore(layout.appOriginProvenanceDir());
  }

  private Path activeTransaction() {
    return layout.appMutationTransactionsDir().resolve(APP_ID + ".active");
  }

  private static Map<String, String> tree(Path root) throws IOException {
    Map<String, String> bytes = new TreeMap<>();
    try (var paths = Files.walk(root)) {
      for (Path file : paths.filter(Files::isRegularFile).toList()) {
        bytes.put(
            root.relativize(file).toString(),
            Base64.getEncoder().encodeToString(Files.readAllBytes(file)));
      }
    }
    return bytes;
  }

  private record Bundle(Path directory, InstalledAppOrigin origin) {}

  /** Existing production retention dependency is the failure seam immediately before commit. */
  private static final class Retention implements AppHost.CatalogOriginRetention {
    private boolean interrupt;
    private Set<InstalledAppOrigin> pins = Set.of();

    @Override
    public void retain(List<InstalledAppOrigin> origins) {
      pins = Set.copyOf(origins);
      if (interrupt) throw new SimulatedTermination();
    }

    @Override
    public void reconcile(List<InstalledAppOrigin> origins) {
      pins = Set.copyOf(origins);
    }
  }

  /** Models abrupt termination that cannot execute IOException/RuntimeException compensation. */
  private static final class SimulatedTermination extends Error {}
}
