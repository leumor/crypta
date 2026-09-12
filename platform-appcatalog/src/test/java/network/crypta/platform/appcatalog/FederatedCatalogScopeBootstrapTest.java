package network.crypta.platform.appcatalog;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FederatedCatalogScopeBootstrapTest {
  private static final String HASH = "a".repeat(64);
  private static final Instant NOW = Instant.parse("2026-09-11T00:00:00Z");
  @TempDir Path temporary;

  @Test
  void bootstrap_whenExactApprovedScopes_expectNativeStoresAndNoCatalogAuthority()
      throws Exception {
    Path input = handoff("fixture-app");
    Path target = temporary.resolve("apps");

    var result = FederatedCatalogScopeBootstrap.bootstrap(target, input, manifestDigest(input));

    assertEquals(1, result.size());
    assertEquals("fixture-catalog", result.getFirst().catalogId());
    var publishers =
        new FileCatalogPublisherBindingStore(target.resolve("catalog-publisher-bindings"));
    var reviewers = new FileCatalogReviewerScopeStore(target.resolve("catalog-reviewer-scopes"));
    assertTrue(
        publishers
            .findAuthorization(
                "fixture-catalog", "fixture-app", "publisher", HASH, AppCatalogChannel.STABLE, NOW)
            .isPresent());
    assertEquals(
        publishers.policyDigest("fixture-catalog"),
        result.getFirst().publisherPolicyDigestSha256());
    assertEquals(
        reviewers.policyDigest("fixture-catalog"), result.getFirst().reviewerPolicyDigestSha256());
    assertFalse(Files.exists(target.resolve("catalog-trust")));
    assertFalse(Files.exists(target.resolve("catalog-origins")));
    String expectedManifestDigest = manifestDigest(input);
    assertThrows(
        IOException.class,
        () -> FederatedCatalogScopeBootstrap.bootstrap(target, input, expectedManifestDigest));
  }

  @Test
  void bootstrap_whenRecordSubstituted_expectNoDestinationCreated() throws Exception {
    Path input = handoff("fixture-app");
    Files.writeString(input.resolve("publishers/publisher.properties"), "private-canary");
    Path target = temporary.resolve("apps");

    String expectedManifestDigest = manifestDigest(input);
    assertThrows(
        IOException.class,
        () -> FederatedCatalogScopeBootstrap.bootstrap(target, input, expectedManifestDigest));

    assertFalse(Files.exists(target));
    assertNoScratchDirectories();
  }

  @Test
  void bootstrap_whenReviewerAppDiffers_expectNoAuthorityImported() throws Exception {
    Path input = handoff("other-app");
    Path target = temporary.resolve("apps");

    String expectedManifestDigest = manifestDigest(input);
    assertThrows(
        IOException.class,
        () -> FederatedCatalogScopeBootstrap.bootstrap(target, input, expectedManifestDigest));

    assertFalse(Files.exists(target));
    assertNoScratchDirectories();
  }

  @Test
  void bootstrap_whenExtraUnpinnedRecordExists_expectClosedRosterRejection() throws Exception {
    Path input = handoff("fixture-app");
    Files.writeString(input.resolve("publishers/extra.properties"), "unapproved");
    Path target = temporary.resolve("apps");

    String expectedManifestDigest = manifestDigest(input);
    assertThrows(
        IOException.class,
        () -> FederatedCatalogScopeBootstrap.bootstrap(target, input, expectedManifestDigest));

    assertFalse(Files.exists(target));
  }

  @Test
  void bootstrap_whenInputRecordIsSymlink_expectRejectedWithoutFollowingIt() throws Exception {
    Path input = handoff("fixture-app");
    Path publisherRecord = input.resolve("publishers/publisher.properties");
    Path outside = temporary.resolve("outside.properties");
    Files.move(publisherRecord, outside);
    Files.createSymbolicLink(publisherRecord, outside);

    Path target = temporary.resolve("apps");
    String expectedManifestDigest = manifestDigest(input);
    assertThrows(
        IOException.class,
        () -> FederatedCatalogScopeBootstrap.bootstrap(target, input, expectedManifestDigest));

    assertTrue(Files.exists(outside));
    assertFalse(Files.exists(temporary.resolve("apps")));
  }

  @Test
  void bootstrap_whenDestinationExists_expectPreexistingStatePreserved() throws Exception {
    Path input = handoff("fixture-app");
    Path target = Files.createDirectory(temporary.resolve("apps"));
    Path original = target.resolve("original");
    Files.writeString(original, "preserved");

    String expectedManifestDigest = manifestDigest(input);
    assertThrows(
        IOException.class,
        () -> FederatedCatalogScopeBootstrap.bootstrap(target, input, expectedManifestDigest));

    assertEquals("preserved", Files.readString(original));
    assertFalse(Files.exists(target.resolve("catalog-publisher-bindings")));
  }

  private Path handoff(String reviewerApp) throws Exception {
    Path input = Files.createDirectory(temporary.resolve("input"));
    var publisher =
        CatalogPublisherBinding.create(
            "publisher",
            "fixture-catalog",
            "fixture-app",
            "publisher",
            HASH,
            CatalogPublisherBinding.Status.ACTIVE,
            NOW.minusSeconds(60),
            NOW.plusSeconds(3600),
            null,
            null,
            Set.of(AppCatalogChannel.STABLE),
            "synthetic-local-approval",
            HASH,
            NOW,
            NOW,
            "synthetic scope",
            "host-operator");
    var reviewer =
        CatalogReviewerScope.create(
            "reviewer",
            "fixture-catalog",
            reviewerApp,
            Map.of("reviewer", HASH),
            HASH,
            CatalogReviewerScope.Status.ACTIVE,
            NOW,
            NOW,
            "synthetic scope",
            "host-operator");
    new FileCatalogPublisherBindingStore(input.resolve("publishers")).put(publisher);
    new FileCatalogReviewerScopeStore(input.resolve("reviewers")).put(reviewer);
    Files.writeString(
        input.resolve("bootstrap.properties"),
        "schemaVersion=1\npublisher.count=1\nreviewer.count=1\n"
            + "publisher.0.file=publisher.properties\npublisher.0.sha256="
            + FederatedPolicyRecordSupport.digest(publisher.canonicalText())
            + "\nreviewer.0.file=reviewer.properties\nreviewer.0.sha256="
            + FederatedPolicyRecordSupport.digest(reviewer.canonicalText())
            + "\n");
    return input;
  }

  private static String manifestDigest(Path input) throws IOException {
    return FederatedPolicyRecordSupport.digest(
        Files.readString(input.resolve("bootstrap.properties")));
  }

  private void assertNoScratchDirectories() throws IOException {
    try (var entries = Files.list(temporary)) {
      for (Path path : entries.toList()) {
        Path fileName = path.getFileName();
        if (fileName == null) {
          throw new AssertionError("scratch directory entry has no file name");
        }
        assertFalse(fileName.toString().startsWith(".catalog-scope-"));
      }
    }
  }
}
