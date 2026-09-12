package network.crypta.platform.appcatalog;

import java.nio.file.Path;
import java.time.Instant;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CatalogScopeRevocationTest {
  private static final Instant NOW = Instant.parse("2026-09-11T12:00:00Z");
  private static final String DIGEST = "a".repeat(64);
  @TempDir Path root;

  @Test
  void revokePublisher_whenExactActiveRecord_expectTerminalStateAndPreservedAuthorityFields()
      throws Exception {
    FileCatalogPublisherBindingStore store =
        new FileCatalogPublisherBindingStore(root.resolve("publishers"));
    CatalogPublisherBinding prior = publisher();
    store.put(prior);

    CatalogPublisherBinding revoked = store.revoke(request(prior.selfDigest()));

    assertEquals(CatalogPublisherBinding.Status.REVOKED, revoked.status());
    assertEquals(prior.publisherKeyFingerprintSha256(), revoked.publisherKeyFingerprintSha256());
    assertEquals(prior.approvalDigestSha256(), revoked.approvalDigestSha256());
    assertEquals(prior.allowedChannels(), revoked.allowedChannels());
    assertNotEquals(prior.selfDigest(), revoked.selfDigest());
    assertEquals(
        revoked,
        new FileCatalogPublisherBindingStore(root.resolve("publishers"))
            .find("scope")
            .orElseThrow());
    assertThrows(AppCatalogException.class, () -> store.put(prior));
    CatalogScopeRevocation repeatedRequest = request(revoked.selfDigest());
    assertThrows(AppCatalogException.class, () -> store.revoke(repeatedRequest));
  }

  @Test
  void revokeReviewer_whenExactActiveRecord_expectTerminalStateAndPreservedReviewerEvidence()
      throws Exception {
    FileCatalogReviewerScopeStore store =
        new FileCatalogReviewerScopeStore(root.resolve("reviewers"));
    CatalogReviewerScope prior = reviewer();
    store.put(prior);

    CatalogReviewerScope revoked = store.revoke(request(prior.selfDigest()));

    assertEquals(CatalogReviewerScope.Status.REVOKED, revoked.status());
    assertEquals(prior.reviewerFingerprints(), revoked.reviewerFingerprints());
    assertEquals(
        prior.acceptedReviewerSetDigestSha256(), revoked.acceptedReviewerSetDigestSha256());
    assertEquals(prior.appId(), revoked.appId());
    assertEquals(
        revoked,
        new FileCatalogReviewerScopeStore(root.resolve("reviewers")).find("scope").orElseThrow());
    assertThrows(AppCatalogException.class, () -> store.put(prior));
    CatalogScopeRevocation repeatedRequest = request(revoked.selfDigest());
    assertThrows(AppCatalogException.class, () -> store.revoke(repeatedRequest));
  }

  @Test
  void revoke_whenDigestCatalogOrClockChanged_expectNoPolicyMutation() throws Exception {
    FileCatalogPublisherBindingStore publishers =
        new FileCatalogPublisherBindingStore(root.resolve("publishers"));
    FileCatalogReviewerScopeStore reviewers =
        new FileCatalogReviewerScopeStore(root.resolve("reviewers"));
    publishers.put(publisher());
    reviewers.put(reviewer());
    for (CatalogScopeRevocation invalid :
        new CatalogScopeRevocation[] {
          request("b".repeat(64)),
          new CatalogScopeRevocation(
              "other", "scope", publisher().selfDigest(), NOW.plusSeconds(1), "revoke", "operator"),
          new CatalogScopeRevocation(
              "catalog", "absent", DIGEST, NOW.plusSeconds(1), "revoke", "operator"),
          new CatalogScopeRevocation(
              "catalog",
              "scope",
              publisher().selfDigest(),
              NOW.minusSeconds(1),
              "revoke",
              "operator")
        }) {
      assertThrows(AppCatalogException.class, () -> publishers.revoke(invalid));
      assertThrows(AppCatalogException.class, () -> reviewers.revoke(invalid));
    }
    assertEquals(publisher(), publishers.find("scope").orElseThrow());
    assertEquals(reviewer(), reviewers.find("scope").orElseThrow());
  }

  @Test
  void revokeReviewer_whenAuthorizationLeaseHeld_expectWaitThenAtomicStaleRejection()
      throws Exception {
    FileCatalogReviewerScopeStore store =
        new FileCatalogReviewerScopeStore(root.resolve("reviewers"));
    store.put(reviewer());
    var lease = store.retainAuthorization();
    CountDownLatch started = new CountDownLatch(1);
    CompletableFuture<CatalogReviewerScope> operation =
        CompletableFuture.supplyAsync(
            () -> {
              started.countDown();
              try {
                return store.revoke(request(reviewer().selfDigest()));
              } catch (Exception exception) {
                throw new IllegalStateException(exception);
              }
            });
    try {
      assertTrue(started.await(2, TimeUnit.SECONDS));
      assertThrows(TimeoutException.class, () -> operation.get(100, TimeUnit.MILLISECONDS));
      assertEquals(reviewer(), store.find("scope").orElseThrow());
    } finally {
      lease.close();
    }
    assertEquals(CatalogReviewerScope.Status.REVOKED, operation.get(2, TimeUnit.SECONDS).status());
    CatalogScopeRevocation staleRequest = request(reviewer().selfDigest());
    assertThrows(AppCatalogException.class, () -> store.revoke(staleRequest));
  }

  @Test
  void revokePublisher_whenAuthorizationLeaseHeld_expectWaitBeforeTerminalMutation()
      throws Exception {
    FileCatalogPublisherBindingStore store =
        new FileCatalogPublisherBindingStore(root.resolve("publishers"));
    store.put(publisher());
    var lease =
        store.retainHistoricalAuthorization(
            "catalog",
            store.policyDigest("catalog"),
            "test-app",
            "publisher",
            DIGEST,
            AppCatalogChannel.STABLE,
            NOW);
    CountDownLatch started = new CountDownLatch(1);
    CompletableFuture<CatalogPublisherBinding> operation =
        CompletableFuture.supplyAsync(
            () -> {
              started.countDown();
              try {
                return store.revoke(request(publisher().selfDigest()));
              } catch (Exception exception) {
                throw new IllegalStateException(exception);
              }
            });
    try {
      assertTrue(started.await(2, TimeUnit.SECONDS));
      assertThrows(TimeoutException.class, () -> operation.get(100, TimeUnit.MILLISECONDS));
      assertEquals(publisher(), store.find("scope").orElseThrow());
    } finally {
      lease.close();
    }
    assertEquals(
        CatalogPublisherBinding.Status.REVOKED, operation.get(2, TimeUnit.SECONDS).status());
  }

  @Test
  void revokePublisher_whenTwoRequestsUseSameDigest_expectExactlyOneMutation() throws Exception {
    FileCatalogPublisherBindingStore store =
        new FileCatalogPublisherBindingStore(root.resolve("publishers"));
    store.put(publisher());
    CountDownLatch start = new CountDownLatch(1);
    java.util.concurrent.Callable<Boolean> action =
        () -> {
          start.await();
          try {
            store.revoke(request(publisher().selfDigest()));
            return true;
          } catch (AppCatalogException _) {
            return false;
          }
        };
    try (var executor = java.util.concurrent.Executors.newFixedThreadPool(2)) {
      var first = executor.submit(action);
      var second = executor.submit(action);
      start.countDown();
      assertNotEquals(first.get(2, TimeUnit.SECONDS), second.get(2, TimeUnit.SECONDS));
    }
    assertNotSame(
        CatalogPublisherBinding.Status.ACTIVE, store.find("scope").orElseThrow().status());
  }

  private static CatalogScopeRevocation request(String digest) {
    return new CatalogScopeRevocation(
        "catalog", "scope", digest, NOW.plusSeconds(1), "synthetic revocation", "operator");
  }

  private static CatalogPublisherBinding publisher() {
    return CatalogPublisherBinding.create(
        "scope",
        "catalog",
        "test-app",
        "publisher",
        DIGEST,
        CatalogPublisherBinding.Status.ACTIVE,
        NOW.minusSeconds(60),
        NOW.plusSeconds(3600),
        null,
        null,
        Set.of(AppCatalogChannel.STABLE),
        "synthetic-local-selection",
        DIGEST,
        NOW,
        NOW,
        "approved",
        "operator");
  }

  private static CatalogReviewerScope reviewer() {
    return CatalogReviewerScope.create(
        "scope",
        "catalog",
        "test-app",
        Map.of("reviewer", DIGEST),
        DIGEST,
        CatalogReviewerScope.Status.ACTIVE,
        NOW,
        NOW,
        "approved",
        "operator");
  }
}
