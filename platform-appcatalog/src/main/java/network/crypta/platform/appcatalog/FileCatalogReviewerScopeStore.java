package network.crypta.platform.appcatalog;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.Semaphore;

/**
 * Atomic, closed storage for catalog/app-scoped reviewer policy.
 *
 * <p>The store persists one catalog-wide or app-specific reviewer scope per authorization subject,
 * rejects overlap, and computes catalog-local policy digests. A fair permit fence lets executable
 * bundle mutations retain the complete reviewer policy while evaluating receipts, preventing a
 * concurrent lifecycle or scope update from invalidating the decision before commit.
 */
public final class FileCatalogReviewerScopeStore {
  /** Filename suffix for serialized reviewer scopes. */
  private static final String SUFFIX = ".properties";

  /** Complete permit count acquired by policy mutations. */
  private static final int MUTATION_PERMITS = Integer.MAX_VALUE;

  /** Fair mutation fences shared by stores addressing the same normalized root. */
  private static final ConcurrentMap<Path, Semaphore> MUTATION_FENCES = new ConcurrentHashMap<>();

  /** Absolute normalized private policy-store root. */
  private final Path root;

  /** Store-wide fence coordinating writes with retained authorization. */
  private final Semaphore mutationFence;

  /** Same-thread lease retaining the reviewer-scope policy through a host mutation. */
  @FunctionalInterface
  public interface AuthorizationLease extends AutoCloseable {
    /** Releases the retained reviewer-scope policy. */
    @Override
    void close();
  }

  /** One single-use authorization permit returned to a mutation caller. */
  private static final class PermitAuthorizationLease implements AuthorizationLease {
    /** Fence to release when the retained decision is no longer needed. */
    private final Semaphore mutationFence;

    /** Whether the single-use lease has already been released. */
    private boolean closed;

    /**
     * Creates a retained authorization backed by one acquired permit.
     *
     * @param mutationFence store fence owning the permit
     */
    private PermitAuthorizationLease(Semaphore mutationFence) {
      this.mutationFence = mutationFence;
    }

    @Override
    public synchronized void close() {
      if (closed) {
        throw new IllegalStateException("reviewer-scope authorization lease is already closed");
      }
      closed = true;
      mutationFence.release();
    }
  }

  /**
   * Creates a host-owned reviewer policy store below the supplied private root.
   *
   * @param root private directory containing reviewer scope records
   */
  public FileCatalogReviewerScopeStore(Path root) {
    this.root = root.toAbsolutePath().normalize();
    mutationFence =
        MUTATION_FENCES.computeIfAbsent(
            this.root, ignored -> new Semaphore(MUTATION_PERMITS, true));
  }

  /**
   * Atomically creates or replaces one scope after rejecting overlapping scope records.
   *
   * @param scope validated reviewer scope to persist
   * @throws IOException if existing records cannot be read or replacement cannot be written
   */
  public void put(CatalogReviewerScope scope) throws IOException {
    mutationFence.acquireUninterruptibly(MUTATION_PERMITS);
    try {
      putUnderFence(scope);
    } finally {
      mutationFence.release(MUTATION_PERMITS);
    }
  }

  /**
   * Revokes one exact existing scope while respecting all retained authorization leases.
   *
   * @param request exact host-operator request; no new reviewer or subject fields are accepted
   * @return persisted terminal record
   * @throws IOException if current policy cannot be read or atomically persisted
   */
  public CatalogReviewerScope revoke(CatalogScopeRevocation request) throws IOException {
    java.util.Objects.requireNonNull(request, "request");
    mutationFence.acquireUninterruptibly(MUTATION_PERMITS);
    try {
      CatalogReviewerScope prior =
          find(request.scopeId()).orElseThrow(CatalogScopeRevocation::rejected);
      request.requireCurrent(prior.catalogId(), prior.selfDigest(), prior.updatedAt());
      if (prior.status() != CatalogReviewerScope.Status.ACTIVE
          && prior.status() != CatalogReviewerScope.Status.SUSPENDED) {
        throw CatalogScopeRevocation.rejected();
      }
      CatalogReviewerScope revoked =
          CatalogReviewerScope.create(
              prior.scopeId(),
              prior.catalogId(),
              prior.appId().orElse(null),
              prior.reviewerFingerprints(),
              prior.acceptedReviewerSetDigestSha256(),
              CatalogReviewerScope.Status.REVOKED,
              prior.createdAt(),
              request.changedAt(),
              request.reason(),
              request.operatorId());
      putUnderFence(revoked);
      return revoked;
    } finally {
      mutationFence.release(MUTATION_PERMITS);
    }
  }

  /** Validates and persists one reviewer scope while the mutation fence is exclusive. */
  private synchronized void putUnderFence(CatalogReviewerScope scope) throws IOException {
    CatalogReviewerScope checked = java.util.Objects.requireNonNull(scope, "scope");
    for (CatalogReviewerScope existing : list()) {
      if (existing.scopeId().equals(checked.scopeId())) {
        if (!sameScope(existing, checked)) {
          throw FederatedPolicyRecordSupport.invalid(
              "reviewer scope id cannot move to another catalog or app scope");
        }
        if (existing.status() == CatalogReviewerScope.Status.REVOKED
            && checked.status() != CatalogReviewerScope.Status.REVOKED) {
          throw FederatedPolicyRecordSupport.invalid(
              "revoked reviewer scope cannot be reactivated");
        }
        continue;
      }
      if (sameScope(existing, checked)) {
        throw FederatedPolicyRecordSupport.invalid(
            "catalog reviewer scope already has a local policy");
      }
    }
    FederatedPolicyRecordSupport.atomicWrite(
        root, recordPath(checked.scopeId()), checked.canonicalText(), ".reviewer-scope-");
  }

  /**
   * Retains the complete reviewer-scope policy while a caller evaluates and uses it.
   *
   * <p>Lifecycle and scope updates through this store wait for the returned lease to close. The
   * lease retains one permit from a fair policy fence and is intended for one bounded AppHost
   * mutation.
   *
   * @return single-use lease retaining the complete reviewer policy until closed
   */
  public AuthorizationLease retainAuthorization() {
    AuthorizationLease authorization = new PermitAuthorizationLease(mutationFence);
    mutationFence.acquireUninterruptibly();
    return authorization;
  }

  /**
   * Finds one scope by stable local ID.
   *
   * @param scopeId stable local reviewer-scope identifier
   * @return matching validated scope, or empty when absent
   * @throws IOException if an existing record cannot be read
   */
  public synchronized Optional<CatalogReviewerScope> find(String scopeId) throws IOException {
    Path path = recordPath(scopeId);
    if (!Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
      return Optional.empty();
    }
    return Optional.of(read(path));
  }

  /**
   * Lists all scopes deterministically and rejects hand-created overlap.
   *
   * @return immutable scopes sorted by record path
   * @throws IOException if the store cannot be enumerated or a record cannot be read
   */
  public synchronized List<CatalogReviewerScope> list() throws IOException {
    if (!Files.exists(root, LinkOption.NOFOLLOW_LINKS)) {
      return List.of();
    }
    FederatedPolicyRecordSupport.requireSafeRoot(root);
    List<CatalogReviewerScope> scopes = new ArrayList<>();
    try (var stream = Files.list(root)) {
      for (Path path :
          stream.filter(item -> item.getFileName().toString().endsWith(SUFFIX)).sorted().toList()) {
        scopes.add(read(path));
      }
    }
    rejectDuplicateScopes(scopes);
    return List.copyOf(scopes);
  }

  /**
   * Returns a deterministic digest of the complete closed reviewer-scope policy set.
   *
   * @return lowercase SHA-256 digest of all canonical scopes
   * @throws IOException if the policy set cannot be read
   */
  public synchronized String policyDigest() throws IOException {
    return FederatedPolicyRecordSupport.digest(
        list().stream().map(CatalogReviewerScope::canonicalText).reduce("", String::concat));
  }

  /**
   * Returns the policy digest for one catalog without coupling unrelated catalog scopes.
   *
   * @param catalogId catalog identity whose scope set is requested
   * @return lowercase SHA-256 digest of the catalog's canonical scopes
   * @throws IOException if the catalog policy set cannot be read
   */
  public synchronized String policyDigest(String catalogId) throws IOException {
    String normalizedCatalogId = AppCatalog.normalizeCatalogId(catalogId);
    return FederatedPolicyRecordSupport.digest(
        listForCatalog(normalizedCatalogId).stream()
            .map(CatalogReviewerScope::canonicalText)
            .reduce("", String::concat));
  }

  /**
   * Finds the deterministic effective scope, preferring an exact app scope over catalog-wide.
   *
   * @param catalogId exact catalog identity
   * @param appId exact application identity
   * @return effective validated reviewer scope, or empty when none is configured
   * @throws IOException if the catalog policy set cannot be read
   */
  public synchronized Optional<CatalogReviewerScope> findEffective(String catalogId, String appId)
      throws IOException {
    String normalizedCatalogId = AppCatalog.normalizeCatalogId(catalogId);
    String normalizedAppId = AppCatalogEntry.normalizeAppId(appId);
    List<CatalogReviewerScope> matching =
        listForCatalog(normalizedCatalogId).stream()
            .filter(
                scope ->
                    scope.appId().isEmpty()
                        || scope.appId().filter(normalizedAppId::equals).isPresent())
            .toList();
    List<CatalogReviewerScope> exact =
        matching.stream().filter(scope -> scope.appId().isPresent()).toList();
    if (exact.size() > 1 || (exact.isEmpty() && matching.size() > 1)) {
      throw FederatedPolicyRecordSupport.invalid("ambiguous effective catalog reviewer scope");
    }
    return exact.isEmpty() ? matching.stream().findFirst() : exact.stream().findFirst();
  }

  /**
   * Reads and authenticates records routed to one normalized catalog identity.
   *
   * @param catalogId normalized catalog identity
   * @return immutable validated catalog-local scopes
   * @throws IOException if candidate records cannot be enumerated or read
   */
  private List<CatalogReviewerScope> listForCatalog(String catalogId) throws IOException {
    List<CatalogReviewerScope> scopes = new ArrayList<>();
    for (Path path :
        FederatedPolicyRecordSupport.catalogScopedRecordPaths(root, SUFFIX, catalogId)) {
      CatalogReviewerScope scope = read(path);
      if (!scope.catalogId().equals(catalogId)) {
        throw FederatedPolicyRecordSupport.invalid("reviewer scope changed during scoped lookup");
      }
      scopes.add(scope);
    }
    rejectDuplicateScopes(scopes);
    return List.copyOf(scopes);
  }

  /**
   * Parses and validates one reviewer scope record.
   *
   * @param path confined record path
   * @return validated reviewer scope
   * @throws IOException if the record cannot be read
   */
  private CatalogReviewerScope read(Path path) throws IOException {
    FederatedPolicyRecordSupport.requireSafeRoot(root);
    Map<String, String> fields = FederatedPolicyRecordSupport.parse(path);
    int schemaVersion = FederatedPolicyRecordSupport.parseVersion(fields);
    String scopeId = FederatedPolicyRecordSupport.remove(fields, "scopeId");
    String catalogId = FederatedPolicyRecordSupport.remove(fields, "catalogId");
    String appIdValue = FederatedPolicyRecordSupport.remove(fields, "appId");
    Optional<String> appId = appIdValue.isEmpty() ? Optional.empty() : Optional.of(appIdValue);
    LinkedHashMap<String, String> reviewers = new LinkedHashMap<>();
    for (String reviewerId :
        FederatedPolicyRecordSupport.split(
            FederatedPolicyRecordSupport.remove(fields, "reviewerIds"))) {
      reviewers.put(
          reviewerId, FederatedPolicyRecordSupport.remove(fields, "reviewer." + reviewerId));
    }
    String reviewerSetDigest =
        FederatedPolicyRecordSupport.remove(fields, "acceptedReviewerSetDigestSha256");
    CatalogReviewerScope.Status status =
        CatalogReviewerScope.Status.parse(FederatedPolicyRecordSupport.remove(fields, "status"));
    Instant createdAt = FederatedPolicyRecordSupport.parseInstant(fields, "createdAt");
    Instant updatedAt = FederatedPolicyRecordSupport.parseInstant(fields, "updatedAt");
    String reason = FederatedPolicyRecordSupport.remove(fields, "reason");
    String operatorId = FederatedPolicyRecordSupport.remove(fields, "operatorId");
    String selfDigest = FederatedPolicyRecordSupport.remove(fields, "selfDigest");
    FederatedPolicyRecordSupport.requireClosed(fields);
    CatalogReviewerScope scope =
        new CatalogReviewerScope(
            schemaVersion,
            scopeId,
            catalogId,
            appId,
            reviewers,
            reviewerSetDigest,
            status,
            createdAt,
            updatedAt,
            reason,
            operatorId,
            selfDigest);
    Path fileName = path.getFileName();
    if (fileName == null || !fileName.toString().equals(scope.scopeId() + SUFFIX)) {
      throw FederatedPolicyRecordSupport.invalid("reviewer scope id does not match file name");
    }
    return scope;
  }

  /**
   * Resolves one validated scope identifier below the store root.
   *
   * @param scopeId stable local reviewer-scope identifier
   * @return confined normalized record path
   */
  private Path recordPath(String scopeId) {
    String checked =
        FederatedPolicyRecordSupport.requireId(
            scopeId, "reviewer scope id", FederatedPolicyRecordSupport.LOCAL_ID);
    Path path = root.resolve(checked + SUFFIX).normalize();
    if (!root.equals(path.getParent())) {
      throw FederatedPolicyRecordSupport.invalid("reviewer scope path escapes store root");
    }
    return path;
  }

  /**
   * Tests whether two records address the same immutable catalog/app scope.
   *
   * @param left first reviewer scope
   * @param right second reviewer scope
   * @return whether catalog and optional app scope both match
   */
  private static boolean sameScope(CatalogReviewerScope left, CatalogReviewerScope right) {
    return left.catalogId().equals(right.catalogId()) && left.appId().equals(right.appId());
  }

  /**
   * Rejects a policy set containing overlapping catalog/app scopes.
   *
   * @param scopes reviewer scopes to validate together
   */
  private static void rejectDuplicateScopes(List<CatalogReviewerScope> scopes) {
    for (int left = 0; left < scopes.size(); left++) {
      for (int right = left + 1; right < scopes.size(); right++) {
        if (sameScope(scopes.get(left), scopes.get(right))) {
          throw FederatedPolicyRecordSupport.invalid("duplicate catalog reviewer scope");
        }
      }
    }
  }
}
