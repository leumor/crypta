package network.crypta.platform.appcatalog;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Atomic, closed storage for catalog/app-scoped publisher authorizations.
 *
 * <p>Records are keyed by stable local binding ID and retain an exact catalog, application,
 * publisher key, lifecycle, validity window, and channel scope. Writes reject identity movement and
 * ambiguous key mappings. Read leases allow callers to retain a verified routine or historical
 * publisher decision through the corresponding executable bundle mutation.
 */
public final class FileCatalogPublisherBindingStore {
  /** Filename suffix for serialized publisher bindings. */
  private static final String SUFFIX = ".properties";

  /** Fair mutation fences shared by store instances addressing the same normalized root. */
  private static final ConcurrentMap<Path, CatalogMutationFence> MUTATION_FENCES =
      new ConcurrentHashMap<>();

  /** Absolute normalized private policy-store root. */
  private final Path root;

  /** Store-wide fence coordinating policy writes with retained authorization leases. */
  private final CatalogMutationFence mutationFence;

  /** Single-use lease retaining one exact publisher-policy authorization. */
  @FunctionalInterface
  public interface AuthorizationLease extends AutoCloseable {
    /** Releases the retained publisher policy. */
    @Override
    void close();
  }

  /**
   * Creates a host-owned policy store below the supplied private root.
   *
   * @param root private directory containing publisher binding records
   */
  public FileCatalogPublisherBindingStore(Path root) {
    this.root = root.toAbsolutePath().normalize();
    mutationFence =
        MUTATION_FENCES.computeIfAbsent(this.root, ignored -> new CatalogMutationFence());
  }

  /**
   * Atomically creates or replaces one binding after rejecting ambiguous identities.
   *
   * @param binding validated publisher binding to persist
   * @throws IOException if existing records cannot be read or the replacement cannot be written
   */
  public void put(CatalogPublisherBinding binding) throws IOException {
    mutationFence.withWriteLock(() -> putUnderFence(binding));
  }

  /**
   * Revokes one exact existing scope while respecting all retained authorization leases.
   *
   * @param request exact host-operator request; no new authority fields are accepted
   * @return persisted terminal record
   * @throws IOException if current policy cannot be read or atomically persisted
   */
  public CatalogPublisherBinding revoke(CatalogScopeRevocation request) throws IOException {
    java.util.Objects.requireNonNull(request, "request");
    return mutationFence.withWriteLock(
        () -> {
          CatalogPublisherBinding prior =
              find(request.scopeId()).orElseThrow(CatalogScopeRevocation::rejected);
          request.requireCurrent(prior.catalogId(), prior.selfDigest(), prior.updatedAt());
          if (prior.status() != CatalogPublisherBinding.Status.ACTIVE
              && prior.status() != CatalogPublisherBinding.Status.SUSPENDED) {
            throw CatalogScopeRevocation.rejected();
          }
          CatalogPublisherBinding revoked =
              CatalogPublisherBinding.create(
                  prior.bindingId(),
                  prior.catalogId(),
                  prior.appId(),
                  prior.publisherKeyId(),
                  prior.publisherKeyFingerprintSha256(),
                  CatalogPublisherBinding.Status.REVOKED,
                  prior.validFrom(),
                  prior.validUntil(),
                  prior.predecessorKeyId().orElse(null),
                  prior.successorKeyId().orElse(null),
                  prior.allowedChannels(),
                  prior.approvalSource(),
                  prior.approvalDigestSha256(),
                  prior.createdAt(),
                  request.changedAt(),
                  request.reason(),
                  request.operatorId());
          putUnderFence(revoked);
          return revoked;
        });
  }

  /** Validates and persists one publisher binding while the mutation fence is exclusive. */
  private synchronized void putUnderFence(CatalogPublisherBinding binding) throws IOException {
    CatalogPublisherBinding checked = java.util.Objects.requireNonNull(binding, "binding");
    List<CatalogPublisherBinding> existingBindings = list();
    for (CatalogPublisherBinding existing : existingBindings) {
      if (existing.bindingId().equals(checked.bindingId())) {
        if (!sameScopeAndKey(existing, checked)) {
          throw FederatedPolicyRecordSupport.invalid(
              "publisher binding id cannot move to another authorization subject");
        }
        if (existing.status() == CatalogPublisherBinding.Status.REVOKED
            && checked.status() != CatalogPublisherBinding.Status.REVOKED) {
          throw FederatedPolicyRecordSupport.invalid(
              "revoked publisher binding cannot be reactivated");
        }
        continue;
      }
      if (sameScopeAndKey(existing, checked)) {
        throw FederatedPolicyRecordSupport.invalid(
            "publisher scope already contains this publisher identity");
      }
      if (existing.publisherKeyId().equals(checked.publisherKeyId())
          != existing
              .publisherKeyFingerprintSha256()
              .equals(checked.publisherKeyFingerprintSha256())) {
        throw FederatedPolicyRecordSupport.invalid(
            "publisher key id and fingerprint identities are inconsistent");
      }
    }
    Path target = recordPath(checked.bindingId());
    FederatedPolicyRecordSupport.atomicWrite(
        root, target, checked.canonicalText(), ".publisher-binding-");
  }

  /**
   * Finds one binding by stable local ID.
   *
   * @param bindingId stable local publisher-binding identifier
   * @return matching validated binding, or empty when absent
   * @throws IOException if an existing record cannot be read
   */
  public synchronized Optional<CatalogPublisherBinding> find(String bindingId) throws IOException {
    Path path = recordPath(bindingId);
    if (!Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
      return Optional.empty();
    }
    return Optional.of(read(path));
  }

  /**
   * Lists all bindings deterministically and rejects hand-created ambiguity.
   *
   * @return immutable bindings sorted by record path
   * @throws IOException if the store cannot be enumerated or a record cannot be read
   */
  public synchronized List<CatalogPublisherBinding> list() throws IOException {
    if (!Files.exists(root, LinkOption.NOFOLLOW_LINKS)) {
      return List.of();
    }
    FederatedPolicyRecordSupport.requireSafeRoot(root);
    List<CatalogPublisherBinding> bindings = new ArrayList<>();
    try (var stream = Files.list(root)) {
      for (Path path :
          stream.filter(item -> item.getFileName().toString().endsWith(SUFFIX)).sorted().toList()) {
        bindings.add(read(path));
      }
    }
    rejectAmbiguity(bindings);
    return List.copyOf(bindings);
  }

  /**
   * Returns a deterministic digest of the complete closed publisher policy set.
   *
   * @return lowercase SHA-256 digest of all canonical bindings
   * @throws IOException if the policy set cannot be read
   */
  public synchronized String policyDigest() throws IOException {
    return FederatedPolicyRecordSupport.digest(
        list().stream().map(CatalogPublisherBinding::canonicalText).reduce("", String::concat));
  }

  /**
   * Returns the policy digest for one catalog without coupling unrelated catalog bindings.
   *
   * @param catalogId catalog identity whose policy set is requested
   * @return lowercase SHA-256 digest of the catalog's canonical bindings
   * @throws IOException if the catalog policy set cannot be read
   */
  public synchronized String policyDigest(String catalogId) throws IOException {
    String normalizedCatalogId = AppCatalog.normalizeCatalogId(catalogId);
    return FederatedPolicyRecordSupport.digest(
        listForCatalog(normalizedCatalogId).stream()
            .map(CatalogPublisherBinding::canonicalText)
            .reduce("", String::concat));
  }

  /**
   * Finds the unique active authorization for an exact catalog/app/signer decision.
   *
   * @param catalogId exact catalog identity
   * @param appId exact application identity
   * @param publisherKeyId verified publisher key identifier
   * @param fingerprint canonical publisher-key fingerprint
   * @param channel requested catalog channel
   * @param now time used for validity evaluation
   * @return unique active matching binding, or empty when unauthorized
   * @throws IOException if the catalog policy set cannot be read
   */
  public synchronized Optional<CatalogPublisherBinding> findAuthorization(
      String catalogId,
      String appId,
      String publisherKeyId,
      String fingerprint,
      AppCatalogChannel channel,
      Instant now)
      throws IOException {
    String normalizedCatalogId = AppCatalog.normalizeCatalogId(catalogId);
    List<CatalogPublisherBinding> matches =
        listForCatalog(normalizedCatalogId).stream()
            .filter(
                binding ->
                    binding.authorizes(
                        normalizedCatalogId, appId, publisherKeyId, fingerprint, channel, now))
            .toList();
    if (matches.size() > 1) {
      throw FederatedPolicyRecordSupport.invalid(
          "multiple active publisher bindings authorize one catalog app");
    }
    return matches.stream().findFirst();
  }

  /**
   * Authenticates and retains one exact routine publisher decision through a host mutation.
   *
   * <p>Publisher lifecycle and policy updates through this store wait until the returned lease is
   * closed. The expected catalog-wide policy-set digest, selected binding identity, and exact
   * routine subject are evaluated while the read lease is already held, so suspension, revocation,
   * expiry, binding substitution, or scope replacement cannot race the executable bundle commit.
   *
   * @param catalogId exact catalog identity
   * @param expectedPolicyDigest expected aggregate policy digest for that catalog
   * @param appId exact application identity
   * @param publisher contextual publisher verification result
   * @param channel requested catalog channel
   * @param now time used for validity evaluation
   * @return single-use lease retaining the exact authorization until closed
   * @throws IOException if the policy set cannot be read
   */
  public AuthorizationLease retainAuthorization(
      String catalogId,
      String expectedPolicyDigest,
      String appId,
      AppCatalogBundleVerificationResult publisher,
      AppCatalogChannel channel,
      Instant now)
      throws IOException {
    CatalogMutationFence.Authorized<Boolean> authorized =
        mutationFence.authorizeRead(
            () -> {
              String normalizedCatalogId = AppCatalog.normalizeCatalogId(catalogId);
              String checkedDigest =
                  FederatedPolicyRecordSupport.requireDigest(
                      expectedPolicyDigest, "publisher policy digest");
              if (!checkedDigest.equals(policyDigest(normalizedCatalogId))) {
                throw FederatedPolicyRecordSupport.invalid(
                    "catalog publisher policy digest changed");
              }
              AppCatalogBundleVerificationResult checkedPublisher =
                  java.util.Objects.requireNonNull(publisher, "publisher");
              CatalogPublisherBinding binding =
                  findAuthorization(
                          normalizedCatalogId,
                          appId,
                          checkedPublisher.publisherKeyId(),
                          checkedPublisher.publisherKeyFingerprintSha256(),
                          channel,
                          now)
                      .orElseThrow(
                          () ->
                              FederatedPolicyRecordSupport.invalid(
                                  "catalog publisher is not authorized"));
              if (!checkedPublisher.catalogScoped()
                  || !binding.bindingId().equals(checkedPublisher.authorizationPolicyId())
                  || !binding
                      .selfDigest()
                      .equals(checkedPublisher.authorizationPolicyDigestSha256())) {
                throw FederatedPolicyRecordSupport.invalid("catalog publisher is not authorized");
              }
              return Boolean.TRUE;
            });
    try (var leaseTransfer = new AuthorizationLeaseTransfer(authorized.authorization())) {
      return leaseTransfer.transfer();
    }
  }

  /**
   * Finds the unique current binding that permits one exact historical publisher subject.
   *
   * @param catalogId exact catalog identity
   * @param appId exact application identity
   * @param publisherKeyId retained publisher key identifier
   * @param fingerprint retained publisher-key fingerprint
   * @param channel retained catalog channel
   * @param verifiedAt timestamp of the original verification
   * @return unique binding permitting the historical subject, or empty
   * @throws IOException if the catalog policy set cannot be read
   */
  public synchronized Optional<CatalogPublisherBinding> findHistoricalAuthorization(
      String catalogId,
      String appId,
      String publisherKeyId,
      String fingerprint,
      AppCatalogChannel channel,
      Instant verifiedAt)
      throws IOException {
    String normalizedCatalogId = AppCatalog.normalizeCatalogId(catalogId);
    List<CatalogPublisherBinding> matches =
        listForCatalog(normalizedCatalogId).stream()
            .filter(
                binding ->
                    binding.authorizesHistorical(
                        normalizedCatalogId,
                        appId,
                        publisherKeyId,
                        fingerprint,
                        channel,
                        verifiedAt))
            .toList();
    if (matches.size() > 1) {
      throw FederatedPolicyRecordSupport.invalid(
          "multiple publisher bindings authorize one historical catalog app");
    }
    return matches.stream().findFirst();
  }

  /**
   * Authenticates and retains one exact historical publisher decision through host rollback.
   *
   * <p>Publisher lifecycle and policy updates through this store wait until the returned lease is
   * closed. The expected catalog policy digest and exact historical subject are evaluated while the
   * read lease is already held, so neither can change between verification and retention.
   *
   * @param catalogId exact catalog identity
   * @param expectedPolicyDigest expected aggregate policy digest for that catalog
   * @param appId exact application identity
   * @param publisherKeyId retained publisher key identifier
   * @param fingerprint retained publisher-key fingerprint
   * @param channel retained catalog channel
   * @param verifiedAt timestamp of the original verification
   * @return single-use lease retaining the historical authorization until closed
   * @throws IOException if the policy set cannot be read
   */
  public AuthorizationLease retainHistoricalAuthorization(
      String catalogId,
      String expectedPolicyDigest,
      String appId,
      String publisherKeyId,
      String fingerprint,
      AppCatalogChannel channel,
      Instant verifiedAt)
      throws IOException {
    CatalogMutationFence.Authorized<Boolean> authorized =
        mutationFence.authorizeRead(
            () -> {
              String normalizedCatalogId = AppCatalog.normalizeCatalogId(catalogId);
              String checkedDigest =
                  FederatedPolicyRecordSupport.requireDigest(
                      expectedPolicyDigest, "publisher policy digest");
              if (!checkedDigest.equals(policyDigest(normalizedCatalogId))) {
                throw FederatedPolicyRecordSupport.invalid(
                    "catalog publisher policy digest changed");
              }
              if (findHistoricalAuthorization(
                      normalizedCatalogId, appId, publisherKeyId, fingerprint, channel, verifiedAt)
                  .isEmpty()) {
                throw FederatedPolicyRecordSupport.invalid(
                    "historical catalog publisher is not authorized");
              }
              return Boolean.TRUE;
            });
    try (var leaseTransfer = new AuthorizationLeaseTransfer(authorized.authorization())) {
      return leaseTransfer.transfer();
    }
  }

  /** Closes a retained fence authorization unless ownership transfers to the caller. */
  private static final class AuthorizationLeaseTransfer implements AutoCloseable {
    private AppCatalogManager.CatalogTrustAuthorization authorization;

    private AuthorizationLeaseTransfer(AppCatalogManager.CatalogTrustAuthorization authorization) {
      this.authorization = java.util.Objects.requireNonNull(authorization, "authorization");
    }

    private AuthorizationLease transfer() {
      AppCatalogManager.CatalogTrustAuthorization transferred = authorization;
      authorization = null;
      return transferred::close;
    }

    @Override
    public void close() {
      if (authorization != null) {
        authorization.close();
      }
    }
  }

  /**
   * Lists active publisher bindings for one exact catalog/app/channel conflict subject.
   *
   * @param catalogId exact catalog identity
   * @param appId exact application identity
   * @param channel requested catalog channel
   * @param now time used for validity evaluation
   * @return immutable active bindings applicable to the subject
   * @throws IOException if the catalog policy set cannot be read
   */
  public synchronized List<CatalogPublisherBinding> findActiveForScope(
      String catalogId, String appId, AppCatalogChannel channel, Instant now) throws IOException {
    String normalizedCatalogId = AppCatalog.normalizeCatalogId(catalogId);
    String normalizedAppId = AppCatalogEntry.normalizeAppId(appId);
    Instant checkedNow = java.util.Objects.requireNonNull(now, "now");
    return listForCatalog(normalizedCatalogId).stream()
        .filter(binding -> binding.appId().equals(normalizedAppId))
        .filter(binding -> binding.status() == CatalogPublisherBinding.Status.ACTIVE)
        .filter(binding -> binding.allowedChannels().contains(channel))
        .filter(binding -> !checkedNow.isBefore(binding.validFrom()))
        .filter(binding -> checkedNow.isBefore(binding.validUntil()))
        .toList();
  }

  /**
   * Lists current and suspended records that define one catalog-local publisher key lineage.
   *
   * <p>The result supplies authenticated key-id-to-fingerprint mappings for conflict comparison.
   * Pending, revoked, and removed records cannot contribute lineage evidence. Routine publisher
   * authorization remains the responsibility of {@link #findActiveForScope(String, String,
   * AppCatalogChannel, Instant)}.
   *
   * @param catalogId exact catalog identity
   * @param appId exact application identity
   * @param channel requested catalog channel
   * @return immutable applicable lineage records
   * @throws IOException if the catalog-local policy set cannot be read
   */
  public synchronized List<CatalogPublisherBinding> findLineageForScope(
      String catalogId, String appId, AppCatalogChannel channel) throws IOException {
    String normalizedCatalogId = AppCatalog.normalizeCatalogId(catalogId);
    String normalizedAppId = AppCatalogEntry.normalizeAppId(appId);
    return listForCatalog(normalizedCatalogId).stream()
        .filter(binding -> binding.appId().equals(normalizedAppId))
        .filter(
            binding ->
                binding.status() == CatalogPublisherBinding.Status.ACTIVE
                    || binding.status() == CatalogPublisherBinding.Status.SUSPENDED)
        .filter(binding -> binding.allowedChannels().contains(channel))
        .toList();
  }

  /**
   * Reads and authenticates records routed to one normalized catalog identity.
   *
   * @param catalogId normalized catalog identity
   * @return immutable validated catalog-local bindings
   * @throws IOException if candidate records cannot be enumerated or read
   */
  private List<CatalogPublisherBinding> listForCatalog(String catalogId) throws IOException {
    List<CatalogPublisherBinding> bindings = new ArrayList<>();
    for (Path path :
        FederatedPolicyRecordSupport.catalogScopedRecordPaths(root, SUFFIX, catalogId)) {
      CatalogPublisherBinding binding = read(path);
      if (!binding.catalogId().equals(catalogId)) {
        throw FederatedPolicyRecordSupport.invalid(
            "publisher binding changed during scoped lookup");
      }
      bindings.add(binding);
    }
    rejectAmbiguity(bindings);
    return List.copyOf(bindings);
  }

  /**
   * Parses and validates one publisher binding record.
   *
   * @param path confined record path
   * @return validated publisher binding
   * @throws IOException if the record cannot be read
   */
  private CatalogPublisherBinding read(Path path) throws IOException {
    FederatedPolicyRecordSupport.requireSafeRoot(root);
    Map<String, String> fields = FederatedPolicyRecordSupport.parse(path);
    int schemaVersion = FederatedPolicyRecordSupport.parseVersion(fields);
    String bindingId = FederatedPolicyRecordSupport.remove(fields, "bindingId");
    String catalogId = FederatedPolicyRecordSupport.remove(fields, "catalogId");
    String appId = FederatedPolicyRecordSupport.remove(fields, "appId");
    String publisherKeyId = FederatedPolicyRecordSupport.remove(fields, "publisherKeyId");
    String fingerprint =
        FederatedPolicyRecordSupport.remove(fields, "publisherKeyFingerprintSha256");
    CatalogPublisherBinding.Status status =
        CatalogPublisherBinding.Status.parse(FederatedPolicyRecordSupport.remove(fields, "status"));
    Instant validFrom = FederatedPolicyRecordSupport.parseInstant(fields, "validFrom");
    Instant validUntil = FederatedPolicyRecordSupport.parseInstant(fields, "validUntil");
    Optional<String> predecessor = optional(fields, "predecessorKeyId");
    Optional<String> successor = optional(fields, "successorKeyId");
    Set<AppCatalogChannel> channels = new LinkedHashSet<>();
    for (String value :
        FederatedPolicyRecordSupport.split(
            FederatedPolicyRecordSupport.remove(fields, "channels"))) {
      channels.add(AppCatalogChannel.parse(value, "publisher binding channels"));
    }
    String approvalSource = FederatedPolicyRecordSupport.remove(fields, "approvalSource");
    String approvalDigest = FederatedPolicyRecordSupport.remove(fields, "approvalDigestSha256");
    Instant createdAt = FederatedPolicyRecordSupport.parseInstant(fields, "createdAt");
    Instant updatedAt = FederatedPolicyRecordSupport.parseInstant(fields, "updatedAt");
    String reason = FederatedPolicyRecordSupport.remove(fields, "reason");
    String operatorId = FederatedPolicyRecordSupport.remove(fields, "operatorId");
    String selfDigest = FederatedPolicyRecordSupport.remove(fields, "selfDigest");
    FederatedPolicyRecordSupport.requireClosed(fields);
    CatalogPublisherBinding binding =
        new CatalogPublisherBinding(
            schemaVersion,
            bindingId,
            catalogId,
            appId,
            publisherKeyId,
            fingerprint,
            status,
            validFrom,
            validUntil,
            predecessor,
            successor,
            channels,
            approvalSource,
            approvalDigest,
            createdAt,
            updatedAt,
            reason,
            operatorId,
            selfDigest);
    Path fileName = path.getFileName();
    if (fileName == null || !fileName.toString().equals(binding.bindingId() + SUFFIX)) {
      throw FederatedPolicyRecordSupport.invalid("publisher binding id does not match file name");
    }
    return binding;
  }

  /**
   * Resolves one validated binding identifier below the store root.
   *
   * @param bindingId stable local publisher-binding identifier
   * @return confined normalized record path
   */
  private Path recordPath(String bindingId) {
    String checked =
        FederatedPolicyRecordSupport.requireId(
            bindingId, "publisher binding id", FederatedPolicyRecordSupport.LOCAL_ID);
    Path path = root.resolve(checked + SUFFIX).normalize();
    if (!root.equals(path.getParent())) {
      throw FederatedPolicyRecordSupport.invalid("publisher binding path escapes store root");
    }
    return path;
  }

  /**
   * Removes one required serialized field with an empty-as-absent representation.
   *
   * @param fields remaining parsed properties
   * @param key property name
   * @return optional property value
   */
  private static Optional<String> optional(Map<String, String> fields, String key) {
    String value = FederatedPolicyRecordSupport.remove(fields, key);
    return value.isEmpty() ? Optional.empty() : Optional.of(value);
  }

  /**
   * Tests whether two records bind the same immutable authorization subject.
   *
   * @param left first publisher binding
   * @param right second publisher binding
   * @return whether catalog, app, key ID, and fingerprint all match
   */
  private static boolean sameScopeAndKey(
      CatalogPublisherBinding left, CatalogPublisherBinding right) {
    return left.catalogId().equals(right.catalogId())
        && left.appId().equals(right.appId())
        && left.publisherKeyId().equals(right.publisherKeyId())
        && left.publisherKeyFingerprintSha256().equals(right.publisherKeyFingerprintSha256());
  }

  /**
   * Rejects duplicate subjects and inconsistent global key identity mappings.
   *
   * @param bindings publisher bindings to validate as one policy set
   */
  private static void rejectAmbiguity(List<CatalogPublisherBinding> bindings) {
    Set<String> identities = new java.util.HashSet<>();
    Map<String, String> fingerprintByKeyId = new java.util.HashMap<>();
    Map<String, String> keyIdByFingerprint = new java.util.HashMap<>();
    for (CatalogPublisherBinding binding : bindings) {
      String identity =
          binding.catalogId()
              + '\n'
              + binding.appId()
              + '\n'
              + binding.publisherKeyId()
              + '\n'
              + binding.publisherKeyFingerprintSha256();
      if (!identities.add(identity)) {
        throw FederatedPolicyRecordSupport.invalid("duplicate publisher scope identity");
      }
      String priorFingerprint =
          fingerprintByKeyId.putIfAbsent(
              binding.publisherKeyId(), binding.publisherKeyFingerprintSha256());
      String priorKeyId =
          keyIdByFingerprint.putIfAbsent(
              binding.publisherKeyFingerprintSha256(), binding.publisherKeyId());
      if ((priorFingerprint != null
              && !priorFingerprint.equals(binding.publisherKeyFingerprintSha256()))
          || (priorKeyId != null && !priorKeyId.equals(binding.publisherKeyId()))) {
        throw FederatedPolicyRecordSupport.invalid(
            "publisher key id and fingerprint identities are inconsistent");
      }
    }
  }
}
