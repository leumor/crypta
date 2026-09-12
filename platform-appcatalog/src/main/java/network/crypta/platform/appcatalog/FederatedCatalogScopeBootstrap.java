package network.crypta.platform.appcatalog;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Pattern;

/**
 * Imports an explicitly selected private scope handoff before a host's first app-platform startup.
 *
 * <p>This offline operation accepts only a new, absent apps root and exact digest-pinned canonical
 * publisher and reviewer records. It uses the same closed records and stores as the daemon. It
 * imports no keys, catalog bindings, sources, installed apps, or origin records. Catalog approval
 * still requires the normal operator trust route and all installation authorization still runs in
 * the daemon. The invoking protected supervisor owns authentication of the original handoff and
 * selection of the expected digest; a digest alone is not original producer authentication.
 */
public final class FederatedCatalogScopeBootstrap {
  /** Closed basename grammar for snapshotted publisher and reviewer records. */
  private static final Pattern RECORD_FILE_NAME =
      Pattern.compile("[a-z0-9][a-z0-9._-]{0,127}\\.properties");

  /** Fixed manifest basename in the private handoff directory. */
  private static final String MANIFEST = "bootstrap.properties";

  /** Manifest-relative directory containing publisher binding records. */
  private static final String PUBLISHERS_DIRECTORY = "publishers";

  /** Manifest-relative directory containing reviewer scope records. */
  private static final String REVIEWERS_DIRECTORY = "reviewers";

  /** Maximum records accepted for each scope family in one handoff. */
  private static final int MAX_RECORDS = 32;

  /** Fixed CLI failure code that does not disclose private input details. */
  private static final String FAILURE = "catalog_scope_bootstrap_rejected";

  /** Prevents construction of the stateless offline bootstrap utility. */
  private FederatedCatalogScopeBootstrap() {}

  /**
   * Imports scopes into an absent node apps root and prints only catalog-local policy commitments.
   *
   * <p>Standard output is a private JSON protocol consumed by the protected runtime driver, not a
   * log stream. Failures emit only the fixed reason code on standard error. Logging must not
   * decorate or redirect these channels or disclose the private policy commitments.
   *
   * @param args absent apps root, private input directory, and raw lowercase manifest SHA-256
   */
  @SuppressWarnings("java:S106")
  static void main(String[] args) {
    try {
      if (args.length != 3) {
        throw new IOException(FAILURE);
      }
      List<CatalogPolicy> policies = bootstrap(Path.of(args[0]), Path.of(args[1]), args[2]);
      System.out.println(summary(policies));
    } catch (IOException | RuntimeException _) {
      System.err.println(FAILURE);
      System.exit(1);
    }
  }

  /**
   * Validates a complete private handoff and creates a new scope-only apps root.
   *
   * <p>Existing destinations and symlink ancestors fail before mutation. All inputs are bounded and
   * copied once into a private snapshot before parsing. Failed preparation removes only its own
   * temporary directories. Installation of the prepared root never replaces an existing root.
   * Snapshot cleanup completes before installation so its failure cannot report a committed import
   * as rejected. Callers must keep the parent directory and input tree under exclusive ownership
   * during this operation; this method does not coordinate a running daemon or concurrent
   * filesystem writers. On POSIX filesystems temporary roots are created with owner-only
   * permissions. Other filesystems use their inherited access controls, which the caller must
   * restrict appropriately.
   *
   * @param appsRoot absent app-platform root beneath an existing host-owned directory
   * @param input exact handoff directory with bootstrap.properties, publishers, and reviewers
   * @param expectedDigest independently selected raw manifest digest
   * @return immutable catalog-local policy digests for explicit subsequent catalog approval
   * @throws IOException if input validation, safe preparation, installation, or cleanup fails
   * @throws NullPointerException if either path is null
   * @throws AppCatalogException if a scope record fails native policy validation
   */
  public static List<CatalogPolicy> bootstrap(Path appsRoot, Path input, String expectedDigest)
      throws IOException {
    Path target = appsRoot.toAbsolutePath().normalize();
    Path source = input.toAbsolutePath().normalize();
    Path parent = target.getParent();
    if (parent == null) {
      throw new IOException(FAILURE);
    }
    requireSafeDirectory(parent);
    requireSafeDirectory(source);
    if (Files.exists(target, LinkOption.NOFOLLOW_LINKS) || source.startsWith(target)) {
      throw new IOException(FAILURE);
    }
    byte[] manifest = readBounded(source.resolve(MANIFEST));
    requireDigest(manifest, expectedDigest);
    Path snapshot = privateDirectory(parent, ".catalog-scope-input-");
    Path prepared = null;
    try {
      Files.write(snapshot.resolve(MANIFEST), manifest);
      Map<String, String> fields = FederatedPolicyRecordSupport.parse(snapshot.resolve(MANIFEST));
      if (!"1".equals(fields.remove("schemaVersion"))) {
        throw new IOException(FAILURE);
      }
      snapshotRecords(source, snapshot, fields, "publisher", PUBLISHERS_DIRECTORY);
      snapshotRecords(source, snapshot, fields, "reviewer", REVIEWERS_DIRECTORY);
      if (!fields.isEmpty()) {
        throw new IOException(FAILURE);
      }
      requireEntries(source, Set.of(MANIFEST, PUBLISHERS_DIRECTORY, REVIEWERS_DIRECTORY));
      List<CatalogPublisherBinding> publishers =
          new FileCatalogPublisherBindingStore(snapshot.resolve(PUBLISHERS_DIRECTORY)).list();
      List<CatalogReviewerScope> reviewers =
          new FileCatalogReviewerScopeStore(snapshot.resolve(REVIEWERS_DIRECTORY)).list();
      requireCoveredSubjects(publishers, reviewers);
      prepared = privateDirectory(parent, ".catalog-scope-prepared-");
      FileCatalogPublisherBindingStore publisherStore =
          new FileCatalogPublisherBindingStore(prepared.resolve("catalog-publisher-bindings"));
      FileCatalogReviewerScopeStore reviewerStore =
          new FileCatalogReviewerScopeStore(prepared.resolve("catalog-reviewer-scopes"));
      for (CatalogPublisherBinding binding : publishers) {
        publisherStore.put(binding);
      }
      for (CatalogReviewerScope scope : reviewers) {
        reviewerStore.put(scope);
      }
      List<CatalogPolicy> result = new ArrayList<>();
      for (String catalogId : catalogIds(publishers)) {
        result.add(
            new CatalogPolicy(
                catalogId,
                publisherStore.policyDigest(catalogId),
                reviewerStore.policyDigest(catalogId)));
      }
      Files.writeString(prepared.resolve("catalog-scope-bootstrap.sha256"), expectedDigest + "\n");
      List<CatalogPolicy> policies = List.copyOf(result);
      deleteOwnedDirectory(snapshot);
      snapshot = null;
      Files.move(prepared, target);
      prepared = null;
      return policies;
    } finally {
      try {
        if (snapshot != null) {
          deleteOwnedDirectory(snapshot);
        }
      } finally {
        if (prepared != null) {
          deleteOwnedDirectory(prepared);
        }
      }
    }
  }

  /**
   * Copies one bounded scope family into the private snapshot and consumes its manifest fields.
   *
   * @param source original handoff root
   * @param snapshot invocation-owned snapshot root
   * @param fields mutable manifest fields; processed entries are removed
   * @param prefix manifest field prefix identifying the scope family
   * @param directory scope directory basename beneath both roots
   * @throws IOException if counts, names, digests, directory contents, or file operations are
   *     invalid
   */
  private static void snapshotRecords(
      Path source, Path snapshot, Map<String, String> fields, String prefix, String directory)
      throws IOException {
    int count;
    try {
      count = Integer.parseInt(fields.remove(prefix + ".count"));
    } catch (RuntimeException _) {
      throw new IOException(FAILURE);
    }
    if (count < 1 || count > MAX_RECORDS) {
      throw new IOException(FAILURE);
    }
    Path originals = source.resolve(directory);
    requireSafeDirectory(originals);
    Path copies = Files.createDirectory(snapshot.resolve(directory));
    Set<String> names = new TreeSet<>();
    for (int index = 0; index < count; index++) {
      String name = fields.remove(prefix + "." + index + ".file");
      String digest = fields.remove(prefix + "." + index + ".sha256");
      if (name == null || !RECORD_FILE_NAME.matcher(name).matches() || !names.add(name)) {
        throw new IOException(FAILURE);
      }
      byte[] bytes = readBounded(originals.resolve(name));
      requireDigest(bytes, digest);
      Files.write(copies.resolve(name), bytes);
    }
    requireEntries(originals, names);
  }

  /**
   * Requires active publisher and app-specific reviewer records covering the same catalog/app
   * pairs.
   *
   * <p>This checks subject coverage only; it does not replace runtime signature, channel, or
   * validity checks.
   *
   * @param publishers publisher bindings read through the native store
   * @param reviewers reviewer scopes read through the native store
   * @throws IOException if a record is inactive or lacks its corresponding subject coverage
   */
  private static void requireCoveredSubjects(
      List<CatalogPublisherBinding> publishers, List<CatalogReviewerScope> reviewers)
      throws IOException {
    Set<String> catalogs = catalogIds(publishers);
    for (CatalogPublisherBinding publisher : publishers) {
      if (publisher.status() != CatalogPublisherBinding.Status.ACTIVE
          || reviewers.stream()
              .noneMatch(
                  scope ->
                      scope.catalogId().equals(publisher.catalogId())
                          && scope.appId().equals(java.util.Optional.of(publisher.appId())))) {
        throw new IOException(FAILURE);
      }
    }
    for (CatalogReviewerScope reviewer : reviewers) {
      if (reviewer.status() != CatalogReviewerScope.Status.ACTIVE
          || reviewer.appId().isEmpty()
          || !catalogs.contains(reviewer.catalogId())
          || publishers.stream()
              .noneMatch(
                  binding ->
                      binding.catalogId().equals(reviewer.catalogId())
                          && reviewer.appId().orElseThrow().equals(binding.appId()))) {
        throw new IOException(FAILURE);
      }
    }
  }

  /**
   * Collects the distinct catalog identifiers in deterministic order.
   *
   * @param publishers publisher records from the validated snapshot
   * @return a new sorted set of catalog identifiers
   */
  private static Set<String> catalogIds(List<CatalogPublisherBinding> publishers) {
    Set<String> result = new TreeSet<>();
    publishers.forEach(binding -> result.add(binding.catalogId()));
    return result;
  }

  /**
   * Rejects unlisted or missing immediate directory entries.
   *
   * @param root directory whose children are compared
   * @param expected exact allowed basenames
   * @throws IOException if listing fails or the entry set differs
   */
  private static void requireEntries(Path root, Set<String> expected) throws IOException {
    try (var entries = Files.list(root)) {
      Set<String> actual = new TreeSet<>();
      for (Path path : entries.toList()) {
        Path fileName = path.getFileName();
        if (fileName == null) {
          throw new IOException(FAILURE);
        }
        actual.add(fileName.toString());
      }
      if (!actual.equals(expected)) {
        throw new IOException(FAILURE);
      }
    }
  }

  /**
   * Checks that a directory and all of its ancestors are directories without symbolic links.
   *
   * @param path absolute directory path under caller-controlled ownership
   * @throws IOException if any checked path is absent, a link, or not a directory
   */
  private static void requireSafeDirectory(Path path) throws IOException {
    for (Path current = path; current != null; current = current.getParent()) {
      if (!Files.isDirectory(current, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(current)) {
        throw new IOException(FAILURE);
      }
    }
  }

  /**
   * Reads a non-symlink regular file within the native policy-record byte limit.
   *
   * @param path file to snapshot
   * @return exact file bytes, checked again for size after reading
   * @throws IOException if the file is unsafe, oversized, or unreadable
   */
  private static byte[] readBounded(Path path) throws IOException {
    if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)
        || Files.isSymbolicLink(path)
        || Files.size(path) > FederatedPolicyRecordSupport.MAX_RECORD_BYTES) {
      throw new IOException(FAILURE);
    }
    try (var stream = Files.newInputStream(path, LinkOption.NOFOLLOW_LINKS)) {
      byte[] bytes = stream.readNBytes((int) FederatedPolicyRecordSupport.MAX_RECORD_BYTES + 1);
      if (bytes.length > FederatedPolicyRecordSupport.MAX_RECORD_BYTES) {
        throw new IOException(FAILURE);
      }
      return bytes;
    }
  }

  /**
   * Checks exact bytes against a raw lowercase SHA-256 commitment.
   *
   * @param bytes snapshotted file bytes
   * @param expected independently selected digest, without an algorithm prefix
   * @throws IOException if the digest syntax is invalid or the bytes do not match
   */
  private static void requireDigest(byte[] bytes, String expected) throws IOException {
    if (expected == null || !expected.matches("[0-9a-f]{64}")) {
      throw new IOException(FAILURE);
    }
    try {
      if (!expected.equals(
          HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)))) {
        throw new IOException(FAILURE);
      }
    } catch (NoSuchAlgorithmException impossible) {
      throw new IllegalStateException(impossible);
    }
  }

  /**
   * Creates an invocation-owned temporary directory with owner-only POSIX access where supported.
   *
   * @param parent existing caller-owned parent directory
   * @param prefix temporary directory name prefix
   * @return newly created directory; non-POSIX access controls are inherited
   * @throws IOException if filesystem inspection or directory creation fails
   */
  private static Path privateDirectory(Path parent, String prefix) throws IOException {
    if (Files.getFileStore(parent).supportsFileAttributeView("posix")) {
      return Files.createTempDirectory(
          parent,
          prefix,
          PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
    }
    return Files.createTempDirectory(parent, prefix);
  }

  /**
   * Deletes a caller-owned temporary tree in child-before-parent order without following links.
   *
   * @param root temporary tree created by this invocation
   * @throws IOException if traversal or deletion fails
   */
  private static void deleteOwnedDirectory(Path root) throws IOException {
    try (var paths = Files.walk(root)) {
      for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) {
        Files.delete(path);
      }
    }
  }

  /**
   * Encodes the private CLI result using the fixed schema-version-1 JSON protocol.
   *
   * @param policies native catalog identifiers and hexadecimal policy commitments
   * @return JSON for the protected caller; these commitments are not public telemetry
   */
  private static String summary(List<CatalogPolicy> policies) {
    List<String> rows = new ArrayList<>();
    for (CatalogPolicy policy : policies) {
      rows.add(
          "{\"catalogId\":\""
              + policy.catalogId()
              + "\",\"publisherPolicyDigestSha256\":\""
              + policy.publisherPolicyDigestSha256()
              + "\",\"reviewerPolicyDigestSha256\":\""
              + policy.reviewerPolicyDigestSha256()
              + "\"}");
    }
    return "{\"schemaVersion\":1,\"catalogs\":[" + String.join(",", rows) + "]}";
  }

  /**
   * Private host-local commitments used by the subsequent explicit catalog approval.
   *
   * @param catalogId exact catalog identity
   * @param publisherPolicyDigestSha256 complete catalog-local publisher policy digest
   * @param reviewerPolicyDigestSha256 complete catalog-local reviewer policy digest
   */
  public record CatalogPolicy(
      String catalogId, String publisherPolicyDigestSha256, String reviewerPolicyDigestSha256) {}
}
