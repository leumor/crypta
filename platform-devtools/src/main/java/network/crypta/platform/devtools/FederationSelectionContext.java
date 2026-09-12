package network.crypta.platform.devtools;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.regex.Pattern;
import network.crypta.platform.api.PlatformApiAppAdmission;
import network.crypta.platform.api.json.PlatformApiJsonWriter;
import network.crypta.platform.appcatalog.AppCatalog;
import network.crypta.platform.appcatalog.AppCatalogBundleExtractor;
import network.crypta.platform.appcatalog.AppCatalogBundleVerificationContext;
import network.crypta.platform.appcatalog.AppCatalogEntry;
import network.crypta.platform.appcatalog.AppCatalogVerifier;
import network.crypta.platform.appcatalog.AppReviewPolicy;
import network.crypta.platform.appcatalog.CatalogScopedPublisherVerificationPolicy;
import network.crypta.platform.appcatalog.CatalogScopedReviewerPolicy;
import network.crypta.platform.appcatalog.FederatedCatalogConflictEngine;
import network.crypta.platform.appcatalog.FederatedCatalogTrustBinding;
import network.crypta.platform.appcatalog.FederatedCatalogVerifier;
import network.crypta.platform.appcatalog.FileCatalogPublisherBindingStore;
import network.crypta.platform.appcatalog.FileCatalogReviewerScopeStore;
import network.crypta.platform.appcatalog.FileFederatedCatalogTrustStore;
import network.crypta.platform.appcatalog.TrustedReviewerKeys;
import network.crypta.platform.appdist.AppBundleDigest;
import network.crypta.platform.appdist.AppBundleManifest;
import network.crypta.platform.appdist.AppBundleManifestParser;
import network.crypta.platform.appdist.AppBundleVerifier;
import network.crypta.platform.appdist.PublicKeyFingerprint;
import network.crypta.platform.appdist.TrustedAppKeys;

/**
 * Invocation-private local federation selection, authenticated externally by the protected
 * producer.
 *
 * <p>The closed handoff carries exact original file references, complete relevant catalog
 * candidates, native scope records and one effective selected subject. Every referenced byte is
 * snapshotted before verification. Native stores below the invocation scratch root only read these
 * immutable snapshots; no live trust store, source, origin, or installed bundle is modified. Public
 * key membership never substitutes for the catalog, publisher and reviewer scopes. The caller must
 * independently authenticate the original handoff and complete candidate roster before invoking
 * this pure tool.
 */
final class FederationSelectionContext {
  /** Closed basename grammar for copied local scope records. */
  private static final Pattern RECORD_FILE_NAME =
      Pattern.compile("[a-z0-9][a-z0-9._-]{0,127}\\.properties");

  /** Canonical handoff field {@code generation}. */
  private static final String FIELD_GENERATION = "generation";

  /** Canonical handoff field {@code catalogId}. */
  private static final String FIELD_CATALOG_ID = "catalogId";

  /** Canonical handoff field {@code appId}. */
  private static final String FIELD_APP_ID = "appId";

  /** Canonical handoff field {@code channel}. */
  private static final String FIELD_CHANNEL = "channel";

  /** Canonical handoff field {@code catalogDigest}. */
  private static final String FIELD_CATALOG_DIGEST = "catalogDigest";

  /** Canonical handoff field {@code catalogSignatureDigest}. */
  private static final String FIELD_CATALOG_SIGNATURE_DIGEST = "catalogSignatureDigest";

  /** Canonical handoff field {@code catalogRevisionDigest}. */
  private static final String FIELD_CATALOG_REVISION_DIGEST = "catalogRevisionDigest";

  /** Canonical handoff field {@code catalogSignerFingerprint}. */
  private static final String FIELD_CATALOG_SIGNER_FINGERPRINT = "catalogSignerFingerprint";

  /** Canonical handoff field {@code bundleDigest}. */
  private static final String FIELD_BUNDLE_DIGEST = "bundleDigest";

  /** Canonical handoff field {@code signedContentDigest}. */
  private static final String FIELD_SIGNED_CONTENT_DIGEST = "signedContentDigest";

  /** Canonical handoff field {@code publisherFingerprint}. */
  private static final String FIELD_PUBLISHER_FINGERPRINT = "publisherFingerprint";

  /** Canonical handoff field {@code reviewDigest}. */
  private static final String FIELD_REVIEW_DIGEST = "reviewDigest";

  /** Canonical handoff field {@code catalogBindings}. */
  private static final String FIELD_CATALOG_BINDINGS = "catalogBindings";

  /** Canonical handoff field {@code publisherBindings}. */
  private static final String FIELD_PUBLISHER_BINDINGS = "publisherBindings";

  /** Canonical handoff field {@code reviewerScopes}. */
  private static final String FIELD_REVIEWER_SCOPES = "reviewerScopes";

  /** Canonical handoff field {@code digest}. */
  private static final String FIELD_DIGEST = "digest";

  /** Canonical handoff field {@code catalog}. */
  private static final String FIELD_CATALOG = "catalog";

  /** Canonical handoff field {@code signature}. */
  private static final String FIELD_SIGNATURE = "signature";

  /** Exact field set accepted for the version-one selection handoff. */
  private static final Set<String> FIELDS =
      Set.of(
          "schemaVersion",
          "kind",
          FIELD_GENERATION,
          "validFrom",
          "validUntil",
          FIELD_CATALOG_ID,
          FIELD_APP_ID,
          FIELD_CHANNEL,
          FIELD_CATALOG_DIGEST,
          FIELD_CATALOG_SIGNATURE_DIGEST,
          FIELD_CATALOG_REVISION_DIGEST,
          FIELD_CATALOG_SIGNER_FINGERPRINT,
          FIELD_BUNDLE_DIGEST,
          "bundleSize",
          FIELD_SIGNED_CONTENT_DIGEST,
          FIELD_PUBLISHER_FINGERPRINT,
          FIELD_REVIEW_DIGEST,
          FIELD_CATALOG_BINDINGS,
          FIELD_PUBLISHER_BINDINGS,
          FIELD_REVIEWER_SCOPES,
          "candidates");

  /** Content identities that must match the independently derived native declaration. */
  private static final Set<String> SUBJECT_FIELDS =
      Set.of(
          FIELD_CATALOG_ID,
          FIELD_APP_ID,
          FIELD_CATALOG_DIGEST,
          FIELD_CATALOG_SIGNATURE_DIGEST,
          FIELD_BUNDLE_DIGEST,
          "bundleSize",
          FIELD_SIGNED_CONTENT_DIGEST,
          FIELD_PUBLISHER_FINGERPRINT,
          FIELD_REVIEW_DIGEST);

  /** Parsed selection fields retained from the private snapshot. */
  private final Map<String, Object> selection;

  /** Prefixed SHA-256 of the original selection snapshot bytes. */
  private final String selectionDigest;

  /** Complete ordered candidate file roster, including competing catalogs. */
  private final List<CandidateFiles> candidates;

  /** Catalog binding store backed only by invocation-owned snapshots. */
  private final FileFederatedCatalogTrustStore catalogs;

  /** Publisher binding store backed only by invocation-owned snapshots. */
  private final FileCatalogPublisherBindingStore publishers;

  /** Reviewer scope store backed only by invocation-owned snapshots. */
  private final FileCatalogReviewerScopeStore reviewers;

  /** Single snapshot-time instant reused for lifecycle and scope checks. */
  private final Instant now;

  /**
   * Binds the copied selection and candidate roster to stores in the private scratch directory.
   *
   * @param selection parsed selection with its exact closed field set
   * @param selectionDigest prefixed digest of the original selection bytes
   * @param scratch invocation-owned root containing copied scope records
   * @param candidates complete candidate snapshots in handoff order
   * @param now instant captured while reading the selection
   */
  private FederationSelectionContext(
      Map<String, Object> selection,
      String selectionDigest,
      Path scratch,
      List<CandidateFiles> candidates,
      Instant now) {
    this.selection = selection;
    this.selectionDigest = selectionDigest;
    this.candidates = List.copyOf(candidates);
    this.catalogs = new FileFederatedCatalogTrustStore(scratch.resolve(FIELD_CATALOG_BINDINGS));
    this.publishers =
        new FileCatalogPublisherBindingStore(scratch.resolve(FIELD_PUBLISHER_BINDINGS));
    this.reviewers = new FileCatalogReviewerScopeStore(scratch.resolve(FIELD_REVIEWER_SCOPES));
    this.now = now;
  }

  /**
   * Reads and confines every reference before any candidate is extracted or verified.
   *
   * <p>The selection is capped at 1 MiB; reference lists are nonempty and capped at 64 entries.
   * Catalog, signature and bundle snapshots together must not exceed 512 MiB. The caller owns
   * scratch cleanup, including partial snapshots left when preparation fails.
   *
   * @param source private selection JSON file; relative references use its parent directory
   * @param expectedGeneration independently approved integer generation, from 1 through 2^53 - 1
   * @param scratch existing invocation-owned directory for new snapshot files and directories
   * @return context bound to the snapshot bytes and one captured verification instant
   * @throws IOException if reading or copying a reference fails
   * @throws IllegalArgumentException if format, generation, validity, confinement or digest checks
   *     fail
   */
  static FederationSelectionContext snapshot(Path source, long expectedGeneration, Path scratch)
      throws IOException {
    Path root = source.toAbsolutePath().normalize().getParent();
    rejectSymlinkPath(source.toAbsolutePath().normalize());
    Path snapshot =
        AppSubjectProjectionCommand.snapshot(
            source, scratch.resolve("selection.json"), 1024L * 1024);
    Map<String, Object> selection =
        object(FederationSelectionJson.parse(Files.readString(snapshot)), FIELDS);
    Instant now = Instant.now();
    long generation = number(selection, FIELD_GENERATION);
    if (number(selection, "schemaVersion") != 1
        || !text(selection, "kind").equals("federated-app-selection")
        || generation < 1
        || generation > 9_007_199_254_740_991L
        || generation != expectedGeneration
        || Instant.parse(text(selection, "validFrom")).isAfter(now)
        || !Instant.parse(text(selection, "validUntil")).isAfter(now)) throw invalid();
    for (String field :
        List.of(
            FIELD_CATALOG_DIGEST,
            FIELD_CATALOG_SIGNATURE_DIGEST,
            FIELD_CATALOG_REVISION_DIGEST,
            FIELD_CATALOG_SIGNER_FINGERPRINT,
            FIELD_BUNDLE_DIGEST,
            FIELD_SIGNED_CONTENT_DIGEST,
            FIELD_PUBLISHER_FINGERPRINT,
            FIELD_REVIEW_DIGEST)) {
      requireDigest(text(selection, field));
    }
    for (String category :
        List.of(FIELD_CATALOG_BINDINGS, FIELD_PUBLISHER_BINDINGS, FIELD_REVIEWER_SCOPES)) {
      Path directory = Files.createDirectory(scratch.resolve(category));
      for (Object item : array(selection, category)) {
        Map<String, Object> reference = object(item, Set.of("path", FIELD_DIGEST));
        Path file = confined(root, text(reference, "path"));
        Path fileName = file.getFileName();
        if (fileName == null) throw invalid();
        String name = fileName.toString();
        if (!RECORD_FILE_NAME.matcher(name).matches()) throw invalid();
        copyReference(root, reference, directory.resolve(name), 1024L * 1024);
      }
    }
    List<CandidateFiles> candidates = new ArrayList<>();
    long total = 0;
    for (Object item : array(selection, "candidates")) {
      Map<String, Object> candidate =
          object(item, Set.of(FIELD_CATALOG, FIELD_SIGNATURE, "bundle"));
      Path directory = Files.createDirectory(scratch.resolve("candidate-" + candidates.size()));
      Path catalog =
          copyReference(
              root,
              candidate.get(FIELD_CATALOG),
              directory.resolve(FIELD_CATALOG),
              8L * 1024 * 1024);
      Path signature =
          copyReference(
              root, candidate.get(FIELD_SIGNATURE), directory.resolve(FIELD_SIGNATURE), 64L * 1024);
      Path bundle =
          copyReference(
              root, candidate.get("bundle"), directory.resolve("bundle.zip"), 512L * 1024 * 1024);
      total += Files.size(catalog) + Files.size(signature) + Files.size(bundle);
      if (total > 512L * 1024 * 1024) throw invalid();
      candidates.add(new CandidateFiles(catalog, signature, bundle, directory));
    }
    return new FederationSelectionContext(
        Map.copyOf(selection), digest(snapshot), scratch, candidates, now);
  }

  /**
   * Runs native signature, scope, lifecycle, channel, manifest and complete conflict checks.
   *
   * <p>Extraction writes only beneath the candidate scratch directories. Use this context for one
   * verification invocation; it is not a live trust-store view or a reusable installation
   * authority.
   *
   * @param catalogKeys immutable public verification registry for catalog signers
   * @param publisherKeys immutable public verification registry for bundle publishers
   * @param reviewerKeys immutable public verification registry for review signers
   * @param declaration fields derived by the native exporter from the selected signed bundle
   * @return private selection, subject, conflict and policy commitments for the declaration
   *     companion
   * @throws IOException if artifact reading or native signature/scope verification fails
   * @throws IllegalArgumentException if selection identities, lifecycle or conflict checks fail
   */
  Map<String, Object> verify(
      TrustedAppKeys catalogKeys,
      TrustedAppKeys publisherKeys,
      TrustedReviewerKeys reviewerKeys,
      Map<String, Object> declaration)
      throws IOException {
    requireMatchingDeclaration(declaration);
    var publisherPolicy =
        new CatalogScopedPublisherVerificationPolicy(
            publishers,
            () -> publisherKeys,
            () -> catalogKeys,
            () -> reviewerKeys,
            Clock.fixed(now, java.time.ZoneOffset.UTC),
            catalogs,
            CatalogScopedPublisherVerificationPolicy.CatalogSignerTrustMode.ROLE_SEPARATED);
    var reviewerPolicy = new CatalogScopedReviewerPolicy(reviewers, catalogs);
    requireCurrentScopes();
    var verified = new ArrayList<VerifiedCandidate>();
    var catalogIds = new HashSet<String>();
    for (CandidateFiles files : candidates) {
      VerifiedCandidate candidate =
          verifyCandidate(
              files, catalogKeys, publisherKeys, reviewerKeys, publisherPolicy, reviewerPolicy);
      if (!catalogIds.add(candidate.catalog().catalogId())) throw invalid();
      verified.add(candidate);
    }
    Set<String> bindings = new HashSet<>();
    for (var binding : catalogs.list()) bindings.add(binding.catalogId());
    if (!bindings.equals(catalogIds)) throw invalid();
    VerifiedCandidate selectedCandidate =
        requireSelectedCandidate(verified, catalogKeys, declaration);
    requireNoSecurityConflicts(verified);
    return projectionResult(verified, selectedCandidate, declaration);
  }

  /**
   * Requires exact selected content identities and channel in the native declaration.
   *
   * @param declaration independently derived native fields
   * @throws IllegalArgumentException if any selected field differs
   */
  private void requireMatchingDeclaration(Map<String, Object> declaration) {
    for (String field : SUBJECT_FIELDS) {
      Object actual = declaration.get(field);
      Object expected = selection.get(field);
      if (actual instanceof Number actualNumber && expected instanceof Number expectedNumber) {
        if (actualNumber.longValue() != expectedNumber.longValue()) throw invalid();
      } else if (!java.util.Objects.equals(actual, expected)) throw invalid();
    }
    if (!text(selection, FIELD_CHANNEL).equals(declaration.get("catalogChannel"))) throw invalid();
  }

  /**
   * Rejects publisher or reviewer records updated after the captured verification instant.
   *
   * @throws IOException if a snapshot store cannot be read
   * @throws IllegalArgumentException if a record is future-dated
   */
  private void requireCurrentScopes() throws IOException {
    for (var publisher : publishers.list()) if (publisher.updatedAt().isAfter(now)) throw invalid();
    for (var reviewer : reviewers.list()) if (reviewer.updatedAt().isAfter(now)) throw invalid();
  }

  /**
   * Finds one selected catalog and checks its exact bytes, revision and signing identity.
   *
   * @param verified all natively verified candidates
   * @param catalogKeys catalog signer verification material
   * @param declaration native declaration containing the selected catalog key ID
   * @return unique candidate matching the selected catalog and artifact commitments
   * @throws IOException if reading candidate or signature bytes fails
   * @throws IllegalArgumentException if selection cardinality or a commitment differs
   */
  private VerifiedCandidate requireSelectedCandidate(
      List<VerifiedCandidate> verified, TrustedAppKeys catalogKeys, Map<String, Object> declaration)
      throws IOException {
    var selected =
        verified.stream()
            .filter(
                candidate ->
                    candidate.catalog().catalogId().equals(text(selection, FIELD_CATALOG_ID)))
            .toList();
    if (selected.size() != 1) throw invalid();
    VerifiedCandidate selectedCandidate = selected.getFirst();
    if (!digest(selectedCandidate.files().catalog()).equals(text(selection, FIELD_CATALOG_DIGEST))
        || !digest(selectedCandidate.files().signature())
            .equals(text(selection, FIELD_CATALOG_SIGNATURE_DIGEST))
        || !digest(selectedCandidate.files().bundle()).equals(text(selection, FIELD_BUNDLE_DIGEST))
        || !revision(selectedCandidate.files())
            .equals(text(selection, FIELD_CATALOG_REVISION_DIGEST))) throw invalid();
    String signer =
        AppCatalogVerifier.readSignature(Files.readAllBytes(selectedCandidate.files().signature()))
            .keyId();
    if (!declaration.get("catalogKeyId").equals(signer)
        || !prefixed(
                PublicKeyFingerprint.sha256(
                    catalogKeys.findPolicy(signer).orElseThrow().key().publicKey()))
            .equals(text(selection, FIELD_CATALOG_SIGNER_FINGERPRINT))) throw invalid();
    return selectedCandidate;
  }

  /**
   * Applies every trusted catalog's version denials to every candidate before conflict
   * classification.
   *
   * @param verified complete verified candidate roster
   * @throws IllegalArgumentException if any catalog blocks a candidate installation or update
   */
  private static void requireNoSecurityConflicts(List<VerifiedCandidate> verified) {
    // Every trusted catalog's exact-version denylist applies before source selection.
    for (VerifiedCandidate candidate : verified) {
      for (VerifiedCandidate other : verified) {
        var decision =
            other
                .catalog()
                .securityPolicy()
                .decisionForInstalledVersion(
                    candidate.entry().appId(), candidate.entry().version());
        if (decision.blocksInstall() || decision.blocksUpdate()) throw invalid();
      }
    }
  }

  /**
   * Classifies the complete subject set and derives the private selected-subject commitments.
   *
   * @param verified complete roster supplied to the native conflict engine
   * @param selectedCandidate verified effective subject selected by the handoff
   * @param declaration native declaration providing the selected app version
   * @return ordered companion fields with prefixed SHA-256 identities
   * @throws IllegalArgumentException if the native engine reports a hard conflict
   */
  private Map<String, Object> projectionResult(
      List<VerifiedCandidate> verified,
      VerifiedCandidate selectedCandidate,
      Map<String, Object> declaration) {
    var conflict =
        FederatedCatalogConflictEngine.classify(
            verified.stream().map(VerifiedCandidate::subject).toList());
    if (conflict.isPresent() && conflict.orElseThrow().hard()) throw invalid();
    String conflictDigest =
        conflict
            .map(value -> prefixed(value.subjectSetDigest()))
            .orElseGet(() -> hash("federation-no-conflict\n" + selectionDigest));
    var identity = new TreeMap<String, Object>();
    for (String field : SUBJECT_FIELDS) identity.put(field, selection.get(field));
    for (String field :
        List.of(
            FIELD_CHANNEL,
            FIELD_GENERATION,
            FIELD_CATALOG_REVISION_DIGEST,
            FIELD_CATALOG_SIGNER_FINGERPRINT)) identity.put(field, selection.get(field));
    identity.put("appVersion", declaration.get("appVersion"));
    var binding = selectedCandidate.binding();
    identity.put("catalogBindingDigest", prefixed(binding.selfDigest()));
    identity.put("publisherPolicyDigest", prefixed(binding.publisherPolicyDigest().orElseThrow()));
    identity.put("publisherBindingDigest", prefixed(selectedCandidate.publisherBindingDigest()));
    identity.put("reviewerPolicyDigest", prefixed(binding.reviewerPolicyDigest().orElseThrow()));
    var result = new LinkedHashMap<String, Object>();
    result.put("selectionDigest", selectionDigest);
    result.put(FIELD_GENERATION, number(selection, FIELD_GENERATION));
    result.put("selectedSubjectDigest", hash(PlatformApiJsonWriter.write(identity)));
    result.put("conflictSetDigest", conflictDigest);
    for (String field :
        List.of(
            "catalogBindingDigest",
            FIELD_CATALOG_REVISION_DIGEST,
            "publisherPolicyDigest",
            "publisherBindingDigest",
            "reviewerPolicyDigest")) result.put(field, identity.get(field));
    return result;
  }

  /**
   * Verifies one snapshotted catalog, scope, review and bundle without executing app code.
   *
   * @param files exact candidate snapshots and their owned extraction directory
   * @param catalogKeys catalog signature verification registry
   * @param publisherKeys bundle signature verification registry
   * @param reviewerKeys review signature verification registry
   * @param publisherPolicy local catalog/app publisher authorization policy
   * @param reviewerPolicy local catalog/app reviewer authorization policy
   * @return candidate with native conflict subject and publisher binding identity
   * @throws IOException if reading, extraction or native verification fails
   * @throws IllegalArgumentException if the candidate does not satisfy the selected policy
   */
  private VerifiedCandidate verifyCandidate(
      CandidateFiles files,
      TrustedAppKeys catalogKeys,
      TrustedAppKeys publisherKeys,
      TrustedReviewerKeys reviewerKeys,
      CatalogScopedPublisherVerificationPolicy publisherPolicy,
      CatalogScopedReviewerPolicy reviewerPolicy)
      throws IOException {
    byte[] content = Files.readAllBytes(files.catalog());
    byte[] signature = Files.readAllBytes(files.signature());
    // Global signature parsing only discovers the binding key; it never supplies scoped authority.
    AppCatalog parsed = AppCatalogVerifier.verify(content, signature, catalogKeys);
    FederatedCatalogTrustBinding binding =
        catalogs
            .findByCatalogId(parsed.catalogId())
            .orElseThrow(FederationSelectionContext::invalid);
    AppCatalog catalog =
        FederatedCatalogVerifier.verifyRoutine(content, signature, catalogKeys, binding);
    if (binding.updatedAt().isAfter(now)) throw invalid();
    var entries =
        catalog.entries().stream()
            .filter(entry -> entry.appId().equals(text(selection, FIELD_APP_ID)))
            .toList();
    if (entries.size() != 1) throw invalid();
    var entry = entries.getFirst();
    if (!binding.allowedChannels().contains(entry.productionMetadata().channel())
        || !entry
            .productionMetadata()
            .channel()
            .catalogValue()
            .equals(text(selection, FIELD_CHANNEL))) throw invalid();
    var security = catalog.securityPolicy().decisionFor(entry);
    if (security.blocksInstall() || security.blocksUpdate() || security.requiresAcknowledgement())
      throw invalid();
    var review =
        reviewerPolicy.evaluate(
            catalog.catalogId(), entry, reviewerKeys, AppReviewPolicy.DEFAULT, now);
    if (!review.authorized() || !review.reviewDecision().positive()) throw invalid();
    if (Files.size(files.bundle()) != entry.bundleSizeBytes()
        || !digest(files.bundle()).equals(prefixed(entry.bundleSha256()))) throw invalid();
    Path staged =
        new AppCatalogBundleExtractor()
            .extract(entry, files.bundle(), files.directory(), publisherKeys);
    var publisherAuthorization =
        publisherPolicy.verify(
            new AppCatalogBundleVerificationContext(catalog.catalogId(), entry), staged);
    var verification = AppBundleVerifier.requireSigned(publisherKeys).verify(staged);
    var receipt = entry.reviewReceipt().orElseThrow().payload();
    if (receipt.bundleKeyId().isPresent()
        && !receipt.bundleKeyId().orElseThrow().equals(verification.keyId())) throw invalid();
    var manifest =
        AppBundleManifestParser.parse(staged.resolve(AppBundleDigest.MANIFEST_FILE_NAME));
    PlatformApiAppAdmission.requireCatalogDeclarationMatchesManifest(
        entry.compatibility().apiCompatibility(), manifest.apiCompatibility());
    // A projection never invents publisher continuity. Exact fingerprints identify this bounded
    // cohort.
    var subject =
        new FederatedCatalogConflictEngine.Subject(
            catalog.catalogId(),
            binding.selfDigest(),
            entry.appId(),
            entry.version(),
            entry.bundleSha256(),
            entry.bundleType(),
            verification.keyFingerprintSha256(),
            verification.keyFingerprintSha256(),
            review.policySemanticDigestSha256(),
            hash(PlatformApiJsonWriter.write(security.toJsonValue())).substring(7),
            metadataDigest(entry, manifest));
    return new VerifiedCandidate(
        catalog,
        entry,
        binding,
        files,
        subject,
        publisherAuthorization.authorizationPolicyDigestSha256());
  }

  /**
   * Hashes canonical compatibility, channel, permissions and review metadata for conflict
   * comparison.
   *
   * @param entry verified catalog entry
   * @param manifest parsed signed bundle manifest
   * @return lowercase SHA-256 hex without an algorithm prefix
   */
  private static String metadataDigest(AppCatalogEntry entry, AppBundleManifest manifest) {
    var metadata = new TreeMap<String, Object>();
    var compatibility = manifest.apiCompatibility();
    metadata.put("version", entry.version());
    metadata.put(FIELD_CHANNEL, entry.productionMetadata().channel().catalogValue());
    metadata.put("permissions", manifest.permissions().stream().sorted().toList());
    metadata.put(
        "optionalCapabilities", compatibility.optionalCapabilities().stream().sorted().toList());
    metadata.put("targetStability", compatibility.targetStability().manifestValue());
    metadata.put("targetStabilityDeclared", compatibility.targetStabilityDeclared());
    metadata.put("targetBaseline", compatibility.targetBaseline());
    metadata.put("minimumContractVersion", compatibility.minimumVersion());
    metadata.put("maximumTestedContractVersion", compatibility.maximumTestedVersion());
    metadata.put(
        "experimentalCapabilitiesAccepted", compatibility.experimentalCapabilitiesAccepted());
    metadata.put(FIELD_REVIEW_DIGEST, entry.reviewReceipt().orElseThrow().fingerprintSha256());
    return hash(PlatformApiJsonWriter.write(metadata)).substring(7);
  }

  /**
   * Commits to catalog and detached signature bytes with a four-byte length before each member.
   *
   * @param files candidate snapshots in catalog-then-signature order
   * @return prefixed SHA-256 revision identity
   * @throws IOException if either snapshot cannot be read
   */
  private static String revision(CandidateFiles files) throws IOException {
    MessageDigest digest = sha256();
    for (Path file : List.of(files.catalog(), files.signature())) {
      byte[] bytes = Files.readAllBytes(file);
      digest.update(ByteBuffer.allocate(4).putInt(bytes.length).array());
      digest.update(bytes);
    }
    return prefixed(HexFormat.of().formatHex(digest.digest()));
  }

  /**
   * Copies a confined reference once and requires its declared digest to match the copied bytes.
   *
   * @param root root against which the relative reference is confined
   * @param value closed object containing path and digest fields
   * @param target new snapshot destination
   * @param maximum largest permitted member size in bytes
   * @return copied snapshot path
   * @throws IOException if bounded snapshot creation or digest reading fails
   * @throws IllegalArgumentException if reference shape, confinement or digest checks fail
   */
  private static Path copyReference(Path root, Object value, Path target, long maximum)
      throws IOException {
    Map<String, Object> reference = object(value, Set.of("path", FIELD_DIGEST));
    String expected = text(reference, FIELD_DIGEST);
    requireDigest(expected);
    Path result =
        AppSubjectProjectionCommand.snapshot(
            confined(root, text(reference, "path")), target, maximum);
    if (!digest(result).equals(expected)) throw invalid();
    return result;
  }

  /**
   * Resolves a restricted relative path to a regular file without symbolic-link ancestors.
   *
   * @param root normalized absolute reference root
   * @param relative handoff path with no absolute, dot or parent segments
   * @return normalized path confined beneath the root
   * @throws IllegalArgumentException if the path spelling or filesystem shape is rejected
   */
  private static Path confined(Path root, String relative) {
    if (!relative.matches("[A-Za-z0-9._/-]{1,512}")) throw invalid();
    Path path = Path.of(relative);
    if (path.isAbsolute()) throw invalid();
    for (Path part : path)
      if (part.toString().equals(".") || part.toString().equals("..")) throw invalid();
    Path result = root.resolve(path).normalize();
    if (!result.startsWith(root)) throw invalid();
    rejectSymlinkPath(result);
    return result;
  }

  /**
   * Rejects symbolic links anywhere in a regular file's ancestor chain.
   *
   * @param path non-null file path to inspect
   * @throws IllegalArgumentException if a link is present or the final path is not a regular file
   * @throws NullPointerException if the path is null
   */
  private static void rejectSymlinkPath(Path path) {
    java.util.Objects.requireNonNull(path);
    for (Path current = path; current != null; current = current.getParent()) {
      if (Files.isSymbolicLink(current)) throw invalid();
    }
    if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) throw invalid();
  }

  /**
   * Copies a parsed object only when its keys exactly match the closed field set.
   *
   * @param value parsed JSON value
   * @param fields complete permitted and required key set
   * @return copied field/value map
   * @throws IllegalArgumentException if the value is not an object with exactly these fields
   */
  private static Map<String, Object> object(Object value, Set<String> fields) {
    if (!(value instanceof Map<?, ?> map) || !map.keySet().equals(fields)) throw invalid();
    var result = new LinkedHashMap<String, Object>();
    for (String field : fields) result.put(field, map.get(field));
    return result;
  }

  /**
   * Reads a required nonempty list with at most 64 members.
   *
   * @param value parsed containing object
   * @param field required list field
   * @return parsed bounded list
   * @throws IllegalArgumentException if the field is absent, not a list, empty or oversized
   */
  private static List<?> array(Map<String, Object> value, String field) {
    if (!(value.get(field) instanceof List<?> list) || list.isEmpty() || list.size() > 64)
      throw invalid();
    return list;
  }

  /**
   * Reads a required nonblank string without coercing other JSON values.
   *
   * @param value parsed containing object
   * @param field required string field
   * @return unchanged nonblank string
   * @throws IllegalArgumentException if the field is absent, blank or not a string
   */
  private static String text(Map<String, Object> value, String field) {
    if (!(value.get(field) instanceof String text) || text.isBlank()) throw invalid();
    return text;
  }

  /**
   * Reads a required long integer without coercion.
   *
   * @param value parsed containing object
   * @param field required integer field
   * @return parsed integer value
   * @throws IllegalArgumentException if the field does not contain a {@link Long}
   */
  private static long number(Map<String, Object> value, String field) {
    if (!(value.get(field) instanceof Long number)) throw invalid();
    return number;
  }

  /**
   * Requires a prefixed lowercase SHA-256 digest.
   *
   * @param digest non-null text to validate
   * @throws IllegalArgumentException if the algorithm prefix or 64 hexadecimal digits are invalid
   */
  private static void requireDigest(String digest) {
    if (!digest.matches("sha256:[0-9a-f]{64}")) throw invalid();
  }

  /**
   * Adds the SHA-256 algorithm prefix to a raw digest.
   *
   * @param digest raw lowercase hexadecimal digest
   * @return digest preceded by {@code sha256:}
   */
  private static String prefixed(String digest) {
    return "sha256:" + digest;
  }

  /**
   * Hashes exact file bytes using the exporter's digest implementation.
   *
   * @param path snapshot file to read
   * @return prefixed SHA-256 digest
   * @throws IOException if the file cannot be read
   */
  private static String digest(Path path) throws IOException {
    return AppSubjectProjectionCommand.digest(path);
  }

  /**
   * Hashes UTF-8 text for a semantic identity.
   *
   * @param text canonical serialized content or domain-separated identity text
   * @return prefixed SHA-256 digest
   */
  private static String hash(String text) {
    return prefixed(
        HexFormat.of().formatHex(sha256().digest(text.getBytes(StandardCharsets.UTF_8))));
  }

  /**
   * Creates a fresh SHA-256 accumulator.
   *
   * @return independent digest instance
   * @throws IllegalStateException if the required SHA-256 provider is unavailable
   */
  private static MessageDigest sha256() {
    try {
      return MessageDigest.getInstance("SHA-256");
    } catch (NoSuchAlgorithmException exception) {
      throw new IllegalStateException(exception);
    }
  }

  /**
   * Creates a fixed diagnostic without including private input details.
   *
   * @return selection-rejection exception
   */
  private static IllegalArgumentException invalid() {
    return new IllegalArgumentException("federation selection rejected");
  }

  /**
   * Exact copied candidate members and their invocation-owned extraction location.
   *
   * @param catalog signed catalog content snapshot
   * @param signature detached catalog signature snapshot
   * @param bundle bundle ZIP snapshot
   * @param directory private candidate directory used for extraction
   */
  private record CandidateFiles(Path catalog, Path signature, Path bundle, Path directory) {}

  /**
   * Native verification result used for complete conflict and selected-subject checks.
   *
   * @param catalog verified catalog content
   * @param entry unique selected app entry in this catalog
   * @param binding local catalog signer and policy binding
   * @param files exact candidate snapshot paths
   * @param subject native conflict-engine identity
   * @param publisherBindingDigest raw digest of the authorized local publisher binding
   */
  private record VerifiedCandidate(
      AppCatalog catalog,
      AppCatalogEntry entry,
      FederatedCatalogTrustBinding binding,
      CandidateFiles files,
      FederatedCatalogConflictEngine.Subject subject,
      String publisherBindingDigest) {}
}
