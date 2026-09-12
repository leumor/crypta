package network.crypta.platform.devtools;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;
import network.crypta.platform.api.PlatformApiAppAdmission;
import network.crypta.platform.api.PlatformApiContractJson;
import network.crypta.platform.api.json.PlatformApiJsonWriter;
import network.crypta.platform.appcatalog.AppCatalogBundleExtractor;
import network.crypta.platform.appcatalog.AppCatalogEntry;
import network.crypta.platform.appcatalog.AppCatalogVerifier;
import network.crypta.platform.appcatalog.AppReviewPolicy;
import network.crypta.platform.appcatalog.AppReviewReceiptVerifier;
import network.crypta.platform.appcatalog.AppSubmissionPackageVerifier;
import network.crypta.platform.appcatalog.TrustedReviewerKeys;
import network.crypta.platform.appdist.AppBundleDigest;
import network.crypta.platform.appdist.AppBundleManifestParser;
import network.crypta.platform.appdist.AppBundleSignature;
import network.crypta.platform.appdist.AppBundleVerifier;
import network.crypta.platform.appdist.TrustedAppKeys;
import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.Spec;

/**
 * Derives compatibility declarations from an exact signed catalog and its signed ZIP artifact.
 *
 * <p>The command never executes bundle code. Signature, extraction, manifest, and reviewer checks
 * use the same Java implementations as catalog installation. Its output is a local cryptographic
 * projection, not a protected producer attestation or permission to install an app. A protected
 * collector must independently authenticate the selected source artifacts and this executable.
 *
 * <p>Invoke through picocli so required options and command metadata are populated before {@link
 * #call()}. Each invocation copies selected artifact inputs into a temporary directory beneath an
 * existing POSIX private root with permissions {@code rwx------}. The output contains verified
 * artifact identities and manifest declarations; it does not contain extracted bundle contents or
 * local source paths. An optional submission must contain the same bundle bytes, and a catalog
 * review receipt requires a trusted, positive review under the current default policy.
 *
 * <p>Instances hold mutable invocation state and must not be shared between concurrent executions.
 * The caller owns the trust registries, private root, and output destination; this command does not
 * grant installation authority or fetch an artifact from the catalog's bundle URI. Federation mode
 * requires the independently selected generation and packaged contract pair and emits a private
 * version-3 declaration; its local scope and selection identities must not be publicly disclosed.
 */
@Command(
    name = "subject-projection",
    mixinStandardHelpOptions = true,
    description = "Derive compatibility metadata from exact signed catalog and app bytes.")
public final class AppSubjectProjectionCommand implements Callable<Integer> {
  private static final String SHA256_PREFIX = "sha256:";
  private CommandSpec spec;

  @Option(names = "--catalog", required = true)
  private Path catalog;

  @Option(names = "--catalog-signature", required = true)
  private Path catalogSignature;

  @Option(names = "--catalog-keys", required = true)
  private Path catalogKeys;

  @Option(names = "--catalog-key-id", required = true)
  private String catalogKeyId;

  @Option(names = "--bundle", required = true)
  private Path bundle;

  @Option(names = "--publisher-keys", required = true)
  private Path publisherKeys;

  @Option(names = "--reviewer-keys")
  private Path reviewerKeys;

  @Option(names = "--submission-file")
  private Path submissionFile;

  @Option(names = "--app-id", required = true)
  private String appId;

  @Option(names = "--private-root", required = true)
  private Path privateRoot;

  @Option(names = "--contract")
  private Path contract;

  @Option(names = "--baseline-registry")
  private Path baselineRegistry;

  @Option(names = "--federation-selection")
  private Path federationSelection;

  @Option(names = "--federation-generation")
  private Long federationGeneration;

  @Option(names = "--output", required = true)
  private Path output;

  /**
   * Creates an uninitialized invocation for picocli to populate.
   *
   * <p>Construction alone does not supply the required paths or command output streams.
   */
  public AppSubjectProjectionCommand() {
    // Picocli supplies invocation fields after constructing this command.
  }

  /**
   * Receives command metadata from picocli when it builds the command model.
   *
   * @param spec metadata providing this invocation's output and diagnostic streams
   */
  @SuppressWarnings("unused")
  @Spec
  void setSpec(CommandSpec spec) {
    this.spec = spec;
  }

  /**
   * Writes a new projection only after the entire selected artifact verifies.
   *
   * <p>Version-3 federation selection fields are private operator evidence.
   *
   * <p>The destination is created with {@link StandardOpenOption#CREATE_NEW}; an existing file is
   * never overwritten. Verification or I/O failures emit a fixed diagnostic and return one without
   * exposing exception details. A write failure can leave a partial destination, so callers must
   * require a successful exit before consuming it.
   *
   * <p>Temporary extraction files are deleted on both success and failure. An I/O error during
   * cleanup emits a separate fixed diagnostic but does not change the selected return code; callers
   * requiring complete cleanup must also inspect that diagnostic.
   *
   * @return zero when the projection was written, or one on verification, runtime, or I/O failure
   */
  @Override
  public Integer call() {
    Path scratch = null;
    try {
      if (!Files.isDirectory(privateRoot, LinkOption.NOFOLLOW_LINKS)
          || Files.isSymbolicLink(privateRoot)
          || !Files.getPosixFilePermissions(privateRoot)
              .equals(PosixFilePermissions.fromString("rwx------"))) {
        throw new IOException("unsafe root");
      }
      scratch =
          Files.createTempDirectory(
              privateRoot,
              "subject-",
              PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
      var projection = derive(scratch);
      String serialized = PlatformApiJsonWriter.write(projection) + "\n";
      if (federationSelection == null) {
        Files.writeString(
            output, serialized, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
      } else {
        try (var channel =
            Files.newByteChannel(
                output,
                Set.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE),
                PosixFilePermissions.asFileAttribute(
                    PosixFilePermissions.fromString("rw-------")))) {
          ByteBuffer bytes = StandardCharsets.UTF_8.encode(serialized);
          while (bytes.hasRemaining()) channel.write(bytes);
        }
      }
      spec.commandLine().getOut().println("app_subject_projection_complete");
      return 0;
    } catch (IOException | RuntimeException _) {
      spec.commandLine().getErr().println("app_subject_projection_failed");
      return 1;
    } finally {
      if (scratch != null) {
        try (var paths = Files.walk(scratch)) {
          for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) Files.delete(path);
        } catch (IOException _) {
          spec.commandLine().getErr().println("app_subject_projection_cleanup_incomplete");
        }
      }
    }
  }

  /**
   * Verifies local artifact snapshots and derives declarations from the signed manifest.
   *
   * @param scratch invocation-owned directory for snapshots and extracted bundle files
   * @return ordered projection fields, with absent review and submission identities represented by
   *     {@code null}
   * @throws IOException if reading, extraction, verification, or subject matching fails
   */
  private Map<String, Object> derive(Path scratch) throws IOException {
    if ((federationSelection == null) != (federationGeneration == null)
        || (federationSelection != null && (contract == null || baselineRegistry == null)))
      throw new IOException("federation selection incomplete");
    var selection =
        federationSelection == null
            ? null
            : FederationSelectionContext.snapshot(
                federationSelection,
                federationGeneration,
                Files.createDirectory(scratch.resolve("federation")));
    Path catalogKeysSnapshot = snapshot(catalogKeys, scratch.resolve("catalog-keys"), 1024L * 1024);
    Path publisherKeysSnapshot =
        snapshot(publisherKeys, scratch.resolve("publisher-keys"), 1024L * 1024);
    Path reviewerKeysSnapshot =
        reviewerKeys == null
            ? null
            : snapshot(reviewerKeys, scratch.resolve("reviewer-keys"), 1024L * 1024);
    var catalogTrust = TrustedAppKeys.load(catalogKeysSnapshot);
    var reviewerTrust =
        reviewerKeysSnapshot == null
            ? TrustedReviewerKeys.empty()
            : TrustedReviewerKeys.load(reviewerKeysSnapshot);
    Path catalogSnapshot = snapshot(catalog, scratch.resolve("catalog"), 8L * 1024 * 1024);
    Path signatureSnapshot = snapshot(catalogSignature, scratch.resolve("signature"), 64L * 1024);
    var verifiedCatalog =
        AppCatalogVerifier.verify(catalogSnapshot, signatureSnapshot, catalogTrust, catalogKeyId);
    var entry =
        verifiedCatalog.entries().stream()
            .filter(value -> value.appId().equals(appId))
            .findFirst()
            .orElseThrow(() -> new IOException("missing app"));
    Path artifact = snapshot(bundle, scratch.resolve("artifact.zip"), entry.bundleSizeBytes());
    if (Files.size(artifact) != entry.bundleSizeBytes()
        || !digest(artifact).equals(SHA256_PREFIX + entry.bundleSha256())) {
      throw new IOException("artifact mismatch");
    }
    var keys = TrustedAppKeys.load(publisherKeysSnapshot);
    Path staged = new AppCatalogBundleExtractor().extract(entry, artifact, scratch, keys);
    var verification = AppBundleVerifier.requireSigned(keys).verify(staged);
    Path manifestPath = staged.resolve(AppBundleDigest.MANIFEST_FILE_NAME);
    var manifest = AppBundleManifestParser.parse(manifestPath);
    var compatibility = manifest.apiCompatibility();
    var catalogCompatibility = entry.compatibility().apiCompatibility();
    PlatformApiAppAdmission.requireCatalogDeclarationMatchesManifest(
        catalogCompatibility, compatibility);
    var result = new LinkedHashMap<String, Object>();
    result.put("schemaVersion", contract == null ? 1 : 2);
    result.put("kind", "signed-app-subject-projection");
    result.put("appId", manifest.appId());
    result.put("appVersion", manifest.appVersion());
    result.put("bundleDigest", digest(artifact));
    result.put("bundleSize", Files.size(artifact));
    result.put("manifestDigest", digest(manifestPath));
    result.put("signedContentDigest", SHA256_PREFIX + verification.signedContentDigestSha256());
    result.put("signatureDigest", digest(staged.resolve(AppBundleSignature.SIGNATURE_FILE_NAME)));
    result.put("publisherId", verification.keyId());
    result.put("publisherFingerprint", SHA256_PREFIX + verification.keyFingerprintSha256());
    result.put("catalogId", verifiedCatalog.catalogId());
    result.put("catalogDigest", digest(catalogSnapshot));
    result.put("catalogSignatureDigest", digest(signatureSnapshot));
    result.put("catalogKeyId", catalogKeyId);
    result.put("reviewDigest", null);
    result.put("reviewerId", null);
    result.put("submissionDigest", null);
    addSubmissionProjection(scratch, artifact, manifestPath, result);
    addReviewProjection(entry, verification.keyId(), reviewerTrust, result);
    result.put(
        "targetStability",
        compatibility.targetStabilityDeclared()
            ? compatibility.targetStability().manifestValue()
            : "legacy");
    result.put("targetBaseline", compatibility.targetBaseline());
    result.put("minimumContractVersion", compatibility.minimumVersion());
    result.put("maximumTestedContractVersion", compatibility.maximumTestedVersion());
    result.put("requiredCapabilities", manifest.permissions().stream().sorted().toList());
    result.put(
        "optionalCapabilities", compatibility.optionalCapabilities().stream().sorted().toList());
    result.put(
        "experimentalCapabilitiesAccepted", compatibility.experimentalCapabilitiesAccepted());
    if ((contract == null) != (baselineRegistry == null))
      throw new IOException("target incomplete");
    if (contract != null) {
      Path contractSnapshot =
          snapshot(contract, scratch.resolve("contract.json"), 8L * 1024 * 1024);
      Path registrySnapshot =
          snapshot(baselineRegistry, scratch.resolve("registry.json"), 8L * 1024 * 1024);
      String contractJson = Files.readString(contractSnapshot);
      var target = PlatformApiContractJson.parse(contractJson);
      var registry =
          PlatformApiContractJson.parseBaselineRegistry(Files.readString(registrySnapshot));
      PlatformApiContractJson.verifyBaselineRegistrySummary(contractJson, registry);
      PlatformApiAppAdmission.requireCompatibility(
          compatibility, manifest.permissions(), target, registry);
      result.put("contractSnapshotDigest", digest(contractSnapshot));
      result.put("baselineRegistryDigest", digest(registrySnapshot));
      result.put("nativeAdmission", "accepted");
      result.put("catalogChannel", entry.productionMetadata().channel().catalogValue());
    }
    if (selection != null) {
      result.put(
          "federationSelection", selection.verify(catalogTrust, keys, reviewerTrust, result));
      result.put("schemaVersion", 3);
    }
    return result;
  }

  /**
   * Adds the optional submission identity after matching its bundle and manifest bytes.
   *
   * @param scratch invocation-owned directory for the submission snapshot
   * @param artifact verified bundle archive to match
   * @param manifestPath extracted signed manifest to match
   * @param result projection to update; unchanged when no submission was supplied
   * @throws IOException if snapshotting, verification, or subject matching fails
   */
  private void addSubmissionProjection(
      Path scratch, Path artifact, Path manifestPath, Map<String, Object> result)
      throws IOException {
    if (submissionFile == null) return;
    Path submission =
        snapshot(submissionFile, scratch.resolve("submission.zip"), 512L * 1024 * 1024);
    var submitted = AppSubmissionPackageVerifier.readVerifiedBundleArtifact(submission);
    if (!MessageDigest.isEqual(submitted.bytes(), Files.readAllBytes(artifact))
        || !digest(manifestPath).equals(SHA256_PREFIX + submitted.submission().manifestDigest())) {
      throw new IOException("submission subject mismatch");
    }
    result.put("submissionDigest", digest(submission));
  }

  /**
   * Adds the catalog receipt's identity only after trust, verdict, and publisher checks pass.
   *
   * @param entry verified catalog entry whose optional receipt is evaluated
   * @param publisherId signing key identifier from bundle verification
   * @param reviewerTrust immutable snapshot of the local reviewer registry
   * @param result projection to update; unchanged when the entry has no receipt
   * @throws IOException if a receipt lacks reviewer trust or fails the required checks
   */
  private void addReviewProjection(
      AppCatalogEntry entry,
      String publisherId,
      TrustedReviewerKeys reviewerTrust,
      Map<String, Object> result)
      throws IOException {
    if (entry.reviewReceipt().isPresent()) {
      if (reviewerKeys == null) throw new IOException("reviewer trust missing");
      var review =
          AppReviewReceiptVerifier.evaluate(
              entry, reviewerTrust, AppReviewPolicy.DEFAULT, Instant.now());
      if (!review.trusted() || !review.positive()) throw new IOException("review rejected");
      var receipt = entry.reviewReceipt().orElseThrow();
      if (receipt.payload().bundleKeyId().isPresent()
          && !receipt.payload().bundleKeyId().orElseThrow().equals(publisherId)) {
        throw new IOException("review publisher mismatch");
      }
      result.put("reviewDigest", SHA256_PREFIX + receipt.fingerprintSha256());
      result.put("reviewerId", review.reviewerKeyId());
    }
  }

  /**
   * Copies a regular input file into a new bounded snapshot without following its final symlink.
   *
   * <p>The caller owns cleanup of the destination, including a partial copy after failure.
   *
   * @param source local input file
   * @param destination new snapshot path beneath the invocation's scratch directory
   * @param maximum maximum copied bytes, from one byte through 512 MiB inclusive
   * @return the destination path after the copy completes
   * @throws IOException if the bound or input is invalid, the destination exists, or copying fails
   */
  static Path snapshot(Path source, Path destination, long maximum) throws IOException {
    if (maximum < 1
        || maximum > 512L * 1024 * 1024
        || !Files.isRegularFile(source, LinkOption.NOFOLLOW_LINKS))
      throw new IOException("input rejected");
    try (var input = Files.newInputStream(source, LinkOption.NOFOLLOW_LINKS);
        var target = Files.newOutputStream(destination, StandardOpenOption.CREATE_NEW)) {
      byte[] buffer = new byte[65536];
      long total = 0;
      int count;
      while ((count = input.read(buffer)) != -1) {
        total += count;
        if (total > maximum) throw new IOException("input oversized");
        target.write(buffer, 0, count);
      }
    }
    return destination;
  }

  /**
   * Streams a file into the public artifact digest representation.
   *
   * @param file artifact snapshot or extracted signed metadata file
   * @return {@code sha256:} followed by the lowercase hexadecimal SHA-256 digest
   * @throws IOException if the file cannot be read
   * @throws IllegalStateException if the runtime lacks the required SHA-256 algorithm
   */
  static String digest(Path file) throws IOException {
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      try (var input = Files.newInputStream(file)) {
        byte[] buffer = new byte[65536];
        int count;
        while ((count = input.read(buffer)) != -1) digest.update(buffer, 0, count);
      }
      return SHA256_PREFIX + HexFormat.of().formatHex(digest.digest());
    } catch (java.security.NoSuchAlgorithmException exception) {
      throw new IllegalStateException(exception);
    }
  }
}
