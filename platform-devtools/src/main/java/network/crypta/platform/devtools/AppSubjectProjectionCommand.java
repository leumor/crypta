package network.crypta.platform.devtools;

import java.io.IOException;
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
import java.util.concurrent.Callable;
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
 */
@Command(
    name = "subject-projection",
    mixinStandardHelpOptions = true,
    description = "Derive public compatibility metadata from exact signed catalog and app bytes.")
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

  @Option(names = "--output", required = true)
  private Path output;

  /** Creates an invocation whose inputs are populated by Picocli. */
  public AppSubjectProjectionCommand() {
    // Picocli supplies invocation fields after constructing this command.
  }

  // Picocli discovers this method through @Spec when it builds the command model.
  @SuppressWarnings("unused")
  @Spec
  void setSpec(CommandSpec spec) {
    this.spec = spec;
  }

  /**
   * Writes a new public projection only after the entire selected artifact verifies.
   *
   * @return zero on successful derivation, one on a bounded verification failure
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
      Files.writeString(
          output,
          PlatformApiJsonWriter.write(projection) + "\n",
          StandardOpenOption.CREATE_NEW,
          StandardOpenOption.WRITE);
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

  private Map<String, Object> derive(Path scratch) throws IOException {
    Path catalogSnapshot = snapshot(catalog, scratch.resolve("catalog"), 8L * 1024 * 1024);
    Path signatureSnapshot = snapshot(catalogSignature, scratch.resolve("signature"), 64L * 1024);
    var verifiedCatalog =
        AppCatalogVerifier.verify(
            catalogSnapshot, signatureSnapshot, TrustedAppKeys.load(catalogKeys), catalogKeyId);
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
    var keys = TrustedAppKeys.load(publisherKeys);
    Path staged = new AppCatalogBundleExtractor().extract(entry, artifact, scratch, keys);
    var verification = AppBundleVerifier.requireSigned(keys).verify(staged);
    Path manifestPath = staged.resolve(AppBundleDigest.MANIFEST_FILE_NAME);
    var manifest = AppBundleManifestParser.parse(manifestPath);
    var compatibility = manifest.apiCompatibility();
    var catalogCompatibility = entry.compatibility().apiCompatibility();
    if (catalogCompatibility.targetBaselineDeclared()
        && (!java.util.Objects.equals(
                catalogCompatibility.targetBaseline(), compatibility.targetBaseline())
            || catalogCompatibility.targetStability() != compatibility.targetStability())) {
      throw new IOException("catalog compatibility mismatch");
    }
    var result = new LinkedHashMap<String, Object>();
    result.put("schemaVersion", 1);
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
    if (submissionFile != null) {
      Path submission =
          snapshot(submissionFile, scratch.resolve("submission.zip"), 512L * 1024 * 1024);
      var submitted = AppSubmissionPackageVerifier.readVerifiedBundleArtifact(submission);
      if (!MessageDigest.isEqual(submitted.bytes(), Files.readAllBytes(artifact))
          || !digest(manifestPath)
              .equals(SHA256_PREFIX + submitted.submission().manifestDigest())) {
        throw new IOException("submission subject mismatch");
      }
      result.put("submissionDigest", digest(submission));
    }
    addReviewProjection(entry, verification.keyId(), result);
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
    return result;
  }

  private void addReviewProjection(
      AppCatalogEntry entry, String publisherId, Map<String, Object> result) throws IOException {
    if (entry.reviewReceipt().isPresent()) {
      if (reviewerKeys == null) throw new IOException("reviewer trust missing");
      var review =
          AppReviewReceiptVerifier.evaluate(
              entry,
              TrustedReviewerKeys.load(reviewerKeys),
              AppReviewPolicy.DEFAULT,
              Instant.now());
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

  private static Path snapshot(Path source, Path destination, long maximum) throws IOException {
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

  private static String digest(Path file) throws IOException {
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
