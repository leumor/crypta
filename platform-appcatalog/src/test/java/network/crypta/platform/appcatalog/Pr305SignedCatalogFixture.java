package network.crypta.platform.appcatalog;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import network.crypta.platform.appdist.AppBundlePackager;
import network.crypta.platform.appdist.AppBundleSigner;
import network.crypta.platform.appdist.AppBundleVerifier;
import network.crypta.platform.appdist.PublicKeyFingerprint;
import network.crypta.platform.appdist.TrustedAppKeys;

/** Synthetic local signing fixture; never packaged as runtime or protected producer authority. */
public final class Pr305SignedCatalogFixture {
  private static final String APP_ID = "pr305-fixture";
  private static final Instant NOW = Instant.parse("2026-09-11T00:00:00Z");

  private Pr305SignedCatalogFixture() {}

  /** Creates fresh synthetic bundles, signed reviews/catalogs, and an explicit scope handoff. */
  static void main(String[] args) throws Exception {
    Path root = Path.of(args[0]).toAbsolutePath();
    Files.createDirectories(root);
    KeyPair publisher = key();
    KeyPair otherPublisher = key();
    Map<String, KeyPair> catalogs = new java.util.LinkedHashMap<>();
    for (String id :
        List.of(
            "catalog-a",
            "catalog-b",
            "catalog-conflict",
            "catalog-beta",
            "catalog-publisher-conflict",
            "catalog-deny",
            "catalog-untrusted")) {
      catalogs.put(id, key());
    }
    KeyPair reviewer = key();
    writePublisherKeys(root, publisher);
    Files.writeString(
        root.resolve("publisher-keys.properties"),
        "key.1.id=other-publisher\nkey.1.algorithm=Ed25519\nkey.1.public.key.base64="
            + encoded(otherPublisher)
            + "\n",
        java.nio.file.StandardOpenOption.APPEND);
    writeCatalogKeys(root, catalogs);
    Files.writeString(
        root.resolve("reviewer-keys.properties"),
        "trusted.reviewers.version=2\nreviewer.1.id=reviewer\nreviewer.1.algorithm=Ed25519\n"
            + "reviewer.1.public.key.base64="
            + encoded(reviewer)
            + "\n"
            + "reviewer.1.display.name=Synthetic fixture review\n"
            + "reviewer.1.policy.id=synthetic-review-v1\nreviewer.1.policy.version=1\n");
    writeRevokedRegistries(root);
    List<String> rows = new ArrayList<>();
    rows.add(subject(root, "A1", "catalog-a", "1", publisher, catalogs.get("catalog-a"), reviewer));
    rows.add(subject(root, "A2", "catalog-a", "2", publisher, catalogs.get("catalog-a"), reviewer));
    rows.add(subject(root, "B3", "catalog-b", "3", publisher, catalogs.get("catalog-b"), reviewer));
    rows.add(subject(root, "B4", "catalog-b", "4", publisher, catalogs.get("catalog-b"), reviewer));
    List<String> equivalents =
        List.of(
            subject(root, "E2", "catalog-b", "2", publisher, catalogs.get("catalog-b"), reviewer));
    List<String> negatives = new ArrayList<>();
    negatives.add(
        subject(
            root,
            "C2",
            "catalog-conflict",
            "2",
            publisher,
            catalogs.get("catalog-conflict"),
            reviewer));
    negatives.add(
        subject(
            root, "BETA", "catalog-beta", "4", publisher, catalogs.get("catalog-beta"), reviewer));
    negatives.add(
        subject(
            root,
            "P2",
            "catalog-publisher-conflict",
            "2",
            otherPublisher,
            catalogs.get("catalog-publisher-conflict"),
            reviewer));
    negatives.add(
        subject(
            root,
            "U",
            "catalog-untrusted",
            "2",
            publisher,
            catalogs.get("catalog-untrusted"),
            reviewer));
    negatives.add(
        subject(
            root, "DENY", "catalog-deny", "2", publisher, catalogs.get("catalog-deny"), reviewer));
    bootstrap(root, publisher, reviewer, otherPublisher);
    for (String selected : List.of("A1", "A2", "B3", "B4")) {
      selection(root, selected, catalogs);
    }
    Files.writeString(
        root.resolve("fixture.json"),
        "{\"schemaVersion\":2,\"synthetic\":true,\"appId\":\""
            + APP_ID
            + "\",\"bootstrapManifestDigest\":\""
            + digest(root.resolve("bootstrap/bootstrap.properties"))
            + "\",\"subjects\":{"
            + String.join(",", rows)
            + "},\"equivalents\":{"
            + String.join(",", equivalents)
            + "},\"negatives\":{"
            + String.join(",", negatives)
            + "},\"registryVariants\":{\"publisher\":\"sha256:"
            + digest(root.resolve("publisher-keys-revoked.properties"))
            + "\",\"reviewer\":\"sha256:"
            + digest(root.resolve("reviewer-keys-revoked.properties"))
            + "\"}}\n");
  }

  private static void writeRevokedRegistries(Path root) throws Exception {
    String publishers =
        Files.readString(root.resolve("publisher-keys.properties"))
            .replace("trusted.keys.version=1", "trusted.keys.version=2");
    Path publisherVariant = root.resolve("publisher-keys-revoked.properties");
    Files.writeString(
        publisherVariant,
        publishers
            + "key.0.status=revoked\nkey.0.valid.from=2025-01-01T00:00:00Z\n"
            + "key.0.valid.until=2030-01-01T00:00:00Z\n"
            + "key.1.status=active\nkey.1.valid.from=2025-01-01T00:00:00Z\n"
            + "key.1.valid.until=2030-01-01T00:00:00Z\n");
    TrustedAppKeys.load(publisherVariant);
    Path reviewerVariant = root.resolve("reviewer-keys-revoked.properties");
    Files.writeString(
        reviewerVariant,
        Files.readString(root.resolve("reviewer-keys.properties"))
            + "reviewer.1.status=revoked\nreviewer.1.revoked.at=2026-09-11T00:00:00Z\n"
            + "reviewer.1.revocation.reason=Synthetic revocation drill\n");
    TrustedReviewerKeys.load(reviewerVariant);
  }

  private static String subject(
      Path root,
      String name,
      String catalogId,
      String version,
      KeyPair publisher,
      KeyPair catalog,
      KeyPair reviewer)
      throws Exception {
    Path directory = Files.createDirectory(root.resolve(name));
    String publisherId = name.equals("P2") ? "other-publisher" : "publisher";
    Path bundle = directory.resolve("app");
    Path artifact = directory.resolve("bundle.zip");
    boolean exactEquivalent = name.equals("E2") || name.equals("DENY");
    if (exactEquivalent) {
      copyEquivalent(root.resolve("A2"), directory);
    } else {
      Files.createDirectory(bundle);
      Files.createDirectory(bundle.resolve("static"));
      Files.writeString(
          bundle.resolve("static/index.html"),
          "<!doctype html><title>Synthetic fixture</title><p>" + version + " " + name + "</p>\n");
      Files.createDirectory(bundle.resolve("bin"));
      Path launcher = bundle.resolve("bin/launch.sh");
      Files.writeString(launcher, "#!/bin/sh\nexit 0\n");
      if (Files.getFileStore(bundle).supportsFileAttributeView("posix")) {
        Files.setPosixFilePermissions(launcher, PosixFilePermissions.fromString("rwx------"));
      }
      Files.writeString(
          bundle.resolve("cryptad-app.properties"),
          "manifest.version=1\napp.id="
              + APP_ID
              + "\napp.name=Synthetic federation fixture\n"
              + "app.version="
              + version
              + "\n"
              + "app.exec=bin/launch.sh\n"
              + "app.ui.mode=static\n"
              + "app.ui.entry=static/index.html\n"
              + "api.minimumVersion=1\n"
              + "api.maximumTestedVersion=26\n"
              + "api.targetStability=stable\n"
              + "api.targetBaseline=1.0\n"
              + "api.experimentalCapabilitiesAccepted=false\n");
      AppBundleSigner.sign(bundle, publisherId, publisher.getPrivate());
      AppBundlePackager.packageBundle(bundle, artifact);
      AppSubmissionPackageWriter.create(
          new AppSubmissionPackageWriter.CreateRequest(
              bundle,
              directory.resolve("submission.zip"),
              AppSubmissionType.NEW_APP,
              Optional.empty(),
              Optional.empty(),
              Optional.empty(),
              Optional.empty(),
              Optional.empty(),
              Optional.empty(),
              Optional.empty(),
              Optional.empty(),
              Optional.empty(),
              Optional.empty(),
              new AppSubmissionMaintainer(
                  "Synthetic fixture maintainer", "mailto:fixture@example.invalid"),
              new AppSubmissionSourceReference(
                  java.net.URI.create("https://example.invalid/synthetic-fixture"),
                  Optional.empty()),
              true,
              false));
    }
    Path descriptor = directory.resolve("entry.properties");
    Files.writeString(
        descriptor,
        "artifact.path="
            + artifact
            + "\nbundle.uri="
            + artifact.toUri()
            + "\nsummary=Synthetic federation fixture\nchannel="
            + (name.equals("BETA") ? "beta" : "stable")
            + "\n");
    Path receipt = directory.resolve("review.properties");
    if (!exactEquivalent) {
      AppReviewReceiptIO.write(
          receipt,
          AppReviewReceiptSigner.sign(
              new AppReviewReceiptPayload(
                  1,
                  APP_ID,
                  version,
                  digest(artifact),
                  Files.size(artifact),
                  Optional.of(publisherId),
                  "synthetic-review-v1",
                  "1",
                  AppReviewReceiptStatus.REVIEWED,
                  "reviewer",
                  NOW,
                  Optional.empty(),
                  Optional.empty(),
                  Optional.empty(),
                  Optional.empty(),
                  Optional.of("Synthetic no-side-effect fixture")),
              reviewer.getPrivate()));
    }
    Path catalogFile = directory.resolve("catalog.properties");
    AppCatalogWriter.write(
        new AppCatalogBuildRequest(
            catalogId,
            "Synthetic fixture catalog",
            NOW.plusSeconds(Integer.parseInt(version)),
            List.of(descriptor),
            List.of(receipt),
            name.equals("DENY") ? deniedVersionPolicy(version) : AppCatalogSecurityPolicy.EMPTY,
            catalogFile));
    AppCatalogSigner.sign(catalogFile, catalogId, catalog.getPrivate());
    var authenticated =
        AppCatalogVerifier.verify(
            Files.readAllBytes(catalogFile),
            Files.readAllBytes(directory.resolve("cryptad-app-catalog.signature")),
            TrustedAppKeys.load(root.resolve("catalog-keys.properties")));
    if (name.equals("DENY")) {
      var decision = authenticated.securityPolicy().decisionFor(authenticated.entries().getFirst());
      if (decision.status() != AppCatalogSecurityDecisionStatus.DENYLISTED
          || !decision.blocksInstall()
          || !decision.blocksUpdate()
          || !decision.blocksAutomaticApply()) {
        throw new IllegalStateException("synthetic signed denylist was not enforced");
      }
    }
    AppBundleVerifier.requireSigned(TrustedAppKeys.load(root.resolve("publisher-keys.properties")))
        .verify(bundle);
    if (!AppReviewReceiptVerifier.evaluate(
            authenticated.entries().getFirst(),
            AppReviewReceiptIO.read(receipt),
            TrustedReviewerKeys.load(root.resolve("reviewer-keys.properties")),
            AppReviewPolicy.DEFAULT,
            NOW.plusSeconds(30))
        .positive()) {
      throw new IllegalStateException("synthetic reviewed subject verification failed");
    }
    Map<String, String> values = new java.util.TreeMap<>();
    values.put("appId", APP_ID);
    values.put("catalogId", catalogId);
    values.put("appVersion", version);
    values.put("channel", name.equals("BETA") ? "beta" : "stable");
    values.put("bundleDigest", "sha256:" + digest(artifact));
    values.put("signedContentDigest", "sha256:" + digest(bundle.resolve("cryptad-app.digests")));
    values.put("publisherFingerprint", PublicKeyFingerprint.sha256(publisher.getPublic()));
    values.put("publisherKeyId", publisherId);
    values.put("catalogSignerKeyId", catalogId);
    values.put("catalogSignerFingerprint", PublicKeyFingerprint.sha256(catalog.getPublic()));
    values.put("catalogDigest", "sha256:" + digest(catalogFile));
    values.put(
        "catalogSignatureDigest",
        "sha256:" + digest(directory.resolve("cryptad-app-catalog.signature")));
    values.put("reviewDigest", "sha256:" + digest(receipt));
    List<String> fields = new ArrayList<>();
    values.forEach((key, value) -> fields.add("\"" + key + "\":\"" + value + "\""));
    return "\"" + name + "\":{" + String.join(",", fields) + "}";
  }

  private static void copyEquivalent(Path original, Path target) throws Exception {
    Path app = original.resolve("app");
    try (var files = Files.walk(app)) {
      for (Path file : files.sorted().toList()) {
        Path destination = target.resolve("app").resolve(app.relativize(file));
        if (Files.isDirectory(file)) {
          Files.createDirectory(destination);
        } else {
          Files.copy(file, destination, java.nio.file.StandardCopyOption.COPY_ATTRIBUTES);
        }
      }
    }
    for (String member : List.of("bundle.zip", "review.properties", "submission.zip")) {
      Files.copy(original.resolve(member), target.resolve(member));
      if (Files.mismatch(original.resolve(member), target.resolve(member)) != -1) {
        throw new IllegalStateException("synthetic equivalent bytes changed");
      }
    }
  }

  private static AppCatalogSecurityPolicy deniedVersionPolicy(String version) {
    String advisory = "PR305-SYNTHETIC-DENY";
    return new AppCatalogSecurityPolicy(
        List.of(
            new AppCatalogSecurityAdvisoryRecord(
                advisory,
                java.net.URI.create("https://example.invalid/advisories/pr305-synthetic"),
                "Synthetic denied fixture version",
                AppCatalogSecuritySeverity.CRITICAL,
                AppCatalogSecurityStatus.ACTIVE,
                AppCatalogSecurityAction.DENYLIST,
                "Synthetic fixture must remain blocked under catalog preference.",
                NOW,
                NOW,
                Optional.empty(),
                Optional.empty())),
        List.of(
            new AppCatalogVersionDenylistEntry(
                "pr305-denied-version",
                APP_ID,
                version,
                advisory,
                "Synthetic exact-version denial.",
                Optional.empty(),
                Optional.empty())));
  }

  private static void bootstrap(
      Path root, KeyPair publisher, KeyPair reviewer, KeyPair otherPublisher) throws Exception {
    Path input = Files.createDirectory(root.resolve("bootstrap"));
    FileCatalogPublisherBindingStore publishers =
        new FileCatalogPublisherBindingStore(input.resolve("publishers"));
    FileCatalogReviewerScopeStore reviewers =
        new FileCatalogReviewerScopeStore(input.resolve("reviewers"));
    StringBuilder manifest =
        new StringBuilder("schemaVersion=1\npublisher.count=6\nreviewer.count=6\n");
    List<String> publisherRecords = new ArrayList<>();
    List<String> reviewerRecords = new ArrayList<>();
    int index = 0;
    for (String id :
        List.of(
            "catalog-a",
            "catalog-b",
            "catalog-conflict",
            "catalog-beta",
            "catalog-publisher-conflict",
            "catalog-deny")) {
      boolean competingPublisher = id.equals("catalog-publisher-conflict");
      var publisherBinding =
          CatalogPublisherBinding.create(
              id,
              id,
              APP_ID,
              competingPublisher ? "other-publisher" : "publisher",
              PublicKeyFingerprint.sha256(
                  (competingPublisher ? otherPublisher : publisher).getPublic()),
              CatalogPublisherBinding.Status.ACTIVE,
              NOW.minusSeconds(86400),
              Instant.parse("2030-01-01T00:00:00Z"),
              null,
              null,
              Set.of(AppCatalogChannel.STABLE),
              "synthetic-explicit-host-selection",
              digest("synthetic fixture local approval"),
              NOW,
              NOW,
              "synthetic fixture scope",
              "host-operator");
      var reviewerScope =
          CatalogReviewerScope.create(
              id,
              id,
              APP_ID,
              Map.of("reviewer", PublicKeyFingerprint.sha256(reviewer.getPublic())),
              digest("synthetic approved reviewer set"),
              CatalogReviewerScope.Status.ACTIVE,
              NOW,
              NOW,
              "synthetic fixture scope",
              "host-operator");
      publishers.put(publisherBinding);
      reviewers.put(reviewerScope);
      publisherRecords.add(
          scopeRecord(id, publisherBinding.bindingId(), publisherBinding.selfDigest()));
      reviewerRecords.add(scopeRecord(id, reviewerScope.scopeId(), reviewerScope.selfDigest()));
      manifest
          .append("publisher.")
          .append(index)
          .append(".file=")
          .append(id)
          .append(".properties\n")
          .append("publisher.")
          .append(index)
          .append(".sha256=")
          .append(digest(publisherBinding.canonicalText()))
          .append('\n')
          .append("reviewer.")
          .append(index)
          .append(".file=")
          .append(id)
          .append(".properties\n")
          .append("reviewer.")
          .append(index)
          .append(".sha256=")
          .append(digest(reviewerScope.canonicalText()))
          .append('\n');
      index++;
    }
    Files.writeString(input.resolve("bootstrap.properties"), manifest.toString());
    Files.writeString(
        root.resolve("scoped-records.json"),
        "{\"schemaVersion\":1,\"publisher\":{"
            + String.join(",", publisherRecords)
            + "},\"reviewer\":{"
            + String.join(",", reviewerRecords)
            + "}}\n");
  }

  private static String scopeRecord(String catalogId, String scopeId, String selfDigest) {
    return "\""
        + catalogId
        + "\":{\"scopeId\":\""
        + scopeId
        + "\",\"selfDigestSha256\":\""
        + selfDigest
        + "\"}";
  }

  private static KeyPair key() throws Exception {
    return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
  }

  private static void selection(Path root, String selected, Map<String, KeyPair> catalogKeys)
      throws Exception {
    Path context = Files.createDirectories(root.resolve("selections").resolve(selected));
    List<String> candidates =
        selected.startsWith("B") ? List.of("A2", selected) : List.of(selected);
    List<String> catalogRefs = new ArrayList<>();
    List<String> publisherRefs = new ArrayList<>();
    List<String> reviewerRefs = new ArrayList<>();
    List<String> candidateRefs = new ArrayList<>();
    var publisherSource =
        new FileCatalogPublisherBindingStore(root.resolve("bootstrap/publishers"));
    var reviewerSource = new FileCatalogReviewerScopeStore(root.resolve("bootstrap/reviewers"));
    var trustStore = new FileFederatedCatalogTrustStore(context.resolve("catalogBindings"));
    var publisherStore = new FileCatalogPublisherBindingStore(context.resolve("publisherBindings"));
    var reviewerStore = new FileCatalogReviewerScopeStore(context.resolve("reviewerScopes"));
    for (String candidate : candidates) {
      String catalogId = candidate.startsWith("A") ? "catalog-a" : "catalog-b";
      var binding = publisherSource.find(catalogId).orElseThrow();
      var scope = reviewerSource.find(catalogId).orElseThrow();
      publisherStore.put(binding);
      reviewerStore.put(scope);
      trustStore.put(
          FederatedCatalogTrustBinding.create(
              catalogId,
              catalogId,
              Map.of(
                  catalogId, PublicKeyFingerprint.sha256(catalogKeys.get(catalogId).getPublic())),
              FederatedCatalogTrustBinding.Status.ACTIVE,
              Set.of(AppCatalogChannel.STABLE),
              0,
              null,
              reviewerStore.policyDigest(catalogId),
              publisherStore.policyDigest(catalogId),
              NOW,
              NOW,
              "synthetic explicit selection",
              "host-operator"));
      Path bytes = Files.createDirectory(context.resolve(candidate));
      for (String file :
          List.of(
              "catalog.properties",
              "cryptad-app-catalog.signature",
              "bundle.zip",
              "review.properties")) {
        Files.copy(root.resolve(candidate).resolve(file), bytes.resolve(file));
      }
      catalogRefs.add(
          reference(
              context, context.resolve("catalogBindings").resolve(catalogId + ".properties")));
      publisherRefs.add(
          reference(
              context, context.resolve("publisherBindings").resolve(catalogId + ".properties")));
      reviewerRefs.add(
          reference(context, context.resolve("reviewerScopes").resolve(catalogId + ".properties")));
      candidateRefs.add(
          "{\"catalog\":"
              + reference(context, bytes.resolve("catalog.properties"))
              + ",\"signature\":"
              + reference(context, bytes.resolve("cryptad-app-catalog.signature"))
              + ",\"bundle\":"
              + reference(context, bytes.resolve("bundle.zip"))
              + "}");
    }
    Path original = root.resolve(selected);
    Map<String, String> fields = new java.util.TreeMap<>();
    fields.put("kind", "federated-app-selection");
    fields.put("validFrom", NOW.minusSeconds(86400).toString());
    fields.put("validUntil", "2030-01-01T00:00:00Z");
    fields.put("catalogId", selected.startsWith("A") ? "catalog-a" : "catalog-b");
    fields.put("appId", APP_ID);
    fields.put("channel", "stable");
    fields.put("catalogDigest", "sha256:" + digest(original.resolve("catalog.properties")));
    fields.put(
        "catalogSignatureDigest",
        "sha256:" + digest(original.resolve("cryptad-app-catalog.signature")));
    fields.put(
        "catalogSignerFingerprint",
        "sha256:"
            + PublicKeyFingerprint.sha256(catalogKeys.get(fields.get("catalogId")).getPublic()));
    fields.put("bundleDigest", "sha256:" + digest(original.resolve("bundle.zip")));
    fields.put(
        "signedContentDigest", "sha256:" + digest(original.resolve("app/cryptad-app.digests")));
    fields.put(
        "publisherFingerprint",
        "sha256:"
            + publisherSource
                .find(fields.get("catalogId"))
                .orElseThrow()
                .publisherKeyFingerprintSha256());
    fields.put("reviewDigest", "sha256:" + digest(original.resolve("review.properties")));
    MessageDigest revision = MessageDigest.getInstance("SHA-256");
    for (String file : List.of("catalog.properties", "cryptad-app-catalog.signature")) {
      byte[] bytes = Files.readAllBytes(original.resolve(file));
      revision.update(java.nio.ByteBuffer.allocate(4).putInt(bytes.length).array());
      revision.update(bytes);
    }
    fields.put("catalogRevisionDigest", "sha256:" + HexFormat.of().formatHex(revision.digest()));
    List<String> json = new ArrayList<>();
    json.add("\"schemaVersion\":1");
    json.add("\"generation\":7");
    json.add("\"bundleSize\":" + Files.size(original.resolve("bundle.zip")));
    fields.forEach((key, value) -> json.add("\"" + key + "\":\"" + value + "\""));
    json.add("\"catalogBindings\":[" + String.join(",", catalogRefs) + "]");
    json.add("\"publisherBindings\":[" + String.join(",", publisherRefs) + "]");
    json.add("\"reviewerScopes\":[" + String.join(",", reviewerRefs) + "]");
    json.add("\"candidates\":[" + String.join(",", candidateRefs) + "]");
    Files.writeString(context.resolve("selection.json"), "{" + String.join(",", json) + "}\n");
  }

  private static String reference(Path root, Path file) throws Exception {
    return "{\"path\":\""
        + root.relativize(file).toString().replace('\\', '/')
        + "\",\"digest\":\"sha256:"
        + digest(file)
        + "\"}";
  }

  private static void writeCatalogKeys(Path root, Map<String, KeyPair> keys) throws Exception {
    StringBuilder content = new StringBuilder("trusted.keys.version=1\n");
    int index = 0;
    for (var entry : keys.entrySet()) {
      content
          .append("key.")
          .append(index)
          .append(".id=")
          .append(entry.getKey())
          .append('\n')
          .append("key.")
          .append(index)
          .append(".algorithm=Ed25519\n")
          .append("key.")
          .append(index)
          .append(".public.key.base64=")
          .append(encoded(entry.getValue()))
          .append('\n');
      index++;
    }
    Files.writeString(root.resolve("catalog-keys.properties"), content.toString());
  }

  private static String encoded(KeyPair key) {
    return Base64.getEncoder().encodeToString(key.getPublic().getEncoded());
  }

  private static void writePublisherKeys(Path root, KeyPair key) throws Exception {
    Files.writeString(
        root.resolve("publisher-keys.properties"),
        "trusted.keys.version=1\n"
            + "key.0.id=publisher\n"
            + "key.0.algorithm=Ed25519\n"
            + "key.0.public.key.base64="
            + encoded(key)
            + "\n");
  }

  private static String digest(Path path) throws Exception {
    return HexFormat.of()
        .formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(path)));
  }

  private static String digest(String value) throws Exception {
    return HexFormat.of()
        .formatHex(
            MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
  }
}
