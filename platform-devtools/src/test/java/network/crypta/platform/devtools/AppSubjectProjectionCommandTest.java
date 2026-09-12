package network.crypta.platform.devtools;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyPairGenerator;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.UnaryOperator;
import network.crypta.platform.api.json.PlatformApiJsonWriter;
import network.crypta.platform.appcatalog.AppCatalogChannel;
import network.crypta.platform.appcatalog.AppCatalogSigner;
import network.crypta.platform.appcatalog.AppSubmissionMaintainer;
import network.crypta.platform.appcatalog.AppSubmissionPackageWriter;
import network.crypta.platform.appcatalog.AppSubmissionSourceReference;
import network.crypta.platform.appcatalog.AppSubmissionType;
import network.crypta.platform.appcatalog.CatalogPublisherBinding;
import network.crypta.platform.appcatalog.CatalogReviewerScope;
import network.crypta.platform.appcatalog.FederatedCatalogTrustBinding;
import network.crypta.platform.appcatalog.FileCatalogPublisherBindingStore;
import network.crypta.platform.appcatalog.FileCatalogReviewerScopeStore;
import network.crypta.platform.appcatalog.FileFederatedCatalogTrustStore;
import network.crypta.platform.appdist.AppBundlePackager;
import network.crypta.platform.appdist.AppBundleSigner;
import network.crypta.platform.appdist.PublicKeyFingerprint;
import network.crypta.platform.appdist.TrustedAppKeys;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import picocli.CommandLine;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

class AppSubjectProjectionCommandTest {
  @TempDir Path temporary;

  @Test
  void projection_whenStableChannelProvided_expectNativeAdmissionAndExactByteIdentities()
      throws Exception {
    assertNativeAdmissionChannel("stable");
  }

  @Test
  void projection_whenBetaChannelProvided_expectNativeAdmissionAndExactByteIdentities()
      throws Exception {
    assertNativeAdmissionChannel("beta");
  }

  private void assertNativeAdmissionChannel(String channel) throws Exception {
    var fixture = prepare(contents -> contents + "app.sample-app.channel=" + channel + "\n");
    Path contract = temporary.resolve("contract.json");
    Path registry = temporary.resolve("registry.json");
    var baseline = network.crypta.platform.api.PlatformApiBaselineRegistry.current();
    Files.writeString(
        contract,
        network.crypta.platform.api.PlatformApiContractJson.writeEnvelope(
            network.crypta.platform.api.PlatformApiContract.current(), baseline));
    Files.writeString(
        registry,
        network.crypta.platform.api.PlatformApiContractJson.writeBaselineRegistry(baseline));
    Path output = temporary.resolve("native.json");

    assertEquals(
        0,
        project(
            fixture,
            output,
            "--contract",
            contract.toString(),
            "--baseline-registry",
            registry.toString()));

    String result = Files.readString(output);
    assertTrue(result.contains("\"schemaVersion\":2"));
    assertTrue(result.contains("\"nativeAdmission\":\"accepted\""));
    assertTrue(result.contains("\"catalogChannel\":\"" + channel + "\""));
    String digest =
        java.util.HexFormat.of()
            .formatHex(
                java.security.MessageDigest.getInstance("SHA-256")
                    .digest(Files.readAllBytes(contract)));
    assertTrue(result.contains("\"contractSnapshotDigest\":\"sha256:" + digest + "\""));
  }

  @Test
  void projection_whenOnlyContractProvided_expectNoOutput() throws Exception {
    var fixture = prepare();
    Path contract = temporary.resolve("contract.json");
    Files.writeString(contract, "{}");
    Path output = temporary.resolve("native.json");

    assertEquals(1, project(fixture, output, "--contract", contract.toString()));

    assertFalse(Files.exists(output));
  }

  @Test
  void projection_whenOnlyRegistryProvided_expectNoOutput() throws Exception {
    var fixture = prepare();
    Path registry = temporary.resolve("registry.json");
    Files.writeString(registry, "{}");
    Path output = temporary.resolve("native.json");

    int result = project(fixture, output, "--baseline-registry", registry.toString());

    assertEquals(1, result);
    assertFalse(Files.exists(output));
  }

  @Test
  void projection_whenTargetSnapshotMalformed_expectNoAdmissionOrPrivateDiagnostic()
      throws Exception {
    var fixture = prepare();
    Path contract = temporary.resolve("private-contract.json");
    Path registry = temporary.resolve("registry.json");
    Files.writeString(contract, "private malformed contract");
    Files.writeString(
        registry,
        network.crypta.platform.api.PlatformApiContractJson.writeBaselineRegistry(
            network.crypta.platform.api.PlatformApiBaselineRegistry.current()));
    Path output = temporary.resolve("native.json");

    Invocation result =
        projectInvocation(
            fixture,
            output,
            "--contract",
            contract.toString(),
            "--baseline-registry",
            registry.toString());

    assertEquals(1, result.exitCode());
    assertFalse(Files.exists(output));
    assertFalse(result.diagnostics().contains(temporary.toString()));
    assertFalse(result.diagnostics().contains("private malformed contract"));
  }

  @Test
  void projection_whenExactSignedArtifactsProvided_expectManifestDerivedFields() throws Exception {
    var fixture = prepare();
    Path output = temporary.resolve("projection.json");

    assertEquals(0, project(fixture, output));

    String projection = Files.readString(output);
    assertTrue(projection.contains("\"requiredCapabilities\":[\"queue.read\"]"));
    assertTrue(projection.contains("\"targetBaseline\":\"1.0\""));
    assertTrue(projection.contains("\"publisherId\":\"publisher\""));
    assertTrue(projection.contains("\"signedContentDigest\":\"sha256:"));
    assertFalse(projection.contains(temporary.toString()));
    assertEquals(1, project(fixture, output));
  }

  @Test
  void projection_whenGenuineDifferentBundleSubstituted_expectNoOutput() throws Exception {
    var fixture = prepare();
    Files.writeString(fixture.bundle(), "substituted artifact");
    Path output = temporary.resolve("projection.json");

    assertEquals(1, project(fixture, output));

    assertFalse(Files.exists(output));
  }

  @Test
  void projection_whenSignedCatalogModified_expectNoOutput() throws Exception {
    var fixture = prepare();
    Files.writeString(
        fixture.catalog(),
        Files.readString(fixture.catalog()).replace("catalog.id=synthetic", "catalog.id=other"));
    Path output = temporary.resolve("projection.json");

    assertEquals(1, project(fixture, output));

    assertFalse(Files.exists(output));
  }

  @Test
  void projection_whenSubmissionContainsExactBundle_expectDerivedSubmissionDigest()
      throws Exception {
    var fixture = prepare();
    Path rationale = temporary.resolve("rationale.txt");
    Files.writeString(rationale, "queue.read: lists synthetic queued requests.\n");
    Path submission = temporary.resolve("submission.zip");
    AppSubmissionPackageWriter.create(
        new AppSubmissionPackageWriter.CreateRequest(
            temporary.resolve("app"),
            submission,
            AppSubmissionType.NEW_APP,
            Optional.empty(),
            Optional.empty(),
            Optional.empty(),
            Optional.of(rationale),
            Optional.empty(),
            Optional.empty(),
            Optional.empty(),
            Optional.empty(),
            Optional.empty(),
            Optional.empty(),
            new AppSubmissionMaintainer(
                "Synthetic maintainer", "mailto:maintainer@example.invalid"),
            new AppSubmissionSourceReference(
                URI.create("https://example.invalid/repository"), Optional.empty()),
            true,
            false));
    Path output = temporary.resolve("projection.json");

    assertEquals(0, project(fixture, output, "--submission-file", submission.toString()));

    assertTrue(Files.readString(output).contains("\"submissionDigest\":\"sha256:"));
  }

  @Test
  void projection_whenPublisherKeySubstituted_expectSanitizedFailureAndScratchCleanup()
      throws Exception {
    var fixture = prepare();
    var unrelatedKey = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    registry("publisher", unrelatedKey.getPublic().getEncoded());
    Path output = temporary.resolve("projection.json");

    Invocation result = projectInvocation(fixture, output);

    assertRejectedProjection(fixture, output, result);
  }

  @Test
  void projection_whenCatalogKeySubstituted_expectSanitizedFailureAndScratchCleanup()
      throws Exception {
    var fixture = prepare();
    var unrelatedKey = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    registry("catalog", unrelatedKey.getPublic().getEncoded());
    Path output = temporary.resolve("projection.json");

    Invocation result = projectInvocation(fixture, output);

    assertRejectedProjection(fixture, output, result);
  }

  @Test
  void projection_whenPrivateRootIsGroupReadable_expectNoOutput() throws Exception {
    var fixture = prepare();
    Files.setPosixFilePermissions(
        fixture.privateRoot(), PosixFilePermissions.fromString("rwxr-x---"));
    Path output = temporary.resolve("projection.json");

    Invocation result = projectInvocation(fixture, output);

    assertRejectedProjection(fixture, output, result);
  }

  @Test
  void projection_whenPrivateRootIsSymlink_expectNoOutputOrTargetMutation() throws Exception {
    var fixture = prepare();
    Path actual = temporary.resolve("actual-private");
    Files.move(fixture.privateRoot(), actual);
    Files.createSymbolicLink(fixture.privateRoot(), actual);
    Path output = temporary.resolve("projection.json");

    Invocation result = projectInvocation(fixture, output);

    assertRejectedProjection(fixture, output, result);
    assertTrue(Files.isSymbolicLink(fixture.privateRoot()));
  }

  @Test
  void projection_whenBundleIsSymlink_expectNoOutputAndPreservedTarget() throws Exception {
    var fixture = prepare();
    Path actual = temporary.resolve("actual-bundle.zip");
    Files.move(fixture.bundle(), actual);
    Files.createSymbolicLink(fixture.bundle(), actual);
    long originalSize = Files.size(actual);
    Path output = temporary.resolve("projection.json");

    Invocation result = projectInvocation(fixture, output);

    assertRejectedProjection(fixture, output, result);
    assertTrue(Files.isSymbolicLink(fixture.bundle()));
    assertEquals(originalSize, Files.size(actual));
  }

  @Test
  void projection_whenOutputAlreadyExists_expectOriginalBytesAndNoScratchFiles() throws Exception {
    var fixture = prepare();
    Path output = temporary.resolve("projection.json");
    Files.writeString(output, "existing-public-projection");

    Invocation result = projectInvocation(fixture, output);

    assertEquals(1, result.exitCode());
    assertEquals("app_subject_projection_failed", result.diagnostics().strip());
    assertEquals("existing-public-projection", Files.readString(output));
    try (var files = Files.list(fixture.privateRoot())) {
      assertEquals(0L, files.count());
    }
  }

  @Test
  void projection_whenCatalogStabilityDiffersWithoutBaseline_expectNoOutput() throws Exception {
    var fixture =
        prepare(
            catalog ->
                catalog
                    .replace("app.sample-app.api.targetBaseline=1.0\n", "")
                    .replace(
                        "app.sample-app.api.targetStability=stable",
                        "app.sample-app.api.targetStability=experimental"));
    Path output = temporary.resolve("projection.json");

    Invocation result = projectInvocation(fixture, output);

    assertRejectedProjection(fixture, output, result);
  }

  @Test
  void projection_whenLegacyCatalogStabilityMatchesWithoutBaseline_expectProjection()
      throws Exception {
    var fixture =
        prepare(catalog -> catalog.replace("app.sample-app.api.targetBaseline=1.0\n", ""));
    Path output = temporary.resolve("projection.json");

    Invocation result = projectInvocation(fixture, output);

    assertEquals(0, result.exitCode());
    assertTrue(Files.readString(output).contains("\"targetStability\":\"stable\""));
    assertTrue(Files.readString(output).contains("\"targetBaseline\":\"1.0\""));
  }

  @Test
  void projection_whenCatalogOmitsStabilityAndBaseline_expectSignedManifestDeclarations()
      throws Exception {
    var fixture =
        prepare(
            catalog ->
                catalog
                    .replace("app.sample-app.api.targetBaseline=1.0\n", "")
                    .replace("app.sample-app.api.targetStability=stable\n", ""));
    Path output = temporary.resolve("projection.json");

    Invocation result = projectInvocation(fixture, output);

    assertEquals(0, result.exitCode());
    assertTrue(Files.readString(output).contains("\"targetStability\":\"stable\""));
    assertTrue(Files.readString(output).contains("\"targetBaseline\":\"1.0\""));
  }

  @Test
  void federation_whenExactScopedReviewedSelection_expectNativeV3Projection() throws Exception {
    var fixture = federationFixture("sample-app", CatalogReviewerScope.Status.ACTIVE);
    Path output = temporary.resolve("federation-output.json");

    var invocation = federationProject(fixture, output, "7");

    assertEquals(0, invocation.exitCode(), invocation.diagnostics());
    String result = Files.readString(output);
    assertTrue(result.contains("\"schemaVersion\":3"));
    assertTrue(result.contains("\"federationSelection\":{"));
    assertTrue(result.contains("\"generation\":7"));
    assertTrue(
        result.contains(
            "\"catalogRevisionDigest\":\""
                + fixture.context().get("catalogRevisionDigest")
                + "\""));
    var publisherStore =
        new FileCatalogPublisherBindingStore(temporary.resolve("publisher-bindings"));
    String selectedBindingDigest = publisherStore.list().getFirst().selfDigest();
    assertTrue(
        result.contains("\"publisherBindingDigest\":\"sha256:" + selectedBindingDigest + "\""));
    assertNotEquals(selectedBindingDigest, publisherStore.policyDigest("synthetic"));

    assertEquals(
        PosixFilePermissions.fromString("rw-------"), Files.getPosixFilePermissions(output));
    assertFalse(result.contains(temporary.toString()));
  }

  @Test
  void federation_whenSameAppFromTwoCatalogs_expectCompleteCandidateSetPreserved()
      throws Exception {
    var fixture = federationFixture("sample-app", CatalogReviewerScope.Status.ACTIVE);
    addCompetingCatalog(fixture, false);
    Path output = temporary.resolve("federation-output.json");

    var invocation = federationProject(fixture, output, "7");

    assertEquals(0, invocation.exitCode(), invocation.diagnostics());
    assertTrue(Files.readString(output).contains("\"conflictSetDigest\":\"sha256:"));
    assertEquals(2, ((List<?>) fixture.context().get("candidates")).size());
  }

  @Test
  void federation_whenSameVersionHasDifferentSignedBytes_expectHardConflict() throws Exception {
    var fixture = federationFixture("sample-app", CatalogReviewerScope.Status.ACTIVE);
    addCompetingCatalog(fixture, true);
    Path output = temporary.resolve("federation-output.json");

    var invocation = federationProject(fixture, output, "7");

    assertRejectedProjection(fixture.base(), output, invocation);
  }

  private void addCompetingCatalog(FederationFixture fixture, boolean changedBundle)
      throws Exception {
    Path secondBundle = fixture.base().bundle();
    Path descriptor = temporary.resolve("entry.properties");
    Path receipt = temporary.resolve("review.properties");
    if (changedBundle) {
      Path app = temporary.resolve("app");
      Files.writeString(app.resolve("extra.txt"), "different signed content, same app and version");
      AppBundleSigner.sign(app, "publisher", fixture.base().publisherKey().getPrivate());
      secondBundle = temporary.resolve("second.zip");
      AppBundlePackager.packageBundle(app, secondBundle);
      descriptor = temporary.resolve("second-entry.properties");
      Files.writeString(
          descriptor,
          "artifact.path="
              + secondBundle
              + "\nbundle.uri="
              + secondBundle.toUri()
              + "\nsummary=Synthetic subject\n");
      receipt = temporary.resolve("second-review.properties");
      assertEquals(
          0,
          cli(
              "review",
              "sign",
              "--catalog-entry",
              descriptor.toString(),
              "--receipt-file",
              receipt.toString(),
              "--reviewer-key-id",
              "reviewer",
              "--reviewer-private-key-file",
              temporary.resolve("reviewer.der").toString(),
              "--policy-id",
              "synthetic-review-v1",
              "--policy-version",
              "1",
              "--status",
              "reviewed",
              "--reviewed-at",
              "2026-05-01T00:00:00Z"));
    }
    Path directory = Files.createDirectory(temporary.resolve("second-catalog"));
    Path secondCatalog = directory.resolve("catalog.properties");
    assertEquals(
        0,
        cli(
            "catalog",
            "create",
            "--catalog-file",
            secondCatalog.toString(),
            "--catalog-id",
            "synthetic-b",
            "--name",
            "Synthetic B",
            "--entry",
            descriptor.toString(),
            "--review-receipt",
            receipt.toString()));
    var secondSigner = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    AppCatalogSigner.sign(secondCatalog, "catalog-b", secondSigner.getPrivate());
    Files.writeString(
        fixture.base().catalogKeys(),
        Files.readString(fixture.base().catalogKeys())
            + "key.1.id=catalog-b\nkey.1.algorithm=Ed25519\nkey.1.public.key.base64="
            + Base64.getEncoder().encodeToString(secondSigner.getPublic().getEncoded())
            + "\n");
    var publisherStore =
        new FileCatalogPublisherBindingStore(temporary.resolve("publisher-bindings"));
    var publisher = publisherStore.list().getFirst();
    publisherStore.put(
        CatalogPublisherBinding.create(
            "publisher-b",
            "synthetic-b",
            publisher.appId(),
            publisher.publisherKeyId(),
            publisher.publisherKeyFingerprintSha256(),
            publisher.status(),
            publisher.validFrom(),
            publisher.validUntil(),
            null,
            null,
            publisher.allowedChannels(),
            publisher.approvalSource(),
            publisher.approvalDigestSha256(),
            publisher.createdAt(),
            publisher.updatedAt(),
            "synthetic",
            "operator"));
    var reviewerStore = new FileCatalogReviewerScopeStore(temporary.resolve("reviewer-scopes"));
    var reviewer = reviewerStore.list().getFirst();
    reviewerStore.put(
        CatalogReviewerScope.create(
            "reviewer-b",
            "synthetic-b",
            "sample-app",
            reviewer.reviewerFingerprints(),
            reviewer.acceptedReviewerSetDigestSha256(),
            reviewer.status(),
            reviewer.createdAt(),
            reviewer.updatedAt(),
            "synthetic",
            "operator"));
    var catalogStore = new FileFederatedCatalogTrustStore(temporary.resolve("catalog-bindings"));
    var catalog = catalogStore.list().getFirst();
    catalogStore.put(
        FederatedCatalogTrustBinding.create(
            "catalog-b",
            "synthetic-b",
            Map.of("catalog-b", PublicKeyFingerprint.sha256(secondSigner.getPublic())),
            catalog.status(),
            catalog.allowedChannels(),
            2,
            "3".repeat(64),
            reviewerStore.policyDigest("synthetic-b"),
            publisherStore.policyDigest("synthetic-b"),
            catalog.createdAt(),
            catalog.updatedAt(),
            "synthetic",
            "operator"));
    for (var pair :
        List.of(
            List.of("catalogBindings", "catalog-bindings/catalog-b.properties"),
            List.of("publisherBindings", "publisher-bindings/publisher-b.properties"),
            List.of("reviewerScopes", "reviewer-scopes/reviewer-b.properties"))) {
      var entries = new ArrayList<Object>((List<?>) fixture.context().get(pair.getFirst()));
      entries.add(reference(temporary.resolve(pair.get(1))));
      fixture.context().put(pair.getFirst(), entries);
    }
    var candidates = new ArrayList<Object>((List<?>) fixture.context().get("candidates"));
    candidates.add(
        Map.of(
            "catalog",
            reference(secondCatalog),
            "signature",
            reference(directory.resolve("cryptad-app-catalog.signature")),
            "bundle",
            reference(secondBundle)));
    fixture.context().put("candidates", candidates);
    Files.writeString(fixture.selection(), PlatformApiJsonWriter.write(fixture.context()));
  }

  @Test
  void federation_whenGenuineCatalogSignatureHasWrongLocalSignerBinding_expectDenied()
      throws Exception {
    var fixture = federationFixture("sample-app", CatalogReviewerScope.Status.ACTIVE);
    var store = new FileFederatedCatalogTrustStore(temporary.resolve("catalog-bindings"));
    var binding = store.list().getFirst();
    var other = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    store.put(
        FederatedCatalogTrustBinding.create(
            binding.bindingId(),
            binding.catalogId(),
            Map.of("catalog", PublicKeyFingerprint.sha256(other.getPublic())),
            binding.status(),
            binding.allowedChannels(),
            binding.localPriority(),
            binding.discoveryProvenanceDigest().orElseThrow(),
            binding.reviewerPolicyDigest().orElseThrow(),
            binding.publisherPolicyDigest().orElseThrow(),
            binding.createdAt(),
            binding.updatedAt(),
            "synthetic",
            "operator"));
    fixture
        .context()
        .put(
            "catalogBindings",
            List.of(reference(temporary.resolve("catalog-bindings/catalog-binding.properties"))));
    Files.writeString(fixture.selection(), PlatformApiJsonWriter.write(fixture.context()));
    Path output = temporary.resolve("federation-output.json");

    var invocation = federationProject(fixture, output, "7");

    assertRejectedProjection(fixture.base(), output, invocation);
  }

  @Test
  void federation_whenInvalidScopedMetadataHasUpdatedBytePin_expectNoGlobalFallback()
      throws Exception {
    var fixture = federationFixture("sample-app", CatalogReviewerScope.Status.ACTIVE);
    Path bindingRecord = temporary.resolve("publisher-bindings/publisher-binding.properties");
    Files.writeString(
        bindingRecord, Files.readString(bindingRecord) + "unrecognizedScope=allow-all\n");
    fixture.context().put("publisherBindings", List.of(reference(bindingRecord)));
    Files.writeString(fixture.selection(), PlatformApiJsonWriter.write(fixture.context()));
    Path output = temporary.resolve("federation-output.json");

    var invocation = federationProject(fixture, output, "7");

    assertRejectedProjection(fixture.base(), output, invocation);
  }

  @Test
  void federation_whenGenerationExceedsExactJsonIntegerRange_expectNoProjection() throws Exception {
    var fixture = federationFixture("sample-app", CatalogReviewerScope.Status.ACTIVE);
    fixture.context().put("generation", 9_007_199_254_740_992L);
    Files.writeString(fixture.selection(), PlatformApiJsonWriter.write(fixture.context()));
    Path output = temporary.resolve("federation-output.json");

    var invocation = federationProject(fixture, output, "9007199254740992");

    assertRejectedProjection(fixture.base(), output, invocation);
  }

  @Test
  void federation_whenGenerationStale_expectNoGlobalFallback() throws Exception {
    var fixture = federationFixture("sample-app", CatalogReviewerScope.Status.ACTIVE);
    Path output = temporary.resolve("federation-output.json");

    var invocation = federationProject(fixture, output, "6");

    assertRejectedProjection(fixture.base(), output, invocation);
  }

  @Test
  void federation_whenPublisherOutsideAppScope_expectNoGlobalFallback() throws Exception {
    var fixture = federationFixture("other-app", CatalogReviewerScope.Status.ACTIVE);
    Path output = temporary.resolve("federation-output.json");

    var invocation = federationProject(fixture, output, "7");

    assertRejectedProjection(fixture.base(), output, invocation);
  }

  @Test
  void federation_whenReviewerScopeRevoked_expectNoGlobalFallback() throws Exception {
    var fixture = federationFixture("sample-app", CatalogReviewerScope.Status.REVOKED);
    Path output = temporary.resolve("federation-output.json");

    var invocation = federationProject(fixture, output, "7");

    assertRejectedProjection(fixture.base(), output, invocation);
  }

  @Test
  void federation_whenSelectedIdentitySubstituted_expectEveryFieldRejected() throws Exception {
    var fixture = federationFixture("sample-app", CatalogReviewerScope.Status.ACTIVE);
    String original = Files.readString(fixture.selection());
    for (String field :
        List.of(
            "catalogId",
            "appId",
            "channel",
            "catalogDigest",
            "catalogSignatureDigest",
            "catalogRevisionDigest",
            "catalogSignerFingerprint",
            "bundleDigest",
            "signedContentDigest",
            "publisherFingerprint",
            "reviewDigest")) {
      var changed = new LinkedHashMap<>(fixture.context());
      changed.put(
          field,
          field.endsWith("Digest") || field.endsWith("Fingerprint")
              ? "sha256:" + "0".repeat(64)
              : "other");
      Files.writeString(fixture.selection(), PlatformApiJsonWriter.write(changed));
      Path output = temporary.resolve("rejected-" + field + ".json");

      var invocation = federationProject(fixture, output, "7");

      assertRejectedProjection(fixture.base(), output, invocation);
    }
    Files.writeString(fixture.selection(), original);
  }

  @Test
  void federation_whenContextIncompleteOrUnknown_expectNoProjection() throws Exception {
    var fixture = federationFixture("sample-app", CatalogReviewerScope.Status.ACTIVE);
    var changed = new LinkedHashMap<>(fixture.context());
    changed.put("verified", "true");
    Files.writeString(fixture.selection(), PlatformApiJsonWriter.write(changed));
    Path output = temporary.resolve("invalid.json");

    var invocation = federationProject(fixture, output, "7");

    assertRejectedProjection(fixture.base(), output, invocation);
  }

  @Test
  void federation_whenScopeReferenceEscapesOrTraversesSymlink_expectNoProjection()
      throws Exception {
    var fixture = federationFixture("sample-app", CatalogReviewerScope.Status.ACTIVE);
    var changed = new LinkedHashMap<>(fixture.context());
    changed.put(
        "publisherBindings",
        List.of(Map.of("path", "../outside.properties", "digest", "sha256:" + "0".repeat(64))));
    Files.writeString(fixture.selection(), PlatformApiJsonWriter.write(changed));
    Path output = temporary.resolve("invalid.json");

    var invocation = federationProject(fixture, output, "7");

    assertRejectedProjection(fixture.base(), output, invocation);
  }

  @Test
  void federation_whenContractOrGenerationMissing_expectNoProjection() throws Exception {
    var fixture = federationFixture("sample-app", CatalogReviewerScope.Status.ACTIVE);
    Path output = temporary.resolve("invalid.json");

    var invocation =
        projectInvocation(
            fixture.base(), output, "--federation-selection", fixture.selection().toString());

    assertRejectedProjection(fixture.base(), output, invocation);
  }

  private FederationFixture federationFixture(
      String publisherAppId, CatalogReviewerScope.Status reviewerStatus) throws Exception {
    Fixture base = prepare();
    var reviewer = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    Path privateKey = temporary.resolve("reviewer.der");
    Files.write(privateKey, reviewer.getPrivate().getEncoded());
    Path reviewerKeys = temporary.resolve("reviewer-keys.properties");
    Files.writeString(
        reviewerKeys,
        "trusted.reviewers.version=1\n"
            + "reviewer.1.id=reviewer\n"
            + "reviewer.1.algorithm=Ed25519\n"
            + "reviewer.1.public.key.base64="
            + Base64.getEncoder().encodeToString(reviewer.getPublic().getEncoded())
            + "\n"
            + "reviewer.1.display.name=Synthetic Review\n"
            + "reviewer.1.policy.id=synthetic-review-v1\n");
    Path receipt = temporary.resolve("review.properties");
    assertEquals(
        0,
        cli(
            "review",
            "sign",
            "--catalog-entry",
            temporary.resolve("entry.properties").toString(),
            "--receipt-file",
            receipt.toString(),
            "--reviewer-key-id",
            "reviewer",
            "--reviewer-private-key-file",
            privateKey.toString(),
            "--policy-id",
            "synthetic-review-v1",
            "--policy-version",
            "1",
            "--status",
            "reviewed",
            "--reviewed-at",
            "2026-05-01T00:00:00Z"));
    Files.delete(base.catalog());
    Files.delete(temporary.resolve("cryptad-app-catalog.signature"));
    assertEquals(
        0,
        cli(
            "catalog",
            "create",
            "--catalog-file",
            base.catalog().toString(),
            "--catalog-id",
            "synthetic",
            "--name",
            "Synthetic",
            "--entry",
            temporary.resolve("entry.properties").toString(),
            "--review-receipt",
            receipt.toString()));
    AppCatalogSigner.sign(base.catalog(), "catalog", base.catalogKey().getPrivate());
    var catalogRegistry = TrustedAppKeys.load(base.catalogKeys());
    var publisherRegistry = TrustedAppKeys.load(base.publisherKeys());
    String publisherFingerprint =
        PublicKeyFingerprint.sha256(
            publisherRegistry.findPolicy("publisher").orElseThrow().key().publicKey());
    String catalogFingerprint =
        PublicKeyFingerprint.sha256(
            catalogRegistry.findPolicy("catalog").orElseThrow().key().publicKey());
    Instant at = Instant.parse("2026-05-01T00:00:00Z");
    Path publisherRoot = temporary.resolve("publisher-bindings");
    var publisherStore = new FileCatalogPublisherBindingStore(publisherRoot);
    publisherStore.put(
        CatalogPublisherBinding.create(
            "publisher-binding",
            "synthetic",
            publisherAppId,
            "publisher",
            publisherFingerprint,
            CatalogPublisherBinding.Status.ACTIVE,
            at,
            Instant.parse("2099-01-01T00:00:00Z"),
            null,
            null,
            Set.of(AppCatalogChannel.STABLE),
            "synthetic",
            "1".repeat(64),
            at,
            at,
            "synthetic",
            "operator"));
    Path reviewerRoot = temporary.resolve("reviewer-scopes");
    var reviewerStore = new FileCatalogReviewerScopeStore(reviewerRoot);
    reviewerStore.put(
        CatalogReviewerScope.create(
            "reviewer-scope",
            "synthetic",
            "sample-app",
            Map.of("reviewer", PublicKeyFingerprint.sha256(reviewer.getPublic())),
            "2".repeat(64),
            reviewerStatus,
            at,
            at,
            "synthetic",
            "operator"));
    Path catalogRoot = temporary.resolve("catalog-bindings");
    var catalogStore = new FileFederatedCatalogTrustStore(catalogRoot);
    catalogStore.put(
        FederatedCatalogTrustBinding.create(
            "catalog-binding",
            "synthetic",
            Map.of("catalog", catalogFingerprint),
            FederatedCatalogTrustBinding.Status.ACTIVE,
            Set.of(AppCatalogChannel.STABLE),
            1,
            "3".repeat(64),
            reviewerStore.policyDigest("synthetic"),
            publisherStore.policyDigest("synthetic"),
            at,
            at,
            "synthetic",
            "operator"));
    Path contract = temporary.resolve("federation-contract.json");
    Path registry = temporary.resolve("federation-registry.json");
    var baseline = network.crypta.platform.api.PlatformApiBaselineRegistry.current();
    Files.writeString(
        contract,
        network.crypta.platform.api.PlatformApiContractJson.writeEnvelope(
            network.crypta.platform.api.PlatformApiContract.current(), baseline));
    Files.writeString(
        registry,
        network.crypta.platform.api.PlatformApiContractJson.writeBaselineRegistry(baseline));
    Path originalProjection = temporary.resolve("original-projection.json");
    assertEquals(0, project(base, originalProjection, "--reviewer-keys", reviewerKeys.toString()));
    @SuppressWarnings("unchecked")
    var original =
        (Map<String, Object>) FederationSelectionJson.parse(Files.readString(originalProjection));
    var context = new LinkedHashMap<String, Object>();
    context.put("schemaVersion", 1);
    context.put("kind", "federated-app-selection");
    context.put("generation", 7);
    context.put("validFrom", at.toString());
    context.put("validUntil", "2099-01-01T00:00:00Z");
    for (String field :
        List.of(
            "catalogId",
            "appId",
            "catalogDigest",
            "catalogSignatureDigest",
            "bundleDigest",
            "bundleSize",
            "signedContentDigest",
            "publisherFingerprint",
            "reviewDigest")) context.put(field, original.get(field));
    context.put("channel", "stable");
    context.put("catalogSignerFingerprint", "sha256:" + catalogFingerprint);
    var revision = java.security.MessageDigest.getInstance("SHA-256");
    for (Path file : List.of(base.catalog(), temporary.resolve("cryptad-app-catalog.signature"))) {
      byte[] bytes = Files.readAllBytes(file);
      revision.update(java.nio.ByteBuffer.allocate(4).putInt(bytes.length).array());
      revision.update(bytes);
    }
    context.put(
        "catalogRevisionDigest", "sha256:" + java.util.HexFormat.of().formatHex(revision.digest()));
    context.put(
        "catalogBindings", List.of(reference(catalogRoot.resolve("catalog-binding.properties"))));
    context.put(
        "publisherBindings",
        List.of(reference(publisherRoot.resolve("publisher-binding.properties"))));
    context.put(
        "reviewerScopes", List.of(reference(reviewerRoot.resolve("reviewer-scope.properties"))));
    context.put(
        "candidates",
        List.of(
            Map.of(
                "catalog",
                reference(base.catalog()),
                "signature",
                reference(temporary.resolve("cryptad-app-catalog.signature")),
                "bundle",
                reference(base.bundle()))));
    Path selection = temporary.resolve("selection.json");
    Files.writeString(selection, PlatformApiJsonWriter.write(context));
    return new FederationFixture(base, selection, contract, registry, reviewerKeys, context);
  }

  private Map<String, Object> reference(Path path) throws Exception {
    return Map.of(
        "path",
        temporary.relativize(path).toString(),
        "digest",
        AppSubjectProjectionCommand.digest(path));
  }

  private Invocation federationProject(FederationFixture fixture, Path output, String generation) {
    return projectInvocation(
        fixture.base(),
        output,
        "--reviewer-keys",
        fixture.reviewerKeys().toString(),
        "--contract",
        fixture.contract().toString(),
        "--baseline-registry",
        fixture.registry().toString(),
        "--federation-selection",
        fixture.selection().toString(),
        "--federation-generation",
        generation);
  }

  private record FederationFixture(
      Fixture base,
      Path selection,
      Path contract,
      Path registry,
      Path reviewerKeys,
      Map<String, Object> context) {}

  private void assertRejectedProjection(Fixture fixture, Path output, Invocation result)
      throws Exception {
    assertEquals(1, result.exitCode());
    assertEquals("app_subject_projection_failed", result.diagnostics().strip());
    assertFalse(Files.exists(output));
    try (var files = Files.list(fixture.privateRoot())) {
      assertEquals(0L, files.count());
    }
  }

  private Fixture prepare() throws Exception {
    return prepare(UnaryOperator.identity());
  }

  private Fixture prepare(UnaryOperator<String> catalogTransform) throws Exception {
    Path app = temporary.resolve("app");
    assertEquals(
        0,
        cli(
            "init",
            "--dir",
            app.toString(),
            "--app-id",
            "sample-app",
            "--name",
            "Synthetic app",
            "--version",
            "1",
            "--permission",
            "queue.read"));
    var publisher = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    var catalogKey = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    AppBundleSigner.sign(app, "publisher", publisher.getPrivate());
    Path bundle = temporary.resolve("app.zip");
    AppBundlePackager.packageBundle(app, bundle);
    Path entry = temporary.resolve("entry.properties");
    Files.writeString(
        entry,
        "artifact.path="
            + bundle
            + "\nbundle.uri="
            + bundle.toUri()
            + "\nsummary=Synthetic subject\n");
    Path catalog = temporary.resolve("catalog.properties");
    assertEquals(
        0,
        cli(
            "catalog",
            "create",
            "--catalog-file",
            catalog.toString(),
            "--catalog-id",
            "synthetic",
            "--name",
            "Synthetic",
            "--entry",
            entry.toString()));
    String catalogContents = Files.readString(catalog);
    assertTrue(catalogContents.contains("app.sample-app.api.targetBaseline=1.0\n"));
    assertTrue(catalogContents.contains("app.sample-app.api.targetStability=stable\n"));
    Files.writeString(catalog, catalogTransform.apply(catalogContents));
    AppCatalogSigner.sign(catalog, "catalog", catalogKey.getPrivate());
    Path catalogKeys = registry("catalog", catalogKey.getPublic().getEncoded());
    Path publisherKeys = registry("publisher", publisher.getPublic().getEncoded());
    Path privateRoot =
        Files.createDirectory(
            temporary.resolve("private"),
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
    return new Fixture(
        catalog, catalogKeys, publisherKeys, bundle, privateRoot, catalogKey, publisher);
  }

  private Path registry(String id, byte[] key) throws Exception {
    Path file = temporary.resolve(id + "-keys.properties");
    Files.writeString(
        file,
        "trusted.keys.version=1\nkey.0.id="
            + id
            + "\nkey.0.algorithm=Ed25519\nkey.0.public.key.base64="
            + Base64.getEncoder().encodeToString(key)
            + "\n");
    return file;
  }

  private int project(Fixture fixture, Path output, String... extra) {
    return projectInvocation(fixture, output, extra).exitCode();
  }

  private Invocation projectInvocation(Fixture fixture, Path output, String... extra) {
    var arguments =
        new ArrayList<>(
            List.of(
                "subject-projection",
                "--catalog",
                fixture.catalog().toString(),
                "--catalog-signature",
                temporary.resolve("cryptad-app-catalog.signature").toString(),
                "--catalog-keys",
                fixture.catalogKeys().toString(),
                "--catalog-key-id",
                "catalog",
                "--publisher-keys",
                fixture.publisherKeys().toString(),
                "--bundle",
                fixture.bundle().toString(),
                "--app-id",
                "sample-app",
                "--private-root",
                fixture.privateRoot().toString(),
                "--output",
                output.toString()));
    arguments.addAll(List.of(extra));
    var diagnostics = new StringWriter();
    int result =
        CryptaAppCli.execute(
            new PrintWriter(diagnostics),
            new PrintWriter(diagnostics),
            arguments.toArray(String[]::new));
    return new Invocation(result, diagnostics.toString());
  }

  private int cli(String... arguments) {
    var output = new StringWriter();
    var command = new CommandLine(new CryptaAppCli());
    command.setOut(new PrintWriter(output));
    command.setErr(new PrintWriter(output));
    int result = command.execute(arguments);
    if (result != 0 && !arguments[0].equals("subject-projection")) fail(output.toString());
    return result;
  }

  private record Invocation(int exitCode, String diagnostics) {}

  private record Fixture(
      Path catalog,
      Path catalogKeys,
      Path publisherKeys,
      Path bundle,
      Path privateRoot,
      java.security.KeyPair catalogKey,
      java.security.KeyPair publisherKey) {}
}
