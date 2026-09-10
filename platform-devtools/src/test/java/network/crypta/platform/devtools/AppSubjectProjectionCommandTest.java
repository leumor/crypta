package network.crypta.platform.devtools;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyPairGenerator;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.function.UnaryOperator;
import network.crypta.platform.appcatalog.AppCatalogSigner;
import network.crypta.platform.appcatalog.AppSubmissionMaintainer;
import network.crypta.platform.appcatalog.AppSubmissionPackageWriter;
import network.crypta.platform.appcatalog.AppSubmissionSourceReference;
import network.crypta.platform.appcatalog.AppSubmissionType;
import network.crypta.platform.appdist.AppBundlePackager;
import network.crypta.platform.appdist.AppBundleSigner;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import picocli.CommandLine;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

class AppSubjectProjectionCommandTest {
  @TempDir Path temporary;

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
    return new Fixture(catalog, catalogKeys, publisherKeys, bundle, privateRoot);
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
      Path catalog, Path catalogKeys, Path publisherKeys, Path bundle, Path privateRoot) {}
}
