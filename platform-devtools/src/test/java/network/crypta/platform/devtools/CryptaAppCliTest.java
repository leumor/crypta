package network.crypta.platform.devtools;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipOutputStream;
import network.crypta.platform.api.PlatformApiBaselineDefinition;
import network.crypta.platform.api.PlatformApiBaselineEvidenceKind;
import network.crypta.platform.api.PlatformApiBaselineId;
import network.crypta.platform.api.PlatformApiBaselineLineage;
import network.crypta.platform.api.PlatformApiBaselineRegistry;
import network.crypta.platform.api.PlatformApiBaselineStatus;
import network.crypta.platform.api.PlatformApiContract;
import network.crypta.platform.api.PlatformApiContractJson;
import network.crypta.platform.api.json.PlatformApiJsonWriter;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import picocli.CommandLine;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class CryptaAppCliTest {
  private static final String SUBMISSION_METADATA_ENTRY = "crypta-app-submission.json";
  private static final String SUBMISSION_BUNDLE_ARTIFACT_ENTRY = "artifacts/app-bundle.zip";

  @TempDir private Path tempDir;

  @Test
  void init_whenStaticAppRequested_expectStandaloneBundleSkeleton() throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    CliResult result =
        runCli(
            "init",
            "--dir",
            appDir.toString(),
            "--app-id",
            "sample-app",
            "--name",
            "Sample App",
            "--version",
            "0.1.0");

    assertEquals(CommandLine.ExitCode.OK, result.exitCode());
    assertTrue(Files.isRegularFile(appDir.resolve("cryptad-app.properties")));
    assertTrue(Files.isRegularFile(appDir.resolve("bin").resolve("start.sh")));
    assertTrue(Files.isRegularFile(appDir.resolve("static").resolve("index.html")));
    assertTrue(Files.isRegularFile(appDir.resolve("static").resolve("app.js")));
    assertTrue(Files.isRegularFile(appDir.resolve("static").resolve("app.css")));
    assertTrue(Files.isRegularFile(appDir.resolve("static").resolve("crypta-platform.js")));
    assertTrue(
        Files.isRegularFile(
            appDir.resolve("static").resolve("crypta-ui").resolve("crypta-ui-tokens.css")));
    assertTrue(
        Files.isRegularFile(
            appDir.resolve("static").resolve("crypta-ui").resolve("crypta-ui.css")));
    assertTrue(
        Files.isRegularFile(
            appDir.resolve("static").resolve("crypta-ui").resolve("crypta-ui-components.js")));
    assertTrue(Files.isRegularFile(appDir.resolve("README.md")));
    assertTrue(result.out().contains("Initialized app bundle"));
    String indexHtml = Files.readString(appDir.resolve("static").resolve("index.html"));
    assertTrue(indexHtml.indexOf("crypta-ui-tokens.css") < indexHtml.indexOf("crypta-ui.css"));
    assertTrue(indexHtml.indexOf("crypta-ui.css") < indexHtml.indexOf("app.css"));
    assertTrue(indexHtml.contains("class=\"cr-app\""));
    assertTrue(
        Files.readString(appDir.resolve("static").resolve("crypta-platform.js"))
            .contains("window.CryptaPlatform"));
  }

  @Test
  void init_whenNoPermissionsRequested_expectManifestOmitsBlankPermissions() throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");

    String manifest =
        Files.readString(appDir.resolve("cryptad-app.properties"), StandardCharsets.UTF_8);

    assertFalse(manifest.contains("app.permissions="));
    assertTrue(
        manifest.contains(
            "api.minimumVersion="
                + PlatformApiContract.current().stableBaseline().contractVersion()
                + "\n"));
    assertTrue(manifest.contains("api.maximumTestedVersion=" + currentContractVersion() + "\n"));
    assertTrue(manifest.contains("api.targetStability=stable\n"));
    assertTrue(manifest.contains("api.targetBaseline=1.0\n"));
    assertTrue(manifest.contains("api.experimentalCapabilitiesAccepted=false\n"));
  }

  @Test
  void init_whenPermissionCaseNeedsNormalization_expectDisclosureAndManifestUseCanonicalValue()
      throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0",
        "--permission",
        "Queue.Read");

    CliResult result = runCli("ui", "lint", "--bundle-dir", appDir.toString(), "--strict");
    String manifest =
        Files.readString(appDir.resolve("cryptad-app.properties"), StandardCharsets.UTF_8);
    String indexHtml =
        Files.readString(appDir.resolve("static").resolve("index.html"), StandardCharsets.UTF_8);

    assertEquals(CommandLine.ExitCode.OK, result.exitCode());
    assertTrue(manifest.contains("app.permissions=queue.read\n"));
    assertTrue(indexHtml.contains("<code>queue.read</code>"));
    assertFalse(indexHtml.contains("Queue.Read"));
  }

  @Test
  void init_whenExperimentalPermissionRequested_expectExperimentalMetadataAndStrictValidation()
      throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0",
        "--permission",
        "vault.identities.read");

    CliResult result = runCli("validate", "--bundle-dir", appDir.toString(), "--strict");
    String manifest =
        Files.readString(appDir.resolve("cryptad-app.properties"), StandardCharsets.UTF_8);

    assertEquals(CommandLine.ExitCode.OK, result.exitCode());
    assertTrue(manifest.contains("app.permissions=vault.identities.read\n"));
    assertTrue(manifest.contains("api.targetStability=experimental\n"));
    assertTrue(manifest.contains("api.experimentalCapabilitiesAccepted=true\n"));
    assertEquals("", result.err());
  }

  @Test
  void init_whenOperatorOnlyPermissionRequested_expectFailureBeforeManifestWrite() {
    Path appDir = tempDir.resolve("sample-app");

    CliResult result =
        runCli(
            "init",
            "--dir",
            appDir.toString(),
            "--app-id",
            "sample-app",
            "--name",
            "Sample App",
            "--version",
            "0.1.0",
            "--permission",
            "vault.identities.manage");

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("permission vault.identities.manage is operator-only"));
    assertFalse(Files.exists(appDir.resolve("cryptad-app.properties")));
  }

  @Test
  void init_whenShellPanelRequested_expectManifestUsesShellPanelWithoutStaticTemplate()
      throws Exception {
    Path appDir = tempDir.resolve("sample-app");

    CliResult result =
        runCli(
            "init",
            "--dir",
            appDir.toString(),
            "--app-id",
            "sample-app",
            "--name",
            "Sample App",
            "--version",
            "0.1.0",
            "--ui-mode",
            "shell-panel");
    String manifest =
        Files.readString(appDir.resolve("cryptad-app.properties"), StandardCharsets.UTF_8);

    assertEquals(CommandLine.ExitCode.OK, result.exitCode());
    assertTrue(manifest.contains("app.ui.mode=shell-panel\n"));
    assertTrue(manifest.contains("app.ui.entry=/app/node/#sample-app\n"));
    assertFalse(Files.exists(appDir.resolve("static")));
  }

  @Test
  void init_whenTargetDirectoryIsNotEmptyWithoutOverwrite_expectFailure() throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    Files.createDirectories(appDir);
    Files.writeString(appDir.resolve("existing.txt"), "existing", StandardCharsets.UTF_8);

    CliResult result =
        runCli(
            "init",
            "--dir",
            appDir.toString(),
            "--app-id",
            "sample-app",
            "--name",
            "Sample App",
            "--version",
            "0.1.0");

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("target directory is not empty"));
  }

  @Test
  void init_whenTargetDirectoryIsSymbolicLink_expectFailureWithoutWritingThroughLink()
      throws Exception {
    Path externalTarget = tempDir.resolve("external-target");
    Path appDir = tempDir.resolve("linked-app");
    Files.createDirectories(externalTarget);
    Assumptions.assumeTrue(canCreateSymlink(appDir));
    Files.createSymbolicLink(appDir, externalTarget);

    CliResult result =
        runCli(
            "init",
            "--dir",
            appDir.toString(),
            "--app-id",
            "sample-app",
            "--name",
            "Sample App",
            "--version",
            "0.1.0",
            "--overwrite");

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("target directory must not be a symbolic link"));
    assertFalse(Files.exists(externalTarget.resolve("cryptad-app.properties")));
  }

  @Test
  void validate_whenScaffoldIsMinimal_expectSuccess() {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");

    CliResult result = runCli("validate", "--bundle-dir", appDir.toString());

    assertEquals(CommandLine.ExitCode.OK, result.exitCode());
    assertTrue(result.out().contains("Bundle is valid: sample-app 0.1.0"));
    assertEquals("", result.err());
  }

  @Test
  void validate_whenStableBundleTargetsUnknownBaseline_expectFailure() throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");
    Path manifest = appDir.resolve("cryptad-app.properties");
    Files.writeString(
        manifest,
        Files.readString(manifest, StandardCharsets.UTF_8)
            .replace("api.targetBaseline=1.0", "api.targetBaseline=1.1"),
        StandardCharsets.UTF_8);

    CliResult result = runCli("validate", "--bundle-dir", appDir.toString());

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("unknown Platform API baseline: 1.1"));
  }

  @Test
  void uiLint_whenScaffoldedStaticAppCheckedStrict_expectSuccessAndJson() throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    Path json = tempDir.resolve("reports").resolve("ui-lint.json");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0",
        "--permission",
        "queue.read");

    CliResult result =
        runCli(
            "ui", "lint", "--bundle-dir", appDir.toString(), "--strict", "--json", json.toString());

    assertEquals(CommandLine.ExitCode.OK, result.exitCode());
    assertTrue(result.out().contains("UI lint passed: 0 error(s)"));
    String jsonText = Files.readString(json, StandardCharsets.UTF_8);
    assertTrue(jsonText.contains("\"appId\": \"sample-app\""));
    assertTrue(jsonText.contains("\"uiMode\": \"static\""));
    assertTrue(jsonText.contains("\"findings\": []"));
    assertFalse(jsonText.contains(tempDir.toString()));
  }

  @Test
  void uiLint_whenFirstPartyBetaReadinessMarkersPresent_expectStrictSuccess() throws Exception {
    Path appDir = tempDir.resolve("first-party-ready-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "first-party-ready-app",
        "--name",
        "First-party Ready App",
        "--version",
        "0.1.0",
        "--permission",
        "queue.read");
    addFirstPartyBetaReadinessFixture(appDir);

    CliResult result = runCli("ui", "lint", "--bundle-dir", appDir.toString(), "--strict");

    assertEquals(CommandLine.ExitCode.OK, result.exitCode());
    assertTrue(result.out().contains("UI lint passed: 0 error(s)"));
    assertFalse(result.err().contains("first_party_"));
  }

  @Test
  void uiLint_whenFirstPartyBetaReadinessMarkerMissing_expectStrictFailure() throws Exception {
    Path appDir = tempDir.resolve("first-party-missing-marker-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "first-party-missing-marker-app",
        "--name",
        "First-party Missing Marker App",
        "--version",
        "0.1.0",
        "--permission",
        "queue.read");
    addFirstPartyBetaReadinessFixture(appDir);
    Path index = appDir.resolve("static").resolve("index.html");
    Files.writeString(
        index,
        Files.readString(index, StandardCharsets.UTF_8).replace(" data-beta-empty-state", ""),
        StandardCharsets.UTF_8);

    CliResult result = runCli("ui", "lint", "--bundle-dir", appDir.toString(), "--strict");

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("first_party_empty_state_missing"));
  }

  @Test
  void uiLint_whenFirstPartyPermissionRationaleMissing_expectStrictFailure() throws Exception {
    Path appDir = tempDir.resolve("first-party-missing-rationale-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "first-party-missing-rationale-app",
        "--name",
        "First-party Missing Rationale App",
        "--version",
        "0.1.0",
        "--permission",
        "queue.read");
    addFirstPartyBetaReadinessFixture(appDir);
    Path manifest = appDir.resolve("cryptad-app.properties");
    Files.writeString(
        manifest,
        Files.readString(manifest, StandardCharsets.UTF_8)
            .replace(
                "permissions.rationale.queue.read=Display bounded local queue state for beta"
                    + " support.\n",
                ""),
        StandardCharsets.UTF_8);

    CliResult result = runCli("ui", "lint", "--bundle-dir", appDir.toString(), "--strict");

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("first_party_permission_rationale_manifest_missing"));
  }

  @Test
  void uiLint_whenFirstPartyManifestReadinessFieldMissing_expectStrictFailure() throws Exception {
    Path appDir = tempDir.resolve("first-party-missing-manifest-field-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "first-party-missing-manifest-field-app",
        "--name",
        "First-party Missing Manifest Field App",
        "--version",
        "0.1.0",
        "--permission",
        "queue.read");
    addFirstPartyBetaReadinessFixture(appDir);
    Path manifest = appDir.resolve("cryptad-app.properties");
    Files.writeString(
        manifest,
        Files.readString(manifest, StandardCharsets.UTF_8)
            .replace("app.beta.qualityLevel=beta\n", "app.beta.qualityLevel=release\n")
            .replace(
                "app.beta.support.uri=https://example.invalid/crypta/apps/first-party-ready-app/support\n",
                ""),
        StandardCharsets.UTF_8);

    CliResult result = runCli("ui", "lint", "--bundle-dir", appDir.toString(), "--strict");

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("first_party_manifest_field_missing"));
    assertTrue(result.err().contains("app.beta.qualityLevel=beta"));
    assertTrue(result.err().contains("manifest field app.beta.support.uri"));
  }

  @Test
  void uiLint_whenFirstPartyManifestUsesBomColonAndEscapes_expectStrictSuccess() throws Exception {
    Path appDir = tempDir.resolve("first-party-escaped-manifest-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "first-party-escaped-manifest-app",
        "--name",
        "First-party Escaped Manifest App",
        "--version",
        "0.1.0",
        "--permission",
        "queue.read");
    addFirstPartyBetaReadinessFixture(appDir);
    Path manifest = appDir.resolve("cryptad-app.properties");
    String escapedOwner = "app.beta.support.owner: crypta" + '\\' + "u002dcore\n";
    String escapedRationale =
        "permissions.rationale.queue"
            + '\\'
            + "u002eread: Display bounded local queue state for beta support.\n";
    String manifestText =
        Files.readString(manifest, StandardCharsets.UTF_8)
            .replace("app.beta.support.owner=crypta-core\n", escapedOwner)
            .replace(
                "permissions.rationale.queue.read=Display bounded local queue state for beta"
                    + " support.\n",
                escapedRationale);
    Files.writeString(
        manifest,
        "\uFEFF# first-party beta metadata\n! generated test fixture\n" + manifestText,
        StandardCharsets.UTF_8);

    CliResult result = runCli("ui", "lint", "--bundle-dir", appDir.toString(), "--strict");

    assertEquals(CommandLine.ExitCode.OK, result.exitCode());
    assertTrue(result.out().contains("UI lint passed: 0 error(s)"));
    assertEquals("", result.err());
  }

  @Test
  void uiLint_whenFirstPartyDurableAppClaimsExportSupport_expectNoStatelessOverclaim()
      throws Exception {
    Path appDir = tempDir.resolve("first-party-durable-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "first-party-durable-app",
        "--name",
        "First-party Durable App",
        "--version",
        "0.1.0",
        "--permission",
        "queue.read");
    addFirstPartyBetaReadinessFixture(appDir);
    Path manifest = appDir.resolve("cryptad-app.properties");
    Files.writeString(
        manifest,
        Files.readString(manifest, StandardCharsets.UTF_8)
            .replace("app.beta.appData=stateless\n", "app.beta.appData=durable\n")
            .replace(
                "app.beta.backupRestore=not-applicable\n", "app.beta.backupRestore=supported\n")
            .replace("app.beta.exportSupported=not-applicable\n", "app.beta.exportSupported=true\n")
            .replace("app.beta.importSupported=not-applicable\n", "app.beta.importSupported=true\n")
            .replace(
                "app.beta.migrationDryRunSupported=not-applicable\n",
                "app.beta.migrationDryRunSupported=false\n"),
        StandardCharsets.UTF_8);

    CliResult result = runCli("ui", "lint", "--bundle-dir", appDir.toString(), "--strict");

    assertEquals(CommandLine.ExitCode.OK, result.exitCode());
    assertFalse(result.err().contains("first_party_stateless_backup_overclaim"));
  }

  @Test
  void uiLint_whenFirstPartyStatelessAppClaimsBackup_expectStrictFailure() throws Exception {
    Path appDir = tempDir.resolve("first-party-backup-overclaim-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "first-party-backup-overclaim-app",
        "--name",
        "First-party Backup Overclaim App",
        "--version",
        "0.1.0",
        "--permission",
        "queue.read");
    addFirstPartyBetaReadinessFixture(appDir);
    Path manifest = appDir.resolve("cryptad-app.properties");
    Files.writeString(
        manifest,
        Files.readString(manifest, StandardCharsets.UTF_8)
            .replace(
                "app.beta.backupRestore=not-applicable\n", "app.beta.backupRestore=supported\n"),
        StandardCharsets.UTF_8);

    CliResult result = runCli("ui", "lint", "--bundle-dir", appDir.toString(), "--strict");

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("first_party_stateless_backup_overclaim"));
  }

  @Test
  void uiLint_whenFirstPartyPermissionRationaleMarkerMissing_expectStrictFailure()
      throws Exception {
    Path appDir = tempDir.resolve("first-party-missing-ui-rationale-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "first-party-missing-ui-rationale-app",
        "--name",
        "First-party Missing UI Rationale App",
        "--version",
        "0.1.0",
        "--permission",
        "queue.read");
    addFirstPartyBetaReadinessFixture(appDir);
    Path index = appDir.resolve("static").resolve("index.html");
    Files.writeString(
        index,
        Files.readString(index, StandardCharsets.UTF_8)
            .replace(" data-beta-permission-rationale", ""),
        StandardCharsets.UTF_8);

    CliResult result = runCli("ui", "lint", "--bundle-dir", appDir.toString(), "--strict");

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("first_party_permission_rationale_missing"));
  }

  @Test
  void uiLint_whenFirstPartyDiagnosticsCopyMissing_expectStrictFailure() throws Exception {
    Path appDir = tempDir.resolve("first-party-missing-diagnostics-copy-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "first-party-missing-diagnostics-copy-app",
        "--name",
        "First-party Missing Diagnostics Copy App",
        "--version",
        "0.1.0",
        "--permission",
        "queue.read");
    addFirstPartyBetaReadinessFixture(appDir);
    Path index = appDir.resolve("static").resolve("index.html");
    Files.writeString(
        index,
        Files.readString(index, StandardCharsets.UTF_8)
            .replace("redacted-summary-only diagnostics", "bounded diagnostics"),
        StandardCharsets.UTF_8);

    CliResult result = runCli("ui", "lint", "--bundle-dir", appDir.toString(), "--strict");

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("first_party_diagnostics_redaction_marker_missing"));
  }

  @Test
  void uiLint_whenTrustGraphScopeCopyMissing_expectStrictFailure() throws Exception {
    Path appDir = tempDir.resolve("trust-graph");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "trust-graph",
        "--name",
        "Trust Graph Local RC",
        "--version",
        "0.1.0",
        "--permission",
        "queue.read");
    addFirstPartyBetaReadinessFixture(appDir);

    CliResult result = runCli("ui", "lint", "--bundle-dir", appDir.toString(), "--strict");

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("first_party_local_rc_scope_missing"));
  }

  @Test
  void uiLint_whenSocialInboxLegacyProtocolCopyMissing_expectStrictFailure() throws Exception {
    Path appDir = tempDir.resolve("social-inbox");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "social-inbox",
        "--name",
        "Social Inbox RC",
        "--version",
        "0.1.0",
        "--permission",
        "queue.read");
    addFirstPartyBetaReadinessFixture(appDir);

    CliResult result = runCli("ui", "lint", "--bundle-dir", appDir.toString(), "--strict");

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("first_party_legacy_protocol_non_goal_missing"));
  }

  @Test
  void uiLint_whenStaticEntryIsNotHtml_expectFailure() throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");
    Path staticDir = appDir.resolve("static");
    Files.move(staticDir.resolve("index.html"), staticDir.resolve("index.txt"));
    Path manifest = appDir.resolve("cryptad-app.properties");
    Files.writeString(
        manifest,
        Files.readString(manifest, StandardCharsets.UTF_8)
            .replace("app.ui.entry=static/index.html\n", "app.ui.entry=static/index.txt\n"),
        StandardCharsets.UTF_8);

    CliResult lintResult = runCli("ui", "lint", "--bundle-dir", appDir.toString(), "--strict");
    CliResult validateResult = runCli("validate", "--bundle-dir", appDir.toString(), "--strict");

    assertEquals(CommandLine.ExitCode.SOFTWARE, lintResult.exitCode());
    assertTrue(lintResult.err().contains("static-entry-non-html"));
    assertTrue(lintResult.err().contains("application/octet-stream"));
    assertTrue(lintResult.err().contains("static/index.txt"));
    assertEquals(CommandLine.ExitCode.SOFTWARE, validateResult.exitCode());
    assertTrue(validateResult.err().contains("static-entry-non-html"));
  }

  @Test
  void uiLint_whenStaticEntryParentIsSymbolicLink_expectFailureWithoutReadingExternalUi()
      throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");
    Path staticDir = appDir.resolve("static");
    Path externalStaticDir = tempDir.resolve("external-static");
    Files.move(staticDir, externalStaticDir);
    Assumptions.assumeTrue(canCreateSymlink(staticDir));
    Files.createSymbolicLink(staticDir, externalStaticDir);

    CliResult result = runCli("ui", "lint", "--bundle-dir", appDir.toString(), "--strict");

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("static-entry-missing"));
    assertTrue(result.err().contains("static/index.html"));
  }

  @Test
  void uiLint_whenLocalScriptAndStylesheetReferencesAreMissing_expectFailure() throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");
    Files.delete(appDir.resolve("static").resolve("crypta-platform.js"));
    Files.delete(appDir.resolve("static").resolve("app.js"));
    Files.delete(appDir.resolve("static").resolve("app.css"));

    CliResult lintResult = runCli("ui", "lint", "--bundle-dir", appDir.toString(), "--strict");
    CliResult validateResult = runCli("validate", "--bundle-dir", appDir.toString(), "--strict");

    assertEquals(CommandLine.ExitCode.SOFTWARE, lintResult.exitCode());
    assertTrue(lintResult.err().contains("local-ui-reference-missing"));
    assertTrue(lintResult.err().contains("static/crypta-platform.js"));
    assertTrue(lintResult.err().contains("static/app.js"));
    assertTrue(lintResult.err().contains("static/app.css"));
    assertEquals(CommandLine.ExitCode.SOFTWARE, validateResult.exitCode());
    assertTrue(validateResult.err().contains("UI lint failed"));
    assertTrue(validateResult.err().contains("local-ui-reference-missing"));
  }

  @Test
  void uiLint_whenLocalScriptParentIsSymbolicLink_expectFailureWithoutReadingExternalAsset()
      throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");
    Path staticDir = appDir.resolve("static");
    Path externalAssetDir = tempDir.resolve("external-assets");
    Files.createDirectories(externalAssetDir);
    Files.writeString(
        externalAssetDir.resolve("app.js"),
        "CryptaPlatform.bootstrap.load().then(() => undefined);\n",
        StandardCharsets.UTF_8);
    Path linkedAssetDir = staticDir.resolve("linked");
    Assumptions.assumeTrue(canCreateSymlink(linkedAssetDir));
    Files.createSymbolicLink(linkedAssetDir, externalAssetDir);
    Path index = staticDir.resolve("index.html");
    Files.writeString(
        index,
        Files.readString(index, StandardCharsets.UTF_8).replace("./app.js", "./linked/app.js"),
        StandardCharsets.UTF_8);

    CliResult result = runCli("ui", "lint", "--bundle-dir", appDir.toString(), "--strict");

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("local-ui-reference-missing"));
    assertTrue(result.err().contains("static/linked/app.js"));
  }

  @Test
  void uiLint_whenLocalScriptAndStylesheetUseUnsupportedTypes_expectFailure() throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");
    Path staticDir = appDir.resolve("static");
    Files.move(staticDir.resolve("app.js"), staticDir.resolve("app.jsx"));
    Files.move(staticDir.resolve("app.css"), staticDir.resolve("app.scss"));
    Path index = staticDir.resolve("index.html");
    Files.writeString(
        index,
        Files.readString(index, StandardCharsets.UTF_8)
            .replace("./app.js", "./app.jsx")
            .replace("./app.css", "./app.scss"),
        StandardCharsets.UTF_8);

    CliResult result = runCli("ui", "lint", "--bundle-dir", appDir.toString(), "--strict");

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("local-ui-reference-unsupported-type"));
    assertTrue(result.err().contains("static/app.jsx"));
    assertTrue(result.err().contains("static/app.scss"));
  }

  @Test
  void uiLint_whenLocalReferencesAreNotRouteSafe_expectFailure() throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");
    Path staticDir = appDir.resolve("static");
    Files.writeString(staticDir.resolve("foo:bar.css"), "body {}\n", StandardCharsets.UTF_8);
    Path index = staticDir.resolve("index.html");
    Files.writeString(
        index,
        Files.readString(index, StandardCharsets.UTF_8)
            .replace("./app.js", "../../app.js")
            .replace("./app.css", "./foo:bar.css"),
        StandardCharsets.UTF_8);

    CliResult result = runCli("ui", "lint", "--bundle-dir", appDir.toString(), "--strict");

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("local-ui-reference-route-invalid"));
    assertTrue(result.err().contains("../app.js"));
    assertTrue(result.err().contains("static/foo:bar.css"));
  }

  @Test
  void uiLint_whenAbsoluteScriptAndStylesheetReferencesPresent_expectFailure() throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");
    Path index = appDir.resolve("static").resolve("index.html");
    Files.writeString(
        index,
        Files.readString(index, StandardCharsets.UTF_8)
            .replace("./app.js", "/api/v1/foo.js")
            .replace("./app.css", "/theme.css"),
        StandardCharsets.UTF_8);

    CliResult result = runCli("ui", "lint", "--bundle-dir", appDir.toString(), "--strict");

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("local-ui-reference-route-invalid"));
    assertTrue(result.err().contains("/api/v1/foo.js"));
    assertTrue(result.err().contains("/theme.css"));
  }

  @Test
  void uiLint_whenLocalReferenceUsesRouteEncoding_expectSuccess() throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");
    Path staticDir = appDir.resolve("static");
    Files.writeString(
        staticDir.resolve("space app.js"),
        Files.readString(staticDir.resolve("app.js"), StandardCharsets.UTF_8),
        StandardCharsets.UTF_8);
    Path index = staticDir.resolve("index.html");
    Files.writeString(
        index,
        Files.readString(index, StandardCharsets.UTF_8).replace("./app.js", "./space%20app.js"),
        StandardCharsets.UTF_8);

    CliResult result = runCli("ui", "lint", "--bundle-dir", appDir.toString(), "--strict");

    assertEquals(CommandLine.ExitCode.OK, result.exitCode());
  }

  @Test
  void uiLint_whenEncodedLoadedAppScriptOmitsBootstrap_expectStrictFailure() throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");
    Path staticDir = appDir.resolve("static");
    Files.writeString(
        staticDir.resolve("space app.js"), "console.log('loaded');\n", StandardCharsets.UTF_8);
    Path index = staticDir.resolve("index.html");
    Files.writeString(
        index,
        Files.readString(index, StandardCharsets.UTF_8).replace("./app.js", "./space%20app.js"),
        StandardCharsets.UTF_8);

    CliResult result = runCli("ui", "lint", "--bundle-dir", appDir.toString(), "--strict");

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("sdk-bootstrap-missing"));
    assertTrue(result.err().contains("static/space app.js"));
  }

  @Test
  void uiLint_whenBootstrapAppearsOnlyInCommentOrString_expectStrictFailure() throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");
    Files.writeString(
        appDir.resolve("static").resolve("app.js"),
        """
        // TODO call CryptaPlatform.bootstrap.load({ appId: "sample-app" });
        const example = "platform.bootstrap.load({ appId: 'sample-app' })";
        console.log(example);
        """,
        StandardCharsets.UTF_8);

    CliResult result = runCli("ui", "lint", "--bundle-dir", appDir.toString(), "--strict");

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("sdk-bootstrap-missing"));
    assertTrue(result.err().contains("static/app.js"));
  }

  @Test
  void uiLint_whenBootstrapFollowsRegexLiteralWithEscapedSlashes_expectStrictSuccess()
      throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");
    Files.writeString(
        appDir.resolve("static").resolve("app.js"),
        """
        const matcher = /^https?:\\/\\//; CryptaPlatform.bootstrap.load({ appId: "sample-app" });
        console.log(matcher.test(window.location.href));
        """,
        StandardCharsets.UTF_8);

    CliResult result = runCli("ui", "lint", "--bundle-dir", appDir.toString(), "--strict");

    assertEquals(CommandLine.ExitCode.OK, result.exitCode());
  }

  @Test
  void uiLint_whenBootstrapAppearsOnlyInRegexLiteral_expectStrictFailure() throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");
    Files.writeString(
        appDir.resolve("static").resolve("app.js"),
        """
        const example = /CryptaPlatform.bootstrap.load()/;
        console.log(example);
        """,
        StandardCharsets.UTF_8);

    CliResult result = runCli("ui", "lint", "--bundle-dir", appDir.toString(), "--strict");

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("sdk-bootstrap-missing"));
    assertTrue(result.err().contains("static/app.js"));
  }

  @Test
  void uiLint_whenBootstrapUsesLargeMemberChain_expectStrictSuccess() throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");
    StringBuilder script = new StringBuilder("const root = window.CryptaPlatform;\nroot");
    for (int index = 0; index < 2048; index++) {
      script.append(".member").append(index);
    }
    script.append(".bootstrap.load({ appId: \"sample-app\" });\n");
    Files.writeString(
        appDir.resolve("static").resolve("app.js"), script.toString(), StandardCharsets.UTF_8);

    CliResult result = runCli("ui", "lint", "--bundle-dir", appDir.toString(), "--strict");

    assertEquals(CommandLine.ExitCode.OK, result.exitCode());
  }

  @Test
  void uiLint_whenAppScriptLivesUnderCryptaUiDirectory_expectStrictBootstrapFailure()
      throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");
    Path staticDir = appDir.resolve("static");
    Files.writeString(
        staticDir.resolve("crypta-ui").resolve("main.js"),
        "console.log('loaded app code');\n",
        StandardCharsets.UTF_8);
    Path index = staticDir.resolve("index.html");
    Files.writeString(
        index,
        Files.readString(index, StandardCharsets.UTF_8).replace("./app.js", "./crypta-ui/main.js"),
        StandardCharsets.UTF_8);

    CliResult result = runCli("ui", "lint", "--bundle-dir", appDir.toString(), "--strict");

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("sdk-bootstrap-missing"));
    assertTrue(result.err().contains("static/crypta-ui/main.js"));
  }

  @Test
  void uiLint_whenCssImportUsesNonLocalScheme_expectFailure() throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");
    Files.writeString(
        appDir.resolve("static").resolve("app.css"),
        "\n@import url(\"data:text/css,body{}\");\n",
        StandardCharsets.UTF_8,
        java.nio.file.StandardOpenOption.APPEND);

    CliResult result = runCli("ui", "lint", "--bundle-dir", appDir.toString(), "--strict");

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("non-local-css-import"));
    assertTrue(result.err().contains("static/app.css"));
  }

  @Test
  void uiLint_whenPermissionDisclosureOmitsDeclaredPermission_expectStrictFailure()
      throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0",
        "--permission",
        "queue.read",
        "--permission",
        "queue.write");
    Path index = appDir.resolve("static").resolve("index.html");
    Files.writeString(
        index,
        Files.readString(index, StandardCharsets.UTF_8)
            .replace("              <li><code>queue.write</code></li>\n", ""),
        StandardCharsets.UTF_8);

    CliResult result = runCli("ui", "lint", "--bundle-dir", appDir.toString(), "--strict");

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("permission-disclosure-missing-permission"));
    assertTrue(result.err().contains("queue.write"));
  }

  @Test
  void uiLint_whenPermissionDisclosureMentionsUndeclaredPermission_expectStrictFailure()
      throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0",
        "--permission",
        "queue.read");
    Path index = appDir.resolve("static").resolve("index.html");
    Files.writeString(
        index,
        Files.readString(index, StandardCharsets.UTF_8)
            .replace(
                "              <li><code>queue.read</code></li>\n",
                """
                              <li><code>queue.read</code></li>
                              <li><code>content.insert</code></li>
                """),
        StandardCharsets.UTF_8);

    CliResult result = runCli("ui", "lint", "--bundle-dir", appDir.toString(), "--strict");

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("permission-disclosure-undeclared-permission"));
    assertTrue(result.err().contains("content.insert"));
  }

  @Test
  void validate_whenStaticUiEntryUsesCustomRelativePath_expectStrictUiLintSuccess()
      throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0",
        "--permission",
        "queue.read");
    Path uiDir = appDir.resolve("ui");
    Files.createDirectory(uiDir);
    Path manifest = appDir.resolve("cryptad-app.properties");
    Files.writeString(
        manifest,
        Files.readString(manifest, StandardCharsets.UTF_8)
            .replace("app.ui.entry=static/index.html\n", "app.ui.entry=ui/index.html\n"),
        StandardCharsets.UTF_8);
    Files.writeString(
        uiDir.resolve("index.html"),
        """
        <!doctype html>
        <html lang="en">
          <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>Sample App</title>
            <link rel="stylesheet" href="../static/crypta-ui/crypta-ui-tokens.css">
            <link rel="stylesheet" href="../static/crypta-ui/crypta-ui.css">
            <link rel="stylesheet" href="./app.css">
          </head>
          <body class="cr-app">
            <main class="cr-shell">
              <h1>Sample App</h1>
              <section class="cr-permission-summary" data-crypta-permission-summary>
                <p><strong>Declared permissions</strong></p>
                <ul><li><code>queue.read</code></li></ul>
              </section>
              <p class="cr-status" id="status" role="status" aria-live="polite"></p>
            </main>
            <script src="../static/crypta-platform.js"></script>
            <script type="module" src="./main.js"></script>
          </body>
        </html>
        """,
        StandardCharsets.UTF_8);
    Files.writeString(uiDir.resolve("app.css"), ".custom { color: var(--cr-color-text); }\n");
    Files.writeString(
        uiDir.resolve("main.js"),
        """
        async function main() {
          await CryptaPlatform.bootstrap.load({ appId: "sample-app" });
        }
        main();
        """,
        StandardCharsets.UTF_8);

    CliResult result = runCli("validate", "--bundle-dir", appDir.toString(), "--strict");

    assertEquals(CommandLine.ExitCode.OK, result.exitCode());
    assertTrue(result.out().contains("Bundle is valid: sample-app 0.1.0"));
    assertEquals("", result.err());
  }

  @Test
  void uiLint_whenCustomAppScriptLoadsBeforeSdk_expectStrictOrderFailure() throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");
    Path index = appDir.resolve("static").resolve("index.html");
    Files.writeString(
        index,
        Files.readString(index, StandardCharsets.UTF_8)
            .replace(
                """
                    <script src="./crypta-platform.js"></script>
                    <script type="module" src="./app.js"></script>
                """,
                """
                    <script src="./main.js"></script>
                    <script src="./crypta-platform.js"></script>
                """),
        StandardCharsets.UTF_8);
    Files.writeString(
        appDir.resolve("static").resolve("main.js"),
        """
        async function main() {
          await CryptaPlatform.bootstrap.load({ appId: "sample-app" });
        }
        main();
        """,
        StandardCharsets.UTF_8);

    CliResult result = runCli("ui", "lint", "--bundle-dir", appDir.toString(), "--strict");

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("sdk-script-order"));
  }

  @Test
  void uiLint_whenDeferredSdkPrecedesParserBlockingAppScript_expectStrictOrderFailure()
      throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");
    Path index = appDir.resolve("static").resolve("index.html");
    Files.writeString(
        index,
        Files.readString(index, StandardCharsets.UTF_8)
            .replace(
                """
                    <script src="./crypta-platform.js"></script>
                    <script type="module" src="./app.js"></script>
                """,
                """
                    <script src="./crypta-platform.js" defer></script>
                    <script src="./app.js"></script>
                """),
        StandardCharsets.UTF_8);

    CliResult result = runCli("ui", "lint", "--bundle-dir", appDir.toString(), "--strict");

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("sdk-script-defer-order"));
  }

  @Test
  void uiLint_whenRemoteScriptPresent_expectFailure() throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");
    Path index = appDir.resolve("static").resolve("index.html");
    Files.writeString(
        index,
        Files.readString(index, StandardCharsets.UTF_8)
            .replace(
                "<script src=\"./crypta-platform.js\"></script>",
                "<script src=\"https://cdn.example.invalid/platform.js\"></script>"),
        StandardCharsets.UTF_8);

    CliResult result = runCli("ui", "lint", "--bundle-dir", appDir.toString());

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("remote-script"));
  }

  @Test
  void uiLint_whenInlineScriptAndEventHandlerPresent_expectFailure() throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");
    Path index = appDir.resolve("static").resolve("index.html");
    Files.writeString(
        index,
        Files.readString(index, StandardCharsets.UTF_8)
            .replace("<body class=\"cr-app\">", "<body class=\"cr-app\" onclick=\"void 0\">")
            .replace("</body>", "<script>window.inline = true;</script>\n</body>"),
        StandardCharsets.UTF_8);

    CliResult result = runCli("ui", "lint", "--bundle-dir", appDir.toString());

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("inline-event-handler"));
    assertTrue(result.err().contains("inline-script"));
  }

  @Test
  void uiLint_whenForbiddenTokenTextPresent_expectFailure() throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");
    Files.writeString(
        appDir.resolve("static").resolve("app.js"),
        "\nconsole.log('CRYPTAD_APP_TOKEN');\n",
        StandardCharsets.UTF_8,
        java.nio.file.StandardOpenOption.APPEND);

    CliResult result = runCli("ui", "lint", "--bundle-dir", appDir.toString());

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("forbidden-token-text"));
    assertTrue(result.err().contains("static/app.js"));
  }

  @Test
  void uiLint_whenUnsafeLocalJavaScriptPatternsPresent_expectFailure() throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");
    Files.writeString(
        appDir.resolve("static").resolve("app.js"),
        """
        async function main() {
          await CryptaPlatform.bootstrap.load({ appId: "sample-app" });
          eval("console.log('unsafe')");
          const factory = new Function("return 1");
          localStorage.setItem("session", "value");
          await fetch("/api/v1/queue");
          return factory();
        }
        main();
        """,
        StandardCharsets.UTF_8);

    CliResult result = runCli("ui", "lint", "--bundle-dir", appDir.toString(), "--strict");

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("dynamic-code-evaluation"));
    assertTrue(result.err().contains("persistent-browser-storage"));
    assertTrue(result.err().contains("direct-platform-api-reference"));
    assertTrue(result.err().contains("static/app.js"));
  }

  @Test
  void validate_whenStrictStaticUiLintFindsProblem_expectFailure() throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");
    Path index = appDir.resolve("static").resolve("index.html");
    Files.writeString(
        index,
        Files.readString(index, StandardCharsets.UTF_8)
            .replace("    <link rel=\"stylesheet\" href=\"./crypta-ui/crypta-ui.css\">\n", ""),
        StandardCharsets.UTF_8);

    CliResult normalResult = runCli("validate", "--bundle-dir", appDir.toString());
    CliResult strictResult = runCli("validate", "--bundle-dir", appDir.toString(), "--strict");

    assertEquals(CommandLine.ExitCode.OK, normalResult.exitCode());
    assertEquals(CommandLine.ExitCode.SOFTWARE, strictResult.exitCode());
    assertTrue(strictResult.err().contains("design-system-css-not-linked"));
    assertTrue(strictResult.err().contains("UI lint failed"));
  }

  @Test
  void uiLint_whenCanonicalDesignSystemAssetIsModified_expectStrictFailure() throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");
    Files.writeString(
        appDir.resolve("static").resolve("crypta-ui").resolve("crypta-ui.css"),
        "\n.modified {}\n",
        StandardCharsets.UTF_8,
        java.nio.file.StandardOpenOption.APPEND);

    CliResult result = runCli("ui", "lint", "--bundle-dir", appDir.toString(), "--strict");

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("design-system-asset-modified"));
    assertTrue(result.err().contains("static/crypta-ui/crypta-ui.css"));
  }

  @Test
  void uiLint_whenDesignSystemTokensLoadAfterBaseCss_expectStrictOrderFailure() throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");
    Path index = appDir.resolve("static").resolve("index.html");
    Files.writeString(
        index,
        Files.readString(index, StandardCharsets.UTF_8)
            .replace(
                """
                    <link rel="stylesheet" href="./crypta-ui/crypta-ui-tokens.css">
                    <link rel="stylesheet" href="./crypta-ui/crypta-ui.css">
                """,
                """
                    <link rel="stylesheet" href="./crypta-ui/crypta-ui.css">
                    <link rel="stylesheet" href="./crypta-ui/crypta-ui-tokens.css">
                """),
        StandardCharsets.UTF_8);

    CliResult result = runCli("ui", "lint", "--bundle-dir", appDir.toString(), "--strict");

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("design-system-css-order"));
  }

  @Test
  void uiLint_whenNonCanonicalCryptaUiStylesheetLoadsBeforeTokens_expectStrictOrderFailure()
      throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");
    Path staticDir = appDir.resolve("static");
    Files.writeString(
        staticDir.resolve("crypta-ui").resolve("custom.css"),
        ".cr-app { color: inherit; }\n",
        StandardCharsets.UTF_8);
    Path index = staticDir.resolve("index.html");
    Files.writeString(
        index,
        Files.readString(index, StandardCharsets.UTF_8)
            .replace(
                """
                    <link rel="stylesheet" href="./crypta-ui/crypta-ui-tokens.css">
                    <link rel="stylesheet" href="./crypta-ui/crypta-ui.css">
                """,
                """
                    <link rel="stylesheet" href="./crypta-ui/custom.css">
                    <link rel="stylesheet" href="./crypta-ui/crypta-ui-tokens.css">
                    <link rel="stylesheet" href="./crypta-ui/crypta-ui.css">
                """),
        StandardCharsets.UTF_8);

    CliResult result = runCli("ui", "lint", "--bundle-dir", appDir.toString(), "--strict");

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("design-system-css-order"));
  }

  @Test
  void uiLint_whenUiModeIsNone_expectNotApplicableSuccess() {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0",
        "--ui-mode",
        "none");

    CliResult result = runCli("ui", "lint", "--bundle-dir", appDir.toString(), "--strict");

    assertEquals(CommandLine.ExitCode.OK, result.exitCode());
    assertTrue(result.out().contains("UI lint not applicable for app.ui.mode=none"));
  }

  @Test
  void uiLint_whenNoUiBundleHasLiteralWindowsExecPath_expectNotApplicableSuccess()
      throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0",
        "--ui-mode",
        "none");
    Path manifest = appDir.resolve("cryptad-app.properties");
    Files.writeString(
        manifest,
        Files.readString(manifest, StandardCharsets.UTF_8)
            .replace("app.exec=bin/start.sh\n", "app.exec=bin" + '\\' + "update.exe\n"),
        StandardCharsets.UTF_8);

    CliResult result = runCli("ui", "lint", "--bundle-dir", appDir.toString(), "--strict");

    assertEquals(CommandLine.ExitCode.OK, result.exitCode());
    assertTrue(result.out().contains("UI lint not applicable for app.ui.mode=none"));
    assertEquals("", result.err());
  }

  @Test
  void uiLint_whenStaticBundleHasLiteralWindowsExecPath_expectStrictSuccess() throws Exception {
    Path appDir = tempDir.resolve("static-windows-exec-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "static-windows-exec-app",
        "--name",
        "Static Windows Exec App",
        "--version",
        "0.1.0",
        "--permission",
        "queue.read");
    Path manifest = appDir.resolve("cryptad-app.properties");
    Files.writeString(
        manifest,
        Files.readString(manifest, StandardCharsets.UTF_8)
            .replace("app.exec=bin/start.sh\n", "app.exec=bin" + '\\' + "update.exe\n"),
        StandardCharsets.UTF_8);

    CliResult result = runCli("ui", "lint", "--bundle-dir", appDir.toString(), "--strict");

    assertEquals(CommandLine.ExitCode.OK, result.exitCode());
    assertTrue(result.out().contains("UI lint passed: 0 error(s)"));
    assertEquals("", result.err());
  }

  @Test
  void uiLint_whenStaticBundleHasEscapedWindowsExecPath_expectStrictSuccess() throws Exception {
    Path appDir = tempDir.resolve("static-escaped-windows-exec-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "static-escaped-windows-exec-app",
        "--name",
        "Static Escaped Windows Exec App",
        "--version",
        "0.1.0",
        "--permission",
        "queue.read");
    Path manifest = appDir.resolve("cryptad-app.properties");
    Files.writeString(
        manifest,
        Files.readString(manifest, StandardCharsets.UTF_8)
            .replace("app.exec=bin/start.sh\n", "app.exec=bin" + "\\\\" + "update.exe\n"),
        StandardCharsets.UTF_8);

    CliResult result = runCli("ui", "lint", "--bundle-dir", appDir.toString(), "--strict");

    assertEquals(CommandLine.ExitCode.OK, result.exitCode());
    assertTrue(result.out().contains("UI lint passed: 0 error(s)"));
    assertEquals("", result.err());
  }

  @Test
  void uiLint_whenUiModeIsShellPanel_expectNotApplicableSuccess() {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0",
        "--ui-mode",
        "shell-panel");

    CliResult result = runCli("ui", "lint", "--bundle-dir", appDir.toString(), "--strict");

    assertEquals(CommandLine.ExitCode.OK, result.exitCode());
    assertTrue(result.out().contains("UI lint not applicable for app.ui.mode=shell-panel"));
  }

  @Test
  void apiSnapshot_whenOutputRequested_expectContractJsonWritten() throws Exception {
    Path contractFile = tempDir.resolve("platform-api-contract.json");

    CliResult result = runCli("api", "snapshot", "--output", contractFile.toString());

    assertEquals(CommandLine.ExitCode.OK, result.exitCode());
    assertTrue(result.out().contains("Wrote Platform API contract"));
    String json = Files.readString(contractFile, StandardCharsets.UTF_8);
    assertTrue(json.contains("\"contractVersion\":" + currentContractVersion()));
    assertTrue(json.contains("\"platform.contract.read\""));
    assertTrue(json.contains("\"baselineRegistrySummary\""));
    assertEquals(
        PlatformApiContractJson.writeEnvelope(
            PlatformApiContract.current(), PlatformApiBaselineRegistry.current()),
        json);
  }

  @Test
  void apiContentFormats_whenOutputRequested_expectAuthoritativeRegistryWritten() throws Exception {
    Path output = tempDir.resolve("content-format-profiles.json");

    CliResult result = runCli("api", "content-formats", "--output", output.toString());

    assertEquals(CommandLine.ExitCode.OK, result.exitCode());
    assertTrue(result.out().contains("6 profile(s)"));
    String json = Files.readString(output, StandardCharsets.UTF_8);
    assertTrue(json.contains("\"kind\":\"content-format-profile-registry\""));
    assertTrue(json.contains("\"id\":\"crypta.profile.v1\""));
    assertTrue(json.contains("\"id\":\"crypta.feed.snapshot.v1\""));
    assertTrue(json.contains("\"id\":\"crypta.trust.statement.v1\""));
    assertTrue(json.contains("\"id\":\"crypta.social.message.v1\""));
    assertTrue(json.contains("\"id\":\"crypta.social.outbox.v1\""));
    assertTrue(json.contains("\"id\":\"crypta.mail.envelope.v1\""));
    assertTrue(json.contains("\"canonicalizationKind\""));
    assertTrue(json.contains("\"versionPolicy\""));
    assertFalse(json.contains(tempDir.toString()));
  }

  @Test
  void apiPolicy_whenRequested_expectCompatibilityWindowSummary() {
    CliResult result = runCli("api", "policy");

    assertEquals(CommandLine.ExitCode.OK, result.exitCode());
    assertTrue(result.out().contains("Platform API 1.0 compatibility window"));
    assertTrue(result.out().contains("contract=" + currentContractVersion()));
    assertTrue(
        result
            .out()
            .contains(
                "baselineContract="
                    + PlatformApiContract.PLATFORM_API_STABLE_BASELINE_CONTRACT_VERSION));
    assertEquals("", result.err());
  }

  @Test
  void apiPolicy_whenOutputRequested_expectPathFreeJsonReport() throws Exception {
    Path output = tempDir.resolve("reports").resolve("platform-api-policy.json");

    CliResult result = runCli("api", "policy", "--output", output.toString());

    assertEquals(CommandLine.ExitCode.OK, result.exitCode());
    String json = Files.readString(output, StandardCharsets.UTF_8);
    assertTrue(json.contains("\"compatibilityWindow\""));
    assertTrue(json.contains("\"previousSnapshotRequiredInProductionBeta\":true"));
    assertTrue(json.contains("\"criticalStableRemovalWaiverAllowed\":false"));
    assertTrue(json.contains("\"graduationPolicy\""));
    assertFalse(json.contains(tempDir.toString()));
  }

  @Test
  void apiDiff_whenSameSnapshotCompared_expectSuccessAndJsonReport() throws Exception {
    Path previous = tempDir.resolve("previous.json");
    Path current = tempDir.resolve("current.json");
    Path report = tempDir.resolve("stable-diff.json");
    String snapshot = PlatformApiContractJson.writeEnvelope(PlatformApiContract.current());
    Files.writeString(previous, snapshot, StandardCharsets.UTF_8);
    Files.writeString(current, snapshot, StandardCharsets.UTF_8);

    CliResult result =
        runCli(
            "api",
            "diff",
            "--previous",
            previous.toString(),
            "--current",
            current.toString(),
            "--output",
            report.toString());

    assertEquals(CommandLine.ExitCode.OK, result.exitCode(), result.err());
    assertTrue(result.out().contains("Platform API stable diff passed."));
    assertEquals("", result.err());
    String json = Files.readString(report, StandardCharsets.UTF_8);
    assertTrue(json.contains("\"ok\":true"));
    assertTrue(json.contains("\"errors\":0"));
    assertTrue(json.contains("\"findings\":[]"));
    assertFalse(json.contains(tempDir.toString()));
  }

  @Test
  void apiDiff_whenStableEndpointRemoved_expectSoftwareExitAndFinding() throws Exception {
    Path previous = tempDir.resolve("previous.json");
    Path current = tempDir.resolve("current.json");
    Files.writeString(
        previous,
        PlatformApiContractJson.writeEnvelope(PlatformApiContract.current()),
        StandardCharsets.UTF_8);
    PlatformApiContract base = PlatformApiContract.current();
    PlatformApiContract removedQueueEndpoint =
        new PlatformApiContract(
            base.apiVersion(),
            base.contractVersion(),
            base.generatedBy(),
            base.stabilityPolicy(),
            base.capabilities(),
            base.endpoints().stream()
                .filter(
                    endpoint ->
                        !(endpoint.method().equals("POST")
                            && endpoint.routeTemplate().equals("/queue/downloads")))
                .toList());
    Files.writeString(
        current,
        PlatformApiContractJson.writeEnvelope(removedQueueEndpoint),
        StandardCharsets.UTF_8);

    CliResult result =
        runCli("api", "diff", "--previous", previous.toString(), "--current", current.toString());

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("stable diff failed"));
    assertTrue(result.err().contains("Stable endpoint was removed: POST /queue/downloads"));
  }

  @Test
  void apiDiff_whenPreviousCompatibilityWindowMissingInProduction_expectSoftwareExit()
      throws Exception {
    Path previous = tempDir.resolve("previous.json");
    Path current = tempDir.resolve("current.json");
    Files.writeString(previous, snapshotWithoutCompatibilityWindow(), StandardCharsets.UTF_8);
    Files.writeString(
        current,
        PlatformApiContractJson.writeEnvelope(PlatformApiContract.current()),
        StandardCharsets.UTF_8);

    CliResult result =
        runCli(
            "api",
            "diff",
            "--previous",
            previous.toString(),
            "--current",
            current.toString(),
            "--production-beta");

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("compatibility-window metadata"));
    assertTrue(result.err().contains("stable diff failed"));
  }

  @Test
  void compatVerify_whenBundleTargetsCurrentContract_expectSuccess() {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0",
        "--permission",
        "queue.read");

    CliResult result = runCli("compat", "verify", "--bundle-dir", appDir.toString());

    assertEquals(CommandLine.ExitCode.OK, result.exitCode());
    assertTrue(result.out().contains("Compatibility verified."));
    assertEquals("", result.err());
  }

  @Test
  void apiBaselineInspect_whenCurrentRegistryRequested_expectCanonical10OnlyArtifact()
      throws Exception {
    Path registry = tempDir.resolve("baseline-registry.json");

    CliResult result = runCli("api", "baseline", "inspect", "--output", registry.toString());

    assertEquals(CommandLine.ExitCode.OK, result.exitCode());
    assertTrue(result.out().contains("supported=[1.0]"));
    String json = Files.readString(registry, StandardCharsets.UTF_8);
    assertTrue(json.contains("\"id\":\"1.0\""));
    assertTrue(json.contains("\"status\":\"active\""));
    assertFalse(json.contains("\"id\":\"1.1\""));
  }

  @Test
  void apiPreview_whenRegistryProposalVerified_expectNonProductionBoundary() throws Exception {
    Path proposal = tempDir.resolve("baseline-proposal.json");
    Path preview = tempDir.resolve("baseline-preview.json");
    Files.writeString(
        proposal,
        PlatformApiContractJson.writeBaselineRegistry(
            network.crypta.platform.api.PlatformApiBaselineRegistry.current()),
        StandardCharsets.UTF_8);

    CliResult result =
        runCli("api", "preview", "--proposal", proposal.toString(), "--output", preview.toString());

    assertEquals(CommandLine.ExitCode.OK, result.exitCode());
    String json = Files.readString(preview, StandardCharsets.UTF_8);
    assertTrue(json.contains("\"kind\":\"platform-api-1.x-preview\""));
    assertTrue(json.contains("\"preview\":true"));
    assertTrue(json.contains("\"nonProduction\":true"));
    assertTrue(json.contains("\"activatesBaseline\":false"));
    assertTrue(json.contains("\"evidenceBoundary\":"));
    assertFalse(json.contains(tempDir.toString()));
  }

  @Test
  void apiPreview_whenExactContractBytesSupplied_expectDigestBindsInputBytes() throws Exception {
    PlatformApiBaselineRegistry registry = PlatformApiBaselineRegistry.current();
    Path proposal = tempDir.resolve("baseline-proposal.json");
    Path contract = tempDir.resolve("candidate-contract.json");
    Path preview = tempDir.resolve("baseline-preview.json");
    Files.writeString(
        proposal, PlatformApiContractJson.writeBaselineRegistry(registry), StandardCharsets.UTF_8);
    Files.writeString(
        contract,
        PlatformApiContractJson.writeEnvelope(PlatformApiContract.current(), registry) + "\n",
        StandardCharsets.UTF_8);

    CliResult result =
        runCli(
            "api",
            "preview",
            "--proposal",
            proposal.toString(),
            "--contract",
            contract.toString(),
            "--output",
            preview.toString());

    assertEquals(CommandLine.ExitCode.OK, result.exitCode(), result.err());
    assertTrue(
        Files.readString(preview, StandardCharsets.UTF_8)
            .contains("\"contractDigest\":\"sha256:" + sha256Hex(contract) + "\""));
  }

  @Test
  void apiPreview_whenContractSummaryDoesNotMatchProposal_expectRejected() throws Exception {
    PlatformApiBaselineRegistry registry = PlatformApiBaselineRegistry.current();
    Path proposal = tempDir.resolve("baseline-proposal.json");
    Path contract = tempDir.resolve("candidate-contract.json");
    Path preview = tempDir.resolve("baseline-preview.json");
    Files.writeString(
        proposal, PlatformApiContractJson.writeBaselineRegistry(registry), StandardCharsets.UTF_8);
    Files.writeString(
        contract,
        PlatformApiContractJson.writeEnvelope(PlatformApiContract.current(), registry)
            .replace(registry.registryDigest(), "f".repeat(64)),
        StandardCharsets.UTF_8);

    CliResult result =
        runCli(
            "api",
            "preview",
            "--proposal",
            proposal.toString(),
            "--contract",
            contract.toString(),
            "--output",
            preview.toString());

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("does not match the candidate baseline registry"));
    assertFalse(Files.exists(preview));
  }

  @Test
  void apiPreview_whenRejectedDefinitionIsRetained_expectTerminalHistoryNotProjected()
      throws Exception {
    PlatformApiBaselineRegistry current = PlatformApiBaselineRegistry.current();
    PlatformApiBaselineDefinition stable10 = current.definitions().getFirst();
    List<String> capabilities = new ArrayList<>(stable10.capabilities());
    capabilities.add("future.rejected.read");
    PlatformApiBaselineDefinition rejectedDefinition =
        PlatformApiBaselineDefinition.create(
            PlatformApiBaselineId.parse("1.1"),
            stable10.id(),
            capabilities,
            stable10.endpoints(),
            "a".repeat(64),
            "b".repeat(64),
            null,
            null,
            PlatformApiContract.CURRENT_CONTRACT_VERSION + 1);
    PlatformApiBaselineLineage proposed =
        PlatformApiBaselineLineage.create(
            rejectedDefinition.id(),
            rejectedDefinition.definitionDigest(),
            PlatformApiBaselineStatus.PROPOSED,
            PlatformApiBaselineEvidenceKind.FIXTURE,
            "c".repeat(64),
            null,
            null,
            null,
            null,
            null);
    PlatformApiBaselineLineage rejected =
        PlatformApiBaselineLineage.create(
            rejectedDefinition.id(),
            rejectedDefinition.definitionDigest(),
            PlatformApiBaselineStatus.REJECTED,
            PlatformApiBaselineEvidenceKind.FIXTURE,
            "d".repeat(64),
            null,
            null,
            null,
            null,
            proposed.lineageDigest());
    List<PlatformApiBaselineDefinition> definitions = new ArrayList<>(current.definitions());
    definitions.add(rejectedDefinition);
    List<PlatformApiBaselineLineage> lineage = new ArrayList<>(current.lineage());
    lineage.add(proposed);
    lineage.add(rejected);
    PlatformApiBaselineRegistry candidate =
        PlatformApiBaselineRegistry.create(definitions, lineage);
    Path proposal = tempDir.resolve("rejected-baseline-proposal.json");
    Path preview = tempDir.resolve("rejected-baseline-preview.json");
    Files.writeString(
        proposal, PlatformApiContractJson.writeBaselineRegistry(candidate), StandardCharsets.UTF_8);

    CliResult result =
        runCli("api", "preview", "--proposal", proposal.toString(), "--output", preview.toString());

    assertEquals(CommandLine.ExitCode.OK, result.exitCode(), result.err());
    String json = Files.readString(preview, StandardCharsets.UTF_8);
    assertTrue(json.contains("\"lifecycleStatus\":\"rejected\""));
    assertTrue(json.contains("\"ok\":true"));
  }

  @Test
  void apiPreview_whenDeprecationVersionIsAbsent_expectNullableMetadataWritten() throws Exception {
    Path proposal = tempDir.resolve("baseline-proposal.json");
    Path contract = tempDir.resolve("nullable-deprecation-contract.json");
    Path preview = tempDir.resolve("nullable-deprecation-preview.json");
    Files.writeString(
        proposal,
        PlatformApiContractJson.writeBaselineRegistry(PlatformApiBaselineRegistry.current()),
        StandardCharsets.UTF_8);
    String contractJson =
        PlatformApiContractJson.writeEnvelope(
                PlatformApiContract.current(), PlatformApiBaselineRegistry.current())
            .replaceFirst(
                "\"deprecation\":null",
                "\"deprecation\":{\"deprecatedSinceContractVersion\":null,"
                    + "\"removalContractVersion\":null,\"note\":\"preview only\"}");
    Files.writeString(contract, contractJson, StandardCharsets.UTF_8);

    CliResult result =
        runCli(
            "api",
            "preview",
            "--proposal",
            proposal.toString(),
            "--contract",
            contract.toString(),
            "--output",
            preview.toString());

    assertEquals(CommandLine.ExitCode.OK, result.exitCode(), result.err());
    String json = Files.readString(preview, StandardCharsets.UTF_8);
    assertTrue(json.contains("\"deprecatedSinceContractVersion\":null"));
  }

  @Test
  void compatVerify_whenJsonRequested_expectPathFreeCompatibilityReport() throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    Path report = tempDir.resolve("compat-report.json");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0",
        "--permission",
        "queue.read");

    CliResult result =
        runCli("compat", "verify", "--bundle-dir", appDir.toString(), "--json", report.toString());

    assertEquals(CommandLine.ExitCode.OK, result.exitCode());
    String json = Files.readString(report, StandardCharsets.UTF_8);
    assertTrue(json.contains("\"ok\":true"));
    assertTrue(json.contains("\"targetKind\":\"bundle\""));
    assertTrue(json.contains("\"findings\":[]"));
    assertFalse(json.contains(tempDir.toString()));
  }

  @Test
  void compatVerify_whenContractSummaryDoesNotMatchSelectedRegistry_expectFailure()
      throws Exception {
    PlatformApiBaselineRegistry registry = PlatformApiBaselineRegistry.current();
    Path appDir = tempDir.resolve("mismatched-registry-app");
    Path registryFile = tempDir.resolve("baseline-registry.json");
    Path contractFile = tempDir.resolve("platform-api-contract.json");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "mismatched-registry-app",
        "--name",
        "Mismatched Registry App",
        "--version",
        "0.1.0");
    Files.writeString(
        registryFile,
        PlatformApiContractJson.writeBaselineRegistry(registry),
        StandardCharsets.UTF_8);
    Files.writeString(
        contractFile,
        PlatformApiContractJson.writeEnvelope(PlatformApiContract.current(), registry)
            .replace(registry.registryDigest(), "f".repeat(64)),
        StandardCharsets.UTF_8);

    CliResult result =
        runCli(
            "compat",
            "verify",
            "--bundle-dir",
            appDir.toString(),
            "--contract",
            contractFile.toString(),
            "--baseline-registry",
            registryFile.toString());

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("does not match the candidate baseline registry"));
  }

  @Test
  void compatVerify_whenExperimentalBaselineIsPreviewOnly_expectStrictFailure() throws Exception {
    PlatformApiBaselineRegistry registry = proposed11Registry();
    Path appDir = tempDir.resolve("strict-preview-app");
    Path registryFile = tempDir.resolve("strict-preview-registry.json");
    Path contractFile = tempDir.resolve("strict-preview-contract.json");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "strict-preview-app",
        "--name",
        "Strict Preview App",
        "--version",
        "0.1.0");
    Files.writeString(
        registryFile,
        PlatformApiContractJson.writeBaselineRegistry(registry),
        StandardCharsets.UTF_8);
    Files.writeString(
        contractFile,
        PlatformApiContractJson.writeEnvelope(PlatformApiContract.current(), registry),
        StandardCharsets.UTF_8);
    String[] arguments = {
      "compat", "verify", "--bundle-dir", appDir.toString(),
      "--contract", contractFile.toString(), "--baseline-registry", registryFile.toString(),
      "--target-stability", "experimental", "--target-baseline", "1.1"
    };
    List<String> strictArguments = new ArrayList<>(List.of(arguments));
    strictArguments.add("--strict");

    CliResult nonStrict = runCli(arguments);
    CliResult strict = runCli(strictArguments.toArray(String[]::new));

    assertEquals(CommandLine.ExitCode.OK, nonStrict.exitCode(), nonStrict.err());
    assertTrue(nonStrict.out().contains("Compatibility verified"));
    assertEquals(CommandLine.ExitCode.SOFTWARE, strict.exitCode(), strict.err());
    assertTrue(strict.err().contains("Experimental app target is preview-only"));
    assertFalse(strict.out().contains("Compatibility verified"));
  }

  @Test
  void compatibilityCommands_whenExperimentalAppTargetsActiveBaseline_expectStrictFailure()
      throws Exception {
    Path appDir = tempDir.resolve("experimental-active-baseline-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "experimental-active-baseline-app",
        "--name",
        "Experimental Active Baseline App",
        "--version",
        "0.1.0");
    Path manifest = appDir.resolve("cryptad-app.properties");
    Files.writeString(
        manifest,
        Files.readString(manifest, StandardCharsets.UTF_8)
            .replace("api.targetStability=stable", "api.targetStability=experimental")
            .replace(
                "api.experimentalCapabilitiesAccepted=false",
                "api.experimentalCapabilitiesAccepted=true"),
        StandardCharsets.UTF_8);

    CliResult nonStrict = runCli("compat", "verify", "--bundle-dir", appDir.toString());
    CliResult strict = runCli("compat", "verify", "--bundle-dir", appDir.toString(), "--strict");
    CliResult nonStrictTest = runCli("test", "--bundle-dir", appDir.toString());
    CliResult strictTest = runCli("test", "--bundle-dir", appDir.toString(), "--strict");

    assertEquals(CommandLine.ExitCode.OK, nonStrict.exitCode(), nonStrict.err());
    assertTrue(nonStrict.out().contains("Compatibility verified"));
    assertTrue(
        nonStrict.err().contains("Experimental target does not claim the active stable baseline"));
    assertEquals(CommandLine.ExitCode.SOFTWARE, strict.exitCode(), strict.err());
    assertTrue(
        strict.err().contains("Experimental target does not claim the active stable baseline"));
    assertFalse(strict.out().contains("Compatibility verified"));
    assertEquals(CommandLine.ExitCode.OK, nonStrictTest.exitCode(), nonStrictTest.err());
    assertTrue(nonStrictTest.out().contains("api.compat warn"));
    assertEquals(CommandLine.ExitCode.SOFTWARE, strictTest.exitCode(), strictTest.err());
    assertTrue(strictTest.out().contains("api.compat fail"));
  }

  @Test
  void test_whenCandidateContractUsesPairedRegistry_expectPreviewCompatibilityEvaluated()
      throws Exception {
    PlatformApiBaselineRegistry candidateRegistry = proposed11Registry();
    Path appDir = tempDir.resolve("candidate-baseline-app");
    Path registryFile = tempDir.resolve("candidate-baseline-registry.json");
    Path contractFile = tempDir.resolve("candidate-contract.json");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "candidate-baseline-app",
        "--name",
        "Candidate Baseline App",
        "--version",
        "0.1.0");
    Path manifest = appDir.resolve("cryptad-app.properties");
    Files.writeString(
        manifest,
        Files.readString(manifest, StandardCharsets.UTF_8)
            .replace("api.targetStability=stable", "api.targetStability=experimental")
            .replace("api.targetBaseline=1.0", "api.targetBaseline=1.1")
            .replace(
                "api.experimentalCapabilitiesAccepted=false",
                "api.experimentalCapabilitiesAccepted=true"),
        StandardCharsets.UTF_8);
    Files.writeString(
        registryFile,
        PlatformApiContractJson.writeBaselineRegistry(candidateRegistry),
        StandardCharsets.UTF_8);
    Files.writeString(
        contractFile,
        PlatformApiContractJson.writeEnvelope(
            PlatformApiContract.current(), PlatformApiBaselineRegistry.current()),
        StandardCharsets.UTF_8);

    CliResult mismatched =
        runCli(
            "test",
            "--bundle-dir",
            appDir.toString(),
            "--contract",
            contractFile.toString(),
            "--baseline-registry",
            registryFile.toString());
    Files.writeString(
        contractFile,
        PlatformApiContractJson.writeEnvelope(PlatformApiContract.current(), candidateRegistry),
        StandardCharsets.UTF_8);
    CliResult matched =
        runCli(
            "test",
            "--bundle-dir",
            appDir.toString(),
            "--contract",
            contractFile.toString(),
            "--baseline-registry",
            registryFile.toString());

    assertEquals(CommandLine.ExitCode.SOFTWARE, mismatched.exitCode());
    assertTrue(mismatched.out().contains("api.compat fail"));
    assertEquals(CommandLine.ExitCode.OK, matched.exitCode(), matched.err());
    assertTrue(matched.out().contains("api.compat warn"));
    assertTrue(matched.out().contains("App test suite warn: candidate-baseline-app 0.1.0"));
  }

  @Test
  void compatVerify_whenTargetBaselineOverridden_expectOverrideBoundInReport() throws Exception {
    Path appDir = tempDir.resolve("baseline-app");
    Path report = tempDir.resolve("baseline-compat-report.json");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "baseline-app",
        "--name",
        "Baseline App",
        "--version",
        "0.1.0",
        "--permission",
        "queue.read");

    CliResult result =
        runCli(
            "compat",
            "verify",
            "--bundle-dir",
            appDir.toString(),
            "--target-stability",
            "stable",
            "--target-baseline",
            "1.0",
            "--json",
            report.toString());

    assertEquals(CommandLine.ExitCode.OK, result.exitCode());
    String json = Files.readString(report, StandardCharsets.UTF_8);
    assertTrue(json.contains("\"targetStabilityOverride\":\"stable\""));
    assertTrue(json.contains("\"targetBaselineOverride\":\"1.0\""));
    assertFalse(json.contains(tempDir.toString()));
  }

  @Test
  void compatVerify_whenTargetStabilityOverrideRejectsExperimentalUse_expectFailure() {
    Path appDir = tempDir.resolve("experimental-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "experimental-app",
        "--name",
        "Experimental App",
        "--version",
        "0.1.0",
        "--permission",
        "vault.identities.read");

    CliResult result =
        runCli(
            "compat",
            "verify",
            "--bundle-dir",
            appDir.toString(),
            "--target-stability",
            "stable",
            "--strict");

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("Stable Platform API target must not declare experimental"));
  }

  @Test
  void compatVerify_whenHelloStableTargetsStableBaselineContract_expectSuccess() throws Exception {
    Path appDir = tempDir.resolve("hello-stable-app");
    Path baselineContract = tempDir.resolve("platform-api-contract-19.json");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "hello-stable-app",
        "--name",
        "Hello Stable App",
        "--version",
        "0.1.0",
        "--template",
        "hello-stable");
    Files.writeString(
        baselineContract,
        PlatformApiContractJson.writeEnvelope(stableBaselineContract()),
        StandardCharsets.UTF_8);

    CliResult result =
        runCli(
            "compat",
            "verify",
            "--bundle-dir",
            appDir.toString(),
            "--contract",
            baselineContract.toString(),
            "--strict");

    String manifest =
        Files.readString(appDir.resolve("cryptad-app.properties"), StandardCharsets.UTF_8);
    assertTrue(
        manifest.contains(
            "api.minimumVersion="
                + PlatformApiContract.PLATFORM_API_STABLE_BASELINE_CONTRACT_VERSION
                + "\n"));
    assertTrue(manifest.contains("api.maximumTestedVersion=" + currentContractVersion() + "\n"));
    assertEquals(CommandLine.ExitCode.OK, result.exitCode(), result.err());
    assertTrue(result.out().contains("Compatibility verified."));
    assertEquals("", result.err());
  }

  @Test
  void compatVerify_whenCatalogRangeExcludesManifestBaselineRoot_expectFailure() throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    Path outputZip = tempDir.resolve("sample-app.zip");
    Path descriptor = tempDir.resolve("entry.properties");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0",
        "--permission",
        "queue.read");
    runCli("pack", "--bundle-dir", appDir.toString(), "--output", outputZip.toString());
    Files.writeString(
        descriptor,
        lines(
            "artifact.path=" + outputZip.toAbsolutePath().normalize(),
            "bundle.uri=" + outputZip.toUri(),
            "summary=Sample catalog entry.",
            "api.minimumVersion=" + currentContractVersion(),
            "api.maximumTestedVersion=" + currentContractVersion()),
        StandardCharsets.UTF_8);

    CliResult result =
        runCli("compat", "verify", "--catalog-entry", descriptor.toString(), "--strict");

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("does not include target baseline 1.0 contract 19"));
  }

  @Test
  void
      compatVerify_whenCatalogEntryExperimentalTargetOmitsAcceptance_expectManifestAcceptanceIsUsed()
          throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    Path outputZip = tempDir.resolve("sample-app.zip");
    Path descriptor = tempDir.resolve("entry.properties");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0",
        "--permission",
        "vault.identities.read");
    runCli("pack", "--bundle-dir", appDir.toString(), "--output", outputZip.toString());
    Files.writeString(
        descriptor,
        lines(
            "artifact.path=" + outputZip.toAbsolutePath().normalize(),
            "bundle.uri=" + outputZip.toUri(),
            "summary=Sample catalog entry.",
            "api.targetStability=experimental"),
        StandardCharsets.UTF_8);

    CliResult result =
        runCli("compat", "verify", "--catalog-entry", descriptor.toString(), "--strict");

    assertEquals(CommandLine.ExitCode.OK, result.exitCode());
    assertTrue(result.out().contains("Compatibility verified."));
    assertEquals("", result.err());
  }

  @Test
  void compatVerify_whenCatalogEntryExplicitlyRejectsManifestAcceptance_expectFailure()
      throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    Path outputZip = tempDir.resolve("sample-app.zip");
    Path descriptor = tempDir.resolve("entry.properties");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0",
        "--permission",
        "vault.identities.read");
    runCli("pack", "--bundle-dir", appDir.toString(), "--output", outputZip.toString());
    Files.writeString(
        descriptor,
        lines(
            "artifact.path=" + outputZip.toAbsolutePath().normalize(),
            "bundle.uri=" + outputZip.toUri(),
            "summary=Sample catalog entry.",
            "api.targetStability=experimental",
            "api.experimentalCapabilitiesAccepted=false"),
        StandardCharsets.UTF_8);

    CliResult result =
        runCli("compat", "verify", "--catalog-entry", descriptor.toString(), "--strict");

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(
        result
            .err()
            .contains(
                "Experimental capability requires api.experimentalCapabilitiesAccepted=true"));
  }

  @Test
  void compatVerify_whenStrictBundleMinimumExceedsContract_expectFailure() throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");
    Path manifest = appDir.resolve("cryptad-app.properties");
    int futureContractVersion = currentContractVersion() + 1;
    Files.writeString(
        manifest,
        Files.readString(manifest, StandardCharsets.UTF_8)
            .replace(
                "api.minimumVersion="
                    + PlatformApiContract.current().stableBaseline().contractVersion(),
                "api.minimumVersion=" + futureContractVersion)
            .replace(
                "api.maximumTestedVersion=" + currentContractVersion(),
                "api.maximumTestedVersion=" + futureContractVersion),
        StandardCharsets.UTF_8);

    CliResult result = runCli("compat", "verify", "--bundle-dir", appDir.toString(), "--strict");

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("requires Platform API contract " + futureContractVersion));
  }

  @Test
  void validate_whenBundleIsBroken_expectFailureMessage() throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");
    Files.delete(appDir.resolve("bin").resolve("start.sh"));

    CliResult result = runCli("validate", "--bundle-dir", appDir.toString());

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("app.exec does not resolve to a file"));
  }

  @Test
  void validate_whenUnknownPermissionAndStrict_expectFailure() {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0",
        "--permission",
        "future.read");

    CliResult result = runCli("validate", "--bundle-dir", appDir.toString(), "--strict");

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("unknown app permission(s): future.read"));
  }

  @Test
  void validate_whenUnknownPermissionAndNotStrict_expectWarningAndSuccess() {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0",
        "--permission",
        "future.read");

    CliResult result = runCli("validate", "--bundle-dir", appDir.toString());

    assertEquals(CommandLine.ExitCode.OK, result.exitCode());
    assertTrue(result.err().contains("Warning: unknown app permission(s): future.read"));
    assertTrue(result.out().contains("Bundle is valid: sample-app 0.1.0"));
  }

  @Test
  void validate_whenVaultPermissionsAndStrict_expectRecognizedByValidationAndUiLint()
      throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0",
        "--permission",
        "vault.secrets.read",
        "--permission",
        "vault.identities.use");

    CliResult result = runCli("validate", "--bundle-dir", appDir.toString(), "--strict");
    String manifest =
        Files.readString(appDir.resolve("cryptad-app.properties"), StandardCharsets.UTF_8);
    String indexHtml =
        Files.readString(appDir.resolve("static").resolve("index.html"), StandardCharsets.UTF_8);

    assertEquals(CommandLine.ExitCode.OK, result.exitCode());
    assertTrue(result.out().contains("Bundle is valid: sample-app 0.1.0"));
    assertEquals("", result.err());
    assertTrue(manifest.contains("api.targetStability=experimental\n"));
    assertTrue(manifest.contains("api.experimentalCapabilitiesAccepted=true\n"));
    assertTrue(indexHtml.contains("<code>vault.secrets.read</code>"));
    assertTrue(indexHtml.contains("<code>vault.identities.use</code>"));
  }

  @Test
  void signAndVerify_whenBundleCliRoundTrips_expectSuccess() throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    Path privateKey = tempDir.resolve("private.der");
    Path publicKey = tempDir.resolve("public.der");
    Files.write(privateKey, keyPair.getPrivate().getEncoded());
    Files.write(publicKey, keyPair.getPublic().getEncoded());
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");

    CliResult signResult =
        runCli(
            "sign",
            "--bundle-dir",
            appDir.toString(),
            "--key-id",
            "dev-local",
            "--private-key-file",
            privateKey.toString());
    CliResult verifyResult =
        runCli(
            "verify",
            "--bundle-dir",
            appDir.toString(),
            "--trusted-key-id",
            "dev-local",
            "--trusted-public-key-file",
            publicKey.toString());

    assertEquals(CommandLine.ExitCode.OK, signResult.exitCode());
    assertTrue(signResult.out().contains("Signed bundle:"));
    assertEquals(CommandLine.ExitCode.OK, verifyResult.exitCode());
    assertTrue(verifyResult.out().contains("Verified bundle:"));
  }

  @Test
  void pack_whenScaffoldIsValid_expectZipArtifact() throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    Path outputZip = tempDir.resolve("sample-app.zip");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");

    CliResult result =
        runCli("pack", "--bundle-dir", appDir.toString(), "--output", outputZip.toString());

    assertEquals(CommandLine.ExitCode.OK, result.exitCode());
    assertTrue(Files.isRegularFile(outputZip));
    assertTrue(result.out().contains("Packaged bundle:"));
    assertTrue(result.out().contains(sha256Hex(outputZip)));
  }

  @Test
  void pack_whenOutputExistsWithoutOverwrite_expectFailure() throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    Path outputZip = tempDir.resolve("sample-app.zip");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");
    Files.writeString(outputZip, "existing");

    CliResult result =
        runCli("pack", "--bundle-dir", appDir.toString(), "--output", outputZip.toString());

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("output ZIP already exists"));
  }

  @Test
  void catalogCreate_whenDescriptorPointsAtBundleZip_expectCatalogWithComputedArtifactMetadata()
      throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    Path outputZip = tempDir.resolve("sample-app.zip");
    Path descriptor = tempDir.resolve("entry.properties");
    Path catalogFile = tempDir.resolve("cryptad-app-catalog.properties");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0",
        "--permission",
        "queue.read");
    runCli("pack", "--bundle-dir", appDir.toString(), "--output", outputZip.toString());
    Files.writeString(
        descriptor,
        lines(
            "artifact.path=" + outputZip.toAbsolutePath().normalize(),
            "bundle.uri=" + outputZip.toUri(),
            "summary=Sample catalog entry.",
            "homepage=https://example.invalid/sample-app",
            "source=https://example.invalid/sample-app/source",
            "license=MIT",
            "categories=Productivity,network",
            "minimumCryptaVersion=0.1.0",
            "maximumCryptaVersion=0.9.99",
            "channel=beta",
            "support.status=experimental",
            "deprecation.status=deprecated",
            "deprecation.message=Use Sample App stable.",
            "replacementAppId=sample-app-stable",
            "securityAdvisories=CRYPTA-2026-0001",
            "securityAdvisory.CRYPTA-2026-0001.uri=https://example.invalid/advisories/CRYPTA-2026-0001",
            "maintenance.owner=crypta-core",
            "maintenance.ownerUri=https://example.invalid/crypta/owners/core",
            "maintenance.supportLevel=maintained",
            "maintenance.dataSchemaPolicy=stateless",
            "maintenance.migrationPolicy=none",
            "maintenance.backupRestore=not-applicable",
            "maintenance.securityPolicy=catalog-advisories",
            "maintenance.deprecationPolicy=none",
            "maintenance.supportUri=https://example.invalid/crypta/apps/sample-app/support",
            "review.status=reviewed",
            "review.note=Reviewed for local operator safety.",
            "permissions.rationale.queue.read=Reads the local transfer queue.",
            "screenshot.1=https://example.invalid/sample-app/shot-1.png",
            "changelog.summary=Adds queue retry controls.",
            "changelog.uri=https://example.invalid/sample-app/changelog.txt"),
        StandardCharsets.UTF_8);

    CliResult result =
        runCli(
            "catalog",
            "create",
            "--catalog-file",
            catalogFile.toString(),
            "--catalog-id",
            "dev",
            "--name",
            "Development Apps",
            "--generated-at",
            "2026-04-29T00:00:00Z",
            "--entry",
            descriptor.toString());

    String catalog = Files.readString(catalogFile, StandardCharsets.UTF_8);
    List<String> expectedCatalogFragments =
        List.of(
            "catalog.version=7\n",
            "catalog.generatedAt=2026-04-29T00:00:00Z\n",
            "app.sample-app.id=sample-app\n",
            "app.sample-app.homepage=https://example.invalid/sample-app\n",
            "app.sample-app.source=https://example.invalid/sample-app/source\n",
            "app.sample-app.license=MIT\n",
            "app.sample-app.categories=productivity,network\n",
            "app.sample-app.minimumCryptaVersion=0.1.0\n",
            "app.sample-app.maximumCryptaVersion=0.9.99\n",
            "app.sample-app.channel=beta\n",
            "app.sample-app.support.status=experimental\n",
            "app.sample-app.deprecation.status=deprecated\n",
            "app.sample-app.replacementAppId=sample-app-stable\n",
            "app.sample-app.securityAdvisory.CRYPTA-2026-0001.uri=https://example.invalid/advisories/CRYPTA-2026-0001\n",
            "app.sample-app.maintenance.owner=crypta-core\n",
            "app.sample-app.maintenance.ownerUri=https://example.invalid/crypta/owners/core\n",
            "app.sample-app.maintenance.supportLevel=maintained\n",
            "app.sample-app.maintenance.dataSchemaPolicy=stateless\n",
            "app.sample-app.maintenance.migrationPolicy=none\n",
            "app.sample-app.maintenance.backupRestore=not-applicable\n",
            "app.sample-app.maintenance.securityPolicy=catalog-advisories\n",
            "app.sample-app.maintenance.deprecationPolicy=none\n",
            "app.sample-app.maintenance.supportUri=https://example.invalid/crypta/apps/sample-app/support\n",
            "app.sample-app.api.minimumVersion="
                + PlatformApiContract.current().stableBaseline().contractVersion()
                + "\n",
            "app.sample-app.api.maximumTestedVersion=" + currentContractVersion() + "\n",
            "app.sample-app.api.targetStability=stable\n",
            "app.sample-app.api.targetBaseline=1.0\n",
            "app.sample-app.api.experimentalCapabilitiesAccepted=false\n",
            "app.sample-app.review.status=reviewed\n",
            "app.sample-app.review.note=Reviewed for local operator safety.\n",
            "app.sample-app.permissions.rationale.queue.read=Reads the local transfer queue.\n",
            "app.sample-app.screenshot.1=https://example.invalid/sample-app/shot-1.png\n",
            "app.sample-app.changelog.summary=Adds queue retry controls.\n",
            "app.sample-app.changelog.uri=https://example.invalid/sample-app/changelog.txt\n",
            "app.sample-app.permissions=queue.read\n",
            "app.sample-app.bundle.size.bytes=" + Files.size(outputZip),
            "app.sample-app.bundle.sha256=" + sha256Hex(outputZip));
    List<String> missingCatalogFragments =
        expectedCatalogFragments.stream().filter(fragment -> !catalog.contains(fragment)).toList();

    assertEquals(CommandLine.ExitCode.OK, result.exitCode());
    assertTrue(result.out().contains("Created catalog: dev with 1 entry"));
    assertEquals(List.of(), missingCatalogFragments);
  }

  @Test
  void catalogCreate_whenSecurityPolicyFlagsProvided_expectVersionSevenPolicyWritten()
      throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    Path outputZip = tempDir.resolve("sample-app.zip");
    Path descriptor = tempDir.resolve("entry.properties");
    Path catalogFile = tempDir.resolve("cryptad-app-catalog.properties");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");
    runCli("pack", "--bundle-dir", appDir.toString(), "--output", outputZip.toString());
    Files.writeString(
        descriptor,
        lines(
            "artifact.path=" + outputZip.toAbsolutePath().normalize(),
            "bundle.uri=" + outputZip.toUri(),
            "summary=Sample catalog entry."),
        StandardCharsets.UTF_8);

    CliResult result =
        runCli(
            "catalog",
            "create",
            "--catalog-file",
            catalogFile.toString(),
            "--catalog-id",
            "dev",
            "--name",
            "Development Apps",
            "--entry",
            descriptor.toString(),
            "--security-advisory-record",
            String.join(
                ";",
                "id=CRYPTA-2026-0001",
                "uri=https://example.invalid/advisories/CRYPTA-2026-0001",
                "title=Sample App 0.1.0 vulnerable",
                "severity=critical",
                "status=active",
                "action=denylist",
                "summary=Upgrade to a reviewed replacement.",
                "publishedAt=2026-06-11T00:00:00Z",
                "updatedAt=2026-06-11T00:00:00Z",
                "replacementAppId=sample-app",
                "safeUninstallGuidance=Export app data before removal."),
            "--security-denylist-entry",
            String.join(
                ";",
                "id=deny-sample-app-0-1-0",
                "appId=sample-app",
                "version=0.1.0",
                "advisoryId=CRYPTA-2026-0001",
                "reason=Known vulnerable release.",
                "replacementAppId=sample-app",
                "safeUninstallGuidance=Export app data before removal."));

    String catalog = Files.readString(catalogFile, StandardCharsets.UTF_8);
    assertEquals(CommandLine.ExitCode.OK, result.exitCode());
    assertTrue(result.out().contains("Created catalog: dev with 1 entry"));
    assertTrue(catalog.contains("catalog.version=7\n"));
    assertTrue(catalog.contains("catalog.securityAdvisories=CRYPTA-2026-0001\n"));
    assertTrue(catalog.contains("catalog.securityAdvisory.CRYPTA-2026-0001.action=denylist\n"));
    assertTrue(
        catalog.contains(
            "catalog.securityAdvisory.CRYPTA-2026-0001.safeUninstallGuidance=Export app data before"
                + " removal.\n"));
    assertTrue(catalog.contains("catalog.securityDenylist=deny-sample-app-0-1-0\n"));
    assertTrue(catalog.contains("catalog.securityDenylist.deny-sample-app-0-1-0.version=0.1.0\n"));
    assertTrue(
        catalog.contains(
            "catalog.securityDenylist.deny-sample-app-0-1-0.advisoryId=CRYPTA-2026-0001\n"));
  }

  @Test
  void catalogCreate_whenDescriptorUsesCryptaChkBundleUri_expectCatalogWithCryptaArtifact()
      throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    Path outputZip = tempDir.resolve("sample-app.zip");
    Path descriptor = tempDir.resolve("entry.properties");
    Path catalogFile = tempDir.resolve("cryptad-app-catalog.properties");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");
    runCli("pack", "--bundle-dir", appDir.toString(), "--output", outputZip.toString());
    Files.writeString(
        descriptor,
        lines(
            "artifact.path=" + outputZip.toAbsolutePath().normalize(),
            "bundle.uri=crypta:CHK@sample-bundle",
            "summary=Sample catalog entry."),
        StandardCharsets.UTF_8);

    CliResult result =
        runCli(
            "catalog",
            "create",
            "--catalog-file",
            catalogFile.toString(),
            "--catalog-id",
            "dev",
            "--name",
            "Development Apps",
            "--entry",
            descriptor.toString());

    String catalog = Files.readString(catalogFile, StandardCharsets.UTF_8);
    assertEquals(CommandLine.ExitCode.OK, result.exitCode());
    assertTrue(catalog.contains("app.sample-app.bundle.uri=crypta:CHK@sample-bundle\n"));
    assertTrue(catalog.contains("app.sample-app.bundle.size.bytes=" + Files.size(outputZip)));
    assertTrue(catalog.contains("app.sample-app.bundle.sha256=" + sha256Hex(outputZip)));
  }

  @Test
  void catalogCreate_whenDescriptorUsesMutableCryptaBundleUri_expectInvalidArtifactFailure()
      throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    Path outputZip = tempDir.resolve("sample-app.zip");
    Path descriptor = tempDir.resolve("entry.properties");
    Path catalogFile = tempDir.resolve("cryptad-app-catalog.properties");
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");
    runCli("pack", "--bundle-dir", appDir.toString(), "--output", outputZip.toString());
    Files.writeString(
        descriptor,
        lines(
            "artifact.path=" + outputZip.toAbsolutePath().normalize(),
            "bundle.uri=crypta:SSK@sample-bundle",
            "summary=Sample catalog entry."),
        StandardCharsets.UTF_8);

    CliResult result =
        runCli(
            "catalog",
            "create",
            "--catalog-file",
            catalogFile.toString(),
            "--catalog-id",
            "dev",
            "--name",
            "Development Apps",
            "--entry",
            descriptor.toString());

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("artifact URI must use an immutable CHK key"));
  }

  @Test
  void reviewSignVerifyAndCatalogCreate_whenReceiptIsTrusted_expectEmbeddedReceipt()
      throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    Path outputZip = tempDir.resolve("sample-app.zip");
    Path descriptor = tempDir.resolve("entry.properties");
    Path receiptFile = tempDir.resolve("review-receipt.properties");
    Path trustedReviewers = tempDir.resolve("trusted-reviewers.properties");
    Path catalogFile = tempDir.resolve("cryptad-app-catalog.properties");
    KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    Path privateKey = tempDir.resolve("review-private.der");
    Files.write(privateKey, keyPair.getPrivate().getEncoded());
    Files.writeString(
        trustedReviewers,
        lines(
            "trusted.reviewers.version=1",
            "reviewer.1.id=dev-review",
            "reviewer.1.algorithm=Ed25519",
            "reviewer.1.public.key.base64="
                + Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()),
            "reviewer.1.display.name=Development Review",
            "reviewer.1.policy.id=dev-review-v1"),
        StandardCharsets.UTF_8);
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0",
        "--permission",
        "queue.read");
    runCli("pack", "--bundle-dir", appDir.toString(), "--output", outputZip.toString());
    Files.writeString(
        descriptor,
        lines(
            "artifact.path=" + outputZip.toAbsolutePath().normalize(),
            "bundle.uri=" + outputZip.toUri(),
            "summary=Sample catalog entry."),
        StandardCharsets.UTF_8);

    CliResult signResult =
        runCli(
            "review",
            "sign",
            "--catalog-entry",
            descriptor.toString(),
            "--receipt-file",
            receiptFile.toString(),
            "--reviewer-key-id",
            "dev-review",
            "--reviewer-private-key-file",
            privateKey.toString(),
            "--policy-id",
            "dev-review-v1",
            "--policy-version",
            "1",
            "--status",
            "reviewed",
            "--reviewed-at",
            "2026-05-01T00:00:00Z");
    CliResult verifyResult =
        runCli(
            "review",
            "verify",
            "--catalog-entry",
            descriptor.toString(),
            "--receipt-file",
            receiptFile.toString(),
            "--trusted-reviewer-keys-file",
            trustedReviewers.toString());
    CliResult catalogResult =
        runCli(
            "catalog",
            "create",
            "--catalog-file",
            catalogFile.toString(),
            "--catalog-id",
            "dev",
            "--name",
            "Development Apps",
            "--entry",
            descriptor.toString(),
            "--review-receipt",
            receiptFile.toString());

    String catalog = Files.readString(catalogFile, StandardCharsets.UTF_8);
    assertEquals(CommandLine.ExitCode.OK, signResult.exitCode());
    assertTrue(signResult.out().contains("Signed review receipt: sample-app 0.1.0 reviewed"));
    assertEquals(CommandLine.ExitCode.OK, verifyResult.exitCode());
    assertTrue(verifyResult.out().contains("Verified review receipt: trusted_reviewed"));
    assertEquals(CommandLine.ExitCode.OK, catalogResult.exitCode());
    assertTrue(catalog.contains("app.sample-app.review.receipt.status=reviewed\n"));
    assertTrue(catalog.contains("app.sample-app.review.receipt.reviewer.key.id=dev-review\n"));
    assertTrue(catalog.contains("app.sample-app.review.receipt.signature.value.base64="));
  }

  @Test
  void reviewFingerprint_whenReceiptProvided_expectRedactedFingerprintSummary() throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    Path outputZip = tempDir.resolve("sample-app.zip");
    Path descriptor = tempDir.resolve("entry.properties");
    Path receiptFile = tempDir.resolve("review-receipt.properties");
    KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    Path privateKey = tempDir.resolve("review-private.der");
    Files.write(privateKey, keyPair.getPrivate().getEncoded());
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");
    runCli("pack", "--bundle-dir", appDir.toString(), "--output", outputZip.toString());
    Files.writeString(
        descriptor,
        lines(
            "artifact.path=" + outputZip.toAbsolutePath().normalize(),
            "bundle.uri=" + outputZip.toUri(),
            "summary=Sample catalog entry."),
        StandardCharsets.UTF_8);
    runCli(
        "review",
        "sign",
        "--catalog-entry",
        descriptor.toString(),
        "--receipt-file",
        receiptFile.toString(),
        "--reviewer-key-id",
        "dev-review",
        "--reviewer-private-key-file",
        privateKey.toString(),
        "--policy-id",
        "dev-review-v1",
        "--policy-version",
        "1",
        "--status",
        "reviewed",
        "--reviewed-at",
        "2026-05-01T00:00:00Z");

    CliResult result = runCli("review", "fingerprint", "--receipt-file", receiptFile.toString());

    assertEquals(CommandLine.ExitCode.OK, result.exitCode());
    assertTrue(
        result
            .out()
            .matches(
                "(?s).*Review receipt fingerprint: fingerprintSha256=[0-9a-f]{64} "
                    + "payloadSha256=[0-9a-f]{64} reviewer=dev-review.*"));
    assertFalse(result.out().contains("signature.value.base64"));
    assertFalse(result.out().contains(privateKey.toString()));
  }

  @Test
  void reviewTransparencyVerify_whenLogFileIsMissing_expectFailure() {
    Path missingLog = tempDir.resolve("missing-review-transparency-log.jsonl");

    CliResult result =
        runCli("review", "transparency", "verify", "--log-file", missingLog.toString());

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("review transparency log file not found"));
    assertFalse(result.out().contains("Verified review transparency log"));
  }

  @Test
  void catalogSignAndVerify_whenCatalogCliRoundTrips_expectSuccess() throws Exception {
    Path appDir = tempDir.resolve("sample-app");
    Path outputZip = tempDir.resolve("sample-app.zip");
    Path descriptor = tempDir.resolve("entry.properties");
    Path catalogFile = tempDir.resolve("cryptad-app-catalog.properties");
    KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    Path privateKey = tempDir.resolve("catalog-private.der");
    Path publicKey = tempDir.resolve("catalog-public.der");
    Files.write(privateKey, keyPair.getPrivate().getEncoded());
    Files.write(publicKey, keyPair.getPublic().getEncoded());
    runCli(
        "init",
        "--dir",
        appDir.toString(),
        "--app-id",
        "sample-app",
        "--name",
        "Sample App",
        "--version",
        "0.1.0");
    runCli("pack", "--bundle-dir", appDir.toString(), "--output", outputZip.toString());
    Files.writeString(
        descriptor,
        lines(
            "artifact.path=" + outputZip.toAbsolutePath().normalize(),
            "bundle.uri=" + outputZip.toUri(),
            "summary=Sample catalog entry."),
        StandardCharsets.UTF_8);
    runCli(
        "catalog",
        "create",
        "--catalog-file",
        catalogFile.toString(),
        "--catalog-id",
        "dev",
        "--name",
        "Development Apps",
        "--entry",
        descriptor.toString());
    String catalog = Files.readString(catalogFile, StandardCharsets.UTF_8);

    assertTrue(catalog.contains("catalog.version=7\n"));
    assertTrue(
        catalog.contains(
            "app.sample-app.api.minimumVersion="
                + PlatformApiContract.current().stableBaseline().contractVersion()
                + "\n"));
    assertTrue(catalog.contains("app.sample-app.api.targetStability=stable\n"));
    assertTrue(catalog.contains("app.sample-app.api.targetBaseline=1.0\n"));
    assertTrue(catalog.contains("app.sample-app.api.experimentalCapabilitiesAccepted=false\n"));
    CliResult signResult =
        runCli(
            "catalog",
            "sign",
            "--catalog-file",
            catalogFile.toString(),
            "--key-id",
            "dev-local",
            "--private-key-file",
            privateKey.toString());
    Path detachedSignature = tempDir.resolve("candidate-catalog.detached-signature");
    Files.move(catalogFile.resolveSibling("cryptad-app-catalog.signature"), detachedSignature);
    CliResult verifyResult =
        runCli(
            "catalog",
            "verify",
            "--catalog-file",
            catalogFile.toString(),
            "--catalog-signature-file",
            detachedSignature.toString(),
            "--expected-key-id",
            "dev-local",
            "--trusted-key-id",
            "dev-local",
            "--trusted-public-key-file",
            publicKey.toString());
    CliResult wrongExpectedKey =
        runCli(
            "catalog",
            "verify",
            "--catalog-file",
            catalogFile.toString(),
            "--catalog-signature-file",
            detachedSignature.toString(),
            "--expected-key-id",
            "catalog-production-other",
            "--trusted-key-id",
            "dev-local",
            "--trusted-public-key-file",
            publicKey.toString());

    assertEquals(CommandLine.ExitCode.OK, signResult.exitCode());
    assertTrue(signResult.out().contains("Signed catalog with key: dev-local"));
    assertEquals(CommandLine.ExitCode.OK, verifyResult.exitCode());
    assertTrue(verifyResult.out().contains("Verified catalog: dev"));
    assertEquals(CommandLine.ExitCode.SOFTWARE, wrongExpectedKey.exitCode());
    assertTrue(
        wrongExpectedKey.err().contains("catalog signature key id does not match expected key id"));
  }

  @Test
  void help_whenRequested_expectUsage() {
    CliResult result = runCli("--help");

    assertEquals(CommandLine.ExitCode.OK, result.exitCode());
    assertTrue(result.out().contains("Usage: crypta-app"));
    assertTrue(result.out().contains("init"));
    assertTrue(result.out().contains("validate"));
    assertTrue(result.out().contains("pack"));
    assertTrue(result.out().contains("api"));
    assertTrue(result.out().contains("compat"));
    assertTrue(result.out().contains("ui"));
    assertTrue(result.out().contains("review"));
    assertTrue(result.out().contains("catalog"));
    assertTrue(result.out().contains("submission"));
  }

  @Test
  void submissionHelp_whenRequested_expectWorkflowCommands() {
    CliResult result = runCli("submission");

    assertEquals(CommandLine.ExitCode.OK, result.exitCode());
    assertTrue(result.out().contains("create"));
    assertTrue(result.out().contains("verify"));
    assertTrue(result.out().contains("pre-review"));
    assertTrue(result.out().contains("decide"));
    assertTrue(result.out().contains("catalog-candidate"));
  }

  @Test
  void submissionCreate_whenInitializedStaticBundleIncludesSdk_expectAccepted() {
    Path appDir = tempDir.resolve("sdk-template-app");
    Path submission = tempDir.resolve("sdk-template-submission.zip");
    Path reviewDir = appDir.resolve("review");
    CliResult init =
        runCli(
            "init",
            "--dir",
            appDir.toString(),
            "--id",
            "sdk-template-app",
            "--name",
            "SDK Template App",
            "--version",
            "1.0.0",
            "--template",
            "hello-stable");

    CliResult create =
        runCli(
            "submission",
            "create",
            "--bundle-dir",
            appDir.toString(),
            "--output",
            submission.toString(),
            "--submission-type",
            "new_app",
            "--maintainer-name",
            "Example Maintainer",
            "--maintainer-contact",
            "mailto:maintainer@example.invalid",
            "--source-url",
            "https://example.invalid/sdk-template-app",
            "--permission-rationale",
            reviewDir.resolve("permission-rationale.md").toString(),
            "--sandbox-rationale",
            reviewDir.resolve("sandbox-rationale.md").toString(),
            "--data-schema",
            reviewDir.resolve("data-schema.md").toString(),
            "--backup-restore",
            reviewDir.resolve("backup-restore.md").toString(),
            "--security-notes",
            reviewDir.resolve("security-notes.md").toString(),
            "--changelog",
            reviewDir.resolve("changelog.md").toString(),
            "--non-production");

    assertEquals(CommandLine.ExitCode.OK, init.exitCode(), init.err());
    assertEquals(CommandLine.ExitCode.OK, create.exitCode(), create.err());
    assertTrue(Files.isRegularFile(submission));
    assertFalse(create.err().contains("redaction.session-token"));
    assertFalse(create.err().contains("redaction.raw-content"));
  }

  @Test
  void submissionVerifyJson_whenRedactionBlockerIsInMetadata_expectRedactedSummary()
      throws Exception {
    Path appDir = createSubmissionBundle("json-leak-app", "JSON Leak App", "1.0.0");
    Path submission = tempDir.resolve("json-leak-submission.zip");
    CliResult create =
        runCli(
            "submission",
            "create",
            "--bundle-dir",
            appDir.toString(),
            "--output",
            submission.toString(),
            "--submission-type",
            "new_app",
            "--maintainer-name",
            "Example Maintainer",
            "--maintainer-contact",
            "mailto:maintainer@example.invalid",
            "--source-url",
            "https://example.invalid/json-leak-app",
            "--non-production");
    assertEquals(CommandLine.ExitCode.OK, create.exitCode(), create.err());
    String token = "Bearer abcdefghijklmnop";
    String metadata =
        readSubmissionMetadataText(submission)
            .replace(
                "\"sourceReference\":{\"url\":\"https://example.invalid/json-leak-app\"}",
                "\"sourceReference\":{\"url\":\"https://example.invalid/json-leak-app\","
                    + "\"revision\":\""
                    + token
                    + "\"}");
    Path tampered = tempDir.resolve("json-leak-tampered.zip");
    writeZipWithReplacements(
        submission,
        tampered,
        Map.of(
            SUBMISSION_METADATA_ENTRY,
            metadata.getBytes(StandardCharsets.UTF_8),
            "metadata/source.json",
            ("{\"url\":\"https://example.invalid/json-leak-app\",\"revision\":\"" + token + "\"}\n")
                .getBytes(StandardCharsets.UTF_8)));

    CliResult result =
        runCli("submission", "verify", "--submission", tampered.toString(), "--json");

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.out().contains("\"redacted\":true"));
    assertTrue(result.out().contains("redaction.bearer-token"));
    assertFalse(result.out().contains(token));
    assertFalse(result.out().contains("sourceReference"));
    assertTrue(result.err().contains("redaction.bearer-token"));
    assertFalse(result.err().contains(token));
  }

  @Test
  void redactedMessage_whenExceptionContainsCommonAbsolutePaths_expectPathsRedacted() {
    String redacted =
        CryptaAppCli.redactedMessage(
            new IllegalArgumentException(
                "failed /var/folders/aa/app/index.html and /opt/crypta/bin/tool and"
                    + " /workspace/cryptad/platform-devtools/build.log and"
                    + " C:\\Users\\Alice\\secret.txt"));

    assertTrue(redacted.contains("[redacted-path]"));
    assertFalse(redacted.contains("/var/folders"));
    assertFalse(redacted.contains("/opt/crypta"));
    assertFalse(redacted.contains("/workspace/cryptad"));
    assertFalse(redacted.contains("C:\\Users\\Alice"));
  }

  @Test
  void submissionCatalogCandidate_whenSubmissionIsResubmission_expectDescriptorPreservesLink()
      throws Exception {
    Path appDir = createSubmissionBundle("resubmitted-app", "Resubmitted App", "1.0.0");
    Path submission = tempDir.resolve("resubmitted-submission.zip");
    CliResult create =
        runCli(
            "submission",
            "create",
            "--bundle-dir",
            appDir.toString(),
            "--output",
            submission.toString(),
            "--submission-type",
            "resubmission",
            "--resubmission-of",
            "previous-submission",
            "--submission-id",
            "current-submission",
            "--maintainer-name",
            "Example Maintainer",
            "--maintainer-contact",
            "mailto:maintainer@example.invalid",
            "--source-url",
            "https://example.invalid/resubmitted-app",
            "--non-production");
    Path preReview = tempDir.resolve("resubmitted-pre-review.json");
    CliResult preReviewResult =
        runCli(
            "submission",
            "pre-review",
            "--submission",
            submission.toString(),
            "--output",
            preReview.toString());
    KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    Path privateKey = tempDir.resolve("review-private.der");
    Files.write(privateKey, keyPair.getPrivate().getEncoded());
    Path trustedReviewers = tempDir.resolve("review-trusted-reviewers.properties");
    writeTrustedReviewers(trustedReviewers, keyPair);
    Path reason = tempDir.resolve("review-reason.md");
    Files.writeString(reason, "Reviewed resubmission.\n", StandardCharsets.UTF_8);
    Path receipt = tempDir.resolve("review-receipt.properties");
    CliResult decide =
        runCli(
            "submission",
            "decide",
            "--submission",
            submission.toString(),
            "--pre-review",
            preReview.toString(),
            "--decision",
            "reviewed",
            "--reviewer-key-id",
            "reviewer-dev",
            "--reviewer-private-key",
            privateKey.toString(),
            "--reason",
            reason.toString(),
            "--receipt-output",
            receipt.toString(),
            "--reviewed-at",
            "2026-06-18T00:00:00Z",
            "--allow-non-production");
    Path descriptor = tempDir.resolve("resubmitted-catalog-entry.properties");
    CliResult candidate =
        runCli(
            "submission",
            "catalog-candidate",
            "--submission",
            submission.toString(),
            "--review-receipt",
            receipt.toString(),
            "--trusted-reviewer-keys",
            trustedReviewers.toString(),
            "--output",
            descriptor.toString());

    assertEquals(CommandLine.ExitCode.OK, create.exitCode(), create.err());
    assertEquals(CommandLine.ExitCode.OK, preReviewResult.exitCode(), preReviewResult.err());
    assertEquals(CommandLine.ExitCode.OK, decide.exitCode(), decide.err());
    assertEquals(CommandLine.ExitCode.OK, candidate.exitCode(), candidate.err());
    String preReviewDigest = sha256Hex(preReview);
    String reasonDigest = sha256Hex(reason);
    String receiptText = Files.readString(receipt, StandardCharsets.UTF_8);
    assertTrue(receiptText.contains("review.receipt.version=2\n"));
    assertTrue(receiptText.contains("review.receipt.evidence.sha256=" + preReviewDigest + "\n"));
    assertTrue(
        receiptText.contains("review.receipt.decision.reason.sha256=" + reasonDigest + "\n"));
    String descriptorText = Files.readString(descriptor, StandardCharsets.UTF_8);
    assertTrue(descriptorText.contains("review.resubmissionOf=previous-submission\n"));
    assertTrue(descriptorText.contains("review.preReview.sha256=" + preReviewDigest + "\n"));
    assertTrue(descriptorText.contains("review.decision.reason.sha256=" + reasonDigest + "\n"));
    assertTrue(descriptorText.contains("review.receipt.status=reviewed\n"));
    assertTrue(descriptorText.contains("review.receipt.signature.value.base64="));
    Path catalog = tempDir.resolve("resubmitted-catalog.properties");
    CliResult catalogCreate =
        runCli(
            "catalog",
            "create",
            "--catalog-file",
            catalog.toString(),
            "--catalog-id",
            "dev",
            "--name",
            "Development Apps",
            "--entry",
            descriptor.toString());
    assertEquals(CommandLine.ExitCode.OK, catalogCreate.exitCode(), catalogCreate.err());
    String catalogText = Files.readString(catalog, StandardCharsets.UTF_8);
    assertTrue(catalogText.contains("catalog.version=7\n"));
    assertTrue(
        catalogText.contains("app.resubmitted-app.review.preReview.sha256=" + preReviewDigest));
    assertTrue(
        catalogText.contains("app.resubmitted-app.review.decision.reason.sha256=" + reasonDigest));
    assertTrue(catalogText.contains("app.resubmitted-app.review.receipt.status=reviewed\n"));
    assertTrue(catalogText.contains("app.resubmitted-app.review.receipt.signature.value.base64="));
  }

  @Test
  void submissionCatalogCandidate_whenVersionContainsUriReservedCharacters_expectDefaultUriIsSafe()
      throws Exception {
    Path appDir =
        createSubmissionBundle("reserved-version-app", "Reserved Version App", "1.0 beta");
    Path submission = tempDir.resolve("reserved-version-submission.zip");
    CliResult create =
        runCli(
            "submission",
            "create",
            "--bundle-dir",
            appDir.toString(),
            "--output",
            submission.toString(),
            "--submission-type",
            "new_app",
            "--maintainer-name",
            "Example Maintainer",
            "--maintainer-contact",
            "mailto:maintainer@example.invalid",
            "--source-url",
            "https://example.invalid/reserved-version-app",
            "--non-production");
    Path preReview = tempDir.resolve("reserved-version-pre-review.json");
    CliResult preReviewResult =
        runCli(
            "submission",
            "pre-review",
            "--submission",
            submission.toString(),
            "--output",
            preReview.toString());
    KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    Path privateKey = tempDir.resolve("reserved-version-review-private.der");
    Files.write(privateKey, keyPair.getPrivate().getEncoded());
    Path trustedReviewers = tempDir.resolve("reserved-version-trusted-reviewers.properties");
    writeTrustedReviewers(trustedReviewers, keyPair);
    Path reason = tempDir.resolve("reserved-version-review-reason.md");
    Files.writeString(reason, "Reviewed reserved version.\n", StandardCharsets.UTF_8);
    Path receipt = tempDir.resolve("reserved-version-review-receipt.properties");
    CliResult decide =
        runCli(
            "submission",
            "decide",
            "--submission",
            submission.toString(),
            "--pre-review",
            preReview.toString(),
            "--decision",
            "reviewed",
            "--reviewer-key-id",
            "reviewer-dev",
            "--reviewer-private-key",
            privateKey.toString(),
            "--reason",
            reason.toString(),
            "--receipt-output",
            receipt.toString(),
            "--reviewed-at",
            "2026-06-18T00:00:00Z",
            "--allow-non-production");
    Path descriptor = tempDir.resolve("reserved-version-catalog-entry.properties");
    CliResult candidate =
        runCli(
            "submission",
            "catalog-candidate",
            "--submission",
            submission.toString(),
            "--review-receipt",
            receipt.toString(),
            "--trusted-reviewer-keys",
            trustedReviewers.toString(),
            "--output",
            descriptor.toString());

    assertEquals(CommandLine.ExitCode.OK, create.exitCode(), create.err());
    assertEquals(CommandLine.ExitCode.OK, preReviewResult.exitCode(), preReviewResult.err());
    assertEquals(CommandLine.ExitCode.OK, decide.exitCode(), decide.err());
    assertEquals(CommandLine.ExitCode.OK, candidate.exitCode(), candidate.err());
    String descriptorText = Files.readString(descriptor, StandardCharsets.UTF_8);
    assertTrue(
        descriptorText.contains(
            "bundle.uri=https://example.invalid/crypta-apps/reserved-version-app-1_0_beta.zip\n"));
  }

  @Test
  void submissionCatalogCandidate_whenReceiptLacksSubmissionEvidence_expectFailure()
      throws Exception {
    Path appDir = createSubmissionBundle("legacy-receipt-app", "Legacy Receipt App", "1.0.0");
    Path submission = tempDir.resolve("legacy-receipt-submission.zip");
    CliResult create =
        runCli(
            "submission",
            "create",
            "--bundle-dir",
            appDir.toString(),
            "--output",
            submission.toString(),
            "--submission-type",
            "new_app",
            "--maintainer-name",
            "Example Maintainer",
            "--maintainer-contact",
            "mailto:maintainer@example.invalid",
            "--source-url",
            "https://example.invalid/legacy-receipt-app",
            "--non-production");
    Path artifact = tempDir.resolve("legacy-receipt-app-bundle.zip");
    writeSubmissionBundleArtifact(submission, artifact);
    Path legacyDescriptor = tempDir.resolve("legacy-receipt-entry.properties");
    Files.writeString(
        legacyDescriptor,
        lines(
            "artifact.path=" + artifact.toAbsolutePath().normalize(),
            "bundle.uri=" + artifact.toUri(),
            "summary=Legacy receipt catalog entry."),
        StandardCharsets.UTF_8);
    KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    Path privateKey = tempDir.resolve("legacy-receipt-review-private.der");
    Files.write(privateKey, keyPair.getPrivate().getEncoded());
    Path trustedReviewers = tempDir.resolve("legacy-receipt-trusted-reviewers.properties");
    writeTrustedReviewers(trustedReviewers, keyPair);
    Path legacyReceipt = tempDir.resolve("legacy-review-receipt.properties");
    CliResult signLegacyReceipt =
        runCli(
            "review",
            "sign",
            "--catalog-entry",
            legacyDescriptor.toString(),
            "--receipt-file",
            legacyReceipt.toString(),
            "--reviewer-key-id",
            "reviewer-dev",
            "--reviewer-private-key-file",
            privateKey.toString(),
            "--policy-id",
            "dev-review",
            "--policy-version",
            "1",
            "--status",
            "reviewed",
            "--reviewed-at",
            "2026-06-18T00:00:00Z");
    Path candidateDescriptor = tempDir.resolve("legacy-receipt-candidate.properties");

    CliResult candidate =
        runCli(
            "submission",
            "catalog-candidate",
            "--submission",
            submission.toString(),
            "--review-receipt",
            legacyReceipt.toString(),
            "--trusted-reviewer-keys",
            trustedReviewers.toString(),
            "--output",
            candidateDescriptor.toString());

    assertEquals(CommandLine.ExitCode.OK, create.exitCode(), create.err());
    assertEquals(CommandLine.ExitCode.OK, signLegacyReceipt.exitCode(), signLegacyReceipt.err());
    assertEquals(CommandLine.ExitCode.SOFTWARE, candidate.exitCode());
    assertTrue(candidate.err().contains("require v2 review receipt evidence"));
    assertFalse(Files.exists(candidateDescriptor));
  }

  @Test
  void submissionCatalogCandidate_whenReceiptIsNotTrusted_expectNoCandidateArtifacts()
      throws Exception {
    Path appDir = createSubmissionBundle("untrusted-receipt-app", "Untrusted Receipt App", "1.0.0");
    Path submission = tempDir.resolve("untrusted-receipt-submission.zip");
    CliResult create =
        runCli(
            "submission",
            "create",
            "--bundle-dir",
            appDir.toString(),
            "--output",
            submission.toString(),
            "--submission-type",
            "new_app",
            "--maintainer-name",
            "Example Maintainer",
            "--maintainer-contact",
            "mailto:maintainer@example.invalid",
            "--source-url",
            "https://example.invalid/untrusted-receipt-app",
            "--non-production");
    Path preReview = tempDir.resolve("untrusted-receipt-pre-review.json");
    CliResult preReviewResult =
        runCli(
            "submission",
            "pre-review",
            "--submission",
            submission.toString(),
            "--output",
            preReview.toString());
    KeyPair signingKeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    KeyPair registryKeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    Path privateKey = tempDir.resolve("untrusted-receipt-review-private.der");
    Files.write(privateKey, signingKeyPair.getPrivate().getEncoded());
    Path trustedReviewers = tempDir.resolve("untrusted-receipt-trusted-reviewers.properties");
    writeTrustedReviewers(trustedReviewers, registryKeyPair);
    Path reason = tempDir.resolve("untrusted-receipt-reason.md");
    Files.writeString(
        reason, "Reviewed with untrusted registry fixture.\n", StandardCharsets.UTF_8);
    Path receipt = tempDir.resolve("untrusted-receipt.properties");
    CliResult decide =
        runCli(
            "submission",
            "decide",
            "--submission",
            submission.toString(),
            "--pre-review",
            preReview.toString(),
            "--decision",
            "reviewed",
            "--reviewer-key-id",
            "reviewer-dev",
            "--reviewer-private-key",
            privateKey.toString(),
            "--reason",
            reason.toString(),
            "--receipt-output",
            receipt.toString(),
            "--reviewed-at",
            "2026-06-18T00:00:00Z",
            "--allow-non-production");
    Path candidateDescriptor = tempDir.resolve("untrusted-receipt-candidate.properties");
    Path artifactOutput = tempDir.resolve("untrusted-receipt-app-bundle.zip");

    CliResult candidate =
        runCli(
            "submission",
            "catalog-candidate",
            "--submission",
            submission.toString(),
            "--review-receipt",
            receipt.toString(),
            "--trusted-reviewer-keys",
            trustedReviewers.toString(),
            "--output",
            candidateDescriptor.toString(),
            "--artifact-output",
            artifactOutput.toString());

    assertEquals(CommandLine.ExitCode.OK, create.exitCode(), create.err());
    assertEquals(CommandLine.ExitCode.OK, preReviewResult.exitCode(), preReviewResult.err());
    assertEquals(CommandLine.ExitCode.OK, decide.exitCode(), decide.err());
    assertEquals(CommandLine.ExitCode.SOFTWARE, candidate.exitCode());
    assertTrue(
        candidate
            .err()
            .contains("review receipt did not verify against trusted reviewer registry"));
    assertTrue(candidate.err().contains("invalid_signature"));
    assertFalse(Files.exists(candidateDescriptor));
    assertFalse(Files.exists(artifactOutput));
  }

  @Test
  void submissionDecide_whenRejectedReviewerFieldIsMultiline_expectFailure() throws Exception {
    Path appDir = createSubmissionBundle("rejected-app", "Rejected App", "1.0.0");
    Path submission = tempDir.resolve("rejected-submission.zip");
    CliResult create =
        runCli(
            "submission",
            "create",
            "--bundle-dir",
            appDir.toString(),
            "--output",
            submission.toString(),
            "--submission-type",
            "new_app",
            "--maintainer-name",
            "Example Maintainer",
            "--maintainer-contact",
            "mailto:maintainer@example.invalid",
            "--source-url",
            "https://example.invalid/rejected-app",
            "--non-production");
    Path preReview = tempDir.resolve("rejected-pre-review.json");
    CliResult preReviewResult =
        runCli(
            "submission",
            "pre-review",
            "--submission",
            submission.toString(),
            "--output",
            preReview.toString());
    Path reason = tempDir.resolve("rejected-reason.md");
    Path rejection = tempDir.resolve("rejection.properties");
    Files.writeString(reason, "Rejected during metadata validation.\n", StandardCharsets.UTF_8);
    assertEquals(CommandLine.ExitCode.OK, create.exitCode(), create.err());
    assertEquals(CommandLine.ExitCode.OK, preReviewResult.exitCode(), preReviewResult.err());

    CliResult result =
        runCli(
            "submission",
            "decide",
            "--submission",
            submission.toString(),
            "--pre-review",
            preReview.toString(),
            "--decision",
            "rejected",
            "--reviewer-key-id",
            "reviewer-dev\npolicy.id=injected",
            "--rejection-output",
            rejection.toString(),
            "--reason",
            reason.toString(),
            "--allow-non-production");

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("review.receipt.reviewer.key.id must be a single line"));
    assertTrue(Files.notExists(rejection));
  }

  @Test
  void submissionDecide_whenPreReviewDigestDoesNotMatchSubmission_expectFailure() throws Exception {
    Path appDir = createSubmissionBundle("reviewed-app", "Reviewed App", "1.0.0");
    Path submission = tempDir.resolve("reviewed-submission.zip");
    CliResult create =
        runCli(
            "submission",
            "create",
            "--bundle-dir",
            appDir.toString(),
            "--output",
            submission.toString(),
            "--submission-type",
            "new_app",
            "--maintainer-name",
            "Example Maintainer",
            "--maintainer-contact",
            "mailto:maintainer@example.invalid",
            "--source-url",
            "https://example.invalid/reviewed-app",
            "--non-production");
    Path preReview = tempDir.resolve("pre-review.json");
    CliResult preReviewResult =
        runCli(
            "submission",
            "pre-review",
            "--submission",
            submission.toString(),
            "--output",
            preReview.toString());
    assertEquals(CommandLine.ExitCode.OK, create.exitCode(), create.err());
    assertEquals(CommandLine.ExitCode.OK, preReviewResult.exitCode(), preReviewResult.err());
    String badDigest = "0".repeat(64);
    Path tamperedPreReview = tempDir.resolve("tampered-pre-review.json");
    Files.writeString(
        tamperedPreReview,
        Files.readString(preReview, StandardCharsets.UTF_8)
            .replaceAll(
                "\"bundleDigest\"\\s*:\\s*\"[0-9a-f]{64}\"",
                "\"bundleDigest\":\"" + badDigest + "\""),
        StandardCharsets.UTF_8);
    Path reason = tempDir.resolve("reason.md");
    Files.writeString(reason, "Rejected during digest binding check.\n", StandardCharsets.UTF_8);

    CliResult result =
        runCli(
            "submission",
            "decide",
            "--submission",
            submission.toString(),
            "--pre-review",
            tamperedPreReview.toString(),
            "--decision",
            "rejected",
            "--reviewer-key-id",
            "reviewer-dev",
            "--reason",
            reason.toString(),
            "--allow-non-production");

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(result.err().contains("pre-review report bundleDigest does not match submission"));
  }

  @Test
  void submissionDecide_whenCautionDecisionIsLogged_expectTransparencyIsNotPositive()
      throws Exception {
    Path appDir = createSubmissionBundle("caution-app", "Caution App", "1.0.0");
    Path submission = tempDir.resolve("caution-submission.zip");
    CliResult create =
        runCli(
            "submission",
            "create",
            "--bundle-dir",
            appDir.toString(),
            "--output",
            submission.toString(),
            "--submission-type",
            "new_app",
            "--maintainer-name",
            "Example Maintainer",
            "--maintainer-contact",
            "mailto:maintainer@example.invalid",
            "--source-url",
            "https://example.invalid/caution-app",
            "--non-production");
    Path preReview = tempDir.resolve("caution-pre-review.json");
    CliResult preReviewResult =
        runCli(
            "submission",
            "pre-review",
            "--submission",
            submission.toString(),
            "--output",
            preReview.toString());
    KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    Path privateKey = tempDir.resolve("caution-review-private.der");
    Files.write(privateKey, keyPair.getPrivate().getEncoded());
    Path reason = tempDir.resolve("caution-reason.md");
    Files.writeString(reason, "Accepted with reviewer caution.\n", StandardCharsets.UTF_8);
    Path receipt = tempDir.resolve("caution-review-receipt.properties");
    Path transparencyLog = tempDir.resolve("caution-transparency.jsonl");
    assertEquals(CommandLine.ExitCode.OK, create.exitCode(), create.err());
    assertEquals(CommandLine.ExitCode.OK, preReviewResult.exitCode(), preReviewResult.err());

    CliResult result =
        runCli(
            "submission",
            "decide",
            "--submission",
            submission.toString(),
            "--pre-review",
            preReview.toString(),
            "--decision",
            "caution",
            "--reviewer-key-id",
            "reviewer-dev",
            "--reviewer-private-key",
            privateKey.toString(),
            "--reason",
            reason.toString(),
            "--receipt-output",
            receipt.toString(),
            "--transparency-log",
            transparencyLog.toString(),
            "--reviewed-at",
            "2026-06-18T00:00:00Z",
            "--allow-non-production");

    assertEquals(CommandLine.ExitCode.OK, result.exitCode(), result.err());
    String logText = Files.readString(transparencyLog, StandardCharsets.UTF_8);
    assertTrue(logText.contains("\"receiptStatus\":\"caution\""));
    assertTrue(logText.contains("\"positive\":false"));
    assertFalse(logText.contains("\"positive\":true"));
  }

  @Test
  void submissionDecide_whenTrustedReviewerRegistryIsMissing_expectNoReceiptOrLogArtifacts()
      throws Exception {
    Path appDir = createSubmissionBundle("registry-fail-app", "Registry Fail App", "1.0.0");
    Path submission = tempDir.resolve("registry-fail-submission.zip");
    CliResult create =
        runCli(
            "submission",
            "create",
            "--bundle-dir",
            appDir.toString(),
            "--output",
            submission.toString(),
            "--submission-type",
            "new_app",
            "--maintainer-name",
            "Example Maintainer",
            "--maintainer-contact",
            "mailto:maintainer@example.invalid",
            "--source-url",
            "https://example.invalid/registry-fail-app",
            "--non-production");
    Path preReview = tempDir.resolve("registry-fail-pre-review.json");
    CliResult preReviewResult =
        runCli(
            "submission",
            "pre-review",
            "--submission",
            submission.toString(),
            "--output",
            preReview.toString());
    KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    Path privateKey = tempDir.resolve("registry-fail-review-private.der");
    Files.write(privateKey, keyPair.getPrivate().getEncoded());
    Path reason = tempDir.resolve("registry-fail-reason.md");
    Files.writeString(reason, "Reviewed after automated checks.\n", StandardCharsets.UTF_8);
    Path receipt = tempDir.resolve("registry-fail-review-receipt.properties");
    Path transparencyLog = tempDir.resolve("registry-fail-transparency.jsonl");
    Path missingTrustedReviewers = tempDir.resolve("missing-trusted-reviewers.properties");
    assertEquals(CommandLine.ExitCode.OK, create.exitCode(), create.err());
    assertEquals(CommandLine.ExitCode.OK, preReviewResult.exitCode(), preReviewResult.err());

    CliResult result =
        runCli(
            "submission",
            "decide",
            "--submission",
            submission.toString(),
            "--pre-review",
            preReview.toString(),
            "--decision",
            "reviewed",
            "--reviewer-key-id",
            "reviewer-dev",
            "--reviewer-private-key",
            privateKey.toString(),
            "--trusted-reviewer-keys",
            missingTrustedReviewers.toString(),
            "--reason",
            reason.toString(),
            "--receipt-output",
            receipt.toString(),
            "--transparency-log",
            transparencyLog.toString(),
            "--reviewed-at",
            "2026-06-18T00:00:00Z",
            "--allow-non-production");

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(Files.notExists(receipt));
    assertTrue(Files.notExists(transparencyLog));
  }

  @Test
  void submissionDecide_whenTrustedReviewerRegistryHasDifferentKey_expectNoReceiptOrLogArtifacts()
      throws Exception {
    Path appDir = createSubmissionBundle("registry-mismatch-app", "Registry Mismatch App", "1.0.0");
    Path submission = tempDir.resolve("registry-mismatch-submission.zip");
    CliResult create =
        runCli(
            "submission",
            "create",
            "--bundle-dir",
            appDir.toString(),
            "--output",
            submission.toString(),
            "--submission-type",
            "new_app",
            "--maintainer-name",
            "Example Maintainer",
            "--maintainer-contact",
            "mailto:maintainer@example.invalid",
            "--source-url",
            "https://example.invalid/registry-mismatch-app",
            "--non-production");
    Path preReview = tempDir.resolve("registry-mismatch-pre-review.json");
    CliResult preReviewResult =
        runCli(
            "submission",
            "pre-review",
            "--submission",
            submission.toString(),
            "--output",
            preReview.toString());
    KeyPair signingKeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    KeyPair registryKeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    Path privateKey = tempDir.resolve("registry-mismatch-review-private.der");
    Files.write(privateKey, signingKeyPair.getPrivate().getEncoded());
    Path trustedReviewers = tempDir.resolve("registry-mismatch-trusted-reviewers.properties");
    Files.writeString(
        trustedReviewers,
        lines(
            "trusted.reviewers.version=1",
            "reviewer.1.id=reviewer-dev",
            "reviewer.1.algorithm=Ed25519",
            "reviewer.1.public.key.base64="
                + Base64.getEncoder().encodeToString(registryKeyPair.getPublic().getEncoded()),
            "reviewer.1.display.name=Development Review",
            "reviewer.1.policy.id=crypta-app-review-v1"),
        StandardCharsets.UTF_8);
    Path reason = tempDir.resolve("registry-mismatch-reason.md");
    Files.writeString(reason, "Reviewed after automated checks.\n", StandardCharsets.UTF_8);
    Path receipt = tempDir.resolve("registry-mismatch-review-receipt.properties");
    Path transparencyLog = tempDir.resolve("registry-mismatch-transparency.jsonl");
    assertEquals(CommandLine.ExitCode.OK, create.exitCode(), create.err());
    assertEquals(CommandLine.ExitCode.OK, preReviewResult.exitCode(), preReviewResult.err());

    CliResult result =
        runCli(
            "submission",
            "decide",
            "--submission",
            submission.toString(),
            "--pre-review",
            preReview.toString(),
            "--decision",
            "reviewed",
            "--reviewer-key-id",
            "reviewer-dev",
            "--reviewer-private-key",
            privateKey.toString(),
            "--trusted-reviewer-keys",
            trustedReviewers.toString(),
            "--reason",
            reason.toString(),
            "--receipt-output",
            receipt.toString(),
            "--transparency-log",
            transparencyLog.toString(),
            "--reviewed-at",
            "2026-06-18T00:00:00Z",
            "--allow-non-production");

    assertEquals(CommandLine.ExitCode.SOFTWARE, result.exitCode());
    assertTrue(
        result.err().contains("review receipt did not verify against trusted reviewer registry"));
    assertTrue(result.err().contains("invalid_signature"));
    assertTrue(Files.notExists(receipt));
    assertTrue(Files.notExists(transparencyLog));
  }

  @Test
  void submissionIntake_whenReviewedSubmissionStaged_expectBetaCandidateArtifacts()
      throws Exception {
    Path appDir = createSubmissionBundle("intake-reviewed-app", "Intake Reviewed App", "1.0.0");
    Path submission = tempDir.resolve("intake-reviewed-submission.zip");
    CliResult create =
        runCli(
            "submission",
            "create",
            "--bundle-dir",
            appDir.toString(),
            "--output",
            submission.toString(),
            "--submission-type",
            "new_app",
            "--submission-id",
            "sub.intake-reviewed",
            "--maintainer-name",
            "Example Maintainer",
            "--maintainer-contact",
            "mailto:maintainer@example.invalid",
            "--source-url",
            "https://example.invalid/intake-reviewed-app",
            "--non-production");
    Path queueDir = tempDir.resolve("app-intake");
    Path transparencyLog = queueDir.resolve("review-transparency.jsonl");
    CliResult importResult =
        runCli(
            "submission",
            "intake",
            "import",
            "--queue-dir",
            queueDir.toString(),
            "--submission",
            submission.toString(),
            "--imported-at",
            "2026-06-18T00:00:00Z",
            "--transparency-log",
            transparencyLog.toString());
    CliResult listResult =
        runCli("submission", "intake", "list", "--queue-dir", queueDir.toString(), "--json");
    KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    Path privateKey = tempDir.resolve("intake-review-private.der");
    Files.write(privateKey, keyPair.getPrivate().getEncoded());
    Path trustedReviewers = tempDir.resolve("intake-trusted-reviewers.properties");
    writeTrustedReviewers(trustedReviewers, keyPair);
    Path reason = tempDir.resolve("intake-review-reason.md");
    Files.writeString(reason, "Reviewed intake submission.\n", StandardCharsets.UTF_8);
    Path decisionDir = queueDir.resolve("custom-decisions").resolve("sub.intake-reviewed");
    CliResult assign =
        runCli(
            "submission",
            "intake",
            "assign",
            "--queue-dir",
            queueDir.toString(),
            "--submission-id",
            "sub.intake-reviewed",
            "--reviewer-key-id",
            "reviewer-dev",
            "--trusted-reviewer-keys",
            trustedReviewers.toString(),
            "--reason",
            reason.toString(),
            "--assigned-at",
            "2026-06-18T00:01:00Z",
            "--transparency-log",
            transparencyLog.toString());
    Path artifactsDir = queueDir.resolve("artifacts").resolve("sub.intake-reviewed");
    CliResult preReview =
        runCli(
            "submission",
            "intake",
            "pre-review",
            "--queue-dir",
            queueDir.toString(),
            "--submission-id",
            "sub.intake-reviewed",
            "--artifacts-dir",
            artifactsDir.toString(),
            "--completed-at",
            "2026-06-18T00:02:00Z",
            "--transparency-log",
            transparencyLog.toString());
    CliResult decide =
        runCli(
            "submission",
            "intake",
            "decide",
            "--queue-dir",
            queueDir.toString(),
            "--submission-id",
            "sub.intake-reviewed",
            "--decision",
            "reviewed",
            "--reviewer-key-id",
            "reviewer-dev",
            "--reviewer-private-key",
            privateKey.toString(),
            "--trusted-reviewer-keys",
            trustedReviewers.toString(),
            "--reason",
            reason.toString(),
            "--artifacts-dir",
            artifactsDir.toString(),
            "--decision-dir",
            decisionDir.toString(),
            "--reviewed-at",
            "2026-06-18T00:03:00Z",
            "--allow-non-production",
            "--transparency-log",
            transparencyLog.toString());
    Path mismatchedDecisionDir =
        queueDir.resolve("mismatched-decisions").resolve("sub.intake-reviewed");
    Files.createDirectories(mismatchedDecisionDir);
    CliResult mismatchedReceipt =
        runCli(
            "submission",
            "decide",
            "--submission",
            submission.toString(),
            "--pre-review",
            artifactsDir.resolve("pre-review.json").toString(),
            "--decision",
            "reviewed",
            "--reviewer-key-id",
            "reviewer-dev",
            "--reviewer-private-key",
            privateKey.toString(),
            "--reason",
            reason.toString(),
            "--receipt-output",
            mismatchedDecisionDir.resolve("review-receipt.properties").toString(),
            "--reviewed-at",
            "2026-06-18T00:03:30Z",
            "--allow-non-production");
    Path rejectedBetaCandidates = tempDir.resolve("beta-candidates-mismatched-receipt");
    CliResult rejectedStage =
        runCli(
            "submission",
            "intake",
            "stage-candidate",
            "--queue-dir",
            queueDir.toString(),
            "--submission-id",
            "sub.intake-reviewed",
            "--trusted-reviewer-keys",
            trustedReviewers.toString(),
            "--beta-candidate-dir",
            rejectedBetaCandidates.toString(),
            "--bundle-uri",
            "https://example.invalid/crypta-apps/intake-reviewed-app.zip",
            "--decision-dir",
            mismatchedDecisionDir.toString(),
            "--staged-at",
            "2026-06-18T00:03:45Z");
    Path betaCandidates = tempDir.resolve("beta-candidates");
    CliResult stage =
        runCli(
            "submission",
            "intake",
            "stage-candidate",
            "--queue-dir",
            queueDir.toString(),
            "--submission-id",
            "sub.intake-reviewed",
            "--trusted-reviewer-keys",
            trustedReviewers.toString(),
            "--beta-candidate-dir",
            betaCandidates.toString(),
            "--bundle-uri",
            "https://example.invalid/crypta-apps/intake-reviewed-app.zip",
            "--decision-dir",
            decisionDir.toString(),
            "--staged-at",
            "2026-06-18T00:04:00Z",
            "--transparency-log",
            transparencyLog.toString());

    assertReviewedIntakeSetupSucceeded(create, importResult, listResult, assign);
    assertPreReviewAndDecisionArtifactsCreated(preReview, artifactsDir, decide, decisionDir);
    assertMismatchedReceiptCandidateRejected(
        mismatchedReceipt, rejectedStage, rejectedBetaCandidates);
    Path candidateDir = assertCandidateArtifactsCreated(stage, betaCandidates);
    assertCandidateStagingPendingSmoke(queueDir, candidateDir);
    CliResult installSmoke =
        runCli(
            "submission",
            "intake",
            "install-smoke",
            "--queue-dir",
            queueDir.toString(),
            "--submission-id",
            "sub.intake-reviewed",
            "--beta-candidate-dir",
            betaCandidates.toString(),
            "--smoked-at",
            "2026-06-18T00:04:30Z",
            "--transparency-log",
            transparencyLog.toString());
    assertInstallSmokePassed(installSmoke, queueDir, candidateDir);
    String descriptorBefore =
        Files.readString(
            candidateDir.resolve("catalog-candidate.properties"), StandardCharsets.UTF_8);
    String transparencyLogBefore = Files.readString(transparencyLog, StandardCharsets.UTF_8);
    String exportedTransparencyBefore =
        Files.readString(
            candidateDir.resolve("candidate-transparency-log.jsonl"), StandardCharsets.UTF_8);
    CliResult rerunStage =
        runCli(
            "submission",
            "intake",
            "stage-candidate",
            "--queue-dir",
            queueDir.toString(),
            "--submission-id",
            "sub.intake-reviewed",
            "--trusted-reviewer-keys",
            trustedReviewers.toString(),
            "--beta-candidate-dir",
            betaCandidates.toString(),
            "--bundle-uri",
            "https://example.invalid/crypta-apps/mutated-intake-reviewed-app.zip",
            "--summary",
            "Mutated summary must not be written.",
            "--decision-dir",
            decisionDir.toString(),
            "--staged-at",
            "2026-06-18T00:05:00Z",
            "--overwrite",
            "--transparency-log",
            transparencyLog.toString());
    assertRerunCandidateStageDidNotMutateArtifacts(
        rerunStage,
        queueDir,
        candidateDir,
        transparencyLog,
        descriptorBefore,
        transparencyLogBefore,
        exportedTransparencyBefore);
  }

  @Test
  void submissionIntakeDecide_whenQueuePreReviewMissing_expectNoDecisionArtifacts()
      throws Exception {
    Path appDir =
        createSubmissionBundle(
            "intake-missing-pre-review-app", "Intake Missing Pre Review", "1.0.0");
    Path submission = tempDir.resolve("intake-missing-pre-review-submission.zip");
    CliResult create =
        runCli(
            "submission",
            "create",
            "--bundle-dir",
            appDir.toString(),
            "--output",
            submission.toString(),
            "--submission-type",
            "new_app",
            "--submission-id",
            "sub-intake-missing-pre-review",
            "--maintainer-name",
            "Example Maintainer",
            "--maintainer-contact",
            "mailto:maintainer@example.invalid",
            "--source-url",
            "https://example.invalid/intake-missing-pre-review-app",
            "--non-production");
    Path artifactsDir = tempDir.resolve("external-pre-review-artifacts");
    Files.createDirectories(artifactsDir);
    CliResult externalPreReview =
        runCli(
            "submission",
            "pre-review",
            "--submission",
            submission.toString(),
            "--output",
            artifactsDir.resolve("pre-review.json").toString());
    Path queueDir = tempDir.resolve("missing-pre-review-intake");
    CliResult importResult =
        runCli(
            "submission",
            "intake",
            "import",
            "--queue-dir",
            queueDir.toString(),
            "--submission",
            submission.toString(),
            "--imported-at",
            "2026-06-18T00:00:00Z");
    KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    Path privateKey = tempDir.resolve("missing-pre-review-private.der");
    Files.write(privateKey, keyPair.getPrivate().getEncoded());
    Path trustedReviewers = tempDir.resolve("missing-pre-review-trusted.properties");
    writeTrustedReviewers(trustedReviewers, keyPair);
    Path reason = tempDir.resolve("missing-pre-review-reason.md");
    Files.writeString(
        reason, "Attempted decision before queue pre-review.\n", StandardCharsets.UTF_8);
    CliResult assign =
        runCli(
            "submission",
            "intake",
            "assign",
            "--queue-dir",
            queueDir.toString(),
            "--submission-id",
            "sub-intake-missing-pre-review",
            "--reviewer-key-id",
            "reviewer-dev",
            "--trusted-reviewer-keys",
            trustedReviewers.toString(),
            "--reason",
            reason.toString(),
            "--assigned-at",
            "2026-06-18T00:01:00Z");
    Path decisionDir = queueDir.resolve("decisions").resolve("sub-intake-missing-pre-review");
    CliResult decide =
        runCli(
            "submission",
            "intake",
            "decide",
            "--queue-dir",
            queueDir.toString(),
            "--submission-id",
            "sub-intake-missing-pre-review",
            "--decision",
            "reviewed",
            "--reviewer-key-id",
            "reviewer-dev",
            "--reviewer-private-key",
            privateKey.toString(),
            "--trusted-reviewer-keys",
            trustedReviewers.toString(),
            "--reason",
            reason.toString(),
            "--artifacts-dir",
            artifactsDir.toString(),
            "--decision-dir",
            decisionDir.toString(),
            "--reviewed-at",
            "2026-06-18T00:02:00Z",
            "--allow-non-production");

    assertEquals(CommandLine.ExitCode.OK, create.exitCode(), create.err());
    assertEquals(CommandLine.ExitCode.OK, externalPreReview.exitCode(), externalPreReview.err());
    assertEquals(CommandLine.ExitCode.OK, importResult.exitCode(), importResult.err());
    assertEquals(CommandLine.ExitCode.OK, assign.exitCode(), assign.err());
    assertEquals(CommandLine.ExitCode.SOFTWARE, decide.exitCode());
    assertTrue(decide.err().contains("intake decision requires recorded pre-review"));
    assertTrue(Files.notExists(decisionDir.resolve("review-receipt.properties")));
  }

  private static void assertReviewedIntakeSetupSucceeded(
      CliResult create, CliResult importResult, CliResult listResult, CliResult assign) {
    assertEquals(CommandLine.ExitCode.OK, create.exitCode(), create.err());
    assertEquals(CommandLine.ExitCode.OK, importResult.exitCode(), importResult.err());
    assertEquals(CommandLine.ExitCode.OK, listResult.exitCode(), listResult.err());
    assertTrue(listResult.out().contains("\"submissionId\":\"sub.intake-reviewed\""));
    assertEquals(CommandLine.ExitCode.OK, assign.exitCode(), assign.err());
  }

  private static void assertPreReviewAndDecisionArtifactsCreated(
      CliResult preReview, Path artifactsDir, CliResult decide, Path decisionDir) {
    assertEquals(CommandLine.ExitCode.OK, preReview.exitCode(), preReview.err());
    assertTrue(Files.isRegularFile(artifactsDir.resolve("artifact-manifest.json")));
    assertTrue(Files.isRegularFile(artifactsDir.resolve("redaction-scan.json")));
    assertEquals(CommandLine.ExitCode.OK, decide.exitCode(), decide.err());
    assertTrue(Files.isRegularFile(decisionDir.resolve("review-receipt.properties")));
  }

  private static void assertMismatchedReceiptCandidateRejected(
      CliResult mismatchedReceipt, CliResult rejectedStage, Path rejectedBetaCandidates) {
    assertEquals(CommandLine.ExitCode.OK, mismatchedReceipt.exitCode(), mismatchedReceipt.err());
    assertEquals(CommandLine.ExitCode.SOFTWARE, rejectedStage.exitCode());
    assertTrue(
        rejectedStage
            .err()
            .contains("review receipt fingerprint does not match recorded intake decision"));
    assertTrue(
        Files.notExists(
            rejectedBetaCandidates
                .resolve("sub.intake-reviewed")
                .resolve("catalog-candidate.properties")));
  }

  private static Path assertCandidateArtifactsCreated(CliResult stage, Path betaCandidates)
      throws IOException {
    assertEquals(CommandLine.ExitCode.OK, stage.exitCode(), stage.err());
    assertTrue(stage.out().contains("installSmoke=pending"));
    Path candidateDir = betaCandidates.resolve("sub.intake-reviewed");
    assertTrue(Files.isRegularFile(candidateDir.resolve("catalog-candidate.properties")));
    assertTrue(Files.isRegularFile(candidateDir.resolve("candidate-manifest.json")));
    assertTrue(Files.isRegularFile(candidateDir.resolve("candidate-review-receipt.properties")));
    assertTrue(Files.isRegularFile(candidateDir.resolve("candidate-transparency-log.jsonl")));
    assertTrue(
        Files.readString(
                candidateDir.resolve("catalog-candidate.properties"), StandardCharsets.UTF_8)
            .contains("api.targetBaseline=1.0\n"));
    assertTrue(
        Files.readString(candidateDir.resolve("candidate-manifest.json"), StandardCharsets.UTF_8)
            .contains("\"apiTargetBaseline\":\"1.0\""));
    return candidateDir;
  }

  private static void assertCandidateStagingPendingSmoke(Path queueDir, Path candidateDir)
      throws IOException {
    String intakeRecordJson =
        Files.readString(
            queueDir.resolve("records").resolve("sub.intake-reviewed.json"),
            StandardCharsets.UTF_8);
    assertTrue(intakeRecordJson.contains("\"status\":\"staged_to_beta_catalog\""));
    assertTrue(intakeRecordJson.contains("\"installSmokeStatus\":\"pending\""));
    assertFalse(intakeRecordJson.contains("\"status\":\"beta_install_smoke_passed\""));
    assertTrue(
        Files.readString(candidateDir.resolve("candidate-manifest.json"), StandardCharsets.UTF_8)
            .contains("\"installSmokeStatus\":\"pending\""));
  }

  private static void assertInstallSmokePassed(
      CliResult installSmoke, Path queueDir, Path candidateDir) throws IOException {
    assertEquals(CommandLine.ExitCode.OK, installSmoke.exitCode(), installSmoke.err());
    assertTrue(installSmoke.out().contains("Beta catalog install smoke passed"));
    assertTrue(Files.isRegularFile(candidateDir.resolve("candidate-install-smoke.json")));
    assertTrue(
        Files.readString(
                candidateDir.resolve("candidate-install-smoke.json"), StandardCharsets.UTF_8)
            .contains("\"status\":\"pass\""));
    String intakeRecordJson =
        Files.readString(
            queueDir.resolve("records").resolve("sub.intake-reviewed.json"),
            StandardCharsets.UTF_8);
    assertTrue(intakeRecordJson.contains("\"status\":\"beta_install_smoke_passed\""));
    assertTrue(intakeRecordJson.contains("\"installSmokeStatus\":\"pass\""));
  }

  private void assertRerunCandidateStageDidNotMutateArtifacts(
      CliResult rerunStage,
      Path queueDir,
      Path candidateDir,
      Path transparencyLog,
      String descriptorBefore,
      String transparencyLogBefore,
      String exportedTransparencyBefore)
      throws Exception {
    String intakeRecordJson =
        Files.readString(
            queueDir.resolve("records").resolve("sub.intake-reviewed.json"),
            StandardCharsets.UTF_8);
    assertTrue(intakeRecordJson.contains("\"status\":\"beta_install_smoke_passed\""));
    assertTrue(
        intakeRecordJson.contains(
            "\"betaCatalogCandidateReference\":\"beta-candidate:sub.intake-reviewed/"));
    assertFalse(intakeRecordJson.contains(tempDir.toString()));
    assertEquals(CommandLine.ExitCode.SOFTWARE, rerunStage.exitCode());
    assertTrue(rerunStage.err().contains("invalid intake status transition"));
    assertEquals(
        descriptorBefore,
        Files.readString(
            candidateDir.resolve("catalog-candidate.properties"), StandardCharsets.UTF_8));
    assertEquals(transparencyLogBefore, Files.readString(transparencyLog, StandardCharsets.UTF_8));
    assertEquals(
        exportedTransparencyBefore,
        Files.readString(
            candidateDir.resolve("candidate-transparency-log.jsonl"), StandardCharsets.UTF_8));
    assertFalse(
        Files.readString(
                candidateDir.resolve("catalog-candidate.properties"), StandardCharsets.UTF_8)
            .contains("Mutated summary must not be written."));
  }

  private static void writeZipWithReplacements(
      Path source, Path target, Map<String, byte[]> replacements) throws Exception {
    LinkedHashMap<String, byte[]> entries = new LinkedHashMap<>();
    try (ZipFile zip = new ZipFile(source.toFile())) {
      var enumeration = zip.entries();
      while (enumeration.hasMoreElements()) {
        ZipEntry entry = enumeration.nextElement();
        if (!entry.isDirectory()) {
          try (var input = zip.getInputStream(entry)) {
            entries.put(entry.getName(), input.readAllBytes());
          }
        }
      }
    }
    entries.putAll(replacements);
    try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(target))) {
      for (Map.Entry<String, byte[]> entry : entries.entrySet()) {
        zip.putNextEntry(new ZipEntry(entry.getKey()));
        zip.write(entry.getValue());
        zip.closeEntry();
      }
    }
  }

  private static String readSubmissionMetadataText(Path source) throws Exception {
    try (ZipFile zip = new ZipFile(source.toFile())) {
      ZipEntry entry = zip.getEntry(SUBMISSION_METADATA_ENTRY);
      try (var input = zip.getInputStream(entry)) {
        return new String(input.readAllBytes(), StandardCharsets.UTF_8);
      }
    }
  }

  private static void writeSubmissionBundleArtifact(Path source, Path output) throws Exception {
    try (ZipFile zip = new ZipFile(source.toFile())) {
      ZipEntry entry = zip.getEntry(SUBMISSION_BUNDLE_ARTIFACT_ENTRY);
      assertNotNull(entry);
      try (var input = zip.getInputStream(entry)) {
        Files.write(output, input.readAllBytes());
      }
    }
  }

  private Path createSubmissionBundle(String appId, String name, String version) throws Exception {
    Path bundle = tempDir.resolve(appId);
    Files.createDirectories(bundle.resolve("bin"));
    Files.writeString(
        bundle.resolve("cryptad-app.properties"),
        lines(
            "manifest.version=1",
            "app.id=" + appId,
            "app.name=" + name,
            "app.version=" + version,
            "app.exec=bin/start.sh",
            "api.minimumVersion="
                + PlatformApiContract.current().stableBaseline().contractVersion(),
            "api.maximumTestedVersion=" + currentContractVersion(),
            "api.targetStability=stable",
            "api.targetBaseline=1.0",
            "api.experimentalCapabilitiesAccepted=false"),
        StandardCharsets.UTF_8);
    Files.writeString(
        bundle.resolve("bin/start.sh"), "#!/bin/sh\necho reviewed\n", StandardCharsets.UTF_8);
    return bundle;
  }

  private static void addFirstPartyBetaReadinessFixture(Path appDir) throws IOException {
    Path manifest = appDir.resolve("cryptad-app.properties");
    Files.writeString(
        manifest,
        Files.readString(manifest, StandardCharsets.UTF_8)
            + lines(
                "app.beta.readiness=ready",
                "app.beta.qualityLevel=beta",
                "app.beta.support.owner=crypta-core",
                "app.beta.support.uri=https://example.invalid/crypta/apps/first-party-ready-app/support",
                "app.beta.support.diagnostics=redacted-summary-only",
                "app.beta.ui.emptyState=true",
                "app.beta.ui.errorState=true",
                "app.beta.ui.retryAction=true",
                "app.beta.ui.recoveryAction=true",
                "app.beta.appData=stateless",
                "app.beta.backupRestore=not-applicable",
                "app.beta.exportSupported=not-applicable",
                "app.beta.importSupported=not-applicable",
                "app.beta.migrationDryRunSupported=not-applicable",
                "app.beta.accessibility=basic-pass",
                "app.beta.uiConsistency=design-system-pass",
                "app.beta.diagnostics=redacted-summary-only",
                "permissions.rationale.queue.read=Display bounded local queue state for beta"
                    + " support."),
        StandardCharsets.UTF_8);
    Path index = appDir.resolve("static").resolve("index.html");
    String html =
        Files.readString(index, StandardCharsets.UTF_8)
            .replace(
                "data-crypta-permission-summary",
                "data-crypta-permission-summary data-beta-permission-rationale")
            .replace(
                "role=\"status\" aria-live=\"polite\"",
                "role=\"status\" aria-live=\"polite\" data-beta-accessibility-status");
    html =
        html.replace(
            "</main>",
            """
              <section
                class="cr-card"
                data-first-party-beta-readiness
                data-beta-empty-state
                data-beta-error-state
                data-beta-retry-action
                data-beta-recovery-action
                data-beta-app-data-status
                data-beta-support-metadata
                data-beta-diagnostics-redaction
                data-beta-ui-consistency>
                <p>Empty state, bounded error state, retry action, operator recovery, stateless app data, support metadata, and redacted-summary-only diagnostics.</p>
              </section>
            </main>\
            """);
    Files.writeString(index, html, StandardCharsets.UTF_8);
  }

  private static String sha256Hex(Path file) throws Exception {
    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    byte[] bytes = Files.readAllBytes(file);
    digest.update(bytes);
    StringBuilder builder = new StringBuilder(64);
    for (byte value : digest.digest()) {
      builder.append(Character.forDigit((value >>> 4) & 0x0F, 16));
      builder.append(Character.forDigit(value & 0x0F, 16));
    }
    return builder.toString();
  }

  private static String lines(String... values) {
    return String.join("\n", values) + "\n";
  }

  private static String snapshotWithoutCompatibilityWindow() {
    LinkedHashMap<String, Object> contract =
        new LinkedHashMap<>(PlatformApiContractJson.toJsonValue(PlatformApiContract.current()));
    contract.remove("compatibilityWindow");
    LinkedHashMap<String, Object> envelope = new LinkedHashMap<>();
    envelope.put("contract", contract);
    return PlatformApiJsonWriter.write(envelope);
  }

  private static void writeTrustedReviewers(Path output, KeyPair keyPair) throws IOException {
    Files.writeString(
        output,
        lines(
            "trusted.reviewers.version=1",
            "reviewer.1.id=reviewer-dev",
            "reviewer.1.algorithm=Ed25519",
            "reviewer.1.public.key.base64="
                + Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()),
            "reviewer.1.display.name=Development Review",
            "reviewer.1.policy.id=crypta-app-review-v1"),
        StandardCharsets.UTF_8);
  }

  private static boolean canCreateSymlink(Path symlink) {
    try {
      Files.createSymbolicLink(symlink, Path.of("missing-target"));
      Files.deleteIfExists(symlink);
      return true;
    } catch (UnsupportedOperationException | java.io.IOException | SecurityException _) {
      return false;
    }
  }

  private static CliResult runCli(String... arguments) {
    StringWriter out = new StringWriter();
    StringWriter err = new StringWriter();
    int exitCode =
        CryptaAppCli.execute(new PrintWriter(out, true), new PrintWriter(err, true), arguments);
    return new CliResult(exitCode, out.toString(), err.toString());
  }

  private record CliResult(int exitCode, String out, String err) {}

  private static int currentContractVersion() {
    return PlatformApiContract.current().contractVersion();
  }

  private static PlatformApiContract stableBaselineContract() {
    PlatformApiContract current = PlatformApiContract.current();
    return new PlatformApiContract(
        current.apiVersion(),
        PlatformApiContract.PLATFORM_API_STABLE_BASELINE_CONTRACT_VERSION,
        current.generatedBy(),
        current.stabilityPolicy(),
        current.stableBaseline(),
        current.capabilities(),
        current.endpoints());
  }

  private static PlatformApiBaselineRegistry proposed11Registry() {
    PlatformApiBaselineRegistry current = PlatformApiBaselineRegistry.current();
    PlatformApiBaselineDefinition stable10 = current.definitions().getFirst();
    PlatformApiBaselineDefinition candidate =
        PlatformApiBaselineDefinition.create(
            PlatformApiBaselineId.parse("1.1"),
            stable10.id(),
            stable10.capabilities(),
            stable10.endpoints(),
            "a".repeat(64),
            "b".repeat(64),
            null,
            null,
            PlatformApiContract.CURRENT_CONTRACT_VERSION);
    PlatformApiBaselineLineage proposed =
        PlatformApiBaselineLineage.create(
            candidate.id(),
            candidate.definitionDigest(),
            PlatformApiBaselineStatus.PROPOSED,
            PlatformApiBaselineEvidenceKind.FIXTURE,
            "c".repeat(64),
            null,
            null,
            null,
            null,
            null);
    List<PlatformApiBaselineDefinition> definitions = new ArrayList<>(current.definitions());
    definitions.add(candidate);
    List<PlatformApiBaselineLineage> lineage = new ArrayList<>(current.lineage());
    lineage.add(proposed);
    return PlatformApiBaselineRegistry.create(definitions, lineage);
  }
}
