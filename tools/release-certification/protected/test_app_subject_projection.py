import importlib.util
import io
from pathlib import Path
import sys
import unittest
import zipfile
import copy
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from app_subject_projection import AuthenticatedProjection, ProjectionFailure, selected_members, validate_declaration
from original_artifact_authentication import AuthenticationError, OriginalArtifact, validate_coordinates
from sharesite_observation import MigrationFailure, validate_stage
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cryptad_certification.engines import stable_platform_api_1x as api1x
from app_subject_projection import _VERIFIED, FIRST_PARTY
from sharesite_observation import AuthenticatedMigration, CHECKS, validate_observation
import sharesite_observation
from cryptad_certification.engines import stable_legacy_plugin_migration as migration


class ProjectionBoundaryTest(unittest.TestCase):
    def test_selected_cohort_rejects_world_readable_policy_before_using_private_roster(self):
        import app_subject_projection as projection
        for version, mode, expected in ((2, 0o100644, "private-cohort-unavailable"),
                                        (2, 0o100640, "protected-cohort-invalid"),
                                        (1, 0o100644, "protected-cohort-invalid")):
            with self.subTest(version=version, mode=mode):
                policy = unittest.mock.Mock()
                policy.lstat.return_value = SimpleNamespace(st_mode=mode, st_uid=0, st_size=20)
                policy.read_bytes.return_value = ('{"schemaVersion":' + str(version) + '}').encode()
                with patch.object(projection, "COHORT_FILE", policy), self.assertRaisesRegex(ProjectionFailure, expected):
                    projection._cohort()

    def inventory(self):
        roots = {key: "sha256:" + "a" * 64 for key in api1x.AUTHORITY_SCHEMAS}
        contract = {"release": {"releaseId": "synthetic-release"},
                    "repository": {"sourceCommit": "a" * 40}, "authorityRoots": roots}
        inventory = {"schemaVersion": 2, "kind": "platform-api-1.x-app-subject-inventory",
                     "releaseId": "synthetic-release", "sourceCommit": "a" * 40, "authorityRoots": roots,
                     "fixtureOnly": False, "cohortPolicy": "historical-seven", "subjects": []}
        for app in sorted(FIRST_PARTY | {"external-app"}):
            family = "third-party-pilot" if app == "external-app" else "first-party-release"
            declaration = {"schemaVersion": 1, "kind": "signed-app-subject-projection", "appId": app,
                           "appVersion": "1", "bundleSize": 100, "publisherId": "publisher", "catalogId": "catalog",
                           "catalogKeyId": "catalog-key", "reviewerId": "reviewer", "targetStability": "stable",
                           "targetBaseline": "1.0", "minimumContractVersion": 19, "maximumTestedContractVersion": 25,
                           "requiredCapabilities": ["queue.read"], "optionalCapabilities": [],
                           "experimentalCapabilitiesAccepted": False, "submissionDigest": None}
            for field in ("bundleDigest", "manifestDigest", "signedContentDigest", "signatureDigest", "publisherFingerprint",
                          "catalogDigest", "catalogSignatureDigest", "reviewDigest"):
                declaration[field] = "sha256:" + "b" * 64
            row = {key: declaration[key] for key in api1x.MATRIX_SUBJECT_FIELDS
                   if key not in {"sourceAuthority", "fixtureOnly", "requiredForRelease"}}
            row.update({"sourceAuthority": family, "fixtureOnly": False, "requiredForRelease": True,
                        "sourceAuthorityRoot": roots[api1x.MATRIX_SOURCE_ROOTS[family]],
                        "sourceEvidenceDigest": "sha256:" + "c" * 64,
                        "signedProjection": declaration, "originalSource": {"sourceFamily": family}})
            row["subjectDigest"] = api1x._semantic_digest(row, "subjectDigest")
            inventory["subjects"].append(row)
        inventory["requiredAppIds"] = sorted(row["appId"] for row in inventory["subjects"])
        inventory["inventoryDigest"] = api1x._semantic_digest(inventory, "inventoryDigest")
        return inventory, contract, {"requiredFirstPartyAppIds": sorted(FIRST_PARTY)}

    def test_tool_archive_matches_all_installed_files_and_rejects_jar_substitution(self):
        from app_subject_projection import tool_archive_digest, tree_digest
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            for name, content, mode in (("bin/crypta-app", b"synthetic launcher", 0o100755),
                                        ("lib/cli.jar", b"synthetic jar", 0o100644)):
                member = zipfile.ZipInfo("crypta-app-1/" + name)
                member.external_attr = mode << 16
                archive.writestr(member, content)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "bin").mkdir()
            (root / "lib").mkdir()
            (root / "bin/crypta-app").write_bytes(b"synthetic launcher")
            (root / "bin/crypta-app").chmod(0o755)
            (root / "lib/cli.jar").write_bytes(b"synthetic jar")
            self.assertEqual(tool_archive_digest(buffer.getvalue()), tree_digest(root))
            (root / "lib/cli.jar").write_bytes(b"substituted jar")
            self.assertNotEqual(tool_archive_digest(buffer.getvalue()), tree_digest(root))

    def test_upstream_inventory_rejects_genuine_unrelated_bundle(self):
        import app_subject_projection as projection
        declaration = self.inventory()[0]["subjects"][0]["signedProjection"]
        source = {"original": {"sourceFamily": "first-party-release"},
                  "originalInventory": {"sourceFamily": "first-party-inventory"},
                  "sourceAuthorityRoot": "sha256:" + "c" * 64,
                  "sourceEvidenceDigest": "sha256:" + "d" * 64}
        inventory = {"sourceCommit": "a" * 40, "subjectInventoryDigest": source["sourceEvidenceDigest"],
                     "subjects": [{"subjectClass": "first-party-app", "digest": declaration["bundleDigest"],
                                   "size": declaration["bundleSize"], "app": {
                                       "appId": declaration["appId"], "version": declaration["appVersion"],
                                       "manifestDigest": declaration["manifestDigest"],
                                       "bundleSignatureDigest": declaration["signatureDigest"],
                                       "reviewReceiptDigest": declaration["reviewDigest"]}}]}
        summary = {"summaryDigest": source["sourceAuthorityRoot"],
                   "subjectInventoryDigest": source["sourceEvidenceDigest"]}
        artifact = OriginalArtifact(b"unused", {"sourceCommit": "a" * 40})
        with patch.object(projection, "authenticate_original", return_value=artifact), patch.object(
                projection, "_artifact_json", side_effect=lambda original, name: inventory if "subject-inventory" in name else summary):
            projection.verify_upstream_subject(source, declaration, artifact, Path("."))
            inventory["subjects"][0]["app"]["manifestDigest"] = "sha256:" + "f" * 64
            with self.assertRaisesRegex(ProjectionFailure, "byte-substitution"):
                projection.verify_upstream_subject(source, declaration, artifact, Path("."))

    def test_v2_pure_consumer_accepts_exact_internal_authenticated_bytes(self):
        # Synthetic construction exercises policy only and never reaches the protected wrapper.
        inventory, contract, policy = self.inventory()
        authenticated = AuthenticatedProjection(inventory, "sha256:" + "d" * 64, _VERIFIED)
        self.assertEqual([], api1x._app_subject_inventory_errors(inventory, False, contract, policy, authenticated))

    def test_v2_pure_consumer_rejects_json_authentication_and_resealed_substitution(self):
        inventory, contract, policy = self.inventory()
        findings = api1x._app_subject_inventory_errors(inventory, False, contract, policy, {"verified": True})
        self.assertTrue(any("lacks original protected" in finding for finding in findings))
        authenticated = AuthenticatedProjection(inventory, "sha256:" + "d" * 64, _VERIFIED)
        inventory["subjects"][0]["requiredCapabilities"] = ["content.fetch"]
        inventory["subjects"][0]["subjectDigest"] = api1x._semantic_digest(inventory["subjects"][0], "subjectDigest")
        inventory["inventoryDigest"] = api1x._semantic_digest(inventory, "inventoryDigest")
        self.assertTrue(any("lacks original protected" in finding for finding in
                            api1x._app_subject_inventory_errors(inventory, False, contract, policy, authenticated)))

    def test_v2_pure_consumer_compares_every_manifest_declaration(self):
        inventory, contract, policy = self.inventory()
        inventory["subjects"][0]["targetBaseline"] = "1.1"
        inventory["subjects"][0]["subjectDigest"] = api1x._semantic_digest(inventory["subjects"][0], "subjectDigest")
        inventory["inventoryDigest"] = api1x._semantic_digest(inventory, "inventoryDigest")
        authenticated = AuthenticatedProjection(inventory, "sha256:" + "d" * 64, _VERIFIED)
        self.assertTrue(any("differs from the exact signed declaration" in finding for finding in
                            api1x._app_subject_inventory_errors(inventory, False, contract, policy, authenticated)))

    def test_v2_cohort_cannot_omit_external_app(self):
        inventory, contract, policy = self.inventory()
        inventory["subjects"] = [row for row in inventory["subjects"] if row["appId"] != "external-app"]
        inventory["requiredAppIds"] = sorted(FIRST_PARTY)
        inventory["inventoryDigest"] = api1x._semantic_digest(inventory, "inventoryDigest")
        authenticated = AuthenticatedProjection(inventory, "sha256:" + "d" * 64, _VERIFIED)
        self.assertTrue(any("third-party pilot app is absent" in finding for finding in
                            api1x._app_subject_inventory_errors(inventory, False, contract, policy, authenticated)))

    def test_projection_authority_cannot_be_created_from_caller_json(self):
        with self.assertRaises(ProjectionFailure):
            AuthenticatedProjection({"authenticated": True}, "sha256:" + "a" * 64)

    def artifact(self, entries):
        target = io.BytesIO()
        with zipfile.ZipFile(target, "w") as archive:
            for name, body in entries:
                archive.writestr(name, body)
        return OriginalArtifact(target.getvalue(), {})

    def test_selected_members_reject_unselected_traversal_before_reading(self):
        artifact = self.artifact([("catalog", b"a"), ("signature", b"b"), ("bundle", b"c"), ("../escape", b"d")])
        with self.assertRaises(ProjectionFailure):
            selected_members(artifact, {"catalog": "catalog", "catalogSignature": "signature", "bundle": "bundle"})

    def test_selected_members_reject_case_collisions(self):
        artifact = self.artifact([("catalog", b"a"), ("CATALOG", b"b"), ("bundle", b"c")])
        with self.assertRaises(ProjectionFailure):
            selected_members(artifact, {"catalog": "catalog", "catalogSignature": "CATALOG", "bundle": "bundle"})

    def test_selected_members_return_exact_selected_bytes(self):
        artifact = self.artifact([("catalog", b"a"), ("signature", b"b"), ("bundle", b"c")])
        self.assertEqual({"catalog": b"a", "catalogSignature": b"b", "bundle": b"c"}, selected_members(
            artifact, {"catalog": "catalog", "catalogSignature": "signature", "bundle": "bundle"}))

    def test_declaration_rejects_caller_authority_or_private_fields(self):
        with self.assertRaises(ProjectionFailure):
            validate_declaration({"schemaVersion": 1, "kind": "signed-app-subject-projection", "authenticated": True})

    def test_original_coordinates_reject_caller_workflow_override(self):
        with self.assertRaises(AuthenticationError):
            validate_coordinates({"workflow": "attacker.yml"})

    def test_stage_requires_entire_fixed_case_set(self):
        with self.assertRaises(MigrationFailure):
            validate_stage({"schemaVersion": 1, "kind": "sharesite-runtime-stage", "stage": "import",
                            "selectedCount": 1, "checks": {"importCommit": "pass"}}, "import")

    def test_stage_does_not_allow_synthetic_to_become_real_data(self):
        with self.assertRaises(MigrationFailure):
            validate_stage({"schemaVersion": 1, "kind": "sharesite-runtime-stage", "stage": "import",
                            "selectedCount": 1, "checks": {"literalFidelity": "pass", "importCommit": "pass", "replay": "pass"},
                            "realDataMigration": "pass"}, "import")

    def test_stage_rejects_failures_and_private_comparison_hashes(self):
        value = {"schemaVersion": 1, "kind": "sharesite-runtime-stage", "stage": "import",
                 "selectedCount": 1, "checks": {"literalFidelity": "fail", "importCommit": "pass", "replay": "pass"}}
        with self.assertRaises(MigrationFailure):
            validate_stage(value, "import")
        value["checks"]["literalFidelity"] = "pass"
        value["sourceSha256"] = "a" * 64
        with self.assertRaises(MigrationFailure):
            validate_stage(value, "import")


class MigrationAuthorityTest(unittest.TestCase):
    def observation(self):
        return {"schemaVersion": 2, "kind": "sharesite-runtime-observation", "classification": "upstream-writer-synthetic",
                "status": "complete", "selectedCount": 1, "outcomes": {case: "not-observed" if case == "newChkPublication" else "pass" for case in CHECKS},
                "publication": "not-observed", "realDataMigration": "not-observed", "releaseEligibility": "blocked",
                "planDigest": "sha256:" + "a" * 64, "bundleDigest": "sha256:" + "b" * 64,
                "producerTools": {key: "sha256:" + "c" * 64 for key in
                                  ("toolTreeDigest", "javaTreeDigest", "controllerDigest", "driverDigest", "nodeDigest")},
                "producer": {"sourceCommit": "a" * 40, "workflowPath": sharesite_observation.WORKFLOW,
                             "environment": "stable-1-0-sharesite-runtime-observation", "runId": 1, "runAttempt": 1}}

    def test_authenticated_synthetic_execution_never_becomes_real_user_evidence(self):
        value = self.observation()
        value["outcomes"]["newChkPublication"] = "not-observed"
        authority = AuthenticatedMigration(value, sharesite_observation._VERIFIED)
        summary = migration.summarize(value, "verify-runtime", authenticated_runtime=authority)
        self.assertEqual("authenticated-synthetic", summary["runtimeObservation"])
        self.assertEqual("not-observed", summary["realDataMigration"])
        self.assertEqual("blocked", summary["releaseEligibility"])
        self.assertFalse(summary["operationallyComplete"])

    def test_caller_pass_json_is_not_runtime_authority(self):
        value = self.observation()
        summary = migration.summarize(value, "verify-runtime", authenticated_runtime={"pass": True})
        self.assertEqual("not-authenticated", summary["runtimeObservation"])
        with self.assertRaises(MigrationFailure):
            AuthenticatedMigration(value)

    def test_authenticated_bytes_cannot_be_resealed_with_omitted_failure(self):
        value = self.observation()
        value["outcomes"]["privateRestore"] = "fail"
        value["status"] = "partial"
        authority = AuthenticatedMigration(value, sharesite_observation._VERIFIED)
        value["outcomes"]["privateRestore"] = "pass"
        self.assertEqual("not-authenticated", migration.summarize(value, "verify-runtime", authenticated_runtime=authority)["runtimeObservation"])

    def test_missing_case_blocks_even_authenticated_collection(self):
        value = self.observation()
        value["outcomes"]["quotaFailure"] = "not-observed"
        value["status"] = "partial"
        authority = AuthenticatedMigration(value, sharesite_observation._VERIFIED)
        self.assertEqual("blocked", migration.summarize(value, "verify-runtime", authenticated_runtime=authority)["status"])

    def test_public_core_rejects_source_body_hash(self):
        value = self.observation()
        del value["producer"]
        validate_observation(value)
        value["sourceBodyHash"] = "a" * 64
        with self.assertRaises(MigrationFailure):
            validate_observation(value)

    def test_complete_status_cannot_hide_unobserved_or_failed_cases(self):
        value = self.observation()
        del value["producer"]
        value["outcomes"]["quotaFailure"] = "not-observed"
        with self.assertRaisesRegex(MigrationFailure, "complete-contradicts"):
            validate_observation(value)


if __name__ == "__main__":
    unittest.main()
