"""Actual owner consumers reject synthetic promotion, case substitution and private diagnostics."""
from __future__ import annotations

import copy
import datetime as dt
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import xml.etree.ElementTree as ET
import sys
import zipfile

from cryptad_certification import phase_12_runtime_adapters as runtime
from cryptad_certification.tests.test_cross_version_evidence import (
    fixture_plan, fixture_events, checkpoint_for, rechain,
)
from cryptad_certification.tests.test_stable_legacy_plugin_migration import observation

AS_OF = "2026-09-10T12:00:00Z"


def raw(value):
    return json.dumps(value, sort_keys=True).encode()


def soak_inputs(plan=None, events=None):
    plan = plan or fixture_plan()
    if events is None:
        events, checkpoint = fixture_events(plan)
    else:
        checkpoint = checkpoint_for(plan, events)
    return {"plan.json": raw(plan), "events.json": raw(events), "checkpoint.json": raw(checkpoint)}


def migration_v2(classification="upstream-writer-synthetic"):
    digest = "sha256:" + "a" * 64
    return {"schemaVersion": 2, "kind": "sharesite-runtime-observation", "classification": classification,
            "status": "complete", "selectedCount": 1, "publication": "not-observed",
            "realDataMigration": "not-observed", "releaseEligibility": "blocked",
            "planDigest": digest, "bundleDigest": digest,
            "producer": {"sourceCommit": "a" * 40,
                         "workflowPath": ".github/workflows/stable-1.0-sharesite-runtime-observation.yml",
                         "environment": "stable-1-0-sharesite-runtime-observation", "runId": 1, "runAttempt": 1},
            "producerTools": {key: digest for key in
                              ("toolTreeDigest", "javaTreeDigest", "controllerDigest", "driverDigest", "nodeDigest")},
            "outcomes": {key: "not-observed" if key == "newChkPublication" else "pass"
                         for key in runtime.migration.CHECKS}}


def api_inputs():
    runtime._protected("app_subject_projection")
    sys.path.insert(0, str(runtime.PROTECTED))
    try:
        from test_app_subject_projection import ProjectionBoundaryTest
    finally:
        sys.path.pop(0)
    inventory, _contract, _policy = ProjectionBoundaryTest().inventory()
    contract = json.loads((runtime.ROOT / "tools/release-certification/manifests/platform-api-1.x-compatibility.example.json").read_bytes())
    contract["fixtureOnly"] = contract["selfTest"] = False
    contract["authorityRoots"] = inventory["authorityRoots"]
    contract["repository"]["sourceCommit"] = inventory["sourceCommit"]
    contract["release"]["releaseId"] = inventory["releaseId"]
    contract["policyDigest"] = runtime.api._policy(runtime.ROOT)[1]
    inventory["cohortDigest"] = "sha256:" + "c" * 64
    inventory["producer"] = {"sourceCommit": "a" * 40, "runId": 1, "runAttempt": 1,
                             "workflowPath": ".github/workflows/stable-1.0-app-subject-projection.yml",
                             "environment": "stable-1-0-app-subject-projection"}
    for row in inventory["subjects"]:
        def coordinate(family):
            return {"repository": "crypta-network/cryptad", "sourceFamily": family,
                    "sourceCommit": "a" * 40, "runId": 1, "runAttempt": 1, "jobId": 1,
                    "jobName": "synthetic-job", "artifactId": 1, "artifactName": "synthetic-artifact",
                    "artifactDigest": "sha256:" + "d" * 64, "artifactSize": 100}
        row["originalSource"] = coordinate(row["sourceAuthority"])
        row["originalInventorySource"] = coordinate("first-party-inventory" if row["sourceAuthority"] == "first-party-release" else "third-party-inventory")
        row["originalCatalogSource"] = None
        row["subjectDigest"] = runtime.api._semantic_digest(row, "subjectDigest")
    return api_seal(contract, inventory)


def api_seal(contract, inventory):
    inventory["inventoryDigest"] = runtime.api._semantic_digest(inventory, "inventoryDigest")
    blob = raw(inventory)
    contract["evidence"]["appSubjectInventory"] = {
        "fileName": "app-subject-inventory.json", "digest": "sha256:" + hashlib.sha256(blob).hexdigest(), "size": len(blob)}
    return {"execution-contract.json": raw(contract), "app-subject-inventory.json": blob}


def profile_inputs():
    """Explicitly synthetic retained reports; no tests or production producer are impersonated."""
    owner, policy = runtime.profiles, runtime._policy()
    registry = {"schemaVersion": 1, "kind": "content-format-profile-registry",
                "profiles": [{"id": name, "majorVersion": 1,
                              "status": "stable" if "feed" in name else "experimental"}
                             for name in owner.CONTENT_PROFILE_IDS]}
    inputs = {"registry.json": raw(registry)}
    manifest_path = runtime.ROOT / owner.CORPUS / "manifest.json"
    manifest = json.loads(manifest_path.read_bytes())
    javascript = {"runtime": "v24.0.0",
                  "executedCases": [case["caseId"] for case in manifest["cases"]] + policy["javascriptGroups"],
                  "skippedRequired": 0, "manifestDigest": owner.digest(manifest_path).removeprefix("sha256:"),
                  "unsupportedDirections": ["javascript-production-trust-verifier", "historical-executable-reader",
                                            "independent-external-implementation"]}
    inputs["javascript-results.json"] = raw(javascript)
    results = []
    for suite in policy["suites"]:
        tree = ET.Element("testsuite")
        for case in suite["testCases"]:
            ET.SubElement(tree, "testcase", {"name": case, "classname": suite["className"]})
        value = ET.tostring(tree)
        inputs[Path(suite["resultFile"]).name] = value
        results.append({"className": suite["className"], "caseCount": len(suite["testCases"]),
                        "resultDigest": "sha256:" + hashlib.sha256(value).hexdigest()})
    summary = {"schemaVersion": 1, "kind": "content-profile-review",
               "source": owner.source_identity(runtime.ROOT), "corpus": owner.corpus_identity(runtime.ROOT),
               "policyDigest": owner.digest(runtime.ROOT / owner.POLICY),
               "registryExactFileDigest": "sha256:" + hashlib.sha256(inputs["registry.json"]).hexdigest(),
               "profiles": owner.registry_rows(registry, policy),
               "normativeSpecDigest": owner.specification_digest(runtime.ROOT),
               "serviceDefinitionDigest": owner.service_definition_digest(runtime.ROOT),
               "serviceContracts": policy["serviceContracts"], "results": results,
               "javascript": {"runtime": javascript["runtime"], "caseCount": len(javascript["executedCases"]),
                              "resultDigest": owner.semantic_digest(javascript), "productionByteIngress": "not-observed",
                              "referenceTrustVerifier": "first-party-only"},
               "evidenceLevel": "local-executable-conformance", "reviewDecision": "retain-current-statuses",
               "independentImplementation": "not-observed", "priorRuntime": "not-observed",
               "humanSecuritySignoff": "not-observed", "operationalCloseout": "not-assessed",
               "evaluationTime": policy["evaluationTime"], "limitations": policy["limitations"], "redaction": "pass"}
    summary["integrityDigest"] = owner.semantic_digest(summary)
    inputs["review.json"] = raw(summary)
    return inputs


def qualifying_test_journal():
    """Synthetic original-authority fixture; fake time remains in this test module only."""
    plan = fixture_plan()
    plan.update(profile="protected-long-live", provenanceClass="production-artifact-comparison",
                requestedSeconds=400000, probeIntervalSeconds=299)
    plan["policy"].update(minimumObservedSeconds=72 * 3600, maxGapSeconds=600, maxEvents=20000)
    original, _ = fixture_events(plan)
    first = next(i for i, event in enumerate(original) if event["kind"] == "probe")
    last = next(i for i, event in enumerate(original) if event["kind"] == "node-stop")
    events = copy.deepcopy(original[:first + 1])
    for run in range(16):
        segment = copy.deepcopy(original[first + 1:last])
        for event in segment:
            if event["kind"] == "operation":
                event["operation"] += "-cycle-" + str(run)
        events.extend(segment)
    events.extend(copy.deepcopy(original[last:]))
    clock = operations = 0
    start = dt.datetime(2026, 9, 6, tzinfo=dt.timezone.utc)
    for event in events:
        event["monotonicNs"] = clock * 299 * 1000000000
        event["wallTime"] = (start + dt.timedelta(seconds=clock * 299)).isoformat()
        if event["kind"] == "operation":
            operations += 1
        if event["kind"] == "probe":
            event["counters"]["operations"] = operations
        if event["kind"] != "sample":
            clock += 1
    rechain(events)
    return plan, events, checkpoint_for(plan, events)


def supervisor_fixture(plan, events, checkpoint):
    """Issue an internal test capability without an online or production entrypoint."""
    owner = runtime._protected("cross_version_supervisor_authority")
    common = {"schemaVersion": 1, "kind": "cryptad-cross-version-supervisor", "experimentId": plan["experimentId"],
              "planDigest": runtime.soak.digest(plan), "producer": plan["producer"],
              "purpose": "nonrelease-observed-experiment", "releaseEligible": False,
              "selectionDigest": "sha256:" + "a" * 64}
    origin1, origin2, origin3 = ({"runId": i, "runAttempt": 1, "artifactId": i} for i in (1, 2, 3))
    authorize = {**common, "operation": "authorize", "job": {"runId": 1},
                 "approvedBounds": {"maxSeconds": 400000}, "plan": plan, "serviceDigest": "sha256:" + "a" * 64}
    start = {**common, "operation": "start", "job": {"runId": 2}, "previousOrigin": origin1,
             "previousReportDigest": runtime.soak.digest(authorize), "serviceState": "running",
             "approvalOrigin": origin1, "approvalReportDigest": runtime.soak.digest(authorize)}
    final = {**common, "operation": "finish", "job": {"runId": 3}, "previousOrigin": origin2,
             "previousReportDigest": runtime.soak.digest(start), "serviceState": "stopped",
             "approvalOrigin": origin1, "approvalReportDigest": runtime.soak.digest(authorize),
             "checkpoint": {"sequence": checkpoint["sequence"], "tailDigest": checkpoint["tailDigest"],
                            "digest": runtime.soak.digest(checkpoint), "status": checkpoint["status"]},
             "observation": runtime.soak.verify(plan, events, checkpoint, now=dt.datetime.fromisoformat(AS_OF))}
    for report in (authorize, start, final):
        owner.validate_report(report)
    return [{"report": final, "origin": origin3}, {"report": start, "origin": origin2},
            {"report": authorize, "origin": origin1}]


class Phase12RuntimeAdapterTest(unittest.TestCase):
    def run_adapter(self, adapter, payloads):
        with tempfile.TemporaryDirectory() as temporary:
            with mock.patch("socket.create_connection", side_effect=AssertionError("network forbidden")):
                return runtime.verify(adapter, payloads, AS_OF, Path(temporary).resolve())

    def test_complete_fake_clock_journal_does_not_supply_live_hours(self):
        result = self.run_adapter("measured-soak", soak_inputs())
        self.assertEqual("executed-pass", result["dimensions"]["localVerification"])
        self.assertGreater(result["measurements"]["locallyVerifiedEligibleSeconds"], 0)
        self.assertEqual(0, result["measurements"]["authenticatedObservedSeconds"])
        self.assertEqual([], result["coverage"]["observed"])
        self.assertIn("qualifying-72h-protected-profile-required", result["blockers"])

    def test_required_direction_omission_and_replay_fail_owner_coverage(self):
        plan = fixture_plan()
        events, _ = fixture_events(plan)
        for mutation in ("omit", "replay", "future"):
            changed = copy.deepcopy(events)
            if mutation == "omit":
                changed = [event for event in changed if event["scenario"] != "mail-delivery"]
            elif mutation == "replay":
                operations = [event for event in changed if event["kind"] == "operation"]
                operations[1]["operation"] = operations[0]["operation"]
            else:
                changed[-1]["wallTime"] = "2027-01-01T00:00:00Z"
            rechain(changed)
            with self.subTest(mutation=mutation):
                result = self.run_adapter("measured-soak", soak_inputs(plan, changed))
                self.assertEqual("executed-fail", result["dimensions"]["localVerification"])
                self.assertEqual("not-observed", result["dimensions"]["runtimeExecution"])

    def test_shortened_profile_and_shrunken_scenarios_reject(self):
        for field in ("duration", "scenarios"):
            plan = fixture_plan()
            if field == "duration":
                plan["profile"] = "protected-long-live"
            else:
                plan["requiredScenarios"].pop()
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.run_adapter("measured-soak", soak_inputs(plan))

    def test_mail_runtime_cannot_infer_rotation_resume_or_independent_review(self):
        result = self.run_adapter("mail-runtime", soak_inputs())
        self.assertIn("mail-rotation-and-resume-unimplemented", result["blockers"])
        self.assertIn("mail-independent-review-not-observed", result["blockers"])
        self.assertTrue(all(case.startswith("mail-") for case in result["coverage"]["required"]))

    def test_all_fourteen_reported_drill_cases_retain_partial_and_unverified(self):
        record = runtime.drill.plan()
        record.update(status="executed", observedCases=list(runtime.drill.CASES), cleanup="owned-synthetic-state-removed")
        result = self.run_adapter("maintenance-drill", {"drill.json": raw(runtime.drill._seal(record))})
        self.assertEqual(14, len(result["coverage"]["required"]))
        self.assertEqual("partial", result["dimensions"]["implementation"])
        self.assertEqual("unverified", result["dimensions"]["originalProvenance"])
        self.assertEqual("author-reported", result["testEvidence"])
        self.assertEqual("not-performed", result["dimensions"]["activation"])

    def test_drill_source_drift_and_case_erasure_reject(self):
        record = runtime.drill.plan()
        for key, value in (("missingCoverage", []), ("helperFileDigests", {})):
            changed = {**record, key: value}
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.run_adapter("maintenance-drill", {"drill.json": raw(runtime.drill._seal(changed))})

    def test_migration_synthetic_private_and_local_claims_stay_distinct(self):
        for value in (observation(), migration_v2(), migration_v2("operator-owned-private-observation")):
            with self.subTest(classification=value["classification"]):
                result = self.run_adapter("migration-observation", {"observation.json": raw(value)})
                self.assertEqual(value["classification"], result["evidenceClass"])
                self.assertIn("migration-real-user-not-observed", result["blockers"])
                self.assertEqual("not-observed", result["dimensions"]["publication"])
                self.assertEqual([], result["coverage"]["observed"])

    def test_wrong_migration_producer_and_forged_publication_are_invalid(self):
        for field in ("workflow", "environment", "publication", "private-canary"):
            value = migration_v2()
            if field == "workflow":
                value["producer"]["workflowPath"] = ".github/workflows/reupload.yml"
            elif field == "environment":
                value["producer"]["environment"] = "wrong-environment"
            else:
                value[field] = "private-path /home/contact-secret"
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "^phase12-runtime-owner-verification-rejected$"):
                self.run_adapter("migration-observation", {"observation.json": raw(value)})

    def test_original_measurements_reuse_case_verifier_without_erasing_owner_gaps(self):
        inputs = soak_inputs()
        inputs["products.json"] = b"[]"
        result = self.run_adapter("maintenance-measurements", inputs)
        self.assertEqual(9, len(result["coverage"]["required"]))
        self.assertEqual([], result["coverage"]["observed"])
        self.assertIn("maintenance-required-consumer-adapters-incomplete", result["blockers"])

    def test_api_declaration_consistency_is_admitted_without_manufacturing_authentication(self):
        result = self.run_adapter("api-subjects-v2", api_inputs())
        self.assertEqual("executed-pass", result["dimensions"]["localVerification"])
        self.assertIn("original-protected-projection-required", result["blockers"])
        self.assertIn("current-mail-subject-cohort-not-covered", result["blockers"])

    def test_api_resealed_subject_cohort_and_wrong_original_repository_reject(self):
        for mutation in ("declaration", "cohort", "repository"):
            inputs = api_inputs()
            contract = json.loads(inputs["execution-contract.json"])
            inventory = json.loads(inputs["app-subject-inventory.json"])
            if mutation == "declaration":
                inventory["subjects"][0]["minimumContractVersion"] += 1
                inventory["subjects"][0]["subjectDigest"] = runtime.api._semantic_digest(inventory["subjects"][0], "subjectDigest")
            elif mutation == "cohort":
                dropped = inventory["subjects"].pop()
                inventory["requiredAppIds"].remove(dropped["appId"])
            else:
                inventory["subjects"][0]["originalSource"]["repository"] = "attacker/reupload"
                inventory["subjects"][0]["subjectDigest"] = runtime.api._semantic_digest(inventory["subjects"][0], "subjectDigest")
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.run_adapter("api-subjects-v2", api_seal(contract, inventory))

    def test_input_cohort_duplicate_keys_nesting_and_sidecars_reject_without_echo(self):
        cases = ({"observation.json": b'{"private":1,"private":2}'},
                 {"observation.json": b"[" * 100 + b"0" + b"]" * 100},
                 {"observation.json": raw(observation()), "private-key.json": b"private-key-canary"})
        for inputs in cases:
            with self.assertRaisesRegex(ValueError, "^phase12-runtime-owner-verification-rejected$"):
                self.run_adapter("migration-observation", inputs)

    def test_output_is_deterministic_across_independent_scratch_roots(self):
        self.assertEqual(self.run_adapter("measured-soak", soak_inputs()),
                         self.run_adapter("measured-soak", soak_inputs()))

    def test_profile_retention_and_raw_results_are_checked_without_claiming_execution(self):
        identity = {"commit": "a" * 40, "implementationDigest": "sha256:" + "b" * 64}
        with mock.patch.object(runtime.profiles, "source_identity", return_value=identity):
            inputs = profile_inputs()
            result = self.run_adapter("profile-review", inputs)
        self.assertEqual(["p12-298-review"], result["claims"])
        self.assertEqual("executed-pass", result["dimensions"]["localVerification"])
        self.assertEqual("author-reported", result["testEvidence"])
        self.assertIn("profile-independent-implementation-not-observed", result["blockers"])

    def test_profile_skips_resealed_maturity_change_and_source_drift_reject(self):
        identity = {"commit": "a" * 40, "implementationDigest": "sha256:" + "b" * 64}
        with mock.patch.object(runtime.profiles, "source_identity", return_value=identity):
            inputs = profile_inputs()
            for mutation in ("skip", "maturity", "source", "entity"):
                changed = dict(inputs)
                summary = json.loads(changed["review.json"])
                first_xml = next(name for name in changed if name.endswith(".xml"))
                if mutation == "skip":
                    tree = ET.fromstring(changed[first_xml])
                    ET.SubElement(tree.find("testcase"), "skipped")
                    changed[first_xml] = ET.tostring(tree)
                elif mutation == "entity":
                    changed[first_xml] = b'<!DOCTYPE x [<!ENTITY private "private-path-canary">]><testsuite/>'
                elif mutation == "maturity":
                    registry = json.loads(changed["registry.json"])
                    registry["profiles"][0]["status"] = "stable"
                    changed["registry.json"] = raw(registry)
                    summary["registryExactFileDigest"] = "sha256:" + hashlib.sha256(changed["registry.json"]).hexdigest()
                else:
                    summary["source"]["implementationDigest"] = "sha256:" + "c" * 64
                summary.pop("integrityDigest")
                summary["integrityDigest"] = runtime.profiles.semantic_digest(summary)
                changed["review.json"] = raw(summary)
                with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, "^phase12-runtime-owner-verification-rejected$"):
                    self.run_adapter("profile-review", changed)

    def test_actual_projection_capability_admits_same_bytes_and_rejects_json_flags(self):
        owner = runtime._protected("app_subject_projection")
        inputs = api_inputs()
        inventory = json.loads(inputs["app-subject-inventory.json"])
        authority = owner.AuthenticatedProjection(inventory,
                    "sha256:" + hashlib.sha256(inputs["app-subject-inventory.json"]).hexdigest(), owner._VERIFIED)
        with tempfile.TemporaryDirectory() as temporary:
            result = runtime.verify_authenticated("api-subjects-v2", inputs, AS_OF, Path(temporary).resolve(strict=True), authority)
            self.assertEqual("authenticated", result["dimensions"]["originalProvenance"])
            self.assertEqual("observed", result["dimensions"]["runtimeExecution"])
            for invalid in ({"authenticated": True}, owner.AuthenticatedProjection(
                    inventory, "sha256:" + "f" * 64, owner._VERIFIED)):
                with self.assertRaises(ValueError):
                    runtime.verify_authenticated("api-subjects-v2", inputs, AS_OF, Path(temporary).resolve(strict=True), invalid)
        self.assertEqual("unverified", self.run_adapter("api-subjects-v2", inputs)["dimensions"]["originalProvenance"])

    def test_authenticated_migration_scopes_private_confirmation_and_publication_separately(self):
        owner = runtime._protected("sharesite_observation")
        for classification in ("upstream-writer-synthetic", "operator-owned-private-observation"):
            record = migration_v2(classification)
            inputs = {"observation.json": raw(record)}
            authority = owner.AuthenticatedMigration(record, owner._VERIFIED)
            with tempfile.TemporaryDirectory() as temporary:
                result = runtime.verify_authenticated("migration-observation", inputs, AS_OF, Path(temporary).resolve(strict=True), authority)
            self.assertEqual(classification == "operator-owned-private-observation", "p12-297-private" in result["claims"])
            self.assertNotIn("p12-297-confirmation", result["claims"])
            self.assertNotIn("p12-297-publication", result["claims"])
            self.assertEqual("observed", result["claimResults"]["p12-297-recovery"]["dimensions"]["runtimeExecution"])

    def test_authenticated_supervisor_requires_original_lineage_and_derives_72h(self):
        plan, events, checkpoint = qualifying_test_journal()
        inputs = soak_inputs(plan, events)
        chain = supervisor_fixture(plan, events, checkpoint)
        authority = runtime._AuthenticatedSupervisor(chain, runtime._ORIGINAL_SUPERVISOR)
        with tempfile.TemporaryDirectory() as temporary:
            result = runtime.verify_authenticated("measured-soak", inputs, AS_OF, Path(temporary).resolve(strict=True), authority)
            self.assertEqual("observed", result["dimensions"]["runtimeExecution"])
            self.assertEqual("complete", result["dimensions"]["coverage"])
            self.assertEqual([], result["blockers"])
            self.assertGreaterEqual(result["measurements"]["authenticatedObservedSeconds"], 72 * 3600)
            changed = copy.deepcopy(chain)
            changed[0]["report"]["previousOrigin"] = changed[-1]["origin"]
            with self.assertRaises(ValueError):
                runtime.verify_authenticated("measured-soak", inputs, AS_OF, Path(temporary).resolve(strict=True),
                    runtime._AuthenticatedSupervisor(changed, runtime._ORIGINAL_SUPERVISOR))
            with self.assertRaises(ValueError):
                runtime.verify_authenticated("measured-soak", inputs, AS_OF, Path(temporary).resolve(strict=True), {"verified": True})
        # Identical serialized test data entering ordinary production/offline verification has
        # no access to that test-only authority object and contributes zero authenticated hours.
        self.assertEqual(0, self.run_adapter("measured-soak", inputs)["measurements"]["authenticatedObservedSeconds"])

    def test_api_complete_fixture_reruns_history_engine_and_rejects_snapshot_drift(self):
        from cryptad_certification.tests.test_stable_platform_api_1x import Api1xFixture
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Api1xFixture(Path(temporary).resolve(strict=True))
            fixture.contract["evaluationTime"] = AS_OF
            def bundle():
                content = io.BytesIO()
                with zipfile.ZipFile(content, "w") as archive:
                    for path in sorted(fixture.evidence.iterdir()):
                        archive.writestr(path.name, path.read_bytes())
                return {"execution-contract.json": raw(fixture.contract), "evidence.zip": content.getvalue()}
            result = self.run_adapter("api-compatibility", bundle())
            self.assertEqual("executed-pass", result["claimResults"]["p12-296-baseline"]["dimensions"]["localVerification"])
            self.assertEqual("synthetic-rehearsal", result["evidenceClass"])
            fixture.snapshot23.write_bytes(fixture.snapshot23.read_bytes() + b" ")
            rejected = self.run_adapter("api-compatibility", bundle())
            self.assertEqual("executed-fail", rejected["claimResults"]["p12-296-baseline"]["dimensions"]["localVerification"])

    def test_api_archive_links_and_unselected_scripts_reject_before_engine(self):
        contract = (runtime.ROOT / "tools/release-certification/manifests/platform-api-1.x-compatibility.example.json").read_bytes()
        value = json.loads(contract)
        value["evaluationTime"] = AS_OF
        for name in ("../private.json", "script.py", "Private.json", "link.json"):
            content = io.BytesIO()
            with zipfile.ZipFile(content, "w") as archive:
                if name == "Private.json":
                    archive.writestr("private.json", b"{}")
                member = zipfile.ZipInfo(name)
                if name == "link.json":
                    member.external_attr = 0o120777 << 16
                archive.writestr(member, b"{}")
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.run_adapter("api-compatibility", {"execution-contract.json": raw(value), "evidence.zip": content.getvalue()})

    def proof(self, adapter):
        runtime._protected("app_subject_projection")
        from original_artifact_authentication import PRODUCERS
        family = "app-subject-projection" if adapter == "api-subjects-v2" else "sharesite-runtime"
        return {"coordinates": {"repository": "crypta-network/cryptad", "sourceFamily": family,
                 "sourceCommit": "a" * 40, "runId": 1, "runAttempt": 1, "jobId": 1,
                 "jobName": PRODUCERS[family][2], "artifactId": 1, "artifactName": "synthetic-test-artifact",
                 "artifactDigest": "sha256:" + "a" * 64, "artifactSize": 100},
                "members": dict(runtime.ORIGINAL_MEMBERS[adapter])}

    def test_collection_calls_original_owner_and_offline_never_calls_collector(self):
        owner = runtime._protected("app_subject_projection")
        inputs = api_inputs()
        record = json.loads(inputs["app-subject-inventory.json"])
        authority = owner.AuthenticatedProjection(record,
            "sha256:" + hashlib.sha256(inputs["app-subject-inventory.json"]).hexdigest(), owner._VERIFIED)
        proof = self.proof("api-subjects-v2")
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(owner, "authenticate_inventory", return_value=authority) as collect:
            self.run_adapter("api-subjects-v2", inputs)
            runtime.validate_proof("api-subjects-v2", proof, inputs)
            collect.assert_not_called()
            result = runtime.collect_and_verify("api-subjects-v2", inputs, AS_OF, Path(temporary).resolve(strict=True), proof)
            collect.assert_called_once()
            self.assertEqual("authenticated", result["originalProof"]["state"])
            invalid = copy.deepcopy(proof)
            invalid["coordinates"]["jobName"] = "arbitrary-reupload"
            with self.assertRaises(ValueError):
                runtime.collect_and_verify("api-subjects-v2", inputs, AS_OF, Path(temporary).resolve(strict=True), invalid)
            collect.assert_called_once()

    def test_migration_semantic_equivalence_cannot_replace_exact_original_bytes(self):
        owner = runtime._protected("sharesite_observation")
        from original_artifact_authentication import OriginalArtifact
        record = migration_v2()
        inputs = {"observation.json": raw(record)}
        content = io.BytesIO()
        with zipfile.ZipFile(content, "w") as archive:
            archive.writestr("sharesite-runtime-observation.json", raw(record) + b" ")
        proof = self.proof("migration-observation")
        original = OriginalArtifact(content.getvalue(), proof["coordinates"])
        with tempfile.TemporaryDirectory() as temporary, mock.patch(
                "original_artifact_authentication.authenticate_original", return_value=original), mock.patch.object(
                owner, "authenticate_observation", side_effect=AssertionError("must not authenticate substituted member")):
            with self.assertRaises(ValueError):
                runtime.collect_and_verify("migration-observation", inputs, AS_OF, Path(temporary).resolve(strict=True), proof)

    def product_coordinates(self, original, family):
        from original_artifact_authentication import PRODUCERS
        return {"artifactName": "synthetic-portable-artifact", **original.coordinates,
                "repository": "crypta-network/cryptad", "sourceFamily": family,
                "jobId": 1, "jobName": PRODUCERS[family][2], "artifactId": 1,
                "artifactDigest": "sha256:" + hashlib.sha256(original.content).hexdigest(),
                "artifactSize": len(original.content)}

    def test_product_roots_verify_original_frozen_assets_without_claiming_app_api_binding(self):
        from cryptad_certification.tests.test_cross_version_product_admission import CrossVersionProductAdmissionTest
        original, node, freeze_digest = CrossVersionProductAdmissionTest().maintenance_fixture()
        selection = {"node": node, "freezeDigest": freeze_digest,
                     "original": self.product_coordinates(original, "stable-maintenance-freeze")}
        payloads = {"selection.json": raw(selection), "product.zip": original.content}
        result = self.run_adapter("product-admission", payloads)
        self.assertEqual(node["artifactDigest"], result["subjectBindings"]["digest"])
        self.assertEqual("not-established", result["productBinding"]["appContractAuthentication"])
        self.assertEqual("unverified", result["dimensions"]["originalProvenance"])
        selection["node"]["artifactDigest"] = "sha256:" + "f" * 64
        with self.assertRaises(ValueError):
            self.run_adapter("product-admission", {**payloads, "selection.json": raw(selection)})

    def test_rc_portable_root_reuses_both_owners_and_keeps_post_freeze_gap(self):
        from cryptad_certification.tests.test_cross_version_product_admission import CrossVersionProductAdmissionTest
        fixture = CrossVersionProductAdmissionTest()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(strict=True)
            original = fixture.rc(root)
            selected = runtime._protected("cross_version_product_admission").verify_rc_artifact(original, root / "selected")
            portable, node, _payload = fixture.portable(selected)
            node["appDigests"] = []
            selection = {"node": node, "rcOriginal": self.product_coordinates(original, "stable-rc-product"),
                         "portableOriginal": self.product_coordinates(portable, "first-party-release")}
            result = self.run_adapter("rc-product-admission", {
                "selection.json": raw(selection), "rc.zip": original.content, "portable.zip": portable.content})
        self.assertEqual("284", result["subjectBindings"]["build"])
        self.assertIn("rc-portable-post-freeze-binding-not-established", result["blockers"])

    def test_product_collection_reuses_owner_without_treating_archive_as_json(self):
        from cryptad_certification.tests.test_cross_version_product_admission import CrossVersionProductAdmissionTest
        original, node, freeze_digest = CrossVersionProductAdmissionTest().maintenance_fixture()
        selection = {"node": node, "freezeDigest": freeze_digest,
                     "original": self.product_coordinates(original, "stable-maintenance-freeze")}
        inputs = {"selection.json": raw(selection), "product.zip": original.content}
        proof = {"coordinates": selection["original"], "members": runtime.ORIGINAL_MEMBERS["product-admission"]}
        owner = runtime._protected("cross_version_product_admission")
        row = {"sourceCommit": node["sourceCommit"], "artifactDigest": node["artifactDigest"], "buildVersion": "301"}
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(owner, "authenticate_maintenance_product", return_value=row) as collect:
            self.assertEqual("unverified", runtime.validate_proof("product-admission", proof, inputs)["state"])
            result = runtime.collect_and_verify("product-admission", inputs, AS_OF, Path(temporary).resolve(strict=True), proof)
            collect.assert_called_once()
        self.assertEqual("authenticated", result["originalProof"]["state"])
        self.assertEqual("not-established", result["productBinding"]["appContractAuthentication"])
        from original_artifact_authentication import AuthenticationError
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(owner, "authenticate_maintenance_product",
                side_effect=AuthenticationError("original-artifact-leumor-authentication-unavailable")):
            result = runtime.collect_and_verify("product-admission", inputs, AS_OF, Path(temporary).resolve(strict=True), proof)
        self.assertEqual("unverified", result["originalProof"]["state"])
        self.assertIn("original-producer-authentication-access-unavailable", result["blockers"])
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(owner, "authenticate_maintenance_product",
                side_effect=AuthenticationError("original-artifact-byte-mismatch")):
            with self.assertRaisesRegex(ValueError, "runtime-original-collection-rejected"):
                runtime.collect_and_verify("product-admission", inputs, AS_OF, Path(temporary).resolve(strict=True), proof)


if __name__ == "__main__":
    unittest.main()
