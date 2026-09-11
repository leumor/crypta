"""Behavioral closeout tests; synthetic authority never crosses the production boundary."""
from __future__ import annotations

import copy
import io
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from cryptad_certification import phase_12_closeout as audit
from cryptad_certification import phase_12_provenance as provenance
from cryptad_certification import maintenance_drill_command as drill
from cryptad_certification import transparency_sources as sources
from cryptad_certification.transparency_bundle import canonical, digest

AS_OF = "2026-09-11T00:00:00Z"


class CloseoutTest(unittest.TestCase):
    def test_pr304_successor_preserves_mandatory_scope_and_historical_clocks(self):
        prior = json.loads((audit.ROOT / "tools/release-certification/history/phase-12-acceptance-policy-pr303.json").read_bytes())
        current, _ = audit.policy()
        self.assertEqual(1, prior["version"])
        self.assertEqual(2, current["version"])
        before = {row["id"]: row for row in prior["requirements"]}
        after = {row["id"]: row for row in current["requirements"]}
        self.assertEqual(set(before), set(after))
        for identity in before:
            for field in ("assertion", "dimensions", "subjects", "prerequisites", "mandatory", "closure"):
                self.assertEqual(before[identity][field], after[identity][field], (identity, field))
            self.assertEqual(set(before[identity]["authority"]), set(after[identity]["authority"]))
        for historical in prior["history"]:
            self.assertIn(historical, current["history"])
        residuals = {row["id"]: row for row in current["residuals"]}
        for old in prior["residuals"]:
            self.assertEqual(old["origin"], residuals[old["id"]]["origin"])
            self.assertEqual(old["reason"], residuals[old["id"]]["reason"])
        self.assertEqual("partial", after["p12-300-consumers"]["implementation"]["state"])
        self.assertFalse(self.evaluate()["phaseComplete"])

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve(strict=True)
        self.rules, self.pin = audit.policy()
        self.selection = audit.repository_selection()

    def evaluate(self, selection=None, root=None):
        with patch("socket.socket", side_effect=AssertionError("offline network denied")):
            return audit.evaluate(selection or self.selection, root, AS_OF)

    def attach(self, adapter, payloads, *, kind=None, subject=None):
        root = self.root / "inputs"
        directory = root / "selected"
        directory.mkdir(parents=True)
        members = []
        for name, raw in payloads.items():
            (directory / name).write_bytes(raw)
            members.append({"name": name, "digest": digest(raw), "size": len(raw)})
        source = audit.checkout()
        kind = kind or sorted(audit.ADAPTER_KINDS.get(adapter, {"authority-record"}))[0]
        self.selection["artifacts"] = [{"id": "selected", "adapter": adapter, "files": members,
            "subject": subject or {"kind": kind, "commit": source["commit"], "tree": source["tree"],
                                   "build": None, "digest": digest(b"test-local-subject")},
            "predecessors": [], "proof": None, "observedAt": None, "expiresAt": None}]
        return root

    def test_internal_scratch_resolves_symlink_temp_ancestor_for_offline_and_collection(self):
        from cryptad_certification import phase_12_authority_context as native
        from cryptad_certification.tests import test_phase_12_authority_context as fixtures
        target = self.root / "real-temp"
        target.mkdir()
        alias = self.root / "temp-alias"
        alias.symlink_to(target, target_is_directory=True)
        payloads = {"authority.json": fixtures.encoded(fixtures.catalog._manifest()),
                    "evidence.zip": fixtures.archive({})}
        root = self.attach("catalog-closeout", payloads)
        original_verify = native.verify
        for collect in (False, True):
            checked = []
            def verify_scratch(adapter, inputs, as_of, scratch, proof=None):
                self.assertEqual(scratch.resolve(strict=True), scratch)
                self.assertTrue(scratch.is_relative_to(target))
                # Execute the actual confined owner verifier; no synthetic authentication.
                result = original_verify(adapter, inputs, as_of, scratch)
                checked.append(result)
                return result
            # Isolate dispatch to exercise both scratch handoffs with the same real owner verifier.
            with self.subTest(collect=collect), patch.object(tempfile, "tempdir", str(alias)), \
                 patch.object(native, "ORIGINAL_ADAPTERS", native.ORIGINAL_ADAPTERS | {"catalog-closeout"}), \
                 patch.object(native, "collect_and_verify" if collect else "verify", side_effect=verify_scratch), \
                 patch("socket.socket", side_effect=AssertionError("network forbidden")):
                result = audit.evaluate(self.selection, root, "2026-08-22T05:00:00Z", collect_original=collect)
            self.assertEqual(1, len(checked))
            self.assertEqual("complete", checked[0]["claimResults"]["p12-293-drills"]["dimensions"]["coverage"])
            # The real fixture remains synthetic at the assessment boundary.
            self.assertFalse(result["phaseComplete"])
            self.assertEqual("failed", result["subjects"][0]["verification"])
        self.assertEqual([], list(target.iterdir()))

    def test_caller_evidence_symlink_ancestor_is_still_rejected(self):
        from cryptad_certification.tests import test_phase_12_authority_context as fixtures
        root = self.attach("catalog-closeout", {"authority.json": fixtures.encoded(fixtures.catalog._manifest()),
                                               "evidence.zip": fixtures.archive({})})
        alias = self.root / "caller-alias"
        alias.symlink_to(root, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "path-link-denied"):
            self.evaluate(root=alias)

    def test_inventory_all_domains_and_original_residuals(self):
        self.assertEqual({f"PR-{i}" for i in range(291, 304)}, {r["pr"] for r in self.rules["requirements"]})
        original = json.loads((audit.ROOT / "tools/ecosystem-transparency/repository-status.json").read_bytes())
        residuals = {r["id"]: r for r in self.rules["residuals"]}
        for old in original["obligations"]:
            self.assertIn(old["id"], residuals)
            self.assertEqual(original["asOf"], residuals[old["id"]]["origin"]["asOf"])

    def test_missing_extra_duplicate_and_policy_shrinkage_rejected(self):
        for mutation in (lambda s: s["requirementIds"].pop(),
                         lambda s: s["requirementIds"].append("p12-304-unapproved"),
                         lambda s: s["requirementIds"].append(s["requirementIds"][0]),
                         lambda s: s.update(policyDigest=digest(b"weaker policy")),
                         lambda s: s.update(waiver="all-experimental")):
            selected = copy.deepcopy(self.selection)
            mutation(selected)
            with self.assertRaises(ValueError):
                self.evaluate(selected)

    def test_repository_selection_is_honestly_incomplete(self):
        result = self.evaluate()
        self.assertTrue(result["auditExecuted"])
        self.assertEqual("verified-local-consistency", result["assessmentIntegrity"])
        self.assertFalse(result["phaseComplete"])
        self.assertEqual("incomplete", result["phaseDecision"])
        rows = {r["id"]: r for r in result["requirements"]}
        self.assertIn(rows["p12-301-lifecycle"]["dimensions"]["implementation"], {"missing", "partial"})
        self.assertEqual("not-observed", rows["p12-300-72h"]["dimensions"]["runtimeExecution"])
        self.assertEqual("not-observed", rows["p12-302-deployment"]["dimensions"]["publication"])

    def test_inventory_itself_cannot_shrink_dimensions_subjects_or_requirements(self):
        original_read = audit.read_file
        for mutation in (lambda p: p["requirements"].pop(),
                         lambda p: p["requirements"][0]["dimensions"].pop(),
                         lambda p: p["requirements"][0]["subjects"].pop(),
                         lambda p: p["requirements"][0].update(mandatory=False),
                         lambda p: p["requirements"][0]["authority"].update(adapter="transparency-bundle"),
                         lambda p: p["requirements"][0]["authority"].update(verifier="caller_verdict"),
                         lambda p: p["requirements"][0]["implementation"]["sourceEvidence"].pop(),
                         lambda p: p["requirements"][0]["implementation"]["testEvidence"].pop(),
                         lambda p: p["residuals"].pop(),
                         lambda p: p["residuals"][0]["origin"].update(asOf="2026-09-10T23:59:59Z"),
                         lambda p: p["residuals"][0].update(status="approved-limitation"),
                         lambda p: p["history"].pop()):
            weakened = copy.deepcopy(self.rules)
            mutation(weakened)
            def read(path):
                return canonical(weakened) if Path(path) == audit.POLICY else original_read(path)
            with patch.object(audit, "read_file", side_effect=read):
                with self.assertRaisesRegex(ValueError, "unreviewed-acceptance-scope"):
                    audit.policy()

    def test_forward_product_dependencies_propagate_before_dependent_decisions(self):
        isolated = copy.deepcopy(self.rules)
        delivery = next(row for row in isolated["requirements"] if row["id"] == "p12-299-delivery")
        delivery["prerequisites"] = ["p12-300-products"]
        with patch.object(audit, "policy", return_value=(isolated, self.pin)), \
                patch.object(audit, "implementation", return_value=("implemented", [])):
            result = self.evaluate()
        rows = {row["id"]: row for row in result["requirements"]}
        self.assertIn("p12-300-products", rows["p12-299-delivery"]["prerequisites"])
        self.assertIn("prerequisite-incomplete", rows["p12-299-delivery"]["blockers"])

    def test_owner_semantics_execute_but_empty_site_does_not_close_phase(self):
        selection = {"schemaVersion": 1, "mode": "production", "asOf": AS_OF, "sources": []}
        package = sources.collect(selection, self.root)
        root = self.attach("transparency-sources", {"source-package.json": canonical(package)})
        result = self.evaluate(root=root)
        self.assertEqual("executed-pass", result["subjects"][0]["verification"])
        self.assertFalse(result["phaseComplete"])
        rows = {r["id"]: r for r in result["requirements"]}
        self.assertEqual("executed-pass", rows["p12-302-admission"]["dimensions"]["localVerification"])
        self.assertNotEqual("published", rows["p12-302-deployment"]["dimensions"]["publication"])

    def test_self_resealed_fourteen_case_receipt_is_not_executed_producer(self):
        record = drill.plan()
        record.update(status="executed", observedCases=list(drill.CASES), cleanup="owned-synthetic-state-removed")
        record = drill._seal(record)
        root = self.attach("maintenance-drill", {"drill.json": canonical(record)})
        result = self.evaluate(root=root)
        row = next(r for r in result["requirements"] if r["id"] == "p12-301-drill")
        self.assertFalse(result["phaseComplete"])
        self.assertNotEqual("authenticated", row["dimensions"].get("originalProvenance"))
        self.assertNotEqual("observed", row["dimensions"].get("runtimeExecution"))

    def test_supplied_invalid_is_blocked_not_missing(self):
        root = self.attach("maintenance-drill", {"drill.json": b'{"status":"verified"}'})
        result = self.evaluate(root=root)
        self.assertEqual("blocked", result["phaseDecision"])
        self.assertEqual("failed", result["subjects"][0]["verification"])

    def test_empty_non_site_artifact_remains_invalid(self):
        root = self.attach("maintenance-drill", {"drill.json": b""})
        with self.assertRaisesRegex(ValueError, "artifact-byte-contract"):
            self.evaluate(root=root)

    def test_offline_federation_rejects_invalid_supplied_proof_before_missing_authority(self):
        from .test_phase_12_federation_context import FederationFixture, NOW, archive
        from cryptad_certification import phase_12_federation_context as federation
        directory = self.root / "federation"
        directory.mkdir()
        fixture = FederationFixture(directory)
        fixture.write_all()
        execution = fixture.contract_path.read_bytes()
        files = {path.name: path.read_bytes() for path in fixture.evidence.iterdir()}
        payloads = {"execution.json": execution, "evidence.zip": archive({**files, "execution.json": execution})}
        identity = audit.checkout()
        root = self.attach("federation-context", payloads, subject={"kind": "authority-record",
            "commit": fixture.contract["repository"]["sourceCommit"], "tree": identity["tree"],
            "build": fixture.contract["release"]["buildVersion"], "digest": fixture.runtime["receiptDigest"]})
        artifact = self.selection["artifacts"][0]
        artifact["observedAt"] = fixture.runtime["observedAt"]
        proof = {"members": {"evidence.zip": "original-federation-context-archive"}, "coordinates": {
            "repository": "crypta-network/cryptad", "sourceFamily": "federated-catalog", "sourceCommit": "a" * 40,
            "runId": 100, "runAttempt": 1, "jobId": 101, "jobName": federation.PRODUCERS["import"][1],
            "artifactId": 102, "artifactName": "synthetic-context", "artifactDigest": digest(payloads["evidence.zip"]),
            "artifactSize": len(payloads["evidence.zip"])}}
        artifact["proof"] = proof
        baseline = audit.evaluate(self.selection, root, NOW)
        self.assertEqual("executed-pass", baseline["subjects"][0]["verification"])
        for field, value in (("artifactDigest", "sha256:" + "f" * 64), ("sourceCommit", "b" * 40),
                             ("sourceFamily", "catalog-source"), ("jobName", "wrong-original-job")):
            artifact["proof"] = copy.deepcopy(proof)
            artifact["proof"]["coordinates"][field] = value
            with self.subTest(field=field):
                result = audit.evaluate(self.selection, root, NOW)
                self.assertEqual("blocked", result["phaseDecision"])
                self.assertEqual("failed", result["subjects"][0]["verification"])

    def test_byte_digest_is_not_semantic_digest(self):
        raw = b'{ "status" : "verified" }\n'
        root = self.attach("maintenance-drill", {"drill.json": raw})
        self.selection["artifacts"][0]["files"][0]["digest"] = digest(canonical(json.loads(raw)))
        with self.assertRaises(ValueError):
            self.evaluate(root=root)

    def test_subject_dependency_cycle_and_orphan_rejected(self):
        rows = [{"id": "a", "predecessors": ["b"]}, {"id": "b", "predecessors": ["a"]}]
        with self.assertRaises(ValueError):
            audit.ordered(rows, edges="predecessors")
        rows[1]["predecessors"] = ["missing"]
        with self.assertRaises(ValueError):
            audit.ordered(rows, edges="predecessors")

    def test_runtime_must_have_original_product_predecessor(self):
        root = self.attach("maintenance-drill", {"drill.json": canonical(drill._seal(drill.plan()))}, kind="runtime")
        with self.assertRaises(ValueError):
            self.evaluate(root=root)

    def test_future_and_stale_supplied_observations_fail(self):
        root = self.attach("maintenance-drill", {"drill.json": canonical(drill._seal(drill.plan()))})
        row = self.selection["artifacts"][0]
        row["observedAt"] = "2099-01-01T00:00:00Z"
        self.assertEqual("blocked", self.evaluate(root=root)["phaseDecision"])
        row["observedAt"] = None
        row["expiresAt"] = "2026-01-01T00:00:00Z"
        self.assertEqual("blocked", self.evaluate(root=root)["phaseDecision"])

    def test_future_online_evaluation_is_rejected_before_original_acquisition(self):
        with patch.object(audit, "policy", side_effect=AssertionError("input processing must not begin")):
            with self.assertRaisesRegex(ValueError, "evaluation-after-current-time"):
                audit.evaluate(self.selection, None, "2999-01-01T00:00:00Z", collect_original=True)

    def test_source_drift_only_invalidates_reviewed_assertion(self):
        original = copy.deepcopy(self.rules["requirements"][0])
        self.assertNotEqual("unknown", audit.implementation(original)[0])
        original["implementation"]["sourceEvidence"][0]["digest"] = digest(b"changed source")
        self.assertEqual(("unknown", ["audited-source-drift"]), audit.implementation(original))

    def test_historical_product_may_have_a_different_source(self):
        root = self.attach("maintenance-drill", {"drill.json": canonical(drill._seal(drill.plan()))})
        row = self.selection["artifacts"][0]
        row["subject"].update(kind="historical-product", commit="a" * 40, tree="b" * 40)
        # A different historic commit is representable, but a local drill is no product root.
        with self.assertRaises(ValueError):
            audit.validate_selection(self.selection, self.rules, self.pin)
        row["subject"]["kind"] = "audit-tool"
        audit.validate_selection(self.selection, self.rules, self.pin)
        self.assertEqual("blocked", self.evaluate(root=root)["phaseDecision"])

    def test_approved_experimental_retention_does_not_waive_mail(self):
        rows = {r["id"]: r for r in self.rules["requirements"]}
        self.assertTrue(rows["p12-298-review"]["limitations"])
        self.assertTrue(rows["p12-301-lifecycle"]["mandatory"])
        self.assertFalse(self.evaluate()["phaseComplete"])

    def test_complete_internal_graph_is_synthetic_and_not_public_admissible(self):
        result = self.evaluate()
        for row in result["requirements"]:
            row["dimensions"] = {k: audit.PASS[k] for k in row["dimensions"]}
            row["blockers"] = []
        for row in result["residuals"]:
            row["status"] = "closed"
        result.update(audit.decide(result["requirements"], result["residuals"], as_of=AS_OF, synthetic=True))
        self.assertEqual("complete-as-of", result["phaseDecision"])
        with self.assertRaises(ValueError):
            audit.public_projection(result)

    def test_mandatory_deferral_still_blocks_decision(self):
        rows = [{"dimensions": {"implementation": "implemented"}, "blockers": []}]
        self.assertFalse(audit.decide(rows, [{"status": "deferred"}], as_of=AS_OF)["phaseComplete"])

    def test_residual_cannot_disappear_reclassify_or_reset_clock(self):
        prior = self.evaluate()
        for field, replacement in (("origin", {}), ("category", "approved limitation"), ("requirementIds", [])):
            changed = copy.deepcopy(self.rules)
            changed["residuals"][0][field] = replacement
            with self.assertRaises(ValueError):
                audit._carry_forward(changed, prior)
        changed = copy.deepcopy(self.rules)
        changed["residuals"].pop()
        with self.assertRaises(ValueError):
            audit._carry_forward(changed, prior)

    def test_public_allowlist_drops_private_payloads_and_all_private_hashes(self):
        result = self.evaluate()
        canaries = ["PRIVATE-CONTACT-USER", "/secret/backup/path", "CHK@private-ciphertext",
                    "https://private.example/incident", "sha256:" + "9" * 64]
        result["privateReceipts"] = canaries
        result["requirements"][0]["verification"] = canaries
        result["requirements"][0]["blockers"].extend(canaries)
        raw = canonical(audit.public_projection(result)) + audit.markdown(result)
        for canary in canaries:
            self.assertNotIn(canary.encode(), raw)

    def test_public_dimension_canary_is_rejected(self):
        result = self.evaluate()
        result["requirements"][0]["dimensions"]["implementation"] = "PRIVATE-CONTACT-USER"
        with self.assertRaises(ValueError):
            audit.public_projection(result)

    def test_independent_roots_produce_identical_bytes(self):
        first, second = self.evaluate(), self.evaluate()
        audit.write_outputs(first, self.root / "one")
        audit.write_outputs(second, self.root / "two")
        self.assertEqual(audit.file_inventory(self.root / "one"), audit.file_inventory(self.root / "two"))
        with self.assertRaises(ValueError):
            audit.write_outputs(second, self.root / "one")

    def test_symlink_hardlink_sidecar_and_duplicate_json_rejected(self):
        root = self.attach("maintenance-drill", {"drill.json": canonical(drill._seal(drill.plan()))})
        target = root / "selected/drill.json"
        sidecar = root / "private.json"
        sidecar.write_text("{}");
        with self.assertRaises(ValueError):
            self.evaluate(root=root)
        sidecar.unlink()
        os.link(target, sidecar)
        with self.assertRaises(ValueError):
            self.evaluate(root=root)
        sidecar.unlink()
        target.unlink()
        outside = self.root / "outside"
        outside.write_text("{}")
        target.symlink_to(outside)
        with self.assertRaises(ValueError):
            self.evaluate(root=root)
        for raw in (b'{"a":1,"a":2}', b'[' * 40 + b'0' + b']' * 40):
            with self.assertRaises(ValueError):
                audit.parse(raw)

    def test_require_complete_and_cli_errors_are_public_safe(self):
        args = SimpleNamespace(mode="evaluate", selection=None, source_root=None, assessment=None,
                               output=None, as_of=AS_OF, collect_original=False, require_complete=True)
        with patch("sys.stdout", new_callable=io.StringIO) as stdout:
            self.assertEqual(2, audit.run(args))
        self.assertIn('"auditExecuted":true', stdout.getvalue())
        args.selection = self.root / "PRIVATE-CONTACT-USER"
        with patch("sys.stdout", new_callable=io.StringIO) as stdout:
            self.assertEqual(2, audit.run(args))
        self.assertNotIn("PRIVATE-CONTACT-USER", stdout.getvalue())

    def test_verify_recomputes_and_rejects_resealed_complete_result(self):
        result = self.evaluate()
        result.update(phaseDecision="complete-as-of", phaseComplete=True)
        target = self.root / "forged.json"
        target.write_bytes(canonical(result))
        args = SimpleNamespace(mode="verify", selection=None, source_root=None, assessment=target,
                               output=None, as_of=AS_OF, collect_original=False, require_complete=False)
        with patch("sys.stdout", new_callable=io.StringIO):
            self.assertEqual(2, audit.run(args))

    def test_public_root_must_be_disjoint_from_private_root_in_both_directions(self):
        result = self.evaluate()
        private = self.root / "private"
        audit.write_outputs(result, private)
        public = self.root / "public"
        public.mkdir()
        args = SimpleNamespace(mode="public-export", selection=None, source_root=None,
            assessment=private / "phase-12-assessment.json", output=None, as_of=AS_OF,
            collect_original=False, require_complete=False)
        for target in (self.root / "status.json", private / "status.json"):
            args.output = target
            with self.subTest(target=target.name), patch("sys.stdout", new_callable=io.StringIO):
                self.assertEqual(2, audit.run(args))
            self.assertFalse(target.exists())
        args.output = public / "status.json"
        with patch("sys.stdout", new_callable=io.StringIO):
            self.assertEqual(0, audit.run(args))
        self.assertEqual(audit.public_projection(result), json.loads(args.output.read_bytes()))
        self.assertEqual(1, args.output.stat().st_nlink)


class ProvenanceTest(unittest.TestCase):
    def test_absence_and_retained_original_context_distinguished(self):
        self.assertEqual("not-supplied", provenance.original_proof("maintenance-drill", None, {})["state"])
        from cryptad_certification.transparency_sources import _original_helper
        helper = _original_helper()
        coordinates = {"repository": "crypta-network/cryptad", "sourceFamily": "catalog-source",
                       "sourceCommit": "a" * 40, "runId": 1, "runAttempt": 2, "jobId": 3,
                       "jobName": helper.PRODUCERS["catalog-source"][2], "artifactId": 4,
                       "artifactName": "original", "artifactDigest": digest(b"archive"), "artifactSize": 7}
        proof = {"coordinates": coordinates, "members": {"authority.json": "authority.json"}}
        with patch.object(helper, "authenticate_original", side_effect=AssertionError("no GET")):
            self.assertEqual("unverified", provenance.original_proof("catalog-keyset", proof, {"authority.json": b"{}"})["state"])
        coordinates["repository"] = "wrong/repository"
        with self.assertRaises(ValueError):
            provenance.original_proof("catalog-keyset", proof, {"authority.json": b"{}"})

    def test_ci_skip_and_merge_identity_are_not_current_execution(self):
        source = {"commit": "a" * 40}
        run = {"id": 1, "run_attempt": 2, "head_sha": source["commit"], "event": "pull_request",
               "repository": {"full_name": "crypta-network/cryptad"}, "path": ".github/workflows/ci.yml"}
        job = {"id": 3, "run_id": 1, "head_sha": source["commit"], "conclusion": "skipped", "steps": []}
        value = {"schemaVersion": 1, "repository": "crypta-network/cryptad", "observedAt": AS_OF,
                 "runs": [{"run": run, "jobs": [job], "checkout": {"commit": "b" * 40, "kind": "pr-test-merge"}}]}
        result = provenance.hosted_records(canonical(value), source, AS_OF)
        self.assertEqual("skipped", result["records"][0]["execution"])
        self.assertEqual("unknown", result["ci"])
        self.assertEqual("not-inspected", result["records"][0]["analyzers"])
        value["runs"][0]["checkout"]["kind"] = "squash"
        with self.assertRaises(ValueError):
            provenance.hosted_records(canonical(value), source, AS_OF)


if __name__ == "__main__":
    unittest.main()
