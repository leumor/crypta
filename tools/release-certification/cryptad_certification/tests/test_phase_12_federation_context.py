"""Native federation signatures and isolated original-provider admission contracts."""
from __future__ import annotations

import copy
import io
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import zipfile

from cryptad_certification import phase_12_federation_context as context
from cryptad_certification import phase_12_closeout as closeout
from cryptad_certification.tests.test_stable_federated_catalog import FederationFixture, NOW, _seal
from cryptad_certification import transparency_bundle as bounded


def archive(files):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as stream:
        for name, raw in sorted(files.items()):
            stream.writestr(name, raw)
    return output.getvalue()


class FederationContextTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.fixture = FederationFixture(self.root)

    def payloads(self):
        self.fixture.write_all()
        files = {path.name: path.read_bytes() for path in self.fixture.evidence.iterdir()}
        execution = self.fixture.contract_path.read_bytes()
        return {"execution.json": execution, "evidence.zip": archive({**files, "execution.json": execution})}

    def evaluate(self, payloads=None, as_of=NOW):
        with mock.patch("socket.create_connection", side_effect=AssertionError("offline evaluation contacted a host")):
            return context.verify("federation-context", payloads or self.payloads(), as_of, self.root)

    def test_actual_native_signatures_cohort_and_conflicts_pass_only_as_synthetic_local(self):
        result = self.evaluate()
        self.assertEqual("executed-pass", result["dimensions"]["localVerification"])
        self.assertEqual("unverified", result["dimensions"]["originalProvenance"])
        self.assertEqual("not-observed", result["dimensions"]["runtimeExecution"])
        self.assertEqual("synthetic-test", result["evidenceClass"])
        self.assertEqual(context.CLAIMS, result["claims"])
        self.assertEqual(4, len(result["coverage"]["missingPredecessors"]))

    def test_self_resealed_wrong_runtime_or_observer_cannot_enter(self):
        for field in ("authorityDigests", "observerKeyId"):
            with self.subTest(field=field):
                original = copy.deepcopy(self.fixture.runtime)
                if field == "authorityDigests":
                    self.fixture.runtime[field]["protectedRelease"] = "sha256:" + "f" * 64
                else:
                    self.fixture.runtime[field] = "different-observer"
                _seal(self.fixture.runtime, "receiptDigest", *self.fixture.observer)
                if field == "observerKeyId":
                    # Keep the execution's independently selected observer binding unchanged.
                    payloads = self.payloads()
                    contract = bounded.parse(payloads["execution.json"])
                    contract["evidence"]["runtimeObservation"]["observerKeyId"] = original[field]
                    files = context._archive(payloads["evidence.zip"], flat=True)
                    files["execution.json"] = payloads["execution.json"] = bounded.canonical(contract)
                    payloads["evidence.zip"] = archive(files)
                else:
                    payloads = self.payloads()
                with self.assertRaises(ValueError):
                    self.evaluate(payloads)
                self.fixture.runtime = original

    def test_cohort_shrinkage_source_switch_and_private_data_scenarios_reject(self):
        mutations = (lambda row: row["catalogs"].pop(),
                     lambda row: row["scenarios"].update(lexicalTieBreakDisabled=False),
                     lambda row: row["discovery"].update(localStateSent=True),
                     lambda row: row.update(partial=True))
        for mutation in mutations:
            original = copy.deepcopy(self.fixture.runtime)
            mutation(self.fixture.runtime)
            _seal(self.fixture.runtime, "receiptDigest", *self.fixture.observer)
            with self.assertRaises(ValueError):
                self.evaluate()
            self.fixture.runtime = original

    def test_stale_and_future_evaluation_do_not_reuse_historic_verdict(self):
        for stamp in ("2026-08-24T00:00:00Z", "2026-09-10T00:00:00Z"):
            with self.assertRaises(ValueError):
                self.evaluate(as_of=stamp)

    def test_missing_extra_duplicate_binding_and_execution_substitution_reject(self):
        inputs = self.payloads()
        files = context._archive(inputs["evidence.zip"], flat=True)
        for change in (lambda rows: rows.pop("runtime.json"),
                       lambda rows: rows.update({"sidecar.json": b"{}"}),
                       lambda rows: rows.update({"execution.json": b"{}"})):
            revised = dict(files)
            change(revised)
            with self.assertRaises(ValueError):
                self.evaluate({**inputs, "evidence.zip": archive(revised)})
        self.fixture.contract["evidence"]["endorsements"].append(copy.deepcopy(self.fixture.contract["evidence"]["endorsements"][0]))
        encoded = bounded.canonical(self.fixture.contract)
        with self.assertRaises(ValueError):
            self.evaluate({"execution.json": encoded, "evidence.zip": archive({**files, "execution.json": encoded})})

    def test_fixture_promotion_rejected_before_get_or_private_provider_access(self):
        with mock.patch.object(context, "_Collector", side_effect=AssertionError("fixture reached original provider")):
            with self.assertRaises(ValueError):
                context.collect_and_verify("federation-context", self.payloads(), NOW, self.root, None)

    def test_retained_original_coordinates_are_unverified_and_archive_exact(self):
        payloads = self.payloads()
        proof = {"members": {"evidence.zip": "original-federation-context-archive"}, "coordinates": {
            "repository": "crypta-network/cryptad", "sourceFamily": "federated-catalog", "sourceCommit": "a" * 40,
            "runId": 100, "runAttempt": 1, "jobId": 101, "jobName": context.PRODUCERS["import"][1],
            "artifactId": 102, "artifactName": "synthetic-context", "artifactDigest": bounded.digest(payloads["evidence.zip"]),
            "artifactSize": len(payloads["evidence.zip"])}}
        self.assertEqual("unverified", context.validate_proof("federation-context", proof, payloads)["state"])
        proof["coordinates"]["artifactDigest"] = "sha256:" + "f" * 64
        with self.assertRaises(ValueError):
            context.validate_proof("federation-context", proof, payloads)

    def assess_original_context(self, *, missing=False):
        """Isolate native validation/transport authorities, retaining real admission and reconciliation."""
        payloads = self.payloads()
        contract, runtime, files, _, _ = context._context("federation-context", payloads, NOW, self.root)
        contract = copy.deepcopy(contract)
        runtime = copy.deepcopy(runtime)
        binding = contract["evidence"]["runtimeObservation"]
        suffix = f"{contract['executionId']}-100-1"
        receipt = archive({binding["fileName"]: files[binding["fileName"]]})
        binding["receiptProvenance"].update(runId=100, runAttempt=1,
            artifactName="stable-1-0-federated-catalog-runtime-receipt-" + suffix,
            artifactDigest=bounded.digest(receipt))
        runtime["provenance"].update(runId=100,
            artifactName="stable-1-0-federated-catalog-runtime-observation-" + suffix)
        originals = {}
        for name, authority in contract["authorities"].items():
            raw = bounded.canonical({"isolatedTestAuthority": name})
            filename = name + ".json"
            files[filename] = raw
            authority["summary"] = {"fileName": filename, "digest": bounded.digest(raw), "size": len(raw)}
            originals[name] = archive({filename: raw})
        unsigned = {"id": 1, "name": runtime["provenance"]["artifactName"],
                    "digest": runtime["provenance"]["artifactDigest"], "workflow_run": {"id": 100},
                    "created_at": NOW, "updated_at": NOW}
        signed = {"id": 2, "name": binding["receiptProvenance"]["artifactName"],
                  "digest": bounded.digest(receipt), "created_at": NOW}

        def producer(provenance, role, *, branch=None):
            if role == "runtime":
                return receipt, {"head_branch": "develop"}, {"started_at": "2026-08-25T00:00:00Z"}, [unsigned, signed]
            return originals[role], {}, {"completed_at": "2026-08-25T00:00:00Z"}, []

        selected = closeout.repository_selection()
        directory = self.root / "selected" / "federation"
        directory.mkdir(parents=True)
        members = []
        for name, raw in payloads.items():
            (directory / name).write_bytes(raw)
            members.append({"name": name, "digest": bounded.digest(raw), "size": len(raw)})
        selected["artifacts"] = [{"id": "federation", "adapter": "federation-context", "files": members,
            "subject": {"kind": "authority-record", "commit": contract["repository"]["sourceCommit"],
                        "tree": closeout.checkout()["tree"], "build": contract["release"]["buildVersion"],
                        "digest": runtime["receiptDigest"]},
            "predecessors": [], "proof": None, "expiresAt": None, "observedAt": runtime["observedAt"]}]
        verified_native = (contract, runtime, files, ["protectedRelease"] if missing else [], False)
        with mock.patch.object(context, "_context", return_value=verified_native), \
             mock.patch.object(context, "_Collector") as collector, \
             mock.patch("socket.socket", side_effect=AssertionError("isolated authority contacted a host")):
            collector.return_value.producer.side_effect = producer
            result = closeout.evaluate(selected, directory.parent, NOW, collect_original=True)
            if missing:
                collector.assert_not_called()
            else:
                self.assertEqual(5, collector.return_value.producer.call_count)
                collector.return_value.artifact.assert_called_once()
        return result

    def test_original_federation_coverage_reaches_each_assessment_requirement(self):
        result = self.assess_original_context()
        self.assertEqual("executed-pass", result["subjects"][0]["verification"])
        for row in result["requirements"]:
            if row["id"] in context.CLAIMS:
                with self.subTest(requirement=row["id"]):
                    self.assertEqual("complete", row["dimensions"]["coverage"])
                    self.assertEqual("authenticated", row["dimensions"]["originalProvenance"])
                    self.assertEqual("observed", row["dimensions"]["runtimeExecution"])
                    self.assertNotIn("coverage-missing", row["blockers"])
        self.assertFalse(result["phaseComplete"])

    def test_missing_original_predecessor_keeps_assessment_coverage_missing(self):
        result = self.assess_original_context(missing=True)
        for row in result["requirements"]:
            if row["id"] in context.CLAIMS:
                self.assertEqual("missing", row["dimensions"]["coverage"])
                self.assertEqual("unverified", row["dimensions"]["originalProvenance"])
                self.assertIn("coverage-missing", row["blockers"])

    def test_private_canary_in_unbound_archive_has_only_fixed_error(self):
        payloads = self.payloads()
        files = context._archive(payloads["evidence.zip"], flat=True)
        files["PRIVATE_CONTACT.json"] = b'{"private":"/home/private-user/contact"}'
        with self.assertRaisesRegex(ValueError, "^phase12-federation-context-rejected$"):
            self.evaluate({**payloads, "evidence.zip": archive(files)})


class OriginalFederationProviderTests(unittest.TestCase):
    """A synthetic transport exercises real native producer verification, never production keys."""
    def setUp(self):
        self.original = context._original()
        self.raw = archive({"runtime.json": b'{"synthetic":true}'})
        workflow, job, environment = context.PRODUCERS["runtime"]
        self.provenance = {"repositoryIdentity": "github.com/crypta-network/cryptad", "workflowPath": workflow,
            "workflowCommit": "a" * 40, "runId": 100, "runAttempt": 2, "artifactName": "synthetic-original-runtime",
            "artifactDigest": bounded.digest(self.raw), "environment": environment, "conclusion": "success"}
        self.job = {"id": 200, "name": job, "head_sha": "a" * 40, "conclusion": "success",
                    "steps": [{"name": "Exercise protected federation topology", "conclusion": "success"},
                              {"name": "Seal runtime receipt with independently approved observer key", "conclusion": "success"}],
                    "started_at": "2026-08-25T11:00:00Z", "completed_at": "2026-08-25T12:00:00Z"}
        prefix = "repos/crypta-network/cryptad"
        selected = prefix + "/actions/runs/100/attempts/2"
        self.run_endpoint = selected
        self.jobs_endpoint = selected + "/jobs?per_page=100"
        self.artifacts_endpoint = prefix + "/actions/runs/100/artifacts?per_page=100"
        self.status_endpoint = prefix + "/deployments/300/statuses?per_page=100"
        self.archive_endpoint = prefix + "/actions/artifacts/400/zip"
        self.values = {
            selected: {"id": 100, "run_attempt": 2, "head_sha": "a" * 40, "path": workflow,
                       "head_branch": "develop", "event": "workflow_dispatch", "status": "completed", "conclusion": "success",
                       "repository": {"full_name": "crypta-network/cryptad"}, "actor": {"login": "leumor"},
                       "triggering_actor": {"login": "leumor"}},
            self.jobs_endpoint: {"total_count": 1, "jobs": [self.job]},
            prefix + "/deployments?sha=" + "a" * 40 + "&environment=" + environment + "&per_page=100":
                [{"id": 300, "environment": environment, "sha": "a" * 40, "creator": {"login": "github-actions[bot]"}}],
            self.status_endpoint: [{"state": "success", "created_at": "2026-08-25T11:59:00Z",
                                    "log_url": "https://github.com/crypta-network/cryptad/actions/runs/100/job/200"}],
            self.artifacts_endpoint: {"total_count": 1, "artifacts": [{"id": 400, "name": self.provenance["artifactName"],
                "digest": self.provenance["artifactDigest"], "workflow_run": {"id": 100}, "expired": False,
                "created_at": "2026-08-25T11:59:00Z", "updated_at": "2026-08-25T12:00:00Z", "size_in_bytes": len(self.raw)}]},
            self.archive_endpoint: self.raw}
        self.calls = []

    def get(self, args, environment, *, json_result=True):
        self.assertEqual(["api", "--method", "GET"], args[:3])
        self.assertEqual({"synthetic": "isolated"}, environment)
        self.calls.append(args[3])
        return copy.deepcopy(self.values[args[3]])

    def evaluate(self):
        with mock.patch.object(self.original, "_environment", return_value={"synthetic": "isolated"}), \
             mock.patch.object(self.original, "_gh", side_effect=self.get):
            return context._Collector(NOW).producer(self.provenance, "runtime", branch="develop")

    def test_native_original_run_job_environment_and_exact_archive_are_all_rechecked(self):
        raw, run, job, artifacts = self.evaluate()
        self.assertEqual(self.raw, raw)
        self.assertEqual((100, 2, 200, 400), (run["id"], run["run_attempt"], job["id"], artifacts[0]["id"]))
        self.assertEqual(6, len(self.calls))

    def test_wrong_original_workflow_repository_attempt_actor_or_branch_reject(self):
        for field, value in (("path", ".github/workflows/unrelated.yml"), ("run_attempt", 1),
                             ("repository", {"full_name": "attacker/cryptad"}), ("actor", {"login": "other"}),
                             ("head_branch", "feature/unapproved"), ("head_sha", "b" * 40)):
            old = self.values[self.run_endpoint][field]
            self.values[self.run_endpoint][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.evaluate()
            self.values[self.run_endpoint][field] = old

    def test_swapped_environment_job_rejects(self):
        self.values[self.status_endpoint][0]["log_url"] = "https://github.com/crypta-network/cryptad/actions/runs/100/job/999"
        with self.assertRaises(ValueError):
            self.evaluate()

    def test_successful_job_with_skipped_managed_work_is_not_original_runtime(self):
        self.job["steps"][0]["conclusion"] = "skipped"
        with self.assertRaises(ValueError):
            self.evaluate()

    def test_original_job_cannot_claim_work_after_evaluation(self):
        self.job["completed_at"] = "2026-08-26T00:00:00Z"
        with self.assertRaises(ValueError):
            self.evaluate()

    def test_skipped_original_job_cannot_be_an_executed_observer(self):
        self.values[self.jobs_endpoint]["jobs"][0]["conclusion"] = "skipped"
        with self.assertRaises(ValueError):
            self.evaluate()

    def test_reupload_swapped_attempt_time_and_metadata_digest_cannot_authenticate_bytes(self):
        row = self.values[self.artifacts_endpoint]["artifacts"][0]
        for field, value in (("workflow_run", {"id": 101}), ("created_at", "2026-08-25T10:00:00Z"),
                             ("expired", True), ("digest", "sha256:" + "f" * 64), ("size_in_bytes", len(self.raw) + 1)):
            old = row[field]
            row[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.evaluate()
            row[field] = old
        self.values[self.archive_endpoint] = self.raw + b"substitution"
        with self.assertRaises(ValueError):
            self.evaluate()

    def test_ambiguous_artifacts_or_truncated_record_page_reject(self):
        page = self.values[self.artifacts_endpoint]
        page["total_count"] = 2
        with self.assertRaises(ValueError):
            self.evaluate()
        page["artifacts"].append(copy.deepcopy(page["artifacts"][0]))
        with self.assertRaises(ValueError):
            self.evaluate()

    def test_original_receipt_member_must_equal_exact_selected_bytes_not_semantic_digest(self):
        raw = b'{"native":1}\n'
        binding = {"fileName": "runtime.json", "digest": bounded.digest(raw), "size": len(raw)}
        context._member(archive({"runtime.json": raw}), binding, raw)
        with self.assertRaises(ValueError):
            context._member(archive({"runtime.json": b'{"native": 1}\n'}), binding, raw)


if __name__ == "__main__":
    unittest.main()
