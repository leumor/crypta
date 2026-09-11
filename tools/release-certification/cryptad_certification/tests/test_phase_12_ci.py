"""Original API admission with isolated responses, never test fixtures as production authority."""
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace
import zipfile

from cryptad_certification import phase_12_ci as ci

AS_OF = "2026-09-10T12:00:00Z"
SHA = "a" * 40
SOURCE = {"commit": SHA, "tree": "b" * 40, "toolDigest": "sha256:" + "c" * 64}


def encoded(value):
    return json.dumps(value, sort_keys=True).encode()


class OriginalAPI:
    def __init__(self):
        self.responses = {}
        self.requests = []
        self.selection = {"schemaVersion": 1, "repository": ci.REPOSITORY,
                          "observedAt": AS_OF, "runs": []}
        number = 100
        for run_id, workflow in enumerate(sorted(ci.WORKFLOWS), 1):
            run = {"id": run_id, "run_attempt": 2, "repository": {"full_name": ci.REPOSITORY},
                   "head_sha": SHA, "path": workflow, "event": "pull_request", "status": "completed",
                   "conclusion": "success", "updated_at": AS_OF}
            prefix = f"actions/runs/{run_id}/attempts/2"
            jobs = []
            for name, required in ci.STEPS[workflow].items():
                number += 1
                steps = [{"name": "Run " + ci.CHECKOUT, "conclusion": "success",
                          "started_at": "2026-09-10T11:00:00Z", "completed_at": "2026-09-10T11:00:05Z"}]
                steps.extend({"name": step, "conclusion": "success" if index == 0 or name != "build / build" else "skipped"}
                             for index, step in enumerate(required))
                job = {"id": number, "run_id": run_id, "run_attempt": 2, "head_sha": SHA,
                       "name": name, "conclusion": "success", "steps": steps,
                       "check_run_url": f"https://api.github.com/repos/{ci.REPOSITORY}/check-runs/{number}"}
                jobs.append(job)
                self.responses[f"actions/jobs/{number}/logs"] = (
                    "2026-09-10T11:00:01.1234567Z [command]/usr/bin/git log -1 --format=%H\n"
                    f"2026-09-10T11:00:01.2234567Z {SHA}\n").encode()
                self.responses[f"check-runs/{number}"] = {
                    "id": number, "head_sha": SHA, "name": name, "app": {"slug": "github-actions"},
                    "conclusion": "success", "output": {"annotations_count": 0}}
                self.responses[f"check-runs/{number}/annotations?per_page=100"] = []
            for name in ci.EXPECTED_SKIPS[workflow]:
                number += 1
                jobs.append({"id": number, "run_id": run_id, "run_attempt": 2, "head_sha": SHA,
                             "name": name, "conclusion": "skipped", "steps": []})
            self.responses[prefix] = run
            self.responses[prefix + "/jobs?per_page=100"] = {"total_count": len(jobs), "jobs": jobs}
            self.selection["runs"].append({"run": copy.deepcopy(run), "jobs": copy.deepcopy(jobs),
                                           "checkout": {"commit": SHA, "kind": "pr-head"}})
        self.pr_context()

    def pr_context(self, *, branch="develop", paths=None):
        paths = paths or ["tools/ecosystem-transparency/source-policy.json"]
        original = {"number": 1405, "head": {"sha": SHA}, "base": {"sha": "e" * 40, "ref": branch}}
        for key, value in self.responses.items():
            if key.startswith("actions/runs/") and re.fullmatch(r"actions/runs/[0-9]+/attempts/2", key):
                value["pull_requests"] = [copy.deepcopy(original)]
        for row in self.selection["runs"]:
            row["run"]["pull_requests"] = [copy.deepcopy(original)]
        self.responses["pulls/1405"] = {**copy.deepcopy(original), "changed_files": len(paths), "updated_at": AS_OF}
        self.responses["pulls/1405"]["base"]["repo"] = {"full_name": ci.REPOSITORY}
        for page, offset in enumerate(range(0, len(paths), 100), 1):
            self.responses[f"pulls/1405/files?per_page=100&page={page}"] = [
                {"filename": path, "status": "modified"} for path in paths[offset:offset + 100]]

    def select_workflows(self, *paths):
        self.selection["runs"] = [row for row in self.selection["runs"] if row["run"]["path"] in paths]

    def get(self, suffix, *, raw=False):
        self.requests.append(suffix)
        return copy.deepcopy(self.responses[suffix])

    def attest(self, raw, run, workflow_source, signer):
        if raw != self.attested_bytes:
            raise ValueError("test-original-attestation-substitution")

    def complete_reports(self):
        job = next(row for row in self.responses["actions/runs/1/attempts/2/jobs?per_page=100"]["jobs"] if row["name"] == "build / build")
        for step in job["steps"]:
            if step["name"] == "Build and analyze (Gradle)":
                step["conclusion"] = "skipped"
            if step["name"] == "Build (no Sonar token)":
                step["conclusion"] = "success"
        for name, start, end in ((ci.PREPARE_STEP, "11:00:05", "11:00:07"),
                                  (ci.RETAIN_STEP, "11:10:00", "11:10:05"),
                                  (ci.ATTEST_STEP, "11:10:06", "11:10:10"),
                                  (ci.UPLOAD_STEP, "11:10:11", "11:10:15")):
            job["steps"].append({"name": name, "conclusion": "success",
                "started_at": "2026-09-10T" + start + "Z", "completed_at": "2026-09-10T" + end + "Z"})
        rows = []
        for module, kind in ci._report_cohort(ci.ROOT):
            facts = ci._xml_facts(xml(kind, module), kind, module)
            rows.append({"module": module, "kind": kind, "reports": [facts]})
        self.report_value = {"schemaVersion": 1, "kind": "phase-12-original-ci-report-facts", "sourceCommit": SHA,
            "sourceTree": SOURCE["tree"], "workflowSourceCommit": SHA, "signerCommit": SHA, "runId": 1, "runAttempt": 2,
            "jobKey": "build", "producerDigest": ci._producer_identity(), "startedAt": "2026-09-10T11:00:06Z",
            "generatedAt": "2026-09-10T11:10:02Z", "rows": rows,
            "sonarLint": "owner-skipped-standard-build", "rawPayloads": "not-exported"}
        self.replace_reports()

    def replace_reports(self, *, attest=True):
        raw = encoded(self.report_value)
        content = io.BytesIO()
        with zipfile.ZipFile(content, "w") as archive:
            item = zipfile.ZipInfo(ci.REPORT_FILE)
            item.external_attr = (stat.S_IFREG | 0o600) << 16
            archive.writestr(item, raw)
        data = content.getvalue()
        self.responses["actions/runs/1/artifacts?per_page=100"] = {"total_count": 1, "artifacts": [{
            "id": 900, "name": "phase-12-ci-reports-1-2", "expired": False,
            "workflow_run": {"id": 1, "head_sha": SHA}, "created_at": "2026-09-10T11:10:13Z",
            "size_in_bytes": len(data), "digest": "sha256:" + hashlib.sha256(data).hexdigest()}]}
        self.responses["actions/artifacts/900/zip"] = data
        if attest:
            self.attested_bytes = raw


def xml(kind, module="."):
    if kind == "junit":
        return b'<testsuite tests="1" failures="0" errors="0" skipped="0" timestamp="2026-09-10T11:05:00Z"><properties><property name="private" value="private-contact-canary"/></properties><testcase name="private-contact-canary"><system-out>private-contact-canary</system-out></testcase><system-err>private-contact-canary</system-err></testsuite>'
    if kind.startswith("spotbugs"):
        return b'<BugCollection analysisTimestamp="1789038300000"><Project><Jar>private-contact-canary</Jar></Project><Errors errors="0"/><FindBugsSummary total_bugs="0" total_classes="1"/></BugCollection>'
    project = ":" if module == "." else ":" + module.replace("/", ":")
    task = "compileTestJava" if kind.endswith("test") else "compileJava"
    return f'<errorproneReport project="{project}" task="{task}" generatedAt="2026-09-10T11:05:00Z"/>'.encode()


class Phase12HostedCITests(unittest.TestCase):
    def setUp(self):
        self.api = OriginalAPI()

    def verify(self, clean=True):
        with patch.object(ci, "_GitHub", return_value=self.api), patch.object(ci, "_source_clean", return_value=clean):
            return ci.verify(encoded(self.api.selection), SOURCE, AS_OF, collect_original=True)

    def test_actual_original_job_admission_preserves_missing_test_and_nonblocking_reports(self):
        result = self.verify()
        self.assertEqual("authenticated", result["originalProvenance"])
        self.assertEqual("unknown", result["ci"])
        self.assertFalse(result["sourceDrift"])
        self.assertIn("original-ci-test-report-retention-unavailable", result["blockers"])
        self.assertIn("original-ci-nonblocking-analyzer-reports-unavailable", result["blockers"])
        jobs = [job for record in result["records"] for job in record["jobs"]]
        self.assertTrue(any(job["execution"] == "executed-pass" for job in jobs))
        self.assertTrue(any(job["execution"] == "skipped" for job in jobs))
        self.assertNotIn("original-checkout-identity-unavailable", result["blockers"])

    def test_retained_records_do_not_get_original_authority_or_execute_collection(self):
        with patch.object(ci, "_GitHub", side_effect=AssertionError("collection denied")):
            result = ci.verify(encoded(self.api.selection), SOURCE, AS_OF)
        self.assertEqual("unverified", result["originalProvenance"])
        self.assertEqual("unknown", result["ci"])

    def test_dirty_current_source_preserves_historical_original_job_with_source_gap(self):
        result = self.verify(clean=False)
        self.assertTrue(result["sourceDrift"])
        self.assertEqual("authenticated", result["originalProvenance"])
        self.assertIn("ci-effective-source-differs-from-hosted-commit", result["blockers"])

    def test_original_wrong_repository_attempt_and_unselected_job_are_invalid(self):
        mutations = (lambda a: a.responses["actions/runs/1/attempts/2"]["repository"].update(full_name="private/canary"),
                     lambda a: a.responses["actions/runs/1/attempts/2"].update(run_attempt=3),
                     lambda a: a.responses["actions/runs/1/attempts/2/jobs?per_page=100"]["jobs"][0].update(name="unapproved"))
        for mutate in mutations:
            self.api = OriginalAPI()
            mutate(self.api)
            with self.assertRaisesRegex(ValueError, "^phase12-original-ci-invalid$"):
                self.verify()

    def test_original_annotations_remain_disposition_gap_without_private_text(self):
        check = next(key for key in self.api.responses if key.startswith("check-runs/") and "annotations" not in key)
        self.api.responses[check]["output"]["annotations_count"] = 1
        self.api.responses[check + "/annotations?per_page=100"] = [
            {"annotation_level": "warning", "message": "private-contact-path-canary", "path": "private-canary"}]
        result = self.verify()
        self.assertIn("original-ci-annotations-require-disposition", result["blockers"])
        self.assertNotIn("canary", json.dumps(result))

    def test_skipped_required_step_cannot_be_converted_by_successful_job(self):
        job = self.api.responses["actions/runs/1/attempts/2/jobs?per_page=100"]["jobs"][1]
        job["steps"][-1]["conclusion"] = "skipped"
        result = self.verify()
        self.assertIn("required-original-ci-job-not-executed-pass", result["blockers"])
        self.assertEqual("skipped", result["ci"])

    def test_real_test_merge_parent_relationship_does_not_transfer_head_acceptance(self):
        key = next(key for key in self.api.responses if key.endswith("/logs"))
        merge = "d" * 40
        self.api.responses[key] = self.api.responses[key].replace(SHA.encode(), merge.encode())
        self.api.responses["git/commits/" + merge] = {"sha": merge, "parents": [{"sha": SHA}, {"sha": "e" * 40}]}
        result = self.verify()
        self.assertIn("original-checkout-differs-from-audited-source", result["blockers"])
        self.assertTrue(any(job.get("checkoutKind") == "pr-test-merge" for run in result["records"] for job in run["jobs"]))

    def test_checkout_spoof_after_original_action_interval_does_not_bind_source(self):
        key = next(key for key in self.api.responses if key.endswith("/logs"))
        self.api.responses[key] = self.api.responses[key].replace(b"11:00:01", b"11:30:00")
        result = self.verify()
        self.assertIn("original-checkout-identity-unavailable", result["blockers"])

    def test_native_successful_job_with_unavailable_log_stays_original_execution(self):
        original = self.api.get
        def get(path, *, raw=False):
            if raw:
                raise ci.OriginalCIUnavailable("phase12-original-ci-access-unavailable")
            return original(path, raw=raw)
        self.api.get = get
        result = self.verify()
        self.assertEqual("authenticated", result["originalProvenance"])
        self.assertIn("original-checkout-log-unavailable", result["blockers"])
        jobs = [job for run in result["records"] for job in run["jobs"] if "scope" not in job]
        self.assertTrue(all(job["execution"] == "executed-pass" for job in jobs))
        self.assertTrue(all(job["checkedCommit"] is None for job in jobs))

    def test_develop_push_does_not_require_inapplicable_beta_or_transparency_runs(self):
        self.api.selection["runs"] = self.api.selection["runs"][:1]
        requested = self.api.selection["runs"][0]
        requested["run"].update(event="push", head_branch="develop")
        requested["checkout"]["kind"] = "push"
        self.api.responses["actions/runs/1/attempts/2"].update(event="push", head_branch="develop")
        result = self.verify()
        self.assertNotIn("required-original-ci-workflow-not-selected", result["blockers"])

    def test_java_and_unrelated_document_prs_can_pass_without_transparency_workflow(self):
        for path in ("foundation-fs/src/main/java/network/crypta/fs/AppEnv.java",
                     "docs/public-ecosystem-transparency-site.md",
                     "tools/release-certification/cryptad_certification/transparency_nested/unrelated.py"):
            self.api = OriginalAPI()
            self.api.pr_context(paths=[path])
            self.api.complete_reports()
            self.api.select_workflows(".github/workflows/ci.yml", ".github/workflows/production-beta-release.yml")
            with self.subTest(path=path):
                result = self.verify()
                self.assertEqual("executed-pass", result["ci"])
                self.assertEqual([], result["blockers"])
                self.assertNotIn(path, json.dumps(result))

    def test_each_matching_transparency_path_requires_original_workflow(self):
        for path in ("tools/ecosystem-transparency/tests/browser.cjs",
                     "tools/release-certification/cryptad_certification/transparency_bundle.py",
                     "tools/release-certification/cryptad_certification/tests/test_transparency_bundle.py",
                     ".github/workflows/public-ecosystem-transparency.yml"):
            self.api = OriginalAPI()
            self.api.pr_context(paths=[path])
            self.api.complete_reports()
            self.api.select_workflows(".github/workflows/ci.yml", ".github/workflows/production-beta-release.yml")
            with self.subTest(path=path):
                result = self.verify()
                self.assertEqual("unknown", result["ci"])
                self.assertIn("required-original-ci-workflow-not-selected", result["blockers"])

    def test_pr_base_branch_filters_do_not_require_untriggered_beta(self):
        for branch in ("feature/phase-12", "bugfix/a/b"):
            self.api = OriginalAPI()
            self.api.pr_context(branch=branch, paths=["docs/unrelated.md"])
            self.api.complete_reports()
            self.api.select_workflows(".github/workflows/ci.yml")
            with self.subTest(branch=branch):
                self.assertEqual("executed-pass", self.verify()["ci"])
        for branch in ("main", "develop", "release/29", "hotfix/29"):
            self.api = OriginalAPI()
            self.api.pr_context(branch=branch, paths=["docs/unrelated.md"])
            self.api.complete_reports()
            self.api.select_workflows(".github/workflows/ci.yml")
            with self.subTest(branch=branch):
                self.assertIn("required-original-ci-workflow-not-selected", self.verify()["blockers"])

    def test_missing_truncated_and_drifted_pr_metadata_remain_unknown(self):
        for kind in ("run-context", "file-count", "file-page", "duplicate", "too-many", "head", "base", "branch"):
            self.api = OriginalAPI()
            self.api.pr_context(paths=["docs/unrelated.md"])
            self.api.complete_reports()
            self.api.select_workflows(".github/workflows/ci.yml", ".github/workflows/production-beta-release.yml")
            if kind == "run-context":
                self.api.responses["actions/runs/1/attempts/2"].pop("pull_requests")
            elif kind == "file-count":
                self.api.responses["pulls/1405"].pop("changed_files")
            elif kind == "file-page":
                self.api.responses["pulls/1405/files?per_page=100&page=1"] = []
            elif kind == "duplicate":
                self.api.pr_context(paths=["docs/unrelated.md", "docs/unrelated.md"])
            elif kind == "too-many":
                self.api.responses["pulls/1405"]["changed_files"] = 301
            elif kind in {"head", "base"}:
                self.api.responses["pulls/1405"][kind]["sha"] = "f" * 40
            else:
                self.api.responses["pulls/1405"]["base"]["ref"] = "feature/moved"
            with self.subTest(kind=kind):
                result = self.verify()
                self.assertEqual("unknown", result["ci"])
                self.assertTrue(any("original-ci-pr-" in code for code in result["blockers"]))
                self.assertNotIn("required-original-ci-workflow-not-selected", result["blockers"])

    def test_pr_file_metadata_access_denial_and_race_cannot_grant_exemption(self):
        for kind in ("access", "race"):
            self.api = OriginalAPI()
            self.api.pr_context(paths=["docs/unrelated.md"])
            self.api.complete_reports()
            self.api.select_workflows(".github/workflows/ci.yml", ".github/workflows/production-beta-release.yml")
            original = self.api.get
            reads = []
            def get(path, *, raw=False):
                if path == "pulls/1405":
                    reads.append(path)
                    if kind == "race" and len(reads) > 1:
                        self.api.responses[path]["head"]["sha"] = "f" * 40
                if kind == "access" and path.startswith("pulls/"):
                    raise ci.OriginalCIUnavailable("unavailable")
                return original(path, raw=raw)
            self.api.get = get
            with self.subTest(kind=kind):
                result = self.verify()
                self.assertEqual("authenticated", result["originalProvenance"])
                self.assertEqual("unknown", result["ci"])

    def test_complete_bounded_pr_pagination_and_late_matching_path_are_not_omitted(self):
        paths = [f"docs/item-{number}.md" for number in range(299)] + ["tools/ecosystem-transparency/site.js"]
        self.api.pr_context(paths=paths)
        self.api.complete_reports()
        self.api.select_workflows(".github/workflows/ci.yml", ".github/workflows/production-beta-release.yml")
        self.assertIn("required-original-ci-workflow-not-selected", self.verify()["blockers"])
        self.assertIn("pulls/1405/files?per_page=100&page=3", self.api.requests)

    def test_workflow_filter_drift_is_unknown_and_caller_changed_paths_are_not_authority(self):
        self.api.complete_reports()
        original_read = ci.read_file
        def read(path):
            raw = original_read(path)
            if path == ci.ROOT / ".github/workflows/public-ecosystem-transparency.yml":
                raw = raw.replace(b"tools/ecosystem-transparency/**", b"unrelated/**")
            return raw
        with patch.object(ci, "read_file", side_effect=read):
            result = self.verify()
        self.assertEqual("unknown", result["ci"])
        self.assertIn("original-ci-workflow-trigger-policy-drift", result["blockers"])
        self.api.selection["changedPaths"] = ["docs/unrelated.md"]
        with self.assertRaises(ValueError):
            self.verify()

    def test_original_access_denial_is_unverified_not_invalid_evidence(self):
        self.api.get = lambda *args, **kwargs: (_ for _ in ()).throw(ci.OriginalCIUnavailable("unavailable"))
        result = self.verify()
        self.assertEqual("unverified", result["originalProvenance"])
        self.assertIn("original-ci-access-unavailable", result["blockers"])

    def test_transport_rejects_nonallowlisted_endpoint_before_any_credential_or_network_use(self):
        client = object.__new__(ci._GitHub)
        for target in ("https://private-canary.invalid/path", "actions/workflows/ci.yml/dispatches",
                       "actions/runs/1/jobs", "actions/runs/1/attempts/2/jobs?per_page=1000"):
            with self.subTest(target=target), self.assertRaisesRegex(ValueError, "^phase12-original-ci-invalid$"):
                client.get(target)

    def test_genuine_original_report_contract_has_conditional_complete_admission_path(self):
        self.api.complete_reports()
        result = self.verify()
        self.assertEqual("executed-pass", result["ci"])
        self.assertEqual([], result["blockers"])
        self.assertEqual("authenticated", result["originalProvenance"])
        facts = next(job["reportFacts"] for run in result["records"] for job in run["jobs"] if job.get("reportFacts"))
        self.assertGreater(facts["totals"]["tests"], 0)
        self.assertEqual("owner-skipped-standard-build", facts["sonarLint"])
        # The same serialized record does not carry the isolated original API authority offline.
        result = ci.verify(encoded(self.api.selection), SOURCE, AS_OF)
        self.assertEqual("unverified", result["originalProvenance"])

    def test_original_report_count_findings_skips_and_stale_execution_prevent_completion(self):
        for mutation in ("warning", "skipped", "stale", "missing"):
            self.api = OriginalAPI()
            self.api.complete_reports()
            rows = self.api.report_value["rows"]
            if mutation == "warning":
                next(row for row in rows if row["kind"].startswith("errorprone"))["reports"][0]["counts"]["warnings"] = 1
            elif mutation == "skipped":
                next(row for row in rows if row["kind"] == "junit")["reports"][0]["counts"]["skipped"] = 1
            elif mutation == "stale":
                rows[0]["reports"][0]["executedAt"] = "2026-09-09T11:00:00Z"
            else:
                rows[0]["reports"] = []
            self.api.replace_reports()
            with self.subTest(mutation=mutation):
                self.assertNotEqual("executed-pass", self.verify()["ci"])

    def test_cohort_shrink_unrelated_signature_and_reuploaded_archive_cannot_pass(self):
        for mutation in ("cohort", "signature", "attempt", "bytes", "private-extra"):
            self.api = OriginalAPI()
            self.api.complete_reports()
            if mutation == "cohort":
                self.api.report_value["rows"].pop()
                self.api.replace_reports()
            elif mutation == "signature":
                self.api.report_value["runAttempt"] = 3
                self.api.replace_reports(attest=False)
            elif mutation == "attempt":
                self.api.report_value["runAttempt"] = 3
                self.api.replace_reports()
            elif mutation == "bytes":
                self.api.responses["actions/artifacts/900/zip"] += b"changed"
            else:
                self.api.report_value["rows"][0]["private"] = "private-contact-canary"
                self.api.replace_reports()
            with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, "^phase12-original-ci-invalid$"):
                self.verify()

    def test_original_xml_projection_discards_private_payload_and_its_digest(self):
        for kind in ci.REPORT_KINDS:
            raw = xml(kind)
            result = encoded(ci._xml_facts(raw, kind, "."))
            self.assertNotIn(b"private-contact-canary", result)
            self.assertNotIn(hashlib.sha256(raw).hexdigest().encode(), result)
            with self.assertRaises(ValueError):
                ci._xml_facts(b'<!DOCTYPE x [<!ENTITY private "canary">]>' + raw, kind, ".")
        with self.assertRaises(ValueError):
            ci._xml_facts(xml("junit").replace(b'tests="1"', b'tests="2"'), "junit", ".")

    def test_actual_success_only_producer_reads_reports_and_emits_no_private_payload_or_hash(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(strict=True)
            (root / "settings.gradle.kts").write_text("include(" + ",".join(
                '":' + name.replace("/", ":") + '"' for name in ci.MODULES if name != ".") + ")")
            for tree in ("src/main/java", "src/test/java"):
                (root / tree).mkdir(parents=True)
                (root / tree / "ExampleTest.java").write_text("class ExampleTest {}")
            start = root / "started.json"
            start.write_bytes(encoded({"startedAt": "2026-09-10T11:00:06Z"}))
            source_reports = []
            for module, kind in ci._report_cohort(root):
                path = (root / "build/test-results/test/TEST-private-contact-canary.xml" if kind == "junit"
                        else ci._report_paths(root, module, kind)[0])
                path.parent.mkdir(parents=True, exist_ok=True)
                raw = xml(kind, module)
                path.write_bytes(raw)
                source_reports.append(raw)
            environment = {"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": ci.REPOSITORY,
                "GITHUB_JOB": "build", "GITHUB_SHA": SHA, "GITHUB_RUN_ID": "1", "GITHUB_RUN_ATTEMPT": "2"}
            environment["GITHUB_WORKFLOW_SHA"] = SHA
            with patch.object(ci, "ROOT", root), patch.object(ci, "_producer_identity", return_value="sha256:" + "c" * 64), \
                 patch.object(ci.subprocess, "run", return_value=SimpleNamespace(stdout=SHA + "\n" + SOURCE["tree"] + "\n")), \
                 patch.dict(os.environ, environment):
                result = ci.retain_reports(root / "retained", start)
            exported = (root / "retained" / ci.REPORT_FILE).read_bytes()
            self.assertEqual(5, len(result["rows"]))
            self.assertNotIn(b"private-contact-canary", exported)
            for raw in source_reports:
                self.assertNotIn(hashlib.sha256(raw).hexdigest().encode(), exported)
            self.assertEqual([ci.REPORT_FILE], [path.name for path in (root / "retained").iterdir()])

    def test_original_pr_head_product_and_real_test_merge_signer_stay_separate(self):
        self.api.complete_reports()
        merge = "d" * 40
        self.api.report_value.update(workflowSourceCommit=merge, signerCommit=merge)
        self.api.responses["git/commits/" + merge] = {"sha": merge, "parents": [{"sha": SHA}, {"sha": "e" * 40}]}
        self.api.replace_reports()
        result = self.verify()
        self.assertEqual("authenticated", result["originalProvenance"])
        self.assertIn("original-workflow-source-differs-from-audited-product", result["blockers"])
        self.assertNotEqual("executed-pass", result["ci"])
        self.api.responses["git/commits/" + merge]["parents"][0]["sha"] = "f" * 40
        with self.assertRaisesRegex(ValueError, "^phase12-original-ci-invalid$"):
            self.verify()

    def test_attested_report_member_does_not_authorize_archive_sidecars_or_metadata(self):
        for mutation in ("appended", "comment", "extra", "private-member"):
            self.api = OriginalAPI()
            self.api.complete_reports()
            content = io.BytesIO()
            with zipfile.ZipFile(content, "w") as archive:
                info = zipfile.ZipInfo(ci.REPORT_FILE)
                if mutation == "extra":
                    info.extra = b"\x01\x00\x01\x00x"
                archive.writestr(info, self.api.attested_bytes)
                if mutation == "comment":
                    archive.comment = b"private-contact-canary"
                if mutation == "private-member":
                    archive.writestr("private.xml", b"private-contact-canary")
            raw = content.getvalue() + (b"private-contact-canary" if mutation == "appended" else b"")
            self.api.responses["actions/artifacts/900/zip"] = raw
            artifact = self.api.responses["actions/runs/1/artifacts?per_page=100"]["artifacts"][0]
            artifact.update(size_in_bytes=len(raw), digest="sha256:" + hashlib.sha256(raw).hexdigest())
            with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, "^phase12-original-ci-invalid$"):
                self.verify()

    def test_executed_sonar_mode_retains_external_disposition_gap(self):
        self.api.complete_reports()
        job = next(row for row in self.api.responses["actions/runs/1/attempts/2/jobs?per_page=100"]["jobs"] if row["name"] == "build / build")
        for step in job["steps"]:
            if step["name"] == "Build and analyze (Gradle)":
                step["conclusion"] = "success"
            if step["name"] == "Build (no Sonar token)":
                step["conclusion"] = "skipped"
        result = self.verify()
        self.assertIn("original-sonarcloud-disposition-unavailable", result["blockers"])
        self.assertEqual("unknown", result["ci"])

    def test_missing_or_duplicate_original_workflow_and_paginated_job_omissions_reject(self):
        self.api.selection["runs"].pop()
        self.assertIn("required-original-ci-workflow-not-selected", self.verify()["blockers"])
        self.api = OriginalAPI()
        self.api.responses["actions/runs/1/attempts/2/jobs?per_page=100"]["total_count"] += 1
        with self.assertRaisesRegex(ValueError, "^phase12-original-ci-invalid$"):
            self.verify()


if __name__ == "__main__":
    unittest.main()
