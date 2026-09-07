"""Adversarial tests of local conformance binding; no test fixture is runtime authority."""
from __future__ import annotations

import copy
import json
import os
import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cryptad_certification.engines import stable_content_profile_review as review


class ContentProfileReviewTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.policy = json.loads((Path(__file__).resolve().parents[2] / "content-profile-review-policy.json").read_text())
        self.suite = {"resultFile": "result.xml", "className": "synthetic.Test", "testCases": ["case()"]}

    def xml(self, body='<testcase classname="synthetic.Test" name="case()"/>'):
        (self.root / "result.xml").write_text('<testsuite>' + body + '</testsuite>')

    def test_complete_execution_binds_exact_result_bytes(self):
        self.xml()
        results = review.test_results(self.root, [self.suite])
        self.assertEqual(1, results[0]["caseCount"])
        self.assertEqual(review.digest(self.root / "result.xml"), results[0]["resultDigest"])

    def test_missing_skipped_failed_duplicate_and_substituted_tests_rejected(self):
        for body in ('', '<testcase classname="synthetic.Test" name="case()"><skipped/></testcase>',
                     '<testcase classname="synthetic.Test" name="case()"><failure/></testcase>',
                     '<testcase classname="other.Test" name="case()"/>',
                     '<testcase classname="synthetic.Test" name="different()"/>',
                     '<testcase classname="synthetic.Test" name="case()"/>' * 2):
            with self.subTest(body=body):
                self.xml(body)
                with self.assertRaises(ValueError):
                    review.test_results(self.root, [self.suite])

    def test_self_declared_pass_does_not_replace_testcases(self):
        (self.root / "result.xml").write_text('<testsuite tests="1" failures="0" status="pass"/>')
        with self.assertRaises(ValueError):
            review.test_results(self.root, [self.suite])

    def test_missing_result_stays_missing(self):
        with self.assertRaises(FileNotFoundError):
            review.test_results(self.root, [self.suite])
        self.assertIsNone(review.bound_summary(self.root))

    def test_registry_preserves_effective_status_and_original_digest_semantics(self):
        rows = [{"id": name, "majorVersion": 1, "status": "stable" if "feed" in name else "experimental"}
                for name in review.CONTENT_PROFILE_IDS]
        result = review.registry_rows({"schemaVersion": 1, "kind": "content-format-profile-registry", "profiles": rows}, self.policy)
        for source, projected in zip(rows, result):
            self.assertEqual(source["status"], projected["effectiveStatus"])
            self.assertEqual(source["status"], projected["recommendedStatus"])
            self.assertEqual(review.semantic_digest(source), projected["descriptorDigest"])

    def test_missing_duplicate_or_service_registry_rows_rejected(self):
        for ids in (review.CONTENT_PROFILE_IDS[:-1], review.CONTENT_PROFILE_IDS + ("trust.score",),
                    review.CONTENT_PROFILE_IDS[:-1] + (review.CONTENT_PROFILE_IDS[0],)):
            with self.assertRaises(ValueError):
                review.registry_rows({"schemaVersion": 1, "kind": "content-format-profile-registry",
                                      "profiles": [{"id": name} for name in ids]}, self.policy)

    def test_duplicate_cases_and_missing_profiles_rejected(self):
        directory = self.root / review.CORPUS
        directory.mkdir(parents=True)
        for cases in ([], [{"caseId": "one", "profileId": "crypta.profile.v1"}],
                      [{"caseId": "same", "profileId": name} for name in review.CONTENT_PROFILE_IDS]):
            (directory / "manifest.json").write_text(json.dumps({"cases": cases}))
            with self.assertRaises(ValueError):
                review.corpus_identity(self.root)

    def test_resealed_result_cannot_override_source_binding(self):
        path = self.root / review.SUMMARY
        path.parent.mkdir(parents=True)
        policy = self.root / review.POLICY
        policy.parent.mkdir(parents=True)
        policy.write_text('{"suites":[]}')
        data = {"source": {"commit": "wrong"}}
        data["integrityDigest"] = review.semantic_digest(data)
        path.write_text(json.dumps(data))
        with patch.object(review, "source_identity", return_value={"commit": "actual"}):
            with self.assertRaises(ValueError):
                review.bound_summary(self.root)

    def test_javascript_missing_skipped_or_substituted_case_cannot_pass(self):
        directory = self.root / review.CORPUS
        directory.mkdir(parents=True)
        manifest = directory / "manifest.json"
        manifest.write_text('{"cases":[{"caseId":"synthetic-case"}]}')
        value = {"runtime": "v24.20.0", "executedCases": ["synthetic-case", "synthetic-group"],
                 "skippedRequired": 0, "manifestDigest": review.digest(manifest).removeprefix("sha256:"),
                 "unsupportedDirections": ["javascript-production-trust-verifier", "historical-executable-reader", "independent-external-implementation"]}
        log = self.root / "javascript.log"
        log.write_text(json.dumps(value))
        policy = {"javascriptGroups": ["synthetic-group"]}
        self.assertEqual(2, review.javascript_results(self.root, log, policy)["caseCount"])
        for key, replacement in (("executedCases", ["synthetic-case"]), ("skippedRequired", 1),
                                 ("manifestDigest", "0" * 64), ("unsupportedDirections", [])):
            altered = dict(value)
            altered[key] = replacement
            log.write_text(json.dumps(altered))
            with self.assertRaises(ValueError):
                review.javascript_results(self.root, log, policy)

    def test_empty_suite_policy_cannot_claim_review(self):
        policy = copy.deepcopy(self.policy)
        policy["suites"] = []
        with self.assertRaisesRegex(ValueError, "suite-set-invalid"):
            review.validate_policy(policy)

    def test_vector_bytes_cannot_change_behind_manifest_digest(self):
        directory = self.root / review.CORPUS
        directory.mkdir(parents=True)
        vector = directory / "vector.json"
        vector.write_text('{}')
        cases = [{"caseId": str(index), "profileId": name, "inputFile": "vector.json", "inputSize": 2,
                  "inputDigest": review.digest(vector).removeprefix("sha256:")}
                 for index, name in enumerate(review.CONTENT_PROFILE_IDS)]
        (directory / "manifest.json").write_text(json.dumps({"cases": cases}))
        self.assertEqual(5, review.corpus_identity(self.root)["caseCount"])
        vector.write_text('[]')
        with self.assertRaisesRegex(ValueError, "vector-digest-mismatch"):
            review.corpus_identity(self.root)

    def test_interrupted_or_failed_execution_blocks_collector(self):
        failure = self.root / "build/content-profile-review/failure.json"
        failure.parent.mkdir(parents=True)
        failure.write_text('{"state":"incomplete-or-failed"}')
        with self.assertRaisesRegex(ValueError, "incomplete-or-failed"):
            review.bound_summary(self.root)

    def test_unreviewed_registry_status_and_version_changes_rejected(self):
        rows = [{"id": row["profileId"], "majorVersion": row["version"],
                 "status": row["effectiveStatus"]} for row in self.policy["profiles"]]
        for index in range(len(rows)):
            for field, replacement in (("status", "beta"), ("status", "deprecated"),
                                       ("status", "stable" if index != 1 else "experimental"),
                                       ("majorVersion", 2)):
                with self.subTest(index=index, field=field, replacement=replacement):
                    altered = copy.deepcopy(rows)
                    altered[index][field] = replacement
                    with self.assertRaisesRegex(ValueError, "requires-review"):
                        review.registry_rows({"schemaVersion": 1, "kind": "content-format-profile-registry",
                                              "profiles": altered}, self.policy)

    def test_policy_requires_complete_consistent_maturity_decisions(self):
        for replacement in ([], self.policy["profiles"][:-1], self.policy["profiles"] * 2):
            altered = copy.deepcopy(self.policy)
            altered["profiles"] = replacement
            with self.assertRaises(ValueError):
                review.validate_policy(altered)
        for field, value in (("recommendedStatus", "stable"), ("decision", "retain-stable"),
                             ("version", True), ("unexpected", True)):
            altered = copy.deepcopy(self.policy)
            altered["profiles"][0][field] = value
            with self.assertRaises(ValueError):
                review.validate_policy(altered)

    def test_review_refuses_existing_and_dangling_output_links_without_writes(self):
        output = self.root / "build/content-profile-review"
        output.mkdir(parents=True)
        with tempfile.TemporaryDirectory() as outside:
            target = Path(outside) / "protected"
            for name in ("execution-private.log", "javascript-private.log", "registry-private.log",
                         "registry.json", "summary.json", "failure.json"):
                for exists in (True, False):
                    with self.subTest(name=name, exists=exists):
                        if exists:
                            target.write_bytes(b"unchanged")
                        link = output / name
                        link.symlink_to(target)
                        with patch.object(review.subprocess, "run") as process:
                            self.assertEqual(1, review.run(self.root, "review"))
                            process.assert_not_called()
                        with self.assertRaises(ValueError):
                            review.bound_summary(self.root)
                        self.assertTrue(link.is_symlink())
                        self.assertEqual(exists, target.exists())
                        if exists:
                            self.assertEqual(b"unchanged", target.read_bytes())
                            target.unlink()
                        link.unlink()

    def test_review_refuses_linked_output_parent_directories(self):
        with tempfile.TemporaryDirectory() as outside:
            target = Path(outside)
            for relative in ("build", "build/content-profile-review"):
                link = self.root / relative
                link.parent.mkdir(parents=True, exist_ok=True)
                link.symlink_to(target, target_is_directory=True)
                with patch.object(review.subprocess, "run") as process:
                    self.assertEqual(1, review.run(self.root, "review"))
                    process.assert_not_called()
                self.assertEqual([], list(target.iterdir()))
                link.unlink()

    def test_execute_refuses_linked_log_before_starting_process(self):
        target = self.root / "protected"
        target.write_bytes(b"unchanged")
        log = self.root / "execution-private.log"
        log.symlink_to(target)
        with patch.object(review.subprocess, "run") as process:
            with self.assertRaises(ValueError):
                review._execute(self.root, [sys.executable, "-c", "print('synthetic')"], log)
            process.assert_not_called()
        self.assertEqual(b"unchanged", target.read_bytes())

    def test_execute_replaces_regular_or_hardlinked_logs_without_truncating_target(self):
        target = self.root / "protected"
        target.write_bytes(b"unchanged")
        log = self.root / "execution-private.log"
        os.link(target, log)
        review._execute(self.root, [sys.executable, "-c", "print('synthetic')"], log)
        self.assertEqual(b"unchanged", target.read_bytes())
        self.assertEqual(b"synthetic\n", log.read_bytes())
        review._execute(self.root, [sys.executable, "-c", "print('replacement')"], log)
        self.assertEqual(b"replacement\n", log.read_bytes())
        self.assertEqual([], list(self.root.glob(".review-log-*")))
