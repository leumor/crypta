"""Closed PR-302 consumer integration; reviewed local status is never original authority."""
import base64
import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cryptad_certification import phase_12_closeout as audit
from cryptad_certification import transparency_adapters as adapters
from cryptad_certification import transparency_bundle as bundle
from cryptad_certification import transparency_sources as sources


class Phase12PublicTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve(strict=True)
        self.value = audit.public_projection(audit.evaluate(audit.repository_selection(), self.root, "2026-09-10T00:00:00Z"))

    def rules(self, values):
        rules, _ = sources.policy()
        rules = copy.deepcopy(rules)
        rules["approvedSources"].extend({"role": "phase-assessment", "digest": sources.digest(raw),
            "size": len(raw), "disclosureRule": "reviewed-phase12-public-status-v1",
            "evidenceClass": "repository-local-assessment"} for raw in values)
        return rules, sources.digest(sources.canonical(rules))

    def package(self, values, policy_digest, when="2026-09-10T00:00:00Z"):
        rows = [{"role": "phase-assessment", "file": f"source-{index:02d}.json", "digest": sources.digest(raw),
                 "size": len(raw), "required": True} for index, raw in enumerate(values)]
        return {"schemaVersion": 1, "policyDigest": policy_digest,
                "selection": {"schemaVersion": 1, "mode": "production", "asOf": when, "sources": rows},
                "members": [{"file": row["file"], "bytes": base64.b64encode(raw).decode()}
                            for row, raw in zip(rows, values)]}

    def test_local_assessment_needs_new_exact_reviewed_pin(self):
        raw = sources.canonical(self.value)
        rules, pin = sources.policy()
        with self.assertRaisesRegex(ValueError, "source-not-approved"):
            sources.admit(self.package([raw], pin))
        approved, pin = self.rules([raw])
        with patch.object(sources, "policy", return_value=(approved, pin)):
            result = sources.admit(self.package([raw], pin))
        record = result["records"][0]
        self.assertEqual("repository-local-assessment", record["evidenceClass"])
        self.assertEqual("not-established", record["publication"])
        self.assertEqual("not-established", record["activation"])
        self.assertEqual("not-exported", record["fields"]["originalProducerProof"])
        self.assertEqual([raw], list(result["downloads"].values()))
        self.assertFalse(record["fields"]["phaseComplete"])

    def test_pin_does_not_authorize_private_fields_or_changed_dimensions(self):
        attacks = []
        for key, canary in (("incidentId", "private-incident-canary"), ("contactDigest", "sha256:" + "f" * 64),
                            ("privatePath", "/private/source-canary"), ("url", "https://private.invalid/token")):
            value = copy.deepcopy(self.value)
            value[key] = canary
            attacks.append(value)
        value = copy.deepcopy(self.value)
        value["requirements"][0]["dimensions"]["implementation"] = "private-contact-canary"
        attacks.append(value)
        for value in attacks:
            raw = sources.canonical(value)
            rules, pin = self.rules([raw])
            with self.subTest(keys=list(value)), patch.object(sources, "policy", return_value=(rules, pin)):
                with self.assertRaises(ValueError) as caught:
                    sources.admit(self.package([raw], pin))
            self.assertNotIn("canary", str(caught.exception))

    def test_cohort_shrink_duplicate_fake_complete_and_synthetic_promotion_reject(self):
        for mutation in ("omit", "duplicate", "dimension", "complete", "synthetic"):
            value = copy.deepcopy(self.value)
            if mutation == "omit":
                value["requirements"].pop()
            elif mutation == "duplicate":
                value["requirements"][-1] = value["requirements"][0]
            elif mutation == "dimension":
                value["requirements"][0]["dimensions"].pop("implementation")
            elif mutation == "complete":
                value.update(phaseComplete=True, phaseDecision="complete-as-of")
            else:
                value["classification"] = "synthetic-test-only"
            raw = sources.canonical(value)
            rules, pin = self.rules([raw])
            with self.subTest(mutation=mutation), patch.object(sources, "policy", return_value=(rules, pin)), self.assertRaises(ValueError):
                sources.admit(self.package([raw], pin))

    def test_immutable_prior_revision_is_retained_and_original_time_preserved(self):
        old = sources.canonical(self.value)
        newer = copy.deepcopy(self.value)
        newer["asOf"] = "2026-09-10T01:00:00Z"
        new = sources.canonical(newer)
        rules, pin = self.rules([old, new])
        with patch.object(sources, "policy", return_value=(rules, pin)):
            previous, _ = bundle.make_index(self.package([old], pin))
            current, _ = bundle.make_index(self.package([old, new], pin, newer["asOf"]))
            bundle.check_history(current, previous)
            self.assertEqual(self.value["asOf"], current["sources"][0]["observedAt"])
            removed, _ = bundle.make_index(self.package([new], pin, newer["asOf"]))
            with self.assertRaisesRegex(ValueError, "selected-history-removed"):
                bundle.check_history(removed, previous)

    def test_same_public_inputs_build_identical_bytes_and_visible_classification(self):
        raw = sources.canonical(self.value)
        rules, pin = self.rules([raw])
        with patch.object(sources, "policy", return_value=(rules, pin)):
            package = self.package([raw], pin)
            bundle.build(package, self.root / "one")
            bundle.build(package, self.root / "two")
            self.assertEqual(bundle.inventory(self.root / "one"), bundle.inventory(self.root / "two"))
            bundle.verify(self.root / "one", production=True)
            html = (self.root / "one/readiness/index.html").read_bytes()
            self.assertIn(b"repository-local-assessment", html)
            self.assertIn(b"phaseComplete", html)
            self.assertNotIn(b"private-contact-canary", b"".join(bundle.inventory(self.root / "one").values()))

    def test_public_record_is_not_an_original_closeout_artifact(self):
        with self.assertRaises(ValueError):
            from cryptad_certification.phase_12_adapters import verify
            verify("phase-assessment", {"phase-12-public-status.json": sources.canonical(self.value)},
                   self.value["asOf"], self.root)


if __name__ == "__main__":
    unittest.main()
