"""Behavioral checks for owned execution and truthful local-only maintenance closeout."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from cryptad_certification import maintenance_drill_command as drill


class MaintenanceDrillTest(unittest.TestCase):
    def test_disk_rehearsal_executes_failure_recovery_and_cleans_owned_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "new-drill"
            with mock.patch("socket.create_connection", side_effect=AssertionError("network-denied")):
                record = drill.run(root, execute_isolated=True)
            self.assertEqual("executed", record["status"])
            self.assertEqual(list(drill.CASES), record["observedCases"])
            self.assertEqual(["summary.json"], [p.name for p in root.iterdir()])
            self.assertEqual(0, (root / "summary.json").stat().st_mode & 0o077)
            result = drill.closeout(record)
            self.assertEqual("partial", result["implementationCoverage"])
            self.assertEqual("not-observed", result["originalProtectedRuntime"])
            self.assertEqual("not-performed", result["publication"])
            self.assertEqual("not-established", drill.verify(record)["producerAuthentication"])

    def test_execution_requires_authority_and_rejects_preexisting_or_symlink_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            with self.assertRaisesRegex(ValueError, "explicit-isolated"):
                drill.run(parent / "new")
            with self.assertRaisesRegex(ValueError, "must-be-new"):
                drill.run(parent, execute_isolated=True)
            (parent / "alias").symlink_to(parent, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "must-be-new"):
                drill.run(parent / "alias" / "new", execute_isolated=True)

    def test_caller_seal_cannot_claim_protected_eligibility_or_hide_missing_cases(self):
        record = drill.plan()
        record.update(status="executed", observedCases=list(drill.CASES),
                      cleanup="owned-synthetic-state-removed")
        for key, value in (("maintenanceEligibility", "pass"), ("publication", "observed"),
                           ("missingCoverage", []), ("observedCases", list(drill.CASES[:-1]))):
            changed = copy.deepcopy(record)
            changed[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                drill.verify(drill._seal(changed))
        # Even a valid caller-written simulation claims only local integrity.
        self.assertEqual("not-established", drill.verify(drill._seal(record))["producerAuthentication"])

    def test_policy_change_and_unsealed_modification_rejected(self):
        sealed = drill._seal(drill.plan())
        changed = copy.deepcopy(sealed)
        changed["clock"] = "observed-live-time"
        with self.assertRaises(ValueError):
            drill.verify(changed)
        with mock.patch.object(drill, "_policy", return_value="sha256:" + "0" * 64):
            with self.assertRaises(ValueError):
                drill.verify(sealed)

    def test_resealed_wrong_primitive_nested_source_and_collection_types_rejected(self):
        original = drill.plan()
        changes = [
            ("schemaVersion", True), ("schemaVersion", 1.0),
            ("observedCases", None), ("observedCases", {}), ("observedCases", False),
            ("observedCases", [drill.CASES[0]] * (len(drill.CASES) + 1)),
            ("cases", tuple(drill.CASES)), ("cleanup", False), ("status", ["planned"]),
            ("checkoutIdentity", {**original["checkoutIdentity"], "commit": True}),
            ("checkoutIdentity", {**original["checkoutIdentity"], "unapprovedField": "private-path-canary"}),
            ("helperFileDigests", {key: None for key in original["helperFileDigests"]}),
        ]
        for key, value in changes:
            changed = copy.deepcopy(original)
            changed[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                drill.verify(drill._seal(changed))

    def test_failure_output_excludes_exception_canary_and_retains_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            with mock.patch("cryptad_certification.maintenance_drill_runtime.execute",
                            side_effect=RuntimeError("private-contact-canary")):
                record = drill.run(Path(temporary) / "drill", execute_isolated=True)
            self.assertEqual("failed", record["status"])
            self.assertNotIn("private-contact-canary", json.dumps(record))
            self.assertEqual("failed", drill.closeout(record)["isolatedExecution"])

    def test_duplicate_json_members_and_oversized_record_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "record.json"
            path.write_text('{"status":"planned","status":"executed"}')
            with self.assertRaisesRegex(ValueError, "duplicate"):
                drill._read(path)
            path.write_bytes(b" " * 16385)
            with self.assertRaisesRegex(ValueError, "input-invalid"):
                drill._read(path)

    def test_fixed_provider_transport_denies_unknown_calls_and_wrong_capabilities(self):
        from cryptad_certification.maintenance_drill_provider import IsolatedTransport, _provider
        from cryptad_certification.maintenance_drill_runtime import fixture, publication
        with tempfile.TemporaryDirectory() as temporary:
            bundle = fixture.BundleFixture(Path(temporary) / "bundle")
            transport = IsolatedTransport(bundle)
            with self.assertRaisesRegex(ValueError, "target-denied"):
                transport.request("GET", "https://unapproved.invalid/", headers={})
            with self.assertRaisesRegex(ValueError, "target-denied"):
                transport.digest("https://unapproved.invalid/", 1, headers={})
            provider = _provider()
            backend = provider.StableMaintenanceBackend("synthetic-github-token", transport)
            request = publication.PublicationRequest(bundle.load())
            with self.assertRaisesRegex(provider.ProviderError, "purpose-mismatch"):
                backend.publish_target("coreUpdate", request,
                                       publication.SecretMaterial("stable-catalog", "synthetic-catalog-capability"))
            self.assertFalse(transport.mutations)
            transport.calls = 2000
            with self.assertRaisesRegex(ValueError, "operation-budget"):
                transport.digest("https://unapproved.invalid/", 1, headers={})


if __name__ == "__main__":
    unittest.main()
