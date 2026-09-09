"""Offline authority and privacy negatives; no live node or operator-owned source is read."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import sharesite_observation as migration


class PrivateSelectionTest(unittest.TestCase):
    def test_absent_protected_authority_fails_before_reading_source(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(migration, "_read_selected_private_source") as reader:
            with self.assertRaisesRegex(migration.MigrationFailure, "authority-unavailable"):
                migration.observe_operator_private(SimpleNamespace(), SimpleNamespace())
            reader.assert_not_called()

    def test_sealed_selection_binds_plan_role_and_rejects_known_synthetic_relabel(self):
        from datetime import datetime, timedelta, timezone
        from app_subject_projection import _canonical_digest
        supervisor = SimpleNamespace(plan={"experimentId": "offline"})
        inputs = SimpleNamespace(role="candidate-sender", fixture=migration.OPERATOR_SOURCE_ROOT / "offline.db")
        selection = {"schemaVersion": 1, "sourceKind": "stopped-private-snapshot",
                     "sourcePath": str(inputs.fixture), "sourceDigest": "sha256:" + "b" * 64,
                     "sourceBytes": 32, "maximumBytes": 1024, "selectedIndex": 3,
                     "planDigest": _canonical_digest(supervisor.plan), "role": inputs.role,
                     "expiresAt": (datetime.now(timezone.utc) + timedelta(minutes=1)).isoformat()}
        self.assertEqual(3, migration._validate_operator_selection(selection, supervisor, inputs)["selectedIndex"])
        for field, substituted in (("role", "candidate-recipient"), ("planDigest", "sha256:" + "c" * 64),
                                   ("sourcePath", "/private/other.db"), ("selectedIndex", 10000)):
            with self.assertRaises(migration.MigrationFailure):
                migration._validate_operator_selection(dict(selection, **{field: substituted}), supervisor, inputs)
        with self.assertRaisesRegex(migration.MigrationFailure, "known-synthetic"):
            migration._validate_operator_selection(dict(selection, sourceDigest=migration.SYNTHETIC_FIXTURE_DIGEST), supervisor, inputs)

    def test_exact_private_snapshot_rejects_substitution_and_bad_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            source = root / "offline-synthetic.db"
            raw = b"SYNTHETIC unit fixture, not operator data"
            source.write_bytes(raw)
            source.chmod(0o600)
            selection = {"sourcePath": str(source), "sourceBytes": len(raw), "maximumBytes": 1024,
                         "sourceDigest": "sha256:" + hashlib.sha256(raw).hexdigest()}
            with patch.object(migration, "OPERATOR_SOURCE_ROOT", root):
                self.assertEqual(raw, migration._read_selected_private_source(selection))
                source.write_bytes(b"substituted synthetic fixture")
                with self.assertRaises(migration.MigrationFailure):
                    migration._read_selected_private_source(selection)
                source.write_bytes(raw)
                source.chmod(0o644)
                with self.assertRaisesRegex(migration.MigrationFailure, "file-invalid"):
                    migration._read_selected_private_source(selection)

    def test_private_classification_does_not_export_source_hash_or_claim_real_data(self):
        from test_app_subject_projection import MigrationAuthorityTest
        value = MigrationAuthorityTest().observation()
        value["classification"] = "operator-owned-private-observation"
        migration.validate_observation(value, require_producer=True)
        authority = migration.AuthenticatedMigration(value, migration._VERIFIED)
        from cryptad_certification.engines import stable_legacy_plugin_migration
        summary = stable_legacy_plugin_migration.summarize(value, "verify-runtime", authenticated_runtime=authority)
        self.assertEqual("not-observed", summary["realDataMigration"])
        self.assertFalse(summary["operationallyComplete"])
        for forbidden in ("sourceDigest", "sourcePath", "selectedIndex", "sourceBytes"):
            changed = dict(value, **{forbidden: "private"})
            with self.assertRaises(migration.MigrationFailure):
                migration.validate_observation(changed, require_producer=True)
        self.assertNotIn("sourceDigest", json.dumps(summary))


if __name__ == "__main__":
    unittest.main()
