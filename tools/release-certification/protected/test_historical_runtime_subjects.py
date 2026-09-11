"""Offline boundary regressions; these tests never mint original runtime evidence."""
import io
import json
import zipfile
from types import SimpleNamespace
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import historical_runtime_subjects as historical
from maintenance_runtime_metadata import FIRST_PARTY, RuntimeMetadataError, semantic_digest


class HistoricalRuntimeSubjectsTest(unittest.TestCase):
    def original_row(self):
        return {"artifactDigest": "sha256:" + "1" * 64, "artifactSize": 123,
            "sourceCommit": "2" * 40, "rcProductDigest": "sha256:" + "3" * 64,
            "rcFreezeDigest": "sha256:" + "4" * 64,
            "rcOrigin": {"sourceFamily": "stable-rc-product"},
            "historicalShippedSubjects": [{"appId": app, "bundleDigest": "sha256:" + "5" * 64}
                for app in sorted(FIRST_PARTY)],
            "historicalShippedCatalog": {"channel": "stable", "catalogDigest": "sha256:" + "6" * 64}}

    def test_original_inventory_reopens_actual_authenticated_zip_member(self):
        raw = b'{"syntheticInventory":"exact original bytes"}\n'
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w") as output:
            output.writestr("platform-api-1.x-app-subject-inventory.json", raw)
        original = SimpleNamespace(content=archive.getvalue())
        inventory = json.loads(raw)
        authority = SimpleNamespace(digest=historical.digest_bytes(raw), matches=lambda item: item == inventory)
        self.assertEqual(raw, historical._original_inventory_bytes(original, authority))
        authority.digest = "sha256:" + "0" * 64
        with self.assertRaisesRegex(RuntimeMetadataError, "historical-original-projection-substituted"):
            historical._original_inventory_bytes(original, authority)

    def test_current_candidate_cannot_use_later_observation_as_prospective_freeze(self):
        row = self.original_row()
        node = {"role": "candidate-sender", **{key: row[key] for key in (
            "artifactDigest", "artifactSize", "sourceCommit")}}
        with tempfile.TemporaryDirectory() as root, patch.object(historical.projection, "_cohort") as policy:
            with self.assertRaisesRegex(RuntimeMetadataError, "historical-product-selection-invalid"):
                historical.observe_historical_product(row, node,
                    {"coordinates": {}, "cohortDigest": "sha256:" + "7" * 64}, Path(root))
            policy.assert_not_called()

    def test_old_maintenance_freeze_cannot_infer_missing_shipped_inventory(self):
        row = self.original_row()
        row.pop("historicalShippedSubjects")
        with self.assertRaisesRegex(RuntimeMetadataError, "historical-original-shipped-inventory-unsupported"):
            historical._original_shipped_binding(row)

    def test_omitted_shipped_app_cannot_be_replaced_by_experimental_mail(self):
        row = self.original_row()
        row["historicalShippedSubjects"][0]["appId"] = "mail-prototype"
        with self.assertRaisesRegex(RuntimeMetadataError, "historical-original-shipped-inventory-unsupported"):
            historical._original_shipped_binding(row)

    def test_original_release_app_bytes_and_catalog_both_change_shipped_commitment(self):
        row = self.original_row()
        first = semantic_digest(historical._original_shipped_binding(row))
        row["historicalShippedSubjects"][0]["bundleDigest"] = "sha256:" + "8" * 64
        second = semantic_digest(historical._original_shipped_binding(row))
        row["historicalShippedCatalog"]["catalogDigest"] = "sha256:" + "9" * 64
        third = semantic_digest(historical._original_shipped_binding(row))
        self.assertEqual(3, len({first, second, third}))
        self.assertEqual("original-rc-frozen-shipped-subjects",
                         historical._original_shipped_binding(row)["provenance"])

    def test_invalid_selection_preserves_existing_private_output(self):
        row = self.original_row()
        with tempfile.TemporaryDirectory() as root:
            output = Path(root) / "historical-runtime-previous"
            output.mkdir()
            existing = output / "owner-record"
            existing.write_bytes(b"retain original bytes")
            with self.assertRaises(RuntimeMetadataError):
                historical.observe_historical_product(row, {"role": "previous"}, {}, Path(root))
            self.assertEqual(b"retain original bytes", existing.read_bytes())


if __name__ == "__main__":
    unittest.main()
