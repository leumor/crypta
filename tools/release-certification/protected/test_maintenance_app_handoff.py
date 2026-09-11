"""Original prefreeze handoff authentication regressions with isolated attestation transport."""
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import app_subject_projection as projection
from original_artifact_authentication import OriginalArtifact
import test_app_subject_projection as fixtures


class MaintenanceAppHandoffTest(unittest.TestCase):
    def fixture(self):
        inventory, _, _ = fixtures.ProjectionBoundaryTest().inventory()
        declarations = [row["signedProjection"] for row in inventory["subjects"]
                        if row["appId"] in projection.FIRST_PARTY]
        members = {"catalogs/stable.properties": b"synthetic exact catalog",
                   "catalogs/stable.properties.sig": b"synthetic exact signature"}
        subjects = []
        for declaration in declarations:
            app = declaration["appId"]
            name = f"apps/{app}.zip"
            members[name] = b"synthetic exact signed archive " + app.encode()
            declaration["bundleSize"] = len(members[name])
            declaration["bundleDigest"] = self.digest(members[name])
            declaration["catalogDigest"] = self.digest(members["catalogs/stable.properties"])
            declaration["catalogSignatureDigest"] = self.digest(members["catalogs/stable.properties.sig"])
            subjects.append({"appId": app, "members": {"catalog": "catalogs/stable.properties",
                "catalogSignature": "catalogs/stable.properties.sig", "bundle": name}, "signedProjection": declaration})
        coordinates = {"repository": "crypta-network/cryptad", "sourceFamily": "maintenance-app-products",
            "sourceCommit": "a" * 40, "runId": 123, "runAttempt": 2, "jobId": 456,
            "jobName": "Build and authenticate prospective maintenance app products",
            "artifactId": 789, "artifactName": "maintenance-app-products-123-2",
            "artifactDigest": "sha256:" + "0" * 64, "artifactSize": 1}
        handoff = {"schemaVersion": 1, "kind": "maintenance-app-subject-handoff", "sourceCommit": "b" * 40,
            "releaseId": "synthetic-maintenance", "buildVersion": "2000", "generatedAt": "2026-09-11T01:00:00Z",
            "cohortPolicy": "historical-seven", "producer": {"repository": "crypta-network/cryptad",
                "workflowPath": ".github/workflows/stable-1.0-maintenance-release.yml", "workflowSourceCommit": "a" * 40,
                "runId": 123, "runAttempt": 2, "jobName": coordinates["jobName"]}, "subjects": subjects,
            "members": [{"fileName": name, "digest": self.digest(value), "sizeBytes": len(value)}
                        for name, value in sorted(members.items())]}
        return handoff, members, coordinates

    @staticmethod
    def digest(raw):
        return "sha256:" + hashlib.sha256(raw).hexdigest()

    def verify(self, handoff, members, coordinates, *, extra=None, proofs=True):
        raw = json.dumps(handoff, sort_keys=True).encode()
        zipped = io.BytesIO()
        with zipfile.ZipFile(zipped, "w") as archive:
            archive.writestr("maintenance-app-subject-handoff.json", raw)
            for name, payload in {**members, **(extra or {})}.items():
                archive.writestr(name, payload)
        coordinates = dict(coordinates, artifactDigest=self.digest(zipped.getvalue()), artifactSize=len(zipped.getvalue()))
        original = OriginalArtifact(zipped.getvalue(), coordinates, "2026-09-11T02:00:00Z")
        selected = handoff["subjects"][0]
        source = {"original": coordinates, "originalInventory": coordinates, "catalogOriginal": None,
            "sourceAuthorityRoot": self.digest(raw), "sourceEvidenceDigest": self.digest(raw), "members": selected["members"]}
        proof = [{"verificationResult": {"signature": {"certificate": {
            "runInvocationURI": "https://github.com/crypta-network/cryptad/actions/runs/123/attempts/2"}}}}] if proofs else []
        with tempfile.TemporaryDirectory() as root, patch.object(projection, "_environment", return_value={}), patch.object(projection, "_gh", return_value=proof) as transport:
            projection.verify_upstream_subject(source, selected["signedProjection"], original, Path(root))
            return transport.call_count

    def test_closed_original_member_handoff_accepts_exact_attempt_without_independent_claim(self):
        handoff, members, coordinates = self.fixture()
        self.assertEqual(len(members) + 1, self.verify(handoff, members, coordinates))
        self.assertNotIn("independentReproducibility", handoff)
        self.assertNotEqual(handoff["sourceCommit"], handoff["producer"]["workflowSourceCommit"])

    def test_substituted_member_rejects_before_attestation(self):
        handoff, members, coordinates = self.fixture()
        members["catalogs/stable.properties"] += b"!"
        with self.assertRaisesRegex(projection.ProjectionFailure, "member-substituted"):
            self.verify(handoff, members, coordinates)

    def test_extra_unbound_member_rejects(self):
        with self.assertRaisesRegex(projection.ProjectionFailure, "unbound-member"):
            self.verify(*self.fixture(), extra={"unexpected": b"must not survive"})

    def test_wrong_original_attempt_rejects(self):
        with self.assertRaisesRegex(projection.ProjectionFailure, "attested-attempt-mismatch"):
            self.verify(*self.fixture(), proofs=False)

    def test_missing_shipped_app_rejects(self):
        handoff, members, coordinates = self.fixture()
        handoff["subjects"].pop()
        with self.assertRaisesRegex(projection.ProjectionFailure, "handoff-schema-invalid"):
            self.verify(handoff, members, coordinates)

    def test_boolean_attempt_cannot_equal_integer_original_identity(self):
        handoff, members, coordinates = self.fixture()
        coordinates["runAttempt"] = 1
        handoff["producer"]["runAttempt"] = True
        with self.assertRaisesRegex(projection.ProjectionFailure, "handoff-schema-invalid"):
            self.verify(handoff, members, coordinates)

    def test_runtime_inventory_version_does_not_upgrade_original_api_authority(self):
        self.assertEqual("platform-api-1.x-app-subject-inventory-v2.schema.json", projection.inventory_schema(2))
        self.assertEqual("platform-api-1.x-app-subject-inventory-v3.schema.json", projection.inventory_schema(3))
        with self.assertRaises(projection.ProjectionFailure):
            projection.inventory_schema(True)
        with self.assertRaisesRegex(projection.ProjectionFailure, "duplicate-json-key"):
            projection._strict_json(b'{"schemaVersion":2,"schemaVersion":3}')


if __name__ == "__main__":
    unittest.main()
