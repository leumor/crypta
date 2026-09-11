"""Candidate freeze identity, provenance and historical format regression tests."""
from __future__ import annotations

import copy
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path
from unittest import mock

from cryptad_certification.engines import stable_1_0_maintenance_core as core
from cryptad_certification.engines.stable_1_0_maintenance_core import (
    CANDIDATE_FREEZE_SCHEMA,
    LoadedJson,
    _candidate_freeze_errors,
    _candidate_provenance_errors,
    stable_catalog_verification_identity,
)
from cryptad_certification.engines.stable_1_0_rc_core import (
    ValidationState,
    file_digest,
    semantic_digest,
)
from cryptad_certification.io import write_json
from cryptad_certification.schema_validation import validate_schema
from cryptad_certification.tests.test_stable_maintenance import (
    BUILD, COMMIT, FROZEN, PRODUCT_DIGEST, RELEASE_ID,
    _candidate_input, _context, _digest, _ga_and_predecessor, _redaction, _timestamp,
)


class StableMaintenanceCandidateFreezeTest(unittest.TestCase):
    def test_candidate_authentication_passes_exact_predecessor_to_freeze_verifier(self) -> None:
        for release_class in ("maintenance", "security-hotfix"):
            for follow_up in (False, True):
                with self.subTest(release_class=release_class, follow_up=follow_up), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory).resolve()
                    context = _context(root)
                    context.manifest.policies["releaseClass"] = release_class
                    candidate = _candidate_input(release_class)
                    _, predecessor = _ga_and_predecessor()
                    subject = root / "synthetic-subject"
                    subject.write_bytes(b"synthetic candidate input")
                    loaded = LoadedJson("maintenanceCandidate", subject, candidate, file_digest(subject))
                    expected = {
                        "sourceCommit": predecessor.source_commit,
                        "releaseId": predecessor.release_id,
                        "buildVersion": predecessor.build_version,
                        "productDigest": predecessor.product_digest,
                        "baselineDigest": predecessor.baseline_digest,
                        "publicationReceiptDigest": predecessor.receipt_digest,
                        "latestPublishedPointerDigest": predecessor.latest_pointer_digest,
                    }
                    override = dict(expected, sourceCommit="d" * 40) if follow_up else None
                    # Isolate original input acquisition and the receiving verifier. Exercise the
                    # actual authenticate_candidate caller; this is not an eligibility fixture.
                    with mock.patch.object(core, "load_json_input", return_value=loaded), \
                            mock.patch.object(core, "configured_path", return_value=subject), \
                            mock.patch.object(core, "_asset_root", return_value=root), \
                            mock.patch.object(core, "_asset_path", return_value=subject), \
                            mock.patch.object(core, "_candidate_freeze_errors", return_value=[]) as verify:
                        core.authenticate_candidate(context, predecessor, {}, ValidationState(),
                            freeze_predecessor_observation=override)
                    self.assertEqual(override if follow_up else expected, verify.call_args.args[3])


    def test_candidate_freeze_binds_one_build_assets_and_predecessor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            context = _context(root)
            candidate = _candidate_input()
            _, predecessor = _ga_and_predecessor()
            expected_assets = [
                {
                    "role": "product",
                    "fileName": "cryptad-301.tar.gz",
                    "digest": PRODUCT_DIGEST,
                    "sizeBytes": 1024,
                    "packageKey": None,
                    "os": None,
                    "arch": None,
                    "producerArchitecture": None,
                    "packageType": None,
                    "publicAsset": True,
                    "signingStatus": "pass",
                    "notarizationStatus": "not-applicable",
                },
                {
                    "role": "stable-catalog",
                    "fileName": "stable-catalog.json",
                    "digest": candidate["stableCatalog"]["digest"],
                    "sizeBytes": 1024,
                    "packageKey": None,
                    "os": None,
                    "arch": None,
                    "producerArchitecture": None,
                    "packageType": None,
                    "publicAsset": True,
                    "signingStatus": "pass",
                    "notarizationStatus": "not-applicable",
                },
                {
                    "role": "stable-catalog-signature",
                    "fileName": "stable-catalog.json.sig",
                    "digest": candidate["stableCatalog"]["signatureDigest"],
                    "sizeBytes": 256,
                    "packageKey": None,
                    "os": None,
                    "arch": None,
                    "producerArchitecture": None,
                    "packageType": None,
                    "publicAsset": True,
                    "signingStatus": "pass",
                    "notarizationStatus": "not-applicable",
                },
                {
                    "role": "package",
                    "fileName": "cryptad-301-amd64.deb",
                    "digest": _digest("a"),
                    "sizeBytes": 2048,
                    "packageKey": "amd64.deb",
                    "os": "linux",
                    "arch": "amd64",
                    "producerArchitecture": "amd64",
                    "packageType": "deb",
                    "publicAsset": True,
                    "signingStatus": "pass",
                    "notarizationStatus": "not-applicable",
                },
            ]
            catalog_verification = stable_catalog_verification_identity(
                candidate["stableCatalog"], _digest("9")
            )
            catalog_verification_digest = semantic_digest(catalog_verification)
            frozen_assets = []
            for index, row in enumerate(expected_assets):
                signing_receipt_digest = _digest(str(index + 1))
                if row["role"] in {
                    "stable-catalog",
                    "stable-catalog-signature",
                }:
                    signing_receipt_digest = catalog_verification_digest
                frozen_assets.append(
                    {
                        **row,
                        "signingReceiptDigest": signing_receipt_digest,
                        "notarizationReceiptDigest": None,
                    }
                )
            freeze = {
                "schemaVersion": 1,
                "kind": "stable-1.0-maintenance-candidate-freeze",
                "generatedAt": _timestamp(FROZEN),
                "frozenAt": _timestamp(FROZEN),
                "stableMilestone": "1.0",
                "releaseId": RELEASE_ID,
                "buildVersion": BUILD,
                "releaseClass": "maintenance",
                "source": candidate["source"],
                "toolchain": candidate["toolchain"],
                "producer": {
                    "system": "github-actions",
                    "repository": "crypta-network/cryptad",
                    "workflowPath": ".github/workflows/stable-1.0-maintenance-release.yml",
                    "workflowCommit": COMMIT,
                    "runId": "1001",
                    "runAttempt": 1,
                    "runnerEnvironment": "github-hosted",
                    "producerIdentityReceiptDigest": _digest("4"),
                    "sourceRefReceiptDigest": _digest("5"),
                    "buildReceiptDigest": _digest("6"),
                    "authenticationStatus": "pass",
                },
                "predecessorObservation": {
                    "releaseId": predecessor.release_id,
                    "buildVersion": predecessor.build_version,
                    "productDigest": predecessor.product_digest,
                    "baselineDigest": predecessor.baseline_digest,
                    "publicationReceiptDigest": predecessor.receipt_digest,
                    "latestPublishedPointerDigest": None,
                    "observedAt": _timestamp(FROZEN - timedelta(minutes=1)),
                    "status": "latest-published",
                },
                "stableCatalogVerification": catalog_verification,
                "buildCount": 1,
                "rebuildPerformed": False,
                "checksumsDigest": _digest("7"),
                "assets": frozen_assets,
                "assetSetDigest": semantic_digest(
                    sorted(frozen_assets, key=lambda row: row["fileName"])
                ),
                "redaction": _redaction(),
            }
            freeze_path = root / "candidate-freeze.json"
            write_json(freeze_path, freeze)
            candidate["candidateFreezeDigest"] = file_digest(freeze_path)
            loaded = LoadedJson(
                "maintenanceCandidateFreeze",
                freeze_path,
                freeze,
                file_digest(freeze_path),
            )

            errors = _candidate_freeze_errors(
                context,
                loaded,
                candidate,
                predecessor,
                expected_assets,
                _digest("7"),
            )

            self.assertEqual(validate_schema(freeze, CANDIDATE_FREEZE_SCHEMA), [])
            self.assertEqual(errors, [])
            # v1 has no predecessor source binding. v2 must accept the authenticated SHA and
            # reject substitution independently of its separate runtime-metadata gate.
            for source_commit in (predecessor.source_commit, "d" * 40):
                prospective = copy.deepcopy(freeze)
                prospective["schemaVersion"] = 2
                prospective["predecessorObservation"]["sourceCommit"] = source_commit
                prospective["runtimeMetadata"] = {"fileName": "runtime-subjects.json",
                    "digest": _digest("8"), "sizeBytes": 2}
                prospective_path = root / "prospective-freeze.json"
                write_json(prospective_path, prospective)
                prospective_candidate = dict(candidate, candidateFreezeDigest=file_digest(prospective_path))
                prospective_loaded = LoadedJson("maintenanceCandidateFreeze", prospective_path,
                    prospective, file_digest(prospective_path))
                prospective_errors = _candidate_freeze_errors(context, prospective_loaded,
                    prospective_candidate, predecessor, expected_assets, _digest("7"))
                expected_errors = ["candidate freeze runtime metadata is missing or does not bind exact inputs"]
                if source_commit != predecessor.source_commit:
                    expected_errors.append("candidate freeze used a stale or substituted predecessor observation")
                self.assertEqual(expected_errors, prospective_errors)
            unverified_catalog = copy.deepcopy(freeze)
            unverified_catalog["stableCatalogVerification"][
                "cryptographicVerificationStatus"
            ] = "fail"
            unverified_path = root / "unverified-catalog.json"
            write_json(unverified_path, unverified_catalog)
            unverified_loaded = LoadedJson(
                "maintenanceCandidateFreeze",
                unverified_path,
                unverified_catalog,
                file_digest(unverified_path),
            )
            unverified_candidate = copy.deepcopy(candidate)
            unverified_candidate["candidateFreezeDigest"] = unverified_loaded.digest
            self.assertIn(
                "candidate freeze lacks exact cryptographic Stable catalog verification",
                _candidate_freeze_errors(
                    context,
                    unverified_loaded,
                    unverified_candidate,
                    predecessor,
                    expected_assets,
                    _digest("7"),
                ),
            )
            wrong_catalog_receipt = copy.deepcopy(freeze)
            wrong_catalog_receipt["assets"][1]["signingReceiptDigest"] = _digest(
                "unverified-catalog"
            )
            wrong_catalog_receipt["assetSetDigest"] = semantic_digest(
                sorted(
                    wrong_catalog_receipt["assets"],
                    key=lambda row: row["fileName"],
                )
            )
            wrong_catalog_receipt_path = root / "wrong-catalog-receipt.json"
            write_json(wrong_catalog_receipt_path, wrong_catalog_receipt)
            wrong_catalog_receipt_loaded = LoadedJson(
                "maintenanceCandidateFreeze",
                wrong_catalog_receipt_path,
                wrong_catalog_receipt,
                file_digest(wrong_catalog_receipt_path),
            )
            wrong_catalog_receipt_candidate = copy.deepcopy(candidate)
            wrong_catalog_receipt_candidate["candidateFreezeDigest"] = (
                wrong_catalog_receipt_loaded.digest
            )
            self.assertIn(
                "candidate freeze catalog signature verification receipt is invalid for stable-catalog.json",
                _candidate_freeze_errors(
                    context,
                    wrong_catalog_receipt_loaded,
                    wrong_catalog_receipt_candidate,
                    predecessor,
                    expected_assets,
                    _digest("7"),
                ),
            )
            misbound_notarization = copy.deepcopy(freeze)
            misbound_notarization["assets"][3]["notarizationStatus"] = "pass"
            misbound_notarization["assets"][3]["notarizationReceiptDigest"] = _digest(
                "mac-notarization"
            )
            misbound_notarization["assetSetDigest"] = semantic_digest(
                sorted(
                    misbound_notarization["assets"],
                    key=lambda row: row["fileName"],
                )
            )
            misbound_path = root / "misbound-notarization.json"
            write_json(misbound_path, misbound_notarization)
            misbound_loaded = LoadedJson(
                "maintenanceCandidateFreeze",
                misbound_path,
                misbound_notarization,
                file_digest(misbound_path),
            )
            misbound_candidate = copy.deepcopy(candidate)
            misbound_candidate["candidateFreezeDigest"] = misbound_loaded.digest
            self.assertIn(
                "candidate freeze non-DMG asset carries notarization for cryptad-301-amd64.deb",
                _candidate_freeze_errors(
                    context,
                    misbound_loaded,
                    misbound_candidate,
                    predecessor,
                    expected_assets,
                    _digest("7"),
                ),
            )
            provenance = {
                "kind": "stable-1.0-maintenance-candidate-provenance",
                "releaseId": RELEASE_ID,
                "buildVersion": BUILD,
                "releaseClass": "maintenance",
                "source": candidate["source"],
                "productDigest": PRODUCT_DIGEST,
                "candidateInputDigest": _digest("8"),
                "candidateFreezeDigest": loaded.digest,
                "assets": [
                    {"name": row["fileName"], "digest": row["digest"]}
                    for row in expected_assets
                ],
                "redaction": _redaction(),
            }
            expected_asset_map = {
                row["fileName"]: row["digest"] for row in expected_assets
            }
            self.assertEqual(
                _candidate_provenance_errors(
                    context,
                    provenance,
                    candidate["source"],
                    PRODUCT_DIGEST,
                    _digest("8"),
                    loaded.digest,
                    expected_asset_map,
                ),
                [],
            )
            substituted_provenance = copy.deepcopy(provenance)
            substituted_provenance["candidateFreezeDigest"] = _digest("0")
            self.assertTrue(
                _candidate_provenance_errors(
                    context,
                    substituted_provenance,
                    candidate["source"],
                    PRODUCT_DIGEST,
                    _digest("8"),
                    loaded.digest,
                    expected_asset_map,
                )
            )

            rebuilt = copy.deepcopy(freeze)
            rebuilt["buildCount"] = 2
            write_json(root / "rebuilt.json", rebuilt)
            wrong_architecture = copy.deepcopy(freeze)
            wrong_architecture["assets"][2]["producerArchitecture"] = "arm64"
            wrong_architecture["assetSetDigest"] = semantic_digest(
                sorted(wrong_architecture["assets"], key=lambda row: row["fileName"])
            )
            wrong_architecture_path = root / "wrong-architecture.json"
            write_json(wrong_architecture_path, wrong_architecture)
            wrong_architecture_loaded = LoadedJson(
                "maintenanceCandidateFreeze",
                wrong_architecture_path,
                wrong_architecture,
                file_digest(wrong_architecture_path),
            )
            wrong_architecture_candidate = copy.deepcopy(candidate)
            wrong_architecture_candidate["candidateFreezeDigest"] = (
                wrong_architecture_loaded.digest
            )

            self.assertTrue(
                _candidate_freeze_errors(
                    context,
                    wrong_architecture_loaded,
                    wrong_architecture_candidate,
                    predecessor,
                    expected_assets,
                    _digest("7"),
                )
            )
            candidate["candidateFreezeDigest"] = file_digest(root / "rebuilt.json")
            rebuilt_loaded = LoadedJson(
                "maintenanceCandidateFreeze",
                root / "rebuilt.json",
                rebuilt,
                file_digest(root / "rebuilt.json"),
            )
            self.assertTrue(
                _candidate_freeze_errors(
                    context,
                    rebuilt_loaded,
                    candidate,
                    predecessor,
                    expected_assets,
                    _digest("7"),
                )
            )

            replaced = copy.deepcopy(freeze)
            replaced["assets"][0]["digest"] = _digest("f")
            replaced["assetSetDigest"] = semantic_digest(replaced["assets"])
            write_json(root / "replaced.json", replaced)
            candidate["candidateFreezeDigest"] = file_digest(root / "replaced.json")
            replaced_loaded = LoadedJson(
                "maintenanceCandidateFreeze",
                root / "replaced.json",
                replaced,
                file_digest(root / "replaced.json"),
            )
            self.assertTrue(
                _candidate_freeze_errors(
                    context,
                    replaced_loaded,
                    candidate,
                    predecessor,
                    expected_assets,
                    _digest("7"),
                )
            )
