"""Offline tests for the protected Stable 1.0 lifecycle publication boundary."""

from __future__ import annotations

import base64
import copy
import dataclasses
import datetime as dt
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import stat
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
import urllib.error
import zipfile

from cryptad_certification.engines.stable_1_0_lifecycle_core import (
    UPDATE_KEY_IDENTITY_DIGEST,
    build_descriptor,
    build_ledger,
    entry_digest,
    ledger_digest,
)
from cryptad_certification.engines.stable_1_0_lifecycle import (
    _publication_plan as engine_publication_plan,
    _transition_set_digest as engine_transition_set_digest,
    _validate_authorization as engine_validate_authorization,
    _write_canonical_json as engine_write_canonical_json,
)
from cryptad_certification.engines.stable_1_0_rc_core import semantic_digest
from cryptad_certification.schema_validation import validate_schema


SCRIPT = (
    Path(__file__).resolve().parents[2]
    / "protected"
    / "stable_lifecycle_publication.py"
)
ROOT = Path(__file__).resolve().parents[4]
BACKEND_SOURCE = (
    ROOT
    / "tools"
    / "release-certification"
    / "publication-backend"
    / "src"
)
SPEC = importlib.util.spec_from_file_location(
    "stable_lifecycle_publication_under_test", SCRIPT
)
assert SPEC is not None and SPEC.loader is not None
publication = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = publication
SPEC.loader.exec_module(publication)

INPUT_PRODUCER_SCRIPT = (
    Path(__file__).resolve().parents[2]
    / "protected"
    / "stable_lifecycle_input_producer.py"
)
INPUT_PRODUCER_SPEC = importlib.util.spec_from_file_location(
    "stable_lifecycle_input_producer_under_test", INPUT_PRODUCER_SCRIPT
)
assert INPUT_PRODUCER_SPEC is not None and INPUT_PRODUCER_SPEC.loader is not None
input_producer = importlib.util.module_from_spec(INPUT_PRODUCER_SPEC)
sys.modules[INPUT_PRODUCER_SPEC.name] = input_producer
INPUT_PRODUCER_SPEC.loader.exec_module(input_producer)


NOW = dt.datetime(2026, 7, 21, 12, 0, tzinfo=dt.timezone.utc)
GENERATED_AT = "2026-07-21T12:00:00Z"
EXPIRES_AT = "2026-07-21T14:00:00Z"
SECRET = "USK@protected-support-lifecycle-insert-material"
KEY_DIGEST = UPDATE_KEY_IDENTITY_DIGEST
PUBLIC_URI = "https://93.184.216.34/support-lifecycle/1"
MAINTENANCE_POINTER_URI = "https://93.184.216.34/stable-1.0/maintenance/latest.json"
POLICY_DIGEST = "sha256:" + hashlib.sha256(
    (ROOT / "tools/release-certification/stable-1.0-support-lifecycle-policy.json").read_bytes()
).hexdigest()


def digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def canonical_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True).encode() + b"\n"


def file_digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_bytes(value))


def redaction() -> dict[str, object]:
    return {"status": "pass", "findingCount": 0, "findings": []}


class BundleFixture:
    """Build the same closed artifacts used by the side-effect-free lifecycle engine."""

    def __init__(self, root: Path, *, authorized: bool = True) -> None:
        self.root = root
        self.artifacts = root / "component" / "artifacts" / "legacy"
        self.artifacts.mkdir(parents=True)
        self.inventory = {
            "schemaVersion": 1,
            "kind": "stable-1.0-support-lifecycle-inventory",
            "generatedAt": GENERATED_AT,
            "stableMilestone": "1.0",
            "gaRootDigest": digest("ga-root"),
            "latestPointerDigest": None,
            "chainDepth": 0,
            "entries": [
                {
                    "releaseId": "stable-1-0-ga-300",
                    "buildVersion": "300",
                    "tag": "v300",
                    "sourceCommit": "b" * 40,
                    "releaseClass": "stable-ga",
                    "productDigest": digest("product"),
                    "publicationReceiptDigest": digest("receipt"),
                    "baselineDigest": digest("baseline"),
                    "publishedAt": "2026-07-01T00:00:00Z",
                    "chainDepth": 0,
                    "unresolvedHotfixFollowUp": False,
                }
            ],
            "status": "pass",
            "redaction": redaction(),
        }
        self.inventory["inventoryDigest"] = semantic_digest(self.inventory)
        policy = {
            "cardinality": {"minimumSimultaneouslySupportedBuilds": 1},
            "descriptor": {"maximumEntries": 256},
            "supportWindows": {
                "minimumFullMaintenanceDuration": 90,
                "minimumSecurityFixesOnlyDuration": 90,
                "minimumDeprecationNoticeDuration": 30,
                "maximumDescriptorAgeDays": 14,
            }
        }
        self.ledger, _proposed, errors = build_ledger(
            self.inventory,
            policy,
            POLICY_DIGEST,
            GENERATED_AT,
            None,
            None,
        )
        if errors:
            raise AssertionError(errors)
        transition_request_digest = semantic_digest([])
        self.transition_set = {
            "schemaVersion": 1,
            "kind": "stable-1.0-support-lifecycle-transition-set",
            "generatedAt": GENERATED_AT,
            "stableMilestone": "1.0",
            "previousLedgerDigest": None,
            "resultingLedgerDigest": self.ledger["ledgerDigest"],
            "transitionRequestDigest": transition_request_digest,
            "transitions": [],
            "redaction": redaction(),
        }
        self.transition_set["transitionSetDigest"] = publication._transition_set_digest(
            self.transition_set
        )
        self.descriptor, errors = build_descriptor(
            self.ledger, policy, GENERATED_AT, None, KEY_DIGEST
        )
        if errors:
            raise AssertionError(errors)
        self.genesis_proof = {
            "schemaVersion": 1,
            "kind": "stable-1.0-support-lifecycle-genesis-proof",
            "generatedAt": GENERATED_AT,
            "observedAt": GENERATED_AT,
            "stableMilestone": "1.0",
            "observationStatus": "absent",
            "transportStatus": 404,
            "publicRequestUri": PUBLIC_URI,
            "updateKeyIdentityDigest": KEY_DIGEST,
            "updateKeyScope": f"{KEY_DIGEST}/support-lifecycle/0",
            "updateKeyDocName": "support-lifecycle",
            "inventoryDigest": self.inventory["inventoryDigest"],
            "gaRootDigest": self.inventory["gaRootDigest"],
            "latestPointerDigest": None,
            "chainDepth": 0,
            "releaseId": "stable-1-0-ga-300",
            "buildVersion": "300",
            "baselineDigest": digest("baseline"),
            "publicationReceiptDigest": digest("receipt"),
            "provider": {
                "sourceCommit": "c" * 40,
                "artifactDigest": digest("provider"),
                "signerWorkflow": "crypta-network/cryptad/.github/workflows/stable-1.0-support-lifecycle-publication-backend-producer.yml",
            },
            "redaction": redaction(),
        }
        self.genesis_proof["proofDigest"] = semantic_digest(self.genesis_proof)
        self.provenance = {
            "schemaVersion": 1,
            "kind": "stable-1.0-support-lifecycle-provenance",
            "generatedAt": GENERATED_AT,
            "stableMilestone": "1.0",
            "gaRootDigest": self.inventory["gaRootDigest"],
            "maintenanceTipBaselineDigest": self.inventory["entries"][-1][
                "baselineDigest"
            ],
            "maintenanceTipReceiptDigest": self.inventory["entries"][-1][
                "publicationReceiptDigest"
            ],
            "latestMaintenancePointerPublicUri": MAINTENANCE_POINTER_URI,
            "inventoryDigest": self.inventory["inventoryDigest"],
            "ledgerDigest": self.ledger["ledgerDigest"],
            "descriptorDigest": self.descriptor["descriptorDigest"],
            "policyDigest": POLICY_DIGEST,
            "genesisProofDigest": self.genesis_proof["proofDigest"],
            "sideEffectsPerformed": False,
            "redaction": redaction(),
        }
        request_digest = semantic_digest(
            {
                "operation": "publish-support-lifecycle",
                "ledgerDigest": self.ledger["ledgerDigest"],
                "descriptorDigest": self.descriptor["descriptorDigest"],
                "descriptorEdition": self.descriptor["descriptorEdition"],
                "publicRequestUri": PUBLIC_URI,
                "latestMaintenancePointerPublicUri": MAINTENANCE_POINTER_URI,
                "latestMaintenancePointerDigest": None,
                "transitionRequestDigest": transition_request_digest,
                "previousLedgerDigest": None,
                "previousDescriptorDigest": None,
                "requiredRole": "stable-lifecycle-release-manager",
            }
        )
        self.authorization = {
            "schemaVersion": 1,
            "kind": "stable-1.0-support-lifecycle-authorization",
            "authorizationId": (
                "lifecycle-authorization-1" if authorized else "pending-protected-approval"
            ),
            "generatedAt": GENERATED_AT,
            "expiresAt": EXPIRES_AT if authorized else GENERATED_AT,
            "role": "stable-lifecycle-release-manager",
            "operation": "publish-support-lifecycle",
            "stableMilestone": "1.0",
            "targetLedgerDigest": self.ledger["ledgerDigest"],
            "targetDescriptorDigest": self.descriptor["descriptorDigest"],
            "targetDescriptorEdition": self.descriptor["descriptorEdition"],
            "targetPublicRequestUri": PUBLIC_URI,
            "targetLatestMaintenancePointerPublicUri": MAINTENANCE_POINTER_URI,
            "targetLatestMaintenancePointerDigest": None,
            "transitionRequestDigest": transition_request_digest,
            "previousLedgerDigest": None,
            "previousDescriptorDigest": None,
            "authorizationRequestDigest": request_digest,
            "decision": "approved" if authorized else "pending",
            "redaction": redaction(),
        }
        self.plan = {
            "schemaVersion": 1,
            "kind": "stable-1.0-support-lifecycle-publication-plan",
            "generatedAt": GENERATED_AT,
            "stableMilestone": "1.0",
            "operation": "insert-or-verify-support-lifecycle",
            "descriptorEdition": self.descriptor["descriptorEdition"],
            "descriptorDigest": self.descriptor["descriptorDigest"],
            "descriptorSizeBytes": len(canonical_bytes(self.descriptor)),
            "ledgerDigest": self.ledger["ledgerDigest"],
            "transitionSetDigest": self.transition_set["transitionSetDigest"],
            "updateKeyIdentityDigest": KEY_DIGEST,
            "updateKeyScope": f"{KEY_DIGEST}/support-lifecycle/0",
            "updateKeyDocName": "support-lifecycle",
            "publicRequestUri": PUBLIC_URI,
            "latestMaintenancePointerPublicUri": MAINTENANCE_POINTER_URI,
            "latestMaintenancePointerDigest": None,
            "previousDescriptorEdition": None,
            "previousDescriptorDigest": None,
            "authorizationDigest": file_digest(self.authorization) if authorized else None,
            "publicationAuthorized": authorized,
            "conflictPolicy": "verify-identical-or-fail-never-overwrite",
            "sideEffectsPerformed": False,
            "redaction": redaction(),
        }
        self.plan["publicationPlanDigest"] = semantic_digest(self.plan)
        self.write()

    def write(self) -> None:
        write_json(self.artifacts / publication.DESCRIPTOR_FILE, self.descriptor)
        write_json(self.artifacts / publication.LEDGER_FILE, self.ledger)
        write_json(self.artifacts / publication.TRANSITION_FILE, self.transition_set)
        write_json(self.artifacts / publication.INVENTORY_FILE, self.inventory)
        write_json(self.artifacts / publication.PROVENANCE_FILE, self.provenance)
        write_json(self.artifacts / publication.GENESIS_PROOF_FILE, self.genesis_proof)
        write_json(self.artifacts / publication.AUTHORIZATION_FILE, self.authorization)
        write_json(self.artifacts / publication.PLAN_FILE, self.plan)

    def reauthenticated(self) -> "BundleFixture":
        """Create a distinct immediate certification result for the same exact inputs."""

        return BundleFixture(
            self.root.parent / f"{self.root.name}-reauthenticated",
            authorized=self.authorization.get("decision") == "approved",
        )

    def observation(self, status: str) -> object:
        current = status == "matching"
        return publication.PublicObservation(
            status=status,
            public_request_uri=self.plan["publicRequestUri"],
            update_key_identity_digest=KEY_DIGEST,
            update_key_scope=f"{KEY_DIGEST}/support-lifecycle/0",
            update_key_doc_name="support-lifecycle",
            descriptor_edition=1 if current else None,
            descriptor_digest=self.descriptor["descriptorDigest"] if current else None,
            descriptor_byte_digest=file_digest(self.descriptor) if current else None,
            previous_descriptor_edition=None,
            previous_descriptor_digest=None,
        )

    def authority_chain(self) -> Path:
        """Materialize the exact five-file maintenance authority-chain projection."""

        bundle = publication.load_bundle(self.root, require_authorization=True)
        root = self.root.parent / f"{self.root.name}-maintenance-authority-chain"
        root.mkdir()
        for name in (
            publication.LEDGER_FILE,
            publication.DESCRIPTOR_FILE,
            publication.AUTHORIZATION_FILE,
            publication.PLAN_FILE,
        ):
            (root / name).write_bytes((self.artifacts / name).read_bytes())
        receipt = publication._receipt(
            bundle, self.observation("matching"), "inserted"
        )
        write_json(root / publication.RECEIPT_FILE, receipt)
        return root

    def published_bundle(
        self, *, generated_at: str = GENERATED_AT, operation: str = "inserted"
    ) -> Path:
        """Add the protected publication receipt beside the immutable component."""

        bundle = publication.load_bundle(self.root, require_authorization=True)
        receipt = publication._receipt(
            bundle, self.observation("matching"), operation
        )
        receipt["generatedAt"] = generated_at
        write_json(self.root / publication.RECEIPT_FILE, receipt)
        return self.root


class FakeOperations:
    def __init__(self, fixture: BundleFixture, before: str = "absent") -> None:
        self.fixture = fixture
        self.before = before
        self.observe_calls = 0
        self.maintenance_tip_calls = 0
        self.publish_calls = 0
        self.verify_calls = 0
        self.secret_seen: object | None = None
        self.fail_after_publish = False

    def observe_lifecycle(self, _request: object) -> object:
        self.observe_calls += 1
        return self.fixture.observation(self.before)

    def observe_lifecycle_genesis(self, request: object) -> object:
        assert isinstance(request, dict)
        return publication.GenesisObservation(
            "absent",
            404,
            str(request["publicRequestUri"]),
            str(request["updateKeyIdentityDigest"]),
            str(request["updateKeyScope"]),
            str(request["updateKeyDocName"]),
        )

    def observe_latest_maintenance_tip(self, _request: object) -> object:
        self.maintenance_tip_calls += 1
        tip = self.fixture.inventory["entries"][-1]
        return publication.MaintenanceTipObservation(
            "absent",
            MAINTENANCE_POINTER_URI,
            None,
            str(tip["releaseId"]),
            str(tip["buildVersion"]),
            str(tip["baselineDigest"]),
            str(tip["publicationReceiptDigest"]),
        )

    def publish_lifecycle(self, _request: object, protected_input: object) -> None:
        self.publish_calls += 1
        self.secret_seen = protected_input
        if self.fail_after_publish:
            raise RuntimeError(f"provider failure must not leak {SECRET}")

    def verify_lifecycle(self, _request: object) -> object:
        self.verify_calls += 1
        return self.fixture.observation("matching")


class StableLifecyclePublicationTest(unittest.TestCase):
    """Exact-byte, idempotency, conflict, and protected-boundary tests."""

    def setUp(self) -> None:
        self.now_patch = mock.patch.object(publication, "_now", return_value=NOW)
        self.now_patch.start()

    def tearDown(self) -> None:
        self.now_patch.stop()

    def test_transition_set_digest_matches_engine_after_authorization_binding(self) -> None:
        transition_set = {
            "schemaVersion": 1,
            "kind": "stable-1.0-support-lifecycle-transition-set",
            "transitions": [
                {
                    "buildVersion": "300",
                    "fromStatus": "current-stable",
                    "toStatus": "supported-maintenance",
                    "authorizationDigest": digest("approval"),
                }
            ],
        }

        expected = semantic_digest(transition_set)
        transition_set["transitionSetDigest"] = expected

        self.assertEqual(publication._transition_set_digest(transition_set), expected)

    def test_protected_adapter_rejects_already_stale_descriptor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = BundleFixture(Path(directory) / "bundle")
            stale = {**fixture.descriptor, "staleAt": GENERATED_AT}
            stale["descriptorDigest"] = semantic_digest(
                {
                    key: value
                    for key, value in stale.items()
                    if key != "descriptorDigest"
                }
            )

            with self.assertRaisesRegex(
                publication.AdapterError, "descriptor-future-or-stale"
            ):
                publication._validate_descriptor(stale)

    def test_protected_adapter_rejects_future_effective_entry_status(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = BundleFixture(Path(directory) / "bundle")
            descriptor = copy.deepcopy(fixture.descriptor)
            descriptor["entries"][0]["statusEffectiveAt"] = "2026-07-22T00:00:00Z"
            descriptor["descriptorDigest"] = semantic_digest(
                {
                    key: value
                    for key, value in descriptor.items()
                    if key != "descriptorDigest"
                }
            )

            with self.assertRaisesRegex(
                publication.AdapterError, "descriptor-entry-future-effective"
            ):
                publication._validate_descriptor(descriptor)

    def test_protected_adapter_accepts_recovery_only_revoked_tip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = BundleFixture(Path(directory) / "bundle")
            policy = json.loads(
                (
                    ROOT
                    / "tools/release-certification/stable-1.0-support-lifecycle-policy.json"
                ).read_text(encoding="utf-8")
            )
            request = {
                "transitions": [
                    {
                        "targetBuild": "300",
                        "toStatus": "revoked",
                        "effectiveAt": GENERATED_AT,
                        "reasonCode": "unsafe-current-build",
                        "advisoryId": "CRYPTA-ADV-2026-001",
                        "severity": "critical",
                        "affectedBuilds": ["300"],
                        "securityEvidenceIds": ["security-drill-2026-001"],
                        "publicationTargetDigest": digest("publication-target"),
                        "replacementBuild": None,
                        "recoveryGuidance": "Restore the prior verified package from offline media.",
                    }
                ]
            }
            ledger, _proposed, errors = build_ledger(
                fixture.inventory,
                policy,
                POLICY_DIGEST,
                GENERATED_AT,
                None,
                request,
            )
            descriptor, descriptor_errors = build_descriptor(
                ledger,
                policy,
                GENERATED_AT,
                None,
                KEY_DIGEST,
            )
            provenance = {
                **fixture.provenance,
                "ledgerDigest": ledger["ledgerDigest"],
                "descriptorDigest": descriptor["descriptorDigest"],
            }

            publication._validate_inventory_bindings(
                fixture.inventory,
                ledger,
                descriptor,
                provenance,
                fixture.plan,
                fixture.genesis_proof,
            )

            self.assertEqual(errors, [])
            self.assertEqual(descriptor_errors, [])
            self.assertIsNone(descriptor["currentStableBuild"])
            self.assertIsNone(descriptor["recommendedBuild"])

            unsafe_ledger = copy.deepcopy(ledger)
            unsafe_ledger["entries"][0]["replacementBuild"] = "300"
            unsafe_ledger["entries"][0]["entryDigest"] = entry_digest(
                unsafe_ledger["entries"][0]
            )
            unsafe_ledger["ledgerDigest"] = ledger_digest(unsafe_ledger)
            unsafe_descriptor = copy.deepcopy(descriptor)
            unsafe_descriptor["ledgerDigest"] = unsafe_ledger["ledgerDigest"]
            unsafe_descriptor["entries"][0]["replacementBuild"] = "300"
            unsafe_descriptor["descriptorDigest"] = semantic_digest(
                {
                    key: value
                    for key, value in unsafe_descriptor.items()
                    if key != "descriptorDigest"
                }
            )
            unsafe_provenance = {
                **provenance,
                "ledgerDigest": unsafe_ledger["ledgerDigest"],
                "descriptorDigest": unsafe_descriptor["descriptorDigest"],
            }
            with self.assertRaisesRegex(
                publication.AdapterError, "ledger-recommends-revoked-build"
            ):
                publication._validate_inventory_bindings(
                    fixture.inventory,
                    unsafe_ledger,
                    unsafe_descriptor,
                    unsafe_provenance,
                    fixture.plan,
                    fixture.genesis_proof,
                )

    def test_engine_emits_non_ascii_guidance_as_protected_canonical_bytes(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = BundleFixture(Path(directory) / "bundle")
            policy = json.loads(
                (
                    ROOT
                    / "tools/release-certification/stable-1.0-support-lifecycle-policy.json"
                ).read_text(encoding="utf-8")
            )
            guidance = "Récupérez le paquet vérifié depuis le support hors ligne."
            request = {
                "transitions": [
                    {
                        "targetBuild": "300",
                        "toStatus": "revoked",
                        "effectiveAt": GENERATED_AT,
                        "reasonCode": "unsafe-current-build",
                        "advisoryId": "CRYPTA-ADV-2026-001",
                        "severity": "critical",
                        "affectedBuilds": ["300"],
                        "securityEvidenceIds": ["security-drill-2026-001"],
                        "publicationTargetDigest": digest("publication-target"),
                        "replacementBuild": None,
                        "recoveryGuidance": guidance,
                    }
                ]
            }
            ledger, proposed, ledger_errors = build_ledger(
                fixture.inventory,
                policy,
                POLICY_DIGEST,
                GENERATED_AT,
                None,
                request,
            )
            transition_set = {
                "schemaVersion": 1,
                "kind": "stable-1.0-support-lifecycle-transition-set",
                "generatedAt": GENERATED_AT,
                "stableMilestone": "1.0",
                "previousLedgerDigest": ledger["previousLedgerDigest"],
                "resultingLedgerDigest": ledger["ledgerDigest"],
                "transitionRequestDigest": semantic_digest(
                    [row["authorizationRequestDigest"] for row in proposed]
                ),
                "transitions": [
                    {
                        **row,
                        "authorizationDigest": None,
                        "resultingLedgerDigest": ledger["ledgerDigest"],
                    }
                    for row in proposed
                ],
                "redaction": redaction(),
            }
            transition_set["transitionSetDigest"] = engine_transition_set_digest(
                transition_set
            )
            descriptor, descriptor_errors = build_descriptor(
                ledger,
                policy,
                GENERATED_AT,
                None,
                KEY_DIGEST,
            )
            authorization, authorization_valid, authorization_errors = (
                engine_validate_authorization(
                    None,
                    policy,
                    descriptor,
                    ledger,
                    transition_set,
                    PUBLIC_URI,
                    MAINTENANCE_POINTER_URI,
                    None,
                    NOW,
                )
            )
            self.assertFalse(authorization_valid)
            self.assertEqual(authorization_errors, [])
            authorization.update(
                {
                    "authorizationId": "lifecycle-non-ascii-guidance-approval",
                    "expiresAt": EXPIRES_AT,
                    "decision": "approved",
                }
            )
            authorization, authorization_valid, authorization_errors = (
                engine_validate_authorization(
                    authorization,
                    policy,
                    descriptor,
                    ledger,
                    transition_set,
                    PUBLIC_URI,
                    MAINTENANCE_POINTER_URI,
                    None,
                    NOW,
                )
            )
            authorization_digest = file_digest(authorization)
            for transition in transition_set["transitions"]:
                transition["authorizationDigest"] = authorization_digest
            transition_set["transitionSetDigest"] = engine_transition_set_digest(
                transition_set
            )
            plan = engine_publication_plan(
                descriptor,
                ledger,
                authorization,
                authorization_valid,
                PUBLIC_URI,
                MAINTENANCE_POINTER_URI,
                None,
                transition_set["transitionSetDigest"],
            )
            provenance = {
                **fixture.provenance,
                "ledgerDigest": ledger["ledgerDigest"],
                "descriptorDigest": descriptor["descriptorDigest"],
            }
            artifacts = {
                publication.DESCRIPTOR_FILE: descriptor,
                publication.LEDGER_FILE: ledger,
                publication.TRANSITION_FILE: transition_set,
                publication.INVENTORY_FILE: fixture.inventory,
                publication.PROVENANCE_FILE: provenance,
                publication.GENESIS_PROOF_FILE: fixture.genesis_proof,
                publication.AUTHORIZATION_FILE: authorization,
                publication.PLAN_FILE: plan,
            }
            for name, value in artifacts.items():
                engine_write_canonical_json(fixture.artifacts / name, value)

            bundle = publication.load_bundle(fixture.root, require_authorization=True)
            descriptor_bytes = (
                fixture.artifacts / publication.DESCRIPTOR_FILE
            ).read_bytes()

            self.assertEqual(ledger_errors, [])
            self.assertEqual(descriptor_errors, [])
            self.assertEqual(authorization_errors, [])
            self.assertTrue(authorization_valid)
            self.assertEqual(
                bundle.descriptor["entries"][0]["recoveryGuidance"], guidance
            )
            self.assertIn(guidance.encode("utf-8"), descriptor_bytes)
            self.assertNotIn(b"R\\u00e9cup", descriptor_bytes)
            self.assertEqual(plan["descriptorSizeBytes"], len(descriptor_bytes))
            self.assertEqual(file_digest(descriptor), bundle.descriptor_byte_digest)

    def test_protected_adapter_rejects_runtime_unsafe_recovery_guidance(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = BundleFixture(Path(directory) / "bundle")
            invalid_guidance = {
                "supplementary-emoji": "Recover safely \U0001f6e1",
                "isolated-surrogate": "Recover safely \ud800",
                "unicode-format": "Recover\u200e safely",
                "iso-control": "Recover\u0085 safely",
                "java-utf16-overflow": "x" * 257,
            }

            for name, guidance in invalid_guidance.items():
                with self.subTest(name=name):
                    descriptor = copy.deepcopy(fixture.descriptor)
                    descriptor["entries"][0]["recoveryGuidance"] = guidance

                    with self.assertRaisesRegex(
                        publication.AdapterError, "artifact-schema-validation-failed"
                    ):
                        publication._validate_descriptor(descriptor)
                    with self.assertRaisesRegex(
                        publication.AdapterError,
                        "public-artifact-unsafe-recovery-guidance",
                    ):
                        publication._scan_public({"recoveryGuidance": guidance})

    def test_protected_adapter_rejects_runtime_unsafe_guidance_projections(
        self,
    ) -> None:
        valid_entries = [
            {
                "buildVersion": "299",
                "lifecycleStatus": "end-of-support",
                "replacementBuild": "300",
                "recoveryGuidance": None,
            },
            {
                "buildVersion": "300",
                "lifecycleStatus": "current-stable",
                "replacementBuild": None,
                "recoveryGuidance": None,
            },
        ]
        invalid_replacements = {
            "missing": (0, "999"),
            "self": (0, "299"),
            "not-security-supported": (1, "299"),
        }
        for name, (entry_index, replacement) in invalid_replacements.items():
            with self.subTest(name=name):
                entries = copy.deepcopy(valid_entries)
                entries[entry_index]["replacementBuild"] = replacement
                with self.assertRaisesRegex(
                    publication.AdapterError, "ledger-replacement-target-invalid"
                ):
                    publication._validate_ledger_runtime_guidance(entries)

        recovery_only = copy.deepcopy(valid_entries)
        recovery_only[0]["replacementBuild"] = None
        recovery_only[0]["recoveryGuidance"] = (
            "Restore a verified package from offline recovery media."
        )
        with self.assertRaisesRegex(
            publication.AdapterError,
            "ledger-recovery-guidance-with-current-stable",
        ):
            publication._validate_ledger_runtime_guidance(recovery_only)

    def test_publication_rechecks_freshness_immediately_before_insert(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = BundleFixture(root / "bundle")
            reauthenticated = fixture.reauthenticated()

            class ExpiresDuringPreflight(FakeOperations):
                def observe_latest_maintenance_tip(self, request: object) -> object:
                    observation = super().observe_latest_maintenance_tip(request)
                    publication._now.return_value = NOW + dt.timedelta(days=15)
                    return observation

            operations = ExpiresDuringPreflight(fixture)
            receipt = root / "receipt.json"
            preflight = root / "preflight.json"

            outcome = publication.publish_exact(
                fixture.root,
                reauthenticated.root,
                operations,
                publication.SecretMaterial(publication.INSERT_PURPOSE, SECRET),
                receipt,
                preflight,
            )

            self.assertFalse(outcome.passed)
            self.assertEqual(operations.publish_calls, 0)
            audit = next(iter(outcome.artifacts.values()))
            self.assertEqual(audit["failureCode"], "descriptor-future-or-stale")

    def test_publication_does_not_emit_receipt_after_authorization_expiry(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = BundleFixture(root / "bundle")
            reauthenticated = fixture.reauthenticated()

            class AuthorizationExpiresAfterVerification(FakeOperations):
                def verify_lifecycle(self, request: object) -> object:
                    observation = super().verify_lifecycle(request)
                    publication._now.return_value = dt.datetime(
                        2026, 7, 21, 14, 0, tzinfo=dt.timezone.utc
                    )
                    return observation

            operations = AuthorizationExpiresAfterVerification(fixture)
            outcome = publication.publish_exact(
                fixture.root,
                reauthenticated.root,
                operations,
                publication.SecretMaterial(publication.INSERT_PURPOSE, SECRET),
                root / "receipt.json",
                root / "preflight.json",
            )

            self.assertFalse(outcome.passed)
            self.assertEqual(operations.publish_calls, 1)
            self.assertNotIn(root / "receipt.json", outcome.artifacts)
            audit = next(iter(outcome.artifacts.values()))
            self.assertEqual(audit["failureCode"], "authorization-expired-or-malformed")
            self.assertTrue(audit["sideEffectsMayHaveOccurred"])

    def test_protected_genesis_proof_accepts_only_404_not_410(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = BundleFixture(root / "bundle")
            request = {
                key: value
                for key, value in fixture.genesis_proof.items()
                if key not in {"observedAt", "observationStatus", "transportStatus", "proofDigest"}
            }
            request["kind"] = "stable-1.0-support-lifecycle-genesis-proof-request"
            request_path = root / "request.json"
            output = root / "proof.json"
            write_json(request_path, request)
            operations = FakeOperations(fixture)

            outcome = publication.prove_genesis(request_path, operations, output)

            self.assertTrue(outcome.passed)
            proof = outcome.artifacts[output]
            self.assertEqual(proof["transportStatus"], 404)
            self.assertEqual(
                validate_schema(
                    proof,
                    "stable-1.0-support-lifecycle-genesis-proof-v1.schema.json",
                ),
                [],
            )

            class Tombstoned(FakeOperations):
                def observe_lifecycle_genesis(self, request: object) -> object:
                    observed = super().observe_lifecycle_genesis(request)
                    return dataclasses.replace(
                        observed, status="tombstoned", transport_status=410
                    )

            with self.assertRaisesRegex(
                publication.AdapterError, "genesis-proof-target-tombstoned"
            ):
                publication.prove_genesis(
                    request_path, Tombstoned(fixture), output
                )

    def test_descriptor_genesis_requires_protected_absence_proof_at_any_chain_depth(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = BundleFixture(Path(directory) / "bundle")
            bundle = publication.load_bundle(
                fixture.root, require_authorization=True
            )

            publication._validate_descriptor_history_binding(
                bundle.inventory, bundle.ledger, bundle.descriptor, bundle.genesis_proof
            )
            post_ga_inventory = {**bundle.inventory, "chainDepth": 1}
            publication._validate_descriptor_history_binding(
                post_ga_inventory, bundle.ledger, bundle.descriptor, bundle.genesis_proof
            )
            with self.assertRaisesRegex(
                publication.AdapterError, "descriptor-genesis-proof-or-history-invalid"
            ):
                publication._validate_descriptor_history_binding(
                    bundle.inventory, bundle.ledger, bundle.descriptor, None
                )
            unbound_successor = {
                **bundle.descriptor,
                "descriptorEdition": 2,
                "previousDescriptorEdition": None,
                "previousDescriptorDigest": None,
            }
            with self.assertRaisesRegex(
                publication.AdapterError,
                "descriptor-successor-history-binding-missing",
            ):
                publication._validate_descriptor_history_binding(
                    bundle.inventory,
                    bundle.ledger,
                    unbound_successor,
                    bundle.genesis_proof,
                )

    def test_absent_descriptor_is_inserted_once_and_verified(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = BundleFixture(Path(directory) / "bundle")
            reauthenticated = fixture.reauthenticated()
            operations = FakeOperations(fixture)
            receipt = fixture.root / "receipt.json"
            preflight = fixture.root / "preflight.json"

            outcome = publication.publish_exact(
                fixture.root,
                reauthenticated.root,
                operations,
                publication.SecretMaterial(publication.INSERT_PURPOSE, SECRET),
                receipt,
                preflight,
            )

            self.assertTrue(outcome.passed)
            self.assertEqual(operations.publish_calls, 1)
            self.assertEqual(operations.verify_calls, 1)
            self.assertEqual(outcome.artifacts[receipt]["operation"], "inserted")
            self.assertEqual(
                outcome.artifacts[receipt]["descriptorBytesDigest"],
                file_digest(fixture.descriptor),
            )
            self.assertNotIn(SECRET, json.dumps(list(outcome.artifacts.values())))

    def test_identical_public_descriptor_is_idempotent_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = BundleFixture(Path(directory) / "bundle")
            reauthenticated = fixture.reauthenticated()
            operations = FakeOperations(fixture, "matching")
            receipt = fixture.root / "receipt.json"

            outcome = publication.publish_exact(
                fixture.root,
                reauthenticated.root,
                operations,
                publication.SecretMaterial(publication.INSERT_PURPOSE, SECRET),
                receipt,
                fixture.root / "preflight.json",
            )

            self.assertTrue(outcome.passed)
            self.assertEqual(operations.publish_calls, 0)
            self.assertEqual(operations.verify_calls, 1)
            self.assertEqual(outcome.artifacts[receipt]["operation"], "verified-existing")

    def test_conflict_and_unavailable_state_fail_without_mutation(self) -> None:
        for status in ("conflict", "unavailable"):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as directory:
                fixture = BundleFixture(Path(directory) / "bundle")
                reauthenticated = fixture.reauthenticated()
                operations = FakeOperations(fixture, status)
                receipt = fixture.root / "receipt.json"

                outcome = publication.publish_exact(
                    fixture.root,
                    reauthenticated.root,
                    operations,
                    publication.SecretMaterial(publication.INSERT_PURPOSE, SECRET),
                    receipt,
                    fixture.root / "preflight.json",
                )

                self.assertFalse(outcome.passed)
                self.assertEqual(operations.publish_calls, 0)
                audit = next(iter(outcome.artifacts.values()))
                self.assertFalse(audit["publicationAttempted"])
                self.assertFalse(audit["sideEffectsMayHaveOccurred"])

    def test_wrong_public_bytes_edition_digest_or_scope_fail_closed(self) -> None:
        mutations = (
            ("descriptor_byte_digest", digest("wrong-bytes")),
            ("descriptor_edition", 2),
            ("descriptor_digest", digest("wrong-descriptor")),
            ("update_key_scope", f"{KEY_DIGEST}/wrong-doc/0"),
        )
        for field, value in mutations:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                fixture = BundleFixture(Path(directory) / "bundle")
                reauthenticated = fixture.reauthenticated()
                operations = FakeOperations(fixture, "matching")
                original = operations.observe_lifecycle

                def observe(request: object, *, field: str = field, value: object = value) -> object:
                    row = original(request)
                    return publication.dataclasses.replace(row, **{field: value})

                operations.observe_lifecycle = observe  # type: ignore[method-assign]
                outcome = publication.publish_exact(
                    fixture.root,
                    reauthenticated.root,
                    operations,
                    publication.SecretMaterial(publication.INSERT_PURPOSE, SECRET),
                    fixture.root / "receipt.json",
                    fixture.root / "preflight.json",
                )
                self.assertFalse(outcome.passed)
                self.assertEqual(operations.publish_calls, 0)

    def test_missing_authorization_fails_before_provider_observation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = BundleFixture(Path(directory) / "bundle")
            reauthenticated = fixture.reauthenticated()
            (fixture.artifacts / publication.AUTHORIZATION_FILE).unlink()
            operations = FakeOperations(fixture)

            outcome = publication.publish_exact(
                fixture.root,
                reauthenticated.root,
                operations,
                publication.SecretMaterial(publication.INSERT_PURPOSE, SECRET),
                fixture.root / "receipt.json",
                fixture.root / "preflight.json",
            )

            self.assertFalse(outcome.passed)
            self.assertEqual(operations.observe_calls, 0)
            self.assertEqual(operations.publish_calls, 0)

    def test_ga_only_pointer_must_still_be_publicly_absent_before_insert(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = BundleFixture(Path(directory) / "bundle")
            reauthenticated = fixture.reauthenticated()
            operations = FakeOperations(fixture)
            tip = fixture.inventory["entries"][-1]

            def newly_published_tip(_request: object) -> object:
                operations.maintenance_tip_calls += 1
                return publication.MaintenanceTipObservation(
                    "conflict",
                    MAINTENANCE_POINTER_URI,
                    digest("first-maintenance-pointer"),
                    "stable-1-0-maintenance-301",
                    "301",
                    digest("new-baseline"),
                    digest("new-receipt"),
                )

            operations.observe_latest_maintenance_tip = newly_published_tip  # type: ignore[method-assign]

            outcome = publication.publish_exact(
                fixture.root,
                reauthenticated.root,
                operations,
                publication.SecretMaterial(publication.INSERT_PURPOSE, SECRET),
                fixture.root / "receipt.json",
                fixture.root / "preflight.json",
            )

            self.assertFalse(outcome.passed)
            self.assertEqual(operations.maintenance_tip_calls, 1)
            self.assertEqual(operations.publish_calls, 0)
            self.assertNotEqual(str(tip["buildVersion"]), "301")
            audit = next(iter(outcome.artifacts.values()))
            self.assertEqual(
                audit["failureCode"],
                "public-maintenance-tip-changed-before-publication",
            )

    def test_changed_fresh_certification_fails_before_any_provider_read(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = BundleFixture(Path(directory) / "bundle")
            reauthenticated = fixture.reauthenticated()
            reauthenticated.provenance["generatedAt"] = "2026-07-21T12:00:01Z"
            reauthenticated.write()
            operations = FakeOperations(fixture)

            outcome = publication.publish_exact(
                fixture.root,
                reauthenticated.root,
                operations,
                publication.SecretMaterial(publication.INSERT_PURPOSE, SECRET),
                fixture.root / "receipt.json",
                fixture.root / "preflight.json",
            )

            self.assertFalse(outcome.passed)
            self.assertEqual(operations.observe_calls, 0)
            self.assertEqual(operations.maintenance_tip_calls, 0)
            self.assertEqual(operations.publish_calls, 0)
            audit = next(iter(outcome.artifacts.values()))
            self.assertEqual(
                audit["failureCode"],
                "authenticated-maintenance-tip-changed-before-publication",
            )

    def test_authorization_rejects_future_or_policy_overlong_validity(self) -> None:
        mutations = (
            {
                "generatedAt": "2026-07-21T13:00:00Z",
                "expiresAt": "2026-07-21T14:00:00Z",
            },
            {
                "generatedAt": "2026-07-20T12:00:00Z",
                "expiresAt": "2026-07-21T12:00:01Z",
            },
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                fixture = BundleFixture(Path(directory) / "bundle")
                fixture.authorization.update(mutation)
                fixture.plan["authorizationDigest"] = file_digest(fixture.authorization)
                fixture.plan["publicationPlanDigest"] = semantic_digest(
                    {
                        key: value
                        for key, value in fixture.plan.items()
                        if key != "publicationPlanDigest"
                    }
                )
                fixture.write()

                with self.assertRaisesRegex(
                    publication.AdapterError,
                    "authorization-expired-or-malformed",
                ):
                    publication.load_bundle(
                        fixture.root, require_authorization=True
                    )

    def test_authorization_window_is_bound_to_the_ledger_policy_digest(self) -> None:
        self.assertEqual(
            publication._maximum_authorization_validity(POLICY_DIGEST),
            dt.timedelta(hours=24),
        )
        with self.assertRaisesRegex(
            publication.AdapterError,
            "authorization-policy-digest-mismatch",
        ):
            publication._maximum_authorization_validity(digest("other-policy"))

    def test_authorized_bundle_remains_current_time_bound_for_mutation_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = BundleFixture(Path(directory) / "bundle")
            bundle = publication.load_bundle(
                fixture.root, require_authorization=True
            )

            with self.assertRaisesRegex(
                publication.AdapterError,
                "authorization-expired-or-malformed",
            ):
                publication._validate_bundle_authorization_at(
                    bundle, NOW + dt.timedelta(days=1)
                )

    def test_authorization_binds_the_exact_public_request_uri(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = BundleFixture(Path(directory) / "bundle")
            fixture.plan["publicRequestUri"] = (
                "https://93.184.216.34/support-lifecycle/substituted"
            )
            fixture.genesis_proof["publicRequestUri"] = fixture.plan[
                "publicRequestUri"
            ]
            fixture.genesis_proof["proofDigest"] = semantic_digest(
                {
                    key: value
                    for key, value in fixture.genesis_proof.items()
                    if key != "proofDigest"
                }
            )
            fixture.provenance["genesisProofDigest"] = fixture.genesis_proof[
                "proofDigest"
            ]
            fixture.plan["publicationPlanDigest"] = semantic_digest(
                {
                    key: value
                    for key, value in fixture.plan.items()
                    if key != "publicationPlanDigest"
                }
            )
            fixture.write()

            with self.assertRaisesRegex(
                publication.AdapterError,
                "authorization-targetPublicRequestUri-mismatch",
            ):
                publication.load_bundle(fixture.root, require_authorization=True)

    def test_local_modes_never_load_or_call_provider(self) -> None:
        for mode, authorized in (
            ("evaluate", False),
            ("prepare-transition", False),
            ("validate-authorization", True),
        ):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                fixture = BundleFixture(Path(directory) / "bundle", authorized=authorized)
                operations = mock.Mock()
                out = fixture.root / f"{mode}.json"

                code = publication.main(
                    [
                        "--mode",
                        mode,
                        "--bundle",
                        str(fixture.root),
                        "--out",
                        str(out),
                        "--no-side-effects",
                    ],
                    operations=operations,
                    environ={"GITHUB_EVENT_NAME": "pull_request"},
                )

                self.assertEqual(code, 0)
                operations.assert_not_called()
                self.assertFalse(json.loads(out.read_text())["sideEffectsPerformed"])

    def test_verify_publication_re_fetches_without_insert_secret(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = BundleFixture(Path(directory) / "bundle")
            fixture.published_bundle()
            operations = FakeOperations(fixture, "matching")
            receipt = fixture.root / "receipt.json"

            code = publication.main(
                [
                    "--mode",
                    "verify-publication",
                    "--bundle",
                    str(fixture.root),
                    "--out",
                    str(fixture.root / "verify-summary.json"),
                    "--receipt",
                    str(receipt),
                    "--no-side-effects",
                ],
                operations=operations,
                environ={"GITHUB_EVENT_NAME": "workflow_dispatch"},
            )

            self.assertEqual(code, 0)
            self.assertEqual(operations.verify_calls, 1)
            self.assertEqual(operations.publish_calls, 0)
            self.assertEqual(json.loads(receipt.read_text())["operation"], "verified-existing")

    def test_verify_publication_accepts_expired_authorization_used_in_window(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = BundleFixture(Path(directory) / "bundle")
            fixture.published_bundle()
            publication._now.return_value = NOW + dt.timedelta(days=1)
            operations = FakeOperations(fixture, "matching")
            receipt = fixture.root / "independent-receipt.json"

            outcome = publication.verify_exact(fixture.root, operations, receipt)

            self.assertTrue(outcome.passed)
            self.assertEqual(operations.verify_calls, 1)
            self.assertEqual(operations.publish_calls, 0)

    def test_verify_publication_rejects_receipt_outside_authorization_window(self) -> None:
        invalid_times = (
            "2026-07-21T11:59:59Z",
            EXPIRES_AT,
        )
        for generated_at in invalid_times:
            with self.subTest(generated_at=generated_at), tempfile.TemporaryDirectory() as directory:
                publication._now.return_value = NOW
                fixture = BundleFixture(Path(directory) / "bundle")
                fixture.published_bundle(generated_at=generated_at)
                publication._now.return_value = NOW + dt.timedelta(days=1)
                operations = FakeOperations(fixture, "matching")

                with self.assertRaisesRegex(
                    publication.AdapterError,
                    "publication-receipt-outside-authorization-window",
                ):
                    publication.verify_exact(
                        fixture.root,
                        operations,
                        fixture.root / "independent-receipt.json",
                    )

                self.assertEqual(operations.verify_calls, 0)

    def test_verify_publication_rejects_missing_or_future_receipt_time(self) -> None:
        invalid_times: tuple[str | None, ...] = (
            None,
            "2026-07-21T12:00:01Z",
        )
        for generated_at in invalid_times:
            with self.subTest(generated_at=generated_at), tempfile.TemporaryDirectory() as directory:
                fixture = BundleFixture(Path(directory) / "bundle")
                fixture.published_bundle()
                receipt_path = fixture.root / publication.RECEIPT_FILE
                historical_receipt = json.loads(receipt_path.read_text())
                if generated_at is None:
                    historical_receipt.pop("generatedAt")
                else:
                    historical_receipt["generatedAt"] = generated_at
                write_json(receipt_path, historical_receipt)
                operations = FakeOperations(fixture, "matching")

                expected = (
                    "artifact-schema-validation-failed"
                    if generated_at is None
                    else "publication-receipt-time-invalid"
                )
                with self.assertRaisesRegex(publication.AdapterError, expected):
                    publication.verify_exact(
                        fixture.root,
                        operations,
                        fixture.root / "independent-receipt.json",
                    )

                self.assertEqual(operations.verify_calls, 0)

    def test_verify_publication_rejects_receipt_target_digest_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = BundleFixture(Path(directory) / "bundle")
            fixture.published_bundle()
            receipt_path = fixture.root / publication.RECEIPT_FILE
            historical_receipt = json.loads(receipt_path.read_text())
            historical_receipt["publicationPlanDigest"] = digest("substituted-plan")
            write_json(receipt_path, historical_receipt)
            operations = FakeOperations(fixture, "matching")

            with self.assertRaisesRegex(
                publication.AdapterError,
                "historical-publication-receipt-mismatch",
            ):
                publication.verify_exact(
                    fixture.root,
                    operations,
                    fixture.root / "independent-receipt.json",
                )

            self.assertEqual(operations.verify_calls, 0)

    def test_authorized_state_observation_re_fetches_exact_tip_without_network(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = BundleFixture(Path(directory) / "bundle")
            authority_chain = fixture.authority_chain()
            operations = FakeOperations(fixture, "matching")
            receipt = fixture.root / "public-observation.json"

            code = publication.main(
                [
                    "--mode",
                    "observe-authorized-state",
                    "--authority-chain",
                    str(authority_chain),
                    "--out",
                    str(fixture.root / "observation-summary.json"),
                    "--receipt",
                    str(receipt),
                    "--no-side-effects",
                ],
                operations=operations,
                environ={
                    "GITHUB_ACTIONS": "true",
                    "GITHUB_EVENT_NAME": "workflow_dispatch",
                    "GITHUB_WORKFLOW": "Stable 1.0 Maintenance Release",
                    "CRYPTAD_STABLE_LIFECYCLE_OBSERVATION_ENVIRONMENT": "true",
                },
            )

            self.assertEqual(0, code)
            self.assertEqual(1, operations.verify_calls)
            self.assertEqual(0, operations.publish_calls)
            value = json.loads(receipt.read_text(encoding="utf-8"))
            self.assertEqual("verified-existing", value["operation"])
            self.assertEqual(fixture.descriptor["descriptorDigest"], value["descriptorDigest"])

    def test_authorized_state_observation_rejects_superseded_public_tip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = BundleFixture(Path(directory) / "bundle")
            authority_chain = fixture.authority_chain()
            class Superseded(FakeOperations):
                def verify_lifecycle(self, _request: object) -> object:
                    self.verify_calls += 1
                    return self.fixture.observation("conflict")

            operations = Superseded(fixture)

            code = publication.main(
                [
                    "--mode",
                    "observe-authorized-state",
                    "--authority-chain",
                    str(authority_chain),
                    "--out",
                    str(fixture.root / "observation-summary.json"),
                    "--receipt",
                    str(fixture.root / "public-observation.json"),
                    "--no-side-effects",
                ],
                operations=operations,
                environ={
                    "GITHUB_ACTIONS": "true",
                    "GITHUB_EVENT_NAME": "workflow_dispatch",
                    "GITHUB_WORKFLOW": "Stable 1.0 Maintenance Release",
                    "CRYPTAD_STABLE_LIFECYCLE_OBSERVATION_ENVIRONMENT": "true",
                },
            )

            self.assertEqual(1, code)
            self.assertEqual(1, operations.verify_calls)
            self.assertEqual(0, operations.publish_calls)

    def test_authorized_state_observation_requires_protected_maintenance_context(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = BundleFixture(Path(directory) / "bundle")
            authority_chain = fixture.authority_chain()
            operations = FakeOperations(fixture, "matching")

            code = publication.main(
                [
                    "--mode",
                    "observe-authorized-state",
                    "--authority-chain",
                    str(authority_chain),
                    "--out",
                    str(fixture.root / "observation-summary.json"),
                    "--receipt",
                    str(fixture.root / "public-observation.json"),
                    "--no-side-effects",
                ],
                operations=operations,
                environ={"GITHUB_EVENT_NAME": "pull_request"},
            )

            self.assertEqual(1, code)
            self.assertEqual(0, operations.verify_calls)

    def test_pull_request_cannot_publish(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = BundleFixture(Path(directory) / "bundle")
            reauthenticated = fixture.reauthenticated()
            code = publication.main(
                [
                    "--mode",
                    "publish",
                    "--bundle",
                    str(fixture.root),
                    "--reauthenticated-bundle",
                    str(reauthenticated.root),
                    "--out",
                    str(fixture.root / "summary.json"),
                    "--receipt",
                    str(fixture.root / "receipt.json"),
                    "--preflight",
                    str(fixture.root / "preflight.json"),
                    "--insert-input-env",
                    publication.INSERT_INPUT_ENV,
                    "--idempotency",
                    "exact-match-only",
                    "--conflict-action",
                    "fail",
                    "--forbid-overwrite",
                    "--verify-after-publication",
                ],
                operations=FakeOperations(fixture),
                environ={
                    "GITHUB_ACTIONS": "true",
                    "GITHUB_EVENT_NAME": "pull_request",
                    publication.INSERT_INPUT_ENV: SECRET,
                },
            )
            self.assertEqual(code, 1)

    def test_publish_scrubs_secret_and_redacts_provider_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(
            os.environ, {publication.INSERT_INPUT_ENV: SECRET}, clear=False
        ):
            fixture = BundleFixture(Path(directory) / "bundle")
            reauthenticated = fixture.reauthenticated()
            operations = FakeOperations(fixture)
            operations.fail_after_publish = True
            out = fixture.root / "summary.json"
            receipt = fixture.root / "receipt.json"

            code = publication.main(
                [
                    "--mode",
                    "publish",
                    "--bundle",
                    str(fixture.root),
                    "--reauthenticated-bundle",
                    str(reauthenticated.root),
                    "--out",
                    str(out),
                    "--receipt",
                    str(receipt),
                    "--preflight",
                    str(fixture.root / "preflight.json"),
                    "--insert-input-env",
                    publication.INSERT_INPUT_ENV,
                    "--idempotency",
                    "exact-match-only",
                    "--conflict-action",
                    "fail",
                    "--forbid-overwrite",
                    "--verify-after-publication",
                ],
                operations=operations,
                environ={
                    "GITHUB_ACTIONS": "true",
                    "GITHUB_EVENT_NAME": "workflow_dispatch",
                    "GITHUB_WORKFLOW": "Stable 1.0 Support Lifecycle",
                    "CRYPTAD_STABLE_LIFECYCLE_PROTECTED_ENVIRONMENT": "true",
                    publication.INSERT_INPUT_ENV: SECRET,
                },
            )

            self.assertEqual(code, 1)
            self.assertNotIn(publication.INSERT_INPUT_ENV, os.environ)
            audit = fixture.root / publication.FAILURE_AUDIT_FILE
            self.assertTrue(audit.is_file())
            content = audit.read_text() + out.read_text()
            self.assertNotIn(SECRET, content)
            value = json.loads(audit.read_text())
            self.assertTrue(value["publicationAttempted"])
            self.assertTrue(value["sideEffectsMayHaveOccurred"])

    def test_public_artifacts_reject_secret_fields_and_values(self) -> None:
        unsafe = (
            {"privateInsertUri": SECRET},
            {"token": "secret"},
            {"rawSupportBundle": "support bytes"},
            {"rawAppData": "app-private value"},
            {"guidance": "Authorization: Bearer secret"},
            {"path": "/home/runner/work/private"},
            {"guidance": "USK@private-insert/value"},
            {"guidance": "unsafe\u0001control"},
        )
        for value in unsafe:
            with self.subTest(value=value):
                with self.assertRaises(publication.AdapterError):
                    publication._scan_public(value, secret=SECRET)

    def test_nested_archives_are_not_accepted_as_publication_inputs(self) -> None:
        for archive_type in ("zip", "tar"):
            with self.subTest(archive_type=archive_type), tempfile.TemporaryDirectory() as directory:
                fixture = BundleFixture(Path(directory) / "bundle")
                path = fixture.artifacts / f"unexpected-private-input.{archive_type}"
                if archive_type == "zip":
                    with zipfile.ZipFile(path, "w") as archive:
                        archive.writestr("private.json", json.dumps({"privateInsertUri": SECRET}))
                else:
                    payload = b"/home/runner/private\n"
                    info = tarfile.TarInfo("support-bundle.txt")
                    info.size = len(payload)
                    with tarfile.open(path, "w") as archive:
                        archive.addfile(info, io.BytesIO(payload))

                with self.assertRaises(publication.AdapterError):
                    publication.load_bundle(fixture.root, require_authorization=True)

    def test_every_allowed_public_artifact_is_scanned(self) -> None:
        unsafe_artifacts = (
            (
                "stable-1.0-support-lifecycle-summary.json",
                {"rawSupportBundle": "private"},
            ),
            (
                "stable-1.0-support-lifecycle-report.md",
                "runner path: /home/runner/private\n",
            ),
        )
        for filename, unsafe_value in unsafe_artifacts:
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as directory:
                fixture = BundleFixture(Path(directory) / "bundle")
                path = fixture.artifacts / filename
                if isinstance(unsafe_value, dict):
                    write_json(path, unsafe_value)
                else:
                    path.write_text(unsafe_value, encoding="utf-8")

                with self.assertRaises(publication.AdapterError):
                    publication.load_bundle(fixture.root, require_authorization=True)

    def test_unsafe_or_unexpected_sibling_is_rejected(self) -> None:
        sibling_cases = (
            (
                "stable-lifecycle-authorization-validation.json",
                {"rawSupportBundle": "private"},
            ),
            ("unexpected-publication-input.zip", b"PK\x03\x04private"),
        )
        for filename, value in sibling_cases:
            with self.subTest(filename=filename), tempfile.TemporaryDirectory() as directory:
                fixture = BundleFixture(Path(directory) / "bundle")
                path = fixture.root / filename
                if isinstance(value, dict):
                    write_json(path, value)
                else:
                    path.write_bytes(value)

                with self.assertRaises(publication.AdapterError):
                    publication.load_bundle(fixture.root, require_authorization=True)

    def test_reviewed_workflow_wrapper_artifacts_are_scanned_and_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = BundleFixture(Path(directory) / "bundle")
            write_json(fixture.root / "component" / "summary.json", {"status": "pass"})
            write_json(
                fixture.root / "component" / "redaction-report.json",
                redaction(),
            )
            write_json(
                fixture.root / "component" / "artifacts" / "legacy-summary.json",
                {"status": "pass", "redaction": redaction()},
            )
            (fixture.root / "component" / "report.md").write_text(
                "# Public lifecycle report\n", encoding="utf-8"
            )
            write_json(
                fixture.root / "manifest" / "stable-lifecycle-manifest.json",
                {"releaseId": "stable-lifecycle-300"},
            )
            write_json(
                fixture.root / "stable-lifecycle-protected-evaluation.json",
                {"status": "pass", "sideEffectsPerformed": False},
            )
            write_json(
                fixture.root / "stable-lifecycle-authorization-validation.json",
                {"status": "pass", "sideEffectsPerformed": False},
            )

            bundle = publication.load_bundle(
                fixture.root, require_authorization=True
            )

            self.assertEqual(bundle.descriptor["descriptorEdition"], 1)

    def test_unified_wrapper_legacy_summary_is_scanned(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = BundleFixture(Path(directory) / "bundle")
            write_json(
                fixture.root / "component" / "artifacts" / "legacy-summary.json",
                {"rawSupportBundle": "private"},
            )

            with self.assertRaisesRegex(
                publication.AdapterError,
                "public-artifact-sensitive-field",
            ):
                publication.load_bundle(fixture.root, require_authorization=True)

    def test_idempotent_main_summary_does_not_claim_a_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(
            os.environ, {publication.INSERT_INPUT_ENV: SECRET}, clear=False
        ):
            fixture = BundleFixture(Path(directory) / "bundle")
            reauthenticated = fixture.reauthenticated()
            operations = FakeOperations(fixture, "matching")
            out = fixture.root / "summary.json"

            code = publication.main(
                [
                    "--mode",
                    "publish",
                    "--bundle",
                    str(fixture.root),
                    "--reauthenticated-bundle",
                    str(reauthenticated.root),
                    "--out",
                    str(out),
                    "--receipt",
                    str(fixture.root / "receipt.json"),
                    "--preflight",
                    str(fixture.root / "preflight.json"),
                    "--insert-input-env",
                    publication.INSERT_INPUT_ENV,
                    "--idempotency",
                    "exact-match-only",
                    "--conflict-action",
                    "fail",
                    "--forbid-overwrite",
                    "--verify-after-publication",
                ],
                operations=operations,
                environ={
                    "GITHUB_ACTIONS": "true",
                    "GITHUB_EVENT_NAME": "workflow_dispatch",
                    "GITHUB_WORKFLOW": "Stable 1.0 Support Lifecycle",
                    "CRYPTAD_STABLE_LIFECYCLE_PROTECTED_ENVIRONMENT": "true",
                    publication.INSERT_INPUT_ENV: SECRET,
                },
            )

            self.assertEqual(code, 0)
            summary = json.loads(out.read_text())
            self.assertFalse(summary["sideEffectsPerformed"])
            self.assertFalse(summary["sideEffectsMayHaveOccurred"])
            self.assertEqual(operations.publish_calls, 0)


class StableLifecycleInputProducerTest(unittest.TestCase):
    """Fail-closed protected-input download and archive handling tests."""

    def test_locator_rejects_credentials_query_fragment_and_ambiguous_paths(self) -> None:
        for uri in (
            "https://user:pass@example.test/bundle.zip",
            "https://example.test/bundle.zip?token=secret",
            "https://example.test/bundle.zip#fragment",
            "https://example.test/a/../bundle.zip",
            "https://example.test/bundle\n.zip",
            "https://\ud800.test/bundle.zip",
            "http://example.test/bundle.zip",
        ):
            with self.subTest(uri=uri), self.assertRaises(input_producer.InputError):
                input_producer._validated_locator(uri)

    def test_locator_rejects_private_or_mixed_dns_answers(self) -> None:
        public = (
            socket.AF_INET,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
            "",
            ("93.184.216.34", 443),
        )
        private = (
            socket.AF_INET,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
            "",
            ("127.0.0.1", 443),
        )
        for answers in ([private], [public, private]):
            with self.subTest(answers=answers), mock.patch.object(
                input_producer.socket, "getaddrinfo", return_value=answers
            ), self.assertRaisesRegex(
                input_producer.InputError,
                "protected-lifecycle-input-address-not-public",
            ):
                input_producer._validated_locator(
                    "https://example.test/bundle.zip"
                )

    def test_redirect_and_digest_failures_are_bounded_and_delete_partial_output(self) -> None:
        secret_url = "https://example.test/private-bundle.zip"
        secret_token = "do-not-print-this-token"
        endpoints = ((socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, ("93.184.216.34", 443)),)
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            input_producer,
            "_validated_locator",
            return_value=(secret_url, "example.test", 443, endpoints),
        ), mock.patch.object(
            input_producer.urllib.request,
            "build_opener",
        ) as opener:
            opener.return_value.open.side_effect = urllib.error.HTTPError(
                secret_url, 302, "redirect", {}, None
            )
            output = Path(directory) / "bundle.zip"

            with self.assertRaises(input_producer.InputError) as raised:
                input_producer._fetch(
                    secret_url, secret_token, digest("expected"), output
                )

            self.assertEqual(str(raised.exception), "protected-lifecycle-input-fetch-failed")
            self.assertNotIn(secret_url, str(raised.exception))
            self.assertNotIn(secret_token, str(raised.exception))
            self.assertFalse(output.exists())

        response = mock.MagicMock()
        response.status = 200
        response.read.side_effect = [b"different bytes", b""]
        response.__enter__.return_value = response
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            input_producer,
            "_validated_locator",
            return_value=(secret_url, "example.test", 443, endpoints),
        ), mock.patch.object(
            input_producer.urllib.request,
            "build_opener",
        ) as opener:
            opener.return_value.open.return_value = response
            output = Path(directory) / "bundle.zip"

            with self.assertRaisesRegex(
                input_producer.InputError,
                "protected-lifecycle-input-digest-mismatch",
            ):
                input_producer._fetch(
                    secret_url, secret_token, digest("expected"), output
                )

            self.assertFalse(output.exists())

    def test_archive_rejects_traversal_symlink_duplicates_and_expansion_bombs(self) -> None:
        cases: list[tuple[str, object]] = []
        cases.append(("traversal", [("../secret", b"secret", None)]))
        symlink = zipfile.ZipInfo("link")
        symlink.external_attr = (stat.S_IFLNK | 0o777) << 16
        cases.append(("symlink", [(symlink, b"target", None)]))
        cases.append(
            (
                "duplicate",
                [("same.json", b"{}", None), ("same.json", b"{}", None)],
            )
        )
        cases.append(("nested-archive", [("nested.zip", b"PK\x03\x04", None)]))
        cases.append(("bomb", [("large.bin", b"12345", 4)]))

        for name, members in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                archive = root / "bundle.zip"
                with mock.patch("warnings.warn"):
                    with zipfile.ZipFile(archive, "w") as bundle:
                        limit = None
                        for member, body, configured_limit in members:
                            bundle.writestr(member, body)
                            limit = configured_limit if configured_limit is not None else limit
                destination = root / "out"
                destination.mkdir()
                context = (
                    mock.patch.object(input_producer, "MAX_MEMBER_BYTES", limit)
                    if limit is not None
                    else mock.patch.object(
                        input_producer,
                        "MAX_MEMBER_BYTES",
                        input_producer.MAX_MEMBER_BYTES,
                    )
                )

                with context, self.assertRaises(input_producer.InputError):
                    input_producer._extract(archive, destination)

    def test_malformed_expected_digest_fails_before_reading_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            sys,
            "argv",
            [
                "stable_lifecycle_input_producer.py",
                "--expected-digest",
                "sha256:" + ("g" * 64),
                "--out",
                str(Path(directory) / "out"),
            ],
        ), mock.patch.dict(
            os.environ,
            {
                "CRYPTAD_STABLE_LIFECYCLE_INPUT_BUNDLE_URL": "secret-url",
                "CRYPTAD_STABLE_LIFECYCLE_INPUT_BUNDLE_BEARER_TOKEN": "secret-token",
            },
            clear=False,
        ):
            with self.assertRaisesRegex(
                input_producer.InputError,
                "protected-lifecycle-input-digest-invalid",
            ):
                input_producer.main()
            self.assertIn(
                "CRYPTAD_STABLE_LIFECYCLE_INPUT_BUNDLE_URL", os.environ
            )


class StableLifecycleWorkflowTest(unittest.TestCase):
    """Static guarantees for the protected workflow's trust and mutation boundaries."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = (
            ROOT / ".github"
            / "workflows"
            / "stable-1.0-support-lifecycle.yml"
        ).read_text(encoding="utf-8")
        cls.producer = (
            ROOT
            / ".github"
            / "workflows"
            / "stable-1.0-support-lifecycle-publication-backend-producer.yml"
        ).read_text(encoding="utf-8")
        cls.input_producer = (
            ROOT
            / ".github"
            / "workflows"
            / "stable-1.0-support-lifecycle-input-producer.yml"
        ).read_text(encoding="utf-8")

    def test_workflow_has_only_closed_manual_operations(self) -> None:
        self.assertIn("on:\n  workflow_dispatch:", self.workflow)
        self.assertNotIn("pull_request:", self.workflow)
        options = self.workflow.split("        options:\n", 1)[1].split(
            "      release_id:", 1
        )[0]
        for operation in (
            "prove-genesis",
            "evaluate",
            "prepare-transition",
            "validate-authorization",
            "publish",
            "verify-publication",
        ):
            self.assertIn(f"          - {operation}\n", options)

    def test_every_lifecycle_job_binds_workflow_and_checkout_to_source_commit(
        self,
    ) -> None:
        checkout_marker = "uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
        binding_marker = "- name: Bind workflow and checkout to exact source"
        checkout_count = self.workflow.count(checkout_marker)

        self.assertEqual(checkout_count, 6)
        self.assertEqual(self.workflow.count(binding_marker), checkout_count)
        self.assertEqual(
            self.workflow.count(
                '|| "$GITHUB_SHA" != "$INPUT_SOURCE_COMMIT" \\'
            ),
            checkout_count,
        )
        self.assertEqual(
            self.workflow.count(
                '|| "$(git rev-parse \'HEAD^{commit}\')" != "$INPUT_SOURCE_COMMIT"'
            ),
            checkout_count,
        )
        for checkout_tail in self.workflow.split(checkout_marker)[1:]:
            before_next_action = checkout_tail.split("\n        uses:", 1)[0]
            self.assertIn(binding_marker, before_next_action)
            self.assertIn(
                "INPUT_SOURCE_COMMIT: ${{ inputs.source_commit }}",
                before_next_action,
            )

    def test_lifecycle_jobs_enter_environments_only_from_authenticated_protected_refs(
        self,
    ) -> None:
        validation = self.workflow.split("  validate-dispatch:", 1)[1].split(
            "  local-evaluation:", 1
        )[0]

        for expected in (
            "refs/heads/main",
            '"refs/heads/release/$INPUT_BUILD_VERSION"',
            '"refs/heads/hotfix/$INPUT_BUILD_VERSION"',
            "select(.protected == true)",
            'git merge-base --is-ancestor "$INPUT_SOURCE_COMMIT" "$remote_tip"',
            'echo "trusted_source_ref=$GITHUB_REF" >> "$GITHUB_OUTPUT"',
        ):
            self.assertIn(expected, validation)
        self.assertEqual(
            5,
            self.workflow.count(
                "needs.validate-dispatch.outputs.trusted_source_ref == github.ref"
            ),
        )
        self.assertEqual(5, self.workflow.count("&& github.ref_protected"))

        protected = self.workflow.split("  protected-publication:", 1)[1].split(
            "  verify-publication:", 1
        )[0]
        secret = "secrets.CRYPTAD_STABLE_LIFECYCLE_PUBLICATION_INPUT"
        for expected in (
            "fetch-depth: 0",
            "select(.protected == true)",
            'git merge-base --is-ancestor "$INPUT_SOURCE_COMMIT" "$remote_tip"',
        ):
            self.assertIn(expected, protected)
            self.assertLess(protected.index(expected), protected.index(secret))

    def test_provider_job_enters_environment_only_from_protected_main(
        self,
    ) -> None:
        job = self.producer.split("  build-and-attest:", 1)[1]
        before_environment = job.split(
            "    environment: stable-1.0-lifecycle-evidence", 1
        )[0]

        self.assertIn(
            "if: github.ref_protected && github.ref == 'refs/heads/main'",
            before_environment,
        )

    def test_input_producer_rejects_unprotected_refs_before_credentials(
        self,
    ) -> None:
        credential_step = (
            "- name: Fetch and safely expand the exact reviewed bundle"
        )
        before_credentials = self.input_producer.split(credential_step, 1)[0]

        for expected in (
            "github.ref_protected",
            "github.ref == 'refs/heads/main'",
            "github.ref == format('refs/heads/release/{0}', inputs.build_version)",
            "github.ref == format('refs/heads/hotfix/{0}', inputs.build_version)",
            "needs.validate-dispatch.outputs.trusted_source_ref == github.ref",
            "needs: validate-dispatch",
            "fetch-depth: 0",
            "select(.protected == true)",
            'git merge-base --is-ancestor "$INPUT_SOURCE_COMMIT" "$remote_tip"',
        ):
            self.assertIn(expected, before_credentials)
        preflight = self.input_producer.split(
            "  authenticate-and-attest:", 1
        )[0]
        self.assertIn(
            'echo "trusted_source_ref=$GITHUB_REF" >> "$GITHUB_OUTPUT"',
            preflight,
        )
        self.assertNotIn("environment:", preflight)
        self.assertNotIn(
            "secrets.CRYPTAD_STABLE_LIFECYCLE_INPUT_BUNDLE",
            before_credentials,
        )

    def test_every_phase_binds_dispatch_identity_to_attested_lifecycle_content(
        self,
    ) -> None:
        local = self.workflow.split("  local-evaluation:", 1)[1].split(
            "  prove-genesis:", 1
        )[0]
        proof = self.workflow.split("  prove-genesis:", 1)[1].split(
            "  validate-authorization:", 1
        )[0]
        validation = self.workflow.split("  validate-authorization:", 1)[1].split(
            "  protected-publication:", 1
        )[0]
        protected = self.workflow.split("  protected-publication:", 1)[1].split(
            "  verify-publication:", 1
        )[0]
        verification = self.workflow.split("  verify-publication:", 1)[1]
        manifest_identity = (
            ".release == {\n"
            "              id: $release_id,\n"
            "              version: $build_version,\n"
            '              profile: "stable-review"\n'
            "            }"
        )
        summary_identity = (
            ".payload.legacy.releaseId == $release_id\n"
            "            and .payload.legacy.buildVersion == $build_version"
        )
        tip_identity = ".entries[-1].buildVersion == $build_version"

        for phase in (local, proof, validation, protected, verification):
            with self.subTest(phase=phase[:40]):
                self.assertIn(
                    "INPUT_RELEASE_ID: ${{ inputs.release_id }}", phase
                )
                self.assertIn(
                    "INPUT_BUILD_VERSION: ${{ inputs.build_version }}", phase
                )

        self.assertIn(manifest_identity, local)
        self.assertIn(summary_identity, local)
        self.assertIn('gh attestation verify "$manifest"', proof)
        self.assertIn(manifest_identity, proof)
        self.assertIn(".buildVersion == $build_version", proof)
        self.assertIn(manifest_identity, validation)
        self.assertIn(summary_identity, validation)
        self.assertIn("component/summary.json", validation)

        for phase in (protected, verification):
            with self.subTest(subject_phase=phase[:40]):
                self.assertIn('gh attestation verify "$summary"', phase)
                self.assertIn(summary_identity, phase)
                self.assertEqual(2, phase.count(tip_identity))

        self.assertIn(manifest_identity, protected)
        self.assertGreaterEqual(protected.count(summary_identity), 2)

    def test_local_workflow_reads_the_native_summary_from_the_v2_envelope(self) -> None:
        local = self.workflow.split("  local-evaluation:", 1)[1].split(
            "  validate-authorization:", 1
        )[0]

        self.assertIn(".schemaVersion == 2", local)
        self.assertIn(".payload.legacy.commandMode == $mode", local)
        self.assertIn(
            '.payload.legacy.publicationState == "not-published"', local
        )
        self.assertNotIn("\n            .commandMode == $mode", local)

    def test_only_protected_publication_receives_insert_material(self) -> None:
        local = self.workflow.split("  local-evaluation:", 1)[1].split(
            "  validate-authorization:", 1
        )[0]
        protected = self.workflow.split("  protected-publication:", 1)[1].split(
            "  verify-publication:", 1
        )[0]
        verification = self.workflow.split("  verify-publication:", 1)[1]
        secret_reference = "secrets.CRYPTAD_STABLE_LIFECYCLE_PUBLICATION_INPUT"

        self.assertNotIn(secret_reference, local)
        self.assertIn("environment: stable-1.0-lifecycle-publication", protected)
        self.assertIn(secret_reference, protected)
        self.assertNotIn(secret_reference, verification)
        self.assertIn("--mode verify-publication", verification)
        self.assertNotIn("--mode publish", verification)
        self.assertIn("Upload independently verified lifecycle receipt", verification)
        self.assertIn(publication.RECEIPT_FILE, verification)
        self.assertIn(
            "--bundle build/stable-lifecycle-verification \\", verification
        )
        self.assertNotIn(
            "--bundle build/stable-lifecycle-verification/component", verification
        )

    def test_genesis_proof_is_attested_read_only_and_never_receives_insert_material(
        self,
    ) -> None:
        proof = self.workflow.split("  prove-genesis:", 1)[1].split(
            "  validate-authorization:", 1
        )[0]
        secret_reference = "secrets.CRYPTAD_STABLE_LIFECYCLE_PUBLICATION_INPUT"

        self.assertIn("environment: stable-1.0-lifecycle-evidence", proof)
        self.assertIn("CRYPTAD_STABLE_LIFECYCLE_PROOF_ENVIRONMENT: 'true'", proof)
        self.assertIn("--mode prove-genesis", proof)
        self.assertIn("--no-side-effects", proof)
        self.assertIn("actions/attest-build-provenance@", proof)
        self.assertIn("--source-digest", proof)
        self.assertIn("--deny-self-hosted-runners", proof)
        self.assertNotIn(secret_reference, proof)
        self.assertNotIn("--mode publish", proof)

        self.assertIn(
            'gh attestation verify "$proof"', self.input_producer
        )
        self.assertIn("--source-digest \"$EXPECTED_SOURCE_COMMIT\"", self.input_producer)
        self.assertIn(".payload.legacy.blockers | length == 1", self.input_producer)
        self.assertIn('.status == "pass"', self.input_producer)

    def test_provider_is_pinned_and_lifecycle_only(self) -> None:
        for binding in (
            "PUBLICATION_BACKEND_SOURCE_COMMIT",
            "PUBLICATION_BACKEND_WHEEL_SHA256",
            "PUBLICATION_BACKEND_SIGNER_WORKFLOW",
            "PUBLICATION_BACKEND_ARTIFACT_NAME",
            "publication_backend_artifact_digest",
            "stable-1.0-support-lifecycle-publication-backend-producer.yml",
            "cryptad_stable_maintenance_backend:lifecycle_factory",
            "gh attestation verify",
            "--deny-self-hosted-runners",
        ):
            self.assertIn(binding, self.workflow)
        for forbidden in (
            "gh release create",
            "git tag",
            "CRYPTAD_STABLE_CATALOG_PUBLICATION_INPUT",
            "CRYPTAD_CORE_UPDATE_PUBLICATION_INPUT",
            "core-info.json =",
        ):
            self.assertNotIn(forbidden, self.workflow)

    def test_workflow_preserves_truthful_failure_audit(self) -> None:
        self.assertIn("continue-on-error: true", self.workflow)
        self.assertIn(publication.FAILURE_AUDIT_FILE, self.workflow)
        self.assertIn("sideEffectsMayHaveOccurred", self.workflow)
        self.assertIn("Fail after retaining publication audit", self.workflow)

    def test_authorization_is_regenerated_and_tip_is_reauthenticated_before_publish(self) -> None:
        validation = self.workflow.split("  validate-authorization:", 1)[1].split(
            "  protected-publication:", 1
        )[0]
        protected = self.workflow.split("  protected-publication:", 1)[1].split(
            "  verify-publication:", 1
        )[0]

        self.assertIn("stable-1.0-support-lifecycle-input-producer.yml", self.workflow)
        self.assertIn("certify.py stable-lifecycle", validation)
        self.assertIn('--mode validate-authorization', validation)
        self.assertIn("certify.py stable-lifecycle", protected)
        self.assertIn("--reauthenticated-bundle", protected)
        self.assertIn("stable-1-0-maintenance-publication", self.workflow)
        self.assertIn('stage="build/stable-lifecycle-published-stage"', protected)
        self.assertIn(
            'cp -R "$source/component" "$stage/component"', protected
        )
        self.assertIn(
            '[[ -e "$stage/protected-inputs" || -e "$stage/manifest" ]]',
            protected,
        )
        self.assertNotIn(
            'cp -R build/stable-lifecycle-publication "$stage"', protected
        )
        self.assertIn(publication.RECEIPT_FILE, protected)

    def test_successor_subjects_use_the_canonical_current_component_paths(self) -> None:
        protected = self.workflow.split("  protected-publication:", 1)[1].split(
            "  verify-publication:", 1
        )[0]
        verification = self.workflow.split("  verify-publication:", 1)[1]

        for section, root in (
            (protected, "build/stable-lifecycle-publication"),
            (verification, "build/stable-lifecycle-verification"),
        ):
            self.assertIn(
                f'subjects="$root/component/artifacts/legacy"', section
            )
            self.assertIn('path="$subjects/$name"', section)
            self.assertIn('gh attestation verify "$path"', section)
            self.assertIn('find "$root" -type l -print -quit', section)
            self.assertNotIn(
                f'find {root} -type f -name "$name" -print', section
            )
            self.assertNotIn('gh attestation verify "${rows[0]}"', section)

    def test_canonical_input_producer_is_manual_attested_and_never_publishes(self) -> None:
        self.assertIn("on:\n  workflow_dispatch:", self.input_producer)
        self.assertNotIn("pull_request:", self.input_producer)
        for operation in (
            "prove-genesis",
            "evaluate",
            "prepare-transition",
            "validate-authorization",
        ):
            self.assertIn(f"          - {operation}\n", self.input_producer)
        self.assertNotIn("          - publish\n", self.input_producer)
        self.assertIn("actions/attest-build-provenance@", self.input_producer)
        self.assertIn("input_bundle_sha256", self.input_producer)
        self.assertIn("stable_lifecycle_input_producer.py", self.input_producer)
        self.assertIn('"allowDirtyWorkspace": False', self.input_producer)
        self.assertIn('"fixtureEvidence": False', self.input_producer)
        self.assertIn('"allowTestSigningInProduction": False', self.input_producer)
        self.assertIn('"collectLiveNetwork": False', self.input_producer)
        self.assertIn('"writeHistory": False', self.input_producer)
        self.assertNotIn("CRYPTAD_STABLE_LIFECYCLE_PUBLICATION_INPUT", self.input_producer)
        self.assertNotIn("--mode publish", self.input_producer)

    def test_input_producer_defines_shell_paths_before_genesis_proof_verification(
        self,
    ) -> None:
        validation = self.input_producer.split(
            "      - name: Validate the closed manifest, exact input set, and side-effect-free result",
            1,
        )[1].split("      - name:", 1)[0]
        proof_lookup = validation.index(
            "proof_path=\"$(jq -r '.inputs.stableLifecycleGenesisProof // empty' \"$manifest_path\")\""
        )

        self.assertLess(
            validation.index(
                'manifest_path="$stage/manifest/stable-lifecycle-manifest.json"'
            ),
            proof_lookup,
        )
        self.assertLess(
            validation.index('protected="$stage/protected-inputs"'),
            proof_lookup,
        )

    def test_provider_producer_is_manual_deterministic_and_attested(self) -> None:
        self.assertIn("on:\n  workflow_dispatch:", self.producer)
        self.assertNotIn("pull_request:", self.producer)
        self.assertIn("git/ref/heads/main", self.producer)
        self.assertEqual(self.producer.count('python3 "$builder" --out'), 2)
        self.assertIn("cmp --silent", self.producer)
        self.assertIn("actions/attest@", self.producer)
        self.assertIn(
            "cryptad_stable_maintenance_backend:lifecycle_factory", self.producer
        )
        self.assertIn('"revoke_update_key"', self.producer)


class StableLifecycleProviderTest(unittest.TestCase):
    """Offline lifecycle-only deployment-provider protocol tests."""

    @classmethod
    def setUpClass(cls) -> None:
        sys.path.insert(0, str(BACKEND_SOURCE))
        cls.lifecycle = __import__(
            "cryptad_stable_maintenance_backend.lifecycle", fromlist=["lifecycle"]
        )

    @classmethod
    def tearDownClass(cls) -> None:
        sys.path.remove(str(BACKEND_SOURCE))

    def test_provider_exposes_only_lifecycle_operations(self) -> None:
        backend = self.lifecycle.StableLifecycleBackend(transport=mock.Mock())
        for required in (
            "observe_lifecycle",
            "observe_lifecycle_genesis",
            "observe_latest_maintenance_tip",
            "publish_lifecycle",
            "verify_lifecycle",
        ):
            self.assertTrue(callable(getattr(backend, required)))
        for forbidden in (
            "activate_latest",
            "publish_target",
            "create_release",
            "create_tag",
            "publish_catalog",
            "publish_core_update",
            "revoke_update_key",
        ):
            self.assertFalse(hasattr(backend, forbidden))

    def test_provider_observes_publishes_and_refetches_exact_bytes(self) -> None:
        with mock.patch.object(
            publication, "_now", return_value=NOW
        ), tempfile.TemporaryDirectory() as directory:
            fixture = BundleFixture(Path(directory) / "bundle")
            bundle = publication.load_bundle(
                fixture.root, require_authorization=True
            )
            request = publication.PublicationRequest(bundle)

            class Transport:
                def __init__(self) -> None:
                    self.published = False
                    self.subject: dict[str, object] | None = None

                def request(self, method, uri, *, headers=None, body=None):
                    if method == "GET":
                        if not self.published:
                            return 404, {}, b""
                        return 200, {}, bundle.descriptor_bytes
                    self.subject = json.loads(body)
                    self.published = True
                    response = {
                        "schemaVersion": 1,
                        "kind": "cryptad-stable-support-lifecycle-publication-result",
                        "status": "inserted",
                        "descriptorEdition": bundle.descriptor["descriptorEdition"],
                        "descriptorDigest": bundle.descriptor["descriptorDigest"],
                        "descriptorBytesDigest": bundle.descriptor_byte_digest,
                        "publicRequestUri": bundle.plan["publicRequestUri"],
                    }
                    return 200, {}, canonical_bytes(response)

            transport = Transport()
            backend = self.lifecycle.StableLifecycleBackend(transport=transport)

            before = backend.observe_lifecycle(request)
            maintenance_before = backend.observe_latest_maintenance_tip(request)
            backend.publish_lifecycle(
                request,
                publication.SecretMaterial(
                    publication.INSERT_PURPOSE,
                    "https://insert.example.test/capability",
                ),
            )
            after = backend.verify_lifecycle(request)
            maintenance_after = backend.observe_latest_maintenance_tip(request)

            self.assertEqual(before.status, "absent")
            self.assertEqual(maintenance_before.status, "absent")
            self.assertEqual(
                maintenance_before.public_uri, MAINTENANCE_POINTER_URI
            )
            self.assertEqual(after.status, "matching")
            self.assertEqual(maintenance_after.status, "conflict")
            assert transport.subject is not None
            self.assertEqual(
                base64.b64decode(str(transport.subject["descriptorBytes"])),
                bundle.descriptor_bytes,
            )
            self.assertNotIn("privateInsertUri", transport.subject)

    def test_provider_treats_410_as_tombstone_not_genesis_absence(self) -> None:
        with mock.patch.object(
            publication, "_now", return_value=NOW
        ), tempfile.TemporaryDirectory() as directory:
            fixture = BundleFixture(Path(directory) / "bundle")
            bundle = publication.load_bundle(
                fixture.root, require_authorization=True
            )
            request = publication.PublicationRequest(bundle)

            class Transport:
                def request(self, _method, _uri, *, headers=None, body=None):
                    return 410, {}, b""

            backend = self.lifecycle.StableLifecycleBackend(transport=Transport())
            genesis_request = {
                key: value
                for key, value in fixture.genesis_proof.items()
                if key not in {"observedAt", "observationStatus", "transportStatus", "proofDigest"}
            }

            ordinary = backend.observe_lifecycle(request)
            genesis = backend.observe_lifecycle_genesis(genesis_request)
            maintenance_tip = backend.observe_latest_maintenance_tip(request)

            self.assertEqual(ordinary.status, "conflict")
            self.assertEqual(genesis.status, "tombstoned")
            self.assertEqual(genesis.transport_status, 410)
            self.assertEqual(maintenance_tip.status, "conflict")
            with self.assertRaisesRegex(
                publication.AdapterError,
                "public-maintenance-tip-changed-before-publication",
            ):
                publication._validate_maintenance_tip_observation(
                    bundle, maintenance_tip
                )
            with self.assertRaisesRegex(
                publication.AdapterError, "public-lifecycle-state-conflict"
            ):
                publication._classify_observation(request, ordinary)

    def test_provider_accepts_only_the_exact_post_ga_public_pointer(self) -> None:
        with mock.patch.object(
            publication, "_now", return_value=NOW
        ), tempfile.TemporaryDirectory() as directory:
            fixture = BundleFixture(Path(directory) / "bundle")
            bundle = publication.load_bundle(fixture.root, require_authorization=True)
            tip = {
                **bundle.inventory["entries"][-1],
                "releaseId": "stable-1-0-maintenance-301",
                "buildVersion": "301",
                "tag": "v301",
                "baselineDigest": digest("maintenance-baseline"),
                "publicationReceiptDigest": digest("maintenance-receipt"),
                "chainDepth": 1,
            }
            pointer = {
                "schemaVersion": 1,
                "kind": "stable-1.0-maintenance-latest-published",
                "generatedAt": GENERATED_AT,
                "releaseId": tip["releaseId"],
                "buildVersion": tip["buildVersion"],
                "releaseClass": "maintenance",
                "baselineDigest": tip["baselineDigest"],
                "baselineIdentityDigest": digest("baseline-identity"),
                "publicationReceiptDigest": tip["publicationReceiptDigest"],
                "publicationReceiptIdentityDigest": digest("receipt-identity"),
                "lineageDigest": digest("lineage"),
                "historyDigest": digest("history"),
                "compareAndSwapPredecessorBaselineDigest": digest("previous-baseline"),
                "status": "active",
                "redaction": redaction(),
            }

            def observe(pointer_value):
                pointer_bytes = canonical_bytes(pointer_value)
                plan = {
                    **bundle.plan,
                    "latestMaintenancePointerDigest": publication._byte_digest(
                        pointer_bytes
                    ),
                }
                inventory = {
                    **bundle.inventory,
                    "chainDepth": 1,
                    "latestPointerDigest": plan["latestMaintenancePointerDigest"],
                    "entries": [bundle.inventory["entries"][0], tip],
                }
                post_ga_bundle = publication.dataclasses.replace(
                    bundle, plan=plan, inventory=inventory
                )
                request = publication.PublicationRequest(post_ga_bundle)

                class Transport:
                    def request(self, method, uri, *, headers=None, body=None):
                        if (
                            method != "GET"
                            or uri != MAINTENANCE_POINTER_URI
                            or body is not None
                        ):
                            raise AssertionError(
                                "unexpected maintenance pointer request"
                            )
                        return 200, {}, pointer_bytes

                backend = self.lifecycle.StableLifecycleBackend(
                    transport=Transport()
                )
                return (
                    backend.observe_latest_maintenance_tip(request),
                    plan["latestMaintenancePointerDigest"],
                )

            for accepted_pointer in (
                pointer,
                {
                    **pointer,
                    "backportReleaseTrainDigest": digest("release-train"),
                },
            ):
                with self.subTest(fields=set(accepted_pointer)):
                    observation, expected_digest = observe(accepted_pointer)
                    self.assertEqual(observation.status, "matching")
                    self.assertEqual(
                        observation.pointer_digest, expected_digest
                    )
                    self.assertEqual(observation.build_version, "301")

            for rejected_pointer in (
                {**pointer, "backportReleaseTrainDigest": "malformed"},
                {**pointer, "unexpectedField": digest("unexpected")},
            ):
                with self.subTest(rejected_fields=set(rejected_pointer)):
                    observation, _expected_digest = observe(rejected_pointer)
                    self.assertEqual(observation.status, "conflict")


if __name__ == "__main__":
    unittest.main()
