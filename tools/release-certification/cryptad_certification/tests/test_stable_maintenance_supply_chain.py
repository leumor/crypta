"""Stable maintenance integration with PR-289 supply-chain governance."""

from __future__ import annotations

import dataclasses
import datetime as dt
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cryptad_certification import selftest
from cryptad_certification.cli import build_parser
from cryptad_certification.engines import release_certification_core
from cryptad_certification.engines.stable_1_0_maintenance import (
    _dependency_vulnerability_promotion_errors,
    _supply_chain_companion_assets,
    _supply_chain_promotion_errors,
)
from cryptad_certification.engines.stable_1_0_dependency_vulnerability_core import (
    EVIDENCE_IDS as DEPENDENCY_VULNERABILITY_EVIDENCE_IDS,
    semantic_digest as dependency_vulnerability_semantic_digest,
)
from cryptad_certification.engines.stable_1_0_maintenance_core import (
    Candidate,
    LoadedJson,
    Predecessor,
)
from cryptad_certification.engines.stable_1_0_rc_core import file_digest
from cryptad_certification.engines.stable_1_0_supply_chain import (
    EVIDENCE_IDS as SUPPLY_CHAIN_EVIDENCE_IDS,
)
from cryptad_certification.engines.stable_1_0_supply_chain_core import (
    PUBLICATION_ROLE_FILES,
    canonical_json_bytes as supply_chain_canonical_json_bytes,
    semantic_digest as supply_chain_semantic_digest,
    sha256_digest as supply_chain_sha256_digest,
)
from cryptad_certification.io import read_json, write_json
from cryptad_certification.manifest import COMMAND_NAMES
from cryptad_certification.models import RunContext
from cryptad_certification.tests.support import workspace_root
from cryptad_certification.tests.test_stable_maintenance import (
    BUILD,
    COMMIT,
    RELEASE_ID,
    _candidate,
    _context,
    _digest,
    _ga_and_predecessor,
)


def _supply_chain_summary(candidate: Candidate, predecessor: Predecessor) -> dict[str, object]:
    supply_policy = read_json(
        workspace_root()
        / "tools/release-certification/stable-1.0-supply-chain-policy.json"
    )
    assert isinstance(supply_policy, dict)
    package_projection = {
        "packages": sorted(
            [
                {
                    "packageKey": row["packageKey"],
                    "digest": row["digest"],
                }
                for row in candidate.assets
            ],
            key=lambda row: str(row["packageKey"]),
        )
    }
    value: dict[str, object] = {
        "schemaVersion": 1,
        "kind": "stable-1.0-supply-chain-promotion-summary",
        "releaseId": RELEASE_ID,
        "buildVersion": int(BUILD),
        "tag": f"v{BUILD}",
        "sourceCommit": COMMIT,
        "sourceRef": f"commit:{COMMIT}",
        "policyDigest": supply_policy["policyDigest"],
        "mode": "evaluate-promotion",
        "status": "pass",
        "promotionReady": True,
        "candidateIdentityDigest": supply_chain_sha256_digest(
            supply_chain_canonical_json_bytes(candidate.input_value)
        ),
        "candidateFreezeDigest": candidate.freeze_digest,
        "productDigest": candidate.product_digest,
        "predecessorReleaseId": predecessor.release_id,
        "predecessorBuildVersion": int(predecessor.build_version),
        "predecessorProductDigest": predecessor.product_digest,
        "packageMatrixDigest": supply_chain_sha256_digest(
            supply_chain_canonical_json_bytes(package_projection)
        ),
        "packageAuthenticationDigest": _digest("d"),
        "selectedSubjectInventoryDigest": _digest("1"),
        "vulnerabilitySummaryDigest": None,
        "vulnerabilityReverseIndexDigest": _digest("2"),
        "resolvedDependencySnapshotDigest": _digest("3"),
        "componentInventoryDigest": _digest("4"),
        "subjectInventoryDigest": _digest("5"),
        "sbomDigest": _digest("6"),
        "licenseInventoryDigest": _digest("7"),
        "buildMaterialsDigest": _digest("8"),
        "primaryBuilderReceiptDigest": _digest("9"),
        "verifierBuilderReceiptDigest": _digest("a"),
        "comparisonPlanDigest": _digest("b"),
        "reproducibilityResultDigest": _digest("c"),
        "evidence": [
            {"evidenceId": evidence_id, "status": "pass", "nonWaivable": True}
            for evidence_id in SUPPLY_CHAIN_EVIDENCE_IDS
            if evidence_id != "stable-supply-chain.publication"
        ],
        "blockers": [],
        "waivers": [],
        "artifacts": [
            {
                "name": role,
                "digest": supply_chain_sha256_digest(role.encode("utf-8")),
                "size": index + 1,
            }
            for index, role in enumerate(PUBLICATION_ROLE_FILES)
            if role != "supply-chain-summary"
        ],
        "redaction": {
            "status": "pass",
            "privatePathsExcluded": True,
            "credentialsExcluded": True,
            "privateUrisExcluded": True,
            "embargoedVulnerabilityDataExcluded": True,
            "sideEffectsPerformed": False,
        },
        "summaryDigest": _digest("0"),
    }
    value["summaryDigest"] = supply_chain_semantic_digest(value, "summaryDigest")
    return value


def _dependency_vulnerability_summary(
    candidate: Candidate,
    predecessor: Predecessor,
    supply_chain: dict[str, object],
    *,
    policy_digest: str,
    vulnerability_summary_digest: str,
) -> dict[str, object]:
    value: dict[str, object] = {
        "schemaVersion": 1,
        "kind": "stable-1.0-dependency-vulnerability-promotion-summary",
        "repositoryIdentity": "github.com/crypta-network/cryptad",
        "stableMilestone": "Stable 1.0",
        "releaseId": RELEASE_ID,
        "buildVersion": int(BUILD),
        "candidateSourceCommit": COMMIT,
        "candidateFrozenAt": candidate.frozen_at,
        "predecessorReleaseId": predecessor.release_id,
        "predecessorBuildVersion": int(predecessor.build_version),
        "policyDigest": policy_digest,
        "mode": "evaluate-promotion",
        "status": "pass",
        "promotionReady": True,
        "activationStatus": "active-post-activation",
        "supplyChainPolicyDigest": supply_chain["policyDigest"],
        "supplyChainPromotionSummaryDigest": supply_chain["summaryDigest"],
        "componentReverseIndexDigest": supply_chain[
            "vulnerabilityReverseIndexDigest"
        ],
        "intelligenceSnapshotDigest": _digest("3"),
        "findingSetDigest": _digest("4"),
        "dispositionSetDigest": _digest("5"),
        "authorizationSetDigest": _digest("6"),
        "ledgerEdition": 7,
        "ledgerDigest": _digest("7"),
        "validUntil": "2099-08-10T00:00:00Z",
        "remediationSetDigest": _digest("8"),
        "vulnerabilityPromotionSummaryDigest": vulnerability_summary_digest,
        "publicationPlanDigest": None,
        "publicationReceiptDigest": None,
        "publicObservationDigest": None,
        "publicSummaryDigest": _digest("c"),
        "redactionDigest": _digest("d"),
        "evidence": [
            {"evidenceId": evidence_id, "status": "pass", "nonWaivable": True}
            for evidence_id in DEPENDENCY_VULNERABILITY_EVIDENCE_IDS
            if evidence_id != "stable-dependency-vulnerability.publication"
        ],
        "blockers": [],
        "waivers": [],
        "artifacts": [],
        "redaction": {
            "status": "pass",
            "privateCaseMaterialExcluded": True,
            "reporterIdentityExcluded": True,
            "embargoedDetailsExcluded": True,
            "credentialsExcluded": True,
            "privateUrisExcluded": True,
            "absolutePathsExcluded": True,
            "rawFeedsExcluded": True,
            "sideEffectsPerformed": False,
        },
        "summaryDigest": _digest("e"),
    }
    value["summaryDigest"] = dependency_vulnerability_semantic_digest(
        value, "summaryDigest"
    )
    return value


def _write_dependency_vulnerability_handoff(
    context: RunContext, path: Path
) -> dict[str, object]:
    run_id = "2001"
    run_attempt = "2"
    artifact_name = (
        f"stable-1.0-dependency-vulnerability-{RELEASE_ID}-evaluation"
    )
    artifact_digest = _digest("6")
    context.manifest.policies["metadata"].update(
        {
            "stableDependencyVulnerabilityRunId": run_id,
            "stableDependencyVulnerabilityRunAttempt": run_attempt,
            "stableDependencyVulnerabilityArtifactName": artifact_name,
            "stableDependencyVulnerabilityArtifactDigest": artifact_digest,
        }
    )
    summary_byte_digest = file_digest(path)
    summary = json.loads(path.read_text(encoding="utf-8"))
    source_status_path = path.with_name(
        "stable-1.0-dependency-vulnerability-source-status.json"
    )
    write_json(source_status_path, {"fixture": "authenticated-source-status"})
    source_status_byte_digest = file_digest(source_status_path)
    handoff: dict[str, object] = {
        "schemaVersion": 1,
        "kind": "stable-1.0-dependency-vulnerability-promotion-handoff",
        "repository": "crypta-network/cryptad",
        "workflow": (
            "crypta-network/cryptad/.github/workflows/"
            f"stable-1.0-dependency-vulnerability-evaluation.yml@{COMMIT}"
        ),
        "workflowCommit": COMMIT,
        "runId": run_id,
        "runAttempt": run_attempt,
        "operation": "evaluate-promotion",
        "releaseId": RELEASE_ID,
        "buildVersion": BUILD,
        "sourceCommit": COMMIT,
        "artifactName": artifact_name,
        "producerArtifactDigest": artifact_digest,
        "ledgerEdition": summary["ledgerEdition"],
        "ledgerDigest": summary["ledgerDigest"],
        "validUntil": summary["validUntil"],
        "summaryFileName": (
            "stable-1.0-dependency-vulnerability-promotion-summary.json"
        ),
        "summaryByteDigest": summary_byte_digest,
        "sourceStatusFileName": source_status_path.name,
        "sourceStatusByteDigest": source_status_byte_digest,
        "attestationSubjectDigest": summary_byte_digest,
        "attestationVerified": True,
        "denySelfHostedRunners": True,
        "authenticationStatus": "pass",
        "authenticationAlgorithm": "hmac-sha256",
        "authenticationTag": _digest("pending-dependency-vulnerability-tag"),
    }
    handoff["authenticationTag"] = (
        release_certification_core.stable_dependency_vulnerability_handoff_authentication_tag(
            handoff,
            b"d" * 32,
        )
    )
    write_json(
        path.with_name(
            "stable-1.0-dependency-vulnerability-summary-provenance.json"
        ),
        handoff,
    )
    return handoff


def _dependency_vulnerability_handoff_environment() -> dict[str, str]:
    return {
        release_certification_core.STABLE_DEPENDENCY_VULNERABILITY_HANDOFF_KEY_ENV: (
            "ZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGQ="
        )
    }


def _dependency_vulnerability_case(
    root: Path,
    *,
    frozen_at: str = "2026-08-09T01:00:00Z",
) -> tuple[RunContext, Candidate, LoadedJson, Path]:
    policy_target = (
        root
        / "tools/release-certification/"
        "stable-1.0-dependency-vulnerability-policy.json"
    )
    policy_target.parent.mkdir(parents=True)
    shutil.copyfile(
        workspace_root()
        / "tools/release-certification/"
        "stable-1.0-dependency-vulnerability-policy.json",
        policy_target,
    )
    policy = read_json(policy_target)
    assert isinstance(policy, dict)
    candidate = dataclasses.replace(_candidate(root), frozen_at=frozen_at)
    predecessor = _ga_and_predecessor()[1]
    supply_chain = _supply_chain_summary(candidate, predecessor)
    supply_path = root / "stable-1.0-supply-chain-summary.json"
    write_json(supply_path, supply_chain)
    vulnerability_summary_digest = _digest("f")
    write_json(
        root / "stable-1.0-vulnerability-summary.json",
        {"summaryDigest": vulnerability_summary_digest},
    )
    companion = _dependency_vulnerability_summary(
        candidate,
        predecessor,
        supply_chain,
        policy_digest=str(policy["policyDigest"]),
        vulnerability_summary_digest=vulnerability_summary_digest,
    )
    companion_path = root / "stable-1.0-dependency-vulnerability-summary.json"
    write_json(companion_path, companion)
    context = _context(
        root,
        inputs={
            "dependencyVulnerabilityPromotionSummary": companion_path.name,
            "stableVulnerabilitySummary": "stable-1.0-vulnerability-summary.json",
        },
    )
    loaded_supply_chain = LoadedJson(
        "supplyChainPromotionSummary",
        supply_path,
        supply_chain,
        file_digest(supply_path),
    )
    return context, candidate, loaded_supply_chain, companion_path


def _write_supply_chain_handoff(
    context: RunContext,
    path: Path,
    summary: dict[str, object],
) -> dict[str, object]:
    artifact_name = f"stable-1.0-supply-chain-{RELEASE_ID}-comparison"
    artifact_digest = _digest("d")
    metadata = context.manifest.policies["metadata"]
    metadata.update(
        {
            "stableSupplyChainRunId": "1001",
            "stableSupplyChainRunAttempt": "1",
            "stableSupplyChainArtifactName": artifact_name,
            "stableSupplyChainArtifactDigest": artifact_digest,
        }
    )
    handoff: dict[str, object] = {
        "schemaVersion": 1,
        "kind": "stable-1.0-supply-chain-promotion-handoff",
        "repository": "crypta-network/cryptad",
        "workflow": (
            "crypta-network/cryptad/.github/workflows/"
            f"stable-1.0-supply-chain.yml@{COMMIT}"
        ),
        "workflowCommit": COMMIT,
        "runId": "1001",
        "runAttempt": "1",
        "operation": "compare-evaluate",
        "releaseId": RELEASE_ID,
        "buildVersion": BUILD,
        "sourceCommit": COMMIT,
        "artifactName": artifact_name,
        "producerArtifactDigest": artifact_digest,
        "summaryFileName": "stable-1.0-supply-chain-summary.json",
        "summaryByteDigest": file_digest(path),
        "attestationSubjectDigest": file_digest(path),
        "attestationVerified": True,
        "denySelfHostedRunners": True,
        "authenticationStatus": "pass",
        "authenticationAlgorithm": "hmac-sha256",
        "authenticationTag": _digest("pending-supply-chain-handoff-tag"),
    }
    handoff["authenticationTag"] = (
        release_certification_core.stable_supply_chain_handoff_authentication_tag(
            handoff,
            b"stable-supply-chain-test-key-v1!",
        )
    )
    write_json(path.with_name("stable-1.0-supply-chain-summary-provenance.json"), handoff)
    return handoff


def _supply_chain_handoff_environment() -> dict[str, str]:
    return {
        release_certification_core.STABLE_SUPPLY_CHAIN_HANDOFF_KEY_ENV: (
            "c3RhYmxlLXN1cHBseS1jaGFpbi10ZXN0LWtleS12MSE="
        )
    }


class StableMaintenanceSupplyChainTest(unittest.TestCase):
    """Supply-chain promotion handoff and registration contracts."""

    def test_dependency_vulnerability_companion_requires_keyed_producer_handoff(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            context, candidate, supply_chain, _companion = (
                _dependency_vulnerability_case(Path(directory))
            )

            with mock.patch.dict(
                os.environ, _dependency_vulnerability_handoff_environment()
            ):
                errors = _dependency_vulnerability_promotion_errors(
                    context, candidate, supply_chain
                )

        self.assertIn(
            "configured dependency-vulnerability handoff is missing, unreadable, or malformed",
            errors,
        )

    def test_dependency_vulnerability_companion_is_prepublication_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            context, candidate, supply_chain, companion_path = (
                _dependency_vulnerability_case(Path(directory))
            )
            companion = read_json(companion_path)
            assert isinstance(companion, dict)
            companion["mode"] = "verify-publication"
            companion["publicationPlanDigest"] = _digest("9")
            companion["publicationReceiptDigest"] = _digest("a")
            companion["publicObservationDigest"] = _digest("b")
            companion["evidence"].append(
                {
                    "evidenceId": "stable-dependency-vulnerability.publication",
                    "status": "pass",
                    "nonWaivable": True,
                }
            )
            companion["summaryDigest"] = (
                dependency_vulnerability_semantic_digest(
                    companion, "summaryDigest"
                )
            )
            write_json(companion_path, companion)
            _write_dependency_vulnerability_handoff(context, companion_path)

            with mock.patch.dict(
                os.environ, _dependency_vulnerability_handoff_environment()
            ):
                errors = _dependency_vulnerability_promotion_errors(
                    context, candidate, supply_chain
                )

        self.assertTrue(
            any("prepublication evidence ids" in error for error in errors)
        )
        self.assertTrue(
            any("prematurely claims" in error for error in errors)
        )
        self.assertTrue(
            any("prepublication maintenance" in error for error in errors)
        )

    def test_dependency_vulnerability_companion_rejects_manifest_run_substitution(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            context, candidate, supply_chain, companion = (
                _dependency_vulnerability_case(Path(directory))
            )
            _write_dependency_vulnerability_handoff(context, companion)
            context.manifest.policies["metadata"][
                "stableDependencyVulnerabilityRunAttempt"
            ] = "3"

            with mock.patch.dict(
                os.environ, _dependency_vulnerability_handoff_environment()
            ):
                errors = _dependency_vulnerability_promotion_errors(
                    context, candidate, supply_chain
                )

        self.assertIn(
            "dependency-vulnerability producer handoff differs from manifest "
            "stableDependencyVulnerabilityRunAttempt",
            errors,
        )

    def test_dependency_vulnerability_companion_rejects_forged_handoff_mac(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            context, candidate, supply_chain, companion = (
                _dependency_vulnerability_case(Path(directory))
            )
            handoff = _write_dependency_vulnerability_handoff(context, companion)
            handoff["authenticationTag"] = _digest("forged-handoff-tag")
            write_json(
                companion.with_name(
                    "stable-1.0-dependency-vulnerability-summary-provenance.json"
                ),
                handoff,
            )

            with mock.patch.dict(
                os.environ, _dependency_vulnerability_handoff_environment()
            ):
                errors = _dependency_vulnerability_promotion_errors(
                    context, candidate, supply_chain
                )

        self.assertIn(
            "configured dependency-vulnerability handoff authentication failed",
            errors,
        )

    def test_dependency_vulnerability_companion_rejects_expired_authorization_preparation(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            context, candidate, supply_chain, companion_path = (
                _dependency_vulnerability_case(Path(directory))
            )
            companion = read_json(companion_path)
            assert isinstance(companion, dict)
            companion["validUntil"] = "2026-08-09T12:00:00Z"
            companion["summaryDigest"] = dependency_vulnerability_semantic_digest(
                companion, "summaryDigest"
            )
            write_json(companion_path, companion)
            _write_dependency_vulnerability_handoff(context, companion_path)

            with mock.patch.dict(
                os.environ, _dependency_vulnerability_handoff_environment()
            ), mock.patch(
                "cryptad_certification.engines.stable_1_0_maintenance._now",
                return_value=dt.datetime(2026, 8, 9, 12, 0, tzinfo=dt.timezone.utc),
            ):
                errors = _dependency_vulnerability_promotion_errors(
                    context, candidate, supply_chain
                )

        self.assertIn(
            "dependency-vulnerability promotion companion is stale at authorization preparation",
            errors,
        )

    def test_pre_activation_dependency_vulnerability_companion_remains_optional(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            context, candidate, supply_chain, companion = (
                _dependency_vulnerability_case(
                    Path(directory), frozen_at="2026-08-08T23:59:59Z"
                )
            )
            companion.unlink()
            context.manifest.inputs.pop("dependencyVulnerabilityPromotionSummary")

            errors = _dependency_vulnerability_promotion_errors(
                context, candidate, supply_chain
            )

        self.assertEqual(errors, [])

    def test_dependency_vulnerability_policy_digest_precedes_activation_decision(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            context, candidate, supply_chain, companion = (
                _dependency_vulnerability_case(Path(directory))
            )
            companion.unlink()
            context.manifest.inputs.pop("dependencyVulnerabilityPromotionSummary")
            policy_path = (
                context.workspace_root
                / "tools/release-certification/"
                "stable-1.0-dependency-vulnerability-policy.json"
            )
            policy = read_json(policy_path)
            assert isinstance(policy, dict)
            policy["effectiveAt"] = "2099-08-09T00:00:00Z"
            write_json(policy_path, policy)

            errors = _dependency_vulnerability_promotion_errors(
                context, candidate, supply_chain
            )

        self.assertEqual(
            errors,
            ["the checked-in dependency-vulnerability policy digest is invalid"],
        )

    def test_dependency_vulnerability_policy_rejects_digest_valid_activation_mismatch(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            context, candidate, supply_chain, companion = (
                _dependency_vulnerability_case(Path(directory))
            )
            companion.unlink()
            context.manifest.inputs.pop("dependencyVulnerabilityPromotionSummary")
            policy_path = (
                context.workspace_root
                / "tools/release-certification/"
                "stable-1.0-dependency-vulnerability-policy.json"
            )
            policy = read_json(policy_path)
            assert isinstance(policy, dict)
            activation = policy["governanceActivation"]
            assert isinstance(activation, dict)
            activation["candidateFrozenAtNotBefore"] = "2099-08-09T00:00:00Z"
            policy["policyDigest"] = dependency_vulnerability_semantic_digest(
                policy, "policyDigest"
            )
            write_json(policy_path, policy)

            errors = _dependency_vulnerability_promotion_errors(
                context, candidate, supply_chain
            )

        self.assertEqual(
            errors,
            [
                "the checked-in dependency-vulnerability policy activation timestamps differ"
            ],
        )

    def test_dependency_vulnerability_companion_uses_semantic_reverse_index_digest(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy_target = (
                root
                / "tools/release-certification/"
                "stable-1.0-dependency-vulnerability-policy.json"
            )
            policy_target.parent.mkdir(parents=True)
            shutil.copyfile(
                workspace_root()
                / "tools/release-certification/"
                "stable-1.0-dependency-vulnerability-policy.json",
                policy_target,
            )
            policy = read_json(policy_target)
            assert isinstance(policy, dict)
            candidate = dataclasses.replace(
                _candidate(root), frozen_at="2026-08-09T01:00:00Z"
            )
            predecessor = _ga_and_predecessor()[1]
            supply_chain = _supply_chain_summary(candidate, predecessor)
            artifact_digest = next(
                row["digest"]
                for row in supply_chain["artifacts"]
                if row["name"] == "component-reverse-index"
            )
            self.assertNotEqual(
                artifact_digest, supply_chain["vulnerabilityReverseIndexDigest"]
            )
            supply_path = root / "stable-1.0-supply-chain-summary.json"
            write_json(supply_path, supply_chain)
            vulnerability_summary_digest = _digest("f")
            write_json(
                root / "stable-1.0-vulnerability-summary.json",
                {"summaryDigest": vulnerability_summary_digest},
            )
            companion = _dependency_vulnerability_summary(
                candidate,
                predecessor,
                supply_chain,
                policy_digest=str(policy["policyDigest"]),
                vulnerability_summary_digest=vulnerability_summary_digest,
            )
            write_json(
                root / "stable-1.0-dependency-vulnerability-summary.json", companion
            )
            context = _context(
                root,
                inputs={
                    "dependencyVulnerabilityPromotionSummary": (
                        "stable-1.0-dependency-vulnerability-summary.json"
                    ),
                    "stableVulnerabilitySummary": (
                        "stable-1.0-vulnerability-summary.json"
                    ),
                },
            )
            _write_dependency_vulnerability_handoff(
                context,
                root / "stable-1.0-dependency-vulnerability-summary.json",
            )
            loaded_supply_chain = LoadedJson(
                "supplyChainPromotionSummary",
                supply_path,
                supply_chain,
                file_digest(supply_path),
            )

            with mock.patch.dict(
                os.environ, _dependency_vulnerability_handoff_environment()
            ):
                errors = _dependency_vulnerability_promotion_errors(
                    context, candidate, loaded_supply_chain
                )

        self.assertEqual(errors, [])

    def test_dependency_vulnerability_companion_rejects_reverse_index_file_digest(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy_target = (
                root
                / "tools/release-certification/"
                "stable-1.0-dependency-vulnerability-policy.json"
            )
            policy_target.parent.mkdir(parents=True)
            shutil.copyfile(
                workspace_root()
                / "tools/release-certification/"
                "stable-1.0-dependency-vulnerability-policy.json",
                policy_target,
            )
            policy = read_json(policy_target)
            assert isinstance(policy, dict)
            candidate = dataclasses.replace(
                _candidate(root), frozen_at="2026-08-09T01:00:00Z"
            )
            predecessor = _ga_and_predecessor()[1]
            supply_chain = _supply_chain_summary(candidate, predecessor)
            artifact_digest = next(
                row["digest"]
                for row in supply_chain["artifacts"]
                if row["name"] == "component-reverse-index"
            )
            supply_path = root / "stable-1.0-supply-chain-summary.json"
            write_json(supply_path, supply_chain)
            vulnerability_summary_digest = _digest("f")
            write_json(
                root / "stable-1.0-vulnerability-summary.json",
                {"summaryDigest": vulnerability_summary_digest},
            )
            companion = _dependency_vulnerability_summary(
                candidate,
                predecessor,
                supply_chain,
                policy_digest=str(policy["policyDigest"]),
                vulnerability_summary_digest=vulnerability_summary_digest,
            )
            companion["componentReverseIndexDigest"] = artifact_digest
            companion["summaryDigest"] = dependency_vulnerability_semantic_digest(
                companion, "summaryDigest"
            )
            write_json(
                root / "stable-1.0-dependency-vulnerability-summary.json", companion
            )
            context = _context(
                root,
                inputs={
                    "dependencyVulnerabilityPromotionSummary": (
                        "stable-1.0-dependency-vulnerability-summary.json"
                    ),
                    "stableVulnerabilitySummary": (
                        "stable-1.0-vulnerability-summary.json"
                    ),
                },
            )
            _write_dependency_vulnerability_handoff(
                context,
                root / "stable-1.0-dependency-vulnerability-summary.json",
            )
            loaded_supply_chain = LoadedJson(
                "supplyChainPromotionSummary",
                supply_path,
                supply_chain,
                file_digest(supply_path),
            )

            with mock.patch.dict(
                os.environ, _dependency_vulnerability_handoff_environment()
            ):
                errors = _dependency_vulnerability_promotion_errors(
                    context, candidate, loaded_supply_chain
                )

        self.assertIn(
            "dependency-vulnerability companion reverse-index digest differs", errors
        )

    def test_companion_assets_bind_policy_roles_and_exact_summary_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy_target = (
                root
                / "tools/release-certification/stable-1.0-supply-chain-policy.json"
            )
            policy_target.parent.mkdir(parents=True)
            shutil.copyfile(
                workspace_root()
                / "tools/release-certification/stable-1.0-supply-chain-policy.json",
                policy_target,
            )
            candidate = _candidate(root)
            predecessor = _ga_and_predecessor()[1]
            value = _supply_chain_summary(candidate, predecessor)
            path = root / "stable-1.0-supply-chain-summary.json"
            write_json(path, value)
            loaded = LoadedJson(
                "supplyChainPromotionSummary", path, value, file_digest(path)
            )

            rows = _supply_chain_companion_assets(_context(root), loaded)
            summary_size = path.stat().st_size

        self.assertEqual([row["role"] for row in rows], list(PUBLICATION_ROLE_FILES))
        self.assertEqual(rows[-1]["digest"], loaded.digest)
        self.assertEqual(rows[-1]["sizeBytes"], summary_size)
        self.assertEqual(
            rows[-1]["publicUri"],
            "https://github.com/crypta-network/cryptad/releases/download/"
            f"v{BUILD}/stable-1.0-supply-chain-summary.json",
        )

    def test_supply_chain_summary_binds_exact_candidate_and_predecessor(self) -> None:
        """Pre-activation frozen candidates retain their historical validation contract."""

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy_target = (
                root
                / "tools/release-certification/stable-1.0-supply-chain-policy.json"
            )
            policy_target.parent.mkdir(parents=True)
            shutil.copyfile(
                workspace_root()
                / "tools/release-certification/stable-1.0-supply-chain-policy.json",
                policy_target,
            )
            candidate = _candidate(root)
            predecessor = _ga_and_predecessor()[1]
            value = _supply_chain_summary(candidate, predecessor)
            path = root / "stable-1.0-supply-chain-summary.json"
            write_json(path, value)
            loaded = LoadedJson(
                "supplyChainPromotionSummary", path, value, file_digest(path)
            )

            errors = _supply_chain_promotion_errors(
                _context(root), loaded, candidate, predecessor
            )

        self.assertEqual(errors, [])

    def test_governed_supply_chain_summary_requires_protected_handoff(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy_target = (
                root
                / "tools/release-certification/stable-1.0-supply-chain-policy.json"
            )
            policy_target.parent.mkdir(parents=True)
            shutil.copyfile(
                workspace_root()
                / "tools/release-certification/stable-1.0-supply-chain-policy.json",
                policy_target,
            )
            candidate = dataclasses.replace(
                _candidate(root), frozen_at="2026-08-04T00:00:00Z"
            )
            predecessor = _ga_and_predecessor()[1]
            value = _supply_chain_summary(candidate, predecessor)
            path = root / "stable-1.0-supply-chain-summary.json"
            write_json(path, value)
            loaded = LoadedJson(
                "supplyChainPromotionSummary", path, value, file_digest(path)
            )

            errors = _supply_chain_promotion_errors(
                _context(root), loaded, candidate, predecessor
            )

        self.assertIn(
            "Stable supply-chain summary lacks its protected producer handoff", errors
        )

    def test_governed_supply_chain_summary_authenticates_exact_handoff(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy_target = (
                root
                / "tools/release-certification/stable-1.0-supply-chain-policy.json"
            )
            policy_target.parent.mkdir(parents=True)
            shutil.copyfile(
                workspace_root()
                / "tools/release-certification/stable-1.0-supply-chain-policy.json",
                policy_target,
            )
            candidate = dataclasses.replace(
                _candidate(root), frozen_at="2026-08-04T00:00:00Z"
            )
            predecessor = _ga_and_predecessor()[1]
            value = _supply_chain_summary(candidate, predecessor)
            path = root / "stable-1.0-supply-chain-summary.json"
            write_json(path, value)
            context = _context(root)
            _write_supply_chain_handoff(context, path, value)
            loaded = LoadedJson(
                "supplyChainPromotionSummary", path, value, file_digest(path)
            )

            with mock.patch.dict(os.environ, _supply_chain_handoff_environment()):
                errors = _supply_chain_promotion_errors(
                    context, loaded, candidate, predecessor
                )

        self.assertEqual(errors, [])

    def test_governed_supply_chain_summary_rejects_unkeyed_handoff(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy_target = (
                root
                / "tools/release-certification/stable-1.0-supply-chain-policy.json"
            )
            policy_target.parent.mkdir(parents=True)
            shutil.copyfile(
                workspace_root()
                / "tools/release-certification/stable-1.0-supply-chain-policy.json",
                policy_target,
            )
            candidate = dataclasses.replace(
                _candidate(root), frozen_at="2026-08-04T00:00:00Z"
            )
            predecessor = _ga_and_predecessor()[1]
            value = _supply_chain_summary(candidate, predecessor)
            path = root / "stable-1.0-supply-chain-summary.json"
            write_json(path, value)
            context = _context(root)
            _write_supply_chain_handoff(context, path, value)
            loaded = LoadedJson(
                "supplyChainPromotionSummary", path, value, file_digest(path)
            )

            with mock.patch.dict(os.environ, {}, clear=True):
                errors = _supply_chain_promotion_errors(
                    context, loaded, candidate, predecessor
                )

        self.assertIn(
            "configured supply-chain handoff authentication key is invalid",
            errors,
        )

    def test_governed_supply_chain_summary_rejects_manifest_handoff_substitution(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy_target = (
                root
                / "tools/release-certification/stable-1.0-supply-chain-policy.json"
            )
            policy_target.parent.mkdir(parents=True)
            shutil.copyfile(
                workspace_root()
                / "tools/release-certification/stable-1.0-supply-chain-policy.json",
                policy_target,
            )
            candidate = dataclasses.replace(
                _candidate(root), frozen_at="2026-08-04T00:00:00Z"
            )
            predecessor = _ga_and_predecessor()[1]
            value = _supply_chain_summary(candidate, predecessor)
            path = root / "stable-1.0-supply-chain-summary.json"
            write_json(path, value)
            context = _context(root)
            _write_supply_chain_handoff(context, path, value)
            context.manifest.policies["metadata"][
                "stableSupplyChainArtifactDigest"
            ] = _digest("e")
            loaded = LoadedJson(
                "supplyChainPromotionSummary", path, value, file_digest(path)
            )

            with mock.patch.dict(os.environ, _supply_chain_handoff_environment()):
                errors = _supply_chain_promotion_errors(
                    context, loaded, candidate, predecessor
                )

        self.assertIn(
            "Stable supply-chain producer handoff differs from manifest "
            "stableSupplyChainArtifactDigest",
            errors,
        )

    def test_supply_chain_promotion_does_not_accept_publication_as_passing(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy_target = (
                root
                / "tools/release-certification/stable-1.0-supply-chain-policy.json"
            )
            policy_target.parent.mkdir(parents=True)
            shutil.copyfile(
                workspace_root()
                / "tools/release-certification/stable-1.0-supply-chain-policy.json",
                policy_target,
            )
            candidate = _candidate(root)
            predecessor = _ga_and_predecessor()[1]
            value = _supply_chain_summary(candidate, predecessor)
            value["evidence"].append(
                {
                    "evidenceId": "stable-supply-chain.publication",
                    "status": "pass",
                    "nonWaivable": True,
                }
            )
            value["summaryDigest"] = supply_chain_semantic_digest(
                value, "summaryDigest"
            )
            path = root / "stable-1.0-supply-chain-summary.json"
            write_json(path, value)
            loaded = LoadedJson(
                "supplyChainPromotionSummary", path, value, file_digest(path)
            )

            errors = _supply_chain_promotion_errors(
                _context(root), loaded, candidate, predecessor
            )

        self.assertIn(
            "Stable supply-chain promotion summary falsely claims publication passed",
            errors,
        )

    def test_supply_chain_summary_rejects_substituted_predecessor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy_target = (
                root
                / "tools/release-certification/stable-1.0-supply-chain-policy.json"
            )
            policy_target.parent.mkdir(parents=True)
            shutil.copyfile(
                workspace_root()
                / "tools/release-certification/stable-1.0-supply-chain-policy.json",
                policy_target,
            )
            candidate = _candidate(root)
            predecessor = _ga_and_predecessor()[1]
            value = _supply_chain_summary(candidate, predecessor)
            value["predecessorProductDigest"] = _digest("d")
            value["summaryDigest"] = supply_chain_semantic_digest(
                value, "summaryDigest"
            )
            path = root / "stable-1.0-supply-chain-summary.json"
            write_json(path, value)
            loaded = LoadedJson(
                "supplyChainPromotionSummary", path, value, file_digest(path)
            )

            errors = _supply_chain_promotion_errors(
                _context(root), loaded, candidate, predecessor
            )

        self.assertIn(
            "Stable supply-chain summary predecessorProductDigest differs", errors
        )

    def test_command_and_selftest_are_registered(self) -> None:
        self.assertIn("stable-maintenance", COMMAND_NAMES)
        self.assertEqual(
            selftest.SUITE_MODULES["stable-maintenance"],
            [
                "cryptad_certification.tests.test_stable_maintenance",
                "cryptad_certification.tests.test_stable_maintenance_freeze",
                "cryptad_certification.tests.test_stable_maintenance_supply_chain",
                "cryptad_certification.tests.test_stable_maintenance_authorization_compatibility",
                "cryptad_certification.tests.test_stable_maintenance_publication",
                "cryptad_certification.tests.test_stable_maintenance_workflows",
            ],
        )
        parsed = build_parser().parse_args(["stable-maintenance", "--self-test"])
        self.assertEqual(parsed.command, "stable-maintenance")
        self.assertTrue(parsed.self_test)
