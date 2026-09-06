"""Focused offline tests for Stable 1.0 protected execution orchestration."""

from __future__ import annotations

import copy
import json
import os
import re
import subprocess
import tempfile
import unittest
import zipfile
from contextlib import nullcontext
from datetime import timedelta
from pathlib import Path
from unittest import mock

from cryptad_certification.engines import stable_1_0_protected_release as protected
from cryptad_certification.engines import stable_1_0_supply_chain as supply_chain
from cryptad_certification.engines.stable_1_0_supply_chain_reproducibility import (
    promotion_summary_errors,
)
from cryptad_certification.io import read_json, write_json
from cryptad_certification.models import EvidenceEnvelope
from cryptad_certification.schema_validation import validate_schema
from cryptad_certification.tests.test_release_certification_stable_dependency_vulnerability import (
    _promotion_summary as dependency_promotion_summary,
    _semantic_digest as dependency_semantic_digest,
)
from cryptad_certification.tests.test_release_certification_stable_supply_chain import (
    _promotion_summary as supply_chain_promotion_summary,
)
from cryptad_certification.tests.support import workspace_root

COMMIT = "a" * 40
DIGEST_ZERO = "sha256:" + "0" * 64
RELEASE_ID = "cryptad-stable-1-0-rc-3"
EVIDENCE_IDS = [
    "app-platform",
    "catalog-operations",
    "hyphanet-interop",
    "live-network",
    "multi-node",
    "network-scale",
    "performance",
    "previous-candidate",
    "release-certification",
    "release-history",
    "sandbox-provider",
    "security-drills",
    "stable-dependency-vulnerability",
    "stable-readiness",
    "stable-supply-chain",
    "stable-vulnerability",
    "third-party-intake",
]
EVIDENCE_SCHEMAS = {
    "app-platform": "evidence-envelope-v2.schema.json",
    "catalog-operations": "stable-1.0-rc-catalog-operations-v1.schema.json",
    "hyphanet-interop": "evidence-envelope-v2.schema.json",
    "live-network": "evidence-envelope-v2.schema.json",
    "multi-node": "evidence-envelope-v2.schema.json",
    "network-scale": "evidence-envelope-v2.schema.json",
    "performance": "evidence-envelope-v2.schema.json",
    "previous-candidate": "evidence-envelope-v2.schema.json",
    "release-certification": "evidence-envelope-v2.schema.json",
    "release-history": "evidence-envelope-v2.schema.json",
    "sandbox-provider": "evidence-envelope-v2.schema.json",
    "security-drills": "evidence-envelope-v2.schema.json",
    "stable-dependency-vulnerability": "stable-1.0-dependency-vulnerability-promotion-summary-v1.schema.json",
    "stable-readiness": "evidence-envelope-v2.schema.json",
    "stable-supply-chain": "stable-1.0-supply-chain-promotion-summary-v1.schema.json",
    "stable-vulnerability": "stable-1.0-vulnerability-summary-v1.schema.json",
    "third-party-intake": "evidence-envelope-v2.schema.json",
}
EVIDENCE_KINDS = {
    "app-platform": "app-platform-smoke",
    "catalog-operations": "stable-1.0-rc-catalog-operations",
    "hyphanet-interop": "release-certification",
    "live-network": "live-network-beta-smoke",
    "multi-node": "multi-node-beta-soak",
    "network-scale": "network-scale-soak",
    "performance": "release-certification",
    "previous-candidate": "migrated-v1-previous-candidate",
    "release-certification": "release-certification",
    "release-history": "migrated-v1-release-history",
    "sandbox-provider": "app-platform-smoke",
    "security-drills": "production-security-response",
    "stable-dependency-vulnerability": "stable-1.0-dependency-vulnerability-promotion-summary",
    "stable-readiness": "stable-1.0-readiness",
    "stable-supply-chain": "stable-1.0-supply-chain-promotion-summary",
    "stable-vulnerability": "stable-1.0-vulnerability-summary",
    "third-party-intake": "production-beta-release",
}
RC_GENERATED_EVIDENCE_IDS = {
    "app-platform",
    "hyphanet-interop",
    "performance",
    "release-certification",
    "sandbox-provider",
    "stable-readiness",
    "third-party-intake",
}
RC_INPUT_PATHS = {
    "catalog-operations": "build/stable-rc-protected-inputs/stable-catalog-operations-summary.json",
    "live-network": "build/stable-rc-protected-inputs/live-network-summary.json",
    "multi-node": "build/stable-rc-protected-inputs/multi-node-soak-summary.json",
    "network-scale": "build/stable-rc-protected-inputs/network-scale-soak-summary.json",
    "previous-candidate": "build/stable-rc-protected-inputs/previous-candidate-summary.json",
    "release-history": "build/stable-rc-protected-inputs/release-history-summary.json",
    "security-drills": "build/stable-rc-protected-inputs/security-drills-summary.json",
}
PROTECTED_EVIDENCE = {
    "stable-dependency-vulnerability": (
        ".github/workflows/stable-1.0-dependency-vulnerability-evaluation.yml",
        "stable-1.0-dependency-vulnerability-evaluation",
    ),
    "stable-supply-chain": (
        ".github/workflows/stable-1.0-supply-chain.yml",
        "stable-1.0-supply-chain-evidence",
    ),
    "stable-vulnerability": (
        ".github/workflows/stable-1.0-vulnerability-intake.yml",
        "stable-1.0-vulnerability-case",
    ),
}


def _binding(root: Path, path: Path) -> dict[str, object]:
    return {
        "path": path.as_posix(),
        "sha256": protected._digest(root / path),  # noqa: SLF001
        "schema": None,
    }


def _contract(root: Path) -> dict[str, object]:
    evidence: list[dict[str, object]] = []
    for index, evidence_id in enumerate(EVIDENCE_IDS, 1):
        relative = Path(
            RC_INPUT_PATHS.get(evidence_id, f"evidence/{evidence_id}.json")
        )
        path = root / relative
        evidence_value: dict[str, object]
        if evidence_id == "third-party-intake":
            evidence_value = EvidenceEnvelope(
                kind="production-beta-release",
                generated_at="2026-08-16T00:00:00Z",
                subject={
                    "releaseId": RELEASE_ID,
                    "version": "3",
                    "profile": "stable-review",
                    "component": "production-beta",
                },
                result={
                    "status": "pass",
                    "decision": "go",
                    "promotionReady": True,
                    "exitCode": 0,
                },
                counts={"evidence": 0, "blockers": 0, "warnings": 0, "waivers": 0},
                redaction={
                    "status": "pass",
                    "findingCount": 0,
                    "findings": [],
                    "guarantees": {},
                },
                payload={
                    "legacy": {
                        "schemaVersion": 1,
                        "releaseId": RELEASE_ID,
                        "version": "3",
                        "status": "pass",
                        "promotionReady": True,
                        "nonRelease": False,
                    }
                },
            ).to_json()
        else:
            evidence_value = {
                "kind": EVIDENCE_KINDS[evidence_id],
                "releaseId": RELEASE_ID,
                "buildVersion": "3",
                "candidateSourceCommit": COMMIT,
                "status": "pass",
                "promotionReady": True,
                "nonRelease": False,
                "fixture": False,
                "simulatedOnly": False,
                "testSigning": False,
                "redaction": {"status": "pass", "findingCount": 0, "findings": []},
            }
        write_json(path, evidence_value)
        file_binding = _binding(root, relative)
        file_binding["schema"] = EVIDENCE_SCHEMAS[evidence_id]
        protected_producer = evidence_id in PROTECTED_EVIDENCE
        if protected_producer:
            workflow, environment = PROTECTED_EVIDENCE[evidence_id]
            artifact_name = {
                "stable-dependency-vulnerability": (
                    f"stable-1.0-dependency-vulnerability-{RELEASE_ID}-evaluation"
                ),
                "stable-supply-chain": (
                    f"stable-1.0-supply-chain-{RELEASE_ID}-comparison"
                ),
                "stable-vulnerability": (
                    f"stable-1.0-vulnerability-protected-ledger-wide-{index}-1"
                ),
            }[evidence_id]
            producer: dict[str, object] | None = {
                "repository": "crypta-network/cryptad",
                "workflowPath": workflow,
                "workflowCommit": COMMIT,
                "runId": str(index),
                "runAttempt": "1",
                "artifactName": artifact_name,
                "artifactDigest": "sha256:" + f"{index:064x}",
                "environment": environment,
                "conclusion": "success",
            }
            authority_class = "protected-producer"
        elif evidence_id in RC_GENERATED_EVIDENCE_IDS:
            producer = None
            authority_class = "rc-generated-prerequisite"
        else:
            producer = None
            authority_class = "exact-dispatch-input"
        evidence.append(
            {
                "id": evidence_id,
                "kind": EVIDENCE_KINDS[evidence_id],
                "authorityClass": authority_class,
                "file": file_binding,
                "producer": producer,
                "releaseId": RELEASE_ID,
                "buildVersion": "3",
                "candidateCommit": COMMIT,
                "classification": (
                    "protected-operation" if protected_producer else "offline-prerequisite"
                ),
                "status": "pass",
                "promotionReady": True,
                "nonRelease": False,
                "fixture": False,
                "simulatedOnly": False,
                "testSigning": False,
                "validUntil": "2026-08-17T00:00:00Z",
            }
        )
    known_issues_relative = Path(
        "build/stable-rc-protected-inputs/public-beta-known-issues.json"
    )
    write_json(
        root / known_issues_relative,
        {"schemaVersion": 1, "kind": "public-beta-known-issues", "issues": []},
    )
    third_party_relative = Path(
        "build/stable-rc-protected-inputs/third-party-intake-summary.json"
    )
    write_json(
        root / third_party_relative,
        {
            "status": "pass",
            "releaseId": RELEASE_ID,
            "buildVersion": "3",
            "fixtureOnly": False,
            "simulatedOnly": False,
            "nonRelease": False,
            "nonProduction": False,
            "generatedAt": "2026-08-16T00:00:00Z",
            "evidence": [],
            "redaction": {"status": "pass", "findingCount": 0, "findings": []},
        },
    )
    return {
        "schemaVersion": 1,
        "kind": "stable-1.0-protected-release-execution",
        "executionId": "stable-1-0-build-3",
        "evaluationTime": "2026-08-16T01:00:00Z",
        "repository": {
            "identity": "github.com/crypta-network/cryptad",
            "candidateCommit": COMMIT,
            "sourceRef": "refs/heads/release/3",
            "requireCleanWorkspace": True,
        },
        "release": {
            "id": RELEASE_ID,
            "integerBuild": "3",
            "milestone": "Stable 1.0",
            "freezeMode": "first-freeze",
            "previousRcFreeze": None,
        },
        "publicTargets": {
            "artifactBaseUri": "https://1.1.1.1/stable/",
            "catalogPrimaryUri": "https://1.1.1.1/catalog/primary/first-party-catalog.properties",
            "catalogMirrorUris": ["https://1.1.1.1/catalog/mirror/first-party-catalog.properties"],
            "catalogRollbackUri": "https://1.1.1.1/catalog/rollback/first-party-catalog.properties",
        },
        "authorities": {
            "protectedEnvironments": [
                "stable-1-0-rc",
                "stable-1-0-ga-evidence",
                "stable-1-0-ga",
                "stable-1-0-public-observation",
            ],
            "workflowPaths": {
                "rc": ".github/workflows/stable-1.0-rc-release.yml",
                "ga": ".github/workflows/stable-1.0-ga-promotion.yml",
                "publicObservation": ".github/workflows/stable-1.0-public-observation.yml",
            },
            "keyIdentities": {
                "appSigningKeyId": "app-production-2026",
                "reviewerKeyId": "reviewer-production-2026",
                "reviewPolicyId": "stable-review-v1",
                "reviewPolicyVersion": "1",
                "catalogSigningKeyId": "catalog-production-2026",
            },
        },
        "upstreamEvidence": evidence,
        "rcInputs": {
            "publicBetaKnownIssues": _binding(root, known_issues_relative),
            "thirdPartyIntake": _binding(root, third_party_relative),
            "goNoGoWaivers": None,
            "stableReadinessWaivers": None,
            "freezeExceptions": None,
        },
        "archives": [],
        "workflowCoordinates": {
            "rc": None,
            "gaValidation": None,
            "gaEvidenceApproval": None,
            "gaPublication": None,
            "publicObservation": None,
        },
        "ga": {
            "publicationIntent": "validate-only",
            "publicObservationRequired": True,
            "selectedRc": None,
            "validationIdentityDigest": None,
            "authorization": None,
        },
        "operationEvidence": {
            "preflight": None,
            "rcPreflight": None,
            "rcFreeze": None,
            "rcFreezeRecord": None,
            "rcFreezeArtifact": None,
            "gaValidation": None,
            "gaValidationIdentity": None,
            "gaValidationArtifact": None,
            "gaPromotionPlan": None,
            "gaPublication": None,
            "gaPublicationArtifact": None,
            "publicObservation": None,
            "publicObservationArtifact": None,
            "independentReproducibility": None,
            "independentReproducibilityArtifact": None,
            "independentReproducibilityCoordinate": None,
        },
        "lifecycleState": "planned",
        "evidenceClassification": {
            "repositoryImplementation": "present",
            "offlineVerification": "pending",
            "protectedOperation": "not-performed",
            "publicObservation": "not-performed",
        },
        "blockedReason": None,
    }


def _preflight_summary(contract: dict[str, object]) -> dict[str, object]:
    return {
        "schemaVersion": 1,
        "kind": "stable-1.0-protected-release-execution-summary",
        "executionId": contract["executionId"],
        "mode": "preflight",
        "status": "pass",
        "promotionReady": True,
        "lifecycleState": "preflight-passed",
        "contractDigest": protected._plan_digest(contract),  # noqa: SLF001
        "candidateCommit": contract["repository"]["candidateCommit"],  # type: ignore[index]
        "releaseId": contract["release"]["id"],  # type: ignore[index]
        "buildVersion": contract["release"]["integerBuild"],  # type: ignore[index]
        "evidenceClassification": {
            "repositoryImplementation": "present",
            "offlineVerification": "passed",
            "protectedRcOperation": "not-performed",
            "gaValidation": "not-performed",
            "gaPublication": "not-performed",
            "publicObservation": "not-performed",
            "independentReproducibility": "pending",
        },
        "dispatchPackage": protected._dispatch_package(contract),  # noqa: SLF001
        "findings": [],
        "redaction": {"status": "pass", "findingCount": 0, "findings": []},
    }


def _rc_input_map(root: Path, contract: dict[str, object]) -> dict[str, object]:
    preflight_relative = Path("build/stable-rc-protected-inputs/preflight-summary.json")
    write_json(root / preflight_relative, _preflight_summary(contract))
    preflight_binding = _binding(root, preflight_relative)
    preflight_binding["schema"] = protected.SUMMARY_SCHEMA
    contract["operationEvidence"]["preflight"] = preflight_binding  # type: ignore[index]
    rows = {
        row["id"]: row
        for row in contract["upstreamEvidence"]  # type: ignore[index]
    }
    materialized_ids = sorted(set(EVIDENCE_IDS) - RC_GENERATED_EVIDENCE_IDS)
    coordinate_names = {
        "stable-vulnerability": "stableVulnerability",
        "stable-supply-chain": "stableSupplyChain",
        "stable-dependency-vulnerability": "stableDependencyVulnerability",
    }
    stable_coordinates = {}
    for evidence_id, name in coordinate_names.items():
        producer = rows[evidence_id]["producer"]
        stable_coordinates[name] = {
            field: producer[field]
            for field in ("runId", "runAttempt", "artifactName", "artifactDigest")
        }
    return {
        "schemaVersion": 1,
        "repository": {
            "candidateCommit": contract["repository"]["candidateCommit"],  # type: ignore[index]
            "sourceRef": contract["repository"]["sourceRef"],  # type: ignore[index]
        },
        "release": {
            "id": contract["release"]["id"],  # type: ignore[index]
            "integerBuild": contract["release"]["integerBuild"],  # type: ignore[index]
            "freezeMode": contract["release"]["freezeMode"],  # type: ignore[index]
        },
        "artifactBaseUri": contract["publicTargets"]["artifactBaseUri"],  # type: ignore[index]
        "keyIdentities": contract["authorities"]["keyIdentities"],  # type: ignore[index]
        "evidenceFiles": {
            evidence_id: rows[evidence_id]["file"]["path"]
            for evidence_id in materialized_ids
        },
        "stableAuthorityCoordinates": stable_coordinates,
        "rcGeneratedEvidenceIds": sorted(RC_GENERATED_EVIDENCE_IDS),
        "rcInputs": {
            "publicBetaKnownIssues": contract["rcInputs"]["publicBetaKnownIssues"]["path"],  # type: ignore[index]
            "thirdPartyIntake": contract["rcInputs"]["thirdPartyIntake"]["path"],  # type: ignore[index]
            "goNoGoWaivers": None,
            "stableReadinessWaivers": None,
            "freezeExceptions": None,
            "previousRcFreeze": None,
        },
        "preflightReceipt": preflight_relative.as_posix(),
    }


def _coordinate(
    workflow: str,
    environment: str,
    *,
    run_id: str = "100",
    run_attempt: str = "1",
    artifact_name: str = "protected-evidence",
    artifact_digest: str = "sha256:" + "f" * 64,
) -> dict[str, object]:
    return {
        "repository": "crypta-network/cryptad",
        "workflowPath": workflow,
        "workflowCommit": COMMIT,
        "runId": run_id,
        "runAttempt": run_attempt,
        "artifactName": artifact_name,
        "artifactDigest": artifact_digest,
        "environment": environment,
        "conclusion": "success",
    }


def _rc_lineage_receipt(coordinate: dict[str, object]) -> dict[str, object]:
    workflow = {
        "provider": "github-actions",
        "repository": coordinate["repository"],
        "workflowName": "Stable 1.0 RC Release Freeze",
        "workflowRef": f"{coordinate['workflowPath']}@{coordinate['workflowCommit']}",
        "runId": int(str(coordinate["runId"])),
        "runAttempt": int(str(coordinate["runAttempt"])),
        "artifactName": coordinate["artifactName"],
        "artifactDigest": coordinate["artifactDigest"],
        "environment": coordinate["environment"],
        "conclusion": "success",
    }
    selection = {
        "freezeDigest": "sha256:" + "2" * 64,
        "freezeFileDigest": "sha256:" + "3" * 64,
        "archiveDigest": "sha256:" + "4" * 64,
        "productDistributionDigest": "sha256:" + "5" * 64,
        "sourceCommit": COMMIT,
        "workflow": workflow,
    }
    return {
        "schemaVersion": 1,
        "kind": "stable-1.0-rc-lineage",
        "generatedAt": "2026-08-16T00:30:00Z",
        "releaseId": RELEASE_ID,
        "buildVersion": "3",
        "profile": "stable-review",
        "component": "stable-rc",
        "sourceCommit": COMMIT,
        "sourceRef": "refs/heads/release/3",
        "status": "pass",
        "selectedFreeze": selection,
        "latestSuccessfulFreeze": copy.deepcopy(selection),
        "history": [
            {
                "ordinal": 1,
                "freezeMode": "first-freeze",
                "successful": True,
                **copy.deepcopy(selection),
            }
        ],
        "acceptedFreezeExceptionHistoryDigest": protected._semantic_digest([]),  # noqa: SLF001
        "redaction": {"status": "pass", "findingCount": 0, "findings": []},
    }


def _ga_validation_receipt(
    contract: dict[str, object],
    selected: dict[str, object],
    lineage_digest: str,
    authorization: dict[str, object],
    authorization_digest: str,
) -> dict[str, object]:
    surface_digest = "sha256:" + "6" * 64
    frozen_surfaces = {
        surface: {
            "status": "pass",
            "frozenDigest": surface_digest,
            "currentDigest": surface_digest,
            "drift": False,
        }
        for surface in (
            "platformApi",
            "stableCatalog",
            "firstPartyApps",
            "contentProfiles",
            "limitations",
        )
    }
    return {
        "schemaVersion": 1,
        "kind": "stable-1.0-ga-validation",
        "generatedAt": "2026-08-16T00:45:00Z",
        "state": "publication-authorized",
        "releaseId": RELEASE_ID,
        "buildVersion": "3",
        "profile": "stable-review",
        "component": "stable-ga",
        "sourceCommit": COMMIT,
        "sourceRef": "refs/heads/release/3",
        "status": "pass",
        "promotionReady": True,
        "nonRelease": False,
        "decision": "go",
        "selectedRc": {
            "status": "pass",
            "promotionReady": True,
            "nonRelease": False,
            "driftStatus": "no-drift",
            "finalDecision": "go",
            "lineageDigest": lineage_digest,
            "freezeDigest": selected["freezeDigest"],
            "archiveDigest": selected["archiveDigest"],
            "productDistributionDigest": selected["productDigest"],
            "catalogDigest": authorization["catalogDigest"],
            "catalogRevision": authorization["catalogRevision"],
        },
        "postFreezeValidation": {
            "status": "pass",
            "exactRcBinding": True,
            "validationDigest": "sha256:" + "7" * 64,
            "evidenceAgeDays": 0,
            "requiredUpgradePredecessor": {
                "releaseId": "cryptad-public-beta-2",
                "buildVersion": "2",
                "previousCandidateDigest": "sha256:" + "d" * 64,
                "productDistributionDigest": "sha256:" + "e" * 64,
            },
        },
        "authorization": {
            "status": "authorized",
            "authorizationId": authorization["authorizationId"],
            "authorizationDigest": authorization_digest,
            "publicationTargetsDigest": authorization[
                "publicationTargetsDigest"
            ],
            "allowedPublicationScope": authorization[
                "allowedPublicationScope"
            ],
        },
        "payloadIdentity": {
            "rcProductDigest": selected["productDigest"],
            "gaProductDigest": selected["productDigest"],
            "bitIdentical": True,
            "rebuildPerformed": False,
        },
        "frozenSurfaces": frozen_surfaces,
        "acceptedRcWaivers": [],
        "blockers": [],
        "redaction": {"status": "pass", "findingCount": 0, "findings": []},
    }


def _ga_validation_identity(
    contract: dict[str, object],
    selected: dict[str, object],
    lineage: dict[str, object],
    lineage_digest: str,
    authorization: dict[str, object],
) -> dict[str, object]:
    selected_freeze = lineage["selectedFreeze"]
    assert isinstance(selected_freeze, dict)
    targets = protected._canonical_publication_targets(contract)  # noqa: SLF001
    product_digest = selected["productDigest"]
    return {
        "schemaVersion": 1,
        "kind": "stable-1.0-ga-validation-authorization-identity",
        "releaseId": RELEASE_ID,
        "buildVersion": "3",
        "profile": "stable-review",
        "component": "stable-ga",
        "sourceCommit": COMMIT,
        "sourceRef": "refs/heads/release/3",
        "lineageDigest": lineage_digest,
        "freezeDigest": selected["freezeDigest"],
        "freezeFileDigest": selected_freeze["freezeFileDigest"],
        "archiveDigest": selected["archiveDigest"],
        "productDistributionDigest": product_digest,
        "checksumsDigest": "sha256:" + "4" * 64,
        "provenanceDigest": "sha256:" + "5" * 64,
        "postFreezeValidationDigest": "sha256:" + "7" * 64,
        "postFreezeValidationGeneratedAt": "2026-08-16T00:30:00Z",
        "requiredUpgradePredecessor": {
            "releaseId": "cryptad-public-beta-2",
            "buildVersion": "2",
            "previousCandidateDigest": "sha256:" + "d" * 64,
            "productDistributionDigest": "sha256:" + "e" * 64,
        },
        "catalogDigest": authorization["catalogDigest"],
        "catalogRevision": authorization["catalogRevision"],
        "platformApiDigest": "sha256:" + "6" * 64,
        "firstPartyAppsDigest": "sha256:" + "7" * 64,
        "contentProfilesDigest": "sha256:" + "8" * 64,
        "limitationsDigest": "sha256:" + "9" * 64,
        "publicationTargets": targets,
        "publicationTargetsDigest": protected._semantic_digest(targets),  # noqa: SLF001
        "acceptedRcWaivers": [],
        "payloadIdentity": {
            "rcProductDigest": product_digest,
            "gaProductDigest": product_digest,
            "bitIdentical": True,
            "rebuildPerformed": False,
        },
    }


def _post_freeze_validation_record(
    selected: dict[str, object], freeze_record: dict[str, object]
) -> dict[str, object]:
    from cryptad_certification.tests.test_stable_ga import (
        _policy as ga_policy,
        _post_freeze_validation as ga_post_freeze_validation,
        _selected_rc as ga_selected_rc,
    )

    value = ga_post_freeze_validation(ga_selected_rc(), ga_policy())
    catalog = freeze_record["stableCatalog"]
    assert isinstance(catalog, dict)
    exact_binding = {
        "releaseId": RELEASE_ID,
        "buildVersion": "3",
        "sourceCommit": COMMIT,
        "freezeDigest": selected["freezeDigest"],
        "productDistributionDigest": selected["productDigest"],
        "archiveDigest": selected["archiveDigest"],
        "catalogDigest": selected["catalogDigest"],
        "catalogRevision": selected["catalogRevision"],
    }

    def replace_bindings(item: object) -> None:
        if isinstance(item, dict):
            if "binding" in item:
                item["binding"] = copy.deepcopy(exact_binding)
            for child in item.values():
                replace_bindings(child)
        elif isinstance(item, list):
            for child in item:
                replace_bindings(child)

    value.update(
        generatedAt="2026-08-16T00:30:00Z",
        releaseId=RELEASE_ID,
        buildVersion="3",
        sourceCommit=COMMIT,
        sourceRef="refs/heads/release/3",
        freezeDigest=selected["freezeDigest"],
        productDistributionDigest=selected["productDigest"],
        archiveDigest=selected["archiveDigest"],
        stableCatalog={
            "catalogId": catalog["catalogId"],
            "channel": "stable",
            "revision": selected["catalogRevision"],
            "catalogDigest": selected["catalogDigest"],
            "signatureDigest": catalog["signatureDigest"],
            "signingKeyId": catalog["catalogSigningKeyId"],
        },
    )
    replace_bindings(value)
    upgrade = value["scenarios"]["upgradeRollbackStatePreservation"]
    assert isinstance(upgrade, dict)
    upgrade.update(
        previousCandidateDigest="sha256:" + "d" * 64,
        previousReleaseId="cryptad-public-beta-2",
        previousBuildVersion="2",
        previousProductDigest="sha256:" + "e" * 64,
    )
    return value


def _authorization_document(
    contract: dict[str, object],
    selected: dict[str, object],
    validation_identity: str,
    *,
    expires_at: str = "2026-08-17T00:00:00Z",
) -> dict[str, object]:
    targets = protected._canonical_publication_targets(contract)  # noqa: SLF001
    targets_digest = protected._semantic_digest(targets)  # noqa: SLF001
    return {
        "schemaVersion": 1,
        "kind": "stable-1.0-ga-authorization",
        "generatedAt": "2026-08-16T00:30:00Z",
        "authorizationId": "stable-ga-3-authorization",
        "releaseId": RELEASE_ID,
        "buildVersion": "3",
        "sourceCommit": COMMIT,
        "freezeDigest": selected["freezeDigest"],
        "archiveDigest": selected["archiveDigest"],
        "productDistributionDigest": selected["productDigest"],
        "catalogDigest": "sha256:" + "b" * 64,
        "catalogRevision": 3,
        "gaValidationDigest": validation_identity,
        "publicationTargets": targets,
        "publicationTargetsDigest": targets_digest,
        "status": "authorized",
        "authorizationRole": "stable-release-manager",
        "approverIdentity": "leumor",
        "approvedAt": "2026-08-16T00:15:00Z",
        "expiresAt": expires_at,
        "reviewWindowHours": 24,
        "allowedPublicationScope": [
            "git-tag",
            "github-release",
            "release-assets",
            "stable-catalog-confirmation",
            "post-publication-verification",
        ],
        "redaction": {"status": "pass", "findingCount": 0, "findings": []},
    }


def _selected_rc() -> dict[str, object]:
    return {
        "runId": "10",
        "runAttempt": "1",
        "artifactName": f"stable-1-0-rc-{RELEASE_ID}-3-10-1",
        "artifactDigest": "sha256:" + "1" * 64,
        "freezeDigest": "sha256:" + "2" * 64,
        "productDigest": "sha256:" + "3" * 64,
        "archiveDigest": "sha256:" + "4" * 64,
        "catalogDigest": "sha256:" + "b" * 64,
        "catalogRevision": 3,
    }


def _rc_freeze_record(selected: dict[str, object]) -> dict[str, object]:
    from cryptad_certification.engines.stable_1_0_rc_freeze import (
        freeze_content_digest,
    )
    from cryptad_certification.tests.test_stable_rc import _freeze

    value = _freeze()
    candidate = value["candidate"]
    catalog = value["stableCatalog"]
    assert isinstance(candidate, dict)
    assert isinstance(catalog, dict)
    candidate.update(
        releaseId=RELEASE_ID,
        buildVersion="3",
        sourceCommit=COMMIT,
        sourceRef="refs/heads/release/3",
        productionDistributionDigest=selected["productDigest"],
    )
    catalog.update(
        catalogId="stable-first-party",
        revision=selected["catalogRevision"],
        catalogDigest=selected["catalogDigest"],
        signatureDigest="sha256:" + "d" * 64,
        catalogSigningKeyId="catalog-production-2026",
    )
    primary = catalog["primaryHealth"]
    assert isinstance(primary, dict)
    primary.update(
        revision=selected["catalogRevision"],
        digest=selected["catalogDigest"],
    )
    for mirror in catalog["mirrorHealth"]:
        assert isinstance(mirror, dict)
        mirror.update(
            revision=selected["catalogRevision"],
            digest=selected["catalogDigest"],
        )
    rollback = catalog["verifiedRollback"]
    assert isinstance(rollback, dict)
    rollback.update(revision=2, digest="sha256:" + "e" * 64)
    value["contentDigest"] = freeze_content_digest(value)
    selected["freezeDigest"] = value["contentDigest"]
    return value


def _publication_receipt(
    contract: dict[str, object],
    selected: dict[str, object],
    coordinate: dict[str, object],
    promotion_identity_digest: str,
) -> dict[str, object]:
    targets = contract["publicTargets"]
    assert isinstance(targets, dict)
    base = targets["artifactBaseUri"]
    release_notes_digest = "sha256:" + "6" * 64
    asset_rows = (
        (f"cryptad-stable-1.0-rc-3.tar.gz", selected["archiveDigest"], 4096),
        (f"crypta-stable-1.0-rc-3-product.tar.gz", selected["productDigest"], 8192),
        ("stable-1.0-ga-release-notes.md", release_notes_digest, 512),
        ("stable-1.0-ga-known-limitations.json", "sha256:" + "7" * 64, 256),
        ("stable-1.0-ga-provenance.json", "sha256:" + "8" * 64, 1024),
        ("stable-1.0-maintenance-baseline.json", "sha256:" + "9" * 64, 1024),
        ("stable-1.0-ga-checksums.txt", "sha256:" + "a" * 64, 384),
    )
    catalog_digest = "sha256:" + "b" * 64
    return {
        "schemaVersion": 1,
        "kind": "stable-1.0-ga-publication-receipt",
        "generatedAt": "2026-08-16T01:00:00Z",
        "releaseId": RELEASE_ID,
        "buildVersion": "3",
        "sourceCommit": COMMIT,
        "publicationState": "publication-complete",
        "operation": "created",
        "artifactBaseUri": base,
        "tag": {
            "name": "v3",
            "targetCommit": COMMIT,
            "annotated": True,
            "verificationStatus": "pass",
        },
        "githubRelease": {
            "releaseId": 3,
            "publicUrl": "https://github.com/crypta-network/cryptad/releases/tag/v3",
            "releaseNotesDigest": release_notes_digest,
            "verificationStatus": "pass",
        },
        "assets": [
            {
                "name": name,
                "sizeBytes": size,
                "digest": digest,
                "publicUri": f"{base}{name}",
                "verificationStatus": "pass",
            }
            for name, digest, size in asset_rows
        ],
        "freezeDigest": selected["freezeDigest"],
        "productDistributionDigest": selected["productDigest"],
        "archiveDigest": selected["archiveDigest"],
        "gaPromotionSummaryDigest": promotion_identity_digest,
        "catalog": {
            "catalogId": "stable-first-party",
            "channel": "stable",
            "revision": 3,
            "catalogDigest": catalog_digest,
            "signatureDigest": "sha256:" + "d" * 64,
            "signingKeyId": "catalog-production-2026",
            "artifactTimestamp": "2026-08-16T00:45:00Z",
            "primary": {
                "locationId": "primary",
                "publicUri": targets["catalogPrimaryUri"],
                "digest": catalog_digest,
                "signatureVerified": True,
                "verificationStatus": "pass",
            },
            "mirrors": [
                {
                    "locationId": f"mirror-{index}",
                    "publicUri": uri,
                    "digest": catalog_digest,
                    "signatureVerified": True,
                    "transportFallbackOnly": True,
                    "verificationStatus": "pass",
                }
                for index, uri in enumerate(targets["catalogMirrorUris"], 1)
            ],
            "rollback": {
                "revision": 2,
                "digest": "sha256:" + "e" * 64,
                "publicUri": targets["catalogRollbackUri"],
                "signatureDigest": "sha256:" + "f" * 64,
                "signingKeyId": "catalog-production-2026",
                "signatureVerified": True,
                "verificationStatus": "pass",
            },
            "keyRotationStatus": "complete",
            "advisoryCount": 0,
            "denylistCount": 0,
            "verificationStatus": "pass",
        },
        "releaseNotesDigest": release_notes_digest,
        "publishedAt": "2026-08-16T00:55:00Z",
        "workflow": {
            "provider": "github-actions",
            "repository": coordinate["repository"],
            "workflowName": "Stable 1.0 GA Promotion",
            "runId": int(str(coordinate["runId"])),
            "runAttempt": int(str(coordinate["runAttempt"])),
            "environment": coordinate["environment"],
        },
        "publicStateObservation": {
            "tag": {"status": "verified"},
            "githubRelease": {"status": "verified"},
            "releaseAssets": {
                "status": "verified",
                "observedCount": len(asset_rows),
                "missingPlannedAssets": [],
                "unexpectedCount": 0,
                "unexpectedNameDigests": [],
            },
        },
        "finalVerificationStatus": "pass",
        "redaction": {"status": "pass", "findingCount": 0, "findings": []},
    }


def _publication_plan(
    contract: dict[str, object],
    receipt: dict[str, object],
    promotion_identity_digest: str,
) -> dict[str, object]:
    targets = contract["publicTargets"]
    assert isinstance(targets, dict)
    receipt_assets = receipt["assets"]
    assert isinstance(receipt_assets, list)
    receipt_catalog = receipt["catalog"]
    assert isinstance(receipt_catalog, dict)
    primary = receipt_catalog["primary"]
    mirrors = receipt_catalog["mirrors"]
    rollback = receipt_catalog["rollback"]
    assert isinstance(primary, dict)
    assert isinstance(mirrors, list)
    assert isinstance(rollback, dict)
    roles = {
        "cryptad-stable-1.0-rc-3.tar.gz": ("rc-archive", "immutable-rc"),
        "crypta-stable-1.0-rc-3-product.tar.gz": ("rc-product", "immutable-rc"),
        "stable-1.0-ga-release-notes.md": ("release-notes", "ga-metadata"),
        "stable-1.0-ga-known-limitations.json": ("known-limitations", "ga-metadata"),
        "stable-1.0-ga-provenance.json": ("provenance", "ga-metadata"),
        "stable-1.0-maintenance-baseline.json": ("maintenance-baseline", "ga-metadata"),
        "stable-1.0-ga-checksums.txt": ("checksums", "ga-metadata"),
    }
    return {
        "schemaVersion": 1,
        "kind": "stable-1.0-ga-publication-plan",
        "generatedAt": "2026-08-16T00:45:00Z",
        "releaseId": RELEASE_ID,
        "buildVersion": "3",
        "sourceCommit": COMMIT,
        "expectedTag": "v3",
        "expectedReleaseBranch": "release/3",
        "artifactBaseUri": targets["artifactBaseUri"],
        "publicationTargetsDigest": protected._semantic_digest(  # noqa: SLF001
            protected._canonical_publication_targets(contract)  # noqa: SLF001
        ),
        "publicationState": "publication-authorized",
        "promotionIdentityDigest": promotion_identity_digest,
        "releaseNotesDigest": receipt["releaseNotesDigest"],
        "catalog": {
            "catalogId": receipt_catalog["catalogId"],
            "channel": "stable",
            "revision": receipt_catalog["revision"],
            "catalogDigest": receipt_catalog["catalogDigest"],
            "signatureDigest": receipt_catalog["signatureDigest"],
            "signingKeyId": receipt_catalog["signingKeyId"],
            "artifactTimestamp": receipt_catalog["artifactTimestamp"],
            "primary": {
                "locationId": primary["locationId"],
                "publicUri": primary["publicUri"],
            },
            "mirrors": [
                {
                    "locationId": mirror["locationId"],
                    "publicUri": mirror["publicUri"],
                }
                for mirror in mirrors
                if isinstance(mirror, dict)
            ],
            "rollbackUri": rollback["publicUri"],
            "rollbackRevision": rollback["revision"],
            "rollbackDigest": rollback["digest"],
            "keyRotationState": "complete",
            "advisoryCount": 0,
            "denylistCount": 0,
            "publicationOperation": "verify-exact-frozen-bytes",
        },
        "assets": [
            {
                "name": asset["name"],
                "sizeBytes": asset["sizeBytes"],
                "digest": asset["digest"],
                "role": roles[asset["name"]][0],
                "sourceKind": roles[asset["name"]][1],
            }
            for asset in receipt_assets
            if isinstance(asset, dict)
        ],
        "sideEffectsPerformed": False,
        "redaction": {"status": "pass", "findingCount": 0, "findings": []},
    }


def _public_observation(
    contract: dict[str, object],
    receipt: dict[str, object],
    receipt_digest: str,
) -> dict[str, object]:
    targets = contract["publicTargets"]
    selected = contract["ga"]["selectedRc"]  # type: ignore[index]
    assert isinstance(targets, dict)
    assert isinstance(selected, dict)
    assets = receipt["assets"]  # type: ignore[index]
    assert isinstance(assets, list)
    catalog = receipt["catalog"]
    assert isinstance(catalog, dict)
    catalog_digest = catalog["catalogDigest"]
    rollback = catalog["rollback"]
    assert isinstance(rollback, dict)

    def observed_target(
        role: str, uri: object, digest: object, size: int
    ) -> dict[str, object]:
        return {
            "role": role,
            "publicUri": uri,
            "sha256": digest,
            "size": size,
            "status": "observed-exact",
        }

    observed_targets = [
        *[
            observed_target(
                f"release-asset-{index}",
                asset["publicUri"], asset["digest"], asset["sizeBytes"],
            )
            for index, asset in enumerate(assets, 1)
        ],
        observed_target("catalog-primary", targets["catalogPrimaryUri"], catalog_digest, 256),
        observed_target(
            "catalog-primary-signature",
            protected.catalog_signature_uri(targets["catalogPrimaryUri"]),
            catalog["signatureDigest"],
            128,
        ),
        *[
            row
            for index, uri in enumerate(targets["catalogMirrorUris"], 1)
            for row in (
                observed_target(f"catalog-mirror-{index}", uri, catalog_digest, 256),
                observed_target(
                    f"catalog-mirror-{index}-signature",
                    protected.catalog_signature_uri(uri),
                    catalog["signatureDigest"],
                    128,
                ),
            )
        ],
        observed_target("catalog-rollback", targets["catalogRollbackUri"], rollback["digest"], 256),
        observed_target(
            "catalog-rollback-signature",
            protected.catalog_signature_uri(targets["catalogRollbackUri"]),
            rollback["signatureDigest"],
            128,
        ),
    ]
    return {
        "schemaVersion": 1,
        "kind": "stable-1.0-protected-release-public-observation",
        "repositoryIdentity": "github.com/crypta-network/cryptad",
        "releaseId": RELEASE_ID,
        "buildVersion": "3",
        "candidateCommit": COMMIT,
        "publicationReceiptDigest": receipt_digest,
        "productDigest": selected["productDigest"],
        "observedAt": "2026-08-16T02:00:00Z",
        "observer": {
            "repository": "crypta-network/cryptad",
            "workflowPath": ".github/workflows/stable-1.0-public-observation.yml",
            "workflowCommit": COMMIT,
            "runId": "31",
            "runAttempt": "1",
            "artifactName": "stable-1-0-public-observation-3-31-1",
            "environment": "stable-1-0-public-observation",
            "conclusion": "success",
            "readOnly": True,
        },
        "tag": {
            "name": receipt["tag"]["name"],  # type: ignore[index]
            "targetCommit": receipt["tag"]["targetCommit"],  # type: ignore[index]
            "annotated": True,
            "status": "observed-exact",
        },
        "githubRelease": {
            "releaseId": receipt["githubRelease"]["releaseId"],  # type: ignore[index]
            "publicUrl": receipt["githubRelease"]["publicUrl"],  # type: ignore[index]
            "name": "Cryptad Stable 1.0 (v3)",
            "tagName": "v3",
            "targetCommitish": COMMIT,
            "draft": False,
            "prerelease": False,
            "releaseNotesDigest": receipt["githubRelease"]["releaseNotesDigest"],  # type: ignore[index]
            "status": "observed-exact",
        },
        "targets": observed_targets,
        "status": "pass",
        "fixture": False,
        "redaction": {"status": "pass", "findingCount": 0, "findings": []},
    }


def _bind_observation_coordinate(
    contract: dict[str, object], observation: dict[str, object]
) -> None:
    observer = observation["observer"]
    assert isinstance(observer, dict)
    contract["workflowCoordinates"]["publicObservation"] = {  # type: ignore[index]
        **{key: value for key, value in observer.items() if key != "readOnly"},
        "artifactDigest": "sha256:" + "5" * 64,
    }


def _bind_observation_artifact(
    root: Path, contract: dict[str, object], observation_path: Path
) -> Path:
    archive_path = root / "stable-1.0-public-observation-artifact.zip"
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_STORED) as archive:
        member = zipfile.ZipInfo("stable-1.0-public-observation.json")
        member.external_attr = 0o100644 << 16
        archive.writestr(member, observation_path.read_bytes())
    binding = _binding(root, Path(archive_path.name))
    contract["operationEvidence"]["publicObservationArtifact"] = binding  # type: ignore[index]
    contract["workflowCoordinates"]["publicObservation"]["artifactDigest"] = (  # type: ignore[index]
        binding["sha256"]
    )
    return archive_path


def _bind_ga_validation_artifact(
    root: Path, contract: dict[str, object]
) -> Path:
    archive_path = root / "stable-1.0-ga-validated-artifact.zip"
    evidence = contract["operationEvidence"]
    authorization = contract["ga"]["authorization"]  # type: ignore[index]
    assert isinstance(evidence, dict)
    assert isinstance(authorization, dict)
    members = {
        "component/artifacts/legacy/stable-1.0-ga-validation.json": evidence[
            "gaValidation"
        ],
        "publication-inputs/stable-1.0-ga-validation-authorization-identity.json": evidence[
            "gaValidationIdentity"
        ],
        "publication-inputs/stable-1.0-ga-authorization.json": authorization["file"],
        "publication-inputs/stable-1.0-rc-lineage.json": evidence["rcFreeze"],
        "publication-inputs/stable-1.0-rc-freeze.json": evidence["rcFreezeRecord"],
        "component/artifacts/legacy/stable-1.0-ga-publication-plan.json": evidence[
            "gaPromotionPlan"
        ],
        "publication-inputs/checksums.txt": {"path": "checksums.txt"},
        "publication-inputs/provenance.json": {"path": "provenance.json"},
        "publication-inputs/stable-1.0-rc-validation.json": {
            "path": "stable-1.0-rc-validation.json"
        },
    }
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_STORED) as archive:
        for member_name, member_binding in members.items():
            assert isinstance(member_binding, dict)
            archive.write(root / str(member_binding["path"]), arcname=member_name)
    binding = _binding(root, Path(archive_path.name))
    evidence["gaValidationArtifact"] = binding
    contract["workflowCoordinates"]["gaEvidenceApproval"]["artifactDigest"] = (  # type: ignore[index]
        binding["sha256"]
    )
    contract["workflowCoordinates"]["gaValidation"]["artifactDigest"] = binding[  # type: ignore[index]
        "sha256"
    ]
    return archive_path


def _configure_publish(
    root: Path,
    contract: dict[str, object],
    selected: dict[str, object] | None = None,
) -> dict[str, object]:
    selected = selected or _selected_rc()
    validation_identity = "sha256:" + "7" * 64
    authorization_path = root / "exact-authorization.json"
    write_json(
        authorization_path,
        _authorization_document(contract, selected, validation_identity),
    )
    targets_digest = protected._semantic_digest(  # noqa: SLF001
        protected._canonical_publication_targets(contract)  # noqa: SLF001
    )
    contract["ga"] = {
        "publicationIntent": "publish",
        "publicObservationRequired": True,
        "selectedRc": selected,
        "validationIdentityDigest": validation_identity,
        "authorization": {
            "file": {
                **_binding(root, Path("exact-authorization.json")),
                "schema": protected.GA_AUTHORIZATION_SCHEMA,
            },
            "authorizationId": "stable-ga-3-authorization",
            "authorizationFileDigest": protected._digest(authorization_path),  # noqa: SLF001
            "identityDigest": validation_identity,
            "authorizedTargetsDigest": targets_digest,
            "validUntil": "2026-08-17T00:00:00Z",
            "role": "stable-release-manager",
            "approverId": "leumor",
        },
    }
    contract["workflowCoordinates"]["gaEvidenceApproval"] = _coordinate(  # type: ignore[index]
        ".github/workflows/stable-1.0-ga-promotion.yml",
        "stable-1-0-ga-evidence",
        run_id="20",
        artifact_name=f"stable-1-0-ga-validated-{RELEASE_ID}-3-20-1",
    )
    return selected


def _configure_publication_receipt(
    root: Path, contract: dict[str, object]
) -> tuple[dict[str, object], Path]:
    selected = _selected_rc()
    freeze_record = _rc_freeze_record(selected)
    freeze_record_path = root / "stable-1.0-rc-freeze.json"
    write_json(freeze_record_path, freeze_record)
    rc_preflight_path = root / "stable-1.0-rc-consumed-preflight.json"
    write_json(rc_preflight_path, _preflight_summary(contract))
    rc_preflight_binding = _binding(root, Path(rc_preflight_path.name))
    rc_preflight_binding["schema"] = protected.SUMMARY_SCHEMA
    contract["operationEvidence"]["rcPreflight"] = rc_preflight_binding  # type: ignore[index]
    rc_archive_path = root / "stable-1.0-rc-artifact.zip"
    with zipfile.ZipFile(
        rc_archive_path, "w", compression=zipfile.ZIP_STORED
    ) as archive:
        archive.write(
            freeze_record_path,
            arcname="artifacts/legacy/stable-1.0-rc-freeze.json",
        )
        archive.write(
            rc_preflight_path,
            arcname=(
                "artifacts/protected-execution/"
                "stable-1.0-protected-release-preflight-summary.json"
            ),
        )
    rc_archive_binding = _binding(root, Path(rc_archive_path.name))
    selected["artifactDigest"] = rc_archive_binding["sha256"]
    _configure_publish(root, contract, selected)
    rc_coordinate = _coordinate(
        ".github/workflows/stable-1.0-rc-release.yml",
        "stable-1-0-rc",
        run_id=str(selected["runId"]),
        run_attempt=str(selected["runAttempt"]),
        artifact_name=str(selected["artifactName"]),
        artifact_digest=str(selected["artifactDigest"]),
    )
    lineage = _rc_lineage_receipt(rc_coordinate)
    for freeze in (
        lineage["selectedFreeze"],
        lineage["latestSuccessfulFreeze"],
        lineage["history"][0],
    ):
        freeze["freezeDigest"] = selected["freezeDigest"]
        freeze["archiveDigest"] = selected["archiveDigest"]
        freeze["productDistributionDigest"] = selected["productDigest"]
        freeze["freezeFileDigest"] = protected._digest(freeze_record_path)  # noqa: SLF001
    lineage_path = root / "stable-1.0-rc-lineage.json"
    write_json(lineage_path, lineage)
    contract["workflowCoordinates"]["rc"] = rc_coordinate  # type: ignore[index]
    contract["operationEvidence"]["rcFreeze"] = {  # type: ignore[index]
        **_binding(root, Path(lineage_path.name)),
        "schema": protected.RC_LINEAGE_SCHEMA,
    }
    contract["operationEvidence"]["rcFreezeRecord"] = {  # type: ignore[index]
        **_binding(root, Path(freeze_record_path.name)),
        "schema": protected.RC_FREEZE_SCHEMA,
    }
    contract["operationEvidence"]["rcFreezeArtifact"] = rc_archive_binding  # type: ignore[index]

    authorization_path = root / "exact-authorization.json"
    authorization = json.loads(authorization_path.read_text(encoding="utf-8"))
    identity = _ga_validation_identity(
        contract,
        selected,
        lineage,
        protected._digest(lineage_path),  # noqa: SLF001
        authorization,
    )
    checksums_path = root / "checksums.txt"
    checksums_path.write_text("fixture checksums\n", encoding="utf-8")
    provenance_path = root / "provenance.json"
    write_json(provenance_path, {"fixture": False, "status": "pass"})
    post_freeze = _post_freeze_validation_record(selected, freeze_record)
    post_freeze_path = root / "stable-1.0-rc-validation.json"
    write_json(post_freeze_path, post_freeze)
    upgrade = post_freeze["scenarios"]["upgradeRollbackStatePreservation"]
    assert isinstance(upgrade, dict)
    predecessor = {
        "releaseId": upgrade["previousReleaseId"],
        "buildVersion": upgrade["previousBuildVersion"],
        "previousCandidateDigest": upgrade["previousCandidateDigest"],
        "productDistributionDigest": upgrade["previousProductDigest"],
    }
    identity.update(
        checksumsDigest=protected._digest(checksums_path),  # noqa: SLF001
        provenanceDigest=protected._digest(provenance_path),  # noqa: SLF001
        postFreezeValidationDigest=protected._digest(post_freeze_path),  # noqa: SLF001
        postFreezeValidationGeneratedAt=post_freeze["generatedAt"],
        requiredUpgradePredecessor=predecessor,
        platformApiDigest=protected._semantic_digest(freeze_record["platformApi"]),  # noqa: SLF001
        firstPartyAppsDigest=protected._semantic_digest(freeze_record["firstPartyApps"]),  # noqa: SLF001
        contentProfilesDigest=protected._semantic_digest(freeze_record["contentFormatProfiles"]),  # noqa: SLF001
        limitationsDigest=protected._semantic_digest(freeze_record["limitationsAndPolicy"]),  # noqa: SLF001
    )
    validation_identity_digest = protected._semantic_digest(identity)  # noqa: SLF001
    authorization = _authorization_document(
        contract,
        selected,
        validation_identity_digest,
    )
    write_json(authorization_path, authorization)
    contract["ga"]["validationIdentityDigest"] = validation_identity_digest  # type: ignore[index]
    contract["ga"]["authorization"]["identityDigest"] = validation_identity_digest  # type: ignore[index]
    contract["ga"]["authorization"]["file"] = {  # type: ignore[index]
        **_binding(root, Path(authorization_path.name)),
        "schema": protected.GA_AUTHORIZATION_SCHEMA,
    }
    contract["ga"]["authorization"]["authorizationFileDigest"] = (  # type: ignore[index]
        protected._digest(authorization_path)  # noqa: SLF001
    )
    identity_path = root / "stable-1.0-ga-validation-authorization-identity.json"
    write_json(identity_path, identity)
    contract["operationEvidence"]["gaValidationIdentity"] = {  # type: ignore[index]
        **_binding(root, Path(identity_path.name)),
        "schema": protected.GA_VALIDATION_IDENTITY_SCHEMA,
    }
    validation = _ga_validation_receipt(
        contract,
        selected,
        protected._digest(lineage_path),  # noqa: SLF001
        authorization,
        protected._digest(authorization_path),  # noqa: SLF001
    )
    validation["postFreezeValidation"]["validationDigest"] = protected._digest(  # type: ignore[index] # noqa: SLF001
        post_freeze_path
    )
    validation["postFreezeValidation"]["requiredUpgradePredecessor"] = predecessor  # type: ignore[index]
    validation_path = root / "stable-1.0-ga-validation.json"
    write_json(validation_path, validation)
    contract["workflowCoordinates"]["gaValidation"] = _coordinate(  # type: ignore[index]
        ".github/workflows/stable-1.0-ga-promotion.yml",
        "none",
        run_id="20",
        artifact_name=f"stable-1-0-ga-validated-{RELEASE_ID}-3-20-1",
    )
    contract["operationEvidence"]["gaValidation"] = {  # type: ignore[index]
        **_binding(root, Path(validation_path.name)),
        "schema": protected.GA_VALIDATION_SCHEMA,
    }
    coordinate = _coordinate(
        ".github/workflows/stable-1.0-ga-promotion.yml",
        "stable-1-0-ga",
        run_id="30",
        artifact_name=(
            f"stable-1-0-ga-publication-receipt-{RELEASE_ID}-3-30-1"
        ),
    )
    promotion_identity_digest = protected._ga_promotion_identity_digest(identity)  # noqa: SLF001
    receipt = _publication_receipt(
        contract,
        selected,
        coordinate,
        promotion_identity_digest,
    )
    plan = _publication_plan(contract, receipt, promotion_identity_digest)
    plan_path = root / "stable-1.0-ga-publication-plan.json"
    write_json(plan_path, plan)
    contract["operationEvidence"]["gaPromotionPlan"] = {  # type: ignore[index]
        **_binding(root, Path(plan_path.name)),
        "schema": protected.GA_PUBLICATION_PLAN_SCHEMA,
    }
    _bind_ga_validation_artifact(root, contract)
    receipt_path = root / "ga-publication-receipt.json"
    write_json(receipt_path, receipt)
    contract["workflowCoordinates"]["gaPublication"] = coordinate  # type: ignore[index]
    contract["operationEvidence"]["gaPublication"] = {  # type: ignore[index]
        **_binding(root, Path(receipt_path.name)),
        "schema": protected.GA_PUBLICATION_RECEIPT_SCHEMA,
    }
    publication_archive_path = root / "stable-1.0-ga-publication-artifact.zip"
    with zipfile.ZipFile(
        publication_archive_path, "w", compression=zipfile.ZIP_STORED
    ) as archive:
        archive.write(
            receipt_path,
            arcname="stable-1.0-ga-publication-receipt.json",
        )
    publication_archive_binding = _binding(
        root, Path(publication_archive_path.name)
    )
    contract["operationEvidence"][  # type: ignore[index]
        "gaPublicationArtifact"
    ] = publication_archive_binding
    contract["workflowCoordinates"]["gaPublication"][  # type: ignore[index]
        "artifactDigest"
    ] = publication_archive_binding["sha256"]
    preflight_path = root / "stable-1.0-protected-release-preflight.json"
    write_json(preflight_path, _preflight_summary(contract))
    preflight_binding = _binding(root, Path(preflight_path.name))
    preflight_binding["schema"] = protected.SUMMARY_SCHEMA
    contract["operationEvidence"]["preflight"] = preflight_binding  # type: ignore[index]
    contract["lifecycleState"] = "ga-published"
    contract["evidenceClassification"] = {
        "repositoryImplementation": "present",
        "offlineVerification": "passed",
        "protectedOperation": "completed",
        "publicObservation": "not-performed",
    }
    return receipt, receipt_path


class StableProtectedToolchainTests(unittest.TestCase):
    def test_checkout_matches_policy_and_rejects_gradle_coordinate_drift(self) -> None:
        root = workspace_root()
        policy = read_json(root / "tools/release-certification/stable-1.0-protected-release-policy.json")
        settings = subprocess.CompletedProcess(
            args=["java"], returncode=0, stdout="",
            stderr=(
                f"    java.version = {policy['toolchain']['setupJavaVersion'].split('+')[0]}\n"
                "    java.vendor = Eclipse Adoptium\n"
            ),
        )
        # Keep the real checkout's wrapper and build-logic checks; isolate only the host JVM.
        with mock.patch.object(protected.subprocess, "run", return_value=settings):
            self.assertEqual([], protected._toolchain_errors(root, policy))
            for field, value in (
                ("gradleVersion", "0.0.0"),
                ("gradleDistributionSha256", "0" * 64),
            ):
                with self.subTest(field=field):
                    drifted = copy.deepcopy(policy)
                    drifted["toolchain"][field] = value
                    self.assertEqual(
                        ["Gradle wrapper version differs from protected release policy"],
                        protected._toolchain_errors(root, drifted),
                    )


class StableProtectedReleaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.contract = _contract(self.root)
        self.policy = json.loads(
            (workspace_root() / "tools/release-certification/stable-1.0-protected-release-policy.json").read_text(
                encoding="utf-8"
            )
        )
        self.github_coordinate_auth = protected._github_actions_coordinate_errors  # noqa: SLF001
        self.source_auth = protected._source_errors  # noqa: SLF001
        github_auth_patcher = mock.patch.object(
            protected, "_github_actions_coordinate_errors", return_value=[]
        )
        github_auth_patcher.start()
        self.addCleanup(github_auth_patcher.stop)
        source_auth_patcher = mock.patch.object(
            protected, "_source_errors", return_value=[]
        )
        source_auth_patcher.start()
        self.addCleanup(source_auth_patcher.stop)

    def _preflight(
        self,
        contract: dict[str, object] | None = None,
        *,
        check_evidence: bool = False,
    ) -> list[str]:
        with mock.patch.object(protected, "_source_errors", return_value=[]), mock.patch.object(  # noqa: SLF001
            protected, "_toolchain_errors", return_value=[]
        ), mock.patch.object(protected, "_policy_errors", return_value=[]), (
            nullcontext()
            if check_evidence
            else mock.patch.object(protected, "_evidence_errors", return_value=[])
        ):
            return protected._preflight(  # noqa: SLF001
                self.root,
                contract or self.contract,
                self.policy,
                protected._timestamp(  # noqa: SLF001
                    (contract or self.contract)["evaluationTime"]  # type: ignore[index]
                ),
            )

    def test_example_matches_the_closed_contract_schema(self) -> None:
        example = json.loads(
            (workspace_root() / "tools/release-certification/manifests/stable-1.0-protected-release.example.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual([], validate_schema(example, protected.CONTRACT_SCHEMA))
        evidence_contracts = self.policy["requiredEvidenceContracts"]
        self.assertEqual(
            self.policy["requiredEvidenceIds"],
            [row["id"] for row in example["upstreamEvidence"]],
        )
        for row in example["upstreamEvidence"]:
            expected = evidence_contracts[row["id"]]
            self.assertEqual(expected["kind"], row["kind"])
            self.assertEqual(expected["schema"], row["file"]["schema"])
            self.assertEqual(expected["authorityClass"], row["authorityClass"])
            if "workflowPath" in expected:
                self.assertEqual(
                    expected["workflowPath"],
                    row["producer"]["workflowPath"],
                )
            if "environment" in expected:
                self.assertEqual(
                    expected["environment"],
                    row["producer"]["environment"],
                )
                self.assertEqual("protected-operation", row["classification"])
            else:
                self.assertIsNone(row["producer"])
                self.assertEqual("offline-prerequisite", row["classification"])
            if "rcInputPath" in expected:
                self.assertEqual(expected["rcInputPath"], row["file"]["path"])
        self.assertIn("publicBetaKnownIssues", example["rcInputs"])
        self.assertIn("thirdPartyIntake", example["rcInputs"])
        third_party_aggregate = next(
            row for row in example["upstreamEvidence"] if row["id"] == "third-party-intake"
        )
        self.assertNotEqual(
            third_party_aggregate["file"]["path"],
            example["rcInputs"]["thirdPartyIntake"]["path"],
        )
        evidence_findings = protected._evidence_errors(  # noqa: SLF001
            self.root,
            self.contract,
            self.policy,
            protected._timestamp("2026-08-16T01:00:00Z"),  # noqa: SLF001
        )
        self.assertFalse(
            any(item.startswith("upstream evidence third-party-intake") for item in evidence_findings),
            evidence_findings,
        )

    def test_legacy_v1_contract_without_independent_coordinate_preserves_preflight(self) -> None:
        legacy = copy.deepcopy(self.contract)
        legacy["operationEvidence"].pop("independentReproducibilityCoordinate")  # type: ignore[index]

        legacy_digest = protected._plan_digest(legacy)  # noqa: SLF001
        current_digest = protected._plan_digest(self.contract)  # noqa: SLF001
        input_map = _rc_input_map(self.root, legacy)
        preflight_binding = legacy["operationEvidence"]["preflight"]  # type: ignore[index]
        preflight_receipt = read_json(self.root / preflight_binding["path"])
        observed = protected._timestamp("2026-08-16T01:01:00Z")  # noqa: SLF001
        legacy["lifecycleState"] = "preflight-passed"
        legacy["evidenceClassification"]["offlineVerification"] = "passed"  # type: ignore[index]

        with mock.patch.object(protected, "_policy_errors", return_value=[]):
            closeout_findings, closeout_statuses = protected._closeout(  # noqa: SLF001
                self.root,
                legacy,
                self.policy,
            )

        self.assertEqual([], validate_schema(legacy, protected.CONTRACT_SCHEMA))
        self.assertNotEqual(current_digest, legacy_digest)
        self.assertEqual(legacy_digest, preflight_receipt["contractDigest"])
        self.assertEqual(
            [],
            protected.credential_free_preflight_receipt_errors(
                legacy,
                preflight_receipt,
                preflight_binding["sha256"],
            ),
        )
        self.assertEqual(
            [],
            protected._rc_dispatch_errors(  # noqa: SLF001
                self.root,
                legacy,
                self.policy,
                input_map,
                observed,
            ),
        )
        self.assertEqual([], closeout_findings)
        self.assertEqual("pending", closeout_statuses["independentReproducibility"])

    def test_optional_catalog_authority_evidence_does_not_change_the_plan_root(self) -> None:
        historical = copy.deepcopy(self.contract)
        current = copy.deepcopy(self.contract)
        current["workflowCoordinates"]["catalogAuthority"] = _coordinate(  # type: ignore[index]
            protected.CATALOG_AUTHORITY_WORKFLOW,
            protected.CATALOG_AUTHORITY_ENVIRONMENT,
        )
        current["operationEvidence"]["catalogAuthority"] = copy.deepcopy(  # type: ignore[index]
            current["rcInputs"]["publicBetaKnownIssues"]  # type: ignore[index]
        )

        self.assertEqual([], validate_schema(historical, protected.CONTRACT_SCHEMA))
        self.assertEqual([], validate_schema(current, protected.CONTRACT_SCHEMA))
        self.assertEqual(
            protected._plan_digest(historical),  # noqa: SLF001
            protected._plan_digest(current),  # noqa: SLF001
        )

    def test_rc_dispatch_binds_every_materialized_input_and_stable_coordinate(self) -> None:
        input_map = _rc_input_map(self.root, self.contract)
        observed = protected._timestamp("2026-08-16T01:01:00Z")  # noqa: SLF001

        self.assertEqual(
            [],
            protected._rc_dispatch_errors(  # noqa: SLF001
                self.root,
                self.contract,
                self.policy,
                input_map,
                observed,
            ),
        )

        substituted_bytes = copy.deepcopy(input_map)
        substituted_path = Path("build/stable-rc-protected-inputs/substituted-live.json")
        write_json(self.root / substituted_path, {"status": "pass", "other": True})
        substituted_bytes["evidenceFiles"]["live-network"] = substituted_path.as_posix()  # type: ignore[index]
        byte_findings = protected._rc_dispatch_errors(  # noqa: SLF001
            self.root,
            self.contract,
            self.policy,
            substituted_bytes,
            observed,
        )

        substituted_coordinate = copy.deepcopy(input_map)
        substituted_coordinate["stableAuthorityCoordinates"]["stableSupplyChain"][  # type: ignore[index]
            "runAttempt"
        ] = "2"
        coordinate_findings = protected._rc_dispatch_errors(  # noqa: SLF001
            self.root,
            self.contract,
            self.policy,
            substituted_coordinate,
            observed,
        )

        self.assertTrue(any("bytes differ" in item for item in byte_findings), byte_findings)
        self.assertTrue(
            any("coordinates differ" in item for item in coordinate_findings),
            coordinate_findings,
        )
        for identity in self.contract["authorities"]["keyIdentities"]:  # type: ignore[index]
            with self.subTest(identity=identity):
                substituted_identity = copy.deepcopy(input_map)
                substituted_identity["keyIdentities"][identity] = "other-production-identity"  # type: ignore[index]
                identity_findings = protected._rc_dispatch_errors(  # noqa: SLF001
                    self.root, self.contract, self.policy, substituted_identity, observed
                )
                self.assertTrue(any("runtime signing and review identities" in item for item in identity_findings))

        missing_preflight = copy.deepcopy(self.contract)
        missing_preflight["operationEvidence"]["preflight"] = None  # type: ignore[index]
        missing_findings = protected._rc_dispatch_errors(  # noqa: SLF001
            self.root,
            missing_preflight,
            self.policy,
            input_map,
            observed,
        )
        self.assertTrue(any("passing preflight receipt" in item for item in missing_findings))

        invented_authority = copy.deepcopy(self.contract)
        invented_row = next(
            row
            for row in invented_authority["upstreamEvidence"]  # type: ignore[index]
            if row["id"] == "app-platform"
        )
        invented_row["authorityClass"] = "protected-producer"
        invented_row["classification"] = "protected-operation"
        invented_row["producer"] = copy.deepcopy(
            next(
                row
                for row in invented_authority["upstreamEvidence"]  # type: ignore[index]
                if row["id"] == "stable-supply-chain"
            )["producer"]
        )
        invented_findings = protected._rc_dispatch_errors(  # noqa: SLF001
            self.root,
            invented_authority,
            self.policy,
            input_map,
            observed,
        )
        self.assertTrue(any("authority class differs" in item for item in invented_findings))

        unsafe_native = copy.deepcopy(self.contract)
        native_binding = unsafe_native["rcInputs"]["thirdPartyIntake"]  # type: ignore[index]
        native_path = self.root / native_binding["path"]
        native_value = json.loads(native_path.read_text(encoding="utf-8"))
        native_value["nonRelease"] = True
        write_json(native_path, native_value)
        native_binding["sha256"] = protected._digest(native_path)  # noqa: SLF001
        unsafe_map = _rc_input_map(self.root, unsafe_native)
        unsafe_findings = protected._rc_dispatch_errors(  # noqa: SLF001
            self.root,
            unsafe_native,
            self.policy,
            unsafe_map,
            observed,
        )
        self.assertTrue(
            any("third-party intake requires explicit nonRelease=false" in item for item in unsafe_findings),
            unsafe_findings,
        )

    def test_rc_dispatch_allows_only_bounded_runner_temp_protected_evidence(self) -> None:
        input_map = _rc_input_map(self.root, self.contract)
        observed = protected._timestamp("2026-08-16T01:01:00Z")  # noqa: SLF001
        supply_row = next(
            row
            for row in self.contract["upstreamEvidence"]  # type: ignore[index]
            if row["id"] == "stable-supply-chain"
        )
        runner_root = self.root / "runner-private"
        external_summary = runner_root / "stable-supply-chain-summary.json"
        external_summary.parent.mkdir(parents=True)
        external_summary.write_bytes(
            (self.root / supply_row["file"]["path"]).read_bytes()
        )
        input_map["evidenceFiles"]["stable-supply-chain"] = external_summary.as_posix()  # type: ignore[index]

        with mock.patch.dict(os.environ, {"RUNNER_TEMP": runner_root.as_posix()}):
            accepted = protected._rc_dispatch_errors(  # noqa: SLF001
                self.root,
                self.contract,
                self.policy,
                input_map,
                observed,
            )
            outside = copy.deepcopy(input_map)
            outside["evidenceFiles"]["stable-supply-chain"] = (  # type: ignore[index]
                self.root / supply_row["file"]["path"]
            ).as_posix()
            rejected = protected._rc_dispatch_errors(  # noqa: SLF001
                self.root,
                self.contract,
                self.policy,
                outside,
                observed,
            )

        self.assertEqual([], accepted)
        self.assertTrue(any("outside the protected runner" in item for item in rejected), rejected)

    def test_rc_dispatch_command_writes_a_passing_bound_summary(self) -> None:
        input_map = _rc_input_map(self.root, self.contract)
        contract_path = self.root / "protected-contract.json"
        input_map_path = self.root / "rc-input-map.json"
        output = (
            self.root
            / "build/release-certification"
            / str(self.contract["executionId"])
            / "stable-protected-release/rc-dispatch"
        )
        write_json(contract_path, self.contract)
        write_json(input_map_path, input_map)

        with mock.patch.object(protected, "_source_errors", return_value=[]), mock.patch.object(
            protected, "_policy_errors", return_value=[]
        ), mock.patch.object(
            protected,
            "_utc_now",
            return_value=protected._timestamp("2026-08-16T01:01:00Z"),  # noqa: SLF001
        ):
            result = protected.run(
                self.root,
                contract_path,
                "rc-dispatch",
                None,
                input_map_path,
            )

        summary = json.loads((output / protected.SUMMARY_FILE).read_text(encoding="utf-8"))
        self.assertEqual(0, result)
        self.assertEqual("rc-dispatch", summary["mode"])
        self.assertEqual("pass", summary["status"])
        self.assertTrue(summary["promotionReady"])
        self.assertEqual([], validate_schema(summary, protected.SUMMARY_SCHEMA))

    def test_evidence_authority_classes_reject_self_asserted_producers(self) -> None:
        generated = copy.deepcopy(self.contract)
        generated_row = next(
            row
            for row in generated["upstreamEvidence"]  # type: ignore[index]
            if row["id"] == "app-platform"
        )
        generated_row["producer"] = {
            "repository": "crypta-network/cryptad",
            "workflowPath": ".github/workflows/invented.yml",
            "workflowCommit": COMMIT,
            "runId": "1",
            "runAttempt": "1",
            "artifactName": "invented",
            "artifactDigest": "sha256:" + "1" * 64,
            "environment": "unprotected",
            "conclusion": "success",
        }
        generated_findings = protected._evidence_errors(  # noqa: SLF001
            self.root,
            generated,
            self.policy,
            protected._timestamp(generated["evaluationTime"]),  # type: ignore[arg-type] # noqa: SLF001
        )

        protected_contract = copy.deepcopy(self.contract)
        protected_row = next(
            row
            for row in protected_contract["upstreamEvidence"]  # type: ignore[index]
            if row["id"] == "stable-dependency-vulnerability"
        )
        protected_row["producer"]["environment"] = "unprotected"  # type: ignore[index]
        protected_findings = protected._evidence_errors(  # noqa: SLF001
            self.root,
            protected_contract,
            self.policy,
            protected._timestamp(protected_contract["evaluationTime"]),  # type: ignore[arg-type] # noqa: SLF001
        )

        self.assertTrue(
            any("must not claim a protected producer" in item for item in generated_findings),
            generated_findings,
        )
        self.assertTrue(
            any("producer environment differs" in item for item in protected_findings),
            protected_findings,
        )

    def test_protected_policy_binds_canonical_supply_chain_policy_identity(self) -> None:
        supply_chain_policy_path = (
            workspace_root()
            / "tools/release-certification/stable-1.0-supply-chain-policy.json"
        )
        supply_chain_policy = json.loads(
            supply_chain_policy_path.read_text(encoding="utf-8")
        )
        canonical_digest = supply_chain_policy["policyDigest"]

        self.assertEqual(
            canonical_digest,
            protected.supply_chain_semantic_digest(  # noqa: SLF001
                supply_chain_policy,
                "policyDigest",
            ),
        )
        self.assertEqual(
            canonical_digest,
            self.policy["requiredEvidenceContracts"]["stable-supply-chain"][
                "policyDigest"
            ],
        )
        self.assertNotEqual(canonical_digest, protected._digest(supply_chain_policy_path))  # noqa: SLF001

        wrong_policy = copy.deepcopy(self.policy)
        wrong_policy["requiredEvidenceContracts"]["stable-supply-chain"][  # type: ignore[index]
            "policyDigest"
        ] = protected._digest(supply_chain_policy_path)  # noqa: SLF001
        findings = protected._policy_errors(  # noqa: SLF001
            workspace_root(),
            self.contract,
            wrong_policy,
        )
        self.assertTrue(
            any("differs from the canonical policy" in finding for finding in findings),
            findings,
        )

    def test_protected_policy_pins_pr288_and_pr290_producer_authorities(self) -> None:
        evidence_contracts = self.policy["requiredEvidenceContracts"]

        self.assertEqual(
            {
                "workflowPath": ".github/workflows/stable-1.0-vulnerability-intake.yml",
                "environment": "stable-1.0-vulnerability-case",
            },
            {
                key: evidence_contracts["stable-vulnerability"][key]
                for key in ("workflowPath", "environment")
            },
        )
        self.assertEqual(
            {
                "workflowPath": ".github/workflows/stable-1.0-dependency-vulnerability-evaluation.yml",
                "environment": "stable-1.0-dependency-vulnerability-evaluation",
            },
            {
                key: evidence_contracts["stable-dependency-vulnerability"][key]
                for key in ("workflowPath", "environment")
            },
        )

    def test_authentic_supply_chain_summary_uses_protected_policy_identity(self) -> None:
        summary = supply_chain_promotion_summary()
        summary["releaseId"] = RELEASE_ID
        summary["buildVersion"] = 3
        summary["tag"] = "v3"
        summary["sourceCommit"] = COMMIT
        summary["sourceRef"] = f"commit:{COMMIT}"
        summary["policyDigest"] = self.policy["requiredEvidenceContracts"][
            "stable-supply-chain"
        ]["policyDigest"]
        summary["summaryDigest"] = protected.supply_chain_semantic_digest(
            summary,
            "summaryDigest",
        )
        release_identity = {
            "releaseId": RELEASE_ID,
            "buildVersion": 3,
            "tag": "v3",
            "sourceCommit": COMMIT,
            "sourceRef": f"commit:{COMMIT}",
            "policyDigest": self.policy["requiredEvidenceContracts"][
                "stable-supply-chain"
            ]["policyDigest"],
        }
        self.assertEqual([], promotion_summary_errors(summary, release_identity))
        self.assertEqual([], supply_chain.evaluated_promotion_summary_errors(summary))

        contract = copy.deepcopy(self.contract)
        row = next(
            item
            for item in contract["upstreamEvidence"]  # type: ignore[index]
            if item["id"] == "stable-supply-chain"
        )
        evidence_path = self.root / row["file"]["path"]
        write_json(evidence_path, summary)
        row["kind"] = "stable-1.0-supply-chain-promotion-summary"
        row["producer"]["workflowPath"] = ".github/workflows/stable-1.0-supply-chain.yml"
        row["producer"]["environment"] = "stable-1.0-supply-chain-evidence"
        row["producer"]["artifactName"] = (
            f"stable-1.0-supply-chain-{RELEASE_ID}-comparison"
        )
        row["file"]["sha256"] = protected._digest(evidence_path)  # noqa: SLF001

        findings = protected._evidence_errors(  # noqa: SLF001
            self.root,
            contract,
            self.policy,
        )

        self.assertFalse(
            any("upstream evidence stable-supply-chain" in finding for finding in findings),
            findings,
        )

    def test_supply_chain_promotion_requires_exact_evidence_and_complete_bindings(self) -> None:
        summary = supply_chain_promotion_summary()
        wrong_evidence = copy.deepcopy(summary)
        wrong_evidence["evidence"] = []
        self.assertTrue(supply_chain.evaluated_promotion_summary_errors(wrong_evidence))
        for field in supply_chain.EVALUATED_PROMOTION_BINDING_FIELDS:
            with self.subTest(field=field):
                wrong_binding = copy.deepcopy(summary)
                wrong_binding[field] = None
                self.assertTrue(
                    supply_chain.evaluated_promotion_summary_errors(wrong_binding)
                )
        wrong_mode = copy.deepcopy(summary)
        wrong_mode["mode"] = "verify-publication"
        self.assertTrue(supply_chain.evaluated_promotion_summary_errors(wrong_mode))

    def test_valid_first_freeze_preflight_passes(self) -> None:
        self.assertEqual([], self._preflight())

    def test_preflight_binds_evaluation_time_to_current_runner_utc(self) -> None:
        declared = protected._timestamp(self.contract["evaluationTime"])  # noqa: SLF001
        maximum = self.policy["maximumPreflightClockSkewSeconds"]

        self.assertEqual(
            [],
            protected._evaluation_clock_errors(  # noqa: SLF001
                self.contract,
                self.policy,
                declared + timedelta(seconds=maximum),
            ),
        )
        for observed in (
            declared + timedelta(seconds=maximum + 1),
            declared - timedelta(seconds=maximum + 1),
        ):
            with self.subTest(observed=observed):
                self.assertTrue(
                    any(
                        "current runner UTC" in finding
                        for finding in protected._evaluation_clock_errors(  # noqa: SLF001
                            self.contract,
                            self.policy,
                            observed,
                        )
                    )
                )

    def test_rc_dispatch_preserves_reviewed_preflight_across_approval_delay(self) -> None:
        delayed = protected._timestamp("2026-08-16T03:00:00Z")  # noqa: SLF001
        input_map = _rc_input_map(self.root, self.contract)

        delayed_findings = protected._rc_dispatch_errors(  # noqa: SLF001
            self.root,
            self.contract,
            self.policy,
            input_map,
            delayed,
        )

        self.assertEqual([], delayed_findings)
        for offset, expected_finding in ((300, False), (301, True)):
            with self.subTest(future_offset=offset):
                future = copy.deepcopy(self.contract)
                future["evaluationTime"] = (
                    delayed + timedelta(seconds=offset)
                ).isoformat().replace("+00:00", "Z")
                future_map = _rc_input_map(self.root, future)
                findings = protected._rc_dispatch_errors(  # noqa: SLF001
                    self.root,
                    future,
                    self.policy,
                    future_map,
                    delayed,
                )
                self.assertEqual(
                    expected_finding,
                    any("future-dated beyond policy skew" in item for item in findings),
                    findings,
                )
        expired = copy.deepcopy(self.contract)
        expired_row = next(
            row
            for row in expired["upstreamEvidence"]  # type: ignore[index]
            if row["id"] == "stable-supply-chain"
        )
        expired_row["validUntil"] = "2026-08-16T03:00:00Z"
        expired_map = _rc_input_map(self.root, expired)
        expired_findings = protected._rc_dispatch_errors(  # noqa: SLF001
            self.root,
            expired,
            self.policy,
            expired_map,
            delayed,
        )
        self.assertTrue(
            any("stable-supply-chain evidence is stale" in item for item in expired_findings),
            expired_findings,
        )

    def test_source_auth_accepts_only_exact_local_or_origin_release_refs(self) -> None:
        repository = self.root / "detached-actions-checkout"
        repository.mkdir()

        def git(*args: str, input_text: str | None = None) -> str:
            completed = subprocess.run(
                ["git", *args],
                cwd=repository,
                check=True,
                capture_output=True,
                text=True,
                input=input_text,
                timeout=30,
            )
            return completed.stdout.strip()

        git("init", "--quiet")
        git("config", "user.name", "Cryptad Test")
        git("config", "user.email", "cryptad-test@example.invalid")
        (repository / "build.gradle.kts").write_text('version = "3"\n', encoding="utf-8")
        git("add", "build.gradle.kts")
        git("commit", "--quiet", "-m", "test candidate")
        candidate = git("rev-parse", "HEAD")
        tree = git("rev-parse", "HEAD^{tree}")
        other = git(
            "commit-tree",
            tree,
            "-p",
            candidate,
            input_text="different release ref\n",
        )
        contract = copy.deepcopy(self.contract)
        contract["repository"]["candidateCommit"] = candidate  # type: ignore[index]
        git("checkout", "--quiet", "--detach", candidate)

        local_ref = "refs/heads/release/3"
        remote_ref = "refs/remotes/origin/release/3"
        git("update-ref", remote_ref, candidate)
        self.assertEqual([], self.source_auth(repository, contract))

        git("update-ref", "-d", remote_ref)
        git("update-ref", local_ref, candidate)
        self.assertEqual([], self.source_auth(repository, contract))

        git("update-ref", "-d", local_ref)
        unavailable = self.source_auth(repository, contract)
        self.assertTrue(any("source ref is unavailable" in item for item in unavailable))

        for local_commit, remote_commit in (
            (candidate, other),
            (other, candidate),
        ):
            with self.subTest(local=local_commit, remote=remote_commit):
                git("update-ref", local_ref, local_commit)
                git("update-ref", remote_ref, remote_commit)
                findings = self.source_auth(repository, contract)
                self.assertTrue(
                    any("does not resolve to the exact candidate" in item for item in findings),
                    findings,
                )

    def test_schema_invalid_contract_writes_a_failed_summary_without_policy_inspection(
        self,
    ) -> None:
        malformed = copy.deepcopy(self.contract)
        del malformed["repository"]["candidateCommit"]  # type: ignore[index]
        contract_path = self.root / "malformed-execution.json"
        output = self.root / "malformed-output"
        write_json(contract_path, malformed)

        with mock.patch.object(
            protected,
            "_policy_errors",
            side_effect=AssertionError("policy inspection must not run"),
        ):
            result = protected.run(self.root, contract_path, "preflight", output)

        summary = json.loads(
            (output / protected.SUMMARY_FILE).read_text(encoding="utf-8")
        )
        self.assertEqual(1, result)
        self.assertEqual("fail", summary["status"])
        self.assertIsNone(summary["candidateCommit"])
        self.assertIsNone(summary["dispatchPackage"])
        self.assertEqual([], validate_schema(summary, protected.SUMMARY_SCHEMA))
        self.assertTrue(any("candidateCommit" in item for item in summary["findings"]))

    def test_preflight_writes_schema_valid_deterministic_review_artifacts(self) -> None:
        contract_path = self.root / "execution.json"
        output = self.root / "output"
        write_json(contract_path, self.contract)
        with mock.patch.object(protected, "_source_errors", return_value=[]), mock.patch.object(  # noqa: SLF001
            protected, "_toolchain_errors", return_value=[]
        ), mock.patch.object(protected, "_policy_errors", return_value=[]), mock.patch.object(
            protected, "_evidence_errors", return_value=[]
        ), mock.patch.object(
            protected,
            "_utc_now",
            return_value=protected._timestamp(self.contract["evaluationTime"]),  # noqa: SLF001
        ):
            result = protected.run(self.root, contract_path, "preflight", output)

        summary = json.loads((output / protected.SUMMARY_FILE).read_text(encoding="utf-8"))
        report = (output / protected.REPORT_FILE).read_text(encoding="utf-8")
        redaction = json.loads((output / protected.REDACTION_FILE).read_text(encoding="utf-8"))

        self.assertEqual(0, result, summary["findings"])
        self.assertEqual(
            [],
            validate_schema(
                summary, "stable-1.0-protected-release-execution-summary-v1.schema.json"
            ),
        )
        self.assertEqual("pass", redaction["status"])
        self.assertIn(summary["contractDigest"], report)

    def test_default_closeout_preserves_the_bound_preflight_receipt(self) -> None:
        contract_path = self.root / "execution.json"
        write_json(contract_path, self.contract)
        default_root = (
            self.root
            / "build/release-certification"
            / str(self.contract["executionId"])
            / "stable-protected-release"
        )
        preflight_path = default_root / protected.SUMMARY_FILE
        closeout_path = default_root / "closeout" / protected.SUMMARY_FILE
        run_patches = (
            mock.patch.object(protected, "_source_errors", return_value=[]),
            mock.patch.object(protected, "_toolchain_errors", return_value=[]),
            mock.patch.object(protected, "_policy_errors", return_value=[]),
            mock.patch.object(protected, "_evidence_errors", return_value=[]),
            mock.patch.object(
                protected,
                "_utc_now",
                return_value=protected._timestamp(self.contract["evaluationTime"]),  # noqa: SLF001
            ),
        )
        with run_patches[0], run_patches[1], run_patches[2], run_patches[3], run_patches[4]:
            self.assertEqual(0, protected.run(self.root, contract_path, "preflight", None))
        preflight_digest = protected._digest(preflight_path)  # noqa: SLF001
        self.contract["operationEvidence"]["preflight"] = {  # type: ignore[index]
            **_binding(self.root, preflight_path.relative_to(self.root)),
            "schema": protected.SUMMARY_SCHEMA,
        }
        self.contract["lifecycleState"] = "preflight-passed"
        self.contract["evidenceClassification"]["offlineVerification"] = "passed"  # type: ignore[index]
        write_json(contract_path, self.contract)

        for invocation in (1, 2):
            with self.subTest(invocation=invocation), mock.patch.object(
                protected, "_policy_errors", return_value=[]
            ):
                self.assertEqual(0, protected.run(self.root, contract_path, "closeout", None))
            closeout = json.loads(closeout_path.read_text(encoding="utf-8"))
            self.assertEqual("closeout", closeout["mode"])
            self.assertEqual(
                "passed", closeout["evidenceClassification"]["offlineVerification"]
            )
            self.assertEqual(preflight_digest, protected._digest(preflight_path))  # noqa: SLF001
            self.assertEqual(
                "preflight",
                json.loads(preflight_path.read_text(encoding="utf-8"))["mode"],
            )

        with mock.patch.object(protected, "_policy_errors", return_value=[]):
            with self.assertRaisesRegex(ValueError, "overwrite immutable input evidence"):
                protected.run(self.root, contract_path, "closeout", default_root)
        self.assertEqual(preflight_digest, protected._digest(preflight_path))  # noqa: SLF001

    def test_output_targets_cannot_replace_contract_or_rc_input_map(self) -> None:
        contract_dir = self.root / "contract-collision"
        contract_dir.mkdir()
        contract_path = contract_dir / protected.SUMMARY_FILE
        write_json(contract_path, self.contract)
        contract_bytes = contract_path.read_bytes()

        with mock.patch.object(protected, "_source_errors", return_value=[]), mock.patch.object(
            protected, "_toolchain_errors", return_value=[]
        ), mock.patch.object(protected, "_policy_errors", return_value=[]), mock.patch.object(
            protected, "_evidence_errors", return_value=[]
        ):
            with self.assertRaisesRegex(ValueError, "overwrite immutable input evidence"):
                protected.run(self.root, contract_path, "preflight", contract_dir)
        self.assertEqual(contract_bytes, contract_path.read_bytes())

        rc_contract_path = self.root / "rc-contract.json"
        input_dir = self.root / "input-map-collision"
        input_dir.mkdir()
        input_map_path = input_dir / protected.SUMMARY_FILE
        write_json(rc_contract_path, self.contract)
        write_json(input_map_path, _rc_input_map(self.root, self.contract))
        input_map_bytes = input_map_path.read_bytes()
        with mock.patch.object(protected, "_source_errors", return_value=[]), mock.patch.object(
            protected, "_policy_errors", return_value=[]
        ), mock.patch.object(protected, "_rc_dispatch_errors", return_value=[]):
            with self.assertRaisesRegex(ValueError, "overwrite immutable input evidence"):
                protected.run(
                    self.root,
                    rc_contract_path,
                    "rc-dispatch",
                    input_dir,
                    input_map_path,
                )
        self.assertEqual(input_map_bytes, input_map_path.read_bytes())

    def test_run_rejects_lexical_output_and_contract_symlinks(self) -> None:
        contract_path = self.root / "execution.json"
        write_json(contract_path, self.contract)
        real_output = self.root / "real-output"
        real_output.mkdir()
        output_alias = self.root / "output-alias"
        output_alias.symlink_to(real_output, target_is_directory=True)

        with self.assertRaisesRegex(ValueError, "symbolic-link component"):
            protected.run(
                self.root,
                contract_path,
                "preflight",
                output_alias / "nested",
            )

        contract_alias = self.root / "execution-alias.json"
        contract_alias.symlink_to(contract_path)
        with self.assertRaisesRegex(ValueError, "symbolic link"):
            protected.run(
                self.root,
                contract_alias,
                "preflight",
                self.root / "unused-output",
            )

    def test_relative_output_is_anchored_to_the_selected_workspace(self) -> None:
        contract_path = self.root / "execution.json"
        write_json(contract_path, self.contract)
        with mock.patch.object(protected, "_source_errors", return_value=[]), mock.patch.object(  # noqa: SLF001
            protected, "_toolchain_errors", return_value=[]
        ), mock.patch.object(protected, "_policy_errors", return_value=[]), mock.patch.object(
            protected, "_evidence_errors", return_value=[]
        ), mock.patch.object(
            protected,
            "_utc_now",
            return_value=protected._timestamp(self.contract["evaluationTime"]),  # noqa: SLF001
        ):
            result = protected.run(
                self.root,
                contract_path,
                "preflight",
                Path("relative-output"),
            )

        self.assertEqual(0, result)
        self.assertTrue((self.root / "relative-output" / protected.SUMMARY_FILE).is_file())

    def test_valid_refreeze_requires_exact_predecessor_binding(self) -> None:
        predecessor = self.root / "previous-freeze.json"
        write_json(
            predecessor,
            {"releaseId": RELEASE_ID, "buildVersion": "3", "sourceCommit": "b" * 40},
        )
        self.contract["release"]["freezeMode"] = "refreeze"  # type: ignore[index]
        self.contract["release"]["previousRcFreeze"] = _binding(  # type: ignore[index]
            self.root, Path(predecessor.name)
        )

        self.assertEqual([], self._preflight())

    def test_first_freeze_rejects_predecessor_and_refreeze_requires_it(self) -> None:
        predecessor = self.root / "previous-freeze.json"
        write_json(predecessor, {"releaseId": RELEASE_ID, "buildVersion": "3"})
        first = copy.deepcopy(self.contract)
        first["release"]["previousRcFreeze"] = _binding(  # type: ignore[index]
            self.root, Path(predecessor.name)
        )
        refreeze = copy.deepcopy(self.contract)
        refreeze["release"]["freezeMode"] = "refreeze"  # type: ignore[index]

        self.assertIn("first-freeze cannot supply a previous RC freeze", self._preflight(first))
        self.assertIn("refreeze requires the exact previous RC freeze", self._preflight(refreeze))

    def test_wrong_commit_build_and_release_binding_fail(self) -> None:
        wrong = copy.deepcopy(self.contract)
        wrong["upstreamEvidence"][0]["candidateCommit"] = "b" * 40  # type: ignore[index]
        wrong["upstreamEvidence"][1]["buildVersion"] = "4"  # type: ignore[index]
        wrong["upstreamEvidence"][2]["releaseId"] = "other-release"  # type: ignore[index]

        findings = self._preflight(wrong, check_evidence=True)

        self.assertTrue(any("wrong candidate commit" in item for item in findings))
        self.assertTrue(any("wrong release or build" in item for item in findings))

    def test_placeholder_non_https_and_missing_catalog_targets_fail(self) -> None:
        placeholder = copy.deepcopy(self.contract)
        placeholder["publicTargets"]["artifactBaseUri"] = "https://example.invalid/stable/"  # type: ignore[index]
        non_https = copy.deepcopy(self.contract)
        non_https["publicTargets"]["catalogPrimaryUri"] = "http://catalog.example/first-party.properties"  # type: ignore[index]
        missing_mirror = copy.deepcopy(self.contract)
        missing_mirror["publicTargets"]["catalogMirrorUris"] = []  # type: ignore[index]

        placeholder_findings = self._preflight(placeholder)
        non_https_findings = self._preflight(non_https)
        mirror_findings = self._preflight(missing_mirror)

        self.assertTrue(any("placeholder" in item for item in placeholder_findings))
        self.assertTrue(any("public HTTPS" in item for item in non_https_findings))
        self.assertTrue(any("fewer items" in item for item in mirror_findings))

    def test_public_targets_reject_non_global_literals_and_mixed_dns(self) -> None:
        literals = (
            "https://10.0.0.1/stable/",
            "https://169.254.169.254/stable/",
            "https://127.0.0.1/stable/",
            "https://[fc00::1]/stable/",
            "https://192.0.2.1/stable/",
        )
        for uri in literals:
            with self.subTest(uri=uri):
                self.assertIsNotNone(protected._public_https(uri, base=True))  # noqa: SLF001

        mixed_addresses = [
            (2, 1, 6, "", ("8.8.8.8", 443)),
            (2, 1, 6, "", ("10.0.0.1", 443)),
        ]
        global_addresses = [
            (2, 1, 6, "", ("8.8.8.8", 443)),
            (2, 1, 6, "", ("1.1.1.1", 443)),
        ]
        with mock.patch(
            "cryptad_certification.engines.stable_1_0_ga_core.socket.getaddrinfo",
            return_value=mixed_addresses,
        ):
            self.assertIsNotNone(
                protected._public_https(  # noqa: SLF001
                    "https://downloads.crypta.network/stable/", base=True
                )
            )
        with mock.patch(
            "cryptad_certification.engines.stable_1_0_ga_core.socket.getaddrinfo",
            return_value=global_addresses,
        ):
            self.assertIsNone(
                protected._public_https(  # noqa: SLF001
                    "https://downloads.crypta.network/stable/", base=True
                )
            )

    def test_fixture_simulated_non_release_and_test_signing_fail(self) -> None:
        mutations = (
            ("fixture", True, "fixture evidence"),
            ("simulatedOnly", True, "simulated-only evidence"),
            ("nonRelease", True, "non-release evidence"),
            ("testSigning", True, "test signing"),
        )
        for field, value, expected in mutations:
            with self.subTest(field=field):
                wrong = copy.deepcopy(self.contract)
                evidence_path = self.root / wrong["upstreamEvidence"][0]["file"]["path"]  # type: ignore[index]
                document = json.loads(evidence_path.read_text(encoding="utf-8"))
                document[field] = value
                write_json(evidence_path, document)
                wrong["upstreamEvidence"][0]["file"]["sha256"] = protected._digest(evidence_path)  # type: ignore[index] # noqa: SLF001
                self.assertTrue(
                    any(expected in item for item in self._preflight(wrong, check_evidence=True))
                )
                write_json(evidence_path, {
                    "kind": "app-platform-summary",
                    "releaseId": RELEASE_ID,
                    "buildVersion": "3",
                    "candidateSourceCommit": COMMIT,
                    "status": "pass",
                    "promotionReady": True,
                    "nonRelease": False,
                    "fixture": False,
                    "simulatedOnly": False,
                    "testSigning": False,
                    "redaction": {"status": "pass", "findingCount": 0, "findings": []},
                })

    def test_stale_evidence_fails(self) -> None:
        wrong = copy.deepcopy(self.contract)
        wrong["upstreamEvidence"][0]["validUntil"] = wrong["evaluationTime"]  # type: ignore[index]

        self.assertTrue(
            any("stale" in item for item in self._preflight(wrong, check_evidence=True))
        )

    def test_missing_required_stable_and_network_evidence_fails(self) -> None:
        for evidence_id in (
            "stable-supply-chain",
            "stable-dependency-vulnerability",
            "live-network",
            "network-scale",
            "multi-node",
            "sandbox-provider",
            "security-drills",
            "third-party-intake",
            "stable-readiness",
        ):
            with self.subTest(evidence_id=evidence_id):
                wrong = copy.deepcopy(self.contract)
                wrong["upstreamEvidence"] = [  # type: ignore[index]
                    row
                    for row in wrong["upstreamEvidence"]  # type: ignore[index]
                    if row["id"] != evidence_id
                ]
                self.assertTrue(
                    any(
                        "exact required" in item
                        for item in self._preflight(wrong, check_evidence=True)
                    )
                )

    def test_generic_or_contract_selected_upstream_evidence_cannot_pass(self) -> None:
        findings = self._preflight(check_evidence=True)

        self.assertTrue(any("omits its canonical producer payload" in item for item in findings))

        wrong_workflow = copy.deepcopy(self.contract)
        supply_chain = next(
            row
            for row in wrong_workflow["upstreamEvidence"]  # type: ignore[index]
            if row["id"] == "stable-supply-chain"
        )
        supply_chain["producer"]["workflowPath"] = ".github/workflows/unrelated.yml"

        workflow_findings = self._preflight(wrong_workflow, check_evidence=True)

        self.assertTrue(any("producer workflow differs" in item for item in workflow_findings))

    def test_pr288_and_pr290_require_canonical_protected_producers(self) -> None:
        mutations = (
            ("stable-vulnerability", "workflowPath", ".github/workflows/unrelated.yml", "workflow differs"),
            ("stable-vulnerability", "environment", "unprotected", "environment differs"),
            ("stable-vulnerability", "artifactName", "unrelated-artifact", "artifact name is not canonical"),
            ("stable-dependency-vulnerability", "workflowPath", ".github/workflows/unrelated.yml", "workflow differs"),
            ("stable-dependency-vulnerability", "environment", "unprotected", "environment differs"),
            ("stable-dependency-vulnerability", "artifactName", "unrelated-artifact", "artifact name is not canonical"),
        )
        for evidence_id, field, replacement, expected in mutations:
            with self.subTest(evidence_id=evidence_id, field=field):
                contract = copy.deepcopy(self.contract)
                row = next(
                    item
                    for item in contract["upstreamEvidence"]  # type: ignore[index]
                    if item["id"] == evidence_id
                )
                row["producer"][field] = replacement

                findings = self._preflight(contract, check_evidence=True)

                self.assertTrue(
                    any(
                        f"upstream evidence {evidence_id}" in finding
                        and expected in finding
                        for finding in findings
                    ),
                    findings,
                )

    def test_rc_preflight_rejects_final_publication_pr290_evidence(self) -> None:
        contract = copy.deepcopy(self.contract)
        row = next(
            item
            for item in contract["upstreamEvidence"]  # type: ignore[index]
            if item["id"] == "stable-dependency-vulnerability"
        )
        path = self.root / row["file"]["path"]
        summary = dependency_promotion_summary()
        summary["releaseId"] = RELEASE_ID
        summary["buildVersion"] = 3
        summary["candidateSourceCommit"] = COMMIT
        summary["validUntil"] = "2026-08-17T00:00:00Z"
        summary["summaryDigest"] = dependency_semantic_digest(
            summary,
            "summaryDigest",
        )
        write_json(path, summary)
        row["kind"] = "stable-1.0-dependency-vulnerability-promotion-summary"
        row["producer"]["workflowPath"] = (
            ".github/workflows/stable-1.0-dependency-vulnerability-evaluation.yml"
        )
        row["validUntil"] = summary["validUntil"]
        row["file"]["sha256"] = protected._digest(path)  # noqa: SLF001

        findings = self._preflight(contract, check_evidence=True)

        self.assertTrue(
            any("required authenticated evidence phase" in item for item in findings),
            findings,
        )

    def test_rc_preflight_binds_pr290_internal_and_outer_validity(self) -> None:
        contract = copy.deepcopy(self.contract)
        row = next(
            item
            for item in contract["upstreamEvidence"]  # type: ignore[index]
            if item["id"] == "stable-dependency-vulnerability"
        )
        path = self.root / row["file"]["path"]
        summary = dependency_promotion_summary()
        summary["releaseId"] = RELEASE_ID
        summary["buildVersion"] = 3
        summary["candidateSourceCommit"] = COMMIT
        summary["mode"] = "evaluate-promotion"
        summary["publicationPlanDigest"] = None
        summary["publicationReceiptDigest"] = None
        summary["publicObservationDigest"] = None
        summary["evidence"] = [
            item
            for item in summary["evidence"]
            if item["evidenceId"]
            != "stable-dependency-vulnerability.publication"
        ]
        summary["validUntil"] = "2026-08-17T00:00:00Z"
        summary["summaryDigest"] = dependency_semantic_digest(
            summary,
            "summaryDigest",
        )
        write_json(path, summary)
        row["kind"] = "stable-1.0-dependency-vulnerability-promotion-summary"
        row["producer"]["workflowPath"] = (
            ".github/workflows/stable-1.0-dependency-vulnerability-evaluation.yml"
        )
        row["validUntil"] = "2026-08-18T00:00:00Z"
        row["file"]["sha256"] = protected._digest(path)  # noqa: SLF001

        findings = self._preflight(contract, check_evidence=True)

        self.assertTrue(
            any("validity differs" in item for item in findings),
            findings,
        )

    def test_secret_private_uri_and_absolute_path_fail_without_echoing_values(self) -> None:
        wrong = copy.deepcopy(self.contract)
        secret = "Authorization: Bearer abcdefghijklmnop"
        wrong["blockedReason"] = secret

        findings = self._preflight(wrong)

        self.assertTrue(any("secret" in item for item in findings))
        self.assertNotIn(secret, "\n".join(findings))

    def test_malformed_archives_write_deterministic_failed_preflight_artifacts(self) -> None:
        encrypted = self.root / "encrypted.zip"
        with zipfile.ZipFile(encrypted, "w", zipfile.ZIP_STORED) as archive:
            archive.writestr("payload.txt", b"protected")
        encrypted_bytes = bytearray(encrypted.read_bytes())
        for signature, flag_offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
            header = encrypted_bytes.find(signature)
            self.assertGreaterEqual(header, 0)
            flags = int.from_bytes(
                encrypted_bytes[header + flag_offset : header + flag_offset + 2],
                "little",
            )
            encrypted_bytes[header + flag_offset : header + flag_offset + 2] = (
                flags | 1
            ).to_bytes(2, "little")
        encrypted.write_bytes(encrypted_bytes)
        malformed = {
            "encrypted": encrypted,
            "corrupt-zip": self.root / "corrupt.zip",
            "corrupt-tar": self.root / "corrupt.tar",
        }
        malformed["corrupt-zip"].write_bytes(b"PK\x03\x04truncated")
        malformed["corrupt-tar"].write_bytes(b"not a tar archive")

        for name, path in malformed.items():
            with self.subTest(name=name):
                contract = copy.deepcopy(self.contract)
                contract["archives"] = [  # type: ignore[index]
                    {
                        "id": name,
                        "path": path.name,
                        "sha256": protected._digest(path),  # noqa: SLF001
                        "maximumEntries": 20,
                        "maximumExpandedBytes": 1024 * 1024,
                    }
                ]
                contract_path = self.root / f"execution-{name}.json"
                output = self.root / f"output-{name}"
                write_json(contract_path, contract)
                with mock.patch.object(
                    protected,
                    "_source_errors",
                    return_value=[],
                ), mock.patch.object(
                    protected,
                    "_toolchain_errors",
                    return_value=[],
                ), mock.patch.object(
                    protected,
                    "_policy_errors",
                    return_value=[],
                ), mock.patch.object(
                    protected,
                    "_evidence_errors",
                    return_value=[],
                ), mock.patch.object(
                    protected,
                    "_utc_now",
                    return_value=protected._timestamp(contract["evaluationTime"]),  # noqa: SLF001
                ):
                    result = protected.run(
                        self.root,
                        contract_path,
                        "preflight",
                        output,
                    )

                summary = json.loads(
                    (output / protected.SUMMARY_FILE).read_text(encoding="utf-8")
                )
                report = (output / protected.REPORT_FILE).read_text(encoding="utf-8")
                redaction = json.loads(
                    (output / protected.REDACTION_FILE).read_text(encoding="utf-8")
                )
                self.assertEqual(1, result)
                self.assertEqual("fail", summary["status"])
                self.assertEqual("blocked", summary["lifecycleState"])
                self.assertFalse(summary["promotionReady"])
                self.assertTrue(
                    any("unsafe or malformed" in item for item in summary["findings"]),
                    summary["findings"],
                )
                self.assertEqual("pass", redaction["status"])
                self.assertNotIn("password required", json.dumps(summary) + report)

    def test_publish_requires_selected_rc_authorization_and_evidence_approval(self) -> None:
        wrong = copy.deepcopy(self.contract)
        wrong["ga"]["publicationIntent"] = "publish"  # type: ignore[index]

        findings = self._preflight(wrong)

        self.assertTrue(any("without exact selected-RC" in item for item in findings))

    def test_publish_preflight_accepts_exact_rc_evidence_and_authorization_binding(self) -> None:
        contract = copy.deepcopy(self.contract)
        _configure_publish(self.root, contract)

        self.assertEqual([], self._preflight(contract))

    def test_publish_preflight_rejects_authorization_for_different_targets(self) -> None:
        contract = copy.deepcopy(self.contract)
        _configure_publish(self.root, contract)
        contract["publicTargets"]["catalogPrimaryUri"] = (  # type: ignore[index]
            "https://1.1.1.1/catalog/substituted/first-party-catalog.properties"
        )

        findings = self._preflight(contract)

        self.assertTrue(any("target digest differs" in item for item in findings))
        self.assertTrue(any("binds different public targets" in item for item in findings))

    def test_publish_rejects_substituted_or_stale_authorization(self) -> None:
        wrong = copy.deepcopy(self.contract)
        authorization_path = self.root / "authorization.json"
        write_json(
            authorization_path,
            {
                "status": "authorized",
                "candidateCommit": COMMIT,
                "identityDigest": "sha256:" + "1" * 64,
            },
        )
        wrong["ga"] = {  # type: ignore[index]
            "publicationIntent": "publish",
            "publicObservationRequired": True,
            "selectedRc": {
                "runId": "10",
                "runAttempt": "1",
                "artifactName": "stable-rc",
                "artifactDigest": DIGEST_ZERO,
                "freezeDigest": DIGEST_ZERO,
                "productDigest": DIGEST_ZERO,
                "archiveDigest": DIGEST_ZERO,
                "catalogDigest": DIGEST_ZERO,
                "catalogRevision": 0,
            },
            "validationIdentityDigest": DIGEST_ZERO,
            "authorization": {
                "file": _binding(self.root, Path("authorization.json")),
                "authorizationId": "stable-ga-3-authorization",
                "authorizationFileDigest": _binding(
                    self.root, Path("authorization.json")
                )["sha256"],
                "identityDigest": DIGEST_ZERO,
                "authorizedTargetsDigest": DIGEST_ZERO,
                "validUntil": "2026-08-16T00:00:00Z",
                "role": "stable-release-manager",
                "approverId": "release-manager-1",
            },
        }
        wrong["workflowCoordinates"]["gaEvidenceApproval"] = _coordinate(  # type: ignore[index]
            ".github/workflows/stable-1.0-ga-promotion.yml",
            "stable-1-0-ga-evidence",
        )

        findings = self._preflight(wrong)

        self.assertTrue(any("does not bind" in item for item in findings))
        self.assertTrue(any("stale" in item for item in findings))

    def test_closeout_does_not_infer_remote_success_from_missing_receipts(self) -> None:
        with mock.patch.object(protected, "_policy_errors", return_value=[]):
            findings, statuses = protected._closeout(  # noqa: SLF001
                self.root, self.contract, self.policy
            )

        self.assertEqual([], findings)
        self.assertEqual("not-performed", statuses["protectedRcOperation"])
        self.assertEqual("not-performed", statuses["gaPublication"])
        self.assertEqual("not-performed", statuses["publicObservation"])
        self.assertEqual("pending", statuses["independentReproducibility"])
        self.assertEqual("pending", statuses["catalogAuthority"])

    def test_closeout_rejects_verifier_checkout_that_differs_from_candidate(self) -> None:
        source_finding = "candidate commit differs from checked-out HEAD"
        with mock.patch.object(
            protected, "_source_errors", return_value=[source_finding]
        ) as source_errors, mock.patch.object(
            protected, "_policy_errors", return_value=[]
        ):
            findings, statuses = protected._closeout(  # noqa: SLF001
                self.root,
                self.contract,
                self.policy,
            )

        source_errors.assert_called_once_with(self.root, self.contract)
        self.assertIn(source_finding, findings)
        self.assertEqual("missing", statuses["repositoryImplementation"])
        self.assertEqual("pending", statuses["offlineVerification"])
        for status_name in (
            "protectedRcOperation",
            "gaValidation",
            "gaPublication",
            "publicObservation",
        ):
            with self.subTest(status_name=status_name):
                self.assertEqual("not-performed", statuses[status_name])

    def test_closeout_rejects_legacy_same_provider_supply_chain_evidence(self) -> None:
        contract = copy.deepcopy(self.contract)
        legacy_path = self.root / "legacy-same-provider-reproducibility.json"
        write_json(
            legacy_path,
            {
                "schemaVersion": 1,
                "kind": "stable-1.0-reproducibility-result",
                "status": "pass",
                "resultDigest": DIGEST_ZERO,
            },
        )
        contract["operationEvidence"]["independentReproducibility"] = {  # type: ignore[index]
            **_binding(self.root, Path(legacy_path.name)),
            "schema": protected.REPRODUCIBILITY_SCHEMA,
        }

        with mock.patch.object(protected, "_policy_errors", return_value=[]):
            findings, statuses = protected._closeout(  # noqa: SLF001
                self.root,
                contract,
                self.policy,
            )

        self.assertEqual("pending", statuses["independentReproducibility"])
        self.assertTrue(
            any("summary schema differs" in item for item in findings), findings
        )

    def test_closeout_rejects_self_asserted_publication_complete_object(self) -> None:
        contract = copy.deepcopy(self.contract)
        _configure_publish(self.root, contract)
        coordinate = _coordinate(
            ".github/workflows/stable-1.0-ga-promotion.yml",
            "stable-1-0-ga",
            run_id="30",
            artifact_name=(
                f"stable-1-0-ga-publication-receipt-{RELEASE_ID}-3-30-1"
            ),
        )
        receipt_path = self.root / "self-asserted-publication.json"
        write_json(receipt_path, {"publicationState": "publication-complete"})
        contract["workflowCoordinates"]["gaPublication"] = coordinate  # type: ignore[index]
        contract["operationEvidence"]["gaPublication"] = _binding(  # type: ignore[index]
            self.root, Path(receipt_path.name)
        )

        with mock.patch.object(protected, "_policy_errors", return_value=[]):
            findings, statuses = protected._closeout(  # noqa: SLF001
                self.root, contract, self.policy
            )

        self.assertTrue(any("canonical Stable GA schema" in item for item in findings))
        self.assertTrue(any("omits required field" in item for item in findings))
        self.assertNotEqual("completed", statuses["gaPublication"])

    def test_closeout_accepts_only_exact_canonical_ga_publication_receipt(self) -> None:
        contract = copy.deepcopy(self.contract)
        _configure_publication_receipt(self.root, contract)

        with mock.patch.object(protected, "_policy_errors", return_value=[]):
            findings, statuses = protected._closeout(  # noqa: SLF001
                self.root, contract, self.policy
            )

        self.assertEqual([], findings)
        self.assertEqual("completed", statuses["gaPublication"])
        self.assertEqual("not-performed", statuses["publicObservation"])

    def test_publication_requires_a_separate_evidence_approval_dispatch(self) -> None:
        contract = copy.deepcopy(self.contract)
        _configure_publication_receipt(self.root, contract)
        contract["workflowCoordinates"]["gaPublication"]["runId"] = (  # type: ignore[index]
            contract["workflowCoordinates"]["gaEvidenceApproval"]["runId"]  # type: ignore[index]
        )

        with mock.patch.object(protected, "_policy_errors", return_value=[]):
            findings, statuses = protected._closeout(  # noqa: SLF001
                self.root, contract, self.policy
            )

        self.assertTrue(
            any("separate workflow dispatches" in finding for finding in findings),
            findings,
        )
        self.assertNotEqual("completed", statuses["gaPublication"])

    def test_publication_requires_authenticated_rc_and_ga_validation_chain(self) -> None:
        contract = copy.deepcopy(self.contract)
        _configure_publication_receipt(self.root, contract)
        contract["operationEvidence"]["rcFreeze"] = None  # type: ignore[index]
        contract["operationEvidence"]["gaValidation"] = None  # type: ignore[index]
        contract["workflowCoordinates"]["rc"] = None  # type: ignore[index]
        contract["workflowCoordinates"]["gaValidation"] = None  # type: ignore[index]

        with mock.patch.object(protected, "_policy_errors", return_value=[]):
            findings, statuses = protected._closeout(  # noqa: SLF001
                self.root,
                contract,
                self.policy,
            )

        self.assertTrue(any("authenticated RC operation" in item for item in findings))
        self.assertTrue(any("authenticated GA validation" in item for item in findings))
        self.assertNotEqual("completed", statuses["gaPublication"])

    def test_publication_binds_ga_promotion_identity_and_validation_selection(self) -> None:
        for mutation in (
            "promotion-identity",
            "promotion-plan-identity",
            "coordinated-promotion-identity",
            "validation-selection",
        ):
            with self.subTest(mutation=mutation):
                contract = copy.deepcopy(self.contract)
                receipt, receipt_path = _configure_publication_receipt(
                    self.root,
                    contract,
                )
                if mutation == "promotion-identity":
                    receipt["gaPromotionSummaryDigest"] = DIGEST_ZERO
                    write_json(receipt_path, receipt)
                    contract["operationEvidence"]["gaPublication"]["sha256"] = (  # type: ignore[index]
                        protected._digest(receipt_path)  # noqa: SLF001
                    )
                elif mutation == "promotion-plan-identity":
                    plan_binding = contract["operationEvidence"]["gaPromotionPlan"]  # type: ignore[index]
                    plan_path = self.root / plan_binding["path"]
                    plan = json.loads(plan_path.read_text(encoding="utf-8"))
                    plan["promotionIdentityDigest"] = DIGEST_ZERO
                    write_json(plan_path, plan)
                    plan_binding["sha256"] = protected._digest(  # noqa: SLF001
                        plan_path
                    )
                elif mutation == "coordinated-promotion-identity":
                    substituted = "sha256:" + "1" * 64
                    plan_binding = contract["operationEvidence"]["gaPromotionPlan"]  # type: ignore[index]
                    plan_path = self.root / plan_binding["path"]
                    plan = json.loads(plan_path.read_text(encoding="utf-8"))
                    plan["promotionIdentityDigest"] = substituted
                    write_json(plan_path, plan)
                    plan_binding["sha256"] = protected._digest(  # noqa: SLF001
                        plan_path
                    )
                    receipt["gaPromotionSummaryDigest"] = substituted
                    write_json(receipt_path, receipt)
                    contract["operationEvidence"]["gaPublication"]["sha256"] = (  # type: ignore[index]
                        protected._digest(receipt_path)  # noqa: SLF001
                    )
                else:
                    validation_binding = contract["operationEvidence"]["gaValidation"]  # type: ignore[index]
                    validation_path = self.root / validation_binding["path"]
                    validation = json.loads(
                        validation_path.read_text(encoding="utf-8")
                    )
                    validation["selectedRc"]["freezeDigest"] = DIGEST_ZERO
                    write_json(validation_path, validation)
                    validation_binding["sha256"] = protected._digest(  # noqa: SLF001
                        validation_path
                    )

                with mock.patch.object(
                    protected,
                    "_policy_errors",
                    return_value=[],
                ):
                    findings, statuses = protected._closeout(  # noqa: SLF001
                        self.root,
                        contract,
                        self.policy,
                    )

                self.assertNotEqual([], findings)
                self.assertNotEqual("completed", statuses["gaPublication"])

    def test_ga_validation_requires_positive_decision_and_exact_authorization(self) -> None:
        mutations = {
            "no-go": lambda value: value.update(
                state="validated", promotionReady=False, decision="no-go"
            ),
            "authorization-id": lambda value: value["authorization"].update(
                authorizationId="other-authorization"
            ),
            "authorization-scope": lambda value: value["authorization"].update(
                allowedPublicationScope=[]
            ),
            "catalog-digest": lambda value: value["selectedRc"].update(
                catalogDigest=DIGEST_ZERO
            ),
            "catalog-revision": lambda value: value["selectedRc"].update(
                catalogRevision=4
            ),
            "waiver-decision": lambda value: value.update(
                decision="go-with-waivers"
            ),
        }
        for mutation, apply_mutation in mutations.items():
            with self.subTest(mutation=mutation):
                contract = copy.deepcopy(self.contract)
                _configure_publication_receipt(self.root, contract)
                validation_binding = contract["operationEvidence"]["gaValidation"]  # type: ignore[index]
                validation_path = self.root / validation_binding["path"]
                validation = json.loads(validation_path.read_text(encoding="utf-8"))
                apply_mutation(validation)
                write_json(validation_path, validation)
                validation_binding["sha256"] = protected._digest(  # noqa: SLF001
                    validation_path
                )

                with mock.patch.object(
                    protected,
                    "_policy_errors",
                    return_value=[],
                ):
                    findings, statuses = protected._closeout(  # noqa: SLF001
                        self.root,
                        contract,
                        self.policy,
                    )

                self.assertNotEqual([], findings)
                self.assertNotEqual("completed", statuses["gaValidation"])
                self.assertNotEqual("completed", statuses["gaPublication"])

    def test_ga_validation_uses_canonical_file_byte_digests(self) -> None:
        for mutation in ("lineage-semantic-digest", "authorization-semantic-digest"):
            with self.subTest(mutation=mutation):
                contract = copy.deepcopy(self.contract)
                _configure_publication_receipt(self.root, contract)
                validation_binding = contract["operationEvidence"]["gaValidation"]  # type: ignore[index]
                validation_path = self.root / validation_binding["path"]
                validation = json.loads(validation_path.read_text(encoding="utf-8"))
                if mutation == "lineage-semantic-digest":
                    lineage_binding = contract["operationEvidence"]["rcFreeze"]  # type: ignore[index]
                    lineage_path = self.root / lineage_binding["path"]
                    lineage = json.loads(lineage_path.read_text(encoding="utf-8"))
                    validation["selectedRc"]["lineageDigest"] = (  # type: ignore[index]
                        protected._semantic_digest(lineage)  # noqa: SLF001
                    )
                else:
                    authorization_binding = contract["ga"]["authorization"]["file"]  # type: ignore[index]
                    authorization_path = self.root / authorization_binding["path"]
                    authorization = json.loads(
                        authorization_path.read_text(encoding="utf-8")
                    )
                    validation["authorization"]["authorizationDigest"] = (  # type: ignore[index]
                        protected._semantic_digest(authorization)  # noqa: SLF001
                    )
                write_json(validation_path, validation)
                validation_binding["sha256"] = protected._digest(  # noqa: SLF001
                    validation_path
                )

                with mock.patch.object(
                    protected,
                    "_policy_errors",
                    return_value=[],
                ):
                    findings, statuses = protected._closeout(  # noqa: SLF001
                        self.root,
                        contract,
                        self.policy,
                    )

                self.assertNotEqual([], findings)
                self.assertNotEqual("completed", statuses["gaValidation"])
                self.assertNotEqual("completed", statuses["gaPublication"])

    def test_publication_requires_authenticated_canonical_ga_plan(self) -> None:
        contract = copy.deepcopy(self.contract)
        _configure_publication_receipt(self.root, contract)
        contract["operationEvidence"]["gaPromotionPlan"] = None  # type: ignore[index]

        with mock.patch.object(protected, "_policy_errors", return_value=[]):
            findings, statuses = protected._closeout(  # noqa: SLF001
                self.root,
                contract,
                self.policy,
            )

        self.assertTrue(any("promotion identity" in item for item in findings))
        self.assertNotEqual("completed", statuses["gaPublication"])

    def test_publication_authorized_validation_requires_exact_authorization(self) -> None:
        contract = copy.deepcopy(self.contract)
        _configure_publication_receipt(self.root, contract)
        contract["ga"]["authorization"] = None  # type: ignore[index]
        contract["ga"]["validationIdentityDigest"] = None  # type: ignore[index]
        contract["operationEvidence"]["gaPromotionPlan"] = None  # type: ignore[index]
        contract["operationEvidence"]["gaPublication"] = None  # type: ignore[index]
        contract["workflowCoordinates"]["gaPublication"] = None  # type: ignore[index]
        contract["ga"]["publicationIntent"] = "validate-only"  # type: ignore[index]
        contract["lifecycleState"] = "ga-validated"
        contract["evidenceClassification"]["protectedOperation"] = "partial"  # type: ignore[index]

        with mock.patch.object(protected, "_policy_errors", return_value=[]):
            findings, statuses = protected._closeout(  # noqa: SLF001
                self.root,
                contract,
                self.policy,
            )

        self.assertTrue(any("authorization binding" in item for item in findings))
        self.assertNotEqual("completed", statuses["gaValidation"])

    def test_closeout_rejects_publication_receipt_for_wrong_run_or_payload(self) -> None:
        mutations = (
            ("releaseId", "another-release", "releaseId differs"),
            ("buildVersion", "4", "buildVersion differs"),
            ("sourceCommit", "b" * 40, "sourceCommit differs"),
            ("productDistributionDigest", DIGEST_ZERO, "productDistributionDigest differs"),
        )
        for field, replacement, expected in mutations:
            with self.subTest(field=field):
                contract = copy.deepcopy(self.contract)
                receipt, receipt_path = _configure_publication_receipt(self.root, contract)
                receipt[field] = replacement
                write_json(receipt_path, receipt)
                contract["operationEvidence"]["gaPublication"]["sha256"] = (  # type: ignore[index]
                    protected._digest(receipt_path)  # noqa: SLF001
                )

                with mock.patch.object(protected, "_policy_errors", return_value=[]):
                    findings, statuses = protected._closeout(  # noqa: SLF001
                        self.root, contract, self.policy
                    )

                self.assertTrue(any(expected in item for item in findings), findings)
                self.assertNotEqual("completed", statuses["gaPublication"])

        contract = copy.deepcopy(self.contract)
        receipt, receipt_path = _configure_publication_receipt(self.root, contract)
        receipt["workflow"]["runAttempt"] = 2  # type: ignore[index]
        write_json(receipt_path, receipt)
        contract["operationEvidence"]["gaPublication"]["sha256"] = (  # type: ignore[index]
            protected._digest(receipt_path)  # noqa: SLF001
        )

        with mock.patch.object(protected, "_policy_errors", return_value=[]):
            findings, statuses = protected._closeout(  # noqa: SLF001
                self.root, contract, self.policy
            )

        self.assertTrue(any("workflow differs" in item for item in findings))
        self.assertNotEqual("completed", statuses["gaPublication"])

    def test_publication_completion_requires_every_outer_binding(self) -> None:
        for mutation in (
            "receipt-digest",
            "receipt-schema",
            "workflow",
            "artifact-digest",
            "intent",
            "authorization-digest",
        ):
            with self.subTest(mutation=mutation):
                contract = copy.deepcopy(self.contract)
                _receipt, _receipt_path = _configure_publication_receipt(self.root, contract)
                if mutation == "receipt-digest":
                    contract["operationEvidence"]["gaPublication"]["sha256"] = DIGEST_ZERO  # type: ignore[index]
                elif mutation == "receipt-schema":
                    contract["operationEvidence"]["gaPublication"]["schema"] = None  # type: ignore[index]
                elif mutation == "workflow":
                    contract["workflowCoordinates"]["gaPublication"]["workflowPath"] = (  # type: ignore[index]
                        ".github/workflows/unrelated.yml"
                    )
                elif mutation == "artifact-digest":
                    contract["workflowCoordinates"]["gaPublication"]["artifactDigest"] = DIGEST_ZERO  # type: ignore[index]
                elif mutation == "intent":
                    contract["ga"]["publicationIntent"] = "validate-only"  # type: ignore[index]
                else:
                    contract["ga"]["authorization"]["file"]["sha256"] = DIGEST_ZERO  # type: ignore[index]

                with mock.patch.object(protected, "_policy_errors", return_value=[]):
                    findings, statuses = protected._closeout(  # noqa: SLF001
                        self.root, contract, self.policy
                    )

                self.assertNotEqual([], findings)
                self.assertNotEqual("completed", statuses["gaPublication"])

    def test_publication_receipt_rejects_substituted_catalog_and_asset_count(self) -> None:
        for mutation in ("catalog", "rollback", "asset-count"):
            with self.subTest(mutation=mutation):
                contract = copy.deepcopy(self.contract)
                receipt, receipt_path = _configure_publication_receipt(self.root, contract)
                if mutation == "catalog":
                    substituted = "sha256:" + "1" * 64
                    receipt["catalog"]["catalogDigest"] = substituted  # type: ignore[index]
                    receipt["catalog"]["primary"]["digest"] = substituted  # type: ignore[index]
                    for mirror in receipt["catalog"]["mirrors"]:  # type: ignore[index]
                        mirror["digest"] = substituted
                elif mutation == "rollback":
                    receipt["catalog"]["rollback"]["digest"] = DIGEST_ZERO  # type: ignore[index]
                else:
                    receipt["publicStateObservation"]["releaseAssets"]["observedCount"] = 1  # type: ignore[index]
                write_json(receipt_path, receipt)
                contract["operationEvidence"]["gaPublication"]["sha256"] = (  # type: ignore[index]
                    protected._digest(receipt_path)  # noqa: SLF001
                )

                with mock.patch.object(protected, "_policy_errors", return_value=[]):
                    findings, statuses = protected._closeout(  # noqa: SLF001
                        self.root, contract, self.policy
                    )

                self.assertNotEqual([], findings)
                self.assertNotEqual("completed", statuses["gaPublication"])

    def test_public_observation_requires_exact_product_at_artifact_target(self) -> None:
        contract = copy.deepcopy(self.contract)
        receipt, receipt_path = _configure_publication_receipt(self.root, contract)
        observation = _public_observation(
            contract,
            receipt,
            protected._digest(receipt_path),  # noqa: SLF001
        )
        _bind_observation_coordinate(contract, observation)
        product_uri = next(
            row["publicUri"]
            for row in receipt["assets"]  # type: ignore[index]
            if row["digest"] == contract["ga"]["selectedRc"]["productDigest"]  # type: ignore[index]
        )
        product_row = next(
            row
            for row in observation["targets"]  # type: ignore[index]
            if row["publicUri"] == product_uri
        )
        product_row["sha256"] = DIGEST_ZERO
        observation["targets"].append(  # type: ignore[index]
            {
                "role": "unrelated-product",
                "publicUri": "https://8.8.8.8/unrelated/product.tar.gz",
                "sha256": contract["ga"]["selectedRc"]["productDigest"],  # type: ignore[index]
                "size": product_row["size"],
                "status": "observed-exact",
            }
        )
        observation_path = self.root / "public-observation.json"
        write_json(observation_path, observation)
        contract["operationEvidence"]["publicObservation"] = {  # type: ignore[index]
            **_binding(self.root, Path(observation_path.name)),
            "schema": protected.OBSERVATION_SCHEMA,
        }
        _bind_observation_artifact(self.root, contract, observation_path)
        contract["lifecycleState"] = "publicly-observed"
        contract["evidenceClassification"]["publicObservation"] = "completed"  # type: ignore[index]

        with mock.patch.object(protected, "_policy_errors", return_value=[]):
            findings, statuses = protected._closeout(  # noqa: SLF001
                self.root, contract, self.policy
            )

        self.assertTrue(any("every exact published GA asset" in item for item in findings))
        self.assertNotEqual("completed", statuses["publicObservation"])

    def test_public_observation_requires_every_asset_and_no_extra_target(self) -> None:
        for mutation in ("missing-asset", "changed-size", "extra-target"):
            with self.subTest(mutation=mutation):
                contract = copy.deepcopy(self.contract)
                receipt, receipt_path = _configure_publication_receipt(
                    self.root, contract
                )
                observation = _public_observation(
                    contract,
                    receipt,
                    protected._digest(receipt_path),  # noqa: SLF001
                )
                _bind_observation_coordinate(contract, observation)
                asset_rows = [
                    row
                    for row in observation["targets"]  # type: ignore[index]
                    if str(row["role"]).startswith("release-asset-")
                ]
                if mutation == "missing-asset":
                    observation["targets"].remove(asset_rows[0])  # type: ignore[index]
                elif mutation == "changed-size":
                    asset_rows[0]["size"] += 1
                else:
                    observation["targets"].append(  # type: ignore[index]
                        {
                            "role": "unexpected",
                            "publicUri": "https://8.8.8.8/unplanned.bin",
                            "sha256": DIGEST_ZERO,
                            "size": 1,
                            "status": "observed-exact",
                        }
                    )
                observation_path = self.root / f"observation-{mutation}.json"
                write_json(observation_path, observation)
                contract["operationEvidence"]["publicObservation"] = {  # type: ignore[index]
                    **_binding(self.root, Path(observation_path.name)),
                    "schema": protected.OBSERVATION_SCHEMA,
                }
                contract["lifecycleState"] = "publicly-observed"
                contract["evidenceClassification"]["publicObservation"] = "completed"  # type: ignore[index]

                with mock.patch.object(
                    protected, "_policy_errors", return_value=[]
                ):
                    findings, statuses = protected._closeout(  # noqa: SLF001
                        self.root, contract, self.policy
                    )

                self.assertNotEqual([], findings)
                self.assertNotEqual("completed", statuses["publicObservation"])

    def test_public_observation_requires_exact_tag_and_github_release(self) -> None:
        for field in ("tag", "githubRelease"):
            with self.subTest(field=field):
                contract = copy.deepcopy(self.contract)
                receipt, receipt_path = _configure_publication_receipt(
                    self.root, contract
                )
                observation = _public_observation(
                    contract,
                    receipt,
                    protected._digest(receipt_path),  # noqa: SLF001
                )
                _bind_observation_coordinate(contract, observation)
                if field == "tag":
                    observation["tag"]["targetCommit"] = "b" * 40  # type: ignore[index]
                else:
                    observation["githubRelease"]["releaseId"] = 4  # type: ignore[index]
                observation_path = self.root / f"observation-{field}.json"
                write_json(observation_path, observation)
                contract["operationEvidence"]["publicObservation"] = {  # type: ignore[index]
                    **_binding(self.root, Path(observation_path.name)),
                    "schema": protected.OBSERVATION_SCHEMA,
                }
                contract["lifecycleState"] = "publicly-observed"
                contract["evidenceClassification"]["publicObservation"] = "completed"  # type: ignore[index]

                with mock.patch.object(
                    protected, "_policy_errors", return_value=[]
                ):
                    findings, statuses = protected._closeout(  # noqa: SLF001
                        self.root, contract, self.policy
                    )

                self.assertNotEqual([], findings)
                self.assertNotEqual("completed", statuses["publicObservation"])

    def test_public_observation_schema_requires_observer_coordinates(self) -> None:
        contract = copy.deepcopy(self.contract)
        receipt, receipt_path = _configure_publication_receipt(self.root, contract)
        observation = _public_observation(
            contract,
            receipt,
            protected._digest(receipt_path),  # noqa: SLF001
        )
        del observation["observer"]

        findings = validate_schema(observation, protected.OBSERVATION_SCHEMA)

        self.assertTrue(any("observer" in item for item in findings))

    def test_closeout_accepts_separate_exact_public_observation(self) -> None:
        contract = copy.deepcopy(self.contract)
        receipt, receipt_path = _configure_publication_receipt(self.root, contract)
        observation = _public_observation(
            contract,
            receipt,
            protected._digest(receipt_path),  # noqa: SLF001
        )
        _bind_observation_coordinate(contract, observation)
        observation_path = self.root / "exact-public-observation.json"
        write_json(observation_path, observation)
        contract["operationEvidence"]["publicObservation"] = {  # type: ignore[index]
            **_binding(self.root, Path(observation_path.name)),
            "schema": protected.OBSERVATION_SCHEMA,
        }
        _bind_observation_artifact(self.root, contract, observation_path)
        contract["lifecycleState"] = "publicly-observed"
        contract["evidenceClassification"]["publicObservation"] = "completed"  # type: ignore[index]

        with mock.patch.object(protected, "_policy_errors", return_value=[]):
            findings, statuses = protected._closeout(  # noqa: SLF001
                self.root, contract, self.policy
            )

        self.assertEqual([], findings)
        self.assertEqual("completed", statuses["gaPublication"])
        self.assertEqual("completed", statuses["publicObservation"])

    def test_public_observation_rejects_wrong_nonzero_actions_artifact_digest(
        self,
    ) -> None:
        contract = copy.deepcopy(self.contract)
        receipt, receipt_path = _configure_publication_receipt(self.root, contract)
        observation = _public_observation(
            contract,
            receipt,
            protected._digest(receipt_path),  # noqa: SLF001
        )
        _bind_observation_coordinate(contract, observation)
        observation_path = self.root / "wrong-artifact-digest-observation.json"
        write_json(observation_path, observation)
        contract["operationEvidence"]["publicObservation"] = {  # type: ignore[index]
            **_binding(self.root, Path(observation_path.name)),
            "schema": protected.OBSERVATION_SCHEMA,
        }
        _bind_observation_artifact(self.root, contract, observation_path)
        contract["workflowCoordinates"]["publicObservation"]["artifactDigest"] = (  # type: ignore[index]
            "sha256:" + "9" * 64
        )
        contract["lifecycleState"] = "publicly-observed"
        contract["evidenceClassification"]["publicObservation"] = "completed"  # type: ignore[index]

        with mock.patch.object(protected, "_policy_errors", return_value=[]):
            findings, statuses = protected._closeout(  # noqa: SLF001
                self.root, contract, self.policy
            )

        self.assertTrue(
            any("exact Actions artifact digest" in item for item in findings),
            findings,
        )
        self.assertNotEqual("completed", statuses["publicObservation"])

    def test_ga_validation_requires_exact_retained_actions_artifact_bytes(
        self,
    ) -> None:
        for mutation in (
            "wrong-container-digest",
            "substituted-member",
            "wrong-validation-coordinate",
        ):
            with self.subTest(mutation=mutation):
                contract = copy.deepcopy(self.contract)
                _configure_publication_receipt(self.root, contract)
                if mutation == "wrong-container-digest":
                    contract["workflowCoordinates"]["gaEvidenceApproval"][  # type: ignore[index]
                        "artifactDigest"
                    ] = "sha256:" + "9" * 64
                elif mutation == "substituted-member":
                    validation_binding = contract["operationEvidence"][  # type: ignore[index]
                        "gaValidation"
                    ]
                    validation_path = self.root / str(validation_binding["path"])
                    validation = json.loads(validation_path.read_text(encoding="utf-8"))
                    validation["generatedAt"] = "2026-08-16T00:46:00Z"
                    write_json(validation_path, validation)
                    validation_binding["sha256"] = protected._digest(  # noqa: SLF001
                        validation_path
                    )
                else:
                    contract["workflowCoordinates"]["gaValidation"].update(  # type: ignore[index]
                        runId="999",
                        runAttempt="7",
                        artifactName="fabricated-ga-validation-coordinate",
                        artifactDigest="sha256:" + "f" * 64,
                    )

                with mock.patch.object(
                    protected, "_policy_errors", return_value=[]
                ):
                    findings, statuses = protected._closeout(  # noqa: SLF001
                        self.root, contract, self.policy
                    )

                expected = (
                    "authenticated protected evidence artifact"
                    if mutation == "wrong-validation-coordinate"
                    else "GA validation Actions artifact"
                )
                self.assertTrue(any(expected in item for item in findings), findings)
                self.assertNotEqual("completed", statuses["gaValidation"])

    def test_rc_and_ga_publication_require_exact_retained_actions_artifacts(
        self,
    ) -> None:
        for mutation, status_key, expected in (
            ("missing-rc-archive", "protectedRcOperation", "Stable RC Actions artifact archive is missing"),
            ("substituted-rc-freeze", "protectedRcOperation", "differs from extracted evidence bytes"),
            ("missing-publication-archive", "gaPublication", "GA publication Actions artifact archive is missing"),
            ("substituted-publication-receipt", "gaPublication", "differs from extracted evidence bytes"),
        ):
            with self.subTest(mutation=mutation):
                contract = copy.deepcopy(self.contract)
                receipt, receipt_path = _configure_publication_receipt(
                    self.root, contract
                )
                if mutation == "missing-rc-archive":
                    contract["operationEvidence"]["rcFreezeArtifact"] = None  # type: ignore[index]
                elif mutation == "substituted-rc-freeze":
                    freeze_binding = contract["operationEvidence"][  # type: ignore[index]
                        "rcFreezeRecord"
                    ]
                    freeze_path = self.root / str(freeze_binding["path"])
                    freeze_value = json.loads(freeze_path.read_text(encoding="utf-8"))
                    freeze_path.write_text(
                        json.dumps(freeze_value, sort_keys=True) + "\n",
                        encoding="utf-8",
                    )
                    freeze_binding["sha256"] = protected._digest(freeze_path)  # noqa: SLF001
                elif mutation == "missing-publication-archive":
                    contract["operationEvidence"]["gaPublicationArtifact"] = None  # type: ignore[index]
                else:
                    receipt_path.write_text(
                        json.dumps(receipt, sort_keys=True) + "\n",
                        encoding="utf-8",
                    )
                    contract["operationEvidence"]["gaPublication"][  # type: ignore[index]
                        "sha256"
                    ] = protected._digest(receipt_path)  # noqa: SLF001

                with mock.patch.object(
                    protected, "_policy_errors", return_value=[]
                ):
                    findings, statuses = protected._closeout(  # noqa: SLF001
                        self.root, contract, self.policy
                    )

                self.assertTrue(any(expected in item for item in findings), findings)
                self.assertNotEqual("completed", statuses[status_key])

    def test_github_metadata_rejects_coordinated_local_artifact_substitution(
        self,
    ) -> None:
        coordinate = _coordinate(
            ".github/workflows/stable-1.0-public-observation.yml",
            "stable-1-0-public-observation",
            run_id="31",
            artifact_name="stable-1-0-public-observation-3-31-1",
            artifact_digest="sha256:" + "5" * 64,
        )

        def api_response(path: str, _token: str) -> dict[str, object]:
            if path == "/user":
                return {"login": "leumor"}
            if "/attempts/" in path:
                return {
                    "id": 31,
                    "run_attempt": 1,
                    "head_sha": COMMIT,
                    "path": ".github/workflows/stable-1.0-public-observation.yml",
                    "event": "workflow_dispatch",
                    "conclusion": "success",
                    "repository": {"full_name": "crypta-network/cryptad"},
                    "actor": {"login": "leumor"},
                    "triggering_actor": {"login": "leumor"},
                }
            return {
                "total_count": 1,
                "artifacts": [
                    {
                        "name": coordinate["artifactName"],
                        "digest": coordinate["artifactDigest"],
                        "expired": False,
                    }
                ],
            }

        with mock.patch.dict(os.environ, {"GH_TOKEN": "redacted-test-token"}), mock.patch.object(
            protected, "_github_api_json", side_effect=api_response
        ):
            authentic = self.github_coordinate_auth(
                coordinate,
                label="public observation",
            )
            substituted = copy.deepcopy(coordinate)
            substituted["artifactDigest"] = "sha256:" + "9" * 64
            rejected = self.github_coordinate_auth(
                substituted,
                label="public observation",
            )

        self.assertEqual([], authentic)
        self.assertTrue(any("missing, expired, or ambiguous" in item for item in rejected))

    def test_github_metadata_requires_leumor_dispatch_and_rerun_actors(self) -> None:
        coordinate = _coordinate(
            ".github/workflows/stable-1.0-rc-release.yml",
            "stable-1-0-rc",
        )

        for actor_field in ("actor", "triggering_actor"):
            with self.subTest(actor_field=actor_field):
                def response(path: str, _token: str) -> dict[str, object]:
                    if path == "/user":
                        return {"login": "leumor"}
                    if "/attempts/" in path:
                        return {
                            "id": int(str(coordinate["runId"])),
                            "run_attempt": int(str(coordinate["runAttempt"])),
                            "head_sha": COMMIT,
                            "path": coordinate["workflowPath"],
                            "event": "workflow_dispatch",
                            "conclusion": "success",
                            "repository": {"full_name": "crypta-network/cryptad"},
                            "actor": {
                                "login": (
                                    "not-leumor" if actor_field == "actor" else "leumor"
                                )
                            },
                            "triggering_actor": {
                                "login": (
                                    "not-leumor"
                                    if actor_field == "triggering_actor"
                                    else "leumor"
                                )
                            },
                        }
                    return {
                        "total_count": 1,
                        "artifacts": [
                            {
                                "name": coordinate["artifactName"],
                                "digest": coordinate["artifactDigest"],
                                "expired": False,
                            }
                        ],
                    }

                with mock.patch.dict(
                    os.environ, {"GH_TOKEN": "redacted-test-token"}
                ), mock.patch.object(
                    protected, "_github_api_json", side_effect=response
                ):
                    findings = self.github_coordinate_auth(
                        coordinate, label="RC freeze"
                    )

                self.assertTrue(
                    any("not performed by leumor" in item for item in findings)
                )

    def test_ga_evidence_metadata_requires_successful_protected_attestation_job(
        self,
    ) -> None:
        coordinate = _coordinate(
            ".github/workflows/stable-1.0-ga-promotion.yml",
            "stable-1-0-ga-evidence",
            run_id="20",
            artifact_name=f"stable-1-0-ga-validated-{RELEASE_ID}-3-20-1",
        )

        def authenticate(
            jobs: list[dict[str, object]], *, total_count: int | None = None
        ) -> list[str]:
            def response(path: str, _token: str) -> dict[str, object]:
                if path == "/user":
                    return {"login": "leumor"}
                if path.endswith("/jobs?per_page=100"):
                    return {
                        "total_count": len(jobs) if total_count is None else total_count,
                        "jobs": jobs,
                    }
                if "/attempts/" in path:
                    return {
                        "id": 20,
                        "run_attempt": 1,
                        "head_sha": COMMIT,
                        "path": ".github/workflows/stable-1.0-ga-promotion.yml",
                        "event": "workflow_dispatch",
                        "conclusion": "success",
                        "repository": {"full_name": "crypta-network/cryptad"},
                        "actor": {"login": "leumor"},
                        "triggering_actor": {"login": "leumor"},
                    }
                return {
                    "total_count": 1,
                    "artifacts": [
                        {
                            "name": coordinate["artifactName"],
                            "digest": coordinate["artifactDigest"],
                            "expired": False,
                        }
                    ],
                }

            with mock.patch.dict(
                os.environ, {"GH_TOKEN": "redacted-test-token"}
            ), mock.patch.object(
                protected, "_github_api_json", side_effect=response
            ):
                return self.github_coordinate_auth(
                    coordinate,
                    label="GA evidence approval",
                    required_job_name="Attest protected Stable GA evidence bytes",
                    required_job_steps=(
                        "Verify the exact protected attestation subjects",
                        "Attest exact validation, authorization, and publication-target identity",
                    ),
                )

        authentic_job = {
            "name": "Attest protected Stable GA evidence bytes",
            "run_id": 20,
            "head_sha": COMMIT,
            "status": "completed",
            "conclusion": "success",
            "steps": [
                {
                    "name": "Verify the exact protected attestation subjects",
                    "status": "completed",
                    "conclusion": "success",
                },
                {
                    "name": "Attest exact validation, authorization, and publication-target identity",
                    "status": "completed",
                    "conclusion": "success",
                },
            ],
        }
        authentic = authenticate([authentic_job])
        publication_only = authenticate(
            [
                {
                    **authentic_job,
                    "name": "Explicitly publish authorized Stable 1.0 GA assets",
                }
            ]
        )
        skipped_evidence = authenticate(
            [{**authentic_job, "conclusion": "skipped"}]
        )
        missing_attestation_step = authenticate(
            [
                {
                    **authentic_job,
                    "steps": [authentic_job["steps"][0]],  # type: ignore[index]
                }
            ]
        )
        wrong_job_run = authenticate([{**authentic_job, "run_id": 21}])
        wrong_job_commit = authenticate([{**authentic_job, "head_sha": "d" * 40}])
        duplicate_evidence = authenticate([authentic_job, authentic_job])
        incomplete_jobs = authenticate([authentic_job], total_count=2)

        self.assertEqual([], authentic)
        for findings in (
            publication_only,
            skipped_evidence,
            missing_attestation_step,
            wrong_job_run,
            wrong_job_commit,
            duplicate_evidence,
            incomplete_jobs,
        ):
            with self.subTest(findings=findings):
                self.assertTrue(
                    any(
                        "required protected workflow" in item
                        or "job result is incomplete" in item
                        for item in findings
                    ),
                    findings,
                )

    def test_ga_evidence_job_is_structurally_bound_to_protected_environment(
        self,
    ) -> None:
        ga = (
            workspace_root() / ".github/workflows/stable-1.0-ga-promotion.yml"
        ).read_text(encoding="utf-8")

        attestation_job = protected._workflow_job_block(ga, "attest-evidence")  # noqa: SLF001
        publication_job = protected._workflow_job_block(ga, "publish")  # noqa: SLF001

        self.assertIsNotNone(attestation_job)
        self.assertIsNotNone(publication_job)
        for expected in (
            "name: Attest protected Stable GA evidence bytes",
            "if: inputs.publish == false",
            "needs: validate",
            "environment: stable-1-0-ga-evidence",
            "name: Verify the exact protected attestation subjects",
            "name: Attest exact validation, authorization, and publication-target identity",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, attestation_job)
        for expected in (
            "name: Explicitly publish authorized Stable 1.0 GA assets",
            "if: inputs.publish == true",
            "environment: stable-1-0-ga",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, publication_job)

        mutated = ga.replace(
            "    environment: stable-1-0-ga-evidence\n",
            "    environment: stable-1-0-ga\n",
            1,
        )
        mutated_path = self.root / "stable-1.0-ga-promotion.yml"
        mutated_path.write_text(mutated, encoding="utf-8")
        mutated_job = protected._workflow_job_block(  # noqa: SLF001
            mutated_path.read_text(encoding="utf-8"), "attest-evidence"
        )

        self.assertNotIn("environment: stable-1-0-ga-evidence", mutated_job)
        extract_job = protected._workflow_job_block  # noqa: SLF001

        def job_without_evidence_environment(workflow: str, job_id: str) -> str | None:
            block = extract_job(workflow, job_id)
            if block is not None and job_id == "attest-evidence":
                return block.replace(
                    "environment: stable-1-0-ga-evidence",
                    "environment: stable-1-0-ga",
                )
            return block

        with mock.patch.object(
            protected,
            "_workflow_job_block",
            side_effect=job_without_evidence_environment,
        ):
            findings = protected._policy_errors(  # noqa: SLF001
                workspace_root(), self.contract, self.policy
            )

        self.assertTrue(
            any("exact evidence-attestation job" in finding for finding in findings),
            findings,
        )

    def test_ga_validation_identity_authenticates_every_canonical_source_field(
        self,
    ) -> None:
        contract = copy.deepcopy(self.contract)
        _configure_publication_receipt(self.root, contract)
        identity_path = self.root / str(
            contract["operationEvidence"]["gaValidationIdentity"]["path"]  # type: ignore[index]
        )
        identity = json.loads(identity_path.read_text(encoding="utf-8"))
        lineage_path = self.root / str(
            contract["operationEvidence"]["rcFreeze"]["path"]  # type: ignore[index]
        )
        lineage = json.loads(lineage_path.read_text(encoding="utf-8"))
        freeze_path = self.root / str(
            contract["operationEvidence"]["rcFreezeRecord"]["path"]  # type: ignore[index]
        )
        freeze = json.loads(freeze_path.read_text(encoding="utf-8"))
        validation_path = self.root / str(
            contract["operationEvidence"]["gaValidation"]["path"]  # type: ignore[index]
        )
        validation = json.loads(validation_path.read_text(encoding="utf-8"))
        post_freeze_path = self.root / "stable-1.0-rc-validation.json"
        post_freeze = json.loads(post_freeze_path.read_text(encoding="utf-8"))
        authorization_path = self.root / str(
            contract["ga"]["authorization"]["file"]["path"]  # type: ignore[index]
        )
        authorization = json.loads(authorization_path.read_text(encoding="utf-8"))
        mutations: dict[str, object] = {
            "checksumsDigest": DIGEST_ZERO,
            "provenanceDigest": DIGEST_ZERO,
            "postFreezeValidationGeneratedAt": "2026-08-15T00:00:00Z",
            "requiredUpgradePredecessor": {
                **identity["requiredUpgradePredecessor"],
                "releaseId": "wrong-predecessor",
            },
            "platformApiDigest": DIGEST_ZERO,
            "firstPartyAppsDigest": DIGEST_ZERO,
            "contentProfilesDigest": DIGEST_ZERO,
            "limitationsDigest": DIGEST_ZERO,
        }

        for field, replacement in mutations.items():
            with self.subTest(field=field):
                changed = copy.deepcopy(identity)
                changed[field] = replacement

                findings = protected._ga_validation_identity_errors(  # noqa: SLF001
                    changed,
                    contract,
                    protected._digest(lineage_path),  # noqa: SLF001
                    lineage["selectedFreeze"],
                    authorization,
                    freeze,
                    validation,
                    post_freeze,
                    protected._digest(post_freeze_path),  # noqa: SLF001
                    protected._digest(self.root / "checksums.txt"),  # noqa: SLF001
                    protected._digest(self.root / "provenance.json"),  # noqa: SLF001
                )

                self.assertTrue(any(field in item for item in findings), findings)

    def test_ga_plan_catalog_id_and_rollback_are_frozen_rc_authorities(self) -> None:
        for field, replacement in (
            ("catalogId", "substituted-catalog"),
            ("rollbackDigest", DIGEST_ZERO),
        ):
            with self.subTest(field=field):
                contract = copy.deepcopy(self.contract)
                _configure_publication_receipt(self.root, contract)
                plan_path = self.root / str(
                    contract["operationEvidence"]["gaPromotionPlan"]["path"]  # type: ignore[index]
                )
                plan = json.loads(plan_path.read_text(encoding="utf-8"))
                plan["catalog"][field] = replacement
                authorization_path = self.root / str(
                    contract["ga"]["authorization"]["file"]["path"]  # type: ignore[index]
                )
                authorization = json.loads(
                    authorization_path.read_text(encoding="utf-8")
                )
                freeze_path = self.root / str(
                    contract["operationEvidence"]["rcFreezeRecord"]["path"]  # type: ignore[index]
                )
                freeze = json.loads(freeze_path.read_text(encoding="utf-8"))

                findings = protected._ga_promotion_plan_errors(  # noqa: SLF001
                    plan,
                    contract,
                    authorization,
                    plan["promotionIdentityDigest"],
                    freeze,
                )

                self.assertTrue(
                    any("authenticated RC freeze" in item for item in findings),
                    findings,
                )

    def test_public_observation_rejects_wrong_release_or_build(self) -> None:
        for field, replacement, expected in (
            ("releaseId", "another-release", "different release"),
            ("buildVersion", "4", "different build"),
        ):
            with self.subTest(field=field):
                contract = copy.deepcopy(self.contract)
                receipt, receipt_path = _configure_publication_receipt(self.root, contract)
                observation = _public_observation(
                    contract,
                    receipt,
                    protected._digest(receipt_path),  # noqa: SLF001
                )
                _bind_observation_coordinate(contract, observation)
                observation[field] = replacement
                observation_path = self.root / f"public-observation-{field}.json"
                write_json(observation_path, observation)
                contract["operationEvidence"]["publicObservation"] = {  # type: ignore[index]
                    **_binding(self.root, Path(observation_path.name)),
                    "schema": protected.OBSERVATION_SCHEMA,
                }
                contract["lifecycleState"] = "publicly-observed"
                contract["evidenceClassification"]["publicObservation"] = "completed"  # type: ignore[index]

                with mock.patch.object(protected, "_policy_errors", return_value=[]):
                    findings, statuses = protected._closeout(  # noqa: SLF001
                        self.root, contract, self.policy
                    )

                self.assertTrue(any(expected in item for item in findings), findings)
                self.assertNotEqual("completed", statuses["publicObservation"])

    def test_public_observation_rejects_wrong_catalog_bytes_or_coordinates(self) -> None:
        for mutation in (
            "catalog-digest",
            "catalog-signature-digest",
            "run-attempt",
            "artifact-digest",
        ):
            with self.subTest(mutation=mutation):
                contract = copy.deepcopy(self.contract)
                receipt, receipt_path = _configure_publication_receipt(self.root, contract)
                observation = _public_observation(
                    contract,
                    receipt,
                    protected._digest(receipt_path),  # noqa: SLF001
                )
                _bind_observation_coordinate(contract, observation)
                if mutation in {"catalog-digest", "catalog-signature-digest"}:
                    role = "catalog-primary" if mutation == "catalog-digest" else "catalog-primary-signature"
                    target = next(
                        row
                        for row in observation["targets"]  # type: ignore[index]
                        if row["role"] == role
                    )
                    target["sha256"] = DIGEST_ZERO
                elif mutation == "run-attempt":
                    observation["observer"]["runAttempt"] = "2"  # type: ignore[index]
                else:
                    contract["workflowCoordinates"]["publicObservation"]["artifactDigest"] = DIGEST_ZERO  # type: ignore[index]
                observation_path = self.root / f"public-observation-{mutation}.json"
                write_json(observation_path, observation)
                contract["operationEvidence"]["publicObservation"] = {  # type: ignore[index]
                    **_binding(self.root, Path(observation_path.name)),
                    "schema": protected.OBSERVATION_SCHEMA,
                }
                contract["lifecycleState"] = "publicly-observed"
                contract["evidenceClassification"]["publicObservation"] = "completed"  # type: ignore[index]

                with mock.patch.object(protected, "_policy_errors", return_value=[]):
                    findings, statuses = protected._closeout(  # noqa: SLF001
                        self.root, contract, self.policy
                    )

                self.assertNotEqual([], findings)
                self.assertNotEqual("completed", statuses["publicObservation"])

    def test_closeout_accepts_exact_preflight_and_rc_receipts_only(self) -> None:
        contract = copy.deepcopy(self.contract)
        preflight_path = self.root / "preflight.json"
        rc_path = self.root / "rc-freeze.json"
        selected = _selected_rc()
        freeze_record = _rc_freeze_record(selected)
        freeze_record_path = self.root / "stable-1.0-rc-freeze.json"
        write_json(freeze_record_path, freeze_record)
        write_json(preflight_path, _preflight_summary(contract))
        rc_archive_path = self.root / "stable-1.0-rc-artifact-only.zip"
        with zipfile.ZipFile(
            rc_archive_path, "w", compression=zipfile.ZIP_STORED
        ) as archive:
            archive.write(
                freeze_record_path,
                arcname="artifacts/legacy/stable-1.0-rc-freeze.json",
            )
            archive.write(
                preflight_path,
                arcname=(
                    "artifacts/protected-execution/"
                    "stable-1.0-protected-release-preflight-summary.json"
                ),
            )
        rc_archive_binding = _binding(self.root, Path(rc_archive_path.name))
        rc_coordinate = _coordinate(
            ".github/workflows/stable-1.0-rc-release.yml",
            "stable-1-0-rc",
            artifact_name=f"stable-1-0-rc-{RELEASE_ID}-3-100-1",
            artifact_digest=str(rc_archive_binding["sha256"]),
        )
        lineage = _rc_lineage_receipt(rc_coordinate)
        for freeze in (
            lineage["selectedFreeze"],
            lineage["latestSuccessfulFreeze"],
            lineage["history"][0],
        ):
            freeze["freezeDigest"] = selected["freezeDigest"]
            freeze["freezeFileDigest"] = protected._digest(freeze_record_path)  # noqa: SLF001
            freeze["productDistributionDigest"] = selected["productDigest"]
            freeze["archiveDigest"] = selected["archiveDigest"]
        write_json(rc_path, lineage)
        preflight_binding = _binding(self.root, Path("preflight.json"))
        preflight_binding["schema"] = protected.SUMMARY_SCHEMA
        contract["operationEvidence"]["preflight"] = preflight_binding  # type: ignore[index]
        contract["operationEvidence"]["rcPreflight"] = copy.deepcopy(  # type: ignore[index]
            preflight_binding
        )
        contract["operationEvidence"]["rcFreeze"] = {  # type: ignore[index]
            **_binding(self.root, Path("rc-freeze.json")),
            "schema": protected.RC_LINEAGE_SCHEMA,
        }
        contract["operationEvidence"]["rcFreezeRecord"] = {  # type: ignore[index]
            **_binding(self.root, Path(freeze_record_path.name)),
            "schema": protected.RC_FREEZE_SCHEMA,
        }
        contract["operationEvidence"]["rcFreezeArtifact"] = rc_archive_binding  # type: ignore[index]
        contract["workflowCoordinates"]["rc"] = rc_coordinate  # type: ignore[index]
        contract["lifecycleState"] = "rc-frozen"
        contract["evidenceClassification"] = {
            "repositoryImplementation": "present",
            "offlineVerification": "passed",
            "protectedOperation": "completed",
            "publicObservation": "not-performed",
        }

        with mock.patch.object(protected, "_policy_errors", return_value=[]):
            findings, statuses = protected._closeout(self.root, contract, self.policy)  # noqa: SLF001

        self.assertEqual([], findings)
        self.assertEqual("passed", statuses["offlineVerification"])
        self.assertEqual("completed", statuses["protectedRcOperation"])

        regenerated = copy.deepcopy(contract)
        write_json(preflight_path, {**_preflight_summary(contract), "contractDigest": "sha256:" + "9" * 64})
        regenerated["operationEvidence"]["rcPreflight"] = {  # type: ignore[index]
            **_binding(self.root, Path("preflight.json")), "schema": protected.SUMMARY_SCHEMA
        }
        with mock.patch.object(protected, "_policy_errors", return_value=[]):
            findings, statuses = protected._closeout(self.root, regenerated, self.policy)  # noqa: SLF001
        self.assertNotEqual([], findings)
        self.assertNotEqual("completed", statuses["protectedRcOperation"])

        wrong_attempt = copy.deepcopy(contract)
        wrong_coordinate = wrong_attempt["workflowCoordinates"]["rc"]
        wrong_coordinate["runAttempt"] = "2"
        wrong_lineage = _rc_lineage_receipt(wrong_coordinate)
        for freeze in (
            wrong_lineage["selectedFreeze"],
            wrong_lineage["latestSuccessfulFreeze"],
            wrong_lineage["history"][0],
        ):
            freeze["freezeDigest"] = selected["freezeDigest"]
            freeze["freezeFileDigest"] = protected._digest(freeze_record_path)  # noqa: SLF001
            freeze["productDistributionDigest"] = selected["productDigest"]
            freeze["archiveDigest"] = selected["archiveDigest"]
        write_json(rc_path, wrong_lineage)
        wrong_attempt["operationEvidence"]["rcFreeze"] = {
            **_binding(self.root, Path("rc-freeze.json")),
            "schema": protected.RC_LINEAGE_SCHEMA,
        }

        with mock.patch.object(protected, "_policy_errors", return_value=[]):
            findings, statuses = protected._closeout(  # noqa: SLF001
                self.root,
                wrong_attempt,
                self.policy,
            )

        self.assertTrue(
            any("artifact name is not canonical" in finding for finding in findings),
            findings,
        )
        self.assertNotEqual("completed", statuses["protectedRcOperation"])

    def test_closeout_rejects_minimal_self_asserted_preflight_receipt(self) -> None:
        contract = copy.deepcopy(self.contract)
        preflight_path = self.root / "minimal-preflight.json"
        write_json(
            preflight_path,
            {
                "status": "pass",
                "contractDigest": protected._plan_digest(contract),  # noqa: SLF001
            },
        )
        contract["operationEvidence"]["preflight"] = _binding(  # type: ignore[index]
            self.root,
            Path(preflight_path.name),
        )

        with mock.patch.object(protected, "_policy_errors", return_value=[]):
            findings, statuses = protected._closeout(  # noqa: SLF001
                self.root,
                contract,
                self.policy,
            )

        self.assertTrue(findings)
        self.assertNotEqual("passed", statuses["offlineVerification"])

    def test_preflight_receipt_requires_exact_identity_dispatch_and_redaction(self) -> None:
        binding = {
            "path": "preflight.json",
            "sha256": "sha256:" + "1" * 64,
            "schema": protected.SUMMARY_SCHEMA,
        }
        summary = _preflight_summary(self.contract)
        self.assertEqual(
            [],
            protected._preflight_receipt_errors(  # noqa: SLF001
                self.contract,
                binding,
                summary,
            ),
        )
        mutations = {
            "mode": "closeout",
            "candidateCommit": "b" * 40,
            "releaseId": "another-release",
            "buildVersion": "4",
            "dispatchPackage": {},
            "redaction": {"status": "fail", "findingCount": 1, "findings": [{}]},
        }
        for field, value in mutations.items():
            with self.subTest(field=field):
                wrong = copy.deepcopy(summary)
                wrong[field] = value
                self.assertTrue(
                    protected._preflight_receipt_errors(  # noqa: SLF001
                        self.contract,
                        binding,
                        wrong,
                    )
                )
        wrong_binding = dict(binding)
        wrong_binding["schema"] = None
        self.assertTrue(
            protected._preflight_receipt_errors(  # noqa: SLF001
                self.contract,
                wrong_binding,
                summary,
            )
        )

    def test_closeout_binds_selected_rc_payload_digests_to_lineage(self) -> None:
        for selected_field in ("freezeDigest", "productDigest", "archiveDigest"):
            with self.subTest(selected_field=selected_field):
                contract = copy.deepcopy(self.contract)
                selected = _selected_rc()
                coordinate = _coordinate(
                    ".github/workflows/stable-1.0-rc-release.yml",
                    "stable-1-0-rc",
                    run_id=str(selected["runId"]),
                    run_attempt=str(selected["runAttempt"]),
                    artifact_name=str(selected["artifactName"]),
                    artifact_digest=str(selected["artifactDigest"]),
                )
                lineage = _rc_lineage_receipt(coordinate)
                for freeze in (
                    lineage["selectedFreeze"],
                    lineage["latestSuccessfulFreeze"],
                    lineage["history"][0],
                ):
                    freeze["freezeDigest"] = selected["freezeDigest"]
                    freeze["productDistributionDigest"] = selected["productDigest"]
                    freeze["archiveDigest"] = selected["archiveDigest"]
                lineage_path = self.root / f"lineage-{selected_field}.json"
                write_json(lineage_path, lineage)
                contract["workflowCoordinates"]["rc"] = coordinate  # type: ignore[index]
                contract["operationEvidence"]["rcFreeze"] = {  # type: ignore[index]
                    **_binding(self.root, Path(lineage_path.name)),
                    "schema": protected.RC_LINEAGE_SCHEMA,
                }
                contract["ga"]["selectedRc"] = selected  # type: ignore[index]
                contract["ga"]["selectedRc"][selected_field] = DIGEST_ZERO  # type: ignore[index]
                contract["lifecycleState"] = "rc-frozen"
                contract["evidenceClassification"]["protectedOperation"] = "completed"  # type: ignore[index]

                with mock.patch.object(
                    protected, "_policy_errors", return_value=[]
                ):
                    findings, statuses = protected._closeout(  # noqa: SLF001
                        self.root,
                        contract,
                        self.policy,
                    )

                self.assertTrue(
                    any("payload digests differ" in item for item in findings),
                    findings,
                )
                self.assertNotEqual(
                    "completed", statuses["protectedRcOperation"]
                )

    def test_closeout_requires_latest_and_final_successful_lineage_selection(self) -> None:
        for mutation in ("latest", "history"):
            with self.subTest(mutation=mutation):
                contract = copy.deepcopy(self.contract)
                selected = _selected_rc()
                coordinate = _coordinate(
                    ".github/workflows/stable-1.0-rc-release.yml",
                    "stable-1-0-rc",
                    run_id=str(selected["runId"]),
                    run_attempt=str(selected["runAttempt"]),
                    artifact_name=str(selected["artifactName"]),
                    artifact_digest=str(selected["artifactDigest"]),
                )
                lineage = _rc_lineage_receipt(coordinate)
                for freeze in (
                    lineage["selectedFreeze"],
                    lineage["latestSuccessfulFreeze"],
                    lineage["history"][0],
                ):
                    freeze["freezeDigest"] = selected["freezeDigest"]
                    freeze["productDistributionDigest"] = selected["productDigest"]
                    freeze["archiveDigest"] = selected["archiveDigest"]
                if mutation == "latest":
                    lineage["latestSuccessfulFreeze"]["freezeDigest"] = DIGEST_ZERO
                else:
                    lineage["history"][0]["freezeDigest"] = DIGEST_ZERO
                lineage_path = self.root / f"lineage-{mutation}.json"
                write_json(lineage_path, lineage)
                contract["workflowCoordinates"]["rc"] = coordinate  # type: ignore[index]
                contract["operationEvidence"]["rcFreeze"] = {  # type: ignore[index]
                    **_binding(self.root, Path(lineage_path.name)),
                    "schema": protected.RC_LINEAGE_SCHEMA,
                }
                contract["ga"]["selectedRc"] = selected  # type: ignore[index]
                contract["lifecycleState"] = "rc-frozen"
                contract["evidenceClassification"]["protectedOperation"] = "completed"  # type: ignore[index]

                with mock.patch.object(
                    protected, "_policy_errors", return_value=[]
                ):
                    findings, statuses = protected._closeout(  # noqa: SLF001
                        self.root,
                        contract,
                        self.policy,
                    )

                self.assertTrue(any("selected RC" in item for item in findings))
                self.assertNotEqual(
                    "completed", statuses["protectedRcOperation"]
                )

    def test_closeout_rejects_schema_invalid_lineage_without_selecting_history(self) -> None:
        contract = copy.deepcopy(self.contract)
        selected = _selected_rc()
        coordinate = _coordinate(
            ".github/workflows/stable-1.0-rc-release.yml",
            "stable-1-0-rc",
            run_id=str(selected["runId"]),
            run_attempt=str(selected["runAttempt"]),
            artifact_name=str(selected["artifactName"]),
            artifact_digest=str(selected["artifactDigest"]),
        )
        lineage = _rc_lineage_receipt(coordinate)
        malformed_history = copy.deepcopy(lineage["history"][0])
        malformed_history["ordinal"] = "2"
        lineage["history"].append(malformed_history)
        lineage_path = self.root / "malformed-lineage.json"
        write_json(lineage_path, lineage)
        contract["workflowCoordinates"]["rc"] = coordinate  # type: ignore[index]
        contract["operationEvidence"]["rcFreeze"] = {  # type: ignore[index]
            **_binding(self.root, Path(lineage_path.name)),
            "schema": protected.RC_LINEAGE_SCHEMA,
        }
        contract["ga"]["selectedRc"] = selected  # type: ignore[index]
        contract_path = self.root / "malformed-lineage-execution.json"
        output = self.root / "malformed-lineage-closeout"
        write_json(contract_path, contract)

        with mock.patch.object(protected, "_policy_errors", return_value=[]):
            result = protected.run(
                self.root,
                contract_path,
                "closeout",
                output,
            )

        summary = json.loads(
            (output / protected.SUMMARY_FILE).read_text(encoding="utf-8")
        )
        self.assertEqual(1, result)
        self.assertTrue(
            any("ordinal" in finding for finding in summary["findings"]),
            summary["findings"],
        )
        self.assertNotEqual(
            "completed",
            summary["evidenceClassification"]["protectedRcOperation"],
        )
        self.assertEqual(
            "not-performed",
            summary["evidenceClassification"]["gaPublication"],
        )

    def test_closeout_does_not_parse_schema_invalid_rc_freeze_record(self) -> None:
        contract = copy.deepcopy(self.contract)
        selected = _selected_rc()
        coordinate = _coordinate(
            ".github/workflows/stable-1.0-rc-release.yml",
            "stable-1-0-rc",
            run_id=str(selected["runId"]),
            run_attempt=str(selected["runAttempt"]),
            artifact_name=str(selected["artifactName"]),
            artifact_digest=str(selected["artifactDigest"]),
        )
        lineage = _rc_lineage_receipt(coordinate)
        for freeze in (
            lineage["selectedFreeze"],
            lineage["latestSuccessfulFreeze"],
            lineage["history"][0],
        ):
            freeze["freezeDigest"] = selected["freezeDigest"]
            freeze["productDistributionDigest"] = selected["productDigest"]
            freeze["archiveDigest"] = selected["archiveDigest"]
        lineage_path = self.root / "valid-lineage.json"
        freeze_path = self.root / "malformed-freeze.json"
        write_json(lineage_path, lineage)
        write_json(freeze_path, {"schemaVersion": 1})
        contract["workflowCoordinates"]["rc"] = coordinate  # type: ignore[index]
        contract["operationEvidence"]["rcFreeze"] = {  # type: ignore[index]
            **_binding(self.root, Path(lineage_path.name)),
            "schema": protected.RC_LINEAGE_SCHEMA,
        }
        contract["operationEvidence"]["rcFreezeRecord"] = {  # type: ignore[index]
            **_binding(self.root, Path(freeze_path.name)),
            "schema": protected.RC_FREEZE_SCHEMA,
        }
        contract["ga"]["selectedRc"] = selected  # type: ignore[index]

        with mock.patch.object(
            protected, "_policy_errors", return_value=[]
        ), mock.patch.object(
            protected,
            "freeze_content_digest",
            side_effect=AssertionError("schema-invalid freeze must not be parsed"),
        ):
            findings, statuses = protected._closeout(  # noqa: SLF001
                self.root,
                contract,
                self.policy,
            )

        self.assertTrue(any("freeze record" in finding for finding in findings), findings)
        self.assertNotEqual("completed", statuses["protectedRcOperation"])

    def test_closeout_rejects_noncanonical_rc_and_ga_validation_receipts(self) -> None:
        contract = copy.deepcopy(self.contract)
        rc_coordinate = _coordinate(
            ".github/workflows/stable-1.0-rc-release.yml",
            "stable-1-0-rc",
            artifact_name="stable-rc",
        )
        rc_path = self.root / "rc-lineage.json"
        write_json(rc_path, _rc_lineage_receipt(rc_coordinate))
        contract["workflowCoordinates"]["rc"] = rc_coordinate  # type: ignore[index]
        contract["operationEvidence"]["rcFreeze"] = _binding(  # type: ignore[index]
            self.root, Path(rc_path.name)
        )
        selected = _selected_rc()
        contract["ga"]["selectedRc"] = selected  # type: ignore[index]
        contract["workflowCoordinates"]["gaValidation"] = _coordinate(  # type: ignore[index]
            ".github/workflows/stable-1.0-ga-promotion.yml", "none", run_id="20"
        )
        contract["workflowCoordinates"]["gaEvidenceApproval"] = _coordinate(  # type: ignore[index]
            ".github/workflows/stable-1.0-ga-promotion.yml",
            "stable-1-0-ga-evidence",
            run_id="20",
        )
        validation_path = self.root / "minimal-validation.json"
        write_json(
            validation_path,
            {
                "status": "pass",
                "payloadIdentity": {
                    "bitIdentical": True,
                    "rebuildPerformed": False,
                    "rcProductDigest": selected["productDigest"],
                    "gaProductDigest": selected["productDigest"],
                },
            },
        )
        contract["operationEvidence"]["gaValidation"] = _binding(  # type: ignore[index]
            self.root, Path(validation_path.name)
        )

        with mock.patch.object(protected, "_policy_errors", return_value=[]):
            findings, statuses = protected._closeout(  # noqa: SLF001
                self.root, contract, self.policy
            )

        self.assertTrue(any("canonical schema" in item for item in findings))
        self.assertNotEqual("completed", statuses["protectedRcOperation"])
        self.assertNotEqual("completed", statuses["gaValidation"])

    def test_closeout_rejects_changed_ga_bytes_wrong_rc_coordinates_and_partial_publication(self) -> None:
        contract = copy.deepcopy(self.contract)
        selected = {
            "runId": "10",
            "runAttempt": "2",
            "artifactName": "stable-rc",
            "artifactDigest": "sha256:" + "1" * 64,
            "freezeDigest": "sha256:" + "2" * 64,
            "productDigest": "sha256:" + "3" * 64,
            "archiveDigest": "sha256:" + "4" * 64,
            "catalogDigest": "sha256:" + "b" * 64,
            "catalogRevision": 3,
        }
        contract["ga"]["selectedRc"] = selected  # type: ignore[index]
        contract["workflowCoordinates"]["rc"] = _coordinate(  # type: ignore[index]
            ".github/workflows/stable-1.0-rc-release.yml",
            "stable-1-0-rc",
            run_id="10",
            run_attempt="1",
            artifact_name="stable-rc",
            artifact_digest=selected["artifactDigest"],
        )
        rc_path = self.root / "rc.json"
        write_json(
            rc_path,
            {
                "kind": "stable-1.0-rc-lineage",
                "status": "pass",
                "releaseId": RELEASE_ID,
                "buildVersion": "3",
                "sourceCommit": COMMIT,
                "selectedFreeze": {"workflow": {}},
            },
        )
        contract["operationEvidence"]["rcFreeze"] = _binding(  # type: ignore[index]
            self.root, Path("rc.json")
        )
        validation_path = self.root / "ga-validation.json"
        write_json(
            validation_path,
            {
                "status": "pass",
                "payloadIdentity": {
                    "bitIdentical": False,
                    "rebuildPerformed": True,
                    "rcProductDigest": selected["productDigest"],
                    "gaProductDigest": DIGEST_ZERO,
                },
            },
        )
        contract["operationEvidence"]["gaValidation"] = _binding(  # type: ignore[index]
            self.root, Path("ga-validation.json")
        )
        contract["workflowCoordinates"]["gaValidation"] = _coordinate(  # type: ignore[index]
            ".github/workflows/stable-1.0-ga-promotion.yml", "none", run_id="20"
        )
        contract["workflowCoordinates"]["gaEvidenceApproval"] = _coordinate(  # type: ignore[index]
            ".github/workflows/stable-1.0-ga-promotion.yml",
            "stable-1-0-ga-evidence",
            run_id="20",
        )
        publication_path = self.root / "publication.json"
        write_json(publication_path, {"publicationState": "partial"})
        contract["operationEvidence"]["gaPublication"] = _binding(  # type: ignore[index]
            self.root, Path("publication.json")
        )
        contract["workflowCoordinates"]["gaPublication"] = _coordinate(  # type: ignore[index]
            ".github/workflows/stable-1.0-ga-promotion.yml",
            "stable-1-0-ga",
            run_id="20",
        )

        with mock.patch.object(protected, "_policy_errors", return_value=[]):
            findings, statuses = protected._closeout(self.root, contract, self.policy)  # noqa: SLF001

        self.assertTrue(any("selected RC differs" in item for item in findings))
        self.assertTrue(any("exact-byte no-rebuild" in item for item in findings))
        self.assertTrue(any("partial" in item for item in findings))
        self.assertNotEqual("completed", statuses["gaValidation"])
        self.assertNotEqual("completed", statuses["gaPublication"])

    def test_closeout_rejects_unproved_claimed_lifecycle_state(self) -> None:
        contract = copy.deepcopy(self.contract)
        contract["lifecycleState"] = "publicly-observed"

        with mock.patch.object(protected, "_policy_errors", return_value=[]):
            findings, _statuses = protected._closeout(self.root, contract, self.policy)  # noqa: SLF001

        self.assertTrue(any("lifecycle state claims" in item for item in findings))

    def test_closeout_rejects_fixture_or_self_test_protected_receipts(self) -> None:
        contract = copy.deepcopy(self.contract)
        coordinate = _coordinate(
            ".github/workflows/stable-1.0-rc-release.yml",
            "stable-1-0-rc",
            artifact_name="stable-rc",
        )
        receipt_path = self.root / "fixture-lineage.json"
        write_json(
            receipt_path,
            {
                "kind": "stable-1.0-rc-lineage",
                "status": "pass",
                "releaseId": RELEASE_ID,
                "buildVersion": "3",
                "sourceCommit": COMMIT,
                "fixture": True,
                "selfTest": True,
                "selectedFreeze": {
                    "workflow": {
                        "repository": coordinate["repository"],
                        "runId": int(coordinate["runId"]),
                        "runAttempt": int(coordinate["runAttempt"]),
                        "artifactName": coordinate["artifactName"],
                        "artifactDigest": coordinate["artifactDigest"],
                        "environment": coordinate["environment"],
                        "conclusion": "success",
                    }
                },
            },
        )
        contract["operationEvidence"]["rcFreeze"] = _binding(  # type: ignore[index]
            self.root, Path("fixture-lineage.json")
        )
        contract["workflowCoordinates"]["rc"] = coordinate  # type: ignore[index]

        with mock.patch.object(protected, "_policy_errors", return_value=[]):
            findings, statuses = protected._closeout(self.root, contract, self.policy)  # noqa: SLF001

        self.assertTrue(any("fixture evidence" in item for item in findings))
        self.assertTrue(any("self-test" in item for item in findings))
        self.assertNotEqual("completed", statuses["protectedRcOperation"])

    def test_remote_workflow_action_tags_fail_pinning_policy(self) -> None:
        workflow = self.root / "workflow.yml"
        workflow.write_text(
            "steps:\n  - uses: actions/checkout@v6\n  - uses: ./.github/actions/local\n",
            encoding="utf-8",
        )

        findings = protected._workflow_action_errors(workflow)  # noqa: SLF001

        self.assertEqual(1, len(findings))
        self.assertIn("not pinned", findings[0])

    def test_protected_workflows_keep_pinned_actions_and_authority_boundaries(self) -> None:
        root = workspace_root()
        rc = (root / ".github/workflows/stable-1.0-rc-release.yml").read_text(encoding="utf-8")
        ga = (root / ".github/workflows/stable-1.0-ga-promotion.yml").read_text(encoding="utf-8")
        observation = (
            root / ".github/workflows/stable-1.0-public-observation.yml"
        ).read_text(encoding="utf-8")

        def dispatch_input_count(workflow: str) -> int:
            inputs = workflow.split("    inputs:\n", maxsplit=1)[1].split(
                "\nconcurrency:", maxsplit=1
            )[0]
            return sum(
                1
                for line in inputs.splitlines()
                if re.fullmatch(r"      [a-z0-9_]+:", line)
            )

        self.assertEqual([], protected._workflow_action_errors(root / ".github/workflows/stable-1.0-rc-release.yml"))  # noqa: SLF001
        self.assertEqual([], protected._workflow_action_errors(root / ".github/workflows/stable-1.0-ga-promotion.yml"))  # noqa: SLF001
        self.assertEqual([], protected._workflow_action_errors(root / ".github/workflows/stable-1.0-public-observation.yml"))  # noqa: SLF001
        self.assertIn("environment: stable-1-0-rc", rc)
        self.assertIn("environment: stable-1-0-ga-evidence", ga)
        self.assertIn("environment: stable-1-0-ga", ga)
        self.assertIn("environment: stable-1-0-public-observation", observation)
        self.assertIn("ga_evidence_coordinates:", ga)
        self.assertIn("Authenticate exact prior protected GA evidence approval", ga)
        self.assertIn("Attest protected Stable GA evidence bytes", ga)
        self.assertIn('cmp --silent "$evidence" "$prior_evidence"', ga)
        self.assertIn("java-version: '25.0.4.1+1'", rc)
        self.assertIn("java-version: '25.0.4.1+1'", ga)
        self.assertLessEqual(dispatch_input_count(rc), 25)
        self.assertLessEqual(dispatch_input_count(ga), 25)
        self.assertEqual(7, dispatch_input_count(observation))
        self.assertIn("stable_authority_coordinates:", rc)
        self.assertIn("protected_execution_contract:", rc)
        self.assertIn("protected_preflight_receipt:", rc)
        self.assertIn("--mode rc-dispatch", rc)
        self.assertIn("--rc-input-map", rc)
        self.assertIn("reviewPolicyVersion: $review_policy_version", rc)
        self.assertIn("catalogSigningKeyId: $catalog_signing_key_id", rc)
        self.assertIn("stable-1.0-protected-release-preflight-summary.json", rc)
        self.assertIn(
            "jq -S '.stableSupplyChain | .runAttempt |= tonumber'",
            rc,
        )
        self.assertIn('DISPATCH_ACTOR: ${{ github.actor }}', rc)
        self.assertIn('TRIGGERING_ACTOR: ${{ github.triggering_actor }}', rc)
        self.assertIn('"$DISPATCH_ACTOR" != "leumor"', rc)
        self.assertIn('"$TRIGGERING_ACTOR" != "leumor"', rc)
        self.assertLess(
            rc.index("--mode rc-dispatch"),
            rc.index("certify.py stable-rc --manifest"),
        )
        prior_evidence = ga[
            ga.index("Authenticate exact prior protected GA evidence approval") :
            ga.index("Download exact prior evidence-approved GA artifact")
        ]
        self.assertIn('.actor.login == "leumor"', prior_evidence)
        self.assertIn('.triggering_actor.login == "leumor"', prior_evidence)
        self.assertEqual(1, rc.count("certify.py stable-rc --manifest"))
        failure_closeout = rc[rc.index("\n  retain-failure-closeout:") :]
        stable_rc_job = rc[
            rc.index("\n  stable-rc:") : rc.index("\n  retain-failure-closeout:")
        ]
        self.assertIn("Reauthenticate the current protected RC operator", stable_rc_job)
        self.assertIn('DISPATCH_ACTOR: ${{ github.actor }}', stable_rc_job)
        self.assertIn('TRIGGERING_ACTOR: ${{ github.triggering_actor }}', stable_rc_job)
        self.assertIn('"$DISPATCH_ACTOR" != "leumor"', stable_rc_job)
        self.assertIn('"$TRIGGERING_ACTOR" != "leumor"', stable_rc_job)
        self.assertIn("always()", failure_closeout)
        self.assertIn("- preflight", failure_closeout)
        self.assertIn("- stable-rc", failure_closeout)
        self.assertIn("needs.preflight.result", failure_closeout)
        self.assertIn("needs.stable-rc.result", failure_closeout)
        self.assertIn("permissions: {}", failure_closeout)
        self.assertNotIn("environment:", failure_closeout)
        self.assertNotIn("secrets.", failure_closeout)
        self.assertNotIn("actions/checkout", failure_closeout)
        self.assertNotIn("gh api", failure_closeout)
        self.assertNotIn("${{ inputs.", failure_closeout)
        self.assertIn('"$size" -gt 16384', failure_closeout)
        self.assertIn("protectedRcOperationCompleted: false", failure_closeout)
        self.assertIn('freezeArtifactAuthentication: "unverified"', failure_closeout)
        self.assertNotIn("Write bounded Stable RC failure closeout", stable_rc_job)
        self.assertNotIn("Retain bounded Stable RC failure closeout", stable_rc_job)
        self.assertNotIn("./gradlew build", ga)
        publish = ga[ga.index("\n  publish:") :]
        permission_block = publish[: publish.index("\n    steps:")]
        self.assertIn("contents: read", permission_block)
        self.assertNotIn("contents: write", permission_block)
        self.assertIn('DISPATCH_ACTOR: ${{ github.actor }}', publish)
        self.assertIn('TRIGGERING_ACTOR: ${{ github.triggering_actor }}', publish)
        publication_boundary = publish[
            publish.index("validate_publication_boundary()") :
            publish.index("begin_publication_side_effect()")
        ]
        self.assertIn('"$DISPATCH_ACTOR" != "leumor"', publication_boundary)
        self.assertIn('"$TRIGGERING_ACTOR" != "leumor"', publication_boundary)
        self.assertIn("actions: read", observation)
        self.assertIn("contents: read", observation)
        self.assertNotIn("contents: write", observation)
        self.assertNotIn("gh release create", observation)
        self.assertNotIn("gh api --method", observation)
        self.assertIn("PublicObservationTransport", observation)
        self.assertIn("transport.exact_digest(", observation)
        self.assertIn("transport.bounded_digest(", observation)
        self.assertIn("PUBLIC_SIGNATURE_LIMIT", observation)
        self.assertIn("catalog_signature_uri(", observation)
        self.assertIn('"role": f"{role}-signature"', observation)
        self.assertNotIn("urllib.request", observation)
        self.assertNotIn("response.read()", observation)
        self.assertIn('github_release_identity(', observation)
        self.assertIn("github_annotated_tag_identity(", observation)
        self.assertIn('"tag": observed_tag', observation)
        self.assertIn('DISPATCH_ACTOR: ${{ github.actor }}', observation)
        self.assertIn('TRIGGERING_ACTOR: ${{ github.triggering_actor }}', observation)
        self.assertIn('"$DISPATCH_ACTOR" != "leumor"', observation)
        self.assertIn('"$TRIGGERING_ACTOR" != "leumor"', observation)
        selected_ga_authentication = observation[
            observation.index('run_json="$(gh api') : observation.index(
                'artifacts="$(gh api', observation.index('run_json="$(gh api')
            )
        ]
        for required_identity in (
            '(.id | tostring) == $run_id',
            '(.run_attempt | tostring) == $run_attempt',
            '.event == "workflow_dispatch"',
            '.repository.full_name == $repository',
            '.head_repository.full_name == $repository',
            '.actor.login == "leumor"',
            '.triggering_actor.login == "leumor"',
        ):
            with self.subTest(required_identity=required_identity):
                self.assertIn(required_identity, selected_ga_authentication)
        self.assertIn(
            'observation_artifact="stable-1-0-public-observation-$INPUT_BUILD_VERSION-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT"',
            observation,
        )

    def test_maximum_release_id_does_not_expand_observation_artifact_name(self) -> None:
        release_id = "r" * 128
        artifact_name = "stable-1-0-public-observation-3-18446744073709551615-9999999999"
        coordinate = _coordinate(
            ".github/workflows/stable-1.0-public-observation.yml",
            "stable-1-0-public-observation",
            run_id="18446744073709551615",
            run_attempt="9999999999",
            artifact_name=artifact_name,
        )
        observer = {
            **{key: value for key, value in coordinate.items() if key != "artifactDigest"},
            "readOnly": True,
        }
        configured_contract = copy.deepcopy(self.contract)
        receipt, receipt_path = _configure_publication_receipt(
            self.root,
            configured_contract,
        )
        observation = _public_observation(
            configured_contract,
            receipt,
            protected._digest(receipt_path),  # noqa: SLF001
        )
        observation["releaseId"] = release_id
        observation["observer"] = observer
        observation_schema = json.loads(
            (
                workspace_root()
                / "tools/release-certification/schemas/stable-1.0-protected-release-public-observation-v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        execution_schema = json.loads(
            (
                workspace_root()
                / "tools/release-certification/schemas/stable-1.0-protected-release-execution-v1.schema.json"
            ).read_text(encoding="utf-8")
        )

        self.assertNotIn(release_id, artifact_name)
        self.assertLessEqual(len(artifact_name), 128)
        self.assertEqual([], validate_schema(observation, protected.OBSERVATION_SCHEMA))
        self.assertEqual(
            [],
            protected._observation_coordinate_errors(  # noqa: SLF001
                observation,
                coordinate,
                observation_workflow=".github/workflows/stable-1.0-public-observation.yml",
                observation_environment="stable-1-0-public-observation",
                commit=COMMIT,
                build="3",
            ),
        )
        self.assertRegex(
            artifact_name,
            observation_schema["properties"]["observer"]["properties"]["artifactName"]["pattern"],
        )
        self.assertRegex(
            artifact_name,
            execution_schema["$defs"]["artifactName"]["pattern"],
        )
        build = "2147483647"
        run_id = "18446744073709551615"
        attempt = "9999999999"
        canonical_names = (
            f"stable-1-0-rc-{release_id}-{build}-{run_id}-{attempt}",
            f"stable-1-0-ga-validated-{release_id}-{build}-{run_id}-{attempt}",
            f"stable-1-0-ga-publication-receipt-{release_id}-{build}-{run_id}-{attempt}",
        )
        for canonical_name in canonical_names:
            with self.subTest(canonical_name=canonical_name[:40]):
                self.assertLessEqual(len(canonical_name), 255)
                self.assertRegex(
                    canonical_name,
                    execution_schema["$defs"]["artifactName"]["pattern"],
                )
        self.assertNotRegex(
            "a" * 256,
            execution_schema["$defs"]["artifactName"]["pattern"],
        )
        bounded_contract = copy.deepcopy(self.contract)
        bounded_contract["workflowCoordinates"]["rc"] = _coordinate(  # type: ignore[index]
            ".github/workflows/stable-1.0-rc-release.yml",
            "stable-1-0-rc",
            run_id=run_id,
            run_attempt=attempt,
            artifact_name=canonical_names[0],
        )
        self.assertEqual([], validate_schema(bounded_contract, protected.CONTRACT_SCHEMA))
        bounded_contract["workflowCoordinates"]["rc"]["runId"] = "1" * 21  # type: ignore[index]
        self.assertTrue(validate_schema(bounded_contract, protected.CONTRACT_SCHEMA))


if __name__ == "__main__":
    unittest.main()
