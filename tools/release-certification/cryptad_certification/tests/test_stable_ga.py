"""Offline self-tests for exact-byte Stable 1.0 GA promotion contracts."""

from __future__ import annotations

import ast
import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import textwrap
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

from cryptad_certification.engines import (
    stable_1_0_ga,
    stable_1_0_ga_artifacts,
    stable_1_0_ga_core,
)
from cryptad_certification.cli import _validate_stable_ga_manifest
from cryptad_certification.engines.stable_1_0_ga_core import (
    AUTHORIZATION_SCHEMA,
    AUTHORIZATION_SCOPE,
    GA_VALIDATION_SCHEMA,
    LINEAGE_SCHEMA,
    PROMOTION_SCHEMA,
    PUBLICATION_RECEIPT_SCHEMA,
    RC_VALIDATION_SCHEMA,
    SelectedRc,
    authenticate_upgrade_predecessor,
    authenticate_selected_rc,
    build_ga_validation_record,
    canonical_artifact_base_uri,
    canonical_publication_targets,
    configured_input_path,
    ga_validation_authorization_identity,
    is_supported_artifact_base_uri,
    load_json_input,
    publication_receipt_errors,
    sanitized_public_asset_observation,
    validate_authorization,
    validate_carried_waivers,
    validate_lineage,
    validate_post_freeze,
)
from cryptad_certification.engines.stable_1_0_rc_artifacts import (
    create_deterministic_archive,
    write_named_checksums,
)
from cryptad_certification.engines.stable_1_0_rc_core import (
    SUPPORTING_VERIFIER_FILES,
    ValidationState,
    file_digest,
    semantic_digest,
)
from cryptad_certification.engines.stable_1_0_rc_freeze import freeze_content_digest
from cryptad_certification.engines.stable_1_0_vulnerability_core import (
    canonical_file_bytes as vulnerability_canonical_file_bytes,
    identity_digest as vulnerability_identity_digest,
)
from cryptad_certification.io import write_json
from cryptad_certification.manifest import (
    COMMAND_NAMES,
    INPUT_FIELDS,
    POLICY_FIELDS,
    ManifestError,
    load_manifest,
)
from cryptad_certification.models import (
    OutputSpec,
    ReleaseSpec,
    RunContext,
    RunManifest,
)
from cryptad_certification.redaction import scan_value
from cryptad_certification.schema_validation import validate_schema
from cryptad_certification.stable_vulnerability_handoff import (
    PROMOTION_FRESHNESS_ASSERTION_FILE,
    authenticate_promotion_freshness_assertion,
    promotion_freshness_assertion,
    source_digest as vulnerability_source_digest,
)
from cryptad_certification.tests.support import workspace_root
from cryptad_certification.tests.test_stable_rc import _freeze as _complete_rc_freeze

RELEASE_ID = "stable-1-0-rc-284"
BUILD_VERSION = "284"
SOURCE_COMMIT = "a" * 40
SOURCE_REF = f"commit:{SOURCE_COMMIT}"
NOW = datetime(2026, 7, 15, 12, 0, tzinfo=timezone.utc)
PREVIOUS_RELEASE_ID = "public-beta-283"
PREVIOUS_BUILD_VERSION = "283"
PREVIOUS_PRODUCT_DIGEST = "sha256:" + "f" * 64

SCHEMA_FILES = (
    "stable-1.0-rc-lineage-v1.schema.json",
    "stable-1.0-rc-validation-v1.schema.json",
    "stable-1.0-ga-authorization-v1.schema.json",
    "stable-1.0-ga-validation-v1.schema.json",
    "stable-1.0-ga-promotion-v1.schema.json",
    "stable-1.0-ga-publication-plan-v1.schema.json",
    "stable-1.0-ga-publication-receipt-v1.schema.json",
    "stable-1.0-maintenance-baseline-v1.schema.json",
)


def _digest(character: str) -> str:
    return "sha256:" + character * 64


def _timestamp(value: datetime) -> str:
    return value.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _redaction() -> dict[str, object]:
    return {"status": "pass", "findingCount": 0, "findings": []}


def _vulnerability_promotion_summary(expires_at: datetime) -> dict[str, object]:
    return {
        "mode": "evaluate-promotion",
        "repositoryIdentity": "github.com/crypta-network/cryptad",
        "releaseId": RELEASE_ID,
        "buildVersion": BUILD_VERSION,
        "policyDigest": _digest("1"),
        "ledgerDigest": _digest("2"),
        "ledgerEdition": 7,
        "summaryDigest": _digest("3"),
        "expiresAt": _timestamp(expires_at),
        "blockingStablePromotion": False,
        "blockingCaseOpaqueIds": [],
        "blockers": [],
    }


def _write_vulnerability_freshness_assertion(
    root: Path, value: dict[str, object]
) -> tuple[Path, str]:
    path = root / PROMOTION_FRESHNESS_ASSERTION_FILE
    raw = vulnerability_canonical_file_bytes(value)
    path.write_bytes(raw)
    path.chmod(0o600)
    return path, vulnerability_source_digest(raw)


def _policy() -> dict[str, object]:
    path = workspace_root() / "tools/release-certification/stable-1.0-ga-policy.json"
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _policy_digest() -> str:
    return file_digest(
        workspace_root() / "tools/release-certification/stable-1.0-ga-policy.json"
    )


def _context(root: Path | None = None, inputs: dict[str, str] | None = None) -> RunContext:
    workspace = (root or workspace_root()).resolve()
    manifest = RunManifest(
        path=workspace / "stable-1.0-ga.json",
        release=ReleaseSpec(RELEASE_ID, BUILD_VERSION, "stable-review"),
        output=OutputSpec(workspace / "build/release-certification"),
        requirements={},
        inputs={} if inputs is None else inputs,
        policies={
            "artifactBaseUri": "https://downloads.crypta.network/stable/",
            "catalogChannel": "stable",
            "candidateSourceCommit": SOURCE_COMMIT,
            "candidateSourceRef": SOURCE_REF,
            "expectedPreviousReleaseId": PREVIOUS_RELEASE_ID,
            "expectedPreviousProductDigest": PREVIOUS_PRODUCT_DIGEST,
            "metadata": {
                "catalogPrimaryUri": (
                    "https://catalog.crypta.network/first-party-catalog.properties"
                ),
                "catalogMirrorUris": (
                    "https://mirror.crypta.network/first-party-catalog.properties"
                ),
                "catalogRollbackUri": (
                    "https://catalog.crypta.network/history/6/first-party-catalog.properties"
                ),
            },
            "publicationIntent": "prepare-explicit-protected-publication",
        },
        execution={},
        commands={"stable-ga": {}},
    )
    return RunContext(
        workspace_root=workspace,
        run_root=workspace / "build/release-certification" / RELEASE_ID,
        component="stable-ga",
        manifest=manifest,
    )


def _selected_rc() -> SelectedRc:
    freeze: dict[str, object] = {
        "candidate": {
            "releaseId": RELEASE_ID,
            "buildVersion": BUILD_VERSION,
            "sourceCommit": SOURCE_COMMIT,
            "sourceRef": SOURCE_REF,
            "productionDistributionDigest": _digest("2"),
            "previousCandidateDigest": _digest("d"),
        },
        "contentDigest": _digest("1"),
        "stableCatalog": {
            "catalogId": "crypta-first-party",
            "channel": "stable",
            "edition": 7,
            "revision": 7,
            "catalogDigest": _digest("7"),
            "signatureDigest": _digest("8"),
            "catalogSigningKeyId": "catalog-production-2026",
            "artifactTimestamp": "2026-01-01T00:00:00Z",
            "keyRotationStatus": {"status": "complete", "compromised": False},
            "securityAdvisoryCount": 0,
            "denylistCount": 0,
            "verifiedRollback": {
                "revision": 6,
                "digest": _digest("9"),
            },
        },
        "platformApi": {"baselineDigest": _digest("a")},
        "firstPartyApps": [{"appId": "publisher", "bundleDigest": _digest("b")}],
        "contentFormatProfiles": [
            {"profileId": "crypta.profile.v1", "descriptorDigest": _digest("c")}
        ],
        "limitationsAndPolicy": {"allowedLimitations": []},
        "acceptedFreezeExceptions": [],
    }
    summary = {
        "status": "pass",
        "promotionReady": True,
        "nonRelease": False,
        "stableReady": True,
        "decision": "go",
        "freeze": {"status": "pass", "driftStatus": "no-drift"},
        "acceptedWaivers": [],
    }
    root = Path("selected-stable-rc")
    return SelectedRc(
        summary_path=root / "summary.json",
        freeze_path=root / "stable-1.0-rc-freeze.json",
        sidecar_path=root / "stable-1.0-rc-freeze.sha256",
        archive_path=root / f"cryptad-stable-1.0-rc-{BUILD_VERSION}.tar.gz",
        product_path=root / f"crypta-stable-1.0-rc-{BUILD_VERSION}-product.tar.gz",
        checksums_path=root / "checksums.txt",
        provenance_path=root / "provenance.json",
        summary_envelope={},
        summary=summary,
        freeze=freeze,
        provenance={
            "freezeMode": "first-freeze",
            "comparisonBaseline": None,
            "inputs": {"previousCandidate": _digest("d")},
        },
        archive_digest=_digest("3"),
        product_digest=_digest("2"),
        freeze_file_digest=_digest("4"),
        checksums_digest=_digest("5"),
        provenance_digest=_digest("6"),
    )


def _previous_candidate_envelope() -> dict[str, object]:
    return {
        "schemaVersion": 2,
        "kind": "migrated-v1-previous-candidate",
        "generatedAt": _timestamp(NOW - timedelta(days=2)),
        "subject": {
            "releaseId": RELEASE_ID,
            "version": BUILD_VERSION,
            "profile": "stable-review",
            "component": "migration/previous-candidate",
        },
        "result": {
            "status": "pass",
            "decision": "go",
            "promotionReady": True,
            "exitCode": 0,
        },
        "counts": {"evidence": 0, "blockers": 0, "warnings": 0, "waivers": 0},
        "evidence": [],
        "issues": {"blockers": [], "warnings": []},
        "waivers": [],
        "redaction": {
            "status": "pass",
            "findingCount": 0,
            "findings": [],
            "guarantees": {"legacyPayloadScanned": True},
        },
        "inputs": {},
        "artifacts": {},
        "payload": {
            "migration": {
                "sourceSchemaVersion": 1,
                "sourceKind": "previous-candidate",
                "sourceSha256": "d" * 64,
            },
            "legacy": {
                "schemaVersion": 1,
                "kind": "production-beta-candidate-summary",
                "generatedAt": _timestamp(NOW - timedelta(days=2)),
                "releaseId": PREVIOUS_RELEASE_ID,
                "version": PREVIOUS_BUILD_VERSION,
                "status": "pass",
                "promotionReady": True,
                "redaction": {"status": "pass", "findingCount": 0, "findings": []},
            },
        },
    }


def _upgrade_predecessor(selected: SelectedRc) -> dict[str, str]:
    return {
        "releaseId": PREVIOUS_RELEASE_ID,
        "buildVersion": PREVIOUS_BUILD_VERSION,
        "previousCandidateDigest": str(
            selected.freeze["candidate"]["previousCandidateDigest"]
        ),
        "productDistributionDigest": PREVIOUS_PRODUCT_DIGEST,
    }


def _write_exact_rc_fixture(root: Path) -> tuple[RunContext, dict[str, Path]]:
    """Materialize one complete PR-283-shaped artifact set for GA authentication tests."""

    root = root.resolve()
    artifact_root = root / "protected-rc"
    artifact_root.mkdir(parents=True)
    previous_candidate = artifact_root / "previous-candidate-summary.json"
    write_json(previous_candidate, _previous_candidate_envelope())
    product_payload = artifact_root / "product.bin"
    product_payload.write_bytes(b"exact frozen Stable RC product bytes\n")
    product_payload_checksums = artifact_root / "product-payload-checksums.txt"
    write_named_checksums(
        product_payload_checksums,
        [("payload/product.bin", product_payload)],
    )
    product = artifact_root / f"crypta-stable-1.0-rc-{BUILD_VERSION}-product.tar.gz"
    create_deterministic_archive(
        product,
        [
            ("payload/product.bin", product_payload),
            ("payload-checksums.txt", product_payload_checksums),
        ],
    )

    freeze = _complete_rc_freeze()
    candidate = freeze["candidate"]
    assert isinstance(candidate, dict)
    candidate.update(
        {
            "releaseId": RELEASE_ID,
            "buildVersion": BUILD_VERSION,
            "sourceCommit": SOURCE_COMMIT,
            "sourceRef": SOURCE_REF,
            "productionDistributionDigest": file_digest(product),
            "previousCandidateDigest": file_digest(previous_candidate),
        }
    )
    freeze["contentDigest"] = freeze_content_digest(freeze)
    freeze_path = artifact_root / "stable-1.0-rc-freeze.json"
    write_json(freeze_path, freeze)
    sidecar = artifact_root / "stable-1.0-rc-freeze.sha256"
    sidecar.write_text(
        f"{file_digest(freeze_path).removeprefix('sha256:')}  {freeze_path.name}\n",
        encoding="utf-8",
    )

    native_summary = {
        "schemaVersion": 1,
        "generatedAt": _timestamp(NOW - timedelta(hours=3)),
        "releaseId": RELEASE_ID,
        "version": BUILD_VERSION,
        "status": "pass",
        "promotionReady": True,
        "nonRelease": False,
        "stableReady": True,
        "decision": "go",
        "freeze": {"status": "pass", "driftStatus": "no-drift"},
        "acceptedWaivers": [],
        "redactionStatus": "pass",
        "redaction": {"status": "pass", "findingCount": 0, "findings": []},
        "blockers": [],
        "warnings": [],
    }
    native_summary_path = artifact_root / "stable-1.0-rc-promotion-summary.json"
    write_json(native_summary_path, native_summary)

    metadata_names = [
        "stable-1.0-rc-freeze.json",
        "stable-1.0-rc-freeze.sha256",
        "stable-1.0-rc-freeze-report.md",
        "stable-1.0-rc-promotion-summary.json",
        "stable-1.0-rc-go-no-go.md",
        "stable-1.0-rc-known-limitations.json",
        "stable-1.0-rc-release-notes.md",
        "stable-1.0-rc-drift-report.json",
        "provenance.json",
        "redaction-report.json",
        *SUPPORTING_VERIFIER_FILES,
    ]
    for name in metadata_names:
        target = artifact_root / name
        if target.exists() or name == "provenance.json":
            continue
        if target.suffix == ".md":
            target.write_text("# Authenticated Stable RC fixture\n", encoding="utf-8")
        else:
            write_json(target, {"status": "pass"})

    archive_members = sorted(
        [
            f"payload/{product.name}",
            *[f"metadata/{name}" for name in metadata_names],
            "payload-checksums.txt",
        ]
    )
    provenance = {
        "schemaVersion": 1,
        "kind": "stable-1.0-rc-provenance",
        "releaseId": RELEASE_ID,
        "buildVersion": BUILD_VERSION,
        "freezeMode": "first-freeze",
        "source": {
            "commit": SOURCE_COMMIT,
            "ref": SOURCE_REF,
            "digest": _digest("b"),
        },
        "freeze": {
            "file": freeze_path.name,
            "contentDigest": freeze["contentDigest"],
            "fileDigest": file_digest(freeze_path),
        },
        "comparisonBaseline": None,
        "productionDistribution": {
            "file": f"payload/{product.name}",
            "digest": file_digest(product),
        },
        "inputs": {"previousCandidate": file_digest(previous_candidate)},
        "archiveLayout": {
            "format": "deterministic-tar-gzip-v1",
            "root": "stable-1.0-rc",
            "normalized": True,
            "members": archive_members,
        },
        "redaction": {"status": "pass", "findingCount": 0},
    }
    provenance_path = artifact_root / "provenance.json"
    write_json(provenance_path, provenance)

    payload_checksums = artifact_root / "payload-checksums.txt"
    archive_sources = [
        (f"payload/{product.name}", product),
        *[(f"metadata/{name}", artifact_root / name) for name in metadata_names],
    ]
    write_named_checksums(payload_checksums, archive_sources)
    archive = artifact_root / f"cryptad-stable-1.0-rc-{BUILD_VERSION}.tar.gz"
    create_deterministic_archive(
        archive,
        [*archive_sources, ("payload-checksums.txt", payload_checksums)],
    )

    checksums = artifact_root / "checksums.txt"
    write_named_checksums(
        checksums,
        [
            (archive.name, archive),
            (product.name, product),
            *[(name, artifact_root / name) for name in metadata_names],
        ],
    )
    common_summary = {
        "schemaVersion": 2,
        "kind": "stable-1.0-rc",
        "generatedAt": native_summary["generatedAt"],
        "subject": {
            "releaseId": RELEASE_ID,
            "version": BUILD_VERSION,
            "profile": "stable-review",
            "component": "stable-rc",
        },
        "result": {
            "status": "pass",
            "decision": "go",
            "promotionReady": True,
            "exitCode": 0,
        },
        "counts": {"evidence": 0, "blockers": 0, "warnings": 0, "waivers": 0},
        "evidence": [],
        "issues": {"blockers": [], "warnings": []},
        "waivers": [],
        "redaction": {
            "status": "pass",
            "findingCount": 0,
            "findings": [],
            "guarantees": {"legacyPayloadScanned": True},
        },
        "inputs": {},
        "artifacts": {},
        "payload": {"legacy": native_summary},
    }
    summary_path = artifact_root / "summary.json"
    write_json(summary_path, common_summary)

    paths = {
        "selectedStableRcSummary": summary_path,
        "selectedStableRcFreeze": freeze_path,
        "selectedStableRcFreezeSidecar": sidecar,
        "selectedStableRcArchive": archive,
        "selectedStableRcProduct": product,
        "selectedStableRcChecksums": checksums,
        "selectedStableRcProvenance": provenance_path,
        "previousCandidate": previous_candidate,
    }
    inputs = {
        key: path.relative_to(root).as_posix()
        for key, path in paths.items()
    }
    return _context(root, inputs), paths


def _workflow() -> dict[str, object]:
    return {
        "provider": "github-actions",
        "repository": "crypta-network/cryptad",
        "workflowName": "Stable 1.0 RC Release Freeze",
        "workflowRef": ".github/workflows/stable-1.0-rc-release.yml@" + SOURCE_COMMIT,
        "runId": 2840,
        "runAttempt": 1,
        "artifactName": "stable-1-0-rc-284-a284",
        "artifactDigest": _digest("d"),
        "environment": "stable-1-0-rc",
        "conclusion": "success",
    }


def _lineage(selected: SelectedRc) -> dict[str, object]:
    selection = {
        "freezeDigest": selected.freeze["contentDigest"],
        "freezeFileDigest": selected.freeze_file_digest,
        "archiveDigest": selected.archive_digest,
        "productDistributionDigest": selected.product_digest,
        "sourceCommit": SOURCE_COMMIT,
        "workflow": _workflow(),
    }
    history = {
        "ordinal": 1,
        "freezeMode": "first-freeze",
        "successful": True,
        **copy.deepcopy(selection),
    }
    return {
        "schemaVersion": 1,
        "kind": "stable-1.0-rc-lineage",
        "generatedAt": _timestamp(NOW - timedelta(hours=48)),
        "releaseId": RELEASE_ID,
        "buildVersion": BUILD_VERSION,
        "profile": "stable-review",
        "component": "stable-rc",
        "sourceCommit": SOURCE_COMMIT,
        "sourceRef": SOURCE_REF,
        "status": "pass",
        "selectedFreeze": selection,
        "latestSuccessfulFreeze": copy.deepcopy(selection),
        "history": [history],
        "acceptedFreezeExceptionHistoryDigest": semantic_digest([]),
        "redaction": _redaction(),
    }


def _binding(selected: SelectedRc) -> dict[str, object]:
    catalog = selected.freeze["stableCatalog"]
    assert isinstance(catalog, dict)
    return {
        "releaseId": RELEASE_ID,
        "buildVersion": BUILD_VERSION,
        "sourceCommit": SOURCE_COMMIT,
        "freezeDigest": selected.freeze["contentDigest"],
        "productDistributionDigest": selected.product_digest,
        "archiveDigest": selected.archive_digest,
        "catalogDigest": catalog["catalogDigest"],
        "catalogRevision": catalog["revision"],
    }


def _evidence(
    selected: SelectedRc,
    *,
    started: datetime,
    ended: datetime,
    digest_character: str,
) -> dict[str, object]:
    return {
        "status": "pass",
        "classification": "protected-production",
        "fixtureOnly": False,
        "simulatedOnly": False,
        "skipped": False,
        "startedAt": _timestamp(started),
        "endedAt": _timestamp(ended),
        "binding": _binding(selected),
        "evidenceDigest": _digest(digest_character),
    }


def _post_freeze_validation(
    selected: SelectedRc,
    policy: dict[str, object],
) -> dict[str, object]:
    started = NOW - timedelta(hours=36)
    ended = started + timedelta(seconds=86400)

    def installation_target(
        operating_system: str,
        architecture: str,
        package_type: str,
        digest_character: str,
    ) -> dict[str, object]:
        return {
            "targetId": f"{operating_system}-{architecture}-{package_type}",
            "operatingSystem": operating_system,
            "architecture": architecture,
            "packageType": package_type,
            "artifactName": f"cryptad-{BUILD_VERSION}-{operating_system}.{package_type}",
            "artifactDigest": _digest(digest_character),
            **_evidence(
                selected,
                started=started,
                ended=ended,
                digest_character=digest_character,
            ),
            "cleanInstall": "pass",
            "packageMetadataVerified": "pass",
            "checksumVerified": "pass",
            "launcherRuntimeDiscovery": "pass",
            "firstRunStateCreation": "pass",
            "startup": "pass",
            "shutdown": "pass",
            "operatorAccess": "pass",
            "diagnostics": "pass",
            "uninstallCleanup": "pass",
        }

    installation_targets = [
        installation_target("linux", "x86_64", "deb", "1"),
        installation_target("linux", "x86_64", "rpm", "2"),
        installation_target("macos", "aarch64", "dmg", "3"),
        installation_target("windows", "x86_64", "exe", "4"),
    ]
    upgrade = {
        **_evidence(selected, started=started, ended=ended, digest_character="5"),
        "previousCandidateDigest": selected.freeze["candidate"][
            "previousCandidateDigest"
        ],
        "previousReleaseId": PREVIOUS_RELEASE_ID,
        "previousBuildVersion": PREVIOUS_BUILD_VERSION,
        "previousProductDigest": PREVIOUS_PRODUCT_DIGEST,
        "daemonUpgrade": "pass",
        "daemonRollbackRecovery": "pass",
        "catalogUpdateRollback": "pass",
        "firstPartyAppInstallUpdateRollback": "pass",
        "appDataMigration": "pass",
        "backupBeforeMigration": "pass",
        "backupRestore": "pass",
        "socialInboxStatePreservation": "pass",
        "trustGraphStatePreservation": "pass",
        "feedReaderStatePreservation": "pass",
        "profilePublisherStatePreservation": "pass",
        "failedUpgradeSupportBundle": "pass",
    }
    security = {
        **_evidence(selected, started=started, ended=ended, digest_character="a"),
        "mandatoryDrills": "pass",
        "catalogSigningIdentityUncompromised": True,
        "appSigningIdentitiesUncompromised": True,
        "reviewerIdentitiesUncompromised": True,
        "denylistAdvisory": "pass",
        "failClosedUpdate": "pass",
        "noNewStableBlocker": True,
        "noDisallowedLimitation": True,
    }
    catalog_operations = {
        **_evidence(selected, started=started, ended=ended, digest_character="c"),
        "primary": "pass",
        "mirrors": "pass",
        "rollback": "pass",
        "keyRotation": "pass",
        "advisoryDenylist": "pass",
        "exactFrozenBytes": True,
    }
    post_freeze_policy = policy["postFreezeValidation"]
    assert isinstance(post_freeze_policy, dict)
    catalog = selected.freeze["stableCatalog"]
    assert isinstance(catalog, dict)
    return {
        "schemaVersion": 1,
        "kind": "stable-1.0-rc-validation",
        "generatedAt": _timestamp(ended + timedelta(hours=1)),
        "validationStartedAt": _timestamp(started),
        "validationEndedAt": _timestamp(ended),
        "releaseId": RELEASE_ID,
        "buildVersion": BUILD_VERSION,
        "profile": "stable-review",
        "sourceCommit": SOURCE_COMMIT,
        "sourceRef": SOURCE_REF,
        "freezeDigest": selected.freeze["contentDigest"],
        "productDistributionDigest": selected.product_digest,
        "archiveDigest": selected.archive_digest,
        "stableCatalog": {
            "catalogId": catalog["catalogId"],
            "channel": "stable",
            "revision": catalog["revision"],
            "catalogDigest": catalog["catalogDigest"],
            "signatureDigest": catalog["signatureDigest"],
            "signingKeyId": catalog["catalogSigningKeyId"],
        },
        "status": "pass",
        "exactRcBinding": True,
        "fixtureOnly": False,
        "simulatedOnly": False,
        "nonRelease": False,
        "policy": {
            "policyDigest": _policy_digest(),
            "minimumLiveSoakDurationSeconds": post_freeze_policy[
                "minimumLiveSoakDurationSeconds"
            ],
            "maximumEvidenceAgeDays": post_freeze_policy["maximumEvidenceAgeDays"],
            "minimumNodeCount": post_freeze_policy["minimumNodeCount"],
            "minimumOperationCount": post_freeze_policy["minimumOperationCount"],
        },
        "scenarios": {
            "longSoak": {
                **_evidence(selected, started=started, ended=ended, digest_character="0"),
                "actualDurationSeconds": 86400,
                "nodeCount": post_freeze_policy["minimumNodeCount"],
                "operationCount": post_freeze_policy["minimumOperationCount"],
                "liveNetwork": "pass",
                "stableMemory": "pass",
                "stableThreads": "pass",
                "stableQueues": "pass",
                "unexpectedRestartCount": 0,
                "stateCorruptionCount": 0,
                "unboundedSubscriptionGrowth": False,
                "interoperability": "pass",
                "performanceComparison": "pass",
            },
            "installationPackaging": {
                "status": "pass",
                "requiredTargetCount": len(installation_targets),
                "validatedTargetCount": len(installation_targets),
                "targets": installation_targets,
            },
            "upgradeRollbackStatePreservation": upgrade,
            "liveNetwork": _evidence(
                selected, started=started, ended=ended, digest_character="6"
            ),
            "interoperability": _evidence(
                selected, started=started, ended=ended, digest_character="7"
            ),
            "performance": _evidence(
                selected, started=started, ended=ended, digest_character="8"
            ),
            "sandboxProvider": _evidence(
                selected, started=started, ended=ended, digest_character="9"
            ),
            "securityResponse": security,
            "supportDiagnostics": _evidence(
                selected, started=started, ended=ended, digest_character="b"
            ),
            "catalogOperations": catalog_operations,
        },
        "redaction": _redaction(),
    }


def _authorization(
    selected: SelectedRc,
    identity: dict[str, object],
) -> dict[str, object]:
    catalog = selected.freeze["stableCatalog"]
    assert isinstance(catalog, dict)
    approved = NOW - timedelta(hours=2)
    return {
        "schemaVersion": 1,
        "kind": "stable-1.0-ga-authorization",
        "generatedAt": _timestamp(approved),
        "authorizationId": "stable-ga-284-authorization",
        "releaseId": RELEASE_ID,
        "buildVersion": BUILD_VERSION,
        "sourceCommit": SOURCE_COMMIT,
        "freezeDigest": selected.freeze["contentDigest"],
        "archiveDigest": selected.archive_digest,
        "productDistributionDigest": selected.product_digest,
        "catalogDigest": catalog["catalogDigest"],
        "catalogRevision": catalog["revision"],
        "gaValidationDigest": semantic_digest(identity),
        "publicationTargets": identity["publicationTargets"],
        "publicationTargetsDigest": identity["publicationTargetsDigest"],
        "status": "authorized",
        "authorizationRole": "stable-release-manager",
        "approverIdentity": "crypta-release-approver-1",
        "approvedAt": _timestamp(approved),
        "expiresAt": _timestamp(approved + timedelta(hours=24)),
        "reviewWindowHours": 24,
        "allowedPublicationScope": list(AUTHORIZATION_SCOPE),
        "redaction": _redaction(),
    }


def _planned_assets() -> list[dict[str, object]]:
    return [
        {
            "name": f"cryptad-stable-1.0-rc-{BUILD_VERSION}.tar.gz",
            "sizeBytes": 4096,
            "digest": _digest("a"),
        },
        {
            "name": "stable-1.0-ga-checksums.txt",
            "sizeBytes": 512,
            "digest": _digest("b"),
        },
    ]


def _receipt(
    selected: SelectedRc,
    promotion_digest: str,
    release_notes_digest: str,
    planned_assets: list[dict[str, object]],
    *,
    operation: str = "created",
) -> dict[str, object]:
    catalog = selected.freeze["stableCatalog"]
    assert isinstance(catalog, dict)
    return {
        "schemaVersion": 1,
        "kind": "stable-1.0-ga-publication-receipt",
        "generatedAt": _timestamp(NOW),
        "releaseId": RELEASE_ID,
        "buildVersion": BUILD_VERSION,
        "sourceCommit": SOURCE_COMMIT,
        "publicationState": "publication-complete",
        "operation": operation,
        "artifactBaseUri": "https://downloads.crypta.network/stable/",
        "tag": {
            "name": "v" + BUILD_VERSION,
            "targetCommit": SOURCE_COMMIT,
            "annotated": True,
            "verificationStatus": "pass",
        },
        "githubRelease": {
            "releaseId": 284,
            "publicUrl": "https://github.com/crypta-network/cryptad/releases/tag/v284",
            "releaseNotesDigest": release_notes_digest,
            "verificationStatus": "pass",
        },
        "assets": [
            {
                **copy.deepcopy(row),
                "publicUri": (
                    "https://downloads.crypta.network/stable/" + str(row["name"])
                ),
                "verificationStatus": "pass",
            }
            for row in planned_assets
        ],
        "freezeDigest": selected.freeze["contentDigest"],
        "productDistributionDigest": selected.product_digest,
        "archiveDigest": selected.archive_digest,
        "gaPromotionSummaryDigest": promotion_digest,
        "catalog": {
            "catalogId": catalog["catalogId"],
            "channel": "stable",
            "revision": catalog["revision"],
            "catalogDigest": catalog["catalogDigest"],
            "signatureDigest": catalog["signatureDigest"],
            "signingKeyId": catalog["catalogSigningKeyId"],
            "artifactTimestamp": catalog["artifactTimestamp"],
            "primary": {
                "locationId": "primary",
                "publicUri": (
                    "https://catalog.crypta.network/first-party-catalog.properties"
                ),
                "digest": catalog["catalogDigest"],
                "signatureVerified": True,
                "verificationStatus": "pass",
            },
            "mirrors": [
                {
                    "locationId": "mirror-1",
                    "publicUri": (
                        "https://mirror.crypta.network/first-party-catalog.properties"
                    ),
                    "digest": catalog["catalogDigest"],
                    "signatureVerified": True,
                    "transportFallbackOnly": True,
                    "verificationStatus": "pass",
                }
            ],
            "rollback": {
                "revision": 6,
                "digest": _digest("9"),
                "publicUri": (
                    "https://catalog.crypta.network/history/6/first-party-catalog.properties"
                ),
                "signatureDigest": _digest("8"),
                "signingKeyId": catalog["catalogSigningKeyId"],
                "signatureVerified": True,
                "verificationStatus": "pass",
            },
            "keyRotationStatus": "complete",
            "advisoryCount": 0,
            "denylistCount": 0,
            "verificationStatus": "pass",
        },
        "releaseNotesDigest": release_notes_digest,
        "publishedAt": _timestamp(NOW - timedelta(minutes=5)),
        "workflow": {
            "provider": "github-actions",
            "repository": "crypta-network/cryptad",
            "workflowName": "Stable 1.0 GA Promotion",
            "runId": 2841,
            "runAttempt": 1,
            "environment": "stable-1-0-ga",
        },
        "publicStateObservation": {
            "tag": {"status": "verified"},
            "githubRelease": {"status": "verified"},
            "releaseAssets": {
                "status": "verified",
                "observedCount": len(planned_assets),
                "missingPlannedAssets": [],
                "unexpectedCount": 0,
                "unexpectedNameDigests": [],
            },
        },
        "finalVerificationStatus": "pass",
        "redaction": _redaction(),
    }


def _identity_fixture(
    context: RunContext,
    selected: SelectedRc,
    validation: dict[str, object],
) -> dict[str, object]:
    return ga_validation_authorization_identity(
        context,
        selected,
        semantic_digest(_lineage(selected)),
        validation,
        semantic_digest(validation),
        _upgrade_predecessor(selected),
        [],
    )


def _authorized_ga_run_context(
    fixture_root: Path,
    workspace: Path,
) -> tuple[RunContext, dict[str, Path], SelectedRc]:
    """Return a complete deterministic authorized GA fixture context."""

    _fixture_context, paths = _write_exact_rc_fixture(fixture_root)
    relative_inputs = {
        key: path.relative_to(workspace).as_posix()
        for key, path in paths.items()
    }
    policies = {
        "artifactBaseUri": "https://9.9.9.9/stable/",
        "catalogChannel": "stable",
        "candidateSourceCommit": SOURCE_COMMIT,
        "candidateSourceRef": SOURCE_REF,
        "expectedPreviousReleaseId": PREVIOUS_RELEASE_ID,
        "expectedPreviousProductDigest": PREVIOUS_PRODUCT_DIGEST,
        "metadata": {
            "catalogPrimaryUri": (
                "https://1.1.1.1/first-party-catalog.properties"
            ),
            "catalogMirrorUris": (
                "https://8.8.8.8/first-party-catalog.properties"
            ),
            "catalogRollbackUri": (
                "https://1.0.0.1/history/6/first-party-catalog.properties"
            ),
        },
        "publicationIntent": "prepare-explicit-protected-publication",
    }

    def context(inputs: dict[str, str]) -> RunContext:
        manifest = RunManifest(
            path=fixture_root / "stable-1.0-ga.json",
            release=ReleaseSpec(RELEASE_ID, BUILD_VERSION, "stable-review"),
            output=OutputSpec(fixture_root / "output", reset=True),
            requirements={},
            inputs=inputs,
            policies=policies,
            execution={},
            commands={"stable-ga": {"mode": "validate-only"}},
        )
        return RunContext(
            workspace_root=workspace,
            run_root=fixture_root / "output" / RELEASE_ID,
            component="stable-ga",
            manifest=manifest,
        )

    selection_state = ValidationState()
    selected = authenticate_selected_rc(context(relative_inputs), selection_state)
    if selection_state.blockers:
        raise AssertionError("authorized GA fixture failed exact RC authentication")
    lineage_path = fixture_root / "stable-1.0-rc-lineage.json"
    validation_path = fixture_root / "stable-1.0-rc-validation.json"
    write_json(lineage_path, _lineage(selected))
    validation = _post_freeze_validation(selected, _policy())
    write_json(validation_path, validation)
    complete_inputs = {
        **relative_inputs,
        "selectedStableRcLineage": lineage_path.relative_to(workspace).as_posix(),
        "stableRcValidation": validation_path.relative_to(workspace).as_posix(),
        "stableGaPolicy": "tools/release-certification/stable-1.0-ga-policy.json",
    }
    authorization_context = context(complete_inputs)
    identity = ga_validation_authorization_identity(
        authorization_context,
        selected,
        file_digest(lineage_path),
        validation,
        file_digest(validation_path),
        _upgrade_predecessor(selected),
        [],
    )
    authorization_path = fixture_root / "stable-1.0-ga-authorization.json"
    write_json(authorization_path, _authorization(selected, identity))
    complete_inputs["stableGaAuthorization"] = authorization_path.relative_to(
        workspace
    ).as_posix()
    return context(complete_inputs), paths, selected


class StableGaExactRcAuthenticationTest(unittest.TestCase):
    def test_complete_pr283_artifact_set_authenticates_exact_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            context, _paths = _write_exact_rc_fixture(Path(directory))
            state = ValidationState()

            selected = authenticate_selected_rc(context, state)

            self.assertEqual([], state.blockers)
            self.assertEqual(selected.product_digest, selected.freeze["candidate"]["productionDistributionDigest"])
            self.assertEqual(selected.archive_digest, file_digest(selected.archive_path))

    def test_renamed_outer_archive_is_rejected_even_when_checksums_match(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            context, paths = _write_exact_rc_fixture(Path(directory))
            archive = paths["selectedStableRcArchive"]
            renamed = archive.with_name("renamed.tar.gz")
            archive.rename(renamed)
            checksum_names = [
                row.partition("  ")[2]
                for row in paths["selectedStableRcChecksums"]
                .read_text(encoding="utf-8")
                .splitlines()
            ]
            checksum_names = [
                renamed.name if name == archive.name else name
                for name in checksum_names
            ]
            write_named_checksums(
                paths["selectedStableRcChecksums"],
                [
                    (name, renamed if name == renamed.name else archive.parent / name)
                    for name in checksum_names
                ],
            )
            context.manifest.inputs["selectedStableRcArchive"] = (
                renamed.relative_to(context.workspace_root).as_posix()
            )
            state = ValidationState()

            authenticate_selected_rc(context, state)

            summaries = " ".join(str(row["summary"]) for row in state.blockers)
            self.assertIn(
                "selectedStableRcArchive basename is not canonical",
                summaries,
            )
            self.assertIn("canonical PR-283 artifact set", summaries)

    def test_external_checksum_rows_require_canonical_order(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            context, paths = _write_exact_rc_fixture(Path(directory))
            checksums = paths["selectedStableRcChecksums"]
            rows = checksums.read_text(encoding="utf-8").splitlines()
            checksums.write_text(
                "\n".join(reversed(rows)) + "\n",
                encoding="utf-8",
            )
            state = ValidationState()

            authenticate_selected_rc(context, state)

            summaries = " ".join(str(row["summary"]) for row in state.blockers)
            self.assertIn("not in canonical deterministic order", summaries)

    def test_upgrade_predecessor_must_match_the_exact_pr283_frozen_envelope(self) -> None:
        workspace = workspace_root()
        (workspace / "build").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=workspace / "build") as directory:
            run_context, paths, selected = _authorized_ga_run_context(
                Path(directory),
                workspace,
            )
            state = ValidationState()

            identity = authenticate_upgrade_predecessor(
                run_context,
                selected,
                state,
            )

            self.assertEqual([], state.blockers)
            self.assertEqual(PREVIOUS_RELEASE_ID, identity["releaseId"])
            self.assertEqual(PREVIOUS_BUILD_VERSION, identity["buildVersion"])
            self.assertEqual(
                file_digest(paths["previousCandidate"]),
                identity["previousCandidateDigest"],
            )

            paths["previousCandidate"].write_text(
                paths["previousCandidate"].read_text(encoding="utf-8") + "\n",
                encoding="utf-8",
            )
            rejected = ValidationState()
            authenticate_upgrade_predecessor(run_context, selected, rejected)

            self.assertTrue(rejected.blockers)
            self.assertIn(
                "differ from the exact predecessor frozen by PR-283",
                " ".join(str(row["summary"]) for row in rejected.blockers),
            )

    def test_upgrade_predecessor_must_be_older_and_byte_distinct(self) -> None:
        workspace = workspace_root()
        (workspace / "build").mkdir(exist_ok=True)
        cases = (
            ("same-build", BUILD_VERSION, PREVIOUS_PRODUCT_DIGEST, "must be older"),
            ("newer-build", str(int(BUILD_VERSION) + 1), PREVIOUS_PRODUCT_DIGEST, "must be older"),
            (
                "same-product",
                PREVIOUS_BUILD_VERSION,
                None,
                "identical to the selected Stable GA product",
            ),
        )
        for name, predecessor_build, predecessor_product, expected_error in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory(
                dir=workspace / "build"
            ) as directory:
                run_context, paths, selected = _authorized_ga_run_context(
                    Path(directory),
                    workspace,
                )
                envelope = json.loads(
                    paths["previousCandidate"].read_text(encoding="utf-8")
                )
                envelope["payload"]["legacy"]["version"] = predecessor_build
                write_json(paths["previousCandidate"], envelope)
                predecessor_digest = file_digest(paths["previousCandidate"])
                selected.freeze["candidate"][
                    "previousCandidateDigest"
                ] = predecessor_digest
                selected.provenance["inputs"][
                    "previousCandidate"
                ] = predecessor_digest
                run_context.manifest.policies["expectedPreviousProductDigest"] = (
                    selected.product_digest
                    if predecessor_product is None
                    else predecessor_product
                )
                state = ValidationState()

                authenticate_upgrade_predecessor(run_context, selected, state)

                summaries = " ".join(
                    str(row["summary"]) for row in state.blockers
                )
                self.assertIn(expected_error, summaries)

    def test_selected_rc_payload_is_rescanned_despite_passing_redaction_claim(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            context, paths = _write_exact_rc_fixture(Path(directory))
            summary_path = paths["selectedStableRcSummary"]
            envelope = json.loads(summary_path.read_text(encoding="utf-8"))
            rejected_value = "/home/runner/work/cryptad/raw-support-bundle.json"
            envelope["payload"]["legacy"]["rawSupportBundle"] = rejected_value
            write_json(summary_path, envelope)
            state = ValidationState()

            authenticate_selected_rc(context, state)

            summaries = " ".join(str(row["summary"]) for row in state.blockers)
            self.assertIn("contains redaction findings or placeholders", summaries)
            self.assertNotIn(rejected_value, summaries)

    def test_native_summary_semantics_must_match_the_common_v2_payload(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            context, paths = _write_exact_rc_fixture(Path(directory))
            artifact_root = paths["selectedStableRcFreeze"].parent
            native_path = artifact_root / "stable-1.0-rc-promotion-summary.json"
            native = json.loads(native_path.read_text(encoding="utf-8"))
            native.update(
                {"decision": "no-go", "status": "fail", "promotionReady": False}
            )
            write_json(native_path, native)

            provenance = json.loads(
                paths["selectedStableRcProvenance"].read_text(encoding="utf-8")
            )
            members = provenance["archiveLayout"]["members"]
            product = paths["selectedStableRcProduct"]
            archive_sources = [
                (
                    member,
                    product
                    if member == f"payload/{product.name}"
                    else artifact_root / Path(member).name,
                )
                for member in members
                if member != "payload-checksums.txt"
            ]
            payload_checksums = artifact_root / "payload-checksums.txt"
            write_named_checksums(payload_checksums, archive_sources)
            create_deterministic_archive(
                paths["selectedStableRcArchive"],
                [*archive_sources, ("payload-checksums.txt", payload_checksums)],
            )
            external_names = [
                row.partition("  ")[2]
                for row in paths["selectedStableRcChecksums"]
                .read_text(encoding="utf-8")
                .splitlines()
            ]
            write_named_checksums(
                paths["selectedStableRcChecksums"],
                [(name, artifact_root / name) for name in external_names],
            )
            state = ValidationState()

            authenticate_selected_rc(context, state)

            summaries = " ".join(str(row["summary"]) for row in state.blockers)
            self.assertIn("archive native summary differs from the v2 payload", summaries)

    def test_common_envelope_decision_must_match_its_native_payload(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            context, paths = _write_exact_rc_fixture(Path(directory))
            summary_path = paths["selectedStableRcSummary"]
            envelope = json.loads(summary_path.read_text(encoding="utf-8"))
            envelope["result"]["decision"] = "no-go"
            write_json(summary_path, envelope)
            state = ValidationState()

            authenticate_selected_rc(context, state)

            summaries = " ".join(str(row["summary"]) for row in state.blockers)
            self.assertIn("envelope result and native decision differ", summaries)

    def test_rc_sidecar_archive_product_provenance_and_freeze_mutation_fail_closed(self) -> None:
        def mutate_sidecar(paths: dict[str, Path]) -> None:
            paths["selectedStableRcFreezeSidecar"].write_text(
                f"{'0' * 64}  stable-1.0-rc-freeze.json\n",
                encoding="utf-8",
            )

        def mutate_archive(paths: dict[str, Path]) -> None:
            with paths["selectedStableRcArchive"].open("ab") as stream:
                stream.write(b"substituted")

        def mutate_product(paths: dict[str, Path]) -> None:
            with paths["selectedStableRcProduct"].open("ab") as stream:
                stream.write(b"rebuilt")

        def mutate_provenance(paths: dict[str, Path]) -> None:
            value = json.loads(paths["selectedStableRcProvenance"].read_text(encoding="utf-8"))
            value["source"]["commit"] = "f" * 40
            write_json(paths["selectedStableRcProvenance"], value)

        def mutate_freeze(paths: dict[str, Path]) -> None:
            value = json.loads(paths["selectedStableRcFreeze"].read_text(encoding="utf-8"))
            value["platformApi"]["baselineDigest"] = _digest("f")
            write_json(paths["selectedStableRcFreeze"], value)

        def substitute_standalone_metadata(paths: dict[str, Path]) -> None:
            target = paths["selectedStableRcFreeze"].parent / "platform-api-current-contract.json"
            write_json(target, {"status": "substituted"})
            checksums = paths["selectedStableRcChecksums"]
            rewritten = []
            for row in checksums.read_text(encoding="utf-8").splitlines():
                _digest_value, separator, name = row.partition("  ")
                rewritten.append(
                    f"{file_digest(target).removeprefix('sha256:')}  {name}"
                    if separator and name == target.name
                    else row
                )
            checksums.write_text("\n".join(rewritten) + "\n", encoding="utf-8")

        for name, mutator in {
            "sidecar": mutate_sidecar,
            "archive": mutate_archive,
            "product": mutate_product,
            "provenance": mutate_provenance,
            "freeze": mutate_freeze,
            "metadata-substitution": substitute_standalone_metadata,
        }.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                context, paths = _write_exact_rc_fixture(Path(directory))
                mutator(paths)
                state = ValidationState()

                authenticate_selected_rc(context, state)

                self.assertTrue(state.blockers)

    def test_canonical_engine_emits_deterministic_authorized_exact_byte_bundle(self) -> None:
        workspace = workspace_root()
        (workspace / "build").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=workspace / "build") as directory:
            fixture_root = Path(directory)
            run_context, paths, _selected = _authorized_ga_run_context(
                fixture_root,
                workspace,
            )
            native_output = run_context.component_dir / "artifacts" / "legacy"
            native_output.mkdir(parents=True)

            with mock.patch.object(
                stable_1_0_ga, "_utc_now", return_value=NOW
            ), mock.patch.object(
                stable_1_0_ga_core.socket,
                "getaddrinfo",
                return_value=[(None, None, None, None, ("93.184.216.34", 443))],
            ):
                first_code = stable_1_0_ga._run(  # noqa: SLF001
                    run_context,
                    native_output,
                    ValidationState(),
                )
            first_summary_path = native_output / "stable-1.0-ga-promotion-summary.json"
            first_summary = json.loads(first_summary_path.read_text(encoding="utf-8"))
            first_baseline = json.loads(
                (
                    first_summary_path.parent / "stable-1.0-maintenance-baseline.json"
                ).read_text(encoding="utf-8")
            )
            first_identity = json.loads(
                (
                    first_summary_path.parent
                    / "stable-1.0-ga-validation-authorization-identity.json"
                ).read_text(encoding="utf-8")
            )
            with mock.patch.object(
                stable_1_0_ga, "_utc_now", return_value=NOW
            ), mock.patch.object(
                stable_1_0_ga_core.socket,
                "getaddrinfo",
                return_value=[(None, None, None, None, ("93.184.216.34", 443))],
            ):
                second_code, second_summary_path, _second_report_path = (
                    stable_1_0_ga.run(run_context)
                )
            second_summary = json.loads(second_summary_path.read_text(encoding="utf-8"))
            second_baseline = json.loads(
                (
                    second_summary_path.parent / "stable-1.0-maintenance-baseline.json"
                ).read_text(encoding="utf-8")
            )
            second_identity = json.loads(
                (
                    second_summary_path.parent
                    / "stable-1.0-ga-validation-authorization-identity.json"
                ).read_text(encoding="utf-8")
            )
            second_notes = (
                second_summary_path.parent / "stable-1.0-ga-release-notes.md"
            ).read_text(encoding="utf-8")
            second_plan = json.loads(
                (
                    second_summary_path.parent
                    / "stable-1.0-ga-publication-plan.json"
                ).read_text(encoding="utf-8")
            )

            self.assertEqual(0, first_code)
            self.assertEqual(0, second_code)
            self.assertEqual("pass", second_summary["status"])
            self.assertIs(second_summary["promotionReady"], True)
            self.assertEqual("go", second_summary["decision"])
            self.assertEqual("publication-authorized", second_summary["publicationState"])
            self.assertEqual(
                second_summary["payloadIdentity"]["rcProductDigest"],
                second_summary["payloadIdentity"]["gaProductDigest"],
            )
            self.assertEqual(first_summary, second_summary)
            self.assertEqual(first_baseline, second_baseline)
            self.assertEqual(first_identity, second_identity)
            self.assertEqual(
                second_identity["publicationTargetsDigest"],
                second_plan["publicationTargetsDigest"],
            )
            required_note_sections = (
                "## Milestone and build identity",
                "## Exact release-candidate provenance",
                "## Upgrade, recovery, and backup",
                "## Platform API 1.0 compatibility",
                "## Stable catalog and first-party apps",
                "## Content-format compatibility",
                "## Allowed Stable limitations",
                "## Security and support readiness",
                "## Legacy boundaries",
                "## Checksums and provenance",
                "## Publication status",
                "## Support and security reporting",
            )
            self.assertTrue(
                all(second_notes.count(section) == 1 for section in required_note_sections)
            )
            self.assertNotIn("{{", second_notes)
            self.assertIn("No policy-approved Stable limitation remains open.", second_notes)
            self.assertIn(
                "https://github.com/crypta-network/cryptad/blob/main/docs/SECURITY.md",
                second_notes,
            )
            self.assertEqual(
                paths["selectedStableRcProduct"].read_bytes(),
                (
                    second_summary_path.parent
                    / paths["selectedStableRcProduct"].name
                ).read_bytes(),
            )
            self.assertEqual(
                paths["selectedStableRcArchive"].read_bytes(),
                (
                    second_summary_path.parent
                    / paths["selectedStableRcArchive"].name
                ).read_bytes(),
            )
            checksum_path = (
                second_summary_path.parent / "stable-1.0-ga-checksums.txt"
            )
            checksum_rows = checksum_path.read_text(encoding="utf-8").splitlines()
            checksum_names: list[str] = []
            for row in checksum_rows:
                digest, separator, name = row.partition("  ")
                self.assertEqual("  ", separator)
                checksum_names.append(name)
                self.assertEqual(
                    "sha256:" + digest,
                    file_digest(second_summary_path.parent / name),
                )
            planned_non_checksum_names = {
                str(row["name"])
                for row in second_plan["assets"]
                if row["role"] != "checksums"
            }
            self.assertEqual(6, len(checksum_rows))
            self.assertEqual(len(checksum_names), len(set(checksum_names)))
            self.assertEqual(planned_non_checksum_names, set(checksum_names))
            checksum_asset = next(
                row for row in second_plan["assets"] if row["role"] == "checksums"
            )
            self.assertEqual(file_digest(checksum_path), checksum_asset["digest"])

    def test_records_the_exact_attested_authorization_input_digest(self) -> None:
        workspace = workspace_root()
        (workspace / "build").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=workspace / "build") as directory:
            run_context, _paths, _selected = _authorized_ga_run_context(
                Path(directory),
                workspace,
            )
            authorization_path = configured_input_path(
                run_context,
                "stableGaAuthorization",
            )
            authorization = json.loads(authorization_path.read_text(encoding="utf-8"))
            noncanonical = dict(reversed(list(authorization.items())))
            authorization_path.write_text(
                json.dumps(noncanonical, ensure_ascii=False, separators=(", ", ": "))
                + "\n",
                encoding="utf-8",
            )
            expected_digest = file_digest(authorization_path)
            (run_context.component_dir / "artifacts" / "legacy").mkdir(parents=True)

            with mock.patch.object(
                stable_1_0_ga, "_utc_now", return_value=NOW
            ), mock.patch.object(
                stable_1_0_ga_core.socket,
                "getaddrinfo",
                return_value=[(None, None, None, None, ("93.184.216.34", 443))],
            ):
                code, summary_path, _report_path = stable_1_0_ga.run(run_context)

            validation = json.loads(
                (summary_path.parent / "stable-1.0-ga-validation.json").read_text(
                    encoding="utf-8"
                )
            )
            promotion = json.loads(summary_path.read_text(encoding="utf-8"))
            provenance = json.loads(
                (summary_path.parent / "stable-1.0-ga-provenance.json").read_text(
                    encoding="utf-8"
                )
            )
            summary_digest = file_digest(
                summary_path.parent / "stable-1.0-ga-authorization-summary.json"
            )

            self.assertEqual(0, code)
            self.assertNotEqual(expected_digest, summary_digest)
            self.assertEqual(
                expected_digest,
                validation["authorization"]["authorizationDigest"],
            )
            self.assertEqual(expected_digest, promotion["gaAuthorizationDigest"])
            self.assertEqual(expected_digest, provenance["ga"]["authorizationDigest"])

    def test_failed_ga_run_does_not_retain_rejected_rc_binaries(self) -> None:
        workspace = workspace_root()
        (workspace / "build").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=workspace / "build") as directory:
            run_context, paths, selected = _authorized_ga_run_context(
                Path(directory),
                workspace,
            )
            with paths["selectedStableRcProduct"].open("ab") as stream:
                stream.write(b"rebuilt-after-freeze")
            (run_context.component_dir / "artifacts").mkdir(parents=True)

            with mock.patch.object(
                stable_1_0_ga, "_utc_now", return_value=NOW
            ), mock.patch.object(
                stable_1_0_ga_core.socket,
                "getaddrinfo",
                return_value=[(None, None, None, None, ("93.184.216.34", 443))],
            ):
                code, summary_path, report_path = stable_1_0_ga.run(run_context)

            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            self.assertEqual(1, code)
            self.assertEqual("fail", summary["status"])
            self.assertIs(summary["promotionReady"], False)
            self.assertFalse((summary_path.parent / selected.product_path.name).exists())
            self.assertFalse((summary_path.parent / selected.archive_path.name).exists())
            self.assertTrue(report_path.is_file())
            self.assertTrue((summary_path.parent / "redaction-report.json").is_file())

    def test_repeated_target_failures_emit_schema_valid_no_go_records(self) -> None:
        workspace = workspace_root()
        (workspace / "build").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=workspace / "build") as directory:
            run_context, _paths, selected = _authorized_ga_run_context(
                Path(directory),
                workspace,
            )
            validation_path = configured_input_path(run_context, "stableRcValidation")
            lineage_path = configured_input_path(run_context, "selectedStableRcLineage")
            authorization_path = configured_input_path(
                run_context,
                "stableGaAuthorization",
            )
            validation = json.loads(validation_path.read_text(encoding="utf-8"))
            targets = validation["scenarios"]["installationPackaging"]["targets"]
            for target in targets[:2]:
                target["startedAt"] = _timestamp(NOW - timedelta(days=16))
                target["endedAt"] = _timestamp(NOW - timedelta(days=15))
            write_json(validation_path, validation)
            identity = ga_validation_authorization_identity(
                run_context,
                selected,
                file_digest(lineage_path),
                validation,
                file_digest(validation_path),
                _upgrade_predecessor(selected),
                [],
            )
            write_json(authorization_path, _authorization(selected, identity))
            (run_context.component_dir / "artifacts" / "legacy").mkdir(parents=True)

            with mock.patch.object(
                stable_1_0_ga, "_utc_now", return_value=NOW
            ), mock.patch.object(
                stable_1_0_ga_core.socket,
                "getaddrinfo",
                return_value=[(None, None, None, None, ("93.184.216.34", 443))],
            ):
                code, summary_path, _report_path = stable_1_0_ga.run(run_context)

            promotion = json.loads(summary_path.read_text(encoding="utf-8"))
            ga_validation = json.loads(
                (summary_path.parent / "stable-1.0-ga-validation.json").read_text(
                    encoding="utf-8"
                )
            )
            blocker_rows = [
                json.dumps(row, sort_keys=True, separators=(",", ":"))
                for row in ga_validation["blockers"]
            ]

            self.assertEqual(1, code)
            self.assertEqual("fail", ga_validation["status"])
            self.assertEqual("no-go", ga_validation["decision"])
            self.assertIs(ga_validation["promotionReady"], False)
            self.assertEqual("fail", promotion["status"])
            self.assertEqual("no-go", promotion["decision"])
            self.assertIs(promotion["promotionReady"], False)
            self.assertEqual(len(blocker_rows), len(set(blocker_rows)))
            self.assertEqual([], validate_schema(ga_validation, GA_VALIDATION_SCHEMA))
            self.assertEqual([], validate_schema(promotion, PROMOTION_SCHEMA))
            self.assertFalse(
                any(
                    row["id"]
                    in {
                        "stable-1.0-ga.validation-schema",
                        "stable-1.0-ga.promotion-schema",
                    }
                    for row in ga_validation["blockers"]
                )
            )


class StableGaSchemaAndTemplateTest(unittest.TestCase):
    def test_release_run_schema_matches_the_runtime_stable_ga_contract(self) -> None:
        schema_dir = workspace_root() / "tools/release-certification/schemas"
        schema = json.loads(
            (schema_dir / "release-run-v1.schema.json").read_text(encoding="utf-8")
        )
        properties = schema["properties"]

        self.assertEqual(
            INPUT_FIELDS,
            set(properties["inputs"]["propertyNames"]["enum"]),
        )
        self.assertEqual(
            COMMAND_NAMES,
            set(properties["commands"]["propertyNames"]["enum"]),
        )
        self.assertEqual(
            POLICY_FIELDS,
            set(properties["policies"]["properties"]),
        )
        ga_example = json.loads(
            (
                workspace_root()
                / "tools/release-certification/manifests/stable-1.0-ga.example.json"
            ).read_text(encoding="utf-8")
        )
        rc_example = json.loads(
            (
                workspace_root()
                / "tools/release-certification/manifests/stable-1.0-rc.example.json"
            ).read_text(encoding="utf-8")
        )
        self.assertLessEqual(
            set(ga_example["inputs"]),
            set(properties["inputs"]["propertyNames"]["enum"]),
        )
        self.assertLessEqual(
            set(ga_example["commands"]),
            set(properties["commands"]["propertyNames"]["enum"]),
        )
        self.assertLessEqual(
            set(ga_example["policies"]),
            set(properties["policies"]["properties"]),
        )
        self.assertEqual(
            rc_example["release"]["id"],
            ga_example["release"]["id"],
        )

    def test_all_stable_ga_object_schemas_are_closed(self) -> None:
        schema_dir = workspace_root() / "tools/release-certification/schemas"

        for filename in SCHEMA_FILES:
            with self.subTest(schema=filename):
                value = json.loads((schema_dir / filename).read_text(encoding="utf-8"))

                def assert_closed(node: object, path: str = "$") -> None:
                    if isinstance(node, dict):
                        if node.get("type") == "object":
                            self.assertIs(
                                False,
                                node.get("additionalProperties"),
                                f"{filename}:{path} is not closed",
                            )
                        for key, child in node.items():
                            assert_closed(child, f"{path}.{key}")
                    elif isinstance(node, list):
                        for index, child in enumerate(node):
                            assert_closed(child, f"{path}[{index}]")

                assert_closed(value)

    def test_authorization_schema_rejects_unknown_field(self) -> None:
        selected = _selected_rc()
        context = _context()
        validation = _post_freeze_validation(selected, _policy())
        authorization = _authorization(
            selected,
            _identity_fixture(context, selected, validation),
        )
        self.assertEqual([], validate_schema(authorization, AUTHORIZATION_SCHEMA))

        authorization["unexpected"] = True

        self.assertTrue(validate_schema(authorization, AUTHORIZATION_SCHEMA))

    def test_authorization_schema_uses_ecma_compatible_case_matching(self) -> None:
        schema = json.loads(
            (
                workspace_root()
                / "tools/release-certification/schemas"
                / AUTHORIZATION_SCHEMA
            ).read_text(encoding="utf-8")
        )
        pattern = schema["properties"]["approverIdentity"]["pattern"]
        selected = _selected_rc()
        context = _context()
        validation = _post_freeze_validation(selected, _policy())
        valid = _authorization(
            selected,
            _identity_fixture(context, selected, validation),
        )

        self.assertNotIn("(?i)", pattern)
        self.assertEqual([], validate_schema(valid, AUTHORIZATION_SCHEMA))
        for identity in ("RePlAcE_Me", "PLACEHOLDER", "ExAmPlE", "AnOnYmOuS"):
            with self.subTest(identity=identity):
                authorization = copy.deepcopy(valid)
                authorization["approverIdentity"] = identity

                self.assertTrue(validate_schema(authorization, AUTHORIZATION_SCHEMA))

    def test_limitation_text_is_literal_in_every_public_markdown_report(self) -> None:
        limitation = {
            "id": "limit`[id](https://example.org/id)",
            "title": "[advisory](https://example.org/advisory)",
            "summary": "![pixel](https://example.org/pixel)",
            "boundedBy": "<https://example.org/boundary>",
        }

        release_notes_block = stable_1_0_ga_artifacts._limitations_block(  # noqa: SLF001
            [limitation]
        )
        go_no_go = stable_1_0_ga_artifacts.render_go_no_go(
            {
                "allowedLimitations": [limitation],
                "blockers": [],
            }
        )

        self.assertNotIn("- `", release_notes_block)
        self.assertIn(r"limit\`\[id\]\(https://example.org/id\)", release_notes_block)
        self.assertIn(
            r"\[advisory\]\(https://example.org/advisory\)",
            release_notes_block,
        )
        self.assertIn(
            r"\!\[pixel\]\(https://example.org/pixel\)",
            release_notes_block,
        )
        self.assertIn(r"\<https://example.org/boundary\>", release_notes_block)
        self.assertNotIn("![pixel](", release_notes_block)
        self.assertNotIn("[advisory](", release_notes_block)
        self.assertNotIn("![pixel](", go_no_go)
        self.assertIn(
            r"\!\[pixel\]\(https://example.org/pixel\)",
            go_no_go,
        )

    def test_checked_in_release_note_template_has_exact_contract(self) -> None:
        template = stable_1_0_ga_artifacts._load_template()  # noqa: SLF001

        self.assertTrue(
            template.startswith("<!-- cryptad-stable-ga-release-notes-template:v1 -->\n")
        )
        self.assertEqual(
            stable_1_0_ga_artifacts._TEMPLATE_BLOCKS,  # noqa: SLF001
            tuple(stable_1_0_ga_artifacts._TOKEN_RE.findall(template)),  # noqa: SLF001
        )

    def test_release_note_template_rejects_missing_duplicate_unknown_or_reordered_tokens(
        self,
    ) -> None:
        template = stable_1_0_ga_artifacts._load_template()  # noqa: SLF001
        first = "{{milestone_identity}}"
        second = "{{exact_rc_provenance}}"
        cases = {
            "missing": template.replace(first, "", 1),
            "duplicate": template + first + "\n",
            "unknown": template + "{{unknown_block}}\n",
            "reordered": template.replace(first, "{{swap}}", 1)
            .replace(second, first, 1)
            .replace("{{swap}}", second, 1),
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, value in cases.items():
                with self.subTest(case=name):
                    path = root / f"{name}.md"
                    path.write_text(value, encoding="utf-8")
                    with mock.patch.object(stable_1_0_ga_artifacts, "_TEMPLATE", path):
                        with self.assertRaisesRegex(ValueError, "incomplete or out of order"):
                            stable_1_0_ga_artifacts._load_template()  # noqa: SLF001


class StableGaPostFreezeValidationTest(unittest.TestCase):
    def test_exact_rc_validation_at_86400_seconds_passes(self) -> None:
        selected = _selected_rc()
        policy = _policy()
        value = _post_freeze_validation(selected, policy)
        state = ValidationState()

        validate_post_freeze(
            _context(),
            selected,
            _lineage(selected),
            value,
            _upgrade_predecessor(selected),
            policy,
            _policy_digest(),
            NOW,
            state,
        )

        self.assertEqual([], validate_schema(value, RC_VALIDATION_SCHEMA))
        self.assertEqual(86400, value["scenarios"]["longSoak"]["actualDurationSeconds"])
        self.assertEqual([], state.blockers)

    def test_upgrade_drill_must_match_the_authorized_predecessor(self) -> None:
        selected = _selected_rc()
        policy = _policy()
        value = _post_freeze_validation(selected, policy)
        upgrade = value["scenarios"]["upgradeRollbackStatePreservation"]
        upgrade.update(
            {
                "previousCandidateDigest": _digest("0"),
                "previousReleaseId": "unrelated-release",
                "previousBuildVersion": "99",
                "previousProductDigest": _digest("1"),
            }
        )
        state = ValidationState()

        validate_post_freeze(
            _context(),
            selected,
            _lineage(selected),
            value,
            _upgrade_predecessor(selected),
            policy,
            _policy_digest(),
            NOW,
            state,
        )

        summaries = " ".join(str(row["summary"]) for row in state.blockers)
        self.assertIn("previousCandidateDigest differs", summaries)
        self.assertIn("previousReleaseId differs", summaries)
        self.assertIn("previousBuildVersion differs", summaries)
        self.assertIn("previousProductDigest differs", summaries)

    def test_post_freeze_validation_rejects_pre_freeze_or_short_scenario_intervals(
        self,
    ) -> None:
        selected = _selected_rc()
        policy = _policy()
        lineage = _lineage(selected)
        valid = _post_freeze_validation(selected, policy)
        freeze_completed = datetime.fromisoformat(
            str(lineage["generatedAt"]).replace("Z", "+00:00")
        )
        cases = {
            "top-level-start-before-freeze": (
                "validationStartedAt",
                _timestamp(freeze_completed - timedelta(seconds=1)),
                "before the selected protected freeze completed",
            ),
            "scenario-start-before-freeze": (
                "scenarios.liveNetwork.startedAt",
                _timestamp(freeze_completed - timedelta(seconds=1)),
                "scenario liveNetwork has an invalid time window",
            ),
            "claimed-day-over-seconds": (
                "scenarios.longSoak.endedAt",
                _timestamp(
                    datetime.fromisoformat(
                        str(valid["scenarios"]["longSoak"]["startedAt"]).replace(
                            "Z", "+00:00"
                        )
                    )
                    + timedelta(seconds=5)
                ),
                "long-soak interval is shorter",
            ),
        }
        for name, (path, replacement, expected_error) in cases.items():
            with self.subTest(case=name):
                value = copy.deepcopy(valid)
                target: dict[str, object] = value
                parts = path.split(".")
                for part in parts[:-1]:
                    child = target[part]
                    assert isinstance(child, dict)
                    target = child
                target[parts[-1]] = replacement
                state = ValidationState()

                validate_post_freeze(
                    _context(),
                    selected,
                    lineage,
                    value,
                    _upgrade_predecessor(selected),
                    policy,
                    _policy_digest(),
                    NOW,
                    state,
                )

                self.assertEqual([], validate_schema(value, RC_VALIDATION_SCHEMA))
                self.assertTrue(
                    any(
                        expected_error in str(blocker["summary"])
                        for blocker in state.blockers
                    ),
                    state.blockers,
                )

    def test_post_freeze_validation_rejects_wrong_candidate_or_nested_binding(self) -> None:
        selected = _selected_rc()
        policy = _policy()
        valid = _post_freeze_validation(selected, policy)
        cases = {
            "top-level-product": ("productDistributionDigest", _digest("0")),
            "nested-product": (
                "scenarios.liveNetwork.binding.productDistributionDigest",
                _digest("0"),
            ),
            "catalog-revision": ("stableCatalog.revision", 8),
        }
        for name, (path, replacement) in cases.items():
            with self.subTest(case=name):
                value = copy.deepcopy(valid)
                target: dict[str, object] = value
                parts = path.split(".")
                for part in parts[:-1]:
                    child = target[part]
                    assert isinstance(child, dict)
                    target = child
                target[parts[-1]] = replacement
                state = ValidationState()

                validate_post_freeze(
                    _context(),
                    selected,
                    _lineage(selected),
                    value,
                    _upgrade_predecessor(selected),
                    policy,
                    _policy_digest(),
                    NOW,
                    state,
                )

                self.assertTrue(state.blockers)

    def test_post_freeze_validation_rejects_short_stale_or_nonproduction_evidence(self) -> None:
        selected = _selected_rc()
        policy = _policy()
        valid = _post_freeze_validation(selected, policy)
        cases: dict[str, tuple[str, object]] = {
            "short-soak": ("scenarios.longSoak.actualDurationSeconds", 86399),
            "fixture": ("fixtureOnly", True),
            "simulated-sandbox": ("scenarios.sandboxProvider.simulatedOnly", True),
            "failed-backup": (
                "scenarios.upgradeRollbackStatePreservation.backupRestore",
                "fail",
            ),
            "failed-security-drill": (
                "scenarios.securityResponse.mandatoryDrills",
                "fail",
            ),
        }
        for name, (path, replacement) in cases.items():
            with self.subTest(case=name):
                value = copy.deepcopy(valid)
                target: dict[str, object] = value
                parts = path.split(".")
                for part in parts[:-1]:
                    child = target[part]
                    assert isinstance(child, dict)
                    target = child
                target[parts[-1]] = replacement
                state = ValidationState()

                validate_post_freeze(
                    _context(),
                    selected,
                    _lineage(selected),
                    value,
                    _upgrade_predecessor(selected),
                    policy,
                    _policy_digest(),
                    NOW,
                    state,
                )

                self.assertTrue(state.blockers)

        stale = copy.deepcopy(valid)
        stale["generatedAt"] = _timestamp(NOW - timedelta(days=15))
        stale["validationEndedAt"] = _timestamp(NOW - timedelta(days=15, hours=1))
        stale["validationStartedAt"] = _timestamp(NOW - timedelta(days=16, hours=1))
        state = ValidationState()

        validate_post_freeze(
            _context(),
            selected,
            _lineage(selected),
            stale,
            _upgrade_predecessor(selected),
            policy,
            _policy_digest(),
            NOW,
            state,
        )

        self.assertTrue(
            any("stale" in blocker["summary"] for blocker in state.blockers),
            state.blockers,
        )

    def test_scenario_freshness_is_measured_from_promotion_time(self) -> None:
        selected = _selected_rc()
        policy = _policy()
        value = _post_freeze_validation(selected, policy)
        scenario_started = NOW - timedelta(days=16)
        scenario_ended = NOW - timedelta(days=15)
        value["validationStartedAt"] = _timestamp(scenario_started)
        value["validationEndedAt"] = _timestamp(NOW - timedelta(days=13, hours=1))
        value["generatedAt"] = _timestamp(NOW - timedelta(days=13))
        scenarios = value["scenarios"]
        for scenario_id, scenario in scenarios.items():
            evidence_rows = (
                scenario["targets"]
                if scenario_id == "installationPackaging"
                else [scenario]
            )
            for evidence_row in evidence_rows:
                evidence_row["startedAt"] = _timestamp(scenario_started)
                evidence_row["endedAt"] = _timestamp(scenario_ended)
        lineage = _lineage(selected)
        lineage["generatedAt"] = _timestamp(scenario_started - timedelta(days=1))
        state = ValidationState()

        validate_post_freeze(
            _context(),
            selected,
            lineage,
            value,
            _upgrade_predecessor(selected),
            policy,
            _policy_digest(),
            NOW,
            state,
        )

        self.assertEqual([], validate_schema(value, RC_VALIDATION_SCHEMA))
        self.assertTrue(
            any(
                "scenario liveNetwork is stale under policy" in blocker["summary"]
                for blocker in state.blockers
            ),
            state.blockers,
        )

    def test_post_freeze_validation_rejects_missing_installation_target(self) -> None:
        selected = _selected_rc()
        policy = _policy()
        value = _post_freeze_validation(selected, policy)
        installation = value["scenarios"]["installationPackaging"]
        installation["targets"] = []
        installation["requiredTargetCount"] = 0
        installation["validatedTargetCount"] = 0
        state = ValidationState()

        validate_post_freeze(
            _context(),
            selected,
            _lineage(selected),
            value,
            _upgrade_predecessor(selected),
            policy,
            _policy_digest(),
            NOW,
            state,
        )

        self.assertTrue(state.blockers)

    def test_repeated_installation_target_windows_are_deduplicated(self) -> None:
        selected = _selected_rc()
        policy = _policy()
        value = _post_freeze_validation(selected, policy)
        targets = value["scenarios"]["installationPackaging"]["targets"]
        for target in targets[:2]:
            target["startedAt"] = _timestamp(NOW - timedelta(days=16))
            target["endedAt"] = _timestamp(NOW - timedelta(days=15))
        state = ValidationState()

        validate_post_freeze(
            _context(),
            selected,
            _lineage(selected),
            value,
            _upgrade_predecessor(selected),
            policy,
            _policy_digest(),
            NOW,
            state,
        )

        blocker_rows = [
            json.dumps(row, sort_keys=True, separators=(",", ":"))
            for row in state.blockers
        ]
        summaries = [str(row["summary"]) for row in state.blockers]
        self.assertEqual(len(blocker_rows), len(set(blocker_rows)))
        self.assertEqual(
            1,
            sum(
                "scenario installationPackaging has an invalid time window" in row
                for row in summaries
            ),
        )
        self.assertEqual(
            1,
            sum(
                "scenario installationPackaging is stale under policy" in row
                for row in summaries
            ),
        )


class StableGaLineageAndAuthorizationTest(unittest.TestCase):
    def test_lineage_accepts_exact_latest_successful_freeze(self) -> None:
        selected = _selected_rc()
        lineage = _lineage(selected)
        state = ValidationState()

        validate_lineage(_context(), selected, lineage, state)

        self.assertEqual([], validate_schema(lineage, LINEAGE_SCHEMA))
        self.assertEqual([], state.blockers)

    def test_lineage_rejects_stale_selected_freeze_and_changed_exception_history(self) -> None:
        selected = _selected_rc()
        lineage = _lineage(selected)
        latest = copy.deepcopy(lineage["latestSuccessfulFreeze"])
        latest["freezeDigest"] = _digest("0")
        latest["freezeFileDigest"] = _digest("f")
        lineage["latestSuccessfulFreeze"] = latest
        lineage["history"].append(
            {
                "ordinal": 2,
                "freezeMode": "refreeze",
                "successful": True,
                **copy.deepcopy(latest),
            }
        )
        lineage["acceptedFreezeExceptionHistoryDigest"] = _digest("e")
        state = ValidationState()

        validate_lineage(_context(), selected, lineage, state)

        self.assertTrue(state.blockers)
        summaries = " ".join(blocker["summary"] for blocker in state.blockers)
        self.assertIn("latest", summaries)
        self.assertIn("exception", summaries)

    def test_refreeze_lineage_requires_exact_prior_freeze_comparison_binding(self) -> None:
        selected = _selected_rc()
        selected.provenance["freezeMode"] = "refreeze"
        selected.provenance["comparisonBaseline"] = None
        lineage = _lineage(selected)
        lineage["history"][0]["freezeMode"] = "refreeze"
        state = ValidationState()

        validate_lineage(_context(), selected, lineage, state)

        self.assertTrue(state.blockers)
        selected.provenance["comparisonBaseline"] = {
            "fileDigest": _digest("d"),
            "contentDigest": _digest("e"),
        }
        passing_state = ValidationState()
        validate_lineage(_context(), selected, lineage, passing_state)
        self.assertEqual([], passing_state.blockers)

    def test_authorization_accepts_exact_identity_digest_time_role_and_scope(self) -> None:
        selected = _selected_rc()
        context = _context()
        policy = _policy()
        validation = _post_freeze_validation(selected, policy)
        identity = _identity_fixture(context, selected, validation)
        authorization = _authorization(selected, identity)
        state = ValidationState()

        validate_authorization(
            context,
            selected,
            identity,
            authorization,
            policy,
            NOW,
            state,
        )

        self.assertEqual([], validate_schema(authorization, AUTHORIZATION_SCHEMA))
        self.assertEqual([], state.blockers)

    def test_authorization_rejects_wrong_candidate_or_validation_digest(self) -> None:
        selected = _selected_rc()
        context = _context()
        policy = _policy()
        validation = _post_freeze_validation(selected, policy)
        identity = _identity_fixture(context, selected, validation)
        valid = _authorization(selected, identity)
        cases = {
            "source-commit": ("sourceCommit", "b" * 40),
            "product-digest": ("productDistributionDigest", _digest("0")),
            "validation-digest": ("gaValidationDigest", _digest("0")),
            "publication-targets-digest": (
                "publicationTargetsDigest",
                _digest("0"),
            ),
        }
        for name, (field, replacement) in cases.items():
            with self.subTest(case=name):
                authorization = copy.deepcopy(valid)
                authorization[field] = replacement
                state = ValidationState()

                validate_authorization(
                    context,
                    selected,
                    identity,
                    authorization,
                    policy,
                    NOW,
                    state,
                )

                self.assertTrue(state.blockers)

    def test_authorization_rejects_role_approver_expiration_and_scope(self) -> None:
        selected = _selected_rc()
        context = _context()
        policy = _policy()
        validation = _post_freeze_validation(selected, policy)
        identity = _identity_fixture(context, selected, validation)
        valid = _authorization(selected, identity)
        cases: dict[str, tuple[str, object]] = {
            "role": ("authorizationRole", "release-operator"),
            "placeholder": ("approverIdentity", "release-manager"),
            "padded-placeholder": ("approverIdentity", " Approver "),
            "expired": ("expiresAt", _timestamp(NOW - timedelta(seconds=1))),
            "wildcard": ("allowedPublicationScope", ["*"]),
            "reordered": ("allowedPublicationScope", list(reversed(AUTHORIZATION_SCOPE))),
        }
        for name, (field, replacement) in cases.items():
            with self.subTest(case=name):
                authorization = copy.deepcopy(valid)
                authorization[field] = replacement
                state = ValidationState()

                validate_authorization(
                    context,
                    selected,
                    identity,
                    authorization,
                    policy,
                    NOW,
                    state,
                )

                self.assertTrue(state.blockers)

    def test_authorization_rejects_changed_publication_destinations(self) -> None:
        selected = _selected_rc()
        policy = _policy()
        validation = _post_freeze_validation(selected, policy)
        authorized_context = _context()
        identity = _identity_fixture(authorized_context, selected, validation)
        authorization = _authorization(selected, identity)
        mutations = {
            "artifact-base": (
                "artifactBaseUri",
                "https://other-downloads.crypta.network/stable/",
            ),
            "catalog-primary": (
                "catalogPrimaryUri",
                "https://other-catalog.crypta.network/first-party-catalog.properties",
            ),
            "catalog-mirrors": (
                "catalogMirrorUris",
                (
                    "https://mirror-2.crypta.network/first-party-catalog.properties,"
                    "https://mirror.crypta.network/first-party-catalog.properties"
                ),
            ),
            "catalog-rollback": (
                "catalogRollbackUri",
                "https://other-catalog.crypta.network/history/6/first-party-catalog.properties",
            ),
        }
        for name, (field, replacement) in mutations.items():
            with self.subTest(case=name):
                changed_context = _context()
                if field == "artifactBaseUri":
                    changed_context.manifest.policies[field] = replacement
                else:
                    changed_context.manifest.policies["metadata"][field] = replacement
                changed_identity = _identity_fixture(
                    changed_context,
                    selected,
                    validation,
                )
                state = ValidationState()

                validate_authorization(
                    changed_context,
                    selected,
                    changed_identity,
                    authorization,
                    policy,
                    NOW,
                    state,
                )

                self.assertNotEqual(
                    identity["publicationTargetsDigest"],
                    changed_identity["publicationTargetsDigest"],
                )
                self.assertTrue(state.blockers)

    def test_authorization_public_labels_do_not_allow_malicious_values(self) -> None:
        selected = _selected_rc()
        context = _context()
        policy = _policy()
        validation = _post_freeze_validation(selected, policy)
        identity = _identity_fixture(context, selected, validation)
        authorization = _authorization(selected, identity)
        secret = "Authorization: Bearer abcdefghijklmnop"
        authorization["approverIdentity"] = secret
        state = ValidationState()

        validate_authorization(
            context,
            selected,
            identity,
            authorization,
            policy,
            NOW,
            state,
        )

        self.assertTrue(state.blockers)
        self.assertNotIn(secret, " ".join(row["summary"] for row in state.blockers))

    def test_only_policy_allowlisted_rc_waiver_can_carry_to_ga(self) -> None:
        selected = _selected_rc()
        waiver_id = "stable-support-limitation-284"
        selected.summary["acceptedWaivers"] = [
            {
                "id": waiver_id,
                "active": True,
                "validationErrors": [],
                "usedBy": ["stable-support-documentation"],
                "scope": "Document one bounded non-security support limitation.",
                "expiresAt": _timestamp(NOW + timedelta(days=1)),
            }
        ]
        policy = _policy()
        policy["allowedRcWaiverIds"] = [waiver_id]
        state = ValidationState()

        carried = validate_carried_waivers(selected, policy, NOW, state)

        self.assertEqual([], state.blockers)
        self.assertEqual([waiver_id], [row["id"] for row in carried])
        self.assertIs(carried[0]["stableGaAllowed"], True)
        promotion = stable_1_0_ga._promotion_record(  # noqa: SLF001
            _context(),
            selected,
            _digest("1"),
            _digest("2"),
            _digest("3"),
            carried,
            {"allowedLimitations": []},
            _digest("4"),
            _digest("5"),
            [],
            "publication-authorized",
            True,
            ValidationState(),
            _timestamp(NOW),
        )
        self.assertEqual("go-with-waivers", promotion["decision"])
        self.assertIs(promotion["promotionReady"], True)

        selected.summary["acceptedWaivers"][0]["usedBy"] = [
            "stable-ga.archive-integrity"
        ]
        blocked_state = ValidationState()
        blocked_carried = validate_carried_waivers(
            selected,
            policy,
            NOW,
            blocked_state,
        )
        self.assertTrue(blocked_state.blockers)
        self.assertEqual([], blocked_carried)

        policy["allowedRcWaiverIds"] = []
        unlisted_state = ValidationState()
        unlisted_carried = validate_carried_waivers(
            selected,
            policy,
            NOW,
            unlisted_state,
        )
        self.assertTrue(unlisted_state.blockers)
        self.assertEqual([], unlisted_carried)

    def test_rejected_rc_waivers_are_absent_from_ga_audit_records(self) -> None:
        waiver_id = "stable-support-limitation-284"
        valid_row = {
            "id": waiver_id,
            "active": True,
            "validationErrors": [],
            "usedBy": ["stable-support-documentation"],
            "scope": "Document one bounded non-security support limitation.",
            "expiresAt": _timestamp(NOW + timedelta(days=1)),
        }
        cases = {
            "not-allowlisted": ({}, []),
            "expired": (
                {"expiresAt": _timestamp(NOW - timedelta(seconds=1))},
                [waiver_id],
            ),
            "inactive": ({"active": False}, [waiver_id]),
            "non-waivable": (
                {"usedBy": ["stable-ga.archive-integrity"]},
                [waiver_id],
            ),
        }

        for name, (changes, allowed_ids) in cases.items():
            with self.subTest(name=name):
                selected = _selected_rc()
                selected.summary["acceptedWaivers"] = [
                    {**valid_row, **changes}
                ]
                policy = _policy()
                policy["allowedRcWaiverIds"] = allowed_ids
                state = ValidationState()

                carried = validate_carried_waivers(
                    selected,
                    policy,
                    NOW,
                    state,
                )
                identity = ga_validation_authorization_identity(
                    _context(),
                    selected,
                    _digest("1"),
                    _post_freeze_validation(selected, policy),
                    _digest("2"),
                    _upgrade_predecessor(selected),
                    carried,
                )
                validation = build_ga_validation_record(
                    _context(),
                    selected,
                    _digest("1"),
                    _post_freeze_validation(selected, policy),
                    _digest("2"),
                    _upgrade_predecessor(selected),
                    None,
                    _digest("3"),
                    False,
                    carried,
                    state,
                )

                self.assertTrue(state.blockers)
                self.assertEqual([], carried)
                self.assertEqual([], identity["acceptedRcWaivers"])
                self.assertEqual([], validation["acceptedRcWaivers"])


class StableGaPublicationReceiptTest(unittest.TestCase):
    def test_post_publication_verifier_failure_receipt_is_schema_valid(self) -> None:
        selected = _selected_rc()
        receipt = _receipt(
            selected,
            _digest("c"),
            _digest("d"),
            _planned_assets(),
        )
        receipt.update(
            {
                "publicationState": "publication-verification-failed",
                "operation": "partial",
                "failureCategory": "post-publication-verification-failure",
                "finalVerificationStatus": "fail",
            }
        )

        self.assertEqual([], validate_schema(receipt, PUBLICATION_RECEIPT_SCHEMA))

    def test_matching_created_or_existing_publication_is_idempotent(self) -> None:
        selected = _selected_rc()
        promotion_digest = _digest("c")
        release_notes_digest = _digest("d")
        planned_assets = _planned_assets()
        for operation in ("created", "verified-existing"):
            with self.subTest(operation=operation):
                receipt = _receipt(
                    selected,
                    promotion_digest,
                    release_notes_digest,
                    planned_assets,
                    operation=operation,
                )

                errors = publication_receipt_errors(
                    receipt,
                    _context(),
                    selected,
                    _lineage(selected),
                    promotion_digest,
                    release_notes_digest,
                    planned_assets,
                )

                self.assertEqual([], validate_schema(receipt, PUBLICATION_RECEIPT_SCHEMA))
                self.assertEqual([], errors)

    def test_receipt_rejects_duplicate_mirror_uri_under_another_id(self) -> None:
        selected = _selected_rc()
        promotion_digest = _digest("c")
        release_notes_digest = _digest("d")
        planned_assets = _planned_assets()
        receipt = _receipt(
            selected,
            promotion_digest,
            release_notes_digest,
            planned_assets,
        )
        duplicate = copy.deepcopy(receipt["catalog"]["mirrors"][0])
        duplicate["locationId"] = "mirror-2"
        receipt["catalog"]["mirrors"].append(duplicate)

        errors = publication_receipt_errors(
            receipt,
            _context(),
            selected,
            _lineage(selected),
            promotion_digest,
            release_notes_digest,
            planned_assets,
        )

        self.assertEqual([], validate_schema(receipt, PUBLICATION_RECEIPT_SCHEMA))
        self.assertTrue(errors)

    def test_receipt_requires_exact_ordered_mirror_id_and_uri_pairs(self) -> None:
        selected = _selected_rc()
        promotion_digest = _digest("c")
        release_notes_digest = _digest("d")
        planned_assets = _planned_assets()
        context = _context()
        second_uri = (
            "https://mirror-2.crypta.network/first-party-catalog.properties"
        )
        context.manifest.policies["metadata"]["catalogMirrorUris"] = (
            "https://mirror.crypta.network/first-party-catalog.properties,"
            + second_uri
        )
        receipt = _receipt(
            selected,
            promotion_digest,
            release_notes_digest,
            planned_assets,
        )
        second = copy.deepcopy(receipt["catalog"]["mirrors"][0])
        second["locationId"] = "mirror-2"
        second["publicUri"] = second_uri
        receipt["catalog"]["mirrors"].append(second)

        exact_errors = publication_receipt_errors(
            receipt,
            context,
            selected,
            _lineage(selected),
            promotion_digest,
            release_notes_digest,
            planned_assets,
        )
        reordered = copy.deepcopy(receipt)
        reordered["catalog"]["mirrors"].reverse()
        reordered_errors = publication_receipt_errors(
            reordered,
            context,
            selected,
            _lineage(selected),
            promotion_digest,
            release_notes_digest,
            planned_assets,
        )
        wrong_id = copy.deepcopy(receipt)
        wrong_id["catalog"]["mirrors"][1]["locationId"] = "mirror-3"
        wrong_id_errors = publication_receipt_errors(
            wrong_id,
            context,
            selected,
            _lineage(selected),
            promotion_digest,
            release_notes_digest,
            planned_assets,
        )

        self.assertEqual([], exact_errors)
        self.assertTrue(reordered_errors)
        self.assertTrue(wrong_id_errors)

    def test_receipt_uses_the_publication_plan_canonical_artifact_base(self) -> None:
        selected = _selected_rc()
        promotion_digest = _digest("c")
        release_notes_digest = _digest("d")
        planned_assets = _planned_assets()
        receipt = _receipt(
            selected,
            promotion_digest,
            release_notes_digest,
            planned_assets,
        )
        for raw_base in (
            "https://downloads.crypta.network/stable",
            "https://downloads.crypta.network/stable/",
        ):
            with self.subTest(raw_base=raw_base):
                context = _context()
                context.manifest.policies["artifactBaseUri"] = raw_base
                plan = stable_1_0_ga._publication_plan(
                    context,
                    selected,
                    {
                        "primary": {},
                        "mirrors": [],
                        "rollback": {
                            "publicUri": context.manifest.policies[
                                "metadata"
                            ]["catalogRollbackUri"]
                        },
                    },
                    promotion_digest,
                    release_notes_digest,
                    _timestamp(NOW),
                    planned_assets,
                    "publication-authorized",
                )

                errors = publication_receipt_errors(
                    receipt,
                    context,
                    selected,
                    _lineage(selected),
                    promotion_digest,
                    release_notes_digest,
                    planned_assets,
                )

                self.assertEqual(
                    "https://downloads.crypta.network/stable/",
                    canonical_artifact_base_uri(raw_base),
                )
                self.assertEqual(
                    canonical_artifact_base_uri(raw_base),
                    plan["artifactBaseUri"],
                )
                self.assertEqual([], errors)

    def test_artifact_base_rejects_ambiguous_paths(self) -> None:
        for path in (
            "/staging/../stable/",
            "/stable///",
            "/%73table/",
            "/stable\\release/",
        ):
            with self.subTest(path=path):
                self.assertFalse(
                    is_supported_artifact_base_uri(f"https://9.9.9.9{path}")
                )
                self.assertFalse(
                    stable_1_0_ga._safe_https(  # noqa: SLF001
                        f"https://9.9.9.9{path}"
                    )
                )
                context = _context()
                context.manifest.policies["artifactBaseUri"] = (
                    f"https://9.9.9.9{path}"
                )
                selected = _selected_rc()
                planned_assets = _planned_assets()
                errors = publication_receipt_errors(
                    _receipt(
                        selected,
                        _digest("c"),
                        _digest("d"),
                        planned_assets,
                    ),
                    context,
                    selected,
                    _lineage(selected),
                    _digest("c"),
                    _digest("d"),
                    planned_assets,
                )
                self.assertIn(
                    "publication receipt artifact base URI path is ambiguous",
                    errors,
                )

    def test_receipt_requires_the_actual_protected_environment_name(self) -> None:
        selected = _selected_rc()
        receipt = _receipt(
            selected,
            _digest("c"),
            _digest("d"),
            _planned_assets(),
        )

        self.assertEqual([], validate_schema(receipt, PUBLICATION_RECEIPT_SCHEMA))

        receipt["workflow"]["environment"] = "stable-1.0-ga"
        self.assertTrue(validate_schema(receipt, PUBLICATION_RECEIPT_SCHEMA))

    def test_failure_receipt_can_truthfully_record_an_absent_github_release(self) -> None:
        receipt = _receipt(
            _selected_rc(),
            _digest("c"),
            _digest("d"),
            _planned_assets(),
        )
        receipt.update(
            {
                "publicationState": "publication-verification-failed",
                "operation": "partial",
                "failureCategory": "pre-publication-verification-failure",
                "githubRelease": None,
                "publishedAt": None,
                "finalVerificationStatus": "fail",
            }
        )
        receipt["catalog"]["rollback"]["signatureDigest"] = None
        receipt["publicStateObservation"].update(
            {
                "tag": {"status": "absent"},
                "githubRelease": {"status": "absent"},
                "releaseAssets": {
                    "status": "not-applicable",
                    "observedCount": None,
                    "missingPlannedAssets": [],
                    "unexpectedCount": None,
                    "unexpectedNameDigests": [],
                },
            }
        )

        errors = validate_schema(receipt, PUBLICATION_RECEIPT_SCHEMA)

        self.assertEqual([], errors)

    def test_public_asset_observation_hashes_untrusted_names(self) -> None:
        hostile_names = [
            "../../private.key",
            "Authorization bearer-not-a-real-token",
            "token-shaped-but-safe-name.txt",
            "raw-support-bundle.zip",
            "e\N{COMBINING ACUTE ACCENT}vidence.json",
        ]
        observed = [{"name": _planned_assets()[0]["name"]}]
        observed.extend({"name": name} for name in hostile_names)

        result = sanitized_public_asset_observation(observed, _planned_assets())

        serialized = json.dumps(result, sort_keys=True)
        self.assertEqual("observed", result["status"])
        self.assertEqual(len(observed), result["observedCount"])
        self.assertEqual(len(_planned_assets()) - 1, len(result["missingPlannedAssets"]))
        self.assertEqual(len(hostile_names), result["unexpectedCount"])
        self.assertEqual(
            sorted(
                "sha256:" + hashlib.sha256(name.encode("utf-8")).hexdigest()
                for name in hostile_names
            ),
            result["unexpectedNameDigests"],
        )
        self.assertEqual([], scan_value(result))
        for name in hostile_names:
            self.assertNotIn(name, serialized)

        receipt = _receipt(
            _selected_rc(),
            _digest("c"),
            _digest("d"),
            _planned_assets(),
        )
        receipt.update(
            {
                "publicationState": "publication-verification-failed",
                "operation": "partial",
                "failureCategory": "pre-publication-verification-failure",
                "finalVerificationStatus": "fail",
            }
        )
        receipt["publicStateObservation"]["releaseAssets"] = result
        self.assertEqual([], validate_schema(receipt, PUBLICATION_RECEIPT_SCHEMA))
        self.assertEqual([], scan_value(receipt))
        receipt_text = json.dumps(receipt, sort_keys=True)
        for name in hostile_names:
            self.assertNotIn(name, receipt_text)

    def test_failure_receipt_records_unavailable_observation_without_claiming_absence(
        self,
    ) -> None:
        receipt = _receipt(
            _selected_rc(),
            _digest("c"),
            _digest("d"),
            _planned_assets(),
        )
        receipt.update(
            {
                "publicationState": "publication-verification-failed",
                "operation": "partial",
                "failureCategory": "pre-publication-verification-failure",
                "githubRelease": None,
                "publishedAt": None,
                "finalVerificationStatus": "fail",
            }
        )
        receipt["catalog"]["rollback"]["signatureDigest"] = None
        receipt["publicStateObservation"] = {
            "tag": {"status": "unavailable"},
            "githubRelease": {"status": "unavailable"},
            "releaseAssets": {
                "status": "unavailable",
                "observedCount": None,
                "missingPlannedAssets": [],
                "unexpectedCount": None,
                "unexpectedNameDigests": [],
            },
        }

        self.assertEqual([], validate_schema(receipt, PUBLICATION_RECEIPT_SCHEMA))
        self.assertEqual([], scan_value(receipt))

    def test_completed_receipt_requires_verified_public_observations(self) -> None:
        receipt = _receipt(
            _selected_rc(),
            _digest("c"),
            _digest("d"),
            _planned_assets(),
        )

        receipt["publicStateObservation"]["githubRelease"]["status"] = "unavailable"

        self.assertTrue(validate_schema(receipt, PUBLICATION_RECEIPT_SCHEMA))

    def test_receipt_rejects_tag_asset_release_or_catalog_conflicts(self) -> None:
        selected = _selected_rc()
        promotion_digest = _digest("c")
        release_notes_digest = _digest("d")
        planned_assets = _planned_assets()
        valid = _receipt(
            selected,
            promotion_digest,
            release_notes_digest,
            planned_assets,
        )

        def change_tag(receipt: dict[str, object]) -> None:
            receipt["tag"]["targetCommit"] = "b" * 40

        def change_asset(receipt: dict[str, object]) -> None:
            receipt["assets"][0]["digest"] = _digest("f")

        def omit_asset(receipt: dict[str, object]) -> None:
            receipt["assets"].pop()

        def add_unexpected_asset(receipt: dict[str, object]) -> None:
            receipt["publicStateObservation"]["releaseAssets"].update(
                {
                    "observedCount": len(planned_assets) + 1,
                    "unexpectedCount": 1,
                    "unexpectedNameDigests": [_digest("f")],
                }
            )

        def change_artifact_base(receipt: dict[str, object]) -> None:
            receipt["artifactBaseUri"] = "https://other.crypta.network/stable/"

        def change_asset_public_uri(receipt: dict[str, object]) -> None:
            receipt["assets"][0]["publicUri"] = (
                "https://other.crypta.network/stable/"
                + receipt["assets"][0]["name"]
            )

        def change_release_notes(receipt: dict[str, object]) -> None:
            receipt["githubRelease"]["releaseNotesDigest"] = _digest("f")

        def change_release_url_repository(receipt: dict[str, object]) -> None:
            receipt["githubRelease"]["publicUrl"] = (
                "https://github.com/other/repository/releases/tag/v284"
            )

        def change_release_url_tag(receipt: dict[str, object]) -> None:
            receipt["githubRelease"]["publicUrl"] = (
                "https://github.com/crypta-network/cryptad/releases/tag/v999"
            )

        def change_workflow_repository(receipt: dict[str, object]) -> None:
            receipt["workflow"]["repository"] = "other/repository"

        def change_primary_catalog(receipt: dict[str, object]) -> None:
            receipt["catalog"]["primary"]["digest"] = _digest("f")

        def change_mirror_catalog(receipt: dict[str, object]) -> None:
            receipt["catalog"]["mirrors"][0]["signatureVerified"] = False

        def make_operation_partial(receipt: dict[str, object]) -> None:
            receipt["operation"] = "partial"

        def add_failure_category(receipt: dict[str, object]) -> None:
            receipt["failureCategory"] = "pre-publication-verification-failure"

        def change_primary_location(receipt: dict[str, object]) -> None:
            receipt["catalog"]["primary"]["publicUri"] = (
                "https://other.crypta.network/first-party-catalog.properties"
            )

        def change_rollback(receipt: dict[str, object]) -> None:
            receipt["catalog"]["rollback"]["digest"] = _digest("f")

        def change_rollback_uri(receipt: dict[str, object]) -> None:
            receipt["catalog"]["rollback"]["publicUri"] = (
                "https://other.crypta.network/history/6/first-party-catalog.properties"
            )

        def change_rollback_signature(receipt: dict[str, object]) -> None:
            receipt["catalog"]["rollback"]["signatureVerified"] = False

        def change_rollback_signer(receipt: dict[str, object]) -> None:
            receipt["catalog"]["rollback"]["signingKeyId"] = "unknown-catalog-key"

        def change_catalog_timestamp(receipt: dict[str, object]) -> None:
            receipt["catalog"]["artifactTimestamp"] = "2026-01-02T00:00:00Z"

        mutations = {
            "tag": change_tag,
            "changed-asset": change_asset,
            "missing-asset": omit_asset,
            "unexpected-asset": add_unexpected_asset,
            "artifact-base": change_artifact_base,
            "asset-public-uri": change_asset_public_uri,
            "release-notes": change_release_notes,
            "release-url-repository": change_release_url_repository,
            "release-url-tag": change_release_url_tag,
            "workflow-repository": change_workflow_repository,
            "primary-catalog": change_primary_catalog,
            "mirror-catalog": change_mirror_catalog,
            "partial-operation": make_operation_partial,
            "contradictory-failure-category": add_failure_category,
            "primary-location": change_primary_location,
            "rollback": change_rollback,
            "rollback-uri": change_rollback_uri,
            "rollback-signature": change_rollback_signature,
            "rollback-signer": change_rollback_signer,
            "catalog-timestamp": change_catalog_timestamp,
        }
        for name, mutate in mutations.items():
            with self.subTest(case=name):
                receipt = copy.deepcopy(valid)
                mutate(receipt)

                errors = publication_receipt_errors(
                    receipt,
                    _context(),
                    selected,
                    _lineage(selected),
                    promotion_digest,
                    release_notes_digest,
                    planned_assets,
                )

                self.assertTrue(errors)

    def test_receipt_rejects_schema_valid_unplanned_failed_asset(self) -> None:
        selected = _selected_rc()
        promotion_digest = _digest("c")
        release_notes_digest = _digest("d")
        planned_assets = _planned_assets()
        receipt = _receipt(
            selected,
            promotion_digest,
            release_notes_digest,
            planned_assets,
        )
        receipt["assets"].append(
            {
                "name": "internal-evidence.json",
                "sizeBytes": 1,
                "digest": _digest("e"),
                "publicUri": (
                    "https://downloads.crypta.network/stable/"
                    "internal-evidence.json"
                ),
                "verificationStatus": "fail",
            }
        )

        errors = publication_receipt_errors(
            receipt,
            _context(),
            selected,
            _lineage(selected),
            promotion_digest,
            release_notes_digest,
            planned_assets,
        )

        self.assertEqual([], validate_schema(receipt, PUBLICATION_RECEIPT_SCHEMA))
        self.assertTrue(errors)

    def test_receipt_rejects_redaction_unsafe_public_value_without_echoing_it(self) -> None:
        selected = _selected_rc()
        promotion_digest = _digest("c")
        release_notes_digest = _digest("d")
        planned_assets = _planned_assets()
        receipt = _receipt(
            selected,
            promotion_digest,
            release_notes_digest,
            planned_assets,
        )
        secret = "https://operator:not-a-real-password@example.com/releases/v284"
        receipt["githubRelease"]["publicUrl"] = secret

        errors = publication_receipt_errors(
            receipt,
            _context(),
            selected,
            _lineage(selected),
            promotion_digest,
            release_notes_digest,
            planned_assets,
        )

        self.assertTrue(errors)
        self.assertNotIn(secret, " ".join(errors))


class StableGaVulnerabilityFreshnessAssertionTest(unittest.TestCase):
    def test_fresh_nonblocking_assertion_authenticates_until_exclusive_expiry(
        self,
    ) -> None:
        assertion = promotion_freshness_assertion(
            _vulnerability_promotion_summary(NOW + timedelta(seconds=1))
        )
        for protected_field in (
            "caseSummaries",
            "blockingCaseOpaqueIds",
            "blockers",
            "caseOpaqueId",
            "publicProjectionDigest",
        ):
            with self.subTest(protected_field=protected_field):
                self.assertNotIn(protected_field, assertion)
        with tempfile.TemporaryDirectory() as temporary:
            path, digest = _write_vulnerability_freshness_assertion(
                Path(temporary), assertion
            )

            value, errors = authenticate_promotion_freshness_assertion(
                path,
                workspace_root(),
                workspace_root() / "build",
                digest,
                NOW,
                RELEASE_ID,
                BUILD_VERSION,
            )

        self.assertEqual(assertion, value)
        self.assertEqual([], errors)

    def test_assertion_at_exclusive_expiry_fails_closed(self) -> None:
        assertion = promotion_freshness_assertion(
            _vulnerability_promotion_summary(NOW)
        )
        with tempfile.TemporaryDirectory() as temporary:
            path, digest = _write_vulnerability_freshness_assertion(
                Path(temporary), assertion
            )

            _value, errors = authenticate_promotion_freshness_assertion(
                path,
                workspace_root(),
                workspace_root() / "build",
                digest,
                NOW,
                RELEASE_ID,
                BUILD_VERSION,
            )

        self.assertIn("Stable vulnerability promotion authority is expired", errors)

    def test_tampered_assertion_file_fails_digest_authentication(self) -> None:
        assertion = promotion_freshness_assertion(
            _vulnerability_promotion_summary(NOW + timedelta(hours=1))
        )
        with tempfile.TemporaryDirectory() as temporary:
            path, digest = _write_vulnerability_freshness_assertion(
                Path(temporary), assertion
            )
            tampered = copy.deepcopy(assertion)
            tampered["expiresAt"] = _timestamp(NOW + timedelta(hours=2))
            path.write_bytes(vulnerability_canonical_file_bytes(tampered))
            path.chmod(0o600)

            _value, errors = authenticate_promotion_freshness_assertion(
                path,
                workspace_root(),
                workspace_root() / "build",
                digest,
                NOW,
                RELEASE_ID,
                BUILD_VERSION,
            )

        self.assertIn(
            "Stable vulnerability freshness assertion file digest differs", errors
        )
        self.assertIn(
            "Stable vulnerability freshness assertion digest is invalid", errors
        )

    def test_recomputed_blocking_assertion_fails_closed(self) -> None:
        assertion = promotion_freshness_assertion(
            _vulnerability_promotion_summary(NOW + timedelta(hours=1))
        )
        assertion["blockingStablePromotion"] = True
        assertion["blockingCaseCount"] = 1
        assertion["assertionDigest"] = vulnerability_identity_digest(
            assertion, "assertionDigest"
        )
        with tempfile.TemporaryDirectory() as temporary:
            path, digest = _write_vulnerability_freshness_assertion(
                Path(temporary), assertion
            )

            _value, errors = authenticate_promotion_freshness_assertion(
                path,
                workspace_root(),
                workspace_root() / "build",
                digest,
                NOW,
                RELEASE_ID,
                BUILD_VERSION,
            )

        self.assertIn(
            "Stable vulnerability freshness assertion is blocking or inconsistent",
            errors,
        )

    def test_timezone_naive_runner_clock_fails_closed(self) -> None:
        assertion = promotion_freshness_assertion(
            _vulnerability_promotion_summary(NOW + timedelta(hours=1))
        )
        with tempfile.TemporaryDirectory() as temporary:
            path, digest = _write_vulnerability_freshness_assertion(
                Path(temporary), assertion
            )

            _value, errors = authenticate_promotion_freshness_assertion(
                path,
                workspace_root(),
                workspace_root() / "build",
                digest,
                NOW.replace(tzinfo=None),
                RELEASE_ID,
                BUILD_VERSION,
            )

        self.assertIn(
            "Stable vulnerability freshness evaluation clock is not timezone-aware",
            errors,
        )

    def test_malformed_assertion_expiry_fails_closed(self) -> None:
        assertion = promotion_freshness_assertion(
            _vulnerability_promotion_summary(NOW + timedelta(hours=1))
        )
        assertion["expiresAt"] = "not-a-timestamp"
        assertion["assertionDigest"] = vulnerability_identity_digest(
            assertion, "assertionDigest"
        )
        with tempfile.TemporaryDirectory() as temporary:
            path, digest = _write_vulnerability_freshness_assertion(
                Path(temporary), assertion
            )

            _value, errors = authenticate_promotion_freshness_assertion(
                path,
                workspace_root(),
                workspace_root() / "build",
                digest,
                NOW,
                RELEASE_ID,
                BUILD_VERSION,
            )

        self.assertIn(
            "Stable vulnerability freshness assertion expiry is malformed", errors
        )

    def test_freshness_assertion_requires_private_file_permissions(self) -> None:
        assertion = promotion_freshness_assertion(
            _vulnerability_promotion_summary(NOW + timedelta(hours=1))
        )
        with tempfile.TemporaryDirectory() as temporary:
            path, digest = _write_vulnerability_freshness_assertion(
                Path(temporary), assertion
            )
            path.chmod(0o644)

            _value, errors = authenticate_promotion_freshness_assertion(
                path,
                workspace_root(),
                workspace_root() / "build",
                digest,
                NOW,
                RELEASE_ID,
                BUILD_VERSION,
            )

        self.assertIn("Stable vulnerability freshness assertion file is unsafe", errors)


class StableGaSecurityAndDeterminismTest(unittest.TestCase):
    def test_protected_workflow_checkouts_use_authenticated_dispatch_sha(self) -> None:
        workflow = (
            workspace_root() / ".github/workflows/stable-1.0-ga-promotion.yml"
        ).read_text(encoding="utf-8")

        self.assertEqual(2, workflow.count("          ref: ${{ github.sha }}"))
        self.assertNotIn("          ref: ${{ inputs.candidate_commit }}", workflow)
        self.assertIn(
            '|| "$GITHUB_SHA" != "$INPUT_CANDIDATE_COMMIT"',
            workflow,
        )

    def test_ga_release_asset_allowlist_keeps_pr290_companions_independent(
        self,
    ) -> None:
        filter_path = (
            workspace_root()
            / "tools/release-certification/protected/stable_ga_release_asset_names.jq"
        )
        workflow = (
            workspace_root() / ".github/workflows/stable-1.0-ga-promotion.yml"
        ).read_text(encoding="utf-8")
        planned = [{"name": f"stable-ga-{index}.bin"} for index in range(7)]
        companions = [
            {"name": "stable-1.0-dependency-vulnerability-public-findings.json"},
            {"name": "stable-1.0-dependency-vulnerability-source-status.json"},
            {"name": "stable-1.0-dependency-vulnerability-summary.json"},
        ]
        provider_source = (
            workspace_root()
            / "tools/release-certification/publication-backend/src/"
            "cryptad_stable_maintenance_backend/provider.py"
        ).read_text(encoding="utf-8")
        provider_module = ast.parse(provider_source)
        provider_assignment = next(
            node
            for node in provider_module.body
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name)
                and target.id == "DEPENDENCY_VULNERABILITY_COMPANION_ASSET_FILES"
                for target in node.targets
            )
        )
        provider_companions = ast.literal_eval(provider_assignment.value)

        def accepted(
            observed: list[dict[str, str]], *, active: bool, complete: bool
        ) -> bool:
            result = subprocess.run(
                [
                    "jq",
                    "-e",
                    "--argjson",
                    "planned",
                    json.dumps(planned, separators=(",", ":")),
                    "--arg",
                    "dependency_vulnerability_active",
                    str(active).lower(),
                    "--argjson",
                    "require_complete",
                    str(complete).lower(),
                    "-f",
                    str(filter_path),
                ],
                input=json.dumps(observed, separators=(",", ":")),
                text=True,
                capture_output=True,
                check=False,
            )
            return result.returncode == 0

        self.assertTrue(accepted(planned + companions, active=True, complete=True))
        self.assertTrue(accepted(planned, active=True, complete=True))
        self.assertFalse(accepted(planned + companions[:1], active=True, complete=True))
        self.assertFalse(accepted(planned + companions[:2], active=True, complete=True))
        self.assertTrue(accepted(companions, active=True, complete=False))
        self.assertFalse(accepted(companions[:1], active=True, complete=False))
        self.assertFalse(accepted(companions[:2], active=True, complete=False))
        self.assertFalse(accepted(planned + companions, active=False, complete=True))
        self.assertFalse(
            accepted(planned + [{"name": "unexpected.json"}], active=True, complete=True)
        )
        self.assertFalse(accepted(planned[:-1] + companions, active=True, complete=True))
        self.assertFalse(accepted(planned + companions[:1] * 2, active=True, complete=True))
        self.assertEqual(
            {row["name"] for row in companions}, set(provider_companions.values())
        )
        self.assertEqual(3, workflow.count("stable_ga_release_asset_names.jq"))
        self.assertEqual(1, workflow.count("--argjson require_complete false"))
        self.assertEqual(2, workflow.count("--argjson require_complete true"))

    def test_ga_publication_rechecks_current_vulnerability_state_under_lock(
        self,
    ) -> None:
        workflow = (
            workspace_root() / ".github/workflows/stable-1.0-ga-promotion.yml"
        ).read_text(encoding="utf-8")

        for field in (
            "stable_vulnerability_run_id",
            "stable_vulnerability_run_attempt",
            "stable_vulnerability_artifact_name",
            "stable_vulnerability_artifact_digest",
        ):
            with self.subTest(field=field):
                input_start = workflow.index(f"      {field}:")
                input_end = workflow.index(
                    "\n", workflow.index("        type: string", input_start)
                )
                input_block = workflow[input_start:input_end]
                self.assertIn("required: false", input_block)
                self.assertIn("default: ''", input_block)
                self.assertIn("required only for publish=true", input_block)

        validate_start = workflow.index(
            "      - name: Validate dispatch identity and clean checkout"
        )
        validate_end = workflow.index("\n      - name:", validate_start + 8)
        validate_step = workflow[validate_start:validate_end]
        self.assertIn("INPUT_PUBLISH: ${{ inputs.publish }}", validate_step)
        self.assertIn('[[ "$INPUT_PUBLISH" == "true" ]]', validate_step)
        self.assertIn(
            "publish=true requires exact current vulnerability promotion coordinates",
            validate_step,
        )
        self.assertIn("^sha256:[0-9a-f]{64}$", validate_step)

        publish_start = workflow.index("\n  publish:")
        publish = workflow[publish_start:]
        self.assertIn(
            "    concurrency:\n"
            "      group: stable-1-0-vulnerability-ledger\n"
            "      cancel-in-progress: false",
            publish,
        )
        authenticate = publish.index(
            "      - name: Authenticate exact current Stable vulnerability "
            "promotion producer"
        )
        download = publish.index(
            "      - name: Download exact current encrypted vulnerability "
            "promotion successor"
        )
        recheck = publish.index(
            "      - name: Reauthenticate nonblocking current vulnerability "
            "state before GA mutation"
        )
        mutation = publish.index(
            "      - name: Publish or verify exact authorized tag, Release, and assets"
        )
        self.assertLess(authenticate, download)
        self.assertLess(download, recheck)
        self.assertLess(recheck, mutation)

        authenticate_end = publish.index("\n      - name:", authenticate + 8)
        authenticate_step = publish[authenticate:authenticate_end]
        self.assertIn(
            '"repos/$GITHUB_REPOSITORY/actions/runs/'
            '$STABLE_VULNERABILITY_RUN_ID/attempts/'
            '$STABLE_VULNERABILITY_RUN_ATTEMPT"',
            authenticate_step,
        )
        self.assertIn("(.id | tostring) == $run_id", authenticate_step)

        step_end = publish.index("\n      - name:", recheck + 8)
        step = publish[recheck:step_end]
        self.assertIn("stable_vulnerability_actions_tip.py", step)
        self.assertIn("verify-promotion", step)
        self.assertIn('and .operation == "evaluate-promotion"', step)
        self.assertIn('and .caseOpaqueId == "ledger-wide"', step)
        self.assertIn("authenticate_handoff", step)
        self.assertIn('summary.get("blockingStablePromotion") is not False', step)
        self.assertIn("id: vulnerability_promotion", step)
        self.assertIn("promotion_freshness_assertion(summary)", step)
        self.assertIn("flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL", step)
        self.assertIn('descriptor = os.open(assertion_path, flags, 0o600)', step)
        self.assertIn(
            'output.write(f"freshness_assertion_digest={source_digest(raw)}\\n")',
            step,
        )
        self.assertNotIn("expiresAt=", step)
        self.assertLess(
            step.index('summary.get("blockingStablePromotion") is not False'),
            step.index("promotion_freshness_assertion(summary)"),
        )
        self.assertIn(
            "CRYPTAD_STABLE_VULNERABILITY_ANCHOR_READ_TOKEN: "
            "${{ secrets.CRYPTAD_STABLE_VULNERABILITY_ANCHOR_READ_TOKEN }}",
            step,
        )
        self.assertIn(
            "CRYPTAD_STABLE_VULNERABILITY_HANDOFF_KEY_BASE64: "
            "${{ secrets.CRYPTAD_STABLE_VULNERABILITY_HANDOFF_KEY_BASE64 }}",
            step,
        )
        self.assertIn("$RUNNER_TEMP/stable-ga-vulnerability-summary-", step)

        publication_end = publish.index(
            "\n      - name: Record publication conflict or partial state without side effects",
            mutation,
        )
        publication = publish[mutation:publication_end]
        self.assertIn(
            "STABLE_VULNERABILITY_FRESHNESS_ASSERTION_DIGEST: "
            "${{ steps.vulnerability_promotion.outputs.freshness_assertion_digest }}",
            publication,
        )
        self.assertIn("authenticate_promotion_freshness_assertion", publication)
        self.assertIn("dt.datetime.now(dt.timezone.utc)", publication)
        self.assertIn('rm -f "$vulnerability_freshness_assertion"', publication)
        self.assertNotIn("CRYPTAD_STABLE_VULNERABILITY_HANDOFF_KEY_BASE64", publication)

        validation_stage = workflow[
            workflow.index(
                "      - name: Stage exact public validation and publication inputs"
            ) : workflow.index(
                "      - name: Upload exact redaction-safe Stable GA validation artifact"
            )
        ]
        self.assertNotIn("stable-ga-vulnerability-promotion-input", validation_stage)
        self.assertNotIn("stable-1.0-vulnerability-summary.json", validation_stage)
        self.assertNotIn("sealed-successor", validation_stage)

    def test_ga_publication_requires_current_pr290_authority_prospectively(
        self,
    ) -> None:
        workflow = (
            workspace_root() / ".github/workflows/stable-1.0-ga-promotion.yml"
        ).read_text(encoding="utf-8")

        for field in (
            "stable_dependency_vulnerability_run_id",
            "stable_dependency_vulnerability_run_attempt",
            "stable_dependency_vulnerability_artifact_name",
            "stable_dependency_vulnerability_artifact_digest",
        ):
            with self.subTest(field=field):
                input_start = workflow.index(f"      {field}:")
                input_end = workflow.index(
                    "\n", workflow.index("        type: string", input_start)
                )
                input_block = workflow[input_start:input_end]
                self.assertIn("required: false", input_block)
                self.assertIn("default: ''", input_block)

        materialize_start = workflow.index(
            "      - name: Authenticate and materialize the selected Stable RC and GA inputs"
        )
        materialize_end = workflow.index("\n      - name:", materialize_start + 8)
        materialize = workflow[materialize_start:materialize_end]
        self.assertNotIn("artifact_created_at=", materialize)
        self.assertIn("frozen_at=\"$(jq -er '", materialize)
        self.assertIn(".frozenAt", materialize)
        self.assertIn('echo "frozen_at=$frozen_at"', materialize)
        self.assertLess(
            materialize.index("freeze=\"$(find_one 'Stable RC freeze'"),
            materialize.index("frozen_at=\"$(jq -er '"),
        )
        activation_start = workflow.index(
            "      - name: Determine prospective PR-290 governance activation"
        )
        activation_end = workflow.index("\n      - name:", activation_start + 8)
        activation = workflow[activation_start:activation_end]
        self.assertIn("--authenticated-frozen-at", activation)
        self.assertIn("steps.materialize.outputs.frozen_at", activation)
        self.assertNotIn("stable-1.0-rc-freeze.json", activation)

        publish_start = workflow.index("\n  publish:")
        publish = workflow[publish_start:]
        authenticate = publish.index(
            "      - name: Authenticate exact current PR-290 promotion producer"
        )
        download = publish.index(
            "      - name: Download exact current PR-290 evaluation handoff"
        )
        current = publish.index(
            "      - name: Reauthenticate current PR-290 state before GA mutation"
        )
        mutation = publish.index(
            "      - name: Publish or verify exact authorized tag, Release, and assets"
        )
        self.assertLess(authenticate, download)
        self.assertLess(download, current)
        self.assertLess(current, mutation)
        download_end = publish.index("\n      - name:", download + 8)
        download_step = publish[download:download_end]
        self.assertIn(
            "uses: actions/download-artifact@"
            "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1",
            download_step,
        )
        self.assertNotIn("uses: actions/download-artifact@v8", download_step)

        current_end = publish.index("\n      - name:", current + 8)
        current_step = publish[current:current_end]
        for expected in (
            "stable_dependency_vulnerability_evaluation_handoff_errors",
            "stable_dependency_vulnerability_actions_tip.py",
            "verify-current-status",
            "stable-1.0-dependency-vulnerability-publication-plan.json",
            "stable-1.0-dependency-vulnerability-source-status.json",
            'summary.get("activationStatus") != "active-post-activation"',
            'summary.get("promotionReady") is not True',
            "freshness_assertion_digest=sha256:",
        ):
            self.assertIn(expected, current_step)
        self.assertIn(
            "CRYPTAD_STABLE_DEPENDENCY_VULNERABILITY_ANCHOR_READ_TOKEN: "
            "${{ secrets.CRYPTAD_STABLE_DEPENDENCY_VULNERABILITY_ANCHOR_READ_TOKEN }}",
            current_step,
        )
        self.assertIn(
            "CRYPTAD_STABLE_DEPENDENCY_INTELLIGENCE_LINEAGE_READ_TOKEN: "
            "${{ secrets.CRYPTAD_STABLE_DEPENDENCY_INTELLIGENCE_LINEAGE_READ_TOKEN }}",
            current_step,
        )

        publication_end = publish.index(
            "\n      - name: Record publication conflict or partial state without side effects",
            mutation,
        )
        publication = publish[mutation:publication_end]
        self.assertIn("verify_dependency_vulnerability_promotion_freshness", publication)
        self.assertIn("STABLE_DEPENDENCY_VULNERABILITY_ACTIVE", publication)
        self.assertIn("dt.datetime.now(dt.timezone.utc) >= valid_until", publication)
        self.assertEqual(
            3,
            publication.count("verify_dependency_vulnerability_promotion_freshness"),
        )
        boundary = publication.index("validate_publication_boundary()")
        self.assertLess(
            boundary,
            publication.index("tag_object_json=", boundary),
        )
        self.assertEqual(4, publication.count("begin_publication_side_effect\n"))
        self.assertIn(
            'validate_publication_boundary\n            jq -n --arg ref "refs/tags/$tag"',
            publication,
        )

    def test_protected_workflow_stages_only_authenticated_publication_inputs(self) -> None:
        workflow = (
            workspace_root() / ".github/workflows/stable-1.0-ga-promotion.yml"
        ).read_text(encoding="utf-8")
        materialize_start = workflow.index('\n          input_root="build/stable-ga-inputs"')
        materialize_end = workflow.index(
            "\n          freeze_digest=",
            materialize_start,
        )
        materialize = workflow[materialize_start:materialize_end]
        stage_start = workflow.index(
            "\n      - name: Stage exact public validation and publication inputs"
        )
        stage_end = workflow.index(
            "\n      - name: Upload exact redaction-safe Stable GA validation artifact",
            stage_start,
        )
        stage = workflow[stage_start:stage_end]
        publication_inputs_start = stage.index(
            "\n          for name in \\" "\n            summary.json"
        )
        publication_inputs_end = stage.index(
            "\n          cp \"$COMPONENT/artifacts/legacy/"
            "stable-1.0-ga-validation-authorization-identity.json\"",
            publication_inputs_start,
        )
        publication_inputs = stage[
            publication_inputs_start:publication_inputs_end
        ]
        required_rc_sources = (
            "$freeze",
            "$freeze_sidecar",
            "$rc_archive",
            "$rc_product",
            "$rc_checksums",
            "$rc_provenance",
        )
        required_rc_checksum_metadata = (
            "stable-1.0-rc-freeze-report.md",
            "stable-1.0-rc-promotion-summary.json",
            "stable-1.0-rc-go-no-go.md",
            "stable-1.0-rc-known-limitations.json",
            "stable-1.0-rc-release-notes.md",
            "stable-1.0-rc-drift-report.json",
            "redaction-report.json",
            *SUPPORTING_VERIFIER_FILES,
        )
        self.assertEqual(
            stable_1_0_ga_core._canonical_rc_checksum_names(BUILD_VERSION),
            {
                f"cryptad-stable-1.0-rc-{BUILD_VERSION}.tar.gz",
                f"crypta-stable-1.0-rc-{BUILD_VERSION}-product.tar.gz",
                "stable-1.0-rc-freeze.json",
                "stable-1.0-rc-freeze.sha256",
                "provenance.json",
                *required_rc_checksum_metadata,
            },
        )
        required_publication_inputs = (
            "summary.json",
            "stable-1.0-rc-freeze.json",
            "stable-1.0-rc-freeze.sha256",
            '"cryptad-stable-1.0-rc-$INPUT_BUILD_VERSION.tar.gz"',
            '"crypta-stable-1.0-rc-$INPUT_BUILD_VERSION-product.tar.gz"',
            "checksums.txt",
            "provenance.json",
            "stable-1.0-rc-lineage.json",
            "previous-candidate-summary.json",
            "stable-1.0-rc-validation.json",
            "stable-1.0-ga-authorization.json",
            "stable-1.0-ga-policy.json",
        )

        self.assertNotIn('cp -a "$freeze_dir/."', workflow)
        self.assertNotIn("cp -a build/stable-ga-inputs/.", workflow)
        for source in required_rc_sources:
            with self.subTest(source=source):
                self.assertIn(source, materialize)
        for name in required_rc_checksum_metadata:
            with self.subTest(boundary="materialize", name=name):
                self.assertIn(name, materialize)
            with self.subTest(boundary="publication", name=name):
                self.assertIn(name, publication_inputs)
        for name in required_publication_inputs:
            with self.subTest(name=name):
                self.assertIn(name, publication_inputs)
        self.assertIn('source="build/stable-ga-inputs/$name"', publication_inputs)
        self.assertIn(
            '[[ -L "$source" || ! -f "$source" ]]',
            publication_inputs,
        )

    def test_protected_workflow_authenticates_annotated_tag_object_name(self) -> None:
        workflow = (
            workspace_root() / ".github/workflows/stable-1.0-ga-promotion.yml"
        ).read_text(encoding="utf-8")
        verify_start = workflow.index("\n          verify_tag() {")
        verify_end = workflow.index(
            "\n          reauthenticate_latest_stable_rc() {",
            verify_start,
        )
        verify_tag = workflow[verify_start:verify_end]
        recovery_start = workflow.index(
            "\n      - name: Record publication conflict or partial state without side effects"
        )
        recovery_end = workflow.index(
            "\n      - name: Verify the publication receipt through Stable GA",
            recovery_start,
        )
        recovery = workflow[recovery_start:recovery_end]

        self.assertIn(
            '"$(jq -r \'.tag\' <<< "$object_json")" != "$tag"',
            verify_tag,
        )
        self.assertIn('--arg tag "$tag"', recovery)
        self.assertIn(".tag == $tag", recovery)

    def test_protected_workflow_uses_actions_token_for_artifact_reads(self) -> None:
        workflow = (
            workspace_root() / ".github/workflows/stable-1.0-ga-promotion.yml"
        ).read_text(encoding="utf-8")
        step_start = workflow.index(
            "\n      - name: Reverify exact validated bytes and protected GitHub identity"
        )
        step_end = workflow.index(
            "\n      - name: Publish or verify exact authorized tag, Release, and assets",
            step_start,
        )
        step = workflow[step_start:step_end]

        self.assertIn("ACTIONS_GITHUB_TOKEN: ${{ github.token }}", step)
        self.assertIn('export GH_TOKEN="$LEUMOR_GITHUB_TOKEN"', step)
        self.assertIn(
            'current_artifacts="$(GH_TOKEN="$ACTIONS_GITHUB_TOKEN" '
            "gh api --paginate --method GET",
            step,
        )
        self.assertIn(
            '"repos/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID/artifacts"',
            step,
        )

    def test_protected_workflow_cannot_publish_from_pr_or_default_validation(self) -> None:
        workflow = (
            workspace_root() / ".github/workflows/stable-1.0-ga-promotion.yml"
        ).read_text(encoding="utf-8")
        stable_rc_workflow = (
            workspace_root() / ".github/workflows/stable-1.0-rc-release.yml"
        ).read_text(encoding="utf-8")

        self.assertIn(
            "group: stable-1-0-release-${{ inputs.integer_build_version }}",
            stable_rc_workflow,
        )
        self.assertIn(
            "group: stable-1-0-release-${{ inputs.build_version }}",
            workflow,
        )
        self.assertIn("cancel-in-progress: false", stable_rc_workflow)
        self.assertIn("cancel-in-progress: false", workflow)
        self.assertIn("workflow_dispatch:", workflow)
        self.assertNotIn("pull_request:", workflow)
        self.assertNotIn("\n  push:", workflow)
        self.assertIn("if: inputs.publish == true", workflow)
        self.assertIn("environment: stable-1-0-ga", workflow)
        self.assertIn("environment: stable-1-0-ga-evidence", workflow)
        validate_start = workflow.index("\n  validate:")
        validate_steps = workflow.index("\n    steps:", validate_start)
        self.assertIn(
            "deployments: read",
            workflow[validate_start:validate_steps],
        )
        self.assertIn("contents: read", workflow)
        publish_start = workflow.index("\n  publish:")
        publish_steps = workflow.index("\n    steps:", publish_start)
        publish_permissions = workflow[publish_start:publish_steps]
        self.assertIn("contents: read", publish_permissions)
        self.assertNotIn("contents: write", publish_permissions)
        self.assertIn("attestations: read", workflow)
        self.assertIn("attestations: write", workflow)
        self.assertIn("LEUMOR_GITHUB_TOKEN", workflow)
        self.assertIn("python3 tools/release-certification/certify.py stable-ga", workflow)
        self.assertIn(
            "uses: actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6",
            workflow,
        )
        self.assertIn('gh attestation verify "$evidence"', workflow)
        self.assertIn('--source-digest "$INPUT_CANDIDATE_COMMIT"', workflow)
        self.assertIn('--source-ref "$source_ref"', workflow)
        self.assertIn("--deny-self-hosted-runners", workflow)
        self.assertGreaterEqual(
            workflow.count("stable-1.0-ga-validation-authorization-identity.json"),
            8,
        )
        self.assertIn("publicationTargetsDigest", workflow)
        self.assertIn("authorization_input_digest", workflow)
        self.assertIn(".ga.authorizationDigest == $authorization_digest", workflow)
        self.assertIn(".gaAuthorizationDigest == $authorization_digest", workflow)
        self.assertIn(
            'previousCandidate: "build/stable-ga-inputs/previous-candidate-summary.json"',
            workflow,
        )
        self.assertIn(".candidate.previousCandidateDigest", workflow)
        self.assertIn(".inputs.previousCandidate", workflow)
        self.assertIn(
            "Stable GA checksum rows are not the exact public asset allowlist",
            workflow,
        )
        self.assertIn("revalidate_publication_inputs", workflow)
        self.assertIn("reauthenticate_latest_stable_rc", workflow)
        self.assertIn("selected_attempt_completed_at", workflow)
        self.assertIn("candidate_attempt_completed_at", workflow)
        self.assertIn(
            "Stable RC completion chronology is ambiguous at GitHub timestamp precision",
            workflow,
        )
        self.assertNotIn(
            'candidate_run_id" -lt "$INPUT_RC_RUN_ID',
            workflow,
        )
        branch_definition = workflow.index(
            "\n          verify_release_branch_head() {"
        )
        branch_initial_call = workflow.index(
            "\n          verify_release_branch_head\n",
            branch_definition,
        )
        branch_helper = workflow[branch_definition:branch_initial_call]
        self.assertIn(
            "git/ref/heads/release%2F$INPUT_BUILD_VERSION",
            branch_helper,
        )
        self.assertIn(
            '[[ "$branch_sha" != "$INPUT_CANDIDATE_COMMIT" ]]',
            branch_helper,
        )
        validation_boundary_definition = workflow.index(
            "\n          validate_publication_boundary() {"
        )
        side_effect_boundary_definition = workflow.index(
            "\n          begin_publication_side_effect() {",
            validation_boundary_definition,
        )
        validation_boundary = workflow[
            validation_boundary_definition:side_effect_boundary_definition
        ]
        boundary_vulnerability_freshness = validation_boundary.index(
            "\n            verify_vulnerability_promotion_freshness\n"
        )
        boundary_refresh = validation_boundary.index(
            "\n            reauthenticate_latest_stable_rc\n"
        )
        boundary_revalidation = validation_boundary.index(
            "\n            revalidate_publication_inputs\n",
            boundary_refresh,
        )
        boundary_branch_refresh = validation_boundary.index(
            "\n            verify_release_branch_head\n",
            boundary_revalidation,
        )
        boundary_final_vulnerability_freshness = validation_boundary.index(
            "\n            verify_vulnerability_promotion_freshness\n",
            boundary_branch_refresh,
        )
        initial_boundary_call = workflow.index(
            "\n          validate_publication_boundary\n",
            side_effect_boundary_definition,
        )
        boundary_marker = workflow.index(
            "\n            : > build/stable-ga-publication-side-effect-started",
            side_effect_boundary_definition,
        )
        artifact_base_preflight = workflow.index(
            "\n          verify_artifact_base_assets preflight\n",
            initial_boundary_call,
        )
        first_boundary_call = workflow.index(
            "\n            begin_publication_side_effect\n",
            artifact_base_preflight,
        )
        self.assertLess(
            boundary_vulnerability_freshness,
            boundary_refresh,
        )
        self.assertLess(boundary_refresh, boundary_revalidation)
        self.assertLess(
            boundary_revalidation,
            boundary_branch_refresh,
        )
        self.assertLess(
            boundary_branch_refresh,
            boundary_final_vulnerability_freshness,
        )
        self.assertLess(initial_boundary_call, artifact_base_preflight)
        self.assertLess(
            artifact_base_preflight,
            first_boundary_call,
        )
        side_effect_boundary = workflow[
            side_effect_boundary_definition:initial_boundary_call
        ]
        self.assertIn("\n            validate_publication_boundary\n", side_effect_boundary)
        self.assertLess(
            side_effect_boundary.index("\n            validate_publication_boundary\n"),
            side_effect_boundary.index(
                "\n            : > build/stable-ga-publication-side-effect-started"
            ),
        )
        revalidation_definition_start = workflow.index(
            "\n          revalidate_publication_inputs() {"
        )
        revalidation_definition = workflow[
            revalidation_definition_start:validation_boundary_definition
        ]
        self.assertIn(
            "stable-1.0-ga-validation-authorization-identity.json",
            revalidation_definition,
        )
        self.assertLess(
            first_boundary_call,
            workflow.index(
                'gh api --method POST "repos/$GITHUB_REPOSITORY/git/tags"'
            ),
        )
        tag_object_marker = workflow.index(
            "printf '%s\\n' \"$tag_object\" > "
            "build/stable-ga-publication-side-effect-started"
        )
        tag_ref_boundary = workflow.index(
            "\n            validate_publication_boundary\n",
            tag_object_marker,
        )
        tag_ref_post = workflow.index(
            'gh api --method POST "repos/$GITHUB_REPOSITORY/git/refs"',
            tag_ref_boundary,
        )
        self.assertLess(tag_object_marker, tag_ref_boundary)
        self.assertLess(tag_ref_boundary, tag_ref_post)
        success_receipt = workflow.index(
            'receipt="build/stable-1.0-ga-publication-receipt-candidate.json"'
        )
        final_boundary_refresh = workflow.rfind(
            "\n          validate_publication_boundary\n",
            tag_ref_post,
            success_receipt,
        )
        self.assertGreater(final_boundary_refresh, tag_ref_post)
        self.assertLess(final_boundary_refresh, success_receipt)
        recovery_start = workflow.index(
            "\n      - name: Record publication conflict or partial state without side effects"
        )
        recovery_end = workflow.index(
            "\n      - name: Verify the publication receipt through Stable GA",
            recovery_start,
        )
        recovery = workflow[recovery_start:recovery_end]
        self.assertIn("set -euo pipefail", recovery)
        self.assertNotIn("--method POST", recovery)
        self.assertNotIn("--method PATCH", recovery)
        self.assertNotIn("gh release upload", recovery)
        self.assertNotIn("|| true", recovery)
        self.assertIn("git/matching-refs/tags/$tag", recovery)
        self.assertIn('"repos/$GITHUB_REPOSITORY/releases" -f per_page=100', recovery)
        self.assertIn("sanitized_public_asset_observation", recovery)
        self.assertIn("tag_observation=unavailable", recovery)
        self.assertIn("release_observation=unavailable", recovery)
        self.assertIn('"status":"unavailable"', recovery)
        self.assertIn("unexpectedNameDigests", recovery)
        self.assertNotIn("unexpectedAssets", recovery)
        self.assertNotIn("missingAssets", recovery)
        self.assertNotIn('if [[ ! -f "$marker" ]]', recovery)
        self.assertIn("pre-publication-verification-failure", recovery)
        self.assertIn("side-effecting-publication-failure", recovery)
        self.assertIn('receipt="build/stable-1.0-ga-publication-receipt.json"', recovery)
        self.assertIn("catalog_rollback_uri:", workflow)
        self.assertIn("STABLE_CATALOG_TRUSTED_KEYS_BASE64", workflow)
        self.assertIn('"$rollback_uri" rollback preflight', workflow)
        self.assertIn('"$rollback_uri" rollback final', workflow)
        self.assertIn('"$catalog_verifier" catalog verify', workflow)
        self.assertIn('artifact_base_uri="$(jq -er \'.artifactBaseUri\' "$plan")"', workflow)
        self.assertIn('public_uri="${artifact_base_uri}${name}"', workflow)
        self.assertNotIn('public_uri="${INPUT_ARTIFACT_BASE_URI}${name}"', workflow)
        self.assertIn("Declared artifact base returned different bytes", workflow)
        self.assertIn("publicUri: $public_uri", workflow)
        helper_start = workflow.index("\n          verify_artifact_base_assets() {")
        helper_end = workflow.index("\n          verify_release_branch_head() {", helper_start)
        artifact_base_helper = workflow[helper_start:helper_end]
        for required in (
            "socket.getaddrinfo",
            "ipaddress.ip_address(address).is_global",
            "literal_address = ipaddress.ip_address(parsed.hostname)",
            'resolution_mode = "literal"',
            'if [[ "$resolution_mode" == "dns" ]]',
            'curl_resolution=(--resolve "${host}:443:${resolve_address}")',
            '"${curl_resolution[@]}"',
            "curl --disable",
            "--noproxy '*'",
            "--resolve",
            "--proto '=https'",
            "--max-redirs 0",
            "--max-filesize",
            "--connect-timeout",
            "--max-time",
            "--write-out '%{http_code}'",
        ):
            self.assertIn(required, artifact_base_helper)
        self.assertNotIn(
            '\n                    --resolve "${host}:443:${resolve_address}"',
            artifact_base_helper,
        )
        address_loop_start = artifact_base_helper.index(
            "while IFS=$'\\t' read -r _ address resolution_mode; do"
        )
        address_loop_end = artifact_base_helper.index(
            'done <<< "$resolution_rows"',
            address_loop_start,
        )
        per_address_verification = artifact_base_helper[
            address_loop_start:address_loop_end
        ]
        for required in (
            '--max-filesize "$size"',
            'stat -c%s "$output"',
            'sha256sum "$output"',
            '"$digest"',
            "verified_address=true",
        ):
            self.assertIn(required, per_address_verification)
        self.assertNotIn("break", per_address_verification)
        resolver_marker = "<<'PY'\n"
        resolver_start = artifact_base_helper.index(resolver_marker) + len(
            resolver_marker
        )
        resolver_end = artifact_base_helper.index("\n          PY\n", resolver_start)
        resolver_script = textwrap.dedent(
            artifact_base_helper[resolver_start:resolver_end]
        )
        literal_result = subprocess.run(
            [sys.executable, "-", "https://[2606:4700:4700::1111]/stable/"],
            input=resolver_script,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, literal_result.returncode, literal_result.stderr)
        self.assertEqual(
            "2606:4700:4700::1111\t2606:4700:4700::1111\tliteral",
            literal_result.stdout.strip(),
        )
        self.assertEqual(1, workflow.count("verify_artifact_base_assets preflight"))
        self.assertEqual(
            1,
            workflow.count("verify_artifact_base_assets pre-finalization"),
        )
        self.assertEqual(1, workflow.count("verify_artifact_base_assets final"))
        pre_finalization_artifact_base = workflow.index(
            "\n          verify_artifact_base_assets pre-finalization\n"
        )
        pre_finalization_primary = workflow.index(
            '"$primary_uri" primary pre-finalization',
            pre_finalization_artifact_base,
        )
        pre_finalization_rollback = workflow.index(
            '"$rollback_uri" rollback pre-finalization',
            pre_finalization_primary,
        )
        undraft_condition = workflow.index(
            '\n          if [[ "$(jq -r \'.draft\' <<< "$release_json")" == true ]]; then',
            pre_finalization_rollback,
        )
        undraft_boundary = workflow.index(
            "\n            begin_publication_side_effect\n",
            undraft_condition,
        )
        undraft_patch = workflow.index(
            "gh api --method PATCH",
            undraft_boundary,
        )
        self.assertLess(pre_finalization_artifact_base, pre_finalization_primary)
        self.assertLess(pre_finalization_primary, pre_finalization_rollback)
        self.assertLess(pre_finalization_rollback, undraft_boundary)
        self.assertLess(undraft_boundary, undraft_patch)
        final_artifact_base = workflow.index("verify_artifact_base_assets final")
        self.assertLess(final_artifact_base, final_boundary_refresh)
        materializer_start = workflow.index("\n          materialize_external() {")
        materializer_end = workflow.index(
            "\n          validation=\"$external_root/stable-1.0-rc-validation.json\"",
            materializer_start,
        )
        materializer = workflow[materializer_start:materializer_end]
        for required in (
            "socket.getaddrinfo",
            "ipaddress.ip_address(address).is_global",
            'curl_resolution=(--resolve "${host}:443:${resolve_addresses}")',
            '"${curl_resolution[@]}"',
            "curl --disable",
            "--noproxy '*'",
            "--max-redirs 0",
            "--connect-timeout 15",
            "--max-time 180",
            "--max-filesize 16777216",
            "--write-out '%{http_code}'",
        ):
            self.assertIn(required, materializer)
        self.assertNotIn("--retry", materializer)
        catalog_start = workflow.index("\n          catalog_resolution_rows() {")
        catalog_end = workflow.index(
            "\n          asset_source_for_role() {",
            catalog_start,
        )
        catalog_verification = workflow[catalog_start:catalog_end]
        for required in (
            "socket.getaddrinfo",
            "ipaddress.ip_address(address).is_global",
            "while IFS=$'\\t' read -r _ address resolution_mode; do",
            'curl_resolution=(--resolve "${host}:443:${resolve_address}")',
            '"${curl_resolution[@]}"',
            "curl --disable",
            "--noproxy '*'",
            "--max-redirs 0",
            "--connect-timeout 15",
            "--max-time 180",
            "--max-filesize 16777216",
            "--max-filesize 1048576",
            "--write-out '%{http_code}'",
            "verified_address=true",
            'done <<< "$resolution_rows"',
        ):
            self.assertIn(required, catalog_verification)
        self.assertNotIn("resolve_addresses", catalog_verification)
        self.assertNotIn("--retry", catalog_verification)
        address_loop_start = catalog_verification.index(
            "while IFS=$'\\t' read -r _ address resolution_mode; do"
        )
        address_loop_end = catalog_verification.index(
            'done <<< "$resolution_rows"',
            address_loop_start,
        )
        per_address_verification = catalog_verification[
            address_loop_start:address_loop_end
        ]
        for required in (
            "--max-filesize 16777216",
            "--max-filesize 1048576",
            "expected_catalog_digest",
            "expected_signature_digest",
            '"$catalog_verifier" catalog verify',
            "expected_signing_key",
        ):
            self.assertIn(required, per_address_verification)
        self.assertIn(
            'candidate_ref" != "commit:$INPUT_CANDIDATE_COMMIT"',
            workflow,
        )
        self.assertIn(
            "selected_summary=\"$(find_one 'Stable RC v2 summary' "
            "-path \"$rc_root/summary.json\")\"",
            workflow,
        )
        self.assertIn(
            'cp "$selected_summary" "$input_root/summary.json"',
            workflow,
        )
        self.assertEqual(
            3,
            workflow.count("selectedStableRcSummary"),
        )
        self.assertEqual(
            2,
            workflow.count('selectedStableRcSummary = ($input_root + "/summary.json")'),
        )
        self.assertIn(
            'selectedStableRcSummary: "build/stable-ga-inputs/summary.json"',
            workflow,
        )
        self.assertNotIn("selected-stable-rc-summary.json", workflow)
        self.assertNotIn("-path '*/stable-rc/summary.json'", workflow)
        self.assertIn(
            "path: |\n            ${{ steps.final_gate.outputs.component }}/",
            stable_rc_workflow,
        )
        release_asset_endpoint = (
            '"repos/$GITHUB_REPOSITORY/releases/$release_id/assets"'
        )
        self.assertEqual(4, workflow.count(release_asset_endpoint))
        self.assertNotIn(
            'gh api --paginate "repos/$GITHUB_REPOSITORY/releases/$release_id/assets"',
            workflow,
        )
        self.assertIn(".head_branch == $branch", workflow)
        self.assertNotIn(
            'candidate_ref" != "refs/heads/release/$INPUT_BUILD_VERSION"',
            workflow,
        )
        self.assertIn("socket.getaddrinfo", workflow)
        self.assertIn(
            "valid_public_https(artifact_base, catalog=False)",
            workflow,
        )
        release_post = workflow.index(
            '| gh api --method POST "repos/$GITHUB_REPOSITORY/releases" --input -)"'
        )
        release_marker = workflow.rfind(
            ": > build/stable-ga-publication-side-effect-started",
            0,
            release_post,
        )
        self.assertGreater(release_marker, 0)
        publication_start = workflow.index(
            "\n      - name: Publish or verify exact authorized tag, Release, and assets"
        )
        publication_end = workflow.index(
            "\n      - name: Record publication conflict or partial state without side effects",
            publication_start,
        )
        publication = workflow[publication_start:publication_end]
        self.assertIn("stable-1.0-ga-publication-receipt-candidate.json", publication)
        release_target_check = publication.index(
            '"$(jq -r \'.target_commitish\' <<< "$release_json")" '
            '!= "$INPUT_CANDIDATE_COMMIT"'
        )
        tag_post_in_publication = publication.index(
            'gh api --method POST "repos/$GITHUB_REPOSITORY/git/tags"'
        )
        release_post_in_publication = publication.index(
            'gh api --method POST "repos/$GITHUB_REPOSITORY/releases"'
        )
        asset_upload = publication.index('gh release upload "$tag"')
        release_patch = publication.index("gh api --method PATCH")
        self.assertLess(release_target_check, asset_upload)
        self.assertLess(release_target_check, release_patch)
        preceding_mutation = 0
        for mutation in (
            tag_post_in_publication,
            release_post_in_publication,
            asset_upload,
            release_patch,
        ):
            preceding_boundary = publication.rfind(
                "begin_publication_side_effect", preceding_mutation, mutation
            )
            self.assertGreater(preceding_boundary, preceding_mutation)
            preceding_mutation = mutation
        tag_ref_post_in_publication = publication.index(
            'gh api --method POST "repos/$GITHUB_REPOSITORY/git/refs"'
        )
        self.assertGreater(
            publication.rfind(
                "\n            validate_publication_boundary\n",
                0,
                tag_ref_post_in_publication,
            ),
            publication.index(
                "printf '%s\\n' \"$tag_object\" > "
                "build/stable-ga-publication-side-effect-started"
            ),
        )
        self.assertNotIn(
            'receipt="build/stable-1.0-ga-publication-receipt.json"',
            publication,
        )
        verifier_start = workflow.index(
            "\n      - name: Verify the publication receipt through Stable GA"
        )
        upload_start = workflow.index(
            "\n      - name: Upload publication receipt or partial-state audit record",
            verifier_start,
        )
        verifier_and_downgrade = workflow[verifier_start:upload_start]
        self.assertIn("id: receipt_verification", verifier_and_downgrade)
        self.assertIn("continue-on-error: true", verifier_and_downgrade)
        self.assertIn("post-publication-verification-failure", verifier_and_downgrade)
        audit_start = workflow.index(
            "\n      - name: Validate the redaction-safe publication audit record",
            verifier_start,
        )
        self.assertLess(audit_start, upload_start)
        audit = workflow[audit_start:upload_start]
        self.assertIn("validate_schema", audit)
        self.assertIn("scan_value", audit)
        self.assertIn("placeholder_findings", audit)
        upload_end = workflow.index(
            "\n      - name: Summarize protected publication",
            upload_start,
        )
        self.assertIn(
            "steps.audit_receipt_validation.outcome == 'success'",
            workflow[upload_start:upload_end],
        )
        self.assertNotIn(
            "stable-1.0-ga-publication-receipt-candidate.json",
            workflow[upload_start:upload_end],
        )
        self.assertIn(
            'jq -r \'.publicationState // "publication-verification-failed"\'',
            workflow[upload_end:],
        )

    def test_public_observer_receives_one_canonical_publication_receipt_member(self) -> None:
        workflow = (
            workspace_root() / ".github/workflows/stable-1.0-ga-promotion.yml"
        ).read_text(encoding="utf-8")
        observer = (
            workspace_root() / ".github/workflows/stable-1.0-public-observation.yml"
        ).read_text(encoding="utf-8")
        upload_start = workflow.index(
            "\n      - name: Upload publication receipt or partial-state audit record"
        )
        upload_end = workflow.index(
            "\n      - name: Summarize protected publication",
            upload_start,
        )
        upload = workflow[upload_start:upload_end]
        receipt_paths = [
            line.strip()
            for line in upload.splitlines()
            if line.strip().endswith("stable-1.0-ga-publication-receipt.json")
        ]

        self.assertEqual(
            ["build/stable-1.0-ga-publication-receipt.json"], receipt_paths
        )
        self.assertNotIn(
            "artifacts/legacy/stable-1.0-ga-publication-receipt.json", upload
        )
        self.assertIn(
            'root.rglob("stable-1.0-ga-publication-receipt.json")', observer
        )
        self.assertIn("len(candidates) != 1", observer)

    def test_public_https_requires_every_resolved_address_to_be_global(self) -> None:
        public = [
            (
                stable_1_0_ga_core.socket.AF_INET,
                stable_1_0_ga_core.socket.SOCK_STREAM,
                6,
                "",
                ("93.184.216.34", 443),
            )
        ]
        mixed = [
            *public,
            (
                stable_1_0_ga_core.socket.AF_INET,
                stable_1_0_ga_core.socket.SOCK_STREAM,
                6,
                "",
                ("127.0.0.1", 443),
            ),
        ]

        with mock.patch.object(
            stable_1_0_ga_core.socket,
            "getaddrinfo",
            return_value=public,
        ):
            self.assertTrue(stable_1_0_ga._safe_https("https://downloads.example.org/stable/"))
        with mock.patch.object(
            stable_1_0_ga_core.socket,
            "getaddrinfo",
            return_value=mixed,
        ):
            self.assertFalse(stable_1_0_ga._safe_https("https://127.0.0.1.nip.io/stable/"))
        with mock.patch.object(
            stable_1_0_ga_core.socket,
            "getaddrinfo",
            side_effect=stable_1_0_ga_core.socket.gaierror,
        ):
            self.assertFalse(stable_1_0_ga._safe_https("https://unresolved.example.org/stable/"))

    def test_release_note_support_links_require_public_https(self) -> None:
        for uri in (
            "https://localhost/support",
            "https://127.0.0.1/support",
            "https://support.example.org:8443/support",
        ):
            with self.subTest(uri=uri), self.assertRaisesRegex(
                ValueError,
                "not public HTTPS",
            ):
                stable_1_0_ga_artifacts._public_https_link(uri)  # noqa: SLF001

        private = [(None, None, None, None, ("10.0.0.8", 443))]
        with mock.patch.object(
            stable_1_0_ga_core.socket,
            "getaddrinfo",
            return_value=private,
        ), self.assertRaisesRegex(ValueError, "not public HTTPS"):
            stable_1_0_ga_artifacts._public_https_link(  # noqa: SLF001
                "https://support.example.org/support"
            )

        public = [(None, None, None, None, ("93.184.216.34", 443))]
        with mock.patch.object(
            stable_1_0_ga_core.socket,
            "getaddrinfo",
            return_value=public,
        ):
            self.assertEqual(
                "https://support.example.org/support",
                stable_1_0_ga_artifacts._public_https_link(  # noqa: SLF001
                    "https://support.example.org/support"
                ),
            )

        injected = "https://1.1.1.1/foo)![tracking](https://tracker.example/pixel"
        rendered = stable_1_0_ga_artifacts._public_https_link(injected)  # noqa: SLF001
        self.assertNotIn(")![tracking](", rendered)
        self.assertNotIn("![tracking]", rendered)
        self.assertIn("%29%21%5Btracking%5D%28", rendered)

    def test_catalog_targets_canonicalize_authorities_before_distinctness(self) -> None:
        context = _context()
        metadata = context.manifest.policies["metadata"]
        metadata["catalogPrimaryUri"] = (
            "https://1.1.1.1:443/first-party-catalog.properties"
        )
        metadata["catalogMirrorUris"] = (
            "https://1.1.1.1/first-party-catalog.properties"
        )
        metadata["catalogRollbackUri"] = (
            "https://9.9.9.9/history/6/first-party-catalog.properties"
        )

        targets, errors = stable_1_0_ga._catalog_targets(context)  # noqa: SLF001

        self.assertIn(
            "catalog publication targets contain ambiguous duplicate locations",
            errors,
        )
        self.assertEqual(
            "https://1.1.1.1/first-party-catalog.properties",
            targets["primary"]["publicUri"],
        )

        public = [(None, None, None, None, ("93.184.216.34", 443))]
        first = _context()
        second = _context()
        first_metadata = first.manifest.policies["metadata"]
        second_metadata = second.manifest.policies["metadata"]
        first_metadata["catalogPrimaryUri"] = (
            "https://CATALOG.crypta.network.:443/first-party-catalog.properties"
        )
        second_metadata["catalogPrimaryUri"] = (
            "https://catalog.crypta.network/first-party-catalog.properties"
        )
        with mock.patch.object(
            stable_1_0_ga_core.socket,
            "getaddrinfo",
            return_value=public,
        ):
            first_targets = canonical_publication_targets(first)
            second_targets = canonical_publication_targets(second)

        self.assertEqual(first_targets, second_targets)
        self.assertEqual(semantic_digest(first_targets), semantic_digest(second_targets))

    def test_catalog_targets_reject_ambiguous_paths(self) -> None:
        for path in (
            "/history/6/../6/first-party-catalog.properties",
            "/history//6/first-party-catalog.properties",
            "/history/%36/first-party-catalog.properties",
            "/history\\6/first-party-catalog.properties",
        ):
            with self.subTest(path=path):
                context = _context()
                context.manifest.policies["metadata"]["catalogRollbackUri"] = (
                    f"https://9.9.9.9{path}"
                )

                _targets, errors = stable_1_0_ga._catalog_targets(context)  # noqa: SLF001

                self.assertIn(
                    "catalog rollback target must be a distinct public HTTPS catalog URI",
                    errors,
                )

    def test_release_note_installation_targets_reject_controls_and_escape_markdown(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            context, _paths = _write_exact_rc_fixture(Path(directory))
            state = ValidationState()
            selected = authenticate_selected_rc(context, state)
            validation = _post_freeze_validation(selected, _policy())
            target = validation["scenarios"]["installationPackaging"]["targets"][0]
            target["architecture"] = "x86_64\n\n## Injected heading"

            self.assertEqual([], state.blockers)
            self.assertTrue(validate_schema(validation, RC_VALIDATION_SCHEMA))
            with self.assertRaisesRegex(ValueError, "contains controls"):
                stable_1_0_ga_artifacts.render_release_notes(
                    selected.freeze,
                    validation,
                    {"publicationState": "validated"},
                )

            injected_link = "[docs](https://docs.crypta.network/)"
            target["architecture"] = injected_link
            self.assertTrue(validate_schema(validation, RC_VALIDATION_SCHEMA))
            public = [(None, None, None, None, ("93.184.216.34", 443))]
            with mock.patch.object(
                stable_1_0_ga_core.socket,
                "getaddrinfo",
                return_value=public,
            ):
                notes = stable_1_0_ga_artifacts.render_release_notes(
                    selected.freeze,
                    validation,
                    {"publicationState": "validated"},
                )

            self.assertNotIn(injected_link, notes)
            self.assertIn(r"\[docs\]", notes)
            self.assertIn(r"\(https://docs.crypta.network/\)", notes)

        self.assertEqual(
            r"x86\_64",
            stable_1_0_ga_artifacts._safe_markdown_text("x86_64"),  # noqa: SLF001
        )

    def test_release_note_code_spans_use_collision_free_fences(self) -> None:
        cases = {
            "plain": "`plain`",
            "1` [text](https://example.org)": "``1` [text](https://example.org)``",
            "`edge`": "`` `edge` ``",
            "two `` ticks": "```two `` ticks```",
        }

        for value, expected in cases.items():
            with self.subTest(value=value):
                self.assertEqual(
                    expected,
                    stable_1_0_ga_artifacts._code_span(value),  # noqa: SLF001
                )

    def test_release_note_scalars_reject_unicode_line_separators(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            context, _paths = _write_exact_rc_fixture(Path(directory))
            state = ValidationState()
            selected = authenticate_selected_rc(context, state)
            validation = _post_freeze_validation(selected, _policy())

            self.assertEqual([], state.blockers)
            for separator in ("\x85", "\u2028", "\u2029"):
                with self.subTest(code_point=f"U+{ord(separator):04X}"):
                    injected = f"1{separator}# injected heading"
                    selected.freeze["firstPartyApps"][0]["version"] = injected
                    self.assertEqual(
                        ["1", "# injected heading"],
                        injected.splitlines(),
                    )
                    self.assertEqual(
                        [],
                        validate_schema(
                            selected.freeze,
                            "stable-1.0-rc-freeze-v1.schema.json",
                        ),
                    )
                    with self.assertRaisesRegex(
                        ValueError,
                        "controls or line separators",
                    ):
                        stable_1_0_ga_artifacts.render_release_notes(
                            selected.freeze,
                            validation,
                            {"publicationState": "validated"},
                        )

    def test_release_note_app_version_cannot_terminate_its_code_span(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            context, _paths = _write_exact_rc_fixture(Path(directory))
            state = ValidationState()
            selected = authenticate_selected_rc(context, state)
            validation = _post_freeze_validation(selected, _policy())
            injected = "1` [text](https://example.org)"
            selected.freeze["firstPartyApps"][0]["version"] = injected
            public = [(None, None, None, None, ("93.184.216.34", 443))]

            self.assertEqual([], state.blockers)
            self.assertEqual(
                [],
                validate_schema(
                    selected.freeze,
                    "stable-1.0-rc-freeze-v1.schema.json",
                ),
            )
            with mock.patch.object(
                stable_1_0_ga_core.socket,
                "getaddrinfo",
                return_value=public,
            ):
                notes = stable_1_0_ga_artifacts.render_release_notes(
                    selected.freeze,
                    validation,
                    {"publicationState": "validated"},
                )

        self.assertIn(f"``{injected}``", notes)
        self.assertNotIn(r"1\` [text](https://example.org)", notes)

    def test_manifest_authorization_field_exemption_is_exactly_scoped(self) -> None:
        value = {
            "schemaVersion": 1,
            "release": {
                "id": RELEASE_ID,
                "version": BUILD_VERSION,
                "profile": "stable-review",
            },
            "output": {"root": "build/release-certification", "reset": True},
            "requirements": {},
            "inputs": {"stableGaAuthorization": "build/protected/ga-authorization.json"},
            "policies": {"metadata": {}},
            "execution": {},
            "commands": {},
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "manifest.json"
            write_json(path, value)

            manifest = load_manifest(path, root)

            self.assertEqual(
                "build/protected/ga-authorization.json",
                manifest.inputs["stableGaAuthorization"],
            )
            value["policies"]["metadata"]["stableGaAuthorization"] = "claimed-public"
            write_json(path, value)
            with self.assertRaisesRegex(
                ManifestError,
                r"manifest\.policies\.metadata contains a secret-like field name",
            ):
                load_manifest(path, root)

    def test_manifest_modes_separate_authorization_preparation_from_validation(self) -> None:
        required_inputs = {
            key: f"build/inputs/{key}.json"
            for key in (
                "selectedStableRcSummary",
                "selectedStableRcFreeze",
                "selectedStableRcFreezeSidecar",
                "selectedStableRcArchive",
                "selectedStableRcProduct",
                "selectedStableRcChecksums",
                "selectedStableRcProvenance",
                "selectedStableRcLineage",
                "previousCandidate",
                "stableRcValidation",
                "stableGaPolicy",
            )
        }
        policies = {
            "artifactBaseUri": "https://downloads.example.invalid/stable/",
            "catalogChannel": "stable",
            "candidateSourceCommit": SOURCE_COMMIT,
            "candidateSourceRef": SOURCE_REF,
            "expectedPreviousReleaseId": PREVIOUS_RELEASE_ID,
            "expectedPreviousProductDigest": PREVIOUS_PRODUCT_DIGEST,
            "metadata": {
                "catalogPrimaryUri": "https://catalog.example.invalid/first-party-catalog.properties",
                "catalogMirrorUris": "https://mirror.example.invalid/first-party-catalog.properties",
                "catalogRollbackUri": "https://catalog.example.invalid/history/6/first-party-catalog.properties",
            },
            "publicationIntent": "prepare-explicit-protected-publication",
        }
        base = _context().manifest
        prepare = RunManifest(
            path=base.path,
            release=base.release,
            output=base.output,
            requirements=base.requirements,
            inputs=required_inputs,
            policies=policies,
            execution=base.execution,
            commands={"stable-ga": {"mode": "prepare-authorization"}},
        )
        _validate_stable_ga_manifest(prepare)

        branch_ref_policies = {
            **policies,
            "candidateSourceRef": f"refs/heads/release/{BUILD_VERSION}",
        }
        branch_ref = RunManifest(
            path=base.path,
            release=base.release,
            output=base.output,
            requirements=base.requirements,
            inputs=required_inputs,
            policies=branch_ref_policies,
            execution=base.execution,
            commands={"stable-ga": {"mode": "prepare-authorization"}},
        )
        with self.assertRaisesRegex(ValueError, "immutable commit"):
            _validate_stable_ga_manifest(branch_ref)

        validate_without_authorization = RunManifest(
            path=base.path,
            release=base.release,
            output=base.output,
            requirements=base.requirements,
            inputs=required_inputs,
            policies=policies,
            execution=base.execution,
            commands={"stable-ga": {"mode": "validate-only"}},
        )
        with self.assertRaisesRegex(ValueError, "stableGaAuthorization"):
            _validate_stable_ga_manifest(validate_without_authorization)

        with_authorization = {**required_inputs, "stableGaAuthorization": "build/auth.json"}
        invalid_prepare = RunManifest(
            path=base.path,
            release=base.release,
            output=base.output,
            requirements=base.requirements,
            inputs=with_authorization,
            policies=policies,
            execution=base.execution,
            commands={"stable-ga": {"mode": "prepare-authorization"}},
        )
        with self.assertRaisesRegex(ValueError, "must not include"):
            _validate_stable_ga_manifest(invalid_prepare)

    def test_json_input_rejects_redaction_unsafe_value_without_echoing_it(self) -> None:
        secret = "Authorization: Bearer abcdefghijklmnop"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "unsafe.json"
            write_json(path, {"value": secret})
            context = _context(root, {"stableGaAuthorization": path.name})

            with self.assertRaisesRegex(ValueError, "redaction-unsafe") as raised:
                load_json_input(context, "stableGaAuthorization")

            self.assertNotIn(secret, str(raised.exception))

    def test_json_input_rejects_duplicate_fields_before_digest_binding(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "authorization.json"
            path.write_text(
                '{"schemaVersion":1,"status":"authorized","status":"invalid"}\n',
                encoding="utf-8",
            )
            context = _context(root, {"stableGaAuthorization": path.name})

            with self.assertRaisesRegex(ValueError, "duplicate JSON field"):
                load_json_input(context, "stableGaAuthorization")

    def test_input_rejects_workspace_escape_and_symlinked_parent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workspace = root / "workspace"
            workspace.mkdir()
            outside = root / "outside.json"
            write_json(outside, {"status": "pass"})
            escape_context = _context(workspace, {"stableGaPolicy": "../outside.json"})

            with self.assertRaisesRegex(ValueError, "escapes the workspace"):
                configured_input_path(escape_context, "stableGaPolicy")

            inputs = workspace / "inputs"
            try:
                inputs.symlink_to(root, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"directory symlinks are unavailable: {exc}")
            symlink_context = _context(
                workspace,
                {"stableGaPolicy": "inputs/outside.json"},
            )

            with self.assertRaisesRegex(ValueError, "contains a symlink"):
                configured_input_path(symlink_context, "stableGaPolicy")

    def test_semantic_ga_identity_digest_is_deterministic_and_candidate_sensitive(self) -> None:
        selected = _selected_rc()
        context = _context()
        validation = _post_freeze_validation(selected, _policy())
        identity = _identity_fixture(context, selected, validation)
        reordered = dict(reversed(list(copy.deepcopy(identity).items())))

        first = semantic_digest(identity)
        second = semantic_digest(reordered)
        changed = copy.deepcopy(identity)
        changed["payloadIdentity"]["gaProductDigest"] = _digest("0")
        changed_targets_context = _context()
        changed_targets_context.manifest.policies["metadata"][
            "catalogMirrorUris"
        ] = (
            "https://second-mirror.crypta.network/first-party-catalog.properties,"
            "https://mirror.crypta.network/first-party-catalog.properties"
        )
        changed_targets = canonical_publication_targets(changed_targets_context)

        self.assertEqual(first, second)
        self.assertNotEqual(first, semantic_digest(changed))
        self.assertNotEqual(
            identity["publicationTargetsDigest"],
            semantic_digest(changed_targets),
        )

    def test_generated_ga_validation_is_schema_valid_and_bit_identical(self) -> None:
        selected = _selected_rc()
        context = _context()
        policy = _policy()
        rc_validation = _post_freeze_validation(selected, policy)
        lineage_digest = semantic_digest(_lineage(selected))
        rc_validation_digest = semantic_digest(rc_validation)
        identity = ga_validation_authorization_identity(
            context,
            selected,
            lineage_digest,
            rc_validation,
            rc_validation_digest,
            _upgrade_predecessor(selected),
            [],
        )
        authorization = _authorization(selected, identity)
        record = build_ga_validation_record(
            context,
            selected,
            lineage_digest,
            rc_validation,
            rc_validation_digest,
            _upgrade_predecessor(selected),
            authorization,
            semantic_digest(authorization),
            True,
            [],
            ValidationState(),
        )

        self.assertEqual([], validate_schema(record, GA_VALIDATION_SCHEMA))
        self.assertEqual(
            record["payloadIdentity"]["rcProductDigest"],
            record["payloadIdentity"]["gaProductDigest"],
        )
        self.assertIs(record["payloadIdentity"]["bitIdentical"], True)
        self.assertIs(record["payloadIdentity"]["rebuildPerformed"], False)


if __name__ == "__main__":
    unittest.main()
