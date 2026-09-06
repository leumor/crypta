"""Offline contract tests for Stable 1.0 maintenance and security-hotfix releases."""

from __future__ import annotations

import copy
import dataclasses
import inspect
import io
import json
import shutil
import stat
import tarfile
import tempfile
import unittest
import warnings
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from cryptad_certification.cli import (
    _validate_stable_maintenance_manifest,
)
from cryptad_certification.engines import (
    stable_1_0_ga,
    stable_1_0_ga_core,
    stable_1_0_maintenance,
    stable_1_0_maintenance_compatibility as compatibility,
    stable_1_0_maintenance_core as core,
)
from cryptad_certification.engines.stable_1_0_maintenance import (
    _apply_lifecycle_promotion_gate,
    _authorization,
    _authorization_expected,
    _close_authorization_errors,
    _concurrent_follow_up_errors,
    _core_receipt_errors,
    _lifecycle_input_presence_errors,
    _lineage,
    _public_lifecycle_observation_errors,
    _public_assets,
    _public_checksum_payload_paths,
    _receipt_errors,
    _successor,
    _write_checksums,
)
from cryptad_certification.engines.stable_1_0_maintenance_compatibility import (
    _app_errors,
    _catalog_errors,
    _content_profile_errors,
    _hotfix_follow_up,
    _known_limitations_digest,
    _limitation_delta_digest,
    _limitation_errors,
    _platform_api_errors,
    build_comparison,
    close_hotfix_follow_up,
    validate_production_evidence,
)
from cryptad_certification.engines.stable_1_0_maintenance_core import (
    AUTHORIZATION_SCHEMA,
    AUTHORIZATION_SCOPE,
    CANDIDATE_FREEZE_SCHEMA,
    Candidate,
    GaRoot,
    LoadedJson,
    Predecessor,
    _candidate_package_notarization_errors,
    _candidate_freeze_errors,
    _candidate_provenance_errors,
    _package_matrix_scope_errors,
    _package_identity_errors,
    archive_hygiene_errors,
    authenticate_ga_root,
    authenticate_predecessor,
    build_core_info,
    receipt_identity,
    select_candidate_dmg_for_freeze,
    stable_catalog_verification_identity,
    successor_baseline_identity,
)
from cryptad_certification.engines.stable_1_0_rc_core import (
    ValidationState,
    file_digest,
    semantic_digest,
)
from cryptad_certification.engines.stable_1_0_rc_artifacts import (
    normalize_portable_distribution_archive,
)
from cryptad_certification.io import read_json, write_json
from cryptad_certification.manifest import INPUT_FIELDS, POLICY_FIELDS
from cryptad_certification.models import OutputSpec, ReleaseSpec, RunContext, RunManifest
from cryptad_certification.schema_validation import validate_schema
from cryptad_certification.tests.support import (
    release_train_evidence_result,
    workspace_root,
)
from cryptad_certification.tests.test_stable_ga import (
    NOW as GA_NOW,
    _authorized_ga_run_context,
    _receipt as _ga_receipt,
)


NOW = datetime(2026, 7, 18, 12, 0, tzinfo=timezone.utc)
FROZEN = NOW - timedelta(days=2)
RELEASE_ID = "stable-1-0-maintenance-301"
BUILD = "301"
PREDECESSOR_BUILD = "300"
GA_RELEASE_ID = "stable-1-0-ga-300"
COMMIT = "a" * 40
PRODUCT_DIGEST = "sha256:" + "1" * 64
PREDECESSOR_PRODUCT_DIGEST = "sha256:" + "2" * 64
APP_IDS = (
    "queue-manager",
    "publisher",
    "site-publisher",
    "profile-publisher",
    "social-inbox",
    "feed-reader",
    "trust-graph",
)
PROFILE_IDS = (
    "crypta.profile.v1",
    "crypta.feed.snapshot.v1",
    "crypta.trust.statement.v1",
    "crypta.social.message.v1",
    "crypta.social.outbox.v1",
)
PACKAGE_KEYS = (
    "amd64.deb",
    "amd64.dmg",
    "amd64.exe",
    "amd64.rpm",
    "arm64.deb",
    "arm64.dmg",
    "arm64.exe",
    "arm64.rpm",
)
REQUIRED_PACKAGE_KEYS = (
    "amd64.deb",
    "amd64.dmg",
    "amd64.exe",
    "amd64.rpm",
)


def _digest(character: str) -> str:
    return "sha256:" + character * 64


def _timestamp(value: datetime = NOW) -> str:
    return value.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _redaction() -> dict[str, object]:
    return {"status": "pass", "findingCount": 0, "findings": []}


def _policy() -> dict[str, object]:
    path = workspace_root() / "tools/release-certification/stable-1.0-maintenance-policy.json"
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _app_compatibility_errors(
    ga: object, predecessor: object, candidate: object
) -> list[str]:
    return _app_errors(ga, predecessor, candidate, _policy())


def _required_inputs() -> dict[str, str]:
    names = {
        "stableGaPromotionSummary",
        "stableGaValidation",
        "stableGaAuthorizationSummary",
        "stableGaPublicationPlan",
        "stableGaPublicationReceipt",
        "stableGaChecksums",
        "stableGaProvenance",
        "stableGaMaintenanceBaseline",
        "predecessorPublicationReceipt",
        "predecessorBaseline",
        "maintenanceCandidate",
        "maintenanceCandidateFreeze",
        "maintenanceCandidateAssets",
        "maintenanceCandidateChecksums",
        "maintenanceCandidateProvenance",
        "maintenanceEvidence",
        "maintenancePolicy",
        "stableBackportReleaseTrainAuthorization",
        "stableBackportReleaseTrainValidation",
        "supplyChainPromotionSummary",
    }
    return {name: f"inputs/{name}.json" for name in names}


def _context(
    root: Path,
    *,
    release_class: str = "maintenance",
    mode: str = "validate-only",
    inputs: dict[str, str] | None = None,
) -> RunContext:
    branch = "release" if release_class == "maintenance" else "hotfix"
    manifest = RunManifest(
        path=root / "maintenance.json",
        release=ReleaseSpec(RELEASE_ID, BUILD, "stable-review"),
        output=OutputSpec(root / "build/release-certification"),
        requirements={"stableSupplyChain": mode != "close-hotfix-follow-up"},
        inputs={} if inputs is None else inputs,
        policies={
            "artifactBaseUri": "https://93.184.216.34/artifacts/stable",
            "candidateBaseCommit": "b" * 40,
            "candidateSourceBranch": f"{branch}/{BUILD}",
            "candidateSourceCommit": COMMIT,
            "candidateSourceRef": f"commit:{COMMIT}",
            "catalogChannel": "stable",
            "expectedPredecessorBuild": PREDECESSOR_BUILD,
            "expectedPredecessorReleaseId": "stable-1-0-ga-300",
            "expectedPredecessorProductDigest": PREDECESSOR_PRODUCT_DIGEST,
            "publicationIntent": "prepare-explicit-protected-publication",
            "releaseClass": release_class,
            **(
                {}
                if mode == "close-hotfix-follow-up"
                else {"stableSupplyChainGovernance": "required"}
            ),
            "metadata": {
                "githubReleasePageUri": "https://github.com/crypta-network/cryptad/releases/tag/v301",
                "catalogPrimaryUri": "https://93.184.216.34/catalog/stable/catalog.json",
                "catalogMirrorUris": "https://93.184.216.34/mirror/stable/catalog.json",
                "catalogRollbackUri": "https://93.184.216.34/catalog/stable/history/300.json",
                "coreUpdatePublicUri": "https://93.184.216.34/updates/info/301/core-info.json",
                "deploymentServicePublicUri": "https://93.184.216.34/deployment/observe",
                "latestPointerPublicUri": "https://93.184.216.34/maintenance/latest.json",
            },
        },
        execution={},
        commands={"stable-maintenance": {"mode": mode}},
    )
    return RunContext(
        workspace_root=root.resolve(),
        run_root=root / "build/release-certification" / RELEASE_ID,
        component="stable-maintenance",
        manifest=manifest,
    )


def _published_ga_maintenance_context(root: Path) -> tuple[RunContext, Path]:
    """Materialize one deterministic PR-284 completion graph for maintenance tests."""

    workspace = workspace_root()
    ga_context, _paths, selected = _authorized_ga_run_context(root, workspace)
    output = ga_context.component_dir / "artifacts" / "legacy"
    output.mkdir(parents=True)
    network_result = [(None, None, None, None, ("93.184.216.34", 443))]
    with mock.patch.object(
        stable_1_0_ga, "_utc_now", return_value=GA_NOW
    ), mock.patch.object(
        stable_1_0_ga_core.socket, "getaddrinfo", return_value=network_result
    ):
        code = stable_1_0_ga._run(ga_context, output, ValidationState())  # noqa: SLF001
    if code != 0:
        raise AssertionError("deterministic Stable GA authorization fixture failed")
    plan = read_json(output / "stable-1.0-ga-publication-plan.json")
    if not isinstance(plan, dict):
        raise AssertionError("Stable GA fixture publication plan is malformed")
    planned_assets = [
        {key: row[key] for key in ("name", "sizeBytes", "digest")}
        for row in plan["assets"]
    ]
    receipt = _ga_receipt(
        selected,
        str(plan["promotionIdentityDigest"]),
        str(plan["releaseNotesDigest"]),
        planned_assets,
    )
    receipt["artifactBaseUri"] = plan["artifactBaseUri"]
    for row in receipt["assets"]:
        row["publicUri"] = str(plan["artifactBaseUri"]) + str(row["name"])
    plan_catalog = plan["catalog"]
    receipt_catalog = receipt["catalog"]
    receipt_catalog["primary"]["publicUri"] = plan_catalog["primary"]["publicUri"]
    for observed, planned in zip(
        receipt_catalog["mirrors"], plan_catalog["mirrors"], strict=True
    ):
        observed["publicUri"] = planned["publicUri"]
    receipt_catalog["rollback"]["publicUri"] = plan_catalog["rollbackUri"]
    receipt_catalog["rollback"]["revision"] = plan_catalog["rollbackRevision"]
    receipt_catalog["rollback"]["digest"] = plan_catalog["rollbackDigest"]
    receipt_path = root / "stable-1.0-ga-publication-receipt.json"
    write_json(receipt_path, receipt)
    ga_context.manifest.inputs["stableGaPublicationReceipt"] = receipt_path.relative_to(
        workspace
    ).as_posix()
    shutil.rmtree(output)
    output.mkdir(parents=True)
    with mock.patch.object(
        stable_1_0_ga, "_utc_now", return_value=GA_NOW
    ), mock.patch.object(
        stable_1_0_ga_core.socket, "getaddrinfo", return_value=network_result
    ):
        code = stable_1_0_ga._run(ga_context, output, ValidationState())  # noqa: SLF001
    if code != 0:
        raise AssertionError("deterministic Stable GA publication fixture failed")
    ga_inputs = {
        "stableGaPromotionSummary": "stable-1.0-ga-promotion-summary.json",
        "stableGaValidation": "stable-1.0-ga-validation.json",
        "stableGaAuthorizationSummary": "stable-1.0-ga-authorization-summary.json",
        "stableGaPublicationPlan": "stable-1.0-ga-publication-plan.json",
        "stableGaPublicationReceipt": "stable-1.0-ga-publication-receipt.json",
        "stableGaChecksums": "stable-1.0-ga-checksums.txt",
        "stableGaProvenance": "stable-1.0-ga-provenance.json",
        "stableGaMaintenanceBaseline": "stable-1.0-maintenance-baseline.json",
    }
    inputs = {
        key: (output / name).relative_to(workspace).as_posix()
        for key, name in ga_inputs.items()
    }
    manifest = RunManifest(
        path=root / "stable-1.0-maintenance.json",
        release=ReleaseSpec(RELEASE_ID, BUILD, "stable-review"),
        output=OutputSpec(root / "maintenance-output"),
        requirements={},
        inputs=inputs,
        policies={},
        execution={},
        commands={"stable-maintenance": {"mode": "validate-only"}},
    )
    return (
        RunContext(
            workspace_root=workspace,
            run_root=root / "maintenance-output" / RELEASE_ID,
            component="stable-maintenance",
            manifest=manifest,
        ),
        output,
    )


def _platform_api() -> dict[str, object]:
    deprecation_history: list[dict[str, object]] = []
    return {
        "baselineName": "1.0",
        "baselineDigest": _digest("3"),
        "baselineContractVersion": 23,
        "currentContractVersion": 24,
        "currentContractDigest": _digest("4"),
        "stableSurfaceDigest": _digest("5"),
        "compatibilityWindowPolicyDigest": _digest("6"),
        "stableDiffDigest": _digest("7"),
        "thirdPartyCompatibilityEvidenceDigest": _digest("8"),
        "deprecationHistoryDigest": semantic_digest(deprecation_history),
        "deprecationHistory": deprecation_history,
        "removedStableEndpoints": [],
        "removedStableCapabilities": [],
        "breakingStableChanges": [],
        "criticalRemovalWaiverAttempt": False,
        "deprecationClockReset": False,
        "experimentalMislabelledStable": False,
        "additionsBackwardCompatible": True,
        "thirdPartyCompatibilityStatus": "pass",
    }


def _ga_platform_api() -> dict[str, object]:
    value = _platform_api()
    value["currentContractVersion"] = 23
    value["currentContractDigest"] = _digest("a")
    value.update(
        {
            "minimumDeprecationWindowContractVersions": 2,
            "minimumRemovalWindowContractVersions": 2,
            "criticalStableRemovalWaiverAllowed": False,
        }
    )
    return value


def _catalog() -> dict[str, object]:
    return {
        "catalogId": "crypta-first-party",
        "channel": "stable",
        "revision": 8,
        "edition": 8,
        "digest": _digest("b"),
        "signatureDigest": _digest("c"),
        "signingKeyId": "catalog-production-2026",
        "deltaDigest": _digest("d"),
        "signatureStatus": "pass",
        "keyTrustStatus": "pass",
        "mirrorStatus": "pass",
        "rollbackStatus": "pass",
        "advisoryStatus": "pass",
        "denylistStatus": "pass",
        "keyRotationTrustTransitionStatus": "not-applicable",
    }


def _limitations(
    predecessor_ids: set[str] | None = None,
    *,
    added_ids: set[str] | None = None,
    resolved_ids: set[str] | None = None,
) -> dict[str, object]:
    predecessor = {"stable-known-001"} if predecessor_ids is None else predecessor_ids
    added = set() if added_ids is None else added_ids
    resolved = set() if resolved_ids is None else resolved_ids
    unchanged = predecessor - resolved
    current = added | unchanged
    return {
        "knownLimitationsDigest": _known_limitations_digest(current),
        "deltaDigest": _limitation_delta_digest(
            predecessor, added, resolved, unchanged
        ),
        "addedCount": len(added),
        "resolvedCount": len(resolved),
        "unchangedCount": len(unchanged),
        "addedIds": sorted(added),
        "resolvedIds": sorted(resolved),
        "unchangedIds": sorted(unchanged),
        "changesReviewed": True,
        "noHiddenLimitations": True,
    }


def _apps(*, candidate: bool) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for app_id in APP_IDS:
        row: dict[str, object] = {
            "appId": app_id,
            "version": BUILD if candidate else PREDECESSOR_BUILD,
            "channel": "stable",
            "supportLevel": "maintained",
            "bundleDigest": _digest("e"),
            "reviewReceiptDigest": _digest("f"),
            "appSigningKeyId": "app-production-2026",
            "reviewerKeyId": "reviewer-production-2026",
            "manifestDigest": _digest("0"),
            "permissionSetDigest": _digest("1"),
            "apiCompatibilityEvidenceDigest": _digest("2"),
            "appDataSchemaVersion": 1,
            "migrationEvidenceDigest": _digest("3"),
            "backupRestoreEvidenceDigest": _digest("4"),
            "supportMetadataDigest": _digest("5"),
        }
        if candidate:
            row.update(
                {
                    "trustState": "trusted",
                    "reviewStatus": "pass",
                    "signingStatus": "pass",
                    "apiCompatibilityStatus": "pass",
                    "migrationStatus": "pass",
                    "backupRestoreStatus": "pass",
                    "serviceGrantStatus": "pass",
                    "permissionExpansion": False,
                    "permissionConsentStatus": "not-applicable",
                    "permissionRationaleStatus": "not-applicable",
                    "reviewedBundleDigest": row["bundleDigest"],
                }
            )
        rows.append(row)
    return rows


def _profiles(*, candidate: bool) -> list[dict[str, object]]:
    rows = []
    for profile_id in PROFILE_IDS:
        row: dict[str, object] = {
            "profileId": profile_id,
            "version": 1,
            "status": "stable",
            "descriptorDigest": _digest("6"),
            "canonicalizationRulesDigest": _digest("7"),
            "maximumSizePolicyDigest": _digest("8"),
            "signaturePayloadRulesDigest": _digest("9"),
            "parserVerifierCompatibilityEvidenceDigest": _digest("a"),
        }
        if candidate:
            row.update(
                {"existingValidDocumentsAccepted": True, "acceptanceStatus": "pass"}
            )
        rows.append(row)
    return rows


def _candidate_input(release_class: str = "maintenance") -> dict[str, object]:
    branch = "release" if release_class == "maintenance" else "hotfix"
    catalog = _catalog()
    catalog["fileName"] = "stable-catalog.json"
    catalog["sizeBytes"] = 1024
    catalog["signatureFileName"] = "stable-catalog.json.sig"
    catalog["signatureSizeBytes"] = 256
    scope = {
        "categories": ["compatible-bug-fixes"],
        "changedModules": ["runtime-node"],
        "publicUserVisibleFixes": ["Correct updater package selection."],
        "unrelatedFeatureChanges": [],
        "auditDigest": _digest("b"),
        "incidentId": None,
        "severity": None,
        "affectedPackageKeys": [],
        "shortenedEvidenceIds": (
            [
                "stable-maintenance.live-network-interoperability",
                "stable-maintenance.performance",
                "stable-maintenance.support-redaction",
            ]
            if release_class == "security-hotfix"
            else []
        ),
        "unaffectedPackageProofStatus": "not-applicable",
        "hotfixPolicyAuthorizationDigest": None,
        "followUpOwner": None,
        "followUpApprover": None,
    }
    if release_class == "security-hotfix":
        scope.update(
            {
                "categories": ["security-fixes-and-hotfixes"],
                "incidentId": "CRYPTA-SEC-2026-001",
                "severity": "critical",
                "affectedPackageKeys": list(REQUIRED_PACKAGE_KEYS),
                "hotfixPolicyAuthorizationDigest": _digest("c"),
                "followUpOwner": "stable-security-team",
                "followUpApprover": "stable-security-release-manager",
            }
        )
    return {
        "schemaVersion": 1,
        "kind": "stable-1.0-maintenance-candidate-input",
        "generatedAt": _timestamp(),
        "stableMilestone": "1.0",
        "releaseId": RELEASE_ID,
        "buildVersion": BUILD,
        "releaseClass": release_class,
        "candidateFreezeDigest": _digest("f"),
        "builtOnce": True,
        "rebuildCount": 0,
        "source": {
            "branch": f"{branch}/{BUILD}",
            "ref": f"commit:{COMMIT}",
            "commit": COMMIT,
            "baseBranch": "develop" if release_class == "maintenance" else "main",
            "baseCommit": "b" * 40,
            "clean": True,
            "treeState": "clean",
            "branchHeadVerified": True,
            "immutableRefVerified": True,
            "currentPublishedMainBaseVerified": release_class == "security-hotfix",
            "sourceTreeDigest": _digest("d"),
        },
        "toolchain": {
            "javaVersion": "25.0.1",
            "javaMajorVersion": 25,
            "gradleVersion": "9.1.0",
            "gradleWrapperDigest": _digest("e"),
            "dependencyVerificationDigest": _digest("f"),
            "dependencyVerificationStatus": "pass",
            "buildLogicDigest": _digest("0"),
            "buildTasks": ["assembleCryptadDist"],
            "productionSigning": True,
            "testSigning": False,
        },
        "product": {
            "fileName": "cryptad-301.tar.gz",
            "digest": PRODUCT_DIGEST,
            "sizeBytes": 1024,
            "archiveFormat": "tar.gz",
            "archiveIntegrityStatus": "pass",
            "checksumsDigest": _digest("1"),
            "frozenAt": _timestamp(FROZEN),
            "rebuildPerformed": False,
        },
        "packages": [],
        "platformApi": _platform_api(),
        "stableCatalog": catalog,
        "firstPartyApps": _apps(candidate=True),
        "contentFormatProfiles": _profiles(candidate=True),
        "limitations": _limitations(),
        "security": {
            "advisoryDigest": _digest("5"),
            "denylistDigest": _digest("6"),
            "keyStateDigest": _digest("7"),
            "securityEvidenceDigest": _digest("8"),
            "signingKeysUncompromised": True,
            "advisoryStatus": "pass",
            "denylistStatus": "pass",
            "securityEvidenceStatus": "pass",
        },
        "support": {
            "supportLevelDigest": _digest("9"),
            "diagnosticsEvidenceDigest": _digest("a"),
            "supportBundleDigest": _digest("b"),
            "supportStatus": "pass",
            "diagnosticsStatus": "pass",
            "supportCommitmentReduced": False,
            "redactionStatus": "pass",
        },
        "legacyBoundaries": {
            "pluginRuntime": "removed",
            "inCorePluginApi": "removed",
            "legacyAdminMutationRoutes": "disabled",
            "fproxyBrowse": "retained",
            "contentFiltering": "retained",
            "emergencyFallbackRoutes": "retained",
        },
        "changeScope": scope,
        "coreUpdateChangelog": {
            "shortChk": "CHK@" + "C" * 43 + "," + "D" * 43 + ",AAIC--8/short.txt",
            "fullChk": "CHK@" + "E" * 43 + "," + "F" * 43 + ",AAIC--8/full.txt",
        },
        "redaction": _redaction(),
    }


def _packages() -> list[dict[str, object]]:
    rows = []
    for index, key in enumerate(PACKAGE_KEYS):
        extension = key.rsplit(".", 1)[1]
        rows.append(
            {
                "packageKey": key,
                "fileName": key.replace(".", "-") + ".pkg",
                "os": "linux" if extension in {"deb", "rpm"} else ("macos" if extension == "dmg" else "windows"),
                "arch": key.split(".", 1)[0],
                "producerArchitecture": key.split(".", 1)[0],
                "packageType": extension,
                "digest": _digest(format(index, "x")),
                "sizeBytes": 1000 + index,
                "buildVersion": BUILD,
                "sourceCommit": COMMIT,
                "publicChk": (
                    "CHK@"
                    + "A" * 43
                    + ","
                    + "B" * 43
                    + f",AAIC--{index}/cryptad-{index}.{extension}"
                ),
                "storeUrl": None,
                "signingStatus": "pass",
                "notarizationStatus": "pass" if extension == "dmg" else "not-applicable",
                "installLaunchStatus": "pass",
                "upgradeStatus": "pass",
                "installLaunchEvidenceDigest": _digest("c"),
                "upgradeEvidenceDigest": _digest("d"),
                "uninstallDataRetention": "retained",
                "redactionStatus": "pass",
            }
        )
    return rows


def _candidate(root: Path, release_class: str = "maintenance") -> Candidate:
    value = _candidate_input(release_class)
    packages = _packages()
    value["packages"] = packages
    product = root / "cryptad-301.tar.gz"
    product.parent.mkdir(parents=True, exist_ok=True)
    product.write_bytes(b"candidate-product")
    source = value["source"]
    assert isinstance(source, dict)
    return Candidate(
        source=source,
        input_value=value,
        input_digest=_digest("e"),
        freeze_digest=_digest("f"),
        frozen_at=_timestamp(FROZEN),
        product_path=product,
        product_digest=PRODUCT_DIGEST,
        assets=packages,
        asset_paths={product.name: product},
        checksums_digest=_digest("f"),
        provenance_digest=_digest("0"),
        identity={"kind": "stable-1.0-maintenance-candidate"},
        identity_digest=_digest("1"),
    )


def _ga_and_predecessor() -> tuple[GaRoot, Predecessor]:
    catalog = _catalog()
    catalog["edition"] = 7
    catalog["revision"] = 7
    baseline = {
        "schemaVersion": 1,
        "platformApi": _ga_platform_api(),
        "stableCatalog": catalog,
        "firstPartyApps": _apps(candidate=False),
        "contentFormatProfiles": _profiles(candidate=False),
        "limitations": {
            "stableKnownLimitationsDigest": _digest("2"),
            "allowedLimitations": [{"id": "stable-known-001"}],
        },
        "securityBaseline": {"digest": _digest("3")},
        "supportBaseline": {"digest": _digest("4")},
        "legacyBoundaries": _candidate_input()["legacyBoundaries"],
    }
    ga = GaRoot(
        baseline=baseline,
        baseline_digest=_digest("5"),
        receipt={"publicationState": "publication-complete"},
        receipt_digest=_digest("6"),
        release_id=GA_RELEASE_ID,
        build_version=PREDECESSOR_BUILD,
        source_commit="b" * 40,
        product_digest=PREDECESSOR_PRODUCT_DIGEST,
        tag="v300",
        root_identity_digest=_digest("7"),
    )
    history = [
        {
            "chainDepth": 0,
            "releaseId": ga.release_id,
            "buildVersion": ga.build_version,
            "tag": ga.tag,
            "sourceCommit": ga.source_commit,
            "releaseClass": "stable-ga",
            "productDigest": ga.product_digest,
            "baselineIdentityDigest": ga.root_identity_digest,
            "publicationReceiptIdentityDigest": semantic_digest(ga.receipt),
            "previousLineageDigest": ga.root_identity_digest,
        }
    ]
    predecessor = Predecessor(
        baseline=baseline,
        baseline_digest=ga.baseline_digest,
        receipt=ga.receipt,
        receipt_digest=ga.receipt_digest,
        release_id=ga.release_id,
        build_version=ga.build_version,
        source_commit=ga.source_commit,
        product_digest=ga.product_digest,
        tag=ga.tag,
        chain_depth=0,
        previous_lineage_digest=ga.root_identity_digest,
        lineage_history=history,
        outstanding_follow_up=None,
    )
    return ga, predecessor




def _evidence(release_class: str = "maintenance", *, window: str = "normal") -> dict[str, object]:
    start = NOW - (timedelta(days=1) if window == "normal" else timedelta(hours=1))
    evidence_ids = [
        *core.REQUIRED_PRODUCTION_EVIDENCE,
        "stable-maintenance.direct-ga-upgrade",
        "stable-maintenance.candidate-identity",
        "stable-maintenance.platform-api-compatibility",
    ]
    rows = []
    digest_characters = "0123456789abcdef"
    for index, evidence_id in enumerate(evidence_ids):
        direct_ga = evidence_id == "stable-maintenance.direct-ga-upgrade"
        rows.append(
            {
                "evidenceId": evidence_id,
                "status": "pass",
                "candidateReleaseId": RELEASE_ID,
                "candidateBuild": BUILD,
                "candidateProductDigest": PRODUCT_DIGEST,
                "candidateFreezeDigest": _digest("f"),
                "predecessorBuild": PREDECESSOR_BUILD,
                "predecessorProductDigest": PREDECESSOR_PRODUCT_DIGEST,
                "gaReleaseId": GA_RELEASE_ID if direct_ga else None,
                "gaBuild": PREDECESSOR_BUILD if direct_ga else None,
                "gaProductDigest": PREDECESSOR_PRODUCT_DIGEST if direct_ga else None,
                "startedAt": _timestamp(start),
                "endedAt": _timestamp(),
                "environmentClass": "production",
                "production": True,
                "nodeCount": 2,
                "operationCount": 500,
                "evidenceDigest": _digest(digest_characters[index]),
                "fresh": True,
                "redactionStatus": "pass",
            }
        )
    return {
        "schemaVersion": 1,
        "kind": "stable-1.0-maintenance-evidence",
        "generatedAt": _timestamp(),
        "releaseId": RELEASE_ID,
        "buildVersion": BUILD,
        "releaseClass": release_class,
        "candidateProductDigest": PRODUCT_DIGEST,
        "candidateFreezeDigest": _digest("f"),
        "predecessorBuild": PREDECESSOR_BUILD,
        "predecessorProductDigest": PREDECESSOR_PRODUCT_DIGEST,
        "windowClass": window,
        "validationStartedAt": _timestamp(start),
        "validationEndedAt": _timestamp(),
        "productionEvidence": True,
        "fixtureOnly": False,
        "simulatedOnly": False,
        "skipped": False,
        "evidenceRows": rows,
        "redaction": _redaction(),
    }


class StableMaintenanceRegistrationTest(unittest.TestCase):
    """Command, manifest, policy, and schema registration contracts."""


    def test_release_run_allowlists_match_maintenance_contract(self) -> None:
        for field in (
            "maintenanceCandidate",
            "maintenanceCandidateFreeze",
            "maintenanceEvidence",
            "stableGaMaintenanceBaseline",
            "predecessorPublicationReceipt",
            "previousStableLifecycleLedger",
            "previousStableLifecycleDescriptor",
            "stableLifecycleAuthorization",
            "stableLifecyclePublicationPlan",
            "stableLifecyclePublicationReceipt",
            "coreUpdatePublicationReceipt",
            "hotfixFollowUpEvidence",
        ):
            with self.subTest(field=field):
                self.assertIn(field, INPUT_FIELDS)
        for field in (
            "candidateSourceBranch",
            "expectedPredecessorBuild",
            "expectedPredecessorProductDigest",
            "releaseClass",
        ):
            with self.subTest(field=field):
                self.assertIn(field, POLICY_FIELDS)

    def test_policy_has_closed_integer_release_classes_and_nonwaivable_gates(self) -> None:
        policy = _policy()
        self.assertEqual(policy["stableMilestone"], "1.0")
        self.assertEqual(policy["releaseClasses"], ["maintenance", "security-hotfix"])
        self.assertEqual(
            policy["branchPolicy"]["maintenance"]["branchPattern"],
            "^release/[1-9][0-9]*$",
        )
        self.assertEqual(
            policy["branchPolicy"]["security-hotfix"]["branchPattern"],
            "^hotfix/[1-9][0-9]*$",
        )
        self.assertTrue(policy["publication"]["validationIsSideEffectFree"])
        self.assertTrue(
            policy["catalogAndApps"][
                "requiresCatalogVersionAdvanceForIdentityChange"
            ]
        )
        self.assertTrue(policy["limitations"]["requiresDisjointDeltaPartition"])
        self.assertEqual(
            policy["limitations"]["successorMembershipField"],
            "limitations.currentIds",
        )
        self.assertEqual(
            policy["packageMatrix"]["requiredCoreUpdatePackageKeys"],
            list(REQUIRED_PACKAGE_KEYS),
        )
        self.assertEqual(
            policy["catalogAndApps"]["supportLevelOrder"],
            ["local-rc", "maintained", "core"],
        )
        self.assertTrue(policy["hotfix"]["requiresNonemptyAffectedPackageKeys"])
        self.assertTrue(
            policy["hotfix"]["requiresExactAffectedKeysForNarrowedMatrix"]
        )
        self.assertEqual(
            policy["hotfix"]["fullMatrixUnaffectedPackageProofStatus"],
            "not-applicable",
        )
        self.assertEqual(
            policy["hotfix"]["narrowedMatrixUnaffectedPackageProofStatus"],
            "pass",
        )
        blockers = set(policy["nonWaivableBlockers"])
        self.assertIn("stable-maintenance.candidate-identity", blockers)
        self.assertIn("stable-maintenance.support-redaction", blockers)

    def test_protected_workflow_signs_and_reverifies_every_package_producer_asset(
        self,
    ) -> None:
        policy = _policy()["packageMatrix"]["assetSigning"]
        self.assertEqual(policy["method"], "sigstore-github-attestation")
        self.assertTrue(policy["exactByteSubjectsRequired"])
        self.assertTrue(policy["perAssetVerificationReceiptRequired"])
        self.assertTrue(policy["producerVerificationRequired"])
        self.assertTrue(policy["freezeBoundaryReverificationRequired"])
        self.assertFalse(policy["privateKeyInputAllowed"])

        workflow = (
            workspace_root()
            / ".github/workflows/stable-1.0-maintenance-release.yml"
        ).read_text(encoding="utf-8")
        for required in (
            "Cryptographically attest every exact package producer asset",
            "actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6",
            "subject-path: build/stable-maintenance-package-output/",
            "Independently verify and bind every exact package producer attestation",
            'signingMethod: "sigstore-github-attestation"',
            '"gh", "attestation", "verify", str(asset)',
            "product_signing_receipt = signing_receipt_by_name.get(product_path.name)",
            'package["packageType"] in {"deb", "rpm", "dmg"}',
        ):
            with self.subTest(required=required):
                self.assertIn(required, workflow)
        self.assertNotIn("CRYPTAD_LINUX_PACKAGE_SIGNING_PRIVATE_KEY", workflow)
        self.assertNotIn("CRYPTAD_LINUX_PACKAGE_SIGNING_PASSPHRASE", workflow)

    def test_protected_workflow_resolves_candidate_inputs_before_reading_bytes(self) -> None:
        workflow = (
            workspace_root()
            / ".github/workflows/stable-1.0-maintenance-release.yml"
        ).read_text(encoding="utf-8")
        for required in (
            'protected_root = Path("build/protected-inputs").resolve(strict=True)',
            "resolved.relative_to(protected_root)",
            'candidate_path = protected_input(inputs["maintenanceCandidate"])',
            'source_assets = protected_input(inputs["maintenanceCandidateAssets"], directory=True)',
            'baseline_path = protected_input(inputs["predecessorBaseline"])',
            'receipt_path = protected_input(inputs["predecessorPublicationReceipt"])',
        ):
            with self.subTest(required=required):
                self.assertIn(required, workflow)
        self.assertNotIn(
            'str(path).startswith("build/protected-inputs/")',
            workflow,
        )

    def test_protected_workflow_rejects_build_drift_and_omitted_predecessor(self) -> None:
        workflow = (
            workspace_root()
            / ".github/workflows/stable-1.0-maintenance-release.yml"
        ).read_text(encoding="utf-8")

        def step(name: str) -> str:
            marker = f"      - name: {name}"
            start = workflow.index(marker)
            end = workflow.find("\n      - name:", start + len(marker))
            return workflow[start:] if end == -1 else workflow[start:end]

        drift_gate = step("Reject tracked source or index drift after package build")
        self.assertIn('git rev-parse HEAD^{commit}', drift_gate)
        self.assertIn("git diff-index --quiet --cached HEAD --", drift_gate)
        self.assertIn("git diff-files --quiet --", drift_gate)
        self.assertIn("git status --short --untracked-files=no", drift_gate)
        self.assertLess(
            workflow.index("Reject tracked source or index drift after package build"),
            workflow.index("Stage exact package producer output"),
        )

        ancestry_gate = step("Authenticate source ancestry and exact change scope")
        self.assertIn(".inputs.predecessorBaseline", ancestry_gate)
        self.assertIn(".release.sourceCommit", ancestry_gate)
        self.assertGreaterEqual(ancestry_gate.count("git merge-base --is-ancestor"), 2)
        self.assertIn(
            '"$predecessor_commit" "$INPUT_CANDIDATE_COMMIT"', ancestry_gate
        )

    def test_all_new_object_schemas_are_closed(self) -> None:
        names = (
            core.CANDIDATE_INPUT_SCHEMA,
            core.CANDIDATE_FREEZE_SCHEMA,
            core.EVIDENCE_SCHEMA,
            core.LINEAGE_SCHEMA,
            core.COMPARISON_SCHEMA,
            core.VALIDATION_SCHEMA,
            core.AUTHORIZATION_SCHEMA,
            "stable-1.0-maintenance-activation-authorization-v1.schema.json",
            core.PUBLICATION_PLAN_SCHEMA,
            core.PUBLICATION_RECEIPT_SCHEMA,
            core.PUBLICATION_FAILURE_AUDIT_SCHEMA,
            core.SUCCESSOR_SCHEMA,
            core.FOLLOW_UP_SCHEMA,
            core.FOLLOW_UP_CLOSURE_SCHEMA,
            core.CORE_INFO_SCHEMA,
            core.CORE_PLAN_SCHEMA,
            core.CORE_RECEIPT_SCHEMA,
        )

        def visit(value: object, path: str) -> None:
            if isinstance(value, dict):
                if value.get("type") == "object":
                    self.assertIs(value.get("additionalProperties"), False, path)
                for key, child in value.items():
                    visit(child, f"{path}/{key}")
            elif isinstance(value, list):
                for index, child in enumerate(value):
                    visit(child, f"{path}/{index}")

        schema_root = workspace_root() / "tools/release-certification/schemas"
        for name in names:
            with self.subTest(schema=name):
                visit(json.loads((schema_root / name).read_text(encoding="utf-8")), name)

    def test_valid_manifest_classes_and_modes(self) -> None:
        for release_class, mode in (
            ("maintenance", "validate-only"),
            ("maintenance", "prepare-authorization"),
            ("security-hotfix", "validate-only"),
            ("security-hotfix", "close-hotfix-follow-up"),
        ):
            with self.subTest(release_class=release_class, mode=mode):
                inputs = _required_inputs()
                if mode != "prepare-authorization":
                    inputs["stableMaintenanceAuthorization"] = "inputs/authorization.json"
                if mode == "close-hotfix-follow-up":
                    inputs.update(
                        {
                            "hotfixFollowUpObligation": "inputs/obligation.json",
                            "hotfixFollowUpEvidence": "inputs/follow-up.json",
                        }
                    )
                with tempfile.TemporaryDirectory() as directory:
                    context = _context(
                        Path(directory), release_class=release_class, mode=mode, inputs=inputs
                    )
                    _validate_stable_maintenance_manifest(context.manifest)

    def test_manifest_requires_the_exact_lifecycle_authority_chain_when_any_is_named(
        self,
    ) -> None:
        lifecycle_inputs = {
            "previousStableLifecycleLedger": "inputs/lifecycle-ledger.json",
            "previousStableLifecycleDescriptor": "inputs/lifecycle-descriptor.json",
            "stableLifecycleAuthorization": "inputs/lifecycle-authorization.json",
            "stableLifecyclePublicationPlan": "inputs/lifecycle-plan.json",
            "stableLifecyclePublicationReceipt": "inputs/lifecycle-receipt.json",
        }
        for count in (1, 2, 3, 4):
            with self.subTest(count=count), tempfile.TemporaryDirectory() as directory:
                inputs = {
                    **_required_inputs(),
                    "stableMaintenanceAuthorization": "inputs/authorization.json",
                    **dict(list(lifecycle_inputs.items())[:count]),
                }
                context = _context(Path(directory), inputs=inputs)

                with self.assertRaisesRegex(ValueError, "exact ledger, descriptor"):
                    _validate_stable_maintenance_manifest(context.manifest)

        with tempfile.TemporaryDirectory() as directory:
            context = _context(
                Path(directory),
                inputs={
                    **_required_inputs(),
                    "stableMaintenanceAuthorization": "inputs/authorization.json",
                    **lifecycle_inputs,
                },
            )

            _validate_stable_maintenance_manifest(context.manifest)

    def test_lifecycle_presence_gate_allows_ga_genesis_and_follow_up_closure_omission(
        self,
    ) -> None:
        absent = (None, None, None, None, None)
        complete = (
            {"ledger": True},
            {"descriptor": True},
            {"authorization": True},
            {"plan": True},
            {"receipt": True},
        )

        self.assertEqual([], _lifecycle_input_presence_errors(absent, 0))
        genesis_result = {"promotionReady": True, "decision": "go"}
        _apply_lifecycle_promotion_gate(genesis_result, False)
        self.assertEqual(
            {"promotionReady": False, "decision": "no-go"}, genesis_result
        )
        self.assertTrue(_lifecycle_input_presence_errors(absent, 1))
        # Closing a follow-up emits an overlay for an already-published carrier. It neither
        # promotes a successor nor activates lifecycle state, so successor authority is irrelevant.
        self.assertEqual(
            [],
            _lifecycle_input_presence_errors(
                absent, 1, require_activation=False
            ),
        )
        self.assertTrue(
            _lifecycle_input_presence_errors(
                (complete[0], None, complete[2], complete[3], complete[4]), 0
            )
        )
        self.assertTrue(
            _lifecycle_input_presence_errors(
                (complete[0], None, complete[2], complete[3], complete[4]), 1
            )
        )
        self.assertEqual([], _lifecycle_input_presence_errors(complete, 1))
        activated_result = {"promotionReady": True, "decision": "go"}
        _apply_lifecycle_promotion_gate(activated_result, True)
        self.assertEqual(
            {"promotionReady": True, "decision": "go"}, activated_result
        )

    def test_public_lifecycle_observation_enforces_exact_tip_and_short_freshness(
        self,
    ) -> None:
        digest = "sha256:" + "a" * 64
        other_digest = "sha256:" + "b" * 64
        redaction = {"status": "pass", "findingCount": 0, "findings": []}
        ledger = {"ledgerDigest": digest}
        descriptor = {
            "descriptorEdition": 7,
            "descriptorDigest": other_digest,
            "previousDescriptorEdition": 6,
            "previousDescriptorDigest": digest,
            "updateKeyIdentityDigest": digest,
            "updateKeyScope": f"{digest}/support-lifecycle/0",
            "updateKeyDocName": "support-lifecycle",
        }
        authorization = {"decision": "approved"}
        plan = {
            "publicRequestUri": "https://93.184.216.34/support-lifecycle/7",
            "publicationPlanDigest": other_digest,
        }
        publication_receipt = {"generatedAt": "2026-07-21T11:00:00Z"}
        observation = {
            "schemaVersion": 1,
            "kind": "stable-1.0-support-lifecycle-publication-receipt",
            "generatedAt": "2026-07-21T11:50:00Z",
            "stableMilestone": "1.0",
            "descriptorEdition": 7,
            "descriptorDigest": other_digest,
            "descriptorBytesDigest": digest,
            "ledgerDigest": digest,
            "previousDescriptorEdition": 6,
            "previousDescriptorDigest": digest,
            "updateKeyIdentityDigest": digest,
            "updateKeyScope": f"{digest}/support-lifecycle/0",
            "updateKeyDocName": "support-lifecycle",
            "publicRequestUri": plan["publicRequestUri"],
            "publicationPlanDigest": other_digest,
            "authorizationDigest": digest,
            "operation": "verified-existing",
            "publicationState": "publication-complete",
            "verificationStatus": "verified",
            "conflict": False,
            "redaction": redaction,
        }
        now = datetime(2026, 7, 21, 12, 0, tzinfo=timezone.utc)

        self.assertEqual(
            [],
            _public_lifecycle_observation_errors(
                observation,
                ledger,
                descriptor,
                authorization,
                plan,
                publication_receipt,
                digest,
                digest,
                now,
                30,
            ),
        )
        for generated_at in (
            "2026-07-21T11:29:59Z",
            "2026-07-21T12:00:01Z",
            "2026-07-21T10:59:59Z",
        ):
            with self.subTest(generated_at=generated_at):
                changed = dict(observation)
                changed["generatedAt"] = generated_at
                errors = _public_lifecycle_observation_errors(
                    changed,
                    ledger,
                    descriptor,
                    authorization,
                    plan,
                    publication_receipt,
                    digest,
                    digest,
                    now,
                    30,
                )
                self.assertTrue(any("stale, future-dated" in error for error in errors))

        superseded = dict(observation)
        superseded["descriptorEdition"] = 8
        self.assertTrue(
            any(
                "exact authorized edition" in error
                for error in _public_lifecycle_observation_errors(
                    superseded,
                    ledger,
                    descriptor,
                    authorization,
                    plan,
                    publication_receipt,
                    digest,
                    digest,
                    now,
                    30,
                )
            )
        )

    def test_follow_up_closure_allows_a_later_carrier_predecessor(self) -> None:
        inputs = {
            **_required_inputs(),
            "stableMaintenanceAuthorization": "inputs/authorization.json",
            "hotfixFollowUpObligation": "inputs/obligation.json",
            "hotfixFollowUpEvidence": "inputs/follow-up.json",
        }
        with tempfile.TemporaryDirectory() as directory:
            context = _context(
                Path(directory),
                release_class="security-hotfix",
                mode="close-hotfix-follow-up",
                inputs=inputs,
            )
            context.manifest.policies["expectedPredecessorBuild"] = str(
                int(BUILD) + 1
            )

            _validate_stable_maintenance_manifest(context.manifest)

    def test_candidate_classes_validate_against_closed_input_schema(self) -> None:
        for release_class in ("maintenance", "security-hotfix"):
            with self.subTest(release_class=release_class):
                value = _candidate_input(release_class)
                value["packages"] = _packages()
                self.assertEqual(
                    validate_schema(value, core.CANDIDATE_INPUT_SCHEMA), []
                )

    def test_hotfix_full_matrix_requires_valid_affected_package_subset(self) -> None:
        policy = _policy()
        scope = _candidate_input("security-hotfix")["changeScope"]
        assert isinstance(scope, dict)
        scope["affectedPackageKeys"] = ["amd64.exe"]
        self.assertEqual(
            _package_matrix_scope_errors(
                "security-hotfix",
                list(REQUIRED_PACKAGE_KEYS),
                list(REQUIRED_PACKAGE_KEYS),
                scope,
                policy,
            ),
            [],
        )

        for label, affected in (
            ("empty", []),
            ("unrelated", ["arm64.deb"]),
        ):
            with self.subTest(label=label):
                invalid_scope = copy.deepcopy(scope)
                invalid_scope["affectedPackageKeys"] = affected
                self.assertTrue(
                    _package_matrix_scope_errors(
                        "security-hotfix",
                        list(REQUIRED_PACKAGE_KEYS),
                        list(REQUIRED_PACKAGE_KEYS),
                        invalid_scope,
                        policy,
                    )
                )

    def test_hotfix_narrowed_matrix_requires_exact_affected_package_keys(self) -> None:
        policy = _policy()
        scope = _candidate_input("security-hotfix")["changeScope"]
        assert isinstance(scope, dict)
        scope["affectedPackageKeys"] = ["amd64.exe"]
        scope["unaffectedPackageProofStatus"] = "pass"
        self.assertEqual(
            _package_matrix_scope_errors(
                "security-hotfix",
                ["amd64.exe"],
                list(REQUIRED_PACKAGE_KEYS),
                scope,
                policy,
            ),
            [],
        )

        for label, mutate in (
            (
                "wrong-status",
                lambda value: value.__setitem__(
                    "unaffectedPackageProofStatus", "not-applicable"
                ),
            ),
            (
                "non-exact-affected-set",
                lambda value: value.__setitem__(
                    "affectedPackageKeys", ["amd64.deb"]
                ),
            ),
        ):
            with self.subTest(label=label):
                invalid_scope = copy.deepcopy(scope)
                mutate(invalid_scope)
                self.assertTrue(
                    _package_matrix_scope_errors(
                        "security-hotfix",
                        ["amd64.exe"],
                        list(REQUIRED_PACKAGE_KEYS),
                        invalid_scope,
                        policy,
                    )
                )

    def test_routine_package_matrix_semantics_are_unchanged(self) -> None:
        scope = _candidate_input("maintenance")["changeScope"]
        assert isinstance(scope, dict)
        self.assertEqual(
            _package_matrix_scope_errors(
                "maintenance",
                list(REQUIRED_PACKAGE_KEYS),
                list(REQUIRED_PACKAGE_KEYS),
                scope,
                _policy(),
            ),
            [],
        )
        self.assertTrue(
            _package_matrix_scope_errors(
                "maintenance",
                ["amd64.exe"],
                list(REQUIRED_PACKAGE_KEYS),
                scope,
                _policy(),
            )
        )

    def test_candidate_notarization_is_scoped_only_to_dmg_packages(self) -> None:
        packages = _packages()
        for row in packages:
            key = str(row["packageKey"])
            with self.subTest(package_key=key):
                self.assertEqual(
                    _candidate_package_notarization_errors(row, key), []
                )

        executable = next(
            row for row in packages if row["packageType"] == "exe"
        )
        executable["notarizationStatus"] = "pass"
        self.assertEqual(
            _candidate_package_notarization_errors(
                executable, str(executable["packageKey"])
            ),
            ["candidate non-DMG package claims notarization for amd64.exe"],
        )

        dmg = next(row for row in packages if row["packageType"] == "dmg")
        dmg["notarizationStatus"] = "not-applicable"
        self.assertEqual(
            _candidate_package_notarization_errors(dmg, str(dmg["packageKey"])),
            ["candidate macOS package notarization status failed for amd64.dmg"],
        )

    def test_candidate_dmg_selection_allows_only_declared_narrowed_hotfix_omission(
        self,
    ) -> None:
        packages = [row for row in _packages() if row["arch"] == "amd64"]
        selected = select_candidate_dmg_for_freeze(packages, "maintenance", {})
        self.assertIsNotNone(selected)
        self.assertEqual("amd64.dmg", selected["packageKey"])
        with self.assertRaisesRegex(ValueError, "multiple DMG packages"):
            select_candidate_dmg_for_freeze(
                [*packages, copy.deepcopy(selected)], "security-hotfix", {}
            )

        without_dmg = [
            row for row in packages if row["packageType"] != "dmg"
        ]
        affected_keys = [row["packageKey"] for row in without_dmg]
        narrowed_scope = {
            "affectedPackageKeys": affected_keys,
            "unaffectedPackageProofStatus": "pass",
        }
        self.assertIsNone(
            select_candidate_dmg_for_freeze(
                without_dmg, "security-hotfix", narrowed_scope
            )
        )
        with self.assertRaisesRegex(ValueError, "not a declared narrowed hotfix"):
            select_candidate_dmg_for_freeze(
                without_dmg, "maintenance", narrowed_scope
            )
        incomplete_scope = {
            **narrowed_scope,
            "affectedPackageKeys": affected_keys[:-1],
        }
        with self.assertRaisesRegex(ValueError, "not a declared narrowed hotfix"):
            select_candidate_dmg_for_freeze(
                without_dmg, "security-hotfix", incomplete_scope
            )

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

    def test_candidate_schema_rejects_byte_and_compatibility_drift(self) -> None:
        mutations = (
            lambda value: value.__setitem__("rebuildCount", 1),
            lambda value: value["source"].__setitem__("treeState", "dirty"),
            lambda value: value["platformApi"].__setitem__(
                "breakingStableChanges", ["remove /v1/apps"]
            ),
            lambda value: value["contentFormatProfiles"][0].__setitem__(
                "existingValidDocumentsAccepted", False
            ),
        )
        for mutate in mutations:
            value = _candidate_input()
            value["packages"] = _packages()
            mutate(value)
            self.assertTrue(validate_schema(value, core.CANDIDATE_INPUT_SCHEMA))

    def test_manifest_rejects_wrong_branch_mode_and_nonincreasing_build(self) -> None:
        mutations = (
            ("wrong branch", lambda manifest: manifest.policies.__setitem__("candidateSourceBranch", "main")),
            ("unsupported mode", lambda manifest: manifest.commands["stable-maintenance"].__setitem__("mode", "publish")),
            ("non-increasing build", lambda manifest: manifest.policies.__setitem__("expectedPredecessorBuild", BUILD)),
        )
        for label, mutate in mutations:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                context = _context(Path(directory), inputs={**_required_inputs(), "stableMaintenanceAuthorization": "inputs/auth.json"})
                mutate(context.manifest)
                with self.assertRaises(ValueError):
                    _validate_stable_maintenance_manifest(context.manifest)


class StableMaintenanceGaAuthenticationTest(unittest.TestCase):
    def test_completed_ga_graph_authenticates_exact_immutable_baseline(self) -> None:
        workspace = workspace_root()
        (workspace / "build").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=workspace / "build") as directory:
            context, output = _published_ga_maintenance_context(Path(directory))
            state = ValidationState()

            root = authenticate_ga_root(context, state)

            self.assertEqual([], state.blockers)
            self.assertEqual(
                file_digest(output / "stable-1.0-maintenance-baseline.json"),
                root.baseline_digest,
            )
            self.assertEqual("publication-complete", root.receipt["publicationState"])
            self.assertEqual(root.baseline["release"]["rcProductDigest"], root.product_digest)

    def test_mixed_modified_or_incomplete_ga_graph_fails_closed(self) -> None:
        workspace = workspace_root()
        (workspace / "build").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=workspace / "build") as directory:
            context, output = _published_ga_maintenance_context(Path(directory))
            cases = (
                (
                    "modified-baseline",
                    "stable-1.0-maintenance-baseline.json",
                    lambda value: value["platformApi"].update(
                        {"currentContractDigest": _digest("f")}
                    ),
                ),
                (
                    "mixed-validation",
                    "stable-1.0-ga-promotion-summary.json",
                    lambda value: value.update({"gaValidationDigest": _digest("e")}),
                ),
                (
                    "wrong-product-receipt",
                    "stable-1.0-ga-publication-receipt.json",
                    lambda value: value.update(
                        {"productDistributionDigest": _digest("d")}
                    ),
                ),
            )
            for name, filename, mutate in cases:
                with self.subTest(name=name):
                    path = output / filename
                    original = read_json(path)
                    modified = copy.deepcopy(original)
                    mutate(modified)
                    write_json(path, modified)
                    state = ValidationState()

                    authenticate_ga_root(context, state)

                    self.assertTrue(state.blockers)
                    write_json(path, original)

    def test_ga_receipt_rejects_failed_asset_observation(self) -> None:
        workspace = workspace_root()
        (workspace / "build").mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=workspace / "build") as directory:
            context, output = _published_ga_maintenance_context(Path(directory))
            receipt_path = output / "stable-1.0-ga-publication-receipt.json"
            receipt = read_json(receipt_path)
            receipt["assets"][0]["verificationStatus"] = "fail"
            write_json(receipt_path, receipt)
            state = ValidationState()

            authenticate_ga_root(context, state)

            self.assertTrue(
                any("unverified release asset" in row["summary"] for row in state.blockers),
                state.blockers,
            )

    def test_ga_predecessor_rejects_unrelated_latest_maintenance_pointer(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline = {"schemaVersion": 1, "kind": "stable-1.0-maintenance-baseline"}
            receipt = {"publicationState": "publication-complete"}
            pointer = {
                "kind": "stable-1.0-maintenance-latest-published",
                "releaseId": "forked-maintenance-999",
            }
            write_json(root / "baseline.json", baseline)
            write_json(root / "receipt.json", receipt)
            write_json(root / "pointer.json", pointer)
            ga = GaRoot(
                baseline=baseline,
                baseline_digest=file_digest(root / "baseline.json"),
                receipt=receipt,
                receipt_digest=file_digest(root / "receipt.json"),
                release_id="stable-1-0-ga-300",
                build_version=PREDECESSOR_BUILD,
                source_commit="b" * 40,
                product_digest=PREDECESSOR_PRODUCT_DIGEST,
                tag="v300",
                root_identity_digest=_digest("7"),
            )
            context = _context(
                root,
                inputs={
                    "predecessorBaseline": "baseline.json",
                    "predecessorPublicationReceipt": "receipt.json",
                    "latestPublishedMaintenancePointer": "pointer.json",
                },
            )
            state = ValidationState()

            predecessor = authenticate_predecessor(context, ga, state)
            lineage = _lineage(context, ga, predecessor, _candidate(root), state)

            self.assertTrue(
                any(
                    "GA predecessor forbids a latest-maintenance pointer" in row["summary"]
                    for row in state.blockers
                ),
                state.blockers,
            )
            self.assertIsNone(predecessor.latest_pointer_digest)
            self.assertEqual(
                ga.root_identity_digest,
                lineage["latestPublishedPointerDigest"],
            )


class StableMaintenanceInputSecurityTest(unittest.TestCase):
    """Ambiguous JSON and archive inputs fail closed offline."""

    def test_gradle_archive_modes_use_only_deterministic_member_paths(self) -> None:
        root = Path(__file__).resolve().parents[4]
        distribution = (
            root / "build-logic/src/main/kotlin/cryptad.distribution.gradle.kts"
        ).read_text(encoding="utf-8")
        runtime = (
            root / "build-logic/src/main/kotlin/cryptad.runtime.gradle.kts"
        ).read_text(encoding="utf-8")
        normalizer = (
            root / "build-logic/src/main/kotlin/cryptad/PortableArchiveNormalizer.kt"
        ).read_text(encoding="utf-8")

        for script in (distribution, runtime):
            self.assertNotIn("file.canExecute()", script)
            self.assertEqual(
                script.count(
                    "PortableArchiveNormalizer.unixPermissionsForMember(path)"
                ),
                2,
            )
        self.assertIn('normalized.startsWith("bin/")', normalizer)
        self.assertIn('!normalized.endsWith(".bat")', normalizer)
        self.assertIn('!normalized.endsWith(".exe")', normalizer)
        self.assertIn('normalized == "lib/jspawnhelper"', normalizer)
        self.assertNotIn("mode and 0x49", normalizer)

    def test_duplicate_json_keys_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.json"
            path.write_text('{"buildVersion":"301","buildVersion":"302"}\n', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate field"):
                read_json(path)

    def test_safe_archive_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "safe.zip"
            with zipfile.ZipFile(path, "w") as archive:
                info = zipfile.ZipInfo("cryptad/readme.txt", (1980, 1, 1, 0, 0, 0))
                info.create_system = 3
                info.external_attr = 0o100644 << 16
                archive.writestr(info, "safe")
            self.assertEqual(archive_hygiene_errors(path), [])

    def test_archive_hygiene_rejects_path_role_mode_mismatch(self) -> None:
        cases = (
            ("bin/cryptad", 0o644),
            ("conf/wrapper.conf", 0o755),
            ("lib/cryptad.jar", 0o755),
        )
        for name, wrong_mode in cases:
            for archive_format in ("tar", "zip"):
                with self.subTest(
                    name=name, archive_format=archive_format
                ), tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / f"wrong-mode.{archive_format}"
                    if archive_format == "tar":
                        payload = b"not-inspected"
                        with tarfile.open(path, "w") as archive:
                            info = tarfile.TarInfo(name)
                            info.size = len(payload)
                            info.mode = wrong_mode
                            info.mtime = 0
                            info.uid = 0
                            info.gid = 0
                            info.uname = "root"
                            info.gname = "root"
                            archive.addfile(info, io.BytesIO(payload))
                    else:
                        with zipfile.ZipFile(path, "w") as archive:
                            info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
                            info.create_system = 3
                            info.external_attr = (stat.S_IFREG | wrong_mode) << 16
                            archive.writestr(info, b"not-inspected")

                    errors = archive_hygiene_errors(path, nested=False)

                    self.assertTrue(
                        any("mode is not normalized" in error for error in errors),
                        errors,
                    )

    def test_archive_hygiene_rejects_raw_member_aliases(self) -> None:
        aliases = ("bin/./cryptad", "bin//cryptad", "./bin/cryptad")
        for alias in aliases:
            for archive_format in ("tar", "zip"):
                with self.subTest(
                    alias=alias, archive_format=archive_format
                ), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    path = root / f"unsafe.{archive_format}"
                    if archive_format == "tar":
                        payload = b"unsafe"
                        with tarfile.open(path, "w") as archive:
                            info = tarfile.TarInfo(alias)
                            info.size = len(payload)
                            info.mode = 0o644
                            info.mtime = 0
                            info.uid = 0
                            info.gid = 0
                            info.uname = "root"
                            info.gname = "root"
                            archive.addfile(info, io.BytesIO(payload))
                    else:
                        with zipfile.ZipFile(path, "w") as archive:
                            info = zipfile.ZipInfo(alias, (1980, 1, 1, 0, 0, 0))
                            info.create_system = 3
                            info.external_attr = 0o100644 << 16
                            archive.writestr(info, b"unsafe")

                    errors = archive_hygiene_errors(path)

                    self.assertTrue(
                        any("unsafe or duplicate member" in error for error in errors),
                        errors,
                    )

    def test_zip_archive_rejects_file_directory_path_aliases(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate-path.zip"
            with zipfile.ZipFile(path, "w") as archive:
                file_info = zipfile.ZipInfo("same", (1980, 1, 1, 0, 0, 0))
                file_info.create_system = 3
                file_info.external_attr = 0o100644 << 16
                archive.writestr(file_info, b"payload")
                directory_info = zipfile.ZipInfo("same/", (1980, 1, 1, 0, 0, 0))
                directory_info.create_system = 3
                directory_info.external_attr = 0o40755 << 16
                archive.writestr(directory_info, b"")

            errors = archive_hygiene_errors(path)

            self.assertTrue(
                any("unsafe or duplicate member" in error for error in errors), errors
            )

    def test_zip_archive_rejects_comments_and_extra_fields(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "metadata.zip"
            with zipfile.ZipFile(path, "w") as archive:
                archive.comment = b"archive-comment"
                info = zipfile.ZipInfo("safe.txt", (1980, 1, 1, 0, 0, 0))
                info.create_system = 3
                info.external_attr = 0o100644 << 16
                info.comment = b"member-comment"
                info.extra = b"\xfe\xca\x01\x00x"
                archive.writestr(info, b"payload")

            errors = archive_hygiene_errors(path)

            self.assertTrue(any("ZIP comment" in error for error in errors), errors)
            self.assertTrue(any("ZIP metadata" in error for error in errors), errors)

    def test_zip_archive_rejects_missing_unix_mode_metadata(self) -> None:
        cases = (
            ("zero Unix mode", 3, 1),
            ("non-Unix metadata", 0, (0o100644 << 16) | 1),
        )
        for label, create_system, external_attr in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "missing-mode.zip"
                with zipfile.ZipFile(path, "w") as archive:
                    info = zipfile.ZipInfo(
                        "cryptad/readme.txt", (1980, 1, 1, 0, 0, 0)
                    )
                    info.create_system = create_system
                    info.external_attr = external_attr
                    archive.writestr(info, b"unsafe")

                errors = archive_hygiene_errors(path)

                self.assertTrue(
                    any("Unix mode is missing" in error for error in errors), errors
                )

    def test_gradle_portable_archives_are_normalized_deterministically(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            gzip_tar = root / "cryptad.tar.gz"
            plain_tar = root / "cryptad.tar"
            zip_archive = root / "cryptad.zip"
            archives = (gzip_tar, plain_tar, zip_archive)
            jar_bytes = io.BytesIO()
            with zipfile.ZipFile(jar_bytes, "w") as jar:
                jar_info = zipfile.ZipInfo(
                    "META-INF/MANIFEST.MF", (1980, 1, 1, 0, 0, 0)
                )
                jar_info.create_system = 3
                jar_info.external_attr = 0o100644 << 16
                jar.writestr(jar_info, b"Manifest-Version: 1.0\r\n\r\n")
            jar_payload = jar_bytes.getvalue()
            for tar_path, mode in ((gzip_tar, "w:gz"), (plain_tar, "w")):
                with tarfile.open(tar_path, mode) as archive:
                    for name in ("bin", "conf", "lib"):
                        directory_info = tarfile.TarInfo(name)
                        directory_info.type = tarfile.DIRTYPE
                        directory_info.mode = 0o40775
                        directory_info.mtime = 123456
                        archive.addfile(directory_info)
                    for name, source_mode, payload in (
                        ("bin/cryptad", 0o100644, b"#!/bin/sh\n"),
                        ("bin/cryptad.bat", 0o100755, b"@echo off\r\n"),
                        ("conf/wrapper.conf", 0o100755, b"wrapper.java.command=java\n"),
                        ("lib/cryptad.jar", 0o100755, jar_payload),
                        ("lib/libwrapper-linux-x86-64.so", 0o100644, b"native"),
                    ):
                        file_info = tarfile.TarInfo(name)
                        file_info.mode = source_mode
                        file_info.mtime = 123456
                        file_info.size = len(payload)
                        archive.addfile(file_info, io.BytesIO(payload))
            with zipfile.ZipFile(zip_archive, "w") as archive:
                for name in ("bin/", "conf/", "lib/"):
                    directory_info = zipfile.ZipInfo(name, (2026, 7, 18, 12, 0, 0))
                    directory_info.external_attr = 0o40775 << 16
                    archive.writestr(directory_info, b"")
                for name, source_mode, payload in (
                    ("bin/cryptad", 0o100644, b"#!/bin/sh\n"),
                    ("bin/cryptad.bat", 0o100755, b"@echo off\r\n"),
                    ("conf/wrapper.conf", 0o100755, b"wrapper.java.command=java\n"),
                    ("lib/cryptad.jar", 0o100755, jar_payload),
                    ("lib/libwrapper-linux-x86-64.so", 0o100644, b"native"),
                ):
                    file_info = zipfile.ZipInfo(name, (2026, 7, 18, 12, 0, 0))
                    file_info.external_attr = source_mode << 16
                    archive.writestr(file_info, payload)

            for archive in archives:
                with self.subTest(archive=archive.name):
                    normalize_portable_distribution_archive(archive)
                    first_digest = file_digest(archive)
                    normalize_portable_distribution_archive(archive)

                    self.assertEqual(file_digest(archive), first_digest)
                    self.assertEqual(archive_hygiene_errors(archive), [])

            self.assertFalse(plain_tar.read_bytes().startswith(b"\x1f\x8b"))
            with tarfile.open(plain_tar, "r:") as archive:
                modes = {member.name: member.mode for member in archive.getmembers()}
            with zipfile.ZipFile(zip_archive) as archive:
                zip_modes = {
                    member.filename.rstrip("/"): member.external_attr >> 16 & 0o777
                    for member in archive.infolist()
                }
            expected_modes = {
                "bin": 0o755,
                "bin/cryptad": 0o755,
                "bin/cryptad.bat": 0o644,
                "conf": 0o755,
                "conf/wrapper.conf": 0o644,
                "lib": 0o755,
                "lib/cryptad.jar": 0o644,
                "lib/libwrapper-linux-x86-64.so": 0o755,
            }
            self.assertEqual(modes, expected_modes)
            self.assertEqual(zip_modes, expected_modes)

    def test_nested_archive_size_is_rejected_before_payload_read(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "outer.tar"
            payload = b"not-a-zip"
            with tarfile.open(path, "w") as archive:
                info = tarfile.TarInfo("payload/nested.zip")
                info.size = len(payload)
                info.mode = 0o644
                info.mtime = 0
                info.uid = 0
                info.gid = 0
                info.uname = "root"
                info.gname = "root"
                archive.addfile(info, io.BytesIO(payload))

            with mock.patch.object(core, "MAX_NESTED_ARCHIVE_BYTES", 4):
                errors = archive_hygiene_errors(path)

            self.assertTrue(
                any("exceeds inspection policy" in error for error in errors), errors
            )

    def test_nested_zip_rejects_duplicate_members(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            nested = io.BytesIO()
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                with zipfile.ZipFile(nested, "w") as archive:
                    archive.writestr("same.class", b"first")
                    archive.writestr("same.class", b"second")
            path = Path(directory) / "outer.tar"
            with tarfile.open(path, "w") as archive:
                info = tarfile.TarInfo("payload/nested.jar")
                info.size = len(nested.getvalue())
                info.mode = 0o644
                info.mtime = 0
                info.uid = 0
                info.gid = 0
                info.uname = "root"
                info.gname = "root"
                archive.addfile(info, io.BytesIO(nested.getvalue()))

            errors = archive_hygiene_errors(path)

            self.assertTrue(
                any("nested archive contains a duplicate" in error for error in errors),
                errors,
            )

    def test_gzip_archive_rejects_optional_header_fields(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "metadata.tar.gz"
            with tarfile.open(path, "w:gz") as archive:
                payload = b"payload"
                info = tarfile.TarInfo("safe.txt")
                info.size = len(payload)
                info.mode = 0o644
                info.mtime = 0
                info.uid = 0
                info.gid = 0
                info.uname = "root"
                info.gname = "root"
                archive.addfile(info, io.BytesIO(payload))
            normalize_portable_distribution_archive(path)
            encoded = bytearray(path.read_bytes())
            encoded[3] |= 0x10
            encoded[10:10] = b"noncanonical-comment\0"
            path.write_bytes(encoded)

            errors = archive_hygiene_errors(path)

            self.assertTrue(
                any("gzip header metadata" in error for error in errors), errors
            )

    def test_tar_archive_rejects_noncanonical_pax_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "metadata.tar"
            with tarfile.open(path, "w", format=tarfile.PAX_FORMAT) as archive:
                payload = b"payload"
                info = tarfile.TarInfo("safe.txt")
                info.size = len(payload)
                info.mode = 0o644
                info.mtime = 0
                info.uid = 0
                info.gid = 0
                info.uname = "root"
                info.gname = "root"
                info.pax_headers = {"comment": "secret-value"}
                archive.addfile(info, io.BytesIO(payload))

            errors = archive_hygiene_errors(path)

            self.assertTrue(
                any("noncanonical PAX metadata" in error for error in errors), errors
            )

    def test_pe_machine_must_match_declared_and_producer_architecture(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cryptad.exe"
            payload = bytearray(512)
            payload[:2] = b"MZ"
            payload[0x3C:0x40] = (0x80).to_bytes(4, "little")
            payload[0x80:0x84] = b"PE\0\0"
            payload[0x84:0x86] = b"\x64\xaa"
            path.write_bytes(payload)
            row = {
                "packageKey": "amd64.exe",
                "os": "windows",
                "arch": "amd64",
                "producerArchitecture": "amd64",
                "packageType": "exe",
            }

            errors = _package_identity_errors(row, path)

            self.assertTrue(any("byte architecture is arm64" in error for error in errors))

    def test_archive_hygiene_rejects_unsafe_members(self) -> None:
        cases = (
            ("traversal", "../escape.txt"),
            ("absolute", "/absolute.txt"),
            ("Windows drive absolute", "C:\\Windows\\escape.txt"),
            ("Windows UNC absolute", "\\\\server\\share\\escape.txt"),
            ("apple metadata", "__MACOSX/value"),
            ("nested archive", "payload/nested.zip"),
        )
        for label, member in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "unsafe.tar"
                payload = b"bad"
                with tarfile.open(path, "w") as archive:
                    info = tarfile.TarInfo(member)
                    info.size = len(payload)
                    archive.addfile(info, io.BytesIO(payload))
                self.assertTrue(archive_hygiene_errors(path))

    def test_nested_archive_rejects_windows_absolute_member_and_escaping_symlink(self) -> None:
        nested_cases: tuple[tuple[str, tarfile.TarInfo], ...] = (
            ("Windows absolute member", tarfile.TarInfo("C:/Windows/escape.txt")),
            ("UNC member", tarfile.TarInfo("//server/share/escape.txt")),
            ("escaping symlink", tarfile.TarInfo("safe/link")),
        )
        for label, nested_info in nested_cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                nested = io.BytesIO()
                with tarfile.open(fileobj=nested, mode="w") as archive:
                    if label == "escaping symlink":
                        nested_info.type = tarfile.SYMTYPE
                        nested_info.linkname = "../../../outside"
                        archive.addfile(nested_info)
                    else:
                        payload = b"unsafe"
                        nested_info.size = len(payload)
                        archive.addfile(nested_info, io.BytesIO(payload))
                path = Path(directory) / "outer.tar"
                with tarfile.open(path, "w") as archive:
                    outer = tarfile.TarInfo("payload/nested.tar")
                    outer.size = len(nested.getvalue())
                    outer.mode = 0o644
                    outer.mtime = 0
                    outer.uid = 0
                    outer.gid = 0
                    outer.uname = "root"
                    outer.gname = "root"
                    archive.addfile(outer, io.BytesIO(nested.getvalue()))

                errors = archive_hygiene_errors(path)

                self.assertTrue(
                    any("nested archive contains an unsafe" in error for error in errors),
                    errors,
                )

    def test_archive_hygiene_rejects_special_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "special.tar"
            with tarfile.open(path, "w") as archive:
                info = tarfile.TarInfo("device")
                info.type = tarfile.CHRTYPE
                archive.addfile(info)
            self.assertTrue(
                any("special member" in error for error in archive_hygiene_errors(path))
            )

    def test_unknown_archive_and_mislabeled_package_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            unknown = root / "candidate.bin"
            unknown.write_bytes(b"not-an-archive")
            package = root / "cryptad.exe"
            package.write_bytes(b"MZ" + b"\0" * 32)

            archive_errors = archive_hygiene_errors(unknown)
            selector_errors = _package_identity_errors(
                {
                    "packageKey": "amd64.deb",
                    "os": "linux",
                    "arch": "amd64",
                    "producerArchitecture": "amd64",
                    "packageType": "deb",
                },
                package,
            )

            self.assertTrue(archive_errors)
            self.assertTrue(selector_errors)


class StableMaintenanceCoreInfoTest(unittest.TestCase):
    """Deterministic package-to-CoreUpdater mapping tests."""

    def test_core_info_is_sorted_candidate_bound_and_schema_valid(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            context = _context(root)
            candidate = _candidate(root)
            candidate.assets.reverse()
            state = ValidationState()
            descriptor, identity = build_core_info(context, candidate, state)
            self.assertEqual(state.blockers, [])
            self.assertEqual(list(descriptor["packages"]), sorted(PACKAGE_KEYS))
            self.assertEqual(descriptor["version"], BUILD)
            self.assertNotIn("sha256", json.dumps(descriptor))
            self.assertEqual(identity["candidateIdentityDigest"], candidate.identity_digest)
            self.assertEqual(validate_schema(descriptor, core.CORE_INFO_SCHEMA), [])

    def test_core_info_keeps_fixed_github_release_page_offline(self) -> None:
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            stable_1_0_ga_core.socket,
            "getaddrinfo",
            side_effect=OSError("offline"),
        ):
            root = Path(directory)
            context = _context(root)
            state = ValidationState()

            descriptor, _identity = build_core_info(
                context, _candidate(root), state
            )

            self.assertEqual(state.blockers, [])
            self.assertEqual(
                descriptor["release_page_url"],
                "https://github.com/crypta-network/cryptad/releases/tag/v301",
            )

            context.manifest.policies["metadata"]["githubReleasePageUri"] = (
                "https://github.com/crypta-network/cryptad/releases/tag/v302"
            )
            invalid_state = ValidationState()
            build_core_info(context, _candidate(root), invalid_state)
            self.assertTrue(
                any(
                    "release page URL is not public-safe" in row["summary"]
                    for row in invalid_state.blockers
                ),
                invalid_state.blockers,
            )

    def test_core_info_rejects_ambiguous_or_private_package_reference(self) -> None:
        mutations = (
            ("both references", lambda row: row.__setitem__("storeUrl", "https://store.crypta.network/app")),
            ("private insert", lambda row: row.__setitem__("publicChk", "USK@private/insert/301")),
            ("local path", lambda row: row.__setitem__("publicChk", "/tmp/package.deb")),
        )
        for label, mutate in mutations:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                candidate = _candidate(root)
                mutate(candidate.assets[0])
                state = ValidationState()
                build_core_info(_context(root), candidate, state)
                self.assertTrue(state.blockers)

    def test_core_info_same_input_has_same_semantic_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidate = _candidate(root)
            first = build_core_info(_context(root), candidate, ValidationState())
            second = build_core_info(_context(root), candidate, ValidationState())
            self.assertEqual(semantic_digest(first), semantic_digest(second))

    def test_core_info_rejects_reserved_or_privately_resolved_store_url(self) -> None:
        private_resolution = [(None, None, None, None, ("10.0.0.8", 443))]
        for store_url in (
            "https://artifact.local/apps/cryptad.flatpak",
            "https://packages.crypta.network/apps/cryptad.flatpak",
        ):
            with self.subTest(
                store_url=store_url
            ), tempfile.TemporaryDirectory() as directory, mock.patch.object(
                stable_1_0_ga_core.socket,
                "getaddrinfo",
                return_value=private_resolution,
            ):
                root = Path(directory)
                candidate = _candidate(root)
                store_package = copy.deepcopy(candidate.assets[0])
                store_package.update(
                    {
                        "packageKey": "amd64.flatpak",
                        "fileName": "cryptad-amd64.flatpak",
                        "packageType": "flatpak",
                        "digest": _digest("f"),
                        "publicChk": None,
                        "storeUrl": store_url,
                    }
                )
                candidate.assets.append(store_package)
                state = ValidationState()

                build_core_info(_context(root), candidate, state)

                self.assertTrue(
                    any("unsafe store URL" in row["summary"] for row in state.blockers),
                    state.blockers,
                )

    def test_publication_targets_reject_privately_resolved_dns_name(self) -> None:
        private_resolution = [(None, None, None, None, ("192.168.50.10", 443))]
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            stable_1_0_ga_core.socket,
            "getaddrinfo",
            return_value=private_resolution,
        ):
            context = _context(Path(directory))
            context.manifest.policies["metadata"]["catalogPrimaryUri"] = (
                "https://catalog.crypta.network/stable/catalog.json"
            )
            state = ValidationState()

            stable_1_0_maintenance._targets(context, state)  # noqa: SLF001

            self.assertTrue(
                any("public credential-free HTTPS" in row["summary"] for row in state.blockers),
                state.blockers,
            )

    def test_publication_urls_reject_private_or_reserved_hosts(self) -> None:
        for value in (
            "https://127.0.0.1/release",
            "https://10.0.0.1/release",
            "https://artifact.local/release",
            "https://artifact.invalid/release",
            "https://user:password@artifacts.crypta.network/release",
        ):
            with self.subTest(value=value):
                self.assertFalse(stable_1_0_maintenance._https(value))
        public_resolution = [(None, None, None, None, ("93.184.216.34", 443))]
        with mock.patch.object(
            stable_1_0_ga_core.socket,
            "getaddrinfo",
            return_value=public_resolution,
        ):
            self.assertTrue(
                stable_1_0_maintenance._https(
                    "https://github.com/crypta-network/cryptad/releases/tag/v301"
                )
            )


class StableMaintenanceCompatibilityTest(unittest.TestCase):
    """Long-term GA and immediate-predecessor compatibility policy tests."""

    def test_valid_comparison_is_go_and_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ga, predecessor = _ga_and_predecessor()
            candidate = _candidate(root)
            state = ValidationState()
            first = build_comparison(
                _context(root), ga, predecessor, candidate, _policy(), state
            )
            second = build_comparison(
                _context(root),
                ga,
                predecessor,
                candidate,
                _policy(),
                ValidationState(),
            )
            self.assertEqual(state.blockers, [])
            self.assertTrue(first["compatible"])
            self.assertEqual(first["decision"], "go")
            self.assertEqual(semantic_digest(first), semantic_digest(second))

    def test_platform_api_negative_gates(self) -> None:
        ga = _ga_platform_api()
        predecessor = copy.deepcopy(ga)
        cases = (
            ("endpoint removal", "removedStableEndpoints", ["/v1/apps"]),
            ("capability removal", "removedStableCapabilities", ["app-data"]),
            ("deprecation reset", "deprecationClockReset", True),
            ("critical waiver", "criticalRemovalWaiverAttempt", True),
            ("experimental mislabel", "experimentalMislabelledStable", True),
            ("incompatible addition", "additionsBackwardCompatible", False),
        )
        for label, field, value in cases:
            with self.subTest(label=label):
                candidate = _platform_api()
                candidate[field] = value
                self.assertTrue(_platform_api_errors(ga, predecessor, candidate))

        changed_surface = _platform_api()
        changed_surface["stableSurfaceDigest"] = _digest("f")
        self.assertTrue(_platform_api_errors(ga, predecessor, changed_surface))

    def test_platform_api_deprecation_history_preserves_original_clocks(self) -> None:
        ga = _ga_platform_api()
        predecessor = copy.deepcopy(ga)
        first_history = [
            {
                "kind": "endpoint",
                "identity": "GET /api/v1/example",
                "stability": "deprecated",
                "deprecatedSinceContractVersion": 24,
                "removalContractVersion": None,
            }
        ]
        candidate = _platform_api()
        candidate["deprecationHistory"] = first_history
        candidate["deprecationHistoryDigest"] = semantic_digest(first_history)
        self.assertEqual(_platform_api_errors(ga, predecessor, candidate), [])

        predecessor = copy.deepcopy(candidate)
        predecessor["currentContractVersion"] = 24
        successor = copy.deepcopy(candidate)
        successor["currentContractVersion"] = 25
        successor["currentContractDigest"] = _digest("a")
        self.assertEqual(_platform_api_errors(ga, predecessor, successor), [])

        reset = copy.deepcopy(successor)
        reset["deprecationHistory"][0]["deprecatedSinceContractVersion"] = 25
        reset["deprecationHistoryDigest"] = semantic_digest(reset["deprecationHistory"])
        self.assertTrue(_platform_api_errors(ga, predecessor, reset))

        backdated = copy.deepcopy(successor)
        backdated["deprecationHistory"].append(
            {
                "kind": "capability",
                "identity": "example.read",
                "stability": "deprecated",
                "deprecatedSinceContractVersion": 24,
                "removalContractVersion": None,
            }
        )
        backdated["deprecationHistoryDigest"] = semantic_digest(
            backdated["deprecationHistory"]
        )
        self.assertTrue(_platform_api_errors(ga, predecessor, backdated))

        shortened = copy.deepcopy(successor)
        shortened["deprecationHistory"][0].update(
            {
                "stability": "scheduled-for-removal",
                "removalContractVersion": 26,
            }
        )
        shortened["deprecationHistoryDigest"] = semantic_digest(
            shortened["deprecationHistory"]
        )
        self.assertTrue(_platform_api_errors(ga, predecessor, shortened))

        wrong_digest = copy.deepcopy(successor)
        wrong_digest["deprecationHistoryDigest"] = _digest("b")
        self.assertTrue(_platform_api_errors(ga, predecessor, wrong_digest))

    def test_content_profile_drift_and_rejection_fail(self) -> None:
        ga = _profiles(candidate=False)
        predecessor = copy.deepcopy(ga)
        for field, value in (
            ("canonicalizationRulesDigest", _digest("f")),
            ("signaturePayloadRulesDigest", _digest("0")),
            ("existingValidDocumentsAccepted", False),
            ("acceptanceStatus", "fail"),
        ):
            with self.subTest(field=field):
                candidate = _profiles(candidate=True)
                candidate[0][field] = value
                self.assertTrue(_content_profile_errors(ga, predecessor, candidate))

    def test_catalog_app_and_limitation_negative_gates(self) -> None:
        ga_catalog = _catalog()
        ga_catalog.update({"edition": 7, "revision": 7})
        predecessor_catalog = copy.deepcopy(ga_catalog)
        predecessor_catalog["catalogDigest"] = predecessor_catalog.pop("digest")
        candidate_value = {"stableCatalog": _catalog()}
        for field, value in (
            ("channel", "beta"),
            ("revision", 6),
            ("signatureStatus", "fail"),
            ("mirrorStatus", "fail"),
        ):
            with self.subTest(catalog_field=field):
                current = copy.deepcopy(candidate_value)
                current["stableCatalog"][field] = value
                self.assertTrue(_catalog_errors(ga_catalog, predecessor_catalog, current))
        rotated = copy.deepcopy(candidate_value)
        rotated["stableCatalog"]["signingKeyId"] = "catalog-production-2027"
        self.assertTrue(_catalog_errors(ga_catalog, predecessor_catalog, rotated))
        rotated["stableCatalog"]["keyRotationTrustTransitionStatus"] = "complete"
        self.assertEqual(_catalog_errors(ga_catalog, predecessor_catalog, rotated), [])
        unchanged_version = copy.deepcopy(candidate_value)
        unchanged_version["stableCatalog"].update({"edition": 7, "revision": 7})
        self.assertEqual(
            _catalog_errors(ga_catalog, predecessor_catalog, unchanged_version), []
        )
        for identity_field in ("digest", "signatureDigest", "signingKeyId"):
            with self.subTest(catalog_identity_field=identity_field):
                changed_identity = copy.deepcopy(unchanged_version)
                changed_identity["stableCatalog"][identity_field] = (
                    "catalog-production-2027"
                    if identity_field == "signingKeyId"
                    else _digest("9")
                )
                if identity_field == "signingKeyId":
                    changed_identity["stableCatalog"][
                        "keyRotationTrustTransitionStatus"
                    ] = "complete"
                self.assertTrue(
                    _catalog_errors(ga_catalog, predecessor_catalog, changed_identity)
                )
                changed_identity["stableCatalog"]["revision"] = 8
                self.assertEqual(
                    _catalog_errors(ga_catalog, predecessor_catalog, changed_identity), []
                )
        for mutate in (
            lambda rows: rows.pop(),
            lambda rows: rows[0].__setitem__("channel", "beta"),
            lambda rows: rows[0].__setitem__("supportLevel", "local-rc"),
            lambda rows: rows[0].__setitem__("reviewedBundleDigest", _digest("f")),
            lambda rows: rows[0].update({"permissionExpansion": True, "permissionConsentStatus": "fail"}),
        ):
            rows = _apps(candidate=True)
            mutate(rows)
            self.assertTrue(
                _app_compatibility_errors(
                    _apps(candidate=False), _apps(candidate=False), rows
                )
            )
        predecessor_apps = _apps(candidate=False)
        predecessor_apps[0]["appDataSchemaVersion"] = 3
        downgraded_apps = _apps(candidate=True)
        downgraded_apps[0]["appDataSchemaVersion"] = 2
        self.assertTrue(
            _app_compatibility_errors(
                _apps(candidate=False), predecessor_apps, downgraded_apps
            )
        )
        downgraded_apps[0]["appDataSchemaVersion"] = "not-applicable"
        self.assertTrue(
            _app_compatibility_errors(
                _apps(candidate=False), predecessor_apps, downgraded_apps
            )
        )
        upgraded_apps = _apps(candidate=True)
        upgraded_apps[0]["appDataSchemaVersion"] = 4
        self.assertEqual(
            _app_compatibility_errors(
                _apps(candidate=False), predecessor_apps, upgraded_apps
            ),
            [],
        )
        ga_limitations = {
            "allowedLimitations": [{"id": "stable-known-001"}]
        }
        predecessor_limitations = copy.deepcopy(ga_limitations)
        limitations = _candidate_input()["limitations"]
        assert isinstance(limitations, dict)
        limitations["addedCount"] = 1
        self.assertTrue(
            _limitation_errors(ga_limitations, predecessor_limitations, limitations)
        )

    def test_first_party_app_versions_track_update_selection_semantics(self) -> None:
        ga_apps = _apps(candidate=False)
        predecessor_apps = _apps(candidate=False)
        candidate_apps = _apps(candidate=True)
        for rows in (ga_apps, predecessor_apps, candidate_apps):
            rows[0]["version"] = "1.9.0"
        self.assertEqual(
            _app_compatibility_errors(ga_apps, predecessor_apps, candidate_apps), []
        )

        candidate_apps[0]["bundleDigest"] = _digest("9")
        candidate_apps[0]["reviewedBundleDigest"] = _digest("9")
        candidate_apps[0]["version"] = "1.10.0"
        self.assertEqual(
            _app_compatibility_errors(ga_apps, predecessor_apps, candidate_apps), []
        )

        for version in ("1.9.0", "1.9", "1.8.99"):
            with self.subTest(changed_bundle_version=version):
                candidate_apps[0]["version"] = version
                self.assertTrue(
                    _app_compatibility_errors(
                        ga_apps, predecessor_apps, candidate_apps
                    )
                )

        candidate_apps[0]["bundleDigest"] = ga_apps[0]["bundleDigest"]
        candidate_apps[0]["reviewedBundleDigest"] = ga_apps[0]["bundleDigest"]
        candidate_apps[0]["version"] = "1.8.99"
        self.assertTrue(
            _app_compatibility_errors(ga_apps, predecessor_apps, candidate_apps)
        )

        candidate_apps[0]["version"] = "1.9.1-hotfix"
        self.assertTrue(
            _app_compatibility_errors(ga_apps, predecessor_apps, candidate_apps)
        )

        predecessor_apps[0]["version"] = "1.9.0-rc1"
        candidate_apps[0]["version"] = "1.10.0"
        self.assertTrue(
            _app_compatibility_errors(ga_apps, predecessor_apps, candidate_apps)
        )

        ga_apps[0]["version"] = "2.0.0"
        predecessor_apps[0]["version"] = "1.9.0"
        candidate_apps[0]["version"] = "1.10.0"
        self.assertTrue(
            _app_compatibility_errors(ga_apps, predecessor_apps, candidate_apps)
        )

        candidate_apps[0]["version"] = "9" * 5_000
        self.assertTrue(
            _app_compatibility_errors(ga_apps, predecessor_apps, candidate_apps)
        )

    def test_first_party_app_support_commitment_is_non_decreasing(self) -> None:
        ga_apps = _apps(candidate=False)
        predecessor_apps = _apps(candidate=False)
        candidate_apps = _apps(candidate=True)
        ga_apps[0]["supportLevel"] = "local-rc"
        predecessor_apps[0]["supportLevel"] = "maintained"
        candidate_apps[0]["supportLevel"] = "core"

        self.assertEqual(
            _app_compatibility_errors(ga_apps, predecessor_apps, candidate_apps), []
        )

        candidate_apps[0]["supportLevel"] = "maintained"
        self.assertEqual(
            _app_compatibility_errors(ga_apps, predecessor_apps, candidate_apps), []
        )

        candidate_apps[0]["supportLevel"] = "local-rc"
        self.assertTrue(
            _app_compatibility_errors(ga_apps, predecessor_apps, candidate_apps)
        )

        ga_apps[0]["supportLevel"] = "core"
        candidate_apps[0]["supportLevel"] = "maintained"
        self.assertTrue(
            _app_compatibility_errors(ga_apps, predecessor_apps, candidate_apps)
        )

    def test_first_party_app_support_commitment_rejects_unknown_levels(self) -> None:
        for anchor in ("ga", "predecessor", "candidate"):
            with self.subTest(anchor=anchor):
                ga_apps = _apps(candidate=False)
                predecessor_apps = _apps(candidate=False)
                candidate_apps = _apps(candidate=True)
                selected = {
                    "ga": ga_apps,
                    "predecessor": predecessor_apps,
                    "candidate": candidate_apps,
                }[anchor]
                selected[0]["supportLevel"] = "unknown-support"

                self.assertTrue(
                    _app_compatibility_errors(
                        ga_apps, predecessor_apps, candidate_apps
                    )
                )

        malformed_policy = _policy()
        malformed_policy["catalogAndApps"]["supportLevelOrder"] = [
            "local-rc",
            "maintained",
        ]
        self.assertTrue(
            _app_errors(
                _apps(candidate=False),
                _apps(candidate=False),
                _apps(candidate=True),
                malformed_policy,
            )
        )

    def test_limitation_delta_is_an_exact_authenticated_membership_transition(self) -> None:
        predecessor_ids = {"stable-known-001", "stable-known-002"}
        ga_limitations = {
            "allowedLimitations": [
                {"id": limitation_id} for limitation_id in sorted(predecessor_ids)
            ]
        }
        predecessor_limitations = copy.deepcopy(ga_limitations)
        valid = _limitations(
            predecessor_ids,
            added_ids={"stable-known-003"},
            resolved_ids={"stable-known-001"},
        )
        self.assertEqual(
            _limitation_errors(ga_limitations, predecessor_limitations, valid), []
        )
        unsorted_delta = _limitations(
            predecessor_ids,
            added_ids={"stable-known-003", "stable-known-004"},
        )
        unsorted_delta["addedIds"] = list(reversed(unsorted_delta["addedIds"]))
        self.assertTrue(
            _limitation_errors(
                ga_limitations, predecessor_limitations, unsorted_delta
            )
        )

        mutations = {
            "overlap": lambda value: value["addedIds"].append("stable-known-002"),
            "invented-unchanged": lambda value: value["unchangedIds"].append(
                "stable-known-999"
            ),
            "omitted-predecessor": lambda value: value["resolvedIds"].clear(),
            "wrong-current-digest": lambda value: value.__setitem__(
                "knownLimitationsDigest", _digest("8")
            ),
            "wrong-delta-digest": lambda value: value.__setitem__(
                "deltaDigest", _digest("9")
            ),
        }
        for label, mutate in mutations.items():
            with self.subTest(mutation=label):
                invalid = copy.deepcopy(valid)
                mutate(invalid)
                if label in {"overlap", "invented-unchanged"}:
                    invalid["addedCount"] = len(invalid["addedIds"])
                    invalid["unchangedCount"] = len(invalid["unchangedIds"])
                self.assertTrue(
                    _limitation_errors(
                        ga_limitations, predecessor_limitations, invalid
                    )
                )

        successor_anchor = {
            "currentDigest": _known_limitations_digest(
                {"stable-known-002", "stable-known-003"}
            ),
            "currentIds": ["stable-known-002", "stable-known-003"],
            "gaBaselineDigest": _digest("a"),
            "predecessorDigest": _digest("b"),
        }
        next_delta = _limitations(
            {"stable-known-002", "stable-known-003"},
            resolved_ids={"stable-known-002"},
        )
        self.assertEqual(
            _limitation_errors(ga_limitations, successor_anchor, next_delta), []
        )
        successor_anchor["currentIds"] = list(
            reversed(successor_anchor["currentIds"])
        )
        self.assertTrue(
            _limitation_errors(ga_limitations, successor_anchor, next_delta)
        )
        successor_anchor["currentIds"].sort()
        successor_anchor["currentDigest"] = _digest("c")
        self.assertTrue(
            _limitation_errors(ga_limitations, successor_anchor, next_delta)
        )


@mock.patch.object(compatibility.dt, "datetime", mock.Mock(wraps=datetime, **{"now.return_value": NOW}))
class StableMaintenanceEvidenceTest(unittest.TestCase):
    """Normal evidence and narrowly expedited hotfix follow-up tests."""

    def test_normal_evidence_is_candidate_and_predecessor_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence_path = root / "evidence.json"
            write_json(evidence_path, _evidence())
            context = _context(root, inputs={"maintenanceEvidence": "evidence.json"})
            ga, predecessor = _ga_and_predecessor()
            state = ValidationState()
            value, digest, follow_up = validate_production_evidence(
                context, ga, predecessor, _candidate(root), _policy(), state
            )
            self.assertEqual(state.blockers, [])
            self.assertEqual(digest, file_digest(evidence_path))
            self.assertEqual(value["candidateProductDigest"], PRODUCT_DIGEST)
            self.assertIsNone(follow_up)

    def test_later_maintenance_binds_direct_upgrade_to_authenticated_ga(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ga, predecessor = _ga_and_predecessor()
            predecessor = dataclasses.replace(
                predecessor,
                release_id="stable-1-0-maintenance-301",
                build_version="301",
                product_digest=_digest("a"),
                chain_depth=1,
            )
            evidence = _evidence()
            evidence.update(
                {
                    "releaseId": "stable-1-0-maintenance-302",
                    "buildVersion": "302",
                    "predecessorBuild": predecessor.build_version,
                    "predecessorProductDigest": predecessor.product_digest,
                }
            )
            direct_ga_row = None
            for row in evidence["evidenceRows"]:
                row.update(
                    {
                        "candidateReleaseId": "stable-1-0-maintenance-302",
                        "candidateBuild": "302",
                        "predecessorBuild": predecessor.build_version,
                        "predecessorProductDigest": predecessor.product_digest,
                    }
                )
                if row["evidenceId"] == "stable-maintenance.direct-ga-upgrade":
                    direct_ga_row = row
            assert direct_ga_row is not None
            context = _context(root, inputs={"maintenanceEvidence": "evidence.json"})
            context = dataclasses.replace(
                context,
                manifest=dataclasses.replace(
                    context.manifest,
                    release=ReleaseSpec(
                        "stable-1-0-maintenance-302", "302", "stable-review"
                    ),
                ),
            )
            write_json(root / "evidence.json", evidence)

            accepted = ValidationState()
            validate_production_evidence(
                context, ga, predecessor, _candidate(root), _policy(), accepted
            )

            self.assertEqual(accepted.blockers, [])
            self.assertEqual(direct_ga_row["gaReleaseId"], ga.release_id)
            self.assertEqual(direct_ga_row["gaBuild"], ga.build_version)
            self.assertEqual(direct_ga_row["gaProductDigest"], ga.product_digest)

            direct_ga_row["gaProductDigest"] = predecessor.product_digest
            write_json(root / "evidence.json", evidence)
            rejected = ValidationState()
            validate_production_evidence(
                context, ga, predecessor, _candidate(root), _policy(), rejected
            )

            self.assertTrue(rejected.blockers)

    def test_evidence_rejects_fixture_stale_wrong_candidate_and_failed_rows(self) -> None:
        mutations = (
            ("fixture", lambda value: value.__setitem__("fixtureOnly", True)),
            ("wrong candidate", lambda value: value.__setitem__("candidateProductDigest", _digest("f"))),
            ("wrong freeze", lambda value: value.__setitem__("candidateFreezeDigest", _digest("e"))),
            (
                "wrong row freeze",
                lambda value: value["evidenceRows"][0].__setitem__(
                    "candidateFreezeDigest", _digest("e")
                ),
            ),
            ("stale row", lambda value: value["evidenceRows"][0].__setitem__("fresh", False)),
            ("failed row", lambda value: value["evidenceRows"][0].__setitem__("status", "fail")),
        )
        for label, mutate in mutations:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                value = _evidence()
                mutate(value)
                path = root / "evidence.json"
                write_json(path, value)
                state = ValidationState()
                validate_production_evidence(
                    _context(root, inputs={"maintenanceEvidence": "evidence.json"}),
                    _ga_and_predecessor()[0],
                    _ga_and_predecessor()[1],
                    _candidate(root),
                    _policy(),
                    state,
                )
                self.assertTrue(state.blockers)

    def test_warned_evidence_requires_exact_frozen_warning_and_waiver(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = _evidence()
            performance = next(
                row
                for row in evidence["evidenceRows"]
                if row["evidenceId"] == "stable-maintenance.performance"
            )
            performance["status"] = "warn"
            candidate = _candidate(root)
            warning = {
                "warningId": "stable-maintenance.performance-comparable-runner-warning",
                "status": "warn",
                "evidenceDigest": performance["evidenceDigest"],
            }
            candidate.input_value["operationalWarnings"] = [warning]
            write_json(root / "evidence.json", evidence)
            context = _context(root, inputs={"maintenanceEvidence": "evidence.json"})
            ga, predecessor = _ga_and_predecessor()
            state = ValidationState()

            validate_production_evidence(
                context, ga, predecessor, candidate, _policy(), state
            )
            expected = _authorization_expected(
                context,
                ga,
                predecessor,
                candidate,
                _digest("2"),
                _digest("3"),
                _digest("4"),
                _digest("5"),
                _digest("6"),
                _digest("7"),
                _digest("8"),
                None,
                _digest("9"),
            )

            self.assertEqual(state.blockers, [])
            self.assertEqual(
                ["stable-maintenance.performance-comparable-runner-warning"],
                expected["acceptedWarningIds"],
            )
            self.assertEqual(
                ["stable-maintenance.performance-comparable-runner-warning"],
                [row["id"] for row in state.warnings],
            )

    def test_warned_evidence_rejects_missing_or_wrong_frozen_binding(self) -> None:
        cases = (
            ("missing", None),
            ("wrong digest", _digest("f")),
        )
        for label, warning_digest in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                evidence = _evidence()
                performance = next(
                    row
                    for row in evidence["evidenceRows"]
                    if row["evidenceId"] == "stable-maintenance.performance"
                )
                performance["status"] = "warn"
                candidate = _candidate(root)
                if warning_digest is not None:
                    candidate.input_value["operationalWarnings"] = [
                        {
                            "warningId": "stable-maintenance.performance-comparable-runner-warning",
                            "status": "warn",
                            "evidenceDigest": warning_digest,
                        }
                    ]
                write_json(root / "evidence.json", evidence)
                state = ValidationState()

                validate_production_evidence(
                    _context(root, inputs={"maintenanceEvidence": "evidence.json"}),
                    _ga_and_predecessor()[0],
                    _ga_and_predecessor()[1],
                    candidate,
                    _policy(),
                    state,
                )

                self.assertTrue(state.blockers)

    def test_declared_warning_rejects_nonwarned_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = _evidence()
            performance = next(
                row
                for row in evidence["evidenceRows"]
                if row["evidenceId"] == "stable-maintenance.performance"
            )
            candidate = _candidate(root)
            candidate.input_value["operationalWarnings"] = [
                {
                    "warningId": "stable-maintenance.performance-comparable-runner-warning",
                    "status": "warn",
                    "evidenceDigest": performance["evidenceDigest"],
                }
            ]
            write_json(root / "evidence.json", evidence)
            state = ValidationState()

            validate_production_evidence(
                _context(root, inputs={"maintenanceEvidence": "evidence.json"}),
                _ga_and_predecessor()[0],
                _ga_and_predecessor()[1],
                candidate,
                _policy(),
                state,
            )

            self.assertTrue(state.blockers)

    def test_normal_evidence_rejects_short_individual_observation_window(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = _evidence()
            rows = evidence["evidenceRows"]
            assert isinstance(rows, list)
            live_row = next(
                row
                for row in rows
                if row["evidenceId"]
                == "stable-maintenance.live-network-interoperability"
            )
            live_row["startedAt"] = _timestamp(NOW - timedelta(hours=1))
            path = root / "evidence.json"
            write_json(path, evidence)
            state = ValidationState()
            validate_production_evidence(
                _context(root, inputs={"maintenanceEvidence": "evidence.json"}),
                _ga_and_predecessor()[0],
                _ga_and_predecessor()[1],
                _candidate(root),
                _policy(),
                state,
            )
            self.assertTrue(state.blockers)

    def test_evidence_rejects_pre_freeze_aggregate_and_rows(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence = _evidence()
            before_freeze = _timestamp(FROZEN - timedelta(hours=1))
            evidence["validationStartedAt"] = before_freeze
            for row in evidence["evidenceRows"]:
                row["startedAt"] = before_freeze
            write_json(root / "evidence.json", evidence)
            state = ValidationState()

            validate_production_evidence(
                _context(root, inputs={"maintenanceEvidence": "evidence.json"}),
                _ga_and_predecessor()[0],
                _ga_and_predecessor()[1],
                _candidate(root),
                _policy(),
                state,
            )

            self.assertTrue(state.blockers)

    def test_shortened_hotfix_window_creates_closed_obligation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidate = _candidate(root, "security-hotfix")
            evidence = _evidence("security-hotfix", window="shortened-security-hotfix")
            state = ValidationState()
            obligation = _hotfix_follow_up(
                _context(root, release_class="security-hotfix"),
                candidate,
                evidence,
                _policy(),
                NOW,
                state,
            )
            self.assertEqual(state.blockers, [])
            self.assertEqual(obligation["status"], "open")
            self.assertTrue(obligation["blocksRoutineMaintenance"])
            self.assertEqual(obligation["predecessorBuild"], PREDECESSOR_BUILD)
            self.assertEqual(
                obligation["predecessorProductDigest"], PREDECESSOR_PRODUCT_DIGEST
            )
            self.assertEqual(validate_schema(obligation, core.FOLLOW_UP_SCHEMA), [])
            without_predecessor = copy.deepcopy(obligation)
            without_predecessor.pop("predecessorBuild")
            self.assertTrue(validate_schema(without_predecessor, core.FOLLOW_UP_SCHEMA))

    def test_hotfix_follow_up_closes_only_with_full_production_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidate = _candidate(root, "security-hotfix")
            evidence = _evidence("security-hotfix")
            obligation = _hotfix_follow_up(
                _context(root, release_class="security-hotfix"),
                candidate,
                evidence,
                _policy(),
                NOW,
                ValidationState(),
            )
            obligation_path = root / "obligation.json"
            evidence_path = root / "follow-up.json"
            policy_path = root / "maintenance-policy.json"
            write_json(obligation_path, obligation)
            write_json(evidence_path, evidence)
            write_json(policy_path, _policy())
            context = _context(
                root,
                release_class="security-hotfix",
                mode="close-hotfix-follow-up",
                inputs={
                    "hotfixFollowUpObligation": "obligation.json",
                    "hotfixFollowUpEvidence": "follow-up.json",
                    "maintenancePolicy": "maintenance-policy.json",
                },
            )
            state = ValidationState()
            closure = close_hotfix_follow_up(
                context, _ga_and_predecessor()[0], candidate, state
            )
            self.assertEqual(state.blockers, [])
            self.assertEqual(closure["status"], "closed")
            evidence["fixtureOnly"] = True
            write_json(evidence_path, evidence)
            rejected = close_hotfix_follow_up(
                context, _ga_and_predecessor()[0], candidate, ValidationState()
            )
            self.assertEqual(rejected["status"], "rejected")

    def test_carried_hotfix_follow_up_closes_original_obligated_release(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            latest_candidate = _candidate(root, "security-hotfix")
            evidence = _evidence("security-hotfix")
            obligation = _hotfix_follow_up(
                _context(root, release_class="security-hotfix"),
                latest_candidate,
                evidence,
                _policy(),
                NOW,
                ValidationState(),
            )
            original_release = "stable-1-0-hotfix-300"
            original_build = "300"
            original_product = _digest("a")
            original_identity = _digest("b")
            original_freeze = _digest("c")
            original_predecessor_build = "299"
            original_predecessor_product = _digest("d")
            obligation.update(
                {
                    "releaseId": original_release,
                    "buildVersion": original_build,
                    "productDigest": original_product,
                    "candidateIdentityDigest": original_identity,
                    "candidateFreezeDigest": original_freeze,
                    "predecessorBuild": original_predecessor_build,
                    "predecessorProductDigest": original_predecessor_product,
                }
            )
            evidence.update(
                {
                    "releaseId": original_release,
                    "buildVersion": original_build,
                    "candidateProductDigest": original_product,
                    "candidateFreezeDigest": original_freeze,
                    "predecessorBuild": original_predecessor_build,
                    "predecessorProductDigest": original_predecessor_product,
                }
            )
            for row in evidence["evidenceRows"]:
                row.update(
                    {
                        "candidateReleaseId": original_release,
                        "candidateBuild": original_build,
                        "candidateProductDigest": original_product,
                        "candidateFreezeDigest": original_freeze,
                        "predecessorBuild": original_predecessor_build,
                        "predecessorProductDigest": original_predecessor_product,
                    }
                )
            write_json(root / "obligation.json", obligation)
            write_json(root / "follow-up.json", evidence)
            write_json(root / "maintenance-policy.json", _policy())
            context = _context(
                root,
                release_class="security-hotfix",
                mode="close-hotfix-follow-up",
                inputs={
                    "hotfixFollowUpObligation": "obligation.json",
                    "hotfixFollowUpEvidence": "follow-up.json",
                    "maintenancePolicy": "maintenance-policy.json",
                },
            )
            state = ValidationState()

            closure = close_hotfix_follow_up(
                context, _ga_and_predecessor()[0], latest_candidate, state
            )

            self.assertEqual(state.blockers, [])
            self.assertEqual(closure["status"], "closed")
            self.assertEqual(closure["releaseId"], original_release)
            self.assertEqual(closure["buildVersion"], original_build)
            self.assertEqual(closure["productDigest"], original_product)
            self.assertEqual(closure["candidateIdentityDigest"], original_identity)
            self.assertEqual(closure["predecessorBuild"], original_predecessor_build)
            self.assertEqual(
                closure["predecessorProductDigest"], original_predecessor_product
            )

    def test_hotfix_follow_up_rejects_substituted_original_predecessor(self) -> None:
        mutations = (
            lambda evidence, _row: evidence.__setitem__("predecessorBuild", "299"),
            lambda _evidence, row: row.__setitem__(
                "predecessorProductDigest", _digest("e")
            ),
        )
        for mutate in mutations:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                candidate = _candidate(root, "security-hotfix")
                evidence = _evidence("security-hotfix")
                obligation = _hotfix_follow_up(
                    _context(root, release_class="security-hotfix"),
                    candidate,
                    evidence,
                    _policy(),
                    NOW,
                    ValidationState(),
                )
                required_id = obligation["fullEvidenceRequired"][0]
                required_row = next(
                    row
                    for row in evidence["evidenceRows"]
                    if row["evidenceId"] == required_id
                )
                mutate(evidence, required_row)
                write_json(root / "obligation.json", obligation)
                write_json(root / "follow-up.json", evidence)
                write_json(root / "maintenance-policy.json", _policy())
                context = _context(
                    root,
                    release_class="security-hotfix",
                    mode="close-hotfix-follow-up",
                    inputs={
                        "hotfixFollowUpObligation": "obligation.json",
                        "hotfixFollowUpEvidence": "follow-up.json",
                        "maintenancePolicy": "maintenance-policy.json",
                    },
                )
                state = ValidationState()

                closure = close_hotfix_follow_up(
                    context, _ga_and_predecessor()[0], candidate, state
                )

                self.assertEqual(closure["status"], "rejected")
                self.assertTrue(state.blockers)

    def test_hotfix_follow_up_rejects_substituted_ga_upgrade_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidate = _candidate(root, "security-hotfix")
            evidence = _evidence("security-hotfix")
            obligation = _hotfix_follow_up(
                _context(root, release_class="security-hotfix"),
                candidate,
                evidence,
                _policy(),
                NOW,
                ValidationState(),
            )
            direct_ga_row = next(
                row
                for row in evidence["evidenceRows"]
                if row["evidenceId"] == "stable-maintenance.direct-ga-upgrade"
            )
            direct_ga_row["gaProductDigest"] = _digest("e")
            write_json(root / "obligation.json", obligation)
            write_json(root / "follow-up.json", evidence)
            write_json(root / "maintenance-policy.json", _policy())
            context = _context(
                root,
                release_class="security-hotfix",
                mode="close-hotfix-follow-up",
                inputs={
                    "hotfixFollowUpObligation": "obligation.json",
                    "hotfixFollowUpEvidence": "follow-up.json",
                    "maintenancePolicy": "maintenance-policy.json",
                },
            )
            state = ValidationState()

            closure = close_hotfix_follow_up(
                context, _ga_and_predecessor()[0], candidate, state
            )

            self.assertEqual(closure["status"], "rejected")
            self.assertTrue(state.blockers)

    def test_hotfix_follow_up_rejects_short_obligated_row_in_long_aggregate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidate = _candidate(root, "security-hotfix")
            evidence = _evidence("security-hotfix")
            obligation = _hotfix_follow_up(
                _context(root, release_class="security-hotfix"),
                candidate,
                evidence,
                _policy(),
                NOW,
                ValidationState(),
            )
            obligated_id = obligation["fullEvidenceRequired"][0]
            row = next(
                item
                for item in evidence["evidenceRows"]
                if item["evidenceId"] == obligated_id
            )
            row["startedAt"] = _timestamp(NOW - timedelta(hours=1))
            write_json(root / "obligation.json", obligation)
            write_json(root / "follow-up.json", evidence)
            write_json(root / "maintenance-policy.json", _policy())
            context = _context(
                root,
                release_class="security-hotfix",
                mode="close-hotfix-follow-up",
                inputs={
                    "hotfixFollowUpObligation": "obligation.json",
                    "hotfixFollowUpEvidence": "follow-up.json",
                    "maintenancePolicy": "maintenance-policy.json",
                },
            )
            state = ValidationState()

            closure = close_hotfix_follow_up(
                context, _ga_and_predecessor()[0], candidate, state
            )

            self.assertEqual(closure["status"], "rejected")
            self.assertTrue(state.blockers)

    def test_hotfix_follow_up_rejects_future_dated_full_window(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidate = _candidate(root, "security-hotfix")
            evidence = _evidence("security-hotfix")
            obligation = _hotfix_follow_up(
                _context(root, release_class="security-hotfix"),
                candidate,
                evidence,
                _policy(),
                NOW,
                ValidationState(),
            )
            future_start = NOW + timedelta(days=30)
            future_end = future_start + timedelta(days=1)
            evidence["validationStartedAt"] = _timestamp(future_start)
            evidence["validationEndedAt"] = _timestamp(future_end)
            for row in evidence["evidenceRows"]:
                row["startedAt"] = _timestamp(future_start)
                row["endedAt"] = _timestamp(future_end)
            write_json(root / "obligation.json", obligation)
            write_json(root / "follow-up.json", evidence)
            write_json(root / "maintenance-policy.json", _policy())
            context = _context(
                root,
                release_class="security-hotfix",
                mode="close-hotfix-follow-up",
                inputs={
                    "hotfixFollowUpObligation": "obligation.json",
                    "hotfixFollowUpEvidence": "follow-up.json",
                    "maintenancePolicy": "maintenance-policy.json",
                },
            )

            closure = close_hotfix_follow_up(
                context, _ga_and_predecessor()[0], candidate, ValidationState()
            )

            self.assertEqual(closure["status"], "rejected")

    def test_hotfix_follow_up_rejects_closure_when_an_earlier_gate_failed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidate = _candidate(root, "security-hotfix")
            evidence = _evidence("security-hotfix")
            obligation = _hotfix_follow_up(
                _context(root, release_class="security-hotfix"),
                candidate,
                evidence,
                _policy(),
                NOW,
                ValidationState(),
            )
            write_json(root / "obligation.json", obligation)
            write_json(root / "follow-up.json", evidence)
            write_json(root / "maintenance-policy.json", _policy())
            context = _context(
                root,
                release_class="security-hotfix",
                mode="close-hotfix-follow-up",
                inputs={
                    "hotfixFollowUpObligation": "obligation.json",
                    "hotfixFollowUpEvidence": "follow-up.json",
                    "maintenancePolicy": "maintenance-policy.json",
                },
            )
            state = ValidationState()
            state.block(
                "stable-maintenance.authorization",
                "stable-maintenance.authorization",
                "The original publication authorization did not match.",
                "Use the exact published authorization.",
            )

            closure = close_hotfix_follow_up(
                context, _ga_and_predecessor()[0], candidate, state
            )

            self.assertEqual(closure["status"], "rejected")


class StableMaintenanceAuthorizationAndPublicationTest(unittest.TestCase):
    def test_backport_release_train_handoff_is_exact_and_non_waivable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy_source = (
                workspace_root()
                / "tools/release-certification/stable-1.0-backport-release-train-policy.json"
            )
            policy_path = (
                root
                / "tools/release-certification/stable-1.0-backport-release-train-policy.json"
            )
            policy_path.parent.mkdir(parents=True)
            shutil.copyfile(policy_source, policy_path)
            ga, predecessor = _ga_and_predecessor()
            candidate = _candidate(root)
            public_fix = {
                "fixId": "stable-fix-abcdefghijklmnop",
                "classification": "compatible-bug-fix",
                "severity": "moderate",
                "publicSummary": "Corrects node behavior without changing stable contracts.",
                "affectedComponentSummary": "node-core",
                "provenanceMode": "inherited",
                "lineageDigest": _digest("8"),
                "publicProjectionDigest": _digest("5"),
                "incidentOpaqueId": None,
                "advisoryOpaqueId": None,
                "publicSecuritySummary": None,
                "securityPublicProjectionDigest": None,
                "disclosureState": None,
            }
            public_fix["publicProjectionDigest"] = semantic_digest(
                {
                    "fixId": public_fix["fixId"],
                    "classification": public_fix["classification"],
                    "publicSummary": public_fix["publicSummary"],
                }
            )
            validation = {
                "schemaVersion": 1,
                "kind": "stable-1.0-release-train-validation",
                "generatedAt": _timestamp(NOW),
                "stableMilestone": "1.0",
                "mode": "prepare-candidate",
                "trainId": "stable-train-301",
                "release": {
                    "releaseId": RELEASE_ID,
                    "releaseClass": "maintenance",
                    "buildVersion": BUILD,
                    "tag": f"v{BUILD}",
                },
                "policyDigest": file_digest(policy_path),
                "queueDigest": _digest("1"),
                "planDigest": _digest("2"),
                "candidateDigest": _digest("3"),
                "predecessorCommit": predecessor.source_commit,
                "candidateCommit": candidate.source["commit"],
                "hotfixFollowUpClosureDigest": predecessor.follow_up_closure_digest,
                "requiredFixIds": [public_fix["fixId"]],
                "includedFixIds": [public_fix["fixId"]],
                "omittedFixIds": [],
                "deferredFixIds": [],
                "unaccountedCommitIds": [],
                "publicFixes": [public_fix],
                "evidenceResults": [
                    release_train_evidence_result(
                        public_fix["fixId"],
                        "stable-backport.candidate-bound-tests",
                        _digest("4"),
                        NOW,
                    )
                ],
                "blockers": [],
                "authorizationRequired": True,
                "authorization": None,
                "decision": "go",
                "redaction": _redaction(),
            }
            prepare_validation_digest = semantic_digest(validation)
            train_authorization = {
                "schemaVersion": 1,
                "kind": "stable-1.0-release-train-authorization",
                "stableMilestone": "1.0",
                "trainId": validation["trainId"],
                "release": validation["release"],
                "repositoryIdentity": "github.com/crypta-network/cryptad",
                "workflowIdentity": (
                    "github.com/crypta-network/cryptad/.github/workflows/"
                    "stable-1.0-backport-release-train.yml@"
                    f"{candidate.source['commit']}"
                ),
                "policyDigest": validation["policyDigest"],
                "queueDigest": validation["queueDigest"],
                "planDigest": validation["planDigest"],
                "validationDigest": prepare_validation_digest,
                "predecessorCommit": predecessor.source_commit,
                "candidateCommit": candidate.source["commit"],
                "acceptedFixes": [public_fix],
                "securityOpaqueIds": [],
                "allowedOperation": "candidate-handoff",
                "role": "stable-maintenance-train-manager",
                "scope": ["train:composition", "candidate:handoff"],
                "issuedAt": _timestamp(NOW - timedelta(minutes=30)),
                "expiresAt": _timestamp(NOW + timedelta(hours=1)),
                "decision": "go",
                "redaction": _redaction(),
            }
            train_authorization["authorizationDigest"] = semantic_digest(
                train_authorization
            )
            validation["mode"] = "validate-authorization"
            validation["authorization"] = {
                "authorizationDigest": train_authorization[
                    "authorizationDigest"
                ],
                "status": "valid",
                "expiresAt": train_authorization["expiresAt"],
                "role": train_authorization["role"],
            }
            validation["validationDigest"] = semantic_digest(validation)
            train_path = root / "train.json"
            train_authorization_path = root / "train-authorization.json"
            write_json(train_path, validation)
            write_json(train_authorization_path, train_authorization)
            context = _context(
                root,
                inputs={
                    "stableBackportReleaseTrainAuthorization": "train-authorization.json",
                    "stableBackportReleaseTrainValidation": "train.json",
                },
            )
            state = ValidationState()
            with mock.patch.object(
                stable_1_0_maintenance, "_now", return_value=NOW
            ):
                loaded, authenticated = stable_1_0_maintenance._authenticate_backport_release_train(  # noqa: SLF001
                    context, predecessor, candidate, state
                )

            self.assertEqual((state.blockers, authenticated), ([], True))
            self.assertEqual(loaded.digest, file_digest(train_path))
            substituted = copy.deepcopy(validation)
            substituted["candidateCommit"] = "f" * 40
            substituted["validationDigest"] = semantic_digest(
                {
                    key: value
                    for key, value in substituted.items()
                    if key != "validationDigest"
                }
            )
            write_json(train_path, substituted)
            rejected = ValidationState()
            with mock.patch.object(
                stable_1_0_maintenance, "_now", return_value=NOW
            ):
                stable_1_0_maintenance._authenticate_backport_release_train(  # noqa: SLF001
                    context, predecessor, candidate, rejected
                )
            self.assertTrue(rejected.blockers)
            write_json(train_path, validation)
            substituted_authorization = copy.deepcopy(train_authorization)
            substituted_authorization["candidateCommit"] = "f" * 40
            substituted_authorization["authorizationDigest"] = semantic_digest(
                {
                    key: value
                    for key, value in substituted_authorization.items()
                    if key != "authorizationDigest"
                }
            )
            substituted_validation = copy.deepcopy(validation)
            substituted_validation["authorization"]["authorizationDigest"] = (
                substituted_authorization["authorizationDigest"]
            )
            substituted_validation["validationDigest"] = semantic_digest(
                {
                    key: value
                    for key, value in substituted_validation.items()
                    if key != "validationDigest"
                }
            )
            write_json(train_path, substituted_validation)
            write_json(train_authorization_path, substituted_authorization)
            rejected_authorization = ValidationState()
            with mock.patch.object(
                stable_1_0_maintenance, "_now", return_value=NOW
            ):
                stable_1_0_maintenance._authenticate_backport_release_train(  # noqa: SLF001
                    context, predecessor, candidate, rejected_authorization
                )
            self.assertTrue(rejected_authorization.blockers)

    def test_hotfix_train_binds_candidate_incident_and_policy_authorization(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            policy_relative = Path(
                "tools/release-certification/"
                "stable-1.0-backport-release-train-policy.json"
            )
            policy_source = workspace_root() / policy_relative
            policy_path = root / policy_relative
            policy_path.parent.mkdir(parents=True)
            shutil.copyfile(policy_source, policy_path)
            _ga, predecessor = _ga_and_predecessor()
            candidate = _candidate(root, "security-hotfix")
            scope = candidate.input_value["changeScope"]
            incident = scope["incidentId"]
            policy_authorization_digest = scope[
                "hotfixPolicyAuthorizationDigest"
            ]

            def bundle(
                incident_id: str,
                incident_evidence_digest: str,
                advisory_id: str | None = None,
                severity: str = "critical",
            ) -> tuple[dict[str, object], dict[str, object]]:
                public_fix: dict[str, object] = {
                    "fixId": "stable-fix-abcdefghijklmnop",
                    "classification": "security-fix",
                    "severity": severity,
                    "publicSummary": "A bounded security correction is available.",
                    "affectedComponentSummary": "node-core",
                    "provenanceMode": "inherited",
                    "lineageDigest": _digest("8"),
                    "incidentOpaqueId": incident_id,
                    "advisoryOpaqueId": advisory_id,
                    "publicSecuritySummary": "A bounded security correction is available.",
                    "disclosureState": "protected-embargoed",
                }
                public_fix["publicProjectionDigest"] = semantic_digest(
                    {
                        "fixId": public_fix["fixId"],
                        "classification": public_fix["classification"],
                        "publicSummary": public_fix["publicSummary"],
                    }
                )
                public_fix["securityPublicProjectionDigest"] = semantic_digest(
                    {
                        "fixId": public_fix["fixId"],
                        "incidentOpaqueId": incident_id,
                        "advisoryOpaqueId": advisory_id,
                        "severity": severity,
                        "disclosureState": "protected-embargoed",
                        "publicSafeSummary": public_fix[
                            "publicSecuritySummary"
                        ],
                    }
                )
                release = {
                    "releaseId": RELEASE_ID,
                    "releaseClass": "security-hotfix",
                    "buildVersion": BUILD,
                    "tag": f"v{BUILD}",
                }
                prepare: dict[str, object] = {
                    "schemaVersion": 1,
                    "kind": "stable-1.0-release-train-validation",
                    "generatedAt": _timestamp(NOW),
                    "stableMilestone": "1.0",
                    "mode": "prepare-candidate",
                    "trainId": "stable-train-301",
                    "release": release,
                    "policyDigest": file_digest(policy_path),
                    "queueDigest": _digest("1"),
                    "planDigest": _digest("2"),
                    "candidateDigest": _digest("3"),
                    "predecessorCommit": predecessor.source_commit,
                    "candidateCommit": candidate.source["commit"],
                    "hotfixFollowUpClosureDigest": (
                        predecessor.follow_up_closure_digest
                    ),
                    "requiredFixIds": [public_fix["fixId"]],
                    "includedFixIds": [public_fix["fixId"]],
                    "omittedFixIds": [],
                    "deferredFixIds": [],
                    "unaccountedCommitIds": [],
                    "publicFixes": [public_fix],
                    "evidenceResults": [
                        release_train_evidence_result(
                            public_fix["fixId"],
                            "stable-backport.candidate-bound-tests",
                            _digest("4"),
                            NOW,
                        ),
                        release_train_evidence_result(
                            public_fix["fixId"],
                            "stable-backport.security-incident-scope",
                            incident_evidence_digest,
                            NOW,
                        ),
                        release_train_evidence_result(
                            public_fix["fixId"],
                            "stable-backport.security-public-projection",
                            _digest("7"),
                            NOW,
                        ),
                    ],
                    "blockers": [],
                    "authorizationRequired": True,
                    "authorization": None,
                    "decision": "go",
                    "redaction": _redaction(),
                }
                prepare_digest = semantic_digest(prepare)
                authorization: dict[str, object] = {
                    "schemaVersion": 1,
                    "kind": "stable-1.0-release-train-authorization",
                    "stableMilestone": "1.0",
                    "trainId": prepare["trainId"],
                    "release": release,
                    "repositoryIdentity": "github.com/crypta-network/cryptad",
                    "workflowIdentity": (
                        "github.com/crypta-network/cryptad/.github/workflows/"
                        "stable-1.0-backport-release-train.yml@"
                        f"{candidate.source['commit']}"
                    ),
                    "policyDigest": prepare["policyDigest"],
                    "queueDigest": prepare["queueDigest"],
                    "planDigest": prepare["planDigest"],
                    "validationDigest": prepare_digest,
                    "predecessorCommit": predecessor.source_commit,
                    "candidateCommit": candidate.source["commit"],
                    "acceptedFixes": [public_fix],
                    "securityOpaqueIds": [incident_id],
                    "allowedOperation": "candidate-handoff",
                    "role": "stable-security-train-manager",
                    "scope": ["train:composition", "candidate:handoff"],
                    "issuedAt": _timestamp(NOW - timedelta(minutes=30)),
                    "expiresAt": _timestamp(NOW + timedelta(hours=1)),
                    "decision": "go",
                    "redaction": _redaction(),
                }
                authorization["authorizationDigest"] = semantic_digest(authorization)
                validation = copy.deepcopy(prepare)
                validation["mode"] = "validate-authorization"
                validation["authorization"] = {
                    "authorizationDigest": authorization["authorizationDigest"],
                    "status": "valid",
                    "expiresAt": authorization["expiresAt"],
                    "role": authorization["role"],
                }
                validation["validationDigest"] = semantic_digest(validation)
                return validation, authorization

            train_path = root / "hotfix-train.json"
            authorization_path = root / "hotfix-train-authorization.json"
            context = _context(
                root,
                release_class="security-hotfix",
                inputs={
                    "stableBackportReleaseTrainAuthorization": "hotfix-train-authorization.json",
                    "stableBackportReleaseTrainValidation": "hotfix-train.json",
                },
            )
            valid_train, valid_authorization = bundle(
                incident,
                policy_authorization_digest,
            )
            write_json(train_path, valid_train)
            write_json(authorization_path, valid_authorization)
            valid_state = ValidationState()

            with mock.patch.object(
                stable_1_0_maintenance, "_now", return_value=NOW
            ):
                stable_1_0_maintenance._authenticate_backport_release_train(  # noqa: SLF001
                    context, predecessor, candidate, valid_state
                )

            self.assertEqual(valid_state.blockers, [])
            advisory = "CRYPTA-ADVISORY-301"
            scope["incidentId"] = advisory
            advisory_train, advisory_authorization = bundle(
                incident,
                policy_authorization_digest,
                advisory,
            )
            write_json(train_path, advisory_train)
            write_json(authorization_path, advisory_authorization)
            advisory_state = ValidationState()
            with mock.patch.object(
                stable_1_0_maintenance, "_now", return_value=NOW
            ):
                stable_1_0_maintenance._authenticate_backport_release_train(  # noqa: SLF001
                    context, predecessor, candidate, advisory_state
                )
            self.assertEqual(advisory_state.blockers, [])
            scope["incidentId"] = incident
            for label, train_incident, evidence_digest, severity in (
                ("incident", "CRYPTA-SEC-OTHER", policy_authorization_digest, "critical"),
                ("policy-authorization", incident, _digest("f"), "critical"),
                ("noncritical-hotfix", incident, policy_authorization_digest, "high"),
            ):
                with self.subTest(label=label):
                    bad_train, bad_authorization = bundle(
                        train_incident,
                        evidence_digest,
                        severity=severity,
                    )
                    write_json(train_path, bad_train)
                    write_json(authorization_path, bad_authorization)
                    rejected = ValidationState()
                    with mock.patch.object(
                        stable_1_0_maintenance, "_now", return_value=NOW
                    ):
                        stable_1_0_maintenance._authenticate_backport_release_train(  # noqa: SLF001
                            context, predecessor, candidate, rejected
                        )
                    self.assertTrue(rejected.blockers)

    def test_public_checksums_name_only_noncircular_public_payloads(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidate = _candidate(root)
            generated = {
                core.RELEASE_NOTES_FILE: b"maintenance notes\n",
                core.KNOWN_LIMITATIONS_FILE: b"{}\n",
                core.PROVENANCE_FILE: b"{}\n",
                core.CORE_INFO_FILE: b"{}\n",
                core.AUTHORIZATION_FILE: b"{}\n",
            }
            for name, payload in generated.items():
                (root / name).write_bytes(payload)

            payload_paths = _public_checksum_payload_paths(candidate, root)
            _write_checksums(root / core.CHECKSUMS_FILE, payload_paths.values())
            planned_assets = _public_assets(
                candidate,
                root,
                "https://downloads.crypta.network/stable/",
                root / core.AUTHORIZATION_FILE,
            )

            planned_names = {row["fileName"] for row in planned_assets}
            noncircular_names = planned_names - {
                core.CHECKSUMS_FILE,
                core.AUTHORIZATION_FILE,
            }
            checksum_names = {
                line.split("  ", 1)[1]
                for line in (root / core.CHECKSUMS_FILE)
                .read_text(encoding="utf-8")
                .splitlines()
            }
            internal_names = {
                core.CANDIDATE_FREEZE_FILE,
                core.CANDIDATE_FILE,
                core.LINEAGE_FILE,
                core.COMPARISON_FILE,
                core.FOLLOW_UP_FILE,
                core.PUBLICATION_PLAN_FILE,
                core.AUDIT_CHECKSUMS_FILE,
            }

            self.assertEqual(checksum_names, noncircular_names)
            self.assertTrue(internal_names.isdisjoint(checksum_names))
            self.assertNotIn(core.AUDIT_CHECKSUMS_FILE, planned_names)

    def test_canonical_authorization_input_preserves_unescaped_unicode(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "authorization.json"
            value = {"approverIdentity": "José stable-release-manager"}
            path.write_bytes(
                (
                    json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True)
                    + "\n"
                ).encode("utf-8")
            )

            self.assertTrue(
                stable_1_0_maintenance._canonical_json_input(path, value)  # noqa: SLF001
            )
            self.assertIn("José", path.read_text(encoding="utf-8"))
            self.assertNotIn(r"\u00e9", path.read_text(encoding="utf-8"))

            path.write_bytes(
                (
                    json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True)
                    + "\n"
                ).encode("utf-8")
            )
            self.assertFalse(
                stable_1_0_maintenance._canonical_json_input(path, value)  # noqa: SLF001
            )

    def test_publication_targets_require_nonempty_catalog_mirror(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            context = _context(Path(directory))
            context.manifest.policies["metadata"]["catalogMirrorUris"] = "  "
            state = ValidationState()

            stable_1_0_maintenance._targets(context, state)  # noqa: SLF001

            self.assertTrue(
                any(
                    "require at least one catalog mirror URI" in row["summary"]
                    for row in state.blockers
                ),
                state.blockers,
            )

    def test_publication_targets_require_the_fixed_github_release_page(self) -> None:
        invalid_pages = (
            "https://93.184.216.34/releases/tag/v301",
            "https://github.com/crypta-network/another/releases/tag/v301",
            "https://github.com/crypta-network/cryptad/releases/tag/v302",
        )
        for page_uri in invalid_pages:
            with self.subTest(page_uri=page_uri), tempfile.TemporaryDirectory() as directory:
                context = _context(Path(directory))
                context.manifest.policies["metadata"]["githubReleasePageUri"] = page_uri
                state = ValidationState()

                stable_1_0_maintenance._targets(context, state)  # noqa: SLF001

                self.assertTrue(
                    any(
                        "fixed repository and build tag" in row["summary"]
                        for row in state.blockers
                    ),
                    state.blockers,
                )

    def test_publication_targets_canonicalize_authorities_before_distinctness(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            context = _context(Path(directory))
            metadata = context.manifest.policies["metadata"]
            metadata["catalogPrimaryUri"] = (
                "https://CATALOG.CRYPTA.NETWORK:443/stable/catalog.json"
            )
            metadata["catalogMirrorUris"] = (
                "https://catalog.crypta.network/stable/catalog.json"
            )
            state = ValidationState()

            targets, _digest_value = stable_1_0_maintenance._targets(  # noqa: SLF001
                context, state
            )

            self.assertEqual(
                targets["catalogPrimaryUri"],
                "https://catalog.crypta.network/stable/catalog.json",
            )
            self.assertTrue(
                any(
                    "ambiguous duplicate URI" in row["summary"]
                    for row in state.blockers
                ),
                state.blockers,
            )

    def test_publication_targets_reject_ambiguous_or_whitespace_paths(self) -> None:
        unsafe_uris = (
            "https://catalog.crypta.network/stable/../history/300.json",
            "https://catalog.crypta.network/stable/catalog copy.json",
            "https://catalog.crypta.network/stable/%63atalog.json",
        )
        for unsafe_uri in unsafe_uris:
            with self.subTest(
                unsafe_uri=unsafe_uri
            ), tempfile.TemporaryDirectory() as directory:
                context = _context(Path(directory))
                context.manifest.policies["metadata"]["catalogRollbackUri"] = unsafe_uri
                state = ValidationState()

                stable_1_0_maintenance._targets(context, state)  # noqa: SLF001

                self.assertTrue(state.blockers)

    def test_configurable_publication_targets_remain_fail_closed(self) -> None:
        unsafe_uris = (
            "http://93.184.216.34/stable/catalog.json",
            "https://localhost/stable/catalog.json",
            "https://169.254.169.254/stable/catalog.json",
            "https://user:password@93.184.216.34/stable/catalog.json",
            "https://93.184.216.34/stable/catalog.json?edition=301",
            "https://93.184.216.34/stable/catalog.json#fragment",
        )
        for unsafe_uri in unsafe_uris:
            with self.subTest(
                unsafe_uri=unsafe_uri
            ), tempfile.TemporaryDirectory() as directory:
                context = _context(Path(directory))
                context.manifest.policies["metadata"]["catalogRollbackUri"] = unsafe_uri
                state = ValidationState()

                stable_1_0_maintenance._targets(context, state)  # noqa: SLF001

                self.assertTrue(
                    any(
                        "public credential-free HTTPS" in row["summary"]
                        for row in state.blockers
                    ),
                    state.blockers,
                )

    def test_concrete_publication_destinations_are_distinct(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            context = _context(root)
            state = ValidationState()
            targets, _targets_digest = stable_1_0_maintenance._targets(  # noqa: SLF001
                context, state
            )

            errors = stable_1_0_maintenance._concrete_publication_destination_errors(  # noqa: SLF001
                targets, _candidate(root)
            )

            self.assertEqual(state.blockers, [])
            self.assertEqual(errors, [])

    def test_concrete_publication_destinations_keep_fixed_github_target_offline(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            stable_1_0_ga_core.socket,
            "getaddrinfo",
            side_effect=OSError("DNS unavailable"),
        ):
            root = Path(directory)
            state = ValidationState()
            targets, _targets_digest = stable_1_0_maintenance._targets(  # noqa: SLF001
                _context(root), state
            )

            errors = stable_1_0_maintenance._concrete_publication_destination_errors(  # noqa: SLF001
                targets, _candidate(root)
            )

            self.assertEqual(state.blockers, [])
            self.assertEqual(errors, [])

    def test_catalog_signature_cannot_alias_core_update_descriptor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            context = _context(root)
            context.manifest.policies["metadata"]["coreUpdatePublicUri"] = (
                "https://93.184.216.34:443/catalog/stable/stable-catalog.json.sig"
            )
            state = ValidationState()
            targets, _targets_digest = stable_1_0_maintenance._targets(  # noqa: SLF001
                context, state
            )

            errors = stable_1_0_maintenance._concrete_publication_destination_errors(  # noqa: SLF001
                targets, _candidate(root)
            )

            self.assertEqual(state.blockers, [])
            self.assertTrue(
                any(
                    "core-update-descriptor" in error
                    and "stable-catalog-signature" in error
                    for error in errors
                ),
                errors,
            )

    def test_catalog_signature_cannot_alias_core_info_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            context = _context(root)
            candidate = _candidate(root)
            catalog = candidate.input_value["stableCatalog"]
            assert isinstance(catalog, dict)
            catalog["signatureFileName"] = core.CORE_INFO_FILE
            state = ValidationState()
            targets, _targets_digest = stable_1_0_maintenance._targets(  # noqa: SLF001
                context, state
            )

            errors = stable_1_0_maintenance._concrete_publication_destination_errors(  # noqa: SLF001
                targets, candidate
            )

            self.assertEqual(state.blockers, [])
            self.assertTrue(
                any(
                    "artifact:core-info" in error
                    and "artifact:stable-catalog-signature" in error
                    for error in errors
                ),
                errors,
            )

    def test_catalog_and_mirror_objects_cannot_alias_artifact_objects(self) -> None:
        cases = (
            ("catalogPrimaryUri", "stable-catalog.json"),
            ("catalogMirrorUris", "cryptad-301.tar.gz"),
            ("catalogRollbackUri", core.CORE_INFO_FILE),
        )
        for field, artifact_name in cases:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                context = _context(root)
                context.manifest.policies["metadata"][field] = (
                    f"https://93.184.216.34/artifacts/stable/{artifact_name}"
                )
                state = ValidationState()
                targets, _targets_digest = stable_1_0_maintenance._targets(  # noqa: SLF001
                    context, state
                )

                errors = stable_1_0_maintenance._concrete_publication_destination_errors(  # noqa: SLF001
                    targets, _candidate(root)
                )

                self.assertEqual(state.blockers, [])
                self.assertTrue(errors)

    def test_authorization_expected_identity_is_exact_and_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ga, predecessor = _ga_and_predecessor()
            candidate = _candidate(root)
            args = (
                _context(root), ga, predecessor, candidate,
                _digest("2"), _digest("3"), _digest("4"), _digest("5"),
                _digest("6"), _digest("7"), _digest("8"), None,
                _digest("9"),
            )
            first = _authorization_expected(*args)
            second = _authorization_expected(*args)
            self.assertEqual(first, second)
            self.assertEqual(first["role"], "stable-maintenance-release-manager")
            self.assertEqual(first["candidateFreezeDigest"], candidate.freeze_digest)
            self.assertEqual(first["allowedPublicationScopes"], list(AUTHORIZATION_SCOPE))
            changed = dict(first)
            changed["productDigest"] = _digest("f")
            self.assertNotEqual(semantic_digest(first), semantic_digest(changed))

    def test_authorization_request_requires_waiver_decision_for_warnings(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            context = _context(root, mode="prepare-authorization")
            ga, predecessor = _ga_and_predecessor()
            candidate = _candidate(root)
            expected = _authorization_expected(
                context,
                ga,
                predecessor,
                candidate,
                _digest("2"),
                _digest("3"),
                _digest("4"),
                _digest("5"),
                _digest("6"),
                _digest("7"),
                _digest("8"),
                None,
                _digest("9"),
            )
            state = ValidationState()

            request, _request_digest, authorized = _authorization(
                context, expected, _policy(), state, prepare=True
            )

            self.assertEqual(request["decisionRequired"], "go")
            self.assertFalse(authorized)

            expected["acceptedWarningIds"] = [
                "stable-maintenance.performance-comparable-runner-warning"
            ]
            warned_request, _warned_digest, warned_authorized = _authorization(
                context, expected, _policy(), state, prepare=True
            )

            self.assertEqual(
                warned_request["decisionRequired"], "go-with-waivers"
            )
            self.assertFalse(warned_authorized)

    def test_authorization_scope_is_accepted_by_closed_schema(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ga, predecessor = _ga_and_predecessor()
            expected = _authorization_expected(
                _context(root), ga, predecessor, _candidate(root),
                _digest("2"), _digest("3"), _digest("4"), _digest("5"),
                _digest("6"), _digest("7"), _digest("8"), None,
                _digest("9"),
            )
            authorization = {
                "schemaVersion": 1,
                "kind": "stable-1.0-maintenance-authorization",
                "authorizationId": "maintenance-301-authorization",
                **expected,
                "approverIdentity": "stable-maintenance-approver",
                "authorizedAt": _timestamp(NOW - timedelta(minutes=5)),
                "expiresAt": _timestamp(NOW + timedelta(hours=1)),
                "decision": "go",
                "status": "approved",
                "redaction": _redaction(),
            }
            self.assertEqual(validate_schema(authorization, AUTHORIZATION_SCHEMA), [])

    def test_follow_up_closure_requires_exact_published_eligible_authorization(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            context = _context(root, release_class="security-hotfix")
            ga, predecessor = _ga_and_predecessor()
            candidate = _candidate(root, "security-hotfix")
            expected = _authorization_expected(
                context,
                ga,
                predecessor,
                candidate,
                _digest("2"),
                _digest("3"),
                _digest("4"),
                _digest("5"),
                _digest("6"),
                _digest("7"),
                _digest("8"),
                _digest("9"),
                _digest("a"),
            )
            authorization = {
                "schemaVersion": 1,
                "kind": "stable-1.0-maintenance-authorization",
                "authorizationId": "hotfix-301-authorization",
                **expected,
                "approverIdentity": "stable-security-approver",
                "authorizedAt": _timestamp(NOW - timedelta(minutes=5)),
                "expiresAt": _timestamp(NOW + timedelta(hours=1)),
                "decision": "go",
                "status": "approved",
                "redaction": _redaction(),
            }
            authorization_path = root / "authorization.json"
            write_json(authorization_path, authorization)
            loaded = LoadedJson(
                "stableMaintenanceAuthorization",
                authorization_path,
                authorization,
                file_digest(authorization_path),
            )
            obligation = SimpleNamespace(
                value={
                    "releaseId": RELEASE_ID,
                    "buildVersion": BUILD,
                    "productDigest": candidate.product_digest,
                    "candidateIdentityDigest": candidate.identity_digest,
                    "candidateFreezeDigest": candidate.freeze_digest,
                }
            )
            published_follow_up = {"authorizationDigest": loaded.digest}
            self.assertEqual(
                _close_authorization_errors(loaded, obligation, published_follow_up), []
            )

            replacement = copy.deepcopy(authorization)
            replacement["approverIdentity"] = "replacement-approver"
            write_json(root / "replacement.json", replacement)
            replacement_loaded = LoadedJson(
                "stableMaintenanceAuthorization",
                root / "replacement.json",
                replacement,
                file_digest(root / "replacement.json"),
            )
            self.assertTrue(
                _close_authorization_errors(replacement_loaded, obligation, published_follow_up)
            )

            no_go = copy.deepcopy(authorization)
            no_go["decision"] = "no-go"
            write_json(root / "no-go.json", no_go)
            no_go_loaded = LoadedJson(
                "stableMaintenanceAuthorization",
                root / "no-go.json",
                no_go,
                file_digest(root / "no-go.json"),
            )
            no_go_follow_up = {"authorizationDigest": no_go_loaded.digest}
            self.assertTrue(
                _close_authorization_errors(no_go_loaded, obligation, no_go_follow_up)
            )

    def _core_receipt_fixture(
        self, root: Path, operation: str
    ) -> tuple[
        RunContext,
        LoadedJson,
        Candidate,
        Path,
        dict[str, object],
        Path,
        dict[str, object],
    ]:
        context = _context(root)
        candidate = _candidate(root)
        descriptor = build_core_info(context, candidate, ValidationState())[0]
        core_info_path = root / "core-info.json"
        core_plan_path = root / "core-plan.json"
        write_json(core_info_path, descriptor)
        core_plan = {
            "descriptorDigest": file_digest(core_info_path),
            "descriptorSizeBytes": core_info_path.stat().st_size,
            "packageMapDigest": semantic_digest(descriptor["packages"]),
            "edition": int(BUILD),
            "publicFetchUri": "https://updates.crypta.network/info/301/core-info.json",
        }
        write_json(core_plan_path, core_plan)
        receipt = {
            "schemaVersion": 1,
            "kind": "cryptad-core-update-publication-receipt",
            "generatedAt": _timestamp(),
            "releaseId": RELEASE_ID,
            "buildVersion": BUILD,
            "releaseClass": "maintenance",
            "candidateIdentityDigest": candidate.identity_digest,
            "publicationPlanDigest": file_digest(core_plan_path),
            "descriptorDigest": file_digest(core_info_path),
            "descriptorSizeBytes": core_info_path.stat().st_size,
            "packageMapDigest": semantic_digest(descriptor["packages"]),
            "edition": int(BUILD),
            "publicFetchUri": "https://updates.crypta.network/info/301/core-info.json",
            "operation": operation,
            "fetchedDescriptorDigest": file_digest(core_info_path),
            "referencedPackages": [
                {
                    "packageKey": row["packageKey"],
                    "candidateAssetDigest": row["digest"],
                    "candidateAssetSizeBytes": row["sizeBytes"],
                    "publicReference": row["publicChk"],
                    "verificationStatus": "pass",
                }
                for row in candidate.assets
            ],
            "conflictStatus": "clear",
            "verificationStatus": "pass",
            "publicationState": "publication-complete",
            "redaction": _redaction(),
        }
        path = root / "core-receipt.json"
        write_json(path, receipt)
        return (
            context,
            LoadedJson("coreUpdatePublicationReceipt", path, receipt, file_digest(path)),
            candidate,
            core_plan_path,
            core_plan,
            core_info_path,
            descriptor,
        )

    def test_core_receipt_created_and_existing_are_idempotent(self) -> None:
        for operation in ("created", "verified-existing"):
            with self.subTest(operation=operation), tempfile.TemporaryDirectory() as directory:
                args = self._core_receipt_fixture(Path(directory), operation)
                self.assertEqual(_core_receipt_errors(*args), [])

    def test_core_receipt_conflict_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            args = list(self._core_receipt_fixture(Path(directory), "verified-existing"))
            loaded = args[1]
            loaded.value["fetchedDescriptorDigest"] = _digest("f")
            write_json(loaded.path, loaded.value)
            self.assertTrue(_core_receipt_errors(*args))

    def test_core_receipt_wrong_authorized_target_fails_closed(self) -> None:
        mutations = (
            ("edition", 302),
            ("publicFetchUri", "https://updates.crypta.network/info/302/core-info.json"),
        )
        for field, replacement in mutations:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                args = list(self._core_receipt_fixture(Path(directory), "created"))
                loaded = args[1]
                assert isinstance(loaded, LoadedJson)
                loaded.value[field] = replacement
                write_json(loaded.path, loaded.value)
                self.assertTrue(_core_receipt_errors(*args))

    def _publication_fixture(
        self, root: Path, operation: str
    ) -> tuple[tuple[object, ...], dict[str, object]]:
        context = _context(root)
        candidate = _candidate(root)
        asset = {
            "role": "product",
            "fileName": candidate.product_path.name,
            "digest": candidate.product_digest,
            "sizeBytes": 17,
            "publicUri": "https://downloads.crypta.network/stable/cryptad-301.tar.gz",
        }
        plan = {
            "githubReleasePageUri": "https://github.com/crypta-network/cryptad/releases/tag/v301",
            "deploymentServicePublicUri": "https://93.184.216.34/deployment/observe",
            "latestPointerPublicUri": "https://93.184.216.34/maintenance/latest.json",
            "checksumsDigest": _digest("2"),
            "provenanceDigest": _digest("3"),
            "authorizationDigest": _digest("4"),
            "backportReleaseTrainDigest": _digest("7"),
            "releaseNotesDigest": _digest("5"),
            "coreInfoDigest": _digest("6"),
            "stableCatalogDigest": _digest("b"),
            "assets": [asset],
            "stableCatalogTarget": {
                "catalogId": "crypta-first-party",
                "channel": "stable",
                "revision": 8,
                "edition": 8,
                "digest": _digest("b"),
                "signatureDigest": _digest("c"),
                "publicUri": "https://catalog.crypta.network/stable/catalog.json",
                "signaturePublicUri": "https://catalog.crypta.network/stable/stable-catalog.json.sig",
                "mirrorUris": ["https://mirror.crypta.network/stable/catalog.json"],
                "rollbackUri": "https://catalog.crypta.network/stable/history/300/catalog.json",
                "mirrorSetDigest": _digest("d"),
                "rollbackStateDigest": _digest("e"),
            },
            "coreUpdateTarget": {
                "edition": 301,
                "descriptorDigest": _digest("6"),
                "publicUri": "https://updates.crypta.network/info/301/core-info.json",
                "protectedInsertInputName": "CRYPTAD_CORE_UPDATE_PUBLICATION_INPUT",
            },
        }
        plan_path = root / "publication-plan.json"
        write_json(plan_path, plan)
        core_receipt = {
            "descriptorDigest": _digest("6"),
            "packageMapDigest": _digest("7"),
            "edition": 301,
            "publicFetchUri": "https://updates.crypta.network/info/301/core-info.json",
        }
        core_receipt_digest = _digest("8")
        successor_digest = _digest("9")
        history_digest = _digest("a")
        receipt = {
            "schemaVersion": 1,
            "kind": "stable-1.0-maintenance-publication-receipt",
            "generatedAt": _timestamp(),
            "releaseId": RELEASE_ID,
            "buildVersion": BUILD,
            "releaseClass": "maintenance",
            "sourceCommit": COMMIT,
            "githubReleasePageUri": plan["githubReleasePageUri"],
            "deploymentServicePublicUri": plan["deploymentServicePublicUri"],
            "latestPointerPublicUri": plan["latestPointerPublicUri"],
            "candidateIdentityDigest": candidate.identity_digest,
            "productDigest": candidate.product_digest,
            "checksumsDigest": plan["checksumsDigest"],
            "provenanceDigest": plan["provenanceDigest"],
            "authorizationDigest": plan["authorizationDigest"],
            "backportReleaseTrainDigest": plan["backportReleaseTrainDigest"],
            "coreUpdateReceiptDigest": core_receipt_digest,
            "publicationPlanDigest": file_digest(plan_path),
            "releaseNotesDigest": plan["releaseNotesDigest"],
            "coreInfoDigest": plan["coreInfoDigest"],
            "successorBaselineDigest": successor_digest,
            "releaseHistoryDigest": history_digest,
            "tag": {
                "name": "v301", "objectType": "annotated", "targetCommit": COMMIT,
                "tagObjectDigest": _digest("b"), "operation": operation,
                "verificationStatus": "verified",
            },
            "githubRelease": {
                "releaseId": RELEASE_ID, "tag": "v301",
                "pageUri": "https://github.com/crypta-network/cryptad/releases/tag/v301",
                "notesDigest": plan["releaseNotesDigest"], "operation": operation,
                "verificationStatus": "verified",
            },
            "assets": [{**asset, "operation": operation, "verificationStatus": "verified"}],
            "stableCatalog": {
                "catalogId": "crypta-first-party", "revision": 8, "edition": 8,
                "digest": plan["stableCatalogDigest"], "signatureDigest": _digest("c"),
                "publicUri": "https://catalog.crypta.network/stable/catalog.json",
                "signaturePublicUri": "https://catalog.crypta.network/stable/stable-catalog.json.sig",
                "mirrorSetDigest": _digest("d"), "rollbackStateDigest": _digest("e"),
                "operation": operation, "verificationStatus": "verified",
            },
            "coreUpdate": {
                "edition": 301, "descriptorDigest": core_receipt["descriptorDigest"],
                "publicUri": "https://updates.crypta.network/info/301/core-info.json",
                "packageMapDigest": core_receipt["packageMapDigest"],
                "operation": operation, "verificationStatus": "verified",
            },
            "workflow": {
                "repository": "crypta-network/cryptad", "runId": 1, "runAttempt": 1,
                "environment": "stable-1.0-maintenance-publication", "actor": "release-manager",
                "attestationDigest": _digest("f"),
            },
            "publicObservations": {
                "tag": "verified", "githubRelease": "verified", "assets": "verified",
                "artifactBase": "verified", "stableCatalog": "verified", "coreUpdate": "verified",
            },
            "publicationState": "publication-complete",
            "finalVerificationStatus": "pass",
            "failureCategory": None,
            "redaction": _redaction(),
        }
        path = root / "receipt.json"
        write_json(path, receipt)
        loaded = LoadedJson("stableMaintenancePublicationReceipt", path, receipt, file_digest(path))
        args = (
            context, loaded, candidate, plan_path, plan, core_receipt,
            core_receipt_digest, successor_digest, history_digest,
        )
        return args, receipt

    def test_publication_receipt_created_and_existing_are_idempotent(self) -> None:
        for operation in ("created", "verified-existing"):
            with self.subTest(operation=operation), tempfile.TemporaryDirectory() as directory:
                args, _ = self._publication_fixture(Path(directory), operation)
                self.assertEqual(_receipt_errors(*args), [])

    def test_publication_receipt_conflicts_fail_closed(self) -> None:
        mutations = (
            lambda value: value["tag"].__setitem__("targetCommit", "f" * 40),
            lambda value: value["assets"][0].__setitem__("digest", _digest("0")),
            lambda value: value["publicObservations"].__setitem__("coreUpdate", "conflict"),
        )
        for mutate in mutations:
            with tempfile.TemporaryDirectory() as directory:
                args, receipt = self._publication_fixture(Path(directory), "verified-existing")
                mutate(receipt)
                loaded = args[1]
                assert isinstance(loaded, LoadedJson)
                write_json(loaded.path, receipt)
                self.assertTrue(_receipt_errors(*args))

    def test_publication_receipt_github_release_identity_mismatch_fails_closed(self) -> None:
        mutations = (
            ("releaseId", "stable-1-0-maintenance-302"),
            ("tag", "v302"),
            ("pageUri", "https://github.com/crypta-network/cryptad/releases/tag/v302"),
        )
        for field, replacement in mutations:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                args, receipt = self._publication_fixture(
                    Path(directory), "verified-existing"
                )
                receipt["githubRelease"][field] = replacement
                loaded = args[1]
                assert isinstance(loaded, LoadedJson)
                write_json(loaded.path, receipt)
                self.assertTrue(_receipt_errors(*args))

    def test_publication_receipt_catalog_target_mismatch_fails_closed(self) -> None:
        mutations = (
            ("catalogId", "another-catalog"),
            ("revision", 9),
            ("edition", 9),
            ("digest", _digest("0")),
            ("publicUri", "https://catalog.crypta.network/stable/other.json"),
            ("mirrorSetDigest", _digest("0")),
            ("rollbackStateDigest", _digest("0")),
            ("signatureDigest", _digest("0")),
            ("signaturePublicUri", "https://catalog.crypta.network/stable/other.sig"),
        )
        for field, replacement in mutations:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                args, receipt = self._publication_fixture(
                    Path(directory), "verified-existing"
                )
                receipt["stableCatalog"][field] = replacement
                loaded = args[1]
                assert isinstance(loaded, LoadedJson)
                write_json(loaded.path, receipt)
                self.assertTrue(_receipt_errors(*args))

    def test_publication_receipt_core_update_target_mismatch_fails_closed(self) -> None:
        mutations = (
            ("edition", 302),
            ("descriptorDigest", _digest("0")),
            ("publicUri", "https://updates.crypta.network/info/302/core-info.json"),
            ("packageMapDigest", _digest("0")),
        )
        for field, replacement in mutations:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                args, receipt = self._publication_fixture(
                    Path(directory), "verified-existing"
                )
                receipt["coreUpdate"][field] = replacement
                loaded = args[1]
                assert isinstance(loaded, LoadedJson)
                write_json(loaded.path, receipt)
                self.assertTrue(_receipt_errors(*args))

    def test_publication_plan_catalog_identity_must_match_frozen_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            args, receipt = self._publication_fixture(Path(directory), "created")
            plan = args[4]
            assert isinstance(plan, dict)
            plan["stableCatalogTarget"]["catalogId"] = "substituted-catalog"
            receipt["stableCatalog"]["catalogId"] = "substituted-catalog"
            plan_path = args[3]
            assert isinstance(plan_path, Path)
            write_json(plan_path, plan)
            receipt["publicationPlanDigest"] = file_digest(plan_path)
            loaded = args[1]
            assert isinstance(loaded, LoadedJson)
            write_json(loaded.path, receipt)
            self.assertTrue(_receipt_errors(*args))

    def test_receipt_identity_binds_public_catalog_and_observations(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            _, receipt = self._publication_fixture(Path(directory), "created")
            changed_catalog = copy.deepcopy(receipt)
            changed_catalog["stableCatalog"]["digest"] = _digest("0")
            changed_observation = copy.deepcopy(receipt)
            changed_observation["publicObservations"]["coreUpdate"] = "conflict"
            self.assertNotEqual(receipt_identity(receipt), receipt_identity(changed_catalog))
            self.assertNotEqual(receipt_identity(receipt), receipt_identity(changed_observation))

    def test_successor_uses_non_circular_identity_and_valid_schema(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ga, predecessor = _ga_and_predecessor()
            candidate = _candidate(root)
            receipt = self._publication_fixture(root, "created")[1]
            evidence = _evidence()
            successor = _successor(
                _context(root), ga, predecessor, candidate, _digest("1"), evidence,
                _digest("2"), receipt, _digest("3"), _digest("4"), None, None,
            )
            identity = successor_baseline_identity(successor)
            self.assertEqual(successor["lineage"]["history"][-1]["baselineIdentityDigest"], identity)
            self.assertEqual(successor["limitations"]["currentIds"], ["stable-known-001"])
            self.assertEqual(
                successor["limitations"]["currentDigest"],
                _known_limitations_digest({"stable-known-001"}),
            )
            successor_with_external_digest = copy.deepcopy(successor)
            successor_with_external_digest["externalPhysicalDigest"] = _digest("f")
            self.assertEqual(identity, successor_baseline_identity(successor_with_external_digest))
            self.assertEqual(validate_schema(successor, core.SUCCESSOR_SCHEMA), [])

    def test_superseding_hotfix_carries_open_predecessor_follow_up(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ga, predecessor = _ga_and_predecessor()
            inherited = {
                "status": "open",
                "generatedAt": _timestamp(NOW - timedelta(days=2)),
                "obligationDigest": _digest("d"),
                "deadline": _timestamp(NOW + timedelta(days=5)),
                "closureEvidenceDigest": None,
                "blocksRoutineMaintenance": True,
                "obligatedReleaseId": "stable-1-0-hotfix-300",
                "obligatedBuildVersion": "300",
                "obligatedProductDigest": _digest("2"),
                "obligatedCandidateIdentityDigest": _digest("3"),
                "obligatedCandidateFreezeDigest": _digest("4"),
                "obligatedCandidateFrozenAt": _timestamp(FROZEN - timedelta(days=1)),
                "obligatedPredecessorBuild": "299",
                "obligatedPredecessorProductDigest": _digest("5"),
                "authorizationDigest": _digest("5"),
            }
            predecessor = Predecessor(
                **{
                    **predecessor.__dict__,
                    "outstanding_follow_up": inherited,
                }
            )
            candidate = _candidate(root, "security-hotfix")
            receipt = self._publication_fixture(root, "created")[1]

            successor = _successor(
                _context(root, release_class="security-hotfix"),
                ga,
                predecessor,
                candidate,
                _digest("1"),
                _evidence("security-hotfix"),
                _digest("2"),
                receipt,
                _digest("3"),
                _digest("4"),
                None,
                None,
            )

            self.assertEqual(successor["hotfixFollowUp"], inherited)
            self.assertEqual(validate_schema(successor, core.SUCCESSOR_SCHEMA), [])
            self.assertTrue(_concurrent_follow_up_errors(predecessor, {"status": "open"}))

    def test_overdue_predecessor_follow_up_remains_active(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ga, predecessor = _ga_and_predecessor()
            inherited = {
                "status": "overdue",
                "generatedAt": _timestamp(NOW - timedelta(days=10)),
                "obligationDigest": _digest("d"),
                "deadline": _timestamp(NOW - timedelta(days=3)),
                "closureEvidenceDigest": None,
                "blocksRoutineMaintenance": True,
                "obligatedReleaseId": "stable-1-0-hotfix-300",
                "obligatedBuildVersion": "300",
                "obligatedProductDigest": _digest("2"),
                "obligatedCandidateIdentityDigest": _digest("3"),
                "obligatedCandidateFreezeDigest": _digest("4"),
                "obligatedCandidateFrozenAt": _timestamp(FROZEN - timedelta(days=1)),
                "obligatedPredecessorBuild": "299",
                "obligatedPredecessorProductDigest": _digest("5"),
                "authorizationDigest": _digest("5"),
            }
            predecessor = Predecessor(
                **{
                    **predecessor.__dict__,
                    "outstanding_follow_up": inherited,
                }
            )
            candidate = _candidate(root, "security-hotfix")
            receipt = self._publication_fixture(root, "created")[1]

            successor = _successor(
                _context(root, release_class="security-hotfix"),
                ga,
                predecessor,
                candidate,
                _digest("1"),
                _evidence("security-hotfix"),
                _digest("2"),
                receipt,
                _digest("3"),
                _digest("4"),
                None,
                None,
            )

            self.assertEqual(successor["hotfixFollowUp"], inherited)
            self.assertEqual(validate_schema(successor, core.SUCCESSOR_SCHEMA), [])
            self.assertTrue(_concurrent_follow_up_errors(predecessor, {"status": "open"}))
            overdue_without_flag = {
                **inherited,
                "deadline": _timestamp(NOW + timedelta(days=3)),
                "blocksRoutineMaintenance": False,
            }
            self.assertTrue(
                core._routine_follow_up_blocked(  # noqa: SLF001
                    overdue_without_flag,
                    "maintenance",
                    NOW,
                )
            )
            self.assertFalse(
                core._routine_follow_up_blocked(  # noqa: SLF001
                    overdue_without_flag,
                    "security-hotfix",
                    NOW,
                )
            )


class StableMaintenanceNoSideEffectsTest(unittest.TestCase):
    """Ordinary execution is diagnostic-only and fail closed."""

    def test_engine_contains_no_public_mutation_client(self) -> None:
        source = inspect.getsource(stable_1_0_maintenance)
        for forbidden in (
            "subprocess.run",
            "urllib.request",
            "requests.",
            "fcpput",
            "git tag",
            "gh release create",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)

    def test_fail_closed_run_writes_only_local_diagnostics(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            context = _context(root, mode="prepare-authorization", inputs={})
            (context.component_dir / "artifacts").mkdir(parents=True)
            with mock.patch.object(
                stable_1_0_maintenance,
                "authenticate_ga_root",
                side_effect=ValueError("malformed protected input"),
            ), mock.patch.object(stable_1_0_maintenance, "_verify_receipts") as verify:
                code, summary_path, report_path = stable_1_0_maintenance.run(context)
            self.assertEqual(code, 1)
            self.assertTrue(summary_path.is_file())
            self.assertTrue(report_path.is_file())
            verify.assert_not_called()
            summary = read_json(summary_path)
            self.assertFalse(summary["promotionReady"])
            names = {path.name for path in summary_path.parent.iterdir()}
            self.assertEqual(
                names,
                {
                    core.SUMMARY_FILE,
                    core.REPORT_FILE,
                    core.REDACTION_REPORT_FILE,
                },
            )


if __name__ == "__main__":
    unittest.main()
