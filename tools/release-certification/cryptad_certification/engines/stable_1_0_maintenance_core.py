"""Authentication, identity, archive, and updater helpers for Stable 1.0 maintenance."""

from __future__ import annotations

import dataclasses
import datetime as dt
import io
import json
import re
import stat
import struct
import tarfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

from cryptad_certification.io import read_json
from cryptad_certification.models import RunContext
from cryptad_certification.redaction import scan_value
from cryptad_certification.schema_validation import validate_schema

from .stable_1_0_ga_core import (
    _has_unambiguous_publication_path,
    is_public_https_uri,
    public_audit_redaction_findings,
)
from .stable_1_0_rc_core import (
    BUILD_VERSION_RE,
    COMMIT_RE,
    DIGEST_RE,
    ValidationState,
    _configured_path,
    file_digest,
    parse_timestamp,
    placeholder_findings,
    semantic_digest,
)

SCHEMA_VERSION = 1
TOOL_NAME = "stable-1.0-maintenance"
TOOL_VERSION = 1
STABLE_MILESTONE = "1.0"
COMPONENT = "stable-maintenance"
RELEASE_CLASSES = ("maintenance", "security-hotfix")
COMMAND_MODES = (
    "validate-only",
    "prepare-authorization",
    "close-hotfix-follow-up",
)
DECISIONS = ("go", "no-go", "go-with-waivers")
MAX_NESTED_ARCHIVE_BYTES = 256 * 1024 * 1024

SUMMARY_FILE = "stable-1.0-maintenance-promotion-summary.json"
REPORT_FILE = "stable-1.0-maintenance-go-no-go.md"
LINEAGE_FILE = "stable-1.0-maintenance-lineage.json"
CANDIDATE_FILE = "stable-1.0-maintenance-candidate.json"
CANDIDATE_FREEZE_FILE = "stable-1.0-maintenance-candidate-freeze.json"
COMPARISON_FILE = "stable-1.0-maintenance-comparison.json"
VALIDATION_FILE = "stable-1.0-maintenance-validation.json"
AUTHORIZATION_FILE = "stable-1.0-maintenance-authorization-summary.json"
KNOWN_LIMITATIONS_FILE = "stable-1.0-maintenance-known-limitations.json"
RELEASE_NOTES_FILE = "stable-1.0-maintenance-release-notes.md"
PUBLICATION_PLAN_FILE = "stable-1.0-maintenance-publication-plan.json"
PUBLICATION_RECEIPT_FILE = "stable-1.0-maintenance-publication-receipt.json"
CHECKSUMS_FILE = "stable-1.0-maintenance-checksums.txt"
AUDIT_CHECKSUMS_FILE = "stable-1.0-maintenance-audit-checksums.txt"
PROVENANCE_FILE = "stable-1.0-maintenance-provenance.json"
SUCCESSOR_BASELINE_FILE = "stable-1.0-maintenance-successor-baseline.json"
HISTORY_FILE = "stable-1.0-maintenance-history-entry.json"
LATEST_POINTER_FILE = "stable-1.0-maintenance-latest-published.json"
FOLLOW_UP_FILE = "stable-1.0-hotfix-follow-up-obligation.json"
FOLLOW_UP_CLOSURE_FILE = "stable-1.0-hotfix-follow-up-closure.json"
CORE_INFO_FILE = "core-info.json"
CORE_PLAN_FILE = "core-update-publication-plan.json"
CORE_RECEIPT_FILE = "core-update-publication-receipt.json"
REDACTION_REPORT_FILE = "redaction-report.json"

GA_BASELINE_SCHEMA = "stable-1.0-maintenance-baseline-v1.schema.json"
GA_PROMOTION_SCHEMA = "stable-1.0-ga-promotion-v1.schema.json"
GA_VALIDATION_SCHEMA = "stable-1.0-ga-validation-v1.schema.json"
GA_AUTHORIZATION_SCHEMA = "stable-1.0-ga-authorization-v1.schema.json"
GA_PUBLICATION_PLAN_SCHEMA = "stable-1.0-ga-publication-plan-v1.schema.json"
GA_PUBLICATION_RECEIPT_SCHEMA = "stable-1.0-ga-publication-receipt-v1.schema.json"
CANDIDATE_INPUT_SCHEMA = "stable-1.0-maintenance-candidate-input-v1.schema.json"
CANDIDATE_FREEZE_SCHEMA = "stable-1.0-maintenance-candidate-freeze.schema.json"
EVIDENCE_SCHEMA = "stable-1.0-maintenance-evidence-v1.schema.json"
LINEAGE_SCHEMA = "stable-1.0-maintenance-lineage-v1.schema.json"
COMPARISON_SCHEMA = "stable-1.0-maintenance-comparison-v1.schema.json"
VALIDATION_SCHEMA = "stable-1.0-maintenance-validation-v1.schema.json"
AUTHORIZATION_SCHEMA = "stable-1.0-maintenance-authorization-v1.schema.json"
PUBLICATION_PLAN_SCHEMA = "stable-1.0-maintenance-publication-plan-v1.schema.json"
PUBLICATION_RECEIPT_SCHEMA = "stable-1.0-maintenance-publication-receipt-v1.schema.json"
PUBLICATION_FAILURE_AUDIT_SCHEMA = (
    "stable-1.0-maintenance-publication-failure-audit-v1.schema.json"
)
SUCCESSOR_SCHEMA = "stable-1.0-maintenance-successor-baseline-v2.schema.json"
FOLLOW_UP_SCHEMA = "stable-1.0-hotfix-follow-up-obligation-v1.schema.json"
FOLLOW_UP_CLOSURE_SCHEMA = "stable-1.0-hotfix-follow-up-closure-v1.schema.json"
CORE_INFO_SCHEMA = "cryptad-core-info-v1.schema.json"
CORE_PLAN_SCHEMA = "cryptad-core-update-publication-plan-v1.schema.json"
CORE_RECEIPT_SCHEMA = "cryptad-core-update-publication-receipt-v1.schema.json"

AUTHORIZATION_SCOPE = (
    "tag:create-or-verify",
    "github-release:create-or-verify",
    "artifact-base:publish-or-verify",
    "stable-catalog:publish-or-verify",
    "core-update:insert-or-verify",
    "successor-baseline:activate",
    "release-history:append",
)
GA_PUBLIC_ASSET_NAMES = {
    "stable-1.0-ga-release-notes.md",
    "stable-1.0-ga-known-limitations.json",
    "stable-1.0-ga-provenance.json",
    "stable-1.0-maintenance-baseline.json",
    "stable-1.0-ga-checksums.txt",
}
REQUIRED_PRODUCTION_EVIDENCE = (
    "stable-maintenance.installation-packaging",
    "stable-maintenance.upgrade-rollback-migration-backup",
    "stable-maintenance.live-network-interoperability",
    "stable-maintenance.performance",
    "stable-maintenance.sandbox",
    "stable-maintenance.security",
    "stable-maintenance.support-redaction",
)
ALLOWED_OPERATIONAL_WARNING_IDS = frozenset(
    {
        "stable-maintenance.catalog-mirror-latency-warning",
        "stable-maintenance.performance-comparable-runner-warning",
    }
)
OPERATIONAL_WARNING_EVIDENCE_IDS = {
    "stable-maintenance.catalog-mirror-latency-warning": (
        "stable-maintenance.catalog-app-compatibility"
    ),
    "stable-maintenance.performance-comparable-runner-warning": (
        "stable-maintenance.performance"
    ),
}


@dataclasses.dataclass(frozen=True)
class LoadedJson:
    """One exact, strict, public-safe JSON input."""

    key: str
    path: Path
    value: dict[str, Any]
    digest: str


@dataclasses.dataclass(frozen=True)
class GaRoot:
    """Authenticated immutable Stable 1.0 GA chain root."""

    baseline: dict[str, Any]
    baseline_digest: str
    receipt: dict[str, Any]
    receipt_digest: str
    release_id: str
    build_version: str
    source_commit: str
    product_digest: str
    tag: str
    root_identity_digest: str


@dataclasses.dataclass(frozen=True)
class Predecessor:
    """Authenticated immediate predecessor and chain state."""

    baseline: dict[str, Any]
    baseline_digest: str
    receipt: dict[str, Any]
    receipt_digest: str
    release_id: str
    build_version: str
    source_commit: str
    product_digest: str
    tag: str
    chain_depth: int
    previous_lineage_digest: str
    lineage_history: list[dict[str, Any]]
    outstanding_follow_up: dict[str, Any] | None
    latest_pointer_digest: str | None = None
    follow_up_closure_digest: str | None = None


@dataclasses.dataclass(frozen=True)
class Candidate:
    """Authenticated one-time maintenance candidate and its exact assets."""

    source: dict[str, Any]
    input_value: dict[str, Any]
    input_digest: str
    freeze_digest: str
    frozen_at: str
    product_path: Path
    product_digest: str
    assets: list[dict[str, Any]]
    asset_paths: dict[str, Path]
    checksums_digest: str
    provenance_digest: str
    identity: dict[str, Any]
    identity_digest: str


def add_blockers(
    state: ValidationState,
    issue_id: str,
    errors: list[str],
    remediation: str,
) -> None:
    """Append deduplicated, non-waivable blockers for one evidence identity."""

    existing = {
        (row.get("id"), row.get("summary"))
        for row in state.blockers
        if isinstance(row, dict)
    }
    for error in errors:
        summary = error.rstrip(".") + "."
        if (issue_id, summary) in existing:
            continue
        state.block(issue_id, issue_id, summary, remediation)
        existing.add((issue_id, summary))


def _regular_file(path: Path) -> bool:
    try:
        mode = path.stat(follow_symlinks=False).st_mode
    except OSError:
        return False
    return stat.S_ISREG(mode) and not path.is_symlink()


def configured_path(
    context: RunContext,
    key: str,
    *,
    required: bool = True,
    directory: bool = False,
) -> Path | None:
    """Resolve one workspace-confined input and reject every symlinked component."""

    raw = context.manifest.inputs.get(key)
    if isinstance(raw, str) and Path(raw).is_absolute():
        raise ValueError(f"Stable maintenance input path must be workspace-relative: {key}")
    path = _configured_path(context, key)
    if path is None:
        if required:
            raise ValueError(f"required Stable maintenance input is missing: {key}")
        return None
    if directory:
        if path.is_symlink() or not path.is_dir():
            raise ValueError(f"Stable maintenance input directory is missing or unsafe: {key}")
    elif not _regular_file(path):
        raise ValueError(f"Stable maintenance input is missing or unsafe: {key}")
    return path


def load_json_input(
    context: RunContext,
    key: str,
    *,
    required: bool = True,
    public_authorization: bool = False,
) -> LoadedJson | None:
    """Load a duplicate-safe, placeholder-free, public-safe JSON input."""

    path = configured_path(context, key, required=required)
    if path is None:
        return None
    value = read_json(path)
    if not isinstance(value, dict):
        raise ValueError(f"Stable maintenance input must be a JSON object: {key}")
    findings = _maintenance_public_redaction_findings(value)
    if findings or placeholder_findings(value):
        raise ValueError(
            f"Stable maintenance input is redaction-unsafe or contains placeholders: {key}"
        )
    return LoadedJson(key, path, value, file_digest(path))


def _maintenance_public_redaction_view(value: Any) -> Any:
    """Rename only closed public approval labels while retaining recursive value scans."""

    if isinstance(value, dict):
        safe_labels = {
            "authorization": "publicApprovalPolicy",
            "authorizationDigest": "publicApprovalDigest",
            "authorizationId": "publicApprovalId",
            "authorizationRequestDigest": "publicApprovalRequestDigest",
            "authorizedAt": "publicApprovalTime",
            "allowedPublicationScopes": "allowedPublicOperationScopes",
            "approverIdentity": "publicApproverLabel",
            "hotfixPolicyAuthorizationDigest": "hotfixPublicApprovalDigest",
            "stableLifecycleAuthorization": "stableLifecyclePublicApproval",
        }
        return {
            safe_labels.get(str(key), str(key)): _maintenance_public_redaction_view(child)
            for key, child in value.items()
        }
    if isinstance(value, list):
        return [_maintenance_public_redaction_view(child) for child in value]
    return value


def _maintenance_public_redaction_findings(value: Any) -> list[dict[str, str]]:
    return public_audit_redaction_findings(_maintenance_public_redaction_view(value))


def canonical_policy(context: RunContext, supplied: LoadedJson) -> list[str]:
    """Require the exact checked-in authoritative maintenance policy bytes."""

    canonical = (
        context.workspace_root
        / "tools"
        / "release-certification"
        / "stable-1.0-maintenance-policy.json"
    )
    errors: list[str] = []
    if read_json(canonical) != supplied.value or file_digest(canonical) != supplied.digest:
        errors.append(
            "Stable maintenance policy is not the exact checked-in authoritative policy"
        )
    if (
        supplied.value.get("schemaVersion") != 1
        or supplied.value.get("kind") != "stable-1.0-maintenance-policy"
        or supplied.value.get("stableMilestone") != STABLE_MILESTONE
        or supplied.value.get("component") != COMPONENT
        or supplied.value.get("profile") != "stable-review"
        or tuple(supplied.value.get("releaseClasses", [])) != RELEASE_CLASSES
    ):
        errors.append("Stable maintenance policy identity is invalid")
    return errors


def _checksum_rows(path: Path) -> tuple[dict[str, str], list[str]]:
    """Parse one deterministic single-basename SHA-256 checksum file."""

    values: dict[str, str] = {}
    errors: list[str] = []
    try:
        rows = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return {}, ["checksum file is not readable UTF-8"]
    for number, row in enumerate(rows, start=1):
        digest, separator, name = row.partition("  ")
        relative = Path(name)
        if (
            not separator
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            or not name
            or name in values
            or relative.is_absolute()
            or len(relative.parts) != 1
            or ".." in relative.parts
        ):
            errors.append(f"checksum line {number} is malformed")
            continue
        values[name] = "sha256:" + digest
    canonical = [
        f"{digest.removeprefix('sha256:')}  {name}"
        for name, digest in sorted(values.items())
    ]
    if rows != canonical:
        errors.append("checksum rows are not in canonical deterministic order")
    return values, errors


def authenticate_ga_root(context: RunContext, state: ValidationState) -> GaRoot:
    """Authenticate PR-284 GA publication and the immutable v1 baseline as one graph."""

    promotion = load_json_input(context, "stableGaPromotionSummary")
    validation = load_json_input(context, "stableGaValidation")
    authorization = load_json_input(
        context, "stableGaAuthorizationSummary", public_authorization=True
    )
    plan = load_json_input(context, "stableGaPublicationPlan")
    receipt = load_json_input(context, "stableGaPublicationReceipt")
    provenance = load_json_input(context, "stableGaProvenance")
    baseline = load_json_input(context, "stableGaMaintenanceBaseline")
    checksums_path = configured_path(context, "stableGaChecksums")
    assert all(
        item is not None
        for item in (
            promotion,
            validation,
            authorization,
            plan,
            receipt,
            provenance,
            baseline,
            checksums_path,
        )
    )
    assert promotion and validation and authorization and plan and receipt and provenance and baseline
    assert checksums_path is not None
    errors: list[str] = []
    for value, schema, label in (
        (promotion.value, GA_PROMOTION_SCHEMA, "promotion summary"),
        (validation.value, GA_VALIDATION_SCHEMA, "validation"),
        (authorization.value, GA_AUTHORIZATION_SCHEMA, "authorization"),
        (plan.value, GA_PUBLICATION_PLAN_SCHEMA, "publication plan"),
        (receipt.value, GA_PUBLICATION_RECEIPT_SCHEMA, "publication receipt"),
        (baseline.value, GA_BASELINE_SCHEMA, "maintenance baseline"),
    ):
        errors.extend(f"Stable GA {label}: {item}" for item in validate_schema(value, schema))
    base_release = baseline.value.get("release")
    base_release = base_release if isinstance(base_release, dict) else {}
    release_id = str(base_release.get("releaseId", ""))
    build_version = str(base_release.get("buildVersion", ""))
    source_commit = str(base_release.get("sourceCommit", ""))
    product_digest = str(base_release.get("rcProductDigest", ""))
    tag = str(base_release.get("tag", ""))
    if (
        baseline.value.get("status") != "prepared"
        or baseline.value.get("stableMilestone") != STABLE_MILESTONE
        or BUILD_VERSION_RE.fullmatch(build_version) is None
        or COMMIT_RE.fullmatch(source_commit) is None
        or DIGEST_RE.fullmatch(product_digest) is None
        or tag != f"v{build_version}"
    ):
        errors.append("Stable GA maintenance baseline release identity is invalid")
    promotion_value = promotion.value
    promotion_selected = promotion_value.get("selectedRc")
    promotion_selected = promotion_selected if isinstance(promotion_selected, dict) else {}
    promotion_payload = promotion_value.get("payloadIdentity")
    promotion_payload = promotion_payload if isinstance(promotion_payload, dict) else {}
    promotion_catalog = promotion_value.get("stableCatalog")
    promotion_catalog = promotion_catalog if isinstance(promotion_catalog, dict) else {}
    if (
        promotion_value.get("status") != "pass"
        or promotion_value.get("promotionReady") is not True
        or promotion_value.get("nonRelease") is not False
        or promotion_value.get("publicationState") != "publication-complete"
        or promotion_value.get("releaseId") != release_id
        or promotion_value.get("buildVersion") != build_version
        or promotion_value.get("sourceCommit") != source_commit
        or promotion_value.get("expectedTag") != tag
        or promotion_value.get("expectedReleaseBranch") != f"release/{build_version}"
        or promotion_value.get("gaValidationDigest") != validation.digest
        or promotion_selected.get("productDistributionDigest") != product_digest
        or promotion_payload.get("rcProductDigest") != product_digest
        or promotion_payload.get("gaProductDigest") != product_digest
        or promotion_payload.get("bitIdentical") is not True
        or promotion_payload.get("rebuildPerformed") is not False
    ):
        errors.append("Stable GA promotion is not a completed matching GA result")
    validation_value = validation.value
    validation_selected = validation_value.get("selectedRc")
    validation_selected = validation_selected if isinstance(validation_selected, dict) else {}
    validation_payload = validation_value.get("payloadIdentity")
    validation_payload = validation_payload if isinstance(validation_payload, dict) else {}
    validation_authorization = validation_value.get("authorization")
    validation_authorization = (
        validation_authorization if isinstance(validation_authorization, dict) else {}
    )
    if (
        validation_value.get("releaseId") != release_id
        or validation_value.get("buildVersion") != build_version
        or validation_value.get("profile") != "stable-review"
        or validation_value.get("component") != "stable-ga"
        or validation_value.get("sourceCommit") != source_commit
        or validation_value.get("status") != "pass"
        or validation_value.get("promotionReady") is not True
        or validation_value.get("nonRelease") is not False
        or validation_value.get("decision") not in {"go", "go-with-waivers"}
        or validation_selected.get("productDistributionDigest") != product_digest
        or validation_payload.get("rcProductDigest") != product_digest
        or validation_payload.get("gaProductDigest") != product_digest
        or validation_payload.get("bitIdentical") is not True
        or validation_payload.get("rebuildPerformed") is not False
        or validation_authorization.get("status") != "authorized"
        or validation_authorization.get("authorizationId")
        != authorization.value.get("authorizationId")
        or promotion_value.get("gaAuthorizationDigest")
        != validation_authorization.get("authorizationDigest")
        or validation_authorization.get("publicationTargetsDigest")
        != authorization.value.get("publicationTargetsDigest")
        or validation_authorization.get("allowedPublicationScope")
        != authorization.value.get("allowedPublicationScope")
    ):
        errors.append("Stable GA validation does not bind the exact authorized GA result")
    authorization_value = authorization.value
    if (
        authorization_value.get("releaseId") != release_id
        or authorization_value.get("buildVersion") != build_version
        or authorization_value.get("sourceCommit") != source_commit
        or authorization_value.get("productDistributionDigest") != product_digest
        or authorization_value.get("freezeDigest")
        != promotion_selected.get("freezeDigest")
        or authorization_value.get("archiveDigest")
        != promotion_selected.get("archiveDigest")
        or authorization_value.get("catalogDigest")
        != promotion_catalog.get("catalogDigest")
        or authorization_value.get("catalogRevision")
        != promotion_catalog.get("revision")
        or authorization_value.get("publicationTargetsDigest")
        != promotion_value.get("publicationTargetsDigest")
        or authorization_value.get("status") != "authorized"
        or authorization_value.get("authorizationRole") != "stable-release-manager"
        or authorization_value.get("allowedPublicationScope")
        != [
            "git-tag",
            "github-release",
            "release-assets",
            "stable-catalog-confirmation",
            "post-publication-verification",
        ]
    ):
        errors.append("Stable GA authorization does not bind the exact promotion identity")
    plan_value = plan.value
    plan_catalog = plan_value.get("catalog")
    plan_catalog = plan_catalog if isinstance(plan_catalog, dict) else {}
    if (
        plan_value.get("releaseId") != release_id
        or plan_value.get("buildVersion") != build_version
        or plan_value.get("sourceCommit") != source_commit
        or plan_value.get("expectedTag") != tag
        or plan_value.get("expectedReleaseBranch") != f"release/{build_version}"
        or plan_value.get("publicationState") != "publication-authorized"
        or plan_value.get("sideEffectsPerformed") is not False
        or plan_value.get("publicationTargetsDigest")
        != promotion_value.get("publicationTargetsDigest")
        or plan_value.get("promotionIdentityDigest")
        != base_release.get("gaPromotionDigest")
        or plan_value.get("releaseNotesDigest")
        != promotion_value.get("releaseNotesDigest")
        or plan_catalog.get("catalogDigest") != promotion_catalog.get("catalogDigest")
        or plan_catalog.get("revision") != promotion_catalog.get("revision")
        or plan_catalog.get("signatureDigest")
        != promotion_catalog.get("signatureDigest")
        or plan_catalog.get("signingKeyId") != promotion_catalog.get("signingKeyId")
    ):
        errors.append("Stable GA publication plan is not the exact authorized promotion plan")
    receipt_value = receipt.value
    tag_value = receipt_value.get("tag")
    tag_value = tag_value if isinstance(tag_value, dict) else {}
    observations = receipt_value.get("publicStateObservation")
    observations = observations if isinstance(observations, dict) else {}
    assets_observation = observations.get("releaseAssets")
    assets_observation = assets_observation if isinstance(assets_observation, dict) else {}
    if (
        receipt_value.get("publicationState") != "publication-complete"
        or receipt_value.get("operation") not in {"created", "verified-existing"}
        or receipt_value.get("finalVerificationStatus") != "pass"
        or receipt_value.get("releaseId") != release_id
        or receipt_value.get("buildVersion") != build_version
        or receipt_value.get("sourceCommit") != source_commit
        or receipt_value.get("productDistributionDigest") != product_digest
        or receipt_value.get("freezeDigest") != promotion_selected.get("freezeDigest")
        or receipt_value.get("archiveDigest") != promotion_selected.get("archiveDigest")
        or receipt_value.get("gaPromotionSummaryDigest")
        != base_release.get("gaPromotionDigest")
        or receipt_value.get("releaseNotesDigest") != plan_value.get("releaseNotesDigest")
        or receipt_value.get("artifactBaseUri") != plan_value.get("artifactBaseUri")
        or tag_value.get("name") != tag
        or tag_value.get("targetCommit") != source_commit
        or tag_value.get("annotated") is not True
        or tag_value.get("verificationStatus") != "pass"
        or observations.get("tag", {}).get("status") != "verified"
        or observations.get("githubRelease", {}).get("status") != "verified"
        or assets_observation.get("status") != "verified"
        or assets_observation.get("missingPlannedAssets") != []
        or assets_observation.get("unexpectedCount") != 0
    ):
        errors.append("Stable GA publication receipt does not prove complete exact public state")
    receipt_catalog = receipt_value.get("catalog")
    receipt_catalog = receipt_catalog if isinstance(receipt_catalog, dict) else {}
    if (
        receipt_catalog.get("catalogId") != plan_catalog.get("catalogId")
        or receipt_catalog.get("channel") != "stable"
        or receipt_catalog.get("revision") != plan_catalog.get("revision")
        or receipt_catalog.get("catalogDigest") != plan_catalog.get("catalogDigest")
        or receipt_catalog.get("signatureDigest") != plan_catalog.get("signatureDigest")
        or receipt_catalog.get("signingKeyId") != plan_catalog.get("signingKeyId")
        or receipt_catalog.get("verificationStatus") != "pass"
    ):
        errors.append("Stable GA publication receipt catalog is not the planned stable catalog")
    baseline_digest = baseline.digest
    if promotion_value.get("maintenanceBaselineDigest") != baseline_digest:
        errors.append("Stable GA promotion does not bind the exact maintenance baseline bytes")
    plan_assets = plan.value.get("assets")
    receipt_assets = receipt_value.get("assets")
    promotion_assets = promotion_value.get("plannedPublicArtifacts")
    if not all(isinstance(item, list) for item in (plan_assets, receipt_assets, promotion_assets)):
        errors.append("Stable GA public asset records are malformed")
        plan_assets = []
        receipt_assets = []
        promotion_assets = []
    if any(
        not isinstance(row, dict) or row.get("verificationStatus") != "pass"
        for row in receipt_assets
    ):
        errors.append("Stable GA publication receipt contains an unverified release asset")

    def asset_map(rows: list[Any]) -> dict[str, tuple[Any, Any]]:
        mapped: dict[str, tuple[Any, Any]] = {}
        for row in rows:
            if not isinstance(row, dict) or not isinstance(row.get("name"), str):
                continue
            name = row["name"]
            if name in mapped:
                errors.append(f"Stable GA public asset set contains duplicate {name}")
            mapped[name] = (row.get("sizeBytes"), row.get("digest"))
        return mapped
    planned = asset_map(plan_assets)
    observed = asset_map(receipt_assets)
    promoted = asset_map(promotion_assets)
    if planned != observed or planned != promoted:
        errors.append("Stable GA plan, promotion, and receipt asset sets differ")
    if planned.get("stable-1.0-maintenance-baseline.json", (None, None))[1] != baseline_digest:
        errors.append("Stable GA public asset set omits the exact maintenance baseline")
    checksums, checksum_errors = _checksum_rows(checksums_path)
    errors.extend(f"Stable GA {item}" for item in checksum_errors)
    if checksums.get("stable-1.0-maintenance-baseline.json") != baseline_digest:
        errors.append("Stable GA checksums do not bind the exact maintenance baseline")
    if set(checksums).union({"stable-1.0-ga-checksums.txt"}) != set(planned):
        errors.append("Stable GA checksum and public asset allowlists differ")
    provenance_release = provenance.value.get("releaseId")
    provenance_source = provenance.value.get("source")
    provenance_source = provenance_source if isinstance(provenance_source, dict) else {}
    payload = provenance.value.get("payloadIdentity")
    payload = payload if isinstance(payload, dict) else {}
    provenance_ga = provenance.value.get("ga")
    provenance_ga = provenance_ga if isinstance(provenance_ga, dict) else {}
    provenance_catalog = provenance.value.get("catalogIdentity")
    provenance_catalog = provenance_catalog if isinstance(provenance_catalog, dict) else {}
    if (
        provenance.value.get("kind") != "stable-1.0-ga-provenance"
        or provenance_release != release_id
        or provenance.value.get("buildVersion") != build_version
        or provenance_source.get("commit") != source_commit
        or payload.get("gaProductDigest") != product_digest
        or payload.get("rcProductDigest") != product_digest
        or payload.get("bitIdentical") is not True
        or payload.get("rebuildPerformed") is not False
        or provenance_ga.get("validationFileDigest") != validation.digest
        or provenance_ga.get("authorizationDigest")
        != promotion_value.get("gaAuthorizationDigest")
        or provenance_ga.get("validationAuthorizationIdentityDigest")
        != authorization_value.get("gaValidationDigest")
        or provenance_ga.get("promotionIdentityDigest")
        != base_release.get("gaPromotionDigest")
        or provenance_catalog.get("catalogId") != promotion_catalog.get("catalogId")
        or provenance_catalog.get("revision") != promotion_catalog.get("revision")
        or provenance_catalog.get("catalogDigest")
        != promotion_catalog.get("catalogDigest")
        or provenance_catalog.get("signatureDigest")
        != promotion_catalog.get("signatureDigest")
    ):
        errors.append("Stable GA provenance does not bind the baseline product identity")
    for value, label in (
        (promotion.value, "promotion"),
        (validation.value, "validation"),
        (authorization.value, "authorization"),
        (plan.value, "publication plan"),
        (receipt.value, "publication receipt"),
        (provenance.value, "provenance"),
        (baseline.value, "maintenance baseline"),
    ):
        redaction = value.get("redaction") if isinstance(value, dict) else None
        if placeholder_findings(value) or redaction != {
            "status": "pass",
            "findingCount": 0,
            "findings": [],
        }:
            errors.append(f"Stable GA {label} contains placeholders or redaction findings")
    add_blockers(
        state,
        "stable-maintenance.ga-baseline-authentication",
        errors,
        "Restore the exact verified PR-284 publication artifact graph.",
    )
    root_identity = {
        "schemaVersion": 1,
        "kind": "stable-1.0-ga-maintenance-root-identity",
        "releaseId": release_id,
        "buildVersion": build_version,
        "sourceCommit": source_commit,
        "tag": tag,
        "productDigest": product_digest,
        "baselineDigest": baseline_digest,
        "publicationReceiptDigest": receipt.digest,
        "gaPromotionIdentityDigest": base_release.get("gaPromotionDigest"),
    }
    return GaRoot(
        baseline.value,
        baseline_digest,
        receipt.value,
        receipt.digest,
        release_id,
        build_version,
        source_commit,
        product_digest,
        tag,
        semantic_digest(root_identity),
    )


def _receipt_identity(receipt: dict[str, Any]) -> str:
    """Return the non-circular semantic identity of one maintenance receipt."""

    identity_keys = [
        "schemaVersion",
        "kind",
        "releaseId",
        "buildVersion",
        "releaseClass",
        "sourceCommit",
        "githubReleasePageUri",
        "deploymentServicePublicUri",
        "latestPointerPublicUri",
        "publicationState",
        "candidateIdentityDigest",
        "productDigest",
        "checksumsDigest",
        "provenanceDigest",
        "authorizationDigest",
        "publicationPlanDigest",
        "releaseNotesDigest",
        "coreInfoDigest",
        "coreUpdateReceiptDigest",
        "tag",
        "githubRelease",
        "assets",
        "stableCatalog",
        "coreUpdate",
        "workflow",
        "publicObservations",
        "finalVerificationStatus",
        "failureCategory",
        "redaction",
    ]
    if "backportReleaseTrainDigest" in receipt:
        identity_keys.insert(
            identity_keys.index("publicationPlanDigest"),
            "backportReleaseTrainDigest",
        )
    fields = {
        key: receipt.get(key)
        for key in identity_keys
    }
    return semantic_digest(fields)


def successor_baseline_identity(baseline: dict[str, Any]) -> str:
    """Return a non-circular identity for one v2 successor baseline."""

    identity_keys = [
        "schemaVersion",
        "kind",
        "generatedAt",
        "stableMilestone",
        "status",
        "gaRoot",
        "previousBaselineDigest",
        "chainDepth",
        "previousLineageDigest",
        "publication",
        "release",
        "platformApi",
        "stableCatalog",
        "firstPartyApps",
        "contentFormatProfiles",
        "limitations",
        "security",
        "support",
        "legacyBoundaries",
        "evidenceWindowPolicy",
        "hotfixFollowUp",
        "releaseHistoryDigest",
        "redaction",
    ]
    if "releaseTrain" in baseline:
        identity_keys.insert(identity_keys.index("releaseHistoryDigest"), "releaseTrain")
    return semantic_digest(
        {key: baseline.get(key) for key in identity_keys}
    )


def authenticate_predecessor(
    context: RunContext,
    ga: GaRoot,
    state: ValidationState,
    *,
    allow_non_successor_build: bool = False,
) -> Predecessor:
    """Authenticate GA or the latest activated v2 successor as immediate predecessor."""

    baseline = load_json_input(context, "predecessorBaseline")
    receipt = load_json_input(context, "predecessorPublicationReceipt")
    assert baseline and receipt
    errors: list[str] = []
    if baseline.value.get("schemaVersion") == 1:
        pointer = load_json_input(
            context, "latestPublishedMaintenancePointer", required=False
        )
        if pointer is not None:
            errors.append(
                "GA predecessor forbids a latest-maintenance pointer that is not part of the authenticated GA root"
            )
        if baseline.digest != ga.baseline_digest or receipt.digest != ga.receipt_digest:
            errors.append("first maintenance predecessor is not the exact authenticated GA root")
        release_id = ga.release_id
        build_version = ga.build_version
        source_commit = ga.source_commit
        product_digest = ga.product_digest
        tag = ga.tag
        chain_depth = 0
        previous_lineage_digest = ga.root_identity_digest
        history = [
            {
                "chainDepth": 0,
                "releaseId": ga.release_id,
                "buildVersion": ga.build_version,
                "tag": ga.tag,
                "sourceCommit": ga.source_commit,
                "releaseClass": "stable-ga",
                "productDigest": ga.product_digest,
                "baselineIdentityDigest": ga.baseline_digest,
                "publicationReceiptIdentityDigest": ga.receipt_digest,
                "previousLineageDigest": ga.root_identity_digest,
            }
        ]
        outstanding = None
        pointer_digest: str | None = None
        closure_digest: str | None = None
    else:
        errors.extend(validate_schema(baseline.value, SUCCESSOR_SCHEMA))
        errors.extend(validate_schema(receipt.value, PUBLICATION_RECEIPT_SCHEMA))
        release = baseline.value.get("release")
        release = release if isinstance(release, dict) else {}
        lineage = baseline.value.get("lineage")
        lineage = lineage if isinstance(lineage, dict) else {}
        publication = baseline.value.get("publication")
        publication = publication if isinstance(publication, dict) else {}
        release_id = str(release.get("releaseId", ""))
        build_version = str(release.get("buildVersion", ""))
        source_commit = str(release.get("sourceCommit", ""))
        product_digest = str(release.get("productDigest", ""))
        tag = str(release.get("tag", ""))
        chain_depth = lineage.get("chainDepth") if type(lineage.get("chainDepth")) is int else -1
        previous_lineage_digest = str(lineage.get("lineageDigest", ""))
        history_value = lineage.get("history")
        history = list(history_value) if isinstance(history_value, list) else []
        outstanding_value = baseline.value.get("hotfixFollowUp")
        outstanding = outstanding_value if isinstance(outstanding_value, dict) else None
        if outstanding and outstanding.get("status") in {"open", "overdue"}:
            required_obligation_bindings = (
                "obligatedReleaseId",
                "obligatedBuildVersion",
                "obligatedProductDigest",
                "obligatedCandidateIdentityDigest",
                "obligatedCandidateFreezeDigest",
                "obligatedCandidateFrozenAt",
                "obligatedPredecessorBuild",
                "obligatedPredecessorProductDigest",
                "authorizationDigest",
            )
            if any(not outstanding.get(key) for key in required_obligation_bindings):
                errors.append(
                    "unresolved predecessor hotfix follow-up omits original release identity bindings"
                )
        if (
            baseline.value.get("kind") != "stable-1.0-maintenance-successor-baseline"
            or baseline.value.get("stableMilestone") != STABLE_MILESTONE
            or baseline.value.get("status") != "published"
            or lineage.get("gaBaselineDigest") != ga.baseline_digest
            or lineage.get("gaPublicationReceiptDigest") != ga.receipt_digest
            or receipt.value.get("publicationState") != "publication-complete"
            or receipt.value.get("finalVerificationStatus") != "pass"
            or receipt.value.get("releaseId") != release_id
            or receipt.value.get("buildVersion") != build_version
            or receipt.value.get("sourceCommit") != source_commit
            or receipt.value.get("productDigest") != product_digest
            or receipt.value.get("successorBaselineDigest") != baseline.digest
            or publication.get("receiptIdentityDigest") != _receipt_identity(receipt.value)
        ):
            errors.append("predecessor successor baseline and public receipt do not authenticate")
        pointer = load_json_input(context, "latestPublishedMaintenancePointer", required=False)
        pointer_digest = pointer.digest if pointer is not None else None
        closure_digest = None
        if pointer is None:
            errors.append("later predecessor requires the protected latest-published pointer")
        elif (
            pointer.value.get("kind") != "stable-1.0-maintenance-latest-published"
            or pointer.value.get("releaseId") != release_id
            or pointer.value.get("buildVersion") != build_version
            or pointer.value.get("baselineDigest") != baseline.digest
            or pointer.value.get("publicationReceiptDigest") != receipt.digest
            or pointer.value.get("lineageDigest") != previous_lineage_digest
            or pointer.value.get("backportReleaseTrainDigest")
            != baseline.value.get("releaseTrain", {}).get("validationDigest")
            or pointer.value.get("status") != "active"
        ):
            errors.append("latest-published pointer does not select the predecessor exactly")
        if len(history) != chain_depth + 1:
            errors.append("predecessor lineage history depth is incomplete")
        last_build = 0
        seen: set[str] = set()
        for index, row in enumerate(history):
            if not isinstance(row, dict):
                errors.append("predecessor lineage history contains a malformed row")
                continue
            row_build = str(row.get("buildVersion", ""))
            row_baseline = str(row.get("baselineIdentityDigest", ""))
            expected_previous_lineage = (
                ga.root_identity_digest
                if index <= 1
                else semantic_digest(history[:index])
            )
            if (
                row.get("chainDepth") != index
                or BUILD_VERSION_RE.fullmatch(row_build) is None
                or int(row_build) <= last_build
                or DIGEST_RE.fullmatch(row_baseline) is None
                or row_baseline in seen
                or row.get("tag") != f"v{row_build}"
                or COMMIT_RE.fullmatch(str(row.get("sourceCommit", ""))) is None
                or DIGEST_RE.fullmatch(str(row.get("productDigest", ""))) is None
                or DIGEST_RE.fullmatch(
                    str(row.get("publicationReceiptIdentityDigest", ""))
                )
                is None
                or row.get("previousLineageDigest") != expected_previous_lineage
                or (
                    index == 0
                    and (
                        row.get("releaseId") != ga.release_id
                        or row_build != ga.build_version
                        or row.get("tag") != ga.tag
                        or row.get("sourceCommit") != ga.source_commit
                        or row.get("releaseClass") != "stable-ga"
                        or row.get("productDigest") != ga.product_digest
                        or row_baseline != ga.baseline_digest
                        or row.get("publicationReceiptIdentityDigest")
                        != ga.receipt_digest
                    )
                )
                or (index > 0 and row.get("releaseClass") not in RELEASE_CLASSES)
            ):
                errors.append("predecessor lineage contains a gap, fork, or non-monotonic build")
            last_build = int(row_build) if row_build.isdigit() else last_build
            seen.add(row_baseline)
        if not history or history[0].get("baselineIdentityDigest") != ga.baseline_digest:
            errors.append("predecessor lineage is not rooted in the authenticated GA baseline")
        if history and history[-1].get(
            "baselineIdentityDigest"
        ) != successor_baseline_identity(baseline.value):
            errors.append("predecessor lineage does not end at the selected latest identity")
        if history and (
            history[-1].get("releaseId") != release_id
            or history[-1].get("buildVersion") != build_version
            or history[-1].get("tag") != tag
            or history[-1].get("sourceCommit") != source_commit
            or history[-1].get("releaseClass") != release.get("releaseClass")
            or history[-1].get("productDigest") != product_digest
            or history[-1].get("publicationReceiptIdentityDigest")
            != _receipt_identity(receipt.value)
            or history[-1].get("previousLineageDigest")
            != baseline.value.get("previousLineageDigest")
            or lineage.get("lineageDigest") != semantic_digest(history)
        ):
            errors.append("predecessor lineage tip does not bind the selected published release")
    expected_build = str(context.manifest.policies.get("expectedPredecessorBuild", ""))
    expected_release = str(context.manifest.policies.get("expectedPredecessorReleaseId", ""))
    expected_product = str(context.manifest.policies.get("expectedPredecessorProductDigest", ""))
    candidate_build = str(context.manifest.release.version or "")
    if (
        build_version != expected_build
        or release_id != expected_release
        or product_digest != expected_product
        or BUILD_VERSION_RE.fullmatch(candidate_build) is None
        or BUILD_VERSION_RE.fullmatch(build_version) is None
        or (
            not allow_non_successor_build
            and int(candidate_build) <= int(build_version)
        )
    ):
        errors.append("declared predecessor identity is stale, mismatched, or non-increasing")
    release_class = context.manifest.policies.get("releaseClass")
    if outstanding and outstanding.get("status") in {"open", "overdue"}:
        closure = load_json_input(context, "hotfixFollowUpClosure", required=False)
        if closure is not None:
            closure_errors = validate_schema(
                closure.value, FOLLOW_UP_CLOSURE_SCHEMA
            )
            if (
                closure.value.get("status") != "closed"
                or closure.value.get("releaseId")
                != outstanding.get("obligatedReleaseId")
                or closure.value.get("buildVersion")
                != outstanding.get("obligatedBuildVersion")
                or closure.value.get("releaseClass") != "security-hotfix"
                or closure.value.get("productDigest")
                != outstanding.get("obligatedProductDigest")
                or closure.value.get("successorBaselineDigest") != baseline.digest
                or closure.value.get("publicationReceiptDigest") != receipt.digest
                or closure.value.get("publicationReceiptIdentityDigest")
                != _receipt_identity(receipt.value)
                or closure.value.get("authorizationDigest")
                != outstanding.get("authorizationDigest")
                or closure.value.get("candidateIdentityDigest")
                != outstanding.get("obligatedCandidateIdentityDigest")
                or closure.value.get("predecessorBuild")
                != outstanding.get("obligatedPredecessorBuild")
                or closure.value.get("predecessorProductDigest")
                != outstanding.get("obligatedPredecessorProductDigest")
                or closure.value.get("latestPublishedPointerDigest") != pointer_digest
                or closure.value.get("obligationDigest")
                != outstanding.get("obligationDigest")
            ):
                closure_errors.append(
                    "hotfix follow-up closure does not bind the published predecessor"
                )
            if closure_errors:
                errors.extend(closure_errors)
            else:
                closure_digest = closure.digest
                outstanding = {
                    **outstanding,
                    "status": "closed",
                    "closureEvidenceDigest": closure.value.get("fullEvidenceDigest"),
                    "blocksRoutineMaintenance": False,
                }
        if _routine_follow_up_blocked(outstanding, release_class):
            errors.append(
                "routine maintenance is blocked by an unresolved hotfix follow-up obligation"
            )
    add_blockers(
        state,
        "stable-maintenance.predecessor-lineage",
        errors,
        "Select the exact latest activated predecessor baseline, receipt, and pointer.",
    )
    return Predecessor(
        baseline.value,
        baseline.digest,
        receipt.value,
        receipt.digest,
        release_id,
        build_version,
        source_commit,
        product_digest,
        tag,
        chain_depth,
        previous_lineage_digest,
        history,
        outstanding,
        pointer_digest,
        closure_digest,
    )


def _routine_follow_up_blocked(
    outstanding: dict[str, Any],
    release_class: Any,
    now: dt.datetime | None = None,
) -> bool:
    """Return whether one unresolved follow-up blocks a routine successor."""

    if (
        release_class != "maintenance"
        or outstanding.get("status") not in {"open", "overdue"}
    ):
        return False
    deadline = parse_timestamp(outstanding.get("deadline"))
    current = now or dt.datetime.now(dt.timezone.utc)
    return bool(
        outstanding.get("status") == "overdue"
        or deadline is None
        or deadline <= current
        or outstanding.get("blocksRoutineMaintenance") is True
    )


def _safe_member_name(name: str) -> bool:
    normalized = name.replace("\\", "/")
    canonical = normalized[:-1] if normalized.endswith("/") else normalized
    raw_parts = canonical.split("/")
    pure = PurePosixPath(canonical)
    return (
        bool(name)
        and bool(canonical)
        and "\\" not in name
        and not any(part in {"", "."} for part in raw_parts)
        and re.match(r"^[A-Za-z]:", normalized) is None
        and not normalized.startswith("//")
        and not pure.is_absolute()
        and ".." not in pure.parts
        and not any(part in {"__MACOSX", ".DS_Store"} or part.startswith("._") for part in pure.parts)
    )


def _canonical_member_name(name: str) -> str | None:
    """Return the unique extraction-path identity for one safe archive member."""

    if not _safe_member_name(name):
        return None
    normalized = name.replace("\\", "/")
    return normalized[:-1] if normalized.endswith("/") else normalized


def _safe_symlink_target(member_name: str, link_name: str) -> bool:
    """Reject absolute, drive-qualified, UNC, or escaping archive symlink targets."""

    if not _safe_member_name(member_name) or not _safe_member_name(link_name):
        return False
    target = PurePosixPath(member_name.replace("\\", "/")).parent / PurePosixPath(
        link_name.replace("\\", "/")
    )
    return ".." not in target.parts


def _expected_archive_mode(
    name: str, *, directory: bool, symlink: bool = False
) -> int:
    """Return the fixed portable permission mode for one member path and type."""

    if symlink:
        return 0o777
    if directory:
        return 0o755
    normalized = name.replace("\\", "/").rstrip("/").lower()
    executable_bin_member = (
        normalized.startswith("bin/")
        and not normalized.endswith(".bat")
        and not normalized.endswith(".exe")
    )
    executable_library_member = (
        normalized in {"lib/jexec", "lib/jspawnhelper"}
        or normalized.startswith("lib/libwrapper-linux-")
        or normalized.startswith("lib/libwrapper-macosx-")
    )
    return 0o755 if executable_bin_member or executable_library_member else 0o644


def _normalized_archive_mode(
    mode: int, name: str, *, directory: bool, symlink: bool = False
) -> bool:
    """Require the path-derived portable permission emitted by both normalizers."""

    return mode & 0o7777 == _expected_archive_mode(
        name, directory=directory, symlink=symlink
    )


def _bounded_nested_bytes(stream: Any, size: int, name: str) -> tuple[bytes | None, str | None]:
    """Read a nested member only after enforcing its declared and streamed size bound."""

    if size < 0 or size > MAX_NESTED_ARCHIVE_BYTES:
        return None, f"nested archive exceeds inspection policy: {name}"
    data = stream.read(MAX_NESTED_ARCHIVE_BYTES + 1)
    if len(data) > MAX_NESTED_ARCHIVE_BYTES or len(data) != size:
        return None, f"nested archive exceeds inspection policy: {name}"
    return data, None


def _nested_archive_errors(data: bytes, name: str, depth: int = 1) -> list[str]:
    """Inspect a bounded nested archive for path, type, and further nesting attacks."""

    errors: list[str] = []
    if depth > 3 or len(data) > MAX_NESTED_ARCHIVE_BYTES:
        return [f"nested archive exceeds inspection policy: {name}"]
    lowered = name.lower()
    try:
        if lowered.endswith((".zip", ".jar", ".war", ".ear")):
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                names: set[str] = set()
                for member in archive.infolist():
                    canonical_name = _canonical_member_name(member.filename)
                    if canonical_name is None:
                        errors.append(f"nested archive contains an unsafe member: {name}")
                    elif canonical_name in names:
                        errors.append(
                            f"nested archive contains a duplicate member path: {name}"
                        )
                    else:
                        names.add(canonical_name)
                    mode = member.external_attr >> 16
                    file_type = stat.S_IFMT(mode)
                    if not member.is_dir() and file_type not in {
                        0,
                        stat.S_IFREG,
                        stat.S_IFDIR,
                    }:
                        errors.append(f"nested archive contains a special member: {name}")
                    if member.filename.lower().endswith(
                        (".zip", ".jar", ".war", ".ear", ".tar", ".tar.gz", ".tgz")
                    ):
                        with archive.open(member) as stream:
                            nested_data, size_error = _bounded_nested_bytes(
                                stream, member.file_size, member.filename
                            )
                        if size_error:
                            errors.append(size_error)
                        elif nested_data is not None:
                            errors.extend(
                                _nested_archive_errors(
                                    nested_data, member.filename, depth + 1
                                )
                            )
        elif lowered.endswith((".tar", ".tar.gz", ".tgz")):
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
                names = set()
                for member in archive.getmembers():
                    canonical_name = _canonical_member_name(member.name)
                    if canonical_name is None:
                        errors.append(f"nested archive contains an unsafe member: {name}")
                    elif canonical_name in names:
                        errors.append(
                            f"nested archive contains a duplicate member path: {name}"
                        )
                    else:
                        names.add(canonical_name)
                    if not (member.isfile() or member.isdir() or member.issym()):
                        errors.append(f"nested archive contains a special member: {name}")
                    if member.issym() and not _safe_symlink_target(
                        member.name, member.linkname
                    ):
                        errors.append(
                            f"nested archive contains an unsafe symlink target: {name}"
                        )
                    if member.isfile() and member.name.lower().endswith(
                        (".zip", ".jar", ".war", ".ear", ".tar", ".tar.gz", ".tgz")
                    ):
                        stream = archive.extractfile(member)
                        if stream is None:
                            errors.append(f"nested archive member cannot be inspected: {name}")
                        else:
                            nested_data, size_error = _bounded_nested_bytes(
                                stream, member.size, member.name
                            )
                            if size_error:
                                errors.append(size_error)
                            elif nested_data is not None:
                                errors.extend(
                                    _nested_archive_errors(
                                        nested_data, member.name, depth + 1
                                    )
                                )
    except (OSError, tarfile.TarError, zipfile.BadZipFile, RuntimeError):
        errors.append(f"nested archive cannot be opened safely: {name}")
    return errors


def _pax_metadata_errors(member: tarfile.TarInfo) -> list[str]:
    """Reject PAX records except canonical extensions required by tar field limits."""

    errors: list[str] = []
    headers = member.pax_headers
    unknown = sorted(set(headers) - {"path", "linkpath", "size"})
    if unknown:
        errors.append(f"archive member has noncanonical PAX metadata: {member.name}")

    def needs_text_extension(value: str, limit: int) -> bool:
        try:
            value.encode("ascii", "strict")
        except UnicodeEncodeError:
            return True
        return len(value) > limit

    path = headers.get("path")
    if path is not None and (
        path != member.name or not needs_text_extension(member.name, tarfile.LENGTH_NAME)
    ):
        errors.append(f"archive member has unnecessary PAX path metadata: {member.name}")
    linkpath = headers.get("linkpath")
    if linkpath is not None and (
        linkpath != member.linkname
        or not needs_text_extension(member.linkname, tarfile.LENGTH_LINK)
    ):
        errors.append(f"archive member has unnecessary PAX link metadata: {member.name}")
    size = headers.get("size")
    if size is not None and (
        size != str(member.size) or member.size < 8 ** (tarfile.LENGTH_SIZE - 1)
    ):
        errors.append(f"archive member has unnecessary PAX size metadata: {member.name}")
    return errors


def archive_hygiene_errors(path: Path, *, nested: bool = True) -> list[str]:
    """Inspect tar/zip archives without extraction and reject unsafe members and nesting."""

    errors: list[str] = []
    suffix = path.name.lower()
    try:
        if suffix.endswith((".tar.gz", ".tgz", ".tar")):
            if suffix.endswith((".tar.gz", ".tgz")):
                with path.open("rb") as stream:
                    header = stream.read(10)
                if (
                    len(header) < 10
                    or header[:2] != b"\x1f\x8b"
                    or header[4:8] != b"\0\0\0\0"
                    or header[3] != 0
                ):
                    errors.append("gzip header metadata is not deterministic")
            with tarfile.open(path, "r:*") as archive:
                if archive.pax_headers:
                    errors.append("archive has noncanonical global PAX metadata")
                members = archive.getmembers()
                if [member.name for member in members] != sorted(
                    member.name for member in members
                ):
                    errors.append("archive member order is not deterministic")
                names: set[str] = set()
                for member in members:
                    canonical_name = _canonical_member_name(member.name)
                    if canonical_name is None or canonical_name in names:
                        errors.append(f"archive contains unsafe or duplicate member {member.name}")
                    elif canonical_name is not None:
                        names.add(canonical_name)
                    errors.extend(_pax_metadata_errors(member))
                    if not (member.isfile() or member.isdir() or member.issym()):
                        errors.append(f"archive contains special member {member.name}")
                    if (
                        member.mtime != 0
                        or member.uid != 0
                        or member.gid != 0
                        or member.uname != "root"
                        or member.gname != "root"
                    ):
                        errors.append(f"archive member metadata is not normalized: {member.name}")
                    if not _normalized_archive_mode(
                        member.mode,
                        member.name,
                        directory=member.isdir(),
                        symlink=member.issym(),
                    ):
                        errors.append(f"archive member mode is not normalized: {member.name}")
                    if member.issym():
                        if not _safe_symlink_target(member.name, member.linkname):
                            errors.append(f"archive contains unsafe symlink target {member.name}")
                    if nested and member.isfile() and member.name.lower().endswith(
                        (".zip", ".jar", ".war", ".ear", ".tar", ".tar.gz", ".tgz")
                    ):
                        stream = archive.extractfile(member)
                        if stream is None:
                            errors.append(f"archive nested member cannot be inspected {member.name}")
                        else:
                            nested_data, size_error = _bounded_nested_bytes(
                                stream, member.size, member.name
                            )
                            if size_error:
                                errors.append(size_error)
                            elif nested_data is not None:
                                errors.extend(_nested_archive_errors(nested_data, member.name))
        elif suffix.endswith(".zip"):
            with zipfile.ZipFile(path) as archive:
                if archive.comment:
                    errors.append("archive ZIP comment is not permitted")
                members = archive.infolist()
                if [member.filename for member in members] != sorted(
                    member.filename for member in members
                ):
                    errors.append("archive member order is not deterministic")
                names: set[str] = set()
                for member in members:
                    canonical_name = _canonical_member_name(member.filename)
                    if canonical_name is None or canonical_name in names:
                        errors.append(f"archive contains unsafe or duplicate member {member.filename}")
                    elif canonical_name is not None:
                        names.add(canonical_name)
                    if member.comment or member.extra:
                        errors.append(
                            f"archive member ZIP metadata is not empty: {member.filename}"
                        )
                    mode = member.external_attr >> 16
                    has_unix_mode = member.create_system == 3 and mode != 0
                    if not has_unix_mode:
                        errors.append(
                            f"archive member Unix mode is missing: {member.filename}"
                        )
                    elif stat.S_ISLNK(mode):
                        errors.append(f"archive contains unsupported symlink {member.filename}")
                    if member.date_time != (1980, 1, 1, 0, 0, 0):
                        errors.append(
                            f"archive member timestamp is not normalized: {member.filename}"
                        )
                    if has_unix_mode and (
                        (member.is_dir() and not stat.S_ISDIR(mode))
                        or (not member.is_dir() and not stat.S_ISREG(mode))
                    ):
                        errors.append(f"archive contains special member {member.filename}")
                    if has_unix_mode and not _normalized_archive_mode(
                        mode,
                        member.filename,
                        directory=member.is_dir(),
                    ):
                        errors.append(
                            f"archive member mode is not normalized: {member.filename}"
                        )
                    if nested and member.filename.lower().endswith(
                        (".zip", ".jar", ".war", ".ear", ".tar", ".tar.gz", ".tgz")
                    ):
                        with archive.open(member) as stream:
                            nested_data, size_error = _bounded_nested_bytes(
                                stream, member.file_size, member.filename
                            )
                        if size_error:
                            errors.append(size_error)
                        elif nested_data is not None:
                            errors.extend(
                                _nested_archive_errors(nested_data, member.filename)
                            )
        else:
            errors.append("candidate archive format is not a supported deterministic archive")
    except (OSError, tarfile.TarError, zipfile.BadZipFile):
        errors.append("candidate archive cannot be opened safely")
    return errors


def _package_identity_errors(row: dict[str, Any], path: Path) -> list[str]:
    """Bind the AppEnv package selector to OS, architecture, suffix, and file magic."""

    errors: list[str] = []
    package_type = str(row.get("packageType", ""))
    architecture = str(row.get("arch", ""))
    package_key = str(row.get("packageKey", ""))
    expected_os = {
        "deb": "linux",
        "rpm": "linux",
        "flatpak": "linux",
        "snap": "linux",
        "dmg": "macos",
        "pkg": "macos",
        "exe": "windows",
        "msi": "windows",
    }.get(package_type)
    if (
        expected_os is None
        or row.get("os") != expected_os
        or package_key != f"{architecture}.{package_type}"
        or row.get("producerArchitecture") != architecture
        or not path.name.lower().endswith(f".{package_type}")
    ):
        errors.append(f"candidate package selector or suffix is inconsistent for {package_key}")
        return errors
    try:
        with path.open("rb") as stream:
            header = stream.read(8)
            trailer = b""
            if package_type == "dmg":
                stream.seek(-512, 2)
                trailer = stream.read(4)
    except OSError:
        return [f"candidate package cannot be inspected for {package_key}"]
    magic_valid = {
        "deb": header == b"!<arch>\n",
        "rpm": header.startswith(b"\xed\xab\xee\xdb"),
        "exe": header.startswith(b"MZ"),
        "dmg": trailer == b"koly",
    }.get(package_type, True)
    if not magic_valid:
        errors.append(f"candidate package file format is invalid for {package_key}")
    byte_architecture = _package_byte_architecture(path, package_type)
    if package_type in {"deb", "rpm", "exe"} and byte_architecture is None:
        errors.append(
            f"candidate package byte architecture cannot be authenticated for {package_key}"
        )
    elif byte_architecture is not None and byte_architecture != architecture:
        errors.append(
            f"candidate package byte architecture is {byte_architecture}, not {architecture}, for {package_key}"
        )
    return errors


def _package_byte_architecture(path: Path, package_type: str) -> str | None:
    """Read an architecture from formats whose authenticated bytes expose one portably."""

    try:
        if package_type == "exe":
            with path.open("rb") as stream:
                if stream.read(2) != b"MZ":
                    return None
                stream.seek(0x3C)
                offset_bytes = stream.read(4)
                if len(offset_bytes) != 4:
                    return None
                pe_offset = struct.unpack("<I", offset_bytes)[0]
                if (
                    pe_offset < 0x40
                    or pe_offset > 16 * 1024 * 1024
                    or pe_offset + 6 > path.stat().st_size
                ):
                    return None
                stream.seek(pe_offset)
                if stream.read(4) != b"PE\0\0":
                    return None
                machine_bytes = stream.read(2)
                if len(machine_bytes) != 2:
                    return None
                return {0x8664: "amd64", 0xAA64: "arm64"}.get(
                    struct.unpack("<H", machine_bytes)[0]
                )
        if package_type == "rpm":
            return _rpm_byte_architecture(path)
        if package_type == "deb":
            return _deb_byte_architecture(path)
    except (OSError, OverflowError, struct.error, tarfile.TarError, UnicodeError):
        return None
    return None


def _rpm_byte_architecture(path: Path) -> str | None:
    """Read RPMTAG_ARCH from the main RPM header without invoking host package tools."""

    def read_header(
        stream: Any, offset: int
    ) -> tuple[list[tuple[int, int, int, int]], bytes, int] | None:
        stream.seek(offset)
        header = stream.read(16)
        if len(header) != 16 or header[:4] != b"\x8e\xad\xe8\x01":
            return None
        count, store_size = struct.unpack(">II", header[8:16])
        if count > 100_000 or store_size > 64 * 1024 * 1024:
            return None
        raw_entries = stream.read(count * 16)
        store = stream.read(store_size)
        if len(raw_entries) != count * 16 or len(store) != store_size:
            return None
        entries = [
            struct.unpack(">IIII", raw_entries[index : index + 16])
            for index in range(0, len(raw_entries), 16)
        ]
        return entries, store, offset + 16 + len(raw_entries) + store_size

    with path.open("rb") as stream:
        if stream.read(4) != b"\xed\xab\xee\xdb":
            return None
        signature = read_header(stream, 96)
        if signature is None:
            return None
        main_offset = (signature[2] + 7) & ~7
        main = read_header(stream, main_offset)
        if main is None:
            return None
        entries, store, _ = main
        for tag, value_type, offset, count in entries:
            if tag != 1022 or value_type != 6 or count != 1 or offset >= len(store):
                continue
            end = store.find(b"\0", offset)
            if end < 0:
                return None
            value = store[offset:end].decode("ascii", errors="strict")
            return {
                "x86_64": "amd64",
                "amd64": "amd64",
                "aarch64": "arm64",
            }.get(value)
    return None


def _deb_byte_architecture(path: Path) -> str | None:
    """Read Architecture from a bounded DEB control archive when stdlib supports it."""

    with path.open("rb") as stream:
        if stream.read(8) != b"!<arch>\n":
            return None
        while True:
            header = stream.read(60)
            if not header:
                return None
            if len(header) != 60 or header[58:60] != b"`\n":
                return None
            try:
                size = int(header[48:58].decode("ascii").strip())
            except ValueError:
                return None
            if size < 0:
                return None
            name = header[:16].decode("ascii", errors="ignore").strip().rstrip("/")
            if name.startswith("control.tar"):
                if size > 32 * 1024 * 1024:
                    return None
                control_archive = stream.read(size)
                if len(control_archive) != size:
                    return None
                try:
                    with tarfile.open(fileobj=io.BytesIO(control_archive), mode="r:*") as control:
                        candidates = [
                            member
                            for member in control.getmembers()
                            if member.isfile() and member.name.lstrip("./") == "control"
                        ]
                        if len(candidates) != 1 or candidates[0].size > 1024 * 1024:
                            return None
                        extracted = control.extractfile(candidates[0])
                        if extracted is None:
                            return None
                        payload = extracted.read(candidates[0].size + 1)
                except (tarfile.ReadError, EOFError):
                    return None
                if len(payload) > candidates[0].size:
                    return None
                for line in payload.decode("utf-8", errors="strict").splitlines():
                    key, separator, value = line.partition(":")
                    if separator and key == "Architecture":
                        return {"amd64": "amd64", "arm64": "arm64"}.get(
                            value.strip()
                        )
                return None
            stream.seek(size + (size & 1), 1)


def _asset_root(context: RunContext) -> Path:
    root = configured_path(context, "maintenanceCandidateAssets", directory=True)
    assert root is not None
    return root.resolve()


def _asset_path(root: Path, name: Any) -> Path:
    if not isinstance(name, str) or not name or Path(name).name != name:
        raise ValueError("maintenance candidate asset filename is unsafe")
    path = root / name
    if not _regular_file(path) or path.resolve().parent != root:
        raise ValueError(f"maintenance candidate asset is missing or unsafe: {name}")
    return path


def _freeze_asset_identity(row: dict[str, Any]) -> dict[str, Any]:
    """Select the byte and package fields that must agree with the frozen asset set."""

    return {
        key: row.get(key)
        for key in (
            "role",
            "fileName",
            "digest",
            "sizeBytes",
            "packageKey",
            "os",
            "arch",
            "producerArchitecture",
            "packageType",
            "publicAsset",
            "signingStatus",
            "notarizationStatus",
        )
    }


def stable_catalog_verification_identity(
    catalog: Mapping[str, Any], trusted_key_registry_digest: str,
) -> dict[str, Any]:
    """Return the public-safe identity of one exact catalog signature verification."""

    return {
        "schemaVersion": 1,
        "kind": "stable-1.0-maintenance-catalog-signature-verification",
        "catalogDigest": catalog.get("digest"),
        "signatureDigest": catalog.get("signatureDigest"),
        "signingKeyId": catalog.get("signingKeyId"),
        "trustedKeyRegistryDigest": trusted_key_registry_digest,
        "signatureAlgorithm": "Ed25519",
        "verifier": "network.crypta.platform.appcatalog.AppCatalogVerifier",
        "cryptographicVerificationStatus": "pass",
        "redaction": {"status": "pass", "findingCount": 0, "findings": []},
    }


def catalog_authority_binding_errors(candidate: Mapping[str, Any]) -> list[str]:
    """Reject unauthenticated local projections of protected PR-293 authority."""

    binding = candidate.get("catalogAuthority")
    if binding is None:
        return []
    if not isinstance(binding, Mapping):
        return ["selected catalog-authority evidence binding is malformed"]
    catalog = candidate.get("stableCatalog")
    catalog = catalog if isinstance(catalog, Mapping) else {}
    errors: list[str] = []
    if binding.get("catalogSigningKeyId") != catalog.get("signingKeyId"):
        errors.append(
            "selected catalog-authority evidence does not authorize the candidate catalog signer"
        )
    digest_fields = (
        "summaryDigest",
        "protectedEvidenceDigest",
        "keysetDigest",
        "transparencyDigest",
        "catalogSigningKeyFingerprintSha256",
    )
    digests = [binding.get(field) for field in digest_fields]
    if any(value == "sha256:" + "0" * 64 for value in digests):
        errors.append("selected catalog-authority evidence contains an unbound digest")
    if binding.get("summaryDigest") == binding.get("protectedEvidenceDigest"):
        errors.append(
            "catalog-authority summary and protected evidence must be distinct exact artifacts"
        )
    errors.append(
        "a local catalog-authority binding cannot authenticate protected operational evidence"
    )
    return errors


def _candidate_package_notarization_errors(
    row: dict[str, Any], package_key: str
) -> list[str]:
    """Require notarization only for the exact macOS DMG package class."""

    expected = "pass" if row.get("packageType") == "dmg" else "not-applicable"
    if row.get("notarizationStatus") == expected:
        return []
    if expected == "pass":
        return [f"candidate macOS package notarization status failed for {package_key}"]
    return [
        f"candidate non-DMG package claims notarization for {package_key}"
    ]


def select_candidate_dmg_for_freeze(
    packages: list[dict[str, Any]],
    release_class: str,
    change_scope: dict[str, Any],
) -> dict[str, Any] | None:
    """Select at most one DMG, allowing omission only for a declared narrowed hotfix."""

    dmg_packages = [
        package for package in packages if package.get("packageType") == "dmg"
    ]
    if len(dmg_packages) > 1:
        raise ValueError("candidate contains multiple DMG packages")
    if dmg_packages:
        return dmg_packages[0]
    if not isinstance(change_scope, dict):
        raise ValueError("candidate without a DMG lacks a valid change-scope declaration")
    package_keys = sorted(str(package.get("packageKey", "")) for package in packages)
    affected_keys = change_scope.get("affectedPackageKeys")
    narrowed_hotfix = (
        release_class == "security-hotfix"
        and change_scope.get("unaffectedPackageProofStatus") == "pass"
        and isinstance(affected_keys, list)
        and bool(package_keys)
        and package_keys == sorted(str(key) for key in affected_keys)
    )
    if not narrowed_hotfix:
        raise ValueError("candidate without a DMG is not a declared narrowed hotfix")
    return None


def _candidate_freeze_errors(
    context: RunContext,
    freeze: LoadedJson,
    candidate_value: dict[str, Any],
    expected_predecessor_observation: Predecessor | Mapping[str, Any],
    expected_assets: list[dict[str, Any]],
    checksums_digest: str,
) -> list[str]:
    """Authenticate a prior one-build freeze against candidate declarations and actual bytes."""

    value = freeze.value
    errors = validate_schema(value, CANDIDATE_FREEZE_SCHEMA)
    if value.get("schemaVersion") == 2:
        try:
            helper_path = Path(__file__).resolve().parents[2] / "protected" / "maintenance_runtime_metadata.py"
            # Fixed checked-in validator is offline; it never executes or fetches product inputs.
            import sys
            sys.path.insert(0, str(helper_path.parent))
            from maintenance_runtime_metadata import validate_runtime_metadata
            runtime_inputs = configured_path(context, "maintenanceRuntimeInputs", directory=True)
            if runtime_inputs is None:
                raise ValueError("missing runtime input")
            product = candidate_value.get("product", {})
            validate_runtime_metadata(value, runtime_inputs / "runtime",
                                      package_path=_asset_root(context) / product["fileName"])
        except (ValueError, KeyError, OSError):
            errors.append("candidate freeze runtime metadata is missing or does not bind exact inputs")
    source = candidate_value.get("source")
    source = source if isinstance(source, dict) else {}
    toolchain = candidate_value.get("toolchain")
    toolchain = toolchain if isinstance(toolchain, dict) else {}
    producer = value.get("producer")
    producer = producer if isinstance(producer, dict) else {}
    candidate_catalog = candidate_value.get("stableCatalog")
    candidate_catalog = (
        candidate_catalog if isinstance(candidate_catalog, dict) else {}
    )
    catalog_verification = value.get("stableCatalogVerification")
    catalog_verification = (
        catalog_verification if isinstance(catalog_verification, dict) else {}
    )
    expected_catalog_verification = stable_catalog_verification_identity(
        candidate_catalog,
        str(catalog_verification.get("trustedKeyRegistryDigest", "")),
    )
    catalog_verification_digest = semantic_digest(expected_catalog_verification)
    observation = value.get("predecessorObservation")
    observation = observation if isinstance(observation, dict) else {}
    if isinstance(expected_predecessor_observation, Predecessor):
        expected_predecessor_observation = {
            "sourceCommit": expected_predecessor_observation.source_commit,
            "releaseId": expected_predecessor_observation.release_id,
            "buildVersion": expected_predecessor_observation.build_version,
            "productDigest": expected_predecessor_observation.product_digest,
            "baselineDigest": expected_predecessor_observation.baseline_digest,
            "publicationReceiptDigest": (
                expected_predecessor_observation.receipt_digest
            ),
            "latestPublishedPointerDigest": (
                expected_predecessor_observation.latest_pointer_digest
            ),
        }
    generated = parse_timestamp(value.get("generatedAt"))
    frozen = parse_timestamp(value.get("frozenAt"))
    observed = parse_timestamp(observation.get("observedAt"))
    candidate_generated = parse_timestamp(candidate_value.get("generatedAt"))
    candidate_product = candidate_value.get("product")
    candidate_product = candidate_product if isinstance(candidate_product, dict) else {}
    if (
        value.get("releaseId") != context.manifest.release.release_id
        or value.get("buildVersion") != context.manifest.release.version
        or value.get("releaseClass") != context.manifest.policies.get("releaseClass")
        or value.get("stableMilestone") != STABLE_MILESTONE
        or value.get("source") != source
        or value.get("toolchain") != toolchain
        or producer.get("workflowCommit") != source.get("commit")
        or value.get("buildCount") != 1
        or value.get("rebuildPerformed") is not False
        or value.get("checksumsDigest") != checksums_digest
        or candidate_value.get("candidateFreezeDigest") != freeze.digest
        or candidate_product.get("frozenAt") != value.get("frozenAt")
        or generated is None
        or frozen is None
        or observed is None
        or candidate_generated is None
        or generated < frozen
        or observed > frozen
        or candidate_generated < generated
    ):
        errors.append(
            "candidate freeze release, source, toolchain, producer, checksum, or time binding is invalid"
        )
    if (
        observation.get("releaseId")
        != expected_predecessor_observation.get("releaseId")
        or observation.get("buildVersion")
        != expected_predecessor_observation.get("buildVersion")
        or observation.get("productDigest")
        != expected_predecessor_observation.get("productDigest")
        or observation.get("baselineDigest")
        != expected_predecessor_observation.get("baselineDigest")
        or observation.get("publicationReceiptDigest")
        != expected_predecessor_observation.get("publicationReceiptDigest")
        or observation.get("latestPublishedPointerDigest")
        != expected_predecessor_observation.get("latestPublishedPointerDigest")
        or (value.get("schemaVersion") == 2
            and observation.get("sourceCommit") != expected_predecessor_observation.get("sourceCommit"))
        or observation.get("status") != "latest-published"
    ):
        errors.append("candidate freeze used a stale or substituted predecessor observation")
    if catalog_verification != expected_catalog_verification:
        errors.append(
            "candidate freeze lacks exact cryptographic Stable catalog verification"
        )
    rows = value.get("assets")
    rows = rows if isinstance(rows, list) else []
    valid_rows = [row for row in rows if isinstance(row, dict)]
    names = [row.get("fileName") for row in valid_rows]
    package_keys = [
        row.get("packageKey")
        for row in valid_rows
        if row.get("role") == "package"
    ]
    actual_identities = sorted(
        (_freeze_asset_identity(row) for row in valid_rows),
        key=lambda row: str(row.get("fileName")),
    )
    expected_identities = sorted(
        (_freeze_asset_identity(row) for row in expected_assets),
        key=lambda row: str(row.get("fileName")),
    )
    if (
        len(rows) != len(names)
        or len(names) != len(set(names))
        or len(package_keys) != len(set(package_keys))
        or actual_identities != expected_identities
        or value.get("assetSetDigest")
        != semantic_digest(
            sorted(valid_rows, key=lambda row: str(row.get("fileName")))
        )
    ):
        errors.append("candidate freeze contains an omitted, extra, replaced, or duplicate asset")
    for row in rows:
        if not isinstance(row, dict):
            continue
        if row.get("role") in {"stable-catalog", "stable-catalog-signature"} and (
            row.get("signingStatus") != "pass"
            or row.get("signingReceiptDigest") != catalog_verification_digest
        ):
            errors.append(
                f"candidate freeze catalog signature verification receipt is invalid for {row.get('fileName')}"
            )
        notarization = row.get("notarizationStatus")
        notarization_receipt = row.get("notarizationReceiptDigest")
        is_dmg_package = (
            row.get("role") == "package" and row.get("packageType") == "dmg"
        )
        receipt_is_digest = (
            DIGEST_RE.fullmatch(str(notarization_receipt)) is not None
        )
        if is_dmg_package and (
            notarization != "pass" or not receipt_is_digest
        ):
            errors.append(
                f"candidate freeze DMG notarization receipt is invalid for {row.get('fileName')}"
            )
        elif not is_dmg_package and (
            notarization != "not-applicable" or notarization_receipt is not None
        ):
            errors.append(
                f"candidate freeze non-DMG asset carries notarization for {row.get('fileName')}"
            )
    return errors


def _candidate_provenance_errors(
    context: RunContext,
    provenance: dict[str, Any],
    source: dict[str, Any],
    product_digest: str,
    candidate_input_digest: str,
    candidate_freeze_digest: str,
    expected_assets: dict[str, str],
) -> list[str]:
    """Bind candidate provenance to the exact declaration, freeze, source, and asset set."""

    provenance_assets = provenance.get("assets")
    provenance_assets = provenance_assets if isinstance(provenance_assets, list) else []
    provenance_map = {
        str(row.get("name")): str(row.get("digest"))
        for row in provenance_assets
        if isinstance(row, dict)
    }
    if (
        provenance.get("kind")
        != "stable-1.0-maintenance-candidate-provenance"
        or provenance.get("releaseId") != context.manifest.release.release_id
        or provenance.get("buildVersion") != context.manifest.release.version
        or provenance.get("releaseClass")
        != context.manifest.policies.get("releaseClass")
        or provenance.get("source") != source
        or provenance.get("productDigest") != product_digest
        or provenance.get("candidateInputDigest") != candidate_input_digest
        or provenance.get("candidateFreezeDigest") != candidate_freeze_digest
        or len(provenance_map) != len(provenance_assets)
        or provenance_map != expected_assets
        or provenance.get("redaction", {}).get("status") != "pass"
    ):
        return [
            "candidate provenance does not bind the exact input, freeze, and asset identities"
        ]
    return []


def _package_matrix_scope_errors(
    release_class: str,
    package_keys: list[str],
    required_keys: list[str],
    change_scope: dict[str, Any],
    policy: dict[str, Any],
) -> list[str]:
    """Validate the complete or explicitly narrowed hotfix package matrix."""

    if release_class != "security-hotfix":
        if sorted(package_keys) == sorted(required_keys):
            return []
        return ["candidate package matrix is incomplete or contains unsupported keys"]

    errors: list[str] = []
    hotfix_policy = (
        policy.get("hotfix") if isinstance(policy.get("hotfix"), dict) else {}
    )
    affected_value = change_scope.get("affectedPackageKeys")
    affected_keys = (
        [key for key in affected_value if isinstance(key, str)]
        if isinstance(affected_value, list)
        else []
    )
    affected_set = set(affected_keys)
    package_set = set(package_keys)
    required_set = set(required_keys)
    if (
        hotfix_policy.get("requiresNonemptyAffectedPackageKeys") is not True
        or not isinstance(affected_value, list)
        or not affected_keys
        or len(affected_keys) != len(affected_value)
        or len(affected_keys) != len(affected_set)
        or not affected_set.issubset(required_set)
        or not affected_set.issubset(package_set)
    ):
        errors.append(
            "security hotfix affected package keys must be a nonempty supported subset "
            "of the candidate package matrix"
        )

    full_matrix = sorted(package_keys) == sorted(required_keys)
    proof_status = change_scope.get("unaffectedPackageProofStatus")
    if full_matrix:
        expected_status = hotfix_policy.get(
            "fullMatrixUnaffectedPackageProofStatus"
        )
        if expected_status != "not-applicable" or proof_status != expected_status:
            errors.append(
                "complete security-hotfix package matrix requires "
                "unaffectedPackageProofStatus=not-applicable"
            )
    else:
        expected_status = hotfix_policy.get(
            "narrowedMatrixUnaffectedPackageProofStatus"
        )
        exact_keys_required = hotfix_policy.get(
            "requiresExactAffectedKeysForNarrowedMatrix"
        )
        if (
            expected_status != "pass"
            or exact_keys_required is not True
            or proof_status != expected_status
            or not package_keys
            or not package_set.issubset(required_set)
            or sorted(package_keys) != sorted(affected_keys)
        ):
            errors.append(
                "narrowed security-hotfix package matrix requires "
                "unaffectedPackageProofStatus=pass and exact affected-package equality"
            )
    return errors


def authenticate_candidate(
    context: RunContext,
    predecessor: Predecessor,
    policy: dict[str, Any],
    state: ValidationState,
    *,
    allow_published_product: bool = False,
    freeze_predecessor_observation: Mapping[str, Any] | None = None,
) -> Candidate:
    """Authenticate exact candidate bytes, one-time build provenance, and package matrix."""

    loaded = load_json_input(context, "maintenanceCandidate")
    freeze = load_json_input(context, "maintenanceCandidateFreeze")
    provenance = load_json_input(context, "maintenanceCandidateProvenance")
    checksums_path = configured_path(context, "maintenanceCandidateChecksums")
    assert loaded and freeze and provenance and checksums_path
    errors = validate_schema(loaded.value, CANDIDATE_INPUT_SCHEMA)
    value = loaded.value
    errors.extend(catalog_authority_binding_errors(value))
    source = value.get("source") if isinstance(value.get("source"), dict) else {}
    product = value.get("product") if isinstance(value.get("product"), dict) else {}
    packages = value.get("packages") if isinstance(value.get("packages"), list) else []
    toolchain = value.get("toolchain") if isinstance(value.get("toolchain"), dict) else {}
    release_class = str(context.manifest.policies.get("releaseClass", ""))
    build_version = str(context.manifest.release.version or "")
    expected_branch = f"{'release' if release_class == 'maintenance' else 'hotfix'}/{build_version}"
    if (
        value.get("releaseId") != context.manifest.release.release_id
        or value.get("buildVersion") != build_version
        or value.get("releaseClass") != release_class
        or source.get("branch") != expected_branch
        or source.get("commit") != context.manifest.policies.get("candidateSourceCommit")
        or source.get("ref") != context.manifest.policies.get("candidateSourceRef")
        or source.get("baseCommit")
        != context.manifest.policies.get("candidateBaseCommit")
        or source.get("treeState") != "clean"
        or source.get("branchHeadVerified") is not True
        or source.get("immutableRefVerified") is not True
        or value.get("builtOnce") is not True
        or value.get("rebuildCount") != 0
        or toolchain.get("dependencyVerificationStatus") != "pass"
        or toolchain.get("javaMajorVersion", 0) < 25
    ):
        errors.append("candidate source, class, one-time build, or toolchain identity is invalid")
    if release_class == "maintenance" and source.get("baseBranch") != "develop":
        errors.append("routine maintenance candidate is not based on develop")
    if release_class == "security-hotfix" and (
        source.get("baseBranch") != "main"
        or source.get("currentPublishedMainBaseVerified") is not True
    ):
        errors.append("security hotfix is not based on the currently published main state")
    root = _asset_root(context)
    product_path = _asset_path(root, product.get("fileName"))
    product_digest = file_digest(product_path)
    if (
        product.get("digest") != product_digest
        or product.get("sizeBytes") != product_path.stat().st_size
        or product.get("checksumsDigest") != file_digest(checksums_path)
        or (
            product_digest == predecessor.product_digest
            and not allow_published_product
        )
    ):
        errors.append("candidate product bytes, size, or predecessor distinction is invalid")
    archive_format = product.get("archiveFormat")
    if (
        archive_format == "tar.gz"
        and not product_path.name.lower().endswith((".tar.gz", ".tgz"))
    ) or (archive_format == "zip" and not product_path.name.lower().endswith(".zip")):
        errors.append("candidate product filename does not match its declared archive format")
    errors.extend(archive_hygiene_errors(product_path))
    catalog = value.get("stableCatalog")
    catalog = catalog if isinstance(catalog, dict) else {}
    catalog_path = _asset_path(root, catalog.get("fileName"))
    catalog_signature_path = _asset_path(root, catalog.get("signatureFileName"))
    if (
        catalog.get("digest") != file_digest(catalog_path)
        or catalog.get("sizeBytes") != catalog_path.stat().st_size
    ):
        errors.append("stable catalog bytes or size do not match the frozen candidate")
    if (
        catalog.get("signatureDigest") != file_digest(catalog_signature_path)
        or catalog.get("signatureSizeBytes") != catalog_signature_path.stat().st_size
    ):
        errors.append(
            "stable catalog detached signature bytes or size do not match the frozen candidate"
        )
    assets: list[dict[str, Any]] = []
    asset_paths: dict[str, Path] = {
        product_path.name: product_path,
        catalog_path.name: catalog_path,
        catalog_signature_path.name: catalog_signature_path,
    }
    package_keys: list[str] = []
    for row in packages:
        if not isinstance(row, dict):
            errors.append("candidate package row is malformed")
            continue
        name = row.get("fileName")
        try:
            path = _asset_path(root, name)
        except ValueError as exc:
            errors.append(str(exc))
            continue
        key = str(row.get("packageKey", ""))
        package_keys.append(key)
        if (
            row.get("digest") != file_digest(path)
            or row.get("sizeBytes") != path.stat().st_size
            or row.get("sourceCommit") != source.get("commit")
            or row.get("buildVersion") != build_version
            or row.get("signingStatus") != "pass"
            or row.get("installLaunchStatus") != "pass"
            or row.get("upgradeStatus") != "pass"
            or row.get("redactionStatus") != "pass"
        ):
            errors.append(f"candidate package identity or evidence failed for {key}")
        errors.extend(_candidate_package_notarization_errors(row, key))
        errors.extend(_package_identity_errors(row, path))
        asset_paths[str(name)] = path
        assets.append(dict(row))
    if len(package_keys) != len(set(package_keys)) or len(asset_paths) != len(packages) + 3:
        errors.append("candidate package keys or asset filenames are duplicated")
    matrix = policy.get("packageMatrix") if isinstance(policy.get("packageMatrix"), dict) else {}
    required_keys = list(matrix.get("requiredCoreUpdatePackageKeys", []))
    change_scope = value.get("changeScope") if isinstance(value.get("changeScope"), dict) else {}
    categories = change_scope.get("categories")
    allowed_categories = set(policy.get("allowedMaintenanceCategories", []))
    if (
        not isinstance(categories, list)
        or not categories
        or not set(categories).issubset(allowed_categories)
        or (
            release_class == "security-hotfix"
            and "security-fixes-and-hotfixes" not in categories
        )
    ):
        errors.append("candidate change categories are outside the closed maintenance policy")
    errors.extend(
        _package_matrix_scope_errors(
            release_class,
            package_keys,
            required_keys,
            change_scope,
            policy,
        )
    )
    if change_scope.get("unrelatedFeatureChanges") != []:
        errors.append("candidate change-scope audit found unrelated feature work")
    checksums, checksum_errors = _checksum_rows(checksums_path)
    errors.extend(checksum_errors)
    expected_checksums = {name: file_digest(path) for name, path in asset_paths.items()}
    if checksums != expected_checksums:
        errors.append("candidate checksum file does not bind the exact asset set")
    expected_freeze_assets = [
        {
            "role": "product",
            "fileName": product_path.name,
            "digest": product_digest,
            "sizeBytes": product_path.stat().st_size,
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
            "fileName": catalog_path.name,
            "digest": file_digest(catalog_path),
            "sizeBytes": catalog_path.stat().st_size,
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
            "fileName": catalog_signature_path.name,
            "digest": file_digest(catalog_signature_path),
            "sizeBytes": catalog_signature_path.stat().st_size,
            "packageKey": None,
            "os": None,
            "arch": None,
            "producerArchitecture": None,
            "packageType": None,
            "publicAsset": True,
            "signingStatus": "pass",
            "notarizationStatus": "not-applicable",
        },
        *[
            {
                "role": "package",
                "fileName": row.get("fileName"),
                "digest": file_digest(asset_paths[str(row.get("fileName"))]),
                "sizeBytes": asset_paths[str(row.get("fileName"))].stat().st_size,
                "packageKey": row.get("packageKey"),
                "os": row.get("os"),
                "arch": row.get("arch"),
                "producerArchitecture": row.get("producerArchitecture"),
                "packageType": row.get("packageType"),
                "publicAsset": True,
                "signingStatus": row.get("signingStatus"),
                "notarizationStatus": row.get("notarizationStatus"),
            }
            for row in assets
        ],
    ]
    expected_freeze_predecessor = freeze_predecessor_observation or {
        "sourceCommit": predecessor.source_commit,
        "releaseId": predecessor.release_id,
        "buildVersion": predecessor.build_version,
        "productDigest": predecessor.product_digest,
        "baselineDigest": predecessor.baseline_digest,
        "publicationReceiptDigest": predecessor.receipt_digest,
        "latestPublishedPointerDigest": predecessor.latest_pointer_digest,
    }
    errors.extend(
        _candidate_freeze_errors(
            context,
            freeze,
            value,
            expected_freeze_predecessor,
            expected_freeze_assets,
            file_digest(checksums_path),
        )
    )
    errors.extend(
        _candidate_provenance_errors(
            context,
            provenance.value,
            source,
            product_digest,
            loaded.digest,
            freeze.digest,
            expected_checksums,
        )
    )
    add_blockers(
        state,
        "stable-maintenance.candidate-identity",
        errors,
        "Rebuild and freeze one clean candidate once; do not repair authorized bytes.",
    )
    for warning in value.get("operationalWarnings", []):
        if isinstance(warning, dict):
            warning_id = str(warning.get("warningId", ""))
            state.warnings.append(
                {
                    "id": warning_id,
                    "evidenceId": OPERATIONAL_WARNING_EVIDENCE_IDS.get(
                        warning_id, warning_id
                    ),
                    "severity": "warning",
                    "summary": "A policy-allowlisted noncritical operational warning requires explicit acceptance.",
                    "waivable": True,
                }
            )
    identity = {
        "schemaVersion": 1,
        "kind": "stable-1.0-maintenance-candidate",
        "generatedAt": value.get("generatedAt"),
        "stableMilestone": STABLE_MILESTONE,
        "releaseId": context.manifest.release.release_id,
        "buildVersion": build_version,
        "releaseClass": release_class,
        "source": source,
        "toolchain": toolchain,
        "product": {
            "fileName": product_path.name,
            "sizeBytes": product_path.stat().st_size,
            "digest": product_digest,
        },
        "packages": sorted(assets, key=lambda row: str(row.get("packageKey", ""))),
        "candidateInputDigest": loaded.digest,
        "candidateFreezeDigest": freeze.digest,
        "frozenAt": freeze.value.get("frozenAt"),
        "checksumsDigest": file_digest(checksums_path),
        "provenanceDigest": provenance.digest,
        "platformApiDigest": semantic_digest(value.get("platformApi")),
        "stableCatalogDigest": semantic_digest(value.get("stableCatalog")),
        "firstPartyAppsDigest": semantic_digest(value.get("firstPartyApps")),
        "contentProfilesDigest": semantic_digest(value.get("contentFormatProfiles")),
        "knownLimitationsDigest": semantic_digest(value.get("limitations")),
        "securityDigest": semantic_digest(value.get("security")),
        "supportDigest": semantic_digest(value.get("support")),
        "legacyBoundariesDigest": semantic_digest(value.get("legacyBoundaries")),
        "changeScopeDigest": semantic_digest(value.get("changeScope")),
        "operationalWarningsDigest": semantic_digest(value.get("operationalWarnings", [])),
        "builtOnce": True,
        "rebuildPerformedAfterFreeze": False,
        "redaction": {"status": "pass", "findingCount": 0, "findings": []},
    }
    catalog_authority = value.get("catalogAuthority")
    if isinstance(catalog_authority, dict):
        identity["catalogAuthorityBindingDigest"] = semantic_digest(
            catalog_authority
        )
    identity_digest = semantic_digest(identity)
    return Candidate(
        source,
        value,
        loaded.digest,
        freeze.digest,
        str(freeze.value.get("frozenAt", "")),
        product_path,
        product_digest,
        sorted(assets, key=lambda row: str(row.get("packageKey", ""))),
        asset_paths,
        file_digest(checksums_path),
        provenance.digest,
        identity,
        identity_digest,
    )


def _public_reference(value: Any) -> bool:
    if not isinstance(value, str) or not value or any(ord(ch) < 32 for ch in value):
        return False
    if value.startswith("CHK@"):
        return re.fullmatch(
            r"CHK@[A-Za-z0-9~-]{43},[A-Za-z0-9~-]{43},[A-Za-z0-9~-]{7}"
            r"(?:/[A-Za-z0-9._~/-]+)?",
            value,
        ) is not None
    return (
        is_public_https_uri(value)
        and _has_unambiguous_publication_path(value)
        and "REPLACE" not in value.upper()
        and "\\" not in value
    )


def build_core_info(
    context: RunContext,
    candidate: Candidate,
    state: ValidationState,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Build strict deterministic CoreUpdater descriptor bytes from candidate assets."""

    errors: list[str] = []
    packages: dict[str, dict[str, Any]] = {}
    for row in candidate.assets:
        key = row.get("packageKey")
        direct = row.get("publicChk")
        store = row.get("storeUrl")
        if not isinstance(key, str) or re.fullmatch(r"(?:amd64|arm64)\.(?:deb|rpm|dmg|exe|flatpak|snap)", key) is None:
            errors.append("CoreUpdater package key is not an AppEnv-compatible selector")
            continue
        if key in packages:
            errors.append(f"CoreUpdater descriptor duplicates package key {key}")
            continue
        if direct is not None and store is not None:
            errors.append(f"CoreUpdater package {key} has ambiguous CHK and store references")
            continue
        if direct is not None:
            if not _public_reference(direct):
                errors.append(f"CoreUpdater package {key} has an unsafe CHK")
                continue
            spec = {"chk": direct, "size": row.get("sizeBytes")}
        elif store is not None and key.endswith((".flatpak", ".snap")):
            if not _public_reference(store):
                errors.append(f"CoreUpdater package {key} has an unsafe store URL")
                continue
            spec = {"size": row.get("sizeBytes"), "store_url": store}
        else:
            errors.append(f"CoreUpdater package {key} has no authenticated public reference")
            continue
        if type(spec.get("size")) is not int or spec["size"] <= 0:
            errors.append(f"CoreUpdater package {key} has an invalid size")
        packages[key] = spec
    metadata = context.manifest.policies.get("metadata")
    metadata = metadata if isinstance(metadata, dict) else {}
    release_page = metadata.get("githubReleasePageUri")
    expected_release_page = (
        "https://github.com/crypta-network/cryptad/releases/tag/"
        f"v{context.manifest.release.version}"
    )
    if release_page != expected_release_page:
        errors.append("CoreUpdater release page URL is not public-safe")
    descriptor: dict[str, Any] = {
        "version": str(context.manifest.release.version),
        "release_page_url": release_page,
        "packages": {key: packages[key] for key in sorted(packages)},
    }
    changelog = candidate.input_value.get("coreUpdateChangelog")
    changelog = changelog if isinstance(changelog, dict) else {}
    for source, target in (
        ("shortChk", "changelog_chk"),
        ("fullChk", "fullchangelog_chk"),
    ):
        value = changelog.get(source)
        if value is not None:
            if not _public_reference(value) or not str(value).startswith("CHK@"):
                errors.append(f"CoreUpdater {source} is not a public candidate-bound CHK")
            else:
                descriptor[target] = value
    errors.extend(validate_schema(descriptor, CORE_INFO_SCHEMA))
    if set(descriptor) - {
        "version",
        "release_page_url",
        "packages",
        "changelog_chk",
        "fullchangelog_chk",
    }:
        errors.append("CoreUpdater descriptor contains unknown or misleading fields")
    add_blockers(
        state,
        "stable-maintenance.core-update-descriptor",
        errors,
        "Regenerate core-info.json from the exact candidate package map.",
    )
    identity = {
        "schemaVersion": 1,
        "kind": "cryptad-core-info-identity",
        "releaseId": context.manifest.release.release_id,
        "buildVersion": context.manifest.release.version,
        "releaseClass": context.manifest.policies.get("releaseClass"),
        "candidateIdentityDigest": candidate.identity_digest,
        "descriptor": descriptor,
        "packageAssets": [
            {
                "packageKey": row.get("packageKey"),
                "fileName": row.get("fileName"),
                "digest": row.get("digest"),
                "sizeBytes": row.get("sizeBytes"),
            }
            for row in candidate.assets
        ],
    }
    return descriptor, identity


def receipt_identity(receipt: dict[str, Any]) -> str:
    """Public wrapper for the non-circular maintenance receipt identity."""

    return _receipt_identity(receipt)
