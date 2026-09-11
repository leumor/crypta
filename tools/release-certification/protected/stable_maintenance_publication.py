#!/usr/bin/env python3
"""Fail-closed protected publication boundary for Stable 1.0 maintenance releases.

The certification engine deliberately has no public side effects.  This adapter is the only
bridge used by the protected workflow.  Provider-specific operations are supplied through the
``ExternalOperations`` protocol so that all policy and exact-byte behavior is testable offline.

The command-line entry point will not load a provider by default.  A protected runner must expose
``CRYPTAD_STABLE_MAINTENANCE_PUBLICATION_BACKEND`` as ``module.path:factory`` and
``CRYPTAD_STABLE_MAINTENANCE_PUBLICATION_BACKEND_SITE`` as the canonical authenticated wheel site
root.  The adapter excludes checkout and global package paths while importing the provider and
while invoking every provider method.  The factory returns an ``ExternalOperations``
implementation.  Catalog insertion, CoreUpdater insertion, and maintenance-state activation use
distinct opaque ``SecretMaterial`` values. The entry point captures them once and removes their
environment variables before importing or invoking provider code. Public GitHub and artifact-base
targets receive no protected input. Protected values are never rendered, logged, or copied into an
artifact.
"""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import datetime as dt
import hashlib
import importlib
import inspect
import json
import os
from pathlib import Path
import re
import stat
import sys
import sysconfig
import tempfile
from types import ModuleType
from typing import Any, Callable, Iterator, Mapping, Protocol, Sequence
from urllib import parse as urllib_parse
from urllib import request as urllib_request


_RELEASE_CERTIFICATION_ROOT = Path(__file__).resolve().parents[1]
if str(_RELEASE_CERTIFICATION_ROOT) not in sys.path:
    sys.path.insert(0, str(_RELEASE_CERTIFICATION_ROOT))

from cryptad_certification.schema_validation import validate_schema  # noqa: E402


TARGETS = (
    "artifactBase",
    "tag",
    "githubRelease",
    "assets",
    "stableCatalog",
    "coreUpdate",
)
MUTATION_TARGETS = TARGETS
TARGET_STATUSES = frozenset({"absent", "matching", "conflict", "unavailable"})
AUTHORIZATION_SCOPES = (
    "tag:create-or-verify",
    "github-release:create-or-verify",
    "artifact-base:publish-or-verify",
    "stable-catalog:publish-or-verify",
    "core-update:insert-or-verify",
    "successor-baseline:activate",
    "release-history:append",
)
BACKEND_FACTORY_ENV = "CRYPTAD_STABLE_MAINTENANCE_PUBLICATION_BACKEND"
BACKEND_SITE_ENV = "CRYPTAD_STABLE_MAINTENANCE_PUBLICATION_BACKEND_SITE"
GITHUB_TOKEN_ENV = "GITHUB_TOKEN"
SOURCE_REPOSITORY = "crypta-network/cryptad"
CATALOG_INPUT_ENV = "CRYPTAD_STABLE_CATALOG_PUBLICATION_INPUT"
CORE_UPDATE_INPUT_ENV = "CRYPTAD_CORE_UPDATE_PUBLICATION_INPUT"
MAINTENANCE_STATE_INPUT_ENV = "CRYPTAD_STABLE_MAINTENANCE_STATE_INPUT"
PRIVATE_INPUT_ENV = CORE_UPDATE_INPUT_ENV
_CATALOG_PURPOSE = "stable-catalog"
_CORE_UPDATE_PURPOSE = "core-update"
_MAINTENANCE_STATE_PURPOSE = "maintenance-state"
WORKFLOW_PATH = "/.github/workflows/stable-1.0-maintenance-release.yml@"
MAX_JSON_BYTES = 16 * 1024 * 1024
FAILURE_AUDIT_FILE = "stable-1.0-maintenance-publication-failure-audit.json"
FOLLOW_UP_CLOSURE_FILE = "stable-1.0-hotfix-follow-up-closure.json"
BACKPORT_RELEASE_TRAIN_VALIDATION_FILE = (
    "stable-1.0-release-train-validation.json"
)
BACKPORT_RELEASE_TRAIN_VALIDATION_SCHEMA = (
    "stable-1.0-release-train-validation-v1.schema.json"
)
BACKPORT_RELEASE_TRAIN_AUTHORIZATION_FILE = (
    "stable-1.0-release-train-authorization-summary.json"
)
BACKPORT_RELEASE_TRAIN_AUTHORIZATION_SCHEMA = (
    "stable-1.0-release-train-authorization-v1.schema.json"
)
SUPPLY_CHAIN_COMPANION_FILES = {
    "build-materials": "stable-1.0-build-materials.json",
    "component-inventory": "stable-1.0-component-inventory.json",
    "component-reverse-index": "stable-1.0-component-reverse-index.json",
    "license-inventory": "stable-1.0-license-inventory.json",
    "reproducibility-report": "stable-1.0-reproducibility-report.json",
    "release-subject-inventory": "stable-1.0-release-subject-inventory.json",
    "sbom": "stable-1.0-sbom.spdx.json",
    "supply-chain-summary": "stable-1.0-supply-chain-summary.json",
}
SUPPLY_CHAIN_PUBLICATION_BASE = (
    "https://github.com/crypta-network/cryptad/releases/download"
)
UNRESOLVED_FOLLOW_UP_STATUSES = frozenset({"open", "overdue"})
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_BUILD_RE = re.compile(r"^[1-9][0-9]*$")
_COMMIT_RE = re.compile(r"^[0-9a-f]{40,64}$")
_SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_FACTORY_RE = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_.]*:[A-Za-z_][A-Za-z0-9_]*$"
)
_ABSOLUTE_PATH_RE = re.compile(r"^(?:/|[A-Za-z]:[\\/]|\\\\)")
_PASS_REDACTION = {"status": "pass", "findingCount": 0, "findings": []}
_SENSITIVE_KEYS = frozenset(
    {
        "authorizationheader",
        "cookie",
        "identitymaterial",
        "inserturi",
        "localpath",
        "password",
        "privateinserturi",
        "privatekey",
        "rawappdata",
        "rawcontent",
        "token",
    }
)
_ALLOWED_PROTECTED_KEY = "protectedInsertInputName"


class AdapterError(RuntimeError):
    """One safe, non-secret fail-closed adapter error."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclasses.dataclass(frozen=True, repr=False)
class SecretMaterial:
    """Opaque protected material that must never enter public output or diagnostics."""

    purpose: str
    value: str

    def __repr__(self) -> str:
        return "SecretMaterial(<protected>)"

    def __str__(self) -> str:
        return "<protected>"


@dataclasses.dataclass(frozen=True, repr=False)
class PublicationProtectedInputs:
    """Closed least-privilege inputs for the two side-effecting publication targets."""

    stable_catalog: SecretMaterial
    core_update: SecretMaterial

    def __post_init__(self) -> None:
        if self.stable_catalog.purpose != _CATALOG_PURPOSE:
            raise AdapterError("catalog-protected-input-purpose-mismatch")
        if self.core_update.purpose != _CORE_UPDATE_PURPOSE:
            raise AdapterError("core-update-protected-input-purpose-mismatch")

    def for_target(self, target: str) -> SecretMaterial | None:
        if target == "stableCatalog":
            return self.stable_catalog
        if target == "coreUpdate":
            return self.core_update
        if target in {"tag", "githubRelease", "assets", "artifactBase"}:
            return None
        raise AdapterError("unknown-publication-target")


@dataclasses.dataclass(frozen=True)
class PublicSnapshot:
    """One independent public observation used for conflict and idempotency decisions."""

    predecessor_pointer_digest: str | None
    targets: Mapping[str, str]
    latest_candidate_identity_digest: str | None = None


@dataclasses.dataclass(frozen=True)
class PointerSnapshot:
    """Observed latest-baseline pointer state."""

    status: str
    pointer_digest: str | None
    active_baseline_digest: str | None
    candidate_identity_digest: str | None = None


@dataclasses.dataclass(frozen=True)
class VerificationMaterial:
    """Exact public observations returned by an independent provider verifier."""

    maintenance_receipt: Mapping[str, Any]
    core_update_receipt: Mapping[str, Any]
    successor_baseline: Mapping[str, Any]
    history_entry: Mapping[str, Any]


@dataclasses.dataclass(frozen=True)
class PublicationBundle:
    """Authenticated, exact-byte candidate publication inputs."""

    root: Path
    legacy: Path
    plan_path: Path
    plan: Mapping[str, Any]
    candidate_path: Path
    candidate: Mapping[str, Any]
    authorization_path: Path
    authorization: Mapping[str, Any]
    lineage_path: Path
    lineage: Mapping[str, Any]
    core_plan_path: Path
    core_plan: Mapping[str, Any]
    core_info_path: Path
    core_info: Mapping[str, Any]
    candidate_input_path: Path
    candidate_input: Mapping[str, Any]
    candidate_freeze_path: Path
    candidate_freeze: Mapping[str, Any]
    ga_baseline_path: Path
    ga_baseline: Mapping[str, Any]
    predecessor_baseline_path: Path
    predecessor_baseline: Mapping[str, Any]
    evidence_path: Path
    evidence: Mapping[str, Any]
    backport_release_train_validation_path: Path
    backport_release_train_validation: Mapping[str, Any]
    backport_release_train_authorization_path: Path
    backport_release_train_authorization: Mapping[str, Any]
    fingerprint: str
    follow_up_obligation_path: Path | None = None
    follow_up_obligation: Mapping[str, Any] | None = None
    follow_up_closure_path: Path | None = None
    follow_up_closure: Mapping[str, Any] | None = None


@dataclasses.dataclass(frozen=True)
class PublicationRequest:
    """Public, non-secret request passed to an injected provider implementation."""

    bundle: PublicationBundle

    @property
    def release_id(self) -> str:
        return str(self.bundle.plan["releaseId"])

    @property
    def build_version(self) -> str:
        return str(self.bundle.plan["buildVersion"])

    @property
    def release_class(self) -> str:
        return str(self.bundle.plan["releaseClass"])

    @property
    def candidate_identity_digest(self) -> str:
        return str(self.bundle.plan["candidateIdentityDigest"])


@dataclasses.dataclass(frozen=True)
class ActivationRequest:
    """Exact verified records authorized for compare-and-swap activation."""

    successor_path: Path
    successor: Mapping[str, Any]
    history_path: Path
    history: Mapping[str, Any]
    receipt_path: Path
    receipt: Mapping[str, Any]
    authorization_path: Path
    authorization: Mapping[str, Any]
    authorization_digest: str
    activation_authorization_path: Path
    activation_authorization: Mapping[str, Any]
    activation_authorization_digest: str
    expected_pointer_digest: str
    successor_digest: str
    history_digest: str
    receipt_digest: str
    activated_pointer: Mapping[str, Any]
    activated_pointer_bytes: bytes
    activated_pointer_digest: str


class ExternalOperations(Protocol):
    """Closed provider boundary; no branch or merge operation exists in this interface."""

    def observe_public_state(self, request: PublicationRequest) -> PublicSnapshot:
        """Fetch current public tag, release, assets, catalog, updater, and predecessor state."""

    def publish_target(
        self,
        target: str,
        request: PublicationRequest,
        protected_input: SecretMaterial | None,
    ) -> None:
        """Create one exact target or verify an exact concurrent creation."""

    def verify_publication(self, request: PublicationRequest) -> VerificationMaterial:
        """Independently fetch exact public state and return public-safe receipts and lineage."""

    def observe_latest_pointer(self, request: ActivationRequest) -> PointerSnapshot:
        """Fetch the latest published maintenance pointer without mutation."""

    def activate_latest(
        self, request: ActivationRequest, protected_input: SecretMaterial
    ) -> None:
        """Compare-and-swap the latest pointer to ``request.activated_pointer_bytes``."""


@dataclasses.dataclass(frozen=True)
class PreflightOutcome:
    artifact: Mapping[str, Any]
    snapshot: PublicSnapshot
    passed: bool


@dataclasses.dataclass(frozen=True)
class CommandOutcome:
    passed: bool
    artifacts: Mapping[Path, Mapping[str, Any]]


def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


def _timestamp(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def _parse_timestamp(value: Any) -> dt.datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(dt.timezone.utc)


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n"


def _semantic_digest(value: Any) -> str:
    encoded = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise AdapterError("unsafe-or-missing-exact-file") from exc
    return "sha256:" + digest.hexdigest()


def _strict_json_bytes(data: bytes, source_code: str) -> Any:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise AdapterError("duplicate-json-field")
            result[key] = value
        return result

    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=reject_duplicates)
    except AdapterError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AdapterError(source_code) from exc


def _regular_file(path: Path) -> None:
    try:
        mode = path.stat(follow_symlinks=False).st_mode
    except OSError as exc:
        raise AdapterError("unsafe-or-missing-exact-file") from exc
    if path.is_symlink() or not stat.S_ISREG(mode):
        raise AdapterError("unsafe-or-missing-exact-file")


def _read_json(path: Path, *, canonical: bool = True) -> dict[str, Any]:
    _regular_file(path)
    try:
        size = path.stat(follow_symlinks=False).st_size
        if size <= 0 or size > MAX_JSON_BYTES:
            raise AdapterError("json-size-outside-policy")
        data = path.read_bytes()
    except OSError as exc:
        raise AdapterError("unsafe-or-missing-json") from exc
    value = _strict_json_bytes(data, "malformed-json")
    if not isinstance(value, dict):
        raise AdapterError("json-root-is-not-object")
    if canonical and data != _canonical_bytes(value):
        raise AdapterError("noncanonical-json-bytes")
    _scan_public_value(value)
    return value


def _scan_public_value(value: Any, *, key: str | None = None, secret: str | None = None) -> None:
    if key is not None:
        normalized = re.sub(r"[^a-z0-9]", "", key.lower())
        if normalized in _SENSITIVE_KEYS and key != _ALLOWED_PROTECTED_KEY:
            raise AdapterError("public-artifact-sensitive-field")
    if isinstance(value, Mapping):
        for child_key, child in value.items():
            if not isinstance(child_key, str):
                raise AdapterError("public-artifact-nonstring-field")
            _scan_public_value(child, key=child_key, secret=secret)
        return
    if isinstance(value, list):
        for child in value:
            _scan_public_value(child, secret=secret)
        return
    if not isinstance(value, str):
        return
    if any(ord(character) < 32 and character not in "\n\t" for character in value):
        raise AdapterError("public-artifact-control-character")
    lowered = value.lower()
    if secret and secret in value:
        raise AdapterError("protected-input-leak")
    if "file://" in lowered or "authorization: bearer " in lowered:
        raise AdapterError("public-artifact-private-reference")
    if ("usk@" in lowered or "ssk@" in lowered) and "insert" in lowered:
        raise AdapterError("public-artifact-private-insert-uri")
    if _ABSOLUTE_PATH_RE.match(value) and key not in {"route", "endpoint"}:
        raise AdapterError("public-artifact-absolute-path")


def _validate_schema(value: Mapping[str, Any], schema: str) -> None:
    if validate_schema(dict(value), schema):
        raise AdapterError("artifact-schema-validation-failed")


def _validate_supply_chain_companion_assets(
    root: Path, plan: Mapping[str, Any]
) -> None:
    """Authenticate the optional prospective PR-289 GitHub Release asset suffix."""

    rows = plan.get("supplyChainCompanionAssets")
    if rows is None:
        return
    if not isinstance(rows, list):
        raise AdapterError("supply-chain-companion-assets-invalid")
    release_id = plan.get("releaseId")
    build = plan.get("buildVersion")
    source_commit = plan.get("sourceCommit")
    summary_path = (
        root
        / "protected-inputs"
        / "supply-chain"
        / SUPPLY_CHAIN_COMPANION_FILES["supply-chain-summary"]
    )
    summary = _read_json(summary_path)
    _validate_schema(summary, "stable-1.0-supply-chain-promotion-summary-v1.schema.json")
    summary_payload = {
        key: value for key, value in summary.items() if key != "summaryDigest"
    }
    if (
        summary.get("summaryDigest") != _semantic_digest(summary_payload)
        or summary.get("releaseId") != release_id
        or summary.get("buildVersion") != int(str(build))
        or summary.get("sourceCommit") != source_commit
        or summary.get("mode") != "evaluate-promotion"
        or summary.get("status") != "pass"
        or summary.get("promotionReady") is not True
        or summary.get("blockers") != []
        or summary.get("waivers") != []
    ):
        raise AdapterError("supply-chain-companion-summary-binding-mismatch")
    artifacts = summary.get("artifacts")
    artifacts = artifacts if isinstance(artifacts, list) else []
    artifacts_by_name = {
        row.get("name"): row for row in artifacts if isinstance(row, Mapping)
    }
    if len(artifacts_by_name) != len(artifacts):
        raise AdapterError("supply-chain-companion-summary-artifacts-invalid")
    expected_rows: list[dict[str, Any]] = []
    for role, file_name in SUPPLY_CHAIN_COMPANION_FILES.items():
        if role == "supply-chain-summary":
            digest = _file_digest(summary_path)
            size = summary_path.stat().st_size
        else:
            artifact = artifacts_by_name.get(role)
            if not isinstance(artifact, Mapping):
                raise AdapterError("supply-chain-companion-summary-artifacts-invalid")
            digest = artifact.get("digest")
            size = artifact.get("size")
        expected_rows.append(
            {
                "role": role,
                "fileName": file_name,
                "digest": digest,
                "sizeBytes": size,
                "publicUri": (
                    f"{SUPPLY_CHAIN_PUBLICATION_BASE}/v{build}/{file_name}"
                ),
            }
        )
    maintenance_names = {
        row.get("fileName")
        for row in plan.get("assets", [])
        if isinstance(row, Mapping)
    }
    if rows != expected_rows or maintenance_names.intersection(
        row["fileName"] for row in expected_rows
    ):
        raise AdapterError("supply-chain-companion-assets-binding-mismatch")


def _safe_tree(root: Path) -> None:
    try:
        root_mode = root.stat(follow_symlinks=False).st_mode
    except OSError as exc:
        raise AdapterError("unsafe-bundle-root") from exc
    if root.is_symlink() or not stat.S_ISDIR(root_mode):
        raise AdapterError("unsafe-bundle-root")
    for current, directories, files in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        for name in [*directories, *files]:
            entry = current_path / name
            try:
                mode = entry.stat(follow_symlinks=False).st_mode
            except OSError as exc:
                raise AdapterError("unsafe-bundle-entry") from exc
            if entry.is_symlink() or not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
                raise AdapterError("unsafe-bundle-entry")


def _legacy_root(root: Path) -> Path:
    direct = root
    nested = root / "component" / "artifacts" / "legacy"
    matches = [
        candidate
        for candidate in (direct, nested)
        if (candidate / "stable-1.0-maintenance-publication-plan.json").is_file()
    ]
    if len(matches) != 1:
        raise AdapterError("ambiguous-or-missing-publication-bundle")
    return matches[0]


def _plan_asset_paths(legacy: Path, plan: Mapping[str, Any]) -> dict[str, Path]:
    result: dict[str, Path] = {}
    rows = plan.get("assets")
    if not isinstance(rows, list) or not rows:
        raise AdapterError("publication-plan-assets-missing")
    for row in rows:
        if not isinstance(row, Mapping):
            raise AdapterError("publication-plan-asset-malformed")
        name = row.get("fileName")
        if not isinstance(name, str) or not _SAFE_NAME_RE.fullmatch(name):
            raise AdapterError("publication-plan-asset-name-unsafe")
        if name in result:
            raise AdapterError("publication-plan-asset-duplicate")
        path = legacy / name
        _regular_file(path)
        if path.parent != legacy:
            raise AdapterError("publication-plan-asset-escape")
        if row.get("digest") != _file_digest(path) or row.get("sizeBytes") != path.stat().st_size:
            raise AdapterError("publication-plan-asset-byte-mismatch")
        result[name] = path
    return result


def _load_follow_up_closure(
    authenticated_inputs: Path,
    lineage: Mapping[str, Any],
    predecessor_baseline: Mapping[str, Any],
    predecessor_baseline_path: Path,
) -> tuple[Path | None, Mapping[str, Any] | None]:
    """Load and authenticate the optional predecessor follow-up closure overlay."""

    predecessor_lineage = lineage.get("predecessor")
    predecessor_lineage = (
        predecessor_lineage if isinstance(predecessor_lineage, Mapping) else {}
    )
    expected_digest = predecessor_lineage.get("hotfixFollowUpClosureDigest")
    closure_path = authenticated_inputs / FOLLOW_UP_CLOSURE_FILE
    if expected_digest is None:
        if closure_path.exists():
            raise AdapterError("unexpected-hotfix-follow-up-closure")
        return None, None
    if not isinstance(expected_digest, str) or not _DIGEST_RE.fullmatch(expected_digest):
        raise AdapterError("hotfix-follow-up-closure-digest-malformed")
    _regular_file(closure_path)
    if _file_digest(closure_path) != expected_digest:
        raise AdapterError("hotfix-follow-up-closure-digest-mismatch")
    closure = _read_json(closure_path)
    _validate_schema(closure, "stable-1.0-hotfix-follow-up-closure-v1.schema.json")

    outstanding = predecessor_baseline.get("hotfixFollowUp")
    publication = predecessor_baseline.get("publication")
    outstanding = outstanding if isinstance(outstanding, Mapping) else {}
    publication = publication if isinstance(publication, Mapping) else {}
    predecessor_digest = _file_digest(predecessor_baseline_path)
    if (
        outstanding.get("status") not in UNRESOLVED_FOLLOW_UP_STATUSES
        or closure.get("status") != "closed"
        or closure.get("releaseClass") != "security-hotfix"
        or closure.get("releaseId") != outstanding.get("obligatedReleaseId")
        or closure.get("buildVersion") != outstanding.get("obligatedBuildVersion")
        or closure.get("productDigest") != outstanding.get("obligatedProductDigest")
        or closure.get("candidateIdentityDigest")
        != outstanding.get("obligatedCandidateIdentityDigest")
        or closure.get("predecessorBuild")
        != outstanding.get("obligatedPredecessorBuild")
        or closure.get("predecessorProductDigest")
        != outstanding.get("obligatedPredecessorProductDigest")
        or closure.get("authorizationDigest") != outstanding.get("authorizationDigest")
        or closure.get("obligationDigest") != outstanding.get("obligationDigest")
        or closure.get("successorBaselineDigest") != predecessor_digest
        or predecessor_lineage.get("successorBaselineDigest") != predecessor_digest
        or closure.get("publicationReceiptDigest")
        != predecessor_lineage.get("publicationReceiptDigest")
        or closure.get("publicationReceiptIdentityDigest")
        != publication.get("receiptIdentityDigest")
        or closure.get("latestPublishedPointerDigest")
        != lineage.get("latestPublishedPointerDigest")
    ):
        raise AdapterError("hotfix-follow-up-closure-binding-mismatch")
    return closure_path, closure


def _validate_backport_release_train(
    value: Mapping[str, Any],
    full_authorization: Mapping[str, Any],
    *,
    plan: Mapping[str, Any],
    lineage: Mapping[str, Any],
    candidate_scope: Mapping[str, Any],
    handoff_at: dt.datetime | None,
    now: dt.datetime,
) -> None:
    """Authenticate one train at its frozen maintenance handoff and current evidence time."""

    _validate_schema(value, BACKPORT_RELEASE_TRAIN_VALIDATION_SCHEMA)
    _validate_schema(
        full_authorization, BACKPORT_RELEASE_TRAIN_AUTHORIZATION_SCHEMA
    )
    release_value = value.get("release")
    release = release_value if isinstance(release_value, Mapping) else {}
    authorization_summary_value = value.get("authorization")
    authorization_summary = (
        authorization_summary_value
        if isinstance(authorization_summary_value, Mapping)
        else {}
    )
    predecessor_value = lineage.get("predecessor")
    predecessor = (
        predecessor_value if isinstance(predecessor_value, Mapping) else {}
    )
    expected_lane = (
        "routine-maintenance"
        if plan.get("releaseClass") == "maintenance"
        else "security-hotfix"
    )
    expected_identity = _semantic_digest(
        {key: item for key, item in value.items() if key != "validationDigest"}
    )
    required_fix_ids = value.get("requiredFixIds")
    included_fix_ids = value.get("includedFixIds")
    deferred_fix_ids = value.get("deferredFixIds")
    public_fix_ids = [
        row.get("fixId")
        for row in value.get("publicFixes", [])
        if isinstance(row, Mapping)
    ]
    evidence_results = value.get("evidenceResults")
    evidence_subjects = [
        (str(row.get("fixId")), str(row.get("evidenceId")))
        for row in (evidence_results if isinstance(evidence_results, list) else [])
        if isinstance(row, Mapping)
    ]
    policy_path = (
        _RELEASE_CERTIFICATION_ROOT
        / "stable-1.0-backport-release-train-policy.json"
    )
    try:
        _regular_file(policy_path)
        policy_bytes = policy_path.read_bytes()
        if not policy_bytes or len(policy_bytes) > MAX_JSON_BYTES:
            raise AdapterError("backport-release-train-policy-size-invalid")
        policy = _strict_json_bytes(
            policy_bytes, "backport-release-train-policy-malformed"
        )
        if not isinstance(policy, dict):
            raise AdapterError("backport-release-train-policy-malformed")
        classification_policy = policy.get("classificationEligibility", {})
        authorization_policy = policy.get("authorization", {})
        evidence_policy = policy.get("evidencePolicy", {})
        if (
            not isinstance(classification_policy, Mapping)
            or not isinstance(authorization_policy, Mapping)
            or not isinstance(evidence_policy, Mapping)
        ):
            raise AdapterError("backport-release-train-policy-malformed")
        routine_maximum_age_days = evidence_policy.get("routineMaximumAgeDays")
        hotfix_maximum_age_hours = evidence_policy.get(
            "securityHotfixMaximumAgeHours"
        )
        if (
            type(routine_maximum_age_days) is not int
            or routine_maximum_age_days < 1
            or type(hotfix_maximum_age_hours) is not int
            or hotfix_maximum_age_hours < 1
        ):
            raise AdapterError("backport-release-train-policy-malformed")
        exact_policy_digest = _file_digest(policy_path)
    except (AdapterError, OSError, ValueError):
        raise AdapterError("backport-release-train-policy-unavailable") from None
    public_projection_valid = True
    eligible_for_lane = True
    security_projection_valid = True
    has_security_fix = False
    critical_hotfix_fix_set_valid = True
    for public_fix in value.get("publicFixes", []):
        if not isinstance(public_fix, Mapping):
            public_projection_valid = False
            continue
        classification = public_fix.get("classification")
        if public_fix.get("publicProjectionDigest") != _semantic_digest(
            {
                "fixId": public_fix.get("fixId"),
                "classification": classification,
                "publicSummary": public_fix.get("publicSummary"),
            }
        ):
            public_projection_valid = False
        eligibility = (
            classification_policy.get(classification, {})
            if isinstance(classification_policy, Mapping)
            else {}
        )
        if expected_lane not in eligibility.get("allowedLanes", []):
            eligible_for_lane = False
        security_fields = (
            public_fix.get("incidentOpaqueId"),
            public_fix.get("advisoryOpaqueId"),
            public_fix.get("publicSecuritySummary"),
            public_fix.get("securityPublicProjectionDigest"),
            public_fix.get("disclosureState"),
        )
        if classification == "security-fix":
            has_security_fix = True
            if (
                expected_lane == "security-hotfix"
                and public_fix.get("severity") != "critical"
            ):
                critical_hotfix_fix_set_valid = False
            if (
                not public_fix.get("incidentOpaqueId")
                or public_fix.get("securityPublicProjectionDigest")
                != _semantic_digest(
                    {
                        "fixId": public_fix.get("fixId"),
                        "incidentOpaqueId": public_fix.get("incidentOpaqueId"),
                        "advisoryOpaqueId": public_fix.get("advisoryOpaqueId"),
                        "severity": public_fix.get("severity"),
                        "disclosureState": public_fix.get("disclosureState"),
                        "publicSafeSummary": public_fix.get(
                            "publicSecuritySummary"
                        ),
                    }
                )
                or (
                    public_fix.get("severity") == "critical"
                    and expected_lane != "security-hotfix"
                )
            ):
                security_projection_valid = False
        elif any(field is not None for field in security_fields):
            security_projection_valid = False
    expected_role = (
        authorization_policy.get("routineRole")
        if expected_lane == "routine-maintenance"
        else authorization_policy.get("securityHotfixRole")
    )
    expected_scopes = authorization_policy.get("candidateHandoffScopes")
    maximum_validity_hours = authorization_policy.get("maximumValidityHours")
    prepare_validation = dict(value)
    prepare_validation["mode"] = "prepare-candidate"
    prepare_validation["authorization"] = None
    prepare_validation.pop("validationDigest", None)
    prepare_validation_digest = _semantic_digest(prepare_validation)
    public_fixes = value.get("publicFixes")
    public_fixes = public_fixes if isinstance(public_fixes, list) else []
    expected_security_ids = sorted(
        {
            str(row["incidentOpaqueId"])
            for row in public_fixes
            if isinstance(row, Mapping)
            and isinstance(row.get("incidentOpaqueId"), str)
        }
    )
    expected_candidate_security_ids = sorted(
        {
            str(row.get("advisoryOpaqueId") or row["incidentOpaqueId"])
            for row in public_fixes
            if isinstance(row, Mapping)
            and isinstance(row.get("incidentOpaqueId"), str)
        }
    )
    incident_scope_rows = [
        row
        for row in (
            evidence_results if isinstance(evidence_results, list) else []
        )
        if isinstance(row, Mapping)
        and row.get("evidenceId") == "stable-backport.security-incident-scope"
    ]
    security_fix_ids = sorted(
        str(row["fixId"])
        for row in public_fixes
        if isinstance(row, Mapping)
        and row.get("classification") == "security-fix"
        and isinstance(row.get("fixId"), str)
    )
    candidate_security_scope_valid = expected_lane != "security-hotfix" or (
        expected_candidate_security_ids == [candidate_scope.get("incidentId")]
        and candidate_scope.get("severity") == "critical"
        and sorted(str(row.get("fixId")) for row in incident_scope_rows)
        == security_fix_ids
        and all(
            row.get("evidenceDigest")
            == candidate_scope.get("hotfixPolicyAuthorizationDigest")
            for row in incident_scope_rows
        )
    )
    expected_authorization = {
        "stableMilestone": "1.0",
        "trainId": value.get("trainId"),
        "release": value.get("release"),
        "repositoryIdentity": "github.com/crypta-network/cryptad",
        "workflowIdentity": (
            "github.com/crypta-network/cryptad/.github/workflows/"
            "stable-1.0-backport-release-train.yml@"
            f"{plan.get('sourceCommit')}"
        ),
        "policyDigest": value.get("policyDigest"),
        "queueDigest": value.get("queueDigest"),
        "planDigest": value.get("planDigest"),
        "validationDigest": prepare_validation_digest,
        "predecessorCommit": value.get("predecessorCommit"),
        "candidateCommit": value.get("candidateCommit"),
        "acceptedFixes": public_fixes,
        "securityOpaqueIds": expected_security_ids,
        "allowedOperation": "candidate-handoff",
        "role": expected_role,
        "scope": expected_scopes,
        "decision": "go",
        "redaction": _PASS_REDACTION,
    }
    issued_at = _parse_timestamp(full_authorization.get("issuedAt"))
    expires_at = _parse_timestamp(full_authorization.get("expiresAt"))
    generated_at = _parse_timestamp(value.get("generatedAt"))
    now_utc = now.astimezone(dt.timezone.utc)
    handoff_utc = (
        handoff_at.astimezone(dt.timezone.utc) if handoff_at is not None else None
    )
    maximum_age = (
        dt.timedelta(days=routine_maximum_age_days)
        if expected_lane == "routine-maintenance"
        else dt.timedelta(hours=hotfix_maximum_age_hours)
    )
    evidence_freshness_valid = True
    for evidence_result in (
        evidence_results if isinstance(evidence_results, list) else []
    ):
        if not isinstance(evidence_result, Mapping):
            evidence_freshness_valid = False
            continue
        evidence_generated_at = _parse_timestamp(
            evidence_result.get("generatedAt")
        )
        evidence_expires_at = _parse_timestamp(evidence_result.get("expiresAt"))
        evidence_deadline_at = _parse_timestamp(
            evidence_result.get("freshnessDeadlineAt")
        )
        if (
            evidence_generated_at is None
            or evidence_expires_at is None
            or evidence_deadline_at is None
            or evidence_generated_at > now_utc
            or evidence_expires_at <= evidence_generated_at
            or evidence_deadline_at
            != min(
                evidence_expires_at,
                evidence_generated_at + maximum_age,
            )
            or evidence_deadline_at < now_utc
            or evidence_result.get("generatedAt")
            != _timestamp(evidence_generated_at)
            or evidence_result.get("expiresAt")
            != _timestamp(evidence_expires_at)
            or evidence_result.get("freshnessDeadlineAt")
            != _timestamp(evidence_deadline_at)
        ):
            evidence_freshness_valid = False
    authorization_digest = full_authorization.get("authorizationDigest")
    expected_authorization_digest = _semantic_digest(
        {
            key: item
            for key, item in full_authorization.items()
            if key != "authorizationDigest"
        }
    )
    expected_authorization_summary = {
        "authorizationDigest": authorization_digest,
        "status": "valid",
        "expiresAt": full_authorization.get("expiresAt"),
        "role": full_authorization.get("role"),
    }
    if (
        value.get("kind") != "stable-1.0-release-train-validation"
        or value.get("mode") != "validate-authorization"
        or value.get("hotfixFollowUpClosureDigest")
        != predecessor.get("hotfixFollowUpClosureDigest")
        or release.get("releaseId") != plan.get("releaseId")
        or release.get("buildVersion") != plan.get("buildVersion")
        or release.get("releaseClass") != plan.get("releaseClass")
        or release.get("tag") != plan.get("expectedTag")
        or value.get("candidateCommit") != plan.get("sourceCommit")
        or not _DIGEST_RE.fullmatch(str(value.get("candidateDigest", "")))
        or value.get("predecessorCommit") != predecessor.get("sourceCommit")
        or not isinstance(required_fix_ids, list)
        or not required_fix_ids
        or required_fix_ids != sorted(required_fix_ids)
        or len(required_fix_ids) != len(set(required_fix_ids))
        or required_fix_ids != included_fix_ids
        or not isinstance(deferred_fix_ids, list)
        or deferred_fix_ids != sorted(set(deferred_fix_ids))
        or public_fix_ids != included_fix_ids
        or not public_projection_valid
        or not eligible_for_lane
        or not security_projection_valid
        or (expected_lane == "security-hotfix" and not has_security_fix)
        or (
            expected_lane == "security-hotfix"
            and not critical_hotfix_fix_set_valid
        )
        or not candidate_security_scope_valid
        or not isinstance(evidence_results, list)
        or not evidence_results
        or len(evidence_subjects) != len(evidence_results)
        or evidence_subjects != sorted(evidence_subjects)
        or len(evidence_subjects) != len(set(evidence_subjects))
        or {subject[0] for subject in evidence_subjects}
        != set(included_fix_ids)
        or any(
            not isinstance(row, Mapping)
            or row.get("status") != "pass"
            or row.get("candidateBound") is not True
            or row.get("predecessorBound") is not True
            or row.get("fresh") is not True
            for row in evidence_results
        )
        or not evidence_freshness_valid
        or value.get("decision") != "go"
        or value.get("authorizationRequired") is not True
        or value.get("blockers") != []
        or value.get("omittedFixIds") != []
        or value.get("unaccountedCommitIds") != []
        or value.get("validationDigest") != expected_identity
        or value.get("policyDigest") != exact_policy_digest
        or not isinstance(expected_role, str)
        or not isinstance(expected_scopes, list)
        or type(maximum_validity_hours) is not int
        or maximum_validity_hours < 1
        or any(
            full_authorization.get(field) != expected
            for field, expected in expected_authorization.items()
        )
        or not _DIGEST_RE.fullmatch(str(authorization_digest))
        or authorization_digest != expected_authorization_digest
        or authorization_summary != expected_authorization_summary
        or generated_at is None
        or generated_at > now_utc
        or generated_at < now_utc - maximum_age
        or issued_at is None
        or expires_at is None
        or handoff_utc is None
        or handoff_utc > now_utc
        or issued_at > handoff_utc
        or expires_at <= handoff_utc
        or expires_at <= issued_at
        or expires_at - issued_at
        > dt.timedelta(hours=maximum_validity_hours)
        or any(item == "*" for item in full_authorization.values())
        or value.get("redaction") != _PASS_REDACTION
    ):
        raise AdapterError("backport-release-train-binding-mismatch")


def _load_bundle(root: Path) -> PublicationBundle:
    _safe_tree(root)
    legacy = _legacy_root(root)
    authenticated_inputs = root / "authenticated-inputs"
    if authenticated_inputs.is_symlink() or not authenticated_inputs.is_dir():
        raise AdapterError("authenticated-public-inputs-missing")
    candidate_input_path = authenticated_inputs / "maintenance-candidate-input.json"
    candidate_freeze_path = authenticated_inputs / "maintenance-candidate-freeze.json"
    ga_baseline_path = authenticated_inputs / "stable-ga-maintenance-baseline.json"
    predecessor_baseline_path = authenticated_inputs / "predecessor-maintenance-baseline.json"
    evidence_path = authenticated_inputs / "maintenance-evidence.json"
    backport_release_train_validation_path = (
        authenticated_inputs / BACKPORT_RELEASE_TRAIN_VALIDATION_FILE
    )
    backport_release_train_authorization_path = (
        authenticated_inputs / BACKPORT_RELEASE_TRAIN_AUTHORIZATION_FILE
    )
    plan_path = legacy / "stable-1.0-maintenance-publication-plan.json"
    candidate_path = legacy / "stable-1.0-maintenance-candidate.json"
    authorization_path = legacy / "stable-1.0-maintenance-authorization-summary.json"
    lineage_path = legacy / "stable-1.0-maintenance-lineage.json"
    core_plan_path = legacy / "core-update-publication-plan.json"
    core_info_path = legacy / "core-info.json"
    provenance_path = legacy / "stable-1.0-maintenance-provenance.json"
    comparison_path = legacy / "stable-1.0-maintenance-comparison.json"
    checksums_path = legacy / "stable-1.0-maintenance-checksums.txt"
    notes_path = legacy / "stable-1.0-maintenance-release-notes.md"
    for path in (provenance_path, comparison_path, checksums_path, notes_path):
        _regular_file(path)

    plan = _read_json(plan_path)
    candidate = _read_json(candidate_path)
    authorization = _read_json(authorization_path)
    lineage = _read_json(lineage_path)
    core_plan = _read_json(core_plan_path)
    core_info = _read_json(core_info_path)
    provenance = _read_json(provenance_path)
    candidate_input = _read_json(candidate_input_path)
    candidate_freeze = _read_json(candidate_freeze_path)
    ga_baseline = _read_json(ga_baseline_path)
    predecessor_baseline = _read_json(predecessor_baseline_path)
    evidence = _read_json(evidence_path)
    backport_release_train_validation = _read_json(
        backport_release_train_validation_path
    )
    backport_release_train_authorization = _read_json(
        backport_release_train_authorization_path
    )
    _validate_schema(plan, "stable-1.0-maintenance-publication-plan-v1.schema.json")
    _validate_supply_chain_companion_assets(root, plan)
    _validate_schema(authorization, "stable-1.0-maintenance-authorization-v1.schema.json")
    _validate_schema(lineage, "stable-1.0-maintenance-lineage-v1.schema.json")
    _validate_schema(core_plan, "cryptad-core-update-publication-plan-v1.schema.json")
    _validate_schema(core_info, "cryptad-core-info-v1.schema.json")
    _validate_schema(
        candidate_freeze, "stable-1.0-maintenance-candidate-freeze.schema.json"
    )
    follow_up_closure_path, follow_up_closure = _load_follow_up_closure(
        authenticated_inputs,
        lineage,
        predecessor_baseline,
        predecessor_baseline_path,
    )

    release_id = plan.get("releaseId")
    build = plan.get("buildVersion")
    release_class = plan.get("releaseClass")
    source_commit = plan.get("sourceCommit")
    candidate_digest = _semantic_digest(candidate)
    source = candidate.get("source") if isinstance(candidate.get("source"), Mapping) else {}
    product = candidate.get("product") if isinstance(candidate.get("product"), Mapping) else {}
    plan_governance_active = plan.get(
        "dependencyVulnerabilityGovernanceActive", False
    )
    authorization_governance_active = authorization.get(
        "dependencyVulnerabilityGovernanceActive", False
    )
    if (
        plan.get("publicationState") != "publication-authorized"
        or plan.get("sideEffectsPerformed") is not False
        or not isinstance(release_id, str)
        or not _SAFE_NAME_RE.fullmatch(release_id)
        or not isinstance(build, str)
        or not _BUILD_RE.fullmatch(build)
        or release_class not in {"maintenance", "security-hotfix"}
        or not isinstance(source_commit, str)
        or not _COMMIT_RE.fullmatch(source_commit)
        or plan.get("expectedTag") != f"v{build}"
        or candidate.get("releaseId") != release_id
        or candidate.get("buildVersion") != build
        or candidate.get("releaseClass") != release_class
        or source.get("commit") != source_commit
        or source.get("branch") != plan.get("sourceBranch")
        or candidate_digest != plan.get("candidateIdentityDigest")
        or product.get("digest") != plan.get("productDigest")
        or candidate.get("builtOnce") is not True
        or candidate.get("rebuildPerformedAfterFreeze") is not False
        or candidate.get("redaction", {}).get("status") != "pass"
        or type(plan_governance_active) is not bool
        or type(authorization_governance_active) is not bool
        or authorization_governance_active != plan_governance_active
    ):
        raise AdapterError("candidate-publication-identity-mismatch")

    candidate_section_digests = {
        "platformApiDigest": "platformApi",
        "stableCatalogDigest": "stableCatalog",
        "firstPartyAppsDigest": "firstPartyApps",
        "contentProfilesDigest": "contentFormatProfiles",
        "knownLimitationsDigest": "limitations",
        "securityDigest": "security",
        "supportDigest": "support",
        "legacyBoundariesDigest": "legacyBoundaries",
    }
    candidate_freeze_digest = _file_digest(candidate_freeze_path)
    if (
        candidate_input.get("releaseId") != release_id
        or candidate_input.get("buildVersion") != build
        or candidate_input.get("releaseClass") != release_class
        or candidate_input.get("source", {}).get("commit") != source_commit
        or candidate.get("candidateInputDigest") != _file_digest(candidate_input_path)
        or candidate.get("candidateFreezeDigest") != candidate_freeze_digest
        or candidate_input.get("candidateFreezeDigest") != candidate_freeze_digest
        or candidate_freeze.get("releaseId") != release_id
        or candidate_freeze.get("buildVersion") != build
        or candidate_freeze.get("releaseClass") != release_class
        or candidate_freeze.get("source") != candidate_input.get("source")
        or candidate_freeze.get("toolchain") != candidate_input.get("toolchain")
        or candidate_freeze.get("frozenAt") != candidate.get("frozenAt")
        or candidate_input.get("product", {}).get("frozenAt")
        != candidate_freeze.get("frozenAt")
        or any(
            candidate.get(digest_field)
            != _semantic_digest(candidate_input.get(section_name))
            for digest_field, section_name in candidate_section_digests.items()
        )
        or candidate_input.get("redaction", {}).get("status") != "pass"
    ):
        raise AdapterError("authenticated-candidate-input-binding-mismatch")

    expected_branch = (
        f"release/{build}" if release_class == "maintenance" else f"hotfix/{build}"
    )
    if plan.get("sourceBranch") != expected_branch:
        raise AdapterError("candidate-branch-class-mismatch")

    predecessor = lineage.get("predecessor", {})
    change_scope_value = candidate_input.get("changeScope")
    change_scope = (
        change_scope_value if isinstance(change_scope_value, Mapping) else {}
    )
    _validate_backport_release_train(
        backport_release_train_validation,
        backport_release_train_authorization,
        plan=plan,
        lineage=lineage,
        candidate_scope=change_scope,
        handoff_at=_parse_timestamp(authorization.get("authorizedAt")),
        now=_utcnow(),
    )
    backport_release_train_digest = _file_digest(
        backport_release_train_validation_path
    )
    expected_predecessor_identity = _semantic_digest(
        {
            "releaseId": predecessor.get("releaseId"),
            "buildVersion": predecessor.get("buildVersion"),
            "sourceCommit": predecessor.get("sourceCommit"),
            "productDigest": predecessor.get("productDigest"),
            "baselineDigest": _file_digest(predecessor_baseline_path),
        }
    )
    warnings = candidate_input.get("operationalWarnings", [])
    expected_warning_ids = sorted(
        row.get("warningId") for row in warnings if isinstance(row, Mapping)
    )
    expected_role = (
        "stable-maintenance-release-manager"
        if release_class == "maintenance"
        else "stable-security-release-manager"
    )
    follow_up_path = legacy / "stable-1.0-hotfix-follow-up-obligation.json"
    if follow_up_path.exists():
        follow_up_obligation_path: Path | None = follow_up_path
        follow_up_obligation: Mapping[str, Any] | None = _read_json(follow_up_path)
        _validate_schema(
            follow_up_obligation,
            "stable-1.0-hotfix-follow-up-obligation-v1.schema.json",
        )
        expected_follow_up_digest = _file_digest(follow_up_path)
    else:
        follow_up_obligation_path = None
        follow_up_obligation = None
        expected_follow_up_digest = None
    if (
        authorization.get("releaseId") != release_id
        or authorization.get("buildVersion") != build
        or authorization.get("releaseClass") != release_class
        or authorization.get("candidateIdentityDigest") != candidate_digest
        or authorization.get("gaBaselineDigest") != _file_digest(ga_baseline_path)
        or authorization.get("predecessorIdentityDigest")
        != expected_predecessor_identity
        or authorization.get("predecessorProductDigest")
        != predecessor.get("productDigest")
        or authorization.get("predecessorPublicationReceiptDigest")
        != predecessor.get("publicationReceiptDigest")
        or authorization.get("candidateFreezeDigest")
        != candidate_freeze_digest
        or authorization.get("productDigest") != plan.get("productDigest")
        or authorization.get("checksumsDigest") != plan.get("checksumsDigest")
        or authorization.get("provenanceDigest") != plan.get("provenanceDigest")
        or authorization.get("comparisonDigest") != _file_digest(comparison_path)
        or authorization.get("evidenceDigest") != _file_digest(evidence_path)
        or authorization.get("coreInfoDigest") != plan.get("coreInfoDigest")
        or authorization.get("stableCatalogDigest") != plan.get("stableCatalogDigest")
        or authorization.get("knownLimitationsDeltaDigest")
        != plan.get("knownLimitationsDeltaDigest")
        or authorization.get("releaseNotesDigest") != plan.get("releaseNotesDigest")
        or authorization.get("publicationTargetsDigest")
        != plan.get("publicationTargetsDigest")
        or authorization.get("backportReleaseTrainDigest")
        != backport_release_train_digest
        or plan.get("backportReleaseTrainDigest")
        != backport_release_train_digest
        or authorization.get("allowedPublicationScopes") != list(AUTHORIZATION_SCOPES)
        or "*" in authorization.get("allowedPublicationScopes", [])
        or authorization.get("acceptedWarningIds") != expected_warning_ids
        or authorization.get("role") != expected_role
        or authorization.get("hotfixIncidentId") != change_scope.get("incidentId")
        or authorization.get("hotfixPolicyAuthorizationDigest")
        != change_scope.get("hotfixPolicyAuthorizationDigest")
        or authorization.get("hotfixShortenedEvidenceIds")
        != sorted(change_scope.get("shortenedEvidenceIds", []))
        or authorization.get("hotfixFollowUpObligationDigest")
        != expected_follow_up_digest
        or authorization.get("decision") not in {"go", "go-with-waivers"}
        or authorization.get("status") != "approved"
        or plan.get("authorizationDigest") != _file_digest(authorization_path)
    ):
        raise AdapterError("authorization-binding-mismatch")

    if (
        lineage.get("candidate", {}).get("releaseId") != release_id
        or lineage.get("candidate", {}).get("buildVersion") != build
        or lineage.get("candidate", {}).get("sourceCommit") != source_commit
        or lineage.get("candidate", {}).get("releaseClass") != release_class
        or lineage.get("status") != "pass"
        or lineage.get("noGap") is not True
        or lineage.get("noFork") is not True
        or not _DIGEST_RE.fullmatch(str(lineage.get("latestPublishedPointerDigest", "")))
    ):
        raise AdapterError("lineage-binding-mismatch")

    descriptor_digest = _file_digest(core_info_path)
    package_map_digest = _semantic_digest(core_info.get("packages"))
    if (
        core_plan.get("releaseId") != release_id
        or core_plan.get("buildVersion") != build
        or core_plan.get("releaseClass") != release_class
        or core_plan.get("candidateIdentityDigest") != candidate_digest
        or core_plan.get("descriptorDigest") != descriptor_digest
        or core_plan.get("descriptorSizeBytes") != core_info_path.stat().st_size
        or core_plan.get("packageMapDigest") != package_map_digest
        or core_plan.get("edition") != int(build)
        or core_plan.get("publicFetchUri") != plan.get("coreUpdateTarget", {}).get("publicUri")
        or core_plan.get("authorizationDigest") != _file_digest(authorization_path)
        or core_plan.get("protectedInsertInputName") != PRIVATE_INPUT_ENV
        or core_plan.get("sideEffectsPerformed") is not False
        or plan.get("coreInfoDigest") != descriptor_digest
        or plan.get("coreUpdateTarget", {}).get("descriptorDigest") != descriptor_digest
    ):
        raise AdapterError("core-update-plan-binding-mismatch")

    if (
        plan.get("checksumsDigest") != _file_digest(checksums_path)
        or plan.get("provenanceDigest") != _file_digest(provenance_path)
        or plan.get("releaseNotesDigest") != _file_digest(notes_path)
        or provenance.get("candidateIdentityDigest") != candidate_digest
        or provenance.get("candidateFreezeDigest") != candidate_freeze_digest
        or provenance.get("candidateProductDigest") != plan.get("productDigest")
        or provenance.get("lineageDigest") != _file_digest(lineage_path)
        or provenance.get("backportReleaseTrainDigest")
        != backport_release_train_digest
        or provenance.get("redaction", {}).get("status") != "pass"
    ):
        raise AdapterError("frozen-provenance-binding-mismatch")

    if (
        _file_digest(ga_baseline_path)
        != lineage.get("gaRoot", {}).get("maintenanceBaselineDigest")
        or _file_digest(predecessor_baseline_path)
        != provenance.get("predecessorBaselineDigest")
        or evidence.get("releaseId") != release_id
        or evidence.get("buildVersion") != build
        or evidence.get("releaseClass") != release_class
        or evidence.get("candidateProductDigest") != plan.get("productDigest")
        or evidence.get("candidateFreezeDigest") != candidate_freeze_digest
        or provenance.get("evidenceDigest") != _file_digest(evidence_path)
        or ga_baseline.get("redaction", {}).get("status") != "pass"
        or predecessor_baseline.get("redaction", {}).get("status") != "pass"
        or evidence.get("redaction", {}).get("status") != "pass"
    ):
        raise AdapterError("authenticated-baseline-or-evidence-binding-mismatch")

    asset_paths = _plan_asset_paths(legacy, plan)
    planned_roles = {
        str(row.get("role")): str(row.get("fileName")) for row in plan.get("assets", [])
    }
    if planned_roles.get("product") != product.get("fileName"):
        raise AdapterError("product-asset-binding-mismatch")
    catalog = candidate_input.get("stableCatalog", {})
    catalog_name = catalog.get("fileName")
    signature_name = catalog.get("signatureFileName")
    catalog_path = asset_paths.get(catalog_name) if isinstance(catalog_name, str) else None
    signature_path = (
        asset_paths.get(signature_name) if isinstance(signature_name, str) else None
    )
    if (
        catalog_path is None
        or signature_path is None
        or planned_roles.get("stable-catalog") != catalog_name
        or planned_roles.get("stable-catalog-signature") != signature_name
        or catalog.get("digest") != _file_digest(catalog_path)
        or catalog.get("sizeBytes") != catalog_path.stat().st_size
        or catalog.get("signatureDigest") != _file_digest(signature_path)
        or catalog.get("signatureSizeBytes") != signature_path.stat().st_size
    ):
        raise AdapterError("stable-catalog-asset-binding-mismatch")
    packages = candidate.get("packages")
    if not isinstance(packages, list) or not packages:
        raise AdapterError("candidate-package-set-missing")
    descriptor_packages = core_info.get("packages")
    if not isinstance(descriptor_packages, Mapping):
        raise AdapterError("core-info-package-map-missing")
    expected_keys: set[str] = set()
    for package in packages:
        if not isinstance(package, Mapping):
            raise AdapterError("candidate-package-malformed")
        key = package.get("packageKey")
        name = package.get("fileName")
        if not isinstance(key, str) or not isinstance(name, str) or name not in asset_paths:
            raise AdapterError("candidate-package-asset-missing")
        expected_keys.add(key)
        descriptor_row = descriptor_packages.get(key)
        if not isinstance(descriptor_row, Mapping):
            raise AdapterError("core-info-package-omitted")
        reference = package.get("publicChk") or package.get("storeUrl")
        observed_reference = descriptor_row.get("chk") or descriptor_row.get("store_url")
        if (
            package.get("digest") != _file_digest(asset_paths[name])
            or package.get("sizeBytes") != asset_paths[name].stat().st_size
            or descriptor_row.get("size") != package.get("sizeBytes")
            or observed_reference != reference
        ):
            raise AdapterError("core-info-package-substitution")
    if set(descriptor_packages) != expected_keys:
        raise AdapterError("core-info-package-set-mismatch")

    fingerprint = _semantic_digest(
        {
            "plan": _file_digest(plan_path),
            "candidate": _file_digest(candidate_path),
            "authorization": _file_digest(authorization_path),
            "lineage": _file_digest(lineage_path),
            "comparison": _file_digest(comparison_path),
            "corePlan": _file_digest(core_plan_path),
            "coreInfo": descriptor_digest,
            "candidateInput": _file_digest(candidate_input_path),
            "candidateFreeze": candidate_freeze_digest,
            "gaBaseline": _file_digest(ga_baseline_path),
            "predecessorBaseline": _file_digest(predecessor_baseline_path),
            "evidence": _file_digest(evidence_path),
            "backportReleaseTrainValidation": backport_release_train_digest,
            "backportReleaseTrainAuthorization": _file_digest(
                backport_release_train_authorization_path
            ),
            "hotfixFollowUpClosure": (
                _file_digest(follow_up_closure_path)
                if follow_up_closure_path is not None
                else None
            ),
            "hotfixFollowUpObligation": expected_follow_up_digest,
            "assets": {
                name: _file_digest(path) for name, path in sorted(asset_paths.items())
            },
        }
    )
    return PublicationBundle(
        root=root,
        legacy=legacy,
        plan_path=plan_path,
        plan=plan,
        candidate_path=candidate_path,
        candidate=candidate,
        authorization_path=authorization_path,
        authorization=authorization,
        lineage_path=lineage_path,
        lineage=lineage,
        core_plan_path=core_plan_path,
        core_plan=core_plan,
        core_info_path=core_info_path,
        core_info=core_info,
        candidate_input_path=candidate_input_path,
        candidate_input=candidate_input,
        candidate_freeze_path=candidate_freeze_path,
        candidate_freeze=candidate_freeze,
        ga_baseline_path=ga_baseline_path,
        ga_baseline=ga_baseline,
        predecessor_baseline_path=predecessor_baseline_path,
        predecessor_baseline=predecessor_baseline,
        evidence_path=evidence_path,
        evidence=evidence,
        backport_release_train_validation_path=backport_release_train_validation_path,
        backport_release_train_validation=backport_release_train_validation,
        backport_release_train_authorization_path=backport_release_train_authorization_path,
        backport_release_train_authorization=backport_release_train_authorization,
        fingerprint=fingerprint,
        follow_up_obligation_path=follow_up_obligation_path,
        follow_up_obligation=follow_up_obligation,
        follow_up_closure_path=follow_up_closure_path,
        follow_up_closure=follow_up_closure,
    )


def _normalize_snapshot(snapshot: PublicSnapshot) -> PublicSnapshot:
    if snapshot.predecessor_pointer_digest is not None and not _DIGEST_RE.fullmatch(
        snapshot.predecessor_pointer_digest
    ):
        raise AdapterError("public-predecessor-observation-malformed")
    if snapshot.latest_candidate_identity_digest is not None and not _DIGEST_RE.fullmatch(
        snapshot.latest_candidate_identity_digest
    ):
        raise AdapterError("public-latest-candidate-observation-malformed")
    if set(snapshot.targets) != set(TARGETS):
        raise AdapterError("public-target-observation-incomplete")
    statuses = dict(snapshot.targets)
    if any(value not in TARGET_STATUSES for value in statuses.values()):
        raise AdapterError("public-target-observation-malformed")
    return PublicSnapshot(
        snapshot.predecessor_pointer_digest,
        {target: statuses[target] for target in TARGETS},
        snapshot.latest_candidate_identity_digest,
    )


def _observe(operations: ExternalOperations, request: PublicationRequest) -> PublicSnapshot:
    try:
        return _normalize_snapshot(operations.observe_public_state(request))
    except AdapterError:
        raise
    except Exception as exc:  # noqa: BLE001 - provider messages may contain protected material
        raise AdapterError("public-state-observation-unavailable") from exc


def _unavailable_snapshot() -> PublicSnapshot:
    return PublicSnapshot(None, {target: "unavailable" for target in TARGETS})


def _public_state_class(snapshot: PublicSnapshot) -> str:
    statuses = list(snapshot.targets.values())
    if "unavailable" in statuses:
        return "unavailable"
    if "conflict" in statuses:
        return "conflict"
    if all(status == "absent" for status in statuses):
        return "absent"
    if all(status == "matching" for status in statuses):
        return "matching-existing"
    seen_absent = False
    matching_prefix = False
    for target in TARGETS:
        status = snapshot.targets[target]
        if status == "absent":
            seen_absent = True
        elif status == "matching" and not seen_absent:
            matching_prefix = True
        else:
            break
    else:
        if matching_prefix and seen_absent:
            return "resumable-prefix"
    return "partial"


def _completed_target_prefix(snapshot: PublicSnapshot) -> list[str]:
    """Return the exact ordered matching prefix that is safe to resume after."""

    completed: list[str] = []
    for target in TARGETS:
        if snapshot.targets[target] != "matching":
            break
        completed.append(target)
    return completed


def _authorization_current(bundle: PublicationBundle, now: dt.datetime) -> bool:
    authorized = _parse_timestamp(bundle.authorization.get("authorizedAt"))
    expires = _parse_timestamp(bundle.authorization.get("expiresAt"))
    return bool(
        authorized is not None
        and expires is not None
        and authorized <= now.astimezone(dt.timezone.utc) < expires
    )


def preflight(
    root: Path,
    expected_predecessor_pointer_digest: str,
    operations: ExternalOperations,
    *,
    now: dt.datetime | None = None,
) -> PreflightOutcome:
    """Validate exact frozen bytes and observe all public targets without mutation."""

    if not _DIGEST_RE.fullmatch(expected_predecessor_pointer_digest):
        raise AdapterError("expected-predecessor-pointer-digest-malformed")
    bundle = _load_bundle(root)
    request = PublicationRequest(bundle)
    try:
        snapshot = _observe(operations, request)
    except AdapterError:
        snapshot = _unavailable_snapshot()
    public_state = _public_state_class(snapshot)
    artifact_base_pre_staged = snapshot.targets.get("artifactBase") == "matching"
    expected_from_lineage = bundle.lineage.get("latestPublishedPointerDigest")
    pointer_matches_authorization = expected_from_lineage == expected_predecessor_pointer_digest
    pointer_unchanged = snapshot.predecessor_pointer_digest == expected_predecessor_pointer_digest
    if (
        public_state == "matching-existing"
        and snapshot.latest_candidate_identity_digest
        == bundle.plan.get("candidateIdentityDigest")
    ):
        pointer_unchanged = True
    current = _authorization_current(bundle, now or _utcnow())
    passed = bool(
        pointer_matches_authorization
        and pointer_unchanged
        and current
        and artifact_base_pre_staged
        and public_state in {"matching-existing", "resumable-prefix"}
    )
    failure: str | None = None
    if not pointer_matches_authorization or not pointer_unchanged:
        failure = "predecessor-conflict"
    elif not current:
        failure = "authorization-expired"
    elif public_state == "unavailable":
        failure = "verification-unavailable"
    elif public_state in {"conflict", "partial"}:
        failure = "publication-conflict"
    elif not artifact_base_pre_staged:
        failure = "artifact-base-not-prestaged"
    artifact = {
        "schemaVersion": 1,
        "kind": "stable-1.0-maintenance-publication-preflight",
        "generatedAt": _timestamp(now or _utcnow()),
        "releaseId": bundle.plan.get("releaseId"),
        "buildVersion": bundle.plan.get("buildVersion"),
        "releaseClass": bundle.plan.get("releaseClass"),
        "candidateIdentityDigest": bundle.plan.get("candidateIdentityDigest"),
        "status": "pass" if passed else "fail",
        "sideEffectsPerformed": False,
        "latestPredecessorUnchanged": pointer_matches_authorization and pointer_unchanged,
        "authorizationCurrent": current,
        "freezeBytesExact": True,
        "publicState": public_state,
        "publicStateObservation": dict(snapshot.targets),
        "failureCategory": failure,
        "redaction": dict(_PASS_REDACTION),
    }
    _scan_public_value(artifact)
    return PreflightOutcome(artifact, snapshot, passed)


def _revalidate_bundle(request: PublicationRequest) -> PublicationRequest:
    refreshed = _load_bundle(request.bundle.root)
    if refreshed.fingerprint != request.bundle.fingerprint:
        raise AdapterError("candidate-byte-drift-before-mutation")
    return PublicationRequest(refreshed)


def _expected_mutation_snapshot(
    snapshot: PublicSnapshot,
    completed: Sequence[str],
    remaining: Sequence[str],
    expected_pointer: str,
) -> bool:
    return bool(
        snapshot.predecessor_pointer_digest == expected_pointer
        and all(snapshot.targets[target] == "matching" for target in completed)
        and all(snapshot.targets[target] == "absent" for target in remaining)
    )


def _receipt_identity(receipt: Mapping[str, Any]) -> str:
    """Match the engine's current non-circular publication-receipt identity exactly."""

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
    return _semantic_digest(fields)


def _successor_identity(successor: Mapping[str, Any]) -> str:
    """Match the engine's non-circular successor-baseline identity exactly."""

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
    if "releaseTrain" in successor:
        identity_keys.insert(identity_keys.index("releaseHistoryDigest"), "releaseTrain")
    return _semantic_digest(
        {key: successor.get(key) for key in identity_keys}
    )


def _expected_successor_follow_up(bundle: PublicationBundle) -> dict[str, Any]:
    """Return the authenticated unresolved obligation carried into the successor."""

    predecessor_value = bundle.predecessor_baseline.get("hotfixFollowUp")
    inherited = (
        predecessor_value
        if isinstance(predecessor_value, Mapping)
        and predecessor_value.get("status") in UNRESOLVED_FOLLOW_UP_STATUSES
        else None
    )
    if inherited is not None and bundle.follow_up_closure is not None:
        inherited = None
    follow_up_path = bundle.legacy / "stable-1.0-hotfix-follow-up-obligation.json"
    current: Mapping[str, Any] | None = None
    current_digest: str | None = None
    if follow_up_path.exists():
        current = _read_json(follow_up_path)
        current_digest = _file_digest(follow_up_path)
    effective = inherited or current
    effective_digest = (
        inherited.get("obligationDigest") if inherited is not None else current_digest
    )
    result = {
        "status": effective.get("status", "open") if effective else "not-required",
        "generatedAt": (
            effective.get("generatedAt")
            if effective
            else bundle.candidate_input.get("generatedAt")
        ),
        "obligationDigest": effective_digest,
        "deadline": effective.get("deadline") if effective else None,
        "closureEvidenceDigest": (
            effective.get("closureEvidenceDigest") if effective else None
        ),
        "blocksRoutineMaintenance": bool(effective),
    }
    if effective:
        result.update(
            {
                "obligatedReleaseId": effective.get(
                    "obligatedReleaseId", effective.get("releaseId")
                ),
                "obligatedBuildVersion": effective.get(
                    "obligatedBuildVersion", effective.get("buildVersion")
                ),
                "obligatedProductDigest": effective.get(
                    "obligatedProductDigest", effective.get("productDigest")
                ),
                "obligatedCandidateIdentityDigest": effective.get(
                    "obligatedCandidateIdentityDigest",
                    effective.get("candidateIdentityDigest"),
                ),
                "obligatedCandidateFreezeDigest": effective.get(
                    "obligatedCandidateFreezeDigest",
                    effective.get("candidateFreezeDigest"),
                ),
                "obligatedCandidateFrozenAt": effective.get(
                    "obligatedCandidateFrozenAt", effective.get("candidateFrozenAt")
                ),
                "obligatedPredecessorBuild": effective.get(
                    "obligatedPredecessorBuild", effective.get("predecessorBuild")
                ),
                "obligatedPredecessorProductDigest": effective.get(
                    "obligatedPredecessorProductDigest",
                    effective.get("predecessorProductDigest"),
                ),
                "authorizationDigest": (
                    effective.get("authorizationDigest")
                    if inherited is not None
                    else _file_digest(bundle.authorization_path)
                ),
            }
        )
    return result


def _validate_history(
    history: Mapping[str, Any], bundle: PublicationBundle, receipt_identity: str
) -> None:
    lineage = bundle.lineage
    provenance = _read_json(bundle.legacy / "stable-1.0-maintenance-provenance.json")
    expected = {
        "generatedAt": bundle.candidate_input.get("generatedAt"),
        "releaseId": bundle.plan.get("releaseId"),
        "buildVersion": bundle.plan.get("buildVersion"),
        "tag": bundle.plan.get("expectedTag"),
        "sourceCommit": bundle.plan.get("sourceCommit"),
        "releaseClass": bundle.plan.get("releaseClass"),
        "chainDepth": lineage.get("chainDepth"),
        "gaBaselineDigest": lineage.get("gaRoot", {}).get("maintenanceBaselineDigest"),
        "previousBaselineDigest": provenance.get("predecessorBaselineDigest"),
        "previousLineageDigest": lineage.get("previousLineageDigest"),
        "candidateIdentityDigest": bundle.plan.get("candidateIdentityDigest"),
        "productDigest": bundle.plan.get("productDigest"),
        "publicationReceiptIdentityDigest": receipt_identity,
        "coreInfoDigest": bundle.plan.get("coreInfoDigest"),
        "evidenceDigest": provenance.get("evidenceDigest"),
        "backportReleaseTrainDigest": bundle.plan.get(
            "backportReleaseTrainDigest"
        ),
        "status": "published-and-verified",
    }
    if (
        set(history)
        != {
            "schemaVersion",
            "kind",
            "generatedAt",
            "stableMilestone",
            "releaseId",
            "buildVersion",
            "tag",
            "sourceCommit",
            "releaseClass",
            "chainDepth",
            "gaBaselineDigest",
            "previousBaselineDigest",
            "previousLineageDigest",
            "candidateIdentityDigest",
            "productDigest",
            "publicationReceiptIdentityDigest",
            "coreInfoDigest",
            "evidenceDigest",
            "backportReleaseTrainDigest",
            "status",
            "redaction",
        }
        or history.get("schemaVersion") != 1
        or history.get("kind") != "stable-1.0-maintenance-history-entry"
        or history.get("stableMilestone") != "1.0"
        or any(history.get(key) != value for key, value in expected.items())
        or history.get("redaction") != _PASS_REDACTION
    ):
        raise AdapterError("release-history-binding-mismatch")


def _validate_successor(
    successor: Mapping[str, Any],
    history: Mapping[str, Any],
    history_digest: str,
    bundle: PublicationBundle,
    receipt_identity: str,
) -> None:
    _validate_schema(
        successor, "stable-1.0-maintenance-successor-baseline-v2.schema.json"
    )
    lineage = bundle.lineage
    provenance = _read_json(bundle.legacy / "stable-1.0-maintenance-provenance.json")
    release = successor.get("release") if isinstance(successor.get("release"), Mapping) else {}
    release_train = (
        successor.get("releaseTrain")
        if isinstance(successor.get("releaseTrain"), Mapping)
        else {}
    )
    publication = (
        successor.get("publication")
        if isinstance(successor.get("publication"), Mapping)
        else {}
    )
    candidate_input = bundle.candidate_input
    platform_api = candidate_input.get("platformApi", {})
    stable_catalog = candidate_input.get("stableCatalog", {})
    expected_platform = {
        key: platform_api.get(key)
        for key in (
            "baselineName",
            "baselineDigest",
            "baselineContractVersion",
            "currentContractVersion",
            "currentContractDigest",
            "stableSurfaceDigest",
            "compatibilityWindowPolicyDigest",
            "deprecationHistoryDigest",
            "deprecationHistory",
        )
    }
    expected_catalog = {
        key: stable_catalog.get(key)
        for key in (
            "catalogId",
            "channel",
            "revision",
            "edition",
            "digest",
            "signatureFileName",
            "signatureSizeBytes",
            "signatureDigest",
            "signingKeyId",
        )
    }
    app_fields = (
        "appId",
        "version",
        "channel",
        "supportLevel",
        "bundleDigest",
        "reviewReceiptDigest",
        "appSigningKeyId",
        "reviewerKeyId",
        "manifestDigest",
        "permissionSetDigest",
        "appDataSchemaVersion",
        "supportMetadataDigest",
    )
    profile_fields = (
        "profileId",
        "version",
        "status",
        "descriptorDigest",
        "canonicalizationRulesDigest",
        "maximumSizePolicyDigest",
        "signaturePayloadRulesDigest",
    )
    expected_apps = [
        {key: row.get(key) for key in app_fields}
        for row in candidate_input.get("firstPartyApps", [])
        if isinstance(row, Mapping)
    ]
    expected_profiles = [
        {key: row.get(key) for key in profile_fields}
        for row in candidate_input.get("contentFormatProfiles", [])
        if isinstance(row, Mapping)
    ]
    ga_baseline = bundle.ga_baseline
    predecessor = bundle.predecessor_baseline
    limitations = candidate_input.get("limitations", {})
    current_limitation_ids = sorted(
        {
            item
            for field in ("addedIds", "unchangedIds")
            for item in (
                limitations.get(field)
                if isinstance(limitations.get(field), list)
                else []
            )
            if isinstance(item, str)
        }
    )
    security = candidate_input.get("security", {})
    support = candidate_input.get("support", {})
    expected_sections = {
        "limitations": {
            "currentDigest": _semantic_digest(
                {"limitationIds": current_limitation_ids}
            ),
            "currentIds": current_limitation_ids,
            "gaBaselineDigest": _semantic_digest(ga_baseline.get("limitations")),
            "predecessorDigest": _semantic_digest(predecessor.get("limitations")),
        },
        "security": {
            "currentDigest": _semantic_digest(security),
            "gaBaselineDigest": _semantic_digest(ga_baseline.get("securityBaseline")),
            "predecessorDigest": _semantic_digest(
                predecessor.get("security", predecessor.get("securityBaseline"))
            ),
        },
        "support": {
            "currentDigest": _semantic_digest(support),
            "gaBaselineDigest": _semantic_digest(ga_baseline.get("supportBaseline")),
            "predecessorDigest": _semantic_digest(
                predecessor.get("support", predecessor.get("supportBaseline"))
            ),
        },
    }
    evidence_rows = bundle.evidence.get("evidenceRows", [])
    evidence_ids = sorted(
        row.get("evidenceId") for row in evidence_rows if isinstance(row, Mapping)
    )
    expected_evidence_policy = {
        "windowClass": bundle.evidence.get("windowClass"),
        "policyDigest": provenance.get("policyDigest"),
        "requiredEvidenceDigest": _semantic_digest(evidence_ids),
        "completedEvidenceDigest": _file_digest(bundle.evidence_path),
    }
    expected_follow_up = _expected_successor_follow_up(bundle)
    expected_release_train = {
        "validationDigest": bundle.plan.get("backportReleaseTrainDigest"),
        "requiredEvidenceId": "stable-maintenance.backport-release-train",
        "candidateCommit": bundle.plan.get("sourceCommit"),
        "predecessorCommit": lineage.get("predecessor", {}).get(
            "sourceCommit"
        ),
        "unresolvedObligationsCarried": bool(
            expected_follow_up.get("blocksRoutineMaintenance")
        ),
    }
    ga_root = lineage.get("gaRoot", {})
    expected_ga_root = {
        key: ga_root.get(key)
        for key in (
            "releaseId",
            "buildVersion",
            "tag",
            "sourceCommit",
            "productDigest",
            "maintenanceBaselineDigest",
            "publicationReceiptDigest",
        )
    }
    if (
        successor.get("generatedAt") != candidate_input.get("generatedAt")
        or successor.get("gaRoot") != expected_ga_root
        or successor.get("previousBaselineDigest")
        != provenance.get("predecessorBaselineDigest")
        or successor.get("chainDepth") != lineage.get("chainDepth")
        or successor.get("previousLineageDigest") != lineage.get("previousLineageDigest")
        or successor.get("releaseHistoryDigest") != history_digest
        or release.get("releaseId") != bundle.plan.get("releaseId")
        or release.get("buildVersion") != bundle.plan.get("buildVersion")
        or release.get("tag") != bundle.plan.get("expectedTag")
        or release.get("sourceCommit") != bundle.plan.get("sourceCommit")
        or release.get("releaseClass") != bundle.plan.get("releaseClass")
        or release.get("productDigest") != bundle.plan.get("productDigest")
        or release.get("checksumsDigest") != bundle.plan.get("checksumsDigest")
        or release.get("provenanceDigest") != bundle.plan.get("provenanceDigest")
        or release.get("coreInfoDigest") != bundle.plan.get("coreInfoDigest")
        or release.get("publicationReceiptIdentityDigest") != receipt_identity
        or publication.get("receiptIdentityDigest") != receipt_identity
        or publication.get("publicationState") != "publication-complete"
        or publication.get("verificationStatus") != "pass"
        or successor.get("platformApi") != expected_platform
        or successor.get("stableCatalog") != expected_catalog
        or successor.get("firstPartyApps") != expected_apps
        or successor.get("contentFormatProfiles") != expected_profiles
        or successor.get("limitations") != expected_sections["limitations"]
        or successor.get("security") != expected_sections["security"]
        or successor.get("support") != expected_sections["support"]
        or successor.get("legacyBoundaries") != candidate_input.get("legacyBoundaries")
        or successor.get("evidenceWindowPolicy") != expected_evidence_policy
        or successor.get("hotfixFollowUp") != expected_follow_up
        or release_train != expected_release_train
        or successor.get("gaRoot", {}).get("maintenanceBaselineDigest")
        != lineage.get("gaRoot", {}).get("maintenanceBaselineDigest")
        or successor.get("gaRoot", {}).get("publicationReceiptDigest")
        != lineage.get("gaRoot", {}).get("publicationReceiptDigest")
        or successor.get("redaction") != _PASS_REDACTION
    ):
        raise AdapterError("successor-baseline-binding-mismatch")

    predecessor_history: list[Mapping[str, Any]]
    if predecessor.get("schemaVersion") == 1:
        ga = bundle.lineage.get("gaRoot", {})
        predecessor_history = [
            {
                "chainDepth": 0,
                "releaseId": ga.get("releaseId"),
                "buildVersion": ga.get("buildVersion"),
                "tag": ga.get("tag"),
                "sourceCommit": ga.get("sourceCommit"),
                "releaseClass": "stable-ga",
                "productDigest": ga.get("productDigest"),
                "baselineIdentityDigest": _file_digest(bundle.ga_baseline_path),
                "publicationReceiptIdentityDigest": ga.get("publicationReceiptDigest"),
                "previousLineageDigest": bundle.lineage.get("previousLineageDigest"),
            }
        ]
    else:
        predecessor_lineage = predecessor.get("lineage", {})
        predecessor_history = list(predecessor_lineage.get("history", []))
    expected_history = [*predecessor_history]
    expected_history.append(
        {
            "chainDepth": bundle.lineage.get("chainDepth"),
            "releaseId": bundle.plan.get("releaseId"),
            "buildVersion": bundle.plan.get("buildVersion"),
            "tag": bundle.plan.get("expectedTag"),
            "sourceCommit": bundle.plan.get("sourceCommit"),
            "releaseClass": bundle.plan.get("releaseClass"),
            "productDigest": bundle.plan.get("productDigest"),
            "baselineIdentityDigest": _successor_identity(successor),
            "publicationReceiptIdentityDigest": receipt_identity,
            "previousLineageDigest": bundle.lineage.get("previousLineageDigest"),
        }
    )
    expected_lineage = {
        "gaBaselineDigest": _file_digest(bundle.ga_baseline_path),
        "gaPublicationReceiptDigest": bundle.lineage.get("gaRoot", {}).get(
            "publicationReceiptDigest"
        ),
        "chainDepth": bundle.lineage.get("chainDepth"),
        "lineageDigest": _semantic_digest(expected_history),
        "history": expected_history,
    }
    if successor.get("lineage") != expected_lineage:
        raise AdapterError("successor-lineage-binding-mismatch")


def _validate_verification_material(
    material: VerificationMaterial, bundle: PublicationBundle
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    receipt = dict(material.maintenance_receipt)
    core_receipt = dict(material.core_update_receipt)
    successor = dict(material.successor_baseline)
    history = dict(material.history_entry)
    for value in (receipt, core_receipt, successor, history):
        _scan_public_value(value)
    _validate_schema(
        receipt, "stable-1.0-maintenance-publication-receipt-v1.schema.json"
    )
    _validate_schema(
        core_receipt, "cryptad-core-update-publication-receipt-v1.schema.json"
    )

    plan = bundle.plan
    planned_assets = {
        row.get("fileName"): (
            row.get("role"),
            row.get("digest"),
            row.get("sizeBytes"),
            row.get("publicUri"),
        )
        for row in plan.get("assets", [])
        if isinstance(row, Mapping)
    }
    receipt_assets = receipt.get("assets", [])
    receipt_asset_names = [
        row.get("fileName") for row in receipt_assets if isinstance(row, Mapping)
    ]
    assets_are_exact = (
        isinstance(receipt_assets, list)
        and len(receipt_assets) == len(planned_assets)
        and len(receipt_asset_names) == len(receipt_assets)
        and len(set(receipt_asset_names)) == len(receipt_asset_names)
        and all(
            row.get("operation") in {"created", "verified-existing"}
            and row.get("verificationStatus") == "verified"
            for row in receipt_assets
            if isinstance(row, Mapping)
        )
    )
    observed_assets = {
        row.get("fileName"): (
            row.get("role"),
            row.get("digest"),
            row.get("sizeBytes"),
            row.get("publicUri"),
        )
        for row in receipt_assets
        if isinstance(row, Mapping)
    }
    public_observations = receipt.get("publicObservations")
    exact_operations = {"created", "verified-existing"}
    catalog_target = plan.get("stableCatalogTarget", {})
    core_target = plan.get("coreUpdateTarget", {})
    if (
        receipt.get("releaseId") != plan.get("releaseId")
        or receipt.get("buildVersion") != plan.get("buildVersion")
        or receipt.get("releaseClass") != plan.get("releaseClass")
        or receipt.get("sourceCommit") != plan.get("sourceCommit")
        or receipt.get("githubReleasePageUri") != plan.get("githubReleasePageUri")
        or receipt.get("deploymentServicePublicUri")
        != plan.get("deploymentServicePublicUri")
        or receipt.get("latestPointerPublicUri") != plan.get("latestPointerPublicUri")
        or receipt.get("candidateIdentityDigest") != plan.get("candidateIdentityDigest")
        or receipt.get("productDigest") != plan.get("productDigest")
        or receipt.get("checksumsDigest") != plan.get("checksumsDigest")
        or receipt.get("provenanceDigest") != plan.get("provenanceDigest")
        or receipt.get("authorizationDigest") != plan.get("authorizationDigest")
        or receipt.get("backportReleaseTrainDigest")
        != plan.get("backportReleaseTrainDigest")
        or receipt.get("coreUpdateReceiptDigest")
        != "sha256:" + hashlib.sha256(_canonical_bytes(core_receipt)).hexdigest()
        or receipt.get("publicationPlanDigest") != _file_digest(bundle.plan_path)
        or receipt.get("releaseNotesDigest") != plan.get("releaseNotesDigest")
        or receipt.get("coreInfoDigest") != plan.get("coreInfoDigest")
        or not assets_are_exact
        or planned_assets != observed_assets
        or receipt.get("tag", {}).get("name") != plan.get("expectedTag")
        or receipt.get("tag", {}).get("objectType") != "annotated"
        or receipt.get("tag", {}).get("targetCommit") != plan.get("sourceCommit")
        or receipt.get("tag", {}).get("operation") not in exact_operations
        or receipt.get("tag", {}).get("verificationStatus") != "verified"
        or receipt.get("githubRelease", {}).get("tag") != plan.get("expectedTag")
        or receipt.get("githubRelease", {}).get("pageUri")
        != plan.get("githubReleasePageUri")
        or receipt.get("githubRelease", {}).get("notesDigest")
        != plan.get("releaseNotesDigest")
        or receipt.get("githubRelease", {}).get("operation") not in exact_operations
        or receipt.get("githubRelease", {}).get("verificationStatus") != "verified"
        or any(
            receipt.get("stableCatalog", {}).get(key) != catalog_target.get(key)
            for key in (
                "catalogId",
                "revision",
                "edition",
                "digest",
                "signatureDigest",
                "publicUri",
                "signaturePublicUri",
                "mirrorSetDigest",
                "rollbackStateDigest",
            )
        )
        or catalog_target.get("signatureDigest")
        != bundle.candidate_input.get("stableCatalog", {}).get("signatureDigest")
        or receipt.get("stableCatalog", {}).get("operation") not in exact_operations
        or receipt.get("stableCatalog", {}).get("verificationStatus") != "verified"
        or any(
            receipt.get("coreUpdate", {}).get(key) != core_target.get(key)
            for key in ("edition", "descriptorDigest", "publicUri")
        )
        or receipt.get("coreUpdate", {}).get("packageMapDigest")
        != _semantic_digest(bundle.core_info.get("packages"))
        or receipt.get("coreUpdate", {}).get("operation") not in exact_operations
        or receipt.get("coreUpdate", {}).get("verificationStatus") != "verified"
        or not isinstance(public_observations, Mapping)
        or set(public_observations) != set(TARGETS)
        or set(public_observations.values()) != {"verified"}
        or receipt.get("publicationState") != "publication-complete"
        or receipt.get("finalVerificationStatus") != "pass"
        or receipt.get("failureCategory") is not None
        or receipt.get("redaction") != _PASS_REDACTION
    ):
        raise AdapterError("maintenance-publication-receipt-mismatch")

    packages = bundle.candidate.get("packages")
    expected_packages = {
        row.get("packageKey"): (
            row.get("digest"),
            row.get("sizeBytes"),
            row.get("publicChk") or row.get("storeUrl"),
        )
        for row in packages
        if isinstance(row, Mapping)
    }
    referenced_packages = core_receipt.get("referencedPackages", [])
    referenced_package_keys = [
        row.get("packageKey")
        for row in referenced_packages
        if isinstance(row, Mapping)
    ]
    packages_are_exact = (
        isinstance(referenced_packages, list)
        and len(referenced_packages) == len(expected_packages)
        and len(referenced_package_keys) == len(referenced_packages)
        and len(set(referenced_package_keys)) == len(referenced_package_keys)
        and all(
            row.get("verificationStatus") == "pass"
            for row in referenced_packages
            if isinstance(row, Mapping)
        )
    )
    observed_packages = {
        row.get("packageKey"): (
            row.get("candidateAssetDigest"),
            row.get("candidateAssetSizeBytes"),
            row.get("publicReference"),
        )
        for row in referenced_packages
        if isinstance(row, Mapping)
    }
    if (
        core_receipt.get("releaseId") != plan.get("releaseId")
        or core_receipt.get("buildVersion") != plan.get("buildVersion")
        or core_receipt.get("releaseClass") != plan.get("releaseClass")
        or core_receipt.get("candidateIdentityDigest") != plan.get("candidateIdentityDigest")
        or core_receipt.get("publicationPlanDigest") != _file_digest(bundle.core_plan_path)
        or core_receipt.get("descriptorDigest") != plan.get("coreInfoDigest")
        or core_receipt.get("descriptorSizeBytes") != bundle.core_info_path.stat().st_size
        or core_receipt.get("packageMapDigest")
        != _semantic_digest(bundle.core_info.get("packages"))
        or core_receipt.get("edition") != int(str(plan.get("buildVersion")))
        or core_receipt.get("publicFetchUri")
        != plan.get("coreUpdateTarget", {}).get("publicUri")
        or core_receipt.get("fetchedDescriptorDigest") != plan.get("coreInfoDigest")
        or not packages_are_exact
        or observed_packages != expected_packages
        or core_receipt.get("operation") not in exact_operations
        or core_receipt.get("conflictStatus") != "clear"
        or core_receipt.get("verificationStatus") != "pass"
        or core_receipt.get("publicationState") != "publication-complete"
        or core_receipt.get("redaction") != _PASS_REDACTION
        or receipt.get("coreUpdate", {}).get("descriptorDigest")
        != core_receipt.get("descriptorDigest")
        or receipt.get("coreUpdate", {}).get("packageMapDigest")
        != core_receipt.get("packageMapDigest")
    ):
        raise AdapterError("core-update-publication-receipt-mismatch")

    receipt_identity = _receipt_identity(receipt)
    _validate_history(history, bundle, receipt_identity)
    history_bytes = _canonical_bytes(history)
    history_digest = "sha256:" + hashlib.sha256(history_bytes).hexdigest()
    _validate_successor(successor, history, history_digest, bundle, receipt_identity)
    successor_bytes = _canonical_bytes(successor)
    successor_digest = "sha256:" + hashlib.sha256(successor_bytes).hexdigest()
    if (
        receipt.get("successorBaselineDigest") != successor_digest
        or receipt.get("releaseHistoryDigest") != history_digest
    ):
        raise AdapterError("publication-successor-digest-mismatch")
    return receipt, core_receipt, successor, history


def _failure_audit_path(receipt_path: Path) -> Path:
    """Return the canonical non-receipt path for a failed publication attempt."""

    return receipt_path.with_name(FAILURE_AUDIT_FILE)


def _failure_audit(
    bundle: PublicationBundle,
    snapshot: PublicSnapshot,
    failure_category: str,
    now: dt.datetime,
    attempted_targets: Sequence[str] = (),
    completed_targets: Sequence[str] = (),
) -> dict[str, Any]:
    attempted = [target for target in TARGETS if target in set(attempted_targets)]
    completed = [
        target
        for target in TARGETS
        if target in set(completed_targets) or snapshot.targets.get(target) == "matching"
    ]
    public_state = _public_state_class(snapshot)
    publication_state = (
        "publication-partial"
        if attempted or completed or public_state == "partial"
        else "publication-verification-failed"
    )
    audit = {
        "schemaVersion": 1,
        "kind": "stable-1.0-maintenance-publication-failure-audit",
        "generatedAt": _timestamp(now),
        "releaseId": bundle.plan.get("releaseId"),
        "buildVersion": bundle.plan.get("buildVersion"),
        "releaseClass": bundle.plan.get("releaseClass"),
        "sourceCommit": bundle.plan.get("sourceCommit"),
        "candidateIdentityDigest": bundle.plan.get("candidateIdentityDigest"),
        "productDigest": bundle.plan.get("productDigest"),
        "publicationPlanDigest": _file_digest(bundle.plan_path),
        "publicationState": publication_state,
        "failureCategory": failure_category,
        "predecessorPointerDigest": snapshot.predecessor_pointer_digest,
        "latestCandidateIdentityDigest": snapshot.latest_candidate_identity_digest,
        "observedPublicState": dict(snapshot.targets),
        "attemptedTargets": attempted,
        "completedTargets": completed,
        "sideEffectsMayHaveOccurred": bool(attempted or completed),
        "finalVerificationStatus": "fail",
        "redaction": dict(_PASS_REDACTION),
    }
    _validate_schema(
        audit, "stable-1.0-maintenance-publication-failure-audit-v1.schema.json"
    )
    return audit


def publish_or_verify_exact(
    root: Path,
    expected_predecessor_pointer_digest: str,
    operations: ExternalOperations,
    protected_inputs: PublicationProtectedInputs,
    source_ref_revalidator: Callable[[PublicationBundle | ActivationRequest], None],
    receipt_path: Path,
    core_receipt_path: Path,
    *,
    now: Callable[[], dt.datetime] = _utcnow,
) -> CommandOutcome:
    """Publish each exact target once or verify an entirely matching pre-existing release."""

    initial = preflight(root, expected_predecessor_pointer_digest, operations, now=now())
    bundle = _load_bundle(root)
    request = PublicationRequest(bundle)
    if not initial.passed:
        audit = _failure_audit(
            bundle,
            initial.snapshot,
            str(initial.artifact.get("failureCategory") or "verification-unavailable"),
            now(),
        )
        return CommandOutcome(False, {_failure_audit_path(receipt_path): audit})

    initial_state = _public_state_class(initial.snapshot)
    attempted: list[str] = []
    completed = _completed_target_prefix(initial.snapshot)
    try:
        if initial_state in {"absent", "resumable-prefix"}:
            for index in range(len(completed), len(MUTATION_TARGETS)):
                target = MUTATION_TARGETS[index]
                request = _revalidate_bundle(request)
                if not _authorization_current(request.bundle, now()):
                    raise AdapterError("authorization-expired-before-mutation")
                snapshot = _observe(operations, request)
                remaining = MUTATION_TARGETS[index:]
                if not _expected_mutation_snapshot(
                    snapshot, completed, remaining, expected_predecessor_pointer_digest
                ):
                    raise AdapterError("public-state-changed-before-mutation")
                source_ref_revalidator(request.bundle)
                if not _authorization_current(request.bundle, now()):
                    raise AdapterError("authorization-expired-before-mutation")
                attempted.append(target)
                try:
                    operations.publish_target(
                        target, request, protected_inputs.for_target(target)
                    )
                except Exception as exc:  # noqa: BLE001 - never expose provider/secret details
                    raise AdapterError("protected-publication-operation-failed") from exc
                completed.append(target)
        elif initial_state != "matching-existing":
            raise AdapterError("publication-preflight-not-mutation-safe")
        else:
            source_ref_revalidator(request.bundle)

        request = _revalidate_bundle(request)
        final_snapshot = _observe(operations, request)
        if (
            _public_state_class(final_snapshot) != "matching-existing"
            or (
                final_snapshot.predecessor_pointer_digest
                != expected_predecessor_pointer_digest
                and final_snapshot.latest_candidate_identity_digest
                != request.candidate_identity_digest
            )
        ):
            raise AdapterError("post-publication-public-state-mismatch")
        try:
            material = operations.verify_publication(request)
        except Exception as exc:  # noqa: BLE001
            raise AdapterError("independent-publication-verification-unavailable") from exc
        receipt, core, _successor, _history = _validate_verification_material(
            material, request.bundle
        )
        return CommandOutcome(True, {receipt_path: receipt, core_receipt_path: core})
    except AdapterError as failure:
        try:
            snapshot = _observe(operations, request)
        except AdapterError:
            snapshot = _unavailable_snapshot()
        audit = _failure_audit(
            bundle,
            snapshot,
            failure.code,
            now(),
            attempted,
            completed,
        )
        return CommandOutcome(False, {_failure_audit_path(receipt_path): audit})


def verify_public_state(
    root: Path,
    operations: ExternalOperations,
    receipt_path: Path,
    core_receipt_path: Path,
    successor_path: Path,
    history_path: Path,
) -> CommandOutcome:
    """Independently verify public bytes and materialize only authenticated public records."""

    bundle = _load_bundle(root)
    request = PublicationRequest(bundle)
    try:
        snapshot = _observe(operations, request)
        if _public_state_class(snapshot) != "matching-existing":
            raise AdapterError("independent-public-state-is-not-exact")
        expected_pointer = str(bundle.lineage.get("latestPublishedPointerDigest"))
        if (
            snapshot.predecessor_pointer_digest != expected_pointer
            and snapshot.latest_candidate_identity_digest != request.candidate_identity_digest
        ):
            raise AdapterError("independent-predecessor-observation-changed")
        try:
            material = operations.verify_publication(request)
        except Exception as exc:  # noqa: BLE001
            raise AdapterError("independent-publication-verification-unavailable") from exc
        receipt, core, successor, history = _validate_verification_material(
            material, bundle
        )
        return CommandOutcome(
            True,
            {
                receipt_path: receipt,
                core_receipt_path: core,
                successor_path: successor,
                history_path: history,
            },
        )
    except AdapterError as failure:
        audit = _failure_audit(
            bundle,
            snapshot if "snapshot" in locals() else _unavailable_snapshot(),
            failure.code,
            _utcnow(),
        )
        return CommandOutcome(False, {_failure_audit_path(receipt_path): audit})


def _activated_latest_pointer(
    successor: Mapping[str, Any],
    successor_digest: str,
    receipt: Mapping[str, Any],
    receipt_digest: str,
    history_digest: str,
) -> dict[str, Any]:
    """Build the one canonical latest-published pointer authorized for activation."""

    release_value = successor.get("release")
    release = release_value if isinstance(release_value, Mapping) else {}
    lineage_value = successor.get("lineage")
    lineage = lineage_value if isinstance(lineage_value, Mapping) else {}
    return {
        "schemaVersion": 1,
        "kind": "stable-1.0-maintenance-latest-published",
        "generatedAt": successor.get("generatedAt"),
        "releaseId": release.get("releaseId"),
        "buildVersion": release.get("buildVersion"),
        "releaseClass": release.get("releaseClass"),
        "baselineDigest": successor_digest,
        "baselineIdentityDigest": _successor_identity(successor),
        "publicationReceiptDigest": receipt_digest,
        "publicationReceiptIdentityDigest": _receipt_identity(receipt),
        "lineageDigest": lineage.get("lineageDigest"),
        "historyDigest": history_digest,
        "backportReleaseTrainDigest": successor.get("releaseTrain", {}).get(
            "validationDigest"
        ),
        "compareAndSwapPredecessorBaselineDigest": successor.get(
            "previousBaselineDigest"
        ),
        "status": "active",
        "redaction": dict(_PASS_REDACTION),
    }


def _load_activation_request(
    successor_path: Path,
    history_path: Path,
    receipt_path: Path,
    authorization_path: Path,
    activation_authorization_path: Path,
    expected_pointer_digest: str,
) -> ActivationRequest:
    if not _DIGEST_RE.fullmatch(expected_pointer_digest):
        raise AdapterError("expected-current-pointer-digest-malformed")
    successor = _read_json(successor_path)
    history = _read_json(history_path)
    receipt = _read_json(receipt_path)
    authorization = _read_json(authorization_path)
    activation_authorization = _read_json(activation_authorization_path)
    _validate_schema(
        successor, "stable-1.0-maintenance-successor-baseline-v2.schema.json"
    )
    _validate_schema(
        receipt, "stable-1.0-maintenance-publication-receipt-v1.schema.json"
    )
    _validate_schema(
        authorization, "stable-1.0-maintenance-authorization-v1.schema.json"
    )
    _validate_schema(
        activation_authorization,
        "stable-1.0-maintenance-activation-authorization-v1.schema.json",
    )
    _scan_public_value(authorization)
    _scan_public_value(activation_authorization)
    successor_digest = _file_digest(successor_path)
    history_digest = _file_digest(history_path)
    receipt_digest = _file_digest(receipt_path)
    authorization_digest = _file_digest(authorization_path)
    activation_authorization_digest = _file_digest(activation_authorization_path)
    release = successor.get("release") if isinstance(successor.get("release"), Mapping) else {}
    release_train = (
        successor.get("releaseTrain")
        if isinstance(successor.get("releaseTrain"), Mapping)
        else {}
    )
    release_class = receipt.get("releaseClass")
    expected_role = (
        "stable-maintenance-release-manager"
        if release_class == "maintenance"
        else "stable-security-release-manager"
    )
    expected_environment = (
        "stable-1.0-maintenance-publication"
        if release_class == "maintenance"
        else "stable-1.0-security-hotfix-publication"
    )
    if (
        receipt.get("publicationState") != "publication-complete"
        or receipt.get("finalVerificationStatus") != "pass"
        or receipt.get("successorBaselineDigest") != successor_digest
        or receipt.get("releaseHistoryDigest") != history_digest
        or successor.get("status") != "published"
        or successor.get("releaseHistoryDigest") != history_digest
        or release.get("releaseId") != receipt.get("releaseId")
        or release.get("buildVersion") != receipt.get("buildVersion")
        or release.get("releaseClass") != receipt.get("releaseClass")
        or release.get("sourceCommit") != receipt.get("sourceCommit")
        or history.get("releaseId") != receipt.get("releaseId")
        or history.get("buildVersion") != receipt.get("buildVersion")
        or history.get("publicationReceiptIdentityDigest") != _receipt_identity(receipt)
        or history.get("backportReleaseTrainDigest")
        != release_train.get("validationDigest")
        or receipt.get("backportReleaseTrainDigest")
        != release_train.get("validationDigest")
        or successor.get("publication", {}).get("receiptIdentityDigest")
        != _receipt_identity(receipt)
        or receipt.get("authorizationDigest") != authorization_digest
        or authorization.get("releaseId") != receipt.get("releaseId")
        or authorization.get("buildVersion") != receipt.get("buildVersion")
        or authorization.get("releaseClass") != release_class
        or authorization.get("candidateIdentityDigest")
        != receipt.get("candidateIdentityDigest")
        or authorization.get("productDigest") != receipt.get("productDigest")
        or authorization.get("checksumsDigest") != receipt.get("checksumsDigest")
        or authorization.get("provenanceDigest") != receipt.get("provenanceDigest")
        or authorization.get("coreInfoDigest") != receipt.get("coreInfoDigest")
        or authorization.get("releaseNotesDigest")
        != receipt.get("releaseNotesDigest")
        or authorization.get("backportReleaseTrainDigest")
        != release_train.get("validationDigest")
        or release_train.get("candidateCommit") != receipt.get("sourceCommit")
        or not _DIGEST_RE.fullmatch(
            str(release_train.get("validationDigest", ""))
        )
        or authorization.get("allowedPublicationScopes") != list(AUTHORIZATION_SCOPES)
        or authorization.get("role") != expected_role
        or authorization.get("decision") not in {"go", "go-with-waivers"}
        or authorization.get("status") != "approved"
        or authorization.get("redaction") != _PASS_REDACTION
        or activation_authorization.get("protectedEnvironment")
        != expected_environment
        or activation_authorization.get("sourceCommit")
        != receipt.get("sourceCommit")
        or activation_authorization.get("releaseId") != receipt.get("releaseId")
        or activation_authorization.get("buildVersion")
        != receipt.get("buildVersion")
        or activation_authorization.get("releaseClass") != release_class
        or activation_authorization.get("candidateIdentityDigest")
        != receipt.get("candidateIdentityDigest")
        or activation_authorization.get("publicationReceiptDigest")
        != receipt_digest
        or activation_authorization.get("successorBaselineDigest")
        != successor_digest
        or activation_authorization.get("historyDigest") != history_digest
        or activation_authorization.get("originalAuthorizationDigest")
        != authorization_digest
        or activation_authorization.get("expectedCurrentPointerDigest")
        != expected_pointer_digest
        or activation_authorization.get("allowedScope")
        != "successor-baseline:activate"
        or activation_authorization.get("status") != "approved"
        or activation_authorization.get("redaction") != _PASS_REDACTION
    ):
        raise AdapterError("baseline-activation-input-binding-mismatch")
    activated_pointer = _activated_latest_pointer(
        successor,
        successor_digest,
        receipt,
        receipt_digest,
        history_digest,
    )
    activated_pointer_bytes = _canonical_bytes(activated_pointer)
    activated_pointer_digest = (
        "sha256:" + hashlib.sha256(activated_pointer_bytes).hexdigest()
    )
    return ActivationRequest(
        successor_path,
        successor,
        history_path,
        history,
        receipt_path,
        receipt,
        authorization_path,
        authorization,
        authorization_digest,
        activation_authorization_path,
        activation_authorization,
        activation_authorization_digest,
        expected_pointer_digest,
        successor_digest,
        history_digest,
        receipt_digest,
        activated_pointer,
        activated_pointer_bytes,
        activated_pointer_digest,
    )


def _revalidate_activation_authorization(
    request: ActivationRequest, now: dt.datetime
) -> None:
    """Require the exact renewable activation-only grant to remain current."""

    current = _read_json(request.activation_authorization_path)
    _validate_schema(
        current, "stable-1.0-maintenance-activation-authorization-v1.schema.json"
    )
    _scan_public_value(current)
    if (
        _file_digest(request.activation_authorization_path)
        != request.activation_authorization_digest
        or current != request.activation_authorization
        or current.get("releaseId") != request.receipt.get("releaseId")
        or current.get("buildVersion") != request.receipt.get("buildVersion")
        or current.get("releaseClass") != request.receipt.get("releaseClass")
        or current.get("candidateIdentityDigest")
        != request.receipt.get("candidateIdentityDigest")
        or current.get("publicationReceiptDigest") != request.receipt_digest
        or current.get("successorBaselineDigest") != request.successor_digest
        or current.get("historyDigest") != request.history_digest
        or current.get("originalAuthorizationDigest")
        != request.authorization_digest
        or current.get("expectedCurrentPointerDigest")
        != request.expected_pointer_digest
        or current.get("allowedScope") != "successor-baseline:activate"
        or current.get("status") != "approved"
        or current.get("redaction") != _PASS_REDACTION
    ):
        raise AdapterError("baseline-activation-authorization-changed")
    authorized = _parse_timestamp(current.get("authorizedAt"))
    expires = _parse_timestamp(current.get("expiresAt"))
    if (
        authorized is None
        or expires is None
        or expires <= authorized
        or expires - authorized > dt.timedelta(hours=1)
        or not (authorized <= now < expires)
    ):
        raise AdapterError("activation-authorization-expired")


def _normalize_pointer(snapshot: PointerSnapshot) -> PointerSnapshot:
    if snapshot.status not in {"observed", "unavailable"}:
        raise AdapterError("latest-pointer-observation-malformed")
    for digest in (
        snapshot.pointer_digest,
        snapshot.active_baseline_digest,
        snapshot.candidate_identity_digest,
    ):
        if digest is not None and not _DIGEST_RE.fullmatch(digest):
            raise AdapterError("latest-pointer-observation-malformed")
    return snapshot


def activate_latest_baseline(
    successor_path: Path,
    history_path: Path,
    receipt_path: Path,
    authorization_path: Path,
    activation_authorization_path: Path,
    expected_pointer_digest: str,
    operations: ExternalOperations,
    maintenance_state_input: SecretMaterial,
    source_ref_revalidator: Callable[[PublicationBundle | ActivationRequest], None],
    activation_receipt_path: Path,
    *,
    now: dt.datetime | Callable[[], dt.datetime] | None = None,
) -> CommandOutcome:
    """Activate the verified successor with an exact compare-and-swap operation."""

    if maintenance_state_input.purpose != _MAINTENANCE_STATE_PURPOSE:
        raise AdapterError("maintenance-state-protected-input-purpose-mismatch")
    if callable(now):
        clock = now
    elif isinstance(now, dt.datetime):
        clock = lambda: now
    else:
        clock = _utcnow
    generated_at = clock()
    request = _load_activation_request(
        successor_path,
        history_path,
        receipt_path,
        authorization_path,
        activation_authorization_path,
        expected_pointer_digest,
    )
    mutation_started = False
    operation = "created"
    observed_pointer_digest: str | None = None
    try:
        try:
            before = _normalize_pointer(operations.observe_latest_pointer(request))
        except Exception as exc:  # noqa: BLE001
            raise AdapterError("latest-pointer-observation-unavailable") from exc
        observed_pointer_digest = before.pointer_digest
        already_active = (
            before.status == "observed"
            and before.pointer_digest == request.activated_pointer_digest
            and before.active_baseline_digest == request.successor_digest
            and before.candidate_identity_digest
            == request.receipt.get("candidateIdentityDigest")
        )
        if already_active:
            source_ref_revalidator(request)
            _revalidate_activation_authorization(request, clock())
            operation = "verified-existing"
        else:
            if (
                before.status != "observed"
                or before.pointer_digest != expected_pointer_digest
            ):
                raise AdapterError("latest-pointer-compare-and-swap-conflict")
            source_ref_revalidator(request)
            _revalidate_activation_authorization(request, clock())
            mutation_started = True
            try:
                operations.activate_latest(request, maintenance_state_input)
            except Exception as exc:  # noqa: BLE001
                raise AdapterError("latest-pointer-activation-failed") from exc
        try:
            after = _normalize_pointer(operations.observe_latest_pointer(request))
        except Exception as exc:  # noqa: BLE001
            raise AdapterError("latest-pointer-post-activation-unavailable") from exc
        observed_pointer_digest = after.pointer_digest
        if (
            after.status != "observed"
            or after.pointer_digest != request.activated_pointer_digest
            or after.active_baseline_digest != request.successor_digest
            or after.candidate_identity_digest
            != request.receipt.get("candidateIdentityDigest")
        ):
            raise AdapterError("latest-pointer-post-activation-mismatch")
        artifact = {
            "schemaVersion": 1,
            "kind": "stable-1.0-maintenance-baseline-activation-receipt",
            "generatedAt": _timestamp(generated_at),
            "releaseId": request.receipt.get("releaseId"),
            "buildVersion": request.receipt.get("buildVersion"),
            "releaseClass": request.receipt.get("releaseClass"),
            "candidateIdentityDigest": request.receipt.get("candidateIdentityDigest"),
            "authorizationDigest": request.authorization_digest,
            "activationAuthorizationDigest": request.activation_authorization_digest,
            "successorBaselineDigest": request.successor_digest,
            "historyDigest": request.history_digest,
            "backportReleaseTrainDigest": request.activated_pointer.get(
                "backportReleaseTrainDigest"
            ),
            "expectedPreviousPointerDigest": expected_pointer_digest,
            "expectedActivatedPointerDigest": request.activated_pointer_digest,
            "observedPointerDigest": observed_pointer_digest,
            "operation": operation,
            "pointerUpdate": "activated",
            "status": "pass",
            "verificationStatus": "pass",
            "failureCategory": None,
            "redaction": dict(_PASS_REDACTION),
        }
        return CommandOutcome(True, {activation_receipt_path: artifact})
    except AdapterError as failure:
        artifact = {
            "schemaVersion": 1,
            "kind": "stable-1.0-maintenance-baseline-activation-receipt",
            "generatedAt": _timestamp(generated_at),
            "releaseId": request.receipt.get("releaseId"),
            "buildVersion": request.receipt.get("buildVersion"),
            "releaseClass": request.receipt.get("releaseClass"),
            "candidateIdentityDigest": request.receipt.get("candidateIdentityDigest"),
            "authorizationDigest": request.authorization_digest,
            "activationAuthorizationDigest": request.activation_authorization_digest,
            "successorBaselineDigest": request.successor_digest,
            "historyDigest": request.history_digest,
            "backportReleaseTrainDigest": request.activated_pointer.get(
                "backportReleaseTrainDigest"
            ),
            "expectedPreviousPointerDigest": expected_pointer_digest,
            "expectedActivatedPointerDigest": request.activated_pointer_digest,
            "observedPointerDigest": observed_pointer_digest,
            "operation": "partial" if mutation_started else "none",
            "pointerUpdate": "not-activated",
            "status": "fail",
            "verificationStatus": "fail",
            "failureCategory": failure.code,
            "redaction": dict(_PASS_REDACTION),
        }
        return CommandOutcome(False, {activation_receipt_path: artifact})


def _write_canonical(
    path: Path,
    value: Mapping[str, Any],
    protected_inputs: Sequence[SecretMaterial] = (),
) -> None:
    for protected_input in protected_inputs:
        _scan_public_value(value, secret=protected_input.value)
    data = _canonical_bytes(value)
    if any(
        protected_input.value.encode("utf-8") in data
        for protected_input in protected_inputs
    ):
        raise AdapterError("protected-input-leak")
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True)
    if parent.is_symlink() or path.is_symlink():
        raise AdapterError("unsafe-output-path")
    if path.exists():
        _regular_file(path)
        if path.read_bytes() == data:
            return
        raise AdapterError("refusing-to-overwrite-different-audit-output")
    descriptor, temporary_name = tempfile.mkstemp(
        dir=parent, prefix=f".{path.name}.", suffix=".tmp"
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
        os.chmod(temporary, 0o644)
        if path.is_symlink() or path.exists():
            raise AdapterError("unsafe-output-race")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _assert_execution_context(mode: str, environ: Mapping[str, str]) -> None:
    forbidden_markers = (
        "CRYPTAD_SELF_TEST",
        "CODEX_SELF_TEST",
        "PYTEST_CURRENT_TEST",
        "UNITTEST_CURRENT_TEST",
    )
    expected_job = {
        "preflight-only": "protected-publication",
        "publish-or-verify-exact": "protected-publication",
        "verify-public-state-only": "independent-verification",
        "activate-latest-baseline": "activate-latest-baseline",
    }[mode]
    workflow_ref = environ.get("GITHUB_WORKFLOW_REF", "")
    if (
        any(environ.get(marker) for marker in forbidden_markers)
        or environ.get("GITHUB_ACTIONS") != "true"
        or environ.get("GITHUB_EVENT_NAME") != "workflow_dispatch"
        or environ.get("GITHUB_REPOSITORY") != "crypta-network/cryptad"
        or WORKFLOW_PATH not in workflow_ref
        or environ.get("GITHUB_JOB") != expected_job
        or not re.fullmatch(r"refs/heads/(?:release|hotfix)/[1-9][0-9]*", environ.get("GITHUB_REF", ""))
    ):
        raise AdapterError("protected-workflow-context-required")


def _load_secret(
    name: str | None,
    expected_name: str,
    purpose: str,
    environ: Mapping[str, str],
) -> SecretMaterial:
    if name != expected_name:
        raise AdapterError("protected-input-environment-name-rejected")
    value = environ.get(name, "")
    if len(value) < 12 or "\x00" in value or "\n" in value or "\r" in value:
        raise AdapterError("protected-input-not-materialized")
    return SecretMaterial(purpose, value)


def _scrub_protected_input_environment(
    environ: Mapping[str, str],
) -> dict[str, str]:
    """Remove target-specific protected inputs before any provider code executes."""

    sanitized = dict(environ)
    for name in (
        CATALOG_INPUT_ENV,
        CORE_UPDATE_INPUT_ENV,
        MAINTENANCE_STATE_INPUT_ENV,
    ):
        sanitized.pop(name, None)
        os.environ.pop(name, None)
    return sanitized


def _make_remote_source_ref_revalidator(
    repository: str | None,
    branch: str | None,
    commit: str | None,
    token_environment_name: str | None,
    environ: Mapping[str, str],
    *,
    opener: Callable[..., Any] = urllib_request.urlopen,
) -> Callable[[PublicationBundle | ActivationRequest], None]:
    """Create a secret-safe GitHub ref verifier bound to the authorized source identity."""

    if (
        repository != SOURCE_REPOSITORY
        or not isinstance(branch, str)
        or not re.fullmatch(r"(?:release|hotfix)/[1-9][0-9]*", branch)
        or not isinstance(commit, str)
        or not _COMMIT_RE.fullmatch(commit)
        or token_environment_name != GITHUB_TOKEN_ENV
    ):
        raise AdapterError("remote-source-ref-command-binding-invalid")
    token = environ.get(GITHUB_TOKEN_ENV, "")
    if len(token) < 12 or any(character in token for character in "\x00\r\n"):
        raise AdapterError("remote-source-ref-token-not-materialized")

    def verify(record: PublicationBundle | ActivationRequest) -> None:
        if isinstance(record, PublicationBundle):
            record_branch = record.plan.get("sourceBranch")
            record_commit = record.plan.get("sourceCommit")
        else:
            record_commit = record.receipt.get("sourceCommit")
            record_branch = (
                f"release/{record.receipt.get('buildVersion')}"
                if record.receipt.get("releaseClass") == "maintenance"
                else f"hotfix/{record.receipt.get('buildVersion')}"
            )
        if record_branch != branch or record_commit != commit:
            raise AdapterError("remote-source-ref-artifact-binding-mismatch")

        encoded_branch = urllib_parse.quote(branch, safe="/")
        endpoint = (
            "https://api.github.com/repos/crypta-network/cryptad/git/ref/heads/"
            f"{encoded_branch}"
        )
        source_request = urllib_request.Request(
            endpoint,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {token}",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "cryptad-stable-maintenance-publication",
            },
            method="GET",
        )
        try:
            with opener(source_request, timeout=30) as response:
                status = getattr(response, "status", None)
                encoded = response.read(MAX_JSON_BYTES + 1)
        except Exception as exc:  # noqa: BLE001 - never expose request or token details
            raise AdapterError("remote-source-ref-observation-unavailable") from exc
        if status != 200 or len(encoded) > MAX_JSON_BYTES:
            raise AdapterError("remote-source-ref-observation-unavailable")
        payload = _strict_json_bytes(encoded, "remote-source-ref-response-malformed")
        observed_object = (
            payload.get("object") if isinstance(payload, Mapping) else None
        )
        if (
            not isinstance(observed_object, Mapping)
            or payload.get("ref") != f"refs/heads/{branch}"
            or observed_object.get("type") != "commit"
            or observed_object.get("sha") != commit
        ):
            raise AdapterError("remote-source-ref-moved")

    return verify


_BACKEND_METHODS = (
    "observe_public_state",
    "publish_target",
    "verify_publication",
    "observe_latest_pointer",
    "activate_latest",
)


def _path_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _authenticated_backend_site(environ: Mapping[str, str]) -> Path:
    raw_site = environ.get(BACKEND_SITE_ENV, "")
    supplied = Path(raw_site)
    if not raw_site or not supplied.is_absolute():
        raise AdapterError("protected-publication-backend-site-not-authenticated")
    try:
        resolved = supplied.resolve(strict=True)
    except OSError as exc:
        raise AdapterError(
            "protected-publication-backend-site-not-authenticated"
        ) from exc
    if supplied != resolved or not resolved.is_dir():
        raise AdapterError("protected-publication-backend-site-not-authenticated")
    return resolved


def _module_origin(module: ModuleType) -> Path | None:
    raw_origin = getattr(module, "__file__", None)
    if not isinstance(raw_origin, str) or not raw_origin:
        return None
    try:
        return Path(raw_origin).resolve(strict=True)
    except OSError:
        return None


def _module_is_from_site(module: ModuleType, site: Path) -> bool:
    origin = _module_origin(module)
    return origin is not None and _path_within(origin, site)


def _stdlib_roots() -> tuple[Path, ...]:
    roots: list[Path] = []
    for key in ("stdlib", "platstdlib"):
        value = sysconfig.get_path(key)
        if not value:
            continue
        resolved = Path(value).resolve()
        if resolved not in roots:
            roots.append(resolved)
    return tuple(roots)


_STDLIB_ROOTS = _stdlib_roots()


def _path_is_stdlib(path: Path) -> bool:
    for root in _STDLIB_ROOTS:
        if not _path_within(path, root):
            continue
        relative_parts = path.relative_to(root).parts
        if not {"site-packages", "dist-packages"}.intersection(relative_parts):
            return True
    return False


def _module_is_trusted_for_backend(module: ModuleType, site: Path) -> bool:
    if module is sys.modules.get(__name__):
        return True
    origin = _module_origin(module)
    if origin is not None:
        return _path_within(origin, site) or _path_is_stdlib(origin)
    spec = getattr(module, "__spec__", None)
    spec_origin = getattr(spec, "origin", None)
    if spec_origin in {"built-in", "frozen"}:
        return True
    namespace_paths = getattr(module, "__path__", None)
    if namespace_paths is None:
        return False
    resolved_paths: list[Path] = []
    try:
        for item in namespace_paths:
            resolved_paths.append(Path(item).resolve(strict=True))
    except (OSError, TypeError, ValueError):
        return False
    return bool(resolved_paths) and all(
        _path_within(path, site) or _path_is_stdlib(path) for path in resolved_paths
    )


def _trusted_backend_sys_path(site: Path) -> list[str]:
    trusted = [str(site)]
    for raw_path in sys.path:
        if not raw_path:
            continue
        candidate = Path(raw_path).resolve()
        if candidate == site or not _path_is_stdlib(candidate):
            continue
        rendered = str(candidate)
        if rendered not in trusted:
            trusted.append(rendered)
    return trusted


@contextlib.contextmanager
def _authenticated_backend_import_scope(site: Path) -> Iterator[None]:
    original_path = list(sys.path)
    original_modules = dict(sys.modules)
    removed_modules: dict[str, ModuleType] = {}
    for name, module in original_modules.items():
        if not isinstance(module, ModuleType):
            continue
        if not _module_is_trusted_for_backend(module, site):
            removed_modules[name] = module
            sys.modules.pop(name, None)
    sys.path[:] = _trusted_backend_sys_path(site)
    importlib.invalidate_caches()
    invalid_modules: list[str] = []
    try:
        yield
    finally:
        for name, module in tuple(sys.modules.items()):
            if not isinstance(module, ModuleType):
                continue
            if original_modules.get(name) is module:
                continue
            if not _module_is_trusted_for_backend(module, site):
                invalid_modules.append(name)
        for name in invalid_modules:
            sys.modules.pop(name, None)
        sys.path[:] = original_path
        importlib.invalidate_caches()
        for name, original in removed_modules.items():
            current = sys.modules.get(name)
            if current is None:
                sys.modules[name] = original
            elif not _module_is_trusted_for_backend(current, site):
                sys.modules[name] = original
        if invalid_modules:
            raise AdapterError("protected-publication-backend-origin-invalid")


def _require_site_module(module: ModuleType | None, site: Path) -> ModuleType:
    if module is None or not _module_is_from_site(module, site):
        raise AdapterError("protected-publication-backend-origin-invalid")
    return module


def _require_site_callable(value: Any, site: Path) -> Callable[..., Any]:
    if not callable(value):
        raise AdapterError("protected-publication-backend-contract-invalid")
    module = inspect.getmodule(value)
    if module is None and inspect.ismethod(value):
        module = inspect.getmodule(value.__func__)
    _require_site_module(module, site)
    return value


class _AuthenticatedBackend:
    """Invoke every provider method with checkout and global packages excluded."""

    def __init__(self, backend: ExternalOperations, site: Path) -> None:
        self._backend = backend
        self._site = site

    def __getattr__(self, name: str) -> Callable[..., Any]:
        if name not in _BACKEND_METHODS:
            raise AttributeError(name)

        def invoke(*args: Any, **kwargs: Any) -> Any:
            with _authenticated_backend_import_scope(self._site):
                _require_site_module(inspect.getmodule(type(self._backend)), self._site)
                operation = _require_site_callable(
                    getattr(self._backend, name, None), self._site
                )
                return operation(*args, **kwargs)

        return invoke


def _load_backend(environ: Mapping[str, str]) -> ExternalOperations:
    if any(
        name in environ or name in os.environ
        for name in (
            CATALOG_INPUT_ENV,
            CORE_UPDATE_INPUT_ENV,
            MAINTENANCE_STATE_INPUT_ENV,
        )
    ):
        raise AdapterError("protected-input-environment-not-scrubbed")
    factory_name = environ.get(BACKEND_FACTORY_ENV, "")
    if not _FACTORY_RE.fullmatch(factory_name):
        raise AdapterError("protected-publication-backend-not-materialized")
    site = _authenticated_backend_site(environ)
    module_name, attribute = factory_name.split(":", 1)
    try:
        with _authenticated_backend_import_scope(site):
            module = importlib.import_module(module_name)
            _require_site_module(module, site)
            factory = _require_site_callable(getattr(module, attribute, None), site)
            backend = factory()
            _require_site_module(inspect.getmodule(type(backend)), site)
            for name in _BACKEND_METHODS:
                _require_site_callable(getattr(backend, name, None), site)
    except Exception as exc:  # noqa: BLE001
        raise AdapterError("protected-publication-backend-load-failed") from exc
    return _AuthenticatedBackend(backend, site)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument(
        "--mode",
        required=True,
        choices=(
            "preflight-only",
            "publish-or-verify-exact",
            "verify-public-state-only",
            "activate-latest-baseline",
        ),
    )
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--catalog-input-env")
    parser.add_argument("--core-update-input-env")
    parser.add_argument("--maintenance-state-input-env")
    parser.add_argument("--no-protected-inputs", action="store_true")
    parser.add_argument("--expected-predecessor-pointer-digest")
    parser.add_argument("--expected-current-pointer-digest")
    parser.add_argument("--expected-source-repository")
    parser.add_argument("--expected-source-branch")
    parser.add_argument("--expected-source-commit")
    parser.add_argument("--github-token-env")
    parser.add_argument("--out", type=Path)
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--core-update-receipt", type=Path)
    parser.add_argument("--successor-baseline", type=Path)
    parser.add_argument("--history-entry", type=Path)
    parser.add_argument("--publication-receipt", type=Path)
    parser.add_argument("--authorization", type=Path)
    parser.add_argument("--activation-authorization", type=Path)
    parser.add_argument("--activation-receipt", type=Path)
    parser.add_argument("--idempotency", choices=("exact-match-only",))
    parser.add_argument("--conflict-action", choices=("fail",))
    parser.add_argument("--partial-state-action", choices=("record-only",))
    for name in (
        "check-latest-predecessor",
        "check-authorization-expiry",
        "check-exact-freeze-bytes",
        "check-tag-release-artifact-catalog-and-updater-conflicts",
        "recheck-remote-source-ref",
        "no-side-effects",
        "revalidate-before-each-mutation",
        "forbid-overwrite",
        "forbid-delete-recovery",
        "verify-annotated-tag",
        "verify-github-release-and-assets",
        "verify-artifact-base",
        "verify-stable-catalog-primary-mirrors-and-rollback",
        "verify-core-info-exact-bytes",
        "verify-every-core-info-package-reference",
        "forbid-unexpected-assets",
        "compare-and-swap",
        "forbid-overwrite-on-conflict",
        "verify-after-activation",
    ):
        parser.add_argument(f"--{name}", action="store_true")
    return parser


def _require(value: Any, code: str) -> Any:
    if value is None or value is False:
        raise AdapterError(code)
    return value


def _validate_mode_args(arguments: argparse.Namespace) -> None:
    mode = arguments.mode
    if mode == "preflight-only":
        for value in (
            arguments.bundle,
            arguments.no_protected_inputs,
            arguments.expected_predecessor_pointer_digest,
            arguments.out,
            arguments.check_latest_predecessor,
            arguments.check_authorization_expiry,
            arguments.check_exact_freeze_bytes,
            arguments.check_tag_release_artifact_catalog_and_updater_conflicts,
            arguments.no_side_effects,
        ):
            _require(value, "preflight-command-contract-incomplete")
        if arguments.idempotency != "exact-match-only" or arguments.conflict_action != "fail":
            raise AdapterError("preflight-command-policy-mismatch")
        if any(
            value is not None
            for value in (
                arguments.catalog_input_env,
                arguments.core_update_input_env,
                arguments.maintenance_state_input_env,
                arguments.authorization,
                arguments.activation_authorization,
            )
        ):
            raise AdapterError("preflight-protected-input-forbidden")
    elif mode == "publish-or-verify-exact":
        for value in (
            arguments.bundle,
            arguments.catalog_input_env,
            arguments.core_update_input_env,
            arguments.expected_predecessor_pointer_digest,
            arguments.expected_source_repository,
            arguments.expected_source_branch,
            arguments.expected_source_commit,
            arguments.github_token_env,
            arguments.recheck_remote_source_ref,
            arguments.receipt,
            arguments.core_update_receipt,
            arguments.revalidate_before_each_mutation,
            arguments.forbid_overwrite,
            arguments.forbid_delete_recovery,
        ):
            _require(value, "publication-command-contract-incomplete")
        if (
            arguments.idempotency != "exact-match-only"
            or arguments.conflict_action != "fail"
            or arguments.partial_state_action != "record-only"
        ):
            raise AdapterError("publication-command-policy-mismatch")
        if (
            arguments.maintenance_state_input_env is not None
            or arguments.authorization is not None
            or arguments.activation_authorization is not None
            or arguments.no_protected_inputs
        ):
            raise AdapterError("publication-protected-input-contract-mismatch")
    elif mode == "verify-public-state-only":
        for value in (
            arguments.bundle,
            arguments.no_protected_inputs,
            arguments.receipt,
            arguments.core_update_receipt,
            arguments.successor_baseline,
            arguments.history_entry,
            arguments.verify_annotated_tag,
            arguments.verify_github_release_and_assets,
            arguments.verify_artifact_base,
            arguments.verify_stable_catalog_primary_mirrors_and_rollback,
            arguments.verify_core_info_exact_bytes,
            arguments.verify_every_core_info_package_reference,
            arguments.forbid_unexpected_assets,
        ):
            _require(value, "verification-command-contract-incomplete")
        if any(
            value is not None
            for value in (
                arguments.catalog_input_env,
                arguments.core_update_input_env,
                arguments.maintenance_state_input_env,
                arguments.authorization,
                arguments.activation_authorization,
            )
        ):
            raise AdapterError("verification-protected-input-forbidden")
    else:
        for value in (
            arguments.maintenance_state_input_env,
            arguments.expected_current_pointer_digest,
            arguments.expected_source_repository,
            arguments.expected_source_branch,
            arguments.expected_source_commit,
            arguments.github_token_env,
            arguments.recheck_remote_source_ref,
            arguments.successor_baseline,
            arguments.history_entry,
            arguments.publication_receipt,
            arguments.authorization,
            arguments.activation_authorization,
            arguments.activation_receipt,
            arguments.check_authorization_expiry,
            arguments.compare_and_swap,
            arguments.forbid_overwrite_on_conflict,
            arguments.verify_after_activation,
        ):
            _require(value, "activation-command-contract-incomplete")
        if (
            arguments.catalog_input_env is not None
            or arguments.core_update_input_env is not None
            or arguments.no_protected_inputs
        ):
            raise AdapterError("activation-protected-input-contract-mismatch")


def main(
    argv: Sequence[str] | None = None,
    *,
    operations: ExternalOperations | None = None,
    source_ref_revalidator: Callable[
        [PublicationBundle | ActivationRequest], None
    ]
    | None = None,
    environ: Mapping[str, str] | None = None,
) -> int:
    """Execute one exact workflow-aligned adapter mode."""

    environment = dict(os.environ if environ is None else environ)
    protected_values: tuple[SecretMaterial, ...] = ()
    try:
        arguments = _parser().parse_args(argv)
        _assert_execution_context(arguments.mode, environment)
        _validate_mode_args(arguments)
        publication_inputs: PublicationProtectedInputs | None = None
        maintenance_state_input: SecretMaterial | None = None
        try:
            if arguments.mode == "publish-or-verify-exact":
                catalog_input = _load_secret(
                    arguments.catalog_input_env,
                    CATALOG_INPUT_ENV,
                    _CATALOG_PURPOSE,
                    environment,
                )
                core_update_input = _load_secret(
                    arguments.core_update_input_env,
                    CORE_UPDATE_INPUT_ENV,
                    _CORE_UPDATE_PURPOSE,
                    environment,
                )
                protected_values = (catalog_input, core_update_input)
                publication_inputs = PublicationProtectedInputs(
                    catalog_input, core_update_input
                )
            elif arguments.mode == "activate-latest-baseline":
                maintenance_state_input = _load_secret(
                    arguments.maintenance_state_input_env,
                    MAINTENANCE_STATE_INPUT_ENV,
                    _MAINTENANCE_STATE_PURPOSE,
                    environment,
                )
                protected_values = (maintenance_state_input,)
        finally:
            environment = _scrub_protected_input_environment(environment)
        backend = operations or _load_backend(environment)
        if arguments.mode == "preflight-only":
            outcome = preflight(
                arguments.bundle,
                arguments.expected_predecessor_pointer_digest,
                backend,
            )
            _write_canonical(arguments.out, outcome.artifact)
            return 0 if outcome.passed else 1
        if arguments.mode == "publish-or-verify-exact":
            active_source_ref_revalidator = (
                source_ref_revalidator
                or _make_remote_source_ref_revalidator(
                    arguments.expected_source_repository,
                    arguments.expected_source_branch,
                    arguments.expected_source_commit,
                    arguments.github_token_env,
                    environment,
                )
            )
            assert publication_inputs is not None
            outcome = publish_or_verify_exact(
                arguments.bundle,
                arguments.expected_predecessor_pointer_digest,
                backend,
                publication_inputs,
                active_source_ref_revalidator,
                arguments.receipt,
                arguments.core_update_receipt,
            )
        elif arguments.mode == "verify-public-state-only":
            outcome = verify_public_state(
                arguments.bundle,
                backend,
                arguments.receipt,
                arguments.core_update_receipt,
                arguments.successor_baseline,
                arguments.history_entry,
            )
        else:
            active_source_ref_revalidator = (
                source_ref_revalidator
                or _make_remote_source_ref_revalidator(
                    arguments.expected_source_repository,
                    arguments.expected_source_branch,
                    arguments.expected_source_commit,
                    arguments.github_token_env,
                    environment,
                )
            )
            assert maintenance_state_input is not None
            outcome = activate_latest_baseline(
                arguments.successor_baseline,
                arguments.history_entry,
                arguments.publication_receipt,
                arguments.authorization,
                arguments.activation_authorization,
                arguments.expected_current_pointer_digest,
                backend,
                maintenance_state_input,
                active_source_ref_revalidator,
                arguments.activation_receipt,
            )
        for path, value in outcome.artifacts.items():
            _write_canonical(path, value, protected_values)
        return 0 if outcome.passed else 1
    except AdapterError as exc:
        print(
            f"stable maintenance publication adapter failed closed: {exc.code}",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
