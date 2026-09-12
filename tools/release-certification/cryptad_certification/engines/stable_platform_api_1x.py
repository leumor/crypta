"""Verify Platform API 1.x compatibility operations without mutating release state.

The authority consumes only digest-bound local evidence.  It never activates a baseline, graduates
a descriptor, changes the runtime contract, publishes a release, or treats fixture evidence as an
operational receipt.
"""

from __future__ import annotations

import copy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
from typing import Any

from ..io import read_json, read_json_bytes, write_json, write_text
from ..redaction import scan_value
from ..schema_validation import validate_schema


EXECUTION_SCHEMA = "platform-api-1.x-execution-v1.schema.json"
SNAPSHOT_SCHEMA = "platform-api-contract-snapshot-envelope-v1.schema.json"
BASELINE_REGISTRY_SCHEMA = "platform-api-1.x-baseline-registry-v1.schema.json"
HISTORY_SCHEMA = "platform-api-1.x-history-ledger-v1.schema.json"
PROPOSAL_SCHEMA = "platform-api-1.x-baseline-proposal-v1.schema.json"
GRADUATION_SCHEMA = "platform-api-1.x-graduation-record-v1.schema.json"
DEPRECATION_SCHEMA = "platform-api-1.x-deprecation-ledger-v1.schema.json"
APP_SUBJECT_INVENTORY_SCHEMA = "platform-api-1.x-app-subject-inventory-v1.schema.json"
MATRIX_SCHEMA = "platform-api-1.x-app-compatibility-matrix-v1.schema.json"
RUNTIME_SCHEMA = "platform-api-1.x-runtime-observation-v1.schema.json"
LIFECYCLE_DESCRIPTOR_SCHEMA = "stable-1.0-support-lifecycle-descriptor-v1.schema.json"
LIFECYCLE_RECEIPT_SCHEMA = (
    "stable-1.0-support-lifecycle-publication-receipt-v1.schema.json"
)
SELECTED_RC_FREEZE_SCHEMA = "stable-1.0-rc-freeze-v1.schema.json"
SUMMARY_SCHEMA = "platform-api-1.x-summary-v1.schema.json"
POLICY_FILE = "platform-api-1.x-compatibility-policy.json"
SUMMARY_FILE = "platform-api-1.x-compatibility-summary.json"
REPORT_FILE = "platform-api-1.x-compatibility-report.md"
REDACTION_FILE = "platform-api-1.x-redaction-report.json"
ZERO_DIGEST = "sha256:" + "0" * 64

MODES = (
    "preflight",
    "verify-history",
    "verify-baseline-proposal",
    "verify-graduation",
    "verify-app-matrix",
    "verify-runtime",
    "closeout",
)
STAGES = ("preflight", "history", "proposal", "graduation", "matrix", "runtime", "roots")
OPERATIONAL_STATES = frozenset(
    {
        "history-authenticated",
        "app-matrix-verified",
        "baseline-proposal-reviewed",
        "runtime-compatibility-verified",
        "operational-1x-compatibility-complete",
    }
)
AUTHORITY_SCHEMAS = {
    "protectedRelease": "stable-1.0-protected-release-execution-summary-v1.schema.json",
    "independentReproducibility": "stable-1.0-independent-reproducibility-summary-v1.schema.json",
    "catalogAuthority": "stable-1.0-catalog-authority-summary-v1.schema.json",
    "thirdPartyPilot": "stable-1.0-third-party-app-pilot-summary-v1.schema.json",
    "federatedCatalog": "stable-1.0-federated-catalog-summary-v1.schema.json",
}
BASELINE_ID = re.compile(r"^1\.(?:0|[1-9][0-9]*)$")
FROZEN_1_0_ARTIFACT_DIGEST = (
    "297f09dbe3d0a9206dd7ea2b2e6ddfd1a05cf2af77951e81320e829330c89396"
)
FROZEN_1_0_DEFINITION_DIGEST = (
    "f94a06f06e929e655c4481bea92d02b90fbcac7b28f3628f5538dd073d5c71d6"
)
FROZEN_1_0_LINEAGE_DIGEST = (
    "3578b57e292a74dd023bc72d76f883b945e594e126d920a0f0af3fe148a24aba"
)
SUPPORTED_BASELINE_STATES = frozenset({"active", "deprecated"})
ACTIVATION_COORDINATE_FIELDS = (
    "activationRelease",
    "activationBuild",
    "supportStartedRelease",
)
MATRIX_SUBJECT_FIELDS = (
    "appId", "appVersion", "bundleDigest", "manifestDigest", "publisherId", "catalogId",
    "reviewDigest", "targetStability", "targetBaseline", "minimumContractVersion",
    "maximumTestedContractVersion", "requiredCapabilities", "optionalCapabilities",
    "experimentalCapabilitiesAccepted", "sourceAuthority", "fixtureOnly",
    "requiredForRelease",
)
MATRIX_SOURCE_ROOTS = {
    "first-party-release": "independentReproducibility",
    "third-party-pilot": "thirdPartyPilot",
    "federated-catalog": "federatedCatalog",
}
STABLE_COMPATIBILITY_STATES = frozenset(
    {"stable", "deprecated", "scheduled-for-removal"}
)
BASELINE_TRANSITIONS = {
    "proposed": frozenset({"candidate", "rejected"}),
    "candidate": frozenset({"reviewed", "rejected"}),
    "reviewed": frozenset({"documented", "rejected"}),
    "documented": frozenset({"active", "rejected"}),
    "active": frozenset({"deprecated"}),
    "deprecated": frozenset({"end-of-support"}),
    "end-of-support": frozenset(),
    "rejected": frozenset(),
}


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _digest_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _semantic_digest(value: dict[str, Any], field: str) -> str:
    normalized = copy.deepcopy(value)
    normalized[field] = ZERO_DIGEST
    return _digest_bytes(_canonical_bytes(normalized))


def _append_baseline_field(parts: list[str], value: Any) -> None:
    text = "" if value is None else str(value)
    java_length = len(text.encode("utf-16-le")) // 2
    parts.append(f"{java_length}:{text};")


def _baseline_definition_digest(definition: dict[str, Any]) -> str:
    parts = ["platform-api-baseline-definition-v1;"]
    _append_baseline_field(parts, definition["id"])
    _append_baseline_field(parts, definition["predecessorId"])
    parts.append(f"{definition['firstCompleteContractVersion']};")
    for field in (
        "sourceArtifactDigest", "proposalDigest", "reviewDigest", "documentationDigest"
    ):
        _append_baseline_field(parts, definition[field])
    for capability in definition["capabilities"]:
        _append_baseline_field(parts, capability)
    for endpoint in definition["endpoints"]:
        for field in ("id", "routeFamily", "actionLabel"):
            _append_baseline_field(parts, endpoint[field])
        parts.append(
            f"{str(endpoint['hostOperatorBypassAllowed']).lower()};"
            f"{str(endpoint['appProcessPrincipalsAllowed']).lower()};"
            f"{str(endpoint['appBrowserPrincipalsAllowed']).lower()};"
        )
        for capability in endpoint["requiredCapabilities"]:
            _append_baseline_field(parts, capability)
    return hashlib.sha256("".join(parts).encode("utf-8")).hexdigest()


def _baseline_lineage_digest(lineage: dict[str, Any]) -> str:
    parts = ["platform-api-baseline-lineage-v1;"]
    for field in (
        "id", "definitionDigest", "status", "evidenceKind", "evidenceDigest",
        "activationRelease", "activationBuild", "supportStartedRelease", "supportEndedRelease",
        "previousLineageDigest",
    ):
        _append_baseline_field(parts, lineage[field])
    return hashlib.sha256("".join(parts).encode("utf-8")).hexdigest()


def _baseline_registry_digest(registry: dict[str, Any]) -> str:
    parts = [f"platform-api-baseline-registry-v1;{registry['schemaVersion']};"]
    for definition in registry["definitions"]:
        _append_baseline_field(parts, definition["id"])
        _append_baseline_field(parts, definition["definitionDigest"])
    for lineage in registry["lineage"]:
        _append_baseline_field(parts, lineage["lineageDigest"])
    return hashlib.sha256("".join(parts).encode("utf-8")).hexdigest()


def _baseline_id_key(value: str) -> tuple[int, int]:
    match = BASELINE_ID.fullmatch(value)
    if match is None:
        return (2**31, 2**31)
    major, minor = value.split(".", 1)
    return int(major), int(minor)


def _java_string_key(value: str) -> bytes:
    return value.encode("utf-16-be")


def _baseline_definition_errors(
    definition: dict[str, Any], index: int
) -> list[str]:
    errors: list[str] = []
    baseline_id = definition["id"]
    predecessor = definition["predecessorId"]
    baseline_key = _baseline_id_key(baseline_id)
    if baseline_key[1] > 2_147_483_647:
        errors.append(f"baseline registry definition {index} identity exceeds Java integer range")
    if baseline_id == "1.0" and predecessor is not None:
        errors.append("baseline registry 1.0 definition cannot name a predecessor")
    if baseline_id != "1.0" and predecessor is None:
        errors.append(f"baseline registry definition {baseline_id} requires a predecessor")
    if predecessor is not None and _baseline_id_key(predecessor) >= baseline_key:
        errors.append(
            f"baseline registry definition {baseline_id} predecessor is not earlier"
        )
    if baseline_id != "1.0" and definition["proposalDigest"] is None:
        errors.append(
            f"baseline registry definition {baseline_id} requires proposal evidence"
        )
    capabilities = definition["capabilities"]
    canonical_capabilities = sorted(set(capabilities), key=_java_string_key)
    if capabilities != canonical_capabilities or any(
        capability != capability.strip() or not capability.strip()
        for capability in capabilities
    ):
        errors.append(
            f"baseline registry definition {baseline_id} capabilities are not canonical and unique"
        )
    endpoints = definition["endpoints"]
    endpoint_ids = [endpoint["id"] for endpoint in endpoints]
    if endpoint_ids != sorted(set(endpoint_ids), key=_java_string_key):
        errors.append(
            f"baseline registry definition {baseline_id} endpoints are not canonical and unique"
        )
    capability_set = set(capabilities)
    for endpoint in endpoints:
        if any(
            endpoint[field] != endpoint[field].strip() or not endpoint[field].strip()
            for field in ("id", "routeFamily", "actionLabel")
        ):
            errors.append(
                f"baseline registry endpoint {endpoint['id']} text is not canonical"
            )
        required = endpoint["requiredCapabilities"]
        if required != sorted(set(required), key=_java_string_key) or any(
            capability != capability.strip() or not capability.strip()
            for capability in required
        ):
            errors.append(
                f"baseline registry endpoint {endpoint['id']} requirements are not canonical and unique"
            )
        if not capability_set.issuperset(required):
            errors.append(
                f"baseline registry endpoint {endpoint['id']} requires a capability outside its definition"
            )
        if not (
            endpoint["appProcessPrincipalsAllowed"]
            or endpoint["appBrowserPrincipalsAllowed"]
        ):
            errors.append(
                f"baseline registry endpoint {endpoint['id']} allows no app principal"
            )
    if definition["firstCompleteContractVersion"] > 2_147_483_647:
        errors.append(
            f"baseline registry definition {baseline_id} contract version exceeds Java integer range"
        )
    if definition["definitionDigest"] != _baseline_definition_digest(definition):
        errors.append(f"baseline registry definition {index} self digest is invalid")
    return errors


def _baseline_lineage_evidence_errors(item: dict[str, Any], index: int) -> list[str]:
    errors: list[str] = []
    status = item["status"]
    evidence_kind = item["evidenceKind"]
    for field in (
        "activationRelease",
        "supportStartedRelease",
        "supportEndedRelease",
    ):
        value = item[field]
        if value is not None and (value != value.strip() or not value.strip()):
            errors.append(
                f"baseline registry lineage {index} {field} is not canonical"
            )
    if evidence_kind == "fixture" and (
        status in SUPPORTED_BASELINE_STATES or status == "end-of-support"
    ):
        errors.append(
            f"baseline registry lineage {index} fixture evidence establishes an operational state"
        )
    if (
        status not in SUPPORTED_BASELINE_STATES
        and status != "end-of-support"
        and any(item[field] is not None for field in ACTIVATION_COORDINATE_FIELDS)
    ):
        errors.append(
            f"baseline registry lineage {index} carries activation coordinates before activation"
        )
    if evidence_kind == "imported-frozen-baseline" and not (
        item["id"] == "1.0"
        and status == "active"
        and item["definitionDigest"] == FROZEN_1_0_DEFINITION_DIGEST
        and item["evidenceDigest"] == FROZEN_1_0_ARTIFACT_DIGEST
    ):
        errors.append(
            f"baseline registry lineage {index} misuses imported frozen evidence"
        )
    if status in SUPPORTED_BASELINE_STATES and evidence_kind == "protected-release":
        if (
            item["activationRelease"] is None
            or item["activationBuild"] is None
            or item["supportStartedRelease"] is None
        ) and not (
            item["id"] == "1.0"
            and status == "deprecated"
            and all(item[field] is None for field in ACTIVATION_COORDINATE_FIELDS)
        ):
            errors.append(
                f"baseline registry lineage {index} protected activation coordinates are incomplete"
            )
    if status == "end-of-support" and item["supportEndedRelease"] is None:
        errors.append(
            f"baseline registry lineage {index} end-of-support evidence is incomplete"
        )
    if status != "end-of-support" and item["supportEndedRelease"] is not None:
        errors.append(
            f"baseline registry lineage {index} carries an invalid support-end coordinate"
        )
    return errors


def _baseline_registry_errors(
    envelope: dict[str, Any],
    contract: dict[str, Any],
    fixture: bool,
    policy: dict[str, Any] | None = None,
) -> list[str]:
    del fixture
    registry = envelope["baselineRegistry"]
    errors: list[str] = []
    definitions = registry["definitions"]
    lineage = registry["lineage"]
    definition_by_id: dict[str, dict[str, Any]] = {}
    definition_ids = [definition["id"] for definition in definitions]
    if definition_ids != sorted(set(definition_ids), key=_baseline_id_key):
        errors.append("baseline registry definitions are not in canonical semantic order")
    for index, definition in enumerate(definitions):
        baseline_id = definition["id"]
        if baseline_id in definition_by_id:
            errors.append(f"baseline registry duplicates definition {baseline_id}")
        definition_by_id[baseline_id] = definition
        errors.extend(_baseline_definition_errors(definition, index))
    for definition in definitions:
        predecessor = definition["predecessorId"]
        if predecessor is not None and predecessor not in definition_by_id:
            errors.append(f"baseline registry definition {definition['id']} has unknown predecessor")
    for definition in definitions:
        visited: set[str] = set()
        current = definition
        while current["predecessorId"] is not None:
            if current["id"] in visited:
                errors.append("baseline registry predecessor lineage contains a cycle")
                break
            visited.add(current["id"])
            predecessor = definition_by_id.get(current["predecessorId"])
            if predecessor is None:
                break
            current = predecessor

    latest_lineage: dict[str, dict[str, Any]] = {}
    seen_lineage_digests: set[str] = set()
    for index, item in enumerate(lineage):
        definition = definition_by_id.get(item["id"])
        if definition is None or item["definitionDigest"] != definition["definitionDigest"]:
            errors.append(f"baseline registry lineage {index} does not bind its definition")
        if item["lineageDigest"] in seen_lineage_digests:
            errors.append(f"baseline registry lineage {index} duplicates a lifecycle digest")
        seen_lineage_digests.add(item["lineageDigest"])
        previous = latest_lineage.get(item["id"])
        if previous is None:
            if item["previousLineageDigest"] is not None:
                errors.append(
                    f"baseline registry lineage {index} first record names a predecessor"
                )
            if (
                item["evidenceKind"] != "imported-frozen-baseline"
                and item["status"] != "proposed"
            ):
                errors.append(
                    f"baseline registry lineage {index} does not begin at proposed"
                )
        else:
            if item["previousLineageDigest"] != previous["lineageDigest"]:
                errors.append(f"baseline registry lineage {index} is not gap-free")
            if item["status"] not in BASELINE_TRANSITIONS[previous["status"]]:
                errors.append(
                    f"baseline registry lineage {index} has illegal transition "
                    f"{previous['status']} -> {item['status']}"
                )
            if previous["status"] in SUPPORTED_BASELINE_STATES and any(
                item[field] != previous[field]
                for field in ACTIVATION_COORDINATE_FIELDS
            ):
                errors.append(
                    f"baseline registry lineage {index} changes immutable activation coordinates"
                )
        errors.extend(_baseline_lineage_evidence_errors(item, index))
        activatable = set(
            (policy or {}).get("operationallyActivatableBaselines", ["1.0"])
        )
        if (
            item["id"] not in activatable
            and item["status"] in {"active", "deprecated", "end-of-support"}
        ):
            errors.append(
                f"baseline registry lineage {index} future baseline operational lifecycle "
                "lacks an authenticated activation authority"
            )
        if item["lineageDigest"] != _baseline_lineage_digest(item):
            errors.append(f"baseline registry lineage {index} self digest is invalid")
        latest_lineage[item["id"]] = item
    missing_lifecycle = set(definition_by_id).difference(latest_lineage)
    for baseline_id in sorted(missing_lifecycle, key=_baseline_id_key):
        errors.append(f"baseline registry definition {baseline_id} has no lifecycle evidence")

    frozen = definition_by_id.get("1.0")
    genesis = lineage[0] if lineage else None
    if (
        frozen is None
        or frozen["sourceArtifactDigest"] != FROZEN_1_0_ARTIFACT_DIGEST
        or frozen["definitionDigest"] != FROZEN_1_0_DEFINITION_DIGEST
    ):
        errors.append("baseline registry does not contain the exact frozen 1.0 definition")
    if (
        genesis is None
        or genesis["id"] != "1.0"
        or genesis["status"] != "active"
        or genesis["evidenceKind"] != "imported-frozen-baseline"
        or genesis["definitionDigest"] != FROZEN_1_0_DEFINITION_DIGEST
        or genesis["evidenceDigest"] != FROZEN_1_0_ARTIFACT_DIGEST
        or genesis["lineageDigest"] != FROZEN_1_0_LINEAGE_DIGEST
    ):
        errors.append("baseline registry genesis is not the exact frozen 1.0 import")

    for candidate in definitions:
        candidate_key = _baseline_id_key(candidate["id"])
        for predecessor in definitions:
            predecessor_id = predecessor["id"]
            if _baseline_id_key(predecessor_id) >= candidate_key:
                continue
            predecessor_state = latest_lineage.get(predecessor_id)
            if (
                predecessor_state is not None
                and predecessor_state["status"] in SUPPORTED_BASELINE_STATES
            ):
                missing_capabilities = set(predecessor["capabilities"]).difference(
                    candidate["capabilities"]
                )
                if missing_capabilities:
                    errors.append(
                        f"baseline registry definition {candidate['id']} omits a supported predecessor capability"
                    )
                candidate_endpoints = {
                    endpoint["id"]: endpoint for endpoint in candidate["endpoints"]
                }
                for endpoint in predecessor["endpoints"]:
                    inherited = candidate_endpoints.get(endpoint["id"])
                    if inherited is None:
                        errors.append(
                            f"baseline registry definition {candidate['id']} omits a supported predecessor endpoint"
                        )
                    elif inherited != endpoint:
                        errors.append(
                            f"baseline registry definition {candidate['id']} changes inherited endpoint semantics"
                        )

    if registry["registryDigest"] != _baseline_registry_digest(registry):
        errors.append("baseline registry self digest is invalid")
    supported = sorted(
        (
            baseline_id
            for baseline_id, item in latest_lineage.items()
            if item["status"] in SUPPORTED_BASELINE_STATES
        ),
        key=_baseline_id_key,
    )
    if contract["activeStableBaselines"] != supported:
        errors.append("baseline registry supported set differs from the execution contract")
    activatable = sorted(
        (policy or {}).get("operationallyActivatableBaselines", ["1.0"]),
        key=_baseline_id_key,
    )
    if contract["activeStableBaselines"] != activatable:
        errors.append(
            "execution supported baselines exceed this authority version's authenticated "
            "activation set"
        )
    for baseline_id in supported:
        definition = definition_by_id[baseline_id]
        if definition["firstCompleteContractVersion"] > contract["contractVersion"]:
            errors.append(
                f"supported baseline {baseline_id} is newer than the execution contract"
            )
    return errors


def _historical_baseline_registry_errors(
    envelope: dict[str, Any],
    contract_version: int,
    fixture: bool,
    policy: dict[str, Any],
) -> list[str]:
    """Validate a predecessor registry without binding it to the current release subject."""

    latest_status: dict[str, str] = {}
    for lineage in envelope["baselineRegistry"]["lineage"]:
        latest_status[lineage["id"]] = lineage["status"]
    supported = sorted(
        (
            baseline_id
            for baseline_id, status in latest_status.items()
            if status in SUPPORTED_BASELINE_STATES
        ),
        key=_baseline_id_key,
    )
    historical_contract = {
        "activeStableBaselines": supported,
        "contractVersion": contract_version,
    }
    return _baseline_registry_errors(
        envelope, historical_contract, fixture, policy
    )


def _timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{label} is missing or malformed")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{label} is malformed") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{label} has no timezone offset")
    return parsed.astimezone(timezone.utc)


def _confined_path(root: Path, requested: Path, label: str, *, directory: bool) -> Path:
    candidate = requested if requested.is_absolute() else root / requested
    try:
        relative = candidate.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"{label} is outside the workspace") from exc
    current = root
    for part in relative.parts:
        current /= part
        if current.is_symlink():
            raise ValueError(f"{label} contains a symlink")
    resolved = candidate.resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError as exc:
        raise ValueError(f"{label} escapes the workspace") from exc
    if directory:
        if not resolved.is_dir():
            raise ValueError(f"{label} is not a directory")
    elif not resolved.is_file():
        raise ValueError(f"{label} is not a regular file")
    return resolved


def _policy(workspace: Path) -> tuple[dict[str, Any], str]:
    path = workspace / "tools/release-certification" / POLICY_FILE
    value = read_json(path)
    if not isinstance(value, dict):
        raise ValueError("Platform API 1.x policy is not an object")
    if scan_value(value):
        raise ValueError("Platform API 1.x policy contains prohibited material")
    if value.get("operationallyActivatableBaselines") != ["1.0"]:
        raise ValueError(
            "Platform API 1.x policy does not preserve the closed 1.0 activation boundary"
        )
    producer_fields = {
        "workflowPath", "jobName", "environment", "summaryFileName", "artifactNamePrefix"
    }
    for name in ("supportLifecycleProducer", "runtimeObservationProducer"):
        producer = value.get(name)
        if not isinstance(producer, dict) or set(producer) != producer_fields:
            raise ValueError(f"Platform API 1.x policy {name} is not closed")
    return value, _digest_bytes(path.read_bytes())


def _output_directory(workspace: Path, requested: Path) -> Path:
    candidate = requested if requested.is_absolute() else workspace / requested
    try:
        candidate.relative_to(workspace)
    except ValueError as exc:
        raise ValueError("Platform API 1.x output is outside the workspace") from exc
    parent = candidate.parent.resolve()
    try:
        parent.relative_to(workspace.resolve())
    except ValueError as exc:
        raise ValueError("Platform API 1.x output escapes the workspace") from exc
    if candidate.is_symlink():
        raise ValueError("Platform API 1.x output is a symlink")
    candidate.mkdir(parents=True, exist_ok=True)
    return candidate.resolve()


def _bound_json(
    evidence_dir: Path | None,
    binding: dict[str, Any] | None,
    schema: str,
    label: str,
) -> tuple[dict[str, Any] | None, list[str]]:
    if binding is None:
        return None, [f"{label} is not bound"]
    if evidence_dir is None:
        return None, [f"{label} requires a confined evidence directory"]
    try:
        path = _confined_path(evidence_dir, evidence_dir / binding["fileName"], label, directory=False)
        encoded = path.read_bytes()
        if len(encoded) != binding["size"]:
            return None, [f"{label} size differs from its binding"]
        if _digest_bytes(encoded) != binding["digest"]:
            return None, [f"{label} digest differs from its binding"]
        value = read_json_bytes(encoded, label)
    except (OSError, ValueError) as exc:
        return None, [str(exc)]
    if not isinstance(value, dict):
        return None, [f"{label} is not a JSON object"]
    errors = validate_schema(value, schema)
    if scan_value(value):
        errors.append("contains prohibited or unredacted material")
    return value, [f"{label}: {error}" for error in errors]


def _optional_bound_json(
    evidence_dir: Path | None,
    binding: dict[str, Any] | None,
    schema: str,
    label: str,
) -> tuple[dict[str, Any] | None, list[str]]:
    if binding is None:
        return None, []
    return _bound_json(evidence_dir, binding, schema, label)


def _snapshot_endpoint_semantics(endpoint: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": f"{endpoint['method']} {endpoint['routeTemplate']}",
        "routeFamily": endpoint["routeFamily"],
        "actionLabel": endpoint["actionLabel"],
        "requiredCapabilities": sorted(
            endpoint["requiredCapabilities"], key=_java_string_key
        ),
        "hostOperatorBypassAllowed": endpoint["hostOperatorBypassAllowed"],
        "appProcessPrincipalsAllowed": endpoint["appProcessPrincipalsAllowed"],
        "appBrowserPrincipalsAllowed": endpoint["appBrowserPrincipalsAllowed"],
    }


def _expected_baseline_registry_summary(
    registry: dict[str, Any],
) -> dict[str, Any]:
    definitions = {
        definition["id"]: definition for definition in registry["definitions"]
    }
    latest: dict[str, dict[str, Any]] = {}
    for lineage in registry["lineage"]:
        latest[lineage["id"]] = lineage
    supported = sorted(
        (
            baseline_id
            for baseline_id, lineage in latest.items()
            if lineage["status"] in SUPPORTED_BASELINE_STATES
        ),
        key=_baseline_id_key,
    )
    return {
        "schemaVersion": registry["schemaVersion"],
        "registryDigest": registry["registryDigest"],
        "supportedBaselines": [
            {
                "id": baseline_id,
                "status": latest[baseline_id]["status"],
                "definitionDigest": definitions[baseline_id]["definitionDigest"],
            }
            for baseline_id in supported
        ],
    }


def _record_baseline_registry_digest(registry_envelope: dict[str, Any]) -> str:
    """Return the history-record form of a registry's semantic digest."""

    return "sha256:" + registry_envelope["baselineRegistry"]["registryDigest"]


def _snapshot_baseline_errors(
    snapshot_contract: dict[str, Any],
    registry_envelope: dict[str, Any] | None,
    label: str,
    *,
    require_supported_complete: bool = False,
    require_current_registry_summary: bool = True,
) -> list[str]:
    if registry_envelope is None:
        return [f"{label} cannot be verified without the accepted baseline registry"]
    errors: list[str] = []
    registry = registry_envelope["baselineRegistry"]
    definitions = {
        definition["id"]: definition for definition in registry["definitions"]
    }
    latest_status: dict[str, str] = {}
    for lineage in registry["lineage"]:
        latest_status[lineage["id"]] = lineage["status"]

    registry_summary = snapshot_contract.get("baselineRegistrySummary")
    if snapshot_contract["contractVersion"] >= 24 and registry_summary is None:
        errors.append(f"{label} version 24 or later omits its baseline registry summary")
    elif (
        registry_summary is not None
        and require_current_registry_summary
        and registry_summary != _expected_baseline_registry_summary(registry)
    ):
        errors.append(f"{label} baseline registry summary differs from the accepted registry")

    summary_status: dict[str, str] = {}
    if registry_summary is not None:
        for item in registry_summary["supportedBaselines"]:
            baseline_id = item["id"]
            definition = definitions.get(baseline_id)
            if definition is None:
                errors.append(
                    f"{label} registry summary names an unknown baseline: {baseline_id}"
                )
                continue
            if item["definitionDigest"] != definition["definitionDigest"]:
                errors.append(
                    f"{label} registry summary definition digest differs: {baseline_id}"
                )
            summary_status[baseline_id] = item["status"]

    if not require_current_registry_summary:
        historical_ids = set(summary_status)
        historical_ids.add(snapshot_contract["stableBaseline"]["name"])
        definitions = {
            baseline_id: definition
            for baseline_id, definition in definitions.items()
            if baseline_id in historical_ids
        }
        latest_status = summary_status
        latest_status.setdefault(snapshot_contract["stableBaseline"]["name"], "active")

    capabilities: dict[str, dict[str, Any]] = {}
    for descriptor in snapshot_contract["capabilities"]:
        name = descriptor["name"]
        if name in capabilities:
            errors.append(f"{label} duplicates capability descriptor {name}")
        else:
            capabilities[name] = descriptor
    endpoints: dict[str, dict[str, Any]] = {}
    for descriptor in snapshot_contract["endpoints"]:
        identity = f"{descriptor['method']} {descriptor['routeTemplate']}"
        if identity in endpoints:
            errors.append(f"{label} duplicates endpoint descriptor {identity}")
        else:
            endpoints[identity] = descriptor

    stable_baseline = snapshot_contract["stableBaseline"]
    stable_definition = definitions.get(stable_baseline["name"])
    if stable_definition is None:
        errors.append(f"{label} stable baseline has no registry definition")
    else:
        if (
            stable_baseline["contractVersion"]
            != stable_definition["firstCompleteContractVersion"]
        ):
            errors.append(f"{label} stable baseline contract version differs from its definition")
        if stable_baseline["capabilities"] != stable_definition["capabilities"]:
            errors.append(f"{label} stable baseline capability membership differs from its definition")
        expected_endpoints = [
            endpoint["id"] for endpoint in stable_definition["endpoints"]
        ]
        if stable_baseline["endpoints"] != expected_endpoints:
            errors.append(f"{label} stable baseline endpoint membership differs from its definition")
    if stable_baseline["capabilityCount"] != len(stable_baseline["capabilities"]):
        errors.append(f"{label} stable baseline capability count differs")
    if stable_baseline["endpointCount"] != len(stable_baseline["endpoints"]):
        errors.append(f"{label} stable baseline endpoint count differs")

    snapshot_version = snapshot_contract["contractVersion"]
    for baseline_id, definition in definitions.items():
        lifecycle_status = latest_status.get(baseline_id)
        if lifecycle_status in {"end-of-support", "rejected"}:
            # Terminal definitions remain immutable history subjects, but no longer force their
            # descriptors to remain in a later live contract snapshot.
            continue
        if definition["firstCompleteContractVersion"] > snapshot_version:
            if (
                require_supported_complete
                and lifecycle_status in SUPPORTED_BASELINE_STATES
            ):
                errors.append(
                    f"{label} claims supported baseline {baseline_id} before its complete contract version"
                )
            continue
        requires_stable_coverage = (
            baseline_id == "1.0"
            or lifecycle_status in SUPPORTED_BASELINE_STATES
        )
        for name in definition["capabilities"]:
            descriptor = capabilities.get(name)
            if descriptor is None:
                errors.append(f"{label} baseline capability descriptor is missing: {name}")
                continue
            if (
                descriptor["sinceContractVersion"]
                > definition["firstCompleteContractVersion"]
            ):
                errors.append(
                    f"{label} baseline capability {name} was introduced after its "
                    "claimed complete contract version"
                )
            if descriptor["audience"] != "app" or descriptor["stability"] in {
                "operator-only",
                "internal",
            }:
                errors.append(f"{label} baseline capability descriptor is restricted: {name}")
            if requires_stable_coverage and descriptor["stability"] not in STABLE_COMPATIBILITY_STATES:
                errors.append(
                    f"{label} supported baseline capability is not stable-compatibility-covered: {name}"
                )
            if baseline_id == "1.0" and (
                not descriptor["stableBaselineMember"]
                or descriptor["stableBaseline"] != "1.0"
                or descriptor["sinceContractVersion"] > 19
            ):
                errors.append(f"{label} frozen 1.0 capability membership changed: {name}")
        for expected in definition["endpoints"]:
            identity = expected["id"]
            descriptor = endpoints.get(identity)
            if descriptor is None:
                errors.append(f"{label} baseline endpoint descriptor is missing: {identity}")
                continue
            if (
                descriptor["sinceContractVersion"]
                > definition["firstCompleteContractVersion"]
            ):
                errors.append(
                    f"{label} baseline endpoint {identity} was introduced after its "
                    "claimed complete contract version"
                )
            if (
                descriptor["audience"] != "app"
                or descriptor["stability"] in {"operator-only", "internal"}
                or not (
                    descriptor["appProcessPrincipalsAllowed"]
                    or descriptor["appBrowserPrincipalsAllowed"]
                )
            ):
                errors.append(f"{label} baseline endpoint descriptor is restricted: {identity}")
            if _snapshot_endpoint_semantics(descriptor) != expected:
                errors.append(f"{label} baseline endpoint semantics changed: {identity}")
            if requires_stable_coverage and descriptor["stability"] not in STABLE_COMPATIBILITY_STATES:
                errors.append(
                    f"{label} supported baseline endpoint is not stable-compatibility-covered: {identity}"
                )
            if baseline_id == "1.0" and (
                not descriptor["stableBaselineMember"]
                or descriptor["stableBaseline"] != "1.0"
                or descriptor["sinceContractVersion"] > 19
            ):
                errors.append(f"{label} frozen 1.0 endpoint membership changed: {identity}")
    return errors


def _history_errors(
    ledger: dict[str, Any],
    evidence_dir: Path | None,
    contract: dict[str, Any],
    baseline_registry: dict[str, Any] | None,
    baseline_registry_binding: dict[str, Any] | None,
    fixture: bool,
    evaluation: datetime,
    policy: dict[str, Any],
    *,
    bind_execution_head: bool = True,
) -> list[str]:
    errors: list[str] = []
    records = ledger["records"]
    release_keys: set[tuple[str, int]] = set()
    prior: dict[str, Any] | None = None
    for index, record in enumerate(records):
        label = f"history record {index}"
        if record["selfDigest"] != _semantic_digest(record, "selfDigest"):
            errors.append(f"{label} self digest is invalid")
        if not fixture and record["fixtureOnly"]:
            errors.append(f"{label} fixture record cannot enter production history")
        if not fixture:
            provenance = record["provenance"]
            if (
                provenance["repositoryIdentity"] != policy["repositoryIdentity"]
                or provenance["workflowCommit"] != record["sourceCommit"]
                or provenance["artifactDigest"] == ZERO_DIGEST
            ):
                errors.append(f"{label} provenance is not the protected release subject")
        generated_at = _timestamp(record["generatedAt"], f"{label} generatedAt")
        if generated_at > evaluation:
            errors.append(f"{label} is future-dated")
        published_at = (
            None
            if record["publishedAt"] is None
            else _timestamp(record["publishedAt"], f"{label} publishedAt")
        )
        if published_at is not None:
            if published_at > evaluation:
                errors.append(f"{label} publication is future-dated")
            if published_at < generated_at:
                errors.append(f"{label} publication predates its generation")
        key = (record["releaseId"], record["buildVersion"])
        if key in release_keys:
            errors.append(f"{label} duplicates a release/build identity")
        release_keys.add(key)
        if prior is None:
            if record["predecessorRecordDigest"] is not None or record["recordStatus"] != "imported":
                errors.append("history genesis must be an explicit import without a predecessor")
        else:
            prior_generated_at = _timestamp(
                prior["generatedAt"], f"history record {index - 1} generatedAt"
            )
            if generated_at <= prior_generated_at:
                errors.append(f"{label} generatedAt does not follow its predecessor")
            if record["predecessorRecordDigest"] != prior["selfDigest"]:
                errors.append(f"{label} predecessor digest is not gap-free")
            if record["contractVersion"] < prior["contractVersion"]:
                errors.append(f"{label} regresses the contract version")
            same_contract = record["contractVersion"] == prior["contractVersion"]
            same_snapshot = record["contractSnapshot"]["digest"] == prior["contractSnapshot"]["digest"]
            if same_contract and not same_snapshot:
                errors.append(f"{label} changes snapshot bytes without advancing contract version")
            if not same_contract and same_snapshot:
                errors.append(f"{label} advances contract version without changed snapshot bytes")
        snapshot, item_errors = _bound_json(
            evidence_dir,
            record["contractSnapshot"],
            SNAPSHOT_SCHEMA,
            f"{label} contract snapshot",
        )
        errors.extend(item_errors)
        if snapshot is not None and not item_errors:
            snapshot_contract = snapshot["contract"]
            if snapshot_contract["apiVersion"] != record["urlApiVersion"]:
                errors.append(f"{label} URL API version differs from its snapshot")
            if snapshot_contract["contractVersion"] != record["contractVersion"]:
                errors.append(f"{label} contract version differs from its snapshot")
            window = snapshot_contract["compatibilityWindow"]
            baseline = snapshot_contract["stableBaseline"]
            if window["currentContractVersion"] != record["contractVersion"]:
                errors.append(f"{label} compatibility window differs from its contract version")
            if window["baselineName"] != baseline["name"]:
                errors.append(f"{label} compatibility window baseline differs from its snapshot")
            if window["baselineContractVersion"] != baseline["contractVersion"]:
                errors.append(f"{label} compatibility window baseline version differs")
            if record["compatibilityWindowDigest"] != _digest_bytes(_canonical_bytes(window)):
                errors.append(f"{label} compatibility-window digest differs from its snapshot")
            registry_summary = snapshot_contract.get("baselineRegistrySummary")
            if registry_summary is not None and record["baselineRegistryDigest"] != (
                "sha256:" + registry_summary["registryDigest"]
            ):
                errors.append(
                    f"{label} baseline-registry digest differs from its snapshot summary"
                )
            errors.extend(
                _snapshot_baseline_errors(
                    snapshot_contract,
                    baseline_registry,
                    label,
                    require_supported_complete=(
                        bind_execution_head and index == len(records) - 1
                    ),
                    require_current_registry_summary=(
                        bind_execution_head and index == len(records) - 1
                    ),
                )
            )
        prior = record
    if not records or ledger["headRecordDigest"] != records[-1]["selfDigest"]:
        errors.append("history ledger head does not bind the final record")
    record_digests = {record["selfDigest"] for record in records}
    if ledger["oldestSupportedRecordDigest"] not in record_digests:
        errors.append("history ledger oldest-supported record is absent from the chain")
    elif not fixture:
        oldest_supported = next(
            record
            for record in records
            if record["selfDigest"] == ledger["oldestSupportedRecordDigest"]
        )
        if oldest_supported["recordStatus"] not in {"imported", "published"}:
            errors.append("history ledger oldest-supported record is not a published release")
    if records and bind_execution_head:
        head = records[-1]
        expected = contract["release"]
        if (
            head["releaseId"] != expected["releaseId"]
            or head["buildVersion"] != expected["buildVersion"]
            or head["sourceCommit"] != contract["repository"]["sourceCommit"]
            or head["sourceRef"] != contract["repository"]["sourceRef"]
            or head["releaseRootDigest"] != expected["releaseRootDigest"]
            or head["contractVersion"] != contract["contractVersion"]
        ):
            errors.append("history ledger head differs from the execution subject")
        if (
            baseline_registry_binding is None
            or baseline_registry is None
            or head["baselineRegistryDigest"]
            != _record_baseline_registry_digest(baseline_registry)
        ):
            errors.append("history ledger head differs from the accepted baseline registry")
        head_snapshot, head_errors = _bound_json(
            evidence_dir,
            head["contractSnapshot"],
            SNAPSHOT_SCHEMA,
            "history head contract snapshot",
        )
        if head_snapshot is not None and not head_errors:
            snapshot_contract = head_snapshot["contract"]
            if (
                snapshot_contract["apiVersion"] != contract["urlApiVersion"]
                or snapshot_contract["contractVersion"] != contract["contractVersion"]
            ):
                errors.append("history head snapshot differs from the execution contract")
            if snapshot_contract["stableBaseline"]["name"] not in contract["activeStableBaselines"]:
                errors.append("history head stable baseline is not active in the execution contract")
    if ledger["ledgerDigest"] != _semantic_digest(ledger, "ledgerDigest"):
        errors.append("history ledger self digest is invalid")
    return errors


def _history_extension_errors(
    ledger: dict[str, Any], previous_ledger: dict[str, Any] | None, fixture: bool
) -> list[str]:
    if previous_ledger is None:
        records = ledger["records"]
        if (
            len(records) == 1
            and records[0]["recordStatus"] == "imported"
            and records[0]["predecessorRecordDigest"] is None
        ):
            return []
        return ["history after the imported genesis requires an authenticated previous ledger"]
    previous_records = previous_ledger["records"]
    current_records = ledger["records"]
    errors: list[str] = []
    if len(current_records) != len(previous_records) + 1:
        errors.append("history ledger must extend the authenticated predecessor by exactly one record")
        return errors
    if current_records[: len(previous_records)] != previous_records:
        errors.append("history ledger rewrites the authenticated predecessor prefix")
    if previous_ledger["headRecordDigest"] != previous_records[-1]["selfDigest"]:
        errors.append("previous history ledger head is invalid")
    successor = current_records[-1]
    if successor["predecessorRecordDigest"] != previous_ledger["headRecordDigest"]:
        errors.append("history successor does not extend the authenticated previous head")
    if successor["recordStatus"] == "imported":
        errors.append("history successor cannot be another import record")
    return errors


def _baseline_registry_extension_errors(
    registry: dict[str, Any],
    previous_registry: dict[str, Any] | None,
    previous_ledger: dict[str, Any] | None,
) -> list[str]:
    """Verify that the current registry exactly extends its authenticated predecessor."""

    if previous_ledger is None:
        if previous_registry is not None:
            return ["genesis history cannot bind a predecessor baseline registry"]
        return []
    if previous_registry is None:
        return ["history successor requires the authenticated predecessor baseline registry"]

    current = registry["baselineRegistry"]
    previous = previous_registry["baselineRegistry"]
    errors: list[str] = []
    previous_definitions = previous["definitions"]
    previous_lineage = previous["lineage"]
    if len(current["definitions"]) < len(previous_definitions):
        errors.append("baseline registry drops an authenticated definition")
    elif current["definitions"][: len(previous_definitions)] != previous_definitions:
        errors.append("baseline registry rewrites the authenticated definition prefix")
    if len(current["lineage"]) < len(previous_lineage):
        errors.append("baseline registry drops authenticated lifecycle history")
    elif current["lineage"][: len(previous_lineage)] != previous_lineage:
        errors.append("baseline registry rewrites the authenticated lifecycle prefix")

    previous_head = previous_ledger["records"][-1]
    if previous_head["baselineRegistryDigest"] != _record_baseline_registry_digest(
        previous_registry
    ):
        errors.append(
            "previous history head differs from the authenticated predecessor baseline registry"
        )
    return errors


def _protected_selected_rc(
    protected_summary: dict[str, Any],
) -> tuple[dict[str, Any] | None, list[str]]:
    errors: list[str] = []
    dispatch = protected_summary.get("dispatchPackage")
    validation = dispatch.get("gaValidation") if isinstance(dispatch, dict) else None
    publication = dispatch.get("gaPublication") if isinstance(dispatch, dict) else None
    selected = validation.get("selectedRc") if isinstance(validation, dict) else None
    published = publication.get("selectedRc") if isinstance(publication, dict) else None
    if not isinstance(selected, dict) or not isinstance(published, dict):
        return None, ["PR-291 authority lacks the selected RC identity"]
    if selected != published:
        errors.append("PR-291 validation and publication select different RC subjects")
    return selected, errors


def _current_history_authority_errors(
    contract: dict[str, Any],
    ledger: dict[str, Any],
    selected_rc_freeze: dict[str, Any] | None,
    selected_rc_freeze_binding: dict[str, Any] | None,
    protected_summary: dict[str, Any] | None,
    independent_summary: dict[str, Any] | None,
) -> list[str]:
    """Bind the newly supplied history head to authenticated release subjects."""

    errors: list[str] = []
    if selected_rc_freeze is None or selected_rc_freeze_binding is None:
        errors.append("current history requires the authenticated selected RC freeze")
        return errors
    if protected_summary is None or independent_summary is None:
        errors.append("current history requires authenticated PR-291 and PR-292 authorities")
        return errors
    protected_rc, protected_errors = _protected_selected_rc(protected_summary)
    errors.extend(protected_errors)
    independent_rc = independent_summary.get("selectedRc")
    if protected_rc is None or not isinstance(independent_rc, dict):
        if not isinstance(independent_rc, dict):
            errors.append("PR-292 authority lacks the selected RC identity")
        return errors
    compared_fields = (
        "runId",
        "runAttempt",
        "artifactName",
        "artifactDigest",
        "freezeDigest",
        "productDigest",
    )
    if any(
        str(protected_rc.get(field)) != str(independent_rc.get(field))
        for field in compared_fields
    ):
        errors.append("PR-291 and PR-292 select different RC subjects")
    if (
        independent_rc.get("workflowPath")
        != ".github/workflows/stable-1.0-rc-release.yml"
        or independent_rc.get("workflowCommit")
        != contract["repository"]["sourceCommit"]
    ):
        errors.append("PR-292 selected RC producer differs from the execution subject")
    freeze_content = copy.deepcopy(selected_rc_freeze)
    freeze_content.pop("contentDigest", None)
    if selected_rc_freeze.get("contentDigest") != _digest_bytes(
        _canonical_bytes(freeze_content)
    ):
        errors.append("selected RC freeze content digest is invalid")
    if selected_rc_freeze.get("contentDigest") != independent_rc.get("freezeDigest"):
        errors.append("selected RC freeze differs from the authenticated PR-292 subject")
    if selected_rc_freeze_binding["digest"] != independent_rc.get("freezeFileDigest"):
        errors.append("selected RC freeze bytes differ from the authenticated PR-292 subject")
    head = ledger["records"][-1]
    candidate = selected_rc_freeze["candidate"]
    platform_api = selected_rc_freeze["platformApi"]
    if (
        head["releaseId"] != candidate["releaseId"]
        or str(head["buildVersion"]) != str(candidate["buildVersion"])
        or head["sourceCommit"] != candidate["sourceCommit"]
        or head["sourceRef"] != candidate["sourceRef"]
    ):
        errors.append("current history head differs from the authenticated selected RC")
    if head["releaseRootDigest"] != independent_rc.get("productDigest"):
        errors.append("current history release root differs from the authenticated selected RC")
    if (
        head["contractVersion"] != platform_api["currentContractVersion"]
        or head["contractSnapshot"]["digest"]
        != platform_api["currentContractDigest"]
    ):
        errors.append("current history contract differs from the authenticated selected RC freeze")
    if (
        platform_api["baselineName"] != "1.0"
        or platform_api["baselineDigest"]
        != "sha256:" + FROZEN_1_0_ARTIFACT_DIGEST
    ):
        errors.append("selected RC freeze differs from the immutable Platform API 1.0 baseline")
    if head["provenance"] != contract["authorities"]["protectedRelease"]["provenance"]:
        errors.append("current history provenance differs from its authenticated release receipt")
    return errors


def _previous_history_authority_errors(
    contract: dict[str, Any],
    ledger: dict[str, Any],
    previous_ledger: dict[str, Any] | None,
    evidence_dir: Path | None,
    fixture: bool,
    policy: dict[str, Any],
    previous_deprecation: dict[str, Any] | None = None,
    previous_baseline_registry: dict[str, Any] | None = None,
    previous_baseline_registry_binding: dict[str, Any] | None = None,
) -> list[str]:
    authority = contract["previousHistoryAuthority"]
    if fixture:
        return []
    records = ledger["records"]
    if (
        previous_ledger is None
        and len(records) == 1
        and records[0]["recordStatus"] == "imported"
        and records[0]["predecessorRecordDigest"] is None
    ):
        return []
    if (
        previous_ledger is None
        or previous_baseline_registry is None
        or previous_baseline_registry_binding is None
        or authority is None
    ):
        return ["production history requires a protected previous Platform API 1.x authority"]
    summary, errors = _bound_json(
        evidence_dir,
        authority["summary"],
        SUMMARY_SCHEMA,
        "previous Platform API 1.x authority summary",
    )
    if errors or summary is None:
        return errors
    provenance = authority["provenance"]
    previous_head = previous_ledger["records"][-1]
    producer = policy["previousHistoryProducer"]
    if authority["operational"] is not True:
        errors.append("previous Platform API 1.x authority is not operational")
    if authority["summaryDigest"] != summary["summaryDigest"]:
        errors.append("previous Platform API 1.x summary digest differs")
    if authority["artifactDigest"] != provenance["artifactDigest"]:
        errors.append("previous Platform API 1.x artifact digest differs")
    if (
        provenance["repositoryIdentity"] != policy["repositoryIdentity"]
        or provenance["workflowPath"] != producer["workflowPath"]
        or provenance["workflowCommit"] != previous_head["sourceCommit"]
        or provenance["environment"] != producer["environment"]
        or provenance["conclusion"] != "success"
    ):
        errors.append("previous Platform API 1.x provenance is not the protected authority")
    expected_artifact_name = (
        f"{producer['artifactNamePrefix']}{previous_head['releaseId']}-"
        f"{provenance['runId']}-{provenance['runAttempt']}"
    )
    if (
        authority["summary"]["fileName"] != producer["summaryFileName"]
        or provenance["artifactName"] != expected_artifact_name
    ):
        errors.append("previous Platform API 1.x artifact subject is not canonical")
    if (
        summary["mode"] != "closeout"
        or summary["status"] != "pass"
        or summary["state"] != "operational-1x-compatibility-complete"
        or not summary["operational"]
        or summary["fixtureOnly"]
        or summary["selfTest"]
        or summary["blockers"]
    ):
        errors.append("previous Platform API 1.x summary is not an operational closeout")
    if (
        summary["releaseId"] != previous_head["releaseId"]
        or summary["buildVersion"] != previous_head["buildVersion"]
        or summary["sourceCommit"] != previous_head["sourceCommit"]
        or summary["contractVersion"] != previous_head["contractVersion"]
    ):
        errors.append("previous Platform API 1.x summary subject differs from the previous head")
    if (
        summary["historyLedgerDigest"] != previous_ledger["ledgerDigest"]
        or summary["historyLedgerHeadDigest"] != previous_ledger["headRecordDigest"]
    ):
        errors.append("previous Platform API 1.x summary does not authenticate the ledger head")
    if (
        summary.get("baselineRegistryDigest")
        != _record_baseline_registry_digest(previous_baseline_registry)
        or summary.get("baselineRegistryArtifactDigest")
        != previous_baseline_registry_binding["digest"]
    ):
        errors.append(
            "previous Platform API 1.x summary does not authenticate the baseline registry"
        )
    if (
        previous_deprecation is None
        or summary["deprecationLedgerDigest"] != previous_deprecation["ledgerDigest"]
    ):
        errors.append(
            "previous Platform API 1.x summary does not authenticate the deprecation ledger"
        )
    if summary["summaryDigest"] != _semantic_digest(summary, "summaryDigest"):
        errors.append("previous Platform API 1.x summary self digest is invalid")
    return errors


def _baseline_definition_members(definition: dict[str, Any]) -> list[str]:
    members = [
        *(f"capability:{name}" for name in definition["capabilities"]),
        *(
            f"endpoint:{endpoint['id'].replace(' ', ':', 1)}"
            for endpoint in definition["endpoints"]
        ),
    ]
    return sorted(members, key=_java_string_key)


def _proposal_errors(
    proposal: dict[str, Any],
    contract: dict[str, Any],
    baseline_registry: dict[str, Any] | None,
    fixture: bool,
    policy: dict[str, Any],
) -> list[str]:
    errors: list[str] = []
    target = proposal["targetBaselineId"]
    predecessor = proposal["predecessorBaselineId"]
    if not BASELINE_ID.fullmatch(target) or not BASELINE_ID.fullmatch(predecessor):
        errors.append("proposal baseline identity is malformed")
    if target == "1.0" or target == predecessor:
        errors.append("proposal target must be a future 1.x successor")
    if proposal["sourceCommit"] != contract["repository"]["sourceCommit"]:
        errors.append("proposal source commit differs from the execution contract")
    if proposal["releaseId"] != contract["release"]["releaseId"]:
        errors.append("proposal release differs from the execution contract")
    if proposal["targetContractVersion"] != contract["contractVersion"]:
        errors.append("proposal target contract version differs from the execution contract")
    member_fields = (
        "predecessorMembers", "candidateMembers", "additions", "claimedRemovals"
    )
    for field in member_fields:
        members = proposal.get(field, [])
        if members != sorted(set(members), key=_java_string_key):
            errors.append(f"proposal {field} is not canonical and unique")
    predecessor_members = set(proposal["predecessorMembers"])
    candidate_members = set(proposal["candidateMembers"])
    expected_additions = sorted(candidate_members.difference(predecessor_members), key=_java_string_key)
    expected_removals = sorted(predecessor_members.difference(candidate_members), key=_java_string_key)
    if proposal.get("additions", []) != expected_additions:
        errors.append("proposal additions do not match its exact membership delta")
    if proposal["claimedRemovals"] != expected_removals:
        errors.append("proposal removals do not match its exact membership delta")
    if expected_removals:
        errors.append("proposal is not monotonic with its supported predecessor")
        errors.append("a compatible 1.x proposal cannot claim removals")
    if baseline_registry is None:
        errors.append("proposal cannot be verified without the accepted baseline registry")
    else:
        registry = baseline_registry["baselineRegistry"]
        definitions = {
            definition["id"]: definition for definition in registry["definitions"]
        }
        latest_lineage = {
            lineage["id"]: lineage for lineage in registry["lineage"]
        }
        predecessor_definition = definitions.get(predecessor)
        target_definition = definitions.get(target)
        if predecessor_definition is None:
            errors.append("proposal predecessor is absent from the accepted baseline registry")
        elif proposal["predecessorMembers"] != _baseline_definition_members(
            predecessor_definition
        ):
            errors.append("proposal predecessor membership differs from the accepted registry")
        if target_definition is None:
            errors.append("proposal target is absent from the accepted baseline registry")
        else:
            if target_definition["predecessorId"] != predecessor:
                errors.append("proposal predecessor differs from the target definition")
            if proposal["candidateMembers"] != _baseline_definition_members(target_definition):
                errors.append("proposal candidate membership differs from the target definition")
            if (
                target_definition["firstCompleteContractVersion"]
                != proposal["targetContractVersion"]
            ):
                errors.append("proposal contract version differs from the target definition")
            if target_definition["proposalDigest"] != proposal["proposalDigest"].removeprefix(
                "sha256:"
            ):
                errors.append("proposal digest differs from the target definition")
        lifecycle = latest_lineage.get(target)
        if lifecycle is None:
            errors.append("proposal target has no accepted lifecycle record")
        else:
            proposal_state = proposal["lifecycleState"]
            registry_state = lifecycle["status"]
            lifecycle_order = {
                "proposed": 0,
                "candidate": 1,
                "reviewed": 2,
                "documented": 3,
                "active": 4,
                "deprecated": 5,
                "end-of-support": 6,
            }
            if (
                (proposal_state == "rejected" and registry_state != "rejected")
                or (
                    proposal_state != "rejected"
                    and (
                        registry_state == "rejected"
                        or lifecycle_order.get(registry_state, -1)
                        < lifecycle_order.get(proposal_state, -1)
                    )
                )
            ):
                errors.append("proposal lifecycle differs from the accepted baseline registry")
    if proposal["lifecycleState"] == "active":
        errors.append("a proposal cannot activate a baseline")
    if proposal.get("lifecycleState") in {"reviewed", "documented"} and proposal.get(
        "decision"
    ) != "approved":
        errors.append("reviewed proposal does not carry an approved decision")
    if proposal.get("lifecycleState") == "rejected" and proposal.get("decision") != "rejected":
        errors.append("rejected proposal does not carry a rejected decision")
    if proposal["proposalDigest"] != _semantic_digest(proposal, "proposalDigest"):
        errors.append("proposal self digest is invalid")
    provenance = proposal["reviewProvenance"]
    if (
        provenance["repositoryIdentity"] != policy["repositoryIdentity"]
        or provenance["workflowPath"] != policy["reviewWorkflow"]
        or provenance["workflowCommit"] != contract["repository"]["sourceCommit"]
    ):
        errors.append("proposal review provenance is not the protected review authority")
    if any(
        proposal[name] == ZERO_DIGEST
        for name in (
            "compatibilityAnalysisDigest", "rationaleDigest", "securityReviewDigest",
            "documentationDigest", "testEvidenceDigest", "appMatrixDigest",
        )
    ):
        errors.append("proposal omits required review or compatibility evidence")
    if not fixture and proposal["fixtureOnly"]:
        errors.append("fixture proposal cannot satisfy production verification")
    return errors


def _proposal_presence_errors(
    proposal: dict[str, Any] | None,
    baseline_registry: dict[str, Any] | None,
    policy: dict[str, Any],
) -> list[str]:
    if baseline_registry is None:
        return []
    registry = baseline_registry["baselineRegistry"]
    latest_status: dict[str, str] = {}
    for lineage in registry["lineage"]:
        latest_status[lineage["id"]] = lineage["status"]
    bootstrap = policy["immutableBootstrapBaseline"]["baselineId"]
    future_definitions = [
        definition
        for definition in registry["definitions"]
        if definition["id"] != bootstrap
        and latest_status.get(definition["id"]) not in {"rejected", "end-of-support"}
    ]
    if not future_definitions:
        return []
    if proposal is None:
        return [
            "a nonterminal future baseline definition requires exact proposal evidence"
        ]
    if len(future_definitions) != 1:
        return [
            "execution schema v1 cannot authenticate multiple nonterminal future baseline definitions"
        ]
    if proposal["targetBaselineId"] != future_definitions[0]["id"]:
        return ["proposal target differs from the nonterminal future baseline definition"]
    return []


def _history_snapshot_subjects(
    ledger: dict[str, Any] | None, evidence_dir: Path | None
) -> tuple[list[tuple[dict[str, Any], dict[str, Any]]], list[str]]:
    if ledger is None:
        return [], ["authenticated contract history is unavailable"]
    subjects: list[tuple[dict[str, Any], dict[str, Any]]] = []
    errors: list[str] = []
    for index, record in enumerate(ledger["records"]):
        snapshot, item_errors = _bound_json(
            evidence_dir,
            record["contractSnapshot"],
            SNAPSHOT_SCHEMA,
            f"history record {index} contract snapshot",
        )
        errors.extend(item_errors)
        if snapshot is not None and not item_errors:
            subjects.append((record, snapshot["contract"]))
    return subjects, errors


def _descriptor_identity(kind: str, descriptor: dict[str, Any]) -> str:
    if kind == "capability":
        return f"capability:{descriptor['name']}"
    return f"endpoint:{descriptor['method']}:{descriptor['routeTemplate']}"


def _descriptor_allowed_principals(
    kind: str, descriptor: dict[str, Any]
) -> list[str]:
    if kind == "capability":
        if descriptor["audience"] == "app":
            return ["app-browser", "app-process"]
        if descriptor["audience"] == "operator-only":
            return ["host-operator"]
        return []
    principals: list[str] = []
    if descriptor["appBrowserPrincipalsAllowed"]:
        principals.append("app-browser")
    if descriptor["appProcessPrincipalsAllowed"]:
        principals.append("app-process")
    if descriptor["hostOperatorBypassAllowed"]:
        principals.append("host-operator")
    return principals


def _descriptor_behavior_projection(
    kind: str, descriptor: dict[str, Any]
) -> dict[str, Any]:
    if kind == "capability":
        return {
            "name": descriptor["name"],
            "description": descriptor["description"],
        }
    return {
        field: descriptor[field]
        for field in (
            "routeFamily",
            "method",
            "routeTemplate",
            "actionLabel",
            "requiredCapabilities",
            "hostOperatorBypassAllowed",
            "appProcessPrincipalsAllowed",
            "appBrowserPrincipalsAllowed",
            "description",
        )
    }


def _graduation_source_descriptor(
    record: dict[str, Any],
    history_subjects: list[tuple[dict[str, Any], dict[str, Any]]],
) -> dict[str, Any] | None:
    kind = record["descriptorKind"]
    identity = record["descriptorIdentity"]
    for history_record, snapshot_contract in reversed(history_subjects):
        if (
            history_record["contractVersion"] != record["sourceContractVersion"]
            or history_record["sourceCommit"] != record["sourceCommit"]
        ):
            continue
        collection = "capabilities" if kind == "capability" else "endpoints"
        for descriptor in snapshot_contract[collection]:
            if _descriptor_identity(kind, descriptor) == identity:
                return descriptor
    return None


def _graduation_errors(
    records: list[dict[str, Any]],
    proposal: dict[str, Any] | None,
    contract: dict[str, Any],
    baseline_registry: dict[str, Any] | None,
    history_subjects: list[tuple[dict[str, Any], dict[str, Any]]],
    fixture: bool,
    evaluation: datetime,
    policy: dict[str, Any],
) -> list[str]:
    errors: list[str] = []
    identities: set[str] = set()
    definitions = (
        {
            definition["id"]: definition
            for definition in baseline_registry["baselineRegistry"]["definitions"]
        }
        if baseline_registry is not None
        else {}
    )
    for index, record in enumerate(records):
        label = f"graduation record {index}"
        identity = record["descriptorIdentity"]
        if identity in identities:
            errors.append(f"{label} duplicates a descriptor identity")
        identities.add(identity)
        if record["descriptorAudience"] in {"operator", "internal"}:
            errors.append(f"{label} attempts to graduate an operator/internal descriptor")
        if record["sourceCommit"] != contract["repository"]["sourceCommit"]:
            errors.append(f"{label} source commit differs")
        if proposal is None or record["targetBaselineId"] != proposal["targetBaselineId"]:
            errors.append(f"{label} target baseline differs from the proposal")
        if identity not in (proposal or {}).get("additions", []):
            errors.append(f"{label} descriptor is not an exact proposal addition")
        if any(record[name] == ZERO_DIGEST for name in (
            "descriptorDigest", "behaviorContractDigest", "securityReviewDigest", "compatibilityReviewDigest",
            "documentationDigest", "testEvidenceDigest", "appEvidenceDigest",
        )):
            errors.append(f"{label} omits required review evidence")
        if record["decision"] != "approved":
            errors.append(f"{label} is not approved")
        if record["recordDigest"] != _semantic_digest(record, "recordDigest"):
            errors.append(f"{label} self digest is invalid")
        provenance = record["reviewProvenance"]
        if (
            provenance["repositoryIdentity"] != policy["repositoryIdentity"]
            or provenance["workflowPath"] != policy["reviewWorkflow"]
            or provenance["workflowCommit"] != contract["repository"]["sourceCommit"]
        ):
            errors.append(f"{label} review provenance is not the protected review authority")
        if not fixture and record["fixtureOnly"]:
            errors.append(f"{label} fixture evidence cannot satisfy production verification")
        expected_kind = identity.split(":", 1)[0]
        if expected_kind != record["descriptorKind"]:
            errors.append(f"{label} descriptor kind differs from its identity")
        descriptor = _graduation_source_descriptor(record, history_subjects)
        if descriptor is None:
            errors.append(f"{label} descriptor is absent from its authenticated source snapshot")
            continue
        actual_audience = (
            "operator" if descriptor["audience"] == "operator-only" else descriptor["audience"]
        )
        if descriptor["stability"] != "experimental" or actual_audience != "app":
            errors.append(f"{label} source descriptor is not experimental app-facing API")
        if record["descriptorAudience"] != actual_audience:
            errors.append(f"{label} descriptor audience differs from its source snapshot")
        if record["descriptorDigest"] != _digest_bytes(_canonical_bytes(descriptor)):
            errors.append(f"{label} descriptor digest differs from its source snapshot")
        expected_required = (
            descriptor["requiredCapabilities"]
            if record["descriptorKind"] == "endpoint"
            else []
        )
        if record["requiredCapabilities"] != expected_required:
            errors.append(f"{label} required capabilities differ from its source snapshot")
        if record["allowedPrincipals"] != _descriptor_allowed_principals(
            record["descriptorKind"], descriptor
        ):
            errors.append(f"{label} allowed principals differ from its source snapshot")
        expected_action = (
            descriptor["actionLabel"]
            if record["descriptorKind"] == "endpoint"
            else descriptor["name"]
        )
        if record["auditAction"] != expected_action:
            errors.append(f"{label} audit action differs from its source snapshot")
        if record["behaviorContractDigest"] != _digest_bytes(
            _canonical_bytes(_descriptor_behavior_projection(record["descriptorKind"], descriptor))
        ):
            errors.append(f"{label} behavior contract differs from its source snapshot")
        observation = record["observationWindow"]
        if record["sourceContractVersion"] not in observation["contractVersions"]:
            errors.append(f"{label} observation window omits its source contract")
        first_observed = _timestamp(
            observation["firstObservedAt"], f"{label} firstObservedAt"
        )
        last_observed = _timestamp(
            observation["lastObservedAt"], f"{label} lastObservedAt"
        )
        if last_observed < first_observed:
            errors.append(f"{label} observation window is reversed")
        if first_observed > evaluation or last_observed > evaluation:
            errors.append(f"{label} observation window is future-dated")
        target_definition = definitions.get(record["targetBaselineId"])
        if target_definition is None:
            errors.append(f"{label} target definition is absent from the accepted registry")
        elif record["descriptorKind"] == "capability":
            if descriptor["name"] not in target_definition["capabilities"]:
                errors.append(f"{label} capability is absent from the target definition")
        else:
            expected_endpoint = next(
                (
                    endpoint
                    for endpoint in target_definition["endpoints"]
                    if f"endpoint:{endpoint['id'].replace(' ', ':', 1)}" == identity
                ),
                None,
            )
            if expected_endpoint is None:
                errors.append(f"{label} endpoint is absent from the target definition")
            elif expected_endpoint != _snapshot_endpoint_semantics(descriptor):
                errors.append(f"{label} endpoint semantics differ from the target definition")
    expected_graduations = set((proposal or {}).get("additions", []))
    if identities != expected_graduations:
        errors.append("graduation records do not exactly cover the proposal additions")
    return errors


def _deprecation_errors(
    ledger: dict[str, Any],
    prior: dict[str, Any] | None,
    current_contract_version: int,
    history_subjects: list[tuple[dict[str, Any], dict[str, Any]]] | None = None,
) -> list[str]:
    errors: list[str] = []
    if ledger["ledgerDigest"] != _semantic_digest(ledger, "ledgerDigest"):
        errors.append("deprecation ledger self digest is invalid")
    rows = {row["descriptorIdentity"]: row for row in ledger["entries"]}
    if len(rows) != len(ledger["entries"]):
        errors.append("deprecation ledger contains duplicate descriptor identities")
    prior_rows: dict[str, dict[str, Any]] = {}
    if prior is not None:
        if ledger["predecessorLedgerDigest"] != prior["ledgerDigest"]:
            errors.append("deprecation ledger predecessor digest differs")
        prior_rows = {row["descriptorIdentity"]: row for row in prior["entries"]}
        for identity, old in prior_rows.items():
            new = rows.get(identity)
            if new is None:
                errors.append(f"deprecation notice disappeared for {identity}")
                continue
            if new["firstDeprecatedContractVersion"] != old["firstDeprecatedContractVersion"]:
                errors.append(f"deprecation contract clock changed for {identity}")
            if new["firstObservedAt"] != old["firstObservedAt"]:
                errors.append(f"deprecation public-notice time changed for {identity}")
            if (
                new["firstAuthenticatedReleaseId"] != old["firstAuthenticatedReleaseId"]
                or new["firstAuthenticatedBuildVersion"] != old["firstAuthenticatedBuildVersion"]
            ):
                errors.append(f"deprecation first authenticated release changed for {identity}")
            if new["predecessorTimelineDigest"] != old["timelineDigest"]:
                errors.append(f"deprecation timeline predecessor differs for {identity}")
            allowed_states = {
                "deprecated": {"deprecated", "scheduled", "removal-blocked"},
                "scheduled": {"scheduled", "removal-blocked", "removed"},
                "removal-blocked": {"removal-blocked", "scheduled", "removed"},
                "removed": {"removed"},
            }
            if new["state"] not in allowed_states[old["state"]]:
                errors.append(f"deprecation lifecycle state regressed for {identity}")
            old_removal = old["scheduledRemovalContractVersion"]
            new_removal = new["scheduledRemovalContractVersion"]
            if old_removal is not None and (new_removal is None or new_removal < old_removal):
                errors.append(f"scheduled removal moved earlier for {identity}")
            if old["scheduledRemovalBaseline"] is not None and (
                new["scheduledRemovalBaseline"] is None
                or new["scheduledRemovalBaseline"] != old["scheduledRemovalBaseline"]
            ):
                errors.append(f"scheduled removal baseline changed for {identity}")
    for row in ledger["entries"]:
        identity = row["descriptorIdentity"]
        expected_prefix = f"{row['descriptorKind']}:"
        if not identity.startswith(expected_prefix):
            errors.append(
                f"deprecation descriptor kind differs from identity for {identity}"
            )
        is_new_successor_row = prior is not None and identity not in prior_rows
        if (prior is None or is_new_successor_row) and row["predecessorTimelineDigest"] is not None:
            errors.append(
                f"new deprecation timeline names a predecessor for {identity}"
            )
        if is_new_successor_row:
            if row["state"] not in {"deprecated", "scheduled"}:
                errors.append(f"new deprecation timeline starts in an invalid state for {identity}")
            subjects = history_subjects or []
            notices: list[tuple[dict[str, Any], dict[str, Any]]] = []
            for record, snapshot in subjects:
                raw_identity = identity.removeprefix(expected_prefix)
                if row["descriptorKind"] == "capability":
                    descriptor = next(
                        (
                            item
                            for item in snapshot["capabilities"]
                            if item["name"] == raw_identity
                        ),
                        None,
                    )
                else:
                    method, separator, route = raw_identity.partition(":")
                    descriptor = next(
                        (
                            item
                            for item in snapshot["endpoints"]
                            if separator
                            and item["method"] == method
                            and item["routeTemplate"] == route
                        ),
                        None,
                    )
                if descriptor is not None and descriptor["deprecation"] is not None:
                    notices.append((record, descriptor))
            if not notices:
                errors.append(f"new deprecation timeline has no authenticated notice for {identity}")
            else:
                first_record, first_descriptor = notices[0]
                if not subjects or first_record["selfDigest"] != subjects[-1][0]["selfDigest"]:
                    errors.append(
                        f"new deprecation timeline was omitted from predecessor history for {identity}"
                    )
                notice_version = first_descriptor["deprecation"][
                    "deprecatedSinceContractVersion"
                ]
                if (
                    row["firstDeprecatedContractVersion"] != notice_version
                    or row["firstDeprecatedContractVersion"]
                    != first_record["contractVersion"]
                ):
                    errors.append(f"new deprecation contract clock is not history-derived for {identity}")
                if (
                    row["firstAuthenticatedReleaseId"] != first_record["releaseId"]
                    or row["firstAuthenticatedBuildVersion"]
                    != first_record["buildVersion"]
                ):
                    errors.append(f"new deprecation first release is not history-derived for {identity}")
                if row["firstObservedAt"] != first_record["generatedAt"]:
                    errors.append(f"new deprecation first notice time is not history-derived for {identity}")
        if row["timelineDigest"] != _semantic_digest(row, "timelineDigest"):
            errors.append(f"deprecation timeline self digest is invalid for {identity}")
        removal = row["scheduledRemovalContractVersion"]
        if removal is not None and removal < row["firstDeprecatedContractVersion"] + 2:
            errors.append(f"deprecation runway is shorter than two contract versions for {row['descriptorIdentity']}")
        if (
            removal is not None
            and removal < current_contract_version
            and row["state"] != "removed"
        ):
            errors.append(f"scheduled removal is before the current contract for {row['descriptorIdentity']}")
        if (
            removal is not None
            and row["state"] == "removed"
            and current_contract_version < removal
        ):
            errors.append(
                f"descriptor removal precedes its scheduled contract version for {row['descriptorIdentity']}"
            )
    return errors


def _deprecation_history_binding_errors(
    ledger: dict[str, Any],
    prior: dict[str, Any] | None,
    history: dict[str, Any],
    previous_history: dict[str, Any] | None,
) -> list[str]:
    """Bind deprecation continuity to the authenticated release-history prefix."""

    errors: list[str] = []
    records = history["records"]
    if records[-1]["deprecationLedgerDigest"] != ledger["ledgerDigest"]:
        errors.append("history head differs from the accepted deprecation ledger")
    is_genesis = len(records) == 1 and records[0]["recordStatus"] == "imported"
    if is_genesis:
        if prior is not None or ledger["predecessorLedgerDigest"] is not None:
            errors.append("deprecation genesis must not name a predecessor ledger")
        return errors
    if prior is None:
        errors.append("successor history requires the authenticated previous deprecation ledger")
        return errors
    if previous_history is None:
        errors.append("previous deprecation ledger requires the authenticated previous history")
        return errors
    if previous_history["records"][-1]["deprecationLedgerDigest"] != prior["ledgerDigest"]:
        errors.append("previous history head differs from the previous deprecation ledger")
    return errors


def _supported_baseline_memberships(
    registry_envelope: dict[str, Any] | None, descriptor_kind: str, identity: str
) -> list[str]:
    if registry_envelope is None:
        return []
    registry = registry_envelope["baselineRegistry"]
    latest_status = {
        item["id"]: item["status"] for item in registry["lineage"]
    }
    raw_identity = identity.removeprefix(f"{descriptor_kind}:")
    if descriptor_kind == "endpoint":
        method, separator, route = raw_identity.partition(":")
        raw_identity = f"{method} {route}" if separator else raw_identity
    memberships: list[str] = []
    for definition in registry["definitions"]:
        if latest_status.get(definition["id"]) not in SUPPORTED_BASELINE_STATES:
            continue
        members = (
            definition["capabilities"]
            if descriptor_kind == "capability"
            else [endpoint["id"] for endpoint in definition["endpoints"]]
        )
        if raw_identity in members:
            memberships.append(definition["id"])
    return sorted(memberships, key=_baseline_id_key)


def _required_app_dependencies(
    matrix: dict[str, Any] | None,
    snapshot_contract: dict[str, Any] | None,
    descriptor_kind: str,
    identity: str,
) -> list[str]:
    if matrix is None or snapshot_contract is None:
        return []
    raw_identity = identity.removeprefix(f"{descriptor_kind}:")
    required_capabilities: set[str]
    if descriptor_kind == "capability":
        required_capabilities = {raw_identity}
    else:
        method, separator, route = raw_identity.partition(":")
        endpoint_identity = f"{method} {route}" if separator else raw_identity
        endpoint = next(
            (
                item
                for item in snapshot_contract["endpoints"]
                if f"{item['method']} {item['routeTemplate']}" == endpoint_identity
            ),
            None,
        )
        required_capabilities = (
            set(endpoint["requiredCapabilities"]) if endpoint is not None else set()
        )
        if not required_capabilities:
            return []
    dependencies = {
        row["appId"]
        for row in matrix["rows"]
        if row["requiredForRelease"]
        and required_capabilities.issubset(set(row["requiredCapabilities"]))
    }
    return sorted(dependencies, key=_java_string_key)


def _deprecation_subject_errors(
    ledger: dict[str, Any],
    registry_envelope: dict[str, Any] | None,
    matrix: dict[str, Any] | None,
    snapshot_contract: dict[str, Any] | None,
) -> list[str]:
    """Derive removal blockers from accepted baseline and app subjects."""

    errors: list[str] = []
    ledger_identities = {row["descriptorIdentity"] for row in ledger["entries"]}
    if snapshot_contract is not None:
        for kind, descriptors in (
            ("capability", snapshot_contract["capabilities"]),
            ("endpoint", snapshot_contract["endpoints"]),
        ):
            for descriptor in descriptors:
                identity = _descriptor_identity(kind, descriptor)
                if (
                    descriptor["deprecation"] is not None
                    and _supported_baseline_memberships(
                        registry_envelope, kind, identity
                    )
                    and identity not in ledger_identities
                ):
                    errors.append(
                        f"supported stable deprecation is absent from the ledger for {identity}"
                    )
    for row in ledger["entries"]:
        identity = row["descriptorIdentity"]
        raw_identity = identity.removeprefix(f"{row['descriptorKind']}:")
        if row["descriptorKind"] == "capability":
            descriptor = next(
                (
                    item
                    for item in (snapshot_contract or {}).get("capabilities", [])
                    if item["name"] == raw_identity
                ),
                None,
            )
        else:
            method, separator, route = raw_identity.partition(":")
            descriptor = next(
                (
                    item
                    for item in (snapshot_contract or {}).get("endpoints", [])
                    if separator
                    and item["method"] == method
                    and item["routeTemplate"] == route
                ),
                None,
            )
        memberships = _supported_baseline_memberships(
            registry_envelope, row["descriptorKind"], identity
        )
        dependencies = _required_app_dependencies(
            matrix, snapshot_contract, row["descriptorKind"], identity
        )
        if row["supportedBaselineMemberships"] != memberships:
            errors.append(f"derived supported baseline memberships differ for {identity}")
        if row["requiredAppDependencies"] != dependencies:
            errors.append(f"derived required app dependencies differ for {identity}")
        if memberships and not row["critical"]:
            errors.append(f"supported stable descriptor is not marked critical for {identity}")
        if row["state"] == "removed" and (memberships or dependencies):
            errors.append(f"removal is blocked by a supported baseline or app for {identity}")
        if row["state"] == "removed" and (row["critical"] or memberships):
            errors.append(f"critical stable removal is non-waivable for {identity}")
        if row["state"] == "removed" and descriptor is not None:
            errors.append(f"removed descriptor remains in the current snapshot for {identity}")
        if row["state"] != "removed" and descriptor is None:
            errors.append(f"deprecated descriptor is absent from the current snapshot for {identity}")
        if descriptor is not None:
            snapshot_deprecation = descriptor["deprecation"]
            if snapshot_deprecation is None:
                errors.append(f"deprecation metadata disappeared from the snapshot for {identity}")
            elif (
                snapshot_deprecation["deprecatedSinceContractVersion"]
                != row["firstDeprecatedContractVersion"]
                or snapshot_deprecation["removalContractVersion"]
                != row["scheduledRemovalContractVersion"]
            ):
                errors.append(f"deprecation clock differs from the current snapshot for {identity}")
    return errors


def _matrix_app_subjects_digest(matrix: dict[str, Any]) -> str:
    subjects = [
        {name: row[name] for name in MATRIX_SUBJECT_FIELDS}
        for row in sorted(
            matrix["rows"],
            key=lambda item: (item["appId"], item["appVersion"], item["bundleDigest"]),
        )
    ]
    return _digest_bytes(_canonical_bytes(subjects))


def _app_subject_inventory_errors(
    inventory: dict[str, Any],
    fixture: bool,
    contract: dict[str, Any],
    policy: dict[str, Any],
    authenticated_projection: Any = None,
) -> list[str]:
    errors: list[str] = []
    projected = False
    if inventory.get("schemaVersion") == 4 and inventory.get("baseInventoryVersion") != 2:
        return ["runtime-only app inventory does not establish independent API release authority"]
    if inventory.get("schemaVersion") in {2, 4}:
        # Only the protected wrapper can inject bytes it just fetched and authenticated.
        # No JSON property or local self digest substitutes for this producer boundary.
        try:
            from app_subject_projection import AuthenticatedProjection, validate_declaration, validate_federation_inventory
            validate_federation_inventory(inventory)
            projected = (isinstance(authenticated_projection, AuthenticatedProjection)
                         and authenticated_projection.matches(inventory))
        except (ImportError, ValueError, KeyError, TypeError):
            projected = False
        if not projected:
            errors.append("version-2 app inventory lacks original protected projection authentication")
    if inventory["inventoryDigest"] != _semantic_digest(inventory, "inventoryDigest"):
        errors.append("app subject inventory self digest is invalid")
    if (
        inventory["releaseId"] != contract["release"]["releaseId"]
        or inventory["sourceCommit"] != contract["repository"]["sourceCommit"]
    ):
        errors.append("app subject inventory release subject differs")
    if inventory["authorityRoots"] != contract["authorityRoots"]:
        errors.append("app subject inventory authority roots differ")
    if inventory["fixtureOnly"] != fixture:
        errors.append("app subject inventory fixture classification differs")

    identities: set[tuple[str, str, str]] = set()
    app_versions: set[tuple[str, str]] = set()
    required_ids: set[str] = set()
    first_party_ids: set[str] = set()
    for index, subject in enumerate(inventory["subjects"]):
        label = f"app subject inventory row {index}"
        identity = (subject["appId"], subject["appVersion"], subject["bundleDigest"])
        if identity in identities:
            errors.append(f"{label} duplicates an app subject")
        identities.add(identity)
        app_version = (subject["appId"], subject["appVersion"])
        if app_version in app_versions:
            errors.append(f"{label} duplicates an app version with another bundle")
        app_versions.add(app_version)
        if subject["subjectDigest"] != _semantic_digest(subject, "subjectDigest"):
            errors.append(f"{label} self digest is invalid")
        if subject["requiredCapabilities"] != sorted(set(subject["requiredCapabilities"])):
            errors.append(f"{label} required capabilities are not canonical")
        if subject["optionalCapabilities"] != sorted(set(subject["optionalCapabilities"])):
            errors.append(f"{label} optional capabilities are not canonical")
        if set(subject["requiredCapabilities"]).intersection(subject["optionalCapabilities"]):
            errors.append(f"{label} capability is both required and optional")
        if subject["requiredForRelease"]:
            required_ids.add(subject["appId"])
        source = subject["sourceAuthority"]
        if source == "fixture":
            if (
                not fixture
                or subject["sourceAuthorityRoot"] is not None
                or subject["sourceEvidenceDigest"] is not None
            ):
                errors.append(f"{label} fixture authority is invalid")
        else:
            expected_root_name = MATRIX_SOURCE_ROOTS[source]
            if subject["sourceAuthorityRoot"] != contract["authorityRoots"][expected_root_name]:
                errors.append(f"{label} source authority root differs")
            if fixture or subject["fixtureOnly"]:
                errors.append(f"{label} operational authority is fixture-shaped")
            if subject["sourceEvidenceDigest"] in {None, ZERO_DIGEST}:
                errors.append(f"{label} source evidence digest is absent")
            # PR-292 authenticates bundle and selected manifest/review digests, PR-294
            # authenticates only its bounded handoff projection, and PR-295 authenticates
            # catalog discovery rather than an app manifest. None of those legacy summaries
            # commits every field used by this matrix (notably target baseline/range and the
            # required/optional capability split). Until a protected producer supplies an
            # exact subject projection, accepting the broad authority digest here would let
            # the caller rewrite and reseal both the inventory and matrix.
            if not projected:
                errors.append(f"{label} lacks an authenticated complete compatibility projection")
            else:
                try:
                    declaration = validate_declaration(subject["signedProjection"])
                    compared = set(MATRIX_SUBJECT_FIELDS) - {"sourceAuthority", "fixtureOnly", "requiredForRelease"}
                    if any(subject[field] != declaration[field] for field in compared):
                        errors.append(f"{label} differs from the exact signed declaration")
                    if subject["originalSource"]["sourceFamily"] != source:
                        errors.append(f"{label} original source family differs")
                except (ValueError, KeyError, TypeError):
                    errors.append(f"{label} signed projection is invalid")
        if source == "first-party-release":
            first_party_ids.add(subject["appId"])

    if inventory["requiredAppIds"] != sorted(set(inventory["requiredAppIds"])):
        errors.append("app subject inventory required app IDs are not canonical")
    if set(inventory["requiredAppIds"]) != required_ids:
        errors.append("app subject inventory required app IDs differ from required subjects")
    if not fixture:
        expected_first_party = set(policy["requiredFirstPartyAppIds"])
        if projected and inventory["cohortPolicy"] == "current-eight-experimental-mail":
            expected_first_party.add("mail-prototype")
        if first_party_ids != expected_first_party:
            errors.append("app subject inventory differs from the policy-required first-party apps")
        if not expected_first_party.issubset(required_ids):
            errors.append("policy-required first-party app is not required for release")
        if not any(
            subject["sourceAuthority"] == "third-party-pilot"
            and subject["requiredForRelease"]
            for subject in inventory["subjects"]
        ):
            errors.append("authenticated third-party pilot app is absent from release coverage")
    return errors


def _descriptor_semantic_digest(descriptor: dict[str, Any]) -> str:
    normalized = copy.deepcopy(descriptor)
    normalized.pop("descriptorDigest", None)
    return _digest_bytes(_canonical_bytes(normalized))


def _support_lifecycle_errors(
    contract: dict[str, Any],
    evidence_dir: Path | None,
    ledger: dict[str, Any] | None,
    fixture: bool,
    evaluation: datetime,
    policy: dict[str, Any],
) -> tuple[dict[str, Any] | None, list[str]]:
    """Resolve the oldest ordinarily supported release from protected lifecycle evidence."""

    authority = contract["supportLifecycleAuthority"]
    descriptor_binding = contract["evidence"]["supportLifecycleDescriptor"]
    if fixture and authority is None and descriptor_binding is None:
        if ledger is None:
            return None, []
        selected = next(
            (
                record
                for record in ledger["records"]
                if record["selfDigest"] == ledger["oldestSupportedRecordDigest"]
            ),
            None,
        )
        return selected, []
    if authority is None or descriptor_binding is None:
        return None, [
            "operational oldest-supported selection requires authenticated support-lifecycle evidence"
        ]

    errors: list[str] = []
    receipt, receipt_errors = _bound_json(
        evidence_dir,
        authority["summary"],
        LIFECYCLE_RECEIPT_SCHEMA,
        "support-lifecycle authority receipt",
    )
    descriptor, descriptor_errors = _bound_json(
        evidence_dir,
        descriptor_binding,
        LIFECYCLE_DESCRIPTOR_SCHEMA,
        "support-lifecycle descriptor",
    )
    errors.extend(receipt_errors)
    errors.extend(descriptor_errors)
    provenance = authority["provenance"]
    producer = policy["supportLifecycleProducer"]
    if not authority["operational"]:
        errors.append("support-lifecycle authority is not operational")
    if authority["artifactDigest"] == ZERO_DIGEST:
        errors.append("support-lifecycle authority artifact digest is unset")
    if (
        provenance["repositoryIdentity"] != policy["repositoryIdentity"]
        or provenance["workflowPath"] != producer["workflowPath"]
        or provenance["workflowCommit"] != contract["repository"]["sourceCommit"]
        or provenance["environment"] != producer["environment"]
        or provenance["conclusion"] != "success"
        or provenance["artifactDigest"] != authority["artifactDigest"]
    ):
        errors.append("support-lifecycle authority provenance differs from its protected producer")
    expected_artifact = (
        f"{producer['artifactNamePrefix']}{contract['release']['releaseId']}-"
        f"{provenance['runId']}-{provenance['runAttempt']}"
    )
    if provenance["artifactName"] != expected_artifact:
        errors.append("support-lifecycle authority artifact name is not canonical")
    if authority["summary"] is not None:
        if authority["summary"]["fileName"] != producer["summaryFileName"]:
            errors.append("support-lifecycle authority receipt file name differs")
        if authority["summaryDigest"] != authority["summary"]["digest"]:
            errors.append("support-lifecycle authority receipt digest differs")

    if receipt is None or descriptor is None or ledger is None:
        return None, errors
    if (
        receipt["publicationState"] != "publication-complete"
        or receipt["verificationStatus"] != "verified"
        or receipt["conflict"]
        or receipt["operation"] not in {"inserted", "verified-existing"}
        or receipt["redaction"]["status"] != "pass"
    ):
        errors.append("support-lifecycle authority is not an independently verified publication")
    if descriptor_binding["digest"] != receipt["descriptorBytesDigest"]:
        errors.append("support-lifecycle descriptor bytes differ from the protected receipt")
    if descriptor["descriptorDigest"] != _descriptor_semantic_digest(descriptor):
        errors.append("support-lifecycle descriptor semantic digest is invalid")
    if (
        descriptor["descriptorDigest"] != receipt["descriptorDigest"]
        or descriptor["ledgerDigest"] != receipt["ledgerDigest"]
    ):
        errors.append("support-lifecycle descriptor differs from the protected receipt")
    if (
        descriptor["descriptorEdition"] != receipt["descriptorEdition"]
        or descriptor["updateKeyIdentityDigest"] != receipt["updateKeyIdentityDigest"]
        or descriptor["updateKeyScope"] != receipt["updateKeyScope"]
        or descriptor["updateKeyDocName"] != receipt["updateKeyDocName"]
        or descriptor["previousDescriptorEdition"]
        != receipt["previousDescriptorEdition"]
        or descriptor["previousDescriptorDigest"] != receipt["previousDescriptorDigest"]
    ):
        errors.append("support-lifecycle descriptor coordinates differ from the protected receipt")
    generated = _timestamp(descriptor["generatedAt"], "support-lifecycle generatedAt")
    effective = _timestamp(descriptor["effectiveAt"], "support-lifecycle effectiveAt")
    stale = _timestamp(descriptor["staleAt"], "support-lifecycle staleAt")
    receipt_generated = _timestamp(
        receipt["generatedAt"], "support-lifecycle receipt generatedAt"
    )
    if not generated <= effective <= evaluation < stale or receipt_generated > evaluation:
        errors.append("support-lifecycle descriptor is not effective and fresh")

    ordinarily_supported = [
        int(row["buildVersion"])
        for row in descriptor["entries"]
        if row["lifecycleStatus"] in {"current-stable", "supported-maintenance"}
    ]
    minimum = min(ordinarily_supported) if ordinarily_supported else None
    declared_minimum = (
        int(descriptor["minimumSupportedBuild"])
        if descriptor["minimumSupportedBuild"] is not None
        else None
    )
    if minimum is None or declared_minimum != minimum:
        errors.append("support-lifecycle minimum supported build is absent or not derived")
        return None, errors
    entries = [
        row
        for row in descriptor["entries"]
        if int(row["buildVersion"]) == minimum
        and row["lifecycleStatus"] in {"current-stable", "supported-maintenance"}
    ]
    if len(entries) != 1:
        errors.append("support-lifecycle minimum supported release is ambiguous")
        return None, errors
    entry = entries[0]
    matches = [
        record
        for record in ledger["records"]
        if record["releaseId"] == entry["releaseId"]
        and record["buildVersion"] == minimum
        and record["sourceCommit"] == entry["sourceCommit"]
        and record["releaseRootDigest"] == entry["productDigest"]
        and record["recordStatus"] in {"imported", "published"}
    ]
    if len(matches) != 1:
        errors.append("support-lifecycle minimum supported release is absent from history")
        return None, errors
    selected = matches[0]
    if ledger["oldestSupportedRecordDigest"] != selected["selfDigest"]:
        errors.append("history oldest-supported record differs from authenticated lifecycle evidence")
    return selected, errors


def _matrix_static_result(
    row: dict[str, Any],
    evaluation: dict[str, Any],
    snapshot_contract: dict[str, Any],
    baseline_registry: dict[str, Any] | None,
) -> tuple[str, list[str]]:
    errors: list[str] = []
    warnings: list[str] = []
    snapshot_version = snapshot_contract["contractVersion"]
    minimum = row["minimumContractVersion"]
    maximum = row["maximumTestedContractVersion"]
    if minimum > snapshot_version:
        errors.append("contract.below-minimum")
    if maximum < snapshot_version:
        errors.append("contract.newer-than-tested")

    target_stability = row["targetStability"]
    target_baseline = row["targetBaseline"]
    target_definition: dict[str, Any] | None = None
    target_status: str | None = None
    if evaluation["baselineId"] != target_baseline:
        errors.append("evaluation.baseline-mismatch")
    if target_baseline is not None:
        if baseline_registry is None:
            errors.append("baseline.registry-unavailable")
        else:
            registry = baseline_registry["baselineRegistry"]
            target_definition = next(
                (
                    definition
                    for definition in registry["definitions"]
                    if definition["id"] == target_baseline
                ),
                None,
            )
            lifecycle = next(
                (
                    item
                    for item in reversed(registry["lineage"])
                    if item["id"] == target_baseline
                ),
                None,
            )
            target_status = lifecycle["status"] if lifecycle is not None else None
            if target_definition is None or target_status is None:
                errors.append("baseline.unknown")
            elif target_definition["firstCompleteContractVersion"] > snapshot_version:
                errors.append("baseline.not-yet-complete")
            elif target_status in {"end-of-support", "rejected"}:
                errors.append("baseline.unsupported")
            elif target_status not in SUPPORTED_BASELINE_STATES:
                if target_stability == "experimental" and evaluation["releaseRole"] == "preview":
                    warnings.append("baseline.preview-only")
                else:
                    errors.append("baseline.inactive")
            elif target_status == "deprecated":
                warnings.append("baseline.deprecated")
            elif target_stability == "experimental":
                warnings.append("baseline.experimental-target")
            if target_definition is not None and (
                minimum > target_definition["firstCompleteContractVersion"]
                or maximum < target_definition["firstCompleteContractVersion"]
            ):
                errors.append("baseline.outside-contract-range")
    elif target_stability == "stable":
        errors.append("baseline.missing")

    descriptors = {
        descriptor["name"]: descriptor for descriptor in snapshot_contract["capabilities"]
    }
    baseline_capabilities = (
        set(target_definition["capabilities"]) if target_definition is not None else set()
    )
    for optional, capabilities in (
        (False, row["requiredCapabilities"]),
        (True, row["optionalCapabilities"]),
    ):
        prefix = "optional-capability" if optional else "capability"
        for capability in capabilities:
            descriptor = descriptors.get(capability)
            if descriptor is None:
                errors.append(f"{prefix}.unknown")
                continue
            stability = descriptor["stability"]
            if descriptor["audience"] == "operator-only" or stability == "operator-only":
                errors.append(f"{prefix}.operator-only")
                continue
            if descriptor["audience"] == "internal" or stability == "internal":
                errors.append(f"{prefix}.internal")
                continue
            if target_stability == "stable" and capability not in baseline_capabilities:
                errors.append(f"{prefix}.outside-target-baseline")
                continue
            if stability == "experimental":
                if target_stability == "stable" and capability in baseline_capabilities:
                    continue
                if not row["experimentalCapabilitiesAccepted"]:
                    errors.append(f"{prefix}.experimental-opt-in-missing")
            elif stability == "deprecated":
                warnings.append(f"{prefix}.deprecated")
            elif stability == "scheduled-for-removal":
                errors.append(f"{prefix}.scheduled-for-removal")

    findings = sorted(set([*errors, *warnings]))
    unsupported_codes = {
        "baseline.registry-unavailable",
        "baseline.unknown",
        "baseline.not-yet-complete",
        "baseline.unsupported",
        "baseline.inactive",
        "baseline.missing",
    }
    unsupported = bool(set(errors).intersection(unsupported_codes))
    range_codes = {
        "contract.below-minimum",
        "contract.newer-than-tested",
        "baseline.outside-contract-range",
    }
    if unsupported:
        verdict = "unsupported-baseline"
    elif errors and set(errors).issubset(range_codes):
        verdict = "outside-tested-range"
    elif errors:
        verdict = "incompatible"
    elif "baseline.preview-only" in warnings:
        verdict = "preview-only"
    elif warnings:
        verdict = "compatible-with-warnings"
    else:
        verdict = "compatible"
    return verdict, findings


def _matrix_errors(
    matrix: dict[str, Any],
    fixture: bool,
    contract: dict[str, Any],
    proposal: dict[str, Any] | None,
    ledger: dict[str, Any] | None,
    baseline_registry: dict[str, Any] | None,
    history_subjects: list[tuple[dict[str, Any], dict[str, Any]]],
    oldest_supported_record: dict[str, Any] | None = None,
    app_subject_inventory: dict[str, Any] | None = None,
) -> list[str]:
    errors: list[str] = []
    supported_baselines: set[str] = set()
    if baseline_registry is not None:
        for lineage in baseline_registry["baselineRegistry"]["lineage"]:
            baseline_id = lineage["id"]
            if lineage["status"] in SUPPORTED_BASELINE_STATES:
                supported_baselines.add(baseline_id)
            else:
                supported_baselines.discard(baseline_id)
    if matrix["matrixDigest"] != _semantic_digest(matrix, "matrixDigest"):
        errors.append("app compatibility matrix self digest is invalid")
    if matrix["appSubjectsDigest"] != _matrix_app_subjects_digest(matrix):
        errors.append("app compatibility matrix subject digest is invalid")
    if (
        matrix["releaseId"] != contract["release"]["releaseId"]
        or matrix["sourceCommit"] != contract["repository"]["sourceCommit"]
    ):
        errors.append("app compatibility matrix release subject differs")
    if proposal is not None and proposal["appMatrixDigest"] != matrix["matrixDigest"]:
        errors.append("proposal app-matrix digest differs from the accepted matrix")
    identities: set[tuple[str, str, str]] = set()
    authenticated_subjects = (
        {
            (subject["appId"], subject["appVersion"], subject["bundleDigest"]): subject
            for subject in app_subject_inventory["subjects"]
        }
        if app_subject_inventory is not None
        else {}
    )
    if not fixture and app_subject_inventory is None:
        errors.append("operational app matrix lacks an authenticated app subject inventory")
    matrix_subject_keys = {
        (row["appId"], row["appVersion"], row["bundleDigest"])
        for row in matrix["rows"]
    }
    if app_subject_inventory is not None and matrix_subject_keys != set(authenticated_subjects):
        errors.append("app matrix subject set differs from the authenticated inventory")
    history_by_digest = {
        record["selfDigest"]: (record, snapshot)
        for record, snapshot in history_subjects
    }
    records = ledger["records"] if ledger is not None else []
    expected_subjects: dict[str, dict[str, Any]] = {}
    if records:
        if oldest_supported_record is not None:
            expected_subjects["oldest-supported"] = oldest_supported_record
        expected_subjects["candidate"] = records[-1]
        if len(records) >= 2:
            expected_subjects["previous"] = records[-2]
        expected_subjects["preview"] = records[-1]
    for index, row in enumerate(matrix["rows"]):
        label = f"app matrix row {index}"
        key = (row["appId"], row["appVersion"], row["bundleDigest"])
        if key in identities:
            errors.append(f"{label} duplicates an app subject")
        identities.add(key)
        authenticated = authenticated_subjects.get(key)
        if authenticated is None and app_subject_inventory is not None:
            errors.append(f"{label} lacks an authenticated subject")
        elif authenticated is not None and any(
            row[field] != authenticated[field] for field in MATRIX_SUBJECT_FIELDS
        ):
            errors.append(f"{label} differs from the authenticated subject")
        if row["targetStability"] == "stable" and row["targetBaseline"] is None:
            errors.append(f"{label} stable target omits a baseline")
        if (
            row["targetStability"] == "stable"
            and row["targetBaseline"] not in supported_baselines
        ):
            errors.append(f"{label} stable app targets an inactive baseline")
        if row["targetStability"] == "legacy" and row["targetBaseline"] is not None:
            errors.append(f"{label} legacy app is silently assigned a stable baseline")
        if set(row["requiredCapabilities"]).intersection(row["optionalCapabilities"]):
            errors.append(f"{label} capability is both required and optional")
        if row["fixtureOnly"] and not fixture:
            errors.append(f"{label} fixture app cannot satisfy production coverage")
        roles = [evaluation["releaseRole"] for evaluation in row["evaluations"]]
        if len(roles) != len(set(roles)):
            errors.append(f"{label} contains duplicate release-role evaluations")
        verdicts = {evaluation["verdict"] for evaluation in row["evaluations"]}
        if "compatible" in verdicts and any(
            evaluation["contractVersion"] < row["minimumContractVersion"]
            or evaluation["contractVersion"] > row["maximumTestedContractVersion"]
            for evaluation in row["evaluations"] if evaluation["verdict"] == "compatible"
        ):
            errors.append(f"{label} is marked compatible outside its tested range")
        if any(evaluation["runtimeObserved"] for evaluation in row["evaluations"]):
            errors.append(f"{label} static matrix claims a runtime observation")
        derived_verdicts: dict[str, str] = {}
        for evaluation in row["evaluations"]:
            role = evaluation["releaseRole"]
            expected = expected_subjects.get(role)
            if expected is None:
                errors.append(f"{label} {role} evaluation has no authenticated history subject")
                continue
            if (
                evaluation["releaseId"] != expected["releaseId"]
                or evaluation["contractVersion"] != expected["contractVersion"]
            ):
                errors.append(f"{label} {role} evaluation subject differs from history")
            accepted = history_by_digest.get(expected["selfDigest"])
            if accepted is None:
                errors.append(f"{label} {role} evaluation snapshot is unavailable")
                continue
            if role == "preview" and (
                proposal is None
                or row["targetBaseline"] != proposal["targetBaselineId"]
                or evaluation["contractVersion"] != proposal["targetContractVersion"]
            ):
                errors.append(f"{label} preview evaluation differs from the accepted proposal")
            derived_verdict, derived_findings = _matrix_static_result(
                row, evaluation, accepted[1], baseline_registry
            )
            derived_verdicts[role] = derived_verdict
            if not evaluation["staticVerified"]:
                errors.append(f"{label} {role} evaluation is not statically verified")
            if evaluation["verdict"] != derived_verdict:
                errors.append(f"{label} {role} verdict differs from contract-derived compatibility")
            if evaluation["findingCodes"] != derived_findings:
                errors.append(f"{label} {role} finding codes differ from contract-derived compatibility")
        if row["requiredForRelease"] and any(
            verdict not in {"compatible", "compatible-with-warnings", "preview-only"}
            for verdict in derived_verdicts.values()
        ):
            errors.append(f"{label} required release app is incompatible")
        if row["requiredForRelease"] and not fixture:
            required_roles = {"oldest-supported", "previous", "candidate"}
            if not required_roles.issubset(roles) or set(roles).difference(required_roles | {"preview"}):
                errors.append(f"{label} omits a required static release-role evaluation")
            if any(
                derived_verdicts.get(role) not in {"compatible", "compatible-with-warnings"}
                for role in required_roles
            ):
                errors.append(f"{label} required static release-role evaluation is not compatible")
            if ledger is None or len(ledger["records"]) < 2:
                errors.append(f"{label} lacks authenticated oldest/previous release history")
    if (
        not fixture
        and records
        and records[-1]["appMatrixDigest"] != matrix["matrixDigest"]
    ):
        errors.append("history head app-matrix digest differs from the accepted matrix")
    required_ids = (
        set(app_subject_inventory["requiredAppIds"])
        if app_subject_inventory is not None
        else set(matrix["requiredAppIds"])
    )
    if set(matrix["requiredAppIds"]) != required_ids:
        errors.append("app matrix required app IDs differ from the authenticated inventory")
    covered_ids = {row["appId"] for row in matrix["rows"] if row["requiredForRelease"]}
    if required_ids != covered_ids:
        errors.append("app compatibility matrix omits or invents a required release app")
    return errors


def _runtime_errors(
    observation: dict[str, Any],
    contract: dict[str, Any],
    fixture: bool,
    evaluation: datetime,
    policy: dict[str, Any],
    ledger: dict[str, Any] | None,
    matrix: dict[str, Any] | None,
    authority: dict[str, Any] | None = None,
    observation_binding: dict[str, Any] | None = None,
) -> list[str]:
    errors: list[str] = []
    if observation["observationDigest"] != _semantic_digest(observation, "observationDigest"):
        errors.append("runtime observation self digest is invalid")
    if observation["sourceCommit"] != contract["repository"]["sourceCommit"]:
        errors.append("runtime observation source commit differs")
    if observation["releaseId"] != contract["release"]["releaseId"]:
        errors.append("runtime observation release differs")
    if observation["buildVersion"] != contract["release"]["buildVersion"]:
        errors.append("runtime observation build differs")
    if observation["releaseRootDigest"] != contract["release"]["releaseRootDigest"]:
        errors.append("runtime observation release root differs")
    if observation["contractVersion"] != contract["contractVersion"]:
        errors.append("runtime observation contract version differs")
    if set(observation["baselineIds"]) != set(contract["activeStableBaselines"]):
        errors.append("runtime observation baseline set differs")
    if ledger is None or observation["contractSnapshotDigest"] != ledger["records"][-1]["contractSnapshot"]["digest"]:
        errors.append("runtime observation contract snapshot differs from accepted history")
    if matrix is None or observation["appSubjectsDigest"] != matrix["appSubjectsDigest"]:
        errors.append("runtime observation app subjects differ from the accepted matrix")
    started = _timestamp(observation["startedAt"], "runtime observation startedAt")
    completed = _timestamp(observation["completedAt"], "runtime observation completedAt")
    if completed < started or completed > evaluation:
        errors.append("runtime observation timing is invalid or future-dated")
    if (evaluation - completed).total_seconds() > policy["maximumRuntimeObservationHours"] * 3600:
        errors.append("runtime observation is stale")
    if observation["longDurationSoak"]:
        errors.append("PR-296 runtime evidence cannot claim a long-duration soak")
    if observation["representativeChecks"] != policy["requiredRuntimeRepresentativeChecks"]:
        errors.append("runtime observation omits or invents a required representative check")
    if (
        observation["authorizationFailureChecks"]
        != policy["requiredRuntimeDenialChecks"]
    ):
        errors.append("runtime observation omits or invents a required authorization-failure check")
    if observation["status"] != "pass" or observation["partial"]:
        errors.append("runtime observation is partial or failed")
    if not fixture and observation["fixtureOnly"]:
        errors.append("fixture runtime observation cannot satisfy production verification")
    if not fixture:
        if authority is None or observation_binding is None:
            errors.append(
                "operational runtime observation lacks an authenticated protected producer"
            )
            return errors
        provenance = authority["provenance"]
        producer = policy["runtimeObservationProducer"]
        if not authority["operational"]:
            errors.append("runtime observation authority is not operational")
        if authority["artifactDigest"] == ZERO_DIGEST:
            errors.append("runtime observation authority artifact digest is unset")
        if (
            provenance["repositoryIdentity"] != policy["repositoryIdentity"]
            or provenance["workflowPath"] != producer["workflowPath"]
            or provenance["workflowCommit"] != contract["repository"]["sourceCommit"]
            or provenance["environment"] != producer["environment"]
            or provenance["conclusion"] != "success"
            or provenance["artifactDigest"] != authority["artifactDigest"]
        ):
            errors.append("runtime observation authority provenance differs from its protected producer")
        expected_artifact = (
            f"{producer['artifactNamePrefix']}{contract['release']['releaseId']}-"
            f"{provenance['runId']}-{provenance['runAttempt']}"
        )
        if provenance["artifactName"] != expected_artifact:
            errors.append("runtime observation authority artifact name is not canonical")
        if authority["summary"] != observation_binding:
            errors.append("runtime observation authority binds another observation")
        elif authority["summary"]["fileName"] != producer["summaryFileName"]:
            errors.append("runtime observation authority file name differs")
        if authority["summaryDigest"] != observation["observationDigest"]:
            errors.append("runtime observation authority semantic digest differs")
        if (
            observation["workflowPath"] != provenance["workflowPath"]
            or observation["runId"] != provenance["runId"]
            or observation["runAttempt"] != provenance["runAttempt"]
        ):
            errors.append("runtime observation producer coordinates differ from its authority")
    return errors


def _expected_authority_artifact_name(
    name: str,
    contract: dict[str, Any],
    summary: dict[str, Any],
    provenance: dict[str, Any],
    prefix: str,
) -> str:
    if name == "thirdPartyPilot":
        subject = summary.get("pilotId", "")
    elif name == "federatedCatalog":
        subject = summary.get("executionId", "")
    else:
        subject = (
            f"{contract['release']['releaseId']}-{contract['release']['buildVersion']}"
        )
    return f"{prefix}{subject}-{provenance['runId']}-{provenance['runAttempt']}"


def _authority_summary_digest(name: str, summary: dict[str, Any]) -> str:
    normalized = copy.deepcopy(summary)
    if name == "independentReproducibility":
        normalized.pop("summaryDigest", None)
    else:
        normalized["summaryDigest"] = ZERO_DIGEST
        if name in {"thirdPartyPilot", "federatedCatalog"}:
            normalized.pop("signatureBase64", None)
    return _digest_bytes(_canonical_bytes(normalized))


def _authority_errors(
    contract: dict[str, Any],
    evidence_dir: Path | None,
    policy: dict[str, Any],
    app_subject_inventory: dict[str, Any] | None = None,
) -> list[str]:
    errors: list[str] = []
    summaries: dict[str, dict[str, Any]] = {}
    for name, schema in AUTHORITY_SCHEMAS.items():
        authority = contract["authorities"][name]
        summary, item_errors = _bound_json(evidence_dir, authority["summary"], schema, f"{name} authority summary")
        errors.extend(item_errors)
        if authority["operational"] is not True:
            errors.append(f"{name} authority is not operational")
        if authority["summaryDigest"] == ZERO_DIGEST or authority["artifactDigest"] == ZERO_DIGEST:
            errors.append(f"{name} authority has an unset digest")
        provenance = authority["provenance"]
        producer = policy["requiredAuthorityProducers"][name]
        if provenance["repositoryIdentity"] != policy["repositoryIdentity"]:
            errors.append(f"{name} authority repository differs")
        if provenance["workflowPath"] != producer["workflowPath"]:
            errors.append(f"{name} authority workflow differs")
        if provenance["environment"] != producer["environment"]:
            errors.append(f"{name} authority protected environment differs")
        if provenance["conclusion"] != "success":
            errors.append(f"{name} authority producer did not conclude successfully")
        if provenance["workflowCommit"] != contract["repository"]["sourceCommit"]:
            errors.append(f"{name} authority workflow commit differs")
        if provenance["artifactDigest"] != authority["artifactDigest"]:
            errors.append(f"{name} authority artifact digest differs")
        if summary is not None:
            summaries[name] = summary
            if authority["summary"]["fileName"] != producer["summaryFileName"]:
                errors.append(f"{name} authority summary file name differs")
            expected_artifact = _expected_authority_artifact_name(
                name, contract, summary, provenance, producer["artifactNamePrefix"]
            )
            if provenance["artifactName"] != expected_artifact:
                errors.append(f"{name} authority artifact name is not canonical")
            if authority["summaryDigest"] != summary.get("summaryDigest", authority["summary"]["digest"]):
                # The PR-291 protected summary uses a file digest rather than a summaryDigest field.
                if authority["summaryDigest"] != authority["summary"]["digest"]:
                    errors.append(f"{name} authority summary digest differs")
            if (
                name != "protectedRelease"
                and summary["summaryDigest"] != _authority_summary_digest(name, summary)
            ):
                errors.append(f"{name} authority summary self digest is invalid")
            if summary.get("releaseId") != contract["release"]["releaseId"]:
                errors.append(f"{name} authority release differs")
            if str(summary.get("buildVersion")) != str(contract["release"]["buildVersion"]):
                errors.append(f"{name} authority build differs")
            if summary.get("fixtureOnly", summary.get("fixture", False)) or summary.get("selfTest", False):
                errors.append(f"{name} fixture authority cannot satisfy operational closeout")
            if summary.get("sourceCommit", summary.get("candidateCommit")) != contract["repository"]["sourceCommit"]:
                errors.append(f"{name} authority source commit differs")
            if summary.get("operational", True) is not True or summary.get("status") not in {
                "pass", "independently-reproduced"
            }:
                errors.append(f"{name} authority is not a successful operational closeout")
    expected_roots = contract["authorityRoots"]
    for name in AUTHORITY_SCHEMAS:
        if expected_roots[name] != contract["authorities"][name]["summaryDigest"]:
            errors.append(f"{name} exact authority root differs")
    federation = summaries.get("federatedCatalog")
    if federation is not None and federation.get("state") != "operational-federation-complete":
        errors.append("PR-295 authority is not an operational federation closeout")
    pilot = summaries.get("thirdPartyPilot")
    if pilot is not None and pilot.get("state") != "operational-pilot-complete":
        errors.append("PR-294 authority is not an operational pilot closeout")
    protected = summaries.get("protectedRelease")
    if protected is not None:
        classifications = protected.get("evidenceClassification", {})
        expected = {
            "protectedRcOperation": "completed",
            "gaValidation": "completed",
            "gaPublication": "completed",
            "publicObservation": "completed",
            "independentReproducibility": "independently-reproduced",
        }
        if protected.get("mode") != "closeout" or protected.get("lifecycleState") != "publicly-observed" or any(
            classifications.get(key) != value for key, value in expected.items()
        ):
            errors.append("PR-291 authority is not an exact protected closeout")
    independent = summaries.get("independentReproducibility")
    if independent is not None and (
        independent.get("operationMode") != "closeout"
        or independent.get("lifecycleState") != "independently-reproduced"
        or independent.get("comparisonStatus") != "pass"
        or independent.get("evidenceClassification") != "authenticated-external-provider"
    ):
        errors.append("PR-292 authority is not an exact independent closeout")
    catalog = summaries.get("catalogAuthority")
    if catalog is not None and (
        catalog.get("mode") != "closeout"
        or catalog.get("protectedReleaseSummaryDigest") != expected_roots["protectedRelease"]
        or catalog.get("independentReproducibilitySummaryDigest")
        != expected_roots["independentReproducibility"]
    ):
        errors.append("PR-293 authority predecessor roots differ")
    if pilot is not None:
        pilot_roots = pilot.get("authorityDigests", {})
        if any(
            pilot_roots.get(name) != expected_roots[name]
            for name in ("protectedRelease", "independentReproducibility", "catalogAuthority")
        ):
            errors.append("PR-294 authority predecessor roots differ")
    if federation is not None:
        federation_roots = federation.get("authorityDigests", {})
        if any(
            federation_roots.get(name) != expected_roots[name]
            for name in (
                "protectedRelease", "independentReproducibility", "catalogAuthority", "thirdPartyPilot"
            )
        ):
            errors.append("PR-295 authority predecessor roots differ")
    if app_subject_inventory is not None:
        independent_subject_digest = (
            summaries.get("independentReproducibility", {}).get("subjectInventoryDigest")
        )
        pilot_external_digest = next(
            (
                row.get("digest")
                for row in summaries.get("thirdPartyPilot", {}).get("evidence", [])
                if row.get("id") == "third-party-pilot.external-developer"
            ),
            None,
        )
        federation_descriptor_digest = summaries.get("federatedCatalog", {}).get(
            "descriptorDigest"
        )
        expected_source_digests = {
            "first-party-release": independent_subject_digest,
            "third-party-pilot": pilot_external_digest,
            "federated-catalog": federation_descriptor_digest,
        }
        pilot_subjects = []
        for subject in app_subject_inventory["subjects"]:
            source = subject["sourceAuthority"]
            if source == "fixture":
                continue
            if subject["sourceEvidenceDigest"] != expected_source_digests[source]:
                errors.append(
                    f"app subject {subject['appId']} source evidence differs from its authority"
                )
            if source == "third-party-pilot":
                pilot_subjects.append(subject)
        if pilot is not None:
            pilot_app = pilot["externalApp"]
            if len(pilot_subjects) != 1 or any(
                subject["appId"] != pilot_app["appId"]
                or subject["publisherId"] != pilot_app["publisherKeyId"]
                for subject in pilot_subjects
            ):
                errors.append("app subject inventory differs from the authenticated PR-294 app")
    return errors


def _evidence_member_errors(
    evidence_dir: Path,
    contract_path: Path,
    contract: dict[str, Any],
    ledger: dict[str, Any] | None,
) -> list[str]:
    expected: set[str] = set()
    for name, binding in contract["evidence"].items():
        if name == "graduationRecords":
            expected.update(item["fileName"] for item in binding)
        elif binding is not None:
            expected.add(binding["fileName"])
    for authority in contract["authorities"].values():
        if authority["summary"] is not None:
            expected.add(authority["summary"]["fileName"])
    previous_authority = contract["previousHistoryAuthority"]
    if previous_authority is not None and previous_authority["summary"] is not None:
        expected.add(previous_authority["summary"]["fileName"])
    for name in ("supportLifecycleAuthority", "runtimeObservationAuthority"):
        authority = contract[name]
        if authority is not None and authority["summary"] is not None:
            expected.add(authority["summary"]["fileName"])
    if ledger is not None:
        expected.update(record["contractSnapshot"]["fileName"] for record in ledger["records"])
    try:
        expected.add(contract_path.relative_to(evidence_dir).as_posix())
    except ValueError:
        pass
    actual: set[str] = set()
    for path in evidence_dir.iterdir():
        if path.is_symlink() or not path.is_file():
            return ["evidence directory contains a link or non-file member"]
        if path.name.startswith("._") or path.name in {".DS_Store", "__MACOSX"}:
            return ["evidence directory contains a prohibited archive sidecar"]
        actual.add(path.name)
    extra = sorted(actual.difference(expected))
    missing = sorted(expected.difference(actual))
    errors = [f"unexpected evidence member {name}" for name in extra]
    errors.extend(f"missing evidence member {name}" for name in missing)
    return errors


def _report(summary: dict[str, Any]) -> str:
    lines = [
        "# Platform API 1.x compatibility operations",
        "",
        f"- Status: `{summary['status']}`",
        f"- State: `{summary['state']}`",
        f"- Operational: `{'yes' if summary['operational'] else 'no'}`",
        f"- Fixture only: `{'yes' if summary['fixtureOnly'] else 'no'}`",
        "- Future Platform API 1.x baseline activation authorized: `no`",
        "- Long-duration cross-version soak: `not evaluated; PR-300 boundary`",
    ]
    if summary["blockers"]:
        lines.extend(("", "## Blockers", ""))
        lines.extend(f"- `{item}`" for item in summary["blockers"])
    return "\n".join(lines) + "\n"


def run(
    workspace_root: Path,
    execution_contract: Path,
    mode: str,
    out_dir: Path | None = None,
    evidence_dir: Path | None = None,
    *,
    authenticated_projection: Any = None,
) -> int:
    """Verify one Platform API 1.x phase and emit bounded local evidence."""

    if mode not in MODES:
        raise ValueError("unsupported Platform API 1.x mode")
    workspace = workspace_root.resolve()
    contract_path = _confined_path(workspace, execution_contract, "Platform API 1.x contract", directory=False)
    contract = read_json(contract_path)
    if not isinstance(contract, dict):
        raise ValueError("Platform API 1.x contract is not an object")
    schema_errors = validate_schema(contract, EXECUTION_SCHEMA)
    if schema_errors:
        raise ValueError("Platform API 1.x contract failed its closed schema: " + "; ".join(schema_errors[:8]))
    if scan_value(contract):
        raise ValueError("Platform API 1.x contract contains prohibited material")
    policy, policy_digest = _policy(workspace)
    if contract["policyDigest"] != policy_digest:
        raise ValueError("Platform API 1.x contract binds another policy")
    fixture = contract["fixtureOnly"] or contract["selfTest"]
    evaluation = _timestamp(contract["evaluationTime"], "Platform API 1.x evaluationTime")
    if evaluation > datetime.now(timezone.utc):
        raise ValueError("Platform API 1.x evaluation time is in the future")
    errors: list[str] = []
    if fixture and contract["requestedState"] in OPERATIONAL_STATES:
        errors.append("fixture or self-test contract requests an operational state")
    if contract["urlApiVersion"] != "v1":
        errors.append("Platform API 1.x operations require URL API v1")
    resolved_evidence = None
    if evidence_dir is not None:
        resolved_evidence = _confined_path(workspace, evidence_dir, "Platform API 1.x evidence", directory=True)

    rank = MODES.index(mode)
    stage_ok = {stage: False for stage in STAGES}
    stage_ok["preflight"] = not errors
    ledger = previous_ledger = baseline_registry = proposal = deprecation = matrix = runtime = None
    previous_baseline_registry = None
    selected_rc_freeze = None
    app_subject_inventory = None
    app_subject_inventory_errors: list[str] = []
    oldest_supported_record = None
    prior_deprecation = None
    history_subjects: list[tuple[dict[str, Any], dict[str, Any]]] = []
    graduations: list[dict[str, Any]] = []

    if rank >= 1:
        baseline_registry, stage_errors = _bound_json(
            resolved_evidence,
            contract["evidence"]["baselineRegistry"],
            BASELINE_REGISTRY_SCHEMA,
            "baseline registry",
        )
        if baseline_registry is not None and not stage_errors:
            stage_errors.extend(
                _baseline_registry_errors(baseline_registry, contract, fixture, policy)
            )
        ledger, ledger_errors = _bound_json(
            resolved_evidence,
            contract["evidence"]["historyLedger"],
            HISTORY_SCHEMA,
            "history ledger",
        )
        stage_errors.extend(ledger_errors)
        previous_ledger, previous_history_errors = _optional_bound_json(
            resolved_evidence,
            contract["evidence"]["previousHistoryLedger"],
            HISTORY_SCHEMA,
            "previous history ledger",
        )
        stage_errors.extend(previous_history_errors)
        previous_baseline_registry, previous_registry_errors = _optional_bound_json(
            resolved_evidence,
            contract["evidence"]["previousBaselineRegistry"],
            BASELINE_REGISTRY_SCHEMA,
            "previous baseline registry",
        )
        stage_errors.extend(previous_registry_errors)
        selected_rc_freeze, selected_rc_freeze_errors = _optional_bound_json(
            resolved_evidence,
            contract["evidence"]["selectedRcFreeze"],
            SELECTED_RC_FREEZE_SCHEMA,
            "selected RC freeze",
        )
        stage_errors.extend(selected_rc_freeze_errors)
        protected_summary = independent_summary = None
        if not fixture:
            if selected_rc_freeze is None:
                stage_errors.append(
                    "production history requires the authenticated selected RC freeze"
                )
            stage_errors.extend(_authority_errors(contract, resolved_evidence, policy))
            protected_summary, protected_errors = _bound_json(
                resolved_evidence,
                contract["authorities"]["protectedRelease"]["summary"],
                AUTHORITY_SCHEMAS["protectedRelease"],
                "protectedRelease authority summary",
            )
            independent_summary, independent_errors = _bound_json(
                resolved_evidence,
                contract["authorities"]["independentReproducibility"]["summary"],
                AUTHORITY_SCHEMAS["independentReproducibility"],
                "independentReproducibility authority summary",
            )
            stage_errors.extend(protected_errors)
            stage_errors.extend(independent_errors)
        deprecation, current_deprecation_errors = _bound_json(
            resolved_evidence,
            contract["evidence"]["deprecationLedger"],
            DEPRECATION_SCHEMA,
            "deprecation ledger",
        )
        stage_errors.extend(current_deprecation_errors)
        prior_deprecation, previous_deprecation_errors = _optional_bound_json(
            resolved_evidence,
            contract["evidence"]["previousDeprecationLedger"],
            DEPRECATION_SCHEMA,
            "previous deprecation ledger",
        )
        stage_errors.extend(previous_deprecation_errors)
        if ledger is not None and not ledger_errors:
            history_subjects, snapshot_errors = _history_snapshot_subjects(
                ledger, resolved_evidence
            )
            stage_errors.extend(snapshot_errors)
        if previous_ledger is not None and not previous_history_errors:
            if previous_baseline_registry is not None and not previous_registry_errors:
                stage_errors.extend(
                    _historical_baseline_registry_errors(
                        previous_baseline_registry,
                        previous_ledger["records"][-1]["contractVersion"],
                        fixture,
                        policy,
                    )
                )
            stage_errors.extend(
                _history_errors(
                    previous_ledger,
                    resolved_evidence,
                    contract,
                    previous_baseline_registry,
                    None,
                    fixture,
                    evaluation,
                    policy,
                    bind_execution_head=False,
                )
            )
        if ledger is not None and not stage_errors:
            stage_errors.extend(
                _history_errors(
                    ledger,
                    resolved_evidence,
                    contract,
                    baseline_registry,
                    contract["evidence"]["baselineRegistry"],
                    fixture,
                    evaluation,
                    policy,
                )
            )
            stage_errors.extend(_history_extension_errors(ledger, previous_ledger, fixture))
            if baseline_registry is not None:
                stage_errors.extend(
                    _baseline_registry_extension_errors(
                        baseline_registry,
                        previous_baseline_registry,
                        previous_ledger,
                    )
                )
            if not fixture:
                stage_errors.extend(
                    _current_history_authority_errors(
                        contract,
                        ledger,
                        selected_rc_freeze,
                        contract["evidence"]["selectedRcFreeze"],
                        protected_summary,
                        independent_summary,
                    )
                )
            stage_errors.extend(
                _deprecation_errors(
                    deprecation,
                    prior_deprecation,
                    contract["contractVersion"],
                    history_subjects,
                )
            )
            stage_errors.extend(
                _deprecation_history_binding_errors(
                    deprecation, prior_deprecation, ledger, previous_ledger
                )
            )
            stage_errors.extend(
                _previous_history_authority_errors(
                    contract,
                    ledger,
                    previous_ledger,
                    resolved_evidence,
                    fixture,
                    policy,
                    prior_deprecation,
                    previous_baseline_registry,
                    contract["evidence"]["previousBaselineRegistry"],
                )
            )
            oldest_supported_record, lifecycle_errors = _support_lifecycle_errors(
                contract,
                resolved_evidence,
                ledger,
                fixture,
                evaluation,
                policy,
            )
            stage_errors.extend(lifecycle_errors)
        errors.extend(stage_errors)
        stage_ok["history"] = stage_ok["preflight"] and not stage_errors
    if rank >= 2:
        app_subject_inventory, app_subject_inventory_errors = _optional_bound_json(
            resolved_evidence,
            contract["evidence"]["appSubjectInventory"],
            ("platform-api-1.x-app-subject-inventory-v4.schema.json" if authenticated_projection is not None
             and authenticated_projection.inventory().get("schemaVersion") == 4 else
             "platform-api-1.x-app-subject-inventory-v2.schema.json"
             if authenticated_projection is not None else APP_SUBJECT_INVENTORY_SCHEMA),
            "app subject inventory",
        )
        if app_subject_inventory is not None and not app_subject_inventory_errors:
            app_subject_inventory_errors.extend(
                _app_subject_inventory_errors(
                    app_subject_inventory, fixture, contract, policy, authenticated_projection
                )
            )
        proposal, stage_errors = _optional_bound_json(resolved_evidence, contract["evidence"]["baselineProposal"], PROPOSAL_SCHEMA, "baseline proposal")
        stage_errors.extend(
            _proposal_presence_errors(proposal, baseline_registry, policy)
        )
        if proposal is not None and not stage_errors:
            stage_errors.extend(
                _proposal_errors(proposal, contract, baseline_registry, fixture, policy)
            )
            proposal_matrix, matrix_binding_errors = _bound_json(
                resolved_evidence,
                contract["evidence"]["appMatrix"],
                MATRIX_SCHEMA,
                "proposal app compatibility matrix",
            )
            stage_errors.extend(matrix_binding_errors)
            stage_errors.extend(app_subject_inventory_errors)
            if proposal_matrix is not None and not matrix_binding_errors:
                proposal_matrix_errors = _matrix_errors(
                    proposal_matrix,
                    fixture,
                    contract,
                    proposal,
                    ledger,
                    baseline_registry,
                    history_subjects,
                    oldest_supported_record,
                    app_subject_inventory,
                )
                stage_errors.extend(proposal_matrix_errors)
                if not proposal_matrix_errors:
                    matrix = proposal_matrix
        errors.extend(stage_errors)
        stage_ok["proposal"] = stage_ok["history"] and not stage_errors
    if rank >= 3:
        stage_errors = []
        for index, binding in enumerate(contract["evidence"]["graduationRecords"]):
            record, item_errors = _bound_json(resolved_evidence, binding, GRADUATION_SCHEMA, f"graduation record {index}")
            stage_errors.extend(item_errors)
            if record is not None:
                graduations.append(record)
        if not stage_errors:
            stage_errors.extend(
                _graduation_errors(
                    graduations,
                    proposal,
                    contract,
                    baseline_registry,
                    history_subjects,
                    fixture,
                    evaluation,
                    policy,
                )
            )
        errors.extend(stage_errors)
        stage_ok["graduation"] = stage_ok["proposal"] and not stage_errors
    if rank >= 4:
        matrix, stage_errors = _bound_json(resolved_evidence, contract["evidence"]["appMatrix"], MATRIX_SCHEMA, "app compatibility matrix")
        stage_errors.extend(app_subject_inventory_errors)
        if not fixture and app_subject_inventory is None:
            stage_errors.append(
                "operational app matrix requires an authenticated app subject inventory"
            )
        if matrix is not None and not stage_errors:
            stage_errors.extend(
                _matrix_errors(
                    matrix,
                    fixture,
                    contract,
                    proposal,
                    ledger,
                    baseline_registry,
                    history_subjects,
                    oldest_supported_record,
                    app_subject_inventory,
                )
            )
        if deprecation is not None and not current_deprecation_errors:
            head_snapshot = history_subjects[-1][1] if history_subjects else None
            stage_errors.extend(
                _deprecation_subject_errors(
                    deprecation, baseline_registry, matrix, head_snapshot
                )
            )
        errors.extend(stage_errors)
        stage_ok["matrix"] = stage_ok["graduation"] and not stage_errors
    if rank >= 5:
        runtime, stage_errors = _optional_bound_json(resolved_evidence, contract["evidence"]["runtimeObservation"], RUNTIME_SCHEMA, "runtime observation")
        if runtime is not None and not stage_errors:
            stage_errors.extend(
                _runtime_errors(
                    runtime,
                    contract,
                    fixture,
                    evaluation,
                    policy,
                    ledger,
                    matrix,
                    contract["runtimeObservationAuthority"],
                    contract["evidence"]["runtimeObservation"],
                )
            )
        if not fixture and runtime is None:
            stage_errors.append("operational runtime verification requires an observation")
        errors.extend(stage_errors)
        stage_ok["runtime"] = stage_ok["matrix"] and not stage_errors
    if rank >= 6:
        if fixture:
            stage_errors = []
        elif stage_ok["runtime"]:
            stage_errors = _authority_errors(
                contract, resolved_evidence, policy, app_subject_inventory
            )
        else:
            stage_errors = ["operational closeout is blocked by incomplete predecessor stages"]
        errors.extend(stage_errors)
        stage_ok["roots"] = stage_ok["runtime"] and not stage_errors

    if rank >= 1 and resolved_evidence is not None:
        errors.extend(_evidence_member_errors(resolved_evidence, contract_path, contract, ledger))

    errors = sorted(set(errors))
    if errors:
        status = "partial" if any(stage_ok.values()) else "fail"
        state = "partial" if any(stage_ok.values()) else "blocked"
    elif fixture and rank >= 1:
        status, state = "pass", "fixture-verification-complete"
    else:
        states = (
            "implementation-complete", "history-authenticated", "baseline-proposal-reviewed",
            "baseline-proposal-reviewed", "app-matrix-verified", "runtime-compatibility-verified",
            "operational-1x-compatibility-complete",
        )
        state = states[rank]
        if rank in {2, 3} and (
            proposal is None
            or proposal["lifecycleState"] not in {"reviewed", "documented"}
            or proposal["decision"] != "approved"
        ):
            state = "history-authenticated"
        status = "pass"
    operational = state == "operational-1x-compatibility-complete"
    checks = []
    for index, stage in enumerate(STAGES):
        check_status = "pending" if index > rank else "pass" if stage_ok[stage] else "fail"
        if fixture and check_status == "pass" and stage != "preflight":
            check_status = "fixture-only"
        checks.append({"id": f"platform-api-1x.{stage}", "status": check_status})
    summary: dict[str, Any] = {
        "schemaVersion": 1,
        "kind": "platform-api-1.x-compatibility-summary",
        "executionId": contract["executionId"],
        "releaseId": contract["release"]["releaseId"],
        "buildVersion": contract["release"]["buildVersion"],
        "sourceCommit": contract["repository"]["sourceCommit"],
        "mode": mode,
        "status": status,
        "state": state,
        "fixtureOnly": contract["fixtureOnly"],
        "selfTest": contract["selfTest"],
        "operational": operational,
        "urlApiVersion": contract["urlApiVersion"],
        "contractVersion": contract["contractVersion"],
        "activeStableBaselines": contract["activeStableBaselines"],
        "policyDigest": policy_digest,
        "historyLedgerDigest": ledger.get("ledgerDigest") if ledger else None,
        "historyLedgerHeadDigest": ledger.get("headRecordDigest") if ledger else None,
        "baselineRegistryDigest": (
            _record_baseline_registry_digest(baseline_registry)
            if baseline_registry else None
        ),
        "baselineRegistryArtifactDigest": (
            contract["evidence"]["baselineRegistry"]["digest"]
            if contract["evidence"]["baselineRegistry"] is not None else None
        ),
        "baselineProposalDigest": proposal.get("proposalDigest") if proposal else None,
        "graduationRecordDigests": sorted(item["recordDigest"] for item in graduations),
        "deprecationLedgerDigest": deprecation.get("ledgerDigest") if deprecation else None,
        "appSubjectInventoryDigest": (
            app_subject_inventory.get("inventoryDigest")
            if app_subject_inventory else None
        ),
        "appMatrixDigest": matrix.get("matrixDigest") if matrix else None,
        "runtimeObservationDigest": runtime.get("observationDigest") if runtime else None,
        "authorityRoots": contract["authorityRoots"],
        "checks": checks,
        "blockers": errors[:128],
        "summaryDigest": ZERO_DIGEST,
    }
    summary["summaryDigest"] = _semantic_digest(summary, "summaryDigest")
    findings = validate_schema(summary, SUMMARY_SCHEMA)
    if findings:
        raise ValueError("generated Platform API 1.x summary failed its closed schema: " + "; ".join(findings[:8]))
    report = _report(summary)
    if scan_value([summary, report]):
        raise ValueError("generated Platform API 1.x outputs failed redaction validation")
    output = _output_directory(
        workspace, out_dir or Path("build/release-certification/stable-platform-api-1x") / mode
    )
    write_json(output / SUMMARY_FILE, summary)
    write_text(output / REPORT_FILE, report)
    write_json(output / REDACTION_FILE, {
        "schemaVersion": 1,
        "kind": "platform-api-1.x-redaction-report",
        "status": "pass",
        "findingCount": 0,
        "findings": [],
    })
    return 0 if status == "pass" else 1
