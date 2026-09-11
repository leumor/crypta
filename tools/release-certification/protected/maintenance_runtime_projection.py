"""Measured maintenance components from the original owned supervisor journal.

This is a prospective projection of executed components, not a maintenance acceptance receipt.
The existing runtime does not implement every required maintenance adapter. Those missing cases
remain explicit blockers even when an original protected producer authenticates the measurements.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import math
from pathlib import Path
import re

from cryptad_certification.cross_version_evidence import CASES, ROLES, digest, verify
from cryptad_certification.engines.stable_1_0_rc_core import parse_timestamp

POLICY = Path(__file__).resolve().parent.parent / "stable-1.0-maintenance-policy.json"
_AUTHORITY = object()
PREFIX = "stable-maintenance."
# Each row names the existing consumer and the precise remaining runtime adapters. This version
# deliberately admits no complete maintenance row; producer authentication cannot fill a gap.
ROWS = {
    "live-network-interoperability": (("network-chk", "network-ssk", "network-usk", "network-subscription",
                                      "persistent-request-restart", "partition-rejoin", "relay-health"),
                                     ("hyphanet-required-matrix-adapter-missing",)),
    "performance": (("app-budgets",), ("scheduler-pressure-adapter-missing", "reviewed-runtime-baseline-missing")),
    "catalog-app-compatibility": (("catalog-provenance", "app-lifecycle"),
                                 ("catalog-origin-channel-fallback-consent-rollback-cohort-incomplete",)),
    "content-profile-compatibility": (("profile-directions",),
                                      ("historical-and-independent-required-profile-directions-incomplete",)),
    "upgrade-rollback-migration-backup": (("daemon-upgrade", "unsafe-downgrade", "mail-restore", "migration-runtime"),
                                          ("mail-and-sharesite-required-recovery-cohort-incomplete",)),
    "platform-api-compatibility": (("stable-api-runtime",), ("complete-required-app-contract-matrix-missing",)),
    "sandbox": (("mail-origin",), ("complete-origin-process-authority-cohort-missing",)),
    "security": (("mail-origin", "mail-canary"), ("complete-security-response-runtime-cohort-missing",)),
    "support-redaction": (("mail-canary",), ("complete-export-and-failure-canary-cohort-missing",)),
}
COMMON_BLOCKERS = {
    "journal-required-coverage-or-integrity-incomplete", "owned-cleanup-not-observed",
    "terminal-checkpoint-not-complete", "original-production-products-required",
    "maintenance-observation-stale-or-future", "routine-full-window-not-observed",
    "required-node-count-not-observed", "required-operation-count-not-observed",
    "candidate-or-predecessor-portable-freeze-unbound", "journal-start-precedes-freeze-completion",
    "required-direction-not-observed",
}


class ProjectionError(ValueError):
    """Closed public failure without operational inputs."""


class AuthenticatedMeasurements:
    """In-process original producer result; serialized flags cannot construct authority."""
    def __init__(self, value, origin, authority=None):
        if authority is not _AUTHORITY:
            raise ProjectionError("maintenance-measurements-original-authority-required")
        self._canonical = json.dumps(value, sort_keys=True, separators=(",", ":"))
        self._origin = json.dumps(origin, sort_keys=True, separators=(",", ":"))

    def measurements(self):
        return json.loads(self._canonical)

    def original_coordinates(self):
        return json.loads(self._origin)


def _project_v1(plan, events, checkpoint, products, *, policy_path=POLICY, now=None):
    """Recompute measurements from the exact journal prefix; perform no network or node calls.

    ``products`` comes only from the root-owned activation in the protected caller. Direct calls
    remain local calculations. This function neither manufactures that authority nor accepts
    supplementary runtime verdicts as executed journal cases.
    """
    now = now or dt.datetime.now(dt.timezone.utc)
    if now.tzinfo is None or now.utcoffset() is None:
        raise ProjectionError("maintenance-measurements-clock-invalid")
    policy_bytes = policy_path.read_bytes()
    policy = json.loads(policy_bytes)
    windows = policy["evidenceWindows"]
    if any(PREFIX + key not in policy["requiredEvidenceIds"] for key in ROWS):
        raise ProjectionError("maintenance-measurements-policy-row-mismatch")
    observation = verify(plan, events, checkpoint, now=now)
    common = []
    if observation["findings"]:
        common.append("journal-required-coverage-or-integrity-incomplete")
    if observation["cleanup"] != "observed":
        common.append("owned-cleanup-not-observed")
    if checkpoint["status"] != "complete":
        common.append("terminal-checkpoint-not-complete")
    if plan["provenanceClass"] != "production-artifact-comparison":
        common.append("original-production-products-required")
    end = parse_timestamp(events[-1]["wallTime"]) if events else None
    start = parse_timestamp(events[0]["wallTime"]) if events else None
    if end is None or end > now or now - end > dt.timedelta(days=windows["maximumAgeDays"]):
        common.append("maintenance-observation-stale-or-future")
    if observation["observedEligibleSeconds"] < windows["minimumLiveNetworkDurationSeconds"]:
        common.append("routine-full-window-not-observed")
    # A sandbox denial, app lifecycle check or cleanup is not a network operation. Count
    # only the verified successful directional operations emitted by fixed network drivers.
    network_operations = sum(count for case, count in observation["caseSamples"].items()
                             if case.split("/", 1)[0] in {"network-chk", "network-ssk", "network-usk", "network-subscription"})
    network_roles = {role for case, count in observation["caseSamples"].items() if count
                     and case.split("/", 1)[0] in {"network-chk", "network-ssk", "network-usk", "network-subscription"}
                     for role in case.split("/")[1:]}
    if len(network_roles) < windows["minimumNodeCount"]:
        common.append("required-node-count-not-observed")
    if network_operations < windows["minimumOperationCount"]:
        common.append("required-operation-count-not-observed")
    bindings = []
    by_role = {row.get("role"): row for row in (products or [])}
    if len(by_role) != len(products or []):
        raise ProjectionError("maintenance-measurements-product-roster-duplicated")
    for node in plan["nodes"]:
        row = by_role.get(node["role"], {})
        exact = all(row.get(key) == node[key] for key in ("sourceCommit", "artifactDigest", "artifactSize", "packageTarget"))
        frozen = parse_timestamp(row.get("freezeCompletedAt"))
        bound = (exact and row.get("frozenPortableBinding") == "existing-maintenance-freeze-exact-product-v1"
                 and re.fullmatch(r"sha256:[0-9a-f]{64}", str(row.get("maintenanceFreezeDigest"))) is not None
                 and frozen is not None)
        if node["role"] in {"candidate-sender", "candidate-recipient", "previous"}:
            if not bound:
                common.append("candidate-or-predecessor-portable-freeze-unbound")
            elif start is None or start < frozen:
                common.append("journal-start-precedes-freeze-completion")
        bindings.append({"role": node["role"], "sourceCommit": node["sourceCommit"],
                         "artifactDigest": node["artifactDigest"],
                         "maintenanceFreezeDigest": row["maintenanceFreezeDigest"] if bound else None,
                         "freezeCompletedAt": row["freezeCompletedAt"] if bound else None,
                         "binding": "exact-maintenance-product" if bound else "not-established"})
    rows = []
    for name, (scenarios, missing_adapters) in sorted(ROWS.items()):
        cases = sorted("/".join(part for part in (scenario, role, peer) if part)
                       for scenario in scenarios for role, peer in CASES[scenario])
        counts = {case: observation["caseSamples"][case] for case in cases}
        missing = [case for case, count in counts.items() if not count]
        blockers = sorted(set(common) | set(missing_adapters) | ({"required-direction-not-observed"} if missing else set()))
        rows.append({"id": PREFIX + name, "status": "blocked", "caseSamples": counts,
                     "missingCases": missing, "blockers": blockers})
    return {"schemaVersion": 1, "kind": "maintenance-runtime-measurements",
            "planDigest": digest(plan), "policyByteDigest": "sha256:" + hashlib.sha256(policy_bytes).hexdigest(),
            "producer": dict(plan["producer"]), "checkpointDigest": digest(checkpoint),
            "observedUntil": events[-1]["wallTime"] if events else None,
            "observedEligibleSeconds": observation["observedEligibleSeconds"],
            "observedNetworkOperations": network_operations,
            "observedNetworkNodeCount": len(network_roles),
            "controllerEpochCount": len({event["epoch"] for event in events}),
            "products": bindings, "rows": rows, "maintenanceEligibility": "blocked"}


def _validate_v1(value):
    """Validate the versioned bounded projection before original-artifact public admission."""
    fields = {"schemaVersion", "kind", "planDigest", "policyByteDigest", "producer", "checkpointDigest",
              "observedUntil", "observedEligibleSeconds", "observedNetworkOperations", "observedNetworkNodeCount",
              "controllerEpochCount", "products", "rows", "maintenanceEligibility"}
    if (not isinstance(value, dict) or set(value) != fields or type(value["schemaVersion"]) is not int or value["schemaVersion"] != 1
            or value["kind"] != "maintenance-runtime-measurements" or value["maintenanceEligibility"] != "blocked"
            or not isinstance(value["rows"], list) or len(value["rows"]) != len(ROWS)):
        raise ProjectionError("maintenance-measurements-contract-invalid")
    for field in ("planDigest", "policyByteDigest", "checkpointDigest"):
        if re.fullmatch(r"sha256:[0-9a-f]{64}", str(value[field])) is None:
            raise ProjectionError("maintenance-measurements-digest-invalid")
    producer = value["producer"]
    if (not isinstance(producer, dict) or set(producer) != {"sourceCommit", "runnerDigest", "adapterDigest"}
            or re.fullmatch(r"[0-9a-f]{40}", str(producer["sourceCommit"])) is None
            or any(re.fullmatch(r"sha256:[0-9a-f]{64}", str(producer[field])) is None for field in ("runnerDigest", "adapterDigest"))
            or type(value["controllerEpochCount"]) is not int or not 0 <= value["controllerEpochCount"] <= 1000000
            or type(value["observedNetworkOperations"]) is not int or not 0 <= value["observedNetworkOperations"] <= 1000000
            or type(value["observedNetworkNodeCount"]) is not int or not 0 <= value["observedNetworkNodeCount"] <= 6
            or type(value["observedEligibleSeconds"]) not in {int, float}
            or not 0 <= value["observedEligibleSeconds"] <= 432000 or not math.isfinite(value["observedEligibleSeconds"])
            or (value["observedUntil"] is not None and parse_timestamp(value["observedUntil"]) is None)):
        raise ProjectionError("maintenance-measurements-producer-or-clock-invalid")
    products = value["products"]
    if not isinstance(products, list) or not 4 <= len(products) <= 6:
        raise ProjectionError("maintenance-measurements-products-invalid")
    roles = []
    for product in products:
        if (not isinstance(product, dict) or set(product) != {"role", "sourceCommit", "artifactDigest", "maintenanceFreezeDigest", "freezeCompletedAt", "binding"}
                or not isinstance(product["role"], str) or product["role"] not in ROLES or product["role"] in roles
                or re.fullmatch(r"[0-9a-f]{40}", str(product["sourceCommit"])) is None
                or re.fullmatch(r"sha256:[0-9a-f]{64}", str(product["artifactDigest"])) is None
                or not isinstance(product["binding"], str) or product["binding"] not in {"exact-maintenance-product", "not-established"}):
            raise ProjectionError("maintenance-measurements-product-invalid")
        roles.append(product["role"])
        if product["binding"] == "exact-maintenance-product":
            if (re.fullmatch(r"sha256:[0-9a-f]{64}", str(product["maintenanceFreezeDigest"])) is None
                    or parse_timestamp(product["freezeCompletedAt"]) is None):
                raise ProjectionError("maintenance-measurements-freeze-invalid")
        elif product["maintenanceFreezeDigest"] is not None or product["freezeCompletedAt"] is not None:
            raise ProjectionError("maintenance-measurements-unestablished-freeze-invalid")
    if (any(not isinstance(row, dict) or not isinstance(row.get("id"), str) for row in value["rows"])
            or {row["id"] for row in value["rows"]} != {PREFIX + name for name in ROWS}):
        raise ProjectionError("maintenance-measurements-row-set-invalid")
    for row in value["rows"]:
        scenarios, missing = ROWS[row["id"][len(PREFIX):]]
        cases = {"/".join(part for part in (scenario, role, peer) if part)
                 for scenario in scenarios for role, peer in CASES[scenario]}
        if (set(row) != {"id", "status", "caseSamples", "missingCases", "blockers"}
                or row["status"] != "blocked" or not isinstance(row["caseSamples"], dict) or set(row["caseSamples"]) != cases
                or any(type(count) is not int or not 0 <= count <= 1000000 for count in row["caseSamples"].values())
                or not isinstance(row["missingCases"], list)
                or any(not isinstance(case, str) for case in row["missingCases"])
                or row["missingCases"] != sorted(case for case, count in row["caseSamples"].items() if count == 0)
                or not isinstance(row["blockers"], list) or any(not isinstance(blocker, str) for blocker in row["blockers"])
                or row["blockers"] != sorted(set(row["blockers"]))
                or not set(missing) <= set(row["blockers"])
                or not set(row["blockers"]) <= COMMON_BLOCKERS | set(missing)):
            raise ProjectionError("maintenance-measurements-row-invalid")
    return value


BINDING_DIGESTS = ("metadataDigest", "contractSnapshotDigest", "contractSemanticDigest",
                   "baselineRegistryDigest", "shippedCohortDigest", "experimentCohortDigest")
SUBJECT_BLOCKERS = {"exact-runtime-product-subject-missing", "exact-runtime-api-subject-missing",
                    "exact-runtime-app-roster-missing", "runtime-subject-observation-after-start",
                    "original-production-products-required"}
# Missing scenarios, duration and cleanup are separate parent gates. Every other journal finding
# still prevents the narrow derivation from passing, including replay, gaps and clock changes.
COVERAGE_FINDINGS = {"required-scenarios-not-observed", "observed-duration-insufficient", "cleanup-not-observed"}
DERIVATION_BLOCKERS = {
    "journal-lineage-invalid", "journal-wall-clock-invalid", "continuation-lineage-invalid",
    "controller-epoch-changed", "event-role-outside-roster", "node-start-reuses-runtime-epoch",
    "runtime-epoch-mismatch", "operation-on-stopped-node", "observed-failure", "fault-operation-replayed",
    "fault-recovery-lineage-invalid", "peer-runtime-epoch-mismatch", "operation-replayed",
    "operation-outside-required-case", "clock-discontinuity", "operation-counter-regressed",
    "checkpoint-substitution-or-truncation", "controller-restarted-uninterrupted-soak-unproven",
    "run-incomplete", "node-observations-incomplete", "idle-only-run", "unexplained-observation-gap",
    "authorized-duration-exceeded", "fault-recovery-incomplete", "terminal-checkpoint-not-complete",
    "maintenance-observation-stale-or-future",
}


def _digest_valid(value):
    return isinstance(value, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None


def project(plan, events, checkpoint, products, *, policy_path=POLICY, now=None):
    """Project prospective exact subjects separately from incomplete maintenance scenarios.

    Historical input without a runtime binding retains byte-for-byte v1 semantics. A v2 result
    cannot be constructed by upgrading that report: the original journal and exact product rows
    must be presented again to this producer, then authenticated through the original supervisor.
    """
    now = now or dt.datetime.now(dt.timezone.utc)
    result = _project_v1(plan, events, checkpoint, products, policy_path=policy_path, now=now)
    if not any("runtimeBinding" in row for row in (products or [])):
        return result
    from cryptad_certification.redaction import scan_value
    if scan_value(products):
        raise ProjectionError("maintenance-measurements-private-product-input")
    checked = verify(plan, events, checkpoint, now=now)
    start = parse_timestamp(events[0]["wallTime"]) if events else None
    by_role = {row["role"]: row for row in products}
    if set(by_role) != {node["role"] for node in plan["nodes"]}:
        raise ProjectionError("maintenance-measurements-product-roster-mismatch")
    subjects = []
    all_blockers = set()
    for node in plan["nodes"]:
        row = by_role.get(node["role"], {})
        binding = row.get("runtimeBinding", {})
        if not isinstance(binding, dict):
            binding = {}
        blockers = set()
        if plan["provenanceClass"] != "production-artifact-comparison":
            blockers.add("original-production-products-required")
        if not all(row.get(key) == node[key] for key in ("sourceCommit", "artifactDigest", "artifactSize", "packageTarget")):
            blockers.add("exact-runtime-product-subject-missing")
        if (not isinstance(binding, dict) or set(binding) != set(BINDING_DIGESTS) | {"provenance"}
                or not all(_digest_valid(binding.get(key)) for key in BINDING_DIGESTS)
                or binding.get("provenance") not in {"frozen-with-original-release", "observed-from-original-package"}
                or row.get("contractVersion") != node["contractVersion"]):
            blockers.add("exact-runtime-api-subject-missing")
        matrix = row.get("appMatrix", [])
        if (not isinstance(matrix, list) or any(not isinstance(app, dict) for app in matrix)
                or sorted(app.get("bundleDigest", "") for app in matrix) != sorted(node["appDigests"])
                or any(app.get("contractVerifier") != "executed" or app.get("nativeAdmission") != "accepted"
                       or app.get("contractSnapshotDigest") != binding.get("contractSnapshotDigest") for app in matrix)):
            blockers.add("exact-runtime-app-roster-missing")
        cutoff = parse_timestamp(row.get("freezeCompletedAt") if binding.get("provenance") == "frozen-with-original-release"
                                 else row.get("runtimeObservationCompletedAt"))
        if cutoff is None or start is None or cutoff > start:
            blockers.add("runtime-subject-observation-after-start")
        subjects.append({"role": node["role"], "bindingDigest": digest(binding),
                         "appMatrixDigest": digest(matrix), "status": "pass" if not blockers else "blocked",
                         "blockers": sorted(blockers)})
        all_blockers.update(blockers)
    derivation = set(checked["findings"]) - COVERAGE_FINDINGS
    if checkpoint["status"] != "complete":
        derivation.add("terminal-checkpoint-not-complete")
    if any("maintenance-observation-stale-or-future" in row["blockers"] for row in result["rows"]):
        derivation.add("maintenance-observation-stale-or-future")
    result.update(schemaVersion=2, admittedProductsDigest=digest(products),
                  evaluationCutoff=now.isoformat(),
                  subjectAdmission={"status": "pass" if not all_blockers else "blocked",
                                    "subjects": subjects, "blockers": sorted(all_blockers)},
                  measurementDerivation={"status": "pass" if not derivation else "blocked",
                                         "journalDigest": digest(events),
                                         "caseSamplesDigest": digest(checked["caseSamples"]),
                                         "participantEpochsDigest": digest([{key: event.get(key) for key in
                                             ("epoch", "role", "nodeEpoch", "peerRole", "peerNodeEpoch")} for event in events]),
                                         "blockers": sorted(derivation)})
    return result


def validate(value):
    """Validate historical diagnostics or the closed prospective narrow-component contract."""
    if not isinstance(value, dict) or value.get("schemaVersion") != 2:
        return _validate_v1(value)
    extra = {"admittedProductsDigest", "evaluationCutoff", "subjectAdmission", "measurementDerivation"}
    historical = {key: item for key, item in value.items() if key not in extra}
    historical["schemaVersion"] = 1
    _validate_v1(historical)
    if not extra <= set(value) or not _digest_valid(value["admittedProductsDigest"]) or parse_timestamp(value["evaluationCutoff"]) is None:
        raise ProjectionError("maintenance-measurements-v2-subject-contract-invalid")
    observed = parse_timestamp(value["observedUntil"])
    if observed is not None and observed > parse_timestamp(value["evaluationCutoff"]):
        raise ProjectionError("maintenance-measurements-v2-evaluation-precedes-observation")
    admission, derivation = value["subjectAdmission"], value["measurementDerivation"]
    if (not isinstance(admission, dict) or set(admission) != {"status", "subjects", "blockers"}
            or not isinstance(admission["subjects"], list)
            or len(admission["subjects"]) != len(value["products"])):
        raise ProjectionError("maintenance-measurements-v2-subject-contract-invalid")
    roles, blockers = [], set()
    for subject in admission["subjects"]:
        if (not isinstance(subject, dict) or set(subject) != {"role", "bindingDigest", "appMatrixDigest", "status", "blockers"}
                or not isinstance(subject["role"], str) or subject["role"] not in ROLES or subject["role"] in roles
                or not all(_digest_valid(subject[key]) for key in ("bindingDigest", "appMatrixDigest"))
                or not isinstance(subject["blockers"], list) or any(not isinstance(code, str) for code in subject["blockers"])
                or subject["blockers"] != sorted(set(subject["blockers"]))
                or not set(subject["blockers"]) <= SUBJECT_BLOCKERS
                or subject["status"] != ("blocked" if subject["blockers"] else "pass")):
            raise ProjectionError("maintenance-measurements-v2-subject-invalid")
        roles.append(subject["role"])
        blockers.update(subject["blockers"])
    if (set(roles) != {row["role"] for row in value["products"]} or admission["blockers"] != sorted(blockers)
            or admission["status"] != ("blocked" if blockers else "pass")):
        raise ProjectionError("maintenance-measurements-v2-subject-roster-invalid")
    if (not isinstance(derivation, dict) or set(derivation) != {"status", "journalDigest", "caseSamplesDigest", "participantEpochsDigest", "blockers"}
            or not all(_digest_valid(derivation[key]) for key in ("journalDigest", "caseSamplesDigest", "participantEpochsDigest"))
            or not isinstance(derivation["blockers"], list)
            or any(not isinstance(code, str) or code not in DERIVATION_BLOCKERS for code in derivation["blockers"])
            or derivation["blockers"] != sorted(set(derivation["blockers"]))
            or derivation["status"] != ("blocked" if derivation["blockers"] else "pass")):
        raise ProjectionError("maintenance-measurements-v2-derivation-invalid")
    return value


def authenticate(coordinates, private_root, *, expected_plan_digest, expected_policy_digest, now=None):
    """Materialize original measured inputs in the protected producer, never in offline verify."""
    from cross_version_supervisor_authority import authenticate_report
    report, origin = authenticate_report(coordinates, private_root)
    if report.get("schemaVersion") not in {2, 3} or report.get("operation") != "finish":
        raise ProjectionError("maintenance-measurements-original-finish-v2-required")
    value = validate(report["maintenanceMeasurements"])
    if (value["planDigest"] != expected_plan_digest or report["planDigest"] != expected_plan_digest
            or value["policyByteDigest"] != expected_policy_digest
            or value["producer"] != report["producer"] or value["checkpointDigest"] != report["checkpoint"]["digest"]
            or value["schemaVersion"] != report["schemaVersion"] - 1
            or (value["schemaVersion"] == 2 and report["admittedProductsDigest"] != value["admittedProductsDigest"])):
        raise ProjectionError("maintenance-measurements-original-selection-mismatch")
    policy_bytes = POLICY.read_bytes()
    if "sha256:" + hashlib.sha256(policy_bytes).hexdigest() != expected_policy_digest:
        raise ProjectionError("maintenance-measurements-current-policy-mismatch")
    now = now or dt.datetime.now(dt.timezone.utc)
    end = parse_timestamp(value["observedUntil"])
    maximum_age = json.loads(policy_bytes)["evidenceWindows"]["maximumAgeDays"]
    if (now.tzinfo is None or now.utcoffset() is None or end is None or end > now
            or now - end > dt.timedelta(days=maximum_age)
            or (value["schemaVersion"] == 2 and parse_timestamp(value["evaluationCutoff"]) > now)):
        raise ProjectionError("maintenance-measurements-original-observation-expired")
    return AuthenticatedMeasurements(value, origin, _AUTHORITY)
