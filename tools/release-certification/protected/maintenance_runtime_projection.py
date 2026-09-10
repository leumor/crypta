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


def project(plan, events, checkpoint, products, *, policy_path=POLICY, now=None):
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


def validate(value):
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


def authenticate(coordinates, private_root, *, expected_plan_digest, expected_policy_digest, now=None):
    """Materialize original measured inputs in the protected producer, never in offline verify."""
    from cross_version_supervisor_authority import authenticate_report
    report, origin = authenticate_report(coordinates, private_root)
    if report.get("schemaVersion") != 2 or report.get("operation") != "finish":
        raise ProjectionError("maintenance-measurements-original-finish-v2-required")
    value = validate(report["maintenanceMeasurements"])
    if (value["planDigest"] != expected_plan_digest or report["planDigest"] != expected_plan_digest
            or value["policyByteDigest"] != expected_policy_digest
            or value["producer"] != report["producer"] or value["checkpointDigest"] != report["checkpoint"]["digest"]):
        raise ProjectionError("maintenance-measurements-original-selection-mismatch")
    policy_bytes = POLICY.read_bytes()
    if "sha256:" + hashlib.sha256(policy_bytes).hexdigest() != expected_policy_digest:
        raise ProjectionError("maintenance-measurements-current-policy-mismatch")
    now = now or dt.datetime.now(dt.timezone.utc)
    end = parse_timestamp(value["observedUntil"])
    maximum_age = json.loads(policy_bytes)["evidenceWindows"]["maximumAgeDays"]
    if (now.tzinfo is None or now.utcoffset() is None or end is None or end > now
            or now - end > dt.timedelta(days=maximum_age)):
        raise ProjectionError("maintenance-measurements-original-observation-expired")
    return AuthenticatedMeasurements(value, origin, _AUTHORITY)
