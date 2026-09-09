"""Closed measured-soak evidence; local integrity never implies protected authority.

Operational paths, payloads, tokens and process identifiers belong to the private supervisor.
This module accepts only bounded counters and fixed scenario identifiers for public export.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat as stat_module
import time
import uuid

KIND = "cryptad-cross-version-soak-plan"
ROLES = frozenset({"candidate-sender", "candidate-recipient", "previous", "relay-no-apps", "oldest", "hyphanet"})
MANDATORY_ROLES = ROLES - {"oldest", "hyphanet"}
SCENARIOS = frozenset({"network-chk", "network-ssk", "network-usk", "network-subscription", "persistent-request-restart", "partition-rejoin", "catalog-provenance", "app-lifecycle", "app-budgets", "relay-health", "daemon-upgrade", "unsafe-downgrade", "mail-delivery", "mail-retry", "mail-origin", "mail-canary", "mail-restore", "migration-runtime", "profile-directions", "stable-api-runtime"})
# The versioned policy owns required directions. Callers cannot omit a direction by
# shrinking a manifest matrix, or satisfy a recipient check with a sender observation.
NETWORK_DIRECTIONS = (("candidate-sender", "previous"), ("previous", "candidate-recipient"))
CASES = {scenario: (("candidate-sender", ""),) for scenario in SCENARIOS}
for _scenario in ("network-chk", "network-ssk", "network-usk", "network-subscription", "profile-directions"):
    CASES[_scenario] = NETWORK_DIRECTIONS
CASES.update({
    "partition-rejoin": (("candidate-recipient", ""),),
    "relay-health": (("relay-no-apps", ""),),
    "daemon-upgrade": (("previous", ""),),
    "unsafe-downgrade": (("previous", ""),),
    "mail-delivery": (("candidate-sender", "candidate-recipient"), ("candidate-recipient", "candidate-sender")),
    "mail-origin": (("candidate-recipient", ""),),
    "mail-canary": (("candidate-sender", ""), ("candidate-recipient", "")),
    "mail-restore": (("candidate-recipient", ""),),
    "stable-api-runtime": (("candidate-sender", ""), ("previous", "")),
})

PROFILES = {"offline-self-test", "bounded-live", "protected-long-live"}
KINDS = {"continuation", "start", "node-start", "probe", "sample", "operation", "fault", "recovery", "node-stop", "cleanup", "finish"}
OUTCOMES = {"pass", "fail", "partial", "unsupported", "not-observed", "cleanup-incomplete"}
ZERO = "sha256:" + "0" * 64
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
IDENTIFIER = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._-]{0,95}\Z")
COUNTERS = {"operations", "bytes", "memoryBytes", "threads", "fileDescriptors", "queueDepth", "subscriptions", "failures"}


class EvidenceError(ValueError):
    """An evidence contract or owned-resource invariant was violated."""


def digest(value):
    return "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def _closed(value, fields, label):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise EvidenceError(label + "-fields-invalid")


def _number(value, minimum, maximum, label):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not minimum <= value <= maximum:
        raise EvidenceError(label + "-invalid")


def validate_plan(plan):
    """Validate public identities and workload policy without admitting executable bytes."""
    _closed(plan, {"schemaVersion", "kind", "experimentId", "profile", "topologyClass", "provenanceClass", "requestedSeconds", "probeIntervalSeconds", "policy", "requiredScenarios", "producer", "nodes"} | ({key for key in ("cohorts", "workloadInputs") if key in plan} if isinstance(plan, dict) else set()), "plan")
    if type(plan["schemaVersion"]) is not int or plan["schemaVersion"] != 1 or plan["kind"] != KIND or not isinstance(plan["profile"], str) or plan["profile"] not in PROFILES:
        raise EvidenceError("plan-version-or-profile-invalid")
    if not isinstance(plan["experimentId"], str) or not IDENTIFIER.fullmatch(plan["experimentId"]) or plan["topologyClass"] != "single-host-independent-processes":
        raise EvidenceError("experiment-or-topology-invalid")
    if not isinstance(plan["provenanceClass"], str) or plan["provenanceClass"] not in {"source-build-comparison", "production-artifact-comparison"}:
        raise EvidenceError("provenance-class-invalid")
    _number(plan["requestedSeconds"], 1, 5 * 86400, "requested-duration")
    _number(plan["probeIntervalSeconds"], .01, 300, "probe-interval")
    policy = plan["policy"]
    _closed(policy, {"id", "minimumObservedSeconds", "maxGapSeconds", "maxEvents"}, "policy")
    if policy["id"] != "cross-version-observed-v1":
        raise EvidenceError("policy-id-invalid")
    _number(policy["minimumObservedSeconds"], 0, 5 * 86400, "minimum-duration")
    _number(policy["maxGapSeconds"], plan["probeIntervalSeconds"], 600, "maximum-gap")
    _number(policy["maxEvents"], 10, 1000000, "event-budget")
    if type(policy["maxEvents"]) is not int or policy["minimumObservedSeconds"] > plan["requestedSeconds"]:
        raise EvidenceError("policy-budget-invalid")
    if plan["profile"] == "protected-long-live" and policy["minimumObservedSeconds"] < 72 * 3600:
        raise EvidenceError("protected-policy-duration-too-short")
    scenarios = plan["requiredScenarios"]
    if not isinstance(scenarios, list) or any(not isinstance(s, str) for s in scenarios) or len(scenarios) != len(set(scenarios)) or set(scenarios) != SCENARIOS:
        raise EvidenceError("required-scenario-set-invalid")
    producer = plan["producer"]
    _closed(producer, {"sourceCommit", "runnerDigest", "adapterDigest"}, "producer")
    if not COMMIT.fullmatch(str(producer["sourceCommit"])) or any(not DIGEST.fullmatch(str(producer[k])) for k in ("runnerDigest", "adapterDigest")):
        raise EvidenceError("producer-identity-invalid")
    nodes = plan["nodes"]
    if not isinstance(nodes, list) or not 4 <= len(nodes) <= 6:
        raise EvidenceError("node-count-invalid")
    workload = plan.get("workloadInputs", {})
    if (not isinstance(workload, dict) or not set(workload) <= {"budget", "catalog"}
            or any(not DIGEST.fullmatch(str(value)) for value in workload.values())):
        raise EvidenceError("workload-input-binding-invalid")
    cohorts = plan.get("cohorts", [])
    if not isinstance(cohorts, list) or len(cohorts) > 1:
        raise EvidenceError("recovery-cohort-roster-invalid")
    for cohort in cohorts:
        _closed(cohort, {"id", "sourceRole", "targetRole", "configDigest"}, "cohort")
        if (cohort["id"] != "previous-to-candidate" or cohort["sourceRole"] != "previous"
                or cohort["targetRole"] != "candidate-sender"
                or not DIGEST.fullmatch(str(cohort["configDigest"]))):
            raise EvidenceError("recovery-cohort-binding-invalid")
    roles = []
    for node in nodes:
        _closed(node, {"role", "product", "sourceCommit", "artifactDigest", "artifactSize", "packageTarget", "runtimeDigest", "contractVersion", "configDigest", "appDigests"}, "node")
        roles.append(node["role"])
        if not isinstance(node["role"], str) or not isinstance(node["product"], str) or node["role"] not in ROLES or node["product"] not in {"cryptad", "hyphanet"}:
            raise EvidenceError("node-role-product-invalid")
        if (node["role"] == "hyphanet") != (node["product"] == "hyphanet"):
            raise EvidenceError("node-product-role-mismatch")
        if not COMMIT.fullmatch(str(node["sourceCommit"])) or not IDENTIFIER.fullmatch(str(node["packageTarget"])):
            raise EvidenceError("node-source-target-invalid")
        for key in ("artifactDigest", "runtimeDigest", "configDigest"):
            if not DIGEST.fullmatch(str(node[key])):
                raise EvidenceError("node-digest-invalid")
        _number(node["artifactSize"], 1, 4 * 1024 ** 3, "artifact-size")
        _number(node["contractVersion"], 0, 10000, "contract-version")
        apps = node["appDigests"]
        if not isinstance(apps, list) or any(not isinstance(a, str) for a in apps) or len(apps) > 32 or len(apps) != len(set(apps)) or any(not DIGEST.fullmatch(str(x)) for x in apps):
            raise EvidenceError("app-digests-invalid")
        if node["role"] in {"relay-no-apps", "hyphanet"} and apps:
            raise EvidenceError("app-free-role-has-apps")
    if len(roles) != len(set(roles)) or not MANDATORY_ROLES <= set(roles):
        raise EvidenceError("node-roster-invalid")
    by_role = {n["role"]: n for n in nodes}
    sender, recipient, previous = (by_role[k] for k in ("candidate-sender", "candidate-recipient", "previous"))
    if sender["artifactDigest"] != recipient["artifactDigest"] or sender["sourceCommit"] != recipient["sourceCommit"]:
        raise EvidenceError("candidate-artifacts-differ")
    if previous["artifactDigest"] == sender["artifactDigest"] or previous["sourceCommit"] == sender["sourceCommit"]:
        raise EvidenceError("previous-relabels-current")
    if any(n["contractVersion"] < 25 or not n["appDigests"] for n in (sender, recipient)):
        raise EvidenceError("mail-endpoint-incompatible")
    if len({n["configDigest"] for n in nodes}) != len(nodes):
        raise EvidenceError("node-config-alias")
    return json.loads(json.dumps(plan))


def _atomic(path, value):
    temporary = path.with_name(path.name + ".new")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(value, stream, sort_keys=True, separators=(",", ":"), allow_nan=False)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def boot_identity():
    """Read the kernel boot identity; never expose it in public summaries."""
    try:
        value = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    except OSError as exc:
        raise EvidenceError("boot-identity-unavailable") from exc
    if not re.fullmatch(r"[0-9a-f-]{36}", value):
        raise EvidenceError("boot-identity-invalid")
    return value


def _private_root(root):
    for parent in (root, *root.parents):
        if parent.is_symlink():
            raise EvidenceError("journal-root-symlink")
    stat = root.stat()
    if stat.st_uid != os.getuid() or stat.st_mode & 0o077:
        raise EvidenceError("journal-root-not-private-or-owned")
    return stat


def _unique_json_members(items):
    result = {}
    for key, value in items:
        if key in result:
            raise EvidenceError("journal-duplicate-json-member")
        result[key] = value
    return result


def _private_json(path, maximum=1024 * 1024):
    stat = path.lstat()
    if path.is_symlink() or not path.is_file() or stat.st_uid != os.getuid() or stat.st_mode & 0o077 or stat.st_size > maximum:
        raise EvidenceError("private-input-ownership-or-size-invalid")
    return json.loads(path.read_text(), object_pairs_hook=_unique_json_members)


class Journal:
    """Exclusive private journal with exact, explicit same-owner bounded continuation.

    Local OS ownership authenticates only access to the disposable journal, never a
    protected producer. A resumed controller starts a new measured epoch; downtime and
    coverage from unrelated epochs cannot be added into an uninterrupted soak.
    """
    def __init__(self, root, plan, continuation=None):
        try:
            import fcntl
        except ImportError as exc:
            raise EvidenceError("posix-owned-journal-unavailable") from exc
        self.plan = validate_plan(plan)
        self.root = Path(root).absolute()
        if any(parent.is_symlink() for parent in (self.root, *self.root.parents)):
            raise EvidenceError("journal-root-symlink")
        self.root.mkdir(mode=0o700, parents=False, exist_ok=True)
        stat = _private_root(self.root)
        self._lock = os.open(self.root / "lease", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        self.events = []
        self.epoch = uuid.uuid4().hex
        self.failed = False
        self.finished = False
        self.node_epochs = {}
        self.resumed = continuation is not None
        try:
            lock_stat = os.fstat(self._lock)
            if lock_stat.st_uid != os.getuid() or lock_stat.st_mode & 0o077 or not stat_module.S_ISREG(lock_stat.st_mode) or lock_stat.st_nlink != 1:
                raise EvidenceError("lease-owner-invalid")
            fcntl.flock(self._lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            owner = {"ownerUid": os.getuid(), "bootId": boot_identity(), "planDigest": digest(self.plan),
                     "rootDevice": stat.st_dev, "rootInode": stat.st_ino}
            existing = any((self.root / n).exists() for n in ("journal.jsonl", "checkpoint.json", "journal-owner.json"))
            if existing:
                self._resume(continuation, owner)
                mode = os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW
            else:
                if continuation is not None:
                    raise EvidenceError("continuation-journal-missing")
                _atomic(self.root / "journal-owner.json", owner)
                mode = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
            self._stream = os.fdopen(os.open(self.root / "journal.jsonl", mode, 0o600), "a")
            if self.resumed:
                self.append("continuation", prior_checkpoint=self._prior_checkpoint)
        except BaseException:
            if hasattr(self, "_stream"):
                self._stream.close()
            os.close(self._lock)
            raise

    def _resume(self, continuation, owner):
        if continuation is None:
            raise EvidenceError("authenticated-continuation-required")
        if self.plan["profile"] != "bounded-live":
            raise EvidenceError("protected-or-fixture-continuation-not-admitted")
        _closed(continuation, {"experimentId", "planDigest", "checkpointDigest", "root", "ownerUid", "bootId"}, "continuation")
        if (continuation["experimentId"] != self.plan["experimentId"]
                or continuation["planDigest"] != digest(self.plan)
                or continuation["root"] != str(self.root)
                or continuation["ownerUid"] != os.getuid()
                or continuation["bootId"] != boot_identity()):
            raise EvidenceError("continuation-authorization-mismatch")
        if _private_json(self.root / "journal-owner.json") != owner:
            raise EvidenceError("continuation-root-owner-boot-substituted")
        checkpoint = _private_json(self.root / "checkpoint.json")
        if digest(checkpoint) != continuation["checkpointDigest"] or checkpoint.get("status") == "complete":
            raise EvidenceError("continuation-checkpoint-substituted-or-complete")
        path = self.root / "journal.jsonl"
        stat = path.lstat()
        if path.is_symlink() or not path.is_file() or stat.st_uid != os.getuid() or stat.st_mode & 0o077 or stat.st_size > self.plan["policy"]["maxEvents"] * 4096:
            raise EvidenceError("continuation-journal-unsafe")
        with path.open() as stream:
            while True:
                line = stream.readline(4097)
                if not line:
                    break
                if len(line) > 4096 or not line.endswith("\n"):
                    raise EvidenceError("continuation-journal-truncated")
                self.events.append(json.loads(line, object_pairs_hook=_unique_json_members))
                if len(self.events) >= self.plan["policy"]["maxEvents"]:
                    raise EvidenceError("continuation-journal-budget-exhausted")
        result = verify(self.plan, self.events, checkpoint)
        structural = {"journal-lineage-invalid", "journal-wall-clock-invalid", "controller-epoch-changed", "clock-discontinuity", "checkpoint-substitution-or-truncation", "continuation-lineage-invalid", "runtime-epoch-mismatch", "operation-on-stopped-node", "operation-replayed", "node-start-reuses-runtime-epoch", "peer-runtime-epoch-mismatch"}
        if structural.intersection(result["findings"]):
            raise EvidenceError("continuation-journal-lineage-invalid")
        self.failed = any(e["outcome"] in {"fail", "cleanup-incomplete"} for e in self.events)
        self._prior_checkpoint = checkpoint
        self.node_epochs = {(e.get("cohort", ""), e["role"]): e["nodeEpoch"] for e in self.events if e["kind"] == "node-start"}

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        try:
            if not self.finished:
                self.checkpoint("partial")
        finally:
            try:
                self._stream.close()
            finally:
                os.close(self._lock)

    def append(self, kind, role="", scenario="", operation="", outcome="pass", counters=None, prior_checkpoint=None, peer_role="", node_epoch=None, cohort=""):
        if self.finished or len(self.events) >= self.plan["policy"]["maxEvents"]:
            raise EvidenceError("journal-closed-or-budget-exhausted")
        scope = (cohort, role)
        if kind == "node-start" and role:
            if node_epoch is None and self.plan["profile"] != "offline-self-test":
                raise EvidenceError("observed-runtime-epoch-required")
            if node_epoch is not None and not re.fullmatch("[0-9a-f]{32}", str(node_epoch)):
                raise EvidenceError("observed-runtime-epoch-invalid")
            self.node_epochs[scope] = node_epoch or uuid.uuid4().hex
        elif node_epoch is not None and node_epoch != self.node_epochs.get(scope):
            raise EvidenceError("observed-runtime-epoch-substituted")
        event = {"sequence": len(self.events) + 1, "previousDigest": digest(self.events[-1]) if self.events else ZERO,
                 "planDigest": digest(self.plan), "epoch": self.epoch, "wallTime": dt.datetime.now(dt.timezone.utc).isoformat(),
                 "monotonicNs": time.monotonic_ns(), "kind": kind, "role": role, "scenario": scenario,
                 "operation": operation, "outcome": outcome, "counters": counters or {},
                 "peerRole": peer_role, "nodeEpoch": self.node_epochs.get(scope, "") if role else ""}
        if peer_role:
            event["peerNodeEpoch"] = self.node_epochs.get(("", peer_role), "")
        if cohort:
            event["cohort"] = cohort
        if kind == "continuation":
            event["priorCheckpoint"] = prior_checkpoint
        _validate_event(event, self.plan)
        self._stream.write(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n")
        self._stream.flush()
        os.fsync(self._stream.fileno())
        self.events.append(event)
        self.failed |= outcome in {"fail", "cleanup-incomplete"}
        return event

    def checkpoint(self, status="partial"):
        if status not in {"partial", "complete", "failed"}:
            raise EvidenceError("checkpoint-status-invalid")
        if self.failed:
            status = "failed"
        checkpoint = {"schemaVersion": 1, "planDigest": digest(self.plan), "sequence": len(self.events),
                      "tailDigest": digest(self.events[-1]) if self.events else ZERO, "epoch": self.epoch, "status": status}
        _atomic(self.root / "checkpoint.json", checkpoint)
        self.finished = status in {"complete", "failed"}
        return checkpoint


def _validate_event(event, plan):
    fields = {"sequence", "previousDigest", "planDigest", "epoch", "wallTime", "monotonicNs", "kind", "role", "scenario", "operation", "outcome", "counters", "nodeEpoch", "peerRole"}
    if isinstance(event, dict) and event.get("kind") == "continuation":
        fields.add("priorCheckpoint")
    if isinstance(event, dict) and "peerNodeEpoch" in event:
        fields.add("peerNodeEpoch")
        if not event.get("peerRole") or not re.fullmatch("[0-9a-f]{32}", str(event["peerNodeEpoch"])):
            raise EvidenceError("peer-node-epoch-invalid")
    if isinstance(event, dict) and "cohort" in event:
        fields.add("cohort")
        selected = {c["id"]: c for c in plan.get("cohorts", [])}
        cohort = event["cohort"]
        if (not isinstance(cohort, str) or cohort not in selected
                or event.get("kind") not in {"node-start", "node-stop", "operation", "cleanup"}
                or event.get("role") not in {selected[cohort]["sourceRole"], selected[cohort]["targetRole"]}
                or event.get("peerRole")
                or event.get("scenario") not in {"", "daemon-upgrade", "unsafe-downgrade"}):
            raise EvidenceError("event-cohort-binding-invalid")
    _closed(event, fields, "event")
    if any(not isinstance(event[k], str) for k in ("kind", "outcome", "role", "scenario", "peerRole", "operation")):
        raise EvidenceError("event-enum-type-invalid")
    if event["kind"] not in KINDS or event["outcome"] not in OUTCOMES or event["role"] not in ROLES | {""} or event["scenario"] not in SCENARIOS | {""}:
        raise EvidenceError("event-enum-invalid")
    if event["peerRole"] not in ROLES | {""} or (event["peerRole"] and event["peerRole"] == event["role"]):
        raise EvidenceError("peer-role-invalid")
    if event["role"]:
        if not re.fullmatch("[0-9a-f]{32}", str(event["nodeEpoch"])):
            raise EvidenceError("node-epoch-missing")
    elif event["nodeEpoch"]:
        raise EvidenceError("node-epoch-without-role")
    if event["operation"] and not IDENTIFIER.fullmatch(str(event["operation"])):
        raise EvidenceError("operation-id-invalid")
    if not isinstance(event["epoch"], str) or not re.fullmatch("[0-9a-f]{32}", event["epoch"]):
        raise EvidenceError("epoch-invalid")
    if type(event["sequence"]) is not int or type(event["monotonicNs"]) is not int or event["monotonicNs"] < 0:
        raise EvidenceError("event-clock-sequence-invalid")
    if not isinstance(event["counters"], dict) or not set(event["counters"]) <= COUNTERS:
        raise EvidenceError("event-counters-invalid")
    for value in event["counters"].values():
        if type(value) is not int or not 0 <= value <= 2 ** 53:
            raise EvidenceError("event-counter-invalid")
    if event["kind"] == "sample":
        if (not event["role"] or event["scenario"] not in {"app-lifecycle", "app-budgets"}
                or event["peerRole"] or event["operation"]):
            raise EvidenceError("periodic-sample-binding-invalid")
        if event["scenario"] == "app-budgets" and event["outcome"] == "pass":
            if (not {"memoryBytes", "threads", "fileDescriptors"} <= set(event["counters"])
                    or any(event["counters"].get(k, 0) < 1 for k in ("memoryBytes", "threads", "fileDescriptors"))):
                raise EvidenceError("resource-sample-incomplete")
        if event["scenario"] == "app-lifecycle" and event["outcome"] == "pass":
            selected = next((n for n in plan["nodes"] if n["role"] == event["role"]), None)
            if selected is None or not selected["appDigests"] or event["counters"] != {"operations": len(selected["appDigests"])}:
                raise EvidenceError("lifecycle-sample-app-cohort-incomplete")
    if event["kind"] == "operation" and (not event["scenario"] or not event["operation"] or not event["role"]):
        raise EvidenceError("operation-binding-missing")


def verify(plan, events, checkpoint, now=None):
    """Pure coverage verification; no local receipt is authenticated operational evidence."""
    plan = validate_plan(plan)
    errors = set()
    _closed(checkpoint, {"schemaVersion", "planDigest", "sequence", "tailDigest", "epoch", "status"}, "checkpoint")
    if (type(checkpoint["schemaVersion"]) is not int or type(checkpoint["sequence"]) is not int
            or checkpoint["sequence"] < 0 or not isinstance(checkpoint["status"], str)
            or checkpoint["status"] not in {"partial", "complete", "failed"}):
        raise EvidenceError("checkpoint-field-types-invalid")
    if not isinstance(events, list) or len(events) > plan["policy"]["maxEvents"]:
        raise EvidenceError("journal-budget-invalid")
    current = now or dt.datetime.now(dt.timezone.utc)
    if not isinstance(current, dt.datetime) or current.tzinfo is None or current.utcoffset() is None:
        raise EvidenceError("evaluation-clock-invalid")
    previous = None
    elapsed = 0.0
    gaps = 0.0
    gap_intervals = {}
    wall_start = None
    operation_ids = set()
    open_faults = {}
    fault_intervals = {}
    fault_since_probe = False
    samples = {s: 0 for s in sorted(SCENARIOS)}
    case_samples = {(s, role, peer): 0 for s, cases in CASES.items() for role, peer in cases}
    runtime_epochs = {}
    runtime_epoch_controllers = {}
    roles = {n["role"] for n in plan["nodes"]}
    active_roles = set()
    owned_scopes = set()
    periodic_samples = set()
    expected_samples = {(n["role"], "app-budgets") for n in plan["nodes"]}
    expected_samples |= {(n["role"], "app-lifecycle") for n in plan["nodes"] if n["appDigests"]}
    cohort_samples = {c["id"]: 0 for c in plan.get("cohorts", [])}
    observed_roles = set()
    epoch = None
    epoch_coverages = []
    controller_restarts = 0
    cleanup = False
    last_probe = None
    operations_since_probe = 0
    for index, event in enumerate(events):
        _validate_event(event, plan)
        if event["sequence"] != index + 1 or event["previousDigest"] != (digest(previous) if previous else ZERO) or event["planDigest"] != digest(plan):
            errors.add("journal-lineage-invalid")
        try:
            stamp = dt.datetime.fromisoformat(event["wallTime"])
            if stamp.tzinfo is None or stamp.utcoffset() is None:
                raise ValueError("naive timestamp")
            if stamp > current:
                errors.add("journal-wall-clock-invalid")
        except (TypeError, ValueError, OverflowError):
            errors.add("journal-wall-clock-invalid")
            stamp = current

        if epoch is None:
            epoch, wall_start = event["epoch"], stamp
        if event["kind"] == "continuation":
            prior = event["priorCheckpoint"]
            expected = {"schemaVersion": 1, "planDigest": digest(plan), "sequence": index,
                        "tailDigest": digest(previous) if previous else ZERO, "epoch": epoch,
                        "status": prior.get("status") if isinstance(prior, dict) else None}
            if prior != expected or not isinstance(expected["status"], str) or expected["status"] not in {"partial", "failed"} or event["epoch"] == epoch or plan["profile"] != "bounded-live":
                errors.add("continuation-lineage-invalid")
            epoch_coverages.append(elapsed)
            elapsed = 0
            last_probe = None
            operations_since_probe = 0
            epoch = event["epoch"]
            controller_restarts += 1
            active_roles.clear()
            periodic_samples.clear()
        elif event["epoch"] != epoch:
            errors.add("controller-epoch-changed")
        if event["role"] and event["role"] not in roles:
            errors.add("event-role-outside-roster")
        cohort = event.get("cohort", "")
        if event["kind"] in {"node-start", "operation", "sample", "fault", "recovery"}:
            cleanup = False
        scope = (cohort, event["role"])
        if event["kind"] == "node-start" and event["outcome"] == "pass":
            if not cohort:
                observed_roles.add(event["role"])
                last_probe = None
            if runtime_epochs.get(scope) == event["nodeEpoch"] and runtime_epoch_controllers.get(scope) == event["epoch"]:
                errors.add("node-start-reuses-runtime-epoch")
            runtime_epochs[scope] = event["nodeEpoch"]
            runtime_epoch_controllers[scope] = event["epoch"]
            active_roles.add(scope)
            owned_scopes.add(scope)
        elif event["role"] and runtime_epochs.get(scope) != event["nodeEpoch"]:
            errors.add("runtime-epoch-mismatch")
        elif event["kind"] in {"operation", "sample"} and scope not in active_roles:
            errors.add("operation-on-stopped-node")
        if event["kind"] == "node-stop":
            active_roles.discard(scope)
            if event["outcome"] == "pass":
                owned_scopes.discard(scope)
            if not cohort:
                last_probe = None
                operations_since_probe = 0
        if event["outcome"] in {"fail", "cleanup-incomplete"}:
            errors.add("observed-failure")
        if event["kind"] == "fault":
            fault_since_probe = True
            if event["operation"]:
                key = (event["role"], event["operation"])
                if key in open_faults:
                    errors.add("fault-operation-replayed")
                open_faults[key] = (event["epoch"], event["monotonicNs"])
        if event["kind"] == "recovery":
            fault_since_probe = True
            key = (event["role"], event["operation"])
            started = open_faults.pop(key, None)
            if started is None or started[0] != event["epoch"] or started[1] > event["monotonicNs"]:
                errors.add("fault-recovery-lineage-invalid")
            else:
                fault_intervals.setdefault(event["epoch"], []).append((started[1], event["monotonicNs"]))
        if (event["kind"] == "sample" and event["outcome"] == "pass" and scope in active_roles
                and runtime_epochs.get(scope) == event["nodeEpoch"]):
            periodic_samples.add((event["role"], event["scenario"]))
        if event["kind"] == "operation":
            peer = event["peerRole"]
            if peer and (("", peer) not in active_roles
                         or event.get("peerNodeEpoch") != runtime_epochs.get(("", peer))):
                errors.add("peer-runtime-epoch-mismatch")
            identity = (cohort, event["operation"])
            if identity in operation_ids:
                errors.add("operation-replayed")
            operation_ids.add(identity)
            if cohort:
                cohort_samples[cohort] += 1
            if (event["outcome"] == "pass" and not cohort and scope in active_roles
                    and runtime_epochs.get(scope) == event["nodeEpoch"]
                    and (not peer or (("", peer) in active_roles
                         and event.get("peerNodeEpoch") == runtime_epochs.get(("", peer))))):
                samples[event["scenario"]] += 1
                operations_since_probe += 1
                case = (event["scenario"], event["role"], event["peerRole"])
                if case in case_samples:
                    case_samples[case] += 1
                else:
                    errors.add("operation-outside-required-case")
        if previous and event["kind"] != "continuation":
            interval = (event["monotonicNs"] - previous["monotonicNs"]) / 1e9
            wall_delta = (stamp - previous_stamp).total_seconds()
            if interval < 0 or wall_delta < 0 or abs(interval - wall_delta) > 2:
                errors.add("clock-discontinuity")
            elif interval > plan["policy"]["maxGapSeconds"]:
                gap_intervals.setdefault(event["epoch"], []).append((previous["monotonicNs"], event["monotonicNs"]))
        if event["kind"] == "probe":
            if last_probe:
                probe_interval = (event["monotonicNs"] - last_probe["monotonicNs"]) / 1e9
                if probe_interval > plan["policy"]["maxGapSeconds"]:
                    gap_intervals.setdefault(event["epoch"], []).append((last_probe["monotonicNs"], event["monotonicNs"]))
                old_count = last_probe["counters"].get("operations", 0)
                new_count = event["counters"].get("operations", 0)
                if new_count < old_count:
                    errors.add("operation-counter-regressed")
                if (0 <= probe_interval <= plan["policy"]["maxGapSeconds"]
                        and event["epoch"] == last_probe["epoch"]
                        and last_probe["outcome"] == event["outcome"] == "pass"
                        and not fault_since_probe and not open_faults
                        and all(("", role) in active_roles for role in roles)
                        and expected_samples <= periodic_samples
                        and operations_since_probe > 0
                        and new_count - old_count == operations_since_probe):
                    elapsed += probe_interval
            last_probe = event
            operations_since_probe = 0
            fault_since_probe = bool(open_faults)
            periodic_samples.clear()
        if not cohort and event["kind"] == "cleanup":
            cleanup = event["outcome"] == "pass" and not owned_scopes
        previous = event
        previous_stamp = stamp
    if checkpoint["schemaVersion"] != 1 or checkpoint["planDigest"] != digest(plan) or checkpoint["sequence"] != len(events) or checkpoint["tailDigest"] != (digest(previous) if previous else ZERO) or checkpoint["epoch"] != epoch:
        errors.add("checkpoint-substitution-or-truncation")
    if controller_restarts:
        errors.add("controller-restarted-uninterrupted-soak-unproven")
    epoch_coverages.append(elapsed)
    elapsed = max(epoch_coverages, default=0)
    if checkpoint["status"] != "complete" or not events or events[0]["kind"] != "start" or events[-1]["kind"] != "finish":
        errors.add("run-incomplete")
    if observed_roles != roles:
        errors.add("node-observations-incomplete")
    missing_cases = sorted("/".join(part for part in case if part) for case, count in case_samples.items() if count == 0)
    missing = sorted(s for s in SCENARIOS if any(case_samples[(s, role, peer)] == 0 for role, peer in CASES[s]))
    if missing:
        errors.add("required-scenarios-not-observed")
    if not operation_ids:
        elapsed = 0
        errors.add("idle-only-run")
    for intervals in gap_intervals.values():
        end = None
        for left, right in sorted(intervals):
            if end is None or left > end:
                gaps += (right - left) / 1e9
            elif right > end:
                gaps += (right - end) / 1e9
            end = max(right, end if end is not None else right)
    if gaps:
        errors.add("unexplained-observation-gap")
    if {"clock-discontinuity", "controller-epoch-changed", "journal-wall-clock-invalid", "runtime-epoch-mismatch", "journal-lineage-invalid", "checkpoint-substitution-or-truncation", "continuation-lineage-invalid", "operation-replayed", "operation-on-stopped-node", "peer-runtime-epoch-mismatch"}.intersection(errors):
        elapsed = 0
        epoch_coverages = [0.0 for _ in epoch_coverages]
    if elapsed < plan["policy"]["minimumObservedSeconds"]:
        errors.add("observed-duration-insufficient")
    if elapsed > plan["requestedSeconds"] + plan["policy"]["maxGapSeconds"]:
        errors.add("authorized-duration-exceeded")
    if open_faults:
        errors.add("fault-recovery-incomplete")
    planned_fault_seconds = 0.0
    for intervals in fault_intervals.values():
        end = None
        for left, right in sorted(intervals):
            planned_fault_seconds += max(0, right - max(left, end if end is not None else left)) / 1e9
            end = max(right, end if end is not None else right)
    if not cleanup:
        errors.add("cleanup-not-observed")
    wall_span = max(0, (previous_stamp - wall_start).total_seconds()) if previous else 0
    # A hash-chain reader cannot elevate locally fabricated events into an original protected
    # producer. A future authenticated adapter must retain original run/attempt/job ownership.
    return {"schemaVersion": 1, "kind": "cryptad-cross-version-soak-observation", "experimentId": plan["experimentId"],
            "planDigest": digest(plan), "evidenceProfile": plan["profile"], "topologyClass": plan["topologyClass"],
            "provenanceClass": plan["provenanceClass"],
            "producer": dict(plan["producer"]), "participants": [dict(node) for node in plan["nodes"]],
            "actualTopologyIdentity": "local-journal-integrity-only",
            "recoveryCohortSamples": cohort_samples,
            "artifactAuthentication": "not-authenticated",
            "roleScenarioSamples": {role: {scenario: sum(count for (case_scenario, case_role, _peer), count in case_samples.items() if case_scenario == scenario and case_role == role)
                                               for scenario in sorted(SCENARIOS)} for role in sorted(roles)},
            "status": "fail" if "observed-failure" in errors else ("partial" if errors else "verified-local-integrity"),
            "requestedSeconds": plan["requestedSeconds"], "wallSpanSeconds": wall_span,
            "observedEligibleSeconds": elapsed, "controllerRestarts": controller_restarts,
            "measuredEpochSeconds": epoch_coverages, "unexplainedGapSeconds": gaps, "plannedFaultSeconds": planned_fault_seconds, "scenarioSamples": samples,
            "missingScenarios": missing, "missingCases": missing_cases,
            "caseSamples": {"/".join(part for part in case if part): count for case, count in sorted(case_samples.items())}, "findings": sorted(errors), "cleanup": "observed" if cleanup else "not-observed",
            "protectedAuthentication": "not-authenticated", "releaseEligible": False}
