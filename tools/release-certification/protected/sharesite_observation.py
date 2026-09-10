"""Run the fixed converter and installed Site Publisher controller on an admitted disposable node.

This callable adapter requires the supervisor that owns the node and authenticates app sessions.
It never accepts reported outcomes, executes shell text, or publishes CHKs. Operator-owned snapshots
require the separate root-sealed private selection before any source is read. Neither a protected
runner nor an operator-owned snapshot establishes independently verified real-user completion.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import json
import os
from pathlib import Path
import subprocess
from typing import Protocol
import uuid
import sys
sys.modules.setdefault("sharesite_observation", sys.modules[__name__])

_VERIFIED = object()
WORKFLOW = ".github/workflows/stable-1.0-sharesite-runtime-observation.yml"


class AuthenticatedMigration:
    """Private immutable comparison value from original protected runtime authentication."""
    __slots__ = ("__canonical",)
    def __init__(self, observation: dict, authority: object = None):
        if authority is not _VERIFIED:
            raise MigrationFailure("migration-authority-not-verified")
        self.__canonical = json.dumps(observation, sort_keys=True, separators=(",", ":"))
    def matches(self, value: dict) -> bool:
        return json.dumps(value, sort_keys=True, separators=(",", ":")) == self.__canonical

SYNTHETIC_FIXTURE_DIGEST = "sha256:89cebfb977a2cd6687954eb618570d79bf00b617a8d334062a8d2bb744cf162a"
CHECKS = frozenset({"literalFidelity", "sourcePreservation", "secretExclusionStatus", "importCommit",
                    "restartPersistence", "editSave", "literalPreview", "replay", "stalePreview",
                    "quotaFailure", "interruptionRecovery", "dataUndo", "privateRestore",
                    "bundleRollback", "cleanup", "newChkPublication"})
# Conservative complete-stage allowances include reads, writes, denials and quota cleanup.
STAGE_REQUEST_LIMITS = {"import": 64, "recover": 96, "restore": 256}
STAGE_CHECKS = {"import": {"literalFidelity", "importCommit", "replay"},
                "recover": {"restartPersistence", "interruptionRecovery", "editSave", "stalePreview", "dataUndo"},
                "restore": {"privateRestore", "quotaFailure"}}


class MigrationFailure(ValueError):
    """A fixed failure code; private collector outputs are never exception text."""


class AdmittedSupervisor(Protocol):
    """Control available only after exact disposable topology and app admission."""
    plan: dict

    def app_session(self, role: str, app_id: str) -> dict[str, str]:
        """Issue a fresh legitimate own-app browser session for the admitted signed app."""
    def restart_node(self, role: str) -> None:
        """Restart only the exact owned node, re-probe health and preserve its data stores."""
    def reserve_operations(self, count: int) -> None:
        """Durably charge request capacity before issuing it to a subprocess; no implicit refund."""
    def remaining(self, seconds: float) -> float:
        """Bound one operation by the remaining approved experiment deadline."""


@dataclass(frozen=True)
class MigrationInputs:
    """Private paths selected from the supervisor's authenticated artifact roster."""
    role: str
    converter: Path
    converter_digest: str
    node_executable: Path
    node_digest: str
    controller: Path
    controller_digest: str
    fixture: Path
    private_root: Path
    tool_root: Path
    tool_tree_digest: str
    java_home: Path
    java_tree_digest: str
    driver_digest: str
    recovery_role: str | None = None


def _digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _checked_file(path: Path, expected: str, maximum: int) -> None:
    info = path.lstat()
    import stat
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 1 <= info.st_size <= maximum or _digest(path) != expected:
        raise MigrationFailure("migration-input-identity-invalid")


def _execute(arguments: list[str], payload: dict | None = None, *, java_home: Path,
             temporary: Path, timeout: float) -> bytes:
    try:
        from bounded_process import run
        return run(arguments, payload=None if payload is None else json.dumps(payload).encode(),
                   environment={"PATH": str(java_home / "bin") + ":/usr/bin:/bin", "JAVA_HOME": str(java_home),
                                "LANG": "C.UTF-8", "TMPDIR": str(temporary)}, output_limit=16384, timeout=timeout)
    except (OSError, ValueError):
        raise MigrationFailure("migration-adapter-operation-failed") from None


def _run_stage(supervisor, inputs, stage, config, driver, private):
    maximum = STAGE_REQUEST_LIMITS[stage]
    supervisor.reserve_operations(maximum)
    raw = _execute([str(inputs.node_executable), str(driver)], {**config, "maximumRequests": maximum},
                   java_home=inputs.java_home, temporary=private, timeout=supervisor.remaining(180))
    return validate_stage(json.loads(raw), stage)


def validate_stage(value: object, stage: str) -> dict:
    if (not isinstance(value, dict) or set(value) != {"schemaVersion", "kind", "stage", "selectedCount", "checks"}
            or value["schemaVersion"] != 1 or value["kind"] != "sharesite-runtime-stage"
            or value["stage"] != stage or type(value["selectedCount"]) is not int or value["selectedCount"] != 1
            or not isinstance(value["checks"], dict) or set(value["checks"]) != STAGE_CHECKS[stage]
            or any(result != "pass" for result in value["checks"].values())):
        raise MigrationFailure("migration-stage-result-invalid")
    return value


OPERATOR_SELECTION = Path("/etc/cryptad-certification/sharesite-topology/operator-source-selection.json")
OPERATOR_SOURCE_ROOT = Path("/var/lib/cryptad-sharesite-private-sources")


def _operator_selection(supervisor: AdmittedSupervisor, inputs: MigrationInputs) -> dict:
    """Authenticate fixed private source authority before opening any selected source bytes."""
    import stat
    from datetime import datetime, timezone
    if os.environ.get("GITHUB_WORKFLOW_REF") != f"crypta-network/cryptad/{WORKFLOW}@refs/heads/develop":
        raise MigrationFailure("migration-private-source-authority-unavailable")
    for parent in (OPERATOR_SELECTION.parent,):
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise MigrationFailure("migration-private-source-authority-unavailable")
    info = OPERATOR_SELECTION.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != 0
            or info.st_mode & 0o027 or not 1 <= info.st_size <= 16384):
        raise MigrationFailure("migration-private-source-authority-unavailable")
    with os.fdopen(os.open(OPERATOR_SELECTION, os.O_RDONLY | os.O_NOFOLLOW), "rb") as stream:
        selection = json.load(stream)
    return _validate_operator_selection(selection, supervisor, inputs)


def _validate_operator_selection(selection: dict, supervisor: AdmittedSupervisor, inputs: MigrationInputs) -> dict:
    """Validate already root-authenticated selection semantics without reading source bytes."""
    from datetime import datetime, timezone
    fields = {"schemaVersion", "sourceKind", "sourcePath", "sourceDigest", "sourceBytes", "maximumBytes",
              "selectedIndex", "planDigest", "role", "expiresAt"}
    if not isinstance(selection, dict) or set(selection) != fields or selection["schemaVersion"] != 1:
        raise MigrationFailure("migration-private-source-selection-invalid")
    import re
    from app_subject_projection import _canonical_digest
    if (selection["sourceKind"] != "stopped-private-snapshot" or selection["role"] != inputs.role
            or not isinstance(selection["sourcePath"], str)
            or not Path(selection["sourcePath"]).is_absolute()
            or not Path(selection["sourcePath"]).is_relative_to(OPERATOR_SOURCE_ROOT)
            or ".." in Path(selection["sourcePath"]).parts
            or selection["planDigest"] != _canonical_digest(supervisor.plan)
            or not isinstance(selection["sourceDigest"], str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", selection["sourceDigest"]) is None
            or type(selection["selectedIndex"]) is not int or not 0 <= selection["selectedIndex"] < 10000
            or type(selection["sourceBytes"]) is not int or type(selection["maximumBytes"]) is not int
            or not 1 <= selection["sourceBytes"] <= selection["maximumBytes"] <= 1024 * 1024):
        raise MigrationFailure("migration-private-source-selection-invalid")
    expiry = datetime.fromisoformat(selection["expiresAt"].replace("Z", "+00:00"))
    if expiry.tzinfo is None or expiry <= datetime.now(timezone.utc):
        raise MigrationFailure("migration-private-source-authority-expired")
    if selection["sourceDigest"] == SYNTHETIC_FIXTURE_DIGEST:
        raise MigrationFailure("migration-known-synthetic-source-cannot-be-private")
    return selection


def _read_selected_private_source(selection: dict) -> bytes:
    import stat
    path = Path(selection["sourcePath"])
    if not path.is_absolute() or not path.is_relative_to(OPERATOR_SOURCE_ROOT) or ".." in path.parts:
        raise MigrationFailure("migration-private-source-outside-selection")
    for parent in (OPERATOR_SOURCE_ROOT, *path.relative_to(OPERATOR_SOURCE_ROOT).parents):
        if not parent.is_absolute():
            parent = OPERATOR_SOURCE_ROOT / parent
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid not in {0, os.geteuid()} or info.st_mode & 0o077:
            raise MigrationFailure("migration-private-source-directory-invalid")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1
                or info.st_mode & 0o077 or info.st_size != selection["sourceBytes"]):
            raise MigrationFailure("migration-private-source-file-invalid")
        raw = stream.read(selection["maximumBytes"] + 1)
    if (len(raw) != selection["sourceBytes"] or "sha256:" + hashlib.sha256(raw).hexdigest() != selection["sourceDigest"]):
        raise MigrationFailure("migration-private-source-substituted")
    return raw


def observe_operator_private(supervisor: AdmittedSupervisor, inputs: MigrationInputs) -> dict:
    """Observe one explicitly selected private snapshot without claiming independent real-user proof.

    The sealed selection, source bytes and comparison digests never enter public output. This API
    cannot be activated by the synthetic fixture flag or an arbitrary caller-provided approval.
    """
    selection = _operator_selection(supervisor, inputs)
    raw = _read_selected_private_source(selection)
    if (inputs.private_root.is_symlink() or not inputs.private_root.is_dir()
            or inputs.private_root.stat().st_uid != os.geteuid() or inputs.private_root.stat().st_mode & 0o077):
        raise MigrationFailure("migration-private-root-invalid")
    snapshot = inputs.private_root / ("authorized-source-" + str(uuid.uuid4()) + ".db")
    with snapshot.open("xb") as stream:
        os.chmod(snapshot, 0o600)
        stream.write(raw)
    from datetime import datetime, timezone
    import time
    expiry = datetime.fromisoformat(selection["expiresAt"].replace("Z", "+00:00"))
    deadline = time.monotonic() + (expiry - datetime.now(timezone.utc)).total_seconds()

    class PrivateSupervisor:
        def remaining(self, seconds: float) -> float:
            duration = min(supervisor.remaining(seconds), deadline - time.monotonic())
            if duration <= 0:
                raise MigrationFailure("migration-private-source-authority-expired")
            return duration

        def app_session(self, role: str, app_id: str) -> dict[str, str]:
            self.remaining(1)
            return supervisor.app_session(role, app_id)

        def reserve_operations(self, count: int) -> None:
            self.remaining(1)
            supervisor.reserve_operations(count)

        def restart_node(self, role: str) -> None:
            self.remaining(1)
            supervisor.restart_node(role)

    result = _observe(PrivateSupervisor(), replace(inputs, fixture=snapshot), selection["sourceDigest"],
                      selection["selectedIndex"], "operator-owned-private-observation")
    try:
        _read_selected_private_source(selection)
    except (MigrationFailure, OSError, ValueError):
        result["outcomes"]["sourcePreservation"] = "fail"
        result["status"] = "failed"
        result["failureCode"] = "migration-runtime-incomplete"
    return result


def observe_synthetic(supervisor: AdmittedSupervisor, inputs: MigrationInputs) -> dict:
    """Run only the pinned public upstream-writer corpus on admitted disposable resources."""
    return _observe(supervisor, inputs, SYNTHETIC_FIXTURE_DIGEST, 0, "upstream-writer-synthetic")


def _observe(supervisor: AdmittedSupervisor, inputs: MigrationInputs, source_digest: str,
             selected_index: int, classification: str) -> dict:
    _checked_file(inputs.fixture, source_digest, 1024 * 1024)
    _checked_file(inputs.converter, inputs.converter_digest, 512 * 1024 * 1024)
    _checked_file(inputs.node_executable, inputs.node_digest, 512 * 1024 * 1024)
    _checked_file(inputs.controller, inputs.controller_digest, 262144)
    from app_subject_projection import tree_digest
    if (tree_digest(inputs.tool_root) != inputs.tool_tree_digest
            or tree_digest(inputs.java_home) != inputs.java_tree_digest
            or not inputs.converter.resolve().is_relative_to(inputs.tool_root.resolve())):
        raise MigrationFailure("migration-tool-tree-identity-invalid")
    driver = Path(__file__).with_name("sharesite_runtime_driver.cjs")
    _checked_file(driver, inputs.driver_digest, 262144)
    if inputs.private_root.is_symlink() or not inputs.private_root.is_dir() or inputs.private_root.stat().st_mode & 0o077:
        raise MigrationFailure("migration-private-root-invalid")
    private = inputs.private_root / ("sharesite-" + str(uuid.uuid4()))
    private.mkdir(mode=0o700)
    workspace = private / "conversion"
    operation = str(uuid.uuid4())
    outcomes = {check: "not-observed" for check in sorted(CHECKS)}
    observed = {"schemaVersion": 2, "kind": "sharesite-runtime-observation",
                "classification": classification, "status": "partial",
                "selectedCount": 1, "outcomes": outcomes, "publication": "not-observed",
                "realDataMigration": "not-observed", "releaseEligibility": "blocked",
                "producerTools": {"toolTreeDigest": inputs.tool_tree_digest, "javaTreeDigest": inputs.java_tree_digest,
                                  "controllerDigest": inputs.controller_digest, "driverDigest": inputs.driver_digest,
                                  "nodeDigest": inputs.node_digest}}
    base = [str(inputs.converter), "migration", "sharesite"]
    common = ["--snapshot", str(inputs.fixture), "--workspace", str(workspace), "--writer-stopped"]
    selection = ["--select", str(selected_index), "--operation-id", operation, "--provenance",
                 ("SYNTHETIC pinned upstream writer fixture" if classification == "upstream-writer-synthetic"
                  else "Operator-selected private stopped snapshot"), "--ack-exclusions"]
    try:
        _execute([*base, "inspect", *common], java_home=inputs.java_home, temporary=private,
                 timeout=supervisor.remaining(180))
        _execute([*base, "plan", *common, *selection], java_home=inputs.java_home, temporary=private,
                 timeout=supervisor.remaining(180))
        private_plan_digest = _digest(workspace / "plan.json").removeprefix("sha256:")
        _execute([*base, "export", *common, *selection, "--ack-plan-sha256", private_plan_digest],
                 java_home=inputs.java_home, temporary=private, timeout=supervisor.remaining(180))
        migration = workspace / "migration.json"
        if b"SYNTHETIC_SECRET_CANARY_DO_NOT_EXPORT" in migration.read_bytes():
            raise MigrationFailure("migration-private-canary-detected")
        if classification == "upstream-writer-synthetic":
            outcomes["secretExclusionStatus"] = "pass"
        for stage in ("import", "recover", *(("restore",) if inputs.recovery_role else ())):
            if stage == "recover":
                supervisor.restart_node(inputs.role)
            session = supervisor.app_session(inputs.recovery_role if stage == "restore" else inputs.role, "site-publisher")
            if set(session) != {"api", "origin", "session"}:
                raise MigrationFailure("migration-session-admission-invalid")
            config = {**session, "stage": stage, "controllerFile": str(inputs.controller),
                      "controllerDigest": inputs.controller_digest, "migrationFile": str(migration),
                      "backupFile": str(private / "before-import.json"),
                      "retainedBackupFile": str(private / "after-import.json")}
            stage_result = _run_stage(supervisor, inputs, stage, config, driver, private)
            outcomes.update(stage_result["checks"])
        if _digest(inputs.fixture) != source_digest:
            raise MigrationFailure("migration-source-changed")
        outcomes["sourcePreservation"] = "pass"
    except (MigrationFailure, OSError, ValueError, KeyError):
        observed["status"] = "failed"
        observed["failureCode"] = "migration-runtime-incomplete"
    # Private backups and the retained undo tombstone require separate supervised cleanup;
    # neither destroying the profile nor declaring them clean is an implicit action here.
    return observed


def validate_observation(value: object, *, require_producer: bool = False) -> dict:
    """Validate the exact public core before export; this does not authenticate its producer."""
    import re
    core = {"schemaVersion", "kind", "classification", "status", "selectedCount", "outcomes",
            "publication", "realDataMigration", "releaseEligibility", "planDigest", "bundleDigest", "producerTools"}
    if require_producer:
        core.add("producer")
    if not isinstance(value, dict) or set(value) not in (core, core | {"failureCode"}):
        raise MigrationFailure("migration-runtime-fields-invalid")
    if (type(value["schemaVersion"]) is not int or value["schemaVersion"] != 2
            or value["kind"] != "sharesite-runtime-observation"
            or value["classification"] not in {"upstream-writer-synthetic", "operator-owned-private-observation"}
            or value["status"] not in {"partial", "failed", "complete"}
            or type(value["selectedCount"]) is not int or value["selectedCount"] != 1
            or value["publication"] != "not-observed" or value["realDataMigration"] != "not-observed"
            or value["releaseEligibility"] != "blocked"):
        raise MigrationFailure("migration-runtime-classification-invalid")
    if not isinstance(value["outcomes"], dict) or set(value["outcomes"]) != CHECKS:
        raise MigrationFailure("migration-runtime-case-set-invalid")
    if any(result not in {"pass", "fail", "not-observed"} for result in value["outcomes"].values()):
        raise MigrationFailure("migration-runtime-outcome-invalid")
    if value["outcomes"]["newChkPublication"] != "not-observed":
        raise MigrationFailure("migration-runtime-publication-not-executed")
    if value["status"] == "complete" and any(value["outcomes"][case] != "pass" for case in CHECKS - {"newChkPublication"}):
        raise MigrationFailure("migration-runtime-complete-contradicts-outcomes")
    if (value["status"] == "failed") != (value.get("failureCode") == "migration-runtime-incomplete"):
        raise MigrationFailure("migration-runtime-failure-status-inconsistent")
    tools = value["producerTools"]
    if not isinstance(tools, dict) or set(tools) != {"toolTreeDigest", "javaTreeDigest", "controllerDigest", "driverDigest", "nodeDigest"}:
        raise MigrationFailure("migration-runtime-tool-set-invalid")
    for digest in [value["planDigest"], value["bundleDigest"], *tools.values()]:
        if not isinstance(digest, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None:
            raise MigrationFailure("migration-runtime-identity-invalid")
    if "failureCode" in value and value["failureCode"] != "migration-runtime-incomplete":
        raise MigrationFailure("migration-runtime-failure-code-invalid")
    if require_producer:
        producer = value["producer"]
        if (not isinstance(producer, dict) or set(producer) != {"sourceCommit", "workflowPath", "runId", "runAttempt", "environment"}
                or producer["workflowPath"] != WORKFLOW or producer["environment"] != "stable-1-0-sharesite-runtime-observation"
                or not isinstance(producer["sourceCommit"], str) or re.fullmatch(r"[0-9a-f]{40}", producer["sourceCommit"]) is None
                or any(type(producer[field]) is not int or producer[field] < 1 for field in ("runId", "runAttempt"))):
            raise MigrationFailure("migration-runtime-producer-invalid")
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from cryptad_certification.redaction import scan_value
    if scan_value(value):
        raise MigrationFailure("migration-runtime-public-scan-failed")
    return value


def authenticate_observation(coordinates: dict, private_root: Path,
                             expected_plan_digest: str, expected_bundle_digest: str) -> tuple[dict, AuthenticatedMigration]:
    """Authenticate original runtime job, exact attested member, plan and signed app subject."""
    from original_artifact_authentication import authenticate_original, _gh, _environment, REPOSITORY
    import io
    import stat
    import tempfile
    import zipfile
    if coordinates.get("sourceFamily") != "sharesite-runtime":
        raise MigrationFailure("migration-producer-family-mismatch")
    artifact = authenticate_original(coordinates, private_root)
    with zipfile.ZipFile(io.BytesIO(artifact.content)) as archive:
        if archive.namelist() != ["sharesite-runtime-observation.json"]:
            raise MigrationFailure("migration-producer-member-set-invalid")
        entry = archive.infolist()[0]
        if entry.file_size > 32768 or stat.S_ISLNK(entry.external_attr >> 16):
            raise MigrationFailure("migration-producer-member-invalid")
        raw = archive.read(entry)
    with tempfile.TemporaryDirectory(prefix="migration-verify-", dir=private_root) as directory:
        path = Path(directory) / "sharesite-runtime-observation.json"
        path.write_bytes(raw)
        verified = _gh(["attestation", "verify", str(path), "--repo", REPOSITORY,
                        "--signer-workflow", REPOSITORY + "/" + WORKFLOW,
                        "--signer-digest", coordinates["sourceCommit"], "--source-digest", coordinates["sourceCommit"],
                        "--format", "json"], _environment())
    invocation = f"https://github.com/{REPOSITORY}/actions/runs/{coordinates['runId']}/attempts/{coordinates['runAttempt']}"
    if not any(row.get("verificationResult", {}).get("signature", {}).get("certificate", {}).get("runInvocationURI")
               == invocation for row in verified):
        raise MigrationFailure("migration-attester-attempt-mismatch")
    observation = json.loads(raw)
    if (observation.get("planDigest") != expected_plan_digest or observation.get("bundleDigest") != expected_bundle_digest
            or observation.get("producer") != {"sourceCommit": coordinates["sourceCommit"], "workflowPath": WORKFLOW,
                "runId": coordinates["runId"], "runAttempt": coordinates["runAttempt"],
                "environment": "stable-1-0-sharesite-runtime-observation"}):
        raise MigrationFailure("migration-authenticated-subject-mismatch")
    return observation, AuthenticatedMigration(observation, _VERIFIED)


def main() -> int:
    """Bind same-job observed bytes or verify the original authenticated producing artifact."""
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("bind-producer", "verify"))
    parser.add_argument("--input", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--coordinates", type=Path)
    parser.add_argument("--private-root", type=Path)
    parser.add_argument("--expected-plan-digest")
    parser.add_argument("--expected-bundle-digest")
    args = parser.parse_args()
    try:
        if args.mode == "bind-producer":
            if (args.input is None or args.input.is_symlink() or args.input.stat().st_size > 32768
                    or os.environ.get("GITHUB_WORKFLOW_REF") != "crypta-network/cryptad/" + WORKFLOW + "@refs/heads/develop"):
                raise MigrationFailure("migration-producer-input-invalid")
            value = validate_observation(json.loads(args.input.read_bytes()))
            value["producer"] = {"sourceCommit": os.environ["GITHUB_SHA"], "workflowPath": WORKFLOW,
                                 "runId": int(os.environ["GITHUB_RUN_ID"]), "runAttempt": int(os.environ["GITHUB_RUN_ATTEMPT"]),
                                 "environment": "stable-1-0-sharesite-runtime-observation"}
            validate_observation(value, require_producer=True)
        else:
            if any(item is None for item in (args.coordinates, args.private_root, args.expected_plan_digest, args.expected_bundle_digest)):
                raise MigrationFailure("migration-verification-input-required")
            observation, authentication = authenticate_observation(json.loads(args.coordinates.read_bytes()), args.private_root,
                                                                     args.expected_plan_digest, args.expected_bundle_digest)
            validate_observation(observation, require_producer=True)
            sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
            from cryptad_certification.engines.stable_legacy_plugin_migration import summarize
            value = summarize(observation, "verify-runtime", authenticated_runtime=authentication)
        with args.output.open("x", encoding="utf-8") as output:
            json.dump(value, output, sort_keys=True, separators=(",", ":"))
            output.write("\n")
        return 0
    except (ValueError, KeyError, OSError):
        print("sharesite_observation_failed", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
