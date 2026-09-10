"""Isolated previous-to-candidate daemon recovery using owned packaged process primitives.

This module never overwrites a main participant's product identity. A separately authorized
cohort keeps one private profile while its explicit subject changes from previous to candidate.
All backups and comparison values stay in that cohort. No daemon downgrade is executed.
"""
from __future__ import annotations

import base64
import copy
import json
import os
from pathlib import Path
import secrets
import uuid

import cross_version_runtime as runtime

COHORT = "previous-to-candidate"
SUBJECTS = ("previous", "candidate-sender")
SELECTION_FIELDS = {"cohortId", "fnpPort", "fcpPort", "httpPort"}


class RecoveryFailure(ValueError):
    """A fixed public error, with no private response or state text."""


def validate_selection(supervisor, selection):
    if (not isinstance(supervisor, runtime.Supervisor) or not isinstance(selection, dict)
            or set(selection) != SELECTION_FIELDS or selection["cohortId"] != COHORT
            or supervisor.authorization.get("recoveryInputsDigest") != runtime.canonical_digest(selection)):
        raise RecoveryFailure("isolated-recovery-selection-not-authorized")
    if supervisor.plan.get("cohorts") != [{"id": COHORT, "sourceRole": "previous", "targetRole": "candidate-sender",
                                          "configDigest": runtime.canonical_digest(selection)}]:
        raise RecoveryFailure("recovery-public-cohort-binding-invalid")
    ports = [selection[name] for name in ("fnpPort", "fcpPort", "httpPort")]
    main_ports = {row[name] for row in supervisor.private["nodes"].values()
                  for name in ("fnpPort", "fcpPort", "httpPort")}
    if (any(type(port) is not int or not 1024 <= port <= 65535 for port in ports)
            or len(set(ports)) != 3 or main_ports.intersection(ports)):
        raise RecoveryFailure("isolated-recovery-port-binding-invalid")
    rows = {row["role"]: row for row in supervisor.plan["nodes"]}
    if rows["previous"]["artifactDigest"] == rows["candidate-sender"]["artifactDigest"]:
        raise RecoveryFailure("recovery-source-and-target-bytes-identical")
    apps = supervisor.private["nodes"]["previous"]["apps"]
    if not any(app["appId"] == "site-publisher" for app in apps):
        raise RecoveryFailure("previous-signed-site-publisher-required")
    return rows


class OwnedRecoveryCohort(runtime.Supervisor):
    """Concrete owned local process adapter; exact selected package subjects never relabeled.

    ``emit_scoped`` is the main runner's journal boundary. It must bind ``cohort_id`` separately
    from the subject role, so these node epochs cannot replace a main participant's epoch.
    This adapter deliberately cannot resume an interrupted cohort or attach arbitrary processes.
    Its preserved private state is the reconciliation input after interruption.
    """
    def __init__(self, supervisor, selection, emit_scoped):
        rows = validate_selection(supervisor, selection)
        if not callable(emit_scoped):
            raise RecoveryFailure("recovery-scoped-journal-required")
        self.parent = supervisor
        self.plan = supervisor.plan
        self.authorization = supervisor.authorization
        self.selection = dict(selection)
        self.subjects = {role: copy.deepcopy(rows[role]) for role in SUBJECTS}
        self.emit_scoped = emit_scoped
        self.root = supervisor.root / "runtime" / "recovery-upgrade"
        if self.root.exists() or self.root.is_symlink():
            raise RecoveryFailure("recovery-root-already-exists-reconciliation-required")
        self.root.mkdir(mode=0o700)
        self.owner_nonce = uuid.uuid4().hex
        self.nodes, self.apps, self.prepared, self.trust_paths = {}, {}, {}, {}
        self.app_staging, self.app_staging_identities = {}, {}
        self.package_identities, self.daemon_identities = {}, {}
        # The isolated upgrade cohort inherits the launcher, not main catalog injections.
        self.catalog_prepared = None
        self.catalog_environment = {}
        self.private = {"nodes": {}}
        self.orphaned_spawn = False
        self.current_role = None
        self.phase = "allocated"
        self.closed = False
        self.canaries = []
        self.mail_canary_observations = {}
        self.save_state()
        try:
            with runtime.absolute_deadline(self.remaining(600)):
                self._prepare()
        except BaseException:
            self.phase = "preparation-failed"
            self.save_state()
            raise

    def remaining(self, limit=180):
        return self.parent.remaining(limit)

    def next_operation(self):
        return self.parent.next_operation()

    def emit(self, kind, role="", scenario="", operation="", outcome="pass", counters=None,
             peer_role="", node_epoch=None):
        if role and role not in SUBJECTS:
            raise RecoveryFailure("recovery-subject-role-invalid")
        self.emit_scoped(kind, cohort_id=COHORT, subject_role=role, scenario=scenario,
                         operation=operation, outcome=outcome, counters=counters or {}, node_epoch=node_epoch)

    def save_state(self):
        nodes = {role: {"identity": node.identity, "running": node.runtime.process.poll() is None}
                 for role, node in self.nodes.items()}
        value = {"schemaVersion": 1, "kind": "private-daemon-recovery-state", "cohortId": COHORT,
                 "planDigest": runtime.canonical_digest(self.plan), "selectionDigest": runtime.canonical_digest(self.selection),
                 "ownerNonce": self.owner_nonce, "phase": self.phase, "currentSubject": self.current_role,
                 "nodes": nodes}
        temporary = self.root / ("state-" + uuid.uuid4().hex + ".tmp")
        with temporary.open("x", encoding="utf-8") as stream:
            temporary.chmod(0o600)
            json.dump(value, stream, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, self.root / "state.json")
        descriptor = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _prepare(self):
        source = self.parent.private["nodes"]["previous"]
        selected_app = next(app for app in source["apps"] if app["appId"] == "site-publisher")
        self.app = copy.deepcopy(selected_app)
        self.trust = self.root / "trusted-app-keys.properties"
        self.trust.write_bytes(Path(source["trustedKeysPath"]).read_bytes())
        self.trust.chmod(0o600)
        if runtime.digest_file(self.trust) != source["trustedKeysDigest"]:
            raise RecoveryFailure("recovery-trust-substitution")
        self.staging = self.root / "staged-site-publisher"
        runtime.extract_app_bundle(selected_app["bundlePath"], self.staging, selected_app["bundleDigest"])
        self.app_tree = runtime.tree_digest(self.staging, require_java=False)
        node_root = self.root / "node"
        ports = runtime.interop.Ports(self.selection["fnpPort"], self.selection["fcpPort"], 0, 0)
        runtime.interop.ensure_tcp_port_available(self.selection["fcpPort"])
        runtime.interop.ensure_tcp_port_available(self.selection["httpPort"])
        runtime.interop.ensure_udp_port_available(self.selection["fnpPort"])
        config = runtime.make_runtime_config(node_root, ports, self.selection["httpPort"])
        config_digest = runtime.config_identity(config, node_root, self.selection["fnpPort"],
                                                self.selection["fcpPort"], self.selection["httpPort"], source["trustedKeysDigest"])
        for role in SUBJECTS:
            selected = self.subjects[role]
            distribution, _, _, java_home, _ = self.parent.prepared[role]
            package = self.parent.private["nodes"][role]
            if (runtime.digest_file(package["archivePath"]) != selected["artifactDigest"]
                    or runtime.tree_digest(distribution, require_java=False) != self.parent.package_identities[role]
                    or runtime.tree_digest(java_home) != selected["runtimeDigest"]):
                raise RecoveryFailure("recovery-selected-package-changed")
            self.package_identities[role] = self.parent.package_identities[role]
            self.daemon_identities[role] = runtime.packaged_daemon_identity(distribution, selected["sourceCommit"])
            self.prepared[role] = (distribution, node_root, ports, java_home, config_digest)
            self.trust_paths[role] = self.trust
            self.private["nodes"][role] = {**copy.deepcopy(package), "apps": [copy.deepcopy(self.app)],
                                           **{field: self.selection[field] for field in ("fnpPort", "fcpPort", "httpPort")}}
            self.app_staging[(role, "site-publisher")] = self.staging
            self.app_staging_identities[role + "/site-publisher"] = self.app_tree
        if self.daemon_identities["previous"] == self.daemon_identities["candidate-sender"]:
            raise RecoveryFailure("recovery-current-daemon-relabeled-previous")
        self.phase = "prepared"
        self.save_state()

    def launch(self, role):
        if role not in SUBJECTS or self.current_role is not None:
            raise RecoveryFailure("recovery-transition-requires-stopped-cohort")
        if role == "previous" and self.phase != "prepared":
            raise RecoveryFailure("daemon-downgrade-storage-compatibility-unestablished")
        selected = self.subjects[role]
        distribution, _, _, java_home, _ = self.prepared[role]
        if (runtime.tree_digest(distribution, require_java=False) != self.package_identities[role]
                or runtime.tree_digest(java_home) != selected["runtimeDigest"]):
            raise RecoveryFailure("recovery-target-bytes-changed")
        self.start(role)
        self.current_role = role
        handle = runtime.AppHandle(self, role, "site-publisher")
        handle.host_bootstrap()
        status, contract = handle.request("GET", "/api/v1/platform/contract")
        if status != 200 or contract.get("contract", {}).get("contractVersion") != selected["contractVersion"]:
            raise RecoveryFailure("recovery-running-contract-mismatch")
        if self.phase == "prepared":
            status, inventory = handle.request("GET", "/api/v1/apps")
            if status != 200 or inventory.get("apps") != []:
                raise RecoveryFailure("recovery-profile-not-fresh")
            status, value = handle.request("POST", "/api/v1/apps/install", {"stagedDir": str(self.staging)})
            if status != 201 or value.get("app", {}).get("appId") != "site-publisher":
                raise RecoveryFailure("recovery-app-install-not-admitted")
        status, existing = handle.request("GET", "/api/v1/apps/site-publisher/runtime")
        if status != 200:
            raise RecoveryFailure("recovery-app-runtime-unavailable")
        if existing.get("runtime", {}).get("running") is not True:
            status, _ = handle.request("POST", "/api/v1/apps/site-publisher/start")
            if status not in (200, 201):
                raise RecoveryFailure("recovery-app-start-failed")
        handle.observe_worker()
        handle.refresh_session()
        self.apps[(role, "site-publisher")] = handle
        self.app_subject(role, "site-publisher")
        self.phase = "running-" + role
        self.save_state()
        return handle

    def stop_current(self):
        if self.current_role is not None:
            self.stop(self.current_role)
            self.current_role = None
            self.save_state()

    def transition(self):
        if self.current_role != "previous":
            raise RecoveryFailure("recovery-upgrade-must-start-previous")
        self.stop_current()
        return self.launch("candidate-sender")

    def close(self):
        complete = not self.orphaned_spawn
        for role in reversed(SUBJECTS):
            try:
                self.stop(role)
            except (OSError, ValueError, runtime.RuntimeFailure):
                complete = False
        self.closed = complete
        self.phase = "stopped" if complete else "cleanup-incomplete"
        self.save_state()
        if self.nodes:
            observed_role = "candidate-sender" if "candidate-sender" in self.nodes else "previous"
            self.emit("cleanup", role=observed_role, outcome="pass" if complete else "fail")
        return "observed" if complete else "cleanup-incomplete"


def observe_upgrade(cohort):
    """Create state under old bytes, privately back it up, then observe current-byte persistence."""
    if not isinstance(cohort, OwnedRecoveryCohort):
        raise RecoveryFailure("owned-recovery-cohort-required")
    result = {"kind": "cross-version-recovery-observation", "cohortId": COHORT, "status": "partial",
              "previousArtifactDigest": cohort.subjects["previous"]["artifactDigest"],
              "candidateArtifactDigest": cohort.subjects["candidate-sender"]["artifactDigest"],
              "appSubjectRole": "previous", "appBundleDigest": cohort.app["bundleDigest"],
              "daemonUpgrade": "not-observed", "privateBackup": "not-observed", "privateRestore": "not-observed",
              "privateState": "retained-for-reconciliation",
              "unsafeDowngrade": "not-observed", "mailRestore": "not-observed", "cleanup": "not-observed"}
    namespace = "recovery-" + uuid.uuid4().hex
    record_path = "/api/v1/app-data/records/" + namespace + "/probe"
    value = base64.b64encode(secrets.token_bytes(64)).decode()
    try:
        handle = cohort.launch("previous")
        status, _ = handle.request("GET", record_path, principal="app")
        if status != 404:
            raise RecoveryFailure("recovery-synthetic-record-already-exists")
        status, _ = handle.request("POST", "/api/v1/app-data/records", {"namespace": namespace, "key": "probe",
                                  "schemaVersion": 1, "contentType": "application/octet-stream", "valueBase64": value}, principal="app")
        if status not in (200, 201):
            raise RecoveryFailure("recovery-previous-write-failed")
        status, record = handle.request("GET", record_path, principal="app")
        if status != 200 or record.get("record", {}).get("valueBase64") != value:
            raise RecoveryFailure("recovery-previous-read-mismatch")
        # The normal operator route validates host form-password and keeps values private.
        status, backup = handle.request("POST", "/api/v1/operator/app-data/backups", {"appId": "site-publisher"})
        if status != 200 or not isinstance(backup.get("payloadBase64"), str):
            raise RecoveryFailure("recovery-private-backup-failed")
        encoded = json.dumps(backup, separators=(",", ":")).encode()
        if len(encoded) > 2 * 1024**2:
            raise RecoveryFailure("recovery-private-backup-too-large")
        with (cohort.root / "private-app-backup.json").open("xb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        result["privateBackup"] = "observed"
        cohort.emit("operation", role="previous", scenario="daemon-upgrade", operation=cohort.next_operation(),
                    outcome="partial", counters={"operations": 1})
        handle = cohort.transition()
        status, record = handle.request("GET", record_path, principal="app")
        if status != 200 or record.get("record", {}).get("valueBase64") != value:
            raise RecoveryFailure("recovery-current-state-mismatch")
        current_value = base64.b64encode(secrets.token_bytes(64) + b"current-write").decode()
        status, _ = handle.request("POST", "/api/v1/app-data/records", {"namespace": namespace, "key": "probe",
                                  "schemaVersion": 1, "contentType": "application/octet-stream", "valueBase64": current_value}, principal="app")
        if status not in (200, 201):
            raise RecoveryFailure("recovery-current-write-failed")
        cohort.stop_current()
        handle = cohort.launch("candidate-sender")
        status, record = handle.request("GET", record_path, principal="app")
        if status != 200 or record.get("record", {}).get("valueBase64") != current_value:
            raise RecoveryFailure("recovery-current-restart-state-mismatch")
        result["daemonUpgrade"] = "observed"
        cohort.emit("operation", role="candidate-sender", scenario="daemon-upgrade", operation=cohort.next_operation(),
                    outcome="partial", counters={"operations": 1})
        changed = base64.b64encode(secrets.token_bytes(64) + b"changed").decode()
        status, _ = handle.request("POST", "/api/v1/app-data/records", {"namespace": namespace, "key": "probe",
                                  "schemaVersion": 1, "contentType": "application/octet-stream", "valueBase64": changed}, principal="app")
        if status not in (200, 201):
            raise RecoveryFailure("recovery-restore-arrangement-failed")
        status, record = handle.request("GET", record_path, principal="app")
        if status != 200 or record.get("record", {}).get("valueBase64") != changed:
            raise RecoveryFailure("recovery-restore-arrangement-mismatch")
        parameters = {"payloadBase64": backup["payloadBase64"], "mode": "replaceApp", "appId": "site-publisher"}
        status, preview = handle.request("POST", "/api/v1/operator/app-data/restore/plan", parameters)
        if status != 200 or preview.get("restorePlan", {}).get("status") != "ready":
            raise RecoveryFailure("recovery-private-restore-not-ready")
        status, restored = handle.request("POST", "/api/v1/operator/app-data/restore", parameters)
        if (status != 200 or restored.get("restoreResult", {}).get("restored") is not True
                or restored.get("restoreResult", {}).get("status") != "restored"):
            raise RecoveryFailure("recovery-private-restore-not-committed")
        status, record = handle.request("GET", record_path, principal="app")
        if status != 200 or record.get("record", {}).get("valueBase64") != value:
            raise RecoveryFailure("recovery-private-restore-mismatch")
        result["privateRestore"] = "observed"
        cohort.emit("operation", role="candidate-sender", scenario="daemon-upgrade", operation=cohort.next_operation(),
                    outcome="partial", counters={"operations": 1})
        # This cohort contains no authenticated Mail account. It cannot establish the Mail
        # unsafe-vault downgrade or intentionally paused restore scenario by assertion.
    except Exception:
        result["status"] = "failed"
    finally:
        result["cleanup"] = cohort.close()
        if result["cleanup"] != "observed":
            result["status"] = "failed"
    return result
