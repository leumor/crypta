#!/usr/bin/env python3
"""Disposable packaged daemon adapter for the reviewed synthetic catalog-origin cohort.

This executable reuses the normal supervisor HTTP client and native platform gates. All inputs,
observations, process logs and traffic counters stay private; local success is never a protected
observer receipt. The protected producer must authenticate this implementation and its inputs.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import time

import cross_version_runtime as runtime
import cross_version_catalog as catalog
from catalog_origin_fixture_server import FixtureServer
from catalog_origin_lifecycle import Driver, Journal, LifecycleFailure, Subject, digest


def port():
    with socket.socket() as selected:
        selected.bind(("127.0.0.1", 0))
        return selected.getsockname()[1]


def raw_digest(value):
    return value.removeprefix("sha256:")


def installed_content_tree(root):
    """Compare every installed byte, independent of native versus ZIP extraction permissions."""
    rows = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or not (path.is_dir() or path.is_file()):
            raise LifecycleFailure("catalog-owned-installed-special-file")
        if path.is_file():
            rows.append([path.relative_to(root).as_posix(), runtime.digest_file(path)])
    if not rows or len(rows) > 4096:
        raise LifecycleFailure("catalog-owned-installed-tree-invalid")
    return digest(rows)


def remaining_budget(budget, seconds):
    """Clamp authorized work to one deadline; owned cleanup remains unconditional."""
    remaining = budget["deadline"] - time.monotonic()
    if remaining <= 0:
        raise LifecycleFailure("catalog-owned-budget-exhausted")
    return min(seconds, remaining)


class OwnedHost:
    """One absent-app role, exact package, scoped bootstrap and bounded normal HTTP control."""
    role = "catalog-origin"

    def __init__(self, root, distribution, java, fixture_root, metadata, server, policies, maximum=900, *, role="catalog-origin", budget=None):
        if role not in {"catalog-origin", "catalog-origin-update", "catalog-origin-staged-negative", "catalog-origin-publisher-scope-negative", "catalog-origin-reviewer-scope-negative"}:
            raise LifecycleFailure("catalog-owned-role-invalid")
        self.role = role
        self.budget = budget if budget is not None else {"operations": 0, "deadline": time.monotonic() + maximum}
        self.root, self.distribution, self.java = root, distribution, java
        self.fixture_root, self.metadata, self.server = fixture_root, metadata, server
        self.deadline = self.budget["deadline"]
        self.operations = 0
        self.node_root = root / "node"
        self.node = None
        self.app_id = metadata["subjects"]["A1"]["appId"]
        self.catalog_prepared = True
        self.http_port = port()
        self.ports = runtime.interop.Ports(port(), port(), 0, 0)
        self.private = {"nodes": {self.role: {"httpPort": self.http_port}}}
        self.policies = {row["catalogId"]: row for row in policies["catalogs"]}
        self.handle = runtime.AppHandle(self, self.role, self.app_id)
        self.epochs = []
        self.transport = Journal(root / "transport-operations.json", digest(metadata))
        self.suppress_install_response = True
        self.authority_observations = {}
        self.activations = []
        self.registry_paths = {}
        self.observed_revisions = {}
        material = root / "verification-material"
        material.mkdir(mode=0o700)
        for role in ("catalog", "publisher", "reviewer"):
            destination = material / (role + ".properties")
            payload = (fixture_root / (role + "-keys.properties")).read_bytes()
            if not 0 < len(payload) <= 1024 * 1024:
                raise LifecycleFailure("catalog-owned-registry-size-invalid")
            with destination.open("xb") as stream:
                stream.write(payload)
            destination.chmod(0o600)
            self.registry_paths[role] = destination

    def remaining(self, seconds):
        return remaining_budget(self.budget, seconds)

    def next_operation(self):
        self.remaining(1)
        self.operations += 1
        self.budget["operations"] += 1
        if self.budget["operations"] > 600:
            raise LifecycleFailure("catalog-owned-operation-budget-exhausted")

    def catalog_route_allowed(self, role, app_id, method, path):
        if (role, app_id) != (self.role, self.app_id):
            return False
        routes = {("GET", "/api/v1/app-catalogs"), ("POST", "/api/v1/app-catalogs/add"),
                  ("GET", "/api/v1/consent/install-preview"),
                  ("GET", "/api/v1/consent/catalog-update-preview"),
                  ("POST", "/api/v1/consent/approve"),
                  ("GET", "/api/v1/operator/catalog-federation"),
                  ("GET", "/api/v1/operator/catalog-federation/conflicts/" + app_id),
                  ("POST", "/api/v1/operator/catalog-federation/conflicts/" + app_id + "/resolve"),
                  ("GET", "/api/v1/operator/apps/" + app_id + "/catalog-origin"),
                  ("POST", "/api/v1/operator/apps/" + app_id + "/catalog-origin/switch-preview"),
                  ("POST", "/api/v1/apps/" + app_id + "/updates/rollback")}
        routes.add(("POST", "/api/v1/apps/" + app_id + "/updates/check"))
        if self.role == "catalog-origin-staged-negative":
            routes.add(("POST", "/api/v1/apps/install"))
        for subject in [*self.metadata["subjects"].values(), *self.metadata.get("negatives", {}).values(), *self.metadata.get("equivalents", {}).values()]:
            catalog_id = subject["catalogId"]
            base = "/api/v1/app-catalogs/" + catalog_id
            routes.update({("POST", base + "/refresh"), ("POST", base + "/mirrors"),
                           ("DELETE", base), ("GET", base + "/operations/health"),
                           ("GET", base + "/operations/revisions"),
                           ("POST", base + "/apps/" + app_id + "/install"),
                           ("POST", base + "/apps/" + app_id + "/update"),
                           *( ("POST", "/api/v1/operator/catalog-federation/" + catalog_id + "/" + action)
                              for action in ("trust", "suspend", "revoke", "remove", "publisher-scope-revoke", "reviewer-scope-revoke"))})
        return (method, path) in routes

    def catalog_principal_probe_allowed(self, role, app_id, method, path):
        return ((role, app_id, method) == (self.role, self.app_id, "POST")
                and path in {"/api/v1/operator/apps/" + app_id + "/catalog-origin/switch-preview",
                             "/api/v1/operator/catalog-federation/" + self.metadata["subjects"]["B3"]["catalogId"] + "/trust"})

    def request(self, method, path, parameters=None, *, principal="host"):
        if self.node is None or self.node.process.poll() is not None:
            raise LifecycleFailure("catalog-owned-daemon-not-running")
        operation = None
        if method != "GET":
            operation = {"operation": len(self.transport.value["operations"]) + 1, "method": method,
                         "route": path, "principal": principal, "requestDigest": digest(parameters or {}), "status": "started"}
            self.transport.value["operations"].append(operation)
            self.transport.save()
        status, response = self.handle.request(method, path, parameters, principal=principal)
        if operation is not None:
            operation.update(status="response-observed", httpStatus=status, responseDigest=digest(response))
            self.transport.save()
        if self.suppress_install_response and method == "POST" and path.endswith("/apps/" + self.app_id + "/install") and status == 201:
            self.suppress_install_response = False
            operation["status"] = "owned-client-response-suppressed"
            self.transport.save()
            raise runtime.RuntimeFailure("catalog-owned-injected-response-loss")
        return status, response

    def ok(self, method, path, parameters=None):
        status, value = self.request(method, path, parameters)
        if status not in {200, 201}:
            raise LifecycleFailure("catalog-owned-native-request-denied")
        return value

    def start(self):
        self.remaining(1)
        if self.node is not None and self.node.process.poll() is None:
            raise LifecycleFailure("catalog-owned-daemon-already-running")
        args = ["--config-file", str(self.node_root / "config/cryptad.ini")]
        for option in ("config", "data", "cache", "run", "logs"):
            args += ["--" + option + "-dir", str(self.node_root / option)]
        command = [str(self.distribution / "bin/cryptad")]
        command += [f"wrapper.app.parameter.{index}={value}" for index, value in enumerate(args, 1)]
        # Existing opt-in JVM configuration, scoped to this owned process. No global settings.
        command.append("wrapper.java.additional.10=-Dcryptad.appCatalogFederationEnabled=true")
        environment = {"PATH": str(self.java / "bin") + ":/usr/bin:/bin", "JAVA_HOME": str(self.java),
                       "HOME": str(self.node_root), "LANG": "C.UTF-8",
                       "CRYPTAD_APPHOST_TRUSTED_KEYS_FILE": str(self.registry_paths["publisher"]),
                       "CRYPTAD_APPCATALOG_TRUSTED_KEYS_FILE": str(self.registry_paths["catalog"]),
                       "CRYPTAD_APPREVIEW_TRUSTED_REVIEWER_KEYS_FILE": str(self.registry_paths["reviewer"])}
        if os.geteuid() == 0:
            environment["CRYPTAD_ALLOW_ROOT"] = "1"
        stdout_path, stderr_path = self.node_root / "logs/stdout.log", self.node_root / "logs/stderr.log"
        stdout, stderr = stdout_path.open("ab"), stderr_path.open("ab")
        intent = {"operation": len(self.transport.value["operations"]) + 1, "kind": "daemon-start",
                  "configDigest": runtime.digest_file(self.node_root / "config/cryptad.ini"), "status": "started"}
        self.transport.value["operations"].append(intent)
        self.transport.save()
        try:
            process = subprocess.Popen(command, cwd=self.node_root, env=environment, stdout=stdout,
                                       stderr=stderr, start_new_session=True)
        except BaseException:
            stdout.close()
            stderr.close()
            raise
        self.node = runtime.interop.NodeRuntime(self.role, self.node_root,
            self.node_root / "config/cryptad.ini", stdout_path, stderr_path, process, stdout, stderr)
        epoch = {"supervisor": runtime.process_identity(process.pid)}
        self.epochs.append(epoch)
        runtime.interop.wait_for_fcp("127.0.0.1", self.ports.cryptad_fcp, self.remaining(170), [self.node])
        while True:
            try:
                self.handle.host_bootstrap()
                break
            except runtime.RuntimeFailure:
                self.remaining(1)
                if process.poll() is not None:
                    raise LifecycleFailure("catalog-owned-daemon-start-failed") from None
                time.sleep(0.25)
        java_digest = runtime.digest_file(self.java / "bin/java")
        descendants = []
        for entry in Path("/proc").iterdir():
            if not entry.name.isdigit():
                continue
            try:
                cursor = int(entry.name)
                for _ in range(64):
                    if cursor == process.pid:
                        identity = runtime.process_identity(int(entry.name))
                        if identity["executableDigest"] == java_digest:
                            descendants.append(identity)
                        break
                    if cursor <= 1:
                        break
                    fields = (Path("/proc") / str(cursor) / "stat").read_text().rsplit(")", 1)[1].split()
                    cursor = int(fields[1])
            except (OSError, ValueError):
                continue
        if len(descendants) != 1:
            raise LifecycleFailure("catalog-owned-java-identity-not-observed")
        epoch["jvm"] = descendants[0]
        intent.update(status="complete", epochDigest=digest(epoch))
        self.transport.save()

    def stop(self):
        if self.node is not None:
            node = self.node
            intent = {"operation": len(self.transport.value["operations"]) + 1,
                      "kind": "daemon-stop", "status": "started",
                      "epochDigest": digest(self.epochs[-1]) if self.epochs else None}
            self.transport.value["operations"].append(intent)
            try:
                self.transport.save()
            finally:
                # A failed journal write must never prevent cleanup of the process we own.
                runtime.interop.terminate_node(node)
                self.node = None
            intent.update(status="complete", exitCode=node.process.poll())
            self.transport.save()

    def restart(self):
        self.stop()
        self.start()

    def observe(self, app_id):
        if app_id != self.app_id:
            raise LifecycleFailure("catalog-owned-app-not-selected")
        installed = self.node_root / "data/node/apps/installed" / app_id
        status, origin = self.request("GET", "/api/v1/operator/apps/" + app_id + "/catalog-origin")
        if status == 404 and not installed.exists():
            return None
        if status != 200 or not installed.is_dir():
            raise LifecycleFailure("catalog-owned-origin-missing")
        path = self.node_root / "data/node/apps/catalog-origins" / (app_id + ".properties")
        if path.is_symlink() or path.stat().st_size > 65536 or "schemaVersion=2\n" not in path.read_text():
            raise LifecycleFailure("catalog-owned-origin-v2-required")
        retained = self.retained_revision(origin)
        return {"appId": origin["appId"], "appVersion": origin["appVersion"], "catalogId": origin["catalogId"],
                "bundleDigest": "sha256:" + origin["bundleSha256"],
                "publisherFingerprint": "sha256:" + origin["publisherKeyFingerprintSha256"],
                "signedContentDigest": "sha256:" + origin["signedContentDigestSha256"],
                "installedTreeDigest": installed_content_tree(installed),
                "originSchemaVersion": 2, "originDigest": "sha256:" + origin["selfDigestSha256"],
                "originFileDigest": runtime.digest_file(path),
                "catalogContentDigest": "sha256:" + origin["catalogRevisionDigestSha256"],
                "catalogRevisionDigest": retained["revisionDigest"],
                "retainedCatalogRevision": dict(retained),
                "catalogSignerFingerprint": "sha256:" + origin["catalogSignerFingerprintSha256"],
                "catalogKeyId": origin["catalogSignerKeyId"],
                "reviewDigest": "sha256:" + origin["reviewReceiptFingerprintSha256"],
                "publisherBindingDigest": "sha256:" + origin["publisherPolicyDigestSha256"],
                "reviewerPolicyDigest": "sha256:" + origin["reviewerPolicyDigestSha256"],
                "catalogTrustBindingDigest": "sha256:" + origin["catalogTrustBindingDigestSha256"]}

    def retained_revision(self, origin):
        catalog_base = "/api/v1/app-catalogs/" + origin["catalogId"]
        origin_digest = origin["selfDigestSha256"]
        retained = self.observed_revisions.get(origin_digest)
        if retained is None:
            health = self.ok("GET", catalog_base + "/operations/health")["health"]
            retained = {"revisionDigest": "sha256:" + raw_digest(health["catalogDigest"]),
                        "signatureKeyId": health["signatureKeyId"]}
        history = self.ok("GET", catalog_base + "/operations/revisions")["revisions"]
        matches = [row["revision"] for row in history["revisions"]
                   if "sha256:" + raw_digest(row["revision"]["revisionDigest"]) == retained["revisionDigest"]
                   and row["revision"]["signatureKeyId"] == retained["signatureKeyId"]]
        if (history["catalogId"] != origin["catalogId"] or len(matches) != 1
                or retained["signatureKeyId"] != origin["catalogSignerKeyId"]):
            raise LifecycleFailure("catalog-owned-retained-revision-not-observed")
        self.observed_revisions[origin_digest] = retained
        return retained

    def approve_catalog(self, subject):
        policy = self.policies[subject["catalogId"]]
        binding = self.ok("POST", "/api/v1/operator/catalog-federation/" + subject["catalogId"] + "/trust",
                {"bindingId": "pr305-" + subject["catalogId"], "signerKeyId": subject["catalogSignerKeyId"],
                 "signerFingerprintSha256": raw_digest(subject["catalogSignerFingerprint"]),
                 "channels": "stable", "localPriority": "1", "reason": "synthetic-reviewed-cohort",
                 "publisherPolicyDigestSha256": policy["publisherPolicyDigestSha256"],
                 "reviewerPolicyDigestSha256": policy["reviewerPolicyDigestSha256"]})
        if (binding.get("status") != "active" or binding.get("publisherPolicyDigest") != policy["publisherPolicyDigestSha256"]
                or binding.get("reviewerPolicyDigest") != policy["reviewerPolicyDigestSha256"]
                or binding.get("signerKeyIds") != [subject["catalogSignerKeyId"]]
                or binding.get("signerFingerprints") != [raw_digest(subject["catalogSignerFingerprint"])]) :
            raise LifecycleFailure("catalog-owned-role-activation-mismatch")
        self.activations.append({"role": self.role, "sequence": len(self.activations) + 1,
                                 "daemonEpochDigest": digest(self.epochs[-1]), "binding": binding,
                                 "authorityScope": "fresh-role-local-operator-activation"})

    def select_revision(self, name):
        if name == "update":
            self.server.selected = "update"
            self.ok("POST", "/api/v1/app-catalogs/" + self.metadata["subjects"]["A1"]["catalogId"] + "/refresh")
        elif name == "switch":
            subject = self.metadata["subjects"]["B3"]
            catalogs = self.ok("GET", "/api/v1/app-catalogs")["catalogs"]
            if subject["catalogId"] not in {row["catalogId"] for row in catalogs}:
                self.approve_catalog(subject)
                equivalent = self.metadata["equivalents"]["E2"]
                before_equivalent = self.observe(self.app_id)
                if equivalent["bundleDigest"] != before_equivalent["bundleDigest"]:
                    raise LifecycleFailure("catalog-owned-equivalent-bytes-substituted")
                self.server.alternate_selected = "equivalent"
                self.ok("POST", "/api/v1/app-catalogs/add", {"source": self.server.uri("alternate"),
                                                          "expectedCatalogId": subject["catalogId"]})
                equivalent_candidate = self.ok("POST", "/api/v1/apps/" + self.app_id + "/updates/check")["updates"]["candidate"]
                if (self.observe(self.app_id) != before_equivalent
                        or equivalent_candidate.get("catalogId") != before_equivalent["catalogId"]
                        or equivalent_candidate.get("status") != "none"):
                    raise LifecycleFailure("catalog-owned-equivalent-origin-changed")
                self.authority_observations["exactEquivalentSource"] = {
                    "candidate": equivalent_candidate, "equivalentBundleDigest": equivalent["bundleDigest"],
                    "beforeOrigin": before_equivalent, "afterOrigin": self.observe(self.app_id)}
                self.server.alternate_selected = "switch"
                self.ok("POST", "/api/v1/app-catalogs/" + subject["catalogId"] + "/refresh")
                before = self.observe(self.app_id)
                candidate = self.ok("POST", "/api/v1/apps/" + self.app_id + "/updates/check")["updates"]["candidate"]
                if (before["catalogId"] != self.metadata["subjects"]["A2"]["catalogId"]
                        or self.observe(self.app_id) != before or candidate.get("status") != "blocked"):
                    raise LifecycleFailure("catalog-owned-competing-newer-source-not-blocked")
                self.authority_observations["competingNewerRoutineCheck"] = {
                    "candidate": candidate, "beforeOrigin": before, "afterOrigin": self.observe(self.app_id)}
        else:
            raise LifecycleFailure("catalog-owned-unplanned-revision")

    def resolve_switch_conflict(self, subject_key="B3"):
        if subject_key not in {"B3", "B4"}:
            raise LifecycleFailure("catalog-owned-unplanned-conflict-resolution")
        path = "/api/v1/operator/catalog-federation/conflicts/" + self.app_id
        state = self.ok("GET", path)
        expected = {(self.metadata["subjects"][key]["catalogId"],
                     raw_digest(self.metadata["subjects"][key]["bundleDigest"])) for key in ("A2", subject_key)}
        actual = {(row["catalogId"], row["bundleDigestSha256"]) for row in state["subjects"]}
        if (state["hard"] is not False or actual != expected
                or not set(state["types"]) <= {"competing_versions", "reviewer_policy_disagreement", "metadata_disagreement"}):
            raise LifecycleFailure("catalog-owned-hard-conflict-not-switchable")
        intent = {"conflictId": state["conflictId"], "subjectSetDigestSha256": state["subjectSetDigestSha256"],
                  "kind": "explicit_source_switch_required", "reason": "synthetic-reviewed-exact-switch"}
        checkpoint = self.root / ("switch-resolution-intent.json" if subject_key == "B3" else "revision-resolution-intent.json")
        if checkpoint.exists():
            if json.loads(checkpoint.read_bytes()) != intent:
                raise LifecycleFailure("catalog-owned-stale-conflict-resolution")
        else:
            with checkpoint.open("x") as stream:
                json.dump(intent, stream, sort_keys=True)
                stream.flush()
                os.fsync(stream.fileno())
            checkpoint.chmod(0o600)
        self.ok("POST", path + "/resolve", intent)
        after = self.ok("GET", path)
        if after["subjectSetDigestSha256"] != state["subjectSetDigestSha256"] or after.get("resolution", {}).get("kind") != "explicit_source_switch_required":
            raise LifecycleFailure("catalog-owned-conflict-resolution-not-observed")

    def mirror_cases(self):
        catalog_id = self.metadata["subjects"]["A1"]["catalogId"]
        base = "/api/v1/app-catalogs/" + catalog_id
        self.ok("POST", base + "/mirrors", {"source": self.server.uri("mirror"),
                "mirrorId": "pr305-owned-mirror", "priority": "1", "enabled": "true"})
        records = {}
        for name, available, mode, source, successful in (
                ("exactFallback", False, "exact", "mirror", True),
                ("mismatchedSignature", False, "mismatch", "mirror", False),
                ("staleCatalog", False, "stale", "mirror", False),
                ("primaryRecovery", True, "exact", "primary", True)):
            self.server.primary_available, self.server.mirror_mode = available, mode
            before = self.server.counts()
            origin = self.observe(self.app_id)
            prior_health = self.ok("GET", base + "/operations/health")["health"]
            status, response = self.request("POST", base + "/refresh")
            after = self.server.require_fetched(source, before)
            observed = self.observe(self.app_id)
            health = self.ok("GET", base + "/operations/health")["health"]
            identity_fields = ("catalogDigest", "signatureKeyId")
            if ((status in {200, 201}) != successful or observed != origin
                    or any(health.get(field) != prior_health.get(field) for field in identity_fields)):
                raise LifecycleFailure("catalog-mirror-native-postcondition-failed")
            records[name] = {"beforeRequests": before, "afterRequests": after, "httpStatus": status,
                             "errorCode": response.get("error", {}).get("code"),
                             "beforeOrigin": origin, "afterOrigin": observed,
                             "beforeCatalog": {key: prior_health.get(key) for key in identity_fields},
                             "afterCatalog": {key: health.get(key) for key in identity_fields},
                             "primaryAvailable": available, "mirrorMode": mode}
        return records

    def source_security_cases(self):
        before = self.observe(self.app_id)
        path = "/api/v1/operator/catalog-federation/conflicts/" + self.app_id
        conflict_before = self.ok("GET", path)
        untrusted = self.metadata["negatives"]["U"]
        status, response = self.request("POST", "/api/v1/app-catalogs/add", {
            "source": self.server.uri("untrusted"), "expectedCatalogId": untrusted["catalogId"]})
        conflict_after = self.ok("GET", path)
        if (status != 400 or response.get("error", {}).get("code") != "invalid_catalog_signature"
                or conflict_after["subjectSetDigestSha256"] != conflict_before["subjectSetDigestSha256"]
                or self.observe(self.app_id) != before):
            raise LifecycleFailure("catalog-owned-untrusted-source-poisoned-selection")
        unknown = {"httpStatus": status, "errorCode": response["error"]["code"],
                   "beforeConflict": conflict_before, "afterConflict": conflict_after,
                   "beforeOrigin": before, "afterOrigin": self.observe(self.app_id)}
        deny = self.metadata["negatives"]["DENY"]
        self.approve_catalog(deny)
        self.ok("POST", "/api/v1/app-catalogs/add", {
            "source": self.server.uri("deny"), "expectedCatalogId": deny["catalogId"]})
        conflict = self.ok("GET", path)
        if not conflict["hard"] or "security_policy_disagreement" not in conflict["types"]:
            raise LifecycleFailure("catalog-owned-security-conflict-not-classified")
        status, response = self.request("POST", path + "/resolve", {
            "conflictId": conflict["conflictId"], "subjectSetDigestSha256": conflict["subjectSetDigestSha256"],
            "kind": "prefer_catalog", "catalogId": before["catalogId"], "reason": "synthetic-denylist-preference-negative"})
        candidate = self.ok("POST", "/api/v1/apps/" + self.app_id + "/updates/check")["updates"]["candidate"]
        if (status not in {200, 201, 400, 409} or candidate.get("status") != "blocked"
                or self.observe(self.app_id) != before):
            raise LifecycleFailure("catalog-owned-preference-bypassed-denylist")
        self.ok("DELETE", "/api/v1/app-catalogs/" + deny["catalogId"])
        return {"untrustedSource": unknown, "denylistPreference": {
            "conflict": conflict, "httpStatus": status, "errorCode": response.get("error", {}).get("code"),
            "candidate": candidate, "beforeOrigin": before, "afterOrigin": self.observe(self.app_id)}}

    def conflict_channel_cases(self):
        """Isolate the hard conflict, then exercise a stable-only binding against a beta entry."""
        selected = self.metadata.get("negatives", {})
        if set(selected) != {"C2", "BETA", "P2", "U", "DENY"}:
            raise LifecycleFailure("catalog-owned-negative-cohort-incomplete")
        before = self.observe(self.app_id)
        conflict_path = "/api/v1/operator/catalog-federation/conflicts/" + self.app_id
        original = self.ok("GET", conflict_path)
        c2 = selected["C2"]
        self.approve_catalog(c2)
        self.ok("POST", "/api/v1/app-catalogs/add", {"source": self.server.uri("conflict"),
                                                   "expectedCatalogId": c2["catalogId"]})
        state = self.ok("GET", conflict_path)
        if state["hard"] is not True or "same_version_payload_conflict" not in state["types"]:
            raise LifecycleFailure("catalog-owned-hard-conflict-not-classified")
        routine = self.ok("POST", "/api/v1/apps/" + self.app_id + "/updates/check")["updates"]
        if routine.get("candidate", {}).get("status") != "blocked":
            raise LifecycleFailure("catalog-owned-hard-conflict-not-blocking-routine-update")
        status, response = self.request("POST", conflict_path + "/resolve", {
            "conflictId": original["conflictId"], "subjectSetDigestSha256": original["subjectSetDigestSha256"],
            "kind": "explicit_source_switch_required", "reason": "synthetic-stale-selection-negative"})
        if status in {200, 201} or self.observe(self.app_id) != before:
            raise LifecycleFailure("catalog-owned-stale-resolution-accepted")
        stale_resolution = {"httpStatus": status, "errorCode": response.get("error", {}).get("code"),
                            "beforeOrigin": before, "afterOrigin": self.observe(self.app_id),
                            "originalSubjectSetDigest": original["subjectSetDigestSha256"],
                            "currentSubjectSetDigest": state["subjectSetDigestSha256"]}
        self.ok("DELETE", "/api/v1/app-catalogs/" + c2["catalogId"])
        if self.ok("GET", conflict_path)["hard"] is not False:
            raise LifecycleFailure("catalog-owned-conflict-isolation-cleanup-failed")
        publisher = selected["P2"]
        self.approve_catalog(publisher)
        self.ok("POST", "/api/v1/app-catalogs/add", {"source": self.server.uri("publisher"),
                                                   "expectedCatalogId": publisher["catalogId"]})
        publisher_conflict = self.ok("GET", conflict_path)
        if publisher_conflict["hard"] is not True or "publisher_namespace_conflict" not in publisher_conflict["types"]:
            raise LifecycleFailure("catalog-owned-publisher-conflict-not-classified")
        publisher_routine = self.ok("POST", "/api/v1/apps/" + self.app_id + "/updates/check")["updates"]
        if publisher_routine.get("candidate", {}).get("status") != "blocked" or self.observe(self.app_id) != before:
            raise LifecycleFailure("catalog-owned-publisher-conflict-not-blocking")
        self.ok("DELETE", "/api/v1/app-catalogs/" + publisher["catalogId"])
        beta = selected["BETA"]
        self.approve_catalog(beta)
        status, response = self.request("POST", "/api/v1/app-catalogs/add", {
            "source": self.server.uri("beta"), "expectedCatalogId": beta["catalogId"]})
        if status in {200, 201}:
            status, response = self.request("GET", "/api/v1/consent/catalog-update-preview",
                                            {"appId": self.app_id, "catalogId": beta["catalogId"]})
            if status in {200, 201}:
                preview = response["consent"]
                consent = {"consentRequestId": preview["consentRequestId"], "snapshotDigest": preview["snapshotDigest"]}
                self.ok("POST", "/api/v1/consent/approve", consent)
                status, response = self.request("POST", "/api/v1/app-catalogs/" + beta["catalogId"] + "/apps/" + self.app_id + "/update", consent)
            self.ok("DELETE", "/api/v1/app-catalogs/" + beta["catalogId"])
        if (status != 400 or response.get("error", {}).get("code") != "invalid_catalog_signature"
                or self.observe(self.app_id) != before):
            raise LifecycleFailure("catalog-owned-stable-channel-escape")
        # Source removal must leave the two unrelated approved catalogs readable and origin intact.
        present = {row["catalogId"] for row in self.ok("GET", "/api/v1/app-catalogs")["catalogs"]}
        if present != {self.metadata["subjects"][key]["catalogId"] for key in ("A1", "B3")}:
            raise LifecycleFailure("catalog-owned-source-removal-contaminated-other-catalog")
        return {"sameVersionPayloadConflict": state, "sameVersionRoutineCandidate": routine["candidate"],
                "publisherConflict": publisher_conflict, "publisherRoutineCandidate": publisher_routine["candidate"],
                "staleResolution": stale_resolution,
                "stableOnlyChannel": {"httpStatus": status, "errorCode": response.get("error", {}).get("code"),
                                      "beforeOrigin": before, "afterOrigin": self.observe(self.app_id)},
                "unrelatedCatalogs": sorted(present), "beforeOrigin": before, "afterOrigin": self.observe(self.app_id)}

    def principal_cases(self):
        before = self.observe(self.app_id)
        bootstrap = self.ok("GET", "/apps/" + self.app_id + "/.well-known/cryptad-bootstrap.json")
        if bootstrap.get("uiOriginMode") == "same-origin-fallback" and bootstrap.get("uiOrigin") is None:
            self.handle.origin = self.handle.base
        else:
            self.handle.origin = runtime.mail_demo.target(bootstrap.get("uiOrigin"))
        self.handle.session = bootstrap.get("browserSessionToken")
        if not isinstance(self.handle.session, str) or not 1 <= len(self.handle.session) <= 4096:
            raise LifecycleFailure("catalog-owned-app-session-unavailable")
        target = self.metadata["subjects"]["B3"]["catalogId"]
        records = []
        for path in ("/api/v1/operator/apps/" + self.app_id + "/catalog-origin/switch-preview",
                     "/api/v1/operator/catalog-federation/" + target + "/trust"):
            status, response = self.request("POST", path, {"targetCatalogId": target}, principal="app")
            if status != 403 or response.get("error", {}).get("code") not in {"forbidden", "host_operator_required"}:
                raise LifecycleFailure("catalog-owned-app-principal-not-denied")
            records.append({"operation": "source-switch-preview" if path.endswith("switch-preview") else "trust",
                            "httpStatus": status, "errorCode": response["error"]["code"]})
        if self.observe(self.app_id) != before:
            raise LifecycleFailure("catalog-owned-app-principal-mutated-origin")
        return {"originMode": bootstrap["uiOriginMode"], "requests": records,
                "beforeOrigin": before, "afterOrigin": self.observe(self.app_id)}

    def before_rollback(self):
        before = self.observe(self.app_id)
        candidate = self.ok("POST", "/api/v1/apps/" + self.app_id + "/updates/check")["updates"]["candidate"]
        same_origin = (candidate.get("catalogId") == before["catalogId"]
                       and candidate.get("bundle", {}).get("sha256") == raw_digest(before["bundleDigest"]))
        conflict_blocked = (candidate.get("status") == "blocked"
                            and candidate.get("policyBlockReason") == "unresolved_cross_catalog_conflict")
        if (not ((same_origin and candidate.get("status") == "none") or conflict_blocked)
                or self.observe(self.app_id) != before):
            raise LifecycleFailure("catalog-owned-switched-origin-routine-policy-invalid")
        self.authority_observations["switchedOriginRoutineCheck"] = {
            "candidate": candidate, "beforeOrigin": before, "afterOrigin": self.observe(self.app_id),
            "disposition": "conflict-blocked" if conflict_blocked else "same-origin-no-update"}
        self.expected_rollback_target = before

    def after_rollback(self):
        pass

    def suspended_rollback_roundtrip(self, before):
        target = self.expected_rollback_target
        binding = self.ok("POST", "/api/v1/operator/catalog-federation/" + target["catalogId"] + "/suspend",
                          {"reason": "synthetic-exact-historical-rollback"})
        if binding.get("status") != "suspended" or self.observe(self.app_id) != before:
            raise LifecycleFailure("catalog-owned-suspension-mutated-app")
        def subject(value):
            return Subject(value["appId"], value["catalogId"], value["bundleDigest"],
                           value["installedTreeDigest"], value["signedContentDigest"],
                           value["publisherFingerprint"], value["appVersion"])
        journal = Journal(self.root / "suspended-rollback-operations.json", digest([before, target]))
        for name, current, desired in (("suspended-historical-rollback", before, target),
                                       ("active-return-rollback", target, before)):
            restored = journal.transition(name, subject(current), subject(desired),
                lambda: self.observe(self.app_id),
                lambda: self.ok("POST", "/api/v1/apps/" + self.app_id + "/updates/rollback"))
            if restored != desired:
                raise LifecycleFailure("catalog-owned-suspended-rollback-origin-substituted")
        self.authority_observations["suspendedRollbackRoundtrip"] = {
            "binding": binding, "operations": journal.value["operations"],
            "beforeOrigin": before, "afterOrigin": self.observe(self.app_id)}

    def retained_rollback_target(self):
        expected = self.expected_rollback_target
        root = self.node_root / "data/node/apps"
        bundle = root / "rollback" / self.app_id
        origin = root / "catalog-origins/rollback" / (self.app_id + ".properties")
        if (not bundle.is_dir() or origin.is_symlink() or not origin.is_file()
                or runtime.digest_file(origin) != expected["originFileDigest"]
                or installed_content_tree(bundle) != expected["installedTreeDigest"]):
            raise LifecycleFailure("catalog-owned-retained-rollback-substituted")
        return expected

    def update_consent(self, target):
        response = self.ok("GET", "/api/v1/consent/catalog-update-preview",
                           {"appId": self.app_id, "catalogId": target})["consent"]
        parameters = {"consentRequestId": response["consentRequestId"],
                      "snapshotDigest": response["snapshotDigest"]}
        self.ok("POST", "/api/v1/consent/approve", parameters)
        return parameters

    def rollback_authority_cases(self):
        before = self.observe(self.app_id)
        target = self.metadata["subjects"]["B3"]["catalogId"]
        preview = self.ok("POST", "/api/v1/operator/apps/" + self.app_id + "/catalog-origin/switch-preview",
                          {"targetCatalogId": target})
        retained = self.retained_rollback_target()
        consent = self.update_consent(target)
        self.suspended_rollback_roundtrip(before)
        # Revocation is terminal; removal must be observed before final revocation.
        for action in ("remove", "revoke"):
            binding = self.ok("POST", "/api/v1/operator/catalog-federation/" + target + "/" + action,
                              {"reason": "synthetic-executable-rollback-denial"})
            status, response = self.request("POST", "/api/v1/apps/" + self.app_id + "/updates/rollback")
            after = self.observe(self.app_id)
            if status != 409 or response.get("error", {}).get("code") != "catalog_rollback_trust_blocked" or after != before:
                raise LifecycleFailure("catalog-owned-revoked-rollback-not-denied")
            self.authority_observations[action + "Rollback"] = {
                "binding": binding, "retainedTarget": retained, "httpStatus": status, "errorCode": response.get("error", {}).get("code"),
                "beforeOrigin": before, "afterOrigin": after}
            if action == "revoke":
                status, response = self.request("POST", "/api/v1/app-catalogs/" + target + "/apps/" + self.app_id + "/update",
                    {**consent, "sourceSwitchConsent": preview["consentDigestSha256"], "targetCatalogId": target})
                if status not in {400, 409} or self.observe(self.app_id) != before:
                    raise LifecycleFailure("catalog-owned-revoked-preview-not-denied")
                self.authority_observations["revokedPreview"] = {"httpStatus": status,
                    "errorCode": response.get("error", {}).get("code"), "beforeOrigin": before,
                    "afterOrigin": self.observe(self.app_id)}
        remaining = self.ok("GET", "/api/v1/app-catalogs")["catalogs"]
        if {row["catalogId"] for row in remaining} != {before["catalogId"]}:
            raise LifecycleFailure("catalog-owned-revocation-disabled-unrelated-origin")
        return self.authority_observations

    def current_origin_trust_removal(self):
        """Observe terminal current-source trust changes without uninstalling its app."""
        before = self.observe(self.app_id)
        unrelated = self.metadata["subjects"]["A2"]
        current = self.metadata["subjects"]["B4"]
        if before["catalogId"] != current["catalogId"] or before["bundleDigest"] != current["bundleDigest"]:
            raise LifecycleFailure("catalog-owned-current-origin-removal-subject-invalid")
        self.server.selected = "update"
        self.ok("POST", "/api/v1/app-catalogs/add", {"source": self.server.uri("primary"),
                                                    "expectedCatalogId": unrelated["catalogId"]})
        if self.observe(self.app_id) != before:
            raise LifecycleFailure("catalog-owned-unrelated-registration-mutated-origin")
        base = "/api/v1/app-catalogs/" + unrelated["catalogId"]
        approved_health = self.ok("GET", base + "/operations/health")["health"]
        records = []
        for action, status in (("remove", "removed"), ("revoke", "revoked")):
            binding = self.ok("POST", "/api/v1/operator/catalog-federation/" + current["catalogId"] + "/" + action,
                              {"reason": "synthetic-current-origin-preservation"})
            requests = self.server.counts()
            refresh_status, _ = self.request("POST", base + "/refresh")
            after_requests = self.server.require_fetched("primary", requests)
            health = self.ok("GET", base + "/operations/health")["health"]
            after = self.observe(self.app_id)
            if (binding.get("catalogId") != current["catalogId"] or binding.get("status") != status
                    or refresh_status != 200 or after != before
                    or health["signatureKeyId"] != unrelated["catalogSignerKeyId"]
                    or health["catalogDigest"] != approved_health["catalogDigest"]):
                raise LifecycleFailure("catalog-owned-current-origin-removal-mutated-app")
            records.append({"action": action, "binding": binding, "beforeOrigin": before, "afterOrigin": after,
                            "refreshHttpStatus": refresh_status, "beforeRequests": requests, "afterRequests": after_requests,
                            "unrelatedCatalog": {"catalogId": unrelated["catalogId"],
                                "catalogDigest": "sha256:" + raw_digest(health["catalogDigest"]),
                                "signatureKeyId": health["signatureKeyId"]}})
        return {"beforeOrigin": before, "cases": records}

    def select_registry(self, role, revoked):
        if role not in {"publisher", "reviewer"}:
            raise LifecycleFailure("catalog-owned-registry-role-invalid")
        source = self.fixture_root / (role + "-keys" + ("-revoked" if revoked else "") + ".properties")
        if source.is_symlink() or not source.is_file() or source.stat().st_size > 1024 * 1024:
            raise LifecycleFailure("catalog-owned-registry-selection-invalid")
        if revoked and runtime.digest_file(source) != self.metadata.get("registryVariants", {}).get(role):
            raise LifecycleFailure("catalog-owned-registry-variant-substituted")
        target = self.registry_paths[role]
        intent = {"operation": len(self.transport.value["operations"]) + 1, "kind": "registry-selection",
                  "role": role, "revoked": revoked, "beforeDigest": runtime.digest_file(target),
                  "selectedDigest": runtime.digest_file(source), "status": "started"}
        self.transport.value["operations"].append(intent)
        self.transport.save()
        temporary = target.with_suffix(".pending")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(source.read_bytes())
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
        if runtime.digest_file(target) != intent["selectedDigest"]:
            raise LifecycleFailure("catalog-owned-registry-selection-substituted")
        intent["status"] = "complete"
        self.transport.save()
        return intent["selectedDigest"]

    def local_scope_revocation_case(self, kind):
        if kind not in {"publisher", "reviewer"}:
            raise LifecycleFailure("catalog-owned-scope-kind-invalid")
        before = self.observe(self.app_id)
        target = self.metadata["subjects"]["B3"]["catalogId"]
        retained = self.retained_rollback_target()
        preview = self.ok("POST", "/api/v1/operator/apps/" + self.app_id + "/catalog-origin/switch-preview",
                          {"targetCatalogId": target})
        consent = self.update_consent(target)
        revision_invalidation = None
        if kind == "publisher":
            old_preview = preview
            before_health = self.ok("GET", "/api/v1/app-catalogs/" + target + "/operations/health")["health"]
            self.server.alternate_selected = "originUpdate"
            self.ok("POST", "/api/v1/app-catalogs/" + target + "/refresh")
            self.resolve_switch_conflict("B4")
            consent = self.update_consent(target)
            denied_status, denied = self.request("POST", "/api/v1/app-catalogs/" + target + "/apps/" + self.app_id + "/update",
                {**consent, "sourceSwitchConsent": old_preview["consentDigestSha256"], "targetCatalogId": target})
            after_denial = self.observe(self.app_id)
            after_health = self.ok("GET", "/api/v1/app-catalogs/" + target + "/operations/health")["health"]
            preview = self.ok("POST", "/api/v1/operator/apps/" + self.app_id + "/catalog-origin/switch-preview",
                              {"targetCatalogId": target})
            if (denied_status != 409 or denied.get("error", {}).get("code") != "catalog_source_switch_consent_required"
                    or after_denial != before or old_preview["consentDigestSha256"] == preview["consentDigestSha256"]
                    or before_health["catalogDigest"] == after_health["catalogDigest"]
                    or preview["targetBundleSha256"] != raw_digest(self.metadata["subjects"]["B4"]["bundleDigest"])):
                raise LifecycleFailure("catalog-owned-revised-source-preview-accepted")
            revision_invalidation = {"httpStatus": denied_status, "errorCode": denied["error"]["code"],
                "beforeOrigin": before, "afterOrigin": after_denial,
                "beforeCatalogRevisionDigest": "sha256:" + raw_digest(before_health["catalogDigest"]),
                "afterCatalogRevisionDigest": "sha256:" + raw_digest(after_health["catalogDigest"]),
                "oldConsentDigest": old_preview["consentDigestSha256"], "newConsentDigest": preview["consentDigestSha256"],
                "targetBundleDigest": self.metadata["subjects"]["B4"]["bundleDigest"]}
            consent = self.update_consent(target)
        roster = self.fixture_root / "scoped-records.json"
        if roster.is_symlink() or not roster.is_file() or not 0 < roster.stat().st_size <= 65536:
            raise LifecycleFailure("catalog-owned-scope-roster-invalid")
        if runtime.digest_file(roster) != self.scope_roster_digest:
            raise LifecycleFailure("catalog-owned-scope-roster-substituted")
        records = json.loads(roster.read_bytes())
        if set(records) != {"schemaVersion", "publisher", "reviewer"} or records["schemaVersion"] != 1:
            raise LifecycleFailure("catalog-owned-scope-roster-invalid")
        expected = records[kind][target]
        binding = self.ok("POST", "/api/v1/operator/catalog-federation/" + target + "/" + kind + "-scope-revoke",
                          {"scopeId": expected["scopeId"], "expectedDigestSha256": expected["selfDigestSha256"],
                           "reason": "synthetic-exact-local-scope-revocation"})
        if (binding.get("status") != "revoked" or binding.get("previousDigestSha256") != expected["selfDigestSha256"]
                or binding.get("scopeId") != expected["scopeId"] or binding.get("catalogId") != target):
            raise LifecycleFailure("catalog-owned-scope-revocation-mismatch")
        status, response = self.request("POST", "/api/v1/apps/" + self.app_id + "/updates/rollback")
        switch_status, switch_response = self.request("POST", "/api/v1/app-catalogs/" + target + "/apps/" + self.app_id + "/update",
            {**consent, "sourceSwitchConsent": preview["consentDigestSha256"], "targetCatalogId": target})
        after = self.observe(self.app_id)
        expected_switch_codes = {"catalog_publisher_scope_rejected"} if kind == "publisher" else {
            "catalog_reviewer_scope_required", "app_review_untrusted"}
        if (status != 409 or response.get("error", {}).get("code") != "catalog_rollback_trust_blocked"
                or switch_status != 409 or switch_response.get("error", {}).get("code") not in expected_switch_codes
                or after != before):
            raise LifecycleFailure("catalog-owned-local-scope-not-revalidated")
        return {"scopeKind": kind, "retainedTarget": retained, "binding": binding,
                "revisionInvalidation": revision_invalidation,
                "rollbackHttpStatus": status, "rollbackErrorCode": response["error"]["code"],
                "switchHttpStatus": switch_status, "switchErrorCode": switch_response.get("error", {}).get("code"),
                "beforeOrigin": before, "afterOrigin": self.observe(self.app_id)}

    def scoped_revocation_cases(self):
        before = self.observe(self.app_id)
        target = self.metadata["subjects"]["B3"]["catalogId"]
        records = {}
        for role in ("publisher", "reviewer"):
            preview = self.ok("POST", "/api/v1/operator/apps/" + self.app_id + "/catalog-origin/switch-preview",
                              {"targetCatalogId": target})
            consent = self.update_consent(target)
            retained = self.retained_rollback_target()
            original_registry = runtime.digest_file(self.registry_paths[role])
            try:
                selected = self.select_registry(role, True)
                status, response = self.request("POST", "/api/v1/apps/" + self.app_id + "/updates/rollback")
                after = self.observe(self.app_id)
                expected_error = "rollback_bundle_verification_failed" if role == "publisher" else "catalog_rollback_trust_blocked"
                if status != 409 or response.get("error", {}).get("code") != expected_error or after != before:
                    raise LifecycleFailure("catalog-owned-revoked-key-rollback-not-denied")
                switch_status, switch_response = self.request("POST", "/api/v1/app-catalogs/" + target + "/apps/" + self.app_id + "/update",
                    {**consent, "sourceSwitchConsent": preview["consentDigestSha256"], "targetCatalogId": target})
                if switch_status not in {400, 409} or self.observe(self.app_id) != before:
                    raise LifecycleFailure("catalog-owned-revoked-key-preview-not-denied")
                records[role] = {"registryDigest": selected, "originalRegistryDigest": original_registry,
                                 "retainedTarget": retained, "rollbackHttpStatus": status,
                                 "rollbackErrorCode": response.get("error", {}).get("code"),
                                 "switchHttpStatus": switch_status,
                                 "switchErrorCode": switch_response.get("error", {}).get("code"),
                                 "beforeOrigin": before, "afterOrigin": after}
            finally:
                restored = self.select_registry(role, False)
            if restored != original_registry:
                raise LifecycleFailure("catalog-owned-registry-restoration-failed")
            records[role]["restoredRegistryDigest"] = restored
            restored_preview = self.ok("POST", "/api/v1/operator/apps/" + self.app_id + "/catalog-origin/switch-preview",
                                       {"targetCatalogId": target})
            records[role]["restoredPreviewDigest"] = restored_preview["consentDigestSha256"]
        return records


def execute(root, distribution, java, tool, fixture_root, *, source_commit, maximum_seconds=900,
            expected_projections=None):
    if type(maximum_seconds) is not int or not 30 <= maximum_seconds <= 1800:
        raise LifecycleFailure("catalog-owned-duration-budget-invalid")
    budget = {"operations": 0, "deadline": time.monotonic() + maximum_seconds}
    if root.exists() or root.is_symlink():
        raise LifecycleFailure("catalog-owned-existing-root-refused")
    root.mkdir(mode=0o700)
    java_environment = {"PATH": str(java / "bin") + ":/usr/bin:/bin", "JAVA_HOME": str(java),
                        "LANG": "C.UTF-8", "HOME": str(root)}
    manifest = fixture_root / "fixture.json"
    if manifest.is_symlink() or not manifest.is_file() or not 0 < manifest.stat().st_size <= 1024 * 1024:
        raise LifecycleFailure("catalog-owned-fixture-cohort-invalid")
    metadata = json.loads(manifest.read_bytes())
    if (not isinstance(metadata, dict) or set(metadata) != {
            "schemaVersion", "synthetic", "appId", "bootstrapManifestDigest", "subjects", "negatives", "registryVariants", "equivalents"}
            or type(metadata["schemaVersion"]) is not int or metadata["schemaVersion"] != 2
            or metadata["synthetic"] is not True or set(metadata["subjects"]) != {"A1", "A2", "B3", "B4"}
            or set(metadata["negatives"]) != {"C2", "BETA", "P2", "U", "DENY"}
            or set(metadata["equivalents"]) != {"E2"}
            or set(metadata["registryVariants"]) != {"publisher", "reviewer"}):
        raise LifecycleFailure("catalog-owned-fixture-cohort-invalid")
    if raw_digest(metadata["bootstrapManifestDigest"]) != raw_digest(runtime.digest_file(fixture_root / "bootstrap/bootstrap.properties")):
        raise LifecycleFailure("catalog-owned-bootstrap-manifest-substituted")
    runtime.packaged_daemon_identity(distribution, source_commit)
    exported = subprocess.run([str(java / "bin/java"), "-cp", str(distribution / "lib/*"),
        "network.crypta.platform.api.PackagedApiExport"], capture_output=True,
        timeout=remaining_budget(budget, 60), check=False,
        env=java_environment)
    if exported.returncode != 0 or len(exported.stdout) > 16 * 1024 * 1024:
        raise LifecycleFailure("catalog-owned-packaged-api-export-failed")
    contract = json.loads(exported.stdout)
    if contract.get("kind") != "packaged-platform-api-export" or contract.get("schemaVersion") != 1:
        raise LifecycleFailure("catalog-owned-packaged-api-export-invalid")
    (root / "contract.json").write_text(contract["contractSnapshot"])
    (root / "registry.json").write_text(contract["baselineRegistry"])
    class Preflight:
        def remaining(self, seconds):
            return remaining_budget(budget, min(seconds, 180))
    verifier = catalog.Tool(tool, catalog.tree_digest(tool), java, catalog.tree_digest(java), root)
    subjects = {}
    projections = {}
    for label, key in (("initial", "A1"), ("update", "A2"), ("switch", "B3"), ("originUpdate", "B4")):
        row = metadata["subjects"][key]
        source = fixture_root / key
        keys = [fixture_root / (name + "-keys.properties") for name in ("catalog", "publisher", "reviewer")]
        verified = catalog.verify_fixture(Preflight(), verifier, catalog.Fixture(
            source / "catalog.properties", source / "cryptad-app-catalog.signature", source / "bundle.zip",
            *keys, row["catalogSignerKeyId"], row["appId"], row["catalogId"], row["catalogDigest"],
            row["catalogSignatureDigest"], row["bundleDigest"], *(runtime.digest_file(path) for path in keys)),
            native_context={"contract": root / "contract.json", "registry": root / "registry.json",
                            "selection": fixture_root / "selections" / key / "selection.json", "generation": 7,
                            "submission": source / "submission.zip"})
        if (verified["appVersion"] != row["appVersion"]
                or verified["signedContentDigest"] != row["signedContentDigest"]
                or verified["publisherFingerprint"] != "sha256:" + raw_digest(row["publisherFingerprint"])):
            raise LifecycleFailure("catalog-owned-native-declaration-mismatch")
        projections[label] = verified
        staging = root / ("subject-" + label)
        runtime.extract_app_bundle(fixture_root / key / "bundle.zip", staging, row["bundleDigest"])
        subjects[label] = Subject(row["appId"], row["catalogId"], row["bundleDigest"],
            installed_content_tree(staging), row["signedContentDigest"],
            "sha256:" + raw_digest(row["publisherFingerprint"]), row["appVersion"])
    if expected_projections is not None and projections != expected_projections:
        raise LifecycleFailure("catalog-owned-original-projection-substitution")
    objects = {label: {"catalog": (fixture_root / key / "catalog.properties").read_bytes(),
                       "signature": (fixture_root / key / "cryptad-app-catalog.signature").read_bytes()}
               for label, key in (("initial", "A1"), ("update", "A2"), ("switch", "B3"), ("originUpdate", "B4"))}
    for label, key in (("conflict", "C2"), ("beta", "BETA"), ("publisher", "P2"), ("untrusted", "U"), ("deny", "DENY"), ("equivalent", "E2")):
        objects[label] = {"catalog": (fixture_root / key / "catalog.properties").read_bytes(),
                          "signature": (fixture_root / key / "cryptad-app-catalog.signature").read_bytes()}
    for label, key in (("initial", "A1"), ("update", "A2"), ("switch", "B3"), ("originUpdate", "B4"),
                       ("conflict", "C2"), ("beta", "BETA"), ("publisher", "P2"),
                       ("untrusted", "U"), ("deny", "DENY"), ("equivalent", "E2")):
        row = metadata["subjects" if key in metadata["subjects"] else "equivalents" if key == "E2" else "negatives"][key]
        if any("sha256:" + hashlib.sha256(objects[label][member]).hexdigest() != row[field]
               for member, field in (("catalog", "catalogDigest"), ("signature", "catalogSignatureDigest"))):
            raise LifecycleFailure("catalog-owned-source-snapshot-substituted")
    node_root = root / "node"
    runtime.make_runtime_config(node_root, runtime.interop.Ports(port(), port(), 0, 0), port())
    admission = {"subjects": metadata, "nativeProjections": projections, "sourceCommit": source_commit,
                 "daemonDigest": runtime.digest_file(distribution / "lib/cryptad.jar"),
                 "toolTreeDigest": verifier.tree_digest, "javaTreeDigest": verifier.java_tree_digest,
                 "fixtureTreeDigest": catalog.tree_digest(fixture_root),
                 "scopeRosterDigest": runtime.digest_file(fixture_root / "scoped-records.json"),
                 "implementation": runtime.runner_identity(), "roles": ["catalog-origin", "catalog-origin-update", "catalog-origin-staged-negative",
                           "catalog-origin-publisher-scope-negative", "catalog-origin-reviewer-scope-negative"],
                 "maximumSeconds": maximum_seconds, "maximumOperations": 600}
    selection_digest = digest(admission)
    for role in admission["roles"][1:]:
        (root / role).mkdir(mode=0o700)
    role_plan = root / "role-plan.json"
    with role_plan.open("x") as stream:
        json.dump(admission, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    role_plan.chmod(0o600)
    setup = Journal(root / "setup-operations.json", selection_digest)
    setup.value["operations"].append({"operation": "scope-bootstrap", "status": "started",
                                      "bootstrapManifestDigest": runtime.digest_file(fixture_root / "bootstrap/bootstrap.properties")})
    setup.save()
    result = subprocess.run([str(java / "bin/java"), "-cp", str(tool / "lib/*"),
        "network.crypta.platform.appcatalog.FederatedCatalogScopeBootstrap", str(node_root / "data/node/apps"),
        str(fixture_root / "bootstrap"), raw_digest(runtime.digest_file(fixture_root / "bootstrap/bootstrap.properties"))],
        capture_output=True, timeout=remaining_budget(budget, 60), check=False, env=java_environment)
    if result.returncode != 0 or len(result.stdout) > 65536:
        raise LifecycleFailure("catalog-owned-scope-bootstrap-failed")
    policies = json.loads(result.stdout)
    scoped = {row["catalogId"]: row for row in policies["catalogs"]}
    for native in projections.values():
        if any(raw_digest(scoped[native["catalogId"]][field + "Sha256"]) !=
               raw_digest(native["federationSelection"][field])
               for field in ("publisherPolicyDigest", "reviewerPolicyDigest")):
            raise LifecycleFailure("catalog-owned-original-scoped-policy-substituted")
    setup.value["operations"][0].update(status="complete", resultDigest=digest(policies))
    setup.save()
    with FixtureServer(objects) as server:
        host = OwnedHost(root, distribution, java, fixture_root, metadata, server, policies, maximum_seconds, budget=budget)
        config = runtime.make_runtime_config(node_root, host.ports, host.http_port)
        config.write_text(config.read_text().replace("End\n", "fproxy.hasCompletedWizard=true\nEnd\n"))
        try:
            host.start()
            initial = metadata["subjects"]["A1"]
            if host.ok("GET", "/api/v1/apps")["apps"] != [] or host.ok("GET", "/api/v1/app-catalogs")["catalogs"] != []:
                raise LifecycleFailure("catalog-owned-initial-state-not-empty")
            host.approve_catalog(initial)
            host.ok("POST", "/api/v1/app-catalogs/add", {"source": server.uri("primary"),
                                                       "expectedCatalogId": initial["catalogId"]})
            journal = Journal(root / "operations.json", selection_digest)
            observation = catalog.run_catalog_origin_lifecycle(host, {key: subjects[key] for key in ("initial", "update", "switch")}, journal)
            observation["mirror"] = host.mirror_cases()
            observation["sourceSecurity"] = host.source_security_cases()
            observation["conflictAndChannel"] = host.conflict_channel_cases()
            observation["principals"] = host.principal_cases()
            observation["keyRevocationsWithActiveScopes"] = host.scoped_revocation_cases()
            observation["rollbackAuthority"] = host.rollback_authority_cases()
            observation["requestCounts"] = server.counts()
            observation["nativeProjections"] = projections
            observation["roleActivationBindings"] = host.activations
            observation["originalPreauthorizationDigest"] = digest(projections)
            observation["terminalOrigin"] = host.observe(host.app_id)
            observation["daemonEpochs"] = host.epochs
            observation["cleanup"] = "owned-process-stopped-private-state-retained"
        finally:
            host.stop()
    observation["schemaVersion"] = 2
    observation["secondaryRoles"] = []
    for role in admission["roles"][1:]:
        observation["secondaryRoles"].append(execute_secondary_role(
            root / role, role, distribution, java, tool, fixture_root, metadata, objects,
            subjects, selection_digest, budget, maximum_seconds, java_environment, policies, admission["scopeRosterDigest"]))
    observation["rolePlanDigest"] = selection_digest
    observation["totalOperations"] = budget["operations"]
    output = root / "observation.json"
    output.write_text(json.dumps(observation, sort_keys=True), encoding="utf-8")
    output.chmod(0o600)
    return observation



def execute_secondary_role(root, role, distribution, java, tool, fixture_root, metadata, objects,
                           subjects, plan_digest, budget, maximum_seconds, java_environment, expected_policies, scope_roster_digest):
    remaining_budget(budget, 1)
    node_root = root / "node"
    runtime.make_runtime_config(node_root, runtime.interop.Ports(port(), port(), 0, 0), port())
    setup = Journal(root / "setup.json", plan_digest)
    setup.value["operations"].append({"operation": "scope-bootstrap", "role": role, "status": "started"})
    setup.save()
    native = subprocess.run([str(java / "bin/java"), "-cp", str(tool / "lib/*"),
        "network.crypta.platform.appcatalog.FederatedCatalogScopeBootstrap", str(node_root / "data/node/apps"),
        str(fixture_root / "bootstrap"), raw_digest(runtime.digest_file(fixture_root / "bootstrap/bootstrap.properties"))],
        capture_output=True, timeout=remaining_budget(budget, 60), check=False, env=java_environment)
    if native.returncode != 0 or len(native.stdout) > 65536:
        raise LifecycleFailure("catalog-owned-scope-bootstrap-failed")
    policies = json.loads(native.stdout)
    if policies != expected_policies:
        raise LifecycleFailure("catalog-owned-secondary-scoped-policy-substituted")
    setup.value["operations"][0].update(status="complete", resultDigest=digest(policies))
    setup.save()
    with FixtureServer(objects) as server:
        host = OwnedHost(root, distribution, java, fixture_root, metadata, server, policies,
                         maximum_seconds, role=role, budget=budget)
        host.scope_roster_digest = scope_roster_digest
        config = runtime.make_runtime_config(node_root, host.ports, host.http_port)
        config.write_text(config.read_text().replace("End\n", "fproxy.hasCompletedWizard=true\nEnd\n"))
        journal = Journal(root / "operations.json", plan_digest)
        try:
            host.start()
            if host.ok("GET", "/api/v1/apps")["apps"] != [] or host.ok("GET", "/api/v1/app-catalogs")["catalogs"] != []:
                raise LifecycleFailure("catalog-owned-initial-state-not-empty")
            initial = metadata["subjects"]["A1"]
            host.approve_catalog(initial)
            if role == "catalog-origin-staged-negative":
                staged = root / "staged"
                runtime.extract_app_bundle(fixture_root / "A1/bundle.zip", staged, initial["bundleDigest"])
                host.ok("POST", "/api/v1/apps/install", {"stagedDir": str(staged)})
                installed = node_root / "data/node/apps/installed" / host.app_id
                before_tree = installed_content_tree(installed)
                host.ok("POST", "/api/v1/app-catalogs/add", {"source": server.uri("primary"),
                                                           "expectedCatalogId": initial["catalogId"]})
                status, response = host.request("GET", "/api/v1/operator/apps/" + host.app_id + "/catalog-origin")
                after_tree = installed_content_tree(installed)
                if (status != 404 or before_tree != subjects["initial"].installed_tree_digest or before_tree != after_tree
                        or (node_root / "data/node/apps/catalog-origins" / (host.app_id + ".properties")).exists()):
                    raise LifecycleFailure("catalog-owned-staged-install-gained-origin")
                result = {"stagedRegistration": {"httpStatus": status, "errorCode": response.get("error", {}).get("code"),
                           "beforeInstalledTreeDigest": before_tree, "afterInstalledTreeDigest": after_tree,
                           "bundleDigest": initial["bundleDigest"], "originPresent": False}}
            else:
                host.ok("POST", "/api/v1/app-catalogs/add", {"source": server.uri("primary"),
                                                           "expectedCatalogId": initial["catalogId"]})
                driver = Driver(host, {key: subjects[key] for key in ("initial", "update", "switch")}, journal)
                result = driver.run(include_rollback=role != "catalog-origin-update")
                if role == "catalog-origin-update":
                    before = host.observe(host.app_id)
                    host.ok("DELETE", "/api/v1/app-catalogs/" + metadata["subjects"]["A2"]["catalogId"])
                    server.alternate_selected = "originUpdate"
                    host.ok("POST", "/api/v1/app-catalogs/" + metadata["subjects"]["B4"]["catalogId"] + "/refresh")
                    candidate = host.ok("POST", "/api/v1/apps/" + host.app_id + "/updates/check")["updates"]["candidate"]
                    target = subjects["originUpdate"]
                    if (candidate.get("catalogId") != target.catalog_id or candidate.get("status") != "available"
                            or candidate.get("bundle", {}).get("sha256") != raw_digest(target.bundle_digest)
                            or host.observe(host.app_id) != before):
                        raise LifecycleFailure("catalog-owned-origin-update-not-eligible")
                    journal.transition("origin-update", subjects["switch"], target, lambda: host.observe(host.app_id),
                                       lambda: driver.mutation(target, "update"))
                    result["eligibleOriginUpdate"] = {"candidate": candidate, "beforeOrigin": before,
                                                       "afterOrigin": host.observe(host.app_id)}
                    result["currentOriginTrustRemoval"] = host.current_origin_trust_removal()
                else:
                    result["scopeRevocation"] = host.local_scope_revocation_case(
                        "publisher" if role == "catalog-origin-publisher-scope-negative" else "reviewer")
                result["terminalOrigin"] = host.observe(host.app_id)
            result.update(schemaVersion=2, role=role, rolePlanDigest=plan_digest, operations=journal.value["operations"],
                          daemonEpochs=host.epochs, roleActivationBindings=host.activations,
                          requestCounts=server.counts())
        finally:
            host.stop()
    result["cleanup"] = "owned-process-stopped-private-state-retained"
    return result


def main(argv=None):
    class PrivateArgumentParser(argparse.ArgumentParser):
        def error(self, message):
            raise LifecycleFailure("catalog-owned-runtime-arguments-invalid")
    parser = PrivateArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["run-synthetic"])
    for name in ("private-root", "distribution", "java-home", "tool-root", "fixture-root"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    try:
        args = parser.parse_args(argv)
        execute(args.private_root, args.distribution, args.java_home, args.tool_root, args.fixture_root,
                source_commit=args.source_commit)
    except Exception:
        print("catalog-owned-runtime-failed")
        return 2
    print("catalog-owned-synthetic-observation-complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
