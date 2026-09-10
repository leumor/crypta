"""Fixed backend protocol rehearsal with an allowlisted, network-free transport.

This models remote persistence and fault boundaries. It does not model GitHub authorization,
attestations, network delivery, infrastructure durability, or authentic release history.
"""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

from .maintenance_drill_runtime import fixture, publication, _require, _publish


def _provider():
    path = (Path(__file__).resolve().parents[1] / "publication-backend/src"
            / "cryptad_stable_maintenance_backend/provider.py")
    name = "maintenance_drill_fixed_provider"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class IsolatedTransport:
    """Bounded byte store for the fixed provider's exact HTTP request contract."""

    def __init__(self, bundle):
        self.bundle = bundle
        self.loaded = bundle.load()
        self.plan = self.loaded.plan
        self.tag = None
        self.tag_ref = None
        self.release = None
        self.assets = {}
        self.base = {}
        self.remote = {}
        self.calls = 0
        self.mutations = []
        self.fail_asset_once = False
        self.uncertain_asset_once = False
        self.crash_activation = False
        self.race_activation = False
        self.pointer_digest = fixture.POINTER
        self.pointer_bytes = None
        self.active_baseline = fixture.PREVIOUS_BASELINE
        self.active_candidate = fixture.digest("unactivated")

    def prestage(self):
        self.base = {row["publicUri"]: (self.loaded.legacy / row["fileName"]).read_bytes()
                     for row in self.plan["assets"]}

    def _budget(self):
        self.calls += 1
        if self.calls > 2000:
            raise ValueError("drill-provider-operation-budget")

    def digest(self, uri, limit, *, headers):
        self._budget()
        prefix = "https://api.github.com/repos/crypta-network/cryptad/releases/assets/"
        if uri.startswith(prefix):
            data = next((data for index, data in self.assets.values()
                         if str(index) == uri.removeprefix(prefix)), None)
        elif uri in {row["publicUri"] for row in self.plan["assets"]}:
            data = self.base.get(uri)
        else:
            raise ValueError("drill-provider-digest-target-denied")
        if data is None:
            return 404, 0, None
        return 200, len(data), "sha256:" + hashlib.sha256(data).hexdigest()

    @staticmethod
    def _response(value, status=200):
        return status, {}, fixture.canonical_bytes(value)

    def request(self, method, uri, *, headers, body=None):
        self._budget()
        parsed = urlsplit(uri)
        path = parsed.path
        prefix = "/repos/crypta-network/cryptad"
        if parsed.netloc == "api.github.com":
            if method == "GET" and path == prefix + "/git/ref/tags/" + self.plan["expectedTag"]:
                return self._response({"object": {"type": "tag", "sha": self.tag_ref}}) if self.tag_ref else self._response({}, 404)
            if method == "GET" and path == prefix + "/git/tags/" + "1" * 40:
                return self._response(self.tag)
            if method == "GET" and path == prefix + "/releases/tags/" + self.plan["expectedTag"]:
                if self.release is None:
                    return self._response({}, 404)
                return self._response({**self.release, "assets": [
                    {"name": name, "id": index, "size": len(data)}
                    for name, (index, data) in self.assets.items()]})
            if method == "POST":
                value = json.loads(body)
                if path == prefix + "/git/tags":
                    _require(self.tag is None)
                    self.tag = {**value, "object": {"type": value["type"], "sha": value["object"]}}
                    self.mutations.append("tag-object")
                    return self._response({"sha": "1" * 40}, 201)
                if path == prefix + "/git/refs":
                    _require(self.tag_ref is None and value["ref"] == "refs/tags/" + self.plan["expectedTag"])
                    self.tag_ref = value["sha"]
                    self.mutations.append("tag-ref")
                    return self._response({}, 201)
                if path == prefix + "/releases":
                    _require(self.release is None)
                    self.release = {**value, "id": 1, "html_url": self.plan["githubReleasePageUri"]}
                    self.mutations.append("release")
                    return self._response(self.release, 201)
        if (parsed.netloc == "uploads.github.com" and method == "POST"
                and path == prefix + "/releases/1/assets"):
            name = parse_qs(parsed.query)["name"][0]
            _require(name in {row["fileName"] for row in self.plan["assets"]} and name not in self.assets)
            if self.fail_asset_once:
                self.fail_asset_once = False
                return self._response({}, 503)
            self.assets[name] = (len(self.assets) + 1, body)
            self.mutations.append("asset")
            if self.uncertain_asset_once:
                self.uncertain_asset_once = False
                raise RuntimeError("synthetic-response-lost-after-write")
            return self._response({}, 201)
        if method == "POST" and uri in {
            self.plan["deploymentServicePublicUri"], "synthetic-catalog-capability",
            "synthetic-update-capability", "synthetic-maintenance-state-capability",
        }:
            return self._service(uri, json.loads(body))
        raise ValueError("drill-provider-request-target-denied")

    def _service(self, uri, value):
        operation = value["operation"]
        subject = value["subject"]
        if operation == "observe-publication":
            _require(uri == self.plan["deploymentServicePublicUri"])
            return self._response({"schemaVersion": 1, "kind": "cryptad-stable-maintenance-deployment-observation",
                                   "predecessorPointerDigest": fixture.POINTER,
                                   "latestCandidateIdentityDigest": None,
                                   "targets": {target: "matching" if target in self.remote else "absent"
                                               for target in ("stableCatalog", "coreUpdate")}})
        if operation in {"publish-stable-catalog", "publish-core-update"}:
            catalog = operation == "publish-stable-catalog"
            target = "stableCatalog" if catalog else "coreUpdate"
            _require(uri == ("synthetic-catalog-capability" if catalog else "synthetic-update-capability"))
            content = (base64.b64decode(subject["catalogBytes"]) + base64.b64decode(subject["signatureBytes"])
                       if catalog else base64.b64decode(subject["descriptorBytes"]))
            expected = (self.bundle.catalog.read_bytes() + self.bundle.catalog_signature.read_bytes()
                        if catalog else self.bundle.core_info_path.read_bytes())
            _require(content == expected and (target not in self.remote or self.remote[target] == content))
            self.remote[target] = content
            self.mutations.append(target)
            return self._response({"schemaVersion": 1, "kind": "cryptad-stable-maintenance-deployment-mutation",
                                   "target": target, "candidateIdentityDigest": subject["candidateIdentityDigest"], "status": "created"})
        if operation == "verify-publication":
            _require(uri == self.plan["deploymentServicePublicUri"] and len(self.remote) == 2
                     and len(self.assets) == len(self.plan["assets"]))
            material = self.bundle.material()
            return self._response({"schemaVersion": 1, "kind": "cryptad-stable-maintenance-deployment-verification",
                                   "maintenanceReceipt": material.maintenance_receipt,
                                   "coreUpdateReceipt": material.core_update_receipt,
                                   "successorBaseline": material.successor_baseline,
                                   "historyEntry": material.history_entry})
        if operation == "observe-latest-pointer":
            _require(uri == self.plan["deploymentServicePublicUri"])
            return self._response({"schemaVersion": 1, "kind": "cryptad-stable-maintenance-pointer-observation",
                                   "status": "observed", "pointerDigest": self.pointer_digest,
                                   "activeBaselineDigest": self.active_baseline,
                                   "candidateIdentityDigest": self.active_candidate})
        if operation == "activate-latest-pointer":
            _require(uri == "synthetic-maintenance-state-capability")
            if self.race_activation:
                self.pointer_digest = fixture.digest("synthetic-concurrent-pointer")
            if subject["expectedPointerDigest"] != self.pointer_digest:
                return self._response({}, 409)
            data = base64.b64decode(subject["activatedPointerBytes"])
            _require("sha256:" + hashlib.sha256(data).hexdigest() == subject["activatedPointerDigest"])
            self.pointer_bytes = data
            self.pointer_digest = subject["activatedPointerDigest"]
            self.active_baseline = json.loads(data)["baselineDigest"]
            self.active_candidate = subject["candidateIdentityDigest"]
            self.mutations.append("activate")
            if self.crash_activation:
                raise RuntimeError("synthetic-crash-after-cas")
            return self._response({"schemaVersion": 1, "kind": "cryptad-stable-maintenance-pointer-activation",
                                   "status": "activated", "activatedPointerDigest": self.pointer_digest})
        raise ValueError("drill-provider-service-operation-denied")


def execute(root, bundle):
    provider = _provider()
    transport = IsolatedTransport(bundle)
    backend = provider.StableMaintenanceBackend("synthetic-github-token", transport)
    _require(not _publish(bundle, backend, root).passed and not transport.mutations)
    transport.prestage()
    transport.fail_asset_once = True
    outcome = _publish(bundle, backend, root)
    _require(not outcome.passed and transport.mutations == ["tag-object", "tag-ref", "release"])
    transport.uncertain_asset_once = True
    outcome = _publish(bundle, backend, root)
    _require(not outcome.passed and len(transport.assets) == 1
             and next(iter(outcome.artifacts.values()))["sideEffectsMayHaveOccurred"])
    _require(_publish(bundle, backend, root).passed)
    count = len(transport.mutations)
    _require(_publish(bundle, backend, root).passed and len(transport.mutations) == count)
    first = next(iter(transport.assets))
    asset_id, original = transport.assets[first]
    transport.assets[first] = (asset_id, b"synthetic-conflict")
    _require(not _publish(bundle, backend, root).passed and len(transport.mutations) == count
             and transport.assets[first][1] == b"synthetic-conflict")
    transport.assets[first] = (asset_id, original)
    _activation(root, bundle, backend, transport)
    return ["fixed-provider-exact-byte-failure-recovery", "fixed-provider-activation-cas-response-loss"]


def _activation(root, bundle, backend, transport):
    material = bundle.material()
    successor = root / "synthetic-successor.json"
    history = root / "synthetic-history.json"
    receipt = root / "synthetic-receipt.json"
    fixture.write_json(successor, material.successor_baseline)
    fixture.write_json(history, material.history_entry)
    fixture.write_json(receipt, material.maintenance_receipt)
    # Reuse only the fixture builder, never a TestCase execution or its assertions.
    auth = fixture.StableMaintenancePublicationTest.activation_authorization(
        SimpleNamespace(root=root, fixture=bundle), successor, history, receipt)
    def activate():
        return publication.activate_latest_baseline(
            successor, history, receipt, bundle.authorization_path, auth, fixture.POINTER,
            backend, publication.SecretMaterial("maintenance-state", "synthetic-maintenance-state-capability"),
            lambda record: None, root / "not-exported-activation-receipt.json", now=fixture.NOW)
    transport.pointer_digest = fixture.digest("stale-pointer")
    count = len(transport.mutations)
    _require(not activate().passed and len(transport.mutations) == count)
    transport.pointer_digest = fixture.POINTER
    transport.race_activation = True
    raced = activate()
    _require(not raced.passed and len(transport.mutations) == count
             and next(iter(raced.artifacts.values()))["operation"] == "partial")
    transport.race_activation = False
    transport.pointer_digest = fixture.POINTER
    transport.crash_activation = True
    lost = activate()
    _require(not lost.passed and next(iter(lost.artifacts.values()))["operation"] == "partial"
             and transport.pointer_bytes is not None)
    count = len(transport.mutations)
    recovered = activate()
    _require(recovered.passed and len(transport.mutations) == count
             and next(iter(recovered.artifacts.values()))["operation"] == "verified-existing")
