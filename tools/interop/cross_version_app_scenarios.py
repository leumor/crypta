"""Finite Stable 1.0 operations through a normally installed app's own principal.

The supervisor supplies an admitted Site Publisher handle. Values, record identities and
comparison digests remain private. This establishes representative endpoint behavior, not
the complete static contract, catalog lifecycle, permission or network-budget matrix.
"""
from __future__ import annotations

import base64
import secrets
import uuid


class ScenarioFailure(ValueError):
    """Fixed observer failure without endpoint response or private comparison text."""


def _require(condition):
    if not condition:
        raise ScenarioFailure("stable-api-postcondition-failed")


def stable_api(supervisor, role):
    """Observe own-app round trip, denied stale write, restart persistence and cleanup.

    A missing signed app is an unobserved mandatory cell. The runner must authorize the
    selected disposable node and synthetic writes before entering this callable adapter.
    This operation never substitutes host credentials for an app principal.
    """
    result = {"status": "not-observed", "cleanup": "not-required", "operations": 0}
    handle = supervisor.apps.get((role, "site-publisher"))
    if handle is None:
        return result
    namespace = "soak-" + uuid.uuid4().hex
    record_path = "/api/v1/app-data/records/" + namespace + "/probe"
    namespace_path = "/api/v1/app-data/namespaces/" + namespace
    value = base64.b64encode(secrets.token_bytes(64)).decode("ascii")
    owned = False

    def request(method, path, parameters=None):
        # Account every actual request against the supervisor's approved operation budget.
        supervisor.next_operation()
        result["operations"] += 1
        return handle.request(method, path, parameters, principal="app")

    def read_back():
        status, response = request("GET", record_path)
        _require(status == 200 and response.get("record", {}).get("valueBase64") == value)

    try:
        handle.refresh_session()
        status, response = request("GET", "/api/v1/app-data/status")
        _require(status == 200 and isinstance(response.get("status"), dict))
        status, response = request("GET", "/api/v1/queue")
        _require(status == 200 and isinstance(response, dict))
        status, _ = request("GET", namespace_path)
        _require(status == 404)
        # Only this fresh namespace becomes cleanup input; existing app data is never deleted.
        owned = True
        parameters = {"namespace": namespace, "key": "probe", "schemaVersion": 1,
                      "contentType": "application/octet-stream", "valueBase64": value}
        status, _ = request("POST", "/api/v1/app-data/records", parameters)
        _require(status in (200, 201))
        read_back()
        status, response = request("POST", "/api/v1/app-data/records",
                                   {**parameters, "valueBase64": "eA==", "ifMatchSha256": "0" * 64})
        _require(status == 409 and response.get("error", {}).get("code") == "app_data_write_conflict")
        read_back()
        supervisor.restart_node(role)
        handle = supervisor.apps[(role, "site-publisher")]
        handle.refresh_session()
        read_back()
        result["status"] = "observed"
    except Exception:
        # Response bodies can contain private values. Export only the fixed failure class.
        result["status"] = "failed"
    finally:
        if owned:
            try:
                status, _ = request("DELETE", namespace_path)
                _require(status in (200, 204))
                status, _ = request("GET", namespace_path)
                _require(status == 404)
                result["cleanup"] = "observed"
            except Exception:
                result["cleanup"] = "cleanup-incomplete"
                result["status"] = "failed"
    return result
