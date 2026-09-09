#!/usr/bin/env python3
"""Fixed tokenless Linux service for an explicitly selected disposable experiment.

This service executes the checked-in runner, not remote commands. Protected execution requires
the original attested authorization and root activation checked by the control helper. Its installed paths
are deliberately fixed; changing a deployment requires operator review and installation.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

CHECKOUT = Path("/opt/cryptad-cross-version/current")
STATE = Path("/var/lib/cryptad-cross-version")
MAX_SECONDS = 5 * 86400


class ServiceError(ValueError):
    """Closed diagnostic without private file contents or paths."""


def _digest(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(65536):
            result.update(block)
    return "sha256:" + result.hexdigest()


def _read_private(path):
    if (path.is_symlink() or any(parent.is_symlink() for parent in path.parents)
            or not path.is_file() or path.stat().st_uid != os.getuid()
            or path.stat().st_mode & 0o077 or path.stat().st_size > 1024 * 1024):
        raise ServiceError("service-selection-not-private")
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ServiceError("service-selection-duplicate-member")
            result[key] = value
        return result
    try:
        return json.loads(path.read_bytes(), object_pairs_hook=pairs)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ServiceError("service-selection-invalid-json") from exc


def load_selection(checkout, state):
    """Validate fixed-file selection before starting a controller or daemon.

    Parameters enable offline filesystem tests; the executable main exposes no path flags.
    Local selection means explicit same-owner source comparison, not signed-release proof.
    """
    selected = state / "selected"
    selection = _read_private(selected / "service-selection.json")
    required = {"schemaVersion", "serviceDigest", "planDigest", "privateConfigDigest", "authorizationDigest"}
    if not isinstance(selection, dict) or set(selection) != required or selection["schemaVersion"] != 1:
        raise ServiceError("service-selection-fields-invalid")
    service = checkout / "tools/interop/cross_version_service.py"
    if service.is_symlink() or _digest(service) != selection["serviceDigest"]:
        raise ServiceError("service-executable-binding-mismatch")
    for name, field in (("plan.json", "planDigest"), ("private-config.json", "privateConfigDigest"), ("authorization.json", "authorizationDigest")):
        path = selected / name
        _read_private(path)
        if _digest(path) != selection[field]:
            raise ServiceError("service-input-binding-mismatch")
    plan = _read_private(selected / "plan.json")
    private = _read_private(selected / "private-config.json")
    authorization = _read_private(selected / "authorization.json")
    if plan.get("profile") == "protected-long-live":
        if not (checkout / "tools/release-certification/protected/cross_version_supervisor_authority.py").is_file():
            raise ServiceError("service-protected-authority-not-configured")
        sys.path.insert(0, str(checkout / "tools/release-certification/protected"))
        from cross_version_supervisor_authority import authenticate_runner
        try:
            authenticate_runner(plan, private, authorization)
        except (ValueError, OSError):
            raise ServiceError("service-protected-authority-not-configured") from None
    elif plan.get("profile") != "bounded-live" or plan.get("provenanceClass") != "source-build-comparison":
        raise ServiceError("service-protected-authority-not-configured")
    identifier = plan.get("experimentId")
    import re
    if not isinstance(identifier, str) or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,95}", identifier) is None:
        raise ServiceError("service-experiment-id-invalid")
    root = state / "experiments" / identifier
    output = state / "public" / identifier
    if private.get("root") != str(root) or authorization.get("root") != str(root):
        raise ServiceError("service-root-selection-mismatch")
    if root.exists() or root.is_symlink() or output.exists() or output.is_symlink():
        raise ServiceError("service-existing-experiment-requires-reconciliation")
    for parent in (selected, root.parent, output.parent):
        if (not parent.is_dir() or parent.is_symlink() or any(p.is_symlink() for p in parent.parents)
                or parent.stat().st_uid != os.getuid() or parent.stat().st_mode & 0o077):
            raise ServiceError("service-parent-not-private")
    maximum = authorization.get("maxSeconds")
    if type(maximum) is not int or not 30 <= maximum <= MAX_SECONDS:
        raise ServiceError("service-duration-outside-policy")
    if authorization.get("syntheticContent") is not True:
        raise ServiceError("service-synthetic-authorization-required")
    return selected, root, output, maximum


def child_environment(state):
    """Do not pass GitHub, signing, session, proxy, or caller runtime credentials."""
    return {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "HOME": str(state),
            "PYTHONUNBUFFERED": "1", "PYTHONDONTWRITEBYTECODE": "1"}


def supervise(checkout, state):
    selected, root, output, maximum = load_selection(checkout, state)
    command = ["/usr/bin/python3", str(checkout / "tools/release-certification/certify.py"),
               "cross-version-soak", "run", "--execute", "--plan", str(selected / "plan.json"),
               "--private-config", str(selected / "private-config.json"),
               "--authorization", str(selected / "authorization.json"), "--journal-root", str(root),
               "--out-dir", str(output)]
    stop_requested = False
    child = None
    def stop(_signum, _frame):
        nonlocal stop_requested
        stop_requested = True
        if child is not None and child.poll() is None:
            # SIGINT unwinds the Python runner through its owned-node cleanup and partial
            # checkpoint path. systemd subsequently bounds the entire owned service cgroup.
            child.send_signal(signal.SIGINT)
    previous_handlers = {sig: signal.signal(sig, stop) for sig in (signal.SIGTERM, signal.SIGINT)}
    try:
        child = subprocess.Popen(command, cwd=checkout, env=child_environment(state), stdin=subprocess.DEVNULL,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        started = time.monotonic()
        stopping = None
        while child.poll() is None:
            if time.monotonic() - started > maximum + 180 and not stop_requested:
                stop(signal.SIGTERM, None)
            if stop_requested:
                stopping = stopping or time.monotonic()
                if time.monotonic() - stopping > 180:
                    # Only the child PID is signaled here; cgroup cleanup belongs to systemd.
                    # Never search or kill by executable name or trust a persisted PID file.
                    child.kill()
                    child.wait(timeout=10)
                    raise ServiceError("service-cleanup-incomplete-reconciliation-required")
            time.sleep(.25)
        if stop_requested:
            return 2
        return child.returncode
    finally:
        for sig, handler in previous_handlers.items():
            signal.signal(sig, handler)


def main():
    if len(sys.argv) != 1:
        print("cross-version-service: fixed-selection-only", file=sys.stderr)
        return 2
    if os.name != "posix" or not Path("/proc/sys/kernel/random/boot_id").is_file():
        print("cross-version-service: linux-required", file=sys.stderr)
        return 2
    try:
        cgroup = Path("/proc/self/cgroup").read_text()
    except OSError:
        cgroup = ""
    if not any(line.endswith(":/system.slice/cryptad-cross-version-soak.service") for line in cgroup.splitlines()):
        print("cross-version-service: dedicated-systemd-cgroup-required", file=sys.stderr)
        return 2
    os.umask(0o077)
    try:
        return supervise(CHECKOUT, STATE)
    except (ServiceError, OSError, subprocess.SubprocessError, ValueError):
        print("cross-version-service: failed-private-reconciliation-required", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
