#!/usr/bin/env python3
"""Owned disposable packaged-node experiments; never a protected evidence authority.

All process output, FCP transcripts, references and comparisons stay in the private root.
The adapter deliberately reports unimplemented mandatory scenarios as not-observed.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import base64
import fcntl
import datetime as dt
from html.parser import HTMLParser
import importlib.util
import json
import os
import re
from pathlib import Path, PurePosixPath
import signal
import socket
import stat
import subprocess
import sys
import tarfile
import time
import tempfile
import uuid
import urllib.error
import urllib.parse
import urllib.request
import zipfile

import interop_smoke as interop

ROLES = ("candidate-sender", "candidate-recipient", "previous", "relay-no-apps")
MAX_ARCHIVE = 4 * 1024**3
MAX_FILES = 30000
MAX_EXPANDED = 8 * 1024**3
MAX_LOG_BYTES = 64 * 1024**2

_mail_spec = importlib.util.spec_from_file_location("cryptad_mail_demo", Path(__file__).resolve().parents[1] / "mail-prototype/two_node_demo.py")
mail_demo = importlib.util.module_from_spec(_mail_spec)
_mail_spec.loader.exec_module(mail_demo)


class RuntimeFailure(Exception):
    """A fixed public error code; never include private exception text."""


def digest_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def canonical_digest(value):
    return "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                                 allow_nan=False).encode()).hexdigest()


def tree_digest(root, require_java=True):
    """Bind the complete executable runtime, refusing links outside the selected runtime."""
    root = Path(root).resolve(strict=True)
    records = []
    total_bytes = 0
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if path.is_file():
            total_bytes += path.stat().st_size
            if total_bytes > MAX_EXPANDED:
                raise RuntimeFailure("runtime-byte-budget-exceeded")
        if path.is_symlink():
            target = path.resolve(strict=True)
            if not target.is_relative_to(root) or not target.is_file():
                raise RuntimeFailure("runtime-link-outside-selected-tree")
            records.append([relative, "link", os.readlink(path), digest_file(target)])
        elif path.is_file():
            records.append([relative, "file", path.stat().st_mode & 0o777, digest_file(path)])
        elif not path.is_dir():
            raise RuntimeFailure("runtime-special-file-rejected")
        if len(records) > MAX_FILES:
            raise RuntimeFailure("runtime-file-budget-exceeded")
    if not records or (require_java and not (root / "bin/java").is_file()):
        raise RuntimeFailure("runtime-java-missing")
    return canonical_digest(records)


def packaged_daemon_identity(distribution, source_commit, build_version=None):
    """Check embedded build marker and actual daemon bytes, without claiming release authority."""
    jar = Path(distribution) / "lib/cryptad.jar"
    try:
        with zipfile.ZipFile(jar) as archive:
            entries = [entry for entry in archive.infolist() if entry.filename == "META-INF/MANIFEST.MF"]
            if len(entries) != 1 or entries[0].file_size > 65536:
                raise RuntimeFailure("daemon-manifest-invalid")
            raw = archive.read(entries[0]).decode("utf-8")
        logical = []
        for line in raw.replace("\r\n", "\n").splitlines():
            if line.startswith(" ") and logical:
                logical[-1] += line[1:]
            elif not line:
                break
            else:
                logical.append(line)
        attributes = {}
        for line in logical:
            key, separator, value = line.partition(": ")
            if not separator or key in attributes:
                raise RuntimeFailure("daemon-manifest-invalid")
            attributes[key] = value
        revision = attributes.get("Implementation-Version", "").split()
        if len(revision) != 2 or not re.fullmatch("[0-9a-f]{7,40}", revision[1]) or not source_commit.startswith(revision[1]):
            raise RuntimeFailure("daemon-embedded-source-mismatch")
        if build_version is not None and revision[0] != str(build_version):
            raise RuntimeFailure("daemon-embedded-build-mismatch")
        return digest_file(jar)
    except (OSError, UnicodeError, zipfile.BadZipFile) as error:
        raise RuntimeFailure("daemon-package-identity-unavailable") from error


def require_native_target(distribution, selected_target, java_home):
    targets = {"linux-x64": ("x86_64", "wrapper-linux-x86-64", 62),
               "linux-arm64": ("aarch64", "wrapper-linux-arm-64", 183)}
    if selected_target not in targets:
        raise RuntimeFailure("package-target-unsupported")
    machine, binary, elf_machine = targets[selected_target]
    if os.uname().machine != machine:
        raise RuntimeFailure("package-target-host-mismatch")
    wrapper = Path(distribution) / "bin/wrapper"
    if not wrapper.exists():
        wrapper = Path(distribution) / "bin" / binary
    for path in (wrapper, Path(java_home) / "bin/java"):
        with path.open("rb") as stream:
            header = stream.read(20)
        if (len(header) != 20 or header[:6] != b"\x7fELF\x02\x01"
                or int.from_bytes(header[18:20], "little") != elf_machine):
            raise RuntimeFailure("package-native-architecture-mismatch")


def extract_package(archive, destination, expected_digest, expected_size):
    """Extract only a pinned portable tar distribution into a new owned directory."""
    archive, destination = Path(archive), Path(destination)
    if archive.is_symlink() or not archive.is_file():
        raise RuntimeFailure("artifact-file-invalid")
    if not 0 < expected_size <= MAX_ARCHIVE or archive.stat().st_size != expected_size:
        raise RuntimeFailure("artifact-size-mismatch")
    if digest_file(archive) != expected_digest:
        raise RuntimeFailure("artifact-digest-mismatch")
    if destination.exists() or destination.is_symlink():
        raise RuntimeFailure("extraction-target-exists")
    try:
        with tarfile.open(archive, "r:*") as source:
            members = []
            for member in source:
                members.append(member)
                if len(members) > MAX_FILES:
                    raise RuntimeFailure("artifact-member-budget-exceeded")
            if not members:
                raise RuntimeFailure("artifact-member-budget-exceeded")
            names, portable = set(), set()
            total = 0
            for member in members:
                name = PurePosixPath(member.name)
                if (name.is_absolute() or not name.parts or any(p in (".", "..", "") for p in name.parts)
                        or "\\" in member.name or ":" in member.name or "\x00" in member.name
                        or member.name.startswith("./") or any(ord(c) < 32 for c in member.name)
                        or not (member.isfile() or member.isdir()) or member.mode & 0o7000):
                    raise RuntimeFailure("artifact-member-unsafe")
                normalized = name.as_posix()
                if normalized in names or normalized.casefold() in portable:
                    raise RuntimeFailure("artifact-member-collision")
                names.add(normalized)
                portable.add(normalized.casefold())
                total += member.size
                if member.size < 0 or total > MAX_EXPANDED:
                    raise RuntimeFailure("artifact-expanded-budget-exceeded")
            member_types = {PurePosixPath(member.name).as_posix(): member.isdir() for member in members}
            for name in names:
                if any(str(parent) in names and not member_types[str(parent)]
                       for parent in PurePosixPath(name).parents if str(parent) != "."):
                    raise RuntimeFailure("artifact-parent-collision")
            destination.mkdir(mode=0o700)
            for member in members:
                path = destination.joinpath(*PurePosixPath(member.name).parts)
                if member.isdir():
                    path.mkdir(parents=True, exist_ok=True, mode=0o700)
                    continue
                path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                with source.extractfile(member) as stream, path.open("xb") as output:
                    remaining = member.size
                    while remaining:
                        chunk = stream.read(min(1024 * 1024, remaining))
                        if not chunk:
                            raise RuntimeFailure("artifact-member-truncated")
                        output.write(chunk)
                        remaining -= len(chunk)
                path.chmod(0o700 if member.mode & 0o111 else 0o600)
        roots = [destination] if (destination / "bin/cryptad").is_file() else [destination / "cryptad-dist"]
        root = roots[0]
        if not (root / "bin/cryptad").is_file() or not os.access(root / "bin/cryptad", os.X_OK):
            raise RuntimeFailure("artifact-package-layout-unsupported")
        if digest_file(archive) != expected_digest:
            raise RuntimeFailure("artifact-changed-during-extraction")
        return root
    except (OSError, tarfile.TarError) as error:
        raise RuntimeFailure("artifact-extraction-failed") from error


@contextmanager
def absolute_deadline(seconds):
    """Bound whole operations including trickled FCP frames and response consumption."""
    if seconds <= 0:
        raise RuntimeFailure("experiment-deadline-exceeded")
    def timeout(_signal, _frame):
        raise RuntimeFailure("operation-deadline-exceeded")
    previous = signal.getsignal(signal.SIGALRM)
    old_timer = signal.getitimer(signal.ITIMER_REAL)
    if old_timer[0]:
        raise RuntimeFailure("nested-process-timer-rejected")
    signal.signal(signal.SIGALRM, timeout)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def config_identity(config, root, fnp_port, fcp_port, http_port=None, trust_digest=None):
    """Digest generated configuration with opaque substitutions for private locations/ports."""
    text = Path(config).read_text(encoding="utf-8")
    text = text.replace(str(root), "<owned-node-root>")
    text = text.replace(f"node.listenPort={fnp_port}\n", "node.listenPort=<assigned-fnp>\n")
    text = text.replace(f"fcp.port={fcp_port}\n", "fcp.port=<assigned-fcp>\n")
    if http_port is not None:
        text = text.replace(f"fproxy.port={http_port}\n", "fproxy.port=<assigned-http>\n")
    return canonical_digest({"role": Path(root).parent.name, "configuration": text, "appTrustDigest": trust_digest})


def make_runtime_config(node_root, ports, http_port):
    config = interop.make_cryptad_config(node_root, ports)
    text = config.read_text(encoding="utf-8").replace("fproxy.enabled=false\n", "fproxy.enabled=true\n")
    text = text.replace("End\n", f"fproxy.port={http_port}\nfproxy.bindTo=127.0.0.1\nfproxy.allowedHosts=127.0.0.1\nfproxy.allowedHostsFullAccess=127.0.0.1\nEnd\n")
    config.write_text(text, encoding="utf-8")
    return config


def planned_config_identity(role, fnp_port, fcp_port, http_port, trust_digest=None):
    """Derive the fixed config pin without touching a selected node or private run root."""
    with tempfile.TemporaryDirectory(prefix="cryptad-config-inspection-") as temporary:
        root = Path(temporary) / role / "node"
        config = make_runtime_config(root, interop.Ports(fnp_port, fcp_port, 0, 0), http_port)
        return config_identity(config, root, fnp_port, fcp_port, http_port, trust_digest)


def node_epoch(identity):
    return canonical_digest({key: identity[key] for key in ("bootId", "pid", "startTicks")})[7:39]


def process_identity(pid):
    """Linux supervisor identity, including process-start epoch to detect PID reuse."""
    root = Path("/proc") / str(pid)
    fields = (root / "stat").read_text().rsplit(")", 1)[1].split()
    return {"pid": pid, "startTicks": int(fields[19]),
            "bootId": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            "executableDigest": digest_file(root / "exe")}


def extract_app_bundle(archive, destination, expected_digest):
    """Confine a selected signed app ZIP; Java AppHost remains signature/manifest authority."""
    archive, destination = Path(archive), Path(destination)
    if archive.is_symlink() or not archive.is_file() or archive.stat().st_size > 64 * 1024**2:
        raise RuntimeFailure("app-bundle-file-invalid")
    if digest_file(archive) != expected_digest or destination.exists():
        raise RuntimeFailure("app-bundle-binding-invalid")
    try:
        with zipfile.ZipFile(archive) as source:
            members = source.infolist()
            if not members or len(members) > 4096:
                raise RuntimeFailure("app-bundle-member-budget-exceeded")
            names, total = set(), 0
            for member in members:
                name = PurePosixPath(member.filename)
                mode = member.external_attr >> 16
                if (not name.parts or name.is_absolute() or ".." in name.parts or "\\" in member.filename
                        or ":" in member.filename or member.filename.startswith("./")
                        or member.filename.casefold() in names or member.flag_bits & 1
                        or stat.S_ISLNK(mode) or stat.S_IFMT(mode) not in {0, stat.S_IFREG, stat.S_IFDIR}
                        or any(ord(c) < 32 for c in member.filename)):
                    raise RuntimeFailure("app-bundle-member-unsafe")
                names.add(member.filename.casefold())
                total += member.file_size
                if total > 128 * 1024**2:
                    raise RuntimeFailure("app-bundle-expanded-budget-exceeded")
            destination.mkdir(mode=0o700)
            for member in members:
                target = destination.joinpath(*PurePosixPath(member.filename).parts)
                if member.is_dir():
                    target.mkdir(parents=True, exist_ok=True, mode=0o700)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                with source.open(member) as stream, target.open("xb") as output:
                    remaining = member.file_size
                    while remaining:
                        chunk = stream.read(min(65536, remaining))
                        if not chunk:
                            raise RuntimeFailure("app-bundle-truncated")
                        output.write(chunk)
                        remaining -= len(chunk)
                target.chmod(0o700 if member.external_attr >> 16 & 0o111 else 0o600)
        if not (destination / "cryptad-app.properties").is_file():
            raise RuntimeFailure("app-bundle-manifest-missing")
        if digest_file(archive) != expected_digest:
            raise RuntimeFailure("app-bundle-changed-during-extraction")
    except (OSError, zipfile.BadZipFile) as error:
        raise RuntimeFailure("app-bundle-extraction-failed") from error


@contextmanager
def fixed_helper_imports():
    """Make only the pinned repository helper directories available to fixed adapters."""
    root = Path(__file__).resolve().parents[2]
    added = [str(root / "tools/release-certification/protected"), str(root / "tools/release-certification"), str(root / "tools/interop")]
    original = list(sys.path)
    sys.path[:0] = added
    try:
        yield
    finally:
        sys.path[:] = original


def fixed_helper(name):
    allowed = {"sharesite_observation": "tools/release-certification/protected/sharesite_observation.py",
               "app_subject_projection": "tools/release-certification/protected/app_subject_projection.py",
               "cross_version_app_scenarios": "tools/interop/cross_version_app_scenarios.py",
               "cross_version_recovery": "tools/interop/cross_version_recovery.py",
               "cross_version_product_admission": "tools/release-certification/protected/cross_version_product_admission.py",
               "cross_version_supervisor_authority": "tools/release-certification/protected/cross_version_supervisor_authority.py",
               "cross_version_budget": "tools/interop/cross_version_budget.py",
               "cross_version_catalog": "tools/interop/cross_version_catalog.py"}
    if name not in allowed:
        raise RuntimeFailure("unselected-helper-rejected")
    expected = Path(__file__).resolve().parents[2] / allowed[name]
    module = __import__(name)
    if Path(module.__file__).resolve() != expected:
        raise RuntimeFailure("unselected-helper-rejected")
    return module


def authenticate_runner_selection(plan, private_config, authorization):
    try:
        with fixed_helper_imports():
            module = fixed_helper("cross_version_supervisor_authority")
            admission = module.authenticate_runner(plan, private_config, authorization)
            if not isinstance(admission, module.AuthenticatedRunner):
                raise RuntimeFailure("protected-runner-authority-not-produced")
            return admission
    except (ValueError, OSError) as error:
        raise RuntimeFailure("protected-runner-authority-unavailable") from error


def authenticate_product_selection(plan, private_config):
    """Re-authenticate original producers; byte-identical predownloaded packages may be selected."""
    selection = private_config.get("productAdmission")
    if selection is None:
        raise RuntimeFailure("original-product-selection-required")
    try:
        with fixed_helper_imports(), tempfile.TemporaryDirectory(prefix="cryptad-product-admission-") as temporary:
            module = fixed_helper("cross_version_product_admission")
            admission = module.authenticate_products(plan, selection, Path(temporary) / "original")
            if not isinstance(admission, module.AuthenticatedProducts):
                raise RuntimeFailure("original-product-authority-not-produced")
            admission.bind(plan, private_config)
            return admission
    except (ValueError, OSError) as error:
        raise RuntimeFailure("original-product-authentication-failed") from error


def validate_migration_selection(selection):
    expected = {"role", "recoveryRole", "toolRoot", "toolTreeDigest", "javaHome", "javaTreeDigest", "nodeExecutable", "nodeDigest"}
    if (not isinstance(selection, dict) or set(selection) - {"dataClass"} != expected
            or selection["role"] != "candidate-sender"
            or selection["recoveryRole"] not in {None, "candidate-recipient"}
            or selection.get("dataClass", "upstream-writer-synthetic") not in {"upstream-writer-synthetic", "operator-owned-private-observation"}):
        raise RuntimeFailure("migration-selection-invalid")
    for field in ("toolRoot", "javaHome", "nodeExecutable"):
        path = Path(selection[field])
        if not path.is_absolute() or path.is_symlink() or not path.exists():
            raise RuntimeFailure("migration-tool-path-invalid")
    with fixed_helper_imports():
        projection = fixed_helper("app_subject_projection")
        if (projection.tree_digest(Path(selection["toolRoot"])) != selection["toolTreeDigest"]
                or projection.tree_digest(Path(selection["javaHome"])) != selection["javaTreeDigest"]
                or digest_file(selection["nodeExecutable"]) != selection["nodeDigest"]):
            raise RuntimeFailure("migration-tool-identity-mismatch")
    converter = Path(selection["toolRoot"]) / "bin/crypta-app"
    if converter.is_symlink() or not converter.is_file() or not os.access(converter, os.X_OK):
        raise RuntimeFailure("migration-fixed-converter-unavailable")


def validate_recovery_selection(plan, private_config, authorization):
    selection = private_config.get("recovery")
    declared = plan.get("cohorts", [])
    if selection is None:
        if declared:
            raise RuntimeFailure("recovery-declared-without-private-selection")
        return
    if (not isinstance(selection, dict) or set(selection) != {"cohortId", "fnpPort", "fcpPort", "httpPort"}
            or selection["cohortId"] != "previous-to-candidate"):
        raise RuntimeFailure("recovery-selection-invalid")
    expected = [{"id": "previous-to-candidate", "sourceRole": "previous", "targetRole": "candidate-sender",
                 "configDigest": canonical_digest(selection)}]
    if declared != expected or authorization is None or authorization.get("recoveryInputsDigest") != canonical_digest(selection):
        raise RuntimeFailure("recovery-selection-not-authorized")
    ports = [selection[field] for field in ("fnpPort", "fcpPort", "httpPort")]
    main_ports = {row[field] for row in private_config["nodes"].values() for field in ("fnpPort", "fcpPort", "httpPort")}
    if (any(type(port) is not int or not 1024 <= port <= 65535 for port in ports)
            or len(set(ports)) != 3 or main_ports.intersection(ports)):
        raise RuntimeFailure("recovery-port-alias-rejected")
    if not any(app["appId"] == "site-publisher" for app in private_config["nodes"]["previous"]["apps"]):
        raise RuntimeFailure("recovery-previous-signed-app-missing")


def validate_budget_selection(plan, private_config, authorization):
    selection = private_config.get("budget")
    declared = plan.get("workloadInputs", {}).get("budget")
    if selection is None:
        if declared is not None or (authorization or {}).get("budgetInputsDigest") is not None:
            raise RuntimeFailure("budget-declared-without-private-selection")
        return
    if (not isinstance(selection, dict) or set(selection) != {"role", "nodeExecutable", "nodeDigest"}
            or selection["role"] != "candidate-sender"):
        raise RuntimeFailure("budget-selection-invalid")
    binding = canonical_digest(selection)
    if declared != binding or authorization is None or authorization.get("budgetInputsDigest") != binding:
        raise RuntimeFailure("budget-selection-not-authorized")
    if not any(app["appId"] == "feed-reader" for app in private_config["nodes"][selection["role"]]["apps"]):
        raise RuntimeFailure("budget-signed-feed-reader-not-selected")
    executable = Path(selection["nodeExecutable"])
    if (not executable.is_absolute() or executable.is_symlink() or not executable.is_file()
            or any(parent.is_symlink() for parent in executable.parents)
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", str(selection["nodeDigest"]))
            or digest_file(executable) != selection["nodeDigest"]):
        raise RuntimeFailure("budget-node-executable-not-selected")


class _BootstrapParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.active = False
        self.parts = []
        self.count = 0

    def handle_starttag(self, tag, attrs):
        if tag == "script" and dict(attrs).get("id") == "web-shell-bootstrap":
            self.active = True
            self.count += 1

    def handle_endtag(self, tag):
        if tag == "script":
            self.active = False

    def handle_data(self, data):
        if self.active:
            self.parts.append(data)


class ObservedMailClient(mail_demo.Client):
    """Reuse Mail protocol while charging every actual command/result/control request."""
    def __init__(self, supervisor, *args):
        self.supervisor = supervisor
        super().__init__(*args)

    def post(self, path, parameters, host=False):
        self.supervisor.next_operation()
        self.supervisor.remaining(1)
        return super().post(path, parameters, host)


class AppHandle:
    """Private own-app session and bounded HTTP access bound to an owned node process."""
    def __init__(self, supervisor, role, app_id):
        self.supervisor, self.role, self.app_id = supervisor, role, app_id
        self.base = "http://127.0.0.1:" + str(supervisor.private["nodes"][role]["httpPort"])
        self.api = self.base + "/api/v1"
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), mail_demo.NoRedirect())
        self.origin = self.session = self.password = None
        self.session_expires_at = None
        self.worker_identity = None

    def request(self, method, path, parameters=None, *, principal="host", raw=False, headers_override=None):
        """Only fixed selected app, Mail, app-data and observation routes; no generic proxy."""
        exact = {"/app/node/", "/api/v1/apps", "/api/v1/apps/install", "/api/v1/diagnostics",
                 "/api/v1/mail/command", "/api/v1/mail/result", "/api/v1/audit", "/api/v1/queue", "/api/v1/platform/contract", "/api/v1/operator/support-bundle",
                 "/api/v1/operator/app-data/backups", "/api/v1/operator/app-data/restore/plan", "/api/v1/operator/app-data/restore"}
        if self.app_id == "feed-reader" and principal == "app":
            if (method == "GET" and path == "/api/v1/content/subscriptions") or (method == "POST" and path == "/api/v1/content/fetch"):
                exact.add(path)
        if principal == "host" and getattr(self.supervisor, "catalog_prepared", None) is not None:
            if self.supervisor.catalog_route_allowed(self.role, self.app_id, method, path) is True:
                exact.add(path)
        prefixes = ("/api/v1/app-data/",)
        allowed_app = {"/api/v1/apps/" + self.app_id + suffix for suffix in ("", "/start", "/stop", "/runtime", "/logs", "/audit")}
        bootstrap = "/apps/" + self.app_id + "/.well-known/cryptad-bootstrap.json"
        if (path not in exact | allowed_app | {bootstrap} and not path.startswith(prefixes)) or "?" in path or ".." in path:
            raise RuntimeFailure("app-route-not-approved")
        self.supervisor.next_operation()
        headers = {"Accept": "application/json"}
        values = dict(parameters or {})
        if principal == "app":
            if not self.session or not self.origin:
                raise RuntimeFailure("own-app-session-unavailable")
            headers.update({"Origin": self.origin, "X-Crypta-App-Session": self.session})
        elif principal == "host":
            if method != "GET":
                if not self.password:
                    raise RuntimeFailure("owned-host-session-unavailable")
                values["formPassword"] = self.password
        else:
            raise RuntimeFailure("app-principal-invalid")
        if headers_override:
            if set(headers_override) - {"Origin", "X-Crypta-App-Session"}:
                raise RuntimeFailure("app-header-override-invalid")
            headers.update(headers_override)
        data = urllib.parse.urlencode(values).encode() if method != "GET" else None
        if data and len(data) > 1024**2:
            raise RuntimeFailure("app-request-budget-exceeded")
        if data:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        request = urllib.request.Request(self.base + path, data=data, headers=headers, method=method)
        try:
            with absolute_deadline(self.supervisor.remaining(30)):
                try:
                    response = self.opener.open(request, timeout=25)
                except urllib.error.HTTPError as error:
                    response = error
                with response:
                    body = response.read(2 * 1024**2 + 1)
                    if len(body) > 2 * 1024**2:
                        raise RuntimeFailure("app-response-budget-exceeded")
                    if raw:
                        return response.status, body
                    value = {} if response.status == 204 and not body else json.loads(body)
                    if not isinstance(value, dict):
                        raise RuntimeFailure("app-response-shape-invalid")
                    return response.status, value
        except (OSError, ValueError, mail_demo.DemoFailure) as error:
            raise RuntimeFailure("private-app-http-failed") from error

    def host_bootstrap(self):
        status, raw = self.request("GET", "/app/node/", raw=True)
        parser = _BootstrapParser()
        parser.feed(raw.decode("utf-8"))
        if status != 200 or parser.count != 1:
            raise RuntimeFailure("owned-host-bootstrap-unavailable")
        value = json.loads("".join(parser.parts))
        password = value.get("formPassword")
        if not isinstance(password, str) or not password or len(password) > 4096:
            raise RuntimeFailure("owned-host-bootstrap-invalid")
        self.password = password

    def refresh_session(self):
        """Acquire a fresh ordinary bootstrap; no extended expiry or process credentials."""
        status, value = self.request("GET", "/apps/" + self.app_id + "/.well-known/cryptad-bootstrap.json")
        if status != 200:
            raise RuntimeFailure("own-app-bootstrap-failed")
        self.origin = mail_demo.target(value.get("uiOrigin"))
        self.session = value.get("browserSessionToken")
        self.session_expires_at = value.get("browserSessionExpiresAt")
        if not isinstance(self.session, str) or not self.session or len(self.session) > 4096:
            raise RuntimeFailure("own-app-bootstrap-invalid")
        if self.origin == self.base:
            raise RuntimeFailure("isolated-own-app-origin-required")
        return self

    def observe_worker(self):
        status, value = self.request("GET", "/api/v1/apps/" + self.app_id + "/runtime")
        runtime = value.get("runtime", {})
        if status != 200 or runtime.get("running") is not True:
            raise RuntimeFailure("app-child-not-running")
        sandbox = runtime.get("sandbox", {})
        if sandbox.get("provider") != "bubblewrap" or sandbox.get("active") is not True:
            raise RuntimeFailure("real-app-sandbox-not-observed")
        pid = runtime.get("pid")
        if type(pid) is not int:
            raise RuntimeFailure("app-child-pid-missing")
        expected = self.supervisor.nodes[self.role].runtime.process.pid
        cursor = pid
        for _ in range(64):
            if cursor == expected:
                self.worker_identity = process_identity(pid)
                if self.app_id == "mail-prototype":
                    expected_java = digest_file(self.supervisor.nodes[self.role].java_home / "bin/java")
                    found = False
                    for proc in Path("/proc").iterdir():
                        if not proc.name.isdigit():
                            continue
                        try:
                            child = int(proc.name)
                            if process_identity(child)["executableDigest"] != expected_java:
                                continue
                            cursor_child = child
                            for _ in range(64):
                                if cursor_child == pid:
                                    found = True
                                    break
                                fields_child = (Path("/proc") / str(cursor_child) / "stat").read_text().rsplit(")", 1)[1].split()
                                cursor_child = int(fields_child[1])
                                if cursor_child <= 1:
                                    break
                            if found:
                                break
                        except (OSError, ValueError):
                            continue
                    if not found:
                        raise RuntimeFailure("mail-java-child-not-observed")
                return
            fields = (Path("/proc") / str(cursor) / "stat").read_text().rsplit(")", 1)[1].split()
            cursor = int(fields[1])
            if cursor <= 1:
                break
        raise RuntimeFailure("app-child-not-owned")

    def mail_client(self):
        self.refresh_session()
        return ObservedMailClient(self.supervisor, self.api, self.origin, self.session, self.password)


def require_persistent_identity(requests, operation, uri):
    selected = [entry for entry in requests if entry.get("fields", {}).get("Identifier") == operation]
    if len(selected) != 1 or selected[0].get("name") != "PersistentGet":
        raise RuntimeFailure("persistent-original-request-missing-or-duplicate")
    fields = selected[0]["fields"]
    if fields.get("URI") != uri or fields.get("Persistence") != "forever" or fields.get("Global") != "false":
        raise RuntimeFailure("persistent-original-request-substituted")
    return selected[0]


def observe_partition_denial(receiver, operation, reference):
    """Require an actual bounded retrieval failure, never reinterpret protocol errors."""
    receiver.send("ClientGet", interop.build_client_get_fields(operation, reference, ignore_ds=True))
    frame = receiver.read_until(30, {"GetFailed", "AllData"})
    if frame.fields.get("Identifier") != operation:
        raise RuntimeFailure("partition-operation-binding-mismatch")
    return frame.name == "GetFailed" and frame.fields.get("Code") in {"13", "14", "28", "30"}


class _BoundedWireFile:
    """Apply strict frame budgets while retaining the existing interop FCP parser."""
    def __init__(self, stream):
        self.stream = stream
        self.header_bytes = 0
        self.fields = set()

    def readline(self):
        line = self.stream.readline(8193)
        self.header_bytes += len(line)
        if len(line) > 8192 or self.header_bytes > 65536:
            raise RuntimeFailure("fcp-header-budget-exceeded")
        if b"=" in line:
            key, value = line.rstrip(b"\n").split(b"=", 1)
            if key in self.fields:
                raise RuntimeFailure("fcp-duplicate-field")
            self.fields.add(key)
            if key == b"DataLength" and (not value.isdigit() or not 0 <= int(value) <= 1024**2):
                raise RuntimeFailure("fcp-payload-budget-exceeded")
        return line

    def read(self, length):
        if not 0 <= length <= 1024**2:
            raise RuntimeFailure("fcp-payload-budget-exceeded")
        return self.stream.read(length)


class BoundedFcpClient(interop.FcpClient):
    def __init__(self, *args, before_send=None):
        self.before_send = before_send
        super().__init__(*args)

    def send(self, name, fields, payload=None):
        if self.before_send is not None:
            self.before_send()
        self.expected_identifier = fields.get("Identifier")
        return super().send(name, fields, payload)

    def read_message(self, timeout):
        self.sock.settimeout(timeout)
        frame = interop.read_fcp_frame_from_file(_BoundedWireFile(self.file))
        observed = frame.fields.get("Identifier")
        expected = getattr(self, "expected_identifier", None)
        allowed = getattr(self, "allowed_identifiers", set())
        if ((observed is not None and expected is not None and observed != expected and observed not in allowed)
                or (frame.name in {"AllData", "PutSuccessful", "GetFailed", "PutFailed", "SubscribedUSK", "SubscribedUSKUpdate"} and observed != expected and observed not in allowed)):
            raise RuntimeFailure("fcp-operation-binding-mismatch")
        self._log_message("RECV", frame)
        return frame


class _ContinuedProcess:
    """Popen-compatible control only for exact authenticated owned process-start identity."""
    def __init__(self, identity):
        self.identity = identity
        self.pid = identity["pid"]

    def poll(self):
        try:
            if process_identity(self.pid) != self.identity:
                raise RuntimeFailure("continued-process-identity-mismatch")
            if os.getpgid(self.pid) != self.pid:
                raise RuntimeFailure("continued-process-group-mismatch")
            return None
        except FileNotFoundError:
            return 0

    def wait(self, timeout):
        deadline = time.monotonic() + timeout
        while self.poll() is None:
            if time.monotonic() >= deadline:
                raise subprocess.TimeoutExpired("owned-process", timeout)
            time.sleep(.1)
        return 0


@dataclass
class OwnedNode:
    role: str
    runtime: interop.NodeRuntime
    ports: interop.Ports
    distribution: Path
    java_home: Path
    identity: dict
    config_digest: str
    reference: dict | None = None


class Supervisor:
    """Control only processes created in one already leased, previously empty private root."""
    def __init__(self, plan, private_config, authorization, journal):
        self.plan, self.journal = plan, journal
        self.private = private_config
        self.authorization = authorization
        self.nodes = {}
        self.apps = {}
        self.app_staging = {}
        self.app_staging_identities = {}
        self.trust_paths = {}
        self.package_identities = {}
        self.daemon_identities = {}
        self.resume_pending_roles = set()
        self.orphaned_spawn = False
        self.prepared = {}
        self.operations = 0
        self.observed_operations = 0
        self.started = time.monotonic()
        self.deadline = self.started + authorization.get("maxSeconds", 0)
        self.root = Path(private_config.get("root", ""))
        self.owner_nonce = uuid.uuid4().hex
        self.outcomes = {}
        self.private_work = {}
        self.migration_observation = None
        self.recovery_observation = None
        self.catalog_observation = None
        self.catalog_prepared = None
        self.catalog_environment = {}
        self.budget_observation = None
        self.resource_observations = {"sampleCount": 0, "initial": {}, "latest": {}}
        self.recovery_cohort = None
        self.recovery_incomplete = False
        self.product_identities = None
        self.product_admission = None
        self.runner_admission = None
        self.canaries = []
        self.mail_origin_observations = {}
        self.mail_canary_observations = {}
        self.expiry_probe = None
        self._validate()
        if plan["producer"] != implementation_identity():
            raise RuntimeFailure("selected-runner-identity-mismatch")
        if plan["provenanceClass"] == "production-artifact-comparison":
            self.product_admission = (self.runner_admission.product_admission(plan, self.private)
                                      if self.runner_admission else authenticate_product_selection(plan, self.private))
            self.product_admission.bind_apps(plan)
            self.product_identities = self.product_admission.public_identities()
        self.prepare_catalog_selection()

    def _validate(self):
        if os.name != "posix" or not Path("/proc/sys/kernel/random/boot_id").is_file():
            raise RuntimeFailure("linux-supervisor-required")
        if self.plan.get("profile") not in {"bounded-live", "protected-long-live"} or self.plan.get("provenanceClass") not in {"source-build-comparison", "production-artifact-comparison"}:
            raise RuntimeFailure("protected-producer-admission-not-configured")
        if set(self.private) - {"migration", "productAdmission", "recovery", "budget", "catalog"} != {"root", "nodes"}:
            raise RuntimeFailure("private-config-fields-invalid")
        required = {"experimentId", "planDigest", "root", "maxSeconds", "maxOperations", "syntheticContent"}
        auth = self.authorization
        if (set(auth) - {"runtimeStateDigest", "migrationInputsDigest", "recoveryInputsDigest", "budgetInputsDigest", "catalogInputsDigest"} != required or auth["experimentId"] != self.plan["experimentId"]
                or auth["planDigest"] != canonical_digest(self.plan)
                or auth["syntheticContent"] is not True
                or type(auth["maxSeconds"]) is not int or not 30 <= auth["maxSeconds"] <= 432000
                or type(auth["maxOperations"]) is not int or not 1 <= auth["maxOperations"] <= 1000000
                or auth["maxSeconds"] < self.plan["requestedSeconds"]):
            raise RuntimeFailure("exact-topology-authorization-invalid")
        if (not self.root.is_absolute() or self.root.is_symlink() or not self.root.is_dir()
                or str(self.root.resolve()) != str(self.root) or auth["root"] != str(self.root)
                or self.root.stat().st_mode & 0o077 or self.root.stat().st_uid != os.geteuid()):
            raise RuntimeFailure("private-root-invalid")
        lock = getattr(self.journal, "_lock", None)
        if type(lock) is not int or getattr(self.journal, "root", None) != self.root:
            raise RuntimeFailure("exclusive-journal-lease-required")
        try:
            actual, expected = os.fstat(lock), (self.root / "lease").stat()
            if (actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino):
                raise RuntimeFailure("exclusive-journal-lease-required")
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            raise RuntimeFailure("exclusive-journal-lease-required") from error
        migration = self.private.get("migration")
        if migration is not None and auth.get("migrationInputsDigest") != canonical_digest(migration):
            raise RuntimeFailure("migration-selection-not-authorized")
        roles = {row["role"] for row in self.plan["nodes"]}
        if roles != set(ROLES) or set(self.private["nodes"]) != roles:
            raise RuntimeFailure("runtime-topology-unsupported")
        # This concrete adapter supports source/package comparison, not historical release authority.
        if any(row.get("product") != "cryptad" for row in self.plan["nodes"]):
            raise RuntimeFailure("runtime-product-adapter-unavailable")
        ports = []
        for row in self.private["nodes"].values():
            if set(row) != {"archivePath", "javaHome", "fnpPort", "fcpPort", "httpPort", "apps", "trustedKeysPath", "trustedKeysDigest"}:
                raise RuntimeFailure("private-node-fields-invalid")
            for field in ("archivePath", "javaHome"):
                path = Path(row[field])
                if not path.is_absolute() or path.is_symlink() or not path.exists():
                    raise RuntimeFailure("private-artifact-path-invalid")
            for field in ("fnpPort", "fcpPort", "httpPort"):
                value = row[field]
                if type(value) is not int or not 1024 <= value <= 65535:
                    raise RuntimeFailure("private-port-invalid")
                ports.append(value)
            apps = row["apps"]
            if not isinstance(apps, list) or len(apps) > 8:
                raise RuntimeFailure("private-app-set-invalid")
            selected = next(node for node in self.plan["nodes"] if self.private["nodes"][node["role"]] is row)
            if sorted(app["bundleDigest"] for app in apps) != sorted(selected["appDigests"]):
                raise RuntimeFailure("private-app-subject-set-mismatch")
            if len({app["appId"] for app in apps}) != len(apps):
                raise RuntimeFailure("private-app-duplicate")
            for app in apps:
                if set(app) != {"appId", "bundlePath", "bundleDigest"} or app["appId"] not in {"mail-prototype", "site-publisher", "feed-reader"}:
                    raise RuntimeFailure("private-app-adapter-unsupported")
            if selected["role"] in {"candidate-sender", "candidate-recipient"} and "mail-prototype" not in {app["appId"] for app in apps}:
                raise RuntimeFailure("mail-bundle-required")
            if apps and (not Path(row["trustedKeysPath"]).is_file() or Path(row["trustedKeysPath"]).is_symlink()
                         or digest_file(row["trustedKeysPath"]) != row["trustedKeysDigest"]):
                raise RuntimeFailure("private-app-trust-binding-mismatch")
        if len(set(ports)) != len(ports):
            raise RuntimeFailure("node-port-alias-rejected")
        validate_recovery_selection(self.plan, self.private, self.authorization)
        validate_budget_selection(self.plan, self.private, self.authorization)
        if (self.root / "runtime").is_symlink():
            raise RuntimeFailure("runtime-root-already-exists")
        if (self.root / "runtime").exists() and not getattr(self.journal, "resumed", False):
            raise RuntimeFailure("runtime-root-already-exists")
        if getattr(self.journal, "resumed", False) and "runtimeStateDigest" not in auth:
            raise RuntimeFailure("runtime-continuation-state-not-authorized")
        if self.plan["profile"] == "protected-long-live":
            self.runner_admission = authenticate_runner_selection(self.plan, self.private, self.authorization)

    def remaining(self, limit=180):
        self._check_resources()
        remaining = min(limit, self.deadline - time.monotonic())
        if getattr(self, "runner_admission", None) is not None:
            current = authenticate_runner_selection(self.plan, self.private, self.authorization)
            if current.public_identity() != self.runner_admission.public_identity():
                raise RuntimeFailure("protected-runner-authority-substitution")
            remaining = min(remaining, current.remaining_seconds())
        if remaining <= 0:
            raise RuntimeFailure("experiment-deadline-exceeded")
        return remaining

    def _check_resources(self):
        runtime_root = self.root / "runtime"
        total = 0
        if runtime_root.exists():
            for path in runtime_root.rglob("*.log"):
                if path.is_symlink():
                    raise RuntimeFailure("private-log-link-rejected")
                total += path.stat().st_size
            if total > MAX_LOG_BYTES:
                raise RuntimeFailure("private-log-budget-exceeded")

    def emit(self, kind, role="", scenario="", operation="", outcome="pass", counters=None, peer_role="", node_epoch=None, cohort=""):
        if kind == "operation" and outcome == "pass" and not cohort:
            self.observed_operations += 1
        self.journal.append(kind, role=role, scenario=scenario, operation=operation,
                            outcome=outcome, counters=counters or {}, peer_role=peer_role, node_epoch=node_epoch, cohort=cohort)

    def prepare(self):
        """Check every package/runtime before any selected executable may run."""
        runtime_root = self.root / "runtime"
        runtime_root.mkdir(mode=0o700)
        (runtime_root / "owner.json").write_text(json.dumps({"nonce": self.owner_nonce,
            "experimentId": self.plan["experimentId"]}), encoding="utf-8")
        (runtime_root / "owner.json").chmod(0o600)
        for selected in self.plan["nodes"]:
            private = self.private["nodes"][selected["role"]]
            archive = Path(private["archivePath"])
            if archive.stat().st_size != selected["artifactSize"] or digest_file(archive) != selected["artifactDigest"]:
                raise RuntimeFailure("artifact-roster-binding-mismatch")
            if tree_digest(private["javaHome"]) != selected["runtimeDigest"]:
                raise RuntimeFailure("runtime-roster-binding-mismatch")
            interop.ensure_tcp_port_available(private["fcpPort"])
            interop.ensure_udp_port_available(private["fnpPort"])
            interop.ensure_tcp_port_available(private["httpPort"])
            for app in private["apps"]:
                if digest_file(app["bundlePath"]) != app["bundleDigest"]:
                    raise RuntimeFailure("app-bundle-roster-binding-mismatch")
        for selected in self.plan["nodes"]:
            role = selected["role"]
            private = self.private["nodes"][role]
            home = runtime_root / role
            home.mkdir(mode=0o700)
            if private["apps"]:
                trust = home / "trusted-app-keys.properties"
                trust.write_bytes(Path(private["trustedKeysPath"]).read_bytes())
                trust.chmod(0o600)
                if digest_file(trust) != private["trustedKeysDigest"]:
                    raise RuntimeFailure("private-app-trust-binding-mismatch")
                self.trust_paths[role] = trust
            distribution = extract_package(private["archivePath"], home / "package", selected["artifactDigest"], selected["artifactSize"])
            self.package_identities[role] = tree_digest(distribution, require_java=False)
            build_version = None if not self.product_identities else next(row["buildVersion"] for row in self.product_identities if row["role"] == role)
            self.daemon_identities[role] = packaged_daemon_identity(distribution, selected["sourceCommit"], build_version)
            require_native_target(distribution, selected["packageTarget"], private["javaHome"])
            node_root = home / "node"
            ports = interop.Ports(private["fnpPort"], private["fcpPort"], 0, 0)
            config = make_runtime_config(node_root, ports, private["httpPort"])
            config_digest = config_identity(config, node_root, private["fnpPort"], private["fcpPort"], private["httpPort"], private["trustedKeysDigest"])
            for app in private["apps"]:
                staging = home / ("staged-" + app["appId"])
                extract_app_bundle(app["bundlePath"], staging, app["bundleDigest"])
                self.app_staging[(role, app["appId"])] = staging
                self.app_staging_identities[role + "/" + app["appId"]] = tree_digest(staging, require_java=False)
            if config_digest != selected["configDigest"]:
                raise RuntimeFailure("node-config-binding-mismatch")
            self.prepared[role] = (distribution, node_root, ports, Path(private["javaHome"]), config_digest)
        if self.daemon_identities["previous"] == self.daemon_identities["candidate-sender"]:
            raise RuntimeFailure("previous-repackages-current-daemon")
        # Different stores are established by owned filesystem objects, not URL comparisons.
        stores = [((entry[1] / "data/store").stat().st_dev, (entry[1] / "data/store").stat().st_ino)
                  for entry in self.prepared.values()]
        if len(set(stores)) != len(stores):
            raise RuntimeFailure("node-store-alias-rejected")

    def start(self, role):
        if role in self.nodes and self.nodes[role].runtime.process.poll() is None:
            raise RuntimeFailure("owned-node-already-running")
        distribution, node_root, ports, java_home, config_digest = self.prepared[role]
        # Reuse the packaged launcher contract, but do not inherit caller JVM/proxy/credential state.
        args = ["--config-file", str(node_root / "config/cryptad.ini")]
        for option, directory in (("config", "config"), ("data", "data"), ("cache", "cache"), ("run", "run"), ("logs", "logs")):
            args.extend(["--" + option + "-dir", str(node_root / directory)])
        command = [str(distribution / "bin/cryptad")]
        command.extend(f"wrapper.app.parameter.{i}={value}" for i, value in enumerate(args, 1))
        environment = {"PATH": str(java_home / "bin") + ":/usr/bin:/bin", "JAVA_HOME": str(java_home),
                       "HOME": str(node_root), "LANG": "C.UTF-8"}
        private = self.private["nodes"][role]
        if private["apps"]:
            environment["CRYPTAD_APPHOST_TRUSTED_KEYS_FILE"] = str(self.trust_paths[role])
            environment["CRYPTAD_APPHOST_SANDBOX_PROVIDER"] = "bubblewrap"
        if self.catalog_prepared is not None and role == self.catalog_prepared.role:
            for name, path in self.catalog_environment.items():
                expected = (self.catalog_prepared.baseline.catalog_keys_digest if name == "CRYPTAD_APPCATALOG_TRUSTED_KEYS_FILE"
                            else self.catalog_prepared.baseline.reviewer_keys_digest)
                if Path(path).is_symlink() or digest_file(path) != expected:
                    raise RuntimeFailure("catalog-staged-registry-substituted")
                environment[name] = path
        if os.geteuid() == 0:
            environment["CRYPTAD_ALLOW_ROOT"] = "1"
        stdout_path, stderr_path = node_root / "logs/stdout.log", node_root / "logs/stderr.log"
        stdout, stderr = stdout_path.open("ab"), stderr_path.open("ab")
        self.remaining(1)
        try:
            process = subprocess.Popen(command, cwd=node_root, env=environment, stdout=stdout, stderr=stderr,
                                       start_new_session=True)
        except BaseException:
            stdout.close()
            stderr.close()
            raise
        runtime = interop.NodeRuntime(role, node_root, node_root / "config/cryptad.ini", stdout_path,
                                      stderr_path, process, stdout, stderr)
        try:
            identity = process_identity(process.pid)
        except BaseException:
            # The unreaped Popen child cannot be PID-reused; clean up that exact spawned group.
            try:
                interop.terminate_node(runtime)
            except BaseException:
                self.orphaned_spawn = True
            raise
        node = OwnedNode(role, runtime, ports, distribution, java_home, identity, config_digest)
        self.nodes[role] = node
        self.emit("node-start", role, counters={"operations": 0}, node_epoch=node_epoch(self.nodes[role].identity))
        self.save_state()
        with absolute_deadline(self.remaining(180)):
            interop.wait_for_fcp("127.0.0.1", ports.cryptad_fcp, 170, [runtime])
            with self.client(role) as client:
                node.reference = interop.get_node_reference(client, "node-identity")
            # Launcher wrapper PID is not necessarily JVM PID. Verify an actual owned JVM descendant.
            java_digest = digest_file(java_home / "bin/java")
            descendants = []
            for proc in Path("/proc").iterdir():
                if not proc.name.isdigit():
                    continue
                try:
                    if os.getpgid(int(proc.name)) == process.pid:
                        observed = process_identity(int(proc.name))
                        if observed["executableDigest"] == java_digest:
                            descendants.append(observed)
                except (OSError, ValueError):
                    continue
            if len(descendants) != 1:
                raise RuntimeFailure("owned-java-process-identity-unobserved")
        node.identity = process_identity(process.pid)
        private_identity = {"supervisor": node.identity, "jvm": descendants[0], "configDigest": config_digest}
        path = node_root / "run/process-identity.json"
        path.write_text(json.dumps(private_identity, sort_keys=True), encoding="utf-8")
        path.chmod(0o600)
        self.save_state()
        return node

    @contextmanager
    def client(self, role, client_name=None, persistent_identifier=None):
        node = self.nodes[role]
        if node.runtime.process.poll() is not None:
            raise RuntimeFailure("owned-node-exited")
        client = BoundedFcpClient("127.0.0.1", node.ports.cryptad_fcp, client_name or "soak-" + uuid.uuid4().hex,
                                   node.runtime.base_dir / "logs/fcp.log", before_send=self.next_operation)
        if persistent_identifier:
            client.allowed_identifiers = {persistent_identifier}
        try:
            yield client
        finally:
            client.close()

    def connect(self):
        relay = self.nodes["relay-no-apps"]
        for role in ROLES[:-1]:
            node = self.nodes[role]
            with absolute_deadline(self.remaining(180)), self.client(role) as client, self.client(relay.role) as peer:
                interop.add_peer(client, "peer-add", relay.reference)
                interop.add_peer(peer, "peer-add", node.reference)
                interop.wait_for_peer_connection(client, "peer-check", relay.reference["identity"], 150)
                interop.wait_for_peer_connection(peer, "peer-check", node.reference["identity"], 150)

    def save_state(self):
        if not self.prepared or self.resume_pending_roles:
            return
        nodes = {}
        for role, node in self.nodes.items():
            nodes[role] = {"identity": node.identity, "running": node.runtime.process.poll() is None,
                           "reference": node.reference, "configDigest": node.config_digest,
                           "configFileDigest": digest_file(node.runtime.config_file),
                           "packageTreeDigest": self.package_identities[role]}
        state = {"schemaVersion": 1, "experimentId": self.plan["experimentId"],
                 "planDigest": canonical_digest(self.plan), "ownerNonce": self.owner_nonce,
                 "nodes": nodes, "outcomes": self.outcomes, "operations": self.operations,
                 "observedOperations": self.observed_operations,
                 "mailInitialized": "mail-delivery" in self.outcomes, "privateWork": self.private_work,
                 "migrationObservation": self.migration_observation, "recoveryObservation": self.recovery_observation,
                 "catalogObservation": self.catalog_observation, "budgetObservation": self.budget_observation, "resourceObservations": self.resource_observations, "appTrees": self.app_staging_identities, "privateCanaries": self.canaries,
                 "mailOriginObservations": self.mail_origin_observations, "mailCanaryObservations": self.mail_canary_observations}
        target = self.root / "runtime/runtime-state.json"
        temporary = target.with_suffix(".new")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(descriptor, "w") as stream:
                json.dump(state, stream, sort_keys=True, separators=(",", ":"))
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, target)
        finally:
            temporary.unlink(missing_ok=True)

    def resume_owned(self):
        """Re-admit exact owned resources only with explicit private checkpoint authorization."""
        path = self.root / "runtime/runtime-state.json"
        if (path.is_symlink() or not path.is_file() or path.stat().st_size > 1024**2
                or path.stat().st_mode & 0o077
                or digest_file(path) != self.authorization["runtimeStateDigest"]):
            raise RuntimeFailure("runtime-continuation-state-mismatch")
        state = json.loads(path.read_text())
        owner = json.loads((self.root / "runtime/owner.json").read_text())
        if (state.get("experimentId") != self.plan["experimentId"]
                or state.get("planDigest") != canonical_digest(self.plan)
                or state.get("ownerNonce") != owner.get("nonce")
                or set(state.get("nodes", {})) != set(ROLES)
                or state.get("mailInitialized") is not True):
            raise RuntimeFailure("runtime-continuation-incomplete-or-unbound")
        self.resume_pending_roles = set(ROLES)
        self.owner_nonce = state["ownerNonce"]
        self.operations = state["operations"]
        self.observed_operations = state["observedOperations"]
        self.outcomes = state["outcomes"]
        self.private_work = state.get("privateWork", {})
        self.migration_observation = state.get("migrationObservation")
        self.recovery_observation = state.get("recoveryObservation")
        self.catalog_observation = state.get("catalogObservation")
        self.budget_observation = state.get("budgetObservation")
        self.resource_observations = state.get("resourceObservations", {"sampleCount": 0, "initial": {}, "latest": {}})
        self.app_staging_identities = state.get("appTrees", {})
        self.canaries = state.get("privateCanaries", [])
        self.mail_origin_observations = state.get("mailOriginObservations", {})
        self.mail_canary_observations = state.get("mailCanaryObservations", {})
        for selected in self.plan["nodes"]:
            role = selected["role"]
            private = self.private["nodes"][role]
            home = self.root / "runtime" / role
            node_root = home / "node"
            distribution = home / "package"
            if not (distribution / "bin/cryptad").is_file():
                distribution /= "cryptad-dist"
            config = node_root / "config/cryptad.ini"
            observed_config = state["nodes"][role]["configDigest"]
            # Daemon-written normalized defaults are preserved at an exact private checkpoint.
            if observed_config != selected["configDigest"] or digest_file(config) != state["nodes"][role]["configFileDigest"]:
                raise RuntimeFailure("runtime-continuation-config-changed")
            self.package_identities[role] = tree_digest(distribution, require_java=False)
            if self.package_identities[role] != state["nodes"][role]["packageTreeDigest"]:
                raise RuntimeFailure("runtime-continuation-package-changed")
            ports = interop.Ports(private["fnpPort"], private["fcpPort"], 0, 0)
            self.prepared[role] = (distribution, node_root, ports, Path(private["javaHome"]), observed_config)
            if private["apps"]:
                self.trust_paths[role] = home / "trusted-app-keys.properties"
                if digest_file(self.trust_paths[role]) != private["trustedKeysDigest"]:
                    raise RuntimeFailure("runtime-continuation-trust-changed")
            saved = state["nodes"][role]
            if saved["running"]:
                process = _ContinuedProcess(saved["identity"])
                if process.poll() is not None:
                    raise RuntimeFailure("runtime-continuation-process-missing")
                stdout_path, stderr_path = node_root / "logs/stdout.log", node_root / "logs/stderr.log"
                runtime = interop.NodeRuntime(role, node_root, config, stdout_path, stderr_path, process,
                                              stdout_path.open("ab"), stderr_path.open("ab"))
                self.nodes[role] = OwnedNode(role, runtime, ports, distribution, Path(private["javaHome"]),
                                             saved["identity"], observed_config, saved["reference"])
                self.emit("node-start", role, counters={"operations": 0}, node_epoch=node_epoch(self.nodes[role].identity))
            else:
                self.start(role)
            probe = AppHandle(self, role, "mail-prototype")
            probe.host_bootstrap()
            status, contract = probe.request("GET", "/api/v1/platform/contract")
            selected_node = next(row for row in self.plan["nodes"] if row["role"] == role)
            if status != 200 or contract.get("contract", {}).get("contractVersion") != selected_node["contractVersion"]:
                raise RuntimeFailure("running-contract-roster-mismatch")
            status, inventory = probe.request("GET", "/api/v1/apps")
            installed = inventory.get("apps", [])
            if status != 200 or sorted(app.get("appId") for app in installed) != sorted(app["appId"] for app in private["apps"]):
                raise RuntimeFailure("runtime-continuation-app-inventory-changed")
            for app in private["apps"]:
                handle = AppHandle(self, role, app["appId"])
                handle.password = probe.password
                if not saved["running"]:
                    status, _ = handle.request("POST", "/api/v1/apps/" + app["appId"] + "/start")
                    if status != 200:
                        raise RuntimeFailure("runtime-continuation-app-start-failed")
                handle.observe_worker()
                handle.refresh_session()
                self.apps[(role, app["appId"])] = handle
                self.app_staging[(role, app["appId"])] = home / ("staged-" + app["appId"])
                self.app_subject(role, app["appId"])
            self.resume_pending_roles.remove(role)
        # New measured controller epoch; never initialize accounts or repeat send operations.
        for role in ("candidate-sender", "candidate-recipient"):
            client = self.apps[(role, "mail-prototype")].mail_client()
            with absolute_deadline(self.remaining(30)):
                status = client.command("status")
            if status.get("status") != "ready" or status.get("recovery") not in {None, "normal"}:
                raise RuntimeFailure("runtime-continuation-mail-not-active")
        self.save_state()

    def provision_apps(self):
        """Install exact signed staged bundles through normal AppHost verification and launch."""
        for role in ROLES:
            selected_apps = self.private["nodes"][role]["apps"]
            probe = AppHandle(self, role, "mail-prototype")
            probe.host_bootstrap()
            status, contract = probe.request("GET", "/api/v1/platform/contract")
            selected_node = next(row for row in self.plan["nodes"] if row["role"] == role)
            if status != 200 or contract.get("contract", {}).get("contractVersion") != selected_node["contractVersion"]:
                raise RuntimeFailure("running-contract-roster-mismatch")
            status, inventory = probe.request("GET", "/api/v1/apps")
            if status != 200 or inventory.get("apps") != []:
                raise RuntimeFailure("disposable-app-inventory-not-empty")
            for app in selected_apps:
                handle = AppHandle(self, role, app["appId"])
                handle.password = probe.password
                status, installed = handle.request("POST", "/api/v1/apps/install",
                    {"stagedDir": str(self.app_staging[(role, app["appId"])])})
                if status != 201 or installed.get("app", {}).get("appId") != app["appId"]:
                    raise RuntimeFailure("signed-app-install-not-admitted")
                status, _ = handle.request("POST", "/api/v1/apps/" + app["appId"] + "/start")
                if status not in (200, 201):
                    raise RuntimeFailure("signed-app-start-failed")
                handle.observe_worker()
                handle.refresh_session()
                self.apps[(role, app["appId"])] = handle
                self.app_subject(role, app["appId"])
            if role == "relay-no-apps":
                self.emit("operation", role, "relay-health", self.next_operation(), counters={"operations": 1})

    def app_session(self, role, app_id):
        """Private migration/Mail adapter handoff from admitted installed AppHost subjects."""
        handle = self.apps.get((role, app_id))
        if handle is None:
            raise RuntimeFailure("selected-app-not-admitted")
        handle.observe_worker()
        handle.refresh_session()
        return {"api": handle.api, "origin": handle.origin, "session": handle.session}

    def app_subject(self, role, app_id):
        """Exact signed installed app selected by normal admission, with private staged source."""
        if (role, app_id) not in self.apps:
            raise RuntimeFailure("selected-app-not-admitted")
        selected = next(app for app in self.private["nodes"][role]["apps"] if app["appId"] == app_id)
        staging = self.app_staging[(role, app_id)]
        installed = self.nodes[role].runtime.base_dir / "data/node/apps/installed" / app_id
        expected = self.app_staging_identities[role + "/" + app_id]
        if (tree_digest(staging, require_java=False) != expected
                or tree_digest(installed, require_java=False) != expected):
            raise RuntimeFailure("installed-app-subject-changed")
        return {"bundleDigest": selected["bundleDigest"], "stagedRoot": staging, "installedRoot": installed}

    def restart_app(self, role, app_id):
        handle = self.apps.get((role, app_id))
        if handle is None:
            raise RuntimeFailure("selected-app-not-admitted")
        self.scan_private_process_logs()
        for action in ("stop", "start"):
            status, _ = handle.request("POST", "/api/v1/apps/" + app_id + "/" + action)
            if status != 200:
                raise RuntimeFailure("app-restart-failed")
        handle.observe_worker()
        handle.refresh_session()

    def mail_delivery(self):
        alice = self.apps[("candidate-sender", "mail-prototype")]
        bob = self.apps[("candidate-recipient", "mail-prototype")]
        first = self.next_operation()
        self.canaries = ["SYNTHETIC-MAIL-CANARY-" + uuid.uuid4().hex, "SYNTHETIC-MAIL-REPLY-" + uuid.uuid4().hex]
        self.save_state()
        # Original demo holds CHK/cards/body comparisons in memory and retries original operation.
        with absolute_deadline(self.remaining(1800)):
            clients = (ObservedMailClient(self, alice.api, alice.origin, alice.session, alice.password),
                       ObservedMailClient(self, bob.api, bob.origin, bob.session, bob.password))
            result = mail_demo.run_flow(*clients, min(600, int(self.deadline - time.monotonic())), True,
                                        body=self.canaries[0], reply_body=self.canaries[1],
                                        before_restart=self.scan_private_process_logs)
        if result.get("overall") != "observed-demo":
            raise RuntimeFailure("mail-delivery-incomplete")
        alice.observe_worker()
        bob.observe_worker()
        vaults = []
        for role in ("candidate-sender", "candidate-recipient"):
            vault = self.nodes[role].runtime.base_dir / "data/node/apps/vault"
            if vault.is_symlink() or not vault.is_dir():
                raise RuntimeFailure("mail-vault-store-not-observed")
            observed = vault.stat()
            vaults.append((observed.st_dev, observed.st_ino))
        if len(set(vaults)) != 2:
            raise RuntimeFailure("mail-vault-store-alias-rejected")
        self.emit("operation", "candidate-sender", "mail-delivery", first, counters={"operations": 1}, peer_role="candidate-recipient")
        self.emit("operation", "candidate-recipient", "mail-delivery", self.next_operation(), counters={"operations": 1}, peer_role="candidate-sender")
        self.outcomes["mail-delivery"] = "observed"
        self.mail_origin_checks()
        self.scan_mail_surfaces()
        self.outcomes["mail-retry"] = "not-observed"

    def _scan_canaries(self, data):
        needles = [needle for value in self.canaries for needle in
                   (value.encode("utf-8"), base64.b64encode(value.encode("utf-8")))]
        if any(needle in data for needle in needles):
            self.mail_canary_observations["privacy"] = "failed"
            raise RuntimeFailure("private-canary-exposure-observed")

    def scan_private_process_logs(self):
        """Scan before worker replacement, which legitimately truncates its process log."""
        if not self.canaries:
            return
        total, count, consumed = 0, 0, 0
        for owned in self.nodes.values():
            roots = (owned.runtime.base_dir / "logs", owned.runtime.base_dir / "run/apps")
            for root in roots:
                if not root.exists():
                    continue
                for path in sorted(root.rglob("*")):
                    if path.is_symlink():
                        raise RuntimeFailure("private-log-link-rejected")
                    if path.is_dir():
                        continue
                    if not path.is_file():
                        raise RuntimeFailure("private-log-type-rejected")
                    count += 1
                    total += path.stat().st_size
                    if count > MAX_FILES or total > MAX_LOG_BYTES:
                        raise RuntimeFailure("private-log-budget-exceeded")
                    with path.open("rb") as stream:
                        tail = b""
                        while chunk := stream.read(65536):
                            consumed += len(chunk)
                            if consumed > MAX_LOG_BYTES:
                                raise RuntimeFailure("private-log-budget-exceeded")
                            self._scan_canaries(tail + chunk)
                            tail = chunk[-8192:]
        self.mail_canary_observations["processLogs"] = "observed" if count else "not-observed"

    def scan_mail_surfaces(self):
        if not self.canaries:
            return
        self.scan_private_process_logs()
        for role in ("candidate-sender", "candidate-recipient"):
            handle = self.apps.get((role, "mail-prototype"))
            if not handle:
                continue
            surfaces = {"appLogs": "/api/v1/apps/mail-prototype/logs",
                        "audit": "/api/v1/apps/mail-prototype/audit",
                        "support": "/api/v1/operator/support-bundle",
                        "queue": "/api/v1/queue", "diagnostics": "/api/v1/diagnostics"}
            for name, route in surfaces.items():
                self.next_operation()
                status, body = handle.request("GET", route, raw=True)
                self._scan_canaries(body)
                key = role + ":" + name
                previous = self.mail_canary_observations.get(key)
                current = "observed" if status == 200 else "not-observed"
                self.mail_canary_observations[key] = "not-observed" if previous == "not-observed" else current
        # Successful collection does not establish privacy of every collector failure path.
        self.mail_canary_observations["collectorFailurePaths"] = "not-observed"
        self.outcomes["mail-canary"] = "partial"

    def mail_origin_checks(self):
        for role in ("candidate-sender", "candidate-recipient"):
            handle = self.apps.get((role, "mail-prototype"))
            sibling = self.apps.get((role, "site-publisher"))
            for name in ("siblingOrigin", "wrongApp", "expiredBrowserSession", "staleProcessLaunchToken", "decryptionSideEffects"):
                self.mail_origin_observations[role + ":" + name] = "not-observed"
            if handle is None or sibling is None:
                continue
            sibling.refresh_session()
            parameters = {"command": "status", "payloadBase64": "e30="}
            for name, headers in (("siblingOrigin", {"Origin": sibling.origin}),
                                  ("wrongApp", {"Origin": sibling.origin, "X-Crypta-App-Session": sibling.session})):
                self.next_operation()
                status, body = handle.request("POST", "/api/v1/mail/command", parameters,
                                               principal="app", raw=True, headers_override=headers)
                self._scan_canaries(body)
                if status not in {401, 403}:
                    raise RuntimeFailure("mail-own-app-origin-denial-not-observed")
                self.mail_origin_observations[role + ":" + name] = "observed"
        # Browser sessions bind installed bundle/origin and survive worker replacement by design.
        self.outcomes["mail-origin"] = "partial"

    def begin_mail_expiry_probe(self):
        handle = self.apps[("candidate-recipient", "mail-prototype")]
        handle.refresh_session()
        value = handle.session_expires_at
        try:
            expires = dt.datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
        except (AttributeError, TypeError, ValueError):
            return
        now = time.time()
        if expires <= now:
            raise RuntimeFailure("fresh-browser-session-already-expired")
        self.next_operation()
        with absolute_deadline(self.remaining(30)):
            ObservedMailClient(self, handle.api, handle.origin, handle.session).command("status")
        self.expiry_probe = {"session": handle.session, "origin": handle.origin, "expires": expires,
                             "remaining": expires - now, "started": time.monotonic(),
                             "lastGood": time.monotonic(), "identity": dict(self.nodes[handle.role].identity)}

    def observe_mail_expiry(self):
        probe = self.expiry_probe
        if not probe:
            return
        handle = self.apps[("candidate-recipient", "mail-prototype")]
        if self.nodes[handle.role].identity != probe["identity"]:
            self.expiry_probe = None
            return
        monotonic = time.monotonic()
        if time.time() < probe["expires"]:
            self.next_operation()
            with absolute_deadline(self.remaining(30)):
                ObservedMailClient(self, handle.api, probe["origin"], probe["session"]).command("status")
            probe["lastGood"] = monotonic
            return
        if monotonic - probe["started"] < probe["remaining"]:
            raise RuntimeFailure("browser-expiry-clock-discontinuity")
        self.next_operation()
        status, body = handle.request("POST", "/api/v1/mail/command",
                                       {"command": "status", "payloadBase64": "e30="}, principal="app", raw=True,
                                       headers_override={"Origin": probe["origin"], "X-Crypta-App-Session": probe["session"]})
        self._scan_canaries(body)
        if status not in {401, 403}:
            raise RuntimeFailure("expired-browser-session-denial-not-observed")
        if monotonic - probe["lastGood"] <= self.plan["policy"]["maxGapSeconds"]:
            self.mail_origin_observations["candidate-recipient:expiredBrowserSession"] = "observed"
        self.expiry_probe = None

    def next_operation(self):
        if getattr(self, "runner_admission", None) is not None:
            self.remaining(1)
        self.operations += 1
        if self.operations > self.authorization["maxOperations"]:
            raise RuntimeFailure("operation-budget-exceeded")
        return "op-" + uuid.uuid4().hex

    def content(self, source, recipient, scenario="network-chk"):
        operation = self.next_operation()
        payload = ("PUBLIC SYNTHETIC CROSS-VERSION " + uuid.uuid4().hex).encode("ascii")
        uri = "CHK@"
        with absolute_deadline(self.remaining(180)), self.client(source) as sender, self.client(recipient) as receiver:
            if scenario != "network-chk":
                insert, request = interop.generate_ssk(sender, operation + "-keys")
                if scenario == "network-ssk":
                    uri = interop.ssk_with_name(insert, operation)
                else:
                    uri = interop.usk_from_ssk(insert, operation, 0)
            reference = interop.put_and_wait_for_success(sender, operation + "-insert", uri, payload, "text/plain",
                                                         local_request_only=True)
            actual = interop.fetch_direct(receiver, operation + "-fetch", reference, 120, ignore_ds=True)
            if actual != payload:
                raise RuntimeFailure("cross-node-content-mismatch")
            if scenario == "network-usk":
                later = payload + b" edition-one"
                edition = interop.usk_from_ssk(insert, operation, 1)
                reference = interop.put_and_wait_for_success(sender, operation + "-later", edition, later, "text/plain",
                                                             local_request_only=True)
                if interop.fetch_direct(receiver, operation + "-later-fetch", reference, 120, ignore_ds=True) != later:
                    raise RuntimeFailure("cross-node-content-mismatch")
        self.emit("operation", source, scenario, operation, counters={"bytes": len(payload), "operations": 1}, peer_role=recipient)

        self.outcomes[scenario] = "observed"

    def stop(self, role):
        node = self.nodes.get(role)
        if node is None:
            return
        if node.runtime.process.poll() is not None:
            node.runtime.stdout_handle.close()
            node.runtime.stderr_handle.close()
            try:
                os.killpg(node.runtime.process.pid, 0)
            except ProcessLookupError:
                self.emit("node-stop", role)
                return
            raise RuntimeFailure("owned-process-group-remains")
        if any(process_identity(node.runtime.process.pid)[key] != node.identity[key] for key in ("pid", "startTicks", "bootId")):
            raise RuntimeFailure("owned-process-identity-changed")
        interop.terminate_node(node.runtime)
        try:
            os.killpg(node.runtime.process.pid, 0)
        except ProcessLookupError:
            self.emit("node-stop", role)
            return
        raise RuntimeFailure("owned-process-group-remains")

    def migrate_synthetic(self):
        selection = self.private.get("migration")
        if selection is None:
            self.outcomes["migration-runtime"] = "not-observed"
            return
        # An interrupted converter/import has its own private workdir and cannot be rerun blindly.
        if self.migration_observation is not None or "migrationStarted" in self.private_work:
            self.outcomes["migration-runtime"] = "partial"
            return
        validate_migration_selection(selection)
        role = selection["role"]
        if (role, "site-publisher") not in self.apps or (selection["recoveryRole"] is not None
                and (selection["recoveryRole"], "site-publisher") not in self.apps):
            raise RuntimeFailure("migration-signed-app-not-admitted")
        root = Path(__file__).resolve().parents[2]
        subject = self.app_subject(role, "site-publisher")
        controller = subject["installedRoot"] / "static/drafts.js"
        operation = self.next_operation()
        self.private_work["migrationStarted"] = operation
        self.save_state()
        with fixed_helper_imports():
            module = fixed_helper("sharesite_observation")
            converter = Path(selection["toolRoot"]) / "bin/crypta-app"
            inputs = module.MigrationInputs(role=role, converter=converter, converter_digest=digest_file(converter),
                node_executable=Path(selection["nodeExecutable"]), node_digest=selection["nodeDigest"],
                controller=controller, controller_digest=digest_file(controller),
                fixture=root / "platform-devtools/src/test/resources/network/crypta/platform/devtools/migration/sharesite/upstream-mixed.db",
                private_root=self.root / "runtime", tool_root=Path(selection["toolRoot"]),
                tool_tree_digest=selection["toolTreeDigest"], java_home=Path(selection["javaHome"]),
                java_tree_digest=selection["javaTreeDigest"],
                driver_digest=digest_file(root / "tools/release-certification/protected/sharesite_runtime_driver.cjs"),
                recovery_role=selection["recoveryRole"])
            # Each helper has its own process-group deadline. Supervisory HTTP/restart controls
            # additionally enforce the remaining experiment deadline; no nested SIGALRM timer.
            producer = module.observe_synthetic if selection.get("dataClass", "upstream-writer-synthetic") == "upstream-writer-synthetic" else module.observe_operator_private
            self.migration_observation = producer(self, inputs)
            self.migration_observation.update(planDigest=canonical_digest(self.plan), bundleDigest=subject["bundleDigest"])
            module.validate_observation(self.migration_observation)
        self.save_state()
        if self.migration_observation["status"] == "failed":
            self.emit("operation", role, "migration-runtime", operation, outcome="fail")
            raise RuntimeFailure("migration-runtime-failed")
        # Partial producer coverage remains partial at the complete required migration gate.
        self.emit("operation", role, "migration-runtime", operation, outcome="partial")
        self.outcomes["migration-runtime"] = "partial"

    def prepare_catalog_selection(self):
        selection = self.private.get("catalog")
        declared = self.plan.get("workloadInputs", {}).get("catalog")
        if selection is None:
            if declared is not None or self.authorization.get("catalogInputsDigest") is not None:
                raise RuntimeFailure("catalog-declared-without-private-selection")
            return
        binding = canonical_digest(selection)
        if declared != binding or self.authorization.get("catalogInputsDigest") != binding:
            raise RuntimeFailure("catalog-selection-not-authorized")
        with fixed_helper_imports():
            module = fixed_helper("cross_version_catalog")
            private = self.root / "catalog-preflight"
            if private.is_symlink():
                raise RuntimeFailure("catalog-private-root-invalid")
            private.mkdir(mode=0o700, exist_ok=True)
            self.catalog_prepared = module.preflight_selection(selection, expected_digest=binding,
                private_root=private, remaining=self.remaining)
        prepared = self.catalog_prepared
        node = self.private["nodes"][prepared.role]
        if node["trustedKeysDigest"] != prepared.baseline.publisher_keys_digest or not any(
                app["appId"] == prepared.baseline.app_id and app["bundleDigest"] == prepared.baseline.bundle_digest for app in node["apps"]):
            raise RuntimeFailure("catalog-existing-publisher-or-app-mismatch")
        for name, source in prepared.daemon_environment().items():
            target = private / ("catalog.keys" if name == "CRYPTAD_APPCATALOG_TRUSTED_KEYS_FILE" else "reviewer.keys")
            expected = prepared.baseline.catalog_keys_digest if name == "CRYPTAD_APPCATALOG_TRUSTED_KEYS_FILE" else prepared.baseline.reviewer_keys_digest
            if target.is_symlink():
                raise RuntimeFailure("catalog-staged-registry-substituted")
            if not target.exists():
                descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(Path(source).read_bytes())
            if digest_file(target) != expected:
                raise RuntimeFailure("catalog-staged-registry-substituted")
            self.catalog_environment[name] = str(target)

    def catalog_route_allowed(self, role, app_id, method, path):
        selected = self.catalog_prepared
        if selected is None or role != selected.role or app_id != selected.baseline.app_id:
            return False
        if (method, path) in {("GET", "/api/v1/app-catalogs"), ("POST", "/api/v1/app-catalogs/add")}:
            return True
        for fixture in (selected.baseline, selected.other_catalog):
            if fixture is None:
                continue
            base = "/api/v1/app-catalogs/" + fixture.catalog_id
            if (method, path) in {("DELETE", base), ("GET", base + "/operations/health"),
                                  ("POST", base + "/refresh"), ("POST", base + "/mirrors"),
                                  ("POST", base + "/apps/" + selected.baseline.app_id + "/update")}:
                return True
        return False

    def catalog_request(self, role, method, path, form=None):
        selected = self.catalog_prepared
        if selected is None or not self.catalog_route_allowed(role, selected.baseline.app_id, method, path):
            raise RuntimeFailure("catalog-route-not-authorized")
        return self.apps[(role, selected.baseline.app_id)].request(method, path, form)

    def stop_app(self, role, app_id):
        if self.catalog_prepared is None or (role, app_id) != (self.catalog_prepared.role, self.catalog_prepared.baseline.app_id):
            raise RuntimeFailure("catalog-app-control-not-authorized")
        status, _ = self.apps[(role, app_id)].request("POST", "/api/v1/apps/" + app_id + "/stop")
        if status != 200:
            raise RuntimeFailure("catalog-app-stop-failed")

    def start_app(self, role, app_id):
        if self.catalog_prepared is None or (role, app_id) != (self.catalog_prepared.role, self.catalog_prepared.baseline.app_id):
            raise RuntimeFailure("catalog-app-control-not-authorized")
        self.app_subject(role, app_id)
        handle = self.apps[(role, app_id)]
        status, _ = handle.request("POST", "/api/v1/apps/" + app_id + "/start")
        if status != 200:
            raise RuntimeFailure("catalog-app-start-failed")
        handle.observe_worker()
        handle.refresh_session()

    def catalog_scenarios(self):
        if self.catalog_prepared is None:
            return
        if self.catalog_observation is not None:
            self.outcomes["catalog-provenance"] = "partial"
            return
        if "catalogStarted" in self.private_work:
            raise RuntimeFailure("catalog-interrupted-reconciliation-required")
        operation = self.next_operation()
        self.private_work["catalogStarted"] = operation
        self.save_state()
        self.catalog_observation = self.catalog_prepared.run(self)
        self.save_state()
        outcome = "fail" if self.catalog_observation["status"] == "failed" else "partial"
        self.outcomes["catalog-provenance"] = outcome
        self.emit("operation", self.catalog_prepared.role, "catalog-provenance", operation, outcome=outcome)
        if outcome == "fail":
            raise RuntimeFailure("catalog-runtime-incomplete")

    def sample_app_lifecycle(self):
        """Observe every selected app before stamping any role's recurring coverage."""
        expected = {(role, app["appId"]) for role, node in self.private["nodes"].items() for app in node["apps"]}
        counts = {node["role"]: len(node["appDigests"]) for node in self.plan["nodes"]}
        if (set(self.apps) != expected or set(counts) != set(self.private["nodes"])
                or any(sum(1 for selected_role, _app in expected if selected_role == role) != count
                       for role, count in counts.items())):
            raise RuntimeFailure("periodic-app-roster-mismatch")
        for role, app_id in sorted(expected):
            handle = self.apps[(role, app_id)]
            self.app_subject(role, app_id)
            handle.observe_worker()
            handle.refresh_session()
            if app_id == "mail-prototype":
                with absolute_deadline(self.remaining(30)):
                    status = ObservedMailClient(self, handle.api, handle.origin, handle.session).command("status")
                if status.get("status") != "ready" or status.get("recovery") not in {None, "normal"}:
                    raise RuntimeFailure("mail-continuing-health-not-ready")
        for role, count in sorted(counts.items()):
            if count:
                self.emit("sample", role, "app-lifecycle", counters={"operations": count})

    def sample_resources(self):
        """Observe all owned JVMs independently of optional foreground quota stress."""
        if set(self.nodes) != {node["role"] for node in self.plan["nodes"]}:
            raise RuntimeFailure("periodic-resource-roster-mismatch")
        measured = {}
        with fixed_helper_imports():
            module = fixed_helper("cross_version_budget")
            for role, node in self.nodes.items():
                path = node.runtime.config_file.parent.parent / "run/process-identity.json"
                if path.is_symlink() or path.stat().st_mode & 0o077 or path.stat().st_uid != os.getuid() or path.stat().st_size > 4096:
                    raise RuntimeFailure("resource-private-jvm-identity-invalid")
                identity = json.loads(path.read_bytes())
                if identity.get("supervisor") != node.identity:
                    raise RuntimeFailure("resource-private-supervisor-substituted")
                measured[role] = module.measure_resources(identity["jvm"], self.apps.get((role, "feed-reader")),
                    jvm_executable_digest=digest_file(node.java_home / "bin/java"))
        if not self.resource_observations["initial"]:
            self.resource_observations["initial"] = measured
        self.resource_observations["latest"] = measured
        self.resource_observations["sampleCount"] += 1
        for role, report in measured.items():
            counters = {key: value for key, value in report["metrics"].items() if value is not None}
            if all(type(counters.get(key)) is int and counters[key] > 0 for key in ("memoryBytes", "threads", "fileDescriptors")):
                self.emit("sample", role, "app-budgets", counters=counters)
            else:
                self.emit("operation", role, "app-budgets", self.next_operation(), outcome="partial", counters=counters)

    def budget_scenarios(self):
        selection = self.private.get("budget")
        if selection is None:
            return
        if self.budget_observation is not None:
            self.outcomes["app-budgets"] = "partial"
            return
        if "budgetStarted" in self.private_work:
            raise RuntimeFailure("budget-interrupted-reconciliation-required")
        validate_budget_selection(self.plan, self.private, self.authorization)
        # Reserve room for normal AppHost bootstrap/resource/FCP controls before doing work.
        if self.authorization["maxOperations"] - self.operations < 64 or self.remaining(400) < 365:
            raise RuntimeFailure("budget-scenario-capacity-unavailable")
        operation = self.next_operation()
        self.private_work["budgetStarted"] = operation
        self.save_state()
        handle = self.apps[(selection["role"], "feed-reader")]
        handle.observe_worker()
        handle.refresh_session()
        self.sample_resources()
        payload = ("PUBLIC SYNTHETIC BUDGET " + uuid.uuid4().hex).encode("ascii")
        with absolute_deadline(self.remaining(170)), self.client("previous") as source:
            reference = interop.put_and_wait_for_success(source, operation + "-budget-fixture", "CHK@", payload,
                "text/plain", local_request_only=True)
        # Charge the entire bounded request allowance before entering the child. Unknown
        # child outcome retains that charge and never automatically repeats the experiment.
        if self.authorization["maxOperations"] - self.operations < 38 or self.remaining(185) < 185:
            raise RuntimeFailure("budget-http-capacity-unavailable")
        self.operations += 38
        self.save_state()
        activation = None
        if self.plan["profile"] == "protected-long-live":
            self.remaining(185)
            activation = digest_file(Path("/var/lib/cryptad-cross-version-authority/activation.json"))
        with fixed_helper_imports():
            module = fixed_helper("cross_version_budget")
            self.budget_observation = module.observe_budget(handle, reference, payload,
                selection["nodeExecutable"], selection["nodeDigest"], lambda: self.remaining(185), activation_digest=activation)
        self.operations -= 38 - self.budget_observation["requestCount"]
        self.sample_resources()
        self.save_state()
        outcome = "fail" if self.budget_observation["status"] == "fail" else "partial"
        self.emit("operation", selection["role"], "app-budgets", operation, outcome=outcome,
                  counters={"operations": self.budget_observation["requestCount"]})
        self.outcomes["app-budgets"] = outcome
        if outcome == "fail":
            raise RuntimeFailure("budget-foreground-observation-failed")

    def recovery_scenarios(self):
        selection = self.private.get("recovery")
        if selection is None:
            return
        if self.recovery_observation is not None:
            self.outcomes["daemon-upgrade"] = "partial"
            return
        if "recoveryStarted" in self.private_work:
            self.recovery_incomplete = True
            raise RuntimeFailure("recovery-interrupted-reconciliation-required")
        validate_recovery_selection(self.plan, self.private, self.authorization)
        validate_budget_selection(self.plan, self.private, self.authorization)
        self.private_work["recoveryStarted"] = self.next_operation()
        self.save_state()

        def scoped(kind, *, cohort_id, subject_role, scenario, operation, outcome, counters, node_epoch):
            self.emit(kind, role=subject_role, scenario=scenario, operation=operation, outcome=outcome,
                      counters=counters, node_epoch=node_epoch, cohort=cohort_id)

        with fixed_helper_imports():
            module = fixed_helper("cross_version_recovery")
            self.recovery_cohort = module.OwnedRecoveryCohort(self, selection, scoped)
            self.recovery_observation = module.observe_upgrade(self.recovery_cohort)
        self.recovery_incomplete = self.recovery_observation["cleanup"] != "observed"
        self.save_state()
        self.outcomes["daemon-upgrade"] = "partial"
        if self.recovery_observation["status"] == "failed":
            raise RuntimeFailure("isolated-recovery-observation-failed")

    def stable_api_scenarios(self):
        with fixed_helper_imports():
            adapter = fixed_helper("cross_version_app_scenarios")
            for role in ("candidate-sender", "previous"):
                result = adapter.stable_api(self, role)
                if result["status"] == "observed":
                    self.emit("operation", role, "stable-api-runtime", self.next_operation(), counters={"operations": 1})
                    self.outcomes["stable-api-runtime:" + role] = "observed"
                elif result["status"] == "failed":
                    self.emit("operation", role, "stable-api-runtime", self.next_operation(), outcome="fail")
                    raise RuntimeFailure("stable-api-runtime-failed")
                else:
                    self.outcomes["stable-api-runtime:" + role] = "not-observed"

    def subscribe(self, source, recipient):
        """Observe a later edition on an open subscription; fetch fallback is a separate result."""
        operation = self.next_operation()
        payload = ("PUBLIC SYNTHETIC SUBSCRIPTION " + uuid.uuid4().hex).encode()
        with absolute_deadline(self.remaining(360)), self.client(source) as sender, self.client(recipient) as subscriber:
            insert, request = interop.generate_ssk(sender, operation + "-keys")
            initial_insert = interop.usk_from_ssk(insert, operation, 0)
            initial_request = interop.usk_from_ssk(request, operation, 0)
            interop.put_and_wait_for_success(sender, operation + "-initial", initial_insert, payload,
                                             "text/plain", local_request_only=True, uri_fallback=initial_request)
            with self.client(recipient) as fetcher:
                if interop.fetch_direct(fetcher, operation + "-initial-fetch", initial_request, 90, ignore_ds=True) != payload:
                    raise RuntimeFailure("subscription-initial-content-mismatch")
            subscriber.send("SubscribeUSK", {"Identifier": operation, "URI": initial_request,
                "DontPoll": "false", "SparsePoll": "true", "PriorityClass": "2",
                "PriorityClassProgress": "1", "RealTimeFlag": "true", "IgnoreUSKDatehints": "true"})
            acknowledgement = subscriber.read_until(30, {"SubscribedUSK"})
            if acknowledgement.fields.get("Identifier") != operation:
                raise RuntimeFailure("subscription-operation-binding-mismatch")
            subscriber.allowed_identifiers = {operation}
            try:
                # Keep this exact connection subscribed while ordinary core health remains observed.
                hold_until = time.monotonic() + min(30, max(2, self.plan["probeIntervalSeconds"]))
                while time.monotonic() < hold_until:
                    with self.client("relay-no-apps") as control:
                        interop.get_node_reference(control, "subscription-core-health")
                    time.sleep(min(1, max(0, hold_until - time.monotonic())))
                later_payload = payload + b" later-edition"
                later_insert = interop.usk_from_ssk(insert, operation, 1)
                later_request = interop.usk_from_ssk(request, operation, 1)
                interop.put_and_wait_for_success(sender, operation + "-later", later_insert, later_payload,
                                                 "text/plain", local_request_only=True, uri_fallback=later_request)
                edition, counts, _frames = interop.wait_for_subscription_update(subscriber, operation, 1,
                                                                               min(120, int(self.remaining(120))), 5)
                notified = edition is not None and edition >= 1 and counts.get("SubscribedUSKUpdate", 0) > 0
                with self.client(recipient) as fetcher:
                    fetched = interop.fetch_direct(fetcher, operation + "-later-fetch", later_request, 90, ignore_ds=True)
                    if fetched != later_payload:
                        raise RuntimeFailure("subscription-later-content-mismatch")
                if notified:
                    self.emit("operation", source, "network-subscription", operation,
                              counters={"operations": 1, "bytes": len(later_payload)}, peer_role=recipient)
                else:
                    self.emit("operation", source, "network-subscription", operation, outcome="not-observed",
                              counters={"operations": 0}, peer_role=recipient)
                self.outcomes["network-subscription:" + source + ":" + recipient] = (
                    "notification-observed" if notified else "fetch-observed-not-notification")
                directions = ("network-subscription:candidate-sender:previous", "network-subscription:previous:candidate-recipient")
                self.outcomes["network-subscription"] = "observed" if all(self.outcomes.get(key) == "notification-observed" for key in directions) else "partial"
            finally:
                subscriber.send("UnsubscribeUSK", {"Identifier": operation})

    def persistent_replay(self):
        """Restart an actual unpublished future-USK request and complete its original identity."""
        if self.outcomes.get("persistent-request-restart") == "observed":
            return
        role, source = "candidate-sender", "previous"
        state = self.private_work.get("persistentReplay")
        if state is None:
            operation = self.next_operation()
            with absolute_deadline(self.remaining(60)), self.client(source) as sender:
                insert, request = interop.generate_ssk(sender, operation + "-keys")
            state = {"operation": operation, "clientName": "soak-persistent-" + uuid.uuid4().hex,
                     "insert": interop.usk_from_ssk(insert, operation, 0),
                     "request": interop.usk_from_ssk(request, operation, 0),
                     "payload": base64.b64encode(("PUBLIC SYNTHETIC PERSISTENT " + uuid.uuid4().hex).encode()).decode(),
                     "phase": "prepared"}
            self.private_work["persistentReplay"] = state
            self.save_state()
            with absolute_deadline(self.remaining(60)), self.client(role, state["clientName"], operation) as pending:
                pending.send("ClientGet", interop.build_persistent_replay_get_fields(operation, state["request"]))
                requests = interop.wait_for_persistent_request_present(pending, operation, 30)
                require_persistent_identity(requests, operation, state["request"])
            state["phase"] = "queued"
            self.save_state()
        operation = state["operation"]
        if state["phase"] == "prepared":
            # Unknown enqueue outcome: query the original identity; never create replacement work.
            with absolute_deadline(self.remaining(60)), self.client(role, state["clientName"], operation) as pending:
                requests = interop.list_persistent_requests(pending, operation + "-reconcile")
                require_persistent_identity(requests, operation, state["request"])
            state["phase"] = "queued"
            self.save_state()
        if state["phase"] == "queued":
            self.emit("fault", role, "persistent-request-restart", operation)
            self.restart_node(role)
            with absolute_deadline(self.remaining(60)), self.client(role, state["clientName"], operation) as pending:
                requests = interop.list_persistent_requests(pending, operation + "-after-restart")
                require_persistent_identity(requests, operation, state["request"])
            state["phase"] = "restarted"
            self.save_state()
        if state["phase"] not in {"restarted", "published", "received", "removed"}:
            raise RuntimeFailure("persistent-checkpoint-phase-invalid")
        payload = base64.b64decode(state["payload"], validate=True)
        if state["phase"] in {"restarted", "published"}:
            with absolute_deadline(self.remaining(300)), self.client(role, state["clientName"], operation) as pending:
                if state["phase"] == "restarted":
                    # Repeating this exact signed edition after uncertain insert cannot reseal/change bytes.
                    with self.client(source) as sender:
                        interop.put_and_wait_for_success(sender, operation + "-publish", state["insert"], payload,
                                                        "text/plain", local_request_only=False, uri_fallback=state["request"])
                    state["phase"] = "published"
                    self.save_state()
                pending.expected_identifier = operation
                interop.request_persistent_get_data(pending, operation)
                actual = interop.read_persistent_get_payload(pending, operation, 240)
                if actual != payload:
                    raise RuntimeFailure("persistent-replay-content-mismatch")
                requests = interop.list_persistent_requests(pending, operation + "-completed")
                require_persistent_identity(requests, operation, state["request"])
            state["phase"] = "received"
            self.save_state()
        if state["phase"] == "received":
            with absolute_deadline(self.remaining(60)), self.client(role, state["clientName"], operation) as pending:
                removal = interop.remove_persistent_request(pending, operation)
                if removal != "removed":
                    raise RuntimeFailure("persistent-owned-request-cleanup-unobserved")
            state["phase"] = "removed"
            self.save_state()
        self.emit("recovery", role, "persistent-request-restart", operation, counters={"operations": 1})
        self.emit("operation", role, "persistent-request-restart", operation, counters={"operations": 1, "bytes": len(payload)})
        self.outcomes["persistent-request-restart"] = "observed"
        del self.private_work["persistentReplay"]
        self.save_state()

    def restart_node(self, role):
        """Restart one explicitly owned daemon and recover its existing app installations."""
        if role not in ROLES:
            raise RuntimeFailure("restart-role-not-owned")
        self.scan_private_process_logs()
        self.stop(role)
        self.start(role)
        peers = ROLES[:-1] if role == "relay-no-apps" else ("relay-no-apps",)
        for peer in peers:
            with absolute_deadline(self.remaining(180)), self.client(role) as client:
                interop.wait_for_peer_connection(client, "restart-peer", self.nodes[peer].reference["identity"], 150)
        for (app_role, app_id), handle in self.apps.items():
            if app_role != role:
                continue
            handle.host_bootstrap()
            status, value = handle.request("GET", "/api/v1/apps/" + app_id + "/runtime")
            if status != 200:
                raise RuntimeFailure("app-after-daemon-restart-failed")
            if not value.get("runtime", {}).get("running"):
                status, _ = handle.request("POST", "/api/v1/apps/" + app_id + "/start")
                if status != 200:
                    raise RuntimeFailure("app-after-daemon-restart-failed")
            handle.observe_worker()
            handle.refresh_session()
        self.save_state()

    def restart(self):
        role = "candidate-recipient"
        operation = self.next_operation()
        self.emit("fault", role, operation=operation)
        self.restart_node(role)
        self.content("previous", role)
        self.emit("recovery", role, operation=operation, counters={"operations": 1})
        self.outcomes["daemon-restart"] = "observed"

    def partition_rejoin(self):
        role, relay = "candidate-recipient", "relay-no-apps"
        operation = self.next_operation()
        self.emit("fault", role, "partition-rejoin", operation)
        failed = False
        # New bytes are created only after the approved recipient edge is disabled.
        with absolute_deadline(self.remaining(180)), self.client(relay) as control, self.client(role) as recipient:
            interop.modify_peer(control, "partition", self.nodes[role].reference["identity"], {"IsDisabled": "true"})
            interop.modify_peer(recipient, "partition", self.nodes[relay].reference["identity"], {"IsDisabled": "true"})
        try:
            with absolute_deadline(self.remaining(90)), self.client("previous") as sender, self.client(role) as receiver:
                payload = ("PUBLIC SYNTHETIC PARTITION " + uuid.uuid4().hex).encode()
                reference = interop.put_and_wait_for_success(sender, operation + "-insert", "CHK@", payload, "text/plain",
                                                             local_request_only=True)
                failed = observe_partition_denial(receiver, operation + "-blocked", reference)
            if not failed:
                raise RuntimeFailure("partition-did-not-block-fresh-fetch")
        finally:
            with absolute_deadline(self.remaining(180)), self.client(relay) as control, self.client(role) as recipient:
                interop.modify_peer(control, "rejoin", self.nodes[role].reference["identity"], {"IsDisabled": "false"})
                interop.modify_peer(recipient, "rejoin", self.nodes[relay].reference["identity"], {"IsDisabled": "false"})
                interop.wait_for_peer_connection(recipient, "rejoin-peer", self.nodes[relay].reference["identity"], 150)
        with absolute_deadline(self.remaining(120)), self.client(role) as receiver:
            if interop.fetch_direct(receiver, operation + "-recover", reference, 90, ignore_ds=True) != payload:
                raise RuntimeFailure("partition-recovery-content-mismatch")
        self.emit("recovery", role, "partition-rejoin", operation, counters={"failures": 1, "operations": 1})
        self.emit("operation", role, "partition-rejoin", operation, counters={"operations": 1})
        self.outcomes["partition-rejoin"] = "observed"

    def cleanup(self):
        """Stop only owned groups; preserve all private data for explicit bounded retention."""
        complete = not bool(self.resume_pending_roles) and not self.orphaned_spawn and not getattr(self, "recovery_incomplete", False)
        if getattr(self, "recovery_cohort", None) is not None and not self.recovery_cohort.closed:
            try:
                if self.recovery_cohort.close() != "observed":
                    complete = False
            except (RuntimeFailure, OSError, ValueError, subprocess.SubprocessError):
                complete = False
        for role in reversed(ROLES):
            try:
                self.stop(role)
            except (RuntimeFailure, OSError, ValueError, subprocess.SubprocessError):
                complete = False
        try:
            self.save_state()
        except (OSError, ValueError, RuntimeFailure):
            complete = False
        self.emit("cleanup", outcome="pass" if complete else "fail", counters={"operations": 0})
        return "complete" if complete else "cleanup-incomplete"

    def execute(self):
        failure = None
        try:
            with absolute_deadline(self.remaining(120)):
                _preflight(self.plan, self.private, self.authorization, self.product_admission)
            if getattr(self.journal, "resumed", False):
                self.resume_owned()
            else:
                with absolute_deadline(self.remaining(600)):
                    self.prepare()
                for role in ROLES:
                    self.start(role)
                self.connect()
                self.provision_apps()
                self.mail_delivery()
                self.save_state()
            self.migrate_synthetic()
            self.stable_api_scenarios()
            self.recovery_scenarios()
            self.catalog_scenarios()
            self.budget_scenarios()
            self.outcomes["relay-health"] = "observed-core-processes"
            for scenario in ("network-chk", "network-ssk", "network-usk"):
                self.content("candidate-sender", "previous", scenario)
                self.content("previous", "candidate-recipient", scenario)
            self.subscribe("candidate-sender", "previous")
            self.subscribe("previous", "candidate-recipient")
            self.persistent_replay()
            self.restart()
            self.partition_rejoin()
            self.begin_mail_expiry_probe()
            # Content work, not idle heartbeats, establishes repeated measured observation windows.
            target = self.started + self.plan["requestedSeconds"]
            interval = self.plan["probeIntervalSeconds"]
            self.emit("probe", counters={"operations": self.observed_operations})
            while time.monotonic() < target:
                self.content("candidate-sender", "previous")
                self.content("previous", "candidate-recipient")
                for role in ROLES:
                    with absolute_deadline(self.remaining(30)), self.client(role) as client:
                        interop.get_node_reference(client, "scheduled-health")
                self.sample_app_lifecycle()
                self.observe_mail_expiry()
                self.sample_resources()
                self.scan_mail_surfaces()
                self.emit("probe", counters={"operations": self.observed_operations})
                self.save_state()
                self.journal.checkpoint("partial")
                time.sleep(max(0, min(interval, target - time.monotonic(), self.deadline - time.monotonic())))
        except (RuntimeFailure, interop.InteropFailure, mail_demo.DemoFailure, OSError, ValueError, EOFError, subprocess.SubprocessError) as error:
            failure = str(error) if isinstance(error, RuntimeFailure) else "private-runtime-operation-failed"
            self.emit("fault", outcome="fail")
        except KeyboardInterrupt:
            failure = "controller-interrupted"
            self.emit("fault", outcome="partial")
        finally:
            cleanup = self.cleanup()
        scenarios = self.plan["requiredScenarios"]
        for scenario in scenarios:
            identifier = scenario["id"] if isinstance(scenario, dict) else scenario
            if identifier not in self.outcomes:
                self.outcomes[identifier] = "not-observed"
        return {"kind": "cross-version-runtime-observation", "evidenceLevel": self.plan["profile"],
                "topologyClass": "single-host-independent-processes", "status": "failed" if failure else "partial",
                "failureCode": failure, "scenarios": dict(sorted(self.outcomes.items())), "cleanup": cleanup,
                "observedControllerSeconds": round(time.monotonic() - self.started, 3),
                "operations": self.operations, "releaseEligible": False,
                "artifactAuthority": "original-producer-authenticated" if self.product_identities else "local-exact-byte-comparison",
                "productIdentities": self.product_identities, "appInstallation": "observed" if self.apps else "not-observed",
                "runnerAuthority": self.runner_admission.public_identity() if self.runner_admission else None,
                "independentSecurityReview": "not-observed", "migrationObservation": self.migration_observation,
                "recoveryObservation": self.recovery_observation, "catalogObservation": self.catalog_observation, "budgetObservation": self.budget_observation,
                "resourceObservations": self.resource_observations,
                "mailOriginObservations": self.mail_origin_observations, "mailCanaryObservations": self.mail_canary_observations}


def runner_python_identity():
    """Bind actual interpreter and loaded libpython bytes; not an OS image attestation."""
    selected = Path(sys.executable)
    actual = Path("/proc/self/exe") if Path("/proc/self/exe").exists() else selected
    actual_digest = digest_file(actual)
    if not selected.is_file() or digest_file(selected) != actual_digest:
        raise RuntimeFailure("runner-python-executable-mismatch")
    libraries = set()
    maps = Path("/proc/self/maps")
    if maps.is_file():
        for line in maps.read_text().splitlines():
            fields = line.split(maxsplit=5)
            if len(fields) == 6 and "libpython" in Path(fields[5]).name:
                library = Path(fields[5])
                if not library.is_file() or library.stat().st_size > 128 * 1024**2:
                    raise RuntimeFailure("runner-python-library-unavailable")
                libraries.add(library)
    if len(libraries) > 16:
        raise RuntimeFailure("runner-python-library-budget-exceeded")
    return {"executableDigest": actual_digest, "version": sys.version,
            "implementation": sys.implementation.name, "cacheTag": sys.implementation.cache_tag,
            "loadedPythonLibraryDigests": sorted(digest_file(path) for path in libraries), "osImageAuthentication": "not-established"}


def runner_identity():
    """Bind the closed executing helper set independently of participant artifact revisions."""
    root = Path(__file__).resolve().parents[2]
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True, timeout=10).strip()
    names = ["tools/interop/cross_version_runtime.py", "tools/mail-prototype/two_node_demo.py",
             "tools/release-certification/cryptad_certification/cross_version_evidence.py",
             "tools/release-certification/cryptad_certification/cross_version_command.py",
             "tools/interop/cross_version_app_scenarios.py",
             "tools/interop/cross_version_recovery.py",
             "tools/interop/cross_version_catalog.py",
             "tools/interop/cross_version_budget.py",
             "tools/interop/cross_version_budget_driver.cjs",
             "tools/release-certification/protected/sharesite_observation.py",
             "tools/release-certification/protected/sharesite_runtime_driver.cjs",
             "tools/release-certification/protected/bounded_process.py",
             "tools/release-certification/protected/app_subject_projection.py",
             "tools/release-certification/protected/original_artifact_authentication.py",
             "tools/release-certification/protected/cross_version_product_admission.py",
             "tools/release-certification/protected/cross_version_supervisor_authority.py",
             "tools/interop/cross_version_service.py",
             "tools/interop/systemd/cryptad-cross-version-soak.service",
             "tools/interop/systemd/cryptad-cross-version-control.sudoers",
             ".github/workflows/cross-version-live-network-soak.yml",
             "platform-devtools/src/test/resources/network/crypta/platform/devtools/migration/sharesite/upstream-mixed.db"]
    certification = root / "tools/release-certification"
    names.extend(path.relative_to(root).as_posix() for path in (certification / "cryptad_certification").rglob("*.py")
                 if "tests" not in path.relative_to(certification).parts)
    names.extend(path.relative_to(root).as_posix() for path in (certification / "schemas").glob("*.json"))
    names.extend(path.relative_to(root).as_posix() for path in certification.glob("*.json"))
    return {"sourceCommit": commit,
            "runnerDigest": canonical_digest([[name, digest_file(root / name)] for name in sorted(set(names))] + [["@executing-python-runtime", runner_python_identity()]]),
            "adapterDigest": digest_file(Path(interop.__file__))}


implementation_identity = runner_identity


def _preflight(plan, private_config, authorization=None, product_admission=None):
    """Read actual selected bytes; never extract, start a process or contact a node."""
    if plan["producer"] != implementation_identity():
        raise RuntimeFailure("selected-runner-identity-mismatch")
    if plan["profile"] not in {"bounded-live", "protected-long-live"} or plan["provenanceClass"] not in {"source-build-comparison", "production-artifact-comparison"}:
        raise RuntimeFailure("protected-producer-admission-not-configured")
    runner_admission = None
    if plan["profile"] == "protected-long-live":
        runner_admission = authenticate_runner_selection(plan, private_config, authorization)
    if plan["provenanceClass"] == "production-artifact-comparison":
        if product_admission is None:
            product_admission = (runner_admission.product_admission(plan, private_config)
                                 if runner_admission else authenticate_product_selection(plan, private_config))
        else:
            with fixed_helper_imports():
                module = fixed_helper("cross_version_product_admission")
                if not isinstance(product_admission, module.AuthenticatedProducts):
                    raise RuntimeFailure("original-product-authority-not-produced")
                product_admission.bind(plan, private_config)
        product_admission.bind_apps(plan)
    selected_roles = {row["role"] for row in plan["nodes"]}
    if selected_roles != set(ROLES) or set(private_config["nodes"]) != selected_roles:
        raise RuntimeFailure("runtime-topology-unsupported")
    ports = []
    for selected in plan["nodes"]:
        private = private_config["nodes"][selected["role"]]
        for field in ("fnpPort", "fcpPort", "httpPort"):
            if type(private[field]) is not int or not 1024 <= private[field] <= 65535:
                raise RuntimeFailure("private-port-invalid")
            ports.append(private[field])
        if planned_config_identity(selected["role"], private["fnpPort"], private["fcpPort"], private["httpPort"], private["trustedKeysDigest"]) != selected["configDigest"]:
            raise RuntimeFailure("node-config-binding-mismatch")
        archive = Path(private["archivePath"])
        if archive.is_symlink() or archive.stat().st_size != selected["artifactSize"] or digest_file(archive) != selected["artifactDigest"]:
            raise RuntimeFailure("artifact-roster-binding-mismatch")
        if tree_digest(private["javaHome"]) != selected["runtimeDigest"]:
            raise RuntimeFailure("runtime-roster-binding-mismatch")
        if sorted(app["bundleDigest"] for app in private["apps"]) != sorted(selected["appDigests"]):
            raise RuntimeFailure("private-app-subject-set-mismatch")
        for app in private["apps"]:
            if digest_file(app["bundlePath"]) != app["bundleDigest"]:
                raise RuntimeFailure("app-bundle-roster-binding-mismatch")
        if private["apps"] and digest_file(private["trustedKeysPath"]) != private["trustedKeysDigest"]:
            raise RuntimeFailure("private-app-trust-binding-mismatch")
    if len(ports) != len(set(ports)):
        raise RuntimeFailure("node-port-alias-rejected")
    validate_recovery_selection(plan, private_config, authorization)
    validate_budget_selection(plan, private_config, authorization)
    if private_config.get("migration") is not None:
        validate_migration_selection(private_config["migration"])
        if authorization is None or authorization.get("migrationInputsDigest") != canonical_digest(private_config["migration"]):
            raise RuntimeFailure("migration-selection-not-authorized")
    if authorization is not None and (authorization.get("experimentId") != plan["experimentId"]
            or authorization.get("planDigest") != canonical_digest(plan)
            or authorization.get("root") != private_config["root"]
            or authorization.get("syntheticContent") is not True):
        raise RuntimeFailure("exact-topology-authorization-invalid")
    return {"kind": "cross-version-runtime-preflight", "status": "pins-verified",
            "artifactAuthority": "original-producer-authenticated" if product_admission else "local-exact-byte-comparison", "execution": "not-started",
            "nodeCount": len(selected_roles), "protectedAuthentication": "selected-service-authorized" if runner_admission else "not-observed"}


def preflight(plan, private_config, authorization=None):
    with absolute_deadline(120):
        return _preflight(plan, private_config, authorization)


def run(plan, private_config, authorization, journal):
    """Execute only a previously validated, explicitly authorized bounded disposable plan."""
    old_mask = os.umask(0o077)
    try:
        return Supervisor(plan, private_config, authorization, journal).execute()
    finally:
        os.umask(old_mask)
