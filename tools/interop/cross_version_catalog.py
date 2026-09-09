"""Finite normal-route catalog observations for an approved disposable app cohort.

Private file sources must already be inside the daemon's approved local catalog roots. This module
never imports publisher keys or edits an installed application. Java derives signed declarations
before mutation; the supervisor owns bounded literal-loopback control and exact process identity.
"""
from __future__ import annotations
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import sys
import tempfile
from typing import Protocol

PROTECTED = Path(__file__).resolve().parents[1] / "release-certification/protected"
sys.path.insert(0, str(PROTECTED))
from app_subject_projection import tree_digest, validate_declaration
from bounded_process import run

CASES = frozenset({"signedCatalogAdmission", "untrustedCatalogBlocking", "exactMirrorSubject",
                   "sourceSwitchConsent", "stableBetaIsolation", "sameVersionDigestConflict",
                   "updatePermissionConsent", "bundleRollback"})


class CatalogFailure(ValueError):
    """Bounded code only; no private source URI or server error detail escapes."""


class Supervisor(Protocol):
    def remaining(self, seconds: float) -> float: ...
    def catalog_request(self, role: str, method: str, path: str, form: dict | None = None) -> tuple[int, dict]: ...
    def app_subject(self, role: str, app_id: str) -> dict: ...
    def stop_app(self, role: str, app_id: str) -> None: ...
    def start_app(self, role: str, app_id: str) -> None: ...


@dataclass(frozen=True)
class Tool:
    root: Path
    tree_digest: str
    java_home: Path
    java_tree_digest: str
    private_root: Path


@dataclass(frozen=True)
class Fixture:
    catalog: Path
    signature: Path
    bundle: Path
    catalog_keys: Path
    publisher_keys: Path
    reviewer_keys: Path
    catalog_key_id: str
    app_id: str
    catalog_id: str
    catalog_digest: str
    signature_digest: str
    bundle_digest: str
    catalog_keys_digest: str
    publisher_keys_digest: str
    reviewer_keys_digest: str


def _file(path: Path, expected: str, maximum: int) -> None:
    import stat
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 1 <= info.st_size <= maximum
            or "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest() != expected):
        raise CatalogFailure("catalog-selected-file-substituted")


def verify_fixture(supervisor: Supervisor, tool: Tool, fixture: Fixture) -> dict:
    """Reopen exact signed artifacts through the production Java verifier before daemon actions."""
    if tree_digest(tool.root) != tool.tree_digest or tree_digest(tool.java_home) != tool.java_tree_digest:
        raise CatalogFailure("catalog-selected-tool-substituted")
    if tool.private_root.is_symlink() or not tool.private_root.is_dir() or tool.private_root.stat().st_mode & 0o077:
        raise CatalogFailure("catalog-private-root-invalid")
    for path, digest, bound in ((fixture.catalog, fixture.catalog_digest, 8*1024*1024),
                               (fixture.signature, fixture.signature_digest, 65536),
                               (fixture.bundle, fixture.bundle_digest, 512*1024*1024),
                               (fixture.catalog_keys, fixture.catalog_keys_digest, 1024*1024),
                               (fixture.publisher_keys, fixture.publisher_keys_digest, 1024*1024),
                               (fixture.reviewer_keys, fixture.reviewer_keys_digest, 1024*1024)):
        _file(path, digest, bound)
    # The daemon resolves this fixed sidecar name beside the selected file catalog.
    if fixture.signature != fixture.catalog.parent / "cryptad-app-catalog.signature":
        raise CatalogFailure("catalog-selected-sidecar-mismatch")
    with tempfile.TemporaryDirectory(prefix="catalog-projection-", dir=tool.private_root) as directory:
        private = Path(directory)
        output = private / "declaration.json"
        run([str(tool.root / "bin/crypta-app"), "subject-projection", "--catalog", str(fixture.catalog),
             "--catalog-signature", str(fixture.signature), "--catalog-key-id", fixture.catalog_key_id,
             "--catalog-keys", str(fixture.catalog_keys), "--publisher-keys", str(fixture.publisher_keys),
             "--reviewer-keys", str(fixture.reviewer_keys), "--bundle", str(fixture.bundle),
             "--app-id", fixture.app_id, "--private-root", str(private), "--output", str(output)],
            environment={"JAVA_HOME": str(tool.java_home), "PATH": str(tool.java_home / "bin") + ":/usr/bin:/bin",
                         "LANG": "C.UTF-8", "TMPDIR": str(private)}, timeout=supervisor.remaining(180), output_limit=4096)
        if output.stat().st_size > 32768:
            raise CatalogFailure("catalog-projection-oversized")
        value = validate_declaration(json.loads(output.read_bytes()))
    if any(value[key] != expected for key, expected in (("appId", fixture.app_id),
            ("catalogId", fixture.catalog_id), ("catalogDigest", fixture.catalog_digest),
            ("catalogSignatureDigest", fixture.signature_digest), ("bundleDigest", fixture.bundle_digest))):
        raise CatalogFailure("catalog-derived-subject-substituted")
    return value


def _request(supervisor, role, method, path, form=None):
    supervisor.remaining(1)
    status, value = supervisor.catalog_request(role, method, path, form)
    if type(status) is not int or not isinstance(value, dict):
        raise CatalogFailure("catalog-invalid-response")
    return status, value


def _ok(supervisor, role, method, path, envelope, form=None):
    status, value = _request(supervisor, role, method, path, form)
    if status not in {200, 201} or envelope not in value:
        raise CatalogFailure("catalog-operation-failed")
    return value[envelope]


def _inventory(supervisor, role):
    value = _ok(supervisor, role, "GET", "/api/v1/app-catalogs", "catalogs")
    if not isinstance(value, list) or len(value) > 64 or any(not isinstance(row, dict) for row in value):
        raise CatalogFailure("catalog-inventory-invalid")
    return {row["catalogId"] for row in value}


def _exact(supervisor, role, fixture):
    base = "/api/v1/app-catalogs/" + fixture.catalog_id
    health = _ok(supervisor, role, "GET", base + "/operations/health", "health")
    digest = health.get("catalogDigest", "")
    if digest.removeprefix("sha256:") != fixture.catalog_digest.removeprefix("sha256:") or health.get("signatureKeyId") != fixture.catalog_key_id:
        raise CatalogFailure("catalog-observed-subject-mismatch")
    return health


def run_catalog_cases(supervisor: Supervisor, role: str, tool: Tool, baseline: Fixture,
                      *, mirror: Fixture | None = None, other_catalog: Fixture | None = None,
                      untrusted_catalog: Path | None = None, untrusted_digest: str | None = None, untrusted_signature_digest: str | None = None) -> dict:
    """Execute a bounded selected subset; missing required cases remain not-observed.

    Baseline and optional alternate are admitted through real Java signature verification. The
    untrusted negative is an exact selected catalog+sidecar in approved local roots whose signing
    root is absent from the daemon trust registry; rejection must be observed, never assumed.
    """
    outcomes = {case: "not-observed" for case in sorted(CASES)}
    result = {"schemaVersion": 1, "kind": "cross-version-catalog-observation", "status": "partial",
              "outcomes": outcomes, "releaseEligibility": "blocked", "cleanup": "not-observed"}
    owned, stopped, before = [], False, None
    try:
        declaration = verify_fixture(supervisor, tool, baseline)
        for identifier in (baseline.catalog_id, baseline.app_id):
            if re.fullmatch(r"[a-z][a-z0-9-]{1,63}", identifier) is None:
                raise CatalogFailure("catalog-selected-id-invalid")
        before = _inventory(supervisor, role)
        if baseline.catalog_id in before:
            raise CatalogFailure("catalog-preexisting-source-refused")
        owned.append(baseline.catalog_id)
        _ok(supervisor, role, "POST", "/api/v1/app-catalogs/add", "catalog",
            {"source": baseline.catalog.as_uri(), "expectedCatalogId": baseline.catalog_id})
        _exact(supervisor, role, baseline)
        outcomes["signedCatalogAdmission"] = "pass"
        if mirror is not None:
            derived = verify_fixture(supervisor, tool, mirror)
            if (derived != declaration or mirror.catalog == baseline.catalog):
                raise CatalogFailure("catalog-mirror-selected-subject-mismatch")
            base = "/api/v1/app-catalogs/" + baseline.catalog_id
            _ok(supervisor, role, "POST", base + "/mirrors", "mirror",
                {"source": mirror.catalog.as_uri(), "mirrorId": "soak-exact-mirror", "priority": "1", "enabled": "true"})
            _ok(supervisor, role, "POST", base + "/refresh", "catalog")
            _exact(supervisor, role, baseline)
            # Exact subject registration is distinct from fallback, which needs a supervised outage.
            outcomes["exactMirrorSubject"] = "pass"
        if untrusted_catalog is not None:
            _file(untrusted_catalog, untrusted_digest, 8*1024*1024)
            _file(untrusted_catalog.parent / "cryptad-app-catalog.signature", untrusted_signature_digest, 65536)
            prior = _inventory(supervisor, role)
            status, response = _request(supervisor, role, "POST", "/api/v1/app-catalogs/add", {"source": untrusted_catalog.as_uri()})
            if status in {200, 201}:
                unexpected = response.get("catalog", {}).get("catalogId")
                if isinstance(unexpected, str) and re.fullmatch(r"[a-z][a-z0-9-]{1,63}", unexpected) and unexpected not in prior:
                    owned.append(unexpected)
            if status != 400 or response.get("error", {}).get("code") != "invalid_catalog_signature" or _inventory(supervisor, role) != prior:
                raise CatalogFailure("catalog-untrusted-source-not-blocked")
            outcomes["untrustedCatalogBlocking"] = "pass"
        if other_catalog is not None:
            alternate = verify_fixture(supervisor, tool, other_catalog)
            if alternate["appId"] != baseline.app_id or other_catalog.catalog_id == baseline.catalog_id:
                raise CatalogFailure("catalog-alternate-subject-invalid")
            versions = (declaration["appVersion"], alternate["appVersion"])
            if any(re.fullmatch(r"[0-9]+(?:\.[0-9]+){0,3}", value) is None for value in versions):
                raise CatalogFailure("catalog-version-comparison-unsupported")
            parsed = [tuple(map(int, value.split("."))) for value in versions]
            width = max(map(len, parsed))
            if parsed[1] + (0,) * (width-len(parsed[1])) <= parsed[0] + (0,) * (width-len(parsed[0])):
                raise CatalogFailure("catalog-alternate-higher-version-required")
            if other_catalog.catalog_id in _inventory(supervisor, role):
                raise CatalogFailure("catalog-preexisting-source-refused")
            installed = supervisor.app_subject(role, baseline.app_id)["bundleDigest"]
            if installed != baseline.bundle_digest:
                raise CatalogFailure("catalog-installed-baseline-mismatch")
            owned.append(other_catalog.catalog_id)
            _ok(supervisor, role, "POST", "/api/v1/app-catalogs/add", "catalog",
                {"source": other_catalog.catalog.as_uri(), "expectedCatalogId": other_catalog.catalog_id})
            supervisor.stop_app(role, baseline.app_id)
            stopped = True
            status, response = _request(supervisor, role, "POST", "/api/v1/app-catalogs/" + other_catalog.catalog_id + "/apps/" + baseline.app_id + "/update", {})
            if status != 409 or response.get("error", {}).get("code") != "catalog_source_switch_consent_required":
                raise CatalogFailure("catalog-source-switch-not-blocked")
            if supervisor.app_subject(role, baseline.app_id)["bundleDigest"] != installed:
                raise CatalogFailure("catalog-source-switch-mutated-installed-app")
            outcomes["sourceSwitchConsent"] = "pass"
    except (OSError, ValueError, KeyError, TypeError):
        result["status"] = "failed"
    finally:
        try:
            if stopped:
                if supervisor.app_subject(role, baseline.app_id)["bundleDigest"] != baseline.bundle_digest:
                    raise CatalogFailure("catalog-installed-recovery-required")
                supervisor.start_app(role, baseline.app_id)
            for catalog_id in reversed(owned):
                _ok(supervisor, role, "DELETE", "/api/v1/app-catalogs/" + catalog_id, "catalog")
            if before is not None and _inventory(supervisor, role) != before:
                raise CatalogFailure("catalog-cleanup-incomplete")
            result["cleanup"] = "complete"
        except (OSError, ValueError, KeyError, TypeError):
            result["cleanup"] = "incomplete"
            result["status"] = "failed"
    return result


@dataclass(frozen=True)
class PreparedCatalog:
    """Private verified selection; this is not protected producer or release authentication."""
    role: str
    selection_digest: str
    local_root: Path
    tool: Tool
    baseline: Fixture
    mirror: Fixture | None
    other_catalog: Fixture | None
    untrusted: dict | None

    def daemon_environment(self) -> dict[str, str]:
        """Select separate approved public-key registries for this disposable daemon only."""
        return {"CRYPTAD_APPCATALOG_TRUSTED_KEYS_FILE": str(self.baseline.catalog_keys),
                "CRYPTAD_APPREVIEW_TRUSTED_REVIEWER_KEYS_FILE": str(self.baseline.reviewer_keys)}

    def run(self, supervisor: Supervisor) -> dict:
        selected = self.untrusted
        return run_catalog_cases(supervisor, self.role, self.tool, self.baseline, mirror=self.mirror,
            other_catalog=self.other_catalog, untrusted_catalog=Path(selected["catalogPath"]) if selected else None,
            untrusted_digest=selected["catalogDigest"] if selected else None,
            untrusted_signature_digest=selected["signatureDigest"] if selected else None)


def selection_digest(value: dict) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()


def _absolute_path(value) -> Path:
    if not isinstance(value, str) or not value or any(ord(c) < 32 for c in value):
        raise CatalogFailure("catalog-selection-path-invalid")
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts or any(parent.is_symlink() for parent in (path, *path.parents)):
        raise CatalogFailure("catalog-selection-path-invalid")
    return path


def _confined_path(value, root: Path) -> Path:
    path = _absolute_path(value)
    if not path.is_relative_to(root):
        raise CatalogFailure("catalog-selection-root-escape")
    return path


def _fixture_config(value, root: Path) -> Fixture:
    names = {"catalogPath": "catalog", "signaturePath": "signature", "bundlePath": "bundle",
             "catalogKeysPath": "catalog_keys", "publisherKeysPath": "publisher_keys", "reviewerKeysPath": "reviewer_keys",
             "catalogKeyId": "catalog_key_id", "appId": "app_id", "catalogId": "catalog_id",
             "catalogDigest": "catalog_digest", "signatureDigest": "signature_digest", "bundleDigest": "bundle_digest",
             "catalogKeysDigest": "catalog_keys_digest", "publisherKeysDigest": "publisher_keys_digest", "reviewerKeysDigest": "reviewer_keys_digest"}
    if not isinstance(value, dict) or set(value) != set(names):
        raise CatalogFailure("catalog-selection-fixture-fields-invalid")
    normalized = {}
    for key, destination in names.items():
        selected = value[key]
        if key.endswith("Path"):
            selected = _confined_path(selected, root)
        elif key.endswith("Digest"):
            if not isinstance(selected, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", selected) is None:
                raise CatalogFailure("catalog-selection-digest-invalid")
        elif not isinstance(selected, str) or re.fullmatch(r"[a-z][a-z0-9-]{1,63}", selected) is None:
            raise CatalogFailure("catalog-selection-id-invalid")
        normalized[destination] = selected
    return Fixture(**normalized)


def preflight_selection(value: dict, *, expected_digest: str, private_root: Path, remaining) -> PreparedCatalog:
    """Parse a sealed private selection and execute Java verification before any node starts.

    ``expected_digest`` comes from both the authorized plan workload input and private authority;
    callers must compare those two independently. ``remaining`` is the supervisor's absolute
    deadline callback, not a manifest-supplied executable. No node/API method is called here.
    """
    expected = {"schemaVersion", "role", "localRoot", "tool", "baseline", "mirror", "otherCatalog", "untrusted"}
    if (not isinstance(value, dict) or set(value) != expected or type(value["schemaVersion"]) is not int
            or value["schemaVersion"] != 1 or value["role"] != "candidate-sender"
            or selection_digest(value) != expected_digest):
        raise CatalogFailure("catalog-selection-authority-mismatch")
    root = _absolute_path(value["localRoot"])
    if not root.is_dir() or root.stat().st_mode & 0o022:
        raise CatalogFailure("catalog-selection-root-invalid")
    source = value["tool"]
    if not isinstance(source, dict) or set(source) != {"root", "treeDigest", "javaHome", "javaTreeDigest"}:
        raise CatalogFailure("catalog-selection-tool-fields-invalid")
    tool = Tool(_absolute_path(source["root"]), source["treeDigest"], _absolute_path(source["javaHome"]),
                source["javaTreeDigest"], private_root)
    for digest in (tool.tree_digest, tool.java_tree_digest):
        if not isinstance(digest, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None:
            raise CatalogFailure("catalog-selection-tool-digest-invalid")
    baseline = _fixture_config(value["baseline"], root)
    mirror = _fixture_config(value["mirror"], root) if value["mirror"] is not None else None
    other = _fixture_config(value["otherCatalog"], root) if value["otherCatalog"] is not None else None
    class Preflight:
        def remaining(self, seconds): return remaining(seconds)
    declared = verify_fixture(Preflight(), tool, baseline)
    for name, fixture in (("mirror", mirror), ("otherCatalog", other)):
        if fixture is None:
            continue
        if any(getattr(fixture, field) != getattr(baseline, field) for field in
               ("catalog_keys", "publisher_keys", "reviewer_keys", "catalog_keys_digest", "publisher_keys_digest", "reviewer_keys_digest")):
            raise CatalogFailure("catalog-selection-registry-scope-mismatch")
        derived = verify_fixture(Preflight(), tool, fixture)
        if name == "mirror" and (derived != declared or fixture.catalog == baseline.catalog):
            raise CatalogFailure("catalog-mirror-selected-subject-mismatch")
        if name == "otherCatalog" and (fixture.app_id != baseline.app_id or fixture.catalog_id == baseline.catalog_id):
            raise CatalogFailure("catalog-alternate-subject-invalid")
    untrusted = value["untrusted"]
    if untrusted is not None:
        if not isinstance(untrusted, dict) or set(untrusted) != {"catalogPath", "catalogDigest", "signatureDigest"}:
            raise CatalogFailure("catalog-negative-selection-invalid")
        negative = _confined_path(untrusted["catalogPath"], root)
        _file(negative, untrusted["catalogDigest"], 8 * 1024 * 1024)
        _file(negative.parent / "cryptad-app-catalog.signature", untrusted["signatureDigest"], 65536)
    return PreparedCatalog(value["role"], expected_digest, root, tool, baseline, mirror, other,
                           dict(untrusted) if untrusted is not None else None)
