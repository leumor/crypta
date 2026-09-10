"""Closed public source selection, confined reads and explicit bounded observation.

A selected checksum does not authenticate its producer. Production sources require a reviewed
policy entry and their original authority; empty policy deliberately admits no live artifacts.
"""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import math
import os
import io
import sys
import tempfile
import zipfile
from pathlib import Path
import re
import stat
from urllib.parse import urlsplit
from datetime import datetime

POLICY_PATH = Path(__file__).resolve().parents[2] / "ecosystem-transparency/source-policy.json"
LIMIT = 4 * 1024 * 1024


class SourceError(ValueError):
    """Fixed public-safe source failure code."""


class SiteContentMismatch(SourceError):
    """A successful public response exceeded the approved asset's byte bound."""


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def strict_json(raw):
    if not isinstance(raw, bytes) or len(raw) > LIMIT:
        raise SourceError("source-json-bound")
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise SourceError("source-json-duplicate")
            result[key] = value
        return result
    def constant(_value):
        raise SourceError("source-json-nonfinite")
    def number(value):
        result = float(value)
        if not math.isfinite(result):
            raise SourceError("source-json-nonfinite")
        return result
    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant, parse_float=number)
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise SourceError("source-json-invalid") from None


def safe_read(path, maximum=LIMIT):
    path = Path(path).absolute()
    if any(parent.is_symlink() for parent in (path, *path.parents)):
        raise SourceError("source-path-invalid")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > maximum:
                raise SourceError("source-file-invalid")
            raw = stream.read(maximum + 1)
            if len(raw) > maximum:
                raise SourceError("source-file-bound")
            return raw
    except OSError:
        raise SourceError("source-read-unavailable") from None


def safe_link(value, *, hosts=None, crypta=False):
    """Allow canonical inert public links; encoded characters are unnecessary and denied."""
    if not isinstance(value, str) or not 1 <= len(value) <= 2048:
        raise SourceError("source-link-invalid")
    if any(ord(c) < 33 or ord(c) > 126 for c in value) or any(c in value for c in '\\%<>"\'`'):
        raise SourceError("source-link-invalid")
    if ",AQECAAE" in value:
        raise SourceError("source-private-insertion-link")
    if crypta and re.fullmatch(r"crypta:(?:USK|SSK)@[A-Za-z0-9~,._/-]+", value):
        return value
    try:
        parsed = urlsplit(value)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
                or parsed.port is not None or parsed.query or parsed.fragment
                or parsed.netloc != parsed.hostname or parsed.hostname != parsed.hostname.lower()
                or parsed.hostname.endswith(".") or "." not in parsed.hostname
                or any(p in {".", ".."} for p in parsed.path.split("/"))
                or "//" in parsed.path):
            raise SourceError("source-link-invalid")
        try:
            address = ipaddress.ip_address(parsed.hostname)
        except ValueError:
            address = None
        if ((address is not None and not address.is_global)
                or parsed.hostname.endswith((".localhost", ".local", ".internal"))):
            raise SourceError("source-link-private")
        if hosts is not None and parsed.hostname not in hosts:
            raise SourceError("source-link-host")
        return value
    except ValueError:
        raise SourceError("source-link-invalid") from None


def timestamp(value):
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", value):
        raise SourceError("source-time-invalid")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        raise SourceError("source-time-invalid") from None
    return value


def policy():
    raw = safe_read(POLICY_PATH)
    return strict_json(raw), digest(raw)


def validate_selection(value):
    from .schema_validation import validate_schema
    if validate_schema(value, 'public-ecosystem-source-selection-v1.schema.json'):
        raise SourceError('source-selection-schema-invalid')
    rules, _ = policy()
    if (type(value) is not dict or set(value) != {"schemaVersion", "mode", "asOf", "sources"}
            or type(value["schemaVersion"]) is not int or value["schemaVersion"] != 1
            or type(value["mode"]) is not str or value["mode"] not in {"production", "demo"}):
        raise SourceError("source-selection-invalid")
    timestamp(value["asOf"])
    rows = value["sources"]
    if type(rows) is not list or len(rows) > rules["maximumSources"]:
        raise SourceError("source-selection-bound")
    seen = set()
    for row in rows:
        if type(row) is not dict or set(row) != {"role", "file", "digest", "size", "required"}:
            raise SourceError("source-entry-invalid")
        if (type(row["role"]) is not str or row["role"] not in rules["roles"] or type(row["file"]) is not str
                or re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}\.json", row["file"]) is None
                or type(row["digest"]) is not str or re.fullmatch(r"sha256:[a-f0-9]{64}", row["digest"]) is None
                or type(row["size"]) is not int or not 1 <= row["size"] <= rules["maximumSourceBytes"]
                or type(row["required"]) is not bool or row["file"] in seen):
            raise SourceError("source-entry-invalid")
        seen.add(row["file"])
    return value


def load_selection(path):
    return validate_selection(strict_json(safe_read(path)))


def collect(selection, source_root, mode=None):
    """Read only explicitly selected local public files; never discover or fetch links."""
    validate_selection(selection)
    if mode is not None and mode != selection["mode"]:
        raise SourceError("source-mode-mismatch")
    _, pin = policy()
    members = []
    public_rows = []
    for index, row in enumerate(selection["sources"]):
        public_name = f"source-{index:02d}.json"
        public_rows.append({**row, "file": public_name})
        selected_path = (Path(source_root) / row["file"]).absolute()
        if (not row["required"] and not selected_path.exists()
                and not any(parent.is_symlink() for parent in (selected_path, *selected_path.parents))):
            members.append({"file": public_name, "bytes": None})
            continue
        raw = safe_read(selected_path, row["size"])
        if len(raw) != row["size"] or digest(raw) != row["digest"]:
            raise SourceError("source-byte-mismatch")
        members.append({"file": public_name, "bytes": base64.b64encode(raw).decode("ascii")})
    package = {"schemaVersion": 1, "policyDigest": pin, "selection": {**selection, "sources": public_rows}, "members": members}
    admit(package)
    return package


def admit(package):
    """Recompute every adapter from exact safe originals; input claims are never proofs."""
    rules, pin = policy()
    if (type(package) is not dict or set(package) != {"schemaVersion", "policyDigest", "selection", "members"}
            or type(package["schemaVersion"]) is not int or package["schemaVersion"] != 1
            or package["policyDigest"] != pin or len(canonical(package)) > LIMIT):
        raise SourceError("source-package-invalid")
    selection = validate_selection(package["selection"])
    members = package["members"]
    if type(members) is not list or len(members) != len(selection["sources"]):
        raise SourceError("source-inventory-incomplete")
    records, downloads, sources = [], {}, []
    for index, (row, member) in enumerate(zip(selection["sources"], members)):
        if row["file"] != f"source-{index:02d}.json":
            raise SourceError("source-public-name-not-opaque")
        if type(member) is not dict or set(member) != {"file", "bytes"} or member["file"] != row["file"]:
            raise SourceError("source-member-invalid")
        if member["bytes"] is None:
            if row["required"]:
                raise SourceError("source-required-missing")
            if selection["mode"] == "production" and not any(
                    all(entry.get(key) == row[key] for key in ("role", "digest", "size"))
                    for entry in rules["approvedSources"]):
                raise SourceError("source-not-approved")
            sources.append({"role": row["role"], "status": "optional-source-unavailable"})
            continue
        try:
            raw = base64.b64decode(member["bytes"], validate=True)
        except (ValueError, TypeError):
            raise SourceError("source-member-invalid") from None
        if len(raw) != row["size"] or digest(raw) != row["digest"]:
            raise SourceError("source-byte-mismatch")
        if selection["mode"] == "production":
            # No receipt Boolean or caller-selected trust root can populate this reviewed list.
            approved = [p for p in rules["approvedSources"] if p.get("role") == row["role"] and p.get("digest") == row["digest"] and p.get("size") == row["size"]]
            if len(approved) != 1:
                raise SourceError("source-not-approved")
        else:
            approved = []
        if row["role"] in {"release", "maintenance", "advisories"}:
            from .transparency_public_projection import validate_public_projection
            try:
                public = validate_public_projection(raw)
            except ValueError:
                raise SourceError('source-original-not-disclosure-safe') from None
            if selection['mode'] == 'production' and public.get('evidenceClass') == 'synthetic-rehearsal':
                raise SourceError('source-synthetic-production-denied')
            if public['role'] != row['role']:
                raise SourceError('source-projection-role-invalid')
        from .redaction import scan_value
        # All bytes exported later are screened, not merely their selected visible fields.
        raw_value = raw.decode("utf-8") if row["role"] in {"catalogs", "reviews"} else strict_json(raw)
        if row["role"] in {"reviews", "catalogs"}:
            from .transparency_adapters import _properties
            review = _properties(raw)
            withheld = {"review.receipt.evidence.sha256", "review.receipt.decision.reason.sha256", "review.receipt.evidence.uri", "review.receipt.note"}
            if any(key.endswith(tuple(withheld)) for key in review):
                raise SourceError("source-review-private-metadata")
        if row["role"] == "keys":
            from .engines.stable_1_0_catalog_authority import _sensitive_findings
            findings = _sensitive_findings(raw_value, allow_public_keys=True)
        else:
            findings = scan_value(raw_value)
        if findings:
            raise SourceError("source-disclosure-rejected")
        _disclosure_fields(raw_value)
        if row["role"] == "drill":
            projected = project_drill(raw, {"mode": selection["mode"], "approvedSource": approved[0] if approved else None})
        else:
            from .transparency_adapters import project
            projected = project(row["role"], raw, {"mode": selection["mode"], "selection": row, "policy": rules, "approvedSource": approved[0] if approved else None})
        records.append(projected["view"])
        for name, data in projected.get("downloads", {}).items():
            if not re.fullmatch(r"[a-zA-Z0-9_.-]{1,96}", name) or name in {".", ".."}:
                raise SourceError("source-download-invalid")
            downloads[digest(data)[7:] + "/" + name] = data
        sources.append({"role": row["role"], "digest": row["digest"], "size": row["size"]})
    return {"records": records, "downloads": downloads, "sources": sources}


def project_drill(raw, context):
    """Validate the fixed historical drill contract without executing historical source."""
    from . import maintenance_drill_command as drill
    value = strict_json(raw)
    fields = {"schemaVersion", "kind", "classification", "policyFileDigest", "helperFileDigests", "checkoutIdentity", "clock", "cases", "observedCases", "missingCoverage", "status", "cleanup", "productionEvidence", "maintenanceEligibility", "publication", "activation", "hotfixFollowUp", "independentSecurityReview", "localIntegrityDigest"}
    if type(value) is not dict or set(value) != fields:
        raise SourceError("drill-contract-invalid")
    if context.get("mode") == "production":
        approved = context.get("approvedSource")
        pins = approved.get("historicalDrill") if type(approved) is dict else None
        if (type(pins) is not dict or set(pins) != {"helperFileDigests", "policyFileDigest", "checkoutIdentity"}
                or any(value.get(key) != pins[key] for key in pins)):
            raise SourceError("drill-historical-binding-invalid")
    expected = {"schemaVersion": 1, "kind": "stable-maintenance-isolated-drill", "classification": "synthetic-isolated-rehearsal", "clock": "simulation-no-observed-duration", "cases": list(drill.CASES), "missingCoverage": list(drill.MISSING), "productionEvidence": "not-authenticated", "maintenanceEligibility": "blocked-original-authority-required", "publication": "not-performed", "activation": "not-performed", "hotfixFollowUp": "synthetic-rule-coverage-only", "independentSecurityReview": "pending"}
    if any(type(value[k]) is not type(v) or value[k] != v for k, v in expected.items()):
        raise SourceError("drill-contract-invalid")
    original = dict(value)
    seal = original.pop("localIntegrityDigest")
    if seal != digest(canonical(original)):
        raise SourceError("drill-integrity-invalid")
    if type(value["helperFileDigests"]) is not dict:
        raise SourceError("drill-binding-invalid")
    for item in [value["policyFileDigest"], *value["helperFileDigests"].values()]:
        if type(item) is not str or not re.fullmatch(r"sha256:[a-f0-9]{64}", item):
            raise SourceError("drill-binding-invalid")
    # Exact approved historical helper set; filenames cannot become private identifiers.
    helper_names = {"maintenance_drill_command.py", "maintenance_drill_runtime.py", "maintenance_drill_provider.py", "maintenance_drill_train.py", "stable_backport_git.py", "engines/stable_1_0_backport.py", "engines/stable_1_0_backport_core.py", "tests/test_stable_backport_git.py", "tests/test_stable_maintenance_publication.py", "protected/stable_maintenance_publication.py", "publication-backend/provider.py", "stable-1.0-backport-release-train-policy.json"}
    if set(value["helperFileDigests"]) != helper_names:
        raise SourceError("drill-binding-invalid")
    checkout = value["checkoutIdentity"]
    if (type(checkout) is not dict or set(checkout) != {"commit", "committedTree", "binding"}
            or any(type(checkout[k]) is not str or re.fullmatch(r"[a-f0-9]{40}", checkout[k]) is None for k in ("commit", "committedTree"))
            or checkout["binding"] != "checkout-only-helper-file-digests-bind-local-edits"):
        raise SourceError("drill-binding-invalid")
    allowed = {"executed": (list(drill.CASES), {"owned-synthetic-state-removed"}), "planned": ([], {"not-started"}), "failed": ([], {"owned-synthetic-state-removed", "incomplete"})}
    state = value["status"]
    if type(state) is not str or state not in allowed or value["observedCases"] != allowed[state][0] or type(value["cleanup"]) is not str or value["cleanup"] not in allowed[state][1]:
        raise SourceError("drill-state-invalid")
    return {"view": {"role": "drill", "identity": "maintenance-local-rehearsal", "evidenceClass": "synthetic/local-rehearsal", "provenance": "not-established", "verification": "verified-local-integrity", "disclosure": "bounded-drill-handoff", "publication": "not-performed", "activation": "not-performed", "observedAt": None, "staleAt": None, "fields": {"implementationCoverage": "partial", "originalProtectedRuntime": "not-observed", "maintenanceEligibility": "blocked-original-authority-required", "independentSecurityReview": "pending", "observedCases": value["observedCases"], "missingCoverage": value["missingCoverage"], "status": state, "localIntegrityDigest": seal}}, "downloads": {}}


def observe_bytes(url, expected_size, expected_digest):
    """Explicit read-only exact-byte observation, with no redirects or credential URLs."""
    safe_link(url)
    if type(expected_size) is not int or not 0 <= expected_size <= LIMIT:
        raise SourceError("observation-bound")
    from .engines.stable_1_0_public_observation import PublicObservationTransport
    try:
        observed = PublicObservationTransport(timeout=10).exact_digest(url, expected_size, redirect_budget=0)
        return "exact-match" if observed.digest == expected_digest else "conflict"
    except Exception:
        return "unavailable"


def fetch_public(url, maximum_bytes=262144):
    """Fetch a single policy-selected public URL with the existing DNS-pinned transport.

    Collection requires a reviewed exact URL. Observation uses the separately configured site
    origin in its caller; neither path follows redirects or linked resources.
    """
    rules, _ = policy()
    entries = [entry for entry in rules["networkSources"] if entry.get("url") == url]
    if len(entries) != 1 or type(maximum_bytes) is not int or not 1 <= maximum_bytes <= rules["maximumSourceBytes"]:
        raise SourceError("source-network-not-approved")
    safe_link(url)
    from .engines.stable_1_0_public_observation import PublicObservationTransport
    try:
        raw, _ = PublicObservationTransport(timeout=10)._read(
            url, headers={"Accept-Encoding": "identity"}, maximum_bytes=maximum_bytes,
            exact_size=None, redirect_budget=0, retain=True, visited=frozenset())
        if digest(raw) != entries[0]["digest"] or len(raw) != entries[0]["size"]:
            raise SourceError("source-network-byte-mismatch")
        return raw
    except Exception:
        raise SourceError("source-network-unavailable") from None


def collect_online(selection):
    """Explicit bounded network collection; build/admit never invoke this operation."""
    validate_selection(selection)
    rules, pin = policy()
    if selection["mode"] != "production":
        raise SourceError("source-network-production-only")
    members = []
    public_rows = []
    for index, row in enumerate(selection["sources"]):
        public_name = f"source-{index:02d}.json"
        public_rows.append({**row, "file": public_name})
        entries = [entry for entry in rules["networkSources"] if all(entry.get(k) == row[k] for k in ("role", "digest", "size"))]
        if len(entries) != 1:
            raise SourceError("source-network-not-approved")
        entry = entries[0]
        raw = fetch_original_member(entry) if "original" in entry else fetch_public(entry["url"], row["size"])
        members.append({"file": public_name, "bytes": base64.b64encode(raw).decode("ascii")})
    package = {"schemaVersion": 1, "policyDigest": pin, "selection": {**selection, "sources": public_rows}, "members": members}
    admit(package)
    return package



def fetch_site(url, maximum_bytes, base_url):
    """Fetch one asset beneath an exact reviewed site target; never follow redirects."""
    rules, _ = policy()
    if base_url not in rules.get("siteTargets", []):
        raise SourceError("site-target-not-approved")
    safe_link(base_url)
    safe_link(url)
    if (not base_url.endswith("/") or not url.startswith(base_url)
            or type(maximum_bytes) is not int or not 0 <= maximum_bytes <= LIMIT):
        raise SourceError("site-fetch-boundary")
    from .engines.stable_1_0_public_observation import (
        PublicObservationTransport, PublicObservationTransportError,
    )
    try:
        raw, _ = PublicObservationTransport(timeout=10)._read(
            url, headers={"Accept-Encoding": "identity"}, maximum_bytes=maximum_bytes,
            exact_size=None, redirect_budget=0, retain=True, visited=frozenset())
        return raw
    except PublicObservationTransportError as error:
        if str(error) == 'http-response-too-large':
            raise SiteContentMismatch('site-content-size-mismatch') from None
        raise SourceError("site-fetch-unavailable") from None
    except Exception:
        raise SourceError("site-fetch-unavailable") from None


def _original_helper():
    # Fixed checked-in code only. No artifact can select executable code or import paths.
    directory = str(Path(__file__).resolve().parents[1] / "protected")
    if directory not in sys.path:
        sys.path.insert(0, directory)
    import original_artifact_authentication
    return original_artifact_authentication


def _selected_archive_member(raw, entry):
    """Inspect the entire exact ZIP inventory before reading a bounded selected member."""
    maximum = 4 * 1024 * 1024
    if not isinstance(raw, bytes) or len(raw) > maximum:
        raise SourceError("source-archive-bound")
    expected = entry.get("members")
    selected = entry.get("member")
    if (type(expected) is not list or not 1 <= len(expected) <= 16
            or type(selected) is not str or selected not in expected
            or any(type(name) is not str or re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,95}", name) is None for name in expected)
            or len(set(name.casefold() for name in expected)) != len(expected)):
        raise SourceError("source-archive-policy-invalid")
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            entries = archive.infolist()
            if len(entries) != len(expected) or {member.filename for member in entries} != set(expected):
                raise SourceError("source-archive-inventory-invalid")
            total = 0
            for member in entries:
                mode = member.external_attr >> 16
                if (member.is_dir() or stat.S_IFMT(mode) not in {0, stat.S_IFREG}
                        or member.flag_bits & 1 or member.extra or member.comment
                        or member.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
                        or member.file_size > 262144
                        or member.file_size > max(1, member.compress_size) * 100):
                    raise SourceError("source-archive-member-invalid")
                total += member.file_size
            if total > maximum or archive.comment:
                raise SourceError("source-archive-bound")
            content = archive.read(selected)
            if len(content) != entry["size"] or digest(content) != entry["digest"]:
                raise SourceError("source-member-byte-mismatch")
            return content
    except (zipfile.BadZipFile, KeyError, OSError, RuntimeError):
        raise SourceError("source-archive-invalid") from None


def fetch_original_member(entry):
    """Authenticate reviewed original ZIP coordinates, then the exact public member attestation.

    Original API metadata and attestation responses remain private. Rebuilding the public bundle
    does not repeat this network operation or present a stored collection Boolean as proof.
    """
    rules, _ = policy()
    if entry not in rules["networkSources"] or "original" not in entry:
        raise SourceError("source-original-not-approved")
    helper = _original_helper()
    try:
        coordinates = helper.validate_coordinates(entry["original"])
        if coordinates["artifactSize"] > LIMIT:
            raise SourceError("source-archive-bound")
        with tempfile.TemporaryDirectory(prefix="transparency-private-") as directory:
            private_root = Path(directory)
            original = helper.authenticate_original(coordinates, private_root)
            if (type(original) is not helper.OriginalArtifact or original.coordinates != coordinates
                    or len(original.content) != coordinates["artifactSize"]
                    or digest(original.content) != coordinates["artifactDigest"]):
                raise SourceError("source-original-identity-invalid")
            content = _selected_archive_member(original.content, entry)
            member_path = private_root / "selected-public-member"
            member_path.write_bytes(content)
            workflow = helper.PRODUCERS[coordinates["sourceFamily"]][0]
            results = helper._gh([
                "attestation", "verify", str(member_path), "--repo", helper.REPOSITORY,
                "--signer-workflow", helper.REPOSITORY + "/" + workflow,
                "--source-digest", coordinates["sourceCommit"], "--signer-digest", coordinates["sourceCommit"],
                "--format", "json"], helper._environment())
            invocation = (f"https://github.com/{helper.REPOSITORY}/actions/runs/{coordinates['runId']}"
                          f"/attempts/{coordinates['runAttempt']}")
            if not isinstance(results, list) or not any(
                    type(row) is dict and row.get("verificationResult", {}).get("signature", {}).get("certificate", {}).get("runInvocationURI") == invocation
                    for row in results):
                raise SourceError("source-original-attestation-invalid")
            return content
    except Exception:
        raise SourceError("source-original-authentication-failed") from None



def _disclosure_fields(value):
    """Do not let permissive upstream reason-code strings carry private material hashes."""
    if type(value) is dict:
        for key, child in value.items():
            if key == "reasonCodes":
                if (type(child) is not list or any(type(code) is not str
                        or re.fullmatch(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*", code) is None
                        or len(code) > 64 or re.search(r"[a-f0-9]{20}", code) for code in child)):
                    raise SourceError("source-disclosure-reason-invalid")
            _disclosure_fields(child)
    elif type(value) is list:
        for child in value:
            _disclosure_fields(child)
