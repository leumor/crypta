"""One local maintenance rehearsal entrypoint; never a release authority or publisher."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

CASES = (
    "absent-artifact-base-denied", "interrupted-assets-preserve-prefix", "exact-prefix-resume",
    "exact-existing-no-mutation", "conflict-preserved", "uncertain-write-observe-before-retry",
    "stale-predecessor-denied", "hotfix-obligation-carry-and-drop-denial",
    "fixed-provider-exact-byte-failure-recovery", "fixed-provider-activation-cas-response-loss",
    "scratch-git-clean-cherry-pick-exact-provenance", "scratch-git-conflict-resolution-regression",
    "scratch-git-hidden-omitted-duplicate-change-denial", "scratch-git-wrong-lane-and-unsupported-change-denial",
)
MISSING = (
    "authenticated-ga-predecessor-train", "app-bearing-maintenance-freeze-runtime-binding",
    "complete-original-journal-maintenance-projection", "packaged-predecessor-upgrade-recovery",
    "full-window-hotfix-follow-up", "dependency-finding-to-fixed-bytes",
    "catalog-origin-compromise-recovery", "protected-publication-activation-reconciliation",
    "mail-lifecycle-process-cohort",
    "independent-security-review",
)


def _digest(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _policy():
    return _digest((Path(__file__).resolve().parents[1] / "stable-1.0-maintenance-policy.json").read_bytes())


def _helper_identity():
    directory = Path(__file__).resolve().parent
    files = ("maintenance_drill_command.py", "maintenance_drill_runtime.py", "maintenance_drill_provider.py",
             "maintenance_drill_train.py", "stable_backport_git.py", "engines/stable_1_0_backport.py",
             "engines/stable_1_0_backport_core.py", "tests/test_stable_backport_git.py",
             "tests/test_stable_maintenance_publication.py")
    identity = {name: _digest((directory / name).read_bytes()) for name in files}
    identity["protected/stable_maintenance_publication.py"] = _digest(
        (directory.parent / "protected/stable_maintenance_publication.py").read_bytes())
    identity["publication-backend/provider.py"] = _digest(
        (directory.parent / "publication-backend/src/cryptad_stable_maintenance_backend/provider.py").read_bytes())
    identity["stable-1.0-backport-release-train-policy.json"] = _digest(
        (directory.parent / "stable-1.0-backport-release-train-policy.json").read_bytes())
    return identity


def _checkout_identity():
    checkout = Path(__file__).resolve().parents[3]
    result = subprocess.run(["git", "rev-parse", "HEAD", "HEAD^{tree}"], cwd=checkout,
                            capture_output=True, text=True, check=True, timeout=5)
    commit, tree = result.stdout.splitlines()
    return {"commit": commit, "committedTree": tree,
            "binding": "checkout-only-helper-file-digests-bind-local-edits"}


def plan():
    """Return a closed, non-production plan using the current policy's exact file identity."""
    return {
        "schemaVersion": 1, "kind": "stable-maintenance-isolated-drill",
        "classification": "synthetic-isolated-rehearsal", "policyFileDigest": _policy(),
        "helperFileDigests": _helper_identity(), "checkoutIdentity": _checkout_identity(),
        "clock": "simulation-no-observed-duration", "cases": list(CASES),
        "observedCases": [], "missingCoverage": list(MISSING), "status": "planned",
        "cleanup": "not-started", "productionEvidence": "not-authenticated",
        "maintenanceEligibility": "blocked-original-authority-required",
        "publication": "not-performed", "activation": "not-performed",
        "hotfixFollowUp": "synthetic-rule-coverage-only",
        "independentSecurityReview": "pending",
    }


def _seal(record):
    return {**record, "localIntegrityDigest": _digest(_bytes(record))}


def _fresh(path):
    path = Path(path).absolute()
    if (path.exists() or path.is_symlink() or not path.parent.is_dir()
            or any(p.is_symlink() for p in path.parents)):
        raise ValueError("drill-output-must-be-new-without-symlinks")
    return path


def run(root, *, execute_isolated=False):
    """Run fixed drivers inside a newly owned root, then remove all synthetic input bytes."""
    if not execute_isolated:
        raise ValueError("drill-explicit-isolated-execution-required")
    root = _fresh(root)
    root.mkdir(mode=0o700)
    record = plan()
    try:
        from .maintenance_drill_runtime import execute
        with tempfile.TemporaryDirectory(prefix="owned-", dir=root) as temporary:
            record["observedCases"] = execute(Path(temporary))
        record["status"] = "executed"
        record["cleanup"] = "owned-synthetic-state-removed"
    except Exception:
        # Exception content and synthetic fixture authorities never enter the public summary.
        record["status"] = "failed"
        record["cleanup"] = "owned-synthetic-state-removed" if not list(root.iterdir()) else "incomplete"
    sealed = _seal(record)
    _write(root / "summary.json", sealed)
    return sealed


def verify(record):
    """Check local integrity only; a caller-authored seal cannot authenticate a producer."""
    if type(record) is not dict:
        raise ValueError("drill-record-invalid")
    value = {k: v for k, v in record.items() if k != "localIntegrityDigest"}
    expected = plan()
    if (set(value) != set(expected)
            or type(record.get("localIntegrityDigest")) is not str
            or len(record["localIntegrityDigest"]) != 71):
        raise ValueError("drill-record-contract-invalid")
    for key in expected.keys() - {"observedCases", "status", "cleanup"}:
        if not _exact_contract(value[key], expected[key]):
            raise ValueError("drill-record-contract-invalid")
    if (type(value["status"]) is not str or type(value["cleanup"]) is not str
            or len(value["status"]) > 16 or len(value["cleanup"]) > 64
            or type(value["observedCases"]) is not list
            or len(value["observedCases"]) > len(CASES)
            or any(type(case) is not str or case not in CASES for case in value["observedCases"])):
        raise ValueError("drill-record-contract-invalid")
    if value["status"] == "executed":
        if value["observedCases"] != list(CASES) or value["cleanup"] != "owned-synthetic-state-removed":
            raise ValueError("drill-case-set-or-cleanup-incomplete")
    elif value["status"] == "planned":
        if value["observedCases"] or value["cleanup"] != "not-started":
            raise ValueError("drill-plan-invalid")
    elif value["status"] == "failed":
        if value["observedCases"] or value["cleanup"] not in {"owned-synthetic-state-removed", "incomplete"}:
            raise ValueError("drill-failure-record-invalid")
    else:
        raise ValueError("drill-status-invalid")
    if record["localIntegrityDigest"] != _digest(_bytes(value)):
        raise ValueError("drill-record-integrity-invalid")
    return {"status": "verified-local-integrity", "producerAuthentication": "not-established",
            "maintenanceEligibility": "blocked-original-authority-required"}


def _exact_contract(value, expected):
    """Match the generated closed contract without Python Boolean/integer coercion."""
    if type(value) is not type(expected):
        return False
    if type(expected) is dict:
        return set(value) == set(expected) and all(
            _exact_contract(value[key], child) for key, child in expected.items())
    if type(expected) is list:
        return len(value) == len(expected) and all(
            _exact_contract(actual, required) for actual, required in zip(value, expected))
    return value == expected


def closeout(record):
    """Retain acceptance dimensions even when every implemented isolated driver succeeded."""
    verify(record)
    return {"schemaVersion": 1, "kind": "stable-maintenance-isolated-drill-closeout",
            "localIntegrity": "verified", "isolatedExecution": record["status"],
            "observedCases": record["observedCases"], "missingCoverage": list(MISSING),
            "implementationCoverage": "partial", "originalProtectedRuntime": "not-observed",
            "maintenanceEligibility": "blocked-original-authority-required",
            "publication": "not-performed", "activation": "not-performed",
            "independentSecurityReview": "pending", "cleanup": record["cleanup"]}


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("drill-duplicate-json-member")
        result[key] = value
    return result


def _read(path):
    path = Path(path).absolute()
    if (path.is_symlink() or any(p.is_symlink() for p in path.parents)
            or not path.is_file() or path.stat().st_size > 16384):
        raise ValueError("drill-record-input-invalid")
    return json.loads(path.read_bytes(), object_pairs_hook=_unique)


def _write(path, value):
    path = _fresh(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(_bytes(value) + b"\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("plan", "run", "verify", "closeout"), required=True)
    parser.add_argument("--root", type=Path)
    parser.add_argument("--record", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--execute-isolated", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.mode == "run":
            if args.root is None or args.record is not None or args.output is not None:
                raise ValueError("drill-run-arguments-invalid")
            value = run(args.root, execute_isolated=args.execute_isolated)
        else:
            if args.root is not None or args.execute_isolated:
                raise ValueError("drill-read-only-arguments-invalid")
            if args.mode == "plan":
                if args.record is not None:
                    raise ValueError("drill-plan-arguments-invalid")
                value = _seal(plan())
            else:
                if args.record is None:
                    raise ValueError("drill-record-required")
                value = (verify if args.mode == "verify" else closeout)(_read(args.record))
            if args.output is not None:
                _write(args.output, value)
        print(json.dumps(value, sort_keys=True))
        return 1 if value.get("status") == "failed" else 0
    except (ValueError, OSError):
        print('{"status":"rejected","reason":"drill-input-or-contract-invalid"}')
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
