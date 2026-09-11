"""Read-only original hosted CI admission, separate from retained record consistency.

Historical builds retained runnable products without complete analyzer/test evidence. The
fixed original producer below now projects bounded JUnit, SpotBugs and Error Prone facts,
without publishing raw diagnostic payloads. Only authenticated exact-source complete facts
and original jobs can satisfy CI acceptance. No caller supplies a findings disposition.
"""
from __future__ import annotations

import datetime as dt
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import xml.etree.ElementTree as ET
import zipfile

from .transparency_bundle import canonical, parse, timestamp, read_file, digest

ROOT = Path(__file__).resolve().parents[3]
REPOSITORY = "crypta-network/cryptad"
CHECKOUT = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
WORKFLOWS = {".github/workflows/ci.yml", ".github/workflows/production-beta-release.yml",
             ".github/workflows/public-ecosystem-transparency.yml"}
# These finite semantics belong to the existing workflow triggers. A trigger edit requires
# updating this reviewed adapter; it cannot silently change an exemption during evaluation.
TRIGGERS = {
    ".github/workflows/ci.yml": "  push:\n    branches: [ main, develop, 'release/**', 'hotfix/**' ]\n    tags: [ 'v[0-9]+' ]\n  pull_request:\n    branches: [ main, develop, 'feature/**', 'bugfix/**', 'hotfix/**', 'release/**' ]\n",
    ".github/workflows/production-beta-release.yml": "  pull_request:\n    branches: [ main, develop, 'release/**', 'hotfix/**' ]\n  push:\n    branches: [ 'release/**' ]\n    tags: [ 'v*' ]\n",
    ".github/workflows/public-ecosystem-transparency.yml": "  pull_request:\n    paths:\n      - 'tools/ecosystem-transparency/**'\n      - 'tools/release-certification/cryptad_certification/transparency*'\n      - 'tools/release-certification/cryptad_certification/tests/test_transparency*'\n      - '.github/workflows/public-ecosystem-transparency.yml'\n",
}
CI_STEPS = {
    "build / build": ("Build and analyze (Gradle)", "Build (no Sonar token)"),
    "interop-smoke": ("Run Hyphanet interop smoke",),
    "dependency-submission": ("Generate and submit dependency graph",),
    **{f"interop parser/client self-test ({system})":
       ("Run interop parser/client self-test",) +
       (("Run offline cross-version adapter tests",) if system == "ubuntu-latest" else ())
       for system in ("ubuntu-latest", "macos-latest", "windows-latest")},
    **{f"performance smoke self-test ({system})": ("Run performance smoke self-test",)
       for system in ("ubuntu-latest", "macos-latest", "windows-latest")},
    **{f"release certification self-test ({system})":
       ("Run release certification self-tests", "Test protected producer boundaries offline",
        "Reconcile Phase 12 without operational inputs") for system in ("ubuntu-latest", "macos-latest")},
}
STEPS = {
    ".github/workflows/ci.yml": CI_STEPS,
    ".github/workflows/production-beta-release.yml": {"dry-run-or-release-candidate":
        ("Run production beta pipeline self-test", "Run CI-safe production beta pipeline")},
    ".github/workflows/public-ecosystem-transparency.yml": {"offline":
        ("Offline conformance", "Empty production preview", "Admitted synthetic demo preview", "Browser conformance")},
}
EXPECTED_SKIPS = {".github/workflows/ci.yml": {"interop-extended", "performance-smoke"},
                  ".github/workflows/production-beta-release.yml": {"production-beta"},
                  ".github/workflows/public-ecosystem-transparency.yml":
                      {"build", "transfer-verify", "deploy", "observe"}}
MAX_JSON = 2 * 1024 * 1024
MAX_LOG = 8 * 1024 * 1024
REPORT_FILE = "phase-12-ci-reports.json"
PREPARE_STEP = "Prepare bounded CI report retention"
RETAIN_STEP = "Retain typed CI test and analyzer facts"
ATTEST_STEP = "Attest exact CI report facts"
UPLOAD_STEP = "Upload bounded CI report facts"
MODULES = (".", "apps/queue-manager", "apps/publisher", "apps/feed-reader", "apps/profile-publisher",
           "apps/social-inbox", "apps/site-publisher", "apps/trust-graph", "apps/mail-prototype",
           "platform-design-system", "platform-appvault", "platform-appdist", "platform-devtools",
           "platform-app-ui", "platform-appcatalog", "platform-trustgraph", "foundation-support",
           "foundation-store", "foundation-store-contracts", "foundation-crypto-keys", "interop-wire",
           "foundation-config", "foundation-fs", "foundation-compat", "kernel-content", "kernel-transport",
           "kernel-routing", "runtime-spi", "platform-api", "platform-apphost", "platform-sdk-js",
           "platform-web-shell", "runtime-alerts", "runtime-node", "adapter-fcp", "bridge-fcp-runtime",
           "bridge-http-runtime", "adapter-http-legacy-admin", "adapter-http-legacy-browse",
           "thirdparty-onion", "thirdparty-legacy", "launcher-desktop")
REPORT_KINDS = {"junit", "spotbugs-main", "spotbugs-test", "errorprone-main", "errorprone-test"}


def _producer_identity():
    files = (".github/workflows/build.yml", "build.gradle.kts", "settings.gradle.kts",
             "build-logic/src/main/kotlin/cryptad.java-kotlin-conventions.gradle.kts",
             "build-logic/src/main/kotlin/cryptad.sonar.gradle.kts",
             "tools/release-certification/cryptad_certification/phase_12_ci.py")
    return digest(canonical({name: digest(read_file(ROOT / name)) for name in files}))


def _report_cohort(root):
    """Mirror the existing Java source-set/no-source rules, never a caller cohort flag."""
    selected = set(re.findall(r'":([a-z][a-z:-]+)"', (root / "settings.gradle.kts").read_text()))
    if selected != {name.replace("/", ":") for name in MODULES if name != "."}:
        _deny()
    result = []
    for module in MODULES:
        project = root / module
        main = list((project / "src/main/java").rglob("*.java"))
        tests = list((project / "src/test/java").rglob("*.java"))
        kotlin = list((project / "src/test/kotlin").rglob("*.kt"))
        if len(main) + len(tests) + len(kotlin) > 30000:
            _deny()
        kinds = (["spotbugs-main", "errorprone-main"] if main else [])
        kinds += ["spotbugs-test", "errorprone-test"] if tests else []
        if tests or kotlin:
            kinds.append("junit")
        result.extend((module, kind) for kind in kinds)
    return sorted(result)


def _report_paths(root, module, kind):
    build = root / module / "build"
    if kind == "junit":
        return sorted((build / "test-results/test").glob("TEST-*.xml"))
    task = "compileTestJava" if kind.endswith("test") else "compileJava"
    if kind.startswith("spotbugs"):
        return [build / "reports/spotbugs" / ("spotbugsTest.xml" if kind.endswith("test") else "spotbugsMain.xml")]
    label = ((module.replace("/", "_") + "_") if module != "." else "") + task
    return [build / "reports/errorprone" / label / (task + ".xml")]


def _number(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]{1,16}", value):
        _deny()
    return int(value)


def _read_report(path):
    path = Path(path).absolute()
    if path.is_symlink() or any(parent.is_symlink() for parent in path.parents):
        _deny()
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 0 < info.st_size <= 16 * 1024 * 1024:
            _deny()
        raw = stream.read(16 * 1024 * 1024 + 1)
    if len(raw) != info.st_size:
        _deny()
    return raw


def _xml_facts(raw, kind, module):
    """Discard all paths, case names, messages, stdout/stderr and private-content digests.

    Counts sufficient for a zero-finding disposition survive. Any finding remains blocking;
    this projection offers no caller-supplied waiver and never publishes diagnostic payloads.
    """
    if len(raw) > 16 * 1024 * 1024 or b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
        _deny()
    tree = ET.fromstring(raw)
    pending, count = [(tree, 0)], 0
    while pending:
        node, depth = pending.pop()
        count += 1
        if count > 200000 or depth > 24:
            _deny()
        pending.extend((child, depth + 1) for child in node)
    if kind == "junit":
        if tree.tag != "testsuite":
            _deny()
        cases = tree.findall("testcase")
        result = {name: _number(tree.get(name)) for name in ("tests", "errors", "failures", "skipped")}
        if (result["tests"] != len(cases) or result["errors"] != sum(len(row.findall("error")) for row in cases)
                or result["failures"] != sum(len(row.findall("failure")) for row in cases)
                or result["skipped"] != sum(len(row.findall("skipped")) for row in cases)):
            _deny()
        observed = tree.get("timestamp")
        if isinstance(observed, str) and re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?", observed):
            observed += "Z"  # Gradle's unzoned JUnit report timestamps are UTC.
        _time(observed)
        return {"counts": result, "executedAt": observed}
    if kind.startswith("spotbugs"):
        if tree.tag != "BugCollection":
            _deny()
        summary, errors = tree.find("FindBugsSummary"), tree.find("Errors")
        if summary is None or errors is None:
            _deny()
        bugs = len(tree.findall("BugInstance"))
        if _number(summary.get("total_bugs")) != bugs:
            _deny()
        counts = {"bugs": bugs, "errors": len(errors.findall("Error")),
                  "missingClasses": len(errors.findall("MissingClass")),
                  "classes": _number(summary.get("total_classes"))}
        if (counts["errors"] != _number(errors.get("errors"))
                or counts["missingClasses"] != _number(errors.get("missingClasses", "0"))):
            _deny()
        observed = dt.datetime.fromtimestamp(_number(tree.get("analysisTimestamp")) / 1000, dt.timezone.utc)
        return {"counts": counts, "executedAt": observed.isoformat()}
    if (tree.tag != "errorproneReport" or tree.get("project") != (":" if module == "." else ":" + module.replace("/", ":"))
            or tree.get("task") != ("compileTestJava" if kind.endswith("test") else "compileJava")):
        _deny()
    counts = {"warnings": 0, "errors": 0}
    for row in tree.findall("diagnostic"):
        if row.get("severity") not in {"warning", "error"}:
            _deny()
        counts["warnings" if row.get("severity") == "warning" else "errors"] += 1
    _time(tree.get("generatedAt"))
    return {"counts": counts, "executedAt": tree.get("generatedAt")}


def retain_reports(output, started_file):
    """Success-only original producer: emit bounded facts, never raw XML or payload digests."""
    if (os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("GITHUB_REPOSITORY") != REPOSITORY
            or os.environ.get("GITHUB_JOB") != "build"):
        _deny()
    source = subprocess.run(["git", "rev-parse", "HEAD", "HEAD^{tree}"], cwd=ROOT,
                            capture_output=True, text=True, timeout=10, check=True).stdout.splitlines()
    start = parse(read_file(started_file))
    if set(start) != {"startedAt"}:
        _deny()
    _time(start["startedAt"])
    rows, total = [], 0
    for module, kind in _report_cohort(ROOT):
        reports = []
        for path in _report_paths(ROOT, module, kind):
            if not path.exists():
                continue
            raw = _read_report(path)
            total += len(raw)
            if total > 256 * 1024 * 1024 or len(reports) > 4096:
                _deny()
            reports.append(_xml_facts(raw, kind, module))
        rows.append({"module": module, "kind": kind, "reports": reports})
    result = {"schemaVersion": 1, "kind": "phase-12-original-ci-report-facts", "sourceCommit": source[0],
              "sourceTree": source[1], "workflowSourceCommit": os.environ["GITHUB_SHA"],
              "signerCommit": os.environ["GITHUB_WORKFLOW_SHA"],
              "runId": int(os.environ["GITHUB_RUN_ID"]), "runAttempt": int(os.environ["GITHUB_RUN_ATTEMPT"]),
              "jobKey": "build", "producerDigest": _producer_identity(), "startedAt": start["startedAt"],
              "generatedAt": dt.datetime.now(dt.timezone.utc).isoformat(), "rows": rows,
              "sonarLint": "owner-skipped-standard-build", "rawPayloads": "not-exported"}
    output = Path(output)
    if output.exists() or output.is_symlink() or any(p.is_symlink() for p in output.parents):
        _deny()
    output.mkdir(mode=0o700)
    raw = canonical(result)
    if len(raw) > MAX_JSON:
        _deny()
    (output / REPORT_FILE).write_bytes(raw)
    (output / REPORT_FILE).chmod(0o600)
    return result


class OriginalCIUnavailable(ValueError):
    """Original GET response could not be acquired within the closed access/size bounds."""


def _deny():
    raise ValueError("phase12-original-ci-invalid")


def _time(value):
    if not isinstance(value, str):
        _deny()
    result = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        _deny()
    return result


def _step_contains(step, instant):
    # Original Actions step timestamps have second precision; raw report/log clocks can have
    # fractions. Preserve that exact API precision interval rather than treating truncation
    # as an unavailable or forged checkout/report.
    return _time(step["started_at"]) <= instant < _time(step["completed_at"]) + dt.timedelta(seconds=1)


def _source_clean(source):
    """A commit label cannot cover locally changed implementation, tests or workflows."""
    identity = subprocess.run(["git", "rev-parse", "HEAD", "HEAD^{tree}"], cwd=ROOT,
                              capture_output=True, text=True, timeout=10, check=True).stdout.splitlines()
    if identity != [source["commit"], source["tree"]]:
        _deny()
    changed = subprocess.run(["git", "status", "--porcelain", "--untracked-files=normal"], cwd=ROOT,
                             capture_output=True, timeout=10, check=True).stdout
    return not changed


class _GitHub:
    """Fixed bounded GET endpoints and explicitly selected repository operator identity."""
    def __init__(self):
        from .transparency_sources import _original_helper
        self.owner = _original_helper()
        self.environment = self.owner._environment()  # gh auth token --user leumor outside Actions.
        self.calls = 0

    def get(self, suffix, *, raw=False):
        if not re.fullmatch(
            r"(?:actions/runs/[1-9][0-9]*/attempts/[1-9][0-9]*(?:/jobs\?per_page=100)?|"
            r"actions/runs/[1-9][0-9]*/artifacts\?per_page=100|actions/artifacts/[1-9][0-9]*/zip|"
            r"actions/jobs/[1-9][0-9]*/logs|check-runs/[1-9][0-9]*(?:/annotations\?per_page=100)?|"
            r"git/commits/[0-9a-f]{40}|pulls/[1-9][0-9]*(?:/files\?per_page=100&page=[1-3])?)", suffix):
            _deny()
        self.calls += 1
        if self.calls > 128:
            _deny()
        from bounded_process import run
        try:
            result = run(["gh", "api", "--method", "GET", f"repos/{REPOSITORY}/{suffix}"],
                         environment=self.environment, timeout=45, output_limit=MAX_LOG if raw else MAX_JSON)
        except (ValueError, OSError):
            raise OriginalCIUnavailable("phase12-original-ci-access-unavailable") from None
        if raw:
            return result
        return parse(result)

    def attest(self, raw, run, workflow_source, signer):
        with tempfile.TemporaryDirectory(prefix="phase12-ci-attest-") as temporary:
            path = Path(temporary) / REPORT_FILE
            path.write_bytes(raw)
            result = self.owner._gh(["attestation", "verify", str(path), "--repo", REPOSITORY,
                "--signer-workflow", REPOSITORY + "/.github/workflows/build.yml",
                "--source-digest", workflow_source, "--signer-digest", signer, "--format", "json"],
                self.environment)
        invocation = f"https://github.com/{REPOSITORY}/actions/runs/{run['id']}/attempts/{run['run_attempt']}"
        if not isinstance(result, list) or not any(
                row.get("verificationResult", {}).get("signature", {}).get("certificate", {}).get("runInvocationURI") == invocation
                for row in result if isinstance(row, dict)):
            _deny()


def _report_facts(raw, source, run, job, evaluation, workflow_source, signer):
    value = parse(raw)
    fields = {"schemaVersion", "kind", "sourceCommit", "sourceTree", "workflowSourceCommit", "runId",
              "runAttempt", "jobKey", "producerDigest", "startedAt", "generatedAt", "rows", "sonarLint", "rawPayloads", "signerCommit"}
    if (type(value) is not dict or set(value) != fields or type(value["schemaVersion"]) is not int or value["schemaVersion"] != 1
            or value["kind"] != "phase-12-original-ci-report-facts" or value["sourceCommit"] != source["commit"]
            or value["sourceTree"] != source["tree"] or value["workflowSourceCommit"] != workflow_source or value["signerCommit"] != signer
            or type(value["runId"]) is not int or type(value["runAttempt"]) is not int
            or value["runId"] != run["id"] or value["runAttempt"] != run["run_attempt"] or value["jobKey"] != "build"
            or value["producerDigest"] != _producer_identity() or value["sonarLint"] != "owner-skipped-standard-build"
            or value["rawPayloads"] != "not-exported" or type(value["rows"]) is not list):
        _deny()
    steps = {step["name"]: step for step in job["steps"]}
    start, end = _time(value["startedAt"]), _time(value["generatedAt"])
    if not (_step_contains(steps[PREPARE_STEP], start) and _step_contains(steps[RETAIN_STEP], end)
            and start <= end <= evaluation):
        _deny()
    if [(row.get("module"), row.get("kind")) for row in value["rows"]] != _report_cohort(ROOT):
        _deny()
    totals = {"tests": 0, "failures": 0, "errors": 0, "skipped": 0, "bugs": 0,
              "missingClasses": 0, "warnings": 0}
    blockers, report_count = [], 0
    for row in value["rows"]:
        if set(row) != {"module", "kind", "reports"} or type(row["reports"]) is not list or len(row["reports"]) > 4096:
            _deny()
        expected = ({"tests", "failures", "errors", "skipped"} if row["kind"] == "junit" else
                    {"bugs", "errors", "missingClasses", "classes"} if row["kind"].startswith("spotbugs") else {"warnings", "errors"})
        if not row["reports"]:
            blockers.append("original-ci-required-report-missing")
        for report in row["reports"]:
            report_count += 1
            if (report_count > 4096 or type(report) is not dict or set(report) != {"counts", "executedAt"}
                    or type(report["counts"]) is not dict or set(report["counts"]) != expected
                    or any(type(number) is not int or not 0 <= number <= 10000000 for number in report["counts"].values())):
                _deny()
            if not start <= _time(report["executedAt"]) <= end:
                blockers.append("original-ci-report-execution-outside-selected-job")
            if row["kind"] == "junit" and (not report["counts"]["tests"]
                    or sum(report["counts"][key] for key in ("failures", "errors", "skipped")) > report["counts"]["tests"]):
                _deny()
            if row["kind"].startswith("spotbugs") and not report["counts"]["classes"]:
                blockers.append("original-ci-analyzer-class-coverage-empty")
            for name, number in report["counts"].items():
                if name in totals:
                    totals[name] += number
    if not totals["tests"]:
        blockers.append("original-ci-tests-not-observed")
    if totals["failures"] or totals["errors"]:
        blockers.append("original-ci-test-or-analyzer-failures")
    if totals["bugs"] or totals["missingClasses"] or totals["warnings"]:
        blockers.append("original-ci-analyzer-findings-require-disposition")
    if totals["skipped"]:
        blockers.append("original-ci-skipped-tests-require-owner-disposition")
    return {"cohortRows": len(value["rows"]), "reportCount": report_count, "totals": totals,
            "sonarLint": value["sonarLint"], "rawPayloads": "not-exported", "workflowSourceCommit": workflow_source,
            "signerCommit": signer, "blockers": sorted(set(blockers))}


def _reports(client, run, job, source, evaluation):
    steps = {step["name"]: step for step in job["steps"]}
    if any(steps.get(name, {}).get("conclusion") != "success" for name in (PREPARE_STEP, RETAIN_STEP, ATTEST_STEP, UPLOAD_STEP)):
        return None
    listed = client.get(f"actions/runs/{run['id']}/artifacts?per_page=100")
    if (type(listed) is not dict or listed.get("total_count") != len(listed.get("artifacts", []))
            or len(listed["artifacts"]) > 100):
        _deny()
    name = f"phase-12-ci-reports-{run['id']}-{run['run_attempt']}"
    selected = [row for row in listed["artifacts"] if row.get("name") == name]
    if not selected:
        return None
    if len(selected) != 1:
        _deny()
    artifact = selected[0]
    if (artifact.get("expired") is not False or artifact.get("workflow_run", {}).get("id") != run["id"]
            or artifact["workflow_run"].get("head_sha") != run["head_sha"]
            or not _time(steps[UPLOAD_STEP]["started_at"]) <= _time(artifact["created_at"]) <= _time(steps[UPLOAD_STEP]["completed_at"])
            or type(artifact.get("id")) is not int or type(artifact.get("size_in_bytes")) is not int
            or not 0 < artifact["size_in_bytes"] <= MAX_JSON or not re.fullmatch(r"sha256:[0-9a-f]{64}", str(artifact.get("digest")))):
        _deny()
    archive = client.get(f"actions/artifacts/{artifact['id']}/zip", raw=True)
    if len(archive) != artifact["size_in_bytes"] or digest(archive) != artifact["digest"]:
        _deny()
    if (len(archive) < 22 or archive[:4] != b"PK\x03\x04" or archive[-22:-18] != b"PK\x05\x06"
            or int.from_bytes(archive[-10:-6], "little") + int.from_bytes(archive[-6:-2], "little") != len(archive) - 22):
        _deny()
    with zipfile.ZipFile(io.BytesIO(archive)) as container:
        members = container.infolist()
        if container.comment or len(members) != 1 or members[0].filename != REPORT_FILE:
            _deny()
        member = members[0]
        if (member.file_size > MAX_JSON or member.flag_bits & 1 or member.is_dir() or member.extra or member.comment
                or member.header_offset != 0 or member.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
                or stat.S_IFMT(member.external_attr >> 16) not in {0, stat.S_IFREG}):
            _deny()
        raw = container.read(member)
    # A PR can execute a reviewed head while its local reusable workflow/signature originates
    # at the original test merge. Validate that actual parent relationship and exact original
    # attestation, retaining the difference instead of replacing either commit with the other.
    selected = parse(raw)
    workflow_source, signer = selected.get("workflowSourceCommit"), selected.get("signerCommit")
    if (not isinstance(workflow_source, str) or not re.fullmatch(r"[a-f0-9]{40}", workflow_source)
            or signer != workflow_source):
        _deny()
    different = workflow_source != run["head_sha"]
    if different:
        if run["event"] != "pull_request":
            _deny()
        commit = client.get("git/commits/" + workflow_source)
        if (commit.get("sha") != workflow_source or len(commit.get("parents", [])) != 2
                or run["head_sha"] not in {row["sha"] for row in commit["parents"]}):
            _deny()
    client.attest(raw, run, workflow_source, signer)
    facts = _report_facts(raw, source, run, job, evaluation, workflow_source, signer)
    if different:
        facts["blockers"].append("original-workflow-source-differs-from-audited-product")
    return facts


def _checkout_sha(job, raw):
    """Read only the pinned checkout action's exact original step interval in the job log."""
    checkout = [step for step in job["steps"] if step.get("name") == "Run " + CHECKOUT]
    if len(checkout) != 1 or checkout[0].get("conclusion") != "success":
        return None
    step = checkout[0]
    lines = []
    for line in raw.decode("utf-8", errors="strict").splitlines():
        match = re.fullmatch(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z) (.*)", line)
        if match and _step_contains(step, _time(match[1])):
            lines.append(match[2])
    selected = []
    for index, line in enumerate(lines[:-1]):
        if re.fullmatch(r"\[command\](?:[^ ]*/)?git(?:\.exe)? log -1 --format=(?:%H|'\%H'|\"%H\")", line):
            value = lines[index + 1].strip()
            if re.fullmatch(r"[0-9a-f]{40}", value):
                selected.append(value)
    return selected[0] if len(selected) == 1 else None


def _workflow_applicability(client, run, evaluation):
    """Use original event coordinates and complete current metadata for that exact PR diff.

    Retained callers never provide changed paths. GitHub's PR-file API is mutable, so both
    sides of its bounded read must still match the head/base recorded on the original run.
    Missing, moved or truncated context is unknown; it cannot grant a path exemption.
    """
    def unknown(code):
        return {"state": "unknown", "requiredWorkflows": [], "context": None}, [code]
    for path, expected in TRIGGERS.items():
        text = read_file(ROOT / path).decode("utf-8")
        if "\non:\n" not in text or text.split("\non:\n", 1)[1].split("  workflow_dispatch:\n", 1)[0] != expected:
            return unknown("original-ci-workflow-trigger-policy-drift")
    required = set()
    if run["event"] == "push":
        branch = run.get("head_branch")
        if not isinstance(branch, str) or not branch:
            return unknown("original-ci-push-ref-metadata-unavailable")
        # These disjoint repository release names distinguish the owner's branch and tag
        # trigger classes. Other names cannot be inferred to be an eligible push reference.
        if branch in {"main", "develop"} or re.fullmatch(r"(?:release|hotfix)/.+", branch):
            required.add(".github/workflows/ci.yml")
        if branch.startswith("release/") or re.fullmatch(r"v[^/]*", branch):
            required.add(".github/workflows/production-beta-release.yml")
        if re.fullmatch(r"v[0-9]+", branch):
            required.add(".github/workflows/ci.yml")
        if not required:
            return unknown("original-ci-push-ref-outside-owner-filters")
        return {"state": "authenticated-event-filters", "requiredWorkflows": sorted(required),
                "context": {"event": "push", "refName": branch}}, []
    originals = run.get("pull_requests")
    if type(originals) is not list or len(originals) != 1:
        return unknown("original-ci-pr-event-metadata-unavailable")
    original = originals[0]
    number = original.get("number")
    if type(number) is not int or not 0 < number < 2**53:
        return unknown("original-ci-pr-event-metadata-unavailable")
    head, base = original.get("head", {}), original.get("base", {})
    if (head.get("sha") != run["head_sha"] or not isinstance(base.get("ref"), str)
            or not re.fullmatch(r"[a-f0-9]{40}", str(base.get("sha")))):
        return unknown("original-ci-pr-event-metadata-unavailable")
    try:
        before = client.get(f"pulls/{number}")
        if (before.get("number") != number or before.get("base", {}).get("repo", {}).get("full_name") != REPOSITORY):
            _deny()
        def identity(value):
            return (value.get("head", {}).get("sha"), value.get("base", {}).get("sha"),
                    value.get("base", {}).get("ref"), value.get("changed_files"), value.get("updated_at"))
        if identity(before)[:3] != (run["head_sha"], base["sha"], base["ref"]):
            return unknown("original-ci-pr-diff-source-drift")
        total = before.get("changed_files")
        if type(total) is not int or not 0 < total <= 300:
            return unknown("original-ci-pr-diff-truncated-or-unavailable")
        if _time(before.get("updated_at")) > evaluation:
            return unknown("original-ci-pr-metadata-after-evaluation")
        files = []
        for page in range(1, (total + 99) // 100 + 1):
            found = client.get(f"pulls/{number}/files?per_page=100&page={page}")
            if type(found) is not list or len(found) != min(100, total - len(files)):
                return unknown("original-ci-pr-diff-truncated-or-unavailable")
            files.extend(found)
        after = client.get(f"pulls/{number}")
        if identity(after) != identity(before):
            return unknown("original-ci-pr-diff-source-drift")
    except OriginalCIUnavailable:
        return unknown("original-ci-pr-applicability-access-unavailable")
    paths = []
    for item in files:
        path = item.get("filename")
        names = [path] + ([item.get("previous_filename")] if item.get("status") == "renamed" else [])
        if any(not isinstance(name, str) or len(name) > 2048 or name.startswith("/") or "\\" in name
               or any(part in {"", ".", ".."} for part in name.split("/"))
               or any(ord(char) < 32 for char in name) for name in names):
            _deny()
        paths.extend(names)
    if len({item["filename"] for item in files}) != total:
        return unknown("original-ci-pr-diff-truncated-or-unavailable")
    branch = base["ref"]
    if branch in {"main", "develop"} or re.fullmatch(r"(?:feature|bugfix|hotfix|release)/.+", branch):
        required.add(".github/workflows/ci.yml")
    if branch in {"main", "develop"} or re.fullmatch(r"(?:release|hotfix)/.+", branch):
        required.add(".github/workflows/production-beta-release.yml")
    if any(re.fullmatch(r"(?:tools/ecosystem-transparency/.+|"
            r"tools/release-certification/cryptad_certification/transparency[^/]*|"
            r"tools/release-certification/cryptad_certification/tests/test_transparency[^/]*|"
            r"\.github/workflows/public-ecosystem-transparency\.yml)", path) for path in paths):
        required.add(".github/workflows/public-ecosystem-transparency.yml")
    return {"state": "authenticated-event-and-complete-pr-diff", "requiredWorkflows": sorted(required),
            "context": {"event": "pull_request", "number": number, "baseCommit": base["sha"],
                        "baseBranch": branch, "changedFiles": total}}, []


def _run(client, requested, source, as_of):
    selected = requested["run"]
    run_id, attempt = selected["id"], selected["run_attempt"]
    prefix = f"actions/runs/{run_id}/attempts/{attempt}"
    run = client.get(prefix)
    if (run.get("id") != run_id or run.get("run_attempt") != attempt
            or run.get("repository", {}).get("full_name") != REPOSITORY
            or run.get("head_sha") != source["commit"] or run.get("path") not in WORKFLOWS
            or run.get("path") != selected["path"] or run.get("event") != selected["event"]
            or run.get("event") not in {"push", "pull_request"}
            or run.get("status") != "completed" or _time(run["updated_at"]) > as_of):
        _deny()
    jobs = client.get(prefix + "/jobs?per_page=100")
    if (type(jobs) is not dict or type(jobs.get("jobs")) is not list
            or jobs.get("total_count") != len(jobs["jobs"]) or len(jobs["jobs"]) > 32):
        _deny()
    actual = {row["name"]: row for row in jobs["jobs"]}
    expected = STEPS[run["path"]]
    if (len(actual) != len(jobs["jobs"]) or not set(expected) <= set(actual)
            or not set(actual) <= set(expected) | EXPECTED_SKIPS[run["path"]]):
        _deny()
    records, blockers = [], []
    for name, job in sorted(actual.items()):
        if (job.get("run_id") != run_id or job.get("run_attempt", attempt) != attempt
                or job.get("head_sha") != source["commit"] or type(job.get("id")) is not int
                or type(job.get("steps")) is not list or len(job["steps"]) > 100):
            _deny()
        conclusion = job.get("conclusion")
        if name not in expected:
            if conclusion != "skipped":
                _deny()
            records.append({"jobId": job["id"], "name": name, "execution": "skipped",
                            "scope": "owner-event-inapplicable"})
            continue
        steps = {step["name"]: step for step in job["steps"]}
        if len(steps) != len(job["steps"]):
            _deny()
        required = expected[name]
        passing = [step for step in required if steps.get(step, {}).get("conclusion") == "success"]
        executed = (conclusion == "success" and (len(passing) == 1 if name == "build / build"
                                                 else len(passing) == len(required)))
        if not executed:
            blockers.append("required-original-ci-job-not-executed-pass")
        try:
            checked = _checkout_sha(job, client.get(f"actions/jobs/{job['id']}/logs", raw=True))
        except OriginalCIUnavailable:
            checked = None
            blockers.append("original-checkout-log-unavailable")
        if checked is None:
            blockers.append("original-checkout-identity-unavailable")
        elif checked != source["commit"]:
            blockers.append("original-checkout-differs-from-audited-source")
        kind = "push" if run["event"] == "push" else "pr-head" if checked == source["commit"] else "pr-test-merge-unverified"
        if checked and checked != source["commit"]:
            commit = client.get("git/commits/" + checked)
            if commit.get("sha") != checked:
                _deny()
            if run["event"] == "pull_request" and source["commit"] in {p["sha"] for p in commit.get("parents", [])}:
                kind = "pr-test-merge"
        check_url = job.get("check_run_url", "")
        match = re.fullmatch(r"https://api.github.com/repos/crypta-network/cryptad/check-runs/([1-9][0-9]*)", check_url)
        if match is None:
            _deny()
        check = client.get("check-runs/" + match[1])
        if (check.get("id") != int(match[1]) or check.get("head_sha") != source["commit"]
                or check.get("name") != name or check.get("app", {}).get("slug") != "github-actions"
                or check.get("conclusion") != conclusion):
            _deny()
        count = check.get("output", {}).get("annotations_count")
        if type(count) is not int or not 0 <= count <= 100:
            _deny()
        annotations = client.get("check-runs/" + match[1] + "/annotations?per_page=100")
        if type(annotations) is not list or len(annotations) != count:
            _deny()
        levels = {level: 0 for level in ("notice", "warning", "failure")}
        for item in annotations:
            level = item.get("annotation_level")
            if level not in levels:
                _deny()
            levels[level] += 1
        if levels["warning"] or levels["failure"]:
            blockers.append("original-ci-annotations-require-disposition")
        if name == "build / build" and steps.get("Build and analyze (Gradle)", {}).get("conclusion") == "success":
            blockers.append("original-sonarcloud-disposition-unavailable")
        reports = None
        if name == "build / build":
            try:
                reports = _reports(client, run, job, source, as_of)
            except OriginalCIUnavailable:
                blockers.append("original-ci-report-access-unavailable")
            if reports is not None:
                blockers.extend(reports["blockers"])
        skipped = (conclusion in {"skipped", "neutral"} or (conclusion == "success" and not executed
                   and any(steps.get(step, {}).get("conclusion") in {None, "skipped", "neutral"} for step in required)))
        records.append({"jobId": job["id"], "name": name,
            "execution": "executed-pass" if conclusion == "success" and job["steps"] else "skipped" if conclusion in {"skipped", "neutral"} else "executed-fail",
            "requiredStepExecution": "executed-pass" if executed else "skipped" if skipped else "executed-fail",
            "jobConclusion": conclusion,
            "checkedCommit": checked, "checkoutKind": kind, "checkRunId": check["id"],
            "annotationCounts": levels, "reportFacts": reports,
            "tests": "original-attested-report-facts" if reports is not None else "original-machine-reports-unavailable",
            "analyzers": "original-attested-applicable-report-facts" if reports is not None else
                         "annotation-counts-only;complete-original-reports-unavailable"})
    applicability, gaps = _workflow_applicability(client, run, as_of)
    blockers.extend(gaps)
    return {"runId": run_id, "attempt": attempt, "workflow": run["path"], "event": run["event"],
            "sourceCommit": source["commit"], "requiredWorkflows": applicability["requiredWorkflows"],
            "applicability": applicability, "jobs": records}, blockers


def verify(raw, source, as_of, *, collect_original=False):
    """Reauthenticate selected retained run coordinates only when explicitly requested.

    Historical missing reports remain unavailable. Newly retained source-owned facts must
    pass exact original artifact/attestation admission and the complete report cohort; no
    caller-supplied flag or locally resealed summary can grant acceptance.
    """
    from .phase_12_provenance import hosted_records
    retained = hosted_records(raw, source, as_of)
    if not collect_original:
        return retained
    try:
        clean = _source_clean(source)
        now = timestamp(as_of).replace(tzinfo=dt.timezone.utc)
        if now > dt.datetime.now(dt.timezone.utc):
            _deny()
        client = _GitHub()
        records, blockers, workflows = [], [], set()
        if not clean:
            blockers.append("ci-effective-source-differs-from-hosted-commit")
        for selected in parse(raw)["runs"]:
            record, gaps = _run(client, selected, source, now)
            if record["workflow"] in workflows:
                _deny()
            workflows.add(record["workflow"])
            records.append(record)
            blockers.extend(gaps)
        required_workflows = {path for record in records for path in record["requiredWorkflows"]}
        if records and all(record["applicability"]["state"] != "unknown" for record in records):
            if len({canonical(record["applicability"]["context"]) for record in records}) != 1:
                _deny()
            if workflows != required_workflows:
                blockers.append("required-original-ci-workflow-not-selected")
        # Historical builds retain only product archives. The new source-owned attested
        # projection permits an actual complete path without exposing raw diagnostic payloads.
        report_sets = [job["reportFacts"] for record in records for job in record["jobs"]
                       if job.get("reportFacts") is not None]
        if len(report_sets) != 1:
            blockers.extend(["original-ci-test-report-retention-unavailable",
                             "original-ci-nonblocking-analyzer-reports-unavailable"])
        required_jobs = [job for record in records for job in record["jobs"] if "scope" not in job]
        state = ("executed-fail" if any(job["requiredStepExecution"] == "executed-fail" for job in required_jobs)
                 else "skipped" if any(job["requiredStepExecution"] == "skipped" for job in required_jobs)
                 else "unknown" if blockers else "executed-pass")
        return {"originalProvenance": "authenticated" if records else "not-supplied", "ci": state,
                "records": records, "observedAt": as_of, "retainedBytesDigest": retained["retainedBytesDigest"],
                "sourceDrift": not clean, "blockers": sorted(set(blockers))}
    except OriginalCIUnavailable:
        return {**retained, "sourceDrift": not clean,
                "blockers": sorted(set(retained["blockers"] + ["original-ci-access-unavailable"]))}
    except Exception:
        raise ValueError("phase12-original-ci-invalid") from None


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--prepare", type=Path)
    parser.add_argument("--retain", type=Path)
    parser.add_argument("--started", type=Path)
    args = parser.parse_args()
    try:
        if args.prepare and not args.retain and not args.started:
            with args.prepare.open("xb") as output:
                output.write(canonical({"startedAt": dt.datetime.now(dt.timezone.utc).isoformat()}))
            args.prepare.chmod(0o600)
        elif args.retain and args.started and not args.prepare:
            retain_reports(args.retain, args.started)
        else:
            _deny()
    except Exception:
        raise SystemExit("phase12-ci-report-retention-failed") from None
