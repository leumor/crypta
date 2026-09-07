"""Execute local profile conformance without manufacturing release or reviewer authority."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import xml.etree.ElementTree as ET

from ..io import read_json_bytes, write_json
from ..redaction import scan_value
from ..schema_validation import validate_schema
from .stable_1_0_rc_core import CONTENT_PROFILE_IDS, semantic_digest

CORPUS = "platform-api/src/test/resources/content-profile-conformance/v1"
POLICY = "tools/release-certification/content-profile-review-policy.json"
SUMMARY = "build/content-profile-review/summary.json"


def digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def source_identity(root: Path) -> dict:
    """Bind current tracked and untracked source bytes, including dirty local implementations."""
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    names = subprocess.check_output(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"], cwd=root
    ).decode().split("\0")
    subjects = []
    for name in sorted(set(names) - {""}):
        path = root / name
        if path.is_symlink():
            subjects.append([name, "link", os.readlink(path)])
        elif path.is_file():
            subjects.append([name, digest(path)])
        else:
            subjects.append([name, "missing"])
    return {"commit": commit, "implementationDigest": semantic_digest(subjects)}


def corpus_identity(root: Path) -> dict:
    """Reject duplicate case identities and bind all exact public synthetic vector bytes."""
    directory = root / CORPUS
    manifest = read_json_bytes((directory / "manifest.json").read_bytes(), "public corpus")
    cases = manifest.get("cases", [])
    ids = [case.get("caseId") for case in cases]
    if not ids or len(set(ids)) != len(ids):
        raise ValueError("profile-review-case-set-invalid")
    if set(case.get("profileId") for case in cases) != set(CONTENT_PROFILE_IDS):
        raise ValueError("profile-review-profile-coverage-missing")
    for case in cases:
        for field, hash_field in (("inputFile", "inputDigest"),
                                  ("expectedCanonicalBytesFile", "expectedCanonicalDigest"),
                                  ("expectedSignaturePreimageFile", None)):
            if field not in case:
                continue
            relative = Path(case[field])
            if relative.is_absolute() or ".." in relative.parts:
                raise ValueError("profile-review-corpus-path-invalid")
            path = directory / relative
            if not path.is_file() or path.is_symlink():
                raise ValueError("profile-review-vector-missing")
            if hash_field and digest(path).removeprefix("sha256:") != case[hash_field]:
                raise ValueError("profile-review-vector-digest-mismatch")
            if field == "inputFile" and path.stat().st_size != case["inputSize"]:
                raise ValueError("profile-review-vector-size-mismatch")
    files = []
    for path in sorted(directory.rglob("*")):
        if path.is_symlink():
            raise ValueError("profile-review-corpus-link-rejected")
        if path.is_file():
            files.append([path.relative_to(directory).as_posix(), digest(path)])
    return {"digest": semantic_digest(files), "caseCount": len(ids)}


def validate_policy(policy: dict) -> None:
    if set(policy) != {"schemaVersion", "evaluationTime", "suites", "serviceContracts", "limitations", "javascriptGroups", "profiles"}:
        raise ValueError("profile-review-policy-fields-invalid")
    profile_decisions(policy)
    suites = policy["suites"]
    if not suites or len({suite["className"] for suite in suites}) != len(suites):
        raise ValueError("profile-review-suite-set-invalid")
    for suite in suites:
        if set(suite) != {"module", "className", "resultFile", "testCases"} or not suite["testCases"]:
            raise ValueError("profile-review-suite-fields-invalid")
        if len(set(suite["testCases"])) != len(suite["testCases"]):
            raise ValueError("profile-review-test-set-invalid")
        expected = suite["module"].replace(":", "/") + "/build/test-results/test/TEST-" + suite["className"] + ".xml"
        if suite["resultFile"] != expected:
            raise ValueError("profile-review-suite-result-invalid")
    if len(policy["serviceContracts"]) != 1 or policy["serviceContracts"][0]["serviceId"] != "trust.score":
        raise ValueError("profile-review-service-set-invalid")


def test_results(root: Path, suites: list[dict]) -> list[dict]:
    """Require the complete policy-declared JUnit case set; skips cannot satisfy execution."""
    results = []
    for suite in suites:
        path = root / suite["resultFile"]
        try:
            tree = ET.fromstring(path.read_bytes())
        except ET.ParseError:
            raise ValueError("profile-review-result-xml-invalid") from None
        cases = tree.findall("testcase")
        names = [case.get("name") for case in cases]
        if (not names or len(set(names)) != len(names)
                or sorted(names) != sorted(suite["testCases"])):
            raise ValueError("profile-review-test-set-mismatch")
        if any(case.find(tag) is not None for case in cases for tag in ("failure", "error", "skipped")):
            raise ValueError("profile-review-test-not-passed")
        if any(case.get("classname") != suite["className"] for case in cases):
            raise ValueError("profile-review-test-substitution")
        results.append({"className": suite["className"], "caseCount": len(cases),
                        "resultDigest": digest(path)})
    return results


def profile_decisions(policy: dict) -> list[dict]:
    """Require a closed, complete set of explicitly reviewed retention decisions."""
    rows = policy.get("profiles", [])
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise ValueError("profile-review-policy-profile-set-invalid")
    if tuple(row.get("profileId") for row in rows) != CONTENT_PROFILE_IDS:
        raise ValueError("profile-review-policy-profile-set-invalid")
    for row in rows:
        if set(row) != {"profileId", "version", "effectiveStatus", "recommendedStatus", "decision"}:
            raise ValueError("profile-review-policy-profile-fields-invalid")
        status = row["effectiveStatus"]
        if (type(row["version"]) is not int or row["version"] != 1
                or status not in {"stable", "experimental", "beta"}
                or row["recommendedStatus"] != status or row["decision"] != "retain-" + status):
            raise ValueError("profile-review-policy-decision-invalid")
    return rows


def registry_rows(value: dict, policy: dict) -> list[dict]:
    if value.get("schemaVersion") != 1 or value.get("kind") != "content-format-profile-registry":
        raise ValueError("profile-review-registry-invalid")
    rows = value.get("profiles", [])
    if tuple(row.get("id") for row in rows) != CONTENT_PROFILE_IDS:
        raise ValueError("profile-review-registry-set-invalid")
    result = []
    for row, decision in zip(rows, profile_decisions(policy)):
        if (type(row.get("majorVersion")) is not int
                or row.get("status") != decision["effectiveStatus"]
                or row.get("majorVersion") != decision["version"]):
            raise ValueError("profile-review-status-or-version-requires-review")
        result.append({**decision, "descriptorDigest": semantic_digest(row)})
    return result


def javascript_results(root: Path, log: Path, policy: dict) -> dict:
    try:
        value = read_json_bytes(log.read_bytes().splitlines()[-1], "javascript result")
    except (ValueError, IndexError):
        raise ValueError("profile-review-javascript-result-invalid") from None
    manifest = read_json_bytes((root / CORPUS / "manifest.json").read_bytes(), "corpus")
    expected = [case["caseId"] for case in manifest["cases"]] + policy["javascriptGroups"]
    if (value.get("executedCases") != expected or len(set(expected)) != len(expected)
            or value.get("skippedRequired") != 0
            or value.get("manifestDigest") != digest(root / CORPUS / "manifest.json").removeprefix("sha256:")
            or value.get("unsupportedDirections") != ["javascript-production-trust-verifier", "historical-executable-reader", "independent-external-implementation"]):
        raise ValueError("profile-review-javascript-coverage-mismatch")
    return {"runtime": value["runtime"], "caseCount": len(expected), "resultDigest": semantic_digest(value),
            "productionByteIngress": "not-observed", "referenceTrustVerifier": "first-party-only"}


def specification_digest(root: Path) -> str:
    return semantic_digest([[name, digest(root / "docs" / name)] for name in (
        "trust-social-content-format-profiles.md", "trust-social-stable-profile-review.md",
        "trust-social-wire-contracts.md", "trust-social-consumer-review.md",
        "trust-social-local-service-review.md")])


def service_definition_digest(root: Path) -> str:
    lines = (root / "apps/trust-graph/src/staged/cryptad-app.properties.template").read_text().splitlines()
    descriptor = dict(line.split("=", 1) for line in lines if line.startswith("app.service.trust-score."))
    expected = {"id": "trust.score", "version": "1", "adapter": "trust-graph.score",
                "scopes": "score.read", "contexts": "message-author,profile", "kind": "platform-adapter"}
    if any(descriptor.get("app.service.trust-score." + key) != value for key, value in expected.items()):
        raise ValueError("profile-review-service-definition-requires-review")
    return semantic_digest(descriptor)


def _validate_output_path(root: Path, path: Path, *, directory: bool = False) -> None:
    """Reject links and nonregular destinations, including linked parent directories."""
    base = root.absolute()
    relative = path.absolute().relative_to(base)
    if ".." in relative.parts:
        raise ValueError("profile-review-output-outside-workspace")
    current = base
    for index, part in enumerate(relative.parts):
        current = current / part
        if current.is_symlink():
            raise ValueError("profile-review-output-symlink")
        if current.exists():
            wants_directory = directory or index < len(relative.parts) - 1
            if not (current.is_dir() if wants_directory else current.is_file()):
                raise ValueError("profile-review-output-type-invalid")


def _validate_outputs(root: Path) -> Path:
    output = root / "build/content-profile-review"
    _validate_output_path(root, output, directory=True)
    if output.exists():
        for path in output.iterdir():
            _validate_output_path(root, path)
    return output


def _execute(root: Path, command: list[str], log: Path) -> None:
    # Capture privately and replace atomically: never truncate an existing link or hardlink target.
    _validate_output_path(root, log)
    descriptor, name = tempfile.mkstemp(prefix=".review-log-", dir=log.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            completed = subprocess.run(command, cwd=root, stdout=output, stderr=subprocess.STDOUT)
        _validate_output_path(root, log)
        os.replace(temporary, log)
    finally:
        temporary.unlink(missing_ok=True)
    if completed.returncode:
        raise ValueError("profile-review-execution-failed")


def run(root: Path, mode: str) -> int:
    """Inspect metadata or execute the fixed local suite; never import caller pass receipts."""
    try:
        output = _validate_outputs(root)
        output.mkdir(parents=True, exist_ok=True)
        summary_path = output / "summary.json"
        failure_path = output / "failure.json"
        if mode == "review":
            summary_path.unlink(missing_ok=True)
            write_json(failure_path, {"kind": "content-profile-review-failure", "state": "incomplete-or-failed"})
        policy = read_json_bytes((root / POLICY).read_bytes(), "review policy")
        validate_policy(policy)
        source = source_identity(root)
        corpus = corpus_identity(root)
        if mode == "inspect":
            print(json.dumps({"kind": "content-profile-review-inspection", "source": source,
                              "corpus": corpus, "execution": "not-run"}, sort_keys=True))
            return 0
        tasks = []
        for suite in policy["suites"]:
            module = suite["module"]
            if ":" + module + ":cleanTest" not in tasks:
                tasks.extend([":" + module + ":cleanTest", ":" + module + ":test"])
            tasks.extend(["--tests", suite["className"]])
        wrapper = [str(root / "gradlew.bat")] if os.name == "nt" else ["bash", "gradlew"]
        _execute(root, [*wrapper, *tasks, ":platform-devtools:installDist"], output / "execution-private.log")
        registry_path = output / "registry.json"
        registry_path.unlink(missing_ok=True)
        launcher = root / "platform-devtools/build/install/crypta-app/bin" / ("crypta-app.bat" if os.name == "nt" else "crypta-app")
        _execute(root, [str(launcher), "api", "content-formats", "--output", str(registry_path)], output / "registry-private.log")
        rows = registry_rows(read_json_bytes(registry_path.read_bytes(), "registry"), policy)
        results = test_results(root, policy["suites"])
        javascript_log = output / "javascript-private.log"
        _execute(root, ["node", "platform-sdk-js/src/test/resources/content-profile-conformance.cjs", "."], javascript_log)
        javascript = javascript_results(root, javascript_log, policy)
        if source != source_identity(root) or corpus != corpus_identity(root):
            raise ValueError("profile-review-input-changed-during-execution")
        summary = {"schemaVersion": 1, "kind": "content-profile-review", "source": source,
                   "corpus": corpus, "policyDigest": digest(root / POLICY),
                   "registryExactFileDigest": digest(registry_path), "profiles": rows,
                   "normativeSpecDigest": specification_digest(root),
                   "serviceDefinitionDigest": service_definition_digest(root),
                   "serviceContracts": policy["serviceContracts"], "results": results,
                   "javascript": javascript,
                   "evidenceLevel": "local-executable-conformance", "reviewDecision": "retain-current-statuses",
                   "independentImplementation": "not-observed", "priorRuntime": "not-observed",
                   "humanSecuritySignoff": "not-observed", "operationalCloseout": "not-assessed",
                   "evaluationTime": policy["evaluationTime"], "limitations": policy["limitations"],
                   "redaction": "pass"}
        if validate_schema(summary, "content-profile-review-v1.schema.json"):
            raise ValueError("profile-review-schema-invalid")
        if scan_value(summary):
            raise ValueError("profile-review-public-output-redaction-failed")
        summary["integrityDigest"] = semantic_digest(summary)
        write_json(summary_path, summary)
        failure_path.unlink(missing_ok=True)
        print("Local executable content-profile conformance completed; statuses retained.")
        return 0
    except (ValueError, OSError, ET.ParseError, subprocess.CalledProcessError):
        print("Content-profile review failed; no successful summary emitted. Inspect local execution logs.")
        return 1


def bound_summary(root: Path) -> dict | None:
    """Validate local report integrity and current artifacts; this is not runner authentication."""
    _validate_outputs(root)
    path = root / SUMMARY
    if (path.parent / "failure.json").exists():
        raise ValueError("profile-review-execution-incomplete-or-failed")
    if not path.exists():
        return None
    value = read_json_bytes(path.read_bytes(), "local review")
    integrity = value.pop("integrityDigest", None)
    if validate_schema(value, "content-profile-review-v1.schema.json"):
        raise ValueError("profile-review-schema-invalid")
    if integrity != semantic_digest(value):
        raise ValueError("profile-review-result-integrity-mismatch")
    policy = read_json_bytes((root / POLICY).read_bytes(), "review policy")
    validate_policy(policy)
    registry = root / "build/content-profile-review/registry.json"
    if (value["source"] != source_identity(root) or value["corpus"] != corpus_identity(root)
            or value["normativeSpecDigest"] != specification_digest(root)
            or value["serviceDefinitionDigest"] != service_definition_digest(root)
            or value["policyDigest"] != digest(root / POLICY)
            or value["registryExactFileDigest"] != digest(registry)
            or value["results"] != test_results(root, policy["suites"])
            or value["javascript"] != javascript_results(root, root / "build/content-profile-review/javascript-private.log", policy)
            or value["profiles"] != registry_rows(read_json_bytes(registry.read_bytes(), "registry"), policy)
            or value["serviceContracts"] != policy["serviceContracts"]
            or value["evaluationTime"] != policy["evaluationTime"]
            or value["limitations"] != policy["limitations"]
            or value["evidenceLevel"] != "local-executable-conformance"
            or value["reviewDecision"] != "retain-current-statuses"
            or any(value[key] != "not-observed" for key in ("independentImplementation", "priorRuntime", "humanSecuritySignoff"))
            or value["operationalCloseout"] != "not-assessed"
            or value["redaction"] != "pass"):
        raise ValueError("profile-review-stale-or-substituted-results")
    if scan_value(value):
        raise ValueError("profile-review-public-output-redaction-failed")
    return {"evidenceLevel": "local-executable-conformance", "integrityDigest": integrity,
            "corpus": value["corpus"], "profiles": value["profiles"],
            "independentImplementation": "not-observed", "operationalCloseout": "not-assessed"}
