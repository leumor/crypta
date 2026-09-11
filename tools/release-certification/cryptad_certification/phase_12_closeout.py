"""Phase 12 acceptance reconciliation, using fixed existing owner verifiers.

The reviewed inventory is mandatory. Assessment integrity, local verifier execution, original
producer authentication and phase acceptance are independent claims. This module has no release,
node, signing, workflow-dispatch or publication operation.
"""
from __future__ import annotations

import copy
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile

from .transparency_bundle import canonical, confined, digest, inventory as file_inventory
from .transparency_bundle import parse, read_file, safe_name, timestamp, tool_identity

ROOT = Path(__file__).resolve().parents[3]
POLICY = ROOT / "tools/release-certification/phase-12-acceptance-policy.json"
SHA = re.compile(r"[a-f0-9]{40}")
DIGEST = re.compile(r"sha256:[a-f0-9]{64}")
ID = re.compile(r"[a-z][a-z0-9-]{0,95}")
DIMENSIONS = {
    "implementation": {"implemented", "partial", "missing", "unknown"},
    "localVerification": {"executed-pass", "executed-fail", "skipped", "not-run", "author-reported"},
    "originalProvenance": {"authenticated", "unverified", "invalid", "not-supplied"},
    "runtimeExecution": {"observed", "partial", "not-observed", "failed"},
    "publication": {"published", "not-observed", "not-performed", "partial", "failed"},
    "activation": {"activated", "not-observed", "not-performed", "partial", "failed"},
    "publicObservation": {"observed", "not-observed", "partial", "stale", "failed"},
    "independentReview": {"accepted", "not-observed", "pending", "rejected", "partial"},
    "coverage": {"complete", "partial", "missing"},
    "cleanup": {"complete", "not-observed", "partial", "failed"},
    "ci": {"executed-pass", "executed-fail", "unknown", "skipped"},
}
INITIAL = {"implementation": "unknown", "localVerification": "not-run",
           "originalProvenance": "not-supplied", "runtimeExecution": "not-observed",
           "publication": "not-observed", "activation": "not-observed",
           "publicObservation": "not-observed", "independentReview": "not-observed",
           "coverage": "missing", "cleanup": "not-observed", "ci": "unknown"}
PASS = {"implementation": "implemented", "localVerification": "executed-pass",
        "originalProvenance": "authenticated", "runtimeExecution": "observed",
        "publication": "published", "activation": "activated", "publicObservation": "observed",
        "independentReview": "accepted", "coverage": "complete", "cleanup": "complete",
        "ci": "executed-pass"}
KINDS = {"audit-tool", "current-product", "historical-product", "app-bundle",
         "subject-projection", "runtime", "public-site", "ci", "authority-record"}
ADAPTER_KINDS = {
    "product-admission": {"current-product", "historical-product"},
    "rc-product-admission": {"current-product", "historical-product"},
    "api-subjects-v2": {"subject-projection"},
    "measured-soak": {"runtime"}, "mail-runtime": {"runtime"},
    "maintenance-measurements": {"runtime"}, "migration-observation": {"runtime"},
    "maintenance-drill": {"audit-tool"}, "profile-review": {"audit-tool"},
    "transparency-bundle": {"public-site"}, "historical-transparency-bundle": {"public-site"},
    "transparency-sources": {"public-site"},
    "site-deployment": {"public-site"}, "site-observation": {"public-site"},
}
PREDECESSORS = {"subject-projection": {"current-product", "historical-product", "app-bundle"},
                "runtime": {"current-product", "historical-product", "subject-projection"},
                "public-site": {"current-product", "historical-product", "app-bundle", "runtime"}}
MAX_INPUT_FILE = 512 * 1024 * 1024  # Original bounded product comparisons may contain real archives.
MAX_INPUT_TOTAL = 1536 * 1024 * 1024
# This pin covers the reviewed acceptance scope, independently of implementation byte pins.
# Updating code/test evidence cannot shrink a cohort or weaken a mandatory dimension. A scope
# revision requires an explicit reviewed code change as well as a new inventory version.
ACCEPTANCE_SCOPE_DIGEST = "sha256:0221c0e5353417bdcff8ef33620f5b924dda6b1240b2d76fad1276775401804c"


def fail(code):
    raise ValueError("phase12-" + code)


def exact(value, fields):
    if type(value) is not dict or set(value) != set(fields.split()):
        fail("closed-contract")


def input_name(name):
    if (type(name) is not str or len(name) > 220
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9./_-]*", name) is None
            or any(part in {"", ".", ".."} for part in name.split("/"))):
        fail("input-name")
    return name


def ordered(rows, key="id", edges="prerequisites"):
    """Stable topological order. Missing dependencies and cycles are errors, never dropped."""
    by_id = {row[key]: row for row in rows}
    if len(by_id) != len(rows):
        fail("duplicate-id")
    if any(type(r.get(edges)) is not list or len(set(r[edges])) != len(r[edges])
           or any(p not in by_id for p in r[edges]) for r in rows):
        fail("orphan-or-duplicate-dependency")
    result, remaining = [], set(by_id)
    while remaining:
        ready = sorted(i for i in remaining if not set(by_id[i][edges]) & remaining)
        if not ready:
            fail("dependency-cycle")
        if edges == "dependencies":
            # Within the ready remediation workstreams, repair the interfaces that unblock
            # more dependents first. This never changes any acceptance decision or threshold.
            ready.sort(key=lambda item: (-sum(item in row[edges] for row in rows), item))
        result.extend(by_id[i] for i in ready)
        remaining.difference_update(ready)
    return result


def policy():
    raw = read_file(POLICY)
    value = parse(raw)
    if value.get("schemaVersion") != 1 or value.get("kind") != "phase-12-acceptance-policy":
        fail("policy-version")
    scope_fields = ("id", "pr", "assertion", "dimensions", "subjects", "prerequisites", "mandatory",
                    "operatingClass", "applicability", "limitations", "closure")
    scope = {"version": value["version"], "requirements": [
        {**{field: row[field] for field in scope_fields},
         "ownerAuthority": {key: item for key, item in row["authority"].items() if key != "policyDigest"},
         "implementationState": row["implementation"]["state"],
         "implementationPaths": {group: [item["path"] for item in row["implementation"][group]]
                                 for group in ("sourceEvidence", "testEvidence")}}
        for row in value["requirements"]],
        "residuals": value["residuals"], "history": value["history"],
        "scopeDecisions": value.get("scopeDecisions", [])}
    if digest(canonical(scope)) != ACCEPTANCE_SCOPE_DIGEST:
        fail("unreviewed-acceptance-scope")
    rows = value["requirements"]
    if len(rows) > 96 or {r["pr"] for r in rows} != {f"PR-{i}" for i in range(291, 304)}:
        fail("policy-domain-coverage")
    ordered(rows)
    for row in rows:
        if (not ID.fullmatch(row["id"]) or row.get("mandatory") is not True
                or not row["dimensions"] or len(set(row["dimensions"])) != len(row["dimensions"])
                or any(d not in DIMENSIONS for d in row["dimensions"])
                or row["implementation"]["state"] not in DIMENSIONS["implementation"]):
            fail("policy-requirement-contract")
    ordered(value["residuals"], edges="dependencies")
    required = {r["id"] for r in rows}
    if any(not set(r["requirementIds"]) <= required for r in value["residuals"]):
        fail("residual-requirement-orphan")
    for historical in value["history"]:
        path = ROOT / historical["path"]
        if digest(read_file(path)) != historical["digest"]:
            fail("historical-statement-pin-drift")
    return value, digest(raw)


def checkout():
    result = subprocess.run(["git", "rev-parse", "HEAD", "HEAD^{tree}"], cwd=ROOT,
                            capture_output=True, text=True, check=True, timeout=10)
    commit, tree = result.stdout.splitlines()
    if not SHA.fullmatch(commit) or not SHA.fullmatch(tree):
        fail("checkout-identity")
    # PR-302's renderer identity intentionally covers fewer protected helpers. These additional
    # original authentication/consumer files are part of the audit tool, including local edits.
    protected = POLICY.parent / "protected"
    original_helpers = {p.relative_to(protected).as_posix(): digest(read_file(p))
                        for p in sorted(protected.rglob("*.py"))}
    effective_tool = digest(canonical({"certificationAndSchemas": tool_identity(),
                                       "originalHelpers": original_helpers}))
    return {"commit": commit, "tree": tree, "toolDigest": effective_tool,
            "binding": "checkout-and-effective-tool-files;historical-products-separate"}


def repository_selection():
    rules, pin = policy()
    return {"schemaVersion": 1, "kind": "phase-12-evidence-selection", "policyDigest": pin,
            "requirementIds": sorted(r["id"] for r in rules["requirements"]), "artifacts": [],
            "previousAssessment": None, "hostedCi": None}


def validate_selection(value, rules, pin):
    from .schema_validation import validate_schema
    if validate_schema(value, "phase-12-evidence-selection-v1.schema.json"):
        fail("selection-schema")
    exact(value, "schemaVersion kind policyDigest requirementIds artifacts previousAssessment hostedCi")
    if (type(value["schemaVersion"]) is not int or value["schemaVersion"] != 1
            or value["kind"] != "phase-12-evidence-selection" or value["policyDigest"] != pin
            or value["requirementIds"] != sorted(r["id"] for r in rules["requirements"])
            or type(value["artifacts"]) is not list or len(value["artifacts"]) > 64):
        fail("mandatory-inventory-or-policy-mismatch")
    from .phase_12_adapters import REQUIRED_INPUTS
    for row in value["artifacts"]:
        exact(row, "id adapter files subject predecessors proof observedAt expiresAt")
        if (type(row["id"]) is not str or not ID.fullmatch(row["id"])
                or row["adapter"] not in REQUIRED_INPUTS or type(row["files"]) is not list
                or len(row["files"]) > 64):
            fail("artifact-contract")
        names = []
        for member in row["files"]:
            exact(member, "name digest size")
            names.append(input_name(member["name"]))
            # The site owner uses an empty predecessor marker for bootstrap. Its verifier
            # checks whether the selected checkpoint permits it; all other inputs stay nonempty.
            minimum_size = 0 if (row["adapter"] in {"site-deployment", "site-observation"}
                                 and member["name"] == "previous.zip") else 1
            if (not DIGEST.fullmatch(member["digest"]) or type(member["size"]) is not int
                    or not minimum_size <= member["size"] <= MAX_INPUT_FILE):
                fail("artifact-byte-contract")
        expected = REQUIRED_INPUTS[row["adapter"]]
        if set(names) != set(expected) or len(set(n.casefold() for n in names)) != len(names):
            fail("adapter-input-cohort")
        subject = row["subject"]
        exact(subject, "kind commit tree build digest")
        if (subject["kind"] not in KINDS or not SHA.fullmatch(subject["commit"])
                or not SHA.fullmatch(subject["tree"]) or not DIGEST.fullmatch(subject["digest"])
                or subject["build"] is not None and (type(subject["build"]) is not str
                    or re.fullmatch(r"[1-9][0-9]{0,9}", subject["build"]) is None)):
            fail("subject-identity")
        if subject["kind"] not in ADAPTER_KINDS.get(row["adapter"], {"authority-record"}):
            fail("adapter-subject-kind")
        for name in ("observedAt", "expiresAt"):
            if row[name] is not None:
                timestamp(row[name])
    graph = ordered(value["artifacts"], edges="predecessors")
    by_id = {r["id"]: r for r in graph}
    seen_observations = set()
    for row in graph:
        kind = row["subject"]["kind"]
        for prior in row["predecessors"]:
            if by_id[prior]["subject"]["kind"] not in PREDECESSORS.get(kind, set()):
                fail("wrong-subject-predecessor")
            if (row["observedAt"] is not None and by_id[prior]["observedAt"] is not None
                    and timestamp(row["observedAt"]) < timestamp(by_id[prior]["observedAt"])):
                fail("retrospective-predecessor")
        if kind in {"runtime", "subject-projection"} and not row["predecessors"]:
            fail("required-subject-orphan")
        if kind == "runtime":
            observation = (row["subject"]["digest"], row["observedAt"])
            if observation in seen_observations:
                fail("duplicate-observation")
            seen_observations.add(observation)
    for name in ("previousAssessment", "hostedCi"):
        if value[name] is not None:
            exact(value[name], "name digest size")
            input_name(value[name]["name"])
            if not DIGEST.fullmatch(value[name]["digest"]) or type(value[name]["size"]) is not int:
                fail("retained-input-identity")
    return graph


def _selected_bytes(selection, source_root):
    expected = {f"{row['id']}/{f['name']}": f for row in selection["artifacts"] for f in row["files"]}
    for name in ("previousAssessment", "hostedCi"):
        if selection[name] is not None:
            member = selection[name]
            if member["name"] in expected:
                fail("duplicate-input")
            expected[member["name"]] = member
    if not expected:
        if source_root is not None and file_inventory(source_root):
            fail("unselected-input-sidecars")
        return {}
    if source_root is None:
        fail("input-root-required")
    source_root = confined(source_root)
    found, directories = {}, set()
    for directory, subdirs, files in os.walk(source_root, followlinks=False):
        for name in subdirs:
            path = Path(directory) / name
            relative = input_name(path.relative_to(source_root).as_posix())
            if path.is_symlink() or relative.count("/") > 4 or len(directories) > 256:
                fail("input-directory")
            directories.add(relative)
        for name in files:
            path = Path(directory) / name
            relative = input_name(path.relative_to(source_root).as_posix())
            if relative not in expected or relative.casefold() in {p.casefold() for p in found}:
                fail("input-inventory-sidecar-or-missing")
            found[relative] = path
    implied = {str(p) for name in expected for p in Path(name).parents if str(p) != "."}
    if set(found) != set(expected) or implied != directories:
        fail("input-inventory-sidecar-or-missing")
    actual, total = {}, 0
    for name, path in sorted(found.items()):
        descriptor = os.open(confined(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as stream:
            status = os.fstat(stream.fileno())
            total += status.st_size
            if (not stat.S_ISREG(status.st_mode) or status.st_nlink != 1
                    or status.st_size > MAX_INPUT_FILE or total > MAX_INPUT_TOTAL
                    or status.st_size != expected[name]["size"]):
                fail("input-type-or-size")
            raw = stream.read(status.st_size + 1)
        actual[name] = raw
    for name, raw in actual.items():
        if len(raw) != expected[name]["size"] or digest(raw) != expected[name]["digest"]:
            fail("input-byte-mismatch")
        if name.endswith(".json"):
            parse(raw)  # Reject duplicate keys/nonfinite/deep JSON even in owner legacy parsers.
    return actual


def implementation(row):
    """A reviewed semantic source assertion applies only while all its exact files match.

No filename/existence search can establish implementation. Policy carries the human-reviewable
assertion and byte pins; source drift becomes unknown pending a new reviewed disposition.
"""
    evidence = row["implementation"]["sourceEvidence"] + row["implementation"]["testEvidence"]
    if not evidence:
        return "unknown", ["implementation-review-required"]
    for item in evidence:
        relative = Path(item["path"])
        if relative.is_absolute() or ".." in relative.parts:
            fail("audited-source-path")
        path = ROOT / relative
        try:
            if digest(read_file(path)) != item["digest"]:
                return "unknown", ["audited-source-drift"]
        except OSError:
            return "unknown", ["audited-source-unavailable"]
    authority = row["authority"]
    if authority.get("policyDigest") and digest(read_file(ROOT / authority["policy"])) != authority["policyDigest"]:
        return "unknown", ["audited-owner-policy-drift"]
    return row["implementation"]["state"], []


def decide(rows, residuals, *, as_of, synthetic=False):
    """Pure total decision; tests can build complete graphs without production fixture authority."""
    timestamp(as_of)
    complete = bool(rows) and not any(r["blockers"] for r in rows)
    for row in rows:
        if any(value != PASS[name] for name, value in row["dimensions"].items()):
            complete = False
    if any(r["status"] not in {"closed", "approved-limitation"} for r in residuals):
        complete = False
    invalid = any("supplied-evidence-invalid" in r["blockers"] for r in rows)
    return {"auditExecuted": True, "assessmentIntegrity": "verified-local-consistency",
            "phaseDecision": "blocked" if invalid else "complete-as-of" if complete else "incomplete",
            "phaseComplete": complete, "asOf": as_of,
            "evidenceContext": "synthetic-test-only" if synthetic else "repository-local-assessment"}


def _carry_forward(rules, previous):
    residuals = copy.deepcopy(rules["residuals"])
    if previous is not None:
        if previous.get("kind") != "phase-12-assessment" or previous.get("schemaVersion") != 1:
            fail("previous-assessment-contract")
        old = {r["id"]: r for r in previous["residuals"]}
        new = {r["id"]: r for r in residuals}
        if not set(old) <= set(new):
            fail("residual-removal")
        for key, row in old.items():
            # No silent renaming, clock reset, scope loss, reclassification or claimed closure.
            for field in ("origin", "requirementIds", "category"):
                if new[key][field] != row[field]:
                    fail("residual-undisposed-change")
            if row["status"] not in {"closed", "approved-limitation"} and new[key]["status"] != row["status"]:
                fail("residual-undisposed-closure")
    return residuals


def evaluate(selection, source_root, as_of, *, collect_original=False):
    """Recompute a bounded assessment; evaluation never starts an experiment or a live node."""
    timestamp(as_of)
    if collect_original:
        from datetime import datetime, timezone
        if timestamp(as_of).replace(tzinfo=timezone.utc) > datetime.now(timezone.utc):
            fail("evaluation-after-current-time")
    rules, pin = policy()
    graph = validate_selection(selection, rules, pin)
    raw_files = _selected_bytes(selection, source_root)
    source = checkout()
    prior = parse(raw_files[selection["previousAssessment"]["name"]]) if selection["previousAssessment"] else None
    residuals = _carry_forward(rules, prior)
    rows = []
    for requirement in ordered(rules["requirements"]):
        dimensions = {d: INITIAL[d] for d in requirement["dimensions"]}
        state, blockers = implementation(requirement)
        dimensions["implementation"] = state
        rows.append({"id": requirement["id"], "pr": requirement["pr"],
                     "capability": requirement["capability"], "dimensions": dimensions,
                     "blockers": blockers, "evidence": [], "verification": [],
                     "prerequisites": requirement["prerequisites"]})
    by_id = {r["id"]: r for r in rows}
    requirement_by_id = {r["id"]: r for r in rules["requirements"]}
    artifacts, verified_results = [], {}
    from .phase_12_adapters import verify
    from .phase_12_provenance import original_proof
    for artifact in graph:
        adapter = artifact["adapter"]
        assigned = [r for r in rows if adapter in requirement_by_id[r["id"]]["authority"].get(
            "adapters", [requirement_by_id[r["id"]]["authority"].get("adapter")])]
        if not assigned:
            fail("unassigned-artifact")
        payloads = {f["name"]: raw_files[f"{artifact['id']}/{f['name']}"] for f in artifact["files"]}
        try:
            if artifact["observedAt"] and timestamp(artifact["observedAt"]) > timestamp(as_of):
                fail("future-observation")
            if artifact["expiresAt"] and timestamp(artifact["expiresAt"]) <= timestamp(as_of):
                fail("stale-observation")
            with tempfile.TemporaryDirectory(prefix="phase12-verify-") as temporary:
                # The OS temp root may have trusted symlink ancestors (for example macOS /var).
                # Canonicalize only our allocated scratch; selected evidence stays confined as supplied.
                scratch = Path(temporary).resolve(strict=True)
                from . import phase_12_runtime_adapters as runtime
                from . import phase_12_authority_context as native
                from . import phase_12_federation_context as federation
                if adapter in native.ORIGINAL_ADAPTERS | federation.ORIGINAL_ADAPTERS:
                    context = native if adapter in native.ORIGINAL_ADAPTERS else federation
                    if adapter in native.ORIGINAL_ADAPTERS and artifact["proof"] is not None:
                        fail("native-context-single-proof-not-supported")
                    if adapter in federation.ORIGINAL_ADAPTERS and artifact["proof"] is not None:
                        federation.validate_proof(adapter, artifact["proof"], payloads)
                    result = (context.collect_and_verify(adapter, payloads, as_of, scratch, artifact["proof"])
                              if collect_original else context.verify(adapter, payloads, as_of, scratch))
                    provenance = result.get("originalProof", {"state": "unverified",
                        "scope": "native-original-context-not-reauthenticated",
                        "blockers": ["original-producer-reauthentication-required"]})
                elif adapter in runtime.ORIGINAL_MEMBERS and artifact["proof"] is not None:
                    runtime.validate_proof(adapter, artifact["proof"], payloads)
                    if collect_original:
                        result = runtime.collect_and_verify(adapter, payloads, as_of, scratch, artifact["proof"])
                        provenance = result["originalProof"]
                    else:
                        result = verify(adapter, payloads, as_of, scratch)
                        provenance = {"state": "unverified", "scope": "retained-coordinates-only",
                                      "blockers": ["original-producer-reauthentication-required"]}
                else:
                    provenance = original_proof(adapter, artifact["proof"], payloads, collect=collect_original)
                    result = verify(adapter, payloads, as_of, scratch)
            if not set(result.get("claims", [])) <= {r["id"] for r in assigned}:
                fail("adapter-claim-outside-inventory")
            for key, value in result.get("subjectBindings", {}).items():
                if key not in {"commit", "tree", "build", "digest"} or artifact["subject"][key] != value:
                    fail("adapter-subject-substitution")
            if artifact["proof"] is not None and result.get("producerCoordinates"):
                original = result["producerCoordinates"]
                selected = artifact["proof"]["coordinates"]
                for owner_key, selected_key in (("repository", "repository"), ("runId", "runId"),
                                                 ("runAttempt", "runAttempt"), ("job", "jobName")):
                    if str(original[owner_key]) != str(selected[selected_key]):
                        fail("original-producer-attempt-substitution")
            if result.get("requiredSubjects"):
                predecessors = [verified_results.get(key, {}) for key in artifact["predecessors"]]
                products = [item["productBinding"] for item in predecessors if "productBinding" in item]
                for required in result["requiredSubjects"]:
                    candidates = [p for p in products if p["role"] == required["role"]]
                    if len(candidates) != 1 or any(candidates[0].get(key) != value for key, value in required.items()):
                        fail("runtime-product-predecessor-substitution")
            if result.get("observedAt"):
                from datetime import datetime
                if (artifact["observedAt"] is None or datetime.fromisoformat(artifact["observedAt"]) !=
                        datetime.fromisoformat(result["observedAt"])):
                    fail("observation-clock-substitution")
            if result.get("evidenceClass") == "synthetic-test-only":
                fail("synthetic-authority-production")
            if (provenance["state"] == "authenticated" and result.get("evidenceClass") in {
                    "synthetic-rehearsal", "synthetic-isolated-rehearsal", "synthetic-preview"}):
                fail("synthetic-authority-production")
            for row in assigned:
                if row["id"] not in result.get("claims", []):
                    continue
                row["evidence"].append(artifact["id"])
                row["verification"].append({"adapter": adapter,
                                             "execution": result.get("dimensions", {}).get("localVerification", "not-run"),
                                             "scope": "owner-semantic-verification;test-execution-separate",
                                             "evidenceClass": result.get("evidenceClass", "local-semantics"),
                                             "testExecution": result.get("testEvidence", "not-run"),
                                             "originalProof": provenance})
                claim = result.get("claimResults", {}).get(row["id"], result)
                row["verification"][-1]["coverage"] = claim.get("coverage", result.get("coverage", {}))
                row["verification"][-1]["reportedDimensions"] = claim.get("dimensions", {})
                common_local = {name: value for name, value in result.get("dimensions", {}).items()
                                if name == "localVerification"}
                for dimension, value in {**common_local, **claim.get("dimensions", {})}.items():
                    if dimension not in row["dimensions"] or dimension == "implementation":
                        continue
                    if value not in DIMENSIONS[dimension]:
                        fail("adapter-dimension-contract")
                    if dimension in {"runtimeExecution", "publication", "activation", "publicObservation",
                                     "independentReview", "cleanup"} and provenance["state"] != "authenticated":
                        # Retained reports have passed semantic checks. They have not become
                        # authenticated observed operations, even when their original fields pass.
                        value = INITIAL[dimension]
                    row["dimensions"][dimension] = value
                # Provenance authenticates original bytes only. It cannot manufacture protected
                # consumer objects, elapsed coverage, review, publication or activation.
                if "originalProvenance" in row["dimensions"]:
                    row["dimensions"]["originalProvenance"] = provenance["state"]
                row["blockers"].extend(claim.get("blockers", []))
            artifacts.append({"id": artifact["id"], "adapter": adapter, "subject": artifact["subject"],
                              "predecessors": artifact["predecessors"], "provenance": provenance,
                              "coverage": result.get("coverage", {}), "measurements": result.get("measurements", {}),
                              "verification": "executed-pass"})
            verified_results[artifact["id"]] = result
        except Exception:
            for row in assigned:
                row["blockers"].append("supplied-evidence-invalid")
                if "localVerification" in row["dimensions"]:
                    row["dimensions"]["localVerification"] = "executed-fail"
                if "originalProvenance" in row["dimensions"]:
                    row["dimensions"]["originalProvenance"] = "invalid"
            artifacts.append({"id": artifact["id"], "adapter": adapter,
                              "verification": "failed", "reason": "supplied-evidence-invalid"})
    ci = None
    if selection["hostedCi"]:
        from .phase_12_ci import verify as verify_hosted_ci
        ci = verify_hosted_ci(raw_files[selection["hostedCi"]["name"]], source, as_of,
                              collect_original=collect_original)
        if "p12-303-ci" in by_id:
            row = by_id["p12-303-ci"]
            row["evidence"].append("hosted-ci")
            row["verification"].append({"adapter": "hosted-ci",
                "execution": "executed-pass", "scope": "exact-selected-hosted-records",
                "testExecution": "not-run", "originalProof": {"state": ci["originalProvenance"]}})
            for name, value in {"localVerification": "executed-pass",
                                "originalProvenance": ci["originalProvenance"], "ci": ci["ci"],
                                "coverage": "complete" if not ci["blockers"] else "partial"}.items():
                row["dimensions"][name] = value
            row["blockers"].extend(ci["blockers"])
    for requirement in ordered(rules["requirements"]):
        row = by_id[requirement["id"]]
        if requirement["id"] == "p12-303-reconciliation":
            for name in ("localVerification", "coverage"):
                if name in row["dimensions"]:
                    row["dimensions"][name] = PASS[name]
        if requirement["id"] == "p12-303-public":
            # Closed export shape is checked below; publication remains an independent site row.
            if "localVerification" in row["dimensions"]:
                row["dimensions"]["localVerification"] = "executed-pass"
            if "coverage" in row["dimensions"]:
                row["dimensions"]["coverage"] = "complete"
        for dimension, value in row["dimensions"].items():
            if value != PASS[dimension]:
                row["blockers"].append(f"{dimension}-{value}")
        if requirement["authority"].get("adapter") == "unavailable":
            row["blockers"].append("owner-adapter-unavailable")
        for prerequisite in row["prerequisites"]:
            if by_id[prerequisite]["blockers"]:
                row["blockers"].append("prerequisite-incomplete")
        row["blockers"] = sorted(set(row["blockers"]))
    # A residual closes only through all of its owning assertions. Retain its original reason,
    # clock and scope, and bind closure to the actual reverified artifacts, never a Markdown edit.
    for residual in residuals:
        mapped = [by_id[key] for key in residual["requirementIds"]]
        if mapped and all(not row["blockers"] for row in mapped):
            evidence = sorted({item for row in mapped for item in row["evidence"]})
            if evidence:
                residual["status"] = "closed"
                residual["closureEvidence"] = [{"artifactId": item, "verifiedAsOf": as_of} for item in evidence]
        elif residual["status"] == "closed":
            # A policy's proposed closure cannot stand in for absent original closure evidence.
            residual["status"] = "open"
            residual["closureEvidence"] = []
    remediation = ordered(residuals, edges="dependencies")
    decision = decide(rows, remediation, as_of=as_of)
    assessment = {"schemaVersion": 1, "kind": "phase-12-assessment", **decision,
                  "policyVersion": rules["version"], "policyDigest": pin, "source": source,
                  "selectionDigest": digest(canonical(selection)), "requirements": rows,
                  "subjects": artifacts, "residuals": remediation, "hostedCi": ci,
                  "history": rules["history"],
                  "previousAssessmentDigest": digest(canonical(prior)) if prior else None,
                  "publication": "not-performed", "activation": "not-performed"}
    # Reuse the exact public validator before declaring that the export projection is sound.
    public_projection(assessment)
    from .schema_validation import validate_schema
    if validate_schema(assessment, "phase-12-assessment-v1.schema.json"):
        fail("assessment-schema")
    return assessment


def public_projection(assessment):
    """Only fixed inventory IDs/enums reach public data; no source or receipt digest is exported."""
    rules, pin = policy()
    if (assessment.get("policyDigest") != pin or assessment.get("evidenceContext") != "repository-local-assessment"
            or assessment.get("phaseDecision") not in {"incomplete", "blocked", "complete-as-of"}
            or assessment.get("phaseComplete") is not (assessment["phaseDecision"] == "complete-as-of")):
        fail("public-assessment-contract")
    expected = {r["id"] for r in rules["requirements"]}
    required_dimensions = {r["id"]: set(r["dimensions"]) for r in rules["requirements"]}
    if {r["id"] for r in assessment["requirements"]} != expected or len(assessment["requirements"]) != len(expected):
        fail("public-inventory-contract")
    rows = []
    for row in sorted(assessment["requirements"], key=lambda r: r["id"]):
        dimensions = row["dimensions"]
        if (set(dimensions) != required_dimensions[row["id"]]
                or any(k not in DIMENSIONS or v not in DIMENSIONS[k] for k, v in dimensions.items())):
            fail("public-dimension-contract")
        rows.append({"id": row["id"], "dimensions": dimensions,
                     "decision": "satisfied" if not row["blockers"] else "unresolved"})
    value = {"schemaVersion": 1, "kind": "phase-12-public-status", "asOf": assessment["asOf"],
             "classification": "repository-local-assessment", "originalProducerProof": "not-exported",
             "phaseDecision": assessment["phaseDecision"], "phaseComplete": assessment["phaseComplete"],
             "requirements": rows, "publication": "not-performed", "activation": "not-performed"}
    timestamp(value["asOf"])
    recalculated = decide(assessment["requirements"], assessment["residuals"], as_of=assessment["asOf"])
    if any(recalculated[k] != assessment[k] for k in ("phaseDecision", "phaseComplete")):
        fail("public-decision-mismatch")
    return value


def markdown(assessment):
    lines = ["# Phase 12 local acceptance assessment", "",
             f"Assessment as of {assessment['asOf']}: **{assessment['phaseDecision']}**.", "",
             "The audit executed and verified local consistency. Local semantic verification does not",
             "authenticate original protected work, independent review or public observation.", "",
             "| Requirement | Implementation | Verifier | Runtime | Outstanding dimensions |",
             "| --- | --- | --- | --- | --- |"]
    for row in assessment["requirements"]:
        d = row["dimensions"]
        gaps = ", ".join(k for k, v in d.items() if v != PASS[k]) or "none"
        lines.append(f"| {row['id']} | {d['implementation']} | {d.get('localVerification', 'not-required')} | "
                     f"{d.get('runtimeExecution', 'not-required')} | {gaps} |")
    lines.extend(["", "Remediation follows the dependency order in phase-12-remediation-plan.json.", ""])
    return "\n".join(lines).encode()


def write_outputs(assessment, output):
    output = confined(output)
    if output.exists() or not output.parent.is_dir():
        fail("output-must-be-fresh")
    with tempfile.TemporaryDirectory(prefix=".phase12-", dir=output.parent) as temporary:
        stage = Path(temporary) / "assessment"
        stage.mkdir(mode=0o700)
        for name, raw in {
            "phase-12-assessment.json": canonical(assessment),
            "phase-12-assessment.md": markdown(assessment),
            "phase-12-remediation-plan.json": canonical({"schemaVersion": 1,
                "asOf": assessment["asOf"], "residuals": assessment["residuals"]}),
        }.items():
            with (stage / name).open("xb") as stream:
                os.chmod(stage / name, 0o600)
                stream.write(raw)
        if output.exists():
            fail("output-race")
        stage.rename(output)


def run(args):
    try:
        if args.mode is None:
            fail("mode-required")
        if args.collect_original and args.mode not in {"evaluate", "verify", "public-export"}:
            fail("collection-mode")
        if args.mode == "inventory":
            from .phase_12_adapters import REQUIRED_INPUTS
            from .phase_12_runtime_adapters import ORIGINAL_MEMBERS
            from .phase_12_authority_context import ORIGINAL_ADAPTERS as NATIVE_ORIGINAL
            from .phase_12_federation_context import ORIGINAL_ADAPTERS as FEDERATION_ORIGINAL
            rules, pin = policy()
            result = {"policyDigest": pin, "inventory": rules, "selectionTemplate": repository_selection(),
                      "adapters": {name: {"requiredFiles": list(files), "verification": "owner-semantic",
                          "originalCollection": "existing-owner-helper" if name in ORIGINAL_MEMBERS
                          else "native-original-context" if name in NATIVE_ORIGINAL | FEDERATION_ORIGINAL
                          else "unavailable"} for name, files in sorted(REQUIRED_INPUTS.items())},
                      "operationalClaim": "none"}
        else:
            if not args.as_of:
                fail("evaluation-time-required")
            selection = parse(read_file(args.selection)) if args.selection else repository_selection()
            assessment = evaluate(selection, args.source_root, args.as_of, collect_original=args.collect_original)
            if args.collect_original or assessment["phaseComplete"]:
                from datetime import datetime, timezone
                if timestamp(args.as_of).replace(tzinfo=timezone.utc) > datetime.now(timezone.utc):
                    fail("evaluation-after-current-time")
            if args.mode in {"verify", "public-export"}:
                if not args.assessment:
                    fail("assessment-required")
                supplied = parse(read_file(args.assessment))
                if canonical(supplied) != canonical(assessment):
                    fail("assessment-recomputation-mismatch")
            if args.mode == "public-export":
                if not args.output:
                    fail("public-output-required")
                target = confined(args.output)
                roots = [confined(args.assessment).parent]
                if args.source_root:
                    roots.append(confined(args.source_root))
                if (target.exists() or not target.parent.is_dir()
                        or any(target.parent.is_relative_to(p) or p.is_relative_to(target.parent) for p in roots)):
                    fail("public-private-root-overlap")
                # Make the complete file visible in one operation without replacing an
                # existing revision. The temporary hardlink is removed before returning.
                with tempfile.TemporaryDirectory(prefix="phase12-public-", dir=target.parent) as directory:
                    staged = Path(directory) / "status.json"
                    staged.write_bytes(canonical(public_projection(assessment)))
                    os.link(staged, target)
                    staged.unlink()
            elif args.mode == "evaluate" and args.output:
                if args.source_root and (confined(args.output).is_relative_to(confined(args.source_root))
                        or confined(args.source_root).is_relative_to(confined(args.output))):
                    fail("input-output-root-overlap")
                write_outputs(assessment, args.output)
            result = {k: assessment[k] for k in ("auditExecuted", "assessmentIntegrity", "phaseDecision",
                       "phaseComplete", "asOf", "evidenceContext")}
            result["unresolvedRequirements"] = sum(bool(r["blockers"]) for r in assessment["requirements"])
        print(canonical(result).decode(), end="")
        return 2 if args.require_complete and not result.get("phaseComplete", False) else 0
    except Exception:
        # No exception strings, selected paths, payloads, private hashes or source URLs escape.
        print('{"auditExecuted":false,"phaseComplete":false,"reason":"phase12-input-or-verification-failed"}')
        return 2
