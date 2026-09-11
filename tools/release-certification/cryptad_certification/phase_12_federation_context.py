"""Native federation context and explicit original observer admission.

The GET checks are the fixed authority checks from the PR-295 evidence producer, using the
existing bounded GitHub transport and repository identity. No runtime adapter is invoked.
"""
from __future__ import annotations

import importlib
import io
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tempfile
import zipfile

from .engines import stable_1_0_federated_catalog as owner
from . import transparency_bundle as bounded
from .schema_validation import validate_schema
from .redaction import scan_value

ROOT = Path(__file__).resolve().parents[3]
REQUIRED_INPUTS = {"federation-context": ("execution.json", "evidence.zip")}
ORIGINAL_ADAPTERS = frozenset(REQUIRED_INPUTS)
CLAIMS = ["p12-295-trust", "p12-295-conflicts", "p12-295-origin"]
MAX_BYTES = 64 * 1024 * 1024
PRODUCERS = {
    "import": (".github/workflows/stable-1.0-federated-catalog-trust.yml",
               "Authenticate and confine federation evidence", "stable-1-0-federated-catalog-import"),
    "runtime": (".github/workflows/stable-1.0-federated-catalog-runtime.yml",
                "Collect and sign exact federation runtime observation", "stable-1-0-federated-catalog-runtime-observation"),
    "protectedRelease": (".github/workflows/stable-1.0-protected-release-closeout.yml",
                         "Authenticate final protected-release evidence", "stable-1-0-protected-release-closeout"),
    "independentReproducibility": (".github/workflows/stable-1.0-independent-reproducibility.yml",
                                  "Authenticate and compare independent rebuild", "stable-1.0-independent-reproducibility-external-receipt"),
    "catalogAuthority": (".github/workflows/stable-1.0-catalog-authority.yml",
                         "Close out only authenticated catalog-authority evidence", "stable-1-0-catalog-authority-closeout"),
    "thirdPartyPilot": (".github/workflows/stable-1.0-third-party-app-pilot.yml",
                        "Authenticate operational closeout", "stable-1-0-third-party-pilot-closeout"),
}


def _deny():
    raise ValueError("phase12-federation-context-rejected")


def _check(errors):
    if errors:
        _deny()


def _archive(raw, *, flat=False):
    if not isinstance(raw, bytes) or len(raw) > MAX_BYTES:
        _deny()
    values, seen, total = {}, set(), 0
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        entries = archive.infolist()
        if (not entries or len(entries) > 256 or archive.comment
                or not raw.startswith(b"PK\x03\x04") or raw[-22:-18] != b"PK\x05\x06"):
            _deny()
        for entry in entries:
            name = entry.filename
            parts = PurePosixPath(name).parts
            if (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,219}", name)
                    or any(part in {"", ".", ".."} for part in name.split("/"))
                    or name.casefold() in seen or entry.is_dir() or entry.flag_bits & 1
                    or entry.extra or entry.comment
                    or stat.S_IFMT(entry.external_attr >> 16) not in {0, stat.S_IFREG}
                    or flat and (len(parts) != 1 or not name.endswith(".json"))):
                _deny()
            seen.add(name.casefold())
            total += entry.file_size
            if total > MAX_BYTES or flat and entry.file_size > 1024 * 1024:
                _deny()
            values[name] = archive.read(entry)
    return values


def _context(adapter, payloads, as_of, scratch):
    if (adapter not in REQUIRED_INPUTS or set(payloads) != set(REQUIRED_INPUTS[adapter])
            or any(type(raw) is not bytes for raw in payloads.values())
            or len(payloads["execution.json"]) > 1024 * 1024):
        _deny()
    contract = bounded.parse(payloads["execution.json"])
    _check(validate_schema(contract, owner.EXECUTION_SCHEMA))
    _check(scan_value(contract))
    policy, pin = owner._policy(ROOT)
    evaluation = owner._timestamp(as_of, "evaluation")
    if contract["policyDigest"] != pin or owner._timestamp(contract["evaluationTime"], "contract time") > evaluation:
        _deny()
    fixture = contract["fixtureOnly"] or contract["selfTest"]
    if fixture and contract["requestedState"] in owner.OPERATIONAL_STATES:
        _deny()
    if not fixture:
        _check(owner._operational_identity_errors(contract))
    files = _archive(payloads["evidence.zip"], flat=True)
    if files.get("execution.json") != payloads["execution.json"]:
        _deny()
    with tempfile.TemporaryDirectory(prefix="federation-context-", dir=bounded.confined(scratch)) as temporary:
        root = Path(temporary)
        for name, raw in files.items():
            (root / name).write_bytes(raw)
        _check(owner._evidence_member_errors(root, root / "execution.json", contract, policy))
        def document(binding, schema):
            value, errors = owner._bound_json(root, binding, schema, "selected federation evidence")
            _check(errors)
            return value
        descriptor_binding = contract["evidence"]["descriptor"]
        descriptor = document(descriptor_binding, owner.DESCRIPTOR_SCHEMA)
        _check(owner._descriptor_errors(descriptor, descriptor_binding, evaluation, policy))
        endorsements = []
        for binding in contract["evidence"]["endorsements"]:
            item = document(binding, owner.ENDORSEMENT_SCHEMA)
            _check(owner._endorsement_errors(item, binding, descriptor, evaluation, policy))
            endorsements.append(item)
        for key in ("endorsementId", "selfDigestSha256"):
            if len({item[key] for item in endorsements}) != len(endorsements):
                _deny()
        runtime_binding = contract["evidence"]["runtimeObservation"]
        runtime = document(runtime_binding, owner.RUNTIME_SCHEMA)
        _check(owner._runtime_errors(runtime, runtime_binding, contract, descriptor, endorsements, evaluation, policy))
        if runtime["partial"] or runtime["status"] != "pass" or runtime["conflictCounts"]["unresolvedHard"] < 1:
            _deny()
        missing_roots = [key for key, value in contract["authorities"].items() if value["summary"] is None]
        # Missing originals are gaps, but another missing root cannot hide a supplied-invalid
        # predecessor, workflow, source, artifact relationship, or exact summary.
        absent = {name + " " + suffix for name in missing_roots for suffix in (
            "authority is not operational", "predecessor summary is not bound", "authority summary digest is unset")}
        _check([error for error in owner._authority_errors(contract, policy, root) if error not in absent])
    return contract, runtime, files, missing_roots, fixture


def verify(adapter, payloads, as_of, scratch):
    """Execute native semantic checks offline without treating saved coordinates as origin."""
    try:
        contract, runtime, _, missing, fixture = _context(adapter, payloads, as_of, scratch)
        blockers = ["federation-original-observer-context-unverified"]
        if missing:
            blockers.append("federation-predecessor-original-context-missing")
        if fixture:
            blockers.append("synthetic-evidence-not-operational")
        return {"dimensions": {"localVerification": "executed-pass", "originalProvenance": "unverified",
                               "runtimeExecution": "not-observed"},
                "claims": CLAIMS.copy(), "blockers": sorted(blockers),
                "evidenceClass": "synthetic-test" if fixture else "federation-native-context",
                "coverage": {"required": ["signed-discovery", "local-scoped-trust", "hard-conflict",
                                            "installed-origin-consent", "original-observer", "original-predecessors"],
                             "observed": ["signed-discovery-semantics", "runtime-scenario-semantics"],
                             "missingPredecessors": missing},
                "subjectBindings": {"commit": contract["repository"]["sourceCommit"],
                                    "build": contract["release"]["buildVersion"], "digest": runtime["receiptDigest"]},
                "observedAt": runtime["observedAt"]}
    except Exception:
        raise ValueError("phase12-federation-context-rejected") from None


def _original():
    # Only the repository-installed transport is imported; no evidence selects a module.
    sys.path.insert(0, str(ROOT / "tools/release-certification/protected"))
    try:
        importlib.import_module("bounded_process")
        return importlib.import_module("original_artifact_authentication")
    finally:
        sys.path.pop(0)


def validate_proof(adapter, proof, payloads):
    if proof is None:
        return {"state": "not-supplied", "scope": "none", "blockers": ["original-proof-missing"]}
    try:
        if adapter not in REQUIRED_INPUTS or type(proof) is not dict or set(proof) != {"coordinates", "members"}:
            _deny()
        if proof["members"] != {"evidence.zip": "original-federation-context-archive"}:
            _deny()
        coordinates = _original().validate_coordinates(proof["coordinates"])
        contract = bounded.parse(payloads["execution.json"])
        if (coordinates["sourceFamily"] != "federated-catalog"
                or coordinates["jobName"] != PRODUCERS["import"][1]
                or coordinates["sourceCommit"] != contract["repository"]["sourceCommit"]
                or coordinates["artifactSize"] != len(payloads["evidence.zip"])
                or coordinates["artifactDigest"] != owner._digest_bytes(payloads["evidence.zip"])
                or coordinates["artifactSize"] > MAX_BYTES):
            _deny()
        return {"state": "unverified", "scope": "retained-original-coordinates-only",
                "blockers": ["original-producer-reauthentication-required"]}
    except Exception:
        raise ValueError("phase12-federation-original-proof-rejected") from None


class _Collector:
    """Finite GET implementation of the owning workflow's original admission checks."""
    def __init__(self, as_of):
        self.transport = _original()
        self.environment = self.transport._environment()
        self.evaluation = owner._timestamp(as_of, "evaluation")
        self.calls = 0

    def get(self, endpoint, *, binary=False):
        self.calls += 1
        if self.calls > 80 or not endpoint.startswith("repos/crypta-network/cryptad/"):
            _deny()
        return self.transport._gh(["api", "--method", "GET", endpoint], self.environment, json_result=not binary)

    def producer(self, provenance, name, *, branch=None):
        workflow, job_name, environment = PRODUCERS[name]
        if (provenance["repositoryIdentity"] != "github.com/crypta-network/cryptad"
                or provenance["workflowPath"] != workflow or provenance["environment"] != environment
                or provenance["conclusion"] != "success"):
            _deny()
        run_id, attempt = provenance["runId"], provenance["runAttempt"]
        for number in (run_id, attempt):
            if type(number) is not int or not 1 <= number < 2**53:
                _deny()
        prefix = "repos/crypta-network/cryptad"
        selected = f"{prefix}/actions/runs/{run_id}/attempts/{attempt}"
        run = self.get(selected)
        if (run.get("id") != run_id or run.get("run_attempt") != attempt
                or run.get("head_sha") != provenance["workflowCommit"] or run.get("path") != workflow
                or run.get("event") != "workflow_dispatch" or run.get("status") != "completed"
                or run.get("conclusion") != "success" or run.get("repository", {}).get("full_name") != "crypta-network/cryptad"
                or run.get("actor", {}).get("login") != "leumor" or run.get("triggering_actor", {}).get("login") != "leumor"
                or not run.get("head_branch") or branch is not None and run["head_branch"] != branch):
            _deny()
        page = self.get(selected + "/jobs?per_page=100")
        if page.get("total_count") != len(page.get("jobs", [])) or len(page["jobs"]) > 100:
            _deny()
        jobs = [job for job in page["jobs"] if job.get("name") == job_name
                and job.get("head_sha") == provenance["workflowCommit"] and job.get("conclusion") == "success"]
        if len(jobs) != 1:
            _deny()
        job = jobs[0]
        if name == "runtime":
            steps = job.get("steps")
            required = {"Exercise protected federation topology", "Seal runtime receipt with independently approved observer key"}
            if (type(steps) is not list or len(steps) > 64
                    or any(sum(step.get("name") == wanted and step.get("conclusion") == "success"
                               for step in steps) != 1 for wanted in required)):
                _deny()
        start, end = (owner._timestamp(job[key], "job time") for key in ("started_at", "completed_at"))
        if start > end or end > self.evaluation or type(job.get("id")) is not int:
            _deny()
        deployments = self.get(prefix + "/deployments?sha=" + provenance["workflowCommit"]
                               + "&environment=" + environment + "&per_page=100")
        if type(deployments) is not list or len(deployments) >= 100:
            _deny()
        approved = False
        candidates = [item for item in deployments if item.get("environment") == environment
                      and item.get("sha") == provenance["workflowCommit"]
                      and item.get("creator", {}).get("login") == "github-actions[bot]"]
        if len(candidates) > 8:
            _deny()
        for deployment in candidates:
            if type(deployment.get("id")) is not int or deployment["id"] <= 0:
                _deny()
            statuses = self.get(f"{prefix}/deployments/{deployment['id']}/statuses?per_page=100")
            if type(statuses) is not list or len(statuses) >= 100:
                _deny()
            expected_log = f"https://github.com/crypta-network/cryptad/actions/runs/{run_id}/job/{job['id']}"
            approved |= any(item.get("state") == "success" and item.get("log_url") == expected_log
                            and start <= owner._timestamp(item["created_at"], "deployment time") <= end for item in statuses)
        if not approved:
            _deny()
        page = self.get(f"{prefix}/actions/runs/{run_id}/artifacts?per_page=100")
        if page.get("total_count") != len(page.get("artifacts", [])) or len(page["artifacts"]) > 100:
            _deny()
        artifacts = [item for item in page["artifacts"] if item.get("name") == provenance["artifactName"]
                     and item.get("digest") == provenance["artifactDigest"] and item.get("workflow_run", {}).get("id") == run_id]
        if len(artifacts) != 1:
            _deny()
        artifact = artifacts[0]
        raw = self.artifact(artifact, provenance, job)
        return raw, run, job, page["artifacts"]

    def artifact(self, artifact, provenance, job):
        if (type(artifact.get("id")) is not int or artifact["id"] <= 0 or artifact.get("expired") is not False
                or type(artifact.get("size_in_bytes")) is not int or not 1 <= artifact["size_in_bytes"] <= MAX_BYTES
                or not job["started_at"] <= artifact.get("created_at", "") <= artifact.get("updated_at", "") <= job["completed_at"]):
            _deny()
        raw = self.get(f"repos/crypta-network/cryptad/actions/artifacts/{artifact['id']}/zip", binary=True)
        if len(raw) != artifact["size_in_bytes"] or owner._digest_bytes(raw) != provenance["artifactDigest"]:
            _deny()
        return raw


def _member(raw, binding, expected):
    files = _archive(raw)
    matches = [value for name, value in files.items() if PurePosixPath(name).name == binding["fileName"]]
    if (len(matches) != 1 or matches[0] != expected or len(matches[0]) != binding["size"]
            or owner._digest_bytes(matches[0]) != binding["digest"]):
        _deny()


def collect_and_verify(adapter, payloads, as_of, scratch, proof):
    """Explicit original admission; authenticates producer work rather than saved API records."""
    local = verify(adapter, payloads, as_of, scratch)
    try:
        if proof is not None and validate_proof(adapter, proof, payloads)["state"] != "unverified":
            _deny()
        contract, runtime, files, missing, fixture = _context(adapter, payloads, as_of, scratch)
        if fixture:
            _deny()
        if missing:
            local["originalProof"] = {"state": "unverified", "scope": "native-predecessor-context-incomplete",
                                      "blockers": ["federation-predecessor-original-context-missing"]}
            return local
        collector = _Collector(as_of)
        branch = None
        if proof is not None:
            coordinates = proof["coordinates"]
            provenance = {"repositoryIdentity": "github.com/crypta-network/cryptad",
                          "workflowPath": PRODUCERS["import"][0], "workflowCommit": coordinates["sourceCommit"],
                          "runId": coordinates["runId"], "runAttempt": coordinates["runAttempt"],
                          "artifactName": coordinates["artifactName"], "artifactDigest": coordinates["artifactDigest"],
                          "environment": PRODUCERS["import"][2], "conclusion": "success"}
            expected_name = f"stable-federated-catalog-{contract['executionId']}-{coordinates['runId']}-{coordinates['runAttempt']}"
            if coordinates["artifactName"] != expected_name:
                _deny()
            imported, run, job, artifacts = collector.producer(provenance, "import")
            selected = [item for item in artifacts if item["id"] == coordinates["artifactId"]]
            if (imported != payloads["evidence.zip"] or job["id"] != coordinates["jobId"] or len(selected) != 1
                    or selected[0]["name"] != coordinates["artifactName"] or selected[0]["digest"] != coordinates["artifactDigest"]):
                _deny()
            branch = run["head_branch"]
        binding = contract["evidence"]["runtimeObservation"]
        original, run, runtime_job, artifacts = collector.producer(binding["receiptProvenance"], "runtime", branch=branch)
        branch = run["head_branch"]
        suffix = f"{contract['executionId']}-{binding['receiptProvenance']['runId']}-{binding['receiptProvenance']['runAttempt']}"
        if binding["receiptProvenance"]["artifactName"] != "stable-1-0-federated-catalog-runtime-receipt-" + suffix:
            _deny()
        _member(original, binding, files[binding["fileName"]])
        observed = runtime["provenance"]
        if observed["artifactName"] != "stable-1-0-federated-catalog-runtime-observation-" + suffix:
            _deny()
        unsigned = [item for item in artifacts if item.get("name") == observed["artifactName"]
                    and item.get("digest") == observed["artifactDigest"] and item.get("workflow_run", {}).get("id") == observed["runId"]]
        if len(unsigned) != 1:
            _deny()
        # The owner producer signs the pinned original observation archive after its managed
        # runner finishes. Its payload layout is adapter-owned, so do not invent a replacement.
        collector.artifact(unsigned[0], observed, runtime_job)
        receipts = [item for item in artifacts if item.get("name") == binding["receiptProvenance"]["artifactName"]
                    and item.get("digest") == binding["receiptProvenance"]["artifactDigest"]]
        if (len(receipts) != 1 or unsigned[0]["id"] == receipts[0]["id"]
                or unsigned[0]["updated_at"] > receipts[0]["created_at"]):
            _deny()
        observation_time = owner._timestamp(runtime["observedAt"], "original observation")
        if not owner._timestamp(runtime_job["started_at"], "start") <= observation_time <= owner._timestamp(unsigned[0]["created_at"], "original upload"):
            _deny()
        for name, authority in contract["authorities"].items():
            original, _, predecessor_job, _ = collector.producer(authority["provenance"], name, branch=branch)
            if owner._timestamp(predecessor_job["completed_at"], "predecessor completion") > observation_time:
                _deny()
            _member(original, authority["summary"], files[authority["summary"]["fileName"]])
        local["dimensions"].update(originalProvenance="authenticated", runtimeExecution="observed", coverage="complete")
        local["blockers"] = []
        local["coverage"]["observed"] = local["coverage"]["required"].copy()
        local["originalProof"] = {"state": "authenticated", "scope": "native-federation-original-observer-and-predecessors", "blockers": []}
        return local
    except Exception as error:
        if isinstance(error, _original().AuthenticationError):
            local["blockers"] = sorted(set(local["blockers"] + ["federation-original-provider-access-unavailable"]))
            local["originalProof"] = {"state": "unverified", "scope": "original-provider-access-unavailable",
                                      "blockers": ["federation-original-provider-access-unavailable"]}
            return local
        raise ValueError("phase12-federation-original-collection-rejected") from None
