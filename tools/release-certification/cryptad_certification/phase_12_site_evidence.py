"""Read-only admission of native PR-302 site, deployment and observation records.

The existing site command owns bundle/history checks and the native observation meaning.
Retained Actions/API records do not authenticate themselves. In particular, this module never
replays expected local files through the network observer and calls that a public observation.
"""
from __future__ import annotations

import io
from pathlib import Path
import re
import stat
import tarfile
import tempfile
import zipfile

from . import transparency_bundle as owner
from .transparency_sources import safe_link

REPOSITORY = "crypta-network/cryptad"
API = "https://api.github.com/repos/" + REPOSITORY
WEB = "https://github.com/" + REPOSITORY
WORKFLOW = ".github/workflows/public-ecosystem-transparency.yml"
COMMON = ("selection.json", "bundle.zip", "previous.zip", "checkpoint.json", "run.json", "jobs.json",
          "artifact.json", "pages-artifact.json", "pages-artifact.zip", "deployment.json", "deployment-status.json")
REQUIRED_INPUTS = {
    "site-deployment": COMMON,
    "site-observation": COMMON + ("observation.json", "observation-artifact.json", "observation.zip"),
}
JOBS = ("offline", "build", "transfer-verify", "deploy", "observe")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


def _reject():
    raise ValueError("phase12-site-native-evidence-rejected")


def _integer(value):
    if type(value) is not int or not 1 <= value < 2**53:
        _reject()
    return value


def _zip(raw, *, pages=False):
    files, seen, directories, size = {}, set(), set(), 0
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        entries = archive.infolist()
        if (not entries or len(entries) > owner.MAX_FILES or archive.comment
                or not raw.startswith(b"PK\x03\x04") or raw[-22:-18] != b"PK\x05\x06"):
            _reject()
        for entry in entries:
            name = owner.safe_name(entry.filename.rstrip("/"))
            mode = entry.external_attr >> 16
            if (name.casefold() in seen or entry.flag_bits & 1 or entry.extra or entry.comment
                    or entry.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
                    or stat.S_IFMT(mode) not in {0, stat.S_IFREG, stat.S_IFDIR}):
                _reject()
            seen.add(name.casefold())
            if entry.is_dir():
                directories.add(name)
                continue
            size += entry.file_size
            maximum = owner.MAX_TOTAL if pages else owner.MAX_FILE
            if entry.file_size > maximum or size > owner.MAX_TOTAL:
                _reject()
            files[name] = archive.read(entry)
    _directories(files, directories)
    return files


def _directories(files, directories):
    implied = {str(parent) for name in files for parent in Path(name).parents if str(parent) != "."}
    if not directories <= implied or any(name.count("/") > 4 for name in implied):
        _reject()


def _pages_files(raw):
    wrapped = _zip(raw, pages=True)
    if set(wrapped) != {"artifact.tar"}:
        _reject()
    files, seen, directories, total = {}, set(), set(), 0
    # upload-pages-artifact at the repository pin produces an uncompressed artifact.tar
    # with ./ relative entries. No extraction of link/device/PAX paths takes place.
    with tarfile.open(fileobj=io.BytesIO(wrapped["artifact.tar"]), mode="r:") as archive:
        for count, entry in enumerate(archive):
            if count >= 2 * owner.MAX_FILES:
                _reject()
            # The pinned Ubuntu upload action invokes GNU tar, not a PAX writer.
            if entry.pax_headers or entry.sparse is not None:
                _reject()
            name = entry.name[2:] if entry.name.startswith("./") else entry.name
            if name in {"", "."} and entry.isdir():
                continue
            name = owner.safe_name(name.rstrip("/"))
            if name.casefold() in seen or not (entry.isfile() or entry.isdir()):
                _reject()
            seen.add(name.casefold())
            if entry.isdir():
                directories.add(name)
                continue
            total += entry.size
            if entry.size > owner.MAX_FILE or total > owner.MAX_TOTAL:
                _reject()
            stream = archive.extractfile(entry)
            if stream is None:
                _reject()
            files[name] = stream.read(owner.MAX_FILE + 1)
            if len(files[name]) != entry.size:
                _reject()
        if archive.pax_headers or any(wrapped["artifact.tar"][archive.offset:]):
            _reject()
    _directories(files, directories)
    return files


def _materialize(files, root):
    root.mkdir()
    for name, raw in files.items():
        target = root / owner.safe_name(name)
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as stream:
            stream.write(raw)


def _selection(value):
    fields = {"schemaVersion", "sourceCommit", "runId", "runAttempt", "manifestDigest",
              "previousManifestDigest", "bootstrapManifestDigest", "siteUrl"}
    if (type(value) is not dict or set(value) != fields or type(value["schemaVersion"]) is not int
            or value["schemaVersion"] != 1 or not re.fullmatch(r"[0-9a-f]{40}", str(value["sourceCommit"]))
            or not DIGEST.fullmatch(str(value["manifestDigest"]))):
        _reject()
    _integer(value["runId"])
    _integer(value["runAttempt"])
    safe_link(value["siteUrl"])
    if not value["siteUrl"].endswith("/"):
        _reject()
    previous, bootstrap = value["previousManifestDigest"], value["bootstrapManifestDigest"]
    if ((previous is None) == (bootstrap is None)
            or not DIGEST.fullmatch(str(previous if previous is not None else bootstrap))):
        _reject()
    if previous is None and bootstrap != value["manifestDigest"]:
        _reject()
    return value


def _jobs(run, record, selected, as_of):
    if (type(run) is not dict or run.get("id") != selected["runId"]
            or run.get("run_attempt") != selected["runAttempt"]
            or run.get("path") != WORKFLOW or run.get("repository", {}).get("full_name") != REPOSITORY
            or run.get("event") != "workflow_dispatch" or run.get("head_branch") != "develop"
            or run.get("head_sha") != selected["sourceCommit"] or run.get("status") != "completed"
            or type(record) is not dict or set(record) != {"total_count", "jobs"}
            or type(record["jobs"]) is not list or type(record["total_count"]) is not int
            or record["total_count"] != len(record["jobs"]) or len(record["jobs"]) != len(JOBS)):
        _reject()
    # These are selected immutable-attempt records, not a PR rollup. Native jobs lack a portable
    # signed attempt identity; retained run/job binding still requires original authentication.
    jobs, ids = {}, set()
    for job in record["jobs"]:
        if (type(job) is not dict or job.get("name") not in JOBS or job["name"] in jobs
                or job.get("run_id") != selected["runId"] or job.get("head_sha") != selected["sourceCommit"]
                or job.get("status") != "completed" or type(job.get("steps")) is not list
                or job.get("conclusion") not in {"success", "failure", "neutral", "cancelled", "skipped", "timed_out", "action_required", "stale"}
                or (not job["steps"] and job["conclusion"] != "skipped") or len(job["steps"]) > 64):
            _reject()
        identity = _integer(job.get("id"))
        if identity in ids:
            _reject()
        ids.add(identity)
        if job.get("started_at") is None and job.get("completed_at") is None and job["conclusion"] == "skipped":
            pass
        else:
            start, end = owner.timestamp(job["started_at"]), owner.timestamp(job["completed_at"])
            if start > end or end > as_of:
                _reject()
        jobs[job["name"]] = job
    for before, after in (("offline", "build"), ("build", "transfer-verify"),
                          ("transfer-verify", "deploy"), ("deploy", "observe")):
        end, start = jobs[before]["completed_at"], jobs[after]["started_at"]
        if end is not None and start is not None and owner.timestamp(end) > owner.timestamp(start):
            _reject()
    return jobs


def _artifact(value, raw, name, job, selected):
    if (type(value) is not dict or value.get("name") != name
            or value.get("digest") != owner.digest(raw) or value.get("size_in_bytes") != len(raw)
            or value.get("workflow_run", {}).get("id") != selected["runId"]
            or value.get("workflow_run", {}).get("head_sha") != selected["sourceCommit"]):
        _reject()
    _integer(value.get("id"))
    if not (owner.timestamp(job["started_at"]) <= owner.timestamp(value["created_at"])
            <= owner.timestamp(value["updated_at"]) <= owner.timestamp(job["completed_at"])):
        _reject()


def _deployment(value, status, jobs, selected, as_of):
    identity = _integer(value.get("id"))
    if (value.get("environment") != "github-pages" or value.get("sha") != selected["sourceCommit"]
            or value.get("creator", {}).get("login") != "github-actions[bot]"
            or value.get("repository_url") != API or value.get("url") != API + f"/deployments/{identity}"
            or status.get("deployment_url") != value["url"] or status.get("environment") != "github-pages"
            or status.get("environment_url") != selected["siteUrl"]
            or status.get("log_url") != WEB + f"/actions/runs/{selected['runId']}/job/{jobs['deploy']['id']}"):
        _reject()
    _integer(status.get("id"))
    start, end = (owner.timestamp(jobs["deploy"][key]) for key in ("started_at", "completed_at"))
    # Environment deployments can be created while a job waits for approval, and GitHub's
    # final environment status may be written after the runner has completed the job.
    created, reported = owner.timestamp(value["created_at"]), owner.timestamp(status["created_at"])
    if (created > reported or not start <= reported <= as_of or end > as_of
            or status.get("state") not in {"error", "failure", "inactive", "pending", "success", "queued", "in_progress"}):
        _reject()
    return status.get("state") == "success" and all(jobs[name].get("conclusion") == "success" for name in JOBS[:-1])


def _observation(value, files, manifest, job, as_of):
    fields = {"schemaVersion", "kind", "status", "observedAt", "manifestDigest", "exactFiles",
              "unavailableFiles", "conflictingFiles", "scope", "propagation", "sourcePublication"}
    if (type(value) is not dict or set(value) != fields or type(value["schemaVersion"]) is not int
            or value["schemaVersion"] != 1 or value["kind"] != "public-ecosystem-site-observation"
            or value["manifestDigest"] != manifest
            or value["scope"] != "one-bounded-observation-not-independent-infrastructure"
            or value["propagation"] != "cdn-propagation-uncertainty" or value["sourcePublication"] != "unchanged"):
        _reject()
    counts = [value[key] for key in ("exactFiles", "unavailableFiles", "conflictingFiles")]
    if any(type(count) is not int or not 0 <= count <= owner.MAX_FILES for count in counts) or sum(counts) != len(files):
        _reject()
    exact, missing, changed = counts
    # This is precisely the native observer's verdict algebra. It validates a retained report;
    # the report's counts remain producer claims until its original execution is authenticated.
    expected = "conflict" if changed else ("unavailable" if not exact else "partial") if missing else "exact-match"
    observed = owner.timestamp(value["observedAt"])
    if (value["status"] != expected or not owner.timestamp(job["started_at"]) <= observed
            <= owner.timestamp(job["completed_at"]) <= as_of):
        _reject()
    if value["status"] == "exact-match" and job.get("conclusion") != "success":
        _reject()
    return expected == "exact-match"


def verify(adapter, payloads, as_of, scratch):
    """Validate exact native selected relationships; emit no hosted-authentication shortcut."""
    try:
        if (adapter not in REQUIRED_INPUTS or set(payloads) != set(REQUIRED_INPUTS[adapter])
                or any(type(raw) is not bytes or len(raw) > owner.MAX_TOTAL for raw in payloads.values())
                or sum(map(len, payloads.values())) > 4 * owner.MAX_TOTAL):
            _reject()
        scratch = owner.confined(scratch)
        if not scratch.is_dir():
            _reject()
        current = owner.timestamp(as_of)
        values = {name: owner.parse(raw) for name, raw in payloads.items() if name.endswith(".json")}
        selected = _selection(values["selection.json"])
        files = _zip(payloads["bundle.zip"])
        if files != _pages_files(payloads["pages-artifact.zip"]):
            _reject()
        with tempfile.TemporaryDirectory(prefix="phase12-site-", dir=scratch) as temporary:
            root = Path(temporary)
            _materialize(files, root / "current")
            index = owner.verify_checkpoint(root / "current", selected["manifestDigest"])
            if index["mode"] != "production" or owner.timestamp(index["asOf"]) > current:
                _reject()
            historical_tool = index["toolDigest"] != owner.tool_identity()
            if not historical_tool:
                owner.verify(root / "current", production=True, expected_manifest=selected["manifestDigest"])
            checkpoint = values["checkpoint.json"]
            if selected["previousManifestDigest"]:
                _materialize(_zip(payloads["previous.zip"]), root / "previous")
                prior = owner.verify_checkpoint(root / "previous", selected["previousManifestDigest"])
                owner.check_history(index, prior)
                expected_checkpoint = {"status": "checkpoint-verified", "manifestDigest": selected["previousManifestDigest"]}
            else:
                if payloads["previous.zip"] != b"":
                    _reject()
                expected_checkpoint = {"status": "bootstrap-authorized", "manifestDigest": selected["bootstrapManifestDigest"]}
            if checkpoint != expected_checkpoint:
                _reject()
        jobs = _jobs(values["run.json"], values["jobs.json"], selected, current)
        if owner.timestamp(index["asOf"]) > owner.timestamp(jobs["build"]["started_at"]):
            _reject()
        _artifact(values["artifact.json"], payloads["bundle.zip"], "verified-public-site", jobs["build"], selected)
        _artifact(values["pages-artifact.json"], payloads["pages-artifact.zip"], "github-pages", jobs["transfer-verify"], selected)
        if values["artifact.json"]["id"] == values["pages-artifact.json"]["id"]:
            _reject()
        deployed = _deployment(values["deployment.json"], values["deployment-status.json"], jobs, selected, current)
        blockers = ["site-original-hosted-context-unverified", "site-protected-configuration-unverified",
                    "site-checkpoint-approval-context-unverified", "site-pages-deployment-artifact-binding-unverified"]
        if historical_tool:
            blockers.append("historical-site-tool-original-context-unverified")
        if not deployed:
            blockers.append("site-required-deployment-jobs-not-successful")
        claim = "p12-302-deployment"
        observed_at = None
        retained = "deployment-records-consistent" if deployed else "deployment-not-established"
        required = ["exact-build-export", "exact-pages-export", "checkpoint-history", "deployment-subject"]
        if adapter == "site-observation":
            observed = values["observation.json"]
            original = _zip(payloads["observation.zip"])
            if original != {"public-observation.json": payloads["observation.json"]}:
                _reject()
            _artifact(values["observation-artifact.json"], payloads["observation.zip"], "public-site-observation", jobs["observe"], selected)
            if values["observation-artifact.json"]["id"] in {values["artifact.json"]["id"], values["pages-artifact.json"]["id"]}:
                _reject()
            exact = _observation(observed, files, selected["manifestDigest"], jobs["observe"], current)
            claim, observed_at = "p12-302-observation", observed["observedAt"]
            retained = "native-exact-match-reported" if exact else "native-conflict-or-unavailability-reported"
            required.append("exact-native-observation")
            if not exact:
                blockers.append("site-public-byte-observation-not-exact")
        return {"dimensions": {"localVerification": "executed-pass", "originalProvenance": "unverified",
                               "runtimeExecution": "not-observed", "publication": "not-observed",
                               "publicObservation": "not-observed"},
                "claims": [claim], "blockers": sorted(blockers), "evidenceClass": "retained-native-site-records",
                "coverage": {"required": required, "observed": []},
                "retainedRecordClassification": retained,
                "subjectBindings": {"commit": selected["sourceCommit"], "digest": selected["manifestDigest"]},
                **({"observedAt": observed_at} if observed_at else {})}
    except Exception:
        # Native API records may contain account names, descriptions, URLs and private log text.
        # Neither successful results nor failures copy those fields into assessment/public output.
        raise ValueError("phase12-site-native-evidence-rejected") from None
