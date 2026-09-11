"""Bounded original acquisition and retained hosted-record classification for PR-303.

No saved JSON is an authentication capability. Network acquisition is explicit and uses the
existing original producer's fixed GET/attestation verifier; ordinary assessment is offline.
"""
from __future__ import annotations

from pathlib import Path
import tempfile

from .transparency_bundle import canonical, digest, parse, timestamp

# Original source families are owned by original_artifact_authentication.PRODUCERS. This mapping
# limits what a valid attestation may substantiate; the semantic adapter still checks subjects.
FAMILIES = {
    "protected-ga-receipt": {"catalog-source"},
    "independent-receipts": {"first-party-inventory"},
    "catalog-keyset": {"catalog-source"},
    "pilot-review": {"third-party-pilot", "third-party-inventory"},
    "federation-trust": {"federated-catalog"},
    "api-subjects-v2": {"app-subject-projection"},
    "migration-observation": {"sharesite-runtime"},
    "measured-soak": {"cross-version-supervisor"},
    "maintenance-measurements": {"cross-version-supervisor"},
}
GROUPED_ORIGINAL_GAPS = {
    "protected-ga-receipt": "original-ga-multi-producer-context-unavailable",
    "independent-receipts": "original-independent-provider-adapter-unavailable",
    "catalog-keyset": "original-key-ceremony-context-required",
    "pilot-review": "original-pilot-review-multi-producer-context-required",
    "federation-trust": "original-federation-observer-context-required",
    "catalog-closeout": "original-catalog-multi-producer-context-required",
    "pilot-runtime": "original-pilot-runtime-context-required",
    "lifecycle-receipt": "original-lifecycle-producer-context-required",
    "protected-public-observation": "original-public-observer-context-required",
    "independent-comparison": "original-independent-provider-adapter-unavailable",
    "api-compatibility": "original-api-history-runtime-context-required",
    "historical-transparency-bundle": "original-site-build-deploy-observe-context-required",
    "transparency-bundle": "original-site-build-deploy-observe-context-required",
    "transparency-sources": "original-public-source-proofs-required",
    "maintenance-publication": "original-maintenance-multi-producer-context-required",
    "maintenance-activation": "original-maintenance-activation-backend-context-required",
    "site-deployment": "original-site-build-deploy-context-required",
    "site-observation": "original-site-observer-transcript-context-required",
}


def original_proof(adapter, proof, payloads, *, collect=False):
    """Authenticate selected original bytes, or report the exact absent proof boundary.

Retained coordinates are claims until recollected. This deliberately does not return or forge
AuthenticatedProjection/Observation objects owned by protected producers. A valid origin never
promotes an unsupported semantic consumer or a synthetic execution class.
"""
    if proof is None:
        return {"state": "not-supplied", "scope": "none", "blockers": ["original-proof-missing"]}
    from .transparency_sources import _original_helper, _selected_archive_member
    helper = _original_helper()
    if adapter in GROUPED_ORIGINAL_GAPS and adapter not in FAMILIES:
        if (type(proof) is not dict or set(proof) != {"coordinates", "members"}
                or type(proof["members"]) is not dict):
            raise ValueError("phase12-original-proof-contract")
        # The common coordinate shape is checked by the selection schema. There is no
        # implemented bridge for this native multi-producer context, so do not misclassify
        # authentic retained coordinates as a bad signature or accept an unrelated signer.
        if proof["coordinates"].get("repository") != helper.REPOSITORY:
            raise ValueError("phase12-original-owner-mismatch")
        return {"state": "unverified", "scope": "original-owner-context-unavailable",
                "blockers": [GROUPED_ORIGINAL_GAPS[adapter]]}
    if (type(proof) is not dict or set(proof) != {"coordinates", "members"}
            or type(proof["members"]) is not dict or set(proof["members"]) != set(payloads)):
        raise ValueError("phase12-original-proof-contract")
    coordinates = helper.validate_coordinates(proof["coordinates"])
    if (coordinates["sourceFamily"] not in FAMILIES.get(adapter, set())
            or coordinates["jobName"] != helper.PRODUCERS[coordinates["sourceFamily"]][2]
            or len(set(proof["members"].values())) != len(payloads)):
        raise ValueError("phase12-original-owner-mismatch")
    # Validate archive names and member mapping before any network request.
    from .transparency_bundle import safe_name
    for member in proof["members"].values():
        if "/" in safe_name(member) or len(member) > 96:
            raise ValueError("phase12-original-member-contract")
    if coordinates["artifactSize"] > 4 * 1024 * 1024:
        raise ValueError("phase12-original-archive-limit")
    if adapter in GROUPED_ORIGINAL_GAPS:
        # These native contexts have multiple original producers. A convenient aggregate
        # reupload under one real signer cannot authenticate the absent predecessor work.
        return {"state": "unverified", "scope": "original-owner-context-unavailable",
                "blockers": [GROUPED_ORIGINAL_GAPS[adapter]]}
    if not collect:
        return {"state": "unverified", "scope": "retained-coordinates-only",
                "blockers": ["original-producer-reauthentication-required"]}
    with tempfile.TemporaryDirectory(prefix="phase12-original-") as directory:
        root = Path(directory)
        original = helper.authenticate_original(coordinates, root)
        if (type(original) is not helper.OriginalArtifact or original.coordinates != coordinates
                or digest(original.content) != coordinates["artifactDigest"]
                or len(original.content) != coordinates["artifactSize"]):
            raise ValueError("phase12-original-byte-mismatch")
        invocation = (f"https://github.com/{helper.REPOSITORY}/actions/runs/{coordinates['runId']}"
                      f"/attempts/{coordinates['runAttempt']}")
        workflow = helper.PRODUCERS[coordinates["sourceFamily"]][0]
        for number, (name, raw) in enumerate(sorted(payloads.items())):
            entry = {"members": sorted(proof["members"].values()), "member": proof["members"][name],
                     "size": len(raw), "digest": digest(raw)}
            if _selected_archive_member(original.content, entry) != raw:
                raise ValueError("phase12-original-member-mismatch")
            selected = root / f"member-{number}"
            selected.write_bytes(raw)
            results = helper._gh([
                "attestation", "verify", str(selected), "--repo", helper.REPOSITORY,
                "--signer-workflow", helper.REPOSITORY + "/" + workflow,
                "--source-digest", coordinates["sourceCommit"],
                "--signer-digest", coordinates["sourceCommit"], "--format", "json"], helper._environment())
            if not isinstance(results, list) or not any(
                isinstance(row, dict) and row.get("verificationResult", {}).get("signature", {})
                .get("certificate", {}).get("runInvocationURI") == invocation for row in results
            ):
                raise ValueError("phase12-original-attestation-mismatch")
    return {"state": "authenticated", "scope": "exact-original-members-and-producer-attempt",
            "blockers": []}


def hosted_records(raw, source, as_of):
    """Classify retained original API records without confusing them with TLS acquisition.

The record is deliberately not a portable authentication receipt. It preserves run/attempt/job
identity and skips; missing logs/test reports/analyzer dispositions stay unknown.
"""
    value = parse(raw)
    if (type(value) is not dict or set(value) != {"schemaVersion", "repository", "observedAt", "runs"}
            or type(value["schemaVersion"]) is not int or value["schemaVersion"] != 1
            or value["repository"] != "crypta-network/cryptad" or type(value["runs"]) is not list
            or len(value["runs"]) > 32 or timestamp(value["observedAt"]) > timestamp(as_of)):
        raise ValueError("phase12-ci-contract")
    identities, jobs, observations = set(), set(), []
    for selected in value["runs"]:
        if type(selected) is not dict or set(selected) != {"run", "jobs", "checkout"}:
            raise ValueError("phase12-ci-record")
        run, checkout = selected["run"], selected["checkout"]
        if (type(run) is not dict or type(selected["jobs"]) is not list
                or len(selected["jobs"]) > 100 or type(checkout) is not dict
                or set(checkout) != {"commit", "kind"}
                or checkout["kind"] not in {"pr-head", "pr-test-merge", "squash", "push", "unknown"}
                or run.get("repository", {}).get("full_name") != value["repository"]
                or run.get("head_sha") != source["commit"]
                or type(run.get("id")) is not int or type(run.get("run_attempt")) is not int
                or not isinstance(run.get("path"), str)
                or not (run["path"].startswith(".github/workflows/") or run["path"].startswith("dynamic/"))):
            raise ValueError("phase12-ci-source-or-run")
        key = (run["id"], run["run_attempt"])
        if key in identities:
            raise ValueError("phase12-ci-duplicate-attempt")
        identities.add(key)
        if checkout["kind"] in {"squash", "push", "pr-head"} and checkout["commit"] != source["commit"]:
            raise ValueError("phase12-ci-checkout-substitution")
        if run.get("event") == "pull_request" and checkout["kind"] in {"squash", "push"}:
            raise ValueError("phase12-ci-event-substitution")
        for job in selected["jobs"]:
            if (type(job) is not dict or job.get("run_id") != run["id"]
                    or job.get("head_sha") != run["head_sha"] or type(job.get("id")) is not int
                    or job["id"] in jobs or type(job.get("steps")) is not list):
                raise ValueError("phase12-ci-job-substitution")
            jobs.add(job["id"])
            conclusion = job.get("conclusion")
            state = ("skipped" if conclusion in {"skipped", "neutral"} else
                     "executed-pass" if conclusion == "success" and job["steps"] else
                     "executed-fail" if conclusion in {"failure", "cancelled", "timed_out"} else "not-run")
            observations.append({"runId": run["id"], "attempt": run["run_attempt"],
                                 "jobId": job["id"], "event": run.get("event"),
                                 "workflow": run["path"], "checkout": checkout,
                                 "execution": state, "tests": "unknown", "analyzers": "not-inspected"})
    return {"originalProvenance": "unverified", "ci": "unknown", "records": observations,
            "observedAt": value["observedAt"], "retainedBytesDigest": digest(raw),
            "blockers": ["ci-retained-record-authentication-required", "ci-analyzer-disposition-missing"]}
