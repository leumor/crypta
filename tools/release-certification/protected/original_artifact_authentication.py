"""Reauthenticate original protected artifacts; never accept saved API JSON as authority.

The returned bytes were downloaded from their original immutable artifact and checked against
the original successful attempt, producing job, environment deployment and GitHub artifact digest.
This belongs in a protected producer, not the side-effect-free certification engine.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from typing import Any

REPOSITORY = "crypta-network/cryptad"
MAX_ARTIFACT_BYTES = 512 * 1024 * 1024
# These are existing upstream authorities, never caller-selected workflows or environments.
PRODUCERS = {
    "maintenance-app-products": (
        ".github/workflows/stable-1.0-maintenance-release.yml",
        "stable-1.0-maintenance-evidence",
        "Build and authenticate prospective maintenance app products",
    ),
    "stable-maintenance-freeze": (
        ".github/workflows/stable-1.0-maintenance-release.yml",
        "stable-1.0-maintenance-evidence",
        "Freeze exact bytes or validate a prior frozen Stable maintenance candidate",
    ),
    "stable-rc-product": (
        ".github/workflows/stable-1.0-rc-release.yml", "stable-1-0-rc", "stable-rc",
    ),
    "first-party-inventory": (
        ".github/workflows/stable-1.0-independent-reproducibility.yml",
        "stable-1.0-independent-reproducibility-external-receipt",
        "Authenticate and compare independent rebuild",
    ),
    "third-party-inventory": (
        ".github/workflows/stable-1.0-third-party-app-pilot.yml",
        "stable-1-0-third-party-pilot-closeout",
        "Authenticate operational closeout",
    ),
    "first-party-release": (
        ".github/workflows/stable-1.0-supply-chain.yml",
        "stable-1.0-supply-chain-producer",
        "candidate-producer-portable-apps",
    ),
    "third-party-pilot": (
        ".github/workflows/stable-1.0-third-party-app-pilot.yml",
        "stable-1-0-third-party-pilot-import",
        "Authenticate and confine external handoff",
    ),
    "federated-catalog": (
        ".github/workflows/stable-1.0-federated-catalog-trust.yml",
        "stable-1-0-federated-catalog-import",
        "Authenticate and confine federation evidence",
    ),
    "projection-tools": (
        ".github/workflows/stable-1.0-app-subject-projection.yml",
        "stable-1-0-app-subject-projection-tools",
        "build-projection-tools",
    ),
    "app-subject-projection": (
        ".github/workflows/stable-1.0-app-subject-projection.yml",
        "stable-1-0-app-subject-projection",
        "project-app-subjects",
    ),
    "cross-version-supervisor": (
        ".github/workflows/cross-version-live-network-soak.yml",
        "cross-version-live-network-soak",
        "supervise-cross-version",
    ),
    "sharesite-runtime": (
        ".github/workflows/stable-1.0-sharesite-runtime-observation.yml",
        "stable-1-0-sharesite-runtime-observation",
        "observe-sharesite-runtime",
    ),
    "catalog-source": (
        ".github/workflows/stable-1.0-ga-promotion.yml",
        "stable-1-0-ga",
        "Explicitly publish authorized Stable 1.0 GA assets",
    ),
}


class AuthenticationError(ValueError):
    """An allowlisted failure code without supplied paths or API response text."""


@dataclass(frozen=True)
class OriginalArtifact:
    """Bytes and original coordinates obtained through the protected authenticator."""
    content: bytes
    coordinates: dict[str, Any]
    job_completed_at: str | None = None
    artifact_updated_at: str | None = None


def validate_coordinates(value: Any) -> dict[str, Any]:
    fields = {"repository", "sourceFamily", "sourceCommit", "runId", "runAttempt",
              "jobId", "jobName", "artifactId", "artifactName", "artifactDigest", "artifactSize"}
    if not isinstance(value, dict) or set(value) != fields or value["repository"] != REPOSITORY:
        raise AuthenticationError("original-artifact-coordinates-invalid")
    if value["sourceFamily"] not in PRODUCERS:
        raise AuthenticationError("original-artifact-source-family-invalid")
    if not isinstance(value["sourceCommit"], str) or re.fullmatch(r"[0-9a-f]{40}", value["sourceCommit"]) is None:
        raise AuthenticationError("original-artifact-source-invalid")
    if not isinstance(value["artifactDigest"], str) or re.fullmatch(r"sha256:[0-9a-f]{64}", value["artifactDigest"]) is None:
        raise AuthenticationError("original-artifact-digest-invalid")
    for field in ("runId", "runAttempt", "jobId", "artifactId", "artifactSize"):
        if type(value[field]) is not int or not 1 <= value[field] <= 2**53 - 1:
            raise AuthenticationError("original-artifact-coordinate-number-invalid")
    if value["artifactSize"] > MAX_ARTIFACT_BYTES:
        raise AuthenticationError("original-artifact-oversized")
    for field in ("jobName", "artifactName"):
        if not isinstance(value[field], str) or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 ._-]{0,159}", value[field]) is None:
            raise AuthenticationError("original-artifact-coordinate-name-invalid")
    return dict(value)


def _environment() -> dict[str, str]:
    environment = dict(os.environ)
    for name in ("CLICOLOR_FORCE", "FORCE_COLOR", "GH_FORCE_TTY"):
        environment.pop(name, None)
    environment["NO_COLOR"] = "1"
    environment["GH_HOST"] = "github.com"
    if environment.get("GITHUB_ACTIONS") != "true":
        # Explicit repository identity for operator-invoked read-only GitHub calls.
        from bounded_process import run
        try:
            token = run(["gh", "auth", "token", "--user", "leumor", "--hostname", "github.com"],
                        environment=environment, timeout=15, output_limit=16384)
        except (ValueError, OSError):
            raise AuthenticationError("original-artifact-leumor-authentication-unavailable") from None
        if not token.strip():
            raise AuthenticationError("original-artifact-leumor-authentication-unavailable")
        environment["GH_TOKEN"] = token.decode("utf-8").strip()
    return environment


def _gh(arguments: list[str], environment: dict[str, str], *, json_result: bool = True) -> Any:
    try:
        from bounded_process import run
        output = run(["gh", *arguments], environment=environment, timeout=120,
                     output_limit=16 * 1024 * 1024 if json_result else MAX_ARTIFACT_BYTES)
        return json.loads(output) if json_result else output
    except (OSError, ValueError, UnicodeError):
        raise AuthenticationError("original-artifact-github-verification-failed") from None


def authenticate_original(value: Any, private_root: Path) -> OriginalArtifact:
    """Fetch and verify original coordinates without running artifact contents.

    Callers must select the source family and artifact coordinates from their separately reviewed
    source cohort. A valid signature on an unrelated source remains unrelated; this function does
    not construct cohort membership or infer app declarations from an evidence summary.
    """
    selected = validate_coordinates(value)
    workflow, protected_environment, producing_job = PRODUCERS[selected["sourceFamily"]]
    if selected["jobName"] != producing_job:
        raise AuthenticationError("original-artifact-job-policy-mismatch")
    env = _environment()
    prefix = f"repos/{REPOSITORY}"
    attempt = f"{prefix}/actions/runs/{selected['runId']}/attempts/{selected['runAttempt']}"
    run = _gh(["api", attempt], env)
    if (run.get("id") != selected["runId"] or run.get("run_attempt") != selected["runAttempt"]
            or run.get("head_sha") != selected["sourceCommit"] or run.get("path") != workflow
            or run.get("event") != "workflow_dispatch" or run.get("status") != "completed"
            or run.get("conclusion") != "success" or run.get("repository", {}).get("full_name") != REPOSITORY
            or run.get("actor", {}).get("login") != "leumor"
            or run.get("triggering_actor", {}).get("login") != "leumor"):
        raise AuthenticationError("original-artifact-run-mismatch")
    pages = _gh(["api", "--paginate", "--slurp", attempt + "/jobs?per_page=100"], env)
    jobs = [job for page in pages for job in page.get("jobs", [])
            if job.get("id") == selected["jobId"] and job.get("name") == selected["jobName"]
            and job.get("head_sha") == selected["sourceCommit"] and job.get("conclusion") == "success"]
    if len(jobs) != 1:
        raise AuthenticationError("original-artifact-job-mismatch")
    job = jobs[0]
    artifact = _gh(["api", f"{prefix}/actions/artifacts/{selected['artifactId']}"], env)
    if (artifact.get("id") != selected["artifactId"] or artifact.get("name") != selected["artifactName"]
            or artifact.get("digest") != selected["artifactDigest"]
            or artifact.get("size_in_bytes") != selected["artifactSize"]
            or artifact.get("workflow_run", {}).get("id") != selected["runId"]
            or artifact.get("expired") is not False
            or not job["started_at"] <= artifact.get("created_at", "") <= artifact.get("updated_at", "") <= job["completed_at"]):
        raise AuthenticationError("original-artifact-ownership-mismatch")
    deployments = _gh(["api", "--paginate", "--slurp", "--method", "GET", prefix + "/deployments",
                       "-f", "sha=" + selected["sourceCommit"], "-f", "environment=" + protected_environment,
                       "-f", "per_page=100"], env)
    approved = False
    for page in deployments:
        for deployment in page:
            if (deployment.get("environment") != protected_environment or deployment.get("sha") != selected["sourceCommit"]
                    or deployment.get("creator", {}).get("login") != "github-actions[bot]"):
                continue
            statuses = _gh(["api", "--paginate", "--slurp",
                            f"{prefix}/deployments/{deployment['id']}/statuses?per_page=100"], env)
            expected_log = f"https://github.com/{REPOSITORY}/actions/runs/{selected['runId']}/job/{selected['jobId']}"
            approved |= any(status.get("state") == "success" and status.get("log_url") == expected_log
                            and job["started_at"] <= status.get("created_at", "")
                            for rows in statuses for status in rows)
    if not approved:
        raise AuthenticationError("original-artifact-environment-unobserved")
    content = _gh(["api", f"{prefix}/actions/artifacts/{selected['artifactId']}/zip"], env, json_result=False)
    if len(content) != selected["artifactSize"] or "sha256:" + hashlib.sha256(content).hexdigest() != selected["artifactDigest"]:
        raise AuthenticationError("original-artifact-byte-mismatch")
    # The transport ZIP is not an attestation subject. Member signatures/attestations are
    # verified after confined selection; reuploading cannot change the original API ownership.
    return OriginalArtifact(content, selected, job.get("completed_at"), artifact.get("updated_at"))
