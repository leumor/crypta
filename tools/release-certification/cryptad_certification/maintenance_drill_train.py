"""Synthetic scratch-Git execution for existing backport inspectors and coverage logic.

Real Git operations and a tiny Python regression run only inside a new disposable repository.
The synthetic review digest exercises validation plumbing; it is not a human review, protected
producer identity, GA chain, real fix, or authorization to release. No commit IDs are exported.
"""
from __future__ import annotations

import copy
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

from .engines import stable_1_0_backport as engine
from .engines import stable_1_0_backport_core as core
from .schema_validation import validate_schema
from .stable_backport_git import GitInspectionError, GitInspector
from .tests.test_stable_backport_git import StableBackportPolicySchemaTest

CASES = (
    "scratch-git-clean-cherry-pick-exact-provenance",
    "scratch-git-conflict-resolution-regression",
    "scratch-git-hidden-omitted-duplicate-change-denial",
    "scratch-git-wrong-lane-and-unsupported-change-denial",
)
SYNTHETIC_REVIEW = "sha256:" + hashlib.sha256(b"synthetic-not-protected-review").hexdigest()


def _require(condition):
    if not condition:
        raise ValueError("drill-train-postcondition-failed")


def _denied(action):
    try:
        action()
    except GitInspectionError:
        return
    raise ValueError("drill-train-unsafe-provenance-accepted")


class ScratchGit:
    """Fixed, finite local commands; identity settings apply only to this synthetic test repo."""

    def __init__(self, root):
        if (not root.is_dir() or root.is_symlink() or any(p.is_symlink() for p in root.parents)
                or any(root.iterdir())):
            raise ValueError("drill-train-scratch-root-must-be-empty")
        self.root = root
        self.calls = 0
        self.environment = GitInspector._sanitized_environment()
        self.environment.update({"GIT_EDITOR": "true", "GIT_SEQUENCE_EDITOR": "true",
                                 "GIT_AUTHOR_DATE": "2001-01-01T00:00:00+00:00",
                                 "GIT_COMMITTER_DATE": "2001-01-01T00:00:00+00:00"})
        self.run("init", "--quiet", "--initial-branch=main", "--object-format=sha1")

    def run(self, *arguments, allowed=(0,)):
        self.calls += 1
        if self.calls > 64 or arguments[0] not in {
            "init", "add", "commit", "checkout", "cherry-pick", "rev-parse", "diff", "status",
        }:
            raise ValueError("drill-train-command-budget-or-operation-denied")
        result = subprocess.run(
            ["git", "--no-replace-objects", "-c", "core.hooksPath=" + os.devnull,
             "-c", "commit.gpgSign=false", "-c", "core.fsmonitor=false",
             "-c", "user.name=Synthetic maintenance drill",
             "-c", "user.email=synthetic-maintenance-drill@example.invalid", *arguments],
            cwd=self.root, env=self.environment, stdin=subprocess.DEVNULL,
            capture_output=True, text=True, timeout=10)
        if result.returncode not in allowed or len(result.stdout) + len(result.stderr) > 65536:
            raise ValueError("drill-train-git-command-failed")
        return result

    def commit(self, message, files):
        for name, content in files.items():
            _require(name in {"limit.py", "context.txt", "unreviewed.txt"})
            (self.root / name).write_text(content, encoding="utf-8")
        self.run("add", "--", *sorted(files))
        self.run("commit", "--quiet", "--no-gpg-sign", "-m", message)
        return self.tip()

    def tip(self):
        return self.run("rev-parse", "HEAD").stdout.strip()

    def regression(self, cap):
        # The candidate's own implementation is executed, not a function copied into the test.
        script = ("import runpy; limit=runpy.run_path('limit.py')['limit']; "
                  "assert limit(-1)==0; assert limit(3)==3; assert limit(100)==" + str(cap))
        result = subprocess.run(["python3", "-I", "-B", "-c", script], cwd=self.root,
                                env=self.environment, stdin=subprocess.DEVNULL,
                                capture_output=True, timeout=10)
        _require(result.returncode == 0)


def execute(root: Path) -> list[str]:
    """Execute real cherry-pick/conflict/coverage cases and remove the owned scratch repo."""
    root = Path(root).absolute()
    if (not root.is_dir() or root.is_symlink() or any(p.is_symlink() for p in root.parents)
            or root.stat().st_uid != os.geteuid()):
        raise ValueError("drill-train-root-invalid")
    policy = json.loads((Path(__file__).resolve().parents[1]
                         / "stable-1.0-backport-release-train-policy.json").read_bytes())
    _require(not validate_schema(policy, "stable-1.0-backport-release-train-policy-v1.schema.json"))
    with tempfile.TemporaryDirectory(prefix="owned-synthetic-train-", dir=root) as temporary:
        _execute_repository(Path(temporary), policy)
    return list(CASES)


def _execute_repository(root, policy):
    git = ScratchGit(root)
    base = git.commit("test: synthetic predecessor", {"limit.py": "def limit(value):\n    return min(value, 10)\n"})
    git.run("checkout", "--quiet", "-b", "synthetic-source", base)
    source = git.commit("fix: synthetic lower bound", {"limit.py": "def limit(value):\n    return max(0, min(value, 10))\n"})
    git.regression(10)
    git.run("checkout", "--quiet", "main")
    predecessor = git.commit("test: synthetic target context", {"context.txt": "synthetic context\n"})
    git.run("checkout", "--quiet", "-b", "synthetic-clean", predecessor)
    git.run("cherry-pick", source)
    picked = git.tip()
    _require(picked != source)
    git.regression(10)
    inspector = GitInspector(root, expected_repository_identity="synthetic.invalid/maintenance/drill",
                             max_output_bytes=1024 * 1024, timeout_seconds=10)
    provenance = inspector.verify_clean_cherry_pick(source, picked, picked, SYNTHETIC_REVIEW, ["limit.py"])
    _require(provenance.mode == "clean-cherry-pick" and provenance.source_commit == source
             and provenance.candidate_commit == picked and provenance.touched_paths == ("limit.py",))
    _denied(lambda: inspector.verify_clean_cherry_pick(source, picked, picked, "", ["limit.py"]))
    _denied(lambda: inspector.verify_clean_cherry_pick(source, picked, picked, SYNTHETIC_REVIEW, ["context.txt"]))
    _coverage(git, inspector, predecessor, picked)
    _lanes(inspector, predecessor, picked, base, policy)
    git.run("checkout", "--quiet", "-b", "synthetic-conflict", base)
    target_base = git.commit("test: synthetic changed target limit", {"limit.py": "def limit(value):\n    return min(value, 5)\n"})
    conflict = git.run("cherry-pick", source, allowed=(1,))
    _require(conflict.returncode == 1 and git.tip() == target_base)
    paths = git.run("diff", "--name-only", "--diff-filter=U", "-z").stdout.split("\0")
    _require(paths == ["limit.py", ""])
    (root / "limit.py").write_text("def limit(value):\n    return max(0, min(value, 5))\n", encoding="utf-8")
    git.run("add", "--", "limit.py")
    git.run("cherry-pick", "--continue")
    resolved = git.tip()
    git.regression(5)
    _require(not git.run("status", "--porcelain").stdout)
    evidence = inspector.manual_conflict_evidence_digest(source, resolved, ["limit.py"])
    arguments = dict(source_commit=source, candidate_commit=resolved, candidate_tip=resolved,
                     source_base_commit=base, target_base_commit=target_base,
                     expected_merge_base_commit=base, conflict_paths=["limit.py"], allowed_paths=["limit.py"],
                     reviewer_authorization_digest=SYNTHETIC_REVIEW,
                     focused_test_evidence_ids=["synthetic-limit-regression"],
                     normalized_diff_evidence_digest=evidence, no_unrelated_feature_change=True)
    manual = inspector.verify_manual_conflict_resolution(**arguments)
    _require(manual.mode == "manual-conflict-resolution" and manual.stable_patch_id is None)
    for changed in ({"focused_test_evidence_ids": []}, {"reviewer_authorization_digest": ""},
                    {"normalized_diff_evidence_digest": SYNTHETIC_REVIEW}, {"target_base_commit": base}):
        _denied(lambda changed=changed: inspector.verify_manual_conflict_resolution(**{**arguments, **changed}))
    _denied(lambda: inspector.verify_clean_cherry_pick(source, resolved, resolved, SYNTHETIC_REVIEW, ["limit.py"]))


def _coverage(git, inspector, predecessor, picked):
    fix = {"fixId": "synthetic-limit-fix", "classification": "compatible-bug-fix",
           "provenance": {"candidateCommit": picked}}
    coverage, unaccounted = engine._candidate_coverage(inspector, predecessor, picked, [fix])
    _require(not unaccounted and len(coverage) == 1 and coverage[0]["category"] == "accepted-fix")
    hidden = git.commit("test: synthetic unexplained change", {"unreviewed.txt": "unaccounted\n"})
    coverage, unaccounted = engine._candidate_coverage(inspector, predecessor, hidden, [fix])
    _require(unaccounted == [hidden] and next(row for row in coverage if row["commit"] == hidden)["category"] == "unaccounted")
    _, omitted = engine._candidate_coverage(inspector, predecessor, hidden, [])
    _require(set(omitted) == {picked, hidden})
    _denied(lambda: engine._candidate_coverage(inspector, predecessor, hidden,
                                             [fix, {**fix, "fixId": "synthetic-duplicate"}]))


def _lanes(inspector, predecessor, candidate, source_base, policy):
    role = dict(lane="routine-maintenance", candidate_build="2", candidate_commit=candidate,
                branch_base=predecessor, authorized_lineage_commit=predecessor,
                authenticated_predecessor_commit=predecessor)
    _require(inspector.verify_branch_role(**role).branch_role == policy["releaseLanePolicy"]["routine-maintenance"]["branchRole"])
    _denied(lambda: inspector.verify_branch_role(**{**role, "lane": "security-hotfix",
                                                   "authorized_lineage_commit": source_base}))
    _denied(lambda: inspector.verify_branch_role(**{**role, "lane": "synthetic-unsupported"}))
    # Reuse only a schema fixture builder. This is not an accepted or reviewed real fix record.
    record = StableBackportPolicySchemaTest._fix_record()
    now = dt.datetime(2026, 1, 2, tzinfo=dt.timezone.utc)
    for classification, reason in (("breaking-change", "never eligible for Stable 1.0"),
                                   ("unsupported-feature-change", "not eligible for Stable 1.0")):
        changed = copy.deepcopy(record)
        changed["classification"] = classification
        changed["publicProjectionDigest"] = core.semantic_digest({
            "fixId": changed["fixId"], "classification": classification,
            "publicSummary": changed["publicSummary"]})
        _require(any(reason in error for error in core.fix_record_errors(changed, policy, now=now)))
