"""Owned filesystem rehearsal of the maintenance adapter, with synthetic authority only.

The fixture has no authentic GA, signature, train or operator authority. Nothing emitted here
is a publication receipt. The production adapter's CLI remains inaccessible to local execution.
"""
from __future__ import annotations

import copy
import dataclasses
import datetime as dt
import hashlib
from pathlib import Path
from unittest import mock

from .tests import test_stable_maintenance_publication as fixture

publication = fixture.publication


class DiskOperations:
    """Finite synthetic ExternalOperations implementation; no network or environment inputs."""

    def __init__(self, root, bundle):
        self.root = root
        root.mkdir(mode=0o700)
        self.bundle = bundle
        self.calls = []
        self.fail_target = None
        self.fail_after_write = False
        self.predecessor = fixture.POINTER
        self.expected = {
            target: fixture.canonical_bytes({
                "syntheticTarget": target,
                "assets": [{"name": p.name, "bytes": p.read_bytes().hex()}
                           for p in (bundle.product, bundle.package, bundle.catalog,
                                     bundle.catalog_signature)],
            }) for target in publication.TARGETS
        }

    def observe_public_state(self, request):
        targets = {}
        for target, expected in self.expected.items():
            path = self.root / target
            targets[target] = ("absent" if not path.exists() else
                               "matching" if path.read_bytes() == expected else "conflict")
        return publication.PublicSnapshot(self.predecessor, targets)

    def publish_target(self, target, request, protected_input):
        if target not in publication.MUTATION_TARGETS:
            raise ValueError("drill-target-not-allowlisted")
        if len(self.calls) >= 32:
            raise ValueError("drill-operation-budget-exceeded")
        self.calls.append(target)
        if target == self.fail_target and not self.fail_after_write:
            raise RuntimeError("synthetic-failure")
        path = self.root / target
        if path.exists():
            if path.read_bytes() != self.expected[target]:
                raise ValueError("drill-conflicting-bytes")
        else:
            with path.open("xb") as stream:
                stream.write(self.expected[target])
        if target == self.fail_target:
            raise RuntimeError("synthetic-uncertain-response")

    def verify_publication(self, request):
        if any(v != "matching" for v in self.observe_public_state(request).targets.values()):
            raise ValueError("drill-independent-observation-failed")
        return self.bundle.material()


def _require(condition):
    if not condition:
        raise ValueError("drill-postcondition-failed")


def _publish(bundle, operations, root):
    return publication.publish_or_verify_exact(
        bundle.root, fixture.POINTER, operations,
        publication.PublicationProtectedInputs(
            publication.SecretMaterial("stable-catalog", "synthetic-catalog-capability"),
            publication.SecretMaterial("core-update", "synthetic-update-capability")),
        lambda record: _require(record.plan["sourceCommit"] == fixture.COMMIT),
        root / "never-export-receipt.json", root / "never-export-core.json",
        now=lambda: fixture.NOW)


def execute(root: Path) -> list[str]:
    """Execute bounded filesystem mutations and assert production-adapter postconditions.

    Returned values are fixed case ids. Synthetic fixture receipts stay in memory; all fixture
    inputs and target bytes remain inside the caller-owned disposable root.
    """
    completed = []
    with mock.patch.object(publication, "_utcnow", return_value=fixture.NOW):
        bundle = fixture.BundleFixture(root / "synthetic-inputs")
        operations = DiskOperations(root / "synthetic-targets", bundle)
        absent = _publish(bundle, operations, root)
        _require(not absent.passed and not operations.calls)
        completed.append("absent-artifact-base-denied")
        (operations.root / "artifactBase").write_bytes(operations.expected["artifactBase"])
        operations.fail_target = "assets"
        failed = _publish(bundle, operations, root)
        audit = next(iter(failed.artifacts.values()))
        _require(not failed.passed and audit["sideEffectsMayHaveOccurred"]
                 and audit["attemptedTargets"] == ["tag", "githubRelease", "assets"])
        completed.append("interrupted-assets-preserve-prefix")
        operations.fail_target = None
        operations.calls.clear()
        resumed = _publish(bundle, operations, root)
        _require(resumed.passed and operations.calls == ["assets", "stableCatalog", "coreUpdate"])
        completed.append("exact-prefix-resume")
        operations.calls.clear()
        _require(_publish(bundle, operations, root).passed and not operations.calls)
        completed.append("exact-existing-no-mutation")
        (operations.root / "assets").write_bytes(b"synthetic-conflicting-bytes")
        denied = _publish(bundle, operations, root)
        _require(not denied.passed and not operations.calls
                 and (operations.root / "assets").read_bytes() == b"synthetic-conflicting-bytes")
        completed.append("conflict-preserved")
        uncertain = DiskOperations(root / "uncertain-targets", bundle)
        (uncertain.root / "artifactBase").write_bytes(uncertain.expected["artifactBase"])
        uncertain.fail_target = "stableCatalog"
        uncertain.fail_after_write = True
        failed = _publish(bundle, uncertain, root)
        audit = next(iter(failed.artifacts.values()))
        _require(not failed.passed and audit["sideEffectsMayHaveOccurred"]
                 and (uncertain.root / "stableCatalog").exists())
        uncertain.calls.clear()
        uncertain.fail_target = None
        _require(_publish(bundle, uncertain, root).passed and uncertain.calls == ["coreUpdate"])
        completed.append("uncertain-write-observe-before-retry")
        uncertain.predecessor = fixture.digest("changed-pointer")
        uncertain.calls.clear()
        _require(not _publish(bundle, uncertain, root).passed and not uncertain.calls)
        completed.append("stale-predecessor-denied")
        _follow_up(bundle)
        completed.append("hotfix-obligation-carry-and-drop-denial")
        from .maintenance_drill_provider import execute as execute_provider
        completed.extend(execute_provider(root, bundle))
        from .maintenance_drill_train import execute as execute_train
        completed.extend(execute_train(root))
    return completed


def _follow_up(bundle):
    """Exercise exact inherited obligation preservation, with an explicitly simulated clock."""
    inherited = {
        "status": "open", "generatedAt": fixture.timestamp(fixture.NOW - dt.timedelta(days=1)),
        "obligationDigest": fixture.digest("synthetic-obligation"),
        "deadline": fixture.timestamp(fixture.NOW + dt.timedelta(days=6)),
        "closureEvidenceDigest": None, "blocksRoutineMaintenance": True,
        "obligatedReleaseId": "stable-1-0-hotfix-300", "obligatedBuildVersion": "300",
        "obligatedProductDigest": fixture.digest("synthetic-product"),
        "obligatedCandidateIdentityDigest": fixture.digest("synthetic-candidate"),
        "obligatedCandidateFreezeDigest": fixture.digest("synthetic-freeze"),
        "obligatedCandidateFrozenAt": fixture.timestamp(fixture.NOW - dt.timedelta(days=3)),
        "obligatedPredecessorBuild": "299",
        "obligatedPredecessorProductDigest": fixture.digest("synthetic-predecessor"),
        "authorizationDigest": fixture.digest("synthetic-authorization"),
    }
    loaded = bundle.load()
    loaded = dataclasses.replace(loaded, predecessor_baseline={
        **loaded.predecessor_baseline, "hotfixFollowUp": inherited})
    _require(publication._expected_successor_follow_up(loaded) == inherited)
    material = bundle.material()
    successor = copy.deepcopy(material.successor_baseline)
    successor["hotfixFollowUp"] = dict(inherited)
    successor["releaseTrain"]["unresolvedObligationsCarried"] = True
    successor["lineage"]["history"][-1]["baselineIdentityDigest"] = publication._successor_identity(successor)
    successor["lineage"]["lineageDigest"] = fixture.semantic_digest(successor["lineage"]["history"])
    args = (material.history_entry,
            "sha256:" + hashlib.sha256(fixture.canonical_bytes(material.history_entry)).hexdigest(),
            loaded, publication._receipt_identity(material.maintenance_receipt))
    publication._validate_successor(successor, *args)
    successor["hotfixFollowUp"]["deadline"] = fixture.timestamp(fixture.NOW + dt.timedelta(days=7))
    try:
        publication._validate_successor(successor, *args)
    except publication.AdapterError:
        pass
    else:
        raise ValueError("drill-reset-obligation-accepted")
    successor["hotfixFollowUp"] = {"status": "not-required", "generatedAt": fixture.timestamp(fixture.NOW),
                                  "obligationDigest": None, "deadline": None,
                                  "closureEvidenceDigest": None, "blocksRoutineMaintenance": False}
    try:
        publication._validate_successor(successor, *args)
    except publication.AdapterError:
        return
    raise ValueError("drill-dropped-obligation-accepted")
