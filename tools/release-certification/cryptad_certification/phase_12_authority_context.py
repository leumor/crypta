"""Bounded native authority contexts used by the Phase 12 evidence audit.

Only fixed, read-only owner validators are invoked. These functions derive semantic scope from
original-format inputs; producer authentication remains a separate prerequisite. In particular,
valid receipt relationships never manufacture an authenticated protected capability.
"""
from __future__ import annotations

import datetime as dt
import contextlib
import hashlib
import importlib.util
import io
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlsplit
import zipfile

from .schema_validation import validate_schema
from .transparency_sources import strict_json

ROOT = Path(__file__).resolve().parents[3]
BASE = Path(__file__).resolve().parents[1]
MAX_BYTES = 512 * 1024 * 1024
REQUIRED_INPUTS = {
    "catalog-closeout": ("authority.json", "evidence.zip"),
    "pilot-runtime": ("execution.json", "evidence.zip"),
    "lifecycle-receipt": ("ledger.json", "descriptor.json", "previous-descriptor.json",
                          "transition.json", "authorization.json", "plan.json", "receipt.json"),
    "protected-public-observation": ("contract.json", "publication.json", "observation.json",
                                     "observation.zip"),
    "maintenance-publication": ("manifest.json", "evidence.zip"),
    "maintenance-activation": ("successor.json", "history.json", "publication.json",
        "authorization.json", "activation-authorization.json", "activation.json", "current-pointer.json"),
    "protected-ga-closeout": ("contract.json", "evidence.zip"),
    "pilot-closeout": ("execution.json", "evidence.zip"),
}
NATIVE_ORIGINAL = frozenset({"protected-ga-closeout", "pilot-closeout"})
ORIGINAL_ADAPTERS = NATIVE_ORIGINAL


class AuthorityContextError(ValueError):
    """Fixed diagnostic without source paths or original private evidence."""


def _deny():
    raise AuthorityContextError("phase12-native-authority-context-invalid")


def _check(errors):
    if errors:
        _deny()


def _json(raw, schema=None):
    try:
        value = strict_json(raw)
    except (ValueError, TypeError, RecursionError):
        _deny()
    pending = [(value, 0)]
    count = 0
    while pending:
        child, depth = pending.pop()
        count += 1
        if depth > 32 or count > 100000:
            _deny()
        if isinstance(child, dict):
            pending.extend((v, depth + 1) for v in child.values())
        elif isinstance(child, list):
            pending.extend((v, depth + 1) for v in child)
    if schema is not None:
        _check(validate_schema(value, schema))
    return value


def _time(value):
    if not isinstance(value, str):
        _deny()
    result = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None or result.utcoffset() != dt.timedelta(0):
        _deny()
    return result


def _digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _archive(raw, destination):
    """Extract only bounded regular files; the owner validates the exact allowed member set."""
    if (len(raw) > MAX_BYTES or len(raw) < 22 or raw[-22:-18] != b"PK\x05\x06"
            or raw[-2:] != b"\x00\x00"):
        _deny()
    destination.mkdir(mode=0o700)
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        entries = archive.infolist()
        if archive.comment or len(entries) > 4096 or sum(e.file_size for e in entries) > MAX_BYTES:
            _deny()
        seen = set()
        for entry in entries:
            name = PurePosixPath(entry.filename)
            mode = entry.external_attr >> 16
            if (entry.is_dir() or not entry.filename or str(name) != entry.filename
                    or name.is_absolute() or any(p in {".", ".."} for p in name.parts)
                    or any(p.casefold() in {".ds_store", "__macosx"} or p.startswith("._") for p in name.parts)
                    or "\\" in entry.filename or ":" in entry.filename
                    or entry.filename.casefold() in seen or entry.flag_bits & 1
                    or entry.extra or entry.comment or entry.file_size > max(1, entry.compress_size) * 128
                    or (stat.S_IFMT(mode) not in {0, stat.S_IFREG})
                    or entry.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}):
                _deny()
            seen.add(entry.filename.casefold())
            path = destination.joinpath(*name.parts)
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with archive.open(entry) as source:
                content = source.read(min(MAX_BYTES, entry.file_size) + 1)
            if len(content) != entry.file_size:
                _deny()
            if path.suffix.casefold() == ".json":
                _json(content)
            with path.open("xb") as target:
                target.write(content)
            path.chmod(0o600)
    return destination


def _result(claims, dimensions, coverage, *, synthetic=False, subject=None, claim_results=None):
    value = {"claims": sorted(claims), "dimensions": {
        "localVerification": "executed-pass", "originalProvenance": "unverified", **dimensions},
        "coverage": {"required": sorted(coverage), "observed": sorted(coverage)}, "blockers": [],
        "evidenceClass": "synthetic-test-only" if synthetic else "verified-local-semantics",
        "subjectBindings": subject or {}}
    if claim_results is not None:
        value["claimResults"] = claim_results
    return value


def _catalog(payloads, evaluation, scratch):
    from .engines import stable_1_0_catalog_authority as owner
    manifest = _json(payloads["authority.json"], owner.EXECUTION_SCHEMA)
    _check(owner._policy_contract_errors(_json((BASE / "stable-1.0-catalog-authority-policy.json").read_bytes())))
    _check(owner._sensitive_findings(manifest, allow_public_keys=True))
    if _time(manifest["transparency"]["generatedAt"]) > evaluation:
        _deny()
    evidence = _archive(payloads["evidence.zip"], scratch / "evidence")
    actual_members = {p.relative_to(evidence).as_posix() for p in evidence.rglob("*") if p.is_file()}
    expected_members = {owner.PROTECTED_RELEASE_SUMMARY_FILE, owner.INDEPENDENT_SUMMARY_FILE,
        owner.SUBJECT_INVENTORY_FILE, owner.PRIMARY_SUBJECT_BUNDLE_FILE, owner.FROZEN_CATALOG_FILE,
        owner.FROZEN_SIGNATURE_FILE, owner.ROLLBACK_CATALOG_FILE, owner.ROLLBACK_SIGNATURE_FILE,
        owner.GA_PLAN_FILE, owner.GA_RECEIPT_FILE, owner.GA_OBSERVATION_FILE, owner.LIVE_PUBLICATION_FILE,
        owner.MIRROR_OBSERVATION_FILE, owner.DRILL_RECEIPTS_FILE}
    if manifest["ceremony"]["ceremonyType"] != "genesis":
        expected_members.update({owner.PREVIOUS_TRANSPARENCY_FILE, owner.PREVIOUS_TRANSPARENCY_SIGNATURE_FILE})
    if manifest["recoveryAuthorization"]["authorizationType"] == "protected-recovery-quorum":
        expected_members.add(owner.RECOVERY_QUORUM_RECEIPT_FILE)
    if actual_members != expected_members and not (manifest["fixtureOnly"] and not actual_members):
        _deny()
    errors, keys = owner._validate_keyset(manifest, True)
    errors += owner._validate_recovery(manifest, keys, True)
    # Fixture manifests intentionally have no original operational handoff. They stay synthetic.
    source = None if manifest["fixtureOnly"] and not any(evidence.iterdir()) else evidence
    bound_errors, _, _ = owner._validate_bound_evidence(manifest, "closeout", source, None, keys)
    drill_errors, times = owner._validate_drills(manifest, True, source)
    errors += bound_errors + drill_errors
    errors += owner._validate_publication(manifest, keys, True, times.get("catalog-rollback"), True)
    artifact = owner._transparency_artifact(manifest)
    signature_errors, _ = owner._validate_transparency_signature(manifest, artifact, keys, True)
    errors += signature_errors + validate_schema(artifact, owner.TRANSPARENCY_SCHEMA)
    _check(errors)
    for observation in manifest["publication"]["observations"]:
        if _time(observation["observedAt"]) > evaluation:
            _deny()
    if any(_time(value) > evaluation for value in times.values()):
        _deny()
    publication = {"dimensions": {"localVerification": "executed-pass", "coverage": "complete",
        "publication": "published", "publicObservation": "observed"}, "blockers": []}
    drills = {"dimensions": {"localVerification": "executed-pass", "coverage": "complete",
        "runtimeExecution": "observed"}, "blockers": []}
    # Native key-transparency verification proves the signed export. The owner deliberately
    # has no separate public-key publication receipt; do not infer a deployment from this file.
    transparency = {"dimensions": {"localVerification": "executed-pass", "coverage": "complete"},
                    "blockers": []}
    return _result(["p12-293-publication", "p12-293-drills", "p12-293-transparency"], {},
        ["exact-catalog-and-signatures", "all-primary-and-mirror-observations", *owner.REQUIRED_DRILLS,
         "signed-key-transparency-export"], synthetic=manifest["fixtureOnly"],
        subject={"commit": manifest["release"]["sourceCommit"], "build": str(manifest["release"]["buildVersion"])},
        claim_results={"p12-293-publication": publication, "p12-293-drills": drills,
                       "p12-293-transparency": transparency})


def _pilot(payloads, evaluation, scratch, *, include_roots=False):
    from .engines import stable_1_0_third_party_pilot as owner
    contract = _json(payloads["execution.json"], owner.EXECUTION_SCHEMA)
    evidence = _archive(payloads["evidence.zip"], scratch / "evidence")
    policy, _ = owner._policy(ROOT)
    errors, roles = owner._key_errors(contract, evaluation)
    errors += owner._externality_errors(contract, policy, roles, evaluation)
    errors += owner._cohort_contract_errors(contract) + owner._pilot_node_contract_errors(contract)
    documents = {}
    for field, schema in (("externalHandoff", owner.HANDOFF_SCHEMA), ("reviewCohort", owner.REVIEW_SCHEMA),
                          ("publisherApproval", owner.APPROVAL_SCHEMA), ("catalogPublication", owner.PUBLICATION_SCHEMA),
                          ("runtimeDrill", owner.RUNTIME_SCHEMA), ("collectorSummary", owner.COLLECTOR_SCHEMA)):
        documents[field], item_errors = owner._bound_json(contract, evidence, field, schema)
        errors += item_errors
    _check(errors)
    handoff, review, approval = (documents[x] for x in ("externalHandoff", "reviewCohort", "publisherApproval"))
    expected_members = {contract["evidence"][name]["fileName"] for name in documents}
    for row in handoff["cohort"]:
        expected_members.update({row["submissionFile"], row["bundleFile"]})
    if include_roots:
        for field in ("protectedRelease", "independentReproducibility", "catalogAuthority", "selectedRcFreeze"):
            binding = contract["evidence"][field]
            if binding is not None:
                expected_members.add(binding["fileName"])
                expected_schema = owner.RC_FREEZE_SCHEMA if field == "selectedRcFreeze" else None
                _check(owner._bound_file(contract, evidence, field, expected_schema)[2])
    if {p.relative_to(evidence).as_posix() for p in evidence.rglob("*") if p.is_file()} != expected_members:
        _deny()
    if include_roots:
        roots = {}
        for field, member, schema in (
                ("protectedRelease", "stable-1.0-protected-release-execution-summary.json", "stable-1.0-protected-release-execution-summary-v1.schema.json"),
                ("independentReproducibility", "stable-1.0-independent-reproducibility-summary.json", "stable-1.0-independent-reproducibility-summary-v1.schema.json")):
            if contract["evidence"][field] is not None:
                roots[field], root_errors = owner._bound_artifact_json(contract, evidence, field, member, schema)
                _check(root_errors)
        if contract["evidence"]["selectedRcFreeze"] is not None:
            roots["selectedRcFreeze"], root_errors = owner._bound_json(contract, evidence, "selectedRcFreeze", owner.RC_FREEZE_SCHEMA)
            _check(root_errors)
            freeze = roots["selectedRcFreeze"]
            _check(owner.rc_freeze.validate_freeze_shape(freeze))
            candidate = freeze["candidate"]
            source = contract["evidence"]["selectedRcFreeze"]["provenance"]
            if (candidate["releaseId"] != contract["release"]["releaseId"]
                    or candidate["buildVersion"] != str(contract["release"]["buildVersion"])
                    or candidate["sourceCommit"] != contract["repository"]["sourceCommit"]
                    or candidate["sourceRef"] != f"refs/heads/release/{contract['release']['buildVersion']}"
                    or candidate["productionDistributionDigest"] != contract["release"]["productDistributionDigest"]
                    or source["repositoryIdentity"] != contract["repository"]["identity"]
                    or source["workflowPath"] != owner.SELECTED_RC_WORKFLOW
                    or source["workflowCommit"] != contract["repository"]["sourceCommit"]
                    or source["environment"] != owner.SELECTED_RC_ENVIRONMENT or source["conclusion"] != "success"):
                _deny()
        if contract["evidence"]["catalogAuthority"] is not None:
            binding = contract["evidence"]["catalogAuthority"]
            path = evidence / binding["fileName"]
            summary = owner._catalog_authority_summary(path)
            _check(validate_schema(summary, owner.catalog_authority.AUTHORITY_SUMMARY_SCHEMA))
            independent = roots.get("independentReproducibility")
            dispatch = roots.get("protectedRelease", {}).get("dispatchPackage") or {}
            selected = (dispatch.get("gaValidation") or {}).get("selectedRc")
            frozen = roots.get("selectedRcFreeze", {}).get("stableCatalog")
            independent_digests = None if independent is None else {
                "summaryDigest": independent["summaryDigest"], "resultDigest": independent["reproducibilityResultDigest"],
                "subjectInventoryDigest": independent["subjectInventoryDigest"]}
            _, root_errors = owner.catalog_authority_closeout.verify_artifact(path, expected_digest=binding["digest"],
                contract_root=contract["authorities"]["protectedReleaseRootDigest"], release_id=contract["release"]["releaseId"],
                build_version=contract["release"]["buildVersion"], source_commit=contract["repository"]["sourceCommit"],
                selected_rc=selected, frozen_catalog=frozen, independent_digests=independent_digests)
            missing_context = set()
            if independent is None:
                missing_context.add("catalog authority summary differs from the exact PR-292 result")
            if selected is None or frozen is None:
                missing_context.add("catalog authority summary lacks the authenticated frozen catalog subject")
            _check([error for error in root_errors if error not in missing_context])
            if (summary["summaryDigest"] != contract["authorities"]["catalogAuthorityDigest"]
                    or summary["keysetDigest"] != contract["authorities"]["keysetDigest"]
                    or summary["independentReproducibilitySummaryDigest"] != contract["authorities"]["independentReproducibilityDigest"]
                    or _time(summary["generatedAt"]) > evaluation):
                _deny()
    maximum = policy["freshness"]["maximumReceiptAgeSeconds"]
    # These are the same side-effect-free stages as owner.run(verify-runtime). The root phase
    # alone performs online Actions authentication; it is deliberately not invoked here.
    _check(owner._handoff_errors(contract, handoff, evidence, policy, evaluation))
    _check(owner._review_errors(contract, handoff, review, roles["app-reviewer"], evaluation, maximum))
    _check(owner._approval_errors(contract, handoff, approval, roles["app-reviewer"], evaluation, maximum))
    _check(owner._publication_errors(contract, review, documents["catalogPublication"], roles["catalog-signing"], evaluation, maximum))
    _check(owner._runtime_errors(contract, review, approval, documents["catalogPublication"],
        documents["runtimeDrill"], documents["collectorSummary"], evaluation, maximum))
    return _result(["p12-294-runtime"], {"runtimeExecution": "observed", "coverage": "complete", "cleanup": "complete"},
        policy["requiredRuntimeEvents"], synthetic=contract["fixtureOnly"] or contract["selfTest"],
        subject={"commit": contract["repository"]["sourceCommit"], "build": str(contract["release"]["buildVersion"]),
                 "digest": contract["release"]["productDistributionDigest"]})


def _pilot_closeout(payloads, evaluation, scratch, *, collect):
    from .engines import stable_1_0_third_party_pilot as owner
    from .engines import stable_1_0_protected_release as transport_owner
    from .transparency_sources import _original_helper
    from unittest.mock import patch
    contract = _json(payloads["execution.json"], owner.EXECUTION_SCHEMA)
    if collect and (contract["fixtureOnly"] or contract["selfTest"]):
        _deny()
    policy, _ = owner._policy(ROOT)
    evaluation = owner._verification_time(contract, policy, evaluation)
    if (contract["repository"]["identity"] != policy["repositoryIdentity"]
            or contract["authorities"]["catalogChannel"] != policy["requiredCatalogChannel"]):
        _deny()
    result = _pilot(payloads, evaluation, scratch, include_roots=True)
    result["claims"] = ["p12-294-externality", "p12-294-review", "p12-294-runtime"]
    runtime_dimensions = dict(result["dimensions"])
    result["dimensions"] = {"localVerification": "executed-pass", "originalProvenance": "unverified"}
    missing = [field for field in ("protectedRelease", "independentReproducibility", "catalogAuthority", "selectedRcFreeze")
               if contract["evidence"][field] is None]
    collected, gap = False, "original-producer-reauthentication-required"
    if missing:
        gap = "native-pilot-original-roots-not-supplied"
        # Missing predecessors do not hide invalid supplied roots. Defer only the original
        # GET checks and the exact native missing-input diagnostics. Fixture runtime records
        # have their own producer class and can never enter explicit original collection.
        permitted = {f"{field} evidence is not bound" for field in missing}
        if contract["fixtureOnly"] or contract["selfTest"]:
            permitted.add("runtimeDrill protected producer provenance differs")
        with patch.object(owner, "_github_actions_coordinate_errors", return_value=[]), \
                patch("socket.socket", side_effect=OSError("phase12-offline-network-denied")):
            errors = owner._authority_root_errors(contract, scratch / "evidence")
        _check([error for error in errors if error not in permitted])
    else:
        token = None
        if collect:
            try:
                token = _original_helper()._environment().get("GH_TOKEN")
            except (OSError, ValueError):
                pass
        if token:
            with patch.dict(os.environ, {"GH_TOKEN": token}), _ga_bounded_transport(transport_owner) as transport:
                errors = owner._authority_root_errors(contract, scratch / "evidence")
            collected = not transport["unavailable"] and transport["requests"] > 0
            gap = "native-pilot-original-access-unavailable" if transport["unavailable"] else "native-original-stages-not-observed"
        elif collect:
            gap = "native-pilot-leumor-authentication-unavailable"
        if not collected:
            # Only the original GET boundary is deferred. All fixed root schemas, exact
            # archive memberships, selected RC and PR292/293 consumer checks still execute.
            with patch.object(owner, "_github_actions_coordinate_errors", return_value=[]), \
                    patch("socket.socket", side_effect=OSError("phase12-offline-network-denied")):
                errors = owner._authority_root_errors(contract, scratch / "evidence")
        _check(errors)
    blocked = [] if collected else [gap]
    result["claimResults"] = {
        "p12-294-externality": {"dimensions": {"localVerification": "executed-pass", "coverage": "complete"},
            "coverage": {"required": ["actual-external-source-and-publisher"], "observed": ["actual-external-source-and-publisher"]}, "blockers": blocked},
        "p12-294-review": {"dimensions": {"localVerification": "executed-pass", "coverage": "complete",
            **({"independentReview": "accepted"} if collected else {})},
            "coverage": {"required": ["reviewed-rejected-resubmitted-caution-cohort"], "observed": ["reviewed-rejected-resubmitted-caution-cohort"]}, "blockers": blocked},
        "p12-294-runtime": {"dimensions": {key: value for key, value in runtime_dimensions.items()
            if collected or key not in {"runtimeExecution", "cleanup"}}, "coverage": result["coverage"], "blockers": blocked}}
    result["originalProof"] = {"state": "authenticated" if collected else "unverified",
        "scope": "native-pilot-exact-protected-roots-and-runtime-producer" if collected else "native-pilot-local-semantics-only", "blockers": blocked}
    return result


def _lifecycle(payloads, evaluation):
    from .engines import stable_1_0_lifecycle as owner
    from .engines import stable_1_0_lifecycle_core as core
    names = {"ledger": owner.LEDGER_FILE, "descriptor": owner.DESCRIPTOR_FILE,
             "transition": owner.TRANSITION_FILE, "authorization": owner.AUTHORIZATION_FILE,
             "plan": owner.PLAN_FILE, "receipt": owner.RECEIPT_FILE}
    data = {key: _json(payloads[key + ".json"], owner.SCHEMAS[file]) for key, file in names.items()}
    previous = _json(payloads["previous-descriptor.json"])
    if previous is not None:
        _check(validate_schema(previous, owner.SCHEMAS[owner.DESCRIPTOR_FILE]))
    policy = _json((BASE / owner.POLICY_FILE).read_bytes(), owner.SCHEMAS[owner.POLICY_FILE])
    _check(core.policy_errors(policy))
    ledger, descriptor, transition, authorization, plan, receipt = (data[k] for k in names)
    if (ledger["ledgerDigest"] != core.ledger_digest(ledger)
            or transition["transitionSetDigest"] != owner._transition_set_digest(transition)):
        _deny()
    derived, errors = core.build_descriptor(ledger, policy, descriptor["generatedAt"], previous,
                                           policy["descriptor"]["updateKeyIdentityDigest"])
    _check(errors + owner._descriptor_freshness_errors(descriptor, evaluation))
    if derived != descriptor:
        _deny()
    _, valid, errors = owner._validate_authorization(authorization, policy, descriptor, ledger, transition,
        plan["publicRequestUri"], plan["latestMaintenancePointerPublicUri"], plan["latestMaintenancePointerDigest"],
        evaluation, valid_at=_time(receipt["generatedAt"]))
    _check(errors)
    expected = owner._publication_plan(descriptor, ledger, authorization, valid, plan["publicRequestUri"],
        plan["latestMaintenancePointerPublicUri"], plan["latestMaintenancePointerDigest"], transition["transitionSetDigest"])
    if not valid or expected != plan:
        _deny()
    valid, errors = owner._verify_receipt(receipt, descriptor, plan, authorization, evaluation)
    _check(errors)
    if not valid:
        _deny()
    result = _result(["p12-301-support-lifecycle"], {"publication": "published", "coverage": "partial"},
        ["exact-ledger-descriptor", "exact-transition-authorization", "original-format-publication-receipt"],
        subject={"digest": descriptor["descriptorDigest"]})
    result["blockers"] = ["original-lifecycle-public-observation-required"]
    result["coverage"]["required"].append("independent-public-observation")
    return result


def _observation(payloads, evaluation, scratch):
    from .engines import stable_1_0_protected_release as owner
    contract = _json(payloads["contract.json"], owner.CONTRACT_SCHEMA)
    publication = _json(payloads["publication.json"], owner.GA_PUBLICATION_RECEIPT_SCHEMA)
    value = _json(payloads["observation.json"], owner.OBSERVATION_SCHEMA)
    policy = _json((BASE / "stable-1.0-protected-release-policy.json").read_bytes())
    coordinate = contract["workflowCoordinates"]["publicObservation"]
    _check(owner._receipt_classification_errors(value, "public observation"))
    _check(owner._observation_coordinate_errors(value, coordinate,
        observation_workflow=policy["requiredWorkflowPaths"]["publicObservation"],
        observation_environment=policy["workflowPolicy"]["publicObservationEnvironment"],
        commit=contract["repository"]["candidateCommit"], build=contract["release"]["integerBuild"]))
    receipt_path = scratch / "observation.json"
    receipt_path.write_bytes(payloads["observation.json"])
    archive_path = scratch / "observation.zip"
    archive_path.write_bytes(payloads["observation.zip"])
    binding = {"path": "observation.zip", "sha256": _digest(payloads["observation.zip"]), "schema": None}
    _check(owner._observation_artifact_errors(scratch, binding, receipt_path, coordinate))
    commit = contract["repository"]["candidateCommit"]
    build = contract["release"]["integerBuild"]
    selected = contract["ga"]["selectedRc"]
    _check(owner._receipt_classification_errors(publication, "GA publication"))
    if (value["releaseId"] != contract["release"]["id"] or value["buildVersion"] != build
            or value["candidateCommit"] != commit or value["publicationReceiptDigest"] != _digest(payloads["publication.json"])
            or value["productDigest"] != selected["productDigest"]
            or publication["releaseId"] != contract["release"]["id"]
            or publication["buildVersion"] != build or publication["sourceCommit"] != commit
            or publication["freezeDigest"] != selected["freezeDigest"]
            or publication["productDistributionDigest"] != selected["productDigest"]
            or publication["archiveDigest"] != selected["archiveDigest"]
            or publication["publicationState"] != "publication-complete"
            or publication["finalVerificationStatus"] != "pass"
            or not _time(publication["publishedAt"]) <= _time(value["observedAt"]) <= evaluation):
        _deny()
    expected_tag = {"name": publication["tag"]["name"], "targetCommit": publication["tag"]["targetCommit"],
                    "annotated": True, "status": "observed-exact"}
    release = publication["githubRelease"]
    expected_release = {"releaseId": release["releaseId"], "publicUrl": release["publicUrl"],
        "name": f"Cryptad Stable 1.0 (v{build})", "tagName": f"v{build}", "targetCommitish": commit,
        "draft": False, "prerelease": False, "releaseNotesDigest": release["releaseNotesDigest"], "status": "observed-exact"}
    if value["tag"] != expected_tag or value["githubRelease"] != expected_release:
        _deny()
    expected = {a["publicUri"]: (a["digest"], a["sizeBytes"]) for a in publication["assets"]}
    if len(expected) != len(publication["assets"]):
        _deny()
    catalog = publication["catalog"]
    targets = contract["publicTargets"]
    for uri in [targets["catalogPrimaryUri"], *targets["catalogMirrorUris"], targets["catalogRollbackUri"]]:
        rollback = uri == targets["catalogRollbackUri"]
        subject = catalog["rollback"] if rollback else catalog
        expected[uri] = (subject["digest" if rollback else "catalogDigest"], None)
        expected[owner.catalog_signature_uri(uri)] = (subject["signatureDigest"], None)
    observations = value["targets"]
    if len(observations) != len(expected) or {r["publicUri"] for r in observations} != set(expected):
        _deny()
    for row in observations:
        digest, size = expected[row["publicUri"]]
        if (row["sha256"] != digest or row["status"] != "observed-exact"
                or (size is not None and row["size"] != size)
                or owner._public_https(row["publicUri"]) is not None):
            _deny()
    result = _result(["p12-291-observation"], {"publicObservation": "observed", "coverage": "complete"},
        ["exact-publication-receipt", "annotated-tag", "public-release", "every-asset-catalog-signature"],
        subject={"commit": commit, "build": str(build), "digest": value["productDigest"]})
    result["observedAt"] = value["observedAt"]
    return result


def _relative_input(value):
    if not isinstance(value, str):
        _deny()
    path = PurePosixPath(value)
    if (not value or path.is_absolute() or str(path) != value or "\\" in value or ":" in value
            or any(part in {".", ".."} for part in path.parts)):
        _deny()
    return path


def _maintenance_inputs(payloads, scratch):
    """Validate the immutable native manifest and exact referenced original input inventory."""
    from .cli import _validate_stable_maintenance_manifest
    from .manifest import load_manifest
    manifest = _json(payloads["manifest.json"])
    if (not isinstance(manifest, dict) or manifest.get("commands") not in (
            {"stable-maintenance": {"mode": "validate-only"}},
            {"stable-maintenance": {"mode": "validate-only", "args": []}})
            or not isinstance(manifest.get("execution"), dict)
            or any(type(v) is not bool or (v and k not in {"skipGradle", "skipFullBuild"})
                   for k, v in manifest["execution"].items())):
        _deny()
    manifest_path = scratch / "original-manifest.json"
    manifest_path.write_bytes(payloads["manifest.json"])
    # Reuse the native strict manifest parser before materializing any paths. It validates the
    # owning release profile, policy keys, required inputs and the permitted command vocabulary.
    parsed = load_manifest(manifest_path, ROOT, scratch / "unused-output")
    _validate_stable_maintenance_manifest(parsed)
    if parsed.release.profile != "stable-review" or parsed.policies.get("releaseClass") not in {"maintenance", "security-hotfix"}:
        _deny()
    if not {"stableMaintenancePublicationReceipt", "coreUpdatePublicationReceipt"}.issubset(parsed.inputs):
        _deny()
    inputs = manifest["inputs"]
    if not inputs or any(not isinstance(v, str) for v in inputs.values()):
        _deny()
    for value in inputs.values():
        _relative_input(value)
    evidence = _archive(payloads["evidence.zip"], scratch / "evidence")
    exact = set()
    for key, value in inputs.items():
        path = evidence.joinpath(*_relative_input(value).parts)
        if key == "maintenanceCandidateAssets":
            if not path.is_dir():
                _deny()
            continue
        if not path.is_file():
            _deny()
        exact.add(value)
    if "maintenanceCandidateAssets" in inputs:
        if "maintenanceCandidate" not in inputs:
            _deny()
        from .engines.stable_1_0_maintenance_core import CANDIDATE_INPUT_SCHEMA
        candidate = _json((evidence / inputs["maintenanceCandidate"]).read_bytes(), CANDIDATE_INPUT_SCHEMA)
        names = [candidate["product"]["fileName"], candidate["stableCatalog"]["fileName"],
                 candidate["stableCatalog"]["signatureFileName"], *(p["fileName"] for p in candidate["packages"])]
        if len(names) != len(set(names)):
            _deny()
        for name in names:
            if len(_relative_input(name).parts) != 1:
                _deny()
            exact.add(str(PurePosixPath(inputs["maintenanceCandidateAssets"]) / name))
    actual = {p.relative_to(evidence).as_posix() for p in evidence.rglob("*") if p.is_file()}
    if actual != exact:
        _deny()
    return manifest, evidence


def _maintenance_dns_required(manifest):
    """Report unavailable address verification without resolving artifact-selected hosts."""
    policies = manifest["policies"]
    metadata = policies.get("metadata", {})
    fields = [policies.get("artifactBaseUri")]
    for key in ("catalogPrimaryUri", "catalogMirrorUris", "catalogRollbackUri", "coreUpdatePublicUri",
                "deploymentServicePublicUri", "latestPointerPublicUri"):
        value = metadata.get(key)
        if isinstance(value, str):
            fields.extend(value.split(","))
    for value in fields:
        if not value:
            continue
        parsed = urlsplit(value.strip())
        if parsed.scheme != "https":
            continue  # The original authority will reject invalid targets itself.
        try:
            ipaddress.ip_address(parsed.hostname or "")
        except ValueError:
            return True
    return False


def _maintenance(payloads, evaluation, scratch):
    """Run the complete existing maintenance validate-only path on exact confined originals."""
    from . import transparency_public_projection as public
    manifest, evidence = _maintenance_inputs(payloads, scratch)
    if _maintenance_dns_required(manifest):
        return _result(["p12-301-publication"], {"localVerification": "not-run", "coverage": "partial"},
            ["native-maintenance-context-selected"], claim_results={"p12-301-publication": {
                "dimensions": {"localVerification": "not-run", "coverage": "partial"},
                "coverage": {"required": ["current-owner-public-address-verification", "complete-native-maintenance-validation"],
                             "observed": []},
                "blockers": ["native-maintenance-public-address-verification-unavailable"]}})
    # The existing source-owned exporter intentionally uses the actual checkout for canonical
    # policies. Only transport paths are relocated; every original input byte stays unchanged.
    # The raw selected manifest remains bound separately in the selection and is never rewritten.
    with tempfile.TemporaryDirectory(prefix=".phase12-maintenance-", dir=ROOT) as temporary:
        native = Path(temporary)
        relative = native.relative_to(ROOT)
        shutil.copytree(evidence, native / "inputs")
        materialized = json.loads(json.dumps(manifest))
        materialized["inputs"] = {key: str(relative / "inputs" / value) for key, value in manifest["inputs"].items()}
        materialized["output"] = {"root": str(relative / "private-output"), "reset": False}
        materialized_path = native / "manifest.json"
        materialized_path.write_bytes(json.dumps(materialized, sort_keys=True, separators=(",", ":")).encode())
        # Denial adds no trust: even a dependency trying direct-IP transport cannot establish a
        # connection. The original exporter independently denies DNS and invokes validate-only.
        from unittest.mock import patch
        with patch("socket.socket", side_effect=OSError("native-offline-network-denied")):
            raw = public.export_from_manifest("maintenance", materialized_path, native / "private-output", allow_network=False)
        projection = public.validate_public_projection(raw)
    fields = projection["fields"]
    if (fields["buildVersion"] != manifest["release"]["version"]
            or fields["releaseId"] != manifest["release"]["id"]
            or _time(projection["observedAt"]) > evaluation):
        _deny()
    return _result(["p12-301-publication"], {"publication": "published", "coverage": "complete"},
        ["native-ga-root-and-predecessor", "exact-candidate-freeze-and-assets", "native-maintenance-authorization",
         "native-core-update-receipt", "native-successor-and-history", "exact-maintenance-publication-receipt"],
        subject={"commit": fields["sourceCommit"], "build": fields["buildVersion"], "digest": fields["productDigest"]})


def _maintenance_activation_owner():
    """Load one fixed repository verifier; no artifact-controlled backend is imported."""
    name = "cryptad_phase12_maintenance_activation_owner"
    path = BASE / "protected" / "stable_maintenance_publication.py"
    if name in sys.modules:
        module = sys.modules[name]
        if Path(module.__file__).resolve() != path.resolve():
            _deny()
        return module
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        _deny()
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _maintenance_activation(payloads, evaluation, scratch):
    """Verify retained native activation and exact observed pointer, without activating."""
    owner = _maintenance_activation_owner()
    values = {name: _json(raw) for name, raw in payloads.items()}
    for name, raw in payloads.items():
        (scratch / name).write_bytes(raw)
        (scratch / name).chmod(0o600)
    authorization = values["activation-authorization.json"]
    receipt = values["activation.json"]
    original = values["publication.json"]
    request = owner._load_activation_request(
        scratch / "successor.json", scratch / "history.json", scratch / "publication.json",
        scratch / "authorization.json", scratch / "activation-authorization.json",
        authorization.get("expectedCurrentPointerDigest", ""))
    observed = _time(receipt["generatedAt"])
    if not _time(original["generatedAt"]) <= observed <= evaluation:
        _deny()
    # This evaluates the original grant at the original operation, preserving renewable grants;
    # it does not authorize an operation now or claim indefinite current pointer freshness.
    owner._revalidate_activation_authorization(request, observed)
    if authorization["authorizationId"] != (
            f"activation-{authorization['workflowRunId']}-{authorization['workflowRunAttempt']}"):
        _deny()
    expected = {"schemaVersion": 1, "kind": "stable-1.0-maintenance-baseline-activation-receipt",
        "generatedAt": receipt["generatedAt"], "releaseId": original["releaseId"],
        "buildVersion": original["buildVersion"], "releaseClass": original["releaseClass"],
        "candidateIdentityDigest": original["candidateIdentityDigest"],
        "authorizationDigest": request.authorization_digest,
        "activationAuthorizationDigest": request.activation_authorization_digest,
        "successorBaselineDigest": request.successor_digest, "historyDigest": request.history_digest,
        "backportReleaseTrainDigest": request.activated_pointer["backportReleaseTrainDigest"],
        "expectedPreviousPointerDigest": request.expected_pointer_digest,
        "expectedActivatedPointerDigest": request.activated_pointer_digest,
        "observedPointerDigest": request.activated_pointer_digest,
        "operation": receipt.get("operation"), "pointerUpdate": "activated", "status": "pass",
        "verificationStatus": "pass", "failureCategory": None, "redaction": dict(owner._PASS_REDACTION)}
    if receipt.get("operation") not in {"created", "verified-existing"} or receipt != expected:
        _deny()
    # Native pointer identity hashes its exact canonical bytes, independently of JSON semantics.
    if (payloads["current-pointer.json"] != request.activated_pointer_bytes
            or values["current-pointer.json"] != request.activated_pointer
            or _digest(payloads["current-pointer.json"]) != receipt["observedPointerDigest"]):
        _deny()
    pointer = owner._normalize_pointer(owner.PointerSnapshot("observed", _digest(payloads["current-pointer.json"]),
        values["current-pointer.json"]["baselineDigest"], original["candidateIdentityDigest"]))
    if (pointer.pointer_digest != request.activated_pointer_digest
            or pointer.active_baseline_digest != request.successor_digest
            or pointer.candidate_identity_digest != original["candidateIdentityDigest"]):
        _deny()
    result = _result(["p12-301-activation"], {"activation": "activated", "publicObservation": "observed", "coverage": "complete"},
        ["native-successor-history-publication-binding", "native-renewable-activation-grant",
         "native-compare-and-swap-result", "exact-observed-current-pointer"],
        subject={"commit": original["sourceCommit"], "build": original["buildVersion"], "digest": original["productDigest"]})
    result["observedAt"] = receipt["generatedAt"]
    result["producerCoordinates"] = {"repository": authorization["workflowRepository"],
        "workflow": ".github/workflows/stable-1.0-maintenance-release.yml",
        "runId": authorization["workflowRunId"], "runAttempt": str(authorization["workflowRunAttempt"]),
        "environment": authorization["protectedEnvironment"], "job": "activate-latest-baseline"}
    return result


def _ga_inputs(payloads, evaluation, scratch):
    from .engines import stable_1_0_protected_release as owner
    contract = _json(payloads["contract.json"], owner.CONTRACT_SCHEMA)
    _check(owner._contract_redaction_errors(contract))
    if _time(contract["evaluationTime"]) > evaluation:
        _deny()
    evidence = _archive(payloads["evidence.zip"], scratch / "evidence")
    bindings = {}
    pending = [contract]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            if "path" in value:
                path = _relative_input(value["path"])
                if any(part.casefold() == ".git" for part in path.parts) or "sha256" not in value:
                    _deny()
                previous = bindings.setdefault(str(path), value)
                if previous["sha256"] != value["sha256"]:
                    _deny()
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
    actual = {p.relative_to(evidence).as_posix() for p in evidence.rglob("*") if p.is_file()}
    if actual != set(bindings):
        _deny()
    for relative, binding in bindings.items():
        raw = (evidence / relative).read_bytes()
        if _digest(raw) != binding["sha256"]:
            _deny()
        if relative.endswith(".json"):
            # The native closeout owns which original schemas apply to each stage. Earlier
            # protected preflight inputs stay exact bytes, not a newly invented replay mode.
            value = _json(raw)
            # Original expiration remains owner-defined. Original event clocks cannot be future.
            for key in ("generatedAt", "observedAt", "publishedAt", "frozenAt"):
                if isinstance(value, dict) and value.get(key) is not None and _time(value[key]) > evaluation:
                    _deny()
    return contract, evidence


def _ga_git(workspace, *args):
    from .transparency_sources import _original_helper
    _original_helper()  # Make only the fixed protected helper directory available.
    from bounded_process import run
    try:
        raw = run(["git", "-C", str(workspace), "-c", "core.hooksPath=/dev/null", *args],
            timeout=60, output_limit=1024 * 1024,
            environment={**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1",
                         "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_ALLOW_PROTOCOL": "file",
                         "GIT_NO_LAZY_FETCH": "1", "GIT_LFS_SKIP_SMUDGE": "1"})
    except (OSError, ValueError):
        raise subprocess.CalledProcessError(1, ["git"]) from None
    return raw.decode("utf-8").strip()


@contextlib.contextmanager
def _ga_workspace(contract, evidence, scratch):
    """Replay only an already-present original candidate and original local release reference."""
    commit = contract["repository"]["candidateCommit"]
    reference = contract["repository"]["sourceRef"]
    observed_refs = []
    for name in (reference, "refs/remotes/origin/" + reference.removeprefix("refs/heads/")):
        try:
            observed_refs.append(_ga_git(ROOT, "rev-parse", "--verify", name + "^{commit}"))
        except subprocess.CalledProcessError:
            pass
    if not observed_refs:
        yield None
        return
    if any(value != commit for value in observed_refs):
        yield None
        return
    try:
        if _ga_git(ROOT, "rev-parse", "--verify", commit + "^{commit}") != commit:
            _deny()
    except subprocess.CalledProcessError:
        yield None
        return
    workspace = scratch / "candidate"
    _ga_git(ROOT, "clone", "--shared", "--no-checkout", "--no-hardlinks", "--", str(ROOT), str(workspace))
    _ga_git(workspace, "checkout", "--detach", commit)
    # Preserve the original ref's observed value in the isolated clone, without creating or
    # changing a reference in the actual shared repository or resolving any remote endpoint.
    _ga_git(workspace, "update-ref", reference, commit)
    for path in evidence.rglob("*"):
        if not path.is_file():
            continue
        target = workspace / path.relative_to(evidence)
        if any(p.is_symlink() for p in (target, *target.parents)):
            _deny()
        if target.exists():
            if not target.is_file() or target.read_bytes() != path.read_bytes():
                _deny()
        else:
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            target.write_bytes(path.read_bytes())
            target.chmod(0o600)
    yield workspace


@contextlib.contextmanager
def _ga_bounded_transport(owner):
    """Guard the native metadata function's original GET requests and response reads."""
    from urllib.request import HTTPRedirectHandler, build_opener
    from urllib.error import HTTPError, URLError
    from unittest.mock import patch
    import re
    class NoRedirect(HTTPRedirectHandler):
        def redirect_request(self, *_args, **_kwargs):
            raise URLError("phase12-native-redirect-denied")
    opener = build_opener(NoRedirect())
    started, counters = time.monotonic(), {"requests": 0, "bytes": 0, "unavailable": False}
    def open_bounded(request, timeout=30):
        parsed = urlsplit(request.full_url)
        allowed = re.fullmatch(r"/repos/crypta-network/cryptad/actions/runs/[1-9][0-9]*/(?:artifacts|attempts/[1-9][0-9]*(?:/jobs)?)", parsed.path)
        if (request.get_method() != "GET" or parsed.scheme != "https" or parsed.netloc != "api.github.com"
                or parsed.fragment or (parsed.path != "/user" and not allowed)
                or parsed.query not in {"", "per_page=100"} or counters["requests"] >= 32
                or time.monotonic() - started >= 180):
            raise URLError("phase12-native-get-boundary")
        counters["requests"] += 1
        try:
            response = opener.open(request, timeout=min(30, timeout))
        except HTTPError as error:
            if error.code in {401, 403, 429} or error.code >= 500:
                counters["unavailable"] = True
            raise
        except (URLError, OSError, TimeoutError):
            counters["unavailable"] = True
            raise
        class Response:
            def __enter__(self):
                return self
            def __exit__(self, *_args):
                response.close()
            def read(self, size=-1):
                raw = response.read(2 * 1024 * 1024 + 1)
                counters["bytes"] += len(raw)
                if len(raw) > 2 * 1024 * 1024 or counters["bytes"] > 16 * 1024 * 1024:
                    raise URLError("phase12-native-get-response-boundary")
                _json(raw)
                return raw
        return Response()
    with patch.object(owner, "urlopen", side_effect=open_bounded):
        yield counters


def _ga_closeout(payloads, evaluation, scratch, *, collect):
    from .engines import stable_1_0_protected_release as owner
    from unittest.mock import patch
    contract, evidence = _ga_inputs(payloads, evaluation, scratch)
    collected = False
    access_gap = "original-producer-reauthentication-required"
    claims = ["p12-291-freeze", "p12-291-validation", "p12-291-publication", "p12-291-observation"]
    with _ga_workspace(contract, evidence, scratch) as workspace:
        if workspace is None:
            result = _result(claims, {"localVerification": "not-run", "coverage": "partial"}, [])
            result["blockers"] = ["original-candidate-checkout-and-release-ref-required"]
            result["originalProof"] = {"state": "unverified", "scope": "native-original-candidate-unavailable", "blockers": result["blockers"]}
            return result
        policy = _json((workspace / "tools/release-certification" / owner.POLICY_FILE).read_bytes())
        token = None
        if collect:
            from .transparency_sources import _original_helper
            try:
                token = _original_helper()._environment().get("GH_TOKEN")
            except (OSError, ValueError):
                pass
        if token:
            with patch.dict(os.environ, {"GH_TOKEN": token}), _ga_bounded_transport(owner) as transport:
                findings, statuses = owner._closeout(workspace, contract, policy)
            collected = not transport["unavailable"] and transport["requests"] > 0
            access_gap = "native-protected-closeout-original-access-unavailable"
            if not transport["unavailable"] and transport["requests"] == 0:
                access_gap = "native-original-stages-not-observed"
        elif collect:
            access_gap = "native-protected-closeout-github-token-unavailable"
        if not collected:
            # A semantic pass through the same native checks grants no original capability.
            # Defer only original transport; fixed coordinate/subject/artifact checks still run.
            with patch.object(owner, "_github_actions_coordinate_errors", return_value=[]), \
                    patch("socket.socket", side_effect=OSError("phase12-offline-network-denied")):
                findings, statuses = owner._closeout(workspace, contract, policy)
        _check(findings)
    stages = {"p12-291-freeze": "protectedRcOperation", "p12-291-validation": "gaValidation",
              "p12-291-publication": "gaPublication", "p12-291-observation": "publicObservation"}
    dimensions = {"p12-291-freeze": {"runtimeExecution": "observed"},
                  "p12-291-validation": {"runtimeExecution": "observed"},
                  "p12-291-publication": {"publication": "published"},
                  "p12-291-observation": {"publicObservation": "observed"}}
    per_claim = {}
    for claim, stage in stages.items():
        passed = statuses[stage] == "completed"
        per_claim[claim] = {"dimensions": {"localVerification": "executed-pass", "coverage": "complete" if passed else "partial",
            **(dimensions[claim] if passed and collected else {})},
            "blockers": ([] if passed else ["native-original-stage-not-observed"]) + ([] if collected else [access_gap]),
            "coverage": {"required": [stage], "observed": [stage] if passed else []}}
    scoped_claims = [claim for claim, stage in stages.items() if statuses[stage] == "completed"]
    result = _result(scoped_claims, {}, [], subject={"commit": contract["repository"]["candidateCommit"],
        "build": str(contract["release"]["integerBuild"])}, claim_results=per_claim)
    selected = contract["ga"]["selectedRc"]
    if selected is not None:
        result["subjectBindings"]["digest"] = selected["productDigest"]
    if statuses["publicObservation"] == "completed":
        observation = _json((evidence / contract["operationEvidence"]["publicObservation"]["path"]).read_bytes())
        result["observedAt"] = observation["observedAt"]
    # The original consumer upgrades only authenticated PR293 partial closeout to its bounded
    # mirrors-observed state. Its exact archive proves ceremony, role registries and six drills;
    # it does not publish the separate signed public-key transparency export.
    if statuses["catalogAuthority"] == "mirrors-observed":
        result["claims"].extend(["p12-293-keyset", "p12-293-publication", "p12-293-drills"])
        catalog_dimensions = {
            "p12-293-keyset": {"runtimeExecution": "observed"},
            "p12-293-publication": {"publication": "published", "publicObservation": "observed"},
            "p12-293-drills": {"runtimeExecution": "observed"}}
        for claim, observed_dimensions in catalog_dimensions.items():
            result["claimResults"][claim] = {"dimensions": {"localVerification": "executed-pass", "coverage": "complete",
                **(observed_dimensions if collected else {})}, "blockers": [] if collected else [access_gap],
                "coverage": {"required": ["native-catalog-producer-and-frozen-subject-closeout"],
                             "observed": ["native-catalog-producer-and-frozen-subject-closeout"]}}
    result["originalProof"] = {"state": "authenticated" if collected else "unverified",
        "scope": "native-protected-closeout-original-actions-and-exact-retained-members" if collected else "native-closeout-local-semantics-only",
        "blockers": [] if collected else [access_gap]}
    return result


def collect_and_verify(adapter, payloads, as_of, scratch, proof=None):
    """Explicit original collection invokes the native producer authority, never a reupload."""
    try:
        if adapter not in NATIVE_ORIGINAL or proof is not None or set(payloads) != set(REQUIRED_INPUTS[adapter]):
            _deny()
        if any(type(raw) is not bytes or len(raw) > MAX_BYTES for raw in payloads.values()):
            _deny()
        scratch = Path(scratch)
        if not scratch.is_dir() or any(scratch.iterdir()) or any(p.is_symlink() for p in (scratch, *scratch.parents)):
            _deny()
        if adapter == "pilot-closeout":
            return _pilot_closeout(payloads, _time(as_of), scratch, collect=True)
        return _ga_closeout(payloads, _time(as_of), scratch, collect=True)
    except Exception:
        raise AuthorityContextError("phase12-native-authority-context-invalid") from None


def verify(adapter, payloads, as_of, scratch):
    """Verify one closed native context without network, experiments or publication."""
    try:
        if adapter not in REQUIRED_INPUTS or set(payloads) != set(REQUIRED_INPUTS[adapter]):
            _deny()
        if any(type(raw) is not bytes or len(raw) > MAX_BYTES for raw in payloads.values()):
            _deny()
        scratch = Path(scratch)
        if not scratch.is_dir() or any(scratch.iterdir()) or any(p.is_symlink() for p in (scratch, *scratch.parents)):
            _deny()
        evaluation = _time(as_of)
        if adapter == "catalog-closeout":
            return _catalog(payloads, evaluation, scratch)
        if adapter == "pilot-runtime":
            return _pilot(payloads, evaluation, scratch)
        if adapter == "lifecycle-receipt":
            return _lifecycle(payloads, evaluation)
        if adapter == "maintenance-publication":
            return _maintenance(payloads, evaluation, scratch)
        if adapter == "maintenance-activation":
            return _maintenance_activation(payloads, evaluation, scratch)
        if adapter == "protected-ga-closeout":
            return _ga_closeout(payloads, evaluation, scratch, collect=False)
        if adapter == "pilot-closeout":
            return _pilot_closeout(payloads, evaluation, scratch, collect=False)
        return _observation(payloads, evaluation, scratch)
    except Exception:
        raise AuthorityContextError("phase12-native-authority-context-invalid") from None
