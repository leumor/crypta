"""Original protected artifact admission for bounded packaged-node comparisons.

The Stable RC freeze binds its app product, not the portable daemon archive. This adapter
therefore authenticates BOTH original RC and portable producer artifacts, verifies the RC
using the existing GA consumer, and selects daemon bytes from the producer's checksummed
subject handoff. This does not establish a post-freeze portable binding or a long-run authority.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from original_artifact_authentication import authenticate_original, _gh, _environment
from cryptad_certification.cross_version_evidence import validate_plan, digest
from cryptad_certification.engines import stable_1_0_ga_core as ga
from cryptad_certification.engines.stable_1_0_rc_core import ValidationState, file_digest
from cryptad_certification.models import RunContext, RunManifest, ReleaseSpec, OutputSpec

MAX_FILES = 30000
MAX_BYTES = 4 * 1024**3
_SEAL = object()


class ProductAdmissionError(ValueError):
    """Closed error code; upstream details and member paths remain private."""


class AuthenticatedProducts:
    """In-process result of original-byte verification, never a deserializable trust flag."""
    def __init__(self, seal, plan_digest, rows):
        if seal is not _SEAL:
            raise ProductAdmissionError("product-authority-object-not-produced")
        self._plan_digest = plan_digest
        self._rows = rows

    def bind(self, plan, private_config):
        if digest(plan) != self._plan_digest:
            raise ProductAdmissionError("product-authority-plan-substituted")
        for node in plan["nodes"]:
            role = node["role"]
            row = self._rows.get(role)
            supplied = private_config["nodes"][role]["archivePath"]
            path = Path(supplied)
            if (row is None or not path.is_absolute() or not path.is_file() or path.is_symlink()
                    or any(parent.is_symlink() for parent in path.parents)
                    or file_digest(path) != row["artifactDigest"] or row["artifactDigest"] != node["artifactDigest"]
                    or path.stat().st_size != row["artifactSize"] or row["artifactSize"] != node["artifactSize"]):
                raise ProductAdmissionError("product-authority-package-substituted")
        return True

    def bind_apps(self, plan):
        """Require artifact-derived declarations for every selected installed app before launch."""
        if digest(plan) != self._plan_digest:
            raise ProductAdmissionError("app-authority-plan-substituted")
        for node in plan["nodes"]:
            if node["appDigests"] and not self._rows[node["role"]].get("appMatrix"):
                raise ProductAdmissionError("authenticated-app-projection-required-before-launch")
        return True

    def package_paths(self):
        return {role: str(row["path"]) for role, row in self._rows.items()}

    def public_identities(self):
        return [{key: value for key, value in row.items() if key != "path"}
                for _role, row in sorted(self._rows.items())]


def _json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ProductAdmissionError("product-json-duplicate-field")
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=pairs)


def _members(content):
    """Reopen the exact authenticated ZIP and reject links, collisions and expansion bombs."""
    if not isinstance(content, bytes) or len(content) > MAX_BYTES:
        raise ProductAdmissionError("product-archive-byte-budget")
    source = zipfile.ZipFile(io.BytesIO(content))
    members = source.infolist()
    if not members or len(members) > MAX_FILES:
        source.close()
        raise ProductAdmissionError("product-archive-member-budget")
    names, total = set(), 0
    for member in members:
        path = PurePosixPath(member.filename)
        mode = member.external_attr >> 16
        if (not path.parts or path.is_absolute() or any(p in {"", ".", ".."} for p in member.filename.rstrip("/").split("/"))
                or "\\" in member.filename or ":" in member.filename or member.filename.casefold() in names
                or member.flag_bits & 1 or stat.S_ISLNK(mode)
                or stat.S_IFMT(mode) not in {0, stat.S_IFREG, stat.S_IFDIR}
                or any(ord(c) < 32 for c in member.filename)):
            source.close()
            raise ProductAdmissionError("product-archive-unsafe-member")
        names.add(member.filename.casefold())
        total += member.file_size
        if total > MAX_BYTES:
            source.close()
            raise ProductAdmissionError("product-archive-expanded-budget")
    return source


def _one(source, basename):
    matches = [member for member in source.infolist() if not member.is_dir() and PurePosixPath(member.filename).name == basename]
    if len(matches) != 1:
        raise ProductAdmissionError("product-required-member-missing-or-ambiguous")
    return source.read(matches[0])


def _write(path, value):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(value)


def verify_rc_artifact(original, root):
    """Reuse actual GA freeze, provenance, archive, sidecar and complete checksum checks."""
    with _members(original.content) as source:
        freeze_bytes = _one(source, ga.RC_FREEZE_FILE)
        freeze = _json(freeze_bytes)
        candidate = freeze.get("candidate", {})
        if candidate.get("sourceCommit") != original.coordinates["sourceCommit"]:
            raise ProductAdmissionError("rc-original-source-mismatch")
        build = candidate.get("buildVersion")
        if not isinstance(build, str) or re.fullmatch(r"[1-9][0-9]*", build) is None:
            raise ProductAdmissionError("rc-build-invalid")
        names = ga._canonical_rc_artifact_names(build)
        expected_name = f"stable-1-0-rc-{candidate.get('releaseId')}-{build}-{original.coordinates['runId']}-{original.coordinates['runAttempt']}"
        if original.coordinates["artifactName"] != expected_name:
            raise ProductAdmissionError("rc-original-artifact-name-mismatch")
        root.mkdir(mode=0o700)
        required = set(names.values()) | set(ga._canonical_rc_metadata_names())
        for name in sorted(required):
            _write(root / name, _one(source, name))
    manifest = RunManifest(root / "local-selection.json",
        ReleaseSpec(candidate["releaseId"], build, "stable-review"), OutputSpec(root / "output"), {},
        {key: name for key, name in names.items()},
        {"candidateSourceCommit": candidate["sourceCommit"], "candidateSourceRef": candidate["sourceRef"]}, {}, {})
    context = RunContext(root, root / "verify", "stable-ga", manifest)
    state = ValidationState()
    selected = ga.authenticate_selected_rc(context, state)
    if state.blockers:
        raise ProductAdmissionError("rc-existing-consumer-rejected")
    return selected


def verify_portable_artifact(original, selected_rc, node, destination):
    """Select the exact original portable handoff member, never rebuild an old package."""
    with _members(original.content) as source:
        handoff = _json(_one(source, "handoff.json"))
        candidate = selected_rc.freeze["candidate"]
        expected = {"schemaVersion": 1, "kind": "cryptad-stable-supply-chain-builder-handoff",
                    "builderRole": "candidate-producer", "executionId": "portable-apps",
                    "jobName": "candidate-producer-portable-apps", "runnerOs": "linux", "runnerArchitecture": "amd64",
                    "releaseId": candidate["releaseId"], "buildVersion": int(candidate["buildVersion"]),
                    "sourceCommit": candidate["sourceCommit"], "workflowSha": original.coordinates["sourceCommit"],
                    "runId": original.coordinates["runId"], "runAttempt": original.coordinates["runAttempt"]}
        if any(handoff.get(key) != value for key, value in expected.items()):
            raise ProductAdmissionError("portable-original-source-build-or-producer-mismatch")
        if original.coordinates["sourceCommit"] != candidate["sourceCommit"]:
            raise ProductAdmissionError("portable-rc-source-mismatch")
        workflow = f"github.com/crypta-network/cryptad/.github/workflows/stable-1.0-supply-chain.yml@{candidate['sourceCommit']}"
        if handoff.get("workflow") != workflow:
            raise ProductAdmissionError("portable-workflow-source-mismatch")
        checksum_bytes = _one(source, "subject-files.sha256")
        if "sha256:" + hashlib.sha256(checksum_bytes).hexdigest() != handoff.get("fileSetDigest"):
            raise ProductAdmissionError("portable-checksum-list-mismatch")
        checksums = {}
        for line in checksum_bytes.decode("utf-8").splitlines():
            match = re.fullmatch(r"([0-9a-f]{64})  (?:\./)?([A-Za-z0-9][A-Za-z0-9._+@/-]*)", line)
            if not match or ".." in PurePosixPath(match[2]).parts or match[2] in checksums:
                raise ProductAdmissionError("portable-checksums-invalid")
            checksums[match[2]] = "sha256:" + match[1]
        name = f"distributions/cryptad-v{candidate['buildVersion']}.tar.gz"
        members = [m for m in source.infolist() if m.filename == "subjects/" + name]
        if len(members) != 1 or name not in checksums:
            raise ProductAdmissionError("portable-daemon-artifact-missing")
        payload = source.read(members[0])
        actual_digest = "sha256:" + hashlib.sha256(payload).hexdigest()
        if (actual_digest != checksums[name] or actual_digest != node["artifactDigest"]
                or len(payload) != node["artifactSize"] or node["sourceCommit"] != candidate["sourceCommit"]
                or node["product"] != "cryptad" or node["packageTarget"] != "linux-x64"
                or node["contractVersion"] != selected_rc.freeze["platformApi"]["currentContractVersion"]):
            raise ProductAdmissionError("portable-selected-role-binding-mismatch")
        _write(destination, payload)
    return {"role": node["role"], "sourceCommit": candidate["sourceCommit"],
            "releaseId": candidate["releaseId"], "buildVersion": candidate["buildVersion"],
            "artifactDigest": actual_digest, "artifactSize": len(payload), "packageTarget": "linux-x64",
            "rcFreezeDigest": selected_rc.freeze["contentDigest"], "rcProductDigest": selected_rc.product_digest,
            "rcOrigin": selected_rc._original_coordinates,
            "portableOrigin": original.coordinates, "frozenPortableBinding": "not-established",
            "path": destination}


def verify_app_projection(selected_rc, node, selection, root):
    """Bind Java-derived signed declarations to the RC's exact contract snapshot.

    This is a conservative prelaunch subset check, not PlatformApiContractVerifier.
    The selected release policy strictly rejects versions above maximumTested; the
    ordinary app compatibility contract may report that condition as a warning.
    Normal AppHost permission, review,
    consent and origin enforcement remains mandatory; this grants no app privileges.
    """
    from app_subject_projection import authenticate_inventory, validate_declaration
    if not isinstance(selection, dict) or set(selection) != {"coordinates", "cohortDigest"}:
        raise ProductAdmissionError("app-projection-selection-invalid")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", str(selection["cohortDigest"])):
        raise ProductAdmissionError("app-projection-cohort-invalid")
    authenticated = authenticate_inventory(selection["coordinates"], root,
                                          expected_cohort_digest=selection["cohortDigest"])
    inventory = authenticated.inventory()
    if node["role"] in {"candidate-sender", "candidate-recipient"} and inventory.get("sourceCommit") != node["sourceCommit"]:
        raise ProductAdmissionError("app-projection-candidate-source-mismatch")
    contract_path = selected_rc.freeze_path.parent / "platform-api-current-contract.json"
    if file_digest(contract_path) != selected_rc.freeze["platformApi"]["currentContractDigest"]:
        raise ProductAdmissionError("app-contract-snapshot-freeze-binding-mismatch")
    value = _json(contract_path.read_bytes())
    contract = value.get("contract", value)
    if contract.get("contractVersion") != node["contractVersion"] or not isinstance(contract.get("capabilities"), list):
        raise ProductAdmissionError("app-contract-snapshot-invalid")
    descriptors = {}
    for descriptor in contract["capabilities"]:
        name = descriptor.get("name")
        if not isinstance(name, str) or name in descriptors:
            raise ProductAdmissionError("app-contract-capability-duplicate-or-invalid")
        descriptors[name] = descriptor
    by_digest = {}
    for subject in inventory.get("subjects", []):
        declaration = validate_declaration(subject["signedProjection"])
        if declaration["bundleDigest"] in by_digest:
            raise ProductAdmissionError("app-projection-duplicate-bundle")
        by_digest[declaration["bundleDigest"]] = declaration
    results = []
    for bundle in node["appDigests"]:
        app = by_digest.get(bundle)
        if app is None:
            raise ProductAdmissionError("app-projection-selected-bundle-missing")
        minimum, maximum = app["minimumContractVersion"], app["maximumTestedContractVersion"]
        if minimum is None or maximum is None or not minimum <= node["contractVersion"] <= maximum:
            raise ProductAdmissionError("app-projection-outside-tested-contract-range")
        baseline = contract.get("stableBaseline", {})
        if app["targetStability"] == "stable" and (app["targetBaseline"] != "1.0"
                or baseline.get("name") != "1.0" or baseline.get("contractVersion") != 19):
            raise ProductAdmissionError("app-projection-stable-baseline-unsupported")
        if app["targetBaseline"] not in {None, "1.0"}:
            raise ProductAdmissionError("app-projection-baseline-not-active")
        optional_unavailable = []
        for optional, names in ((False, app["requiredCapabilities"]), (True, app["optionalCapabilities"])):
            for name in names:
                descriptor = descriptors.get(name)
                if descriptor is None:
                    if optional:
                        optional_unavailable.append(name)
                        continue
                    raise ProductAdmissionError("app-required-capability-unknown")
                stability = descriptor.get("stability")
                if stability not in {"stable", "experimental", "deprecated"} or descriptor.get("audience") in {"internal", "operator-only"}:
                    raise ProductAdmissionError("app-required-capability-unavailable")
                if app["targetStability"] == "stable" and name not in baseline.get("capabilities", []):
                    raise ProductAdmissionError("app-capability-outside-stable-baseline")
                if stability == "experimental" and not app["experimentalCapabilitiesAccepted"]:
                    raise ProductAdmissionError("app-capability-experimental-opt-in-missing")
        results.append({"appId": app["appId"], "bundleDigest": bundle, "manifestDigest": app["manifestDigest"],
                        "projectionDigest": authenticated.digest, "contractSnapshotDigest": file_digest(contract_path),
                        "requiredCapabilities": app["requiredCapabilities"], "optionalUnavailable": optional_unavailable,
                        "status": "conservative-screening-normal-apphost-admission-required",
                        "contractVerifier": "not-executed", "rangePolicy": "strict-tested-range"})
    if node["role"] in {"candidate-sender", "candidate-recipient"} and "mail-prototype" not in {row["appId"] for row in results}:
        raise ProductAdmissionError("app-projection-mail-endpoint-subject-missing")
    return results


def verify_portable_attestations(original, package, root):
    """Verify the existing producer's exact handoff and package member attestations."""
    with _members(original.content) as source:
        handoff = root / (package.stem + "-handoff.json")
        _write(handoff, _one(source, "handoff.json"))
    coordinates = original.coordinates
    invocation = (f"https://github.com/crypta-network/cryptad/actions/runs/"
                  f"{coordinates['runId']}/attempts/{coordinates['runAttempt']}")
    environment = _environment()
    for member in (handoff, package):
        results = _gh(["attestation", "verify", str(member), "--repo", "crypta-network/cryptad",
                       "--signer-workflow", "crypta-network/cryptad/.github/workflows/stable-1.0-supply-chain.yml",
                       "--source-digest", coordinates["sourceCommit"], "--signer-digest", coordinates["sourceCommit"],
                       "--format", "json"], environment)
        if not isinstance(results, list) or not any(
                row.get("verificationResult", {}).get("signature", {}).get("certificate", {}).get("runInvocationURI") == invocation
                for row in results if isinstance(row, dict)):
            raise ProductAdmissionError("portable-original-attested-attempt-mismatch")


def authenticate_products(plan, selection, private_root):
    """Fetch each original producer at its own source; return admitted exact packaged bytes.

    Selection is private environment configuration, not a caller-provided successful receipt.
    No network call is made in unit tests; tests replace the original API transport only.
    """
    plan = validate_plan(plan)
    if plan["profile"] not in {"bounded-live", "protected-long-live"} or plan["provenanceClass"] != "production-artifact-comparison":
        raise ProductAdmissionError("product-admission-profile-unsupported")
    roles = {node["role"] for node in plan["nodes"]}
    if not isinstance(selection, dict) or set(selection) != {"schemaVersion", "roles"} or selection["schemaVersion"] != 1 or set(selection["roles"]) != roles:
        raise ProductAdmissionError("product-selection-required-roster-missing")
    root = Path(private_root)
    if root.exists() or root.is_symlink() or any(parent.is_symlink() for parent in root.parents):
        raise ProductAdmissionError("product-admission-root-must-be-new")
    root.mkdir(mode=0o700)
    rows = {}
    try:
        for node in plan["nodes"]:
            role = node["role"]
            selected = selection["roles"][role]
            if not isinstance(selected, dict) or set(selected) not in ({"rcCoordinates", "portableCoordinates"}, {"rcCoordinates", "portableCoordinates", "appProjection"}):
                raise ProductAdmissionError("product-coordinate-selection-invalid")
            if selected["rcCoordinates"].get("sourceFamily") != "stable-rc-product" or selected["portableCoordinates"].get("sourceFamily") != "first-party-release":
                raise ProductAdmissionError("product-original-authority-family-mismatch")
            rc_original = authenticate_original(selected["rcCoordinates"], root)
            rc = verify_rc_artifact(rc_original, root / (role + "-rc"))
            # SelectedRc is frozen; retain its original provenance separately without modifying it.
            from types import SimpleNamespace
            rc_view = SimpleNamespace(**rc.__dict__, _original_coordinates=rc_original.coordinates)
            portable = authenticate_original(selected["portableCoordinates"], root)
            rows[role] = verify_portable_artifact(portable, rc_view, node, root / (role + ".tar.gz"))
            verify_portable_attestations(portable, rows[role]["path"], root)
            if "appProjection" in selected:
                rows[role]["appMatrix"] = verify_app_projection(rc, node, selected["appProjection"], root)
    except ProductAdmissionError:
        raise
    except (ValueError, KeyError, TypeError, OSError, zipfile.BadZipFile) as exc:
        raise ProductAdmissionError("original-product-admission-failed") from exc
    candidate = rows["candidate-sender"]
    recipient = rows["candidate-recipient"]
    if any(candidate[key] != recipient[key] for key in ("releaseId", "buildVersion", "artifactDigest", "sourceCommit")):
        raise ProductAdmissionError("authenticated-candidate-roster-conflict")
    if int(rows["previous"]["buildVersion"]) >= int(candidate["buildVersion"]):
        raise ProductAdmissionError("authenticated-predecessor-build-not-previous")
    if "oldest" in rows and int(rows["oldest"]["buildVersion"]) > int(rows["previous"]["buildVersion"]):
        raise ProductAdmissionError("authenticated-oldest-build-order-invalid")
    return AuthenticatedProducts(_SEAL, digest(plan), rows)
