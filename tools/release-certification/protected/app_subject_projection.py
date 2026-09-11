"""Derive signed app declarations from confined original protected artifact members.

The Java exporter is the declaration authority: Python never parses app properties. This producer
retains original artifact coordinates and does not relabel a local result as an attested inventory.
PR-296's production gate remains closed until a fresh protected projection attestation is supplied.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import stat
import subprocess
import tempfile
import sys
from typing import Any
import zipfile

from original_artifact_authentication import OriginalArtifact
from original_artifact_authentication import authenticate_original, _environment, _gh, REPOSITORY
sys.modules.setdefault("app_subject_projection", sys.modules[__name__])

COHORT_FILE = Path("/etc/cryptad-certification/app-subject-cohort.json")
FIRST_PARTY = frozenset({"queue-manager", "publisher", "site-publisher", "profile-publisher",
                         "social-inbox", "feed-reader", "trust-graph"})
WORKFLOW = ".github/workflows/stable-1.0-app-subject-projection.yml"
_VERIFIED = object()


class AuthenticatedProjection:
    """Internal result of original artifact and member-attestation authentication."""
    __slots__ = ("__canonical", "digest")
    def __init__(self, inventory: dict, digest: str, _authority: object = None):
        if _authority is not _VERIFIED:
            raise ProjectionFailure("app-subject-unverified-constructor")
        self.__canonical = json.dumps(inventory, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        self.digest = digest

    def matches(self, inventory: dict) -> bool:
        return json.dumps(inventory, sort_keys=True, separators=(",", ":"), ensure_ascii=False) == self.__canonical

    def inventory(self) -> dict:
        """Return a defensive copy of exactly the authenticated member for admission consumers."""
        return json.loads(self.__canonical)

DECLARATION_FIELDS = frozenset({"schemaVersion", "kind", "appId", "appVersion", "bundleDigest",
    "bundleSize", "manifestDigest", "signedContentDigest", "signatureDigest", "publisherId",
    "publisherFingerprint", "catalogId", "catalogDigest", "catalogSignatureDigest", "catalogKeyId",
    "reviewDigest", "reviewerId", "targetStability", "targetBaseline", "minimumContractVersion",
    "maximumTestedContractVersion", "requiredCapabilities", "optionalCapabilities",
    "experimentalCapabilitiesAccepted", "submissionDigest"})


class ProjectionFailure(ValueError):
    """A fixed failure code without caller values or private diagnostics."""


def _strict_json(raw):
    def pairs(rows):
        result = {}
        for key, value in rows:
            if key in result:
                raise ProjectionFailure("app-subject-duplicate-json-key")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs)


def inventory_schema(version):
    if type(version) is not int or version not in {2, 3}:
        raise ProjectionFailure("app-subject-inventory-version-unsupported")
    return f"platform-api-1.x-app-subject-inventory-v{version}.schema.json"


def validate_declaration(value: Any) -> dict[str, Any]:
    import re
    extra = {"contractSnapshotDigest", "baselineRegistryDigest", "nativeAdmission", "catalogChannel"} if isinstance(value, dict) and value.get("schemaVersion") == 2 else set()
    if (not isinstance(value, dict) or set(value) != DECLARATION_FIELDS | extra
            or type(value["schemaVersion"]) is not int or value["schemaVersion"] not in {1, 2}
            or value["kind"] != "signed-app-subject-projection"):
        raise ProjectionFailure("app-subject-declaration-fields-invalid")
    if extra and (value["nativeAdmission"] != "accepted" or value["catalogChannel"] not in {"stable", "beta", "nightly", "deprecated"} or any(
            re.fullmatch(r"sha256:[0-9a-f]{64}", str(value[key])) is None
            for key in ("contractSnapshotDigest", "baselineRegistryDigest"))):
        raise ProjectionFailure("app-subject-native-admission-invalid")
    for key in ("bundleDigest", "manifestDigest", "signedContentDigest", "signatureDigest",
                "publisherFingerprint", "catalogDigest", "catalogSignatureDigest"):
        if not isinstance(value[key], str) or re.fullmatch(r"sha256:[0-9a-f]{64}", value[key]) is None:
            raise ProjectionFailure("app-subject-declaration-digest-invalid")
    for key in ("appId", "appVersion", "publisherId", "catalogId", "catalogKeyId"):
        if not isinstance(value[key], str) or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", value[key]) is None:
            raise ProjectionFailure("app-subject-declaration-identity-invalid")
    if value["reviewDigest"] is not None and (not isinstance(value["reviewDigest"], str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", value["reviewDigest"]) is None):
        raise ProjectionFailure("app-subject-review-digest-invalid")
    if value["submissionDigest"] is not None and (not isinstance(value["submissionDigest"], str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", value["submissionDigest"]) is None):
        raise ProjectionFailure("app-subject-submission-digest-invalid")
    if value["reviewerId"] is not None and (not isinstance(value["reviewerId"], str)
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", value["reviewerId"]) is None):
        raise ProjectionFailure("app-subject-review-identity-invalid")
    if (value["reviewDigest"] is None) != (value["reviewerId"] is None):
        raise ProjectionFailure("app-subject-review-incomplete")
    if value["targetStability"] not in {"stable", "experimental", "legacy"}:
        raise ProjectionFailure("app-subject-stability-invalid")
    if value["targetBaseline"] is not None and (not isinstance(value["targetBaseline"], str)
            or re.fullmatch(r"1\.(?:0|[1-9][0-9]*)", value["targetBaseline"]) is None):
        raise ProjectionFailure("app-subject-baseline-invalid")
    if type(value["experimentalCapabilitiesAccepted"]) is not bool:
        raise ProjectionFailure("app-subject-opt-in-invalid")
    for key in ("minimumContractVersion", "maximumTestedContractVersion"):
        if value[key] is not None and (type(value[key]) is not int or not 1 <= value[key] <= 2147483647):
            raise ProjectionFailure("app-subject-contract-invalid")
    if (value["minimumContractVersion"] is not None and value["maximumTestedContractVersion"] is not None
            and value["minimumContractVersion"] > value["maximumTestedContractVersion"]):
        raise ProjectionFailure("app-subject-contract-range-invalid")
    if type(value["bundleSize"]) is not int or not 1 <= value["bundleSize"] <= 512 * 1024 * 1024:
        raise ProjectionFailure("app-subject-bundle-size-invalid")
    for key in ("requiredCapabilities", "optionalCapabilities"):
        values = value[key]
        if (not isinstance(values, list) or len(values) > 512
                or any(not isinstance(item, str) or re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,127}", item) is None for item in values)
                or values != sorted(set(values))):
            raise ProjectionFailure("app-subject-capabilities-invalid")
    if set(value["requiredCapabilities"]) & set(value["optionalCapabilities"]):
        raise ProjectionFailure("app-subject-capability-overlap")
    if value["appId"] == "mail-prototype" and (value["targetStability"] != "experimental"
            or value["experimentalCapabilitiesAccepted"] is not True):
        raise ProjectionFailure("app-subject-mail-stability-invalid")
    return value


def selected_members(artifact: OriginalArtifact, names: dict[str, str]) -> dict[str, bytes]:
    """Inspect the entire authenticated ZIP before reading a closed bounded member selection."""
    if not names or not set(names).issubset({"catalog", "catalogSignature", "bundle", "submission"}) or len(set(names.values())) != len(names):
        raise ProjectionFailure("app-subject-member-selection-invalid")
    result = {}
    seen = set()
    total = 0
    with zipfile.ZipFile(io.BytesIO(artifact.content)) as archive:
        if len(archive.infolist()) > 4096:
            raise ProjectionFailure("app-subject-archive-count-invalid")
        for entry in archive.infolist():
            name = entry.filename
            path = PurePosixPath(name)
            if (not name or path.is_absolute() or "\\" in name or any(part in {"", ".", ".."} for part in name.rstrip("/").split("/"))
                    or name.casefold().rstrip("/") in seen or stat.S_ISLNK(entry.external_attr >> 16)
                    or entry.flag_bits & 1):
                raise ProjectionFailure("app-subject-archive-path-invalid")
            seen.add(name.casefold().rstrip("/"))
            total += entry.file_size
            if total > 512 * 1024 * 1024:
                raise ProjectionFailure("app-subject-archive-size-invalid")
        for field, name in names.items():
            entry = archive.getinfo(name)
            bound = 512 * 1024 * 1024 if field in {"bundle", "submission"} else 8 * 1024 * 1024
            if entry.is_dir() or entry.file_size > bound:
                raise ProjectionFailure("app-subject-selected-member-invalid")
            with archive.open(entry) as source:
                data = source.read(bound + 1)
            if len(data) != entry.file_size or len(data) > bound:
                raise ProjectionFailure("app-subject-selected-member-size-invalid")
            result[field] = data
    return result


def produce(artifact: OriginalArtifact, names: dict[str, str], *, exporter: Path,
            exporter_digest: str, app_id: str, catalog_key_id: str,
            catalog_keys: Path, publisher_keys: Path, reviewer_keys: Path | None,
            private_root: Path, java_home: Path | None = None,
            catalog_artifact: OriginalArtifact | None = None,
            contract_path: Path | None = None, baseline_registry_path: Path | None = None) -> dict[str, Any]:
    """Execute the pinned Java exporter against exact selected original signed artifact bytes.

    The supervisor authenticates the exporter distribution and public-key registry artifact origins.
    This function verifies its selected executable bytes before launch, preserves original source
    coordinates, and emits an explicitly unattested result until the protected job attests it.
    """
    if (contract_path is None) != (baseline_registry_path is None):
        raise ProjectionFailure("app-subject-contract-pair-required")
    if (exporter.is_symlink() or not exporter.is_file() or exporter.stat().st_size > 512 * 1024 * 1024
            or "sha256:" + hashlib.sha256(exporter.read_bytes()).hexdigest() != exporter_digest):
        raise ProjectionFailure("app-subject-exporter-identity-invalid")
    if set(names) not in ({"catalog", "catalogSignature", "bundle"}, {"catalog", "catalogSignature", "bundle", "submission"}):
        raise ProjectionFailure("app-subject-member-selection-incomplete")
    members = selected_members(artifact, {"bundle": names["bundle"]})
    if "submission" in names:
        members.update(selected_members(artifact, {"submission": names["submission"]}))
    members.update(selected_members(catalog_artifact or artifact,
                                   {key: names[key] for key in ("catalog", "catalogSignature")}))
    with tempfile.TemporaryDirectory(prefix="projection-", dir=private_root) as directory:
        root = Path(directory)
        for name, data in members.items():
            path = root / name
            path.write_bytes(data)
            os.chmod(path, 0o600)
        output = root / "projection.json"
        arguments = [str(exporter), "subject-projection", "--catalog", str(root / "catalog"),
                     "--catalog-signature", str(root / "catalogSignature"), "--bundle", str(root / "bundle"),
                     "--catalog-keys", str(catalog_keys), "--publisher-keys", str(publisher_keys),
                     "--catalog-key-id", catalog_key_id, "--app-id", app_id,
                     "--private-root", str(root), "--output", str(output)]
        if contract_path is not None:
            arguments += ["--contract", str(contract_path), "--baseline-registry", str(baseline_registry_path)]
        if reviewer_keys is not None:
            arguments += ["--reviewer-keys", str(reviewer_keys)]
        if "submission" in members:
            arguments += ["--submission-file", str(root / "submission")]
        try:
            environment = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "TMPDIR": str(root)}
            if java_home is not None:
                environment["JAVA_HOME"] = str(java_home)
                environment["PATH"] = str(java_home / "bin") + ":/usr/bin:/bin"
            from bounded_process import run as run_bounded
            run_bounded(arguments, environment=environment)
            if not output.is_file() or output.stat().st_size > 32768:
                raise ProjectionFailure("app-subject-java-verification-failed")
            declaration = validate_declaration(_strict_json(output.read_bytes()))
        except (OSError, subprocess.TimeoutExpired, ValueError):
            raise ProjectionFailure("app-subject-java-verification-failed") from None
    if (declaration["appId"] != app_id or declaration["bundleSize"] != len(members["bundle"])
            or declaration["bundleDigest"] != "sha256:" + hashlib.sha256(members["bundle"]).hexdigest()
            or declaration["catalogDigest"] != "sha256:" + hashlib.sha256(members["catalog"]).hexdigest()
            or declaration["catalogSignatureDigest"] != "sha256:" + hashlib.sha256(members["catalogSignature"]).hexdigest()):
        raise ProjectionFailure("app-subject-exported-member-mismatch")
    canonical = json.dumps(declaration, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return {"schemaVersion": 1, "kind": "app-subject-derived-observation",
            "declaration": declaration, "declarationDigest": "sha256:" + hashlib.sha256(canonical).hexdigest(),
            "originalSource": artifact.coordinates, "exporterDigest": exporter_digest,
            "producerAttestation": "not-observed", "releaseEligibility": "blocked"}


def _canonical_digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                                ensure_ascii=False).encode()).hexdigest()


def _cohort() -> dict:
    info = COHORT_FILE.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_size > 1024 * 1024:
        raise ProjectionFailure("app-subject-protected-cohort-unavailable")
    value = _strict_json(COHORT_FILE.read_bytes())
    if (not isinstance(value, dict) or set(value) != {"schemaVersion", "cohortPolicy", "releaseId",
            "sourceCommit", "authorityRoots", "toolRoot", "toolTreeDigest", "toolOriginal", "toolMember", "exporterRelativePath",
            "javaHome", "javaTreeDigest", "sources"} or value["schemaVersion"] != 1
            or value["cohortPolicy"] not in {"historical-seven", "current-eight-experimental-mail"}
            or not isinstance(value["sources"], list) or not 8 <= len(value["sources"]) <= 64):
        raise ProjectionFailure("app-subject-protected-cohort-invalid")
    first_party = set()
    ids = set()
    external = False
    for source in value["sources"]:
        fields = {"appId", "original", "originalInventory", "catalogOriginal", "members", "catalogKeyId", "catalogKeys", "catalogKeysDigest",
                  "publisherKeys", "publisherKeysDigest", "reviewerKeys", "reviewerKeysDigest",
                  "sourceAuthorityRoot", "sourceEvidenceDigest", "requiredForRelease"}
        if not isinstance(source, dict) or set(source) != fields or source["appId"] in ids or source["requiredForRelease"] is not True:
            raise ProjectionFailure("app-subject-protected-cohort-subject-invalid")
        ids.add(source["appId"])
        family = source["original"]["sourceFamily"]
        if family in {"first-party-release", "maintenance-app-products"}:
            first_party.add(source["appId"])
        elif family == "third-party-pilot":
            external = True
        elif family == "federated-catalog":
            raise ProjectionFailure("app-subject-selected-federation-provenance-not-configured")
        else:
            raise ProjectionFailure("app-subject-protected-cohort-family-invalid")
    expected = FIRST_PARTY | ({"mail-prototype"} if value["cohortPolicy"] == "current-eight-experimental-mail" else set())
    if first_party != expected or not external:
        raise ProjectionFailure("app-subject-protected-cohort-coverage-invalid")
    prospective = [source for source in value["sources"] if source["original"]["sourceFamily"] == "maintenance-app-products"]
    if prospective:
        if (len(prospective) != len(expected)
                or set(value["authorityRoots"]) != {"maintenanceAppProducts", "thirdPartyPilot"}
                or any(source["originalInventory"] != source["original"]
                       or source["catalogOriginal"] is not None
                       or source["sourceAuthorityRoot"] != value["authorityRoots"]["maintenanceAppProducts"]
                       or source["sourceEvidenceDigest"] != source["sourceAuthorityRoot"] for source in prospective)
                or len({_canonical_digest(source["original"]) for source in prospective}) != 1):
            raise ProjectionFailure("app-subject-prospective-owner-roots-invalid")
    return value


def tree_digest(root: Path) -> str:
    """Commit every regular file, executable bit and relative name in a complete tool/JDK tree."""
    if root.is_symlink() or not root.is_dir():
        raise ProjectionFailure("app-subject-tool-tree-invalid")
    rows = []
    total = 0
    for path in sorted(root.rglob("*")):
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            continue
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ProjectionFailure("app-subject-tool-tree-link-invalid")
        total += info.st_size
        if len(rows) >= 32768 or total > 4 * 1024**3:
            raise ProjectionFailure("app-subject-tool-tree-budget-exceeded")
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            while chunk := stream.read(65536): digest.update(chunk)
        rows.append([path.relative_to(root).as_posix(), info.st_size, bool(info.st_mode & 0o111), digest.hexdigest()])
    return _canonical_digest(rows)


def tool_archive_digest(content: bytes) -> str:
    """Compare complete distZip payload without extracting or executing any selected member."""
    rows, names, roots = [], set(), set()
    total = 0
    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        if not 1 <= len(archive.infolist()) <= 32768:
            raise ProjectionFailure("app-subject-tool-archive-budget")
        for member in archive.infolist():
            name = member.filename.rstrip("/")
            parts = name.split("/")
            mode = member.external_attr >> 16
            if (not name or name.startswith("/") or "\\" in name or ":" in name
                    or any(part in {"", ".", ".."} for part in parts) or name.casefold() in names
                    or member.flag_bits & 1 or stat.S_ISLNK(mode)
                    or (mode and not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)))
                    or any(ord(c) < 32 for c in name)):
                raise ProjectionFailure("app-subject-tool-archive-unsafe")
            names.add(name.casefold())
            roots.add(parts[0])
            if member.is_dir():
                continue
            if len(parts) < 2:
                raise ProjectionFailure("app-subject-tool-archive-root-invalid")
            total += member.file_size
            if total > 512 * 1024 * 1024:
                raise ProjectionFailure("app-subject-tool-archive-budget")
            rows.append(["/".join(parts[1:]), member.file_size, bool(mode & 0o111),
                         hashlib.sha256(archive.read(member)).hexdigest()])
    if len(roots) != 1 or not rows:
        raise ProjectionFailure("app-subject-tool-archive-root-invalid")
    return _canonical_digest(sorted(rows))


def authenticate_tool_tree(cohort: dict, tool_root: Path, private_root: Path) -> None:
    coordinates = cohort["toolOriginal"]
    if coordinates.get("sourceFamily") != "projection-tools" or coordinates.get("sourceCommit") != os.environ.get("GITHUB_SHA"):
        raise ProjectionFailure("app-subject-tool-producer-source-mismatch")
    original = authenticate_original(coordinates, private_root)
    content = selected_members(original, {"bundle": cohort["toolMember"]})["bundle"]
    with tempfile.TemporaryDirectory(prefix="tool-subject-", dir=private_root) as directory:
        member = Path(directory) / "projection-tools.zip"
        member.write_bytes(content)
        results = _gh(["attestation", "verify", str(member), "--repo", REPOSITORY,
                       "--signer-workflow", REPOSITORY + "/" + WORKFLOW,
                       "--source-digest", coordinates["sourceCommit"], "--signer-digest", coordinates["sourceCommit"],
                       "--format", "json"], _environment())
        invocation = (f"https://github.com/{REPOSITORY}/actions/runs/{coordinates['runId']}"
                      f"/attempts/{coordinates['runAttempt']}")
        if not isinstance(results, list) or not any(
                row.get("verificationResult", {}).get("signature", {}).get("certificate", {}).get("runInvocationURI") == invocation
                for row in results if isinstance(row, dict)):
            raise ProjectionFailure("app-subject-tool-attested-attempt-mismatch")
    if tool_archive_digest(content) != cohort["toolTreeDigest"] or tree_digest(tool_root) != cohort["toolTreeDigest"]:
        raise ProjectionFailure("app-subject-tool-installed-bytes-substituted")


def _public_cohort(value: dict) -> dict:
    return {"cohortPolicy": value["cohortPolicy"], "releaseId": value["releaseId"],
            "sourceCommit": value["sourceCommit"], "authorityRoots": value["authorityRoots"],
            "toolTreeDigest": value["toolTreeDigest"], "javaTreeDigest": value["javaTreeDigest"],
            "toolOriginal": value["toolOriginal"], "toolMember": value["toolMember"],
            "sources": [{key: source[key] for key in sorted(source)
                         if key not in {"catalogKeys", "publisherKeys", "reviewerKeys"}}
                        for source in value["sources"]]}


def _artifact_json(artifact: OriginalArtifact, name: str) -> dict:
    # Reuse confinement for the whole original archive before reading a selected JSON member.
    content = selected_members(artifact, {"catalog": name})["catalog"]
    if len(content) > 1024 * 1024:
        raise ProjectionFailure("app-subject-upstream-inventory-budget")
    value = _strict_json(content)
    if not isinstance(value, dict):
        raise ProjectionFailure("app-subject-upstream-inventory-invalid")
    return value


def _verify_maintenance_handoff(source: dict, declaration: dict, artifact: OriginalArtifact,
                                private_root: Path) -> None:
    """Authenticate prefreeze app product bytes without claiming an independent rebuild."""
    name = "maintenance-app-subject-handoff.json"
    if (source["originalInventory"] != artifact.coordinates or source["original"] != artifact.coordinates
            or source["catalogOriginal"] is not None):
        raise ProjectionFailure("app-subject-maintenance-origin-mismatch")
    raw = selected_members(artifact, {"catalog": name})["catalog"]
    expected_digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    if (len(raw) > 1024 * 1024 or source["sourceAuthorityRoot"] != expected_digest
            or source["sourceEvidenceDigest"] != expected_digest):
        raise ProjectionFailure("app-subject-maintenance-handoff-substitution")
    value = _strict_json(raw)
    from cryptad_certification.schema_validation import validate_schema
    if validate_schema(value, "maintenance-app-subject-handoff-v1.schema.json"):
        raise ProjectionFailure("app-subject-maintenance-handoff-schema-invalid")
    fields = {"schemaVersion", "kind", "sourceCommit", "releaseId", "buildVersion", "generatedAt",
              "cohortPolicy", "producer", "subjects", "members"}
    producer = {"repository": REPOSITORY,
        "workflowPath": ".github/workflows/stable-1.0-maintenance-release.yml",
        "workflowSourceCommit": artifact.coordinates["sourceCommit"],
        "runId": artifact.coordinates["runId"], "runAttempt": artifact.coordinates["runAttempt"],
        "jobName": "Build and authenticate prospective maintenance app products"}
    import re
    import datetime
    if (not isinstance(value, dict) or set(value) != fields or type(value["schemaVersion"]) is not int
            or value["schemaVersion"] != 1 or value["kind"] != "maintenance-app-subject-handoff"
            or value["producer"] != producer
            or re.fullmatch(r"[0-9a-f]{40}", str(value["sourceCommit"])) is None
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", str(value["releaseId"])) is None
            or not isinstance(value["buildVersion"], str) or re.fullmatch(r"[1-9][0-9]*", value["buildVersion"]) is None
            or value["cohortPolicy"] not in {"historical-seven", "current-eight-experimental-mail"}):
        raise ProjectionFailure("app-subject-maintenance-handoff-fields-invalid")
    try:
        observed = datetime.datetime.fromisoformat(value["generatedAt"].replace("Z", "+00:00"))
        if observed.tzinfo is None or (artifact.job_completed_at is not None
                and observed > datetime.datetime.fromisoformat(artifact.job_completed_at.replace("Z", "+00:00"))):
            raise ValueError()
    except (ValueError, TypeError, AttributeError):
        raise ProjectionFailure("app-subject-maintenance-handoff-time-invalid") from None
    expected_ids = FIRST_PARTY | ({"mail-prototype"} if value["cohortPolicy"] == "current-eight-experimental-mail" else set())
    if (not isinstance(value["subjects"], list) or len(value["subjects"]) != len(expected_ids)
            or not isinstance(value["members"], list) or not 3 <= len(value["members"]) <= 32):
        raise ProjectionFailure("app-subject-maintenance-handoff-roster-invalid")
    subjects, referenced = {}, set()
    for subject in value["subjects"]:
        if (not isinstance(subject, dict) or set(subject) != {"appId", "members", "signedProjection"}
                or subject["appId"] in subjects or not isinstance(subject["members"], dict)
                or set(subject["members"]) != {"catalog", "catalogSignature", "bundle"}
                or len(set(subject["members"].values())) != 3):
            raise ProjectionFailure("app-subject-maintenance-handoff-subject-invalid")
        signed = validate_declaration(subject["signedProjection"])
        if signed["schemaVersion"] != 1 or signed["appId"] != subject["appId"]:
            raise ProjectionFailure("app-subject-maintenance-handoff-declaration-invalid")
        subjects[subject["appId"]] = subject
        referenced.update(subject["members"].values())
    if set(subjects) != expected_ids:
        raise ProjectionFailure("app-subject-maintenance-handoff-roster-invalid")
    inventory = {}
    for member in value["members"]:
        if (not isinstance(member, dict) or set(member) != {"fileName", "digest", "sizeBytes"}
                or not isinstance(member["fileName"], str) or member["fileName"] in inventory
                or type(member["sizeBytes"]) is not int or not 1 <= member["sizeBytes"] <= 512 * 1024 * 1024
                or re.fullmatch(r"sha256:[0-9a-f]{64}", str(member["digest"])) is None):
            raise ProjectionFailure("app-subject-maintenance-member-invalid")
        inventory[member["fileName"]] = member
    if set(inventory) != referenced or name in referenced:
        raise ProjectionFailure("app-subject-maintenance-member-roster-invalid")
    exact = {name: raw}
    with zipfile.ZipFile(io.BytesIO(artifact.content)) as archive:
        if {entry.filename for entry in archive.infolist() if not entry.is_dir()} != referenced | {name}:
            raise ProjectionFailure("app-subject-maintenance-unbound-member")
        for member_name, member in inventory.items():
            entry = archive.getinfo(member_name)
            if entry.is_dir() or entry.file_size != member["sizeBytes"]:
                raise ProjectionFailure("app-subject-maintenance-member-substituted")
            payload = archive.read(entry)
            if "sha256:" + hashlib.sha256(payload).hexdigest() != member["digest"]:
                raise ProjectionFailure("app-subject-maintenance-member-substituted")
            exact[member_name] = payload
    for subject in subjects.values():
        signed = subject["signedProjection"]
        members = subject["members"]
        if (inventory[members["bundle"]]["digest"] != signed["bundleDigest"]
                or inventory[members["bundle"]]["sizeBytes"] != signed["bundleSize"]
                or inventory[members["catalog"]]["digest"] != signed["catalogDigest"]
                or inventory[members["catalogSignature"]]["digest"] != signed["catalogSignatureDigest"]):
            raise ProjectionFailure("app-subject-maintenance-declared-member-substitution")
    selected = subjects.get(declaration["appId"])
    legacy = {key: item for key, item in declaration.items() if key not in
              {"contractSnapshotDigest", "baselineRegistryDigest", "nativeAdmission", "catalogChannel"}}
    legacy["schemaVersion"] = 1
    if selected is None or selected["members"] != source["members"] or selected["signedProjection"] != legacy:
        raise ProjectionFailure("app-subject-maintenance-selected-subject-substitution")
    invocation = (f"https://github.com/{REPOSITORY}/actions/runs/{artifact.coordinates['runId']}"
                  f"/attempts/{artifact.coordinates['runAttempt']}")
    with tempfile.TemporaryDirectory(prefix="maintenance-subject-attest-", dir=private_root) as directory:
        for index, (member_name, payload) in enumerate(sorted(exact.items())):
            member = Path(directory) / str(index)
            member.write_bytes(payload)
            proofs = _gh(["attestation", "verify", str(member), "--repo", REPOSITORY,
                "--signer-workflow", REPOSITORY + "/" + producer["workflowPath"],
                "--source-digest", artifact.coordinates["sourceCommit"],
                "--signer-digest", artifact.coordinates["sourceCommit"], "--format", "json"], _environment())
            if not isinstance(proofs, list) or not any(
                    proof.get("verificationResult", {}).get("signature", {}).get("certificate", {}).get("runInvocationURI") == invocation
                    for proof in proofs if isinstance(proof, dict)):
                raise ProjectionFailure("app-subject-maintenance-member-attested-attempt-mismatch")


def verify_upstream_subject(source: dict, declaration: dict, artifact: OriginalArtifact,
                            private_root: Path) -> None:
    """Match derived signed bytes to the original selected upstream subject, never caller fields."""
    family = source["original"]["sourceFamily"]
    if family == "maintenance-app-products":
        _verify_maintenance_handoff(source, declaration, artifact, private_root)
        return
    expected = {"first-party-release": "first-party-inventory", "third-party-pilot": "third-party-inventory"}
    if source["originalInventory"].get("sourceFamily") != expected.get(family):
        raise ProjectionFailure("app-subject-upstream-inventory-family-mismatch")
    inventory_artifact = authenticate_original(source["originalInventory"], private_root)
    if family == "first-party-release":
        summary = _artifact_json(inventory_artifact, "stable-1.0-independent-reproducibility-summary.json")
        inventory = _artifact_json(inventory_artifact, "stable-1.0-release-subject-inventory.json")
        if (summary.get("summaryDigest") != source["sourceAuthorityRoot"]
                or summary.get("subjectInventoryDigest") != source["sourceEvidenceDigest"]
                or inventory.get("subjectInventoryDigest") != source["sourceEvidenceDigest"]
                or inventory.get("sourceCommit") != artifact.coordinates["sourceCommit"]):
            raise ProjectionFailure("app-subject-upstream-root-mismatch")
        rows = [row for row in inventory.get("subjects", []) if row.get("subjectClass") == "first-party-app"
                and row.get("app", {}).get("appId") == declaration["appId"]]
        if len(rows) != 1:
            raise ProjectionFailure("app-subject-upstream-membership-mismatch")
        row, app = rows[0], rows[0]["app"]
        if (row.get("digest") != declaration["bundleDigest"] or row.get("size") != declaration["bundleSize"]
                or app.get("version") != declaration["appVersion"]
                or app.get("manifestDigest") != declaration["manifestDigest"]
                or app.get("bundleSignatureDigest") != declaration["signatureDigest"]
                or app.get("reviewReceiptDigest") != declaration["reviewDigest"]):
            raise ProjectionFailure("app-subject-upstream-byte-substitution")
    elif family == "third-party-pilot":
        summary = _artifact_json(inventory_artifact, "stable-1.0-third-party-app-pilot-summary.json")
        execution = _artifact_json(artifact, "execution.json")
        roots = [row for row in summary.get("evidence", []) if row.get("id") == "third-party-pilot.external-developer"]
        app = summary.get("externalApp", {})
        if (summary.get("summaryDigest") != source["sourceAuthorityRoot"] or len(roots) != 1
                or roots[0].get("digest") != source["sourceEvidenceDigest"] or roots[0].get("status") != "pass"
                or app.get("appId") != declaration["appId"]
                or app.get("publisherKeyId") != declaration["publisherId"]
                or app.get("publisherFingerprint") != declaration["publisherFingerprint"]
                or execution.get("externalApp", {}).get("appId") != declaration["appId"]):
            raise ProjectionFailure("app-subject-external-upstream-mismatch")
        rows = [row for row in execution.get("cohort", []) if row.get("bundleDigest") == declaration["bundleDigest"]]
        if (len(rows) != 1 or rows[0].get("appVersion") != declaration["appVersion"]
                or rows[0].get("submissionDigest") != declaration["submissionDigest"]
                or rows[0].get("bundleSignatureDigest") != declaration["signatureDigest"]
                or rows[0].get("expectedDecision") not in {"reviewed", "caution"}):
            raise ProjectionFailure("app-subject-external-submission-substitution")
    else:
        raise ProjectionFailure("app-subject-selected-federation-provenance-not-configured")


def produce_cohort(private_root: Path, output: Path) -> dict:
    """Produce the protected environment-selected cohort with fresh artifact-derived fields."""
    cohort = _cohort()
    if os.environ.get("GITHUB_WORKFLOW_REF") != f"{REPOSITORY}/{WORKFLOW}@refs/heads/develop":
        raise ProjectionFailure("app-subject-producer-workflow-mismatch")
    tool_root = Path(cohort["toolRoot"])
    java_home = Path(cohort["javaHome"])
    if tree_digest(tool_root) != cohort["toolTreeDigest"] or tree_digest(java_home) != cohort["javaTreeDigest"]:
        raise ProjectionFailure("app-subject-runtime-tree-substituted")
    authenticate_tool_tree(cohort, tool_root, private_root)
    exporter = tool_root / cohort["exporterRelativePath"]
    if exporter.resolve().is_relative_to(tool_root.resolve()) is False:
        raise ProjectionFailure("app-subject-exporter-outside-tree")
    exporter_digest = "sha256:" + hashlib.sha256(exporter.read_bytes()).hexdigest()
    rows = []
    for source in sorted(cohort["sources"], key=lambda item: item["appId"]):
        for key in ("catalogKeys", "publisherKeys", "reviewerKeys"):
            if source[key] is not None:
                selected = Path(source[key])
                if selected.is_symlink() or "sha256:" + hashlib.sha256(selected.read_bytes()).hexdigest() != source[key + "Digest"]:
                    raise ProjectionFailure("app-subject-trust-registry-substituted")
        artifact = authenticate_original(source["original"], private_root)
        catalog_artifact = None
        if source["catalogOriginal"] is not None:
            if source["catalogOriginal"].get("sourceFamily") != "catalog-source":
                raise ProjectionFailure("app-subject-catalog-source-invalid")
            catalog_artifact = authenticate_original(source["catalogOriginal"], private_root)
        result = produce(artifact, source["members"], exporter=exporter, exporter_digest=exporter_digest,
                         app_id=source["appId"], catalog_key_id=source["catalogKeyId"],
                         catalog_keys=Path(source["catalogKeys"]), publisher_keys=Path(source["publisherKeys"]),
                         reviewer_keys=Path(source["reviewerKeys"]) if source["reviewerKeys"] else None,
                         private_root=private_root, java_home=java_home, catalog_artifact=catalog_artifact)
        declaration = result["declaration"]
        if source["original"]["sourceFamily"] == "third-party-pilot" and (declaration["reviewDigest"] is None or declaration["submissionDigest"] is None):
            raise ProjectionFailure("app-subject-external-review-missing")
        verify_upstream_subject(source, declaration, artifact, private_root)
        keys = {"appId", "appVersion", "bundleDigest", "manifestDigest", "publisherId", "catalogId",
                "reviewDigest", "targetStability", "targetBaseline", "minimumContractVersion",
                "maximumTestedContractVersion", "requiredCapabilities", "optionalCapabilities",
                "experimentalCapabilitiesAccepted"}
        row = {key: declaration[key] for key in keys}
        row.update({"sourceAuthority": source["original"]["sourceFamily"],
                    "sourceAuthorityRoot": source["sourceAuthorityRoot"], "sourceEvidenceDigest": source["sourceEvidenceDigest"],
                    "fixtureOnly": False, "requiredForRelease": True,
                    "signedProjection": declaration, "originalSource": artifact.coordinates,
                    "originalCatalogSource": catalog_artifact.coordinates if catalog_artifact else None,
                    "originalInventorySource": source["originalInventory"]})
        row["subjectDigest"] = "sha256:" + "0" * 64
        row["subjectDigest"] = _canonical_digest(row)
        rows.append(row)
    version = 3 if any(row["sourceAuthority"] == "maintenance-app-products" for row in rows) else 2
    inventory = {"schemaVersion": version, "kind": "platform-api-1.x-app-subject-inventory",
                 "releaseId": cohort["releaseId"], "sourceCommit": cohort["sourceCommit"],
                 "authorityRoots": cohort["authorityRoots"], "requiredAppIds": sorted(row["appId"] for row in rows),
                 "subjects": rows, "fixtureOnly": False, "cohortPolicy": cohort["cohortPolicy"],
                 "cohortDigest": _canonical_digest(_public_cohort(cohort)),
                 "producer": {"sourceCommit": os.environ["GITHUB_SHA"], "workflowPath": WORKFLOW,
                              "environment": "stable-1-0-app-subject-projection",
                              "runId": int(os.environ["GITHUB_RUN_ID"]), "runAttempt": int(os.environ["GITHUB_RUN_ATTEMPT"])}}
    inventory["inventoryDigest"] = "sha256:" + "0" * 64
    inventory["inventoryDigest"] = _canonical_digest(inventory)
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from cryptad_certification.redaction import scan_value
    from cryptad_certification.schema_validation import validate_schema
    if (validate_schema(inventory, inventory_schema(inventory.get("schemaVersion")))
            or scan_value(inventory)):
        raise ProjectionFailure("app-subject-public-inventory-rejected")
    with output.open("x", encoding="utf-8") as stream:
        json.dump(inventory, stream, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        stream.write("\n")
    return inventory


def authenticate_inventory(coordinates: dict, private_root: Path,
                           expected_cohort_digest: str | None = None) -> AuthenticatedProjection:
    """Authenticate the original projection job and exact attested inventory member."""
    if coordinates.get("sourceFamily") != "app-subject-projection":
        raise ProjectionFailure("app-subject-producer-family-invalid")
    artifact = authenticate_original(coordinates, private_root)
    with zipfile.ZipFile(io.BytesIO(artifact.content)) as archive:
        if archive.namelist() != ["platform-api-1.x-app-subject-inventory.json"]:
            raise ProjectionFailure("app-subject-producer-artifact-members-invalid")
        entry = archive.infolist()[0]
        if entry.file_size > 1024 * 1024 or stat.S_ISLNK(entry.external_attr >> 16):
            raise ProjectionFailure("app-subject-producer-inventory-invalid")
        raw = archive.read(entry)
    with tempfile.TemporaryDirectory(prefix="verify-projection-", dir=private_root) as directory:
        member = Path(directory) / "platform-api-1.x-app-subject-inventory.json"
        member.write_bytes(raw)
        verified = _gh(["attestation", "verify", str(member), "--repo", REPOSITORY,
             "--signer-workflow", REPOSITORY + "/" + WORKFLOW,
             "--signer-digest", coordinates["sourceCommit"], "--source-digest", coordinates["sourceCommit"],
             "--format", "json"], _environment())
        expected_invocation = (f"https://github.com/{REPOSITORY}/actions/runs/"
                               f"{coordinates['runId']}/attempts/{coordinates['runAttempt']}")
        if not isinstance(verified, list) or not any(
                row.get("verificationResult", {}).get("signature", {}).get("certificate", {}).get("runInvocationURI")
                == expected_invocation for row in verified):
            raise ProjectionFailure("app-subject-attested-attempt-mismatch")
    inventory = _strict_json(raw)
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from cryptad_certification.schema_validation import validate_schema
    from cryptad_certification.redaction import scan_value
    from original_artifact_authentication import validate_coordinates
    if validate_schema(inventory, inventory_schema(inventory.get("schemaVersion"))) or scan_value(inventory):
        raise ProjectionFailure("app-subject-attested-schema-invalid")
    for subject in inventory["subjects"]:
        validate_declaration(subject["signedProjection"])
        validate_coordinates(subject["originalSource"])
        validate_coordinates(subject["originalInventorySource"])
        if subject["originalCatalogSource"] is not None:
            validate_coordinates(subject["originalCatalogSource"])
    producer = inventory.get("producer", {})
    if expected_cohort_digest is None:
        expected_cohort_digest = _canonical_digest(_public_cohort(_cohort()))
    if (producer.get("runId") != coordinates["runId"] or producer.get("runAttempt") != coordinates["runAttempt"]
            or producer.get("sourceCommit") != coordinates["sourceCommit"]
            or producer.get("workflowPath") != WORKFLOW
            or inventory.get("cohortDigest") != expected_cohort_digest):
        raise ProjectionFailure("app-subject-producer-substitution")
    return AuthenticatedProjection(inventory, "sha256:" + hashlib.sha256(raw).hexdigest(), _VERIFIED)


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("produce", "verify-matrix"))
    parser.add_argument("--private-root", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--coordinates", type=Path)
    parser.add_argument("--execution-contract", type=Path)
    parser.add_argument("--evidence-dir", type=Path)
    parser.add_argument("--out-dir", type=Path)
    parser.add_argument("--expected-cohort-digest")
    parser.add_argument("--verification-mode", choices=("verify-app-matrix", "verify-runtime", "closeout"),
                        default="verify-app-matrix")
    args = parser.parse_args()
    try:
        if args.mode == "produce":
            if args.output is None: raise ProjectionFailure("app-subject-output-required")
            produce_cohort(args.private_root, args.output)
            return 0
        if any(value is None for value in (args.coordinates, args.execution_contract, args.evidence_dir, args.out_dir)):
            raise ProjectionFailure("app-subject-verification-input-required")
        authenticated = authenticate_inventory(json.loads(args.coordinates.read_bytes()), args.private_root,
                                                 args.expected_cohort_digest)
        import sys
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        from cryptad_certification.engines import stable_platform_api_1x
        return stable_platform_api_1x.run(Path.cwd(), args.execution_contract,
                                         args.verification_mode, args.out_dir, args.evidence_dir,
                                         authenticated_projection=authenticated)
    except (ProjectionFailure, OSError, ValueError, KeyError):
        print("app_subject_projection_failed", file=__import__("sys").stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
