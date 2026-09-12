"""Prospective exact-package runtime metadata owned by the maintenance freeze producer.

Validation is offline and never executes a product or authenticates a remote input. Production
explicitly authenticates the environment-selected original app cohort, observes the selected
package with a fixed Java entry point, and reruns native signed app admission before sealing.
No serialized field creates an authenticated capability.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tarfile
import tempfile
import zipfile
from datetime import datetime, timezone

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cryptad_certification.engines import stable_1_0_maintenance_core as maintenance
from cryptad_certification.schema_validation import validate_schema

MANIFEST_FILE = "runtime-subjects.json"
MEMBER_NAMES = {"snapshot": "snapshot.json", "registry": "baseline-registry.json",
                "inventory": "projection-inventory.json", "nativeAdmissions": "native-admissions.json"}
STABLE_DEFINITION = "f94a06f06e929e655c4481bea92d02b90fbcac7b28f3628f5538dd073d5c71d6"
FIRST_PARTY = frozenset({"queue-manager", "publisher", "site-publisher", "profile-publisher",
                         "social-inbox", "feed-reader", "trust-graph"})
FIELDS = frozenset({"schemaVersion", "kind", "provenance", "releaseId", "buildVersion", "sourceCommit",
    "generatedAt", "portable", "executable", "contractVersion", "contractSnapshotDigest",
    "contractSemanticDigest", "baselineRegistryDigest", "baselineName", "baselineContractVersion",
    "stableBaselineDigest", "shippedAppIds", "requiredAppIds", "shippedCohortDigest",
    "experimentCohortDigest", "cohortPolicy", "projectionInventoryDigest", "projectionOrigin",
    "toolTreeDigest", "javaTreeDigest", "rolePolicy", "members"})


class RuntimeMetadataError(ValueError):
    """Closed diagnostics never include private input paths or content."""


def digest_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def semantic_digest(value) -> str:
    return digest_bytes(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def canonical_bytes(value) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def read_json(raw: bytes):
    def pairs(rows):
        result = {}
        for key, value in rows:
            if key in result:
                raise RuntimeMetadataError("runtime-metadata-duplicate-json-key")
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=pairs)
    except (ValueError, UnicodeError):
        raise RuntimeMetadataError("runtime-metadata-json-invalid") from None


def _regular(path: Path, limit: int = 8 * 1024 * 1024) -> bytes:
    if any(parent.is_symlink() for parent in [path, *path.parents]):
        raise RuntimeMetadataError("runtime-metadata-input-link")
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > limit:
        raise RuntimeMetadataError("runtime-metadata-input-unsafe")
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    after = path.stat()
    stable = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
    if len(raw) != info.st_size or any(getattr(after, key) != getattr(info, key) for key in stable):
        raise RuntimeMetadataError("runtime-metadata-input-changed")
    return raw


def identity(path: Path, limit: int = 8 * 1024 * 1024) -> dict:
    raw = _regular(path, limit)
    return {"fileName": path.name, "digest": digest_bytes(raw), "sizeBytes": len(raw)}


def role_policy(cohort_policy: str) -> dict:
    apps = ["feed-reader", "site-publisher"]
    current = sorted(apps + (["mail-prototype"] if cohort_policy == "current-eight-experimental-mail" else []))
    return {"candidate-sender": current, "candidate-recipient": current,
            "previous": apps, "oldest": apps, "relay-no-apps": []}


def _member(root: Path, row: dict, name: str) -> bytes:
    if not isinstance(row, dict) or set(row) != {"fileName", "digest", "sizeBytes"} or row["fileName"] != name:
        raise RuntimeMetadataError("runtime-metadata-member-identity-invalid")
    raw = _regular(root / name)
    if row != {"fileName": name, "digest": digest_bytes(raw), "sizeBytes": len(raw)}:
        raise RuntimeMetadataError("runtime-metadata-member-substituted")
    return raw


def validate_runtime_metadata(freeze: dict, runtime_root: Path, *, package_path: Path | None = None) -> dict:
    """Reopen a closed v2 frozen metadata tree; authenticate neither producer nor JSON flags."""
    try:
        return _validate_runtime_metadata(freeze, Path(runtime_root), package_path)
    except RuntimeMetadataError:
        raise
    except (KeyError, TypeError, ValueError, OSError):
        raise RuntimeMetadataError("runtime-metadata-binding-invalid") from None


def _validate_runtime_metadata(freeze: dict, root: Path, package_path: Path | None = None) -> dict:
    from app_subject_projection import validate_declaration, inventory_schema
    if freeze.get("schemaVersion") != 2:
        raise RuntimeMetadataError("runtime-metadata-absent-historical-freeze")
    raw = _member(root, freeze["runtimeMetadata"], MANIFEST_FILE)
    value = read_json(raw)
    if (not isinstance(value, dict) or set(value) != FIELDS or type(value["schemaVersion"]) is not int or value["schemaVersion"] != 1
            or value["kind"] != "maintenance-runtime-subjects"
            or value["provenance"] != "frozen-with-original-release"
            or value["releaseId"] != freeze["releaseId"] or value["buildVersion"] != freeze["buildVersion"]
            or value["sourceCommit"] != freeze["source"]["commit"]
            or set(value["members"]) != set(MEMBER_NAMES)):
        raise RuntimeMetadataError("runtime-metadata-manifest-fields-invalid")
    generated = maintenance.parse_timestamp(value["generatedAt"])
    frozen = maintenance.parse_timestamp(freeze["frozenAt"])
    if generated is None or frozen is None or generated > frozen:
        raise RuntimeMetadataError("runtime-metadata-post-freeze")
    if {entry.name for entry in root.iterdir()} != {MANIFEST_FILE, *MEMBER_NAMES.values()}:
        raise RuntimeMetadataError("runtime-metadata-member-set-invalid")
    contents = {key: _member(root, value["members"][key], name) for key, name in MEMBER_NAMES.items()}
    contract = read_json(contents["snapshot"])["contract"]
    registry = read_json(contents["registry"])
    if validate_schema(registry, "platform-api-1.x-baseline-registry-v1.schema.json"):
        raise RuntimeMetadataError("runtime-metadata-registry-schema-invalid")
    stable = [row for row in registry["baselineRegistry"]["definitions"] if row["id"] == "1.0"]
    if (len(stable) != 1 or stable[0]["definitionDigest"] != STABLE_DEFINITION
            or stable[0]["firstCompleteContractVersion"] != 19
            or value["baselineName"] != "1.0" or value["baselineContractVersion"] != 19
            or value["stableBaselineDigest"] != "sha256:" + STABLE_DEFINITION
            or type(value["contractVersion"]) is not int or value["contractVersion"] != contract["contractVersion"]
            or value["contractSnapshotDigest"] != digest_bytes(contents["snapshot"])
            or value["contractSemanticDigest"] != semantic_digest(contract)
            or value["baselineRegistryDigest"] != digest_bytes(contents["registry"])):
        raise RuntimeMetadataError("runtime-metadata-contract-binding-invalid")
    products = [row for row in freeze["assets"] if row["role"] == "product"]
    if len(products) != 1 or value["portable"] != {key: products[0][key] for key in ("fileName", "digest", "sizeBytes")}:
        raise RuntimeMetadataError("runtime-metadata-portable-binding-invalid")
    executable = value["executable"]
    if (set(executable) != {"member", "digest", "sizeBytes"}
            or executable["member"] != "lib/cryptad.jar"
            or re.fullmatch(r"sha256:[0-9a-f]{64}", str(executable["digest"])) is None
            or type(executable["sizeBytes"]) is not int or not 0 < executable["sizeBytes"] <= 256 * 1024 * 1024):
        raise RuntimeMetadataError("runtime-metadata-executable-identity-invalid")
    inventory = read_json(contents["inventory"])
    if validate_schema(inventory, inventory_schema(inventory.get("schemaVersion"))):
        raise RuntimeMetadataError("runtime-metadata-inventory-schema-invalid")
    from app_subject_projection import validate_federation_inventory, content_declaration
    validate_federation_inventory(inventory)
    if (inventory["releaseId"] != value["releaseId"] or inventory["sourceCommit"] != value["sourceCommit"]
            or value["projectionInventoryDigest"] != digest_bytes(contents["inventory"])
            or value["experimentCohortDigest"] != inventory["cohortDigest"]
            or value["requiredAppIds"] != inventory["requiredAppIds"]
            or value["cohortPolicy"] != inventory["cohortPolicy"]
            or value["shippedAppIds"] != sorted(FIRST_PARTY)
            or value["rolePolicy"] != role_policy(value["cohortPolicy"])):
        raise RuntimeMetadataError("runtime-metadata-cohort-binding-invalid")
    from original_artifact_authentication import validate_coordinates
    validate_coordinates(value["projectionOrigin"])
    if value["projectionOrigin"]["sourceFamily"] != "app-subject-projection":
        raise RuntimeMetadataError("runtime-metadata-projection-origin-invalid")
    subjects = {row["appId"]: row["signedProjection"] for row in inventory["subjects"]}
    if len(subjects) != len(inventory["subjects"]) or sorted(subjects) != inventory["requiredAppIds"]:
        raise RuntimeMetadataError("runtime-metadata-subject-set-invalid")
    declarations = read_json(contents["nativeAdmissions"])
    if not isinstance(declarations, list) or sorted(row["appId"] for row in declarations) != sorted(subjects):
        raise RuntimeMetadataError("runtime-metadata-native-set-invalid")
    catalog = next(row for row in freeze["assets"] if row["role"] == "stable-catalog")
    signature = next(row for row in freeze["assets"] if row["role"] == "stable-catalog-signature")
    for row in declarations:
        validate_declaration(row)
        original = subjects[row["appId"]]
        projection = content_declaration(row)
        selected = [item for item in inventory.get("selectedFederation", []) if item["appId"] == row["appId"]]
        if selected and (row["schemaVersion"] != 3 or row["federationSelection"] != selected[0]["nativeProjection"]["federationSelection"]):
            raise RuntimeMetadataError("runtime-metadata-federation-selection-substituted")
        if (row["schemaVersion"] != (3 if selected else 2) or projection != original
                or row["contractSnapshotDigest"] != value["contractSnapshotDigest"]
                or row["baselineRegistryDigest"] != value["baselineRegistryDigest"]
                or value["contractVersion"] > row["maximumTestedContractVersion"]):
            raise RuntimeMetadataError("runtime-metadata-native-admission-binding-invalid")
        if (row["catalogChannel"] == "deprecated"
                or row["appId"] in FIRST_PARTY and row["catalogChannel"] != "stable"
                or row["appId"] == "mail-prototype" and (row["catalogChannel"] not in {"beta", "nightly"}
                    or value["cohortPolicy"] != "current-eight-experimental-mail")):
            raise RuntimeMetadataError("runtime-metadata-policy-channel-invalid")
        if row["appId"] in FIRST_PARTY and (row["catalogDigest"] != catalog["digest"]
                or row["catalogSignatureDigest"] != signature["digest"]):
            raise RuntimeMetadataError("runtime-metadata-shipped-catalog-substituted")
    if value["shippedCohortDigest"] != semantic_digest([subjects[key] for key in sorted(FIRST_PARTY)]):
        raise RuntimeMetadataError("runtime-metadata-shipped-cohort-invalid")
    package = root.parent / value["portable"]["fileName"]
    if not package.exists():
        package = root.parent / "assets" / value["portable"]["fileName"]
    verify_package_identity(package_path or package, value)
    for key in ("javaTreeDigest", "toolTreeDigest"):
        if re.fullmatch(r"sha256:[0-9a-f]{64}", str(value[key])) is None:
            raise RuntimeMetadataError("runtime-metadata-tool-identity-invalid")
    return value


def _portable_budget(package: Path) -> None:
    """Bound expanded portable bytes/member count before the governed recursive hygiene walk."""
    total = 0
    names = set()
    with tarfile.open(package, "r|gz") as archive:
        for entry in archive:
            name = entry.name.rstrip("/").casefold()
            total += entry.size
            if name in names or len(names) >= 32768 or total > 1024 * 1024 * 1024:
                raise RuntimeMetadataError("runtime-metadata-portable-budget-or-case-collision")
            names.add(name)


def observe_package(package: Path, java_home: Path, private_root: Path, *,
                    historical_tool_root: Path | None = None) -> tuple[bytes, bytes, dict]:
    """Run only the package's fixed exporter, with no caller-selected class or inherited credentials."""
    from bounded_process import run
    before = identity(package, 1024 * 1024 * 1024)
    _portable_budget(package)
    if maintenance.archive_hygiene_errors(package):
        raise RuntimeMetadataError("runtime-metadata-portable-archive-invalid")
    member_name = "lib/cryptad.jar"
    with tarfile.open(package, "r:gz") as archive:
        members = [entry for entry in archive.getmembers() if entry.name.rstrip("/") == member_name]
        if len(members) != 1 or not members[0].isfile() or members[0].size > 256 * 1024 * 1024:
            raise RuntimeMetadataError("runtime-metadata-packaged-exporter-unavailable")
        jar = archive.extractfile(members[0]).read(members[0].size + 1)
    if len(jar) != members[0].size:
        raise RuntimeMetadataError("runtime-metadata-package-member-invalid")
    with zipfile.ZipFile(io.BytesIO(jar)) as container:
        manifests = [entry for entry in container.infolist() if entry.filename.lower() == "meta-inf/manifest.mf"]
        if len(manifests) > 1:
            raise RuntimeMetadataError("runtime-metadata-jar-manifest-ambiguous")
        if manifests:
            manifest = container.read(manifests[0]).replace(b"\r\n ", b"").replace(b"\n ", b"")
            if re.search(rb"(?im)^(Class-Path|Multi-Release):", manifest):
                raise RuntimeMetadataError("runtime-metadata-jar-external-classpath-rejected")
    with tempfile.TemporaryDirectory(prefix="contract-", dir=private_root) as temporary:
        stage = Path(temporary)
        selected = stage / "cryptad.jar"
        selected.write_bytes(jar)
        selected.chmod(0o400)
        # No wildcard, launcher script, ambient CLASSPATH/JAVA_TOOL_OPTIONS, or tool API classes.
        environment = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "HOME": "/tmp", "TMPDIR": "/tmp"}
        sandbox = ["/usr/bin/bwrap", "--unshare-all", "--die-with-parent", "--new-session",
                   "--ro-bind", "/usr", "/usr", "--ro-bind", "/lib", "/lib",
                   "--ro-bind", "/lib64", "/lib64", "--proc", "/proc", "--dev", "/dev",
                   "--size", "16777216", "--tmpfs", "/tmp", "--ro-bind", str(java_home.resolve()), "/jdk",
                   "--ro-bind", str(stage.resolve()), "/work", "--chdir", "/work"]
        command = ["/jdk/bin/java", "-Xmx128m", "-cp", "/work/cryptad.jar",
                   "network.crypta.platform.api.PackagedApiExport"]
        if historical_tool_root is not None:
            library = historical_tool_root / "lib"
            jars = sorted(library.glob("*.jar"))
            if not jars or len(jars) > 128 or any(path.is_symlink() for path in jars):
                raise RuntimeMetadataError("runtime-metadata-historical-tool-classpath-invalid")
            sandbox += ["--ro-bind", str(historical_tool_root.resolve()), "/tools"]
            command = ["/jdk/bin/java", "-Xmx128m", "-cp", ":".join("/tools/lib/" + path.name for path in jars),
                       "network.crypta.platform.devtools.HistoricalPackagedApiExport", "/work/cryptad.jar"]
        try:
            output = run(["/usr/bin/prlimit", "--cpu=60", "--fsize=8388608", "--nofile=128", "--", *sandbox, "--", *command],
                         environment=environment, timeout=60, output_limit=4 * 1024 * 1024)
        except ValueError:
            raise RuntimeMetadataError("runtime-metadata-packaged-exporter-unsupported") from None
        result = read_json(output)
        if (not isinstance(result, dict) or set(result) != {"schemaVersion", "kind", "contractSnapshot", "baselineRegistry"}
                or result["schemaVersion"] != 1 or result["kind"] != "packaged-platform-api-export"
                or not isinstance(result["contractSnapshot"], str) or not isinstance(result["baselineRegistry"], str)
                or _regular(selected, 256 * 1024 * 1024) != jar):
            raise RuntimeMetadataError("runtime-metadata-export-invalid")
    if before != identity(package, 1024 * 1024 * 1024):
        raise RuntimeMetadataError("runtime-metadata-package-changed")
    return result["contractSnapshot"].encode(), result["baselineRegistry"].encode(), {
        "member": member_name, "digest": digest_bytes(jar), "sizeBytes": len(jar)}


def _produce_runtime_metadata(freeze: dict, package: Path, output: Path, *, projection_origin: dict,
                             private_root: Path) -> dict:
    """Authenticate original cohort inputs and export/admit exact bytes before freezing metadata.

    The cohort policy is the existing root-owned app-subject policy; original projection coordinates
    are separately selected by the protected maintenance environment. No receipt is self-issued.
    """
    import app_subject_projection as projection
    from original_artifact_authentication import authenticate_original
    cohort = projection._cohort()
    # The maintenance workflow uploads this directory as ordinary artifact members.
    # Selected federation requires encrypted companions, which this format cannot carry.
    if cohort["schemaVersion"] == 2:
        raise RuntimeMetadataError("runtime-metadata-private-companion-unsupported")
    cohort_digest = projection._canonical_digest(projection._public_cohort(cohort))
    original_projection = projection.authenticate_inventory(projection_origin, private_root,
                                                            expected_cohort_digest=cohort_digest)
    inventory = original_projection.inventory()
    if inventory["schemaVersion"] == 4:
        raise RuntimeMetadataError("runtime-metadata-private-companion-unsupported")
    if (cohort["releaseId"] != freeze["releaseId"] or cohort["sourceCommit"] != freeze["source"]["commit"]):
        raise RuntimeMetadataError("runtime-metadata-cohort-release-mismatch")
    if any(source["original"]["sourceFamily"] != "maintenance-app-products"
           for source in cohort["sources"] if source["appId"] in FIRST_PARTY | {"mail-prototype"}):
        raise RuntimeMetadataError("runtime-metadata-prospective-app-source-required")
    expected_release = {"releaseId": freeze["releaseId"], "buildVersion": freeze["buildVersion"],
                        "sourceCommit": freeze["source"]["commit"]}
    tool_root, java_home = Path(cohort["toolRoot"]), Path(cohort["javaHome"])
    projection.authenticate_tool_tree(cohort, tool_root, private_root)
    if projection.tree_digest(java_home) != cohort["javaTreeDigest"]:
        raise RuntimeMetadataError("runtime-metadata-java-tree-substituted")
    exporter = tool_root / cohort["exporterRelativePath"]
    if not exporter.resolve().is_relative_to(tool_root.resolve()):
        raise RuntimeMetadataError("runtime-metadata-exporter-path-invalid")
    snapshot, registry, executable = observe_package(package, java_home, private_root)
    if output.exists() or output.is_symlink() or any(path.is_symlink() for path in output.parents):
        raise RuntimeMetadataError("runtime-metadata-output-must-be-new")
    output.mkdir(mode=0o700)
    try:
        (output / MEMBER_NAMES["snapshot"]).write_bytes(snapshot)
        (output / MEMBER_NAMES["registry"]).write_bytes(registry)
        # Recover exact authenticated inventory bytes, not a reserialized substitute.
        raw_inventory = original_projection.original_bytes()
        if digest_bytes(raw_inventory) != original_projection.digest:
            raise RuntimeMetadataError("runtime-metadata-original-inventory-changed")
        (output / MEMBER_NAMES["inventory"]).write_bytes(raw_inventory)
        declarations = []
        for source in sorted(cohort["sources"], key=lambda row: row["appId"]):
            for key in ("catalogKeys", "publisherKeys", "reviewerKeys"):
                if source[key] is not None and digest_bytes(_regular(Path(source[key]))) != source[key + "Digest"]:
                    raise RuntimeMetadataError("runtime-metadata-trust-registry-substituted")
            artifact = authenticate_original(source["original"], private_root)
            catalog = (authenticate_original(source["catalogOriginal"], private_root)
                       if source["catalogOriginal"] is not None else None)
            scoped, _ = projection.selected_federation(cohort, source["appId"], private_root)
            result = projection.produce(artifact, source["members"], exporter=exporter,
                exporter_digest=digest_bytes(_regular(exporter)), app_id=source["appId"],
                catalog_key_id=source["catalogKeyId"], catalog_keys=Path(source["catalogKeys"]),
                publisher_keys=Path(source["publisherKeys"]),
                reviewer_keys=Path(source["reviewerKeys"]) if source["reviewerKeys"] else None,
                private_root=private_root, java_home=java_home, catalog_artifact=catalog,
                contract_path=output / MEMBER_NAMES["snapshot"],
                baseline_registry_path=output / MEMBER_NAMES["registry"], source=source, **scoped)
            declaration = result["declaration"]
            projection.verify_upstream_subject(source, declaration, artifact, private_root,
                expected_release=expected_release)
            declarations.append(declaration)
        if (projection.tree_digest(tool_root) != cohort["toolTreeDigest"]
                or projection.tree_digest(java_home) != cohort["javaTreeDigest"]):
            raise RuntimeMetadataError("runtime-metadata-tool-tree-changed-during-admission")
        (output / MEMBER_NAMES["nativeAdmissions"]).write_bytes(canonical_bytes(declarations))
        subjects = {row["appId"]: row["signedProjection"] for row in inventory["subjects"]}
        value = {"schemaVersion": 1, "kind": "maintenance-runtime-subjects",
            "provenance": "frozen-with-original-release", "releaseId": freeze["releaseId"],
            "buildVersion": freeze["buildVersion"], "sourceCommit": freeze["source"]["commit"],
            "generatedAt": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            "portable": identity(package, 1024 * 1024 * 1024), "executable": executable,
            "contractVersion": read_json(snapshot)["contract"]["contractVersion"],
            "contractSnapshotDigest": digest_bytes(snapshot), "contractSemanticDigest": semantic_digest(read_json(snapshot)["contract"]),
            "baselineRegistryDigest": digest_bytes(registry), "baselineName": "1.0", "baselineContractVersion": 19,
            "stableBaselineDigest": "sha256:" + STABLE_DEFINITION,
            "shippedAppIds": sorted(FIRST_PARTY), "requiredAppIds": inventory["requiredAppIds"],
            "shippedCohortDigest": semantic_digest([subjects[key] for key in sorted(FIRST_PARTY)]),
            "experimentCohortDigest": inventory["cohortDigest"], "cohortPolicy": inventory["cohortPolicy"],
            "projectionInventoryDigest": original_projection.digest, "projectionOrigin": projection_origin,
            "toolTreeDigest": cohort["toolTreeDigest"], "javaTreeDigest": cohort["javaTreeDigest"],
            "rolePolicy": role_policy(cohort["cohortPolicy"]),
            "members": {key: identity(output / name) for key, name in MEMBER_NAMES.items()}}
        (output / MANIFEST_FILE).write_bytes(canonical_bytes(value))
        for path in output.iterdir():
            path.chmod(0o600)
        return value
    except Exception:
        shutil.rmtree(output)
        raise


def produce_runtime_metadata(freeze: dict, package: Path, output: Path, *, projection_origin: dict,
                             private_root: Path) -> dict:
    """Produce metadata with bounded diagnostics even when private input acquisition fails."""
    try:
        return _produce_runtime_metadata(freeze, package, output,
                                        projection_origin=projection_origin, private_root=private_root)
    except RuntimeMetadataError:
        raise
    except (ValueError, KeyError, TypeError, OSError, zipfile.BadZipFile, tarfile.TarError):
        raise RuntimeMetadataError("runtime-metadata-production-failed") from None


def _seal_prospective_freeze(freeze: dict, package: Path, runtime_root: Path, *, projection_origin: dict,
                            private_root: Path) -> dict:
    """Build runtime manifest first, then seal the prospective freeze without a digest cycle."""
    produce_runtime_metadata(freeze, package, runtime_root, projection_origin=projection_origin,
                             private_root=private_root)
    result = dict(freeze)
    result["schemaVersion"] = 2
    result["runtimeMetadata"] = identity(runtime_root / MANIFEST_FILE)
    completed = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    result["generatedAt"] = completed
    result["frozenAt"] = completed
    if validate_schema(result, "stable-1.0-maintenance-candidate-freeze-v2.schema.json"):
        raise RuntimeMetadataError("runtime-metadata-freeze-schema-invalid")
    validate_runtime_metadata(result, runtime_root)
    return result


def seal_prospective_freeze(freeze: dict, package: Path, runtime_root: Path, *, projection_origin: dict,
                            private_root: Path) -> dict:
    """Seal only exact validated metadata; report acquisition failures without private values."""
    existed = runtime_root.exists() or runtime_root.is_symlink()
    try:
        return _seal_prospective_freeze(freeze, package, runtime_root,
                                       projection_origin=projection_origin, private_root=private_root)
    except (ValueError, KeyError, TypeError, OSError, zipfile.BadZipFile, tarfile.TarError):
        if not existed and runtime_root.is_dir() and not runtime_root.is_symlink():
            shutil.rmtree(runtime_root, ignore_errors=True)
        raise RuntimeMetadataError("runtime-metadata-freeze-sealing-failed") from None


def observe_original_package(package: Path, java_home: Path, tool_root: Path, private_root: Path) -> tuple[bytes, bytes, dict]:
    """Observe supported historical ABI from original bytes with the approved isolated bridge.

    The protected caller authenticates the exact complete tool/JDK trees first and labels the
    returned observation observed-from-original-package, never frozen-with-original-release.
    """
    return observe_package(package, java_home, private_root, historical_tool_root=tool_root)


def verify_package_identity(package: Path, metadata: dict) -> None:
    """Reopen the selected original archive and executable without running product code."""
    if identity(package, 1024 * 1024 * 1024) != metadata["portable"]:
        raise RuntimeMetadataError("runtime-metadata-portable-bytes-substituted")
    _portable_budget(package)
    if maintenance.archive_hygiene_errors(package):
        raise RuntimeMetadataError("runtime-metadata-portable-archive-invalid")
    with tarfile.open(package, "r:gz") as archive:
        rows = [row for row in archive.getmembers() if row.name == metadata["executable"]["member"]]
        if len(rows) != 1 or not rows[0].isfile() or rows[0].size != metadata["executable"]["sizeBytes"]:
            raise RuntimeMetadataError("runtime-metadata-executable-substituted")
        data = archive.extractfile(rows[0]).read(rows[0].size + 1)
        if len(data) != rows[0].size or digest_bytes(data) != metadata["executable"]["digest"]:
            raise RuntimeMetadataError("runtime-metadata-executable-substituted")


def authenticate_predecessor_observation(context, observed_at: str) -> dict:
    """Derive the pre-freeze predecessor only from the existing complete maintenance graph.

    Transport authentication remains the existing protected input/maintenance workflow boundary.
    This reuses its native GA-root, published successor, receipt, pointer and hotfix-follow-up
    semantics before freezing a product, without requiring any future candidate evidence.
    """
    try:
        if maintenance.parse_timestamp(observed_at) is None:
            raise RuntimeMetadataError("runtime-predecessor-observation-time-invalid")
        state = maintenance.ValidationState()
        ga = maintenance.authenticate_ga_root(context, state)
        if state.blockers:
            raise RuntimeMetadataError("runtime-predecessor-ga-root-rejected")
        predecessor = maintenance.authenticate_predecessor(context, ga, state)
        if state.blockers:
            raise RuntimeMetadataError("runtime-predecessor-published-graph-rejected")
        return {"releaseId": predecessor.release_id, "buildVersion": predecessor.build_version,
            "sourceCommit": predecessor.source_commit, "productDigest": predecessor.product_digest,
            "baselineDigest": predecessor.baseline_digest,
            "publicationReceiptDigest": predecessor.receipt_digest,
            "latestPublishedPointerDigest": predecessor.latest_pointer_digest,
            "observedAt": observed_at, "status": "latest-published"}
    except RuntimeMetadataError:
        raise
    except (ValueError, OSError, KeyError, TypeError, AssertionError):
        raise RuntimeMetadataError("runtime-predecessor-authentication-failed") from None


def stage_jdk(source: Path, destination: Path, expected_digest: str) -> Path:
    """Materialize installed JDK links privately, then require the approved complete byte tree.

    Only links within the selected installation are supported. Missing targets, cycles, special
    files and oversized trees reject; no executable is invoked and no expected digest is inferred.
    """
    import app_subject_projection as projection
    source = source.resolve(strict=True)
    if (not source.is_dir() or destination.exists() or destination.is_symlink()
            or any(p.is_symlink() for p in destination.parents)):
        raise RuntimeMetadataError("runtime-metadata-jdk-stage-invalid")
    target = destination.resolve()
    if target.is_relative_to(source) or source.is_relative_to(target):
        raise RuntimeMetadataError("runtime-metadata-jdk-stage-overlap")
    destination.mkdir(mode=0o700)
    count = total = 0

    def copy_entry(entry: Path, output: Path, ancestors: frozenset):
        nonlocal count, total
        resolved = entry.resolve(strict=True)
        if not resolved.is_relative_to(source):
            raise RuntimeMetadataError("runtime-metadata-jdk-link-escapes-installation")
        count += 1
        if count > 32768:
            raise RuntimeMetadataError("runtime-metadata-jdk-stage-budget")
        before = resolved.stat()
        if stat.S_ISDIR(before.st_mode):
            if resolved in ancestors:
                raise RuntimeMetadataError("runtime-metadata-jdk-link-cycle")
            output.mkdir(mode=0o700)
            for child in sorted(resolved.iterdir()):
                copy_entry(child, output / child.name, ancestors | {resolved})
        elif stat.S_ISREG(before.st_mode):
            total += before.st_size
            if total > 4 * 1024**3:
                raise RuntimeMetadataError("runtime-metadata-jdk-stage-budget")
            with resolved.open("rb") as incoming, output.open("xb") as outgoing:
                remaining = before.st_size
                while remaining:
                    chunk = incoming.read(min(65536, remaining))
                    if not chunk:
                        raise RuntimeMetadataError("runtime-metadata-jdk-source-changed")
                    outgoing.write(chunk)
                    remaining -= len(chunk)
                if incoming.read(1):
                    raise RuntimeMetadataError("runtime-metadata-jdk-source-changed")
            after = resolved.stat()
            if any(getattr(before, key) != getattr(after, key)
                   for key in ("st_dev", "st_ino", "st_size", "st_mtime_ns")):
                raise RuntimeMetadataError("runtime-metadata-jdk-source-changed")
            output.chmod(0o700 if before.st_mode & 0o111 else 0o600)
        else:
            raise RuntimeMetadataError("runtime-metadata-jdk-special-file")

    try:
        for entry in sorted(source.iterdir()):
            copy_entry(entry, destination / entry.name, frozenset({source}))
        if projection.tree_digest(destination) != expected_digest:
            raise RuntimeMetadataError("runtime-metadata-approved-jdk-mismatch")
        return destination.resolve(strict=True)
    except Exception as error:
        shutil.rmtree(destination)
        if isinstance(error, RuntimeMetadataError):
            raise
        raise RuntimeMetadataError("runtime-metadata-jdk-staging-failed") from None


def prepare_environment(inputs: Path, prepared_cohort: Path, java_home: Path, tool_root: Path,
                        jdk_root: Path) -> None:
    """Stage the installed JDK against owner policy before preparing any executable tools."""
    expected = read_json(_regular(inputs / "cohort.json"))["javaTreeDigest"]
    staged = stage_jdk(java_home, jdk_root, expected)
    try:
        _prepare_environment(inputs, prepared_cohort, staged, tool_root)
    except Exception:
        shutil.rmtree(staged)
        raise


def _prepare_environment(inputs: Path, prepared_cohort: Path, java_home: Path, tool_root: Path) -> None:
    """Install the exact original tool ZIP and map private paths without changing cohort identity.

    This explicit online producer preparation runs before the root-owned cohort is installed. The
    staged JDK must already equal its approved full tree digest; preparation never downloads a
    caller-selected executable or follows a catalog URL.
    """
    import app_subject_projection as projection
    from original_artifact_authentication import authenticate_original
    inputs = inputs.resolve(strict=True)
    if prepared_cohort.exists() or prepared_cohort.is_symlink():
        raise RuntimeMetadataError("runtime-metadata-prepared-cohort-must-be-new")
    cohort = read_json(_regular(inputs / "cohort.json"))
    previous_identity = projection._canonical_digest(projection._public_cohort(cohort))
    if projection.tree_digest(java_home) != cohort["javaTreeDigest"]:
        raise RuntimeMetadataError("runtime-metadata-approved-jdk-not-installed")
    if tool_root.exists() or tool_root.is_symlink() or any(path.is_symlink() for path in tool_root.parents):
        raise RuntimeMetadataError("runtime-metadata-tool-stage-must-be-new")
    with tempfile.TemporaryDirectory(prefix="runtime-tools-", dir=prepared_cohort.parent) as temporary:
        private = Path(temporary)
        original = authenticate_original(cohort["toolOriginal"], private)
        content = projection.selected_members(original, {"bundle": cohort["toolMember"]})["bundle"]
        if projection.tool_archive_digest(content) != cohort["toolTreeDigest"]:
            raise RuntimeMetadataError("runtime-metadata-original-tool-tree-mismatch")
        tool_root.mkdir(mode=0o700)
        try:
            with zipfile.ZipFile(io.BytesIO(content)) as archive:
                for entry in archive.infolist():
                    parts = Path(entry.filename).parts[1:]
                    if not parts:
                        continue
                    destination = tool_root.joinpath(*parts)
                    if entry.is_dir():
                        destination.mkdir(parents=True, exist_ok=True)
                    else:
                        destination.parent.mkdir(parents=True, exist_ok=True)
                        destination.write_bytes(archive.read(entry))
                        destination.chmod(0o700 if (entry.external_attr >> 16) & 0o111 else 0o600)
            cohort["toolRoot"] = str(tool_root.resolve())
            cohort["javaHome"] = str(java_home.resolve())
            for source in cohort["sources"]:
                for key in ("catalogKeys", "publisherKeys", "reviewerKeys"):
                    if source[key] is not None:
                        selected = inputs / "trust" / Path(source[key]).name
                        if digest_bytes(_regular(selected)) != source[key + "Digest"]:
                            raise RuntimeMetadataError("runtime-metadata-scoped-registry-missing")
                        source[key] = str(selected.resolve())
            if cohort.get("schemaVersion") == 2:
                for field, basename in (("snapshot", "contract.json"), ("registry", "registry.json")):
                    selected = inputs / "admission" / basename
                    if digest_bytes(_regular(selected)) != cohort["admissionContract"][field + "Digest"]:
                        raise RuntimeMetadataError("runtime-metadata-selected-contract-missing")
                    cohort["admissionContract"][field + "Path"] = str(selected.resolve())
            if projection._canonical_digest(projection._public_cohort(cohort)) != previous_identity:
                raise RuntimeMetadataError("runtime-metadata-cohort-remapping-changed-authority")
            projection.authenticate_tool_tree(cohort, tool_root, private)
            prepared_cohort.write_bytes(canonical_bytes(cohort))
            prepared_cohort.chmod(0o600)
        except Exception:
            shutil.rmtree(tool_root)
            raise


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("prepare-environment",))
    parser.add_argument("--inputs", required=True, type=Path)
    parser.add_argument("--prepared-cohort", required=True, type=Path)
    parser.add_argument("--java-home", required=True, type=Path)
    parser.add_argument("--tool-root", required=True, type=Path)
    parser.add_argument("--jdk-root", required=True, type=Path)
    arguments = parser.parse_args()
    try:
        prepare_environment(arguments.inputs, arguments.prepared_cohort, arguments.java_home,
                            arguments.tool_root, arguments.jdk_root)
        return 0
    except (ValueError, OSError, KeyError, TypeError):
        print("runtime-metadata-environment-preparation-failed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
