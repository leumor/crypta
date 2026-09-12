"""Later static observation of authenticated original packages, never a historical refreeze.

Only the protected product admission caller invokes this executable/online path after original
product authentication. A returned dictionary cannot construct AuthenticatedProducts. The existing
supervisor admission and original finish evidence own the subsequent authority chain.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import shutil

import app_subject_projection as projection
from maintenance_runtime_metadata import (
    RuntimeMetadataError, _regular, canonical_bytes, digest_bytes, identity, read_json,
    role_policy, semantic_digest, FIRST_PARTY, STABLE_DEFINITION,
)
from original_artifact_authentication import authenticate_original


_NATIVE_FIELDS = frozenset({"contractSnapshotDigest", "baselineRegistryDigest", "nativeAdmission", "catalogChannel"})


def _original_shipped_binding(row: dict) -> dict:
    """Commit the original release authority without inventing its missing runtime inventory."""
    apps, catalog = row.get("historicalShippedSubjects"), row.get("historicalShippedCatalog")
    if (not isinstance(apps, list) or len(apps) != len(FIRST_PARTY)
            or {app.get("appId") for app in apps} != FIRST_PARTY
            or not isinstance(catalog, dict) or catalog.get("channel") != "stable"
            or "rcProductDigest" not in row):
        raise RuntimeMetadataError("historical-original-shipped-inventory-unsupported")
    return {"provenance": "original-rc-frozen-shipped-subjects",
            "rcProductDigest": row["rcProductDigest"], "rcFreezeDigest": row["rcFreezeDigest"],
            "origin": row["rcOrigin"], "apps": sorted(apps, key=lambda app: app["appId"]),
            "catalog": catalog}


def _native_subject(source, signed, snapshot, registry, cohort, root):
    for key in ("catalogKeys", "publisherKeys", "reviewerKeys"):
        if source[key] is not None and digest_bytes(_regular(Path(source[key]))) != source[key + "Digest"]:
            raise RuntimeMetadataError("historical-trust-registry-substituted")
    artifact = authenticate_original(source["original"], root)
    scoped, _ = projection.selected_federation(cohort, source["appId"], root)
    catalog = None
    if source["catalogOriginal"] is not None:
        if not scoped and source["catalogOriginal"].get("sourceFamily") != "catalog-source":
            raise RuntimeMetadataError("historical-catalog-source-invalid")
        catalog = authenticate_original(source["catalogOriginal"], root)
    exporter = Path(cohort["toolRoot"]) / cohort["exporterRelativePath"]
    result = projection.produce(artifact, source["members"], exporter=exporter,
        exporter_digest=digest_bytes(_regular(exporter)), app_id=source["appId"],
        catalog_key_id=source["catalogKeyId"], catalog_keys=Path(source["catalogKeys"]),
        publisher_keys=Path(source["publisherKeys"]),
        reviewer_keys=Path(source["reviewerKeys"]) if source["reviewerKeys"] else None,
        private_root=root, java_home=Path(cohort["javaHome"]), catalog_artifact=catalog,
        contract_path=snapshot, baseline_registry_path=registry, source=source, **scoped)
    declaration = projection.validate_declaration(result["declaration"])
    legacy = projection.content_declaration(declaration)
    expected = projection.content_declaration(signed)
    if (declaration.get("nativeAdmission") != "accepted" or declaration.get("catalogChannel") == "deprecated" or legacy != expected
            or declaration["contractSnapshotDigest"] != digest_bytes(_regular(snapshot))
            or declaration["baselineRegistryDigest"] != digest_bytes(_regular(registry))):
        raise RuntimeMetadataError("historical-native-signed-subject-mismatch")
    if source["original"]["sourceFamily"] == "third-party-pilot" and (
            declaration["reviewDigest"] is None or declaration["submissionDigest"] is None):
        raise RuntimeMetadataError("historical-external-review-missing")
    projection.verify_upstream_subject(source, declaration, artifact, root)
    return declaration


def _original_inventory_bytes(original, authenticated):
    import io
    import zipfile
    with zipfile.ZipFile(io.BytesIO(original.content)) as archive:
        encrypted = archive.namelist() == ["platform-api-1.x-app-subject-inventory.cms"]
    raw = (authenticated.original_bytes() if encrypted else projection.selected_members(original,
        {"catalog": "platform-api-1.x-app-subject-inventory.json"})["catalog"])
    if (len(raw) > 1024 * 1024 or digest_bytes(raw) != authenticated.digest
            or not authenticated.matches(read_json(raw))):
        raise RuntimeMetadataError("historical-original-projection-substituted")
    return raw


def observe_historical_product(row: dict, node: dict, selection: dict, root: Path) -> dict:
    """Observe an already authenticated original package and admit its owner-selected app subset.

    Tool/cohort/source authentication is deliberately explicit and online. This is not an offline
    report verifier and never supplies a release freeze or publication authority. The historical
    release retains its own freeze/publication clock; the new timestamp dates only this observation.
    """
    output = None
    try:
        if (not isinstance(selection, dict) or set(selection) != {"coordinates", "cohortDigest"}
                or node["role"] not in {"previous", "oldest", "relay-no-apps"}
                or row["artifactDigest"] != node["artifactDigest"]
                or row["artifactSize"] != node["artifactSize"]
                or row["sourceCommit"] != node["sourceCommit"]):
            raise RuntimeMetadataError("historical-product-selection-invalid")
        shipped_binding = _original_shipped_binding(row)
        cohort = projection._cohort()
        cohort_digest = projection._canonical_digest(projection._public_cohort(cohort))
        if selection["cohortDigest"] != cohort_digest:
            raise RuntimeMetadataError("historical-cohort-policy-substituted")
        authenticated = projection.authenticate_inventory(selection["coordinates"], root,
                                                           expected_cohort_digest=cohort_digest)
        inventory = authenticated.inventory()
        sources = {source["appId"]: source for source in cohort["sources"]}
        subjects = {subject["appId"]: subject for subject in inventory["subjects"]}
        if (len(subjects) != len(inventory["subjects"]) or sorted(subjects) != inventory["requiredAppIds"]
                or set(subjects) != set(sources) or inventory["cohortPolicy"] != cohort["cohortPolicy"]):
            raise RuntimeMetadataError("historical-complete-cohort-mismatch")
        expected_ids = role_policy(cohort["cohortPolicy"])[node["role"]]
        selected = [subjects[app_id]["signedProjection"] for app_id in expected_ids]
        if sorted(app["bundleDigest"] for app in selected) != sorted(node["appDigests"]):
            raise RuntimeMetadataError("historical-required-app-roster-mismatch")
        for app_id, subject in subjects.items():
            source = sources[app_id]
            if (subject["originalSource"] != source["original"]
                    or subject["originalCatalogSource"] != source["catalogOriginal"]
                    or subject["originalInventorySource"] != source["originalInventory"]):
                raise RuntimeMetadataError("historical-cohort-source-substituted")
        tool_root, java_home = Path(cohort["toolRoot"]), Path(cohort["javaHome"])
        projection.authenticate_tool_tree(cohort, tool_root, root)
        if projection.tree_digest(java_home) != cohort["javaTreeDigest"]:
            raise RuntimeMetadataError("historical-java-tree-substituted")
        exporter = tool_root / cohort["exporterRelativePath"]
        if not exporter.resolve().is_relative_to(tool_root.resolve()):
            raise RuntimeMetadataError("historical-exporter-path-invalid")
        package = Path(row["path"])
        before = identity(package, 1024 * 1024 * 1024)
        if before["digest"] != row["artifactDigest"] or before["sizeBytes"] != row["artifactSize"]:
            raise RuntimeMetadataError("historical-package-substituted")
        from maintenance_runtime_metadata import observe_original_package
        snapshot, registry, executable = observe_original_package(package, java_home, tool_root, root)
        contract = read_json(snapshot)["contract"]
        if contract["contractVersion"] != node["contractVersion"]:
            raise RuntimeMetadataError("historical-observed-contract-label-mismatch")
        registry_value = read_json(registry)
        stable = [item for item in registry_value["baselineRegistry"]["definitions"] if item["id"] == "1.0"]
        if (len(stable) != 1 or stable[0]["definitionDigest"] != STABLE_DEFINITION
                or stable[0]["firstCompleteContractVersion"] != 19):
            raise RuntimeMetadataError("historical-stable-baseline-unsupported")
        destination = root / ("historical-runtime-" + node["role"])
        destination.mkdir(mode=0o700)
        output = destination
        (output / "snapshot.json").write_bytes(snapshot)
        (output / "baseline-registry.json").write_bytes(registry)
        original = authenticate_original(selection["coordinates"], root)
        raw_inventory = _original_inventory_bytes(original, authenticated)
        (output / "projection-inventory.json").write_bytes(raw_inventory)
        declarations = [_native_subject(sources[app_id], subjects[app_id]["signedProjection"],
            output / "snapshot.json", output / "baseline-registry.json", cohort, root)
            for app_id in expected_ids]
        matrix = []
        for app in declarations:
            minimum, maximum = app["minimumContractVersion"], app["maximumTestedContractVersion"]
            if minimum is None or maximum is None or not minimum <= node["contractVersion"] <= maximum:
                raise RuntimeMetadataError("historical-app-outside-tested-contract-range")
            matrix.append({key: app[key] for key in ("appId", "bundleDigest", "bundleSize", "manifestDigest",
                "contractSnapshotDigest", "nativeAdmission")} | {"projectionDigest": authenticated.digest,
                "contractVerifier": "executed", "rangePolicy": "strict-tested-range"})
        (output / "native-admissions.json").write_bytes(canonical_bytes(declarations))
        if (identity(package, 1024 * 1024 * 1024) != before
                or projection.tree_digest(tool_root) != cohort["toolTreeDigest"]
                or projection.tree_digest(java_home) != cohort["javaTreeDigest"]):
            raise RuntimeMetadataError("historical-observation-input-changed")
        completed = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        manifest = {"schemaVersion": 1, "kind": "historical-runtime-subject-observation",
            "provenance": "observed-from-original-package", "completedAt": completed,
            "portable": before, "executable": executable, "sourceCommit": row["sourceCommit"],
            "releaseId": row["releaseId"], "buildVersion": row["buildVersion"],
            "contractVersion": node["contractVersion"], "contractSnapshotDigest": digest_bytes(snapshot),
            "contractSemanticDigest": semantic_digest(contract), "baselineRegistryDigest": digest_bytes(registry),
            "originalShippedBinding": shipped_binding,
            "experimentCohortDigest": cohort_digest, "projectionOrigin": selection["coordinates"],
            "projectionInventoryDigest": authenticated.digest, "toolTreeDigest": cohort["toolTreeDigest"],
            "javaTreeDigest": cohort["javaTreeDigest"], "requiredAppIds": sorted(expected_ids),
            "members": {key: identity(output / name) for key, name in {
                "snapshot": "snapshot.json", "registry": "baseline-registry.json",
                "inventory": "projection-inventory.json", "nativeAdmissions": "native-admissions.json"}.items()}}
        manifest["shippedCohortDigest"] = semantic_digest(manifest["originalShippedBinding"])
        manifest_bytes = canonical_bytes(manifest)
        (output / "runtime-subjects.json").write_bytes(manifest_bytes)
        for path in output.iterdir():
            path.chmod(0o600)
        result = dict(row, runtimeRoot=output,
            runtimeBinding={"metadataDigest": digest_bytes(manifest_bytes), **{key: manifest[key] for key in (
                "contractSnapshotDigest", "contractSemanticDigest", "baselineRegistryDigest", "shippedCohortDigest",
                "experimentCohortDigest", "provenance")}}, appMatrix=matrix, requiredAppIds=sorted(expected_ids),
            contractVersion=node["contractVersion"], runtimeObservationCompletedAt=completed,
            runtimeContractAuthentication="observed-from-original-package",
            shippedCohortProvenance="original-rc-frozen-shipped-subjects")
        result.pop("historicalShippedSubjects", None)
        result.pop("historicalShippedCatalog", None)
        return result
    except Exception as error:
        if output is not None and output.exists() and output.is_dir() and not output.is_symlink():
            shutil.rmtree(output)
        if isinstance(error, RuntimeMetadataError):
            raise
        raise RuntimeMetadataError("historical-runtime-observation-rejected") from None
