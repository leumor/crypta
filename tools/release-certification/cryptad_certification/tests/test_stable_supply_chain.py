"""Focused deterministic and adversarial tests for Stable supply-chain governance."""

from __future__ import annotations

import copy
import gzip
import hashlib
import io
import stat
import shutil
import tarfile
import tempfile
import re
import textwrap
import unittest
from unittest.mock import patch
import zipfile
from pathlib import Path

from cryptad_certification.io import read_json, write_json
from cryptad_certification.manifest import ManifestError, _validate_execution
from cryptad_certification.models import OutputSpec, ReleaseSpec, RunContext, RunManifest
from cryptad_certification.redaction import scan_value
from cryptad_certification.schema_validation import validate_schema

from ..engines import stable_1_0_supply_chain as engine
from ..engines.stable_1_0_supply_chain_archive import (
    ARCHIVE_PACKAGE_TYPES,
    archive_subject_errors,
    build_archive_payload_manifest,
    canonical_mode_class,
)
from ..engines.stable_1_0_supply_chain_core import (
    COMMAND_MODES,
    PUBLICATION_ROLE_FILES,
    build_material_errors,
    builder_observation_errors,
    canonical_json_bytes,
    canonical_java_runtime_build,
    component_inventory_errors,
    component_reverse_index_errors,
    configured_directory,
    file_digest,
    license_inventory_errors,
    installer_subject_binding_errors,
    jdk_component_coverage_errors,
    observed_java_identity,
    payload_manifest_errors,
    resolution_snapshot_errors,
    safe_relative_path_errors,
    semantic_digest,
    sha256_digest,
    subject_inventory_errors,
)
from ..engines.stable_1_0_supply_chain_jdk import jdk_installation_identity
from ..engines.stable_1_0_supply_chain_reproducibility import (
    _payload_comparison_view,
    build_comparison_plan,
    builder_receipt_errors,
    builder_independence_errors,
    compare_rebuilds,
    publication_errors,
    promotion_summary_errors,
    reproducibility_result_errors,
)
from ..engines.stable_1_0_supply_chain_sbom import (
    build_reverse_index,
    build_sbom_binding,
    build_spdx,
    reverse_index_errors,
    sbom_errors,
)

REPOSITORY = Path(__file__).resolve().parents[4]
POLICY_PATH = REPOSITORY / "tools/release-certification/stable-1.0-supply-chain-policy.json"
OVERRIDES_PATH = (
    REPOSITORY
    / "tools/release-certification/stable-1.0-supply-chain-license-overrides.json"
)
WORKFLOW_PATH = REPOSITORY / ".github/workflows/stable-1.0-supply-chain.yml"
PLATFORM_HANDOFF_PATH = REPOSITORY / "tools/release-certification/protected/stable_supply_chain_platform_handoff.py"
CI_WORKFLOW_PATH = REPOSITORY / ".github/workflows/ci.yml"
GIT_ATTRIBUTES_PATH = REPOSITORY / ".gitattributes"
DISTRIBUTION_BUILD_LOGIC_PATH = (
    REPOSITORY / "build-logic/src/main/kotlin/cryptad.distribution.gradle.kts"
)
SUPPLY_CHAIN_BUILD_LOGIC_PATH = (
    REPOSITORY / "build-logic/src/main/kotlin/cryptad.supply-chain.gradle.kts"
)
SOURCE_COMMIT = "a" * 40
SOURCE_REF = "commit:" + SOURCE_COMMIT
SUPPLY_CHAIN_SCHEMAS = (
    "stable-1.0-supply-chain-policy-v1.schema.json",
    "stable-1.0-component-v1.schema.json",
    "stable-1.0-component-inventory-v1.schema.json",
    "stable-1.0-release-subject-inventory-v1.schema.json",
    "stable-1.0-build-materials-v1.schema.json",
    "stable-1.0-resolved-dependency-snapshot-v1.schema.json",
    "stable-1.0-license-inventory-v1.schema.json",
    "stable-1.0-license-overrides-v1.schema.json",
    "stable-1.0-sbom-binding-v1.schema.json",
    "stable-1.0-payload-manifest-v1.schema.json",
    "stable-1.0-package-extraction-evidence-v1.schema.json",
    "stable-1.0-builder-receipt-v1.schema.json",
    "stable-1.0-rebuild-comparison-plan-v1.schema.json",
    "stable-1.0-reproducibility-result-v1.schema.json",
    "stable-1.0-supply-chain-promotion-summary-v1.schema.json",
    "stable-1.0-supply-chain-publication-plan-v1.schema.json",
    "stable-1.0-supply-chain-publication-receipt-v1.schema.json",
    "stable-1.0-supply-chain-public-observation-v1.schema.json",
    "stable-1.0-component-reverse-index-v1.schema.json",
)


def _digest(value: str | bytes) -> str:
    data = value.encode() if isinstance(value, str) else value
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _seal(value: dict, field: str) -> dict:
    value[field] = "sha256:" + "0" * 64
    value[field] = semantic_digest(value, field)
    return value


def _release(policy: dict) -> dict:
    return {
        "releaseId": "stable-maintenance-300",
        "buildVersion": 300,
        "tag": "v300",
        "sourceCommit": SOURCE_COMMIT,
        "sourceRef": SOURCE_REF,
        "policyDigest": policy["policyDigest"],
    }


def _promotion_summary(policy: dict) -> dict:
    release = _release(policy)
    manifest = RunManifest(
        path=REPOSITORY / "manifest.json",
        release=ReleaseSpec(release["releaseId"], str(release["buildVersion"]), "stable-review"),
        output=OutputSpec(REPOSITORY / "build"),
        requirements={"stableSupplyChain": True},
        inputs={},
        policies={
            "candidateSourceCommit": SOURCE_COMMIT,
            "candidateSourceRef": SOURCE_REF,
        },
        execution={"evaluationClock": "2026-08-04T01:00:00Z"},
        commands={"stable-supply-chain": {"mode": "evaluate-promotion"}},
    )
    context = RunContext(
        REPOSITORY, REPOSITORY / "build", "stable-supply-chain", manifest
    )
    return engine._summary(
        context,
        "evaluate-promotion",
        release,
        [],
        [],
        engine._evidence_for_mode("evaluate-promotion"),
    )


def _required_subject_rules(policy: dict) -> list[dict]:
    return sorted(
        [row for row in policy["releaseSubjects"] if row["required"]],
        key=lambda row: row["subjectKey"],
    )


def _archive_suffix(package_type: str) -> str:
    return {
        "app-zip": ".zip",
        "jar": ".jar",
        "tar": ".tar.gz",
        "wheel": "-1-py3-none-any.whl",
        "zip": ".zip",
    }.get(package_type, "." + package_type)


def _fixture_archive_entries() -> list[tuple[str, bytes]]:
    return [
        ("components/runtime.bin", b"component"),
        ("components/db4o.bin", (REPOSITORY / "libs/db4o-7.4.58.jar").read_bytes()),
        ("components/wrapper.bin", (REPOSITORY / "libs/wrapper.jar").read_bytes()),
    ]


def _write_fixture_archive(path: Path, package_type: str) -> None:
    entries = _fixture_archive_entries()
    if package_type in {"app-zip", "jar", "wheel", "zip"}:
        with zipfile.ZipFile(path, "w") as archive:
            for name, data in entries:
                info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                info.create_system = 3
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = (stat.S_IFREG | 0o444) << 16
                archive.writestr(info, data)
        return

    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, data in entries:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o444
            info.mtime = 0
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            archive.addfile(info, io.BytesIO(data))
    with path.open("wb") as output:
        with gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=0) as archive:
            archive.write(stream.getvalue())


def _component(subject_keys: list[str]) -> dict:
    value = {
        "schemaVersion": 1,
        "kind": "stable-1.0-component",
        "componentId": "pkg:maven/example/runtime@1.2.3",
        "componentKind": "maven",
        "name": "runtime",
        "version": "1.2.3",
        "namespace": "example",
        "purl": "pkg:maven/example/runtime@1.2.3",
        "digest": _digest("component"),
        "origin": {
            "type": "maven-central",
            "uri": "https://repo1.maven.org/maven2/example/runtime/1.2.3/runtime-1.2.3.jar",
            "immutableReference": _digest("component"),
            "provenanceDigest": _digest("provenance"),
        },
        "resolved": {
            "coordinates": "example:runtime:1.2.3",
            "selectedVariant": "runtimeElements",
            "attributes": [{"name": "org.gradle.usage", "value": "java-runtime"}],
        },
        "roles": ["runtime", "build"],
        "relationships": {
            "direct": True,
            "parents": [],
            "contains": [],
            "dependsOn": [],
        },
        "subjectKeys": sorted(subject_keys),
        "apps": [
            {"appId": key.removeprefix("app-"), "version": "300"}
            for key in subject_keys
            if key.startswith("app-")
        ],
        "runtimeComponentIds": ["request-scheduler"],
        "license": {
            "expression": "GPL-3.0-only",
            "status": "allowed-with-notice",
            "evidenceDigest": _digest((REPOSITORY / "LICENSE").read_bytes()),
            "licenseTextDigest": _digest((REPOSITORY / "LICENSE").read_bytes()),
        },
        "dependencyVerificationStatus": "verified",
        "buildMaterialStatus": "verified",
        "classification": "public",
        "recordDigest": "",
    }
    return _seal(value, "recordDigest")


def _vendored_component(override: dict, subject_keys: list[str]) -> dict:
    component = _component(subject_keys)
    component_id = override["componentId"]
    name = component_id.split("/", 2)[-1].split("@", 1)[0]
    component.update(
        {
            "componentId": component_id,
            "componentKind": "vendored-binary",
            "name": name,
            "version": override["version"],
            "namespace": "cryptad-vendored",
            "purl": component_id,
            "digest": override["componentDigest"],
            "origin": {
                "type": "reviewed-vendor",
                "uri": f"https://crypta.network/vendor/{name}/{override['version']}",
                "immutableReference": override["componentDigest"],
                "provenanceDigest": _digest("vendor-provenance:" + component_id),
            },
            "resolved": {
                "coordinates": f"cryptad-vendored:{name}:{override['version']}",
                "selectedVariant": "vendored-binary",
                "attributes": [],
            },
            "apps": [],
            "runtimeComponentIds": [],
            "license": {
                "expression": override["licenseExpression"],
                "status": "allowed-with-notice",
                "evidenceDigest": override["licenseTextDigest"],
                "licenseTextDigest": override["licenseTextDigest"],
            },
            "dependencyVerificationStatus": "not-applicable",
            "buildMaterialStatus": "verified",
        }
    )
    return _seal(component, "recordDigest")


def _governance_component(subject_keys: list[str]) -> dict:
    component = _component(subject_keys)
    component_id = (
        "pkg:generic/cryptad-module/release-governance@300?commit=" + SOURCE_COMMIT
    )
    evidence_digest = _digest("reviewed internal release-governance license policy")
    component.update(
        {
            "componentId": component_id,
            "componentKind": "publication-tool",
            "name": "release-governance",
            "version": "300",
            "namespace": "cryptad",
            "purl": component_id,
            "digest": _digest("release-governance"),
            "origin": {
                "type": "repository-source",
                "uri": None,
                "immutableReference": SOURCE_COMMIT,
                "provenanceDigest": _digest("release-governance-provenance"),
            },
            "resolved": {
                "coordinates": None,
                "selectedVariant": None,
                "attributes": [],
            },
            "roles": ["build", "publication"],
            "apps": [],
            "runtimeComponentIds": [],
            "license": {
                "expression": "LicenseRef-Crypta-Internal",
                "status": "not-applicable-internal",
                "evidenceDigest": evidence_digest,
                "licenseTextDigest": None,
            },
            "dependencyVerificationStatus": "not-applicable",
            "buildMaterialStatus": "built",
        }
    )
    return _seal(component, "recordDigest")


def _jdk_installations() -> list[dict]:
    return [
        {
            "runnerOs": runner_os,
            "architecture": "amd64",
            "installationManifestDigest": _digest("jdk-installation:" + runner_os),
            "releaseFileDigest": _digest("jdk-release:" + runner_os),
        }
        for runner_os in ("linux", "macos", "windows")
    ]


def _jdk_component(
    module: str, subject_keys: list[str], distribution_digest: str
) -> dict:
    component = _component(subject_keys)
    component_id = f"pkg:generic/openjdk-module/{module}@25.0.4.1+1"
    license_digest = _digest((REPOSITORY / "LICENSE").read_bytes())
    component.update(
        {
            "componentId": component_id,
            "componentKind": "jdk-module",
            "name": module,
            "version": "25.0.4.1+1",
            "namespace": "openjdk",
            "purl": component_id,
            "digest": distribution_digest,
            "origin": {
                "type": "openjdk",
                "uri": "https://adoptium.net/temurin/releases/?version=25",
                "immutableReference": distribution_digest,
                "provenanceDigest": distribution_digest,
            },
            "resolved": {
                "coordinates": f"openjdk:{module}:25.0.4.1+1",
                "selectedVariant": "jlink-runtime-module",
                "attributes": [],
            },
            "roles": ["runtime"],
            "relationships": {
                "direct": False,
                "parents": [],
                "contains": [],
                "dependsOn": [],
            },
            "apps": [],
            "runtimeComponentIds": ["openjdk-" + module.replace(".", "-")],
            "license": {
                "expression": "LicenseRef-Crypta-Test-Fixture",
                "status": "allowed-with-notice",
                "evidenceDigest": license_digest,
                "licenseTextDigest": license_digest,
            },
            "dependencyVerificationStatus": "not-applicable",
            "buildMaterialStatus": "verified",
        }
    )
    return _seal(component, "recordDigest")


class SupplyChainFixture:
    """Build a complete local Stable inventory without network or external mutation."""

    def __init__(self, root: Path):
        self.root = root
        self.policy = read_json(POLICY_PATH)
        self.release = _release(self.policy)
        self.subject_root = root / "subjects"
        self.payload_root = root / "payload-manifests"
        self.license_root = root / "license-texts"
        self.subject_root.mkdir(parents=True)
        self.payload_root.mkdir()
        self.license_root.mkdir()
        rules = _required_subject_rules(self.policy)
        product_keys = [
            row["subjectKey"]
            for row in rules
            if row["normalizationRuleId"] is not None
            and row["reproducibilityClass"] != "not-a-product-subject"
        ]
        governance_keys = [
            row["subjectKey"]
            for row in rules
            if row["subjectKey"] not in product_keys
        ]
        self.component = _component(product_keys)
        self.jdk_installations = _jdk_installations()
        self.jdk_distribution_digest = sha256_digest(
            canonical_json_bytes(self.jdk_installations)
        )
        jdk_subject_keys = sorted(
            row["subjectKey"]
            for row in rules
            if row["subjectClass"] in {"installer", "runtime-image"}
        )
        self.jdk_components = [
            _jdk_component(module, jdk_subject_keys, self.jdk_distribution_digest)
            for module in ("java.base", "java.logging")
        ]
        self.override_registry = read_json(OVERRIDES_PATH)
        self.vendored_components = [
            _vendored_component(override, product_keys)
            for override in self.override_registry["overrides"]
        ]
        self.governance_component = _governance_component(governance_keys)
        all_components = sorted(
            [
                self.component,
                *self.jdk_components,
                *self.vendored_components,
                self.governance_component,
            ],
            key=lambda row: row["componentId"],
        )
        self.all_components = all_components
        self.product_component_ids = sorted(
            [
                self.component["componentId"],
                *[row["componentId"] for row in self.jdk_components],
                *[row["componentId"] for row in self.vendored_components],
            ]
        )
        self.governance_component_ids = [self.governance_component["componentId"]]
        self.snapshot = self._snapshot()
        self.components = _seal(
            {
                "schemaVersion": 1,
                "kind": "stable-1.0-component-inventory",
                "releaseId": self.release["releaseId"],
                "buildVersion": self.release["buildVersion"],
                "sourceCommit": SOURCE_COMMIT,
                "policyDigest": self.policy["policyDigest"],
                "resolvedDependencySnapshotDigest": self.snapshot["snapshotDigest"],
                "components": all_components,
                "inventoryDigest": "",
            },
            "inventoryDigest",
        )
        self.payloads: dict[str, dict] = {}
        self.subjects = self._subjects(rules)
        license_rows = sorted(
            [
                {
                    "componentId": self.component["componentId"],
                    "expression": "GPL-3.0-only",
                    "status": "allowed-with-notice",
                    "decisionSource": "reviewed-metadata",
                    "evidenceDigest": _digest((REPOSITORY / "LICENSE").read_bytes()),
                    "licenseTextPath": "LICENSE",
                    "licenseTextDigest": _digest((REPOSITORY / "LICENSE").read_bytes()),
                    "noticeRequired": True,
                    "rationale": "Reviewed repository license evidence for the fixture component.",
                },
                {
                    "componentId": self.governance_component["componentId"],
                    "expression": "LicenseRef-Crypta-Internal",
                    "status": "not-applicable-internal",
                    "decisionSource": "internal-policy",
                    "evidenceDigest": self.governance_component["license"][
                        "evidenceDigest"
                    ],
                    "licenseTextPath": None,
                    "licenseTextDigest": None,
                    "noticeRequired": False,
                    "rationale": "First-party release-governance code uses the repository policy.",
                },
                *[
                    {
                        "componentId": component["componentId"],
                        "expression": component["license"]["expression"],
                        "status": "allowed-with-notice",
                        "decisionSource": "reviewed-metadata",
                        "evidenceDigest": component["license"]["evidenceDigest"],
                        "licenseTextPath": "LICENSE",
                        "licenseTextDigest": component["license"]["licenseTextDigest"],
                        "noticeRequired": True,
                        "rationale": "Deterministic test-fixture JDK license decision.",
                    }
                    for component in self.jdk_components
                ],
                *[
                    {
                        "componentId": component["componentId"],
                        "expression": override["licenseExpression"],
                        "status": "allowed-with-notice",
                        "decisionSource": "override",
                        "evidenceDigest": override["licenseTextDigest"],
                        "licenseTextPath": override["licenseTextPath"],
                        "licenseTextDigest": override["licenseTextDigest"],
                        "noticeRequired": True,
                        "rationale": "Reviewed exact-byte vendored license override.",
                    }
                    for component, override in zip(
                        self.vendored_components,
                        self.override_registry["overrides"],
                        strict=True,
                    )
                ],
            ],
            key=lambda row: row["componentId"],
        )
        notice_rows = [
            {
                "componentId": row["componentId"],
                "expression": row["expression"],
                "evidenceDigest": row["evidenceDigest"],
                "licenseTextPath": row["licenseTextPath"],
                "licenseTextDigest": row["licenseTextDigest"],
            }
            for row in license_rows
            if row["noticeRequired"]
        ]
        self.licenses = _seal(
            {
                "schemaVersion": 1,
                "kind": "stable-1.0-license-inventory",
                "releaseId": self.release["releaseId"],
                "buildVersion": self.release["buildVersion"],
                "sourceCommit": SOURCE_COMMIT,
                "policyDigest": self.policy["policyDigest"],
                "componentInventoryDigest": self.components["inventoryDigest"],
                "components": license_rows,
                "noticesDigest": sha256_digest(canonical_json_bytes(notice_rows)),
                "licenseInventoryDigest": "",
            },
            "licenseInventoryDigest",
        )
        for override in self.override_registry["overrides"]:
            source = REPOSITORY / override["licenseTextPath"]
            destination = self.license_root / override["licenseTextPath"]
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(source.read_bytes())
        self.materials = self._materials()

    def _snapshot(self) -> dict:
        material_names = self.policy["buildMaterialRules"]["requiredDigests"]
        value = {
            "schemaVersion": 1,
            "kind": "stable-1.0-resolved-dependency-snapshot",
            "sourceCommit": SOURCE_COMMIT,
            "policyDigest": self.policy["policyDigest"],
            "configurations": [
                {
                    "project": ":",
                    "name": "runtimeClasspath",
                    "role": "runtime",
                    "attributes": [
                        {"name": "org.gradle.usage", "value": "java-runtime"}
                    ],
                    "componentIds": ["pkg:maven/example/runtime@1.2.3"],
                    "resolutionDigest": _digest("resolution"),
                },
                {
                    "project": ":build-logic",
                    "name": "buildLogicSettingsPluginClasspath",
                    "role": "build",
                    "attributes": [],
                    "componentIds": ["pkg:maven/example/runtime@1.2.3"],
                    "resolutionDigest": _digest("build-logic-settings-resolution"),
                },
                {
                    "project": ":build-logic",
                    "name": "rootSettingsPluginClasspath",
                    "role": "build",
                    "attributes": [],
                    "componentIds": ["pkg:maven/example/runtime@1.2.3"],
                    "resolutionDigest": _digest("root-settings-resolution"),
                },
                {
                    "project": ":build-logic",
                    "name": "runtimeClasspath",
                    "role": "build",
                    "attributes": [
                        {"name": "org.gradle.usage", "value": "java-runtime"}
                    ],
                    "componentIds": ["pkg:maven/example/runtime@1.2.3"],
                    "resolutionDigest": _digest("build-logic-resolution"),
                },
            ],
            "components": [
                {
                    "componentId": "pkg:maven/example/runtime@1.2.3",
                    "componentKind": "external-module",
                    "coordinates": "example:runtime:1.2.3",
                    "version": "1.2.3",
                    "selectedVariant": "runtimeElements",
                    "attributes": [
                        {"name": "org.gradle.usage", "value": "java-runtime"}
                    ],
                    "roles": ["runtime", "build"],
                    "artifactDigest": _digest("component"),
                    "verificationStatus": "verified",
                    "changing": False,
                    "direct": True,
                    "parents": [],
                }
            ],
            "dependencyVerification": {
                "status": "verified",
                "metadataDigest": _digest("verification-metadata"),
                "keyringDigest": _digest("keyring"),
                "keyringKeysDigest": _digest("keys"),
            },
            "locking": {
                "status": "authenticated-snapshot",
                "snapshotMode": "authenticated-resolution-snapshot",
                "lockDigest": _digest("rawResolutionExport"),
            },
            "materialDigests": {name: _digest(name) for name in material_names},
            "snapshotDigest": "",
        }
        return _seal(value, "snapshotDigest")

    def _subjects(self, rules: list[dict]) -> dict:
        rows = []
        for rule in rules:
            key = rule["subjectKey"]
            component_ids = sorted(
                row["componentId"]
                for row in self.all_components
                if key in row["subjectKeys"]
            )
            normalization = next(
                (
                    item
                    for item in self.policy["normalizationRules"]
                    if item["id"] == rule["normalizationRuleId"]
                ),
                None,
            )
            package_type = normalization["packageTypes"][0] if normalization else None
            suffix = _archive_suffix(package_type) if package_type else ".bin"
            file_name = f"artifacts/{key}{suffix}"
            path = self.subject_root / file_name
            path.parent.mkdir(parents=True, exist_ok=True)
            if package_type in ARCHIVE_PACKAGE_TYPES:
                _write_fixture_archive(path, package_type)
            else:
                path.write_bytes(("subject:" + key).encode())
            data = path.read_bytes()
            payload_digest = None
            package_metadata_digest = None
            if normalization is not None and package_type in ARCHIVE_PACKAGE_TYPES:
                manifest = build_archive_payload_manifest(
                    path,
                    key,
                    rule["subjectClass"],
                    component_ids,
                    normalization,
                    self.policy,
                )
            elif rule["reproducibilityClass"] == "normalized-payload-identical":
                manifest = _seal(
                    {
                        "schemaVersion": 1,
                        "kind": "stable-1.0-payload-manifest",
                        "subjectKey": key,
                        "publishedSubjectDigest": _digest(data),
                        "packageType": package_type,
                        "normalizationRuleId": normalization["id"],
                        "normalizationRuleVersion": normalization["version"],
                        "preSigningPayloadDigest": _digest("staged:" + key),
                        "packageMetadataDigest": _digest("metadata:" + key),
                        "entries": [
                            {
                                "path": "opt/cryptad/runtime.jar",
                                "kind": "file",
                                "digest": _digest("payload:" + key),
                                "size": 10,
                                "modeClass": "read-only",
                                "symlinkTarget": None,
                                "componentIds": component_ids,
                            }
                        ],
                        "ignoredPaths": [],
                        "limits": {
                            "entryCount": 1,
                            "expandedBytes": 10,
                            "nestedArchiveDepth": 0,
                        },
                        "manifestDigest": "",
                    },
                    "manifestDigest",
                )
            if normalization is not None:
                self.payloads[key] = manifest
                write_json(self.payload_root / f"{key}.json", manifest)
                payload_digest = manifest["manifestDigest"]
                package_metadata_digest = manifest["packageMetadataDigest"]
            app = None
            if key.startswith("app-"):
                app = {
                    "appId": key.removeprefix("app-"),
                    "version": "300",
                    "bundleSignatureDigest": _digest("signature:" + key),
                    "manifestDigest": _digest("manifest:" + key),
                    "permissionDigest": _digest("permission:" + key),
                    "staticFilesDigest": _digest("static:" + key),
                    "dataSchemaDigest": _digest("schema:" + key),
                    "contentProfileDigest": _digest("profile:" + key),
                    "reviewReceiptDigest": _digest("review:" + key),
                }
            rows.append(
                {
                    "subjectKey": key,
                    "subjectClass": rule["subjectClass"],
                    "fileName": file_name,
                    "digest": _digest(data),
                    "size": len(data),
                    "reproducibilityClass": rule["reproducibilityClass"],
                    "payloadManifestDigest": payload_digest,
                    "componentIds": component_ids,
                    "app": app,
                    "catalogEdition": (
                        "stable-300" if rule["subjectClass"] == "catalog" else None
                    ),
                    "signatureReceiptDigest": (
                        _digest("signing:" + key)
                        if rule["subjectClass"]
                        in self.policy["subjectMetadataRules"][
                            "signatureReceiptClasses"
                        ]
                        else None
                    ),
                    "notarizationReceiptDigest": (
                        _digest("notarization:" + key) if key == "amd64.dmg" else None
                    ),
                    "packageMetadataDigest": package_metadata_digest,
                }
            )
        return _seal(
            {
                "schemaVersion": 1,
                "kind": "stable-1.0-release-subject-inventory",
                "releaseId": self.release["releaseId"],
                "buildVersion": self.release["buildVersion"],
                "sourceCommit": SOURCE_COMMIT,
                "policyDigest": self.policy["policyDigest"],
                "componentInventoryDigest": self.components["inventoryDigest"],
                "subjects": rows,
                "subjectInventoryDigest": "",
            },
            "subjectInventoryDigest",
        )

    def _materials(self) -> dict:
        workflow_ref = (
            self.policy["builderPolicy"]["allowedWorkflowPaths"][0] + "@" + SOURCE_COMMIT
        )
        return _seal(
            {
                "schemaVersion": 1,
                "kind": "stable-1.0-build-materials",
                **self.release,
                "resolutionSnapshotDigest": self.snapshot["snapshotDigest"],
                "source": {
                    "commit": SOURCE_COMMIT,
                    "ref": SOURCE_REF,
                    "treeDigest": _digest("tree"),
                    "clean": True,
                    "submoduleStateDigest": _digest("submodules"),
                    "vendorStateDigest": _digest("vendors"),
                    "authenticatedCommitTime": "2026-08-04T00:00:00Z",
                },
                "gradle": {
                    "version": "9.1.0",
                    "wrapperJarDigest": self.snapshot["materialDigests"]["gradleWrapperJar"],
                    "wrapperPropertiesDigest": self.snapshot["materialDigests"]["gradleWrapperProperties"],
                    "distributionUri": "https://services.gradle.org/distributions/gradle-9.1.0-bin.zip",
                    "distributionDigest": self.snapshot["materialDigests"]["gradleDistribution"],
                    "versionCatalogDigest": self.snapshot["materialDigests"]["versionCatalog"],
                    "repositoryConfigurationDigest": self.snapshot["materialDigests"]["repositoryConfiguration"],
                    "verificationMetadataDigest": self.snapshot["materialDigests"]["verificationMetadata"],
                    "verificationKeyringDigest": self.snapshot["materialDigests"]["verificationKeyring"],
                    "verificationKeyringKeysDigest": self.snapshot["dependencyVerification"]["keyringKeysDigest"],
                    "buildLogicDigest": self.snapshot["materialDigests"]["buildLogic"],
                    "pluginResolutionDigest": self.snapshot["materialDigests"]["pluginResolution"],
                    "testResolutionDigest": self.snapshot["materialDigests"]["testResolution"],
                    "rawResolutionExportDigest": self.snapshot["materialDigests"]["rawResolutionExport"],
                },
                "jdk": {
                    "vendor": "Eclipse Adoptium",
                    "version": "25",
                    "build": "25.0.4.1+1",
                    "distribution": "temurin",
                    "setupJavaVersion": "25.0.4.1+1",
                    "installationDigestAlgorithm": "crypta-jdk-installed-tree-sha256-v1",
                    "distributionDigest": self.jdk_distribution_digest,
                    "installations": self.jdk_installations,
                    "modules": ["java.base", "java.logging"],
                },
                "buildLogic": [{"path": "build-logic/build.gradle.kts", "digest": _digest("logic")}],
                "packagingInputs": [
                    {"path": "gradle/wrapper/gradle-wrapper.properties", "digest": _digest("packaging")},
                    *[
                        {"path": "external/" + name, "digest": _digest("direct:" + name)}
                        for name in self.policy["buildMaterialRules"]["requiredDirectInputs"]
                    ],
                ],
                "directInputs": [
                    {
                        "name": "gradle-wrapper-distribution",
                        "digest": _digest("direct:gradle-wrapper-distribution"),
                        "origin": "https://services.gradle.org/distributions/gradle-9.1.0-bin.zip",
                        "immutabilityClass": "versioned-url",
                    },
                    {
                        "name": "seedrefs-source-archive",
                        "digest": _digest("direct:seedrefs-source-archive"),
                        "origin": f"https://codeload.github.com/hyphanet/seedrefs/zip/{SOURCE_COMMIT}",
                        "immutabilityClass": "immutable-git-archive",
                    },
                    {
                        "name": "tanuki-wrapper-delta-pack",
                        "digest": _digest("direct:tanuki-wrapper-delta-pack"),
                        "origin": "https://sourceforge.net/projects/wrapper/files/wrapper/Wrapper_3.6.2_20250605/wrapper-delta-pack-3.6.2.tar.gz/download",
                        "immutabilityClass": "versioned-url",
                    },
                    {
                        "name": "windows-wrapper-amd64",
                        "digest": _digest("direct:windows-wrapper-amd64"),
                        "origin": "https://github.com/crypta-network/wrapper-windows-build/releases/download/v3.6.2/wrapper-windows-amd64.zip",
                        "immutabilityClass": "immutable-release-asset",
                    },
                    {
                        "name": "windows-wrapper-arm64",
                        "digest": _digest("direct:windows-wrapper-arm64"),
                        "origin": "https://github.com/crypta-network/wrapper-windows-build/releases/download/v3.6.2/wrapper-windows-arm64.zip",
                        "immutabilityClass": "immutable-release-asset",
                    },
                ],
                "publicationBackend": {
                    "wheelName": "cryptad_publication_backend-1-py3-none-any.whl",
                    "wheelDigest": _digest("wheel"),
                    "sourceDigest": _digest("wheel-source"),
                },
                "canonicalBuildEpoch": 1785801600,
                "environment": {
                    "osImage": "ubuntu-24.04@stable-build-image-1",
                    "osImageDigest": _digest("os-image"),
                    "architecture": "amd64",
                    "locale": "C.UTF-8",
                    "timezone": "UTC",
                    "encoding": "UTF-8",
                    "allowedVariableNames": ["LANG", "LC_ALL", "SOURCE_DATE_EPOCH", "TZ"],
                },
                "buildTasks": self.policy["builderPolicy"]["buildTasks"],
                "workflow": {
                    "repository": "github.com/crypta-network/cryptad",
                    "workflowRef": workflow_ref,
                    "workflowSha": workflow_ref.rsplit("@", 1)[1],
                    "runId": 100,
                    "runAttempt": 1,
                    "jobName": "candidate-producer",
                    "producerIdentity": "cryptad-stable-supply-chain",
                },
                "materialsDigest": "",
            },
            "materialsDigest",
        )

    def receipt(self, role: str, run_id: int, *, verifier_bytes: dict[str, bytes] | None = None) -> dict:
        workflow_ref = (
            self.policy["builderPolicy"]["allowedWorkflowPaths"][0] + "@" + SOURCE_COMMIT
        )
        subjects = []
        policy_by_key = {
            row["subjectKey"]: row for row in self.policy["releaseSubjects"]
        }
        for row in self.subjects["subjects"]:
            if policy_by_key[row["subjectKey"]]["evidencePhase"] != "independent-builder":
                continue
            data = (
                verifier_bytes.get(row["subjectKey"])
                if verifier_bytes is not None and row["subjectKey"] in verifier_bytes
                else (self.subject_root / row["fileName"]).read_bytes()
            )
            subjects.append(
                {
                    "subjectKey": row["subjectKey"],
                    "fileName": row["fileName"],
                    "digest": _digest(data),
                    "size": len(data),
                    "payloadManifestDigest": row["payloadManifestDigest"],
                    "signatureReceiptDigest": (
                        row["signatureReceiptDigest"]
                        if role == "candidate-producer" else None
                    ),
                    "notarizationReceiptDigest": (
                        row["notarizationReceiptDigest"]
                        if role == "candidate-producer" else None
                    ),
                    "extractionEvidenceDigest": (
                        _digest("extraction:" + row["subjectKey"])
                        if row["reproducibilityClass"] == "normalized-payload-identical"
                        else None
                    ),
                    "publishedCandidate": role == "candidate-producer",
                }
            )
        execution_subjects = {
            "linux-installers": sorted(
                row["subjectKey"]
                for row in subjects
                if row["subjectKey"]
                in {"amd64.deb", "amd64.flatpak", "amd64.rpm", "amd64.snap"}
            ),
            "macos-installer": ["amd64.dmg"],
            "portable-apps": sorted(
                row["subjectKey"]
                for row in subjects
                if row["subjectKey"]
                not in {
                    "amd64.deb",
                    "amd64.dmg",
                    "amd64.exe",
                    "amd64.flatpak",
                    "amd64.rpm",
                    "amd64.snap",
                }
            ),
            "windows-installer": ["amd64.exe"],
        }
        runner_os = {
            "linux-installers": "linux",
            "macos-installer": "macos",
            "portable-apps": "linux",
            "windows-installer": "windows",
        }
        builder_executions = []
        by_subject = {row["subjectKey"]: row for row in subjects}
        for execution_id in self.policy["builderPolicy"]["executionIds"]:
            subject_keys = execution_subjects[execution_id]
            selected = [by_subject[key] for key in subject_keys]
            installation = next(
                row
                for row in self.materials["jdk"]["installations"]
                if row["runnerOs"] == runner_os[execution_id]
            )
            toolchain = {
                "javaVendor": self.materials["jdk"]["vendor"],
                "javaVersion": self.materials["jdk"]["version"],
                "javaBuild": self.materials["jdk"]["build"],
                "javaEncoding": self.materials["environment"]["encoding"],
                "javaArchitecture": installation["architecture"],
                "javaInstallationManifestDigest": installation[
                    "installationManifestDigest"
                ],
                "javaReleaseFileDigest": installation["releaseFileDigest"],
                "javaIdentityDigest": "",
                "gradleWrapperJarDigest": self.materials["gradle"]["wrapperJarDigest"],
                "gradleWrapperPropertiesDigest": self.materials["gradle"]["wrapperPropertiesDigest"],
                "gradleDistributionDigest": self.materials["gradle"]["distributionDigest"],
            }
            toolchain["javaIdentityDigest"] = sha256_digest(
                canonical_json_bytes(
                    {
                        key: toolchain[key]
                        for key in (
                            "javaVendor",
                            "javaVersion",
                            "javaBuild",
                            "javaEncoding",
                            "javaArchitecture",
                            "javaInstallationManifestDigest",
                            "javaReleaseFileDigest",
                        )
                    }
                )
            )
            task_set = self.policy["builderPolicy"]["executionTasks"][execution_id]
            payload_set = [
                {
                    "subjectKey": row["subjectKey"],
                    "payloadManifestDigest": row["payloadManifestDigest"],
                }
                for row in selected
            ]
            builder_executions.append(
                {
                    "executionId": execution_id,
                    "workflowRef": workflow_ref,
                    "workflowSha": SOURCE_COMMIT,
                    "runId": run_id,
                    "runAttempt": 1,
                    "jobName": f"{role}-{execution_id}",
                    "runnerOs": runner_os[execution_id],
                    "runnerArchitecture": "amd64",
                    "runnerImageIdentity": f"cryptad-{runner_os[execution_id]}-builder-v1",
                    "runnerImageDigest": _digest("runner:" + execution_id),
                    "toolchain": toolchain,
                    "materialIdentities": {
                        "dependencyVerificationDigest": self.snapshot["materialDigests"]["verificationMetadata"],
                        "verificationKeyringDigest": self.snapshot["materialDigests"]["verificationKeyring"],
                        "pluginResolutionDigest": self.snapshot["materialDigests"]["pluginResolution"],
                        "buildLogicDigest": self.snapshot["materialDigests"]["buildLogic"],
                        "resolutionSnapshotDigest": self.snapshot["snapshotDigest"],
                    },
                    "taskSet": task_set,
                    "taskSetDigest": sha256_digest(canonical_json_bytes(task_set)),
                    "canonicalEnvironment": {
                        "locale": self.materials["environment"]["locale"],
                        "timezone": self.materials["environment"]["timezone"],
                        "encoding": self.materials["environment"]["encoding"],
                        "sourceDateEpoch": self.materials["canonicalBuildEpoch"],
                    },
                    "environmentVariables": {
                        "LANG": self.materials["environment"]["locale"],
                        "LC_ALL": self.materials["environment"]["locale"],
                        "SOURCE_DATE_EPOCH": str(self.materials["canonicalBuildEpoch"]),
                        "TZ": self.materials["environment"]["timezone"],
                    },
                    "directInputsDigest": "",
                    "payloadManifestSetDigest": sha256_digest(canonical_json_bytes(payload_set)),
                    "extractionManifestSetDigest": sha256_digest(canonical_json_bytes(payload_set)),
                    "handoffDigest": _digest(f"handoff:{role}:{execution_id}"),
                    "subjectSetDigest": sha256_digest(canonical_json_bytes(selected)),
                    "artifactAttestationDigest": _digest(
                        f"execution-attestation:{role}:{execution_id}"
                    ),
                    "attestationVerified": True,
                    "subjectKeys": subject_keys,
                    "sourceCommit": SOURCE_COMMIT,
                    "sourceTreeDigest": _digest("tree"),
                    "materialsDigest": self.materials["materialsDigest"],
                    "resolutionSnapshotDigest": self.snapshot["snapshotDigest"],
                    "buildStartedAt": "2026-08-04T00:00:00Z",
                    "buildCompletedAt": "2026-08-04T00:30:00Z",
                    "candidateProductAvailableBeforeBuild": False,
                }
            )
        receipt = {
                "schemaVersion": 1,
                "kind": "stable-1.0-builder-receipt",
                **self.release,
                "role": role,
                "builderIdentity": {
                    "repository": "github.com/crypta-network/cryptad",
                    "workflowRef": workflow_ref,
                    "workflowSha": workflow_ref.rsplit("@", 1)[1],
                    "runId": run_id,
                    "runAttempt": 1,
                    "jobName": role,
                    "artifactAttestationDigest": _digest("attestation:" + role),
                    "attestationVerified": True,
                },
                "builderExecutions": builder_executions,
                "source": {
                    "commit": SOURCE_COMMIT,
                    "ref": SOURCE_REF,
                    "treeDigest": _digest("tree"),
                    "clean": True,
                },
                "materialsDigest": self.materials["materialsDigest"],
                "resolutionSnapshotDigest": self.snapshot["snapshotDigest"],
                "directInputs": [
                    {
                        **next(
                            row
                            for row in self.materials["directInputs"]
                            if row["name"] == name
                        ),
                        "verificationStatus": "verified",
                        "verificationMechanism": (
                            "gradle-wrapper-checksum"
                            if name == "gradle-wrapper-distribution"
                            else "sha256-before-use"
                        ),
                    }
                    for name in sorted(
                        self.policy["buildMaterialRules"]["requiredDirectInputs"]
                    )
                ],
                "buildTasks": self.policy["builderPolicy"]["buildTasks"],
                "buildStartedAt": "2026-08-04T00:00:00Z",
                "buildCompletedAt": "2026-08-04T00:30:00Z",
                "candidateProductAvailableBeforeBuild": False,
                "subjects": subjects,
                "receiptDigest": "",
            }
        direct_inputs_digest = sha256_digest(canonical_json_bytes(receipt["directInputs"]))
        for execution in receipt["builderExecutions"]:
            execution["directInputsDigest"] = direct_inputs_digest
        return _seal(receipt, "receiptDigest")

    def write_inputs(self) -> dict[str, str]:
        values = {
            "resolvedDependencySnapshot": self.snapshot,
            "componentInventory": self.components,
            "releaseSubjectInventory": self.subjects,
            "licenseInventory": self.licenses,
            "buildMaterials": self.materials,
        }
        inputs: dict[str, str] = {}
        for key, value in values.items():
            path = self.root / f"{key}.json"
            write_json(path, value)
            inputs[key] = path.relative_to(REPOSITORY).as_posix()
        inputs.update(
            {
                "supplyChainPolicy": POLICY_PATH.relative_to(REPOSITORY).as_posix(),
                "primarySubjectRoot": self.subject_root.relative_to(REPOSITORY).as_posix(),
                "primaryPayloadManifests": self.payload_root.relative_to(REPOSITORY).as_posix(),
                "licenseOverrides": OVERRIDES_PATH.relative_to(REPOSITORY).as_posix(),
                "licenseTextRoot": self.license_root.relative_to(REPOSITORY).as_posix(),
            }
        )
        return inputs


class StableSupplyChainTest(unittest.TestCase):
    def test_runtime_build_accepts_lts_patch_versions_without_losing_components(self) -> None:
        for version in ("25.0.3+9", "25.0.4.1+1"):
            with self.subTest(version=version):
                self.assertEqual(canonical_java_runtime_build(version), version)
                self.assertEqual(canonical_java_runtime_build(version + "-LTS"), version)

    def test_runtime_build_rejects_other_java_lines_and_incomplete_builds(self) -> None:
        for version in (
            "26.0.1+1", "25.0.4.1", "25.0.4.1+1-ea", "25.0.4.1.2+1",
            "25.0.4.1+1-LTS-extra", "25.0.4.1+1\n",
        ):
            with self.subTest(version=version), self.assertRaises(ValueError):
                canonical_java_runtime_build(version)

    @classmethod
    def setUpClass(cls) -> None:
        cls.policy = read_json(POLICY_PATH)
        cls.release = _release(cls.policy)

    def test_policy_has_closed_modes_and_valid_digest(self) -> None:
        self.assertEqual(self.policy["modes"], list(COMMAND_MODES))
        self.assertEqual(self.policy["policyDigest"], semantic_digest(self.policy, "policyDigest"))
        self.assertEqual(validate_schema(self.policy, "stable-1.0-supply-chain-policy-v1.schema.json"), [])

    def test_preactivation_candidate_can_emit_historical_contract_promotion_summary(self) -> None:
        freeze_digest = _digest("historical-candidate-freeze")
        product_digest = _digest("historical-product")
        candidate = {
            "kind": "stable-1.0-maintenance-candidate",
            "releaseId": self.release["releaseId"],
            "buildVersion": self.release["buildVersion"],
            "source": {"commit": SOURCE_COMMIT},
            "candidateFreezeDigest": freeze_digest,
            "product": {"digest": product_digest},
            "packages": [],
        }
        freeze = {
            "releaseId": self.release["releaseId"],
            "buildVersion": self.release["buildVersion"],
            "source": {"commit": SOURCE_COMMIT},
            "frozenAt": "2026-08-03T23:59:59Z",
            "assets": [],
            "predecessorObservation": {
                "releaseId": "stable-ga-299",
                "buildVersion": 299,
                "productDigest": _digest("predecessor-product"),
            },
        }
        vulnerability = _seal(
            {
                "releaseId": self.release["releaseId"],
                "buildVersion": self.release["buildVersion"],
                "status": "pass",
                "blockingStablePromotion": False,
                "summaryDigest": "",
            },
            "summaryDigest",
        )
        subjects = {
            "subjectInventoryDigest": _digest("subject-inventory"),
            "subjects": [
                {
                    "subjectKey": "portable-product",
                    "subjectClass": "portable-archive",
                    "digest": product_digest,
                }
            ],
        }

        with (
            patch.object(
                engine,
                "_load_untyped_public_object",
                return_value=(Path("candidate.json"), candidate, _digest("candidate-file")),
            ),
            patch.object(
                engine,
                "load_document",
                return_value=(Path("freeze.json"), freeze, freeze_digest),
            ),
            patch.object(
                engine,
                "_authenticated_vulnerability_summary",
                return_value=vulnerability,
            ),
            patch.object(engine, "configured_file", return_value=Path("primary.json")),
            patch.object(engine, "read_json", return_value={"subjects": []}),
            patch.object(
                engine,
                "context_value_digest",
                side_effect=lambda _context, key, field: _digest(f"{key}:{field}"),
            ),
        ):
            bindings = engine._maintenance_promotion_bindings(
                object(),
                self.release,
                subjects,
                {"reverseIndexDigest": _digest("reverse-index")},
            )

        self.assertEqual(bindings["candidateFreezeDigest"], freeze_digest)
        self.assertEqual(bindings["productDigest"], product_digest)
        self.assertEqual(bindings["predecessorBuildVersion"], 299)

    def test_policy_rejects_installers_without_protected_builder_coverage(self) -> None:
        subject_keys = {row["subjectKey"] for row in self.policy["releaseSubjects"]}
        normalization_rule_ids = {row["id"] for row in self.policy["normalizationRules"]}

        self.assertTrue({"amd64.flatpak", "amd64.snap"}.isdisjoint(subject_keys))
        self.assertTrue(
            {
                "crypta-flatpak-payload-v1",
                "crypta-snap-payload-v1",
            }.isdisjoint(normalization_rule_ids)
        )
        workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
        self.assertNotIn("amd64.flatpak", workflow)
        self.assertNotIn("amd64.snap", workflow)
        self.assertIn("subject_keys: amd64.deb,amd64.rpm", workflow)

        build_root = REPOSITORY / "build"
        build_root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="supply-unsupported-installer-", dir=build_root
        ) as temporary:
            fixture = SupplyChainFixture(Path(temporary))
            subjects = copy.deepcopy(fixture.subjects)
            unauthorized = copy.deepcopy(
                next(
                    row
                    for row in subjects["subjects"]
                    if row["subjectKey"] == "release-notes"
                )
            )
            unauthorized.update(
                subjectKey="amd64.flatpak",
                fileName="cryptad.flatpak",
            )
            subjects["subjects"].append(unauthorized)
            subjects["subjects"].sort(key=lambda row: row["subjectKey"])
            _seal(subjects, "subjectInventoryDigest")

            errors = subject_inventory_errors(
                subjects,
                fixture.components,
                fixture.policy,
                fixture.release,
            )

        self.assertIn("subject amd64.flatpak is not authorized by policy", errors)

    def test_license_text_root_may_select_only_the_workspace_directory(self) -> None:
        manifest = RunManifest(
            path=REPOSITORY / "manifest.json",
            release=ReleaseSpec("stable-maintenance-300", "300", "stable-review"),
            output=OutputSpec(REPOSITORY / "build"),
            requirements={},
            inputs={"licenseTextRoot": ".", "primarySubjectRoot": "."},
            policies={},
            execution={},
            commands={},
        )
        context = RunContext(
            REPOSITORY,
            REPOSITORY / "build",
            "stable-supply-chain",
            manifest,
        )

        self.assertEqual(
            configured_directory(
                context,
                "licenseTextRoot",
                allow_workspace_root=True,
            ),
            REPOSITORY,
        )
        with self.assertRaisesRegex(ValueError, "canonical relative path"):
            configured_directory(context, "primarySubjectRoot")

    def test_all_supply_chain_schemas_are_valid_closed_and_bounded(self) -> None:
        schema_root = REPOSITORY / "tools/release-certification/schemas"
        self.assertEqual(len(SUPPLY_CHAIN_SCHEMAS), 19)
        for name in SUPPLY_CHAIN_SCHEMAS:
            path = schema_root / name
            schema = read_json(path)
            self.assertIs(schema.get("additionalProperties"), False, path.name)
            self.assertEqual(schema.get("type"), "object", path.name)

            def assert_bounded(node: object, location: str = "$") -> None:
                if isinstance(node, dict):
                    node_type = node.get("type")
                    if node_type == "object":
                        self.assertIs(
                            node.get("additionalProperties"),
                            False,
                            f"{path.name}:{location}",
                        )
                    if node_type == "array":
                        self.assertIn("maxItems", node, f"{path.name}:{location}")
                    string_typed = node_type == "string" or (
                        isinstance(node_type, list) and "string" in node_type
                    )
                    if string_typed and "const" not in node and "enum" not in node:
                        self.assertIn("maxLength", node, f"{path.name}:{location}")
                    for key, value in node.items():
                        assert_bounded(value, f"{location}/{key}")
                elif isinstance(node, list):
                    for index, value in enumerate(node):
                        assert_bounded(value, f"{location}/{index}")

            assert_bounded(schema)
        release_run = read_json(schema_root / "release-run-v1.schema.json")
        evaluation_clock = release_run["properties"]["execution"]["properties"][
            "evaluationClock"
        ]
        self.assertEqual(evaluation_clock["format"], "date-time")
        self.assertEqual(evaluation_clock["maxLength"], 32)
        self.assertEqual(
            _validate_execution({"evaluationClock": "2026-08-04T01:00:00Z"})[
                "evaluationClock"
            ],
            "2026-08-04T01:00:00Z",
        )
        for malformed_clock in (
            "2026-08-04T01:00:00.1Z",
            "2026-08-04T01:00:00+00:00",
            "not-a-time",
        ):
            with self.subTest(evaluationClock=malformed_clock):
                with self.assertRaises(ManifestError):
                    _validate_execution({"evaluationClock": malformed_clock})

    def test_component_rejects_dynamic_snapshot_latest_and_range_versions(self) -> None:
        policy = copy.deepcopy(self.policy)
        policy["releaseSubjects"] = [
            {**row, "required": row["subjectKey"] == "core-jar"}
            for row in policy["releaseSubjects"]
        ]
        for version in ("1.+", "2.0-SNAPSHOT", "latest", "[1,2)", "1.*"):
            component = _component(["core-jar"])
            component["version"] = version
            _seal(component, "recordDigest")
            inventory = _seal(
                {
                    "schemaVersion": 1,
                    "kind": "stable-1.0-component-inventory",
                    "releaseId": self.release["releaseId"],
                    "buildVersion": 300,
                    "sourceCommit": SOURCE_COMMIT,
                    "policyDigest": self.policy["policyDigest"],
                    "resolvedDependencySnapshotDigest": _digest("snapshot"),
                    "components": [component],
                    "inventoryDigest": "",
                }, "inventoryDigest"
            )
            self.assertTrue(any("mutable" in error for error in component_inventory_errors(inventory, policy, self.release)), version)

    def test_duplicate_component_identity_with_different_digest_blocks(self) -> None:
        first = _component(["core-jar"])
        second = copy.deepcopy(first)
        second["digest"] = _digest("different")
        _seal(second, "recordDigest")
        inventory = _seal({"schemaVersion": 1, "kind": "stable-1.0-component-inventory", "releaseId": self.release["releaseId"], "buildVersion": 300, "sourceCommit": SOURCE_COMMIT, "policyDigest": self.policy["policyDigest"], "resolvedDependencySnapshotDigest": _digest("snapshot"), "components": [first, second], "inventoryDigest": ""}, "inventoryDigest")
        errors = component_inventory_errors(inventory, self.policy, self.release)
        self.assertTrue(any("different content" in error for error in errors))

    def test_runtime_noassertion_license_blocks(self) -> None:
        component = _component(["core-jar"])
        component["license"]["expression"] = "NOASSERTION"
        component["license"]["status"] = "unknown-blocking"
        _seal(component, "recordDigest")
        inventory = _seal({"schemaVersion": 1, "kind": "stable-1.0-component-inventory", "releaseId": self.release["releaseId"], "buildVersion": 300, "sourceCommit": SOURCE_COMMIT, "policyDigest": self.policy["policyDigest"], "resolvedDependencySnapshotDigest": _digest("snapshot"), "components": [component], "inventoryDigest": ""}, "inventoryDigest")
        self.assertTrue(any("blocking license" in error for error in component_inventory_errors(inventory, self.policy, self.release)))

    def test_payload_manifest_rejects_traversal_appledouble_and_ignore_list(self) -> None:
        base = _seal({"schemaVersion": 1, "kind": "stable-1.0-payload-manifest", "subjectKey": "amd64.deb", "publishedSubjectDigest": _digest("deb"), "packageType": "deb", "normalizationRuleId": "crypta-deb-payload-v1", "normalizationRuleVersion": 1, "preSigningPayloadDigest": _digest("stage"), "packageMetadataDigest": _digest("metadata"), "entries": [{"path": "opt/cryptad/core.jar", "kind": "file", "digest": _digest("core"), "size": 4, "modeClass": "read-only", "symlinkTarget": None, "componentIds": [_component(["core-jar"])["componentId"]]}], "ignoredPaths": [], "limits": {"entryCount": 1, "expandedBytes": 4, "nestedArchiveDepth": 0}, "manifestDigest": ""}, "manifestDigest")
        for bad_path in ("../core.jar", "/core.jar", "__MACOSX/core.jar", "._core.jar", ".DS_Store"):
            value = copy.deepcopy(base)
            value["entries"][0]["path"] = bad_path
            _seal(value, "manifestDigest")
            self.assertTrue(payload_manifest_errors(value, self.policy), bad_path)
        value = copy.deepcopy(base)
        value["ignoredPaths"] = ["signature.bin"]
        _seal(value, "manifestDigest")
        self.assertTrue(any("ignored" in error for error in payload_manifest_errors(value, self.policy)))

    def test_app_payload_normalization_excludes_only_the_signing_envelope(self) -> None:
        build_root = REPOSITORY / "build"
        build_root.mkdir(exist_ok=True)
        normalization = next(
            row
            for row in self.policy["normalizationRules"]
            if row["id"] == "crypta-app-signature-envelope-v1"
        )
        component_id = _component(["app-queue-manager"])["componentId"]
        with tempfile.TemporaryDirectory(prefix="supply-app-envelope-", dir=build_root) as temporary:
            root = Path(temporary)
            unsigned = root / "unsigned.zip"
            signed = root / "signed.zip"
            partial = root / "partial.zip"
            drifted = root / "drifted.zip"
            payload = {
                "bin/launch": b"#!/bin/sh\n",
                "cryptad-app.properties": b"app.id=queue-manager\n",
            }

            def write_app(path: Path, *, include_envelope: bool) -> None:
                members = dict(payload)
                if include_envelope:
                    members["cryptad-app.digests"] = b"digest.version=1\n"
                    members["cryptad-app.signature"] = b"signature.version=1\n"
                with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_STORED) as archive:
                    for name, content in sorted(members.items()):
                        info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                        info.compress_type = zipfile.ZIP_STORED
                        info.create_system = 3
                        info.external_attr = (stat.S_IFREG | 0o644) << 16
                        archive.writestr(info, content)

            write_app(unsigned, include_envelope=False)
            write_app(signed, include_envelope=True)
            write_app(partial, include_envelope=False)
            with zipfile.ZipFile(partial, "a", compression=zipfile.ZIP_STORED) as archive:
                info = zipfile.ZipInfo(
                    "cryptad-app.signature", date_time=(1980, 1, 1, 0, 0, 0)
                )
                info.compress_type = zipfile.ZIP_STORED
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | 0o644) << 16
                archive.writestr(info, b"signature.version=1\n")
            drifted_payload = dict(payload)
            drifted_payload["bin/launch"] = b"#!/bin/sh\nexit 1\n"
            with zipfile.ZipFile(
                drifted, "w", compression=zipfile.ZIP_STORED
            ) as archive:
                for name, content in sorted(drifted_payload.items()):
                    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                    info.compress_type = zipfile.ZIP_STORED
                    info.create_system = 3
                    info.external_attr = (stat.S_IFREG | 0o644) << 16
                    archive.writestr(info, content)
            unsigned_manifest = build_archive_payload_manifest(
                unsigned,
                "app-queue-manager",
                "first-party-app",
                [component_id],
                normalization,
                self.policy,
            )
            signed_manifest = build_archive_payload_manifest(
                signed,
                "app-queue-manager",
                "first-party-app",
                [component_id],
                normalization,
                self.policy,
            )
            drifted_manifest = build_archive_payload_manifest(
                drifted,
                "app-queue-manager",
                "first-party-app",
                [component_id],
                normalization,
                self.policy,
            )

            self.assertEqual(
                _payload_comparison_view(unsigned_manifest),
                _payload_comparison_view(signed_manifest),
            )
            self.assertNotEqual(
                unsigned_manifest["publishedSubjectDigest"],
                signed_manifest["publishedSubjectDigest"],
            )
            self.assertEqual(
                [],
                [
                    row["path"]
                    for row in signed_manifest["entries"]
                    if row["path"] in {"cryptad-app.digests", "cryptad-app.signature"}
                ],
            )
            self.assertNotEqual(
                _payload_comparison_view(unsigned_manifest),
                _payload_comparison_view(drifted_manifest),
            )
            with self.assertRaisesRegex(ValueError, "partial signing envelope"):
                build_archive_payload_manifest(
                    partial,
                    "app-queue-manager",
                    "first-party-app",
                    [component_id],
                    normalization,
                    self.policy,
                )

    def test_payload_and_archive_paths_reject_dot_and_repeated_separators(self) -> None:
        for path in ("./opt/cryptad/core.jar", "opt//cryptad/core.jar", "opt/./core.jar"):
            with self.subTest(payloadPath=path):
                self.assertTrue(safe_relative_path_errors(path, "payload entry"))

        build_root = REPOSITORY / "build"
        build_root.mkdir(exist_ok=True)
        normalization = next(
            row
            for row in self.policy["normalizationRules"]
            if row["id"] == "crypta-zip-content-v1"
        )
        with tempfile.TemporaryDirectory(
            prefix="supply-noncanonical-archive-", dir=build_root
        ) as temporary:
            for index, path in enumerate(("./core.jar", "opt//core.jar")):
                archive_path = Path(temporary) / f"bad-{index}.zip"
                with zipfile.ZipFile(archive_path, "w") as archive:
                    archive.writestr(path, b"unsafe")
                with self.subTest(archivePath=path):
                    with self.assertRaises(ValueError):
                        build_archive_payload_manifest(
                            archive_path,
                            "portable-zip",
                            "portable",
                            [_component(["portable-zip"])["componentId"]],
                            normalization,
                            self.policy,
                        )

    def test_payload_manifest_rejects_case_collision_and_escaping_symlink(self) -> None:
        value = _seal({"schemaVersion": 1, "kind": "stable-1.0-payload-manifest", "subjectKey": "amd64.exe", "publishedSubjectDigest": _digest("exe"), "packageType": "exe", "normalizationRuleId": "crypta-exe-payload-v1", "normalizationRuleVersion": 1, "preSigningPayloadDigest": _digest("stage"), "packageMetadataDigest": _digest("metadata"), "entries": [{"path": "App/Core.jar", "kind": "file", "digest": _digest("a"), "size": 1, "modeClass": "regular", "symlinkTarget": None, "componentIds": [_component(["core-jar"])["componentId"]]}, {"path": "app/core.jar", "kind": "symlink", "digest": None, "size": 0, "modeClass": "symlink", "symlinkTarget": "../../../escape", "componentIds": [_component(["core-jar"])["componentId"]]}], "ignoredPaths": [], "limits": {"entryCount": 2, "expandedBytes": 1, "nestedArchiveDepth": 0}, "manifestDigest": ""}, "manifestDigest")
        errors = payload_manifest_errors(value, self.policy)
        self.assertTrue(any("case-fold" in error for error in errors))
        self.assertTrue(any("escaping symlink" in error for error in errors))

    def test_actual_archive_entry_omission_and_component_mapping_drift_block(self) -> None:
        build_root = REPOSITORY / "build"
        build_root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="supply-archive-", dir=build_root) as temporary:
            fixture = SupplyChainFixture(Path(temporary))
            subject = next(
                row for row in fixture.subjects["subjects"] if row["subjectKey"] == "core-jar"
            )
            manifest = copy.deepcopy(fixture.payloads["core-jar"])
            manifest["entries"].pop()
            for entry in manifest["entries"]:
                entry["componentIds"] = entry["componentIds"][:-1]
            _seal(manifest, "manifestDigest")

            errors = archive_subject_errors(
                fixture.subject_root / subject["fileName"],
                manifest,
                subject,
                {row["componentId"]: row for row in fixture.components["components"]},
                fixture.policy,
            )

            self.assertTrue(any("actual archive entries" in error for error in errors))
            self.assertTrue(any("does not map every subject component" in error for error in errors))

    def test_actual_archive_rejects_nested_traversal_and_appledouble_bytes(self) -> None:
        build_root = REPOSITORY / "build"
        build_root.mkdir(exist_ok=True)
        normalization = next(
            row
            for row in self.policy["normalizationRules"]
            if row["id"] == "crypta-zip-content-v1"
        )
        with tempfile.TemporaryDirectory(prefix="supply-unsafe-", dir=build_root) as temporary:
            root = Path(temporary)
            nested_stream = io.BytesIO()
            with zipfile.ZipFile(nested_stream, "w") as nested:
                nested.writestr("../escape", b"unsafe")
            nested_path = root / "nested.zip"
            with zipfile.ZipFile(nested_path, "w") as archive:
                archive.writestr("nested.zip", nested_stream.getvalue())
            apple_double_path = root / "appledouble.zip"
            with zipfile.ZipFile(apple_double_path, "w") as archive:
                archive.writestr("._host", b"unsafe")

            for path in (nested_path, apple_double_path):
                with self.subTest(path=path.name):
                    with self.assertRaises(ValueError):
                        build_archive_payload_manifest(
                            path,
                            "portable-zip",
                            "portable",
                            [_component(["portable-zip"])["componentId"]],
                            normalization,
                            self.policy,
                        )

    def test_spdx_is_deterministic_and_bound_to_inventory(self) -> None:
        policy = copy.deepcopy(self.policy)
        policy["releaseSubjects"] = [{**row, "required": row["subjectKey"] == "core-jar"} for row in policy["releaseSubjects"]]
        component = _component(["core-jar"])
        components = _seal({"schemaVersion": 1, "kind": "stable-1.0-component-inventory", "releaseId": self.release["releaseId"], "buildVersion": 300, "sourceCommit": SOURCE_COMMIT, "policyDigest": self.policy["policyDigest"], "resolvedDependencySnapshotDigest": _digest("snapshot"), "components": [component], "inventoryDigest": ""}, "inventoryDigest")
        subjects = _seal({"schemaVersion": 1, "kind": "stable-1.0-release-subject-inventory", "releaseId": self.release["releaseId"], "buildVersion": 300, "sourceCommit": SOURCE_COMMIT, "policyDigest": self.policy["policyDigest"], "componentInventoryDigest": components["inventoryDigest"], "subjects": [{"subjectKey": "core-jar", "subjectClass": "core", "fileName": "core.jar", "digest": _digest("core"), "size": 4, "reproducibilityClass": "byte-identical", "payloadManifestDigest": None, "componentIds": [component["componentId"]], "app": None, "catalogEdition": None, "signatureReceiptDigest": None, "notarizationReceiptDigest": None, "packageMetadataDigest": None}], "subjectInventoryDigest": ""}, "subjectInventoryDigest")
        first = build_spdx(self.release, policy, components, subjects)
        second = build_spdx(self.release, policy, components, subjects)
        self.assertEqual(first, second)
        binding = build_sbom_binding(self.release, first, components, subjects)
        self.assertEqual(sbom_errors(first, binding, second, components, subjects), [])
        changed = copy.deepcopy(first)
        changed["packages"][-1]["versionInfo"] = "wrong"
        self.assertTrue(sbom_errors(changed, binding, second, components, subjects))

    def test_reverse_index_resolves_one_runtime_component(self) -> None:
        component = _component(["core-jar"])
        components = _seal({"schemaVersion": 1, "kind": "stable-1.0-component-inventory", "releaseId": self.release["releaseId"], "buildVersion": 300, "sourceCommit": SOURCE_COMMIT, "policyDigest": self.policy["policyDigest"], "resolvedDependencySnapshotDigest": _digest("snapshot"), "components": [component], "inventoryDigest": ""}, "inventoryDigest")
        subjects = _seal({"schemaVersion": 1, "kind": "stable-1.0-release-subject-inventory", "releaseId": self.release["releaseId"], "buildVersion": 300, "sourceCommit": SOURCE_COMMIT, "policyDigest": self.policy["policyDigest"], "componentInventoryDigest": components["inventoryDigest"], "subjects": [{"subjectKey": "core-jar", "subjectClass": "core", "fileName": "core.jar", "digest": _digest("core"), "size": 4, "reproducibilityClass": "byte-identical", "payloadManifestDigest": None, "componentIds": [component["componentId"]], "app": None, "catalogEdition": None, "signatureReceiptDigest": None, "notarizationReceiptDigest": None, "packageMetadataDigest": None}], "subjectInventoryDigest": ""}, "subjectInventoryDigest")
        index = build_reverse_index(self.release, components, subjects)
        self.assertEqual(
            component_reverse_index_errors(
                index,
                release_id=self.release["releaseId"],
                build_version=300,
                source_commit=SOURCE_COMMIT,
                source_ref=SOURCE_REF,
                runtime_component_ids=["request-scheduler"],
            ),
            [],
        )
        self.assertTrue(
            component_reverse_index_errors(
                index,
                source_commit=SOURCE_COMMIT,
                source_ref=SOURCE_REF,
                runtime_component_ids=["absent-component"],
            )
        )
        stale_source = copy.deepcopy(index)
        stale_source["sourceCommit"] = "b" * 40
        stale_source["sourceRef"] = "commit:" + "b" * 40
        _seal(stale_source, "reverseIndexDigest")
        source_errors = component_reverse_index_errors(
            stale_source,
            release_id=self.release["releaseId"],
            build_version=300,
            source_commit=SOURCE_COMMIT,
            source_ref=SOURCE_REF,
            runtime_component_ids=["request-scheduler"],
        )
        self.assertTrue(
            any("another source commit" in error for error in source_errors),
            source_errors,
        )
        self.assertTrue(
            any("another source ref" in error for error in source_errors),
            source_errors,
        )
        missing_build = copy.deepcopy(index)
        missing_build["entries"][0]["stableBuilds"] = [299]
        _seal(missing_build, "reverseIndexDigest")
        build_errors = component_reverse_index_errors(
            missing_build,
            release_id=self.release["releaseId"],
            build_version=300,
            source_commit=SOURCE_COMMIT,
            source_ref=SOURCE_REF,
            runtime_component_ids=["request-scheduler"],
        )
        self.assertTrue(
            any("does not map to the requested Stable build" in error for error in build_errors),
            build_errors,
        )
        stale = copy.deepcopy(index)
        stale["buildVersion"] = 299
        _seal(stale, "reverseIndexDigest")
        self.assertTrue(reverse_index_errors(stale, self.release, components, subjects))

    def test_builder_independence_rejects_same_run_and_resolution_drift(self) -> None:
        primary = {"builderIdentity": {"runId": 1, "workflowRef": "a", "workflowSha": "b", "jobName": "producer", "runAttempt": 1}, "receiptDigest": _digest("one"), "materialsDigest": _digest("m"), "resolutionSnapshotDigest": _digest("r"), "buildTasks": [":build"]}
        verifier = copy.deepcopy(primary)
        verifier["receiptDigest"] = _digest("two")
        verifier["resolutionSnapshotDigest"] = _digest("drift")
        errors = builder_independence_errors(primary, verifier, self.policy)
        self.assertTrue(any("same workflow run" in error for error in errors))
        self.assertTrue(any("resolution differs" in error for error in errors))

    def test_builder_independence_compares_role_neutral_payload_not_dmg_extraction(self) -> None:
        build_root = REPOSITORY / "build"
        build_root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="supply-dmg-independence-", dir=build_root
        ) as temporary:
            fixture = SupplyChainFixture(Path(temporary))
            primary = fixture.receipt("candidate-producer", 101)
            verifier = fixture.receipt("independent-verifier", 102)
            verifier_macos = next(
                row
                for row in verifier["builderExecutions"]
                if row["executionId"] == "macos-installer"
            )
            verifier_macos["extractionManifestSetDigest"] = _digest(
                "role-specific-verifier-dmg-extraction"
            )
            _seal(verifier, "receiptDigest")

            self.assertEqual(
                builder_independence_errors(primary, verifier, fixture.policy), []
            )

            verifier_macos["payloadManifestSetDigest"] = _digest(
                "different-normalized-dmg-payload"
            )
            _seal(verifier, "receiptDigest")
            errors = builder_independence_errors(primary, verifier, fixture.policy)

            self.assertTrue(
                any("payload manifest set digest differs" in error for error in errors),
                errors,
            )

    def test_verifier_receipt_rejects_candidate_bytes_before_build(self) -> None:
        build_root = REPOSITORY / "build"
        build_root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="supply-receipt-", dir=build_root) as temporary:
            fixture = SupplyChainFixture(Path(temporary))
            receipt = fixture.receipt("independent-verifier", 102)
            receipt["candidateProductAvailableBeforeBuild"] = True
            _seal(receipt, "receiptDigest")
            errors = builder_receipt_errors(
                receipt,
                "independent-verifier",
                fixture.release,
                fixture.policy,
                fixture.materials["materialsDigest"],
                fixture.snapshot["snapshotDigest"],
                fixture.materials,
                fixture.subjects,
                fixture.snapshot,
            )
            self.assertTrue(any("before its build" in error for error in errors))

    def test_builder_receipt_authenticates_each_platform_execution(self) -> None:
        build_root = REPOSITORY / "build"
        build_root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="supply-executions-", dir=build_root
        ) as temporary:
            fixture = SupplyChainFixture(Path(temporary))
            receipt = fixture.receipt("candidate-producer", 101)
            self.assertEqual(
                builder_receipt_errors(
                    receipt,
                    "candidate-producer",
                    fixture.release,
                    fixture.policy,
                    fixture.materials["materialsDigest"],
                    fixture.snapshot["snapshotDigest"],
                    fixture.materials,
                    fixture.subjects,
                    fixture.snapshot,
                ),
                [],
            )
            string_run = copy.deepcopy(receipt)
            string_run["builderIdentity"]["runId"] = "101"
            string_run["builderExecutions"][0]["runId"] = "101"
            _seal(string_run, "receiptDigest")
            self.assertTrue(
                any(
                    "runId" in error or "integer" in error
                    for error in builder_receipt_errors(
                        string_run,
                        "candidate-producer",
                        fixture.release,
                        fixture.policy,
                        fixture.materials["materialsDigest"],
                        fixture.snapshot["snapshotDigest"],
                        fixture.materials,
                        fixture.subjects,
                        fixture.snapshot,
                    )
                )
            )
            mutations = (
                (
                    lambda row: row.update(attestationVerified=False),
                    "attestation",
                ),
                (
                    lambda row: row.update(sourceCommit="b" * 40),
                    "source commit",
                ),
                (
                    lambda row: row.update(subjectSetDigest=_digest("substituted")),
                    "subject set digest",
                ),
                (
                    lambda row: row.update(runnerImageIdentity="ubuntu-latest"),
                    "mutable runner image",
                ),
                (
                    lambda row: row["toolchain"].update(javaBuild="25+37"),
                    "javaBuild",
                ),
                (
                    lambda row: row["toolchain"].update(javaEncoding="ISO-8859-1"),
                    "javaEncoding",
                ),
                (
                    lambda row: row["environmentVariables"].update(TZ="Europe/Paris"),
                    "environment",
                ),
                (
                    lambda row: row["taskSet"].append(":unreviewedTask"),
                    "task set",
                ),
            )
            for mutate, expected in mutations:
                with self.subTest(expected=expected):
                    changed = copy.deepcopy(receipt)
                    mutate(changed["builderExecutions"][0])
                    _seal(changed, "receiptDigest")
                    errors = builder_receipt_errors(
                        changed,
                        "candidate-producer",
                        fixture.release,
                        fixture.policy,
                        fixture.materials["materialsDigest"],
                        fixture.snapshot["snapshotDigest"],
                        fixture.materials,
                        fixture.subjects,
                        fixture.snapshot,
                    )
                    self.assertTrue(any(expected in error for error in errors), errors)

            primary = fixture.receipt("candidate-producer", 101)
            verifier = fixture.receipt("independent-verifier", 102)
            verifier["builderExecutions"][0]["runId"] = 101
            _seal(verifier, "receiptDigest")
            self.assertTrue(
                any(
                    "reuse" in error
                    for error in builder_independence_errors(
                        primary, verifier, fixture.policy
                    )
                )
            )

            verifier = fixture.receipt("independent-verifier", 102)
            verifier_app = next(
                row
                for row in verifier["subjects"]
                if row["subjectKey"] == "app-queue-manager"
            )
            verifier_app["digest"] = _digest("different-signed-app-envelope")
            _seal(verifier, "receiptDigest")
            self.assertIn(
                "builder app-queue-manager signed app bundle bytes differ",
                builder_independence_errors(primary, verifier, fixture.policy),
            )

            verifier = fixture.receipt("independent-verifier", 102)
            verifier_recipe = {
                "buildTasks": [":dist", ":packageUnsignedFirstPartyApps"],
                "executionTasks": copy.deepcopy(
                    fixture.policy["builderPolicy"]["executionTasks"]
                ),
            }
            verifier_recipe["executionTasks"]["portable-apps"] = [
                ":dist",
                ":packageUnsignedFirstPartyApps",
            ]
            verifier["buildTasks"] = verifier_recipe["buildTasks"]
            for execution in verifier["builderExecutions"]:
                tasks = verifier_recipe["executionTasks"][execution["executionId"]]
                execution["taskSet"] = tasks
                execution["taskSetDigest"] = sha256_digest(canonical_json_bytes(tasks))
            _seal(verifier, "receiptDigest")

            self.assertEqual(
                [],
                builder_independence_errors(
                    primary,
                    verifier,
                    fixture.policy,
                    provider_distinct=True,
                    provider_distinct_recipe=verifier_recipe,
                ),
            )

    def test_normalized_packages_may_differ_only_when_payload_views_match(self) -> None:
        build_root = REPOSITORY / "build"
        build_root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="supply-compare-", dir=build_root) as temporary:
            root = Path(temporary)
            fixture = SupplyChainFixture(root / "fixture")
            verifier_root = root / "verifier"
            verifier_root.mkdir()
            changed: dict[str, bytes] = {}
            for subject in fixture.subjects["subjects"]:
                source = fixture.subject_root / subject["fileName"]
                destination = verifier_root / subject["fileName"]
                destination.parent.mkdir(parents=True, exist_ok=True)
                data = source.read_bytes()
                if (
                    subject["reproducibilityClass"] == "normalized-payload-identical"
                    and not subject["subjectKey"].startswith("app-")
                ):
                    data += b":different-signature-container"
                    changed[subject["subjectKey"]] = data
                destination.write_bytes(data)
            primary = fixture.receipt("candidate-producer", 101)
            verifier = fixture.receipt("independent-verifier", 102, verifier_bytes=changed)
            plan = build_comparison_plan(
                fixture.release,
                fixture.policy,
                fixture.subjects,
                primary,
                verifier,
            )
            result, errors = compare_rebuilds(
                fixture.release,
                fixture.policy,
                plan,
                fixture.subject_root,
                verifier_root,
                fixture.payload_root,
                fixture.payload_root,
            )
            self.assertEqual(errors, [])
            self.assertEqual(result["status"], "pass")

    def test_installer_byte_binding_is_role_sensitive_and_fail_closed(self) -> None:
        inventory = {"digest": _digest("candidate"), "size": 100}
        self.assertEqual(
            installer_subject_binding_errors(
                "candidate-producer", inventory["digest"], inventory["size"], inventory
            ),
            [],
        )
        self.assertTrue(
            installer_subject_binding_errors(
                "candidate-producer", _digest("different"), 101, inventory
            )
        )
        self.assertEqual(
            installer_subject_binding_errors(
                "independent-verifier", _digest("different"), 101, inventory
            ),
            [],
        )
        self.assertTrue(
            installer_subject_binding_errors("self-reported", _digest("candidate"), 100, inventory)
        )

    def test_byte_identical_subject_difference_fails_closed(self) -> None:
        build_root = REPOSITORY / "build"
        build_root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="supply-byte-", dir=build_root) as temporary:
            root = Path(temporary)
            fixture = SupplyChainFixture(root / "fixture")
            verifier_root = root / "verifier"
            shutil.copytree(fixture.subject_root, verifier_root)
            changed = {"core-jar": b"different-core"}
            core = next(row for row in fixture.subjects["subjects"] if row["subjectKey"] == "core-jar")
            (verifier_root / core["fileName"]).write_bytes(changed["core-jar"])
            primary = fixture.receipt("candidate-producer", 101)
            verifier = fixture.receipt("independent-verifier", 102, verifier_bytes=changed)
            plan = build_comparison_plan(fixture.release, fixture.policy, fixture.subjects, primary, verifier)
            result, errors = compare_rebuilds(fixture.release, fixture.policy, plan, fixture.subject_root, verifier_root, fixture.payload_root, fixture.payload_root)
            self.assertEqual(result["status"], "fail")
            self.assertTrue(any("byte-identical" in error for error in errors))

    def test_post_build_and_governance_subjects_are_excluded_from_builder_claims(self) -> None:
        build_root = REPOSITORY / "build"
        build_root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="supply-wheel-byte-", dir=build_root
        ) as temporary:
            root = Path(temporary)
            fixture = SupplyChainFixture(root / "fixture")
            primary = fixture.receipt("candidate-producer", 101)
            verifier = fixture.receipt("independent-verifier", 102)
            plan = build_comparison_plan(
                fixture.release,
                fixture.policy,
                fixture.subjects,
                primary,
                verifier,
            )
            excluded = {
                row["subjectKey"]
                for row in fixture.policy["releaseSubjects"]
                if row["evidencePhase"] != "independent-builder"
            }
            self.assertTrue(
                {"stable-catalog", "stable-core-update-descriptor", "publication-backend-wheel"}
                <= excluded
            )
            self.assertTrue(excluded.isdisjoint(row["subjectKey"] for row in primary["subjects"]))
            self.assertTrue(excluded.isdisjoint(row["subjectKey"] for row in plan["comparisons"]))
            catalog_rule = next(
                row for row in fixture.policy["releaseSubjects"]
                if row["subjectKey"] == "stable-catalog"
            )
            self.assertEqual(catalog_rule["reproducibilityClass"], "byte-identical")
            self.assertEqual(catalog_rule["evidencePhase"], "authenticated-post-build")

            injected = copy.deepcopy(primary)
            catalog = next(
                row for row in fixture.subjects["subjects"]
                if row["subjectKey"] == "stable-catalog"
            )
            injected["subjects"].append(
                {
                    "subjectKey": "stable-catalog",
                    "fileName": catalog["fileName"],
                    "digest": catalog["digest"],
                    "size": catalog["size"],
                    "payloadManifestDigest": None,
                    "signatureReceiptDigest": catalog["signatureReceiptDigest"],
                    "notarizationReceiptDigest": catalog["notarizationReceiptDigest"],
                    "extractionEvidenceDigest": None,
                    "publishedCandidate": True,
                }
            )
            injected["subjects"].sort(key=lambda row: row["subjectKey"])
            _seal(injected, "receiptDigest")
            errors = builder_receipt_errors(
                injected,
                "candidate-producer",
                fixture.release,
                fixture.policy,
                fixture.materials["materialsDigest"],
                fixture.snapshot["snapshotDigest"],
                fixture.materials,
                fixture.subjects,
                fixture.snapshot,
            )
            self.assertTrue(any("exact independent-builder subject set" in error for error in errors))

    def test_frozen_installer_authentication_requires_exact_signing_and_notarization(self) -> None:
        subject = {
            "subjectKey": "amd64.dmg",
            "subjectClass": "installer",
            "digest": _digest("dmg"),
            "signatureReceiptDigest": _digest("signing"),
            "notarizationReceiptDigest": _digest("notarization"),
        }
        asset = {
            "packageType": "dmg",
            "signingReceiptDigest": subject["signatureReceiptDigest"],
            "notarizationStatus": "pass",
            "notarizationReceiptDigest": subject["notarizationReceiptDigest"],
        }
        row = engine._frozen_asset_authentication_row(asset, subject)
        self.assertEqual(row["subjectKey"], "amd64.dmg")
        for field, value in (
            ("signingReceiptDigest", _digest("substituted-signing")),
            ("notarizationReceiptDigest", _digest("substituted-notarization")),
            ("notarizationStatus", "not-applicable"),
        ):
            with self.subTest(field=field):
                changed = copy.deepcopy(asset)
                changed[field] = value
                with self.assertRaises(ValueError):
                    engine._frozen_asset_authentication_row(changed, subject)

    def test_forged_reproducibility_result_row_is_rejected_even_when_resealed(self) -> None:
        build_root = REPOSITORY / "build"
        build_root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="supply-result-", dir=build_root) as temporary:
            root = Path(temporary)
            fixture = SupplyChainFixture(root / "fixture")
            verifier_root = root / "verifier"
            shutil.copytree(fixture.subject_root, verifier_root)
            primary = fixture.receipt("candidate-producer", 101)
            verifier = fixture.receipt("independent-verifier", 102)
            plan = build_comparison_plan(
                fixture.release, fixture.policy, fixture.subjects, primary, verifier
            )
            result, differences = compare_rebuilds(
                fixture.release,
                fixture.policy,
                plan,
                fixture.subject_root,
                verifier_root,
                fixture.payload_root,
                fixture.payload_root,
            )
            self.assertEqual(differences, [])
            self.assertEqual(reproducibility_result_errors(result, fixture.release, plan), [])

            forged = copy.deepcopy(result)
            forged["comparisons"][0]["primaryDigest"] = _digest("forged-equal")
            forged["comparisons"][0]["verifierDigest"] = _digest("forged-equal")
            forged["status"] = "pass"
            forged["unexplainedDifferences"] = 0
            _seal(forged, "resultDigest")
            errors = reproducibility_result_errors(forged, fixture.release, plan)
            self.assertTrue(any("primaryDigest differs from plan" in error for error in errors))

    def test_matching_display_metadata_cannot_hide_presigning_payload_drift(self) -> None:
        build_root = REPOSITORY / "build"
        build_root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="supply-presign-", dir=build_root) as temporary:
            root = Path(temporary)
            fixture = SupplyChainFixture(root / "fixture")
            verifier_root = root / "verifier"
            verifier_manifests = root / "verifier-manifests"
            shutil.copytree(fixture.subject_root, verifier_root)
            shutil.copytree(fixture.payload_root, verifier_manifests)
            normalized_key = sorted(fixture.payloads)[0]
            manifest_path = verifier_manifests / f"{normalized_key}.json"
            manifest = read_json(manifest_path)
            manifest["preSigningPayloadDigest"] = _digest("different-staged-payload")
            _seal(manifest, "manifestDigest")
            write_json(manifest_path, manifest)
            primary = fixture.receipt("candidate-producer", 101)
            verifier = fixture.receipt("independent-verifier", 102)
            next(row for row in verifier["subjects"] if row["subjectKey"] == normalized_key)["payloadManifestDigest"] = manifest["manifestDigest"]
            _seal(verifier, "receiptDigest")
            plan = build_comparison_plan(fixture.release, fixture.policy, fixture.subjects, primary, verifier)
            result, errors = compare_rebuilds(fixture.release, fixture.policy, plan, fixture.subject_root, verifier_root, fixture.payload_root, verifier_manifests)
            self.assertEqual(result["status"], "fail")
            self.assertTrue(any("pre-signing staged payload differs" in error for error in errors))

    def test_actual_subject_digest_drift_is_rejected(self) -> None:
        build_root = REPOSITORY / "build"
        build_root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="supply-subject-", dir=build_root) as temporary:
            fixture = SupplyChainFixture(Path(temporary))
            first = fixture.subjects["subjects"][0]
            (fixture.subject_root / first["fileName"]).write_bytes(b"substituted")
            errors = subject_inventory_errors(
                fixture.subjects,
                fixture.components,
                fixture.policy,
                fixture.release,
                fixture.subject_root,
            )
            self.assertTrue(any("digest mismatch" in error for error in errors))

    def test_stale_license_override_for_other_component_bytes_blocks(self) -> None:
        build_root = REPOSITORY / "build"
        build_root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="supply-license-", dir=build_root) as temporary:
            fixture = SupplyChainFixture(Path(temporary))
            overrides = read_json(OVERRIDES_PATH)
            stale_component_id = overrides["overrides"][0]["componentId"]
            components = copy.deepcopy(fixture.components)
            stale_component = next(
                row
                for row in components["components"]
                if row["componentId"] == stale_component_id
            )
            stale_component["digest"] = _digest("substituted-vendored-bytes")
            _seal(stale_component, "recordDigest")
            _seal(components, "inventoryDigest")
            licenses = copy.deepcopy(fixture.licenses)
            licenses["componentInventoryDigest"] = components["inventoryDigest"]
            _seal(licenses, "licenseInventoryDigest")
            errors = license_inventory_errors(
                licenses,
                components,
                fixture.policy,
                fixture.license_root,
                overrides,
            )
            self.assertTrue(any("stale" in error for error in errors))

            unused = copy.deepcopy(fixture.licenses)
            next(
                row
                for row in unused["components"]
                if row["componentId"]
                == fixture.override_registry["overrides"][0]["componentId"]
            )["decisionSource"] = "reviewed-metadata"
            _seal(unused, "licenseInventoryDigest")
            errors = license_inventory_errors(
                unused,
                fixture.components,
                fixture.policy,
                fixture.license_root,
                overrides,
            )
            self.assertTrue(any("unused" in error for error in errors))

            duplicated = copy.deepcopy(overrides)
            duplicate = copy.deepcopy(duplicated["overrides"][0])
            duplicate["rationale"] += " Duplicate identity fixture."
            duplicated["overrides"].append(duplicate)
            _seal(duplicated, "overridesDigest")
            errors = license_inventory_errors(
                fixture.licenses,
                fixture.components,
                fixture.policy,
                fixture.license_root,
                duplicated,
            )
            self.assertTrue(any("duplicated" in error for error in errors))

    def test_publication_requires_exact_receipt_and_fresh_observation(self) -> None:
        summary = _promotion_summary(self.policy)
        assets = [
            {
                "role": role,
                "fileName": PUBLICATION_ROLE_FILES[role],
                "digest": _digest(role),
                "size": 10,
                "uri": (
                    self.policy["publicationPolicy"]["immutableBaseUri"]
                    + f"/v300/{PUBLICATION_ROLE_FILES[role]}"
                ),
            }
            for role in self.policy["publicationPolicy"]["requiredRoles"]
        ]
        plan = _seal({"schemaVersion": 1, "kind": "stable-1.0-supply-chain-publication-plan", **self.release, "summaryDigest": summary["summaryDigest"], "assets": assets, "overwriteAllowed": False, "allowedOperations": ["created", "verified-existing"], "sideEffectsPerformed": False, "planDigest": ""}, "planDigest")
        receipt = _seal({"schemaVersion": 1, "kind": "stable-1.0-supply-chain-publication-receipt", **self.release, "planDigest": plan["planDigest"], "generatedAt": "2026-08-04T00:30:00Z", "backendIdentity": "cryptad-publication-backend", "workflowIdentity": "github.com/crypta-network/cryptad/.github/workflows/stable-1.0-maintenance-release.yml@" + SOURCE_COMMIT, "attestationDigest": _digest("publication-attestation"), "backendAuthenticated": True, "operations": [{"role": row["role"], "digest": row["digest"], "size": row["size"], "uri": row["uri"], "operation": "verified-existing"} for row in assets], "receiptDigest": ""}, "receiptDigest")
        observation = _seal({"schemaVersion": 1, "kind": "stable-1.0-supply-chain-public-observation", **self.release, "receiptDigest": receipt["receiptDigest"], "observedAt": "2026-08-04T00:45:00Z", "observerIdentity": "cryptad-public-observer", "observerAttestationDigest": _digest("observer"), "observerAuthenticated": True, "assets": [{"role": row["role"], "digest": row["digest"], "size": row["size"], "uri": row["uri"]} for row in assets], "observationDigest": ""}, "observationDigest")
        self.assertEqual(publication_errors(plan, receipt, observation, summary, self.release, self.policy, "2026-08-04T01:00:00Z"), [])
        for field, conflicting_value in (
            ("tag", "v999"),
            ("sourceRef", "refs/heads/attacker"),
        ):
            with self.subTest(field=field):
                conflicting_plan = copy.deepcopy(plan)
                conflicting_plan[field] = conflicting_value
                _seal(conflicting_plan, "planDigest")
                conflicting_receipt = copy.deepcopy(receipt)
                conflicting_receipt[field] = conflicting_value
                conflicting_receipt["planDigest"] = conflicting_plan["planDigest"]
                _seal(conflicting_receipt, "receiptDigest")
                conflicting_observation = copy.deepcopy(observation)
                conflicting_observation[field] = conflicting_value
                conflicting_observation["receiptDigest"] = conflicting_receipt[
                    "receiptDigest"
                ]
                _seal(conflicting_observation, "observationDigest")

                coordinate_errors = publication_errors(
                    conflicting_plan,
                    conflicting_receipt,
                    conflicting_observation,
                    summary,
                    self.release,
                    self.policy,
                    "2026-08-04T01:00:00Z",
                )

                for label in (
                    "publication plan",
                    "publication receipt",
                    "public observation",
                ):
                    self.assertIn(f"{label} {field} differs", coordinate_errors)
        misnamed_plan = copy.deepcopy(plan)
        misnamed_plan["assets"][0]["fileName"] = "stable-1.0-sbom.spdx.json"
        _seal(misnamed_plan, "planDigest")
        misnamed_receipt = copy.deepcopy(receipt)
        misnamed_receipt["planDigest"] = misnamed_plan["planDigest"]
        _seal(misnamed_receipt, "receiptDigest")
        misnamed_observation = copy.deepcopy(observation)
        misnamed_observation["receiptDigest"] = misnamed_receipt["receiptDigest"]
        _seal(misnamed_observation, "observationDigest")
        self.assertTrue(
            any(
                "policy-derived immutable target" in error
                for error in publication_errors(
                    misnamed_plan,
                    misnamed_receipt,
                    misnamed_observation,
                    summary,
                    self.release,
                    self.policy,
                    "2026-08-04T01:00:00Z",
                )
            )
        )
        conflicting = copy.deepcopy(observation)
        conflicting["assets"][0]["digest"] = _digest("conflicting-existing-bytes")
        _seal(conflicting, "observationDigest")
        self.assertTrue(publication_errors(plan, receipt, conflicting, summary, self.release, self.policy, "2026-08-04T01:00:00Z"))
        observation["observedAt"] = "2026-08-03T00:00:00Z"
        _seal(observation, "observationDigest")
        self.assertTrue(publication_errors(plan, receipt, observation, summary, self.release, self.policy, "2026-08-04T01:00:00Z"))

    def test_publication_rejects_tampered_or_inconsistent_promotion_summary(self) -> None:
        summary = _promotion_summary(self.policy)
        self.assertEqual(promotion_summary_errors(summary, self.release), [])

        failed = copy.deepcopy(summary)
        failed["status"] = "fail"
        failed["promotionReady"] = False
        failed["blockers"] = [
            {
                "evidenceId": "stable-supply-chain.release-promotion",
                "message": "Deterministic adversarial publication fixture.",
            }
        ]
        failed["redaction"]["status"] = "fail"
        _seal(failed, "summaryDigest")
        failed["promotionReady"] = True

        tampered_errors = promotion_summary_errors(failed, self.release)
        self.assertTrue(
            any("summaryDigest is invalid" in error for error in tampered_errors),
            tampered_errors,
        )
        self.assertTrue(
            any("readiness is inconsistent" in error for error in tampered_errors),
            tampered_errors,
        )

        wrong_release = copy.deepcopy(summary)
        wrong_release["releaseId"] = "stable-maintenance-301"
        _seal(wrong_release, "summaryDigest")
        self.assertTrue(
            any(
                "releaseId differs" in error
                for error in promotion_summary_errors(wrong_release, self.release)
            )
        )

        inconsistent = copy.deepcopy(summary)
        inconsistent["status"] = "fail"
        _seal(inconsistent, "summaryDigest")
        self.assertTrue(
            any(
                "status is inconsistent" in error
                for error in promotion_summary_errors(inconsistent, self.release)
            )
        )

    def test_verify_publication_rejects_tampered_summary_before_publication_inputs(self) -> None:
        tampered = _promotion_summary(self.policy)
        tampered["promotionReady"] = False
        manifest = RunManifest(
            path=REPOSITORY / "manifest.json",
            release=ReleaseSpec(
                self.release["releaseId"],
                str(self.release["buildVersion"]),
                "stable-review",
            ),
            output=OutputSpec(REPOSITORY / "build"),
            requirements={"stableSupplyChain": True},
            inputs={},
            policies={
                "artifactBaseUri": self.policy["publicationPolicy"]["immutableBaseUri"]
            },
            execution={"evaluationClock": "2026-08-04T01:00:00Z"},
            commands={"stable-supply-chain": {"mode": "verify-publication"}},
        )
        context = RunContext(
            REPOSITORY, REPOSITORY / "build", "stable-supply-chain", manifest
        )

        with (
            patch.object(
                engine,
                "_load_policy_and_release",
                return_value=(self.policy, self.release),
            ),
            patch.object(
                engine,
                "_required_value",
                side_effect=(tampered, {}, {}, {}),
            ),
            self.assertRaisesRegex(ValueError, "summaryDigest is invalid"),
        ):
            engine._verify_publication(context, REPOSITORY / "build")

    def test_publication_rejects_self_consistent_arbitrary_https_targets(self) -> None:
        summary = _promotion_summary(self.policy)
        assets = [
            {
                "role": role,
                "fileName": PUBLICATION_ROLE_FILES[role],
                "digest": _digest(role),
                "size": 10,
                "uri": f"https://attacker.example/v300/{PUBLICATION_ROLE_FILES[role]}",
            }
            for role in self.policy["publicationPolicy"]["requiredRoles"]
        ]
        plan = _seal({"schemaVersion": 1, "kind": "stable-1.0-supply-chain-publication-plan", **self.release, "summaryDigest": summary["summaryDigest"], "assets": assets, "overwriteAllowed": False, "allowedOperations": ["created", "verified-existing"], "sideEffectsPerformed": False, "planDigest": ""}, "planDigest")
        receipt = _seal({"schemaVersion": 1, "kind": "stable-1.0-supply-chain-publication-receipt", **self.release, "planDigest": plan["planDigest"], "generatedAt": "2026-08-04T00:30:00Z", "backendIdentity": "cryptad-publication-backend", "workflowIdentity": "github.com/crypta-network/cryptad/.github/workflows/stable-1.0-maintenance-release.yml@" + SOURCE_COMMIT, "attestationDigest": _digest("publication-attestation"), "backendAuthenticated": True, "operations": [{"role": row["role"], "digest": row["digest"], "size": row["size"], "uri": row["uri"], "operation": "verified-existing"} for row in assets], "receiptDigest": ""}, "receiptDigest")
        observation = _seal({"schemaVersion": 1, "kind": "stable-1.0-supply-chain-public-observation", **self.release, "receiptDigest": receipt["receiptDigest"], "observedAt": "2026-08-04T00:45:00Z", "observerIdentity": "cryptad-public-observer", "observerAttestationDigest": _digest("observer"), "observerAuthenticated": True, "assets": [{"role": row["role"], "digest": row["digest"], "size": row["size"], "uri": row["uri"]} for row in assets], "observationDigest": ""}, "observationDigest")

        errors = publication_errors(plan, receipt, observation, summary, self.release, self.policy, "2026-08-04T01:00:00Z")

        self.assertTrue(any("policy-derived immutable target" in error for error in errors), errors)

    def test_promotion_rejects_expired_or_ledger_stale_vulnerability_summary(self) -> None:
        manifest = RunManifest(
            path=REPOSITORY / "manifest.json",
            release=ReleaseSpec("stable-maintenance-300", "300", "stable-review"),
            output=OutputSpec(REPOSITORY / "build"),
            requirements={"stableSupplyChain": True},
            inputs={
                "stableVulnerabilitySummary": "stable-1.0-vulnerability-summary.json"
            },
            policies={},
            execution={"evaluationClock": "2026-08-04T01:00:00Z"},
            commands={"stable-supply-chain": {"mode": "evaluate-promotion"}},
        )
        context = RunContext(
            REPOSITORY, REPOSITORY / "build", "stable-supply-chain", manifest
        )
        for authentication_error in (
            "Stable vulnerability summary is stale or from the future",
            "Stable vulnerability summary ledger digest is superseded by the current ledger tip",
        ):
            with self.subTest(authentication_error=authentication_error):
                with patch.object(
                    engine,
                    "load_summary",
                    return_value=({}, [authentication_error]),
                ):
                    with self.assertRaisesRegex(
                        ValueError, "vulnerability summary authentication failed"
                    ):
                        engine._authenticated_vulnerability_summary(context)

    def test_resolved_graph_keeps_runtime_build_and_test_roles_separate(self) -> None:
        build_root = REPOSITORY / "build"
        build_root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="supply-roles-", dir=build_root) as temporary:
            fixture = SupplyChainFixture(Path(temporary))
            snapshot = copy.deepcopy(fixture.snapshot)
            rows = []
            for role, suffix in (("runtime", "a"), ("build", "b"), ("test", "c")):
                row = copy.deepcopy(snapshot["components"][0])
                row["componentId"] = f"pkg:maven/example/{suffix}@1.0.0"
                row["coordinates"] = f"example:{suffix}:1.0.0"
                row["version"] = "1.0.0"
                row["roles"] = [role]
                row["artifactDigest"] = _digest(role)
                rows.append(row)
            snapshot["components"] = rows
            snapshot["configurations"] = [
                {
                    "project": ":",
                    "name": role + "Classpath",
                    "role": role,
                    "attributes": [],
                    "componentIds": [rows[index]["componentId"]],
                    "resolutionDigest": _digest("resolution:" + role),
                }
                for index, role in enumerate(("runtime", "build", "test"))
            ]
            snapshot["configurations"].append(
                {
                    "project": ":build-logic",
                    "name": "runtimeClasspath",
                    "role": "build",
                    "attributes": [],
                    "componentIds": [rows[1]["componentId"]],
                    "resolutionDigest": _digest("resolution:build-logic"),
                }
            )
            snapshot["configurations"].extend(
                {
                    "project": ":build-logic",
                    "name": name,
                    "role": "build",
                    "attributes": [],
                    "componentIds": [rows[1]["componentId"]],
                    "resolutionDigest": _digest("resolution:" + name),
                }
                for name in (
                    "buildLogicSettingsPluginClasspath",
                    "rootSettingsPluginClasspath",
                )
            )
            snapshot["configurations"].sort(
                key=lambda row: (row["project"], row["name"], row["role"])
            )
            _seal(snapshot, "snapshotDigest")
            self.assertEqual(resolution_snapshot_errors(snapshot, fixture.release, fixture.policy), [])
            self.assertEqual({row["roles"][0] for row in snapshot["components"]}, {"runtime", "build", "test"})

    def test_resolution_and_verification_drift_cases_block(self) -> None:
        build_root = REPOSITORY / "build"
        build_root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="supply-drift-", dir=build_root) as temporary:
            fixture = SupplyChainFixture(Path(temporary))
            mutations = (
                lambda value: value["dependencyVerification"].update(status="failed"),
                lambda value: value["locking"].update(status="drifted"),
                lambda value: value["components"][0].update(verificationStatus="unverified"),
                lambda value: value["components"][0].update(changing=True),
                lambda value: value["components"][0].update(version="latest"),
            )
            for mutate in mutations:
                with self.subTest(mutation=mutate):
                    snapshot = copy.deepcopy(fixture.snapshot)
                    mutate(snapshot)
                    _seal(snapshot, "snapshotDigest")
                    self.assertTrue(resolution_snapshot_errors(snapshot, fixture.release, fixture.policy))

            internal = copy.deepcopy(fixture.snapshot)
            internal_component = internal["components"][0]
            internal_component["componentId"] = (
                "pkg:generic/cryptad-module/cryptad@300?commit=" + SOURCE_COMMIT
            )
            internal_component["coordinates"] = "cryptad:300"
            internal_component["version"] = "300"
            internal_component["componentKind"] = "internal-project"
            internal_component["verificationStatus"] = "authenticated-first-party"
            for configuration in internal["configurations"]:
                configuration["componentIds"] = [internal_component["componentId"]]
            _seal(internal, "snapshotDigest")
            self.assertEqual(
                resolution_snapshot_errors(internal, fixture.release, fixture.policy), []
            )
            internal_graph_component = _component(
                [row["subjectKey"] for row in _required_subject_rules(fixture.policy)]
            )
            internal_graph_component.update(
                {
                    "componentId": internal_component["componentId"],
                    "componentKind": "internal-module",
                    "name": "cryptad",
                    "version": "300",
                    "namespace": "cryptad",
                    "purl": internal_component["componentId"],
                    "digest": internal_component["artifactDigest"],
                    "origin": {
                        "type": "repository-source",
                        "uri": "https://github.com/crypta-network/cryptad",
                        "immutableReference": SOURCE_COMMIT,
                        "provenanceDigest": _digest("source-provenance"),
                    },
                    "resolved": {
                        "coordinates": internal_component["coordinates"],
                        "selectedVariant": internal_component["selectedVariant"],
                        "attributes": internal_component["attributes"],
                    },
                    "roles": internal_component["roles"],
                    "relationships": {
                        "direct": internal_component["direct"],
                        "parents": internal_component["parents"],
                        "contains": [],
                        "dependsOn": [],
                    },
                    "dependencyVerificationStatus": "not-applicable",
                    "buildMaterialStatus": "built",
                }
            )
            _seal(internal_graph_component, "recordDigest")
            internal_graph = _seal(
                {
                    "schemaVersion": 1,
                    "kind": "stable-1.0-component-inventory",
                    "releaseId": fixture.release["releaseId"],
                    "buildVersion": fixture.release["buildVersion"],
                    "sourceCommit": SOURCE_COMMIT,
                    "policyDigest": fixture.policy["policyDigest"],
                    "resolvedDependencySnapshotDigest": internal["snapshotDigest"],
                    "components": [internal_graph_component],
                    "inventoryDigest": "",
                },
                "inventoryDigest",
            )
            self.assertEqual(
                component_inventory_errors(
                    internal_graph, fixture.policy, fixture.release
                ),
                [],
            )
            self.assertEqual(
                engine._resolved_component_coverage_errors(internal, internal_graph), []
            )
            internal_graph_component["componentKind"] = "maven"
            _seal(internal_graph_component, "recordDigest")
            _seal(internal_graph, "inventoryDigest")
            self.assertTrue(
                engine._resolved_component_coverage_errors(internal, internal_graph)
            )

            spoofed = copy.deepcopy(fixture.snapshot)
            spoofed["components"][0]["verificationStatus"] = "authenticated-first-party"
            _seal(spoofed, "snapshotDigest")
            self.assertTrue(
                any(
                    "spoofs first-party authentication" in error
                    for error in resolution_snapshot_errors(
                        spoofed, fixture.release, fixture.policy
                    )
                )
            )

    def test_partial_gradle_lockfile_cannot_replace_reviewed_resolution_export(self) -> None:
        build_root = REPOSITORY / "build"
        build_root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="supply-lock-", dir=build_root) as temporary:
            fixture = SupplyChainFixture(Path(temporary))
            claimed_locked = copy.deepcopy(fixture.snapshot)
            claimed_locked["locking"] = {
                "status": "locked",
                "snapshotMode": "gradle-locking",
                "lockDigest": _digest("one-partial-gradle.lockfile"),
            }
            _seal(claimed_locked, "snapshotDigest")

            errors = resolution_snapshot_errors(
                claimed_locked, fixture.release, fixture.policy
            )

            self.assertTrue(errors)
            schema = read_json(
                REPOSITORY
                / "tools/release-certification/schemas/"
                "stable-1.0-resolved-dependency-snapshot-v1.schema.json"
            )
            locking_schema = schema["properties"]["locking"]["properties"]
            self.assertEqual(
                locking_schema["status"]["enum"],
                ["authenticated-snapshot", "unlocked", "drifted"],
            )
            self.assertEqual(
                locking_schema["snapshotMode"]["const"],
                "authenticated-resolution-snapshot",
            )
            projection = (
                REPOSITORY
                / "build-logic/src/main/kotlin/cryptad/"
                "StableSupplyChainSnapshotProjection.kt"
            ).read_text(encoding="utf-8")
            self.assertNotIn("lockMaterials", projection)
            self.assertIn(
                'if (reviewedExportMatches) "authenticated-snapshot" else "unlocked"',
                projection,
            )
            self.assertIn(
                '"snapshotMode" to "authenticated-resolution-snapshot"', projection
            )

    def test_resolution_requires_compiler_and_settings_plugin_materials(self) -> None:
        build_root = REPOSITORY / "build"
        build_root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="supply-tool-resolution-", dir=build_root
        ) as temporary:
            fixture = SupplyChainFixture(Path(temporary))
            snapshot = copy.deepcopy(fixture.snapshot)
            component_id = snapshot["components"][0]["componentId"]
            snapshot["configurations"].extend(
                [
                    {
                        "project": ":",
                        "name": "annotationProcessor",
                        "role": "build",
                        "attributes": [],
                        "componentIds": [component_id],
                        "resolutionDigest": _digest("annotation-processor"),
                    },
                    {
                        "project": ":",
                        "name": "compileClasspath",
                        "role": "build",
                        "attributes": [],
                        "componentIds": [component_id],
                        "resolutionDigest": _digest("compile-classpath"),
                    },
                    {
                        "project": ":",
                        "name": "testAnnotationProcessor",
                        "role": "test",
                        "attributes": [],
                        "componentIds": [component_id],
                        "resolutionDigest": _digest("test-annotation-processor"),
                    },
                    {
                        "project": ":",
                        "name": "testCompileClasspath",
                        "role": "test",
                        "attributes": [],
                        "componentIds": [component_id],
                        "resolutionDigest": _digest("test-compile-classpath"),
                    },
                ]
            )
            snapshot["components"][0]["roles"] = ["runtime", "build", "test"]
            snapshot["configurations"].sort(
                key=lambda row: (row["project"], row["name"], row["role"])
            )
            _seal(snapshot, "snapshotDigest")
            self.assertEqual(
                resolution_snapshot_errors(snapshot, fixture.release, fixture.policy),
                [],
            )

            for missing_name, expected in (
                ("annotationProcessor", "omits required annotationProcessor"),
                (
                    "testAnnotationProcessor",
                    "omits required testAnnotationProcessor",
                ),
                (
                    "rootSettingsPluginClasspath",
                    "omits required settings-plugin configuration",
                ),
            ):
                with self.subTest(missing_name=missing_name):
                    incomplete = copy.deepcopy(snapshot)
                    incomplete["configurations"] = [
                        row
                        for row in incomplete["configurations"]
                        if row["name"] != missing_name
                    ]
                    _seal(incomplete, "snapshotDigest")
                    errors = resolution_snapshot_errors(
                        incomplete, fixture.release, fixture.policy
                    )
                    self.assertTrue(
                        any(expected in error for error in errors), errors
                    )

    def test_component_graph_fields_must_exactly_match_authenticated_resolution(self) -> None:
        build_root = REPOSITORY / "build"
        build_root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="supply-component-binding-", dir=build_root
        ) as temporary:
            fixture = SupplyChainFixture(Path(temporary))
            self.assertEqual(
                engine._resolved_component_coverage_errors(
                    fixture.snapshot, fixture.components
                ),
                [],
            )
            mutations = {
                "digest": lambda row: row.update(digest=_digest("substituted")),
                "version": lambda row: row.update(version="9.9.9"),
                "roles": lambda row: row.update(roles=["runtime"]),
                "selected variant": lambda row: row["resolved"].update(
                    selectedVariant="otherElements"
                ),
                "resolved attributes": lambda row: row["resolved"].update(
                    attributes=[]
                ),
                "direct relationship": lambda row: row["relationships"].update(
                    direct=False
                ),
                "parent relationships": lambda row: row["relationships"].update(
                    parents=["pkg:maven/example/parent@1.0.0"]
                ),
                "dependency relationships": lambda row: row[
                    "relationships"
                ].update(dependsOn=["pkg:maven/example/child@1.0.0"]),
                "origin": lambda row: row["origin"].update(type="repository-source"),
                "immutable origin": lambda row: row["origin"].update(
                    immutableReference=_digest("different-origin")
                ),
            }
            for expected, mutate in mutations.items():
                with self.subTest(field=expected):
                    inventory = copy.deepcopy(fixture.components)
                    component = next(
                        row
                        for row in inventory["components"]
                        if row["componentId"] == fixture.component["componentId"]
                    )
                    mutate(component)
                    _seal(component, "recordDigest")
                    _seal(inventory, "inventoryDigest")
                    errors = engine._resolved_component_coverage_errors(
                        fixture.snapshot, inventory
                    )
                    self.assertTrue(
                        any(expected in error for error in errors),
                        errors,
                    )

    def test_subject_class_and_class_specific_metadata_are_policy_closed(self) -> None:
        build_root = REPOSITORY / "build"
        build_root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="supply-subject-metadata-", dir=build_root
        ) as temporary:
            fixture = SupplyChainFixture(Path(temporary))
            self.assertEqual(
                subject_inventory_errors(
                    fixture.subjects,
                    fixture.components,
                    fixture.policy,
                    fixture.release,
                ),
                [],
            )
            mutations = (
                ("core-jar", lambda row: row.update(subjectClass="portable"), "subject class"),
                (
                    "core-jar",
                    lambda row: row.update(
                        app=copy.deepcopy(
                            next(
                                item["app"]
                                for item in fixture.subjects["subjects"]
                                if item["subjectKey"] == "app-feed-reader"
                            )
                        )
                    ),
                    "prohibited app metadata",
                ),
                (
                    "stable-catalog",
                    lambda row: row.update(catalogEdition=None),
                    "lacks catalog metadata",
                ),
                (
                    "stable-catalog-signature",
                    lambda row: row.update(signatureReceiptDigest=None),
                    "lacks signature receipt metadata",
                ),
                (
                    "core-jar",
                    lambda row: row.update(packageMetadataDigest=None),
                    "lacks package metadata",
                ),
                (
                    "release-notes",
                    lambda row: row.update(packageMetadataDigest=_digest("unexpected")),
                    "prohibited package metadata",
                ),
            )
            for subject_key, mutate, expected in mutations:
                with self.subTest(subject=subject_key, expected=expected):
                    subjects = copy.deepcopy(fixture.subjects)
                    subject = next(
                        row
                        for row in subjects["subjects"]
                        if row["subjectKey"] == subject_key
                    )
                    mutate(subject)
                    _seal(subjects, "subjectInventoryDigest")
                    errors = subject_inventory_errors(
                        subjects,
                        fixture.components,
                        fixture.policy,
                        fixture.release,
                    )
                    self.assertTrue(any(expected in error for error in errors), errors)

    def test_runtime_components_cannot_map_to_non_product_subjects(self) -> None:
        build_root = REPOSITORY / "build"
        build_root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="supply-runtime-subject-", dir=build_root
        ) as temporary:
            fixture = SupplyChainFixture(Path(temporary))
            components = copy.deepcopy(fixture.components)
            component = next(
                row
                for row in components["components"]
                if row["componentId"] == fixture.component["componentId"]
            )
            component["subjectKeys"] = ["release-notes"]
            _seal(component, "recordDigest")
            _seal(components, "inventoryDigest")
            subjects = copy.deepcopy(fixture.subjects)
            for subject in subjects["subjects"]:
                if subject["subjectKey"] == "release-notes":
                    subject["componentIds"] = sorted(
                        [*subject["componentIds"], component["componentId"]]
                    )
                else:
                    subject["componentIds"] = [
                        value
                        for value in subject["componentIds"]
                        if value != component["componentId"]
                    ]
            subjects["componentInventoryDigest"] = components["inventoryDigest"]
            _seal(subjects, "subjectInventoryDigest")

            errors = subject_inventory_errors(
                subjects,
                components,
                fixture.policy,
                fixture.release,
            )

            self.assertTrue(
                any("maps to non-product subject release-notes" in error for error in errors),
                errors,
            )
            self.assertTrue(
                any("not contained by an actual product subject" in error for error in errors),
                errors,
            )

    def test_jdk_modules_and_canonical_environment_drift_block(self) -> None:
        build_root = REPOSITORY / "build"
        build_root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="supply-jdk-", dir=build_root) as temporary:
            fixture = SupplyChainFixture(Path(temporary))
            self.assertEqual(
                build_material_errors(
                    fixture.materials,
                    fixture.release,
                    fixture.snapshot["snapshotDigest"],
                    fixture.policy,
                ),
                [],
            )
            for field, value in (("timezone", "America/New_York"), ("encoding", "ISO-8859-1"), ("locale", "en_US.UTF-8")):
                materials = copy.deepcopy(fixture.materials)
                materials["environment"][field] = value
                _seal(materials, "materialsDigest")
                self.assertTrue(build_material_errors(materials, fixture.release, fixture.snapshot["snapshotDigest"]))
            materials = copy.deepcopy(fixture.materials)
            materials["jdk"]["modules"] = ["java.logging", "java.base"]
            _seal(materials, "materialsDigest")
            self.assertTrue(any("JDK module" in error for error in build_material_errors(materials, fixture.release, fixture.snapshot["snapshotDigest"])))
            materials = copy.deepcopy(fixture.materials)
            materials["packagingInputs"] = [
                row
                for row in materials["packagingInputs"]
                if row["path"] != "external/seedrefs-source-archive"
            ]
            _seal(materials, "materialsDigest")
            self.assertTrue(
                any(
                    "authenticated direct input" in error
                    for error in build_material_errors(
                        materials,
                        fixture.release,
                        fixture.snapshot["snapshotDigest"],
                        fixture.policy,
                    )
                )
            )

            materials = copy.deepcopy(fixture.materials)
            materials["canonicalBuildEpoch"] += 1
            _seal(materials, "materialsDigest")
            self.assertTrue(
                any(
                    "authenticated source commit time" in error
                    for error in build_material_errors(
                        materials,
                        fixture.release,
                        fixture.snapshot["snapshotDigest"],
                        fixture.policy,
                    )
                )
            )

    def test_mutable_or_substituted_direct_input_origins_block(self) -> None:
        build_root = REPOSITORY / "build"
        build_root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="supply-direct-origin-", dir=build_root
        ) as temporary:
            fixture = SupplyChainFixture(Path(temporary))
            rejected = (
                (
                    "seedrefs-source-archive",
                    "https://codeload.github.com/hyphanet/seedrefs/zip/refs/heads/master",
                ),
                (
                    "seedrefs-source-archive",
                    "https://codeload.github.com/hyphanet/seedrefs/zip/abcdef0",
                ),
                (
                    "windows-wrapper-amd64",
                    "https://api.github.com/repos/crypta-network/wrapper-windows-build/releases/latest",
                ),
                (
                    "windows-wrapper-amd64",
                    "https://github.com/other/wrapper-windows-build/releases/download/v1/a.zip",
                ),
            )
            for name, origin in rejected:
                materials = copy.deepcopy(fixture.materials)
                next(
                    row for row in materials["directInputs"] if row["name"] == name
                )["origin"] = origin
                _seal(materials, "materialsDigest")
                errors = build_material_errors(
                    materials,
                    fixture.release,
                    fixture.snapshot["snapshotDigest"],
                    fixture.policy,
                )
                self.assertTrue(any("mutable origin" in error for error in errors), errors)

            receipt = fixture.receipt("candidate-producer", 101)
            receipt["directInputs"][1]["origin"] = (
                "https://codeload.github.com/hyphanet/seedrefs/zip/"
                + "b" * 40
            )
            _seal(receipt, "receiptDigest")
            errors = builder_receipt_errors(
                receipt,
                "candidate-producer",
                fixture.release,
                fixture.policy,
                fixture.materials["materialsDigest"],
                fixture.snapshot["snapshotDigest"],
                fixture.materials,
                fixture.subjects,
                fixture.snapshot,
            )
            self.assertTrue(
                any("authenticated build materials" in error for error in errors), errors
            )

            materials = copy.deepcopy(fixture.materials)
            materials["environment"]["allowedVariableNames"].remove("LC_ALL")
            _seal(materials, "materialsDigest")
            self.assertTrue(
                any(
                    "environment variable names differ" in error
                    for error in build_material_errors(
                        materials,
                        fixture.release,
                        fixture.snapshot["snapshotDigest"],
                        fixture.policy,
                    )
                )
            )

    def test_observed_java_and_environment_bind_to_authenticated_materials(self) -> None:
        build_root = REPOSITORY / "build"
        build_root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="supply-java-", dir=build_root) as temporary:
            fixture = SupplyChainFixture(Path(temporary))
            installation = fixture.materials["jdk"]["installations"][0]
            java = observed_java_identity(
                {
                    "java.vendor": "Eclipse Adoptium",
                    "java.specification.version": "25",
                    "java.runtime.version": "25.0.4.1+1-LTS",
                    "file.encoding": "UTF-8",
                    "os.arch": "x86_64",
                },
                installation,
            )
            environment = {
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "SOURCE_DATE_EPOCH": "1785801600",
                "TZ": "UTC",
            }
            self.assertEqual(java["javaBuild"], "25.0.4.1+1")
            self.assertEqual(
                builder_observation_errors(
                    java, environment, fixture.materials, "linux"
                ),
                [],
            )
            for field, value in (
                ("javaVendor", "Unexpected Vendor"),
                ("javaVersion", "26"),
                ("javaBuild", "25.0.3+10"),
                ("javaEncoding", "ISO-8859-1"),
                ("javaArchitecture", "arm64"),
                ("javaInstallationManifestDigest", _digest("substituted-jdk")),
                ("javaReleaseFileDigest", _digest("substituted-release")),
            ):
                with self.subTest(field=field):
                    changed = copy.deepcopy(java)
                    changed[field] = value
                    self.assertTrue(
                        builder_observation_errors(
                            changed, environment, fixture.materials, "linux"
                        )
                    )
            changed_environment = copy.deepcopy(environment)
            changed_environment["TZ"] = "Europe/Paris"
            self.assertTrue(
                builder_observation_errors(
                    java, changed_environment, fixture.materials, "linux"
                )
            )
            with self.assertRaisesRegex(ValueError, "architecture"):
                observed_java_identity(
                    {
                        "java.vendor": "Eclipse Adoptium",
                        "java.specification.version": "25",
                        "java.runtime.version": "25.0.4.1+1",
                        "file.encoding": "UTF-8",
                        "os.arch": "sparc",
                    },
                    installation,
                )
            with self.assertRaisesRegex(ValueError, "canonical Stable JDK build"):
                observed_java_identity(
                    {
                        "java.vendor": "Eclipse Adoptium",
                        "java.specification.version": "25",
                        "java.runtime.version": "25.0.4.1+1-vendor-modified",
                        "file.encoding": "UTF-8",
                        "os.arch": "x86_64",
                    },
                    installation,
                )

    def test_jdk_installation_identity_is_path_independent_and_content_bound(self) -> None:
        build_root = REPOSITORY / "build"
        build_root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="supply-jdk-tree-", dir=build_root) as temporary:
            root = Path(temporary)

            def installation(name: str) -> Path:
                java_home = root / name
                (java_home / "bin").mkdir(parents=True)
                (java_home / "lib/empty").mkdir(parents=True)
                (java_home / "release").write_bytes(b'JAVA_VERSION="25.0.3"\n')
                (java_home / "bin/java").write_bytes(b"exact-java-binary")
                (java_home / "bin/current").symlink_to("java")
                return java_home

            first_root = installation("first")
            second_root = installation("second")
            first = jdk_installation_identity(first_root)
            second = jdk_installation_identity(second_root)

            self.assertEqual(first, second)
            self.assertNotIn(str(first_root), repr(first))
            (second_root / "bin/java").write_bytes(b"substituted-java-binary")
            self.assertNotEqual(first, jdk_installation_identity(second_root))
            (second_root / "escape").symlink_to("../outside")
            with self.assertRaisesRegex(ValueError, "escaping symbolic link"):
                jdk_installation_identity(second_root)

    def test_jdk_modules_are_required_exact_canonical_components(self) -> None:
        build_root = REPOSITORY / "build"
        build_root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="supply-jdk-components-", dir=build_root) as temporary:
            fixture = SupplyChainFixture(Path(temporary))
            self.assertEqual(
                jdk_component_coverage_errors(
                    fixture.components,
                    fixture.subjects,
                    fixture.materials,
                    fixture.policy,
                ),
                [],
            )
            components = copy.deepcopy(fixture.components)
            components["components"] = [
                row
                for row in components["components"]
                if row.get("name") != "java.logging"
            ]
            _seal(components, "inventoryDigest")
            errors = jdk_component_coverage_errors(
                components, fixture.subjects, fixture.materials, fixture.policy
            )
            self.assertTrue(any("authenticated runtime modules" in error for error in errors))

            components = copy.deepcopy(fixture.components)
            component = next(
                row for row in components["components"] if row.get("name") == "java.base"
            )
            component["digest"] = _digest("unreviewed-jdk-distribution")
            _seal(component, "recordDigest")
            _seal(components, "inventoryDigest")
            errors = jdk_component_coverage_errors(
                components, fixture.subjects, fixture.materials, fixture.policy
            )
            self.assertTrue(any("authenticated build materials" in error for error in errors))

    def test_canonical_mode_class_preserves_writable_regular_files(self) -> None:
        expected = {
            0o755: "executable",
            0o555: "executable",
            0o444: "read-only",
            0o400: "read-only",
            0o644: "regular",
            0o600: "regular",
            0o666: "regular",
            0o000: "regular",
        }
        self.assertEqual(
            {mode: canonical_mode_class(mode) for mode in expected}, expected
        )

        manifest = _seal(
            {
                "schemaVersion": 1,
                "kind": "stable-1.0-payload-manifest",
                "subjectKey": "amd64.rpm",
                "publishedSubjectDigest": _digest("rpm"),
                "packageType": "rpm",
                "normalizationRuleId": "crypta-rpm-payload-v1",
                "normalizationRuleVersion": 1,
                "preSigningPayloadDigest": _digest("stage"),
                "packageMetadataDigest": _digest("metadata"),
                "entries": [
                    {
                        "path": "opt/cryptad/config",
                        "kind": "file",
                        "digest": _digest("config"),
                        "size": 6,
                        "modeClass": "directory",
                        "symlinkTarget": None,
                        "componentIds": ["pkg:generic/cryptad-module/core@300"],
                    }
                ],
                "ignoredPaths": [],
                "limits": {
                    "entryCount": 1,
                    "expandedBytes": 6,
                    "nestedArchiveDepth": 0,
                },
                "manifestDigest": "",
            },
            "manifestDigest",
        )
        self.assertTrue(payload_manifest_errors(manifest, self.policy))

    def test_component_requires_exact_digest_approved_origin_and_consistent_license(self) -> None:
        build_root = REPOSITORY / "build"
        build_root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="supply-component-policy-", dir=build_root) as temporary:
            fixture = SupplyChainFixture(Path(temporary))
            for mutate, expected in (
                (lambda row: row.update(digest=None), "content digest"),
                (
                    lambda row: row["origin"].update(type="mutable-download"),
                    "unapproved origin",
                ),
                (
                    lambda row: row["license"].update(
                        status="not-applicable-internal", licenseTextDigest=None
                    ),
                    "inconsistent internal license",
                ),
            ):
                with self.subTest(expected=expected):
                    inventory = copy.deepcopy(fixture.components)
                    row = next(
                        value
                        for value in inventory["components"]
                        if value["componentId"] == fixture.component["componentId"]
                    )
                    mutate(row)
                    _seal(row, "recordDigest")
                    _seal(inventory, "inventoryDigest")
                    errors = component_inventory_errors(
                        inventory, fixture.policy, fixture.release
                    )
                    self.assertTrue(any(expected in error for error in errors), errors)

    def test_build_materials_bind_build_logic_plugin_test_and_key_identities(self) -> None:
        build_root = REPOSITORY / "build"
        build_root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="supply-material-binding-", dir=build_root) as temporary:
            fixture = SupplyChainFixture(Path(temporary))
            for field in (
                "buildLogicDigest",
                "pluginResolutionDigest",
                "testResolutionDigest",
                "verificationKeyringKeysDigest",
            ):
                with self.subTest(field=field):
                    materials = copy.deepcopy(fixture.materials)
                    materials["gradle"][field] = _digest("drift:" + field)
                    _seal(materials, "materialsDigest")
                    errors = build_material_errors(
                        materials,
                        fixture.release,
                        fixture.snapshot["snapshotDigest"],
                        fixture.policy,
                        fixture.snapshot,
                    )
                    self.assertTrue(any("different" in error for error in errors), errors)

    def test_license_notice_requirement_and_notice_set_digest_are_derived(self) -> None:
        build_root = REPOSITORY / "build"
        build_root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="supply-license-binding-", dir=build_root) as temporary:
            fixture = SupplyChainFixture(Path(temporary))
            licenses = copy.deepcopy(fixture.licenses)
            row = next(
                value
                for value in licenses["components"]
                if value["componentId"] == fixture.component["componentId"]
            )
            row["noticeRequired"] = False
            _seal(licenses, "licenseInventoryDigest")
            errors = license_inventory_errors(
                licenses,
                fixture.components,
                fixture.policy,
                fixture.license_root,
                fixture.override_registry,
            )
            self.assertTrue(any("notice" in error for error in errors), errors)

            licenses = copy.deepcopy(fixture.licenses)
            licenses["noticesDigest"] = _digest("caller-asserted-notices")
            _seal(licenses, "licenseInventoryDigest")
            errors = license_inventory_errors(
                licenses,
                fixture.components,
                fixture.policy,
                fixture.license_root,
                fixture.override_registry,
            )
            self.assertTrue(any("notice-set digest" in error for error in errors), errors)

    def test_builder_toolchain_and_task_set_drift_block(self) -> None:
        build_root = REPOSITORY / "build"
        build_root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="supply-builder-", dir=build_root) as temporary:
            fixture = SupplyChainFixture(Path(temporary))
            receipt = fixture.receipt("candidate-producer", 101)
            receipt["buildTasks"] = [":assembleCryptadDist"]
            _seal(receipt, "receiptDigest")
            errors = builder_receipt_errors(receipt, "candidate-producer", fixture.release, fixture.policy, _digest("other-materials"), fixture.snapshot["snapshotDigest"], fixture.materials, fixture.subjects, fixture.snapshot)
            self.assertTrue(any("task set" in error for error in errors))
            self.assertTrue(any("different build materials" in error for error in errors))
            receipt = fixture.receipt("candidate-producer", 101)
            receipt["directInputs"][0]["digest"] = _digest("substituted-direct-input")
            _seal(receipt, "receiptDigest")
            errors = builder_receipt_errors(
                receipt,
                "candidate-producer",
                fixture.release,
                fixture.policy,
                fixture.materials["materialsDigest"],
                fixture.snapshot["snapshotDigest"],
                fixture.materials,
                fixture.subjects,
                fixture.snapshot,
            )
            self.assertTrue(any("direct inputs differ" in error for error in errors))

    def test_reviewed_wrapper_and_db4o_overrides_bind_exact_bytes_and_texts(self) -> None:
        registry = read_json(OVERRIDES_PATH)
        by_name = {
            "db4o": REPOSITORY / "libs/db4o-7.4.58.jar",
            "java-service-wrapper": REPOSITORY / "libs/wrapper.jar",
        }
        self.assertEqual(registry["overridesDigest"], semantic_digest(registry, "overridesDigest"))
        self.assertEqual(len(registry["overrides"]), 2)
        for row in registry["overrides"]:
            name = next(name for name in by_name if name in row["componentId"])
            self.assertEqual(row["componentDigest"], file_digest(by_name[name]))
            self.assertEqual(row["licenseTextDigest"], file_digest(REPOSITORY / row["licenseTextPath"]))
        self.assertEqual(registry["policyEdition"], self.policy["edition"])
        build_root = REPOSITORY / "build"
        build_root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="supply-vendored-components-", dir=build_root
        ) as temporary:
            fixture = SupplyChainFixture(Path(temporary))
            self.assertEqual(
                component_inventory_errors(
                    fixture.components, fixture.policy, fixture.release
                ),
                [],
            )
            self.assertEqual(
                {row["componentId"] for row in fixture.vendored_components},
                {row["componentId"] for row in registry["overrides"]},
            )

    def test_missing_and_orphaned_license_texts_block(self) -> None:
        build_root = REPOSITORY / "build"
        build_root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="supply-notice-", dir=build_root) as temporary:
            fixture = SupplyChainFixture(Path(temporary))
            orphan = fixture.license_root / "docs/licenses/ORPHAN.txt"
            orphan.parent.mkdir(parents=True, exist_ok=True)
            orphan.write_text("orphan", encoding="utf-8")
            errors = license_inventory_errors(fixture.licenses, fixture.components, fixture.policy, fixture.license_root)
            self.assertTrue(any("orphaned" in error for error in errors))
            licenses = copy.deepcopy(fixture.licenses)
            component = next(
                row
                for row in fixture.components["components"]
                if row["componentId"] == fixture.component["componentId"]
            )
            component["license"]["status"] = "allowed-with-notice"
            component["license"]["expression"] = "MIT"
            component["license"]["licenseTextDigest"] = _digest("missing")
            _seal(component, "recordDigest")
            _seal(fixture.components, "inventoryDigest")
            licenses["componentInventoryDigest"] = fixture.components["inventoryDigest"]
            next(
                row
                for row in licenses["components"]
                if row["componentId"] == fixture.component["componentId"]
            ).update({"status": "allowed-with-notice", "expression": "MIT", "licenseTextPath": "docs/licenses/MIT.txt", "licenseTextDigest": _digest("missing"), "decisionSource": "reviewed-metadata"})
            _seal(licenses, "licenseInventoryDigest")
            errors = license_inventory_errors(licenses, fixture.components, fixture.policy, fixture.license_root)
            self.assertTrue(any("missing" in error for error in errors))

    def test_payload_duplicate_special_kind_and_expansion_bounds_block(self) -> None:
        manifest = _seal({"schemaVersion": 1, "kind": "stable-1.0-payload-manifest", "subjectKey": "amd64.rpm", "publishedSubjectDigest": _digest("rpm"), "packageType": "rpm", "normalizationRuleId": "crypta-rpm-payload-v1", "normalizationRuleVersion": 1, "preSigningPayloadDigest": _digest("stage"), "packageMetadataDigest": _digest("metadata"), "entries": [{"path": "opt/cryptad/core.jar", "kind": "file", "digest": _digest("one"), "size": 8, "modeClass": "regular", "symlinkTarget": None, "componentIds": [_component(["core-jar"])["componentId"]]}, {"path": "opt/cryptad/core.jar", "kind": "file", "digest": _digest("two"), "size": 8, "modeClass": "regular", "symlinkTarget": None, "componentIds": [_component(["core-jar"])["componentId"]]}], "ignoredPaths": [], "limits": {"entryCount": 2, "expandedBytes": 16, "nestedArchiveDepth": 0}, "manifestDigest": ""}, "manifestDigest")
        self.assertTrue(any("duplicate" in error for error in payload_manifest_errors(manifest, self.policy)))
        special = copy.deepcopy(manifest)
        special["entries"][1]["path"] = "opt/cryptad/device"
        special["entries"][1]["kind"] = "device"
        _seal(special, "manifestDigest")
        self.assertTrue(payload_manifest_errors(special, self.policy))
        bounded_policy = copy.deepcopy(self.policy)
        bounded_policy["publicArtifactBounds"]["maximumExpandedBytes"] = 4
        self.assertTrue(any("expansion" in error for error in payload_manifest_errors(manifest, bounded_policy)))

    def test_spdx_namespace_changes_with_release_identity(self) -> None:
        policy = copy.deepcopy(self.policy)
        policy["releaseSubjects"] = [{**row, "required": row["subjectKey"] == "core-jar"} for row in policy["releaseSubjects"]]
        component = _component(["core-jar"])
        components = _seal({"schemaVersion": 1, "kind": "stable-1.0-component-inventory", "releaseId": self.release["releaseId"], "buildVersion": 300, "sourceCommit": SOURCE_COMMIT, "policyDigest": self.policy["policyDigest"], "resolvedDependencySnapshotDigest": _digest("snapshot"), "components": [component], "inventoryDigest": ""}, "inventoryDigest")
        subjects = _seal({"schemaVersion": 1, "kind": "stable-1.0-release-subject-inventory", "releaseId": self.release["releaseId"], "buildVersion": 300, "sourceCommit": SOURCE_COMMIT, "policyDigest": self.policy["policyDigest"], "componentInventoryDigest": components["inventoryDigest"], "subjects": [{"subjectKey": "core-jar", "subjectClass": "core", "fileName": "core.jar", "digest": _digest("core"), "size": 4, "reproducibilityClass": "byte-identical", "payloadManifestDigest": None, "componentIds": [component["componentId"]], "app": None, "catalogEdition": None, "signatureReceiptDigest": None, "notarizationReceiptDigest": None, "packageMetadataDigest": None}], "subjectInventoryDigest": ""}, "subjectInventoryDigest")
        other_release = {**self.release, "releaseId": "stable-maintenance-301", "buildVersion": 301, "tag": "v301"}
        first = build_spdx(self.release, policy, components, subjects)
        second = build_spdx(other_release, policy, components, subjects)
        self.assertNotEqual(first["documentNamespace"], second["documentNamespace"])

    def test_fixture_maps_exactly_seven_apps_and_stable_catalog(self) -> None:
        build_root = REPOSITORY / "build"
        build_root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="supply-apps-", dir=build_root) as temporary:
            fixture = SupplyChainFixture(Path(temporary))
            app_subjects = [row for row in fixture.subjects["subjects"] if row["subjectClass"] == "first-party-app"]
            self.assertEqual(len(app_subjects), 7)
            self.assertEqual(
                {row["app"]["appId"] for row in app_subjects},
                {
                    "feed-reader",
                    "profile-publisher",
                    "publisher",
                    "queue-manager",
                    "site-publisher",
                    "social-inbox",
                    "trust-graph",
                },
            )
            self.assertTrue(all(row["app"] is not None for row in app_subjects))
            catalog = next(row for row in fixture.subjects["subjects"] if row["subjectKey"] == "stable-catalog")
            self.assertEqual(catalog["catalogEdition"], "stable-300")
            required_companions = {
                row["subjectKey"]: row["reproducibilityClass"]
                for row in fixture.policy["releaseSubjects"]
                if row["required"] and row["subjectClass"] == "companion-artifact"
            }
            self.assertEqual(
                required_companions,
                {
                    "checksums": "not-a-product-subject",
                    "release-notes": "not-a-product-subject",
                    "release-provenance": "not-a-product-subject",
                },
            )

    def test_public_redaction_rejects_paths_credentials_and_private_uris(self) -> None:
        findings = scan_value({"artifactPath": "/home/runner/work/private.json", "credential": "super-secret-value", "uri": "USK@private,key,AQECAAE/path"})
        categories = {row["category"] for row in findings}
        self.assertTrue(categories)

    def test_repository_checkout_preserves_digest_bound_text_bytes(self) -> None:
        attributes = GIT_ATTRIBUTES_PATH.read_text(encoding="utf-8").splitlines()
        self.assertIn("* text=auto eol=lf", attributes)
        self.assertIn("*.bat text eol=crlf", attributes)
        self.assertIn("*.cmd text eol=crlf", attributes)

    def test_full_protected_certification_suite_uses_supported_hosts(self) -> None:
        workflow = CI_WORKFLOW_PATH.read_text(encoding="utf-8")
        job = workflow[
            workflow.index("  release-certification-self-test:") : workflow.index(
                "  dependency-submission:"
            )
        ]
        self.assertIn("- os: ubuntu-latest", job)
        self.assertIn("- os: macos-latest", job)
        self.assertNotIn("windows-latest", job)
        self.assertGreaterEqual(workflow.count("- os: windows-latest"), 2)

    def test_complete_assemble_inventory_mode_passes_offline(self) -> None:
        build_root = REPOSITORY / "build"
        build_root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="supply-chain-test-", dir=build_root) as temporary:
            root = Path(temporary)
            fixture = SupplyChainFixture(root)
            inputs = fixture.write_inputs()
            run_root = root / "run"
            run_root.mkdir()
            (run_root / "stable-supply-chain" / "artifacts").mkdir(parents=True)
            manifest = RunManifest(path=root / "manifest.json", release=ReleaseSpec(fixture.release["releaseId"], "300", "stable-review"), output=OutputSpec(run_root), requirements={"stableSupplyChain": True}, inputs=inputs, policies={"candidateSourceCommit": SOURCE_COMMIT, "candidateSourceRef": SOURCE_REF, "stableSupplyChainGovernance": "required"}, execution={"evaluationClock": "2026-08-04T01:00:00Z"}, commands={"stable-supply-chain": {"mode": "assemble-inventory"}})
            context = RunContext(REPOSITORY, run_root, "stable-supply-chain", manifest)
            code, summary_path, report_path = engine.run(context)
            self.assertEqual(code, 0, read_json(summary_path))
            self.assertEqual(read_json(summary_path)["status"], "pass")
            self.assertTrue((summary_path.parent / "stable-1.0-sbom.spdx.json").is_file())
            self.assertIn("External side effects performed: `false`", report_path.read_text())

    def test_mode_rejects_irrelevant_publication_receipt_during_assembly(self) -> None:
        required, _ = engine._PHASE_INPUTS["assemble-inventory"]
        inputs = {key: "input.json" for key in required}
        inputs["supplyChainPublicationReceipt"] = "receipt.json"
        manifest = RunManifest(path=REPOSITORY / "manifest.json", release=ReleaseSpec("stable-300", "300", "stable-review"), output=OutputSpec(REPOSITORY / "build"), requirements={}, inputs=inputs, policies={}, execution={}, commands={"stable-supply-chain": {"mode": "assemble-inventory"}})
        context = RunContext(REPOSITORY, REPOSITORY / "build", "stable-supply-chain", manifest)
        with self.assertRaisesRegex(ValueError, "irrelevant"):
            engine._phase_input_errors(context, "assemble-inventory")

    def test_workflow_has_closed_operations_and_minimal_permissions(self) -> None:
        text = WORKFLOW_PATH.read_text(encoding="utf-8")
        for operation in (
            "inventory",
            "producer-build",
            "verifier-build",
            "compare-evaluate",
            "publish",
            "verify-publication",
        ):
            self.assertIn(f"          - {operation}", text)
        self.assertIn("permissions: {}", text)
        publish = text[text.index("\n  publish:") : text.index("\n  verify-publication:")]
        ordinary = text.replace(publish, "")
        self.assertIn("contents: write", publish)
        self.assertNotIn("contents: write", ordinary)
        self.assertNotIn("packages: write", text)
        self.assertNotIn("pull-requests: write", text)

    def test_publication_handoff_preserves_policy_base_uri(self) -> None:
        text = WORKFLOW_PATH.read_text(encoding="utf-8")
        publish = text[text.index("\n  publish:") : text.index("\n  verify-publication:")]

        self.assertIn(
            '"tools/release-certification/stable-1.0-supply-chain-policy.json"',
            publish,
        )
        self.assertIn(
            'immutable_base_uri = publication_policy["immutableBaseUri"]',
            publish,
        )
        self.assertIn(
            'original_manifest["policies"]["artifactBaseUri"] = immutable_base_uri',
            publish,
        )
        self.assertNotIn('+ str(plan["tag"])', publish)

    def test_workflow_enforces_verifier_build_before_candidate_download(self) -> None:
        text = WORKFLOW_PATH.read_text(encoding="utf-8")
        verifier = text[
            text.index("\n  verifier-build:") : text.index("\n  compare-evaluate:")
        ]
        clean = verifier.index("Clean verifier workspace before receiving reviewed phase inputs")
        recipe = verifier.index("Download exact reviewed verifier recipe without candidate subjects")
        authenticate = verifier.index(
            "Authenticate reviewed verifier recipe and resolution expectations"
        )
        build = verifier.index(
            "Build and digest verifier subjects against reviewed resolution evidence"
        )
        self.assertLess(clean, recipe)
        self.assertLess(recipe, authenticate)
        self.assertLess(authenticate, build)
        self.assertIn(
            "Only the recipe has been downloaded. No producer subject byte is available",
            verifier,
        )
        self.assertIn(
            "reviewed resolution export and snapshot are required regular files",
            verifier,
        )
        self.assertIn(
            "-PstableSupplyChainExpectedResolutionExport=build/stable-supply-chain-phase/"
            "resolved-dependency-export.json",
            verifier,
        )
        self.assertIn(
            "-PstableSupplyChainExpectedResolutionSnapshot=build/stable-supply-chain-phase/"
            "resolved-dependency-snapshot.json",
            verifier,
        )
        self.assertIn(
            "Validate exact closed verifier recipe before build without candidate subjects",
            verifier,
        )
        self.assertIn("verifier recipe inputs are not the exact closed pre-build set", verifier)
        for prohibited in (
            "primarySubjectRoot",
            "verifierSubjectRoot",
            "primaryPayloadManifests",
            "verifierPayloadManifests",
            "reproducibilityResult",
            "supplyChainPublicationReceipt",
        ):
            self.assertIn(f'"{prohibited}"', verifier)
        validator = verifier.index(
            "Validate exact closed verifier recipe before build without candidate subjects"
        )
        self.assertLess(validator, build)

    def test_workflow_authenticates_original_builder_artifacts_before_comparison(self) -> None:
        text = WORKFLOW_PATH.read_text(encoding="utf-8")
        comparison = text[text.index("\n  compare-evaluate:") : text.index("\n  publish:")]
        for name in (
            "producer_run_id",
            "producer_run_attempt",
            "producer_artifact_name",
            "producer_artifact_digest",
            "verifier_run_id",
            "verifier_run_attempt",
            "verifier_artifact_name",
            "verifier_artifact_digest",
        ):
            self.assertIn(f"inputs.{name}", text)
        self.assertEqual(
            comparison.count("Download exact original "),
            2,
        )
        self.assertIn("actions/runs/$run_id/attempts/$run_attempt", comparison)
        self.assertIn(".digest == $digest", comparison)
        self.assertIn("--deny-self-hosted-runners --format=json", comparison)
        self.assertNotIn("phase {label} receipt is not exactly derived", comparison)
        self.assertIn("derived-producer-builder-receipt.json", comparison)
        self.assertIn("derived-verifier-builder-receipt.json", comparison)
        self.assertIn("authenticated-comparison-manifest.json", comparison)
        self.assertNotIn(
            "--manifest build/stable-supply-chain-phase/manifest.json\n\n"
            "      - name: Stage flat authenticated comparison handoff",
            comparison,
        )
        self.assertIn("stable_1_0_independent_handoff", comparison)
        self.assertIn("stage-primary", comparison)
        self.assertIn("--subject-bundle", comparison)
        self.assertIn("independent-primary-subjects-attempt-${{ github.run_attempt }}", comparison)
        bounded_handoff = comparison[
            comparison.index("- name: Upload immutable comparison handoff") :
            comparison.index("- name: Attest independent primary subject bundle")
        ]
        self.assertNotIn("stable-1.0-primary-subject-bundle.zip", bounded_handoff)

    def test_workflow_preserves_closed_cross_platform_execution_provenance(self) -> None:
        text = WORKFLOW_PATH.read_text(encoding="utf-8")
        platform = text[
            text.index("\n  platform-package-build:") :
            text.index("\n  compare-evaluate:")
        ]
        for execution_id, runner, task in (
            ("linux-installers", "ubuntu-24.04", "jpackageInstallerLinuxAll"),
            ("macos-installer", "macos-15-intel", "jpackageInstallerCryptad"),
            ("windows-installer", "windows-2025", "jpackageInstallerWindowsExeCryptad"),
        ):
            self.assertIn(f"execution_id: {execution_id}", platform)
            self.assertIn(f"runner: {runner}", platform)
            self.assertIn(f"build_task: {task}", platform)
        for execution_id in (
            "linux-installers",
            "macos-installer",
            "portable-apps",
            "windows-installer",
        ):
            self.assertIn(f'"{execution_id}"', platform)
        self.assertIn("merge-multiple: false", platform)
        self.assertIn("builder-executions.json", platform)
        self.assertIn("runnerImageIdentity", platform)
        self.assertIn("artifactAttestationDigest", platform)
        self.assertIn("subjectSetDigest", platform)
        self.assertIn("candidateProductAvailableBeforeBuild", platform)
        self.assertIn("Attest complete cross-platform builder handoff", platform)

    def test_interpolated_workflow_run_scalars_stay_below_expression_budget(self) -> None:
        # GitHub rejected the original oversized interpolated platform script before creating jobs.
        text = WORKFLOW_PATH.read_text(encoding="utf-8")
        blocks = re.findall(r"^        run: [|>]\n((?:(?:          .*|)\n)+)", text, re.MULTILINE)
        self.assertTrue(blocks)
        for block in blocks:
            if "${{" in block:
                self.assertLess(len(textwrap.dedent(block)), 20000)
        compile(PLATFORM_HANDOFF_PATH.read_text(encoding="utf-8"), str(PLATFORM_HANDOFF_PATH), "exec")

    def test_platform_build_uses_a_closed_cross_platform_python_launcher(self) -> None:
        text = WORKFLOW_PATH.read_text(encoding="utf-8")
        platform = text[
            text.index("\n  platform-package-build:") :
            text.index("\n  aggregate-builder-handoff:")
        ]
        self.assertEqual(platform.count("python_cmd: python3"), 2)
        self.assertEqual(platform.count("python_cmd: py -3.14"), 1)
        self.assertEqual(platform.count("${{ matrix.python_cmd }} -"), 4)
        self.assertIn("${{ matrix.python_cmd }} tools/release-certification/protected/stable_supply_chain_platform_handoff.py", platform)
        self.assertNotIn("python3 -", platform)

    def test_exporter_builds_and_binds_a_fresh_canonical_jlink_inventory(self) -> None:
        build_logic = SUPPLY_CHAIN_BUILD_LOGIC_PATH.read_text(encoding="utf-8")
        runtime_logic = (
            REPOSITORY
            / "build-logic/src/main/kotlin/cryptad.runtime.gradle.kts"
        ).read_text(encoding="utf-8")
        workflow = WORKFLOW_PATH.read_text(encoding="utf-8") + "\n" + PLATFORM_HANDOFF_PATH.read_text(encoding="utf-8")
        self.assertIn('val inventoryJreModules = tasks.named("inventoryJreModules")', build_logic)
        self.assertIn(
            "dependsOn(inventoryJreModules, exportStableBuildLogicResolution)",
            build_logic,
        )
        self.assertNotIn("if (file.isFile)", build_logic)
        self.assertIn("modules != modules.sorted().distinct()", build_logic)
        self.assertIn(
            "jdeps failed to produce the exact runtime module inventory",
            runtime_logic,
        )
        self.assertIn('commandLine(java.absolutePath, "--list-modules")', runtime_logic)
        self.assertIn('layout.buildDirectory.file("jlink/runtime-modules.list")', build_logic)
        self.assertIn('.file(modulesFileProvider)', runtime_logic)
        self.assertIn(
            'inputs.property("jlinkCompression", jlinkCompressionProvider)', runtime_logic
        )
        self.assertIn('.file(jlinkExecutableProvider)', runtime_logic)
        self.assertIn('.files(jlinkModuleSourceProvider)', runtime_logic)
        self.assertIn('javaHome.file("lib/modules")', runtime_logic)
        self.assertIn("if (jmods.isDirectory)", runtime_logic)
        for toolchain_input in (
            "javaLanguageVersion",
            "javaVendor",
            "javaRuntimeVersion",
            "jvmVersion",
            "javaArchitecture",
        ):
            self.assertIn(f'inputs.property("{toolchain_input}"', runtime_logic)
        self.assertLess(
            runtime_logic.index('.file(modulesFileProvider)'),
            runtime_logic.index("outputs.dir(jreDirProvider)"),
        )
        self.assertNotIn('else "java.base"', runtime_logic)
        stable_toolchain = (
            REPOSITORY
            / "build-logic/src/main/kotlin/cryptad/StableJavaToolchain.kt"
        ).read_text(encoding="utf-8")
        jdk_fingerprint = (
            REPOSITORY
            / "build-logic/src/main/kotlin/cryptad/StableJdkFingerprint.kt"
        ).read_text(encoding="utf-8")
        self.assertIn("vendor.set(JvmVendorSpec.ADOPTIUM)", stable_toolchain)
        self.assertIn("selectStableJava25()", build_logic)
        self.assertIn("fun canonicalRuntimeBuild(reportedVersion: String)", jdk_fingerprint)
        self.assertIn('(?:-LTS)?$"', jdk_fingerprint)
        self.assertEqual(
            build_logic.count("StableJdkFingerprint.canonicalRuntimeBuild"), 1
        )
        self.assertEqual(runtime_logic.count("selectStableJava25()"), 2)
        jpackage_logic = (
            REPOSITORY
            / "build-logic/src/main/kotlin/cryptad.jpackage.gradle.kts"
        ).read_text(encoding="utf-8")
        self.assertIn("selectStableJava25()", jpackage_logic)
        conventions = (
            REPOSITORY
            / "build-logic/src/main/kotlin/cryptad.java-kotlin-conventions.gradle.kts"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "toolchain { languageVersion.set(JavaLanguageVersion.of(25)) }",
            conventions,
        )
        self.assertNotIn("selectStableJava25", conventions)
        included_build = (REPOSITORY / "build-logic/build.gradle.kts").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "toolchain { languageVersion.set(JavaLanguageVersion.of(25)) }",
            included_build,
        )
        self.assertIn("kotlin { jvmToolchain(25) }", included_build)
        self.assertNotIn("JvmVendorSpec.ADOPTIUM", included_build)
        for label in ("raw resolution or final", "producer jlink", "verifier jlink", "platform jlink"):
            self.assertIn(label, workflow)

    def test_workflow_binds_actual_native_extraction_and_product_free_build_recipes(self) -> None:
        text = WORKFLOW_PATH.read_text(encoding="utf-8")
        producer = text[text.index("\n  producer-build:") : text.index("\n  verifier-build:")]
        platform = text[
            text.index("\n  platform-package-build:") :
            text.index("\n  compare-evaluate:")
        ]
        platform += "\n" + PLATFORM_HANDOFF_PATH.read_text(encoding="utf-8")
        for section in (producer, platform):
            self.assertNotIn('"primaryBuilderReceipt",', section)
            self.assertNotIn('"verifierBuilderReceipt",', section)
            self.assertIn("contains candidate product bytes", section)
        self.assertNotIn("primarySubjectRoot", producer)
        self.assertNotIn("configured_root", platform)
        for extractor in (
            '["dpkg-deb", "--extract"',
            '["rpm2cpio", str(source)]',
            '["hdiutil", "attach"',
            '["7z", "x"',
            '["msiexec.exe", "/a"',
        ):
            self.assertIn(extractor, platform)
        self.assertIn("stable-1.0-package-extraction-evidence-v1.schema.json", platform)
        self.assertIn("publishedSubjectDigest", platform)
        self.assertIn("signatureReceiptDigest", platform)
        self.assertIn("stagedPayloadContainedExactly", platform)
        self.assertIn("extraction_views", platform)
        self.assertNotIn(
            '"extractionManifestSetDigest": sha256_digest(canonical_json_bytes(payload_views))',
            platform,
        )
        python_blocks = re.findall(r"<<'PY'\n(.*?)\n\s+PY", platform, flags=re.DOTALL)
        self.assertGreaterEqual(len(python_blocks), 3)
        for index, block in enumerate(python_blocks):
            with self.subTest(embeddedPython=index):
                compile(textwrap.dedent(block), f"platform-workflow-{index}.py", "exec")

    def test_workflow_uses_exact_maintenance_freeze_only_after_producer_build(self) -> None:
        text = WORKFLOW_PATH.read_text(encoding="utf-8")
        dispatch = text[text.index("  workflow_dispatch:") : text.index("\n# One candidate")]
        input_names = re.findall(r"^      ([a-z][a-z0-9_]+):$", dispatch, flags=re.MULTILINE)
        self.assertLessEqual(len(input_names), 25)
        self.assertIn("frozen_candidate_run", input_names)
        self.assertNotIn("frozen_candidate_run_id", input_names)
        self.assertNotIn("frozen_candidate_run_attempt", input_names)

        validation = text[text.index("\n  validate-dispatch:") : text.index("\n  inventory:")]
        self.assertIn("^[1-9][0-9]*:[1-9][0-9]*$", validation)
        self.assertIn(".github/workflows/stable-1.0-maintenance-release.yml", validation)
        self.assertIn("(freeze-candidate)", validation)
        self.assertIn(
            "stable-1-0-maintenance-frozen-$INPUT_RELEASE_ID-$INPUT_BUILD_VERSION-"
            "$INPUT_FROZEN_RUN_ID-$INPUT_FROZEN_RUN_ATTEMPT",
            validation,
        )
        self.assertIn("frozen_run_id=$INPUT_FROZEN_RUN_ID", validation)
        self.assertIn("frozen_run_attempt=$INPUT_FROZEN_RUN_ATTEMPT", validation)

        producer = text[text.index("\n  producer-build:") : text.index("\n  verifier-build:")]
        build = producer.index("Export resolution and build closed producer subjects")
        download = producer.index("Download exact frozen candidate after producer staged build")
        authenticate = producer.index("Authenticate frozen candidate after portable producer staged build")
        self.assertLess(build, download)
        self.assertLess(download, authenticate)
        self.assertEqual(
            producer[build:download].count(
                "./gradlew exportStableSupplyChainResolution verifyStableSupplyChainResolution"
            ),
            2,
        )
        self.assertIn('freeze_root / "assets"', producer)
        self.assertIn("stable-1.0-maintenance-candidate-freeze.schema.json", producer)
        self.assertIn(
            'signer="crypta-network/cryptad/.github/workflows/'
            'stable-1.0-maintenance-release.yml"',
            producer,
        )
        self.assertIn('Path(row["fileName"]).name', producer)
        self.assertIn("producer staged build does not reproduce frozen", producer)
        self.assertNotIn("stable-supply-chain-frozen-candidate/subjects", producer)

        platform = text[
            text.index("\n  platform-package-build:") :
            text.index("\n  aggregate-builder-handoff:")
        ]
        platform += "\n" + PLATFORM_HANDOFF_PATH.read_text(encoding="utf-8")
        platform_build = platform.index("Build exact Linux or macOS installer payload independently")
        platform_download = platform.index("Download exact frozen signed candidate after producer staged build")
        self.assertLess(platform_build, platform_download)
        self.assertIn('freeze_root / "assets"', platform)
        self.assertIn("selected package is absent from the maintenance freeze", platform)
        self.assertNotIn("stable-supply-chain-frozen-candidate/subjects", platform)

    def test_prepublication_summary_does_not_claim_publication_passed(self) -> None:
        self.assertNotIn(
            "stable-supply-chain.publication",
            engine._evidence_for_mode("evaluate-promotion"),
        )
        self.assertIn(
            "stable-supply-chain.publication",
            engine._evidence_for_mode("verify-publication"),
        )

    def test_workflow_authenticates_protected_vulnerability_summary_for_promotion(self) -> None:
        text = WORKFLOW_PATH.read_text(encoding="utf-8")
        comparison = text[text.index("\n  compare-evaluate:") : text.index("\n  publish:")]
        self.assertIn(
            'value != "stable-1.0-vulnerability-summary.json"', comparison
        )
        self.assertIn("stable-1.0-vulnerability-successor-binding.json", comparison)
        self.assertIn("stable-1.0-vulnerability-summary-provenance.json", comparison)
        self.assertIn("stable-1.0-protected-handoff.enc", comparison)
        self.assertIn("stable_backport_protected_handoff.py open", comparison)
        self.assertIn("stable_vulnerability_actions_tip.py", comparison)
        self.assertIn("verify-promotion", comparison)
        self.assertIn("CRYPTAD_STABLE_VULNERABILITY_SUMMARY_ROOT", comparison)
        for suffix in (
            "RUN_ID",
            "RUN_ATTEMPT",
            "ARTIFACT_NAME",
            "ARTIFACT_DIGEST",
            "LEDGER_DIGEST",
            "LEDGER_EDITION",
        ):
            self.assertIn(
                "CRYPTAD_STABLE_VULNERABILITY_CURRENT_TIP_" + suffix,
                comparison,
            )
        self.assertNotIn(
            "CRYPTAD_STABLE_VULNERABILITY_HANDOFF_KEY_BASE64=%s",
            comparison,
        )

    def test_workflow_pins_java_gradle_actions_and_artifact_allowlists(self) -> None:
        text = WORKFLOW_PATH.read_text(encoding="utf-8")
        external_actions = [
            reference
            for reference in re.findall(
                r"^\s*uses:\s+([^\s#]+)", text, flags=re.MULTILINE
            )
            if not reference.startswith("./")
        ]
        expected_actions = {
            "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1": 9,
            "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97": 8,
            "actions/setup-java@dd06d9cba3e5552c54d9f8ea23572deb30010f7c": 4,
            "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c": 13,
            "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a": 9,
            "actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8": 9,
            "gradle/actions/setup-gradle@9c971963bec38e04b3d30dcc455b5382be2fdbfb": 4,
        }

        self.assertEqual(
            expected_actions,
            {reference: external_actions.count(reference) for reference in external_actions},
        )
        for reference in external_actions:
            self.assertRegex(reference, r"^[^@\s]+@[0-9a-f]{40}$")
        self.assertEqual(text.count("java-version: '25.0.4.1+1'"), 4)
        self.assertNotIn("java-version: '25'", text)
        self.assertIn("./gradlew exportStableSupplyChainResolution", text)
        self.assertIn("phase bundle contains an unreferenced entry", text)
        self.assertIn("fixed_files", text)
        for property_name in (
            "seedrefsSha256",
            "seedrefsUrl",
            "wrapperDeltaPackSha256",
            "wrapperWinAmd64Sha256",
            "wrapperWinArm64Sha256",
            "wrapperWinAmd64Url",
            "wrapperWinArm64Url",
        ):
            self.assertGreaterEqual(text.count("-P" + property_name), 4)

    def test_raw_environment_allowlist_matches_the_closed_policy_vocabulary(self) -> None:
        build_logic = SUPPLY_CHAIN_BUILD_LOGIC_PATH.read_text(encoding="utf-8")
        start = build_logic.index("val stableAllowedEnvironmentVariables =")
        end = build_logic.index("\n\nfun StableSupplyChainResolutionTask", start)
        allowlist = build_logic[start:end]
        for name in ("LANG", "LC_ALL", "SOURCE_DATE_EPOCH", "TZ"):
            self.assertIn(f'"{name}"', allowlist)
        for prohibited in ("JAVA_HOME", "GITHUB_RUN_ID", "GITHUB_SHA", "RUNNER_OS"):
            self.assertNotIn(prohibited, allowlist)

        workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
        cross_check = workflow[
            workflow.index("Cross-check live raw build evidence with reviewed final materials") :
            workflow.index("Run side-effect-free inventory phase")
        ]
        self.assertIn(
            'canonical_environment_names = ["LANG", "LC_ALL", "SOURCE_DATE_EPOCH", "TZ"]',
            cross_check,
        )
        self.assertIn(
            'raw_environment.get("allowedVariableNames")', cross_check
        )
        self.assertIn(
            'final_environment.get("allowedVariableNames")', cross_check
        )

    def test_gradle_export_covers_compiler_and_settings_plugin_classpaths(self) -> None:
        root_logic = SUPPLY_CHAIN_BUILD_LOGIC_PATH.read_text(encoding="utf-8")
        included_logic = (REPOSITORY / "build-logic/build.gradle.kts").read_text(
            encoding="utf-8"
        )
        root_settings = (REPOSITORY / "settings.gradle.kts").read_text(
            encoding="utf-8"
        )
        included_settings = (
            REPOSITORY / "build-logic/settings.gradle.kts"
        ).read_text(encoding="utf-8")

        self.assertIn('"annotationProcessor" to "build"', root_logic)
        self.assertIn('"testAnnotationProcessor" to "test"', root_logic)
        for configuration in (
            "buildLogicSettingsPluginClasspath",
            "rootSettingsPluginClasspath",
        ):
            self.assertIn(configuration, included_logic)
        marker = "org.gradle.toolchains.foojay-resolver-convention.gradle.plugin"
        self.assertIn(marker, included_logic)
        self.assertIn("libs.versions.foojayResolver.get()", included_logic)
        self.assertIn('version("foojayResolver")', root_settings)
        self.assertIn('ver("foojayResolver")', included_settings)
        for settings in (root_settings, included_settings):
            self.assertIn(
                'plugins { id("org.gradle.toolchains.foojay-resolver-convention") }',
                settings,
            )

    def test_seedrefs_url_is_an_input_only_of_the_seedrefs_download_task(self) -> None:
        build_logic = DISTRIBUTION_BUILD_LOGIC_PATH.read_text(encoding="utf-8")
        wrapper = build_logic[
            build_logic.index("val downloadWrapper by") :
            build_logic.index("// Extract the delta pack")
        ]
        seedrefs = build_logic[
            build_logic.index("val downloadSeedrefs by") :
            build_logic.index("// Extract seedrefs")
        ]
        self.assertIn('inputs.property("sourceUrl", wrapperBaseUrl)', wrapper)
        self.assertNotIn("seedrefsZipUrl", wrapper)
        self.assertIn('inputs.property("sourceUrl", seedrefsZipUrl)', seedrefs)

    def test_workflow_scopes_every_builder_handoff_to_one_run_attempt(self) -> None:
        text = WORKFLOW_PATH.read_text(encoding="utf-8")
        self.assertIn("producer-portable-apps-attempt-${{ github.run_attempt }}", text)
        self.assertIn("verifier-portable-apps-attempt-${{ github.run_attempt }}", text)
        self.assertIn("matrix.execution_id }}-attempt-${{ github.run_attempt }}", text)
        self.assertIn("'verifier' }}-*-attempt-${{ github.run_attempt }}", text)
        self.assertIn("-$execution_id-attempt-$GITHUB_RUN_ATTEMPT", text)
        self.assertIn('handoff.get("runId") != int(os.environ["GITHUB_RUN_ID"])', text)
        self.assertIn(
            'handoff.get("runAttempt") != int(os.environ["GITHUB_RUN_ATTEMPT"])',
            text,
        )
        self.assertIn("-producer-attempt-$INPUT_PRODUCER_RUN_ATTEMPT", text)
        self.assertIn("-verifier-attempt-$INPUT_VERIFIER_RUN_ATTEMPT", text)

    def test_workflow_records_integer_runs_and_observed_build_environment(self) -> None:
        text = WORKFLOW_PATH.read_text(encoding="utf-8")
        producer = text[text.index("\n  producer-build:") : text.index("\n  verifier-build:")]
        verifier = text[
            text.index("\n  verifier-build:") : text.index("\n  platform-package-build:")
        ]
        platform = text[
            text.index("\n  platform-package-build:") :
            text.index("\n  compare-evaluate:")
        ]
        platform += "\n" + PLATFORM_HANDOFF_PATH.read_text(encoding="utf-8")
        self.assertEqual(text.count('--argjson runId "$GITHUB_RUN_ID"'), 2)
        self.assertNotIn('--arg runId "$GITHUB_RUN_ID"', text)
        self.assertNotIn('int(handoff.get("runId"', text)
        self.assertNotIn('int(handoff.get("runAttempt"', text)
        self.assertEqual(
            text.count("Install canonical build environment and observe exact Java runtime"),
            3,
        )
        for section, build_marker in (
            (producer, "Export resolution and build closed producer subjects"),
            (verifier, "Build and digest verifier subjects against reviewed resolution evidence"),
            (platform, "Build exact Linux or macOS installer payload independently"),
        ):
            self.assertLess(
                section.index("Install canonical build environment"),
                section.index(build_marker),
            )
            for name in ("LANG", "LC_ALL", "SOURCE_DATE_EPOCH", "TZ"):
                self.assertIn(f'"{name}"', section)
            self.assertIn("jdk_installation_identity", section)
            self.assertIn("observed_java_identity(", section)
            self.assertIn("builder_observation_errors", section)
        self.assertIn("installer_subject_binding_errors", platform)
        self.assertIn('observed_java = handoff.get("observedJava", {})', platform)
        self.assertIn('"canonicalEnvironment": handoff["canonicalEnvironment"]', platform)
        self.assertIn('"environmentVariables": environment_variables', platform)

    def test_package_extraction_schema_separates_exact_and_macos_bindings(self) -> None:
        def evidence(builder_role: str, package_type: str, binding_method: str) -> dict:
            normalized = binding_method == "macos-code-signature-normalized"
            candidate = builder_role == "candidate-producer"
            value = {
                "schemaVersion": 1,
                "kind": "stable-1.0-package-extraction-evidence",
                "builderRole": builder_role,
                "subjectKey": "amd64." + package_type,
                "packageType": package_type,
                "bindingMethod": binding_method,
                "publishedSubjectDigest": _digest("subject"),
                "payloadManifestDigest": _digest("payload"),
                "signatureReceiptDigest": _digest("signature") if candidate else None,
                "notarizationReceiptDigest": (
                    _digest("notarization") if candidate and package_type == "dmg" else None
                ),
                "extractionTool": {
                    "name": "hdiutil" if package_type == "dmg" else "dpkg-deb",
                    "version": "fixed-tool-version",
                    "runnerImageDigest": _digest("runner"),
                },
                "stagedPayloadDigest": _digest("staged"),
                "embeddedStagedPayloadDigest": (
                    _digest("embedded") if normalized and candidate else _digest("staged")
                ),
                "extractedPayloadDigest": _digest("extracted"),
                "stagedPayloadContainedExactly": not (normalized and candidate),
                "normalizationEvidence": None,
                "evidenceDigest": _digest("evidence"),
            }
            if normalized:
                value["normalizationEvidence"] = {
                    "normalizationRuleId": "crypta-dmg-payload-v2",
                    "normalizationRuleVersion": 2,
                    "codesignTool": {
                        "name": "apple-system-codesign",
                        "executableDigest": _digest("codesign"),
                        "runnerImageDigest": _digest("runner"),
                    },
                    "mountedAppSigningVerified": candidate,
                    "releaseBytesUnmodified": True,
                    "nonCodeEntriesIdentical": True,
                    "signatureMaterialAccounted": True,
                    "frozenSubjectDigest": _digest("subject") if candidate else None,
                    "frozenSigningReceiptDigest": _digest("signature") if candidate else None,
                    "frozenNotarizationReceiptDigest": (
                        _digest("notarization") if candidate else None
                    ),
                    "normalizedStagedPayloadDigest": _digest("normalized"),
                    "normalizedEmbeddedPayloadDigest": _digest("normalized"),
                    "codeObjects": [{
                        "path": "Contents/MacOS/Crypta",
                        "stagedDigest": _digest("unsigned-code"),
                        "embeddedDigest": _digest("signed-code"),
                        "strippedDigest": _digest("unsigned-code"),
                        "strippedSize": 4096,
                        "stagedSigned": False,
                        "embeddedSigned": candidate,
                        "rawBytesIdentical": not candidate,
                        "normalizedBytesIdentical": True,
                    }],
                    "signatureMaterial": [{
                        "path": "Contents/_CodeSignature/CodeResources",
                        "structure": "bundle-code-resources-file",
                        "change": "added-to-embedded" if candidate else "unchanged",
                        "stagedDigest": None if candidate else _digest("resources"),
                        "embeddedDigest": _digest("resources"),
                        "stagedSize": None if candidate else 512,
                        "embeddedSize": 512,
                        "stagedModeClass": None if candidate else "read-only",
                        "embeddedModeClass": "read-only",
                        "stagedSymlinkTarget": None,
                        "embeddedSymlinkTarget": None,
                    }],
                }
            return value

        schema = "stable-1.0-package-extraction-evidence-v1.schema.json"
        exact = evidence("candidate-producer", "deb", "exact-staged-payload")
        candidate_dmg = evidence(
            "candidate-producer", "dmg", "macos-code-signature-normalized"
        )
        verifier_dmg = evidence(
            "independent-verifier", "dmg", "macos-code-signature-normalized"
        )
        self.assertEqual(validate_schema(exact, schema), [])
        self.assertEqual(validate_schema(candidate_dmg, schema), [])
        self.assertEqual(validate_schema(verifier_dmg, schema), [])

        exact_dmg = evidence("independent-verifier", "dmg", "exact-staged-payload")
        self.assertTrue(validate_schema(exact_dmg, schema))
        normalized_deb = evidence(
            "candidate-producer", "deb", "macos-code-signature-normalized"
        )
        self.assertTrue(validate_schema(normalized_deb, schema))

    def test_dmg_policy_has_one_closed_copy_only_codesign_contract(self) -> None:
        rule = next(
            value
            for value in self.policy["normalizationRules"]
            if value["id"] == "crypta-dmg-payload-v2"
        )
        self.assertEqual(rule["packageTypes"], ["dmg"])
        self.assertEqual(rule["version"], 2)
        self.assertEqual(rule["ignoredPaths"], [])
        self.assertEqual(
            rule["codeSignatureNormalization"],
            {
                "bindingMethod": "macos-code-signature-normalized",
                "tool": "apple-system-codesign",
                "copyOnlySignatureRemoval": True,
                "releaseBytesMutable": False,
                "strictMountedAppVerification": True,
                "signatureResourceStructures": [
                    "bundle-code-directory",
                    "bundle-code-resources-file",
                    "legacy-code-resources-symlink",
                ],
            },
        )
        subject = next(
            value for value in self.policy["releaseSubjects"]
            if value["subjectKey"] == "amd64.dmg"
        )
        self.assertEqual(subject["normalizationRuleId"], rule["id"])

    def test_package_extraction_schema_rejects_broad_or_unauthenticated_macos_views(self) -> None:
        schema = "stable-1.0-package-extraction-evidence-v1.schema.json"
        base = {
            "schemaVersion": 1,
            "kind": "stable-1.0-package-extraction-evidence",
            "builderRole": "candidate-producer",
            "subjectKey": "amd64.dmg",
            "packageType": "dmg",
            "bindingMethod": "macos-code-signature-normalized",
            "publishedSubjectDigest": _digest("subject"),
            "payloadManifestDigest": _digest("payload"),
            "signatureReceiptDigest": _digest("signature"),
            "notarizationReceiptDigest": _digest("notarization"),
            "extractionTool": {
                "name": "hdiutil",
                "version": "fixed-tool-version",
                "runnerImageDigest": _digest("runner"),
            },
            "stagedPayloadDigest": _digest("staged"),
            "embeddedStagedPayloadDigest": _digest("embedded"),
            "extractedPayloadDigest": _digest("extracted"),
            "stagedPayloadContainedExactly": False,
            "normalizationEvidence": {
                "normalizationRuleId": "crypta-dmg-payload-v2",
                "normalizationRuleVersion": 2,
                "codesignTool": {
                    "name": "apple-system-codesign",
                    "executableDigest": _digest("codesign"),
                    "runnerImageDigest": _digest("runner"),
                },
                "mountedAppSigningVerified": True,
                "releaseBytesUnmodified": True,
                "nonCodeEntriesIdentical": True,
                "signatureMaterialAccounted": True,
                "frozenSubjectDigest": _digest("subject"),
                "frozenSigningReceiptDigest": _digest("signature"),
                "frozenNotarizationReceiptDigest": _digest("notarization"),
                "normalizedStagedPayloadDigest": _digest("normalized"),
                "normalizedEmbeddedPayloadDigest": _digest("normalized"),
                "codeObjects": [{
                    "path": "Contents/MacOS/Crypta",
                    "stagedDigest": _digest("unsigned"),
                    "embeddedDigest": _digest("signed"),
                    "strippedDigest": _digest("unsigned"),
                    "strippedSize": 1024,
                    "stagedSigned": False,
                    "embeddedSigned": True,
                    "rawBytesIdentical": False,
                    "normalizedBytesIdentical": True,
                }],
                "signatureMaterial": [{
                    "path": "Contents/_CodeSignature/CodeResources",
                    "structure": "bundle-code-resources-file",
                    "change": "added-to-embedded",
                    "stagedDigest": None,
                    "embeddedDigest": _digest("resources"),
                    "stagedSize": None,
                    "embeddedSize": 512,
                    "stagedModeClass": None,
                    "embeddedModeClass": "read-only",
                    "stagedSymlinkTarget": None,
                    "embeddedSymlinkTarget": None,
                }],
            },
            "evidenceDigest": _digest("evidence"),
        }
        self.assertEqual(validate_schema(base, schema), [])
        mutations = []
        missing_receipt = copy.deepcopy(base)
        missing_receipt["notarizationReceiptDigest"] = None
        mutations.append(missing_receipt)
        unverified = copy.deepcopy(base)
        unverified["normalizationEvidence"]["mountedAppSigningVerified"] = False
        mutations.append(unverified)
        broad_ignore = copy.deepcopy(base)
        broad_ignore["normalizationEvidence"]["ignoredPaths"] = ["Contents/_CodeSignature"]
        mutations.append(broad_ignore)
        duplicate_code = copy.deepcopy(base)
        duplicate_code["normalizationEvidence"]["codeObjects"] *= 2
        mutations.append(duplicate_code)
        duplicate_signature = copy.deepcopy(base)
        duplicate_signature["normalizationEvidence"]["signatureMaterial"] *= 2
        mutations.append(duplicate_signature)
        for mutation in mutations:
            with self.subTest(mutation=mutations.index(mutation)):
                self.assertTrue(validate_schema(mutation, schema))

    def test_workflow_uses_closed_macos_codesign_view_on_copies(self) -> None:
        text = WORKFLOW_PATH.read_text(encoding="utf-8")
        platform = text[
            text.index("\n  platform-package-build:") :
            text.index("\n  compare-evaluate:")
        ]
        platform += "\n" + PLATFORM_HANDOFF_PATH.read_text(encoding="utf-8")
        self.assertIn('codesign = Path("/usr/bin/codesign")', platform)
        self.assertIn('shutil.copyfile(source, copy)', platform)
        self.assertIn('[str(codesign), "--remove-signature", str(copy)]', platform)
        self.assertNotIn('[str(codesign), "--remove-signature", str(source)]', platform)
        self.assertIn('"releaseBytesUnmodified": True', platform)
        self.assertIn('"ignoredPaths": []', platform)
        self.assertIn('"macos-code-signature-normalized"', platform)
        self.assertIn('"bundle-code-resources-file"', platform)
        self.assertIn('"legacy-code-resources-symlink"', platform)
        self.assertIn('"macOS non-code payload bytes differ"', platform)
        self.assertIn('"macOS outside-app payload bytes differ"', platform)
        self.assertIn('"macOS Mach-O differs outside its code-signature view"', platform)
        self.assertIn('"macOS payload added or removed a non-signature path"', platform)
        self.assertIn('"mounted frozen app fails strict codesign verification"', platform)
        self.assertIn('local_temporary = temporary_root / "locally-built"', platform)
        self.assertIn('staged_comparison_entries = canonical_entries(local_root)', platform)
        self.assertIn('embedded_entries = extracted_entries', platform)
        self.assertIn('"locally built DMG does not contain its exact unsigned staged app"', platform)
        self.assertIn('relative.startswith(app_prefix + "/")', platform)
        self.assertNotIn('payload_comparison_entries = staged_entries', platform)
        self.assertIn('"frozenSigningReceiptDigest"', platform)
        self.assertIn('"frozenNotarizationReceiptDigest"', platform)
        self.assertIn('code_objects.sort(key=lambda value: value["path"])', platform)
        self.assertIn('signature_material.sort(key=lambda value: value["path"])', platform)

    def test_workflow_has_no_publication_mutation_or_secret_interpolation(self) -> None:
        text = WORKFLOW_PATH.read_text(encoding="utf-8")
        producer = text[text.index("\n  producer-build:") : text.index("\n  verifier-build:")]
        verifier = text[text.index("\n  verifier-build:") : text.index("\n  compare-evaluate:")]
        comparison = text[text.index("\n  compare-evaluate:") : text.index("\n  publish:")]
        publish = text[text.index("\n  publish:") : text.index("\n  verify-publication:")]
        ordinary = (
            text.replace(producer, "")
            .replace(verifier, "")
            .replace(comparison, "")
            .replace(publish, "")
        )
        self.assertNotIn("${{ secrets.", ordinary)
        for builder in (producer, verifier):
            self.assertEqual(builder.count("${{ secrets.CRYPTAD_APP_SIGNING_"), 3)
            self.assertIn("environment: stable-1.0-supply-chain-", builder)
            self.assertIn("packageFirstPartyApps", builder)
        self.assertEqual(publish.count("${{ secrets.LEUMOR_GITHUB_TOKEN }}"), 2)
        self.assertEqual(
            comparison.count(
                "${{ secrets.CRYPTAD_STABLE_VULNERABILITY_HANDOFF_KEY_BASE64 }}"
            ),
            2,
        )
        self.assertNotIn("gh release upload", text)
        self.assertNotIn("git push", text)
        self.assertNotIn("curl -X POST", text)
        self.assertIn("without publication credentials", text)


if __name__ == "__main__":
    unittest.main()
