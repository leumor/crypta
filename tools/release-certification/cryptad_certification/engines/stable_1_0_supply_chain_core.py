"""Strict data, identity, and filesystem primitives for Stable supply-chain evidence."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import posixpath
import re
import stat
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping

from cryptad_certification.io import read_json, write_json
from cryptad_certification.models import RunContext
from cryptad_certification.redaction import scan_value
from cryptad_certification.schema_validation import validate_schema

from .stable_1_0_supply_chain_jdk import JDK_INSTALLATION_DIGEST_ALGORITHM

SCHEMA_VERSION = 1
REPOSITORY_IDENTITY = "github.com/crypta-network/cryptad"
STABLE_MILESTONE = "Stable 1.0"
COMMAND_MODES = (
    "assemble-inventory",
    "verify-inventory",
    "prepare-rebuild-comparison",
    "compare-rebuilds",
    "evaluate-promotion",
    "verify-publication",
)
REPRODUCIBILITY_CLASSES = (
    "byte-identical",
    "normalized-payload-identical",
    "not-a-product-subject",
)
SUBJECT_EVIDENCE_PHASES = (
    "independent-builder",
    "authenticated-post-build",
    "derived-governance",
)
LICENSE_STATUSES = (
    "allowed",
    "allowed-with-notice",
    "review-required",
    "prohibited",
    "unknown-blocking",
    "not-applicable-internal",
)
COMPONENT_ROLES = ("runtime", "build", "test", "packaging", "publication")
REQUIRED_CONFIGURATION_MAPPINGS = (
    ("release-projects", "compileClasspath", "annotationProcessor", "build"),
    (
        "release-projects",
        "testCompileClasspath",
        "testAnnotationProcessor",
        "test",
    ),
)
REQUIRED_BUILD_LOGIC_CONFIGURATIONS = (
    "buildLogicSettingsPluginClasspath",
    "rootSettingsPluginClasspath",
)
PUBLICATION_OPERATIONS = ("created", "verified-existing")
CANONICAL_BUILD_ENVIRONMENT_VARIABLES = (
    "LANG",
    "LC_ALL",
    "SOURCE_DATE_EPOCH",
    "TZ",
)

POLICY_FILE = "stable-1.0-supply-chain-policy.json"
COMPONENT_INVENTORY_FILE = "stable-1.0-component-inventory.json"
SUBJECT_INVENTORY_FILE = "stable-1.0-release-subject-inventory.json"
RESOLUTION_SNAPSHOT_FILE = "stable-1.0-resolved-dependency-snapshot.json"
LICENSE_INVENTORY_FILE = "stable-1.0-license-inventory.json"
SBOM_FILE = "stable-1.0-sbom.spdx.json"
SBOM_BINDING_FILE = "stable-1.0-sbom-binding.json"
BUILD_MATERIALS_FILE = "stable-1.0-build-materials.json"
COMPARISON_PLAN_FILE = "stable-1.0-rebuild-comparison-plan.json"
REPRODUCIBILITY_FILE = "stable-1.0-reproducibility-report.json"
REVERSE_INDEX_FILE = "stable-1.0-component-reverse-index.json"
SUMMARY_FILE = "stable-1.0-supply-chain-summary.json"
REPORT_FILE = "stable-1.0-supply-chain-report.md"
PUBLICATION_PLAN_FILE = "stable-1.0-supply-chain-publication-plan.json"
PUBLICATION_RECEIPT_FILE = "stable-1.0-supply-chain-publication-receipt.json"
PUBLIC_OBSERVATION_FILE = "stable-1.0-supply-chain-public-observation.json"

PUBLICATION_ROLE_FILES = {
    "build-materials": BUILD_MATERIALS_FILE,
    "component-inventory": COMPONENT_INVENTORY_FILE,
    "component-reverse-index": REVERSE_INDEX_FILE,
    "license-inventory": LICENSE_INVENTORY_FILE,
    "reproducibility-report": REPRODUCIBILITY_FILE,
    "release-subject-inventory": SUBJECT_INVENTORY_FILE,
    "sbom": SBOM_FILE,
    "supply-chain-summary": SUMMARY_FILE,
}

POLICY_SCHEMA = "stable-1.0-supply-chain-policy-v1.schema.json"
COMPONENT_SCHEMA = "stable-1.0-component-v1.schema.json"
COMPONENT_INVENTORY_SCHEMA = "stable-1.0-component-inventory-v1.schema.json"
SUBJECT_INVENTORY_SCHEMA = "stable-1.0-release-subject-inventory-v1.schema.json"
RESOLUTION_SNAPSHOT_SCHEMA = "stable-1.0-resolved-dependency-snapshot-v1.schema.json"
LICENSE_INVENTORY_SCHEMA = "stable-1.0-license-inventory-v1.schema.json"
LICENSE_OVERRIDES_SCHEMA = "stable-1.0-license-overrides-v1.schema.json"
SBOM_BINDING_SCHEMA = "stable-1.0-sbom-binding-v1.schema.json"
BUILD_MATERIALS_SCHEMA = "stable-1.0-build-materials-v1.schema.json"
PAYLOAD_MANIFEST_SCHEMA = "stable-1.0-payload-manifest-v1.schema.json"
BUILDER_RECEIPT_SCHEMA = "stable-1.0-builder-receipt-v1.schema.json"
COMPARISON_PLAN_SCHEMA = "stable-1.0-rebuild-comparison-plan-v1.schema.json"
REPRODUCIBILITY_SCHEMA = "stable-1.0-reproducibility-result-v1.schema.json"
REVERSE_INDEX_SCHEMA = "stable-1.0-component-reverse-index-v1.schema.json"
SUMMARY_SCHEMA = "stable-1.0-supply-chain-promotion-summary-v1.schema.json"
PUBLICATION_PLAN_SCHEMA = "stable-1.0-supply-chain-publication-plan-v1.schema.json"
PUBLICATION_RECEIPT_SCHEMA = "stable-1.0-supply-chain-publication-receipt-v1.schema.json"
PUBLIC_OBSERVATION_SCHEMA = "stable-1.0-supply-chain-public-observation-v1.schema.json"

DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
COMMIT_RE = re.compile(r"[0-9a-f]{40}\Z")
COMPONENT_ID_RE = re.compile(r"pkg:[a-z0-9.+-]+/[A-Za-z0-9._~%+@/?=&-]+\Z")
MUTABLE_VERSION_RE = re.compile(
    r"(?i)(?:snapshot|\+|\*|\bx\b|\A(?:latest(?:\.(?:release|integration))?|release)\Z)"
)
JDK_BUILD_RE = re.compile(r"25\.[0-9]+\.[0-9]+(?:\.[0-9]+)?\+[0-9]+\Z")


def canonical_json_bytes(value: Any) -> bytes:
    """Return the canonical JSON representation used by all semantic digests."""

    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def sha256_digest(data: bytes) -> str:
    """Return a repository-format SHA-256 digest."""

    return "sha256:" + hashlib.sha256(data).hexdigest()


def semantic_digest(value: dict[str, Any], excluded_field: str) -> str:
    """Digest one canonical object while excluding its declared self-digest field."""

    payload = {key: child for key, child in value.items() if key != excluded_field}
    return sha256_digest(canonical_json_bytes(payload))


def file_digest(path: Path) -> str:
    """Digest one regular file without following a symbolic link."""

    mode = path.stat(follow_symlinks=False).st_mode
    if path.is_symlink() or not stat.S_ISREG(mode):
        raise ValueError(f"supply-chain input is not a regular file: {path.name}")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return "sha256:" + digest.hexdigest()


def parse_timestamp(value: Any, label: str) -> dt.datetime:
    """Parse one timezone-aware canonical timestamp."""

    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError(f"{label} must be a UTC timestamp")
    try:
        parsed = dt.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError(f"{label} is malformed") from exc
    if parsed.tzinfo is None or parsed.microsecond:
        raise ValueError(f"{label} must be second-precision UTC")
    return parsed.astimezone(dt.timezone.utc)


def canonical_java_runtime_build(reported_version: str) -> str:
    """Return the policy coordinate for one observed Temurin runtime build."""

    match = re.fullmatch(r"(25\.[0-9]+\.[0-9]+(?:\.[0-9]+)?\+[0-9]+)(?:-LTS)?", reported_version)
    if match is None:
        raise ValueError("observed Java runtime version is not a canonical Stable JDK build")
    return match.group(1)


def observed_java_identity(
    properties: Mapping[str, str], installation_identity: Mapping[str, str]
) -> dict[str, str]:
    """Return the closed Java identity observed from the builder runtime properties."""

    required = {
        "java.vendor": "javaVendor",
        "java.specification.version": "javaVersion",
        "java.runtime.version": "javaBuild",
        "file.encoding": "javaEncoding",
        "os.arch": "javaArchitecture",
    }
    values: dict[str, str] = {}
    for property_name, field_name in required.items():
        value = properties.get(property_name)
        if not isinstance(value, str) or not value.strip() or len(value.encode("utf-8")) > 128:
            raise ValueError(f"observed Java property {property_name} is absent or invalid")
        values[field_name] = value.strip()
    values["javaBuild"] = canonical_java_runtime_build(values["javaBuild"])
    architecture = values["javaArchitecture"].casefold()
    architecture_aliases = {
        "amd64": "amd64",
        "x86_64": "amd64",
        "aarch64": "arm64",
        "arm64": "arm64",
    }
    if architecture not in architecture_aliases:
        raise ValueError("observed Java architecture is unsupported")
    values["javaArchitecture"] = architecture_aliases[architecture]
    for field in ("installationManifestDigest", "releaseFileDigest"):
        value = installation_identity.get(field)
        if not isinstance(value, str) or DIGEST_RE.fullmatch(value) is None:
            raise ValueError(f"observed Java {field} is absent or invalid")
        values["java" + field[0].upper() + field[1:]] = value
    identity = {
        key: values[key]
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
    identity["javaIdentityDigest"] = sha256_digest(canonical_json_bytes(identity))
    return identity


def builder_observation_errors(
    java: dict[str, Any],
    environment_variables: dict[str, Any],
    materials: dict[str, Any],
    runner_os: str,
) -> list[str]:
    """Bind observed builder Java and environment values to authenticated materials."""

    errors: list[str] = []
    architecture = java.get("javaArchitecture")
    installations = materials.get("jdk", {}).get("installations", [])
    matching_installations = [
        row
        for row in installations
        if isinstance(row, dict)
        and row.get("runnerOs") == runner_os
        and row.get("architecture") == architecture
    ]
    if len(matching_installations) != 1:
        errors.append("observed builder platform has no unique authenticated JDK installation")
        installation: dict[str, Any] = {}
    else:
        installation = matching_installations[0]
    expected_java = {
        "javaVendor": materials.get("jdk", {}).get("vendor"),
        "javaVersion": materials.get("jdk", {}).get("version"),
        "javaBuild": materials.get("jdk", {}).get("build"),
        "javaEncoding": materials.get("environment", {}).get("encoding"),
        "javaArchitecture": installation.get("architecture"),
        "javaInstallationManifestDigest": installation.get(
            "installationManifestDigest"
        ),
        "javaReleaseFileDigest": installation.get("releaseFileDigest"),
    }
    for field, expected in expected_java.items():
        if java.get(field) != expected:
            errors.append(f"observed builder {field} differs from authenticated materials")
    comparable_java = {key: java.get(key) for key in expected_java}
    if java.get("javaIdentityDigest") != sha256_digest(
        canonical_json_bytes(comparable_java)
    ):
        errors.append("observed builder Java identity digest differs")
    expected_environment = {
        "LANG": materials.get("environment", {}).get("locale"),
        "LC_ALL": materials.get("environment", {}).get("locale"),
        "SOURCE_DATE_EPOCH": str(materials.get("canonicalBuildEpoch")),
        "TZ": materials.get("environment", {}).get("timezone"),
    }
    if environment_variables != expected_environment:
        errors.append("observed builder environment differs from authenticated materials")
    return errors


def installer_subject_binding_errors(
    role: str,
    actual_digest: str,
    actual_size: int,
    inventory_subject: dict[str, Any],
) -> list[str]:
    """Require only the candidate producer's installer container to equal release bytes."""

    if role not in {"candidate-producer", "independent-verifier"}:
        return ["installer subject uses an unsupported builder role"]
    if not DIGEST_RE.fullmatch(actual_digest) or actual_size < 0:
        return ["installer subject has an invalid observed byte identity"]
    if role == "candidate-producer" and (
        inventory_subject.get("digest") != actual_digest
        or inventory_subject.get("size") != actual_size
    ):
        return ["candidate installer bytes differ from authenticated inventory"]
    return []


def _confined_path(
    context: RunContext,
    configured: Any,
    key: str,
    *,
    allow_workspace_root: bool = False,
) -> Path:
    if not isinstance(configured, str) or not configured:
        raise ValueError(f"supply-chain input {key} must be a non-empty path")
    canonical = PurePosixPath(configured).as_posix()
    if (
        "\\" in configured
        or (configured == "." and not allow_workspace_root)
        or configured != canonical
        or "//" in configured
    ):
        raise ValueError(f"supply-chain input {key} must use a canonical relative path")
    relative = Path(configured)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError(f"supply-chain input {key} must be workspace-relative")
    workspace = context.workspace_root.resolve(strict=True)
    current = workspace
    for part in relative.parts:
        current /= part
        if current.is_symlink():
            raise ValueError(f"supply-chain input {key} traverses a symbolic link")
    resolved = current.resolve(strict=True)
    try:
        resolved.relative_to(workspace)
    except ValueError as exc:
        raise ValueError(f"supply-chain input {key} escapes the workspace") from exc
    return resolved


def configured_file(context: RunContext, key: str, *, required: bool = True) -> Path | None:
    """Resolve one workspace-confined regular-file manifest input."""

    configured = context.manifest.inputs.get(key)
    if configured is None:
        if required:
            raise ValueError(f"required supply-chain input is missing: {key}")
        return None
    path = _confined_path(context, configured, key)
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"supply-chain input {key} is not a safe regular file")
    return path


def configured_directory(
    context: RunContext,
    key: str,
    *,
    required: bool = True,
    allow_workspace_root: bool = False,
) -> Path | None:
    """Resolve one workspace-confined, non-symlink directory manifest input."""

    configured = context.manifest.inputs.get(key)
    if configured is None:
        if required:
            raise ValueError(f"required supply-chain directory is missing: {key}")
        return None
    path = _confined_path(
        context,
        configured,
        key,
        allow_workspace_root=allow_workspace_root,
    )
    if path.is_symlink() or not path.is_dir():
        raise ValueError(f"supply-chain input {key} is not a safe directory")
    return path


def load_document(
    context: RunContext,
    key: str,
    schema: str,
    *,
    required: bool = True,
    public: bool = True,
) -> tuple[Path, dict[str, Any], str] | None:
    """Load, schema-check, and optionally redact-check one canonical evidence object."""

    path = configured_file(context, key, required=required)
    if path is None:
        return None
    value = read_json(path)
    if not isinstance(value, dict):
        raise ValueError(f"supply-chain input {key} must be a JSON object")
    errors = validate_schema(value, schema)
    if errors:
        raise ValueError(f"supply-chain input {key} violates {schema}: {errors[0]}")
    if public and scan_value(value):
        raise ValueError(f"supply-chain input {key} contains redaction-unsafe data")
    return path, value, file_digest(path)


def validate_document(value: dict[str, Any], schema: str, label: str) -> None:
    """Raise if a generated document violates its closed schema."""

    errors = validate_schema(value, schema)
    if errors:
        raise ValueError(f"generated {label} violates {schema}: {errors[0]}")


def write_document(path: Path, value: dict[str, Any], schema: str) -> None:
    """Validate and deterministically write one supply-chain document."""

    validate_document(value, schema, path.name)
    if scan_value(value):
        raise ValueError(f"generated {path.name} contains redaction-unsafe data")
    write_json(path, value)


def checked_policy_errors(
    context: RunContext, supplied_path: Path, policy: dict[str, Any]
) -> list[str]:
    """Authenticate the supplied policy as exact reviewed repository bytes."""

    errors = validate_schema(policy, POLICY_SCHEMA)
    expected = context.workspace_root / "tools" / "release-certification" / POLICY_FILE
    if expected.is_symlink() or not expected.is_file():
        errors.append("checked-in supply-chain policy is missing or unsafe")
        return errors
    if supplied_path.resolve() != expected.resolve() or file_digest(supplied_path) != file_digest(
        expected
    ):
        errors.append("supplied supply-chain policy is not the exact checked-in policy")
    if semantic_digest(policy, "policyDigest") != policy.get("policyDigest"):
        errors.append("supply-chain policy digest is invalid")
    if policy.get("repositoryIdentity") != REPOSITORY_IDENTITY:
        errors.append("supply-chain repository identity differs")
    if policy.get("stableMilestone") != STABLE_MILESTONE:
        errors.append("supply-chain Stable milestone differs")
    if tuple(policy.get("modes", ())) != COMMAND_MODES:
        errors.append("supply-chain mode vocabulary differs")
    resolution_rules = policy.get("dependencyResolutionRules", {})
    mappings = resolution_rules.get("requiredConfigurationMappings", [])
    mapping_vocabulary = tuple(
        (
            row.get("projectScope"),
            row.get("sourceName"),
            row.get("requiredName"),
            row.get("role"),
        )
        for row in mappings
        if isinstance(row, dict)
    )
    if mapping_vocabulary != REQUIRED_CONFIGURATION_MAPPINGS:
        errors.append("required compiler-configuration mapping vocabulary differs")
    if tuple(resolution_rules.get("requiredBuildLogicConfigurations", ())) != (
        REQUIRED_BUILD_LOGIC_CONFIGURATIONS
    ):
        errors.append("required settings-plugin configuration vocabulary differs")
    jdk_rules = policy.get("jdkRules", {})
    if (
        jdk_rules.get("installationDigestAlgorithm")
        != JDK_INSTALLATION_DIGEST_ALGORITHM
        or jdk_rules.get("requiredInstallations")
        != [
            {"runnerOs": "linux", "architecture": "amd64"},
            {"runnerOs": "macos", "architecture": "amd64"},
            {"runnerOs": "windows", "architecture": "amd64"},
        ]
        or jdk_rules.get("runtimeSubjectClasses") != ["installer", "runtime-image"]
    ):
        errors.append("JDK policy vocabulary differs")
    origin_rules = policy.get("buildMaterialRules", {}).get("directInputOriginRules", [])
    required_direct = policy.get("buildMaterialRules", {}).get("requiredDirectInputs", [])
    if [row.get("name") for row in origin_rules if isinstance(row, dict)] != sorted(
        required_direct
    ):
        errors.append("direct-input origin rules are not the exact sorted required set")
    for row in origin_rules:
        if not isinstance(row, dict):
            continue
        try:
            re.compile(str(row.get("originPattern", "")))
        except re.error:
            errors.append(f"direct-input origin rule is invalid for {row.get('name')}")
    for rule in policy.get("releaseSubjects", []):
        if not isinstance(rule, dict):
            continue
        key = rule.get("subjectKey")
        phase = rule.get("evidencePhase")
        reproducibility_class = rule.get("reproducibilityClass")
        if phase == "independent-builder" and reproducibility_class == "not-a-product-subject":
            errors.append(f"independent-builder subject {key} is not a product subject")
        if phase == "derived-governance" and reproducibility_class != "not-a-product-subject":
            errors.append(f"derived-governance subject {key} claims product reproducibility")
        if phase == "derived-governance" and rule.get("normalizationRuleId") is not None:
            errors.append(f"derived-governance subject {key} claims a product payload view")
    return errors


def release_identity(context: RunContext, policy_digest: str) -> dict[str, Any]:
    """Return the exact release identity used by all generated documents."""

    version = context.manifest.release.version
    if not isinstance(version, str) or not version.isdigit() or int(version) < 1:
        raise ValueError("Stable supply-chain release version must be an integer build")
    commit = context.manifest.policies.get("candidateSourceCommit")
    source_ref = context.manifest.policies.get("candidateSourceRef")
    if not isinstance(commit, str) or COMMIT_RE.fullmatch(commit) is None:
        raise ValueError("Stable supply-chain candidateSourceCommit must be a full Git commit")
    if source_ref != f"commit:{commit}":
        raise ValueError("Stable supply-chain candidateSourceRef must bind the exact full commit")
    return {
        "releaseId": context.manifest.release.release_id,
        "buildVersion": int(version),
        "tag": f"v{version}",
        "sourceCommit": commit,
        "sourceRef": source_ref,
        "policyDigest": policy_digest,
    }


def self_digest_errors(value: dict[str, Any], field: str, label: str) -> list[str]:
    """Return a failure when a digest-bearing object does not authenticate itself."""

    expected = value.get(field)
    if not isinstance(expected, str) or DIGEST_RE.fullmatch(expected) is None:
        return [f"{label} lacks a valid {field}"]
    if semantic_digest(value, field) != expected:
        return [f"{label} {field} is invalid"]
    return []


def _mutable_version(version: Any) -> bool:
    return (
        not isinstance(version, str)
        or not version
        or version.startswith(("[", "("))
        or version.endswith(("]", ")", ","))
        or MUTABLE_VERSION_RE.search(version) is not None
    )


def component_inventory_errors(
    inventory: dict[str, Any], policy: dict[str, Any], release: dict[str, Any]
) -> list[str]:
    """Validate canonical component identities and their non-waivable metadata."""

    errors = validate_schema(inventory, COMPONENT_INVENTORY_SCHEMA)
    errors.extend(self_digest_errors(inventory, "inventoryDigest", "component inventory"))
    for field in ("releaseId", "buildVersion", "sourceCommit", "policyDigest"):
        if inventory.get(field) != release.get(field):
            errors.append(f"component inventory {field} differs")
    components = inventory.get("components")
    components = components if isinstance(components, list) else []
    ids: dict[str, str | None] = {}
    purls: set[str] = set()
    if [row.get("componentId") for row in components if isinstance(row, dict)] != sorted(
        row.get("componentId") for row in components if isinstance(row, dict)
    ):
        errors.append("component inventory is not sorted by canonical component id")
    license_policy = policy.get("licensePolicy", {})
    blocked_statuses = set(license_policy.get("blockingStatuses", []))
    for component in components:
        if not isinstance(component, dict):
            continue
        component_id = component.get("componentId")
        if not isinstance(component_id, str) or COMPONENT_ID_RE.fullmatch(component_id) is None:
            errors.append("component identity is not a canonical PURL")
            continue
        digest = component.get("digest")
        if not isinstance(digest, str) or DIGEST_RE.fullmatch(digest) is None:
            errors.append(f"component {component_id} has no exact content digest")
        if component_id in ids:
            qualifier = "with different content" if ids[component_id] != digest else ""
            errors.append(f"duplicate component identity {qualifier}".rstrip())
        ids[component_id] = digest if isinstance(digest, str) else None
        purl = component.get("purl")
        if not isinstance(purl, str):
            errors.append(f"component {component_id} has no canonical PURL")
        else:
            if purl in purls:
                errors.append("duplicate component PURL identity")
            purls.add(purl)
            if purl != component_id:
                errors.append(f"component {component_id} has an ambiguous PURL alias")
        if _mutable_version(component.get("version")) and not (
            component.get("componentKind") == "jdk-module"
            and isinstance(component.get("version"), str)
            and JDK_BUILD_RE.fullmatch(component["version"]) is not None
        ):
            errors.append(f"component {component_id} has a mutable or missing version")
        origin = component.get("origin")
        if not isinstance(origin, dict) or not origin.get("immutableReference"):
            errors.append(f"component {component_id} has no immutable origin")
        elif origin.get("type") not in set(policy.get("acceptedOrigins", [])):
            errors.append(f"component {component_id} has an unapproved origin")
        if not component.get("subjectKeys"):
            errors.append(f"component {component_id} is not mapped to a release subject")
        license_row = component.get("license")
        if not isinstance(license_row, dict):
            errors.append(f"component {component_id} has no license decision")
        else:
            status = license_row.get("status")
            expression = license_row.get("expression")
            if status in blocked_statuses or (
                "runtime" in component.get("roles", []) and expression == "NOASSERTION"
            ):
                errors.append(f"component {component_id} has a blocking license decision")
            if status != "not-applicable-internal" and not license_row.get(
                "licenseTextDigest"
            ):
                errors.append(f"component {component_id} lacks license text evidence")
            if status == "not-applicable-internal" and (
                component.get("origin", {}).get("type")
                not in {"built-first-party", "repository-source"}
                or license_row.get("licenseTextDigest") is not None
            ):
                errors.append(
                    f"component {component_id} has an inconsistent internal license decision"
                )
        if component.get("dependencyVerificationStatus") not in {"verified", "not-applicable"}:
            errors.append(f"component {component_id} is not dependency-verified")
        if component.get("buildMaterialStatus") not in {"verified", "built", "not-applicable"}:
            errors.append(f"component {component_id} has an unknown build-material status")
        if semantic_digest(component, "recordDigest") != component.get("recordDigest"):
            errors.append(f"component {component_id} record digest is invalid")
    return errors


def jdk_component_coverage_errors(
    components_document: dict[str, Any],
    subjects_document: dict[str, Any],
    materials: dict[str, Any],
    policy: dict[str, Any],
) -> list[str]:
    """Reconcile the exact jlink module set with canonical components and shipped subjects."""

    errors: list[str] = []
    jdk = materials.get("jdk", {})
    modules = jdk.get("modules", [])
    build = jdk.get("build")
    distribution_digest = jdk.get("distributionDigest")
    components = [
        row
        for row in components_document.get("components", [])
        if isinstance(row, dict) and row.get("componentKind") == "jdk-module"
    ]
    component_names = [row.get("name") for row in components]
    if component_names != sorted(modules):
        errors.append("canonical JDK components differ from the authenticated runtime modules")
    policy_subjects = {
        row.get("subjectKey"): row
        for row in policy.get("releaseSubjects", [])
        if isinstance(row, dict)
    }
    actual_subjects = {
        row.get("subjectKey")
        for row in subjects_document.get("subjects", [])
        if isinstance(row, dict)
    }
    required_classes = set(policy.get("jdkRules", {}).get("runtimeSubjectClasses", []))
    expected_subject_keys = sorted(
        key
        for key in actual_subjects
        if isinstance(key, str)
        and policy_subjects.get(key, {}).get("subjectClass") in required_classes
    )
    for component in components:
        module = component.get("name")
        expected_id = f"pkg:generic/openjdk-module/{module}@{build}"
        if component.get("componentId") != expected_id or component.get("purl") != expected_id:
            errors.append(f"JDK module {module} has a non-canonical component identity")
        if (
            component.get("version") != build
            or component.get("namespace") != "openjdk"
            or component.get("digest") != distribution_digest
        ):
            errors.append(f"JDK module {module} differs from authenticated build materials")
        origin = component.get("origin", {})
        if (
            origin.get("type") != "openjdk"
            or origin.get("immutableReference") != distribution_digest
            or origin.get("provenanceDigest") != distribution_digest
        ):
            errors.append(f"JDK module {module} lacks exact distribution provenance")
        if component.get("roles") != ["runtime"]:
            errors.append(f"JDK module {module} does not have the closed runtime role")
        if component.get("subjectKeys") != expected_subject_keys:
            errors.append(f"JDK module {module} is not mapped to every shipped runtime image")
        if component.get("dependencyVerificationStatus") != "not-applicable" or component.get(
            "buildMaterialStatus"
        ) != "verified":
            errors.append(f"JDK module {module} is not authenticated as a build material")
    return errors


def subject_inventory_errors(
    subjects_document: dict[str, Any],
    components_document: dict[str, Any],
    policy: dict[str, Any],
    release: dict[str, Any],
    subject_root: Path | None = None,
) -> list[str]:
    """Validate subject/component coverage and, when supplied, the exact packaged bytes."""

    errors = validate_schema(subjects_document, SUBJECT_INVENTORY_SCHEMA)
    errors.extend(
        self_digest_errors(subjects_document, "subjectInventoryDigest", "subject inventory")
    )
    for field in ("releaseId", "buildVersion", "sourceCommit", "policyDigest"):
        if subjects_document.get(field) != release.get(field):
            errors.append(f"subject inventory {field} differs")
    if subjects_document.get("componentInventoryDigest") != components_document.get(
        "inventoryDigest"
    ):
        errors.append("subject inventory binds a different component inventory")

    components = {
        row.get("componentId"): row
        for row in components_document.get("components", [])
        if isinstance(row, dict)
    }
    subjects = subjects_document.get("subjects")
    subjects = subjects if isinstance(subjects, list) else []
    if [row.get("subjectKey") for row in subjects if isinstance(row, dict)] != sorted(
        row.get("subjectKey") for row in subjects if isinstance(row, dict)
    ):
        errors.append("release subjects are not sorted by subject key")
    by_key: dict[str, dict[str, Any]] = {}
    for subject in subjects:
        if not isinstance(subject, dict):
            continue
        key = subject.get("subjectKey")
        if not isinstance(key, str):
            continue
        if key in by_key:
            errors.append(f"duplicate release subject key {key}")
        by_key[key] = subject
        component_ids = subject.get("componentIds", [])
        if component_ids != sorted(set(component_ids)):
            errors.append(f"subject {key} component ids are not unique and sorted")
        for component_id in component_ids:
            component = components.get(component_id)
            if component is None:
                errors.append(f"subject {key} references an unknown component")
            elif key not in component.get("subjectKeys", []):
                errors.append(f"subject {key} and component {component_id} disagree")
        if subject.get("reproducibilityClass") == "normalized-payload-identical":
            if not subject.get("payloadManifestDigest"):
                errors.append(f"normalized subject {key} lacks a payload manifest")
            if not subject.get("packageMetadataDigest"):
                errors.append(f"normalized subject {key} lacks exact package metadata")
            if not subject.get("signatureReceiptDigest"):
                errors.append(f"normalized subject {key} lacks authenticated signing evidence")
        relative_errors = safe_relative_path_errors(subject.get("fileName"), f"subject {key}")
        errors.extend(relative_errors)
        if subject_root is not None and not relative_errors:
            path = confined_child(subject_root, str(subject["fileName"]))
            if path is None or not path.is_file() or path.is_symlink():
                errors.append(f"subject {key} bytes are missing")
            else:
                if file_digest(path) != subject.get("digest"):
                    errors.append(f"subject {key} digest mismatch")
                if path.stat().st_size != subject.get("size"):
                    errors.append(f"subject {key} size mismatch")
    for component_id, component in components.items():
        for subject_key in component.get("subjectKeys", []):
            subject = by_key.get(subject_key)
            if subject is None:
                errors.append(f"component {component_id} maps to an absent subject")
            elif component_id not in subject.get("componentIds", []):
                errors.append(f"component {component_id} is omitted from subject {subject_key}")

    policy_rules = {
        row.get("subjectKey"): row
        for row in policy.get("releaseSubjects", [])
        if isinstance(row, dict)
    }
    actual_product_keys = {
        key
        for key, rule in policy_rules.items()
        if isinstance(key, str)
        and rule.get("normalizationRuleId") is not None
        and rule.get("reproducibilityClass") != "not-a-product-subject"
    }
    for component_id, component in components.items():
        if "runtime" not in component.get("roles", []):
            continue
        mapped_keys = set(component.get("subjectKeys", []))
        for incompatible_key in sorted(mapped_keys.difference(actual_product_keys)):
            if incompatible_key in policy_rules:
                errors.append(
                    f"runtime component {component_id} maps to non-product subject "
                    f"{incompatible_key}"
                )
        if not mapped_keys.intersection(actual_product_keys).intersection(by_key):
            errors.append(
                f"runtime component {component_id} is not contained by an actual product subject"
            )
    for key, subject in by_key.items():
        rule = policy_rules.get(key)
        if rule is None:
            errors.append(f"subject {key} is not authorized by policy")
            continue
        if subject.get("subjectClass") != rule.get("subjectClass"):
            errors.append(f"subject {key} uses a candidate-selected subject class")
        if subject.get("reproducibilityClass") != rule.get("reproducibilityClass"):
            errors.append(f"subject {key} uses a candidate-selected reproducibility class")
        errors.extend(_subject_metadata_errors(key, subject, rule, policy))
    for key, rule in policy_rules.items():
        if rule.get("required") is True and key not in by_key:
            errors.append(f"policy-required subject {key} is absent")
    return errors


def _subject_metadata_errors(
    key: str,
    subject: dict[str, Any],
    rule: dict[str, Any],
    policy: dict[str, Any],
) -> list[str]:
    """Enforce the one policy-declared metadata shape for each release subject class."""

    errors: list[str] = []
    metadata_policy = policy.get("subjectMetadataRules", {})
    subject_class = rule.get("subjectClass")
    normalization_required = rule.get("normalizationRuleId") is not None
    app_required = subject_class in metadata_policy.get("appMetadataClasses", [])
    catalog_required = subject_class in metadata_policy.get("catalogMetadataClasses", [])
    signature_required = subject_class in metadata_policy.get(
        "signatureReceiptClasses", []
    )

    if (subject.get("app") is not None) != app_required:
        qualifier = "lacks" if app_required else "contains prohibited"
        errors.append(f"subject {key} {qualifier} app metadata")
    if (subject.get("catalogEdition") is not None) != catalog_required:
        qualifier = "lacks" if catalog_required else "contains prohibited"
        errors.append(f"subject {key} {qualifier} catalog metadata")
    if (subject.get("signatureReceiptDigest") is not None) != signature_required:
        qualifier = "lacks" if signature_required else "contains prohibited"
        errors.append(f"subject {key} {qualifier} signature receipt metadata")
    notarization_required = key == "amd64.dmg"
    if (subject.get("notarizationReceiptDigest") is not None) != notarization_required:
        qualifier = "lacks" if notarization_required else "contains prohibited"
        errors.append(f"subject {key} {qualifier} notarization receipt metadata")
    if (subject.get("payloadManifestDigest") is not None) != normalization_required:
        qualifier = "lacks" if normalization_required else "contains prohibited"
        errors.append(f"subject {key} {qualifier} actual-content manifest metadata")
    if (subject.get("packageMetadataDigest") is not None) != normalization_required:
        qualifier = "lacks" if normalization_required else "contains prohibited"
        errors.append(f"subject {key} {qualifier} package metadata")
    return errors


def resolution_snapshot_errors(
    snapshot: dict[str, Any], release: dict[str, Any], policy: dict[str, Any]
) -> list[str]:
    """Validate the authenticated Gradle/build dependency resolution snapshot."""

    errors = validate_schema(snapshot, RESOLUTION_SNAPSHOT_SCHEMA)
    errors.extend(self_digest_errors(snapshot, "snapshotDigest", "resolution snapshot"))
    for field in ("sourceCommit", "policyDigest"):
        if snapshot.get(field) != release.get(field):
            errors.append(f"resolution snapshot {field} differs")
    if snapshot.get("dependencyVerification", {}).get("status") != "verified":
        errors.append("dependency verification did not pass")
    locking = snapshot.get("locking", {})
    locking_status = locking.get("status")
    snapshot_mode = locking.get("snapshotMode")
    if locking_status == "authenticated-snapshot":
        if snapshot_mode != "authenticated-resolution-snapshot":
            errors.append("authenticated dependency snapshot uses an invalid mode")
        if locking.get("lockDigest") != snapshot.get("materialDigests", {}).get(
            "rawResolutionExport"
        ):
            errors.append("authenticated dependency snapshot does not bind the raw resolution export")
    else:
        errors.append("release-relevant dependency resolution lacks an authenticated reviewed export")
    records = snapshot.get("components", [])
    ids: set[str] = set()
    for row in records:
        if not isinstance(row, dict):
            continue
        component_id = row.get("componentId")
        if component_id in ids:
            errors.append("resolved dependency component is duplicated")
        ids.add(str(component_id))
        if _mutable_version(row.get("version")) or row.get("changing") is True:
            errors.append(f"resolved dependency {component_id} is mutable")
        verification_status = row.get("verificationStatus")
        if verification_status == "authenticated-first-party":
            if row.get("componentKind") != "internal-project" or not str(
                component_id
            ).startswith("pkg:generic/cryptad-module/"):
                errors.append(
                    f"resolved dependency {component_id} spoofs first-party authentication"
                )
            if not isinstance(snapshot.get("materialDigests", {}).get("rawResolutionExport"), str):
                errors.append(
                    f"resolved dependency {component_id} lacks its authenticated raw resolution export"
                )
        elif verification_status != "verified":
            errors.append(f"resolved dependency {component_id} is unverified")
    if [row.get("componentId") for row in records if isinstance(row, dict)] != sorted(
        row.get("componentId") for row in records if isinstance(row, dict)
    ):
        errors.append("resolved dependency snapshot is not deterministically sorted")
    configurations = snapshot.get("configurations", [])
    configuration_order = [
        (row.get("project"), row.get("name"), row.get("role"))
        for row in configurations
        if isinstance(row, dict)
    ]
    if configuration_order != sorted(configuration_order):
        errors.append("resolved configurations are not deterministically sorted")
    if len(configuration_order) != len(set(configuration_order)):
        errors.append("resolved configurations contain a duplicate identity")
    represented_roles: dict[str, set[str]] = {}
    resolved_ids = {
        str(row.get("componentId")) for row in records if isinstance(row, dict)
    }
    for configuration in configurations:
        if not isinstance(configuration, dict):
            continue
        if configuration.get("attributes") != _sorted_attributes(
            configuration.get("attributes")
        ):
            errors.append("resolved configuration attributes are not deterministically sorted")
        component_ids = configuration.get("componentIds", [])
        if component_ids != sorted(set(component_ids)):
            errors.append("resolved configuration component ids are not canonical")
        for component_id in component_ids:
            if str(component_id) not in resolved_ids:
                errors.append("resolved configuration references an unknown component")
            represented_roles.setdefault(str(component_id), set()).add(
                str(configuration.get("role"))
            )
    role_order = {role: index for index, role in enumerate(COMPONENT_ROLES)}
    for row in records:
        if not isinstance(row, dict):
            continue
        component_id = str(row.get("componentId"))
        if row.get("attributes") != _sorted_attributes(row.get("attributes")):
            errors.append(f"resolved dependency {component_id} attributes are not canonical")
        roles = row.get("roles", [])
        if roles != sorted(set(roles), key=lambda role: role_order.get(str(role), 999)):
            errors.append(f"resolved dependency {component_id} roles are not canonical")
        parents = row.get("parents", [])
        if parents != sorted(set(parents)):
            errors.append(f"resolved dependency {component_id} parents are not canonical")
        if set(str(parent) for parent in parents).difference(resolved_ids):
            errors.append(f"resolved dependency {component_id} has an unknown parent")
        if set(roles) != represented_roles.get(component_id, set()):
            errors.append(
                f"resolved dependency {component_id} roles differ from its configurations"
            )
    if policy.get("dependencyResolutionRules", {}).get("buildLogicComponentsRequired"):
        build_logic_configurations = [
            row
            for row in configurations
            if isinstance(row, dict)
            and row.get("project") == ":build-logic"
            and row.get("role") == "build"
            and row.get("componentIds")
        ]
        if not build_logic_configurations:
            errors.append("authenticated resolution snapshot omits build-logic components")
    resolution_rules = policy.get("dependencyResolutionRules", {})
    configurations_by_identity = {
        (row.get("project"), row.get("name")): row
        for row in configurations
        if isinstance(row, dict)
    }
    for mapping in resolution_rules.get("requiredConfigurationMappings", []):
        if not isinstance(mapping, dict):
            continue
        source_name = mapping.get("sourceName")
        required_name = mapping.get("requiredName")
        required_role = mapping.get("role")
        project_scope = mapping.get("projectScope")
        source_projects = sorted(
            {
                str(row.get("project"))
                for row in configurations
                if isinstance(row, dict)
                and row.get("name") == source_name
                and not (
                    project_scope == "release-projects"
                    and row.get("project") == ":build-logic"
                )
            }
        )
        for project in source_projects:
            required = configurations_by_identity.get((project, required_name))
            if (
                required is None
                or required.get("role") != required_role
                or not required.get("componentIds")
            ):
                errors.append(
                    f"resolved project {project} omits required {required_name} "
                    f"{required_role} materials"
                )
    for configuration_name in resolution_rules.get(
        "requiredBuildLogicConfigurations", []
    ):
        required = configurations_by_identity.get(
            (":build-logic", configuration_name)
        )
        if (
            required is None
            or required.get("role") != "build"
            or not required.get("componentIds")
        ):
            errors.append(
                "authenticated resolution snapshot omits required settings-plugin "
                f"configuration {configuration_name}"
            )
    required_materials = set(policy.get("buildMaterialRules", {}).get("requiredDigests", []))
    materials = snapshot.get("materialDigests", {})
    for material in sorted(required_materials):
        if not isinstance(materials.get(material), str):
            errors.append(f"resolution snapshot lacks required {material} digest")
    return errors


def _sorted_attributes(value: Any) -> list[dict[str, Any]]:
    rows = value if isinstance(value, list) else []
    return sorted(
        (row for row in rows if isinstance(row, dict)),
        key=lambda row: (str(row.get("name")), str(row.get("value"))),
    )


def build_material_errors(
    materials: dict[str, Any],
    release: dict[str, Any],
    snapshot_digest: str,
    policy: dict[str, Any] | None = None,
    snapshot: dict[str, Any] | None = None,
) -> list[str]:
    """Validate exact source, toolchain, workflow, and environment identities."""

    errors = validate_schema(materials, BUILD_MATERIALS_SCHEMA)
    errors.extend(self_digest_errors(materials, "materialsDigest", "build materials"))
    for field in ("releaseId", "buildVersion", "sourceCommit", "sourceRef", "policyDigest"):
        if materials.get(field) != release.get(field):
            errors.append(f"build materials {field} differs")
    if materials.get("resolutionSnapshotDigest") != snapshot_digest:
        errors.append("build materials bind a different resolution snapshot")
    if materials.get("source", {}).get("clean") is not True:
        errors.append("build materials report a dirty source tree")
    if materials.get("source", {}).get("commit") != release.get("sourceCommit"):
        errors.append("build material source commit differs")
    if materials.get("source", {}).get("ref") != release.get("sourceRef"):
        errors.append("build material source ref differs")
    environment = materials.get("environment", {})
    if environment.get("timezone") != "UTC" or environment.get("encoding") != "UTF-8":
        errors.append("build environment timezone or encoding is not canonical")
    if environment.get("locale") not in {"C", "C.UTF-8"}:
        errors.append("build environment locale is not canonical")
    authenticated_commit_time = materials.get("source", {}).get(
        "authenticatedCommitTime"
    )
    try:
        expected_epoch = int(
            parse_timestamp(
                authenticated_commit_time, "build material authenticated commit time"
            ).timestamp()
        )
        if materials.get("canonicalBuildEpoch") != expected_epoch:
            errors.append(
                "canonical build epoch differs from the authenticated source commit time"
            )
    except ValueError as exc:
        errors.append(str(exc))
    if not materials.get("buildTasks"):
        errors.append("build material record has no exact task set")
    workflow = materials.get("workflow", {})
    if workflow.get("workflowSha") != release.get("sourceCommit") or not str(
        workflow.get("workflowRef", "")
    ).endswith("@" + str(release.get("sourceCommit"))):
        errors.append("build material workflow identity differs from the exact source commit")
    if materials.get("jdk", {}).get("modules") != sorted(
        set(materials.get("jdk", {}).get("modules", []))
    ):
        errors.append("JDK module inventory is not uniquely and deterministically sorted")
    if policy is not None:
        jdk = materials.get("jdk", {})
        jdk_rules = policy.get("jdkRules", {})
        installations = jdk.get("installations", [])
        installation_coordinates = [
            {
                "runnerOs": row.get("runnerOs"),
                "architecture": row.get("architecture"),
            }
            for row in installations
            if isinstance(row, dict)
        ]
        if installation_coordinates != jdk_rules.get("requiredInstallations"):
            errors.append("JDK installations differ from the closed policy platform set")
        if (
            jdk.get("distribution") != jdk_rules.get("distribution")
            or jdk.get("setupJavaVersion") != jdk_rules.get("setupJavaVersion")
            or jdk.get("build") != jdk.get("setupJavaVersion")
            or jdk.get("installationDigestAlgorithm")
            != jdk_rules.get("installationDigestAlgorithm")
            or jdk.get("installationDigestAlgorithm")
            != JDK_INSTALLATION_DIGEST_ALGORITHM
        ):
            errors.append("JDK distribution identity differs from policy")
        if jdk.get("distributionDigest") != sha256_digest(
            canonical_json_bytes(installations)
        ):
            errors.append("JDK distribution digest does not bind its platform installations")
        expected_environment_variables = policy.get("buildMaterialRules", {}).get(
            "allowedEnvironmentVariableNames"
        )
        if expected_environment_variables != list(
            CANONICAL_BUILD_ENVIRONMENT_VARIABLES
        ):
            errors.append(
                "policy build environment variable names are not the closed canonical set"
            )
        if environment.get("allowedVariableNames") != expected_environment_variables:
            errors.append(
                "build material environment variable names differ from policy"
            )
        packaging_inputs = {
            row.get("path"): row.get("digest")
            for row in materials.get("packagingInputs", [])
            if isinstance(row, dict)
        }
        for name in policy.get("buildMaterialRules", {}).get("requiredDirectInputs", []):
            if "external/" + str(name) not in packaging_inputs:
                errors.append(f"build materials omit authenticated direct input {name}")
        direct_inputs = materials.get("directInputs", [])
        direct_names = [row.get("name") for row in direct_inputs if isinstance(row, dict)]
        required_direct = sorted(
            policy.get("buildMaterialRules", {}).get("requiredDirectInputs", [])
        )
        if direct_names != required_direct:
            errors.append("build material direct inputs are not the exact sorted policy set")
        origin_rules = {
            row.get("name"): row
            for row in policy.get("buildMaterialRules", {}).get(
                "directInputOriginRules", []
            )
            if isinstance(row, dict)
        }
        for row in direct_inputs:
            if not isinstance(row, dict):
                continue
            name = row.get("name")
            rule = origin_rules.get(name)
            if not isinstance(rule, dict):
                errors.append(f"build material direct input {name} has no origin rule")
                continue
            origin = row.get("origin")
            pattern = rule.get("originPattern")
            if (
                row.get("immutabilityClass") != rule.get("immutabilityClass")
                or not isinstance(origin, str)
                or not isinstance(pattern, str)
                or re.fullmatch(pattern, origin) is None
            ):
                errors.append(f"build material direct input {name} has a mutable origin")
            if packaging_inputs.get("external/" + str(name)) != row.get("digest"):
                errors.append(
                    f"build material direct input {name} differs from packaging inputs"
                )
    if snapshot is not None:
        snapshot_materials = snapshot.get("materialDigests", {})
        gradle_materials = materials.get("gradle", {})
        for snapshot_name, material_name in (
            ("gradleWrapperJar", "wrapperJarDigest"),
            ("gradleWrapperProperties", "wrapperPropertiesDigest"),
            ("gradleDistribution", "distributionDigest"),
            ("versionCatalog", "versionCatalogDigest"),
            ("repositoryConfiguration", "repositoryConfigurationDigest"),
            ("verificationMetadata", "verificationMetadataDigest"),
            ("verificationKeyring", "verificationKeyringDigest"),
            ("buildLogic", "buildLogicDigest"),
            ("pluginResolution", "pluginResolutionDigest"),
            ("testResolution", "testResolutionDigest"),
            ("rawResolutionExport", "rawResolutionExportDigest"),
        ):
            if snapshot_materials.get(snapshot_name) != gradle_materials.get(
                material_name
            ):
                errors.append(f"build materials bind a different {snapshot_name}")
        if snapshot.get("dependencyVerification", {}).get(
            "keyringKeysDigest"
        ) != gradle_materials.get("verificationKeyringKeysDigest"):
            errors.append("build materials bind different verification key identities")
    return errors


def license_inventory_errors(
    license_inventory: dict[str, Any],
    components_document: dict[str, Any],
    policy: dict[str, Any],
    license_text_root: Path | None,
    overrides: dict[str, Any] | None = None,
) -> list[str]:
    """Validate closed license decisions, evidence bytes, and exact overrides."""

    errors = validate_schema(license_inventory, LICENSE_INVENTORY_SCHEMA)
    errors.extend(self_digest_errors(license_inventory, "licenseInventoryDigest", "license inventory"))
    if license_inventory.get("componentInventoryDigest") != components_document.get(
        "inventoryDigest"
    ):
        errors.append("license inventory binds a different component inventory")
    if license_inventory.get("policyDigest") != policy.get("policyDigest"):
        errors.append("license inventory binds a different policy")
    component_by_id = {
        row.get("componentId"): row
        for row in components_document.get("components", [])
        if isinstance(row, dict)
    }
    rows = license_inventory.get("components", [])
    rows_by_id: dict[str, dict[str, Any]] = {}
    used_texts: set[str] = set()
    blocked = set(policy.get("licensePolicy", {}).get("blockingStatuses", []))
    if [row.get("componentId") for row in rows if isinstance(row, dict)] != sorted(
        row.get("componentId") for row in rows if isinstance(row, dict)
    ):
        errors.append("license inventory is not sorted by canonical component id")
    for row in rows:
        if not isinstance(row, dict):
            continue
        component_id = str(row.get("componentId"))
        if component_id in rows_by_id:
            errors.append("license inventory component is duplicated")
        rows_by_id[component_id] = row
        component = component_by_id.get(component_id)
        if component is None:
            errors.append(f"license inventory references unknown component {component_id}")
            continue
        expected = component.get("license", {})
        for field in ("expression", "status", "evidenceDigest", "licenseTextDigest"):
            if row.get(field) != expected.get(field):
                errors.append(f"license decision for {component_id} diverges from component graph")
        if row.get("status") in blocked or row.get("expression") == "NOASSERTION":
            errors.append(f"license decision for {component_id} blocks Stable promotion")
        status = row.get("status")
        text_path = row.get("licenseTextPath")
        text_digest = row.get("licenseTextDigest")
        notice_required = row.get("noticeRequired") is True
        if status == "allowed-with-notice" and not notice_required:
            errors.append(f"license notice for {component_id} is not required by its decision")
        if notice_required and (text_path is None or text_digest is None):
            errors.append(f"required license notice for {component_id} lacks exact text evidence")
        if (
            policy.get("licensePolicy", {}).get("licenseTextRequired")
            and status != "not-applicable-internal"
            and (text_path is None or text_digest is None)
        ):
            errors.append(f"license decision for {component_id} lacks required license text")
        if status == "not-applicable-internal" and (
            row.get("decisionSource") != "internal-policy"
            or notice_required
            or text_path is not None
            or text_digest is not None
        ):
            errors.append(f"internal license decision for {component_id} is inconsistent")
        if text_path is not None:
            path_errors = safe_relative_path_errors(text_path, "license text")
            errors.extend(path_errors)
            if not path_errors and license_text_root is not None:
                path = confined_child(license_text_root, str(text_path))
                if path is None or not path.is_file() or path.is_symlink():
                    errors.append(f"license text for {component_id} is missing")
                elif file_digest(path) != row.get("licenseTextDigest"):
                    errors.append(f"license text for {component_id} was substituted")
                used_texts.add(str(text_path))
    for component_id in component_by_id:
        if component_id not in rows_by_id:
            errors.append(f"component {component_id} is omitted from the license inventory")
    if overrides is not None:
        errors.extend(validate_schema(overrides, LICENSE_OVERRIDES_SCHEMA))
        errors.extend(self_digest_errors(overrides, "overridesDigest", "license overrides"))
        override_by_component: dict[str, dict[str, Any]] = {}
        for override in overrides.get("overrides", []):
            if not isinstance(override, dict):
                continue
            override_id = str(override.get("componentId"))
            if override_id in override_by_component:
                errors.append(f"license override for {override_id} is duplicated")
            override_by_component[override_id] = override
        used_overrides: set[str] = set()
        for component_id, row in rows_by_id.items():
            if row.get("decisionSource") == "override":
                override = override_by_component.get(component_id)
                component = component_by_id.get(component_id, {})
                stale = (
                    override is None
                    or override.get("version") != component.get("version")
                    or override.get("componentDigest") != component.get("digest")
                    or override.get("licenseExpression") != row.get("expression")
                    or override.get("licenseTextPath") != row.get("licenseTextPath")
                    or override.get("licenseTextDigest") != row.get("licenseTextDigest")
                    or overrides.get("policyEdition") != policy.get("edition")
                )
                if stale:
                    errors.append(f"license override for {component_id} is stale")
                else:
                    used_overrides.add(component_id)
        for component_id in sorted(set(override_by_component).difference(used_overrides)):
            errors.append(f"license override for {component_id} is unused")
    notice_rows = sorted(
        [
            {
                "componentId": row.get("componentId"),
                "expression": row.get("expression"),
                "evidenceDigest": row.get("evidenceDigest"),
                "licenseTextPath": row.get("licenseTextPath"),
                "licenseTextDigest": row.get("licenseTextDigest"),
            }
            for row in rows
            if isinstance(row, dict) and row.get("noticeRequired") is True
        ],
        key=lambda row: str(row["componentId"]),
    )
    if license_inventory.get("noticesDigest") != sha256_digest(
        canonical_json_bytes(notice_rows)
    ):
        errors.append("license notice-set digest is invalid")
    if license_text_root is not None and policy.get("licensePolicy", {}).get(
        "orphanedLicenseTextsBlock"
    ):
        candidates = [license_text_root / "LICENSE"]
        checked_in_notices = license_text_root / "docs" / "licenses"
        if checked_in_notices.is_dir() and not checked_in_notices.is_symlink():
            candidates.extend(checked_in_notices.rglob("*"))
        actual = {
            path.relative_to(license_text_root).as_posix()
            for path in candidates
            if path.is_file() and not path.is_symlink()
        }
        orphaned = actual.difference(used_texts)
        if orphaned:
            errors.append("license text root contains orphaned notice files")
    return errors


def safe_relative_path_errors(value: Any, label: str) -> list[str]:
    """Reject non-canonical, host-specific, or escaping archive paths."""

    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        return [f"{label} path is malformed"]
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or value != path.as_posix()
        or "//" in value
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        return [f"{label} path is absolute, non-canonical, or traversing"]
    if any(part == "__MACOSX" or part == ".DS_Store" or part.startswith("._") for part in path.parts):
        return [f"{label} contains prohibited host metadata"]
    if len(value.encode("utf-8")) > 1024:
        return [f"{label} path exceeds the policy bound"]
    return []


def confined_child(root: Path, relative: str) -> Path | None:
    """Return a safe child path without following symlinks or escaping its root."""

    if safe_relative_path_errors(relative, "confined child"):
        return None
    current = root.resolve(strict=True)
    for part in PurePosixPath(relative).parts:
        current /= part
        if current.is_symlink():
            return None
    try:
        resolved = current.resolve(strict=False)
        resolved.relative_to(root.resolve(strict=True))
    except (OSError, ValueError):
        return None
    return resolved


def payload_manifest_errors(manifest: dict[str, Any], policy: dict[str, Any]) -> list[str]:
    """Validate one safe, complete, policy-controlled canonical payload view."""

    errors = validate_schema(manifest, PAYLOAD_MANIFEST_SCHEMA)
    errors.extend(self_digest_errors(manifest, "manifestDigest", "payload manifest"))
    rule_id = manifest.get("normalizationRuleId")
    rules = {
        row.get("id"): row
        for row in policy.get("normalizationRules", [])
        if isinstance(row, dict)
    }
    if rule_id not in rules:
        errors.append("payload manifest uses a candidate-selected normalization rule")
    else:
        rule = rules[rule_id]
        if manifest.get("normalizationRuleVersion") != rule.get("version"):
            errors.append("payload manifest normalization rule version differs")
        if manifest.get("packageType") not in rule.get("packageTypes", []):
            errors.append("payload manifest package type differs from its normalization rule")
    entries = manifest.get("entries", [])
    seen: set[str] = set()
    folded: set[str] = set()
    total_size = 0
    for row in entries:
        if not isinstance(row, dict):
            continue
        path = row.get("path")
        path_errors = safe_relative_path_errors(path, "payload entry")
        errors.extend(path_errors)
        if not isinstance(path, str):
            continue
        if path in seen:
            errors.append("payload manifest contains duplicate normalized paths")
        seen.add(path)
        folded_path = path.casefold()
        if folded_path in folded:
            errors.append("payload manifest contains a case-fold collision")
        folded.add(folded_path)
        kind = row.get("kind")
        if kind in {"device", "socket", "fifo", "hardlink"}:
            errors.append("payload manifest contains a prohibited file kind")
        component_ids = row.get("componentIds")
        if (
            not isinstance(component_ids, list)
            or not component_ids
            or component_ids != sorted(set(component_ids))
        ):
            errors.append("payload manifest component mapping is absent or non-canonical")
        digest = row.get("digest")
        size = row.get("size")
        mode_class = row.get("modeClass")
        target = row.get("symlinkTarget")
        if kind == "file" and (
            not isinstance(digest, str)
            or not isinstance(size, int)
            or size < 0
            or mode_class not in {"executable", "read-only", "regular"}
            or target is not None
        ):
            errors.append("payload manifest regular-file fields are inconsistent")
        if kind == "directory" and (
            digest is not None or size != 0 or mode_class != "directory" or target is not None
        ):
            errors.append("payload manifest directory fields are inconsistent")
        if kind == "symlink":
            parent = PurePosixPath(path).parent
            if (
                digest is not None
                or size != 0
                or mode_class != "symlink"
                or not isinstance(target, str)
                or target.startswith("/")
            ):
                errors.append("payload manifest contains an unsafe symlink")
            else:
                normalized = posixpath.normpath((parent / target).as_posix())
                if normalized == ".." or normalized.startswith("../"):
                    errors.append("payload manifest contains an escaping symlink")
        total_size += row.get("size", 0) if isinstance(row.get("size"), int) else 0
    bounds = policy.get("publicArtifactBounds", {})
    if len(entries) > bounds.get("maximumPayloadEntries", 100000):
        errors.append("payload manifest exceeds the entry-count bound")
    if total_size > bounds.get("maximumExpandedBytes", 4_000_000_000):
        errors.append("payload manifest exceeds the expansion bound")
    if [row.get("path") for row in entries if isinstance(row, dict)] != sorted(
        row.get("path") for row in entries if isinstance(row, dict)
    ):
        errors.append("payload manifest entries are not sorted")
    if manifest.get("ignoredPaths") != []:
        errors.append("payload manifest contains prohibited ignored paths")
    if rule_id == "crypta-app-signature-envelope-v1" and any(
        row.get("path") in {"cryptad-app.digests", "cryptad-app.signature"}
        for row in entries
        if isinstance(row, dict)
    ):
        errors.append("app payload manifest includes the producer signing envelope")
    return errors


def exact_release_errors(value: dict[str, Any], release: dict[str, Any], label: str) -> list[str]:
    """Bind a phase artifact to the exact candidate release identity."""

    errors: list[str] = []
    for field in ("releaseId", "buildVersion", "sourceCommit", "policyDigest"):
        if value.get(field) != release.get(field):
            errors.append(f"{label} {field} differs")
    return errors


def digest_map(rows: Iterable[tuple[str, Path]]) -> list[dict[str, Any]]:
    """Return deterministic public artifact bindings."""

    return [
        {"name": name, "digest": file_digest(path), "size": path.stat().st_size}
        for name, path in sorted(rows, key=lambda row: row[0])
    ]


def component_reverse_index_errors(
    index: dict[str, Any],
    *,
    release_id: str | None = None,
    build_version: int | str | None = None,
    source_commit: str | None,
    source_ref: str | None,
    runtime_component_ids: Iterable[str] | None = None,
) -> list[str]:
    """Validate PR-288 runtime-component aliases against one authenticated reverse index.

    Each logical vulnerability scope identity must resolve to exactly one canonical component
    identity, exact version/digest, and a non-empty affected subject/build mapping. This helper is
    intentionally independent of the supply-chain engine so the vulnerability engine can use it
    without accepting an advisory feed or another inventory authority.
    """

    errors = validate_schema(index, REVERSE_INDEX_SCHEMA)
    errors.extend(self_digest_errors(index, "reverseIndexDigest", "component reverse index"))
    if release_id is not None and index.get("releaseId") != release_id:
        errors.append("component reverse index belongs to another release")
    valid_source_commit = (
        isinstance(source_commit, str) and COMMIT_RE.fullmatch(source_commit) is not None
    )
    if not valid_source_commit:
        errors.append("requested component reverse-index source commit is malformed")
    elif index.get("sourceCommit") != source_commit:
        errors.append("component reverse index belongs to another source commit")
    expected_source_ref = f"commit:{source_commit}" if valid_source_commit else None
    if source_ref != expected_source_ref:
        errors.append("requested component reverse-index source ref is not immutable")
    elif index.get("sourceRef") != source_ref:
        errors.append("component reverse index belongs to another source ref")
    expected_build: int | None = None
    if build_version is not None:
        try:
            expected_build = int(build_version)
        except (TypeError, ValueError):
            errors.append("requested component reverse-index build is malformed")
        else:
            if index.get("buildVersion") != expected_build:
                errors.append("component reverse index belongs to another build")
    aliases: dict[str, list[dict[str, Any]]] = {}
    for row in index.get("entries", []):
        if not isinstance(row, dict):
            continue
        if not row.get("version") or not row.get("digest"):
            errors.append("component reverse-index entry lacks exact version or digest")
        if not row.get("stableBuilds") or not row.get("subjectKeys"):
            errors.append("component reverse-index entry lacks build or subject coverage")
        for alias in row.get("runtimeComponentIds", []):
            aliases.setdefault(alias, []).append(row)
    for alias, rows in aliases.items():
        if len(rows) != 1:
            errors.append(f"runtime-component alias {alias} is ambiguous")
    for requested in sorted(set(runtime_component_ids or ())):
        rows = aliases.get(requested, [])
        if len(rows) != 1:
            errors.append(
                f"runtime-component identity {requested} does not resolve to exactly one "
                "authenticated component"
            )
        elif expected_build is not None and expected_build not in rows[0].get(
            "stableBuilds", []
        ):
            errors.append(
                f"runtime-component identity {requested} does not map to the requested "
                "Stable build"
            )
    return errors
