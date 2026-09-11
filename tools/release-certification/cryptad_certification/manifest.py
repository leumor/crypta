"""Strict parser for release-run manifest version 1."""

from __future__ import annotations

import datetime as dt
import re
from pathlib import Path
from typing import Any

from .io import read_json
from .models import MANIFEST_SCHEMA_VERSION, OutputSpec, ReleaseSpec, RunManifest
from .redaction import scan_manifest_scalar

PROFILES = {
    "pr",
    "nightly",
    "developer-dry-run",
    "release-candidate",
    "production-beta",
    "stable-review",
}
COMMAND_NAMES = {
    "app-platform",
    "app-platform-docs",
    "network-scale-soak",
    "live-network-beta",
    "release-certification",
    "production-beta",
    "go-no-go",
    "stable-readiness",
    "stable-rc",
    "stable-ga",
    "stable-backport",
    "stable-maintenance",
    "stable-lifecycle",
    "stable-supply-chain",
    "stable-dependency-vulnerability",
    "stable-vulnerability",
    "multi-node-beta",
    "security-response",
}
REQUIREMENT_FIELDS = {
    "history",
    "liveNetwork",
    "multiNodeSoak",
    "sandboxProviderTests",
    "stableReadiness",
    "stableVulnerability",
    "stableSupplyChain",
    "stableDependencyVulnerability",
    "thirdPartyIntake",
}
INPUT_FIELDS = {
    "appPlatform",
    "ecosystemMatrix",
    "goNoGo",
    "interopExtended",
    "interopSmoke",
    "liveNetwork",
    "multiNodeSoak",
    "multiNodeSoakConfig",
    "networkScaleSoak",
    "performanceSmoke",
    "previousCandidate",
    "previousStableRcFreeze",
    "productionBeta",
    "publicBetaKnownIssues",
    "releaseCertification",
    "releaseHistory",
    "selectedStableRcArchive",
    "selectedStableRcChecksums",
    "selectedStableRcFreeze",
    "selectedStableRcFreezeSidecar",
    "selectedStableRcLineage",
    "selectedStableRcProduct",
    "selectedStableRcProvenance",
    "selectedStableRcSummary",
    "securityDrills",
    "stableKnownLimitations",
    "stableGaAuthorization",
    "stableGaPolicy",
    "stableGaPublicationReceipt",
    "stableGaPromotionSummary",
    "stableGaValidation",
    "stableGaAuthorizationSummary",
    "stableGaPublicationPlan",
    "stableGaChecksums",
    "stableGaProvenance",
    "stableGaMaintenanceBaseline",
    "predecessorPublicationReceipt",
    "predecessorBaseline",
    "latestPublishedMaintenancePointer",
    "maintenanceCandidate",
    "maintenanceCandidateFreeze",
    "maintenanceCandidateAssets",
    "maintenanceRuntimeInputs",
    "maintenanceCandidateChecksums",
    "maintenanceCandidateProvenance",
    "maintenanceEvidence",
    "maintenancePolicy",
    "stableMaintenanceAuthorization",
    "stableMaintenancePublicationReceipt",
    "coreUpdatePublicationReceipt",
    "hotfixFollowUpObligation",
    "hotfixFollowUpEvidence",
    "hotfixFollowUpClosure",
    "stableMaintenanceHistory",
    "stableBackportPolicy",
    "stableFixIntake",
    "stableBackportReviewAuthorizations",
    "previousStableBackportQueue",
    "previousStableBackportValidation",
    "previousStableBackportCompletion",
    "previousStableBackportCompletionHandoff",
    "stableBackportAuthorization",
    "stableBackportFrozenValidation",
    "stableBackportCompletionEvidence",
    "stableBackportReleaseTrainAuthorization",
    "stableBackportReleaseTrainValidation",
    "completedStableLifecycleLedger",
    "completedStableLifecycleDescriptor",
    "stableLifecyclePolicy",
    "stableLifecycleGenesisProof",
    "previousStableLifecycleLedger",
    "previousStableLifecycleDescriptor",
    "previousStableLifecycleAuthorization",
    "previousStableLifecyclePublicationPlan",
    "previousStableLifecyclePublicationReceipt",
    "stableLifecycleTransitionRequest",
    "stableLifecycleAuthorization",
    "stableLifecyclePublicationPlan",
    "stableLifecyclePublicationReceipt",
    "stableLifecycleDescriptor",
    "stableLifecyclePublicObservationReceipt",
    "stableBackportValidation",
    "stableBackportCompletion",
    "stableVulnerabilityPolicy",
    "stableVulnerabilityReportEnvelope",
    "stableVulnerabilityPromotionEvaluation",
    "previousStableVulnerabilityLedger",
    "stableVulnerabilityAcknowledgement",
    "stableVulnerabilityTriage",
    "stableVulnerabilityTriageAuthorization",
    "stableVulnerabilityRemediationBinding",
    "stableVulnerabilityMitigationAuthorization",
    "stableVulnerabilityMitigationPublicationReceipt",
    "stableVulnerabilityAuthorityReceiptProvenance",
    "stableVulnerabilitySummary",
    "stableVulnerabilityAdvisory",
    "stableVulnerabilityReporterCoordination",
    "stableVulnerabilityDisclosureAuthorization",
    "stableVulnerabilityPublicationPlan",
    "stableVulnerabilityPublicationReceipt",
    "stableVulnerabilityPublicObservationReceipt",
    "stableVulnerabilityClosureEvidence",
    "supplyChainPolicy",
    "resolvedDependencySnapshot",
    "componentInventory",
    "releaseSubjectInventory",
    "licenseInventory",
    "stableSupplyChainSbom",
    "sbomBinding",
    "buildMaterials",
    "primaryBuilderReceipt",
    "verifierBuilderReceipt",
    "primarySubjectRoot",
    "verifierSubjectRoot",
    "primaryPayloadManifests",
    "verifierPayloadManifests",
    "rebuildComparisonPlan",
    "reproducibilityResult",
    "supplyChainPromotionSummary",
    "supplyChainPublicationPlan",
    "supplyChainPublicationReceipt",
    "supplyChainPublicObservation",
    "componentReverseIndex",
    "dependencyVulnerabilityPolicy",
    "dependencyIntelligenceProvenanceSet",
    "dependencyIntelligenceSnapshot",
    "previousDependencyIntelligenceSnapshot",
    "dependencyVulnerabilityFindingSet",
    "previousDependencyVulnerabilityFindingSet",
    "previousDependencyVulnerabilityLedger",
    "previousDependencyVulnerabilityDispositionSet",
    "dependencyVulnerabilityLedger",
    "dependencyVulnerabilityDispositionSet",
    "dependencyVulnerabilityDispositionAuthorizations",
    "dependencyVulnerabilityDispositionAuthorizationProvenance",
    "dependencyVulnerabilityRemediationSet",
    "dependencyVulnerabilityRemediationEvidenceProvenance",
    "stableBackportCompletionHandoff",
    "dependencyVulnerabilityPromotionSummary",
    "dependencyVulnerabilityPublicationPlan",
    "dependencyVulnerabilityPublicationReceipt",
    "dependencyVulnerabilityPublicObservation",
    "dependencyVulnerabilityPublicationProvenance",
    "stableAssuranceCloseout",
    "licenseOverrides",
    "licenseTextRoot",
    "catalogSecurityPublicationReceipt",
    "keyRevocationOrRotationReceipt",
    "stableCatalogOperations",
    "stableRcFreezeExceptions",
    "stableRcValidation",
    "stableReadiness",
    "stableReadinessPolicy",
    "stableReadinessWaivers",
    "thirdPartyIntake",
    "waiverFile",
}
POLICY_FIELDS = {
    "artifactBaseUri",
    "candidateSourceCommit",
    "candidateBaseCommit",
    "developmentLineageCommit",
    "mainLineageCommit",
    "candidateSourceRef",
    "candidateSourceBranch",
    "catalogChannel",
    "expectedPreviousReleaseId",
    "expectedPreviousProductDigest",
    "expectedPredecessorBuild",
    "expectedPredecessorReleaseId",
    "expectedPredecessorProductDigest",
    "releaseClass",
    "backportReleaseLane",
    "historyDir",
    "historyLabel",
    "metadata",
    "publicationIntent",
    "stableRcFreezeMode",
    "stableVulnerabilityGovernance",
    "stableSupplyChainGovernance",
    "stableDependencyVulnerabilityGovernance",
    "lifecycleDescriptorPublicUri",
    "latestMaintenancePointerPublicUri",
}
EXECUTION_BOOLEAN_FIELDS = {
    "allowDirtyWorkspace",
    "allowTestSigningInProduction",
    "collectEvidence",
    "collectLiveNetwork",
    "emergencySkipBuild",
    "emergencySkipLiveNetwork",
    "fixtureEvidence",
    "generateStableReadiness",
    "runMultiNodeSoak",
    "runThirdPartyIntakeSampleFlow",
    "skipFullBuild",
    "skipGitMetadata",
    "skipGradle",
    "writeHistory",
}
TOP_LEVEL_FIELDS = {
    "schemaVersion",
    "release",
    "output",
    "requirements",
    "inputs",
    "policies",
    "execution",
    "commands",
}
MAX_RELEASE_ID_LENGTH = 128
RELEASE_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
SECRET_KEY_FRAGMENTS = (
    "password",
    "privatekey",
    "private_key",
    "secret",
    "token",
    "authorization",
    "cookie",
    "inserturi",
    "insert_uri",
)
PUBLIC_AUTHORIZATION_INPUT_PATHS = {
    "manifest.inputs.previousStableLifecycleAuthorization",
    "manifest.inputs.stableBackportReleaseTrainAuthorization",
    "manifest.inputs.stableGaAuthorization",
    "manifest.inputs.stableGaAuthorizationSummary",
    "manifest.inputs.stableMaintenanceAuthorization",
    "manifest.inputs.stableBackportAuthorization",
    "manifest.inputs.stableBackportReviewAuthorizations",
    "manifest.inputs.stableLifecycleAuthorization",
    "manifest.inputs.stableVulnerabilityTriageAuthorization",
    "manifest.inputs.stableVulnerabilityMitigationAuthorization",
    "manifest.inputs.stableVulnerabilityDisclosureAuthorization",
    "manifest.inputs.dependencyVulnerabilityDispositionAuthorizations",
    "manifest.inputs.dependencyVulnerabilityDispositionAuthorizationProvenance",
}


class ManifestError(ValueError):
    """Raised when a release-run manifest is malformed or unsafe."""


def _mapping(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ManifestError(f"{field} must be an object")
    return value


def _reject_secret_fields(value: Any, path: str = "manifest") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = str(key).lower().replace("-", "_")
            child_path = f"{path}.{key}"
            if (
                child_path not in PUBLIC_AUTHORIZATION_INPUT_PATHS
                and any(fragment in normalized for fragment in SECRET_KEY_FRAGMENTS)
            ):
                raise ManifestError(
                    f"{path} contains a secret-like field name; "
                    "use a protected environment or file input"
                )
            _reject_secret_fields(child, child_path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_secret_fields(child, f"{path}[{index}]")
    elif isinstance(value, str):
        findings = scan_manifest_scalar(value)
        if findings:
            categories = ", ".join(finding["category"] for finding in findings)
            raise ManifestError(
                f"{path} contains forbidden {categories} material; "
                "use a protected environment or file input"
            )


def _validate_boolean_map(value: Any, field: str, allowed: set[str]) -> dict[str, Any]:
    mapping = _mapping(value, field)
    unknown = sorted(set(mapping) - allowed)
    if unknown:
        raise ManifestError(f"unknown {field} fields: {', '.join(unknown)}")
    invalid = sorted(key for key, item in mapping.items() if not isinstance(item, bool))
    if invalid:
        raise ManifestError(f"{field} fields must be booleans: {', '.join(invalid)}")
    return mapping


def _validate_inputs(value: Any) -> dict[str, Any]:
    inputs = _mapping(value, "inputs")
    unknown = sorted(set(inputs) - INPUT_FIELDS)
    if unknown:
        raise ManifestError(f"unknown inputs fields: {', '.join(unknown)}")
    invalid = sorted(
        key for key, item in inputs.items() if not isinstance(item, str) or not item.strip()
    )
    if invalid:
        raise ManifestError(f"inputs fields must be non-empty path strings: {', '.join(invalid)}")
    return inputs


def _validate_policies(value: Any) -> dict[str, Any]:
    policies = _mapping(value, "policies")
    unknown = sorted(set(policies) - POLICY_FIELDS)
    if unknown:
        raise ManifestError(f"unknown policies fields: {', '.join(unknown)}")
    for key in POLICY_FIELDS - {"metadata"}:
        if key in policies and (not isinstance(policies[key], str) or not policies[key].strip()):
            raise ManifestError(f"policies.{key} must be a non-empty string")
    if "catalogChannel" in policies and policies["catalogChannel"] not in {
        "stable",
        "beta",
        "nightly",
        "deprecated",
    }:
        raise ManifestError("policies.catalogChannel is invalid")
    if "stableRcFreezeMode" in policies and policies["stableRcFreezeMode"] not in {
        "first-freeze",
        "refreeze",
    }:
        raise ManifestError("policies.stableRcFreezeMode is invalid")
    if "stableSupplyChainGovernance" in policies and policies[
        "stableSupplyChainGovernance"
    ] != "required":
        raise ManifestError("policies.stableSupplyChainGovernance is invalid")
    if "releaseClass" in policies and policies["releaseClass"] not in {
        "maintenance",
        "security-hotfix",
    }:
        raise ManifestError("policies.releaseClass is invalid")
    if "backportReleaseLane" in policies and policies["backportReleaseLane"] not in {
        "routine-maintenance",
        "security-hotfix",
    }:
        raise ManifestError("policies.backportReleaseLane is invalid")
    if "candidateSourceCommit" in policies and re.fullmatch(
        r"[0-9a-f]{40,64}", policies["candidateSourceCommit"]
    ) is None:
        raise ManifestError("policies.candidateSourceCommit must be a lowercase Git commit id")
    if "candidateBaseCommit" in policies and re.fullmatch(
        r"[0-9a-f]{40,64}", policies["candidateBaseCommit"]
    ) is None:
        raise ManifestError("policies.candidateBaseCommit must be a lowercase Git commit id")
    if "developmentLineageCommit" in policies and re.fullmatch(
        r"[0-9a-f]{40,64}", policies["developmentLineageCommit"]
    ) is None:
        raise ManifestError(
            "policies.developmentLineageCommit must be a lowercase Git commit id"
        )
    if "mainLineageCommit" in policies and re.fullmatch(
        r"[0-9a-f]{40,64}", policies["mainLineageCommit"]
    ) is None:
        raise ManifestError(
            "policies.mainLineageCommit must be a lowercase Git commit id"
        )
    if "expectedPreviousProductDigest" in policies and re.fullmatch(
        r"sha256:[0-9a-f]{64}", policies["expectedPreviousProductDigest"]
    ) is None:
        raise ManifestError(
            "policies.expectedPreviousProductDigest must be a SHA-256 digest"
        )
    if "expectedPredecessorProductDigest" in policies and re.fullmatch(
        r"sha256:[0-9a-f]{64}", policies["expectedPredecessorProductDigest"]
    ) is None:
        raise ManifestError(
            "policies.expectedPredecessorProductDigest must be a SHA-256 digest"
        )
    if "publicationIntent" in policies and policies["publicationIntent"] != (
        "prepare-explicit-protected-publication"
    ):
        raise ManifestError("policies.publicationIntent is invalid")
    metadata = policies.get("metadata")
    if metadata is not None and (
        not isinstance(metadata, dict)
        or not all(
            isinstance(key, str)
            and key
            and isinstance(item, str)
            and item
            for key, item in metadata.items()
        )
    ):
        raise ManifestError("policies.metadata must map non-empty strings to non-empty strings")
    return policies


def _validate_execution(value: Any) -> dict[str, Any]:
    execution = _mapping(value, "execution")
    allowed = EXECUTION_BOOLEAN_FIELDS | {"evaluationClock", "timeoutSeconds"}
    unknown = sorted(set(execution) - allowed)
    if unknown:
        raise ManifestError(f"unknown execution fields: {', '.join(unknown)}")
    invalid = sorted(
        key
        for key in EXECUTION_BOOLEAN_FIELDS
        if key in execution and not isinstance(execution[key], bool)
    )
    if invalid:
        raise ManifestError(f"execution fields must be booleans: {', '.join(invalid)}")
    timeout = execution.get("timeoutSeconds")
    if timeout is not None and (not isinstance(timeout, int) or isinstance(timeout, bool) or timeout < 1):
        raise ManifestError("execution.timeoutSeconds must be a positive integer")
    evaluation_clock = execution.get("evaluationClock")
    if evaluation_clock is not None:
        if (
            not isinstance(evaluation_clock, str)
            or len(evaluation_clock) > 32
            or not evaluation_clock.endswith("Z")
        ):
            raise ManifestError(
                "execution.evaluationClock must be a bounded second-precision UTC timestamp"
            )
        try:
            parsed_clock = dt.datetime.fromisoformat(evaluation_clock[:-1] + "+00:00")
        except ValueError as exc:
            raise ManifestError("execution.evaluationClock is malformed") from exc
        if parsed_clock.tzinfo is None or parsed_clock.microsecond:
            raise ManifestError(
                "execution.evaluationClock must be a bounded second-precision UTC timestamp"
            )
    return execution


def load_manifest(path: Path, workspace_root: Path, out_root: Path | None = None) -> RunManifest:
    """Load and validate one non-secret release-run manifest."""

    value = read_json(path)
    if not isinstance(value, dict):
        raise ManifestError("manifest must be a JSON object")
    unknown = sorted(set(value) - TOP_LEVEL_FIELDS)
    if unknown:
        raise ManifestError(f"unknown manifest fields: {', '.join(unknown)}")
    missing = sorted(TOP_LEVEL_FIELDS - set(value))
    if missing:
        raise ManifestError(f"missing manifest fields: {', '.join(missing)}")
    schema_version = value.get("schemaVersion")
    if type(schema_version) is not int or schema_version != MANIFEST_SCHEMA_VERSION:
        raise ManifestError(f"schemaVersion must be {MANIFEST_SCHEMA_VERSION}")
    _reject_secret_fields(value)

    release = _mapping(value["release"], "release")
    allowed_release = {"id", "version", "profile"}
    unknown_release = sorted(set(release) - allowed_release)
    if unknown_release:
        raise ManifestError(f"unknown release fields: {', '.join(unknown_release)}")
    missing_release = sorted(allowed_release - set(release))
    if missing_release:
        raise ManifestError(f"missing release fields: {', '.join(missing_release)}")
    release_id = release.get("id")
    if not isinstance(release_id, str) or not RELEASE_ID_RE.fullmatch(release_id):
        raise ManifestError(
            f"release.id must be a path-safe slug of at most {MAX_RELEASE_ID_LENGTH} characters"
        )
    profile = release.get("profile")
    if profile not in PROFILES:
        raise ManifestError(f"release.profile must be one of {', '.join(sorted(PROFILES))}")
    version = release.get("version")
    if version is not None and (not isinstance(version, str) or not version.strip()):
        raise ManifestError("release.version must be a non-empty string or null")

    output = _mapping(value["output"], "output")
    if set(output) - {"root", "reset"}:
        raise ManifestError("output supports only root and reset")
    configured_root = output.get("root", "build/release-certification")
    if not isinstance(configured_root, str) or not configured_root:
        raise ManifestError("output.root must be a non-empty path string")
    reset = output.get("reset", False)
    if not isinstance(reset, bool):
        raise ManifestError("output.reset must be a boolean")
    output_path = out_root or Path(configured_root)
    if not output_path.is_absolute():
        output_path = workspace_root / output_path
    output_path = output_path.resolve()

    requirements = _validate_boolean_map(value["requirements"], "requirements", REQUIREMENT_FIELDS)
    inputs = _validate_inputs(value["inputs"])
    policies = _validate_policies(value["policies"])
    execution = _validate_execution(value["execution"])
    if execution.get("runMultiNodeSoak") is True and "multiNodeSoak" in inputs:
        raise ManifestError(
            "execution.runMultiNodeSoak cannot be combined with inputs.multiNodeSoak"
        )
    commands = _mapping(value["commands"], "commands")
    for command, config in commands.items():
        if not isinstance(command, str) or not isinstance(config, dict):
            raise ManifestError("commands must map command names to objects")
        if command not in COMMAND_NAMES:
            raise ManifestError(f"unknown command configuration: {command}")
        unknown_config = sorted(set(config) - {"args", "mode"})
        if unknown_config:
            raise ManifestError(
                f"unknown commands.{command} fields: {', '.join(unknown_config)}"
            )
        args = config.get("args", [])
        if not isinstance(args, list) or not all(isinstance(arg, str) for arg in args):
            raise ManifestError(f"commands.{command}.args must be an array of strings")
        mode = config.get("mode")
        if mode is not None and (not isinstance(mode, str) or not mode.strip()):
            raise ManifestError(f"commands.{command}.mode must be a non-empty string")
        for argument in args:
            normalized = argument.lower().replace("-", "_")
            if argument.startswith("--") and any(fragment in normalized for fragment in SECRET_KEY_FRAGMENTS):
                raise ManifestError(
                    f"commands.{command}.args contains a secret-bearing option; use a protected environment or file input"
                )
            if any(marker in argument for marker in ("SSK@", "USK@", "-----BEGIN PRIVATE KEY-----")):
                raise ManifestError(
                    f"commands.{command}.args contains private material; use a protected environment or file input"
                )

    return RunManifest(
        path=path.resolve(),
        release=ReleaseSpec(release_id, version, profile),
        output=OutputSpec(output_path, reset),
        requirements=requirements,
        inputs=inputs,
        policies=policies,
        execution=execution,
        commands=commands,
    )
