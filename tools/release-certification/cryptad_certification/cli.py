"""Unified command-line interface for Cryptad release certification."""

from __future__ import annotations

import argparse
import os
import re
import shutil
import sys
from pathlib import Path

from . import selftest
from .engines.stable_1_0_rc_core import SAME_RUN_INPUT_KEYS
from .legacy import execute as execute_engine
from .manifest import load_manifest
from .migration import execute as execute_migration
from .models import RunManifest
from .workspace import _require_confined_directory, prepare_context, prepare_run_root

COMMANDS = (
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
)
MULTI_NODE_ACTIONS = (
    "plan",
    "run",
    "verify",
    "previous-summary",
    "verify-previous-summary",
    "schema",
)
SECURITY_ACTIONS = (
    "verify",
    "drill-create",
    "drill-verify",
    "drill-run-all",
    "drill-verify-all",
    "advisory-template",
)
SELF_TEST_SUITES = ("all", *selftest.SUITE_MODULES)


def _add_run_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--manifest", type=Path, help="Versioned, non-secret release-run manifest.")
    parser.add_argument("--workspace-root", type=Path, default=Path.cwd())
    parser.add_argument("--out-root", type=Path)
    parser.add_argument("--self-test", action="store_true", help="Run this command's focused unittest suite.")


def build_parser() -> argparse.ArgumentParser:
    """Build the unified command tree."""

    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in COMMANDS:
        child = subparsers.add_parser(command)
        _add_run_arguments(child)

    multi = subparsers.add_parser("multi-node-beta")
    _add_run_arguments(multi)
    multi.add_argument("action", nargs="?", choices=MULTI_NODE_ACTIONS)

    cross_version = subparsers.add_parser("cross-version-soak")
    cross_version.add_argument("action", nargs="?", choices=("plan", "run", "verify", "closeout", "profile-compare"))
    cross_version.add_argument("--plan", type=Path)
    cross_version.add_argument("--private-config", type=Path)
    cross_version.add_argument("--authorization", type=Path)
    cross_version.add_argument("--journal-root", type=Path)
    cross_version.add_argument("--continuation", type=Path)
    cross_version.add_argument("--out-dir", type=Path)
    cross_version.add_argument("--previous-source")
    cross_version.add_argument("--current-source")
    cross_version.add_argument("--workspace-root", type=Path, default=Path.cwd())
    cross_version.add_argument("--execute", action="store_true")
    cross_version.add_argument("--self-test", action="store_true")

    security = subparsers.add_parser("security-response")
    _add_run_arguments(security)
    security.add_argument("action", nargs="?", choices=SECURITY_ACTIONS)

    protected = subparsers.add_parser("stable-protected-release")
    protected.add_argument("--mode", choices=("preflight", "rc-dispatch", "closeout"))
    protected.add_argument(
        "--execution-contract",
        "--contract",
        dest="execution_contract",
        type=Path,
        help="Versioned, non-secret Stable protected execution contract.",
    )
    protected.add_argument(
        "--rc-input-map",
        type=Path,
        help="Closed materialized-input map used only by protected RC dispatch verification.",
    )
    protected.add_argument("--workspace-root", type=Path, default=Path.cwd())
    protected.add_argument("--out-dir", type=Path)
    protected.add_argument("--self-test", action="store_true")

    catalog_authority = subparsers.add_parser("stable-catalog-authority")
    catalog_authority.add_argument(
        "--mode",
        choices=(
            "prepare-ceremony",
            "verify-ceremony",
            "prepare-publication",
            "verify-publication",
            "verify-rotation-drill",
            "closeout",
        ),
    )
    catalog_authority.add_argument(
        "--authority-manifest",
        "--manifest",
        dest="authority_manifest",
        type=Path,
        help="Closed, non-secret Stable catalog authority manifest.",
    )
    catalog_authority.add_argument("--workspace-root", type=Path, default=Path.cwd())
    catalog_authority.add_argument("--out-dir", type=Path)
    catalog_authority.add_argument(
        "--evidence-dir",
        type=Path,
        help="Confined exact PR-291, PR-292, GA, catalog, and observation evidence directory.",
    )
    catalog_authority.add_argument(
        "--live-publication-result",
        type=Path,
        help="Sanitized result emitted by the protected live USK publication boundary.",
    )
    catalog_authority.add_argument("--self-test", action="store_true")

    independent = subparsers.add_parser("stable-independent-reproducibility")
    independent.add_argument(
        "--mode",
        choices=(
            "prepare-verifier-kit",
            "verify-external-receipt",
            "compare",
            "closeout",
        ),
    )
    independent.add_argument(
        "--execution-contract",
        "--contract",
        dest="execution_contract",
        type=Path,
        help="Versioned, non-secret independent reproducibility execution contract.",
    )
    independent.add_argument("--workspace-root", type=Path, default=Path.cwd())
    independent.add_argument("--out-dir", type=Path)
    independent.add_argument("--self-test", action="store_true")

    third_party_pilot = subparsers.add_parser("stable-third-party-pilot")
    third_party_pilot.add_argument(
        "--mode",
        choices=(
            "preflight",
            "verify-external-handoff",
            "verify-review-cohort",
            "verify-catalog-publication",
            "verify-runtime-drill",
            "closeout",
        ),
    )
    third_party_pilot.add_argument(
        "--execution-contract",
        "--contract",
        dest="execution_contract",
        type=Path,
        help="Closed, non-secret external third-party app pilot contract.",
    )
    third_party_pilot.add_argument("--workspace-root", type=Path, default=Path.cwd())
    third_party_pilot.add_argument("--out-dir", type=Path)
    third_party_pilot.add_argument(
        "--evidence-dir",
        type=Path,
        help="Confined authenticated handoff and protected receipt directory.",
    )
    third_party_pilot.add_argument("--self-test", action="store_true")

    federated_catalog = subparsers.add_parser("stable-federated-catalog")
    federated_catalog.add_argument(
        "--mode",
        choices=(
            "preflight",
            "verify-discovery",
            "verify-local-trust",
            "verify-conflicts",
            "verify-runtime",
            "closeout",
        ),
    )
    federated_catalog.add_argument(
        "--execution-contract",
        "--contract",
        dest="execution_contract",
        type=Path,
        help="Closed, non-secret federated catalog execution contract.",
    )
    federated_catalog.add_argument("--workspace-root", type=Path, default=Path.cwd())
    federated_catalog.add_argument("--out-dir", type=Path)
    federated_catalog.add_argument(
        "--evidence-dir",
        type=Path,
        help="Confined discovery, runtime, and protected authority evidence directory.",
    )
    federated_catalog.add_argument("--self-test", action="store_true")

    platform_api_1x = subparsers.add_parser("stable-platform-api-1x")
    platform_api_1x.add_argument(
        "--mode",
        choices=(
            "preflight",
            "verify-history",
            "verify-baseline-proposal",
            "verify-graduation",
            "verify-app-matrix",
            "verify-runtime",
            "closeout",
        ),
    )
    platform_api_1x.add_argument(
        "--execution-contract",
        "--contract",
        dest="execution_contract",
        type=Path,
        help="Closed, non-secret Platform API 1.x compatibility execution contract.",
    )
    platform_api_1x.add_argument("--workspace-root", type=Path, default=Path.cwd())
    platform_api_1x.add_argument("--out-dir", type=Path)
    platform_api_1x.add_argument(
        "--evidence-dir",
        type=Path,
        help="Confined exact contract history, proposal, matrix, runtime, and authority evidence.",
    )
    platform_api_1x.add_argument("--self-test", action="store_true")

    profile_review = subparsers.add_parser("stable-content-profile-review")
    profile_review.add_argument("--mode", choices=("inspect", "review"), default="inspect")
    profile_review.add_argument("--workspace-root", type=Path, default=Path.cwd())
    profile_review.add_argument("--self-test", action="store_true")

    legacy_pilot = subparsers.add_parser("stable-legacy-plugin-migration")
    legacy_pilot.add_argument(
        "--mode", choices=("preflight", "verify-migration", "verify-runtime", "closeout")
    )
    legacy_pilot.add_argument("--observation", type=Path)
    legacy_pilot.add_argument("--workspace-root", type=Path, default=Path.cwd())
    legacy_pilot.add_argument("--out-dir", type=Path)
    legacy_pilot.add_argument("--self-test", action="store_true")

    migration = subparsers.add_parser("migrate-v1")
    migration.add_argument("migration_kind", choices=("previous-candidate", "release-history"))
    migration.add_argument("--manifest", type=Path, required=True)
    migration.add_argument("--workspace-root", type=Path, default=Path.cwd())
    migration.add_argument("--out-root", type=Path)

    tests = subparsers.add_parser("self-test")
    tests.add_argument("suite", nargs="?", choices=SELF_TEST_SUITES, default="all")
    return parser


def _execute_component(
    workspace_root: Path,
    manifest: RunManifest,
    command: str,
    action: str | None = None,
) -> int:
    component = command if action is None else f"{command}/{action}"
    run_root = (manifest.output.root / manifest.release.release_id).resolve()
    component_dir = run_root / Path(component)
    _require_confined_directory(component_dir, run_root, "component")
    resolved_component = component_dir.resolve()
    try:
        resolved_component.relative_to(run_root)
    except ValueError as exc:
        raise ValueError(f"component path escapes the release workspace: {component}") from exc
    if component_dir.is_symlink():
        raise ValueError(f"refusing to replace a symlinked component directory: {component}")
    if component_dir.exists():
        if not component_dir.is_dir():
            raise ValueError(f"component output is not a directory: {component}")
        shutil.rmtree(component_dir)
    context = prepare_context(workspace_root, manifest, component)
    return execute_engine(context, command, action)


def _collect_release_evidence(workspace_root: Path, manifest: RunManifest) -> None:
    """Collect every candidate-scoped input formerly generated by the shell wrapper."""

    inputs = manifest.inputs
    if "appPlatform" not in inputs:
        _execute_component(workspace_root, manifest, "app-platform")
    if "networkScaleSoak" not in inputs:
        _execute_component(workspace_root, manifest, "network-scale-soak")
    if "multiNodeSoak" not in inputs:
        _execute_component(workspace_root, manifest, "multi-node-beta", "run")
    if "securityDrills" not in inputs:
        _execute_component(workspace_root, manifest, "security-response", "verify")
        _execute_component(workspace_root, manifest, "security-response", "drill-run-all")
        _execute_component(workspace_root, manifest, "security-response", "drill-verify-all")
    collect_live = (
        manifest.requirements.get("liveNetwork") is True
        or manifest.execution.get("collectLiveNetwork") is True
    )
    if collect_live and "liveNetwork" not in inputs:
        _execute_component(workspace_root, manifest, "live-network-beta")


def _require_pending_component(manifest: RunManifest, component: str) -> None:
    """Reject a completed component without creating or changing its directory."""

    run_root = (manifest.output.root / manifest.release.release_id).resolve()
    component_dir = run_root / Path(component)
    _require_confined_directory(component_dir, run_root, "component")
    summary = component_dir / "summary.json"
    if summary.is_symlink() or summary.exists():
        raise ValueError(
            f"component already has a summary; reset the run before rerunning: {component}"
        )


def _validate_stable_rc_manifest(manifest: RunManifest) -> None:
    """Reject Stable RC orchestration outside the protected Stable review profile."""

    if manifest.release.profile != "stable-review":
        raise ValueError("stable-rc requires release.profile stable-review")
    version = manifest.release.version
    if version is None or re.fullmatch(r"[1-9][0-9]*", version) is None:
        raise ValueError("stable-rc requires a canonical positive integer release.version")
    freeze_mode = manifest.policies.get("stableRcFreezeMode")
    has_previous_freeze = "previousStableRcFreeze" in manifest.inputs
    if freeze_mode not in {"first-freeze", "refreeze"}:
        raise ValueError(
            "stable-rc requires policies.stableRcFreezeMode first-freeze or refreeze"
        )
    if freeze_mode == "first-freeze" and has_previous_freeze:
        raise ValueError(
            "stable-rc first-freeze mode cannot include inputs.previousStableRcFreeze"
        )
    if freeze_mode == "refreeze" and not has_previous_freeze:
        raise ValueError(
            "stable-rc refreeze mode requires inputs.previousStableRcFreeze"
        )
    if (
        manifest.requirements.get("stableVulnerability") is not True
        or manifest.policies.get("stableVulnerabilityGovernance") != "required"
        or "stableVulnerabilitySummary" not in manifest.inputs
    ):
        raise ValueError(
            "stable-rc requires the current authenticated Stable vulnerability "
            "promotion handoff, requirements.stableVulnerability=true, and "
            "policies.stableVulnerabilityGovernance=required"
        )
    configured_same_run = [key for key in SAME_RUN_INPUT_KEYS if key in manifest.inputs]
    if configured_same_run:
        names = ", ".join(f"inputs.{key}" for key in configured_same_run)
        raise ValueError(
            "stable-rc generates production-beta and its promotion inputs in the same "
            f"protected run; externally supplied same-run inputs are not accepted: {names}"
        )
    stable_authorities = (
        (
            "stableSupplyChain",
            "stableSupplyChainGovernance",
            "supplyChainPromotionSummary",
            "Stable supply-chain",
        ),
        (
            "stableDependencyVulnerability",
            "stableDependencyVulnerabilityGovernance",
            "dependencyVulnerabilityPromotionSummary",
            "Stable dependency-vulnerability",
        ),
    )
    for requirement, policy, input_name, label in stable_authorities:
        if (
            manifest.requirements.get(requirement) is not True
            or manifest.policies.get(policy) != "required"
            or input_name not in manifest.inputs
        ):
            raise ValueError(
                f"stable-rc requires the authenticated {label} promotion handoff, "
                f"requirements.{requirement}=true, policies.{policy}=required, "
                f"and inputs.{input_name}"
            )
    source_commit = manifest.policies.get("candidateSourceCommit")
    source_ref = manifest.policies.get("candidateSourceRef")
    if (
        not isinstance(source_commit, str)
        or re.fullmatch(r"[0-9a-f]{40}", source_commit) is None
        or source_ref != f"commit:{source_commit}"
    ):
        raise ValueError(
            "stable-rc requires policies.candidateSourceCommit as the exact lowercase "
            "40-character commit and policies.candidateSourceRef=commit:<commit>"
        )


def _validate_stable_ga_manifest(manifest: RunManifest) -> None:
    """Reject Stable GA validation unless every immutable input is explicit."""

    if manifest.release.profile != "stable-review":
        raise ValueError("stable-ga requires release.profile stable-review")
    version = manifest.release.version
    if version is None or re.fullmatch(r"[1-9][0-9]*", version) is None:
        raise ValueError("stable-ga requires a canonical positive integer release.version")
    required_inputs = {
        "selectedStableRcSummary",
        "selectedStableRcFreeze",
        "selectedStableRcFreezeSidecar",
        "selectedStableRcArchive",
        "selectedStableRcProduct",
        "selectedStableRcChecksums",
        "selectedStableRcProvenance",
        "selectedStableRcLineage",
        "previousCandidate",
        "stableRcValidation",
        "stableGaPolicy",
    }
    missing = sorted(required_inputs.difference(manifest.inputs))
    if missing:
        raise ValueError(
            "stable-ga requires explicit immutable inputs: " + ", ".join(missing)
        )
    mode = manifest.commands.get("stable-ga", {}).get("mode", "validate-only")
    if mode not in {"validate-only", "prepare-authorization"}:
        raise ValueError(
            "stable-ga command mode must be validate-only or prepare-authorization"
        )
    if mode == "validate-only" and "stableGaAuthorization" not in manifest.inputs:
        raise ValueError("stable-ga validate-only requires inputs.stableGaAuthorization")
    if mode == "prepare-authorization" and "stableGaAuthorization" in manifest.inputs:
        raise ValueError(
            "stable-ga prepare-authorization must not include inputs.stableGaAuthorization"
        )
    if mode == "prepare-authorization" and "stableGaPublicationReceipt" in manifest.inputs:
        raise ValueError(
            "stable-ga prepare-authorization cannot verify a publication receipt"
        )
    expected_policies = {
        "catalogChannel": "stable",
        "publicationIntent": "prepare-explicit-protected-publication",
    }
    for field, expected in expected_policies.items():
        if manifest.policies.get(field) != expected:
            raise ValueError(f"stable-ga requires policies.{field} {expected}")
    commit = manifest.policies.get("candidateSourceCommit")
    if not isinstance(commit, str) or re.fullmatch(r"[0-9a-f]{40,64}", commit) is None:
        raise ValueError("stable-ga requires a canonical policies.candidateSourceCommit")
    source_ref = manifest.policies.get("candidateSourceRef")
    if source_ref != f"commit:{commit}":
        raise ValueError(
            "stable-ga requires policies.candidateSourceRef to be the selected immutable "
            "commit:<sha> identity"
        )
    previous_release = manifest.policies.get("expectedPreviousReleaseId")
    if not isinstance(previous_release, str) or not previous_release:
        raise ValueError("stable-ga requires policies.expectedPreviousReleaseId")
    previous_product = manifest.policies.get("expectedPreviousProductDigest")
    if not isinstance(previous_product, str) or re.fullmatch(
        r"sha256:[0-9a-f]{64}", previous_product
    ) is None:
        raise ValueError("stable-ga requires policies.expectedPreviousProductDigest")
    metadata = manifest.policies.get("metadata")
    required_metadata = {
        "catalogPrimaryUri",
        "catalogMirrorUris",
        "catalogRollbackUri",
    }
    if not isinstance(metadata, dict) or not required_metadata.issubset(metadata):
        raise ValueError(
            "stable-ga requires public catalog primary, mirror, and rollback URIs in policies.metadata"
        )


def _validate_stable_maintenance_manifest(manifest: RunManifest) -> None:
    """Reject Stable maintenance runs whose class, mode, or immutable inputs are ambiguous."""

    if manifest.release.profile != "stable-review":
        raise ValueError("stable-maintenance requires release.profile stable-review")
    version = manifest.release.version
    if version is None or re.fullmatch(r"[1-9][0-9]*", version) is None:
        raise ValueError(
            "stable-maintenance requires a canonical positive integer release.version"
        )
    mode = manifest.commands.get("stable-maintenance", {}).get(
        "mode", "validate-only"
    )
    release_class = manifest.policies.get("releaseClass")
    if release_class not in {"maintenance", "security-hotfix"}:
        raise ValueError(
            "stable-maintenance requires policies.releaseClass maintenance or security-hotfix"
        )
    expected_branch = f"{'release' if release_class == 'maintenance' else 'hotfix'}/{version}"
    if manifest.policies.get("candidateSourceBranch") != expected_branch:
        raise ValueError(
            f"stable-maintenance {release_class} requires policies.candidateSourceBranch "
            f"{expected_branch}"
        )
    commit = manifest.policies.get("candidateSourceCommit")
    if not isinstance(commit, str) or re.fullmatch(r"[0-9a-f]{40,64}", commit) is None:
        raise ValueError(
            "stable-maintenance requires a canonical policies.candidateSourceCommit"
        )
    if manifest.policies.get("candidateSourceRef") != f"commit:{commit}":
        raise ValueError(
            "stable-maintenance requires policies.candidateSourceRef to be commit:<sha>"
        )
    base_commit = manifest.policies.get("candidateBaseCommit")
    if (
        not isinstance(base_commit, str)
        or re.fullmatch(r"[0-9a-f]{40,64}", base_commit) is None
        or base_commit == commit
    ):
        raise ValueError(
            "stable-maintenance requires a distinct canonical policies.candidateBaseCommit"
        )
    if manifest.policies.get("catalogChannel") != "stable":
        raise ValueError("stable-maintenance requires policies.catalogChannel stable")
    if manifest.policies.get("publicationIntent") != (
        "prepare-explicit-protected-publication"
    ):
        raise ValueError(
            "stable-maintenance requires explicit protected publication intent"
        )
    required_inputs = {
        "stableGaPromotionSummary",
        "stableGaValidation",
        "stableGaAuthorizationSummary",
        "stableGaPublicationPlan",
        "stableGaPublicationReceipt",
        "stableGaChecksums",
        "stableGaProvenance",
        "stableGaMaintenanceBaseline",
        "predecessorPublicationReceipt",
        "predecessorBaseline",
        "maintenanceCandidate",
        "maintenanceCandidateFreeze",
        "maintenanceCandidateAssets",
        "maintenanceCandidateChecksums",
        "maintenanceCandidateProvenance",
        "maintenanceEvidence",
        "maintenancePolicy",
    }
    if mode != "close-hotfix-follow-up":
        required_inputs.add("stableBackportReleaseTrainAuthorization")
        required_inputs.add("stableBackportReleaseTrainValidation")
        required_inputs.add("supplyChainPromotionSummary")
        if (
            manifest.requirements.get("stableSupplyChain") is not True
            or manifest.policies.get("stableSupplyChainGovernance") != "required"
        ):
            raise ValueError(
                "stable-maintenance requires non-waivable Stable supply-chain governance"
            )
    missing = sorted(required_inputs.difference(manifest.inputs))
    if missing:
        raise ValueError(
            "stable-maintenance requires explicit immutable inputs: "
            + ", ".join(missing)
        )
    lifecycle_inputs = {
        "previousStableLifecycleLedger",
        "previousStableLifecycleDescriptor",
        "stableLifecycleAuthorization",
        "stableLifecyclePublicationPlan",
        "stableLifecyclePublicationReceipt",
    }
    present_lifecycle_inputs = lifecycle_inputs.intersection(manifest.inputs)
    if present_lifecycle_inputs and present_lifecycle_inputs != lifecycle_inputs:
        raise ValueError(
            "stable-maintenance lifecycle state requires the exact ledger, descriptor, "
            "approved authorization, authorized publication plan, and verified publication "
            "receipt together"
        )
    allowed_modes = {
        "validate-only",
        "prepare-authorization",
        "close-hotfix-follow-up",
    }
    if mode not in allowed_modes:
        raise ValueError(
            "stable-maintenance command mode must be validate-only, "
            "prepare-authorization, or close-hotfix-follow-up"
        )
    has_authorization = "stableMaintenanceAuthorization" in manifest.inputs
    if mode == "prepare-authorization" and has_authorization:
        raise ValueError(
            "stable-maintenance prepare-authorization must not include authorization"
        )
    if mode == "prepare-authorization" and (
        "stableMaintenancePublicationReceipt" in manifest.inputs
        or "coreUpdatePublicationReceipt" in manifest.inputs
    ):
        raise ValueError(
            "stable-maintenance prepare-authorization cannot verify publication receipts"
        )
    if mode == "validate-only" and not has_authorization:
        raise ValueError(
            "stable-maintenance validate-only requires inputs.stableMaintenanceAuthorization"
        )
    if mode == "close-hotfix-follow-up":
        required_closure = {
            "stableMaintenanceAuthorization",
            "hotfixFollowUpObligation",
            "hotfixFollowUpEvidence",
        }
        missing_closure = sorted(required_closure.difference(manifest.inputs))
        if release_class != "security-hotfix" or missing_closure:
            raise ValueError(
                "stable-maintenance close-hotfix-follow-up requires security-hotfix and inputs: "
                + ", ".join(missing_closure)
            )
    receipt_inputs = {
        "stableMaintenancePublicationReceipt",
        "coreUpdatePublicationReceipt",
    }
    present_receipts = receipt_inputs.intersection(manifest.inputs)
    if present_receipts and present_receipts != receipt_inputs:
        raise ValueError(
            "stable-maintenance publication verification requires both maintenance and "
            "CoreUpdater receipts"
        )
    predecessor_build = manifest.policies.get("expectedPredecessorBuild")
    if (
        not isinstance(predecessor_build, str)
        or re.fullmatch(r"[1-9][0-9]*", predecessor_build) is None
        or (
            mode != "close-hotfix-follow-up"
            and int(version) <= int(predecessor_build)
        )
    ):
        raise ValueError(
            "stable-maintenance requires a canonical latest predecessor and a strictly "
            "higher release build outside follow-up closure"
        )


def _validate_stable_backport_manifest(manifest: RunManifest) -> None:
    """Reject a Stable release-train run with an ambiguous lane, mode, or protected input."""

    if manifest.release.profile != "stable-review":
        raise ValueError("stable-backport requires release.profile stable-review")
    version = manifest.release.version
    if version is None or re.fullmatch(r"[1-9][0-9]*", version) is None:
        raise ValueError(
            "stable-backport requires a canonical positive integer release.version"
        )
    release_class = manifest.policies.get("releaseClass")
    if release_class not in {"maintenance", "security-hotfix"}:
        raise ValueError(
            "stable-backport requires policies.releaseClass maintenance or security-hotfix"
        )
    lane = manifest.policies.get("backportReleaseLane")
    expected_lane = (
        "routine-maintenance"
        if release_class == "maintenance"
        else "security-hotfix"
    )
    if lane != expected_lane:
        raise ValueError(
            "stable-backport release lane does not match policies.releaseClass"
        )
    expected_branch = f"{'release' if release_class == 'maintenance' else 'hotfix'}/{version}"
    if manifest.policies.get("candidateSourceBranch") != expected_branch:
        raise ValueError(
            f"stable-backport {expected_lane} requires policies.candidateSourceBranch "
            f"{expected_branch}"
        )
    commit = manifest.policies.get("candidateSourceCommit")
    if not isinstance(commit, str) or re.fullmatch(r"[0-9a-f]{40,64}", commit) is None:
        raise ValueError(
            "stable-backport requires a canonical policies.candidateSourceCommit"
        )
    if manifest.policies.get("candidateSourceRef") != f"commit:{commit}":
        raise ValueError(
            "stable-backport requires policies.candidateSourceRef to be commit:<sha>"
        )
    base_commit = manifest.policies.get("candidateBaseCommit")
    if (
        not isinstance(base_commit, str)
        or re.fullmatch(r"[0-9a-f]{40,64}", base_commit) is None
        or base_commit == commit
    ):
        raise ValueError(
            "stable-backport requires a distinct canonical policies.candidateBaseCommit"
        )
    development_lineage = manifest.policies.get("developmentLineageCommit")
    main_lineage = manifest.policies.get("mainLineageCommit")
    if lane == "routine-maintenance":
        if (
            not isinstance(development_lineage, str)
            or re.fullmatch(r"[0-9a-f]{40,64}", development_lineage) is None
            or main_lineage is not None
        ):
            raise ValueError(
                "routine stable-backport requires only the exact protected "
                "developmentLineageCommit"
            )
    elif (
        not isinstance(main_lineage, str)
        or re.fullmatch(r"[0-9a-f]{40,64}", main_lineage) is None
        or development_lineage is not None
    ):
        raise ValueError(
            "security-hotfix stable-backport requires only the exact protected "
            "mainLineageCommit"
        )
    required_inputs = {
        "stableBackportPolicy",
        "stableFixIntake",
        "stableGaPromotionSummary",
        "stableGaValidation",
        "stableGaAuthorizationSummary",
        "stableGaPublicationPlan",
        "stableGaPublicationReceipt",
        "stableGaChecksums",
        "stableGaProvenance",
        "stableGaMaintenanceBaseline",
        "stableLifecyclePolicy",
        "predecessorPublicationReceipt",
        "predecessorBaseline",
        "previousStableLifecycleLedger",
        "previousStableLifecycleDescriptor",
        "previousStableLifecycleAuthorization",
        "previousStableLifecyclePublicationPlan",
        "previousStableLifecyclePublicationReceipt",
        "stableLifecyclePublicObservationReceipt",
    }
    missing = sorted(required_inputs.difference(manifest.inputs))
    if missing:
        raise ValueError(
            "stable-backport requires exact intake, policy, predecessor, and lifecycle inputs: "
            + ", ".join(missing)
        )
    mode = manifest.commands.get("stable-backport", {}).get("mode", "evaluate")
    allowed_modes = {
        "evaluate",
        "prepare-candidate",
        "validate-authorization",
        "verify-release-completion",
    }
    if mode not in allowed_modes:
        raise ValueError(
            "stable-backport mode must be evaluate, prepare-candidate, "
            "validate-authorization, or verify-release-completion"
        )
    protected = {
        "stableBackportAuthorization",
        "stableBackportFrozenValidation",
        "stableBackportCompletionEvidence",
        "stableMaintenancePublicationReceipt",
        "stableLifecyclePublicationReceipt",
        "completedStableLifecycleLedger",
        "completedStableLifecycleDescriptor",
    }
    present_protected = protected.intersection(manifest.inputs)
    if mode in {"evaluate", "prepare-candidate"} and present_protected:
        raise ValueError(
            f"stable-backport {mode} cannot consume protected authorization or completion inputs"
        )
    if mode == "validate-authorization":
        if "stableBackportAuthorization" not in manifest.inputs:
            raise ValueError(
                "stable-backport validate-authorization requires "
                "inputs.stableBackportAuthorization"
            )
        unexpected = present_protected - {"stableBackportAuthorization"}
        if unexpected:
            raise ValueError(
                "stable-backport validate-authorization cannot consume completion inputs"
            )
    if mode == "verify-release-completion":
        completion_required = protected - {
            "stableLifecyclePublicationReceipt",
            "completedStableLifecycleLedger",
            "completedStableLifecycleDescriptor",
        }
        missing_completion = sorted(completion_required.difference(manifest.inputs))
        if missing_completion:
            raise ValueError(
                "stable-backport verify-release-completion requires exact protected inputs: "
                + ", ".join(missing_completion)
            )
    predecessor_build = manifest.policies.get("expectedPredecessorBuild")
    predecessor_release_id = manifest.policies.get(
        "expectedPredecessorReleaseId"
    )
    predecessor_product_digest = manifest.policies.get(
        "expectedPredecessorProductDigest"
    )
    if (
        not isinstance(predecessor_build, str)
        or re.fullmatch(r"[1-9][0-9]*", predecessor_build) is None
        or not isinstance(predecessor_release_id, str)
        or re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", predecessor_release_id
        )
        is None
        or not isinstance(predecessor_product_digest, str)
        or re.fullmatch(
            r"sha256:[0-9a-f]{64}", predecessor_product_digest
        )
        is None
        or int(version) <= int(predecessor_build)
    ):
        raise ValueError(
            "stable-backport requires the complete canonical immediate predecessor "
            "build, release id, and product digest plus a strictly higher candidate build"
        )


def _validate_stable_lifecycle_manifest(manifest: RunManifest) -> None:
    """Reject lifecycle evaluation with ambiguous policy, history, or command mode."""

    if manifest.release.profile != "stable-review":
        raise ValueError("stable-lifecycle requires release.profile stable-review")
    version = manifest.release.version
    if version is None or re.fullmatch(r"[1-9][0-9]*", version) is None:
        raise ValueError("stable-lifecycle requires the authenticated tip as release.version")
    required = {
        "stableGaPromotionSummary",
        "stableGaValidation",
        "stableGaAuthorizationSummary",
        "stableGaPublicationPlan",
        "stableGaPublicationReceipt",
        "stableGaChecksums",
        "stableGaProvenance",
        "stableGaMaintenanceBaseline",
        "predecessorPublicationReceipt",
        "predecessorBaseline",
        "stableMaintenanceHistory",
        "stableLifecyclePolicy",
    }
    missing = sorted(required.difference(manifest.inputs))
    if missing:
        raise ValueError(
            "stable-lifecycle requires explicit authenticated inputs: " + ", ".join(missing)
        )
    mode = manifest.commands.get("stable-lifecycle", {}).get("mode", "evaluate")
    allowed = {
        "evaluate",
        "prepare-transition",
        "validate-authorization",
        "verify-publication",
    }
    if mode not in allowed:
        raise ValueError(
            "stable-lifecycle mode must be evaluate, prepare-transition, "
            "validate-authorization, or verify-publication"
        )
    has_approval = "stableLifecycleAuthorization" in manifest.inputs
    has_receipt = "stableLifecyclePublicationReceipt" in manifest.inputs
    if mode in {"evaluate", "prepare-transition"} and (has_approval or has_receipt):
        raise ValueError(f"stable-lifecycle {mode} cannot consume protected publication inputs")
    if mode in {"validate-authorization", "verify-publication"} and not has_approval:
        raise ValueError(f"stable-lifecycle {mode} requires inputs.stableLifecycleAuthorization")
    if mode == "verify-publication" and not has_receipt:
        raise ValueError(
            "stable-lifecycle verify-publication requires inputs.stableLifecyclePublicationReceipt"
        )
    expected_build = manifest.policies.get("expectedPredecessorBuild")
    if expected_build != version:
        raise ValueError(
            "stable-lifecycle release.version must equal policies.expectedPredecessorBuild"
        )
    if manifest.policies.get("publicationIntent") != (
        "prepare-explicit-protected-publication"
    ):
        raise ValueError("stable-lifecycle requires explicit protected publication intent")


_STABLE_SUPPLY_CHAIN_MODE_INPUTS = {
    "assemble-inventory": {
        "supplyChainPolicy",
        "resolvedDependencySnapshot",
        "componentInventory",
        "releaseSubjectInventory",
        "licenseInventory",
        "buildMaterials",
        "primarySubjectRoot",
        "licenseOverrides",
        "licenseTextRoot",
    },
    "verify-inventory": {
        "supplyChainPolicy",
        "resolvedDependencySnapshot",
        "componentInventory",
        "releaseSubjectInventory",
        "licenseInventory",
        "stableSupplyChainSbom",
        "sbomBinding",
        "buildMaterials",
        "componentReverseIndex",
        "primarySubjectRoot",
        "licenseOverrides",
        "licenseTextRoot",
    },
    "prepare-rebuild-comparison": {
        "supplyChainPolicy",
        "resolvedDependencySnapshot",
        "componentInventory",
        "releaseSubjectInventory",
        "buildMaterials",
        "primaryBuilderReceipt",
        "verifierBuilderReceipt",
    },
    "compare-rebuilds": {
        "supplyChainPolicy",
        "resolvedDependencySnapshot",
        "releaseSubjectInventory",
        "buildMaterials",
        "primaryBuilderReceipt",
        "verifierBuilderReceipt",
        "primarySubjectRoot",
        "verifierSubjectRoot",
        "rebuildComparisonPlan",
    },
    "evaluate-promotion": {
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
        "rebuildComparisonPlan",
        "reproducibilityResult",
        "componentReverseIndex",
        "licenseOverrides",
        "licenseTextRoot",
        "maintenanceCandidate",
        "maintenanceCandidateFreeze",
        "stableVulnerabilitySummary",
    },
    "verify-publication": {
        "supplyChainPolicy",
        "supplyChainPromotionSummary",
        "supplyChainPublicationPlan",
        "supplyChainPublicationReceipt",
        "supplyChainPublicObservation",
    },
}

_STABLE_SUPPLY_CHAIN_OPTIONAL_MODE_INPUTS = {
    "assemble-inventory": {"primaryPayloadManifests"},
    "verify-inventory": {"primaryPayloadManifests"},
    "prepare-rebuild-comparison": {
        "primaryPayloadManifests",
        "verifierPayloadManifests",
    },
    "compare-rebuilds": {
        "primaryPayloadManifests",
        "verifierPayloadManifests",
    },
    "evaluate-promotion": set(),
    "verify-publication": set(),
}


def _validate_stable_supply_chain_manifest(manifest: RunManifest) -> None:
    """Keep inventory, rebuild, promotion, and publication trust boundaries separate."""

    if manifest.release.profile != "stable-review":
        raise ValueError("stable-supply-chain requires release.profile stable-review")
    version = manifest.release.version
    if version is None or re.fullmatch(r"[1-9][0-9]*", version) is None:
        raise ValueError(
            "stable-supply-chain requires a canonical positive integer release.version"
        )
    commit = manifest.policies.get("candidateSourceCommit")
    if not isinstance(commit, str) or re.fullmatch(r"[0-9a-f]{40,64}", commit) is None:
        raise ValueError(
            "stable-supply-chain requires a canonical policies.candidateSourceCommit"
        )
    if manifest.policies.get("candidateSourceRef") != f"commit:{commit}":
        raise ValueError(
            "stable-supply-chain requires policies.candidateSourceRef to bind the full commit"
        )
    if manifest.requirements.get("stableSupplyChain") is not True:
        raise ValueError("stable-supply-chain requires requirements.stableSupplyChain=true")
    if manifest.policies.get("stableSupplyChainGovernance") != "required":
        raise ValueError(
            "stable-supply-chain requires policies.stableSupplyChainGovernance=required"
        )
    mode = manifest.commands.get("stable-supply-chain", {}).get(
        "mode", "verify-inventory"
    )
    required = _STABLE_SUPPLY_CHAIN_MODE_INPUTS.get(mode)
    if required is None:
        raise ValueError(
            "stable-supply-chain mode must be assemble-inventory, verify-inventory, "
            "prepare-rebuild-comparison, compare-rebuilds, evaluate-promotion, or "
            "verify-publication"
        )
    configured = set(manifest.inputs)
    missing = sorted(required - configured)
    optional = _STABLE_SUPPLY_CHAIN_OPTIONAL_MODE_INPUTS[mode]
    irrelevant = sorted(configured - required - optional)
    if missing:
        raise ValueError(
            f"stable-supply-chain {mode} requires exact inputs: " + ", ".join(missing)
        )
    if irrelevant:
        raise ValueError(
            f"stable-supply-chain {mode} rejects irrelevant phase inputs: "
            + ", ".join(irrelevant)
        )
    if mode == "verify-publication":
        if manifest.policies.get("publicationIntent") != (
            "prepare-explicit-protected-publication"
        ):
            raise ValueError(
                "stable-supply-chain publication verification requires explicit protected "
                "publication intent"
            )
        if not isinstance(manifest.policies.get("artifactBaseUri"), str):
            raise ValueError(
                "stable-supply-chain publication verification requires policies.artifactBaseUri"
            )
    if mode == "evaluate-promotion" and not isinstance(
        manifest.execution.get("evaluationClock"), str
    ):
        raise ValueError(
            "stable-supply-chain promotion evaluation requires execution.evaluationClock"
        )


_STABLE_DEPENDENCY_VULNERABILITY_MODE_INPUTS = {
    "validate-intelligence": {
        "dependencyVulnerabilityPolicy",
        "dependencyIntelligenceProvenanceSet",
        "dependencyIntelligenceSnapshot",
    },
    "match-inventory": {
        "dependencyVulnerabilityPolicy",
        "dependencyIntelligenceProvenanceSet",
        "dependencyIntelligenceSnapshot",
        "supplyChainPolicy",
        "supplyChainPromotionSummary",
        "resolvedDependencySnapshot",
        "componentInventory",
        "releaseSubjectInventory",
        "componentReverseIndex",
    },
    "authorize-dispositions": {
        "dependencyVulnerabilityPolicy",
        "dependencyIntelligenceProvenanceSet",
        "dependencyIntelligenceSnapshot",
        "dependencyVulnerabilityFindingSet",
        "dependencyVulnerabilityDispositionSet",
        "dependencyVulnerabilityDispositionAuthorizations",
        "dependencyVulnerabilityDispositionAuthorizationProvenance",
    },
    "prepare-remediation": {
        "dependencyVulnerabilityPolicy",
        "dependencyIntelligenceProvenanceSet",
        "dependencyIntelligenceSnapshot",
        "dependencyVulnerabilityFindingSet",
        "dependencyVulnerabilityLedger",
        "dependencyVulnerabilityDispositionSet",
        "dependencyVulnerabilityRemediationSet",
        "stableVulnerabilitySummary",
        "supplyChainPromotionSummary",
        "componentReverseIndex",
    },
    "evaluate-promotion": {
        "dependencyVulnerabilityPolicy",
        "dependencyIntelligenceProvenanceSet",
        "dependencyIntelligenceSnapshot",
        "dependencyVulnerabilityFindingSet",
        "dependencyVulnerabilityLedger",
        "dependencyVulnerabilityDispositionSet",
        "dependencyVulnerabilityDispositionAuthorizations",
        "dependencyVulnerabilityDispositionAuthorizationProvenance",
        "dependencyVulnerabilityRemediationSet",
        "supplyChainPolicy",
        "supplyChainPromotionSummary",
        "resolvedDependencySnapshot",
        "componentInventory",
        "releaseSubjectInventory",
        "componentReverseIndex",
        "stableVulnerabilitySummary",
        "maintenanceCandidate",
        "maintenanceCandidateFreeze",
        "stableAssuranceCloseout",
    },
    "verify-publication": {
        "dependencyVulnerabilityPolicy",
        "dependencyVulnerabilityPromotionSummary",
        "dependencyVulnerabilityPublicationPlan",
        "dependencyVulnerabilityPublicationReceipt",
        "dependencyVulnerabilityPublicObservation",
        "dependencyVulnerabilityPublicationProvenance",
    },
}

_STABLE_DEPENDENCY_VULNERABILITY_OPTIONAL_MODE_INPUTS = {
    "validate-intelligence": {"previousDependencyIntelligenceSnapshot"},
    "match-inventory": {
        "previousDependencyIntelligenceSnapshot",
        "previousDependencyVulnerabilityFindingSet",
        "previousDependencyVulnerabilityLedger",
        "previousDependencyVulnerabilityDispositionSet",
    },
    "authorize-dispositions": {
        "previousDependencyIntelligenceSnapshot",
        "previousDependencyVulnerabilityFindingSet",
        "previousDependencyVulnerabilityLedger",
        "previousDependencyVulnerabilityDispositionSet",
    },
    "prepare-remediation": {
        "previousDependencyIntelligenceSnapshot",
        "previousDependencyVulnerabilityLedger",
    },
    "evaluate-promotion": {
        "previousDependencyIntelligenceSnapshot",
        "previousDependencyVulnerabilityFindingSet",
        "previousDependencyVulnerabilityLedger",
        "previousDependencyVulnerabilityDispositionSet",
        "stableBackportValidation",
        "stableBackportCompletion",
        "stableBackportCompletionHandoff",
        "stableMaintenancePublicationReceipt",
        "dependencyVulnerabilityRemediationEvidenceProvenance",
    },
    "verify-publication": set(),
}


def _validate_stable_dependency_vulnerability_manifest(manifest: RunManifest) -> None:
    """Keep advisory acquisition, review, remediation, promotion, and publication separate."""

    if manifest.release.profile != "stable-review":
        raise ValueError(
            "stable-dependency-vulnerability requires release.profile stable-review"
        )
    version = manifest.release.version
    if version is None or re.fullmatch(r"[1-9][0-9]*", version) is None:
        raise ValueError(
            "stable-dependency-vulnerability requires a canonical positive integer "
            "release.version"
        )
    commit = manifest.policies.get("candidateSourceCommit")
    if not isinstance(commit, str) or re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        raise ValueError(
            "stable-dependency-vulnerability requires a full candidateSourceCommit"
        )
    if manifest.policies.get("candidateSourceRef") != f"commit:{commit}":
        raise ValueError(
            "stable-dependency-vulnerability candidateSourceRef must bind the commit"
        )
    if manifest.requirements.get("stableDependencyVulnerability") is not True:
        raise ValueError(
            "stable-dependency-vulnerability requires "
            "requirements.stableDependencyVulnerability=true"
        )
    if manifest.policies.get("stableDependencyVulnerabilityGovernance") != "required":
        raise ValueError(
            "stable-dependency-vulnerability requires "
            "policies.stableDependencyVulnerabilityGovernance=required"
        )
    mode = manifest.commands.get("stable-dependency-vulnerability", {}).get(
        "mode", "evaluate-promotion"
    )
    required = _STABLE_DEPENDENCY_VULNERABILITY_MODE_INPUTS.get(mode)
    if required is None:
        raise ValueError(
            "stable-dependency-vulnerability mode must be validate-intelligence, "
            "match-inventory, authorize-dispositions, prepare-remediation, "
            "evaluate-promotion, or verify-publication"
        )
    family_inputs = set().union(
        *_STABLE_DEPENDENCY_VULNERABILITY_MODE_INPUTS.values(),
        *_STABLE_DEPENDENCY_VULNERABILITY_OPTIONAL_MODE_INPUTS.values(),
    )
    configured = family_inputs.intersection(manifest.inputs)
    optional = _STABLE_DEPENDENCY_VULNERABILITY_OPTIONAL_MODE_INPUTS[mode]
    missing = sorted(required.difference(configured))
    irrelevant = sorted(configured.difference(required | optional))
    if missing:
        raise ValueError(
            f"stable-dependency-vulnerability {mode} requires exact inputs: "
            + ", ".join(missing)
        )
    if irrelevant:
        raise ValueError(
            f"stable-dependency-vulnerability {mode} rejects irrelevant phase inputs: "
            + ", ".join(irrelevant)
        )
    if mode == "evaluate-promotion":
        candidate_remediation = {
            "stableBackportValidation",
            "dependencyVulnerabilityRemediationEvidenceProvenance",
        }
        published_remediation = candidate_remediation | {
            "stableBackportCompletion",
            "stableBackportCompletionHandoff",
            "stableMaintenancePublicationReceipt",
        }
        configured_remediation = frozenset(
            published_remediation.intersection(configured)
        )
        if configured_remediation and configured_remediation not in {
            frozenset(candidate_remediation),
            frozenset(published_remediation),
        }:
            raise ValueError(
                "stable-dependency-vulnerability evaluate-promotion requires an "
                "exact candidate or published remediation evidence set"
            )
    if not isinstance(manifest.execution.get("evaluationClock"), str):
        raise ValueError(
            "stable-dependency-vulnerability requires execution.evaluationClock"
        )
    if mode == "verify-publication":
        if manifest.policies.get("publicationIntent") != (
            "prepare-explicit-protected-publication"
        ):
            raise ValueError(
                "stable-dependency-vulnerability publication verification requires "
                "explicit protected publication intent"
            )
        if not isinstance(manifest.policies.get("artifactBaseUri"), str):
            raise ValueError(
                "stable-dependency-vulnerability publication verification requires "
                "policies.artifactBaseUri"
            )


def _validate_stable_vulnerability_manifest(manifest: RunManifest) -> None:
    """Reject vulnerability lifecycle runs with mixed trust-boundary inputs."""

    if manifest.release.profile != "stable-review":
        raise ValueError("stable-vulnerability requires release.profile stable-review")
    version = manifest.release.version
    if version is None or re.fullmatch(r"[1-9][0-9]*", version) is None:
        raise ValueError(
            "stable-vulnerability requires a canonical positive integer release.version"
        )
    mode = manifest.commands.get("stable-vulnerability", {}).get(
        "mode", "evaluate-intake"
    )
    required_by_mode = {
        "evaluate-intake": {
            "stableVulnerabilityPolicy",
            "previousStableVulnerabilityLedger",
            "stableVulnerabilityReportEnvelope",
            "stableVulnerabilityAcknowledgement",
        },
        "evaluate-promotion": {
            "stableVulnerabilityPolicy",
            "previousStableVulnerabilityLedger",
            "stableVulnerabilityPromotionEvaluation",
        },
        "validate-triage": {
            "stableVulnerabilityPolicy",
            "previousStableVulnerabilityLedger",
            "stableVulnerabilityTriage",
            "stableVulnerabilityTriageAuthorization",
        },
        "record-reporter-update": {
            "stableVulnerabilityPolicy",
            "previousStableVulnerabilityLedger",
            "stableVulnerabilityReporterCoordination",
        },
        "prepare-remediation": {
            "stableVulnerabilityPolicy",
            "previousStableVulnerabilityLedger",
            "stableVulnerabilityRemediationBinding",
        },
        "validate-disclosure-authorization": {
            "stableVulnerabilityPolicy",
            "previousStableVulnerabilityLedger",
            "stableVulnerabilityRemediationBinding",
            "stableVulnerabilityAdvisory",
            "stableVulnerabilityReporterCoordination",
            "stableVulnerabilityDisclosureAuthorization",
        },
        "verify-disclosure-publication": {
            "stableVulnerabilityPolicy",
            "previousStableVulnerabilityLedger",
            "stableVulnerabilityAdvisory",
            "stableVulnerabilityDisclosureAuthorization",
            "stableVulnerabilityPublicationPlan",
            "stableVulnerabilityPublicationReceipt",
            "stableVulnerabilityPublicObservationReceipt",
        },
        "verify-closure": {
            "stableVulnerabilityPolicy",
            "previousStableVulnerabilityLedger",
            "stableVulnerabilityAdvisory",
            "stableVulnerabilityDisclosureAuthorization",
            "stableVulnerabilityReporterCoordination",
            "stableVulnerabilityPublicationReceipt",
            "stableVulnerabilityPublicObservationReceipt",
            "stableVulnerabilityClosureEvidence",
        },
    }
    required = required_by_mode.get(mode)
    if required is None:
        raise ValueError(
            "stable-vulnerability mode must be evaluate-intake, evaluate-promotion, "
            "validate-triage, record-reporter-update, "
            "prepare-remediation, validate-disclosure-authorization, "
            "verify-disclosure-publication, or verify-closure"
        )
    missing = sorted(required.difference(manifest.inputs))
    if missing:
        raise ValueError(
            f"stable-vulnerability {mode} requires exact inputs: " + ", ".join(missing)
        )
    authority_receipts = {
        "stableVulnerabilityMitigationPublicationReceipt",
        "catalogSecurityPublicationReceipt",
        "keyRevocationOrRotationReceipt",
    }.intersection(manifest.inputs)
    has_provenance = (
        "stableVulnerabilityAuthorityReceiptProvenance" in manifest.inputs
    )
    if authority_receipts and not has_provenance:
        raise ValueError(
            "independent authority receipts require exact producer provenance"
        )
    if has_provenance and not authority_receipts:
        raise ValueError(
            "authority receipt provenance requires an independent authority receipt"
        )


def _run_command(args: argparse.Namespace) -> int:
    command = str(args.command)
    if getattr(args, "self_test", False):
        return selftest.run(command)
    if command == "cross-version-soak":
        from .cross_version_command import run

        try:
            return run(args)
        except Exception:
            # Selected paths, upstream replies and private comparisons are never public errors.
            raise ValueError("cross-version-command-failed; no complete soak evidence produced") from None
    if command == "stable-protected-release":
        from .engines import stable_1_0_protected_release

        if args.mode is None or args.execution_contract is None:
            raise ValueError(
                "stable-protected-release requires --mode and --execution-contract"
            )

        return stable_1_0_protected_release.run(
            args.workspace_root.resolve(),
            args.execution_contract,
            args.mode,
            args.out_dir,
            args.rc_input_map,
        )
    if command == "stable-catalog-authority":
        from .engines import stable_1_0_catalog_authority

        if args.mode is None or args.authority_manifest is None:
            raise ValueError(
                "stable-catalog-authority requires --mode and --authority-manifest"
            )
        return stable_1_0_catalog_authority.run(
            args.workspace_root.resolve(),
            args.authority_manifest,
            args.mode,
            args.out_dir,
            args.evidence_dir,
            args.live_publication_result,
        )
    if command == "stable-independent-reproducibility":
        from .engines import stable_1_0_independent_reproducibility

        if args.mode is None or args.execution_contract is None:
            raise ValueError(
                "stable-independent-reproducibility requires --mode and --execution-contract"
            )
        return stable_1_0_independent_reproducibility.run(
            args.workspace_root.resolve(),
            args.execution_contract,
            args.mode,
            args.out_dir,
        )
    if command == "stable-third-party-pilot":
        from .engines import stable_1_0_third_party_pilot

        if args.mode is None or args.execution_contract is None:
            raise ValueError(
                "stable-third-party-pilot requires --mode and --execution-contract"
            )
        return stable_1_0_third_party_pilot.run(
            args.workspace_root.resolve(),
            args.execution_contract,
            args.mode,
            args.out_dir,
            args.evidence_dir,
        )
    if command == "stable-federated-catalog":
        from .engines import stable_1_0_federated_catalog

        if args.mode is None or args.execution_contract is None:
            raise ValueError(
                "stable-federated-catalog requires --mode and --execution-contract"
            )
        return stable_1_0_federated_catalog.run(
            args.workspace_root.resolve(),
            args.execution_contract,
            args.mode,
            args.out_dir,
            args.evidence_dir,
        )
    if command == "stable-platform-api-1x":
        from .engines import stable_platform_api_1x

        if args.mode is None or args.execution_contract is None:
            raise ValueError(
                "stable-platform-api-1x requires --mode and --execution-contract"
            )
        return stable_platform_api_1x.run(
            args.workspace_root.resolve(),
            args.execution_contract,
            args.mode,
            args.out_dir,
            args.evidence_dir,
        )
    if command == "stable-content-profile-review":
        from .engines import stable_content_profile_review

        return stable_content_profile_review.run(args.workspace_root.resolve(), args.mode)
    if command == "stable-legacy-plugin-migration":
        from .engines import stable_legacy_plugin_migration

        if args.mode is None or args.observation is None or args.out_dir is None:
            raise ValueError(
                "stable-legacy-plugin-migration requires --mode, --observation, and --out-dir"
            )
        return stable_legacy_plugin_migration.run(
            args.workspace_root.resolve(), args.observation, args.mode, args.out_dir
        )
    manifest_path = getattr(args, "manifest", None)
    if manifest_path is None:
        raise ValueError(f"{command} requires --manifest")
    workspace_root = args.workspace_root.resolve()
    manifest = load_manifest(manifest_path.resolve(), workspace_root, args.out_root)
    if command == "stable-rc":
        _validate_stable_rc_manifest(manifest)
    if command == "stable-ga":
        _validate_stable_ga_manifest(manifest)
    if command == "stable-backport":
        _validate_stable_backport_manifest(manifest)
    if command == "stable-maintenance":
        _validate_stable_maintenance_manifest(manifest)
    if command == "stable-lifecycle":
        _validate_stable_lifecycle_manifest(manifest)
    if command == "stable-supply-chain":
        _validate_stable_supply_chain_manifest(manifest)
    if command == "stable-dependency-vulnerability":
        _validate_stable_dependency_vulnerability_manifest(manifest)
    if command == "stable-vulnerability":
        _validate_stable_vulnerability_manifest(manifest)
    prepare_run_root(manifest)

    previous = Path.cwd()
    try:
        os.chdir(workspace_root)
        if command == "migrate-v1":
            component = f"migration/{args.migration_kind}"
            _require_pending_component(manifest, component)
            context = prepare_context(workspace_root, manifest, component)
            code = execute_migration(context, args.migration_kind)
        else:
            action = getattr(args, "action", None)
            if command in {"multi-node-beta", "security-response"} and action is None:
                raise ValueError(f"{command} requires an action unless --self-test is used")
            if command == "release-certification" and manifest.execution.get("collectEvidence") is True:
                _require_pending_component(manifest, "release-certification")
                _collect_release_evidence(workspace_root, manifest)
            if command == "stable-rc":
                _require_pending_component(manifest, "stable-rc")
                _execute_component(workspace_root, manifest, "production-beta")
            component = command if action is None else f"{command}/{action}"
            context = prepare_context(workspace_root, manifest, component)
            code = execute_engine(context, command, action)
    finally:
        os.chdir(previous)
    print(f"{command}: {context.component_dir / 'summary.json'}")
    return code


def main(argv: list[str] | None = None) -> int:
    """Run the unified CLI with sanitized error handling."""

    args = build_parser().parse_args(argv)
    try:
        if args.command == "self-test":
            return selftest.run(args.suite)
        return _run_command(args)
    except (OSError, ValueError) as exc:
        print(f"certify: {exc}", file=sys.stderr)
        return 2
