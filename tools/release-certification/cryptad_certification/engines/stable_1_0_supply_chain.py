"""Canonical, phase-separated Stable 1.0 supply-chain certification engine."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from cryptad_certification.io import read_json, write_json, write_text
from cryptad_certification.models import RunContext
from cryptad_certification.redaction import scan_value
from cryptad_certification.stable_vulnerability_summary import load_summary
from cryptad_certification.workspace import reset_confined_directory

from .stable_1_0_supply_chain_archive import ARCHIVE_PACKAGE_TYPES, archive_subject_errors
from .stable_1_0_supply_chain_core import (
    BUILD_MATERIALS_FILE,
    BUILD_MATERIALS_SCHEMA,
    BUILDER_RECEIPT_SCHEMA,
    COMMAND_MODES,
    COMPARISON_PLAN_FILE,
    COMPARISON_PLAN_SCHEMA,
    COMPONENT_INVENTORY_FILE,
    COMPONENT_INVENTORY_SCHEMA,
    LICENSE_INVENTORY_FILE,
    LICENSE_INVENTORY_SCHEMA,
    LICENSE_OVERRIDES_SCHEMA,
    POLICY_SCHEMA,
    PUBLICATION_PLAN_FILE,
    PUBLICATION_PLAN_SCHEMA,
    PUBLICATION_RECEIPT_FILE,
    PUBLICATION_RECEIPT_SCHEMA,
    PUBLICATION_ROLE_FILES,
    PUBLIC_OBSERVATION_FILE,
    PUBLIC_OBSERVATION_SCHEMA,
    REPORT_FILE,
    REPRODUCIBILITY_FILE,
    REPRODUCIBILITY_SCHEMA,
    RESOLUTION_SNAPSHOT_FILE,
    RESOLUTION_SNAPSHOT_SCHEMA,
    REVERSE_INDEX_FILE,
    REVERSE_INDEX_SCHEMA,
    SBOM_BINDING_FILE,
    SBOM_BINDING_SCHEMA,
    SBOM_FILE,
    SUBJECT_INVENTORY_FILE,
    SUBJECT_INVENTORY_SCHEMA,
    SUMMARY_FILE,
    SUMMARY_SCHEMA,
    build_material_errors,
    checked_policy_errors,
    component_inventory_errors,
    confined_child,
    configured_directory,
    configured_file,
    digest_map,
    exact_release_errors,
    file_digest,
    jdk_component_coverage_errors,
    license_inventory_errors,
    load_document,
    payload_manifest_errors,
    parse_timestamp,
    release_identity,
    resolution_snapshot_errors,
    semantic_digest,
    subject_inventory_errors,
    write_document,
)
from .stable_1_0_supply_chain_reproducibility import (
    build_comparison_plan,
    builder_independence_errors,
    builder_receipt_errors,
    compare_rebuilds,
    comparison_plan_errors,
    publication_errors,
    promotion_summary_errors,
    reproducibility_result_errors,
)
from .stable_1_0_supply_chain_sbom import (
    build_reverse_index,
    build_sbom_binding,
    build_spdx,
    reverse_index_errors,
    sbom_errors,
)

SUPPLY_CHAIN_INPUTS = frozenset(
    {
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
        "licenseOverrides",
        "licenseTextRoot",
        "maintenanceCandidate",
        "maintenanceCandidateFreeze",
        "stableVulnerabilitySummary",
    }
)

_PHASE_INPUTS: dict[str, tuple[frozenset[str], frozenset[str]]] = {
    "assemble-inventory": (
        frozenset(
            {
                "supplyChainPolicy",
                "resolvedDependencySnapshot",
                "componentInventory",
                "releaseSubjectInventory",
                "licenseInventory",
                "buildMaterials",
                "primarySubjectRoot",
                "licenseOverrides",
                "licenseTextRoot",
            }
        ),
        frozenset({"primaryPayloadManifests"}),
    ),
    "verify-inventory": (
        frozenset(
            {
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
            }
        ),
        frozenset({"primaryPayloadManifests"}),
    ),
    "prepare-rebuild-comparison": (
        frozenset(
            {
                "supplyChainPolicy",
                "resolvedDependencySnapshot",
                "componentInventory",
                "releaseSubjectInventory",
                "buildMaterials",
                "primaryBuilderReceipt",
                "verifierBuilderReceipt",
            }
        ),
        frozenset({"primaryPayloadManifests", "verifierPayloadManifests"}),
    ),
    "compare-rebuilds": (
        frozenset(
            {
                "supplyChainPolicy",
                "resolvedDependencySnapshot",
                "releaseSubjectInventory",
                "buildMaterials",
                "primaryBuilderReceipt",
                "verifierBuilderReceipt",
                "primarySubjectRoot",
                "verifierSubjectRoot",
                "rebuildComparisonPlan",
            }
        ),
        frozenset({"primaryPayloadManifests", "verifierPayloadManifests"}),
    ),
    "evaluate-promotion": (
        frozenset(
            {
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
            }
        ),
        frozenset(),
    ),
    "verify-publication": (
        frozenset(
            {
                "supplyChainPolicy",
                "supplyChainPromotionSummary",
                "supplyChainPublicationPlan",
                "supplyChainPublicationReceipt",
                "supplyChainPublicObservation",
            }
        ),
        frozenset(),
    ),
}

EVIDENCE_IDS = (
    "stable-supply-chain.policy",
    "stable-supply-chain.dependency-resolution",
    "stable-supply-chain.component-coverage",
    "stable-supply-chain.subject-binding",
    "stable-supply-chain.post-build-subject-binding",
    "stable-supply-chain.license-policy",
    "stable-supply-chain.build-materials",
    "stable-supply-chain.builder-independence",
    "stable-supply-chain.byte-reproducibility",
    "stable-supply-chain.normalized-payload-reproducibility",
    "stable-supply-chain.sbom-binding",
    "stable-supply-chain.vulnerability-index",
    "stable-supply-chain.publication",
    "stable-supply-chain.redaction",
    "stable-supply-chain.release-promotion",
)


def run(context: RunContext) -> tuple[int, Path, Path]:
    """Run one supply-chain phase without performing any external mutation."""

    out = reset_confined_directory(
        context.component_dir / "artifacts" / "legacy",
        context.run_root,
        "Stable supply-chain output",
    )
    summary_path = out / SUMMARY_FILE
    report_path = out / REPORT_FILE
    mode = context.manifest.commands.get("stable-supply-chain", {}).get("mode")
    try:
        if mode not in COMMAND_MODES:
            raise ValueError("Stable supply-chain mode is missing or invalid")
        _phase_input_errors(context, mode)
        handler = _HANDLERS[mode]
        code = handler(context, out)
    except Exception:  # noqa: BLE001 - protected evidence must always fail closed
        summary = _summary(
            context,
            str(mode) if mode in COMMAND_MODES else "assemble-inventory",
            None,
            [],
            [
                {
                    "evidenceId": "stable-supply-chain.execution-input",
                    "message": (
                        "Stable supply-chain certification rejected malformed, unsafe, "
                        "stale, irrelevant, or unauthenticated phase input."
                    ),
                }
            ],
            [],
        )
        write_document(summary_path, summary, SUMMARY_SCHEMA)
        write_text(report_path, _render_report(summary))
        code = 1
    return code, summary_path, report_path


def _phase_input_errors(context: RunContext, mode: str) -> None:
    required, optional = _PHASE_INPUTS[mode]
    present = SUPPLY_CHAIN_INPUTS.intersection(context.manifest.inputs)
    missing = sorted(required.difference(present))
    irrelevant = sorted(present.difference(required | optional))
    if missing:
        raise ValueError("supply-chain phase inputs are missing: " + ", ".join(missing))
    if irrelevant:
        raise ValueError("supply-chain phase inputs are irrelevant: " + ", ".join(irrelevant))


def _load_policy_and_release(
    context: RunContext,
) -> tuple[dict[str, Any], dict[str, Any]]:
    # The exact checked-in policy contains closed negative labels such as
    # ``secretValuesProhibited``. Authenticate its reviewed bytes before scanning evidence; those
    # labels are not secret payloads.
    loaded = load_document(context, "supplyChainPolicy", POLICY_SCHEMA, public=False)
    assert loaded is not None
    path, policy, _ = loaded
    errors = checked_policy_errors(context, path, policy)
    if errors:
        raise ValueError(errors[0])
    return policy, release_identity(context, policy["policyDigest"])


def _load_inventory_set(
    context: RunContext,
    policy: dict[str, Any],
    release: dict[str, Any],
    *,
    exact_subject_bytes: bool,
) -> tuple[
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
]:
    snapshot_loaded = load_document(
        context, "resolvedDependencySnapshot", RESOLUTION_SNAPSHOT_SCHEMA
    )
    components_loaded = load_document(
        context, "componentInventory", COMPONENT_INVENTORY_SCHEMA
    )
    subjects_loaded = load_document(
        context, "releaseSubjectInventory", SUBJECT_INVENTORY_SCHEMA
    )
    licenses_loaded = load_document(context, "licenseInventory", LICENSE_INVENTORY_SCHEMA)
    materials_loaded = load_document(context, "buildMaterials", BUILD_MATERIALS_SCHEMA)
    assert all(
        loaded is not None
        for loaded in (
            snapshot_loaded,
            components_loaded,
            subjects_loaded,
            licenses_loaded,
            materials_loaded,
        )
    )
    snapshot = snapshot_loaded[1]  # type: ignore[index]
    components = components_loaded[1]  # type: ignore[index]
    subjects = subjects_loaded[1]  # type: ignore[index]
    licenses = licenses_loaded[1]  # type: ignore[index]
    materials = materials_loaded[1]  # type: ignore[index]
    subject_root = (
        configured_directory(context, "primarySubjectRoot") if exact_subject_bytes else None
    )
    text_root = configured_directory(
        context,
        "licenseTextRoot",
        allow_workspace_root=True,
    )
    overrides_loaded = load_document(context, "licenseOverrides", LICENSE_OVERRIDES_SCHEMA)
    assert overrides_loaded is not None
    errors: list[str] = []
    errors.extend(resolution_snapshot_errors(snapshot, release, policy))
    errors.extend(component_inventory_errors(components, policy, release))
    errors.extend(jdk_component_coverage_errors(components, subjects, materials, policy))
    if components.get("resolvedDependencySnapshotDigest") != snapshot.get("snapshotDigest"):
        errors.append("component inventory binds a different resolution snapshot")
    errors.extend(
        _resolved_component_coverage_errors(snapshot, components)
    )
    errors.extend(
        subject_inventory_errors(
            subjects, components, policy, release, subject_root=subject_root
        )
    )
    errors.extend(
        license_inventory_errors(
            licenses,
            components,
            policy,
            text_root,
            overrides_loaded[1],
        )
    )
    checked_overrides = (
        context.workspace_root
        / "tools"
        / "release-certification"
        / "stable-1.0-supply-chain-license-overrides.json"
    )
    if (
        checked_overrides.is_symlink()
        or not checked_overrides.is_file()
        or overrides_loaded[0].resolve() != checked_overrides.resolve()
        or overrides_loaded[2] != file_digest(checked_overrides)
    ):
        errors.append("license overrides are not the exact checked-in reviewed registry")
    errors.extend(
        build_material_errors(
            materials,
            release,
            snapshot["snapshotDigest"],
            policy,
            snapshot,
        )
    )
    if errors:
        raise ValueError(errors[0])
    return snapshot, components, subjects, licenses, materials


def _resolved_component_coverage_errors(
    snapshot: dict[str, Any], components: dict[str, Any]
) -> list[str]:
    snapshot_by_id = {row["componentId"]: row for row in snapshot["components"]}
    graph_by_id = {
        row["componentId"]: row
        for row in components["components"]
        if row["dependencyVerificationStatus"] == "verified"
        or (
            row["dependencyVerificationStatus"] == "not-applicable"
            and row["componentKind"] == "internal-module"
            and row["buildMaterialStatus"] in {"built", "verified"}
        )
    }
    snapshot_ids = set(snapshot_by_id)
    graph_ids = set(graph_by_id)
    errors: list[str] = []
    if snapshot_ids.difference(graph_ids):
        errors.append("resolved dependency is omitted from the component graph")
    if graph_ids.difference(snapshot_ids):
        errors.append("verified component is absent from the authenticated resolution snapshot")
    expected_dependencies: dict[str, set[str]] = {
        component_id: set() for component_id in snapshot_ids
    }
    for component_id, row in snapshot_by_id.items():
        for parent in row.get("parents", []):
            if parent in expected_dependencies:
                expected_dependencies[parent].add(component_id)
    kind_map = {
        "external-module": {"maven", "gradle-plugin"},
        "internal-project": {"internal-module"},
        "vendored-binary": {"vendored-binary"},
    }
    origin_map = {
        "external-module": {"maven-central", "gradle-plugin-portal"},
        "internal-project": {"repository-source", "built-first-party"},
        "vendored-binary": {"reviewed-vendor"},
    }
    for component_id in sorted(snapshot_ids.intersection(graph_ids)):
        resolved = snapshot_by_id[component_id]
        graph = graph_by_id[component_id]
        bindings = (
            ("digest", graph.get("digest"), resolved.get("artifactDigest")),
            ("version", graph.get("version"), resolved.get("version")),
            ("roles", graph.get("roles"), resolved.get("roles")),
            (
                "coordinates",
                graph.get("resolved", {}).get("coordinates"),
                resolved.get("coordinates"),
            ),
            (
                "selected variant",
                graph.get("resolved", {}).get("selectedVariant"),
                resolved.get("selectedVariant"),
            ),
            (
                "resolved attributes",
                graph.get("resolved", {}).get("attributes"),
                resolved.get("attributes"),
            ),
            (
                "direct relationship",
                graph.get("relationships", {}).get("direct"),
                resolved.get("direct"),
            ),
            (
                "parent relationships",
                graph.get("relationships", {}).get("parents"),
                resolved.get("parents"),
            ),
            (
                "dependency relationships",
                graph.get("relationships", {}).get("dependsOn"),
                sorted(expected_dependencies[component_id]),
            ),
        )
        for label, actual, expected in bindings:
            if actual != expected:
                errors.append(
                    f"component {component_id} {label} differs from authenticated resolution"
                )
        resolved_kind = resolved.get("componentKind")
        if graph.get("componentKind") not in kind_map.get(str(resolved_kind), set()):
            errors.append(
                f"component {component_id} kind differs from authenticated resolution"
            )
        origin_type = graph.get("origin", {}).get("type")
        if origin_type not in origin_map.get(str(resolved_kind), set()):
            errors.append(
                f"component {component_id} origin differs from authenticated resolution"
            )
        if resolved_kind == "external-module" and graph.get("origin", {}).get(
            "immutableReference"
        ) != resolved.get("artifactDigest"):
            errors.append(
                f"component {component_id} immutable origin differs from authenticated bytes"
            )
        resolved_verification = resolved.get("verificationStatus")
        graph_verification = graph.get("dependencyVerificationStatus")
        verification_matches = (
            resolved_verification == "verified" and graph_verification == "verified"
        ) or (
            resolved_verification == "authenticated-first-party"
            and resolved_kind == "internal-project"
            and graph_verification == "not-applicable"
            and graph.get("buildMaterialStatus") in {"built", "verified"}
        )
        if not verification_matches:
            errors.append(
                f"component {component_id} verification status differs from authenticated resolution"
            )
    return errors


def _load_sbom(context: RunContext) -> tuple[Path, dict[str, Any], str]:
    path = configured_file(context, "stableSupplyChainSbom")
    assert path is not None
    value = read_json(path)
    if not isinstance(value, dict) or scan_value(value):
        raise ValueError("Stable supply-chain SPDX input is malformed or redaction-unsafe")
    return path, value, file_digest(path)


def _write_inventory_artifacts(
    out: Path,
    release: dict[str, Any],
    policy: dict[str, Any],
    snapshot: dict[str, Any],
    components: dict[str, Any],
    subjects: dict[str, Any],
    licenses: dict[str, Any],
    materials: dict[str, Any],
) -> dict[str, Path]:
    sbom = build_spdx(release, policy, components, subjects)
    binding = build_sbom_binding(release, sbom, components, subjects)
    reverse_index = build_reverse_index(release, components, subjects)
    paths = {
        "resolved-dependency-snapshot": out / RESOLUTION_SNAPSHOT_FILE,
        "component-inventory": out / COMPONENT_INVENTORY_FILE,
        "release-subject-inventory": out / SUBJECT_INVENTORY_FILE,
        "license-inventory": out / LICENSE_INVENTORY_FILE,
        "build-materials": out / BUILD_MATERIALS_FILE,
        "sbom-binding": out / SBOM_BINDING_FILE,
        "component-reverse-index": out / REVERSE_INDEX_FILE,
    }
    for key, value, schema in (
        ("resolved-dependency-snapshot", snapshot, RESOLUTION_SNAPSHOT_SCHEMA),
        ("component-inventory", components, COMPONENT_INVENTORY_SCHEMA),
        ("release-subject-inventory", subjects, SUBJECT_INVENTORY_SCHEMA),
        ("license-inventory", licenses, LICENSE_INVENTORY_SCHEMA),
        ("build-materials", materials, BUILD_MATERIALS_SCHEMA),
        ("sbom-binding", binding, SBOM_BINDING_SCHEMA),
        ("component-reverse-index", reverse_index, REVERSE_INDEX_SCHEMA),
    ):
        write_document(paths[key], value, schema)
    write_json(out / SBOM_FILE, sbom)
    paths["sbom"] = out / SBOM_FILE
    return paths


def _assemble_inventory(context: RunContext, out: Path) -> int:
    policy, release = _load_policy_and_release(context)
    snapshot, components, subjects, licenses, materials = _load_inventory_set(
        context, policy, release, exact_subject_bytes=True
    )
    _validate_payload_directory_if_present(context, policy, subjects, components)
    paths = _write_inventory_artifacts(
        out, release, policy, snapshot, components, subjects, licenses, materials
    )
    return _finish_phase(context, out, "assemble-inventory", release, paths)


def _verify_inventory(context: RunContext, out: Path) -> int:
    policy, release = _load_policy_and_release(context)
    snapshot, components, subjects, licenses, materials = _load_inventory_set(
        context, policy, release, exact_subject_bytes=True
    )
    _validate_payload_directory_if_present(context, policy, subjects, components)
    supplied_sbom = _load_sbom(context)[1]
    binding_loaded = load_document(context, "sbomBinding", SBOM_BINDING_SCHEMA)
    reverse_loaded = load_document(context, "componentReverseIndex", REVERSE_INDEX_SCHEMA)
    assert binding_loaded is not None and reverse_loaded is not None
    errors = sbom_errors(
        supplied_sbom,
        binding_loaded[1],
        build_spdx(release, policy, components, subjects),
        components,
        subjects,
    )
    errors.extend(reverse_index_errors(reverse_loaded[1], release, components, subjects))
    if errors:
        raise ValueError(errors[0])
    paths = _write_inventory_artifacts(
        out, release, policy, snapshot, components, subjects, licenses, materials
    )
    return _finish_phase(context, out, "verify-inventory", release, paths)


def _prepare_comparison(context: RunContext, out: Path) -> int:
    policy, release = _load_policy_and_release(context)
    snapshot = _required_value(context, "resolvedDependencySnapshot", RESOLUTION_SNAPSHOT_SCHEMA)
    components = _required_value(context, "componentInventory", COMPONENT_INVENTORY_SCHEMA)
    subjects = _required_value(context, "releaseSubjectInventory", SUBJECT_INVENTORY_SCHEMA)
    materials = _required_value(context, "buildMaterials", BUILD_MATERIALS_SCHEMA)
    errors = resolution_snapshot_errors(snapshot, release, policy)
    errors.extend(component_inventory_errors(components, policy, release))
    errors.extend(jdk_component_coverage_errors(components, subjects, materials, policy))
    errors.extend(subject_inventory_errors(subjects, components, policy, release))
    errors.extend(
        build_material_errors(
            materials, release, snapshot["snapshotDigest"], policy, snapshot
        )
    )
    primary = _required_value(context, "primaryBuilderReceipt", BUILDER_RECEIPT_SCHEMA)
    verifier = _required_value(context, "verifierBuilderReceipt", BUILDER_RECEIPT_SCHEMA)
    errors.extend(
        builder_receipt_errors(
            primary,
            "candidate-producer",
            release,
            policy,
            materials["materialsDigest"],
            snapshot["snapshotDigest"],
            materials,
            subjects,
            snapshot,
        )
    )
    errors.extend(
        builder_receipt_errors(
            verifier,
            "independent-verifier",
            release,
            policy,
            materials["materialsDigest"],
            snapshot["snapshotDigest"],
            materials,
            subjects,
            snapshot,
        )
    )
    errors.extend(builder_independence_errors(primary, verifier, policy))
    if errors:
        raise ValueError(errors[0])
    plan = build_comparison_plan(release, policy, subjects, primary, verifier)
    path = out / COMPARISON_PLAN_FILE
    write_document(path, plan, COMPARISON_PLAN_SCHEMA)
    return _finish_phase(
        context,
        out,
        "prepare-rebuild-comparison",
        release,
        {"rebuild-comparison-plan": path},
    )


def _compare(context: RunContext, out: Path) -> int:
    policy, release = _load_policy_and_release(context)
    snapshot = _required_value(context, "resolvedDependencySnapshot", RESOLUTION_SNAPSHOT_SCHEMA)
    subjects = _required_value(context, "releaseSubjectInventory", SUBJECT_INVENTORY_SCHEMA)
    materials = _required_value(context, "buildMaterials", BUILD_MATERIALS_SCHEMA)
    primary = _required_value(context, "primaryBuilderReceipt", BUILDER_RECEIPT_SCHEMA)
    verifier = _required_value(context, "verifierBuilderReceipt", BUILDER_RECEIPT_SCHEMA)
    plan = _required_value(context, "rebuildComparisonPlan", COMPARISON_PLAN_SCHEMA)
    errors: list[str] = []
    errors.extend(resolution_snapshot_errors(snapshot, release, policy))
    errors.extend(
        build_material_errors(
            materials, release, snapshot["snapshotDigest"], policy, snapshot
        )
    )
    errors.extend(
        builder_receipt_errors(
            primary,
            "candidate-producer",
            release,
            policy,
            materials["materialsDigest"],
            snapshot["snapshotDigest"],
            materials,
            subjects,
            snapshot,
        )
    )
    errors.extend(
        builder_receipt_errors(
            verifier,
            "independent-verifier",
            release,
            policy,
            materials["materialsDigest"],
            snapshot["snapshotDigest"],
            materials,
            subjects,
            snapshot,
        )
    )
    errors.extend(
        comparison_plan_errors(plan, release, policy, subjects, primary, verifier)
    )
    if errors:
        raise ValueError(errors[0])
    primary_root = configured_directory(context, "primarySubjectRoot")
    verifier_root = configured_directory(context, "verifierSubjectRoot")
    assert primary_root is not None and verifier_root is not None
    result, differences = compare_rebuilds(
        release,
        policy,
        plan,
        primary_root,
        verifier_root,
        configured_directory(context, "primaryPayloadManifests", required=False),
        configured_directory(context, "verifierPayloadManifests", required=False),
    )
    path = out / REPRODUCIBILITY_FILE
    write_document(path, result, REPRODUCIBILITY_SCHEMA)
    if differences:
        raise ValueError(differences[0])
    return _finish_phase(
        context,
        out,
        "compare-rebuilds",
        release,
        {"reproducibility-report": path},
    )


def _evaluate(context: RunContext, out: Path) -> int:
    policy, release = _load_policy_and_release(context)
    snapshot, components, subjects, licenses, materials = _load_inventory_set(
        context, policy, release, exact_subject_bytes=False
    )
    sbom = _load_sbom(context)[1]
    binding = _required_value(context, "sbomBinding", SBOM_BINDING_SCHEMA)
    reverse_index = _required_value(context, "componentReverseIndex", REVERSE_INDEX_SCHEMA)
    primary = _required_value(context, "primaryBuilderReceipt", BUILDER_RECEIPT_SCHEMA)
    verifier = _required_value(context, "verifierBuilderReceipt", BUILDER_RECEIPT_SCHEMA)
    plan = _required_value(context, "rebuildComparisonPlan", COMPARISON_PLAN_SCHEMA)
    result = _required_value(context, "reproducibilityResult", REPRODUCIBILITY_SCHEMA)
    errors = sbom_errors(
        sbom,
        binding,
        build_spdx(release, policy, components, subjects),
        components,
        subjects,
    )
    errors.extend(reverse_index_errors(reverse_index, release, components, subjects))
    errors.extend(
        builder_receipt_errors(
            primary,
            "candidate-producer",
            release,
            policy,
            materials["materialsDigest"],
            snapshot["snapshotDigest"],
            materials,
            subjects,
            snapshot,
        )
    )
    errors.extend(
        builder_receipt_errors(
            verifier,
            "independent-verifier",
            release,
            policy,
            materials["materialsDigest"],
            snapshot["snapshotDigest"],
            materials,
            subjects,
            snapshot,
        )
    )
    errors.extend(builder_independence_errors(primary, verifier, policy))
    errors.extend(comparison_plan_errors(plan, release, policy, subjects, primary, verifier))
    errors.extend(reproducibility_result_errors(result, release, plan))
    if result.get("status") != "pass" or result.get("unexplainedDifferences") != 0:
        errors.append("reproducibility result contains unexplained differences")
    if errors:
        raise ValueError(errors[0])

    promotion_bindings = _maintenance_promotion_bindings(
        context, release, subjects, reverse_index
    )

    paths = _write_inventory_artifacts(
        out, release, policy, snapshot, components, subjects, licenses, materials
    )
    repro_path = out / REPRODUCIBILITY_FILE
    write_document(repro_path, result, REPRODUCIBILITY_SCHEMA)
    paths["reproducibility-report"] = repro_path
    comparison_plan_path = out / COMPARISON_PLAN_FILE
    write_document(comparison_plan_path, plan, COMPARISON_PLAN_SCHEMA)
    summary = _summary(
        context,
        "evaluate-promotion",
        release,
        digest_map(paths.items()),
        [],
        _evidence_for_mode("evaluate-promotion"),
        bindings=promotion_bindings
    )
    summary_path = out / SUMMARY_FILE
    write_document(summary_path, summary, SUMMARY_SCHEMA)
    paths["supply-chain-summary"] = summary_path
    publication_plan = _publication_plan(context, release, policy, summary, paths)
    write_document(out / PUBLICATION_PLAN_FILE, publication_plan, PUBLICATION_PLAN_SCHEMA)
    write_text(out / REPORT_FILE, _render_report(summary))
    return 0


def _verify_publication(context: RunContext, out: Path) -> int:
    policy, release = _load_policy_and_release(context)
    promotion = _required_value(
        context, "supplyChainPromotionSummary", SUMMARY_SCHEMA
    )
    plan = _required_value(context, "supplyChainPublicationPlan", PUBLICATION_PLAN_SCHEMA)
    receipt = _required_value(
        context, "supplyChainPublicationReceipt", PUBLICATION_RECEIPT_SCHEMA
    )
    observation = _required_value(
        context, "supplyChainPublicObservation", PUBLIC_OBSERVATION_SCHEMA
    )
    summary_errors = promotion_summary_errors(promotion, release)
    summary_errors.extend(evaluated_promotion_summary_errors(promotion))
    if summary_errors:
        raise ValueError(summary_errors[0])
    if context.manifest.policies.get("artifactBaseUri") != policy.get(
        "publicationPolicy", {}
    ).get("immutableBaseUri"):
        raise ValueError(
            "publication artifactBaseUri differs from the reviewed policy immutable base"
        )
    evaluation_clock = context.manifest.execution.get("evaluationClock")
    if not isinstance(evaluation_clock, str):
        raise ValueError("verify-publication requires a deterministic evaluationClock")
    errors = publication_errors(
        plan, receipt, observation, promotion, release, policy, evaluation_clock
    )
    if errors:
        raise ValueError(errors[0])
    binding_fields = (
        "candidateIdentityDigest",
        "candidateFreezeDigest",
        "productDigest",
        "predecessorReleaseId",
        "predecessorBuildVersion",
        "predecessorProductDigest",
        "packageMatrixDigest",
        "packageAuthenticationDigest",
        "selectedSubjectInventoryDigest",
        "vulnerabilitySummaryDigest",
        "vulnerabilityReverseIndexDigest",
        "resolvedDependencySnapshotDigest",
        "componentInventoryDigest",
        "subjectInventoryDigest",
        "sbomDigest",
        "licenseInventoryDigest",
        "buildMaterialsDigest",
        "primaryBuilderReceiptDigest",
        "verifierBuilderReceiptDigest",
        "comparisonPlanDigest",
        "reproducibilityResultDigest",
    )
    final_summary = _summary(
        context,
        "verify-publication",
        release,
        promotion.get("artifacts", []),
        [],
        list(EVIDENCE_IDS),
        bindings={field: promotion.get(field) for field in binding_fields},
    )
    for name, value, schema in (
        (SUMMARY_FILE, final_summary, SUMMARY_SCHEMA),
        (PUBLICATION_PLAN_FILE, plan, PUBLICATION_PLAN_SCHEMA),
        (PUBLICATION_RECEIPT_FILE, receipt, PUBLICATION_RECEIPT_SCHEMA),
        (PUBLIC_OBSERVATION_FILE, observation, PUBLIC_OBSERVATION_SCHEMA),
    ):
        write_document(out / name, value, schema)
    write_text(out / REPORT_FILE, _render_report(final_summary, publication_verified=True))
    return 0


def _required_value(context: RunContext, key: str, schema: str) -> dict[str, Any]:
    loaded = load_document(context, key, schema)
    assert loaded is not None
    return loaded[1]


def _validate_payload_directory_if_present(
    context: RunContext,
    policy: dict[str, Any],
    subjects: dict[str, Any],
    components: dict[str, Any],
) -> None:
    directory = configured_directory(context, "primaryPayloadManifests", required=False)
    policy_rules = {
        row["subjectKey"]: row
        for row in policy["releaseSubjects"]
    }
    required = {
        row["subjectKey"]
        for row in subjects["subjects"]
        if policy_rules[row["subjectKey"]].get("normalizationRuleId") is not None
    }
    if not required and directory is None:
        return
    if directory is None:
        raise ValueError("packaged subjects require primary payload manifests")
    subject_root = configured_directory(context, "primarySubjectRoot")
    assert subject_root is not None
    subject_by_key = {row["subjectKey"]: row for row in subjects["subjects"]}
    component_by_id = {
        row["componentId"]: row for row in components["components"]
    }
    exact_runtime_kinds = {
        "first-party-app",
        "gradle-plugin",
        "maven",
        "native",
        "vendored-binary",
        "web-asset",
    }
    byte_contained_components: set[str] = set()
    found: set[str] = set()
    for path in sorted(directory.iterdir(), key=lambda item: item.name):
        if path.is_symlink() or not path.is_file() or path.suffix != ".json":
            raise ValueError("payload-manifest directory contains an unexpected entry")
        value = read_json(path)
        if not isinstance(value, dict):
            raise ValueError("payload manifest must be an object")
        errors = payload_manifest_errors(value, policy)
        if errors:
            raise ValueError(errors[0])
        key = value["subjectKey"]
        if key in found:
            raise ValueError("payload manifest subject is duplicated")
        found.add(key)
        subject = subject_by_key.get(key)
        if subject is None or subject.get("payloadManifestDigest") != value.get("manifestDigest"):
            raise ValueError("payload manifest differs from the subject inventory binding")
        if value.get("publishedSubjectDigest") != subject.get("digest"):
            raise ValueError("payload manifest binds different published package bytes")
        rule = policy_rules[key]
        if value.get("normalizationRuleId") != rule.get("normalizationRuleId"):
            raise ValueError("payload manifest differs from its subject policy rule")
        mapped = {
            component_id
            for entry in value.get("entries", [])
            if isinstance(entry, dict)
            for component_id in entry.get("componentIds", [])
        }
        if mapped != set(subject.get("componentIds", [])):
            raise ValueError("payload manifest does not map exactly the subject components")
        for component_id in subject.get("componentIds", []):
            component = component_by_id.get(component_id)
            if (
                component is None
                or "runtime" not in component.get("roles", [])
                or component.get("componentKind") not in exact_runtime_kinds
            ):
                continue
            digest = component.get("digest")
            if digest == subject.get("digest") or any(
                entry.get("digest") == digest
                and component_id in entry.get("componentIds", [])
                for entry in value.get("entries", [])
                if isinstance(entry, dict)
            ):
                byte_contained_components.add(component_id)
        if value.get("packageType") in ARCHIVE_PACKAGE_TYPES:
            path = confined_child(subject_root, str(subject["fileName"]))
            if path is None or not path.is_file() or path.is_symlink():
                raise ValueError("archive subject bytes are missing or unsafe")
            archive_errors = archive_subject_errors(
                path, value, subject, component_by_id, policy
            )
            if archive_errors:
                raise ValueError(archive_errors[0])
    if found != required:
        raise ValueError("payload manifests do not cover exactly the policy-selected subjects")
    required_byte_containment = {
        component_id
        for component_id, component in component_by_id.items()
        if "runtime" in component.get("roles", [])
        and component.get("componentKind") in exact_runtime_kinds
    }
    missing_byte_containment = sorted(
        required_byte_containment.difference(byte_contained_components)
    )
    if missing_byte_containment:
        raise ValueError(
            "runtime component is not byte-contained by any actual product payload: "
            + missing_byte_containment[0]
        )


def _finish_phase(
    context: RunContext,
    out: Path,
    mode: str,
    release: dict[str, Any],
    paths: dict[str, Path],
) -> int:
    summary = _summary(
        context,
        mode,
        release,
        digest_map(paths.items()),
        [],
        _evidence_for_mode(mode),
    )
    write_document(out / SUMMARY_FILE, summary, SUMMARY_SCHEMA)
    write_text(out / REPORT_FILE, _render_report(summary))
    return 0


def _evidence_for_mode(mode: str) -> list[str]:
    return {
        "assemble-inventory": [
            "stable-supply-chain.policy",
            "stable-supply-chain.dependency-resolution",
            "stable-supply-chain.component-coverage",
            "stable-supply-chain.subject-binding",
            "stable-supply-chain.post-build-subject-binding",
            "stable-supply-chain.license-policy",
            "stable-supply-chain.build-materials",
            "stable-supply-chain.sbom-binding",
            "stable-supply-chain.vulnerability-index",
        ],
        "verify-inventory": [
            "stable-supply-chain.policy",
            "stable-supply-chain.dependency-resolution",
            "stable-supply-chain.component-coverage",
            "stable-supply-chain.subject-binding",
            "stable-supply-chain.post-build-subject-binding",
            "stable-supply-chain.license-policy",
            "stable-supply-chain.build-materials",
            "stable-supply-chain.sbom-binding",
            "stable-supply-chain.vulnerability-index",
        ],
        "prepare-rebuild-comparison": [
            "stable-supply-chain.policy",
            "stable-supply-chain.build-materials",
            "stable-supply-chain.builder-independence",
        ],
        "compare-rebuilds": [
            "stable-supply-chain.builder-independence",
            "stable-supply-chain.byte-reproducibility",
            "stable-supply-chain.normalized-payload-reproducibility",
        ],
        "evaluate-promotion": [
            evidence_id
            for evidence_id in EVIDENCE_IDS
            if evidence_id != "stable-supply-chain.publication"
        ],
        "verify-publication": [
            "stable-supply-chain.publication",
            "stable-supply-chain.redaction",
            "stable-supply-chain.release-promotion",
        ],
    }[mode]


EVALUATED_PROMOTION_BINDING_FIELDS = (
    "candidateIdentityDigest",
    "candidateFreezeDigest",
    "productDigest",
    "predecessorReleaseId",
    "predecessorBuildVersion",
    "predecessorProductDigest",
    "packageMatrixDigest",
    "packageAuthenticationDigest",
    "selectedSubjectInventoryDigest",
    "vulnerabilitySummaryDigest",
    "vulnerabilityReverseIndexDigest",
    "resolvedDependencySnapshotDigest",
    "componentInventoryDigest",
    "subjectInventoryDigest",
    "sbomDigest",
    "licenseInventoryDigest",
    "buildMaterialsDigest",
    "primaryBuilderReceiptDigest",
    "verifierBuilderReceiptDigest",
    "comparisonPlanDigest",
    "reproducibilityResultDigest",
)


def evaluated_promotion_summary_errors(summary: dict[str, Any]) -> list[str]:
    """Require the complete evaluate-promotion surface consumed by release gates."""

    errors: list[str] = []
    if summary.get("mode") != "evaluate-promotion" or summary.get(
        "promotionReady"
    ) is not True:
        errors.append("release requires a promotion-ready evaluated supply-chain summary")
    expected_evidence = [
        {"evidenceId": evidence_id, "status": "pass", "nonWaivable": True}
        for evidence_id in _evidence_for_mode("evaluate-promotion")
    ]
    if summary.get("evidence") != expected_evidence:
        errors.append("release summary lacks the exact evaluated promotion evidence")
    if any(summary.get(field) is None for field in EVALUATED_PROMOTION_BINDING_FIELDS):
        errors.append("release summary lacks complete evaluated promotion bindings")
    return errors


def _summary(
    context: RunContext,
    mode: str,
    release: dict[str, Any] | None,
    artifacts: list[dict[str, Any]],
    blockers: list[dict[str, str]],
    evidence_ids: list[str],
    *,
    bindings: dict[str, Any] | None = None,
) -> dict[str, Any]:
    release_value = release or {
        "releaseId": context.manifest.release.release_id,
        "buildVersion": int(context.manifest.release.version or 1),
        "tag": f"v{context.manifest.release.version or 1}",
        "sourceCommit": "0" * 40,
        "sourceRef": "refs/heads/invalid",
        "policyDigest": "sha256:" + "0" * 64,
    }
    digest_bindings = {
        "candidateIdentityDigest": None,
        "candidateFreezeDigest": None,
        "productDigest": None,
        "predecessorReleaseId": None,
        "predecessorBuildVersion": None,
        "predecessorProductDigest": None,
        "packageMatrixDigest": None,
        "packageAuthenticationDigest": None,
        "selectedSubjectInventoryDigest": None,
        "vulnerabilitySummaryDigest": None,
        "vulnerabilityReverseIndexDigest": None,
        "resolvedDependencySnapshotDigest": None,
        "componentInventoryDigest": None,
        "subjectInventoryDigest": None,
        "sbomDigest": None,
        "licenseInventoryDigest": None,
        "buildMaterialsDigest": None,
        "primaryBuilderReceiptDigest": None,
        "verifierBuilderReceiptDigest": None,
        "comparisonPlanDigest": None,
        "reproducibilityResultDigest": None,
    }
    digest_bindings.update(bindings or {})
    summary = {
        "schemaVersion": 1,
        "kind": "stable-1.0-supply-chain-promotion-summary",
        **release_value,
        "mode": mode,
        "status": "fail" if blockers else "pass",
        "promotionReady": not blockers and mode in {"evaluate-promotion", "verify-publication"},
        **digest_bindings,
        "evidence": [
            {
                "evidenceId": evidence_id,
                "status": "pass",
                "nonWaivable": True,
            }
            for evidence_id in evidence_ids
        ],
        "blockers": blockers,
        "waivers": [],
        "artifacts": artifacts,
        "redaction": {
            "status": "pass" if not blockers else "fail",
            "privatePathsExcluded": True,
            "credentialsExcluded": True,
            "privateUrisExcluded": True,
            "embargoedVulnerabilityDataExcluded": True,
            "sideEffectsPerformed": False,
        },
        "summaryDigest": "sha256:" + "0" * 64,
    }
    summary["summaryDigest"] = semantic_digest(summary, "summaryDigest")
    return summary


def _load_untyped_public_object(
    context: RunContext, key: str
) -> tuple[Path, dict[str, Any], str]:
    path = configured_file(context, key)
    assert path is not None
    value = read_json(path)
    if not isinstance(value, dict) or scan_value(value):
        raise ValueError(f"{key} is malformed or redaction-unsafe")
    return path, value, file_digest(path)


def _maintenance_promotion_bindings(
    context: RunContext,
    release: dict[str, Any],
    subjects: dict[str, Any],
    reverse_index: dict[str, Any],
) -> dict[str, Any]:
    """Authenticate and bind the maintenance/freeze/PR-288 promotion boundary."""

    _, candidate, _ = _load_untyped_public_object(
        context, "maintenanceCandidate"
    )
    freeze_loaded = load_document(
        context,
        "maintenanceCandidateFreeze",
        "stable-1.0-maintenance-candidate-freeze.schema.json",
    )
    assert freeze_loaded is not None
    _, freeze, freeze_file_digest = freeze_loaded
    vulnerability = _authenticated_vulnerability_summary(context)
    if candidate.get("kind") != "stable-1.0-maintenance-candidate":
        raise ValueError("maintenance candidate identity kind is invalid")
    for value, label in ((candidate, "maintenance candidate"), (freeze, "candidate freeze")):
        if value.get("releaseId") != release["releaseId"]:
            raise ValueError(f"{label} belongs to another release")
        if int(value.get("buildVersion", -1)) != release["buildVersion"]:
            raise ValueError(f"{label} belongs to another build")
    if candidate.get("source", {}).get("commit") != release["sourceCommit"]:
        raise ValueError("maintenance candidate source commit differs")
    if freeze.get("source", {}).get("commit") != release["sourceCommit"]:
        raise ValueError("candidate freeze source commit differs")
    if candidate.get("candidateFreezeDigest") != freeze_file_digest:
        raise ValueError("maintenance candidate binds a different freeze")
    product_digest = candidate.get("product", {}).get("digest")
    if not isinstance(product_digest, str):
        raise ValueError("maintenance candidate product digest is absent")

    subject_by_digest: dict[str, list[dict[str, Any]]] = {}
    for subject in subjects["subjects"]:
        subject_by_digest.setdefault(subject["digest"], []).append(subject)
    selected_subjects: list[dict[str, str]] = []
    package_authentication_rows: list[dict[str, Any]] = []
    primary_receipt_path = configured_file(context, "primaryBuilderReceipt")
    assert primary_receipt_path is not None
    primary_receipt = read_json(primary_receipt_path)
    primary_subjects = {
        row.get("subjectKey"): row
        for row in primary_receipt.get("subjects", [])
        if isinstance(row, dict)
    }
    for asset in freeze.get("assets", []):
        matches = subject_by_digest.get(asset.get("digest"), [])
        if len(matches) != 1:
            raise ValueError("frozen maintenance asset does not resolve to one exact subject")
        selected_subjects.append(
            {"subjectKey": matches[0]["subjectKey"], "digest": matches[0]["digest"]}
        )
        authentication = _frozen_asset_authentication_row(asset, matches[0])
        if authentication is not None:
            package_authentication_rows.append(authentication)
            if matches[0].get("subjectClass") == "installer":
                built = primary_subjects.get(matches[0]["subjectKey"])
                if (
                    built is None
                    or built.get("signatureReceiptDigest")
                    != asset.get("signingReceiptDigest")
                    or built.get("notarizationReceiptDigest")
                    != asset.get("notarizationReceiptDigest")
                    or built.get("extractionEvidenceDigest") is None
                ):
                    raise ValueError(
                        "producer extraction/signing receipt differs from the frozen installer"
                    )
    if product_digest not in subject_by_digest:
        raise ValueError("maintenance product is absent from the subject inventory")
    selected_subjects.sort(key=lambda row: row["subjectKey"])
    if len({row["subjectKey"] for row in selected_subjects}) != len(selected_subjects):
        raise ValueError("frozen maintenance assets map ambiguously to release subjects")

    package_rows = [
        {"packageKey": row["packageKey"], "digest": row["digest"]}
        for row in candidate.get("packages", [])
        if isinstance(row, dict)
    ]
    package_rows.sort(key=lambda row: row["packageKey"])
    if any(row["packageKey"] is None for row in package_rows):
        raise ValueError("maintenance package matrix contains a non-package row")
    package_matrix_digest = semantic_digest({"packages": package_rows}, "__none__")
    package_authentication_rows.sort(key=lambda row: row["subjectKey"])
    package_authentication_digest = semantic_digest(
        {"assets": package_authentication_rows}, "__none__"
    )
    selected_binding_digest = semantic_digest(
        {
            "subjectInventoryDigest": subjects["subjectInventoryDigest"],
            "selectedSubjects": selected_subjects,
        },
        "__none__",
    )

    if vulnerability.get("releaseId") != release["releaseId"] or int(
        vulnerability.get("buildVersion", -1)
    ) != release["buildVersion"]:
        raise ValueError("PR-288 vulnerability summary belongs to another release or build")
    if vulnerability.get("status") != "pass" or vulnerability.get(
        "blockingStablePromotion"
    ) is not False:
        raise ValueError("PR-288 vulnerability summary blocks Stable promotion")
    if semantic_digest(vulnerability, "summaryDigest") != vulnerability.get(
        "summaryDigest"
    ):
        raise ValueError("PR-288 vulnerability summary digest is invalid")
    predecessor = freeze.get("predecessorObservation", {})
    return {
        "candidateIdentityDigest": semantic_digest(candidate, "__none__"),
        "candidateFreezeDigest": freeze_file_digest,
        "productDigest": product_digest,
        "predecessorReleaseId": predecessor.get("releaseId"),
        "predecessorBuildVersion": int(predecessor["buildVersion"]),
        "predecessorProductDigest": predecessor.get("productDigest"),
        "packageMatrixDigest": package_matrix_digest,
        "packageAuthenticationDigest": package_authentication_digest,
        "selectedSubjectInventoryDigest": selected_binding_digest,
        "vulnerabilitySummaryDigest": vulnerability["summaryDigest"],
        "vulnerabilityReverseIndexDigest": reverse_index["reverseIndexDigest"],
        "resolvedDependencySnapshotDigest": context_value_digest(
            context, "resolvedDependencySnapshot", "snapshotDigest"
        ),
        "componentInventoryDigest": context_value_digest(
            context, "componentInventory", "inventoryDigest"
        ),
        "subjectInventoryDigest": subjects["subjectInventoryDigest"],
        "sbomDigest": context_value_digest(context, "sbomBinding", "sbomDigest"),
        "licenseInventoryDigest": context_value_digest(
            context, "licenseInventory", "licenseInventoryDigest"
        ),
        "buildMaterialsDigest": context_value_digest(
            context, "buildMaterials", "materialsDigest"
        ),
        "primaryBuilderReceiptDigest": context_value_digest(
            context, "primaryBuilderReceipt", "receiptDigest"
        ),
        "verifierBuilderReceiptDigest": context_value_digest(
            context, "verifierBuilderReceipt", "receiptDigest"
        ),
        "comparisonPlanDigest": context_value_digest(
            context, "rebuildComparisonPlan", "planDigest"
        ),
        "reproducibilityResultDigest": context_value_digest(
            context, "reproducibilityResult", "resultDigest"
        ),
    }


def _frozen_asset_authentication_row(
    asset: dict[str, Any], subject: dict[str, Any]
) -> dict[str, Any] | None:
    """Bind installer/catalog authentication to the exact maintenance freeze asset."""

    if subject.get("subjectClass") not in {"installer", "catalog"}:
        return None
    if subject.get("signatureReceiptDigest") != asset.get("signingReceiptDigest"):
        raise ValueError("release subject signing receipt differs from the frozen asset")
    if subject.get("notarizationReceiptDigest") != asset.get("notarizationReceiptDigest"):
        raise ValueError("release subject notarization receipt differs from the frozen asset")
    if asset.get("packageType") == "dmg" and (
        asset.get("notarizationStatus") != "pass"
        or not isinstance(asset.get("notarizationReceiptDigest"), str)
    ):
        raise ValueError("frozen DMG lacks authenticated notarization evidence")
    return {
        "subjectKey": subject["subjectKey"],
        "subjectDigest": subject["digest"],
        "signingReceiptDigest": asset["signingReceiptDigest"],
        "notarizationReceiptDigest": asset.get("notarizationReceiptDigest"),
    }


def _authenticated_vulnerability_summary(context: RunContext) -> dict[str, Any]:
    """Authenticate the fresh PR-288 promotion summary and its current ledger tip."""

    evaluation_clock = context.manifest.execution.get("evaluationClock")
    if not isinstance(evaluation_clock, str):
        raise ValueError(
            "supply-chain promotion requires a deterministic vulnerability evaluationClock"
        )
    clock = parse_timestamp(evaluation_clock, "supply-chain promotion evaluation clock")
    summary, errors = load_summary(context, evaluation_clock=clock)
    if summary is None or errors:
        detail = errors[0] if errors else "authenticated vulnerability summary is absent"
        raise ValueError(f"PR-288 vulnerability summary authentication failed: {detail}")
    return summary


def context_value_digest(context: RunContext, key: str, field: str) -> str:
    """Read one already schema-validated phase document's stable identity field."""

    path = configured_file(context, key)
    assert path is not None
    value = read_json(path)
    digest = value.get(field) if isinstance(value, dict) else None
    if not isinstance(digest, str):
        raise ValueError(f"{key} lacks required digest field {field}")
    return digest


def _publication_plan(
    context: RunContext,
    release: dict[str, Any],
    policy: dict[str, Any],
    summary: dict[str, Any],
    paths: dict[str, Path],
) -> dict[str, Any]:
    base_uri = policy["publicationPolicy"]["immutableBaseUri"].rstrip("/")
    required_roles = policy["publicationPolicy"]["requiredRoles"]
    if required_roles != list(PUBLICATION_ROLE_FILES):
        raise ValueError("publication policy role-to-file vocabulary differs")
    assets = []
    for role in required_roles:
        path = paths.get(role)
        if path is None:
            raise ValueError(f"publication role {role} lacks an exact generated artifact")
        if path.name != PUBLICATION_ROLE_FILES[role]:
            raise ValueError(f"publication role {role} uses a noncanonical file name")
        assets.append(
            {
                "role": role,
                "fileName": path.name,
                "digest": file_digest(path),
                "size": path.stat().st_size,
                "uri": f"{base_uri}/v{release['buildVersion']}/{path.name}",
            }
        )
    plan = {
        "schemaVersion": 1,
        "kind": "stable-1.0-supply-chain-publication-plan",
        **release,
        "summaryDigest": summary["summaryDigest"],
        "assets": assets,
        "overwriteAllowed": False,
        "allowedOperations": ["created", "verified-existing"],
        "sideEffectsPerformed": False,
        "planDigest": "sha256:" + "0" * 64,
    }
    plan["planDigest"] = semantic_digest(plan, "planDigest")
    return plan


def _render_report(
    summary: dict[str, Any], *, publication_verified: bool = False
) -> str:
    lines = [
        "# Stable 1.0 supply-chain certification",
        "",
        f"- Release: `{summary['releaseId']}` / `v{summary['buildVersion']}`",
        f"- Mode: `{summary['mode']}`",
        f"- Status: **{summary['status'].upper()}**",
        f"- Promotion ready: `{str(summary['promotionReady']).lower()}`",
        f"- Public publication verified: `{str(publication_verified).lower()}`",
        "- External side effects performed: `false`",
        "",
        "## Evidence",
        "",
    ]
    lines.extend(
        f"- `{row['evidenceId']}`: {row['status']} (non-waivable)"
        for row in summary["evidence"]
    )
    if summary["blockers"]:
        lines.extend(["", "## Blockers", ""])
        lines.extend(f"- {row['message']}" for row in summary["blockers"])
    return "\n".join(lines) + "\n"


_HANDLERS: dict[str, Callable[[RunContext, Path], int]] = {
    "assemble-inventory": _assemble_inventory,
    "verify-inventory": _verify_inventory,
    "prepare-rebuild-comparison": _prepare_comparison,
    "compare-rebuilds": _compare,
    "evaluate-promotion": _evaluate,
    "verify-publication": _verify_publication,
}
