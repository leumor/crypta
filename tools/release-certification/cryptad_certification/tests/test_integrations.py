"""Integration contracts for manifests, adapters, orchestration, and workflows."""

from __future__ import annotations

import contextlib
import io
import os
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock

from cryptad_certification import cli, legacy
from cryptad_certification.engines import (
    app_platform_smoke,
    live_network_beta_smoke,
    multi_node_beta_soak,
    production_beta_go_no_go_dashboard,
    production_beta_release,
    release_certification,
    security_response_runbook,
    stable_1_0_readiness,
)
from cryptad_certification.io import read_json, write_json, write_text
from cryptad_certification.manifest import load_manifest
from cryptad_certification.models import EvidenceEnvelope, RunContext
from cryptad_certification.tests.support import workspace_root, write_manifest
from cryptad_certification.workspace import prepare_context, prepare_run_root


class CollectionIntegrationTest(unittest.TestCase):
    def test_release_collection_runs_every_candidate_scoped_collector(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = load_manifest(
                write_manifest(
                    root,
                    requirements={"liveNetwork": True, "multiNodeSoak": True},
                    execution={"collectEvidence": True},
                ),
                root,
            )
            calls: list[tuple[str, str | None]] = []

            def capture(
                workspace: Path,
                configured_manifest: object,
                command: str,
                action: str | None = None,
            ) -> int:
                self.assertEqual(root, workspace)
                self.assertIs(manifest, configured_manifest)
                calls.append((command, action))
                return 0

            with mock.patch.object(cli, "_execute_component", side_effect=capture):
                cli._collect_release_evidence(root, manifest)

            self.assertEqual(
                [
                    ("app-platform", None),
                    ("network-scale-soak", None),
                    ("multi-node-beta", "run"),
                    ("security-response", "verify"),
                    ("security-response", "drill-run-all"),
                    ("security-response", "drill-verify-all"),
                    ("live-network-beta", None),
                ],
                calls,
            )

    def test_internal_collection_replaces_an_existing_component_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = load_manifest(write_manifest(root), root)
            prepare_run_root(manifest)
            stale_context = prepare_context(root, manifest, "app-platform")
            stale_summary = stale_context.component_dir / "summary.json"
            stale_artifact = stale_context.component_dir / "artifacts/stale.json"
            write_json(stale_summary, {"schemaVersion": 2, "result": {"status": "pass"}})
            write_json(stale_artifact, {"source": "previous invocation"})

            def execute(context: RunContext, command: str, action: str | None) -> int:
                self.assertEqual("app-platform", command)
                self.assertIsNone(action)
                component_dir = context.component_dir
                self.assertFalse((component_dir / "summary.json").exists())
                self.assertFalse((component_dir / "artifacts/stale.json").exists())
                return 0

            with mock.patch.object(cli, "execute_engine", side_effect=execute) as engine:
                self.assertEqual(0, cli._execute_component(root, manifest, "app-platform"))

            engine.assert_called_once()

    def test_internal_collection_rejects_a_symlinked_parent_before_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = load_manifest(write_manifest(root), root)
            run_root = prepare_run_root(manifest)
            preserved_component = run_root / "preserved-security-response/verify"
            preserved_component.mkdir(parents=True)
            preserved_file = preserved_component / "keep.json"
            write_json(preserved_file, {"preserved": True})
            symlinked_parent = run_root / "security-response"
            try:
                symlinked_parent.symlink_to(
                    preserved_component.parent,
                    target_is_directory=True,
                )
            except OSError as exc:
                self.skipTest(f"directory symlinks are unavailable: {exc}")

            with mock.patch.object(cli, "execute_engine") as engine:
                with self.assertRaisesRegex(ValueError, "contains a symlink"):
                    cli._execute_component(
                        root,
                        manifest,
                        "security-response",
                        "verify",
                    )

            engine.assert_not_called()
            self.assertTrue(preserved_file.is_file())

    def test_completed_aggregate_is_rejected_before_recollecting_components(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest_path = write_manifest(
                root,
                execution={"collectEvidence": True},
            )
            manifest = load_manifest(manifest_path, root)
            run_root = prepare_run_root(manifest)
            aggregate_dir = run_root / "release-certification"
            aggregate_dir.mkdir()
            old_summary = {"schemaVersion": 2, "result": {"status": "pass"}}
            write_json(aggregate_dir / "summary.json", old_summary)
            app_platform = prepare_context(root, manifest, "app-platform")
            preserved = app_platform.component_dir / "preserved-evidence.json"
            write_json(preserved, {"candidate": "original"})

            with (
                mock.patch.object(cli, "_collect_release_evidence") as collect,
                contextlib.redirect_stderr(io.StringIO()),
            ):
                code = cli.main(
                    [
                        "release-certification",
                        "--manifest",
                        str(manifest_path),
                        "--workspace-root",
                        str(root),
                    ]
                )

            self.assertEqual(2, code)
            collect.assert_not_called()
            self.assertEqual(old_summary, read_json(aggregate_dir / "summary.json"))
            self.assertFalse((aggregate_dir / "artifacts").exists())
            self.assertEqual({"candidate": "original"}, read_json(preserved))

    def test_completed_migration_is_rejected_without_reset(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "legacy.json"
            original = {
                "schemaVersion": 1,
                "status": "pass",
                "marker": "original",
                "redaction": {"status": "pass", "findings": []},
            }
            write_json(source, original)
            manifest_path = write_manifest(
                root,
                inputs={"previousCandidate": source.name},
            )
            arguments = [
                "migrate-v1",
                "previous-candidate",
                "--manifest",
                str(manifest_path),
                "--workspace-root",
                str(root),
            ]
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(0, cli.main(arguments))
            component = (
                root
                / "build/release-certification/self-test-release/migration/previous-candidate"
            )
            original_summary = read_json(component / "summary.json")
            original_artifact = read_json(component / "artifacts/migrated-summary.json")
            replacement = dict(original)
            replacement["marker"] = "replacement"
            write_json(source, replacement)

            with contextlib.redirect_stderr(io.StringIO()):
                code = cli.main(arguments)

            self.assertEqual(2, code)
            self.assertEqual(original_summary, read_json(component / "summary.json"))
            self.assertEqual(
                original_artifact,
                read_json(component / "artifacts/migrated-summary.json"),
            )

    def test_security_drill_summary_keeps_its_redacted_artifact_set(self) -> None:
        root = workspace_root()
        build_dir = root / "build"
        build_dir.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=build_dir) as directory:
            output = Path(directory)
            manifest = load_manifest(write_manifest(output), root, output)
            prepare_run_root(manifest)
            run_context = prepare_context(
                root,
                manifest,
                "security-response/drill-run-all",
            )
            verify_context = prepare_context(
                root,
                manifest,
                "security-response/drill-verify-all",
            )
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(
                    0,
                    legacy.execute(
                        run_context,
                        "security-response",
                        "drill-run-all",
                    ),
                )
                self.assertEqual(
                    0,
                    legacy.execute(
                        verify_context,
                        "security-response",
                        "drill-verify-all",
                    ),
                )
            summary = read_json(verify_context.component_dir / "artifacts/legacy-summary.json")
            self.assertEqual("pr", summary["mode"])
            self.assertTrue(summary["nonRelease"])
            self.assertFalse(summary["promotionReady"])
            artifact_names = {
                entry["artifact"]
                for entry in summary["artifacts"]
                if isinstance(entry, dict) and isinstance(entry.get("artifact"), str)
            }
            self.assertEqual(7, len(artifact_names))
            for name in artifact_names:
                self.assertTrue((verify_context.component_dir / "artifacts" / name).is_file())

            consumer_output = output / "consumer-output"
            consumer_manifest = load_manifest(
                write_manifest(
                    output / "consumer-manifest",
                    inputs={
                        "securityDrills": str(
                            verify_context.component_dir / "summary.json"
                        )
                    },
                ),
                root,
                consumer_output,
            )
            prepare_run_root(consumer_manifest)
            consumer_context = prepare_context(
                root,
                consumer_manifest,
                "release-certification",
            )

            extracted = legacy._legacy_input_path(consumer_context, "securityDrills")

            self.assertIsNotNone(extracted)
            for name in artifact_names:
                self.assertTrue((extracted.parent / name).is_file())

    def test_security_drill_verification_copies_its_configured_input_set(self) -> None:
        root = workspace_root()
        build_dir = root / "build"
        build_dir.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=build_dir) as directory:
            output = Path(directory)
            external_drills = output / "external-drills"
            external_summary = output / "external-summary.json"
            security_response_runbook.drill_run_all(
                security_response_runbook.DEFAULT_MODEL,
                external_drills,
                external_summary,
                release_id="self-test-release",
                mode="pr",
            )
            manifest = load_manifest(
                write_manifest(
                    output / "manifest",
                    commands={
                        "security-response": {
                            "args": [f"--input-dir={external_drills}"],
                        }
                    },
                ),
                root,
                output / "candidate-output",
            )
            prepare_run_root(manifest)
            context = prepare_context(
                root,
                manifest,
                "security-response/drill-verify-all",
            )

            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(
                    0,
                    legacy.execute(
                        context,
                        "security-response",
                        "drill-verify-all",
                    ),
                )

            summary = read_json(context.component_dir / "artifacts/legacy-summary.json")
            artifact_names = {
                entry["artifact"]
                for entry in summary["artifacts"]
                if isinstance(entry, dict) and isinstance(entry.get("artifact"), str)
            }
            self.assertEqual(7, len(artifact_names))
            self.assertFalse(
                (
                    context.run_root
                    / "security-response/drill-run-all/artifacts/legacy/drills"
                ).exists()
            )
            for name in artifact_names:
                self.assertEqual(
                    (external_drills / name).read_bytes(),
                    (context.component_dir / "artifacts" / name).read_bytes(),
                )

    def test_security_drill_sidecars_require_matching_digests(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            artifact_dir = source / "artifacts"
            artifact_path = artifact_dir / "drill.json"
            write_json(artifact_path, {"scenario": "redacted-drill", "status": "pass"})
            legacy_summary = {
                "schemaVersion": 1,
                "status": "pass",
                "redaction": {"status": "pass", "findings": []},
                "artifacts": [
                    {
                        "artifact": artifact_path.name,
                        "digest": f"sha256:{'0' * 64}",
                    }
                ],
            }
            envelope = EvidenceEnvelope(
                kind="production-security-response",
                generated_at="2026-01-01T00:00:00Z",
                subject={
                    "releaseId": "self-test-release",
                    "version": "self-test",
                    "profile": "pr",
                    "component": "security-response/drill-verify-all",
                },
                result={
                    "status": "pass",
                    "decision": None,
                    "promotionReady": None,
                    "exitCode": 0,
                },
                counts={"evidence": 0, "blockers": 0, "warnings": 0, "waivers": 0},
                redaction={
                    "status": "pass",
                    "findingCount": 0,
                    "findings": [],
                    "guarantees": {},
                },
                payload={"legacy": legacy_summary},
            ).to_json()
            envelope_path = source / "summary.json"
            write_json(envelope_path, envelope)
            manifest = load_manifest(
                write_manifest(root, inputs={"securityDrills": str(envelope_path)}),
                root,
            )
            prepare_run_root(manifest)
            context = prepare_context(root, manifest, "release-certification")

            with self.assertRaisesRegex(ValueError, "artifact digest mismatch"):
                legacy._legacy_input_path(context, "securityDrills")

            self.assertFalse((context.component_dir / "artifacts/inputs/drill.json").exists())

    def test_security_drill_sidecars_are_scanned_before_copying(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            artifact_dir = source / "artifacts"
            artifact_path = artifact_dir / "drill.json"
            write_json(
                artifact_path,
                {"scenario": "redacted-drill", "rawBody": "private message body"},
            )
            legacy_summary = {
                "schemaVersion": 1,
                "status": "pass",
                "redaction": {"status": "pass", "findings": []},
                "artifacts": [
                    {
                        "artifact": artifact_path.name,
                        "digest": security_response_runbook.sha256_path(artifact_path),
                    }
                ],
            }
            envelope = EvidenceEnvelope(
                kind="production-security-response",
                generated_at="2026-01-01T00:00:00Z",
                subject={
                    "releaseId": "self-test-release",
                    "version": "self-test",
                    "profile": "pr",
                    "component": "security-response/drill-verify-all",
                },
                result={
                    "status": "pass",
                    "decision": None,
                    "promotionReady": None,
                    "exitCode": 0,
                },
                counts={"evidence": 0, "blockers": 0, "warnings": 0, "waivers": 0},
                redaction={
                    "status": "pass",
                    "findingCount": 0,
                    "findings": [],
                    "guarantees": {},
                },
                payload={"legacy": legacy_summary},
            ).to_json()
            envelope_path = source / "summary.json"
            write_json(envelope_path, envelope)
            manifest = load_manifest(
                write_manifest(root, inputs={"securityDrills": str(envelope_path)}),
                root,
            )
            prepare_run_root(manifest)
            context = prepare_context(root, manifest, "release-certification")

            with self.assertRaisesRegex(ValueError, "artifact failed the v2 redaction scan"):
                legacy._legacy_input_path(context, "securityDrills")

            self.assertFalse((context.component_dir / "artifacts/inputs/drill.json").exists())


class StableRcOrchestrationIntegrationTest(unittest.TestCase):
    @staticmethod
    def _stable_vulnerability_inputs(root: Path) -> dict[str, str]:
        vulnerability = root / "stable-1.0-vulnerability-summary.json"
        supply_chain = root / "stable-1.0-supply-chain-summary.json"
        dependency = root / "stable-1.0-dependency-vulnerability-summary.json"
        for summary in (vulnerability, supply_chain, dependency):
            write_json(summary, {"schemaVersion": 1})
        return {
            "stableVulnerabilitySummary": str(vulnerability),
            "supplyChainPromotionSummary": str(supply_chain),
            "dependencyVulnerabilityPromotionSummary": str(dependency),
        }

    @staticmethod
    def _stable_rc_policies(**values: object) -> dict[str, object]:
        return {
            "candidateSourceCommit": "a" * 40,
            "candidateSourceRef": "commit:" + "a" * 40,
            "stableRcFreezeMode": "first-freeze",
            "stableVulnerabilityGovernance": "required",
            "stableSupplyChainGovernance": "required",
            "stableDependencyVulnerabilityGovernance": "required",
            **values,
        }

    @staticmethod
    def _stable_rc_requirements() -> dict[str, bool]:
        return {
            "stableVulnerability": True,
            "stableSupplyChain": True,
            "stableDependencyVulnerability": True,
        }

    @staticmethod
    def _write_production_envelope(
        path: Path,
        *,
        release_id: str = "stable-candidate",
        version: str = "283",
        profile: str = "stable-review",
    ) -> None:
        write_json(
            path,
            EvidenceEnvelope(
                kind="production-beta-release",
                generated_at="2026-01-01T00:00:00Z",
                subject={
                    "releaseId": release_id,
                    "version": version,
                    "profile": profile,
                    "component": "production-beta",
                },
                result={
                    "status": "pass",
                    "decision": "go",
                    "promotionReady": True,
                    "exitCode": 0,
                },
                counts={"evidence": 0, "blockers": 0, "warnings": 0, "waivers": 0},
                redaction={
                    "status": "pass",
                    "findingCount": 0,
                    "findings": [],
                    "guarantees": {},
                },
                payload={
                    "legacy": {
                        "schemaVersion": 1,
                        "releaseId": release_id,
                        "version": version,
                        "status": "pass",
                        "promotionReady": True,
                        "nonRelease": False,
                    }
                },
            ).to_json(),
        )

    def test_stable_rc_runs_production_beta_before_the_native_engine_when_missing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest_path = write_manifest(
                root,
                release={
                    "id": "stable-candidate",
                    "version": "283",
                    "profile": "stable-review",
                },
                requirements=self._stable_rc_requirements(),
                inputs=self._stable_vulnerability_inputs(root),
                policies=self._stable_rc_policies(),
            )

            with (
                mock.patch.object(cli, "_execute_component", return_value=1) as execute_component,
                mock.patch.object(cli, "execute_engine", return_value=1) as execute_engine,
                contextlib.redirect_stdout(io.StringIO()),
            ):
                code = cli.main(
                    [
                        "stable-rc",
                        "--manifest",
                        str(manifest_path),
                        "--workspace-root",
                        str(root),
                    ]
                )

            self.assertEqual(1, code)
            execute_component.assert_called_once()
            self.assertEqual("production-beta", execute_component.call_args.args[2])
            execute_engine.assert_called_once()
            context, command, action = execute_engine.call_args.args
            self.assertEqual("stable-rc", context.component)
            self.assertEqual("stable-rc", command)
            self.assertIsNone(action)

    def test_stable_rc_production_stage_uses_catalog_operations_artifact_timestamp(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact_timestamp = "2026-07-14T00:00:00Z"
            write_json(
                root / "catalog-operations.json",
                {"artifactTimestamp": artifact_timestamp},
            )
            manifest = load_manifest(
                write_manifest(
                    root,
                    release={
                        "id": "stable-candidate",
                        "version": "283",
                        "profile": "stable-review",
                    },
                    requirements=self._stable_rc_requirements(),
                    inputs={
                        "stableCatalogOperations": "catalog-operations.json",
                        **self._stable_vulnerability_inputs(root),
                    },
                    policies=self._stable_rc_policies(
                        artifactBaseUri="https://downloads.crypta.invalid/stable/",
                        catalogChannel="stable",
                    ),
                ),
                root,
            )
            prepare_run_root(manifest)
            context = prepare_context(root, manifest, "production-beta")
            captured: list[str] = []

            with mock.patch.object(
                production_beta_release,
                "main",
                side_effect=lambda arguments: captured.extend(arguments) or 0,
            ):
                legacy._run_production_beta(context)

            self.assertEqual(
                artifact_timestamp,
                captured[captured.index("--stable-rc-artifact-timestamp") + 1],
            )
            self.assertIn("--require-stable-vulnerability", captured)
            self.assertEqual(
                str((root / "stable-1.0-vulnerability-summary.json").resolve()),
                captured[captured.index("--stable-vulnerability-summary") + 1],
            )
            self.assertIn("--require-stable-supply-chain", captured)
            self.assertEqual(
                str((root / "stable-1.0-supply-chain-summary.json").resolve()),
                captured[captured.index("--stable-supply-chain-summary") + 1],
            )
            self.assertIn("--require-stable-dependency-vulnerability", captured)
            self.assertEqual(
                str(
                    (
                        root
                        / "stable-1.0-dependency-vulnerability-summary.json"
                    ).resolve()
                ),
                captured[
                    captured.index("--stable-dependency-vulnerability-summary")
                    + 1
                ],
            )
            self.assertEqual(
                "prepublication-evaluation",
                captured[
                    captured.index(
                        "--stable-dependency-vulnerability-evidence-phase"
                    )
                    + 1
                ],
            )
            self.assertEqual(
                "a" * 40,
                captured[
                    captured.index("--stable-governance-candidate-source-commit")
                    + 1
                ],
            )
            self.assertEqual(
                "commit:" + "a" * 40,
                captured[
                    captured.index("--stable-governance-candidate-source-ref")
                    + 1
                ],
            )

    def test_direct_stable_review_production_does_not_require_stable_rc_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = load_manifest(
                write_manifest(
                    root,
                    release={
                        "id": "stable-candidate",
                        "version": "283",
                        "profile": "stable-review",
                    },
                    policies={"catalogChannel": "stable"},
                ),
                root,
            )
            prepare_run_root(manifest)
            context = prepare_context(root, manifest, "production-beta")
            captured: list[str] = []

            with mock.patch.object(
                production_beta_release,
                "main",
                side_effect=lambda arguments: captured.extend(arguments) or 0,
            ):
                legacy._run_production_beta(context)

            self.assertNotIn("--stable-rc-artifact-timestamp", captured)

    def test_stable_rc_regenerates_existing_candidate_bound_production_envelope(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest_path = write_manifest(
                root,
                release={
                    "id": "stable-candidate",
                    "version": "283",
                    "profile": "stable-review",
                },
                requirements=self._stable_rc_requirements(),
                inputs=self._stable_vulnerability_inputs(root),
                policies=self._stable_rc_policies(),
            )
            manifest = load_manifest(manifest_path, root)
            run_root = prepare_run_root(manifest)
            summary = run_root / "production-beta/summary.json"
            summary.parent.mkdir()
            self._write_production_envelope(summary)

            with (
                mock.patch.object(cli, "_execute_component") as execute_component,
                mock.patch.object(cli, "execute_engine", return_value=0) as execute_engine,
                contextlib.redirect_stdout(io.StringIO()),
            ):
                code = cli.main(
                    [
                        "stable-rc",
                        "--manifest",
                        str(manifest_path),
                        "--workspace-root",
                        str(root),
                    ]
                )

            self.assertEqual(0, code)
            execute_component.assert_called_once()
            execute_engine.assert_called_once()

    def test_stable_rc_rejects_every_configured_same_run_input(self) -> None:
        same_run_inputs = (
            "productionBeta",
            "goNoGo",
            "appPlatform",
            "ecosystemMatrix",
            "releaseCertification",
            "stableReadiness",
        )
        for key in same_run_inputs:
            with self.subTest(key=key), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                manifest = load_manifest(
                    write_manifest(
                        root,
                        release={
                            "id": "stable-candidate",
                            "version": "283",
                            "profile": "stable-review",
                        },
                        requirements=self._stable_rc_requirements(),
                        inputs={
                            key: f"{key}.json",
                            **self._stable_vulnerability_inputs(root),
                        },
                        policies=self._stable_rc_policies(),
                    ),
                    root,
                )

                with self.assertRaisesRegex(ValueError, rf"inputs\.{key}"):
                    cli._validate_stable_rc_manifest(manifest)

    def test_stable_rc_requires_explicit_freeze_lineage_pairing(self) -> None:
        cases = (
            ("first-freeze", {}, None),
            (
                "first-freeze",
                {"previousStableRcFreeze": "previous-freeze.json"},
                "first-freeze mode cannot include",
            ),
            ("refreeze", {}, "refreeze mode requires"),
            (
                "refreeze",
                {"previousStableRcFreeze": "previous-freeze.json"},
                None,
            ),
        )
        for mode, inputs, expected_error in cases:
            with self.subTest(mode=mode, inputs=inputs), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                manifest = load_manifest(
                    write_manifest(
                        root,
                        release={
                            "id": "stable-candidate",
                            "version": "283",
                            "profile": "stable-review",
                        },
                        requirements=self._stable_rc_requirements(),
                        inputs={
                            **inputs,
                            **self._stable_vulnerability_inputs(root),
                        },
                        policies=self._stable_rc_policies(
                            stableRcFreezeMode=mode
                        ),
                    ),
                    root,
                )

                if expected_error is None:
                    cli._validate_stable_rc_manifest(manifest)
                else:
                    with self.assertRaisesRegex(ValueError, expected_error):
                        cli._validate_stable_rc_manifest(manifest)

    def test_stable_rc_requires_current_vulnerability_governance(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = load_manifest(
                write_manifest(
                    root,
                    release={
                        "id": "stable-candidate",
                        "version": "283",
                        "profile": "stable-review",
                    },
                    policies={"stableRcFreezeMode": "first-freeze"},
                ),
                root,
            )

            with self.assertRaisesRegex(
                ValueError,
                "current authenticated Stable vulnerability promotion handoff",
            ):
                cli._validate_stable_rc_manifest(manifest)

    def test_stable_rc_rejects_missing_or_unknown_freeze_mode(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = load_manifest(
                write_manifest(
                    root,
                    release={
                        "id": "stable-candidate",
                        "version": "283",
                        "profile": "stable-review",
                    },
                ),
                root,
            )

            with self.assertRaisesRegex(ValueError, "policies.stableRcFreezeMode"):
                cli._validate_stable_rc_manifest(manifest)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(ValueError, "stableRcFreezeMode"):
                load_manifest(
                    write_manifest(
                        root,
                        policies={"stableRcFreezeMode": "verify"},
                    ),
                    root,
                )

    def test_stable_rc_regenerates_wrong_candidate_internal_production_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest_path = write_manifest(
                root,
                release={
                    "id": "stable-candidate",
                    "version": "283",
                    "profile": "stable-review",
                },
                requirements=self._stable_rc_requirements(),
                inputs=self._stable_vulnerability_inputs(root),
                policies=self._stable_rc_policies(),
            )
            manifest = load_manifest(manifest_path, root)
            run_root = prepare_run_root(manifest)
            summary = run_root / "production-beta/summary.json"
            summary.parent.mkdir()
            self._write_production_envelope(summary, release_id="another-candidate")

            with (
                mock.patch.object(cli, "_execute_component", return_value=0) as execute_component,
                mock.patch.object(cli, "execute_engine", return_value=0),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                code = cli.main(
                    [
                        "stable-rc",
                        "--manifest",
                        str(manifest_path),
                        "--workspace-root",
                        str(root),
                    ]
                )

            self.assertEqual(0, code)
            execute_component.assert_called_once()

    def test_stable_rc_rejects_non_stable_profile_before_execution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest_path = write_manifest(
                root,
                release={
                    "id": "stable-candidate",
                    "version": "283",
                    "profile": "production-beta",
                },
                policies={"stableRcFreezeMode": "first-freeze"},
            )

            with (
                mock.patch.object(cli, "_execute_component") as execute_component,
                mock.patch.object(cli, "execute_engine") as execute_engine,
                contextlib.redirect_stderr(io.StringIO()),
            ):
                code = cli.main(
                    [
                        "stable-rc",
                        "--manifest",
                        str(manifest_path),
                        "--workspace-root",
                        str(root),
                    ]
                )

            self.assertEqual(2, code)
            execute_component.assert_not_called()
            execute_engine.assert_not_called()
            self.assertFalse((root / "build/release-certification/stable-candidate").exists())

    def test_stable_rc_rejects_noncanonical_integer_versions(self) -> None:
        for version in ("0", "00", "03", "+3", "3.0"):
            with self.subTest(version=version), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                manifest = load_manifest(
                    write_manifest(
                        root,
                        release={
                            "id": "stable-candidate",
                            "version": version,
                            "profile": "stable-review",
                        },
                        policies={"stableRcFreezeMode": "first-freeze"},
                    ),
                    root,
                )
                with self.assertRaisesRegex(ValueError, "canonical positive integer"):
                    cli._validate_stable_rc_manifest(manifest)


class AdapterIntegrationTest(unittest.TestCase):
    def test_runner_summary_outside_release_workspace_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = load_manifest(write_manifest(root), root)
            prepare_run_root(manifest)
            context = prepare_context(root, manifest, "app-platform")
            external_summary = root / "external-summary.json"
            write_json(
                external_summary,
                {
                    "schemaVersion": 1,
                    "status": "pass",
                    "redaction": {"status": "pass", "findings": []},
                },
            )

            with mock.patch.dict(
                legacy.RUNNERS,
                {
                    "app-platform": lambda _context: (
                        0,
                        external_summary,
                        None,
                    )
                },
            ):
                with self.assertRaisesRegex(ValueError, "outside release workspace"):
                    legacy.execute(context, "app-platform")

            self.assertFalse((context.component_dir / "summary.json").exists())
            self.assertFalse(
                (context.component_dir / "artifacts/legacy-summary.json").exists()
            )

    def test_multiply_linked_runner_summary_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = load_manifest(write_manifest(root), root)
            prepare_run_root(manifest)
            context = prepare_context(root, manifest, "app-platform")

            def write_multiply_linked_summary(
                configured: RunContext,
            ) -> tuple[int, Path, None]:
                output = legacy._legacy_dir(configured)
                summary = output / "summary.json"
                write_json(
                    summary,
                    {
                        "schemaVersion": 1,
                        "status": "pass",
                        "redaction": {"status": "pass", "findings": []},
                    },
                )
                (output / "summary-hardlink.json").hardlink_to(summary)
                return 0, summary, None

            with mock.patch.dict(
                legacy.RUNNERS,
                {"app-platform": write_multiply_linked_summary},
            ):
                with self.assertRaisesRegex(ValueError, "exactly one hard link"):
                    legacy.execute(context, "app-platform")

            self.assertFalse((context.component_dir / "summary.json").exists())
            self.assertFalse(
                (context.component_dir / "artifacts/legacy-summary.json").exists()
            )

    def test_symlinked_runner_summary_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = load_manifest(write_manifest(root), root)
            prepare_run_root(manifest)
            context = prepare_context(root, manifest, "app-platform")

            def write_symlinked_summary(
                configured: RunContext,
            ) -> tuple[int, Path, None]:
                output = legacy._legacy_dir(configured)
                target = output / "summary-target.json"
                summary = output / "summary.json"
                write_json(
                    target,
                    {
                        "schemaVersion": 1,
                        "status": "pass",
                        "redaction": {"status": "pass", "findings": []},
                    },
                )
                try:
                    summary.symlink_to(target)
                except OSError as exc:
                    self.skipTest(f"file symlinks are unavailable: {exc}")
                return 0, summary, None

            with mock.patch.dict(
                legacy.RUNNERS,
                {"app-platform": write_symlinked_summary},
            ):
                with self.assertRaisesRegex(ValueError, "must not be a symlink"):
                    legacy.execute(context, "app-platform")

            self.assertFalse((context.component_dir / "summary.json").exists())
            self.assertFalse(
                (context.component_dir / "artifacts/legacy-summary.json").exists()
            )

    def test_failed_fallback_scan_removes_raw_legacy_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = load_manifest(write_manifest(root), root)
            prepare_run_root(manifest)
            context = prepare_context(root, manifest, "app-platform")

            def write_unsafe_output(
                configured: RunContext,
            ) -> tuple[int, Path, Path]:
                output = legacy._legacy_dir(configured)
                summary = output / "summary.json"
                report = output / "report.md"
                write_json(
                    summary,
                    {
                        "schemaVersion": 1,
                        "status": "pass",
                        "promotionReady": True,
                        "operatorPath": "/home/alice/private-summary.json",
                    },
                )
                write_text(report, "password=hunter2")
                write_json(
                    output / "supporting-artifact.json",
                    {"formPassword": "hunter2"},
                )
                return 0, summary, report

            with mock.patch.dict(
                legacy.RUNNERS,
                {"app-platform": write_unsafe_output},
            ):
                self.assertEqual(1, legacy.execute(context, "app-platform"))

            self.assertFalse((context.component_dir / "artifacts/legacy").exists())
            envelope = read_json(context.component_dir / "summary.json")
            self.assertEqual("fail", envelope["result"]["status"])
            self.assertEqual("fail", envelope["redaction"]["status"])
            self.assertFalse(envelope["result"]["promotionReady"])
            self.assertEqual(
                "fail",
                envelope["payload"]["legacy"]["status"],
            )
            self.assertNotIn("operatorPath", envelope["payload"]["legacy"])
            for path in context.component_dir.rglob("*"):
                if path.is_file():
                    public_value = path.read_text(encoding="utf-8")
                    self.assertNotIn("hunter2", public_value)
                    self.assertNotIn("/home/alice", public_value)

    def test_symlinked_legacy_output_is_rejected_before_engine_execution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = load_manifest(write_manifest(root), root)
            prepare_run_root(manifest)
            context = prepare_context(root, manifest, "app-platform")
            external = root / "external-legacy-output"
            external.mkdir()
            legacy_output = context.component_dir / "artifacts/legacy"
            try:
                legacy_output.symlink_to(external, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"directory symlinks are unavailable: {exc}")

            with mock.patch.object(app_platform_smoke, "main") as engine:
                with self.assertRaisesRegex(ValueError, "legacy output path contains a symlink"):
                    legacy.execute(context, "app-platform")

            engine.assert_not_called()
            self.assertEqual([], list(external.iterdir()))

    def test_symlinked_extracted_input_directory_is_rejected_before_writing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            envelope = EvidenceEnvelope(
                kind="app-platform-smoke",
                generated_at="2026-01-01T00:00:00Z",
                subject={
                    "releaseId": "self-test-release",
                    "version": "self-test",
                    "profile": "pr",
                    "component": "app-platform",
                },
                result={
                    "status": "pass",
                    "decision": None,
                    "promotionReady": None,
                    "exitCode": 0,
                },
                counts={"evidence": 0, "blockers": 0, "warnings": 0, "waivers": 0},
                redaction={
                    "status": "pass",
                    "findingCount": 0,
                    "findings": [],
                    "guarantees": {},
                },
                payload={"legacy": {"schemaVersion": 1, "status": "pass"}},
            ).to_json()
            write_json(root / "app-platform-v2.json", envelope)
            manifest = load_manifest(
                write_manifest(
                    root,
                    inputs={"appPlatform": "app-platform-v2.json"},
                ),
                root,
            )
            prepare_run_root(manifest)
            context = prepare_context(root, manifest, "release-certification")
            external = root / "external-inputs"
            external.mkdir()
            input_dir = context.component_dir / "artifacts/inputs"
            try:
                input_dir.symlink_to(external, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"directory symlinks are unavailable: {exc}")

            with self.assertRaisesRegex(
                ValueError,
                "extracted input path contains a symlink",
            ):
                legacy._legacy_input_path(context, "appPlatform")

            self.assertEqual([], list(external.iterdir()))

    def test_attached_v2_payload_is_scanned_before_extraction(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            envelope = EvidenceEnvelope(
                kind="app-platform-smoke",
                generated_at="2026-01-01T00:00:00Z",
                subject={
                    "releaseId": "self-test-release",
                    "version": "self-test",
                    "profile": "pr",
                    "component": "app-platform",
                },
                result={
                    "status": "pass",
                    "decision": None,
                    "promotionReady": True,
                    "exitCode": 0,
                },
                counts={"evidence": 0, "blockers": 0, "warnings": 0, "waivers": 0},
                redaction={
                    "status": "pass",
                    "findingCount": 0,
                    "findings": [],
                    "guarantees": {},
                },
                payload={
                    "legacy": {
                        "schemaVersion": 1,
                        "status": "pass",
                        "headerValue": "Basic dXNlcjpwYXNzd29yZA==",
                    }
                },
            ).to_json()
            write_json(root / "app-platform-v2.json", envelope)
            manifest = load_manifest(
                write_manifest(
                    root,
                    inputs={"appPlatform": "app-platform-v2.json"},
                ),
                root,
            )
            prepare_run_root(manifest)
            context = prepare_context(root, manifest, "release-certification")

            with self.assertRaisesRegex(
                ValueError,
                r"inputs\.appPlatform payload\.legacy failed the v2 redaction scan",
            ):
                legacy._legacy_input_path(context, "appPlatform")

            self.assertFalse(
                (context.component_dir / "artifacts/inputs/appPlatform.json").exists()
            )

    def test_required_missing_history_reaches_the_release_gate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = load_manifest(
                write_manifest(
                    root,
                    release={
                        "id": "self-test-release",
                        "version": "self-test",
                        "profile": "release-candidate",
                    },
                    requirements={"history": True},
                ),
                root,
            )
            prepare_run_root(manifest)
            context = prepare_context(root, manifest, "release-certification")
            captured: list[str] = []

            def run(arguments: list[str]) -> int:
                captured.extend(arguments)
                out = Path(arguments[arguments.index("--out-dir") + 1])
                write_json(
                    out / "release-certification-summary.json",
                    {
                        "schemaVersion": 1,
                        "tool": "release-certification",
                        "status": "fail",
                        "blockers": ["required release history is missing"],
                        "redaction": {"status": "pass", "findings": []},
                    },
                )
                write_text(
                    out / "release-certification-report.md",
                    "# Release certification\n\nRequired release history is missing.\n",
                )
                return 1

            with mock.patch.object(release_certification, "main", side_effect=run):
                self.assertEqual(
                    1,
                    legacy.execute(context, "release-certification"),
                )

            previous = Path(captured[captured.index("--previous-summary") + 1])
            self.assertFalse(previous.exists())
            self.assertIn("--require-history", captured)
            envelope = read_json(context.component_dir / "summary.json")
            self.assertEqual("fail", envelope["result"]["status"])
            self.assertTrue((context.component_dir / "report.md").is_file())

    def test_release_adapter_preserves_the_shared_history_directory_default(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = load_manifest(
                write_manifest(
                    root,
                    execution={"writeHistory": True},
                ),
                root,
            )
            prepare_run_root(manifest)
            context = prepare_context(root, manifest, "release-certification")
            captured: list[str] = []

            with mock.patch.object(
                release_certification,
                "main",
                side_effect=lambda args: captured.extend(args) or 0,
            ):
                legacy._run_release_certification(context)

            self.assertIn("--write-history", captured)
            self.assertNotIn("--history-dir", captured)

    def test_release_adapter_forwards_exact_supply_chain_source_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_commit = "a" * 40
            source_ref = f"commit:{source_commit}"
            manifest = load_manifest(
                write_manifest(
                    root,
                    release={
                        "id": "stable-1-0-maintenance-301",
                        "version": "301",
                        "profile": "stable-review",
                    },
                    requirements={"stableSupplyChain": True},
                    policies={
                        "candidateSourceCommit": source_commit,
                        "candidateSourceRef": source_ref,
                    },
                ),
                root,
            )
            prepare_run_root(manifest)
            context = prepare_context(root, manifest, "release-certification")
            captured: list[str] = []

            with mock.patch.object(
                release_certification,
                "main",
                side_effect=lambda args: captured.extend(args) or 0,
            ):
                legacy._run_release_certification(context)

            commit_index = captured.index(
                "--stable-supply-chain-candidate-source-commit"
            )
            ref_index = captured.index("--stable-supply-chain-candidate-source-ref")
            self.assertEqual(captured[commit_index + 1], source_commit)
            self.assertEqual(captured[ref_index + 1], source_ref)

    def test_release_adapter_honors_an_explicit_history_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = load_manifest(
                write_manifest(
                    root,
                    policies={"historyDir": "build/shared-certification-history"},
                    execution={"writeHistory": True},
                ),
                root,
            )
            prepare_run_root(manifest)
            context = prepare_context(root, manifest, "release-certification")
            captured: list[str] = []

            with mock.patch.object(
                release_certification,
                "main",
                side_effect=lambda args: captured.extend(args) or 0,
            ):
                legacy._run_release_certification(context)

            history_dir_index = captured.index("--history-dir")
            self.assertEqual(
                (root / "build/shared-certification-history").resolve(),
                Path(captured[history_dir_index + 1]),
            )

    def test_live_network_safe_negative_redaction_fields_remain_reusable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = load_manifest(write_manifest(root), root)
            prepare_run_root(manifest)
            context = prepare_context(root, manifest, "live-network-beta")

            def write_safe_summary(arguments: list[str]) -> int:
                out = Path(arguments[arguments.index("--out-dir") + 1])
                write_json(
                    out / "summary.json",
                    {
                        "schemaVersion": 1,
                        "status": "warning",
                        "redaction": {
                            "status": "pass",
                            "findings": [],
                            "forbiddenPatternsChecked": True,
                            "rawBodiesStored": False,
                            "privateInsertUrisStored": False,
                            "localPathsStored": False,
                        },
                    },
                )
                return 0

            with mock.patch.object(
                live_network_beta_smoke,
                "main",
                side_effect=write_safe_summary,
            ):
                self.assertEqual(0, legacy.execute(context, "live-network-beta"))

            envelope = read_json(context.component_dir / "summary.json")
            self.assertEqual("warn", envelope["result"]["status"])
            self.assertEqual(0, envelope["result"]["exitCode"])
            self.assertEqual("pass", envelope["redaction"]["status"])
            self.assertTrue(
                envelope["redaction"]["guarantees"]["rawBodiesNotStored"]
            )
            consumer_manifest_root = root / "consumer-manifest"
            consumer_manifest_root.mkdir()
            consumer_manifest = load_manifest(
                write_manifest(
                    consumer_manifest_root,
                    inputs={"liveNetwork": str(context.component_dir / "summary.json")},
                ),
                root,
                root / "consumer-output",
            )
            prepare_run_root(consumer_manifest)
            consumer_context = prepare_context(
                root,
                consumer_manifest,
                "release-certification",
            )
            extracted = legacy._legacy_input_path(consumer_context, "liveNetwork")
            self.assertIsNotNone(extracted)
            self.assertEqual("warning", read_json(extracted)["status"])

    def test_component_input_rejects_a_nonzero_process_exit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            envelope = EvidenceEnvelope(
                kind="app-platform-smoke",
                generated_at="2026-01-01T00:00:00Z",
                subject={
                    "releaseId": "self-test-release",
                    "version": "self-test",
                    "profile": "pr",
                    "component": "app-platform",
                },
                result={
                    "status": "pass",
                    "decision": None,
                    "promotionReady": None,
                    "exitCode": 7,
                },
                counts={"evidence": 0, "blockers": 0, "warnings": 0, "waivers": 0},
                redaction={
                    "status": "pass",
                    "findingCount": 0,
                    "findings": [],
                    "guarantees": {},
                },
                payload={"legacy": {"schemaVersion": 1, "status": "pass"}},
            ).to_json()
            write_json(root / "app-platform-v2.json", envelope)
            manifest = load_manifest(
                write_manifest(
                    root,
                    inputs={"appPlatform": "app-platform-v2.json"},
                ),
                root,
            )
            prepare_run_root(manifest)
            context = prepare_context(root, manifest, "release-certification")

            with self.assertRaisesRegex(ValueError, "nonzero"):
                legacy._legacy_input_path(context, "appPlatform")

            self.assertFalse(
                (context.component_dir / "artifacts/inputs/appPlatform.json").exists()
            )

    def test_nightly_profile_reaches_the_nightly_release_policy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = load_manifest(
                write_manifest(
                    root,
                    release={
                        "id": "nightly-candidate",
                        "version": "self-test",
                        "profile": "nightly",
                    },
                ),
                root,
            )
            prepare_run_root(manifest)
            context = prepare_context(root, manifest, "release-certification")
            captured: list[str] = []

            with mock.patch.object(
                release_certification,
                "main",
                side_effect=lambda args: captured.extend(args) or 0,
            ):
                legacy._run_release_certification(context)

            self.assertEqual("nightly", captured[captured.index("--mode") + 1])

    def test_stable_review_uses_production_pipeline_policy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = load_manifest(
                write_manifest(
                    root,
                    release={
                        "id": "stable-review-candidate",
                        "version": "self-test",
                        "profile": "stable-review",
                    },
                ),
                root,
            )
            prepare_run_root(manifest)
            context = prepare_context(root, manifest, "stable-review-mode")

            for command in ("production-beta", "go-no-go"):
                with self.subTest(command=command):
                    self.assertEqual("production-beta", legacy._mode(context, command))

    def test_command_modes_cannot_override_the_manifest_release_policy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            commands = {
                command: {"mode": "pr"}
                for command in (
                    "app-platform",
                    "live-network-beta",
                    "release-certification",
                    "production-beta",
                    "go-no-go",
                )
            }
            manifest = load_manifest(
                write_manifest(
                    root,
                    release={
                        "id": "strict-candidate",
                        "version": "self-test",
                        "profile": "release-candidate",
                    },
                    commands=commands,
                ),
                root,
            )
            prepare_run_root(manifest)
            context = prepare_context(root, manifest, "mode-validation")

            for command in commands:
                with self.subTest(command=command):
                    with self.assertRaisesRegex(
                        ValueError,
                        rf"commands\.{command}\.mode cannot override release\.profile",
                    ):
                        legacy._mode(context, command)

    def test_security_drills_preserve_supported_non_release_profiles(self) -> None:
        for profile in ("pr", "nightly", "developer-dry-run"):
            with self.subTest(profile=profile), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                manifest = load_manifest(
                    write_manifest(
                        root,
                        release={
                            "id": f"{profile}-candidate",
                            "version": "self-test",
                            "profile": profile,
                        },
                    ),
                    root,
                )
                prepare_run_root(manifest)
                context = prepare_context(
                    root,
                    manifest,
                    "security-response/drill-run-all",
                )
                captured: list[str] = []

                with mock.patch.object(
                    security_response_runbook,
                    "main",
                    side_effect=lambda args: captured.extend(args) or 0,
                ):
                    legacy._run_passthrough(
                        context,
                        "security-response",
                        "drill-run-all",
                    )

                self.assertEqual(profile, captured[captured.index("--mode") + 1])

    def test_pr_app_platform_collection_skips_gradle_automatically(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = load_manifest(write_manifest(root), root)
            prepare_run_root(manifest)
            context = prepare_context(root, manifest, "app-platform")
            captured: list[str] = []

            with mock.patch.object(
                app_platform_smoke,
                "main",
                side_effect=lambda args: captured.extend(args) or 0,
            ):
                legacy._run_app_platform(context)

            self.assertEqual("pr", captured[captured.index("--mode") + 1])
            self.assertIn("--skip-gradle", captured)

    def test_multi_node_actions_use_the_structured_topology_config(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            topology = root / "release-topology.json"
            write_json(topology, {"topology": "release-specific"})
            manifest = load_manifest(
                write_manifest(
                    root,
                    inputs={"multiNodeSoakConfig": "release-topology.json"},
                    commands={
                        "multi-node-beta": {
                            "args": ["--config", "ignored-topology.json"]
                        }
                    },
                ),
                root,
            )
            prepare_run_root(manifest)

            for action in ("plan", "run"):
                with self.subTest(action=action):
                    context = prepare_context(root, manifest, f"multi-node-beta/{action}")
                    captured: list[str] = []
                    with mock.patch.object(
                        multi_node_beta_soak,
                        "main",
                        side_effect=lambda args: captured.extend(args) or 0,
                    ):
                        legacy._run_passthrough(context, "multi-node-beta", action)

                    self.assertEqual(1, captured.count("--config"))
                    config_index = captured.index("--config")
                    self.assertEqual(topology.resolve(), Path(captured[config_index + 1]))
                    self.assertNotIn("ignored-topology.json", captured)

    def test_required_live_multi_node_run_fails_without_reachable_nodes(self) -> None:
        cases = (
            ("configured-live", "live", None),
            ("overridden-live", "simulated", "live"),
        )
        for name, config_mode, override_mode in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                topology = root / "release-topology.json"
                config = multi_node_beta_soak.load_config(None)
                config["mode"] = config_mode
                write_json(topology, config)
                command = {} if override_mode is None else {"mode": override_mode}
                manifest = load_manifest(
                    write_manifest(
                        root,
                        requirements={"multiNodeSoak": True},
                        inputs={"multiNodeSoakConfig": topology.name},
                        commands={"multi-node-beta": command},
                    ),
                    root,
                )
                prepare_run_root(manifest)
                context = prepare_context(root, manifest, "multi-node-beta/run")

                self.assertEqual(
                    1,
                    legacy.execute(context, "multi-node-beta", "run"),
                )

                envelope = read_json(context.component_dir / "summary.json")
                self.assertEqual("fail", envelope["result"]["status"])
                self.assertIn(
                    "live mode required at least one reachable localhost node",
                    envelope["payload"]["legacy"]["blockers"],
                )

    def test_multi_node_plan_ignores_external_output_arguments(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            external_plan = root / "external-plan.json"
            external_report = root / "external-report.md"
            external_dir = root / "external-output"
            manifest = load_manifest(
                write_manifest(
                    root,
                    commands={
                        "multi-node-beta": {
                            "args": [
                                f"--out={external_plan}",
                                "--report",
                                str(external_report),
                                "--out-dir",
                                str(external_dir),
                            ]
                        }
                    },
                ),
                root,
            )
            prepare_run_root(manifest)
            context = prepare_context(root, manifest, "multi-node-beta/plan")
            captured: list[str] = []

            def generate_plan(args: list[str]) -> int:
                captured.extend(args)
                output = Path(args[args.index("--out") + 1])
                write_json(
                    output,
                    {
                        "status": "pass",
                        "planMarker": "candidate-scoped-plan",
                        "redaction": {"status": "pass", "findings": []},
                    },
                )
                return 0

            with mock.patch.object(
                multi_node_beta_soak,
                "main",
                side_effect=generate_plan,
            ):
                self.assertEqual(0, legacy.execute(context, "multi-node-beta", "plan"))

            scoped_plan = context.component_dir / "artifacts/legacy/plan.json"
            self.assertEqual(scoped_plan, Path(captured[captured.index("--out") + 1]))
            self.assertNotIn("--report", captured)
            self.assertNotIn("--out-dir", captured)
            self.assertFalse(external_plan.exists())
            self.assertFalse(external_report.exists())
            self.assertFalse(external_dir.exists())
            envelope = read_json(context.component_dir / "summary.json")
            self.assertEqual(
                "candidate-scoped-plan",
                envelope["payload"]["legacy"]["planMarker"],
            )

    def test_abbreviated_controlled_output_option_is_rejected_before_execution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            escaped_plan = root / "escaped-plan.json"
            manifest = load_manifest(
                write_manifest(
                    root,
                    commands={
                        "multi-node-beta": {
                            "args": ["--ou", str(escaped_plan)],
                        }
                    },
                ),
                root,
            )
            prepare_run_root(manifest)
            context = prepare_context(root, manifest, "multi-node-beta/plan")

            with mock.patch.object(multi_node_beta_soak, "main") as engine:
                with self.assertRaisesRegex(
                    ValueError,
                    "abbreviated controlled option: --ou",
                ):
                    legacy._run_passthrough(context, "multi-node-beta", "plan")

            engine.assert_not_called()
            self.assertFalse(escaped_plan.exists())

    def test_abbreviated_controlled_options_are_rejected_for_every_adapter(self) -> None:
        cases = {
            "app-platform": "--work",
            "live-network-beta": "--out-d",
            "multi-node-beta": "--conf",
            "security-response": "--summary-o",
            "release-certification": "--mo",
            "production-beta": "--release-i",
            "go-no-go": "--waiv",
            "stable-readiness": "--pol",
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = load_manifest(
                write_manifest(
                    root,
                    commands={
                        command: {"args": [abbreviation, "controlled-value"]}
                        for command, abbreviation in cases.items()
                    },
                ),
                root,
            )
            prepare_run_root(manifest)
            context = prepare_context(root, manifest, "abbreviation-validation")

            for command, abbreviation in cases.items():
                with self.subTest(command=command, abbreviation=abbreviation):
                    with self.assertRaisesRegex(
                        ValueError,
                        rf"abbreviated controlled option: {abbreviation}",
                    ):
                        legacy._args(context, command)

    def test_alternate_evidence_sources_are_reserved_from_passthrough_args(self) -> None:
        commands = {
            "release-certification": {
                "args": [
                    "--security-response-summary",
                    "unbound-security.json",
                    "--stable-1-0-readiness-summary=unbound-stable.json",
                ]
            },
            "go-no-go": {
                "args": [
                    "--fixtures",
                    "go-no-go-pass.json",
                    "--security-response-summary=unbound-security.json",
                    "--stable-1-0-readiness-summary",
                    "unbound-stable.json",
                ]
            },
            "stable-readiness": {
                "args": ["--multi-node-soak-summary=unbound-soak.json"]
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = load_manifest(write_manifest(root, commands=commands), root)
            prepare_run_root(manifest)
            context = prepare_context(root, manifest, "alternate-input-validation")

            for command in commands:
                with self.subTest(command=command):
                    self.assertEqual([], legacy._args(context, command))

    def test_security_drill_run_ignores_external_output_arguments(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            external_dir = root / "external-drills"
            external_summary = root / "external-summary.json"
            external_notes = root / "external-notes.md"
            manifest = load_manifest(
                write_manifest(
                    root,
                    commands={
                        "security-response": {
                            "args": [
                                "--out-dir",
                                str(external_dir),
                                f"--summary-out={external_summary}",
                                "--release-notes-out",
                                str(external_notes),
                            ]
                        }
                    },
                ),
                root,
            )
            prepare_run_root(manifest)
            context = prepare_context(root, manifest, "security-response/drill-run-all")
            captured: list[str] = []

            def generate_summary(args: list[str]) -> int:
                captured.extend(args)
                output = Path(args[args.index("--summary-out") + 1])
                write_json(
                    output,
                    {
                        "status": "pass",
                        "releaseId": "self-test-release",
                        "summaryMarker": "candidate-scoped-security-summary",
                        "redaction": {"status": "pass", "findings": []},
                    },
                )
                return 0

            with mock.patch.object(
                security_response_runbook,
                "main",
                side_effect=generate_summary,
            ):
                self.assertEqual(
                    0,
                    legacy.execute(
                        context,
                        "security-response",
                        "drill-run-all",
                    ),
                )

            scoped = context.component_dir / "artifacts/legacy"
            self.assertEqual(scoped / "drills", Path(captured[captured.index("--out-dir") + 1]))
            self.assertEqual(
                scoped / "summary.json",
                Path(captured[captured.index("--summary-out") + 1]),
            )
            self.assertEqual(
                scoped / "security-release-notes-draft.md",
                Path(captured[captured.index("--release-notes-out") + 1]),
            )
            self.assertFalse(external_dir.exists())
            self.assertFalse(external_summary.exists())
            self.assertFalse(external_notes.exists())
            envelope = read_json(context.component_dir / "summary.json")
            self.assertEqual(
                "candidate-scoped-security-summary",
                envelope["payload"]["legacy"]["summaryMarker"],
            )

    def test_release_adapter_unwraps_candidate_bound_migrated_history(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            migrated = root / "history-v2.json"
            legacy_history = {
                "schemaVersion": 1,
                "tool": "release-certification",
                "status": "pass",
                "evidence": [{"id": "interop.smoke", "status": "pass"}],
                "redaction": {"status": "pass", "findings": []},
            }
            write_json(
                migrated,
                {
                    "schemaVersion": 2,
                    "kind": "migrated-v1-release-history",
                    "generatedAt": "2026-01-01T00:00:00Z",
                    "subject": {
                        "releaseId": "self-test-release",
                        "version": "self-test",
                        "profile": "pr",
                        "component": "migration/release-history",
                    },
                    "result": {
                        "status": "pass",
                        "decision": None,
                        "promotionReady": None,
                        "exitCode": 0,
                    },
                    "counts": {"evidence": 1, "blockers": 0, "warnings": 0, "waivers": 0},
                    "evidence": [{"id": "interop.smoke", "status": "pass"}],
                    "issues": {"blockers": [], "warnings": []},
                    "waivers": [],
                    "redaction": {"status": "pass", "findingCount": 0, "findings": [], "guarantees": {}},
                    "inputs": {},
                    "artifacts": {},
                    "payload": {"legacy": legacy_history},
                },
            )
            manifest = load_manifest(
                write_manifest(
                    root,
                    requirements={"history": True},
                    inputs={"releaseHistory": "history-v2.json"},
                ),
                root,
            )
            prepare_run_root(manifest)
            context = prepare_context(root, manifest, "release-certification")
            captured: list[str] = []

            def run(arguments: list[str]) -> int:
                captured.extend(arguments)
                return 0

            with mock.patch.object(release_certification, "main", side_effect=run):
                legacy._run_release_certification(context)

            history_path = Path(captured[captured.index("--previous-summary") + 1])
            self.assertEqual(legacy_history, read_json(history_path))
            self.assertIn("--require-history", captured)

    def test_stable_adapter_accepts_warning_go_no_go_evidence_for_waiver_evaluation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            legacy_dashboard = {
                "schemaVersion": 1,
                "releaseId": "self-test-release",
                "decision": "go-with-waivers",
                "status": "warn",
                "waiversUsed": [{"id": "accepted-waiver"}],
            }
            envelope = EvidenceEnvelope(
                kind="production-beta-go-no-go",
                generated_at="2026-01-01T00:00:00Z",
                subject={
                    "releaseId": "self-test-release",
                    "version": "self-test",
                    "profile": "stable-review",
                    "component": "go-no-go",
                },
                result={
                    "status": "warn",
                    "decision": "go-with-waivers",
                    "promotionReady": True,
                    "exitCode": 0,
                },
                counts={"evidence": 0, "blockers": 0, "warnings": 0, "waivers": 1},
                waivers=[{"id": "accepted-waiver"}],
                redaction={
                    "status": "pass",
                    "findingCount": 0,
                    "findings": [],
                    "guarantees": {},
                },
                payload={"legacy": legacy_dashboard},
            ).to_json()
            write_json(root / "go-no-go-v2.json", envelope)
            manifest = load_manifest(
                write_manifest(
                    root,
                    release={
                        "id": "self-test-release",
                        "version": "self-test",
                        "profile": "stable-review",
                    },
                    inputs={"goNoGo": "go-no-go-v2.json"},
                ),
                root,
            )
            prepare_run_root(manifest)
            context = prepare_context(root, manifest, "stable-readiness")
            captured: list[str] = []

            with mock.patch.object(
                stable_1_0_readiness,
                "main",
                side_effect=lambda args: captured.extend(args) or 0,
            ):
                legacy._run_stable_readiness(context)

            extracted = Path(captured[captured.index("--go-no-go-summary") + 1])
            self.assertEqual(legacy_dashboard, read_json(extracted))

    def test_stable_adapter_preserves_v2_multi_node_candidate_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            release_id = "cryptad-candidate-custom"
            legacy_soak = {
                "schemaVersion": 1,
                "status": "pass",
                "currentCandidate": {"version": "3"},
            }
            envelope = EvidenceEnvelope(
                kind="multi-node-beta-soak",
                generated_at="2026-01-01T00:00:00Z",
                subject={
                    "releaseId": release_id,
                    "version": "3",
                    "profile": "stable-review",
                    "component": "multi-node-beta/run",
                },
                result={
                    "status": "pass",
                    "decision": None,
                    "promotionReady": True,
                    "exitCode": 0,
                },
                counts={"evidence": 0, "blockers": 0, "warnings": 0, "waivers": 0},
                redaction={
                    "status": "pass",
                    "findingCount": 0,
                    "findings": [],
                    "guarantees": {},
                },
                payload={"legacy": legacy_soak},
            ).to_json()
            write_json(root / "multi-node-v2.json", envelope)
            manifest = load_manifest(
                write_manifest(
                    root,
                    release={
                        "id": release_id,
                        "version": "3",
                        "profile": "stable-review",
                    },
                    inputs={"multiNodeSoak": "multi-node-v2.json"},
                ),
                root,
            )
            prepare_run_root(manifest)
            context = prepare_context(root, manifest, "stable-readiness")
            captured: list[str] = []

            with mock.patch.object(
                stable_1_0_readiness,
                "main",
                side_effect=lambda args: captured.extend(args) or 0,
            ):
                legacy._run_stable_readiness(context)

            extracted = Path(
                captured[captured.index("--multi-node-beta-soak-summary") + 1]
            )
            extracted_soak = read_json(extracted)
            self.assertEqual(release_id, extracted_soak["releaseId"])
            self.assertEqual(
                [("releaseId", release_id)],
                stable_1_0_readiness.multi_node_candidate_release_ids(extracted_soak),
            )

    def test_every_v2_component_input_requires_its_mapped_kind(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inputs: dict[str, str] = {}
            for key in legacy.V2_KIND_BY_INPUT:
                path = root / f"{key}.json"
                inputs[key] = path.name
                write_json(
                    path,
                    EvidenceEnvelope(
                        kind="wrong-kind",
                        generated_at="2026-01-01T00:00:00Z",
                        subject={
                            "releaseId": "self-test-release",
                            "version": "self-test",
                            "profile": "pr",
                            "component": "wrong",
                        },
                        result={
                            "status": "pass",
                            "decision": None,
                            "promotionReady": None,
                            "exitCode": 0,
                        },
                        counts={"evidence": 0, "blockers": 0, "warnings": 0, "waivers": 0},
                        redaction={
                            "status": "pass",
                            "findingCount": 0,
                            "findings": [],
                            "guarantees": {},
                        },
                        payload={"legacy": {}},
                    ).to_json(),
                )
            manifest = load_manifest(write_manifest(root, inputs=inputs), root)
            prepare_run_root(manifest)
            context = prepare_context(root, manifest, "kind-validation")

            for key, expected_kind in legacy.V2_KIND_BY_INPUT.items():
                with self.subTest(key=key):
                    with self.assertRaisesRegex(ValueError, f"expected evidence kind {expected_kind}"):
                        legacy._legacy_input_path(context, key)

    def test_v2_component_inputs_reject_incompatible_subjects(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def envelope(**subject_overrides: object) -> dict[str, object]:
                subject: dict[str, object] = {
                    "releaseId": "self-test-release",
                    "version": "candidate-version",
                    "profile": "release-candidate",
                    "component": "app-platform",
                }
                subject.update(subject_overrides)
                return EvidenceEnvelope(
                    kind="app-platform-smoke",
                    generated_at="2026-01-01T00:00:00Z",
                    subject=subject,
                    result={
                        "status": "pass",
                        "decision": None,
                        "promotionReady": True,
                        "exitCode": 0,
                    },
                    counts={"evidence": 0, "blockers": 0, "warnings": 0, "waivers": 0},
                    redaction={
                        "status": "pass",
                        "findingCount": 0,
                        "findings": [],
                        "guarantees": {},
                    },
                    payload={"legacy": {"schemaVersion": 1, "status": "pass"}},
                ).to_json()

            manifest = load_manifest(
                write_manifest(
                    root,
                    release={
                        "id": "self-test-release",
                        "version": "candidate-version",
                        "profile": "release-candidate",
                    },
                    inputs={"appPlatform": "app-platform-v2.json"},
                ),
                root,
            )
            prepare_run_root(manifest)
            context = prepare_context(root, manifest, "release-certification")
            invalid_subjects = (
                (
                    {"profile": "developer-dry-run"},
                    "evidence profile developer-dry-run is incompatible",
                ),
                ({"version": "another-version"}, "evidence version does not match"),
                ({"component": "go-no-go"}, "evidence component must be app-platform"),
            )

            for subject_overrides, expected_error in invalid_subjects:
                with self.subTest(subject_overrides=subject_overrides):
                    write_json(root / "app-platform-v2.json", envelope(**subject_overrides))
                    with self.assertRaisesRegex(ValueError, expected_error):
                        legacy._legacy_input_path(context, "appPlatform")

            self.assertFalse(
                (context.component_dir / "artifacts/inputs/appPlatform.json").exists()
            )

    def test_strict_v2_component_inputs_require_a_manifest_version(self) -> None:
        for profile in ("release-candidate", "production-beta", "stable-review"):
            with self.subTest(profile=profile), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                write_json(
                    root / "app-platform-v2.json",
                    EvidenceEnvelope(
                        kind="app-platform-smoke",
                        generated_at="2026-01-01T00:00:00Z",
                        subject={
                            "releaseId": "self-test-release",
                            "version": "candidate-version",
                            "profile": profile,
                            "component": "app-platform",
                        },
                        result={
                            "status": "pass",
                            "decision": None,
                            "promotionReady": True,
                            "exitCode": 0,
                        },
                        counts={
                            "evidence": 0,
                            "blockers": 0,
                            "warnings": 0,
                            "waivers": 0,
                        },
                        redaction={
                            "status": "pass",
                            "findingCount": 0,
                            "findings": [],
                            "guarantees": {},
                        },
                        payload={"legacy": {"schemaVersion": 1, "status": "pass"}},
                    ).to_json(),
                )
                manifest = load_manifest(
                    write_manifest(
                        root,
                        release={
                            "id": "self-test-release",
                            "version": None,
                            "profile": profile,
                        },
                        inputs={"appPlatform": "app-platform-v2.json"},
                    ),
                    root,
                )
                prepare_run_root(manifest)
                context = prepare_context(root, manifest, "strict-version-validation")

                with self.assertRaisesRegex(
                    ValueError,
                    rf"inputs\.appPlatform requires release\.version for strict "
                    rf"release\.profile {profile}",
                ):
                    legacy._legacy_input_path(context, "appPlatform")

                self.assertFalse(
                    (context.component_dir / "artifacts/inputs/appPlatform.json").exists()
                )

    def test_non_strict_v2_input_allows_an_undeclared_manifest_version(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            legacy_payload = {"schemaVersion": 1, "status": "pass"}
            write_json(
                root / "app-platform-v2.json",
                EvidenceEnvelope(
                    kind="app-platform-smoke",
                    generated_at="2026-01-01T00:00:00Z",
                    subject={
                        "releaseId": "self-test-release",
                        "version": "developer-version",
                        "profile": "developer-dry-run",
                        "component": "app-platform",
                    },
                    result={
                        "status": "pass",
                        "decision": None,
                        "promotionReady": False,
                        "exitCode": 0,
                    },
                    counts={"evidence": 0, "blockers": 0, "warnings": 0, "waivers": 0},
                    redaction={
                        "status": "pass",
                        "findingCount": 0,
                        "findings": [],
                        "guarantees": {},
                    },
                    payload={"legacy": legacy_payload},
                ).to_json(),
            )
            manifest = load_manifest(
                write_manifest(
                    root,
                    release={
                        "id": "self-test-release",
                        "version": None,
                        "profile": "developer-dry-run",
                    },
                    inputs={"appPlatform": "app-platform-v2.json"},
                ),
                root,
            )
            prepare_run_root(manifest)
            context = prepare_context(root, manifest, "developer-version-validation")

            extracted = legacy._legacy_input_path(context, "appPlatform")

            self.assertIsNotNone(extracted)
            self.assertEqual(legacy_payload, read_json(extracted))

    def test_v2_component_inputs_allow_documented_profile_transitions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)

            def write_envelope(
                path: Path,
                *,
                kind: str,
                profile: str,
                component: str,
            ) -> None:
                write_json(
                    path,
                    EvidenceEnvelope(
                        kind=kind,
                        generated_at="2026-01-01T00:00:00Z",
                        subject={
                            "releaseId": "self-test-release",
                            "version": "candidate-version",
                            "profile": profile,
                            "component": component,
                        },
                        result={
                            "status": "pass",
                            "decision": None,
                            "promotionReady": True,
                            "exitCode": 0,
                        },
                        counts={"evidence": 0, "blockers": 0, "warnings": 0, "waivers": 0},
                        redaction={
                            "status": "pass",
                            "findingCount": 0,
                            "findings": [],
                            "guarantees": {},
                        },
                        payload={"legacy": {"schemaVersion": 1, "status": "pass"}},
                    ).to_json(),
                )

            production_path = root / "production-v2.json"
            write_envelope(
                production_path,
                kind="production-beta-release",
                profile="production-beta",
                component="production-beta",
            )
            stable_path = root / "stable-v2.json"
            write_envelope(
                stable_path,
                kind="stable-1.0-readiness",
                profile="stable-review",
                component="stable-readiness",
            )
            cases = (
                ("stable-review", "productionBeta", production_path.name),
                ("release-candidate", "stableReadiness", stable_path.name),
                ("production-beta", "stableReadiness", stable_path.name),
            )

            for profile, key, input_path in cases:
                with self.subTest(profile=profile, key=key):
                    output_root = root / f"output-{profile}-{key}"
                    manifest = load_manifest(
                        write_manifest(
                            root,
                            release={
                                "id": "self-test-release",
                                "version": "candidate-version",
                                "profile": profile,
                            },
                            output={"root": str(output_root), "reset": False},
                            inputs={key: input_path},
                        ),
                        root,
                    )
                    prepare_run_root(manifest)
                    context = prepare_context(root, manifest, f"consumer-{profile}-{key}")

                    self.assertIsNotNone(legacy._legacy_input_path(context, key))

    def test_v2_component_inputs_reject_raw_v1_summaries(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inputs: dict[str, str] = {}
            for key in legacy.V2_KIND_BY_INPUT:
                path = root / f"{key}.json"
                inputs[key] = path.name
                write_json(path, {"schemaVersion": 1, "status": "pass"})
            manifest = load_manifest(write_manifest(root, inputs=inputs), root)
            prepare_run_root(manifest)
            context = prepare_context(root, manifest, "v1-rejection")

            for key, expected_kind in legacy.V2_KIND_BY_INPUT.items():
                with self.subTest(key=key):
                    with self.assertRaisesRegex(
                        ValueError,
                        rf"inputs\.{key} must be a v2 {expected_kind} evidence envelope",
                    ):
                        legacy._legacy_input_path(context, key)

    def test_explicit_external_and_non_envelope_inputs_retain_v1_support(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inputs: dict[str, str] = {}
            for key in (
                "ecosystemMatrix",
                "interopSmoke",
                "interopExtended",
                "performanceSmoke",
                "thirdPartyIntake",
            ):
                path = root / f"{key}.json"
                inputs[key] = path.name
                write_json(path, {"schemaVersion": 1, "status": "success"})
            manifest = load_manifest(write_manifest(root, inputs=inputs), root)
            prepare_run_root(manifest)
            context = prepare_context(root, manifest, "external-v1-inputs")

            for key, relative_path in inputs.items():
                with self.subTest(key=key):
                    self.assertEqual(
                        (root / relative_path).resolve(),
                        legacy._legacy_input_path(context, key),
                    )

    def test_production_adapter_propagates_structured_manifest_fields(self) -> None:
        root = workspace_root()
        build_dir = root / "build"
        build_dir.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=build_dir) as directory:
            output = Path(directory)
            reviewed_known_issues = output / "reviewed-public-beta-known-issues.json"
            write_json(reviewed_known_issues, {"schemaVersion": 1, "knownIssues": []})
            manifest = load_manifest(
                write_manifest(
                    output,
                    release={"id": "candidate-id", "version": None, "profile": "developer-dry-run"},
                    policies={
                        "artifactBaseUri": "https://downloads.crypta.invalid/candidate/",
                        "catalogChannel": "beta",
                    },
                    requirements={"liveNetwork": True, "sandboxProviderTests": True},
                    inputs={
                        "publicBetaKnownIssues": reviewed_known_issues.relative_to(root).as_posix()
                    },
                    execution={
                        "fixtureEvidence": True,
                        "skipGradle": True,
                        "skipFullBuild": True,
                        "timeoutSeconds": 75,
                    },
                    commands={
                        "production-beta": {
                            "args": [
                                "--previous-summary",
                                "unsafe-v1.json",
                                "--multi-node-mode",
                                "simulated",
                            ]
                        }
                    },
                ),
                root,
                output,
            )
            prepare_run_root(manifest)
            context = prepare_context(root, manifest, "production-beta")
            captured: list[str] = []

            def run(arguments: list[str]) -> int:
                captured.extend(arguments)
                return 0

            with mock.patch.object(production_beta_release, "main", side_effect=run):
                legacy._run_production_beta(context)

            self.assertEqual("candidate-id", captured[captured.index("--release-id") + 1])
            self.assertEqual("beta", captured[captured.index("--catalog-channel") + 1])
            self.assertEqual(
                "https://downloads.crypta.invalid/candidate/",
                captured[captured.index("--artifact-base-uri") + 1],
            )
            for option in (
                "--require-live-network",
                "--require-sandbox-provider-tests",
                "--use-fixture-evidence",
                "--skip-gradle",
                "--skip-full-build",
            ):
                self.assertIn(option, captured)
            self.assertEqual("75", captured[captured.index("--timeout-seconds") + 1])
            self.assertEqual(
                reviewed_known_issues.resolve(),
                Path(captured[captured.index("--public-beta-known-issues") + 1]),
            )
            self.assertNotIn("unsafe-v1.json", captured)
            self.assertEqual("simulated", captured[captured.index("--multi-node-mode") + 1])

    def test_dashboard_and_stable_adapters_propagate_summary_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            input_contracts = {
                "production.json": ("production-beta-release", "production-beta"),
                "dashboard.json": ("production-beta-go-no-go", "go-no-go"),
                "certification.json": ("release-certification", "release-certification"),
            }
            for name, (kind, component) in input_contracts.items():
                write_json(
                    root / name,
                    EvidenceEnvelope(
                        kind=kind,
                        generated_at="2026-01-01T00:00:00Z",
                        subject={
                            "releaseId": "self-test-release",
                            "version": "self-test",
                            "profile": "pr",
                            "component": component,
                        },
                        result={
                            "status": "pass",
                            "decision": None,
                            "promotionReady": None,
                            "exitCode": 0,
                        },
                        counts={
                            "evidence": 0,
                            "blockers": 0,
                            "warnings": 0,
                            "waivers": 0,
                        },
                        redaction={
                            "status": "pass",
                            "findingCount": 0,
                            "findings": [],
                            "guarantees": {},
                        },
                        payload={"legacy": {"schemaVersion": 1, "status": "pass"}},
                    ).to_json(),
                )
            manifest = load_manifest(
                write_manifest(
                    root,
                    inputs={
                        "productionBeta": "production.json",
                        "goNoGo": "dashboard.json",
                        "releaseCertification": "certification.json",
                    },
                ),
                root,
            )
            prepare_run_root(manifest)
            dashboard_context = prepare_context(root, manifest, "go-no-go")
            stable_context = prepare_context(root, manifest, "stable-readiness")
            dashboard_args: list[str] = []
            stable_args: list[str] = []
            with mock.patch.object(
                production_beta_go_no_go_dashboard,
                "main",
                side_effect=lambda args: dashboard_args.extend(args) or 0,
            ):
                legacy._run_go_no_go(dashboard_context)
            with mock.patch.object(
                stable_1_0_readiness,
                "main",
                side_effect=lambda args: stable_args.extend(args) or 0,
            ):
                legacy._run_stable_readiness(stable_context)
            self.assertIn("--production-beta-summary", dashboard_args)
            self.assertIn("--release-certification-summary", dashboard_args)
            self.assertIn("--production-beta-summary", stable_args)
            self.assertIn("--go-no-go-summary", stable_args)
            self.assertIn("--release-certification-summary", stable_args)


class WorkflowIntegrationTest(unittest.TestCase):
    def test_stable_rc_workflow_binds_reviewed_issues_and_previous_freeze(self) -> None:
        workflow = (
            workspace_root() / ".github/workflows/stable-1.0-rc-release.yml"
        ).read_text(encoding="utf-8")

        self.assertIn(
            '_option_path(\n        args,\n        "--public-beta-known-issues"',
            (workspace_root() / "tools/release-certification/cryptad_certification/legacy.py").read_text(
                encoding="utf-8"
            ),
        )
        self.assertIn('"comparisonBaseline",', workflow)
        self.assertIn('provenance_inputs.get("previousStableRcFreeze")', workflow)
        self.assertIn('drift.get("comparisonBaseline")', workflow)
        self.assertIn("stable_rc_freeze_mode:", workflow)
        self.assertIn("GITHUB_RUN_ATTEMPT", workflow)
        self.assertIn("latest_successful_run_id", workflow)
        self.assertIn("latest_successful_head_sha", workflow)
        self.assertIn("verify_latest_refreeze_parent", workflow)
        self.assertIn("verify_refreeze_lineage_anchor", workflow)
        self.assertIn("checks: write", workflow)
        self.assertIn(
            '"repos/$GITHUB_REPOSITORY/actions/runs/$candidate_run_id/attempts/$attempt"',
            workflow,
        )
        self.assertIn('.conclusion == "success"', workflow)
        self.assertIn(
            '.path == $workflow_path or (.path | startswith($workflow_path + "@"))',
            workflow,
        )
        self.assertIn(
            'cmp --silent "$supplied_freeze" "${authenticated_freezes[0]}"',
            workflow,
        )
        self.assertIn('if ! gh run download "$run_id"', workflow)
        self.assertIn(
            '"repos/$GITHUB_REPOSITORY/commits/$parent_sha/check-runs"',
            workflow,
        )
        self.assertIn('.app.slug == "github-actions"', workflow)
        self.assertIn(
            "Persist authenticated Stable RC freeze lineage",
            workflow,
        )
        failure_closeout = workflow[workflow.index("\n  retain-failure-closeout:") :]
        stable_rc_job = workflow[
            workflow.index("\n  stable-rc:") : workflow.index(
                "\n  retain-failure-closeout:"
            )
        ]
        self.assertIn("always()", failure_closeout)
        self.assertIn("- preflight", failure_closeout)
        self.assertIn("- stable-rc", failure_closeout)
        self.assertIn("needs.preflight.result", failure_closeout)
        self.assertIn("needs.stable-rc.result", failure_closeout)
        self.assertIn("permissions: {}", failure_closeout)
        self.assertNotIn("environment:", failure_closeout)
        self.assertNotIn("secrets.", failure_closeout)
        self.assertNotIn("actions/checkout", failure_closeout)
        self.assertNotIn("gh api", failure_closeout)
        self.assertNotIn("${{ inputs.", failure_closeout)
        self.assertIn(
            "stable-1-0-rc-failure-${{ github.run_id }}-${{ github.run_attempt }}",
            failure_closeout,
        )
        self.assertIn('"$size" -gt 16384', failure_closeout)
        self.assertIn("protectedRcOperationCompleted: false", failure_closeout)
        self.assertNotIn("Write bounded Stable RC failure closeout", stable_rc_job)
        self.assertNotIn("Retain bounded Stable RC failure closeout", stable_rc_job)
        self.assertIn(
            '"repos/$GITHUB_REPOSITORY/check-runs"',
            workflow,
        )
        self.assertIn(
            "stable-1.0-rc-freeze:$INPUT_RELEASE_ID:$INPUT_BUILD_VERSION:$GITHUB_RUN_ID:$GITHUB_RUN_ATTEMPT:$digest",
            workflow,
        )
        self.assertIn('stableRcFreezeMode: $freeze_mode', workflow)
        self.assertIn('provenance.get("freezeMode") != freeze_mode', workflow)
        self.assertIn(
            'candidate_freeze.get("productionDistributionDigest")',
            workflow,
        )
        self.assertIn(
            'distribution_name = f"crypta-stable-1.0-rc-{build_version}-product.tar.gz"',
            workflow,
        )
        self.assertIn(
            'f"crypta-stable-1.0-rc-{build_version}-product.tar.gz"',
            workflow,
        )
        self.assertIn("stable_authority_coordinates:", workflow)
        for authority in (
            "stableVulnerability",
            "stableSupplyChain",
            "stableDependencyVulnerability",
        ):
            with self.subTest(authority=authority):
                self.assertIn(authority, workflow)
        materializer = workflow[
            workflow.index("          materialize_input_file() {") : workflow.index(
                "          freeze_lineage_anchor_name() {"
            )
        ]
        for bounded_download in (
            "--connect-timeout 15",
            "--max-time 180",
            "--max-filesize 16777216",
            'local partial="$path.partial"',
            'rm -f "$partial"',
            '--output "$partial"',
            'mv "$partial" "$path"',
        ):
            with self.subTest(bounded_download=bounded_download):
                self.assertIn(bounded_download, materializer)
        self.assertLess(
            materializer.index('--output "$partial"'),
            materializer.index('mv "$partial" "$path"'),
        )
        self.assertIn(
            '.path == ".github/workflows/stable-1.0-vulnerability-intake.yml"',
            workflow,
        )
        self.assertIn('and .operation == "evaluate-promotion"', workflow)
        self.assertIn('and .caseOpaqueId == "ledger-wide"', workflow)
        self.assertIn("stable_vulnerability_actions_tip.py", workflow)
        self.assertIn("verify-promotion", workflow)
        self.assertIn("stableVulnerability: true", workflow)
        self.assertIn(
            'stableVulnerabilityGovernance: "required"',
            workflow,
        )
        self.assertIn(
            "stableVulnerabilitySummary: $stable_vulnerability",
            workflow,
        )
        self.assertIn("group: stable-1-0-release-${{ inputs.integer_build_version }}", workflow)
        self.assertIn("cancel-in-progress: false", workflow)
        upload = workflow.split(
            "- name: Upload redacted Stable RC artifacts", maxsplit=1
        )[1]
        self.assertNotIn("stable-vulnerability-promotion-input", upload)
        self.assertNotIn("stable-vulnerability-summary-", upload)
        self.assertNotIn('distribution_name = f"crypta-production-beta-', workflow)
        self.assertNotIn("expected_build", workflow)

    def test_release_workflows_bind_the_checked_out_project_version(self) -> None:
        root = workspace_root()
        production = (root / ".github/workflows/production-beta-release.yml").read_text(
            encoding="utf-8"
        )
        release = (root / ".github/workflows/release-certification.yml").read_text(
            encoding="utf-8"
        )

        self.assertNotIn("version: null", production)
        self.assertEqual(2, production.count('release_version="$(./gradlew -q printVersion)"'))
        self.assertEqual(2, production.count('--arg release_version "$release_version"'))
        self.assertEqual(2, production.count("version: $release_version"))
        self.assertEqual(
            2,
            production.count('if [[ ! "$release_version" =~ ^[0-9]+$ ]]'),
        )

        self.assertNotIn("version: null", release)
        self.assertEqual(1, release.count('release_version="$(./gradlew -q printVersion)"'))
        self.assertEqual(1, release.count('--arg release_version "$release_version"'))
        self.assertEqual(1, release.count("version: $release_version"))
        self.assertEqual(
            1,
            release.count('if [[ ! "$release_version" =~ ^[1-9][0-9]*$ ]]'),
        )
        self.assertLess(
            release.index('release_version="$(./gradlew -q printVersion)"'),
            release.index('if [[ "$CERT_MODE" == "release-candidate" ]]'),
        )
        self.assertIn(
            '"$GITHUB_REF" == "refs/heads/release/$release_version"', release
        )
        self.assertIn(
            '"$GITHUB_REF" == "refs/tags/v$release_version"', release
        )
        self.assertIn('release_id="cryptad-candidate-$release_version"', release)
        self.assertIn(
            "automatic runs require the exact release/<build> branch or v<build> tag",
            release,
        )

    def test_release_candidate_identity_is_derived_only_from_an_exact_build_ref(
        self,
    ) -> None:
        release = (
            workspace_root() / ".github/workflows/release-certification.yml"
        ).read_text(encoding="utf-8")
        start = release.index('          release_version="$(./gradlew -q printVersion)"')
        end = release.index("          require_vulnerability=false", start)
        resolver = textwrap.dedent(release[start:end])
        resolver += '\nprintf "%s\\n" "$release_id"\n'

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            gradle = root / "gradlew"
            gradle.write_text(
                "#!/usr/bin/env bash\nprintf '%s\\n' \"$TEST_BUILD_VERSION\"\n",
                encoding="utf-8",
            )
            gradle.chmod(0o700)
            base_environment = {
                **os.environ,
                "CANDIDATE_RELEASE_ID": "",
                "GITHUB_RUN_ID": "88",
                "GITHUB_RUN_ATTEMPT": "2",
                "PREVIOUS_SUMMARY_PATH": "",
                "REQUIRE_STABLE_READINESS": "false",
                "STABLE_READINESS_SUMMARY_PATH": "",
                "TEST_BUILD_VERSION": "301",
            }

            def resolve(
                *,
                mode: str,
                event: str,
                ref: str,
                candidate: str = "",
            ) -> subprocess.CompletedProcess[str]:
                return subprocess.run(
                    ["bash", "-c", resolver],
                    cwd=root,
                    env={
                        **base_environment,
                        "CERT_MODE": mode,
                        "GITHUB_EVENT_NAME": event,
                        "GITHUB_REF": ref,
                        "CANDIDATE_RELEASE_ID": candidate,
                    },
                    capture_output=True,
                    text=True,
                    check=False,
                )

            for ref in ("refs/heads/release/301", "refs/tags/v301"):
                with self.subTest(ref=ref):
                    completed = resolve(
                        mode="release-candidate", event="push", ref=ref
                    )
                    self.assertEqual(0, completed.returncode, completed.stderr)
                    self.assertEqual("cryptad-candidate-301\n", completed.stdout)
            manual = resolve(
                mode="release-candidate",
                event="workflow_dispatch",
                ref="refs/heads/main",
                candidate="reviewed-candidate-301",
            )
            self.assertEqual(0, manual.returncode, manual.stderr)
            self.assertEqual("reviewed-candidate-301\n", manual.stdout)
            nightly = resolve(mode="nightly", event="schedule", ref="")
            self.assertEqual(0, nightly.returncode, nightly.stderr)
            self.assertEqual("ci-88-2\n", nightly.stdout)
            for ref in (
                "refs/heads/release/0301",
                "refs/heads/release/301/extra",
                "refs/heads/release/302",
                "refs/tags/v1.0.0",
                "refs/tags/v301-rc",
            ):
                with self.subTest(rejected_ref=ref):
                    self.assertNotEqual(
                        0,
                        resolve(
                            mode="release-candidate", event="push", ref=ref
                        ).returncode,
                    )
            self.assertNotEqual(
                0,
                resolve(
                    mode="release-candidate",
                    event="workflow_dispatch",
                    ref="refs/heads/release/301",
                ).returncode,
            )

    def test_release_candidate_workflow_requires_authenticated_vulnerability_summary(
        self,
    ) -> None:
        release = (
            workspace_root() / ".github/workflows/release-certification.yml"
        ).read_text(encoding="utf-8")

        for field in (
            "stable-vulnerability-run-id:",
            "stable-vulnerability-run-attempt:",
            "stable-vulnerability-artifact-name:",
            "stable-vulnerability-artifact-digest:",
        ):
            with self.subTest(field=field):
                self.assertIn(field, release)
        self.assertIn(
            'if: env.CERT_MODE == \'release-candidate\'',
            release,
        )
        self.assertIn(
            '.path == ".github/workflows/stable-1.0-vulnerability-intake.yml"',
            release,
        )
        self.assertIn(
            '"repos/$GITHUB_REPOSITORY/actions/runs/'
            '$STABLE_VULNERABILITY_RUN_ID/attempts/'
            '$STABLE_VULNERABILITY_RUN_ATTEMPT"',
            release,
        )
        self.assertIn("(.id | tostring) == $run_id", release)
        self.assertIn('and .operation == "evaluate-promotion"', release)
        self.assertIn('and .caseOpaqueId == "ledger-wide"', release)
        self.assertIn("uses: actions/download-artifact@v8", release)
        self.assertIn(
            "name: ${{ env.STABLE_VULNERABILITY_ARTIFACT_NAME }}",
            release,
        )
        self.assertNotIn("merge-multiple: true", release)
        self.assertIn(
            'external_root="$RUNNER_TEMP/stable-vulnerability-summary-',
            release,
        )
        self.assertIn(
            'export CRYPTAD_STABLE_VULNERABILITY_SUMMARY_ROOT="$external_root"',
            release,
        )
        self.assertIn(
            "CRYPTAD_STABLE_VULNERABILITY_HANDOFF_KEY_BASE64: "
            "${{ env.CERT_MODE == 'release-candidate' && "
            "secrets.CRYPTAD_STABLE_VULNERABILITY_HANDOFF_KEY_BASE64 || '' }}",
            release,
        )
        self.assertIn("stable_vulnerability_actions_tip.py", release)
        self.assertIn("verify-promotion", release)
        self.assertIn(
            "  certify-release-candidate:\n"
            "    if: >-\n"
            "      github.event_name == 'push'\n"
            "      || github.event.inputs.mode == 'release-candidate'\n"
            "    concurrency:\n"
            "      group: stable-1-0-vulnerability-ledger\n"
            "      cancel-in-progress: false",
            release,
        )
        self.assertIn(
            "    environment: stable-1-0-release-certification", release
        )
        self.assertIn("    steps: *certification-steps", release)
        nonpromotion = release[
            release.index("  certify-nonpromotion:") : release.index(
                "  certify-release-candidate:"
            )
        ]
        self.assertIn("steps: &certification-steps", nonpromotion)
        self.assertNotIn(
            "environment: stable-1-0-release-certification", nonpromotion
        )
        self.assertIn("stableVulnerability: $require_vulnerability", release)
        self.assertIn(
            'stableVulnerabilityGovernance: "required"',
            release,
        )
        self.assertIn(
            "stableVulnerabilitySummary: $stable_vulnerability",
            release,
        )
        self.assertIn("persist-credentials: false", release)
        upload = release.split(
            "- name: Upload release certification artifacts", maxsplit=1
        )[1]
        self.assertNotIn("stable-vulnerability-promotion-input", upload)
        self.assertNotIn("stable-vulnerability-summary-", upload)

    def test_protected_production_workflow_requires_third_party_intake(self) -> None:
        production = (
            workspace_root() / ".github/workflows/production-beta-release.yml"
        ).read_text(encoding="utf-8")
        protected = production.split("  production-beta:", maxsplit=1)[1]

        self.assertIn("third_party_intake_summary:", production)
        self.assertIn(
            "INPUT_THIRD_PARTY_INTAKE_SUMMARY: ${{ inputs.third_party_intake_summary || '' }}",
            protected,
        )
        self.assertIn(
            'materialize_input_file "$INPUT_THIRD_PARTY_INTAKE_SUMMARY" '
            "INPUT_THIRD_PARTY_INTAKE_SUMMARY third-party-intake-summary.json",
            protected,
        )
        self.assertIn('if [[ -z "$INPUT_THIRD_PARTY_INTAKE_SUMMARY" ]]', protected)
        self.assertIn(
            "production-beta requires third_party_intake_summary with release-capable intake evidence.",
            protected,
        )
        self.assertIn(
            'require_file "$INPUT_THIRD_PARTY_INTAKE_SUMMARY" "Third-party intake summary"',
            protected,
        )
        self.assertIn('--arg third_party_intake "$INPUT_THIRD_PARTY_INTAKE_SUMMARY"', protected)
        self.assertIn("thirdPartyIntake: true", protected)
        self.assertIn("thirdPartyIntake: $third_party_intake", protected)
        self.assertNotIn("thirdPartyIntake: false", protected)

    def test_workflows_delimit_jq_arguments_and_publish_dashboard_artifacts(self) -> None:
        root = workspace_root()
        production = (root / ".github/workflows/production-beta-release.yml").read_text(
            encoding="utf-8"
        )
        release = (root / ".github/workflows/release-certification.yml").read_text(
            encoding="utf-8"
        )
        self.assertEqual(2, production.count('-- "${args[@]}" > "$manifest"'))
        self.assertNotIn("$ARGS.positional", release)
        self.assertIn("releaseHistory: $release_history", release)
        self.assertIn('if [[ -f "build/interop-smoke/summary.json" ]]', release)
        self.assertIn('if [[ -f "build/interop-extended/summary.json" ]]', release)
        self.assertIn('if [[ -f "build/perf-smoke/summary.json" ]]', release)
        self.assertIn("interopSmoke: $interop_smoke", release)
        self.assertIn("interopExtended: $interop_extended", release)
        self.assertIn("performanceSmoke: $performance_smoke", release)
        self.assertIn("build/release-certification-history/", release)
        self.assertNotIn(
            'interopSmoke: "build/interop-smoke/summary.json"',
            release,
        )
        self.assertNotIn(
            'performanceSmoke: "build/perf-smoke/summary.json"',
            release,
        )
        self.assertIn(
            'if [[ -n "$PREVIOUS_SUMMARY_PATH" \\\n'
            '                && "$candidate_identity_bound" != true ]]; then',
            release,
        )
        self.assertIn(
            "candidate-release-id is required when previous-summary-path is supplied.",
            release,
        )
        self.assertIn(
            'if [[ -n "$STABLE_READINESS_SUMMARY_PATH" \\\n'
            '                && "$candidate_identity_bound" != true ]]; then',
            release,
        )
        self.assertIn(
            "candidate-release-id is required when stable-readiness-summary-path is supplied.",
            release,
        )
        self.assertLess(
            release.index('release_id="${CANDIDATE_RELEASE_ID:-ci-${GITHUB_RUN_ID}'),
            release.index("candidate-release-id is required when previous-summary-path is supplied."),
        )
        self.assertLess(
            release.index('release_id="${CANDIDATE_RELEASE_ID:-ci-${GITHUB_RUN_ID}'),
            release.index(
                "candidate-release-id is required when stable-readiness-summary-path is supplied."
            ),
        )
        dashboard_redaction = (
            "*/production-beta/artifacts/legacy/reports/go-no-go-redaction-report.json"
        )
        dashboard_report = "*/production-beta/artifacts/legacy/reports/go-no-go-dashboard.md"
        self.assertEqual(2, production.count(dashboard_redaction))
        self.assertEqual(2, production.count(dashboard_report))
        self.assertNotIn('glob("*/production-beta/redaction-report.json")', production)
        self.assertNotIn("-path '*/production-beta/report.md'", production)
        self.assertIn("candidate_release_id:", production)
        self.assertEqual(
            2,
            production.count(
                "INPUT_CANDIDATE_RELEASE_ID: ${{ inputs.candidate_release_id || '' }}"
            ),
        )
        self.assertIn('release_id="$INPUT_CANDIDATE_RELEASE_ID"', production)
        self.assertNotIn('release_id="cryptad-beta-${GITHUB_RUN_ID}', production)
        self.assertIn('-n "$INPUT_MULTI_NODE_SOAK_SUMMARY"', production)
        self.assertIn('-n "$INPUT_SECURITY_DRILLS_SUMMARY"', production)
        self.assertIn(
            "candidate_release_id is required when previous_summary, previous_release_certification_summary, multi_node_soak_summary, or security_drills_summary is supplied.",
            production,
        )
        self.assertIn(
            'require_history="$([[ -n "$INPUT_PREVIOUS_RELEASE_CERTIFICATION_SUMMARY" ]]',
            production,
        )
        self.assertNotIn(
            'require_history="$([[ "$mode" != "developer-dry-run"',
            production,
        )
        self.assertIn('if [[ -f "build/interop-smoke/summary.json" ]]', production)
        self.assertIn('if [[ -f "build/perf-smoke/summary.json" ]]', production)
        self.assertIn(
            'if $interop_smoke == "" then {} else {interopSmoke: $interop_smoke} end',
            production,
        )
        self.assertIn(
            'if $performance_smoke == "" then {} else {performanceSmoke: $performance_smoke} end',
            production,
        )
        self.assertNotIn(
            'inputs: ({interopSmoke: "build/interop-smoke/summary.json", performanceSmoke: "build/perf-smoke/summary.json"}',
            production,
        )

    def test_release_workflow_skill_uses_only_unified_cli_options(self) -> None:
        root = workspace_root()
        skill_dir = root / ".agents/skills/cryptad-release-workflow"
        entrypoint = (skill_dir / "SKILL.md").read_text(encoding="utf-8")
        references = sorted((skill_dir / "references").glob("*.md"))
        self.assertTrue(references, "release workflow references must exist")
        guidance = [entrypoint]
        for reference in references:
            with self.subTest(reference=reference.name):
                self.assertIn(f"(references/{reference.name})", entrypoint)
            guidance.append(reference.read_text(encoding="utf-8"))
        release_skill = "\n".join(guidance)
        forbidden = (
            "--out-dir",
            "--mode release-candidate",
            "--mode production-beta",
            "--catalog-channel",
            "--artifact-base-uri",
            "--require-live-network",
            "--require-multi-node-soak",
            "--require-sandbox-provider-tests",
        )
        for option in forbidden:
            with self.subTest(option=option):
                self.assertNotIn(option, release_skill)

        self.assertIn(
            "build/release-certification/<release-id>/release-certification/summary.json",
            release_skill,
        )
        self.assertIn("multi-node-beta/run/summary.json", release_skill)
        self.assertNotIn(
            "build/release-certification/release-certification-summary.json",
            release_skill,
        )

        for command in ("release-certification", "production-beta"):
            with self.subTest(command=command):
                args = cli.build_parser().parse_args(
                    [
                        command,
                        "--manifest",
                        f"tools/release-certification/manifests/{'release-candidate' if command == 'release-certification' else 'production-beta'}.example.json",
                        "--workspace-root",
                        ".",
                    ]
                )
                self.assertEqual(command, args.command)


if __name__ == "__main__":
    unittest.main()
