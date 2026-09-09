"""Characterization suite for the production-beta pipeline."""

from __future__ import annotations

import dataclasses
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cryptad_certification import legacy
from cryptad_certification.engines import production_beta_release
from cryptad_certification.io import read_json, write_json, write_text
from cryptad_certification.legacy import execute as execute_engine
from cryptad_certification.manifest import load_manifest
from cryptad_certification.redaction import _local_absolute_path_fields
from cryptad_certification.tests.support import workspace_root, write_manifest
from cryptad_certification.workspace import prepare_context, prepare_run_root


class ProductionBetaCharacterizationTest(unittest.TestCase):
    def test_shipped_sdk_passes_redaction_but_embedded_payloads_are_rejected(self) -> None:
        sdk = workspace_root() / (
            "platform-sdk-js/src/main/resources/"
            "network/crypta/platform/sdk/js/crypta-platform.js"
        )
        source = sdk.read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            settings = production_beta_release.cleanup_test_settings(
                workspace, workspace / "release"
            )
            findings = production_beta_release.scan_text_for_findings(
                source, "static/crypta-platform.js", settings
            )
            self.assertEqual([], findings)

            for embedded in (
                '{"payloadBase64":"cHVibGljLXN5bnRoZXRpYy1wYXlsb2Fk"}',
                'const leaked = {payloadBase64: "cHVibGljLXN5bnRoZXRpYy1wYXlsb2Fk"};',
            ):
                with self.subTest(embedded=embedded):
                    findings = production_beta_release.scan_text_for_findings(
                        source + "\n" + embedded, "static/crypta-platform.js", settings
                    )
                    self.assertIn(
                        "raw-content-or-app-data", [item["kind"] for item in findings]
                    )

    def test_self_test_git_disables_automatic_maintenance(self) -> None:
        workspace = Path("fixture-workspace")
        with mock.patch.object(
            production_beta_release.subprocess,
            "run",
            return_value=subprocess.CompletedProcess([], 0),
        ) as run:
            self.assertTrue(
                production_beta_release.run_git(workspace, "commit", "-m", "fixture")
            )

        run.assert_called_once_with(
            [
                "git", "-c", "maintenance.auto=false", "-c", "gc.auto=0",
                "commit", "-m", "fixture",
            ],
            cwd=str(workspace),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=60,
        )

    def test_self_test_git_preserves_command_failures(self) -> None:
        for outcome in (
            subprocess.CompletedProcess([], 1),
            OSError("git unavailable"),
            subprocess.TimeoutExpired("git", 60),
        ):
            with self.subTest(outcome=type(outcome).__name__), mock.patch.object(
                production_beta_release.subprocess, "run"
            ) as run:
                if isinstance(outcome, Exception):
                    run.side_effect = outcome
                else:
                    run.return_value = outcome
                self.assertFalse(
                    production_beta_release.run_git(Path("fixture-workspace"), "init")
                )

    def test_existing_production_beta_scenarios(self) -> None:
        production_beta_release.run_self_test()

    def test_unified_adapter_uses_the_production_output_sentinel(self) -> None:
        root = workspace_root()
        build_dir = root / "build"
        build_dir.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="certify-production-", suffix="-workspace", dir=build_dir
        ) as directory:
            output_root = Path(directory)
            manifest_path = write_manifest(
                output_root,
                release={
                    "id": "self-test-production",
                    "version": None,
                    "profile": "developer-dry-run",
                },
                policies={"catalogChannel": "stable"},
                execution={
                    "fixtureEvidence": True,
                    "skipGradle": True,
                    "skipFullBuild": True,
                },
            )
            manifest = load_manifest(manifest_path, root, output_root)
            prepare_run_root(manifest)
            context = prepare_context(root, manifest, "production-beta")

            self.assertEqual(0, execute_engine(context, "production-beta"))

            summary = read_json(context.component_dir / "summary.json")
            self.assertEqual(2, summary["schemaVersion"])
            self.assertEqual("production-beta-release", summary["kind"])
            self.assertEqual("self-test-production", summary["subject"]["releaseId"])
            self.assertEqual(
                "self-test-production",
                summary["payload"]["legacy"]["releaseId"],
            )
            self.assertEqual(
                summary["payload"]["legacy"]["version"],
                summary["subject"]["version"],
            )
            self.assertEqual("pass", summary["redaction"]["status"])
            self.assertEqual(
                summary["payload"]["legacy"]["goNoGo"]["decision"],
                summary["result"]["decision"],
            )
            self.assertTrue(
                (
                    context.component_dir
                    / "artifacts/legacy/.cryptad-production-beta-release-output"
                ).is_file()
            )
            consumer_manifest = dataclasses.replace(
                manifest,
                inputs={"productionBeta": str(context.component_dir / "summary.json")},
            )
            consumer_context = prepare_context(root, consumer_manifest, "go-no-go")
            unix_fields, windows_fields = _local_absolute_path_fields(
                summary["payload"]["legacy"]
            )
            self.assertEqual(set(), unix_fields)
            self.assertEqual(set(), windows_fields)
            extracted = legacy._legacy_input_path(consumer_context, "productionBeta")
            self.assertIsNotNone(extracted)
            self.assertEqual(summary["payload"]["legacy"], read_json(extracted))

    def test_unified_adapter_owns_production_output_cleanup(self) -> None:
        root = workspace_root()
        build_dir = root / "build"
        build_dir.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="certify-production-", dir=build_dir
        ) as directory:
            output_root = Path(directory)
            manifest_path = write_manifest(
                output_root,
                release={
                    "id": "self-test-production-cleanup",
                    "version": None,
                    "profile": "developer-dry-run",
                },
                policies={"catalogChannel": "stable"},
                execution={
                    "fixtureEvidence": True,
                    "skipGradle": True,
                    "skipFullBuild": True,
                },
                commands={
                    "production-beta": {"args": ["--no-clean-out-dir"]},
                },
            )
            manifest = load_manifest(manifest_path, root, output_root)
            prepare_run_root(manifest)
            context = prepare_context(root, manifest, "production-beta")
            legacy_out = context.component_dir / "artifacts/legacy"
            stale_artifact = legacy_out / "stale-release-artifact.json"
            write_json(stale_artifact, {"candidate": "interrupted-run"})
            write_text(
                legacy_out / ".cryptad-production-beta-release-output",
                "Crypta production beta release output directory.\n",
            )

            self.assertEqual(0, execute_engine(context, "production-beta"))

            self.assertFalse(stale_artifact.exists())

    def test_unified_adapter_writes_failed_evidence_for_an_early_engine_exit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = load_manifest(
                write_manifest(
                    root,
                    release={
                        "id": "early-exit-candidate",
                        "version": "self-test",
                        "profile": "release-candidate",
                    },
                    policies={"catalogChannel": "beta"},
                ),
                root,
            )
            prepare_run_root(manifest)
            context = prepare_context(root, manifest, "production-beta")

            with mock.patch.dict(
                "os.environ",
                {"CRYPTAD_PRODUCTION_BETA_ARTIFACT_BASE_URI": ""},
            ):
                code = execute_engine(context, "production-beta")

            self.assertEqual(1, code)
            summary = read_json(context.component_dir / "summary.json")
            self.assertEqual("production-beta-release", summary["kind"])
            self.assertEqual("early-exit-candidate", summary["subject"]["releaseId"])
            self.assertEqual("fail", summary["result"]["status"])
            self.assertFalse(summary["result"]["promotionReady"])
            self.assertEqual(1, summary["result"]["exitCode"])
            self.assertEqual("pass", summary["redaction"]["status"])
            self.assertEqual(
                "production-beta.setup",
                summary["issues"]["blockers"][0]["id"],
            )
            self.assertTrue((context.component_dir / "report.md").is_file())
            self.assertTrue((context.component_dir / "redaction-report.json").is_file())
            legacy_summary = context.run_root / summary["artifacts"]["legacySummary"]
            self.assertTrue(legacy_summary.is_file())

    def test_unified_adapter_stages_an_external_production_output_root(self) -> None:
        with (
            tempfile.TemporaryDirectory() as workspace_directory,
            tempfile.TemporaryDirectory() as output_directory,
        ):
            root = Path(workspace_directory)
            output_root = Path(output_directory)
            manifest = load_manifest(write_manifest(root), root, output_root)
            prepare_run_root(manifest)
            context = prepare_context(root, manifest, "production-beta")
            captured_out: list[Path] = []

            def run(arguments: list[str]) -> int:
                engine_out = Path(arguments[arguments.index("--out-dir") + 1])
                captured_out.append(engine_out)
                write_json(
                    engine_out / "reports/production-beta-summary.json",
                    {
                        "generatedAt": "2026-01-01T00:00:00Z",
                        "releaseId": "self-test-release",
                        "version": "self-test",
                        "status": "pass",
                        "redaction": {"status": "pass", "findings": []},
                    },
                )
                write_text(
                    engine_out / "reports/production-beta-summary.md",
                    "# Production beta",
                )
                write_text(
                    engine_out / ".cryptad-production-beta-release-output",
                    "Crypta production beta release output directory.",
                )
                return 0

            with mock.patch.object(production_beta_release, "main", side_effect=run):
                self.assertEqual(0, execute_engine(context, "production-beta"))

            self.assertEqual(1, len(captured_out))
            self.assertTrue(captured_out[0].resolve().is_relative_to(root.resolve()))
            self.assertFalse(captured_out[0].exists())
            public_out = context.component_dir / "artifacts/legacy"
            self.assertFalse(public_out.resolve().is_relative_to(root.resolve()))
            self.assertTrue(
                (public_out / "reports/production-beta-summary.json").is_file()
            )
            self.assertTrue(
                (public_out / ".cryptad-production-beta-release-output").is_file()
            )

    def test_unified_adapter_rejects_a_symlinked_production_output(self) -> None:
        root = workspace_root()
        build_dir = root / "build"
        build_dir.mkdir(exist_ok=True)
        with (
            tempfile.TemporaryDirectory(prefix="certify-production-", dir=build_dir) as output,
            tempfile.TemporaryDirectory(prefix="production-beta-target-", dir=build_dir) as target,
        ):
            output_root = Path(output)
            target_dir = Path(target)
            preserved = target_dir / "keep.json"
            write_json(preserved, {"preserved": True})
            manifest = load_manifest(write_manifest(output_root), root, output_root)
            prepare_run_root(manifest)
            context = prepare_context(root, manifest, "production-beta")
            public_out = context.component_dir / "artifacts/legacy"
            try:
                public_out.symlink_to(target_dir, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"directory symlinks are unavailable: {exc}")

            with mock.patch.object(production_beta_release, "main") as engine:
                with self.assertRaisesRegex(
                    ValueError,
                    "production output path contains a symlink",
                ):
                    legacy._run_production_beta(context)

            engine.assert_not_called()
            self.assertEqual({"preserved": True}, read_json(preserved))

    def test_production_manifest_binds_required_third_party_intake(self) -> None:
        manifest = read_json(
            workspace_root()
            / "tools/release-certification/manifests/production-beta.example.json"
        )

        self.assertIsInstance(manifest, dict)
        self.assertIsInstance(manifest.get("requirements"), dict)
        self.assertIsInstance(manifest.get("inputs"), dict)
        self.assertIs(True, manifest["requirements"]["thirdPartyIntake"])
        self.assertEqual("REPLACE_ME.json", manifest["inputs"]["thirdPartyIntake"])

    def test_production_profile_requires_third_party_intake_without_manifest_switch(self) -> None:
        root = workspace_root()
        build_dir = root / "build"
        build_dir.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="certify-production-", dir=build_dir
        ) as directory:
            output_root = Path(directory)
            manifest = load_manifest(
                write_manifest(
                    output_root,
                    release={
                        "id": "self-test-production-intake",
                        "version": "self-test",
                        "profile": "production-beta",
                    },
                ),
                root,
                output_root,
            )
            prepare_run_root(manifest)
            context = prepare_context(root, manifest, "production-beta")
            captured: list[str] = []

            def run(arguments: list[str]) -> int:
                captured.extend(arguments)
                return 0

            with mock.patch.object(production_beta_release, "main", side_effect=run):
                legacy._run_production_beta(context)

            self.assertIn("--require-third-party-intake", captured)

    def test_required_live_evidence_is_collected_and_bound_to_aggregation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory) / "repo"
            workspace.mkdir()
            out_dir = workspace / "build/production-beta"
            cert_out = workspace / "build/certification"
            settings = dataclasses.replace(
                production_beta_release.cleanup_test_settings(workspace, out_dir),
                require_live_network=True,
                use_fixture_evidence=False,
            )
            state = production_beta_release.PipelineState(
                settings,
                "self-test",
                production_beta_release.utc_now(),
                [],
                [],
                [],
            )
            captured: dict[str, list[str]] = {}

            def run_command(
                pipeline_state: object,
                name: str,
                args: list[str],
                **kwargs: object,
            ) -> production_beta_release.CommandResult:
                del pipeline_state, kwargs
                captured[name] = list(args)
                return production_beta_release.CommandResult(name, list(args), 0, 1, "", "")

            with mock.patch.object(production_beta_release, "run_command", side_effect=run_command):
                production_beta_release.run_release_certification(state, {}, cert_out)

            app_platform_args = captured["app-platform-smoke"]
            self.assertIn("--skip-gradle", app_platform_args)
            live_args = captured["live-network-beta-smoke"]
            self.assertIn("live-network-beta", live_args)
            self.assertIn("--require", live_args)
            certification_args = captured["release-certification"]
            self.assertNotIn("--require-history", certification_args)
            self.assertIn("--require-live-network-beta", certification_args)
            live_summary_index = certification_args.index("--live-network-summary")
            self.assertEqual(
                cert_out / "live-network-beta-smoke/summary.json",
                Path(certification_args[live_summary_index + 1]),
            )

    def test_attached_optional_live_evidence_is_enabled_without_becoming_required(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory) / "repo"
            workspace.mkdir()
            out_dir = workspace / "build/production-beta"
            cert_out = workspace / "build/certification"
            attached_summary = workspace / "evidence/live-network-summary.json"
            settings = dataclasses.replace(
                production_beta_release.cleanup_test_settings(workspace, out_dir),
                live_network_summary=attached_summary,
                require_live_network=False,
                use_fixture_evidence=False,
            )
            state = production_beta_release.PipelineState(
                settings,
                "self-test",
                production_beta_release.utc_now(),
                [],
                [],
                [],
            )
            captured: dict[str, list[str]] = {}

            def run_command(
                pipeline_state: object,
                name: str,
                args: list[str],
                **kwargs: object,
            ) -> production_beta_release.CommandResult:
                del pipeline_state, kwargs
                captured[name] = list(args)
                return production_beta_release.CommandResult(name, list(args), 0, 1, "", "")

            with mock.patch.object(
                production_beta_release,
                "run_command",
                side_effect=run_command,
            ):
                production_beta_release.run_release_certification(state, {}, cert_out)

            self.assertNotIn("live-network-beta-smoke", captured)
            certification_args = captured["release-certification"]
            self.assertIn("--live-network-beta", certification_args)
            self.assertNotIn("--require-live-network-beta", certification_args)
            live_summary_index = certification_args.index("--live-network-summary")
            self.assertEqual(
                attached_summary,
                Path(certification_args[live_summary_index + 1]),
            )

    def test_strict_app_platform_collection_runs_gradle_sign_and_verify(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory) / "repo"
            workspace.mkdir()
            out_dir = workspace / "build/production-beta"
            cert_out = workspace / "build/certification"
            for mode in ("release-candidate", "production-beta"):
                with self.subTest(mode=mode):
                    settings = dataclasses.replace(
                        production_beta_release.cleanup_test_settings(workspace, out_dir),
                        mode=mode,
                        skip_gradle=False,
                        use_fixture_evidence=False,
                    )
                    state = production_beta_release.PipelineState(
                        settings,
                        "self-test",
                        production_beta_release.utc_now(),
                        [],
                        [],
                        [],
                    )
                    captured: dict[str, list[str]] = {}

                    def run_command(
                        pipeline_state: object,
                        name: str,
                        args: list[str],
                        **kwargs: object,
                    ) -> production_beta_release.CommandResult:
                        del pipeline_state, kwargs
                        captured[name] = list(args)
                        return production_beta_release.CommandResult(
                            name, list(args), 0, 1, "", ""
                        )

                    with mock.patch.object(
                        production_beta_release,
                        "run_command",
                        side_effect=run_command,
                    ):
                        production_beta_release.run_release_certification(
                            state, {}, cert_out
                        )

                    app_platform_args = captured["app-platform-smoke"]
                    self.assertEqual(
                        "release-candidate",
                        app_platform_args[app_platform_args.index("--mode") + 1],
                    )
                    self.assertNotIn("--skip-gradle", app_platform_args)

    def test_strict_app_platform_collection_honors_configured_gradle_skip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory) / "repo"
            workspace.mkdir()
            out_dir = workspace / "build/production-beta"
            cert_out = workspace / "build/certification"
            settings = dataclasses.replace(
                production_beta_release.cleanup_test_settings(workspace, out_dir),
                mode="release-candidate",
                skip_gradle=True,
                use_fixture_evidence=False,
            )
            state = production_beta_release.PipelineState(
                settings,
                "self-test",
                production_beta_release.utc_now(),
                [],
                [],
                [],
            )
            captured: dict[str, list[str]] = {}

            def run_command(
                pipeline_state: object,
                name: str,
                args: list[str],
                **kwargs: object,
            ) -> production_beta_release.CommandResult:
                del pipeline_state, kwargs
                captured[name] = list(args)
                return production_beta_release.CommandResult(name, list(args), 0, 1, "", "")

            with mock.patch.object(production_beta_release, "run_command", side_effect=run_command):
                production_beta_release.run_release_certification(state, {}, cert_out)

            self.assertIn("--skip-gradle", captured["app-platform-smoke"])

    def test_release_candidate_requires_history_only_when_configured(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory) / "repo"
            workspace.mkdir()
            out_dir = workspace / "build/production-beta"
            cert_out = workspace / "build/certification"
            settings = dataclasses.replace(
                production_beta_release.cleanup_test_settings(workspace, out_dir),
                mode="release-candidate",
                require_history=True,
                use_fixture_evidence=False,
            )
            state = production_beta_release.PipelineState(
                settings,
                "self-test",
                production_beta_release.utc_now(),
                [],
                [],
                [],
            )
            captured: dict[str, list[str]] = {}

            def run_command(
                pipeline_state: object,
                name: str,
                args: list[str],
                **kwargs: object,
            ) -> production_beta_release.CommandResult:
                del pipeline_state, kwargs
                captured[name] = list(args)
                return production_beta_release.CommandResult(name, list(args), 0, 1, "", "")

            with mock.patch.object(
                production_beta_release,
                "run_command",
                side_effect=run_command,
            ):
                production_beta_release.run_release_certification(state, {}, cert_out)

            self.assertIn("--require-history", captured["release-certification"])

    def test_generated_stable_multi_node_extract_uses_custom_release_id(self) -> None:
        custom_release_id = "cryptad-candidate-custom"
        summary = {
            "status": "pass",
            "currentCandidate": {"version": "3"},
        }

        stable_summary = production_beta_release.stable_readiness_soak_summary(
            summary,
            release_id=custom_release_id,
        )

        self.assertEqual(custom_release_id, stable_summary["releaseId"])
        self.assertEqual(
            [("releaseId", custom_release_id)],
            production_beta_release.stable_1_0_readiness.multi_node_candidate_release_ids(
                stable_summary
            ),
        )

    def test_evidence_extracts_read_attached_live_and_network_scale_summaries(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory) / "repo"
            workspace.mkdir()
            out_dir = workspace / "build/production-beta"
            cert_out = workspace / "build/certification"
            live_summary_path = workspace / "attached/live-network.json"
            network_summary_path = workspace / "attached/network-scale.json"
            live_summary = {"status": "pass", "source": "attached-live"}
            network_summary = {
                "status": "pass",
                "releaseId": "cryptad-candidate-custom",
                "source": "attached-network-scale",
            }
            write_json(live_summary_path, live_summary)
            write_json(network_summary_path, network_summary)
            settings = dataclasses.replace(
                production_beta_release.cleanup_test_settings(workspace, out_dir),
                live_network_summary=live_summary_path,
                network_scale_soak_summary=network_summary_path,
            )

            extracts = production_beta_release.write_evidence_extracts(
                settings,
                cert_out,
            )

            self.assertEqual(live_summary, extracts["liveNetwork"])
            self.assertEqual(network_summary, extracts["networkScale"])
            self.assertEqual(
                live_summary,
                read_json(out_dir / "evidence/live-network-beta-smoke.json"),
            )
            self.assertEqual(
                network_summary,
                read_json(out_dir / "evidence/network-scale-soak.json"),
            )
            self.assertEqual(
                network_summary,
                read_json(
                    production_beta_release.stable_readiness_network_scale_soak_path(
                        settings
                    )
                ),
            )

    def test_release_candidate_collects_multi_node_soak_with_default_topology(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory) / "repo"
            workspace.mkdir()
            out_dir = workspace / "build/production-beta"
            cert_out = workspace / "build/certification"
            settings = dataclasses.replace(
                production_beta_release.cleanup_test_settings(workspace, out_dir),
                mode="release-candidate",
                run_multi_node_soak=True,
                multi_node_soak_config=None,
                multi_node_soak_summary=None,
                use_fixture_evidence=False,
            )
            state = production_beta_release.PipelineState(
                settings,
                "self-test",
                production_beta_release.utc_now(),
                [],
                [],
                [],
            )
            captured: dict[str, list[str]] = {}

            def run_command(
                pipeline_state: object,
                name: str,
                args: list[str],
                **kwargs: object,
            ) -> production_beta_release.CommandResult:
                del pipeline_state, kwargs
                captured[name] = list(args)
                return production_beta_release.CommandResult(name, list(args), 0, 1, "", "")

            with mock.patch.object(production_beta_release, "run_command", side_effect=run_command):
                production_beta_release.run_release_certification(state, {}, cert_out)

            multi_node_args = captured["multi-node-beta-soak"]
            self.assertIn("multi-node-beta", multi_node_args)
            self.assertIn("run", multi_node_args)
            self.assertNotIn("--config", multi_node_args)
            certification_args = captured["release-certification"]
            summary_index = certification_args.index("--multi-node-soak-summary")
            self.assertEqual(
                cert_out / "multi-node-beta-soak/summary.json",
                Path(certification_args[summary_index + 1]),
            )

    def test_required_live_multi_node_collection_requires_reachability(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory) / "repo"
            workspace.mkdir()
            out_dir = workspace / "build/production-beta"
            cert_out = workspace / "build/certification"
            topology = workspace / "live-topology.json"
            config = production_beta_release.multi_node_beta_soak.load_config(None)
            config["mode"] = "live"
            write_json(topology, config)
            settings = dataclasses.replace(
                production_beta_release.cleanup_test_settings(workspace, out_dir),
                mode="release-candidate",
                run_multi_node_soak=True,
                require_multi_node_soak=True,
                multi_node_soak_config=topology,
                multi_node_soak_summary=None,
                use_fixture_evidence=False,
            )
            state = production_beta_release.PipelineState(
                settings,
                "self-test",
                production_beta_release.utc_now(),
                [],
                [],
                [],
            )
            captured: dict[str, list[str]] = {}

            def run_command(
                pipeline_state: object,
                name: str,
                args: list[str],
                **kwargs: object,
            ) -> production_beta_release.CommandResult:
                del pipeline_state, kwargs
                captured[name] = list(args)
                return production_beta_release.CommandResult(name, list(args), 0, 1, "", "")

            with mock.patch.object(production_beta_release, "run_command", side_effect=run_command):
                production_beta_release.run_release_certification(state, {}, cert_out)

            multi_node_args = captured["multi-node-beta-soak"]
            self.assertIn("--require-all-scenarios", multi_node_args)
            self.assertIn("--require-live", multi_node_args)
