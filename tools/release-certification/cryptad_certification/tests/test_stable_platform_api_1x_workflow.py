"""Source-contract tests for the protected Platform API 1.x workflow."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import unittest

from cryptad_certification.tests.support import workspace_root


WORKFLOW = workspace_root() / ".github/workflows/stable-1.0-platform-api-1x-compatibility.yml"
PRODUCER_WORKFLOW = (
    workspace_root() / ".github/workflows/stable-1.0-platform-api-1x-evidence.yml"
)
RUNTIME_WORKFLOW = (
    workspace_root()
    / ".github/workflows/stable-1.0-platform-api-1x-runtime-observation.yml"
)


class StablePlatformApi1xWorkflowTest(unittest.TestCase):
    """Keeps history and compatibility closeout read-only and exactly authenticated."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")
        cls.producer = PRODUCER_WORKFLOW.read_text(encoding="utf-8")
        cls.runtime = RUNTIME_WORKFLOW.read_text(encoding="utf-8")

    def test_workflow_whenExamined_expectReadOnlyPermissions(self) -> None:
        self.assertIn("\npermissions: {}\n", self.workflow)
        for forbidden in (
            "contents: write", "actions: write", "id-token: write", "packages: write",
            "pull-requests: write", "issues: write",
        ):
            self.assertNotIn(forbidden, self.workflow)

    def test_workflow_whenActionsUsed_expectEveryActionPinnedToFullSha(self) -> None:
        uses = re.findall(r"uses:\s*([^\s#]+)", self.workflow)
        self.assertGreaterEqual(len(uses), 3)
        for action in uses:
            self.assertRegex(action, r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}$")

    def test_workflow_whenSourceRuns_expectProtectedExactCommitAndJava25(self) -> None:
        self.assertIn(
            "if: github.ref_protected && github.actor == 'leumor' && "
            "github.triggering_actor == 'leumor'",
            self.workflow,
        )
        self.assertIn("persist-credentials: false", self.workflow)
        self.assertIn("ref: ${{ github.sha }}", self.workflow)
        self.assertIn("SOURCE_COMMIT: ${{ inputs.source_commit }}", self.workflow)
        self.assertIn("SOURCE_REF: ${{ inputs.source_ref }}", self.workflow)
        self.assertIn('"$SOURCE_COMMIT" != "$GITHUB_SHA"', self.workflow)
        self.assertIn('"$(git rev-parse HEAD)" != "$GITHUB_SHA"', self.workflow)
        self.assertIn('"$SOURCE_REF" != "$GITHUB_REF"', self.workflow)
        self.assertIn(".repository.sourceRef == $ref", self.workflow)
        self.assertIn('.activeStableBaselines == ["1.0"]', self.workflow)
        self.assertIn("java-version: '25'", self.workflow)
        self.assertIn("distributionSha256Sum", self.workflow)
        self.assertIn("validateDistributionUrl", self.workflow)

    def test_workflows_whenShellRuns_expectNoExpressionInterpolation(self) -> None:
        for label, workflow in (
            ("compatibility", self.workflow),
            ("evidence", self.producer),
            ("runtime", self.runtime),
        ):
            with self.subTest(workflow=label):
                run_scripts = self._run_scripts(workflow)
                self.assertGreater(len(run_scripts), 0)
                for script in run_scripts:
                    self.assertNotIn("${{", script)

    @staticmethod
    def _run_scripts(workflow: str) -> list[str]:
        lines = workflow.splitlines()
        scripts: list[str] = []
        for index, line in enumerate(lines):
            match = re.match(r"^(\s*)run:\s*(.*?)\s*$", line)
            if match is None:
                continue
            indentation = len(match.group(1))
            header = match.group(2)
            if not re.fullmatch(r"[|>][+-]?", header):
                scripts.append(header)
                continue
            body: list[str] = []
            for candidate in lines[index + 1 :]:
                if candidate and len(candidate) - len(candidate.lstrip()) <= indentation:
                    break
                body.append(candidate)
            scripts.append("\n".join(body))
        return scripts

    def test_workflow_whenArtifactImported_expectAttemptNameAndDigestAuthenticated(self) -> None:
        authentication = self.workflow.index("Authenticate immutable evidence artifact before extraction")
        extraction = self.workflow.index("Confine exact evidence archive")
        self.assertLess(authentication, extraction)
        self.assertIn("actions/runs/$RUN_ID/attempts/$RUN_ATTEMPT", self.workflow)
        self.assertIn(".head_sha == $commit", self.workflow)
        self.assertNotIn("evidence_workflow_path:", self.workflow)
        self.assertIn(
            "EXPECTED_WORKFLOW: .github/workflows/stable-1.0-platform-api-1x-evidence.yml",
            self.workflow,
        )
        self.assertIn('.path == env.EXPECTED_WORKFLOW', self.workflow)
        self.assertIn(".run_attempt == (env.RUN_ATTEMPT | tonumber)", self.workflow)
        self.assertIn('.repository.full_name == env.GITHUB_REPOSITORY', self.workflow)
        self.assertIn('.actor.login == "leumor"', self.workflow)
        self.assertIn('.triggering_actor.login == "leumor"', self.workflow)
        self.assertIn("deployments: read", self.workflow)
        self.assertIn("EXPECTED_ENVIRONMENT: stable-1-0-platform-api-1x-evidence", self.workflow)
        self.assertIn("deployment_verified=true", self.workflow)
        self.assertIn('.workflow_run.id == (env.RUN_ID | tonumber)', self.workflow)
        self.assertIn('.created_at >= $started_at and .updated_at <= $completed_at', self.workflow)
        self.assertIn(".name == $name and .digest == $digest and .expired == false", self.workflow)
        self.assertIn("actions/artifacts/$artifact_id/zip", self.workflow)
        self.assertIn('test "$actual" = "$ARTIFACT_DIGEST"', self.workflow)

    def test_workflow_whenArchiveConfined_expectUnsafeMembersRejected(self) -> None:
        for marker in ("__MACOSX", ".DS_Store", 'part.startswith("._")', '".." in path.parts',
                       "stat.S_ISLNK", "casefold", "archive bounds exceeded",
                       "inspect_archive_safety", "reject_nested_archives=True"):
            self.assertIn(marker, self.workflow)
        self.assertLess(
            self.workflow.index("unsafe archive path"),
            self.workflow.index("archive.extractall(destination)"),
        )

    def test_workflow_whenCloseoutRuns_expectOneSideEffectFreeAuthority(self) -> None:
        closeout_start = self.workflow.index("Verify exact release contract and close out")
        closeout_end = self.workflow.index("Retain truthful pass, partial, or failure evidence")
        closeout = self.workflow[closeout_start:closeout_end]
        self.assertIn("stable-platform-api-1x --self-test", self.workflow)
        self.assertIn("stable-platform-api-1x \\", closeout)
        self.assertIn("--mode closeout", closeout)
        self.assertIn(".fixtureOnly == false and .selfTest == false", closeout)
        for binding in (
            "SOURCE_COMMIT: ${{ inputs.source_commit }}",
            "SOURCE_REF: ${{ inputs.source_ref }}",
            "RELEASE_ID: ${{ inputs.release_id }}",
            "BUILD_VERSION: ${{ inputs.build_version }}",
            "CONTRACT_VERSION: ${{ inputs.contract_version }}",
        ):
            self.assertIn(binding, closeout)
        self.assertIn('--arg commit "$SOURCE_COMMIT"', closeout)
        self.assertIn('--arg ref "$SOURCE_REF"', closeout)
        self.assertIn('--arg release "$RELEASE_ID"', closeout)
        self.assertIn('--argjson build "$BUILD_VERSION"', closeout)
        self.assertIn('--argjson contractVersion "$CONTRACT_VERSION"', closeout)
        for mutation in ("git push", "gh release", "gh api --method POST", "gh api --method PATCH", "gh api --method DELETE"):
            self.assertNotIn(mutation, self.workflow)

    def test_workflow_whenHistoryCertified_expectSuccessOnlyExactInputRetention(self) -> None:
        retention = self.workflow.index("Retain certified exact contract-history inputs")
        retained_step = self.workflow[retention:]
        self.assertIn("if: success()", retained_step)
        self.assertIn("path: build/platform-api-1x-input/", retained_step)
        self.assertIn("if-no-files-found: error", retained_step)
        self.assertIn("include-hidden-files: false", retained_step)

    def test_producer_whenExamined_expectProtectedReadOnlyExactSubject(self) -> None:
        self.assertIn("\npermissions: {}\n", self.producer)
        self.assertIn(
            "if: github.ref_protected && github.actor == 'leumor' && "
            "github.triggering_actor == 'leumor'",
            self.producer,
        )
        self.assertIn("environment: stable-1-0-platform-api-1x-evidence", self.producer)
        self.assertIn("persist-credentials: false", self.producer)
        self.assertIn('test "$SOURCE_COMMIT" = "$GITHUB_SHA"', self.producer)
        self.assertIn('test "$SOURCE_REF" = "$GITHUB_REF"', self.producer)
        self.assertIn(".fixtureOnly == false and .selfTest == false", self.producer)
        self.assertIn('.activeStableBaselines == ["1.0"]', self.producer)
        self.assertIn("--mode closeout", self.producer)
        self.assertIn("actions: read", self.producer)
        self.assertIn("deployments: read", self.producer)
        self.assertIn("attestations: read", self.producer)
        self.assertNotIn("attestations: write", self.producer)
        self.assertNotIn("contents: write", self.producer)

    def test_producers_whenEvidenceDirectorySelected_expectEveryAncestorConfined(
        self,
    ) -> None:
        for source in (self.producer, self.runtime):
            with self.subTest(workflow="runtime" if source is self.runtime else "aggregate"):
                self.assertIn('.resolve(strict=True)', source)
                self.assertIn('unresolved_source.is_symlink()', source)
                self.assertIn('source.relative_to(workspace)', source)
                self.assertLess(
                    source.index('unresolved_source.is_symlink()'),
                    source.index('for member in sorted(source.iterdir()'),
                )

    def test_producer_whenPredecessorsImported_expectEveryProtectedCoordinateAuthenticated(
        self,
    ) -> None:
        authentication = self.producer.index(
            "Authenticate exact predecessor authority attempts and summaries"
        )
        closeout = self.producer.index("Verify the complete side-effect-free evidence set")
        upload = self.producer.index("Upload the exact protected evidence aggregate")
        self.assertLess(authentication, closeout)
        self.assertLess(closeout, upload)
        for expected in (
            ".github/workflows/stable-1.0-protected-release-closeout.yml",
            "Authenticate final protected-release evidence",
            "stable-1-0-protected-release-closeout",
            ".github/workflows/stable-1.0-independent-reproducibility.yml",
            "Authenticate and compare independent rebuild",
            "stable-1.0-independent-reproducibility-external-receipt",
            ".github/workflows/stable-1.0-catalog-authority.yml",
            "Close out only authenticated catalog-authority evidence",
            "stable-1-0-catalog-authority-closeout",
            ".github/workflows/stable-1.0-third-party-app-pilot.yml",
            "Authenticate operational closeout",
            "stable-1-0-third-party-pilot-closeout",
            ".github/workflows/stable-1.0-federated-catalog-trust.yml",
            "Close out authenticated federation evidence",
            "stable-1-0-federated-catalog-closeout",
            ".github/workflows/stable-1.0-platform-api-1x-compatibility.yml",
            "Authenticate and verify Platform API 1.x compatibility evidence",
            "stable-1-0-platform-api-1x-compatibility",
            ".github/workflows/stable-1.0-support-lifecycle.yml",
            "Independently re-fetch exact lifecycle descriptor",
            "stable-1.0-lifecycle-evidence",
            "stable-1.0-support-lifecycle-independent-verification-receipt.json",
            ".github/workflows/stable-1.0-platform-api-1x-runtime-observation.yml",
            "Observe bounded Platform API 1.x runtime compatibility",
            "stable-1-0-platform-api-1x-runtime",
            "platform-api-1.x-runtime-observation.json",
        ):
            self.assertIn(expected, self.producer)
        for expected in (
            "actions/runs/$run_id/attempts/$run_attempt",
            ".head_sha == $commit and .path == $workflow",
            'current_source_ref="$(jq -er \'.repository.sourceRef\' "$contract")"',
            'previous_history_source_ref="$(jq -er \'.records[-1].sourceRef\'',
            'expected_source_ref="$previous_history_source_ref"',
            ".evidence.previousBaselineRegistry != null",
            '--arg head_branch "$expected_head_branch"',
            ".head_branch == $head_branch",
            ".actor.login == \"leumor\" and .triggering_actor.login == \"leumor\"",
            "predecessor protected producer job is not exact",
            "deployment_verified=true",
            ".workflow_run.id == $run_id and .expired == false",
            "actions/artifacts/$artifact_id/zip",
            "authority summary is absent or ambiguous",
            "authority summary digest differs",
        ):
            self.assertIn(expected, self.producer)
        predecessor_block = self.producer[authentication:closeout]
        self.assertNotIn(".head_branch == env.GITHUB_REF_NAME", predecessor_block)
        self.assertIn(
            'python3 - "$archive" "$artifact_digest" "$summary_file"',
            predecessor_block,
        )
        archive_digest_check = predecessor_block.index(
            "authority archive digest differs"
        )
        archive_open = predecessor_block.index("zipfile.ZipFile(archive_stream)")
        self.assertLess(archive_digest_check, archive_open)

    def test_producer_whenHistoryHeadImported_expectSelectedRcFreezeAuthenticated(self) -> None:
        selected_rc = self.producer.index(
            "Bind history head to the authenticated selected RC freeze"
        )
        closeout = self.producer.index("Verify the complete side-effect-free evidence set")

        self.assertLess(selected_rc, closeout)
        for expected in (
            ".evidence.selectedRcFreeze.digest == $reproduced.freezeFileDigest",
            "$freeze[0].contentDigest == $reproduced.freezeDigest",
            ".release.releaseRootDigest == $reproduced.productDigest",
            ".repository.sourceCommit == $freeze[0].candidate.sourceCommit",
            ".repository.sourceRef == $freeze[0].candidate.sourceRef",
        ):
            self.assertIn(expected, self.producer[selected_rc:closeout])

    def test_producer_whenActionsUsed_expectEveryActionPinnedToFullSha(self) -> None:
        uses = re.findall(r"uses:\s*([^\s#]+)", self.producer)
        self.assertGreaterEqual(len(uses), 3)
        for action in uses:
            self.assertRegex(action, r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}$")

    def test_runtimeProducer_whenExamined_expectProtectedManagedNodeBoundary(self) -> None:
        self.assertIn("\npermissions: {}\n", self.runtime)
        self.assertIn(
            "name: Observe bounded Platform API 1.x runtime compatibility", self.runtime
        )
        self.assertIn(
            "if: github.ref_protected && github.actor == 'leumor' && "
            "github.triggering_actor == 'leumor'",
            self.runtime,
        )
        for label in ("self-hosted", "linux", "x64"):
            self.assertIn(f"- {label}", self.runtime)
        self.assertIn("cryptad-platform-api-1x-runtime", self.runtime)
        self.assertIn("environment: stable-1-0-platform-api-1x-runtime", self.runtime)
        self.assertIn("persist-credentials: false", self.runtime)
        self.assertIn('"$SOURCE_COMMIT" != "$GITHUB_SHA"', self.runtime)
        self.assertIn('"$WORKFLOW_SHA" != "$GITHUB_SHA"', self.runtime)
        self.assertIn('"$(git rev-parse HEAD)" != "$GITHUB_SHA"', self.runtime)
        self.assertIn('"$SOURCE_REF" != "$GITHUB_REF"', self.runtime)
        self.assertIn("CRYPTAD_PLATFORM_API_1X_RUNTIME_ADAPTER_DIGEST", self.runtime)
        self.assertNotIn("runtime_adapter_digest:", self.runtime)
        self.assertIn("CRYPTAD_PLATFORM_API_1X_NODE_URL", self.runtime)
        self.assertIn("CRYPTAD_PLATFORM_API_1X_NODE_FORM_PASSWORD", self.runtime)
        self.assertIn("--require-managed-daemon", self.runtime)
        for forbidden in (
            "contents: write",
            "actions: write",
            "id-token: write",
            "git push",
            "gh release",
            "gh api --method POST",
            "gh api --method PATCH",
            "gh api --method DELETE",
        ):
            self.assertNotIn(forbidden, self.runtime)

    def test_runtimeProducer_whenRun_expectStaticVerificationBeforeNodeAndExactObservation(
        self,
    ) -> None:
        static = self.runtime.index("Verify the exact static matrix before node access")
        exercise = self.runtime.index("Exercise the managed node with the protected runtime adapter")
        validate = self.runtime.index("Validate the bounded runtime observation")
        upload = self.runtime.index("Upload immutable runtime observation")
        self.assertLess(static, exercise)
        self.assertLess(exercise, validate)
        self.assertLess(validate, upload)
        self.assertIn("--mode verify-app-matrix", self.runtime)
        self.assertIn(".runtimeObservationAuthority == null", self.runtime)
        self.assertIn(".evidence.runtimeObservation == null", self.runtime)
        self.assertIn("platform-api-1.x-runtime-observation.json", self.runtime)
        self.assertIn("engine._runtime_errors", self.runtime)
        self.assertIn("scan_value(observation)", self.runtime)
        self.assertIn(".workflow_run.id == (env.GITHUB_RUN_ID | tonumber)", self.runtime)
        self.assertIn("if: failure()", self.runtime)

    def test_runtimeProducer_whenActionsUsed_expectEveryActionPinnedToFullSha(self) -> None:
        uses = re.findall(r"uses:\s*([^\s#]+)", self.runtime)
        self.assertGreaterEqual(len(uses), 4)
        for action in uses:
            self.assertRegex(action, r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}$")

    def test_runtimeProducer_whenArtifactUploaded_expectRestDigestNormalization(self) -> None:
        step = self.runtime.split("Authenticate the uploaded observation artifact", 1)[1]
        step = step.split("- name:", 1)[0]
        self.assertIn(
            "ARTIFACT_DIGEST: sha256:${{ steps.observation.outputs.artifact-digest }}",
            step,
        )
        self.assertIn(".digest == env.ARTIFACT_DIGEST", step)

    @unittest.skipUnless(shutil.which("jq"), "jq is required to exercise the workflow predicate")
    def test_runtimeProducer_whenArtifactAuthenticated_expectExactRestSubject(self) -> None:
        step = self.runtime.split("Authenticate the uploaded observation artifact", 1)[1]
        step = step.split("- name:", 1)[0]
        digest_value = re.search(r"ARTIFACT_DIGEST: (.+)", step).group(1)
        digest_value = digest_value.replace(
            "${{ steps.observation.outputs.artifact-digest }}", "a" * 64
        )
        predicate = re.search(r"jq -e '([^']+)'", step).group(1)
        environment = {
            **os.environ,
            "ARTIFACT_ID": "17",
            "ARTIFACT_NAME": "fixture-runtime-observation",
            "ARTIFACT_DIGEST": digest_value,
            "GITHUB_RUN_ID": "11",
        }
        artifact = {
            "id": 17,
            "name": environment["ARTIFACT_NAME"],
            "workflow_run": {"id": 11},
            "digest": "sha256:" + "a" * 64,
            "expired": False,
        }
        cases = [
            ({}, True),
            ({"digest": "a" * 64}, False),
            ({"digest": "sha256:" + "b" * 64}, False),
            ({"digest": None}, False),
            ({"id": 18}, False),
            ({"name": "other-artifact"}, False),
            ({"workflow_run": {"id": 12}}, False),
            ({"expired": True}, False),
        ]
        for changes, accepted in cases:
            with self.subTest(changes=changes):
                result = subprocess.run(
                    ["jq", "-e", predicate],
                    input=json.dumps({**artifact, **changes}),
                    text=True, capture_output=True, env=environment, check=False,
                )
                self.assertEqual(result.returncode == 0, accepted, result.stderr)

    def test_producer_whenRuntimeImported_expectProtectedAuthorityConstructedBeforeCloseout(
        self,
    ) -> None:
        runtime = self.producer.index(
            "Authenticate and bind the exact protected runtime observation"
        )
        predecessors = self.producer.index(
            "Authenticate exact predecessor authority attempts and summaries"
        )
        closeout = self.producer.index("Verify the complete side-effect-free evidence set")
        self.assertLess(runtime, predecessors)
        self.assertLess(predecessors, closeout)
        for expected in (
            "runtime_run_id:",
            "runtime_run_attempt:",
            "runtime_artifact_id:",
            "runtime_artifact_name:",
            "runtime_artifact_digest:",
            ".github/workflows/stable-1.0-platform-api-1x-runtime-observation.yml",
            "Observe bounded Platform API 1.x runtime compatibility",
            "stable-1-0-platform-api-1x-runtime",
            "runtime protected producer job is not exact",
            "Runtime observation lacks its protected environment deployment",
            "runtime archive member set is not canonical",
            ".runtimeObservationAuthority = {",
            ".evidence.runtimeObservation = {fileName: $file, digest: $digest, size: $size}",
        ):
            self.assertIn(expected, self.producer)


if __name__ == "__main__":
    unittest.main()
