"""Protected-workflow contract tests for local federated catalog trust."""

from __future__ import annotations

import re
import unittest

from cryptad_certification import selftest
from cryptad_certification.tests.support import workspace_root


WORKFLOW = workspace_root() / ".github/workflows/stable-1.0-federated-catalog-trust.yml"
PRODUCER_WORKFLOW = (
    workspace_root() / ".github/workflows/stable-1.0-federated-catalog-evidence.yml"
)
RUNTIME_WORKFLOW = (
    workspace_root() / ".github/workflows/stable-1.0-federated-catalog-runtime.yml"
)


class StableFederatedCatalogWorkflowTest(unittest.TestCase):
    """Keeps import, observation, runtime, and closeout boundaries read-only."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")
        cls.producer_workflow = PRODUCER_WORKFLOW.read_text(encoding="utf-8")
        cls.runtime_workflow = RUNTIME_WORKFLOW.read_text(encoding="utf-8")

    def test_workflow_when_authority_examined_expect_read_only_permissions(self) -> None:
        self.assertIn("\npermissions: {}\n", self.workflow)
        for forbidden in (
            "contents: write",
            "actions: write",
            "id-token: write",
            "packages: write",
            "pull-requests: write",
        ):
            self.assertNotIn(forbidden, self.workflow)

    def test_catalog_origin_observer_can_read_original_producer_deployments(self) -> None:
        job = self.runtime_workflow.split("\n  catalog-origin-synthetic:\n", 1)[1]
        permissions = job.split("    permissions:\n", 1)[1].split("    steps:\n", 1)[0]
        self.assertEqual(
            {"actions": "read", "contents": "read", "deployments": "read"},
            dict(re.findall(r"^      ([\w-]+): (\w+)$", permissions, re.MULTILINE)),
        )

    def test_catalog_origin_upload_digest_reaches_seal_in_canonical_format(self) -> None:
        job = self.runtime_workflow.split("\n  catalog-origin-synthetic:\n", 1)[1]
        seal = job.split("      - name: Seal only the original uploaded immutable ciphertext\n", 1)[1]
        seal = seal.split("      - name:", 1)[0]
        digest = re.search(r"^          ORIGINAL_ARTIFACT_DIGEST: (.+)$", seal, re.MULTILINE)
        self.assertIsNotNone(digest)
        action_output = "0fde654d4c6e659b45783a725dc92f1bfb0baa6c2de64b34e814dc206ff4aaaf"
        rendered = digest.group(1).replace(
            "${{ steps.narrow-observation.outputs.artifact-digest }}", action_output
        )
        self.assertEqual("sha256:" + action_output, rendered)
        self.assertIn('--artifact-digest "$ORIGINAL_ARTIFACT_DIGEST"', seal)

    def test_workflow_when_code_runs_expect_exact_sha_and_repository_identity(self) -> None:
        self.assertEqual(4, self.workflow.count("ref: ${{ github.sha }}"))
        self.assertEqual(4, self.workflow.count("persist-credentials: false"))
        self.assertIn('"$GITHUB_REPOSITORY" != "crypta-network/cryptad"', self.workflow)
        self.assertIn('"$(git rev-parse HEAD)" != "$GITHUB_SHA"', self.workflow)
        self.assertIn('"$GITHUB_ACTOR" != "leumor"', self.workflow)

    def test_workflow_when_artifactImported_expectAuthenticatedBeforeExtraction(self) -> None:
        authentication = self.workflow.index("Authenticate immutable artifact before extraction")
        digest_check = self.workflow.index("sha256sum --check --status", authentication)
        extraction = self.workflow.index("source.extractall(destination)", authentication)
        self.assertLess(authentication, digest_check)
        self.assertLess(digest_check, extraction)
        self.assertIn("expired == false", self.workflow)
        self.assertIn(".digest == env.ARTIFACT_DIGEST", self.workflow)

    def test_workflow_when_producerExamined_expectExactProtectedProvenance(self) -> None:
        self.assertIn(
            '.path == ".github/workflows/stable-1.0-federated-catalog-evidence.yml"',
            self.workflow,
        )
        self.assertIn('.event == "workflow_dispatch"', self.workflow)
        self.assertIn('.head_branch == env.GITHUB_REF_NAME', self.workflow)
        self.assertIn('.triggering_actor.login == "leumor"', self.workflow)
        self.assertIn(
            '.name == "Authenticate and confine exact federation evidence"',
            self.workflow,
        )
        self.assertIn(
            "environment=stable-1-0-federated-catalog-evidence-import",
            self.workflow,
        )
        self.assertIn('contains("/actions/runs/" + $run_id + "/")', self.workflow)
        self.assertIn(
            "environment: stable-1-0-federated-catalog-evidence-import",
            self.producer_workflow,
        )
        self.assertIn("github.ref_protected", self.producer_workflow)
        self.assertIn('"$GITHUB_TRIGGERING_ACTOR" != "leumor"', self.producer_workflow)
        self.assertIn("actions: read", self.producer_workflow)
        self.assertIn(
            "Authenticate exact predecessor authority attempts and summaries",
            self.producer_workflow,
        )
        self.assertIn(
            'actions/runs/$run_id/attempts/$run_attempt', self.producer_workflow
        )
        self.assertIn('.path == $workflow', self.producer_workflow)
        self.assertIn('.head_branch == env.GITHUB_REF_NAME', self.producer_workflow)
        self.assertIn('.digest == $digest', self.producer_workflow)
        self.assertIn('authority summary digest differs', self.producer_workflow)
        authority_authentication = self.producer_workflow.index(
            "Authenticate exact predecessor authority attempts and summaries"
        )
        upload = self.producer_workflow.index(
            "Upload exact authenticated federation evidence"
        )
        self.assertLess(authority_authentication, upload)

    def test_producer_whenPredecessorsImported_expectAllowlistedJobsAndEnvironments(self) -> None:
        authority_authentication = self.producer_workflow.index(
            "Authenticate exact predecessor authority attempts and summaries"
        )
        runtime_authentication = self.producer_workflow.index(
            "Authenticate exact protected runtime observer and signed receipt"
        )
        predecessor_step = self.producer_workflow[
            authority_authentication:runtime_authentication
        ]
        expected_producers = (
            (
                "protectedRelease",
                ".github/workflows/stable-1.0-protected-release-closeout.yml",
                "Authenticate final protected-release evidence",
                "stable-1-0-protected-release-closeout",
            ),
            (
                "independentReproducibility",
                ".github/workflows/stable-1.0-independent-reproducibility.yml",
                "Authenticate and compare independent rebuild",
                "stable-1.0-independent-reproducibility-external-receipt",
            ),
            (
                "catalogAuthority",
                ".github/workflows/stable-1.0-catalog-authority.yml",
                "Close out only authenticated catalog-authority evidence",
                "stable-1-0-catalog-authority-closeout",
            ),
            (
                "thirdPartyPilot",
                ".github/workflows/stable-1.0-third-party-app-pilot.yml",
                "Authenticate operational closeout",
                "stable-1-0-third-party-pilot-closeout",
            ),
        )
        for authority, workflow, job, environment in expected_producers:
            self.assertIn(f"{authority})", predecessor_step)
            self.assertIn(f'expected_workflow="{workflow}"', predecessor_step)
            self.assertIn(f'expected_job="{job}"', predecessor_step)
            self.assertIn(f'expected_environment="{environment}"', predecessor_step)
        self.assertIn('"$workflow_path" != "$expected_workflow"', predecessor_step)
        self.assertIn('"$environment" != "$expected_environment"', predecessor_step)
        self.assertIn('.name == $name and .head_sha == $commit', predecessor_step)
        self.assertIn('job_started_at="$(jq -er', predecessor_step)
        self.assertIn('job_completed_at="$(jq -er', predecessor_step)
        self.assertIn('--arg started "$job_started_at"', predecessor_step)
        self.assertIn('--arg completed "$job_completed_at"', predecessor_step)
        self.assertNotIn('run_started_at="$(jq -er', predecessor_step)
        self.assertNotIn('run_completed_at="$(jq -er', predecessor_step)

    def test_producer_whenRuntimeReceiptImported_expectOriginalObserverAuthenticated(self) -> None:
        self.assertIn(
            "Authenticate exact protected runtime observer and signed receipt",
            self.producer_workflow,
        )
        self.assertIn(
            '.github/workflows/stable-1.0-federated-catalog-runtime.yml',
            self.producer_workflow,
        )
        self.assertIn(
            'Collect and sign exact federation runtime observation',
            self.producer_workflow,
        )
        self.assertIn(
            'stable-1-0-federated-catalog-runtime-observation',
            self.producer_workflow,
        )
        self.assertIn('signed runtime observer identity differs', self.producer_workflow)
        self.assertIn('unsigned runtime observation artifact is not exact', self.producer_workflow)
        runtime_authentication = self.producer_workflow.index(
            "Authenticate exact protected runtime observer and signed receipt"
        )
        upload = self.producer_workflow.index(
            "Upload exact authenticated federation evidence"
        )
        self.assertLess(runtime_authentication, upload)

    def test_runtimeProducer_whenExamined_expectProtectedNodeSideAuthority(self) -> None:
        self.assertIn("\npermissions: {}\n", self.runtime_workflow)
        self.assertIn("if: github.ref_protected", self.runtime_workflow)
        self.assertIn(
            "runs-on: [self-hosted, linux, x64, cryptad-federated-catalog-runtime]",
            self.runtime_workflow,
        )
        self.assertIn(
            "environment: stable-1-0-federated-catalog-runtime-observation",
            self.runtime_workflow,
        )
        self.assertIn(
            "vars.CRYPTAD_FEDERATED_CATALOG_RUNTIME_ADAPTER_DIGEST",
            self.runtime_workflow,
        )
        self.assertIn(
            "vars.CRYPTAD_FEDERATED_CATALOG_OBSERVER_KEY_ID",
            self.runtime_workflow,
        )
        self.assertIn(
            "vars.CRYPTAD_FEDERATED_CATALOG_OBSERVER_KEY_FINGERPRINT",
            self.runtime_workflow,
        )
        self.assertIn(
            "CRYPTAD_FEDERATED_CATALOG_OBSERVER_PRIVATE_KEY",
            self.runtime_workflow,
        )
        self.assertNotIn("observer_key_id:", self.runtime_workflow)
        self.assertNotIn("observer_key_fingerprint:", self.runtime_workflow)
        self.assertIn(
            "Authenticate and confine exact federation evidence",
            self.runtime_workflow,
        )
        self.assertIn(
            "stable-1-0-federated-catalog-evidence-import",
            self.runtime_workflow,
        )
        unsigned_upload = self.runtime_workflow.index(
            "Upload immutable unsigned runtime observation"
        )
        observation_authentication = self.runtime_workflow.index(
            "Authenticate immutable uploaded runtime observation"
        )
        observation_download = self.runtime_workflow.index(
            "Download exact immutable runtime observation for sealing"
        )
        seal = self.runtime_workflow.index(
            "Seal runtime receipt with independently approved observer key"
        )
        signed_upload = self.runtime_workflow.index("Upload exact signed runtime receipt")
        self.assertLess(unsigned_upload, observation_authentication)
        self.assertLess(observation_authentication, observation_download)
        self.assertLess(observation_download, seal)
        self.assertLess(seal, signed_upload)

        authentication_step = self.runtime_workflow[
            observation_authentication:observation_download
        ]
        self.assertIn(".id == (env.OBSERVATION_ARTIFACT_ID | tonumber)", authentication_step)
        self.assertIn(".name == env.OBSERVATION_ARTIFACT_NAME", authentication_step)
        self.assertIn(".workflow_run.id == (env.GITHUB_RUN_ID | tonumber)", authentication_step)
        self.assertIn(".digest == env.OBSERVATION_ARTIFACT_DIGEST", authentication_step)
        self.assertIn(".expired == false", authentication_step)

        download_step = self.runtime_workflow[observation_download:seal]
        self.assertIn(
            "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
            download_step,
        )
        self.assertIn(
            "artifact-ids: ${{ steps.observation.outputs.artifact-id }}",
            download_step,
        )
        self.assertIn("github-token: ${{ github.token }}", download_step)
        self.assertIn("run-id: ${{ github.run_id }}", download_step)
        self.assertIn(
            "path: build/federated-catalog-runtime-observation-sealed-input",
            download_step,
        )

        seal_step = self.runtime_workflow[seal:signed_upload]
        self.assertIn(
            "--observation-dir build/federated-catalog-runtime-observation-sealed-input",
            seal_step,
        )
        self.assertNotIn(
            "--observation-dir build/federated-catalog-runtime-observation ", seal_step
        )
        self.assertNotIn("CRYPTAD_FEDERATION_OBSERVER_PRIVATE_KEY", download_step)

    def test_runtimeProducer_whenAdapterRuns_expectExactExecutableReauthenticated(self) -> None:
        topology = self.runtime_workflow.index("Exercise protected federation topology")
        seal = self.runtime_workflow.index(
            "Seal runtime receipt with independently approved observer key"
        )
        upload = self.runtime_workflow.index("Upload exact signed runtime receipt", seal)
        topology_step = self.runtime_workflow[topology:seal]
        seal_step = self.runtime_workflow[seal:upload]
        for step, operation in ((topology_step, "run"), (seal_step, "seal")):
            self.assertIn(
                'resolved_adapter="$(command -v cryptad-federated-catalog-runtime || true)"',
                step,
            )
            self.assertIn(
                'adapter="$(mktemp "$RUNNER_TEMP/cryptad-federated-catalog-runtime.XXXXXX")"',
                step,
            )
            self.assertIn('cp -- "$resolved_adapter" "$adapter"', step)
            self.assertIn('sha256sum "$adapter"', step)
            self.assertIn(f'"$adapter" {operation}', step)
            self.assertLess(
                step.index('sha256sum "$adapter"'),
                step.index(f'"$adapter" {operation}'),
            )

    def test_workflow_when_environmentsExamined_expectSeparatedBoundaries(self) -> None:
        self.assertIn("environment: stable-1-0-federated-catalog-import", self.workflow)
        self.assertIn("environment: stable-1-0-federated-catalog-observation", self.workflow)
        self.assertIn("environment: stable-1-0-federated-catalog-runtime", self.workflow)
        self.assertIn("environment: stable-1-0-federated-catalog-closeout", self.workflow)

    def test_workflow_whenOperationSelected_expectClosedStageBoundaries(self) -> None:
        observation = self.workflow.index("\n  observation:")
        runtime = self.workflow.index("\n  runtime:", observation)
        observation_job = self.workflow[observation:runtime]
        self.assertIn(
            "if: contains(fromJSON('[\"observe\",\"runtime\",\"closeout\"]'), inputs.operation)",
            observation_job,
        )

    def test_workflow_when_commandsExamined_expectOneCertificationAuthority(self) -> None:
        self.assertGreaterEqual(self.workflow.count("stable-federated-catalog"), 7)
        for delegated_authority in (
            "stable-catalog-authority",
            "stable-third-party-pilot",
        ):
            self.assertNotRegex(
                self.workflow,
                re.compile(rf"certify\.py\s+{delegated_authority}"),
            )
        for forbidden in ("crypta-app catalog sign", "catalog publish", "gh release"):
            self.assertNotIn(forbidden, self.workflow)

    def test_workflow_when_archiveExamined_expectClosedConfinementBounds(self) -> None:
        self.assertIn("len(members) > 256", self.workflow)
        self.assertIn("64 * 1024 * 1024", self.workflow)
        self.assertIn("destination not in target.parents", self.workflow)
        self.assertIn("include-hidden-files: false", self.workflow)

    def test_selfTest_whenFederationSuiteSelected_expectWorkflowContractIncluded(self) -> None:
        self.assertIn(
            "cryptad_certification.tests.test_stable_federated_catalog_workflow",
            selftest.SUITE_MODULES["stable-federated-catalog"],
        )


if __name__ == "__main__":
    unittest.main()
