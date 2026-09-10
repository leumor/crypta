"""Guard the static host reference workflow's publication boundary."""
from pathlib import Path
import re
import unittest


class TransparencyWorkflowTest(unittest.TestCase):
    def test_workflow_has_no_privilege_on_pr_or_render(self):
        workflow = (Path(__file__).resolve().parents[4] / '.github/workflows/public-ecosystem-transparency.yml').read_text()
        self.assertNotIn('pull_request_target', workflow)
        self.assertNotIn('contents: write', workflow)
        self.assertNotIn('always()', workflow)
        self.assertNotIn('configure-pages', workflow)
        self.assertIn('permissions: {}', workflow)
        self.assertIn('cancel-in-progress: false', workflow)
        self.assertEqual(workflow.count('pages: write'), 1)
        self.assertEqual(workflow.count('id-token: write'), 1)
        for action in re.findall(r'uses:\s*([^\s]+)', workflow):
            self.assertRegex(action, r'^[\w/-]+@[0-9a-f]{40}$')
        deploy = workflow.split('  deploy:\n', 1)[1].split('  observe:\n', 1)[0]
        self.assertIn("github.event_name == 'workflow_dispatch'", deploy)
        self.assertIn("github.ref == 'refs/heads/develop'", deploy)
        self.assertIn('needs: transfer-verify', deploy)
        self.assertIn('name: github-pages', deploy)
        self.assertNotIn('checkout', deploy)
        self.assertNotIn('run:', deploy)
        transfer = workflow.split('  transfer-verify:\n', 1)[1].split('  deploy:\n', 1)[0]
        self.assertLess(transfer.index('--mode verify --production'), transfer.index('actions/upload-pages-artifact'))
        self.assertIn('EXPECTED_DIGEST', transfer)
        self.assertNotIn('--mode build', transfer)
        self.assertIn('path: ${{ runner.temp }}/public-site', transfer)
        build = workflow.split('  build:\n', 1)[1].split('  transfer-verify:\n', 1)[0]
        self.assertIn('--selection tools/ecosystem-transparency/production-selection.json', build)
        self.assertIn('ref: ${{ github.sha }}', build)
        self.assertIn('persist-credentials: false', build)
        self.assertNotIn('--demo', build)
        self.assertNotIn('--mode collect', build)

    def test_observation_report_survives_failed_step_without_masking_failure(self):
        import os
        import subprocess
        import tempfile
        workflow = (Path(__file__).resolve().parents[4] / '.github/workflows/public-ecosystem-transparency.yml').read_text()
        observe = workflow.split('  observe:\n', 1)[1]
        run = observe.split('        run: |\n', 1)[1].split('      - name: Retain', 1)[0]
        script = '\n'.join(line[10:] for line in run.splitlines())
        self.assertIn("if: ${{ !cancelled() && steps.observation.outputs.report_ready == 'true' }}", observe)
        self.assertNotIn('continue-on-error', observe)
        retention = observe.split('      - name: Retain', 1)[1]
        self.assertIn('path: ${{ runner.temp }}/public-observation.json', retention)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shim = root/'python3'
            shim.write_text('#!/bin/bash\nif [[ " $* " == *" --mode verify "* ]]; then exit "$VERIFY_EXIT"; fi\nif [ "$EMIT_REPORT" = 1 ]; then echo \'{"status":"conflict","conflictingFiles":1}\'; fi\nexit "$OBSERVE_EXIT"\n')
            shim.chmod(0o700)
            for verify_exit, observer_exit, emits, ready in ((0,0,1,True),(0,2,1,True),(0,2,0,False),(2,0,1,False)):
                with self.subTest(verify=verify_exit, observer=observer_exit, emits=emits):
                    output = root/'outputs'
                    output.write_text('')
                    (root/'public-observation.json').unlink(missing_ok=True)
                    result = subprocess.run(['bash','-e','-c',script], env={**os.environ,
                        'PATH':str(root)+os.pathsep+os.environ['PATH'], 'RUNNER_TEMP':str(root),
                        'GITHUB_OUTPUT':str(output), 'EXPECTED_DIGEST':'a'*64,
                        'SITE_URL':'https://example.org/site/', 'VERIFY_EXIT':str(verify_exit),
                        'OBSERVE_EXIT':str(observer_exit), 'EMIT_REPORT':str(emits)}, capture_output=True)
                    self.assertEqual(result.returncode, verify_exit or observer_exit)
                    self.assertEqual('report_ready=true' in output.read_text(), ready)


if __name__ == '__main__':
    unittest.main()
