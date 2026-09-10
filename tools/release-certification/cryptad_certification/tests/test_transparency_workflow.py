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

    def test_deployment_requires_current_checkpoint_before_build_and_packaging(self):
        workflow = (Path(__file__).resolve().parents[4] / '.github/workflows/public-ecosystem-transparency.yml').read_text()
        build = workflow.split('  build:\n', 1)[1].split('  transfer-verify:\n', 1)[0]
        transfer = workflow.split('  transfer-verify:\n', 1)[1].split('  deploy:\n', 1)[0]
        self.assertLess(build.index('--mode checkpoint'), build.index('--mode build'))
        self.assertLess(transfer.index('--mode checkpoint'), transfer.index('actions/upload-pages-artifact'))
        for stage in (build, transfer):
            self.assertIn('--previous-bundle "$RUNNER_TEMP/previous-site" --previous-manifest-digest "$PRIOR_MANIFEST"', stage)
            self.assertIn('"${history[@]}"', stage)
            self.assertNotIn('continue-on-error', stage)
        self.assertIn('vars.PUBLIC_ECOSYSTEM_CURRENT_MANIFEST_DIGEST', build)
        self.assertIn('vars.PUBLIC_ECOSYSTEM_BOOTSTRAP_MANIFEST_DIGEST', build)
        self.assertIn('--expected-manifest-digest "$BOOTSTRAP_MANIFEST"', build)
        self.assertIn('test "sha256:$EXPECTED_DIGEST" = "$BOOTSTRAP_MANIFEST"', transfer)

    def test_actual_workflow_build_and_transfer_enforce_checkpoint(self):
        import os
        import shutil
        import subprocess
        import sys
        import tempfile
        from cryptad_certification import transparency_bundle as bundle, transparency_sources as sources
        workflow = (Path(__file__).resolve().parents[4] / '.github/workflows/public-ecosystem-transparency.yml').read_text()
        def script(name):
            step = workflow.split('      - name: '+name+'\n', 1)[1].split('      - ', 1)[0]
            return '\n'.join(line[10:] for line in step.split('        run: |\n', 1)[1].splitlines())
        checkpoint = script('Verify approved current public checkpoint or first-publication absence')
        render = script('Render reviewed production successor offline')
        transfer = script('Recheck current public checkpoint and successor before Pages packaging')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            published = root/'published'
            package = sources.collect({'schemaVersion':1,'mode':'production','asOf':'2026-09-10T00:00:00Z','sources':[]}, root)
            bundle.build(package, published)
            prior = bundle.digest((published/bundle.MANIFEST).read_bytes())
            shim = root/'python3'
            shim.write_text('#!'+sys.executable+'\n'+
                'import os,sys\nfrom pathlib import Path\nsys.path.insert(0,str(Path("tools/release-certification").resolve()))\n'+
                'from cryptad_certification import transparency_sources as s\n'+
                'from cryptad_certification.cli import main\n'+
                'def fetch(url,limit,base):\n    name=url.removeprefix(base)\n    return (Path(os.environ["SYNTHETIC_PUBLISHED"])/name).read_bytes()\n'+
                's.fetch_site=fetch\nsys.exit(main(sys.argv[2:]))\n')
            shim.chmod(0o700)
            for time, accepted in (('2026-09-09T00:00:00Z', False), ('2026-09-11T00:00:00Z', True)):
                runner = root/('accepted' if accepted else 'rollback')
                runner.mkdir()
                env = {**os.environ, 'PATH':str(root)+os.pathsep+os.environ['PATH'],
                       'RUNNER_TEMP':str(runner), 'GITHUB_OUTPUT':str(runner/'outputs'),
                       'PRIOR_MANIFEST':prior, 'BOOTSTRAP_MANIFEST':'',
                       'SITE_URL':'https://example.org/site/', 'SNAPSHOT_TIME':time,
                       'SYNTHETIC_PUBLISHED':str(published)}
                result = subprocess.run(['bash','-e','-c',checkpoint+'\n'+render], env=env, capture_output=True)
                self.assertEqual(result.returncode == 0, accepted, result.stdout.decode())
                if not accepted:
                    self.assertFalse((runner/'public-site').exists())
                    continue
                transfer_root = root/'transfer'
                transfer_root.mkdir()
                shutil.copytree(runner/'public-site', transfer_root/'public-site')
                env['RUNNER_TEMP'] = str(transfer_root)
                env['EXPECTED_DIGEST'] = bundle.digest((transfer_root/'public-site'/bundle.MANIFEST).read_bytes())[7:]
                result = subprocess.run(['bash','-e','-c',transfer], env=env, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stdout.decode())
                shutil.rmtree(transfer_root/'previous-site')
                (published/'index.html').write_bytes(b'changed-current-deployment')
                result = subprocess.run(['bash','-e','-c',transfer], env=env, capture_output=True)
                self.assertNotEqual(result.returncode, 0)

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
