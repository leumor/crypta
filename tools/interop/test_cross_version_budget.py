"""No network: exercise the fixed JS recipe with fake transport and real local process files."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import cross_version_budget as budget

DRIVER = Path(budget.__file__).with_name('cross_version_budget_driver.cjs')


class BudgetObserverTest(unittest.TestCase):
    def report(self):
        return {'schemaVersion': 1, 'requests': 38,
                'counts': {'success': 21, 'concurrency-limited': 14, 'rate-limited': 3,
                           'forbidden': 0, 'body-mismatch': 0, 'unexpected': 0, 'transport-failed': 0},
                'recovery': 'success', 'backoffMillis': 61000}

    def test_successful_foreground_cases_still_cannot_pass_scheduler_budget_matrix(self):
        result = budget.summarize(self.report())
        self.assertEqual('partial', result['status'])
        self.assertEqual('observed', result['cases']['foreground-rate'])
        self.assertEqual('not-observed', result['cases']['scheduler-queue-pressure-precedence'])
        self.assertEqual('not-observed', result['fullAppBudgets'])

    def test_unknown_denial_and_forged_counts_cannot_satisfy_budget(self):
        report = self.report()
        report['counts']['other-secret'] = 1
        with self.assertRaises(budget.BudgetObservationError):
            budget.summarize(report)
        report = self.report()
        report['requests'] = 37
        with self.assertRaises(budget.BudgetObservationError):
            budget.summarize(report)

    def test_wrong_principal_and_mismatched_content_are_failures(self):
        report = self.report()
        report['counts']['success'] -= 1
        report['counts']['forbidden'] += 1
        self.assertEqual('fail', budget.summarize(report)['status'])

    def test_fixed_helper_uses_private_stdin_and_clean_environment(self):
        app = SimpleNamespace(app_id='feed-reader', base='http://127.0.0.1:8888', origin='http://127.0.0.1:9999', session='private-session')
        with tempfile.TemporaryDirectory() as directory:
            node = Path(directory) / 'node'
            node.write_bytes(b'pinned executable fixture')
            with patch.object(budget, 'run', return_value=json.dumps(self.report()).encode()) as child:
                result = budget.observe_budget(app, 'CHK@synthetic-fixture', b'private-synthetic', node, budget.file_digest(node), 185)
                self.assertEqual(38, result['requestCount'])
                arguments = child.call_args.args[0]
                self.assertEqual([str(node), str(DRIVER)], arguments)
                self.assertNotIn('private-session', ' '.join(arguments))
                self.assertEqual({'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'}, child.call_args.kwargs['environment'])
                payload = json.loads(child.call_args.kwargs['payload'])
                self.assertEqual('private-session', payload['session'])
                self.assertNotIn('private-session', json.dumps(result))
                self.assertNotIn('private-synthetic', json.dumps(result))
                with self.assertRaisesRegex(budget.BudgetObservationError, 'not-selected'):
                    budget.observe_budget(app, 'CHK@synthetic-fixture', b'private-synthetic', node, 'sha256:' + 'a' * 64, 185)

    def test_external_target_or_short_authority_is_rejected_before_helper(self):
        with patch.object(budget, 'run') as child:
            app = SimpleNamespace(app_id='mail-prototype')
            with self.assertRaises(budget.BudgetObservationError):
                budget.observe_budget(app, 'CHK@fixture', b'x', '/usr/bin/node', 'sha256:' + 'a' * 64, 185)
            with self.assertRaises(budget.BudgetObservationError):
                budget.target('http://example.com:9000')
            with self.assertRaises(budget.BudgetObservationError):
                budget.target('http://127.0.0.1:9000/redirect')
            child.assert_not_called()

    def fixture_proc(self, root):
        proc = root / 'proc'
        node = proc / '123'
        node.mkdir(parents=True)
        fields = ['0'] * 30
        fields[19] = '42'
        (node / 'stat').write_text('123 (synthetic JVM) ' + ' '.join(fields))
        (node / 'status').write_text('VmRSS:\t100 kB\nThreads:\t7\n')
        (node / 'exe').write_bytes(b'fixed java executable')
        (node / 'fd').mkdir()
        for number in range(3):
            (node / 'fd' / str(number)).write_text('private-path-not-read')
        (proc / 'sys/kernel/random').mkdir(parents=True)
        (proc / 'sys/kernel/random/boot_id').write_text('selected-boot')
        return proc, {'pid': 123, 'startTicks': 42, 'bootId': 'selected-boot'}, budget.file_digest(node / 'exe')

    def test_resources_bind_actual_jvm_and_export_only_counts_without_baseline_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            proc, identity, executable = self.fixture_proc(Path(directory))
            app = SimpleNamespace(request=lambda *args, **kwargs: (200, {'subscriptions': [{'private-key': 'never-export'}]}))
            result = budget.measure_resources(identity, app, jvm_executable_digest=executable, proc_root=proc)
            self.assertEqual({'memoryBytes': 102400, 'threads': 7, 'fileDescriptors': 3, 'queueDepth': None, 'subscriptions': 1}, result['metrics'])
            self.assertEqual('measured-but-uncompared', result['status'])
            self.assertIn('queueDepth', result['unavailable'])
            self.assertNotIn('never-export', json.dumps(result))
            with self.assertRaisesRegex(budget.BudgetObservationError, 'jvm-not-observed'):
                budget.measure_resources(identity, jvm_executable_digest='sha256:' + 'a' * 64, proc_root=proc)

    def test_resource_pid_reuse_or_exec_during_sample_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            proc, identity, executable = self.fixture_proc(Path(directory))
            def changed(*args, **kwargs):
                (proc / '123/exe').write_bytes(b'not the selected java')
                return 200, {'subscriptions': []}
            with self.assertRaisesRegex(budget.BudgetObservationError, 'changed-during-sample'):
                budget.measure_resources(identity, SimpleNamespace(request=changed), jvm_executable_digest=executable, proc_root=proc)

    @unittest.skipUnless(shutil.which('node'), 'Node needed for fixed-driver offline execution')
    def test_real_javascript_recipe_uses_fake_transport_only_and_bounds_cadence(self):
        program = r'''
const driver = require(process.argv[1]);
let calls = 0, time = 0, checks = 0;
(async () => {
  const observed = await driver.exercise({deadlineMillis:184000}, async () => {
    calls++;
    if (calls <= 2 || calls === 38) return 'success';
    if (calls <= 16) return 'concurrency-limited';
    if (calls >= 35) return 'rate-limited';
    return 'success';
  }, async ms => {time += ms;}, () => time, () => {checks++;});
  process.stdout.write(JSON.stringify({observed, calls, time, checks}));
})();
'''
        result = subprocess.run([shutil.which('node'), '-e', program, str(DRIVER)], capture_output=True, check=True, timeout=10)
        output = json.loads(result.stdout)
        self.assertEqual(38, output['calls'])
        self.assertEqual(61000, output['time'])
        self.assertGreater(output['checks'], 38)
        self.assertEqual('partial', budget.summarize(output['observed'])['status'])

    @unittest.skipUnless(shutil.which('node'), 'Node needed for fixed-driver offline execution')
    def test_production_http_adapter_rejects_redirects_and_oversized_response_without_network(self):
        program = r'''const http=require('node:http'),{EventEmitter}=require('node:events');
let mode='redirect',options;
http.request=(url,selected,callback)=>{options=selected;const req=new EventEmitter();req.destroy=()=>{};req.end=()=>queueMicrotask(()=>{const res=new EventEmitter();res.statusCode=mode==='redirect'?302:200;callback(res);if(mode==='redirect')res.emit('data',Buffer.from('{}'));else res.emit('data',Buffer.alloc(32769));res.emit('end');});return req;};
const driver=require(process.argv[1]);
(async()=>{const input={base:'http://127.0.0.1:8888',origin:'http://127.0.0.1:9999',session:'private',uri:'CHK@synthetic',expected:'eA=='};const redirect=await driver.request(input,100);mode='oversized';const oversized=await driver.request(input,100);process.stdout.write(JSON.stringify({redirect,oversized,method:options.method,ownSession:options.headers['X-Crypta-App-Session']==='private',hasHostCredential:JSON.stringify(options).includes('formPassword')}));})();'''
        result = subprocess.run([shutil.which('node'), '-e', program, str(DRIVER)], capture_output=True, check=True, timeout=10)
        value = json.loads(result.stdout)
        self.assertEqual('unexpected', value['redirect'])
        self.assertEqual('transport-failed', value['oversized'])
        self.assertEqual('POST', value['method'])
        self.assertTrue(value['ownSession'])
        self.assertFalse(value['hasHostCredential'])

    @unittest.skipUnless(shutil.which('node'), 'Node needed for fixed-driver offline execution')
    def test_driver_rejects_changed_authority_before_next_request_and_distinguishes_429(self):
        program = r'''
const driver = require(process.argv[1]);
(async () => {
  let checks=0,calls=0,blocked=false;
  try { await driver.exercise({deadlineMillis:184000}, async () => {calls++;return 'success';}, async()=>{}, ()=>0, ()=>{if(++checks>16)throw Error('changed');}); }
  catch {blocked=true;}
  process.stdout.write(JSON.stringify({blocked,calls,ordinary:driver.classify(429,{error:{code:'unrelated'}},''),concurrency:driver.classify(429,{error:{code:'network_budget_concurrency_limited'}},'')}));
})();
'''
        result = subprocess.run([shutil.which('node'), '-e', program, str(DRIVER)], capture_output=True, check=True, timeout=10)
        value = json.loads(result.stdout)
        self.assertTrue(value['blocked'])
        self.assertEqual(16, value['calls'])
        self.assertEqual('unexpected', value['ordinary'])
        self.assertEqual('concurrency-limited', value['concurrency'])


if __name__ == '__main__':
    unittest.main()
