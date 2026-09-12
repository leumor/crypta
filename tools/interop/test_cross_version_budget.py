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

    def test_typed_resource_units_and_unknown_runtime_are_never_zero(self):
        with tempfile.TemporaryDirectory() as directory:
            proc, identity, executable = self.fixture_proc(Path(directory))
            node = proc / '123'
            fields = ['0'] * 30
            fields[11], fields[12], fields[19] = '200', '50', '42'
            (node / 'stat').write_text('123 (synthetic JVM) ' + ' '.join(fields))
            snapshot = {'jvm': {'metrics': {'heapUsedBytes': 3000, 'gcTimeMillis': 7}},
                        'contentFetch': {'known': False, 'inFlightOperations': 0}}
            with patch.object(budget.os, 'sysconf', return_value=100):
                sample = budget.measure_runtime_sample(identity, executable_digest=executable,
                    proc_root=proc, runtime_snapshot=snapshot)
            self.assertEqual(102400, sample['metrics']['rssBytes'])
            self.assertEqual(2500000000, sample['metrics']['cpuNanos'])
            self.assertEqual(7, sample['metrics']['gcMillis'])
            self.assertEqual(3000, sample['metrics']['heapUsedBytes'])
            self.assertIsNone(sample['metrics']['inFlight'])
            self.assertIsNone(sample['metrics']['heapMaxBytes'])
            self.assertIn('inFlight', sample['unavailable'])
            self.assertNotIn('selected-boot', json.dumps(sample))

    def test_typed_runtime_metric_illegal_counts_and_mid_read_restart_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            proc, identity, executable = self.fixture_proc(Path(directory))
            for value in (-1, float('nan'), float('inf'), 2**63, True, '1024'):
                with self.subTest(value=value), self.assertRaisesRegex(budget.BudgetObservationError, 'metric-invalid'):
                    budget.measure_runtime_sample(identity, executable_digest=executable, proc_root=proc,
                        runtime_snapshot={'jvm': {'metrics': {'heapUsedBytes': value}}})
            def restart():
                fields = ['0'] * 30
                fields[19] = '43'
                (proc / '123/stat').write_text('123 (synthetic JVM) ' + ' '.join(fields))
                return {'jvm': {'metrics': {}}}
            with self.assertRaisesRegex(budget.BudgetObservationError, 'changed-during-sample'):
                budget.measure_runtime_sample(identity, executable_digest=executable,
                    proc_root=proc, runtime_snapshot=restart)

    def test_resource_transient_missing_rss_and_truncated_queue_are_unavailable(self):
        with tempfile.TemporaryDirectory() as directory:
            proc, identity, executable = self.fixture_proc(Path(directory))
            (proc / '123/status').unlink()
            result = budget.measure_runtime_sample(identity, executable_digest=executable, proc_root=proc,
                runtime_snapshot={'contentFetch': {'known': True, 'truncated': True,
                                                   'inFlightOperations': 0, 'oldestActiveAgeMillis': 0}})
            self.assertIsNone(result['metrics']['rssBytes'])
            self.assertIsNone(result['metrics']['osThreads'])
            self.assertIsNone(result['metrics']['inFlight'])
            self.assertEqual(3, result['metrics']['fileDescriptors'])

    @unittest.skipUnless(shutil.which('node'), 'Node needed for fixed-driver offline execution')
    def test_request_latency_is_frozen_at_terminal_callback_before_report_consumption(self):
        program = r'''const http=require('node:http'),{EventEmitter}=require('node:events');
let now=0n; process.hrtime.bigint=()=>now;
const pending=[],timers=[];
global.setTimeout=callback=>{timers.push(callback);return timers.length;};
global.clearTimeout=()=>{};
http.request=(url,options,callback)=>{const req=new EventEmitter();req.destroy=()=>{};req.end=()=>{};pending.push({req,callback});return req;};
const driver=require(process.argv[1]);
(async()=>{
 const input={base:'http://127.0.0.1:8888',origin:'http://127.0.0.1:9999',session:'private',uri:'USK@synthetic',expected:''};
 const first=driver.request(input,20000,true);
 now=10000000n; const second=driver.request(input,20000,true);
 now=20000000n; const third=driver.request(input,20000,true);
 now=17000000n+20000000n; pending[1].req.emit('error',Error('synthetic'));
 now=50000000n; const res=new EventEmitter();res.statusCode=504;pending[0].callback(res);
 res.emit('data',Buffer.from(JSON.stringify({error:{code:'content_fetch_timeout'}})));res.emit('end');
 now=20020000000n; timers[2]();
 now=90000000000n; pending[0].req.emit('error',Error('late duplicate'));
 process.stdout.write(JSON.stringify(await Promise.all([first,second,third])));
})();'''
        result = subprocess.run([shutil.which('node'), '-e', program, str(DRIVER)],
                                capture_output=True, check=True, timeout=10)
        reports = json.loads(result.stdout)
        self.assertEqual([50, 27, 20000], [report['latencyMillis'] for report in reports])
        self.assertEqual('content_fetch_timeout', reports[0]['errorCode'])
        self.assertEqual(['unexpected', 'transport-failed', 'transport-failed'],
                         [report['category'] for report in reports])

    def test_pressure_controller_preserves_driver_latency_and_rejects_invalid_values(self):
        import io
        import scheduler_pressure_runtime as adapter
        from unittest.mock import Mock

        def lane_for(values):
            lane = object.__new__(adapter.SchedulerLane)
            lane.driver_digest = budget.file_digest(DRIVER)
            lane.remaining = lambda seconds: seconds
            lane.sample = Mock()
            lane.work = {'outstanding': len(values), 'timedOut': 0, 'failed': 0, 'latencyMillis': []}
            lane.driver_processes = []
            for value in values:
                report = {'category': 'unexpected', 'httpStatus': 504,
                          'errorCode': 'content_fetch_timeout', 'latencyMillis': value}
                child = Mock(returncode=0, stdout=io.BytesIO(json.dumps(report).encode()),
                             stderr=io.BytesIO())
                child.poll.return_value = 0
                lane.driver_processes.append((child, 0))
            return lane

        lane = lane_for([50, 27])
        with patch.object(adapter.time, 'monotonic', return_value=90000):
            lane.finish_pressure()
        self.assertEqual([50, 27], lane.work['latencyMillis'])
        self.assertEqual(2, lane.work['timedOut'])
        self.assertEqual(0, lane.work['outstanding'])
        for invalid in (None, True, -1, 480001, 1.5, '50', float('nan'), float('inf')):
            with self.subTest(invalid=invalid):
                lane = lane_for([invalid])
                with self.assertRaisesRegex(adapter.runtime.RuntimeFailure, 'output-invalid'):
                    lane.finish_pressure()
                self.assertEqual([], lane.work['latencyMillis'])
                self.assertEqual(1, lane.work['outstanding'])

    @unittest.skipUnless(shutil.which('node'), 'Node needed for fixed-driver offline execution')
    def test_pressure_cli_rejects_expired_absolute_deadline_without_connecting(self):
        import select
        import socket
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            listener.listen()
            base = f'http://127.0.0.1:{listener.getsockname()[1]}'
            payload = {'mode': 'pressure', 'base': base, 'origin': 'http://127.0.0.1:1',
                       'session': 'synthetic', 'uri': 'USK@synthetic', 'expected': '',
                       'deadlineMillis': 1000, 'deadlineMonotonicNs': '1', 'activationDigest': None}
            result = subprocess.run([shutil.which('node'), str(DRIVER)], input=json.dumps(payload),
                                    capture_output=True, text=True, timeout=3)
            self.assertEqual(2, result.returncode)
            self.assertEqual('', result.stdout)
            self.assertEqual('budget-observer-failed', result.stderr)
            self.assertEqual([], select.select([listener], [], [], 0)[0])

    @unittest.skipUnless(shutil.which('node'), 'Node needed for fixed-driver offline execution')
    def test_pressure_request_clamps_fetch_and_transport_to_remaining_absolute_window(self):
        program = r'''const http=require('node:http'),{EventEmitter}=require('node:events');
let now=1000000000n,calls=0,body,delay,destroyed=false;
process.hrtime.bigint=()=>now;
let expire;global.setTimeout=(callback,ms)=>{expire=callback;delay=ms;return 1;};global.clearTimeout=()=>{};
http.request=()=>{calls++;now+=20000000n;const req=new EventEmitter();req.end=value=>{body=value;};req.destroy=()=>{destroyed=true;};return req;};
const driver=require(process.argv[1]);
(async()=>{
 const input={mode:'pressure',base:'http://127.0.0.1:8888',origin:'http://127.0.0.1:9999',session:'synthetic',uri:'USK@synthetic',expected:'',deadlineMonotonicNs:'1750000000'};
 const pending=driver.request(input,20000,true);
 now=1750000000n;expire();const report=await pending;
 const fetchTimeout=Number(new URLSearchParams(body).get('timeoutMillis'));
 let rejected=0;
 for(const deadline of ['1750000000','1750999999','1']){
  try{await driver.request({...input,deadlineMonotonicNs:deadline},20000,true);}catch{rejected++;}
 }
 process.stdout.write(JSON.stringify({calls,fetchTimeout,delay,destroyed,report,rejected}));
})();'''
        result = subprocess.run([shutil.which('node'), '-e', program, str(DRIVER)],
                                capture_output=True, check=True, timeout=10)
        value = json.loads(result.stdout)
        self.assertEqual(1, value['calls'])
        self.assertEqual(650, value['fetchTimeout'])
        self.assertEqual(730, value['delay'])
        self.assertTrue(value['destroyed'])
        self.assertEqual(750, value['report']['latencyMillis'])
        self.assertEqual('transport-failed', value['report']['category'])
        self.assertEqual(3, value['rejected'])

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
