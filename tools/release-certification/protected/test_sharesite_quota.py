"""Offline ordinary-record HTTP contract checks for the actual Sharesite quota driver."""
import json
from pathlib import Path
import shutil
import subprocess
import unittest


DRIVER = Path(__file__).with_name('sharesite_runtime_driver.cjs')
PROGRAM = r'''
const http = require('node:http');
const {EventEmitter} = require('node:events');
const mode = process.argv[2];
const records = new Map(mode === 'preexisting' ? [['case-01', 'existing']] : []);
const calls = [];
http.request = (options, callback) => {
  const req = new EventEmitter();
  req.destroy = () => req.emit('error', new Error('offline-destroy'));
  req.end = body => queueMicrotask(() => {
    const form = new URLSearchParams(body || '');
    const key = options.method === 'POST' ? form.get('key') : options.path.split('/').pop();
    calls.push({method: options.method, key, hasPrecondition: form.has('ifMatchSha256')});
    let status = 200, value = {record: {key}};
    const deny = (code, number) => {status = number; value = {error: {code}};};
    if (options.path.endsWith('/app-data/status')) {
      value = {status:{quota:{manifestDataQuotaBytes:4096,manifestDataQuotaEnforced:true},limits:{maxRecordBytes:1024}}};
    } else if (options.method === 'GET') {
      if (mode === 'lookup-denied') deny('app_data_forbidden', 403);
      else if (!records.has(key)) deny('app_data_record_not_found', 404);
    } else if (options.method === 'POST') {
      // Ordinary putRecord requires a supplied digest to match an existing record.
      if (form.has('ifMatchSha256') || mode === 'write-conflict') deny('app_data_write_conflict', 409);
      else if (records.size === 2) deny('app_data_quota_exceeded', 413);
      else {records.set(key, form.get('valueText')); status = 201;}
    } else if (options.method === 'DELETE') records.delete(key);
    const response = new EventEmitter(); response.statusCode = status;
    callback(response);
    response.emit('data', Buffer.from(JSON.stringify(value)));
    response.emit('end');
  });
  return req;
};
const driver = require(process.argv[1]);
(async () => {
  let completed = false;
  try {
    if (mode === 'shared-stage') {
      const fs = require('node:fs'), crypto = require('node:crypto');
      const script = Buffer.from(`window.SitePublisherDrafts = {
        parsePackage: async () => ({dataset:{drafts:[{id:'case',text:'synthetic'}]}}),
        controller(api) {let state={operations:[],drafts:[]};return {
          load: async () => {await api.data.status();return state;},
          previewRestore: async () => {state={operations:[],drafts:[{id:'case',text:'synthetic'}]};},
          commit: async () => {await api.data.status();}
        };}
      };`);
      const read = fs.readFileSync;
      fs.readFileSync = (path, ...args) => path === '/fixture-controller' ? script
        : ['/fixture-migration','/fixture-backup'].includes(path) ? Buffer.from('{}') : read(path,...args);
      await driver.run({stage:'restore',api:'http://127.0.0.1:8888/api/v1',origin:'http://127.0.0.1:9999/',session:'synthetic',
        maximumRequests:4,controllerFile:'/fixture-controller',controllerDigest:'sha256:'+crypto.createHash('sha256').update(script).digest('hex'),
        migrationFile:'/fixture-migration',retainedBackupFile:'/fixture-backup'});
    } else await driver.observeQuota({api:'http://127.0.0.1:8888/api/v1', origin:'http://127.0.0.1:9999/', session:'synthetic', maximumRequests:mode === 'limited' ? 1 : mode === 'missing-limit' ? undefined : 256},
      {quota:{manifestDataQuotaBytes:4096,manifestDataQuotaEnforced:true},limits:{maxRecordBytes:1024}});
    completed = true;
  } catch (_) {}
  process.stdout.write(JSON.stringify({completed,calls,retained:[...records.entries()]}));
})().catch(() => {process.exitCode = 1;});
'''


@unittest.skipUnless(shutil.which('node'), 'Node required for offline JavaScript driver checks')
class SharesiteQuotaTest(unittest.TestCase):
    def execute(self, mode):
        result = subprocess.run([shutil.which('node'), '-e', PROGRAM, str(DRIVER), mode],
                                capture_output=True, check=True, timeout=10)
        return json.loads(result.stdout)

    def test_fresh_records_reach_quota_denial_and_only_created_keys_are_cleaned(self):
        result = self.execute('fresh')
        self.assertTrue(result['completed'])
        self.assertEqual([], result['retained'])
        self.assertEqual(['GET', 'POST', 'GET', 'POST', 'GET', 'POST', 'DELETE', 'DELETE'],
                         [row['method'] for row in result['calls']])
        self.assertFalse(any(row['hasPrecondition'] for row in result['calls']))
        self.assertEqual(['case-00', 'case-01'],
                         [row['key'] for row in result['calls'] if row['method'] == 'DELETE'])

    def test_exhausted_request_allowance_blocks_the_next_http_operation(self):
        result = self.execute('limited')
        self.assertFalse(result['completed'])
        self.assertEqual(['GET'], [row['method'] for row in result['calls']])
        self.assertEqual([], result['retained'])

    def test_restore_and_quota_share_one_stage_request_allowance(self):
        result = self.execute('shared-stage')
        self.assertFalse(result['completed'])
        self.assertEqual(['status'] * 4, [row['key'] for row in result['calls']])
        self.assertEqual([], result['retained'])

    def test_missing_request_allowance_prevents_any_http_operation(self):
        result = self.execute('missing-limit')
        self.assertFalse(result['completed'])
        self.assertEqual([], result['calls'])

    def test_existing_fixture_is_preserved_and_prior_owned_fixture_is_cleaned(self):
        result = self.execute('preexisting')
        self.assertFalse(result['completed'])
        self.assertEqual([['case-01', 'existing']], result['retained'])
        self.assertEqual(['GET', 'POST', 'GET', 'DELETE'], [row['method'] for row in result['calls']])

    def test_failed_absence_check_prevents_any_write(self):
        result = self.execute('lookup-denied')
        self.assertFalse(result['completed'])
        self.assertEqual(['GET'], [row['method'] for row in result['calls']])

    def test_write_conflict_is_not_reported_as_quota_denial(self):
        result = self.execute('write-conflict')
        self.assertFalse(result['completed'])
        self.assertEqual(['GET', 'POST'], [row['method'] for row in result['calls']])
