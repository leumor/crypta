'use strict';
// Fixed own-app foreground-budget observer. Private inputs arrive only through stdin.
const http = require('node:http');
const fs = require('node:fs');
const crypto = require('node:crypto');
const ACTIVATION = '/var/lib/cryptad-cross-version-authority/activation.json';
const CATEGORIES = ['success', 'concurrency-limited', 'rate-limited', 'forbidden', 'body-mismatch', 'unexpected', 'transport-failed'];

function activation(input) {
  if (!input.activationDigest) return;
  const stat = fs.lstatSync(ACTIVATION);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.uid !== 0 || (stat.mode & 0o022) || stat.size > 4 * 1024 * 1024) throw Error('authority');
  const bytes = fs.readFileSync(ACTIVATION);
  const actual = 'sha256:' + crypto.createHash('sha256').update(bytes).digest('hex');
  if (actual !== input.activationDigest) throw Error('authority');
  const record = JSON.parse(bytes);
  if (process.hrtime.bigint() + 1000000n >= BigInt(record.deadlineMonotonicNs)) throw Error('authority');
}
function classify(status, payload, expected) {
  if (status === 429 && payload?.error?.code === 'network_budget_concurrency_limited') return 'concurrency-limited';
  if (status === 429 && payload?.error?.code === 'content_fetch_budget_exhausted') return 'rate-limited';
  if (status === 401 || status === 403) return 'forbidden';
  if (status !== 200) return 'unexpected';
  return payload?.format === 'base64' && payload?.contentBase64 === expected ? 'success' : 'body-mismatch';
}
function request(input, timeout) {
  return new Promise(resolve => {
    const body = new URLSearchParams({uri: input.uri, maxBytes: '8192', timeoutMillis: String(Math.max(1, Math.floor(timeout - 100))), format: 'base64', purpose: 'cross-version-synthetic-budget'}).toString();
    let done = false;
    const finish = value => { if (!done) { done = true; clearTimeout(timer); resolve(value); } };
    const req = http.request(input.base + '/api/v1/content/fetch', {
      method: 'POST', agent: false,
      headers: {'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body),
                'Origin': input.origin, 'X-Crypta-App-Session': input.session, 'Accept': 'application/json'}
    }, response => {
      const chunks = []; let bytes = 0;
      response.on('data', chunk => { bytes += chunk.length; if (bytes > 32768) { req.destroy(); finish('transport-failed'); } else chunks.push(chunk); });
      response.on('error', () => finish('transport-failed'));
      response.on('end', () => {
        try { finish(classify(response.statusCode, JSON.parse(Buffer.concat(chunks).toString('utf8')), input.expected)); }
        catch { finish('transport-failed'); }
      });
    });
    const timer = setTimeout(() => { req.destroy(); finish('transport-failed'); }, timeout);
    req.on('error', () => finish('transport-failed'));
    req.end(body);
  });
}
async function exercise(input, transport = request, pause = ms => new Promise(resolve => setTimeout(resolve, ms)), monotonic = () => Number(process.hrtime.bigint()) / 1e6, check = activation) {
  const deadline = Math.min(monotonic() + input.deadlineMillis, input.deadlineMonotonicNs ? Number(BigInt(input.deadlineMonotonicNs)) / 1e6 : Infinity);
  let requests = 0;
  const counts = Object.fromEntries(CATEGORIES.map(value => [value, 0]));
  function gate() { check(input); if (monotonic() >= deadline) throw Error('deadline'); }
  async function one() {
    gate();
    if (++requests > 38) throw Error('budget');
    const outcome = await transport(input, Math.min(5000, deadline - monotonic()));
    if (!Object.hasOwn(counts, outcome)) throw Error('outcome');
    counts[outcome]++;
    return outcome;
  }
  await Promise.all(Array.from({length: 16}, () => one()));
  for (let i = 0; i < 21; i++) {
    const result = await one();
    if (result === 'forbidden' || result === 'body-mismatch') break;
  }
  // Fixed-window rate denial has no Retry-After field. Wait at most one default window;
  // a changed/deployed quota policy may still deny, which is an observed non-recovery.
  const backoff = counts['rate-limited'] ? 61000 : 100;
  for (let remaining = backoff; remaining > 0; remaining -= Math.min(remaining, 1000)) {
    gate(); await pause(Math.min(remaining, 1000));
  }
  gate();
  const recovery = await one();
  return {schemaVersion: 1, requests, counts, recovery, backoffMillis: backoff};
}
function validate(input) {
  if (!input || Object.keys(input).sort().join(',') !== 'activationDigest,base,deadlineMillis,deadlineMonotonicNs,expected,origin,session,uri') throw Error('input');
  for (const key of ['base', 'origin']) {
    const url = new URL(input[key]);
    if (url.protocol !== 'http:' || !['127.0.0.1', '[::1]'].includes(url.hostname) || url.username || url.password || url.search || url.hash || url.pathname !== '/' || !url.port) throw Error('target');
  }
  if (input.origin === input.base || !Number.isInteger(input.deadlineMillis) || input.deadlineMillis < 1000 || input.deadlineMillis > 185000 || typeof input.session !== 'string' || !input.session || input.session.length > 4096 || /[\r\n]/.test(input.session)) throw Error('session');
  if (typeof input.uri !== 'string' || !/^CHK@[A-Za-z0-9~,._\/-]{1,2048}$/.test(input.uri) || !/^[A-Za-z0-9+/]*={0,2}$/.test(input.expected) || input.expected.length > 10924) throw Error('content');
  if (typeof input.deadlineMonotonicNs !== 'string' || !/^[0-9]{1,20}$/.test(input.deadlineMonotonicNs)) throw Error('deadline');
  if (input.activationDigest !== null && !/^sha256:[a-f0-9]{64}$/.test(input.activationDigest)) throw Error('authority');
}
module.exports = {exercise, classify, validate, request};
if (require.main === module) {
  let chunks = []; let length = 0;
  process.stdin.on('data', chunk => { length += chunk.length; if (length > 16384) process.exit(2); chunks.push(chunk); });
  process.stdin.on('end', async () => {
    try { const input = JSON.parse(Buffer.concat(chunks)); validate(input); const report = await exercise(input); process.stdout.write(JSON.stringify(report)); }
    catch { process.stderr.write('budget-observer-failed'); process.exitCode = 2; }
  });
}
