const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const source = fs.readFileSync(process.argv[2], 'utf8');
const elements = new Map();
const buttons = new Map();
const calls = [];
let bootstrapCalls = 0;
let ready;
let deferred;
const canary = '<script>globalThis.executed=true</script><img src="https://example.invalid/canary" onerror="executed=true">';
class Element {
  constructor() { this.value = ''; this.textContent = ''; this.disabled = false; this.listeners = {}; this.dataset = {}; }
  addEventListener(name, callback) { this.listeners[name] = callback; }
  set innerHTML(_) { throw new Error('HTML injection attempted'); }
  get innerHTML() { throw new Error('HTML inspection attempted'); }
}
const element = id => {
  if (!elements.has(id)) elements.set(id, new Element());
  return elements.get(id);
};
for (const command of ['initialize', 'export-contact', 'import-contact', 'approve-contact', 'revoke-contact', 'save-draft', 'preview-send', 'confirm-send', 'import-reference', 'retry', 'read', 'status', 'backup', 'restore']) {
  const button = command === 'confirm-send' ? element('confirm-send') : new Element();
  button.dataset.command = command;
  buttons.set(command, button);
}
const context = {
  TextEncoder,
  document: {
    addEventListener(name, callback) { assert.equal(name, 'DOMContentLoaded'); ready = callback; },
    getElementById: element,
    querySelectorAll(selector) { assert.equal(selector, '[data-command]'); return [...buttons.values()]; },
  },
  CryptaPlatform: {
    bootstrap: { async load() { bootstrapCalls++; } },
    mail: { async command(command, payload) {
      calls.push({command, payload: JSON.parse(JSON.stringify(payload))});
      if (deferred) await deferred;
      if (command === 'read') return {status: 'verified-local-copy', body: canary, subject: canary};
      if (command === 'preview-send') return {approval: 'synthetic-approval', body: canary};
      if (command === 'import-contact') return {fingerprint: 'synthetic-full-fingerprint', status: 'compare-fingerprint-out-of-band'};
      return {status: 'synthetic-result'};
    } },
  },
  fetch() { throw new Error('Direct automatic network access'); },
  XMLHttpRequest() { throw new Error('Direct automatic network access'); },
  Image() { throw new Error('Remote image attempted'); },
};
for (const storage of ['localStorage', 'sessionStorage']) {
  Object.defineProperty(context, storage, {get() { throw new Error('Persistent browser storage attempted'); }});
}
context.window = context;
vm.createContext(context);
vm.runInContext(source, context);
const settle = () => new Promise(resolve => setImmediate(resolve));
const click = async command => { buttons.get(command).listeners.click(); await settle(); };

(async () => {
  ready();
  await settle();
  assert.equal(calls.length, 0);
  assert.equal(bootstrapCalls, 0);
  element('messageId').value = 'synthetic-message-id';
  await click('read');
  assert.equal(calls.length, 1);
  assert.equal(calls[0].command, 'read');
  assert.equal(JSON.parse(element('result').textContent).body, canary);
  assert.equal(context.executed, undefined);
  await click('import-contact');
  assert.equal(element('fingerprint').value, 'synthetic-full-fingerprint');
  assert.equal(calls.some(call => ['confirm-send', 'import-reference'].includes(call.command)), false);
  await click('preview-send');
  assert.equal(element('confirm-send').disabled, false);
  element('body').listeners.input();
  assert.equal(element('confirm-send').disabled, true);
  const before = calls.length;
  await click('confirm-send');
  assert.equal(calls.length, before);
  await click('preview-send');
  element('fingerprint').listeners.input();
  await click('confirm-send');
  assert.equal(calls.filter(call => call.command === 'confirm-send').length, 0);
  await click('preview-send');
  await click('confirm-send');
  assert.equal(calls.at(-1).payload.approval, 'synthetic-approval');
  element('body').value = '\u2603'.repeat(6000);
  const quotaBefore = calls.length;
  await click('save-draft');
  assert.equal(calls.length, quotaBefore);
  element('reference').value = 'CHK@synthetic-only';
  await click('import-reference');
  assert.equal(calls.at(-1).payload.confirmed, 'yes');
  let previewRelease;
  deferred = new Promise(resolve => { previewRelease = resolve; });
  buttons.get('preview-send').listeners.click();
  await settle();
  element('subject').listeners.input();
  previewRelease();
  await settle();
  assert.equal(element('confirm-send').disabled, true);
  deferred = null;
  let release;
  deferred = new Promise(resolve => { release = resolve; });
  buttons.get('status').listeners.click();
  await settle();
  const pendingCount = calls.length;
  await click('initialize');
  assert.equal(calls.length, pendingCount);
  release();
  await settle();
})().catch(() => { process.stderr.write('mail-ui-behavior-failed\n'); process.exitCode = 1; });
