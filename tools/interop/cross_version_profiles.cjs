// Execute the selected production JavaScript controllers in separate VM contexts.
// These ports are local conformance ports, never a daemon or independent implementation.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {webcrypto} = require('node:crypto');

function implementation(root) {
  const element = () => ({value: '', textContent: '', children: [], dataset: {},
    append(...nodes) { this.children.push(...nodes); },
    replaceChildren(...nodes) { this.children = nodes; }, addEventListener() {},
    classList: {add() {}, remove() {}, toggle() {}}, elements: {namedItem: () => element()}});
  class VectorDate extends Date {
    constructor(...args) { super(...(args.length ? args : ['2026-06-01T00:00:00Z'])); }
  }
  const context = {Date: VectorDate, TextEncoder, TextDecoder, Uint8Array, URL, URLSearchParams,
    window: {crypto: webcrypto, atob, TextEncoder},
    document: {getElementById: element, addEventListener() {}, createElement: element,
      createTextNode: text => ({textContent: text})}};
  vm.createContext(context);
  vm.runInContext(fs.readFileSync(path.join(root, 'sdk.js'), 'utf8'), context, {timeout: 5000});
  context.CryptaPlatform = context.window.CryptaPlatform;
  function app(file, name, exports) {
    const source = fs.readFileSync(path.join(root, file), 'utf8');
    const end = source.lastIndexOf('})();');
    assert.ok(end > 0);
    vm.runInContext(source.slice(0, end) + `window.${name} = {${exports}};\n` + source.slice(end),
      context, {timeout: 5000});
    return context.window[name];
  }
  const feed = app('feed.js', 'feed', 'parseCanonicalSnapshot,buildPublishedSnapshot');
  const social = app('social.js', 'social',
    'ensureSignedSocialMessage,verifySocialMessageSignature,importOutboxText,state');
  context.CryptaPlatform = Object.assign({}, context.CryptaPlatform,
    {data: {records: {putJson: async () => ({})}}});
  return {context, feed, social};
}

async function run(previousRoot, currentRoot, corpusRoot) {
  const previous = implementation(previousRoot), current = implementation(currentRoot);
  const cases = [];
  for (const [direction, producer, consumer] of [
    ['current-to-previous', current, previous], ['previous-to-current', previous, current]]) {
    const form = {elements: {namedItem: name => ({value: name === 'feedTitle' ? 'Synthetic feed' : ''})}};
    const generated = producer.feed.buildPublishedSnapshot(form, {title: 'Synthetic Unicode 雪😀'});
    const text = JSON.stringify(generated);
    const read = consumer.feed.parseCanonicalSnapshot(text);
    assert.equal(JSON.stringify(read), JSON.stringify(consumer.context.CryptaPlatform.feed.parseSnapshot(text)));
    assert.equal(read.items[0].title, 'Synthetic Unicode 雪😀');
    cases.push({caseId: 'feed-generated-' + direction, outcome: 'pass'});
  }
  const manifest = JSON.parse(fs.readFileSync(path.join(corpusRoot, 'manifest.json')));
  for (const [role, reader] of [['previous', previous], ['current', current]]) {
    for (const vector of manifest.cases) {
      if (vector.profileId === 'crypta.trust.statement.v1') continue;
      const bytes = fs.readFileSync(path.join(corpusRoot, vector.inputFile));
      let text;
      try { text = new TextDecoder('utf-8', {fatal: true}).decode(bytes); }
      catch (_) { assert.equal(vector.expectedDecodeOutcome, 'rejected'); continue; }
      if (vector.profileId === 'crypta.feed.snapshot.v1') {
        if (vector.expectedParseOutcome === 'rejected') {
          assert.throws(() => reader.feed.parseCanonicalSnapshot(text));
        } else {
          const expected = fs.readFileSync(path.join(corpusRoot, vector.expectedCanonicalBytesFile), 'utf8');
          assert.equal(JSON.stringify(reader.feed.parseCanonicalSnapshot(text)), expected);
        }
      } else if (vector.profileId === 'crypta.profile.v1') {
        await reader.context.CryptaPlatform.profile.verifyDocument(text);
        const changed = JSON.parse(text); changed.profile.displayName += 'tampered';
        await assert.rejects(() => reader.context.CryptaPlatform.profile.verifyDocument(changed));
      } else if (vector.profileId === 'crypta.social.message.v1') {
        const doc = JSON.parse(text);
        reader.social.ensureSignedSocialMessage(doc);
        await reader.social.verifySocialMessageSignature(doc);
        doc.message.body += 'tampered';
        await assert.rejects(() => reader.social.verifySocialMessageSignature(doc));
      } else if (vector.profileId === 'crypta.social.outbox.v1') {
        await reader.social.importOutboxText(text, {id: 'synthetic', label: 'Synthetic', uriHash: 'local-only'}, {});
        const count = reader.social.state.importedMessages.length;
        await reader.social.importOutboxText(text, {id: 'synthetic', label: 'Synthetic', uriHash: 'local-only'}, {});
        assert.equal(reader.social.state.importedMessages.length, count);
      } else throw new Error('unsupported profile');
      cases.push({caseId: role + '-' + vector.caseId, outcome: 'pass'});
    }
  }
  return {schemaVersion: 1, runtime: process.version, cases,
    evidenceLevel: 'local-source-javascript-comparison',
    topology: 'no-network', releaseEligible: false,
    unsupportedDirections: ['production-javascript-trust-reader', 'historical-java-producer',
      'historical-signed-profile-producer', 'independent-external-implementation']};
}

if (require.main === module) {
  run(...process.argv.slice(2)).then(value => process.stdout.write(JSON.stringify(value)))
    .catch(() => { process.stderr.write('profile-comparison-failed\n'); process.exitCode = 1; });
}
module.exports = {run};
