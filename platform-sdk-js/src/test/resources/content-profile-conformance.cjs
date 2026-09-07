const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { webcrypto, createHash, createPublicKey, verify } = require('node:crypto');
const root = path.resolve(process.argv[2] || '.');
const corpus = path.join(root, 'platform-api/src/test/resources/content-profile-conformance/v1');
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const read = file => fs.readFileSync(path.join(root, file), 'utf8');
const element = () => ({ value: '', textContent: '', children: [], dataset: {},
  append(...nodes) { this.children.push(...nodes); },
  replaceChildren(...nodes) { this.children = nodes; }, addEventListener() {},
  classList: { add() {}, remove() {}, toggle() {} }, elements: { namedItem: () => element() } });
const renderedText = node => typeof node === 'string' ? node :
  (node.textContent || '') + (node.children || []).map(renderedText).join('');
class FixedDate extends Date { constructor(...args) { super(...(args.length ? args : ['2026-06-01T00:00:00Z'])); } }
const context = { Date: FixedDate, TextEncoder, TextDecoder, Uint8Array, URL, URLSearchParams,
  window: { crypto: webcrypto, atob, TextEncoder }, document: { getElementById: element, addEventListener() {}, createElement: element, createTextNode: text => ({ textContent: text }) } };
vm.createContext(context);
vm.runInContext(read('platform-sdk-js/src/main/resources/network/crypta/platform/sdk/js/crypta-platform.js'), context);
context.CryptaPlatform = context.window.CryptaPlatform;
// Expose lexical functions only in the test VM; execute the entire unchanged app controller.
function app(file, name, exports) {
  const source = read(file);
  const end = source.lastIndexOf('})();');
  assert.ok(end > 0);
  vm.runInContext(source.slice(0, end) + `window.${name} = {${exports}};\n` + source.slice(end), context);
  return context.window[name];
}
const social = app('apps/social-inbox/src/staged/static/app.js', 'socialHarness',
  'ensureSignedSocialMessage,verifySocialMessageSignature,canonicalSocialMessagePayload,expectedSocialMessageId,importOutboxText,normalizeTrustScore,buildThreadIndex,state,parseJsonObject,trustAnnotationFailure,refreshTrustAnnotations,prepareProfileDocument,elements');
const feed = app('apps/feed-reader/src/staged/static/app.js', 'feedHarness', 'parseCanonicalSnapshot,buildPublishedSnapshot,normalizeEntry,snapshotFromTextResponse');
const profileApp = app('apps/profile-publisher/src/staged/static/app.js', 'profileHarness', 'createSignedProfileDocument,state');
context.CryptaPlatform = Object.assign({}, context.CryptaPlatform, {
  data: { records: { putJson: async () => ({}) } },
  vault: { identities: { createProfileDocument: async () => ({ profileDocument: JSON.parse(fs.readFileSync(path.join(corpus, 'profile/document.json'))) }) } }
});
const cases = [];
const tested = [];
function check(name, callback) { cases.push([name, callback]); }
const manifestBytes = fs.readFileSync(path.join(corpus, 'manifest.json'));
const manifest = JSON.parse(manifestBytes);
const ids = new Set();
for (const vector of manifest.cases) {
  assert.ok(!ids.has(vector.caseId)); ids.add(vector.caseId);
  const bytes = fs.readFileSync(path.join(corpus, vector.inputFile));
  assert.equal(bytes.length, vector.inputSize); assert.equal(hash(bytes), vector.inputDigest);
  check(vector.caseId, async () => {
    let text;
    try { text = new TextDecoder('utf-8', { fatal: true }).decode(bytes); }
    catch (error) {
      assert.equal(vector.expectedDecodeOutcome, 'rejected');
      assert.equal(vector.expectedParseOutcome, 'not-executed');
      return;
    }
    if (vector.profileId === 'crypta.trust.statement.v1') {
      // First-party reference assembly, separate from Java production canonicalizer.
      const document = JSON.parse(text), p = document.payload;
      const payload = { issuer: { identityId:p.issuer.identityId, publicKeyFingerprint:p.issuer.publicKeyFingerprint,
        publicKeyBase64:p.issuer.publicKeyBase64 }, subject:{kind:p.subject.kind,uri:p.subject.uri},
        context:p.context,score:p.score,confidence:p.confidence };
      for (const field of ['reason','tags','issuedAt','expiresAt']) if (Object.hasOwn(p,field)) payload[field]=p[field];
      const canonical = JSON.stringify(payload);
      assert.equal(canonical, fs.readFileSync(path.join(corpus,vector.expectedCanonicalBytesFile),'utf8'));
      const preimage = 'crypta.trust.statement.v1\n' + canonical;
      assert.equal(preimage, fs.readFileSync(path.join(corpus,vector.expectedSignaturePreimageFile),'utf8'));
      const keyBytes = Buffer.from(p.issuer.publicKeyBase64,'base64');
      assert.equal(hash(keyBytes),p.issuer.publicKeyFingerprint);
      assert.equal(document.signature.algorithm,'app-vault-ed25519-preview');
      const key = createPublicKey({key:keyBytes,format:'der',type:'spki'});
      assert.ok(verify(null,Buffer.from(preimage),key,Buffer.from(document.signature.value,'base64')));
      assert.equal(verify(null,Buffer.from(preimage+'x'),key,Buffer.from(document.signature.value,'base64')),false);
    } else if (vector.profileId === 'crypta.feed.snapshot.v1') {
      if (vector.expectedParseOutcome === 'rejected') {
        assert.throws(() => context.CryptaPlatform.feed.parseSnapshot(text));
        assert.throws(() => feed.parseCanonicalSnapshot(text)); return;
      }
      const expected = fs.readFileSync(path.join(corpus, vector.expectedCanonicalBytesFile), 'utf8');
      assert.equal(JSON.stringify(context.CryptaPlatform.feed.parseSnapshot(text)), expected);
      assert.equal(JSON.stringify(feed.parseCanonicalSnapshot(text)), expected);
    } else if (vector.profileId === 'crypta.profile.v1') {
      const document = await context.CryptaPlatform.profile.verifyDocument(text);
      assert.equal(document.signature.domainSeparatedPayload,
        fs.readFileSync(path.join(corpus, vector.expectedSignaturePreimageFile), 'utf8'));
      for (const change of [d => d.profile.displayName += 'x', d => d.identity.fingerprint = '0'.repeat(64),
        d => d.profile.appId = 'other', d => d.identity.identityId = 'other',
        d => d.signature.scope = 'metadata.read', d => d.signature.purpose = 'other',
        d => d.identity.algorithm = 'RSA', d => d.signature.signatureBase64 = 'AA==']) {
        const altered = JSON.parse(text); change(altered);
        await assert.rejects(() => context.CryptaPlatform.profile.verifyDocument(altered));
      }
    } else if (vector.profileId === 'crypta.social.message.v1') {
      const document = JSON.parse(text);
      social.ensureSignedSocialMessage(document); await social.verifySocialMessageSignature(document);
      assert.equal(social.canonicalSocialMessagePayload(document.message),
        fs.readFileSync(path.join(corpus, vector.expectedSignaturePreimageFile), 'utf8'));
      assert.equal(await social.expectedSocialMessageId(document.message), vector.expectedMessageId);
      for (const change of [d => d.message.body += 'x', d => d.signature.publicKeyFingerprint = '0'.repeat(64),
        d => d.message.messageId = 'msg-' + '0'.repeat(64), d => d.signature.payloadHash = '0'.repeat(64),
        d => d.signature.signatureBase64 = 'AA==', d => d.message.tags = (d.message.tags || ['synthetic']).map(tag => ' ' + tag),
        d => d.message.authorLabel = null]) {
        const altered = JSON.parse(text); change(altered);
        await assert.rejects(async () => { social.ensureSignedSocialMessage(altered); await social.verifySocialMessageSignature(altered); });
      }
      const other = JSON.parse(text); other.message.appId = 'another-app';
      assert.throws(() => social.ensureSignedSocialMessage(other), /app id/);
    } else if (vector.profileId === 'crypta.social.outbox.v1') {
      const source = { id: 'synthetic', label: 'Synthetic source', uriHash: 'test-only' };
      await social.importOutboxText(text, source, {});
      assert.equal(social.state.importedMessages.length, 1);
      const wrapper = JSON.parse(text); wrapper.sourceLabel = 'Unauthenticated replacement';
      wrapper.generatedAt = '1970-01-01T00:00:00Z';
      await social.importOutboxText(JSON.stringify(wrapper), source, {});
      assert.equal(social.state.importedMessages.length, 1, 'replay deduplicates');
      wrapper.messages[0].message.body += 'tamper';
      await assert.rejects(() => social.importOutboxText(JSON.stringify(wrapper), source, {}));
    } else throw new Error('Undeclared JS profile');
  });
}
check('profile-publisher-production-controller-verifies-response', async () => {
  profileApp.state.selectedIdentityId = 'conformance-public-identity';
  profileApp.state.draft = {displayName:"Synthetic", tags:[]};
  const document = await profileApp.createSignedProfileDocument();
  assert.equal(document.schema, 'crypta.profile.v1');
});
check('social-profile-preview-unwraps-api-envelope-and-rejects-tampering', async () => {
  const platform = context.CryptaPlatform;
  const previousFormData = context.FormData;
  const identities = social.state.identities;
  const selectedId = social.state.selectedIdentityId;
  const drafts = social.state.drafts;
  const document = JSON.parse(fs.readFileSync(path.join(corpus, 'profile/document.json')));
  let response = { profileDocument: document };
  let writes = 0;
  context.FormData = class {
    get(name) { return ({ displayName: document.profile.displayName, authorLabel: 'Synthetic author' })[name] || ''; }
  };
  context.CryptaPlatform = Object.assign({}, platform, {
    vault: { identities: { createProfileDocument: async identityId => {
      assert.equal(identityId, document.profile.identityId);
      return response;
    } } },
    data: { records: { putJson: async () => { writes += 1; return {}; } } }
  });
  social.state.identities = [{ identityId: document.profile.identityId }];
  social.state.selectedIdentityId = document.profile.identityId;
  social.state.drafts = {};
  try {
    await social.prepareProfileDocument();
    assert.equal(social.elements.status.textContent, 'Signed profile document prepared.');
    const preview = JSON.parse(social.elements.profilePreview.textContent);
    assert.equal(preview.displayName, document.profile.displayName);
    assert.equal(preview.signature, 'present');
    assert.equal(writes, 1);
    const verifiedPreview = social.elements.profilePreview.textContent;
    const altered = JSON.parse(JSON.stringify(document));
    altered.profile.displayName = 'Tampered signed body';
    for (const invalid of [{ profileDocument: altered }, { profileDocument: null }]) {
      response = invalid;
      await social.prepareProfileDocument();
      assert.equal(social.elements.status.dataset.tone, 'error');
      assert.equal(social.elements.profilePreview.textContent, verifiedPreview);
      assert.equal(writes, 1, 'unverified responses cannot persist drafts');
    }
  } finally {
    context.CryptaPlatform = platform;
    context.FormData = previousFormData;
    social.state.identities = identities;
    social.state.selectedIdentityId = selectedId;
    social.state.drafts = drafts;
  }
});
check('feed-production-generator-current-reader', () => {
  const form = {elements:{namedItem:name => ({value: name === 'feedTitle' ? 'Synthetic feed' : ''})}};
  const generated = feed.buildPublishedSnapshot(form,{title:'Synthetic item'});
  const normalized = context.CryptaPlatform.feed.parseSnapshot(generated);
  assert.equal(JSON.stringify(normalized), '{"type":"crypta.feed.snapshot.v1","source":{},"author":{},"title":"Synthetic feed","updatedAt":"2026-06-01T00:00:00.000Z","items":[{"title":"Synthetic item"}]}');
});
check('social-duplicate-depth-surrogate-rejection', () => {
  for (const text of ['{"a":1,"a":2}', '{"a":{"b":1,"b":2}}', '{"a":"\\ud800"}',
    '{"a":' + '['.repeat(17) + '0' + ']'.repeat(17) + '}']) assert.throws(() => social.parseJsonObject(text, 'Synthetic'));
});
check('feed-byte-limit-minus-at-plus-with-multibyte', () => {
  const base = '{"type":"crypta.feed.snapshot.v1","title":"雪😀","items":[]}';
  for (const length of [65535,65536,65537]) {
    const text = base + ' '.repeat(length - Buffer.byteLength(base));
    assert.equal(Buffer.byteLength(text),length);
    if (length > 65536) assert.throws(() => context.CryptaPlatform.feed.parseSnapshot(text));
    else assert.equal(context.CryptaPlatform.feed.parseSnapshot(text).title,'雪😀');
  }
});
check('profile-verification-snapshots-caller-owned-input', async () => {
  const text = fs.readFileSync(path.join(corpus, 'profile/document.json'), 'utf8');
  const document = JSON.parse(text);
  const pending = context.CryptaPlatform.profile.verifyDocument(document);
  document.profile.displayName = 'NOT SIGNED';
  document.profile.tags[0] = 'NOT SIGNED';
  document.identity.identityId = 'NOT SIGNED';
  document.signature.purpose = 'NOT SIGNED';
  const verified = await pending;
  assert.equal(JSON.stringify(verified), text);
  assert.notEqual(verified, document);
  assert.notEqual(verified.profile.tags, document.profile.tags);
});
check('feed-xml-json-like-content-reaches-xml-fallback', () => {
  const previous = context.DOMParser;
  const reached = new Error('XML parser reached');
  let parsedText;
  context.DOMParser = class {
    parseFromString(text, mime) {
      assert.equal(mime, 'application/xml');
      parsedText = text;
      throw reached;
    }
  };
  try {
    for (const text of [
      '<rss><channel><item><description><![CDATA[{"x":1,"x":2}]]></description></item></channel></rss>',
      '<feed xmlns="http://www.w3.org/2005/Atom"><entry><summary>{"x":1,"x":2}</summary></entry></feed>'
    ]) {
      assert.equal(feed.parseCanonicalSnapshot(text), null);
      assert.throws(() => feed.snapshotFromTextResponse({label: 'Synthetic', uri: ''}, text), error => error === reached);
      assert.equal(parsedText, text);
    }
    assert.throws(() => feed.parseCanonicalSnapshot('{"type":"crypta.feed.snapshot.v1","type":"other","items":[]}'));
  } finally { context.DOMParser = previous; }
});
check('profile-duplicate-and-envelope-rejection', async () => {
  const text = fs.readFileSync(path.join(corpus,'profile/document.json'),'utf8');
  assert.ok(text.startsWith('{'));
  const duplicateRoot = '{"schema":"other",' + text.slice(1);
  await assert.rejects(() => context.CryptaPlatform.profile.verifyDocument(duplicateRoot));
  for (const change of [d => d.schema = 'crypta.profile.v2', d => d.identity.publicKeyBase64 = 'AA==',
    d => d.signature.domainSeparatedPayload += 'x', d => d.profile.displayName = '\ud800']) {
    const document = JSON.parse(text); change(document);
    await assert.rejects(() => context.CryptaPlatform.profile.verifyDocument(document));
  }
});
check('profile-envelope-members-require-objects-without-recursive-decoding', async () => {
  const text = fs.readFileSync(path.join(corpus, 'profile/document.json'), 'utf8');
  const document = JSON.parse(text);
  assert.equal(JSON.stringify(await context.CryptaPlatform.profile.verifyDocument(document)), text);
  assert.equal(JSON.stringify(await context.CryptaPlatform.profile.verifyDocument(text)), text);
  for (const [member, duplicatedField] of [['profile', 'displayName'], ['identity', 'identityId'], ['signature', 'purpose']]) {
    const serialized = JSON.stringify(document[member]);
    const duplicate = '{' + JSON.stringify(duplicatedField) + ':"Earlier unverified value",' + serialized.slice(1);
    for (const invalid of [serialized, duplicate, null, [], 0, false, undefined]) {
      const altered = JSON.parse(text);
      altered[member] = invalid;
      await assert.rejects(() => context.CryptaPlatform.profile.verifyDocument(altered), member);
      await assert.rejects(() => context.CryptaPlatform.profile.verifyDocument(JSON.stringify(altered)), member);
    }
    const rawDuplicate = text.replace('"' + member + '":' + serialized, '"' + member + '":' + duplicate);
    assert.notEqual(rawDuplicate, text);
    await assert.rejects(() => context.CryptaPlatform.profile.verifyDocument(rawDuplicate));
  }
  await assert.rejects(() => context.CryptaPlatform.profile.verifyDocument(JSON.stringify(text)),
    'the top-level document must not be recursively decoded either');
});
check('feed-no-ambiguous-downgrade-or-null-nesting', () => {
  assert.throws(() => feed.parseCanonicalSnapshot('{"type":"crypta.feed.snapshot.v1","type":"other","items":[]}'));
  for (const text of ['{"type":"crypta.feed.snapshot.v1","items":[]}',
    '{"type":"other","type":"crypta.feed.snapshot.v1","items":[]}']) {
    assert.throws(() => context.CryptaPlatform.feed.parseSnapshot(JSON.stringify(text)),
      'feed roots must not be decoded twice');
  }
  for (const fragment of ['"source":null','"author":4','"title":null','"title":1e2']) {
    assert.throws(() => context.CryptaPlatform.feed.parseSnapshot('{"type":"crypta.feed.snapshot.v1",'+fragment+',"items":[]}'));
  }
});
check('feed-nested-source-author-require-objects', () => {
  const snapshot = {type: 'crypta.feed.snapshot.v1', items: []};
  for (const [member, field] of [['source', 'uri'], ['author', 'name']]) {
    for (const invalid of ['{}', JSON.stringify({[field]: 'second'}),
      '{"' + field + '":"first","' + field + '":"second"}', null, [], 0, false]) {
      const altered = {...snapshot, [member]: invalid};
      assert.throws(() => context.CryptaPlatform.feed.parseSnapshot(altered), member);
      assert.throws(() => context.CryptaPlatform.feed.parseSnapshot(JSON.stringify(altered)), member);
      assert.throws(() => feed.parseCanonicalSnapshot(JSON.stringify(altered)), member);
    }
    for (const valid of [snapshot, {...snapshot, [member]: {}},
      {...snapshot, [member]: {[field]: 'second'}}]) {
      const parsed = context.CryptaPlatform.feed.parseSnapshot(valid);
      assert.equal(JSON.stringify(parsed[member]), JSON.stringify(valid[member] || {}));
      assert.equal(JSON.stringify(context.CryptaPlatform.feed.parseSnapshot(JSON.stringify(valid))), JSON.stringify(parsed));
      assert.ok(feed.parseCanonicalSnapshot(JSON.stringify(valid)));
    }
  }
});
check('feed-safe-reference-render-model', () => {
  for (const uri of ['file:///etc/passwd','http://127.0.0.1/private','javascript:alert(1)']) {
    assert.equal(feed.normalizeEntry({title:'<script>inert</script>',uri}).uri,'');
    assert.equal(feed.normalizeEntry({title:'<script>inert</script>',uri}).title,'<script>inert</script>');
  }
});
check('trust-failure-categories-preserve-content', () => {
  social.state.trustServiceDescriptor = {contexts:['message-author']};
  for (const status of ['revoked','expired','pending']) {
    social.state.trustServiceGrants = [{providerAppId:'trust-graph',serviceId:'trust.score',
      scopes:['score.read'],contexts:['message-author'],status}];
    assert.ok(social.trustAnnotationFailure({code:'app_service_grant_required'}).summary.includes(status));
  }
  const unavailable = social.trustAnnotationFailure({code:'app_services_unavailable'});
  const malformed = social.trustAnnotationFailure({code:'invalid_query_parameter'});
  assert.notEqual(unavailable.summary,malformed.summary);
  assert.equal(social.state.importedMessages.length,1);
});
check('trust-real-annotation-controller-failure-preserves-rendered-message', async () => {
  const api = context.CryptaPlatform;
  const activeGrant = {providerAppId:'trust-graph',serviceId:'trust.score',scopes:['score.read'],
    contexts:['message-author'],status:'active'};
  const descriptor = {contexts:['message-author']};
  const before = JSON.stringify(social.state.importedMessages);
  const message = social.state.importedMessages[0];
  assert.ok(message && message.bodyPreview);
  let invocations = 0;
  let discoveries = 0;
  try {
    for (const [code, grantStatus, expected] of [
      ['app_services_unavailable','active','provider unavailable'],
      ['app_service_grant_required','revoked','grant revoked'],
      ['app_service_grant_required','expired','grant expired'],
      ['invalid_query_parameter','active','invalid score request'],
    ]) {
      social.state.trustServiceDescriptor = descriptor;
      social.state.trustServiceGrants = [activeGrant];
      context.CryptaPlatform = Object.assign({}, api, {services:{
        invoke: async (provider,service,request) => {
          invocations++;
          assert.equal(provider,'trust-graph'); assert.equal(service,'trust.score');
          assert.equal(request.subjectUri,message.authorFingerprint);
          assert.equal(request.scope,'score.read');
          throw Object.assign(new Error('Synthetic service failure'),{code});
        },
        get: async () => { discoveries++; return descriptor; },
        grants:{list:async () => [{...activeGrant,status:grantStatus}]},
        bundles:{list:async () => []},
      }});
      await social.refreshTrustAnnotations({silent:true});
      assert.equal(JSON.stringify(social.state.importedMessages),before);
      assert.equal(social.state.trustScores[message.authorFingerprint].status,'unscored');
      assert.ok(social.state.trustScores[message.authorFingerprint].summary.includes(expected));
      const displayed = renderedText(social.elements.inboxList);
      assert.ok(displayed.includes(message.bodyPreview), 'valid body remains in rendered inbox');
      assert.ok(displayed.includes(expected), 'actual renderer shows distinct failure category');
    }
    assert.equal(invocations,4); assert.equal(discoveries,4);
  } finally { context.CryptaPlatform = api; }
});
check('trust-zero-is-distinct-from-no-evidence', () => {
  assert.equal(social.normalizeTrustScore({status:'mixed',score:0,contributingEvidenceCount:2}).status, 'scored');
  assert.equal(social.normalizeTrustScore({status:'unknown',score:0,contributingEvidenceCount:0}).status, 'unscored');
});
check('outbox-byte-envelope-boundaries-and-unsigned-membership', async () => {
  const before = social.state.importedMessages;
  const source = {id:'synthetic-boundary',label:'Synthetic',uriHash:'synthetic-only'};
  const base = fs.readFileSync(path.join(corpus,'outbox/outbox-one-message.json'),'utf8');
  try {
    for (const length of [65535,65536,65537]) {
      const text = base + ' '.repeat(length - Buffer.byteLength(base));
      assert.equal(Buffer.byteLength(text),length);
      if (length > 65536) await assert.rejects(() => social.importOutboxText(text,source,{}));
      else await social.importOutboxText(text,source,{});
    }
    const additional = manifest.cases.find(row => row.caseId === 'social-maximal-optionals');
    assert.ok(additional, 'all-optionals signed message vector is required');
    const wrapper = JSON.parse(base);
    wrapper.messages.push(JSON.parse(fs.readFileSync(path.join(corpus,additional.inputFile))));
    await social.importOutboxText(JSON.stringify(wrapper),source,{});
    const ids = social.state.importedMessages.map(message => message.messageId).sort();
    assert.equal(ids.length,2);
    wrapper.messages.reverse(); wrapper.sourceLabel = 'Unauthenticated label';
    wrapper.generatedAt = '1970-01-01T00:00:00Z';
    await social.importOutboxText(JSON.stringify(wrapper),source,{});
    assert.deepEqual(social.state.importedMessages.map(message => message.messageId).sort(),ids);
    wrapper.messages = [];
    await social.importOutboxText(JSON.stringify(wrapper),source,{});
    assert.deepEqual(social.state.importedMessages.map(message => message.messageId).sort(),ids,
      'unsigned omission cannot prove deletion or complete disclosure');
  } finally { social.state.importedMessages = before; }
});
check('signature-runtime-unavailable-fails-closed', async () => {
  const document = JSON.parse(fs.readFileSync(path.join(corpus,'profile/document.json')));
  const crypto = context.window.crypto; context.window.crypto = null;
  try { await assert.rejects(() => context.CryptaPlatform.profile.verifyDocument(document)); }
  finally { context.window.crypto = crypto; }
});
(async () => {
  for (const [name, callback] of cases) {
    try { await callback(); } catch (error) { throw new Error(name, { cause: error }); }
    tested.push(name);
  }
  console.log(JSON.stringify({schemaVersion:1, runtime:process.version, manifestDigest:hash(manifestBytes),
    executedCases:tested, skippedRequired:0, evidenceLevel:'local-production-javascript-conformance',
    unsupportedDirections:['javascript-production-trust-verifier','historical-executable-reader','independent-external-implementation']}));
})().catch(error => { console.error(error); process.exitCode = 1; });
