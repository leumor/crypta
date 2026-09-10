/* Real browser conformance for a generated, already verified site. */
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const http = require('node:http');
const path = require('node:path');
const { chromium } = require('playwright');
let root;
if (process.argv[2] === '--renderer-fixture') {
  const os = require('node:os');
  const {spawnSync} = require('node:child_process');
  root = fs.mkdtempSync(path.join(os.tmpdir(),'transparency-renderer-demo-'));
  const fixture = {schemaVersion:1,mode:'demo',snapshotId:'sha256:'+'a'.repeat(64),asOf:'2026-09-10T00:00:00Z',policyDigest:'sha256:'+'b'.repeat(64),toolDigest:'sha256:'+'c'.repeat(64),coverage:[],selectionCoverage:[{role:'advisories',status:'optional-source-unavailable'}],limitations:['implementationCoverage=partial','originalProtectedRuntime=not-observed','maintenanceEligibility=blocked-original-authority-required','publication=not-performed','activation=not-performed','Independent security review pending'],sources:[]};
  for (const role of ['release','maintenance','catalogs','reviews','keys','advisories','sbom','lifecycle','repository-status']) fixture.sources.push({role,identity:'synthetic-'+role,evidenceClass:'synthetic/local rehearsal',provenance:'not-authenticated',verification:'verified-local-integrity',disclosure:'synthetic-only',publication:'not-performed',activation:'not-performed',observedAt:'2020-01-01T00:00:00Z',staleAt:'2020-01-02T00:00:00Z',freshness:'stale-at-snapshot',fields:{status:'revoked',implementationCoverage:'partial',hostile:'<img src="https://evil.invalid/x" onerror="alert(1)"><script>alert(1)</script>',hostileLink:'javascript:alert(1)',encodedLink:'%256a%2561vascript:alert(1)',publicLink:'https://example.org/approved-public-evidence',cryptaLink:'crypta:USK@synthetic-public-key/catalog/1',invalidHttps:'https://example.org/%256aavascript',currentStable:null}});
  const generated = spawnSync('python3',['-c',"import sys,json; from pathlib import Path; sys.path.insert(0,'tools/release-certification'); from cryptad_certification.transparency_render import render; root=Path(sys.argv[1]); value=json.load(sys.stdin); files=render(value); files['data/public-index.json']=json.dumps(value).encode(); files['site-bundle-manifest.json']=b'{}'; [( (root/name).parent.mkdir(parents=True,exist_ok=True), (root/name).write_bytes(raw)) for name,raw in files.items()]",root],{input:JSON.stringify(fixture),encoding:'utf8'});
  assert.equal(generated.status,0,'renderer fixture generation failed');
} else root = fs.realpathSync(process.argv[2]);
const index = JSON.parse(fs.readFileSync(path.join(root,'data/public-index.json'),'utf8'));
const pages = ['index.html','releases/index.html','catalogs/index.html','keys/index.html','advisories/index.html','supply-chain/index.html','readiness/index.html','verify/index.html'];
const server = http.createServer((req, res) => {
  const relative = decodeURIComponent(new URL(req.url, 'http://fixture.invalid').pathname).replace(/^\//, '');
  const file = path.resolve(root, relative || 'index.html');
  if (!file.startsWith(root + path.sep) || !fs.existsSync(file) || !fs.statSync(file).isFile()) {res.writeHead(404).end(); return;}
  res.setHeader('Content-Type', file.endsWith('.css') ? 'text/css' : file.endsWith('.json') ? 'application/json' : 'text/html');
  res.setHeader('Referrer-Policy','no-referrer');
  res.setHeader('Content-Security-Policy', "default-src 'none'; style-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'");
  res.end(fs.readFileSync(file));
});
(async () => {
  await new Promise(resolve => server.listen(0,'127.0.0.1',resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const browser = process.env.PW_TEST_CONNECT_WS_ENDPOINT ? await chromium.connect(process.env.PW_TEST_CONNECT_WS_ENDPOINT) : await chromium.launch({headless:true});
  try {
    for (const javaScriptEnabled of [true,false]) {
      const context = await browser.newContext({javaScriptEnabled,viewport:{width:375,height:812}});
      const requests = [];
      context.on('request', req => requests.push(req.url()));
      const page = await context.newPage();
      const shown = new Set();
      for (const route of pages) {
        const response = await page.goto(origin + '/' + route);
        assert.equal(response.status(),200);
        assert.equal(response.headers()['referrer-policy'],'no-referrer');
        assert.match(response.headers()['content-security-policy'],/frame-ancestors 'none'/);
        assert.equal(await page.locator('h1').count(),1);
        assert.equal(await page.locator('nav[aria-label="Primary"] a').count(),8);
        assert.equal(await page.locator('nav [aria-current="page"]').count(),1);
        assert.equal(await page.locator('script,iframe,img,form,object,embed').count(),0);
        assert.equal(await page.locator('[onclick],[onerror],link[rel="prefetch"],link[rel="preconnect"]').count(),0);
        assert(await page.locator('main').innerText());
        const visible = await page.locator('main').innerText();
        assert(visible.includes(index.snapshotId));
        assert(visible.includes(index.asOf));
        assert.equal(visible.includes('Synthetic demo — not production evidence.'),index.mode === 'demo');
        if (!index.sources.length && route === 'releases/index.html') assert(visible.includes('No authenticated public release in this snapshot.'));
        if (route === 'index.html') {
          assert(visible.includes('Declared input availability'));
          for (const selected of index.selectionCoverage || []) if (selected.status) assert(visible.includes(selected.status));
        }
        if (route === 'readiness/index.html') assert(visible.includes('PR-303 owns Phase 12 closeout'));
        for (const source of index.sources) {
          if ((await page.locator('article h2').allTextContents()).includes(source.identity)) {
            shown.add(source.identity);
            if (source.fields.hostile) assert(visible.includes(source.fields.hostile));
            if (typeof source.freshness === 'string') assert(visible.includes(source.freshness));
            if (source.fields.publicLink) {
              assert(await page.locator('a[href="'+source.fields.publicLink+'"]').count() > 0);
              assert(await page.locator('a[href="'+source.fields.cryptaLink+'"]').count() > 0);
              assert.equal(await page.locator('a[href="'+source.fields.invalidHttps+'"]').count(),0);
            }
            if (source.fields.status) assert(visible.includes(source.fields.status));
            if (source.staleAt && source.staleAt <= index.asOf) assert(visible.includes('Historical / stale as of this snapshot.'));
            for (const dimension of ['evidenceClass','provenance','verification','disclosure','publication','activation','observedAt','staleAt']) {
              if (typeof source[dimension] === 'string') assert(visible.includes(source[dimension]));
            }
          }
        }
        assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
        await page.setViewportSize({width:1280,height:900});
        assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
        await page.setViewportSize({width:375,height:812});
        await page.keyboard.press('Tab');
        assert.equal(await page.locator(':focus').innerText(),'Skip to content');
        await page.keyboard.press('Enter');
        assert.equal(await page.locator(':focus').getAttribute('id'),'main');
        const links = await page.locator('a[href]').evaluateAll(elements => elements.map(a=>({href:a.getAttribute('href'),rel:a.getAttribute('rel'),referrerpolicy:a.getAttribute('referrerpolicy')})));
        for (const link of links.filter(link=>!link.href.startsWith('#'))) {
          const url = new URL(link.href, page.url());
          if (url.origin !== origin) {
            assert(['https:', 'crypta:'].includes(url.protocol));
            assert.equal(link.rel,'noopener noreferrer');
            assert.equal(link.referrerpolicy,'no-referrer');
            continue;
          }
          const result = await context.request.get(url.href);
          assert.equal(result.status(),200);
        }
        if (javaScriptEnabled) assert.deepEqual(await page.evaluate(()=>({local:localStorage.length,session:sessionStorage.length})),{local:0,session:0});
      }
      assert(requests.every(url=>new URL(url).origin===origin));
      assert(index.sources.every(source=>shown.has(source.identity)),'every admitted source must have a family page');
      await context.close();
    }
    console.log('transparency-browser: passed (8 pages, JavaScript enabled/disabled, mobile/desktop, keyboard, downloads, local-only network, fixture headers)');
  } finally {await browser.close(); server.close();}
})().catch(()=>{console.error('transparency-browser: failed (browser-conformance-failed)');server.close();process.exitCode=1;});
