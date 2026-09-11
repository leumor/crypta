"""Deterministic, text-only presentation of the closed public transparency view."""
from html import escape
import json
from pathlib import Path
import re

ASSETS = Path(__file__).resolve().parents[2] / 'ecosystem-transparency' / 'assets'
PAGES = (
    ('index.html', 'Overview', ()),
    ('releases/index.html', 'Releases', ('release', 'maintenance', 'lifecycle', 'support-lifecycle')),
    ('catalogs/index.html', 'Catalogs and apps', ('catalog', 'catalogs', 'review', 'reviews', 'app-review')),
    ('keys/index.html', 'Governance keys', ('keys', 'keyset', 'governance-keys')),
    ('advisories/index.html', 'Advisories', ('advisory', 'advisories')),
    ('supply-chain/index.html', 'SBOM and reproducibility', ('sbom', 'supply-chain', 'reproducibility')),
    ('readiness/index.html', 'Readiness and limitations', ('drill', 'repository', 'maintenance-drill', 'implementation', 'repository-status', 'phase12', 'phase-assessment')),
    ('verify/index.html', 'Verification and help', ()),
)
EMPTY = {
    'Releases': 'No authenticated public release in this snapshot.',
    'Catalogs and apps': 'No authenticated public catalog or review in this snapshot. Catalog endorsement is not local trust; a scoped review is not a guarantee of safety.',
    'Governance keys': 'No approved public governance key artifact in this snapshot. Historical signing validity does not authorize new signing.',
    'Advisories': 'No observed advisories in the selected public feed. This is not a statement that there are no vulnerabilities.',
    'SBOM and reproducibility': 'No authenticated public component or reproducibility evidence in this snapshot.',
    'Readiness and limitations': 'No operational receipt is supplied by this repository statement. Missing runtime and security observations remain open.',
}


def text(value):
    """Escape every upstream value, including authenticated free text."""
    if isinstance(value, (dict, list)):
        value = json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(',', ':'))
    return escape(str(value), quote=True)


def details(value):
    if isinstance(value, dict):
        return '<dl>' + ''.join('<dt>' + text(k) + '</dt><dd>' + details(v) + '</dd>' for k, v in sorted(value.items())) + '</dl>'
    if isinstance(value, list):
        return '<ul>' + ''.join('<li>' + details(v) + '</li>' for v in value) + '</ul>'
    if isinstance(value, str) and value.startswith(('https://', 'crypta:')):
        from .transparency_sources import SourceError, safe_link
        try:
            target = safe_link(value, crypta=True)
        except SourceError:
            pass
        else:
            return '<a class="value" href="' + text(target) + '" rel="noopener noreferrer" referrerpolicy="no-referrer">' + text(value) + '</a>'
    return '<span class="value">' + text(value) + '</span>'


def render(index: dict) -> dict[str, bytes]:
    """Render only admitted fields; this function performs no IO beyond local CSS."""
    result = {'assets/site.css': (ASSETS / 'site.css').read_bytes()}
    for path, title, roles in PAGES:
        prefix = '' if path == 'index.html' else '../'
        nav = ''.join('<a ' + ('aria-current="page" ' if path == p else '') + 'href="' + prefix + p + '">' + name + '</a>' for p, name, _ in PAGES)
        body = '<h1>' + title + '</h1>'
        if index['mode'] == 'demo':
            body += '<aside class="notice" role="note"><strong>Synthetic demo — not production evidence.</strong> No publication or activation is established by this preview.</aside>'
        body += '<p class="snapshot">Snapshot <code>' + text(index['snapshotId']) + '</code><br>As of <time>' + text(index['asOf']) + '</time></p>'
        if title == 'Overview':
            body += '<h2>Selected source coverage</h2><p>This bounded snapshot is a presentation of selected evidence. Site generation is separate from source publication, activation, support and independent review.</p>' + details(index.get('coverage', []))
            body += '<h2>Declared input availability</h2>' + details(index.get('selectionCoverage', []))
            body += '<h2>Blockers and limitations</h2>' + details(index.get('limitations', []))
            if not index.get('sources'):
                body += '<p class="notice">No authenticated public release in this snapshot. No complete ecosystem inventory is claimed.</p>'
        elif title == 'Verification and help':
            body += '<p><a download href="../site-bundle-manifest.json">Download public file manifest</a> · <a download href="../data/public-index.json">Download public snapshot</a></p><h2>Offline verification</h2><pre>python3 tools/release-certification/certify.py public-ecosystem-transparency --mode verify --bundle SITE</pre><p>Checksums establish byte integrity, not original source authentication. Select trusted roots and historical verification material explicitly when verifying original authorities. An offline snapshot cannot know later revocation. On first use, no global non-equivocation or rollback detection is claimed.</p><h2>Site and source provenance</h2>' + details({'policyDigest': index['policyDigest'], 'toolDigest': index['toolDigest'], 'siteDeployment': 'not-observed', 'publicByteObservation': 'not-observed'})
            body += '<h2>Approved original public downloads</h2>'
            for download in index.get('downloads', []):
                target = download['path']
                if re.fullmatch(r'evidence/[a-f0-9]{64}/[a-z0-9._-]+', target):
                    body += '<p><a download href="../' + target + '">Exact approved public bytes</a> <code>' + text(download['digest']) + '</code> (' + text(download['size']) + ' bytes)</p>'
            body += '<h2>Privacy and hosting</h2><p>The application adds no user telemetry or subscription reporting. Hosting providers and CDNs may observe visitor network requests; static hosting is not an anonymity guarantee. External evidence is opened only by explicit navigation. This site cannot install apps, import trust, grant capabilities or switch sources.</p><p>The local meta CSP restricts content. Framing protection requires an HTTP frame-ancestors header; no production host header deployment is claimed.</p>'
        else:
            rows = [r for r in index.get('sources', []) if r['role'] in roles]
            if not rows:
                body += '<p class="notice">' + EMPTY[title] + '</p>'
            for row in rows:
                body += '<article><h2>' + text(row['identity']) + '</h2>'
                if row.get('staleAt') and row['staleAt'] <= index['asOf']:
                    body += '<p class="notice">Historical / stale as of this snapshot. Generation has not refreshed the upstream evidence.</p>'
                if 'freshness' in row:
                    body += '<h3>Freshness assessment</h3>' + details(row['freshness'])
                body += details({k: v for k, v in row.items() if k not in ('identity', 'downloads', 'freshness')})
                for download in row.get('downloads', []):
                    target = download['path']
                    if re.fullmatch(r'evidence/[a-f0-9]{64}/[a-z0-9.-]+', target):
                        body += '<p><a download href="' + prefix + target + '">Exact approved public bytes</a> <code>' + text(download['digest']) + '</code></p>'
                body += '</article>'
            if title == 'Readiness and limitations':
                body += '<h2>Repository-reported residuals</h2>' + details(index.get('limitations', []))
                body += '<p>Implementation / local rehearsal is separate from protected operations. PR-303 owns Phase 12 closeout. Mail remains experimental; milestone 1.0, API URL v1, integer API contract and integer product build are distinct.</p>'
        html = '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src &#39;none&#39;; style-src &#39;self&#39;; base-uri &#39;none&#39;; form-action &#39;none&#39;"><meta name="referrer" content="no-referrer"><title>' + title + ' · Crypta public evidence</title><link rel="stylesheet" href="' + prefix + 'assets/site.css"></head><body><a class="skip" href="#main">Skip to content</a><header><p class="brand">Crypta · public ecosystem evidence</p><nav aria-label="Primary">' + nav + '</nav></header><main id="main" tabindex="-1">' + body + '</main><footer>Evidence has scope. Site integrity does not upgrade source authority.</footer></body></html>\n'
        result[path] = html.encode('utf-8')
    return result
