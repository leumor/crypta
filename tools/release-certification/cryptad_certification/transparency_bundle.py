"""Deterministic static exports. Checksums establish consistency, never source authority."""
from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import tempfile
import time
from datetime import datetime, timezone

MAX_FILES = 256
MAX_FILE = 4 * 1024 * 1024
MAX_TOTAL = 16 * 1024 * 1024
MANIFEST = 'site-bundle-manifest.json'
SOURCE = 'data/source-snapshot.json'
INDEX = 'data/public-index.json'
FAMILIES = ('release', 'maintenance', 'catalogs', 'reviews', 'keys', 'advisories',
            'supply-chain', 'sbom', 'reproducibility', 'lifecycle', 'drill', 'repository-status')
LIMITATIONS = [
    'No source inventory is globally complete. Only selected public sources are represented.',
    'Checksums establish local consistency; they do not authenticate the site or original producers.',
    'Without an independently pinned checkpoint, global freshness and non-equivocation are not established.',
    'A static snapshot cannot know about later corrections or revocations.',
    'Site generation is not release publication, activation, independent review, or Phase 12 closeout.',
    'The application adds no telemetry or subscription reporting. Hosts and CDNs may observe visitor network requests; static hosting is not an anonymity guarantee.',
]


def fail(code='bundle-invalid'):
    raise ValueError(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                      allow_nan=False).encode() + b'\n'


def digest(raw):
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


def parse(raw):
    if len(raw) > MAX_FILE:
        fail('document-limit')
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                fail('duplicate-json-member')
            result[key] = value
        return result
    def constant(_):
        fail('nonfinite-json')
    try:
        value = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
        def finite(item, depth=0):
            if depth > 32 or isinstance(item, float) and not math.isfinite(item):
                fail('document-depth-or-number')
            if isinstance(item, dict):
                for child in item.values():
                    finite(child, depth + 1)
            elif isinstance(item, list):
                for child in item:
                    finite(child, depth + 1)
        finite(value)
        return value
    except (ValueError, UnicodeError, RecursionError):
        fail('document-invalid')


def timestamp(value):
    if not isinstance(value, str) or not re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ', value):
        fail('timestamp-invalid')
    try:
        return datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ')
    except ValueError:
        fail('timestamp-invalid')


def check_publication_time(as_of, *, now=None):
    """Reject future snapshots at an explicit publication gate, never during offline rendering."""
    current = now if now is not None else datetime.now(timezone.utc)
    if current.tzinfo is None or current.utcoffset() is None:
        fail('publication-clock-invalid')
    if timestamp(as_of).replace(tzinfo=timezone.utc) > current:
        fail('snapshot-after-publication-time')


def safe_name(name):
    if (not isinstance(name, str) or len(name) > 220 or
            not re.fullmatch(r'[a-z0-9][a-z0-9./_-]*', name) or
            any(part in ('', '.', '..') for part in name.split('/'))):
        fail('member-name-invalid')
    return name


def confined(path):
    path = Path(path).absolute()
    if path.is_symlink() or any(p.is_symlink() for p in path.parents):
        fail('path-link-denied')
    return path


def read_file(path):
    path = confined(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        status = os.fstat(stream.fileno())
        if not stat.S_ISREG(status.st_mode) or status.st_nlink != 1 or status.st_size > MAX_FILE:
            fail('member-type-or-limit')
        raw = stream.read(MAX_FILE + 1)
    if len(raw) > MAX_FILE:
        fail('member-limit')
    return raw


def inventory(root):
    root = confined(root)
    if not root.is_dir():
        fail('bundle-root-invalid')
    result = {}
    total = 0
    directories = set()
    for directory, subdirs, files in os.walk(root, followlinks=False):
        for name in subdirs:
            path = Path(directory) / name
            relative = safe_name(path.relative_to(root).as_posix())
            directories.add(relative)
            if len(directories) > MAX_FILES or relative.count('/') > 4:
                fail('directory-limit')
            if path.is_symlink():
                fail('member-link-denied')
        for name in files:
            path = Path(directory) / name
            relative = safe_name(path.relative_to(root).as_posix())
            raw = read_file(path)
            total += len(raw)
            if len(result) >= MAX_FILES or total > MAX_TOTAL:
                fail('bundle-limit')
            result[relative] = raw
    implied = {str(parent) for name in result for parent in Path(name).parents if str(parent) != '.'}
    if directories != implied:
        fail('extra-directory')
    return result


def tool_identity():
    directory = Path(__file__).parent
    root = directory.parent
    files = [path for path in directory.rglob('*.py') if 'tests' not in path.parts]
    files += list((root / 'schemas').glob('*.json'))
    files += [root / 'protected' / 'original_artifact_authentication.py']
    assets = root.parent / 'ecosystem-transparency' / 'assets'
    files += list(assets.glob('*')) if assets.exists() else []
    return digest(canonical({str(p.relative_to(root.parent)): digest(p.read_bytes())
                             for p in sorted(files) if p.is_file()}))


def make_index(package):
    from .transparency_sources import admit
    admitted = admit(package)
    records = admitted['records']
    identities = [(r['role'], r['identity']) for r in records]
    if len(set(identities)) != len(identities):
        fail('source-identity-conflict')
    selection = package['selection']
    as_of = selection['asOf']
    timestamp(as_of)
    validate_lineage(records)
    for row in records:
        row['freshness'] = ('stale-at-snapshot' if row.get('staleAt') and
                            timestamp(row['staleAt']) <= timestamp(as_of) else
                            'within-selected-validity' if row.get('staleAt') else 'no-validity-window-supplied')
        if row.get('observedAt') is not None and timestamp(row['observedAt']) > timestamp(as_of):
            fail('source-observation-after-snapshot')
    identity = {'schemaVersion': 1, 'mode': selection['mode'], 'asOf': as_of,
                'policyDigest': package['policyDigest'], 'toolDigest': tool_identity(),
                'sourceSnapshotDigest': digest(canonical(package))}
    index = {**identity, 'snapshotId': digest(canonical(identity)), 'sources': records,
             'coverage': [{'role': role, 'state': 'selected' if any(r['role'] == role for r in records)
                           else 'not-supplied', 'scope': 'selected-public-sources-only'} for role in FAMILIES],
             'selectionCoverage': admitted.get('sources', []),
             'limitations': LIMITATIONS,
             'site': {'generation': 'generated-offline', 'deployment': 'not-established',
                      'publicObservation': 'not-established'},
             'downloads': []}
    downloads = {}
    for name, raw in admitted.get('downloads', {}).items():
        safe_name(name)
        path = 'evidence/' + hashlib.sha256(raw).hexdigest() + '/' + name.split('/')[-1]
        if path in downloads and downloads[path] != raw:
            fail('download-conflict')
        downloads[path] = raw
        index['downloads'].append({'path': path, 'digest': digest(raw), 'size': len(raw)})
    index['downloads'].sort(key=lambda item: item['path'])
    return index, downloads


def render_files(package):
    from .transparency_render import render
    index, downloads = make_index(package)
    files = {SOURCE: canonical(package), INDEX: canonical(index), **downloads, **render(index)}
    if MANIFEST in files:
        fail('manifest-cycle')
    if len(files) > MAX_FILES - 1 or sum(map(len, files.values())) > MAX_TOTAL:
        fail('bundle-limit')
    for name, raw in files.items():
        safe_name(name)
        if not isinstance(raw, bytes) or len(raw) > MAX_FILE:
            fail('member-limit')
    manifest = {'schemaVersion': 1, 'kind': 'public-ecosystem-site-bundle',
                'snapshotId': index['snapshotId'], 'mode': index['mode'],
                'asOf': index['asOf'], 'authentication': 'not-established',
                'files': [{'path': name, 'size': len(raw), 'digest': digest(raw)}
                          for name, raw in sorted(files.items())]}
    return {**files, MANIFEST: canonical(manifest)}


def validate_lineage(records):
    """Validate supplied public lifecycle/key successors; absent history stays a limited claim."""
    from .engines.stable_1_0_catalog_authority import _key_transition_errors

    for role, edition, previous_edition, previous_digest, current_digest in (
            ('lifecycle', 'descriptorEdition', 'previousDescriptorEdition', 'previousDescriptorDigest', 'descriptorDigest'),
            ('keys', 'keysetVersion', None, 'previousKeysetDigest', 'keysetDigest')):
        selected = [r['fields'] for r in records if r['role'] == role]
        selected.sort(key=lambda row: int(row[edition]))
        for older, newer in zip(selected, selected[1:]):
            if (int(newer[edition]) <= int(older[edition]) or
                    newer[previous_digest] != older[current_digest] or
                    previous_edition and newer[previous_edition] != older[edition]):
                fail('source-lineage-conflict')
            if role == 'lifecycle':
                retained = {str(row['buildVersion']): row for row in newer['entries']}
                for entry in older['entries']:
                    if entry['lifecycleStatus'] == 'revoked':
                        successor = retained.get(str(entry['buildVersion']))
                        if successor is None or successor['lifecycleStatus'] != 'revoked':
                            fail('source-revocation-removed')
            else:
                retained = {row['keyId']: row for row in newer['keys']}
                for entry in older['keys']:
                    successor = retained.get(entry['keyId'])
                    if (successor is None or successor['role'] != entry['role'] or
                            successor['publicKeyFingerprintSha256'] != entry['publicKeyFingerprintSha256'] or
                            _key_transition_errors(entry, successor)):
                        fail('source-key-history-removed')


def check_history(current, previous):
    """A selected previous snapshot constrains replay; it is not a global log."""
    if timestamp(current['asOf']) <= timestamp(previous['asOf']):
        fail('snapshot-not-successor')
    if current['mode'] != previous['mode']:
        fail('snapshot-class-conflict')
    # Older exports used one fixed repository-status identity. Compare that legacy row
    # using its retained exact public-byte digest, without modifying the pinned export.
    def historical_row(row):
        legacy = 'demo-repository-status' if previous['mode'] == 'demo' else 'repository-status'
        if row['role'] == 'repository-status' and row['identity'] == legacy:
            source_digest = row['fields']['originalPublicBytesDigest']
            return {**row, 'identity': legacy + ':' + source_digest}
        return row
    old = {(r['role'], r['identity']): r
           for r in map(historical_row, previous['sources'])}
    new = {(r['role'], r['identity']): r for r in current['sources']}
    if len(new) != len(current['sources']):
        fail('source-identity-conflict')
    # Retaining previous rows also retains known revocations and original observation times.
    for key, row in old.items():
        if key not in new:
            fail('selected-history-removed')
        if canonical({k: v for k, v in new[key].items() if k != 'freshness'}) != canonical({k: v for k, v in row.items() if k != 'freshness'}):
            fail('source-identity-conflict')


def build(package, output, *, previous=None, previous_manifest=None):
    if previous_manifest is not None and previous is None:
        fail('checkpoint-bundle-required')
    output = confined(output)
    if output.exists() or not output.parent.is_dir():
        fail('output-must-be-fresh')
    if package['selection']['mode'] == 'demo' and 'demo' not in output.name:
        fail('demo-output-name-required')
    files = render_files(package)
    if previous is not None:
        checkpoint = verify_checkpoint(previous, previous_manifest) if previous_manifest else verify(previous)['index']
        check_history(parse(files[INDEX]), checkpoint)
    # Complete all admission/render checks before staging public bytes.
    with tempfile.TemporaryDirectory(prefix='.transparency-', dir=output.parent) as temporary:
        stage = Path(temporary) / 'site'
        stage.mkdir()
        for name, raw in sorted(files.items()):
            path = stage / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        verify(stage)
        if output.exists():
            fail('output-raced')
        stage.rename(output)
    return {'status': 'verified-local-consistency', 'manifestDigest': digest(files[MANIFEST]),
            'snapshotId': parse(files[INDEX])['snapshotId'], 'publication': 'not-performed'}


def verify_checkpoint(root, expected_manifest):
    """Read an explicitly pinned prior public bundle without running its historical code.

    The caller must obtain this digest through its existing approved checkpoint authority.
    A supplied checksum alone does not create independent authentication.
    """
    files = inventory(root)
    if MANIFEST not in files or digest(files[MANIFEST]) != expected_manifest:
        fail('checkpoint-substitution')
    manifest = parse(files[MANIFEST])
    from .schema_validation import validate_schema
    if validate_schema(manifest, 'public-ecosystem-site-bundle-v1.schema.json'):
        fail('checkpoint-contract')
    rows = manifest['files']
    names = [row['path'] for row in rows]
    if len(set(names)) != len(names) or set(names) != set(files) - {MANIFEST}:
        fail('checkpoint-inventory')
    for row in rows:
        raw = files[safe_name(row['path'])]
        if row['size'] != len(raw) or row['digest'] != digest(raw):
            fail('checkpoint-content')
    index = parse(files[INDEX])
    identity = {key: index[key] for key in ('schemaVersion', 'mode', 'asOf', 'policyDigest',
                                           'toolDigest', 'sourceSnapshotDigest')}
    if (index['snapshotId'] != digest(canonical(identity)) or manifest['snapshotId'] != index['snapshotId']
            or index['sourceSnapshotDigest'] != digest(files[SOURCE]) or manifest['mode'] != index['mode']
            or manifest['asOf'] != index['asOf']):
        fail('checkpoint-binding')
    return index


def verify(root, *, expected_manifest=None, production=False):
    files = inventory(root)
    if MANIFEST not in files or SOURCE not in files or INDEX not in files:
        fail('bundle-incomplete')
    if expected_manifest is not None and digest(files[MANIFEST]) != expected_manifest:
        fail('manifest-substitution')
    manifest = parse(files[MANIFEST])
    from .schema_validation import validate_schema
    if validate_schema(manifest, 'public-ecosystem-site-bundle-v1.schema.json'):
        fail('manifest-schema-invalid')
    if type(manifest) is not dict or set(manifest) != {
            'schemaVersion', 'kind', 'snapshotId', 'mode', 'asOf', 'authentication', 'files'}:
        fail('manifest-contract')
    if production and manifest['mode'] != 'production':
        fail('demo-production-denied')
    expected = render_files(parse(files[SOURCE]))
    if files != expected:
        fail('bundle-content-or-inventory-mismatch')
    return {'status': 'verified-local-consistency', 'manifestDigest': digest(files[MANIFEST]),
            'authentication': 'not-established', 'index': parse(files[INDEX]),
            'fileCount': len(files)}


def observe(root, base_url, observed_at=None, *, expected_manifest=None, fetcher=None, clock=None):
    """One bounded pass compares the manifest and every exported byte; never publish."""
    from .transparency_sources import SiteContentMismatch, fetch_site
    verified = verify(root, production=True, expected_manifest=expected_manifest)
    files = inventory(root)
    if not base_url.endswith('/'):
        fail('observation-base-invalid')
    fetcher = fetcher or (lambda url, limit: fetch_site(url, limit, base_url))
    # Sample after local verification, immediately before the bounded fetch pass. A caller's
    # optional timestamp is only a sanity assertion; it never supplies temporal evidence.
    started = clock() if clock is not None else datetime.now(timezone.utc)
    if started.tzinfo is None or started.utcoffset() is None:
        fail('observation-clock-invalid')
    started = started.astimezone(timezone.utc)
    if observed_at is not None and abs((timestamp(observed_at).replace(tzinfo=timezone.utc) - started).total_seconds()) > 60:
        fail('observation-time-outside-execution-window')
    if started < timestamp(verified['index']['asOf']).replace(tzinfo=timezone.utc):
        fail('observation-time-before-snapshot')
    observed_at = started.strftime('%Y-%m-%dT%H:%M:%SZ')
    exact = missing = changed = 0
    deadline = time.monotonic() + 60
    for name, expected in sorted(files.items(), key=lambda item: (item[0] != MANIFEST, item[0])):
        if time.monotonic() >= deadline:
            missing += 1
            continue
        try:
            actual = fetcher(base_url + name, len(expected))
        except SiteContentMismatch:
            changed += 1
            continue
        except Exception:
            missing += 1
            continue
        if actual == expected:
            exact += 1
        else:
            changed += 1
    state = 'conflict' if changed else ('unavailable' if not exact else 'partial') if missing else 'exact-match'
    return {'schemaVersion': 1, 'kind': 'public-ecosystem-site-observation', 'status': state,
            'observedAt': observed_at, 'manifestDigest': verified['manifestDigest'],
            'exactFiles': exact, 'unavailableFiles': missing, 'conflictingFiles': changed,
            'scope': 'one-bounded-observation-not-independent-infrastructure',
            'propagation': 'cdn-propagation-uncertainty', 'sourcePublication': 'unchanged'}


def collect_checkpoint(base_url, output, *, previous_manifest=None, bootstrap_manifest=None, fetcher=None):
    """Fetch a pinned current public bundle, or prove explicit first-publication absence.

    Approval pins come from the protected operator configuration, never from fetched bytes.
    No source-selected code runs, and no output is retained after incomplete collection.
    """
    from .transparency_sources import fetch_site, SiteNotFound
    from .schema_validation import validate_schema
    if bool(previous_manifest) == bool(bootstrap_manifest):
        fail('checkpoint-approval-required')
    pin = previous_manifest or bootstrap_manifest
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', pin):
        fail('checkpoint-pin-invalid')
    output = confined(output)
    if output.exists() or not output.parent.is_dir() or not base_url.endswith('/'):
        fail('checkpoint-output-invalid')
    fetcher = fetcher or (lambda url, limit: fetch_site(url, limit, base_url))
    deadline = time.monotonic() + 60
    try:
        raw_manifest = fetcher(base_url + MANIFEST, MAX_FILE)
    except SiteNotFound:
        if not bootstrap_manifest:
            fail('checkpoint-current-missing')
        return {'status': 'bootstrap-authorized', 'manifestDigest': bootstrap_manifest}
    if bootstrap_manifest:
        fail('checkpoint-bootstrap-site-exists')
    if len(raw_manifest) > MAX_FILE or digest(raw_manifest) != previous_manifest:
        fail('checkpoint-current-conflict')
    manifest = parse(raw_manifest)
    if validate_schema(manifest, 'public-ecosystem-site-bundle-v1.schema.json') or manifest['mode'] != 'production':
        fail('checkpoint-contract')
    rows = manifest['files']
    names = [safe_name(row['path']) for row in rows]
    if (MANIFEST in names or len(names) >= MAX_FILES or len(set(names)) != len(names)
            or any(row['size'] > MAX_FILE for row in rows)
            or sum(row['size'] for row in rows) + len(raw_manifest) > MAX_TOTAL):
        fail('checkpoint-inventory')
    with tempfile.TemporaryDirectory(prefix='.checkpoint-', dir=output.parent) as temporary:
        stage = Path(temporary)/'site'
        stage.mkdir()
        (stage/MANIFEST).write_bytes(raw_manifest)
        for row in rows:
            if time.monotonic() >= deadline:
                fail('checkpoint-time-limit')
            raw = fetcher(base_url + row['path'], row['size'])
            if len(raw) != row['size'] or digest(raw) != row['digest']:
                fail('checkpoint-content')
            path = stage/row['path']
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        verify_checkpoint(stage, previous_manifest)
        stage.rename(output)
    return {'status': 'checkpoint-verified', 'manifestDigest': previous_manifest}
