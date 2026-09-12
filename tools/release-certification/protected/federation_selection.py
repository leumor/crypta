"""Private, original pre-runtime federation selection handoff.

The fixed protected producer authenticates public input members and the independently provisioned
local selection. Only randomized CMS ciphertext may leave the private workspace. GitHub original
artifact/member authentication precedes decryption; encryption supplies confidentiality, not
selection authority. No final runtime observation or daemon freeze is an input.
"""
from __future__ import annotations

from dataclasses import dataclass
import datetime as dt
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tempfile
import zipfile

from bounded_process import run
from original_artifact_authentication import authenticate_original, validate_coordinates, REPOSITORY, _gh, _environment

POLICY = Path('/etc/cryptad-certification/federation-selection.json')
RECIPIENT = Path('/etc/cryptad-certification/federation-selection-recipient.pem')
RECIPIENT_KEY = Path('/etc/cryptad-certification/federation-selection-recipient.key')
WORKFLOW = '.github/workflows/stable-1.0-app-subject-projection.yml'
MEMBER = 'federation-selection.cms'
MAX_BYTES = 512 * 1024 * 1024
_AUTHORITY = object()


class SelectionFailure(ValueError):
    """Fixed private-selection diagnostic; never include supplied values."""


def digest(raw):
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


def _json(raw):
    if not isinstance(raw, bytes) or len(raw) > 1024 * 1024:
        raise SelectionFailure('federation-selection-json-budget')
    def pairs(rows):
        value = {}
        for key, item in rows:
            if key in value:
                raise SelectionFailure('federation-selection-duplicate-key')
            value[key] = item
        return value
    try:
        value = json.loads(raw, object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(SelectionFailure('federation-selection-json-invalid')))
    except (ValueError, RecursionError):
        raise SelectionFailure('federation-selection-json-invalid') from None
    pending, count = [(value, 0)], 0
    while pending:
        child, depth = pending.pop()
        count += 1
        if depth > 32 or count > 32768:
            raise SelectionFailure('federation-selection-json-budget')
        if isinstance(child, dict):
            pending.extend((item, depth + 1) for item in child.values())
        elif isinstance(child, list):
            pending.extend((item, depth + 1) for item in child)
    return value


def _bytes(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()


def _name(name):
    if (not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._/-]{0,219}', name)
            or any(part in {'', '.', '..'} for part in name.split('/'))):
        raise SelectionFailure('federation-selection-member-invalid')
    return name


def _regular(path, maximum=1024 * 1024, *, protected=False, private=False):
    path = Path(path)
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 1 <= info.st_size <= maximum
            or any(parent.is_symlink() for parent in (path, *path.parents))
            or protected and (info.st_uid != 0 or info.st_mode & 0o022)
            or private and info.st_mode & 0o007):
        raise SelectionFailure('federation-selection-file-invalid')
    raw = path.read_bytes()
    if len(raw) != info.st_size:
        raise SelectionFailure('federation-selection-file-changed')
    return raw


def archive_members(raw):
    """Validate the whole bounded archive before reading any selected member."""
    if len(raw) > MAX_BYTES:
        raise SelectionFailure('federation-selection-archive-budget')
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        entries = archive.infolist()
        names, total = set(), 0
        if not 1 <= len(entries) <= 256 or archive.comment:
            raise SelectionFailure('federation-selection-archive-invalid')
        for entry in entries:
            name = _name(entry.filename)
            mode = entry.external_attr >> 16
            if (entry.is_dir() or name.casefold() in names or entry.flag_bits & 1 or entry.extra or entry.comment
                    or stat.S_IFMT(mode) not in {0, stat.S_IFREG}):
                raise SelectionFailure('federation-selection-archive-invalid')
            names.add(name.casefold())
            total += entry.file_size
            if total > MAX_BYTES:
                raise SelectionFailure('federation-selection-archive-budget')
        return {entry.filename: archive.read(entry) for entry in entries}


def _archive(files):
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', zipfile.ZIP_STORED) as archive:
        for name, raw in sorted(files.items()):
            info = zipfile.ZipInfo(_name(name))
            info.external_attr = 0o100600 << 16
            archive.writestr(info, raw)
    return output.getvalue()


def _cms(raw, private_root, *, decrypt=False):
    """Keep key material off command arguments and produce no uploadable plaintext."""
    with tempfile.TemporaryDirectory(prefix='selection-cms-', dir=private_root) as directory:
        root = Path(directory)
        source, target = root / 'input', root / 'output'
        source.write_bytes(raw)
        source.chmod(0o600)
        certificate = root / 'recipient.pem'
        certificate.write_bytes(_regular(RECIPIENT, protected=True))
        args = ['/usr/bin/openssl', 'cms', '-binary', '-in', str(source), '-out', str(target)]
        if decrypt:
            if RECIPIENT_KEY.stat().st_mode & 0o077:
                raise SelectionFailure('federation-selection-key-not-private')
            key = root / 'recipient.key'
            key.write_bytes(_regular(RECIPIENT_KEY, protected=True))
            key.chmod(0o600)
            args += ['-decrypt', '-inform', 'DER', '-recip', str(certificate), '-inkey', str(key)]
        else:
            args += ['-encrypt', '-outform', 'DER', '-aes-256-gcm', str(certificate)]
        try:
            run(args, environment={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'OPENSSL_CONF': '/dev/null'},
                timeout=60, output_limit=4096)
            return _regular(target, MAX_BYTES)
        except (OSError, ValueError):
            raise SelectionFailure('federation-selection-envelope-rejected') from None


def _producer():
    if os.environ.get('GITHUB_WORKFLOW_REF') != f'{REPOSITORY}/{WORKFLOW}@refs/heads/develop':
        raise SelectionFailure('federation-selection-producer-invalid')
    return {'workflowPath': WORKFLOW, 'sourceCommit': os.environ['GITHUB_SHA'],
            'runId': int(os.environ['GITHUB_RUN_ID']), 'runAttempt': int(os.environ['GITHUB_RUN_ATTEMPT'])}


def _validate_handoff(value, files, *, now):
    if (not isinstance(value, dict) or set(value) != {'schemaVersion', 'kind', 'producer', 'generatedAt', 'contexts', 'members'}
            or type(value['schemaVersion']) is not int or value['schemaVersion'] != 1
            or value['kind'] != 'private-federation-selection'
            or not isinstance(value['contexts'], list) or not 1 <= len(value['contexts']) <= 32
            or not isinstance(value['members'], list) or not 1 <= len(value['members']) <= 255):
        raise SelectionFailure('federation-selection-handoff-invalid')
    generated = dt.datetime.fromisoformat(value['generatedAt'].replace('Z', '+00:00'))
    if generated.tzinfo is None or generated > now:
        raise SelectionFailure('federation-selection-time-invalid')
    roster = {}
    for row in value['members']:
        if (not isinstance(row, dict) or set(row) != {'name', 'digest', 'size', 'original'}
                or _name(row['name']) in roster or row['name'] == 'selection-handoff.json'):
            raise SelectionFailure('federation-selection-roster-invalid')
        raw = files.get(row['name'])
        if raw is None or type(row['size']) is not int or row['size'] != len(raw) or row['digest'] != digest(raw):
            raise SelectionFailure('federation-selection-member-substituted')
        if row['original'] is not None:
            if set(row['original']) != {'coordinates', 'member'}:
                raise SelectionFailure('federation-selection-original-invalid')
            validate_coordinates(row['original']['coordinates'])
            _name(row['original']['member'])
        roster[row['name']] = row
    if set(files) != set(roster) | {'selection-handoff.json'}:
        raise SelectionFailure('federation-selection-roster-incomplete')
    identifiers, contexts = set(), []
    for row in value['contexts']:
        if (not isinstance(row, dict) or set(row) != {'id', 'appId', 'member', 'digest', 'generation'}
                or not re.fullmatch(r'[a-z][a-z0-9-]{1,63}', str(row['id'])) or row['id'] in identifiers
                or type(row['generation']) is not int or not 1 <= row['generation'] <= 2**53-1
                or row['member'] not in roster or row['digest'] != roster[row['member']]['digest']):
            raise SelectionFailure('federation-selection-context-invalid')
        identifiers.add(row['id'])
        context = _json(files[row['member']])
        if context.get('appId') != row['appId'] or context.get('generation') != row['generation']:
            raise SelectionFailure('federation-selection-context-substituted')
        parent = PurePosixPath(row['member']).parent
        referenced = set()
        for candidate in context['candidates']:
            for field in ('catalog', 'signature', 'bundle'):
                reference = candidate[field]
                name = _name(str(parent / _name(reference['path'])))
                if (name not in roster or roster[name]['digest'] != reference['digest']
                        or roster[name]['original'] is None):
                    raise SelectionFailure('federation-selection-candidate-original-missing')
                referenced.add(name)
        for field in ('catalogBindings', 'publisherBindings', 'reviewerScopes'):
            for reference in context[field]:
                name = _name(str(parent / _name(reference['path'])))
                if name not in roster or roster[name]['digest'] != reference['digest']:
                    raise SelectionFailure('federation-selection-scope-substituted')
                referenced.add(name)
        contexts.append((row, referenced))
    if set(roster) != {row['member'] for row, _ in contexts} | set().union(*(refs for _, refs in contexts)):
        raise SelectionFailure('federation-selection-unreferenced-member')
    return value


def produce_selection(private_root, output):
    """Seal the root-owned finite selection, after authenticating every public input origin."""
    policy = _json(_regular(POLICY, protected=True, private=True))
    if (set(policy) != {'schemaVersion', 'contexts', 'members'} or type(policy['schemaVersion']) is not int
            or policy['schemaVersion'] != 1 or not isinstance(policy['members'], list)):
        raise SelectionFailure('federation-selection-policy-invalid')
    files, rows = {}, []
    for row in policy['members']:
        if set(row) != {'name', 'path', 'digest', 'size', 'original'} or _name(row['name']) in files:
            raise SelectionFailure('federation-selection-policy-member-invalid')
        raw = _regular(Path(row['path']), MAX_BYTES, protected=row['original'] is None,
                       private=row['original'] is None)
        if digest(raw) != row['digest'] or len(raw) != row['size']:
            raise SelectionFailure('federation-selection-policy-member-substituted')
        if row['original'] is not None:
            origin = row['original']
            artifact = authenticate_original(origin['coordinates'], private_root)
            from app_subject_projection import selected_members
            if selected_members(artifact, {'bundle': origin['member']})['bundle'] != raw:
                raise SelectionFailure('federation-selection-original-member-substituted')
        files[row['name']] = raw
        rows.append({key: item for key, item in row.items() if key != 'path'})
    now = dt.datetime.now(dt.timezone.utc)
    handoff = {'schemaVersion': 1, 'kind': 'private-federation-selection', 'producer': _producer(),
               'generatedAt': now.isoformat(), 'contexts': policy['contexts'], 'members': rows}
    files['selection-handoff.json'] = _bytes(handoff)
    _validate_handoff(handoff, files, now=now)
    encrypted = _cms(_archive(files), private_root)
    with Path(output).open('xb') as stream:
        stream.write(encrypted)


class AuthenticatedSelection:
    """Process-local capability retaining exact original selection bytes and coordinates."""
    def __init__(self, files, value, coordinates, authority=None):
        if authority is not _AUTHORITY:
            raise SelectionFailure('federation-selection-original-required')
        self._files, self._value, self._coordinates = dict(files), _bytes(value), _bytes(coordinates)

    def materialize(self, root):
        root = Path(root)
        if root.exists() or root.is_symlink() or any(p.is_symlink() for p in root.parents):
            raise SelectionFailure('federation-selection-destination-invalid')
        root.mkdir(mode=0o700)
        for name, raw in self._files.items():
            path = root / name
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with path.open('xb') as stream:
                stream.write(raw)
            path.chmod(0o600)

    def context(self, identifier):
        rows = [row for row in _json(self._value)['contexts'] if row['id'] == identifier]
        if len(rows) != 1:
            raise SelectionFailure('federation-selection-context-not-selected')
        return rows[0]

    def require_source(self, identifier, source):
        selected = self.context(identifier)
        context = _json(self._files[selected['member']])
        rows = _json(self._value)['members']
        # Bundle provenance remains the original publisher/build producer, distinct from selection.
        matches = [row for row in rows if row['digest'] == context['bundleDigest'] and row['original'] is not None
                   and row['original']['coordinates'] == source['original']
                   and row['original']['member'] == source['members']['bundle']]
        if not matches or selected['appId'] != source['appId']:
            raise SelectionFailure('federation-selection-content-origin-substituted')
        for field, digest_field in (('catalog', 'catalogDigest'), ('catalogSignature', 'catalogSignatureDigest')):
            if not any(row['digest'] == context[digest_field] and row['original'] is not None
                       and row['original']['coordinates'] == (source.get('catalogOriginal') or source['original'])
                       and row['original']['member'] == source['members'][field] for row in rows):
                raise SelectionFailure('federation-selection-catalog-origin-substituted')


def authenticate_selection(coordinates, private_root):
    if coordinates.get('sourceFamily') != 'federation-selection':
        raise SelectionFailure('federation-selection-original-family-invalid')
    artifact = authenticate_original(coordinates, private_root)
    files = archive_members(artifact.content)
    if set(files) != {MEMBER}:
        raise SelectionFailure('federation-selection-original-roster-invalid')
    with tempfile.TemporaryDirectory(prefix='selection-attestation-', dir=private_root) as directory:
        member = Path(directory) / MEMBER
        member.write_bytes(files[MEMBER])
        proof = _gh(['attestation', 'verify', str(member), '--repo', REPOSITORY, '--signer-workflow',
                     REPOSITORY + '/' + WORKFLOW, '--signer-digest', coordinates['sourceCommit'],
                     '--source-digest', coordinates['sourceCommit'], '--format', 'json'], _environment())
        invocation = f"https://github.com/{REPOSITORY}/actions/runs/{coordinates['runId']}/attempts/{coordinates['runAttempt']}"
        if not isinstance(proof, list) or not any(isinstance(row, dict) and row.get('verificationResult', {}).get(
                'signature', {}).get('certificate', {}).get('runInvocationURI') == invocation for row in proof):
            raise SelectionFailure('federation-selection-attested-attempt-mismatch')
    plain = archive_members(_cms(files[MEMBER], private_root, decrypt=True))
    value = _json(plain['selection-handoff.json'])
    now = dt.datetime.now(dt.timezone.utc)
    _validate_handoff(value, plain, now=now)
    if value['producer'] != {'workflowPath': WORKFLOW, 'sourceCommit': coordinates['sourceCommit'],
                            'runId': coordinates['runId'], 'runAttempt': coordinates['runAttempt']}:
        raise SelectionFailure('federation-selection-producer-substituted')
    if artifact.job_completed_at is not None and dt.datetime.fromisoformat(value['generatedAt']) > dt.datetime.fromisoformat(
            artifact.job_completed_at.replace('Z', '+00:00')):
        raise SelectionFailure('federation-selection-original-time-invalid')
    return AuthenticatedSelection(plain, value, coordinates, _AUTHORITY)
