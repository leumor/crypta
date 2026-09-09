#!/usr/bin/env python3
"""Compare exact historical/current JavaScript sources without claiming release identity."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

SOURCES = {
    'sdk.js': 'platform-sdk-js/src/main/resources/network/crypta/platform/sdk/js/crypta-platform.js',
    'feed.js': 'apps/feed-reader/src/staged/static/app.js',
    'social.js': 'apps/social-inbox/src/staged/static/app.js',
}
CORPUS = 'platform-api/src/test/resources/content-profile-conformance/v1'
MAX_BLOB = 1024 * 1024


def digest(data: bytes) -> str:
    return 'sha256:' + hashlib.sha256(data).hexdigest()


def git(root: Path, *args: str) -> bytes:
    return subprocess.check_output(['git', *args], cwd=root, stderr=subprocess.DEVNULL, timeout=30)


def exact_commit(root: Path, value: str) -> str:
    if not re.fullmatch(r'[0-9a-f]{40}', value):
        raise ValueError('profile-source-requires-exact-commit')
    if git(root, 'rev-parse', value + '^{commit}').decode().strip() != value:
        raise ValueError('profile-source-commit-mismatch')
    return value


def blob(root: Path, commit: str, name: str) -> bytes:
    entry = git(root, 'ls-tree', commit, '--', name).decode().strip()
    if not entry.startswith('100644 blob ') or entry.split('\t')[-1] != name:
        raise ValueError('profile-source-not-regular-blob')
    oid = entry.split()[2]
    if int(git(root, 'cat-file', '-s', oid)) > MAX_BLOB:
        raise ValueError('profile-source-byte-limit')
    return git(root, 'cat-file', 'blob', oid)


def materialize(root: Path, commit: str, destination: Path) -> dict:
    destination.mkdir(mode=0o700)
    subjects = []
    for target, source in SOURCES.items():
        data = blob(root, commit, source)
        (destination / target).write_bytes(data)
        subjects.append({'file': source, 'digest': digest(data), 'size': len(data)})
    return {'repository': 'crypta-network/cryptad', 'commit': commit,
            'identityClass': 'local-git-source-comparison', 'subjects': subjects}


def compare(root: Path, previous: str, current: str) -> dict:
    """Execute immutable Git blobs; original published binary authenticity is not inferred."""
    previous, current = exact_commit(root, previous), exact_commit(root, current)
    if previous == current:
        raise ValueError('profile-previous-current-source-alias')
    if subprocess.run(['git', 'merge-base', '--is-ancestor', previous, current], cwd=root,
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30).returncode:
        raise ValueError('profile-previous-source-not-predecessor')
    node = shutil.which('node')
    if not node:
        raise ValueError('profile-node-runtime-missing')
    adapter = Path(__file__).with_suffix('.cjs')
    with tempfile.TemporaryDirectory(prefix='cryptad-profile-comparison-') as directory:
        private = Path(directory)
        older = materialize(root, previous, private / 'previous')
        newer = materialize(root, current, private / 'current')
        corpus = private / 'corpus'
        corpus.mkdir(mode=0o700)
        names = git(root, 'ls-tree', '-r', '--name-only', current, '--', CORPUS).decode().splitlines()
        if not 1 <= len(names) <= 256:
            raise ValueError('profile-corpus-count-limit')
        corpus_subjects = []
        for name in names:
            relative = Path(name).relative_to(CORPUS)
            if '..' in relative.parts or relative.is_absolute():
                raise ValueError('profile-corpus-path-invalid')
            data = blob(root, current, name)
            target = corpus / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            corpus_subjects.append([relative.as_posix(), digest(data)])
        manifest = json.loads((corpus / 'manifest.json').read_bytes())
        ids = set()
        for row in manifest['cases']:
            if row['caseId'] in ids:
                raise ValueError('profile-corpus-duplicate-case')
            ids.add(row['caseId'])
            for field in ('inputFile', 'expectedCanonicalBytesFile', 'expectedSignaturePreimageFile'):
                if field not in row:
                    continue
                selected = Path(row[field])
                if selected.is_absolute() or '..' in selected.parts or not (corpus / selected).is_file():
                    raise ValueError('profile-corpus-path-invalid')
            item = Path(row['inputFile'])
            if item.is_absolute() or '..' in item.parts:
                raise ValueError('profile-corpus-path-invalid')
            data = (corpus / item).read_bytes()
            if len(data) != row['inputSize'] or digest(data) != 'sha256:' + row['inputDigest']:
                raise ValueError('profile-corpus-input-mismatch')
        process_helper = Path(__file__).parents[1] / 'release-certification/protected/bounded_process.py'
        spec = importlib.util.spec_from_file_location('profile_bounded_process', process_helper)
        bounded = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(bounded)
        raw = bounded.run([node, str(adapter), str(private / 'previous'),
                           str(private / 'current'), str(corpus)], timeout=120,
                          output_limit=MAX_BLOB, environment={'PATH': os.defpath, 'LANG': 'C.UTF-8'})
        value = json.loads(raw)
        if (set(value) != {'schemaVersion', 'runtime', 'cases', 'evidenceLevel', 'topology',
                           'releaseEligible', 'unsupportedDirections'}
                or value['releaseEligible'] is not False
                or value['evidenceLevel'] != 'local-source-javascript-comparison'):
            raise ValueError('profile-comparison-output-invalid')
        expected = {'feed-generated-current-to-previous', 'feed-generated-previous-to-current'}
        expected.update(role + '-' + row['caseId'] for role in ('current', 'previous')
                        for row in manifest['cases']
                        if row['profileId'] != 'crypta.trust.statement.v1'
                        and row.get('expectedDecodeOutcome') != 'rejected')
        if (len(value['cases']) != len(expected)
                or {row['caseId'] for row in value['cases']} != expected
                or any(set(row) != {'caseId', 'outcome'} or row['outcome'] != 'pass'
                       for row in value['cases'])):
            raise ValueError('profile-comparison-case-set-invalid')
        value.update(previous=older, current=newer,
                     adapterDigest=digest(adapter.read_bytes()),
                     driverDigest=digest(Path(__file__).read_bytes()),
                     processHelperDigest=digest(process_helper.read_bytes()),
                     runtimeDigest=digest(Path(node).resolve().read_bytes()),
                     corpusDigest=digest(json.dumps(corpus_subjects, separators=(',', ':')).encode()))
        return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace-root', type=Path, default=Path.cwd())
    parser.add_argument('--previous-source', required=True)
    parser.add_argument('--current-source', required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.out.exists() or args.out.is_symlink() or any(p.is_symlink() for p in args.out.parents):
            raise ValueError('profile-output-must-be-new-and-unlinked')
        value = compare(args.workspace_root, args.previous_source, args.current_source)
        with args.out.open('x', encoding='utf-8') as output:
            json.dump(value, output, sort_keys=True, indent=2)
            output.write('\n')
        return 0
    except (ValueError, OSError, subprocess.SubprocessError, KeyError):
        print('profile-comparison-failed; no release evidence produced')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
