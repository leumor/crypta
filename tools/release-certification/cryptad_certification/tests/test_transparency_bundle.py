"""Exercise exported bytes, provenance limits, history and bounded public observation."""
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import tempfile
import unittest

from cryptad_certification import transparency_bundle as b
from cryptad_certification import transparency_sources as s


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.addCleanup(self.temp.cleanup)
        self.package = s.collect({'schemaVersion': 1, 'mode': 'production',
                                  'asOf': '2026-09-10T00:00:00Z', 'sources': []}, self.root)

    def build(self, name='site'):
        path = self.root / name
        b.build(self.package, path)
        return path

    def test_reproducible_distinct_roots_and_empty_production(self):
        first, second = self.build('one'), self.build('two')
        self.assertEqual(b.inventory(first), b.inventory(second))
        verified = b.verify(first, production=True)
        self.assertEqual(verified['index']['sources'], [])
        self.assertEqual(verified['authentication'], 'not-established')
        self.assertIn(b'No authenticated public release', (first/'releases/index.html').read_bytes())
        self.assertNotIn(b'synthetic-stable', b''.join(b.inventory(first).values()))

    def test_manifest_is_non_circular_and_exact(self):
        root = self.build()
        manifest = b.parse((root / b.MANIFEST).read_bytes())
        names = [row['path'] for row in manifest['files']]
        self.assertNotIn(b.MANIFEST, names)
        self.assertEqual(set(names), set(b.inventory(root)) - {b.MANIFEST})
        self.assertEqual(b.verify(root)['fileCount'], len(names) + 1)

    def test_tampered_render_cannot_be_resealed(self):
        root = self.build()
        (root/'index.html').write_bytes(b'<h1>All production evidence passed</h1>')
        manifest = b.parse((root/b.MANIFEST).read_bytes())
        for row in manifest['files']:
            if row['path'] == 'index.html':
                raw = (root/'index.html').read_bytes()
                row.update(size=len(raw), digest=b.digest(raw))
        (root/b.MANIFEST).write_bytes(b.canonical(manifest))
        with self.assertRaises(ValueError):
            b.verify(root)

    def test_tampered_view_cannot_be_resealed(self):
        root = self.build()
        index = b.parse((root/b.INDEX).read_bytes())
        index['site']['deployment'] = 'published'
        (root/b.INDEX).write_bytes(b.canonical(index))
        with self.assertRaises(ValueError):
            b.verify(root)

    def test_extra_sidecar_and_missing_asset_fail(self):
        for kind in ('extra', 'missing'):
            with self.subTest(kind=kind):
                root = self.build(kind)
                if kind == 'extra':
                    (root/'secret.json').write_bytes(b'{}')
                else:
                    (root/'assets/site.css').unlink()
                with self.assertRaises(ValueError):
                    b.verify(root)

    def test_links_and_unsafe_names_fail(self):
        for kind in ('symlink', 'hardlink', 'case', 'unicode'):
            with self.subTest(kind=kind):
                root = self.build(kind)
                if kind == 'symlink':
                    (root/'extra').symlink_to(root/'index.html')
                elif kind == 'hardlink':
                    os.link(root/'index.html', root/'extra')
                else:
                    (root/('INDEX.html' if kind == 'case' else 'é.html')).write_bytes(b'x')
                with self.assertRaises(ValueError):
                    b.verify(root)

    def test_manifest_substitution_and_demo_deployment_fail(self):
        root = self.build()
        with self.assertRaises(ValueError):
            b.verify(root, expected_manifest='sha256:'+'0'*64)
        self.package['selection']['mode'] = 'demo'
        with self.assertRaises(ValueError):
            b.build(self.package, self.root/'not-a-preview')
        demo = self.build('demo-site')
        with self.assertRaises(ValueError):
            b.verify(demo, production=True)
        for path, raw in b.inventory(demo).items():
            if path.endswith('.html'):
                self.assertIn(b'Synthetic demo', raw)

    def test_duplicate_json_and_nonfinite_denied(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}', b'{"x":1e999}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                b.parse(raw)

    def test_fresh_output_rejects_existing_and_symlink_parent(self):
        root = self.build()
        with self.assertRaises(ValueError):
            b.build(self.package, root)
        (self.root/'link').symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ValueError):
            b.build(self.package, self.root/'link/new')

    def test_checkpoint_prevents_duplicate_generation_and_identity_change(self):
        previous = {'mode': 'production', 'asOf': '2026-09-10T00:00:00Z',
                    'sources': [{'role': 'lifecycle', 'identity': 'edition-3', 'fields': {'revoked': True}}]}
        current = copy.deepcopy(previous)
        with self.assertRaises(ValueError):
            b.check_history(current, previous)
        current['asOf'] = '2026-09-11T00:00:00Z'
        b.check_history(current, previous)
        current['sources'][0]['fields']['revoked'] = False
        with self.assertRaises(ValueError):
            b.check_history(current, previous)
        current['sources'] = []
        with self.assertRaises(ValueError):
            b.check_history(current, previous)

    def test_offline_build_never_fetches(self):
        from unittest.mock import patch
        with patch('socket.create_connection', side_effect=AssertionError('network prohibited')):
            root = self.build()
            b.verify(root)

    def test_observation_checks_every_asset_and_preserves_source_state(self):
        root = self.build()
        files = b.inventory(root)
        base = 'https://example.org/transparency/'
        calls = []
        def fetch(url, limit):
            name = url.removeprefix(base)
            calls.append(name)
            self.assertEqual(limit, len(files[name]))
            return files[name]
        result = b.observe(root, base, '2026-09-11T00:00:00Z', fetcher=fetch)
        self.assertEqual(result['status'], 'exact-match')
        self.assertEqual(set(calls), set(files))
        self.assertEqual(calls[0], b.MANIFEST)
        self.assertEqual(result['sourcePublication'], 'unchanged')
        self.assertEqual(b.inventory(root), files)
        for kind, expected in [('missing', 'partial'), ('mixed', 'conflict'), ('timeout', 'unavailable')]:
            def broken(url, limit):
                if kind == 'timeout' or (kind == 'missing' and url.endswith('site.css')):
                    raise TimeoutError('SYNTHETIC_PRIVATE_CANARY')
                return b'changed' if kind == 'mixed' and url.endswith('site.css') else files[url.removeprefix(base)]
            result = b.observe(root, base, '2026-09-11T00:00:00Z', fetcher=broken)
            self.assertEqual(result['status'], expected)
            self.assertNotIn('SYNTHETIC_PRIVATE_CANARY', json.dumps(result))

    def test_extra_empty_directory_is_not_an_export_member(self):
        root = self.build()
        (root/'unlisted').mkdir()
        with self.assertRaises(ValueError):
            b.verify(root)

    def test_explicit_checkpoint_survives_tool_revision_without_rewriting_history(self):
        from unittest.mock import patch
        old = self.build('old')
        pin = b.digest((old/b.MANIFEST).read_bytes())
        expected = b.verify(old)['index']
        self.package['selection']['asOf'] = '2026-09-11T00:00:00Z'
        with patch.object(b, 'tool_identity', return_value='sha256:'+'f'*64):
            self.assertEqual(expected, b.verify_checkpoint(old, pin))
            b.build(self.package, self.root/'new', previous=old, previous_manifest=pin)
            self.assertEqual(b.verify(self.root/'new')['index']['asOf'], '2026-09-11T00:00:00Z')
        with self.assertRaises(ValueError):
            b.verify_checkpoint(old, 'sha256:'+'0'*64)
        (old/'index.html').write_bytes(b'substituted')
        with self.assertRaises(ValueError):
            b.verify_checkpoint(old, pin)

    def test_collect_package_is_directly_buildable_offline(self):
        from cryptad_certification.cli import main
        selection = self.root/'selection.json'
        selection.write_bytes(b.canonical(self.package['selection']))
        package = self.root/'package.json'
        site = self.root/'site'
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(['public-ecosystem-transparency', '--mode', 'collect',
                                   '--selection', str(selection), '--output', str(package)]), 0)
            self.assertEqual(main(['public-ecosystem-transparency', '--mode', 'build',
                                   '--source-package', str(package), '--output', str(site)]), 0)
        self.assertEqual(b.verify(site)['index']['sources'], [])

    def test_source_owned_public_projections_reach_real_pages_without_authority_upgrade(self):
        from cryptad_certification.transparency_public_projection import demo_public_projections
        originals = demo_public_projections()
        selection = {'schemaVersion':1,'mode':'demo','asOf':'2026-09-10T12:09:39Z','sources':[]}
        for number, source in enumerate(originals):
            filename = f'private-local-name-{number}.json'
            (self.root/filename).write_bytes(source['raw'])
            selection['sources'].append({'role':source['role'],'file':filename,
                'digest':s.digest(source['raw']),'size':len(source['raw']),'required':True})
        package = s.collect(selection, self.root)
        site = self.root/'demo-authorities'
        b.build(package, site)
        index = b.verify(site)['index']
        self.assertEqual({'release','maintenance','advisories'}, {row['role'] for row in index['sources']})
        for row in index['sources']:
            self.assertEqual('not-established', row['publication'])
            self.assertEqual('not-established', row['activation'])
            self.assertEqual('derived-statement-schema-and-integrity-only', row['verification'])
        all_bytes = b''.join(b.inventory(site).values())
        for private in (b'private-local-name',b'caseOpaqueId',b'privateRecordDigest',b'candidateIdentityDigest'):
            self.assertNotIn(private, all_bytes)
        self.assertIn(b'reportedSourcePublication', (site/'releases/index.html').read_bytes())
        self.assertIn(b'csa-', (site/'advisories/index.html').read_bytes())

    def test_observation_cannot_predate_snapshot(self):
        root = self.build()
        with self.assertRaises(ValueError):
            b.observe(root, 'https://example.org/site/', '2026-09-09T00:00:00Z',
                      fetcher=lambda *_: self.fail('fetch must not happen'))

    def project_artifact(self, role, value, seal):
        from cryptad_certification import transparency_adapters as adapter
        value = copy.deepcopy(value)
        value[seal] = adapter._digest(adapter._canonical({k: v for k, v in value.items() if k != seal}))
        if role == 'keys':
            from cryptad_certification.engines import stable_1_0_catalog_authority as authority
            value[seal] = authority._semantic_digest(value, seal)
        return adapter.project(role, b.canonical(value), {'mode': 'demo'})['view']

    def test_lifecycle_successor_cannot_splice_or_remove_revocation(self):
        from cryptad_certification import transparency_adapters as adapter
        descriptor = json.loads(next(source['raw'] for source in adapter.demo_sources()
                                     if source['role'] == 'lifecycle'))
        descriptor['currentStableBuild'] = descriptor['recommendedBuild'] = None
        revoked = descriptor['entries'][0]
        revoked['lifecycleStatus'] = 'revoked'
        revoked['securityRevocationEffectiveAt'] = revoked['statusEffectiveAt'] = descriptor['effectiveAt']
        other = copy.deepcopy(revoked)
        other['buildVersion'] = '2'
        other['releaseId'] = 'synthetic-stable-2'
        descriptor['entries'].append(other)
        older = self.project_artifact('lifecycle', descriptor, 'descriptorDigest')
        successor = copy.deepcopy(descriptor)
        successor.update(descriptorEdition=2, previousDescriptorEdition=1,
                         previousDescriptorDigest=older['fields']['descriptorDigest'])
        newer = self.project_artifact('lifecycle', successor, 'descriptorDigest')
        b.validate_lineage([newer, older])
        for mutation in ('remove', 'restore', 'splice'):
            with self.subTest(mutation=mutation):
                changed = copy.deepcopy(successor)
                if mutation == 'remove':
                    changed['entries'].pop(0)
                elif mutation == 'restore':
                    changed['entries'][0]['lifecycleStatus'] = 'current-stable'
                    changed['entries'][0]['securityRevocationEffectiveAt'] = None
                else:
                    changed['previousDescriptorDigest'] = 'sha256:' + 'f' * 64
                newer = self.project_artifact('lifecycle', changed, 'descriptorDigest')
                reason = 'source-lineage-conflict' if mutation == 'splice' else 'source-revocation-removed'
                with self.assertRaisesRegex(ValueError, reason):
                    b.validate_lineage([older, newer])

    def test_key_successors_preserve_identity_and_monotonic_lifecycle_and_compromise(self):
        from cryptad_certification import transparency_adapters as adapter
        artifact = json.loads(next(source['raw'] for source in adapter.demo_sources()
                                   if source['role'] == 'keys'))
        transitions = (
            ('retired', 'uncompromised', 'revoked', 'compromised', True),
            ('retired', 'suspected', 'revoked', 'compromised', True),
            ('revoked', 'compromised', 'revoked', 'compromised', True),
            ('retired', 'uncompromised', 'active', 'uncompromised', False),
            ('revoked', 'compromised', 'retired', 'compromised', False),
            ('retiring', 'uncompromised', 'active', 'uncompromised', False),
            ('revoked', 'compromised', 'revoked', 'suspected', False),
            ('revoked', 'suspected', 'revoked', 'uncompromised', False),
        )
        for previous, compromise, following, next_compromise, accepted in transitions:
            with self.subTest(previous=previous, compromise=compromise,
                              following=following, next_compromise=next_compromise):
                original = copy.deepcopy(artifact)
                original['keys'][0].update(lifecycle=previous, compromiseState=compromise)
                older = self.project_artifact('keys', original, 'selfDigest')
                successor = copy.deepcopy(original)
                successor.update(keysetVersion=original['keysetVersion'] + 1,
                                 previousKeysetDigest=original['keysetDigest'],
                                 keysetDigest='sha256:' + 'f' * 64)
                successor['keys'][0].update(lifecycle=following, compromiseState=next_compromise)
                newer = self.project_artifact('keys', successor, 'selfDigest')
                if accepted:
                    b.validate_lineage([newer, older])
                else:
                    with self.assertRaisesRegex(ValueError, 'source-key-history-removed'):
                        b.validate_lineage([older, newer])

    def test_review_expiry_drives_snapshot_freshness_and_rendering(self):
        from cryptad_certification import transparency_adapters as adapter
        raw = next(source['raw'] for source in adapter.demo_sources() if source['role'] == 'reviews')
        for expiry, expected in ((None, 'no-validity-window-supplied'),
                                 ('2026-08-22T00:00:00Z', 'stale-at-snapshot'),
                                 ('2026-09-10T00:00:00Z', 'stale-at-snapshot'),
                                 ('2026-09-11T00:00:00Z', 'within-selected-validity')):
            with self.subTest(expiry=expiry):
                receipt = raw + (f'review.receipt.expires.at={expiry}\n'.encode() if expiry else b'')
                (self.root/'review.json').write_bytes(receipt)
                package = s.collect({'schemaVersion': 1, 'mode': 'demo',
                    'asOf': '2026-09-10T00:00:00Z', 'sources': [{'role': 'reviews',
                    'file': 'review.json', 'digest': s.digest(receipt),
                    'size': len(receipt), 'required': True}]}, self.root)
                files = b.render_files(package)
                row = b.parse(files[b.INDEX])['sources'][0]
                self.assertEqual(row['staleAt'], expiry)
                self.assertEqual(row['freshness'], expected)
                self.assertEqual(row['verification'], 'schema-and-semantic-checks-only')
                self.assertEqual(b'Historical / stale as of this snapshot.' in files['catalogs/index.html'],
                                 expected == 'stale-at-snapshot')
        for expiry in ('', 'not-a-date', '2026-02-30T00:00:00Z'):
            with self.subTest(invalid_expiry=expiry):
                with self.assertRaisesRegex(adapter.ProjectionError, 'transparency-review-timestamp-invalid'):
                    adapter.project('reviews', raw + f'review.receipt.expires.at={expiry}\n'.encode(),
                                    {'mode': 'demo'})

    def test_observation_classifies_bounded_transport_size_mismatches_as_conflicts(self):
        from unittest import mock
        from cryptad_certification.engines import stable_1_0_public_observation as transport
        from cryptad_certification.tests.test_stable_public_observation import (
            _FakeHttpResponse, _scripted_connections,
        )
        site = self.build()
        files = b.inventory(site)
        base = 'https://example.org/site/'
        rules, policy_digest = s.policy()
        rules = {**rules, 'siteTargets': [base]}
        for target in (b.MANIFEST, 'index.html'):
            for mode in ('declared-oversize', 'streamed-oversize', 'missing'):
                with self.subTest(target=target, mode=mode):
                    responses = []
                    target_response = None
                    for name, raw in sorted(files.items(), key=lambda item: (item[0] != b.MANIFEST, item[0])):
                        if name == target:
                            body = raw + b'SYNTHETIC_PRIVATE_RESPONSE_CANARY'
                            headers = {'Content-Length': str(len(body))} if mode == 'declared-oversize' else {}
                            response = _FakeHttpResponse(404 if mode == 'missing' else 200, body, headers)
                            target_response = response
                        else:
                            response = _FakeHttpResponse(200, raw)
                        responses.append(response)
                    factory, _ = _scripted_connections(responses)
                    with mock.patch.object(s, 'policy', return_value=(rules, policy_digest)), \
                         mock.patch.object(transport, '_global_addresses', return_value=('8.8.8.8',)), \
                         mock.patch.object(transport, '_PinnedHTTPSConnection', side_effect=factory):
                        result = b.observe(site, base, '2026-09-11T00:00:00Z')
                    self.assertEqual(result['status'], 'partial' if mode == 'missing' else 'conflict')
                    self.assertEqual(result['conflictingFiles'], 0 if mode == 'missing' else 1)
                    self.assertEqual(result['unavailableFiles'], 1 if mode == 'missing' else 0)
                    self.assertEqual(result['exactFiles'], len(files) - 1)
                    self.assertNotIn('SYNTHETIC_PRIVATE_RESPONSE_CANARY', json.dumps(result))
                    if mode == 'streamed-oversize':
                        self.assertEqual(target_response._body.tell(), len(files[target]) + 1)
                    else:
                        self.assertEqual(target_response.read_sizes, [])

    def test_reviewed_repository_revisions_survive_policy_and_checkpoint_update(self):
        from unittest.mock import patch
        old_raw = (s.POLICY_PATH.parent/'repository-status.json').read_bytes()
        new_value = json.loads(old_raw)
        new_value['asOf'] = '2026-09-11T00:00:00Z'
        new_value['obligations'][0]['description'] += ' Updated repository assessment.'
        new_raw = b.canonical(new_value)
        def package(raws, as_of):
            selected = []
            for number, raw in enumerate(raws):
                name = f'revision-{number}.json'
                (self.root/name).write_bytes(raw)
                selected.append({'role': 'repository-status', 'file': name,
                                 'digest': s.digest(raw), 'size': len(raw), 'required': True})
            return s.collect({'schemaVersion': 1, 'mode': 'production', 'asOf': as_of,
                              'sources': selected}, self.root)
        old_site = self.root/'old-status'
        b.build(package([old_raw], '2026-09-10T12:09:39Z'), old_site)
        old_index = b.verify(old_site)['index']
        pin = b.digest((old_site/b.MANIFEST).read_bytes())
        rules, _ = s.policy()
        new_pin = {**rules['approvedSources'][0], 'digest': s.digest(new_raw), 'size': len(new_raw)}
        rules['approvedSources'].append(new_pin)
        with patch.object(s, 'policy', return_value=(rules, s.digest(s.canonical(rules)))):
            combined = package([old_raw, new_raw], '2026-09-11T00:00:00Z')
            new_site = self.root/'new-status'
            b.build(combined, new_site, previous=old_site, previous_manifest=pin)
            current = b.verify(new_site)['index']
            self.assertEqual(current['sources'][0], old_index['sources'][0])
            self.assertEqual(len({row['identity'] for row in current['sources']}), 2)
            with self.assertRaisesRegex(ValueError, 'selected-history-removed'):
                b.build(package([new_raw], '2026-09-11T00:00:00Z'), self.root/'removed',
                        previous=old_site, previous_manifest=pin)
            unapproved = new_raw + b' '
            with self.assertRaisesRegex(ValueError, 'source-not-approved'):
                b.render_files(package([unapproved], '2026-09-11T00:00:00Z'))
        rules['approvedSources'] = [new_pin]
        with patch.object(s, 'policy', return_value=(rules, s.digest(s.canonical(rules)))):
            with self.assertRaisesRegex(ValueError, 'source-not-approved'):
                b.render_files(package([old_raw, new_raw], '2026-09-11T00:00:00Z'))

    def test_legacy_repository_identity_checkpoint_matches_only_identical_statement(self):
        from cryptad_certification import transparency_adapters as adapter
        raw = (s.POLICY_PATH.parent/'repository-status.json').read_bytes()
        row = adapter.project('repository-status', raw, {'mode': 'production'})['view']
        previous = {'mode': 'production', 'asOf': '2026-09-10T12:09:39Z',
                    'sources': [{**copy.deepcopy(row), 'identity': 'repository-status'}]}
        current = {'mode': 'production', 'asOf': '2026-09-11T00:00:00Z', 'sources': [row]}
        b.check_history(current, previous)
        current['sources'][0]['fields']['phase12'] = 'complete'
        with self.assertRaisesRegex(ValueError, 'source-identity-conflict'):
            b.check_history(current, previous)

    def test_cli_failure_has_only_fixed_diagnostic_and_no_public_output(self):
        from cryptad_certification.cli import main
        output = self.root/'site'
        captured = io.StringIO()
        with contextlib.redirect_stdout(captured):
            result = main(['public-ecosystem-transparency', '--mode', 'build', '--selection',
                           str(self.root/'SYNTHETIC_PRIVATE_CANARY.json'), '--output', str(output)])
        self.assertEqual(result, 2)
        self.assertNotIn('SYNTHETIC_PRIVATE_CANARY', captured.getvalue())
        self.assertFalse(output.exists())


class LocalObservationTests(unittest.TestCase):
    """Local HTTP is injected only by the test; no CLI flag can enable it for production."""
    def test_http_exact_partial_redirect_and_mixed_generation(self):
        import http.client
        import http.server
        import threading
        from urllib.parse import urlsplit
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            package = s.collect({'schemaVersion': 1, 'mode': 'production',
                                 'asOf': '2026-09-10T00:00:00Z', 'sources': []}, root)
            site = root/'site'
            b.build(package, site)
            files = b.inventory(site)
            state = {'mode': 'exact'}
            class Handler(http.server.BaseHTTPRequestHandler):
                def log_message(self, *_args):
                    pass
                def do_GET(self):
                    name = self.path.removeprefix('/site/')
                    if name not in files or (state['mode'] == 'missing' and name == 'assets/site.css'):
                        self.send_error(404)
                        return
                    if state['mode'] == 'redirect':
                        self.send_response(302)
                        self.send_header('Location', 'http://127.0.0.1/private-canary')
                        self.end_headers()
                        return
                    raw = b'other-generation' if state['mode'] == 'mixed' and name == b.MANIFEST else files[name]
                    self.send_response(200)
                    self.send_header('Content-Length', str(len(raw)))
                    self.end_headers()
                    self.wfile.write(raw)
            server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            self.addCleanup(server.server_close)
            self.addCleanup(server.shutdown)
            base = f'http://127.0.0.1:{server.server_port}/site/'
            def fetch(url, limit):
                parsed = urlsplit(url)
                self.assertEqual(parsed.hostname, '127.0.0.1')
                self.assertEqual(parsed.port, server.server_port)
                connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=1)
                try:
                    connection.request('GET', parsed.path)
                    response = connection.getresponse()
                    if response.status != 200:
                        raise ValueError('synthetic-http-unavailable')
                    return response.read(limit + 1)
                finally:
                    connection.close()
            for mode, expected in [('exact', 'exact-match'), ('missing', 'partial'),
                                   ('redirect', 'unavailable'), ('mixed', 'conflict')]:
                state['mode'] = mode
                result = b.observe(site, base, '2026-09-11T00:00:00Z', fetcher=fetch)
                self.assertEqual(result['status'], expected)
                self.assertNotIn('127.0.0.1', json.dumps(result))
