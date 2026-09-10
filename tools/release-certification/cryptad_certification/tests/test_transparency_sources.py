"""Exercise source admission and privacy boundaries with synthetic bytes only."""
import copy
import json
import io
import http.client
import http.server
import threading
import time
from urllib.parse import urlsplit
import stat
import zipfile
from types import SimpleNamespace
from dataclasses import dataclass
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cryptad_certification import transparency_sources as sources
from cryptad_certification import maintenance_drill_command as drill


class TransparencySourcesTests(unittest.TestCase):
    def selection(self):
        return {"schemaVersion": 1, "mode": "production", "asOf": "2026-09-10T00:00:00Z", "sources": []}

    def test_network_requires_reviewed_exact_url_before_transport(self):
        with patch('cryptad_certification.engines.stable_1_0_public_observation.PublicObservationTransport') as transport:
            with self.assertRaises(sources.SourceError):
                sources.fetch_public('https://example.com/unselected.json')
            transport.assert_not_called()

    def test_production_repository_projection_uses_exact_reviewed_bytes(self):
        raw = sources.safe_read(sources.POLICY_PATH.parent / 'repository-status.json')
        selection = self.selection()
        selection['sources'] = [{"role": "repository-status", "file": "repository-status.json", "digest": sources.digest(raw), "size": len(raw), "required": True}]
        package = sources.collect(selection, sources.POLICY_PATH.parent)
        records = sources.admit(package)['records']
        self.assertEqual(1, len(records))
        self.assertEqual('repository-reported', records[0]['evidenceClass'])
        self.assertEqual('not-established', records[0]['publication'])

    def test_optional_missing_differs_from_invalid_supplied_and_required(self):
        selection = self.selection()
        selection["mode"] = "demo"
        selection['sources'] = [{"role": "keys", "file": "keys.json", "digest": sources.digest(b'{}'), "size": 2, "required": False}]
        with tempfile.TemporaryDirectory() as root:
            package = sources.collect(selection, root)
            self.assertEqual([{"role": "keys", "status": "optional-source-unavailable"}], sources.admit(package)['sources'])
            package['selection']['sources'][0]['required'] = True
            with self.assertRaisesRegex(sources.SourceError, 'source-required-missing'):
                sources.admit(package)
            selection['sources'][0]['required'] = False
            Path(root, 'keys.json').write_bytes(b'[]')
            with self.assertRaises(sources.SourceError):
                sources.collect(selection, root)

    def test_site_fetch_requires_exact_reviewed_prefix(self):
        rules, pin = sources.policy()
        rules['siteTargets'] = ['https://example.com/transparency/']
        with patch.object(sources, 'policy', return_value=(rules, pin)), patch('cryptad_certification.engines.stable_1_0_public_observation.PublicObservationTransport') as transport:
            for url in ('https://example.com/transparency-evil/a', 'https://evil.com/transparency/a', 'https://example.com/transparency/%2e%2e/a'):
                with self.assertRaises(sources.SourceError):
                    sources.fetch_site(url, 20, 'https://example.com/transparency/')
            transport.assert_not_called()
            transport.return_value._read.return_value = (b'bytes', None)
            self.assertEqual(b'bytes', sources.fetch_site('https://example.com/transparency/a', 20, 'https://example.com/transparency/'))
            self.assertEqual(0, transport.return_value._read.call_args.kwargs['redirect_budget'])

    def test_production_drill_pins_original_source_policy_and_helpers(self):
        record = drill._seal(drill.plan())
        pins = {key: copy.deepcopy(record[key]) for key in ('helperFileDigests', 'policyFileDigest', 'checkoutIdentity')}
        context = {'mode': 'production', 'approvedSource': {'historicalDrill': pins}}
        self.assertEqual('verified-local-integrity', sources.project_drill(sources.canonical(record), context)['view']['verification'])
        for key in pins:
            bad = copy.deepcopy(context)
            bad['approvedSource']['historicalDrill'][key] = None
            with self.assertRaisesRegex(sources.SourceError, 'drill-historical-binding-invalid'):
                sources.project_drill(sources.canonical(record), bad)

    def archive(self, name='source.json', mode=None, extra=False, payload=b'{}'):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, 'w') as archive:
            member = zipfile.ZipInfo(name)
            if mode is not None:
                member.external_attr = mode << 16
            archive.writestr(member, payload)
            if extra:
                archive.writestr('private-canary.json', b'private-canary')
        return stream.getvalue()

    def test_archive_closed_members_links_paths_and_expansion_bounds(self):
        entry = {'members': ['source.json'], 'member': 'source.json', 'size': 2, 'digest': sources.digest(b'{}')}
        self.assertEqual(b'{}', sources._selected_archive_member(self.archive(), entry))
        attacks = [self.archive('../source.json'), self.archive(mode=stat.S_IFLNK | 0o777), self.archive(extra=True), self.archive(payload=b'a'*262145)]
        for raw in attacks:
            with self.subTest(size=len(raw)), self.assertRaises(sources.SourceError) as caught:
                sources._selected_archive_member(raw, entry)
            self.assertNotIn('canary', str(caught.exception))

    def test_original_authentication_checks_type_coordinates_and_attested_attempt(self):
        @dataclass
        class OriginalArtifact:
            content: bytes
            coordinates: dict
        raw = self.archive()
        coordinates = {'artifactSize':len(raw),'artifactDigest':sources.digest(raw),'sourceCommit':'a'*40,'sourceFamily':'catalog-source','runId':1,'runAttempt':2}
        entry = {'role':'keys','digest':sources.digest(b'{}'),'size':2,'original':coordinates,'members':['source.json'],'member':'source.json'}
        helper = SimpleNamespace(OriginalArtifact=OriginalArtifact, validate_coordinates=lambda value:value,
            authenticate_original=lambda value,root:OriginalArtifact(raw, coordinates),
            PRODUCERS={'catalog-source':('.github/workflows/stable-1.0-ga-promotion.yml','env','job')},
            REPOSITORY='crypta-network/cryptad', _environment=lambda:{},
            _gh=lambda args,env:[{'verificationResult':{'signature':{'certificate':{'runInvocationURI':'https://github.com/crypta-network/cryptad/actions/runs/1/attempts/2'}}}}])
        rules,pin=sources.policy(); rules['networkSources']=[entry]
        with patch.object(sources,'policy',return_value=(rules,pin)), patch.object(sources,'_original_helper',return_value=helper):
            self.assertEqual(b'{}',sources.fetch_original_member(entry))
            helper.authenticate_original=lambda value,root:SimpleNamespace(content=raw,coordinates=coordinates)
            with self.assertRaises(sources.SourceError):
                sources.fetch_original_member(entry)
            helper.authenticate_original=lambda value,root:OriginalArtifact(raw,{**coordinates,'runAttempt':3})
            with self.assertRaises(sources.SourceError):
                sources.fetch_original_member(entry)
            helper.authenticate_original=lambda value,root:OriginalArtifact(raw,coordinates)
            helper._gh=lambda args,env:[{'verificationResult':{'signature':{'certificate':{'runInvocationURI':'https://github.com/crypta-network/cryptad/actions/runs/1/attempts/3'}}}}]
            with self.assertRaises(sources.SourceError):
                sources.fetch_original_member(entry)

    def test_reason_fields_reject_private_digests_before_export(self):
        for text in ('sha256:'+'a'*64, 'a'*64, 'mail contact canary', '/private/canary'):
            with self.assertRaises(sources.SourceError) as caught:
                sources._disclosure_fields({'entries':[{'reasonCodes':[text]}]})
            self.assertNotIn(text, str(caught.exception))
        sources._disclosure_fields({'reasonCodes':['policy-window-transition']})

    def test_local_synthetic_http_observation_compares_every_asset(self):
        from cryptad_certification import transparency_bundle as bundle
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            package = sources.collect(self.selection(), root)
            site = root / 'site'
            bundle.build(package, site)
            files = bundle.inventory(site)
            mutable = {'mode':'exact'}
            class Handler(http.server.BaseHTTPRequestHandler):
                def log_message(self, *_args):
                    pass
                def do_GET(self):
                    name = self.path.lstrip('/')
                    mode = mutable['mode']
                    if mode == 'timeout':
                        time.sleep(.1)
                        return
                    if mode == 'redirect':
                        self.send_response(302); self.send_header('Location', '/index.html'); self.end_headers(); return
                    if name not in files or (mode == 'partial' and name == 'index.html'):
                        self.send_response(404); self.end_headers(); return
                    body = files[name]
                    if mode == 'mixed' and name == 'index.html':
                        body = b'changed-generation'
                    if mode == 'stale' and name == bundle.MANIFEST:
                        body = b'stale-manifest'
                    self.send_response(200); self.send_header('Content-Length', str(len(body))); self.end_headers()
                    try:
                        self.wfile.write(body)
                    except BrokenPipeError:
                        pass
            server = http.server.ThreadingHTTPServer(('127.0.0.1',0), Handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
            base = f'http://127.0.0.1:{server.server_port}/'
            def synthetic_fetch(url, limit):
                parsed = urlsplit(url)
                connection = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=.03)
                try:
                    connection.request('GET', parsed.path)
                    response = connection.getresponse()
                    if response.status != 200:
                        raise ValueError('synthetic-fetch-unavailable')
                    return response.read(limit+1)
                finally:
                    connection.close()
            try:
                for mode,expected in [('exact','exact-match'),('partial','partial'),('mixed','conflict'),('stale','conflict'),('redirect','unavailable'),('timeout','unavailable')]:
                    mutable['mode']=mode
                    result=bundle.observe(site,base,'2026-09-10T01:00:00Z',fetcher=synthetic_fetch)
                    self.assertEqual(expected,result['status'])
                    self.assertEqual('unchanged',result['sourcePublication'])
            finally:
                server.shutdown(); server.server_close(); thread.join()

    def test_all_demo_source_families_pass_typed_raw_disclosure_gate(self):
        from cryptad_certification.transparency_adapters import demo_sources
        selection = self.selection(); selection['mode'] = 'demo'
        with tempfile.TemporaryDirectory() as root:
            for number, entry in enumerate(demo_sources()):
                name = f'source-{number}.json'
                Path(root,name).write_bytes(entry['raw'])
                selection['sources'].append({'role':entry['role'],'file':name,'digest':sources.digest(entry['raw']),'size':len(entry['raw']),'required':True})
            records = sources.admit(sources.collect(selection,root))['records']
            self.assertEqual(7,len(records))
            self.assertTrue(all(row['evidenceClass'] == 'synthetic-preview' for row in records))

    def test_empty_production_is_valid(self):
        with tempfile.TemporaryDirectory() as root:
            package = sources.collect(self.selection(), root)
            self.assertEqual([], sources.admit(package)["records"])

    def test_duplicates_nonfinite_and_oversize_fail(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}', b'{"a":1e999}', b'[' * 2000):
            with self.subTest(raw=raw[:10]), self.assertRaises(sources.SourceError):
                sources.strict_json(raw)

    def test_bad_links_fail_without_reflecting_secrets(self):
        for url in ('https://example.com/?token=canary', 'https://user:canary@example.com/a',
                    'https://127.0.0.1/a', 'https://example.local/a', 'https://example.com/%252e%252e/a',
                    'https://example.com/../a', 'javascript:canary', 'data:text/html,canary',
                    'https://example.com/a#canary', 'https://example.com\\@evil.com/a'):
            with self.subTest(url=url), self.assertRaises(sources.SourceError) as caught:
                sources.safe_link(url)
            self.assertNotIn('canary', str(caught.exception))
        self.assertEqual('https://github.com/crypta-network/cryptad', sources.safe_link('https://github.com/crypta-network/cryptad'))

    def test_local_selected_filename_never_enters_public_package(self):
        raw = sources.safe_read(sources.POLICY_PATH.parent / 'repository-status.json')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            name = 'private-incident-canary.json'
            (root/name).write_bytes(raw)
            selection = self.selection()
            selection['sources'] = [{'role':'repository-status','file':name,'digest':sources.digest(raw),
                                     'size':len(raw),'required':True}]
            package = sources.collect(selection, root)
            self.assertNotIn(name, json.dumps(package))
            self.assertEqual('source-00.json', package['selection']['sources'][0]['file'])
            self.assertEqual('source-00.json', package['members'][0]['file'])

    def test_missing_optional_production_source_still_requires_disclosure_pin(self):
        with tempfile.TemporaryDirectory() as directory:
            selection = {"schemaVersion": 1, "mode": "production", "asOf": "2026-09-10T12:09:39Z",
                         "sources": [{"role": "lifecycle", "file": "absent.json", "digest": "sha256:"+"a"*64,
                                      "size": 2, "required": False}]}
            with self.assertRaises(ValueError):
                sources.collect(selection, Path(directory).resolve())

    def test_private_crypta_insertion_uri_is_never_clickable(self):
        with self.assertRaises(ValueError):
            sources.safe_link('crypta:USK@abc,def,AQECAAE/name/1', crypta=True)

    def test_symlinks_hardlinks_and_bounds_fail(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            original = root / 'a'
            original.write_bytes(b'canary')
            link = root / 'b'
            link.symlink_to(original)
            with self.assertRaises(sources.SourceError):
                sources.safe_read(link)
            link.unlink()
            os.link(original, link)
            with self.assertRaises(sources.SourceError):
                sources.safe_read(original)
            link.unlink()
            with self.assertRaises(sources.SourceError):
                sources.safe_read(original, 2)

    def test_nonempty_production_never_trusts_checksum(self):
        raw = b'{}'
        selection = self.selection()
        selection['sources'] = [{"role": "keys", "file": "keys.json", "digest": sources.digest(raw), "size": len(raw), "required": True}]
        with tempfile.TemporaryDirectory() as root:
            Path(root, 'keys.json').write_bytes(raw)
            with self.assertRaisesRegex(sources.SourceError, 'source-not-approved'):
                sources.collect(selection, root)

    def test_missing_required_and_substitution_fail(self):
        raw = b'{}'
        selection = self.selection()
        selection['sources'] = [{"role": "keys", "file": "keys.json", "digest": sources.digest(raw), "size": len(raw), "required": True}]
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaises(sources.SourceError):
                sources.collect(selection, root)
            Path(root, 'keys.json').write_bytes(b'[]')
            with self.assertRaisesRegex(sources.SourceError, 'source-byte-mismatch'):
                sources.collect(selection, root)

    def test_unknown_selection_fields_and_traversal_fail(self):
        selection = self.selection()
        selection['verified'] = True
        with self.assertRaises(sources.SourceError):
            sources.validate_selection(selection)
        selection = self.selection()
        selection['sources'] = [{"role": "keys", "file": "../keys.json", "digest": 'sha256:'+'a'*64, "size": 1, "required": True}]
        with self.assertRaises(sources.SourceError):
            sources.validate_selection(selection)

    def test_historical_drill_preserves_partial_and_old_identity(self):
        record = drill.plan()
        record['checkoutIdentity']['commit'] = 'a' * 40
        record['checkoutIdentity']['committedTree'] = 'b' * 40
        record['status'] = 'executed'
        record['cleanup'] = 'owned-synthetic-state-removed'
        record['observedCases'] = list(drill.CASES)
        record = drill._seal(record)
        view = sources.project_drill(sources.canonical(record), {'mode': 'demo'})['view']
        self.assertEqual('verified-local-integrity', view['verification'])
        self.assertEqual('not-established', view['provenance'])
        self.assertEqual('partial', view['fields']['implementationCoverage'])
        self.assertEqual('not-performed', view['publication'])
        self.assertEqual('pending', view['fields']['independentSecurityReview'])
        record['publication'] = 'published'
        record = drill._seal({k:v for k,v in record.items() if k != 'localIntegrityDigest'})
        with self.assertRaises(sources.SourceError):
            sources.project_drill(sources.canonical(record), {'mode': 'demo'})

    def test_private_field_in_drill_fails(self):
        record = drill._seal(drill.plan())
        record['privateRecordDigest'] = 'sha256:' + 'c'*64
        with self.assertRaises(sources.SourceError) as caught:
            sources.project_drill(sources.canonical(record), {'mode': 'demo'})
        self.assertNotIn('cccc', str(caught.exception))

    def test_policy_and_inventory_tampering_fail(self):
        with tempfile.TemporaryDirectory() as root:
            package = sources.collect(self.selection(), root)
        package['members'].append({'file':'secret.json','bytes':'e30='})
        with self.assertRaises(sources.SourceError):
            sources.admit(package)
        package['members'] = []
        package['policyDigest'] = 'sha256:' + 'a'*64
        with self.assertRaises(sources.SourceError):
            sources.admit(package)


if __name__ == '__main__':
    unittest.main()
