"""Executable typed projection and original signature boundaries."""
import base64
import copy
import json
from pathlib import Path
import unittest

from cryptad_certification import transparency_adapters as adapter
from cryptad_certification.engines import stable_1_0_catalog_authority as authority
from cryptad_certification.tests.test_stable_catalog_authority import _manifest, _fixture_keypair, _fixture_sign


class TransparencyAdaptersTest(unittest.TestCase):
    def test_real_schema_demo_sources_project_without_production_claims(self):
        for source in adapter.demo_sources():
            with self.subTest(role=source['role']):
                row = adapter.project(source['role'], source['raw'], {'mode': 'demo'})['view']
                self.assertEqual(row['evidenceClass'], 'synthetic-preview')
                self.assertEqual(row['publication'], 'not-established')
                self.assertEqual(row['activation'], 'not-established')

    def test_downloads_retain_exact_source_bytes_separate_from_view(self):
        for source in adapter.demo_sources():
            projected=adapter.project(source['role'],source['raw'],{'mode':'demo'})
            self.assertIn(source['raw'],projected['downloads'].values())
            self.assertEqual(projected['view']['fields']['originalPublicBytesDigest'],adapter._digest(source['raw']))
            self.assertNotIn('signature',projected['view'])

    def test_identity_and_semantic_lineage_are_separate_from_exact_byte_digest(self):
        source=adapter.demo_sources()[0]
        value=json.loads(source['raw'])
        projected=adapter.project('lifecycle',source['raw'],{'mode':'demo'})['view']
        self.assertEqual(projected['identity'],'demo-support-lifecycle-edition-1')
        self.assertEqual(projected['fields']['descriptorDigest'],value['descriptorDigest'])
        self.assertNotEqual(projected['fields']['descriptorDigest'],projected['fields']['originalPublicBytesDigest'])

    def test_json_duplicate_unknown_and_nonfinite_fail(self):
        source = adapter.demo_sources()[0]
        raw = source['raw']
        for mutated in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}', raw[:-1]+b',"privateContactHash":"canary"}'):
            with self.subTest(raw=mutated[:10]):
                with self.assertRaises(adapter.ProjectionError) as error:
                    adapter.project('lifecycle', mutated, {'mode': 'demo'})
                self.assertNotIn('canary', str(error.exception))

    def test_wrong_role_schema_and_semantic_digest_fail(self):
        source = adapter.demo_sources()[0]
        with self.assertRaises(adapter.ProjectionError):
            adapter.project('keys', source['raw'], {'mode': 'demo'})
        value = json.loads(source['raw'])
        value['descriptorEdition'] += 1
        with self.assertRaises(adapter.ProjectionError):
            adapter.project('lifecycle', adapter._canonical(value), {'mode': 'demo'})

    def test_lifecycle_old_freshness_survives_generation(self):
        source = adapter.demo_sources()[0]
        view = adapter.project('lifecycle',source['raw'],{'mode':'demo'})['view']
        self.assertEqual(view['staleAt'], '2026-07-28T00:00:00Z')

    def test_revoked_tip_can_have_no_current_or_recommendation(self):
        value = json.loads(adapter.demo_sources()[0]['raw'])
        value['currentStableBuild'] = value['recommendedBuild'] = None
        value['entries'][0]['lifecycleStatus'] = 'revoked'
        value['entries'][0]['securityRevocationEffectiveAt'] = value['effectiveAt']
        value['descriptorDigest'] = adapter._digest(adapter._canonical({k:v for k,v in value.items() if k != 'descriptorDigest'}))
        view = adapter.project('lifecycle',adapter._canonical(value),{'mode':'demo'})['view']
        self.assertIsNone(view['fields']['currentStableBuild'])
        self.assertEqual(view['fields']['entries'][0]['lifecycleStatus'],'revoked')

    def test_false_reproducibility_pass_rejected(self):
        value=json.loads(adapter.demo_sources()[1]['raw'])
        value['comparisons'][0]['verifierDigest']='sha256:'+'2'*64
        value['resultDigest']=adapter._digest(adapter._canonical({k:v for k,v in value.items() if k!='resultDigest'}))
        with self.assertRaises(adapter.ProjectionError):
            adapter.project('reproducibility',adapter._canonical(value),{'mode':'demo'})

    def test_real_key_transparency_artifact_projects_roles(self):
        manifest=_manifest()
        value=authority._transparency_artifact(manifest)
        view=adapter.project('keys',adapter._canonical(value),{'mode':'demo'})['view']
        self.assertEqual({k['role'] for k in view['fields']['keys']},{'catalog-signing','first-party-app-signing','app-reviewer','offline-recovery'})

    def test_key_role_alias_and_lineage_splice_rejected(self):
        original=authority._transparency_artifact(_manifest())
        for mutation in ('alias','splice','disclosure'):
            value=copy.deepcopy(original)
            if mutation=='alias':
                for field in ('publicKeySpkiBase64','publicKeyFingerprintSha256'):
                    value['keys'][1][field]=value['keys'][0][field]
            elif mutation=='splice':
                value['keys'][0]['predecessorKeyId']='missing-key'
            else:
                value['keys'][0]['publicTransparencyEligible']=False
            value['selfDigest']=authority._semantic_digest(value,'selfDigest')
            with self.assertRaises(adapter.ProjectionError):
                adapter.project('keys',adapter._canonical(value),{'mode':'demo'})

    def test_fixture_custody_rejected_from_production_even_with_signature(self):
        value=authority._transparency_artifact(_manifest())
        with self.assertRaises(adapter.ProjectionError):
            adapter.project('keys',adapter._canonical(value),{'mode':'production'})

    def test_key_transparency_validates_selected_recovery_signature(self):
        manifest=_manifest()
        value=authority._transparency_artifact(manifest)
        root=next(k for k in manifest['keyset']['keys'] if k['role']=='offline-recovery')
        context={'trustedRecovery':root,'signatureBase64':manifest['transparency']['signatureBase64']}
        self.assertEqual(adapter._signature_verification('keys',b'',value,context),'valid-signature-selected-root-snapshot-only')
        value['keysetVersion'] += 1
        with self.assertRaises(adapter.ProjectionError):
            adapter._signature_verification('keys',b'',value,context)

    def test_missing_signature_proof_is_not_bad_signature(self):
        source=adapter.demo_sources()[0]
        row=adapter.project('lifecycle',source['raw'],{'mode':'production'})['view']
        self.assertEqual(row['verification'],'original-signature-proof-unavailable')
        self.assertEqual(row['publication'],'not-established')

    def test_review_signed_scope_key_and_tampering(self):
        manifest=_manifest()
        key=next(k for k in manifest['keyset']['keys'] if k['role']=='app-reviewer')
        seed,public=_fixture_keypair(key['keyId'])
        value={'review.receipt.version':'2','review.receipt.app.id':'synthetic-app','review.receipt.app.version':'1.0.0',
               'review.receipt.artifact.sha256':'1'*64,'review.receipt.artifact.size':'1',
               'review.receipt.bundle.key.id':'synthetic-signer','review.receipt.policy.id':'synthetic-policy',
               'review.receipt.policy.version':'1','review.receipt.status':'caution',
               'review.receipt.reviewer.key.id':key['keyId'],'review.receipt.reviewed.at':'2026-08-21T00:00:00Z',
               'review.receipt.expires.at':'2026-08-22T00:00:00Z',
               'review.receipt.signature.algorithm':'Ed25519'}
        payload=b''.join(f'{field}={value[field]}\n'.encode() for field in authority._RECEIPT_FIELDS[:-2] if field in value)
        value['review.receipt.signature.value.base64']=base64.b64encode(_fixture_sign(seed,public,payload)).decode()
        approved={'trustedReviewer':key,'reviewScope':{'appId':'synthetic-app','version':'1.0.0','digest':'1'*64,'size':1,'bundleKeyId':'synthetic-signer','policyId':'synthetic-policy','policyVersion':'1'}}
        self.assertEqual(adapter._signature_verification('reviews',b'',value,approved),'valid-signature-selected-root-snapshot-only')
        raw = b''.join(f'{field}={value[field]}\n'.encode() for field in authority._RECEIPT_FIELDS if field in value)
        row = adapter.project('reviews', raw, {'mode': 'production', 'approvedSource': approved})['view']
        self.assertEqual(row['staleAt'], '2026-08-22T00:00:00Z')
        self.assertEqual(row['verification'], 'valid-signature-selected-root-snapshot-only')
        for field,new in [('review.receipt.status','reviewed'),('review.receipt.app.version','2.0.0'),('review.receipt.reviewer.key.id','wrong')]:
            changed=dict(value);changed[field]=new
            with self.assertRaises(adapter.ProjectionError):
                adapter._signature_verification('reviews',b'',changed,approved)

    def test_catalog_duplicate_and_unknown_fields_fail(self):
        source=adapter.demo_sources()[2]
        for suffix in (b'catalog.id=other\n',b'private.backup.sha256=canary\n'):
            with self.assertRaises(adapter.ProjectionError):
                adapter.project('catalogs',source['raw']+suffix,{'mode':'demo'})

    def test_catalog_signature_exact_payload_and_role(self):
        raw=adapter.demo_sources()[2]['raw'].replace(b'2026-07-21',b'2026-08-21')
        key=next(k for k in _manifest()['keyset']['keys'] if k['role']=='catalog-signing')
        seed, public=_fixture_keypair(key['keyId'])
        signed=base64.b64encode(_fixture_sign(seed,public,raw)).decode()
        sidecar=('catalog.signature.version=1\ncatalog.signature.algorithm=Ed25519\n'
                 'catalog.signature.key.id='+key['keyId']+'\ncatalog.signature.payload=cryptad-app-catalog.properties\n'
                 'catalog.signature.value.base64='+signed+'\n')
        approved={'trustedCatalog':key,'signatureSidecar':sidecar}
        self.assertEqual(adapter._signature_verification('catalogs',raw,adapter._properties(raw),approved),'valid-signature-selected-root-snapshot-only')
        with self.assertRaises(adapter.ProjectionError):
            adapter._signature_verification('catalogs',raw+b'\n',adapter._properties(raw),approved)
        key['role']='app-reviewer'
        with self.assertRaises(adapter.ProjectionError):
            adapter._signature_verification('catalogs',raw,adapter._properties(raw),approved)

    def test_component_protected_classification_rejected_after_reseal(self):
        value=json.loads(next(s['raw'] for s in adapter.demo_sources() if s['role']=='supply-chain'))
        component=value['components'][0]
        component['classification']='protected'
        component['recordDigest']=adapter._digest(adapter._canonical({k:v for k,v in component.items() if k!='recordDigest'}))
        value['inventoryDigest']=adapter._digest(adapter._canonical({k:v for k,v in value.items() if k!='inventoryDigest'}))
        with self.assertRaises(adapter.ProjectionError):
            adapter.project('supply-chain',adapter._canonical(value),{'mode':'demo'})

    def test_no_product_reproduction_inferred_from_site(self):
        source=adapter.demo_sources()[1]
        row=adapter.project('reproducibility',source['raw'],{'mode':'production'})['view']
        self.assertIn('not established',row['fields']['independence'])
        self.assertEqual(row['activation'],'not-established')

    def test_all_unknown_roles_and_wrong_modes_rejected(self):
        for role, mode in [('private-incident','demo'),('lifecycle','fixture'),('lifecycle',True)]:
            with self.assertRaises(adapter.ProjectionError):
                adapter.project(role,b'{}',{'mode':mode})

    def test_source_size_and_properties_encoding_boundaries(self):
        for raw in (b'{}'*(adapter.MAX_BYTES//2+1),b'catalog.id=one\\u003dsecret\n',b'\xff'):
            with self.assertRaises(adapter.ProjectionError):
                adapter.project('catalogs',raw,{'mode':'demo'})

    def test_repository_statement_exact_reviewed_only(self):
        raw=(Path(__file__).resolve().parents[3]/'ecosystem-transparency/repository-status.json').read_bytes()
        row=adapter.project('repository-status',raw,{'mode':'production'})['view']
        self.assertEqual(row['evidenceClass'],'repository-reported')
        self.assertEqual(row['fields']['phase12'],'incomplete')
        self.assertEqual(len(row['fields']['obligations']),10)
        value=json.loads(raw);value['phase12']='complete'
        with self.assertRaises(adapter.ProjectionError):
            adapter.project('repository-status',adapter._canonical(value),{'mode':'production'})

if __name__ == '__main__':
    unittest.main()
