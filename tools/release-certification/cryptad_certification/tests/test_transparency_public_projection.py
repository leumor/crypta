"""Original scoped authorities execute before public projections; no fake success flag."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cryptad_certification import transparency_public_projection as public
from cryptad_certification.tests import test_stable_ga as ga_fixture
from cryptad_certification.tests import test_stable_maintenance as maintenance_fixture
from cryptad_certification.tests import test_stable_vulnerability as advisory_fixture
from cryptad_certification.engines import stable_1_0_vulnerability as vulnerability


class PublicProjectionTest(unittest.TestCase):
    def ga(self):
        selected=ga_fixture._selected_rc()
        assets=ga_fixture._planned_assets()
        assets[0]['digest']=selected.product_digest
        receipt=ga_fixture._receipt(selected,ga_fixture._digest('c'),ga_fixture._digest('d'),assets)
        inputs=public.GaPublicationContext(receipt,selected,ga_fixture._lineage(selected),ga_fixture._digest('c'),ga_fixture._digest('d'),assets)
        return ga_fixture._context(),inputs

    def test_actual_ga_verifier_projects_only_public_fields(self):
        context,inputs=self.ga()
        raw=public.export_verified('release',context,inputs=inputs)
        value=public.validate_public_projection(raw)
        self.assertEqual(value['fields']['buildVersion'],'284')
        self.assertEqual({a['role'] for a in value['fields']['assets']},{'product','checksums'})
        for private in ('freezeDigest','archiveDigest','gaPromotionSummaryDigest','workflow','attestationDigest','publicStateObservation'):
            self.assertNotIn(private,raw.decode())
        self.assertEqual(value['originalProducerProof'],'not-exported-private-context')
        self.assertEqual(value['activation'],'not-established')
        self.assertEqual(value['evidenceClass'],'source-owned-statement')

    def test_ga_substitution_and_fabricated_booleans_fail(self):
        for key,new in [('sourceCommit','f'*40),('publicationState','publication-verification-failed'),('productDistributionDigest','sha256:'+'0'*64),('public',True)]:
            context,inputs=self.ga();inputs.receipt[key]=new
            with self.assertRaises(public.PublicProjectionError):
                public.export_verified('release',context,inputs=inputs)
        with self.assertRaises(public.PublicProjectionError):
            public.export_verified('release',ga_fixture._context(),inputs={'verified':True})

    def test_actual_maintenance_verifier_and_conflict(self):
        with tempfile.TemporaryDirectory() as directory:
            args,receipt=maintenance_fixture.StableMaintenanceAuthorizationAndPublicationTest()._publication_fixture(Path(directory).resolve(),'created')
            context,*rest=args
            inputs=public.MaintenancePublicationContext(*rest)
            raw=public.export_verified('maintenance',context,inputs=inputs)
            value=public.validate_public_projection(raw)
            self.assertEqual(value['fields']['buildVersion'],'301')
            self.assertEqual(value['fields']['assets'][0]['role'],'product')
            for private in ('candidateIdentityDigest','authorizationDigest','backportReleaseTrainDigest','successorBaselineDigest','releaseHistoryDigest','latestPointerPublicUri'):
                self.assertNotIn(private,raw.decode())
            receipt['publicObservations']['coreUpdate']='conflict'
            with self.assertRaises(public.PublicProjectionError):
                public.export_verified('maintenance',context,inputs=inputs)

    def test_original_full_advisory_disclosure_chain_executes(self):
        captured=[]
        original=vulnerability._verify_disclosure_publication
        def observe_real_verification(context):
            # Both calls run the actual original verifier; this hook captures private context
            # while the existing end-to-end fixture owns its temporary lifecycle filesystem.
            result=original(context)
            raw=public.export_verified('advisories',context)
            manifest=context.manifest
            manifest.path.write_bytes(public._canonical({
                'schemaVersion':1,'release':{'id':manifest.release.release_id,'version':manifest.release.version,'profile':manifest.release.profile},
                'output':{'root':'unused','reset':False},'requirements':manifest.requirements,
                'inputs':manifest.inputs,'policies':manifest.policies,'execution':manifest.execution,'commands':manifest.commands}))
            operator_raw=public.export_from_manifest('advisories',manifest.path,manifest.path.parent/'transparency-private-export')
            self.assertEqual(operator_raw,raw)
            captured.append(raw)
            return result
        with patch.object(vulnerability,'_verify_disclosure_publication',side_effect=observe_real_verification):
            advisory_fixture.StableVulnerabilityFullLifecycleTest().test_exact_byte_security_hotfix_disclosure_and_closure_chain()
        self.assertGreaterEqual(len(captured),1)
        for raw in captured:
            value=public.validate_public_projection(raw)
            self.assertEqual(value['role'],'advisories')
            self.assertIn(value['fields']['status'],{'published','updated'})
            for private in ('caseOpaqueId','caseSnapshotDigest','privateRecordDigest','publicCaseDigest','reporterCredit','inventoryDigest','authorizationDigest'):
                self.assertNotIn(private,raw.decode())

    def test_projection_unknown_private_fields_duplicate_and_mutation_reject(self):
        context,inputs=self.ga()
        original=public.export_verified('release',context,inputs=inputs)
        for change in ('private','digest','duplicate','url'):
            value=json.loads(original)
            if change=='private': value['privateRecordDigest']='canary'
            elif change=='digest': value['fields']['productDigest']='sha256:'+'0'*64
            elif change=='url':
                value['fields']['assets'][0]['uri']='https://user:canary@example.org/download'
                value['projectionDigest']=public._digest(public._canonical({k:v for k,v in value.items() if k!='projectionDigest'}))
            raw=public._canonical(value)
            if change=='duplicate': raw=raw[:-1]+b',"role":"release"}'
            with self.assertRaises(public.PublicProjectionError) as failure:
                public.validate_public_projection(raw)
            self.assertNotIn('canary',str(failure.exception))

    def test_missing_advisory_context_fails_without_private_diagnostic(self):
        with self.assertRaises(public.PublicProjectionError) as failure:
            public.export_verified('advisories',ga_fixture._context())
        self.assertEqual(str(failure.exception),'public-projection-authority-denied')

    def test_operator_private_root_collision_and_manifest_errors_are_fixed(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve(); manifest=root/'manifest.json'; manifest.write_text('{"canary":"secret"}')
            for scratch in (root,root/'new-private'):
                with self.assertRaises(public.PublicProjectionError) as failure:
                    public.export_from_manifest('release',manifest,scratch)
                self.assertEqual(str(failure.exception),'public-projection-authority-denied')
            self.assertFalse((root/'new-private').exists())

    def test_operator_dns_requires_explicit_network_without_mocked_authority_success(self):
        import socket
        from cryptad_certification.engines import stable_1_0_ga
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve()
            context,_inputs=self.ga(); m=context.manifest
            manifest=root/'manifest.json'
            manifest.write_bytes(public._canonical({'schemaVersion':1,
                'release':{'id':m.release.release_id,'version':m.release.version,'profile':m.release.profile},
                'output':{'root':'unused','reset':False},'requirements':{},'inputs':{},'policies':m.policies,
                'execution':{},'commands':{'stable-ga':{'mode':'validate-only'}}}))
            def probe_then_fail(_context):
                socket.getaddrinfo('source.crypta.network',443)
                raise ValueError('private diagnostics must not escape')
            for online in (False,True):
                with patch.object(socket,'getaddrinfo',return_value=[(2,1,6,'',('93.184.216.34',443))]) as resolver, patch.object(stable_1_0_ga,'run',side_effect=probe_then_fail):
                    with self.assertRaises(public.PublicProjectionError) as failure:
                        public.export_from_manifest('release',manifest,root/str(online),allow_network=online)
                    self.assertEqual(resolver.call_count,1 if online else 0)
                    self.assertEqual(str(failure.exception),'public-projection-authority-denied')

    def test_demo_factory_downgrades_every_source_without_private_originals(self):
        sources=public.demo_public_projections()
        self.assertEqual({s['role'] for s in sources},{'release','maintenance','advisories'})
        for source in sources:
            value=public.validate_public_projection(source['raw'])
            self.assertEqual(value['evidenceClass'],'synthetic-rehearsal')
            self.assertEqual(value['originalProducerProof'],'not-exported-private-context')

if __name__=='__main__': unittest.main()
