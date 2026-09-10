"""Source-owned projection after existing private authority verification.

Call only inside the existing source producer with its complete, authenticated private authority
context. These functions do not authenticate saved API JSON or replace producer attestation. They
rerun the original semantic verifier; the exported statement deliberately omits private authority
bytes, identifiers and digests. A public consumer still needs its reviewed exact source selection
and must report original producer proof unavailable unless supplied through its original authority.
Publication, activation and artifact-selected code never occur here. The operator entrypoint
permits bounded DNS validation only when its explicit ``allow_network`` argument is selected.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from .engines.stable_1_0_ga_core import SelectedRc, publication_receipt_errors
from .engines.stable_1_0_maintenance_core import Candidate, LoadedJson
from .engines.stable_1_0_maintenance import _receipt_errors
from .engines.stable_1_0_vulnerability import _verify_disclosure_publication
from .models import RunContext
from .redaction import scan_value


class PublicProjectionError(ValueError):
    """A fixed denial reason which cannot contain private source material."""


@dataclass(frozen=True)
class GaPublicationContext:
    """Private arguments already authenticated by the original GA producer."""
    receipt: dict[str, Any]
    selected: SelectedRc
    lineage: dict[str, Any]
    promotion_identity_digest: str
    release_notes_digest: str
    planned_assets: list[dict[str, Any]]


@dataclass(frozen=True)
class MaintenancePublicationContext:
    """Private exact candidate/plan/receipt arguments from maintenance verification."""
    loaded: LoadedJson
    candidate: Candidate
    plan_path: Path
    plan: dict[str, Any]
    core_receipt: dict[str, Any]
    core_receipt_digest: str
    successor_digest: str
    history_digest: str


AUTHORITY = {"release": "stable-ga.publication_receipt_errors",
             "maintenance": "stable-maintenance.publication-receipt-errors",
             "advisories": "stable-vulnerability.verify-disclosure-publication"}
BASE_FIELDS = {"schemaVersion", "kind", "role", "sourceAuthority", "sourceVerification",
               "sourcePublication", "originalProducerProof", "activation", "observedAt", "fields", "projectionDigest", "evidenceClass"}
RELEASE_FIELDS = {"releaseId", "buildVersion", "sourceCommit", "productDigest", "publishedAt", "assets"}
ADVISORY_FIELDS = {"advisoryId", "edition", "status", "severity", "title", "summary", "affected", "fixed",
                   "mitigation", "guidance", "references", "publishedAt", "updatedAt", "supersedes", "supersededBy"}
PUBLIC_ASSET_ROLES = {"product", "package", "stable-catalog", "stable-catalog-signature", "release-notes",
                      "known-limitations", "checksums", "provenance", "core-info"}
SCOPE_TYPES = {"core-build", "package-key", "runtime-component", "wire-or-persistent-format",
               "platform-api-endpoint-or-capability", "first-party-app-version", "third-party-app-version",
               "catalog-id-and-edition", "content-format-profile", "reviewer-key", "app-signing-key",
               "catalog-signing-key", "update-signing-key", "support-bundle-or-redaction-path",
               "operator-or-web-shell-surface", "sandbox-or-apphost-boundary"}
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
LIMIT = 262144


def _deny(reason="public-projection-authority-denied"):
    raise PublicProjectionError(reason)


def _canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _deny("public-projection-duplicate-member")
        result[key] = value
    return result


def _text(value, maximum=1024):
    return isinstance(value, str) and len(value) <= maximum and not any(ord(c) < 32 for c in value)


def _timestamp(value, *, nullable=False):
    if nullable and value is None:
        return True
    if not _text(value, 40):
        return False
    from .engines.stable_1_0_ga_core import parse_timestamp
    return parse_timestamp(value) is not None


def _uri(value):
    from .transparency_sources import safe_link
    try:
        return isinstance(value, str) and safe_link(value) == value
    except ValueError:
        return False


def validate_public_projection(raw: bytes) -> dict[str, Any]:
    """Validate a closed *derived* public statement, never its original private authority."""
    if not isinstance(raw, bytes) or not 0 < len(raw) <= LIMIT:
        _deny("public-projection-size-invalid")
    try:
        value = json.loads(raw, object_pairs_hook=_unique,
                           parse_constant=lambda _: _deny("public-projection-nonfinite"))
        if (type(value) is not dict or set(value) != BASE_FIELDS or type(value['schemaVersion']) is not int
                or value['schemaVersion'] != 1 or value['kind'] != 'public-ecosystem-source-projection'
                or value['role'] not in AUTHORITY or value['sourceAuthority'] != AUTHORITY[value['role']]
                or value['sourceVerification'] != 'scoped-original-verifier-passed'
                or value['sourcePublication'] != 'publication-complete'
                or value['evidenceClass'] not in {'source-owned-statement','synthetic-rehearsal'}
                or value['originalProducerProof'] != 'not-exported-private-context'
                or value['activation'] != 'not-established' or not _timestamp(value['observedAt'])):
            _deny("public-projection-contract-invalid")
        if value['projectionDigest'] != _digest(_canonical({k:v for k,v in value.items() if k!='projectionDigest'})):
            _deny("public-projection-digest-invalid")
        fields=value['fields']
        if type(fields) is not dict:
            _deny("public-projection-fields-invalid")
        if value['role'] in {'release','maintenance'}:
            if (set(fields)!=RELEASE_FIELDS or not _text(fields['releaseId'],128)
                    or re.fullmatch(r'[1-9][0-9]{0,9}',fields['buildVersion']) is None
                    or re.fullmatch(r'[0-9a-f]{40}',fields['sourceCommit']) is None
                    or DIGEST.fullmatch(fields['productDigest']) is None
                    or not _timestamp(fields['publishedAt'])):
                _deny("public-projection-release-invalid")
            assets=fields['assets']
            if type(assets) is not list or not 1<=len(assets)<=128:
                _deny("public-projection-assets-invalid")
            seen=set()
            for asset in assets:
                if (type(asset) is not dict or set(asset)!={'role','digest','size','uri'}
                        or asset['role'] not in PUBLIC_ASSET_ROLES or DIGEST.fullmatch(asset['digest']) is None
                        or type(asset['size']) is not int or not 1<=asset['size']<=2**53-1
                        or not _uri(asset['uri']) or asset['uri'] in seen):
                    _deny("public-projection-assets-invalid")
                seen.add(asset['uri'])
        else:
            if (set(fields)!=ADVISORY_FIELDS or re.fullmatch(r'csa-[a-z0-9]{16,64}',fields['advisoryId']) is None
                    or type(fields['edition']) is not int or not 1<=fields['edition']<=2147483647
                    or fields['status'] not in {'published','updated','withdrawn','superseded'}
                    or fields['severity'] not in {'critical','high','moderate','low'}):
                _deny("public-projection-advisory-invalid")
            for name in ('title','summary','mitigation','guidance'):
                if not _text(fields[name],4096):
                    _deny("public-projection-text-invalid")
            for name in ('affected','fixed'):
                if type(fields[name]) is not list or len(fields[name])>256:
                    _deny("public-projection-scope-invalid")
                for row in fields[name]:
                    if (type(row) is not dict or set(row)!={'type','identity','status'}
                            or row['type'] not in SCOPE_TYPES or not _text(row['identity'],256)
                            or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:@-]{0,255}',row['identity']) is None
                            or row['status'] not in {'suspected','affected','unaffected','fixed','mitigated','revoked'}):
                        _deny("public-projection-scope-invalid")
            if (type(fields['references']) is not list or len(fields['references'])>96
                    or any(not _uri(uri) for uri in fields['references'])
                    or not _timestamp(fields['publishedAt'],nullable=True) or not _timestamp(fields['updatedAt'])):
                _deny("public-projection-advisory-reference-invalid")
            for name in ('supersedes','supersededBy'):
                if fields[name] is not None and re.fullmatch(r'csa-[a-z0-9]{16,64}',fields[name]) is None:
                    _deny("public-projection-correction-invalid")
        if scan_value(value):
            _deny("public-projection-disclosure-denied")
        return value
    except (ValueError, TypeError, KeyError, RecursionError, UnicodeError):
        _deny("public-projection-invalid")


def _ga_fields(receipt, selected):
    from .engines.stable_1_0_ga_core import CHECKSUMS_FILE, PROVENANCE_FILE, RELEASE_NOTES_FILE, KNOWN_LIMITATIONS_FILE
    known={CHECKSUMS_FILE:'checksums',PROVENANCE_FILE:'provenance',
           RELEASE_NOTES_FILE:'release-notes',KNOWN_LIMITATIONS_FILE:'known-limitations'}
    catalog=getattr(selected,'freeze',{}).get('stableCatalog',receipt.get('catalog',{}))
    subjects={selected.product_digest:'product'}
    for key,role in (('catalogDigest','stable-catalog'),('signatureDigest','stable-catalog-signature')):
        if isinstance(catalog.get(key),str):
            subjects[catalog[key]]=role
    assets=[]
    for row in receipt['assets']:
        role=subjects.get(row['digest'],known.get(row['name']))
        if role is not None:
            assets.append({'role':role,'digest':row['digest'],'size':row['sizeBytes'],'uri':row['publicUri']})
    return {'releaseId':receipt['releaseId'],'buildVersion':str(receipt['buildVersion']),
            'sourceCommit':receipt['sourceCommit'],'productDigest':receipt['productDistributionDigest'],
            'publishedAt':receipt['publishedAt'],'assets':assets}


def _maintenance_fields(receipt):
    assets=[{'role':row['role'],'digest':row['digest'],'size':row['sizeBytes'],'uri':row['publicUri']}
            for row in receipt['assets'] if row['role'] in PUBLIC_ASSET_ROLES]
    return {'releaseId':receipt['releaseId'],'buildVersion':str(receipt['buildVersion']),
            'sourceCommit':receipt['sourceCommit'],'productDigest':receipt['productDigest'],
            'publishedAt':receipt['generatedAt'],'assets':assets}


def _advisory_fields(advisory):
    return {'advisoryId':advisory['advisoryId'],'edition':advisory['edition'],
            'status':'published' if advisory['status']=='authorized' else advisory['status'],
            'severity':advisory['severity'],'title':advisory['publicTitle'],'summary':advisory['publicSummary'],
            'affected':[{k:r[k] for k in ('type','identity','status')} for r in advisory['affectedScope']],
            'fixed':[{k:r[k] for k in ('type','identity','status')} for r in advisory['fixedOrMitigatedScope']],
            'mitigation':advisory['mitigation'],'guidance':advisory['upgradeOrUninstallGuidance'],
            'references':sorted(set(advisory['releaseReferences']+advisory['catalogReferences']+advisory['lifecycleReferences'])),
            'publishedAt':advisory['publishedAt'],'updatedAt':advisory['updatedAt'],
            'supersedes':advisory['supersedes'],'supersededBy':advisory['supersededBy']}


def _envelope(role, fields, observed):
    value={'schemaVersion':1,'kind':'public-ecosystem-source-projection','role':role,
           'evidenceClass':'source-owned-statement',
           'sourceAuthority':AUTHORITY[role],'sourceVerification':'scoped-original-verifier-passed',
           'sourcePublication':'publication-complete','originalProducerProof':'not-exported-private-context',
           'activation':'not-established','observedAt':observed,'fields':fields}
    value['projectionDigest']=_digest(_canonical(value))
    raw=_canonical(value)
    validate_public_projection(raw)
    return raw


def export_verified(role: str, context: RunContext, *, inputs=None) -> bytes:
    """Rerun the fixed original scoped verifier, then emit only an allowlisted public envelope.

    ``context`` and typed inputs belong to the original private producer; they are not accepted
    from a public source package. GA needs authenticated SelectedRc and lineage/promotion/asset
    bindings. Maintenance needs its authenticated candidate, plan, core receipt and successor
    identities. Advisory needs the complete original private disclosure context. Missing inputs
    fail closed. Producer authentication remains deliberately unexported, so this new statement
    must be separately authenticated/selected; its digest cannot authenticate its creator.
    """
    try:
        if not isinstance(context, RunContext):
            _deny()
        if role=='release' and isinstance(inputs,GaPublicationContext):
            if publication_receipt_errors(inputs.receipt,context,inputs.selected,inputs.lineage,
                    inputs.promotion_identity_digest,inputs.release_notes_digest,inputs.planned_assets):
                _deny()
            fields=_ga_fields(inputs.receipt,inputs.selected)
            observed=inputs.receipt['generatedAt']
        elif role=='maintenance' and isinstance(inputs,MaintenancePublicationContext):
            if _receipt_errors(context,inputs.loaded,inputs.candidate,inputs.plan_path,inputs.plan,
                    inputs.core_receipt,inputs.core_receipt_digest,inputs.successor_digest,inputs.history_digest):
                _deny()
            fields=_maintenance_fields(inputs.loaded.value)
            observed=inputs.loaded.value['generatedAt']
        elif role=='advisories' and inputs is None:
            _policy,_previous,_case,_ledger,documents,_receipt,observation=_verify_disclosure_publication(context)
            advisory=next(value for _name,value,_schema in documents if value.get('kind')=='stable-1.0-vulnerability-advisory')
            fields=_advisory_fields(advisory)
            observed=observation['observedAt']
        else:
            _deny("public-projection-private-context-required")
        return _envelope(role,fields,observed)
    except Exception:
        # Existing private authorities have useful private diagnostics. Never forward them here.
        _deny("public-projection-authority-denied")


def export_from_manifest(role: str, manifest_path: Path, private_root: Path, *, allow_network: bool = False) -> bytes:
    """Operator entrypoint using complete original authority manifest, with private scratch.

    All imported engines are fixed local code. GA/maintenance execute only validate-only, which
    verifies local authenticated authority inputs and writes private reports without publication.
    Advisory uses the original verify-disclosure-publication function and its existing protected
    input environment. Missing originals, expired authority or unsupported historical replay fail
    closed; this function does not change clocks or generate substitute provenance. Without an
    explicit network operation, hostname resolution is denied. With ``allow_network=True``, the
    original address validator receives only actual DNS results under finite query/time bounds;
    source collection, HTTP observation and publication are not added to these engine modes.
    """
    from .manifest import load_manifest
    from .engines import stable_1_0_ga, stable_1_0_maintenance
    from types import SimpleNamespace
    import contextlib
    import os
    import socket
    import queue
    import threading
    import time
    from unittest.mock import patch
    try:
        if role not in AUTHORITY or type(allow_network) is not bool:
            _deny()
        private_root=Path(private_root).absolute()
        manifest_path=Path(manifest_path).absolute()
        if (private_root.exists() or private_root.is_symlink() or not private_root.parent.is_dir()
                or any(p.is_symlink() for p in private_root.parents)
                or manifest_path.is_symlink() or any(p.is_symlink() for p in manifest_path.parents)
                or not manifest_path.is_file() or manifest_path.stat().st_nlink!=1
                or manifest_path.stat().st_size>LIMIT):
            _deny("public-projection-private-boundary-invalid")
        # Check duplicate keys and nonfinite values before handing the same bytes to the source
        # authority's own complete manifest parser.
        json.loads(manifest_path.read_bytes(),object_pairs_hook=_unique,
                   parse_constant=lambda _: _deny("public-projection-nonfinite"))
        workspace=Path(__file__).resolve().parents[3]
        manifest=load_manifest(manifest_path,workspace,private_root)
        component={'release':'stable-ga','maintenance':'stable-maintenance','advisories':'stable-vulnerability'}[role]
        expected_mode='verify-disclosure-publication' if role=='advisories' else 'validate-only'
        if manifest.commands.get(component,{}).get('mode',expected_mode)!=expected_mode:
            _deny("public-projection-read-only-mode-required")
        private_root.mkdir(mode=0o700)
        context=RunContext(workspace,private_root,component,manifest)
        if role=='advisories':
            with open(os.devnull,'w',encoding='utf-8') as sink, contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
                return export_verified(role,context)
        engine=stable_1_0_ga if role=='release' else stable_1_0_maintenance
        # Original validators may report useful private details. They remain in private reports;
        # incidental terminal diagnostics cannot cross this narrow public-facing entrypoint.
        resolver=socket.getaddrinfo
        started=time.monotonic()
        queries=0
        def bounded_dns(*args,**kwargs):
            nonlocal queries
            remaining=15-(time.monotonic()-started)
            if not allow_network or queries>=64 or remaining<=0:
                raise socket.gaierror('projection-dns-boundary')
            queries+=1
            responses=queue.Queue(maxsize=1)
            def resolve():
                try:
                    responses.put((True,resolver(*args,**kwargs)))
                except Exception:
                    responses.put((False,None))
            threading.Thread(target=resolve,daemon=True).start()
            try:
                success,rows=responses.get(timeout=min(5,remaining))
            except queue.Empty:
                raise socket.gaierror('projection-dns-unavailable') from None
            if not success or not isinstance(rows,list) or len(rows)>64:
                raise socket.gaierror('projection-dns-unavailable')
            return rows
        # Preserve the original public-address checks; never substitute successful fake DNS.
        with open(os.devnull,'w',encoding='utf-8') as sink, contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink), patch.object(socket,'getaddrinfo',side_effect=bounded_dns):
            code,_summary,_report=engine.run(context)
        if code!=0:
            _deny()
        path=context.component_dir/'artifacts'/'legacy'/engine.PUBLICATION_RECEIPT_FILE
        if not path.is_file() or path.is_symlink() or path.stat().st_nlink!=1 or path.stat().st_size>LIMIT:
            _deny()
        receipt=json.loads(path.read_bytes(),object_pairs_hook=_unique,
                           parse_constant=lambda _: _deny("public-projection-nonfinite"))
        if receipt.get('publicationState')!='publication-complete':
            _deny()
        fields=(_ga_fields(receipt,SimpleNamespace(product_digest=receipt['productDistributionDigest']))
                if role=='release' else _maintenance_fields(receipt))
        return _envelope(role,fields,receipt['generatedAt'])
    except Exception:
        _deny("public-projection-authority-denied")


def demo_public_projections() -> list[dict[str, Any]]:
    """Execute fixed repository authority fixtures and return only safe derived statements.

    This function is exclusively a demo/test factory. These records never establish original
    producer provenance, publication or live operation; production admission rejects demo data.
    The existing full disclosure fixture owns and removes all of its private temporary contexts.
    """
    import tempfile
    from unittest.mock import patch
    from .tests import test_stable_ga as ga_fixture
    from .tests import test_stable_maintenance as maintenance_fixture
    from .tests import test_stable_vulnerability as advisory_fixture
    from .engines import stable_1_0_vulnerability as vulnerability
    selected=ga_fixture._selected_rc()
    assets=ga_fixture._planned_assets()
    assets[0]['digest']=selected.product_digest
    inputs=GaPublicationContext(ga_fixture._receipt(selected,ga_fixture._digest('c'),ga_fixture._digest('d'),assets),
                               selected,ga_fixture._lineage(selected),ga_fixture._digest('c'),ga_fixture._digest('d'),assets)
    result=[{'role':'release','raw':export_verified('release',ga_fixture._context(),inputs=inputs)}]
    with tempfile.TemporaryDirectory(prefix='synthetic-public-projection-') as directory:
        args,_receipt=maintenance_fixture.StableMaintenanceAuthorizationAndPublicationTest()._publication_fixture(Path(directory),'created')
        context,*rest=args
        result.append({'role':'maintenance','raw':export_verified('maintenance',context,inputs=MaintenancePublicationContext(*rest))})
    original=vulnerability._verify_disclosure_publication
    def capture(context):
        validated=original(context)
        result.append({'role':'advisories','raw':export_verified('advisories',context)})
        return validated
    with patch.object(vulnerability,'_verify_disclosure_publication',side_effect=capture):
        advisory_fixture.StableVulnerabilityFullLifecycleTest().test_exact_byte_security_hotfix_disclosure_and_closure_chain()
    downgraded=[]
    for source in result:
        value=validate_public_projection(source['raw'])
        value['evidenceClass']='synthetic-rehearsal'
        value['projectionDigest']=_digest(_canonical({k:v for k,v in value.items() if k!='projectionDigest'}))
        raw=_canonical(value)
        validate_public_projection(raw)
        downgraded.append({'role':source['role'],'raw':raw})
    return downgraded
