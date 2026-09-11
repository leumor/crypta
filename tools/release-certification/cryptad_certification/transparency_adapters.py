"""Closed, source-shaped public projections; checksums never become release authority.

Original authority records are not generally safe downloads. This module projects fields only;
production admission is additionally confined by the reviewed source inventory in the caller.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from .schema_validation import validate_schema

MAX_BYTES = 1024 * 1024
SCHEMAS = {
    "release": "stable-1.0-ga-publication-receipt-v1.schema.json",
    "maintenance": "stable-1.0-maintenance-publication-receipt-v1.schema.json",
    "keys": "stable-1.0-public-key-transparency-v1.schema.json",
    "lifecycle": "stable-1.0-support-lifecycle-descriptor-v1.schema.json",
    "advisories": "stable-1.0-vulnerability-advisory-v1.schema.json",
    "supply-chain": "stable-1.0-component-inventory-v1.schema.json",
    "reproducibility": "stable-1.0-reproducibility-result-v1.schema.json",
    "sbom": "stable-1.0-sbom-binding-v1.schema.json",
}
# These internal records need source-owned authenticated projections before live admission.
PRIVATE_ORIGINALS = frozenset({"release", "maintenance", "advisories"})


class ProjectionError(ValueError):
    """Fixed public-safe diagnostic; never include supplied strings or exception text."""


def _fail(code="transparency-source-invalid"):
    raise ProjectionError(code)


def _canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            _fail("transparency-duplicate-member")
        value[key] = item
    return value


def _read(raw):
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_BYTES:
        _fail("transparency-source-limit")
    try:
        value = json.loads(raw, object_pairs_hook=_pairs,
                           parse_constant=lambda _: _fail("transparency-nonfinite"))
    except (ValueError, UnicodeError, RecursionError):
        _fail()
    if type(value) is not dict:
        _fail()
    return value


def _pick(value, names):
    return {name: value[name] for name in names.split() if name in value}


def _seal_check(value, field):
    if value.get(field) != _digest(_canonical({k: v for k, v in value.items() if k != field})):
        _fail("transparency-semantic-digest-invalid")


def _properties(raw):
    """Accept the canonical unescaped property subset used by selected public artifacts."""
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_BYTES:
        _fail("transparency-source-limit")
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeError:
        _fail()
    result = {}
    for line in lines:
        if not line:
            continue
        if line.startswith(("#", "!")):
            _fail("transparency-unapproved-property-comment")
        if "=" not in line or "\\" in line or any(ord(c) < 32 for c in line):
            _fail("transparency-properties-invalid")
        key, value = line.split("=", 1)
        if key in result or re.fullmatch(r"[A-Za-z0-9._-]{1,256}", key) is None:
            _fail("transparency-properties-invalid")
        result[key] = value
    return result


def _release(value):
    return _pick(value, "releaseId buildVersion sourceCommit productDistributionDigest productDigest publishedAt publicationState finalVerificationStatus")


def _keys(value):
    from .engines.stable_1_0_catalog_authority import _raw_public_key, _semantic_digest, _validate_lineage
    if value["selfDigest"] != _semantic_digest(value, "selfDigest"):
        _fail("transparency-semantic-digest-invalid")
    ids, fingerprints = set(), set()
    for key in value["keys"]:
        try:
            public = _raw_public_key(key)
        except (ValueError, KeyError):
            _fail("transparency-key-invalid")
        # Fingerprints cover X.509 SPKI, not the extracted raw 32-byte key.
        import base64
        fingerprint = _digest(base64.b64decode(key["publicKeySpkiBase64"], validate=True))
        if (not key["publicTransparencyEligible"] or len(public) != 32 or fingerprint != key["publicKeyFingerprintSha256"]
                or key["keyId"] in ids or fingerprint in fingerprints):
            _fail("transparency-key-role-conflict")
        ids.add(key["keyId"])
        fingerprints.add(fingerprint)
    if _validate_lineage(value["keys"]):
        _fail("transparency-key-lineage-invalid")
    fields = _pick(value, "keysetVersion keysetDigest previousKeysetDigest selfDigest effectiveAt ceremonyType")
    fields["keys"] = [_pick(k, "keyId role algorithm publicKeySpkiBase64 publicKeyFingerprintSha256 lifecycle validFrom validUntil predecessorKeyId successorKeyId compromiseState") for k in value["keys"]]
    fields["signingValidity"] = "Historical signing validity does not grant current signing authority."
    return fields


def _lifecycle(value):
    _seal_check(value, "descriptorDigest")
    rows = value["entries"]
    by_build = {row["buildVersion"]: row for row in rows}
    if len(by_build) != len(rows):
        _fail("transparency-lifecycle-conflict")
    for key in ("currentStableBuild", "recommendedBuild"):
        selected = value[key]
        if selected is not None and (selected not in by_build or by_build[selected]["lifecycleStatus"] == "revoked"):
            _fail("transparency-lifecycle-invalid-tip")
    fields = _pick(value, "stableMilestone descriptorEdition descriptorDigest previousDescriptorEdition previousDescriptorDigest effectiveAt staleAt currentStableBuild minimumSupportedBuild minimumSecuritySupportedBuild recommendedBuild")
    fields["entries"] = [_pick(row, "releaseId buildVersion sourceCommit productDigest publishedAt lifecycleStatus statusEffectiveAt fullSupportUntil securityFixesUntil deprecationEffectiveAt endOfSupportAt securityRevocationEffectiveAt replacementBuild recoveryGuidance advisoryIds reasonCodes") for row in rows]
    fields["authorityBoundary"] = "Support windows and nullable recommendations are preserved from the descriptor."
    return fields


def _advisories(value):
    if value["status"] in {"draft", "authorized"}:
        _fail("transparency-advisory-not-disclosed")
    _seal_check(value, "contentDigest")
    return _pick(value, "advisoryId edition previousAdvisoryDigest status severity publicTitle publicSummary affectedScope fixedOrMitigatedScope impactCategories mitigation upgradeOrUninstallGuidance releaseReferences catalogReferences lifecycleReferences externalIdentifiers publishedAt updatedAt supersedes supersededBy")


def _supply_chain(value):
    _seal_check(value, "inventoryDigest")
    fields = _pick(value, "releaseId buildVersion sourceCommit")
    for component in value["components"]:
        if component["classification"] != "public":
            _fail("transparency-component-not-disclosed")
        _seal_check(component, "recordDigest")
    fields["components"] = [_pick(c, "componentId componentKind name version namespace purl digest roles subjectKeys apps runtimeComponentIds dependencyVerificationStatus buildMaterialStatus") for c in value["components"]]
    return fields


def _reproducibility(value):
    _seal_check(value, "resultDigest")
    for row in value["comparisons"]:
        if row["status"] == "pass":
            pair = ((row["primaryDigest"], row["verifierDigest"]) if row["reproducibilityClass"] == "byte-identical"
                    else (row["primaryPayloadManifestDigest"], row["verifierPayloadManifestDigest"]))
            if pair[0] is None or pair[0] != pair[1] or row["differences"]:
                _fail("transparency-reproducibility-conflict")
    if value["status"] == "pass" and (value["unexplainedDifferences"] or any(r["status"] != "pass" for r in value["comparisons"])):
        _fail("transparency-reproducibility-conflict")
    fields = _pick(value, "releaseId buildVersion sourceCommit status unexplainedDifferences")
    fields["comparisons"] = [_pick(row, "subjectKey reproducibilityClass status primaryDigest verifierDigest primaryPayloadManifestDigest verifierPayloadManifestDigest") for row in value["comparisons"]]
    fields["independence"] = "Provider-distinct independent reproduction is not established by this result."
    fields["coverage"] = "Only listed compared product subjects; signatures and catalogs are not implicitly reproduced."
    return fields


def _sbom(value):
    _seal_check(value, "bindingDigest")
    return _pick(value, "releaseId buildVersion sourceCommit format documentNamespace sbomDigest componentInventoryDigest subjectInventoryDigest subjects")


def _review(value):
    from .engines.stable_1_0_catalog_authority import _RECEIPT_FIELDS, _REQUIRED_RECEIPT_FIELDS
    from .transparency_bundle import timestamp
    if not _REQUIRED_RECEIPT_FIELDS <= value.keys() or value.keys() - set(_RECEIPT_FIELDS):
        _fail("transparency-review-contract-invalid")
    if (value["review.receipt.version"] not in {"1", "2"}
            or value["review.receipt.status"] not in {"reviewed", "caution", "rejected"}
            or value["review.receipt.signature.algorithm"] != "Ed25519"
            or not re.fullmatch(r"[0-9a-f]{64}", value["review.receipt.artifact.sha256"])):
        _fail("transparency-review-contract-invalid")
    try:
        timestamp(value['review.receipt.reviewed.at'])
        if 'review.receipt.expires.at' in value:
            timestamp(value['review.receipt.expires.at'])
    except ValueError:
        _fail('transparency-review-timestamp-invalid')
    fields = _pick(value, "review.receipt.version review.receipt.app.id review.receipt.app.version review.receipt.artifact.sha256 review.receipt.artifact.size review.receipt.bundle.key.id review.receipt.policy.id review.receipt.policy.version review.receipt.status review.receipt.reviewer.key.id review.receipt.reviewed.at review.receipt.expires.at")
    fields["scope"] = "A scoped review statement is not a guarantee of app safety or local trust."
    return fields


def _catalog(value):
    required = {"catalog.version", "catalog.id", "catalog.name", "catalog.generatedAt", "catalog.entries"}
    if not required <= value.keys() or value["catalog.version"] not in {str(n) for n in range(1, 8)}:
        _fail("transparency-catalog-contract-invalid")
    ids = value["catalog.entries"].split(",")
    if len(ids) > 256 or len(set(ids)) != len(ids) or any(not re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,127}", i) for i in ids):
        _fail("transparency-catalog-contract-invalid")
    allowed_catalog = required | {"catalog.channel", "catalog.revision", "catalog.signature.key.id"}
    fields = _pick(value, "catalog.version catalog.id catalog.name catalog.generatedAt catalog.channel catalog.revision")
    fields["apps"] = []
    allowed = set(allowed_catalog)
    for app in ids:
        prefix = f"app.{app}."
        names = ("id name version summary homepage source license bundle.uri bundle.sha256 bundle.size.bytes bundle.type permissions categories "
                 "minimumCryptaVersion maximumCryptaVersion api.minimumVersion api.maximumTestedVersion api.optionalCapabilities api.targetStability api.targetBaseline api.experimentalCapabilitiesAccepted "
                 "channel support.status deprecation.status deprecation.message replacementAppId review.status review.note review.reviewer.keyId review.reviewer.policy "
                 "changelog.summary changelog.uri maintenance.owner maintenance.ownerUri maintenance.supportLevel maintenance.dataSchemaPolicy maintenance.migrationPolicy maintenance.backupRestore maintenance.securityPolicy maintenance.deprecationPolicy maintenance.supportUri").split()
        allowed.update(prefix + n for n in names)
        mandatory = {prefix+n for n in ("id", "version", "bundle.sha256", "bundle.size.bytes")}
        if not mandatory <= value.keys() or value[prefix+"id"] != app or not re.fullmatch(r"[0-9a-f]{64}",value[prefix+"bundle.sha256"]):
            _fail("transparency-catalog-subject-invalid")
        row = {n: value[prefix+n] for n in names if prefix+n in value}
        from .engines.stable_1_0_catalog_authority import _RECEIPT_FIELDS
        receipt = {f: value[prefix+f] for f in _RECEIPT_FIELDS if prefix+f in value}
        if receipt:
            row["reviewReceipt"] = _review(receipt)
            if (receipt["review.receipt.app.id"] != app
                    or receipt["review.receipt.app.version"] != row["version"]
                    or receipt["review.receipt.artifact.sha256"] != row["bundle.sha256"]
                    or receipt["review.receipt.artifact.size"] != row["bundle.size.bytes"]):
                _fail("transparency-review-scope-invalid")
            row["reviewSignature"] = "Separate reviewer signature proof required; catalog signature does not replace it."
            allowed.update(prefix+f for f in _RECEIPT_FIELDS)
        for permission in row.get("permissions", "").split(","):
            if permission:
                allowed.add(prefix+"permissions.rationale."+permission)
        allowed.update(prefix+"screenshot."+str(n) for n in range(1, 9))
        fields["apps"].append(row)
    if value.keys() - allowed:
        _fail("transparency-catalog-unsupported-field")
    fields["scope"] = "Catalog endorsement does not import local trust; no install action is provided."
    return fields


def _repository_status(value):
    if value.get("schemaVersion") != 1 or value.get("kind") != "public-ecosystem-repository-status":
        _fail("transparency-repository-statement-contract-invalid")
    allowed = set('schemaVersion kind asOf sourceCommit sourceTree sourceDocumentDigest phase12 closeoutOwner mail obligations'.split())
    mail_fields = set('apiContract apiUrlVersion restore stableBaselineContract stableMilestone status'.split())
    if (set(value) != allowed or not isinstance(value.get('mail'), dict)
            or set(value['mail']) != mail_fields or not isinstance(value.get('obligations'), list)
            or any(not isinstance(item, dict) or set(item) != {'id', 'description', 'status'}
                   for item in value['obligations'])):
        _fail('transparency-repository-statement-contract-invalid')
    return _pick(value, "asOf sourceCommit sourceTree sourceDocumentDigest phase12 closeoutOwner mail obligations")


def _phase_assessment(value):
    """Validate a reviewed public Phase 12 projection; it never supplies original authority."""
    from .phase_12_closeout import DIMENSIONS, PASS, policy
    from .transparency_sources import timestamp
    allowed = {"schemaVersion", "kind", "asOf", "classification", "originalProducerProof",
               "phaseDecision", "phaseComplete", "requirements", "publication", "activation"}
    if (type(value) is not dict or set(value) != allowed or type(value["schemaVersion"]) is not int
            or value["schemaVersion"] != 1 or value["kind"] != "phase-12-public-status"
            or value["classification"] != "repository-local-assessment"
            or value["originalProducerProof"] != "not-exported"
            or value["publication"] != "not-performed" or value["activation"] != "not-performed"
            or type(value["phaseDecision"]) is not str or value["phaseDecision"] not in {"incomplete", "blocked", "complete-as-of"}
            or type(value["phaseComplete"]) is not bool
            or value["phaseComplete"] != (value["phaseDecision"] == "complete-as-of")):
        _fail("transparency-phase-assessment-contract-invalid")
    timestamp(value["asOf"])
    rules, _ = policy()
    expected = {row["id"]: set(row["dimensions"]) for row in rules["requirements"]}
    rows = value["requirements"]
    if (type(rows) is not list or len(rows) != len(expected)
            or any(type(row) is not dict or set(row) != {"id", "dimensions", "decision"} for row in rows)
            or [row["id"] for row in rows] != sorted(expected)):
        _fail("transparency-phase-assessment-inventory-invalid")
    for row in rows:
        dimensions = row["dimensions"]
        if (type(dimensions) is not dict or set(dimensions) != expected[row["id"]]
                or any(type(v) is not str or v not in DIMENSIONS[k] for k, v in dimensions.items())
                or type(row["decision"]) is not str or row["decision"] not in {"satisfied", "unresolved"}
                or row["decision"] == "satisfied" and any(v != PASS[k] for k, v in dimensions.items())):
            _fail("transparency-phase-assessment-dimension-invalid")
    if value["phaseComplete"] and any(row["decision"] != "satisfied" for row in rows):
        _fail("transparency-phase-assessment-completion-invalid")
    return _pick(value, "asOf classification originalProducerProof phaseDecision phaseComplete requirements publication activation")


def _signature_verification(role, raw, value, approved):
    """Use explicitly selected public trust roots; never infer a root from subject keys."""
    from .engines.stable_1_0_catalog_authority import (
        _raw_public_key, _verify_ed25519, _decode_signature, _reviewer_eligible_at,
        _timestamp, _RECEIPT_FIELDS, _canonical_bytes,
    )
    root = approved.get({"reviews": "trustedReviewer", "catalogs": "trustedCatalog"}.get(role, "trustedRecovery"))
    if root is None:
        return "original-signature-proof-unavailable"
    try:
        if role == "reviews":
            if (root["keyId"] != value["review.receipt.reviewer.key.id"]
                    or not _reviewer_eligible_at(root, _timestamp(value["review.receipt.reviewed.at"]))):
                _fail("transparency-review-key-ineligible")
            scope = approved.get("reviewScope", {})
            bindings = {"appId": "app.id", "version": "app.version", "digest": "artifact.sha256",
                        "size": "artifact.size", "bundleKeyId": "bundle.key.id",
                        "policyId": "policy.id", "policyVersion": "policy.version"}
            if set(scope) != set(bindings) or any(str(scope[k]).removeprefix("sha256:") != value.get("review.receipt."+v) for k,v in bindings.items()):
                _fail("transparency-review-scope-invalid")
            payload = b"".join(f"{field}={value[field]}\n".encode() for field in _RECEIPT_FIELDS[:-2] if field in value)
            signature = _decode_signature(value["review.receipt.signature.value.base64"], "signature")
        elif role == "catalogs":
            sidecar = _properties(approved.get("signatureSidecar", "").encode())
            if (set(sidecar) != {"catalog.signature.version", "catalog.signature.algorithm", "catalog.signature.key.id", "catalog.signature.payload", "catalog.signature.value.base64"}
                    or sidecar["catalog.signature.version"] != "1"
                    or sidecar["catalog.signature.algorithm"] != "Ed25519"
                    or sidecar["catalog.signature.payload"] != "cryptad-app-catalog.properties"
                    or sidecar["catalog.signature.key.id"] != root["keyId"]
                    or root["role"] != "catalog-signing"
                    or root["lifecycle"] not in {"active", "retiring"}
                    or root["compromiseState"] != "uncompromised"
                    or not _timestamp(root["validFrom"]) <= _timestamp(value["catalog.generatedAt"]) < _timestamp(root["validUntil"])):
                _fail("transparency-catalog-signature-invalid")
            payload = raw
            signature = _decode_signature(sidecar["catalog.signature.value.base64"], "signature")
        elif role == "keys":
            if (root["role"] != "offline-recovery" or root["keyId"] != value["transparencySigningKeyId"]
                    or root["lifecycle"] not in {"active", "retiring"}
                    or root["compromiseState"] != "uncompromised"
                    or not _timestamp(root["validFrom"]) <= _timestamp(value["generatedAt"]) < _timestamp(root["validUntil"])):
                _fail("transparency-recovery-key-ineligible")
            payload = _canonical_bytes(value)
            signature = _decode_signature(approved.get("signatureBase64"), "signature")
        else:
            return "original-signature-proof-unavailable"
        if not _verify_ed25519(_raw_public_key(root), payload, signature):
            _fail("transparency-signature-invalid")
    except (KeyError, TypeError, ValueError):
        _fail("transparency-signature-invalid")
    return "valid-signature-selected-root-snapshot-only"


ADAPTERS = {"release": _release, "maintenance": _release, "keys": _keys,
            "lifecycle": _lifecycle, "advisories": _advisories, "supply-chain": _supply_chain,
            "reproducibility": _reproducibility, "sbom": _sbom,
            "catalogs": _catalog, "reviews": _review, "repository-status": _repository_status,
            "phase-assessment": _phase_assessment}


def _project_public_statement(role, raw, context):
    from .transparency_public_projection import validate_public_projection
    value = validate_public_projection(raw)
    if context['mode'] == 'production' and value.get('evidenceClass') == 'synthetic-rehearsal':
        _fail('transparency-synthetic-production-denied')
    if value['role'] != role:
        _fail('transparency-projection-role-mismatch')
    fields = {**value['fields'], 'reportedSourcePublication': value['sourcePublication'],
              'reportedSourceVerification': value['sourceVerification'],
              'sourceAuthority': value['sourceAuthority'],
              'originalProducerProof': value['originalProducerProof'],
              'originalPublicBytesDigest': _digest(raw)}
    identity = (f"{fields['advisoryId']}:edition-{fields['edition']}" if role == 'advisories'
                else f"{fields['releaseId']}:build-{fields['buildVersion']}")
    production = context['mode'] == 'production'
    view = {'role': role, 'identity': identity if production else 'demo-' + identity,
            'evidenceClass': 'source-owned-public-projection' if production else 'synthetic-preview',
            'provenance': 'reviewed-source-selection-original-producer-unavailable' if production else 'not-authenticated',
            'verification': 'derived-statement-schema-and-integrity-only',
            'disclosure': 'source-owned-closed-public-projection',
            'publication': 'not-established', 'activation': 'not-established',
            'observedAt': value['observedAt'], 'staleAt': None, 'fields': fields}
    return {'view': view, 'downloads': {role + '-public-projection.json': raw}}


def project(role: str, raw: bytes, context: dict[str, Any]) -> dict[str, Any]:
    """Project selected bytes without claiming original operational authentication.

    A production exact-byte selection is a source-policy statement. Required signature proofs
    must be admitted by the original source authority; this initial boundary fails closed while
    such a source-owned safe export is unavailable. Demo inputs can exercise all adapters.
    """
    if role not in ADAPTERS or context.get("mode") not in {"demo", "production"}:
        _fail("transparency-role-invalid")
    if role in PRIVATE_ORIGINALS:
        value = _read(raw)
        if value.get('kind') == 'public-ecosystem-source-projection':
            return _project_public_statement(role, raw, context)
    value = _properties(raw) if role in {"catalogs", "reviews"} else _read(raw)
    if role in SCHEMAS and validate_schema(value, SCHEMAS[role]):
        _fail("transparency-source-schema-invalid")
    production = context["mode"] == "production"
    if production and role in PRIVATE_ORIGINALS:
        _fail("transparency-source-owned-public-export-unavailable")
    if production and role == "keys" and value["governance"]["custodyClass"] == "fixture-memory-only":
        _fail("transparency-fixture-authority-in-production")
    if role in {'repository-status', 'phase-assessment'}:
        from .transparency_sources import policy
        rules, _ = policy()
        approved_revisions = [entry for entry in rules['approvedSources']
                              if entry.get('role') == role and entry.get('digest') == _digest(raw)
                              and entry.get('size') == len(raw)
                              and entry.get('disclosureRule') == ('reviewed-repository-status-v1' if role == 'repository-status' else 'reviewed-phase12-public-status-v1')
                              and entry.get('evidenceClass') == ('repository-reported' if role == 'repository-status' else 'repository-local-assessment')]
        if len(approved_revisions) != 1:
            _fail('transparency-repository-statement-not-reviewed' if role == 'repository-status' else 'transparency-phase-assessment-not-reviewed')
    fields = ADAPTERS[role](value)
    identity = str(value.get("advisoryId", value.get("releaseId", value.get("catalog.id", value.get("review.receipt.app.id", role)))))
    if role == "keys":
        identity = f"governance-keyset-{value['keysetVersion']}"
    elif role in {"repository-status", "phase-assessment"}:
        identity = role + ":" + _digest(raw)
    elif role == "lifecycle":
        identity = f"support-lifecycle-edition-{value['descriptorEdition']}"
    elif role == "catalogs":
        revision = value.get("catalog.revision", value["catalog.generatedAt"])
        identity = f"{identity}:{value.get('catalog.channel', 'channel-unspecified')}:{revision}"
    elif role == "reviews":
        identity = f"{identity}:{value['review.receipt.app.version']}:{value['review.receipt.reviewer.key.id']}:{value['review.receipt.reviewed.at']}"
    elif role == "advisories":
        identity = f"{identity}:edition-{value['edition']}"
    elif role in {"release", "maintenance"}:
        identity = f"{identity}:build-{value['buildVersion']}"
    # Only disclosure-safe originals receive public source identifiers and downloads. Internal
    # authority receipts remain outside this boundary even when their derived fields are safe.
    if role not in PRIVATE_ORIGINALS:
        fields["originalPublicBytesDigest"] = _digest(raw)
    verification = "schema-and-semantic-checks-only"
    approved = context.get("approvedSource") or {}
    if production and role in {"reviews", "keys", "catalogs", "lifecycle"}:
        verification = _signature_verification(role, raw, value, approved)
    view = {"role": role, "identity": ("" if production else "demo-") + identity,
            "evidenceClass": "repository-local-assessment" if role == "phase-assessment" else ("repository-reported" if role == "repository-status" else ("selected-public-source" if production else "synthetic-preview")),
            "provenance": "reviewed-source-selection-original-producer-unavailable" if production else "not-authenticated",
            "verification": verification, "disclosure": "reviewed-exact-source-policy" if production else "synthetic-only",
            "publication": "not-established", "activation": "not-established",
            "observedAt": value.get("observedAt", value.get("generatedAt", value.get("catalog.generatedAt", value.get("asOf", value.get("review.receipt.reviewed.at"))))),
            "staleAt": value.get("review.receipt.expires.at") if role == 'reviews' else value.get("staleAt"), "fields": fields}
    downloads = {}
    original_names = {"catalogs": "cryptad-app-catalog.properties", "reviews": "app-review-receipt.properties",
                      "keys": "stable-1.0-public-key-transparency.json", "lifecycle": "stable-1.0-support-lifecycle-descriptor.json",
                      "sbom": "stable-1.0-sbom-binding.json", "supply-chain": "stable-1.0-component-inventory.json",
                      "reproducibility": "stable-1.0-reproducibility-result.json", "repository-status": "repository-status.json",
                      "phase-assessment": "phase-12-public-status.json"}
    if role in original_names:
        downloads[original_names[role]] = raw
    if verification == "valid-signature-selected-root-snapshot-only":
        if role == "catalogs":
            downloads["cryptad-app-catalog.signature"] = approved["signatureSidecar"].encode("utf-8")
        elif role == "keys":
            from .engines.stable_1_0_catalog_authority import _decode_signature
            downloads["stable-1.0-public-key-transparency.signature"] = _decode_signature(approved["signatureBase64"], "signature")
    return {"view": view, "downloads": downloads}


def demo_sources() -> list[dict[str, Any]]:
    """Return bounded schema-shaped synthetic sources, never used by production admission."""
    from .engines.stable_1_0_lifecycle_core import build_ledger, build_descriptor
    from pathlib import Path
    policy = json.loads((Path(__file__).resolve().parents[1] / "stable-1.0-support-lifecycle-policy.json").read_bytes())
    digest = "sha256:" + "1" * 64
    release = {"releaseId": "synthetic-stable-1", "buildVersion": "1", "tag": "v1", "sourceCommit": "1" * 40,
               "releaseClass": "stable-ga", "productDigest": digest, "publicationReceiptDigest": digest,
               "baselineDigest": digest, "publishedAt": "2026-07-20T00:00:00Z", "chainDepth": 0,
               "unresolvedHotfixFollowUp": False}
    ledger, _, errors = build_ledger({"inventoryDigest": digest, "entries": [release]}, policy, digest,
                                    "2026-07-21T00:00:00Z", None, None)
    descriptor, descriptor_errors = build_descriptor(ledger, policy, "2026-07-21T00:00:00Z", None,
                                                     policy["descriptor"]["updateKeyIdentityDigest"])
    if errors or descriptor_errors:
        _fail("transparency-demo-contract-drift")
    result = {"schemaVersion": 1, "kind": "stable-1.0-reproducibility-result",
              "releaseId": "synthetic-stable-1", "buildVersion": 1, "tag": "v1", "sourceCommit": "1"*40,
              "sourceRef": "refs/tags/v1", "policyDigest": digest, "comparisonPlanDigest": digest,
              "primaryBuilderReceiptDigest": digest, "verifierBuilderReceiptDigest": digest,
              "comparisons": [{"subjectKey": "synthetic-portable", "reproducibilityClass": "byte-identical",
                               "status": "pass", "primaryDigest": digest, "verifierDigest": digest,
                               "primaryPayloadManifestDigest": None, "verifierPayloadManifestDigest": None,
                               "differences": []}], "status": "pass", "unexplainedDifferences": 0}
    result["resultDigest"] = _digest(_canonical(result))
    catalog = ("catalog.version=1\ncatalog.id=synthetic\ncatalog.name=Synthetic catalog\n"
               "catalog.generatedAt=2026-07-21T00:00:00Z\ncatalog.entries=synthetic-app\n"
               "app.synthetic-app.id=synthetic-app\napp.synthetic-app.name=Synthetic app\n"
               "app.synthetic-app.version=1.0.0\napp.synthetic-app.bundle.sha256=" + "1"*64 +
               "\napp.synthetic-app.bundle.size.bytes=1\n")
    sources = [{"role": "lifecycle", "raw": _canonical(descriptor)},
               {"role": "reproducibility", "raw": _canonical(result)},
               {"role": "catalogs", "raw": catalog.encode()}]
    binding = {"schemaVersion": 1, "kind": "stable-1.0-sbom-binding", "releaseId": "synthetic-stable-1",
               "buildVersion": 1, "tag": "v1", "sourceCommit": "1"*40, "sourceRef": "refs/tags/v1",
               "policyDigest": digest, "format": "SPDX-2.3-json",
               "documentNamespace": "https://crypta.network/spdx/stable-1.0/synthetic/"+"1"*64,
               "sbomDigest": digest, "componentInventoryDigest": digest, "subjectInventoryDigest": digest,
               "subjects": [{"subjectKey": "synthetic-portable", "subjectDigest": digest}]}
    binding["bindingDigest"] = _digest(_canonical(binding))
    sources.append({"role": "sbom", "raw": _canonical(binding)})
    component = {"schemaVersion": 1, "kind": "stable-1.0-component", "componentId": "pkg:generic/synthetic@1",
                 "componentKind": "internal-module", "name": "synthetic", "version": "1", "namespace": None,
                 "purl": "pkg:generic/synthetic@1", "digest": digest,
                 "origin": {"type": "repository-source", "uri": None, "immutableReference": "1"*40, "provenanceDigest": digest},
                 "resolved": {"coordinates": None, "selectedVariant": None, "attributes": []},
                 "roles": ["runtime"], "relationships": {"direct": True, "parents": [], "contains": [], "dependsOn": []},
                 "subjectKeys": ["synthetic-portable"], "apps": [], "runtimeComponentIds": [],
                 "license": {"expression": "GPL-3.0-only", "status": "not-applicable-internal", "evidenceDigest": digest, "licenseTextDigest": None},
                 "dependencyVerificationStatus": "not-applicable", "buildMaterialStatus": "built", "classification": "public"}
    component["recordDigest"] = _digest(_canonical(component))
    inventory = {"schemaVersion": 1, "kind": "stable-1.0-component-inventory", "releaseId": "synthetic-stable-1",
                 "buildVersion": 1, "sourceCommit": "1"*40, "policyDigest": digest,
                 "resolvedDependencySnapshotDigest": digest, "components": [component]}
    inventory["inventoryDigest"] = _digest(_canonical(inventory))
    sources.append({"role": "supply-chain", "raw": _canonical(inventory)})
    # Fixed repository-owned synthetic fixture code, reachable only through this demo factory.
    from .tests.test_stable_catalog_authority import _manifest, _fixture_keypair, _fixture_sign
    from .engines.stable_1_0_catalog_authority import _transparency_artifact, _RECEIPT_FIELDS
    import base64
    manifest = _manifest()
    sources.append({"role": "keys", "raw": _canonical(_transparency_artifact(manifest))})
    reviewer = next(k for k in manifest["keyset"]["keys"] if k["role"] == "app-reviewer")
    receipt = {"review.receipt.version": "2", "review.receipt.app.id": "synthetic-app",
               "review.receipt.app.version": "1.0.0", "review.receipt.artifact.sha256": "1"*64,
               "review.receipt.artifact.size": "1", "review.receipt.bundle.key.id": "synthetic-app-signer",
               "review.receipt.policy.id": "synthetic-policy", "review.receipt.policy.version": "1",
               "review.receipt.status": "caution", "review.receipt.reviewer.key.id": reviewer["keyId"],
               "review.receipt.reviewed.at": "2026-08-21T00:00:00Z", "review.receipt.signature.algorithm": "Ed25519"}
    payload = b"".join(f"{f}={receipt[f]}\n".encode() for f in _RECEIPT_FIELDS[:-2] if f in receipt)
    seed, public = _fixture_keypair(reviewer["keyId"])
    receipt["review.receipt.signature.value.base64"] = base64.b64encode(_fixture_sign(seed, public, payload)).decode()
    sources.append({"role": "reviews", "raw": b"".join(f"{f}={receipt[f]}\n".encode() for f in _RECEIPT_FIELDS if f in receipt)})
    return sources
