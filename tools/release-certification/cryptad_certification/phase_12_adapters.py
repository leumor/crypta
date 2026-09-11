"""Finite, offline Phase 12 semantic adapters under the existing owning verifiers.

These adapters execute verification, never the selected artifact. A verified signature proves
the signed relationship only: original protected workflow/job/environment authentication belongs
to its owner and is deliberately not manufactured here. Public site records are consumers.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import stat
import zipfile

from .schema_validation import validate_schema
from .transparency_sources import strict_json

ROOT = Path(__file__).resolve().parents[3]
POLICIES = Path(__file__).resolve().parents[1]
MAX_BYTES = 512 * 1024 * 1024
MAX_SITE_BYTES = 16 * 1024 * 1024
OWN_INPUTS = {
    "protected-ga-receipt": ("contract.json", "freeze.json", "authorization.json", "plan.json", "receipt.json", "identity.json"),
    "independent-receipts": ("summary.json", "primary.json", "external.json"),
    "independent-comparison": ("contract.json", "inventory.json", "primary.json", "external.json", "output-manifest.json", "primary.zip", "external.zip"),
    "catalog-keyset": ("authority.json",),
    "pilot-review": ("execution.json", "handoff.json", "review.json", "approval.json"),
    "federation-trust": ("execution.json", "descriptor.json", "endorsements.json", "runtime.json"),
    "transparency-sources": ("source-package.json",),
    "transparency-bundle": ("bundle.zip",),
    "historical-transparency-bundle": ("bundle.zip", "checkpoint.json"),
}


class AdapterError(ValueError):
    """A fixed diagnostic which contains no selected material."""


def _deny():
    raise AdapterError("phase12-owner-evidence-invalid")


def _json(raw):
    value = strict_json(raw)
    pending = [(value, 0)]
    count = 0
    while pending:
        item, depth = pending.pop()
        count += 1
        if depth > 32 or count > 100000:
            _deny()
        if isinstance(item, dict):
            pending.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            pending.extend((child, depth + 1) for child in item)
    return value


def _document(raw, schema):
    value = _json(raw)
    if not isinstance(value, dict) or validate_schema(value, schema):
        _deny()
    return value


def _time(value):
    if not isinstance(value, str):
        _deny()
    instant = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if instant.tzinfo is None or instant.utcoffset() != dt.timedelta(0):
        _deny()
    return instant


def _policy(name):
    return _json((POLICIES / name).read_bytes())


def _check(errors):
    if errors:
        _deny()


def _binding(raw, binding):
    if (not isinstance(binding, dict) or binding.get("size") != len(raw)
            or binding.get("digest") != "sha256:" + hashlib.sha256(raw).hexdigest()):
        _deny()


def _result(claims, required, observed, *, synthetic=False, blockers=(), subject=None):
    return {"dimensions": {"localVerification": "executed-pass", "originalProvenance": "unverified"},
            "claims": sorted(claims), "blockers": sorted(blockers),
            "coverage": {"required": sorted(required), "observed": sorted(observed)},
            "evidenceClass": "synthetic-rehearsal" if synthetic else "verified-local-semantics",
            "subjectBindings": subject or {}}


def _protected(payloads, evaluation):
    from .engines import stable_1_0_protected_release as owner
    from .engines.stable_1_0_rc_freeze import validate_freeze_shape
    schemas = {"contract": owner.CONTRACT_SCHEMA, "freeze": owner.RC_FREEZE_SCHEMA,
               "authorization": owner.GA_AUTHORIZATION_SCHEMA, "plan": owner.GA_PUBLICATION_PLAN_SCHEMA,
               "receipt": owner.GA_PUBLICATION_RECEIPT_SCHEMA, "identity": owner.GA_VALIDATION_IDENTITY_SCHEMA}
    values = {key: _document(payloads[key + ".json"], schema) for key, schema in schemas.items()}
    contract, identity = values["contract"], values["identity"]
    _check(validate_freeze_shape(values["freeze"]))
    identity_digest = owner._ga_promotion_identity_digest(identity)
    _check(owner._ga_promotion_plan_errors(values["plan"], contract, values["authorization"],
                                         identity_digest, values["freeze"]))
    coordinate = contract["workflowCoordinates"]["gaPublication"]
    # The owner's receipt checker additionally binds invocation coordinates from the receipt;
    # this is structural revalidation, not a call to its hosted provenance authenticator.
    _check(owner._ga_publication_receipt_errors(values["receipt"], contract, coordinate,
                                              values["authorization"], values["plan"], identity_digest))
    if _time(values["receipt"]["generatedAt"]) > evaluation:
        _deny()
    return _result(["p12-291-freeze", "p12-291-validation", "p12-291-publication"],
                   ["exact-frozen-product", "protected-validation", "explicit-publication", "public-observation"],
                   ["freeze-cohort-and-semantic-integrity", "ga-plan-authorization-receipt-relationship"],
                   blockers=["original-protected-ga-context-required", "exact-frozen-product-bytes-required"],
                   subject={"commit": contract["repository"]["candidateCommit"],
                            "build": str(contract["release"]["integerBuild"]),
                            "digest": contract["ga"]["selectedRc"]["productDigest"]})


def _independent(payloads, evaluation):
    from .engines import stable_1_0_independent_reproducibility as owner
    from .engines.stable_1_0_independent_closeout import independent_receipt_semantic_errors
    summary = _document(payloads["summary.json"], owner.SUMMARY_SCHEMA)
    primary = _document(payloads["primary.json"], owner.PRIMARY_RECEIPT_SCHEMA)
    external = _document(payloads["external.json"], owner.BUILDER_RECEIPT_SCHEMA)
    supply_policy = _policy("stable-1.0-supply-chain-policy.json")
    independent_policy = _policy("stable-1.0-independent-reproducibility-policy.json")
    if (summary["stableSupplyChainPolicyDigest"] != supply_policy["policyDigest"]
            or summary["independentReproducibilityPolicyDigest"] != independent_policy["policyDigest"]):
        _deny()
    _check(independent_receipt_semantic_errors(summary, primary, external,
              supply_policy, independent_policy))
    for value in (summary, primary, external):
        for field in ("generatedAt", "completedAt"):
            if value.get(field) is not None and _time(value[field]) > evaluation:
                _deny()
    blockers = ["original-builder-proofs-required", "exact-comparison-artifact-reverification-required"]
    if not owner._IMPLEMENTED_OPERATIONAL_EXTERNAL_ADAPTERS:
        blockers.append("external-provider-cryptographic-adapter-unavailable")
    return _result(["p12-292-provider"],
                   ["exact-subject-cohort", "exact-or-owner-normalized-comparison", "independent-provider-original-proof"],
                   ["retained-receipt-subject-recipe-identity"],
                   synthetic=bool(summary.get("fixtureOnly") or summary.get("selfTest")), blockers=blockers,
                   subject={"commit": summary["sourceCommit"], "build": str(summary["buildVersion"])})


def _comparison(payloads, evaluation, scratch):
    from .engines import stable_1_0_independent_reproducibility as owner
    from .engines.stable_1_0_supply_chain_core import SUBJECT_INVENTORY_SCHEMA
    contract = _document(payloads["contract.json"], owner.CONTRACT_SCHEMA)
    inventory = _document(payloads["inventory.json"], SUBJECT_INVENTORY_SCHEMA)
    primary = _document(payloads["primary.json"], owner.PRIMARY_RECEIPT_SCHEMA)
    external = _document(payloads["external.json"], owner.BUILDER_RECEIPT_SCHEMA)
    manifest = _document(payloads["output-manifest.json"], owner.OUTPUT_MANIFEST_SCHEMA)
    policy, supply = owner._load_policy()
    _check(owner._policy_errors(contract, policy, supply))
    if (contract["executionContractDigest"] != owner.execution_contract_digest(contract)
            or external["executionContractDigest"] != contract["executionContractDigest"]
            or inventory["subjectInventoryDigest"] != contract["authenticatedInputs"]["subjectInventoryDigest"]):
        _deny()
    for value, field in ((inventory, "subjectInventoryDigest"), (primary, "receiptDigest"), (external, "receiptDigest")):
        if value[field] != owner._strict_digest(value, field):
            _deny()
    _check(owner._output_manifest_errors(manifest, external, contract, {"kitDigest": external["verifierKitDigest"]}))
    release = owner._release_projection(contract)
    for document in (inventory, primary, external):
        if any(document.get(field) != release[field] for field in ("releaseId", "buildVersion", "sourceCommit")):
            _deny()
    if not (_time(external["buildStartedAt"]) <= _time(external["buildCompletedAt"])
            <= _time(external["outputsSealedAt"]) <= evaluation):
        _deny()
    # Limit transport and expansion before invoking the owner's closed ZIP member selection.
    for name in ("primary.zip", "external.zip"):
        with zipfile.ZipFile(io.BytesIO(payloads[name])) as archive:
            rows = archive.infolist()
            if len(rows) > 4096 or sum(row.file_size for row in rows) > MAX_BYTES:
                _deny()
        (scratch / name).write_bytes(payloads[name])
    _plan, result, _difference, errors = owner._compare_evidence(contract, policy, supply,
        {"subjectInventory": inventory}, primary, external, scratch / "primary.zip", scratch / "external.zip", manifest)
    _check(errors)
    if result is None or result["status"] != "pass":
        _deny()
    return _result(["p12-292-comparison"],
        ["exact-required-product-cohort", "owner-exact-and-normalized-byte-comparison", "original-builder-and-kit-proofs"],
        ["exact-required-product-cohort", "owner-exact-and-normalized-byte-comparison"],
        blockers=["original-builder-and-kit-proofs-required"],
        synthetic=contract["evidenceClassification"]["selfTest"] != "not-performed",
        subject={"commit": release["sourceCommit"], "build": str(release["buildVersion"])})


def _catalog(payloads, evaluation):
    from .engines import stable_1_0_catalog_authority as owner
    manifest = _document(payloads["authority.json"], owner.EXECUTION_SCHEMA)
    _check(owner._policy_contract_errors(_policy("stable-1.0-catalog-authority-policy.json")))
    errors, keys = owner._validate_keyset(manifest, True)
    _check(errors + owner._validate_recovery(manifest, keys, True))
    if _time(manifest["transparency"]["generatedAt"]) > evaluation:
        _deny()
    _check(owner._sensitive_findings(manifest, allow_public_keys=True))
    return _result(["p12-293-keyset"], ["routine-role-keyset", "separate-recovery-authority", "original-ceremony-proof"],
                   ["routine-role-keyset", "separate-recovery-authority"],
                   synthetic=manifest["fixtureOnly"], blockers=["original-key-ceremony-authority-required"],
                   subject={"commit": manifest["release"]["sourceCommit"],
                            "build": str(manifest["release"]["buildVersion"]),
                            "digest": manifest["keyset"]["keysetDigest"]})


def _pilot(payloads, evaluation):
    from .engines import stable_1_0_third_party_pilot as owner
    schemas = {"execution": owner.EXECUTION_SCHEMA, "handoff": owner.HANDOFF_SCHEMA,
               "review": owner.REVIEW_SCHEMA, "approval": owner.APPROVAL_SCHEMA}
    values = {key: _document(payloads[key + ".json"], schema) for key, schema in schemas.items()}
    contract, handoff = values["execution"], values["handoff"]
    policy, _ = owner._policy(ROOT)
    errors, by_role = owner._key_errors(contract, evaluation)
    _check(errors + owner._externality_errors(contract, policy, by_role, evaluation)
           + owner._cohort_contract_errors(contract) + owner._pilot_node_contract_errors(contract))
    for name, key in (("handoff", "externalHandoff"), ("review", "reviewCohort"), ("approval", "publisherApproval")):
        _binding(payloads[name + ".json"], contract["evidence"][key])
    reviewer = by_role["app-reviewer"]
    maximum = policy["freshness"]["maximumReceiptAgeSeconds"]
    _check(owner._review_errors(contract, handoff, values["review"], reviewer, evaluation, maximum))
    _check(owner._approval_errors(contract, handoff, values["approval"], reviewer, evaluation, maximum))
    return _result(["p12-294-externality", "p12-294-review"],
                   ["actual-external-source", "review-caution-rejected-resubmission", "install-update-rollback"],
                   ["externality-policy-relationships", "signed-review-cohort", "signed-publisher-approval"],
                   synthetic=contract["fixtureOnly"] or contract["selfTest"],
                   blockers=["original-external-handoff-and-protected-review-required", "pilot-runtime-not-observed"],
                   subject={"commit": contract["repository"]["sourceCommit"]})


def _federation(payloads, evaluation):
    from .engines import stable_1_0_federated_catalog as owner
    contract = _document(payloads["execution.json"], owner.EXECUTION_SCHEMA)
    descriptor = _document(payloads["descriptor.json"], owner.DESCRIPTOR_SCHEMA)
    observation = _document(payloads["runtime.json"], owner.RUNTIME_SCHEMA)
    policy, pin = owner._policy(ROOT)
    if contract["policyDigest"] != pin:
        _deny()
    _binding(payloads["descriptor.json"], contract["evidence"]["descriptor"])
    _binding(payloads["runtime.json"], contract["evidence"]["runtimeObservation"])
    _check(owner._descriptor_errors(descriptor, contract["evidence"]["descriptor"], evaluation, policy))
    # The carrier preserves each original endorsement's exact bytes rather than resealing it.
    carrier = _json(payloads["endorsements.json"])
    import base64
    bindings = contract["evidence"]["endorsements"]
    if not isinstance(carrier, list) or len(carrier) != len(bindings) or len(carrier) > 32:
        _deny()
    endorsements = []
    for encoded, binding in zip(carrier, bindings):
        raw = base64.b64decode(encoded, validate=True)
        _binding(raw, binding)
        endorsement = _document(raw, owner.ENDORSEMENT_SCHEMA)
        _check(owner._endorsement_errors(endorsement, binding, descriptor, evaluation, policy))
        endorsements.append(endorsement)
    ids = [value["endorsementId"] for value in endorsements]
    if len(set(ids)) != len(ids):
        _deny()
    _check(owner._runtime_errors(observation, contract["evidence"]["runtimeObservation"], contract,
                                 descriptor, endorsements, evaluation, policy))
    return _result(["p12-295-trust", "p12-295-conflicts", "p12-295-origin"],
                   ["local-scoped-trust", "conflict-handling", "installed-origin-and-consent", "original-protected-runtime"],
                   ["signed-discovery-and-endorsement", "signed-runtime-subject-and-freshness"],
                   synthetic=contract["fixtureOnly"] or contract["selfTest"],
                   blockers=["original-federation-observer-authority-required"],
                   subject={"commit": contract["repository"]["sourceCommit"],
                            "build": str(contract["release"]["buildVersion"])})


def _sources(payloads, evaluation):
    from .transparency_sources import admit
    package = _json(payloads["source-package.json"])
    admitted = admit(package)
    if _time(package["selection"]["asOf"]) > evaluation:
        _deny()
    required = ["approved-typed-source-admission", "deployed-exact-bundle", "original-public-observation"]
    observed = ["approved-typed-source-admission"] if admitted["records"] else ["empty-source-selection-verified"]
    return _result(["p12-302-admission"], required, observed,
                   synthetic=package["selection"]["mode"] != "production",
                   blockers=["site-deployment-not-observed", "site-public-observation-not-observed"])


def _site_root(payloads, scratch):
    root = scratch / "site"
    root.mkdir(mode=0o700, parents=False, exist_ok=False)
    raw_archive = payloads["bundle.zip"]
    # Closed transport has no ZIP comment or appended payload after the ordinary end record.
    if (len(raw_archive) < 22 or raw_archive[-22:-18] != b"PK\x05\x06"
            or raw_archive[-2:] != b"\x00\x00" or len(raw_archive) > MAX_SITE_BYTES):
        _deny()
    with zipfile.ZipFile(io.BytesIO(raw_archive)) as archive:
        rows = archive.infolist()
        names = [row.filename for row in rows]
        if (archive.comment or len(rows) > 1024 or len(names) != len(set(names))
                or len(names) != len({name.casefold() for name in names})
                or sum(row.file_size for row in rows) > MAX_SITE_BYTES):
            _deny()
        for row in rows:
            name = PurePosixPath(row.filename)
            mode = row.external_attr >> 16
            if (name.is_absolute() or ".." in name.parts or "\\" in row.filename
                    or str(name) != row.filename or row.is_dir()
                    or (stat.S_IFMT(mode) not in {0, stat.S_IFREG})
                    or row.flag_bits & 1 or row.extra or row.comment
                    or row.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
                    or row.file_size > MAX_SITE_BYTES
                    or row.file_size > max(1, row.compress_size) * 128):
                _deny()
            target = root.joinpath(*name.parts)
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with archive.open(row) as stream:
                raw = stream.read(row.file_size + 1)
            if len(raw) != row.file_size:
                _deny()
            target.write_bytes(raw)
    return root


def _bundle(payloads, evaluation, scratch):
    from .transparency_bundle import verify as verify_bundle
    root = _site_root(payloads, scratch)
    checked = verify_bundle(root)
    if _time(checked["index"]["asOf"]) > evaluation:
        _deny()
    result = _result(["p12-302-bundle"], ["deterministic-site-bundle"],
                     ["deterministic-site-bundle"], synthetic=checked["index"]["mode"] != "production",
                     subject={"digest": checked["manifestDigest"]})
    # This assertion owns deterministic bundle verification. Original release admission,
    # deployment and public observation have separate mandatory requirements.
    result["claimResults"] = {"p12-302-bundle": {
        "dimensions": {"coverage": "complete"}, "coverage": result["coverage"], "blockers": []}}
    return result


def _historical_bundle(payloads, evaluation, scratch):
    from .transparency_bundle import verify_checkpoint
    checkpoint = _json(payloads["checkpoint.json"])
    if (type(checkpoint) is not dict or set(checkpoint) != {"manifestDigest"}
            or type(checkpoint["manifestDigest"]) is not str
            or re.fullmatch(r"sha256:[0-9a-f]{64}", checkpoint["manifestDigest"]) is None):
        _deny()
    index = verify_checkpoint(_site_root(payloads, scratch), checkpoint["manifestDigest"])
    if _time(index["asOf"]) > evaluation:
        _deny()
    return _result(["p12-302-bundle"],
        ["historical-exact-site-checkpoint", "original-historical-tool-verification", "approved-deployment", "original-public-observation"],
        ["historical-exact-site-checkpoint"], synthetic=index["mode"] != "production",
        blockers=["original-historical-site-tool-proof-required", "site-deployment-not-observed", "site-public-observation-not-observed"],
        subject={"digest": checkpoint["manifestDigest"]})


def verify(adapter: str, payloads: dict[str, bytes], as_of: str, scratch: Path) -> dict:
    """Execute one closed semantic adapter and emit only fixed scoped claims and diagnostics."""
    try:
        if adapter not in REQUIRED_INPUTS or not isinstance(payloads, dict) or set(payloads) != set(REQUIRED_INPUTS[adapter]):
            _deny()
        if any(not isinstance(raw, bytes) or len(raw) > MAX_BYTES for raw in payloads.values()):
            _deny()
        evaluation = _time(as_of)
        if adapter in FEDERATION_INPUTS:
            from .phase_12_federation_context import verify as federation_verify
            return federation_verify(adapter, payloads, as_of, scratch)
        if adapter in SITE_INPUTS:
            from .phase_12_site_evidence import verify as site_verify
            return site_verify(adapter, payloads, as_of, scratch)
        if adapter in CONTEXT_INPUTS:
            from .phase_12_authority_context import verify as context_verify
            return context_verify(adapter, payloads, as_of, scratch)
        if adapter not in OWN_INPUTS:
            from .phase_12_runtime_adapters import verify as runtime_verify
            return runtime_verify(adapter, payloads, as_of, scratch)
        if adapter == "transparency-bundle":
            return _bundle(payloads, evaluation, scratch)
        if adapter == "historical-transparency-bundle":
            return _historical_bundle(payloads, evaluation, scratch)
        if adapter == "independent-comparison":
            return _comparison(payloads, evaluation, scratch)
        operation = {"protected-ga-receipt": _protected, "independent-receipts": _independent,
                     "catalog-keyset": _catalog, "pilot-review": _pilot, "federation-trust": _federation,
                     "transparency-sources": _sources}[adapter]
        return operation(payloads, evaluation)
    except (ValueError, TypeError, KeyError, IndexError, AttributeError, OSError, RecursionError, zipfile.BadZipFile):
        raise AdapterError("phase12-owner-evidence-invalid") from None


from .phase_12_runtime_adapters import REQUIRED_INPUTS as RUNTIME_INPUTS
from .phase_12_authority_context import REQUIRED_INPUTS as CONTEXT_INPUTS
from .phase_12_site_evidence import REQUIRED_INPUTS as SITE_INPUTS
from .phase_12_federation_context import REQUIRED_INPUTS as FEDERATION_INPUTS

REQUIRED_INPUTS = {**OWN_INPUTS, **RUNTIME_INPUTS, **CONTEXT_INPUTS, **SITE_INPUTS, **FEDERATION_INPUTS}
