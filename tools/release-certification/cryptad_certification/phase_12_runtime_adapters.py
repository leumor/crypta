"""Finite, offline Phase 12 runtime consumers; original producers remain separate authorities.

Only installed owner verifiers run here. Retained observations and test reports are inputs to
verification, never permission to execute their producers or authenticated execution by themselves.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import importlib
import io
import json
from pathlib import Path
import re
import stat
import sys
import tempfile
from types import SimpleNamespace
import zipfile

from . import cross_version_evidence as soak
from . import maintenance_drill_command as drill
from .engines import stable_content_profile_review as profiles
from .engines import stable_legacy_plugin_migration as migration
from .engines import stable_platform_api_1x as api
from .schema_validation import validate_schema

ROOT = Path(__file__).resolve().parents[3]
PROTECTED = Path(__file__).resolve().parents[1] / "protected"
MAX_BYTES = 32 * 1024 * 1024
PRODUCT_BYTES = 512 * 1024 * 1024
MAX_DEPTH = 32


def _policy():
    value = json.loads((ROOT / profiles.POLICY).read_bytes())
    profiles.validate_policy(value)
    return value


REQUIRED_INPUTS = {
    "product-admission": ("selection.json", "product.zip"),
    "rc-product-admission": ("selection.json", "rc.zip", "portable.zip"),
    "api-compatibility": ("execution-contract.json", "evidence.zip"),
    "api-subjects-v2": ("execution-contract.json", "app-subject-inventory.json"),
    "migration-observation": ("observation.json",),
    "profile-review": ("review.json", "registry.json", "javascript-results.json")
                      + tuple(Path(row["resultFile"]).name for row in _policy()["suites"]),
    "measured-soak": ("plan.json", "events.json", "checkpoint.json"),
    "mail-runtime": ("plan.json", "events.json", "checkpoint.json"),
    "maintenance-drill": ("drill.json",),
    "maintenance-measurements": ("plan.json", "events.json", "checkpoint.json", "products.json"),
}


def _protected(name):
    if name not in {"app_subject_projection", "sharesite_observation", "maintenance_runtime_projection",
                    "cross_version_supervisor_authority", "cross_version_product_admission"}:
        raise ValueError("phase12-runtime-adapter-unknown")
    # Fixed installed modules only, never an evidence-supplied import or script.
    sys.path.insert(0, str(PROTECTED))
    try:
        return importlib.import_module(name)
    finally:
        sys.path.pop(0)


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("phase12-runtime-duplicate-json-key")
        result[key] = value
    return result


def _json(raw):
    value = json.loads(raw, object_pairs_hook=_pairs,
                       parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("nonfinite")))
    pending = [(value, 0)]
    count = 0
    while pending:
        child, depth = pending.pop()
        count += 1
        if depth > MAX_DEPTH or count > 1000000:
            raise ValueError("phase12-runtime-json-budget")
        if isinstance(child, dict):
            pending.extend((item, depth + 1) for item in child.values())
        elif isinstance(child, list):
            pending.extend((item, depth + 1) for item in child)
    return value


def _result(*, claims=(), blockers=(), required=(), observed=(), evidence_class="retained-local-input",
            verification="executed-pass", implementation="implemented"):
    return {"dimensions": {"implementation": implementation, "localVerification": verification,
                           "originalProvenance": "unverified", "runtimeExecution": "not-observed"},
            "claims": sorted(set(claims)), "blockers": sorted(set(blockers)),
            "coverage": {"required": sorted(set(required)), "observed": sorted(set(observed))},
            "evidenceClass": evidence_class}


def _api_subjects(values, payloads, now):
    contract, inventory = values["execution-contract.json"], values["app-subject-inventory.json"]
    if (validate_schema(contract, api.EXECUTION_SCHEMA)
            or validate_schema(inventory, "platform-api-1.x-app-subject-inventory-v2.schema.json")):
        raise ValueError("phase12-runtime-api-schema")
    policy, policy_digest = api._policy(ROOT)
    if contract["policyDigest"] != policy_digest or dt.datetime.fromisoformat(contract["evaluationTime"]) > now:
        raise ValueError("phase12-runtime-api-policy-or-time")
    projection = _protected("app_subject_projection")
    from original_artifact_authentication import validate_coordinates
    binding = contract["evidence"]["appSubjectInventory"]
    raw = payloads["app-subject-inventory.json"]
    if (binding is None or binding["digest"] != "sha256:" + hashlib.sha256(raw).hexdigest()
            or binding["size"] != len(raw)):
        raise ValueError("phase12-runtime-api-inventory-byte-binding")
    fields = set(api.MATRIX_SUBJECT_FIELDS) - {"sourceAuthority", "fixtureOnly", "requiredForRelease"}
    for subject in inventory["subjects"]:
        validate_coordinates(subject["originalSource"])
        validate_coordinates(subject["originalInventorySource"])
        if subject["originalCatalogSource"] is not None:
            validate_coordinates(subject["originalCatalogSource"])
        declaration = projection.validate_declaration(subject["signedProjection"])
        if any(subject[field] != declaration[field] for field in fields):
            raise ValueError("phase12-runtime-api-declaration-substitution")
        if subject["originalSource"]["sourceFamily"] != subject["sourceAuthority"]:
            raise ValueError("phase12-runtime-api-original-substitution")
    # Capability absence remains an explicit admission gap. All other original consumer
    # checks still run; no internal authentication object is constructed here.
    errors = api._app_subject_inventory_errors(inventory, False, contract, policy)
    authentication_only = {
        "version-2 app inventory lacks original protected projection authentication",
        *(f"app subject inventory row {i} lacks an authenticated complete compatibility projection"
          for i in range(len(inventory["subjects"]))),
    }
    # The owner includes Mail when its verified capability selects current-eight. Enforce that
    # same closed cohort here while leaving capability admission to the original producer.
    first_party = {row["appId"] for row in inventory["subjects"]
                   if row["sourceAuthority"] == "first-party-release"}
    expected = set(policy["requiredFirstPartyAppIds"])
    if inventory["cohortPolicy"] == "current-eight-experimental-mail":
        expected.add("mail-prototype")
        authentication_only.add("app subject inventory differs from the policy-required first-party apps")
    if first_party != expected or not expected <= set(inventory["requiredAppIds"]):
        raise ValueError("phase12-runtime-api-cohort-omitted")
    if any(error not in authentication_only for error in errors):
        raise ValueError("phase12-runtime-api-owner-rejected")
    blockers = ["original-protected-projection-required"]
    if inventory["cohortPolicy"] != "current-eight-experimental-mail":
        blockers.append("current-mail-subject-cohort-not-covered")
    if any(row["sourceAuthority"] == "federated-catalog" for row in inventory["subjects"]):
        blockers.append("selected-federation-projection-unsupported")
    result = _result(claims=("p12-296-subjects",), blockers=blockers,
                   required=("first-party-cohort", "external-app", "current-experimental-mail"),
                   observed=("first-party-cohort", "external-app") +
                            (("current-experimental-mail",) if "mail-prototype" in first_party else ()),
                   evidence_class="signed-declaration-local-consistency")
    result["subjectBindings"] = {"commit": inventory["sourceCommit"],
                                 "build": str(contract["release"]["buildVersion"])}
    return result


def _api_compatibility(values, payloads, scratch, now):
    contract = values["execution-contract.json"]
    if (validate_schema(contract, api.EXECUTION_SCHEMA)
            or dt.datetime.fromisoformat(contract["evaluationTime"]) != now):
        raise ValueError("phase12-runtime-api-contract-or-evaluation-invalid")
    with tempfile.TemporaryDirectory(prefix="api-owner-verify-", dir=scratch) as temporary:
        root = Path(temporary)
        evidence = root / "evidence"
        evidence.mkdir()
        policy = root / "tools/release-certification" / api.POLICY_FILE
        policy.parent.mkdir(parents=True)
        policy.write_bytes((ROOT / "tools/release-certification" / api.POLICY_FILE).read_bytes())
        execution = root / "execution.json"
        execution.write_bytes(payloads["execution-contract.json"])
        total, names = 0, set()
        with zipfile.ZipFile(io.BytesIO(payloads["evidence.zip"])) as archive:
            members = archive.infolist()
            if len(members) > 256:
                raise ValueError("phase12-runtime-api-archive-budget")
            for member in members:
                name = member.filename
                total += member.file_size
                mode = member.external_attr >> 16
                if (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,159}", name)
                        or name.casefold() in names or member.is_dir() or member.flag_bits & 1
                        or stat.S_IFMT(mode) not in {0, stat.S_IFREG}
                        or member.file_size > 4 * 1024 * 1024 or total > MAX_BYTES
                        or not (name.endswith(".json") or name.endswith(".sha256"))):
                    raise ValueError("phase12-runtime-api-archive-member-invalid")
                names.add(name.casefold())
                raw = archive.read(member)
                if name.endswith(".json"):
                    _json(raw)  # Duplicate-key/depth rejection before original owner parsing.
                (evidence / name).write_bytes(raw)
        api.run(root, execution, "verify-runtime", root / "result", evidence)
        summary = _json((root / "result" / api.SUMMARY_FILE).read_bytes())
    checks = {row["id"]: row["status"] for row in summary["checks"]}
    fixture = contract["fixtureOnly"] or contract["selfTest"]
    result = _result(claims=("p12-296-baseline", "p12-296-runtime"),
                     blockers=("api-history-runtime-original-producer-unverified",),
                     evidence_class="synthetic-rehearsal" if fixture else "retained-api-compatibility-inputs")
    result["subjectBindings"] = {"commit": summary["sourceCommit"], "build": str(summary["buildVersion"])}
    result["claimResults"] = {}
    for claim, stage in (("p12-296-baseline", "history"), ("p12-296-runtime", "runtime")):
        passed = checks["platform-api-1x." + stage] in {"pass", "fixture-only"}
        result["claimResults"][claim] = {
            "dimensions": {"localVerification": "executed-pass" if passed else "executed-fail",
                           "originalProvenance": "unverified", "runtimeExecution": "not-observed"},
            "blockers": ["api-history-runtime-original-producer-unverified"] +
                        ([] if passed else ["api-required-owner-inputs-or-checks-incomplete"]),
            "coverage": {"required": ["platform-api-1x." + stage],
                         "observed": ["platform-api-1x." + stage] if passed else []}}
    return result


def _product(adapter, values, payloads, scratch, now):
    owner = _protected("cross_version_product_admission")
    from original_artifact_authentication import OriginalArtifact, validate_coordinates
    selection = values["selection.json"]
    fields = ({"node", "original", "freezeDigest"} if adapter == "product-admission"
              else {"node", "rcOriginal", "portableOriginal"})
    if type(selection) is not dict or set(selection) != fields:
        raise ValueError("product-selection-fields")
    node = selection["node"]
    node_fields = {"role", "sourceCommit", "product", "artifactDigest", "artifactSize", "packageTarget", "appDigests"}
    if (type(node) is not dict or set(node) not in (node_fields, node_fields | {"contractVersion"})
            or node["role"] not in soak.ROLES or node["product"] != "cryptad"
            or node["packageTarget"] != "linux-x64" or not soak.COMMIT.fullmatch(str(node["sourceCommit"]))
            or not soak.DIGEST.fullmatch(str(node["artifactDigest"]))
            or type(node["artifactSize"]) is not int or not 1 <= node["artifactSize"] <= PRODUCT_BYTES
            or type(node["appDigests"]) is not list or len(node["appDigests"]) > 64
            or len(set(node["appDigests"])) != len(node["appDigests"])
            or any(not isinstance(value, str) or not soak.DIGEST.fullmatch(value) for value in node["appDigests"])):
        raise ValueError("product-node-fields")
    def original(key, name, family):
        coordinates = validate_coordinates(selection[key])
        data = payloads[name]
        if (coordinates["sourceFamily"] != family or coordinates["artifactSize"] != len(data)
                or coordinates["artifactDigest"] != "sha256:" + hashlib.sha256(data).hexdigest()):
            raise ValueError("product-original-byte-binding")
        with owner._members(data) as archive:
            if sum(row.file_size for row in archive.infolist()) > PRODUCT_BYTES:
                raise ValueError("product-expanded-budget")
            semantic_members = {owner.ga.RC_FREEZE_FILE, owner.maintenance.CANDIDATE_FREEZE_FILE, "handoff.json"}
            for row in archive.infolist():
                if Path(row.filename).name in semantic_members:
                    if row.file_size > MAX_BYTES:
                        raise ValueError("product-json-budget")
                    _json(archive.read(row))
        # OriginalArtifact is the owner's passive bytes+coordinates carrier, not an
        # authenticated capability. Its verifier explicitly leaves provenance to the caller.
        return OriginalArtifact(data, coordinates)
    with tempfile.TemporaryDirectory(prefix="product-byte-verify-", dir=scratch) as temporary:
        root = Path(temporary)
        if adapter == "product-admission":
            selected = original("original", "product.zip", "stable-maintenance-freeze")
            row = owner.verify_maintenance_artifact(selected, node, selection["freezeDigest"], root / "selected")
            if dt.datetime.fromisoformat(row["freezeCompletedAt"]) > now:
                raise ValueError("product-freeze-after-evaluation")
            blockers = ["product-original-producer-unverified"]
        else:
            if type(node.get("contractVersion")) is not int or node["contractVersion"] < 1:
                raise ValueError("product-contract-version-required")
            selected = original("rcOriginal", "rc.zip", "stable-rc-product")
            portable = original("portableOriginal", "portable.zip", "first-party-release")
            rc = owner.verify_rc_artifact(selected, root / "rc")
            view = SimpleNamespace(**rc.__dict__, _original_coordinates=selected.coordinates)
            row = owner.verify_portable_artifact(portable, view, node, root / "portable.tar.gz")
            blockers = ["product-original-producer-unverified", "rc-portable-post-freeze-binding-not-established"]
    runtime_bound = bool(row.get("runtimeBinding"))
    if node["appDigests"] and not runtime_bound:
        blockers.append("product-app-api-cohort-binding-incomplete")
    result = _result(claims=("p12-300-products",), blockers=blockers,
                     required=("exact-portable-product", "frozen-api-app-cohort", "original-product-producer"),
                     observed=("exact-portable-product",) + (("frozen-api-app-cohort",) if runtime_bound else ()), implementation="partial",
                     evidence_class="original-product-byte-consistency")
    result["subjectBindings"] = {"commit": row["sourceCommit"], "digest": row["artifactDigest"], "build": str(row["buildVersion"])}
    result["productBinding"] = {"role": node["role"], "commit": row["sourceCommit"], "digest": row["artifactDigest"],
                                "appDigests": node["appDigests"], "contractVersion": node.get("contractVersion"),
                                "appContractAuthentication": "frozen-byte-consistency" if runtime_bound else "not-established"}
    if runtime_bound:
        result["runtimeBinding"] = row["runtimeBinding"]
    return result


def _migration(values):
    record = values["observation.json"]
    if record.get("schemaVersion") == 2:
        _protected("sharesite_observation").validate_observation(record, require_producer=True)
    summary = migration.summarize(record, "closeout")
    # Neither a valid summary nor original authentication turns synthetic/private observations
    # into independent real-user confirmation, or turns saving a draft into network publication.
    result = _result(claims=("p12-297-conversion", "p12-297-recovery"),
                     blockers=("migration-original-producer-unverified", "migration-real-user-not-observed",
                               "migration-publication-not-observed"),
                     required=migration.CHECKS, evidence_class=record["classification"],
                     implementation="partial")
    if any(value == "fail" for value in record["outcomes"].values()):
        result["blockers"].append("migration-required-case-failed")
        result["dimensions"]["localVerification"] = "executed-fail"
    if any(value != "pass" for key, value in record["outcomes"].items() if key != "newChkPublication"):
        result["blockers"].append("migration-required-cases-missing")
    if summary["runtimeObservation"] != "not-authenticated":
        raise ValueError("phase12-runtime-unexpected-authority")
    result["dimensions"].update(publication="not-observed", independentReview="not-observed")
    result["testEvidence"] = "author-reported"
    result["subjectBindings"] = {"digest": (record["bundleDigest"] if record["schemaVersion"] == 2
                                            else record["target"]["bundleDigest"])}
    return result


def _profile_review(payloads, values, scratch, now):
    policy = _policy()
    review = dict(values["review.json"])
    seal = review.pop("integrityDigest", None)
    if (validate_schema(review, "content-profile-review-v1.schema.json")
            or seal != profiles.semantic_digest(review)
            or dt.datetime.fromisoformat(review["evaluationTime"]) > now):
        raise ValueError("phase12-runtime-profile-summary-invalid")
    # Stage only finite policy-owned raw result locations. This does not execute tests, Gradle,
    # a registry exporter, Node, or commands found in either the report or XML.
    with tempfile.TemporaryDirectory(prefix="profile-verify-", dir=scratch) as temporary:
        stage = Path(temporary)
        for suite in policy["suites"]:
            target = stage / suite["resultFile"]
            target.parent.mkdir(parents=True, exist_ok=True)
            raw = payloads[Path(suite["resultFile"]).name]
            if b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
                raise ValueError("phase12-runtime-xml-entity-denied")
            target.write_bytes(raw)
        results = profiles.test_results(stage, policy["suites"])
        manifest = stage / profiles.CORPUS / "manifest.json"
        manifest.parent.mkdir(parents=True)
        manifest.write_bytes((ROOT / profiles.CORPUS / "manifest.json").read_bytes())
        javascript = stage / "javascript-results.json"
        javascript.write_bytes(payloads["javascript-results.json"])
        js = profiles.javascript_results(stage, javascript, policy)
    expected = {
        "source": profiles.source_identity(ROOT), "corpus": profiles.corpus_identity(ROOT),
        "policyDigest": profiles.digest(ROOT / profiles.POLICY),
        "registryExactFileDigest": "sha256:" + hashlib.sha256(payloads["registry.json"]).hexdigest(),
        "profiles": profiles.registry_rows(values["registry.json"], policy),
        "normativeSpecDigest": profiles.specification_digest(ROOT),
        "serviceDefinitionDigest": profiles.service_definition_digest(ROOT),
        "serviceContracts": policy["serviceContracts"], "results": results, "javascript": js,
        "evidenceLevel": "local-executable-conformance", "reviewDecision": "retain-current-statuses",
        "independentImplementation": "not-observed", "priorRuntime": "not-observed",
        "humanSecuritySignoff": "not-observed", "operationalCloseout": "not-assessed",
        "evaluationTime": policy["evaluationTime"], "limitations": policy["limitations"], "redaction": "pass",
    }
    if any(review[key] != value for key, value in expected.items()):
        raise ValueError("phase12-runtime-profile-source-or-results-drift")
    result = _result(claims=("p12-298-review",),
                     blockers=("profile-original-test-producer-unverified", "profile-historical-directions-missing",
                               "profile-independent-implementation-not-observed", "profile-security-review-not-observed"),
                     required=("exact-v1-retention-review", "complete-declared-test-results"),
                     observed=("exact-v1-retention-review", "complete-declared-test-results"),
                     evidence_class="retained-local-conformance")
    result["testEvidence"] = "author-reported"
    result["subjectBindings"] = {"commit": review["source"]["commit"]}
    # Retaining the exact v1 maturity policy is independently decidable. Historical runtime,
    # external interoperability and human security review have their own mandatory rows.
    result["claimResults"] = {"p12-298-review": {
        "dimensions": {"localVerification": "executed-pass", "coverage": "complete"},
        "coverage": result["coverage"], "blockers": []}}
    return result


def _measured(values, now, *, mail=False, measurements=False):
    plan, events, checkpoint = (values[name] for name in ("plan.json", "events.json", "checkpoint.json"))
    checked = soak.verify(plan, events, checkpoint, now=now)
    prefix = "mail-" if mail else ""
    required = sorted(key for key in checked["caseSamples"] if key.startswith(prefix))
    # Actual measurement consistency does not authenticate the producer. Offline clock fixtures
    # therefore contribute no observed runtime cases or hours to the Phase 12 assessment.
    result = _result(claims=(("p12-299-delivery", "p12-299-privacy-review") if mail else ("p12-300-72h",)),
                     required=required, blockers=("original-supervisor-not-authenticated",),
                     evidence_class=plan["profile"], implementation="partial",
                     verification="executed-pass" if not checked["findings"] else "executed-fail")
    if checked["findings"]:
        result["blockers"].append("measured-required-coverage-or-integrity-incomplete")
    if plan["profile"] != "protected-long-live":
        result["blockers"].append("qualifying-72h-protected-profile-required")
    if checked["observedEligibleSeconds"] < 72 * 3600:
        result["blockers"].append("qualifying-72h-continuous-coverage-missing")
    result["dimensions"]["cleanup"] = "not-observed"
    result["measurements"] = {"locallyVerifiedEligibleSeconds": checked["observedEligibleSeconds"],
                              "authenticatedObservedSeconds": 0,
                              "missingRequiredCaseCount": len(checked["missingCases"])}
    candidate = next(row for row in plan["nodes"] if row["role"] == "candidate-sender")
    result["subjectBindings"] = {"commit": candidate["sourceCommit"], "digest": candidate["artifactDigest"]}
    if events:
        result["observedAt"] = events[-1]["wallTime"]
    result["requiredSubjects"] = [{"role": node["role"], "commit": node["sourceCommit"],
                                   "digest": node["artifactDigest"], "appDigests": node["appDigests"],
                                   "contractVersion": node["contractVersion"]} for node in plan["nodes"]]
    if mail:
        result["blockers"].extend(("mail-rotation-and-resume-unimplemented", "mail-independent-review-not-observed"))
    if measurements:
        owner = _protected("maintenance_runtime_projection")
        measured = owner.project(plan, events, checkpoint, values["products.json"], now=now)
        owner.validate(measured)
        result["claims"] = ["p12-300-consumers"]
        result["coverage"] = {"required": sorted(row["id"] for row in measured["rows"]), "observed": []}
        result["blockers"].append("maintenance-required-consumer-adapters-incomplete")
        if measured["schemaVersion"] == 2:
            result["components"] = {"subjectAdmission": measured["subjectAdmission"]["status"],
                                    "measurementDerivation": measured["measurementDerivation"]["status"],
                                    "originalAuthentication": "unverified",
                                    "maintenanceEligibility": measured["maintenanceEligibility"]}
            result["measurements"]["consumerComponents"] = dict(result["components"])
    return result


def verify(adapter: str, payloads: dict[str, bytes], as_of: str, scratch: Path) -> dict:
    """Execute a finite owner consumer and return fixed, safe diagnostics and scoped claims.

    Missing selection is handled by the assessment layer; a supplied incomplete or malformed
    bundle is invalid. Original provenance, recorded runtime and independent review never become
    authenticated merely because this local semantic verifier succeeds.
    """
    try:
        if adapter not in REQUIRED_INPUTS or set(payloads) != set(REQUIRED_INPUTS[adapter]):
            raise ValueError("input-cohort")
        product = adapter in {"product-admission", "rc-product-admission"}
        maximum = PRODUCT_BYTES if product else MAX_BYTES
        if (any(type(raw) is not bytes or len(raw) > maximum for raw in payloads.values())
                or sum(len(raw) for raw in payloads.values()) > (2 * PRODUCT_BYTES if product else 64 * 1024 * 1024)):
            raise ValueError("input-size")
        scratch = Path(scratch).absolute()
        if (not scratch.is_dir() or scratch.is_symlink()
                or any(parent.is_symlink() for parent in scratch.parents)):
            raise ValueError("scratch-invalid")
        now = dt.datetime.fromisoformat(as_of)
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("clock-invalid")
        values = {name: _json(raw) for name, raw in payloads.items() if name.endswith(".json")}
        if product:
            result = _product(adapter, values, payloads, scratch, now)
        elif adapter == "api-compatibility":
            result = _api_compatibility(values, payloads, scratch, now)
        elif adapter == "api-subjects-v2":
            result = _api_subjects(values, payloads, now)
        elif adapter == "migration-observation":
            result = _migration(values)
        elif adapter == "profile-review":
            result = _profile_review(payloads, values, scratch, now)
        elif adapter == "maintenance-drill":
            record = values["drill.json"]
            drill.verify(record)
            closed = drill.closeout(record)
            result = _result(claims=("p12-301-drill",), required=drill.CASES,
                             blockers=tuple(drill.MISSING) + ("maintenance-local-producer-unverified",),
                             implementation=closed["implementationCoverage"],
                             evidence_class="synthetic-isolated-rehearsal")
            result["dimensions"].update(publication="not-performed", activation="not-performed", cleanup="not-observed")
            result["testEvidence"] = "author-reported" if record["status"] == "executed" else "not-run"
            result["subjectBindings"] = {"commit": record["checkoutIdentity"]["commit"],
                                         "tree": record["checkoutIdentity"]["committedTree"]}
            if record["status"] == "failed":
                result["dimensions"]["localVerification"] = "executed-fail"
        else:
            result = _measured(values, now, mail=adapter == "mail-runtime",
                               measurements=adapter == "maintenance-measurements")
        result["blockers"] = sorted(set(result["blockers"]))
        return result
    except (ValueError, KeyError, TypeError, OSError, OverflowError, RecursionError, ImportError, zipfile.BadZipFile):
        # Never expose assertion text, XML payloads, private names, paths or arbitrary fields.
        raise ValueError("phase12-runtime-owner-verification-rejected") from None


_ORIGINAL_SUPERVISOR = object()


class _AuthenticatedSupervisor:
    """Immutable result of the existing original-report verifier and bounded lineage reads."""
    def __init__(self, reports, authority=None):
        if authority is not _ORIGINAL_SUPERVISOR:
            raise ValueError("phase12-runtime-original-supervisor-required")
        self._reports = json.dumps(reports, sort_keys=True, separators=(",", ":"))

    def reports(self):
        return json.loads(self._reports)


def _supervisor_relationships(authority, values, now):
    if not isinstance(authority, _AuthenticatedSupervisor):
        raise ValueError("phase12-runtime-original-supervisor-required")
    chain = authority.reports()
    if not 3 <= len(chain) <= 16:
        raise ValueError("phase12-runtime-supervisor-lineage-size")
    owner = _protected("cross_version_supervisor_authority")
    plan, events, checkpoint = (values[name] for name in ("plan.json", "events.json", "checkpoint.json"))
    observation = soak.verify(plan, events, checkpoint, now=now)
    for index, row in enumerate(chain):
        report = owner.validate_report(row["report"])
        if (report["planDigest"] != soak.digest(plan) or report["producer"] != plan["producer"]
                or report["experimentId"] != plan["experimentId"]):
            raise ValueError("phase12-runtime-supervisor-subject-substituted")
        if index + 1 < len(chain):
            previous = chain[index + 1]
            if (report["previousOrigin"] != previous["origin"]
                    or report["previousReportDigest"] != soak.digest(previous["report"])
                    or report["selectionDigest"] != previous["report"]["selectionDigest"]):
                raise ValueError("phase12-runtime-supervisor-predecessor-substituted")
        if "checkpoint" in report:
            prefix = report["checkpoint"]
            sequence = prefix["sequence"]
            if (type(sequence) is not int or not 1 <= sequence <= len(events)
                    or prefix["tailDigest"] != soak.digest(events[sequence - 1])):
                raise ValueError("phase12-runtime-supervisor-journal-prefix-substituted")
    final, start, authorization = chain[0]["report"], chain[-2]["report"], chain[-1]["report"]
    if (final["operation"] != "finish" or final["serviceState"] != "stopped"
            or start["operation"] != "start" or authorization["operation"] != "authorize"
            or authorization["plan"] != plan
            or any(row["report"]["operation"] != "checkpoint" for row in chain[1:-2])
            or final["observation"] != observation
            or final["checkpoint"] != {"sequence": checkpoint["sequence"], "tailDigest": checkpoint["tailDigest"],
                                       "digest": soak.digest(checkpoint), "status": checkpoint["status"]}):
        raise ValueError("phase12-runtime-supervisor-observation-substituted")
    for row in chain[:-1]:
        report = row["report"]
        if (report["approvalOrigin"] != chain[-1]["origin"]
                or report["approvalReportDigest"] != soak.digest(authorization)):
            raise ValueError("phase12-runtime-supervisor-approval-substituted")
        if final["schemaVersion"] == 3 and (
                report["schemaVersion"] != 3
                or report["admittedProductsDigest"] != final["admittedProductsDigest"]):
            raise ValueError("phase12-runtime-supervisor-products-substituted")
    return final, observation


def verify_authenticated(adapter, payloads, as_of, scratch, authority):
    """Reuse actual owner capabilities after explicit collection; JSON flags are rejected.

    This function accepts no proof labels or signing root. Projection and migration authority
    objects can be issued only by their original owner helpers. Supervisor lineage is issued
    internally only after those same original producer/attestation verifiers complete.
    """
    result = verify(adapter, payloads, as_of, scratch)
    try:
        values = {name: _json(raw) for name, raw in payloads.items() if name.endswith(".json")}
        claim_results = {}
        if adapter == "api-subjects-v2":
            owner = _protected("app_subject_projection")
            inventory = values["app-subject-inventory.json"]
            if (not isinstance(authority, owner.AuthenticatedProjection) or not authority.matches(inventory)
                    or authority.digest != "sha256:" + hashlib.sha256(payloads["app-subject-inventory.json"]).hexdigest()
                    or api._app_subject_inventory_errors(inventory, False, values["execution-contract.json"],
                                                        api._policy(ROOT)[0], authority)):
                raise ValueError("projection-authority-mismatch")
            result["blockers"].remove("original-protected-projection-required")
            result["dimensions"].update(originalProvenance="authenticated", runtimeExecution="observed",
                                         coverage="complete" if not result["blockers"] else "partial")
            result["coverage"]["observed"] = result["coverage"]["required"] if not result["blockers"] else result["coverage"]["observed"]
        elif adapter == "migration-observation":
            owner = _protected("sharesite_observation")
            record = values["observation.json"]
            if not isinstance(authority, owner.AuthenticatedMigration) or not authority.matches(record):
                raise ValueError("migration-authority-mismatch")
            # Receipt v2 has no observation clock. Only the original owner capability may
            # supply the selected job/artifact timing; caller selection clocks cannot fill it.
            completed, uploaded = authority.execution_times
            if completed is None or uploaded is None:
                result["blockers"].append("migration-original-execution-time-unavailable")
                return result
            completion, upload, cutoff = (dt.datetime.fromisoformat(stamp) for stamp in (completed, uploaded, as_of))
            if (any(stamp.tzinfo is None for stamp in (completion, upload, cutoff))
                    or upload > completion or completion > cutoff):
                raise ValueError("migration-original-execution-after-cutoff-or-invalid")
            summary = migration.summarize(record, "closeout", authenticated_runtime=authority)
            if summary["runtimeObservation"] == "not-authenticated":
                raise ValueError("migration-owner-not-admitted")
            observed = sorted(case for case, verdict in record["outcomes"].items() if verdict == "pass")
            complete = all(record["outcomes"][case] == "pass" for case in migration.CHECKS - {"newChkPublication"})
            result["claims"] = ["p12-297-conversion", "p12-297-recovery"]
            if record["classification"] == "operator-owned-private-observation":
                result["claims"].append("p12-297-private")
            for claim in result["claims"]:
                claim_results[claim] = {
                    "dimensions": {"originalProvenance": "authenticated", "runtimeExecution": "observed" if complete else "partial",
                                   "coverage": "complete" if complete else "partial",
                                   "cleanup": "complete" if record["outcomes"]["cleanup"] == "pass" else "not-observed"},
                    "blockers": [] if complete else ["migration-required-cases-missing"],
                    "coverage": {"required": sorted(migration.CHECKS - {"newChkPublication"}), "observed": observed}}
            result["dimensions"]["originalProvenance"] = "authenticated"
            result["blockers"].remove("migration-original-producer-unverified")
        elif adapter in {"measured-soak", "mail-runtime", "maintenance-measurements"}:
            now = dt.datetime.fromisoformat(as_of)
            final, observation = _supervisor_relationships(authority, values, now)
            plan = values["plan.json"]
            qualifying = (not observation["findings"] and plan["profile"] == "protected-long-live"
                          and plan["provenanceClass"] == "production-artifact-comparison"
                          and observation["observedEligibleSeconds"] >= 72 * 3600)
            result["dimensions"].update(originalProvenance="authenticated", runtimeExecution="observed" if qualifying else "partial",
                                         coverage="complete" if qualifying else "partial",
                                         cleanup="complete" if observation["cleanup"] == "observed" else "not-observed")
            result["blockers"].remove("original-supervisor-not-authenticated")
            result["coverage"]["observed"] = sorted(case for case in result["coverage"]["required"]
                                                     if observation["caseSamples"].get(case, 0))
            result["measurements"]["authenticatedObservedSeconds"] = observation["observedEligibleSeconds"] if qualifying else 0
            if adapter == "maintenance-measurements":
                owner = _protected("maintenance_runtime_projection")
                original = final["maintenanceMeasurements"]
                evaluated = (dt.datetime.fromisoformat(original["evaluationCutoff"])
                             if original["schemaVersion"] == 2 else now)
                if evaluated > now:
                    raise ValueError("maintenance-measurements-future-evaluation")
                measured = owner.project(plan, values["events.json"], values["checkpoint.json"], values["products.json"], now=evaluated)
                if final.get("schemaVersion") not in {2, 3} or measured != original:
                    raise ValueError("maintenance-measurements-substituted")
                if original["schemaVersion"] == 2:
                    if (final["schemaVersion"] != 3
                            or final["admittedProductsDigest"] != soak.digest(values["products.json"])):
                        raise ValueError("maintenance-measurements-products-substituted")
                    result["components"]["originalAuthentication"] = "authenticated"
                    result["measurements"]["consumerComponents"] = dict(result["components"])
                result["dimensions"].update(runtimeExecution="partial", coverage="partial")
        else:
            raise ValueError("authenticated-owner-mode-unavailable")
        result["claimResults"] = claim_results
        return result
    except (ValueError, KeyError, TypeError, OSError, OverflowError, ImportError):
        raise ValueError("phase12-runtime-original-admission-rejected") from None


ORIGINAL_MEMBERS = {
    "product-admission": {"product.zip": "original-maintenance-archive"},
    "rc-product-admission": {"rc.zip": "original-rc-archive", "portable.zip": "original-portable-archive"},
    "api-subjects-v2": {"app-subject-inventory.json": "platform-api-1.x-app-subject-inventory.json"},
    "migration-observation": {"observation.json": "sharesite-runtime-observation.json"},
    "measured-soak": {"supervisor-report": "cross-version-supervisor.json"},
    "mail-runtime": {"supervisor-report": "cross-version-supervisor.json"},
    "maintenance-measurements": {"supervisor-report": "cross-version-supervisor.json"},
}


def validate_proof(adapter, proof, payloads):
    """Check closed original coordinates offline; retained JSON provides no authentication."""
    if proof is None:
        return {"state": "not-supplied", "scope": "none", "blockers": ["original-proof-missing"]}
    try:
        if (adapter not in ORIGINAL_MEMBERS or type(proof) is not dict
                or set(proof) != {"coordinates", "members"} or proof["members"] != ORIGINAL_MEMBERS[adapter]
                or set(payloads) != set(REQUIRED_INPUTS[adapter])):
            raise ValueError("original-member-selection-invalid")
        _protected("app_subject_projection")
        from original_artifact_authentication import validate_coordinates, PRODUCERS
        coordinates = validate_coordinates(proof["coordinates"])
        family = {"api-subjects-v2": "app-subject-projection", "migration-observation": "sharesite-runtime",
                  "product-admission": "stable-maintenance-freeze", "rc-product-admission": "stable-rc-product"}.get(
            adapter, "cross-version-supervisor")
        if (coordinates["sourceFamily"] != family or coordinates["jobName"] != PRODUCERS[family][2]
                or coordinates["artifactSize"] > (PRODUCT_BYTES if adapter in {"product-admission", "rc-product-admission"} else 4 * 1024 * 1024)):
            raise ValueError("original-source-or-budget-invalid")
        if adapter in {"product-admission", "rc-product-admission"}:
            selection = _json(payloads["selection.json"])
            if coordinates != selection["original" if adapter == "product-admission" else "rcOriginal"]:
                raise ValueError("product-original-proof-substitution")
        return {"state": "unverified", "scope": "retained-original-coordinates-only",
                "blockers": ["original-producer-reauthentication-required"]}
    except (ValueError, KeyError, TypeError, OSError, ImportError):
        raise ValueError("phase12-runtime-original-proof-invalid") from None


def collect_and_verify(adapter, payloads, as_of, scratch, proof):
    """Explicit GET/attestation collection through fixed existing owners; never dispatch work."""
    local = verify(adapter, payloads, as_of, scratch)  # Reject unsafe/malformed selections before GET.
    try:
        if validate_proof(adapter, proof, payloads)["state"] != "unverified":
            raise ValueError("original-proof-required")
        _protected("app_subject_projection")
        from original_artifact_authentication import validate_coordinates
        coordinates = validate_coordinates(proof["coordinates"])
        if coordinates["artifactSize"] > (PRODUCT_BYTES if adapter in {"product-admission", "rc-product-admission"} else 4 * 1024 * 1024):
            raise ValueError("original-artifact-budget")
        values = {name: _json(raw) for name, raw in payloads.items() if name.endswith(".json")}
        with tempfile.TemporaryDirectory(prefix="runtime-original-", dir=scratch) as temporary:
            root = Path(temporary)
            if adapter in {"product-admission", "rc-product-admission"}:
                owner = _protected("cross_version_product_admission")
                selection = values["selection.json"]
                node = selection["node"]
                if adapter == "product-admission":
                    row = owner.authenticate_maintenance_product(
                        {"coordinates": coordinates, "freezeDigest": selection["freezeDigest"]}, node, root / "maintenance")
                    if row.get("runtimeBinding"):
                        metadata = _json((row["runtimeRoot"] / "runtime-subjects.json").read_bytes())
                        owner.authenticate_runtime_projection(row,
                            {"coordinates": metadata["projectionOrigin"],
                             "cohortDigest": metadata["experimentCohortDigest"]}, root)
                else:
                    rc_original = owner.authenticate_original(selection["rcOriginal"], root)
                    portable = owner.authenticate_original(selection["portableOriginal"], root)
                    if rc_original.content != payloads["rc.zip"] or portable.content != payloads["portable.zip"]:
                        raise ValueError("product-original-archive-byte-substitution")
                    rc = owner.verify_rc_artifact(rc_original, root / "rc")
                    view = SimpleNamespace(**rc.__dict__, _original_coordinates=rc_original.coordinates)
                    row = owner.verify_portable_artifact(portable, view, node, root / "portable.tar.gz")
                    owner.verify_portable_attestations(portable, row["path"], root)
                if (row["sourceCommit"] != local["subjectBindings"]["commit"]
                        or row["artifactDigest"] != local["subjectBindings"]["digest"]
                        or str(row["buildVersion"]) != local["subjectBindings"]["build"]):
                    raise ValueError("product-original-subject-substitution")
                local["dimensions"]["originalProvenance"] = "authenticated"
                local["blockers"].remove("product-original-producer-unverified")
                local["originalProof"] = {"state": "authenticated", "scope": "original-product-owner-verification",
                                          "blockers": []}
                return local
            elif adapter == "api-subjects-v2":
                owner = _protected("app_subject_projection")
                # The original member is authenticated, and the existing consumer independently
                # fixes the mandatory first-party/external cohort. This expected exact digest is
                # a selection pin, never authority for shrinking that cohort.
                authority = owner.authenticate_inventory(coordinates, root, values["app-subject-inventory.json"]["cohortDigest"])
            elif adapter == "migration-observation":
                record = values["observation.json"]
                owner = _protected("sharesite_observation")
                # The owner capability stores semantic identity. Independently enforce selected
                # original member bytes as well; serialization changes cannot borrow its proof.
                from original_artifact_authentication import authenticate_original
                from .transparency_sources import _selected_archive_member
                original = authenticate_original(coordinates, root)
                selected = {"members": ["sharesite-runtime-observation.json"],
                            "member": "sharesite-runtime-observation.json",
                            "size": len(payloads["observation.json"]),
                            "digest": "sha256:" + hashlib.sha256(payloads["observation.json"]).hexdigest()}
                if _selected_archive_member(original.content, selected) != payloads["observation.json"]:
                    raise ValueError("original-migration-byte-substitution")
                observed, authority = owner.authenticate_observation(coordinates, root, record["planDigest"], record["bundleDigest"])
                if observed != record:
                    raise ValueError("original-migration-member-substituted")
            else:
                owner = _protected("cross_version_supervisor_authority")
                chain, seen = [], set()
                for number in range(16):
                    identity = (coordinates["runId"], coordinates["runAttempt"], coordinates["artifactId"])
                    if identity in seen or coordinates["artifactSize"] > 4 * 1024 * 1024:
                        raise ValueError("original-supervisor-cycle-or-budget")
                    seen.add(identity)
                    stage = root / str(number)
                    stage.mkdir()
                    report, origin = owner.authenticate_report(coordinates, stage)
                    chain.append({"report": report, "origin": origin})
                    if report["operation"] == "authorize":
                        break
                    coordinates = validate_coordinates(report["previousOrigin"])
                else:
                    raise ValueError("original-supervisor-lineage-budget")
                authority = _AuthenticatedSupervisor(chain, _ORIGINAL_SUPERVISOR)
            result = verify_authenticated(adapter, payloads, as_of, scratch, authority)
            if adapter == "migration-observation" and "migration-original-execution-time-unavailable" in result["blockers"]:
                result["originalProof"] = {"state": "unverified", "scope": "original-migration-execution-time-unavailable",
                                          "blockers": ["migration-original-execution-time-unavailable"]}
            else:
                result["originalProof"] = {"state": "authenticated", "scope": "original-owner-capability-and-exact-selected-subject",
                                           "blockers": []}
            return result
    except (ValueError, KeyError, TypeError, OSError, OverflowError, ImportError) as error:
        if str(error) == "original-artifact-leumor-authentication-unavailable":
            # This fixed owner diagnostic means no authentication credential was available.
            # Other verification failures, including rejected attestations, remain failures.
            local["blockers"] = sorted(set(local.get("blockers", []) + ["original-producer-authentication-access-unavailable"]))
            local["originalProof"] = {"state": "unverified", "scope": "original-authentication-access-unavailable",
                                      "blockers": ["original-producer-authentication-access-unavailable"]}
            return local
        raise ValueError("phase12-runtime-original-collection-rejected") from None
