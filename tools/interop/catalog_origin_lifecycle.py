"""Fixed catalog-origin operations shared by the owned packaged runtime adapters.

This driver has no signing authority. Its private journal records intent before every mutation;
the host observer reopens installed files and provenance instead of accepting response verdicts.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import os


class LifecycleFailure(ValueError):
    """Fixed diagnostic, without node responses or private paths."""


def digest(value):
    return "sha256:" + hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                                allow_nan=False).encode()).hexdigest()


@dataclass(frozen=True)
class Subject:
    app_id: str
    catalog_id: str
    bundle_digest: str
    installed_tree_digest: str
    signed_content_digest: str
    publisher_fingerprint: str
    version: str

    def matches(self, observed):
        return observed is not None and all(observed.get(key) == value for key, value in {
            "appId": self.app_id, "catalogId": self.catalog_id, "bundleDigest": self.bundle_digest,
            "installedTreeDigest": self.installed_tree_digest,
            "signedContentDigest": self.signed_content_digest,
            "publisherFingerprint": self.publisher_fingerprint, "appVersion": self.version,
            "originSchemaVersion": 2}.items())


class Journal:
    """Private durable operation ledger; failed requests are reconciled by observed subjects."""
    def __init__(self, path: Path, selection_digest: str):
        self.path = path
        if path.is_symlink() or path.parent.is_symlink() or path.parent.stat().st_mode & 0o077:
            raise LifecycleFailure("catalog-journal-not-private")
        self.value = {"schemaVersion": 1, "selectionDigest": selection_digest, "operations": []}
        if path.exists():
            if path.stat().st_mode & 0o077 or path.stat().st_size > 1024 * 1024:
                raise LifecycleFailure("catalog-journal-not-private")
            self.value = json.loads(path.read_bytes())
            if (set(self.value) != {"schemaVersion", "selectionDigest", "operations"}
                    or self.value["schemaVersion"] != 1 or self.value["selectionDigest"] != selection_digest
                    or not isinstance(self.value["operations"], list) or len(self.value["operations"]) > 64):
                raise LifecycleFailure("catalog-journal-selection-mismatch")

    def save(self):
        temporary = self.path.with_name(self.path.name + ".pending")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(json.dumps(self.value, sort_keys=True).encode())
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            directory = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            temporary.unlink(missing_ok=True)

    def transition(self, name, before, target, observe, mutate):
        rows = self.value["operations"]
        prior = next((row for row in rows if row["operation"] == name), None)
        observed = observe()
        if prior is not None:
            if prior["target"] != target.__dict__:
                raise LifecycleFailure("catalog-transition-cohort-substituted")
            if prior["status"] == "complete":
                latest = rows[-1]
                if latest["status"] == "complete" and observed != latest["observed"]:
                    raise LifecycleFailure("catalog-resume-current-subject-mismatch")
                return prior["observed"]
            # A lost successful response may be sealed only from exact durable postconditions.
            if target.matches(observed):
                prior.update(status="complete", observed=observed, reconciled=True)
                self.save()
                return observed
            # We cannot infer whether an incomplete native transaction has recovered yet.
            raise LifecycleFailure("catalog-transition-recovery-required")
        if (before is None and observed is not None) or (before is not None and not before.matches(observed)):
            raise LifecycleFailure("catalog-transition-before-subject-mismatch")
        row = {"operation": name, "target": target.__dict__, "before": observed,
               "status": "started", "observed": None, "reconciled": False}
        rows.append(row)
        self.save()
        try:
            mutate()
        except Exception:
            # A reply can be lost after the native transaction commits. Reopen the exact subject;
            # never infer success from a transport error and never replay the mutation.
            observed = observe()
            if not target.matches(observed):
                raise
            row.update(status="complete", observed=observed, reconciled=True)
            self.save()
            return observed
        observed = observe()
        if not target.matches(observed):
            raise LifecycleFailure("catalog-transition-after-subject-mismatch")
        row.update(status="complete", observed=observed)
        self.save()
        return observed


class Driver:
    """Three pre-admitted subjects; operations and routes are fixed by this implementation."""
    def __init__(self, host, subjects, journal):
        if set(subjects) != {"initial", "update", "switch"}:
            raise LifecycleFailure("catalog-transition-cohort-incomplete")
        initial, update, switch = (subjects[key] for key in ("initial", "update", "switch"))
        if (len({item.app_id for item in subjects.values()}) != 1
                or initial.catalog_id != update.catalog_id or switch.catalog_id == initial.catalog_id
                or len({item.publisher_fingerprint for item in subjects.values()}) != 1
                or len({item.bundle_digest for item in subjects.values()}) != 3):
            raise LifecycleFailure("catalog-transition-cohort-invalid")
        self.host, self.subjects, self.journal = host, subjects, journal
        self.app = initial.app_id
        self.denials = []

    def request(self, method, path, parameters=None):
        status, value = self.host.request(method, path, parameters)
        if status not in {200, 201}:
            raise LifecycleFailure("catalog-native-operation-denied")
        return value

    def consent(self, subject, action):
        response = self.request("GET", "/api/v1/consent/" + action + "-preview",
                                {"appId": self.app, "catalogId": subject.catalog_id})["consent"]
        parameters = {"consentRequestId": response["consentRequestId"],
                      "snapshotDigest": response["snapshotDigest"]}
        self.request("POST", "/api/v1/consent/approve", parameters)
        return parameters

    def mutation(self, subject, action, extra=None):
        parameters = self.consent(subject, "install" if action == "install" else "catalog-update")
        parameters.update(extra or {})
        self.request("POST", "/api/v1/app-catalogs/" + subject.catalog_id + "/apps/" + self.app + "/" + action,
                     parameters)

    def run(self, *, include_rollback=True):
        a1, a2, b3 = (self.subjects[key] for key in ("initial", "update", "switch"))
        observe = lambda: self.host.observe(self.app)
        if self.journal.value["operations"]:
            latest = self.journal.value["operations"][-1]
            current = observe()
            if (latest["status"] == "complete" and current != latest["observed"]
                    or latest["status"] == "started" and current != latest["before"]
                    and not Subject(**latest["target"]).matches(current)):
                raise LifecycleFailure("catalog-resume-current-subject-mismatch")
        initial = self.journal.transition("install", None, a1, observe, lambda: self.mutation(a1, "install"))
        self.host.restart()
        if not a1.matches(observe()) and not any(row["operation"] == "update" for row in self.journal.value["operations"]):
            raise LifecycleFailure("catalog-origin-restart-persistence-failed")
        self.host.select_revision("update")
        update = self.journal.transition("update", a1, a2, observe, lambda: self.mutation(a2, "update"))
        self.host.select_revision("switch")
        self.host.resolve_switch_conflict()
        # Observe denial and unchanged durable state, not merely an HTTP status.
        if not any(row["operation"] == "switch" for row in self.journal.value["operations"]):
            for supplied in (None, "0" * 64):
                parameters = self.consent(b3, "catalog-update")
                if supplied is not None:
                    parameters["sourceSwitchConsent"] = supplied
                before_denial = observe()
                status, response = self.host.request("POST", "/api/v1/app-catalogs/" + b3.catalog_id + "/apps/" + self.app + "/update", parameters)
                if (status != 409 or response.get("error", {}).get("code") != "catalog_source_switch_consent_required"
                        or not a2.matches(observe())):
                    raise LifecycleFailure("catalog-source-consent-denial-failed")
                self.denials.append({"case": "missing-consent" if supplied is None else "stale-consent",
                                     "httpStatus": status, "errorCode": response["error"]["code"],
                                     "beforeOrigin": before_denial, "afterOrigin": observe()})
        def switch():
            preview = self.request("POST", "/api/v1/operator/apps/" + self.app + "/catalog-origin/switch-preview",
                                   {"targetCatalogId": b3.catalog_id})
            value = preview.get("sourceSwitch", preview.get("preview", preview))
            self.mutation(b3, "update", {"sourceSwitchConsent": value["consentDigestSha256"],
                                         "targetCatalogId": b3.catalog_id})
        self.journal.transition("switch", a2, b3, observe, switch)
        if not include_rollback:
            return self.report()
        self.host.before_rollback()
        rollback = self.journal.transition("rollback", b3, a2, observe,
            lambda: self.request("POST", "/api/v1/apps/" + self.app + "/updates/rollback"))
        if rollback != update:
            raise LifecycleFailure("catalog-rollback-origin-not-exact")
        self.host.after_rollback()
        return self.report()

    def report(self):
        return {"schemaVersion": 1, "kind": "catalog-origin-local-observation",
                "selectionDigest": self.journal.value["selectionDigest"],
                "operations": self.journal.value["operations"], "releaseEligibility": "blocked",
                "sourceSwitchDenials": self.denials,
                "evidenceClass": "synthetic-local", "dataRollback": "not-claimed"}
