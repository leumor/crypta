"""Prepare signed app products before a daemon freeze using the existing maintenance authority.

This fixed producer consumes the app packaging tasks' one-build outputs, creates two separately
signed local catalogs, and asks Java to reopen every signature and manifest. It publishes nothing,
provides no independent-build or security-review claim, and never reads a future freeze/receipt.
"""
from __future__ import annotations
import argparse
import base64
from datetime import datetime, timezone
import io
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile
from types import SimpleNamespace
from urllib.parse import urlsplit
import zipfile

from maintenance_runtime_metadata import FIRST_PARTY, RuntimeMetadataError, canonical_bytes, digest_bytes, identity, _regular
from app_subject_projection import produce
from bounded_process import run
from cryptad_certification.schema_validation import validate_schema

HANDOFF_FILE = "maintenance-app-subject-handoff.json"
JOB_NAME = "Build and authenticate prospective maintenance app products"


def _invoke(exporter: Path, args: list[str], environment: dict) -> None:
    try:
        run([str(exporter), *args], environment=environment, timeout=180, output_limit=32768)
    except ValueError:
        raise RuntimeMetadataError("maintenance-app-native-production-failed") from None


def packaged_bundle(workspace: Path, app: str) -> Path:
    """Select the sole package output; the signed manifest owns the app version."""
    directory = workspace / "apps" / app / "build/cryptad-app-bundle"
    if any(path.is_symlink() for path in (directory, *directory.parents)):
        raise RuntimeMetadataError("maintenance-app-package-path-invalid")
    if not directory.is_dir():
        raise RuntimeMetadataError("maintenance-app-package-missing")
    # A clean build must have exactly one output, never a guessed newest/stale version.
    members = list(directory.iterdir())
    if len(members) != 1 or not re.fullmatch(re.escape(app) + r"-.+\.zip", members[0].name):
        raise RuntimeMetadataError("maintenance-app-package-output-ambiguous")
    _regular(members[0], 512 * 1024 * 1024)
    return members[0]


def produce_app_products(workspace: Path, output: Path, *, release_id: str, build_version: str,
                         source_commit: str, include_mail: bool, artifact_base: str,
                         exporter: Path, java_home: Path) -> dict:
    if (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", release_id)
            or not re.fullmatch(r"[1-9][0-9]*", build_version)
            or not re.fullmatch(r"[0-9a-f]{40}", source_commit)):
        raise RuntimeMetadataError("maintenance-app-release-identity-invalid")
    uri = urlsplit(artifact_base)
    if uri.scheme != "https" or not uri.hostname or uri.username or uri.password or uri.query or uri.fragment:
        raise RuntimeMetadataError("maintenance-app-artifact-base-invalid")
    if output.exists() or output.is_symlink() or any(parent.is_symlink() for parent in output.parents):
        raise RuntimeMetadataError("maintenance-app-output-must-be-new")
    app_key_id = os.environ.get("CRYPTAD_APP_SIGNING_KEY_ID", "")
    catalog_key_id = os.environ.get("STABLE_CATALOG_SIGNING_KEY_ID", "")
    public_app = os.environ.get("CRYPTAD_APP_SIGNING_PUBLIC_KEY_BASE64", "")
    public_catalog = os.environ.get("STABLE_CATALOG_SIGNING_PUBLIC_KEY_BASE64", "")
    private_catalog = os.environ.get("STABLE_CATALOG_SIGNING_PRIVATE_KEY_BASE64", "")
    if not all((app_key_id, catalog_key_id, public_app, public_catalog, private_catalog)):
        raise RuntimeMetadataError("maintenance-app-production-signing-unavailable")
    try:
        app_public_bytes = base64.b64decode(public_app, validate=True)
        catalog_public_bytes = base64.b64decode(public_catalog, validate=True)
    except ValueError:
        raise RuntimeMetadataError("maintenance-app-public-key-encoding-invalid") from None
    if app_key_id == catalog_key_id or app_public_bytes == catalog_public_bytes:
        raise RuntimeMetadataError("maintenance-app-signing-roles-overlap")
    for key in (app_key_id, catalog_key_id):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", key):
            raise RuntimeMetadataError("maintenance-app-signing-label-invalid")
    # Private app signing inputs are consumed only by Gradle before this helper. Do not forward
    # them to Java metadata verification or retain them in a subject, registry, or receipt.
    environment = {"PATH": str(java_home / "bin") + ":/usr/bin:/bin", "JAVA_HOME": str(java_home), "LANG": "C.UTF-8"}
    output.mkdir(mode=0o700)
    generated = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    ids = sorted(FIRST_PARTY | ({"mail-prototype"} if include_mail else set()))
    try:
        with tempfile.TemporaryDirectory(prefix="app-products-", dir=output.parent) as temporary:
            private = Path(temporary)
            catalog_keys = private / "catalog-keys.properties"
            publisher_keys = private / "publisher-keys.properties"
            catalog_keys.write_text(f"trusted.keys.version=1\nkey.0.id={catalog_key_id}\nkey.0.algorithm=Ed25519\nkey.0.public.key.base64={public_catalog}\n")
            publisher_keys.write_text(f"trusted.keys.version=1\nkey.0.id={app_key_id}\nkey.0.algorithm=Ed25519\nkey.0.public.key.base64={public_app}\n")
            catalog_keys.chmod(0o600)
            publisher_keys.chmod(0o600)
            entries = {"stable": [], "experimental": []}
            (output / "apps").mkdir()
            (output / "catalogs").mkdir()
            for app in ids:
                bundle = packaged_bundle(workspace, app)
                stage = workspace / "apps" / app / "build/cryptad-app" / app
                payload = _regular(bundle, 512 * 1024 * 1024)
                (output / "apps" / f"{app}.zip").write_bytes(payload)
                group = "experimental" if app == "mail-prototype" else "stable"
                entry = private / f"{app}.properties"
                _invoke(exporter, ["catalog", "entry", "--bundle-dir", str(stage), "--artifact", str(bundle),
                    "--bundle-uri", artifact_base.rstrip("/") + f"/{app}.zip", "--output", str(entry),
                    "--summary", app, "--channel", "beta" if group == "experimental" else "stable",
                    "--support-status", "experimental" if group == "experimental" else "supported"], environment)
                entries[group].append(entry)
            for group, selected in entries.items():
                if not selected:
                    continue
                catalog = output / "catalogs" / group / "catalog.properties"
                catalog.parent.mkdir()
                arguments = ["catalog", "create", "--catalog-file", str(catalog),
                    "--catalog-id", f"maintenance-{group}", "--name", f"Maintenance {group}", "--generated-at", generated]
                for entry in selected:
                    arguments += ["--entry", str(entry)]
                _invoke(exporter, arguments, environment)
                _invoke(exporter, ["catalog", "sign", "--catalog-file", str(catalog),
                    "--key-id", catalog_key_id, "--private-key-env", "CRYPTAD_RUNTIME_CATALOG_KEY"],
                    {**environment, "CRYPTAD_RUNTIME_CATALOG_KEY": private_catalog})
            # Close the current producer's local handoff with the same Java verifier used by the
            # later authenticated projection. The original workflow attests these exact bytes.
            members = {}
            for path in sorted(output.rglob("*")):
                if path.is_file():
                    members[path.relative_to(output).as_posix()] = _regular(path, 512 * 1024 * 1024)
            content = io.BytesIO()
            with zipfile.ZipFile(content, "w") as archive:
                for name, payload in members.items():
                    archive.writestr(name, payload)
            local_artifact = SimpleNamespace(content=content.getvalue(), coordinates={})
            subjects = []
            for app in ids:
                group = "experimental" if app == "mail-prototype" else "stable"
                names = {"catalog": f"catalogs/{group}/catalog.properties", "catalogSignature": f"catalogs/{group}/cryptad-app-catalog.signature",
                         "bundle": f"apps/{app}.zip"}
                result = produce(local_artifact, names, exporter=exporter, exporter_digest=digest_bytes(_regular(exporter)),
                    app_id=app, catalog_key_id=catalog_key_id, catalog_keys=catalog_keys, publisher_keys=publisher_keys,
                    reviewer_keys=None, private_root=private, java_home=java_home)
                subjects.append({"appId": app, "members": names, "signedProjection": result["declaration"]})
            handoff = {"schemaVersion": 1, "kind": "maintenance-app-subject-handoff", "sourceCommit": source_commit,
                "releaseId": release_id, "buildVersion": build_version, "generatedAt": generated,
                "cohortPolicy": "current-eight-experimental-mail" if include_mail else "historical-seven",
                "producer": {"repository": "crypta-network/cryptad", "workflowPath": ".github/workflows/stable-1.0-maintenance-release.yml",
                    "workflowSourceCommit": os.environ["GITHUB_SHA"], "runId": int(os.environ["GITHUB_RUN_ID"]),
                    "runAttempt": int(os.environ["GITHUB_RUN_ATTEMPT"]), "jobName": JOB_NAME},
                "subjects": subjects, "members": [{"fileName": name, "digest": digest_bytes(payload), "sizeBytes": len(payload)}
                    for name, payload in sorted(members.items())]}
            if validate_schema(handoff, "maintenance-app-subject-handoff-v1.schema.json"):
                raise RuntimeMetadataError("maintenance-app-handoff-schema-invalid")
            (output / HANDOFF_FILE).write_bytes(canonical_bytes(handoff))
            return handoff
    except Exception:
        shutil.rmtree(output)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--release-id", required=True)
    parser.add_argument("--build-version", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--include-mail", action="store_true")
    parser.add_argument("--artifact-base", required=True)
    parser.add_argument("--exporter", required=True, type=Path)
    parser.add_argument("--java-home", required=True, type=Path)
    args = parser.parse_args()
    try:
        produce_app_products(args.workspace, args.output, release_id=args.release_id, build_version=args.build_version,
            source_commit=args.source_commit, include_mail=args.include_mail, artifact_base=args.artifact_base,
            exporter=args.exporter, java_home=args.java_home)
        return 0
    except (ValueError, KeyError, TypeError, OSError, zipfile.BadZipFile):
        print("maintenance-app-product-preparation-failed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
