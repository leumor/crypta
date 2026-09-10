"""Emit the protected platform builder handoff from exact local build inputs.

Invoked only after the workflow authenticates its source and phase artifact.
This helper retains the workflow's native package extraction and signing checks.
"""
import hashlib
import json
import os
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path, PurePosixPath

from cryptad_certification.schema_validation import validate_schema
from cryptad_certification.engines.stable_1_0_supply_chain_archive import (
    canonical_mode_class,
)
from cryptad_certification.engines.stable_1_0_supply_chain_core import (
    CANONICAL_BUILD_ENVIRONMENT_VARIABLES,
    builder_observation_errors,
    payload_manifest_errors,
    installer_subject_binding_errors,
    semantic_digest,
    sha256_digest,
    canonical_json_bytes,
)

workspace = Path.cwd().resolve()
phase = (workspace / "build/stable-supply-chain-phase").resolve(strict=True)
manifest = json.loads((phase / "manifest.json").read_text(encoding="utf-8"))
inventory = json.loads(
    (workspace / manifest["inputs"]["releaseSubjectInventory"]).read_text(encoding="utf-8")
)
materials = json.loads(
    (workspace / manifest["inputs"]["buildMaterials"]).read_text(encoding="utf-8")
)
raw_materials = json.loads(
    (workspace / "build/stable-supply-chain/build-material-inputs.json").read_text(
        encoding="utf-8"
    )
)
raw_jdk = raw_materials.get("jdk", {})
raw_jdk_modules = raw_jdk.get("modules")
reviewed_jdk = materials.get("jdk", {})
runner_os = os.environ["RUNNER_OS"].casefold()
reviewed_installations = [
    row for row in reviewed_jdk.get("installations", [])
    if row.get("runnerOs") == runner_os and row.get("architecture") == "amd64"
]
if (
    not isinstance(raw_jdk_modules, list)
    or not raw_jdk_modules
    or raw_jdk_modules != sorted(set(raw_jdk_modules))
    or raw_jdk_modules != reviewed_jdk.get("modules")
    or len(reviewed_installations) != 1
    or raw_jdk.get("languageVersion") != reviewed_jdk.get("version")
    or raw_jdk.get("javaRuntimeVersion") != reviewed_jdk.get("build")
    or raw_jdk.get("installationManifestDigest")
    != reviewed_installations[0].get("installationManifestDigest")
    or raw_jdk.get("releaseFileDigest")
    != reviewed_installations[0].get("releaseFileDigest")
):
    raise SystemExit("platform jlink modules differ from authenticated materials")
observation = json.loads(
    (workspace / "build/stable-supply-chain-builder-observation.json").read_text(
        encoding="utf-8"
    )
)
actual_environment = {
    name: os.environ.get(name) for name in CANONICAL_BUILD_ENVIRONMENT_VARIABLES
}
if actual_environment != observation.get("environmentVariables"):
    raise SystemExit("canonical build environment changed during the platform build")
observation_errors = builder_observation_errors(
    observation.get("java", {}),
    actual_environment,
    materials,
    os.environ["RUNNER_OS"].casefold(),
)
if observation_errors:
    raise SystemExit(observation_errors[0])
snapshot = json.loads(
    (workspace / manifest["inputs"]["resolvedDependencySnapshot"]).read_text(encoding="utf-8")
)
policy = json.loads(
    Path("tools/release-certification/stable-1.0-supply-chain-policy.json").read_text(
        encoding="utf-8"
    )
)
operation = os.environ["BUILDER_OPERATION"]
role = "candidate-producer" if operation == "producer-build" else "independent-verifier"
execution_id = os.environ["EXECUTION_ID"]
keys = os.environ["SUBJECT_KEYS"].split(",")
extension = {"linux-installers": None, "macos-installer": ".dmg", "windows-installer": ".exe"}[execution_id]
app_root = workspace / "build/jpackage" / ("Crypta.app" if execution_id == "macos-installer" else "Crypta")
if not app_root.is_dir() or app_root.is_symlink():
    raise SystemExit("jpackage pre-signing app-image payload is missing")
def canonical_entries(root: Path) -> list[dict]:
    entries = []
    casefolded = set()
    paths = sorted(root.rglob("*"), key=lambda value: value.relative_to(root).as_posix())
    bounds = policy["publicArtifactBounds"]
    if len(paths) > bounds["maximumPayloadEntries"]:
        raise SystemExit("extracted package exceeds the policy entry bound")
    expanded_bytes = 0
    for path in paths:
        relative = path.relative_to(root).as_posix()
        pure = PurePosixPath(relative)
        if pure.is_absolute() or ".." in pure.parts or relative.casefold() in casefolded:
            raise SystemExit("platform payload contains an unsafe or colliding path")
        casefolded.add(relative.casefold())
        if path.name.startswith("._") or path.name == ".DS_Store" or "__MACOSX" in pure.parts:
            raise SystemExit("platform payload contains prohibited host metadata")
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode):
            target = os.readlink(path)
            resolved = (path.parent / target).resolve()
            resolved.relative_to(root.resolve())
            entries.append({"path": relative, "kind": "symlink", "digest": None,
                            "size": 0, "modeClass": "symlink", "symlinkTarget": target})
        elif stat.S_ISDIR(mode):
            entries.append({"path": relative, "kind": "directory", "digest": None,
                            "size": 0, "modeClass": "directory", "symlinkTarget": None})
        elif stat.S_ISREG(mode):
            expanded_bytes += path.stat().st_size
            if expanded_bytes > bounds["maximumExpandedBytes"]:
                raise SystemExit("extracted package exceeds the policy expansion bound")
            data = path.read_bytes()
            entries.append({"path": relative, "kind": "file",
                            "digest": "sha256:" + hashlib.sha256(data).hexdigest(),
                            "size": len(data),
                            "modeClass": canonical_mode_class(mode),
                            "symlinkTarget": None})
        else:
            raise SystemExit("platform payload contains a special file")
    return entries

def entries_digest(entries: list[dict]) -> str:
    return "sha256:" + hashlib.sha256(
        json.dumps(entries, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()

codesign = Path("/usr/bin/codesign")
macho_magics = {
    b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",
    b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca",
}

def is_macho(path: Path) -> bool:
    with path.open("rb") as handle:
        return handle.read(4) in macho_magics

def signature_material_structure(entry: dict | None, app_prefix: str) -> str | None:
    if entry is None:
        return None
    relative = entry["path"]
    if not relative.startswith(app_prefix + "/"):
        return None
    parts = PurePosixPath(relative.removeprefix(app_prefix + "/")).parts
    if parts[-1:] == ("_CodeSignature",) and entry["kind"] == "directory":
        return "bundle-code-directory"
    if (
        parts[-2:] == ("_CodeSignature", "CodeResources")
        and entry["kind"] == "file"
    ):
        return "bundle-code-resources-file"
    if (
        parts[-1:] == ("CodeResources",)
        and entry["kind"] == "symlink"
        and entry["symlinkTarget"] == "_CodeSignature/CodeResources"
    ):
        return "legacy-code-resources-symlink"
    return None

def stripped_macho_view(source: Path, temporary: Path, label: str) -> tuple[str, int, bool]:
    if not source.is_file() or source.is_symlink() or not is_macho(source):
        raise SystemExit("macOS signature normalization received a non-Mach-O file")
    temporary.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary.chmod(0o700)
    copy = temporary / (hashlib.sha256(label.encode()).hexdigest() + ".macho")
    shutil.copyfile(source, copy)
    probe = subprocess.run(
        [str(codesign), "-dv", "--verbose=4", str(copy)],
        capture_output=True,
        text=True,
    )
    signed = probe.returncode == 0
    if not signed:
        detail = (probe.stdout + "\n" + probe.stderr).casefold()
        if "code object is not signed at all" not in detail:
            raise SystemExit("fixed codesign tool could not classify a Mach-O input")
    else:
        removed = subprocess.run(
            [str(codesign), "--remove-signature", str(copy)],
            capture_output=True,
            text=True,
        )
        if removed.returncode != 0:
            raise SystemExit("fixed codesign tool could not remove a signature from its copy")
    data = copy.read_bytes()
    return "sha256:" + hashlib.sha256(data).hexdigest(), len(data), signed

def normalized_macos_transition(
    staged_root: Path,
    embedded_root: Path,
    embedded_app: Path,
    app_prefix: str,
    staged: list[dict],
    embedded: list[dict],
    temporary: Path,
    runner_image_digest: str,
    frozen_row: dict | None,
) -> tuple[list[dict], dict]:
    if not codesign.is_file() or codesign.is_symlink():
        raise SystemExit("fixed Apple codesign tool is unavailable")
    mounted_app_signing_verified = False
    if frozen_row is not None:
        verified = subprocess.run(
            [str(codesign), "--verify", "--deep", "--strict", "--verbose=4", str(embedded_app)],
            capture_output=True,
            text=True,
        )
        if verified.returncode != 0:
            raise SystemExit("mounted frozen app fails strict codesign verification")
        mounted_app_signing_verified = True
    staged_by_path = {entry["path"]: entry for entry in staged}
    embedded_by_path = {entry["path"]: entry for entry in embedded}
    signature_material = []
    code_objects = []
    normalized_staged_by_path = {key: dict(value) for key, value in staged_by_path.items()}
    normalized_embedded_by_path = {}
    for relative in sorted(set(staged_by_path) | set(embedded_by_path)):
        staged_entry = staged_by_path.get(relative)
        embedded_entry = embedded_by_path.get(relative)
        inside_app = relative == app_prefix or relative.startswith(app_prefix + "/")
        staged_structure = signature_material_structure(staged_entry, app_prefix)
        embedded_structure = signature_material_structure(embedded_entry, app_prefix)
        mentions_code_signature = (
            inside_app and "_CodeSignature" in PurePosixPath(relative).parts
        )
        addition_or_deletion = staged_entry is None or embedded_entry is None
        if staged_structure is not None or embedded_structure is not None:
            if (
                (staged_entry is not None and staged_structure is None)
                or (embedded_entry is not None and embedded_structure is None)
                or (
                    staged_structure is not None
                    and embedded_structure is not None
                    and staged_structure != embedded_structure
                )
            ):
                raise SystemExit("macOS signature material changed to an unapproved structure")
            if staged_entry is None:
                change = "added-to-embedded"
            elif embedded_entry is None:
                change = "removed-from-embedded"
            elif staged_entry == embedded_entry:
                change = "unchanged"
            else:
                change = "changed"
            signature_material.append({
                "path": relative,
                "structure": staged_structure or embedded_structure,
                "change": change,
                "stagedDigest": None if staged_entry is None else staged_entry["digest"],
                "embeddedDigest": None if embedded_entry is None else embedded_entry["digest"],
                "stagedSize": None if staged_entry is None else staged_entry["size"],
                "embeddedSize": None if embedded_entry is None else embedded_entry["size"],
                "stagedModeClass": None if staged_entry is None else staged_entry["modeClass"],
                "embeddedModeClass": None if embedded_entry is None else embedded_entry["modeClass"],
                "stagedSymlinkTarget": (
                    None if staged_entry is None else staged_entry["symlinkTarget"]
                ),
                "embeddedSymlinkTarget": (
                    None if embedded_entry is None else embedded_entry["symlinkTarget"]
                ),
            })
            if staged_entry is not None:
                normalized_embedded_by_path[relative] = dict(staged_entry)
            continue
        if mentions_code_signature or addition_or_deletion:
            raise SystemExit("macOS payload added or removed a non-signature path")
        assert staged_entry is not None and embedded_entry is not None
        if (
            staged_entry["kind"] != embedded_entry["kind"]
            or staged_entry["modeClass"] != embedded_entry["modeClass"]
            or staged_entry["symlinkTarget"] != embedded_entry["symlinkTarget"]
        ):
            raise SystemExit("macOS non-signature payload structure differs")
        if staged_entry["kind"] != "file":
            if staged_entry != embedded_entry:
                raise SystemExit("macOS non-code payload metadata differs")
            normalized_embedded_by_path[relative] = dict(embedded_entry)
            continue
        if not inside_app:
            if staged_entry != embedded_entry:
                raise SystemExit("macOS outside-app payload bytes differ")
            normalized_embedded_by_path[relative] = dict(embedded_entry)
            continue
        staged_path = staged_root / relative
        embedded_path = embedded_root / relative
        staged_macho = is_macho(staged_path)
        embedded_macho = is_macho(embedded_path)
        if staged_macho != embedded_macho:
            raise SystemExit("macOS payload changed a non-code file into a Mach-O file")
        if not staged_macho:
            if staged_entry != embedded_entry:
                raise SystemExit("macOS non-code payload bytes differ")
            normalized_embedded_by_path[relative] = dict(embedded_entry)
            continue
        staged_digest, staged_size, staged_signed = stripped_macho_view(
            staged_path, temporary, "staged:" + relative
        )
        embedded_digest, embedded_size, embedded_signed = stripped_macho_view(
            embedded_path, temporary, "embedded:" + relative
        )
        if staged_digest != embedded_digest or staged_size != embedded_size:
            raise SystemExit("macOS Mach-O differs outside its code-signature view")
        normalized_staged_by_path[relative]["digest"] = staged_digest
        normalized_staged_by_path[relative]["size"] = staged_size
        normalized_embedded_by_path[relative] = dict(embedded_entry)
        normalized_embedded_by_path[relative]["digest"] = embedded_digest
        normalized_embedded_by_path[relative]["size"] = embedded_size
        code_objects.append({
            "path": relative,
            "stagedDigest": staged_entry["digest"],
            "embeddedDigest": embedded_entry["digest"],
            "strippedDigest": staged_digest,
            "strippedSize": staged_size,
            "stagedSigned": staged_signed,
            "embeddedSigned": embedded_signed,
            "rawBytesIdentical": staged_entry["digest"] == embedded_entry["digest"],
            "normalizedBytesIdentical": True,
        })
    normalized_staged = [normalized_staged_by_path[key] for key in sorted(normalized_staged_by_path)]
    normalized_embedded = [
        normalized_embedded_by_path[key] for key in sorted(normalized_embedded_by_path)
    ]
    if normalized_staged != normalized_embedded:
        raise SystemExit("macOS normalized pre-signing payload differs")
    code_objects.sort(key=lambda value: value["path"])
    signature_material.sort(key=lambda value: value["path"])
    if len({value["path"] for value in code_objects}) != len(code_objects):
        raise SystemExit("macOS code-signature evidence contains duplicate code-object paths")
    if len({value["path"] for value in signature_material}) != len(signature_material):
        raise SystemExit("macOS code-signature evidence contains duplicate signature paths")
    if frozen_row is not None and (not code_objects or not signature_material):
        raise SystemExit("signed macOS payload lacks explicit code-signature evidence")
    rule = next(value for value in policy["normalizationRules"] if value["id"] == "crypta-dmg-payload-v2")
    expected_contract = {
        "bindingMethod": "macos-code-signature-normalized",
        "tool": "apple-system-codesign",
        "copyOnlySignatureRemoval": True,
        "releaseBytesMutable": False,
        "strictMountedAppVerification": True,
        "signatureResourceStructures": [
            "bundle-code-directory",
            "bundle-code-resources-file",
            "legacy-code-resources-symlink",
        ],
    }
    if rule.get("codeSignatureNormalization") != expected_contract or rule.get("ignoredPaths") != []:
        raise SystemExit("DMG normalization policy is not the closed code-signature contract")
    normalized_digest = entries_digest(normalized_staged)
    evidence = {
        "normalizationRuleId": rule["id"],
        "normalizationRuleVersion": rule["version"],
        "codesignTool": {
            "name": "apple-system-codesign",
            "executableDigest": "sha256:" + hashlib.sha256(codesign.read_bytes()).hexdigest(),
            "runnerImageDigest": runner_image_digest,
        },
        "mountedAppSigningVerified": mounted_app_signing_verified,
        "releaseBytesUnmodified": True,
        "nonCodeEntriesIdentical": True,
        "signatureMaterialAccounted": True,
        "frozenSubjectDigest": None if frozen_row is None else frozen_row["digest"],
        "frozenSigningReceiptDigest": (
            None if frozen_row is None else frozen_row["signingReceiptDigest"]
        ),
        "frozenNotarizationReceiptDigest": (
            None if frozen_row is None else frozen_row["notarizationReceiptDigest"]
        ),
        "normalizedStagedPayloadDigest": normalized_digest,
        "normalizedEmbeddedPayloadDigest": normalized_digest,
        "codeObjects": code_objects,
        "signatureMaterial": signature_material,
    }
    return normalized_staged, evidence

staged_entries = canonical_entries(app_root)

def command_version(command: list[str]) -> str:
    result = subprocess.run(command, check=True, capture_output=True, text=True)
    value = (result.stdout + result.stderr).strip().splitlines()
    if not value:
        raise SystemExit("package extraction tool version is unavailable")
    return value[0][:256]

def matching_payload_root(extracted: Path) -> Path:
    matches = []
    candidates = [extracted] + [
        path for path in extracted.rglob("*") if path.is_dir() and not path.is_symlink()
    ]
    for candidate in candidates:
        try:
            if canonical_entries(candidate) == staged_entries:
                matches.append(candidate)
        except (OSError, ValueError):
            continue
    if len(matches) != 1:
        raise SystemExit("published package extraction does not contain exactly the staged payload")
    return matches[0]

def mounted_macos_app_root(extracted: Path) -> Path:
    candidates = [
        path for path in extracted.rglob(app_root.name)
        if path.name == app_root.name and path.is_dir() and not path.is_symlink()
    ]
    if len(candidates) != 1:
        raise SystemExit("frozen DMG does not contain exactly one expected app bundle")
    candidate = candidates[0].resolve(strict=True)
    candidate.relative_to(extracted.resolve(strict=True))
    return candidate

def extract_published_package(source: Path, package_type: str, temporary: Path) -> tuple[Path, str, str, callable]:
    if source.stat().st_size > policy["publicArtifactBounds"]["maximumArtifactBytes"]:
        raise SystemExit("published package exceeds the policy artifact bound")
    extracted = temporary / "extracted"
    extracted.mkdir()
    cleanup = lambda: None
    if package_type == "deb":
        subprocess.run(["dpkg-deb", "--extract", str(source), str(extracted)], check=True)
        return extracted, "dpkg-deb", command_version(["dpkg-deb", "--version"]), cleanup
    if package_type == "rpm":
        rpm = subprocess.Popen(["rpm2cpio", str(source)], stdout=subprocess.PIPE)
        assert rpm.stdout is not None
        cpio = subprocess.run(
            ["cpio", "--extract", "--make-directories", "--no-absolute-filenames"],
            cwd=extracted, stdin=rpm.stdout, check=True, capture_output=True,
        )
        rpm.stdout.close()
        if rpm.wait() != 0 or cpio.returncode != 0:
            raise SystemExit("RPM extraction failed")
        version = command_version(["rpm", "--version"]) + "; " + command_version(["cpio", "--version"])
        return extracted, "rpm2cpio-cpio", version[:256], cleanup
    if package_type == "dmg":
        mount = temporary / "mount"
        mount.mkdir()
        subprocess.run(
            ["hdiutil", "attach", "-readonly", "-nobrowse", "-mountpoint", str(mount), str(source)],
            check=True, capture_output=True,
        )
        cleanup = lambda: subprocess.run(
            ["hdiutil", "detach", str(mount)], check=True, capture_output=True
        )
        return mount, "hdiutil", command_version(["sw_vers", "-productVersion"]), cleanup
    if package_type == "exe":
        subprocess.run(["7z", "x", "-y", f"-o{extracted}", str(source)], check=True, capture_output=True)
        msi_files = sorted(extracted.rglob("*.msi"))
        if len(msi_files) != 1:
            raise SystemExit("Windows installer extraction did not expose exactly one MSI payload")
        administrative = temporary / "administrative"
        administrative.mkdir()
        subprocess.run(
            ["msiexec.exe", "/a", str(msi_files[0]), "/qn", f"TARGETDIR={administrative}"],
            check=True,
        )
        version = command_version(["7z"]) + "; windows-msiexec"
        return administrative, "7zip-msiexec", version[:256], cleanup
    raise SystemExit("unsupported normalized package extraction type")
out = workspace / "build/stable-supply-chain-platform-handoff" / execution_id
(out / "subjects").mkdir(parents=True)
(out / "payload-manifests").mkdir()
(out / "extraction-evidence").mkdir()
rows_by_key = {row["subjectKey"]: row for row in inventory["subjects"]}
keys = [key for key in keys if key in rows_by_key]
freeze_rows = {}
frozen_root = None
if role == "candidate-producer":
    freeze_root = workspace / "build/stable-supply-chain-frozen-candidate/freeze"
    freeze = json.loads(
        (freeze_root / "stable-1.0-maintenance-candidate-freeze.json").read_text(
            encoding="utf-8"
        )
    )
    freeze_rows = {row["fileName"]: row for row in freeze["assets"]}
    frozen_root = (freeze_root / "assets").resolve(strict=True)
emitted = []
for key in keys:
    row = rows_by_key[key]
    package_extension = "." + key.rsplit(".", 1)[-1]
    package_type = package_extension.removeprefix(".")
    release_rule = next(
        value for value in policy["releaseSubjects"] if value["subjectKey"] == key
    )
    normalization_rule = next(
        value for value in policy["normalizationRules"]
        if value["id"] == release_rule["normalizationRuleId"]
    )
    candidates = sorted((workspace / "build/jpackage").glob("*" + package_extension))
    if len(candidates) != 1:
        raise SystemExit(f"platform build did not emit exactly one {package_extension}")
    built = candidates[0]
    source = built
    frozen_row = None
    if role == "candidate-producer":
        assert frozen_root is not None
        frozen_row = freeze_rows.get(Path(row["fileName"]).name)
        if frozen_row is None:
            raise SystemExit(f"selected package is absent from the maintenance freeze: {key}")
        if (
            frozen_row["digest"] != row["digest"]
            or frozen_row["sizeBytes"] != row["size"]
            or frozen_row["signingReceiptDigest"] != row["signatureReceiptDigest"]
            or frozen_row["notarizationReceiptDigest"] != row["notarizationReceiptDigest"]
        ):
            raise SystemExit(f"frozen package and authenticated inventory differ for {key}")
        source = (frozen_root / frozen_row["fileName"]).resolve(strict=True)
        source.relative_to(frozen_root)
        if source.is_symlink() or not source.is_file():
            raise SystemExit(f"frozen candidate omits exact package {key}")
        if package_type == "dmg" and (
            frozen_row.get("signingStatus") != "pass"
            or frozen_row.get("notarizationStatus") != "pass"
            or frozen_row.get("notarizationReceiptDigest") is None
        ):
            raise SystemExit("frozen DMG lacks exact signing and notarization bindings")
    destination = out / "subjects" / row["fileName"]
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    published = destination.read_bytes()
    published_digest = "sha256:" + hashlib.sha256(published).hexdigest()
    binding_errors = installer_subject_binding_errors(
        role, published_digest, len(published), row
    )
    if binding_errors:
        raise SystemExit(f"{key}: {binding_errors[0]}")
    component_ids = row["componentIds"]
    runner_image = os.environ.get("ImageOS", "") + "@" + os.environ.get("ImageVersion", "")
    runner_image_digest = "sha256:" + hashlib.sha256(runner_image.encode()).hexdigest()
    binding_method = "exact-staged-payload"
    normalization_evidence = None
    staged_payload_contained_exactly = True
    with tempfile.TemporaryDirectory(prefix="cryptad-package-extraction-") as temporary:
        temporary_root = Path(temporary)
        published_temporary = temporary_root / "published"
        published_temporary.mkdir(mode=0o700)
        extraction_root, extraction_tool, extraction_version, cleanup = extract_published_package(
            destination, package_type, published_temporary
        )
        cleanups = [cleanup]
        try:
            if package_type == "dmg":
                published_app = mounted_macos_app_root(extraction_root)
                published_app_entries = canonical_entries(published_app)
                extracted_entries = canonical_entries(extraction_root)
                published_prefix = published_app.relative_to(extraction_root).as_posix()
                if role == "candidate-producer":
                    if frozen_row is None:
                        raise SystemExit(
                            "DMG normalization lacks its authenticated freeze row"
                        )
                    local_temporary = temporary_root / "locally-built"
                    local_temporary.mkdir(mode=0o700)
                    local_root, local_tool, local_version, local_cleanup = extract_published_package(
                        built, package_type, local_temporary
                    )
                    cleanups.append(local_cleanup)
                    if local_tool != extraction_tool or local_version != extraction_version:
                        raise SystemExit("local and frozen DMGs used different extraction tools")
                    local_app = mounted_macos_app_root(local_root)
                    if canonical_entries(local_app) != staged_entries:
                        raise SystemExit(
                            "locally built DMG does not contain its exact unsigned staged app"
                        )
                    local_prefix = local_app.relative_to(local_root).as_posix()
                    if local_prefix != published_prefix:
                        raise SystemExit("local and frozen DMGs contain different app paths")
                    staged_comparison_entries = canonical_entries(local_root)
                    embedded_entries = extracted_entries
                    if staged_comparison_entries == embedded_entries:
                        raise SystemExit(
                            "frozen signed DMG unexpectedly equals the unsigned local DMG payload"
                        )
                    staged_payload_contained_exactly = False
                    staged_root = local_root
                else:
                    if published_app_entries != staged_entries:
                        raise SystemExit(
                            "verifier DMG does not contain its exact unsigned staged payload"
                        )
                    staged_comparison_entries = extracted_entries
                    embedded_entries = extracted_entries
                    staged_payload_contained_exactly = True
                    staged_root = extraction_root
                binding_method = "macos-code-signature-normalized"
                payload_comparison_entries, normalization_evidence = normalized_macos_transition(
                    staged_root,
                    extraction_root,
                    published_app,
                    published_prefix,
                    staged_comparison_entries,
                    embedded_entries,
                    temporary_root / "codesign-views",
                    runner_image_digest,
                    frozen_row,
                )
            else:
                embedded_root = matching_payload_root(extraction_root)
                embedded_entries = canonical_entries(embedded_root)
                extracted_entries = canonical_entries(extraction_root)
                staged_comparison_entries = staged_entries
                payload_comparison_entries = extracted_entries
        finally:
            for cleanup_action in reversed(cleanups):
                cleanup_action()
    subject_entries = [
        dict(value, componentIds=component_ids) for value in payload_comparison_entries
    ]
    staged_payload = entries_digest(staged_comparison_entries)
    extracted_payload = entries_digest(extracted_entries)
    embedded_staged_payload = entries_digest(embedded_entries)
    if binding_method == "exact-staged-payload" and staged_payload != embedded_staged_payload:
        raise SystemExit(f"published package does not contain the exact staged payload for {key}")
    pre_signing = (
        entries_digest(payload_comparison_entries)
        if package_type == "dmg" else staged_payload
    )
    metadata = {"subjectKey": key, "fileName": row["fileName"], "buildTask": os.environ["BUILD_TASK"]}
    payload = {
        "schemaVersion": 1,
        "kind": "stable-1.0-payload-manifest",
        "subjectKey": key,
        "publishedSubjectDigest": published_digest,
        "packageType": package_type,
        "normalizationRuleId": normalization_rule["id"],
        "normalizationRuleVersion": normalization_rule["version"],
        "preSigningPayloadDigest": pre_signing,
        "packageMetadataDigest": "sha256:" + hashlib.sha256(
            json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        "entries": subject_entries,
        "ignoredPaths": [],
        "limits": {"entryCount": len(payload_comparison_entries),
                   "expandedBytes": sum(value["size"] for value in payload_comparison_entries),
                   "nestedArchiveDepth": 0},
        "manifestDigest": "sha256:" + "0" * 64,
    }
    payload["manifestDigest"] = semantic_digest(payload, "manifestDigest")
    errors = payload_manifest_errors(payload, policy)
    if errors:
        raise SystemExit(f"generated platform payload manifest is invalid: {errors[0]}")
    (out / "payload-manifests" / f"{key}.json").write_text(
        json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    extraction = {
        "schemaVersion": 1,
        "kind": "stable-1.0-package-extraction-evidence",
        "builderRole": role,
        "subjectKey": key,
        "packageType": package_type,
        "bindingMethod": binding_method,
        "publishedSubjectDigest": payload["publishedSubjectDigest"],
        "payloadManifestDigest": payload["manifestDigest"],
        "signatureReceiptDigest": (
            row["signatureReceiptDigest"] if role == "candidate-producer" else None
        ),
        "notarizationReceiptDigest": (
            row["notarizationReceiptDigest"] if role == "candidate-producer" else None
        ),
        "extractionTool": {
            "name": extraction_tool,
            "version": extraction_version,
            "runnerImageDigest": runner_image_digest,
        },
        "stagedPayloadDigest": staged_payload,
        "embeddedStagedPayloadDigest": embedded_staged_payload,
        "extractedPayloadDigest": extracted_payload,
        "stagedPayloadContainedExactly": staged_payload_contained_exactly,
        "normalizationEvidence": normalization_evidence,
        "evidenceDigest": "sha256:" + "0" * 64,
    }
    extraction["evidenceDigest"] = semantic_digest(extraction, "evidenceDigest")
    extraction_errors = validate_schema(
        extraction, "stable-1.0-package-extraction-evidence-v1.schema.json"
    )
    if extraction_errors:
        raise SystemExit(f"generated package extraction evidence is invalid: {extraction_errors[0]}")
    (out / "extraction-evidence" / f"{key}.json").write_text(
        json.dumps(extraction, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    emitted.append({"subjectKey": key, "fileName": row["fileName"],
                    "digest": payload["publishedSubjectDigest"], "size": len(published),
                    "payloadManifestDigest": payload["manifestDigest"]})
runner_image = os.environ.get("ImageOS", "") + "@" + os.environ.get("ImageVersion", "")
if not runner_image.strip("@") or "latest" in runner_image.casefold():
    raise SystemExit("hosted runner image identity is absent or mutable")
handoff = {
    "schemaVersion": 1,
    "kind": "cryptad-stable-supply-chain-platform-execution-handoff",
    "executionId": execution_id,
    "role": role,
    "workflowRef": (
        "github.com/" + os.environ["GITHUB_REPOSITORY"]
        + "/.github/workflows/stable-1.0-supply-chain.yml@"
        + os.environ["SOURCE_COMMIT"]
    ),
    "workflowSha": os.environ["GITHUB_WORKFLOW_SHA"],
    "runId": int(os.environ["GITHUB_RUN_ID"]),
    "runAttempt": int(os.environ["GITHUB_RUN_ATTEMPT"]),
    "jobName": role + "-" + execution_id,
    "runnerOs": os.environ["RUNNER_OS_VALUE"],
    "runnerArchitecture": "amd64",
    "runnerImageIdentity": runner_image,
    "runnerImageDigest": "sha256:" + hashlib.sha256(runner_image.encode()).hexdigest(),
    "observedJava": observation["java"],
    "canonicalEnvironment": observation["canonicalEnvironment"],
    "environmentVariables": observation["environmentVariables"],
    "subjectKeys": sorted(keys),
    "sourceCommit": os.environ["SOURCE_COMMIT"],
    "sourceTreeDigest": materials["source"]["treeDigest"],
    "materialsDigest": materials["materialsDigest"],
    "resolutionSnapshotDigest": snapshot["snapshotDigest"],
    "buildStartedAt": os.environ["PLATFORM_BUILD_STARTED"],
    "buildCompletedAt": __import__("datetime").datetime.now(
        __import__("datetime").timezone.utc
    ).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    "candidateProductAvailableBeforeBuild": False,
    "subjects": sorted(emitted, key=lambda value: value["subjectKey"]),
}
(out / "handoff.json").write_text(
    json.dumps(handoff, sort_keys=True, separators=(",", ":")) + "\n",
    encoding="utf-8",
)
