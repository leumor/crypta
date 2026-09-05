# Platform specifics (selected behaviors) reference

Read for Platform specifics (selected behaviors), Environment detection (important), Descriptor format and integrity, UOM compatibility note. Commands and unlinked source paths are relative to the repository root.

## Platform specifics (selected behaviors)
- Linux:
  - Prefers GUI handoff (`gio`/`xdg-open`) or PackageKit.
  - In Flatpak, uses the portal / `flatpak-spawn` to bridge to host tools.
  - `.snap` files are never GUI-opened; installs use `snap install --dangerous`.
- macOS:
  - Adds Gatekeeper guidance for unsigned builds.
- Windows:
  - Adds SmartScreen guidance and SHA-256 verification tips.

## Environment detection (important)
- `AppEnv` is the single source of truth for OS/arch/sandbox/service detection.
- Do not add new `os.name`/`os.arch` checks; use `AppEnv` APIs.

## Descriptor format and integrity
- JSON includes:
  - `version` (required integer string for release gating)
  - `packages` keyed by `<arch>.<ext>`
  - optional `changelog_chk` / `fullchangelog_chk`
- CHK integrity covers content.
- Any historical `sha256` fields in descriptors are ignored.

## UOM compatibility note
- Code identifiers have been renamed to Core/CorePackage terminology.
- UOM wire compatibility keeps legacy field/type strings where required:
  - field payload names such as `"mainJarKey"`, `"mainJarVersion"`, `"mainJarFileLength"`
  - message type strings `"CryptadUOMRequestMainJar"` / `"CryptadUOMSendingMainJar"`
