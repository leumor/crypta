# Installers (jpackage) reference

Read for Installers (jpackage). Commands and unlinked source paths are relative to the repository root.

## Installers (jpackage)
We ship Gradle tasks that build a desktop app image and (on macOS/Linux) native installers via `jpackage`.

### Tasks
- `./gradlew build`
  - Builds the jpackage app image and enriches it with `cryptad-dist`.
  - On Linux/macOS, also builds native installers (`.deb`/`.rpm` on Linux when tools exist; `.dmg` on macOS).
  - Missing tools cause installer tasks to be skipped, not failed.
- `./gradlew jpackageImageCryptad`
  - Builds only the app image under `build/jpackage/`.
- `./gradlew jpackageInstallerCryptad`
  - Builds a native installer for the current OS (macOS: `.dmg`; Linux: `.deb` or `.rpm` when tools exist).
  - Not available on Windows by default.

### Linux installer type override
- Pass `-PlinuxInstaller=<deb|rpm>` (or set env `CRYPTA_LINUX_INSTALLER`) to force installer type.
- When both are available, RPM is preferred by default.

### Metadata and entrypoint
- Name: `Crypta`, Vendor: `crypta.network`, App ID: `network.crypta.cryptad`
- Main entry: `network.crypta.launcher.Launcher`
- Versioning: jpackage requires numeric `--app-version`. Linux and macOS use the project version
  integer. Windows maps that same integer to the MSI-safe technical form `1.0.<build>` at the app
  image, launcher-configuration, and EXE stages; this does not change Cryptad's project version.

### Icons and resources
- macOS: `src/jpackage/macos/cryptad.icns`
- Windows: `src/jpackage/windows/cryptad.ico`
- Linux: `src/jpackage/linux/cryptad.png`

### Troubleshooting (macOS)
- If double-click does nothing, run `Contents/MacOS/Crypta` in Terminal to see logs.
- Clear quarantine on unsigned builds:
  - `xattr -dr com.apple.quarantine build/jpackage/Crypta.app`
- Verify:
  - `spctl --assess -vv build/jpackage/Crypta.app`

### Troubleshooting (Windows)
- Launch from a console:
  - `build\jpackage\Crypta\Crypta.exe`
- Verify key paths exist:
  - `build\jpackage\Crypta\app\cryptad-dist\lib\cryptad.jar`
  - `build\jpackage\Crypta\app\Crypta.cfg`
- Verify `Crypta.cfg` includes:
  - `app.mainclass=network.crypta.launcher.Launcher`
  - one or more `app.classpath=$APPDIR/cryptad-dist/lib/*.jar` lines
