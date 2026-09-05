# Linux installer behavior (DEB/RPM) reference

Read for Linux installer behavior (DEB/RPM). Commands and unlinked source paths are relative to the repository root.

## Linux installer behavior (DEB/RPM)
- Install location: app image under `/opt/cryptad/Crypta` (some hosts may lowercase it; scripts auto-detect and normalize).
- Desktop vs server detection:
  - Considered “desktop” only when a display manager service exists and is enabled/active; otherwise checks session files.
- Conditional actions:
  - Server: install systemd unit at `/etc/systemd/system/cryptad.service`, daemon-reload, enable (do not auto-start).
  - Desktop: install `.desktop` entry under `/usr/share/applications/crypta.desktop`, refresh menus/caches when tools exist.

### System account behavior
- Creates `cryptad` system user (home `/var/lib/cryptad`, shell `nologin`) when missing.
- Creates explicit `cryptad` system group and sets it as primary group.

### Script library
Common installer logic lives in `src/jpackage/linux/crypta-common.sh` (installed under `lib/` in the app image).
- Do not duplicate `is_desktop`, `ensure_user`, or service control snippets elsewhere.

### Headless helper for core package installs
DEB/RPM install:
- `cryptad-core-install@.service` + `cryptad-core-install.sh`
- Validates paths under `/var/lib/cryptad/updates/core` and performs installs via PackageKit/native tools.
- Polkit rule restricts starting only this unit and only to the `cryptad` user.

### Debugging installers (Linux)
- Set `CRYPTA_DEBUG=1` to enable verbose logging from maintainer scripts.
- Logs append to `/var/log/crypta-installer.log`.
- If dock icon is generic, verify GNOME association with `xprop WM_CLASS` and confirm `.desktop` keys.

### Uninstall semantics
- Service cleanup disables/stops safely and removes unit; does `daemon-reload`.
- Desktop cleanup removes `.desktop` entry and refreshes caches when tools exist.
- Data/account retention: `cryptad` user/group and `/var/lib/cryptad` remain by default to avoid data loss.
