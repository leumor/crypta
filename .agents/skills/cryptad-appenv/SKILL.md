---
name: cryptad-appenv
description: "Use AppEnv as the single source of truth for OS/arch/sandbox/service detection; refactor legacy checks safely."
metadata:
  area: platform
  domain: cryptad
---

## When to use
Use this skill when you touch:
- OS/arch detection
- PATH probing for external tools
- Flatpak/Snap/Docker detection
- Service/desktop environment heuristics

## Rule: AppEnv is the single source of truth
Do not read `System.getProperty("os.name")`, `os.arch`, or parse PATH directly in new code.
Use `network.crypta.fs.AppEnv` instead.

## Source ownership
- `AppEnv` and the rest of `network.crypta.fs` now live in the `:foundation-fs` subproject.
- Canonical source path: `foundation-fs/src/main/java/network/crypta/fs/AppEnv.java`
- The root project and other leaf projects depend on `:foundation-fs`; do not duplicate platform
  detection in parallel helper classes.

## APIs provided (high-level)
- OS:
  - `isWindows()`, `isMac()`, `isLinux()`
  - `osKind(): OsKind`
- Sandbox/environment:
  - `isFlatpak()`, `isSnap()`, `isDocker()`
  - `isServiceMode()` and service heuristics per-OS
- CPU arch:
  - `arch(): String` (returns `"amd64"` or `"arm64"`)
- PATH/tooling:
  - `onPath(cmd: String): Boolean`
  - `availableManagers(): List<String>` (Linux PATH probing)
- Snapshot:
  - `detectEnvironment(): EnvDetection` with `os/arch/availableManagers`
- Display-only strings:
  - `osNameRaw()`, `osVersionRaw()`

## Usage example (Java)
```java
AppEnv env = new AppEnv();
if (env.isServiceMode()) {
  // ...
}

switch (env.osKind()) {
  case WINDOWS:
    // ...
    break;
  default:
    // ...
}
```

## Refactoring guidance
- Replace raw `os.name` / `os.arch` checks and PATH scans with `AppEnv` APIs.
- If a legacy utility exposes more granular enums (e.g., FreeBSD), map from `AppEnv.osKind()` and fall back only where necessary to preserve behavior.
