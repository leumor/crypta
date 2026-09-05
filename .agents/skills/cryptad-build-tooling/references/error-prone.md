# Error Prone reference

Read for Error Prone. Commands and unlinked source paths are relative to the repository root.

## Error Prone
### Key behaviors
- Enabled via `net.ltgt.errorprone` in the shared convention plugin.
- Errors are downgraded to warnings by default (`options.errorprone.allErrorsAsWarnings = true`).

### Report task
- Generate XML reports:
  - `./gradlew errorproneReport`
- Output:
  - `build/reports/errorprone/<task>/<task>.xml` (e.g., `compileJava/compileJava.xml`, `compileTestJava/compileTestJava.xml`)

### Report schema (custom)
- Root element: `<errorproneReport>`
- Per warning: `<diagnostic>` with attributes `severity`, `check`, `file`, `line`, plus `<message>` and optional `<details>`.

### Enforcing errors
- To fail the build on Error Prone errors, set `allErrorsAsWarnings` to `false` in:
  - the shared convention plugin under `build-logic/src/main/`

### Verification refresh on Error Prone bumps
If strict verification blocks resolution:
1) Set `org.gradle.dependency.verification=lenient`
2) Run:
```bash
./gradlew --write-verification-metadata sha256,pgp :build-logic:classes
```
3) Restore `org.gradle.dependency.verification=strict`
4) Optionally `./gradlew --export-keys`
