# Spotless + dependency verification (common failure mode) reference

Read for Spotless + dependency verification (common failure mode), JUnit 6 + dependency verification. Commands and unlinked source paths are relative to the repository root.

## Spotless + dependency verification (common failure mode)
When Gradle dependency verification is strict, Spotless may fail to resolve formatter artifacts even with `mavenCentral()`.

### Spotless target path outside the project dir
If Spotless fails with an error like:
```text
Spotless error! All target files must be within the project dir.
```
run:
```bash
./gradlew clean
```
then retry Spotless (`./gradlew spotlessJava` or `./gradlew spotlessApply`).

### Procedure to refresh verification metadata for Spotless
1) Temporarily set verification to lenient:
- Edit `gradle.properties` → `org.gradle.dependency.verification=lenient`

2) Write verification entries (SHA256 + PGP):
```bash
./gradlew --write-verification-metadata sha256,pgp spotlessApply
```

Optional: force refresh to capture the exact formatter version:
```bash
./gradlew --refresh-dependencies --write-verification-metadata sha256,pgp spotlessApply
```

Faster alternative (no formatting run):
```bash
./gradlew --write-verification-metadata sha256,pgp spotlessInternalRegisterDependencies
```

3) Confirm entries in `gradle/verification-metadata.xml`
- Look for components under `com.google.googlejavaformat` and trusted keys for that group.

4) Restore strict mode:
- Edit `gradle.properties` → `org.gradle.dependency.verification=strict`

5) Validate:
```bash
./gradlew spotlessApply
```

Optional but recommended:
```bash
./gradlew --export-keys
```

Notes:
- Keep Spotless config at the intended formatter version (currently `googleJavaFormat("1.28.0")`).
- Commit updated `gradle/verification-keyring.gpg` and `gradle/verification-keyring.keys` so new environments verify without re-fetching keys.

## JUnit 6 + dependency verification
JUnit 6 introduces `org.jspecify:jspecify`. If strict verification blocks resolution, use the verification refresh steps above.
