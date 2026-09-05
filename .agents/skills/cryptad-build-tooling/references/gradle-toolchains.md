# Gradle wrapper and build-logic toolchains reference

Read for Gradle wrapper and build-logic toolchains. Commands and unlinked source paths are relative to the repository root.

## Gradle wrapper and build-logic toolchains
- The wrapper is pinned in `gradle/wrapper/gradle-wrapper.properties` and currently uses Gradle
  `9.4.1`.
- Convention plugins live in the included build `build-logic`; do not reintroduce `buildSrc`.
- `build-logic/build.gradle.kts` must target Java 25 for both Java and Kotlin DSL compilation:
  Java toolchain `25`, `sourceCompatibility = JavaVersion.VERSION_25`,
  `targetCompatibility = JavaVersion.VERSION_25`, `kotlin { jvmToolchain(25) }`, and Kotlin
  `jvmTarget = JVM_25`.
- Toolchain auto-provisioning is configured in `settings.gradle.kts` through the Foojay resolver
  plugin. If provisioning fails, fix the Java 25/toolchain configuration instead of downgrading
  build logic.
- When updating Gradle, run the wrapper task twice so the scripts and wrapper JAR are refreshed:
  `./gradlew wrapper --gradle-version=<version>` and then `./gradlew wrapper`.
- If strict dependency verification blocks plugin marker resolution after a wrapper or plugin
  change, temporarily use the verification refresh procedure below and restore strict mode before
  validation.
- Validate wrapper/tooling changes with `./gradlew --version`, `./gradlew spotlessApply`, and a
  relevant build or test task.
