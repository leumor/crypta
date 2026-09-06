import groovy.json.JsonOutput
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import org.gradle.api.artifacts.component.ModuleComponentIdentifier
import org.gradle.api.artifacts.result.ResolvedArtifactResult
import org.gradle.api.artifacts.result.ResolvedDependencyResult
import org.gradle.api.artifacts.result.UnresolvedDependencyResult
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
  // Enables precompiled script plugins under src/main/kotlin
  `kotlin-dsl`
}

java {
  toolchain { languageVersion.set(JavaLanguageVersion.of(25)) }
  sourceCompatibility = JavaVersion.VERSION_25
  targetCompatibility = JavaVersion.VERSION_25
}

kotlin { jvmToolchain(25) }

repositories {
  // Needed to resolve plugin marker artifacts like org.beryx:badass-runtime-plugin
  gradlePluginPortal()
  mavenCentral()
}

val rootSettingsPluginClasspath by configurations.creating {
  isCanBeConsumed = false
  isCanBeResolved = true
  description = "Authenticated plugin classpath executed by the root settings script."
}
val buildLogicSettingsPluginClasspath by configurations.creating {
  isCanBeConsumed = false
  isCanBeResolved = true
  description = "Authenticated plugin classpath executed by the included-build settings script."
}

dependencies {
  // Portable archive normalization runs inside Gradle so distribution tasks remain Java-only.
  implementation(libs.commonsCompress)
  // Allow precompiled plugins to apply these without specifying versions in their scripts
  implementation("com.diffplug.spotless:spotless-plugin-gradle:${libs.versions.spotless.get()}")
  implementation(
    "com.github.spotbugs:com.github.spotbugs.gradle.plugin:${libs.versions.spotbugs.get()}"
  )
  implementation(
    "net.ltgt.errorprone:net.ltgt.errorprone.gradle.plugin:${libs.versions.errorpronePlugin.get()}"
  )
  // SonarQube plugin marker for precompiled convention plugin usage
  implementation("org.sonarqube:org.sonarqube.gradle.plugin:${libs.versions.sonarqube.get()}")
  // name.remal.sonarlint plugin marker so our convention plugin can apply it without a version
  implementation(
    "name.remal.sonarlint:name.remal.sonarlint.gradle.plugin:${libs.versions.remalSonarlint.get()}"
  )
  // SonarLint implementation API for typed configuration in precompiled plugin
  implementation(
    "name.remal.gradle-plugins.sonarlint:sonarlint:${libs.versions.remalSonarlint.get()}"
  )
  val foojayMarker =
    "org.gradle.toolchains.foojay-resolver-convention:" +
      "org.gradle.toolchains.foojay-resolver-convention.gradle.plugin:" +
      libs.versions.foojayResolver.get()
  add(rootSettingsPluginClasspath.name, foojayMarker)
  add(buildLogicSettingsPluginClasspath.name, foojayMarker)

  testImplementation(libs.junitJupiterApi)
  testRuntimeOnly(libs.junitJupiterEngine)
  testRuntimeOnly(libs.junitPlatformLauncher)
}

tasks.withType<Test>().configureEach { useJUnitPlatform() }

tasks.withType<KotlinCompile>().configureEach {
  compilerOptions.jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_25)
}

val stableBuildLogicConfigurations =
  setOf(
    "buildLogicSettingsPluginClasspath",
    "compileClasspath",
    "rootSettingsPluginClasspath",
    "runtimeClasspath",
  )

configurations
  .matching { configuration -> configuration.name in stableBuildLogicConfigurations }
  .configureEach {
    resolutionStrategy.failOnDynamicVersions()
    resolutionStrategy.failOnChangingVersions()
  }

tasks.register("exportStableBuildLogicResolution") {
  group = "release certification"
  description = "Exports resolved build-logic and plugin artifacts for Stable build materials."
  val outputFile = layout.buildDirectory.file("stable-supply-chain/resolved-build-logic.json")
  outputs.file(outputFile)
  outputs.upToDateWhen { false }

  doLast {
    fun sha256(file: File): String {
      val digest = MessageDigest.getInstance("SHA-256")
      file.inputStream().buffered().use { input ->
        val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
        while (true) {
          val read = input.read(buffer)
          if (read < 0) break
          digest.update(buffer, 0, read)
        }
      }
      return digest.digest().joinToString("") { byte -> "%02x".format(byte) }
    }

    fun purl(value: String): String =
      URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20")

    val configurationRecords = mutableListOf<Map<String, Any?>>()
    val componentRecords = sortedMapOf<String, Map<String, Any?>>()
    val relationshipRecords = mutableListOf<Map<String, Any?>>()
    val artifactRecords = mutableListOf<Map<String, Any?>>()
    stableBuildLogicConfigurations.sorted().forEach { configurationName ->
      val configuration = configurations.getByName(configurationName)
      val resolution = configuration.incoming.resolutionResult
      resolution.allComponents.forEach { component ->
        val identifier = component.id
        if (identifier is ModuleComponentIdentifier) {
          val id =
            "pkg:maven/${purl(identifier.group)}/${purl(identifier.module)}@${purl(identifier.version)}"
          componentRecords[id] =
            linkedMapOf(
              "id" to id,
              "group" to identifier.group,
              "name" to identifier.module,
              "version" to identifier.version,
            )
        }
      }
      resolution.allDependencies.forEach { dependency ->
        when (dependency) {
          is ResolvedDependencyResult -> {
            val from = dependency.from.id
            val selected = dependency.selected.id
            if (from is ModuleComponentIdentifier && selected is ModuleComponentIdentifier) {
              relationshipRecords +=
                linkedMapOf(
                  "configuration" to configurationName,
                  "from" to
                    "pkg:maven/${purl(from.group)}/${purl(from.module)}@${purl(from.version)}",
                  "to" to
                    "pkg:maven/${purl(selected.group)}/${purl(selected.module)}@${purl(selected.version)}",
                  "requested" to dependency.requested.displayName,
                  "constraint" to dependency.isConstraint,
                )
            }
          }
          is UnresolvedDependencyResult ->
            throw GradleException(
              "Unresolved build-logic dependency: ${dependency.requested.javaClass.simpleName}"
            )
        }
      }
      val artifacts = configuration.incoming.artifactView { isLenient = false }.artifacts
      if (artifacts.failures.isNotEmpty()) {
        throw GradleException("Failed to resolve Stable build-logic artifacts")
      }
      artifacts.artifacts.filterIsInstance<ResolvedArtifactResult>().forEach { artifact ->
        val file = artifact.file
        if (!file.isFile) throw GradleException("Build-logic artifact is not a file: ${file.name}")
        val identifier = artifact.id.componentIdentifier
        val componentId =
          if (identifier is ModuleComponentIdentifier) {
            "pkg:maven/${purl(identifier.group)}/${purl(identifier.module)}@${purl(identifier.version)}"
          } else {
            "pkg:generic/gradle-runtime/${purl(file.name)}@${purl(gradle.gradleVersion)}" +
              "?checksum=${sha256(file)}"
          }
        artifactRecords +=
          linkedMapOf(
            "configuration" to configurationName,
            "componentId" to componentId,
            "fileName" to file.name,
            "sha256" to sha256(file),
            "size" to file.length(),
            "attributes" to
              artifact.variant.attributes
                .keySet()
                .associate { attribute ->
                  attribute.name to artifact.variant.attributes.getAttribute(attribute).toString()
                }
                .toSortedMap(),
          )
      }
      configurationRecords +=
        linkedMapOf(
          "name" to configurationName,
          "attributes" to
            configuration.attributes
              .keySet()
              .associate { attribute ->
                attribute.name to configuration.attributes.getAttribute(attribute).toString()
              }
              .toSortedMap(),
        )
    }
    val report =
      linkedMapOf<String, Any?>(
        "schema" to "cryptad-stable-build-logic-resolution-v1",
        "dependencyVerificationMode" to
          gradle.startParameter.dependencyVerificationMode.name.lowercase(),
        "verificationFileDigests" to
          listOf(
              "gradle/verification-metadata.xml",
              "gradle/verification-keyring.gpg",
              "gradle/verification-keyring.keys",
            )
            .associateWith { relativePath ->
              val file = layout.projectDirectory.file(relativePath).asFile
              if (!file.isFile) {
                throw GradleException(
                  "Missing build-logic dependency verification input: $relativePath"
                )
              }
              sha256(file)
            }
            .toSortedMap(),
        "configurations" to
          configurationRecords.sortedBy { record -> record.getValue("name") as String },
        "components" to componentRecords.values.toList(),
        "relationships" to relationshipRecords.sortedBy { record -> JsonOutput.toJson(record) },
        "artifacts" to artifactRecords.sortedBy { record -> JsonOutput.toJson(record) },
      )
    val target = outputFile.get().asFile
    target.parentFile.mkdirs()
    target.writeText(JsonOutput.toJson(report) + "\n", StandardCharsets.UTF_8)
  }
}
