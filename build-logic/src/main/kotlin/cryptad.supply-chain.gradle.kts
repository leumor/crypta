import cryptad.ExportStableSupplyChainResolution
import cryptad.ExportStableSupplyChainResolutionFragment
import cryptad.StableConfigurationSpec
import cryptad.StableDirectInput
import cryptad.StableJdkFingerprint
import cryptad.StableSupplyChainJson
import cryptad.StableSupplyChainResolutionTask
import cryptad.StableTrackedMaterialPaths
import cryptad.StableVendoredComponent
import cryptad.VerifyStableSupplyChainResolution
import cryptad.VerifyStableTrackedMaterialPaths
import cryptad.selectStableJava25
import org.gradle.api.artifacts.Configuration
import org.gradle.jvm.toolchain.JavaToolchainService

plugins { base }

require(project == rootProject) { "cryptad.supply-chain must be applied to the root project" }

val stableConfigurationRoles =
  mapOf(
    "annotationProcessor" to "build",
    "runtimeClasspath" to "runtime",
    "compileClasspath" to "build",
    "testAnnotationProcessor" to "test",
    "testRuntimeClasspath" to "test",
    "testCompileClasspath" to "test",
    "appDistCli" to "build",
  )

fun stableConfigurations(): List<Configuration> =
  rootProject.allprojects.sortedBy(Project::getPath).flatMap { owner ->
    owner.configurations
      .filter { configuration ->
        configuration.isCanBeResolved && stableConfigurationRoles.containsKey(configuration.name)
      }
      .sortedBy(Configuration::getName)
  }

val fullSourceCommit =
  providers
    .exec {
      workingDir(rootDir)
      commandLine("git", "rev-parse", "HEAD")
    }
    .standardOutput
    .asText
    .map(String::trim)
val sourceRefProvider =
  providers
    .exec {
      workingDir(rootDir)
      commandLine("git", "rev-parse", "--symbolic-full-name", "HEAD")
    }
    .standardOutput
    .asText
    .map(String::trim)
val sourceTreeObjectId =
  providers
    .exec {
      workingDir(rootDir)
      commandLine("git", "rev-parse", "HEAD^{tree}")
    }
    .standardOutput
    .asText
    .map(String::trim)
val sourceStatus =
  providers
    .exec {
      workingDir(rootDir)
      commandLine("git", "status", "--porcelain=v1", "--untracked-files=all")
    }
    .standardOutput
    .asText
    .map { status -> status.replace("\r\n", "\n").trimEnd() }

val javaToolchains = extensions.getByType<JavaToolchainService>()
val java25 = javaToolchains.launcherFor { selectStableJava25() }
val jlinkModulesFile = layout.buildDirectory.file("jlink/runtime-modules.list")
val inventoryJreModules = tasks.named("inventoryJreModules")
val supplyChainPolicyFile =
  layout.projectDirectory.file("tools/release-certification/stable-1.0-supply-chain-policy.json")
val supplyChainPolicyDigest =
  providers.fileContents(supplyChainPolicyFile).asText.map { policy ->
    Regex("\"policyDigest\"\\s*:\\s*\"(sha256:[0-9a-f]{64})\"").find(policy)?.groupValues?.get(1)
      ?: throw GradleException("Stable supply-chain policy does not contain a valid policyDigest")
  }
val reviewedResolutionExport =
  providers.gradleProperty("stableSupplyChainExpectedResolutionExport").map { path -> file(path) }
val reviewedResolutionSnapshot =
  providers.gradleProperty("stableSupplyChainExpectedResolutionSnapshot").map { path -> file(path) }
val publicationBackendHeadTreePaths =
  providers
    .exec {
      workingDir(rootDir)
      commandLine(
        "git",
        "ls-tree",
        "-r",
        "-z",
        "--name-only",
        "HEAD",
        "--",
        StableTrackedMaterialPaths.PUBLICATION_BACKEND_ROOT,
      )
    }
    .standardOutput
    .asBytes
val publicationBackendMaterialFiles = publicationBackendHeadTreePaths.map { encodedPaths ->
  StableTrackedMaterialPaths.selectPublicationBackendFiles(rootDir, encodedPaths)
}

val stableMaterialFiles =
  files(
    "settings.gradle.kts",
    "build.gradle.kts",
    "gradle.properties",
    "gradle/libs.versions.toml",
    "gradle/verification-metadata.xml",
    "gradle/verification-keyring.gpg",
    "gradle/verification-keyring.keys",
    "gradle/wrapper/gradle-wrapper.jar",
    "gradle/wrapper/gradle-wrapper.properties",
    "libs/wrapper.jar",
    "libs/db4o-7.4.58.jar",
    supplyChainPolicyFile,
    "build-logic/build/stable-supply-chain/resolved-build-logic.json",
    fileTree("build-logic") {
      include("build.gradle.kts")
      include("settings.gradle.kts")
      include("gradle/verification-metadata.xml")
      include("gradle/verification-keyring.gpg")
      include("gradle/verification-keyring.keys")
      include("src/main/kotlin/**")
    },
    fileTree(rootDir) {
      include("**/gradle.lockfile")
      exclude(".gradle/**", "**/build/**")
    },
    fileTree("src/jpackage") { include("**/*") },
    fileTree("tools/flatpak") { include("**/*") },
    publicationBackendMaterialFiles,
    fileTree("apps") {
      include("*/build.gradle.kts")
      include("*/src/staged/**")
    },
    fileTree("platform-sdk-js") {
      include("build.gradle.kts")
      include("src/main/resources/**")
    },
    fileTree("platform-design-system") {
      include("build.gradle.kts")
      include("src/main/resources/**")
    },
  )

tasks.register<VerifyStableTrackedMaterialPaths>(
  "verifyStablePublicationBackendMaterialSelection"
) {
  group = "verification"
  description =
    "Verifies authenticated HEAD-tree publication materials reject generated and unsafe paths."
}

val stableVendoredComponents =
  listOf(
    StableVendoredComponent(
        path = "libs/wrapper.jar",
        componentId =
          "pkg:generic/cryptad-vendored/java-service-wrapper@3.6.2" +
            "?checksum=9918de095c0375d49b60aeded11e4ddac8c5bcc691757899cdccd2cbaa02493e",
        version = "3.6.2",
        role = "build-and-compile",
        origin = "https://wrapper.tanukisoftware.com/doc/english/download.jsp",
      )
      .encoded,
    StableVendoredComponent(
        path = "libs/db4o-7.4.58.jar",
        componentId =
          "pkg:generic/cryptad-vendored/db4o@7.4.58" +
            "?checksum=fcc671064d39d553e8812a2bebac082b7e7f58edd795d5ff7f083eb9156389ad",
        version = "7.4.58",
        role = "runtime",
        origin = "repository-vendored:libs/db4o-7.4.58.jar",
      )
      .encoded,
  )

val wrapperVersion = "3.6.2"
val wrapperDeltaPackName = "wrapper-delta-pack-$wrapperVersion.tar.gz"
val wrapperDeltaPackUrl =
  "https://sourceforge.net/projects/wrapper/files/wrapper/Wrapper_3.6.2_20250605/" +
    "$wrapperDeltaPackName/download"
val wrapperWindowsApiUrl =
  providers
    .gradleProperty("wrapperWinApiUrl")
    .orElse("https://api.github.com/repos/crypta-network/wrapper-windows-build/releases/latest")
val wrapperWindowsAmd64Url = providers.gradleProperty("wrapperWinAmd64Url").orElse("")
val wrapperWindowsArm64Url = providers.gradleProperty("wrapperWinArm64Url").orElse("")
val seedrefsUrl =
  providers
    .gradleProperty("seedrefsUrl")
    .orElse("https://codeload.github.com/hyphanet/seedrefs/zip/refs/heads/master")
val immutableSeedrefsUrl =
  Regex("^https://codeload\\.github\\.com/hyphanet/seedrefs/zip/[0-9a-f]{40}$")
val immutableWindowsWrapperUrl =
  Regex(
    "^https://github\\.com/crypta-network/wrapper-windows-build/releases/download/" +
      "[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._+-]*\\.(?:zip|tar\\.gz)$"
  )
val stableDirectInputs = providers.provider {
  val wrapperProperties =
    java.util.Properties().apply {
      file("gradle/wrapper/gradle-wrapper.properties").inputStream().use(::load)
    }
  listOf(
    StableDirectInput(
        name = "gradle-wrapper-distribution",
        url = wrapperProperties.getProperty("distributionUrl"),
        immutabilityClass = "versioned-url",
        expectedSha256 = wrapperProperties.getProperty("distributionSha256Sum").orEmpty(),
        localPath = "build/stable-supply-chain/gradle-wrapper-distribution.bin",
      )
      .encoded,
    StableDirectInput(
        name = "tanuki-wrapper-delta-pack",
        url = wrapperDeltaPackUrl,
        immutabilityClass = "versioned-url",
        expectedSha256 = providers.gradleProperty("wrapperDeltaPackSha256").orNull.orEmpty(),
        localPath = "build/wrapper/$wrapperDeltaPackName",
      )
      .encoded,
    StableDirectInput(
        name = "seedrefs-source-archive",
        url = seedrefsUrl.get(),
        immutabilityClass =
          if (immutableSeedrefsUrl.matches(seedrefsUrl.get())) "immutable-git-archive"
          else "mutable-branch",
        expectedSha256 = providers.gradleProperty("seedrefsSha256").orNull.orEmpty(),
        localPath = "build/seedrefs/seedrefs.zip",
      )
      .encoded,
    StableDirectInput(
        name = "windows-wrapper-amd64",
        url = wrapperWindowsAmd64Url.get().ifBlank { wrapperWindowsApiUrl.get() },
        immutabilityClass =
          if (immutableWindowsWrapperUrl.matches(wrapperWindowsAmd64Url.get()))
            "immutable-release-asset"
          else if (wrapperWindowsAmd64Url.get().isBlank()) "mutable-release-api"
          else "explicit-url",
        expectedSha256 = providers.gradleProperty("wrapperWinAmd64Sha256").orNull.orEmpty(),
        localPath = "build/wrapper/windows/windows-amd64.bin",
      )
      .encoded,
    StableDirectInput(
        name = "windows-wrapper-arm64",
        url = wrapperWindowsArm64Url.get().ifBlank { wrapperWindowsApiUrl.get() },
        immutabilityClass =
          if (immutableWindowsWrapperUrl.matches(wrapperWindowsArm64Url.get()))
            "immutable-release-asset"
          else if (wrapperWindowsArm64Url.get().isBlank()) "mutable-release-api"
          else "explicit-url",
        expectedSha256 = providers.gradleProperty("wrapperWinArm64Sha256").orNull.orEmpty(),
        localPath = "build/wrapper/windows/windows-arm64.bin",
      )
      .encoded,
  )
}

val stableReleaseTasks =
  listOf(
    "buildJar",
    "assembleCryptadDist",
    "distTarCryptad",
    "distZipCryptad",
    "computeJlinkModules",
    "inventoryJreModules",
    "createJreImage",
    "distTarCryptadJlink",
    "distZipCryptadJlink",
    "jpackageImageCryptad",
    "enrichAppImageWithDist",
    "jpackageInstallerDeb",
    "jpackageInstallerRpm",
    "jpackageInstallerCryptad",
    "jpackageInstallerWindowsExeCryptad",
    "stageFirstPartyApps",
    "signFirstPartyApps",
    "verifyFirstPartyApps",
    "packageFirstPartyApps",
  )
val stableAllowedEnvironmentVariables = listOf("LANG", "LC_ALL", "SOURCE_DATE_EPOCH", "TZ")

fun StableSupplyChainResolutionTask.configureStableInputs(
  selectedConfigurations: Provider<List<String>>,
  includeRootMaterials: Boolean,
) {
  configurationDescriptors.set(selectedConfigurations)
  vendoredDescriptors.set(stableVendoredComponents)
  directInputDescriptors.set(
    if (includeRootMaterials) stableDirectInputs else providers.provider { emptyList() }
  )
  if (includeRootMaterials) materialFiles.from(stableMaterialFiles)
  releaseVersion.set(providers.provider { rootProject.version.toString() })
  sourceCommit.set(fullSourceCommit)
  sourceRef.set(sourceRefProvider)
  gitTreeObjectId.set(sourceTreeObjectId)
  sourceTreeClean.set(sourceStatus.map(String::isBlank))
  sourceStatusDigest.set(
    sourceStatus.map { status ->
      val state = if (status.isBlank()) "clean" else "dirty-blocking"
      StableSupplyChainJson.sha256(state.toByteArray(Charsets.UTF_8))
    }
  )
  dependencyVerificationMode.set(
    providers.provider { gradle.startParameter.dependencyVerificationMode.name }
  )
  gradleVersion.set(GradleVersion.current().version)
  if (includeRootMaterials) {
    val jdkInstallationIdentity = java25.map { launcher ->
      StableJdkFingerprint.identity(launcher.metadata.installationPath.asFile.toPath())
    }
    jdkIdentity.put("languageVersion", java25.map { it.metadata.languageVersion.toString() })
    jdkIdentity.put("vendor", java25.map { it.metadata.vendor })
    jdkIdentity.put(
      "javaRuntimeVersion",
      java25.map { StableJdkFingerprint.canonicalRuntimeBuild(it.metadata.javaRuntimeVersion) },
    )
    jdkIdentity.put("jvmVersion", java25.map { it.metadata.jvmVersion })
    jdkIdentity.put(
      "installationManifestDigest",
      jdkInstallationIdentity.map { it.getValue("installationManifestDigest") },
    )
    jdkIdentity.put(
      "releaseFileDigest",
      jdkInstallationIdentity.map { it.getValue("releaseFileDigest") },
    )
  } else {
    jdkIdentity.set(
      mapOf(
        "languageVersion" to "25",
        "vendor" to System.getProperty("java.vendor"),
        "javaRuntimeVersion" to System.getProperty("java.runtime.version"),
        "jvmVersion" to System.getProperty("java.vm.version"),
      )
    )
  }
  if (includeRootMaterials) {
    jdkModules.set(
      providers.provider {
        val file = jlinkModulesFile.get().asFile
        if (!file.isFile) {
          throw GradleException("inventoryJreModules did not produce its required module inventory")
        }
        val raw = file.readText(Charsets.UTF_8)
        val modules = raw.split(',')
        val validModule = Regex("[A-Za-z][A-Za-z0-9]*(?:\\.[A-Za-z0-9]+)*")
        if (
          raw.isBlank() ||
            raw != raw.trim() ||
            modules.any { it.isBlank() || it != it.trim() || !validModule.matches(it) } ||
            modules != modules.sorted().distinct()
        ) {
          throw GradleException("jlink module inventory is empty or non-canonical")
        }
        modules
      }
    )
  } else {
    jdkModules.set(emptyList())
  }
  releaseTasks.set(stableReleaseTasks)
  allowedEnvironmentVariables.set(stableAllowedEnvironmentVariables)
  policyDigest.set(supplyChainPolicyDigest)
}

val exportStableSupplyChainResolution =
  tasks.register<ExportStableSupplyChainResolution>("exportStableSupplyChainResolution") {
    group = "release certification"
    description =
      "Exports the raw and compact Stable dependency resolutions plus build materials; " +
        "-PstableSupplyChainExpectedResolutionExport=<reviewed-file> enables authenticated-snapshot mode."
    configureStableInputs(providers.provider { emptyList() }, includeRootMaterials = true)
    resolutionSnapshotFile.set(
      layout.buildDirectory.file("stable-supply-chain/resolved-dependency-snapshot.json")
    )
    resolutionExportFile.set(
      layout.buildDirectory.file("stable-supply-chain/resolved-dependency-export.json")
    )
    buildMaterialsFile.set(
      layout.buildDirectory.file("stable-supply-chain/build-material-inputs.json")
    )
    buildLogicResolutionFile.set(
      layout.projectDirectory.file(
        "build-logic/build/stable-supply-chain/resolved-build-logic.json"
      )
    )
    reviewedResolutionExportFile.set(layout.file(reviewedResolutionExport))
  }

val verifyStableSupplyChainResolution =
  tasks.register<VerifyStableSupplyChainResolution>("verifyStableSupplyChainResolution") {
    group = "verification"
    description =
      "Requires -PstableSupplyChainExpectedResolutionExport=<reviewed-file> and " +
        "-PstableSupplyChainExpectedResolutionSnapshot=<reviewed-file>, then verifies exact bytes."
    configureStableInputs(providers.provider { emptyList() }, includeRootMaterials = true)
    expectedDocuments.from(
      layout.buildDirectory.file("stable-supply-chain/build-material-inputs.json")
    )
    buildLogicResolutionFile.set(
      layout.projectDirectory.file(
        "build-logic/build/stable-supply-chain/resolved-build-logic.json"
      )
    )
    reviewedResolutionExportFile.set(layout.file(reviewedResolutionExport))
    reviewedResolutionSnapshotFile.set(layout.file(reviewedResolutionSnapshot))
  }

val exportStableBuildLogicResolution =
  gradle.includedBuild("build-logic").task(":exportStableBuildLogicResolution")

exportStableSupplyChainResolution.configure {
  dependsOn(inventoryJreModules, exportStableBuildLogicResolution)
}

verifyStableSupplyChainResolution.configure {
  // The verifier compares the generated build-material document as well as regenerating the
  // dependency model. Make the producer relationship explicit so Gradle cannot schedule the
  // comparison against a stale or concurrently written document.
  dependsOn(exportStableSupplyChainResolution)
}

gradle.projectsEvaluated {
  val configurations = stableConfigurations()
  configurations.forEach { configuration ->
    configuration.resolutionStrategy.failOnDynamicVersions()
    configuration.resolutionStrategy.failOnChangingVersions()
  }
  val fragmentTasks =
    rootProject.allprojects.sortedBy(Project::getPath).map { owner ->
      val ownerConfigurations = providers.provider {
        owner.configurations
          .filter { configuration ->
            configuration.isCanBeResolved &&
              stableConfigurationRoles.containsKey(configuration.name)
          }
          .sortedBy(Configuration::getName)
      }
      val ownerDescriptors = ownerConfigurations.map { configurations ->
        configurations.map { configuration ->
          StableConfigurationSpec(
              projectPath = owner.path,
              configurationName = configuration.name,
              role = stableConfigurationRoles.getValue(configuration.name),
            )
            .encoded
        }
      }
      val ownerArtifactBuildDependencies = ownerConfigurations.map { configurations ->
        configurations.map { configuration ->
          configuration.incoming.artifactView { isLenient = false }.files.buildDependencies
        }
      }
      owner.tasks.register<ExportStableSupplyChainResolutionFragment>(
        "exportStableSupplyChainResolutionFragment"
      ) {
        group = "release certification"
        description = "Exports this project's canonical Stable dependency resolution fragment."
        configureStableInputs(ownerDescriptors, includeRootMaterials = false)
        dependsOn(ownerArtifactBuildDependencies)
        fragmentFile.set(
          owner.layout.buildDirectory.file("stable-supply-chain/resolution-fragment.json")
        )
      }
    }
  exportStableSupplyChainResolution.configure {
    dependsOn(fragmentTasks)
    fragmentFiles.from(fragmentTasks.map { task -> task.flatMap { it.fragmentFile } })
  }
  verifyStableSupplyChainResolution.configure {
    dependsOn(fragmentTasks)
    fragmentFiles.from(fragmentTasks.map { task -> task.flatMap { it.fragmentFile } })
  }
}
