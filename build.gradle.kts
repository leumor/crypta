plugins {
  // Apply Gradle 9 convention plugins from the included build
  id("cryptad.java-kotlin-conventions")
  id("cryptad.spotless")
  id("cryptad.versioning")
  id("cryptad.buildjar")
  id("cryptad.distribution")
  id("cryptad.runtime")
  id("cryptad.jpackage")
  id("cryptad.sonar")
  id("cryptad.supply-chain")
  application
}

// Update version manually before new release development starts
version = "3"

val internalLeafProjects =
  listOf(
    project(":platform-design-system"),
    project(":platform-appvault"),
    project(":platform-appdist"),
    project(":platform-app-ui"),
    project(":platform-appcatalog"),
    project(":platform-trustgraph"),
    project(":foundation-support"),
    project(":foundation-store"),
    project(":foundation-store-contracts"),
    project(":foundation-crypto-keys"),
    project(":interop-wire"),
    project(":foundation-config"),
    project(":foundation-fs"),
    project(":foundation-compat"),
    project(":kernel-content"),
    project(":kernel-transport"),
    project(":kernel-routing"),
    project(":runtime-spi"),
    project(":platform-api"),
    project(":platform-apphost"),
    project(":platform-sdk-js"),
    project(":platform-web-shell"),
    project(":runtime-alerts"),
    project(":runtime-node"),
    project(":adapter-fcp"),
    project(":bridge-fcp-runtime"),
    project(":bridge-http-runtime"),
    project(":adapter-http-legacy-admin"),
    project(":adapter-http-legacy-browse"),
    project(":thirdparty-onion"),
    project(":thirdparty-legacy"),
    project(":launcher-desktop"),
  )

val internalLeafMainJavaSourceDirs = internalLeafProjects.map { leaf ->
  leaf.layout.projectDirectory.dir("src/main/java")
}

val internalLeafMainClassDirs = internalLeafProjects.map { leaf ->
  leaf.layout.buildDirectory.dir("classes/java/main")
}

val internalLeafProjectsWithLocalTests = internalLeafProjects.filter { leaf ->
  leaf.layout.projectDirectory.dir("src/test/java").asFile.isDirectory ||
    leaf.layout.projectDirectory.dir("src/test/kotlin").asFile.isDirectory
}

val internalLeafTestSourceDirs =
  internalLeafProjectsWithLocalTests
    .flatMap { leaf ->
      listOf(
        leaf.layout.projectDirectory.dir("src/test/java"),
        leaf.layout.projectDirectory.dir("src/test/kotlin"),
      )
    }
    .map { it.asFile }
    .filter { it.isDirectory }

val rootSonarTestSourceDirs =
  listOf(
      layout.projectDirectory.dir("src/test/java"),
      layout.projectDirectory.dir("src/test/kotlin"),
    )
    .map { it.asFile }
    .filter { it.isDirectory }

val internalLeafTestResultDirs = internalLeafProjectsWithLocalTests.map { leaf ->
  leaf.layout.buildDirectory.dir("test-results/test").get().asFile
}

val internalLeafJacocoExecFiles = internalLeafProjectsWithLocalTests.map { leaf ->
  leaf.layout.buildDirectory.file("jacoco/test.exec")
}

configurations.named("testCompileOnly") { extendsFrom(configurations.compileOnly.get()) }

dependencies {
  // implementation
  implementation(project(":foundation-support"))
  implementation(project(":foundation-store"))
  implementation(project(":foundation-store-contracts"))
  implementation(project(":foundation-crypto-keys"))
  implementation(project(":interop-wire"))
  implementation(project(":foundation-config"))
  implementation(project(":foundation-fs"))
  implementation(project(":foundation-compat"))
  implementation(project(":kernel-content"))
  implementation(project(":kernel-transport"))
  implementation(project(":kernel-routing"))
  implementation(project(":runtime-spi"))
  implementation(project(":platform-design-system"))
  implementation(project(":platform-appvault"))
  implementation(project(":platform-api"))
  implementation(project(":platform-app-ui"))
  implementation(project(":platform-appcatalog"))
  implementation(project(":platform-trustgraph"))
  implementation(project(":platform-apphost"))
  implementation(project(":platform-sdk-js"))
  implementation(project(":platform-web-shell"))
  implementation(project(":runtime-alerts"))
  implementation(project(":runtime-node"))
  implementation(project(":adapter-fcp"))
  implementation(project(":bridge-fcp-runtime"))
  implementation(project(":bridge-http-runtime"))
  implementation(project(":adapter-http-legacy-admin"))
  implementation(project(":adapter-http-legacy-browse"))
  implementation(project(":thirdparty-onion"))
  implementation(project(":thirdparty-legacy"))
  implementation(project(":launcher-desktop"))
  implementation(libs.bcprov)
  implementation(libs.bcpkix)
  implementation(libs.jna)
  implementation(libs.jnaPlatform)
  implementation(libs.commonsCompress)
  implementation(libs.commonsLang3)
  implementation(files("libs/wrapper.jar"))
  implementation(libs.pebble)
  implementation(libs.unbescape)
  implementation(libs.slf4jApi)
  implementation(libs.logbackClassic)
  // FlatLaf (modern Swing Look & Feel)
  implementation(libs.flatlaf)
  // OS theme detection + change events (no LAF dependency)
  implementation(libs.oshiCore)
  implementation(libs.versionCompare)
  implementation(libs.jfa) { exclude(group = "net.java.dev.jna", module = "jna") }
  // Flatpak/Portal detection via D-Bus
  implementation(libs.dbusCore)
  // CLI parsing and UX
  implementation(libs.picocli)

  // compileOnly
  // Java source annotations used across the codebase
  compileOnly(libs.jetbrainsAnnotations)

  // runtimeOnly
  runtimeOnly(libs.dbusTransportNativeUnix)
  runtimeOnly(files("libs/db4o-7.4.58.jar"))

  // testImplementation
  testImplementation(project(":platform-appdist"))
  testImplementation(libs.junitJupiterApi)
  testImplementation(libs.junitJupiterParams)
  testImplementation(libs.junitPlatformSuite)
  testImplementation(libs.mockitoCore)
  testImplementation(libs.mockitoJunitJupiter)
  testImplementation(libs.hamcrest)
  testImplementation(libs.objenesis)

  // testRuntimeOnly
  testRuntimeOnly(libs.junitJupiterEngine)
  testRuntimeOnly(libs.junitPlatformLauncher)
}

val aggregatedSonarSourcePaths =
  (sourceSets.main.get().java.srcDirs + internalLeafMainJavaSourceDirs.map { it.asFile })
    .distinct()
    .joinToString(",") { relativePath(it) }

val aggregatedSonarBinaryPaths =
  (sourceSets.main.get().output.classesDirs.files +
      internalLeafMainClassDirs.map { it.get().asFile })
    .distinct()
    .joinToString(",") { it.absolutePath }

val aggregatedSonarTestPaths =
  (rootSonarTestSourceDirs + internalLeafTestSourceDirs).distinct().joinToString(",") {
    relativePath(it)
  }

val aggregatedSonarTestInclusions =
  (rootSonarTestSourceDirs + internalLeafTestSourceDirs).distinct().joinToString(",") {
    "${relativePath(it)}/**"
  }

val aggregatedSonarLibraryFiles = sourceSets.main.get().compileClasspath.filter { it.isFile }

val internalLeafJarNames = providers.provider {
  internalLeafProjects.map { leaf -> "${leaf.name}-${project.version}.jar" }.toSet()
}

data class AggregatedMainOutputProducer(val project: Project) {
  val mainClassesDir = project.layout.buildDirectory.dir("classes/java/main")
  val mainResourcesDir = project.layout.buildDirectory.dir("resources/main")
}

data class SelectiveLeafOutputOwnership(
  val leaf: Project,
  val metadataFile: File,
  val patterns: List<String>,
) {
  val pruneTaskName: String =
    "prune" +
      leaf.name.split("-").joinToString(separator = "") { segment ->
        segment.replaceFirstChar { firstChar ->
          if (firstChar.isLowerCase()) firstChar.titlecase() else firstChar.toString()
        }
      } +
      "OwnedOutputsFromNonOwners"
}

fun parseOwnedOutputPatterns(metadataFile: File): List<String> = metadataFile.useLines { lines ->
  lines.map(String::trim).filter { it.isNotEmpty() && !it.startsWith("#") }.toList()
}

val selectiveLeafOwnershipMetadataRelativePath = "gradle/owned-output-patterns.txt"

val aggregatedMainOutputProducers =
  (listOf(project) + internalLeafProjects).map(::AggregatedMainOutputProducer)

// Every extracted internal leaf declares aggregated main-output ownership metadata under
// <leaf>/gradle/owned-output-patterns.txt.
// We need this for structurally separated root -> leaf and leaf -> leaf moves.
// Stale outputs can survive in root or old leaf build directories on non-clean builds or branch
// switches.
// Root packaging/runtime aggregation still consumes the root main output and every internal leaf
// main output.
val selectiveLeafOutputOwnerships = internalLeafProjects.map { leaf ->
  val metadataFile =
    leaf.layout.projectDirectory.file(selectiveLeafOwnershipMetadataRelativePath).asFile
  if (!metadataFile.isFile) {
    throw GradleException(
      "Missing ${relativePath(leaf.projectDir)}/$selectiveLeafOwnershipMetadataRelativePath " +
        "for ${leaf.path}. Add leaf-owned aggregated main-output ownership metadata before " +
        "extracting root or leaf outputs into this leaf."
    )
  }
  SelectiveLeafOutputOwnership(
    leaf = leaf,
    metadataFile = metadataFile,
    patterns = parseOwnedOutputPatterns(metadataFile),
  )
}

val verifySelectiveLeafOwnershipMetadata by tasks.registering {
  group = "verification"
  description =
    "Verifies leaf-owned aggregated main-output ownership metadata for selective extractions"
  doLast {
    val currentOwnerships = selectiveLeafOutputOwnerships.map { ownership ->
      ownership.copy(patterns = parseOwnedOutputPatterns(ownership.metadataFile))
    }

    val emptyMetadataFiles =
      currentOwnerships.filter { it.patterns.isEmpty() }.map { relativePath(it.metadataFile) }
    if (emptyMetadataFiles.isNotEmpty()) {
      throw GradleException(
        "Selective leaf aggregated main-output ownership metadata must not be empty: " +
          emptyMetadataFiles.sorted().joinToString(", ")
      )
    }

    val duplicatePatternsWithinFile = currentOwnerships.mapNotNull { ownership ->
      val duplicatePatterns =
        ownership.patterns.groupingBy { it }.eachCount().filterValues { it > 1 }.keys.sorted()
      if (duplicatePatterns.isEmpty()) {
        null
      } else {
        relativePath(ownership.metadataFile) to duplicatePatterns
      }
    }
    if (duplicatePatternsWithinFile.isNotEmpty()) {
      throw GradleException(
        buildString {
          appendLine(
            "Duplicate patterns found within selective leaf aggregated main-output ownership metadata:"
          )
          duplicatePatternsWithinFile.forEach { (metadataPath, duplicatePatterns) ->
            appendLine("$metadataPath: ${duplicatePatterns.joinToString(", ")}")
          }
        }
      )
    }

    val duplicatePatternsAcrossLeaves =
      currentOwnerships
        .flatMap { ownership ->
          ownership.patterns.map { pattern -> pattern to ownership.leaf.path }
        }
        .groupBy(keySelector = { it.first }, valueTransform = { it.second })
        .mapValues { (_, owningLeaves) -> owningLeaves.distinct().sorted() }
        .filterValues { it.size > 1 }
    if (duplicatePatternsAcrossLeaves.isNotEmpty()) {
      throw GradleException(
        buildString {
          appendLine(
            "Duplicate aggregated main-output ownership patterns claimed by multiple selective leaf projects:"
          )
          duplicatePatternsAcrossLeaves.toSortedMap().forEach { (pattern, owningLeaves) ->
            appendLine("$pattern: ${owningLeaves.joinToString(", ")}")
          }
        }
      )
    }
  }
}

fun ownedOutputTreesFor(producer: AggregatedMainOutputProducer, patterns: List<String>) =
  listOf(
    fileTree(producer.mainClassesDir) { include(*patterns.toTypedArray()) },
    fileTree(producer.mainResourcesDir) { include(*patterns.toTypedArray()) },
  )

val selectiveLeafOutputPruneTasks = selectiveLeafOutputOwnerships.associate { ownership ->
  ownership.leaf.path to
    tasks.register<Delete>(ownership.pruneTaskName) {
      val staleOutputTrees =
        aggregatedMainOutputProducers
          .filter { producer -> producer.project != ownership.leaf }
          .flatMap { producer -> ownedOutputTreesFor(producer, ownership.patterns) }
      group = "build"
      description =
        "Removes stale non-owner aggregated main outputs for paths owned by ${ownership.leaf.path} on non-clean builds"
      dependsOn(verifySelectiveLeafOwnershipMetadata)
      outputs.upToDateWhen { false }
      delete(staleOutputTrees)
    }
}

val pruneSelectiveLeafOutputs by tasks.registering {
  group = "build"
  description =
    "Removes stale aggregated main outputs claimed by selectively extracted leaf projects on non-clean builds"
  dependsOn(verifySelectiveLeafOwnershipMetadata)
  dependsOn(selectiveLeafOutputPruneTasks.values)
}

fun Project.wireSelectiveLeafOutputPruning(
  pruneTask: TaskProvider<out Task>,
  taskNames: Set<String>,
) {
  tasks.matching { task -> task.name in taskNames }.configureEach { dependsOn(pruneTask) }
}

val sharedSelectiveLeafPruneTaskNames =
  setOf(
    "compileJava",
    "processResources",
    "classes",
    "jar",
    "compileTestJava",
    "processTestResources",
    "testClasses",
    "test",
    "jacocoTestReport",
    "jacocoTestCoverageVerification",
    "sonar",
    "sonarqube",
    "sonarResolver",
    "sonarlintFile",
    "sonarlintMain",
    "sonarlintTest",
  )

val rootSelectiveLeafPruneTaskNames =
  sharedSelectiveLeafPruneTaskNames +
    setOf("copyResourcesToClasses2", "buildJar", "run", "runLauncher", "printDirs")

val legacyRuntimeAlertsMainPackageDir =
  layout.buildDirectory.dir("classes/java/main/network/crypta/node/useralerts")

val legacyRuntimeAlertsTestPackageDir =
  layout.buildDirectory.dir("classes/java/test/network/crypta/node/useralerts")

val legacyPlatformApphostRootTestPackageDir =
  layout.buildDirectory.dir("classes/java/test/network/crypta/platform/apphost")

// Selective leaf ownership metadata only covers root <-> leaf and leaf <-> leaf moves.
// Root-local package re-homes still need explicit stale-output pruning, so non-clean builds and
// branch switches do not keep packaging deleted classes from the old package path.
val pruneLegacyRuntimeAlertsOutputs by
  tasks.registering(Delete::class) {
    val staleOutputTrees =
      listOf(
        legacyRuntimeAlertsMainPackageDir,
        fileTree(layout.buildDirectory.dir("classes/java/main")) {
          include("network/crypta/node/runtime/UserAlertManagerStoreAlertSink*.class")
        },
        legacyRuntimeAlertsTestPackageDir,
        fileTree(layout.buildDirectory.dir("classes/java/test")) {
          include("network/crypta/node/runtime/UserAlertManagerStoreAlertSinkTest*.class")
        },
      )
    group = "build"
    description =
      "Removes stale pre-rehome runtime alert outputs from root build directories on non-clean builds"
    outputs.upToDateWhen { false }
    delete(staleOutputTrees)
  }

val pruneLegacyPlatformApphostRootTestOutputs by
  tasks.registering(Delete::class) {
    val staleOutputTrees = listOf(legacyPlatformApphostRootTestPackageDir)
    group = "build"
    description =
      "Removes stale root AppHost test outputs after the focused suite moved into :platform-apphost"
    outputs.upToDateWhen { false }
    delete(staleOutputTrees)
  }

internalLeafProjects.forEach { leaf ->
  leaf.wireSelectiveLeafOutputPruning(pruneSelectiveLeafOutputs, sharedSelectiveLeafPruneTaskNames)
  leaf.extensions.configure<org.sonarqube.gradle.SonarExtension>("sonar") { isSkipProject = true }
}

project.wireSelectiveLeafOutputPruning(pruneSelectiveLeafOutputs, rootSelectiveLeafPruneTaskNames)

project.wireSelectiveLeafOutputPruning(
  pruneLegacyRuntimeAlertsOutputs,
  rootSelectiveLeafPruneTaskNames,
)

project.wireSelectiveLeafOutputPruning(
  pruneLegacyPlatformApphostRootTestOutputs,
  rootSelectiveLeafPruneTaskNames,
)

extensions.extraProperties["cryptad.additionalSonarTestSourceDirs"] = internalLeafTestSourceDirs

extensions.extraProperties["cryptad.additionalSonarTestResultDirs"] = internalLeafTestResultDirs

extensions.extraProperties["cryptad.additionalSonarMainSourceDirs"] =
  internalLeafMainJavaSourceDirs.map {
    it.asFile
  }

extensions.extraProperties["cryptad.additionalSonarMainOutputDirs"] =
  internalLeafMainClassDirs.map {
    it.get().asFile
  }

tasks.named<org.gradle.jvm.tasks.Jar>("buildJar") {
  dependsOn(pruneSelectiveLeafOutputs)
  dependsOn(pruneLegacyRuntimeAlertsOutputs)
  dependsOn(internalLeafProjects.map { "${it.path}:classes" })
  internalLeafProjects.forEach { leaf ->
    from(leaf.extensions.getByType(SourceSetContainer::class.java).named("main").map { it.output })
  }
}

tasks.named<Copy>("prepareWrapperLibs") {
  exclude { details -> details.file.name in internalLeafJarNames.get() }
}

tasks.named<JacocoReport>("jacocoTestReport") {
  dependsOn(internalLeafProjects.map { "${it.path}:classes" })
  dependsOn(internalLeafProjectsWithLocalTests.map { "${it.path}:test" })
  executionData.setFrom(
    files(layout.buildDirectory.file("jacoco/test.exec"), internalLeafJacocoExecFiles)
  )
  classDirectories.setFrom(
    files(sourceSets.main.get().output.classesDirs, internalLeafMainClassDirs)
  )
  sourceDirectories.setFrom(
    files(sourceSets.main.get().java.srcDirs, internalLeafMainJavaSourceDirs)
  )
}

tasks.named<JacocoCoverageVerification>("jacocoTestCoverageVerification") {
  dependsOn(internalLeafProjects.map { "${it.path}:classes" })
  dependsOn(internalLeafProjectsWithLocalTests.map { "${it.path}:test" })
  executionData.setFrom(
    files(layout.buildDirectory.file("jacoco/test.exec"), internalLeafJacocoExecFiles)
  )
  classDirectories.setFrom(
    files(sourceSets.main.get().output.classesDirs, internalLeafMainClassDirs)
  )
  sourceDirectories.setFrom(
    files(sourceSets.main.get().java.srcDirs, internalLeafMainJavaSourceDirs)
  )
}

tasks.named("prepareTestExecutionReport") {
  dependsOn(internalLeafProjectsWithLocalTests.map { "${it.path}:test" })
}

sonar {
  properties {
    property("sonar.sources", aggregatedSonarSourcePaths)
    property("sonar.java.binaries", aggregatedSonarBinaryPaths)
    property("sonar.java.libraries", aggregatedSonarLibraryFiles)
    property("sonar.tests", aggregatedSonarTestPaths)
    property("sonar.test.inclusions", aggregatedSonarTestInclusions)
  }
}

// Utility task to print the project version
tasks.register("printVersion") {
  group = "help"
  description = "Prints the project version"
  doLast { println(project.version.toString()) }
}

tasks.register("stageFirstPartyApps") {
  group = "build"
  description = "Stages the repo-owned first-party AppHost bundles."
  dependsOn(":apps:queue-manager:stageApp")
  dependsOn(":apps:publisher:stageApp")
  dependsOn(":apps:feed-reader:stageApp")
  dependsOn(":apps:profile-publisher:stageApp")
  dependsOn(":apps:social-inbox:stageApp")
  dependsOn(":apps:site-publisher:stageApp")
  dependsOn(":apps:trust-graph:stageApp")
}

tasks.register("signFirstPartyApps") {
  group = "build"
  description = "Signs the repo-owned first-party AppHost bundles."
  dependsOn(":apps:queue-manager:signApp")
  dependsOn(":apps:publisher:signApp")
  dependsOn(":apps:feed-reader:signApp")
  dependsOn(":apps:profile-publisher:signApp")
  dependsOn(":apps:social-inbox:signApp")
  dependsOn(":apps:site-publisher:signApp")
  dependsOn(":apps:trust-graph:signApp")
}

tasks.register("verifyFirstPartyApps") {
  group = "verification"
  description = "Verifies the signed repo-owned first-party AppHost bundles."
  dependsOn(":apps:queue-manager:verifyApp")
  dependsOn(":apps:publisher:verifyApp")
  dependsOn(":apps:feed-reader:verifyApp")
  dependsOn(":apps:profile-publisher:verifyApp")
  dependsOn(":apps:social-inbox:verifyApp")
  dependsOn(":apps:site-publisher:verifyApp")
  dependsOn(":apps:trust-graph:verifyApp")
  mustRunAfter("signFirstPartyApps")
}

tasks.register("packageFirstPartyApps") {
  group = "build"
  description = "Packages the signed repo-owned first-party AppHost bundles deterministically."
  dependsOn(":apps:queue-manager:packageApp")
  dependsOn(":apps:publisher:packageApp")
  dependsOn(":apps:feed-reader:packageApp")
  dependsOn(":apps:profile-publisher:packageApp")
  dependsOn(":apps:social-inbox:packageApp")
  dependsOn(":apps:site-publisher:packageApp")
  dependsOn(":apps:trust-graph:packageApp")
}

tasks.register("packageUnsignedFirstPartyAppsForIndependentReproducibility") {
  group = "build"
  description = "Packages unsigned first-party app payloads for provider-distinct reproducibility."
  dependsOn(":apps:queue-manager:packageUnsignedAppForIndependentReproducibility")
  dependsOn(":apps:publisher:packageUnsignedAppForIndependentReproducibility")
  dependsOn(":apps:feed-reader:packageUnsignedAppForIndependentReproducibility")
  dependsOn(":apps:profile-publisher:packageUnsignedAppForIndependentReproducibility")
  dependsOn(":apps:social-inbox:packageUnsignedAppForIndependentReproducibility")
  dependsOn(":apps:site-publisher:packageUnsignedAppForIndependentReproducibility")
  dependsOn(":apps:trust-graph:packageUnsignedAppForIndependentReproducibility")
}

// The default from build-logic (512m) is too small for the full test suite on Windows and can
// trigger OOM in long-running integration tests.
tasks.withType<Test>().configureEach { maxHeapSize = "2g" }

// The convention-plugin build is included rather than a root subproject, so explicitly make its
// deterministic packaging tests part of the repository's canonical test entry point.
tasks.named<Test>("test") { dependsOn(gradle.includedBuild("build-logic").task(":test")) }

// Application entrypoint (used by jpackage). This does not change how we build the wrapper
// distribution; it's only to inform launchers that invoke the launcher main class directly.
// Align with the actual launcher entrypoint in Launcher.java
application { mainClass.set("network.crypta.launcher.Launcher") }

val nodeRuntimeJvmArgs =
  listOf(
    "-Dnetworkaddress.cache.ttl=0",
    "-Dnetworkaddress.cache.negative.ttl=0",
    "-Djava.net.preferIPv4Stack=false",
    "--enable-native-access=ALL-UNNAMED",
    "--add-opens=java.base/java.lang=ALL-UNNAMED",
    "--add-opens=java.base/java.util=ALL-UNNAMED",
    "--add-opens=java.base/java.io=ALL-UNNAMED",
    "--add-opens=java.base/sun.nio.ch=ALL-UNNAMED",
    "-enableassertions:freenet",
  )

tasks.named<JavaExec>("run") {
  description = "Runs Cryptad daemon via NodeStarter"
  mainClass.set("network.crypta.runtime.bootstrap.NodeStarter")
  jvmArgs(nodeRuntimeJvmArgs)
}

tasks.register<JavaExec>("runLauncher") {
  group = "application"
  description = "Runs the Cryptad Swing launcher"
  javaLauncher.set(javaToolchains.launcherFor { languageVersion.set(JavaLanguageVersion.of(25)) })
  mainClass.set("network.crypta.launcher.Launcher")
  classpath = sourceSets.main.get().runtimeClasspath
  jvmArgs("--enable-native-access=ALL-UNNAMED")
}

// Sonar configuration is applied via the build-logic convention plugin 'cryptad.sonar'
