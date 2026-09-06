import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions
import org.gradle.api.tasks.PathSensitivity

plugins {
  id("cryptad.java-kotlin-conventions")
  id("cryptad.spotless")
  `java-library`
}

version = rootProject.version

val appDisplayName = "Trust Graph Local RC"
val appId = "trust-graph"
val appDistMainClass = "network.crypta.platform.appdist.AppDistributionTool"
val mainSourceSet = sourceSets.named("main")
val appDistCli by configurations.creating
val stageAppDir = layout.buildDirectory.dir("cryptad-app/$appId")
val generatedManifestDir = layout.buildDirectory.dir("generated/stageApp")
val packagedAppFile = layout.buildDirectory.file("cryptad-app-bundle/$appId-${project.version}.zip")
val reproducibilityPayloadFile =
  layout.buildDirectory.file("cryptad-app-reproducibility-payload/$appId-${project.version}.zip")
val stageAssetsDir = layout.projectDirectory.dir("src/staged")
val manifestTemplateFile = stageAssetsDir.file("cryptad-app.properties.template")
val platformDesignSystemResourceDir =
  project(":platform-design-system")
    .layout
    .projectDirectory
    .dir("src/main/resources/network/crypta/platform/designsystem/static")
val platformSdkJsFile =
  project(":platform-sdk-js")
    .layout
    .projectDirectory
    .file("src/main/resources/network/crypta/platform/sdk/js/crypta-platform.js")
val launcherRelativePath = "bin/trust-graph.sh"
val appDistPrivateKeyEnvironmentName = "CRYPTAD_APP_DIST_PRIVATE_KEY_BASE64"
val stagedLauncher = stageAppDir.map { stageDirectory ->
  stageDirectory.file(launcherRelativePath).asFile.toPath()
}

fun Project.optionalSigningInput(propertyName: String, environmentName: String): String? =
  providers
    .gradleProperty(propertyName)
    .orElse(providers.environmentVariable(environmentName))
    .orNull
    ?.trim()
    ?.takeIf { it.isNotEmpty() }

fun Project.requiredSigningInput(
  propertyName: String,
  environmentName: String,
  taskName: String,
): String =
  optionalSigningInput(propertyName, environmentName)
    ?: throw GradleException("$taskName requires -P$propertyName or $environmentName to be set.")

fun Project.addPrivateKeyArguments(
  task: JavaExec,
  taskName: String,
  arguments: MutableList<String>,
) {
  val privateKeyBase64 =
    optionalSigningInput(
      "cryptadAppSigningPrivateKeyBase64",
      "CRYPTAD_APP_SIGNING_PRIVATE_KEY_BASE64",
    )
  val privateKeyFile =
    optionalSigningInput("cryptadAppSigningPrivateKeyFile", "CRYPTAD_APP_SIGNING_PRIVATE_KEY_FILE")
  when {
    privateKeyBase64 != null && privateKeyFile != null ->
      throw GradleException(
        "$taskName requires app signing private key material from " +
          "exactly one of -PcryptadAppSigningPrivateKeyBase64 / " +
          "CRYPTAD_APP_SIGNING_PRIVATE_KEY_BASE64 or -PcryptadAppSigningPrivateKeyFile / " +
          "CRYPTAD_APP_SIGNING_PRIVATE_KEY_FILE."
      )
    privateKeyBase64 != null -> {
      task.environment(appDistPrivateKeyEnvironmentName, privateKeyBase64)
      arguments += listOf("--private-key-env", appDistPrivateKeyEnvironmentName)
    }
    privateKeyFile != null ->
      arguments += listOf("--private-key-file", file(privateKeyFile).absolutePath)
    else ->
      throw GradleException(
        "$taskName requires app signing private key material via " +
          "-PcryptadAppSigningPrivateKeyBase64 / CRYPTAD_APP_SIGNING_PRIVATE_KEY_BASE64 or " +
          "-PcryptadAppSigningPrivateKeyFile / CRYPTAD_APP_SIGNING_PRIVATE_KEY_FILE."
      )
  }
}

fun Project.addPublicKeyArguments(taskName: String, arguments: MutableList<String>) {
  val publicKeyBase64 =
    optionalSigningInput(
      "cryptadAppSigningPublicKeyBase64",
      "CRYPTAD_APP_SIGNING_PUBLIC_KEY_BASE64",
    )
  val publicKeyFile =
    optionalSigningInput("cryptadAppSigningPublicKeyFile", "CRYPTAD_APP_SIGNING_PUBLIC_KEY_FILE")
  when {
    publicKeyBase64 != null && publicKeyFile != null ->
      throw GradleException(
        "$taskName requires app signing public key material from " +
          "exactly one of -PcryptadAppSigningPublicKeyBase64 / " +
          "CRYPTAD_APP_SIGNING_PUBLIC_KEY_BASE64 or -PcryptadAppSigningPublicKeyFile / " +
          "CRYPTAD_APP_SIGNING_PUBLIC_KEY_FILE."
      )
    publicKeyBase64 != null -> arguments += listOf("--trusted-public-key-base64", publicKeyBase64)
    publicKeyFile != null ->
      arguments += listOf("--trusted-public-key-file", file(publicKeyFile).absolutePath)
    else ->
      throw GradleException(
        "$taskName requires app signing public key material via " +
          "-PcryptadAppSigningPublicKeyBase64 / CRYPTAD_APP_SIGNING_PUBLIC_KEY_BASE64 or " +
          "-PcryptadAppSigningPublicKeyFile / CRYPTAD_APP_SIGNING_PUBLIC_KEY_FILE."
      )
  }
}

dependencies {
  appDistCli(project(":platform-appdist"))

  testImplementation(mainSourceSet.map { it.output })
  testImplementation(project(":platform-apphost"))
  testImplementation(libs.junitJupiterApi)
  testRuntimeOnly(libs.junitJupiterEngine)
  testRuntimeOnly(libs.junitPlatformLauncher)
}

val generateManifest by
  tasks.registering(Copy::class) {
    from(manifestTemplateFile) {
      rename { "cryptad-app.properties" }
      expand("appVersion" to project.version.toString())
    }
    into(generatedManifestDir)
    filteringCharset = "UTF-8"
  }

val stageApp by
  tasks.registering(Sync::class) {
    group = "build"
    description = "Stages the $appDisplayName AppHost bundle."
    dependsOn(generateManifest)
    into(stageAppDir)
    from(stageAssetsDir) { exclude("cryptad-app.properties.template") }
    from(platformDesignSystemResourceDir) { into("static/crypta-ui") }
    from(platformSdkJsFile) { into("static") }
    from(generatedManifestDir)
    doLast {
      val launcher = stagedLauncher.get()
      if (
        Files.exists(launcher) && Files.getFileStore(launcher).supportsFileAttributeView("posix")
      ) {
        Files.setPosixFilePermissions(launcher, PosixFilePermissions.fromString("rwxr-xr-x"))
      }
    }
  }

val signApp by
  tasks.registering(JavaExec::class) {
    group = "build"
    description = "Signs the staged $appDisplayName AppHost bundle."
    dependsOn(stageApp)
    classpath = appDistCli
    mainClass.set(appDistMainClass)
    inputs
      .dir(stageAppDir)
      .withPropertyName("trustGraphStagedBundleForSigning")
      .withPathSensitivity(PathSensitivity.RELATIVE)
    doFirst {
      val signingTask = this as JavaExec
      val arguments = mutableListOf("sign", "--bundle-dir", stageAppDir.get().asFile.absolutePath)
      arguments +=
        listOf(
          "--key-id",
          requiredSigningInput("cryptadAppSigningKeyId", "CRYPTAD_APP_SIGNING_KEY_ID", name),
        )
      addPrivateKeyArguments(signingTask, name, arguments)
      setArgs(arguments)
    }
  }

val verifyApp by
  tasks.registering(JavaExec::class) {
    group = "verification"
    description = "Verifies the signed staged $appDisplayName AppHost bundle."
    mustRunAfter(signApp)
    classpath = appDistCli
    mainClass.set(appDistMainClass)
    inputs
      .dir(stageAppDir)
      .withPropertyName("trustGraphStagedBundleForVerification")
      .withPathSensitivity(PathSensitivity.RELATIVE)
    doFirst {
      val arguments = mutableListOf("verify", "--bundle-dir", stageAppDir.get().asFile.absolutePath)
      arguments +=
        listOf(
          "--trusted-key-id",
          requiredSigningInput("cryptadAppSigningKeyId", "CRYPTAD_APP_SIGNING_KEY_ID", name),
        )
      addPublicKeyArguments(name, arguments)
      setArgs(arguments)
    }
  }

val packageApp by
  tasks.registering(JavaExec::class) {
    group = "build"
    description = "Packages the signed $appDisplayName AppHost bundle deterministically."
    dependsOn(signApp, verifyApp)
    classpath = appDistCli
    mainClass.set(appDistMainClass)
    inputs
      .dir(stageAppDir)
      .withPropertyName("signedBundleForPackaging")
      .withPathSensitivity(PathSensitivity.RELATIVE)
    outputs.file(packagedAppFile)
    doFirst {
      setArgs(
        listOf(
          "package",
          "--bundle-dir",
          stageAppDir.get().asFile.absolutePath,
          "--output-zip",
          packagedAppFile.get().asFile.absolutePath,
        )
      )
    }
  }

val packageUnsignedAppForIndependentReproducibility by
  tasks.registering(JavaExec::class) {
    group = "build"
    description = "Packages the unsigned $appDisplayName payload for independent reproducibility."
    dependsOn(stageApp)
    classpath = appDistCli
    mainClass.set(appDistMainClass)
    inputs
      .dir(stageAppDir)
      .withPropertyName("unsignedBundleForIndependentReproducibility")
      .withPathSensitivity(PathSensitivity.RELATIVE)
    outputs.file(reproducibilityPayloadFile)
    doFirst {
      val stagedRoot = stageAppDir.get().asFile.toPath()
      val prohibitedSidecars =
        listOf(
          "cryptad-app.digests",
          "cryptad-app.signature",
          "cryptad-app.catalog",
          "cryptad-app.catalog.signature",
        )
      if (prohibitedSidecars.any { Files.exists(stagedRoot.resolve(it)) }) {
        throw GradleException(
          "$name requires an unsigned staged bundle without distribution sidecars."
        )
      }
      setArgs(
        listOf(
          "package",
          "--bundle-dir",
          stageAppDir.get().asFile.absolutePath,
          "--output-zip",
          reproducibilityPayloadFile.get().asFile.absolutePath,
        )
      )
    }
  }

tasks.named<Test>("test") {
  dependsOn(stageApp)
  inputs
    .dir(stageAppDir)
    .withPropertyName("trustGraphStagedBundle")
    .withPathSensitivity(PathSensitivity.RELATIVE)
  inputs.property("trustGraphAppVersion", project.version.toString())
  systemProperty("trustGraph.stageDir", stageAppDir.get().asFile.absolutePath)
  systemProperty("trustGraph.appVersion", project.version.toString())
}
