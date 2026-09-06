import cryptad.PortableArchiveNormalizer
import cryptad.selectStableJava25
import java.io.ByteArrayOutputStream
import java.util.concurrent.TimeUnit

plugins { java }

// We keep our existing custom distribution (assembleCryptadDist) intact.
// This plugin builds a jlink image directly (no external runtime plugin).

val cryptadDistDir: Provider<Directory> = layout.buildDirectory.dir("cryptad-dist")
val jlinkImageDir: Provider<Directory> = layout.buildDirectory.dir("cryptad-jlink-image")

// No application plugin: the launchers below invoke the main class directly

// jdeps prefers a versioned jar; copy our custom jar to that name
val syncRuntimeJar by tasks.registering {
  group = "build"
  description = "Copies cryptad.jar to build/libs/cryptad-<version>.jar for jdeps"
  dependsOn(tasks.named("buildJar"))
  // Capture values during configuration to avoid Task.project access at execution
  val libsDir = layout.buildDirectory.dir("libs")
  val versionStr = providers.provider { project.version.toString() }
  doLast {
    val libs = libsDir.get().asFile
    val src = libs.resolve("cryptad.jar")
    val dst = libs.resolve("cryptad-${versionStr.get()}.jar")
    if (!src.isFile) throw GradleException("Expected JAR not found: ${src.absolutePath}")
    src.copyTo(dst, overwrite = true)
  }
}

// No external runtime plugin configuration; jlink is invoked below

// The plugin doesn't patch our existing bin/cryptad script (Tanuki Wrapper).
// No separate jlink-specific launchers; we reuse dist/bin scripts and wrapper binaries

// Discover Java modules with jdeps for the assembled app classpath
@CacheableTask
abstract class ComputeJlinkModules @Inject constructor(private val execOps: ExecOperations) :
  DefaultTask() {
  // The JAR content determines the jdeps output; path should not.
  @get:InputFile @get:Classpath abstract val cryptadJar: RegularFileProperty

  // Treat the classpath as a content-addressed input for caching across machines.
  @get:InputFiles @get:Classpath abstract val classpath: ConfigurableFileCollection

  @get:Input abstract val javaLanguageVersion: Property<Int>

  // Provide JDK home explicitly to avoid accessing Project services during execution
  @get:Input abstract val javaHomePath: Property<String>

  @get:OutputFile abstract val modulesFile: RegularFileProperty

  @get:Input abstract val baselineModules: ListProperty<String>

  @TaskAction
  fun compute() {
    val jarFile = cryptadJar.get().asFile
    require(jarFile.isFile) { "Missing ${jarFile.absolutePath}" }

    val javaHome = File(javaHomePath.get())
    val jdeps =
      javaHome.resolve(
        "bin/jdeps${
                        if (System.getProperty("os.name").lowercase().contains("win")) ".exe" else ""
                    }"
      )

    val classpathArg =
      classpath.files
        .filter { it.isFile && it.extension == "jar" && it.name != jarFile.name }
        .joinToString(File.pathSeparator) { it.absolutePath }

    val args =
      mutableListOf(
          jdeps.absolutePath,
          "--ignore-missing-deps",
          "--multi-release",
          javaLanguageVersion.get().toString(),
          "--print-module-deps",
          "-q",
        )
        .apply {
          if (classpathArg.isNotBlank()) addAll(listOf("-cp", classpathArg))
          add(jarFile.absolutePath)
        }

    val out = ByteArrayOutputStream()
    val result = execOps.exec {
      commandLine(args)
      standardOutput = out
      isIgnoreExitValue = true
    }
    val exit = result.exitValue
    val detected = out.toString().trim().removeSuffix(",")

    if (exit != 0 || detected.isBlank()) {
      throw GradleException("jdeps failed to produce the exact runtime module inventory")
    }
    val baseline = baselineModules.get().toSet()
    val modules: Set<String> =
      detected.split(',').map { it.trim() }.filter { it.isNotEmpty() }.toSet() + baseline

    val outFile = modulesFile.get().asFile
    outFile.parentFile.mkdirs()
    outFile.writeText(modules.sorted().joinToString(","))
    println("jdeps modules -> ${outFile.absolutePath}:\n" + modules.sorted().joinToString(","))
  }
}

val computeJlinkModules by
  tasks.registering(ComputeJlinkModules::class) {
    group = "distribution"
    description = "Computes required Java modules using jdeps and writes build/jlink/modules.list"
    dependsOn(syncRuntimeJar, tasks.named("assembleCryptadDist"))

    // Inputs: jars from the assembled distribution
    val libsDirProvider = cryptadDistDir.map { it.dir("lib").asFile }
    cryptadJar.set(project.layout.file(libsDirProvider.map { it.resolve("cryptad.jar") }))
    classpath.from(
      project.provider {
        val d = libsDirProvider.get()
        d.listFiles { f -> f.isFile && f.name.endsWith(".jar") }?.toList() ?: emptyList()
      }
    )

    // Output
    modulesFile.set(layout.buildDirectory.file("jlink/modules.list"))

    // Toolchain + baseline
    javaLanguageVersion.set(25)
    // Resolve the toolchain at configuration time and pass JDK home path as input
    val launcher = javaToolchains.launcherFor { selectStableJava25() }
    javaHomePath.set(launcher.map { it.metadata.installationPath.asFile.absolutePath })
    baselineModules.set(
      listOf(
        "jdk.crypto.ec",
        // Needed by dbus-java to access com.sun.security.auth.module.UnixSystem
        "jdk.security.auth",
        "jdk.charsets",
        "jdk.localedata",
        "jdk.unsupported",
        "jdk.zipfs",
        "jdk.httpserver",
        "java.net.http",
        "java.desktop",
      )
    )
  }

// --- Custom jlink flow for Gradle 9 compatibility ---
// Some runtime plugin variants are not yet Gradle 9 compatible. Provide a direct jlink path.
val createJreImage by tasks.registering {
  group = "distribution"
  description = "Creates a minimal JRE with jlink into build/jre"
  dependsOn(computeJlinkModules)
  // Resolve toolchain and static inputs at configuration time to avoid Task.project access.
  // Every value consumed by jlink must participate in Gradle's up-to-date decision; otherwise an
  // existing build/jre could be silently reused after its module set, compression, or toolchain
  // changes.
  val launcher = javaToolchains.launcherFor { selectStableJava25() }
  val javaHomeDirectoryProvider = launcher.map { it.metadata.installationPath }
  val osName = System.getProperty("os.name").lowercase()
  val jlinkExecutableProvider = javaHomeDirectoryProvider.map {
    it.file("bin/jlink${if (osName.contains("win")) ".exe" else ""}")
  }
  val jmodsDirectoryProvider = javaHomeDirectoryProvider.map { it.dir("jmods") }
  val jlinkModuleSourceProvider = javaHomeDirectoryProvider.map { javaHome ->
    val jmods = javaHome.dir("jmods").asFile
    if (jmods.isDirectory) jmods else javaHome.file("lib/modules").asFile
  }
  val modulesFileProvider = layout.buildDirectory.file("jlink/modules.list")
  val jlinkCompressionProvider =
    providers
      .gradleProperty("jlinkCompression")
      .map { it.trim().ifBlank { "zip-6" } }
      .orElse("zip-6")
  val javaLanguageVersionProvider = launcher.map { it.metadata.languageVersion.toString() }
  val javaVendorProvider = launcher.map { it.metadata.vendor }
  val javaRuntimeVersionProvider = launcher.map { it.metadata.javaRuntimeVersion }
  val jvmVersionProvider = launcher.map { it.metadata.jvmVersion }
  val javaArchitectureProvider = providers.systemProperty("os.arch")
  val jreDirProvider = layout.buildDirectory.dir("jre")

  inputs
    .file(modulesFileProvider)
    .withPropertyName("runtimeModules")
    .withPathSensitivity(PathSensitivity.NONE)
  inputs
    .file(jlinkExecutableProvider)
    .withPropertyName("jlinkExecutable")
    .withPathSensitivity(PathSensitivity.NONE)
  inputs
    .files(jlinkModuleSourceProvider)
    .withPropertyName("jlinkModuleSource")
    .withPathSensitivity(PathSensitivity.RELATIVE)
  inputs.property("jlinkCompression", jlinkCompressionProvider)
  inputs.property("javaLanguageVersion", javaLanguageVersionProvider)
  inputs.property("javaVendor", javaVendorProvider)
  inputs.property("javaRuntimeVersion", javaRuntimeVersionProvider)
  inputs.property("jvmVersion", jvmVersionProvider)
  inputs.property("javaArchitecture", javaArchitectureProvider)
  outputs.dir(jreDirProvider)

  doLast {
    val jlink = jlinkExecutableProvider.get().asFile
    val jmods = jmodsDirectoryProvider.get().asFile
    val jlinkModuleSource = jlinkModuleSourceProvider.get()
    if (!jlinkModuleSource.exists()) {
      throw GradleException("Java toolchain has no jlink module source")
    }

    val jreDir = jreDirProvider.get().asFile
    if (jreDir.exists()) jreDir.deleteRecursively()

    val modulesFile = modulesFileProvider.get().asFile
    if (!modulesFile.isFile) {
      throw GradleException("jlink module inventory is missing")
    }
    val modulesArg = modulesFile.readText(Charsets.UTF_8).trim()
    if (modulesArg.isBlank()) {
      throw GradleException("jlink module inventory is empty")
    }
    val jlinkCompression = jlinkCompressionProvider.get()

    val args =
      mutableListOf(jlink.absolutePath, "-v", "--strip-debug", "--compress", jlinkCompression)
    args.addAll(listOf("--no-header-files", "--no-man-pages"))
    if (jmods.isDirectory) {
      args.addAll(listOf("--module-path", jmods.absolutePath))
    }
    args.addAll(listOf("--add-modules", modulesArg, "--output", jreDir.absolutePath))

    println("Executing jlink: ${args.joinToString(" ")}")
    val process = ProcessBuilder(args).redirectErrorStream(true).start()
    val outputPump = Thread {
      process.inputStream.bufferedReader().useLines { lines ->
        lines.forEach { line -> logger.lifecycle(line) }
      }
    }
      .apply {
        name = "jlink-output-pump"
        isDaemon = true
        start()
      }

    val completed = process.waitFor(10, TimeUnit.MINUTES)
    outputPump.join(2_000)
    if (!completed) {
      val jreReady =
        (jreDir.resolve("release").isFile &&
          jreDir.resolve("lib/modules").isFile &&
          (jreDir.resolve("bin/java.exe").isFile || jreDir.resolve("bin/java").isFile))
      if (jreReady) {
        logger.warn(
          "jlink did not exit, but the runtime image is complete. Terminating lingering jlink process."
        )
        process.destroyForcibly()
        return@doLast
      }
      process.destroyForcibly()
      throw GradleException("jlink timed out after 10 minutes")
    }

    val exit = process.exitValue()
    if (exit != 0) {
      throw GradleException("jlink failed with exit code $exit")
    }
  }
}

@CacheableTask
abstract class InventoryJreModules @Inject constructor(private val execOps: ExecOperations) :
  DefaultTask() {
  @get:InputDirectory
  @get:PathSensitive(PathSensitivity.RELATIVE)
  abstract val runtimeImage: DirectoryProperty

  @get:OutputFile abstract val modulesFile: RegularFileProperty

  @TaskAction
  fun inventory() {
    val image = runtimeImage.get().asFile
    val java =
      image.resolve(
        "bin/java${if (System.getProperty("os.name").lowercase().contains("win")) ".exe" else ""}"
      )
    if (!java.isFile) throw GradleException("jlink runtime image has no Java launcher")
    val out = ByteArrayOutputStream()
    val result = execOps.exec {
      commandLine(java.absolutePath, "--list-modules")
      standardOutput = out
      isIgnoreExitValue = true
    }
    val modulePattern = Regex("^([a-z][a-z0-9.]*)@[A-Za-z0-9._+~-]+$")
    val modules =
      out
        .toString(Charsets.UTF_8)
        .lineSequence()
        .filter(String::isNotBlank)
        .map { line ->
          modulePattern.matchEntire(line.trim())?.groupValues?.get(1)
            ?: throw GradleException("jlink runtime reported a malformed module identity")
        }
        .toList()
        .sorted()
        .distinct()
    if (result.exitValue != 0 || modules.isEmpty()) {
      throw GradleException("jlink runtime failed to report its exact module inventory")
    }
    val output = modulesFile.get().asFile
    output.parentFile.mkdirs()
    output.writeText(modules.joinToString(","), Charsets.UTF_8)
  }
}

val inventoryJreModules by
  tasks.registering(InventoryJreModules::class) {
    group = "distribution"
    description = "Inventories the complete module closure in the generated jlink runtime"
    dependsOn(createJreImage)
    runtimeImage.set(layout.buildDirectory.dir("jre"))
    modulesFile.set(layout.buildDirectory.file("jlink/runtime-modules.list"))
  }

val prepareJlinkImage by tasks.registering {
  group = "distribution"
  description = "Assembles build/cryptad-jlink-image from build/jre and cryptad-dist"
  dependsOn(createJreImage, tasks.named("assembleCryptadDist"))
  doLast {
    val image = jlinkImageDir.get().asFile
    if (image.exists()) image.deleteRecursively()
    image.mkdirs()

    // Copy the jlink runtime to the image root (bin, lib, etc.)
    copy {
      from(layout.buildDirectory.dir("jre"))
      into(image)
    }
    // Merge our app distribution (lib + conf + bin). We include the wrapper binary folder and
    // launch scripts alongside the jlink bin; Gradle copy merges directories, no JRE tools are
    // overwritten because dist/bin doesn't contain them.
    copy {
      from(cryptadDistDir.get().asFile)
      into(image)
      include("lib/**", "conf/**")
    }
    // Bring over wrapper executables and launchers into the image/bin
    copy {
      from(cryptadDistDir.get().asFile.resolve("bin"))
      into(image.resolve("bin"))
      include("**/*")
    }
  }
}

// Zip the jlink image with a predictable name
val distZipCryptadJlink by
  tasks.registering(Zip::class) {
    group = "distribution"
    description = "Packages the jlink runtime image as a zip"
    dependsOn(prepareJlinkImage)
    archiveBaseName.set("cryptad-jlink")
    archiveVersion.set("v${project.version}")
    archiveFileName.set("cryptad-jlink-v${project.version}.zip")
    from(jlinkImageDir)
    destinationDirectory.set(layout.buildDirectory.dir("distributions"))
    isPreserveFileTimestamps = false
    isReproducibleFileOrder = true
    eachFile {
      val memberPermissions = PortableArchiveNormalizer.unixPermissionsForMember(path)
      permissions { unix(memberPermissions) }
    }
    dirPermissions { unix("0755") }
    doLast { PortableArchiveNormalizer.normalize(archiveFile.get().asFile.toPath()) }
  }

// Tar.gz counterpart for convenience
val distTarCryptadJlink by
  tasks.registering(Tar::class) {
    group = "distribution"
    description = "Packages the jlink runtime image as a tar.gz"
    dependsOn(prepareJlinkImage)
    compression = Compression.GZIP
    archiveBaseName.set("cryptad-jlink")
    archiveVersion.set("v${project.version}")
    archiveFileName.set("cryptad-jlink-v${project.version}.tar.gz")
    from(jlinkImageDir)
    destinationDirectory.set(layout.buildDirectory.dir("distributions"))
    isPreserveFileTimestamps = false
    isReproducibleFileOrder = true
    eachFile {
      val memberPermissions = PortableArchiveNormalizer.unixPermissionsForMember(path)
      permissions { unix(memberPermissions) }
    }
    dirPermissions { unix("0755") }
    doLast { PortableArchiveNormalizer.normalize(archiveFile.get().asFile.toPath()) }
  }

// Aggregate task
tasks.register("distJlinkCryptad") {
  group = "distribution"
  description = "Builds all jlink-based Cryptad distribution archives"
  dependsOn(distZipCryptadJlink, distTarCryptadJlink)
}

// Make the standard 'dist' also produce the jlink archives
tasks.named("dist") { dependsOn("distJlinkCryptad") }
