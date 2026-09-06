import java.io.File
import java.io.IOException
import java.security.MessageDigest

plugins { java }

val gitrev: String =
  try {
    val cmd = "git rev-parse --short HEAD"
    ProcessBuilder(cmd.split(" "))
      .directory(rootDir)
      .start()
      .inputStream
      .bufferedReader()
      .readText()
      .trim()
  } catch (_: IOException) {
    "@unknown@"
  }

val buildJar by
  tasks.registering(Jar::class) {
    dependsOn(tasks.processResources, tasks.compileJava)
    // Include compiled classes and PROCESSED resources (from processResources)
    // Using sourceSets.main.output ensures generated resources under build/resources/** are
    // packaged
    from(sourceSets.main.get().output)
    archiveFileName.set("cryptad.jar")
    isPreserveFileTimestamps = false
    isReproducibleFileOrder = true
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    manifest {
      attributes(
        "Permissions" to "all-permissions",
        "Application-Name" to "Crypta Daemon",
        "Compiled-With" to
          "${System.getProperty("java.version")} (${System.getProperty("java.vendor")})",
        "Specification-Title" to "Crypta",
        "Specification-Version" to project.version.toString(),
        "Specification-Vendor" to "crypta.network",
        "Implementation-Title" to "Crypta",
        "Implementation-Version" to "${project.version} $gitrev",
        "Implementation-Vendor" to "crypta.network",
      )
    }
  }

tasks.named<Jar>("jar") { enabled = false }

// Fail fast if someone explicitly asks for :jar
if (gradle.startParameter.taskNames.any { it == "jar" || it.endsWith(":jar") }) {
  throw GradleException("Task 'jar' is disabled. Use ':buildJar' to build cryptad.jar.")
}

val printHashTask by tasks.registering {
  description = "Prints SHA-256 hashes of built JAR files"
  group = "verification"

  inputs.file(buildJar.flatMap { it.archiveFile })
  outputs.upToDateWhen { false }

  doLast {
    fun hash(file: File) {
      val sha256 = MessageDigest.getInstance("SHA-256")
      file.inputStream().use { input ->
        val buffer = ByteArray(4096)
        while (true) {
          val read = input.read(buffer)
          if (read == -1) break
          sha256.update(buffer, 0, read)
        }
      }
      println("SHA-256 of ${file.name}: " + sha256.digest().joinToString("") { "%02x".format(it) })
    }

    val jarFile = buildJar.get().archiveFile.get().asFile
    if (jarFile.exists()) hash(jarFile)
  }
}

buildJar { finalizedBy(printHashTask) }

tasks.named("build") { dependsOn(buildJar) }
