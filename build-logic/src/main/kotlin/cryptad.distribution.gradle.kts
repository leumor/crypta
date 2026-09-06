import cryptad.PortableArchiveNormalizer
import java.net.HttpURLConnection
import java.net.URI
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.MessageDigest

plugins { java }

val wrapperVersion = "3.6.2"
val wrapperDeltaPack = "wrapper-delta-pack-$wrapperVersion.tar.gz"
val wrapperBaseUrl =
  "https://sourceforge.net/projects/wrapper/files/wrapper/Wrapper_3.6.2_20250605/$wrapperDeltaPack/download"

val wrapperWorkDir: Provider<Directory> = layout.buildDirectory.dir("wrapper")
val wrapperExtractDir: Provider<Directory> = layout.buildDirectory.dir("wrapper/extracted")
val wrapperDistDir: Provider<Directory> = layout.buildDirectory.dir("cryptad-dist")

// Windows wrapper binaries are not present in the delta pack. We fetch them from the latest
// release of crypta-network/wrapper-windows-build.
val wrapperWindowsRepo = "crypta-network/wrapper-windows-build"
val wrapperWindowsApiLatest: Provider<String> =
  providers
    .gradleProperty("wrapperWinApiUrl")
    .orElse("https://api.github.com/repos/$wrapperWindowsRepo/releases/latest")
val wrapperWindowsWorkDir: Provider<Directory> = layout.buildDirectory.dir("wrapper/windows")
// We don't assume a specific archive extension from GitHub assets (.zip or .tar.gz).
// Download to a neutral extension; extraction tasks will auto-detect the type by magic bytes.
val wrapperWindowsAmd64Archive: Provider<RegularFile> = wrapperWindowsWorkDir.map {
  it.file("windows-amd64.bin")
}
val wrapperWindowsArm64Archive: Provider<RegularFile> = wrapperWindowsWorkDir.map {
  it.file("windows-arm64.bin")
}
val wrapperWindowsAmd64Extract: Provider<Directory> = wrapperWindowsWorkDir.map {
  it.dir("extracted-amd64")
}
val wrapperWindowsArm64Extract: Provider<Directory> = wrapperWindowsWorkDir.map {
  it.dir("extracted-arm64")
}

// Seednodes generation settings. Stable release jobs override this with the reviewed full-commit
// archive URL; the branch URL remains only a convenience for ordinary local distribution builds.
val seedrefsZipUrl =
  providers
    .gradleProperty("seedrefsUrl")
    .orElse("https://codeload.github.com/hyphanet/seedrefs/zip/refs/heads/master")
val stableSeedrefsUrlPattern =
  Regex("^https://codeload\\.github\\.com/hyphanet/seedrefs/zip/[0-9a-f]{40}$")
val stableWindowsWrapperUrlPattern =
  Regex(
    "^https://github\\.com/crypta-network/wrapper-windows-build/releases/download/" +
      "[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._+-]*\\.(?:zip|tar\\.gz)$"
  )
val seedrefsWorkDir: Provider<Directory> = layout.buildDirectory.dir("seedrefs")
val seedrefsZip: Provider<RegularFile> = seedrefsWorkDir.map { it.file("seedrefs.zip") }
val seedrefsExtracted: Provider<Directory> = seedrefsWorkDir.map { it.dir("extracted") }
val seednodesOut: Provider<RegularFile> =
  layout.buildDirectory.file("generated/seednodes/seednodes.fref")

fun downloadTo(url: String, targetFile: Provider<RegularFile>) {
  val target = targetFile.get().asFile
  target.parentFile.mkdirs()
  val resolvedUrl = URI(url).toURL()
  println("Downloading $url -> " + target.absolutePath)
  resolvedUrl.openStream().use { input ->
    Files.copy(input, target.toPath(), StandardCopyOption.REPLACE_EXISTING)
  }
}

fun verifyExpectedSha256(file: File, expectedValue: String?, materialName: String) {
  val expected = expectedValue?.trim()?.lowercase().orEmpty()
  if (expected.isEmpty()) return
  if (!expected.matches(Regex("[0-9a-f]{64}"))) {
    throw GradleException(
      "$materialName expected SHA-256 must be 64 lowercase hexadecimal characters"
    )
  }
  val digest = MessageDigest.getInstance("SHA-256")
  file.inputStream().buffered().use { input ->
    val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
    while (true) {
      val read = input.read(buffer)
      if (read < 0) break
      digest.update(buffer, 0, read)
    }
  }
  val actual = digest.digest().joinToString("") { byte -> "%02x".format(byte) }
  if (actual != expected) {
    throw GradleException("$materialName SHA-256 mismatch: expected $expected, got $actual")
  }
}

// Download the Wrapper delta pack
val downloadWrapper by tasks.registering {
  group = "distribution"
  description = "Downloads Tanuki Java Service Wrapper delta pack"
  val outFile = wrapperWorkDir.map { it.file(wrapperDeltaPack) }
  val expectedSha256 = providers.gradleProperty("wrapperDeltaPackSha256")
  inputs.property("sourceUrl", wrapperBaseUrl)
  inputs.property("expectedSha256", expectedSha256.orElse(""))
  outputs.file(outFile)
  doLast {
    downloadTo(wrapperBaseUrl, outFile)
    verifyExpectedSha256(outFile.get().asFile, expectedSha256.orNull, "Tanuki Wrapper delta pack")
  }
}

// Extract the delta pack
val extractWrapper by
  tasks.registering(Copy::class) {
    group = "distribution"
    description = "Extracts the Tanuki Wrapper delta pack"
    dependsOn(downloadWrapper)
    val tarFile = wrapperWorkDir.map { it.file(wrapperDeltaPack) }
    from(tarTree(resources.gzip(tarFile)))
    into(wrapperExtractDir)
  }

// Download seedrefs (zip of repo)
val downloadSeedrefs by tasks.registering {
  group = "distribution"
  description = "Downloads hyphanet/seedrefs repository as a zip"
  val expectedSha256 = providers.gradleProperty("seedrefsSha256")
  inputs.property("sourceUrl", seedrefsZipUrl)
  inputs.property("expectedSha256", expectedSha256.orElse(""))
  outputs.file(seedrefsZip)
  doLast {
    val reviewedDigest = expectedSha256.orNull?.trim().orEmpty()
    val sourceUrl = seedrefsZipUrl.get()
    if (reviewedDigest.isNotEmpty() && !stableSeedrefsUrlPattern.matches(sourceUrl)) {
      throw GradleException(
        "A reviewed seedrefs digest requires an immutable full-commit codeload URL"
      )
    }
    downloadTo(sourceUrl, seedrefsZip)
    verifyExpectedSha256(seedrefsZip.get().asFile, expectedSha256.orNull, "seedrefs archive")
  }
}

// Extract seedrefs
val extractSeedrefs by
  tasks.registering(Copy::class) {
    group = "distribution"
    description = "Extracts seedrefs zip"
    dependsOn(downloadSeedrefs)
    from(zipTree(seedrefsZip.get().asFile))
    into(seedrefsExtracted)
  }

// Concatenate all seedrefs files into one seednodes.fref
val generateSeednodesFile by tasks.registering {
  group = "distribution"
  description = "Generates seednodes.fref from hyphanet/seedrefs"
  dependsOn(extractSeedrefs)
  outputs.file(seednodesOut)
  doLast {
    val root = seedrefsExtracted.get().asFile
    val outFile = seednodesOut.get().asFile
    outFile.parentFile.mkdirs()
    val files = root.walkTopDown().filter { it.isFile }.sortedBy { it.name.lowercase() }.toList()
    if (files.isEmpty()) throw GradleException("No files found in extracted seedrefs")
    outFile.printWriter().use { pw ->
      files.forEach { f ->
        val content = f.readText()
        pw.println(content.trim())
        pw.println()
      }
    }
    println(
      "Generated seednodes file at " + outFile.absolutePath + " with " + files.size + " entries"
    )
  }
}

// Copy platform wrapper binaries and helper files under bin/
val copyWrapperBinaries by
  tasks.registering(Copy::class) {
    group = "distribution"
    description = "Copies Wrapper binaries into distribution bin/"
    dependsOn(extractWrapper)
    into(wrapperDistDir.map { it.dir("bin") })
    from(wrapperExtractDir.map { it.dir("wrapper-delta-pack-$wrapperVersion/bin") }) {
      include("*")
      // Drop unsupported platforms and demos
      exclude("*aix*", "*hpux*", "*linux-ppcle*", "*solaris*", "*freebsd*", "*windows*")
      exclude("**/*.bat", "README.txt", "demoapp*", "testwrapper*")
      exclude("Install*", "Uninstall*", "Start*", "Stop*", "Pause*", "Resume*", "Query*")
      // Drop 32-bit binaries
      exclude("*-x86-32*", "*-universal-32*", "*-armel-32*", "*-armhf-32*")
    }
  }

// --- Windows wrapper: locate asset URLs (newest GitHub release) and download ---

fun windowsWrapperApiResponse(url: String): String {
  val connection = URI(url).toURL().openConnection() as HttpURLConnection
  // Optional: use GITHUB_TOKEN when present to raise rate limits.
  val token = System.getenv("GITHUB_TOKEN")
  if (!token.isNullOrBlank()) connection.setRequestProperty("Authorization", "Bearer $token")
  connection.setRequestProperty("Accept", "application/vnd.github+json")
  connection.connectTimeout = 30_000
  connection.readTimeout = 30_000
  connection.inputStream.bufferedReader().use { reader ->
    return reader.readText()
  }
}

fun findWindowsWrapperAssetUrl(apiUrl: String, archHints: Set<String>): String {
  val json = windowsWrapperApiResponse(apiUrl)
  // Very small JSON picker: find the first browser_download_url for Windows and the arch hints.
  // We avoid adding a JSON parser dependency here.
  val expression = Regex(""""browser_download_url"\s*:\s*"([^"]+)"""", RegexOption.IGNORE_CASE)
  val candidate =
    expression
      .findAll(json)
      .map { match -> match.groupValues[1] }
      .firstOrNull { url ->
        val lower = url.lowercase()
        (lower.endsWith(".zip") || lower.endsWith(".tar.gz")) &&
          lower.contains("win") &&
          archHints.any { hint -> lower.contains(hint) }
      }
  return candidate
    ?: throw GradleException("Could not find Windows asset for $archHints in $apiUrl")
}

fun downloadWindowsWrapperAsset(url: String, output: File) {
  println("Downloading $url -> ${output.absolutePath}")
  URI(url).toURL().openStream().use { input ->
    Files.copy(input, output.toPath(), StandardCopyOption.REPLACE_EXISTING)
  }
}

val downloadWindowsWrapper by tasks.registering {
  group = "distribution"
  description = "Downloads Windows wrapper (amd64 + arm64) from latest GitHub release"
  val amd64UrlOverride = providers.gradleProperty("wrapperWinAmd64Url")
  val arm64UrlOverride = providers.gradleProperty("wrapperWinArm64Url")
  val amd64ExpectedSha256 = providers.gradleProperty("wrapperWinAmd64Sha256")
  val arm64ExpectedSha256 = providers.gradleProperty("wrapperWinArm64Sha256")
  inputs.property("apiUrl", wrapperWindowsApiLatest)
  inputs.property("amd64UrlOverride", amd64UrlOverride.orElse(""))
  inputs.property("arm64UrlOverride", arm64UrlOverride.orElse(""))
  inputs.property("amd64ExpectedSha256", amd64ExpectedSha256.orElse(""))
  inputs.property("arm64ExpectedSha256", arm64ExpectedSha256.orElse(""))
  outputs.files(wrapperWindowsAmd64Archive, wrapperWindowsArm64Archive)
  doLast {
    val reviewedAmd64 = amd64ExpectedSha256.orNull?.isNotBlank() == true
    val reviewedArm64 = arm64ExpectedSha256.orNull?.isNotBlank() == true
    val reviewedAmd64Url = amd64UrlOverride.orNull.orEmpty()
    val reviewedArm64Url = arm64UrlOverride.orNull.orEmpty()
    if (
      (reviewedAmd64 && !stableWindowsWrapperUrlPattern.matches(reviewedAmd64Url)) ||
        (reviewedArm64 && !stableWindowsWrapperUrlPattern.matches(reviewedArm64Url))
    ) {
      throw GradleException("Reviewed Windows Wrapper digests require immutable release-asset URLs")
    }
    val amd64File = wrapperWindowsAmd64Archive.get().asFile
    val arm64File = wrapperWindowsArm64Archive.get().asFile
    amd64File.parentFile.mkdirs()
    arm64File.parentFile.mkdirs()
    val amd64Url =
      amd64UrlOverride.orNull?.takeIf(String::isNotBlank)
        ?: findWindowsWrapperAssetUrl(
          wrapperWindowsApiLatest.get(),
          setOf("amd64", "x86_64", "x64"),
        )
    val arm64Url =
      arm64UrlOverride.orNull?.takeIf(String::isNotBlank)
        ?: findWindowsWrapperAssetUrl(wrapperWindowsApiLatest.get(), setOf("arm64", "aarch64"))
    downloadWindowsWrapperAsset(amd64Url, amd64File)
    downloadWindowsWrapperAsset(arm64Url, arm64File)
    verifyExpectedSha256(amd64File, amd64ExpectedSha256.orNull, "Windows amd64 Wrapper archive")
    verifyExpectedSha256(arm64File, arm64ExpectedSha256.orNull, "Windows arm64 Wrapper archive")
  }
}

// --- Archive detection helpers (shared) ---

enum class ArchiveType {
  ZIP,
  TAR_GZ,
}

fun detectArchiveType(file: File): ArchiveType {
  if (!file.exists() || !file.isFile) {
    throw GradleException("Archive not found or not a file: ${file.absolutePath}")
  }
  val size = file.length()
  if (size < 2) {
    throw GradleException(
      "Archive appears empty or truncated (<2 bytes): ${file.name} (size=$size)"
    )
  }
  val magic = ByteArray(2)
  val read = file.inputStream().use { it.read(magic) }
  if (read < 2) {
    throw GradleException("Failed to read magic bytes from archive: ${file.name} (read=$read)")
  }
  val isZip = magic[0] == 0x50.toByte() && magic[1] == 0x4B.toByte()
  val isGzip = magic[0] == 0x1F.toByte() && magic[1] == 0x8B.toByte()
  return when {
    isZip -> {
      ArchiveType.ZIP
    }

    isGzip -> {
      ArchiveType.TAR_GZ
    }

    else -> {
      throw GradleException(
        "Unsupported or unrecognized archive format for Windows wrapper: ${file.name}"
      )
    }
  }
}

fun fileTreeFromArchive(file: File): FileTree =
  when (detectArchiveType(file)) {
    ArchiveType.ZIP -> zipTree(file)
    ArchiveType.TAR_GZ -> tarTree(resources.gzip(file))
  }

// Helper to detect the archive type and configure extraction dynamically at execution time.
fun Copy.fromAutoArchive(file: File) {
  when (detectArchiveType(file)) {
    ArchiveType.ZIP -> from(zipTree(file))
    ArchiveType.TAR_GZ -> from(tarTree(resources.gzip(file)))
  }
}

val extractWindowsWrapperAmd64 by
  tasks.registering(Copy::class) {
    group = "distribution"
    description = "Extracts Windows amd64 wrapper archive"
    dependsOn(downloadWindowsWrapper)
    // Declare inputs/outputs so Gradle executes even when sources are configured late
    inputs.file(wrapperWindowsAmd64Archive)
    outputs.dir(wrapperWindowsAmd64Extract)
    into(wrapperWindowsAmd64Extract)
    doFirst {
      // Configure sources just-in-time to account for the actual downloaded format
      val f = wrapperWindowsAmd64Archive.get().asFile
      fromAutoArchive(f)
    }
  }

val extractWindowsWrapperArm64 by
  tasks.registering(Copy::class) {
    group = "distribution"
    description = "Extracts Windows arm64 wrapper archive"
    dependsOn(downloadWindowsWrapper)
    inputs.file(wrapperWindowsArm64Archive)
    outputs.dir(wrapperWindowsArm64Extract)
    into(wrapperWindowsArm64Extract)
    doFirst {
      val f = wrapperWindowsArm64Archive.get().asFile
      fromAutoArchive(f)
    }
  }

// Copy Windows wrapper binaries into dist:
//  - bin/wrapper-windows-x86-64.exe and bin/wrapper-windows-arm-64.exe
//  - lib/wrapper-windows-x86-64.dll and lib/wrapper-windows-arm-64.dll
val copyWindowsWrapperBinaries by tasks.registering {
  group = "distribution"
  description = "Copies Windows wrapper executables and DLLs into the distribution"
  // Only need downloads; we parse archives directly (no pre-extract step required)
  dependsOn(downloadWindowsWrapper)
  // Declare outputs so other Copy/Sync tasks don’t treat these as unknown files
  val binExeX64 = wrapperDistDir.map { it.file("bin/wrapper-windows-x86-64.exe") }
  val binExeArm = wrapperDistDir.map { it.file("bin/wrapper-windows-arm-64.exe") }
  val libDllX64 = wrapperDistDir.map { it.file("lib/wrapper-windows-x86-64.dll") }
  val libDllArm = wrapperDistDir.map { it.file("lib/wrapper-windows-arm-64.dll") }
  outputs.files(binExeX64, binExeArm, libDllX64, libDllArm)
  doLast {
    val binDir = wrapperDistDir.get().dir("bin").asFile
    val libDir = wrapperDistDir.get().dir("lib").asFile
    binDir.mkdirs()
    libDir.mkdirs()

    val amd64Archive = wrapperWindowsAmd64Archive.get().asFile
    val arm64Archive = wrapperWindowsArm64Archive.get().asFile

    println("[dist] copyWindowsWrapperBinaries: starting")

    fun humanSize(bytes: Long): String {
      val units = arrayOf("B", "KB", "MB", "GB")
      var b = bytes.toDouble()
      var i = 0
      while (b >= 1024 && i < units.lastIndex) {
        b /= 1024
        i++
      }
      return String.format("%.1f %s", b, units[i])
    }
    try {
      val amdType = detectArchiveType(amd64Archive)
      val armType = detectArchiveType(arm64Archive)
      println(
        "[dist] windows archives:\n" +
          "  amd64: ${amd64Archive.absolutePath} (" +
          humanSize(amd64Archive.length()) +
          ", type=$amdType)\n" +
          "  arm64: ${arm64Archive.absolutePath} (" +
          humanSize(arm64Archive.length()) +
          ", type=$armType)"
      )
    } catch (e: Exception) {
      println("[dist] archive detection warning: ${e.message}")
    }

    fun firstN(tree: FileTree, n: Int): String =
      tree.files.take(n).joinToString("\n") { f -> f.toString() }

    fun pickExe(tree: FileTree): File? {
      val exeFiles = tree.matching { include("**/*.exe") }.files.toList()
      if (exeFiles.isEmpty()) return null
      val lower = exeFiles.associateBy { it.name.lowercase() }
      val prefs = listOf("wrapper-windows-x86-64.exe", "wrapper-windows-arm-64.exe", "wrapper.exe")
      for (p in prefs) if (p in lower) return lower[p]
      return exeFiles.firstOrNull { it.name.lowercase().startsWith("wrapper") } ?: exeFiles.first()
    }

    fun pickDll(tree: FileTree): File? {
      val dllFiles = tree.matching { include("**/*.dll") }.files.toList()
      if (dllFiles.isEmpty()) return null
      val lower = dllFiles.associateBy { it.name.lowercase() }
      val prefs = listOf("wrapper.dll", "wrapper-windows-x86-64.dll", "wrapper-windows-arm-64.dll")
      for (p in prefs) if (p in lower) return lower[p]
      return dllFiles.firstOrNull { it.name.lowercase().contains("wrapper") } ?: dllFiles.first()
    }

    // amd64
    run {
      val tree = fileTreeFromArchive(amd64Archive)
      println("[dist] amd64: sample entries:\n" + firstN(tree, 12))
      val exe =
        pickExe(tree)
          ?: run {
            val listing = firstN(tree, 64)
            throw GradleException(
              "No .exe found inside amd64 archive. Entries (first 64):\n$listing"
            )
          }
      val dll =
        pickDll(tree)
          ?: run {
            val listing = firstN(tree, 64)
            throw GradleException(
              "No DLL found inside amd64 archive. Entries (first 64):\n$listing"
            )
          }

      println("[dist] amd64: selected exe=${exe.absolutePath}")
      println("[dist] amd64: selected dll=${dll.absolutePath}")
      val exeOut = binDir.resolve("wrapper-windows-x86-64.exe")
      val dllOut = libDir.resolve("wrapper-windows-x86-64.dll")
      exe.copyTo(exeOut, overwrite = true)
      dll.copyTo(dllOut, overwrite = true)
      println("[dist] amd64: copied exe -> ${exeOut.absolutePath}")
      println("[dist] amd64: copied dll -> ${dllOut.absolutePath}")
    }

    // arm64
    run {
      val tree = fileTreeFromArchive(arm64Archive)
      println("[dist] arm64: sample entries:\n" + firstN(tree, 12))
      val exe =
        pickExe(tree)
          ?: run {
            val listing = firstN(tree, 64)
            throw GradleException(
              "No .exe found inside arm64 archive. Entries (first 64):\n$listing"
            )
          }
      val dll =
        pickDll(tree)
          ?: run {
            val listing = firstN(tree, 64)
            throw GradleException(
              "No DLL found inside arm64 archive. Entries (first 64):\n$listing"
            )
          }

      println("[dist] arm64: selected exe=${exe.absolutePath}")
      println("[dist] arm64: selected dll=${dll.absolutePath}")
      val exeOut = binDir.resolve("wrapper-windows-arm-64.exe")
      val dllOut = libDir.resolve("wrapper-windows-arm-64.dll")
      exe.copyTo(exeOut, overwrite = true)
      dll.copyTo(dllOut, overwrite = true)
      println("[dist] arm64: copied exe -> ${exeOut.absolutePath}")
      println("[dist] arm64: copied dll -> ${dllOut.absolutePath}")
    }
    println("[dist] copyWindowsWrapperBinaries: done")
  }
}

// Copy runtime jars into lib/ and build a classpath list for wrapper.conf
val prepareWrapperLibs by
  tasks.registering(Copy::class) {
    group = "distribution"
    description = "Copies runtime jars to lib/ for the wrapper distribution"
    dependsOn(tasks.named("buildJar"), extractWrapper)
    into(wrapperDistDir.map { it.dir("lib") })
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    from(configurations.runtimeClasspath) { exclude("**/wrapper*.jar") }
    from(tasks.named("buildJar")) { rename { "cryptad.jar" } }
    from(wrapperExtractDir.map { it.dir("wrapper-delta-pack-$wrapperVersion/lib") }) {
      include("*")
      exclude(
        "**/*.dll",
        "**/*aix*",
        "**/*hpux*",
        "**/*solaris*",
        "**/*freebsd*",
        "**/*windows*",
        "**/*-ppcle-*",
      )
      exclude("**/*demo*.*", "**/*test*.*")
      exclude(
        "**/*-x86-32.*",
        "**/*-universal-32.*",
        "**/*-armel-32.*",
        "**/*-armhf-32.*",
        "**/*-32.*",
      )
    }
    from(wrapperExtractDir.map { it.dir("wrapper-delta-pack-$wrapperVersion/lib") }) {
      include("wrapper*.jar")
      rename { "wrapper.jar" }
    }
  }

// Generate conf/wrapper.conf from a template
val generateWrapperConf by tasks.registering {
  group = "distribution"
  description = "Generates conf/wrapper.conf from template"
  dependsOn(prepareWrapperLibs)
  val confDir = wrapperDistDir.map { it.dir("conf") }
  outputs.file(confDir.map { it.file("wrapper.conf") })
  // Capture the template file at configuration time to avoid Task.project access at execution
  val confTemplate = layout.projectDirectory.file("src/main/templates/wrapper.conf.tpl")
  doLast {
    val confDirFile = confDir.get().asFile
    confDirFile.mkdirs()
    val template = confTemplate.asFile.readText()
    val confFile = confDirFile.resolve("wrapper.conf")
    confFile.writeText(template)
    println("Generated " + confFile.absolutePath)
  }
}

// Generate bin/cryptad launcher from template
val generateWrapperLaunchers by tasks.registering {
  group = "distribution"
  description = "Generates launch scripts from templates"
  dependsOn(copyWrapperBinaries)
  val binDir = wrapperDistDir.map { it.dir("bin") }
  outputs.files(binDir.map { it.file("cryptad") }, binDir.map { it.file("cryptad.bat") })
  // Resolve inputs up front (configuration time) to be config-cache-friendly
  val launcherTemplateUnix =
    layout.projectDirectory.file("src/main/templates/cryptad-launcher.sh.tpl")
  val launcherTemplateBat =
    layout.projectDirectory.file("src/main/templates/cryptad-launcher.bat.tpl")
  val mainScriptTemplate = layout.projectDirectory.file("src/main/templates/cryptad.sh.tpl")
  val mainScriptBatTemplate = layout.projectDirectory.file("src/main/templates/cryptad.bat.tpl")
  val dummyCryptad = layout.projectDirectory.file("tools/cryptad-dummy.sh")
  val useDummy = providers.gradleProperty("useDummyCryptad").map { it.toBoolean() }.orElse(false)
  doLast {
    val bin = binDir.get().asFile
    bin.mkdirs()
    val unix = bin.resolve("cryptad")
    val templateL = mainScriptTemplate.asFile.readText()
    unix.writeText(templateL)
    // Ensure executable for all, plus readable for all
    unix.setReadable(true, false)
    unix.setExecutable(true, false)

    // Windows main script
    val winBat = bin.resolve("cryptad.bat")
    val tmplBatMain = mainScriptBatTemplate.asFile
    if (!tmplBatMain.isFile) throw GradleException("Missing template: ${tmplBatMain.path}")
    winBat.writeText(tmplBatMain.readText())

    // --- Generate Swing launcher start scripts (Unix + Windows) ---
    val launcherUnix = bin.resolve("cryptad-launcher")
    val launcherBat = bin.resolve("cryptad-launcher.bat")

    val tmplUnix = launcherTemplateUnix.asFile
    val tmplBat = launcherTemplateBat.asFile
    if (!tmplUnix.isFile) throw GradleException("Missing template: ${tmplUnix.path}")
    if (!tmplBat.isFile) throw GradleException("Missing template: ${tmplBat.path}")

    launcherUnix.writeText(tmplUnix.readText())
    launcherUnix.setReadable(true, false)
    launcherUnix.setExecutable(true, false)
    launcherBat.writeText(tmplBat.readText())

    // Templates are authoritative; no inline fallbacks remain.

    // Optional dev aid: override cryptad with a dummy script when -PuseDummyCryptad=true
    if (useDummy.get()) {
      val dummy = dummyCryptad.asFile
      if (dummy.isFile) {
        println("Overriding bin/cryptad with tools/cryptad-dummy.sh for testing")
        unix.writeText(dummy.readText())
        unix.setReadable(true, false)
        unix.setExecutable(true, false)
      } else {
        println("WARNING: -PuseDummyCryptad was set but tools/cryptad-dummy.sh not found")
      }
    }
  }
}

// Top-level task to assemble the distribution tree
val assembleCryptadDist by tasks.registering {
  group = "distribution"
  description = "Assembles a portable Cryptad distribution under build/cryptad-dist"
  dependsOn(
    copyWrapperBinaries,
    copyWindowsWrapperBinaries,
    prepareWrapperLibs,
    generateWrapperConf,
    generateWrapperLaunchers,
  )
  doLast {
    println("Cryptad distribution assembled at: ${wrapperDistDir.get().asFile.absolutePath}")
  }
}

val cleanCryptadDist by
  tasks.registering(Delete::class) {
    group = "distribution"
    description = "Cleans the Cryptad distribution directory"
    delete(wrapperDistDir)
  }

assembleCryptadDist { dependsOn(cleanCryptadDist) }

copyWrapperBinaries { dependsOn(cleanCryptadDist) }

copyWindowsWrapperBinaries { dependsOn(cleanCryptadDist) }

// Ensure Windows binaries are copied after other bin/lib population tasks,
// so they are not inadvertently removed/overwritten by later copies.
copyWindowsWrapperBinaries {
  mustRunAfter(copyWrapperBinaries)
  mustRunAfter(prepareWrapperLibs)
  mustRunAfter(generateWrapperConf)
  mustRunAfter(generateWrapperLaunchers)
}

prepareWrapperLibs { dependsOn(cleanCryptadDist) }

generateWrapperConf { dependsOn(cleanCryptadDist) }

generateWrapperLaunchers { dependsOn(cleanCryptadDist) }

// Package the distribution as tar.gz with a clean, portable name
tasks.register<Tar>("distTarCryptad") {
  group = "distribution"
  description = "Packages the Cryptad distribution as a tar.gz"
  dependsOn(assembleCryptadDist)
  compression = Compression.GZIP
  // Produce cryptad-<version>.tar.gz (avoid the previous -dist suffix)
  archiveBaseName.set("cryptad")
  // Prefix version with 'v' in the filename
  archiveVersion.set("v${project.version}")
  // Ensure .tar.gz extension across Gradle versions
  archiveFileName.set("cryptad-v${project.version}.tar.gz")
  from(wrapperDistDir)
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

// Package the same distribution as a ZIP for broad platform compatibility
tasks.register<Zip>("distZipCryptad") {
  group = "distribution"
  description = "Packages the Cryptad distribution as a zip"
  dependsOn(assembleCryptadDist)
  archiveBaseName.set("cryptad")
  // Prefix version with 'v' in the filename
  archiveVersion.set("v${project.version}")
  archiveFileName.set("cryptad-v${project.version}.zip")
  from(wrapperDistDir)
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

// Aggregate distribution lifecycle task
val dist by tasks.registering {
  group = "distribution"
  description = "Builds all Cryptad distribution artifacts (tar.gz and zip)"
  dependsOn("distTarCryptad", "distZipCryptad")
}

// Ensure the standard build also produces the distribution archives
tasks.named("build") { dependsOn(dist) }

// Make sure jpackage resources exist even if only installer/image is requested later
gradle.taskGraph.whenReady {
  // When someone runs jpackage tasks from the jpackage plugin, ensure the dist is present
  if (allTasks.any { it.name.contains("jpackage", ignoreCase = true) }) {
    tasks.findByName("assembleCryptadDist")?.let { t ->
      tasks.findByName("prepareWrapperLibs")?.mustRunAfter(t)
    }
  }
}

// Diagnostic: print resolved directories
tasks.register<JavaExec>("printDirs") {
  group = "help"
  description = "Print resolved Cryptad directories (config, data, cache, run, logs)"
  dependsOn("classes")
  mainClass.set("network.crypta.tools.PrintDirsKt")
  classpath = sourceSets.main.get().runtimeClasspath
  systemProperties(gradle.startParameter.systemPropertiesArgs)
}

// Resource copies required by legacy tests and runtime expectations
val copyResourcesToClasses2 by tasks.registering {
  inputs.files(sourceSets["main"].allSource)
  outputs.dir(layout.buildDirectory.dir("classes/java/main/"))
  dependsOn(tasks.named("generateVersionSource"))
  doLast {
    copy {
      from(sourceSets["main"].allSource)
      into(layout.buildDirectory.dir("classes/java/main/"))
      include("network/crypta/l10n/*properties")
      include("network/crypta/l10n/iso-*.tab")
      include("network/crypta/clients/http/staticfiles/**")
      include("network/crypta/clients/http/templates/**")
    }
  }
}

tasks.processResources {
  dependsOn(copyResourcesToClasses2)
  dependsOn(generateSeednodesFile)
  from(seednodesOut) {
    into("seednodes")
    rename { "seednodes.fref" }
  }
}

val copyTestResourcesToClasses2 by tasks.registering {
  inputs.files(sourceSets["test"].allSource)
  outputs.dir(layout.buildDirectory.dir("classes/java/test/"))
  doLast {
    copy {
      from(sourceSets["test"].allSource)
      into(layout.buildDirectory.dir("classes/java/test/"))
      include("network/crypta/client/filter/*/**")
      include("network/crypta/crypt/ciphers/rijndael-gladman-test-data/**")
      include("network/crypta/l10n/*properties")
      include("network/crypta/clients/http/templates/**")
    }
  }
}

tasks.compileTestJava { dependsOn(copyResourcesToClasses2, copyTestResourcesToClasses2) }

// Build a source release, excluding build directories
tasks.register<Tar>("tar") {
  group = "distribution"
  description = "Build a source release, excluding build directories and Gradle caches"
  compression = Compression.BZIP2
  archiveBaseName.set("freenet-sources")
  from(project.rootDir) { exclude("**/build", "build", ".gradle") }
  into(archiveBaseName.get())
  isPreserveFileTimestamps = true
  isReproducibleFileOrder = true
  destinationDirectory.set(layout.buildDirectory)
  archiveFileName.set("${archiveBaseName.get()}.tgz")
  doLast {
    ant.invokeMethod(
      "checksum",
      mapOf("file" to "${destinationDirectory.get()}/${archiveFileName.get()}"),
    )
  }
}
