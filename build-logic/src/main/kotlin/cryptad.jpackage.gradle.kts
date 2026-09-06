import cryptad.DeterministicBootstrapJar
import cryptad.selectStableJava25
import java.io.OutputStream
import java.nio.ByteBuffer
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.util.Locale

plugins { java }

/**
 * JPackage integration for Crypta, matching the repo’s custom build style.
 * - Reuses the jlink image produced by cryptad.runtime (build/jre)
 * - Creates an app image via `jpackage --type app-image`
 * - Optionally builds native installers via `jpackage --type <os-default>`
 * - Copies the portable node layout (build/cryptad-dist) into the app image under app/cryptad-dist
 * - Prepares standard resources (LICENSE.txt, EULA.txt, README.txt) from the project root
 *
 * This file intentionally avoids duplicating jars under the jpackage image; instead a tiny
 * bootstrap jar is created so we can later rewrite `Crypta.cfg` to reference the jars under
 * `app/cryptad-dist/lib/` + `*.jar` as the runtime classpath.
 */
val jreDir: Provider<Directory> = layout.buildDirectory.dir("jre")
val cryptadDistDir: Provider<Directory> = layout.buildDirectory.dir("cryptad-dist")
val jpackageOutDir: Provider<Directory> = layout.buildDirectory.dir("jpackage")
val jpackageResourcesDir: Provider<Directory> = layout.buildDirectory.dir("jpackage/resources")
val jpackageInputDir: Provider<Directory> = layout.buildDirectory.dir("jpackage/input")

// Compute version string: v<project.version>+<gitRevShort>
fun gitRevShort(): String =
  try {
    val pb = ProcessBuilder("git", "rev-parse", "--short", "HEAD")
    pb.directory(project.rootDir)
    pb.redirectErrorStream(true)
    val p = pb.start()
    p.waitFor(5, TimeUnit.SECONDS)
    val s = p.inputStream.bufferedReader().use { it.readText() }.trim()
    if (p.exitValue() == 0 && s.isNotBlank()) s else "unknown"
  } catch (_: Exception) {
    "unknown"
  }

fun clearXattrsQuiet(target: File, timeoutSeconds: Long) {
  try {
    val xattr = File("/usr/bin/xattr")
    if (xattr.canExecute()) {
      ProcessBuilder(xattr.absolutePath, "-cr", target.absolutePath)
        .redirectErrorStream(true)
        .start()
        .waitFor(timeoutSeconds, TimeUnit.SECONDS)
    }
  } catch (_: Exception) {}
}

val appName = "Crypta"
val vendor = "crypta.network"
val appId = "network.crypta.cryptad"
// This identity is part of the Windows upgrade contract. Do not change it between integer builds.
val windowsUpgradeUuid = "779872cd-ca9b-5a0e-8260-7d372a550fb7"

// jpackage --app-version is strict (e.g., macOS CFBundleVersion must be 1..3 integers separated by
// dots).

/** Returns the portable numeric app version accepted by Linux and macOS jpackage. */
fun numericAppVersion(rawVersion: String = project.version.toString()): String {
  val m = Regex("\\d+(?:\\.\\d+){0,3}").find(rawVersion)
  return (m?.value ?: rawVersion.filter { it.isDigit() }.ifBlank { "1" })
}

/** Maps the canonical integer release build to MSI's 16-bit build-version component. */
fun windowsMsiAppVersion(releaseBuild: String): String {
  val build = releaseBuild.toIntOrNull()
  if (build == null || build <= 0 || build > 65_535 || build.toString() != releaseBuild) {
    throw GradleException(
      "Windows Stable release builds must be canonical integers from 1 through 65535"
    )
  }
  return "1.0.$build"
}

/** Returns the OS-specific jpackage version without changing Cryptad's integer release version. */
fun jpackageAppVersion(
  os: String = currentOs(),
  releaseBuild: String = project.version.toString(),
): String = if (os == "win") windowsMsiAppVersion(releaseBuild) else numericAppVersion(releaseBuild)

// Prepare resources for jpackage from root files and src/jpackage assets
val prepareJpackageResources by
  tasks.registering(Sync::class) {
    group = "jpackage"
    description = "Collects jpackage resources (icons + legal docs) into build/jpackage/resources"
    // Copy all standard resources (icons, platform assets, docs)
    from(layout.projectDirectory.dir("src/jpackage"))
    // Linux maintainer scripts for DEB detection are placed at resource root
    from(layout.projectDirectory.dir("src/jpackage/linux")) {
      include("preinst", "prerm", "postinst", "postrm", "postinstall", "postuninstall")
      into("")
    }
    // Shared helper library for maintainer scripts
    from(layout.projectDirectory.dir("src/jpackage/linux")) {
      include("crypta-common.sh")
      into("lib")
    }
    // For RPM: jpackage supports overriding its spec via a file named
    // "<package-name>.spec" in the resource dir (package-name defaults to the application
    // name lowercased; here it is "crypta"). Include our customized specs. We also copy
    // template.spec for completeness, but the concrete package spec takes precedence.
    from(layout.projectDirectory.dir("src/jpackage/linux")) {
      include("crypta.spec", "template.spec")
      into("")
    }
    // RPM payload: place the systemd unit under lib/systemd/system within the resource dir so
    // the spec template copies it into /lib/systemd/system during %install.
    from(layout.projectDirectory.dir("src/jpackage/linux")) {
      include("cryptad.service")
      // Also stage the headless core installer template unit alongside the main service
      include("cryptad-core-install@.service")
      into("lib/systemd/system")
    }
    // Headless core installer script and polkit rule used by post-install scripts (DEB/RPM)
    from(layout.projectDirectory.dir("src/jpackage/linux")) {
      include("cryptad-core-install.sh")
      into("lib")
    }
    from(layout.projectDirectory.dir("src/jpackage/linux/polkit-1")) {
      include("60-cryptad-core-install.rules")
      into("lib/polkit-1")
    }
    // LICENSE -> LICENSE.txt and EULA.txt; README.md -> README.txt
    from(layout.projectDirectory.file("LICENSE")) { rename { "LICENSE.txt" } }
    from(layout.projectDirectory.file("LICENSE")) { rename { "EULA.txt" } }
    from(layout.projectDirectory.file("README.md")) { rename { "README.txt" } }
    into(jpackageResourcesDir)

    // Fail early if icon for current OS is missing (helps local dev)
    doLast {
      val icon = File(iconPathForOs())
      if (!icon.isFile) {
        throw GradleException("Required jpackage icon not found: ${icon.absolutePath}")
      }

      // Ensure Linux maintainer scripts are executable when present
      if (currentOs() == "linux") {
        val res = jpackageResourcesDir.get().asFile
        listOf(
            "preinst",
            "prerm",
            "postinst",
            "postrm",
            "postinstall",
            "postuninstall",
            "lib/crypta-common.sh",
            "lib/cryptad-core-install.sh",
          )
          .map { File(res, it) }
          .filter { it.isFile }
          .forEach { it.setExecutable(true, true) }
      }
    }
  }

// Helper resolving the OS and icon path

private val osNameLower = (System.getProperty("os.name") ?: "").lowercase(Locale.ROOT).trim()

fun isWindowsOs(): Boolean =
  osNameLower.startsWith("windows") ||
    osNameLower.startsWith("cygwin") ||
    osNameLower.startsWith("mingw") ||
    osNameLower.startsWith("msys") ||
    osNameLower == "win"

fun isMacOs(): Boolean = osNameLower.contains("mac") || osNameLower.contains("darwin")

/** Detects the current OS as a stable token: mac|win|linux. */
fun currentOs(): String =
  when {
    isMacOs() -> "mac"
    isWindowsOs() -> "win"
    else -> "linux"
  }

/** Checks if an executable exists on PATH using the platform-appropriate command. */
fun hasExe(name: String): Boolean =
  try {
    val pb =
      ProcessBuilder(
        if (isWindowsOs()) {
          listOf("where", name)
        } else {
          listOf("which", name)
        }
      )
    pb.redirectErrorStream(true)
    val p = pb.start()
    p.waitFor(3, TimeUnit.SECONDS)
    p.exitValue() == 0
  } catch (_: Exception) {
    false
  }

/**
 * Picks the installer type for the current OS; Windows intentionally unsupported. On Linux,
 * supports override via `-PlinuxInstaller=<deb|rpm>` or env `CRYPTA_LINUX_INSTALLER`. Defaults to
 * preferring rpm when both tools are present.
 */
fun resolveInstallerType(os: String): String =
  when (os) {
    "mac" -> {
      "dmg"
    }

    else -> {
      val override =
        (providers.gradleProperty("linuxInstaller").orNull
            ?: System.getenv("CRYPTA_LINUX_INSTALLER"))
          ?.trim()
          ?.lowercase()
      when (override) {
        "deb" -> {
          "deb"
        }

        "rpm" -> {
          "rpm"
        }

        else -> {
          when {
            hasExe("rpmbuild") -> "rpm"
            hasExe("dpkg-deb") -> "deb"
            else -> "deb"
          }
        }
      }
    }
  }

/** Returns absolute icon path for jpackage matching the current OS. */
fun iconPathForOs(): String =
  when (currentOs()) {
    "mac" -> project.file("src/jpackage/macos/cryptad.icns").absolutePath
    "win" -> project.file("src/jpackage/windows/cryptad.ico").absolutePath
    else -> project.file("src/jpackage/linux/cryptad.png").absolutePath
  }

/** Resolves the `jpackage` executable from the Java 25 toolchain. */
fun resolveJpackageExecutable(): File {
  val toolchains = project.extensions.getByType(JavaToolchainService::class.java)
  val launcher = toolchains.launcherFor { selectStableJava25() }
  val javaHome = launcher.get().metadata.installationPath.asFile
  val exe =
    javaHome.resolve(
      "bin/jpackage" +
        if (isWindowsOs()) {
          ".exe"
        } else {
          ""
        }
    )
  if (!exe.isFile) throw GradleException("jpackage not found in toolchain: $exe")
  return exe
}

/** Deletes any pre-existing output image folder for a clean jpackage run. */
fun cleanExistingImage(outDir: File, os: String) {
  val existing =
    when (os) {
      "mac" -> outDir.resolve("$appName.app")
      else -> outDir.resolve(appName)
    }
  if (existing.exists()) existing.deleteRecursively()
}

/**
 * Relocates a macOS app bundle while preserving executable bits, symlinks, and metadata.
 *
 * Copying with Kotlin/JVM file helpers can flatten bundle details needed by launchd.
 */
fun relocateMacAppBundle(stagedApp: File, targetApp: File) {
  if (!stagedApp.isDirectory) {
    throw GradleException("Staged app bundle not found: ${stagedApp.absolutePath}")
  }
  targetApp.parentFile.mkdirs()
  if (targetApp.exists()) targetApp.deleteRecursively()

  try {
    Files.move(
      stagedApp.toPath(),
      targetApp.toPath(),
      StandardCopyOption.REPLACE_EXISTING,
      StandardCopyOption.ATOMIC_MOVE,
    )
    return
  } catch (_: AtomicMoveNotSupportedException) {
    // Fall back to metadata-preserving copy when atomic move is unavailable.
  } catch (_: Exception) {
    // Fall back for cross-device moves (e.g., tmp on another volume).
  }

  val ditto = File("/usr/bin/ditto")
  if (ditto.canExecute()) {
    execAndLog(listOf(ditto.absolutePath, stagedApp.absolutePath, targetApp.absolutePath))
    stagedApp.deleteRecursively()
    return
  }

  throw GradleException("Unable to relocate macOS app bundle: ${stagedApp.absolutePath}")
}

/** Creates a minimal bootstrap jar under the provided input dir and returns its file. */
fun createBootstrapJar(inputDir: File): File {
  if (inputDir.exists()) inputDir.deleteRecursively()
  inputDir.mkdirs()
  val stagedMain = File(inputDir, "bootstrap.jar")
  DeterministicBootstrapJar.write(stagedMain.toPath())
  return stagedMain
}

/** Executes a command and streams output; throws on non-zero exit. */
fun execAndLog(args: List<String>) {
  val pb = ProcessBuilder(args)
  pb.redirectErrorStream(true)
  val p = pb.start()
  val output = p.inputStream.bufferedReader().use { it.readText() }
  val code = p.waitFor()
  logger.lifecycle(output.trim())
  if (code != 0) throw GradleException("Command failed ($code): ${args.joinToString(" ")}")
}

// WiX helper removed with Windows installers.

// Build an app image using the toolchain JDK's jpackage
val jpackageImageCryptad by tasks.registering {
  group = "jpackage"
  description = "Creates a jpackage app image for Crypta into build/jpackage"
  dependsOn(tasks.named("createJreImage")) // from cryptad.runtime
  dependsOn(tasks.named("assembleCryptadDist")) // from cryptad.distribution
  dependsOn(prepareJpackageResources)

  doLast {
    val jpackage = resolveJpackageExecutable()
    val outDir = jpackageOutDir.get().asFile.also { it.mkdirs() }
    val os = currentOs()
    val imageName = appName
    val mainClass = "network.crypta.launcher.Launcher"

    // We'll point jpackage at our distribution lib dir for the classpath and main jar
    val libDir = cryptadDistDir.get().dir("lib").asFile
    val mainJar = libDir.resolve("cryptad.jar")
    if (!mainJar.isFile) throw GradleException("Missing main JAR at ${mainJar.absolutePath}")

    val inputDir = jpackageInputDir.get().asFile
    val stagedMain = createBootstrapJar(inputDir)

    // Ensure we start from a clean target (jpackage fails if the image exists)
    cleanExistingImage(outDir, os)

    // On macOS, stage the app image under the system temp directory to avoid iCloud/
    // FileProvider extended attributes (FinderInfo) being attached during creation, which
    // makes codesign fail. We then move the completed image back to build/jpackage.
    val destDir =
      if (os == "mac") {
        File(
          System.getProperty("java.io.tmpdir"),
          "crypta-jpackage-${System.currentTimeMillis()}",
        )
      } else {
        outDir
      }
    destDir.mkdirs()

    val args =
      mutableListOf(
        jpackage.absolutePath,
        "--type",
        "app-image",
        "--name",
        imageName,
        "--app-version",
        jpackageAppVersion(),
        "--dest",
        destDir.absolutePath,
        "--input",
        inputDir.absolutePath,
        "--main-jar",
        stagedMain.name,
        "--main-class",
        mainClass,
        "--runtime-image",
        jreDir.get().asFile.absolutePath,
        "--resource-dir",
        jpackageResourcesDir.get().asFile.absolutePath,
        "--icon",
        iconPathForOs(),
      )

    // App-image stage must avoid installer-only flags. Do not pass platform-specific
    // packaging options here (e.g., --linux-shortcut, --mac-package-identifier) because
    // jpackage rejects them with --type app-image. Such options are added in the installer task.

    logger.lifecycle("Executing jpackage app-image:\n{}", args.joinToString(" "))
    try {
      execAndLog(args)
      // If we staged to a temp directory, move the result into the build output dir.
      if (destDir != outDir) {
        val staged = destDir.resolve("$appName.app")
        if (staged.isDirectory) {
          val target = outDir.resolve("$appName.app")
          logger.lifecycle("Relocating app image from staging -> {}", target.absolutePath)
          relocateMacAppBundle(staged, target)
          // Best-effort: remove any staging attributes after copy
          clearXattrsQuiet(target, 5)
          destDir.deleteRecursively()
        }
      }
    } catch (e: Exception) {
      // Workaround for macOS codesign failing with FinderInfo xattr on the app bundle root.
      // On some macOS versions, jpackage ad-hoc signs the bundle, and codesign rejects
      // com.apple.FinderInfo on the freshly created <App>.app, yielding:
      //   resource fork, Finder information, or similar detritus not allowed
      // If we see a failure and the output image exists, clear xattrs and ad-hoc sign the
      // bundle. When staging is used (destDir != outDir), operate on the staged app and then
      // relocate the fixed bundle into outDir so downstream tasks find it.
      if (os == "mac") {
        val stagedApp = destDir.resolve("$appName.app")
        val finalApp = outDir.resolve("$appName.app")
        val appDir = if (stagedApp.isDirectory) stagedApp else finalApp
        if (appDir.isDirectory) {
          try {
            // Best-effort: remove extended attributes recursively.
            val xattr = File("/usr/bin/xattr")
            if (xattr.canExecute()) {
              val pb = ProcessBuilder(xattr.absolutePath, "-cr", appDir.absolutePath)
              pb.redirectErrorStream(true)
              val p = pb.start()
              val out = p.inputStream.bufferedReader().use { it.readText() }
              p.waitFor(10, TimeUnit.SECONDS)
              logger.lifecycle(
                "Cleared xattrs on app image (exit ${p.exitValue()}): {}",
                out.trim(),
              )
            } else {
              logger.warn("xattr tool not available; skipping attribute cleanup")
            }

            // Direct ad-hoc sign the bundle root. jpackage already signed Contents/runtime
            // before failing, so this completes the bundle signature.
            val codesign = File("/usr/bin/codesign")
            if (!codesign.canExecute()) throw GradleException("codesign tool not available")
            val csArgs =
              listOf(codesign.absolutePath, "-s", "-", "-vvvv", "--force", appDir.absolutePath)
            logger.lifecycle(
              "Ad-hoc signing app bundle after xattr cleanup:\n{}",
              csArgs.joinToString(" "),
            )
            execAndLog(csArgs)
            logger.lifecycle("codesign completed; relocating if staged")

            // If we fixed the staged app, relocate it now to the final output dir.
            if (appDir == stagedApp) {
              relocateMacAppBundle(stagedApp, finalApp)
              // Remove any staged attrs again just in case
              clearXattrsQuiet(finalApp, 5)
              // Clean up staging directory
              destDir.deleteRecursively()
              logger.lifecycle("Relocated fixed app image -> {}", finalApp.absolutePath)
            }
          } catch (fixErr: Exception) {
            logger.warn("macOS fallback sign failed: {}", fixErr.message)
            throw e
          }
        } else {
          throw e
        }
      } else {
        throw e
      }
    }
  }
}

// Copy the assembled portable distribution into the app image as app/cryptad-dist
val enrichAppImageWithDist by tasks.registering {
  group = "jpackage"
  description = "Copies cryptad-dist into the jpackage image (mac: Contents/app; linux: lib/app)"
  dependsOn(jpackageImageCryptad)
  val serviceSrc = project.layout.projectDirectory.file("src/jpackage/linux/cryptad.service").asFile
  val helperUnitSrc =
    project.layout.projectDirectory.file("src/jpackage/linux/cryptad-core-install@.service").asFile
  val helperScriptSrc =
    project.layout.projectDirectory.file("src/jpackage/linux/cryptad-core-install.sh").asFile
  val polkitSrc =
    project.layout.projectDirectory
      .file("src/jpackage/linux/polkit-1/60-cryptad-core-install.rules")
      .asFile
  doLast {
    val os = currentOs()
    val root = jpackageOutDir.get().asFile
    val imageRoot =
      when (os) {
        "mac" -> root.resolve("$appName.app/Contents")
        else -> root.resolve(appName)
      }
    val appDir = imageRoot.resolve("app")
    // Where to place the portable distribution inside the app image.
    // jpackage layout differs by OS:
    // - macOS:    Contents/app/
    // - Windows:  app/
    // - Linux:    lib/app/
    val target =
      when (os) {
        "mac" -> appDir.resolve("cryptad-dist")
        "win" -> appDir.resolve("cryptad-dist")
        else -> imageRoot.resolve("lib/app/cryptad-dist")
      }
    target.parentFile.mkdirs()
    copy {
      from(cryptadDistDir)
      into(target)
    }
    logger.lifecycle("Copied cryptad-dist -> {}", target.absolutePath)

    // Ensure Linux uses our provided PNG icon verbatim rather than a downsized copy.
    if (os == "linux") {
      val srcIcon = File(iconPathForOs())
      val dstIcon = imageRoot.resolve("lib/$appName.png")
      try {
        srcIcon.copyTo(dstIcon, overwrite = true)
        logger.lifecycle(
          "Replaced Linux icon -> {} ({} bytes)",
          dstIcon.absolutePath,
          dstIcon.length(),
        )

        // Also, place a stable copy and our own .desktop file referencing it, so the desktop
        // entry uses the exact provided icon even if jpackage generates a 32x32 fallback.
        val stableIcon = imageRoot.resolve("lib/cryptad.png")
        srcIcon.copyTo(stableIcon, overwrite = true)
        val desktop = imageRoot.resolve("lib/crypta-$appName.desktop")
        val desktopContent = buildString {
          appendLine("[Desktop Entry]")
          appendLine("Name=$appName")
          appendLine("Comment=$appName")
          appendLine("Exec=/opt/cryptad/crypta/bin/$appName")
          appendLine("Icon=/opt/cryptad/crypta/lib/cryptad.png")
          appendLine("Terminal=false")
          appendLine("Type=Application")
          appendLine("Categories=Network;Utility;")
          appendLine("MimeType=")
          // Ensure GNOME docks associate the window with this entry.
          appendLine("StartupWMClass=network-crypta-launcher-Launcher")
          appendLine("X-GNOME-WMClass=network-crypta-launcher-Launcher")
        }
        desktop.writeText(desktopContent)
        logger.lifecycle("Wrote Linux desktop entry -> {}", desktop.absolutePath)
      } catch (e: Exception) {
        logger.warn("Failed to finalize Linux icon/desktop: {}", e.message)
      }

      // Also, stage systemd units and helper artifacts under lib/ so installers and
      // post-install scripts can find them inside the app image.
      try {
        if (serviceSrc.isFile) {
          val serviceDst = imageRoot.resolve("lib/systemd/system/cryptad.service")
          serviceDst.parentFile.mkdirs()
          serviceSrc.copyTo(serviceDst, overwrite = true)
          logger.lifecycle("Staged systemd unit -> {}", serviceDst.absolutePath)
        } else {
          logger.warn("Missing systemd unit at {}", serviceSrc.absolutePath)
        }
      } catch (e: Exception) {
        logger.warn("Failed to copy systemd unit: {}", e.message)
      }

      // Stage headless core installer template unit
      try {
        if (helperUnitSrc.isFile) {
          val helperUnitDst = imageRoot.resolve("lib/systemd/system/cryptad-core-install@.service")
          helperUnitDst.parentFile.mkdirs()
          helperUnitSrc.copyTo(helperUnitDst, overwrite = true)
          logger.lifecycle("Staged core-install unit -> {}", helperUnitDst.absolutePath)
        } else {
          logger.warn("Missing core-install unit at {}", helperUnitSrc.absolutePath)
        }
      } catch (e: Exception) {
        logger.warn("Failed to copy core-install unit: {}", e.message)
      }

      // Stage headless core installer script
      try {
        if (helperScriptSrc.isFile) {
          val helperScriptDst = imageRoot.resolve("lib/cryptad-core-install.sh")
          helperScriptDst.parentFile.mkdirs()
          helperScriptSrc.copyTo(helperScriptDst, overwrite = true)
          helperScriptDst.setExecutable(true, true)
          logger.lifecycle("Staged core-install script -> {}", helperScriptDst.absolutePath)
        } else {
          logger.warn("Missing core-install script at {}", helperScriptSrc.absolutePath)
        }
      } catch (e: Exception) {
        logger.warn("Failed to copy core-install script: {}", e.message)
      }

      // Stage polkit rule to allow controlled start of the oneshot helper
      try {
        if (polkitSrc.isFile) {
          val polkitDst = imageRoot.resolve("lib/polkit-1/60-cryptad-core-install.rules")
          polkitDst.parentFile.mkdirs()
          polkitSrc.copyTo(polkitDst, overwrite = true)
          logger.lifecycle("Staged polkit rule -> {}", polkitDst.absolutePath)
        } else {
          logger.warn("Missing polkit rule at {}", polkitSrc.absolutePath)
        }
      } catch (e: Exception) {
        logger.warn("Failed to copy polkit rule: {}", e.message)
      }
    }

    // Patch the jpackage launcher config to point the classpath to cryptad-dist/lib and correct
    // the main
    // class.
    val cfg =
      when (os) {
        // macOS: cfg lives under Contents/app
        "mac" -> appDir.resolve("$appName.cfg")

        // Windows: cfg lives under app/
        "win" -> appDir.resolve("$appName.cfg")

        // Linux: cfg lives under lib/app
        else -> imageRoot.resolve("lib/app/$appName.cfg")
      }
    if (cfg.isFile) {
      // Compose a fresh config that keeps only the sections we need.
      val out = mutableListOf<String>()
      out += "[Application]"
      out += "app.mainclass=network.crypta.launcher.Launcher"
      // Add classpath entries for jars under cryptad-dist/lib
      val jarDir = target.resolve("lib")
      val jars = jarDir.listFiles { f -> f.isFile && f.name.endsWith(".jar") }?.sortedBy { it.name }
      val cpPrefix =
        if (os == "linux") $$"$APPDIR/cryptad-dist/lib/" else $$"$APPDIR/cryptad-dist/lib/"
      out += "app.classpath=${cpPrefix}cryptad.jar"
      jars
        ?.filter { it.name != "cryptad.jar" }
        ?.forEach { f -> out += "app.classpath=${cpPrefix}${f.name}" }
      out += ""
      out += "[JavaOptions]"
      out += "java-options=-Djpackage.app-version=${jpackageAppVersion()}"
      cfg.writeText(out.joinToString(System.lineSeparator()))
      logger.lifecycle("Patched launcher cfg -> {}", cfg.absolutePath)
    } else {
      logger.warn("Launcher cfg not found at {}", cfg.absolutePath)
    }
  }
}

/** Returns the opt-in Developer ID Application identity used only by protected macOS packaging. */
fun macSigningKeyUserName(): String =
  providers.gradleProperty("macSigningKeyUserName").orNull?.trim().orEmpty()

/** Builds one restricted codesign command for the explicit inside-out signing sequence. */
fun macCodeSigningArgs(
  codesignPath: String,
  targetPath: String,
  signingKeyUserName: String,
  preserveExistingMetadata: Boolean,
): List<String> = buildList {
  add(codesignPath)
  add("--force")
  add("--options")
  add("runtime")
  add("--timestamp")
  if (preserveExistingMetadata) {
    // jpackage signs the JVM launchers and native runtime before enrichment. Retain their
    // identifiers and executable entitlements while replacing the ad-hoc identity.
    add("--preserve-metadata=identifier,entitlements")
  }
  add("--sign")
  add(signingKeyUserName)
  add(targetPath)
}

/** Returns whether the target currently has a signature whose metadata can be preserved. */
fun hasMacCodeSignature(codesign: File, target: File): Boolean =
  try {
    val process =
      ProcessBuilder(codesign.absolutePath, "--display", target.absolutePath)
        .redirectErrorStream(true)
        .start()
    process.inputStream.use { it.copyTo(OutputStream.nullOutputStream()) }
    process.waitFor() == 0
  } catch (_: Exception) {
    false
  }

/** Returns whether a target belongs to the jpackage-created JVM/native bundle surface. */
fun requiresExistingMacCodeSignature(appImage: File, target: File): Boolean {
  val appPath = appImage.toPath().toAbsolutePath().normalize()
  val targetPath = target.toPath().toAbsolutePath().normalize()
  return targetPath == appPath ||
    targetPath.startsWith(appPath.resolve("Contents/runtime")) ||
    targetPath.startsWith(appPath.resolve("Contents/Frameworks"))
}

/** Returns whether the regular file starts with a recognized thin or universal Mach-O magic. */
fun isMachOCodeFile(path: Path): Boolean {
  if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) return false
  val header = ByteArray(Int.SIZE_BYTES)
  val bytesRead =
    Files.newInputStream(path).use { input ->
      var offset = 0
      while (offset < header.size) {
        val count = input.read(header, offset, header.size - offset)
        if (count < 0) break
        offset += count
      }
      offset
    }
  return bytesRead == header.size &&
    ByteBuffer.wrap(header).int in
      setOf(
        0xFEEDFACE.toInt(), // 32-bit Mach-O
        0xCEFAEDFE.toInt(), // byte-swapped 32-bit Mach-O
        0xFEEDFACF.toInt(), // 64-bit Mach-O
        0xCFFAEDFE.toInt(), // byte-swapped 64-bit Mach-O
        0xCAFEBABE.toInt(), // universal Mach-O
        0xBEBAFECA.toInt(), // byte-swapped universal Mach-O
        0xCAFEBABF.toInt(), // 64-bit universal Mach-O
        0xBFBAFECA.toInt(), // byte-swapped 64-bit universal Mach-O
      )
}

/** Returns whether the directory is a nested native bundle that codesign must seal explicitly. */
fun isNestedMacCodeBundle(appPath: Path, path: Path): Boolean {
  if (!Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS) || path == appPath) return false
  if (path == appPath.resolve("Contents/runtime")) return true
  val name = path.fileName.toString().lowercase(Locale.ROOT)
  return when {
    name.endsWith(".framework") ->
      Files.isDirectory(path.resolve("Versions"), LinkOption.NOFOLLOW_LINKS)
    name.endsWith(".app") ||
      name.endsWith(".appex") ||
      name.endsWith(".xpc") ||
      name.endsWith(".plugin") ||
      name.endsWith(".bundle") ->
      Files.isRegularFile(path.resolve("Contents/Info.plist"), LinkOption.NOFOLLOW_LINKS)
    else -> false
  }
}

/**
 * Selects nested macOS code in inside-out order, leaving the main launcher for the app-root
 * signature as jpackage does.
 */
fun macNestedCodeSigningTargets(appImage: File, mainLauncherName: String): List<File> {
  val appPath = appImage.toPath().toAbsolutePath().normalize()
  val mainLauncher = appPath.resolve("Contents/MacOS/$mainLauncherName")
  val nestedFiles =
    Files.walk(appPath).use { paths ->
      paths
        .filter { path -> path != mainLauncher && isMachOCodeFile(path) }
        .sorted(compareByDescending<Path> { it.nameCount }.thenBy { it.toString() })
        .map(Path::toFile)
        .toList()
    }

  val bundleRoots =
    Files.walk(appPath).use { paths ->
      paths
        .filter { path -> isNestedMacCodeBundle(appPath, path) }
        .sorted(compareByDescending<Path> { it.nameCount }.thenBy { it.toString() })
        .map(Path::toFile)
        .toList()
    }
  return nestedFiles + bundleRoots
}

/** Verifies one nested code object without relying on recursive signing behavior. */
fun macCodeVerificationArgs(codesignPath: String, targetPath: String): List<String> =
  listOf(codesignPath, "--verify", "--strict", "--verbose=2", targetPath)

// jpackage does not apply installer-stage signing to a predefined app image, and it rejects using
// --app-image with --type app-image. Sign the final enriched bundle directly, after cryptad-dist
// and the rewritten launcher config have been added, then package those exact signed bytes.
// Ordinary local packaging skips this task when no identity is supplied.
val signFinalMacAppImageCryptad by tasks.registering {
  group = "jpackage"
  description = "Developer ID signs the final enriched macOS app image when explicitly enabled"
  dependsOn(enrichAppImageWithDist)
  onlyIf { currentOs() == "mac" && macSigningKeyUserName().isNotEmpty() }
  doLast {
    val app = jpackageOutDir.get().asFile.resolve("$appName.app")
    if (!app.isDirectory) {
      throw GradleException("Final enriched macOS app image not found: ${app.absolutePath}")
    }
    val codesign = File("/usr/bin/codesign")
    if (!codesign.canExecute()) {
      throw GradleException("codesign tool not available for protected macOS packaging")
    }

    // Enrichment changes the app payload after the initial app-image build. Clear resource-fork
    // metadata before replacing the ad-hoc image signature with the protected Developer ID.
    clearXattrsQuiet(app, 10)
    val signingIdentity = macSigningKeyUserName()
    val nestedTargets = macNestedCodeSigningTargets(app, appName)
    logger.lifecycle(
      "Developer ID signing {} nested macOS code objects before the final app root",
      nestedTargets.size,
    )
    for (target in nestedTargets) {
      val hasExistingSignature = hasMacCodeSignature(codesign, target)
      if (requiresExistingMacCodeSignature(app, target) && !hasExistingSignature) {
        throw GradleException(
          "jpackage nested code lacks the signature metadata required for safe replacement: " +
            target.absolutePath
        )
      }
      execAndLog(
        macCodeSigningArgs(
          codesign.absolutePath,
          target.absolutePath,
          signingIdentity,
          hasExistingSignature,
        )
      )
      execAndLog(macCodeVerificationArgs(codesign.absolutePath, target.absolutePath))
    }

    // The enclosing app is always last so its resource seal authenticates every replacement
    // nested signature and the enriched application payload.
    if (!hasMacCodeSignature(codesign, app)) {
      throw GradleException(
        "Final enriched macOS app lacks the jpackage signature metadata required for safe replacement"
      )
    }
    execAndLog(macCodeSigningArgs(codesign.absolutePath, app.absolutePath, signingIdentity, true))
    execAndLog(
      listOf(
        codesign.absolutePath,
        "--verify",
        "--deep",
        "--strict",
        "--verbose=2",
        app.absolutePath,
      )
    )
  }
}

val verifyMacAppImageSigningArguments by tasks.registering {
  group = "verification"
  description = "Verifies the restricted final macOS app-image signing command"
  doLast {
    val args =
      macCodeSigningArgs(
        "codesign",
        "Crypta.app/Contents/runtime/Contents/Home/bin/java",
        "Developer ID Application: Crypta (ABCDEFGHIJ)",
        true,
      )
    val expected =
      listOf(
        "codesign",
        "--force",
        "--options",
        "runtime",
        "--timestamp",
        "--preserve-metadata=identifier,entitlements",
        "--sign",
        "Developer ID Application: Crypta (ABCDEFGHIJ)",
        "Crypta.app/Contents/runtime/Contents/Home/bin/java",
      )
    check(args == expected) { "Unexpected nested app-image signing arguments: $args" }
    check("--deep" !in args) { "Recursive codesign is forbidden at the signing boundary" }
    val unsignedArgs =
      macCodeSigningArgs(
        "codesign",
        "Crypta.app/Contents/app/cryptad-dist/bin/cryptad",
        "Developer ID Application: Crypta (ABCDEFGHIJ)",
        false,
      )
    check(unsignedArgs.none { it.startsWith("--preserve-metadata") }) {
      "Unsigned enriched code cannot claim pre-existing entitlement metadata"
    }
    val verifyArgs = macCodeVerificationArgs("codesign", "nested-code")
    check(verifyArgs == listOf("codesign", "--verify", "--strict", "--verbose=2", "nested-code"))
    val forbidden =
      setOf(
        "--name",
        "--dest",
        "--resource-dir",
        "--runtime-image",
        "--input",
        "--main-jar",
        "--main-class",
        "--icon",
        "--mac-package-identifier",
        "--app-image",
        "--type",
      )
    check(args.none(forbidden::contains)) {
      "Installer or app-construction options reached the predefined app-image signing boundary"
    }

    val fixture = temporaryDir.resolve("Crypta.app")
    val runtimeJava = fixture.resolve("Contents/runtime/Contents/Home/bin/java")
    val runtimeLibrary = fixture.resolve("Contents/runtime/Contents/Home/lib/libjli.dylib")
    val frameworkLibrary = fixture.resolve("Contents/Frameworks/Crypta.framework/Versions/A/Crypta")
    val mainLauncher = fixture.resolve("Contents/MacOS/Crypta")
    val embeddedMacLibrary =
      fixture.resolve("Contents/app/cryptad-dist/lib/libwrapper-macosx-universal-64.dylib")
    val embeddedLinuxWrapper = fixture.resolve("Contents/app/cryptad-dist/bin/wrapper-linux-x86-64")
    val embeddedWindowsWrapper = fixture.resolve("Contents/app/cryptad-dist/bin/wrapper.exe")
    val embeddedScript = fixture.resolve("Contents/app/cryptad-dist/bin/cryptad")
    val resource = fixture.resolve("Contents/app/cryptad-dist/conf/cryptad.ini")
    val fakeMacLibrary = fixture.resolve("Contents/app/cryptad-dist/lib/not-really-native.dylib")
    for (file in
      listOf(
        runtimeJava,
        runtimeLibrary,
        frameworkLibrary,
        mainLauncher,
        embeddedMacLibrary,
        embeddedLinuxWrapper,
        embeddedWindowsWrapper,
        embeddedScript,
        resource,
        fakeMacLibrary,
      )) {
      file.parentFile.mkdirs()
    }
    val machO64Magic = byteArrayOf(0xCF.toByte(), 0xFA.toByte(), 0xED.toByte(), 0xFE.toByte())
    for (file in
      listOf(runtimeJava, runtimeLibrary, frameworkLibrary, mainLauncher, embeddedMacLibrary)) {
      file.writeBytes(machO64Magic)
    }
    embeddedLinuxWrapper.writeBytes(
      byteArrayOf(0x7F, 'E'.code.toByte(), 'L'.code.toByte(), 'F'.code.toByte())
    )
    embeddedWindowsWrapper.writeBytes(byteArrayOf('M'.code.toByte(), 'Z'.code.toByte(), 0, 0))
    embeddedScript.writeText("#!/bin/sh\n")
    resource.writeText("not native code\n")
    fakeMacLibrary.writeText("a suffix is not a file format\n")
    embeddedLinuxWrapper.setExecutable(true)
    embeddedWindowsWrapper.setExecutable(true)
    embeddedScript.setExecutable(true)
    val ordered = macNestedCodeSigningTargets(fixture, "Crypta")
    check(mainLauncher !in ordered) { "The app-root signature must own the main launcher" }
    check(embeddedMacLibrary in ordered) { "An embedded Mach-O library must be signed" }
    check(embeddedLinuxWrapper !in ordered) {
      "An embedded ELF executable must not be codesigned"
    }
    check(embeddedWindowsWrapper !in ordered) {
      "An embedded PE executable must not be codesigned"
    }
    check(embeddedScript !in ordered) { "An executable script must not be codesigned" }
    check(resource !in ordered) { "An ordinary resource must not be codesigned" }
    check(fakeMacLibrary !in ordered) { "A fake .dylib resource must not be codesigned" }
    check(ordered.indexOf(runtimeJava) < ordered.indexOf(fixture.resolve("Contents/runtime"))) {
      "Runtime code must be signed before the runtime bundle root"
    }
    check(
      ordered.indexOf(frameworkLibrary) <
        ordered.indexOf(fixture.resolve("Contents/Frameworks/Crypta.framework"))
    ) {
      "Framework code must be signed before the framework bundle root"
    }
    check((ordered + fixture).last() == fixture) { "The app root must be signed last" }
    check(requiresExistingMacCodeSignature(fixture, runtimeJava))
    check(requiresExistingMacCodeSignature(fixture, frameworkLibrary))
    check(requiresExistingMacCodeSignature(fixture, fixture))
    check(
      !requiresExistingMacCodeSignature(
        fixture,
        fixture.resolve("Contents/app/cryptad-dist/bin/cryptad"),
      )
    )
  }
}

tasks.named("check") { dependsOn(verifyMacAppImageSigningArguments) }

// Build an OS-native installer (dmg/msi/deb) using the image created above.
val jpackageInstallerCryptad by tasks.registering {
  group = "jpackage"
  description = "Creates a native installer for the current OS"
  dependsOn(signFinalMacAppImageCryptad)
  onlyIf {
    when (currentOs()) {
      "linux" -> hasExe("dpkg-deb") || hasExe("rpmbuild")

      "win" -> false

      // Windows installers removed
      else -> true
    }
  }
  doLast {
    val jpackage = resolveJpackageExecutable()
    val outDir = jpackageOutDir.get().asFile.also { it.mkdirs() }

    val os = currentOs()
    val installerType = resolveInstallerType(os)
    val imagePath =
      when (os) {
        "mac" -> outDir.resolve("$appName.app").absolutePath
        else -> outDir.resolve(appName).absolutePath
      }

    val args =
      mutableListOf(
        jpackage.absolutePath,
        "--type",
        installerType,
        "--name",
        appName,
        "--app-version",
        jpackageAppVersion(),
        "--dest",
        outDir.absolutePath,
        "--resource-dir",
        jpackageResourcesDir.get().asFile.absolutePath,
        "--app-image",
        imagePath,
        "--vendor",
        vendor,
      )
    if (providers.gradleProperty("jpackageDebug").orNull == "true") args += "--verbose"
    if (os == "mac") {
      args.addAll(listOf("--mac-package-identifier", appId))
      val signingKeyUserName = macSigningKeyUserName()
      if (signingKeyUserName.isNotEmpty()) {
        args.addAll(listOf("--mac-sign", "--mac-signing-key-user-name", signingKeyUserName))
      }
    }
    if (os == "linux") {
      // Install under a stable path used by our service/scripts and tests
      args.addAll(listOf("--install-dir", "/opt/cryptad"))
    }
    // Also pass icon for installer builds so the packaged icon matches our provided file.
    args.addAll(listOf("--icon", iconPathForOs()))

    logger.lifecycle("Executing jpackage installer:\n{}", args.joinToString(" "))
    execAndLog(args)

    // Keep jpackage default filenames (e.g., Crypta-<version>.<ext>)
  }
}

// Explicit Linux installer tasks to force a specific package type
val jpackageInstallerRpm by tasks.registering {
  group = "jpackage"
  description = "Creates an RPM installer for Linux"
  dependsOn(enrichAppImageWithDist)
  onlyIf { currentOs() == "linux" && hasExe("rpmbuild") }
  doLast {
    val jpackage = resolveJpackageExecutable()
    val outDir = jpackageOutDir.get().asFile.also { it.mkdirs() }
    val imagePath = outDir.resolve(appName).absolutePath
    val args =
      mutableListOf(
        jpackage.absolutePath,
        "--type",
        "rpm",
        "--name",
        appName,
        "--app-version",
        jpackageAppVersion(),
        "--dest",
        outDir.absolutePath,
        "--resource-dir",
        jpackageResourcesDir.get().asFile.absolutePath,
        "--app-image",
        imagePath,
        "--vendor",
        vendor,
        "--install-dir",
        "/opt/cryptad",
      )
    // jpackage (JDK 25) does not accept linux post-install flags here; use template.spec
    // override.
    args.addAll(listOf("--icon", iconPathForOs()))
    if (providers.gradleProperty("jpackageDebug").orNull == "true") args += "--verbose"
    logger.lifecycle("Executing jpackage RPM installer:\n{}", args.joinToString(" "))
    execAndLog(args)
  }
}

val jpackageInstallerDeb by tasks.registering {
  group = "jpackage"
  description = "Creates a DEB installer for Linux"
  dependsOn(enrichAppImageWithDist)
  onlyIf { currentOs() == "linux" && hasExe("dpkg-deb") }
  doLast {
    val jpackage = resolveJpackageExecutable()
    val outDir = jpackageOutDir.get().asFile.also { it.mkdirs() }
    val imagePath = outDir.resolve(appName).absolutePath
    val args =
      mutableListOf(
        jpackage.absolutePath,
        "--type",
        "deb",
        "--name",
        appName,
        "--app-version",
        jpackageAppVersion(),
        "--dest",
        outDir.absolutePath,
        "--resource-dir",
        jpackageResourcesDir.get().asFile.absolutePath,
        "--app-image",
        imagePath,
        "--vendor",
        vendor,
        "--install-dir",
        "/opt/cryptad",
      )
    // Scripts handled via resource-dir (postinst/postrm) for DEB.
    args.addAll(listOf("--icon", iconPathForOs()))
    if (providers.gradleProperty("jpackageDebug").orNull == "true") args += "--verbose"
    logger.lifecycle("Executing jpackage DEB installer:\n{}", args.joinToString(" "))
    execAndLog(args)
  }
}

// Convenience task to build all Linux installers available on the host
val jpackageInstallerLinuxAll by tasks.registering {
  group = "jpackage"
  description = "Builds all supported Linux installers (deb/rpm)"
  dependsOn(jpackageInstallerDeb)
  dependsOn(jpackageInstallerRpm)
  onlyIf { currentOs() == "linux" && (hasExe("dpkg-deb") || hasExe("rpmbuild")) }
}

/** Builds the closed jpackage command used by the protected Windows EXE producer. */
fun windowsExeInstallerArgs(
  jpackagePath: String,
  appVersion: String,
  outputPath: String,
  resourcesPath: String,
  appImagePath: String,
  iconPath: String,
  verbose: Boolean,
): List<String> = buildList {
  addAll(
    listOf(
      jpackagePath,
      "--type",
      "exe",
      "--name",
      appName,
      "--app-version",
      appVersion,
      "--dest",
      outputPath,
      "--resource-dir",
      resourcesPath,
      "--app-image",
      appImagePath,
      "--vendor",
      vendor,
      "--icon",
      iconPath,
      "--win-upgrade-uuid",
      windowsUpgradeUuid,
      "--win-dir-chooser",
      "--win-menu",
      "--win-shortcut",
    )
  )
  if (verbose) add("--verbose")
}

/** Builds the protected Windows EXE from the final enriched app image. */
val jpackageInstallerWindowsExeCryptad by tasks.registering {
  group = "jpackage"
  description = "Creates the Stable maintenance Windows EXE installer"
  dependsOn(enrichAppImageWithDist)
  doLast {
    if (currentOs() != "win") {
      throw GradleException("jpackageInstallerWindowsExeCryptad requires a Windows host")
    }
    val jpackage = resolveJpackageExecutable()
    val outDir = jpackageOutDir.get().asFile.also { it.mkdirs() }
    val imagePath = outDir.resolve(appName)
    if (!imagePath.isDirectory) {
      throw GradleException("Final enriched Windows app image not found: ${imagePath.absolutePath}")
    }
    val args =
      windowsExeInstallerArgs(
        jpackage.absolutePath,
        jpackageAppVersion(),
        outDir.absolutePath,
        jpackageResourcesDir.get().asFile.absolutePath,
        imagePath.absolutePath,
        iconPathForOs(),
        providers.gradleProperty("jpackageDebug").orNull == "true",
      )
    logger.lifecycle("Executing jpackage Windows EXE installer")
    execAndLog(args)
  }
}

val verifyWindowsExeInstallerArguments by tasks.registering {
  group = "verification"
  description = "Verifies the protected Windows EXE jpackage command"
  doLast {
    val args =
      windowsExeInstallerArgs(
        "jpackage.exe",
        jpackageAppVersion("win", "301"),
        "jpackage-output",
        "jpackage-resources",
        "Crypta",
        "cryptad.ico",
        true,
      )
    check(args.take(3) == listOf("jpackage.exe", "--type", "exe"))
    check(args.windowed(2).contains(listOf("--app-version", "1.0.301")))
    check(jpackageAppVersion("win", "301") == "1.0.301")
    check(jpackageAppVersion("linux", "301") == "301")
    check(jpackageAppVersion("mac", "301") == "301")
    check(args.containsAll(listOf("--app-image", "--win-upgrade-uuid", windowsUpgradeUuid)))
    check(args.count { it == "--win-upgrade-uuid" } == 1)
    check(args.last() == "--verbose")
    for (invalidBuild in listOf("0", "065", "65536", "1.0", "not-a-build")) {
      check(runCatching { windowsMsiAppVersion(invalidBuild) }.isFailure)
    }
  }
}

tasks.named("check") { dependsOn(verifyWindowsExeInstallerArguments) }

// WiX relink task removed

// Ensure the built app image is fully usable by default builds
// (copies cryptad-dist into the image and patches launcher cfg).
tasks.named("build") {
  dependsOn(enrichAppImageWithDist)
  // On Linux, also build native installers (DEB/RPM) when the host has the tools.
  if (currentOs() == "linux") {
    dependsOn(jpackageInstallerLinuxAll)
  }
  // On macOS, also build a DMG installer.
  if (currentOs() == "mac") {
    dependsOn(jpackageInstallerCryptad)
  }
}
