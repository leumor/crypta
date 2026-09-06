package cryptad

import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.attribute.BasicFileAttributes
import java.security.MessageDigest
import java.util.Locale
import org.gradle.api.GradleException

internal object StableJdkFingerprint {
  const val ALGORITHM = "crypta-jdk-installed-tree-sha256-v1"
  private const val MAXIMUM_ENTRIES = 100_000
  private const val MAXIMUM_FILE_BYTES = 2_000_000_000L
  private val STABLE_RUNTIME_BUILD = Regex("^(25\\.[0-9]+\\.[0-9]+(?:\\.[0-9]+)?\\+[0-9]+)(?:-LTS)?$")

  fun canonicalRuntimeBuild(reportedVersion: String): String =
    STABLE_RUNTIME_BUILD.matchEntire(reportedVersion)?.groupValues?.get(1)
      ?: throw GradleException("Observed Java runtime version is not a canonical Stable JDK build")

  fun identity(javaHome: Path): Map<String, String> {
    if (Files.isSymbolicLink(javaHome) || !Files.isDirectory(javaHome, LinkOption.NOFOLLOW_LINKS)) {
      throw GradleException("Observed Java home is not a safe installation directory")
    }
    val root = javaHome.toRealPath(LinkOption.NOFOLLOW_LINKS)
    val paths = Files.walk(root).use { stream -> stream.filter { it != root }.toList() }
    if (paths.isEmpty() || paths.size > MAXIMUM_ENTRIES) {
      throw GradleException("JDK installation exceeds the fingerprint entry bound")
    }
    val folded = mutableSetOf<String>()
    val entries =
      paths
        .sortedBy { relativePath(root, it) }
        .map { path ->
          val relative = relativePath(root, path)
          if (!folded.add(relative.lowercase(Locale.ROOT))) {
            throw GradleException("JDK installation contains a case-fold path collision")
          }
          val attributes =
            Files.readAttributes(
              path,
              BasicFileAttributes::class.java,
              LinkOption.NOFOLLOW_LINKS,
            )
          when {
            attributes.isSymbolicLink -> symlinkEntry(root, path, relative)
            attributes.isDirectory -> entry(relative, "directory", null, 0, null)
            attributes.isRegularFile -> {
              val digest = digestFile(path)
              entry(relative, "file", digest.first, digest.second, null)
            }
            else -> throw GradleException("JDK installation contains a special file")
          }
        }
    val release = root.resolve("release")
    if (Files.isSymbolicLink(release) || !Files.isRegularFile(release, LinkOption.NOFOLLOW_LINKS)) {
      throw GradleException("JDK installation lacks a safe release identity file")
    }
    val manifest = sortedMapOf<String, Any?>("algorithm" to ALGORITHM, "entries" to entries)
    return sortedMapOf(
      "installationManifestDigest" to
        prefixed(StableSupplyChainJson.sha256(StableSupplyChainJson.canonicalBytes(manifest))),
      "releaseFileDigest" to digestFile(release).first,
    )
  }

  private fun symlinkEntry(
    root: Path,
    path: Path,
    relative: String,
  ): Map<String, Any?> {
    val target = Files.readSymbolicLink(path)
    if (target.toString().isBlank() || target.isAbsolute) {
      throw GradleException("JDK installation contains an unsafe symbolic link")
    }
    val resolved = path.parent.resolve(target).normalize()
    if (!resolved.startsWith(root)) {
      throw GradleException("JDK installation contains an escaping symbolic link")
    }
    return entry(relative, "symlink", null, 0, target.toString().replace('\\', '/'))
  }

  private fun entry(
    path: String,
    kind: String,
    digest: String?,
    size: Long,
    target: String?,
  ): Map<String, Any?> =
    sortedMapOf("digest" to digest, "kind" to kind, "path" to path, "size" to size, "target" to target)

  private fun relativePath(root: Path, path: Path): String =
    root.relativize(path).toString().replace('\\', '/')

  private fun digestFile(path: Path): Pair<String, Long> {
    val digest = MessageDigest.getInstance("SHA-256")
    var size = 0L
    Files.newInputStream(path).buffered().use { input ->
      val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
      while (true) {
        val read = input.read(buffer)
        if (read < 0) break
        size += read
        if (size > MAXIMUM_FILE_BYTES) {
          throw GradleException("JDK installation file exceeds the fingerprint byte bound")
        }
        digest.update(buffer, 0, read)
      }
    }
    return prefixed(digest.digest().joinToString("") { "%02x".format(it) }) to size
  }

  private fun prefixed(value: String): String = "sha256:$value"
}
