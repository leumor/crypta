package cryptad

import java.nio.file.Files
import java.nio.file.Path
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class IndependentAppPackagingTaskContractTest {
  private val appProjects =
    listOf(
      "queue-manager",
      "publisher",
      "feed-reader",
      "profile-publisher",
      "social-inbox",
      "site-publisher",
      "trust-graph",
    )

  @Test
  fun rootAggregate_whenInspected_expectExactlyAllUnsignedAppPackagingTasks() {
    val rootBuild = Files.readString(repositoryRoot().resolve("build.gradle.kts"))
    val block =
      rootBuild.substringAfter(
        "tasks.register(\"packageUnsignedFirstPartyAppsForIndependentReproducibility\")"
      )
        .substringBefore("// The default from build-logic")

    val dependencies =
      Regex(
          """dependsOn\(":apps:([a-z-]+):packageUnsignedAppForIndependentReproducibility"\)"""
        )
        .findAll(block)
        .map { match -> match.groupValues[1] }
        .toList()

    assertEquals(appProjects, dependencies)
    assertFalse(block.contains(":signApp"))
    assertFalse(block.contains(":verifyApp"))
    assertFalse(block.contains(":packageApp"))
  }

  @Test
  fun appTasks_whenInspected_expectUnsignedSecretFreeIsolatedPackagingContract() {
    for (appProject in appProjects + "mail-prototype") {
      val buildFile =
        Files.readString(repositoryRoot().resolve("apps/$appProject/build.gradle.kts"))
      val block =
        buildFile.substringAfter("val packageUnsignedAppForIndependentReproducibility ")
          .substringBefore("tasks.named<Test>")

      assertTrue(
        buildFile.contains("val packageApp by") || buildFile.contains("val packageApp ="),
        appProject,
      )
      assertTrue(
        block.contains("tasks.registering(JavaExec::class)") ||
          block.contains("tasks.register<JavaExec>(\"packageUnsignedAppForIndependentReproducibility\")"),
        appProject,
      )
      assertTrue(block.contains("dependsOn(stageApp)"), appProject)
      assertTrue(block.contains("classpath = appDistCli"), appProject)
      assertTrue(block.contains("mainClass.set(appDistMainClass)"), appProject)
      assertTrue(block.contains("\"package\""), appProject)
      assertTrue(block.contains("reproducibilityPayloadFile"), appProject)
      assertTrue(
        buildFile.contains($$"cryptad-app-reproducibility-payload/$appId-${project.version}.zip"),
        appProject,
      )
      assertFalse(block.contains("dependsOn(signApp"), appProject)
      assertFalse(block.contains("dependsOn(verifyApp"), appProject)
      assertFalse(block.contains("requiredSigningInput"), appProject)
      assertFalse(block.contains("addPrivateKeyArguments"), appProject)
      assertFalse(block.contains("addPublicKeyArguments"), appProject)
      assertFalse(block.contains("CRYPTAD_APP_SIGNING_"), appProject)
      for (
        sidecar in
          listOf(
            "cryptad-app.digests",
            "cryptad-app.signature",
            "cryptad-app.catalog",
            "cryptad-app.catalog.signature",
          )
      ) {
        assertTrue(block.contains("\"$sidecar\""), "$appProject must reject $sidecar")
      }
    }
  }

  private fun repositoryRoot(): Path {
    var current: Path? = Path.of("").toAbsolutePath().normalize()
    while (current != null) {
      if (
        Files.isRegularFile(current.resolve("settings.gradle.kts")) &&
          Files.isDirectory(current.resolve("apps/queue-manager"))
      ) {
        return current
      }
      current = current.parent
    }
    throw IllegalStateException("Cannot locate the Cryptad repository root")
  }
}
