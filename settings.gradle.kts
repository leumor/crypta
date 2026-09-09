pluginManagement {
  val toml = file("gradle/libs.versions.toml").readText()
  fun version(key: String): String {
    val pattern = Regex("""^\s*${Regex.escape(key)}\s*=\s*\"([^\"]+)\"""", RegexOption.MULTILINE)
    return pattern.find(toml)?.groupValues?.get(1)
      ?: error("Version '$key' not found in libs.versions.toml")
  }

  repositories {
    gradlePluginPortal()
    mavenCentral()
  }
  plugins {
    id("org.gradle.toolchains.foojay-resolver-convention") version version("foojayResolver")
  }
}

// Configure repositories for Java toolchain auto-provisioning (fixes Gradle 10 deprecation)
plugins { id("org.gradle.toolchains.foojay-resolver-convention") }

dependencyResolutionManagement {
  repositoriesMode.set(RepositoriesMode.PREFER_PROJECT)
  repositories {
    mavenCentral {
      metadataSources {
        mavenPom()
        artifact()
        ignoreGradleMetadataRedirection()
      }
    }
  }
}

rootProject.name = "cryptad"

include(
  ":apps:queue-manager",
  ":apps:publisher",
  ":apps:feed-reader",
  ":apps:profile-publisher",
  ":apps:social-inbox",
  ":apps:site-publisher",
  ":apps:trust-graph",
  ":apps:mail-prototype",
  ":platform-design-system",
  ":platform-appvault",
  ":platform-appdist",
  ":platform-devtools",
  ":platform-app-ui",
  ":platform-appcatalog",
  ":platform-trustgraph",
  ":foundation-support",
  ":foundation-store",
  ":foundation-store-contracts",
  ":foundation-crypto-keys",
  ":interop-wire",
  ":foundation-config",
  ":foundation-fs",
  ":foundation-compat",
  ":kernel-content",
  ":kernel-transport",
  ":kernel-routing",
  ":runtime-spi",
  ":platform-api",
  ":platform-apphost",
  ":platform-sdk-js",
  ":platform-web-shell",
  ":runtime-alerts",
  ":runtime-node",
  ":adapter-fcp",
  ":bridge-fcp-runtime",
  ":bridge-http-runtime",
  ":adapter-http-legacy-admin",
  ":adapter-http-legacy-browse",
  ":thirdparty-onion",
  ":thirdparty-legacy",
  ":launcher-desktop",
)

// Gradle 9: Use an included build for convention plugins instead of buildSrc
includeBuild("build-logic")
