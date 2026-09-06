plugins {
  id("cryptad.java-kotlin-conventions")
  id("cryptad.spotless")
  `java-library`
}

version = rootProject.version

val mainSourceSet = sourceSets.named("main")

dependencies {
  implementation(project(":foundation-crypto-keys"))
  implementation(project(":foundation-fs"))
  implementation(project(":foundation-support"))
  implementation(project(":kernel-content"))

  api(project(":runtime-spi"))
  api(project(":platform-app-ui"))
  api(project(":platform-apphost"))
  api(project(":platform-appcatalog"))
  api(project(":platform-appvault"))
  api(project(":platform-trustgraph"))

  compileOnly(libs.jetbrainsAnnotations)

  testImplementation(mainSourceSet.map { it.output })
  testImplementation(libs.junitJupiterApi)
  testImplementation(libs.junitJupiterParams)
  testImplementation(libs.mockitoCore)
  testImplementation(libs.mockitoJunitJupiter)
  testRuntimeOnly(libs.junitJupiterEngine)
  testRuntimeOnly(libs.junitPlatformLauncher)
}
