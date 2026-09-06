plugins {
  id("cryptad.java-kotlin-conventions")
  id("cryptad.spotless")
}

version = rootProject.version

val mainSourceSet = sourceSets.named("main")

dependencies {
  implementation(project(":adapter-http-legacy-admin"))
  implementation(project(":adapter-http-legacy-browse"))
  implementation(project(":foundation-support"))
  implementation(project(":foundation-config"))
  implementation(project(":foundation-crypto-keys"))
  implementation(project(":kernel-content"))
  implementation(project(":kernel-routing"))
  implementation(project(":platform-api"))
  implementation(project(":platform-appcatalog"))
  implementation(project(":platform-appdist"))
  implementation(project(":platform-appvault"))
  implementation(project(":runtime-alerts"))
  implementation(project(":runtime-spi"))
  implementation(project(":platform-apphost"))
  implementation(project(":runtime-node"))

  implementation(libs.slf4jApi)

  compileOnly(libs.jetbrainsAnnotations)

  testImplementation(mainSourceSet.map { it.output })
  testImplementation(libs.junitJupiterApi)
  testImplementation(libs.junitJupiterParams)
  testImplementation(libs.mockitoCore)
  testImplementation(libs.mockitoJunitJupiter)
  testImplementation(project(":platform-web-shell"))
  testCompileOnly(libs.jetbrainsAnnotations)
  testRuntimeOnly(libs.junitJupiterEngine)
  testRuntimeOnly(libs.junitPlatformLauncher)
}
