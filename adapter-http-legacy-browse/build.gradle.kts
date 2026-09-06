plugins {
  id("cryptad.java-kotlin-conventions")
  id("cryptad.spotless")
}

version = rootProject.version

val mainSourceSet = sourceSets.named("main")

dependencies {
  implementation(project(":adapter-http-legacy-admin"))
  implementation(project(":foundation-support"))
  implementation(project(":foundation-config"))
  implementation(project(":foundation-fs"))
  implementation(project(":foundation-compat"))
  implementation(project(":foundation-crypto-keys"))
  implementation(project(":interop-wire"))
  implementation(project(":kernel-content"))
  implementation(project(":kernel-transport"))
  implementation(project(":kernel-routing"))
  implementation(project(":runtime-spi"))
  implementation(project(":platform-api"))
  implementation(project(":platform-apphost"))
  implementation(project(":platform-web-shell"))
  implementation(project(":runtime-alerts"))
  implementation(project(":thirdparty-onion"))

  implementation(libs.slf4jApi)
  implementation(libs.pebble)
  implementation(files(rootProject.file("libs/wrapper.jar")))

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
