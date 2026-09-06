import com.github.spotbugs.snom.SpotBugsTask
import java.time.Instant
import javax.xml.stream.XMLOutputFactory
import net.ltgt.gradle.errorprone.errorprone
import org.gradle.api.logging.StandardOutputListener
import org.gradle.api.services.BuildService
import org.gradle.api.services.BuildServiceParameters
import org.gradle.api.tasks.compile.JavaCompile

plugins {
  java
  jacoco
  id("com.github.spotbugs")
  id("net.ltgt.errorprone")
}

abstract class ErrorProneReportService : BuildService<BuildServiceParameters.None>

data class ErrorProneDiagnostic(
  val file: String,
  val line: Int,
  val severity: String,
  val check: String,
  val message: String,
  val details: String,
)

fun parseErrorProneDiagnostics(output: String): List<ErrorProneDiagnostic> {
  val pattern = Regex("^(.+):(\\d+): (warning|error): \\[(.+)] (.+)$")
  val diagnostics = mutableListOf<ErrorProneDiagnostic>()
  var current: ErrorProneDiagnostic? = null
  val detailsBuffer = StringBuilder()

  fun flush() {
    val diag = current ?: return
    diagnostics.add(diag.copy(details = detailsBuffer.toString().trimEnd()))
    current = null
    detailsBuffer.setLength(0)
  }

  output.lineSequence().forEach { line ->
    val match = pattern.matchEntire(line)
    if (match != null) {
      flush()
      val file = match.groupValues[1]
      val lineNumber = match.groupValues[2].toInt()
      val severity = match.groupValues[3]
      val check = match.groupValues[4]
      val message = match.groupValues[5]
      current = ErrorProneDiagnostic(file, lineNumber, severity, check, message, "")
    } else if (current != null) {
      if (line.isNotBlank()) {
        detailsBuffer.append(line).append('\n')
      }
    }
  }
  flush()
  return diagnostics
}

val libs: VersionCatalog = extensions.getByType<VersionCatalogsExtension>().named("libs")

val errorproneReportService =
  gradle.sharedServices.registerIfAbsent(
    "errorproneReportService",
    ErrorProneReportService::class,
  ) {
    maxParallelUsages.set(1)
  }

val errorproneReportTask =
  tasks.register("errorproneReport") {
    group = "verification"
    description = "Generates Error Prone XML reports for Java compile tasks."
  }

errorproneReportTask.configure { dependsOn(tasks.withType<JavaCompile>()) }

val errorproneReportEnabled = providers.provider {
  gradle.startParameter.taskNames.any { taskName ->
    taskName == "errorproneReport" || taskName.endsWith(":errorproneReport")
  }
}

spotbugs { ignoreFailures = true }

val spotbugsExcludeFilter =
  rootProject.layout.projectDirectory.file("build-logic/spotbugs-exclude.xml")

val spotbugsTestExcludeFilter =
  rootProject.layout.projectDirectory.file("build-logic/spotbugs-exclude-test.xml")

tasks.withType<SpotBugsTask>().configureEach {
  excludeFilter.set(
    if (name == "spotbugsTest") spotbugsTestExcludeFilter else spotbugsExcludeFilter
  )

  val xmlReport = reports.maybeCreate("xml")
  xmlReport.required.set(true)
  xmlReport.outputLocation.set(layout.buildDirectory.file("reports/spotbugs/$name.xml"))

  reports.matching { it.name == "text" }.configureEach { required.set(false) }
}

java {
  toolchain { languageVersion.set(JavaLanguageVersion.of(25)) }
  sourceCompatibility = JavaVersion.VERSION_25
  targetCompatibility = JavaVersion.VERSION_25
}

repositories {
  mavenCentral {
    metadataSources {
      mavenPom()
      artifact()
      ignoreGradleMetadataRedirection()
    }
  }
}

sourceSets.named("main") {
  // Exclude templated Version.java from direct compilation; generated source is compiled instead.
  java.exclude("network/crypta/node/Version.java")
}

dependencies { add("errorprone", libs.findLibrary("errorproneCore").get()) }

tasks.withType<JavaCompile>().configureEach {
  options.encoding = "UTF-8"
  // Surface deprecation/unchecked sites explicitly during compilation.
  options.compilerArgs.addAll(listOf("-Xlint:deprecation", "-Xlint:unchecked"))
  options.errorprone.allErrorsAsWarnings.set(true)

  val taskPathLabel = path.removePrefix(":").replace(':', '_').ifBlank { "root" }
  val reportFileProvider = layout.buildDirectory.file("reports/errorprone/$taskPathLabel/$name.xml")
  if (errorproneReportEnabled.get()) {
    outputs.file(reportFileProvider)
    outputs.upToDateWhen { false }
    usesService(errorproneReportService)
  }

  val capturedOutput = StringBuilder()
  val standardOutListener = StandardOutputListener { capturedOutput.append(it) }
  val standardErrListener = StandardOutputListener { capturedOutput.append(it) }

  doFirst {
    if (!errorproneReportEnabled.get()) return@doFirst
    logging.addStandardOutputListener(standardOutListener)
    logging.addStandardErrorListener(standardErrListener)
  }

  doLast {
    if (!errorproneReportEnabled.get()) return@doLast
    logging.removeStandardOutputListener(standardOutListener)
    logging.removeStandardErrorListener(standardErrListener)

    val diagnostics = parseErrorProneDiagnostics(capturedOutput.toString())
    val reportFile = reportFileProvider.get().asFile
    reportFile.parentFile.mkdirs()

    val writer =
      XMLOutputFactory.newInstance().createXMLStreamWriter(reportFile.writer(Charsets.UTF_8))
    writer.writeStartDocument("UTF-8", "1.0")
    writer.writeStartElement("errorproneReport")
    writer.writeAttribute("project", project.path)
    writer.writeAttribute("task", name)
    writer.writeAttribute("generatedAt", Instant.now().toString())
    diagnostics.forEach { diagnostic ->
      writer.writeStartElement("diagnostic")
      writer.writeAttribute("severity", diagnostic.severity)
      writer.writeAttribute("check", diagnostic.check)
      writer.writeAttribute("file", diagnostic.file)
      writer.writeAttribute("line", diagnostic.line.toString())

      writer.writeStartElement("message")
      writer.writeCharacters(diagnostic.message)
      writer.writeEndElement()

      if (diagnostic.details.isNotBlank()) {
        writer.writeStartElement("details")
        writer.writeCharacters(diagnostic.details)
        writer.writeEndElement()
      }
      writer.writeEndElement()
    }
    writer.writeEndElement()
    writer.writeEndDocument()
    writer.flush()
    writer.close()
  }
}

tasks.withType<Javadoc>().configureEach {
  options.encoding = "UTF-8"
  isFailOnError = false
}

// Tests: settings and module opens needed at runtime
tasks.withType<Test>().configureEach {
  useJUnitPlatform()
  // Verbose failures: full exception stack traces/causes for easier debugging
  testLogging { exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL }
  // Open JDK internals used by tests
  if (JavaVersion.current() >= JavaVersion.VERSION_1_9) {
    jvmArgs("--add-opens=java.base/java.lang=ALL-UNNAMED")
    jvmArgs("--add-opens=java.base/java.util=ALL-UNNAMED")
    jvmArgs("--add-opens=java.base/java.io=ALL-UNNAMED")
    jvmArgs("--add-opens=java.base/java.util.zip=ALL-UNNAMED")
    jvmArgs("--enable-native-access=ALL-UNNAMED")
  }
  // Allow dynamic agent loading for Mockito inline mock-maker (JEP 451).
  jvmArgs("-XX:+EnableDynamicAgentLoading")
  minHeapSize = "128m"
  maxHeapSize = "512m"
  include("network/crypta/**/*Test.class")
  include("com/jthemedetecor/**/*Test.class")
  include("com/onionnetworks/**/*Test.class")
  include("org/bitpedia/**/*Test.class")
  include("org/spaceroots/**/*Test.class")
  include("org/sevenzip/**/*Test.class")
  include("org/spaceroots/**/*Test.class")
  exclude("network/crypta/**/*$*Test.class")
  exclude("com/jthemedetecor/**/*$*Test.class")
  exclude("com/onionnetworks/**/*$*Test.class")
  exclude("org/bitpedia/**/*$*Test.class")
  exclude("org/spaceroots/**/*$*Test.class")
  exclude("org/sevenzip/**/*$*Test.class")
  exclude("org/spaceroots/**/*$*Test.class")
  // Point tests expecting old layout to new standard resource locations
  systemProperty("test.l10npath_test", "src/test/resources/network/crypta/l10n/")
  systemProperty("test.l10npath_main", "foundation-config/src/main/resources/network/crypta/l10n/")
}

// Match prior behavior: disable assertions in tests
tasks.withType<Test>().configureEach { enableAssertions = false }

// JaCoCo setup: use a recent agent and produce XML for Sonar
extensions.configure<JacocoPluginExtension>("jacoco") {
  toolVersion = libs.findVersion("jacoco").get().requiredVersion
}

// Generate XML + HTML reports; ensure reports run after tests
tasks.withType<JacocoReport>().configureEach {
  dependsOn(tasks.withType<Test>())
  reports {
    xml.required.set(true)
    csv.required.set(false)
    html.required.set(true)
  }
}

// Enforce a coverage threshold (80% minimum)
tasks.withType<JacocoCoverageVerification>().configureEach {
  dependsOn(tasks.withType<Test>())
  violationRules {
    // Do not fail the build on coverage violations; still log them
    isFailOnViolation = false
    rule {
      limit {
        counter = "LINE"
        value = "COVEREDRATIO"
        minimum = BigDecimal("0.80")
      }
    }
  }
}

// Integrate coverage checks with the standard lifecycle
tasks.named("check") {
  dependsOn(tasks.withType<JacocoReport>())
  dependsOn(tasks.withType<JacocoCoverageVerification>())
}
