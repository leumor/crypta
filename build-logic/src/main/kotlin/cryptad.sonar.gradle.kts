import java.net.URI
import java.net.URLEncoder
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.charset.StandardCharsets
import javax.xml.stream.XMLInputFactory
import javax.xml.stream.XMLOutputFactory
import javax.xml.stream.XMLStreamConstants
import name.remal.gradle_plugins.sonarlint.SonarLint
import name.remal.gradle_plugins.sonarlint.SonarLintSettings

plugins {
  // Apply SonarQube/SonarCloud and SonarLint centrally via convention plugin
  id("org.sonarqube")
  id("name.remal.sonarlint")
}

// Central Sonar configuration for all projects applying this convention
sonar {
  properties {
    property("sonar.projectKey", "crypta-network_cryptad")
    property("sonar.organization", "crypta-network")
    property("sonar.host.url", "https://sonarcloud.io")

    // Point Sonar to the JaCoCo XML report produced by jacocoTestReport
    property(
      "sonar.coverage.jacoco.xmlReportPaths",
      "build/reports/jacoco/test/jacocoTestReport.xml",
    )
    // Use Kotlin-only JUnit reports to avoid KotlinSurefire warnings on Java tests.
    property("sonar.junit.reportPaths", "build/sonar-test-results/kotlin")
    property("sonar.testExecutionReportPaths", "build/sonar-test-results/test-execution.xml")
    property("sonar.tests", "src/test/java,src/test/kotlin")
    property("sonar.test.inclusions", "src/test/java/**,src/test/kotlin/**")
    property("sonar.exclusions", "**/doc-files/**")

    // Read token from environment if provided to avoid passing on CLI (modern scanners read
    // sonar.token)
    providers.environmentVariable("SONAR_TOKEN").orNull?.let { token ->
      if (token.isNotBlank()) property("sonar.token", token)
    }
  }
}

// Minimal SonarLint configuration with optional file scoping via -Psonarlint.sources
extensions.configure<SonarLintSettings>("sonarLint") {
  // default: don't fail builds on findings until CI is configured to be green
  ignoreFailures.convention(true)

  val includeProp =
    providers
      .gradleProperty("sonarlint.sources")
      .orElse(providers.gradleProperty("sonarlint.include"))
      .orElse(providers.gradleProperty("sonar.inclusions"))

  includeProp.orNull?.let { value ->
    // Use Sonar's standard inclusions property so the engine narrows the scope
    sonarProperty("sonar.inclusions", value)
  }

  sonarProperty("sonar.exclusions", "**/doc-files/**")

  val fileProp = providers.gradleProperty("sonarlint.file").orElse(providers.gradleProperty("file"))
  fileProp.orNull?.let { value ->
    if (value.startsWith("src/test/")) {
      sonarProperty("sonar.tests", value)
      sonarProperty("sonar.test.inclusions", value)
    } else {
      sonarProperty("sonar.inclusions", value)
    }
  }

  // Ensure Java language level is explicitly provided so rules that depend on
  // the runtime version (e.g., java:S6204 requiring Java 16+) are evaluated
  // consistently, including for single-file analyses.
  val javaExt = project.extensions.findByType(JavaPluginExtension::class.java)
  val sourceVersion = (javaExt?.sourceCompatibility ?: JavaVersion.current()).majorVersion
  val targetVersion = (javaExt?.targetCompatibility ?: JavaVersion.current()).majorVersion
  sonarProperty("sonar.java.source", sourceVersion)
  sonarProperty("sonar.java.target", targetVersion)
}

// Convenience task: run SonarLint on a single file
// Usage:
//   ./gradlew sonarlintFile -Psonarlint.file=src/main/java/SevenZip/LzmaAlone.java
//   (aliases: -Pfile=..., -Psonarlint.sources=...)
val sourceSets: SourceSetContainer = extensions.getByType(SourceSetContainer::class.java)
val additionalSonarMainSourceDirs: Provider<List<File>> = providers.provider {
  (project.findProperty("cryptad.additionalSonarMainSourceDirs") as? Iterable<*>)?.filterIsInstance<
    File
  >() ?: emptyList()
}
val additionalSonarMainOutputDirs: Provider<List<File>> = providers.provider {
  (project.findProperty("cryptad.additionalSonarMainOutputDirs") as? Iterable<*>)?.filterIsInstance<
    File
  >() ?: emptyList()
}
val kotlinTestReportDir: Provider<Directory> =
  layout.buildDirectory.dir("sonar-test-results/kotlin")
val testExecutionReportFile: Provider<RegularFile> =
  layout.buildDirectory.file("sonar-test-results/test-execution.xml")
val testResultsDir: Provider<Directory> = layout.buildDirectory.dir("test-results/test")
val additionalSonarTestSourceDirs: Provider<List<File>> = providers.provider {
  (project.findProperty("cryptad.additionalSonarTestSourceDirs") as? Iterable<*>)?.filterIsInstance<
    File
  >() ?: emptyList()
}
val additionalSonarTestResultDirs: Provider<List<File>> = providers.provider {
  (project.findProperty("cryptad.additionalSonarTestResultDirs") as? Iterable<*>)?.filterIsInstance<
    File
  >() ?: emptyList()
}

tasks.register("prepareKotlinTestReports") {
  group = "verification"
  description = "Collect Kotlin JUnit reports for Sonar analysis."
  dependsOn(tasks.withType<Test>())
  inputs.dir(testResultsDir)
  outputs.dir(kotlinTestReportDir)

  doLast {
    val testSourceSet = sourceSets.named("test").get()
    val kotlinTestFiles = testSourceSet.allSource.matching { include("**/*.kt") }.files

    val kotlinClassNames =
      kotlinTestFiles
        .mapNotNull { file ->
          val rootDir =
            testSourceSet.allSource.srcDirs.firstOrNull { srcDir ->
              file.toPath().startsWith(srcDir.toPath())
            }
          rootDir?.toPath()?.relativize(file.toPath())?.toString()
        }
        .map { relativePath ->
          relativePath
            .removeSuffix(".kt")
            .replace(File.separatorChar, '.')
            .replace('/', '.')
            .replace('\\', '.')
        }
        .distinct()

    val reportDir = testResultsDir.get().asFile
    val outputDir = kotlinTestReportDir.get().asFile
    if (outputDir.exists()) {
      outputDir.deleteRecursively()
    }
    outputDir.mkdirs()

    val reportNames =
      kotlinClassNames
        .flatMap { className -> listOf("TEST-$className.xml", "TESTS-$className.xml") }
        .toSet()

    reportNames.forEach { reportName ->
      val reportFile = File(reportDir, reportName)
      if (reportFile.isFile) {
        reportFile.copyTo(File(outputDir, reportName), overwrite = true)
      }
    }
  }
}

tasks.register("prepareTestExecutionReport") {
  group = "verification"
  description = "Convert JUnit XML reports into Sonar's generic test execution format."
  dependsOn(tasks.withType<Test>())
  inputs.dir(testResultsDir)
  inputs.files(additionalSonarTestSourceDirs)
  inputs.files(additionalSonarTestResultDirs)
  outputs.file(testExecutionReportFile)

  val projectPath = rootProject.projectDir.toPath()

  doLast {
    data class TestCase(
      val name: String,
      val durationMs: Long,
      val status: String?,
      val message: String?,
    )

    val reportDirs = listOf(testResultsDir.get().asFile) + additionalSonarTestResultDirs.get()
    val outputFile = testExecutionReportFile.get().asFile
    outputFile.parentFile.mkdirs()

    val testSourceSet = sourceSets.named("test").get()
    val testSourceDirs = testSourceSet.allSource.srcDirs + additionalSonarTestSourceDirs.get()

    val byFile = linkedMapOf<String, MutableList<TestCase>>()
    val xmlInputFactory = XMLInputFactory.newInstance()

    reportDirs.forEach { reportDir ->
      reportDir
        .listFiles { _, name ->
          (name.startsWith("TEST-") || name.startsWith("TESTS-")) && name.endsWith(".xml")
        }
        ?.forEach { reportFile ->
          val reader = xmlInputFactory.createXMLStreamReader(reportFile.inputStream())
          try {
            var suiteName: String? = null
            while (reader.hasNext()) {
              when (reader.next()) {
                XMLStreamConstants.START_ELEMENT -> {
                  when (reader.localName) {
                    "testsuite" -> {
                      suiteName = reader.getAttributeValue(null, "name")
                    }

                    "testcase" -> {
                      val name = reader.getAttributeValue(null, "name") ?: continue
                      val className =
                        reader.getAttributeValue(null, "classname") ?: suiteName ?: continue
                      val durationMs =
                        reader.getAttributeValue(null, "time")?.toDoubleOrNull()?.let {
                          (it * 1000).toLong()
                        } ?: 0L
                      var status: String? = null
                      var messageText: String? = null

                      while (reader.hasNext()) {
                        when (reader.next()) {
                          XMLStreamConstants.START_ELEMENT -> {
                            when (reader.localName) {
                              "failure",
                              "error" -> {
                                status = reader.localName
                                val message =
                                  reader.getAttributeValue(null, "message")?.takeIf {
                                    it.isNotBlank()
                                  }
                                val type =
                                  reader.getAttributeValue(null, "type")?.takeIf { it.isNotBlank() }
                                val text = reader.elementText.trim().takeIf { it.isNotBlank() }
                                messageText =
                                  listOfNotNull(message, type, text).joinToString("\n").ifBlank {
                                    null
                                  }
                              }

                              "skipped" -> {
                                status = "skipped"
                              }
                            }
                          }

                          XMLStreamConstants.END_ELEMENT -> {
                            if (reader.localName == "testcase") break
                          }
                        }
                      }

                      val normalizedClassName = className.substringBefore('$')
                      val relativeBase = normalizedClassName.replace('.', '/')
                      val relativePaths = mutableListOf("$relativeBase.java", "$relativeBase.kt")
                      if (normalizedClassName.endsWith("Kt")) {
                        relativePaths.add(
                          normalizedClassName.removeSuffix("Kt").replace('.', '/') + ".kt"
                        )
                      }
                      val sourceFile =
                        relativePaths.firstNotNullOfOrNull { relativePath ->
                          testSourceDirs
                            .firstOrNull { srcDir -> File(srcDir, relativePath).isFile }
                            ?.let { srcDir -> File(srcDir, relativePath) }
                        } ?: continue
                      val sourcePath = sourceFile.toPath()
                      val sonarPath =
                        if (sourcePath.startsWith(projectPath)) {
                          projectPath.relativize(sourcePath).toString()
                        } else {
                          sourceFile.absolutePath
                        }
                      byFile
                        .getOrPut(sonarPath) { mutableListOf() }
                        .add(TestCase(name, durationMs, status, messageText))
                    }
                  }
                }
              }
            }
          } finally {
            reader.close()
          }
        }
    }

    val xmlOutputFactory = XMLOutputFactory.newInstance()
    outputFile.outputStream().use { stream ->
      val writer = xmlOutputFactory.createXMLStreamWriter(stream, "UTF-8")
      writer.writeStartDocument("UTF-8", "1.0")
      writer.writeStartElement("testExecutions")
      writer.writeAttribute("version", "1")
      byFile.forEach { (filePath, testCases) ->
        writer.writeStartElement("file")
        writer.writeAttribute("path", filePath)
        testCases.forEach { testCase ->
          writer.writeStartElement("testCase")
          writer.writeAttribute("name", testCase.name)
          writer.writeAttribute("duration", testCase.durationMs.toString())
          when (testCase.status) {
            "failure",
            "error" -> {
              writer.writeAttribute(testCase.status, "true")
              testCase.message
                ?.lineSequence()
                ?.firstOrNull()
                ?.takeIf { it.isNotBlank() }
                ?.let { writer.writeAttribute("message", it) }
            }

            "skipped" -> {
              writer.writeAttribute("skipped", "true")
            }
          }
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
}

tasks.register("sonarlintFile", SonarLint::class.java) {
  group = "verification"
  description = "Run SonarLint on a single file (-Psonarlint.file=<path>)."
  // Analyze against main sources by default
  setSource(sourceSets.named("main").get().allSource)
  // Propagate the Java language level explicitly for single-file analysis
  val javaExt = project.extensions.findByType(JavaPluginExtension::class.java)
  val targetVersion = (javaExt?.targetCompatibility ?: JavaVersion.current()).majorVersion
  // Configure a task-scoped Java release for the SonarLint engine
  java { release.set(JavaLanguageVersion.of(targetVersion.toInt())) }

  // Provide classpath and output directories, so Java rules that require
  // semantic information are enabled even for single-file analysis.
  val mainSourceSet = sourceSets.named("main").get()
  java {
    mainOutputDirectories.from(mainSourceSet.output.classesDirs)
    mainClasspath.from(mainSourceSet.runtimeClasspath)
  }
  // Pick a file pattern from properties
  val fileProp =
    providers
      .gradleProperty("sonarlint.file")
      .orElse(providers.gradleProperty("file"))
      .orElse(providers.gradleProperty("sonarlint.sources"))
      .orElse(providers.gradleProperty("sonar.inclusions"))

  val pattern = fileProp.orNull
  if (!pattern.isNullOrBlank()) {
    // Normalize to a project-relative path and set it as the only source
    val f = project.layout.projectDirectory.file(pattern).asFile
    val rel = project.relativePath(f)
    if (f.isFile) {
      setSource(f)
      val isTestSource = rel.startsWith("src/test/")
      if (isTestSource) {
        isTest.set(true)
        val testSourceSet = sourceSets.named("test").get()
        java {
          testOutputDirectories.from(testSourceSet.output.classesDirs)
          testClasspath.from(testSourceSet.runtimeClasspath)
        }
      } else {
        isTest.set(false)
      }
    } else {
      // Fall back to include when a glob or directory is provided
      include(rel)
    }
  } else {
    logger.warn("sonarlint.file not specified; use -Psonarlint.file=<path> to scope analysis")
  }
}

// Do not run SonarLint as part of a regular `build`.
// Keep the task available when explicitly requested (any task name containing "sonarlint").
tasks.named("sonarlintMain", SonarLint::class.java).configure {
  val mainSourceSet = sourceSets.named("main").get()
  setSource(files(mainSourceSet.allSource, additionalSonarMainSourceDirs))
  java {
    mainOutputDirectories.from(mainSourceSet.output.classesDirs, additionalSonarMainOutputDirs)
    mainClasspath.from(mainSourceSet.runtimeClasspath)
  }
  onlyIf {
    val explicitlyRequested =
      gradle.startParameter.taskNames.any { it.contains("sonarlint", ignoreCase = true) }
    if (!explicitlyRequested) {
      logger.info(
        "Skipping sonarlintMain during standard builds; run :sonarlintMain explicitly to enable."
      )
    }
    explicitlyRequested
  }
}

tasks.named("sonarlintTest", SonarLint::class.java).configure {
  onlyIf {
    val explicitlyRequested =
      gradle.startParameter.taskNames.any { it.contains("sonarlint", ignoreCase = true) }
    if (!explicitlyRequested) {
      logger.info(
        "Skipping sonarlintTest during standard builds; run :sonarlintTest explicitly to enable."
      )
    }
    explicitlyRequested
  }
}

// Ensure coverage reports exist before publishing analysis.
// Explicitly depend on jacocoTestReport for the SonarQube task; guard optional 'sonar' alias.
tasks.named("sonarqube").configure {
  dependsOn("jacocoTestReport", "prepareKotlinTestReports", "prepareTestExecutionReport")
}

tasks
  .findByName("sonar")
  ?.dependsOn("jacocoTestReport", "prepareKotlinTestReports", "prepareTestExecutionReport")

tasks.register("sonarIssues") {
  group = "verification"
  description =
    "Query SonarQube/SonarCloud issues via /api/issues/search and save JSON in build/reports/sonar."

  doLast {
    val host =
      providers
        .gradleProperty("sonarIssues.host")
        .orElse(providers.gradleProperty("sonar.host.url"))
        .orElse("https://sonarcloud.io")
        .get()
        .trimEnd('/')
    val organization =
      providers.gradleProperty("sonarIssues.organization").orElse("crypta-network").get()
    val componentKeys =
      providers
        .gradleProperty("sonarIssues.componentKeys")
        .orElse(providers.gradleProperty("sonar.projectKey"))
        .orElse("crypta-network_cryptad")
        .get()
    val page = providers.gradleProperty("sonarIssues.page").orElse("1").get()
    val pageSize = providers.gradleProperty("sonarIssues.pageSize").orElse("500").get()
    val resolved = providers.gradleProperty("sonarIssues.resolved").orElse("false").get()
    val rules = providers.gradleProperty("sonarIssues.rules").orNull
    val branch = providers.gradleProperty("sonarIssues.branch").orNull
    val pullRequest = providers.gradleProperty("sonarIssues.pullRequest").orNull
    val statuses = providers.gradleProperty("sonarIssues.statuses").orNull
    val additionalFields = providers.gradleProperty("sonarIssues.additionalFields").orNull
    val token = providers.environmentVariable("SONAR_TOKEN").orNull?.takeIf { it.isNotBlank() }

    val params = linkedMapOf<String, String>()
    params["organization"] = organization
    params["componentKeys"] = componentKeys
    params["p"] = page
    params["ps"] = pageSize
    params["resolved"] = resolved
    if (!additionalFields.isNullOrBlank()) params["additionalFields"] = additionalFields
    if (!rules.isNullOrBlank()) params["rules"] = rules
    if (!branch.isNullOrBlank()) params["branch"] = branch
    if (!pullRequest.isNullOrBlank()) params["pullRequest"] = pullRequest
    if (!statuses.isNullOrBlank()) params["statuses"] = statuses

    val query =
      params.entries.joinToString("&") { (key, value) ->
        "${URLEncoder.encode(key, StandardCharsets.UTF_8)}=${URLEncoder.encode(value, StandardCharsets.UTF_8)}"
      }
    val endpoint = "$host/api/issues/search?$query"

    val requestBuilder =
      HttpRequest.newBuilder().uri(URI.create(endpoint)).header("Accept", "application/json").GET()
    token?.let { requestBuilder.header("Authorization", "Bearer $it") }

    val response =
      HttpClient.newBuilder()
        .followRedirects(HttpClient.Redirect.NORMAL)
        .build()
        .send(requestBuilder.build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8))

    if (response.statusCode() !in 200..299) {
      val bodySnippet = response.body().replace(Regex("\\s+"), " ").take(600)
      throw GradleException(
        "Sonar issues query failed with HTTP ${response.statusCode()} at $endpoint. Response: $bodySnippet"
      )
    }

    val outputPath =
      providers
        .gradleProperty("sonarIssues.output")
        .orElse("build/reports/sonar/issues-page-$page.json")
        .get()
    val outputFile = project.file(outputPath)
    outputFile.parentFile.mkdirs()
    outputFile.writeText(response.body(), Charsets.UTF_8)

    val totalIssues =
      Regex("\"paging\"\\s*:\\s*\\{[^}]*\"total\"\\s*:\\s*(\\d+)", RegexOption.DOT_MATCHES_ALL)
        .find(response.body())
        ?.groupValues
        ?.getOrNull(1)
    logger.lifecycle("Saved Sonar issues response to ${outputFile.path}")
    totalIssues?.let { logger.lifecycle("Sonar issues total (server-side): $it") }
    if (token == null) {
      logger.lifecycle(
        "SONAR_TOKEN is not set; request was sent without authentication (works only for public data)."
      )
    }
  }
}
