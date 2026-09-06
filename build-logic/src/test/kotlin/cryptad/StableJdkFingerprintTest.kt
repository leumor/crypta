package cryptad

import org.gradle.api.GradleException
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

class StableJdkFingerprintTest {
  @Test
  fun canonicalRuntimeBuild_whenStableBuild_expectOnlyLtsSuffixRemoved() {
    for (reported in listOf("25.0.3+9", "25.0.3+9-LTS", "25.0.4.1+1", "25.0.4.1+1-LTS")) {
      assertEquals(reported.removeSuffix("-LTS"), StableJdkFingerprint.canonicalRuntimeBuild(reported))
    }
  }

  @Test
  fun canonicalRuntimeBuild_whenNonCanonicalBuild_expectRejected() {
    for (reported in
      listOf(
        "26.0.0+1",
        "25.0.4.1",
        "25.0+1",
        "25.0.4.1.1+1",
        "25.0.4.1+1-ea",
        "25.0.4.1+1\n",
      )) {
      assertThrows(GradleException::class.java) { StableJdkFingerprint.canonicalRuntimeBuild(reported) }
    }
  }
}
