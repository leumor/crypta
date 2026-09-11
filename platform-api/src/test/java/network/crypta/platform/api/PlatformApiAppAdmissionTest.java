package network.crypta.platform.api;

import java.util.List;
import network.crypta.platform.appdist.AppApiCompatibilityMetadata.TargetStability;
import network.crypta.platform.appdist.AppApiCompatibilityMetadata;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class PlatformApiAppAdmissionTest {
  private static final String ERROR_INCOMPATIBLE_CONTRACT = "incompatible_platform_api_contract";
  private static final String ERROR_INVALID_APP_BUNDLE = "invalid_app_bundle";
  private static final String FIELD_STATUS = "status";
  private static final String STATUS_INCOMPATIBLE = "incompatible";
  private static final List<String> QUEUE_READ_PERMISSIONS = List.of("queue.read");

  @Test
  void requireCompatibility_whenSelectedTargetBelowMinimum_expectNoCurrentContractFallback() {
    var current = PlatformApiContract.current();
    var selected =
        new PlatformApiContract(
            current.apiVersion(),
            25,
            current.generatedBy(),
            current.stabilityPolicy(),
            current.capabilities(),
            current.endpoints());
    var registry = PlatformApiBaselineRegistry.current();
    var metadata =
        new AppApiCompatibilityMetadata(
            26, 26, List.of(), TargetStability.EXPERIMENTAL, true, false, false);
    List<String> permissions = List.of();

    assertDoesNotThrow(
        () -> PlatformApiAppAdmission.requireCurrentCompatibility(metadata, permissions));
    var exception =
        assertThrows(
            PlatformApiException.class,
            () ->
                PlatformApiAppAdmission.requireCompatibility(
                    metadata, permissions, selected, registry));

    assertEquals(ERROR_INCOMPATIBLE_CONTRACT, exception.errorCode());
    assertEquals(409, exception.statusCode());
  }

  @Test
  void requireCompatibility_whenTestedMaximumExceeded_expectOrdinaryRuntimeWarningAllowed() {
    var metadata =
        new AppApiCompatibilityMetadata(
            19, 23, List.of(), TargetStability.STABLE, true, false, false);

    assertDoesNotThrow(
        () ->
            PlatformApiAppAdmission.requireCompatibility(
                metadata,
                QUEUE_READ_PERMISSIONS,
                PlatformApiContract.current(),
                PlatformApiBaselineRegistry.current()));
  }

  @Test
  void requireCompatibility_whenStableOptionalCapabilityUnknown_expectSameNativeRejection() {
    var metadata =
        new AppApiCompatibilityMetadata(
            19, 26, List.of("synthetic.unavailable"), TargetStability.STABLE, true, false, false);
    var contract = PlatformApiContract.current();
    var baselines = PlatformApiBaselineRegistry.current();

    var exception =
        assertThrows(
            PlatformApiException.class,
            () ->
                PlatformApiAppAdmission.requireCompatibility(
                    metadata, QUEUE_READ_PERMISSIONS, contract, baselines));

    assertEquals(ERROR_INCOMPATIBLE_CONTRACT, exception.errorCode());
  }

  @Test
  void requireCompatibility_whenNamedBaselineUnsupported_expectSameNativeRejection() {
    var metadata =
        new AppApiCompatibilityMetadata(
            19, 26, List.of(), TargetStability.STABLE, true, "1.1", true, false, false);
    var contract = PlatformApiContract.current();
    var baselines = PlatformApiBaselineRegistry.current();

    var exception =
        assertThrows(
            PlatformApiException.class,
            () ->
                PlatformApiAppAdmission.requireCompatibility(
                    metadata, QUEUE_READ_PERMISSIONS, contract, baselines));

    assertEquals("unsupported_platform_api_baseline", exception.errorCode());
  }

  @Test
  void requireCurrentCompatibility_whenStableBaselineIsImplicit_expectFrozen10DefaultAllowed() {
    AppApiCompatibilityMetadata metadata =
        new AppApiCompatibilityMetadata(
            19, 23, List.of(), TargetStability.STABLE, true, false, false);

    assertDoesNotThrow(
        () ->
            PlatformApiAppAdmission.requireCurrentCompatibility(metadata, QUEUE_READ_PERMISSIONS));
  }

  @Test
  void requireCurrentCompatibility_whenStableBaselineIsUnknown_expectAdmissionBlocked() {
    AppApiCompatibilityMetadata metadata =
        new AppApiCompatibilityMetadata(
            19, 24, List.of(), TargetStability.STABLE, true, "1.1", true, false, false);

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class,
            () ->
                PlatformApiAppAdmission.requireCurrentCompatibility(
                    metadata, QUEUE_READ_PERMISSIONS));

    assertEquals(409, exception.statusCode());
    assertEquals("unsupported_platform_api_baseline", exception.errorCode());
  }

  @Test
  void requireCurrentCompatibility_whenLegacyMetadataIsUndeclared_expectBehaviorPreserved() {
    assertDoesNotThrow(
        () ->
            PlatformApiAppAdmission.requireCurrentCompatibility(
                AppApiCompatibilityMetadata.undeclared(), QUEUE_READ_PERMISSIONS));
  }

  @Test
  void requireCurrentCompatibility_whenNamedBaselineLacksStability_expectAdmissionBlocked() {
    AppApiCompatibilityMetadata metadata =
        new AppApiCompatibilityMetadata(
            null, null, List.of(), TargetStability.EXPERIMENTAL, false, "1.0", true, false, false);

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class,
            () ->
                PlatformApiAppAdmission.requireCurrentCompatibility(
                    metadata, QUEUE_READ_PERMISSIONS));

    assertEquals(409, exception.statusCode());
    assertEquals(ERROR_INCOMPATIBLE_CONTRACT, exception.errorCode());
    assertEquals(
        STATUS_INCOMPATIBLE,
        PlatformApiAppAdmission.summarizeAdmission(metadata, QUEUE_READ_PERMISSIONS)
            .get(FIELD_STATUS));
  }

  @Test
  void requireCurrentCompatibility_whenLegacyRangeLacksStability_expectBehaviorPreserved() {
    AppApiCompatibilityMetadata metadata =
        new AppApiCompatibilityMetadata(
            19,
            PlatformApiContract.CURRENT_CONTRACT_VERSION,
            List.of(),
            TargetStability.EXPERIMENTAL,
            false,
            false,
            false);

    assertDoesNotThrow(
        () ->
            PlatformApiAppAdmission.requireCurrentCompatibility(metadata, QUEUE_READ_PERMISSIONS));
    assertEquals(
        "compatible",
        PlatformApiAppAdmission.summarizeAdmission(metadata, QUEUE_READ_PERMISSIONS)
            .get(FIELD_STATUS));
  }

  @Test
  void requireCurrentCompatibility_whenRangeExcludesBaselineRoot_expectAdmissionBlocked() {
    AppApiCompatibilityMetadata metadata =
        new AppApiCompatibilityMetadata(
            23, 23, List.of(), TargetStability.STABLE, true, false, false);

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class,
            () ->
                PlatformApiAppAdmission.requireCurrentCompatibility(
                    metadata, QUEUE_READ_PERMISSIONS));

    assertEquals(ERROR_INCOMPATIBLE_CONTRACT, exception.errorCode());
  }

  @Test
  void summarizeAdmission_whenRangeExcludesBaselineRoot_expectIncompatibleStatus() {
    AppApiCompatibilityMetadata metadata =
        new AppApiCompatibilityMetadata(
            23, 23, List.of(), TargetStability.STABLE, true, false, false);

    var summary = PlatformApiAppAdmission.summarizeAdmission(metadata, QUEUE_READ_PERMISSIONS);

    assertEquals(STATUS_INCOMPATIBLE, summary.get(FIELD_STATUS));
  }

  @Test
  void requireCurrentCompatibility_whenStablePermissionIsUnknown_expectAdmissionBlocked() {
    AppApiCompatibilityMetadata metadata =
        new AppApiCompatibilityMetadata(
            19, 23, List.of(), TargetStability.STABLE, true, false, false);
    List<String> permissions = List.of("future.permission");

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class,
            () -> PlatformApiAppAdmission.requireCurrentCompatibility(metadata, permissions));

    assertEquals(ERROR_INCOMPATIBLE_CONTRACT, exception.errorCode());
    assertEquals(
        STATUS_INCOMPATIBLE,
        PlatformApiAppAdmission.summarizeAdmission(metadata, permissions).get(FIELD_STATUS));
  }

  @Test
  void requireCurrentCompatibility_whenStableOptionalCapabilityIsUnknown_expectAdmissionBlocked() {
    AppApiCompatibilityMetadata metadata =
        new AppApiCompatibilityMetadata(
            19, 23, List.of("future.optional"), TargetStability.STABLE, true, false, false);

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class,
            () ->
                PlatformApiAppAdmission.requireCurrentCompatibility(
                    metadata, QUEUE_READ_PERMISSIONS));

    assertEquals(ERROR_INCOMPATIBLE_CONTRACT, exception.errorCode());
    assertEquals(
        STATUS_INCOMPATIBLE,
        PlatformApiAppAdmission.summarizeAdmission(metadata, QUEUE_READ_PERMISSIONS)
            .get(FIELD_STATUS));
  }

  @Test
  void requireCurrentCompatibility_whenStableOptionalCapabilityIsKnown_expectAdmissionAllowed() {
    AppApiCompatibilityMetadata metadata =
        new AppApiCompatibilityMetadata(
            19, 23, List.of("queue.write"), TargetStability.STABLE, true, false, false);

    assertDoesNotThrow(
        () ->
            PlatformApiAppAdmission.requireCurrentCompatibility(metadata, QUEUE_READ_PERMISSIONS));
  }

  @Test
  void requireCurrentCompatibility_whenOnlyMaximumTestedVersionIsOld_expectAdmissionAllowed() {
    AppApiCompatibilityMetadata metadata =
        new AppApiCompatibilityMetadata(
            19, 22, List.of(), TargetStability.STABLE, true, false, false);

    assertDoesNotThrow(
        () ->
            PlatformApiAppAdmission.requireCurrentCompatibility(metadata, QUEUE_READ_PERMISSIONS));
  }

  @Test
  void requireCatalogDeclarationMatchesManifest_whenTargetBaselineDiffers_expectRejected() {
    AppApiCompatibilityMetadata catalog =
        new AppApiCompatibilityMetadata(
            19, 23, List.of(), TargetStability.STABLE, true, "1.0", true, false, true);
    AppApiCompatibilityMetadata manifest =
        new AppApiCompatibilityMetadata(
            19, 24, List.of(), TargetStability.STABLE, true, "1.1", true, false, true);

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class,
            () ->
                PlatformApiAppAdmission.requireCatalogDeclarationMatchesManifest(
                    catalog, manifest));

    assertEquals(400, exception.statusCode());
    assertEquals(ERROR_INVALID_APP_BUNDLE, exception.errorCode());
  }

  @Test
  void requireCatalogDeclarationMatchesManifest_whenStabilityDeclarationDiffers_expectRejected() {
    AppApiCompatibilityMetadata catalog =
        new AppApiCompatibilityMetadata(
            19, 23, List.of(), TargetStability.EXPERIMENTAL, false, "1.1", true, false, false);
    AppApiCompatibilityMetadata manifest =
        new AppApiCompatibilityMetadata(
            19, 23, List.of(), TargetStability.EXPERIMENTAL, true, "1.1", true, false, false);

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class,
            () ->
                PlatformApiAppAdmission.requireCatalogDeclarationMatchesManifest(
                    catalog, manifest));

    assertEquals(ERROR_INVALID_APP_BUNDLE, exception.errorCode());
  }

  @Test
  void requireCatalogDeclarationMatchesManifest_whenLegacyCatalogIsUndeclared_expectAllowed() {
    AppApiCompatibilityMetadata manifest =
        new AppApiCompatibilityMetadata(
            19, 23, List.of(), TargetStability.STABLE, true, "1.0", true, false, true);

    assertDoesNotThrow(
        () ->
            PlatformApiAppAdmission.requireCatalogDeclarationMatchesManifest(
                AppApiCompatibilityMetadata.undeclared(), manifest));
  }

  @Test
  void requireCatalogDeclarationMatchesManifest_whenLegacyStableTargetChanges_expectRejected() {
    AppApiCompatibilityMetadata catalog =
        new AppApiCompatibilityMetadata(
            19, 23, List.of(), TargetStability.STABLE, true, false, false);
    AppApiCompatibilityMetadata manifest =
        new AppApiCompatibilityMetadata(
            19, 23, List.of(), TargetStability.EXPERIMENTAL, true, false, false);

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class,
            () ->
                PlatformApiAppAdmission.requireCatalogDeclarationMatchesManifest(
                    catalog, manifest));

    assertEquals(ERROR_INVALID_APP_BUNDLE, exception.errorCode());
  }

  @Test
  void requireCatalogDeclarationMatchesManifest_whenLegacyStableBaselineChanges_expectRejected() {
    AppApiCompatibilityMetadata catalog =
        new AppApiCompatibilityMetadata(
            19, 23, List.of(), TargetStability.STABLE, true, false, false);
    AppApiCompatibilityMetadata manifest =
        new AppApiCompatibilityMetadata(
            19, 24, List.of(), TargetStability.STABLE, true, "1.1", true, false, false);

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class,
            () ->
                PlatformApiAppAdmission.requireCatalogDeclarationMatchesManifest(
                    catalog, manifest));

    assertEquals(ERROR_INVALID_APP_BUNDLE, exception.errorCode());
  }

  @Test
  void requireCatalogDeclarationMatchesManifest_whenLegacyStableDefaultsAgree_expectAllowed() {
    AppApiCompatibilityMetadata catalog =
        new AppApiCompatibilityMetadata(
            19, 23, List.of(), TargetStability.STABLE, true, false, false);
    AppApiCompatibilityMetadata manifest =
        new AppApiCompatibilityMetadata(
            19, 23, List.of(), TargetStability.STABLE, true, false, false);

    assertDoesNotThrow(
        () -> PlatformApiAppAdmission.requireCatalogDeclarationMatchesManifest(catalog, manifest));
  }
}
