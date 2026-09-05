# Release-tooling boundary reference

Read for Release-tooling boundary. Commands and unlinked source paths are relative to the repository root.

## Release-tooling boundary

- `tools/release-certification/cryptad_certification/engines/` owns side-effect-free policy and
  evidence evaluation. Stable 1.0 GA remains in `stable_1_0_ga*`; later routine maintenance and
  security hotfixes share the `stable_1_0_maintenance*` engine family and one closed policy;
  authenticated build lifecycle and deprecation governance live in the
  `stable_1_0_lifecycle*` engine family and its separate closed policy.
- `tools/release-certification/protected/stable_maintenance_publication.py` owns protected-boundary
  materialization, exact-state revalidation, publication receipt verification, and successor
  activation. Do not import a publication client into the certification engine.
- `tools/release-certification/protected/stable_lifecycle_input_producer.py` owns closed,
  public-safe lifecycle input expansion. `stable_lifecycle_publication.py` owns lifecycle
  authorization/publication/verification revalidation; neither belongs in the side-effect-free
  engine.
- `tools/release-certification/publication-backend/` is the separately built, attested provider
  wheel. Hosted publication jobs load it only from the authenticated installation directory; the
  candidate checkout is not a provider source.
- `.github/workflows/stable-1.0-maintenance-*.yml` owns the protected input, Windows package,
  backend-wheel, candidate-freeze, authorization, publication, independent-verification, and
  activation orchestration. These workflows validate refs and exact artifacts but never create or
  merge release/hotfix branches.
- `.github/workflows/stable-1.0-support-lifecycle*.yml` owns lifecycle input attestation,
  one-time genesis proof, evaluation, transition preparation, authorization validation, exact
  descriptor publication, and independent verification. Lifecycle mutation shares the maintenance
  publication lock so the authenticated chain tip cannot advance between observation and insert.
- `build-logic/src/main/kotlin/cryptad/PortableArchiveNormalizer.kt` and the distribution/runtime
  convention plugins own deterministic portable archive construction. The independent Python
  archive gate verifies those bytes; neither layer is a substitute for the other.
