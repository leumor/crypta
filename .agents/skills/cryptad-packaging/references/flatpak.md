# Flatpak build (local dev) reference

Read for Flatpak build (local dev). Commands and unlinked source paths are relative to the repository root.

## Flatpak build (local dev)
Requirements: `flatpak`, `org.freedesktop.Platform//24.08`, `org.freedesktop.Sdk//24.08`.

Typical flow:
```bash
./gradlew buildJar
./gradlew distJlinkCryptad
cp -f "build/distributions/cryptad-jlink-v$(./gradlew -q printVersion).tar.gz" tools/flatpak/local/cryptad-jlink-v1.tar.gz
rm -rf builddir repo .flatpak-builder
flatpak run org.flatpak.Builder --force-clean --user --arch=$(flatpak --default-arch) \
  --install-deps-from=flathub builddir tools/flatpak/cryptad.yaml
flatpak build-export --arch=$(flatpak --default-arch) repo builddir v1
flatpak build-bundle repo cryptad-v1-$( [ $(flatpak --default-arch) = aarch64 ] && echo arm64 || echo amd64 ).flatpak \
  network.crypta.cryptad v1 --arch=$(flatpak --default-arch)
flatpak --user install -y ./cryptad-v1-*.flatpak
flatpak run network.crypta.cryptad//v1
```

Notes:
- Flatpak packaging files live under `tools/flatpak/`.
- Spotless is scoped to `src/**`; `.spotlessignore` at repo root prevents scanning Flatpak scratch dirs.
