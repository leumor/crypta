# Stable 1.0 RC and GA archives reference

Read for Stable 1.0 RC and GA archives. Commands and unlinked source paths are relative to the repository root.

## Stable 1.0 RC and GA archives

- Use `python3 tools/release-certification/certify.py stable-rc --manifest <copied-manifest>` as the
  canonical Stable RC packaging boundary. It consumes the production pipeline output and writes
  `crypta-stable-1.0-rc-<build>-product.tar.gz` plus the outer
  `cryptad-stable-1.0-rc-<build>.tar.gz`, checksums, provenance, and freeze records.
- The deterministic product archive is the immutable payload selected for GA. Its tar/gzip
  ordering, timestamps, uid/gid, names, modes, members, and content digests are part of the freeze.
  Do not reproduce it by rerunning Gradle, extracting/repacking it, changing an RC marker, or
  generating a same-version replacement.
- `stable-ga` copies or references the exact frozen product and verifies its digest before and after
  GA metadata generation. GA labels, promotion records, notes, checksums, provenance, and the
  maintenance baseline stay outside the immutable product payload.
- If a platform package, launcher, migration command, catalog/app member, file mode, or any other
  payload member must change after freeze, stop promotion and complete a new authorized RC refreeze.
  A GA waiver cannot hide payload drift.
- Keep tests and ordinary PR/local runs side-effect-free. They may validate deterministic fixtures
  and mocked publication receipts, but they must not create tags, Releases, public catalog updates,
  update descriptors, or network inserts.
