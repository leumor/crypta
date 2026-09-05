# Stable 1.0 maintenance candidate packaging reference

Read for Stable 1.0 maintenance candidate packaging. Commands and unlinked source paths are relative to the repository root.

## Stable 1.0 maintenance candidate packaging

Unlike GA promotion, a later Stable 1.0 release introduces new bytes. Build and freeze the product
archive and all declared packages exactly once through `stable-maintenance`; normalize and inspect
archives with the established RC rules, then bind every filename, size, mode, digest, signature,
source commit, and installer result into candidate checksums and provenance. Any changed byte after
authorization requires a new candidate and authorization.

After each protected package build, require `HEAD` to remain the exact candidate commit and reject
any staged or unstaged change to a tracked path before producer metadata or attestations are
created. Ignore untracked Gradle outputs for that source-drift decision. The aggregate freeze must
also prove that the exact `release.sourceCommit` in the authenticated latest predecessor baseline
is an ancestor of the candidate; branch-base ancestry alone is insufficient.

The normal matrix covers the portable distribution and supported Linux DEB/RPM, macOS DMG, and
Windows EXE targets. A local Linux or macOS run must not claim that target passed. Dispatch the
checked-in protected Windows producer at the exact candidate commit; it runs
`jpackageInstallerWindowsExeCryptad` once on the hosted Windows runner, Authenticode-signs and
verifies the final amd64 PE, rechecks tracked source state, and attests both the EXE and its receipt.
The app-image prerequisite, rewritten launcher configuration, and EXE task all map integer build
`<build>` to MSI ProductVersion `1.0.<build>` so the release number uses MSI's 16-bit build
component; protected Windows releases fail closed above build 65535.
The hosted Ubuntu maintenance producer must install the distribution `rpm` package and verify both
`rpm` and `rpmbuild` before invoking `jpackageInstallerLinuxAll`; the package task intentionally
skips RPM creation when that external toolchain is absent.
Every security hotfix declares a nonempty affected-package subset. A full-matrix hotfix records
`unaffectedPackageProofStatus=not-applicable`; a narrowed matrix must equal the affected set
exactly and records `unaffectedPackageProofStatus=pass` only when advisory evidence proves the
omitted targets do not ship the vulnerable code. A narrowed hotfix without a DMG must not attach
the authenticated macOS notarization receipt to any selected non-DMG package.

The protected maintenance package producer uses keyless GitHub/Sigstore attestations to
cryptographically sign every exact staged DEB, RPM, portable archive, and DMG without changing its
bytes. It must immediately verify each subject against the exact maintenance workflow and source
commit, emit a separate redaction-safe per-asset verification receipt, and upload those receipts
with the producer artifact. The freeze boundary independently repeats `gh attestation verify` and
uses the matching per-asset receipt digest for `signingReceiptDigest`; a generic producer receipt,
checksum, `productionSigning` Boolean, or build attestation cannot stand in for this check. This
path uses the workflow's OIDC and attestation permissions and has no private-key or passphrase
input. Never add signing secret material to the workflow command line, logs, receipts, or retained
artifacts.

For the protected macOS maintenance freeze, import the reviewed Developer ID Application identity
into an ephemeral keychain and run `jpackageInstallerCryptad` with
`-PmacSigningKeyUserName=<exact identity>`. After enrichment has copied `cryptad-dist` and rewritten
the launcher configuration, that opt-in property makes `signFinalMacAppImageCryptad` replace the
jpackage signatures in explicit inside-out order and sign the app root last. Preserve the existing
identifier and entitlement metadata on the jpackage JVM, framework, and app-root code while
switching to Developer ID `codesign --options runtime --timestamp`; fail closed if that metadata
is absent. Select nested signable files by their thin/universal Mach-O magic, not by POSIX execute
bits or filename suffixes: the enriched portable distribution also contains executable Linux ELF
and Windows PE files, which are app resources on macOS and must be covered only by the final app
root seal. Sign recognized nested native bundles after their contained Mach-O code. Do not use
recursive `--deep` signing to replace nested signatures. Do not attempt JDK
25's rejected
`--type app-image --app-image` combination. The installer task runs only after that boundary and
retains jpackage's mac signing flags, but those flags do not prove that jpackage signed the outer
DMG container. Ordinary local packaging remains unchanged when the property is absent. Explicitly
Developer-ID-sign and verify the exact DMG after jpackage and before notarization submission, then
staple and verify those resulting bytes again before computing the frozen digest and copying the
DMG into the frozen asset set. Also verify the app, stapling ticket, and Gatekeeper assessment. Do
not freeze a DMG based only on declared signing metadata.

The workflow variable is `CRYPTAD_MACOS_DEVELOPER_ID_APPLICATION`. Keep the P12 and notary values
only in the evidence environment secrets
`CRYPTAD_MACOS_DEVELOPER_ID_APPLICATION_P12_BASE64`,
`CRYPTAD_MACOS_DEVELOPER_ID_APPLICATION_P12_PASSWORD`,
`CRYPTAD_MACOS_NOTARY_APPLE_ID`, `CRYPTAD_MACOS_NOTARY_APP_PASSWORD`, and
`CRYPTAD_MACOS_NOTARY_TEAM_ID`. Never place those values in Gradle properties files, workflow
inputs, command output, receipts, or retained artifacts.

Publication copies the frozen assets; it never reruns Gradle, jpackage, signing, notarization, or
archive creation. Follow `docs/stable-1.0-maintenance-release-and-hotfix-path.md`.

Focused cross-platform argument checks are:

```bash
./gradlew verifyMacAppImageSigningArguments verifyWindowsExeInstallerArguments
```

When portable archive logic changes, build the affected `distZipCryptad`, `distTarCryptad`, and
`distJlinkCryptad` tasks, then run
`python3 tools/release-certification/certify.py stable-maintenance --self-test` so the independent
Python hygiene rules are exercised against the Java normalizer contract. These checks do not
replace protected signing, notarization, multi-OS packaging, or publication.
