---
name: cryptad-crypto-aead
description: "Work safely on AEAD streams and persistent formats (AES-GCM migration + legacy OCB compatibility notes)."
metadata:
  area: crypto
  domain: cryptad
---

## When to use
Use this skill when you touch:
- `network.crypta.crypt` AEAD streams
- On-disk encryption formats for persistent files or plugin stores
- Any migration/compatibility path involving OCB or AES-GCM

## Source ownership
- `network.crypta.crypt` and `network.crypta.keys` now live in the `:foundation-crypto-keys`
  subproject.
- Canonical source root: `foundation-crypto-keys/src/main/java/`
- The root project and other leaf projects depend on `:foundation-crypto-keys`; do not recreate
  duplicate crypto helpers in root-owned code when a reusable leaf-owned type already exists.

## Current state (breaking change)
- AEAD has migrated from OCB to AES-GCM (breaking).
- On-disk prefix remains 16 bytes:
  - The **first 12 bytes** are treated as the GCM nonce.
  - The **remaining 4 bytes** are reserved.
- Total overhead remains 32 bytes (16-byte prefix + 16-byte GCM tag).
- There is **no fallback** for legacy OCB-encrypted data written before the migration.

### User-visible impact of the breaking change
- Client persistence files (`client.dat.crypt` / `client.dat.bak.crypt`) cannot be read; the node starts without resuming persistent requests.
- Plugin stores (`*.data.crypt`) cannot be read; plugins start with empty/default store data.

### Primary files
- `foundation-crypto-keys/src/main/java/network/crypta/crypt/AEADInputStream.java`
- `foundation-crypto-keys/src/main/java/network/crypta/crypt/AEADOutputStream.java`

## Legacy note: OCB nonce compatibility (do not regress)
Historically:
- Legacy on-disk format wrote `mainCipher.getBlockSize()` bytes (16 for AES) before ciphertext.
- BouncyCastle OCB uses a nonce of at most 15 bytes.
- Reader consumed 16 bytes and used only the first 15 for OCB; the extra byte was intentionally discarded.
- Writer persisted a 16-byte prefix again while using only the first 15 internally, preserving backward compatibility.
- Overhead for AES remained 32 bytes (16-byte written nonce + 16-byte MAC).

### Guardrail
Do **not** change the on-disk prefix to 15 bytes. Doing so would break reading of previously stored data.

### Migration edge case
If any data was written during a brief 15-byte-prefix regression window (historical note), coordinate with maintainers before enabling any autodetect path or reader changes.

## How to work safely in this area
- Treat on-disk formats as part of the public compatibility contract.
- If you must change format details:
  - Document the exact format (byte layout and semantics).
  - Add tests that round-trip old/new formats (where applicable).
  - Coordinate with maintainers on any compatibility or migration strategy.
