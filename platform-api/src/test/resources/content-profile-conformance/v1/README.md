# Synthetic public content vectors, version 1

Read `docs/trust-social-wire-contracts.md` for exact signed-byte definitions and provenance.
All bodies and identities are synthetic public material. Profile/social goldens were assembled with
Python 3 JSON in explicitly chosen field order, hashed with SHA-256 and signed with OpenSSL using
RFC 8032 section 7.1 test-1's public seed. Trust goldens use independently assembled Node literals
and Node Ed25519 crypto. No test regenerates these expected files. Review vector changes against
wire compatibility, not against whichever output makes a test pass. Paths in manifest.json are
relative to this directory; byte/digest fields refer to exact bytes including any newline.

These newly authored fixtures do not claim older release provenance, runtime publication, human
security approval, complete boundary coverage or an independent external implementation.

`profile-unicode-whitespace-tags` independently assembles and signs a profile with NBSP
(U+00A0), BOM (U+FEFF), and EM SPACE (U+2003) tags. Its comma-separated generator query
passes the Java request parser's whole-parameter `isBlank` check, and `String.trim()` preserves
all three tags. The Java production builder must reproduce the pinned document exactly, and the
SDK must verify those same bytes without applying JavaScript's broader whitespace trimming.
