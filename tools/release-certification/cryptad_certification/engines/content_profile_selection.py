"""Explicit registry-v1 selection of the unchanged trust/social five-profile subject.

The one allowed additive Mail descriptor is experimental and is not projected into historical
Stable subjects. New registry schemas, profiles or lifecycle changes require another review.
"""
from .stable_1_0_rc_core import CONTENT_PROFILE_IDS

MAIL_ENVELOPE_ID = "crypta.mail.envelope.v1"
MAIL_ENVELOPE_DESCRIPTOR = {
    "id": MAIL_ENVELOPE_ID,
    "majorVersion": 1,
    "contentType": "application/vnd.crypta.mail+json",
    "defaultFilename": "mail-envelope.json",
    "status": "experimental",
    "maxDocumentBytes": 65536,
    "maxSignedPayloadBytes": None,
    "signed": False,
    "signingDomain": None,
    "canonicalizationKind": "strict_flat_json_hpke_authenticated_header",
    "versionPolicy": {
        "unknownFieldPolicy": "reject_unknown_fields",
        "futureVersionPolicy": "reject_unknown_major_accept_known_minor_only",
        "deprecationPolicy": "explicit_warning_or_reject",
    },
    "replacementProfileId": None,
}


def select_trust_social_v1(value: dict) -> list[dict]:
    """Select exactly the original five from historical v1 or reviewed additive Mail v1 exports."""
    if not isinstance(value, dict) or type(value.get("schemaVersion")) is not int or value.get("schemaVersion") != 1 or value.get("kind") != "content-format-profile-registry":
        raise ValueError("profile-review-registry-invalid")
    rows = value.get("profiles")
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise ValueError("profile-review-registry-set-invalid")
    ids = tuple(row.get("id") for row in rows)
    if ids == CONTENT_PROFILE_IDS:
        return rows
    if ids != CONTENT_PROFILE_IDS + (MAIL_ENVELOPE_ID,):
        raise ValueError("profile-review-registry-set-invalid")
    # Exact JSON bytes avoid bool/int equivalence in Python equality for descriptor scalars.
    import json
    if json.dumps(rows[-1], sort_keys=True) != json.dumps(MAIL_ENVELOPE_DESCRIPTOR, sort_keys=True):
        raise ValueError("profile-review-additive-mail-descriptor-invalid")
    return rows[:-1]
