"""Explicit candidate registry selection; no expanded Stable subject or Mail execution claim."""
import copy
import unittest
from cryptad_certification.engines.content_profile_selection import (
    MAIL_ENVELOPE_DESCRIPTOR, select_trust_social_v1,
)
from cryptad_certification.engines.stable_1_0_rc_core import CONTENT_PROFILE_IDS
from cryptad_certification.engines import stable_content_profile_review as review


class ContentProfileSelectionTest(unittest.TestCase):
    def setUp(self):
        self.original = [{"id": name, "majorVersion": 1,
                          "status": "stable" if "feed" in name else "experimental"}
                         for name in CONTENT_PROFILE_IDS]
        self.value = {"schemaVersion": 1, "kind": "content-format-profile-registry",
                      "profiles": self.original + [copy.deepcopy(MAIL_ENVELOPE_DESCRIPTOR)]}

    def test_historical_and_additive_exports_select_identical_five(self):
        self.assertEqual(self.original, select_trust_social_v1(self.value))
        historical = dict(self.value, profiles=self.original)
        self.assertEqual(self.original, select_trust_social_v1(historical))
        self.assertEqual(6, len(self.value["profiles"]))
        self.assertEqual(5, len(CONTENT_PROFILE_IDS))

    def test_changed_mail_status_suite_metadata_or_unknown_profile_rejected(self):
        for field, value in (("id", "crypta.mail.envelope.v2"), ("status", "stable"),
                             ("signed", True), ("maxDocumentBytes", 999999),
                             ("majorVersion", True), ("contentType", "application/json")):
            candidate = copy.deepcopy(self.value)
            candidate["profiles"][-1][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                select_trust_social_v1(candidate)

    def test_unknown_schema_missing_reordered_and_duplicate_subjects_rejected(self):
        candidates = [dict(self.value, schemaVersion=2), dict(self.value, schemaVersion=True)]
        for rows in (self.value["profiles"][1:], list(reversed(self.value["profiles"])),
                     self.value["profiles"] + [copy.deepcopy(MAIL_ENVELOPE_DESCRIPTOR)],
                     self.original + [{"id": "trust.score"}]):
            candidates.append(dict(self.value, profiles=rows))
        for value in candidates:
            with self.assertRaises(ValueError):
                select_trust_social_v1(value)

    def test_additive_subject_never_changes_original_review_digests(self):
        policy = {"profiles": [{"profileId": row["id"], "version": 1,
                                "effectiveStatus": row["status"], "recommendedStatus": row["status"],
                                "decision": "retain-" + row["status"]} for row in self.original]}
        previous = review.registry_rows(dict(self.value, profiles=self.original), policy)
        current = review.registry_rows(self.value, policy)
        self.assertEqual(previous, current)
        self.assertEqual(CONTENT_PROFILE_IDS, tuple(row["profileId"] for row in current))
