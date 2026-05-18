#!/usr/bin/env python3
"""Tests for AI analysis feedback persistence."""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from feedback_store import FeedbackStore, FeedbackValidationError


class TestFeedbackStore(unittest.TestCase):
    def test_add_validates_and_persists_feedback(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = FeedbackStore(os.path.join(tmp, "feedback.jsonl"))
            entry = store.add(
                {
                    "alert_id": "evt-1",
                    "analysis_id": "analysis-1",
                    "rating": "Useful",
                    "correction": "Good triage.",
                    "operator": "analyst-a",
                }
            )

            self.assertEqual(entry["rating"], "useful")
            self.assertEqual(entry["source"], "api")
            self.assertEqual(len(store.list_for_alert("evt-1")), 1)
            self.assertEqual(store.list_for_alert("missing"), [])

    def test_rejects_missing_alert_id(self):
        store = FeedbackStore("/tmp/unused-feedback.jsonl")

        with self.assertRaisesRegex(FeedbackValidationError, "alert_id"):
            store.validate({"rating": "useful"})

    def test_rejects_unknown_rating(self):
        store = FeedbackStore("/tmp/unused-feedback.jsonl")

        with self.assertRaisesRegex(FeedbackValidationError, "rating"):
            store.validate({"alert_id": "evt-1", "rating": "great"})


if __name__ == "__main__":
    unittest.main()
