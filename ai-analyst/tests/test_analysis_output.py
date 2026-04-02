#!/usr/bin/env python3
"""Regression tests for analysis formatting helpers."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from analyze_alert import analysis_to_markdown
from utils import get_severity_color, get_severity_label


class AnalysisOutputTests(unittest.TestCase):
    def test_analysis_to_markdown_omits_empty_optional_context_fields(self):
        markdown = analysis_to_markdown(
            {
                "alert_title": "Example Alert",
                "rule_id": "200020",
                "severity_label": "LOW",
                "timestamp": "2026-04-01T12:00:00Z",
                "source_ip": None,
                "agent": "host-1",
                "user": None,
                "context": {"related_events": 0},
                "playbook": "privilege-escalation.md",
                "playbook_path": "/tmp/playbook.md",
                "mitre_id": None,
                "mitre_info": {},
                "analysis_metadata": {},
                "summary": "Short summary.",
                "investigation_steps": [],
                "recommended_actions": [],
            }
        )

        self.assertIn("- Target System: `host-1`", markdown)
        self.assertNotIn("- Source IP: `None`", markdown)
        self.assertNotIn("- User: `None`", markdown)

    def test_severity_helpers_match_current_thresholds(self):
        self.assertEqual(get_severity_label(12), "CRITICAL")
        self.assertEqual(get_severity_label(10), "HIGH")
        self.assertEqual(get_severity_label(7), "MEDIUM")
        self.assertEqual(get_severity_label(6), "LOW")
        self.assertEqual(get_severity_color(10), "\033[91m")
        self.assertEqual(get_severity_color(7), "\033[93m")
        self.assertEqual(get_severity_color(6), "\033[92m")


if __name__ == "__main__":
    unittest.main()
