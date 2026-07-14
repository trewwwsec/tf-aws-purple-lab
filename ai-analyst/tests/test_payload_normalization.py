"""Tests for alert payload normalization and unwrapping (autopilot hook-first path)."""

import os
import sys
import unittest
from unittest.mock import patch

# Ensure src is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from utils import is_wazuh_alert, normalize_alert_payload


class TestIsWazuhAlert(unittest.TestCase):
    def test_valid_alert_with_rule_id_and_agent(self):
        alert = {
            "timestamp": "2026-01-01T00:00:00Z",
            "rule": {"id": "200001", "level": 10, "description": "Test"},
            "agent": {"id": "001", "name": "test-agent"},
        }
        self.assertTrue(is_wazuh_alert(alert))

    def test_missing_rule_key(self):
        self.assertFalse(is_wazuh_alert({"agent": {"id": "001"}}))

    def test_missing_agent_key(self):
        # is_wazuh_alert only checks for a valid rule dict — agent is optional
        self.assertTrue(is_wazuh_alert({"rule": {"id": "200001"}}))

    def test_empty_dict(self):
        self.assertFalse(is_wazuh_alert({}))

    def test_non_dict_input(self):
        with self.assertRaisesRegex(ValueError, "must be a JSON object"):
            normalize_alert_payload("not a dict")  # type: ignore[arg-type]

    def test_none_input(self):
        with self.assertRaisesRegex(ValueError, "must be a JSON object"):
            normalize_alert_payload(None)  # type: ignore[arg-type]


class TestNormalizeAlertPayload(unittest.TestCase):
    def setUp(self):
        self.sample_alert = {
            "timestamp": "2026-01-01T00:00:00Z",
            "rule": {"id": "200001", "level": 10, "description": "SSH brute force"},
            "agent": {"id": "001", "name": "linux-endpoint-01"},
            "data": {"srcip": "203.0.113.45"},
        }

    def test_raw_alert_passes_through(self):
        result = normalize_alert_payload(self.sample_alert)
        self.assertEqual(result, self.sample_alert)

    def test_alert_wrapper_top_level(self):
        wrapped = {"alert": self.sample_alert}
        result = normalize_alert_payload(wrapped)
        self.assertEqual(result, self.sample_alert)

    def test_alert_wrapper_parameters(self):
        wrapped = {"parameters": {"alert": self.sample_alert}}
        result = normalize_alert_payload(wrapped)
        self.assertEqual(result, self.sample_alert)

    def test_deeply_nested_alert(self):
        wrapped = {"alert": {"parameters": {"alert": self.sample_alert}}}
        result = normalize_alert_payload(wrapped)
        self.assertEqual(result, self.sample_alert)

    def test_no_alert_found(self):
        with self.assertRaisesRegex(ValueError, "must be a raw alert object"):
            normalize_alert_payload({"not-an-alert": 123})

    def test_parameters_no_alert_key(self):
        with self.assertRaisesRegex(ValueError, "must be a raw alert object"):
            normalize_alert_payload({"parameters": {"extra_data": {}}})


class TestAnalyzeAlertCLI(unittest.TestCase):
    """Smoke-tests for --stdin and --alert-file in analyze_alert.py (parse_args only)."""

    def test_stdin_flag_accepted(self):
        from analyze_alert import parse_args

        with patch("sys.argv", ["analyze_alert.py", "--stdin", "--mode", "demo"]):
            args = parse_args()
            self.assertTrue(args.stdin)
            self.assertEqual(args.mode, "demo")

    def test_alert_file_flag(self):
        from analyze_alert import parse_args

        with patch("sys.argv", ["analyze_alert.py", "--alert-file", "/tmp/test.json"]):
            args = parse_args()
            self.assertEqual(args.alert_file, "/tmp/test.json")
            self.assertFalse(args.stdin)

    def test_stdin_outputs_json(self):
        from analyze_alert import parse_args

        with patch(
            "sys.argv", ["analyze_alert.py", "--stdin", "--output", "json", "--mode", "demo"]
        ):
            args = parse_args()
            self.assertTrue(args.stdin)
            self.assertEqual(args.output, "json")


if __name__ == "__main__":
    unittest.main()
