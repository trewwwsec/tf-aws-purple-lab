"""Tests for alert payload normalization and unwrapping (autopilot hook-first path)."""

import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

# Ensure src is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from utils import normalize_alert_payload, is_wazuh_alert


class TestIsWazuhAlert:
    def test_valid_alert_with_rule_id_and_agent(self):
        alert = {
            "timestamp": "2026-01-01T00:00:00Z",
            "rule": {"id": "200001", "level": 10, "description": "Test"},
            "agent": {"id": "001", "name": "test-agent"},
        }
        assert is_wazuh_alert(alert) is True

    def test_missing_rule_key(self):
        assert is_wazuh_alert({"agent": {"id": "001"}}) is False

    def test_missing_agent_key(self):
        assert is_wazuh_alert({"rule": {"id": "200001"}}) is False

    def test_empty_dict(self):
        assert is_wazuh_alert({}) is False

    def test_non_dict_input(self):
        with pytest.raises(ValueError, match="must be a JSON object"):
            normalize_alert_payload("not a dict")  # type: ignore[arg-type]

    def test_none_input(self):
        with pytest.raises(ValueError, match="must be a JSON object"):
            normalize_alert_payload(None)  # type: ignore[arg-type]


class TestNormalizeAlertPayload:
    @pytest.fixture
    def sample_alert(self):
        return {
            "timestamp": "2026-01-01T00:00:00Z",
            "rule": {"id": "200001", "level": 10, "description": "SSH brute force"},
            "agent": {"id": "001", "name": "linux-endpoint-01"},
            "data": {"srcip": "203.0.113.45"},
        }

    def test_raw_alert_passes_through(self, sample_alert):
        result = normalize_alert_payload(sample_alert)
        assert result == sample_alert

    def test_alert_wrapper_top_level(self, sample_alert):
        wrapped = {"alert": sample_alert}
        result = normalize_alert_payload(wrapped)
        assert result == sample_alert

    def test_alert_wrapper_parameters(self, sample_alert):
        wrapped = {"parameters": {"alert": sample_alert}}
        result = normalize_alert_payload(wrapped)
        assert result == sample_alert

    def test_deeply_nested_alert(self, sample_alert):
        wrapped = {"alert": {"parameters": {"alert": sample_alert}}}
        result = normalize_alert_payload(wrapped)
        assert result == sample_alert

    def test_no_alert_found(self):
        with pytest.raises(ValueError, match="must be a raw alert object"):
            normalize_alert_payload({"not-an-alert": 123})

    def test_parameters_no_alert_key(self):
        with pytest.raises(ValueError, match="must be a raw alert object"):
            normalize_alert_payload({"parameters": {"extra_data": {}}})


class TestAnalyzeAlertCLI:
    """Smoke-tests for --stdin and --alert-file in analyze_alert.py (parse_args only)."""

    def test_stdin_flag_accepted(self):
        from analyze_alert import parse_args

        with patch("sys.argv", ["analyze_alert.py", "--stdin", "--mode", "demo"]):
            args = parse_args()
            assert args.stdin is True
            assert args.mode == "demo"

    def test_alert_file_flag(self):
        from analyze_alert import parse_args

        with patch("sys.argv", ["analyze_alert.py", "--alert-file", "/tmp/test.json"]):
            args = parse_args()
            assert args.alert_file == "/tmp/test.json"
            assert args.stdin is False

    def test_stdin_outputs_json(self):
        from analyze_alert import parse_args

        with patch(
            "sys.argv", ["analyze_alert.py", "--stdin", "--output", "json", "--mode", "demo"]
        ):
            args = parse_args()
            assert args.stdin is True
            assert args.output == "json"
