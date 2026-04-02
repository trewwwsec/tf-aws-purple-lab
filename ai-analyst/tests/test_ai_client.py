#!/usr/bin/env python3
"""Regression tests for AI client parsing and fallback behavior."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from ai_client import AIClient


class _ClientReturning:
    def __init__(self, response):
        self.response = response

    def generate(self, prompt, system_prompt=None):
        return self.response


class TestAIClient(unittest.TestCase):
    def test_analyze_alert_parses_json_wrapped_in_markdown(self):
        client = AIClient(provider="mock", use_rag=False, config={}, runtime_mode="demo")
        client.client = _ClientReturning(
            """```json
            {"title":"Wrapped","summary":"OK","investigation_steps":["one"],"recommended_actions":["two"]}
            ```"""
        )
        client.client_uses_mock = False

        result = client.analyze_alert({"rule": {"description": "Example", "id": "200001"}})

        self.assertEqual(result["title"], "Wrapped")
        self.assertEqual(result["analysis_metadata"]["analysis_method"], "llm")

    def test_analyze_alert_uses_rule_fallback_for_invalid_json(self):
        client = AIClient(provider="mock", use_rag=False, config={}, runtime_mode="demo")
        client.client = _ClientReturning("not json at all")
        client.client_uses_mock = False

        result = client.analyze_alert(
            {
                "rule": {"description": "Sudo command executed", "id": "200020", "level": 12},
                "data": {"srcip": "203.0.113.45", "dstuser": "root"},
            }
        )

        self.assertEqual(result["title"], "Sudo command executed")
        self.assertEqual(result["analysis_metadata"]["analysis_method"], "llm_text_parse")

    def test_get_status_reports_fallback_source(self):
        client = AIClient(provider="mock", use_rag=False, config={}, runtime_mode="demo")
        client.fallback_used = True

        status = client.get_status()

        self.assertEqual(status["data_source"], "mock_or_rule_fallback")


if __name__ == "__main__":
    unittest.main()
