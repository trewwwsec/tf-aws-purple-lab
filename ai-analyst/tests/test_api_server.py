#!/usr/bin/env python3
"""Tests for API request parsing and alert lookup behavior."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from api_server import APIHandler, _extract_bearer_token


class _DummyWazuhClient:
    def __init__(self, alert=None, fallback_alert=None, recent_alerts=None):
        self.alert = alert
        self.fallback_alert = fallback_alert
        self.recent_alerts = recent_alerts or []
        self.alert_ids = []
        self.rule_ids = []
        self.recent_limits = []

    def get_alert_by_id(self, alert_id):
        self.alert_ids.append(alert_id)
        return self.alert

    def get_alerts(self, limit=1, rule_id=None):
        if rule_id is not None:
            self.rule_ids.append((rule_id, limit))
            return [self.fallback_alert] if self.fallback_alert else []
        self.recent_limits.append(limit)
        return self.recent_alerts[:limit]


class _DummyAnalyzer:
    def __init__(self, wazuh_client):
        self.wazuh_client = wazuh_client
        self.analyzed = []

    def analyze(self, alert):
        self.analyzed.append(alert)
        return {"rule_id": alert["rule"]["id"], "alert_id": alert.get("id")}


class APIHandlerTests(unittest.TestCase):
    def test_extract_bearer_token_is_case_insensitive(self):
        self.assertEqual(_extract_bearer_token("Bearer secret-token"), "secret-token")
        self.assertEqual(_extract_bearer_token("bearer another-token"), "another-token")
        self.assertIsNone(_extract_bearer_token("Token nope"))

    def test_handle_analyze_alert_id_falls_back_to_rule_lookup(self):
        fallback_alert = {"id": "evt-1", "rule": {"id": "200020"}}
        analyzer = _DummyAnalyzer(
            _DummyWazuhClient(alert=None, fallback_alert=fallback_alert)
        )
        handler = APIHandler.__new__(APIHandler)
        handler.analyzer = analyzer

        response = handler._handle_analyze({"alert_id": "200020"})

        self.assertEqual(response["analysis"]["rule_id"], "200020")
        self.assertEqual(analyzer.wazuh_client.alert_ids, ["200020"])
        self.assertEqual(analyzer.wazuh_client.rule_ids, [("200020", 1)])
        self.assertEqual(analyzer.analyzed, [fallback_alert])

    def test_handle_analyze_recent_validates_range(self):
        analyzer = _DummyAnalyzer(_DummyWazuhClient(recent_alerts=[]))
        handler = APIHandler.__new__(APIHandler)
        handler.analyzer = analyzer

        with self.assertRaisesRegex(ValueError, "range"):
            handler._handle_analyze({"recent": 0})


if __name__ == "__main__":
    unittest.main()
