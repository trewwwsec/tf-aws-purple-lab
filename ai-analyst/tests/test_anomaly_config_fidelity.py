#!/usr/bin/env python3
"""Tests for anomaly detector config fidelity."""

import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from anomaly_detector import AnomalyDetector


class _DummyWazuhClient:
    def __init__(self, events):
        self.events = events
        self.calls = []

    def get_alerts(self, limit=10, offset=0, level=None, rule_id=None, agent_id=None, q=None):
        self.calls.append({"limit": limit, "offset": offset, "q": q})
        return self.events


class TestAnomalyConfigFidelity(unittest.TestCase):
    def _build_detector(self, categories=None, min_confidence=0.6):
        config = {
            "ai": {"provider": "mock"},
            "rag": {"enabled": False},
            "anomaly_detection": {
                "categories": categories
                or {
                    "login_anomalies": True,
                    "process_anomalies": True,
                    "network_anomalies": True,
                    "privilege_anomalies": True,
                    "file_integrity_anomalies": True,
                    "volume_anomalies": True,
                }
            },
        }
        return AnomalyDetector(
            z_score_threshold=2.5,
            min_confidence=min_confidence,
            config=config,
            runtime_mode="demo",
        )

    def test_category_toggles_filter_deviations(self):
        detector = self._build_detector(
            categories={
                "login_anomalies": False,
                "network_anomalies": True,
                "process_anomalies": True,
                "privilege_anomalies": True,
                "file_integrity_anomalies": True,
                "volume_anomalies": True,
            }
        )
        deviations = [
            {"category": "login_anomaly", "detail": "off-hours login"},
            {"category": "network_anomaly", "detail": "new source ip"},
        ]
        filtered = detector._filter_deviations_by_category(deviations)
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0]["category"], "network_anomaly")

    def test_min_confidence_filter_applies(self):
        detector = self._build_detector(min_confidence=0.75)
        ai_analysis = {
            "risk_level": "HIGH",
            "findings": [
                {"title": "Low confidence finding", "severity": "HIGH", "confidence": 0.6},
                {"title": "Strong finding", "severity": "MEDIUM", "confidence": 0.9},
            ],
        }
        filtered = detector._apply_min_confidence_filter(ai_analysis)
        self.assertEqual(len(filtered["findings"]), 1)
        self.assertEqual(filtered["findings"][0]["title"], "Strong finding")
        self.assertEqual(filtered["filtered_out_low_confidence"], 1)

    def test_fetch_events_honors_lookback_window(self):
        detector = self._build_detector()
        now = datetime.now(timezone.utc)
        recent_event = {"id": "1", "timestamp": now.isoformat()}
        old_event = {"id": "2", "timestamp": (now - timedelta(hours=48)).isoformat()}
        dummy = _DummyWazuhClient([recent_event, old_event])
        detector.wazuh_client = dummy

        events = detector._fetch_events(lookback_hours=24, limit=100)
        self.assertEqual([e["id"] for e in events], ["1"])
        self.assertTrue(dummy.calls)
        self.assertIn("timestamp>", dummy.calls[0]["q"])


if __name__ == "__main__":
    unittest.main()
