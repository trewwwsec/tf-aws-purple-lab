#!/usr/bin/env python3
"""Regression tests for alert enrichment helpers."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from alert_enricher import AlertEnricher, HistoricalAnalyzer, ThreatIntelligenceClient


class _ConnectedVectorStore:
    def is_connected(self):
        return True


class _EmptyWazuhClient:
    def search_events(self, **kwargs):
        return []


class TestAlertEnricher(unittest.TestCase):
    def test_mock_threat_intelligence_known_bad_ip(self):
        client = ThreatIntelligenceClient()
        result = client._mock_lookup("203.0.113.45")

        self.assertTrue(result["is_malicious"])
        self.assertEqual(result["source"], "Mock TI")

    def test_should_index_alert_respects_min_level_and_connectivity(self):
        enricher = AlertEnricher(
            enable_rag_indexing=False,
            config={"rag": {"indexing": {"min_level": 5}}},
            runtime_mode="demo",
        )
        enricher._vector_store = _ConnectedVectorStore()

        self.assertFalse(enricher._should_index_alert({"rule": {"level": 4}}))
        self.assertTrue(enricher._should_index_alert({"rule": {"level": 5}}))

    def test_risk_score_uses_expected_thresholds(self):
        enricher = AlertEnricher(enable_rag_indexing=False, config={}, runtime_mode="demo")
        result = enricher._calculate_risk_score(
            {"rule": {"level": 10}},
            {
                "threat_intel": {"is_malicious": True, "confidence": 80},
                "historical": {"total_events": 15},
                "geolocation": {"country_code": "RU"},
            },
        )

        self.assertEqual(result["score"], 83.0)
        self.assertEqual(result["level"], "Critical")

    def test_historical_analyzer_returns_empty_live_result_in_strict_mode(self):
        analyzer = HistoricalAnalyzer(wazuh_client=_EmptyWazuhClient(), runtime_mode="strict")

        result = analyzer.get_related_events(source_ip="203.0.113.10")

        self.assertEqual(result["total_events"], 0)
        self.assertEqual(result["related_sources"], [])
        self.assertIn("No related events found", result["attack_progression"])

    def test_enrich_adds_expected_sources_for_network_alert(self):
        enricher = AlertEnricher(enable_rag_indexing=False, config={}, runtime_mode="demo")

        result = enricher.enrich(
            {
                "rule": {"level": 10, "description": "SSH brute force attack detected"},
                "agent": {"name": "host-1"},
                "data": {"srcip": "203.0.113.45", "dstuser": "root"},
            }
        )

        self.assertEqual(
            result["enrichment_sources"],
            ["threat_intel", "geolocation", "historical"],
        )
        self.assertIn("risk_score", result)
        self.assertIn("attack_classification", result)


if __name__ == "__main__":
    unittest.main()
