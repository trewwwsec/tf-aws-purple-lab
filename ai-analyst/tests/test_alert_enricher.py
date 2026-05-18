#!/usr/bin/env python3
"""Regression tests for alert enrichment helpers."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from alert_enricher import AlertEnricher, HistoricalAnalyzer, ThreatIntelligenceClient


class _ConnectedVectorStore:
    def __init__(self):
        self.indexed = []

    def is_connected(self):
        return True

    def index_alert(self, alert, embedding, **kwargs):
        self.indexed.append((alert, embedding, kwargs))
        return True


class _FailingVectorStore(_ConnectedVectorStore):
    def index_alert(self, alert, embedding, **kwargs):
        raise RuntimeError("OpenSearch unavailable")


class _DummyEmbeddingService:
    def embed_alert(self, alert):
        return [0.1, 0.2, 0.3]


class _EmptyWazuhClient:
    def search_events(self, **kwargs):
        return []


class _UnexpectedHistoricalLookupClient:
    def search_events(self, **kwargs):
        raise AssertionError("historical lookup should be skipped")


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

    def test_enrich_can_skip_historical_queries(self):
        enricher = AlertEnricher(
            enable_rag_indexing=False,
            config={},
            runtime_mode="strict",
            wazuh_client=_UnexpectedHistoricalLookupClient(),
        )

        result = enricher.enrich(
            {
                "rule": {"level": 10, "description": "SSH brute force attack detected"},
                "agent": {"name": "host-1"},
                "data": {"srcip": "203.0.113.45", "dstuser": "root"},
            },
            include_historical=False,
        )

        self.assertEqual(result["related_events"], 0)
        self.assertIsNone(result["first_seen"])
        self.assertNotIn("historical", result["enrichment_sources"])

    def test_index_analyzed_alert_stores_analysis_metadata_after_analysis(self):
        enricher = AlertEnricher(
            enable_rag_indexing=False,
            config={"rag": {"indexing": {"min_level": 5}}},
            runtime_mode="demo",
        )
        vector_store = _ConnectedVectorStore()
        enricher.enable_rag_indexing = True
        enricher._vector_store = vector_store
        enricher._embedding_service = _DummyEmbeddingService()

        result = enricher.index_analyzed_alert(
            {"id": "evt-1", "rule": {"level": 8}},
            {
                "alert_title": "Suspicious login",
                "severity": 8,
                "severity_label": "High",
                "playbook": "ssh-brute-force.md",
                "analysis_metadata": {"analysis_method": "mock"},
            },
            source_path="hook",
        )

        self.assertTrue(result)
        self.assertEqual(len(vector_store.indexed), 1)
        _, embedding, kwargs = vector_store.indexed[0]
        self.assertEqual(embedding, [0.1, 0.2, 0.3])
        self.assertEqual(kwargs["source_path"], "hook")
        self.assertEqual(kwargs["playbook"], "ssh-brute-force.md")
        self.assertEqual(kwargs["analysis_metadata"]["alert_title"], "Suspicious login")

    def test_index_analyzed_alert_respects_min_level(self):
        enricher = AlertEnricher(
            enable_rag_indexing=False,
            config={"rag": {"indexing": {"min_level": 5}}},
            runtime_mode="demo",
        )
        vector_store = _ConnectedVectorStore()
        enricher.enable_rag_indexing = True
        enricher._vector_store = vector_store
        enricher._embedding_service = _DummyEmbeddingService()

        result = enricher.index_analyzed_alert({"rule": {"level": 4}}, {}, source_path="hook")

        self.assertFalse(result)
        self.assertEqual(vector_store.indexed, [])

    def test_index_analyzed_alert_failure_is_non_fatal(self):
        enricher = AlertEnricher(
            enable_rag_indexing=False,
            config={"rag": {"indexing": {"min_level": 5}}},
            runtime_mode="demo",
        )
        enricher.enable_rag_indexing = True
        enricher._vector_store = _FailingVectorStore()
        enricher._embedding_service = _DummyEmbeddingService()

        result = enricher.index_analyzed_alert({"rule": {"level": 5}}, {}, source_path="hook")

        self.assertFalse(result)


if __name__ == "__main__":
    unittest.main()
