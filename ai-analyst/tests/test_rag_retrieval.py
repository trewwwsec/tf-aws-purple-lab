#!/usr/bin/env python3
"""Tests for RAG retrieval completeness, hybrid routing, and telemetry."""

import os
import sys
import types
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

# Provide lightweight stub for environments without opensearchpy installed.
if "opensearchpy" not in sys.modules:
    stub = types.ModuleType("opensearchpy")

    class _OpenSearchStub:
        pass

    stub.OpenSearch = _OpenSearchStub
    stub.helpers = types.SimpleNamespace()
    sys.modules["opensearchpy"] = stub

from rag_retriever import RAGRetriever


class _DummyEmbeddingService:
    dimension = 3

    def embed_alert(self, alert):
        return [0.1, 0.2, 0.3]


class _DummyVectorStore:
    INDEX_ALERTS = "soc-alerts-v1"
    INDEX_THREAT_INTEL = "soc-threat-intel-v1"
    INDEX_PLAYBOOKS = "soc-playbooks-v1"

    def __init__(self):
        self.calls = {
            "hybrid_search": [],
            "search_exact_threat_intel": 0,
            "search_similar_alerts": 0,
            "search_similar_threat_intel": 0,
            "search_relevant_playbooks": 0,
            "search_temporal_alerts": 0,
        }

    def is_connected(self):
        return True

    def get_index_health(self):
        return {
            "connected": True,
            "cluster": {"status": "green"},
            "indices": {
                self.INDEX_ALERTS: {"exists": True, "document_count": 10},
                self.INDEX_THREAT_INTEL: {"exists": True, "document_count": 5},
                self.INDEX_PLAYBOOKS: {"exists": True, "document_count": 3},
            },
        }

    def hybrid_search(self, embedding, text_query, index, **kwargs):
        self.calls["hybrid_search"].append(index)
        if index == "alerts":
            return [
                {
                    "alert_id": "a-1",
                    "rule_description": "SSH brute force attack detected",
                    "agent_name": "linux-endpoint-01",
                    "timestamp": "2026-03-23T12:00:00Z",
                    "similarity_score": 0.91,
                }
            ]
        if index == "threat_intel":
            return [
                {
                    "ioc_id": "ip-203.0.113.45",
                    "ioc_value": "203.0.113.45",
                    "ioc_type": "ip",
                    "threat_type": "brute_force",
                    "similarity_score": 0.88,
                }
            ]
        if index == "playbooks":
            return [
                {
                    "playbook_id": "IR-PB-001",
                    "title": "SSH Brute Force Response",
                    "similarity_score": 0.86,
                }
            ]
        return []

    def search_exact_threat_intel(self, **kwargs):
        self.calls["search_exact_threat_intel"] += 1
        return []

    def search_similar_alerts(self, **kwargs):
        self.calls["search_similar_alerts"] += 1
        return []

    def search_similar_threat_intel(self, **kwargs):
        self.calls["search_similar_threat_intel"] += 1
        return []

    def search_relevant_playbooks(self, **kwargs):
        self.calls["search_relevant_playbooks"] += 1
        return []

    def search_temporal_alerts(self, **kwargs):
        self.calls["search_temporal_alerts"] += 1
        return [
            {
                "alert_id": "t-1",
                "rule_description": "Related failed authentication",
                "agent_name": "linux-endpoint-01",
                "timestamp": "2026-03-23T11:55:00Z",
            }
        ]


class _DummyVectorStoreHybridEmpty(_DummyVectorStore):
    def hybrid_search(self, embedding, text_query, index, **kwargs):
        self.calls["hybrid_search"].append(index)
        return []

    def search_similar_alerts(self, **kwargs):
        self.calls["search_similar_alerts"] += 1
        return [{"alert_id": "semantic-a"}]

    def search_exact_threat_intel(self, **kwargs):
        self.calls["search_exact_threat_intel"] += 1
        return [{"ioc_id": "exact-ioc", "ioc_value": "203.0.113.45", "ioc_type": "ip"}]

    def search_similar_threat_intel(self, **kwargs):
        self.calls["search_similar_threat_intel"] += 1
        return [{"ioc_id": "semantic-ioc", "ioc_value": "203.0.113.45", "ioc_type": "ip"}]

    def search_relevant_playbooks(self, **kwargs):
        self.calls["search_relevant_playbooks"] += 1
        return [{"playbook_id": "semantic-pb", "title": "Fallback Playbook"}]


class TestRAGRetrieval(unittest.TestCase):
    def test_retrieve_context_hybrid_temporal_and_telemetry(self):
        vector_store = _DummyVectorStore()
        retriever = RAGRetriever(
            embedding_service=_DummyEmbeddingService(),
            vector_store=vector_store,
            config={
                "rag": {
                    "retrieval": {
                        "hybrid_search": True,
                        "text_weight": 0.2,
                        "vector_weight": 0.8,
                        "max_temporal_alerts": 5,
                        "temporal_window_before": "1h",
                        "temporal_window_after": "2h",
                    }
                }
            },
        )

        context = retriever.retrieve_context(
            {
                "timestamp": "2026-03-23T12:00:00Z",
                "rule": {"id": "200001", "description": "SSH brute force attack detected"},
                "agent": {"id": "001", "name": "linux-endpoint-01"},
                "data": {"srcip": "203.0.113.45", "dstuser": "root"},
            }
        )

        self.assertEqual(len(context.similar_alerts), 1)
        self.assertEqual(len(context.threat_intel), 1)
        self.assertEqual(len(context.relevant_playbooks), 1)
        self.assertEqual(len(context.temporal_context), 1)
        self.assertEqual(context.total_documents, 4)
        self.assertIn("index_health", context.retrieval_telemetry)
        self.assertIn("total_duration_ms", context.retrieval_telemetry)
        self.assertIn("alerts", vector_store.calls["hybrid_search"])
        self.assertIn("playbooks", vector_store.calls["hybrid_search"])
        self.assertEqual(vector_store.calls["search_temporal_alerts"], 1)

    def test_hybrid_fallbacks_to_semantic_when_empty(self):
        vector_store = _DummyVectorStoreHybridEmpty()
        retriever = RAGRetriever(
            embedding_service=_DummyEmbeddingService(),
            vector_store=vector_store,
            config={"rag": {"retrieval": {"hybrid_search": True}}},
        )

        context = retriever.retrieve_context(
            {
                "timestamp": "2026-03-23T12:00:00Z",
                "rule": {"id": "200001", "description": "SSH brute force attack detected"},
                "agent": {"id": "001", "name": "linux-endpoint-01"},
                "data": {"srcip": "203.0.113.45", "dstuser": "root"},
            }
        )

        self.assertTrue(vector_store.calls["hybrid_search"])
        self.assertGreater(vector_store.calls["search_similar_alerts"], 0)
        self.assertGreater(vector_store.calls["search_relevant_playbooks"], 0)
        self.assertEqual(len(context.similar_alerts), 1)
        self.assertEqual(len(context.relevant_playbooks), 1)


if __name__ == "__main__":
    unittest.main()
