#!/usr/bin/env python3
"""
RAG Retriever - Retrieval-Augmented Generation context retrieval for alert analysis.
Retrieves similar past incidents, threat intelligence, and relevant playbooks.
"""

import os
import logging
import time
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime

from embedding_service import get_embedding_service, EmbeddingService
from vector_store import get_vector_store, VectorStore

logger = logging.getLogger(__name__)


@dataclass
class RAGContext:
    """Container for retrieved RAG context."""

    # Similar past alerts
    similar_alerts: List[Dict[str, Any]] = field(default_factory=list)

    # Related threat intelligence
    threat_intel: List[Dict[str, Any]] = field(default_factory=list)

    # Relevant playbooks
    relevant_playbooks: List[Dict[str, Any]] = field(default_factory=list)

    # Temporal patterns (alerts from same time window)
    temporal_context: List[Dict[str, Any]] = field(default_factory=list)

    # Retrieved at timestamp
    retrieved_at: str = field(default_factory=lambda: datetime.now().isoformat())

    # Retrieval telemetry and health checks
    retrieval_telemetry: Dict[str, Any] = field(default_factory=dict)

    # Total context documents retrieved
    @property
    def total_documents(self) -> int:
        return (
            len(self.similar_alerts)
            + len(self.threat_intel)
            + len(self.relevant_playbooks)
            + len(self.temporal_context)
        )

    def to_prompt_context(
        self,
        max_alerts: int = 3,
        max_intel: int = 2,
        max_playbooks: int = 2,
        max_temporal: int = 3,
    ) -> str:
        """
        Convert RAG context to a formatted string for LLM prompts.

        Args:
            max_alerts: Maximum similar alerts to include
            max_intel: Maximum threat intel items to include
            max_playbooks: Maximum playbooks to include
            max_temporal: Maximum temporal matches to include

        Returns:
            Formatted context string
        """
        sections = []

        # Similar alerts section
        if self.similar_alerts:
            sections.append("## SIMILAR PAST INCIDENTS")
            for i, alert in enumerate(self.similar_alerts[:max_alerts], 1):
                similarity = alert.get("similarity_score", 0)
                desc = alert.get("rule_description", "Unknown")
                agent = alert.get("agent_name", "unknown")
                time = alert.get("timestamp", "unknown")

                sections.append(f"{i}. {desc}")
                sections.append(f"   - Agent: {agent}")
                sections.append(f"   - Time: {time}")
                sections.append(f"   - Similarity: {similarity:.2%}")

                # Add resolution/outcome if available
                if alert.get("resolution"):
                    sections.append(f"   - Outcome: {alert['resolution']}")
                sections.append("")

        # Threat intelligence section
        if self.threat_intel:
            sections.append("## THREAT INTELLIGENCE")
            for i, intel in enumerate(self.threat_intel[:max_intel], 1):
                ioc = intel.get("ioc_value", "unknown")
                ioc_type = intel.get("ioc_type", "unknown")
                threat_type = intel.get("threat_type", "unknown")
                confidence = intel.get("confidence_score", 0)
                similarity = intel.get("similarity_score", 0)

                sections.append(f"{i}. {ioc_type.upper()}: {ioc}")
                sections.append(f"   - Threat Type: {threat_type}")
                sections.append(f"   - Confidence: {confidence:.0%}")
                sections.append(f"   - Similarity Match: {similarity:.2%}")
                sections.append("")

        # Playbooks section
        if self.relevant_playbooks:
            sections.append("## RECOMMENDED PLAYBOOKS")
            for i, pb in enumerate(self.relevant_playbooks[:max_playbooks], 1):
                title = pb.get("title", "Unknown")
                severity = pb.get("severity", "unknown")
                similarity = pb.get("similarity_score", 0)
                techniques = pb.get("mitre_techniques", [])

                sections.append(f"{i}. {title}")
                sections.append(f"   - Severity: {severity}")
                if techniques:
                    sections.append(f"   - MITRE: {', '.join(techniques)}")
                sections.append(f"   - Relevance: {similarity:.2%}")
                sections.append("")

        # Temporal context section
        if self.temporal_context:
            sections.append("## TEMPORAL CORRELATION")
            for i, item in enumerate(self.temporal_context[:max_temporal], 1):
                desc = item.get("rule_description", "Unknown")
                ts = item.get("timestamp", "unknown")
                agent = item.get("agent_name", "unknown")
                src_ip = item.get("src_ip", "")
                sections.append(f"{i}. {desc}")
                sections.append(f"   - Time: {ts}")
                sections.append(f"   - Agent: {agent}")
                if src_ip:
                    sections.append(f"   - Source IP: {src_ip}")
                sections.append("")

        if not sections:
            return "No relevant historical context found."

        return "\n".join(sections)


class RAGRetriever:
    """
    Retrieval-Augmented Generation retriever for security alert analysis.

    Retrieves context from:
    1. Similar past alerts (semantic similarity)
    2. Threat intelligence indicators (pattern matching)
    3. Relevant incident response playbooks
    4. Temporal context (alerts from same time window)
    """

    def __init__(
        self,
        embedding_service: EmbeddingService = None,
        vector_store: VectorStore = None,
        config: Dict[str, Any] = None,
    ):
        """
        Initialize the RAG retriever.

        Args:
            embedding_service: Embedding service instance
            vector_store: Vector store instance
            config: Configuration dictionary
        """
        config = config or {}
        rag_cfg = config.get("rag", config) if isinstance(config, dict) else {}
        embedding_cfg = rag_cfg.get("embedding", {}) if isinstance(rag_cfg, dict) else {}
        opensearch_cfg = rag_cfg.get("opensearch", {}) if isinstance(rag_cfg, dict) else {}
        retrieval_cfg = rag_cfg.get("retrieval", {}) if isinstance(rag_cfg, dict) else {}

        embedding_model = embedding_cfg.get("model")
        embedding_cache = embedding_cfg.get("cache_dir")
        self.embedding_service = embedding_service or get_embedding_service(
            model_name=embedding_model,
            cache_dir=embedding_cache,
            max_memory_entries=embedding_cfg.get("max_memory_entries", 5000),
            max_disk_files=embedding_cfg.get("max_disk_files", 50000),
            max_disk_size_mb=embedding_cfg.get("max_disk_size_mb", 2048),
            prune_interval_writes=embedding_cfg.get("prune_interval_writes", 200),
        )

        os_host = opensearch_cfg.get("host")
        os_port = opensearch_cfg.get("port")
        os_hosts = [f"{os_host}:{os_port}"] if os_host and os_port else None
        os_password = opensearch_cfg.get("password") or os.environ.get("OPENSEARCH_PASSWORD")

        self.vector_store = vector_store or get_vector_store(
            embedding_dimension=self.embedding_service.dimension,
            hosts=os_hosts,
            username=opensearch_cfg.get("username"),
            password=os_password,
            use_ssl=opensearch_cfg.get("use_ssl", True),
            verify_certs=opensearch_cfg.get("verify_certs", True),
        )

        # Default retrieval configuration
        self.config = retrieval_cfg if isinstance(retrieval_cfg, dict) else {}
        self.similarity_threshold = self.config.get("similarity_threshold", 0.7)
        self.max_similar_alerts = self.config.get("max_similar_alerts", 5)
        self.max_threat_intel = self.config.get("max_threat_intel", 3)
        self.max_playbooks = self.config.get("max_playbooks", 2)
        self.max_temporal_alerts = self.config.get("max_temporal_alerts", 10)
        self.time_range = self.config.get("time_range", "7d")
        self.temporal_window_before = self.config.get("temporal_window_before", "2h")
        self.temporal_window_after = self.config.get("temporal_window_after", "2h")
        self.hybrid_search = bool(self.config.get("hybrid_search", False))
        self.text_weight = float(self.config.get("text_weight", 0.3))
        self.vector_weight = float(self.config.get("vector_weight", 0.7))
        self.index_health_check = bool(self.config.get("index_health_check", True))
        self.text_weight, self.vector_weight = self._normalize_weights(
            self.text_weight, self.vector_weight
        )

        logger.info(
            f"RAG Retriever initialized (threshold: {self.similarity_threshold})"
        )

    def retrieve_context(self, alert: Dict[str, Any]) -> RAGContext:
        """
        Retrieve comprehensive RAG context for an alert.

        Args:
            alert: Wazuh alert dictionary

        Returns:
            RAGContext with all retrieved information
        """
        retrieval_started = time.perf_counter()
        context = RAGContext()
        telemetry: Dict[str, Any] = {
            "hybrid_search_enabled": self.hybrid_search,
            "time_range": self.time_range,
            "stages": {},
        }

        if self.index_health_check:
            health = self.vector_store.get_index_health()
            telemetry["index_health"] = health
            telemetry["index_health_ok"] = bool(
                health.get("connected")
                and health.get("indices", {}).get(self.vector_store.INDEX_ALERTS, {}).get("exists")
            )

        # Generate embedding for the alert
        try:
            alert_embedding = self.embedding_service.embed_alert(alert)
        except Exception as e:
            logger.error(f"Failed to generate alert embedding: {e}")
            telemetry["error"] = str(e)
            context.retrieval_telemetry = telemetry
            return context

        # Extract key information from alert
        rule = alert.get("rule", {})
        data = alert.get("data", {})
        agent = alert.get("agent", {})

        src_ip = data.get("srcip")
        agent_id = agent.get("id")
        mitre_ids = self._extract_mitre_ids(rule)
        text_query = self._build_text_query(alert)

        # 1. Retrieve similar past alerts
        t0 = time.perf_counter()
        context.similar_alerts = self._retrieve_similar_alerts(
            embedding=alert_embedding,
            agent_id=agent_id,
            text_query=text_query,
        )
        telemetry["stages"]["similar_alerts"] = {
            "count": len(context.similar_alerts),
            "duration_ms": round((time.perf_counter() - t0) * 1000, 2),
            "method": "hybrid" if self.hybrid_search else "semantic",
        }

        # 2. Retrieve threat intelligence
        if src_ip:
            t0 = time.perf_counter()
            context.threat_intel = self._retrieve_threat_intel(
                src_ip=src_ip,
                embedding=alert_embedding,
                text_query=text_query,
            )
            telemetry["stages"]["threat_intel"] = {
                "count": len(context.threat_intel),
                "duration_ms": round((time.perf_counter() - t0) * 1000, 2),
                "method": "hybrid" if self.hybrid_search else "semantic",
            }

        # 3. Retrieve relevant playbooks
        t0 = time.perf_counter()
        context.relevant_playbooks = self._retrieve_playbooks(
            embedding=alert_embedding,
            mitre_techniques=mitre_ids,
            text_query=text_query,
        )
        telemetry["stages"]["playbooks"] = {
            "count": len(context.relevant_playbooks),
            "duration_ms": round((time.perf_counter() - t0) * 1000, 2),
            "method": "hybrid" if self.hybrid_search else "semantic",
        }

        # 4. Retrieve temporal context
        t0 = time.perf_counter()
        context.temporal_context = self._retrieve_temporal_context(
            reference_timestamp=alert.get("timestamp"),
            agent_id=agent_id,
            src_ip=src_ip,
            rule_id=str(rule.get("id", "")) if rule.get("id") else None,
        )
        telemetry["stages"]["temporal_context"] = {
            "count": len(context.temporal_context),
            "duration_ms": round((time.perf_counter() - t0) * 1000, 2),
            "method": "temporal_query",
            "window_before": self.temporal_window_before,
            "window_after": self.temporal_window_after,
        }
        telemetry["total_duration_ms"] = round(
            (time.perf_counter() - retrieval_started) * 1000, 2
        )
        telemetry["total_documents"] = context.total_documents
        if hasattr(self.embedding_service, "get_cache_stats"):
            try:
                telemetry["embedding_cache"] = self.embedding_service.get_cache_stats()
            except Exception as e:
                telemetry["embedding_cache_error"] = str(e)
        context.retrieval_telemetry = telemetry

        logger.info(
            f"Retrieved RAG context: {len(context.similar_alerts)} alerts, "
            f"{len(context.threat_intel)} intel items, "
            f"{len(context.relevant_playbooks)} playbooks, "
            f"{len(context.temporal_context)} temporal matches "
            f"(total={telemetry.get('total_duration_ms', 0)}ms)"
        )

        return context

    @staticmethod
    def _normalize_weights(text_weight: float, vector_weight: float) -> Tuple[float, float]:
        """Normalize hybrid search weights safely."""
        tw = max(0.0, float(text_weight))
        vw = max(0.0, float(vector_weight))
        total = tw + vw
        if total <= 0:
            return 0.3, 0.7
        return tw / total, vw / total

    @staticmethod
    def _build_text_query(alert: Dict[str, Any]) -> str:
        """Build a compact keyword query from alert fields for hybrid retrieval."""
        rule = alert.get("rule", {})
        data = alert.get("data", {})
        agent = alert.get("agent", {})
        tokens = [
            str(rule.get("description", "")),
            str(rule.get("id", "")),
            str(agent.get("name", "")),
            str(data.get("srcip", "")),
            str(data.get("dstuser", "")),
        ]
        return " ".join([token for token in tokens if token]).strip()

    def _retrieve_similar_alerts(
        self,
        embedding: List[float],
        agent_id: str = None,
        text_query: str = "",
    ) -> List[Dict[str, Any]]:
        """
        Retrieve alerts semantically similar to the query.

        Args:
            embedding: Query embedding vector
            agent_id: Optional agent ID filter

        Returns:
            List of similar alerts
        """
        if not self.vector_store.is_connected():
            logger.warning(
                "Vector store not connected, skipping similar alert retrieval"
            )
            return []

        if self.hybrid_search and text_query:
            try:
                results = self.vector_store.hybrid_search(
                    embedding=embedding,
                    text_query=text_query,
                    index="alerts",
                    k=self.max_similar_alerts,
                    text_boost=self.text_weight,
                    vector_boost=self.vector_weight,
                    min_score=self.similarity_threshold,
                    filters={"agent_id": agent_id} if agent_id else None,
                    time_range=self.time_range,
                )
                if results:
                    return results
            except Exception as e:
                logger.error("Hybrid similar-alert retrieval failed: %s", e)

        try:
            results = self.vector_store.search_similar_alerts(
                embedding=embedding,
                k=self.max_similar_alerts,
                min_score=self.similarity_threshold,
                agent_id=agent_id,
                time_range=self.time_range,
            )
            return results
        except Exception as e:
            logger.error(f"Failed to retrieve similar alerts: {e}")
            return []

    def _retrieve_threat_intel(
        self, src_ip: str, embedding: List[float], text_query: str = ""
    ) -> List[Dict[str, Any]]:
        """
        Retrieve threat intelligence relevant to the alert.

        Args:
            src_ip: Source IP address from alert
            embedding: Query embedding vector

        Returns:
            List of threat intel indicators
        """
        if not self.vector_store.is_connected():
            return []

        intel_results = []

        try:
            # Prioritize exact IOC matches when available.
            exact_matches = self.vector_store.search_exact_threat_intel(
                ioc_value=src_ip, ioc_type="ip", k=self.max_threat_intel
            )
            intel_results.extend(exact_matches)

            if self.hybrid_search and text_query:
                hybrid = self.vector_store.hybrid_search(
                    embedding=embedding,
                    text_query=text_query,
                    index="threat_intel",
                    k=self.max_threat_intel,
                    text_boost=self.text_weight,
                    vector_boost=self.vector_weight,
                    min_score=self.similarity_threshold,
                    filters={"ioc_type": "ip"},
                )
                if hybrid:
                    intel_results.extend(hybrid)

            # Search for similar threat intel by semantic similarity
            similar_intel = self.vector_store.search_similar_threat_intel(
                embedding=embedding,
                k=self.max_threat_intel,
                min_score=self.similarity_threshold,
                ioc_type="ip",
            )
            intel_results.extend(similar_intel)

        except Exception as e:
            logger.error(f"Failed to retrieve threat intel: {e}")

        # Deduplicate by IOC ID/value
        seen = set()
        unique = []
        for item in intel_results:
            ioc_id = item.get("ioc_id") or f"{item.get('ioc_type')}:{item.get('ioc_value')}"
            if ioc_id in seen:
                continue
            seen.add(ioc_id)
            unique.append(item)

        unique.sort(key=lambda x: x.get("similarity_score", 0), reverse=True)
        return unique[: self.max_threat_intel]

    def _retrieve_playbooks_semantic(
        self, embedding: List[float], mitre_techniques: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """Semantic retrieval for playbooks with MITRE-aware filtering."""
        playbooks = []
        if mitre_techniques:
            for technique in mitre_techniques[:2]:
                results = self.vector_store.search_relevant_playbooks(
                    embedding=embedding,
                    k=2,
                    min_score=0.5,
                    mitre_technique=technique,
                )
                playbooks.extend(results)

        if not playbooks:
            playbooks = self.vector_store.search_relevant_playbooks(
                embedding=embedding,
                k=self.max_playbooks,
                min_score=self.similarity_threshold,
            )

        return playbooks

    def _retrieve_playbooks(
        self,
        embedding: List[float],
        mitre_techniques: List[str] = None,
        text_query: str = "",
    ) -> List[Dict[str, Any]]:
        """
        Retrieve relevant incident response playbooks.

        Args:
            embedding: Query embedding vector
            mitre_techniques: List of MITRE technique IDs
            text_query: Hybrid keyword query

        Returns:
            List of relevant playbooks
        """
        if not self.vector_store.is_connected():
            logger.warning("Vector store not connected, skipping playbook retrieval")
            return []

        playbooks = []

        try:
            if self.hybrid_search and text_query:
                filters = {"mitre_techniques": mitre_techniques} if mitre_techniques else None
                playbooks = self.vector_store.hybrid_search(
                    embedding=embedding,
                    text_query=text_query,
                    index="playbooks",
                    k=self.max_playbooks * 2,
                    text_boost=self.text_weight,
                    vector_boost=self.vector_weight,
                    min_score=self.similarity_threshold,
                    filters=filters,
                )

            if not playbooks:
                playbooks = self._retrieve_playbooks_semantic(
                    embedding=embedding, mitre_techniques=mitre_techniques
                )

            # Deduplicate by playbook_id
            seen_ids = set()
            unique_playbooks = []
            for pb in playbooks:
                pb_id = pb.get("playbook_id")
                if pb_id and pb_id not in seen_ids:
                    seen_ids.add(pb_id)
                    unique_playbooks.append(pb)

            unique_playbooks.sort(
                key=lambda item: item.get("similarity_score", item.get("hybrid_score", 0)),
                reverse=True,
            )
            return unique_playbooks[: self.max_playbooks]

        except Exception as e:
            logger.error(f"Failed to retrieve playbooks: {e}")
            return []

    def _retrieve_temporal_context(
        self,
        reference_timestamp: str = None,
        agent_id: str = None,
        src_ip: str = None,
        rule_id: str = None,
    ) -> List[Dict[str, Any]]:
        """
        Retrieve alerts from the same temporal context.
        """
        if not self.vector_store.is_connected():
            return []

        try:
            return self.vector_store.search_temporal_alerts(
                reference_timestamp=reference_timestamp or datetime.now().isoformat(),
                k=self.max_temporal_alerts,
                window_before=self.temporal_window_before,
                window_after=self.temporal_window_after,
                agent_id=agent_id,
                src_ip=src_ip,
                rule_id=rule_id,
            )
        except Exception as e:
            logger.error(f"Failed to retrieve temporal context: {e}")
            return []


    def _extract_mitre_ids(self, rule: Dict) -> List[str]:
        """Extract MITRE technique IDs from rule."""
        ids = []
        mitre = rule.get("mitre", {})

        if isinstance(mitre, dict):
            mitre_ids = mitre.get("id", [])
            if isinstance(mitre_ids, list):
                ids.extend(mitre_ids)
            elif isinstance(mitre_ids, str):
                ids.append(mitre_ids)

        return ids

    def index_alert_for_rag(self, alert: Dict[str, Any]) -> bool:
        """
        Index an alert for future RAG retrieval.

        This should be called when processing new alerts to build
        the knowledge base for similarity search.

        Args:
            alert: Wazuh alert dictionary

        Returns:
            True if indexed successfully
        """
        if not self.vector_store.is_connected():
            logger.warning("Vector store not connected, cannot index alert")
            return False

        try:
            # Generate embedding
            embedding = self.embedding_service.embed_alert(alert)

            # Index in vector store
            success = self.vector_store.index_alert(alert, embedding)

            if success:
                logger.debug(f"Indexed alert {alert.get('id')} for RAG")

            return success

        except Exception as e:
            logger.error(f"Failed to index alert for RAG: {e}")
            return False

    def quick_context_summary(self, alert: Dict[str, Any]) -> str:
        """
        Get a quick text summary of RAG context for an alert.

        This is useful for CLI output or quick analysis.

        Args:
            alert: Wazuh alert dictionary

        Returns:
            Formatted summary string
        """
        context = self.retrieve_context(alert)

        if context.total_documents == 0:
            return "No historical context available."

        lines = ["RAG Context Retrieved:"]

        if context.similar_alerts:
            lines.append(f"  • {len(context.similar_alerts)} similar past alerts")
            # Show top match
            top = context.similar_alerts[0]
            lines.append(
                f"    - Top match: {top.get('rule_description', 'N/A')} "
                f"({top.get('similarity_score', 0):.1%} similar)"
            )

        if context.threat_intel:
            lines.append(f"  • {len(context.threat_intel)} threat intel indicators")

        if context.relevant_playbooks:
            lines.append(f"  • {len(context.relevant_playbooks)} relevant playbooks")
            for pb in context.relevant_playbooks[:2]:
                lines.append(f"    - {pb.get('title', 'N/A')}")

        if context.temporal_context:
            lines.append(
                f"  • {len(context.temporal_context)} temporally correlated alerts"
            )

        total_ms = context.retrieval_telemetry.get("total_duration_ms")
        if total_ms is not None:
            lines.append(f"  • Retrieval time: {total_ms} ms")

        return "\n".join(lines)


# Singleton instance
_rag_retriever = None


def get_rag_retriever(config: Dict[str, Any] = None, reset: bool = False) -> RAGRetriever:
    """Get or create the singleton RAG retriever instance."""
    global _rag_retriever
    if _rag_retriever is None or reset:
        _rag_retriever = RAGRetriever(config=config)
    return _rag_retriever


if __name__ == "__main__":
    # Test the RAG retriever
    logging.basicConfig(level=logging.INFO)

    print("Testing RAG Retriever...")
    print("=" * 60)

    # Create retriever
    retriever = RAGRetriever()

    # Test alert
    test_alert = {
        "id": "test-alert-001",
        "rule": {
            "id": "200001",
            "description": "SSH brute force attack detected",
            "level": 10,
            "mitre": {"id": ["T1110"]},
        },
        "agent": {"id": "001", "name": "linux-endpoint-01"},
        "data": {"srcip": "203.0.113.45", "dstuser": "root"},
        "timestamp": datetime.now().isoformat(),
    }

    # Test embedding generation
    print("\n1. Testing alert embedding generation...")
    embedding_service = get_embedding_service()
    embedding = embedding_service.embed_alert(test_alert)
    print(f"   ✓ Generated embedding (dimension: {len(embedding)})")

    # Test context retrieval
    print("\n2. Testing context retrieval...")
    if retriever.vector_store.is_connected():
        context = retriever.retrieve_context(test_alert)
        print(f"   ✓ Retrieved {context.total_documents} context documents")
        print(f"     - Similar alerts: {len(context.similar_alerts)}")
        print(f"     - Threat intel: {len(context.threat_intel)}")
        print(f"     - Playbooks: {len(context.relevant_playbooks)}")

        # Test context formatting
        print("\n3. Testing context formatting...")
        prompt_context = context.to_prompt_context()
        print("   Generated context snippet:")
        print("   " + "-" * 40)
        for line in prompt_context.split("\n")[:10]:
            print(f"   {line}")
        if len(prompt_context.split("\n")) > 10:
            print("   ...")
        print("   " + "-" * 40)
    else:
        print("   ⚠ OpenSearch not connected - skipping retrieval tests")
        print("   Set OPENSEARCH_HOST/OPENSEARCH_USER/OPENSEARCH_PASSWORD environment variables")

    # Test quick summary
    print("\n4. Testing quick summary...")
    summary = retriever.quick_context_summary(test_alert)
    print(f"   {summary}")

    print("\n" + "=" * 60)
    print("RAG Retriever test completed!")
