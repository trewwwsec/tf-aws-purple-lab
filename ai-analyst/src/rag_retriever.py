#!/usr/bin/env python3
"""
RAG Retriever - Retrieval-Augmented Generation context retrieval for alert analysis.
Retrieves similar past incidents, threat intelligence, and relevant playbooks.
"""

import os
import json
import logging
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

    # Total context documents retrieved
    @property
    def total_documents(self) -> int:
        return (
            len(self.similar_alerts)
            + len(self.threat_intel)
            + len(self.relevant_playbooks)
        )

    def to_prompt_context(
        self, max_alerts: int = 3, max_intel: int = 2, max_playbooks: int = 2
    ) -> str:
        """
        Convert RAG context to a formatted string for LLM prompts.

        Args:
            max_alerts: Maximum similar alerts to include
            max_intel: Maximum threat intel items to include
            max_playbooks: Maximum playbooks to include

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
        self.embedding_service = embedding_service or get_embedding_service()
        self.vector_store = vector_store or get_vector_store(
            embedding_dimension=self.embedding_service.dimension
        )

        # Default configuration
        self.config = config or {}
        self.similarity_threshold = self.config.get("similarity_threshold", 0.7)
        self.max_similar_alerts = self.config.get("max_similar_alerts", 5)
        self.max_threat_intel = self.config.get("max_threat_intel", 3)
        self.max_playbooks = self.config.get("max_playbooks", 2)
        self.time_range = self.config.get("time_range", "7d")

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
        context = RAGContext()

        # Generate embedding for the alert
        try:
            alert_embedding = self.embedding_service.embed_alert(alert)
        except Exception as e:
            logger.error(f"Failed to generate alert embedding: {e}")
            return context

        # Extract key information from alert
        rule = alert.get("rule", {})
        data = alert.get("data", {})
        agent = alert.get("agent", {})

        src_ip = data.get("srcip")
        dstuser = data.get("dstuser")
        agent_id = agent.get("id")
        mitre_ids = self._extract_mitre_ids(rule)

        # 1. Retrieve similar past alerts
        context.similar_alerts = self._retrieve_similar_alerts(
            embedding=alert_embedding, agent_id=agent_id
        )

        # 2. Retrieve threat intelligence
        if src_ip:
            context.threat_intel = self._retrieve_threat_intel(
                src_ip=src_ip, embedding=alert_embedding
            )

        # 3. Retrieve relevant playbooks
        context.relevant_playbooks = self._retrieve_playbooks(
            embedding=alert_embedding, mitre_techniques=mitre_ids
        )

        # 4. Retrieve temporal context
        context.temporal_context = self._retrieve_temporal_context(
            agent_id=agent_id, src_ip=src_ip
        )

        logger.info(
            f"Retrieved RAG context: {len(context.similar_alerts)} alerts, "
            f"{len(context.threat_intel)} intel items, "
            f"{len(context.relevant_playbooks)} playbooks"
        )

        return context

    def _retrieve_similar_alerts(
        self, embedding: List[float], agent_id: str = None
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
        self, src_ip: str, embedding: List[float]
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
            # Search for similar threat intel by semantic similarity
            similar_intel = self.vector_store.search_similar_threat_intel(
                embedding=embedding,
                k=self.max_threat_intel,
                min_score=self.similarity_threshold,
                ioc_type="ip",
            )
            intel_results.extend(similar_intel)

            # Also check for exact IP match
            # (This would require a separate query to check if the IP is in the index)
            # For now, we rely on semantic similarity

        except Exception as e:
            logger.error(f"Failed to retrieve threat intel: {e}")

        return intel_results

    def _retrieve_playbooks(
        self, embedding: List[float], mitre_techniques: List[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Retrieve relevant incident response playbooks.

        Args:
            embedding: Query embedding vector
            mitre_techniques: List of MITRE technique IDs

        Returns:
            List of relevant playbooks
        """
        if not self.vector_store.is_connected():
            logger.warning("Vector store not connected, skipping playbook retrieval")
            return []

        playbooks = []

        try:
            # Try searching by MITRE technique first
            if mitre_techniques:
                for technique in mitre_techniques[:2]:  # Limit to first 2 techniques
                    results = self.vector_store.search_relevant_playbooks(
                        embedding=embedding,
                        k=2,
                        min_score=0.5,
                        mitre_technique=technique,
                    )
                    playbooks.extend(results)

            # If no results or no MITRE techniques, do semantic search
            if not playbooks:
                playbooks = self.vector_store.search_relevant_playbooks(
                    embedding=embedding,
                    k=self.max_playbooks,
                    min_score=self.similarity_threshold,
                )

            # Deduplicate by playbook_id
            seen_ids = set()
            unique_playbooks = []
            for pb in playbooks:
                pb_id = pb.get("playbook_id")
                if pb_id and pb_id not in seen_ids:
                    seen_ids.add(pb_id)
                    unique_playbooks.append(pb)

            return unique_playbooks[: self.max_playbooks]

        except Exception as e:
            logger.error(f"Failed to retrieve playbooks: {e}")
            return []

    def _retrieve_temporal_context(
        self, agent_id: str = None, src_ip: str = None
    ) -> List[Dict[str, Any]]:
        """
        Retrieve alerts from the same temporal context.

        This helps identify ongoing campaigns or related activity.

        Args:
            agent_id: Agent ID
            src_ip: Source IP

        Returns:
            List of temporally related alerts
        """
        if not self.vector_store.is_connected():
            return []

        # Temporal context retrieval would require querying OpenSearch
        # with time range filters. For now, this is a placeholder
        # that could be implemented with direct OpenSearch queries.

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

        return "\n".join(lines)


# Singleton instance
_rag_retriever = None


def get_rag_retriever(config: Dict[str, Any] = None) -> RAGRetriever:
    """Get or create the singleton RAG retriever instance."""
    global _rag_retriever
    if _rag_retriever is None:
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
            "id": "100001",
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
        print("   Set OPENSEARCH_HOST and OPENSEARCH_PASSWORD environment variables")

    # Test quick summary
    print("\n4. Testing quick summary...")
    summary = retriever.quick_context_summary(test_alert)
    print(f"   {summary}")

    print("\n" + "=" * 60)
    print("RAG Retriever test completed!")
