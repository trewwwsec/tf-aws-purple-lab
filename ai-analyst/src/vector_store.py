#!/usr/bin/env python3
"""
Vector Store - OpenSearch k-NN integration for storing and retrieving vector embeddings.
Supports alerts, threat intelligence indicators, and playbooks as vectorized documents.
"""

import os
import json
import logging
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime
from opensearchpy import OpenSearch, helpers

logger = logging.getLogger(__name__)


class VectorStore:
    """
    Vector store using OpenSearch k-NN for semantic similarity search.

    Indexes:
    - soc-alerts-v1: Historical security alerts with embeddings
    - soc-threat-intel-v1: IOCs and threat indicators with embeddings
    - soc-playbooks-v1: Incident response playbooks with embeddings
    """

    INDEX_ALERTS = "soc-alerts-v1"
    INDEX_THREAT_INTEL = "soc-threat-intel-v1"
    INDEX_PLAYBOOKS = "soc-playbooks-v1"

    def __init__(
        self,
        hosts: List[str] = None,
        username: str = None,
        password: str = None,
        use_ssl: bool = True,
        verify_certs: bool = False,
        embedding_dimension: int = 384,
    ):
        """
        Initialize the vector store connection to OpenSearch.

        Args:
            hosts: List of OpenSearch hosts (default: from env or localhost:9200)
            username: OpenSearch username (default: from env)
            password: OpenSearch password (default: from env)
            use_ssl: Use HTTPS connection
            verify_certs: Verify SSL certificates
            embedding_dimension: Dimension of embedding vectors (384 for all-MiniLM-L6-v2)
        """
        self.embedding_dimension = embedding_dimension

        # Get connection details from environment or parameters
        self.hosts = hosts or self._get_hosts_from_env()
        self.username = username or os.environ.get("OPENSEARCH_USER", "admin")
        self.password = password or os.environ.get("OPENSEARCH_PASSWORD", "admin")
        self.use_ssl = use_ssl
        self.verify_certs = verify_certs

        self.client = None
        self._connect()

    def _get_hosts_from_env(self) -> List[str]:
        """Get OpenSearch hosts from environment variables."""
        host = os.environ.get("OPENSEARCH_HOST", "localhost")
        port = os.environ.get("OPENSEARCH_PORT", "9200")
        return [f"{host}:{port}"]

    def _connect(self):
        """Establish connection to OpenSearch."""
        try:
            self.client = OpenSearch(
                hosts=self.hosts,
                http_auth=(self.username, self.password) if self.username else None,
                use_ssl=self.use_ssl,
                verify_certs=self.verify_certs,
                ssl_show_warn=False,
            )

            # Test connection
            info = self.client.info()
            logger.info(f"Connected to OpenSearch {info['version']['number']}")

        except Exception as e:
            logger.error(f"Failed to connect to OpenSearch: {e}")
            self.client = None

    def is_connected(self) -> bool:
        """Check if connected to OpenSearch."""
        if not self.client:
            return False
        try:
            self.client.ping()
            return True
        except:
            return False

    def create_indices(self) -> bool:
        """
        Create all required indices with k-NN mappings.

        Returns:
            True if all indices created successfully
        """
        if not self.is_connected():
            logger.error("Not connected to OpenSearch")
            return False

        success = True
        success &= self._create_alerts_index()
        success &= self._create_threat_intel_index()
        success &= self._create_playbooks_index()

        return success

    def _create_alerts_index(self) -> bool:
        """Create the alerts index with k-NN mapping."""
        index_name = self.INDEX_ALERTS

        if self.client.indices.exists(index=index_name):
            logger.info(f"Index {index_name} already exists")
            return True

        mapping = {
            "settings": {
                "index": {"knn": True, "knn.algo_param.ef_search": 100},
                "number_of_shards": 1,
                "number_of_replicas": 0,
            },
            "mappings": {
                "properties": {
                    "alert_id": {"type": "keyword"},
                    "rule_id": {"type": "keyword"},
                    "rule_description": {"type": "text", "analyzer": "standard"},
                    "rule_level": {"type": "integer"},
                    "agent_id": {"type": "keyword"},
                    "agent_name": {"type": "keyword"},
                    "src_ip": {"type": "ip"},
                    "dst_ip": {"type": "ip"},
                    "dstuser": {"type": "keyword"},
                    "mitre_techniques": {"type": "keyword"},
                    "timestamp": {"type": "date"},
                    "embedding": {
                        "type": "knn_vector",
                        "dimension": self.embedding_dimension,
                        "method": {
                            "name": "hnsw",
                            "space_type": "cosinesimil",
                            "engine": "faiss",
                            "parameters": {"ef_construction": 128, "m": 16},
                        },
                    },
                    "raw_alert": {"type": "object", "enabled": False},
                }
            },
        }

        try:
            self.client.indices.create(index=index_name, body=mapping)
            logger.info(f"Created index: {index_name}")
            return True
        except Exception as e:
            logger.error(f"Failed to create index {index_name}: {e}")
            return False

    def _create_threat_intel_index(self) -> bool:
        """Create the threat intelligence index with k-NN mapping."""
        index_name = self.INDEX_THREAT_INTEL

        if self.client.indices.exists(index=index_name):
            logger.info(f"Index {index_name} already exists")
            return True

        mapping = {
            "settings": {
                "index": {"knn": True, "knn.algo_param.ef_search": 100},
                "number_of_shards": 1,
                "number_of_replicas": 0,
            },
            "mappings": {
                "properties": {
                    "ioc_id": {"type": "keyword"},
                    "ioc_value": {"type": "keyword"},
                    "ioc_type": {"type": "keyword"},
                    "threat_type": {"type": "keyword"},
                    "confidence_score": {"type": "float"},
                    "first_seen": {"type": "date"},
                    "last_seen": {"type": "date"},
                    "source": {"type": "keyword"},
                    "tags": {"type": "keyword"},
                    "embedding": {
                        "type": "knn_vector",
                        "dimension": self.embedding_dimension,
                        "method": {
                            "name": "hnsw",
                            "space_type": "cosinesimil",
                            "engine": "faiss",
                            "parameters": {"ef_construction": 128, "m": 16},
                        },
                    },
                    "metadata": {"type": "object", "enabled": False},
                }
            },
        }

        try:
            self.client.indices.create(index=index_name, body=mapping)
            logger.info(f"Created index: {index_name}")
            return True
        except Exception as e:
            logger.error(f"Failed to create index {index_name}: {e}")
            return False

    def _create_playbooks_index(self) -> bool:
        """Create the playbooks index with k-NN mapping."""
        index_name = self.INDEX_PLAYBOOKS

        if self.client.indices.exists(index=index_name):
            logger.info(f"Index {index_name} already exists")
            return True

        mapping = {
            "settings": {
                "index": {"knn": True, "knn.algo_param.ef_search": 100},
                "number_of_shards": 1,
                "number_of_replicas": 0,
            },
            "mappings": {
                "properties": {
                    "playbook_id": {"type": "keyword"},
                    "title": {"type": "text", "analyzer": "standard"},
                    "description": {"type": "text", "analyzer": "standard"},
                    "severity": {"type": "keyword"},
                    "mitre_techniques": {"type": "keyword"},
                    "file_path": {"type": "keyword"},
                    "created_at": {"type": "date"},
                    "updated_at": {"type": "date"},
                    "embedding": {
                        "type": "knn_vector",
                        "dimension": self.embedding_dimension,
                        "method": {
                            "name": "hnsw",
                            "space_type": "cosinesimil",
                            "engine": "faiss",
                            "parameters": {"ef_construction": 128, "m": 16},
                        },
                    },
                    "content": {"type": "object", "enabled": False},
                }
            },
        }

        try:
            self.client.indices.create(index=index_name, body=mapping)
            logger.info(f"Created index: {index_name}")
            return True
        except Exception as e:
            logger.error(f"Failed to create index {index_name}: {e}")
            return False

    def index_alert(self, alert: Dict[str, Any], embedding: List[float]) -> bool:
        """
        Index a security alert with its embedding.

        Args:
            alert: Wazuh alert dictionary
            embedding: Vector embedding of the alert

        Returns:
            True if indexed successfully
        """
        if not self.is_connected():
            return False

        rule = alert.get("rule", {})
        data = alert.get("data", {})
        agent = alert.get("agent", {})

        doc = {
            "alert_id": alert.get("id", f"alert-{datetime.now().isoformat()}"),
            "rule_id": str(rule.get("id", "unknown")),
            "rule_description": rule.get("description", ""),
            "rule_level": rule.get("level", 0),
            "agent_id": agent.get("id", "unknown"),
            "agent_name": agent.get("name", "unknown"),
            "src_ip": data.get("srcip"),
            "dst_ip": data.get("dstip"),
            "dstuser": data.get("dstuser"),
            "mitre_techniques": self._extract_mitre_techniques(rule),
            "timestamp": alert.get("timestamp", datetime.now().isoformat()),
            "embedding": embedding,
            "raw_alert": alert,
        }

        try:
            self.client.index(index=self.INDEX_ALERTS, body=doc)
            return True
        except Exception as e:
            logger.error(f"Failed to index alert: {e}")
            return False

    def index_threat_intel(
        self,
        ioc_value: str,
        ioc_type: str,
        embedding: List[float],
        threat_type: str = None,
        confidence: float = 0.5,
        source: str = "manual",
        metadata: Dict = None,
    ) -> bool:
        """
        Index a threat intelligence indicator with its embedding.

        Args:
            ioc_value: The IOC value (IP, hash, domain, etc.)
            ioc_type: Type of IOC (ip, hash, domain, url)
            embedding: Vector embedding of the IOC
            threat_type: Category of threat (malware, phishing, etc.)
            confidence: Confidence score (0-1)
            source: Source of the intel (abuseipdb, virustotal, etc.)
            metadata: Additional metadata

        Returns:
            True if indexed successfully
        """
        if not self.is_connected():
            return False

        doc = {
            "ioc_id": f"{ioc_type}-{hash(ioc_value)}",
            "ioc_value": ioc_value,
            "ioc_type": ioc_type,
            "threat_type": threat_type or "unknown",
            "confidence_score": confidence,
            "first_seen": datetime.now().isoformat(),
            "last_seen": datetime.now().isoformat(),
            "source": source,
            "tags": metadata.get("tags", []) if metadata else [],
            "embedding": embedding,
            "metadata": metadata or {},
        }

        try:
            self.client.index(index=self.INDEX_THREAT_INTEL, body=doc)
            return True
        except Exception as e:
            logger.error(f"Failed to index threat intel: {e}")
            return False

    def index_playbook(
        self,
        playbook_id: str,
        title: str,
        description: str,
        embedding: List[float],
        severity: str = "medium",
        mitre_techniques: List[str] = None,
        file_path: str = None,
        content: Dict = None,
    ) -> bool:
        """
        Index an incident response playbook with its embedding.

        Args:
            playbook_id: Unique identifier for the playbook
            title: Playbook title
            description: Playbook description
            embedding: Vector embedding of the playbook
            severity: Incident severity level
            mitre_techniques: List of MITRE ATT&CK technique IDs
            file_path: Path to playbook file
            content: Full playbook content

        Returns:
            True if indexed successfully
        """
        if not self.is_connected():
            return False

        doc = {
            "playbook_id": playbook_id,
            "title": title,
            "description": description,
            "severity": severity,
            "mitre_techniques": mitre_techniques or [],
            "file_path": file_path or "",
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat(),
            "embedding": embedding,
            "content": content or {},
        }

        try:
            self.client.index(index=self.INDEX_PLAYBOOKS, body=doc)
            return True
        except Exception as e:
            logger.error(f"Failed to index playbook: {e}")
            return False

    def search_similar_alerts(
        self,
        embedding: List[float],
        k: int = 5,
        min_score: float = 0.7,
        agent_id: str = None,
        time_range: str = "7d",
        rule_id: str = None,
    ) -> List[Dict[str, Any]]:
        """
        Find alerts similar to the given embedding using k-NN search.

        Args:
            embedding: Query embedding vector
            k: Number of results to return
            min_score: Minimum similarity score (0-1)
            agent_id: Filter by specific agent
            time_range: Time range for search (e.g., "24h", "7d")
            rule_id: Filter by specific rule ID

        Returns:
            List of similar alerts with similarity scores
        """
        if not self.is_connected():
            logger.warning("OpenSearch not connected, returning empty results")
            return []

        # Build filter clauses
        filter_clauses = []

        # Time range filter
        if time_range:
            time_map = {
                "1h": "now-1h",
                "24h": "now-24h",
                "7d": "now-7d",
                "30d": "now-30d",
            }
            time_query = time_map.get(time_range, f"now-{time_range}")
            filter_clauses.append({"range": {"timestamp": {"gte": time_query}}})

        # Agent filter
        if agent_id:
            filter_clauses.append({"term": {"agent_id": agent_id}})

        # Rule filter
        if rule_id:
            filter_clauses.append({"term": {"rule_id": rule_id}})

        query = {
            "size": k,
            "query": {
                "knn": {
                    "embedding": {
                        "vector": embedding,
                        "k": k * 2,  # Get more candidates for filtering
                    }
                }
            },
        }

        # Add post_filter for metadata filtering
        if filter_clauses:
            query["post_filter"] = {"bool": {"must": filter_clauses}}

        try:
            response = self.client.search(index=self.INDEX_ALERTS, body=query)

            results = []
            for hit in response["hits"]["hits"]:
                score = hit["_score"]
                if score >= min_score:
                    result = hit["_source"]
                    result["similarity_score"] = score
                    results.append(result)

            return results[:k]

        except Exception as e:
            logger.error(f"Failed to search similar alerts: {e}")
            return []

    def search_similar_threat_intel(
        self,
        embedding: List[float],
        k: int = 5,
        min_score: float = 0.7,
        ioc_type: str = None,
    ) -> List[Dict[str, Any]]:
        """
        Find threat intel indicators similar to the query.

        Args:
            embedding: Query embedding vector
            k: Number of results
            min_score: Minimum similarity score
            ioc_type: Filter by IOC type (ip, hash, domain)

        Returns:
            List of similar IOCs with similarity scores
        """
        if not self.is_connected():
            return []

        filter_clauses = []
        if ioc_type:
            filter_clauses.append({"term": {"ioc_type": ioc_type}})

        query = {
            "size": k,
            "query": {"knn": {"embedding": {"vector": embedding, "k": k}}},
        }

        if filter_clauses:
            query["post_filter"] = {"bool": {"must": filter_clauses}}

        try:
            response = self.client.search(index=self.INDEX_THREAT_INTEL, body=query)

            results = []
            for hit in response["hits"]["hits"]:
                score = hit["_score"]
                if score >= min_score:
                    result = hit["_source"]
                    result["similarity_score"] = score
                    results.append(result)

            return results

        except Exception as e:
            logger.error(f"Failed to search threat intel: {e}")
            return []

    def search_relevant_playbooks(
        self,
        embedding: List[float],
        k: int = 3,
        min_score: float = 0.6,
        mitre_technique: str = None,
    ) -> List[Dict[str, Any]]:
        """
        Find playbooks relevant to the query.

        Args:
            embedding: Query embedding vector
            k: Number of results
            min_score: Minimum similarity score
            mitre_technique: Filter by MITRE technique ID

        Returns:
            List of relevant playbooks with similarity scores
        """
        if not self.is_connected():
            return []

        # Combine semantic search with MITRE technique filter
        must_clauses = []
        filter_clauses = []

        if mitre_technique:
            filter_clauses.append({"terms": {"mitre_techniques": [mitre_technique]}})

        query = {
            "size": k,
            "query": {"knn": {"embedding": {"vector": embedding, "k": k}}},
        }

        if filter_clauses:
            query["post_filter"] = {"bool": {"must": filter_clauses}}

        try:
            response = self.client.search(index=self.INDEX_PLAYBOOKS, body=query)

            results = []
            for hit in response["hits"]["hits"]:
                score = hit["_score"]
                if score >= min_score:
                    result = hit["_source"]
                    result["similarity_score"] = score
                    results.append(result)

            return results

        except Exception as e:
            logger.error(f"Failed to search playbooks: {e}")
            return []

    def hybrid_search(
        self,
        embedding: List[float],
        text_query: str,
        index: str,
        k: int = 5,
        text_boost: float = 0.3,
        vector_boost: float = 0.7,
    ) -> List[Dict[str, Any]]:
        """
        Perform hybrid search combining text and vector similarity.

        Args:
            embedding: Query embedding vector
            text_query: Text query for keyword matching
            index: Index to search (alerts, threat_intel, or playbooks)
            k: Number of results
            text_boost: Weight for text relevance score
            vector_boost: Weight for vector similarity score

        Returns:
            List of results with combined scores
        """
        if not self.is_connected():
            return []

        # Map index names
        index_map = {
            "alerts": self.INDEX_ALERTS,
            "threat_intel": self.INDEX_THREAT_INTEL,
            "playbooks": self.INDEX_PLAYBOOKS,
        }
        index_name = index_map.get(index, index)

        query = {
            "size": k,
            "query": {
                "script_score": {
                    "query": {
                        "multi_match": {
                            "query": text_query,
                            "fields": ["rule_description^2", "title", "description"],
                        }
                    },
                    "script": {
                        "source": """
                            double textScore = _score;
                            double vectorScore = cosineSimilarity(params.query_vector, 'embedding') + 1.0;
                            return (textScore * params.text_boost) + (vectorScore * params.vector_boost * 10);
                        """,
                        "params": {
                            "query_vector": embedding,
                            "text_boost": text_boost,
                            "vector_boost": vector_boost,
                        },
                    },
                }
            },
        }

        try:
            response = self.client.search(index=index_name, body=query)

            results = []
            for hit in response["hits"]["hits"]:
                result = hit["_source"]
                result["hybrid_score"] = hit["_score"]
                results.append(result)

            return results

        except Exception as e:
            logger.error(f"Failed to perform hybrid search: {e}")
            return []

    def _extract_mitre_techniques(self, rule: Dict) -> List[str]:
        """Extract MITRE technique IDs from rule."""
        techniques = []
        mitre = rule.get("mitre", {})

        if isinstance(mitre, dict):
            ids = mitre.get("id", [])
            if isinstance(ids, list):
                techniques.extend(ids)
            elif isinstance(ids, str):
                techniques.append(ids)

        return techniques

    def get_stats(self) -> Dict[str, Any]:
        """Get statistics about indexed documents."""
        if not self.is_connected():
            return {"error": "Not connected to OpenSearch"}

        stats = {}

        for index in [self.INDEX_ALERTS, self.INDEX_THREAT_INTEL, self.INDEX_PLAYBOOKS]:
            try:
                count = self.client.count(index=index)
                stats[index] = {"document_count": count["count"]}
            except Exception as e:
                stats[index] = {"error": str(e)}

        return stats


# Singleton instance
_vector_store = None


def get_vector_store(embedding_dimension: int = 384) -> VectorStore:
    """Get or create the singleton vector store instance."""
    global _vector_store
    if _vector_store is None:
        _vector_store = VectorStore(embedding_dimension=embedding_dimension)
    return _vector_store


if __name__ == "__main__":
    # Test the vector store
    logging.basicConfig(level=logging.INFO)

    print("Testing Vector Store...")

    store = VectorStore()

    if not store.is_connected():
        print("Not connected to OpenSearch. Make sure OpenSearch is running.")
        print(
            "For Wazuh: OPENSEARCH_HOST=localhost OPENSEARCH_PASSWORD=admin python vector_store.py"
        )
        exit(1)

    # Create indices
    print("\nCreating indices...")
    store.create_indices()

    # Test indexing
    print("\nTesting document indexing...")

    # Sample embedding (384 dimensions for all-MiniLM-L6-v2)
    sample_embedding = [0.1] * 384

    # Index a test alert
    test_alert = {
        "id": "test-001",
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

    success = store.index_alert(test_alert, sample_embedding)
    print(f"Alert indexed: {success}")

    # Index test threat intel
    success = store.index_threat_intel(
        ioc_value="203.0.113.45",
        ioc_type="ip",
        embedding=sample_embedding,
        threat_type="brute_force",
        confidence=0.95,
    )
    print(f"Threat intel indexed: {success}")

    # Index test playbook
    success = store.index_playbook(
        playbook_id="IR-PB-001",
        title="SSH Brute Force Response",
        description="Procedures for responding to SSH brute force attacks",
        embedding=sample_embedding,
        severity="high",
        mitre_techniques=["T1110"],
    )
    print(f"Playbook indexed: {success}")

    # Test search
    print("\nTesting similarity search...")
    results = store.search_similar_alerts(sample_embedding, k=3)
    print(f"Found {len(results)} similar alerts")

    # Get stats
    print("\nIndex statistics:")
    stats = store.get_stats()
    for index, info in stats.items():
        print(f"  {index}: {info}")

    print("\nVector Store test completed!")
