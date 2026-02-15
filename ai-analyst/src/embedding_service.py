#!/usr/bin/env python3
"""
Embedding Service - Generates vector embeddings for text using sentence-transformers.
Supports caching and multiple embedding models optimized for security content.
"""

import os
import json
import hashlib
import logging
from typing import List, Union, Optional
from functools import lru_cache

logger = logging.getLogger(__name__)


class EmbeddingService:
    """
    Service for generating vector embeddings from text.

    Uses sentence-transformers with a model optimized for semantic similarity.
    Implements caching to avoid recomputing embeddings for the same text.
    """

    # Model optimized for semantic similarity and sentence embeddings
    DEFAULT_MODEL = "all-MiniLM-L6-v2"

    # Alternative models for different use cases
    MODELS = {
        "light": "all-MiniLM-L6-v2",  # 384 dimensions, fast
        "balanced": "all-mpnet-base-v2",  # 768 dimensions, better quality
        "security": "sentence-transformers/all-MiniLM-L6-v2",  # Good for technical text
    }

    def __init__(self, model_name: str = None, cache_dir: str = None):
        """
        Initialize the embedding service.

        Args:
            model_name: Name of the sentence-transformer model to use
            cache_dir: Directory to cache the model and embeddings
        """
        self.model_name = model_name or self.DEFAULT_MODEL
        self.cache_dir = cache_dir or os.path.expanduser(
            "~/.cache/ai-analyst/embeddings"
        )
        self._model = None
        self._embedding_cache = {}

        # Create cache directory
        os.makedirs(self.cache_dir, exist_ok=True)

        logger.info(f"EmbeddingService initialized with model: {self.model_name}")

    @property
    def model(self):
        """Lazy load the embedding model."""
        if self._model is None:
            try:
                from sentence_transformers import SentenceTransformer

                logger.info(f"Loading embedding model: {self.model_name}")
                self._model = SentenceTransformer(
                    self.model_name, cache_folder=self.cache_dir
                )
                logger.info(
                    f"Model loaded. Dimension: {self._model.get_sentence_embedding_dimension()}"
                )
            except ImportError:
                logger.error(
                    "sentence-transformers not installed. Run: pip install sentence-transformers"
                )
                raise
            except Exception as e:
                logger.error(f"Failed to load embedding model: {e}")
                raise
        return self._model

    @property
    def dimension(self) -> int:
        """Get the dimension of embeddings produced by this model."""
        return self.model.get_sentence_embedding_dimension()

    def embed(
        self, text: Union[str, List[str]]
    ) -> Union[List[float], List[List[float]]]:
        """
        Generate embedding for text(s).

        Args:
            text: Single text string or list of strings

        Returns:
            Embedding vector(s) - single list for single input, list of lists for multiple
        """
        if isinstance(text, str):
            return self._embed_single(text)
        elif isinstance(text, list):
            return self._embed_batch(text)
        else:
            raise ValueError(
                f"Text must be string or list of strings, got {type(text)}"
            )

    def _embed_single(self, text: str) -> List[float]:
        """Generate embedding for a single text string with caching."""
        # Check memory cache
        cache_key = self._get_cache_key(text)
        if cache_key in self._embedding_cache:
            return self._embedding_cache[cache_key]

        # Check disk cache
        disk_cache_path = os.path.join(self.cache_dir, f"{cache_key}.json")
        if os.path.exists(disk_cache_path):
            try:
                with open(disk_cache_path, "r") as f:
                    embedding = json.load(f)
                    self._embedding_cache[cache_key] = embedding
                    return embedding
            except Exception as e:
                logger.warning(f"Failed to load cached embedding: {e}")

        # Generate embedding
        embedding = self.model.encode(text, convert_to_tensor=False).tolist()

        # Cache in memory and disk
        self._embedding_cache[cache_key] = embedding
        try:
            with open(disk_cache_path, "w") as f:
                json.dump(embedding, f)
        except Exception as e:
            logger.warning(f"Failed to cache embedding: {e}")

        return embedding

    def _embed_batch(self, texts: List[str]) -> List[List[float]]:
        """Generate embeddings for multiple texts efficiently."""
        # Check cache for each text
        results = []
        uncached_texts = []
        uncached_indices = []

        for i, text in enumerate(texts):
            cache_key = self._get_cache_key(text)
            if cache_key in self._embedding_cache:
                results.append((i, self._embedding_cache[cache_key]))
            else:
                uncached_texts.append(text)
                uncached_indices.append(i)
                results.append((i, None))

        # Generate embeddings for uncached texts in batch
        if uncached_texts:
            embeddings = self.model.encode(
                uncached_texts, convert_to_tensor=False, show_progress_bar=False
            )

            for idx, text, embedding in zip(
                uncached_indices, uncached_texts, embeddings
            ):
                embedding_list = embedding.tolist()
                results[idx] = (idx, embedding_list)

                # Cache result
                cache_key = self._get_cache_key(text)
                self._embedding_cache[cache_key] = embedding_list

                # Disk cache
                disk_cache_path = os.path.join(self.cache_dir, f"{cache_key}.json")
                try:
                    with open(disk_cache_path, "w") as f:
                        json.dump(embedding_list, f)
                except Exception as e:
                    logger.warning(f"Failed to cache embedding: {e}")

        # Return in original order
        return [emb for _, emb in sorted(results, key=lambda x: x[0])]

    def _get_cache_key(self, text: str) -> str:
        """Generate a cache key for a text string."""
        return hashlib.md5(text.encode("utf-8")).hexdigest()

    def embed_alert(self, alert: dict) -> List[float]:
        """
        Generate embedding for a Wazuh alert.

        Creates a rich text representation combining rule description,
        data fields, and context.

        Args:
            alert: Wazuh alert dictionary

        Returns:
            Embedding vector
        """
        # Build rich text representation
        rule = alert.get("rule", {})
        data = alert.get("data", {})
        agent = alert.get("agent", {})

        parts = [
            rule.get("description", ""),
            f"Rule ID: {rule.get('id', 'unknown')}",
            f"Severity: {rule.get('level', 0)}",
        ]

        # Add MITRE technique info
        mitre = rule.get("mitre", {})
        if isinstance(mitre, dict) and mitre.get("id"):
            parts.append(f"MITRE: {mitre.get('id')}")

        # Add agent info
        if agent.get("name"):
            parts.append(f"Agent: {agent.get('name')}")

        # Add key data fields
        for key in ["srcip", "dstip", "dstuser", "command", "program_name"]:
            if data.get(key):
                parts.append(f"{key}: {data[key]}")

        text = " | ".join(filter(None, parts))
        return self.embed(text)

    def embed_threat_intel(self, ioc: dict) -> List[float]:
        """
        Generate embedding for threat intelligence indicator.

        Args:
            ioc: Threat intel dictionary with ioc_value, ioc_type, threat_type, etc.

        Returns:
            Embedding vector
        """
        parts = [
            ioc.get("ioc_value", ""),
            f"Type: {ioc.get('ioc_type', '')}",
            f"Threat: {ioc.get('threat_type', '')}",
            ioc.get("description", ""),
        ]

        text = " | ".join(filter(None, parts))
        return self.embed(text)

    def embed_playbook(self, playbook: dict) -> List[float]:
        """
        Generate embedding for an incident response playbook.

        Args:
            playbook: Playbook dictionary with title, description, mitre_techniques, etc.

        Returns:
            Embedding vector
        """
        parts = [
            playbook.get("title", ""),
            playbook.get("description", ""),
            f"Severity: {playbook.get('severity', '')}",
        ]

        # Add MITRE techniques
        mitre = playbook.get("mitre_techniques", [])
        if mitre:
            parts.append(f"MITRE: {', '.join(mitre)}")

        text = " | ".join(filter(None, parts))
        return self.embed(text)

    def similarity(self, embedding1: List[float], embedding2: List[float]) -> float:
        """
        Calculate cosine similarity between two embeddings.

        Args:
            embedding1: First embedding vector
            embedding2: Second embedding vector

        Returns:
            Cosine similarity score (0 to 1)
        """
        import numpy as np

        vec1 = np.array(embedding1)
        vec2 = np.array(embedding2)

        dot_product = np.dot(vec1, vec2)
        norm1 = np.linalg.norm(vec1)
        norm2 = np.linalg.norm(vec2)

        if norm1 == 0 or norm2 == 0:
            return 0.0

        return float(dot_product / (norm1 * norm2))

    def clear_cache(self):
        """Clear the in-memory embedding cache."""
        self._embedding_cache.clear()
        logger.info("Embedding cache cleared")


# Singleton instance for reuse
_embedding_service = None


def get_embedding_service(model_name: str = None) -> EmbeddingService:
    """Get or create the singleton embedding service instance."""
    global _embedding_service
    if _embedding_service is None:
        _embedding_service = EmbeddingService(model_name=model_name)
    return _embedding_service


if __name__ == "__main__":
    # Test the embedding service
    logging.basicConfig(level=logging.INFO)

    print("Testing Embedding Service...")

    service = EmbeddingService()
    print(f"Model dimension: {service.dimension}")

    # Test single embedding
    text = "SSH brute force attack detected from IP 203.0.113.45"
    embedding = service.embed(text)
    print(f"Single embedding shape: {len(embedding)}")
    print(f"First 5 values: {embedding[:5]}")

    # Test batch embedding
    texts = [
        "SSH brute force attack detected",
        "PowerShell encoded command execution",
        "Sudo privilege escalation attempt",
    ]
    embeddings = service.embed(texts)
    print(f"Batch embeddings count: {len(embeddings)}")

    # Test similarity
    sim = service.similarity(embedding, embeddings[0])
    print(f"Similarity with first text: {sim:.4f}")

    # Test alert embedding
    test_alert = {
        "rule": {
            "id": "100001",
            "description": "SSH brute force attack detected",
            "level": 10,
            "mitre": {"id": ["T1110"]},
        },
        "agent": {"name": "linux-endpoint-01"},
        "data": {"srcip": "203.0.113.45", "dstuser": "root"},
    }
    alert_embedding = service.embed_alert(test_alert)
    print(f"Alert embedding shape: {len(alert_embedding)}")

    print("\nEmbedding Service test completed successfully!")
