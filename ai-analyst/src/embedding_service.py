#!/usr/bin/env python3
"""
Embedding Service - Generates vector embeddings for text using sentence-transformers.
Supports in-memory and on-disk caching with pruning and cache telemetry.
"""

import hashlib
import json
import logging
import os
from collections import OrderedDict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

logger = logging.getLogger(__name__)


class EmbeddingService:
    """
    Service for generating vector embeddings from text.

    Uses sentence-transformers with a model optimized for semantic similarity.
    Implements caching to avoid recomputing embeddings for the same text.
    """

    DEFAULT_MODEL = "all-MiniLM-L6-v2"

    MODELS = {
        "light": "all-MiniLM-L6-v2",  # 384 dimensions, fast
        "balanced": "all-mpnet-base-v2",  # 768 dimensions, better quality
        "security": "sentence-transformers/all-MiniLM-L6-v2",  # Good for technical text
    }

    def __init__(
        self,
        model_name: str = None,
        cache_dir: str = None,
        max_memory_entries: int = 5000,
        max_disk_files: int = 50000,
        max_disk_size_mb: int = 2048,
        prune_interval_writes: int = 200,
    ):
        """
        Initialize the embedding service.

        Args:
            model_name: Name of the sentence-transformer model to use
            cache_dir: Directory to cache the model and embeddings
            max_memory_entries: Max number of embeddings to retain in memory
            max_disk_files: Max number of cached embedding files on disk
            max_disk_size_mb: Max aggregate size of cached embedding files on disk
            prune_interval_writes: Run disk pruning every N cache writes
        """
        self.model_name = model_name or self.DEFAULT_MODEL
        self.cache_dir = os.path.expanduser(
            cache_dir or "~/.cache/ai-analyst/embeddings"
        )
        self.max_memory_entries = max(1, int(max_memory_entries))
        self.max_disk_files = max(1, int(max_disk_files))
        self.max_disk_size_mb = max(1, int(max_disk_size_mb))
        self.prune_interval_writes = max(1, int(prune_interval_writes))
        self._model = None
        self._embedding_cache: "OrderedDict[str, List[float]]" = OrderedDict()
        self._writes_since_prune = 0
        self._stats: Dict[str, int] = {
            "memory_hits": 0,
            "disk_hits": 0,
            "misses": 0,
            "writes": 0,
            "memory_evictions": 0,
            "prune_runs": 0,
            "pruned_files": 0,
            "pruned_bytes": 0,
        }

        os.makedirs(self.cache_dir, exist_ok=True)
        logger.info(
            "EmbeddingService initialized with model=%s cache_dir=%s",
            self.model_name,
            self.cache_dir,
        )

    @property
    def model(self):
        """Lazy load the embedding model."""
        if self._model is None:
            try:
                from sentence_transformers import SentenceTransformer

                logger.info("Loading embedding model: %s", self.model_name)
                self._model = SentenceTransformer(
                    self.model_name, cache_folder=self.cache_dir
                )
                logger.info(
                    "Model loaded. Dimension: %d",
                    self._model.get_sentence_embedding_dimension(),
                )
            except ImportError:
                logger.error(
                    "sentence-transformers not installed. Run: pip install sentence-transformers"
                )
                raise
            except Exception as e:
                logger.error("Failed to load embedding model: %s", e)
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
        if isinstance(text, list):
            return self._embed_batch(text)
        raise ValueError(f"Text must be string or list of strings, got {type(text)}")

    def _cache_file_path(self, cache_key: str) -> str:
        """Get on-disk cache path for a key."""
        return os.path.join(self.cache_dir, f"{cache_key}.json")

    def _remember_memory(self, cache_key: str, embedding: List[float]):
        """Store embedding in LRU memory cache and enforce memory limit."""
        if cache_key in self._embedding_cache:
            self._embedding_cache.move_to_end(cache_key)
        self._embedding_cache[cache_key] = embedding

        while len(self._embedding_cache) > self.max_memory_entries:
            self._embedding_cache.popitem(last=False)
            self._stats["memory_evictions"] += 1

    @staticmethod
    def _to_list(embedding: Any) -> List[float]:
        """Convert model output to list."""
        if hasattr(embedding, "tolist"):
            return embedding.tolist()
        if isinstance(embedding, list):
            return embedding
        return list(embedding)

    def _read_disk_cache(self, cache_key: str) -> Optional[List[float]]:
        """Load embedding from disk cache if available."""
        disk_cache_path = self._cache_file_path(cache_key)
        if not os.path.exists(disk_cache_path):
            return None
        try:
            with open(disk_cache_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, list):
                return data
        except Exception as e:
            logger.warning("Failed to load cached embedding: %s", e)
        return None

    def _write_disk_cache(self, cache_key: str, embedding: List[float]):
        """Persist embedding to disk cache."""
        disk_cache_path = self._cache_file_path(cache_key)
        tmp_path = f"{disk_cache_path}.tmp"
        try:
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(embedding, f)
            os.replace(tmp_path, disk_cache_path)
            self._stats["writes"] += 1
            self._writes_since_prune += 1
            self._maybe_prune_disk_cache()
        except Exception as e:
            logger.warning("Failed to cache embedding: %s", e)
            try:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
            except OSError:
                pass

    def _maybe_prune_disk_cache(self):
        """Prune disk cache periodically based on configured interval."""
        if self._writes_since_prune < self.prune_interval_writes:
            return
        self._writes_since_prune = 0
        self.prune_disk_cache()

    def _embed_single(self, text: str) -> List[float]:
        """Generate embedding for a single text string with caching."""
        cache_key = self._get_cache_key(text)
        if cache_key in self._embedding_cache:
            self._stats["memory_hits"] += 1
            self._embedding_cache.move_to_end(cache_key)
            return self._embedding_cache[cache_key]

        disk_cached = self._read_disk_cache(cache_key)
        if disk_cached is not None:
            self._stats["disk_hits"] += 1
            self._remember_memory(cache_key, disk_cached)
            return disk_cached

        self._stats["misses"] += 1
        embedding = self._to_list(self.model.encode(text, convert_to_tensor=False))
        self._remember_memory(cache_key, embedding)
        self._write_disk_cache(cache_key, embedding)
        return embedding

    def _embed_batch(self, texts: List[str]) -> List[List[float]]:
        """Generate embeddings for multiple texts efficiently."""
        results: List[Optional[List[float]]] = [None] * len(texts)
        uncached_texts: List[str] = []
        uncached_indices: List[int] = []
        uncached_keys: List[str] = []

        for i, text in enumerate(texts):
            cache_key = self._get_cache_key(text)
            if cache_key in self._embedding_cache:
                self._stats["memory_hits"] += 1
                self._embedding_cache.move_to_end(cache_key)
                results[i] = self._embedding_cache[cache_key]
                continue

            disk_cached = self._read_disk_cache(cache_key)
            if disk_cached is not None:
                self._stats["disk_hits"] += 1
                self._remember_memory(cache_key, disk_cached)
                results[i] = disk_cached
                continue

            self._stats["misses"] += 1
            uncached_texts.append(text)
            uncached_indices.append(i)
            uncached_keys.append(cache_key)

        if uncached_texts:
            embeddings = self.model.encode(
                uncached_texts, convert_to_tensor=False, show_progress_bar=False
            )
            for idx, cache_key, embedding in zip(uncached_indices, uncached_keys, embeddings):
                embedding_list = self._to_list(embedding)
                results[idx] = embedding_list
                self._remember_memory(cache_key, embedding_list)
                self._write_disk_cache(cache_key, embedding_list)

        return [emb if emb is not None else [] for emb in results]

    def _get_cache_key(self, text: str) -> str:
        """Generate a cache key for a text string."""
        return hashlib.md5(text.encode("utf-8")).hexdigest()

    def prune_disk_cache(
        self,
        max_files: Optional[int] = None,
        max_size_mb: Optional[int] = None,
        max_age_days: Optional[int] = None,
        dry_run: bool = False,
    ) -> Dict[str, int]:
        """
        Prune JSON embedding cache files by age/count/size.
        """
        target_max_files = max(1, int(max_files or self.max_disk_files))
        target_max_size = max(1, int(max_size_mb or self.max_disk_size_mb)) * 1024 * 1024
        target_max_age_days = int(max_age_days) if max_age_days is not None else None

        cache_files = sorted(
            Path(self.cache_dir).glob("*.json"),
            key=lambda p: p.stat().st_mtime if p.exists() else 0,
        )

        total_size = sum(p.stat().st_size for p in cache_files if p.exists())
        files_deleted = 0
        bytes_freed = 0

        def remove_file(path: Path):
            nonlocal files_deleted, bytes_freed
            try:
                size = path.stat().st_size
            except OSError:
                size = 0
            if not dry_run:
                try:
                    path.unlink(missing_ok=True)
                except OSError:
                    return
            files_deleted += 1
            bytes_freed += size

        # Remove files older than max_age_days first.
        if target_max_age_days is not None:
            cutoff_ts = (datetime.now().timestamp() - (target_max_age_days * 86400))
            for path in list(cache_files):
                try:
                    mtime = path.stat().st_mtime
                except OSError:
                    continue
                if mtime < cutoff_ts:
                    remove_file(path)
                    total_size -= path.stat().st_size if path.exists() else 0

        # Recompute candidates after age-based pruning.
        cache_files = sorted(
            Path(self.cache_dir).glob("*.json"),
            key=lambda p: p.stat().st_mtime if p.exists() else 0,
        )
        total_size = sum(p.stat().st_size for p in cache_files if p.exists())

        # Enforce file count.
        while len(cache_files) > target_max_files and cache_files:
            victim = cache_files.pop(0)
            try:
                total_size -= victim.stat().st_size
            except OSError:
                pass
            remove_file(victim)

        # Enforce total disk size.
        while total_size > target_max_size and cache_files:
            victim = cache_files.pop(0)
            try:
                total_size -= victim.stat().st_size
            except OSError:
                pass
            remove_file(victim)

        self._stats["prune_runs"] += 1
        self._stats["pruned_files"] += files_deleted
        self._stats["pruned_bytes"] += bytes_freed

        if files_deleted:
            logger.info(
                "Pruned embedding cache files=%d bytes=%d",
                files_deleted,
                bytes_freed,
            )

        return {"files_deleted": files_deleted, "bytes_freed": bytes_freed}

    def get_cache_stats(self) -> Dict[str, Any]:
        """Return cache telemetry for logging and diagnostics."""
        json_files = list(Path(self.cache_dir).glob("*.json"))
        disk_bytes = 0
        for path in json_files:
            try:
                disk_bytes += path.stat().st_size
            except OSError:
                continue
        return {
            "memory_entries": len(self._embedding_cache),
            "max_memory_entries": self.max_memory_entries,
            "disk_files": len(json_files),
            "max_disk_files": self.max_disk_files,
            "disk_bytes": disk_bytes,
            "max_disk_bytes": self.max_disk_size_mb * 1024 * 1024,
            **self._stats,
        }

    def embed_alert(self, alert: dict) -> List[float]:
        """
        Generate embedding for a Wazuh alert.
        """
        rule = alert.get("rule", {})
        data = alert.get("data", {})
        agent = alert.get("agent", {})

        parts = [
            rule.get("description", ""),
            f"Rule ID: {rule.get('id', 'unknown')}",
            f"Severity: {rule.get('level', 0)}",
        ]

        mitre = rule.get("mitre", {})
        if isinstance(mitre, dict) and mitre.get("id"):
            parts.append(f"MITRE: {mitre.get('id')}")

        if agent.get("name"):
            parts.append(f"Agent: {agent.get('name')}")

        for key in ["srcip", "dstip", "dstuser", "command", "program_name"]:
            if data.get(key):
                parts.append(f"{key}: {data[key]}")

        text = " | ".join(filter(None, parts))
        return self.embed(text)

    def embed_threat_intel(self, ioc: dict) -> List[float]:
        """
        Generate embedding for threat intelligence indicator.
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
        """
        parts = [
            playbook.get("title", ""),
            playbook.get("description", ""),
            f"Severity: {playbook.get('severity', '')}",
        ]
        mitre = playbook.get("mitre_techniques", [])
        if mitre:
            parts.append(f"MITRE: {', '.join(mitre)}")
        text = " | ".join(filter(None, parts))
        return self.embed(text)

    def similarity(self, embedding1: List[float], embedding2: List[float]) -> float:
        """
        Calculate cosine similarity between two embeddings.
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

    def clear_cache(self, clear_disk: bool = False):
        """Clear in-memory cache and optionally JSON disk cache."""
        self._embedding_cache.clear()
        if clear_disk:
            deleted = 0
            for path in Path(self.cache_dir).glob("*.json"):
                try:
                    path.unlink(missing_ok=True)
                    deleted += 1
                except OSError:
                    continue
            logger.info("Removed %d disk cache files", deleted)
        logger.info("Embedding cache cleared (clear_disk=%s)", clear_disk)


_embedding_service = None


def get_embedding_service(
    model_name: str = None,
    cache_dir: str = None,
    max_memory_entries: int = 5000,
    max_disk_files: int = 50000,
    max_disk_size_mb: int = 2048,
    prune_interval_writes: int = 200,
    reset: bool = False,
) -> EmbeddingService:
    """Get or create the singleton embedding service instance."""
    global _embedding_service
    if _embedding_service is None or reset:
        _embedding_service = EmbeddingService(
            model_name=model_name,
            cache_dir=cache_dir,
            max_memory_entries=max_memory_entries,
            max_disk_files=max_disk_files,
            max_disk_size_mb=max_disk_size_mb,
            prune_interval_writes=prune_interval_writes,
        )
    return _embedding_service


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    print("Testing Embedding Service...")
    service = EmbeddingService()
    print(f"Model dimension: {service.dimension}")

    text = "SSH brute force attack detected from IP 203.0.113.45"
    embedding = service.embed(text)
    print(f"Single embedding shape: {len(embedding)}")
    print(f"First 5 values: {embedding[:5]}")

    texts = [
        "SSH brute force attack detected",
        "PowerShell encoded command execution",
        "Sudo privilege escalation attempt",
    ]
    embeddings = service.embed(texts)
    print(f"Batch embeddings count: {len(embeddings)}")

    sim = service.similarity(embedding, embeddings[0])
    print(f"Similarity with first text: {sim:.4f}")

    test_alert = {
        "rule": {
            "id": "200001",
            "description": "SSH brute force attack detected",
            "level": 10,
            "mitre": {"id": ["T1110"]},
        },
        "agent": {"name": "linux-endpoint-01"},
        "data": {"srcip": "203.0.113.45", "dstuser": "root"},
    }
    alert_embedding = service.embed_alert(test_alert)
    print(f"Alert embedding shape: {len(alert_embedding)}")
    print("Cache stats:", service.get_cache_stats())
    print("\nEmbedding Service test completed successfully!")
