#!/usr/bin/env python3
"""Tests for embedding cache read/write, bounds, and pruning."""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from embedding_service import EmbeddingService


class _DummyModel:
    def get_sentence_embedding_dimension(self):
        return 3

    def encode(self, text, convert_to_tensor=False, show_progress_bar=False):
        if isinstance(text, list):
            return [[float(len(t)), 1.0, 2.0] for t in text]
        return [float(len(text)), 1.0, 2.0]


class TestEmbeddingCache(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.service = EmbeddingService(
            model_name="dummy",
            cache_dir=self.tmpdir.name,
            max_memory_entries=2,
            max_disk_files=100,
            max_disk_size_mb=10,
            prune_interval_writes=1000,
        )
        self.service._model = _DummyModel()

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_single_embed_disk_and_memory_cache(self):
        first = self.service.embed("alpha")
        second = self.service.embed("alpha")

        self.assertEqual(first, second)
        stats = self.service.get_cache_stats()
        self.assertGreaterEqual(stats["writes"], 1)
        self.assertGreaterEqual(stats["memory_hits"], 1)

        # Force memory miss and verify disk hit path.
        self.service._embedding_cache.clear()
        third = self.service.embed("alpha")
        self.assertEqual(first, third)
        stats = self.service.get_cache_stats()
        self.assertGreaterEqual(stats["disk_hits"], 1)

    def test_batch_embed_uses_disk_cache(self):
        self.service.embed("one")
        self.service.embed("two")
        self.service._embedding_cache.clear()

        result = self.service.embed(["one", "two", "three"])
        self.assertEqual(len(result), 3)

        stats = self.service.get_cache_stats()
        # "one" and "two" should hit disk after memory clear.
        self.assertGreaterEqual(stats["disk_hits"], 2)
        self.assertGreaterEqual(stats["misses"], 1)

    def test_memory_cache_eviction_bound(self):
        self.service.embed("a")
        self.service.embed("bb")
        self.service.embed("ccc")

        stats = self.service.get_cache_stats()
        self.assertLessEqual(stats["memory_entries"], 2)
        self.assertGreaterEqual(stats["memory_evictions"], 1)

    def test_prune_disk_cache_by_file_count(self):
        for i in range(6):
            self.service.embed(f"prune-{i}")

        before = self.service.get_cache_stats()["disk_files"]
        self.assertGreaterEqual(before, 6)

        result = self.service.prune_disk_cache(max_files=2)
        after = self.service.get_cache_stats()["disk_files"]

        self.assertLessEqual(after, 2)
        self.assertGreaterEqual(result["files_deleted"], 4)


if __name__ == "__main__":
    unittest.main()
