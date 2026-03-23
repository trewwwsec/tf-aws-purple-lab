#!/usr/bin/env python3
"""Security-focused tests for VectorStore OpenSearch client wiring."""

import logging
import os
import sys
import types
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


class _OpenSearchRecorder:
    last_kwargs = None

    def __init__(self, **kwargs):
        _OpenSearchRecorder.last_kwargs = kwargs

    def info(self):
        return {"version": {"number": "2.0.0"}}


if "opensearchpy" not in sys.modules:
    stub = types.ModuleType("opensearchpy")
    stub.OpenSearch = _OpenSearchRecorder
    stub.helpers = types.SimpleNamespace()
    sys.modules["opensearchpy"] = stub

import vector_store

VectorStore = vector_store.VectorStore


class TestVectorStoreSecurity(unittest.TestCase):
    def test_ssl_warning_enabled_when_verify_certs_disabled(self):
        _OpenSearchRecorder.last_kwargs = None
        logger_name = "vector_store"
        with patch.object(vector_store, "OpenSearch", _OpenSearchRecorder):
            with self.assertLogs(logger_name, level=logging.WARNING) as captured:
                VectorStore(
                    hosts=["localhost:9200"],
                    username="u",
                    password="p",
                    use_ssl=True,
                    verify_certs=False,
                )

        kwargs = _OpenSearchRecorder.last_kwargs
        self.assertIsNotNone(kwargs)
        self.assertTrue(kwargs.get("ssl_show_warn"))
        self.assertTrue(any("verify_certs=false" in line for line in captured.output))

    def test_ssl_warning_disabled_when_verify_certs_enabled(self):
        _OpenSearchRecorder.last_kwargs = None
        with patch.object(vector_store, "OpenSearch", _OpenSearchRecorder):
            VectorStore(
                hosts=["localhost:9200"],
                username="u",
                password="p",
                use_ssl=True,
                verify_certs=True,
            )
        kwargs = _OpenSearchRecorder.last_kwargs
        self.assertIsNotNone(kwargs)
        self.assertFalse(kwargs.get("ssl_show_warn"))


if __name__ == "__main__":
    unittest.main()
