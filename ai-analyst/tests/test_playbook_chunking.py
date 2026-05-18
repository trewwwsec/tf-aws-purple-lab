#!/usr/bin/env python3
"""Tests for markdown playbook chunking and chunk prompt formatting."""

import os
import sys
import types
import unittest
from typing import Any

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

# Provide lightweight stub for environments without opensearchpy installed.
if "opensearchpy" not in sys.modules:
    stub: Any = types.ModuleType("opensearchpy")

    class _OpenSearchStub:
        pass

    stub.OpenSearch = _OpenSearchStub
    stub.helpers = types.SimpleNamespace()
    sys.modules["opensearchpy"] = stub

from playbook_chunker import chunk_markdown_playbook
from rag_retriever import RAGContext


class TestPlaybookChunking(unittest.TestCase):
    def test_chunks_markdown_by_heading_with_stable_metadata(self):
        chunks = chunk_markdown_playbook(
            "# Overview\nIntro\n\n## Investigate\nStep 1\n\n## Contain\nStep 2",
            playbook_id="IR-PB-001",
            title="SSH Brute Force Response",
            file_path="/tmp/ssh-brute-force.md",
            severity="high",
            mitre_techniques=["T1110"],
        )

        self.assertEqual([chunk.heading for chunk in chunks], ["Overview", "Investigate", "Contain"])
        self.assertTrue(all(chunk.chunk_id.startswith("IR-PB-001::chunk-") for chunk in chunks))
        self.assertEqual(chunks[1].to_document()["content"]["chunk_text"], "## Investigate\nStep 1")
        self.assertEqual(chunks[1].to_document()["mitre_techniques"], ["T1110"])

    def test_oversized_section_splits_without_dropping_text(self):
        body = "# Long\n" + "alpha " * 120
        chunks = chunk_markdown_playbook(
            body,
            playbook_id="IR-PB-002",
            title="Credential Dumping Response",
            file_path="/tmp/credential-dumping.md",
            severity="critical",
            max_chars=120,
        )

        self.assertGreater(len(chunks), 1)
        combined = " ".join(chunk.text for chunk in chunks)
        self.assertIn("alpha", combined)
        self.assertGreaterEqual(combined.count("alpha"), 100)

    def test_prompt_context_includes_chunk_guidance_and_parent_metadata(self):
        context = RAGContext(
            relevant_playbooks=[
                {
                    "playbook_id": "IR-PB-001",
                    "chunk_id": "IR-PB-001::chunk-002",
                    "title": "SSH Brute Force Response",
                    "heading": "Containment",
                    "severity": "high",
                    "mitre_techniques": ["T1110"],
                    "similarity_score": 0.91,
                    "content": {"chunk_text": "Disable exposed SSH and block the source IP."},
                }
            ]
        )

        prompt = context.to_prompt_context()

        self.assertIn("SSH Brute Force Response", prompt)
        self.assertIn("Section: Containment", prompt)
        self.assertIn("Disable exposed SSH", prompt)


if __name__ == "__main__":
    unittest.main()
