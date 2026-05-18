#!/usr/bin/env python3
"""Markdown playbook chunking utilities for RAG indexing."""

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class PlaybookChunk:
    """A deterministic section-level playbook chunk."""

    chunk_id: str
    playbook_id: str
    title: str
    heading: str
    ordinal: int
    text: str
    file_path: str
    severity: str
    mitre_techniques: List[str]

    def to_document(self) -> Dict[str, Any]:
        """Return the chunk as the playbook document shape used by indexing."""
        return {
            "playbook_id": self.playbook_id,
            "chunk_id": self.chunk_id,
            "title": self.title,
            "heading": self.heading,
            "description": self.text[:500],
            "severity": self.severity,
            "mitre_techniques": self.mitre_techniques,
            "file_path": self.file_path,
            "content": {"chunk_text": self.text},
        }


def _stable_chunk_id(playbook_id: str, file_path: str, heading: str, ordinal: int) -> str:
    basis = f"{playbook_id}|{Path(file_path).name}|{heading}|{ordinal}"
    digest = hashlib.sha1(basis.encode("utf-8")).hexdigest()[:12]
    return f"{playbook_id}::chunk-{ordinal:03d}-{digest}"


def _split_long_text(text: str, max_chars: int) -> List[str]:
    """Split oversized text into bounded chunks without dropping content."""
    if len(text) <= max_chars:
        return [text]

    chunks: List[str] = []
    remaining = text.strip()
    while len(remaining) > max_chars:
        split_at = remaining.rfind("\n\n", 0, max_chars)
        if split_at < max_chars // 2:
            split_at = remaining.rfind("\n", 0, max_chars)
        if split_at < max_chars // 2:
            split_at = remaining.rfind(" ", 0, max_chars)
        if split_at < max_chars // 2:
            split_at = max_chars
        chunks.append(remaining[:split_at].strip())
        remaining = remaining[split_at:].strip()
    if remaining:
        chunks.append(remaining)
    return [chunk for chunk in chunks if chunk]


def chunk_markdown_playbook(
    content: str,
    *,
    playbook_id: str,
    title: str,
    file_path: str,
    severity: str,
    mitre_techniques: Optional[List[str]] = None,
    max_chars: int = 1800,
) -> List[PlaybookChunk]:
    """Chunk a markdown playbook by headings with a long-section fallback splitter."""
    sections: List[tuple[str, List[str]]] = []
    current_heading = title
    current_lines: List[str] = []

    for line in content.splitlines():
        match = re.match(r"^(#{1,6})\s+(.+?)\s*$", line)
        if match and current_lines:
            sections.append((current_heading, current_lines))
            current_heading = match.group(2).strip()
            current_lines = [line]
        else:
            if match:
                current_heading = match.group(2).strip()
            current_lines.append(line)

    if current_lines:
        sections.append((current_heading, current_lines))

    if not sections and content.strip():
        sections = [(title, [content])]

    chunks: List[PlaybookChunk] = []
    techniques = mitre_techniques or []
    ordinal = 1
    for heading, lines in sections:
        section_text = "\n".join(lines).strip()
        if not section_text:
            continue
        for part in _split_long_text(section_text, max_chars=max_chars):
            chunks.append(
                PlaybookChunk(
                    chunk_id=_stable_chunk_id(playbook_id, file_path, heading, ordinal),
                    playbook_id=playbook_id,
                    title=title,
                    heading=heading,
                    ordinal=ordinal,
                    text=part,
                    file_path=file_path,
                    severity=severity,
                    mitre_techniques=techniques,
                )
            )
            ordinal += 1

    return chunks
