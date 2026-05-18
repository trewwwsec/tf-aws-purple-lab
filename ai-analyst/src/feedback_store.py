#!/usr/bin/env python3
"""Operator feedback capture for AI Analyst outputs."""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

VALID_RATINGS = {"useful", "wrong", "needs_review"}


class FeedbackValidationError(ValueError):
    """Raised when feedback payloads are invalid."""


class FeedbackStore:
    """Append-only JSONL feedback store with alert-id lookup."""

    def __init__(self, path: Optional[str] = None):
        self.path = Path(
            os.path.expanduser(path or "~/.cache/ai-analyst/feedback.jsonl")
        )

    def validate(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Validate and normalize a feedback payload."""
        alert_id = str(payload.get("alert_id", "")).strip()
        rating = str(payload.get("rating", "")).strip().lower()
        if not alert_id:
            raise FeedbackValidationError("alert_id is required")
        if rating not in VALID_RATINGS:
            raise FeedbackValidationError(
                f"rating must be one of: {', '.join(sorted(VALID_RATINGS))}"
            )

        entry = {
            "alert_id": alert_id,
            "rating": rating,
            "analysis_id": str(payload.get("analysis_id", "")).strip() or None,
            "correction": str(payload.get("correction", "")).strip() or None,
            "operator": str(payload.get("operator", "")).strip() or "unknown",
            "source": str(payload.get("source", "")).strip() or "api",
            "created_at": datetime.now().isoformat(),
        }
        return entry

    def add(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Persist a validated feedback entry."""
        entry = self.validate(payload)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, sort_keys=True) + "\n")
        return entry

    def list_for_alert(self, alert_id: str) -> List[Dict[str, Any]]:
        """Return feedback entries for a single alert ID."""
        target = str(alert_id).strip()
        if not target or not self.path.exists():
            return []

        entries: List[Dict[str, Any]] = []
        with self.path.open("r", encoding="utf-8") as f:
            for line in f:
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(entry, dict) and entry.get("alert_id") == target:
                    entries.append(entry)
        return entries
