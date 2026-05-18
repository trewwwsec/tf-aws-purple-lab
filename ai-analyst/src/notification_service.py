#!/usr/bin/env python3
"""Notification delivery for completed AI Analyst findings."""

import json
import logging
import os
from typing import Any, Dict, Optional
from urllib import request
from urllib.error import URLError

logger = logging.getLogger(__name__)


class NotificationService:
    """Best-effort webhook notifier for analysis results."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        cfg = config or {}
        self.enabled = bool(cfg.get("enabled", False))
        self.webhook_url = str(
            cfg.get("webhook_url") or os.environ.get(cfg.get("webhook_url_env", "AI_ANALYST_WEBHOOK_URL"), "")
        ).strip()
        self.timeout_seconds = float(cfg.get("timeout_seconds", 5))

    def build_payload(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Build a structured notification payload from analysis output."""
        metadata = analysis.get("analysis_metadata", {})
        return {
            "alert_title": analysis.get("alert_title"),
            "rule_id": analysis.get("rule_id"),
            "severity": analysis.get("severity"),
            "severity_label": analysis.get("severity_label"),
            "summary": analysis.get("summary"),
            "agent": analysis.get("agent"),
            "source_ip": analysis.get("source_ip"),
            "playbook": analysis.get("playbook"),
            "playbook_path": analysis.get("playbook_path"),
            "analysis_method": metadata.get("analysis_method"),
            "provider": metadata.get("provider"),
            "fallback_used": metadata.get("fallback_used"),
        }

    def send(self, analysis: Dict[str, Any]) -> bool:
        """Send the notification. Failures are logged and returned as False."""
        if not self.enabled:
            return False
        if not self.webhook_url:
            logger.warning("Notification enabled but webhook URL is not configured")
            return False

        body = json.dumps(self.build_payload(analysis), default=str).encode("utf-8")
        req = request.Request(
            self.webhook_url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with request.urlopen(req, timeout=self.timeout_seconds) as response:
                status = getattr(response, "status", 200)
                if 200 <= int(status) < 300:
                    return True
                logger.warning("Notification webhook returned status %s", status)
        except (OSError, URLError, ValueError) as e:
            logger.warning("Notification webhook delivery failed: %s", e)
        return False
