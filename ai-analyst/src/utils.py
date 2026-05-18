#!/usr/bin/env python3
"""
Shared utilities for AI Analyst module.
Provides common functions for alert processing, field extraction, and formatting.
"""

import json
import logging
from typing import Dict, Any, Optional


def setup_logging(level: int = logging.INFO) -> logging.Logger:
    """Setup logging configuration for the AI Analyst module."""
    logging.basicConfig(
        level=level, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    return logging.getLogger("ai_analyst")


def generate_mock_response(prompt: str = "") -> str:
    """
    Generate a standardized mock response for LLM clients when APIs are unavailable.

    Args:
        prompt: The input prompt (unused, kept for interface compatibility)

    Returns:
        JSON string with mock analysis response
    """
    return json.dumps(
        {
            "title": "Security Alert Detected",
            "summary": "A security event was detected that requires investigation.",
            "investigation_steps": [
                "Review the alert details",
                "Check related events",
                "Assess potential impact",
            ],
            "recommended_actions": [
                "[IMMEDIATE] Investigate the alert",
                "[SHORT-TERM] Review security controls",
                "[LONG-TERM] Update detection rules",
            ],
        }
    )


def extract_alert_fields(alert: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract common fields from a Wazuh alert dictionary.

    Args:
        alert: The raw Wazuh alert dictionary

    Returns:
        Dictionary with extracted fields
    """
    data = alert.get("data", {})
    return {
        "rule_id": alert.get("rule", {}).get("id", "unknown"),
        "rule_description": alert.get("rule", {}).get("description", "Unknown alert"),
        "severity": alert.get("rule", {}).get("level", 0),
        "agent_name": alert.get("agent", {}).get("name", "unknown"),
        "src_ip": data.get("srcip") or data.get("src_ip"),
        "user": data.get("dstuser") or data.get("user"),
        "timestamp": alert.get("timestamp", ""),
    }


def is_wazuh_alert(payload: Any) -> bool:
    """
    Return True when the payload looks like a Wazuh alert object.

    The shape intentionally stays conservative so wrapper objects are not
    mistaken for alerts.
    """
    if not isinstance(payload, dict):
        return False

    rule = payload.get("rule")
    if not isinstance(rule, dict):
        return False

    return any(key in rule for key in ("id", "description", "level"))


def normalize_alert_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract the actual Wazuh alert from a raw alert or supported wrapper.

    Supported shapes:
    - raw alert object
    - {"alert": {...}}
    - {"parameters": {"alert": {...}}}
    """
    if not isinstance(payload, dict):
        raise ValueError("alert payload must be a JSON object")

    if is_wazuh_alert(payload):
        return payload

    direct_alert = payload.get("alert")
    if isinstance(direct_alert, dict):
        return normalize_alert_payload(direct_alert)

    parameters = payload.get("parameters")
    if isinstance(parameters, dict):
        nested_alert = parameters.get("alert")
        if isinstance(nested_alert, dict):
            return normalize_alert_payload(nested_alert)

    raise ValueError(
        "json payload must be a raw alert object or contain one at alert / parameters.alert"
    )


def get_severity_label(severity: int) -> str:
    """
    Convert a severity level to a human-readable label.

    Args:
        severity: The severity level (typically 0-15)

    Returns:
        Severity label: CRITICAL, HIGH, MEDIUM, or LOW
    """
    if severity >= 12:
        return "CRITICAL"
    elif severity >= 10:
        return "HIGH"
    elif severity >= 7:
        return "MEDIUM"
    else:
        return "LOW"


def get_severity_color(severity: int) -> str:
    """
    Get ANSI color code for a severity level.

    Args:
        severity: The severity level

    Returns:
        ANSI color code string
    """
    if severity >= 10:
        return "\033[91m"  # Red
    elif severity >= 7:
        return "\033[93m"  # Yellow
    else:
        return "\033[92m"  # Green


def extract_json_from_markdown(response: str) -> Optional[str]:
    """
    Extract JSON content from markdown code blocks.

    Args:
        response: Response string that may contain markdown code blocks

    Returns:
        Extracted JSON string or None if extraction fails
    """
    try:
        if "```json" in response:
            return response.split("```json")[1].split("```")[0]
        elif "```" in response:
            return response.split("```")[1].split("```")[0]
        return response
    except (IndexError, AttributeError):
        return None


def parse_json_response(response: str) -> Optional[Dict[str, Any]]:
    """
    Safely parse a JSON response, handling markdown code blocks.

    Args:
        response: JSON string, possibly wrapped in markdown

    Returns:
        Parsed dictionary or None if parsing fails
    """
    try:
        json_str = extract_json_from_markdown(response)
        if json_str:
            return json.loads(json_str.strip())
    except (json.JSONDecodeError, AttributeError):
        pass
    return None


# Convenience alias for backward compatibility
def get_severity_level(severity: int) -> str:
    """Alias for get_severity_label."""
    return get_severity_label(severity)
