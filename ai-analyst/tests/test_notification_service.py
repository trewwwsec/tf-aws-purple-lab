#!/usr/bin/env python3
"""Tests for best-effort analysis notifications."""

import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from notification_service import NotificationService


class _Response:
    status = 204

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class TestNotificationService(unittest.TestCase):
    def test_disabled_notifier_is_noop(self):
        service = NotificationService({"enabled": False})
        self.assertFalse(service.send({"alert_title": "Test"}))

    def test_enabled_notifier_sends_payload(self):
        service = NotificationService(
            {"enabled": True, "webhook_url": "https://example.test/hook"}
        )
        with patch("notification_service.request.urlopen", return_value=_Response()) as mocked:
            sent = service.send(
                {
                    "alert_title": "SSH brute force",
                    "rule_id": "200001",
                    "severity": 10,
                    "severity_label": "High",
                    "summary": "Repeated failures",
                    "playbook": "ssh-brute-force.md",
                    "analysis_metadata": {"analysis_method": "mock", "provider": "mock"},
                }
            )

        self.assertTrue(sent)
        req = mocked.call_args.args[0]
        self.assertEqual(req.get_method(), "POST")
        self.assertIn(b"SSH brute force", req.data)

    def test_delivery_error_is_non_fatal(self):
        service = NotificationService(
            {"enabled": True, "webhook_url": "https://example.test/hook"}
        )
        with patch("notification_service.request.urlopen", side_effect=OSError("boom")):
            self.assertFalse(service.send({"alert_title": "Test"}))


if __name__ == "__main__":
    unittest.main()
