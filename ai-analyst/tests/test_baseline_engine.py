#!/usr/bin/env python3
"""Regression tests for baseline engine normalization and anomaly checks."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from baseline_engine import BaselineEngine


class TestBaselineEngine(unittest.TestCase):
    def test_build_from_events_accepts_alt_ip_field_names(self):
        engine = BaselineEngine()
        engine.build_from_events(
            [
                {
                    "timestamp": "2026-04-01T12:00:00Z",
                    "rule": {"description": "Network connection", "groups": []},
                    "agent": {"id": "001", "name": "host-1"},
                    "data": {"src_ip": "10.0.0.8", "dst_ip": "8.8.8.8", "srcuser": "alice"},
                }
            ]
        )

        baseline = engine.baselines["001"]
        self.assertIn("10.0.0.8", baseline.known_source_ips)
        self.assertIn("8.8.8.8", baseline.known_dest_ips)
        self.assertIn("alice", baseline.known_users)

    def test_check_events_handles_zulu_timestamps_and_new_ips(self):
        engine = BaselineEngine(z_score_threshold=2.5)
        engine.build_from_events(
            [
                {
                    "timestamp": "2026-04-01T10:00:00Z",
                    "rule": {"description": "Successful login", "groups": ["authentication_success"]},
                    "agent": {"id": "001", "name": "host-1"},
                    "data": {"srcip": "10.0.0.1", "srcuser": "alice"},
                },
                {
                    "timestamp": "2026-04-01T11:00:00Z",
                    "rule": {"description": "Successful login", "groups": ["authentication_success"]},
                    "agent": {"id": "001", "name": "host-1"},
                    "data": {"srcip": "10.0.0.1", "srcuser": "alice"},
                },
            ]
        )

        deviations = engine.check_events(
            [
                {
                    "timestamp": "2026-04-01T12:00:00Z",
                    "rule": {"description": "Successful login", "groups": ["authentication_success"]},
                    "agent": {"id": "001", "name": "host-1"},
                    "data": {"src_ip": "203.0.113.10", "srcuser": "alice"},
                }
            ]
        )

        self.assertTrue(any(d["subcategory"] == "new_source_ip" for d in deviations))

    def test_check_events_reports_new_sudo_command(self):
        engine = BaselineEngine(z_score_threshold=2.5)
        engine.build_from_events(
            [
                {
                    "timestamp": "2026-04-01T10:00:00Z",
                    "rule": {
                        "description": "Sudo command executed",
                        "groups": ["privilege_escalation"],
                    },
                    "agent": {"id": "001", "name": "host-1"},
                    "data": {"command": "/usr/bin/id", "srcuser": "alice"},
                }
            ]
        )

        deviations = engine.check_events(
            [
                {
                    "timestamp": "2026-04-01T12:00:00Z",
                    "rule": {
                        "description": "Sudo command executed",
                        "groups": ["privilege_escalation"],
                    },
                    "agent": {"id": "001", "name": "host-1"},
                    "data": {"command": "/usr/bin/cat /etc/shadow", "srcuser": "alice"},
                }
            ]
        )

        self.assertTrue(any(d["subcategory"] == "new_sudo_command" for d in deviations))


if __name__ == "__main__":
    unittest.main()
