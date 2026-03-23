#!/usr/bin/env python3
"""Validation tests for alert-to-playbook mapping integrity."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from analyze_alert import PLAYBOOK_BASE, PLAYBOOK_DEFAULT, load_playbook_mapping


class PlaybookMappingTests(unittest.TestCase):
    def test_rule_ids_use_200_namespace(self):
        mapping = load_playbook_mapping()
        self.assertTrue(mapping, "playbook mapping should not be empty")
        for rule_id in mapping:
            self.assertTrue(
                str(rule_id).startswith("200"),
                f"rule ID {rule_id} is outside expected 200xxx namespace",
            )

    def test_all_mapped_playbooks_exist(self):
        mapping = load_playbook_mapping()
        for playbook in mapping.values():
            path = os.path.join(PLAYBOOK_BASE, playbook)
            self.assertTrue(os.path.exists(path), f"missing playbook file: {path}")

    def test_default_playbook_exists(self):
        path = os.path.join(PLAYBOOK_BASE, PLAYBOOK_DEFAULT)
        self.assertTrue(os.path.exists(path), f"missing default playbook: {path}")


if __name__ == "__main__":
    unittest.main()
