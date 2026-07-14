#!/usr/bin/env python3
"""
Validate active detection workflow references.

Checks:
1. Stale 100xxx rule namespace references do not appear in active workflow files.
2. Referenced 200xxx rule IDs resolve to actual custom Wazuh rules shipped in repo.

This intentionally scopes checks to runnable/testable project paths and ignores
historical roadmap notes or unrelated numeric literals elsewhere in the repo.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent

SCAN_FILES = [
    ROOT / "detections" / "test-detections.sh",
    ROOT / "attack-simulation" / "ssh-brute-force.sh",
    ROOT / "attack-simulation" / "privilege-escalation.sh",
    ROOT / "attack-simulation" / "powershell-attacks.ps1",
    ROOT / "attack-simulation" / "macos-attacks.sh",
    ROOT / "attack-simulation" / "run-all-linux.sh",
    ROOT / "attack-simulation" / "apt-credential-harvest.sh",
    ROOT / "attack-simulation" / "apt-lateral-movement.sh",
    ROOT / "attack-simulation" / "apt-c2-exfil.sh",
    ROOT / "ai-analyst" / "examples" / "sample_alert.json",
    ROOT / "ai-analyst" / "prompts" / "analyze_alert.txt",
    ROOT / "ai-analyst" / "src" / "alert_enricher.py",
    ROOT / "ai-analyst" / "src" / "baseline_engine.py",
    ROOT / "scripts" / "smoke_test_detections.py",
    ROOT / "scripts" / "run_detection_smoke_test.sh",
    ROOT / "scripts" / "run_end_to_end_detection_test.sh",
]

OLD_NAMESPACE_PATTERNS = [
    re.compile(r"\b100\d{3}\b"),
    re.compile(r"\b100xxx\b"),
    re.compile(r"Rule:\s*100\b"),
    re.compile(r"Rule\s+100\d{3}\b"),
    re.compile(r"\b100\*\b"),
]

LINE_ALLOWLIST = [
    "100000 + 50000",  # numeric salary generation in a demo artifact, not a rule ID
]

VALID_RULE_FILES = [
    ROOT / "wazuh" / "custom_rules" / "local_rules.xml",
    ROOT / "wazuh" / "custom_rules" / "macos_rules.xml",
]

RULE_ID_PATTERN = re.compile(r"\b(200\d{3})\b")
RULE_XML_PATTERN = re.compile(r'<rule id="(200\d{3})"')


def load_valid_rule_ids() -> set[str]:
    valid_rule_ids: set[str] = set()
    for path in VALID_RULE_FILES:
        if not path.exists():
            raise FileNotFoundError(f"missing rule definition file: {path.relative_to(ROOT)}")
        valid_rule_ids.update(RULE_XML_PATTERN.findall(path.read_text(encoding="utf-8")))
    return valid_rule_ids


def main() -> int:
    violations: list[str] = []
    valid_rule_ids = load_valid_rule_ids()

    for path in SCAN_FILES:
        if not path.exists():
            violations.append(f"missing validation target: {path.relative_to(ROOT)}")
            continue

        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if any(token in line for token in LINE_ALLOWLIST):
                continue
            if any(pattern.search(line) for pattern in OLD_NAMESPACE_PATTERNS):
                violations.append(f"{path.relative_to(ROOT)}:{lineno}: {line.strip()}")
            for rule_id in RULE_ID_PATTERN.findall(line):
                if rule_id not in valid_rule_ids:
                    violations.append(
                        f"{path.relative_to(ROOT)}:{lineno}: unknown custom rule reference {rule_id}"
                    )

    if violations:
        print("Rule reference validation failed:")
        for violation in violations:
            print(f" - {violation}")
        return 1

    print(
        "Rule reference validation passed "
        f"({len(valid_rule_ids)} custom rules available)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
