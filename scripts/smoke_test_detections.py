#!/usr/bin/env python3
"""
Smoke-test expected Wazuh detections after running an attack simulation.

Supports:
- API polling via ai-analyst/src/wazuh_client.py
- Remote alert log streaming over SSH

Examples:
  python3 scripts/smoke_test_detections.py --simulation ssh-brute-force --mode api
  python3 scripts/smoke_test_detections.py --simulation privilege-escalation --mode ssh-log --ssh-target ubuntu@10.0.1.100
  python3 scripts/smoke_test_detections.py --rule-id 200001 --rule-id 200021 --mode ssh-log --ssh-target ubuntu@10.0.1.100
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "ai-analyst" / "src"))

try:
    from wazuh_client import WazuhClient
except Exception:  # pragma: no cover - import is validated by runtime use
    WazuhClient = None


SIMULATION_RULES = {
    "ssh-brute-force": ["200001", "200002", "200003"],
    "privilege-escalation": ["200020", "200021", "200022", "200032"],
    "powershell-attacks": ["200010", "200011", "200012", "200013", "200014"],
    "apt-credential-harvest": ["200052", "200070", "200220", "200221", "200222", "200223", "200224"],
    "apt-lateral-movement": ["200052"],
    "apt-c2-exfil": ["200100", "200101", "200103", "200261"],
    "macos-attacks": [
        "200200",
        "200202",
        "200210",
        "200211",
        "200212",
        "200220",
        "200221",
        "200222",
        "200223",
        "200224",
        "200230",
        "200231",
        "200234",
        "200240",
        "200241",
        "200242",
        "200243",
        "200250",
        "200251",
        "200252",
        "200260",
        "200261",
    ],
}

RULE_LINE_RE = re.compile(r"Rule:\s*(200\d{3})\b")
TIMESTAMP_FORMATS = (
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%SZ",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Smoke-test expected Wazuh detections")
    parser.add_argument(
        "--mode",
        choices=["api", "ssh-log"],
        help="Validation mode: query Wazuh API or stream alerts.log over SSH",
    )
    parser.add_argument(
        "--simulation",
        choices=sorted(SIMULATION_RULES.keys()),
        help="Known simulation name to expand into expected rule IDs",
    )
    parser.add_argument(
        "--rule-id",
        action="append",
        default=[],
        help="Expected custom rule ID (repeatable)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=180,
        help="Seconds to wait for all expected alerts (default: 180)",
    )
    parser.add_argument(
        "--poll-interval",
        type=int,
        default=5,
        help="Polling interval for API mode in seconds (default: 5)",
    )
    parser.add_argument(
        "--fresh-window-seconds",
        type=int,
        default=900,
        help="Alert freshness window for API mode (default: 900)",
    )
    parser.add_argument(
        "--ssh-target",
        default=os.environ.get("WAZUH_SERVER", ""),
        help="SSH target for ssh-log mode, e.g. ubuntu@10.0.1.100",
    )
    parser.add_argument(
        "--ssh-key",
        default=os.environ.get("WAZUH_SSH_KEY", ""),
        help="Optional SSH private key path for ssh-log mode",
    )
    parser.add_argument(
        "--list-simulations",
        action="store_true",
        help="List known simulation names and exit",
    )
    return parser.parse_args()


def resolve_expected_rule_ids(args: argparse.Namespace) -> list[str]:
    expected = list(args.rule_id)
    if args.simulation:
        expected.extend(SIMULATION_RULES[args.simulation])
    expected = sorted(set(expected))
    if not expected:
        raise SystemExit("Provide --simulation or at least one --rule-id.")
    invalid = [rule_id for rule_id in expected if not re.fullmatch(r"200\d{3}", rule_id)]
    if invalid:
        raise SystemExit(f"Invalid custom rule IDs: {', '.join(invalid)}")
    return expected


def parse_alert_timestamp(raw: str | None) -> datetime | None:
    if not raw:
        return None
    for fmt in TIMESTAMP_FORMATS:
        try:
            parsed = datetime.strptime(raw, fmt)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
        except ValueError:
            continue
    return None


def print_status(found: set[str], expected: Iterable[str]) -> None:
    ordered_expected = list(expected)
    pending = [rule_id for rule_id in ordered_expected if rule_id not in found]
    print(f"Found: {', '.join(sorted(found)) if found else 'none'}")
    print(f"Pending: {', '.join(pending) if pending else 'none'}")


def run_api_mode(args: argparse.Namespace, expected: list[str]) -> int:
    if WazuhClient is None:
        print("Unable to import WazuhClient for API mode.", file=sys.stderr)
        return 1

    freshness_cutoff = datetime.now(timezone.utc) - timedelta(seconds=args.fresh_window_seconds)
    client = WazuhClient(runtime_mode="strict")
    found: set[str] = set()
    deadline = time.time() + args.timeout

    print(f"Polling Wazuh API for rules: {', '.join(expected)}")
    print(f"Freshness cutoff: {freshness_cutoff.isoformat()}")

    while time.time() < deadline:
        for rule_id in expected:
            if rule_id in found:
                continue
            alerts = client.get_alerts(limit=10, rule_id=rule_id)
            for alert in alerts:
                timestamp = parse_alert_timestamp(alert.get("timestamp"))
                if timestamp and timestamp >= freshness_cutoff:
                    found.add(rule_id)
                    print(f"Matched rule {rule_id} via Wazuh API at {alert.get('timestamp')}")
                    break
        if found == set(expected):
            print("Smoke test passed.")
            return 0
        print_status(found, expected)
        time.sleep(args.poll_interval)

    print("Smoke test failed: timed out waiting for expected alerts.", file=sys.stderr)
    print_status(found, expected)
    return 1


def build_ssh_command(args: argparse.Namespace, rule_ids: list[str]) -> list[str]:
    remote_pattern = "|".join(f"Rule: {rule_id}" for rule_id in rule_ids)
    remote_cmd = (
        f"sudo timeout {int(args.timeout)} sh -c "
        f"\"tail -Fn0 /var/ossec/logs/alerts/alerts.log | grep --line-buffered -E '{remote_pattern}'\""
    )
    command = ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10"]
    if args.ssh_key:
        command.extend(["-i", os.path.expanduser(args.ssh_key)])
    command.append(args.ssh_target)
    command.append(remote_cmd)
    return command


def run_ssh_log_mode(args: argparse.Namespace, expected: list[str]) -> int:
    if not args.ssh_target:
        print("ssh-log mode requires --ssh-target or WAZUH_SERVER.", file=sys.stderr)
        return 1

    command = build_ssh_command(args, expected)
    print(f"Streaming remote alerts.log from {args.ssh_target} for rules: {', '.join(expected)}")
    found: set[str] = set()

    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    try:
        assert process.stdout is not None
        for line in process.stdout:
            sys.stdout.write(line)
            match = RULE_LINE_RE.search(line)
            if not match:
                continue
            rule_id = match.group(1)
            if rule_id in expected and rule_id not in found:
                found.add(rule_id)
                print(f"Matched rule {rule_id} via alerts.log stream")
            if found == set(expected):
                process.terminate()
                print("Smoke test passed.")
                return 0
    finally:
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()

    print("Smoke test failed: timed out waiting for expected alerts.", file=sys.stderr)
    print_status(found, expected)
    return 1


def main() -> int:
    args = parse_args()
    if args.list_simulations:
        for name, rule_ids in sorted(SIMULATION_RULES.items()):
            print(f"{name}: {', '.join(rule_ids)}")
        return 0
    if not args.mode:
        raise SystemExit("--mode is required unless --list-simulations is used.")

    expected = resolve_expected_rule_ids(args)
    if args.mode == "api":
        return run_api_mode(args, expected)
    return run_ssh_log_mode(args, expected)


if __name__ == "__main__":
    sys.exit(main())
