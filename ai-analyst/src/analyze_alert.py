#!/usr/bin/env python3
"""
AI-Powered Alert Analyzer
Analyzes Wazuh alerts using LLMs to provide context, summaries, and recommendations.
"""

import argparse
import json
import logging
import os
import sys
import time
from collections import deque
from datetime import datetime
from typing import Any, Dict, List, Optional

from alert_enricher import AlertEnricher
from ai_client import AIClient
from config_loader import enforce_security_posture, load_settings, resolve_runtime_mode
from wazuh_client import WazuhClient

logger = logging.getLogger(__name__)


class Colors:
    HEADER = "\033[95m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"
    END = "\033[0m"


PLAYBOOK_DEFAULT = "privilege-escalation.md"
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PLAYBOOK_BASE = os.path.join(REPO_ROOT, "incident-response", "playbooks")


def print_header(text: str):
    """Print a formatted header."""
    print(f"\n{Colors.CYAN}╔{'═' * 68}╗{Colors.END}")
    print(
        f"{Colors.CYAN}║{Colors.BOLD}  {text:^64}  {Colors.END}{Colors.CYAN}║{Colors.END}"
    )
    print(f"{Colors.CYAN}╚{'═' * 68}╝{Colors.END}\n")


def print_section(emoji: str, title: str, content: str):
    """Print a formatted section."""
    print(f"{Colors.BOLD}{emoji} {title}:{Colors.END}")
    for line in content.strip().split("\n"):
        print(f"   {line}")
    print()


def _expand_range(start: int, end: int, playbook: str) -> Dict[str, str]:
    return {str(rule_id): playbook for rule_id in range(start, end + 1)}


def load_playbook_mapping() -> Dict[str, str]:
    """Load mapping of rule IDs to existing playbooks."""
    mapping: Dict[str, str] = {}
    mapping.update(_expand_range(200001, 200003, "ssh-brute-force.md"))
    mapping.update(_expand_range(200010, 200012, "powershell-abuse.md"))
    mapping["200013"] = "credential-dumping.md"
    mapping["200014"] = "powershell-abuse.md"
    mapping.update(_expand_range(200020, 200022, "privilege-escalation.md"))
    mapping.update(_expand_range(200030, 200033, "privilege-escalation.md"))
    mapping.update(_expand_range(200050, 200053, "persistence.md"))
    mapping.update(_expand_range(200060, 200063, "persistence.md"))
    mapping.update(_expand_range(200070, 200072, "credential-dumping.md"))
    mapping.update(_expand_range(200080, 200082, "persistence.md"))

    # macOS detections
    mapping.update(_expand_range(200200, 200299, "macos-compromise.md"))

    return mapping


def get_mitre_info(technique_id: str) -> Dict[str, Any]:
    """Get MITRE ATT&CK technique information."""
    mitre_db = {
        "T1110": {
            "name": "Brute Force",
            "tactic": "Credential Access",
            "description": "Adversaries may use brute force techniques to gain access to accounts.",
        },
        "T1059.001": {
            "name": "PowerShell",
            "tactic": "Execution",
            "description": "Adversaries may abuse PowerShell commands and scripts for execution.",
        },
        "T1548.003": {
            "name": "Sudo and Sudo Caching",
            "tactic": "Privilege Escalation",
            "description": "Adversaries may abuse sudo to escalate privileges.",
        },
        "T1003": {
            "name": "OS Credential Dumping",
            "tactic": "Credential Access",
            "description": "Adversaries may attempt to dump credentials from the operating system.",
        },
    }
    return mitre_db.get(
        technique_id,
        {
            "name": "Unknown Technique",
            "tactic": "Unknown",
            "description": "Technique information not found.",
        },
    )


class AlertAnalyzer:
    """Main class for analyzing security alerts."""

    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        settings: Optional[Dict[str, Any]] = None,
        runtime_mode: str = "strict",
    ):
        self.config = config or {}
        self.settings = settings or {}
        self.runtime_mode = runtime_mode

        wazuh_cfg = self.settings.get("wazuh", {})
        rag_cfg = self.settings.get("rag", {})
        rag_index_cfg = rag_cfg.get("indexing", {}) if isinstance(rag_cfg, dict) else {}
        playbook_cfg = self.settings.get("playbooks", {})
        self.playbook_base = PLAYBOOK_BASE
        if isinstance(playbook_cfg, dict):
            configured_base = playbook_cfg.get("base_path")
            if isinstance(configured_base, str) and configured_base.strip():
                if os.path.isabs(configured_base):
                    self.playbook_base = configured_base
                else:
                    ai_analyst_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                    self.playbook_base = os.path.abspath(
                        os.path.join(ai_analyst_dir, configured_base)
                    )

        self.wazuh_client = WazuhClient(
            host=wazuh_cfg.get("host"),
            port=wazuh_cfg.get("port", 55000),
            user=wazuh_cfg.get("user"),
            password=wazuh_cfg.get("password"),
            verify_ssl=wazuh_cfg.get("ssl_verify", True),
            runtime_mode=runtime_mode,
        )
        self.ai_client = AIClient(config=self.settings, runtime_mode=runtime_mode)
        self.enricher = AlertEnricher(
            enable_rag_indexing=rag_index_cfg.get("auto_index", True),
            config=self.settings,
            runtime_mode=runtime_mode,
            wazuh_client=self.wazuh_client,
        )
        self.playbook_mapping = load_playbook_mapping()

    def _resolve_playbook(self, rule_id: str) -> Dict[str, str]:
        playbook = self.playbook_mapping.get(rule_id, PLAYBOOK_DEFAULT)
        full_path = os.path.join(self.playbook_base, playbook)
        if not os.path.exists(full_path):
            playbook = PLAYBOOK_DEFAULT
            full_path = os.path.join(self.playbook_base, playbook)
        return {"playbook": playbook, "playbook_path": full_path}

    def analyze(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze a security alert and return enriched analysis."""
        rule_id = str(alert.get("rule", {}).get("id", "unknown"))
        rule_description = alert.get("rule", {}).get("description", "Unknown alert")
        severity = alert.get("rule", {}).get("level", 0)
        timestamp = alert.get("timestamp", datetime.now().isoformat())
        agent_name = alert.get("agent", {}).get("name", "unknown-agent")

        src_ip = alert.get("data", {}).get("srcip") or alert.get("data", {}).get("src_ip")
        user = alert.get("data", {}).get("dstuser") or alert.get("data", {}).get("user")

        mitre_ids = alert.get("rule", {}).get("mitre", {}).get("id", [])
        mitre_id = mitre_ids[0] if mitre_ids else None
        mitre_info = get_mitre_info(mitre_id) if mitre_id else {}

        context = self.enricher.enrich(alert)
        ai_analysis = self.ai_client.analyze_alert(
            alert=alert,
            context=context,
            mitre_info=mitre_info,
        )

        pb = self._resolve_playbook(rule_id)
        if severity >= 10 and rule_id not in self.playbook_mapping:
            message = (
                f"high-severity rule {rule_id} is unmapped; using fallback playbook "
                f"{pb['playbook']}"
            )
            if self.runtime_mode == "strict":
                raise RuntimeError(message)
            logger.warning(message)

        if severity >= 12:
            severity_label = "CRITICAL"
            severity_color = Colors.RED
        elif severity >= 10:
            severity_label = "HIGH"
            severity_color = Colors.RED
        elif severity >= 7:
            severity_label = "MEDIUM"
            severity_color = Colors.YELLOW
        else:
            severity_label = "LOW"
            severity_color = Colors.GREEN

        return {
            "alert_title": ai_analysis.get("title", rule_description),
            "rule_id": rule_id,
            "severity": severity,
            "severity_label": severity_label,
            "severity_color": severity_color,
            "timestamp": timestamp,
            "agent": agent_name,
            "source_ip": src_ip,
            "user": user,
            "summary": ai_analysis.get("summary", "No summary available."),
            "context": context,
            "investigation_steps": ai_analysis.get("investigation_steps", []),
            "recommended_actions": ai_analysis.get("recommended_actions", []),
            "mitre_id": mitre_id,
            "mitre_info": mitre_info,
            "playbook": pb["playbook"],
            "playbook_path": pb["playbook_path"],
            "analysis_metadata": ai_analysis.get(
                "analysis_metadata", self.ai_client.get_status()
            ),
            "raw_alert": alert if self.config.get("include_raw") else None,
        }

    def display_analysis(self, analysis: Dict[str, Any]):
        """Display analysis in terminal format."""
        display_terminal_analysis(analysis)


def display_terminal_analysis(analysis: Dict[str, Any]):
    """Display analysis in terminal format."""
    print_header("AI ALERT ANALYSIS")

    severity_color = analysis.get("severity_color", "")
    print(f"📋 {Colors.BOLD}ALERT: {analysis['alert_title']}{Colors.END}")
    print(
        f"   Rule: {analysis['rule_id']} | "
        f"Severity: {severity_color}{analysis['severity_label']}{Colors.END} | "
        f"Time: {analysis['timestamp']}"
    )

    md = analysis.get("analysis_metadata", {})
    print(
        f"   AI: provider={md.get('provider', 'unknown')} "
        f"mode={md.get('runtime_mode', 'unknown')} "
        f"method={md.get('analysis_method', 'unknown')}"
    )
    print()

    print_section("🎯", "SUMMARY", analysis["summary"])

    context = analysis.get("context", {})
    context_lines = []
    if analysis.get("source_ip"):
        context_lines.append(f"• Source IP: {analysis['source_ip']}")
        if context.get("threat_intel"):
            ti = context["threat_intel"]
            context_lines.append(
                f"  Threat Intel: {ti.get('reports', 0)} reports, Confidence: {ti.get('confidence', 0)}%"
            )
    if analysis.get("agent"):
        context_lines.append(f"• Target System: {analysis['agent']}")
    if analysis.get("user"):
        context_lines.append(f"• User: {analysis['user']}")
    if context.get("related_events") is not None:
        context_lines.append(f"• Related Events: {context.get('related_events', 0)}")
    if context.get("first_seen"):
        context_lines.append(f"• First Seen: {context['first_seen']}")

    if context_lines:
        print_section("📊", "CONTEXT", "\n".join(context_lines))

    if analysis.get("investigation_steps"):
        steps = "\n".join(
            [f"{i+1}. {step}" for i, step in enumerate(analysis["investigation_steps"])]
        )
        print_section("🔍", "INVESTIGATION STEPS", steps)

    if analysis.get("recommended_actions"):
        actions = "\n".join(
            [
                f"{i+1}. {action}"
                for i, action in enumerate(analysis["recommended_actions"])
            ]
        )
        print_section("🛡️", "RECOMMENDED ACTIONS", actions)

    print(f"{Colors.BOLD}📖 PLAYBOOK:{Colors.END} {analysis['playbook']}")
    print(f"   Link: {analysis['playbook_path']}")

    if analysis.get("mitre_id"):
        mitre = analysis["mitre_info"]
        print(
            f"\n{Colors.BOLD}🏷️ MITRE ATT&CK:{Colors.END} "
            f"{analysis['mitre_id']} - {mitre.get('name', 'Unknown')}"
        )
        print(f"   Tactic: {mitre.get('tactic', 'Unknown')}")

    print()


def analysis_to_markdown(analysis: Dict[str, Any]) -> str:
    """Render analysis as markdown."""
    lines = [
        f"# {analysis['alert_title']}",
        "",
        f"- Rule: `{analysis['rule_id']}`",
        f"- Severity: **{analysis['severity_label']}**",
        f"- Time: `{analysis['timestamp']}`",
    ]

    md = analysis.get("analysis_metadata", {})
    lines.append(
        f"- AI: provider=`{md.get('provider', 'unknown')}` mode=`{md.get('runtime_mode', 'unknown')}` method=`{md.get('analysis_method', 'unknown')}`"
    )
    lines.append("")
    lines.extend(["## Summary", "", analysis.get("summary", "No summary available."), ""])

    lines.extend(["## Context", ""])
    context = analysis.get("context", {})
    lines.append(f"- Source IP: `{analysis.get('source_ip')}`") if analysis.get("source_ip") else None
    lines.append(f"- Target System: `{analysis.get('agent')}`") if analysis.get("agent") else None
    lines.append(f"- User: `{analysis.get('user')}`") if analysis.get("user") else None
    lines.append(f"- Related Events: `{context.get('related_events', 0)}`")
    if context.get("first_seen"):
        lines.append(f"- First Seen: `{context.get('first_seen')}`")
    lines.append("")

    if analysis.get("investigation_steps"):
        lines.extend(["## Investigation Steps", ""])
        for step in analysis["investigation_steps"]:
            lines.append(f"- {step}")
        lines.append("")

    if analysis.get("recommended_actions"):
        lines.extend(["## Recommended Actions", ""])
        for action in analysis["recommended_actions"]:
            lines.append(f"- {action}")
        lines.append("")

    lines.extend(
        [
            "## Playbook",
            "",
            f"- `{analysis['playbook']}`",
            f"- Path: `{analysis['playbook_path']}`",
            "",
        ]
    )

    if analysis.get("mitre_id"):
        lines.extend(
            [
                "## MITRE ATT&CK",
                "",
                f"- Technique: `{analysis['mitre_id']}`",
                f"- Name: {analysis['mitre_info'].get('name', 'Unknown')}",
                f"- Tactic: {analysis['mitre_info'].get('tactic', 'Unknown')}",
                "",
            ]
        )

    return "\n".join(lines).strip() + "\n"


def render_output(analysis: Dict[str, Any], output_format: str):
    if output_format == "json":
        print(json.dumps(analysis, indent=2, default=str))
    elif output_format == "markdown":
        print(analysis_to_markdown(analysis))
    else:
        display_terminal_analysis(analysis)


def render_many(analyses: List[Dict[str, Any]], output_format: str):
    if output_format == "json":
        print(json.dumps(analyses, indent=2, default=str))
        return

    if output_format == "markdown":
        for i, analysis in enumerate(analyses):
            if i > 0:
                print("\n---\n")
            print(analysis_to_markdown(analysis))
        return

    # terminal
    for i, analysis in enumerate(analyses):
        if i > 0:
            print("\n" + "=" * 70 + "\n")
        display_terminal_analysis(analysis)


def _render_report(
    analyses: List[Dict[str, Any]],
    report_target: str,
):
    markdown_docs: List[str] = []
    for analysis in analyses:
        markdown_docs.append(analysis_to_markdown(analysis).strip())
    content = "\n\n---\n\n".join(markdown_docs) + "\n"

    if report_target == "-":
        print(content)
        return

    with open(report_target, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"Wrote incident report: {report_target}")


def _fetch_recent_alerts_paginated(
    wazuh_client: WazuhClient,
    total: int,
    page_size: int = 100,
    sleep_seconds: float = 0.1,
) -> List[Dict[str, Any]]:
    alerts: List[Dict[str, Any]] = []
    offset = 0
    while len(alerts) < total:
        batch_limit = min(page_size, total - len(alerts))
        batch = wazuh_client.get_alerts(limit=batch_limit, offset=offset)
        if not batch:
            break
        alerts.extend(batch)
        if len(batch) < batch_limit:
            break
        offset += len(batch)
        if sleep_seconds > 0:
            time.sleep(sleep_seconds)
    return alerts


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="AI-Powered Alert Analyzer for Wazuh SIEM")
    parser.add_argument("--alert-id", "-a", help="Analyze a specific alert by ID")
    parser.add_argument("--alert-file", "-f", help="Analyze alert from JSON file")
    parser.add_argument("--recent", "-r", type=int, help="Analyze N most recent alerts")
    parser.add_argument(
        "--monitor", "-m", action="store_true", help="Monitor and analyze alerts in real-time"
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=30,
        help="Polling interval in seconds for --monitor mode (default: 30)",
    )
    parser.add_argument(
        "--output",
        "-o",
        choices=["terminal", "json", "markdown"],
        default="terminal",
        help="Output format",
    )
    parser.add_argument(
        "--include-raw", action="store_true", help="Include raw alert data in output"
    )
    parser.add_argument("--demo", action="store_true", help="Run with demo/sample alert")
    parser.add_argument(
        "--mode",
        choices=["strict", "demo"],
        default=None,
        help="Runtime mode (strict fails closed, demo allows mock fallbacks)",
    )
    parser.add_argument(
        "--config",
        type=str,
        default=None,
        help="Path to settings.yaml (default: ai-analyst/config/settings.yaml)",
    )
    parser.add_argument(
        "--report",
        nargs="?",
        const="-",
        default=None,
        help="Generate markdown incident report. Optionally pass an output file path.",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    settings = load_settings(args.config)
    runtime_mode = resolve_runtime_mode(
        settings=settings, cli_mode=args.mode, demo_flag=args.demo
    )
    try:
        security_warnings = enforce_security_posture(settings, runtime_mode=runtime_mode)
    except ValueError as e:
        print(f"{Colors.RED}Security configuration error:{Colors.END} {e}")
        sys.exit(1)
    for warning in security_warnings:
        print(f"{Colors.YELLOW}Security warning:{Colors.END} {warning}")

    analyzer_config = {"include_raw": args.include_raw, "output_format": args.output}

    try:
        analyzer = AlertAnalyzer(
            config=analyzer_config, settings=settings, runtime_mode=runtime_mode
        )
    except Exception as e:
        print(f"{Colors.RED}Failed to initialize analyzer:{Colors.END} {e}")
        sys.exit(1)

    try:
        if args.demo:
            alert = {
                "id": "demo-001",
                "timestamp": datetime.now().isoformat(),
                "rule": {
                    "id": "200001",
                    "level": 10,
                    "description": "SSH brute force attack detected",
                    "mitre": {"id": ["T1110"]},
                },
                "agent": {"name": "linux-endpoint-01"},
                "data": {"srcip": "203.0.113.45", "dstuser": "root"},
            }
            analysis = analyzer.analyze(alert)
            if args.report is not None:
                _render_report([analysis], args.report)
            else:
                render_output(analysis, args.output)
            return

        if args.alert_file:
            with open(args.alert_file, "r", encoding="utf-8") as f:
                alert = json.load(f)
            analysis = analyzer.analyze(alert)
            if args.report is not None:
                _render_report([analysis], args.report)
            else:
                render_output(analysis, args.output)
            return

        if args.alert_id:
            alert = analyzer.wazuh_client.get_alert_by_id(args.alert_id)
            if not alert:
                by_rule = analyzer.wazuh_client.get_alerts(limit=1, rule_id=args.alert_id)
                alert = by_rule[0] if by_rule else None
            if not alert:
                print(f"{Colors.YELLOW}Alert not found:{Colors.END} {args.alert_id}")
                sys.exit(1)
            analysis = analyzer.analyze(alert)
            if args.report is not None:
                _render_report([analysis], args.report)
            else:
                render_output(analysis, args.output)
            return

        if args.recent:
            alerts = _fetch_recent_alerts_paginated(
                analyzer.wazuh_client,
                total=args.recent,
            )
            analyses = [analyzer.analyze(alert) for alert in alerts]
            if args.report is not None:
                _render_report(analyses, args.report)
            else:
                render_many(analyses, args.output)
            return

        if args.monitor:
            max_seen_ids = 5000
            seen_ids = set()
            seen_queue = deque()
            print(f"Monitoring alerts every {args.interval}s (Ctrl+C to stop)...")
            while True:
                alerts = analyzer.wazuh_client.get_alerts(limit=50)
                new_alerts = []
                for alert in alerts:
                    alert_id = str(alert.get("id", ""))
                    if alert_id and alert_id not in seen_ids:
                        seen_ids.add(alert_id)
                        seen_queue.append(alert_id)
                        if len(seen_queue) > max_seen_ids:
                            evicted = seen_queue.popleft()
                            seen_ids.discard(evicted)
                        new_alerts.append(alert)

                if new_alerts:
                    analyses = [analyzer.analyze(alert) for alert in new_alerts]
                    if args.report is not None:
                        _render_report(analyses, args.report)
                    else:
                        render_many(analyses, args.output)

                time.sleep(args.interval)

        else:
            print("No action specified. Use --help for available options.")
            sys.exit(1)

    except KeyboardInterrupt:
        print("\nMonitoring stopped.")
        sys.exit(0)
    except Exception as e:
        print(f"{Colors.RED}Error:{Colors.END} {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
