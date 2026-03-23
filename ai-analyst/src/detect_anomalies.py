#!/usr/bin/env python3
"""
AI Anomaly Detector - CLI Entry Point

Proactive behavioral anomaly detection for the Cloud SOC Platform.
Analyzes Wazuh events against behavioral baselines to detect threats
that signature-based rules miss.

Usage:
    python src/detect_anomalies.py --demo
    python src/detect_anomalies.py --hours 24
    python src/detect_anomalies.py --monitor --interval 300
"""

import argparse
import json
import sys
import time
from datetime import datetime

from anomaly_detector import AnomalyDetector
from config_loader import enforce_security_posture, load_settings, resolve_runtime_mode


# ANSI Colors
class Colors:
    HEADER = "\033[95m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    END = "\033[0m"


SEVERITY_COLORS = {
    "CRITICAL": Colors.RED,
    "HIGH": Colors.RED,
    "MEDIUM": Colors.YELLOW,
    "LOW": Colors.BLUE,
    "INFO": Colors.DIM,
}


def print_banner():
    print()
    print(f"{Colors.CYAN}╔══════════════════════════════════════════════════════════════════╗{Colors.END}")
    print(f"{Colors.CYAN}║{Colors.END}  {Colors.BOLD}🧠 AI Anomaly Detection Agent{Colors.END}                                  {Colors.CYAN}║{Colors.END}")
    print(f"{Colors.CYAN}║{Colors.END}  {Colors.DIM}Behavioral & Heuristic Threat Detection{Colors.END}                        {Colors.CYAN}║{Colors.END}")
    print(f"{Colors.CYAN}║{Colors.END}  {Colors.DIM}Cloud SOC Platform{Colors.END}                                              {Colors.CYAN}║{Colors.END}")
    print(f"{Colors.CYAN}╚══════════════════════════════════════════════════════════════════╝{Colors.END}")
    print()


def print_scan_summary(result: dict):
    """Print the scan summary header."""
    status = result.get("status", "unknown")
    events = result.get("events_analyzed", 0)
    agents = result.get("agents_checked", 0)
    deviations = result.get("deviations_found", 0)
    scan_time = result.get("scan_time", "")

    print(f"  {Colors.BOLD}Scan Time{Colors.END}         {scan_time}")
    print(f"  {Colors.BOLD}Events Analyzed{Colors.END}   {events}")
    print(f"  {Colors.BOLD}Agents Checked{Colors.END}    {agents}")

    if status == "clean":
        print(f"  {Colors.BOLD}Status{Colors.END}            {Colors.GREEN}✓ CLEAN — No anomalies detected{Colors.END}")
    elif status == "anomalies_detected":
        print(f"  {Colors.BOLD}Deviations{Colors.END}        {Colors.YELLOW}{deviations} statistical deviations found{Colors.END}")
    elif status == "baseline_built":
        print(f"  {Colors.BOLD}Status{Colors.END}            {Colors.BLUE}Baseline built — run again to detect anomalies{Colors.END}")
    elif status == "no_events":
        print(f"  {Colors.BOLD}Status{Colors.END}            {Colors.DIM}No events found{Colors.END}")

    print()


def print_raw_deviations(deviations: list):
    """Print raw statistical deviations."""
    print(f"{Colors.CYAN}{'─' * 66}{Colors.END}")
    print(f"  {Colors.BOLD}Statistical Deviations{Colors.END}")
    print(f"{Colors.CYAN}{'─' * 66}{Colors.END}")
    print()

    for i, dev in enumerate(deviations, 1):
        z = dev.get("z_score", 0)
        color = Colors.RED if z >= 3.5 else Colors.YELLOW if z >= 2.5 else Colors.DIM
        category = dev.get("category", "").replace("_", " ").title()
        agent = dev.get("agent_name", dev.get("agent_id", ""))

        print(f"  {Colors.BOLD}#{i}{Colors.END}  {color}[z={z:.1f}]{Colors.END}  {category}")
        print(f"       {Colors.DIM}Agent:{Colors.END} {agent}")
        print(f"       {dev.get('detail', '')}")

        mitre = dev.get("mitre", {})
        if mitre:
            print(f"       {Colors.DIM}MITRE:{Colors.END} {mitre.get('technique', '')} — {mitre.get('name', '')}")
        print()


def print_ai_findings(analysis: dict):
    """Print AI-analyzed findings."""
    risk_level = analysis.get("risk_level", "UNKNOWN")
    risk_color = SEVERITY_COLORS.get(risk_level, Colors.DIM)
    findings = analysis.get("findings", [])
    method = analysis.get("analysis_method", "AI-powered")

    print(f"{Colors.CYAN}{'═' * 66}{Colors.END}")
    print(f"  {Colors.BOLD}🎯 AI THREAT ANALYSIS{Colors.END}  {Colors.DIM}({method}){Colors.END}")
    print(f"{Colors.CYAN}{'═' * 66}{Colors.END}")
    print()

    # Overall assessment
    assessment = analysis.get("overall_assessment", "")
    if assessment:
        print(f"  {Colors.BOLD}Overall:{Colors.END} {assessment}")
        print(f"  {Colors.BOLD}Risk Level:{Colors.END} {risk_color}{risk_level}{Colors.END}")
        print()

    # Individual findings
    for i, finding in enumerate(findings, 1):
        severity = finding.get("severity", "UNKNOWN")
        sev_color = SEVERITY_COLORS.get(severity, Colors.DIM)
        confidence = finding.get("confidence", 0)
        is_tp = finding.get("is_true_positive", False)
        tp_label = f"{Colors.RED}TRUE POSITIVE{Colors.END}" if is_tp else f"{Colors.GREEN}LIKELY FALSE POSITIVE{Colors.END}"

        print(f"  {Colors.BOLD}Finding #{i}{Colors.END}  {sev_color}[{severity}]{Colors.END}  Confidence: {confidence:.0%}  {tp_label}")
        print(f"  {Colors.BOLD}{finding.get('title', '')}{Colors.END}")
        print()

        desc = finding.get("description", "")
        if desc:
            print(f"    {desc}")
            print()

        mitre_tech = finding.get("mitre_technique", "")
        mitre_tactic = finding.get("mitre_tactic", "")
        if mitre_tech and mitre_tech != "N/A":
            print(f"    {Colors.DIM}MITRE:{Colors.END} {mitre_tech} — {mitre_tactic}")

        # Investigation steps
        steps = finding.get("investigation_steps", [])
        if steps:
            print(f"    {Colors.DIM}Investigate:{Colors.END}")
            for step in steps:
                print(f"      → {step}")

        # Recommended actions
        actions = finding.get("recommended_actions", [])
        if actions:
            print(f"    {Colors.DIM}Actions:{Colors.END}")
            for action in actions:
                if "[IMMEDIATE]" in action:
                    print(f"      {Colors.RED}▸{Colors.END} {action}")
                elif "[SHORT-TERM]" in action:
                    print(f"      {Colors.YELLOW}▸{Colors.END} {action}")
                else:
                    print(f"      {Colors.BLUE}▸{Colors.END} {action}")

        print()
        print(f"  {Colors.DIM}{'─' * 62}{Colors.END}")
        print()

    # Attack narrative
    narrative = analysis.get("attack_narrative", "")
    if narrative:
        print(f"  {Colors.BOLD}⚡ ATTACK NARRATIVE{Colors.END}")
        print(f"    {narrative}")
        print()


def display_results(result: dict):
    """Display full results in terminal format."""
    print_banner()
    print_scan_summary(result)

    if result.get("status") not in ("anomalies_detected",):
        msg = result.get("message", "")
        if msg:
            print(f"  {Colors.DIM}{msg}{Colors.END}")
            print()
        return

    # Print raw deviations
    deviations = result.get("raw_deviations", [])
    if deviations:
        print_raw_deviations(deviations)

    # Print AI analysis
    ai_analysis = result.get("ai_analysis", {})
    if ai_analysis:
        print_ai_findings(ai_analysis)

    print(f"{Colors.CYAN}{'═' * 66}{Colors.END}")
    print(f"  {Colors.DIM}Scan complete. Review findings above and take indicated actions.{Colors.END}")
    print(f"{Colors.CYAN}{'═' * 66}{Colors.END}")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="AI Anomaly Detection Agent — Behavioral & Heuristic Threat Detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --demo                   Run with mock data (no Wazuh needed)
  %(prog)s --hours 24               Analyze last 24 hours from live Wazuh
  %(prog)s --monitor --interval 300 Continuous monitoring every 5 minutes
  %(prog)s --demo --format json     Output as JSON for pipeline integration
        """,
    )

    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run in demo mode with mock data (no live Wazuh needed)",
    )
    parser.add_argument(
        "--hours",
        type=int,
        default=None,
        help="Hours of event history to analyze (default: from settings)",
    )
    parser.add_argument(
        "--monitor",
        action="store_true",
        help="Continuous monitoring mode",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=None,
        help="Seconds between scans in monitor mode (default: from settings)",
    )
    parser.add_argument(
        "--format",
        choices=["terminal", "json"],
        default="terminal",
        help="Output format (default: terminal)",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=None,
        help="Z-score threshold for flagging deviations (default: 2.5)",
    )
    parser.add_argument(
        "--baseline-file",
        type=str,
        default=None,
        help="Path to baseline file (default: baselines/agent_baselines.json)",
    )
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

    args = parser.parse_args()

    settings = load_settings(args.config)
    runtime_mode = resolve_runtime_mode(
        settings=settings, cli_mode=args.mode, demo_flag=args.demo
    )
    try:
        security_warnings = enforce_security_posture(settings, runtime_mode=runtime_mode)
    except ValueError as e:
        print(f"\n{Colors.RED}Security configuration error:{Colors.END} {e}\n")
        sys.exit(1)
    for warning in security_warnings:
        print(f"{Colors.YELLOW}Security warning:{Colors.END} {warning}")

    anomaly_cfg = settings.get("anomaly_detection", {})

    threshold = args.threshold if args.threshold is not None else anomaly_cfg.get(
        "z_score_threshold", 2.5
    )
    lookback_hours = (
        args.hours if args.hours is not None else anomaly_cfg.get("lookback_hours", 24)
    )
    monitor_interval = args.interval or anomaly_cfg.get("scan_interval_seconds", 300)
    baseline_file = args.baseline_file or anomaly_cfg.get(
        "baseline_file", "baselines/agent_baselines.json"
    )

    # Create detector
    try:
        detector = AnomalyDetector(
            z_score_threshold=threshold,
            min_confidence=anomaly_cfg.get("min_confidence", 0.6),
            baseline_path=baseline_file,
            config=settings,
            runtime_mode=runtime_mode,
        )
    except Exception as e:
        print(f"\n{Colors.RED}Failed to initialize detector:{Colors.END} {e}\n")
        sys.exit(1)

    if args.monitor:
        # Continuous monitoring loop
        print_banner()
        print(f"  {Colors.BOLD}Continuous monitoring mode{Colors.END}")
        print(f"  Scanning every {monitor_interval} seconds")
        print(f"  Press Ctrl+C to stop")
        print()

        try:
            while True:
                if args.demo:
                    result = detector.run_demo()
                else:
                    result = detector.run_live(lookback_hours=lookback_hours)

                if args.format == "json":
                    print(json.dumps(result, indent=2, default=str))
                else:
                    display_results(result)

                time.sleep(monitor_interval)
        except KeyboardInterrupt:
            print(f"\n  {Colors.DIM}Monitoring stopped.{Colors.END}\n")
            sys.exit(0)
        except Exception as e:
            print(f"\n  {Colors.RED}Error:{Colors.END} {e}\n")
            sys.exit(1)
    else:
        # Single scan
        try:
            if args.demo:
                result = detector.run_demo()
            else:
                result = detector.run_live(lookback_hours=lookback_hours)
        except Exception as e:
            print(f"\n{Colors.RED}Error:{Colors.END} {e}\n")
            sys.exit(1)

        if args.format == "json":
            print(json.dumps(result, indent=2, default=str))
        else:
            display_results(result)


if __name__ == "__main__":
    main()
