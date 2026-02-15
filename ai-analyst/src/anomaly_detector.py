#!/usr/bin/env python3
"""
Anomaly Detector - Proactive behavioral anomaly detection engine.

Orchestrates the detection pipeline:
1. Fetch events from Wazuh API (or mock data)
2. Compare against behavioral baselines
3. Send flagged deviations to AI for reasoning
4. Output structured anomaly findings
"""

import json
import logging
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

from ai_client import AIClient
from baseline_engine import BaselineEngine, generate_mock_baselines, generate_mock_anomalous_events
from wazuh_client import WazuhClient

logger = logging.getLogger(__name__)


# Map anomaly categories to MITRE ATT&CK techniques
CATEGORY_MITRE_MAP = {
    "login_anomaly": {
        "unusual_hour": {"technique": "T1078", "tactic": "Initial Access", "name": "Valid Accounts"},
        "failed_login_spike": {"technique": "T1110", "tactic": "Credential Access", "name": "Brute Force"},
    },
    "network_anomaly": {
        "new_source_ip": {"technique": "T1078", "tactic": "Initial Access", "name": "Valid Accounts"},
    },
    "process_anomaly": {
        "new_process": {"technique": "T1059", "tactic": "Execution", "name": "Command and Scripting Interpreter"},
    },
    "privilege_anomaly": {
        "new_sudo_command": {"technique": "T1548.003", "tactic": "Privilege Escalation", "name": "Sudo and Sudo Caching"},
        "sudo_spike": {"technique": "T1548.003", "tactic": "Privilege Escalation", "name": "Sudo and Sudo Caching"},
    },
    "volume_anomaly": {
        "event_spike": {"technique": "T1499", "tactic": "Impact", "name": "Endpoint Denial of Service"},
    },
    "file_integrity_anomaly": {
        "fim_spike": {"technique": "T1565.001", "tactic": "Impact", "name": "Data Manipulation: Stored Data"},
    },
    "beacon_anomaly": {
        "periodic_beacon": {"technique": "T1071.001", "tactic": "Command and Control", "name": "Application Layer Protocol: Web Protocols"},
    },
    "dns_exfil_anomaly": {
        "dns_volume_spike": {"technique": "T1071.004", "tactic": "Command and Control", "name": "Application Layer Protocol: DNS"},
        "high_entropy_dns": {"technique": "T1048.003", "tactic": "Exfiltration", "name": "Exfiltration Over Unencrypted Non-C2 Protocol"},
        "long_dns_queries": {"technique": "T1048.003", "tactic": "Exfiltration", "name": "Exfiltration Over Unencrypted Non-C2 Protocol"},
        "dns_query_spike": {"technique": "T1071.004", "tactic": "Command and Control", "name": "Application Layer Protocol: DNS"},
    },
}


class AnomalyDetector:
    """
    Proactive anomaly detection engine.

    Combines statistical baseline comparison with AI-powered reasoning
    to detect behavioral anomalies that signature-based rules miss.
    """

    def __init__(
        self,
        z_score_threshold: float = 2.5,
        min_confidence: float = 0.6,
        baseline_path: Optional[str] = None,
    ):
        self.z_score_threshold = z_score_threshold
        self.min_confidence = min_confidence
        self.baseline_path = baseline_path
        self.engine = BaselineEngine(z_score_threshold=z_score_threshold)
        self.ai_client = AIClient()

    def run_demo(self) -> Dict[str, Any]:
        """
        Run anomaly detection in demo mode with mock data.
        No live Wazuh instance needed.
        """
        logger.info("Running anomaly detection in DEMO mode")

        # Build baselines from mock historical data
        self.engine = generate_mock_baselines()

        # Generate mock current events (with planted anomalies)
        current_events = generate_mock_anomalous_events()

        # Run detection pipeline
        return self._run_pipeline(current_events)

    def run_live(self, lookback_hours: int = 24) -> Dict[str, Any]:
        """
        Run anomaly detection against a live Wazuh instance.

        Args:
            lookback_hours: How far back to look for events
        """
        logger.info("Running anomaly detection against live Wazuh (lookback: %dh)", lookback_hours)

        # Load persisted baselines if available
        if self.baseline_path and os.path.exists(self.baseline_path):
            self.engine.load(self.baseline_path)
        else:
            logger.warning("No baseline file found. Building baseline from current data.")

        # Fetch events from Wazuh
        wazuh = WazuhClient()
        events = wazuh.get_alerts(limit=1000)

        if not events:
            return {
                "scan_time": datetime.utcnow().isoformat(),
                "status": "no_events",
                "message": "No events found in the specified time window",
                "findings": [],
            }

        # If no baseline exists, build one and return
        if not self.engine.baselines:
            logger.info("Building initial baseline from %d events", len(events))
            self.engine.build_from_events(events)
            if self.baseline_path:
                self.engine.save(self.baseline_path)
            return {
                "scan_time": datetime.utcnow().isoformat(),
                "status": "baseline_built",
                "message": f"Initial baseline built from {len(events)} events across {len(self.engine.baselines)} agents. Run again to detect anomalies.",
                "findings": [],
            }

        # Run detection pipeline
        result = self._run_pipeline(events)

        # Update baselines with new data
        self.engine.build_from_events(events)
        if self.baseline_path:
            self.engine.save(self.baseline_path)

        return result

    def _run_pipeline(self, events: List[Dict]) -> Dict[str, Any]:
        """Core detection pipeline."""
        scan_time = datetime.utcnow().isoformat()

        # Step 1: Check events against baselines
        deviations = self.engine.check_events(events)

        if not deviations:
            return {
                "scan_time": scan_time,
                "status": "clean",
                "events_analyzed": len(events),
                "agents_checked": len(self.engine.baselines),
                "message": "No anomalies detected — all activity within normal baselines",
                "findings": [],
            }

        # Step 2: Enrich deviations with MITRE context
        enriched = self._enrich_deviations(deviations)

        # Step 3: Send to AI for reasoning
        ai_analysis = self._ai_analyze(enriched)

        # Step 4: Build final result
        return {
            "scan_time": scan_time,
            "status": "anomalies_detected",
            "events_analyzed": len(events),
            "agents_checked": len(self.engine.baselines),
            "deviations_found": len(deviations),
            "raw_deviations": enriched,
            "ai_analysis": ai_analysis,
        }

    def _enrich_deviations(self, deviations: List[Dict]) -> List[Dict]:
        """Add MITRE ATT&CK context to deviations."""
        for dev in deviations:
            category = dev.get("category", "")
            subcategory = dev.get("subcategory", "")
            mitre = CATEGORY_MITRE_MAP.get(category, {}).get(subcategory, {})
            dev["mitre"] = mitre

            # Strip the full event from the deviation for the AI prompt (too verbose)
            if dev.get("event"):
                event = dev["event"]
                dev["event_summary"] = {
                    "timestamp": event.get("timestamp", ""),
                    "rule_id": event.get("rule", {}).get("id", ""),
                    "rule_desc": event.get("rule", {}).get("description", ""),
                    "agent": event.get("agent", {}).get("name", ""),
                    "src_ip": event.get("data", {}).get("srcip", ""),
                    "user": event.get("data", {}).get("srcuser", ""),
                    "process": event.get("data", {}).get("process", ""),
                    "command": event.get("data", {}).get("command", ""),
                }
                del dev["event"]

        return deviations

    def _ai_analyze(self, deviations: List[Dict]) -> Dict[str, Any]:
        """Send deviations to the AI for behavioral analysis."""
        # Load the anomaly analysis prompt
        prompt_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "prompts",
            "anomaly_analysis.txt",
        )

        system_prompt = ""
        if os.path.exists(prompt_path):
            with open(prompt_path, "r") as f:
                system_prompt = f.read()
        else:
            system_prompt = (
                "You are a behavioral threat analyst. Analyze the following "
                "statistical deviations and determine which represent genuine "
                "threats. Respond in valid JSON."
            )

        # Build the user prompt with deviation data
        user_prompt = self._build_analysis_prompt(deviations)

        # Call the AI
        try:
            response = self.ai_client.client.generate(
                prompt=user_prompt, system_prompt=system_prompt
            )

            # Try to parse JSON response
            try:
                # Extract JSON from response (may be wrapped in markdown code fence)
                json_str = response
                if "```json" in response:
                    json_str = response.split("```json")[1].split("```")[0]
                elif "```" in response:
                    json_str = response.split("```")[1].split("```")[0]
                parsed = json.loads(json_str)

                # Validate the response has the expected anomaly analysis schema
                if "findings" in parsed and "risk_level" in parsed:
                    return parsed
                else:
                    logger.info("AI response has unexpected schema, using fallback")
                    return self._fallback_analysis(deviations)
            except (json.JSONDecodeError, IndexError):
                logger.warning("Could not parse AI response as JSON, using fallback")
                return self._fallback_analysis(deviations)

        except Exception as e:
            logger.warning("AI analysis failed (%s), using rule-based fallback", e)
            return self._fallback_analysis(deviations)

    def _build_analysis_prompt(self, deviations: List[Dict]) -> str:
        """Build the prompt to send to the AI with deviation data."""
        lines = [
            "Analyze the following behavioral deviations detected in our SOC environment.",
            f"Total deviations found: {len(deviations)}",
            "",
            "DEVIATIONS:",
            "=" * 60,
        ]

        for i, dev in enumerate(deviations, 1):
            lines.append(f"\n--- Deviation #{i} ---")
            lines.append(f"Category: {dev.get('category', 'unknown')}")
            lines.append(f"Subcategory: {dev.get('subcategory', 'unknown')}")
            lines.append(f"Agent: {dev.get('agent_name', '')} (ID: {dev.get('agent_id', '')})")
            lines.append(f"Z-Score: {dev.get('z_score', 0)}")
            lines.append(f"Detail: {dev.get('detail', '')}")

            mitre = dev.get("mitre", {})
            if mitre:
                lines.append(f"MITRE: {mitre.get('technique', '')} - {mitre.get('name', '')} ({mitre.get('tactic', '')})")

            summary = dev.get("event_summary", {})
            if summary:
                lines.append(f"Event: {json.dumps(summary, indent=2)}")

        lines.append("\n" + "=" * 60)
        lines.append("\nProvide your analysis in the JSON format specified in your instructions.")

        return "\n".join(lines)

    def _fallback_analysis(self, deviations: List[Dict]) -> Dict[str, Any]:
        """Rule-based fallback when AI is unavailable."""
        findings = []
        categories_seen = set()

        for dev in deviations:
            category = dev.get("category", "")
            subcategory = dev.get("subcategory", "")
            z_score = dev.get("z_score", 0)
            categories_seen.add(category)

            # Determine severity based on z-score and category
            if z_score >= 4.0 or category == "privilege_anomaly":
                severity = "HIGH"
                confidence = 0.8
            elif z_score >= 3.0:
                severity = "MEDIUM"
                confidence = 0.7
            else:
                severity = "LOW"
                confidence = 0.6

            mitre = dev.get("mitre", {})

            findings.append(
                {
                    "title": f"{category.replace('_', ' ').title()}: {dev.get('detail', subcategory)}",
                    "severity": severity,
                    "confidence": confidence,
                    "is_true_positive": z_score >= 3.0,
                    "description": dev.get("detail", ""),
                    "correlated_anomalies": [category],
                    "mitre_technique": mitre.get("technique", "N/A"),
                    "mitre_tactic": mitre.get("tactic", "N/A"),
                    "investigation_steps": [
                        f"Review recent events for agent {dev.get('agent_name', dev.get('agent_id', ''))}",
                        f"Check if the {subcategory} pattern continues",
                        "Correlate with other concurrent anomalies",
                        "Verify with system owner if activity is expected",
                    ],
                    "recommended_actions": [
                        f"[IMMEDIATE] Investigate {category} on {dev.get('agent_name', '')}",
                        "[SHORT-TERM] Review access logs and audit trails",
                        "[LONG-TERM] Update baselines if activity is confirmed legitimate",
                    ],
                }
            )

        # Determine overall risk
        severities = [f["severity"] for f in findings]
        if "CRITICAL" in severities:
            overall_risk = "CRITICAL"
        elif "HIGH" in severities:
            overall_risk = "HIGH"
        elif "MEDIUM" in severities:
            overall_risk = "MEDIUM"
        else:
            overall_risk = "LOW"

        # Build attack narrative if multiple categories detected
        narrative = ""
        if len(categories_seen) >= 3:
            narrative = (
                "Multiple anomaly categories detected simultaneously, "
                "which may indicate a coordinated attack. The combination of "
                f"{', '.join(categories_seen)} suggests potential lateral movement "
                "or post-exploitation activity. Recommend immediate investigation."
            )
        elif len(categories_seen) == 2:
            narrative = (
                f"Two anomaly categories detected ({', '.join(categories_seen)}). "
                "These may be correlated — investigate whether they share a common source."
            )

        return {
            "overall_assessment": f"Detected {len(findings)} behavioral anomalies across {len(categories_seen)} categories. {'Multiple correlated categories suggest elevated risk.' if len(categories_seen) > 1 else ''}",
            "risk_level": overall_risk,
            "findings": findings,
            "attack_narrative": narrative,
            "analysis_method": "rule-based fallback (AI unavailable)",
        }
