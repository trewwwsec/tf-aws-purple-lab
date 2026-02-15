#!/usr/bin/env python3
"""
Baseline Engine - Builds and maintains behavioral baselines from Wazuh events.

Tracks per-agent and per-user norms for:
- Login patterns (hours, source IPs, geolocations)
- Process execution (commands/binaries per host)
- Network behavior (connection volumes, destinations)
- Privilege usage (sudo/admin frequency and commands)
- File integrity (change rates)

Uses statistical methods (mean, std deviation, z-scores) to flag deviations.
Baselines persist as JSON files across runs.
"""

import json
import logging
import math
import os
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class BaselineProfile:
    """Statistical profile for a single metric."""

    def __init__(self, name: str):
        self.name = name
        self.count = 0
        self.mean = 0.0
        self.variance = 0.0
        self.min_val = float("inf")
        self.max_val = float("-inf")
        self.samples: List[float] = []

    def update(self, value: float):
        """Update running statistics with a new value (Welford's online algorithm)."""
        self.count += 1
        self.samples.append(value)
        delta = value - self.mean
        self.mean += delta / self.count
        delta2 = value - self.mean
        self.variance += delta * delta2
        self.min_val = min(self.min_val, value)
        self.max_val = max(self.max_val, value)

    @property
    def std_dev(self) -> float:
        if self.count < 2:
            return 0.0
        return (self.variance / (self.count - 1)) ** 0.5

    def z_score(self, value: float) -> float:
        """Calculate z-score for a given value against this baseline."""
        if self.std_dev == 0:
            return 0.0 if value == self.mean else 3.0
        return abs(value - self.mean) / self.std_dev

    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "count": self.count,
            "mean": round(self.mean, 4),
            "std_dev": round(self.std_dev, 4),
            "min": self.min_val if self.min_val != float("inf") else 0,
            "max": self.max_val if self.max_val != float("-inf") else 0,
        }

    @classmethod
    def from_dict(cls, data: Dict) -> "BaselineProfile":
        profile = cls(data["name"])
        profile.count = data["count"]
        profile.mean = data["mean"]
        # Reconstruct variance from std_dev and count
        std = data.get("std_dev", 0)
        profile.variance = (std**2) * max(data["count"] - 1, 1)
        profile.min_val = data.get("min", 0)
        profile.max_val = data.get("max", 0)
        return profile


class AgentBaseline:
    """Behavioral baseline for a single Wazuh agent."""

    def __init__(self, agent_id: str, agent_name: str = ""):
        self.agent_id = agent_id
        self.agent_name = agent_name
        self.last_updated = datetime.utcnow().isoformat()

        # Statistical profiles
        self.login_hour_profile = BaselineProfile("login_hours")
        self.events_per_hour_profile = BaselineProfile("events_per_hour")
        self.sudo_per_day_profile = BaselineProfile("sudo_per_day")
        self.unique_ips_per_day_profile = BaselineProfile("unique_ips_per_day")
        self.fim_changes_per_day_profile = BaselineProfile("fim_changes_per_day")
        self.failed_logins_per_hour_profile = BaselineProfile("failed_logins_per_hour")
        self.dns_queries_per_hour_profile = BaselineProfile("dns_queries_per_hour")
        self.dns_query_length_profile = BaselineProfile("dns_query_length")
        self.outbound_conn_interval_profile = BaselineProfile("outbound_conn_interval_std")

        # Categorical baselines (known-good sets)
        self.known_source_ips: set = set()
        self.known_processes: set = set()
        self.known_users: set = set()
        self.known_sudo_commands: set = set()
        self.known_dns_domains: set = set()
        self.known_dest_ips: set = set()

    def to_dict(self) -> Dict:
        return {
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "last_updated": self.last_updated,
            "profiles": {
                "login_hours": self.login_hour_profile.to_dict(),
                "events_per_hour": self.events_per_hour_profile.to_dict(),
                "sudo_per_day": self.sudo_per_day_profile.to_dict(),
                "unique_ips_per_day": self.unique_ips_per_day_profile.to_dict(),
                "fim_changes_per_day": self.fim_changes_per_day_profile.to_dict(),
                "failed_logins_per_hour": self.failed_logins_per_hour_profile.to_dict(),
                "dns_queries_per_hour": self.dns_queries_per_hour_profile.to_dict(),
                "dns_query_length": self.dns_query_length_profile.to_dict(),
                "outbound_conn_interval_std": self.outbound_conn_interval_profile.to_dict(),
            },
            "known_sets": {
                "source_ips": list(self.known_source_ips),
                "processes": list(self.known_processes),
                "users": list(self.known_users),
                "sudo_commands": list(self.known_sudo_commands),
                "dns_domains": list(self.known_dns_domains),
                "dest_ips": list(self.known_dest_ips),
            },
        }

    @classmethod
    def from_dict(cls, data: Dict) -> "AgentBaseline":
        baseline = cls(data["agent_id"], data.get("agent_name", ""))
        baseline.last_updated = data.get("last_updated", "")

        profiles = data.get("profiles", {})
        if "login_hours" in profiles:
            baseline.login_hour_profile = BaselineProfile.from_dict(
                profiles["login_hours"]
            )
        if "events_per_hour" in profiles:
            baseline.events_per_hour_profile = BaselineProfile.from_dict(
                profiles["events_per_hour"]
            )
        if "sudo_per_day" in profiles:
            baseline.sudo_per_day_profile = BaselineProfile.from_dict(
                profiles["sudo_per_day"]
            )
        if "unique_ips_per_day" in profiles:
            baseline.unique_ips_per_day_profile = BaselineProfile.from_dict(
                profiles["unique_ips_per_day"]
            )
        if "fim_changes_per_day" in profiles:
            baseline.fim_changes_per_day_profile = BaselineProfile.from_dict(
                profiles["fim_changes_per_day"]
            )
        if "failed_logins_per_hour" in profiles:
            baseline.failed_logins_per_hour_profile = BaselineProfile.from_dict(
                profiles["failed_logins_per_hour"]
            )
        if "dns_queries_per_hour" in profiles:
            baseline.dns_queries_per_hour_profile = BaselineProfile.from_dict(
                profiles["dns_queries_per_hour"]
            )
        if "dns_query_length" in profiles:
            baseline.dns_query_length_profile = BaselineProfile.from_dict(
                profiles["dns_query_length"]
            )
        if "outbound_conn_interval_std" in profiles:
            baseline.outbound_conn_interval_profile = BaselineProfile.from_dict(
                profiles["outbound_conn_interval_std"]
            )

        known = data.get("known_sets", {})
        baseline.known_source_ips = set(known.get("source_ips", []))
        baseline.known_processes = set(known.get("processes", []))
        baseline.known_users = set(known.get("users", []))
        baseline.known_sudo_commands = set(known.get("sudo_commands", []))
        baseline.known_dns_domains = set(known.get("dns_domains", []))
        baseline.known_dest_ips = set(known.get("dest_ips", []))

        return baseline


class BaselineEngine:
    """
    Builds, persists, and queries behavioral baselines.

    Usage:
        engine = BaselineEngine()
        engine.build_from_events(events)          # Train on historical events
        deviations = engine.check_events(events)   # Check new events for anomalies
        engine.save("baselines/agent_baselines.json")
    """

    def __init__(self, z_score_threshold: float = 2.5):
        self.z_score_threshold = z_score_threshold
        self.baselines: Dict[str, AgentBaseline] = {}

    def _get_or_create_baseline(
        self, agent_id: str, agent_name: str = ""
    ) -> AgentBaseline:
        if agent_id not in self.baselines:
            self.baselines[agent_id] = AgentBaseline(agent_id, agent_name)
        return self.baselines[agent_id]

    def build_from_events(self, events: List[Dict[str, Any]]):
        """
        Build baselines from a list of historical Wazuh events.

        Args:
            events: List of Wazuh alert/event dictionaries
        """
        # Group events by agent
        agent_events: Dict[str, List[Dict]] = defaultdict(list)
        for event in events:
            agent = event.get("agent", {})
            agent_id = agent.get("id", "000")
            agent_events[agent_id].append(event)

        for agent_id, evts in agent_events.items():
            agent_name = evts[0].get("agent", {}).get("name", "")
            baseline = self._get_or_create_baseline(agent_id, agent_name)
            self._process_events_for_baseline(baseline, evts)
            baseline.last_updated = datetime.utcnow().isoformat()

        logger.info(
            "Built baselines for %d agents from %d events",
            len(self.baselines),
            len(events),
        )

    def _process_events_for_baseline(
        self, baseline: AgentBaseline, events: List[Dict]
    ):
        """Process a batch of events to update an agent's baseline."""
        # Aggregate hourly event counts
        hourly_counts: Dict[str, int] = defaultdict(int)
        daily_sudo_counts: Dict[str, int] = defaultdict(int)
        daily_ips: Dict[str, set] = defaultdict(set)
        daily_fim_counts: Dict[str, int] = defaultdict(int)
        hourly_failed_logins: Dict[str, int] = defaultdict(int)
        hourly_dns_counts: Dict[str, int] = defaultdict(int)
        # Track outbound connection timestamps per destination IP
        dest_ip_timestamps: Dict[str, List[float]] = defaultdict(list)

        for event in events:
            timestamp = event.get("timestamp", "")
            try:
                dt = datetime.fromisoformat(
                    timestamp.replace("+0000", "+00:00").replace("Z", "+00:00")
                )
            except (ValueError, AttributeError):
                continue

            hour_key = dt.strftime("%Y-%m-%d-%H")
            day_key = dt.strftime("%Y-%m-%d")

            # Count events per hour
            hourly_counts[hour_key] += 1

            # Track login hours
            rule = event.get("rule", {})
            groups = rule.get("groups", [])
            description = rule.get("description", "").lower()

            if "authentication_success" in groups or "login" in description:
                baseline.login_hour_profile.update(float(dt.hour))

            # Track source IPs
            data = event.get("data", {})
            src_ip = data.get("srcip", "") or data.get("src_ip", "")
            if src_ip:
                baseline.known_source_ips.add(src_ip)
                daily_ips[day_key].add(src_ip)

            # Track destination IPs (for beacon detection)
            dst_ip = data.get("dstip", "") or data.get("dst_ip", "")
            if dst_ip:
                baseline.known_dest_ips.add(dst_ip)
                dest_ip_timestamps[dst_ip].append(dt.timestamp())

            # Track sudo/privilege escalation
            if "sudo" in description or "privilege_escalation" in groups:
                daily_sudo_counts[day_key] += 1
                cmd = data.get("command", "")
                if cmd:
                    baseline.known_sudo_commands.add(cmd)

            # Track processes
            process = data.get("process", "") or data.get("program_name", "")
            if process:
                baseline.known_processes.add(process)

            # Track users
            user = data.get("srcuser", "") or data.get("dstuser", "")
            if user:
                baseline.known_users.add(user)

            # Track file integrity changes
            if "syscheck" in groups or "file_integrity" in description:
                daily_fim_counts[day_key] += 1

            # Track failed logins
            if "authentication_failed" in groups or "failed" in description:
                hourly_failed_logins[hour_key] += 1

            # Track DNS queries
            if "dns" in description or "dns" in " ".join(groups).lower():
                hourly_dns_counts[hour_key] += 1
                query_name = data.get("query", "") or data.get("dns_query", "")
                if query_name:
                    baseline.known_dns_domains.add(self._extract_base_domain(query_name))
                    baseline.dns_query_length_profile.update(float(len(query_name)))

        # Update statistical profiles
        for count in hourly_counts.values():
            baseline.events_per_hour_profile.update(float(count))

        for count in daily_sudo_counts.values():
            baseline.sudo_per_day_profile.update(float(count))

        for ips in daily_ips.values():
            baseline.unique_ips_per_day_profile.update(float(len(ips)))

        for count in daily_fim_counts.values():
            baseline.fim_changes_per_day_profile.update(float(count))

        for count in hourly_failed_logins.values():
            baseline.failed_logins_per_hour_profile.update(float(count))

        for count in hourly_dns_counts.values():
            baseline.dns_queries_per_hour_profile.update(float(count))

        # Train baseline on connection interval variability (std dev of intervals per dest)
        for dst_ip, timestamps in dest_ip_timestamps.items():
            if len(timestamps) >= 3:
                timestamps.sort()
                intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
                if intervals:
                    interval_std = self._std_dev(intervals)
                    baseline.outbound_conn_interval_profile.update(interval_std)

    def check_events(
        self, events: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Check a batch of events against baselines and return deviations.

        Returns:
            List of deviation dictionaries with category, z_score, details
        """
        deviations = []

        # Group events by agent
        agent_events: Dict[str, List[Dict]] = defaultdict(list)
        for event in events:
            agent_id = event.get("agent", {}).get("id", "000")
            agent_events[agent_id].append(event)

        for agent_id, evts in agent_events.items():
            if agent_id not in self.baselines:
                logger.debug("No baseline for agent %s, skipping", agent_id)
                continue

            baseline = self.baselines[agent_id]
            deviations.extend(self._check_agent_events(baseline, evts))

        return deviations

    def _check_agent_events(
        self, baseline: AgentBaseline, events: List[Dict]
    ) -> List[Dict[str, Any]]:
        """Check events for a single agent against its baseline."""
        deviations = []

        # Aggregate current window metrics
        hourly_counts: Dict[str, int] = defaultdict(int)
        daily_sudo_counts: Dict[str, int] = defaultdict(int)
        daily_ips: Dict[str, set] = defaultdict(set)
        daily_fim_counts: Dict[str, int] = defaultdict(int)
        hourly_failed_logins: Dict[str, int] = defaultdict(int)
        hourly_dns_counts: Dict[str, int] = defaultdict(int)
        new_ips: set = set()
        new_processes: set = set()
        # DNS exfil tracking
        dns_queries_by_domain: Dict[str, List[str]] = defaultdict(list)
        # Beacon tracking: connection timestamps per destination IP
        dest_ip_timestamps: Dict[str, List[float]] = defaultdict(list)

        for event in events:
            timestamp = event.get("timestamp", "")
            try:
                dt = datetime.fromisoformat(
                    timestamp.replace("+0000", "+00:00").replace("Z", "+00:00")
                )
            except (ValueError, AttributeError):
                continue

            hour_key = dt.strftime("%Y-%m-%d-%H")
            day_key = dt.strftime("%Y-%m-%d")
            hourly_counts[hour_key] += 1

            rule = event.get("rule", {})
            groups = rule.get("groups", [])
            description = rule.get("description", "").lower()
            data = event.get("data", {})

            # Check for logins at unusual hours
            if "authentication_success" in groups or "login" in description:
                z = baseline.login_hour_profile.z_score(float(dt.hour))
                if z > self.z_score_threshold:
                    deviations.append(
                        {
                            "category": "login_anomaly",
                            "subcategory": "unusual_hour",
                            "agent_id": baseline.agent_id,
                            "agent_name": baseline.agent_name,
                            "z_score": round(z, 2),
                            "detail": f"Login at hour {dt.hour}:00 (baseline mean: {baseline.login_hour_profile.mean:.1f}, std: {baseline.login_hour_profile.std_dev:.1f})",
                            "event": event,
                        }
                    )

            # Check for new/unknown source IPs
            src_ip = data.get("srcip", "") or data.get("src_ip", "")
            if src_ip and src_ip not in baseline.known_source_ips:
                new_ips.add(src_ip)
                daily_ips[day_key].add(src_ip)

            # Track destination IPs for beacon detection
            dst_ip = data.get("dstip", "") or data.get("dst_ip", "")
            if dst_ip:
                dest_ip_timestamps[dst_ip].append(dt.timestamp())

            # Check for new/unknown processes
            process = data.get("process", "") or data.get("program_name", "")
            if process and process not in baseline.known_processes:
                new_processes.add(process)

            # Track sudo
            if "sudo" in description or "privilege_escalation" in groups:
                daily_sudo_counts[day_key] += 1
                cmd = data.get("command", "")
                if cmd and cmd not in baseline.known_sudo_commands:
                    deviations.append(
                        {
                            "category": "privilege_anomaly",
                            "subcategory": "new_sudo_command",
                            "agent_id": baseline.agent_id,
                            "agent_name": baseline.agent_name,
                            "z_score": 3.0,
                            "detail": f"New sudo command never seen before: {cmd}",
                            "event": event,
                        }
                    )

            # Track FIM
            if "syscheck" in groups or "file_integrity" in description:
                daily_fim_counts[day_key] += 1

            # Track failed logins
            if "authentication_failed" in groups or "failed" in description:
                hourly_failed_logins[hour_key] += 1

            # Track DNS queries for exfil detection
            if "dns" in description or "dns" in " ".join(groups).lower():
                hourly_dns_counts[hour_key] += 1
                query_name = data.get("query", "") or data.get("dns_query", "")
                if query_name:
                    base_domain = self._extract_base_domain(query_name)
                    dns_queries_by_domain[base_domain].append(query_name)

        # Check event volume per hour
        for hour_key, count in hourly_counts.items():
            z = baseline.events_per_hour_profile.z_score(float(count))
            if z > self.z_score_threshold:
                deviations.append(
                    {
                        "category": "volume_anomaly",
                        "subcategory": "event_spike",
                        "agent_id": baseline.agent_id,
                        "agent_name": baseline.agent_name,
                        "z_score": round(z, 2),
                        "detail": f"Event volume spike: {count} events/hour (baseline mean: {baseline.events_per_hour_profile.mean:.1f}, std: {baseline.events_per_hour_profile.std_dev:.1f})",
                        "event": None,
                    }
                )

        # Check sudo frequency
        for day_key, count in daily_sudo_counts.items():
            z = baseline.sudo_per_day_profile.z_score(float(count))
            if z > self.z_score_threshold:
                deviations.append(
                    {
                        "category": "privilege_anomaly",
                        "subcategory": "sudo_spike",
                        "agent_id": baseline.agent_id,
                        "agent_name": baseline.agent_name,
                        "z_score": round(z, 2),
                        "detail": f"Elevated sudo usage: {count} commands/day (baseline mean: {baseline.sudo_per_day_profile.mean:.1f})",
                        "event": None,
                    }
                )

        # Check failed login frequency
        for hour_key, count in hourly_failed_logins.items():
            z = baseline.failed_logins_per_hour_profile.z_score(float(count))
            if z > self.z_score_threshold:
                deviations.append(
                    {
                        "category": "login_anomaly",
                        "subcategory": "failed_login_spike",
                        "agent_id": baseline.agent_id,
                        "agent_name": baseline.agent_name,
                        "z_score": round(z, 2),
                        "detail": f"Failed login spike: {count}/hour (baseline mean: {baseline.failed_logins_per_hour_profile.mean:.1f})",
                        "event": None,
                    }
                )

        # Check FIM change rate
        for day_key, count in daily_fim_counts.items():
            z = baseline.fim_changes_per_day_profile.z_score(float(count))
            if z > self.z_score_threshold:
                deviations.append(
                    {
                        "category": "file_integrity_anomaly",
                        "subcategory": "fim_spike",
                        "agent_id": baseline.agent_id,
                        "agent_name": baseline.agent_name,
                        "z_score": round(z, 2),
                        "detail": f"File integrity change spike: {count} changes/day (baseline mean: {baseline.fim_changes_per_day_profile.mean:.1f})",
                        "event": None,
                    }
                )

        # Report new IPs
        if new_ips:
            deviations.append(
                {
                    "category": "network_anomaly",
                    "subcategory": "new_source_ip",
                    "agent_id": baseline.agent_id,
                    "agent_name": baseline.agent_name,
                    "z_score": 2.5,
                    "detail": f"Connections from {len(new_ips)} previously unseen IP(s): {', '.join(list(new_ips)[:5])}",
                    "event": None,
                }
            )

        # Report new processes
        if new_processes:
            deviations.append(
                {
                    "category": "process_anomaly",
                    "subcategory": "new_process",
                    "agent_id": baseline.agent_id,
                    "agent_name": baseline.agent_name,
                    "z_score": 2.5,
                    "detail": f"New process(es) never seen before: {', '.join(list(new_processes)[:5])}",
                    "event": None,
                }
            )

        # === BEACON DETECTION ===
        for dst_ip, timestamps in dest_ip_timestamps.items():
            if len(timestamps) >= 5:  # Need enough connections to detect periodicity
                timestamps.sort()
                intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
                if not intervals:
                    continue
                mean_interval = sum(intervals) / len(intervals)
                interval_std = self._std_dev(intervals)

                # A beacon has very regular intervals → low std dev relative to mean
                # Coefficient of variation < 0.15 with at least 5 connections is suspicious
                if mean_interval > 0:
                    cv = interval_std / mean_interval  # coefficient of variation
                    is_periodic = cv < 0.15 and len(timestamps) >= 5
                    is_new_dest = dst_ip not in baseline.known_dest_ips

                    if is_periodic:
                        interval_min = mean_interval / 60.0
                        deviations.append(
                            {
                                "category": "beacon_anomaly",
                                "subcategory": "periodic_beacon",
                                "agent_id": baseline.agent_id,
                                "agent_name": baseline.agent_name,
                                "z_score": max(4.0, 6.0 - cv * 20),  # Lower CV = higher score
                                "detail": f"Periodic beaconing to {dst_ip}: {len(timestamps)} connections at ~{interval_min:.1f}min intervals (CV={cv:.3f}){' [NEW destination]' if is_new_dest else ''}",
                                "event": None,
                            }
                        )

        # === DNS EXFILTRATION DETECTION ===
        # Check per-domain query patterns
        for domain, queries in dns_queries_by_domain.items():
            # Detect high-volume queries to a single domain
            if len(queries) > 20:  # More than 20 queries to one domain in the window
                z = baseline.dns_queries_per_hour_profile.z_score(float(len(queries)))
                if z > self.z_score_threshold or len(queries) > 50:
                    deviations.append(
                        {
                            "category": "dns_exfil_anomaly",
                            "subcategory": "dns_volume_spike",
                            "agent_id": baseline.agent_id,
                            "agent_name": baseline.agent_name,
                            "z_score": round(max(z, 3.5), 2),
                            "detail": f"High-volume DNS queries to {domain}: {len(queries)} queries (potential tunneling/exfiltration)",
                            "event": None,
                        }
                    )

            # Detect high-entropy subdomains (encoded data in DNS queries)
            long_queries = [q for q in queries if len(q) > 50]
            high_entropy_queries = [q for q in queries if self._subdomain_entropy(q) > 3.5]

            if len(high_entropy_queries) >= 3:
                avg_entropy = sum(self._subdomain_entropy(q) for q in high_entropy_queries) / len(high_entropy_queries)
                deviations.append(
                    {
                        "category": "dns_exfil_anomaly",
                        "subcategory": "high_entropy_dns",
                        "agent_id": baseline.agent_id,
                        "agent_name": baseline.agent_name,
                        "z_score": round(min(avg_entropy * 1.5, 8.0), 2),
                        "detail": f"High-entropy DNS subdomains to {domain}: {len(high_entropy_queries)} queries with avg entropy {avg_entropy:.2f} (likely encoded/encrypted data)",
                        "event": None,
                    }
                )

            if len(long_queries) >= 3:
                avg_len = sum(len(q) for q in long_queries) / len(long_queries)
                deviations.append(
                    {
                        "category": "dns_exfil_anomaly",
                        "subcategory": "long_dns_queries",
                        "agent_id": baseline.agent_id,
                        "agent_name": baseline.agent_name,
                        "z_score": round(min(avg_len / 20.0, 7.0), 2),
                        "detail": f"Unusually long DNS queries to {domain}: {len(long_queries)} queries avg {avg_len:.0f} chars (normal <30 chars)",
                        "event": None,
                    }
                )

        # Check DNS query volume per hour (only flag spikes ABOVE baseline, not below)
        for hour_key, count in hourly_dns_counts.items():
            if count > baseline.dns_queries_per_hour_profile.mean:
                z = baseline.dns_queries_per_hour_profile.z_score(float(count))
                if z > self.z_score_threshold:
                    deviations.append(
                        {
                            "category": "dns_exfil_anomaly",
                            "subcategory": "dns_query_spike",
                            "agent_id": baseline.agent_id,
                            "agent_name": baseline.agent_name,
                            "z_score": round(z, 2),
                            "detail": f"DNS query volume spike: {count} queries/hour (baseline mean: {baseline.dns_queries_per_hour_profile.mean:.1f})",
                            "event": None,
                        }
                    )

        return deviations

    def save(self, filepath: str):
        """Save baselines to a JSON file."""
        os.makedirs(os.path.dirname(filepath) if os.path.dirname(filepath) else ".", exist_ok=True)
        data = {
            agent_id: baseline.to_dict()
            for agent_id, baseline in self.baselines.items()
        }
        with open(filepath, "w") as f:
            json.dump(data, f, indent=2)
        logger.info("Saved baselines for %d agents to %s", len(data), filepath)

    def load(self, filepath: str):
        """Load baselines from a JSON file."""
        if not os.path.exists(filepath):
            logger.warning("Baseline file not found: %s", filepath)
            return
        with open(filepath, "r") as f:
            data = json.load(f)
        self.baselines = {
            agent_id: AgentBaseline.from_dict(agent_data)
            for agent_id, agent_data in data.items()
        }
        logger.info("Loaded baselines for %d agents from %s", len(self.baselines), filepath)

    @staticmethod
    def _extract_base_domain(query: str) -> str:
        """Extract the base domain from a FQDN (e.g., 'sub.evil.com' → 'evil.com')."""
        parts = query.rstrip(".").split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return query

    @staticmethod
    def _subdomain_entropy(query: str) -> float:
        """Calculate Shannon entropy of the subdomain portion of a DNS query."""
        parts = query.rstrip(".").split(".")
        if len(parts) <= 2:
            return 0.0
        subdomain = ".".join(parts[:-2])
        if not subdomain:
            return 0.0
        freq: Dict[str, int] = defaultdict(int)
        for c in subdomain:
            freq[c] += 1
        length = len(subdomain)
        entropy = -sum((count / length) * math.log2(count / length) for count in freq.values())
        return entropy

    @staticmethod
    def _std_dev(values: List[float]) -> float:
        """Calculate standard deviation of a list of values."""
        if len(values) < 2:
            return 0.0
        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / (len(values) - 1)
        return variance ** 0.5


def generate_mock_baselines() -> BaselineEngine:
    """
    Generate realistic mock baselines for demo mode.
    Simulates 30 days of normal activity across 3 agents.
    """
    engine = BaselineEngine()

    agents = [
        ("000", "wazuh-server"),
        ("001", "linux-endpoint"),
        ("002", "windows-endpoint"),
    ]

    for agent_id, agent_name in agents:
        baseline = engine._get_or_create_baseline(agent_id, agent_name)

        # Login hours: typically 8am-6pm
        for _ in range(30):
            for hour in [8, 9, 10, 11, 12, 13, 14, 15, 16, 17]:
                baseline.login_hour_profile.update(float(hour + (hash(agent_id) % 3) - 1))

        # Events per hour: 10-50 normally
        import random
        rng = random.Random(42 + int(agent_id))
        for _ in range(720):  # 30 days * 24 hours
            baseline.events_per_hour_profile.update(float(rng.randint(10, 50)))

        # Sudo per day: 2-8 for server, 0-3 for endpoints
        sudo_range = (2, 8) if agent_id == "000" else (0, 3)
        for _ in range(30):
            baseline.sudo_per_day_profile.update(float(rng.randint(*sudo_range)))

        # Unique IPs per day
        for _ in range(30):
            baseline.unique_ips_per_day_profile.update(float(rng.randint(1, 5)))

        # FIM changes per day
        for _ in range(30):
            baseline.fim_changes_per_day_profile.update(float(rng.randint(0, 10)))

        # Failed logins per hour
        for _ in range(720):
            baseline.failed_logins_per_hour_profile.update(float(rng.randint(0, 2)))

        # DNS queries per hour: low normal rate (5-20)
        for _ in range(720):
            baseline.dns_queries_per_hour_profile.update(float(rng.randint(5, 20)))

        # DNS query length: normal queries are 15-35 chars
        for _ in range(200):
            baseline.dns_query_length_profile.update(float(rng.randint(15, 35)))

        # Outbound connection interval std dev: normal traffic is irregular (high std)
        for _ in range(50):
            baseline.outbound_conn_interval_profile.update(float(rng.uniform(30.0, 600.0)))

        # Known-good sets
        baseline.known_source_ips = {"10.0.1.100", "10.0.1.142", "10.0.2.155", "10.0.2.156"}
        baseline.known_dest_ips = {"10.0.1.1", "8.8.8.8", "1.1.1.1", "169.254.169.254"}
        baseline.known_processes = {
            "sshd", "systemd", "wazuh-agentd", "wazuh-modulesd", "cron",
            "bash", "python3", "apt-get", "dpkg", "sudo",
        }
        baseline.known_users = {"ubuntu", "root", "wazuh"}
        baseline.known_sudo_commands = {
            "/usr/bin/systemctl restart wazuh-manager",
            "/usr/bin/apt-get update",
            "/usr/bin/apt-get upgrade -y",
            "/bin/cat /var/log/auth.log",
        }
        baseline.known_dns_domains = {
            "ubuntu.com", "amazonaws.com", "wazuh.com", "google.com",
            "cloudflare.com", "debian.org",
        }

    return engine


def generate_mock_anomalous_events() -> List[Dict[str, Any]]:
    """
    Generate mock events that contain anomalies for demo purposes.
    Mix of normal events + anomalous events that should trigger detections.
    """
    now = datetime.utcnow()

    events = []

    # === NORMAL EVENTS (should not trigger) ===
    for i in range(20):
        events.append(
            {
                "timestamp": (now - timedelta(hours=i % 8, minutes=i * 3)).strftime(
                    "%Y-%m-%dT%H:%M:%S.000+0000"
                ),
                "rule": {
                    "level": 3,
                    "description": "Sudo command executed",
                    "id": "200020",
                    "groups": ["local", "syslog", "privilege_escalation"],
                },
                "agent": {"id": "000", "name": "wazuh-server", "ip": "10.0.1.142"},
                "data": {
                    "srcuser": "ubuntu",
                    "dstuser": "root",
                    "command": "/usr/bin/systemctl restart wazuh-manager",
                    "srcip": "10.0.1.100",
                    "process": "sudo",
                },
            }
        )

    # === ANOMALOUS EVENTS ===

    # 1. Login at 3 AM (unusual hour)
    events.append(
        {
            "timestamp": now.replace(hour=3, minute=15).strftime(
                "%Y-%m-%dT%H:%M:%S.000+0000"
            ),
            "rule": {
                "level": 3,
                "description": "Successful login",
                "id": "5501",
                "groups": ["authentication_success", "syslog", "sshd"],
            },
            "agent": {"id": "001", "name": "linux-endpoint", "ip": "10.0.2.155"},
            "data": {
                "srcuser": "ubuntu",
                "srcip": "203.0.113.45",
                "process": "sshd",
            },
        }
    )

    # 2. Connection from unknown IP
    events.append(
        {
            "timestamp": (now - timedelta(hours=1)).strftime(
                "%Y-%m-%dT%H:%M:%S.000+0000"
            ),
            "rule": {
                "level": 5,
                "description": "SSH connection established",
                "id": "5715",
                "groups": ["syslog", "sshd"],
            },
            "agent": {"id": "001", "name": "linux-endpoint", "ip": "10.0.2.155"},
            "data": {
                "srcip": "198.51.100.77",
                "process": "sshd",
            },
        }
    )

    # 3. Never-before-seen process
    events.append(
        {
            "timestamp": (now - timedelta(minutes=30)).strftime(
                "%Y-%m-%dT%H:%M:%S.000+0000"
            ),
            "rule": {
                "level": 7,
                "description": "Process execution detected",
                "id": "100050",
                "groups": ["local", "process_monitor"],
            },
            "agent": {"id": "001", "name": "linux-endpoint", "ip": "10.0.2.155"},
            "data": {
                "process": "nmap",
                "srcuser": "ubuntu",
            },
        }
    )

    # 4. New sudo command never seen before
    events.append(
        {
            "timestamp": (now - timedelta(minutes=25)).strftime(
                "%Y-%m-%dT%H:%M:%S.000+0000"
            ),
            "rule": {
                "level": 5,
                "description": "Sudo command executed",
                "id": "200020",
                "groups": ["local", "syslog", "privilege_escalation"],
            },
            "agent": {"id": "001", "name": "linux-endpoint", "ip": "10.0.2.155"},
            "data": {
                "srcuser": "ubuntu",
                "dstuser": "root",
                "command": "/usr/bin/cat /etc/shadow",
                "process": "sudo",
            },
        }
    )

    # 5. Burst of failed logins (20 in one hour)
    for i in range(20):
        events.append(
            {
                "timestamp": (now - timedelta(minutes=i * 2)).strftime(
                    "%Y-%m-%dT%H:%M:%S.000+0000"
                ),
                "rule": {
                    "level": 5,
                    "description": "Authentication failed",
                    "id": "5503",
                    "groups": ["authentication_failed", "syslog", "sshd"],
                },
                "agent": {"id": "002", "name": "windows-endpoint", "ip": "10.0.2.156"},
                "data": {
                    "srcip": "203.0.113.99",
                    "srcuser": "admin",
                    "process": "sshd",
                },
            }
        )

    # 6. FIM spike — 30 file changes in one day
    for i in range(30):
        events.append(
            {
                "timestamp": (now - timedelta(hours=i % 12, minutes=i * 2)).strftime(
                    "%Y-%m-%dT%H:%M:%S.000+0000"
                ),
                "rule": {
                    "level": 7,
                    "description": "File integrity change detected",
                    "id": "550",
                    "groups": ["syscheck", "file_integrity"],
                },
                "agent": {"id": "001", "name": "linux-endpoint", "ip": "10.0.2.155"},
                "data": {
                    "path": f"/etc/config_{i}.conf",
                },
            }
        )

    # === NEW: C2 BEACON ===
    # 7. Periodic beaconing — connections to same C2 IP every ~5 minutes (low jitter)
    c2_ip = "185.220.101.42"
    for i in range(12):  # 12 connections over ~60 minutes
        # Add small jitter (±10 seconds) to simulate realistic beacon
        jitter_sec = (hash(f"beacon_{i}") % 20) - 10
        events.append(
            {
                "timestamp": (now - timedelta(minutes=60 - i * 5, seconds=jitter_sec)).strftime(
                    "%Y-%m-%dT%H:%M:%S.000+0000"
                ),
                "rule": {
                    "level": 3,
                    "description": "Outbound connection detected",
                    "id": "100100",
                    "groups": ["network", "firewall"],
                },
                "agent": {"id": "001", "name": "linux-endpoint", "ip": "10.0.2.155"},
                "data": {
                    "srcip": "10.0.2.155",
                    "dstip": c2_ip,
                    "dstport": "443",
                    "protocol": "tcp",
                    "process": "svchost",
                },
            }
        )

    # === NEW: DNS EXFILTRATION ===
    # 8. High-entropy subdomain queries (data encoded in DNS labels)
    import random as _rng
    _rng.seed(1337)
    exfil_domain = "cdn-static.evil-analytics.com"
    for i in range(25):
        # Generate base64-like encoded subdomain (simulating exfiltrated data chunks)
        encoded_data = ''.join(_rng.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=_rng.randint(30, 55)))
        query_name = f"{encoded_data}.{exfil_domain}"
        events.append(
            {
                "timestamp": (now - timedelta(minutes=i * 2)).strftime(
                    "%Y-%m-%dT%H:%M:%S.000+0000"
                ),
                "rule": {
                    "level": 3,
                    "description": "DNS query detected",
                    "id": "100200",
                    "groups": ["dns", "network"],
                },
                "agent": {"id": "001", "name": "linux-endpoint", "ip": "10.0.2.155"},
                "data": {
                    "query": query_name,
                    "dns_query": query_name,
                    "query_type": "TXT" if i % 3 == 0 else "A",
                    "process": "unknown_binary",
                },
            }
        )

    # 9. Normal DNS queries (should NOT trigger — for contrast)
    normal_domains = ["google.com", "ubuntu.com", "amazonaws.com", "wazuh.com"]
    for i, domain in enumerate(normal_domains):
        events.append(
            {
                "timestamp": (now - timedelta(hours=i + 1)).strftime(
                    "%Y-%m-%dT%H:%M:%S.000+0000"
                ),
                "rule": {
                    "level": 1,
                    "description": "DNS query detected",
                    "id": "100200",
                    "groups": ["dns", "network"],
                },
                "agent": {"id": "001", "name": "linux-endpoint", "ip": "10.0.2.155"},
                "data": {
                    "query": f"www.{domain}",
                    "dns_query": f"www.{domain}",
                    "query_type": "A",
                    "process": "systemd-resolved",
                },
            }
        )

    return events
