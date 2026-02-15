#!/usr/bin/env python3
"""
Alert Enricher - Gathers additional context for security alerts.
Includes threat intelligence, geolocation, historical analysis, and RAG indexing.
"""

import os
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List

# RAG Integration
try:
    from vector_store import VectorStore, get_vector_store
    from embedding_service import EmbeddingService, get_embedding_service

    RAG_AVAILABLE = True
except ImportError:
    RAG_AVAILABLE = False

# Logger
logger = logging.getLogger(__name__)


class ThreatIntelligenceClient:
    """
    Client for threat intelligence lookups.
    Supports AbuseIPDB, VirusTotal, and other sources.
    """

    def __init__(self):
        self.abuseipdb_key = os.environ.get("ABUSEIPDB_API_KEY")
        self.virustotal_key = os.environ.get("VIRUSTOTAL_API_KEY")

    def lookup_ip(self, ip: str) -> Dict[str, Any]:
        """
        Look up threat intelligence for an IP address.

        Args:
            ip: IP address to look up

        Returns:
            Threat intelligence data
        """
        if self.abuseipdb_key:
            return self._abuseipdb_lookup(ip)
        else:
            return self._mock_lookup(ip)

    def _abuseipdb_lookup(self, ip: str) -> Dict[str, Any]:
        """Query AbuseIPDB for IP reputation."""
        try:
            import requests

            headers = {"Key": self.abuseipdb_key, "Accept": "application/json"}
            params = {"ipAddress": ip, "maxAgeInDays": 90}

            response = requests.get(
                "https://api.abuseipdb.com/api/v2/check", headers=headers, params=params
            )

            if response.status_code == 200:
                data = response.json().get("data", {})
                return {
                    "ip": ip,
                    "is_malicious": data.get("abuseConfidenceScore", 0) > 25,
                    "confidence": data.get("abuseConfidenceScore", 0),
                    "reports": data.get("totalReports", 0),
                    "country": data.get("countryCode", "Unknown"),
                    "isp": data.get("isp", "Unknown"),
                    "domain": data.get("domain", "Unknown"),
                    "last_reported": data.get("lastReportedAt"),
                    "usage_type": data.get("usageType", "Unknown"),
                    "source": "AbuseIPDB",
                }
        except Exception as e:
            logger = logging.getLogger(__name__)
            logger.warning(f"AbuseIPDB lookup failed for {ip}: {e}")

        return self._mock_lookup(ip)

    def _mock_lookup(self, ip: str) -> Dict[str, Any]:
        """Return mock threat intelligence data for demo purposes."""
        # Simulate known malicious IPs
        known_bad = {
            "203.0.113.45": {
                "is_malicious": True,
                "confidence": 95,
                "reports": 127,
                "country": "CN",
                "isp": "Example ISP",
                "last_reported": datetime.now().isoformat(),
            },
            "198.51.100.23": {
                "is_malicious": True,
                "confidence": 78,
                "reports": 45,
                "country": "RU",
                "isp": "Another ISP",
                "last_reported": datetime.now().isoformat(),
            },
        }

        if ip in known_bad:
            return {"ip": ip, "source": "Mock TI", **known_bad[ip]}

        return {
            "ip": ip,
            "is_malicious": False,
            "confidence": 0,
            "reports": 0,
            "country": "Unknown",
            "isp": "Unknown",
            "source": "Mock TI",
        }

    def lookup_hash(self, file_hash: str) -> Dict[str, Any]:
        """Look up threat intelligence for a file hash."""
        return {
            "hash": file_hash,
            "is_malicious": False,
            "detections": 0,
            "total_engines": 70,
            "first_seen": None,
            "last_seen": None,
            "source": "Mock TI",
        }

    def lookup_domain(self, domain: str) -> Dict[str, Any]:
        """Look up threat intelligence for a domain."""
        return {
            "domain": domain,
            "is_malicious": False,
            "category": "Unknown",
            "registrar": "Unknown",
            "creation_date": None,
            "source": "Mock TI",
        }


class GeoIPClient:
    """Client for IP geolocation lookups."""

    def __init__(self):
        pass

    def lookup(self, ip: str) -> Dict[str, Any]:
        """
        Get geolocation data for an IP address.

        Args:
            ip: IP address to geolocate

        Returns:
            Geolocation data
        """
        # Mock geolocation data
        mock_data = {
            "203.0.113.45": {
                "country": "China",
                "country_code": "CN",
                "region": "Beijing",
                "city": "Beijing",
                "latitude": 39.9042,
                "longitude": 116.4074,
                "timezone": "Asia/Shanghai",
            },
            "198.51.100.23": {
                "country": "Russia",
                "country_code": "RU",
                "region": "Moscow",
                "city": "Moscow",
                "latitude": 55.7558,
                "longitude": 37.6173,
                "timezone": "Europe/Moscow",
            },
        }

        if ip in mock_data:
            return mock_data[ip]

        return {
            "country": "Unknown",
            "country_code": "XX",
            "region": "Unknown",
            "city": "Unknown",
            "latitude": None,
            "longitude": None,
            "timezone": "Unknown",
        }


class HistoricalAnalyzer:
    """Analyzes historical events for pattern detection."""

    def __init__(self, wazuh_client=None):
        self.wazuh_client = wazuh_client

    def get_related_events(
        self,
        source_ip: str = None,
        user: str = None,
        agent: str = None,
        hours: int = 24,
    ) -> Dict[str, Any]:
        """
        Get related historical events.

        Args:
            source_ip: Source IP to search for
            user: Username to search for
            agent: Agent name to search for
            hours: Number of hours to look back

        Returns:
            Historical event analysis
        """
        # In production, this would query Wazuh API
        # For now, return mock data
        return {
            "total_events": 47,
            "unique_rules": 3,
            "first_seen": (datetime.now() - timedelta(hours=2)).isoformat(),
            "last_seen": datetime.now().isoformat(),
            "event_timeline": [
                {"time": "-2h", "count": 15, "rule": "100001"},
                {"time": "-1h", "count": 20, "rule": "100001"},
                {"time": "-30m", "count": 12, "rule": "100001"},
            ],
            "related_sources": [{"ip": source_ip, "count": 47}] if source_ip else [],
            "attack_progression": "Sustained brute force attack over 2 hours",
        }

    def detect_patterns(self, events: List[Dict]) -> Dict[str, Any]:
        """Detect patterns in event data."""
        return {
            "pattern_detected": True,
            "pattern_type": "brute_force",
            "confidence": 0.95,
            "description": "Repeated authentication failures consistent with automated attack",
        }


class AlertEnricher:
    """
    Main class for enriching security alerts with additional context.
    Combines threat intelligence, geolocation, historical analysis, and RAG indexing.
    """

    def __init__(self, enable_rag_indexing: bool = True):
        self.threat_intel = ThreatIntelligenceClient()
        self.geoip = GeoIPClient()
        self.history = HistoricalAnalyzer()

        # RAG indexing
        self.enable_rag_indexing = enable_rag_indexing and RAG_AVAILABLE
        self._vector_store = None
        self._embedding_service = None

        if self.enable_rag_indexing:
            try:
                self._embedding_service = get_embedding_service()
                self._vector_store = get_vector_store(
                    embedding_dimension=self._embedding_service.dimension
                )
                logger.info("RAG indexing enabled for alert enrichment")
            except Exception as e:
                logger.warning(f"Failed to initialize RAG indexing: {e}")
                self.enable_rag_indexing = False

    def enrich(
        self, alert: Dict[str, Any], index_for_rag: bool = None
    ) -> Dict[str, Any]:
        """
        Enrich an alert with additional context and optionally index for RAG.

        Args:
            alert: The raw Wazuh alert
            index_for_rag: Whether to index this alert for future RAG retrieval
                          (default: True if RAG is enabled and alert meets criteria)

        Returns:
            Enriched context dictionary
        """
        context = {
            "enrichment_timestamp": datetime.now().isoformat(),
            "enrichment_sources": [],
        }

        # Extract key fields from alert
        data = alert.get("data", {})
        src_ip = data.get("srcip") or data.get("src_ip")
        user = data.get("dstuser") or data.get("user")
        agent = alert.get("agent", {}).get("name")

        # Threat Intelligence
        if src_ip:
            ti_data = self.threat_intel.lookup_ip(src_ip)
            context["threat_intel"] = ti_data
            context["enrichment_sources"].append("threat_intel")

            # Geolocation
            geo_data = self.geoip.lookup(src_ip)
            context["geolocation"] = geo_data
            context["enrichment_sources"].append("geolocation")

        # Historical Analysis
        history_data = self.history.get_related_events(
            source_ip=src_ip, user=user, agent=agent
        )
        context["historical"] = history_data
        context["related_events"] = history_data.get("total_events", 0)
        context["first_seen"] = history_data.get("first_seen")
        context["enrichment_sources"].append("historical")

        # Risk Score Calculation
        context["risk_score"] = self._calculate_risk_score(alert, context)

        # Attack Classification
        context["attack_classification"] = self._classify_attack(alert, context)

        # Index for RAG if enabled
        should_index = (
            index_for_rag if index_for_rag is not None else self.enable_rag_indexing
        )
        if should_index and self._should_index_alert(alert):
            rag_result = self._index_alert_for_rag(alert)
            context["rag_indexed"] = rag_result
            if rag_result:
                context["enrichment_sources"].append("rag_indexed")

        return context

    def _should_index_alert(self, alert: Dict[str, Any]) -> bool:
        """
        Determine if an alert should be indexed for RAG based on criteria.

        Args:
            alert: The Wazuh alert

        Returns:
            True if alert should be indexed
        """
        # Minimum severity threshold
        severity = alert.get("rule", {}).get("level", 0)
        if severity < 5:  # Only index alerts with level >= 5
            return False

        # Check if OpenSearch is connected
        if not self._vector_store or not self._vector_store.is_connected():
            return False

        return True

    def _index_alert_for_rag(self, alert: Dict[str, Any]) -> bool:
        """
        Index an alert for RAG retrieval.

        Args:
            alert: The Wazuh alert to index

        Returns:
            True if indexed successfully
        """
        if not self._vector_store or not self._embedding_service:
            return False

        try:
            # Generate embedding
            embedding = self._embedding_service.embed_alert(alert)

            # Index in vector store
            success = self._vector_store.index_alert(alert, embedding)

            if success:
                logger.debug(f"Indexed alert {alert.get('id')} for RAG")

            return success

        except Exception as e:
            logger.error(f"Failed to index alert for RAG: {e}")
            return False

    def get_rag_status(self) -> Dict[str, Any]:
        """
        Get the current RAG indexing status.

        Returns:
            Dictionary with RAG status information
        """
        status = {
            "rag_available": RAG_AVAILABLE,
            "rag_enabled": self.enable_rag_indexing,
            "vector_store_connected": False,
        }

        if self._vector_store:
            status["vector_store_connected"] = self._vector_store.is_connected()
            if status["vector_store_connected"]:
                try:
                    stats = self._vector_store.get_stats()
                    status["vector_store_stats"] = stats
                except Exception as e:
                    status["vector_store_error"] = str(e)

        return status

    def _calculate_risk_score(
        self, alert: Dict[str, Any], context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Calculate a risk score based on all available data.

        Returns a score from 0-100 with contributing factors.
        """
        score = 0
        factors = []

        # Base score from alert severity
        severity = alert.get("rule", {}).get("level", 0)
        severity_score = min(severity * 5, 40)  # Max 40 points
        score += severity_score
        factors.append(f"Alert severity ({severity}): +{severity_score}")

        # Threat intelligence score
        ti = context.get("threat_intel", {})
        if ti.get("is_malicious"):
            ti_score = min(ti.get("confidence", 0) / 2, 30)  # Max 30 points
            score += ti_score
            factors.append(f"Threat intel match: +{ti_score:.0f}")

        # Historical activity score
        history = context.get("historical", {})
        event_count = history.get("total_events", 0)
        if event_count > 10:
            history_score = min(event_count / 5, 20)  # Max 20 points
            score += history_score
            factors.append(
                f"Repeated activity ({event_count} events): +{history_score:.0f}"
            )

        # Geographic risk
        geo = context.get("geolocation", {})
        high_risk_countries = ["CN", "RU", "KP", "IR"]
        if geo.get("country_code") in high_risk_countries:
            score += 10
            factors.append(f"High-risk geography ({geo.get('country_code')}): +10")

        return {
            "score": min(score, 100),
            "level": "Critical"
            if score >= 80
            else "High"
            if score >= 60
            else "Medium"
            if score >= 40
            else "Low",
            "factors": factors,
        }

    def _classify_attack(
        self, alert: Dict[str, Any], context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Classify the type of attack based on all available data."""
        rule_desc = alert.get("rule", {}).get("description", "").lower()

        classifications = {
            "brute_force": ["brute force", "failed login", "authentication fail"],
            "credential_theft": ["mimikatz", "credential dump", "lsass", "shadow"],
            "privilege_escalation": ["sudo", "privilege", "escalation", "root"],
            "malware": ["malware", "virus", "trojan", "ransomware"],
            "lateral_movement": ["lateral", "psexec", "remote"],
            "data_exfiltration": ["exfil", "data theft", "upload"],
            "persistence": ["cron", "scheduled task", "service", "registry"],
            "reconnaissance": ["scan", "enumeration", "discovery"],
        }

        for attack_type, keywords in classifications.items():
            if any(kw in rule_desc for kw in keywords):
                return {
                    "type": attack_type,
                    "confidence": 0.85,
                    "description": f"Alert characteristics match {attack_type.replace('_', ' ')} pattern",
                }

        return {
            "type": "unknown",
            "confidence": 0.5,
            "description": "Unable to classify attack type with high confidence",
        }


# Convenience function for quick enrichment
def enrich_alert(alert: Dict[str, Any]) -> Dict[str, Any]:
    """Quick function to enrich an alert."""
    enricher = AlertEnricher()
    return enricher.enrich(alert)


if __name__ == "__main__":
    # Test enrichment
    sample_alert = {
        "timestamp": datetime.now().isoformat(),
        "rule": {
            "id": "100001",
            "level": 10,
            "description": "SSH brute force attack detected",
        },
        "agent": {"name": "linux-endpoint-01"},
        "data": {"srcip": "203.0.113.45", "dstuser": "root"},
    }

    enricher = AlertEnricher()
    context = enricher.enrich(sample_alert)
    print(json.dumps(context, indent=2, default=str))
