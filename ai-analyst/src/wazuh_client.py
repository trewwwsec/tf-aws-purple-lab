#!/usr/bin/env python3
"""
Wazuh API Client - Handles communication with the Wazuh server.
"""

import os
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


class WazuhClient:
    """
    Client for interacting with the Wazuh API.

    Provides methods to:
    - Authenticate with the Wazuh server
    - Retrieve alerts
    - Query historical events
    - Get agent information
    """

    def __init__(
        self,
        host: str = None,
        port: int = 55000,
        user: str = None,
        password: str = None,
        verify_ssl: bool = None,
        runtime_mode: str = "strict",
    ):
        """
        Initialize the Wazuh API client.

        Args:
            host: Wazuh server hostname/IP (default: from WAZUH_HOST env var)
            port: Wazuh API port (default: 55000)
            user: API user (default: from WAZUH_USER env var)
            password: API password (default: from WAZUH_PASSWORD env var)
            verify_ssl: Verify SSL certificates (default: True, or from WAZUH_VERIFY_SSL env var)
            runtime_mode: Runtime mode ('strict' or 'demo')
        """
        self.host = host or os.environ.get("WAZUH_HOST", "localhost")
        self.port = port
        self.user = user or os.environ.get("WAZUH_USER", "wazuh")
        self.password = password or os.environ.get("WAZUH_PASSWORD", "")
        self.verify_ssl = (
            verify_ssl
            if verify_ssl is not None
            else os.environ.get("WAZUH_VERIFY_SSL", "true").lower() == "true"
        )
        self.runtime_mode = runtime_mode
        self.allow_mock = runtime_mode == "demo"
        self.base_url = f"https://{self.host}:{self.port}"
        self.token = None
        self.token_expires = None

    def _get_token(self) -> str:
        """
        Get or refresh the authentication token.

        Returns:
            JWT token for API authentication
        """
        # Check if we have a valid token
        if self.token and self.token_expires:
            if datetime.now() < self.token_expires:
                return self.token

        try:
            import requests
            from requests.auth import HTTPBasicAuth

            response = requests.post(
                f"{self.base_url}/security/user/authenticate",
                auth=HTTPBasicAuth(self.user, self.password),
                verify=self.verify_ssl,
            )

            if response.status_code == 200:
                data = response.json()
                self.token = data.get("data", {}).get("token")
                # Token typically valid for 15 minutes
                self.token_expires = datetime.now() + timedelta(minutes=14)
                return self.token
        except Exception as e:
            if self.allow_mock:
                logger.debug("Wazuh API authentication failed in demo mode: %s", e)
            else:
                logger.error(f"Failed to authenticate with Wazuh API: {e}")

        return None

    def _ensure_token(self) -> Optional[str]:
        """Return a token or raise in strict mode."""
        token = self._get_token()
        if token:
            return token
        if self.allow_mock:
            return None
        raise RuntimeError(
            "Unable to authenticate to Wazuh API in strict mode. "
            "Check WAZUH_HOST/WAZUH_USER/WAZUH_PASSWORD and TLS settings."
        )

    def _request(
        self, method: str, endpoint: str, params: Dict = None, data: Dict = None
    ) -> Dict[str, Any]:
        """
        Make an authenticated request to the Wazuh API.

        Args:
            method: HTTP method (GET, POST, etc.)
            endpoint: API endpoint path
            params: Query parameters
            data: Request body data

        Returns:
            API response as dictionary
        """
        token = self._ensure_token()
        if not token:
            return {"error": "Unable to authenticate", "data": None}

        try:
            import requests

            headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            }

            url = f"{self.base_url}{endpoint}"

            response = requests.request(
                method=method,
                url=url,
                headers=headers,
                params=params,
                json=data,
                verify=self.verify_ssl,
                timeout=30,
            )

            response.raise_for_status()
            parsed = response.json()
            if not isinstance(parsed, dict):
                return {"data": {}}
            return parsed
        except Exception as e:
            if not self.allow_mock:
                raise RuntimeError(f"Wazuh API request failed: {e}")
            return {"error": str(e), "data": None}

    def get_alerts(
        self,
        limit: int = 10,
        offset: int = 0,
        level: int = None,
        rule_id: str = None,
        agent_id: str = None,
        q: str = None,
    ) -> List[Dict[str, Any]]:
        """
        Get alerts from Wazuh.

        Args:
            limit: Maximum number of alerts to return
            offset: Offset for pagination
            level: Minimum alert level
            rule_id: Filter by rule ID
            agent_id: Filter by agent ID
            q: Custom query string

        Returns:
            List of alert dictionaries
        """
        token = self._ensure_token()
        if not token:
            return self._get_mock_alerts(limit)

        params = {"limit": limit, "offset": offset}

        if level:
            params["level"] = level
        if rule_id:
            params["rule.id"] = rule_id
        if agent_id:
            params["agent.id"] = agent_id
        if q:
            params["q"] = q

        response = self._request("GET", "/alerts", params=params)
        return response.get("data", {}).get("affected_items", [])

    def get_alert_by_id(self, alert_id: str) -> Optional[Dict[str, Any]]:
        """Get a specific alert by ID."""
        token = self._ensure_token()
        if not token:
            for alert in self._get_mock_alerts(limit=20):
                if str(alert.get("id")) == str(alert_id):
                    return alert
            return None
        response = self._request("GET", f"/alerts/{alert_id}")
        items = response.get("data", {}).get("affected_items", [])
        return items[0] if items else None

    def get_agent_info(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """Get information about a specific agent."""
        token = self._ensure_token()
        if not token:
            return self._get_mock_agent(agent_id)

        response = self._request("GET", f"/agents/{agent_id}")
        items = response.get("data", {}).get("affected_items", [])
        return items[0] if items else None

    def get_agents(self, status: str = None) -> List[Dict[str, Any]]:
        """Get list of agents."""
        token = self._ensure_token()
        if not token:
            return self._get_mock_agents()

        params = {}
        if status:
            params["status"] = status

        response = self._request("GET", "/agents", params=params)
        return response.get("data", {}).get("affected_items", [])

    def search_events(
        self,
        source_ip: str = None,
        user: str = None,
        agent_id: str = None,
        rule_id: str = None,
        time_range: str = "24h",
    ) -> List[Dict[str, Any]]:
        """
        Search for events matching criteria.

        Args:
            source_ip: Source IP to search for
            user: Username to search for
            agent_id: Agent ID to search
            rule_id: Rule ID to search
            time_range: Time range (e.g., "24h", "7d")

        Returns:
            List of matching events
        """
        token = self._ensure_token()
        if not token:
            return self._get_mock_events(source_ip, user)

        # Build query
        query_parts = []
        if source_ip:
            query_parts.append(f"data.srcip={source_ip}")
        if user:
            query_parts.append(f"data.dstuser={user}")
        if agent_id:
            query_parts.append(f"agent.id={agent_id}")
        if rule_id:
            query_parts.append(f"rule.id={rule_id}")

        q = ";".join(query_parts) if query_parts else None

        return self.get_alerts(limit=100, q=q)

    # Mock data methods for demo/testing
    def _get_mock_alerts(self, limit: int) -> List[Dict[str, Any]]:
        """Return mock alerts for demo purposes."""
        now = datetime.now()

        return [
            {
                "id": "1",
                "timestamp": (now - timedelta(minutes=5)).isoformat(),
                "rule": {
                    "id": "200001",
                    "level": 10,
                    "description": "SSH brute force attack detected",
                    "mitre": {"id": ["T1110"]},
                },
                "agent": {"id": "001", "name": "linux-endpoint-01"},
                "data": {"srcip": "203.0.113.45", "dstuser": "root"},
            },
            {
                "id": "2",
                "timestamp": (now - timedelta(minutes=10)).isoformat(),
                "rule": {
                    "id": "200010",
                    "level": 12,
                    "description": "PowerShell encoded command detected",
                    "mitre": {"id": ["T1059.001"]},
                },
                "agent": {"id": "002", "name": "windows-endpoint-01"},
                "data": {"user": "admin", "command": "powershell -enc..."},
            },
            {
                "id": "3",
                "timestamp": (now - timedelta(minutes=15)).isoformat(),
                "rule": {
                    "id": "200021",
                    "level": 10,
                    "description": "Sudo abuse - shell escalation",
                    "mitre": {"id": ["T1548.003"]},
                },
                "agent": {"id": "001", "name": "linux-endpoint-01"},
                "data": {"dstuser": "developer", "command": "sudo bash"},
            },
        ][:limit]

    def _get_mock_agent(self, agent_id: str) -> Dict[str, Any]:
        """Return mock agent info."""
        agents = {
            "001": {
                "id": "001",
                "name": "linux-endpoint-01",
                "ip": "10.0.2.155",
                "os": {"name": "Ubuntu", "version": "22.04"},
                "status": "active",
                "lastKeepAlive": datetime.now().isoformat(),
            },
            "002": {
                "id": "002",
                "name": "windows-endpoint-01",
                "ip": "10.0.2.156",
                "os": {"name": "Windows", "version": "Server 2022"},
                "status": "active",
                "lastKeepAlive": datetime.now().isoformat(),
            },
        }
        return agents.get(agent_id, {"id": agent_id, "name": "Unknown"})

    def _get_mock_agents(self) -> List[Dict[str, Any]]:
        """Return list of mock agents."""
        return [self._get_mock_agent("001"), self._get_mock_agent("002")]

    def _get_mock_events(
        self, source_ip: str = None, user: str = None
    ) -> List[Dict[str, Any]]:
        """Return mock events for demo purposes."""
        now = datetime.now()
        events = []

        if source_ip == "203.0.113.45":
            # Generate SSH brute force event history
            for i in range(47):
                events.append(
                    {
                        "timestamp": (now - timedelta(minutes=i * 2)).isoformat(),
                        "rule": {
                            "id": "5551",
                            "description": "SSH authentication failed",
                        },
                        "data": {"srcip": source_ip, "dstuser": "root"},
                    }
                )

        return events


if __name__ == "__main__":
    # Test client
    client = WazuhClient()

    print("Testing Wazuh Client (mock mode)...")

    # Get alerts
    alerts = client.get_alerts(limit=5)
    print(f"\nRecent Alerts ({len(alerts)}):")
    for alert in alerts:
        print(f"  - {alert['rule']['id']}: {alert['rule']['description']}")

    # Get agents
    agents = client.get_agents()
    print(f"\nAgents ({len(agents)}):")
    for agent in agents:
        print(f"  - {agent['name']} ({agent['ip']})")

    # Search events
    events = client.search_events(source_ip="203.0.113.45")
    print(f"\nEvents from 203.0.113.45: {len(events)}")
