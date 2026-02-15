#!/usr/bin/env python3
"""
AI Client - Handles communication with LLM providers for alert analysis.
Supports OpenAI, Anthropic Claude, and local Ollama.

Now with RAG (Retrieval-Augmented Generation) integration for enhanced context.
"""

import os
import json
import logging
from typing import Dict, Any, Optional, List
from abc import ABC, abstractmethod

# RAG Integration
try:
    from rag_retriever import get_rag_retriever, RAGRetriever

    RAG_AVAILABLE = True
except ImportError:
    RAG_AVAILABLE = False

logger = logging.getLogger(__name__)


class BaseLLMClient(ABC):
    """Abstract base class for LLM clients."""

    @abstractmethod
    def generate(self, prompt: str, system_prompt: str = None) -> str:
        """Generate a response from the LLM."""
        pass

    def _mock_response(self, prompt: str = "") -> str:
        """
        Return a mock response when the LLM API is not available.

        This default implementation can be overridden by subclasses.
        """
        return json.dumps(
            {
                "title": "Security Alert Detected",
                "summary": "A security event was detected that requires investigation.",
                "investigation_steps": [
                    "Review the alert details",
                    "Check related events",
                    "Assess potential impact",
                ],
                "recommended_actions": [
                    "[IMMEDIATE] Investigate the alert",
                    "[SHORT-TERM] Review security controls",
                    "[LONG-TERM] Update detection rules",
                ],
            }
        )


class OpenAIClient(BaseLLMClient):
    """OpenAI API client."""

    def __init__(self, model: str = "gpt-4", temperature: float = 0.3):
        self.model = model
        self.temperature = temperature
        self.api_key = os.environ.get("OPENAI_API_KEY")

        if self.api_key:
            try:
                import openai

                self.client = openai.OpenAI(api_key=self.api_key)
            except ImportError:
                self.client = None
        else:
            self.client = None

    def generate(self, prompt: str, system_prompt: str = None) -> str:
        if not self.client:
            return self._mock_response(prompt)

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        response = self.client.chat.completions.create(
            model=self.model, messages=messages, temperature=self.temperature
        )
        return response.choices[0].message.content


class AnthropicClient(BaseLLMClient):
    """Anthropic Claude API client."""

    def __init__(
        self, model: str = "claude-3-sonnet-20240229", temperature: float = 0.3
    ):
        self.model = model
        self.temperature = temperature
        self.api_key = os.environ.get("ANTHROPIC_API_KEY")

        if self.api_key:
            try:
                import anthropic

                self.client = anthropic.Anthropic(api_key=self.api_key)
            except ImportError:
                self.client = None
        else:
            self.client = None

    def generate(self, prompt: str, system_prompt: str = None) -> str:
        if not self.client:
            return self._mock_response(prompt)

        response = self.client.messages.create(
            model=self.model,
            max_tokens=2000,
            system=system_prompt or "You are a security analyst assistant.",
            messages=[{"role": "user", "content": prompt}],
        )
        return response.content[0].text


class OllamaClient(BaseLLMClient):
    """Local Ollama client for running models locally."""

    def __init__(self, model: str = "llama2", host: str = "http://localhost:11434"):
        self.model = model
        self.host = host

    def generate(self, prompt: str, system_prompt: str = None) -> str:
        try:
            import requests

            full_prompt = prompt
            if system_prompt:
                full_prompt = f"{system_prompt}\n\n{prompt}"

            response = requests.post(
                f"{self.host}/api/generate",
                json={"model": self.model, "prompt": full_prompt, "stream": False},
            )
            return response.json().get("response", "")
        except Exception:
            return self._mock_response(prompt)


class AIClient:
    """
    Main AI client that handles LLM interactions for alert analysis.
    Automatically selects the appropriate provider based on available API keys.

    Features RAG (Retrieval-Augmented Generation) for enhanced context from
    historical alerts, threat intelligence, and playbooks.
    """

    def __init__(self, provider: str = None, use_rag: bool = True):
        """
        Initialize the AI client.

        Args:
            provider: Force a specific provider ('openai', 'anthropic', 'ollama')
                     If None, auto-detect based on available API keys.
            use_rag: Enable RAG context retrieval (default: True)
        """
        self.provider = provider or self._detect_provider()
        self.client = self._create_client()
        self.system_prompt = self._load_system_prompt()

        # Initialize RAG retriever if available
        self.use_rag = use_rag and RAG_AVAILABLE
        self.rag_retriever = None
        if self.use_rag:
            try:
                self.rag_retriever = get_rag_retriever()
                logger.info("RAG retriever initialized")
            except Exception as e:
                logger.warning(f"Failed to initialize RAG retriever: {e}")
                self.use_rag = False

    def _detect_provider(self) -> str:
        """Auto-detect which LLM provider to use."""
        if os.environ.get("OPENAI_API_KEY"):
            return "openai"
        elif os.environ.get("ANTHROPIC_API_KEY"):
            return "anthropic"
        else:
            return "mock"  # Fall back to mock responses

    def _create_client(self) -> BaseLLMClient:
        """Create the appropriate LLM client."""
        if self.provider == "openai":
            return OpenAIClient()
        elif self.provider == "anthropic":
            return AnthropicClient()
        elif self.provider == "ollama":
            return OllamaClient()
        else:
            return OpenAIClient()  # Will use mock responses

    def _load_system_prompt(self) -> str:
        """Load the system prompt for alert analysis."""
        return """You are an expert Security Operations Center (SOC) analyst assistant. 
Your role is to analyze security alerts and provide:
1. A clear, meaningful title for the alert
2. A concise summary of what happened (2-3 sentences)
3. Specific investigation steps the analyst should take
4. Recommended containment and response actions

Always consider:
- The MITRE ATT&CK framework context
- Potential false positive scenarios
- Business impact
- Urgency of response

Format your response as JSON with these keys:
- title: A meaningful alert title (not just the rule ID)
- summary: Executive-friendly summary of the incident
- investigation_steps: List of specific steps to investigate
- recommended_actions: List of actions with priority tags [IMMEDIATE], [SHORT-TERM], [LONG-TERM]
"""

    def analyze_alert(
        self,
        alert: Dict[str, Any],
        context: Dict[str, Any] = None,
        mitre_info: Dict[str, str] = None,
        use_rag: bool = None,
    ) -> Dict[str, Any]:
        """
        Analyze a security alert and return structured analysis.

        Args:
            alert: The raw Wazuh alert
            context: Additional context (related events, threat intel, etc.)
            mitre_info: MITRE ATT&CK technique information
            use_rag: Override RAG usage for this analysis (default: use instance setting)

        Returns:
            Dictionary with title, summary, investigation_steps, recommended_actions
        """
        # Determine if we should use RAG for this analysis
        should_use_rag = (
            self.use_rag if use_rag is None else (use_rag and RAG_AVAILABLE)
        )

        # Retrieve RAG context if enabled
        rag_context = None
        if should_use_rag and self.rag_retriever:
            try:
                logger.info("Retrieving RAG context for alert analysis...")
                rag_context = self.rag_retriever.retrieve_context(alert)
                logger.info(
                    f"RAG context retrieved: {rag_context.total_documents} documents"
                )
            except Exception as e:
                logger.warning(f"Failed to retrieve RAG context: {e}")

        # Build the analysis prompt with RAG context
        prompt = self._build_prompt(alert, context, mitre_info, rag_context)

        # Get AI response
        try:
            response = self.client.generate(prompt, self.system_prompt)

            # Parse JSON response
            try:
                # Try to extract JSON from response
                if "```json" in response:
                    json_str = response.split("```json")[1].split("```")[0]
                elif "```" in response:
                    json_str = response.split("```")[1].split("```")[0]
                else:
                    json_str = response

                analysis = json.loads(json_str.strip())
            except json.JSONDecodeError:
                # If JSON parsing fails, create structured response from text
                analysis = self._parse_text_response(response, alert)

        except Exception as e:
            # Fallback to rule-based analysis
            analysis = self._fallback_analysis(alert, context, mitre_info)

        # Add RAG metadata to analysis if used
        if rag_context:
            analysis["rag_context"] = {
                "similar_alerts_count": len(rag_context.similar_alerts),
                "threat_intel_count": len(rag_context.threat_intel),
                "playbooks_count": len(rag_context.relevant_playbooks),
                "retrieved_at": rag_context.retrieved_at,
            }

        return analysis

    def _build_prompt(
        self,
        alert: Dict[str, Any],
        context: Dict[str, Any],
        mitre_info: Dict[str, str],
        rag_context=None,
    ) -> str:
        """Build the prompt for alert analysis, including RAG context if available."""
        rule_id = alert.get("rule", {}).get("id", "unknown")
        rule_desc = alert.get("rule", {}).get("description", "Unknown")
        severity = alert.get("rule", {}).get("level", 0)
        agent = alert.get("agent", {}).get("name", "unknown")

        prompt = f"""Analyze this security alert and provide a structured response.

ALERT DETAILS:
- Rule ID: {rule_id}
- Description: {rule_desc}
- Severity Level: {severity}
- Target System: {agent}
- Timestamp: {alert.get("timestamp", "unknown")}

RAW DATA:
{json.dumps(alert.get("data", {}), indent=2)}
"""

        if mitre_info:
            prompt += f"""
MITRE ATT&CK CONTEXT:
- Technique: {mitre_info.get("name", "Unknown")}
- Tactic: {mitre_info.get("tactic", "Unknown")}
- Description: {mitre_info.get("description", "N/A")}
"""

        # Add RAG context if available
        if rag_context and rag_context.total_documents > 0:
            prompt += f"""
================================================================================
HISTORICAL CONTEXT & THREAT INTELLIGENCE (Retrieved via RAG)
================================================================================

{rag_context.to_prompt_context()}

================================================================================
"""

        if context:
            prompt += f"""
ADDITIONAL CONTEXT:
- Related Events (24h): {context.get("related_events", 0)}
- First Seen: {context.get("first_seen", "Unknown")}
"""
            if context.get("threat_intel"):
                ti = context["threat_intel"]
                prompt += f"- Threat Intel Reports: {ti.get('reports', 0)}\n"
                prompt += f"- Confidence Score: {ti.get('confidence', 0)}%\n"

        prompt += """
INSTRUCTIONS:
1. Use the historical context and threat intelligence above to enrich your analysis
2. Reference similar past incidents and their outcomes if relevant
3. Consider the recommended playbooks for response actions
4. Provide your analysis in JSON format with these keys:
   - title: A meaningful alert title (not just the rule ID)
   - summary: Executive-friendly summary of the incident (include historical context insights)
   - investigation_steps: List of specific steps to investigate (leverage similar past incidents)
   - recommended_actions: List of actions with priority tags [IMMEDIATE], [SHORT-TERM], [LONG-TERM]

Format your response as valid JSON.
"""

        return prompt

    def _parse_text_response(self, response: str, alert: Dict) -> Dict[str, Any]:
        """Parse a text response into structured format."""
        rule_desc = alert.get("rule", {}).get("description", "Security Alert")

        return {
            "title": rule_desc,
            "summary": response[:500] if response else "Analysis unavailable.",
            "investigation_steps": [
                "Review the alert details in Wazuh dashboard",
                "Check for related events from the same source",
                "Verify if this is a known false positive",
            ],
            "recommended_actions": [
                "[IMMEDIATE] Assess the alert severity",
                "[SHORT-TERM] Follow the relevant playbook",
                "[LONG-TERM] Update detection rules if needed",
            ],
        }

    def _fallback_analysis(
        self, alert: Dict[str, Any], context: Dict[str, Any], mitre_info: Dict[str, str]
    ) -> Dict[str, Any]:
        """Generate a rule-based analysis when AI is unavailable."""
        rule_id = str(alert.get("rule", {}).get("id", "unknown"))
        rule_desc = alert.get("rule", {}).get("description", "Security Alert")
        severity = alert.get("rule", {}).get("level", 0)

        # Rule-based title generation
        src_ip = alert.get("data", {}).get("srcip", "")
        user = alert.get("data", {}).get("dstuser", "")

        if "brute force" in rule_desc.lower():
            title = f"SSH Brute Force Attack{f' from {src_ip}' if src_ip else ''}"
        elif "powershell" in rule_desc.lower():
            title = f"Suspicious PowerShell Activity{f' by {user}' if user else ''}"
        elif "sudo" in rule_desc.lower():
            title = f"Privilege Escalation Attempt{f' by {user}' if user else ''}"
        elif "mimikatz" in rule_desc.lower():
            title = f"Credential Dumping (Mimikatz) Detected"
        elif "shadow" in rule_desc.lower():
            title = f"Credential File Access Detected"
        else:
            title = rule_desc

        # Generate summary
        summary = f"Alert {rule_id} was triggered indicating {rule_desc.lower()}. "
        if src_ip:
            summary += f"The activity originated from IP {src_ip}. "
        if user:
            summary += f"The user {user} was involved. "
        summary += "Immediate investigation is recommended based on the severity level."

        # Generate investigation steps based on alert type
        investigation_steps = [
            "Review the full alert details in Wazuh dashboard",
            "Check for related events in the last 24 hours",
        ]

        if src_ip:
            investigation_steps.append(f"Verify if {src_ip} is a known trusted source")
            investigation_steps.append("Check threat intelligence for this IP address")

        if user:
            investigation_steps.append(f"Review recent activity for user {user}")

        # Generate recommended actions based on severity
        recommended_actions = []

        if severity >= 12:
            recommended_actions.append(f"[IMMEDIATE] Isolate affected system")
            recommended_actions.append(f"[IMMEDIATE] Escalate to Incident Commander")
        elif severity >= 10:
            recommended_actions.append(
                f"[IMMEDIATE] Investigate alert within 30 minutes"
            )

        if src_ip:
            recommended_actions.append(f"[IMMEDIATE] Consider blocking IP {src_ip}")

        recommended_actions.append("[SHORT-TERM] Follow incident response playbook")
        recommended_actions.append("[LONG-TERM] Review and tune detection rules")

        return {
            "title": title,
            "summary": summary,
            "investigation_steps": investigation_steps,
            "recommended_actions": recommended_actions,
        }

    def index_alert_for_rag(self, alert: Dict[str, Any]) -> bool:
        """
        Index an alert for future RAG retrieval.

        This allows the alert to be found in future similarity searches.

        Args:
            alert: Wazuh alert dictionary to index

        Returns:
            True if indexed successfully
        """
        if not self.use_rag or not self.rag_retriever:
            logger.warning("RAG not available, cannot index alert")
            return False

        try:
            return self.rag_retriever.index_alert_for_rag(alert)
        except Exception as e:
            logger.error(f"Failed to index alert for RAG: {e}")
            return False

    def get_rag_status(self) -> Dict[str, Any]:
        """
        Get the current RAG status and statistics.

        Returns:
            Dictionary with RAG availability and statistics
        """
        status = {
            "rag_available": self.use_rag and RAG_AVAILABLE,
            "rag_enabled": self.use_rag,
            "retriever_initialized": self.rag_retriever is not None,
        }

        if self.rag_retriever and self.rag_retriever.vector_store:
            try:
                stats = self.rag_retriever.vector_store.get_stats()
                status["vector_store_stats"] = stats
            except Exception as e:
                status["vector_store_error"] = str(e)

        return status

    @staticmethod
    def is_rag_available() -> bool:
        """Check if RAG functionality is available."""
        return RAG_AVAILABLE
