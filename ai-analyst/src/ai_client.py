#!/usr/bin/env python3
"""
AI Client - Handles communication with LLM providers for alert analysis.
Supports OpenAI, Anthropic Claude, and local Ollama.

Now with RAG (Retrieval-Augmented Generation) integration for enhanced context.
"""

import json
import logging
import os
from abc import ABC, abstractmethod
from typing import Any, Dict

# RAG Integration
try:
    from rag_retriever import get_rag_retriever

    RAG_AVAILABLE = True
except ImportError:
    RAG_AVAILABLE = False

logger = logging.getLogger(__name__)


class BaseLLMClient(ABC):
    """Abstract base class for LLM clients."""

    def __init__(self, strict_mode: bool = False):
        self.strict_mode = strict_mode

    @abstractmethod
    def generate(self, prompt: str, system_prompt: str = None) -> str:
        """Generate a response from the LLM."""

    def _mock_response(self, prompt: str = "") -> str:
        """Return a mock response when the LLM API is not available."""
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


class MockLLMClient(BaseLLMClient):
    """Deterministic mock client for demo mode."""

    def generate(self, prompt: str, system_prompt: str = None) -> str:
        return self._mock_response(prompt)


class OpenAIClient(BaseLLMClient):
    """OpenAI API client."""

    def __init__(
        self,
        model: str = "gpt-4",
        temperature: float = 0.3,
        max_tokens: int = 2000,
        strict_mode: bool = False,
    ):
        super().__init__(strict_mode=strict_mode)
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.api_key = os.environ.get("OPENAI_API_KEY")
        self.client = None

        if not self.api_key:
            if self.strict_mode:
                raise RuntimeError("OPENAI_API_KEY is required in strict mode")
            return

        try:
            import openai

            self.client = openai.OpenAI(api_key=self.api_key)
        except ImportError:
            if self.strict_mode:
                raise RuntimeError(
                    "openai package is required for OpenAI provider in strict mode"
                )

    def generate(self, prompt: str, system_prompt: str = None) -> str:
        if not self.client:
            if self.strict_mode:
                raise RuntimeError("OpenAI client is unavailable")
            return self._mock_response(prompt)

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=self.temperature,
                max_tokens=self.max_tokens,
            )
            return response.choices[0].message.content
        except Exception as e:
            if self.strict_mode:
                raise RuntimeError(f"OpenAI request failed: {e}")
            logger.warning("OpenAI request failed, using mock response: %s", e)
            return self._mock_response(prompt)


class AnthropicClient(BaseLLMClient):
    """Anthropic Claude API client."""

    def __init__(
        self,
        model: str = "claude-3-sonnet-20240229",
        temperature: float = 0.3,
        max_tokens: int = 2000,
        strict_mode: bool = False,
    ):
        super().__init__(strict_mode=strict_mode)
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.api_key = os.environ.get("ANTHROPIC_API_KEY")
        self.client = None

        if not self.api_key:
            if self.strict_mode:
                raise RuntimeError("ANTHROPIC_API_KEY is required in strict mode")
            return

        try:
            import anthropic

            self.client = anthropic.Anthropic(api_key=self.api_key)
        except ImportError:
            if self.strict_mode:
                raise RuntimeError(
                    "anthropic package is required for Anthropic provider in strict mode"
                )

    def generate(self, prompt: str, system_prompt: str = None) -> str:
        if not self.client:
            if self.strict_mode:
                raise RuntimeError("Anthropic client is unavailable")
            return self._mock_response(prompt)

        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                system=system_prompt or "You are a security analyst assistant.",
                messages=[{"role": "user", "content": prompt}],
                temperature=self.temperature,
            )
            return response.content[0].text
        except Exception as e:
            if self.strict_mode:
                raise RuntimeError(f"Anthropic request failed: {e}")
            logger.warning("Anthropic request failed, using mock response: %s", e)
            return self._mock_response(prompt)


class OllamaClient(BaseLLMClient):
    """Local Ollama client for running models locally."""

    def __init__(
        self,
        model: str = "llama2",
        host: str = "http://localhost:11434",
        strict_mode: bool = False,
    ):
        super().__init__(strict_mode=strict_mode)
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
                timeout=30,
            )
            response.raise_for_status()
            return response.json().get("response", "")
        except Exception as e:
            if self.strict_mode:
                raise RuntimeError(f"Ollama request failed: {e}")
            logger.warning("Ollama request failed, using mock response: %s", e)
            return self._mock_response(prompt)


class AIClient:
    """
    Main AI client that handles LLM interactions for alert analysis.

    Features RAG (Retrieval-Augmented Generation) for enhanced context from
    historical alerts, threat intelligence, and playbooks.
    """

    VALID_PROVIDERS = {"openai", "anthropic", "ollama", "mock"}

    def __init__(
        self,
        provider: str = None,
        use_rag: bool = True,
        config: Dict[str, Any] = None,
        runtime_mode: str = "strict",
    ):
        self.config = config or {}
        self.runtime_mode = runtime_mode
        self.strict_mode = runtime_mode == "strict"
        self.allow_fallback = not self.strict_mode

        ai_cfg = self.config.get("ai", {}) if isinstance(self.config, dict) else {}
        self.temperature = ai_cfg.get("temperature", 0.3)
        self.max_tokens = ai_cfg.get("max_tokens", 2000)

        self.provider = self._detect_provider(provider)
        self.client = self._create_client()
        self.client_uses_mock = isinstance(self.client, MockLLMClient) or (
            hasattr(self.client, "client") and getattr(self.client, "client") is None
        )
        self.system_prompt = self._load_system_prompt()

        self.fallback_used = False
        self.last_error = None

        rag_cfg = self.config.get("rag", {}) if isinstance(self.config, dict) else {}
        rag_enabled = rag_cfg.get("enabled", True)

        # Initialize RAG retriever if available
        self.use_rag = use_rag and rag_enabled and RAG_AVAILABLE
        self.rag_retriever = None
        if self.use_rag:
            try:
                self.rag_retriever = get_rag_retriever(config=self.config, reset=True)
                logger.info("RAG retriever initialized")
            except Exception as e:
                if self.strict_mode:
                    raise
                logger.warning("Failed to initialize RAG retriever: %s", e)
                self.use_rag = False

    def _detect_provider(self, provider: str = None) -> str:
        """Resolve the active provider from explicit arg, config, or env."""
        configured = provider
        if not configured:
            ai_cfg = self.config.get("ai", {}) if isinstance(self.config, dict) else {}
            configured = ai_cfg.get("provider")

        if configured:
            configured = configured.strip().lower()
            if configured in self.VALID_PROVIDERS:
                return configured

        if os.environ.get("OPENAI_API_KEY"):
            return "openai"
        if os.environ.get("ANTHROPIC_API_KEY"):
            return "anthropic"
        if self.allow_fallback:
            return "mock"

        raise RuntimeError(
            "No AI provider could be resolved in strict mode. "
            "Set ai.provider in settings.yaml and required credentials."
        )

    def _create_client(self) -> BaseLLMClient:
        """Create the appropriate LLM client."""
        ai_cfg = self.config.get("ai", {}) if isinstance(self.config, dict) else {}

        if self.provider == "openai":
            return OpenAIClient(
                model=ai_cfg.get("openai_model", "gpt-4"),
                temperature=self.temperature,
                max_tokens=self.max_tokens,
                strict_mode=self.strict_mode,
            )
        if self.provider == "anthropic":
            return AnthropicClient(
                model=ai_cfg.get("anthropic_model", "claude-3-sonnet-20240229"),
                temperature=self.temperature,
                max_tokens=self.max_tokens,
                strict_mode=self.strict_mode,
            )
        if self.provider == "ollama":
            return OllamaClient(
                model=ai_cfg.get("ollama_model", "llama2"),
                host=ai_cfg.get("ollama_host", "http://localhost:11434"),
                strict_mode=self.strict_mode,
            )
        return MockLLMClient(strict_mode=self.strict_mode)

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
        """
        self.fallback_used = False
        self.last_error = None

        should_use_rag = self.use_rag if use_rag is None else (use_rag and RAG_AVAILABLE)

        # Retrieve RAG context if enabled
        rag_context = None
        if should_use_rag and self.rag_retriever:
            try:
                logger.info("Retrieving RAG context for alert analysis...")
                rag_context = self.rag_retriever.retrieve_context(alert)
                logger.info(
                    "RAG context retrieved: %d documents", rag_context.total_documents
                )
            except Exception as e:
                if self.strict_mode:
                    raise
                logger.warning("Failed to retrieve RAG context: %s", e)
                self.last_error = str(e)

        # Build prompt with available context
        prompt = self._build_prompt(alert, context or {}, mitre_info or {}, rag_context)

        try:
            response = self.client.generate(prompt, self.system_prompt)

            try:
                if "```json" in response:
                    json_str = response.split("```json")[1].split("```")[0]
                elif "```" in response:
                    json_str = response.split("```")[1].split("```")[0]
                else:
                    json_str = response

                analysis = json.loads(json_str.strip())
                analysis_method = "llm"
            except json.JSONDecodeError:
                analysis = self._parse_text_response(response, alert)
                analysis_method = "llm_text_parse"

            if self.client_uses_mock:
                self.fallback_used = True
                analysis_method = "mock_response"

        except Exception as e:
            self.last_error = str(e)
            if self.strict_mode:
                raise
            self.fallback_used = True
            analysis = self._fallback_analysis(alert, context or {}, mitre_info or {})
            analysis_method = "rule-based-fallback"

        if rag_context:
            analysis["rag_context"] = {
                "similar_alerts_count": len(rag_context.similar_alerts),
                "threat_intel_count": len(rag_context.threat_intel),
                "playbooks_count": len(rag_context.relevant_playbooks),
                "temporal_context_count": len(rag_context.temporal_context),
                "retrieved_at": rag_context.retrieved_at,
                "retrieval_telemetry": rag_context.retrieval_telemetry,
            }

        analysis["analysis_metadata"] = {
            "analysis_method": analysis_method,
            "provider": self.provider,
            "runtime_mode": self.runtime_mode,
            "fallback_used": self.fallback_used,
            "last_error": self.last_error,
            "rag_enabled": self.use_rag,
        }

        return analysis

    def _build_prompt(
        self,
        alert: Dict[str, Any],
        context: Dict[str, Any],
        mitre_info: Dict[str, str],
        rag_context=None,
    ) -> str:
        """Build prompt for alert analysis, including RAG context if available."""
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

    def _parse_text_response(self, response: str, alert: Dict[str, Any]) -> Dict[str, Any]:
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

        src_ip = alert.get("data", {}).get("srcip", "")
        user = alert.get("data", {}).get("dstuser", "")

        if "brute force" in rule_desc.lower():
            title = f"SSH Brute Force Attack{f' from {src_ip}' if src_ip else ''}"
        elif "powershell" in rule_desc.lower():
            title = f"Suspicious PowerShell Activity{f' by {user}' if user else ''}"
        elif "sudo" in rule_desc.lower():
            title = f"Privilege Escalation Attempt{f' by {user}' if user else ''}"
        elif "mimikatz" in rule_desc.lower():
            title = "Credential Dumping (Mimikatz) Detected"
        elif "shadow" in rule_desc.lower():
            title = "Credential File Access Detected"
        else:
            title = rule_desc

        summary = f"Alert {rule_id} was triggered indicating {rule_desc.lower()}. "
        if src_ip:
            summary += f"The activity originated from IP {src_ip}. "
        if user:
            summary += f"The user {user} was involved. "
        summary += "Immediate investigation is recommended based on the severity level."

        investigation_steps = [
            "Review the full alert details in Wazuh dashboard",
            "Check for related events in the last 24 hours",
        ]

        if src_ip:
            investigation_steps.append(f"Verify if {src_ip} is a known trusted source")
            investigation_steps.append("Check threat intelligence for this IP address")

        if user:
            investigation_steps.append(f"Review recent activity for user {user}")

        recommended_actions = []

        if severity >= 12:
            recommended_actions.append("[IMMEDIATE] Isolate affected system")
            recommended_actions.append("[IMMEDIATE] Escalate to Incident Commander")
        elif severity >= 10:
            recommended_actions.append("[IMMEDIATE] Investigate alert within 30 minutes")

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
        """Index an alert for future RAG retrieval."""
        if not self.use_rag or not self.rag_retriever:
            logger.warning("RAG not available, cannot index alert")
            return False

        try:
            return self.rag_retriever.index_alert_for_rag(alert)
        except Exception as e:
            if self.strict_mode:
                raise
            logger.error("Failed to index alert for RAG: %s", e)
            return False

    def get_rag_status(self) -> Dict[str, Any]:
        """Get current RAG status and statistics."""
        status = {
            "rag_available": self.use_rag and RAG_AVAILABLE,
            "rag_enabled": self.use_rag,
            "retriever_initialized": self.rag_retriever is not None,
        }

        if self.rag_retriever and self.rag_retriever.vector_store:
            try:
                stats = self.rag_retriever.vector_store.get_stats()
                status["vector_store_stats"] = stats
                status["index_health"] = self.rag_retriever.vector_store.get_index_health()
            except Exception as e:
                status["vector_store_error"] = str(e)

        if self.rag_retriever and hasattr(self.rag_retriever, "embedding_service"):
            embedding_service = self.rag_retriever.embedding_service
            if hasattr(embedding_service, "get_cache_stats"):
                try:
                    status["embedding_cache_stats"] = embedding_service.get_cache_stats()
                except Exception as e:
                    status["embedding_cache_error"] = str(e)

        return status

    def get_status(self) -> Dict[str, Any]:
        """Return current runtime status for logging and output metadata."""
        data_source = "llm"
        if self.client_uses_mock or self.fallback_used:
            data_source = "mock_or_rule_fallback"
        return {
            "provider": self.provider,
            "runtime_mode": self.runtime_mode,
            "ai_mode": self.runtime_mode,
            "data_source": data_source,
            "fallback_used": self.fallback_used,
            "last_error": self.last_error,
            "rag_enabled": self.use_rag,
        }

    @staticmethod
    def is_rag_available() -> bool:
        """Check if RAG functionality is available."""
        return RAG_AVAILABLE
