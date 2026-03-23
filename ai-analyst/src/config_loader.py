#!/usr/bin/env python3
"""
Configuration loading helpers for AI analyst components.
"""

import os
from typing import Any, Dict, List, Optional, Tuple

import yaml


DEFAULT_SETTINGS: Dict[str, Any] = {
    "runtime": {"mode": "strict"},
    "ai": {
        "provider": "openai",
        "openai_model": "gpt-4",
        "anthropic_model": "claude-3-sonnet-20240229",
        "ollama_model": "llama2",
        "temperature": 0.3,
        "max_tokens": 2000,
    },
    "wazuh": {
        "host": "localhost",
        "port": 55000,
        "user": "wazuh",
        "password_env": "WAZUH_PASSWORD",
        "ssl_verify": True,
    },
    "api": {
        "host": "127.0.0.1",
        "port": 8080,
        "enable_cors": False,
        "require_auth": True,
        "auth_token_env": "AI_ANALYST_API_TOKEN",
    },
    "anomaly_detection": {
        "scan_interval_seconds": 300,
        "lookback_hours": 24,
        "baseline_file": "baselines/agent_baselines.json",
        "z_score_threshold": 2.5,
        "min_confidence": 0.6,
    },
    "rag": {
        "enabled": True,
        "embedding": {
            "model": "all-MiniLM-L6-v2",
            "cache_dir": "~/.cache/ai-analyst/embeddings",
            "max_memory_entries": 5000,
            "max_disk_files": 50000,
            "max_disk_size_mb": 2048,
            "prune_interval_writes": 200,
        },
        "opensearch": {
            "host": "localhost",
            "port": 9200,
            "username_env": "OPENSEARCH_USER",
            "password_env": "OPENSEARCH_PASSWORD",
            "use_ssl": True,
            "verify_certs": True,
        },
        "retrieval": {
            "similarity_threshold": 0.7,
            "max_similar_alerts": 5,
            "max_threat_intel": 3,
            "max_playbooks": 2,
            "max_temporal_alerts": 10,
            "time_range": "7d",
            "hybrid_search": True,
            "text_weight": 0.3,
            "vector_weight": 0.7,
            "temporal_window_before": "2h",
            "temporal_window_after": "2h",
            "index_health_check": True,
        },
        "indexing": {
            "auto_index": True,
            "min_level": 5,
            "index_historical": False,
            "historical_days": 30,
        },
    },
}


def deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """Merge nested dictionaries without mutating inputs."""
    merged = dict(base)
    for key, value in override.items():
        base_value = merged.get(key)
        if isinstance(base_value, dict) and isinstance(value, dict):
            merged[key] = deep_merge(base_value, value)
        else:
            merged[key] = value
    return merged


def _default_config_path() -> str:
    return os.path.join(os.path.dirname(os.path.dirname(__file__)), "config", "settings.yaml")


def _inject_env_secrets(value: Any) -> Any:
    """
    Recursively resolve `*_env` keys into sibling secret keys.
    Example: {"password_env": "WAZUH_PASSWORD"} -> {"password": "<env value>"}.
    """
    if isinstance(value, dict):
        resolved = {}
        for k, v in value.items():
            resolved[k] = _inject_env_secrets(v)

        for k, env_name in list(resolved.items()):
            if not k.endswith("_env") or not isinstance(env_name, str) or not env_name:
                continue

            target_key = k[: -len("_env")]
            env_value = os.environ.get(env_name)
            if env_value and not resolved.get(target_key):
                resolved[target_key] = env_value

        return resolved

    if isinstance(value, list):
        return [_inject_env_secrets(item) for item in value]

    return value


def _find_plaintext_secrets(value: Any, path: str = "") -> List[str]:
    """
    Detect plaintext secret-like keys in user YAML (non-env sourced).
    """
    findings: List[str] = []
    if isinstance(value, dict):
        for key, val in value.items():
            child_path = f"{path}.{key}" if path else key
            key_l = key.lower()

            if (
                isinstance(val, str)
                and val.strip()
                and not key_l.endswith("_env")
                and any(
                    token in key_l
                    for token in ("password", "token", "secret", "api_key", "apikey")
                )
            ):
                findings.append(child_path)

            findings.extend(_find_plaintext_secrets(val, child_path))
    elif isinstance(value, list):
        for idx, item in enumerate(value):
            child_path = f"{path}[{idx}]"
            findings.extend(_find_plaintext_secrets(item, child_path))

    return findings


def evaluate_security_posture(settings: Dict[str, Any]) -> Tuple[List[str], List[str]]:
    """
    Return (errors, warnings) for insecure configuration.
    """
    errors: List[str] = []
    warnings: List[str] = []

    if not isinstance(settings, dict):
        return ["settings must be a dictionary"], warnings

    wazuh_cfg = settings.get("wazuh", {}) if isinstance(settings.get("wazuh"), dict) else {}
    rag_cfg = settings.get("rag", {}) if isinstance(settings.get("rag"), dict) else {}
    api_cfg = settings.get("api", {}) if isinstance(settings.get("api"), dict) else {}
    os_cfg = rag_cfg.get("opensearch", {}) if isinstance(rag_cfg.get("opensearch"), dict) else {}

    if not wazuh_cfg.get("ssl_verify", True):
        errors.append("wazuh.ssl_verify must be true")

    if rag_cfg.get("enabled", True):
        if not os_cfg.get("use_ssl", True):
            errors.append("rag.opensearch.use_ssl must be true when rag is enabled")
        if not os_cfg.get("verify_certs", True):
            errors.append("rag.opensearch.verify_certs must be true when rag is enabled")

    if not api_cfg.get("require_auth", True):
        errors.append("api.require_auth must be true")

    os_user = (os_cfg.get("username") or "").strip().lower()
    os_pass = (os_cfg.get("password") or "").strip().lower()
    if os_user == "admin" and os_pass == "admin":
        errors.append("OpenSearch default admin/admin credentials are not allowed")
    elif os_user == "admin":
        warnings.append("OpenSearch username is 'admin'; use least-privilege credentials")

    plaintext_paths = (
        settings.get("_security", {}).get("plaintext_secret_paths", [])
        if isinstance(settings.get("_security"), dict)
        else []
    )
    for secret_path in plaintext_paths:
        errors.append(
            f"plaintext secret detected in config: {secret_path} (use *_env pattern instead)"
        )

    return errors, warnings


def enforce_security_posture(settings: Dict[str, Any], runtime_mode: str = "strict") -> List[str]:
    """
    Enforce secure config in strict mode.
    Returns warnings (and insecure opt-in notices in non-strict mode).
    """
    errors, warnings = evaluate_security_posture(settings)
    if runtime_mode == "strict" and errors:
        raise ValueError("Insecure configuration in strict mode: " + "; ".join(errors))

    if runtime_mode != "strict":
        warnings.extend(
            [f"{err} (allowed only because runtime.mode={runtime_mode})" for err in errors]
        )

    return warnings


def load_settings(config_path: Optional[str] = None) -> Dict[str, Any]:
    """
    Load settings from YAML and merge with sane defaults.
    """
    path = config_path or os.environ.get("AI_ANALYST_CONFIG") or _default_config_path()

    if not os.path.exists(path):
        return dict(DEFAULT_SETTINGS)

    with open(path, "r", encoding="utf-8") as f:
        parsed = yaml.safe_load(f) or {}
        if not isinstance(parsed, dict):
            parsed = {}

    merged = deep_merge(DEFAULT_SETTINGS, parsed)
    merged = _inject_env_secrets(merged)
    merged["_security"] = {
        "plaintext_secret_paths": _find_plaintext_secrets(parsed),
        "config_path": path,
    }
    return merged


def resolve_runtime_mode(
    settings: Optional[Dict[str, Any]] = None,
    cli_mode: Optional[str] = None,
    demo_flag: bool = False,
) -> str:
    """
    Determine runtime mode from CLI > env > config > demo flag > default.
    """
    valid_modes = {"strict", "demo"}

    if cli_mode in valid_modes:
        return cli_mode

    # Demo commands should default to demo behavior unless CLI explicitly overrides.
    if demo_flag:
        return "demo"

    env_mode = os.environ.get("AI_ANALYST_MODE", "").strip().lower()
    if env_mode in valid_modes:
        return env_mode

    cfg_mode = (
        (settings or {}).get("runtime", {}).get("mode", "").strip().lower()
        if isinstance((settings or {}).get("runtime", {}), dict)
        else ""
    )
    if cfg_mode in valid_modes:
        return cfg_mode

    return "strict"
