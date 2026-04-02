#!/usr/bin/env python3
"""
AI Analyst API server.

Provides authenticated endpoints for alert analysis:
- GET /health
- POST /analyze
"""

import argparse
import json
import logging
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from analyze_alert import AlertAnalyzer
from config_loader import enforce_security_posture, load_settings, resolve_runtime_mode

logger = logging.getLogger(__name__)


def _json_response(handler: BaseHTTPRequestHandler, status: int, payload: Dict[str, Any]):
    body = json.dumps(payload, default=str).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    if getattr(handler, "enable_cors", False):
        handler.send_header("Access-Control-Allow-Origin", "*")
        handler.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type, X-API-Token")
        handler.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
    handler.end_headers()
    handler.wfile.write(body)


def _extract_bearer_token(value: str) -> Optional[str]:
    if not value:
        return None
    prefix = "bearer "
    lower = value.lower()
    if lower.startswith(prefix):
        return value[len(prefix):].strip()
    return None


def _lookup_alert(analyzer: AlertAnalyzer, alert_id: str) -> Optional[Dict[str, Any]]:
    alert = analyzer.wazuh_client.get_alert_by_id(alert_id)
    if alert:
        return alert

    by_rule = analyzer.wazuh_client.get_alerts(limit=1, rule_id=alert_id)
    return by_rule[0] if by_rule else None


class APIHandler(BaseHTTPRequestHandler):
    analyzer: Optional[AlertAnalyzer] = None
    require_auth: bool = True
    auth_token: Optional[str] = None
    enable_cors: bool = False
    runtime_mode: str = "strict"

    server_version = "AIAnalystAPI/1.0"

    def log_message(self, format: str, *args):  # noqa: A003
        logger.info("%s - %s", self.address_string(), format % args)

    def do_OPTIONS(self):
        _json_response(self, 200, {"status": "ok"})

    def _authorized(self) -> bool:
        if not self.require_auth:
            return True

        expected = (self.auth_token or "").strip()
        if not expected:
            return False

        header_auth = self.headers.get("Authorization", "")
        bearer = _extract_bearer_token(header_auth)
        if bearer and bearer == expected:
            return True

        api_token = self.headers.get("X-API-Token", "").strip()
        return bool(api_token and api_token == expected)

    def do_GET(self):
        path = urlparse(self.path).path
        if path != "/health":
            _json_response(self, 404, {"error": "not_found"})
            return

        status = {}
        if self.analyzer:
            status = self.analyzer.ai_client.get_status()

        _json_response(
            self,
            200,
            {
                "status": "ok",
                "service": "ai-analyst",
                "runtime_mode": self.runtime_mode,
                "analysis_metadata": status,
            },
        )

    def do_POST(self):
        path = urlparse(self.path).path
        if path != "/analyze":
            _json_response(self, 404, {"error": "not_found"})
            return

        if not self._authorized():
            _json_response(self, 401, {"error": "unauthorized"})
            return

        if not self.analyzer:
            _json_response(self, 500, {"error": "analyzer_not_initialized"})
            return

        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            content_length = 0

        if content_length <= 0:
            _json_response(self, 400, {"error": "request body is required"})
            return
        if content_length > 1024 * 1024:
            _json_response(self, 413, {"error": "request body too large"})
            return

        raw = self.rfile.read(content_length)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except Exception:
            _json_response(self, 400, {"error": "invalid json payload"})
            return

        if not isinstance(payload, dict):
            _json_response(self, 400, {"error": "json payload must be an object"})
            return

        try:
            response = self._handle_analyze(payload)
            _json_response(self, 200, response)
        except ValueError as e:
            _json_response(self, 400, {"error": str(e)})
        except Exception as e:
            logger.exception("API analyze request failed")
            _json_response(self, 500, {"error": "analysis_failed", "message": str(e)})

    def _handle_analyze(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        raw_alert = payload.get("alert")
        alert_id = payload.get("alert_id")
        recent = payload.get("recent")

        requested = sum(
            1 for value in (raw_alert, alert_id, recent) if value not in (None, "")
        )
        if requested != 1:
            raise ValueError("provide exactly one of: alert, alert_id, recent")

        if isinstance(raw_alert, dict):
            return {"analysis": self.analyzer.analyze(raw_alert)}

        if alert_id is not None:
            alert_id = str(alert_id)
            alert = _lookup_alert(self.analyzer, alert_id)
            if not alert:
                raise ValueError(f"alert not found: {alert_id}")
            return {"analysis": self.analyzer.analyze(alert)}

        if recent is None:
            raise ValueError("invalid request")

        try:
            recent_count = int(recent)
        except (TypeError, ValueError):
            raise ValueError("recent must be an integer")

        if recent_count < 1 or recent_count > 200:
            raise ValueError("recent must be in range [1, 200]")

        alerts = self.analyzer.wazuh_client.get_alerts(limit=recent_count)
        analyses: List[Dict[str, Any]] = [self.analyzer.analyze(a) for a in alerts]
        return {"analyses": analyses, "count": len(analyses)}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="AI Analyst REST API server")
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
    parser.add_argument("--host", type=str, default=None, help="Override API host")
    parser.add_argument("--port", type=int, default=None, help="Override API port")
    return parser.parse_args()


def main() -> int:
    logging.basicConfig(
        level=os.environ.get("AI_ANALYST_LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    args = parse_args()

    settings = load_settings(args.config)
    runtime_mode = resolve_runtime_mode(settings=settings, cli_mode=args.mode, demo_flag=False)
    try:
        warnings = enforce_security_posture(settings, runtime_mode=runtime_mode)
    except ValueError as e:
        logger.error("Security configuration error: %s", e)
        return 1
    for warning in warnings:
        logger.warning("Security warning: %s", warning)

    api_cfg = settings.get("api", {}) if isinstance(settings.get("api"), dict) else {}
    host = args.host or api_cfg.get("host", "127.0.0.1")
    port = args.port or int(api_cfg.get("port", 8080))
    require_auth = bool(api_cfg.get("require_auth", True))
    enable_cors = bool(api_cfg.get("enable_cors", False))

    auth_token = (api_cfg.get("auth_token") or "").strip()
    if require_auth and not auth_token:
        logger.error(
            "API authentication is required, but no token is set. "
            "Set %s (or api.auth_token).",
            api_cfg.get("auth_token_env", "AI_ANALYST_API_TOKEN"),
        )
        return 1

    analyzer_config = {"include_raw": False, "output_format": "json"}
    try:
        analyzer = AlertAnalyzer(
            config=analyzer_config,
            settings=settings,
            runtime_mode=runtime_mode,
        )
    except Exception as e:
        logger.error("Failed to initialize AlertAnalyzer: %s", e)
        return 1

    APIHandler.analyzer = analyzer
    APIHandler.require_auth = require_auth
    APIHandler.auth_token = auth_token
    APIHandler.enable_cors = enable_cors
    APIHandler.runtime_mode = runtime_mode

    server = ThreadingHTTPServer((host, port), APIHandler)
    logger.info(
        "AI Analyst API listening on %s:%d (require_auth=%s, mode=%s)",
        host,
        port,
        require_auth,
        runtime_mode,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down API server")
    finally:
        server.server_close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
