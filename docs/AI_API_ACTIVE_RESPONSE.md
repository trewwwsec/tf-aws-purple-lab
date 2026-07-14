# AI API and Active Response Integration

This guide documents secure deployment for:
- `ai-analyst/src/api_server.py`
- `ai-analyst/ai-analyze.sh` (Wazuh active response hook)

## API Server (Auth Enabled by Default)

From the `ai-analyst/` directory:

```bash
export AI_ANALYST_API_TOKEN="replace-with-long-random-token"
export WAZUH_PASSWORD="replace-with-wazuh-api-password"
export OPENAI_API_KEY="replace-with-provider-key"

python3 src/api_server.py --mode strict
```

Test endpoints:

```bash
# Health (no auth required)
curl http://127.0.0.1:8080/health

# Analyze a pushed alert payload (auth required)
curl -X POST http://127.0.0.1:8080/analyze \
  -H "Authorization: Bearer ${AI_ANALYST_API_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "alert": {
      "id": "evt-1",
      "timestamp": "2026-04-08T01:00:00Z",
      "rule": {
        "id": "200001",
        "level": 10,
        "description": "SSH brute force attack detected",
        "mitre": {"id": ["T1110"]}
      },
      "agent": {"id": "001", "name": "linux-endpoint-01"},
      "data": {"srcip": "203.0.113.45", "dstuser": "root"}
    }
  }'
```

`alert_id` and `recent` remain available for manual lookups, but the preferred
alert-triage path is pushing the alert payload itself.

## Wazuh Active Response Integration

The active-response hook path is payload-first: Wazuh sends the detected alert to
`ai-analyze.sh`, and the script forwards that payload into `analyze_alert.py`
without re-querying Wazuh by alert ID.

Deploy the script onto Wazuh manager:

```bash
scp ai-analyst/ai-analyze.sh wazuh@<WAZUH_MANAGER>:/var/ossec/active-response/bin/ai-analyze.sh
ssh wazuh@<WAZUH_MANAGER> "chmod 750 /var/ossec/active-response/bin/ai-analyze.sh"
```

Recommended environment variables on manager host:

```bash
export AI_ANALYST_MODE=strict
export WAZUH_PASSWORD="replace-with-wazuh-api-password"
export OPENAI_API_KEY="replace-with-provider-key"
```

Wazuh config fragment:

```xml
<command>
  <name>ai-analyze</name>
  <executable>ai-analyze.sh</executable>
  <timeout_allowed>yes</timeout_allowed>
</command>

<active-response>
  <command>ai-analyze</command>
  <location>server</location>
  <level>10</level>
</active-response>
```

## CORS Configuration

The API server supports Cross-Origin Resource Sharing (CORS) for browser-based
dashboards that consume the AI analyst API. By default, CORS is **disabled**
(`api.enable_cors: false` in `config/settings.yaml`).

To enable CORS, set `api.enable_cors: true` in your settings. When enabling CORS,
ensure that `api.require_auth: true` (the default) to prevent unauthenticated
cross-origin requests from accessing the API.

**Security recommendation:** Keep CORS disabled unless you are serving a
browser-based dashboard. If enabled, use a reverse proxy (nginx/Caddy) to
restrict allowed origins to your specific dashboard domain.

## Least-Privilege Notes

- Keep API bound to `127.0.0.1` unless reverse-proxied behind authenticated ingress.
- Keep `api.require_auth: true`; do not disable auth in production.
- Source secrets from environment (`*_env` config pattern); do not commit plaintext credentials/tokens.
- Use a dedicated Wazuh API account with read-only alert/query permissions where possible.
- Restrict file mode on `ai-analyze.sh` to owner/group execute and root/wazuh ownership on manager.
- Anomaly detection still uses the Wazuh API for live event collection; the hook-only
  change applies to alert triage, not the anomaly pipeline.
