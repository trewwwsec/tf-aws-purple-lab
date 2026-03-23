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

# Analyze by alert ID (auth required)
curl -X POST http://127.0.0.1:8080/analyze \
  -H "Authorization: Bearer ${AI_ANALYST_API_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"alert_id":"200001"}'
```

## Wazuh Active Response Integration

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

## Least-Privilege Notes

- Keep API bound to `127.0.0.1` unless reverse-proxied behind authenticated ingress.
- Keep `api.require_auth: true`; do not disable auth in production.
- Source secrets from environment (`*_env` config pattern); do not commit plaintext credentials/tokens.
- Use a dedicated Wazuh API account with read-only alert/query permissions where possible.
- Restrict file mode on `ai-analyze.sh` to owner/group execute and root/wazuh ownership on manager.
