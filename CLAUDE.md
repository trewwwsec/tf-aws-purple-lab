# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo is

A Terraform-built AWS security lab: Wazuh SIEM + Linux/Windows/macOS endpoints, 82 custom MITRE-mapped Wazuh detection rules, purple-team attack simulation scripts, NIST-style incident-response playbooks, and a standalone Python "AI Alert Analyst" service that enriches Wazuh alerts with LLM-generated triage. These five pieces (`terraform/`, `wazuh/`, `attack-simulation/`, `incident-response/`, `ai-analyst/`) are loosely coupled — each is best understood by MITRE technique / detection rule ID, not by import graph.

## Commands

### Terraform (`terraform/`)

```bash
cd terraform
terraform init
terraform fmt -check -recursive -diff
terraform validate
terraform plan -out=tfplan
terraform apply tfplan
terraform destroy   # always run when done — NAT Gateway alone is ~$32/mo
```

CI (`terraform-ci.yml`) runs `fmt -check`, `init -backend=false`, and `validate` on any PR touching `terraform/**`. Run the same three before pushing infra changes.

### AI Analyst (`ai-analyst/`)

Tests must run with **stdlib `unittest`**, not bare `pytest` — CI invokes `python3 -m unittest discover -s ai-analyst/tests -q` and cannot import pytest-only APIs (`pytest.raises`, `@pytest.fixture`, bare `assert`). If a test file uses pytest idioms, either it hasn't been reconciled with CI yet or it's being run via `pytest` locally — see the fix in commit `2ff27ca` for the conversion pattern (`pytest.raises` → `self.assertRaisesRegex`, `@pytest.fixture` → `setUp()`, `assert` → `self.assertEqual`/`assertTrue`/etc).

```bash
# From repo root (pytest.ini disables the globally-injected pytest-rerunfailures plugin)
pytest -q
uv run --with-requirements ai-analyst/requirements.txt python -m pytest ai-analyst/tests -q

# CI-equivalent (what actually gates PRs)
python3 -m unittest discover -s ai-analyst/tests -q

# Single test file / case
python3 -m unittest ai-analyst.tests.test_ai_client -v
pytest ai-analyst/tests/test_ai_client.py -q

# Type checking (mypy.ini lists every src/ and tests/ file explicitly — new files must be added there)
cd ai-analyst && mypy
```

CLI entry points (all runnable in `--demo`/mock mode without live AWS/Wazuh):

```bash
cd ai-analyst
python src/analyze_alert.py --demo --mode demo
python src/detect_anomalies.py --demo
python src/api_server.py --host 0.0.0.0 --port 8000
python src/benchmark_rag.py --iterations 10 --output json
python src/prune_embedding_cache.py --max-files 20000 --max-size-mb 1024 --max-age-days 30
```

### Docs / detection validation (repo root)

```bash
python3 scripts/validate_docs.py        # checks markdown links + flags stale command references; part of CI
python3 scripts/validate_rule_namespace.py
python3 scripts/smoke_test_detections.py --list-simulations
./scripts/run_detection_smoke_test.sh --simulation privilege-escalation
./scripts/run_end_to_end_detection_test.sh --simulation ssh-brute-force   # runs a live attack + validates against a deployed lab
```

`run_end_to_end_detection_test.sh` and `run_detection_smoke_test.sh` require a **deployed lab** (they call `terraform output` and SSH to real EC2 instances) — don't run them without confirming a stack is up.

## Architecture notes

### AI Analyst (`ai-analyst/src/`) — the only substantial codebase here

Two independent pipelines sharing the same LLM/config/RAG plumbing:

- **Alert Analyst** (reactive): `analyze_alert.py` → `alert_enricher.py` (context gathering) → `ai_client.py` (LLM call) → recommendations, mapped to IR playbooks. Wazuh pushes alert JSON via active-response (`ai-analyze.sh` on stdin) rather than the analyzer polling Wazuh — see `ai_client.py`'s `alert_id`/`recent` args, which exist only for manual/API lookups.
- **Anomaly Detector** (proactive): `detect_anomalies.py` → `baseline_engine.py` (per-agent/user behavioral baselines) → `anomaly_detector.py` (z-score deviation across 6 categories: login, process, privilege, network, file-integrity, volume) → AI reasoning pass. This path still queries the live Wazuh API for event windows.

Shared infrastructure:
- `ai_client.py` — provider abstraction: `BaseLLMClient` → `OpenAIClient` / `AnthropicClient` / `OllamaClient` / `MockLLMClient`, selected by `ai.provider` in `config/settings.yaml`.
- `config_loader.py` — loads `config/settings.yaml`, deep-merges env-injected secrets (never plaintext in YAML — `evaluate_security_posture`/`enforce_security_posture` actively reject plaintext secrets found in config), and resolves `runtime.mode` (`strict` vs `demo`; demo mode allows mock fallbacks when no API key/Wazuh connection is available).
- `rag_retriever.py` / `vector_store.py` / `embedding_service.py` / `playbook_chunker.py` — RAG pipeline that chunks `incident-response/playbooks/` and retrieves relevant sections via OpenSearch hybrid (vector + text) search; embeddings are disk-cached under `~/.cache/ai-analyst/embeddings` with pruning via `prune_embedding_cache.py`.
- `api_server.py` — stdlib `http.server` (`ThreadingHTTPServer`) app exposing `/analyze`, `/feedback`, `/health`; bearer-token auth (`AI_ANALYST_API_TOKEN`) is **on by default**.
- `feedback_store.py` — append-only JSONL analyst feedback at `~/.cache/ai-analyst/feedback.jsonl`.
- `notification_service.py` — optional webhook delivery, best-effort (never fails core analysis).

Adding a new `src/*.py` module requires adding it to the `files =` list in `ai-analyst/mypy.ini` or it's silently skipped by type checking.

### Detection rules ↔ attack simulation ↔ IR playbooks are ID-linked, not code-linked

The three non-AI subsystems correlate purely through convention, not through any shared schema or code:
- Custom Wazuh rules live in `wazuh/custom_rules/local_rules.xml` (Linux/Windows, IDs `200001`–`200124`) and `wazuh/custom_rules/macos_rules.xml` (IDs `200200`–`200272`). SOCFortress community rules are vendored alongside for broader coverage but are not project-owned.
- Each `attack-simulation/*.sh` script is documented (in its own header and in `attack-simulation/README.md`) with the specific rule IDs it should trigger.
- `incident-response/playbooks/*.md` map to MITRE techniques, which map to specific rule ID ranges (see the table in root `README.md`).
- When adding a new detection: add the rule to `local_rules.xml`/`macos_rules.xml` with a `<mitre>` tag and `MITRE_T....` group, add/extend a simulation script to trigger it, document expected rule IDs in the relevant `detections/*.md` file, and keep `docs/MITRE_COVERAGE.md` in sync.

### Terraform (`terraform/`)

Single flat module (no submodules) provisioning: VPC with public (Wazuh) + private (Linux/Windows endpoints) subnets and NAT Gateway, EC2 instances bootstrapped via `user_data/` scripts, IAM roles (Wazuh EC2 role reads CloudTrail S3 via native `aws-s3` module — no static AWS keys on the server), and security groups. `cloudtrail_wazuh.tf` is the CloudTrail → S3 → Wazuh ingestion path, enabled by default but scoped to management events only (data events/GuardDuty/Config/Security Hub intentionally excluded to control cost). `enable_macos_endpoint` is `false` by default — a macOS endpoint requires an AWS Dedicated Host and is expensive.

### Attack simulation scripts (`attack-simulation/`)

Bash scripts sharing `common.sh` (logging/color/cleanup helpers). Individual technique scripts (`ssh-brute-force.sh`, `privilege-escalation.sh`, etc.) vs. multi-stage `apt-*.sh` scripts that chain several MITRE tactics (credential harvest → lateral movement → C2/exfil) into a simulated APT29-style kill chain, orchestrated end-to-end by `apt-full-killchain.sh`. These are destructive/intrusive by design (SSH brute force, sudo abuse, credential dumping, log tampering) — they must only be pointed at the lab's own endpoints, never at arbitrary hosts, and platform READMEs are explicit that these are for isolated lab use only.
