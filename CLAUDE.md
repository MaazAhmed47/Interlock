# Interlock

MCP runtime trust layer for AI agents. A FastAPI gateway that checks
prompts, tool calls, MCP server/tool surfaces, response exposure, behavioral
permission drift, and audit evidence before agents keep using risky tools. The
core differentiator is post-approval MCP drift detection: is this still the
approved tool/risk boundary?

## Positioning (read before naming things)

The product is called **Interlock**. Public-facing copy uses the tagline
**"MCP runtime trust layer for AI agents."** Do not call it an "LLM firewall."
The firewall layer is commodity. The MCP drift engine, behavioral effective-
permission proof, quarantine decisions, and Security Receipts are the moat. Do
not generate landing-page copy or marketing material that calls this an "LLM
firewall."

---

## Architecture

### Scan pipeline in `proxy.py::run_scan()`

Five layers, short-circuits on first hit:

1. `check_learned_patterns(prompt)` — fingerprint cache from prior LLM-judge results. Sub-ms hits. The differentiator vs. competitors who re-run the LLM every time.
2. `policy_scan(prompt, api_key)` — per-key custom policies (blocked keywords/topics/length).
3. `rule_based_scan` (`core/detector.py`) — regex/keyword. Layer 1 in marketing.
4. `pattern_match_scan` (`core/pattern_matcher.py`) — pattern matching. Layer 2.
5. `llm_judge_scan` (`core/llm_judge.py`) — LLM-as-judge via Groq. Layer 3, slowest. Has fail-modes and a circuit breaker — see below.

### Tool-call / agent path (different from above)

For agent + MCP use cases, requests do NOT go through `run_scan`. They go through:

- `POST /inspect/tool-call` → `core/tool_inspector.py` + RBAC (`core/policy.py::rbac_scan`)
- `POST /mcp/call` → `core/mcp_gateway.py::proxy_mcp_tool_call` → trust check → tool whitelist → inspector → RBAC → forward → response PII scan

When working on agent security, edit those modules — not the prompt-scan layers.

### Entry points

- `proxy.py` — main FastAPI app. All routes live here.
- (No `api.py` or `main.py` — those were hallucinated by the CLAUDE.md auto-generator. If you see them now, they're new.)

### Core modules

- `core/db.py` — SQLite-backed API key store. **All per-key config lives here**: plan, rate limit, fail_mode, webhook_url, custom_policy, siem_configs. Never re-introduce hardcoded per-key dicts in any other file.
- `core/admin.py` — `/admin/keys` CRUD, protected by `ADMIN_TOKEN` env var.
- `core/llm_judge.py` — Layer 3 with three fail-modes (`fail_closed` / `fail_open` / `fail_open_safe`) and a circuit breaker that trips after 5 consecutive failures and skips Groq for 60s.
- `core/mcp_gateway.py` — MCP tool definition validation + tool-call proxy. The differentiator.
- `core/tool_inspector.py` — SQL/code/shell/file threat detection on tool args.
- `core/policy.py` — `policy_scan` (per-key) and `rbac_scan` (per-agent-role). Six predefined roles: support_agent, devops_agent, finance_agent, readonly_agent, data_analyst, admin_agent.
- `core/learning.py` — fingerprint-based pattern cache populated from LLM judge results.
- `core/shadow_mode.py` — log-only mode + risk score (0-100). Risk score combines threat level + confidence + threat-type bonus.
- `core/siem.py` — Datadog/Splunk/Elastic/Slack/PagerDuty/generic webhook dispatch.
- `core/webhook.py` — Slack-format alerts. Reads webhook_url from the DB key record. Async via FastAPI loop, never blocks scan.
- `core/router.py` — multi-provider forwarding (OpenAI/Anthropic/Gemini/Groq/Ollama).
- `core/history.py` — scan history log. **Different from `db.py`** — that's the key store.

### Frontend

- `interlock-web/index.html` — public landing page
- `interlock-web/src/` — React dashboard/admin/audit views

---

## Conventions — DO and DON'T

### DO

- All scan functions return a `ScanResult` (`models/schemas.py`). Required: `is_threat`, `threat_level`, `reason`. Set `confidence`, `layer_caught`, `scan_time_ms`, `risk_score` when you have them.
- New per-key config goes in `core/db.py::api_keys` table. Add the column, update `PLAN_DEFAULTS` if it has a per-plan default, expose in `core/admin.py::UpdateKeyRequest`.
- Webhooks and SIEM dispatch must NEVER raise into the scan path. Catch + log + continue.
- Run focused `pytest` suites after touching relevant modules, plus `ruff`, `black`, and `mypy` before release commits.
- Prefer project-local tooling/virtual environments. Do not suggest global package installs in public docs.

### DON'T

- Don't reintroduce hardcoded per-key dicts (`VALID_API_KEYS`, `WEBHOOK_URLS`, `FAIL_MODE_BY_KEY`, `SIEM_CONFIGS_BY_KEY`). They were removed in the SQLite migration. Use `db.lookup_key(raw)` instead.
- Don't store raw API keys. Only sha256 hashes go in the DB. `core/db.py::_hash_key` is the only allowed path.
- Don't use `asyncio.get_event_loop()`. Use `asyncio.get_running_loop()` inside async, `asyncio.run()` outside. The webhook bug from earlier was exactly this.
- Don't add features without a test. Tests live at the project root: `test_*.py`.
- Don't generate marketing copy that says "LLM firewall." The product is Interlock. See Positioning above.
- Don't add `Co-Authored-By` trailers to commit messages.

---

## Tech stack

- Python 3.12+ / FastAPI / Uvicorn
- Optional LLM judge providers through `core/router.py` and provider env vars.
- SQLite for local/dev and controlled pilots; Postgres/Redis are the production-style path.
- Docker + Helm chart in `helm/` with production-oriented examples, not a broad enterprise certification claim.

---

## Environment (`.env`)

- `GROQ_API_KEY` — required for Layer 3
- `GEMINI_API_KEY` — declared but not consumed (no fallback wired)
- `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` — used by `/v1/chat/completions` proxy when forwarding upstream
- `ADMIN_TOKEN` — required for `/admin/*` endpoints. Generate with `python -c "import secrets; print(secrets.token_urlsafe(32))"`. Treat like a DB root password.
- `SLACK_WEBHOOK_URL` / `DATADOG_API_KEY` / `PAGERDUTY_KEY` — referenced by older SIEM seed code; new keys carry their own `siem_configs` JSON
- `FIREWALL_DB_PATH` — defaults to `data/firewall.db`

`config.py` loads these. If you add a new env var, also add it to `config.py` so it's importable everywhere.

---

## Running locally

```bash
# Windows
venv\Scripts\activate
pip install -r requirements.txt
uvicorn proxy:app --reload --port 8001

# Tests
python test_db.py
python test_webhook_fix.py
python test_judge_failmodes.py

# Swagger UI
# http://localhost:8001/docs
```

---

## Current priorities (June 2026)

1. **Correct ICP** — focus copy and outreach on teams operating agents against MCP tools they do not fully control: AI-agent teams, MCP gateways, internal platform/security teams, and products that let users bring external MCP servers.
2. **Killer demo** — keep one impossible-to-misunderstand flow: approved tool -> same manifest/schema -> expected 403 denied becomes observed 200 allowed -> quarantine -> hash-chain verified receipt.
3. **Reference win** — convert one non-production drift check into a public/private reference before adding more features.
4. **Repo hygiene** — keep public files product-focused. Move founder outreach assets, private target lists, scratch state, and local proof clutter out of the public root.
5. **Verification** — keep CI green with ruff, black, mypy, pytest, dashboard build, Docker/Helm checks.

## Known gotchas

- `verify_key` does a DB hit on every request. Fine at low scale; cache via `functools.lru_cache` with TTL once you exceed ~100 RPS.
- Rate limits and key usage should use Redis for multi-replica deployments; local memory paths are for local/dev and bounded pilots.
- Do not overclaim production readiness. Public proof packs are technical evidence; production proof requires a customer-approved non-production canary and written scope.
- The strongest sales proof is behavioral drift (expected 403 denied -> observed 200 allowed) plus receipt evidence. Keep broad drift coverage as supporting depth, not the headline.


## Git conventions
- Do NOT add "Co-Authored-By: Claude" trailer to commit messages.
- Commit messages should attribute work to the human only.
