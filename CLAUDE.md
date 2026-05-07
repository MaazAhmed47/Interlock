# LLM Firewall

MCP-aware AI security gateway. A FastAPI reverse proxy that scans prompts and
tool calls before they reach LLMs and MCP servers. Differentiator vs.
Lakera/Protect AI/HiddenLayer: native **MCP gateway** with tool-definition
validation, RBAC for agents, and per-key fail-mode policies.

## Positioning (read before naming things)

Public-facing copy says **"AI Agent Security Gateway with native MCP support"** —
not "LLM firewall." The firewall layer is commodity (LLM Guard, NeMo). The MCP
gateway and agent RBAC are the moat. Do not generate landing-page copy or marketing
material that calls this an "LLM firewall."

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

- `index.html` — landing page (needs MCP-gateway repositioning)
- `dashboard.html` — self-contained admin/analytics view

---

## Conventions — DO and DON'T

### DO

- All scan functions return a `ScanResult` (`models/schemas.py`). Required: `is_threat`, `threat_level`, `reason`. Set `confidence`, `layer_caught`, `scan_time_ms`, `risk_score` when you have them.
- New per-key config goes in `core/db.py::api_keys` table. Add the column, update `PLAN_DEFAULTS` if it has a per-plan default, expose in `core/admin.py::UpdateKeyRequest`.
- Webhooks and SIEM dispatch must NEVER raise into the scan path. Catch + log + continue.
- Run `python test_db.py`, `python test_webhook_fix.py`, `python test_judge_failmodes.py` after touching the relevant module.
- Use `pip install ... --break-system-packages` (no sudo, no venv-juggling for system installs).

### DON'T

- Don't reintroduce hardcoded per-key dicts (`VALID_API_KEYS`, `WEBHOOK_URLS`, `FAIL_MODE_BY_KEY`, `SIEM_CONFIGS_BY_KEY`). They were removed in the SQLite migration. Use `db.lookup_key(raw)` instead.
- Don't store raw API keys. Only sha256 hashes go in the DB. `core/db.py::_hash_key` is the only allowed path.
- Don't use `asyncio.get_event_loop()`. Use `asyncio.get_running_loop()` inside async, `asyncio.run()` outside. The webhook bug from earlier was exactly this.
- Don't add features without a test. Tests live at the project root: `test_*.py`.
- Don't generate marketing copy that says "LLM firewall." See Positioning above.
- Don't add `Co-Authored-By` trailers to commit messages.

---

## Tech stack

- Python 3.12+ / FastAPI / Uvicorn
- Groq (`llama-3.3-70b-versatile`) for Layer 3 LLM judge. **No Gemini fallback exists yet** despite the env var — wiring it up is open work.
- SQLite via `core/db.py`. WAL mode, single writer lock. Migration target: Postgres (connect string only).
- In-memory rate-limit window — single-worker only. Redis is the next infra step for HA.
- Docker + Helm chart in `helm/`. Production-ready (HPA, PDB, NetworkPolicy, ServiceMonitor).

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

## Current priorities (week of 2026-05-07)

1. **Repositioning** — `index.html` rewrite around "MCP Security Gateway." Drop "LLM firewall" framing.
2. **Cold outreach** — 50-target design-partner list. Companies publishing MCP servers on GitHub, dev-tool startups, agent platforms.
3. **MCP gateway tests** — `core/mcp_gateway.py` is the differentiator and has zero tests. Add `test_mcp_gateway.py` covering: trust registry, tool-name validation, description injection detection, dangerous schema fields, RBAC integration, response PII scanning.
4. **Risk score on `/scan` path** — currently only set on `/inspect/tool-call` and `/scan/shadow`. Add `result.risk_score = calculate_risk_score(result)` inside `run_scan` before each return.
5. **`requirements.txt`** is empty. Pin actual deps before any deploy.
6. **Gemini fallback wiring** — either delete the env var or actually wire it as a Layer 3 fallback when Groq is rate-limited.

## Known gotchas

- `verify_key` does a DB hit on every request. Fine at low scale; cache via `functools.lru_cache` with TTL once you exceed ~100 RPS.
- `request_counts = defaultdict(list)` is in-memory. Multiple uvicorn workers will not share state. Run with `--workers 1` until Redis is wired in.
- Empty files in the rar archive (`detector.py`, `shadow_mode.py`, `webhook.py`, `llm_judge.py`) were a packaging artifact. The real implementations exist on the dev machine. Don't trust an empty file — verify with `wc -l`.
- The `policy.py` topic blocklist contains `politics → "democrat|republican"` etc. Embarrassing in an enterprise demo. Make opt-in or remove before any pilot.


## Git conventions
- Do NOT add "Co-Authored-By: Claude" trailer to commit messages.
- Commit messages should attribute work to the human only.
