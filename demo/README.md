# Interlock - Live Demo

> **Self-serve offline demo:** the buyer-ready, fully local demo (gateway +
> mock MCP server + dashboard, one `docker compose up`, no external services)
> lives in [`demo/offline/`](offline/README.md). Start there.

Live endpoint: https://interlock.onrender.com

The old public demo key has been retired. Mint your own key on the gateway
(admin token required) via `POST /admin/tokens` then `POST /admin/keys`, then
export it before running the scripts — each script reads `INTERLOCK_API_KEY`:

- PowerShell: `$env:INTERLOCK_API_KEY = "<your-key>"`
- bash: `export INTERLOCK_API_KEY="<your-key>"`

## Run These In Order

1. `./test-safe.ps1` - clean prompt passes through `/scan`
2. `./test-prompt-injection.ps1` - injection attack is blocked by `/scan`
3. `./test-rbac-deny.ps1` - `finance_agent` is denied access to `delete_file` via `/inspect/tool-call`
4. `./test-response-pii.ps1` - PII in an LLM/tool response is blocked via `/scan/output`
5. `./test-shadow-mode.ps1` - `/scan/shadow` shows what would be blocked without enforcing

Each script prints the full JSON response so prospects can see what Interlock caught, where it was caught, and why.

## MCP Drift and Quarantine Demo

`mcp-drift-quarantine-demo.py` shows Interlock's core MCP security story end-to-end.
It runs locally without LLM keys, a running server, or network calls.

```bash
# From the project root:
python demo/mcp-drift-quarantine-demo.py

# From inside the demo/ directory:
python mcp-drift-quarantine-demo.py
```

What it demonstrates:

1. Registers a clean read-only tool baseline (`read_document`)
2. Simulates the same tool changing: new `email` field, external sharing effects (`export`, `share`), PII data class added
3. Shows Interlock detecting the drift with full field-by-field reasons
4. Prints the quarantine decision — the tool is blocked until an operator approves
5. Writes and displays the audit log entry with matched rule and drift evidence

The script uses a temporary SQLite database. Production data is never touched.

## Privacy Note

For sensitive pilots, Interlock can run in metadata-only logging mode. Audit logs can store role, tool, decision, risk score, layer caught, and timestamp while omitting or redacting prompt/response content. See `PRIVACY.md`.
