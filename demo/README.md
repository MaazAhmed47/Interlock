# Interlock - Live Demo

Live endpoint: https://interlock.onrender.com
API key for testing: `lf-dev-key-456`

## Run These In Order

1. `./test-safe.ps1` - clean prompt passes through `/scan`
2. `./test-prompt-injection.ps1` - injection attack is blocked by `/scan`
3. `./test-rbac-deny.ps1` - `finance_agent` is denied access to `delete_file` via `/inspect/tool-call`
4. `./test-response-pii.ps1` - PII in an LLM/tool response is blocked via `/scan/output`
5. `./test-shadow-mode.ps1` - `/scan/shadow` shows what would be blocked without enforcing

Each script prints the full JSON response so prospects can see what Interlock caught, where it was caught, and why.

## Privacy Note

For sensitive pilots, Interlock can run in metadata-only logging mode. Audit logs can store role, tool, decision, risk score, layer caught, and timestamp while omitting or redacting prompt/response content. See `PRIVACY.md`.
