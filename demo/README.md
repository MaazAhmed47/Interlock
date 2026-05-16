# Interlock — Live Demo

Live endpoint: https://interlock.onrender.com
API key for testing: lf-dev-key-456

## Run these in order

1. test-safe.ps1 — clean prompt passes through
2. test-prompt-injection.ps1 — injection attack blocked
3. test-rbac-deny.ps1 — agent RBAC violation blocked
4. test-response-pii.ps1 — PII in response blocked
5. test-shadow-mode.ps1 — shadow mode shows what would be blocked

Each script prints the full JSON response so you can see exactly what Interlock caught and why.
