# Security Policy

Interlock is a runtime security gateway for AI agents. It is intended to sit in sensitive paths between agents, MCP servers, APIs, databases, file systems, and internal tools, so security reports are treated as high priority.

## Supported Status

Interlock is currently pre-release and design-partner ready. The current codebase is suitable for local evaluation, controlled pilots, and self-hosted technical review. Broad enterprise production rollout should include the hardening checklist in [docs/production-readiness.md](docs/production-readiness.md).

## Reporting A Vulnerability

Please do not open a public issue for suspected vulnerabilities.

Email: `maaz@getinterlock.dev`

Include:

- affected commit or release
- affected endpoint or module
- reproduction steps
- expected vs actual behavior
- whether secrets, API keys, MCP tool output, or customer data could be exposed

We aim to acknowledge serious reports quickly and will coordinate disclosure timing with reporters.

## Secret Handling

- Raw customer API keys are returned once and stored only as SHA-256 hashes.
- Scoped admin tokens are returned once and stored only as SHA-256 hashes.
- `ADMIN_TOKEN` is a bootstrap root credential. Use it only to issue scoped admin tokens, then avoid day-to-day sharing.
- Never commit `.env`, provider keys, database URLs, Redis URLs, webhook URLs, or screenshots containing live secrets.
- Rotate any secret that was pasted into chat, logs, tickets, screenshots, or demos.

## Compliance Status

Interlock is pre-certification. It does not currently claim SOC 2, ISO 27001, HIPAA, GDPR certification, or an Interlock DPA. Vendor compliance documents from Supabase, Vercel, or Render may support a chosen deployment path, but they are not Interlock certifications. See [docs/compliance-posture.md](docs/compliance-posture.md).

## Production Expectations

For enterprise pilots:

- Use Postgres through `DATABASE_URL`; do not rely on local SQLite for multi-instance deployments.
- Use Redis through `REDIS_URL` before running multiple workers or pods.
- Put the admin surface behind SSO, VPN, identity-aware proxy, or a private network until native OIDC/SAML is implemented.
- Configure retention with `/admin/retention`.
- Connect logs, metrics, and audit events to the buyer's monitoring/SIEM.
- Test backup restore before routing production agent traffic.

## Disclosure Scope

Useful reports include:

- auth bypass for admin or customer API keys
- raw key leakage
- MCP tool-call authorization bypass
- schema drift quarantine bypass
- response scanning bypass that leaks secrets or PII
- unsafe default deployment configuration
- denial-of-service vectors in scan, MCP, or audit paths
