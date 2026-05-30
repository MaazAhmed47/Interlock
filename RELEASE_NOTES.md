# Interlock v0.1.0 — First Pilot-Ready Release

First tagged release of Interlock for serious design-partner evaluation.

Interlock is a self-hosted runtime security gateway for AI agents and MCP servers. It sits between agents and tools, scans prompts and responses, enforces tool policy, detects MCP drift, and records audit evidence for allow, deny, monitor, and quarantine decisions.

## What's included

### Runtime Security Controls

* OpenAI-compatible `/v1/chat/completions` gateway with prompt scanning before provider forwarding
* MCP tool-call proxy with policy enforcement before execution
* Response scanning for prompt injection, PII, secrets, and oversized outputs
* LLM judge path with configurable fail modes

### MCP Gateway

* MCP server registry
* Tool allowlist and blocklist enforcement
* Tool definition validation before approval
* Tool metadata storage
* Drift review and quarantine workflow
* Role-aware tool-call checks

### Audit & Evidence

* Scan history with structured records
* MCP audit log
* Admin audit log
* SIEM and webhook export support
* Dashboard views for scan, MCP, and audit evidence

### Identity & Access

* Hashed API keys
* Scoped admin tokens
* OIDC admin JWT verification
* Dashboard browser SSO support
* Role-based access controls

### Operations

* Docker local evaluation path
* Helm chart
* Optional Redis-backed shared rate limiting
* SQLite for local evaluation, Postgres via `DATABASE_URL`
* CI workflow for backend tests, dashboard build, Helm checks, and Docker build

## Honest Limitations

* Design-partner MVP, not a certified enterprise security product
* No Interlock SOC 2, ISO 27001, HIPAA, or GDPR certification claim yet
* Redis should be configured before horizontal scaling
* Postgres should be used for multi-instance or long-running pilots
* Start with one real agent workflow and one real MCP server before broad rollout

**Actively looking for 3-5 design partners. If you run real MCP agents, we want your hardest security scenarios.**

Reach out: [maaz@getinterlock.dev](mailto:maaz@getinterlock.dev)

## Try It

* Live: https://getinterlock.dev
* Quickstart: see README.md
* Demo video: https://youtu.be/kc5wAbgoEkw
