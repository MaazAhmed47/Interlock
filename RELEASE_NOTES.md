# Interlock v0.1.0 — First Pilot-Ready Release

After 30 days of building, this is the first version
that's ready for serious design-partner evaluation.

## What's in this release

### Runtime Security Controls
- OpenAI-compatible /v1/chat/completions gateway with
  multi-layered prompt scanning
- MCP tool-call proxy with policy enforcement before execution
- Response scanning: prompt injection, PII, secrets,
  volume anomalies
- LLM judge with three fail modes (open/closed/safe),
  hardened against prompt injection in tool responses

### Drift & Supply Chain
- Full-schema MCP tool drift detection with severity scoring
- Edit-distance-based description drift
- Parameter type change detection
- Tool removal detection (supply chain attack signal)
- Automated quarantine workflow for critical drift

### Audit & Compliance
- Tamper-evident audit log with SHA256 hash chain
- /audit/verify endpoint for chain integrity verification
- Covers both MCP audit log and admin audit log
- SIEM export support (Datadog, Splunk, Elastic, Slack,
  PagerDuty, webhook)

### Identity & Access
- Role-based access control with 6 default roles
- OIDC admin JWT verification
- Dashboard browser SSO login (Supabase)
- Scoped admin tokens with full audit

### Performance & Operations
- /metrics/performance endpoint (avg/p95/p99 latency,
  block rates, drift detections)
- Optional Redis-backed shared rate limiting
- Startup warnings for production misconfigurations
- 148 tests passing, ruff/black/mypy clean

### Honest Limitations
- Design-partner MVP — not certified for SOC 2 / ISO / HIPAA
- LLM judge depends on Groq availability (configurable
  fail modes)
- In-memory rate limiting by default (Redis path supported)
- Single worker unless Redis configured

## Try It
- Live: https://getinterlock.dev
- Quickstart: see README.md
- Demo video: https://youtu.be/kc5wAbgoEkw
