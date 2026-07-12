# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0-alpha.1] - 2026-07-12

Pre-release covering work since v0.1.0 (2026-05-30). Alpha status is
deliberate: see `ROADMAP.md` for what is proven versus still missing.

### Added

- Self-serve offline buyer demo (`demo/offline/`): docker-compose stack with
  the gateway, a mock MCP server, a seeded demo API key, and a scripted
  drift → quarantine → receipt walkthrough, including offline Security
  Receipt verification (`run_demo.py`).
- v2 audit hash chain: `mcp_audit_log` rows now commit to receipt-binding
  fields (server id, call id, argument hash, drift surface hashes) on both
  the SQLite and Postgres backends. Legacy v1 rows still verify under the v1
  hash; replayed or forwarded receipts fail verification if any binding
  field differs from what the audit log recorded.
- Security Receipt export: per-call evidence artifact (allow / deny /
  quarantine) backed by the audit hash chain.
- Effective-permission (behavioral) drift probes: expected-denied canary
  calls that flag and quarantine a tool when a previously denied action
  starts succeeding (403 → 200), with receipt evidence.
- Discovery-time drift receipts and a server rebaseline endpoint.
- Drift-evidence emitter and published drift-record JSON schemas.
- Strict tool-surface interop projection.
- DB-backed dynamic policies and deterministic argument constraints
  (numeric bounds).
- MCP runtime threat model and coverage map documentation.
- Pre-commit formatting hooks; CI code-quality gates (ruff, black, mypy)
  with status badges.
- CI now runs the entire `tests/` directory instead of a hand-maintained
  file list, and adds a dependency-audit job (pip-audit, report-only for
  now) and a secret-scan job (gitleaks).

### Changed

- Landing page redesigned and dashboard rethemed to match.
- README and positioning centered on MCP drift detection; overclaims
  removed; stale test counts corrected.
- Starlette upgraded to 1.3.1.

### Fixed

- Drift classifier false positives: word-boundary matching in the tool
  metadata heuristic, benign-change handling, description heuristics.
- Critical drift enforcement: recursive input-schema walk, fail-closed
  discovery, and quarantine of new destructive tools added after baseline.
- Buyer-view audit filter now applies on initial dashboard load, not only
  after toggling.
- Canonicalized drift severity/action values and stricter side-effect
  derivation in tool metadata.
- Postgres boolean handling for policy seeding (`is_active`).
- Redis health check actively tests the connection instead of assuming it.
- Security Receipt print/PDF rendering; audit print view; MCP audit rows
  record a measured `scan_time_ms`.
- Previously-unrun tests repaired for the full-directory CI run: fixture
  hosts explicitly allowlisted for MCP registration
  (`MCP_REGISTRY_ALLOWED_HOSTS`), loopback URLs for local-only fixtures,
  and fixture-server cleanup so the registry leak check passes.

### Security

- Seeded public demo API keys removed; keys are minted through the admin
  flow; legacy `lf-*` keys rotated; dead demo keys replaced in docs and
  scripts.
- External MCP server registration restricted to an explicit allowlist;
  fixture writes are refused against production database URLs.
- Hosted safety defaults hardened (outbound URL validation, production
  environment guards); offline demo binds to loopback ports only.
- WebSocket audit feed requires an API key.
- Description-injection exfiltration drift blocked: tool descriptions that
  instruct agents to send data to external destinations are flagged as
  drift.

## [0.1.0] - 2026-05-30

First pilot-ready release.

- FastAPI gateway with layered prompt scanning: learned-pattern cache,
  per-key policies, rule-based and pattern-matching scans, LLM judge with
  fail modes and a circuit breaker.
- MCP gateway: server registry, tool whitelist, tool-call inspection, RBAC
  roles, response PII scanning.
- MCP tool-surface drift detection with quarantine.
- SQLite-backed API key store (sha256-hashed keys) with Supabase Postgres
  support.
- Tamper-evident audit-log hash chain with `/audit/verify`.
- React dashboard and landing page, Docker image, Helm chart.

[Unreleased]: https://github.com/MaazAhmed47/Interlock/compare/v0.2.0-alpha.1...HEAD
[0.2.0-alpha.1]: https://github.com/MaazAhmed47/Interlock/compare/v0.1.0...v0.2.0-alpha.1
[0.1.0]: https://github.com/MaazAhmed47/Interlock/releases/tag/v0.1.0
