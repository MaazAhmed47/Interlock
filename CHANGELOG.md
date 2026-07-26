# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Optional self-hosted CI boundary-review gate: a read-only
  `POST /mcp/servers/{server_id}/boundary-review` endpoint plus a stdlib-only
  CLI (`scripts/interlock_ci_gate.py`) that lets a release pipeline check one
  registered MCP server's approved-vs-observed boundary without the dashboard.
  It writes a sanitized JSON + Markdown artifact and exits with stable codes
  (0 clean/advisory, 20 review-required, 21 quarantined, 22 inconclusive,
  2/3/4 for configuration, authentication, and protocol failures). The review
  never rebaselines, approves, quarantines, or changes policy; its only writes
  are append-only evidence. Documentation and a non-active GitHub Actions
  template ship in `docs/integrations/`.
- New least-privilege `mcp.review` API-key scope, granted to no key by
  default, authorizing only the boundary-review route.
- Validated, clamped limits for the boundary review:
  `INTERLOCK_BOUNDARY_REVIEW_TIMEOUT_S` (10s), `..._MAX_RESPONSE_BYTES` (2 MiB),
  `..._MAX_TOOLS` (200), `..._MAX_FINDINGS` (100), and
  `..._IDEMPOTENCY_TTL_S` (24h). Caps are enforced before any surface snapshot
  is retained, and a breach is reported inconclusive rather than clean.
- Idempotency for boundary reviews: the CLI sends a random `Idempotency-Key`,
  the deployment stores only its digest bound to the verified principal and
  server, and a repeat replays the original result without appending evidence.
  The route sends `Cache-Control: no-store`, `Pragma: no-cache`, `Expires: 0`,
  and `Vary`, and the CLI never follows redirects, ignores environment
  proxies, verifies TLS, and requires HTTPS outside loopback.
- Stricter shared credential parsing: `Authorization` must be exactly one
  `Bearer <token>`. `Bearer Bearer <key>`, `Basic`, empty, duplicate, and
  conflicting forms now fail closed on every route that uses the shared
  resolver.
- Boundary-review responses carry `Cache-Control: no-store`, `Pragma: no-cache`,
  `Expires: 0`, and `Vary: Authorization, X-API-Key, Idempotency-Key` on every
  status — including the router-generated 405 and the default 500 — applied by
  ASGI middleware plus a server-error handler rather than only inside the route.
- The boundary-review POST body is bounded by
  `INTERLOCK_CI_BOUNDARY_REVIEW_MAX_REQUEST_BYTES` (default 8 KiB, ceiling
  1 MiB) using the shared bounded reader now also used by the Streamable HTTP
  transport. The body is still ignored; oversized declared or chunked bodies
  are refused with 413 after authentication and before any write.
- The CI gate unwraps urllib's exception chain so a TLS/certificate failure is
  `protocol_error` (exit 4) instead of being mistaken for a transient outage,
  and validates the base-URL path prefix (percent-encoding, backslashes,
  control characters, doubled slashes, and `.`/`..` segments are refused;
  `https://host/interlock` is supported for reverse-proxy deployments).

### Changed

- Boundary-review limits now fail closed: an explicitly set but unparsable or
  out-of-range value raises `config.ConfigurationError` at startup, before any
  database or network work, instead of silently substituting the default.
  Unset or empty still selects the documented default.

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
- Release metadata aligned on `0.2.0-alpha.1` across Python, dashboard,
  FastAPI, SIEM event, and Helm chart metadata.

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
- MCP control-plane and data-plane authorization split: server registration,
  verification, rebaseline, approval, quarantine, unregister, and the global
  MCP audit require an API key with `admin` scope; runtime-only keys receive
  HTTP 403 on those routes.
- MCP tool-call roles are resolved from the authenticated API key; a
  caller-supplied request-body role is ignored. The authenticated principal
  and resolved role are recorded in MCP audit rows and Security Receipts.
- Upstream tool-call responses validate HTTP status, JSON-RPC errors, and
  result-envelope shape so upstream failures cannot surface as successful
  calls.
- SIEM and webhook content is redacted by default; content previews require
  the explicit `SIEM_INCLUDE_CONTENT=true` opt-in.
- PyJWT upgraded to 2.13.0 and idna to 3.15 for the reported pip-audit CVEs.

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
