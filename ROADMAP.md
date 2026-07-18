# Roadmap

Interlock is an MCP runtime trust layer for AI agents, currently at
`0.2.0-alpha.1`. This document states plainly what works today, what the
known limitations are, and what is deferred. It exists so that anyone
evaluating Interlock knows exactly where the boundaries are without having
to discover them. No dates are attached to deferred work; items ship when
they are actually done.

## What's proven today

These paths are implemented, covered by the test suite (500+ tests run as a
whole directory in CI), and reproducible end-to-end in the offline demo:

- **Capability drift detection.** A registered MCP tool's surface
  (description, input schema, annotations, derived effect metadata) is
  baselined at approval. If the same tool later presents a changed surface —
  new parameters, widened effects, exfiltration-flavored description edits —
  the change is classified, and high/critical drift quarantines the tool.
- **Behavioral (effective-permission) drift detection.** Expected-denied
  canary probes record what a tool's backing API actually permits. When a
  previously denied action starts succeeding (403 → 200) with the same
  identity and tool surface, the tool is quarantined with receipt evidence.
- **Quarantine before execution.** Calls to a quarantined or drifted tool
  are blocked at the gateway before the upstream call is made, and the
  denial is recorded with binding fields (call id, argument hash, surface
  hashes).
- **Hash-chained Security Receipts.** Every allow/deny/quarantine decision
  appends to a SHA-256 hash chain; receipts commit to the exact call
  context and fail verification if replayed against a different target,
  argument set, or tool surface.
- **Self-serve offline demo.** A docker-compose stack (gateway, mock MCP
  server, dashboard) that reproduces the full loop — approve, drift,
  quarantine, receipt, offline receipt verification — with no hosted
  dependency at runtime after initial provisioning and no account. Demo
  fixtures and credentials are explicit opt-in, all published ports are
  loopback-bound, only the bundled `mcp-mock` host is allowlisted, and
  production/hosted startup fails closed if offline-demo mode is enabled.

## Known limitations (acknowledged)

These are real gaps, not fine print. We would rather you read them here
than find them in a pilot.

- **The gateway only sees calls routed through it.** An agent with direct
  network access to an MCP server bypasses Interlock entirely. Deployment
  must make the gateway the only path (network policy, egress control);
  Interlock does not currently enforce that itself.
- **Effect drift is detected post-execution for the first call.** Outcome
  drift (a "dry-run" tool that suddenly applies changes) is judged from the
  upstream response, so the first drifting call has already executed by the
  time it is caught. Subsequent calls are blocked by the resulting
  quarantine. Only surface drift and quarantine state block pre-execution.
- **The audit chain is tamper-evident, not externally anchored.** The hash
  chain uses unkeyed SHA-256 and lives in the same database as the data it
  protects. It detects casual tampering; it does not resist an attacker
  with full database write access who recomputes the chain. There is no
  external anchor or signing key yet.
- **Response and prompt scanning is heuristic.** PII/secret detection in
  responses and the layered prompt scanning (rules, patterns, LLM judge)
  are pattern- and model-based, with known false positives and false
  negatives. Several concrete detection gaps are checked in as documented
  `xfail` tests in `tests/test_drift_adversarial.py` (e.g. exfiltration
  verbs outside the heuristic keyword set, indirect auth-scope widening via
  an innocuous-looking parameter).
- **Not yet protocol-complete against the official MCP SDK.** The gateway
  speaks the JSON-RPC tool-call subset it needs and is tested against mocks
  and mock servers, not certified against the official MCP SDK's transports
  and session semantics (Streamable HTTP, stdio, session lifecycle,
  notifications).
- **Single-tenant assumptions.** Per-key data separation exists, but there
  is no hard tenant isolation story (separate schemas/databases,
  per-tenant encryption) for hosting mutually distrusting customers.
- **No published detection benchmarks.** Detection quality claims are
  backed by the test suite and demo, not yet by published precision/recall
  and latency numbers on a stated corpus.

## Deferred work

This is a finite, staged backlog, not a claim that these capabilities are
already shipped. It does not block a controlled non-production evaluation
unless an item is directly relevant to that evaluation's scope.

### 1. Before a production pilot

- **DNS-aware outbound SSRF containment.** Resolve hostnames before
  connecting; deny private, loopback, link-local, multicast, and cloud
  metadata addresses; bound and revalidate redirects; and defend against
  DNS rebinding.
- **Streaming upstream response limits.** Enforce byte and time budgets
  while reading upstream responses, before decompression, JSON parsing, or
  inspection can consume an unbounded payload.
- **Learning-mode decision.** Either remove learned patterns from
  enforcement or make learning mode explicit, disabled by default,
  auditable, and operator-approved.
- **Idempotency and retry semantics.** Define safe duplicate and retry
  behavior for registration, approval, rebaseline, quarantine, and every
  audit-producing write.
- **Operational health surface.** Add a non-secret build/version endpoint,
  readiness checks for required dependencies, and bounded security metrics
  that do not expose credentials, prompts, tool arguments, or responses.
- **Controlled single-tenant pilot threat model.** Document and validate
  gateway-only routing, egress, credential storage, trusted administrators,
  backup/restore, incident handling, and explicit non-goals.
- **Official MCP SDK and transport completeness where required.** Adopt
  and verify official SDK transports, sessions, and lifecycle behavior only
  to the extent required by a real pilot, using SDK-based reference servers.

### 2. Authority and receipt evidence

- **Externally signed and anchored receipts.** Define signatures, external
  anchoring, key rotation, verifier trust roots, and compromise handling so
  verification does not depend on trusting the primary database.
- **Principal-bound authority evidence.** Bind approvals, probes, and
  receipts to authenticated principals and their scopes. Caller-supplied
  identity must never be accepted as authority evidence.
- **Real enterprise-managed authorization integration.** Claim ID-JAG or
  enterprise-managed authorization only after integration with a real
  issuer, audience, client, and resource server. Mock-only paths must remain
  disabled by default and must not be described as interoperable support.
- **Evidence lifecycle guarantees.** Specify and test retention, deletion,
  export, restore, and historical-verification behavior.

### 3. Detection and enforcement quality

- **Published detection benchmarks.** Publish precision, recall, and
  latency results on a stated, versioned corpus so detection claims are
  measurable and reproducible.
- **Principled closure of adversarial gaps.** Resolve the documented
  `xfail` cases for description exfiltration, indirect authorization
  widening, egress verbs, and safety-positive schema changes without
  replacing them with brittle keyword exceptions.
- **Pre-execution effect controls.** Narrow the first-call outcome-drift
  window with enforceable dry-run or effect-class controls that can hold a
  risky call before upstream execution.
- **Distributed abuse controls.** Add shared rate limiting and abuse
  controls before any multi-replica hosted deployment.

### 4. Hosting and operational scale

- **Tenant isolation when required.** Add isolated storage, encryption,
  limits, and audit boundaries before hosting mutually distrusting
  customers; do not imply that current per-key separation provides this.
- **Managed secret lifecycle.** Define least-privilege access, secure
  storage, rotation, revocation, and end-to-end redaction coverage.
- **Production-like data operations.** Test database migrations, rollback,
  backup, restore, and lock budgets under representative production-style
  conditions.
- **Supply-chain release controls.** Establish dependency policy,
  SBOM/provenance generation, vulnerability triage, image verification, and
  reproducible release evidence.

### 5. Demo and claim hygiene

- **Preserve the shipped offline-demo boundary.** Offline fixtures,
  credentials, and mock hosts must remain explicit opt-in and
  loopback-bound; hosted/production startup must continue to fail closed if
  demo mode is enabled, and normal startup must not seed demo data.
- **Claim-to-proof matrix.** Maintain a versioned mapping that distinguishes
  mock-only, offline-only, pilot-only, and production-verified evidence.
