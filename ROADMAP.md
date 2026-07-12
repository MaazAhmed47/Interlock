# Roadmap

Interlock is an MCP runtime trust layer for AI agents, currently at
`0.2.0-alpha.1`. This document states plainly what works today, what the
known limitations are, and what is planned. It exists so that anyone
evaluating Interlock knows exactly where the boundaries are without having
to discover them. No dates are attached to planned work; items ship when
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
  quarantine, receipt, offline receipt verification — with no network access
  and no account.

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

## Planned

In rough priority order; each item closes a limitation above.

- **Official MCP SDK adoption and transport completeness.** Build the
  gateway's MCP surface on the official SDK; support Streamable HTTP and
  stdio transports and correct session lifecycle handling, verified against
  SDK-based reference servers.
- **Signed and externally anchored receipts.** Key-based signatures over
  receipt content and periodic anchoring of the chain head outside the
  primary database, so verification does not depend on trusting the
  database.
- **Identity-bound authorization hardening.** Bind tool approvals and
  probes to the acting principal (agent identity, scopes) rather than the
  API key alone, and tighten the control-plane authorization model.
- **Tenant isolation.** A real multi-tenant story for the hosted path:
  isolated storage, per-tenant limits, and per-tenant audit chains.
- **Published detection benchmarks.** Precision/recall on a published
  drift/injection corpus and latency distributions per scan layer, updated
  per release, so "it detects drift" is a measured claim.
- **Pre-execution effect controls.** Narrow the first-call effect-drift
  window (e.g. enforced dry-run modes, effect-class argument gating) so
  outcome drift can be held before the upstream call, not only after
  observation.
