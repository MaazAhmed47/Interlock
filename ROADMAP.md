# Roadmap

Interlock is an MCP runtime trust layer for AI agents, currently at
`0.2.0-alpha.1`. This document states plainly what works today, what the
known limitations are, and what is planned. It exists so that anyone
evaluating Interlock knows exactly where the boundaries are without having
to discover them. No dates are attached to planned work; items ship when
they are actually done.

## What's proven today

These paths are implemented, covered by the full Python suite in CI, and the
scoped default surface-drift path is reproducible end-to-end in the offline demo:

- **Capability drift detection.** A registered MCP tool's surface
  (description, input schema, annotations, derived effect metadata) is
  baselined at approval. If the same tool later presents a changed surface —
  new parameters, widened effects, exfiltration-flavored description edits —
  the change is classified, and high/critical drift quarantines the tool.
- **Behavioral (effective-permission) drift detection.** Expected-denied
  canary probes record what a tool's backing API actually permits. When a
  previously denied action starts succeeding (403 → 200) with the same
  identity and tool surface, the tool is quarantined with receipt evidence.
- **Gateway hold after detected material drift.** Subsequent calls to a
  quarantined or materially drifted tool are blocked at the gateway before an
  upstream `tools/call` is forwarded, and the
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
  time it is caught. Subsequent calls to that tool are blocked by the
  resulting quarantine. Only surface drift and quarantine state block pre-execution.
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
- **Tested, pinned official-SDK interoperability; not full MCP conformance.**
  Official Python `mcp==2.0.0` and TypeScript client `2.0.0` probes cover the
  scoped stateless `2026-07-28` gateway path, and an official TypeScript server
  `2.0.0` probe covers pinned JSON/SSE upstream calls. These pins do not prove
  other SDK versions, stdio, subscriptions, sessionful transports, or full MCP
  conformance; see `docs/mcp-2026-compatibility.md`.
- **Single-tenant assumptions.** Per-key data separation exists, but there
  is no hard tenant isolation story (separate schemas/databases,
  per-tenant encryption) for hosting mutually distrusting customers.
- **No published detection benchmarks.** Detection quality claims are
  backed by the test suite and demo, not yet by published precision/recall
  and latency numbers on a stated corpus.

## Planned

In rough priority order; each item closes a limitation above.

- **Broader transport and session interoperability.** Preserve the pinned
  official-SDK probes while adding explicitly scoped coverage for stdio,
  subscriptions, and session lifecycle behavior. This remains compatibility
  work, not a promise of full MCP conformance.
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
- **Close the documented detection gaps (deferred).** Seven gaps are checked
  in as documented-gap assertions in `tests/test_drift_adversarial.py`:
  false negatives FN-1 (undeclared server-side behavior change is invisible
  to surface diffing), FN-5U (description-level exfiltration without a concrete
  sensitive resource or trusted approved data-class corroboration), FN-7
  (indirect auth-scope widening via an added delegation parameter), FN-10
  (export verbs outside the heuristic keyword set); and false positives FP-2
  (optional annotation-hint loss downgrades verification level and denies),
  HM-1 (added required safety field denied like any required-field addition),
  HM-3 (optional-to-required tightening scored high/deny). Each closure requires
  an adversarial regression case that fails before the fix, and corpus evidence
  regenerated at the fixed revision.
- **FN-5 resolved only at its corroborated boundary.** Newly added description
  text containing an ordered delivery instruction, a new public destination,
  and retrieved or returned content corroborated by a trusted declared data
  class in the approved baseline now denies. Concrete sensitive-resource
  delivery retains its existing detection path and does not require destination
  novelty. FN-5U remains a distinct known miss, so this corpus-bound result does
  not claim detection of arbitrary semantic exfiltration language.
- **Cautious evidence-corpus sanitizer expansion (deferred).** Extend the
  evidence-corpus input sanitizer with further unambiguous credential
  formats, such as AWS access-key identifiers, where the format is
  high-confidence. The limitation stands and is not removed by this work:
  arbitrary base64 or high-entropy text cannot be reliably classified as
  sensitive, so the sanitizer remains a defined set of high-risk patterns
  rather than general secret detection.
- **Larger versioned evaluation corpora (deferred).** Build domain-specific,
  versioned corpora and accept operator-supplied sanitized cases. This is a
  prerequisite for the published benchmarks item above: corpus-bound results
  on a small synthetic corpus do not generalize and must not be restated as
  a broader detection-quality claim.
- **Pilot evaluation evidence (deferred).** Collect evaluation evidence from
  real deployments only under explicit operator approval, with sanitized
  inputs and a written scope. Synthetic corpus-bound metrics must not be
  republished as a production false-positive rate.
