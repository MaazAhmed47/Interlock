# Interlock Enterprise Boundary Controls

This document covers the hard edge cases that should not be hand-waved in buyer conversations. These are the places where no security product can honestly claim magic. Interlock's posture is to make the boundary explicit, add the strongest available control, and produce evidence that can be reviewed.

## 1. Chains Interlock Never Observes

Hard truth: Interlock cannot detect a future or external chain it is never shown and never observes. No gateway can infer calls that bypass the gateway or plans that are never submitted.

What Interlock supports:

- **Pre-execution planned-chain analysis** via `POST /mcp/chains/analyze` when an orchestrator submits the intended sequence.
- **Observed-chain reconstruction** via `core.chain_drift.analyze_observed_audit_chain()` for calls that already passed through Interlock but were not submitted as a plan upfront.
- **Receipts and audit correlation** for chain decisions and observed call sequences.

Coverage levels:

| Visibility | Interlock control | Prevention? | Honest claim |
| --- | --- | --- | --- |
| Planned chain submitted before execution | `run_chain_analysis` / `/mcp/chains/analyze` | Yes | Interlock can deny risky chains before provider calls. |
| Calls pass through Interlock but no chain was submitted | `analyze_observed_audit_chain` | No, post-hoc | Interlock can detect and preserve evidence after observing the sequence. |
| Calls bypass Interlock or are never submitted/observed | None | No | Not detectable by Interlock. Requires routing enforcement or provider-side audit integration. |

Buyer-safe wording:

> Interlock can block risky chains before execution when the orchestrator submits the chain, and it can reconstruct risky chains after the fact when calls pass through the gateway. It does not claim to detect tool calls it never sees.

## 2. Full OAuth / Provider Scope Introspection

Hard truth: there is no universal OAuth introspection API that works across all MCP providers and all SaaS platforms. Some providers expose scopes; some do not; some only expose behavior through allowed/denied calls.

What Interlock supports:

- **Provider-scope attestation comparison** with `core.provider_scope.compare_provider_scope_attestation()` when a provider-specific integration can read granted scopes.
- **Behavioral effective-permission probes** when scopes are opaque, such as `403 denied -> 200 allowed` with the same tool/schema/arguments.
- **Evidence-safe hashes** of scope sets and subjects. Raw scopes do not need to be persisted in proof reports.

Coverage levels:

| Provider visibility | Interlock control | Honest claim |
| --- | --- | --- |
| Provider exposes granted scopes | Compare baseline/current scope attestation; quarantine expansions. | Scope expansion can be detected directly. |
| Provider scopes opaque but safe canary call exists | Effective-permission probe detects denied -> allowed behavior. | Behavioral scope drift can be detected without introspecting provider internals. |
| Provider exposes neither scopes nor safe behavior probes | No reliable signal. | Requires provider cooperation, audit logs, or a narrower pilot design. |

Buyer-safe wording:

> Interlock does not claim universal OAuth introspection. It detects provider-scope drift directly when scopes are available, and behaviorally when scopes are opaque.

## 3. Production-Cluster / Production-Account Proof

Hard truth: local Docker, local Kubernetes, Gmail/Slack sandbox, and mock proof packs are not production proof. They are technical evidence that the detection path works. Production proof requires customer approval and a controlled canary.

What Interlock supports:

- **Production proof readiness check** with `core.enterprise_assurance.assess_production_proof_request()`.
- Required controls:
  - written approval
  - non-customer canary
  - rollback plan
  - maintenance window
  - provider readback plan
- Proof suite output that separates `PASS` from credential-gated `SKIP`.

Buyer-safe wording:

> The public proof suite is technical evidence. A production proof is a separate controlled canary with written approval, non-customer data, rollback planning, and readback verification.

## 4. Rollback After Hidden Side Effects

Hard truth: if a canary call already changed provider state, Interlock can prove the contradiction and stop continued use, but generic automatic rollback is impossible without provider-specific rollback tools.

What Interlock supports:

- **Remediation planning** with `core.remediation.plan_remediation()`.
- Generic actions:
  - quarantine the tool
  - preserve the Security Receipt
  - rotate or revoke credentials when needed
  - trigger manual incident review when no rollback exists
- Provider-specific actions when available:
  - run rollback tool
  - verify provider readback after rollback

Coverage levels:

| Side effect state | Rollback capability | Interlock action |
| --- | --- | --- |
| Drift caught before execution | Not needed | Deny/quarantine before provider side effect. |
| Side effect already happened; rollback tool exists | Provider-specific | Plan rollback and require readback verification. |
| Side effect already happened; no rollback tool exists | None | Containment only: quarantine, evidence, credential rotation, manual review. |

Buyer-safe wording:

> Interlock is prevention-first. For hidden side-effect canaries, it proves the mismatch and blocks continued use. Rollback is provider-specific and must be separately verified.

## 5. Formal Compliance / Certification

Hard truth: proof packs, tests, and receipts are technical evidence. They are not SOC 2, ISO 27001, or any other certification by themselves.

What Interlock supports:

- **Compliance posture assessment** with `core.enterprise_assurance.assess_compliance_posture()`.
- Evidence artifacts:
  - Security Receipts
  - hash-chain audit verification
  - proof-suite run summaries
  - documented limitations
  - non-production pilot runbooks

Missing for certification:

- external auditor attestation
- formal control owner review
- documented operational policies
- customer-specific deployment evidence

Buyer-safe wording:

> Interlock can provide technical evidence that supports a control review. It does not claim formal certification until an external audit or customer control process verifies it.

## How This Improves The Buyer Story

The point is not to pretend Interlock sees everything. The point is to be the runtime trust layer that is honest about visibility:

- If Interlock sees the tool surface, it can baseline and detect drift.
- If Interlock sees the call behavior, it can detect effective-permission drift.
- If Interlock can read provider state, it can catch hidden side effects.
- If Interlock receives the chain before execution, it can deny risky chains.
- If Interlock only observes the calls afterward, it can reconstruct and preserve evidence.
- If Interlock sees none of it, the buyer needs routing enforcement, provider audit integration, or a narrower pilot.

That honesty is stronger than claiming impossible coverage.
