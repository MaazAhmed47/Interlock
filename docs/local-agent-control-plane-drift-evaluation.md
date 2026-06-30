# Local agent control-plane drift evaluation plan

This is a non-production evaluation plan for testing Interlock as a runtime trust layer around a local coding-agent control plane with a small MCP tool set. It is intended for design-partner evaluation and technical review, not as a production certification or partnership announcement.

## Goal

Evaluate whether Interlock can answer the runtime trust question that appears after a tool has already been approved:

> Is this still the same effective tool, under the same approved boundary, for this caller and run context?

The evaluation focuses on MCP tools used by a local coding agent, such as repo access, docs access, GitHub/CI status, and controlled CI/action surfaces. The point is not first-time approval. The point is what happens after the baseline when a tool changes shape, capability, scope, response behavior, server identity, or downstream side-effect boundary.

## Evaluation boundary

Use only a local or isolated non-production workflow.

Recommended setup:

- one local coding-agent run or local control-plane harness;
- one test repository with no production secrets;
- one docs/search MCP surface;
- one GitHub/CI-style MCP surface or mock;
- Interlock running self-hosted between the agent/control plane and the MCP tools;
- no production credentials, no shared hosted backend, and no destructive external workflow.

Interlock should be evaluated as the runtime/gateway decision point. The MCP server should expose stable identity and capability metadata where possible, but the runtime/gateway owns enforcement and receipt generation because it sees the caller, run context, policy, approval state, and downstream side-effect boundary.

## Four-claim receipt contract

Each evaluation scenario should check whether the emitted receipt or audit evidence makes four claims separately instead of collapsing them into one generic log line.

| Claim | What the receipt should prove | Why it matters |
|---|---|---|
| 1. Approved baseline | The exact capability set, metadata/effect profile, tool identity, and surface hash approved at baseline. | Reviewers need to know what was originally trusted. |
| 2. Drift finding | The drift detected before execution: schema, metadata, effect, external reach, response exposure, effective permission, provenance, or chain risk. | Reviewers need to know what changed and why it mattered. |
| 3. Runtime decision | Whether Interlock allowed, monitored, held, quarantined, denied, or required review/re-approval. | The control outcome must be explicit and auditable. |
| 4. Boundary crossing | Whether an MCP call was forwarded after the decision; if yes, which approved call crossed the boundary; if no, that no downstream call was forwarded. | Security teams need to distinguish pre-execution quarantine from post-call observation. |

A strong receipt should also include evidence-safe identifiers: server id, tool name, caller/run context where available, policy decision, finding types, severity, argument hash, approved/current surface hash, receipt id, evidence digest, and hash-chain verification status.

## Baseline workflow

1. Start Interlock locally.
2. Register a small MCP set for the local agent/control-plane run:
   - `repo_read` or equivalent repository inspection tool;
   - `docs_search` or equivalent documentation lookup tool;
   - `ci_status` or equivalent CI/build status reader;
   - optional controlled `ci_recheck` / `enqueue` / action-like tool in mock or non-production mode.
3. Approve the initial safe baseline.
4. Capture the approved surface and metadata/effect profile.
5. Confirm the baseline receipt/evidence can answer claim 1: what was approved.

## Drift scenarios

Run one controlled drift at a time. Keep all scenarios evidence-safe and non-production.

| Scenario | Controlled change | Expected Interlock classification | Expected decision | Receipt claims to verify |
|---|---|---|---|---|
| Schema / required parameter drift | A previously optional field becomes required, or a new high-risk parameter appears. | `schema_drift` / material tool-definition drift when risk-bearing. | hold or quarantine if material; monitor if non-material. | Baseline schema hash, current schema hash, changed field, decision. |
| Read-only to write/external reach | A read/status tool gains write, recheck, enqueue, webhook, or network-reach behavior. | capability/effect/external-reach drift. | quarantine before continued trusted use. | Approved read-only profile, new effect/externality, no downstream call forwarded if quarantined. |
| Auth scope expansion | Scope changes from local/repo-scoped to account/org-scoped, or upstream permission allows a call that used to deny. | `effective_permission_expansion` / `behavioral_scope_drift` when observed through a canary probe. | quarantine for operator review. | Expected `403 denied`, observed `200 allowed`, same manifest/schema/arguments, argument hash, receipt digest. |
| Response/data exposure drift | A response begins carrying secret-like, policy-sensitive, or broader data than the approved profile. | response/data-exposure drift. | monitor, hold, or quarantine depending on sensitivity. | Approved response profile, current response profile, redaction/evidence hashes, decision. |
| Same tool name maps to different server/version | The same approved tool name is served by a different server identity, version, endpoint, or provenance. | provenance/server-identity drift. | hold or require re-approval. | Approved server/version identity, current identity, decision, whether call was forwarded. |
| Chain risk across tools | A planned run reads sensitive repo/config data, then sends it to a CI/action/external tool. | chain drift such as sensitive-read-to-external-effect or secret-to-execution. | deny before execution when the full chain is submitted/observed. | Planned chain hash, risky transition, denied step, no downstream boundary crossing. |

## Effective-permission proof command

Interlock includes a local live-style proof for the hardest behavioral case: same tool, same manifest, same schema, same arguments, but expected `403 denied` becomes observed `200 allowed`.

Run:

```bash
python3 demo/run_effective_permission_probe_live.py
```

Expected result:

- run 1: `403 -> 403`, no drift, decision `allow`;
- run 2: `403 -> 200`, `effective_permission_expansion` / `behavioral_scope_drift`, decision `quarantine`;
- manifest/schema hash unchanged across both runs;
- receipt evidence verifies;
- raw arguments, bearer token, auth headers, and full response bodies are not persisted.

## Evaluation checklist

A run is useful if it produces the following artifacts:

- baseline surface and metadata/effect profile;
- drift decision object or equivalent audit row for each scenario;
- Security Receipt for each material drift finding;
- proof that quarantined scenarios did not forward a downstream tool call;
- proof that allowed scenarios did record the approved boundary-crossing event;
- hash-chain verification for the audit log;
- a short notes file describing false positives, confusing output, missing fields, and operator trust gaps.

## Acceptance criteria

Interlock passes the local control-plane evaluation when:

- baseline approval is explicit and reproducible;
- material drift is detected before continued trusted execution where the gateway has enough information to decide;
- high-risk drift results in quarantine, deny, hold, or re-approval rather than silent allow;
- unchanged safe tools remain usable;
- receipts separate baseline, detected drift, decision, and boundary-crossing outcome;
- evidence is recomputable or hash-verifiable;
- sensitive runtime material is not stored in raw form;
- limitations are clear when a scenario requires provider-specific introspection or a chain the runtime never observes.

## Honest limits

- Interlock cannot prove a future chain it never sees or is never given.
- Behavioral probes do not introspect every provider's OAuth or admin configuration. They detect observable outcome drift, such as denied to allowed.
- Provider readback requires a safe readback path for the provider being tested.
- Production proof requires a customer-approved non-production canary and written scope.
- This evaluation is technical evidence for a design-partner workflow, not SOC 2, ISO, HIPAA, GDPR, or provider certification.

## Suggested next step

Start with two scenarios only:

1. schema/capability drift on a local repo or docs tool;
2. effective-permission drift using `demo/run_effective_permission_probe_live.py`.

If those receipts satisfy the four-claim contract, expand to response exposure, provenance drift, and chain analysis.
