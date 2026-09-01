# Interlock Control Contract

## Purpose

Interlock is a self-hosted control for a specific MCP runtime risk: an MCP tool
that was approved under one observed boundary changes later, while an agent
continues to treat it as trusted.

For supported, gateway-mediated calls, Interlock records an approved baseline,
compares later observations with that baseline, and can quarantine the affected
tool. Later gateway-mediated calls to that tool are held before upstream
forwarding until an authorized operator makes a new decision.

This document is the authoritative buyer-facing statement of that control. It
does not turn every Interlock feature or roadmap item into a security claim.

## Terms

| Term | Meaning |
| --- | --- |
| **Approved baseline** | The stored, reviewed representation of one server/tool boundary at a point in time. |
| **Observed boundary** | The definition, metadata, effective-permission observation, or other supported evidence Interlock currently has for that tool. |
| **Material drift** | A supported comparison finds a change that crosses the configured risk or policy threshold. |
| **Quarantine** | A per-`(server_id, tool_name)` trust state requiring operator review. It is not a server-wide pause. |
| **Hold** | Interlock returns a local refusal for a later gateway-mediated call to a quarantined tool instead of forwarding that call upstream. |
| **Approval** | An authorized operator accepts a reviewed baseline through Interlock's approval path. It changes Interlock's trust state; it does not deploy or undo upstream code. |
| **Security Receipt** | Hash-chained, tamper-evident decision evidence. It is not externally signed or independently anchored. |

## What Interlock Does

Interlock's core control is capability integrity after approval:

1. A customer explicitly registers and approves an MCP tool boundary.
2. Interlock re-discovers or otherwise obtains supported evidence for that tool.
3. It compares the observation with the approved baseline.
4. If the configured policy classifies the difference as material, Interlock
   records the finding and quarantines that specific tool.
5. A later gateway-mediated call to the quarantined tool is held before
   upstream `tools/call` forwarding.
6. An authorized operator can review the finding and approve a new baseline,
   keep the tool quarantined, or otherwise change Interlock's trust state.

The bundled offline proof demonstrates the surface-drift path. A separate,
controlled effective-permission proof demonstrates one behavioral case where
the visible tool surface stays the same while an expected denied operation later
returns allowed. That controlled probe is forwarded because Interlock needs the
upstream response to observe the changed behavior; the prevention value begins
with later gateway-mediated calls to that same tool.

## Supported Evidence And Decisions

| Evidence path | What can be established | Enforcement consequence |
| --- | --- | --- |
| Tool surface and metadata comparison | A supported observed definition/metadata boundary differs from the approved baseline. | Policy can deny or quarantine; later mediated calls to the quarantined tool are held. |
| Effective-permission probe or observation | A fixed supported operation produced a materially different normalized outcome. | The first observed/probed operation may already have reached upstream; later mediated calls to that same tool can be held after quarantine. |
| Response, effect, or readback evidence | A supported post-call observer found a defined exposure or side-effect change. | This is observation after a call. It can block continuation and quarantine later use; it does not undo the first side effect. |
| Runtime policy | A gateway-mediated call violates a configured policy. | The call can be allowed, monitored, denied, or quarantined according to that policy. |

Exact protocol/profile support is maintained in the [MCP compatibility matrix](mcp-2026-requirements-matrix.md).
An evaluation must pin the specific version, transport, client, and deployment
profile it is testing.

## Enforcement Boundary

Interlock's execution claims apply only to calls that actually traverse the
Interlock gateway. A direct agent-to-server connection is outside the gateway's
evidence boundary unless a separately tested deployment profile prevents that
route.

The Docker Phase 2 reference profile contains tested routing and direct-egress
controls for that reference topology. It is not a claim of Kubernetes, cloud,
customer-infrastructure, or universal DNS-rebinding enforcement. See
[Outbound destination security](outbound-destination-security.md).

An evaluation must document the actual route, identity boundary, fail mode, and
bypass assumptions before it treats Interlock as an enforcement control.

## Important Limits

Interlock does not claim to:

- prove that an unchanged tool definition is behaviorally safe;
- prevent the first observed behavioral change or reverse an already completed
  external side effect;
- establish causality between untrusted content and a tool call;
- protect unmanaged direct traffic, encrypted/unseen channels, or protocols it
  does not mediate;
- infer business impact, data classification, destination, dependency change,
  or actual side effects without a supported trusted evidence source;
- provide universal prompt-injection prevention, complete DLP, full MCP
  conformance, compliance certification, or production certification; or
- provide independently anchored evidence until independent signing/anchoring
  is implemented and verified.

## Operator Responsibilities

An operator using Interlock remains responsible for:

- choosing trusted MCP servers and least-privilege server credentials;
- registering the intended servers and tools explicitly;
- routing the intended traffic through a tested enforcement profile;
- choosing appropriate fail-open/fail-closed behavior for the workflow;
- reviewing quarantines and maintaining approval ownership;
- retaining and exporting evidence according to their own incident and legal
  requirements; and
- keeping independent controls such as network segmentation, server-side
  authorization, secret management, and human approval for irreversible work.

## How To Evaluate The Contract

Start with the [offline evaluator quickstart](evaluator-quickstart.md). For a
real team, use the scoped [design-partner evaluation](design-partner-evaluation.md)
and test only the server, transport, tool set, deployment route, and attack
cases agreed in writing. Detection-quality results are corpus-bound synthetic
evidence, not production rates; see [Detection Quality Evidence](detection-quality-evidence.md).
