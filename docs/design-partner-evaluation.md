# Interlock Design-Partner Evaluation

## Goal

This is a fixed-scope evaluation for a team that operates high-impact MCP tools
and wants to determine whether Interlock's capability-integrity control reduces
a risk they actually own. It is not a production certification, a compliance
assessment, a penetration test, or a promise that Interlock solves all agent
security risks.

The intended result is a decision supported by evidence:

> In this named workflow and deployment boundary, did Interlock detect a
> security-relevant post-approval tool change and hold later gateway-mediated
> use without unacceptable operational cost?

## Good Fit

This evaluation is designed for teams whose agents use MCP tools that can read
sensitive data, modify code or infrastructure, send external messages, invoke
privileged APIs, or affect business workflows. The accountable participant is
normally a CTO, platform/agent lead, or security engineering owner who would
review the incident if a tool's authority changed.

It is not a strong fit for a text-only assistant, a workflow with no meaningful
tool authority, or a deployment where the team cannot identify the MCP route
and ownership boundary.

## Scope

The default evaluation covers one named non-production or tightly constrained
workflow, one MCP server, and an agreed tool set. Before installation, both
sides record:

- MCP protocol version, transport, client, and server identity;
- intended agent-to-gateway-to-server route;
- tool baseline and approval owner;
- configured policy/fail mode;
- known direct-route or observability limitations;
- agreed safe drift, replay, failure, and bypass test cases; and
- what data is allowed in the environment.

No production credentials, customer data, unrestricted network access, or
unbounded custom development is required for the default evaluation.

## Suggested 30-Day Plan

### Week 1: Architecture And Baseline

- Confirm the workflow, tool boundary, route, and accountable operator.
- Deploy Interlock in the agreed isolated profile.
- Register the server and create the approved baseline.
- Verify normal mediated calls and the documented failure behavior.

### Week 2: Control Tests

- Exercise agreed material surface/metadata changes.
- Exercise a supported effective-permission or behavioral case only where a
  safe canary/probe exists.
- Verify quarantine and later-call hold behavior.
- Exercise one agreed direct-route/bypass test for the actual deployment.

### Week 3: Operations

- Review operator decision time, false positives, failure handling, evidence,
  and measured latency/resource overhead.
- Correct configuration and workflow issues found during the evaluation.

### Week 4: Decision

- Produce a factual result table for the agreed cases.
- Separate `held`, `detected only`, `not detected`, `inconclusive`, and
  `out of scope` outcomes.
- Record deployment assumptions and unresolved risks.
- Decide whether a further limited pilot, paid deployment, or no-go is justified.

## Success Metrics

The customer and Interlock agree on thresholds before testing. Suggested metrics
are:

- agreed material changes detected;
- later gateway-mediated calls to the confirmed-quarantined tool held;
- bypass behavior in the supported deployment;
- false positives and cases requiring review;
- p50/p95/p99 added latency for the tested workflow;
- CPU/memory overhead under the agreed load;
- operator review time;
- recovery and Interlock approval-state rollback time; and
- evidence completeness for the agreed test cases.

No metric is generalized beyond the named environment, corpus, version, and
deployment assumptions.

## Responsibilities

**Customer:** provides a safe evaluation environment, identifies the workflow
owner and approval authority, controls its credentials and data, and decides
whether its environment can enforce the intended route.

**Interlock:** provides the documented product path, states the enforcement
boundary and limits, helps reproduce agreed tests, records factual outcomes,
and does not represent a limited evaluation as an audit, endorsement, or
production certification.

## Commercial Boundary

An evaluation should have a written scope, time limit, named contacts, and
fixed fee or explicitly agreed strategic design-partner terms. Any additional
integration work requires a separate decision. A successful evaluation can be
credited toward a self-hosted annual license; it does not obligate either side
to proceed.

## Exit Deliverable

The final report contains the tested architecture, Interlock version, agreed
cases, outcomes, metrics, limitations, and a recommended next decision. It
does not include customer secrets, raw credentials, or unapproved sensitive
payloads.
