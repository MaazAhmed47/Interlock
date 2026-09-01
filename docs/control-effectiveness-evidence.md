# Control Effectiveness Evidence

This page maps each Interlock control claim to the evidence that can support
it. It is intended for an operator deciding whether to run a bounded
evaluation, not as a combined product benchmark, security certification, or
production effectiveness score.

An outcome is meaningful only when all three are named:

1. the **control path** that made the decision;
2. the **test or evidence source** that exercised it; and
3. the **deployment boundary** in which that evidence applies.

Evidence from different paths does not compose into one percentage. A passing
offline hold, a post-call provider readback, and a corpus-bound classifier
result answer different questions.

## Evidence Map

| Control path | What the evidence can establish | Reproducible source | Important boundary |
| --- | --- | --- | --- |
| Approved surface and metadata comparison | A supported observed tool definition differs materially from its approved baseline; policy can quarantine the affected tool. | [Offline evaluator](evaluator-quickstart.md) and the drift regression suite. | Discovery must happen before the later held call. Direct traffic is outside this gateway control. |
| Quarantine hold | A later gateway-mediated call to the confirmed-quarantined tool is refused before upstream `tools/call` forwarding. | [Offline evaluator](evaluator-quickstart.md). | The proof is a bundled local server and one named changed tool. It does not establish a server-wide pause or control over direct routes. |
| Effective-permission observation | A fixed, supported operation changed from an expected denied outcome to an observed allowed outcome despite an unchanged visible surface. | [Detection Quality Evidence](detection-quality-evidence.md), `DQV1-PROBE-001`. | The observed/probed operation is forwarded to obtain its result. Only later mediated calls to that same tool can be held after quarantine. |
| Inconclusive upstream behavior | A timeout, rate limit, or upstream error is kept distinct from either drift or no drift. | [Detection Quality Evidence](detection-quality-evidence.md), `DQV1-PROBE-003` through `DQV1-PROBE-005`. | Inconclusive observations are not counted as successful detection and should trigger operator investigation, not a guessed security conclusion. |
| Response, effect, or readback observation | A supported observer found a defined response exposure or side-effect change. | [Control Contract](control-contract.md) and the named proof packs in [Drift Proof Report](interlock-drift-proof-report.md). | This is post-call evidence. It can control continuation and later use but cannot undo the first external side effect. |
| Runtime policy | A gateway-mediated call matched configured policy and received the configured allow, monitor, deny, or quarantine disposition. | [Policy examples](policy-examples.md) and the gateway policy tests. | The decision is only as strong as the configured policy, trusted inputs, and enforced route. It is not a statement that all tool behavior is safe. |
| Egress-routing reference profile | The published Docker reference topology forces its enumerated HTTP paths through its configured proxy boundary. | [Outbound destination security](outbound-destination-security.md). | This is Docker reference-profile evidence only. It is not Kubernetes, cloud, customer-network, universal SSRF, or universal DNS-rebinding proof. |

## Detection-Quality Corpus

The versioned Detection Quality Evidence v1 corpus contains synthetic,
reviewed drift, no-drift, inconclusive, and known-gap cases. It uses the real
surface-drift and effective-permission paths, but it is **not a production
false-positive rate**, a customer workload sample, or a claim about all MCP
servers.

The report generator publishes its own numerator, denominator, and
qualification for every corpus-bound metric. Do not repeat those values in a
sales deck as product KPIs, combine them with proof-pack passes, or use them
to infer the result in a buyer environment. Re-run the report at the exact
revision under review and read the case rows, not only the aggregate.

The v1 corpus deliberately retains these unresolved cases:

| Case | Current outcome | Why it matters |
| --- | --- | --- |
| `DQV1-GAP-FN1` | Undeclared server-side behavior is allowed. | An unchanged manifest and stored metadata do not prove behavior is safe. |
| `DQV1-GAP-FN5-UNCORROBORATED` | Description-level forwarding language is monitored. | Attacker-controlled wording without trusted data-class corroboration is not treated as proven exfiltration. |
| `DQV1-GAP-FN7` | Delegation parameter addition is monitored. | An optional impersonation-like parameter is not yet elevated as high-risk drift. |
| `DQV1-GAP-FN10` | Remote-sync wording is monitored. | The current heuristic does not cover every semantic synonym for export. |
| `DQV1-GAP-FP2` | Verification-hint loss is denied. | The current policy can over-block an optional annotation downgrade. |
| `DQV1-GAP-HM1` | A required confirmation field is denied. | A safety-positive schema change can currently be treated as high risk. |
| `DQV1-GAP-HM3` | Optional-to-required tightening is denied. | A contract-tightening change can currently be more disruptive than its security effect warrants. |

Those cases are not footnotes. They are the conditions a serious evaluation
should test against the customer's own accepted operational risk.

## How To Use This In A Pilot

For every proposed control claim, record:

- the exact Interlock revision, MCP transport, client, server, and route;
- which evidence-map row is being evaluated;
- the pre-agreed safe scenario and expected disposition;
- whether the result was `held`, `detected only`, `not detected`,
  `inconclusive`, or `out of scope`; and
- the route, identity, credential, and failure-mode assumptions that make the
  result meaningful.

Use the [Design-Partner Evaluation](design-partner-evaluation.md) for the
evaluation process and the [Control Contract](control-contract.md) for the
authoritative product boundary. A buyer should decline a production deployment
when those artifacts cannot identify the route, the expected hold point, and
the relevant unresolved cases.
