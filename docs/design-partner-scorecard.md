# Interlock Design-Partner Pilot Scorecard

## Recording rule

This scorecard records facts for one named environment and test window. Enter
`unknown` when the team cannot establish a fact and `not exercised` when a case
was intentionally omitted. Do not convert either label to zero, pass, or fail.
Attach evidence references; do not paste secrets, customer data, raw tool
arguments/results, or confidential payloads.

Do not calculate a security percentage, benchmark score, detection rate,
compliance grade, ROI, or cross-control total. Surface drift, post-call
observation, network enforcement, and synthetic classifier results answer
different questions; see [Control Effectiveness Evidence](control-effectiveness-evidence.md).

## 1. Scope and evidence identity

| Field | Recorded fact |
| --- | --- |
| Partner/environment alias | |
| Interlock exact 40-character commit | |
| Source state clean and reproducible | Yes / No / unknown; evidence: |
| Test window in UTC | |
| Pilot phase | 1 / 2 / 3 / 4 |
| Deployment profile and differences from repository reference | |
| Agent/runtime and version | |
| MCP client/SDK and version | |
| Interlock entry path | `/mcp/call` / `/mcp/stream/{server_id}` / adapter / other |
| MCP protocol and transport by hop | |
| Upstream server/profile and version | |
| In-scope server IDs and tools | |
| Data classification | Synthetic / approved non-sensitive / other: |
| Accountable technical owner | |
| Approval owner | |
| Rollback owner | |
| Evidence custodian, location, and deletion date | |

## 2. Route and tool inventory

| Path ID | Source -> destination | Server/tool | Registered in Interlock? | Routed through Interlock? | Direct/fallback route present? | Validation evidence | Disposition |
| --- | --- | --- | --- | --- | --- | --- | --- |
| P-01 | | | Yes / No / unknown | Yes / No / unknown | Yes / No / unknown | | Managed / unmanaged / out of scope |

Summarize the inventory without percentages:

| Fact | Count or label | Evidence / qualification |
| --- | --- | --- |
| Registered in-scope MCP servers | | |
| Registered in-scope tools | | |
| Known unmanaged server paths | | |
| Known unmanaged tool paths | | |
| Unknown or untested paths | | |
| Operator-targeted shadow findings | | Do not imply network-wide discovery. |

## 3. Time to first useful evidence

Define useful evidence before starting. It must be an operator-actionable fact,
not installation completion or a dashboard screenshot.

| Field | Recorded fact |
| --- | --- |
| Start event and UTC timestamp | |
| Pre-agreed useful-evidence definition | |
| First qualifying event and UTC timestamp | |
| Elapsed time | |
| Receipt/audit/artifact reference | |
| Operator action enabled by the evidence | |
| If no useful evidence | `none observed` / `unknown`; reason: |

## 4. Exercise results

Use one row per pre-agreed case. Valid outcomes are `held`, `detected only`,
`allowed`, `not detected`, `inconclusive`, `not exercised`, and `out of scope`.

| Case ID | Control path | Expected outcome | Actual outcome | First call reached upstream? | Later same-tool upstream delta | Positive control | Receipt/evidence reference | Limitation or explanation |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| C-01 | | | | Yes / No / unknown | | Pass / Fail / not exercised | | |

### Observed drift events

| Event ID | Server/tool | Observation trigger | Drift type | Approved vs observed evidence | Disposition | Operator finding | Evidence reference |
| --- | --- | --- | --- | --- | --- | --- | --- |
| D-01 | | discovery / probe / response / effect / readback / chain | | | monitor / deny / quarantine | expected / false positive / true but acceptable / unknown | |

Do not count a timeout, rate limit, malformed result, failed discovery, or
missing positive control as detected/no-drift; label it inconclusive.

### Holds and quarantines

| Event ID | Quarantined `(server_id, tool_name)` | Cause | Hold attempted? | Upstream execution evidence | Unaffected-tool control | Reviewer | Time to decision | Final state |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| H-01 | | | Yes / No | zero delta / non-zero / unknown | Pass / Fail / not exercised | | | kept / restored / re-approved / unknown |

Quarantine is tool-scoped and proves a hold only for a later
gateway-mediated call to that same tool. Record direct and alternate paths in
the bypass table.

## 5. False-positive review burden

| Review ID | Trigger | Operator classification | Review minutes | People involved | Evidence missing? | Configuration/change required | Resolution |
| --- | --- | --- | --- | --- | --- | --- | --- |
| R-01 | | expected / false positive / ambiguous / unknown | | | Yes / No | | |

| Summary fact | Value |
| --- | --- |
| Total review events | |
| Total operator review minutes | |
| Median review minutes | `not calculated` unless the sample and method are recorded |
| Reviews still unresolved | |
| Main source of burden | |

Do not infer a production false-positive rate from this bounded sample.

## 6. Latency and availability impact

Record the workload, sample count, timestamps, warm-up, measurement point,
hardware, concurrency, timeout, and failures. If the method cannot separate
Interlock from network/upstream variance, say so.

| Measure | Baseline without pilot path | With Interlock | Difference | Sample/method | Qualification |
| --- | --- | --- | --- | --- | --- |
| p50 latency | | | | | measured / unknown / not exercised |
| p95 latency | | | | | measured / unknown / not exercised |
| p99 latency | | | | | measured / unknown / not exercised |
| Requests attempted | | | | | |
| Successful responses | | | | | |
| Timeouts/errors by category | | | | | |
| Observation window availability | | | | | Do not convert `/health` into deployment-SHA provenance. |

## 7. Bypasses and unknown paths

| Finding ID | Path or assumption | Test performed | Result | Evidence | Exposure if unresolved | Owner | Next action |
| --- | --- | --- | --- | --- | --- | --- | --- |
| B-01 | | | bypass found / denied / unknown / not exercised | | | | |

Explicitly consider direct agent-to-server calls, alternate credentials,
renamed/duplicated tools, cached definitions/connections, fallback SDKs, local
stdio adapters, alternate DNS/IP routes, non-HTTP protocols, proxy/firewall
gaps, and paths outside the selected Docker/kind profile.

## 8. Evidence and privacy review

| Check | Result | Evidence / action |
| --- | --- | --- |
| No production credentials used | Pass / Fail / unknown | |
| No customer or regulated data used | Pass / Fail / unknown | |
| Artifacts stored in approved location | Pass / Fail / unknown | |
| Screenshots/support material redacted | Pass / Fail / not shared | |
| Receipt/audit chain verified | Pass / Fail / not exercised | |
| Presented receipt context verified | Pass / Fail / not exercised | |
| Tampered-copy negative control rejected | Pass / Fail / not exercised | |
| Retention/deletion owner confirmed | Pass / Fail / unknown | |
| External attestation claimed | Must be `No` |

## 9. Operator decision

Select one; do not average the preceding facts.

- [ ] **Stop.** The risk is not material, ownership is absent, the path cannot
  be bounded, rollback failed, or evidence is not useful.
- [ ] **Revise and repeat the same bounded phase.** Configuration, evidence, or
  test design needs repair before a decision.
- [ ] **Proceed to the next pilot phase.** All entry gates for that phase are
  documented; this is not approval for production.
- [ ] **Consider a separately scoped next step.** A new written threat model,
  deployment review, data decision, and authorization are required.

| Decision field | Recorded fact |
| --- | --- |
| Decision and reason | |
| Material evidence supporting it | |
| Contradictory or inconclusive evidence | |
| Remaining limitations | |
| Accepted risks and approver | |
| Next action, owner, and due date | |
| Rollback result | |
| Public disclosure allowed? | `No` unless separately approved in writing |

## 10. Sign-off

| Role | Name | Decision/date |
| --- | --- | --- |
| Partner accountable technical owner | | |
| Partner security reviewer | | |
| Partner rollback owner | | |
| Interlock technical owner | | |

Sign-off confirms only that this record accurately describes the bounded
evaluation. It is not an audit opinion, endorsement, certification,
production-readiness statement, or partnership announcement.
