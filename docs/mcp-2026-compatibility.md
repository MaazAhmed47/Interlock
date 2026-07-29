# MCP 2026 compatibility boundary

Interlock implements a deliberately narrow subset of the final MCP
`2026-07-28` wire profile. This is not a claim of full MCP 2026 compliance. The
profile is externally evaluable only for gateway-mediated calls; direct client
connections to an upstream MCP server bypass Interlock entirely.

The earlier audit used the `2026-07-28-RC` prerelease. The official repository
subsequently published a separate, non-prerelease [`2026-07-28`
release](https://github.com/modelcontextprotocol/modelcontextprotocol/releases/tag/2026-07-28).
This matrix is pinned to that final tag's commit.

## Pinned sources

| Source | Version / commit | Publication state | Authority used here |
|---|---|---|---|
| [MCP specification release](https://github.com/modelcontextprotocol/modelcontextprotocol/releases/tag/2026-07-28) | `2026-07-28`; `5f5440bb26a62e2cf3440b92da5a667efa03b267` | Stable GitHub release, not marked prerelease | Revision publication state and immutable source tree |
| [TypeScript schema](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/5f5440bb26a62e2cf3440b92da5a667efa03b267/schema/2026-07-28/schema.ts) | same commit | Dated final schema artifact | Request `_meta`, `resultType`, cache hints, discovery shape, and result identity metadata |
| [Streamable HTTP](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/5f5440bb26a62e2cf3440b92da5a667efa03b267/docs/specification/2026-07-28/basic/transports/streamable-http.mdx) | same commit | Dated final specification | Stateless POST transport and standard HTTP headers |
| [`server/discover`](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/5f5440bb26a62e2cf3440b92da5a667efa03b267/docs/specification/2026-07-28/server/discover.mdx) | same commit | Dated final specification | Discovery result and `_meta["io.modelcontextprotocol/serverInfo"]` identity placement |
| [Python SDK release](https://github.com/modelcontextprotocol/python-sdk/releases/tag/v2.0.0) | `mcp==2.0.0`; `6f69a3758ebf2ee55ce050f58b470ce11af71133` | Stable SDK release | Official Python client behavior |
| [Python SDK migration guidance](https://github.com/modelcontextprotocol/python-sdk/blob/6f69a3758ebf2ee55ce050f58b470ce11af71133/docs/migration.md) | same commit | Version-pinned SDK documentation | Python v2 connection modes and migration boundary |
| [TypeScript client release](https://github.com/modelcontextprotocol/typescript-sdk/releases/tag/%40modelcontextprotocol%2Fclient%402.0.0) | `@modelcontextprotocol/client@2.0.0`; `cc4b41617ce3601b1290d67216ea0b194a3cd9ac` | Stable SDK release | Official TypeScript client behavior |
| [TypeScript server release](https://github.com/modelcontextprotocol/typescript-sdk/releases/tag/%40modelcontextprotocol%2Fserver%402.0.0) | `@modelcontextprotocol/server@2.0.0`; same commit | Stable SDK release | Official strict modern server behavior |
| [TypeScript 2026 migration guidance](https://github.com/modelcontextprotocol/typescript-sdk/blob/cc4b41617ce3601b1290d67216ea0b194a3cd9ac/docs/migration/support-2026-07-28.md) | same commit | Version-pinned SDK documentation | Explicit pin/no-fallback configuration and migration semantics |
| [MCP conformance tool](https://github.com/modelcontextprotocol/conformance/tree/a9896553900a2ef61787b57adfcbbe936a8ab1f9) | `0.2.0-alpha.10`; `a9896553900a2ef61787b57adfcbbe936a8ab1f9` | Alpha/pre-release supporting tool | Supplemental stateless-server checks only; not sole proof |

The Python wheel `mcp-2.0.0-py3-none-any.whl` was installed only in a
disposable environment after verifying SHA-256
`1cb4c75d2d2c7b8c1d756355e5d82a39f2822cc7f13e22a2051d7ca3592349d6`.
The npm registry integrity values were
`sha512-8f1OghQ2rjzIOfqgUCP+8GiUWqRs89njoWLNqAe8kWmDePv3s1fZXseej+QXemssEuuOvLLmLO/kqM3IQHtISw==`
for the client and
`sha512-YhHWdHfpFMQfd0prsEnxKeS3Qz3ytIGmsS0sth4KDjnacIT7hxk6hXHkJ9KysxlkvTM+WZAtQbbcUhdoP4Hvtw==`
for the server. None is a production dependency.

## Support matrix

| Direction | Capability | Status | Exact boundary |
|---|---|---|---|
| Client to Interlock | Streamable HTTP POST with one JSON-RPC request | Supported | JSON responses only at `/mcp/stream/{server_id}`; Origin, authentication, rate limit, body-size, protocol header, method header, name header, and per-request `_meta` are checked. |
| Client to Interlock | `clientInfo` request metadata | Recommended, optional | Both official SDKs supplied it in tested traffic. Interlock does not require it and validates it when supplied. Protocol version and client capabilities remain required in every request `_meta`. |
| Client to Interlock | `server/discover` | Supported | Advertises only `2026-07-28` and the tools capability. Server identity is stamped in result `_meta`; required private cache hints are included. |
| Client to Interlock | `tools/list` | Supported | Returns only verified, active, allowlisted, stored tool definitions that are callable through the gateway. Private cache hints are returned. |
| Client to Interlock | `tools/call` | Supported | Calls traverse stored-boundary eligibility, authorization, inspection, RBAC, drift holds, upstream forwarding, response scanning, rate limiting, and receipt/audit behavior. |
| Client to Interlock | Unknown or unavailable tool | Blocked | Returns a generic JSON-RPC `-32602` protocol error without exposing whether the tool was missing, blocked, quarantined, inactive, or excluded for unsupported metadata. No upstream call occurs. |
| Client to Interlock | Required client capability / `-32021` | Unsupported / unimplemented | Interlock currently declares no tool requiring a client capability. Missing-capability behavior and JSON-RPC `-32021` are therefore not exercised by the current tool surface or SDK probes and are not claimed as supported. |
| Client to Interlock | Protocol sessions, `initialize`, `notifications/initialized`, GET lifecycle, DELETE lifecycle | Blocked | No session is created. Removed or unsupported RPC methods return HTTP 404 with JSON-RPC `-32601`; GET and DELETE return 405. |
| Client to Interlock | SSE response streams and resumability | Unsupported | Interlock currently chooses JSON responses only. It does not advertise resumability and never emits `Mcp-Session-Id` or `Last-Event-ID`. |
| Client to Interlock | MRTR / `input_required` | Unsupported | Not advertised; no retry state or client-input driver is implemented. |
| Client to Interlock | `subscriptions/listen` and list-change subscriptions | Unsupported | Not advertised; requests fail closed as unsupported methods. |
| Client to Interlock | Tasks and other extensions | Unsupported | Not advertised; requests fail closed as unsupported methods. |
| Interlock to upstream | Existing bare JSON-RPC upstream behavior | Supported | Registration default is the explicit `legacy` profile. Existing single-response `tools/list` and `tools/call` payloads remain unchanged. This does not claim complete legacy Streamable HTTP session support. |
| Interlock to upstream | Explicit `2026-07-28` profile | Supported, scoped | Admin registration pins the profile. `server/discover`, `tools/list`, and `tools/call` carry the protocol version header, method/name headers, and per-request metadata. A declared modern server is never silently downgraded. |
| Interlock to upstream | 2026 discovery negotiation | Supported, pinned | Interlock requires `server/discover` to return `resultType: complete`, the pinned version, tools capability, required cache hints, a valid JSON-RPC envelope, and valid optional identity metadata before accepting `tools/list`. |
| Interlock to upstream | Paginated `tools/list` | Blocked | A non-empty `nextCursor` rejects the observation so Interlock cannot record a partial surface as complete. Pagination is future work. |
| Interlock to upstream | SSE response parsing | Blocked | Requests send the required dual-value `Accept` header, but non-JSON responses are rejected. SSE parsing is future work, so full transport conformance is unproven. |
| Interlock to upstream | 2026 MRTR / `input_required` | Blocked | Only `resultType: complete` is accepted. No retry or downgrade occurs. |
| Both gateway directions | `x-mcp-header` tool parameters | Blocked | Tools containing the annotation are excluded from the inbound advertised surface, rejected from candidate baselines, and denied before upstream invocation. Correct validation and forwarding are future work. |
| Both gateway directions | Tasks, subscriptions, roots, prompts, resources, logging, sampling, elicitation | Future | Not part of this release scope and not advertised as supported. |

## Legacy pagination containment

Any upstream `tools/list` response with a non-empty `nextCursor` is rejected.
Interlock will not record page one as a complete approved surface.

This applies to legacy and `2026-07-28` upstream profiles and affects
registration, verification, discovery, rebaseline, CI boundary review, and
refresh operations. The upstream must expose a complete single-page tool list
until Interlock implements safe pagination.

## Upstream registration

`POST /mcp/servers` accepts `upstream_protocol_profile` with exactly two
values:

- `legacy` (default): preserves the pre-existing bare JSON-RPC adapter.
- `2026-07-28`: pins the modern stateless request profile. Protocol mismatch,
  missing metadata, unsupported result types, pagination, or malformed
  responses fail closed. There is no automatic legacy retry.

Existing SQLite and Postgres rows migrate to `legacy`. This default preserves
behavior and avoids silently treating previously registered servers as modern.

## Claim boundary

The proven claim is: Interlock can expose a scoped stateless MCP 2026 tool
endpoint and can mediate single-page, JSON-response discovery and complete tool
calls to an upstream explicitly pinned to the same profile. Authorization,
approved-boundary comparison, holds, response scanning, and receipt generation
remain on the Interlock gateway path.

The following claims remain unproven: full MCP 2026 compliance, compatibility
with SDK versions other than those pinned below, SSE interoperability,
paginated surface baselining, MRTR, subscriptions, tasks, extension
negotiation, or protection of connections that bypass the gateway.

## Tested SDK interoperability

| SDK and explicit profile | Direction | Operations | Result and boundary |
|---|---|---|---|
| Python `mcp==2.0.0`, `mode="auto"` discovery | SDK client to Interlock | `server/discover`, `tools/list`, `tools/call` | Pass. The SDK parsed `_meta` server identity, required `resultType`, and cache hints. The successful probe emitted no fallback traffic. |
| Python `mcp==2.0.0`, `mode="2026-07-28"` | SDK client to Interlock | `tools/list`, `tools/call`; rejection path | Pass. This SDK's explicit pin adopts the version without a discovery round trip. A protocol rejection did not produce `initialize`. |
| TypeScript client `2.0.0`, `versionNegotiation.mode.pin = "2026-07-28"` | SDK client to Interlock | `server/discover`, `tools/list`, `tools/call`; rejection path | Pass. The explicit pin discovered and parsed Interlock's identity; a protocol rejection did not produce `initialize`. |
| TypeScript server `2.0.0`, `createMcpHandler(..., { legacy: "reject", responseMode: "json" })` | Interlock to SDK server | `server/discover`, `tools/list`, `tools/call` | Pass with an explicit Interlock `2026-07-28` upstream profile. Exact modern headers and request metadata were observed. |
| Conformance `0.2.0-alpha.10`, `server-stateless` | Alpha conformance client to Interlock | Supported stateless subset | Supporting evidence only: 21 checks succeeded; 4 checks failed because Interlock does not declare the scenario's diagnostic tools. One absent tool is the scenario's required-client-capability probe; because Interlock declares no capability-gated tool, `-32021` remains unimplemented and unexercised. Five subscription checks were skipped because subscriptions are unsupported. This is not a conformance-suite pass. |
| Python `mcp==2.0.0b2` | Historical only | `server/discover` | Known superseded-beta failure: b2 required top-level `serverInfo`. Interlock still provides no compatibility shim. This result does not qualify the stable `2.0.0` result above. |

These probes do not cover arbitrary servers, every SDK configuration, direct
upstream connections, or unsupported protocol features. The official SDKs are
test-only executables in isolated environments; they are not imported by
Interlock at runtime.
