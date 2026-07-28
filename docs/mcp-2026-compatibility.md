# MCP 2026 compatibility boundary

Interlock implements a deliberately narrow subset of the MCP `2026-07-28`
draft wire profile. This is not a claim of full MCP 2026 compliance. The
profile is externally evaluable only for gateway-mediated calls; direct client
connections to an upstream MCP server bypass Interlock entirely.

The protocol basis for this matrix is the official MCP specification, pinned
for reproducibility to repository commit
[`04d603e3de66ca8c4b1f79b4cd15568a12f72493`](https://github.com/modelcontextprotocol/modelcontextprotocol/commit/04d603e3de66ca8c4b1f79b4cd15568a12f72493):

- [Streamable HTTP source](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/04d603e3de66ca8c4b1f79b4cd15568a12f72493/docs/specification/draft/basic/transports/streamable-http.mdx)
- [Versioning and compatibility source](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/04d603e3de66ca8c4b1f79b4cd15568a12f72493/docs/specification/draft/basic/versioning.mdx)
- [`server/discover` source](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/04d603e3de66ca8c4b1f79b4cd15568a12f72493/docs/specification/draft/server/discover.mdx)
- [Tools](https://modelcontextprotocol.io/specification/draft/server/tools)
- [Draft schema](https://github.com/modelcontextprotocol/modelcontextprotocol/blob/04d603e3de66ca8c4b1f79b4cd15568a12f72493/schema/draft/schema.ts)

The dated specification was still published as a draft while this boundary was
implemented. Compatibility with a later final text is unproven until the matrix
and tests are rerun against that final text.

## Support matrix

| Direction | Capability | Status | Exact boundary |
|---|---|---|---|
| Client to Interlock | Streamable HTTP POST with one JSON-RPC request | Supported | JSON responses only at `/mcp/stream/{server_id}`; Origin, authentication, rate limit, body-size, protocol header, method header, name header, and per-request `_meta` are checked. |
| Client to Interlock | `server/discover` | Supported | Advertises only `2026-07-28` and the tools capability. Server identity is stamped in result `_meta`; required private cache hints are included. |
| Client to Interlock | `tools/list` | Supported | Returns only verified, active, allowlisted, stored tool definitions that are callable through the gateway. Private cache hints are returned. |
| Client to Interlock | `tools/call` | Supported | Calls traverse stored-boundary eligibility, authorization, inspection, RBAC, drift holds, upstream forwarding, response scanning, rate limiting, and receipt/audit behavior. |
| Client to Interlock | Protocol sessions, `initialize`, `notifications/initialized`, GET lifecycle, DELETE lifecycle | Blocked | No session is created. Removed or unsupported RPC methods return HTTP 404 with JSON-RPC `-32601`; GET and DELETE return 405. |
| Client to Interlock | SSE response streams and resumability | Unsupported | Interlock currently chooses JSON responses only. It does not advertise resumability and never emits `Mcp-Session-Id` or `Last-Event-ID`. |
| Client to Interlock | MRTR / `input_required` | Unsupported | Not advertised; no retry state or client-input driver is implemented. |
| Client to Interlock | `subscriptions/listen` and list-change subscriptions | Unsupported | Not advertised; requests fail closed as unsupported methods. |
| Client to Interlock | Tasks and other extensions | Unsupported | Not advertised; requests fail closed as unsupported methods. |
| Interlock to upstream | Existing bare JSON-RPC upstream behavior | Supported | Registration default is the explicit `legacy` profile. Existing single-response `tools/list` and `tools/call` payloads remain unchanged. This does not claim complete legacy Streamable HTTP session support. |
| Interlock to upstream | Explicit `2026-07-28` profile | Supported, scoped | Admin registration pins the profile. `server/discover`, `tools/list`, and `tools/call` carry the protocol version header, method/name headers, and per-request metadata. A declared modern server is never silently downgraded. |
| Interlock to upstream | 2026 discovery negotiation | Supported, pinned | Interlock requires `server/discover` to return `resultType: complete`, the pinned version, and a tools capability before accepting `tools/list`. |
| Interlock to upstream | Paginated `tools/list` | Blocked | A non-empty `nextCursor` rejects the observation so Interlock cannot record a partial surface as complete. Pagination is future work. |
| Interlock to upstream | SSE response parsing | Blocked | Requests send the required dual-value `Accept` header, but non-JSON responses are rejected. SSE parsing is future work, so full transport conformance is unproven. |
| Interlock to upstream | 2026 MRTR / `input_required` | Blocked | Only `resultType: complete` is accepted. No retry or downgrade occurs. |
| Both gateway directions | `x-mcp-header` tool parameters | Blocked | Tools containing the annotation are excluded from the inbound advertised surface, rejected from candidate baselines, and denied before upstream invocation. Correct validation and forwarding are future work. |
| Both gateway directions | Tasks, subscriptions, roots, prompts, resources, logging, sampling, elicitation | Future | Not part of this release scope and not advertised as supported. |

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
with every official SDK v2 build, SSE interoperability, paginated surface
baselining, MRTR, subscriptions, tasks, extension negotiation, or protection of
connections that bypass the gateway.

## Official Python SDK `2.0.0b2`

The official `mcp==2.0.0b2` release is not interoperable with the current
draft `server/discover` response shape. This is a pinned incompatibility, not
an Interlock compatibility claim:

- PyPI published wheel `mcp-2.0.0b2-py3-none-any.whl` on 2026-07-14 with
  SHA-256 `9c50ae5afa08960ab76d50aa3adab3184952d9bea7ef87f4a4a5ba68bdefcf0a`.
  The corresponding official SDK tag is
  [`v2.0.0b2` at `2713b53b127afc094dc97d6067df9f69b647661c`](https://github.com/modelcontextprotocol/python-sdk/tree/2713b53b127afc094dc97d6067df9f69b647661c).
- That release requires a top-level `DiscoverResult.serverInfo`. The current
  draft instead defines optional server identity at
  `result._meta["io.modelcontextprotocol/serverInfo"]` and removes the
  top-level discover member.
- The specification change landed in
  [modelcontextprotocol/modelcontextprotocol#3002](https://github.com/modelcontextprotocol/modelcontextprotocol/pull/3002)
  on 2026-07-16, two days after the b2 tag. The official SDK subsequently
  merged the corresponding correction in
  [modelcontextprotocol/python-sdk#3143](https://github.com/modelcontextprotocol/python-sdk/pull/3143).
- With b2 in `mode="auto"`, the correct discover response fails SDK model
  validation. The SDK then attempts the legacy `initialize` handshake.
  Interlock rejects that unsafe fallback with HTTP 400 / JSON-RPC `-32022`;
  it does not downgrade.

Interlock does not add a duplicate body `serverInfo`. The b2 wire request has
no trustworthy, unique SDK-profile discriminator: its HTTP user agent identifies
the generic HTTP library, while `clientInfo` is optional, self-reported metadata
that the specification says servers should not use to change behavior. A b2-only
production response therefore cannot be selected deterministically without
weakening the current contract.

The opt-in regression tests require an isolated interpreter rather than a
production dependency change:

```powershell
$env:INTERLOCK_MCP_SDK_B2_PYTHON = 'C:\path\to\isolated-venv\Scripts\python.exe'
pytest tests/test_streamable_mcp_integration.py -k 'official_python_sdk_2_0_0b2'
```

One test proves b2 rejects Interlock's current-draft response. A separate,
test-only server proves b2 accepts its embedded older profile. Neither test
changes the production response or supports a claim of MCP 2026 SDK
interoperability.
