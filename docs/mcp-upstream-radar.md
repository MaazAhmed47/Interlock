# MCP Upstream Radar

Interlock uses public MCP releases and specification material as an input to
compatibility work. Contributor access is useful for discussion, but it is not
required to observe an upstream change or make a defensible implementation
decision.

## What the watcher does

`.github/workflows/mcp-upstream-watch.yml` runs every Monday and can be run
manually. It checks public GitHub releases for the MCP specification, the
TypeScript and Python SDKs, Inspector, and Registry against the reviewed tags
and timestamps in `docs/mcp-upstream-baseline.json`. The timestamp prevents a
new watcher from turning historical releases into a noisy backlog.

When it finds an unreviewed release, it opens one issue containing the public
links and a stable marker. It does not modify Interlock, update the baseline,
or claim protocol support. A maintainer must classify the change and update
the baseline in a reviewed commit. The watcher continues to surface a release
until that happens.

Run it locally:

```bash
python3 scripts/mcp_upstream_watch.py
```

## Review rule

For every upstream item, record one decision in the issue or linked PR:

| Decision | Meaning |
| --- | --- |
| `no action` | No effect on Interlock's trust boundary or supported paths. |
| `test update` | Existing behavior needs a regression or conformance test. |
| `compatibility design` | A supported transport, lifecycle, authorization, or schema boundary needs design work. |
| `supported behavior` | Code and proof now support the change. Update product documentation only after this decision. |

Changes deserve review when they affect tool descriptions, schemas, output
schemas, annotations, tool-list freshness, list-change signals, server
identity, authorization, request metadata, transport framing, or protocol
version negotiation.

## Current compatibility posture

Interlock is a runtime drift gateway for its configured MCP HTTP JSON-RPC
tool-list and tool-call paths. It does **not** currently claim complete MCP
transport or lifecycle conformance. In particular, protocol support must not
be inferred from the existence of a proxy endpoint.

The public `2026-07-28` MCP release candidate is a planning input, not a
supported Interlock protocol version. Its changes that matter to Interlock are:

1. `server/discover` and per-request protocol metadata. These affect server
   identity and version-aware baselining.
2. Stateless request handling and Streamable HTTP changes. These affect the
   gateway transport boundary.
3. `tools/list` cache/freshness fields and subscriptions. These can become
   recheck triggers, not drift findings by themselves.
4. Broader JSON Schema 2020-12 and `$ref` requirements. These need explicit
   normalizer and resource-bound tests before being accepted as supported.
5. Authorization and client-registration changes. These can change the
   observable effective permission boundary, which remains relevant to
   Interlock's behavioral-drift proof.

The compatibility goal is a tested dual-era path when there is a buyer need:
legacy servers remain explicitly supported where proven, while modern support
is added through `server/discover`, version metadata, and transport
conformance tests. Do not advertise a general MCP-gateway claim before those
tests exist.
