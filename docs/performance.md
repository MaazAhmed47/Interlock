# Performance And Latency

Interlock has two different performance profiles.

1. Deterministic gateway controls: metadata checks, RBAC, tool argument inspection, response regex scanning, PII redaction, and audit writes.
2. Provider-dependent controls: LLM judge calls and upstream model/tool calls.

Measure these separately. Do not blame Interlock for upstream MCP server or LLM provider latency.

---

## In-Path Controls

| Path | Expected latency source |
|---|---|
| `/inspect/tool-call` | local argument flattening, regex checks, RBAC |
| `/mcp/call` before forwarding | key lookup, server lookup, whitelist, drift/provenance/policy checks, argument inspection |
| `/mcp/call` after forwarding | response scanning, redaction, audit write |
| `/scan/output` | local response injection, PII, and volume checks |
| `/scan` | deterministic layers plus optional LLM judge depending on key/fail mode |

---

## Smoke Benchmark

Run:

```bash
python demo/performance-smoke.py
```

The script measures local deterministic scanners without network calls. Treat it as a laptop smoke test, not a production benchmark.

---

## Pilot Acceptance Targets

Recommended targets for a first enterprise pilot:

| Metric | Target |
|---|---:|
| deterministic tool-call inspection p95 | under 25 ms excluding network |
| output scan p95 on typical tool response | under 25 ms excluding network |
| MCP drift check | under 50 ms excluding upstream MCP call |
| audit write | under 25 ms for local/pilot SQLite |
| LLM judge path | tracked separately because provider latency dominates |

If a buyer uses high-volume agents, run a benchmark against their actual tool payload sizes and MCP servers.

---

## Latency Controls

- Keep the LLM judge out of latency-critical tool paths where deterministic checks are enough.
- Use per-key fail modes intentionally.
- Set response volume limits per key.
- Route only relevant MCP servers through the pilot gateway first.
- Keep audit retention reasonable during early pilots.

---

## What To Show A CTO

Show the timing fields in scan responses, then show the smoke benchmark. The most important message is that Interlock separates local deterministic checks from upstream model/tool latency.
