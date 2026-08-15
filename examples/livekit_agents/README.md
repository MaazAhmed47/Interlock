# LiveKit Agents integration through Interlock's local MCP compatibility adapter

This fixed-scope example attaches a real LiveKit `MCPToolset` to a real LiveKit `Agent`. After the toolset initializes, the proof harness retrieves its discovered `FunctionTool` wrapper and invokes that wrapper directly through Interlock. It then proves that a material same-tool boundary change is quarantined before a later gateway-mediated wrapper call reaches the synthetic upstream.

> **Synthetic, local-only proof.** It uses synthetic customer data and must not target LiveKit production, a production Interlock deployment, or a real customer MCP server.

## Quickstart

From a fresh clone containing this review change set:

```powershell
git clone https://github.com/MaazAhmed47/Interlock.git Interlock-livekit-review
Set-Location Interlock-livekit-review
py -3.12 -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt -r examples\livekit_agents\requirements-pinned.txt
.venv\Scripts\python examples\livekit_agents\run_proof.py
```

Expected concise output:

```text
PASS LiveKit MCPToolset initialized through the local adapter
PASS initial gateway call forwarded upstream exactly once
PASS material same-tool drift quarantined read_customer
PASS later LiveKit call held with upstream execution delta zero
PASS receipt chain, evidence digest, and context binding verified
Evidence: .../examples/livekit_agents/.proof-artifacts/proof.json
```

The artifact contains the observed approval boundary, explicit approval-endpoint ordering and audit event, mutation, drift decision, tool-scoped quarantine inventory, execution deltas, review evidence, Security Receipt, verification checks, and post-detection execution query. The ephemeral raw API key, disposable SQLite database, and SQLite sidecars are not retained.

### Cleanup

```powershell
.venv\Scripts\python examples\livekit_agents\run_proof.py --cleanup
git status --short
```

Cleanup is marker-guarded and removes only the dedicated evidence directory created by this example. The runner tracks the child processes it starts and stops them when the owner context exits. The interruption regression injects `KeyboardInterrupt` inside that owner context and verifies its tracked child stops; it does not send an operating-system interrupt to the full runner. After cleanup, `git status --short` should show only the uncommitted review change set, or nothing when the change set is committed.

## Exact architecture

```text
real LiveKit Agent
  -- has attached --> real LiveKit MCPToolset
proof harness
  -- directly invokes --> discovered FunctionTool wrapper
  -> local stdio legacy-MCP compatibility adapter
  -> Interlock POST /mcp/call
  -> synthetic stateless MCP 2026-07-28 server
```

The runner first registers and verifies the synthetic server, discovers `read_customer`, and explicitly approves this observed boundary. The runner calls the explicit approval endpoint before `MCPToolset.setup()` and verifies the resulting `tool_baseline_approved` event through the public audit endpoint before setup:

```text
effects:       [read]
side_effect:   read_only
data_classes:  [user_content]
externality:   internal
private notes: excluded
```

The synthetic upstream later retains the same server/tool identity while changing the declared boundary to `[read, export]`, `[user_content, pii]`, and `external`. Drift detection is not automatic. The runner explicitly calls `POST /mcp/discover` after mutation; that discovery/observation refresh is what makes Interlock observe and compare the changed definition. Interlock's existing drift engine then classifies the observed `export` effect escalation as critical, quarantines only `read_customer`, and records the approved/observed surface hashes and reasons. The proof harness directly invokes the same already-initialized LiveKit wrapper again. Interlock returns `tool_quarantined` before building the upstream request, and the synthetic execution counter proves a zero delta for that attempt.

If the observation refresh fails, the current behavior is fail-stale: the last successfully observed approved state remains active, the upstream mutation is not classified or quarantined, and this proof aborts. A mutation alone does not produce detection evidence. Operators must restore discovery and complete a successful refresh before claiming that Interlock detected the drift.

The adapter obtains `tools/list` inventory from Interlock's persisted registry. Its `status=active`, `drift_action=allow`, and `drift_severity=none` check is an eligible-state filter, further narrowed by the example's configured tool-name allowlist. Changed, denied, and quarantined rows are omitted.

This is not independent adapter enforcement of explicit approval. Newly discovered tools can already have the same eligible-state fields before approval, and `/mcp/tools` does not expose a distinct explicit-approval marker. The runnable proof therefore relies on runner sequencing: explicit approval and audit verification happen first, then the configured tool-name allowlist and eligible-state filter are supplied to the adapter. This example does not prove a general adapter-level explicit-approval guarantee. The adapter forwards `tools/call` only through `/mcp/call` and never calls the synthetic server directly.

Proof children do not inherit the parent environment wholesale. The launcher copies only `COMSPEC`, `HOME`, `LANG`, `LANGUAGE`, `LC_ALL`, `LC_CTYPE`, `PATH`, `PATHEXT`, `SYSTEMROOT`, `TEMP`, `TMP`, `TMPDIR`, `USERPROFILE`, and `WINDIR` when present, then adds the example-controlled database and dotenv settings plus an explicitly empty `GROQ_API_KEY`. Proxy, cloud, LLM-provider, SSH-agent, cookie, session, authorization, token, credential, and secret variables are not inherited.

## What this proves

- LiveKit Agents 1.6.10's real `MCPToolset` and MCP SDK `ClientSession` successfully initialize against the local adapter while that toolset is attached to a real `Agent`.
- The harness's direct call to the discovered wrapper reaches Interlock and is forwarded exactly once.
- The approved boundary is read-only/internal and derived from persisted observed state.
- The explicit approval endpoint and its audit event are verified before toolset setup; this ordering is runner-enforced, not adapter-enforced.
- A same-identity read-plus-export/external change is material under Interlock's existing drift model.
- Quarantine is tool-scoped.
- A later direct call to the same initialized wrapper is held before upstream forwarding.
- Gateway audit evidence identifies the tool, approved and observed boundaries, reason, and decision.
- The emitted receipt passes every currently supported check: record lookup, chain integrity, receipt equality, evidence digest, and context binding.
- The post-detection audit query reports zero gateway-mediated executions and the held attempt.
- Retained JSON contains no raw API key, private sentinel, credentials, private-key material, or exception trace.

## What this does not prove

Interlock intentionally exposes a scoped, stateless MCP 2026-07-28 endpoint using `server/discover`; LiveKit Agents at the pinned source uses MCP `<2` and calls `ClientSession.initialize()`. The adapter, not Interlock's native MCP 2026 endpoint, satisfies LiveKit's legacy initialize lifecycle. This is not native LiveKit/Interlock MCP interoperability.

No `AgentSession` is started, and no Agent or LLM selects or invokes the tool. The proof harness retrieves the wrapper from the attached `MCPToolset` and invokes that wrapper directly. The proof therefore covers LiveKit's real MCPToolset initialization and wrapper behavior, not autonomous Agent execution.

This proof does not use LiveKit Cloud, audio/video transport, production data, a customer deployment, or a production canary. It is not a LiveKit endorsement, partnership, customer validation, or native compatibility claim.

## Pinned inputs

- Interlock base `origin/main`: `a78d5a0a4557a63f0db71e41a70d451c03bb13bb`
- LiveKit Agents source commit: `06c71f9c718e24a151630447755a9fa86851b389`
- Python 3.12.9
- LiveKit Agents 1.6.10, built from the exact commit above
- MCP SDK 1.28.1; LiveKit source declares `mcp>=1.24.0,<2`
- Docker 29.6.2, build `dfc4efb`
- Docker Compose v5.3.1

The runner verifies that the pinned Interlock base is an ancestor of the checkout, then records both `interlock_base_sha` and the actual `integration_head_sha` in `proof.json`. This continues to work after the integration is committed on a descendant of the pinned base.

`requirements-pinned.txt` pins the direct LiveKit source and MCP SDK inputs. It is deliberately not named or described as a resolved transitive lock. The proof itself runs as local Python processes and does not require Docker. Docker versions are recorded because repository validation includes Compose parsing.

## Prerequisites

- Git, needed both for the clone and the exact LiveKit commit pin.
- Python 3.12 with virtual-environment support.
- Loopback networking and permission to start child Python processes.
- Internet access during the first dependency install.
- Docker only if running the optional repository Docker validation below.

Do not install dependencies globally. The commands above use the repository-local `.venv`.

## Tests and verification

```powershell
.venv\Scripts\python -m pytest tests\test_livekit_agents_integration.py -q -s
.venv\Scripts\python -m pytest tests\test_mcp_gateway.py tests\test_mcp_gateway_upstream_errors.py tests\test_mcp_drift.py tests\test_drift_evidence.py tests\test_security_receipt.py -q
.venv\Scripts\python -m compileall -q examples\livekit_agents tests\test_livekit_agents_integration.py
docker compose config -q
```

The integration suite covers unavailable Interlock, adapter, and synthetic upstream; missing/invalid key; LiveKit initialization timeout; initial upstream failure; failed drift refresh; unchanged refresh; eligible-state and quarantined inventory; a fresh MCPToolset setup after quarantine; endpoint-backed pre/post-approval state characterization; a different tool drifting while the unaffected tool remains callable; an unwritable evidence path; marker-guarded cleanup; and injected `KeyboardInterrupt` teardown of an owned child process.

## Troubleshooting

### occupied ports

The runner selects free loopback ports by default. If a diagnostic requires fixed ports, use `--interlock-port 18001 --synthetic-port 19001`. An occupied requested port fails before any process starts. Choose unused loopback ports and rerun; do not expose either service publicly.

### LiveKit or MCP installation fails

Confirm Git can read `https://github.com/livekit/agents.git`, then rerun the install inside `.venv`. The direct reference must resolve exactly to `06c71f9c718e24a151630447755a9fa86851b389`; do not silently replace it with a different PyPI release.

### Docker build or Compose validation fails

Docker is not part of the proof runtime. For optional validation, first confirm `docker version` can reach the daemon and `docker compose version` reports Compose. Then run:

```powershell
docker compose config -q
docker compose build --no-cache interlock
```

If the Docker build fails while Python proof tests pass, report the Docker failure separately with its exact output; do not claim container proof and do not substitute mocks for the successful Python end-to-end path.

### A previous evidence directory exists

Inspect `examples/livekit_agents/.proof-artifacts/proof.json`, run the documented cleanup command, and rerun. The runner refuses to overwrite retained evidence or delete a directory without its exact ownership marker.
