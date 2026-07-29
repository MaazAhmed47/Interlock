# Interlock self-guided evaluator journey

This is a bounded, self-guided **non-production** evaluation of one Interlock
MCP trust-boundary workflow. It uses the real Interlock gateway APIs, drift
classifier, quarantine state, audit chain, receipt builder, and receipt verifier
with a bundled local MCP server. It is an engineering proof, not a marketing
simulation or a production-readiness claim.

The running scenario is loopback-only from the host. Gateway, dashboard, mock,
and runners use an internal Docker network; a fixed nginx proxy is the only edge
member and publishes the three loopback ports. The runner rejects service
origins outside explicit loopback and Compose-local names. The initial image and dependency build may need network
access; the scenario itself uses no credentials, third-party APIs, public MCP
servers, or user data.

## What you will evaluate

The bundled private document workspace initially exposes a useful
`read_file` tool with an internal, read-only boundary. You approve that
known-good definition and execute one benign call through Interlock.

The controlled MCP example then changes the same tool to add external export,
broader data handling, and attachment forwarding. Interlock discovers that
material boundary change and quarantines the stored tool. A subsequent call
through `/mcp/call` returns `tool_quarantined` before Interlock sends an upstream
`tools/call`. A separate counter inside the bundled MCP process must remain
unchanged, independently confirming that the changed tool did not execute.

The runner then retrieves real Interlock audit claims and verifies the real
Security Receipt before producing a sanitized proof pack.

## Prerequisites

- Git.
- Docker Engine or Docker Desktop with the `docker compose` command.
- Enough disk space and initial network access to download/build the declared
  Docker images and dependencies.
- Free loopback ports `8001`, `8080`, and `9100`.

No `.env` file, provider key, admin token, Python installation, Node.js
installation, cloud account, or MCP credential is required.

## 1. Clone a clean checkout

For the merged public repository:

```bash
git clone https://github.com/MaazAhmed47/Interlock.git
cd Interlock/demo/offline
```

To evaluate a specific review branch before merge, make the branch explicit:

```bash
git clone --branch agent/evaluator-journey-v2 --single-branch https://github.com/MaazAhmed47/Interlock.git Interlock
cd Interlock/demo/offline
```

Do not add an `.env` file or reuse state from another Interlock checkout.

## 2. Start Interlock and the local MCP example

```bash
docker compose up -d --build
```

Expected result: the gateway, dashboard, MCP mock, and one-shot baseline seeder
start successfully. Confirm with:

```bash
docker compose ps
```

`gateway`, `dashboard`, and `mcp-mock` should be running; `seeder` should have
exited successfully. The fixed demo key exists only because this Compose stack
sets `INTERLOCK_OFFLINE_DEMO=true`; it is not production configuration.

## 3. Run the complete evaluator proof

```bash
docker compose run --rm evaluator-runner run
```

Expected terminal milestones:

```text
[1/7] Start local services and reset the controlled MCP example
[2/7] Register, discover, and approve the known-good baseline
[3/7] Execute one benign approved call through /mcp/call
[4/7] Apply one controlled external-export boundary change
[5/7] Attempt the changed call through Interlock's gateway
[6/7] Retrieve and verify Interlock's real evidence
[7/7] Review artifacts and choose approve, reject, or rebaseline
      result=tool_quarantined forwarded=false upstream_execution_delta=0
      receipt_verified=true artifacts=evaluator-artifacts
```

Any nonzero exit is a failed evaluation. Do not treat a partial artifact
directory as proof; the runner removes incomplete packs and resets its mock
phase/counters on failure.

## 4. Review the evidence

The runner writes `demo/offline/evaluator-artifacts/` on the host:

| File | Evidence |
| --- | --- |
| `approved-state.json` | Normalized approved boundary and its real surface hash. |
| `changed-state.json` | Stored quarantine decision, severity, material change types, and observed surface hash. |
| `held-call.json` | Gateway hold plus before/after MCP execution counts; delta must be zero. |
| `receipt-summary.json` | Sanitized receipt decision, integrity hash, chain status, verifier checks, and surface hashes. |
| `summary.md` | Short human interpretation and claim boundary. |
| `feedback.md` | The seven evaluator comprehension questions. |
| `manifest.json` | SHA-256 digest for every other evidence file. |

The pack deliberately omits credentials, headers, request bodies, raw request
arguments, upstream URLs, raw server identifiers, receipt binding identity,
local absolute paths, and raw tool schemas. Hashes and normalized classifications
remain so an evaluator can distinguish the approved and observed evidence.

Optional UI review: open <http://localhost:8080/dashboard/>. The terminal proof
is complete without the UI. If prompted in dashboard Settings, use API URL
`http://localhost:8001` and the explicitly local key `lf-demo-offline-key`.

## 5. Choose the operator action

Review the evidence first, then run exactly one command.

Reject the changed boundary and keep the tool held:

```bash
docker compose run --rm evaluator-runner decide reject
```

Approve only the changed tool definition:

```bash
docker compose run --rm evaluator-runner decide approve
```

Stage, compare, and atomically approve the complete current server surface:

```bash
docker compose run --rm evaluator-runner decide rebaseline
```

These are not simulated buttons. They call Interlock's existing authenticated
approve, quarantine, or compare-and-swap rebaseline APIs. The selected result is
written as `operator-action.json`, and `manifest.json` is refreshed. “Reject” is
the evaluator language for the product's keep/mark-quarantined action; there is
no separate `/reject` endpoint.

## 6. Give structured feedback

Complete `evaluator-artifacts/feedback.md` without live coaching:

1. What did you think Interlock was checking before you ran it?
2. What changed in the MCP tool?
3. Why was the call held?
4. What evidence supported the decision?
5. What would you do next: approve, reject, or rebaseline?
6. Where did the process confuse or slow you down?
7. Would you keep Interlock in this workflow? Why or why not?

## 7. Clean up

```bash
docker compose down -v
```

The generated proof pack remains in the ignored `evaluator-artifacts/`
directory for review. Delete that directory when you no longer need it. No
production configuration is changed by this journey.

## Troubleshooting

- **A port is already allocated:** stop the local process using `8001`, `8080`,
  or `9100`, then rerun `docker compose up -d --build`. Do not change a binding
  to a public interface for this evaluation.
- **A build or pull fails:** verify Docker can reach its image/package sources.
  Runtime is intentionally isolated after images are built.
- **Seeder did not finish successfully:** run
  `docker compose logs gateway mcp-mock seeder`, then reset with
  `docker compose down -v` before retrying.
- **Runner reports a service unavailable:** run `docker compose ps`; wait for
  the gateway health check, then retry once.
- **The controlled change is not quarantined:** remove stale local state with
  `docker compose down -v`, start again, and rerun. Do not manually edit the
  database or artifact files.
- **Receipt verification fails:** treat the evaluation as failed. Capture only
  the sanitized terminal error and `docker compose logs gateway`; do not publish
  database files or raw HTTP traffic.
- **Artifacts are missing after a failure:** this is expected fail-closed
  cleanup. Only a complete successful run publishes the pack.

## What this proves

- Interlock recorded an approved local MCP tool boundary through its real APIs.
- A deterministic material surface change was discovered and classified.
- The stored tool became quarantined before the demonstrated gateway-mediated
  changed call reached upstream `tools/call`.
- The bundled upstream execution counter and Interlock's audit claim both report
  no changed execution after detection.
- The retrieved Security Receipt verified against Interlock's stored local audit
  evidence.
- An evaluator can apply one real approve, reject, or rebaseline action.

## What this does not prove

- Direct MCP connections that bypass Interlock are not protected or visible.
- The run does not prove arbitrary semantic or behavioral drift detection.
- Discovery occurs before the held call; Interlock does not rediscover every
  upstream tool on every invocation.
- The bundled MCP implementation and synthetic data do not establish behavior
  against a particular third-party server or real customer workload.
- A zero mock execution delta proves only that this bundled changed `tools/call`
  was not received. It is not a claim about traffic outside the Compose proof.
- Local hash-chained receipts are tamper-evident but are not externally signed or
  independently anchored.
- SQLite, a fixed local demo key, and one internal Docker network are suitable
  for this bounded evaluation, not proof of production readiness or scale.
