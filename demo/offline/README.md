# Interlock — offline buyer demo

A self-contained, fully offline demo of Interlock's post-approval MCP drift
detection. One `docker compose up` brings up the gateway, a bundled mock MCP
server, the dashboard, and seeded baseline data. No hosted services, no API
keys, no external network for any core path.

What it proves (and nothing more): the two **live-proven** drift classes.

1. **Capability / surface drift** (default path): a tool a team approved as
   read-only changes under the same name into an external-export/PII tool.
   Interlock detects the drift at re-discovery, quarantines the tool **before
   any call executes**, and issues a tamper-evident Security Receipt.
2. **Behavioral / effective-permission drift** (advanced path): same tool,
   same schema — a call the upstream denied (403) later becomes allowed
   (200). An operator probe catches the effective-permission expansion and
   quarantines the tool.

## Quickstart

```bash
cd demo/offline
docker compose up -d --build     # gateway + mock + dashboard + auto-seed
python run_demo.py smoke         # prove the demo is ready (exit 0 = ready)
python run_demo.py scenario-a    # the narrated default demo path
```

No host Python? Every command also runs inside the compose network:

```bash
docker compose run --rm demo-runner smoke
docker compose run --rm demo-runner scenario-a
```

Dashboard: <http://localhost:8080/dashboard> → Settings → API URL
`http://localhost:8001`, API key `lf-demo-offline-key`.

In **Audit Log → Runtime Decisions**, every event has a **Receipt** button
(the tamper-evident record) and a **Verify** button (the four-claim evidence
view with live verification and a replay check).

| Command | What it does |
| --- | --- |
| `python run_demo.py seed` | Register + verify + approve the demo baseline (runs automatically on `up`) |
| `python run_demo.py scenario-a` | Capability drift, end to end (default path) |
| `python run_demo.py scenario-b` | Behavioral drift 403→200 (advanced path) |
| `python run_demo.py smoke` | Full readiness proof on throwaway servers |
| `python run_demo.py reset` | Remove demo/smoke servers, reset mock phases, re-seed |
| `python run_demo.py status` | Servers, review queue, recent audit rows, mock phases |

## The four-claim receipt

`GET /audit/receipt/{id}/claims` (and the dashboard **Verify** view) answers
four questions about one runtime event, all read from the hash-chained
`mcp_audit_log` — never from UI copy:

1. **What was approved** — the approved baseline surface hash
   (`sha256` over the canonical JSON of `{name, description, inputSchema}`).
   Where the canonical bytes are retained, an `inspect_path`
   (`/audit/evidence/surface/{hash}`) lets anyone re-derive the hash without
   trusting Interlock. Behavioral events also show the approved expectation
   (e.g. `denied / 403`).
2. **What changed** — the observed surface hash and the recorded drift
   reasons. For behavioral drift the approved and observed surface hashes are
   **identical** (`schema_unchanged: true`): the schema did not move, the
   behavior did (`allowed / 200`).
3. **What runtime decision Interlock took** — decision, rule, and reason,
   verbatim from the audit row.
4. **Whether any boundary-crossing call executed after detection** — a live
   query over all subsequent audit rows for the same server/tool, split into
   forwarded calls (`allow`/`monitor`) vs blocked attempts (`blocked_by`
   set). "No boundary-crossing call executed — quarantine happened first" is
   shown only when the query says executed count is zero. Scope is honest:
   only gateway-mediated calls are visible; calls made around Interlock
   cannot be counted.

## Replay / freshness invariant

A Security Receipt is bound to the exact call it was issued for. Each audit
row records a `binding`: `call_id`, target (`server_id/tool_name`),
`argument_hash` (sha256 of canonical arguments — raw values are never
stored), and the approved/observed surface hashes. These fields are
committed into the row's v2 chain hash, so they cannot be rewritten later
without breaking chain verification.

`POST /audit/receipt/verify` takes a receipt plus the context it is being
presented FOR, and fails if **any** of target, argument hash, call id, or
surface hash differ from the record — plus chain verification, stored-record
comparison, and drift-evidence digest recomputation. Rows written before
binding existed **fail closed** (`row_predates_binding_fields`) rather than
verifying silently. Adversarial coverage lives in
`tests/test_receipt_replay.py`; `run_demo.py smoke` re-proves the full
mutation matrix against the live stack on every run.

## Reset & freshness

- `python run_demo.py reset` — repopulates the baseline. The audit chain is
  append-only by design; reset does not rewrite history.
- `docker compose down -v && docker compose up -d --build` — factory-fresh
  database (new volume), then the seeder re-creates the baseline.
- `python run_demo.py smoke` before a presentation: exit code 0 means
  services up, seed present, both scenarios pass end to end, receipts
  verify, the replay matrix rejects all five mutations, and the control tool
  (`list_documents`, never changed) is still allowed.

## Honest limits

- Only the two drift classes above are demonstrated; nothing else is claimed.
- Claim 4 covers calls **through the gateway**. Traffic that bypasses
  Interlock is invisible and is stated as such in the UI and API responses.
- "Executed" means the gateway forwarded the call upstream (and scanned the
  response); upstream side effects are not independently re-verified in this
  demo.
- The `lf-demo-offline-key` API key is seeded only when
  `INTERLOCK_OFFLINE_DEMO=true` (set by this compose file) and must never be
  enabled on hosted deployments.
- The mock's phase flip (`/__demo__/phase`) is demo plumbing that simulates a
  vendor changing their server; everything downstream of discovery/probing is
  the real engine, the real audit chain, and real verification math.
