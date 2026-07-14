#!/usr/bin/env python3
"""
demo/offline/run_demo.py — self-serve driver for the offline Interlock demo.

Runs against the bundled docker-compose stack (gateway + mock MCP server +
dashboard). Stdlib only: no pip installs. Every step goes through the public
gateway API — the same surface a real deployment uses.

Subcommands:

  seed        Register + verify + baseline the two demo MCP servers.
              (The compose seeder service runs this automatically on `up`.)
  scenario-a  DEFAULT PATH — capability drift:
              approved read-only tool changes under the same name ->
              quarantine BEFORE execution -> receipt -> verify -> replay fails.
  scenario-b  ADVANCED PATH — behavioral / effective-permission drift:
              same tool, same schema, previously-denied call (403) becomes
              allowed (200) -> quarantine -> receipt -> verify.
  smoke       Prove demo readiness end-to-end on throwaway servers:
              services up, seed present, both scenarios, receipt verification,
              full replay-mutation matrix, claim-4 query, control stays clean.
  reset       Remove demo/smoke servers, reset mock phases, re-seed.
  status      Show registered servers, review queue, and recent audit rows.

Examples (from demo/offline/):
  docker compose run --rm demo-runner scenario-a     # no host Python needed
  docker compose run --rm demo-runner smoke
  python3 run_demo.py scenario-a                      # optional host variant
"""

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request

DEFAULT_GATEWAY = os.getenv("INTERLOCK_DEMO_GATEWAY", "http://localhost:8001")
# How THIS script reaches the mock's out-of-band controls (phase flips):
DEFAULT_MOCK_ADMIN = os.getenv("INTERLOCK_DEMO_MOCK_ADMIN", "http://localhost:9100")
# How the GATEWAY reaches the mock (compose-internal hostname):
DEFAULT_MOCK_INTERNAL = os.getenv(
    "INTERLOCK_DEMO_MOCK_INTERNAL", "http://mcp-mock:9100"
)
DEFAULT_API_KEY = os.getenv("INTERLOCK_DEMO_KEY", "lf-demo-offline-key")
DEFAULT_DASHBOARD = os.getenv("INTERLOCK_DEMO_DASHBOARD", "http://localhost:8080")

DOCS_SERVER = "demo-docs"
CRM_SERVER = "demo-crm"


# ── HTTP helper (stdlib only) ─────────────────────────────────────────────────
def call(method, base_url, path, api_key=None, body=None, timeout=30):
    url = base_url.rstrip("/") + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if api_key:
        req.add_header("x-api-key", api_key)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode()
            try:
                return resp.getcode(), json.loads(raw or "{}")
            except json.JSONDecodeError:
                return resp.getcode(), {"raw": raw[:200]}
    except urllib.error.HTTPError as e:
        try:
            payload = json.loads(e.read().decode())
        except Exception:
            payload = {"detail": "<non-JSON error body>"}
        return e.code, payload
    except urllib.error.URLError as e:
        return None, {"error": f"connection failed: {e.reason}"}


def banner(text):
    print("\n" + "=" * 70)
    print(f"  {text}")
    print("=" * 70)


def step(text):
    print(f"\n--- {text}")


def show(label, payload, keys=None):
    print(f"    {label}")
    if payload is None:
        return
    if keys:
        payload = {k: payload.get(k) for k in keys if k in payload}
    for line in json.dumps(payload, indent=2).splitlines():
        print(f"      {line}")


def die(msg):
    print(f"\nFAILED: {msg}", file=sys.stderr)
    sys.exit(1)


def context_from_binding(binding):
    """Rebuild the verification context from a receipt's binding block."""
    target = str(binding.get("target") or "/")
    server_id, _, tool_name = target.partition("/")
    return {
        "server_id": server_id,
        "tool_name": tool_name,
        "argument_hash": binding.get("argument_hash") or "",
        "call_id": binding.get("call_id") or "",
        "surface_hash": binding.get("surface_hash") or "",
    }


class Demo:
    def __init__(self, args):
        self.gateway = args.gateway
        self.mock_admin = args.mock_admin
        self.mock_internal = args.mock_internal
        self.key = args.api_key
        self.dashboard = args.dashboard

    # ── gateway/mock primitives ───────────────────────────────────────────────
    def gw(self, method, path, body=None):
        return call(method, self.gateway, path, api_key=self.key, body=body)

    def set_phase(self, path, phase):
        status, payload = call(
            "POST",
            self.mock_admin,
            "/__demo__/phase",
            body={"path": path, "phase": phase},
        )
        if status != 200:
            die(f"could not set mock phase for {path}: {payload}")
        return payload

    def register_and_verify(self, server_id, mock_path, allowed_tools, probes=False):
        """
        Register + verify a demo server.

        probes=True stores the server as non-production and probe-enabled.
        Probe authorization is decided by that STORED registry state, not by
        any request flag, so scenario B's effective-permission probe needs it.
        Everything here targets the bundled local mock server.
        """
        status, payload = self.gw(
            "POST",
            "/mcp/servers",
            {
                "server_id": server_id,
                "url": f"{self.mock_internal}{mock_path}",
                "description": f"Offline demo server ({mock_path})",
                "allowed_tools": allowed_tools,
                "blocked_tools": [],
                "environment": "non_production" if probes else "production",
                "probes_enabled": probes,
            },
        )
        if (
            status not in (200, 201)
            and (payload or {}).get("error") != "already_exists"
        ):
            die(f"register {server_id} failed [{status}]: {payload}")
        if (payload or {}).get("error") == "already_exists" and probes:
            # Row survives from an earlier run: re-assert the stored
            # probe-authorization state through the admin path.
            status, payload = self.gw(
                "POST",
                f"/mcp/servers/{server_id}/environment",
                {"environment": "non_production", "probes_enabled": True},
            )
            if status != 200:
                die(f"probe-enable {server_id} failed [{status}]: {payload}")
        status, payload = self.gw("POST", f"/mcp/servers/{server_id}/verify")
        if status != 200:
            die(f"verify {server_id} failed [{status}]: {payload}")

    def discover(self, server_id, mock_path):
        status, payload = self.gw(
            "POST",
            "/mcp/discover",
            {"server_url": f"{self.mock_internal}{mock_path}", "server_id": server_id},
        )
        if status != 200 or not (payload or {}).get("ok"):
            die(f"discover {server_id} failed [{status}]: {payload}")
        return payload

    def approve(self, server_id, tool_name, reason):
        status, payload = self.gw(
            "POST",
            f"/mcp/tools/{server_id}/{tool_name}/approve",
            {"reviewer": "demo-operator", "reason": reason},
        )
        if status != 200:
            die(f"approve {server_id}/{tool_name} failed [{status}]: {payload}")
        return payload

    def restore_baseline(self, server_id, mock_path, tools):
        """
        Bring a scenario server back to its approved phase-1 baseline so the
        narrated demo can be re-run without wiping the stack. Approval here is
        the same operator action a real review would use.
        """
        self.set_phase(mock_path, 1)
        self.discover(server_id, mock_path)
        for tool in tools:
            self.approve(server_id, tool, "Restore demo baseline (phase 1).")

    def latest_audit_row(self, server_id, tool_name, matched_rule):
        status, payload = self.gw("GET", "/mcp/audit?limit=100")
        if status != 200:
            die(f"audit list failed [{status}]: {payload}")
        for event in payload.get("events") or []:  # newest first
            if (
                event.get("server_id") == server_id
                and event.get("tool_name") == tool_name
                and event.get("matched_rule") == matched_rule
            ):
                return event
        return None

    def receipt(self, audit_id):
        status, payload = self.gw("GET", f"/audit/receipt/{audit_id}")
        if status != 200:
            die(f"receipt {audit_id} failed [{status}]: {payload}")
        return payload

    def claims(self, audit_id):
        status, payload = self.gw("GET", f"/audit/receipt/{audit_id}/claims")
        if status != 200:
            die(f"claims {audit_id} failed [{status}]: {payload}")
        return payload

    def verify_receipt(self, receipt, context):
        status, payload = self.gw(
            "POST",
            "/audit/receipt/verify",
            {"context": context, "receipt": receipt},
        )
        if status != 200:
            die(f"receipt verify failed [{status}]: {payload}")
        return payload

    # ── seed ─────────────────────────────────────────────────────────────────
    def seed(self):
        banner("SEED — approve the offline demo baseline")
        self.wait_for_services()

        step("Reset mock scenario phases to 1 (clean baseline)")
        self.set_phase("/docs", 1)
        self.set_phase("/crm", 1)

        step(f"Register + verify '{DOCS_SERVER}' (capability-drift scenario)")
        self.register_and_verify(
            DOCS_SERVER, "/docs", ["read_document", "list_documents"]
        )

        step(f"Register + verify '{CRM_SERVER}' (behavioral-drift scenario)")
        # Probe-enabled: scenario B runs an effective-permission probe, which
        # requires stored non-production + probes_enabled registry state.
        self.register_and_verify(CRM_SERVER, "/crm", ["update_record"], probes=True)

        step("Discover clean baselines")
        docs = self.discover(DOCS_SERVER, "/docs")
        crm = self.discover(CRM_SERVER, "/crm")
        print(
            f"    {DOCS_SERVER}: {docs['total_tools']} tools "
            f"({docs['blocked_tools']} blocked)"
        )
        print(
            f"    {CRM_SERVER}: {crm['total_tools']} tools "
            f"({crm['blocked_tools']} blocked)"
        )

        step("Operator approves the discovered baselines")
        for tool in ("read_document", "list_documents"):
            self.approve(DOCS_SERVER, tool, "Initial review: read-only surface.")
        self.approve(CRM_SERVER, "update_record", "Initial review: scoped CRM write.")

        banner("SEED COMPLETE")
        print(f"  Dashboard : {self.dashboard}/dashboard")
        print(f"  API URL   : {self.gateway}")
        print(f"  API key   : {self.key}")
        print("  Next      : docker compose run --rm demo-runner scenario-a")

    def wait_for_services(self, attempts=30):
        step("Wait for gateway + mock health")
        for name, base, path in (
            ("gateway", self.gateway, "/health"),
            ("mock", self.mock_admin, "/health"),
        ):
            for i in range(attempts):
                status, _ = call("GET", base, path, timeout=5)
                if status == 200:
                    print(f"    {name}: up")
                    break
                time.sleep(2)
            else:
                die(f"{name} not reachable at {base}{path}")

    # ── scenario A: capability drift (default path) ──────────────────────────
    def scenario_a(self, server_id=DOCS_SERVER, mock_path="/docs", cleanup=False):
        banner("SCENARIO A — capability drift (default demo path)")
        print("  An approved read-only tool changes under the same name into an")
        print("  external-export/PII tool. Interlock quarantines it BEFORE any")
        print("  call executes, and issues a verifiable Security Receipt.")

        if server_id != DOCS_SERVER:
            self.register_and_verify(
                server_id, mock_path, ["read_document", "list_documents"]
            )
        self.restore_baseline(server_id, mock_path, ["read_document", "list_documents"])

        step("1/8 Approved baseline (what the team signed off on)")
        status, tools = self.gw("GET", f"/mcp/tools?server_id={server_id}")
        for tool in tools.get("tools") or []:
            if tool.get("tool_name") == "read_document":
                print(
                    f"    read_document status={tool.get('status')} "
                    f"side_effect={ (tool.get('normalized_metadata') or {}).get('side_effect') }"
                )

        step("2/8 The vendor's server changes the tool (same name, new surface)")
        self.set_phase(mock_path, 2)
        print(
            f"    mock {mock_path} flipped to phase 2 (adds external email export + PII)"
        )

        step("3/8 Interlock re-discovers and classifies the drift")
        discovery = self.discover(server_id, mock_path)
        print(
            f"    total={discovery['total_tools']} safe={discovery['safe_tools']} "
            f"blocked={discovery['blocked_tools']}"
        )
        if not discovery.get("blocked"):
            die("expected read_document to be blocked by capability drift")
        print(f"    blocked reason: {discovery['blocked'][0].get('reason', '')[:120]}")

        step("4/8 Agent attempts the drifted tool -> denied BEFORE execution")
        status, outcome = self.gw(
            "POST",
            "/mcp/call",
            {
                "server_id": server_id,
                "tool_name": "read_document",
                "arguments": {"doc_id": "q3-report", "email": "attacker@example.com"},
            },
        )
        if (outcome or {}).get("error") != "tool_quarantined":
            die(f"expected tool_quarantined, got: {outcome}")
        print(f"    error=tool_quarantined  audit={outcome.get('audit')}")

        step("5/8 Drift-detection Security Receipt")
        detection = self.latest_audit_row(server_id, "read_document", "drift_detected")
        if not detection:
            die("no drift_detected audit row found")
        receipt = self.receipt(detection["id"])
        show(
            "receipt:",
            receipt,
            keys=["receipt_id", "decision", "reason", "integrity_hash", "binding"],
        )

        step("6/8 Verify the receipt against its own context -> PASS expected")
        context = context_from_binding(receipt["binding"])
        verdict = self.verify_receipt(receipt, context)
        print(f"    verified={verdict['verified']} checks={verdict['checks']}")
        if not verdict["verified"]:
            die(f"receipt should verify against its own context: {verdict}")

        step("7/8 Replay the receipt against a DIFFERENT context -> FAIL expected")
        replayed = dict(context, argument_hash="sha256:" + "0" * 64)
        verdict = self.verify_receipt(receipt, replayed)
        if verdict["verified"]:
            die("replayed receipt must not verify")
        print(
            f"    verified={verdict['verified']} "
            f"mismatch={[m['field'] for m in verdict['mismatches']]}"
        )

        step("8/8 Four-claim evidence view (claim 4 is a live audit query)")
        claims = self.claims(detection["id"])
        c4 = claims["claim_4_execution_after_detection"]
        print(
            f"    1. approved  : {claims['claim_1_approved']['approved_surface_hash'][:39]}…"
        )
        print(
            f"    2. observed  : {claims['claim_2_observed']['observed_surface_hash'][:39]}…"
        )
        print(f"       changes   : {claims['claim_2_observed']['changes'][:2]}")
        print(
            f"    3. decision  : {claims['claim_3_decision']['decision']} ({claims['claim_3_decision']['rule_fired']})"
        )
        print(
            f"    4. executed after detection: {c4['boundary_crossing_executed']} "
            f"(executed={c4['executed_count']}, blocked={c4['blocked_attempts']})"
        )
        if c4["boundary_crossing_executed"]:
            die("claim 4 should show no boundary-crossing execution after detection")

        step("CONTROL — the unchanged tool keeps working")
        status, control = self.gw(
            "POST",
            "/mcp/call",
            {
                "server_id": server_id,
                "tool_name": "list_documents",
                "arguments": {},
            },
        )
        if not (control or {}).get("ok"):
            die(f"control tool should still be allowed: {control}")
        print(f"    list_documents ok={control['ok']} (allowed + forwarded + scanned)")

        if cleanup:
            self.gw("DELETE", f"/mcp/servers/{server_id}")
            self.set_phase(mock_path, 1)

        banner("SCENARIO A COMPLETE")
        print("  approve -> drift -> quarantine BEFORE execution -> receipt ->")
        print("  verified; replayed receipt against changed context: REJECTED.")
        return detection["id"]

    # ── scenario B: behavioral drift (advanced path) ─────────────────────────
    def scenario_b(self, server_id=CRM_SERVER, mock_path="/crm", cleanup=False):
        banner("SCENARIO B — behavioral / effective-permission drift (advanced)")
        print("  Same tool, same schema. A call that was denied upstream (403)")
        print("  later becomes allowed (200). Interlock's probe catches the")
        print("  effective-permission expansion and quarantines the tool.")

        if server_id != CRM_SERVER:
            self.register_and_verify(
                server_id, mock_path, ["update_record"], probes=True
            )
        self.restore_baseline(server_id, mock_path, ["update_record"])

        probe_body = {
            "tool_name": "update_record",
            "arguments": {"record_id": "cust-042", "fields": {"tier": "vip"}},
            "expected_outcome": "denied",
            "expected_status_code": 403,
            "non_production": True,
            "safety_note": "Offline demo probe against the bundled mock server.",
        }

        step("1/7 Baseline probe: expectation 'denied' vs live behavior")
        status, probe = self.gw(
            "POST", f"/mcp/servers/{server_id}/probes/run", probe_body
        )
        if status != 200 or not (probe or {}).get("ok"):
            die(f"baseline probe failed [{status}]: {probe}")
        ev = probe["evaluation"]
        print(
            f"    expected=denied observed={ev['observed_outcome']} "
            f"(status={ev['observed_status_code']}) drift={ev['drift_detected']}"
        )
        if ev["drift_detected"]:
            die("baseline probe should match the approved expectation")

        step("2/7 Upstream authorization silently loosens (403 -> 200)")
        self.set_phase(mock_path, 2)
        print(f"    mock {mock_path} flipped to phase 2 — schema is untouched")

        step("3/7 Schema check: tools/list is UNCHANGED")
        discovery = self.discover(server_id, mock_path)
        if discovery["blocked_tools"] != 0:
            die("behavioral scenario must not produce surface drift")
        print(
            f"    total={discovery['total_tools']} blocked={discovery['blocked_tools']} "
            "(no surface drift — this is the point)"
        )

        step("4/7 Same probe again -> behavioral drift detected")
        status, probe = self.gw(
            "POST", f"/mcp/servers/{server_id}/probes/run", probe_body
        )
        ev = probe["evaluation"]
        print(
            f"    expected=denied observed={ev['observed_outcome']} "
            f"(status={ev['observed_status_code']})"
        )
        print(f"    decision={ev['decision']} finding={ev['finding_type']}")
        if ev["decision"] != "quarantine" or not probe.get("quarantine_applied"):
            die(f"expected quarantine on behavioral drift: {probe}")

        audit_id = probe["evidence"]["audit_id"]

        step("5/7 Receipt + verification for the probe evidence")
        receipt = self.receipt(audit_id)
        context = context_from_binding(receipt["binding"])
        verdict = self.verify_receipt(receipt, context)
        print(f"    verified={verdict['verified']} checks={verdict['checks']}")
        if not verdict["verified"]:
            die(f"probe receipt should verify: {verdict}")

        replayed = dict(context, call_id="replayed-from-another-call")
        verdict = self.verify_receipt(receipt, replayed)
        if verdict["verified"]:
            die("replayed probe receipt must not verify")
        print(f"    replay with different call_id -> verified={verdict['verified']}")

        step("6/7 Four-claim view: unchanged schema, changed behavior")
        claims = self.claims(audit_id)
        c1, c2 = claims["claim_1_approved"], claims["claim_2_observed"]
        c4 = claims["claim_4_execution_after_detection"]
        print(
            f"    1. approved  : expected {c1['expected_outcome']}/{c1['expected_status_code']}"
        )
        print(
            f"    2. observed  : {c2['observed_outcome']}/{c2['observed_status_code']} — schema_unchanged={c2['schema_unchanged']}"
        )
        print(f"    3. decision  : {claims['claim_3_decision']['decision']}")
        print(
            f"    4. executed after detection: {c4['boundary_crossing_executed']} "
            f"(blocked={c4['blocked_attempts']})"
        )
        if c2["schema_unchanged"] is not True:
            die("behavioral claims must prove the schema surface was unchanged")

        step("7/7 Agent attempts update_record -> blocked by quarantine")
        status, outcome = self.gw(
            "POST",
            "/mcp/call",
            {
                "server_id": server_id,
                "tool_name": "update_record",
                "arguments": {"record_id": "cust-042", "fields": {"tier": "vip"}},
            },
        )
        if (outcome or {}).get("error") != "tool_quarantined":
            die(f"expected tool_quarantined after behavioral drift, got: {outcome}")
        print(f"    error=tool_quarantined  audit={outcome.get('audit')}")

        if cleanup:
            self.gw("DELETE", f"/mcp/servers/{server_id}")
            self.set_phase(mock_path, 1)

        banner("SCENARIO B COMPLETE")
        print("  approved baseline -> unchanged schema -> observed 403->200 ->")
        print("  quarantine -> verifiable receipt bound to the exact probe call.")
        return audit_id

    # ── smoke ─────────────────────────────────────────────────────────────────
    def smoke(self):
        banner("SMOKE — prove the demo is ready")
        failures = []
        run_id = int(time.time())

        def check(name, fn):
            try:
                fn()
                print(f"  PASS  {name}")
            except SystemExit:
                raise
            except Exception as exc:
                failures.append((name, str(exc)))
                print(f"  FAIL  {name}: {exc}")

        # 1. services up
        self.wait_for_services()
        status, _ = call("GET", self.dashboard, "/", timeout=5)
        if status == 200:
            print("    dashboard: up")
        else:
            print(f"    dashboard: not reachable at {self.dashboard} (non-fatal)")

        # 2. seed data present
        def seed_present():
            status, payload = self.gw("GET", "/mcp/servers")
            assert status == 200, f"servers list failed: {payload}"
            servers = {s["server_id"]: s for s in (payload.get("servers") or [])}
            for sid in (DOCS_SERVER, CRM_SERVER):
                assert sid in servers, f"seed server {sid} missing — run seed"
                assert servers[sid].get("verified"), f"{sid} not verified"

        check("seed data present (demo-docs, demo-crm verified)", seed_present)

        # 3. registration allowlist remains fail-closed for other hosts
        rejected_id = f"smoke-unallowlisted-{run_id}"

        def registration_guard_intact():
            try:
                status, payload = self.gw(
                    "POST",
                    "/mcp/servers",
                    {
                        "server_id": rejected_id,
                        "url": "https://not-allowlisted.invalid/mcp",
                        "description": "Offline smoke rejection probe",
                        "allowed_tools": [],
                        "blocked_tools": [],
                    },
                )
                detail = str((payload or {}).get("detail") or "")
                assert status == 400, f"expected HTTP 400, got {status}: {payload}"
                assert (
                    "External MCP server registration is restricted to the explicit "
                    "allowlist" in detail
                ), f"unexpected rejection detail: {payload}"
                assert "Host 'not-allowlisted.invalid' is not allowed" in detail

                list_status, servers_payload = self.gw("GET", "/mcp/servers")
                assert list_status == 200, f"servers list failed: {servers_payload}"
                server_ids = {
                    server.get("server_id")
                    for server in (servers_payload or {}).get("servers") or []
                }
                assert rejected_id not in server_ids, "rejected server was persisted"
            finally:
                self.gw("DELETE", f"/mcp/servers/{rejected_id}")

        check(
            "registration allowlist rejects arbitrary external host with HTTP 400",
            registration_guard_intact,
        )

        # 4. scenario A end-to-end on a throwaway server
        docs_id = f"smoke-docs-{run_id}"
        docs_path = f"/docs/smoke-{run_id}"

        def scenario_a_smoke():
            detection_id = self.scenario_a(
                server_id=docs_id, mock_path=docs_path, cleanup=False
            )
            # full replay-mutation matrix against the detection receipt
            receipt = self.receipt(detection_id)
            context = context_from_binding(receipt["binding"])
            good = self.verify_receipt(receipt, context)
            assert good["verified"], f"receipt must verify: {good}"
            mutations = {
                "server_id": "attacker-server",
                "tool_name": "attacker_tool",
                "argument_hash": "sha256:" + "f" * 64,
                "call_id": "hijacked-call-id",
                "surface_hash": "sha256:" + "9" * 64,
            }
            for field, bad_value in mutations.items():
                tampered = dict(context, **{field: bad_value})
                verdict = self.verify_receipt(receipt, tampered)
                assert not verdict["verified"], f"mutating {field} must fail"
                assert any(
                    m["field"] == field for m in verdict["mismatches"]
                ), f"mismatch must name {field}"

        check("scenario A end-to-end + replay mutation matrix", scenario_a_smoke)

        # 5. control tool stays clean
        def control_clean():
            status, payload = self.gw("GET", f"/mcp/tools?server_id={docs_id}")
            control = next(
                (
                    t
                    for t in payload.get("tools") or []
                    if t.get("tool_name") == "list_documents"
                ),
                None,
            )
            assert control is not None, "control tool missing"
            assert control.get("status") in (
                "active",
                "allowed",
            ), f"control must stay clean, got {control.get('status')}"

        check("control tool unaffected by drift", control_clean)

        # 6. scenario B end-to-end on a throwaway server
        crm_id = f"smoke-crm-{run_id}"
        crm_path = f"/crm/smoke-{run_id}"
        check(
            "scenario B end-to-end (403 -> 200 behavioral drift)",
            lambda: self.scenario_b(
                server_id=crm_id, mock_path=crm_path, cleanup=False
            ),
        )

        # cleanup throwaway servers + phases
        for sid in (docs_id, crm_id):
            self.gw("DELETE", f"/mcp/servers/{sid}")
        self.set_phase(docs_path, 1)
        self.set_phase(crm_path, 1)

        banner("SMOKE RESULT")
        if failures:
            for name, err in failures:
                print(f"  FAIL  {name}\n        {err}")
            die(f"{len(failures)} smoke check(s) failed")
        print("  ALL CHECKS PASSED — demo is ready.")
        print(f"  Dashboard: {self.dashboard}/dashboard  (API key: {self.key})")

    # ── reset / status ────────────────────────────────────────────────────────
    def reset(self):
        banner("RESET — repopulate the demo baseline")
        status, payload = self.gw("GET", "/mcp/servers")
        for server in (payload or {}).get("servers") or []:
            sid = server.get("server_id") or ""
            if sid in (DOCS_SERVER, CRM_SERVER) or sid.startswith("smoke-"):
                self.gw("DELETE", f"/mcp/servers/{sid}")
                print(f"    removed {sid}")
        self.set_phase("/docs", 1)
        self.set_phase("/crm", 1)
        print("    mock phases reset to 1")
        print(
            "    note: audit history is append-only by design (hash chain);"
            "\n    for a factory-fresh database run: docker compose down -v"
            "\n    then: docker compose up -d --build"
        )
        self.seed()

    def status(self):
        banner("STATUS")
        status, servers = self.gw("GET", "/mcp/servers")
        for server in (servers or {}).get("servers") or []:
            print(
                f"  server {server.get('server_id')}: verified={server.get('verified')} "
                f"url={server.get('url')}"
            )
        status, drifted = self.gw("GET", "/mcp/tools/drifted")
        for tool in (drifted or {}).get("tools") or []:
            print(
                f"  drifted {tool.get('server_id')}/{tool.get('tool_name')}: "
                f"status={tool.get('status')} severity={tool.get('drift_severity')}"
            )
        status, audit = self.gw("GET", "/mcp/audit?limit=5")
        for event in (audit or {}).get("events") or []:
            print(
                f"  audit #{event.get('id')} {event.get('ts', '')[:19]} "
                f"{event.get('server_id')}/{event.get('tool_name')} "
                f"action={event.get('action')} rule={event.get('matched_rule')}"
            )
        status, phases = call("GET", self.mock_admin, "/__demo__/phase")
        print(f"  mock phases: {(phases or {}).get('phases')}")


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument(
        "command",
        choices=["seed", "scenario-a", "scenario-b", "smoke", "reset", "status"],
    )
    ap.add_argument("--gateway", default=DEFAULT_GATEWAY)
    ap.add_argument("--mock-admin", default=DEFAULT_MOCK_ADMIN)
    ap.add_argument("--mock-internal", default=DEFAULT_MOCK_INTERNAL)
    ap.add_argument("--api-key", default=DEFAULT_API_KEY)
    ap.add_argument("--dashboard", default=DEFAULT_DASHBOARD)
    args = ap.parse_args()

    demo = Demo(args)
    if args.command == "seed":
        demo.seed()
    elif args.command == "scenario-a":
        demo.scenario_a()
    elif args.command == "scenario-b":
        demo.scenario_b()
    elif args.command == "smoke":
        demo.smoke()
    elif args.command == "reset":
        demo.reset()
    elif args.command == "status":
        demo.status()
    return 0


if __name__ == "__main__":
    sys.exit(main())
