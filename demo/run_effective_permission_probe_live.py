#!/usr/bin/env python3
"""
demo/run_effective_permission_probe_live.py

LIVE-style verification of Effective Permission Drift Detection (the Genesys
"opaque upstream scope drift" case): SAME tool, SAME schema, SAME args, but a
call that previously returned 403 now returns 200.

Unlike the unit tests (which patch httpx), this drives the REAL probe path
(proxy.mcp_run_effective_permission_probe -> core.effective_permission ->
real httpx POST) against a REAL local mock MCP upstream over real HTTP, on a
throwaway temp DB. No real Genesys tenant, no prod creds, no destructive call.

Run:  python demo/run_effective_permission_probe_live.py
"""

import os
import sys
import json
import socket
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# --- env BEFORE importing the app (temp DB, force non-prod, allow localhost) ---
_tmp = tempfile.mkdtemp()
DB_PATH = os.path.join(_tmp, "eperm-live.db")
os.environ["FIREWALL_DB_PATH"] = DB_PATH
os.environ["PYTHON_DOTENV_DISABLED"] = "1"
os.environ.pop("DATABASE_URL", None)
os.environ["INTERLOCK_ENV"] = "test"  # force non-production
os.environ["INTERLOCK_ALLOW_PRIVATE_OUTBOUND"] = "true"  # allow the localhost upstream
UPSTREAM_TOKEN = "super-secret-token"  # sent as Bearer; must never be stored
os.environ["TEST_MCP_PROBE_TOKEN"] = UPSTREAM_TOKEN

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import asyncio  # noqa: E402
from core import db  # noqa: E402
from core import receipt as receipt_mod  # noqa: E402
from core import drift_evidence  # noqa: E402
from core.effective_permission import arguments_hash  # noqa: E402
import proxy  # noqa: E402

# Be explicit after imports as well as via FIREWALL_DB_PATH. When this script is
# launched by another proof runner, parent process state can otherwise leave the
# imported DB module pointed at the default development DB.
db.DB_PATH = DB_PATH

BOLD, GREEN, RED, YEL, CYAN, RESET = (
    "\033[1m",
    "\033[92m",
    "\033[91m",
    "\033[93m",
    "\033[96m",
    "\033[0m",
)

SERVER_ID = f"{db.FIXTURE_SERVER_PREFIX}genesys-probe-live"
TOOL = {
    "name": "call_genesys_api",
    "description": "Call a Genesys API endpoint.",
    "inputSchema": {
        "type": "object",
        "properties": {
            "method": {"type": "string"},
            "path": {"type": "string"},
            "body": {"type": "object"},
        },
        "required": ["method", "path"],
    },
}
METADATA = {
    "effects": ["api_call"],
    "side_effect": "unknown",
    "data_classes": ["crm"],
    "externality": "external",
    "identity_mode": "authenticated_user",
    "required_scopes": ["genesys.api"],
    "verification_level": "interlock_meta",
    "confidence": 0.95,
    "warnings": [],
}
# Semantically-fixed args across both runs. Contains secret-looking values that
# MUST NOT be persisted anywhere.
PROBE_ARGS = {
    "method": "POST",
    "path": "/api/v2/conversations/calls/canary/probe",
    "body": {"canary": True, "token_like": "argument-secret-value"},
}
RESP_SECRET = "response-secret-value"  # in the 200 body; must never be stored


# ---- Real local mock MCP upstream: 403 in "deny" mode, 200 in "allow" mode ----
class _Up:
    mode = "deny"  # flip to "allow" between runs


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        n = int(self.headers.get("content-length") or 0)
        if n:
            self.rfile.read(n)  # drain request; we do NOT echo it back
        if _Up.mode == "deny":
            status = 403
            payload = {
                "jsonrpc": "2.0",
                "id": 1,
                "error": {"code": -32001, "message": "Forbidden: insufficient scope"},
            }
        else:
            status = 200
            payload = {
                "jsonrpc": "2.0",
                "id": 1,
                "result": {"id": "call-created", "secret": RESP_SECRET},
            }
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _banner(t, c=BOLD):
    print(f"\n{c}{'=' * 72}\n  {t}\n{'=' * 72}{RESET}")


def _kv(k, v):
    print(f"  {CYAN}{k:<26}{RESET} {v}")


def _schema_hash():
    return (db.lookup_mcp_tool_metadata(SERVER_ID, "call_genesys_api") or {}).get(
        "tool_schema_hash"
    )


def _status():
    t = db.lookup_mcp_tool_metadata(SERVER_ID, "call_genesys_api") or {}
    return t.get("status"), t.get("drift_action"), t.get("drift_types")


def _run_probe(api_key):
    req = proxy.MCPEffectivePermissionProbeRequest(
        probe_id="genesys-canary-probe",
        tool_name="call_genesys_api",
        arguments=PROBE_ARGS,
        expected_outcome="denied",
        expected_status_code=403,
        expected_error_fingerprint="forbidden",
        non_production=True,
        safety_note="Canary-only synthetic tenant; non-destructive probe call.",
    )
    return asyncio.run(
        proxy.mcp_run_effective_permission_probe(
            SERVER_ID, request=req, x_api_key=api_key
        )
    )


def run():
    port = _free_port()
    url = f"http://127.0.0.1:{port}/mcp"
    httpd = ThreadingHTTPServer(("127.0.0.1", port), _Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()

    fails = []
    try:
        db.init_db()
        api_key = db.generate_key("free", label="eperm-live")["raw_key"]
        db.register_mcp_server(
            SERVER_ID,
            {
                "url": url,
                "description": "Genesys-style live probe upstream",
                "allowed_tools": ["call_genesys_api"],
                "blocked_tools": [],
                "rate_limit": 10,
                "auth_type": "bearer",
                "auth_token_env": "TEST_MCP_PROBE_TOKEN",
            },
        )
        db.verify_mcp_server(SERVER_ID)
        db.upsert_mcp_tool_metadata(SERVER_ID, TOOL, METADATA)
        schema_before = _schema_hash()
        arg_hash = arguments_hash(PROBE_ARGS)

        _banner("SETUP — registered Genesys-style server (manifest fixed)", GREEN)
        _kv("server_id", SERVER_ID)
        _kv("upstream_url", url)
        _kv("tool_name", "call_genesys_api")
        _kv("argument_hash", arg_hash)
        _kv("tool_schema_hash (baseline)", schema_before)

        # ---- RUN 1: upstream denies (403). Expected denied. No drift. ----------
        _Up.mode = "deny"
        r1 = _run_probe(api_key)
        e1 = r1["evaluation"]
        row1 = db.list_mcp_audit_logs(limit=1)[0]
        st1 = _status()
        sh1 = _schema_hash()
        _banner("RUN 1 — upstream 403 (expected denied)", CYAN)
        _kv(
            "observed_outcome/status",
            f"{e1['observed_outcome']} / {e1['observed_status_code']}",
        )
        _kv("drift_detected", e1["drift_detected"])
        _kv("severity / decision", f"{e1['severity']} / {e1['decision']}")
        _kv("tool status", st1)
        _kv("audit action / rule", f"{row1['action']} / {row1['matched_rule']}")
        if not (
            e1["observed_outcome"] == "denied"
            and e1["drift_detected"] is False
            and e1["decision"] == "allow"
        ):
            fails.append("RUN1: 403 should be denied with no drift")
        if st1[0] != "active":
            fails.append(f"RUN1: tool status={st1[0]} (want active)")

        # ---- RUN 2: ONLY upstream behavior flips to 200. Same tool/args. -------
        _Up.mode = "allow"
        r2 = _run_probe(api_key)
        e2 = r2["evaluation"]
        row2 = db.list_mcp_audit_logs(limit=1)[0]
        st2 = _status()
        sh2 = _schema_hash()
        _banner("RUN 2 — upstream 200 (same probe) -> behavioral scope drift", RED)
        _kv(
            "observed_outcome/status",
            f"{e2['observed_outcome']} / {e2['observed_status_code']}",
        )
        _kv("drift_detected", e2["drift_detected"])
        _kv("finding_type", e2["finding_type"])
        _kv("finding_types", e2["finding_types"])
        _kv("severity / decision", f"{e2['severity']} / {e2['decision']}")
        _kv("quarantine_applied", r2["quarantine_applied"])
        _kv("tool status", st2)
        if not (
            e2["observed_outcome"] == "allowed"
            and e2["drift_detected"] is True
            and e2["finding_type"] == "effective_permission_expansion"
            and "behavioral_scope_drift" in e2["finding_types"]
            and e2["severity"] == "high"
            and e2["decision"] == "quarantine"
        ):
            fails.append(
                "RUN2: 200 should be high/quarantine effective_permission_expansion"
            )
        if st2[0] != "quarantined" or st2[1] != "quarantine":
            fails.append(f"RUN2: tool not quarantined ({st2})")

        # ---- SAME SCHEMA HASH proves behavioral (not surface) drift -----------
        _banner("SCHEMA STABILITY — behavioral, not surface, diff", YEL)
        _kv("schema hash baseline", schema_before)
        _kv("schema hash after RUN1", sh1)
        _kv("schema hash after RUN2", sh2)
        same = schema_before == sh1 == sh2 and bool(schema_before)
        _kv("identical across all runs", same)
        if not same:
            fails.append(
                "schema/manifest hash changed across runs (should be identical)"
            )

        # ---- EVIDENCE / RECEIPT (built from the RUN 2 audit row) --------------
        receipt = receipt_mod.build_receipt(row2, chain_verified=True)
        ev = receipt.get("drift_evidence") or {}
        rec = ev.get("record") or {}
        ref = ev.get("evidence_ref") or {}
        verified = drift_evidence.verify_effective_permission_record(
            rec, ref.get("digest")
        )
        _banner("EVIDENCE / RECEIPT (RUN 2)", CYAN)
        _kv("receipt_id", receipt.get("receipt_id"))
        _kv("evidence_ref.type", ref.get("type"))
        _kv("diff_classification", rec.get("diff_classification"))
        _kv("finding_type", rec.get("finding_type"))
        _kv("severity / decision", f"{rec.get('severity')} / {rec.get('decision')}")
        _kv("evidence_ref.digest", str(ref.get("digest"))[:40])
        _kv("integrity_hash", str(receipt.get("integrity_hash"))[:40])
        _kv("chain_verified", receipt.get("chain_verified"))
        _kv("record verified", verified.get("verified"))
        if not (
            rec.get("diff_classification") == "auth-scope"
            and rec.get("finding_type") == "effective_permission_expansion"
            and rec.get("severity") == "high"
            and rec.get("decision") == "quarantine"
            and verified.get("verified") is True
        ):
            fails.append(
                "evidence record missing auth-scope / high / quarantine / verified"
            )

        # ---- PRIVACY — nothing sensitive persisted (scan the whole temp DB) ---
        with open(DB_PATH, "rb") as fh:
            db_bytes = fh.read()
        persisted_probe = db.lookup_mcp_permission_probe("genesys-canary-probe") or {}
        surface = json.dumps(
            {
                "probe": persisted_probe,
                "audit1": row1,
                "audit2": row2,
                "run1": r1,
                "run2": r2,
                "receipt": receipt,
            },
            default=str,
        )
        secrets = {
            "raw argument value": "argument-secret-value",
            "upstream bearer token": UPSTREAM_TOKEN,
            "response body secret": RESP_SECRET,
            "Authorization header name": "Authorization",
            "Bearer scheme": "Bearer",
        }
        _banner(
            "PRIVACY — no raw args / tokens / headers / response bodies stored", GREEN
        )
        _kv("raw arguments persisted?", "arguments" in persisted_probe)
        _kv("audit argument_keys", row2.get("argument_keys"))
        for label, needle in secrets.items():
            in_db = needle.encode() in db_bytes
            in_surface = needle in surface
            _kv(label, f"in DB file={in_db}  in API/receipt={in_surface}")
            if in_db or in_surface:
                fails.append(f"PRIVACY LEAK: '{label}' present")
        if "arguments" in persisted_probe:
            fails.append("PRIVACY: raw arguments persisted in probe row")

        # ---- SANITIZED PROOF SUMMARY ------------------------------------------
        _banner("SANITIZED PROOF SUMMARY", BOLD)
        summary = {
            "server_id": SERVER_ID,
            "tool_name": "call_genesys_api",
            "argument_hash": arg_hash,
            "manifest_schema_hash": schema_before,
            "manifest_schema_hash_unchanged": same,
            "run1_expected": "denied",
            "run1_observed": f"{e1['observed_outcome']}/{e1['observed_status_code']}",
            "run1_drift": e1["drift_detected"],
            "run1_decision": e1["decision"],
            "run2_expected": "denied",
            "run2_observed": f"{e2['observed_outcome']}/{e2['observed_status_code']}",
            "run2_finding_type": e2["finding_type"],
            "run2_finding_types": e2["finding_types"],
            "run2_diff_classification": rec.get("diff_classification"),
            "run2_severity": e2["severity"],
            "run2_decision": e2["decision"],
            "receipt_id": receipt.get("receipt_id"),
            "evidence_ref_digest": ref.get("digest"),
            "audit_integrity_hash": receipt.get("integrity_hash"),
            "evidence_record_verified": verified.get("verified"),
        }
        print(json.dumps(summary, indent=2))
    finally:
        httpd.shutdown()

    _banner("RESULT", BOLD)
    if fails:
        print(f"  {RED}{BOLD}FAIL{RESET} — {len(fails)} check(s):")
        for f in fails:
            print(f"    {RED}- {f}{RESET}")
        return 1
    print(
        f"  {GREEN}{BOLD}PASS{RESET} — 403->403 produced NO drift; 403->200 produced "
        f"auth-scope / effective_permission_expansion (high, quarantine) with verified"
    )
    print(
        f"  {GREEN}receipt evidence; manifest/schema hash identical across runs (behavioral,"
    )
    print(
        f"  not surface); no raw args/tokens/headers/response bodies persisted.{RESET}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
