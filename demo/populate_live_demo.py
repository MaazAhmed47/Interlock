#!/usr/bin/env python3
"""
demo/populate_live_demo.py

Populate live demo data on the Interlock Render backend THROUGH THE PUBLIC API.
No DB access, no shell on Render, no extra Python dependencies (stdlib only).

It runs three parts, in order:

  Part 1 - Register a demo MCP server
           Appears in the dashboard under MCP Gateway -> Registered Servers.

  Part 2 - Generate MCP tool-call audit rows with working Receipt buttons
           Calls the pre-seeded, *verified* `trusted-filesystem` server with
           denied/blocked tool calls. Each call writes an mcp_audit_log row that
           shows up in Audit Log -> Runtime Decisions with a Receipt button.

  Part 3 - Trigger a REAL schema-drift quarantine (needs --mock-url)
           Discovers a clean tool, then re-discovers a mutated version of the
           same tool. Interlock classifies the change CRITICAL and quarantines
           it (MCP Gateway -> Review Queue). A final operator-quarantine call
           writes the drift-bearing audit row that backs the drift Receipt.

Usage:
  # Full demo (Parts 1-3). Get the mock URL from demo/valtown-mcp-mock.js first.
  python demo/populate_live_demo.py --mock-url https://<you>-mcpmock.web.val.run

  # Parts 1-2 only (no drift) - no mock needed:
  python demo/populate_live_demo.py

  # Preview the exact API calls without sending anything:
  python demo/populate_live_demo.py --mock-url https://... --dry-run
"""

import argparse
import json
import sys
import urllib.error
import urllib.request

DEFAULT_BASE_URL = "https://interlock.onrender.com"
DEFAULT_API_KEY = "lf-dev-key-456"
TRUSTED_SERVER = "trusted-filesystem"  # pre-seeded + verified on the backend
DEMO_TOOL = "read_document"


# ── HTTP helper (stdlib only) ──────────────────────────────────────────────────
def call(method, base_url, path, api_key, body=None, dry=False):
    url = base_url.rstrip("/") + path
    if dry:
        print(f"    [dry-run] {method} {url}")
        if body is not None:
            print(f"              body={json.dumps(body)}")
        return "DRY", None

    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("x-api-key", api_key)
    if data is not None:
        req.add_header("Content-Type", "application/json")

    try:
        with urllib.request.urlopen(req, timeout=45) as resp:
            return resp.getcode(), json.loads(resp.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        try:
            payload = json.loads(e.read().decode())
        except Exception:
            payload = {"detail": "<non-JSON error body>"}
        return e.code, payload
    except urllib.error.URLError as e:
        return None, {"error": f"connection failed: {e.reason}"}


def show(label, status, payload):
    code = status if status is not None else "ERR"
    print(f"    -> [{code}] {label}")
    if payload is not None:
        snippet = json.dumps(payload, indent=2)
        for line in snippet.splitlines():
            print(f"       {line}")


def banner(text):
    print("\n" + "=" * 64)
    print(f"  {text}")
    print("=" * 64)


def with_v(url, v):
    sep = "&" if "?" in url else "?"
    return f"{url}{sep}v={v}"


# ── Part 1 ──────────────────────────────────────────────────────────────────
def part1_register(base, key, server_id, dry):
    banner(f"PART 1 - Register MCP server '{server_id}'")
    status, payload = call(
        "POST",
        base,
        "/mcp/servers",
        key,
        body={
            "server_id": server_id,
            "url": "https://example.com/mcp",
            "description": "Demo internal document server",
            "allowed_tools": [DEMO_TOOL],
            "blocked_tools": ["delete_document"],
        },
        dry=dry,
    )
    show("register server (ok, or already_exists on re-run - both fine)", status, payload)
    print("\n  VERIFY: dashboard -> MCP Gateway -> Registered Servers now lists "
          f"'{server_id}'.\n  Its allowed/blocked tools show in 'All Tools' as ALLOWED/BLOCKED.")


# ── Part 2 ──────────────────────────────────────────────────────────────────
def part2_audit(base, key, dry):
    banner("PART 2 - MCP tool-call audit rows (Receipt buttons)")
    print(f"  Calling the pre-seeded, verified '{TRUSTED_SERVER}' server.\n"
          "  Each call writes an audit row you can open as a Security Receipt.\n")

    calls = [
        (
            "blocked tool -> deny 'tool_blocked'",
            {"server_id": TRUSTED_SERVER, "tool_name": "delete_file",
             "arguments": {"path": "/etc/passwd"}, "role": "readonly_agent"},
        ),
        (
            "tool not in allow-list -> deny 'tool_not_allowed'",
            {"server_id": TRUSTED_SERVER, "tool_name": "exfiltrate_secrets",
             "arguments": {}, "role": "support_agent"},
        ),
        (
            "allowed tool + malicious arg -> Tool Inspector blocks (path traversal)",
            {"server_id": TRUSTED_SERVER, "tool_name": "read_file",
             "arguments": {"path": "../../../../etc/shadow"}, "role": "readonly_agent"},
        ),
        (
            "allowed tool + clean arg -> ALLOW (then upstream unreachable, still audited)",
            {"server_id": TRUSTED_SERVER, "tool_name": "read_file",
             "arguments": {"path": "quarterly-report.txt"}, "role": "readonly_agent"},
        ),
    ]
    for label, body in calls:
        status, payload = call("POST", base, "/mcp/call", key, body=body, dry=dry)
        show(label, status, payload)

    print("\n  VERIFY: dashboard -> Audit Log -> Runtime Decisions.\n"
          "  New rows appear; each has a 'Receipt' button. 'Export Receipts' is now enabled.")


# ── Part 3 ──────────────────────────────────────────────────────────────────
def part3_drift(base, key, server_id, mock_url, dry):
    banner("PART 3 - Real schema drift -> QUARANTINE -> drift Receipt")
    if not mock_url:
        print("  SKIPPED: no --mock-url provided.\n"
              "  Drift requires a reachable tools/list endpoint (see "
              "demo/valtown-mcp-mock.js).\n  Re-run with: --mock-url https://<you>-mcpmock.web.val.run")
        return

    print("  Step 1/4 - discover the CLEAN baseline (?v=1)")
    status, payload = call(
        "POST", base, "/mcp/discover", key,
        body={"server_url": with_v(mock_url, 1), "server_id": server_id}, dry=dry,
    )
    show("discover v=1 (expect ok, total_tools=1, blocked_tools=0)", status, payload)

    print("\n  Step 2/4 - discover the MUTATED tool (?v=2) - drift gets classified")
    status, payload = call(
        "POST", base, "/mcp/discover", key,
        body={"server_url": with_v(mock_url, 2), "server_id": server_id}, dry=dry,
    )
    show("discover v=2 (tool persisted; drift evaluated on upsert)", status, payload)

    print("\n  Step 3/4 - confirm it landed in the Review Queue")
    status, payload = call("GET", base, "/mcp/tools/drifted", key, dry=dry)
    show("GET /mcp/tools/drifted (expect read_document, status quarantined)", status, payload)

    print("\n  Step 4/4 - operator-quarantine (writes the drift-bearing audit row)")
    status, payload = call(
        "POST", base,
        f"/mcp/tools/{server_id}/{DEMO_TOOL}/quarantine", key,
        body={
            "reviewer": "operator",
            "reason": ("Critical schema drift: external email export capability and "
                       "PII data class added after baseline approval."),
        },
        dry=dry,
    )
    show("operator quarantine (drift_severity=critical)", status, payload)

    print("\n  VERIFY: dashboard -> MCP Gateway:\n"
          "    - 'Review queue' count is now >= 1\n"
          f"    - Orange/red 'Drifted / Quarantined' card for '{DEMO_TOOL}' on "
          f"'{server_id}' (CRITICAL)\n"
          "    - 'All Tools' shows read_document = QUARANTINED\n"
          "  Audit Log -> open the read_document quarantine row's Receipt -> "
          "drift section is populated\n  (detected=true, severity=critical, decision=quarantine).")


def main():
    ap = argparse.ArgumentParser(description="Populate Interlock demo data via the live API.")
    ap.add_argument("--base-url", default=DEFAULT_BASE_URL, help=f"default: {DEFAULT_BASE_URL}")
    ap.add_argument("--api-key", default=DEFAULT_API_KEY, help=f"default: {DEFAULT_API_KEY}")
    ap.add_argument("--mock-url", default=None,
                    help="Public Val Town tools/list mock URL (required for Part 3).")
    ap.add_argument("--server-id", default="demo-docs",
                    help="Demo server id (use a fresh value for a pristine run). default: demo-docs")
    ap.add_argument("--dry-run", action="store_true", help="Print calls without sending them.")
    args = ap.parse_args()

    print(f"Target backend : {args.base_url}")
    print(f"API key        : {args.api_key}")
    print(f"Demo server id : {args.server_id}")
    print(f"Mock URL       : {args.mock_url or '(none - Part 3 will be skipped)'}")
    if args.dry_run:
        print("Mode           : DRY RUN (no requests sent)")

    part1_register(args.base_url, args.api_key, args.server_id, args.dry_run)
    part2_audit(args.base_url, args.api_key, args.dry_run)
    part3_drift(args.base_url, args.api_key, args.server_id, args.mock_url, args.dry_run)

    banner("DONE")
    print("  Open the dashboard and Refresh each page. If you connected with an API\n"
          "  key in Settings you'll see live data; clearing the key shows demo mode.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
