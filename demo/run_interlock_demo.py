#!/usr/bin/env python3
"""Clean buyer-facing Interlock demo command.

Default local run:
  1. Behavioral effective-permission proof: 403->200 -> quarantine -> receipt.
  2. Capability surface proof: approved surface -> drifted surface -> quarantine
     -> receipt with before/after surface hashes.

Optional Render reset:
  --repopulate-render seeds the live backend through public API calls only, using
  the capability mock URL so a redeploy-wiped demo backend has baseline, drift,
  quarantine, and receipt data again.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

DEFAULT_BASE_URL = os.environ.get(
    "INTERLOCK_BASE_URL", "https://interlock.onrender.com"
)
DEFAULT_API_KEY = os.environ.get("INTERLOCK_API_KEY", "")
DEFAULT_SERVER_ID = "clean-proof-docs"
DEMO_TOOL = "read_document"


def _banner(text: str) -> None:
    print("\n" + "=" * 72)
    print(f"  {text}")
    print("=" * 72, flush=True)


def _with_v(url: str, version: int) -> str:
    sep = "&" if "?" in url else "?"
    return f"{url}{sep}v={version}"


def _call_api(
    method: str,
    base_url: str,
    path: str,
    api_key: str,
    body: Optional[Dict[str, Any]] = None,
    *,
    dry_run: bool = False,
) -> Tuple[Optional[int], Any]:
    if dry_run:
        print(f"  [dry-run] {method} {path}")
        if body is not None:
            print(f"            body={json.dumps(body, sort_keys=True)}")
        return 200, {"dry_run": True}

    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(base_url.rstrip("/") + path, data=data, method=method)
    req.add_header("x-api-key", api_key)
    if data is not None:
        req.add_header("content-type", "application/json")

    try:
        with urllib.request.urlopen(req, timeout=45) as resp:
            raw = resp.read().decode("utf-8") or "{}"
            return resp.getcode(), json.loads(raw)
    except urllib.error.HTTPError as exc:
        try:
            payload = json.loads(exc.read().decode("utf-8") or "{}")
        except Exception:
            payload = {"detail": "<non-JSON error body>"}
        return exc.code, payload
    except urllib.error.URLError as exc:
        return None, {"error": str(exc.reason)}


def _show_api_result(label: str, status: Optional[int], payload: Any) -> bool:
    code = status if status is not None else "ERR"
    print(f"  [{code}] {label}")
    if payload is not None:
        snippet = json.dumps(payload, sort_keys=True)[:240]
        print(f"        {snippet}")
    return isinstance(status, int) and 200 <= status < 300


def _cleanup_hidden_registry_servers(
    base_url: str, api_key: str, *, dry_run: bool = False
) -> bool:
    if dry_run:
        print("  [dry-run] cleanup hidden fixture / unapproved registry servers")
        return True

    status, payload = _call_api("GET", base_url, "/mcp/servers", api_key, dry_run=False)
    ok = _show_api_result("inspect registered MCP servers", status, payload)
    servers = payload.get("servers") if isinstance(payload, dict) else []
    cleanup = [server for server in servers if not server.get("demo_visible", True)]
    if not cleanup:
        print("  no disposable or unapproved registry servers found.")
        return ok

    for server in cleanup:
        server_id = server.get("server_id") or ""
        label = f"remove hidden registry server {server_id} ({server.get('registry_class') or 'unknown'})"
        status, payload = _call_api(
            "DELETE",
            base_url,
            f"/mcp/servers/{server_id}",
            api_key,
            dry_run=False,
        )
        ok = _show_api_result(label, status, payload) and ok
    return ok


def repopulate_render(args: argparse.Namespace) -> int:
    _banner("Render re-populate - capability demo data only")
    if not args.mock_url:
        print("Missing --mock-url. Use the public Val Town MCP mock URL for this step.")
        return 2
    if not args.dry_run and not args.api_key:
        print(
            "Missing API key. Set INTERLOCK_API_KEY or pass --api-key with "
            "admin, mcp.call, and mcp.read scopes plus a bound role."
        )
        return 2

    base = args.base_url.rstrip("/")
    server_id = args.server_id
    mock_v1 = _with_v(args.mock_url, 1)
    mock_v2 = _with_v(args.mock_url, 2)
    ok = _cleanup_hidden_registry_servers(base, args.api_key, dry_run=args.dry_run)

    steps = [
        (
            "register clean proof MCP server",
            "POST",
            "/mcp/servers",
            {
                "server_id": server_id,
                "url": mock_v1,
                "description": "Clean Interlock capability drift proof mock",
                "allowed_tools": [DEMO_TOOL],
                "blocked_tools": [],
                "rate_limit": 10,
                "auth_type": "none",
            },
        ),
        (
            "verify proof MCP server",
            "POST",
            f"/mcp/servers/{server_id}/verify",
            None,
        ),
        (
            "reset stored baseline to clean v1",
            "POST",
            f"/mcp/servers/{server_id}/rebaseline",
            {"confirm_rebaseline": True},
        ),
        (
            "confirm clean v1 baseline",
            "POST",
            "/mcp/discover",
            {"server_url": mock_v1, "server_id": server_id},
        ),
        (
            "discover drifted v2 surface",
            "POST",
            "/mcp/discover",
            {"server_url": mock_v2, "server_id": server_id},
        ),
        (
            "write quarantined-call receipt",
            "POST",
            "/mcp/call",
            {
                "server_id": server_id,
                "tool_name": DEMO_TOOL,
                "arguments": {"doc_id": "canary-demo-doc"},
            },
        ),
    ]

    print(f"  target={base}")
    print(f"  server_id={server_id}")
    print("  scope=capability baseline/drift/quarantine/receipt")
    for label, method, path, body in steps:
        status, payload = _call_api(
            method, base, path, args.api_key, body, dry_run=args.dry_run
        )
        ok = _show_api_result(label, status, payload) and ok

    if not ok:
        print("Render re-populate did not complete cleanly.")
        return 1
    print("Render re-populate complete.")
    return 0


def run_local_script(script_name: str, label: str) -> int:
    script = Path(__file__).resolve().parent / script_name
    _banner(label)
    proc = subprocess.run([sys.executable, str(script)], check=False)
    if proc.returncode != 0:
        print(f"{script_name} failed with exit code {proc.returncode}.")
    return int(proc.returncode)


def run_local_proofs() -> int:
    behavioral = run_local_script(
        "run_effective_permission_probe_live.py",
        "1) Behavioral proof - 403->200 effective permission drift",
    )
    if behavioral != 0:
        return behavioral
    return run_local_script(
        "run_db_drift_ab.py",
        "2) Capability proof - surface drift receipt hashes",
    )


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the clean Interlock demo without the broad proof suite."
    )
    parser.add_argument(
        "--repopulate-render",
        action="store_true",
        help="Seed the Render backend with scoped capability demo data first.",
    )
    parser.add_argument(
        "--skip-local-proof",
        action="store_true",
        help="Only run the Render re-populate step.",
    )
    parser.add_argument("--dry-run", action="store_true", help="Print API calls only.")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--api-key", default=DEFAULT_API_KEY)
    parser.add_argument("--mock-url", default=os.environ.get("INTERLOCK_DEMO_MOCK_URL"))
    parser.add_argument("--server-id", default=DEFAULT_SERVER_ID)
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)

    if args.repopulate_render:
        rc = repopulate_render(args)
        if rc != 0:
            return rc

    if args.skip_local_proof:
        return 0

    return run_local_proofs()


if __name__ == "__main__":
    raise SystemExit(main())
