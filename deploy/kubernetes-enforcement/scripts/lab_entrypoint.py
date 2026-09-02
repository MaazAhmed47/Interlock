"""Disposable in-cluster fixtures and probes for the enforcement profile.

Output is deliberately bounded. Probe records never include URLs, IP addresses,
credentials, request bodies, exception strings, or response content.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import socket
import subprocess
import sys
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib import request as urllib_request
from urllib.error import URLError

import httpx
import requests

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

MCP_HOST = "mcp.interlock-mcp.svc.cluster.local"
MCP_SERVICE_URL = f"http://{MCP_HOST}:8080"
GATEWAY_URL = "http://interlock.interlock-gateway.svc.cluster.local:8001"
RESULT_PREFIX = "INTERLOCK_K8S_RESULT "
MCP_TOOL_NAME = "get"


def _emit(case_id: str, actual_result: str, failure_category: str) -> None:
    print(
        RESULT_PREFIX
        + json.dumps(
            {
                "case_id": case_id,
                "actual_result": actual_result,
                "failure_category": failure_category,
                "observed_at": datetime.now(timezone.utc).isoformat(),
            },
            sort_keys=True,
        )
    )


class MCPHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def _write_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/health":
            self._write_json(200, {"ok": True})
            return
        self._write_json(404, {"ok": False})

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/mcp":
            self._write_json(404, {"ok": False})
            return
        try:
            length = int(self.headers.get("content-length", "0"))
            if length < 2 or length > 16_384:
                raise ValueError("bounded body required")
            payload = json.loads(self.rfile.read(length))
            request_id = payload.get("id")
            method = payload.get("method")
        except (ValueError, json.JSONDecodeError):
            self._write_json(400, {"error": "malformed"})
            return
        if method == "tools/list":
            result: dict[str, Any] = {
                "tools": [
                    {
                        "name": MCP_TOOL_NAME,
                        "description": "Return a fixed lab acknowledgement.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {},
                            "additionalProperties": False,
                        },
                    }
                ]
            }
        elif method == "tools/call":
            result = {
                "content": [{"type": "text", "text": "kubernetes-lab-ok"}],
                "isError": False,
            }
        else:
            self._write_json(
                200,
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -32601, "message": "unknown method"},
                },
            )
            return
        self._write_json(200, {"jsonrpc": "2.0", "id": request_id, "result": result})


def run_mcp_server() -> int:
    server = ThreadingHTTPServer(("0.0.0.0", 8080), MCPHandler)
    server.serve_forever()
    return 0


def bootstrap() -> int:
    raw_key = os.environ.get("INTERLOCK_LAB_API_KEY", "")
    if not raw_key or not raw_key.startswith("lf_developer_"):
        raise RuntimeError("ephemeral lab key is missing")

    from core import db
    from core.tool_metadata import normalize_tool_metadata

    db.init_db()
    defaults = db.PLAN_DEFAULTS["developer"]
    now = datetime.now(timezone.utc).isoformat()
    with db._db_lock, db.get_conn() as conn:  # noqa: SLF001 - isolated lab seed
        conn.execute(
            """
            INSERT INTO api_keys
              (key_hash, key_prefix, label, plan, monthly_limit, rate_per_min,
               fail_mode, is_active, created_at, max_response_bytes,
               max_array_items, scopes, role)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                db._hash_key(raw_key),  # noqa: SLF001 - raw key is never persisted
                raw_key[:12],
                "disposable kubernetes enforcement lab",
                "developer",
                defaults["monthly_limit"],
                defaults["rate_per_min"],
                defaults["fail_mode"],
                True,
                now,
                defaults["max_response_bytes"],
                defaults["max_array_items"],
                json.dumps(["mcp.call", "audit.read"]),
                "readonly_agent",
            ),
        )

    server_id = "_test_kubernetes_enforcement"
    tool = {
        "name": MCP_TOOL_NAME,
        "description": "Return a fixed lab acknowledgement.",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    }
    if not db.register_mcp_server(
        server_id,
        {
            "url": MCP_SERVICE_URL + "/mcp",
            "description": "Disposable Kubernetes enforcement fixture",
            "allowed_tools": [MCP_TOOL_NAME],
            "blocked_tools": [],
            "environment": "non_production",
            "probes_enabled": False,
        },
    ):
        raise RuntimeError("fixture server registration failed")
    if not db.verify_mcp_server(server_id):
        raise RuntimeError("fixture server verification failed")
    metadata = normalize_tool_metadata(tool)
    result = db.upsert_mcp_tool_metadata(server_id, tool, metadata)
    if result.get("error"):
        raise RuntimeError("fixture tool baseline failed")
    print(json.dumps({"bootstrap": "complete", "nonce": secrets.token_hex(8)}))
    return 0


def _classify_call(callable_) -> tuple[str, str]:
    try:
        callable_()
        return "allowed", "none"
    except (httpx.TimeoutException, requests.Timeout, TimeoutError, socket.timeout):
        return "network_denied", "connect_timeout"
    except URLError as exc:
        if isinstance(exc.reason, (TimeoutError, socket.timeout)):
            return "network_denied", "connect_timeout"
        return "network_denied", "connect_error"
    except (httpx.NetworkError, requests.ConnectionError, ConnectionError, OSError):
        return "network_denied", "connect_error"


def _direct(method: str, destination: str) -> tuple[str, str]:
    url = destination.rstrip("/") + "/health"
    if method == "httpx":
        return _classify_call(lambda: httpx.get(url, timeout=2.0))
    if method == "requests":
        return _classify_call(lambda: requests.get(url, timeout=2.0))
    if method == "urllib":
        return _classify_call(lambda: urllib_request.urlopen(url, timeout=2.0).read(64))
    if method == "socket":
        host = destination.split("//", 1)[1].rsplit(":", 1)[0]

        def connect() -> None:
            with socket.create_connection((host, 8080), timeout=2.0):
                return

        return _classify_call(connect)
    if method == "curl":
        completed = subprocess.run(
            ["curl", "--fail", "--silent", "--show-error", "--max-time", "2", url],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=4,
        )
        if completed.returncode == 0:
            return "allowed", "none"
        if completed.returncode == 28:
            return "network_denied", "connect_timeout"
        return "network_denied", "connect_error"
    raise ValueError("unknown probe method")


def run_probe(args: argparse.Namespace) -> int:
    if args.mode == "dns":
        try:
            address_sets = [
                socket.getaddrinfo(host, 8080, type=socket.SOCK_STREAM)
                for host in (MCP_HOST, "mcp.interlock-mcp")
            ]
        except OSError:
            _emit(args.case_id, "dns_failed", "resolution_error")
            return 1
        resolved = all(addresses for addresses in address_sets)
        _emit(args.case_id, "resolved" if resolved else "dns_failed", "none")
        return 0 if resolved else 1

    if args.mode == "direct":
        actual, category = _direct(args.method, args.destination)
        _emit(args.case_id, actual, category)
        return 0

    if args.mode == "mediated":
        key = os.environ.get("INTERLOCK_LAB_API_KEY", "")
        try:
            response = httpx.post(
                GATEWAY_URL + "/mcp/call",
                headers={"x-api-key": key},
                json={
                    "server_id": "_test_kubernetes_enforcement",
                    "tool_name": MCP_TOOL_NAME,
                    "arguments": {},
                },
                timeout=8.0,
            )
            payload = response.json()
            if response.status_code != 200 or payload.get("ok") is not True:
                raise RuntimeError("gateway rejected fixture")
            audit_id = (payload.get("audit") or {}).get("audit_id")
            if not isinstance(audit_id, int):
                raise RuntimeError("gateway omitted audit reference")
            with open("/tmp/interlock-k8s-audit-id", "w", encoding="ascii") as handle:
                handle.write(str(audit_id))
        except (httpx.HTTPError, ValueError, RuntimeError):
            _emit(args.case_id, "gateway_failed", "gateway_error")
            return 1
        _emit(args.case_id, "allowed", "none")
        return 0

    if args.mode == "receipt":
        key = os.environ.get("INTERLOCK_LAB_API_KEY", "")
        try:
            with open("/tmp/interlock-k8s-audit-id", encoding="ascii") as handle:
                audit_id = int(handle.read())
            response = httpx.get(
                GATEWAY_URL + f"/audit/receipt/{audit_id}",
                headers={"x-api-key": key},
                timeout=4.0,
            )
            receipt = response.json()
            if response.status_code != 200 or receipt.get("chain_verified") is not True:
                raise RuntimeError("receipt not verified")
        except (httpx.HTTPError, OSError, ValueError, RuntimeError):
            _emit(args.case_id, "gateway_failed", "gateway_error")
            return 1
        _emit(args.case_id, "verified", "none")
        return 0

    if args.mode == "gateway-down":
        key = os.environ.get("INTERLOCK_LAB_API_KEY", "")
        try:
            httpx.post(
                GATEWAY_URL + "/mcp/call",
                headers={"x-api-key": key},
                json={
                    "server_id": "_test_kubernetes_enforcement",
                    "tool_name": MCP_TOOL_NAME,
                    "arguments": {},
                },
                timeout=2.0,
            )
        except httpx.HTTPError:
            _emit(
                args.case_id,
                "gateway_unavailable_no_fallback",
                "gateway_unavailable",
            )
            return 0
        _emit(args.case_id, "gateway_unexpectedly_available", "none")
        return 1

    raise ValueError("unknown probe mode")


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("mcp-server")
    subparsers.add_parser("bootstrap")
    probe = subparsers.add_parser("probe")
    probe.add_argument("--case-id", required=True)
    probe.add_argument(
        "--mode",
        choices=["dns", "direct", "mediated", "receipt", "gateway-down"],
        required=True,
    )
    probe.add_argument(
        "--method",
        choices=["httpx", "requests", "urllib", "socket", "curl"],
        default="httpx",
    )
    probe.add_argument("--destination", default=MCP_SERVICE_URL)
    args = parser.parse_args()
    if args.command == "mcp-server":
        return run_mcp_server()
    if args.command == "bootstrap":
        return bootstrap()
    return run_probe(args)


if __name__ == "__main__":
    sys.exit(main())
