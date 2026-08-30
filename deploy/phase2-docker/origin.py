"""Synthetic HTTP/HTTPS origin that records only bounded, non-secret metadata."""

from __future__ import annotations

import json
import socket
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _record(self, route: str) -> None:
        print(
            json.dumps(
                {
                    "event": "origin_request",
                    "host": self.headers.get("Host", "")[:160],
                    "method": self.command,
                    "route": route[:160],
                    "sni": getattr(self.connection, "observed_sni", None),
                    "via_present": bool(self.headers.get("Via")),
                    "authorization_present": bool(self.headers.get("Authorization")),
                    "time_ns": time.time_ns(),
                },
                sort_keys=True,
            ),
            flush=True,
        )

    def _send(
        self, status: int, body: dict | list | None = None, **headers: str
    ) -> None:
        payload = json.dumps(body or {}).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        for name, value in headers.items():
            self.send_header(name.replace("_", "-"), value)
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:
        route = self.path.split("?", 1)[0]
        self._record(route)
        if route == "/jwks":
            self._send(200, json.loads(Path("/certs/jwks.json").read_text("utf-8")))
        elif route.endswith("/tools/list") or route == "/tools/list":
            self._send(
                200, {"tools": [{"name": "echo", "inputSchema": {"type": "object"}}]}
            )
        elif route.startswith("/redirect/"):
            target = route.rsplit("/", 1)[-1]
            locations = {
                "cross-host": "http://wrong.phase2.test:8080/cross-host",
                "private-target": "http://private.phase2.test:8080/private",
                "raw-ip": "http://10.89.0.10:8080/raw",
                "downgrade": "http://allowed.phase2.test:8080/downgraded",
                "credentials": (
                    "http://fixture:fixture@allowed.phase2.test:8080/credentials"
                ),
                "loop": f"http://allowed.phase2.test:8080{route}",
                "hop-exhaustion": (
                    "http://allowed.phase2.test:8080/redirect/hop-exhaustion"
                ),
            }
            code = int(target) if target.isdigit() else 302
            location = locations.get(
                target, "http://denied-sink.phase2.test:8080/redirected"
            )
            self._send(code, {}, Location=location)
        elif route == "/health":
            self._send(200, {"ok": True})
        else:
            self._send(
                200,
                {
                    "ok": True,
                    "host": self.headers.get("Host", ""),
                    "sni": getattr(self.connection, "observed_sni", None),
                    "via_present": bool(self.headers.get("Via")),
                },
            )

    def do_POST(self) -> None:
        route = self.path.split("?", 1)[0]
        size = min(int(self.headers.get("Content-Length", "0") or "0"), 1_048_576)
        raw = self.rfile.read(size)
        self._record(route)
        try:
            request = json.loads(raw or b"{}")
        except (json.JSONDecodeError, UnicodeDecodeError):
            request = {}
        method = request.get("method") if isinstance(request, dict) else None
        request_id = request.get("id") if isinstance(request, dict) else None
        if method == "server/discover":
            self._send(
                200,
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {
                        "supportedVersions": ["2026-01-26"],
                        "capabilities": {"tools": {}},
                    },
                },
            )
        elif method == "tools/list":
            self._send(
                200,
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {
                        "tools": [
                            {
                                "name": "echo",
                                "description": "fixture",
                                "inputSchema": {"type": "object", "properties": {}},
                            }
                        ]
                    },
                },
            )
        elif method == "tools/call":
            self._send(
                200,
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {
                        "content": [{"type": "text", "text": "phase2-ok"}],
                        "structuredContent": {"ok": True},
                    },
                },
            )
        elif route.startswith("/anthropic"):
            self._send(
                200,
                {
                    "model": "fixture",
                    "content": [{"text": "ok"}],
                    "stop_reason": "end_turn",
                },
            )
        elif route.startswith("/google"):
            self._send(
                200,
                {
                    "modelVersion": "fixture",
                    "candidates": [{"content": {"parts": [{"text": "ok"}]}}],
                },
            )
        else:
            self._send(
                200,
                {
                    "id": "fixture",
                    "choices": [{"message": {"role": "assistant", "content": "SAFE"}}],
                },
            )

    def log_message(self, *_args: object) -> None:
        return


class V6Server(ThreadingHTTPServer):
    address_family = socket.AF_INET6

    def server_bind(self) -> None:
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        super().server_bind()


def tls_context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain("/certs/origin.pem", "/certs/origin-key.pem")

    def observe_sni(
        sock: ssl.SSLSocket, name: str | None, _context: ssl.SSLContext
    ) -> None:
        sock.observed_sni = name  # type: ignore[attr-defined]

    context.set_servername_callback(observe_sni)
    return context


def serve(server: ThreadingHTTPServer, *, tls: bool = False) -> None:
    if tls:
        server.socket = tls_context().wrap_socket(server.socket, server_side=True)
    server.serve_forever(poll_interval=0.1)


if __name__ == "__main__":
    servers = [
        (ThreadingHTTPServer(("0.0.0.0", 8080), Handler), False),
        (V6Server(("::", 8080), Handler), False),
        (ThreadingHTTPServer(("0.0.0.0", 8443), Handler), True),
        (V6Server(("::", 8443), Handler), True),
    ]
    for server, encrypted in servers[1:]:
        threading.Thread(
            target=serve, args=(server,), kwargs={"tls": encrypted}, daemon=True
        ).start()
    print('{"event":"ready"}', flush=True)
    serve(servers[0][0])
