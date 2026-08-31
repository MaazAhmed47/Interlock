"""Test-only host-namespace listener for dynamically discovered gateway addresses."""

from __future__ import annotations

import argparse
import json
import socket
import threading
import time


def _serve(listener: socket.socket) -> None:
    while True:
        connection, _address = listener.accept()
        with connection:
            try:
                connection.recv(4096)
                connection.sendall(
                    b"HTTP/1.1 204 No Content\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
                )
            except OSError:
                pass


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--address", action="append", default=[])
    parser.add_argument("--port", type=int, default=18081)
    options = parser.parse_args()
    listeners: list[socket.socket] = []
    bound: list[str] = []
    failed: list[dict[str, str]] = []
    for address in sorted(set(options.address)):
        try:
            candidates = socket.getaddrinfo(
                address,
                options.port,
                socket.AF_UNSPEC,
                socket.SOCK_STREAM,
                0,
                socket.AI_NUMERICHOST,
            )
            family, kind, protocol, _canonical, target = candidates[0]
            listener = socket.socket(family, kind, protocol)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if family == socket.AF_INET6:
                listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            listener.bind(target)
            listener.listen(32)
            listeners.append(listener)
            bound.append(address)
        except OSError as exc:
            failed.append({"address": address, "category": type(exc).__name__})
    for listener in listeners:
        threading.Thread(target=_serve, args=(listener,), daemon=True).start()
    print(
        json.dumps(
            {
                "bound_addresses": bound,
                "failed_addresses": failed,
                "schema": "interlock.phase2-host-gateway-listener.v1",
            },
            sort_keys=True,
        ),
        flush=True,
    )
    while True:
        time.sleep(60)


if __name__ == "__main__":
    raise SystemExit(main())
