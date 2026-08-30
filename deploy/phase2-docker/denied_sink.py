"""Connection-counting sink. Any accepted connection fails the profile."""

from __future__ import annotations

import json
import socket
import threading
import time


def listen(family: socket.AddressFamily, address: str, port: int) -> None:
    sock = socket.socket(family, socket.SOCK_STREAM)
    if family == socket.AF_INET6:
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((address, port))
    sock.listen(128)
    while True:
        conn, _peer = sock.accept()
        print(
            json.dumps(
                {
                    "event": "denied_connection",
                    "family": "ipv6" if family == socket.AF_INET6 else "ipv4",
                    "port": port,
                    "time_ns": time.time_ns(),
                },
                sort_keys=True,
            ),
            flush=True,
        )
        conn.close()


if __name__ == "__main__":
    listeners = [
        (socket.AF_INET, "0.0.0.0", port) for port in (80, 443, 8080, 8443)
    ] + [(socket.AF_INET6, "::", port) for port in (80, 443, 8080, 8443)]
    for args in listeners[1:]:
        threading.Thread(target=listen, args=args, daemon=True).start()
    print('{"event":"ready"}', flush=True)
    listen(*listeners[0])
