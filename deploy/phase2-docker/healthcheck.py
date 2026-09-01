"""Dependency-free container health checks for the Phase 2 profile."""

from __future__ import annotations

import socket
import struct
import sys
import urllib.request


def dns() -> None:
    query = (
        b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        + b"\x07allowed\x06phase2\x04test\x00"
        + struct.pack("!HH", 1, 1)
    )
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1)
    sock.sendto(query, ("127.0.0.1", 53))
    if len(sock.recv(512)) < 12:
        raise RuntimeError("DNS response was truncated")


def http(url: str) -> None:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(url, timeout=1) as response:
        if response.status != 200:
            raise RuntimeError("health endpoint failed")


if __name__ == "__main__":
    mode = sys.argv[1]
    if mode == "dns":
        dns()
    elif mode == "origin":
        http("http://127.0.0.1:8080/health")
    elif mode == "interlock":
        http("http://127.0.0.1:8001/health")
    else:
        raise SystemExit(2)
