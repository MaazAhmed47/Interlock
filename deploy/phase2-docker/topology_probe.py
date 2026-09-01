"""Bounded application/host probes for the Docker Phase 2 topology."""

from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
from contextlib import closing
from urllib.request import ProxyHandler, build_opener

import httpx
import requests

HOST_ALIASES = (
    "gateway.docker.internal",
    "host-gateway",
    "host.docker.internal",
)
METHODS = ("curl", "httpx", "requests", "socket", "urllib")
PORT = 18081


def _safe_environment() -> dict[str, str]:
    environment = os.environ.copy()
    for name in (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "no_proxy",
    ):
        environment.pop(name, None)
    return environment


def discover_aliases() -> dict[str, object]:
    aliases: list[dict[str, object]] = []
    for hostname in HOST_ALIASES:
        addresses: set[str] = set()
        category = ""
        try:
            for _family, _kind, _protocol, _canonical, address in socket.getaddrinfo(
                hostname, PORT, socket.AF_UNSPEC, socket.SOCK_STREAM
            ):
                addresses.add(str(address[0]))
        except OSError as exc:
            category = type(exc).__name__
        aliases.append(
            {
                "addresses": sorted(addresses),
                "category": category,
                "hostname": hostname,
            }
        )
    return {"aliases": aliases, "schema": "interlock.phase2-topology-aliases.v1"}


def _url(address: str) -> str:
    host = address
    if ":" in address and not address.startswith("["):
        host = f"[{address.replace('%', '%25')}]"
    return f"http://{host}:{PORT}/"


def _httpx(address: str) -> bool:
    try:
        httpx.get(_url(address), timeout=1.5, trust_env=False)
    except Exception:
        return False
    return True


def _urllib(address: str) -> bool:
    try:
        build_opener(ProxyHandler({})).open(_url(address), timeout=1.5)
    except Exception:
        return False
    return True


def _requests(address: str) -> bool:
    session = requests.Session()
    session.trust_env = False
    try:
        session.get(_url(address), timeout=1.5)
    except Exception:
        return False
    finally:
        session.close()
    return True


def _socket(address: str) -> bool:
    try:
        candidates = socket.getaddrinfo(
            address,
            PORT,
            socket.AF_UNSPEC,
            socket.SOCK_STREAM,
            0,
            socket.AI_NUMERICHOST,
        )
        for family, kind, protocol, _canonical, target in candidates:
            with closing(socket.socket(family, kind, protocol)) as connection:
                connection.settimeout(1.5)
                connection.connect(target)
                return True
    except OSError:
        return False
    return False


def _curl(address: str) -> bool:
    completed = subprocess.run(
        [
            "curl",
            "--silent",
            "--show-error",
            "--max-time",
            "2",
            "--noproxy",
            "*",
            _url(address),
        ],
        capture_output=True,
        text=True,
        check=False,
        env=_safe_environment(),
    )
    return completed.returncode == 0


def attempt_targets(targets: list[str]) -> dict[str, object]:
    operations = {
        "curl": _curl,
        "httpx": _httpx,
        "requests": _requests,
        "socket": _socket,
        "urllib": _urllib,
    }
    results = []
    for address in sorted(set(targets)):
        family = 6 if ":" in address else 4
        for method in METHODS:
            results.append(
                {
                    "address": address,
                    "connected": operations[method](address),
                    "family": family,
                    "method": method,
                }
            )
    return {"results": results, "schema": "interlock.phase2-topology-attempts.v1"}


def host_bridge(interface: str) -> list[dict[str, object]]:
    completed = subprocess.run(
        ["ip", "-j", "address", "show", "dev", interface],
        capture_output=True,
        text=True,
        check=True,
    )
    value = json.loads(completed.stdout)
    if not isinstance(value, list):
        raise ValueError("host bridge probe returned malformed data")
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="operation", required=True)
    subparsers.add_parser("discover")
    attempts = subparsers.add_parser("attempt")
    attempts.add_argument("--target", action="append", default=[])
    bridge = subparsers.add_parser("host-bridge")
    bridge.add_argument("--interface", required=True)
    options = parser.parse_args()
    if options.operation == "discover":
        result: object = discover_aliases()
    elif options.operation == "attempt":
        result = attempt_targets(options.target)
    else:
        result = host_bridge(options.interface)
    print(json.dumps(result, sort_keys=True), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
