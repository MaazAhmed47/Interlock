"""Controlled UDP DNS for the hermetic Phase 2 profile."""

from __future__ import annotations

import ipaddress
import json
import socketserver
import struct
import sys
import time

ORIGIN_V4 = "93.184.216.10"
ORIGIN_V6 = "2606:4700:4700::10"
DENIED_V4 = "10.89.0.10"
DENIED_V6 = "fd00:dead::10"

STATIC: dict[str, dict[int, list[str]]] = {
    "private.phase2.test": {1: [DENIED_V4]},
    "loopback.phase2.test": {1: ["127.0.0.1"]},
    "linklocal.phase2.test": {1: ["169.254.10.20"]},
    "metadata.phase2.test": {1: ["169.254.169.254"]},
    "cgnat.phase2.test": {1: ["100.64.0.7"]},
    "multicast.phase2.test": {1: ["224.0.0.7"]},
    "reserved.phase2.test": {1: ["240.0.0.7"]},
    "ula.phase2.test": {28: [DENIED_V6]},
    "v6-linklocal.phase2.test": {28: ["fe80::7"]},
    "mapped.phase2.test": {28: ["::ffff:127.0.0.1"]},
    "nat64.phase2.test": {28: ["64:ff9b::a59:aa"]},
    "nat64-local.phase2.test": {28: ["64:ff9b:1::7f00:1"]},
    "mixed.phase2.test": {1: [ORIGIN_V4, DENIED_V4]},
    "mixed-reverse.phase2.test": {1: [DENIED_V4, ORIGIN_V4]},
    "mixed-family.phase2.test": {1: [ORIGIN_V4], 28: [DENIED_V6]},
}


def _decode_question(packet: bytes) -> tuple[str, int, int, int]:
    offset = 12
    labels: list[str] = []
    while packet[offset]:
        length = packet[offset]
        offset += 1
        labels.append(packet[offset : offset + length].decode("ascii"))
        offset += length
    offset += 1
    qtype, qclass = struct.unpack("!HH", packet[offset : offset + 4])
    return ".".join(labels).lower(), qtype, qclass, offset + 4


def _answer(qtype: int, address: str) -> bytes:
    packed = ipaddress.ip_address(address).packed
    return b"\xc0\x0c" + struct.pack("!HHIH", qtype, 1, 60, len(packed)) + packed


def _proxy_client(peer: tuple[str, int]) -> bool:
    return peer[0] in {"172.31.250.2", "fd00:1:2:3::2"}


def _records(name: str, qtype: int, peer: tuple[str, int]) -> list[str]:
    if name == "timeout.phase2.test":
        raise TimeoutError
    if name in {"nxdomain.phase2.test", "servfail.phase2.test"}:
        return []
    if name == "private-public.phase2.test":
        value = ORIGIN_V4 if _proxy_client(peer) else DENIED_V4
        return [value] if qtype == 1 else []
    if name.startswith(("rebind-", "retry-", "concurrent-")):
        value = DENIED_V4 if _proxy_client(peer) else ORIGIN_V4
        return [value] if qtype == 1 else []
    if name in STATIC:
        return STATIC[name].get(qtype, [])
    if name.endswith(".phase2.test"):
        if qtype == 1:
            return [ORIGIN_V4]
        if qtype == 28 and name.startswith(("allowed-v6", "v6-only")):
            return [ORIGIN_V6]
    return []


class DNSHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        packet, sock = self.request
        try:
            name, qtype, _qclass, end = _decode_question(packet)
            if name == "timeout.phase2.test":
                return
            records = _records(name, qtype, self.client_address)
            rcode = (
                3
                if name == "nxdomain.phase2.test"
                else 2 if name == "servfail.phase2.test" else 0
            )
            flags = 0x8180 | rcode
            header = struct.pack(
                "!HHHHHH",
                struct.unpack("!H", packet[:2])[0],
                flags,
                1,
                len(records),
                0,
                0,
            )
            body = packet[12:end] + b"".join(_answer(qtype, value) for value in records)
            sock.sendto(header + body, self.client_address)
            print(
                json.dumps(
                    {
                        "event": "dns",
                        "name": name,
                        "qtype": qtype,
                        "answer_count": len(records),
                        "rcode": rcode,
                        "time_ns": time.time_ns(),
                    },
                    sort_keys=True,
                ),
                flush=True,
            )
        except Exception as exc:
            print(
                json.dumps({"event": "dns_error", "kind": type(exc).__name__}),
                file=sys.stderr,
                flush=True,
            )


class V6UDPServer(socketserver.ThreadingUDPServer):
    address_family = 10

    def server_bind(self) -> None:
        self.socket.setsockopt(41, 26, 1)
        super().server_bind()


if __name__ == "__main__":
    v4 = socketserver.ThreadingUDPServer(("0.0.0.0", 53), DNSHandler)
    v6 = V6UDPServer(("::", 53), DNSHandler)
    import threading

    threading.Thread(target=v6.serve_forever, daemon=True).start()
    print('{"event":"ready"}', flush=True)
    v4.serve_forever()
