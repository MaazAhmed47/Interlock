"""Outbound URL safety checks for hosted Interlock deployments."""

from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

from config import allow_private_outbound_urls, protect_outbound_urls


class OutboundUrlRejected(ValueError):
    """Raised when an outbound URL is unsafe for hosted/server-side fetches."""


_INTERNAL_HOST_SUFFIXES = (
    ".internal",
    ".intranet",
    ".corp",
    ".lan",
    ".local",
    ".localhost",
)
_INTERNAL_HOSTNAMES = {
    "localhost",
    "metadata",
    "metadata.google.internal",
    "169.254.169.254",
    "instance-data",
}


def _host_without_brackets(host: str) -> str:
    host = (host or "").strip().lower().rstrip(".")
    if host.startswith("[") and host.endswith("]"):
        return host[1:-1]
    return host


def _is_blocked_ip(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False

    metadata_ip = ipaddress.ip_address("169.254.169.254")
    return any(
        (
            ip == metadata_ip,
            ip.is_loopback,
            ip.is_private,
            ip.is_link_local,
            ip.is_unspecified,
            ip.is_reserved,
            ip.is_multicast,
        )
    )


def _is_internal_hostname(host: str) -> bool:
    if not host:
        return True
    if host in _INTERNAL_HOSTNAMES:
        return True
    if host.endswith(_INTERNAL_HOST_SUFFIXES):
        return True
    # Single-label hosts are usually internal names in server-side deployments.
    return "." not in host


def ensure_safe_outbound_url(url: str, *, context: str = "outbound") -> str:
    """Validate a server-side outbound URL when hosted protection is enabled."""
    candidate = (url or "").strip()
    if not candidate:
        raise OutboundUrlRejected(f"{context} URL is required")

    parsed = urlparse(candidate)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise OutboundUrlRejected(
            f"{context} URL must use http or https; got '{parsed.scheme or 'missing'}'"
        )
    if not parsed.hostname:
        raise OutboundUrlRejected(f"{context} URL must include a hostname")
    if parsed.username or parsed.password:
        raise OutboundUrlRejected(f"{context} URL must not include credentials")

    if not protect_outbound_urls() or allow_private_outbound_urls():
        return candidate

    host = _host_without_brackets(parsed.hostname)
    if _is_blocked_ip(host) or _is_internal_hostname(host):
        raise OutboundUrlRejected(
            f"{context} URL host '{host}' is not allowed in hosted mode"
        )

    return candidate
