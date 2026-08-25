"""Outbound URL safety checks for hosted Interlock deployments."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from collections.abc import Awaitable, Callable, Sequence
from typing import Any, Optional

import httpx

from config import is_hosted, is_production, offline_demo_enabled, protect_outbound_urls


class OutboundUrlRejected(ValueError):
    """Raised when an outbound URL is unsafe for hosted/server-side fetches."""


Resolver = Callable[..., Sequence[tuple[Any, ...]]]
AsyncResolver = Callable[..., Awaitable[Sequence[tuple[Any, ...]]]]
DEFAULT_RESOLUTION_TIMEOUT_SECONDS = 5.0


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
    host = (host or "").strip().lower()
    if host.startswith("[") and host.endswith("]"):
        return host[1:-1]
    return host


def _is_blocked_ip(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False

    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return _is_forbidden_address(ip)


def _is_forbidden_address(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> bool:
    return any(
        (
            not address.is_global,
            address.is_loopback,
            address.is_private,
            address.is_link_local,
            address.is_unspecified,
            address.is_reserved,
            address.is_multicast,
            isinstance(address, ipaddress.IPv6Address) and address.is_site_local,
        )
    )


def _is_internal_hostname(host: str) -> bool:
    host = host.rstrip(".")
    if not host:
        return True
    if host in _INTERNAL_HOSTNAMES:
        return True
    if host.endswith(_INTERNAL_HOST_SUFFIXES):
        return True
    # Single-label hosts are usually internal names in server-side deployments.
    return "." not in host


def _offline_demo_host_allowed(host: str) -> bool:
    """Allow only the bundled Compose mock in an explicit local demo profile."""
    return (
        host.rstrip(".") == "mcp-mock"
        and offline_demo_enabled()
        and not is_hosted()
        and not is_production()
    )


def _canonical_url_parts(url: str, *, context: str) -> tuple[str, str, int]:
    candidate = (url or "").strip()
    if not candidate:
        raise OutboundUrlRejected(f"{context} URL is required")

    try:
        parsed = httpx.URL(candidate)
    except (httpx.InvalidURL, UnicodeError) as exc:
        raise OutboundUrlRejected(f"{context} URL is invalid") from exc

    if parsed.scheme.lower() not in {"http", "https"}:
        raise OutboundUrlRejected(
            f"{context} URL must use http or https; got '{parsed.scheme or 'missing'}'"
        )
    if not parsed.raw_host:
        raise OutboundUrlRejected(f"{context} URL must include a hostname")
    if parsed.userinfo:
        raise OutboundUrlRejected(f"{context} URL must not include credentials")

    try:
        host = parsed.raw_host.decode("ascii").lower()
    except UnicodeDecodeError as exc:  # pragma: no cover - HTTPX emits ASCII here.
        raise OutboundUrlRejected(f"{context} URL hostname is invalid") from exc
    port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    return str(parsed), host, port


def _addresses_from_answers(
    answers: Sequence[tuple[Any, ...]], *, host: str, context: str
) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...]:
    resolved = []
    for answer in answers:
        try:
            raw_address = str(answer[4][0]).split("%", 1)[0]
            address = ipaddress.ip_address(raw_address)
        except (IndexError, TypeError, ValueError) as exc:
            raise OutboundUrlRejected(
                f"{context} URL host '{host}' returned an invalid address"
            ) from exc
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
            address = address.ipv4_mapped
        resolved.append(address)

    if not resolved:
        raise OutboundUrlRejected(f"{context} URL host '{host}' could not be resolved")
    return tuple(resolved)


def _resolved_addresses(
    host: str,
    port: int,
    *,
    resolver: Resolver,
    context: str,
) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...]:
    try:
        answers = resolver(
            host,
            port,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
            proto=socket.IPPROTO_TCP,
        )
    except (OSError, ValueError) as exc:
        raise OutboundUrlRejected(
            f"{context} URL host '{host}' could not be resolved"
        ) from exc

    return _addresses_from_answers(answers, host=host, context=context)


async def _system_resolver(
    host: str, port: int, **kwargs: Any
) -> Sequence[tuple[Any, ...]]:
    return await asyncio.to_thread(socket.getaddrinfo, host, port, **kwargs)


async def _resolved_addresses_async(
    host: str,
    port: int,
    *,
    resolver: AsyncResolver,
    context: str,
    timeout_seconds: float,
) -> tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, ...]:
    try:
        answers = await asyncio.wait_for(
            resolver(
                host,
                port,
                family=socket.AF_UNSPEC,
                type=socket.SOCK_STREAM,
                proto=socket.IPPROTO_TCP,
            ),
            timeout=timeout_seconds,
        )
    except TimeoutError as exc:
        raise OutboundUrlRejected(
            f"{context} URL host '{host}' resolution timed out"
        ) from exc
    except (OSError, ValueError) as exc:
        raise OutboundUrlRejected(
            f"{context} URL host '{host}' could not be resolved"
        ) from exc
    return _addresses_from_answers(answers, host=host, context=context)


def ensure_safe_outbound_url(
    url: str,
    *,
    context: str = "outbound",
    resolver: Optional[Resolver] = None,
) -> str:
    """Resolve and reject unsafe destinations when outbound protection is enabled.

    This is a partial mitigation only: the HTTP transport resolves the hostname
    again, so DNS rebinding still requires connection pinning or enforced egress.
    """
    candidate, host, port = _canonical_url_parts(url, context=context)

    if not protect_outbound_urls():
        return candidate

    offline_demo_host = _offline_demo_host_allowed(host)
    if _is_blocked_ip(host) or (_is_internal_hostname(host) and not offline_demo_host):
        raise OutboundUrlRejected(
            f"{context} URL host '{host}' is not allowed in hosted mode"
        )

    try:
        literal_address = ipaddress.ip_address(host)
    except ValueError:
        literal_address = None
    if literal_address is not None:
        return candidate

    addresses = _resolved_addresses(
        host,
        port,
        resolver=resolver or socket.getaddrinfo,
        context=context,
    )
    if not offline_demo_host and any(
        _is_forbidden_address(address) for address in addresses
    ):
        raise OutboundUrlRejected(
            f"{context} URL host '{host}' resolved to a non-global address"
        )

    return candidate


async def ensure_safe_outbound_url_async(
    url: str,
    *,
    context: str = "outbound",
    resolver: Optional[AsyncResolver] = None,
    resolution_timeout_seconds: float = DEFAULT_RESOLUTION_TIMEOUT_SECONDS,
) -> str:
    """Asynchronously resolve and reject unsafe outbound destinations.

    The default resolver runs off-thread and has a bounded caller wait. Timing
    out the wait does not prove cancellation of the underlying OS resolver.
    This remains a partial mitigation because the HTTP transport resolves the
    hostname again unless a separate egress boundary pins or filters it.
    """
    candidate, host, port = _canonical_url_parts(url, context=context)

    if not protect_outbound_urls():
        return candidate

    offline_demo_host = _offline_demo_host_allowed(host)
    if _is_blocked_ip(host) or (_is_internal_hostname(host) and not offline_demo_host):
        raise OutboundUrlRejected(
            f"{context} URL host '{host}' is not allowed in hosted mode"
        )

    try:
        literal_address = ipaddress.ip_address(host)
    except ValueError:
        literal_address = None
    if literal_address is not None:
        return candidate

    addresses = await _resolved_addresses_async(
        host,
        port,
        resolver=resolver or _system_resolver,
        context=context,
        timeout_seconds=resolution_timeout_seconds,
    )
    if not offline_demo_host and any(
        _is_forbidden_address(address) for address in addresses
    ):
        raise OutboundUrlRejected(
            f"{context} URL host '{host}' resolved to a non-global address"
        )

    return candidate
