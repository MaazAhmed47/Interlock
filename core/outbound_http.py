"""Central construction and provenance for Interlock server-side HTTP clients.

This module is application plumbing.  It does not enforce destination address
classes or deny direct workload egress; those Phase 2 properties belong to the
separately deployed proxy and network policy.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import ssl
import threading
import weakref
from dataclasses import dataclass
from enum import Enum
from typing import Any, TypeAlias
from urllib.parse import urlsplit

import httpx

from config import outbound_egress_profile_value, outbound_http_proxy_value

# HTTPX includes full request URLs at INFO and HTTPCore can include peer-controlled
# response metadata at DEBUG. Keep dependency logging below the boundary where
# webhook paths, query values, or other credentials could enter retained logs.
for _transport_logger_name in ("httpx", "httpcore"):
    logging.getLogger(_transport_logger_name).setLevel(logging.WARNING)


class OutboundHTTPConfigurationError(RuntimeError):
    """A fail-closed egress setting cannot safely construct an HTTP client."""


class EgressProfile(str, Enum):
    PHASE1 = "phase1"
    ENFORCED = "enforced"


TimeoutValue: TypeAlias = float | httpx.Timeout | None
VerifyValue: TypeAlias = bool | str | ssl.SSLContext

_DNS_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_TRUST_LOCK = threading.Lock()


@dataclass(frozen=True)
class _OutboundHTTPSettings:
    profile: EgressProfile
    proxy_url: str | None

    @property
    def enforced(self) -> bool:
        return self.profile is EgressProfile.ENFORCED


_TRUSTED_SYNC_CLIENTS: weakref.WeakKeyDictionary[
    httpx.Client, _OutboundHTTPSettings
] = weakref.WeakKeyDictionary()
_TRUSTED_ASYNC_CLIENTS: weakref.WeakKeyDictionary[
    httpx.AsyncClient, _OutboundHTTPSettings
] = weakref.WeakKeyDictionary()


def _configuration_error(reason: str) -> OutboundHTTPConfigurationError:
    return OutboundHTTPConfigurationError(
        f"Outbound HTTP configuration is invalid: {reason}. "
        "The configured value was not included."
    )


def current_egress_profile() -> EgressProfile:
    raw = outbound_egress_profile_value()
    try:
        return EgressProfile(raw)
    except ValueError:
        raise _configuration_error(
            "INTERLOCK_EGRESS_PROFILE must be 'phase1' or 'enforced'"
        ) from None


def is_enforced_egress_profile() -> bool:
    return current_egress_profile() is EgressProfile.ENFORCED


def _canonical_proxy_url(raw: str) -> str:
    if raw != raw.strip() or any(ord(character) < 0x20 for character in raw):
        raise _configuration_error("the proxy URL contains whitespace or controls")
    if "\\" in raw:
        raise _configuration_error("the proxy URL contains ambiguous authority syntax")
    try:
        parsed = urlsplit(raw)
    except (TypeError, ValueError, UnicodeError):
        raise _configuration_error("the proxy URL cannot be parsed") from None

    if parsed.scheme.lower() != "http":
        raise _configuration_error("the proxy URL scheme must be http")
    if not parsed.netloc or parsed.hostname is None:
        raise _configuration_error("the proxy URL requires an explicit host and port")
    if (
        parsed.username is not None
        or parsed.password is not None
        or "@" in parsed.netloc
    ):
        raise _configuration_error("embedded proxy credentials are forbidden")
    if parsed.path or parsed.query or parsed.fragment:
        raise _configuration_error("proxy paths, queries, and fragments are forbidden")
    if "%" in parsed.netloc:
        raise _configuration_error("encoded or scoped proxy authorities are forbidden")
    try:
        port = parsed.port
    except ValueError:
        raise _configuration_error("the proxy port is invalid") from None
    if port is None or not 1 <= port <= 65535:
        raise _configuration_error("the proxy URL requires a valid explicit port")

    host = parsed.hostname.lower()
    if host.endswith("."):
        raise _configuration_error("a trailing-dot proxy hostname is forbidden")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        try:
            host.encode("ascii")
        except UnicodeEncodeError:
            raise _configuration_error(
                "proxy hostnames must use explicit ASCII or punycode"
            ) from None
        numeric_labels = host.split(".")
        if all(
            label.isdigit()
            or (
                label.lower().startswith("0x")
                and len(label) > 2
                and all(
                    character in "0123456789abcdef" for character in label[2:].lower()
                )
            )
            for label in numeric_labels
        ):
            raise _configuration_error("ambiguous numeric proxy hosts are forbidden")
        labels = host.split(".")
        if len(host) > 253 or any(not _DNS_LABEL.fullmatch(label) for label in labels):
            raise _configuration_error("the proxy hostname syntax is invalid")
        canonical_host = host
    else:
        canonical_host = (
            f"[{address.compressed}]"
            if isinstance(address, ipaddress.IPv6Address)
            else address.compressed
        )
    return f"http://{canonical_host}:{port}"


def _load_settings() -> _OutboundHTTPSettings:
    profile = current_egress_profile()
    raw_proxy = outbound_http_proxy_value()
    if raw_proxy is None:
        if profile is EgressProfile.ENFORCED:
            raise _configuration_error(
                "the enforced profile requires INTERLOCK_OUTBOUND_HTTP_PROXY"
            )
        return _OutboundHTTPSettings(profile=profile, proxy_url=None)
    return _OutboundHTTPSettings(
        profile=profile,
        proxy_url=_canonical_proxy_url(raw_proxy),
    )


def assert_outbound_http_config_valid() -> None:
    """Validate egress configuration before database or outbound work."""

    _load_settings()


def _validate_client_options(
    settings: _OutboundHTTPSettings,
    *,
    verify: VerifyValue,
    transport: httpx.BaseTransport | httpx.AsyncBaseTransport | None,
) -> None:
    if settings.enforced:
        secure_ssl_context = not isinstance(verify, ssl.SSLContext) or (
            verify.verify_mode == ssl.CERT_REQUIRED and verify.check_hostname
        )
        verification_is_acceptable = (
            verify is True
            or (isinstance(verify, ssl.SSLContext) and secure_ssl_context)
            or (isinstance(verify, str) and bool(verify.strip()))
        )
        if not verification_is_acceptable:
            raise _configuration_error(
                "TLS certificate verification cannot be disabled in the enforced profile"
            )
        if transport is not None:
            raise _configuration_error(
                "custom HTTP transports are forbidden in the enforced profile"
            )


def _remember_sync_client(
    client: httpx.Client, settings: _OutboundHTTPSettings
) -> httpx.Client:
    try:
        with _TRUST_LOCK:
            _TRUSTED_SYNC_CLIENTS[client] = settings
    except TypeError as exc:
        client.close()
        raise _configuration_error(
            "the HTTP client cannot carry factory provenance"
        ) from exc
    return client


def _remember_async_client(
    client: httpx.AsyncClient, settings: _OutboundHTTPSettings
) -> httpx.AsyncClient:
    try:
        with _TRUST_LOCK:
            _TRUSTED_ASYNC_CLIENTS[client] = settings
    except TypeError as exc:
        raise _configuration_error(
            "the HTTP client cannot carry factory provenance"
        ) from exc
    return client


def is_trusted_sync_client(client: object) -> bool:
    try:
        with _TRUST_LOCK:
            return client in _TRUSTED_SYNC_CLIENTS
    except TypeError:
        return False


def is_trusted_async_client(client: object) -> bool:
    try:
        with _TRUST_LOCK:
            return client in _TRUSTED_ASYNC_CLIENTS
    except TypeError:
        return False


def require_trusted_async_client(client: httpx.AsyncClient, *, purpose: str) -> None:
    """Reject caller-created clients at an enforced production injection seam."""

    del purpose  # Purpose labels are deliberately never rendered into failures.
    settings = _load_settings()
    if settings.enforced:
        try:
            with _TRUST_LOCK:
                provenance = _TRUSTED_ASYNC_CLIENTS.get(client)
        except TypeError:
            provenance = None
        if provenance != settings:
            raise _configuration_error(
                "an untrusted caller-injected HTTP client is forbidden in the enforced profile"
            )


def create_sync_client(
    *,
    timeout: TimeoutValue,
    verify: VerifyValue = True,
    transport: httpx.BaseTransport | None = None,
    purpose: str,
) -> httpx.Client:
    """Construct one explicit, non-redirecting, environment-independent client."""

    del purpose
    settings = _load_settings()
    _validate_client_options(settings, verify=verify, transport=transport)
    client_options: dict[str, Any] = {
        "timeout": timeout,
        "verify": verify,
        "proxy": settings.proxy_url,
        "trust_env": False,
        "follow_redirects": False,
    }
    if transport is not None:
        client_options["transport"] = transport
    return _remember_sync_client(httpx.Client(**client_options), settings)


def create_async_client(
    *,
    timeout: TimeoutValue,
    verify: VerifyValue = True,
    transport: httpx.AsyncBaseTransport | None = None,
    purpose: str,
) -> httpx.AsyncClient:
    """Construct the async equivalent of :func:`create_sync_client`."""

    del purpose
    settings = _load_settings()
    _validate_client_options(settings, verify=verify, transport=transport)
    client_options: dict[str, Any] = {
        "timeout": timeout,
        "verify": verify,
        "proxy": settings.proxy_url,
        "trust_env": False,
        "follow_redirects": False,
    }
    if transport is not None:
        client_options["transport"] = transport
    return _remember_async_client(httpx.AsyncClient(**client_options), settings)


def classify_outbound_http_failure(error: BaseException) -> str:
    """Return a stable category without formatting attacker-controlled details."""

    if isinstance(error, OutboundHTTPConfigurationError):
        return "outbound_configuration"
    if isinstance(error, httpx.TimeoutException):
        return "timeout"
    if isinstance(error, httpx.ProxyError):
        return "proxy_failed"
    if isinstance(error, httpx.ConnectError):
        return "connection_failed"
    if isinstance(error, httpx.HTTPStatusError):
        return "upstream_http_error"
    if isinstance(error, httpx.TransportError):
        return "transport_failed"
    return "unexpected_error"
