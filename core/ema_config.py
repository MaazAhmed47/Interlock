"""Strict deployment configuration for the experimental EMA resource server."""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping, Optional
from urllib.parse import urlsplit

from config import experimental_ema_raw_config

EXPERIMENTAL_EMA_PROFILE = "interlock-experimental-ema-jwt-at-v1"
SUPPORTED_PROTOCOL_VERSION = "2025-11-25"
HMAC_ALGORITHM_V1 = "hmac-sha256-v1"

_KEY_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_TOOL_NAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
_RESOURCE_HOST_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
_ROLES = {
    "support_agent",
    "devops_agent",
    "finance_agent",
    "readonly_agent",
    "data_analyst",
    "admin_agent",
}


class EMAConfigError(RuntimeError):
    """The experimental endpoint was enabled without a safe complete profile."""


@dataclass(frozen=True)
class HMACKeyRing:
    """One independently versioned HMAC key ring."""

    purpose: str
    algorithm: str
    active_key_id: str
    keys: Mapping[str, bytes]

    def key(self, key_id: str) -> bytes:
        try:
            return self.keys[key_id]
        except KeyError as exc:
            raise EMAConfigError(f"Unknown retired key ID for {self.purpose}.") from exc


@dataclass(frozen=True)
class EMASettings:
    """Validated immutable settings for one deployment-level EMA endpoint."""

    profile: str
    allowed_algorithms: tuple[str, ...]
    protocol_version: str
    resource_uri: str
    resource_path: str
    protected_resource_metadata_path: str
    issuer: str
    jwks_uri: str
    server_id: str
    interlock_service_principal_id: str
    downstream_service_principal_id: Optional[str]
    role: str
    allowed_client_ids: frozenset[str]
    tool_scopes: Mapping[tuple[str, str], frozenset[str]]
    allowed_origins: frozenset[str]
    oauth_client_keys: HMACKeyRing
    delegated_subject_keys: HMACKeyRing
    token_keys: HMACKeyRing
    require_nbf: bool
    require_iat: bool
    max_token_age_seconds: Optional[int]
    session_lifetime_seconds: int
    clock_skew_seconds: int
    authorization_header_max_bytes: int
    compact_jwt_max_bytes: int
    jwt_header_segment_max_bytes: int
    jwt_payload_segment_max_bytes: int
    jwt_signature_segment_max_bytes: int
    decoded_jose_header_max_bytes: int
    decoded_claims_max_bytes: int
    jwks_document_max_bytes: int
    jwks_key_count_max: int
    jwk_max_bytes: int
    jwks_refresh_cooldown_seconds: int
    jwks_negative_cache_ttl_seconds: int
    jwks_negative_cache_max_entries: int
    jwks_connect_timeout_seconds: float
    jwks_read_timeout_seconds: float
    jwks_total_timeout_seconds: float


def _truthy(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _required(raw: Mapping[str, str], name: str) -> str:
    value = str(raw.get(name) or "").strip()
    if not value:
        raise EMAConfigError(f"{name} is required when experimental EMA is enabled.")
    return value


def _json(raw: Mapping[str, str], name: str):
    text = _required(raw, name)
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError) as exc:
        raise EMAConfigError(f"{name} must be valid JSON.") from exc


def _https_uri(value: str, name: str, *, require_path: bool = False) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or (require_path and parsed.path in {"", "/"})
    ):
        raise EMAConfigError(
            f"{name} must be an exact HTTPS URI without credentials, query, or fragment."
        )
    return value


def _canonical_resource_uri(value: str) -> str:
    value = _https_uri(value, "INTERLOCK_EMA_RESOURCE_URI", require_path=True)
    try:
        value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise EMAConfigError(
            "INTERLOCK_EMA_RESOURCE_URI must use an ASCII canonical host and path."
        ) from exc
    parsed = urlsplit(value)
    host = parsed.hostname or ""
    try:
        port = parsed.port
    except ValueError as exc:
        raise EMAConfigError("INTERLOCK_EMA_RESOURCE_URI has an invalid port.") from exc
    path = parsed.path
    segments = path.split("/")
    if (
        not _RESOURCE_HOST_RE.fullmatch(host)
        or port == 443
        or "%" in path
        or "\\" in path
        or "//" in path
        or any(segment in {".", ".."} for segment in segments)
        or any(ord(character) < 0x21 for character in path)
    ):
        raise EMAConfigError(
            "INTERLOCK_EMA_RESOURCE_URI must be a normalized canonical HTTPS URI."
        )
    authority = host if port is None else f"{host}:{port}"
    canonical = f"https://{authority}{path}"
    if value != canonical:
        raise EMAConfigError(
            "INTERLOCK_EMA_RESOURCE_URI must be supplied in canonical form."
        )
    return canonical


def _parse_ring(raw: Mapping[str, str], name: str, purpose: str) -> HMACKeyRing:
    value = _json(raw, name)
    if not isinstance(value, dict):
        raise EMAConfigError(f"{name} must be a JSON object.")
    active_key_id = str(value.get("active_key_id") or "")
    keys = value.get("keys")
    if not _KEY_ID_RE.fullmatch(active_key_id) or not isinstance(keys, dict):
        raise EMAConfigError(f"{name} has an invalid active key ID or key map.")
    decoded: dict[str, bytes] = {}
    for key_id, encoded in keys.items():
        if not isinstance(key_id, str) or not _KEY_ID_RE.fullmatch(key_id):
            raise EMAConfigError(f"{name} contains an invalid key ID.")
        if not isinstance(encoded, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", encoded):
            raise EMAConfigError(f"{name} contains invalid base64url key material.")
        try:
            padding = "=" * (-len(encoded) % 4)
            key_bytes = base64.urlsafe_b64decode(encoded + padding)
        except (ValueError, TypeError) as exc:
            raise EMAConfigError(f"{name} contains invalid key material.") from exc
        if len(key_bytes) < 32:
            raise EMAConfigError(f"{name} keys must contain at least 256 random bits.")
        decoded[key_id] = key_bytes
    if active_key_id not in decoded:
        raise EMAConfigError(f"{name} active key ID is not present in keys.")
    return HMACKeyRing(
        purpose=purpose,
        algorithm=HMAC_ALGORITHM_V1,
        active_key_id=active_key_id,
        keys=MappingProxyType(decoded),
    )


def _parse_allowed_clients(raw: Mapping[str, str]) -> frozenset[str]:
    value = _json(raw, "INTERLOCK_EMA_ALLOWED_CLIENT_IDS")
    if not isinstance(value, list) or not value:
        raise EMAConfigError(
            "INTERLOCK_EMA_ALLOWED_CLIENT_IDS must be a non-empty JSON list."
        )
    clients = []
    for candidate in value:
        if (
            not isinstance(candidate, str)
            or not candidate.strip()
            or candidate.strip() == "*"
        ):
            raise EMAConfigError(
                "OAuth client IDs must be explicit non-wildcard strings."
            )
        clients.append(candidate.strip())
    if len(set(clients)) != len(clients):
        raise EMAConfigError("OAuth client IDs must not contain duplicates.")
    return frozenset(clients)


def _parse_tool_scopes(
    raw: Mapping[str, str], server_id: str
) -> Mapping[tuple[str, str], frozenset[str]]:
    value = _json(raw, "INTERLOCK_EMA_TOOL_SCOPES")
    if not isinstance(value, dict) or set(value) != {server_id}:
        raise EMAConfigError(
            "Tool scopes must contain exactly the configured MCP server ID."
        )
    server_map = value.get(server_id)
    if not isinstance(server_map, dict) or not server_map:
        raise EMAConfigError("The configured MCP server needs explicit tool scopes.")
    result: dict[tuple[str, str], frozenset[str]] = {}
    for tool_name, required_scopes in server_map.items():
        if (
            not isinstance(tool_name, str)
            or tool_name == "*"
            or not _TOOL_NAME_RE.fullmatch(tool_name)
        ):
            raise EMAConfigError("Tool mappings require exact valid MCP tool names.")
        if not isinstance(required_scopes, list) or not required_scopes:
            raise EMAConfigError(f"Tool '{tool_name}' needs at least one exact scope.")
        normalized = []
        for scope in required_scopes:
            if (
                not isinstance(scope, str)
                or not scope
                or scope == "*"
                or any(char.isspace() or ord(char) < 0x21 for char in scope)
            ):
                raise EMAConfigError("Scopes must be explicit non-wildcard tokens.")
            normalized.append(scope)
        if len(set(normalized)) != len(normalized):
            raise EMAConfigError(f"Tool '{tool_name}' has duplicate scopes.")
        result[(server_id, tool_name)] = frozenset(normalized)
    return MappingProxyType(result)


def _parse_origins(raw: Mapping[str, str]) -> frozenset[str]:
    text = str(raw.get("INTERLOCK_EMA_ALLOWED_ORIGINS") or "").strip()
    if not text:
        return frozenset()
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise EMAConfigError(
            "INTERLOCK_EMA_ALLOWED_ORIGINS must be valid JSON."
        ) from exc
    if not isinstance(value, list):
        raise EMAConfigError("INTERLOCK_EMA_ALLOWED_ORIGINS must be a JSON list.")
    origins = []
    for origin in value:
        if not isinstance(origin, str) or origin == "*":
            raise EMAConfigError("EMA origins must be explicit HTTPS origins.")
        parsed = urlsplit(origin)
        if (
            parsed.scheme != "https"
            or not parsed.netloc
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise EMAConfigError("EMA origins must be exact HTTPS origins.")
        origins.append(origin.rstrip("/"))
    return frozenset(origins)


def _bounded_int(
    raw: Mapping[str, str],
    name: str,
    default: int,
    *,
    minimum: int,
    maximum: int,
) -> int:
    text = str(raw.get(name) or "").strip()
    try:
        value = int(text) if text else default
    except ValueError as exc:
        raise EMAConfigError(f"{name} must be an integer.") from exc
    if value < minimum or value > maximum:
        raise EMAConfigError(f"{name} must be between {minimum} and {maximum}.")
    return value


def load_experimental_ema_settings(
    raw: Optional[Mapping[str, str]] = None,
) -> Optional[EMASettings]:
    """Load one complete profile or return None when the experiment is disabled."""
    values = dict(experimental_ema_raw_config() if raw is None else raw)
    if not _truthy(str(values.get("INTERLOCK_EXPERIMENTAL_EMA_ENABLED") or "")):
        return None

    resource_uri = _canonical_resource_uri(
        _required(values, "INTERLOCK_EMA_RESOURCE_URI")
    )
    parsed_resource = urlsplit(resource_uri)
    resource_path = parsed_resource.path or "/"
    if not resource_path.startswith("/"):
        raise EMAConfigError("The resource URI must contain an absolute path.")
    metadata_path = "/.well-known/oauth-protected-resource"
    if resource_path != "/":
        metadata_path += resource_path

    issuer_metadata = _json(values, "INTERLOCK_EMA_ISSUER_METADATA")
    if not isinstance(issuer_metadata, dict):
        raise EMAConfigError("INTERLOCK_EMA_ISSUER_METADATA must be a JSON object.")
    issuer = _https_uri(
        str(issuer_metadata.get("issuer") or ""),
        "issuer metadata issuer",
    )
    jwks_uri = _https_uri(
        str(issuer_metadata.get("jwks_uri") or ""),
        "issuer metadata jwks_uri",
        require_path=True,
    )

    server_id = _required(values, "INTERLOCK_EMA_SERVER_ID")
    if server_id == "*" or not _TOOL_NAME_RE.fullmatch(server_id):
        raise EMAConfigError("INTERLOCK_EMA_SERVER_ID must be one exact server ID.")
    service_principal = _required(values, "INTERLOCK_EMA_SERVICE_PRINCIPAL_ID")
    downstream_principal = (
        str(values.get("INTERLOCK_EMA_DOWNSTREAM_SERVICE_PRINCIPAL_ID") or "").strip()
        or None
    )
    role = _required(values, "INTERLOCK_EMA_ROLE")
    if role not in _ROLES:
        raise EMAConfigError("INTERLOCK_EMA_ROLE is not a supported local RBAC role.")

    client_keys = _parse_ring(
        values,
        "INTERLOCK_EMA_OAUTH_CLIENT_HMAC_KEYS",
        "oauth_client_binding",
    )
    subject_keys = _parse_ring(
        values,
        "INTERLOCK_EMA_DELEGATED_SUBJECT_HMAC_KEYS",
        "delegated_subject_binding",
    )
    token_keys = _parse_ring(
        values,
        "INTERLOCK_EMA_TOKEN_HMAC_KEYS",
        "token_binding",
    )
    key_material = [
        *client_keys.keys.values(),
        *subject_keys.keys.values(),
        *token_keys.keys.values(),
    ]
    if len(key_material) != len(set(key_material)):
        raise EMAConfigError("HMAC key material must not be reused across key rings.")

    max_token_age_text = str(
        values.get("INTERLOCK_EMA_MAX_TOKEN_AGE_SECONDS") or ""
    ).strip()
    max_token_age = None
    if max_token_age_text:
        max_token_age = _bounded_int(
            values,
            "INTERLOCK_EMA_MAX_TOKEN_AGE_SECONDS",
            0,
            minimum=1,
            maximum=86_400,
        )
    require_iat = _truthy(str(values.get("INTERLOCK_EMA_REQUIRE_IAT") or ""))
    if max_token_age is not None:
        require_iat = True

    return EMASettings(
        profile=EXPERIMENTAL_EMA_PROFILE,
        allowed_algorithms=("RS256",),
        protocol_version=SUPPORTED_PROTOCOL_VERSION,
        resource_uri=resource_uri,
        resource_path=resource_path,
        protected_resource_metadata_path=metadata_path,
        issuer=issuer,
        jwks_uri=jwks_uri,
        server_id=server_id,
        interlock_service_principal_id=service_principal,
        downstream_service_principal_id=downstream_principal,
        role=role,
        allowed_client_ids=_parse_allowed_clients(values),
        tool_scopes=_parse_tool_scopes(values, server_id),
        allowed_origins=_parse_origins(values),
        oauth_client_keys=client_keys,
        delegated_subject_keys=subject_keys,
        token_keys=token_keys,
        require_nbf=_truthy(str(values.get("INTERLOCK_EMA_REQUIRE_NBF") or "")),
        require_iat=require_iat,
        max_token_age_seconds=max_token_age,
        session_lifetime_seconds=_bounded_int(
            values,
            "INTERLOCK_EMA_SESSION_LIFETIME_SECONDS",
            3600,
            minimum=1,
            maximum=86_400,
        ),
        clock_skew_seconds=60,
        authorization_header_max_bytes=16 * 1024,
        compact_jwt_max_bytes=12 * 1024,
        jwt_header_segment_max_bytes=2 * 1024,
        jwt_payload_segment_max_bytes=8 * 1024,
        jwt_signature_segment_max_bytes=2 * 1024,
        decoded_jose_header_max_bytes=1024,
        decoded_claims_max_bytes=6 * 1024,
        jwks_document_max_bytes=256 * 1024,
        jwks_key_count_max=64,
        jwk_max_bytes=8 * 1024,
        jwks_refresh_cooldown_seconds=_bounded_int(
            values,
            "INTERLOCK_EMA_JWKS_REFRESH_COOLDOWN_SECONDS",
            60,
            minimum=1,
            maximum=3600,
        ),
        jwks_negative_cache_ttl_seconds=_bounded_int(
            values,
            "INTERLOCK_EMA_JWKS_NEGATIVE_CACHE_TTL_SECONDS",
            300,
            minimum=1,
            maximum=86_400,
        ),
        jwks_negative_cache_max_entries=_bounded_int(
            values,
            "INTERLOCK_EMA_JWKS_NEGATIVE_CACHE_MAX_ENTRIES",
            1024,
            minimum=1,
            maximum=4096,
        ),
        jwks_connect_timeout_seconds=2.0,
        jwks_read_timeout_seconds=3.0,
        jwks_total_timeout_seconds=5.0,
    )
