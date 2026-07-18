"""Bounded access-token validation for Interlock's experimental EMA profile."""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import hmac
import json
import re
import struct
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Callable, Optional

import httpx
import jwt
from jwt.algorithms import RSAAlgorithm

from core.ema_config import EMASettings, HMACKeyRing

_BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]*$")
_KID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_PROHIBITED_KEY_HEADERS = frozenset({"jku", "x5u", "jwk"})


class EMAAuthError(Exception):
    """A bounded authorization failure that never includes credential data."""

    def __init__(self, code: str, *, status_code: int = 401):
        super().__init__(code)
        self.code = code
        self.status_code = status_code


@dataclass(frozen=True)
class VerifiedAuthority:
    """Verified signed claims, retained only for the current request."""

    issuer: str
    audiences: tuple[str, ...]
    resource: str
    client_id: str
    subject: str
    scopes: tuple[str, ...]
    expires_at: int
    not_before: Optional[int]
    issued_at: Optional[int]
    verified_at: int


@dataclass(frozen=True)
class HMACBinding:
    algorithm: str
    key_id: str
    value: str


def extract_bearer_token(authorization: Optional[str], settings: EMASettings) -> str:
    """Accept exactly one case-sensitive Bearer credential within the size bound."""
    if authorization is None or authorization == "":
        raise EMAAuthError("missing_authorization")
    try:
        encoded = authorization.encode("ascii")
    except UnicodeEncodeError as exc:
        raise EMAAuthError("invalid_authorization") from exc
    if len(encoded) > settings.authorization_header_max_bytes:
        raise EMAAuthError("authorization_too_large")
    if (
        not authorization.startswith("Bearer ")
        or authorization.count(" ") != 1
        or "," in authorization
    ):
        raise EMAAuthError("invalid_authorization")
    token = authorization[len("Bearer ") :]
    if not token or any(char.isspace() for char in token):
        raise EMAAuthError("invalid_authorization")
    return token


def _decode_segment(segment: str, maximum: int) -> bytes:
    if len(segment.encode("ascii", errors="ignore")) > maximum:
        raise EMAAuthError("token_too_large")
    if not _BASE64URL_RE.fullmatch(segment):
        raise EMAAuthError("invalid_token")
    try:
        return base64.urlsafe_b64decode(segment + ("=" * (-len(segment) % 4)))
    except (ValueError, binascii.Error) as exc:
        raise EMAAuthError("invalid_token") from exc


def _bounded_unverified_header(token: str, settings: EMASettings) -> dict[str, Any]:
    try:
        token_bytes = token.encode("ascii")
    except UnicodeEncodeError as exc:
        raise EMAAuthError("invalid_token") from exc
    if len(token_bytes) > settings.compact_jwt_max_bytes:
        raise EMAAuthError("token_too_large")
    segments = token.split(".")
    if len(segments) != 3:
        raise EMAAuthError("invalid_token")
    encoded_limits = (
        settings.jwt_header_segment_max_bytes,
        settings.jwt_payload_segment_max_bytes,
        settings.jwt_signature_segment_max_bytes,
    )
    decoded = [
        _decode_segment(segment, limit)
        for segment, limit in zip(segments, encoded_limits)
    ]
    if len(decoded[0]) > settings.decoded_jose_header_max_bytes:
        raise EMAAuthError("token_too_large")
    if len(decoded[1]) > settings.decoded_claims_max_bytes:
        raise EMAAuthError("token_too_large")
    try:
        header = json.loads(decoded[0])
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise EMAAuthError("invalid_token") from exc
    if not isinstance(header, dict):
        raise EMAAuthError("invalid_token")
    return header


class TrustedJWKSCache:
    """One bounded static JWKS cache with single-flight unknown-kid refresh."""

    def __init__(
        self,
        settings: EMASettings,
        *,
        transport: Optional[httpx.AsyncBaseTransport] = None,
        monotonic: Callable[[], float] = time.monotonic,
    ):
        self.settings = settings
        self._transport = transport
        self._monotonic = monotonic
        self._keys: dict[str, Any] = {}
        self._negative: OrderedDict[str, float] = OrderedDict()
        self._refresh_lock = asyncio.Lock()
        self._last_refresh_attempt = float("-inf")

    @property
    def negative_cache_size(self) -> int:
        return len(self._negative)

    def _negative_hit(self, kid: str, now: float) -> bool:
        expiry = self._negative.get(kid)
        if expiry is None:
            return False
        if expiry <= now:
            self._negative.pop(kid, None)
            return False
        self._negative.move_to_end(kid)
        return True

    def _remember_negative(self, kid: str, now: float) -> None:
        self._negative[kid] = now + self.settings.jwks_negative_cache_ttl_seconds
        self._negative.move_to_end(kid)
        while len(self._negative) > self.settings.jwks_negative_cache_max_entries:
            self._negative.popitem(last=False)

    async def get_key(self, kid: str):
        key = self._keys.get(kid)
        if key is not None:
            return key
        now = self._monotonic()
        if self._negative_hit(kid, now):
            raise EMAAuthError("unknown_kid")

        async with self._refresh_lock:
            key = self._keys.get(kid)
            if key is not None:
                return key
            now = self._monotonic()
            if self._negative_hit(kid, now):
                raise EMAAuthError("unknown_kid")
            if (
                now - self._last_refresh_attempt
                >= self.settings.jwks_refresh_cooldown_seconds
            ):
                self._last_refresh_attempt = now
                await self._refresh()
                key = self._keys.get(kid)
                if key is not None:
                    return key
            self._remember_negative(kid, now)
            raise EMAAuthError("unknown_kid")

    async def _refresh(self) -> None:
        timeout = httpx.Timeout(
            connect=self.settings.jwks_connect_timeout_seconds,
            read=self.settings.jwks_read_timeout_seconds,
            write=self.settings.jwks_connect_timeout_seconds,
            pool=self.settings.jwks_connect_timeout_seconds,
        )
        try:
            async with httpx.AsyncClient(
                transport=self._transport,
                timeout=timeout,
                follow_redirects=False,
            ) as client:
                body = await asyncio.wait_for(
                    self._read_jwks_response(client),
                    timeout=self.settings.jwks_total_timeout_seconds,
                )
            document = json.loads(body)
            keys = self._parse_document(document)
        except EMAAuthError:
            raise
        except (
            asyncio.TimeoutError,
            httpx.HTTPError,
            json.JSONDecodeError,
            UnicodeDecodeError,
            TypeError,
            ValueError,
        ) as exc:
            raise EMAAuthError("jwks_unavailable") from exc
        self._keys = keys
        for key_id in list(self._negative):
            if key_id in keys:
                self._negative.pop(key_id, None)

    async def _read_jwks_response(self, client: httpx.AsyncClient) -> bytes:
        async with client.stream(
            "GET",
            self.settings.jwks_uri,
            headers={"Accept": "application/json"},
        ) as response:
            if response.is_redirect or response.status_code != 200:
                raise EMAAuthError("jwks_unavailable")
            content_length = response.headers.get("content-length")
            if content_length:
                try:
                    if int(content_length) > self.settings.jwks_document_max_bytes:
                        raise EMAAuthError("jwks_unavailable")
                except ValueError as exc:
                    raise EMAAuthError("jwks_unavailable") from exc
            chunks = bytearray()
            async for chunk in response.aiter_bytes():
                chunks.extend(chunk)
                if len(chunks) > self.settings.jwks_document_max_bytes:
                    raise EMAAuthError("jwks_unavailable")
            return bytes(chunks)

    def _parse_document(self, document: Any) -> dict[str, Any]:
        if not isinstance(document, dict) or not isinstance(document.get("keys"), list):
            raise EMAAuthError("jwks_unavailable")
        entries = document["keys"]
        if len(entries) > self.settings.jwks_key_count_max:
            raise EMAAuthError("jwks_unavailable")
        parsed: dict[str, Any] = {}
        for entry in entries:
            if not isinstance(entry, dict):
                raise EMAAuthError("jwks_unavailable")
            encoded = json.dumps(
                entry,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("utf-8")
            if len(encoded) > self.settings.jwk_max_bytes:
                raise EMAAuthError("jwks_unavailable")
            if any(name in entry for name in _PROHIBITED_KEY_HEADERS):
                raise EMAAuthError("jwks_unavailable")
            kid = entry.get("kid")
            if not isinstance(kid, str) or not _KID_RE.fullmatch(kid):
                raise EMAAuthError("jwks_unavailable")
            if (
                entry.get("kty") != "RSA"
                or entry.get("alg") not in (None, "RS256")
                or entry.get("use") not in (None, "sig")
                or kid in parsed
            ):
                raise EMAAuthError("jwks_unavailable")
            try:
                parsed[kid] = RSAAlgorithm.from_jwk(entry)
            except (ValueError, TypeError) as exc:
                raise EMAAuthError("jwks_unavailable") from exc
        return parsed


class EMAAccessTokenValidator:
    """Validate only interlock-experimental-ema-jwt-at-v1 access tokens."""

    def __init__(
        self,
        settings: EMASettings,
        *,
        cache: Optional[TrustedJWKSCache] = None,
        epoch_time: Callable[[], float] = time.time,
    ):
        self.settings = settings
        self.cache = cache or TrustedJWKSCache(settings)
        self._epoch_time = epoch_time

    async def validate_token(self, token: str) -> VerifiedAuthority:
        header = _bounded_unverified_header(token, self.settings)
        if any(name in header for name in _PROHIBITED_KEY_HEADERS):
            raise EMAAuthError("prohibited_key_reference")
        if "crit" in header:
            raise EMAAuthError("unsupported_critical_header")
        if header.get("alg") != "RS256":
            raise EMAAuthError("invalid_algorithm")
        if header.get("typ") != "at+jwt":
            raise EMAAuthError("invalid_typ")
        kid = header.get("kid")
        if not isinstance(kid, str) or not _KID_RE.fullmatch(kid):
            raise EMAAuthError("invalid_kid")

        key = await self.cache.get_key(kid)
        try:
            claims = jwt.decode(
                token,
                key=key,
                algorithms=["RS256"],
                options={
                    "verify_aud": False,
                    "verify_iss": False,
                    "verify_exp": False,
                    "verify_nbf": False,
                    "verify_iat": False,
                    "verify_sub": False,
                    "require": [],
                },
            )
        except jwt.InvalidSignatureError as exc:
            raise EMAAuthError("invalid_signature") from exc
        except jwt.PyJWTError as exc:
            raise EMAAuthError("invalid_token") from exc
        if not isinstance(claims, dict):
            raise EMAAuthError("invalid_token")
        return self._validate_claims(claims)

    def _validate_claims(self, claims: dict[str, Any]) -> VerifiedAuthority:
        required: tuple[str, ...] = (
            "iss",
            "aud",
            "resource",
            "exp",
            "client_id",
            "scope",
            "sub",
        )
        if self.settings.require_nbf:
            required += ("nbf",)
        if self.settings.require_iat:
            required += ("iat",)
        if any(name not in claims for name in required):
            raise EMAAuthError("missing_claim")

        issuer = claims.get("iss")
        if not isinstance(issuer, str) or issuer != self.settings.issuer:
            raise EMAAuthError("invalid_issuer")

        raw_audience = claims.get("aud")
        if isinstance(raw_audience, str):
            audiences = (raw_audience,)
        elif (
            isinstance(raw_audience, list)
            and raw_audience
            and all(isinstance(value, str) and value for value in raw_audience)
        ):
            audiences = tuple(sorted(set(raw_audience)))
        else:
            raise EMAAuthError("invalid_audience")
        if self.settings.resource_uri not in audiences:
            raise EMAAuthError("invalid_audience")

        resource = claims.get("resource")
        if not isinstance(resource, str) or resource != self.settings.resource_uri:
            raise EMAAuthError("invalid_resource")

        now = int(self._epoch_time())
        expires_at = _integer_claim(claims.get("exp"), "invalid_expiry")
        if now >= expires_at + self.settings.clock_skew_seconds:
            raise EMAAuthError("token_expired")

        client_id = claims.get("client_id")
        if not isinstance(client_id, str) or not client_id:
            raise EMAAuthError("invalid_client")
        if client_id not in self.settings.allowed_client_ids:
            raise EMAAuthError("client_unmapped")

        raw_scope = claims.get("scope")
        if not isinstance(raw_scope, str) or not raw_scope:
            raise EMAAuthError("invalid_scope")
        scopes = raw_scope.split(" ")
        if any(
            not scope or scope == "*" or any(char.isspace() for char in scope)
            for scope in scopes
        ):
            raise EMAAuthError("invalid_scope")
        normalized_scopes = tuple(sorted(set(scopes)))

        subject = claims.get("sub")
        if not isinstance(subject, str) or not subject:
            raise EMAAuthError("invalid_subject")

        not_before = _optional_integer_claim(claims, "nbf", "invalid_nbf")
        if (
            not_before is not None
            and not_before > now + self.settings.clock_skew_seconds
        ):
            raise EMAAuthError("token_not_yet_valid")

        issued_at = _optional_integer_claim(claims, "iat", "invalid_iat")
        if issued_at is not None and issued_at > now + self.settings.clock_skew_seconds:
            raise EMAAuthError("invalid_iat")
        if (
            self.settings.max_token_age_seconds is not None
            and issued_at is not None
            and now - issued_at > self.settings.max_token_age_seconds
        ):
            raise EMAAuthError("token_too_old")

        return VerifiedAuthority(
            issuer=issuer,
            audiences=audiences,
            resource=resource,
            client_id=client_id,
            subject=subject,
            scopes=normalized_scopes,
            expires_at=expires_at,
            not_before=not_before,
            issued_at=issued_at,
            verified_at=now,
        )


def _integer_claim(value: Any, error_code: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise EMAAuthError(error_code)
    return value


def _optional_integer_claim(
    claims: dict[str, Any], name: str, error_code: str
) -> Optional[int]:
    if name not in claims:
        return None
    return _integer_claim(claims.get(name), error_code)


def _length_prefix(value: bytes) -> bytes:
    return struct.pack(">Q", len(value)) + value


def _binding(
    ring: HMACKeyRing,
    domain: str,
    parts: tuple[bytes, ...],
    *,
    key_id: Optional[str] = None,
) -> HMACBinding:
    selected = key_id or ring.active_key_id
    message = b"".join(
        _length_prefix(value) for value in (domain.encode("ascii"), *parts)
    )
    digest = hmac.new(ring.key(selected), message, hashlib.sha256).digest()
    encoded = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return HMACBinding(
        algorithm=ring.algorithm,
        key_id=selected,
        value=encoded,
    )


def bind_oauth_client(
    settings: EMASettings, issuer: str, client_id: str, *, key_id: Optional[str] = None
) -> HMACBinding:
    return _binding(
        settings.oauth_client_keys,
        "interlock/ema/oauth-client-binding/v1",
        (issuer.encode("utf-8"), client_id.encode("utf-8")),
        key_id=key_id,
    )


def bind_delegated_subject(
    settings: EMASettings, issuer: str, subject: str, *, key_id: Optional[str] = None
) -> HMACBinding:
    return _binding(
        settings.delegated_subject_keys,
        "interlock/ema/delegated-subject-binding/v1",
        (issuer.encode("utf-8"), subject.encode("utf-8")),
        key_id=key_id,
    )


def bind_access_token(
    settings: EMASettings,
    token: str,
    call_id: str,
    *,
    key_id: Optional[str] = None,
) -> HMACBinding:
    return _binding(
        settings.token_keys,
        "interlock/ema/token-binding/v1",
        (
            settings.resource_uri.encode("utf-8"),
            settings.interlock_service_principal_id.encode("utf-8"),
            call_id.encode("utf-8"),
            token.encode("ascii"),
        ),
        key_id=key_id,
    )


def bindings_equal(left: HMACBinding, right: HMACBinding) -> bool:
    return (
        left.algorithm == right.algorithm
        and left.key_id == right.key_id
        and hmac.compare_digest(left.value, right.value)
    )
