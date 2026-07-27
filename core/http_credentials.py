"""Fail-closed API-credential resolution for routes that read raw headers.

FastAPI's ``Header(None)`` silently takes the first value when a header is
sent more than once, so a request carrying two different ``x-api-key``
headers would authenticate as whichever one arrived first. Routes that must
fail closed on ambiguous authentication read the header lists directly and
resolve them through :func:`single_api_credential`.
"""

from __future__ import annotations

from typing import Optional

from starlette.requests import Request


def _bearer_token(value: str) -> Optional[str]:
    """Return the token of exactly one ``Bearer <token>`` header, else None.

    Strict by construction: the value must split into exactly two
    whitespace-separated parts, the first being the Bearer scheme (matched
    case-insensitively, per RFC 7235) and the second a non-empty token with
    no internal whitespace. ``Bearer Bearer <key>``, ``Basic <key>``, a bare
    ``Bearer``, and a token carrying an embedded scheme all fail closed —
    important because the downstream key lookup still strips a legacy
    ``"Bearer "`` prefix and must never be handed a value containing one.
    """
    parts = value.split()
    if len(parts) != 2:
        return None
    scheme, token = parts
    if scheme.lower() != "bearer" or not token:
        return None
    if token.lower() == "bearer" or " " in token:
        return None
    return token


def single_api_credential(request: Request) -> Optional[str]:
    """Return the one unambiguous API-key credential on a request, else None.

    Fails closed on every ambiguous shape: a repeated ``x-api-key``, a
    repeated ``Authorization``, both header families present at once, an
    empty or whitespace-only ``x-api-key``, or an ``Authorization`` that is
    not exactly one non-empty Bearer token.
    """
    api_keys = request.headers.getlist("x-api-key")
    authorizations = request.headers.getlist("authorization")
    if len(api_keys) > 1 or len(authorizations) > 1:
        return None
    if api_keys and authorizations:
        return None
    if api_keys:
        value = api_keys[0].strip()
        return value or None
    if authorizations:
        return _bearer_token(authorizations[0])
    return None
