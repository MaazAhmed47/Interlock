"""
Bounded request-body reading.

Extracted from the Streamable HTTP transport so every route that must refuse
an oversized body uses one implementation. Both the declared
``Content-Length`` and the actually-streamed bytes are checked: a chunked
request carries no declared length, and a declared length can lie.
"""

from __future__ import annotations

from typing import Optional, Tuple

from starlette.requests import Request

# Why a caller sees no body.
MALFORMED = "malformed"
TOO_LARGE = "too_large"


def declared_length_error(request: Request, max_bytes: int) -> Optional[str]:
    """Screen the declared Content-Length before reading a single byte."""
    content_lengths = [
        value
        for name, value in request.scope.get("headers", [])
        if name.lower() == b"content-length"
    ]
    if len(content_lengths) > 1:
        return MALFORMED
    if not content_lengths:
        return None
    try:
        raw_length = content_lengths[0].decode("ascii")
    except UnicodeDecodeError:
        return MALFORMED
    if not raw_length.isdigit():
        return MALFORMED
    # String compare avoids materializing an attacker-supplied huge integer.
    normalized = raw_length.lstrip("0") or "0"
    maximum = str(int(max_bytes))
    if len(normalized) > len(maximum) or (
        len(normalized) == len(maximum) and normalized > maximum
    ):
        return TOO_LARGE
    return None


async def read_bounded_body(
    request: Request, max_bytes: int
) -> Tuple[Optional[bytes], Optional[str]]:
    """Return ``(body, error)``. ``error`` is MALFORMED or TOO_LARGE, else None.

    Bounds the declared length first, then the streamed bytes, so neither a
    lying Content-Length nor a chunked body can exceed the budget.
    """
    error = declared_length_error(request, max_bytes)
    if error is not None:
        return None, error

    body = bytearray()
    async for chunk in request.stream():
        if len(chunk) > int(max_bytes) - len(body):
            return None, TOO_LARGE
        body.extend(chunk)
    return bytes(body), None


async def discard_bounded_body(request: Request, max_bytes: int) -> Optional[str]:
    """Drain and drop a body the route does not use, refusing oversized ones.

    The bytes are never retained, so a request body cannot influence the
    server, baseline, reviewer, decision, or evidence — it is only bounded so
    it cannot be used to push volume through an authenticated endpoint.
    """
    _, error = await read_bounded_body(request, max_bytes)
    return error
