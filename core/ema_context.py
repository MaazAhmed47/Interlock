"""Server-owned authority context for v4 audit records.

Only the authenticated EMA route may populate this context.  Request bodies
and arbitrary headers are never projected into it.
"""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any, Iterator, Mapping, Optional

_authority_audit_context: ContextVar[Optional[dict[str, Any]]] = ContextVar(
    "interlock_authority_audit_context",
    default=None,
)
_authority_call_id: ContextVar[Optional[str]] = ContextVar(
    "interlock_authority_call_id",
    default=None,
)
_downstream_boundary: ContextVar[Optional[tuple[Optional[str], str]]] = ContextVar(
    "interlock_authority_downstream_boundary", default=None
)


def current_authority_audit_context() -> Optional[dict[str, Any]]:
    value = _authority_audit_context.get()
    return dict(value) if value is not None else None


def current_authority_call_id() -> Optional[str]:
    return _authority_call_id.get()


def mark_authority_downstream_attempt() -> None:
    """Commit the configured downstream identity only at the forward boundary."""
    context = _authority_audit_context.get()
    boundary = _downstream_boundary.get()
    if context is None or boundary is None:
        return
    principal_id, auth_mode = boundary
    updated = dict(context)
    updated["downstream_service_principal_id"] = principal_id
    updated["downstream_auth_mode"] = auth_mode
    _authority_audit_context.set(updated)


@contextmanager
def authority_audit_scope(
    context: Mapping[str, Any],
    *,
    call_id: Optional[str] = None,
    downstream_service_principal_id: Optional[str] = None,
    downstream_auth_mode: str = "none",
) -> Iterator[None]:
    """Install a bounded server-created context for one gateway operation."""
    token = _authority_audit_context.set(dict(context))
    call_token = _authority_call_id.set(call_id)
    downstream_token = _downstream_boundary.set(
        (downstream_service_principal_id, downstream_auth_mode)
    )
    try:
        yield
    finally:
        _downstream_boundary.reset(downstream_token)
        _authority_call_id.reset(call_token)
        _authority_audit_context.reset(token)
