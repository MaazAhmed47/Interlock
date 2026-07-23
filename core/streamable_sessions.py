"""Bounded, expiring lifecycle sessions for MCP Streamable HTTP."""

from __future__ import annotations

import re
import secrets
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, replace
from typing import Callable, Optional

from config import streamable_mcp_max_sessions, streamable_mcp_session_ttl_seconds

_SESSION_ID = re.compile(r"^[A-Za-z0-9_-]{32,128}$")


@dataclass(frozen=True)
class StreamableSession:
    """Safe lifecycle state; never contains credentials or customer payloads."""

    session_id: str
    principal_binding: str
    server_id: str
    created_at: float
    expires_at: float
    initialized: bool = False


class StreamableSessionStore:
    """Process-local fail-closed sessions with TTL and a hard size bound."""

    def __init__(self, *, monotonic: Callable[[], float] = time.monotonic):
        self._monotonic = monotonic
        self._sessions: OrderedDict[str, StreamableSession] = OrderedDict()
        self._lock = threading.Lock()

    def create(self, principal_binding: str, server_id: str) -> StreamableSession:
        now = self._monotonic()
        session = StreamableSession(
            session_id=secrets.token_urlsafe(32),
            principal_binding=principal_binding,
            server_id=server_id,
            created_at=now,
            expires_at=now + streamable_mcp_session_ttl_seconds(),
        )
        with self._lock:
            self._remove_expired_locked(now)
            maximum = streamable_mcp_max_sessions()
            while len(self._sessions) >= maximum:
                self._sessions.popitem(last=False)
            while session.session_id in self._sessions:
                session = replace(session, session_id=secrets.token_urlsafe(32))
            self._sessions[session.session_id] = session
        return session

    def authorize(
        self,
        session_id: str,
        principal_binding: str,
        server_id: str,
        *,
        require_initialized: bool,
    ) -> Optional[StreamableSession]:
        if not _SESSION_ID.fullmatch(session_id):
            return None
        now = self._monotonic()
        with self._lock:
            self._remove_expired_locked(now)
            session = self._sessions.get(session_id)
            if session is None:
                return None
            if (
                not secrets.compare_digest(session.principal_binding, principal_binding)
                or not secrets.compare_digest(session.server_id, server_id)
                or (require_initialized and not session.initialized)
            ):
                return None
            return session

    def mark_initialized(
        self, session_id: str, principal_binding: str, server_id: str
    ) -> bool:
        if not _SESSION_ID.fullmatch(session_id):
            return False
        now = self._monotonic()
        with self._lock:
            self._remove_expired_locked(now)
            session = self._sessions.get(session_id)
            if (
                session is None
                or session.initialized
                or not secrets.compare_digest(
                    session.principal_binding, principal_binding
                )
                or not secrets.compare_digest(session.server_id, server_id)
            ):
                return False
            self._sessions[session_id] = replace(session, initialized=True)
        return True

    def _remove_expired_locked(self, now: float) -> None:
        expired = [
            session_id
            for session_id, session in self._sessions.items()
            if session.expires_at <= now
        ]
        for session_id in expired:
            self._sessions.pop(session_id, None)


session_store = StreamableSessionStore()
