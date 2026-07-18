"""Opaque identity-bound sessions for the experimental Streamable HTTP endpoint."""

from __future__ import annotations

import asyncio
import secrets
import time
from dataclasses import dataclass, replace
from typing import Any, Callable, Optional

from core.ema_auth import (
    VerifiedAuthority,
    bind_delegated_subject,
    bind_oauth_client,
    bindings_equal,
)
from core.ema_config import EMAConfigError, EMASettings


class EMASessionError(Exception):
    """A bounded session authorization failure."""

    def __init__(self, code: str, *, status_code: int = 404):
        super().__init__(code)
        self.code = code
        self.status_code = status_code


class EMASessionKeyRetirementError(RuntimeError):
    """A key rotation attempted to remove keys still referenced by sessions."""

    def __init__(
        self,
        missing_client_key_ids: set[str],
        missing_subject_key_ids: set[str],
    ):
        super().__init__("identity_binding_key_in_use")
        self.missing_client_key_ids = frozenset(missing_client_key_ids)
        self.missing_subject_key_ids = frozenset(missing_subject_key_ids)


@dataclass(frozen=True)
class EMASession:
    session_id: str
    created_at: float
    expires_at: float
    oauth_client_binding: str
    oauth_client_binding_alg: str
    oauth_client_binding_key_id: str
    delegated_subject_binding: str
    delegated_subject_binding_alg: str
    delegated_subject_binding_key_id: str
    interlock_service_principal_id: str
    server_id: str
    resource_uri: str
    profile: str
    initialized: bool = False

    def to_safe_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "oauth_client_binding": self.oauth_client_binding,
            "oauth_client_binding_alg": self.oauth_client_binding_alg,
            "oauth_client_binding_key_id": self.oauth_client_binding_key_id,
            "delegated_subject_binding": self.delegated_subject_binding,
            "delegated_subject_binding_alg": self.delegated_subject_binding_alg,
            "delegated_subject_binding_key_id": (self.delegated_subject_binding_key_id),
            "interlock_service_principal_id": (self.interlock_service_principal_id),
            "server_id": self.server_id,
            "resource_uri": self.resource_uri,
            "profile": self.profile,
            "initialized": self.initialized,
        }


class EMASessionStore:
    """In-memory fail-closed sessions; unknown replicas return session not found."""

    def __init__(
        self,
        settings: EMASettings,
        *,
        epoch_time: Callable[[], float] = time.time,
    ):
        self.settings = settings
        self._epoch_time = epoch_time
        self._sessions: dict[str, EMASession] = {}
        self._lock = asyncio.Lock()

    async def create(self, authority: VerifiedAuthority) -> EMASession:
        now = self._epoch_time()
        if authority.expires_at <= now:
            raise EMASessionError("token_expired", status_code=401)
        client = bind_oauth_client(
            self.settings,
            authority.issuer,
            authority.client_id,
        )
        subject = bind_delegated_subject(
            self.settings,
            authority.issuer,
            authority.subject,
        )
        session = EMASession(
            session_id=secrets.token_urlsafe(32),
            created_at=now,
            expires_at=now + self.settings.session_lifetime_seconds,
            oauth_client_binding=client.value,
            oauth_client_binding_alg=client.algorithm,
            oauth_client_binding_key_id=client.key_id,
            delegated_subject_binding=subject.value,
            delegated_subject_binding_alg=subject.algorithm,
            delegated_subject_binding_key_id=subject.key_id,
            interlock_service_principal_id=(
                self.settings.interlock_service_principal_id
            ),
            server_id=self.settings.server_id,
            resource_uri=self.settings.resource_uri,
            profile=self.settings.profile,
        )
        async with self._lock:
            self._remove_expired_locked()
            while session.session_id in self._sessions:
                session = replace(session, session_id=secrets.token_urlsafe(32))
            self._sessions[session.session_id] = session
        return session

    async def get(self, session_id: str) -> Optional[EMASession]:
        async with self._lock:
            session = self._sessions.get(session_id)
            if session is not None and session.expires_at <= self._epoch_time():
                self._sessions.pop(session_id, None)
                return None
            return session

    async def authorize(
        self,
        session_id: str,
        authority: VerifiedAuthority,
    ) -> EMASession:
        async with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                raise EMASessionError("session_not_found")
            now = self._epoch_time()
            if session.expires_at <= now:
                self._sessions.pop(session_id, None)
                raise EMASessionError("session_expired")
            if authority.expires_at <= now:
                raise EMASessionError("token_expired", status_code=401)
            if (
                session.interlock_service_principal_id
                != self.settings.interlock_service_principal_id
                or session.server_id != self.settings.server_id
                or session.resource_uri != self.settings.resource_uri
                or session.profile != self.settings.profile
                or authority.resource != session.resource_uri
            ):
                raise EMASessionError("session_context_mismatch", status_code=403)

            try:
                client = bind_oauth_client(
                    self.settings,
                    authority.issuer,
                    authority.client_id,
                    key_id=session.oauth_client_binding_key_id,
                )
                subject = bind_delegated_subject(
                    self.settings,
                    authority.issuer,
                    authority.subject,
                    key_id=session.delegated_subject_binding_key_id,
                )
            except EMAConfigError as exc:
                self._sessions.pop(session_id, None)
                raise EMASessionError(
                    "session_binding_key_retired",
                    status_code=401,
                ) from exc

            if not bindings_equal(
                client,
                _session_client_binding(session),
            ):
                raise EMASessionError("session_client_mismatch", status_code=403)
            if not bindings_equal(
                subject,
                _session_subject_binding(session),
            ):
                raise EMASessionError("session_subject_mismatch", status_code=403)

            active_client = bind_oauth_client(
                self.settings,
                authority.issuer,
                authority.client_id,
            )
            active_subject = bind_delegated_subject(
                self.settings,
                authority.issuer,
                authority.subject,
            )
            if (
                active_client.key_id != session.oauth_client_binding_key_id
                or active_subject.key_id != session.delegated_subject_binding_key_id
            ):
                session = replace(
                    session,
                    oauth_client_binding=active_client.value,
                    oauth_client_binding_alg=active_client.algorithm,
                    oauth_client_binding_key_id=active_client.key_id,
                    delegated_subject_binding=active_subject.value,
                    delegated_subject_binding_alg=active_subject.algorithm,
                    delegated_subject_binding_key_id=active_subject.key_id,
                )
                self._sessions[session_id] = session
            return session

    async def mark_initialized(
        self,
        session_id: str,
        authority: VerifiedAuthority,
    ) -> EMASession:
        await self.authorize(session_id, authority)
        async with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                raise EMASessionError("session_not_found")
            session = replace(session, initialized=True)
            self._sessions[session_id] = session
            return session

    async def terminate(
        self,
        session_id: str,
        authority: VerifiedAuthority,
    ) -> None:
        await self.authorize(session_id, authority)
        async with self._lock:
            self._sessions.pop(session_id, None)

    async def rotate_settings(
        self,
        settings: EMASettings,
        *,
        terminate_referencing_sessions: bool = False,
    ) -> int:
        """Apply new key rings without allowing cross-resource session migration."""
        async with self._lock:
            self._remove_expired_locked()
            if (
                settings.resource_uri != self.settings.resource_uri
                or settings.server_id != self.settings.server_id
                or settings.profile != self.settings.profile
                or settings.interlock_service_principal_id
                != self.settings.interlock_service_principal_id
            ):
                if self._sessions and not terminate_referencing_sessions:
                    raise EMASessionError(
                        "session_configuration_changed",
                        status_code=409,
                    )
                terminated = len(self._sessions)
                self._sessions.clear()
                self.settings = settings
                return terminated

            missing_clients = {
                session.oauth_client_binding_key_id
                for session in self._sessions.values()
                if session.oauth_client_binding_key_id
                not in settings.oauth_client_keys.keys
            }
            missing_subjects = {
                session.delegated_subject_binding_key_id
                for session in self._sessions.values()
                if session.delegated_subject_binding_key_id
                not in settings.delegated_subject_keys.keys
            }
            if (missing_clients or missing_subjects) and not (
                terminate_referencing_sessions
            ):
                raise EMASessionKeyRetirementError(
                    missing_clients,
                    missing_subjects,
                )

            terminated = 0
            if missing_clients or missing_subjects:
                doomed = [
                    session_id
                    for session_id, session in self._sessions.items()
                    if session.oauth_client_binding_key_id in missing_clients
                    or session.delegated_subject_binding_key_id in missing_subjects
                ]
                for session_id in doomed:
                    self._sessions.pop(session_id, None)
                terminated = len(doomed)
            self.settings = settings
            return terminated

    def _remove_expired_locked(self) -> None:
        now = self._epoch_time()
        for session_id in [
            key for key, value in self._sessions.items() if value.expires_at <= now
        ]:
            self._sessions.pop(session_id, None)


def _session_client_binding(session: EMASession):
    from core.ema_auth import HMACBinding

    return HMACBinding(
        algorithm=session.oauth_client_binding_alg,
        key_id=session.oauth_client_binding_key_id,
        value=session.oauth_client_binding,
    )


def _session_subject_binding(session: EMASession):
    from core.ema_auth import HMACBinding

    return HMACBinding(
        algorithm=session.delegated_subject_binding_alg,
        key_id=session.delegated_subject_binding_key_id,
        value=session.delegated_subject_binding,
    )
