"""Identity substitution and key-rotation tests for experimental MCP sessions."""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import replace
from types import MappingProxyType

import pytest

from core.ema_auth import VerifiedAuthority
from core.ema_config import HMACKeyRing
from tests.test_ema_config import valid_raw_config


def _settings():
    from core.ema_config import load_experimental_ema_settings

    value = load_experimental_ema_settings(valid_raw_config())
    assert value is not None
    return value


def _authority(
    *,
    client_id: str = "https://client.example/oauth/client.json",
    subject: str = "employee-subject",
    scopes: tuple[str, ...] = ("files:read",),
    expires_at: int | None = None,
) -> VerifiedAuthority:
    now = int(time.time())
    return VerifiedAuthority(
        issuer="https://issuer.example",
        audiences=("https://interlock.example/experimental/mcp",),
        resource="https://interlock.example/experimental/mcp",
        client_id=client_id,
        subject=subject,
        scopes=scopes,
        expires_at=expires_at or now + 600,
        not_before=None,
        issued_at=now,
        verified_at=now,
    )


def _rotated_ring(ring: HMACKeyRing, key_id: str, secret: bytes) -> HMACKeyRing:
    return HMACKeyRing(
        purpose=ring.purpose,
        algorithm=ring.algorithm,
        active_key_id=key_id,
        keys=MappingProxyType({**ring.keys, key_id: secret}),
    )


def test_session_id_is_server_generated_opaque_and_high_entropy():
    from core.ema_sessions import EMASessionStore

    store = EMASessionStore(_settings())
    first = asyncio.run(store.create(_authority()))
    second = asyncio.run(store.create(_authority()))
    assert first.session_id != second.session_id
    assert len(first.session_id) >= 43
    assert first.session_id.isascii()
    assert "employee" not in first.session_id


def test_session_stores_bindings_but_no_raw_identity_or_token_claims():
    from core.ema_sessions import EMASessionStore

    authority = _authority()
    session = asyncio.run(EMASessionStore(_settings()).create(authority))
    encoded = json.dumps(session.to_safe_dict(), sort_keys=True)
    assert authority.client_id not in encoded
    assert authority.subject not in encoded
    assert "email" not in encoded.lower()
    assert session.oauth_client_binding_key_id
    assert session.delegated_subject_binding_key_id


@pytest.mark.parametrize(
    "replacement,code",
    [
        (
            _authority(subject="different-subject"),
            "session_subject_mismatch",
        ),
        (
            _authority(client_id="https://other-client.example/client.json"),
            "session_client_mismatch",
        ),
        (
            _authority(
                client_id="https://other-client.example/client.json",
                subject="different-subject",
            ),
            "session_client_mismatch",
        ),
    ],
)
def test_session_rejects_client_or_subject_substitution(replacement, code):
    from core.ema_sessions import EMASessionError, EMASessionStore

    store = EMASessionStore(_settings())
    session = asyncio.run(store.create(_authority()))
    with pytest.raises(EMASessionError) as captured:
        asyncio.run(store.authorize(session.session_id, replacement))
    assert captured.value.code == code


def test_expired_session_is_removed_and_fails_closed():
    from core.ema_sessions import EMASessionError, EMASessionStore

    clock = [100.0]
    settings = replace(_settings(), session_lifetime_seconds=10)
    store = EMASessionStore(settings, epoch_time=lambda: clock[0])
    session = asyncio.run(store.create(_authority()))
    clock[0] = 111.0
    with pytest.raises(EMASessionError) as captured:
        asyncio.run(store.authorize(session.session_id, _authority()))
    assert captured.value.code == "session_expired"
    assert asyncio.run(store.get(session.session_id)) is None


def test_new_session_creation_purges_expired_session_state():
    from core.ema_sessions import EMASessionStore

    clock = [100.0]
    settings = replace(_settings(), session_lifetime_seconds=10)
    store = EMASessionStore(settings, epoch_time=lambda: clock[0])
    expired = asyncio.run(store.create(_authority()))
    clock[0] = 111.0
    current = asyncio.run(store.create(_authority()))
    assert asyncio.run(store.get(expired.session_id)) is None
    assert asyncio.run(store.get(current.session_id)) is not None
    assert set(store._sessions) == {current.session_id}


def test_refreshed_token_with_same_identity_and_reduced_scopes_keeps_session():
    from core.ema_sessions import EMASessionStore

    store = EMASessionStore(_settings())
    session = asyncio.run(store.create(_authority(scopes=("files:list", "files:read"))))
    refreshed = _authority(scopes=("files:list",))
    authorized = asyncio.run(store.authorize(session.session_id, refreshed))
    assert authorized.session_id == session.session_id
    assert refreshed.scopes == ("files:list",)
    assert "files:read" not in authorized.to_safe_dict()


def test_refreshed_identity_before_rotation_uses_session_key_ids():
    from core.ema_sessions import EMASessionStore

    store = EMASessionStore(_settings())
    session = asyncio.run(store.create(_authority()))
    authorized = asyncio.run(store.authorize(session.session_id, _authority()))
    assert authorized.oauth_client_binding_key_id == session.oauth_client_binding_key_id
    assert (
        authorized.delegated_subject_binding_key_id
        == session.delegated_subject_binding_key_id
    )


def test_refreshed_identity_after_rotation_migrates_atomically_to_active_keys():
    from core.ema_sessions import EMASessionStore

    settings = _settings()
    store = EMASessionStore(settings)
    session = asyncio.run(store.create(_authority()))
    rotated = replace(
        settings,
        oauth_client_keys=_rotated_ring(
            settings.oauth_client_keys,
            "client-2026-08",
            b"C" * 32,
        ),
        delegated_subject_keys=_rotated_ring(
            settings.delegated_subject_keys,
            "subject-2026-08",
            b"S" * 32,
        ),
    )
    asyncio.run(store.rotate_settings(rotated))

    authorized = asyncio.run(store.authorize(session.session_id, _authority()))
    assert authorized.oauth_client_binding_key_id == "client-2026-08"
    assert authorized.delegated_subject_binding_key_id == "subject-2026-08"
    assert authorized.oauth_client_binding != session.oauth_client_binding
    assert authorized.delegated_subject_binding != session.delegated_subject_binding


def test_rotation_cannot_retire_identity_key_referenced_by_live_session():
    from core.ema_sessions import EMASessionKeyRetirementError, EMASessionStore

    settings = _settings()
    store = EMASessionStore(settings)
    session = asyncio.run(store.create(_authority()))
    client_old = session.oauth_client_binding_key_id
    subject_old = session.delegated_subject_binding_key_id
    unsafe = replace(
        settings,
        oauth_client_keys=HMACKeyRing(
            purpose=settings.oauth_client_keys.purpose,
            algorithm=settings.oauth_client_keys.algorithm,
            active_key_id="client-new",
            keys=MappingProxyType({"client-new": b"C" * 32}),
        ),
        delegated_subject_keys=HMACKeyRing(
            purpose=settings.delegated_subject_keys.purpose,
            algorithm=settings.delegated_subject_keys.algorithm,
            active_key_id="subject-new",
            keys=MappingProxyType({"subject-new": b"S" * 32}),
        ),
    )
    with pytest.raises(EMASessionKeyRetirementError) as captured:
        asyncio.run(store.rotate_settings(unsafe))
    assert client_old in captured.value.missing_client_key_ids
    assert subject_old in captured.value.missing_subject_key_ids


def test_rotation_may_explicitly_terminate_sessions_before_old_key_retirement():
    from core.ema_sessions import EMASessionStore

    settings = _settings()
    store = EMASessionStore(settings)
    session = asyncio.run(store.create(_authority()))
    unsafe = replace(
        settings,
        oauth_client_keys=HMACKeyRing(
            purpose=settings.oauth_client_keys.purpose,
            algorithm=settings.oauth_client_keys.algorithm,
            active_key_id="client-new",
            keys=MappingProxyType({"client-new": b"C" * 32}),
        ),
        delegated_subject_keys=HMACKeyRing(
            purpose=settings.delegated_subject_keys.purpose,
            algorithm=settings.delegated_subject_keys.algorithm,
            active_key_id="subject-new",
            keys=MappingProxyType({"subject-new": b"S" * 32}),
        ),
    )
    terminated = asyncio.run(
        store.rotate_settings(unsafe, terminate_referencing_sessions=True)
    )
    assert terminated == 1
    assert asyncio.run(store.get(session.session_id)) is None


def test_session_cannot_migrate_to_a_different_mcp_server():
    from core.ema_sessions import EMASessionError, EMASessionStore

    settings = _settings()
    store = EMASessionStore(settings)
    asyncio.run(store.create(_authority()))
    cross_server = replace(settings, server_id="different-mcp-server")
    with pytest.raises(EMASessionError) as captured:
        asyncio.run(store.rotate_settings(cross_server))
    assert captured.value.code == "session_configuration_changed"


def test_old_keys_can_retire_after_session_migrates_to_active_keys():
    from core.ema_sessions import EMASessionStore

    settings = _settings()
    store = EMASessionStore(settings)
    session = asyncio.run(store.create(_authority()))
    rotated = replace(
        settings,
        oauth_client_keys=_rotated_ring(
            settings.oauth_client_keys, "client-new", b"C" * 32
        ),
        delegated_subject_keys=_rotated_ring(
            settings.delegated_subject_keys, "subject-new", b"S" * 32
        ),
    )
    asyncio.run(store.rotate_settings(rotated))
    asyncio.run(store.authorize(session.session_id, _authority()))

    retired = replace(
        rotated,
        oauth_client_keys=HMACKeyRing(
            purpose=rotated.oauth_client_keys.purpose,
            algorithm=rotated.oauth_client_keys.algorithm,
            active_key_id="client-new",
            keys=MappingProxyType({"client-new": b"C" * 32}),
        ),
        delegated_subject_keys=HMACKeyRing(
            purpose=rotated.delegated_subject_keys.purpose,
            algorithm=rotated.delegated_subject_keys.algorithm,
            active_key_id="subject-new",
            keys=MappingProxyType({"subject-new": b"S" * 32}),
        ),
    )
    assert asyncio.run(store.rotate_settings(retired)) == 0
    assert asyncio.run(store.authorize(session.session_id, _authority()))


def test_initialized_state_and_explicit_termination_are_session_bound():
    from core.ema_sessions import EMASessionError, EMASessionStore

    store = EMASessionStore(_settings())
    session = asyncio.run(store.create(_authority()))
    assert session.initialized is False
    initialized = asyncio.run(store.mark_initialized(session.session_id, _authority()))
    assert initialized.initialized is True
    asyncio.run(store.terminate(session.session_id, _authority()))
    with pytest.raises(EMASessionError) as captured:
        asyncio.run(store.authorize(session.session_id, _authority()))
    assert captured.value.code == "session_not_found"
