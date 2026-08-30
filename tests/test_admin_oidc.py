"""Tests for OIDC admin authentication."""

import json
import logging
import os
import sys
import tempfile
import time
import traceback
from pathlib import Path
from unittest.mock import MagicMock

import jwt
import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

os.environ["PYTHON_DOTENV_DISABLED"] = "1"
os.environ.pop("DATABASE_URL", None)

TEST_DB = tempfile.mktemp(suffix="_admin_oidc_test.db")
os.environ["FIREWALL_DB_PATH"] = TEST_DB

from core import admin  # noqa: E402
from core import db  # noqa: E402

ISSUER = "https://idp.example.com/"
AUDIENCE = "interlock-admin"


def _exception_graph(error: BaseException) -> list[BaseException]:
    pending = [error]
    seen: set[int] = set()
    graph: list[BaseException] = []
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        graph.append(current)
        if current.__cause__ is not None:
            pending.append(current.__cause__)
        if current.__context__ is not None:
            pending.append(current.__context__)
    return graph


def _assert_exception_graph_is_url_free(
    error: BaseException, forbidden: tuple[str, ...]
) -> list[BaseException]:
    graph = _exception_graph(error)
    rendered = "\n".join(
        [
            *(str(item) for item in graph),
            *(repr(item) for item in graph),
            "".join(traceback.format_exception(error)),
        ]
    )
    for value in forbidden:
        assert value not in rendered
    assert not any(isinstance(item, httpx.HTTPError) for item in graph)
    return graph


def _configure_oidc_jwks_failure(monkeypatch, jwks_url, handler):
    monkeypatch.setenv("INTERLOCK_EGRESS_PROFILE", "phase1")
    monkeypatch.delenv("INTERLOCK_OUTBOUND_HTTP_PROXY", raising=False)
    monkeypatch.setattr(admin, "OIDC_ADMIN_ENABLED", True)
    monkeypatch.setattr(admin, "OIDC_ISSUER", ISSUER)
    monkeypatch.setattr(admin, "OIDC_AUDIENCE", AUDIENCE)
    monkeypatch.setattr(admin, "OIDC_JWKS_URL", jwks_url)
    monkeypatch.setattr(admin, "OIDC_ALLOWED_ALGS", ["HS256"])
    monkeypatch.setattr(admin, "_OIDC_JWKS_CLIENT", None)
    monkeypatch.setattr(admin, "_OIDC_JWKS_CLIENT_URL", "")
    monkeypatch.setattr(
        admin,
        "ensure_safe_outbound_url",
        lambda value, *, context: value,
    )

    real_client = httpx.Client

    def client_factory(**kwargs):
        assert kwargs["follow_redirects"] is False
        assert kwargs["trust_env"] is False
        return real_client(transport=httpx.MockTransport(handler))

    monkeypatch.setattr(admin.httpx, "Client", client_factory)
    return jwt.encode(
        {"iss": ISSUER, "aud": AUDIENCE, "sub": "failure-path"},
        "test-signing-secret-with-32-bytes-minimum",
        algorithm="HS256",
        headers={"kid": "failure-key"},
    )


@pytest.fixture(scope="module", autouse=True)
def setup_db():
    old_db_path = db.DB_PATH
    old_admin_token = admin.ADMIN_TOKEN
    db.DB_PATH = TEST_DB
    admin.ADMIN_TOKEN = "bootstrap-for-oidc-tests"
    db.init_db()
    yield
    db.DB_PATH = old_db_path
    admin.ADMIN_TOKEN = old_admin_token
    for path in (TEST_DB, TEST_DB + "-wal", TEST_DB + "-shm"):
        try:
            os.unlink(path)
        except OSError:
            pass


@pytest.fixture()
def oidc_keys(monkeypatch):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    values = {
        "OIDC_ADMIN_ENABLED": admin.OIDC_ADMIN_ENABLED,
        "OIDC_ISSUER": admin.OIDC_ISSUER,
        "OIDC_AUDIENCE": admin.OIDC_AUDIENCE,
        "OIDC_JWKS_URL": admin.OIDC_JWKS_URL,
        "OIDC_GROUPS_CLAIM": admin.OIDC_GROUPS_CLAIM,
        "OIDC_ROLE_CLAIM": admin.OIDC_ROLE_CLAIM,
        "OIDC_EMAIL_CLAIM": admin.OIDC_EMAIL_CLAIM,
        "OIDC_DEFAULT_ROLE": admin.OIDC_DEFAULT_ROLE,
        "OIDC_ADMIN_EMAIL_ALLOWLIST": admin.OIDC_ADMIN_EMAIL_ALLOWLIST,
        "OIDC_ADMIN_DOMAIN_ALLOWLIST": admin.OIDC_ADMIN_DOMAIN_ALLOWLIST,
        "OIDC_ALLOWED_ALGS": list(admin.OIDC_ALLOWED_ALGS),
        "OIDC_GROUP_ROLE_MAP_RAW": admin.OIDC_GROUP_ROLE_MAP_RAW,
    }

    values.update(
        {
            "OIDC_ADMIN_ENABLED": True,
            "OIDC_ISSUER": ISSUER,
            "OIDC_AUDIENCE": AUDIENCE,
            "OIDC_JWKS_URL": "https://idp.example.com/.well-known/jwks.json",
            "OIDC_GROUPS_CLAIM": "groups",
            "OIDC_ROLE_CLAIM": "interlock_role",
            "OIDC_EMAIL_CLAIM": "email",
            "OIDC_DEFAULT_ROLE": "",
            "OIDC_ADMIN_EMAIL_ALLOWLIST": "",
            "OIDC_ADMIN_DOMAIN_ALLOWLIST": "",
            "OIDC_ALLOWED_ALGS": ["RS256"],
            "OIDC_GROUP_ROLE_MAP_RAW": json.dumps(
                {
                    "interlock-owners": "owner",
                    "interlock-operators": "operator",
                    "interlock-security": "security_reviewer",
                    "interlock-auditors": "auditor",
                }
            ),
        }
    )
    for key, value in values.items():
        monkeypatch.setattr(admin, key, value)
    monkeypatch.setattr(admin, "_get_oidc_signing_key", lambda token: public_key)

    yield private_key


def test_oidc_jwks_redirect_is_rejected_without_second_request(monkeypatch):
    monkeypatch.setenv("INTERLOCK_ENV", "development")
    requests = []
    real_client = httpx.Client

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(str(request.url))
        return httpx.Response(
            302,
            headers={"Location": "http://redirect.audit.invalid/jwks"},
            request=request,
        )

    def client_factory(**kwargs):
        assert kwargs["follow_redirects"] is False
        assert kwargs["trust_env"] is False
        return real_client(transport=httpx.MockTransport(handler))

    monkeypatch.setattr(admin.httpx, "Client", client_factory)
    client = admin._GuardedPyJWKClient("https://idp.audit.invalid/jwks")

    with pytest.raises(jwt.exceptions.PyJWKClientConnectionError) as captured:
        client.fetch_data()

    assert requests == ["https://idp.audit.invalid/jwks"]
    assert str(captured.value) == "OIDC JWKS redirect was rejected"
    assert captured.value.category == "redirect"
    assert captured.value.status_code == 302
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None


@pytest.mark.parametrize("failure_kind", ["status", "transport"])
def test_oidc_jwks_failure_is_url_free_across_caller_and_logs(
    monkeypatch, caplog, failure_kind
):
    query_sentinel = "oidc_query_" + "sentinel_7f3a91"
    credential_sentinel = "oidc_credential_" + "sentinel_b84c26"
    query = f"access_token={credential_sentinel}&trace={query_sentinel}"
    jwks_url = f"https://oidc-failure.invalid/jwks?{query}"
    status_probe = MagicMock(
        side_effect=AssertionError("raise_for_status must not be used")
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if failure_kind == "transport":
            raise httpx.ConnectError(
                f"synthetic transport {credential_sentinel}", request=request
            )
        response = httpx.Response(
            503,
            headers={"x-upstream-secret": credential_sentinel},
            content=f"body-{query_sentinel}".encode(),
            request=request,
        )
        response.raise_for_status = status_probe
        return response

    token = _configure_oidc_jwks_failure(monkeypatch, jwks_url, handler)
    direct_client = admin._GuardedPyJWKClient(jwks_url)
    with pytest.raises(admin._OIDCJWKSFetchFailure) as direct_failure:
        direct_client.fetch_data()
    expected_category = (
        "http_status" if failure_kind == "status" else "connection_failed"
    )
    assert direct_failure.value.category == expected_category
    assert direct_failure.value.status_code == (
        503 if failure_kind == "status" else None
    )
    assert direct_failure.value.__cause__ is None
    assert direct_failure.value.__context__ is None
    _assert_exception_graph_is_url_free(
        direct_failure.value,
        (
            query_sentinel,
            credential_sentinel,
            query,
            jwks_url,
            "access_token=",
        ),
    )
    monkeypatch.setattr(admin, "_OIDC_JWKS_CLIENT", None)
    monkeypatch.setattr(admin, "_OIDC_JWKS_CLIENT_URL", "")
    list_keys = MagicMock(side_effect=AssertionError("database access is forbidden"))
    audit = MagicMock(side_effect=AssertionError("audit output is forbidden"))
    monkeypatch.setattr(admin.db, "list_keys", list_keys)
    monkeypatch.setattr(admin.db, "log_admin_audit_event", audit)
    caplog.set_level(logging.DEBUG)

    with pytest.raises(HTTPException) as captured:
        admin.list_all_keys(authorization=f"Bearer {token}")

    assert captured.value.status_code == 401
    assert captured.value.detail == "OIDC token verification failed."
    forbidden = (query_sentinel, credential_sentinel, query, jwks_url, "access_token=")
    graph = _assert_exception_graph_is_url_free(captured.value, forbidden)
    assert graph == [captured.value]
    if failure_kind == "status":
        status_probe.assert_not_called()

    retained_logs = "\n".join(record.getMessage() for record in caplog.records)
    for value in forbidden:
        assert value not in retained_logs
    relevant = [
        record
        for record in caplog.records
        if record.name == "interlock.admin"
        and "OIDC JWKS fetch failed" in record.message
    ]
    assert len(relevant) == 1
    assert relevant[0].exc_info is None
    assert relevant[0].oidc_jwks_category == expected_category
    assert relevant[0].oidc_jwks_status == (503 if failure_kind == "status" else None)
    list_keys.assert_not_called()
    audit.assert_not_called()


def make_token(private_key, **claims):
    now = int(time.time())
    payload = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "user-123",
        "email": "security@example.com",
        "groups": ["interlock-operators"],
        "exp": now + 3600,
        "iat": now,
    }
    payload.update(claims)
    token = jwt.encode(
        payload, private_key, algorithm="RS256", headers={"kid": "test-key"}
    )
    return token.decode("utf-8") if isinstance(token, bytes) else token


def test_oidc_operator_can_read_keys_but_cannot_create_admin_tokens(oidc_keys):
    token = make_token(oidc_keys, groups=["interlock-operators"])

    result = admin.list_all_keys(authorization=f"Bearer {token}")
    assert "keys" in result

    with pytest.raises(HTTPException) as exc:
        admin.create_admin_token(
            admin.CreateAdminTokenRequest(label="should-fail", role="auditor"),
            authorization=f"Bearer {token}",
        )
    assert exc.value.status_code == 403


def test_oidc_owner_role_claim_can_issue_scoped_token(oidc_keys):
    token = make_token(oidc_keys, interlock_role="owner", groups=[])

    created = admin.create_admin_token(
        admin.CreateAdminTokenRequest(label="oidc-created-auditor", role="auditor"),
        authorization=f"Bearer {token}",
    )

    assert created["raw_token"].startswith("ia_")
    assert created["role"] == "auditor"


def test_oidc_unmapped_user_is_forbidden(oidc_keys):
    token = make_token(oidc_keys, groups=["unmapped-group"])

    with pytest.raises(HTTPException) as exc:
        admin.list_all_keys(authorization=f"Bearer {token}")
    assert exc.value.status_code == 403


def test_oidc_rejects_unapproved_algorithm(oidc_keys):
    token = jwt.encode(
        {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": "user-123",
            "groups": ["interlock-operators"],
            "exp": int(time.time()) + 3600,
        },
        "shared-secret-for-test-at-least-32-bytes",
        algorithm="HS256",
    )
    token = token.decode("utf-8") if isinstance(token, bytes) else token

    with pytest.raises(HTTPException) as exc:
        admin.list_all_keys(authorization=f"Bearer {token}")
    assert exc.value.status_code == 401


def test_oidc_email_allowlist_blocks_unapproved_principal(oidc_keys):
    admin.OIDC_ADMIN_EMAIL_ALLOWLIST = "security@example.com"
    good_token = make_token(
        oidc_keys, email="security@example.com", groups=["interlock-operators"]
    )
    assert "keys" in admin.list_all_keys(authorization=f"Bearer {good_token}")

    bad_token = make_token(
        oidc_keys, email="intruder@example.com", groups=["interlock-operators"]
    )
    with pytest.raises(HTTPException) as exc:
        admin.list_all_keys(authorization=f"Bearer {bad_token}")
    assert exc.value.status_code == 403


def test_oidc_domain_allowlist_allows_matching_domain(oidc_keys):
    admin.OIDC_ADMIN_EMAIL_ALLOWLIST = ""
    admin.OIDC_ADMIN_DOMAIN_ALLOWLIST = "example.com"
    token = make_token(
        oidc_keys, email="security@example.com", groups=["interlock-operators"]
    )
    assert "keys" in admin.list_all_keys(authorization=f"Bearer {token}")
