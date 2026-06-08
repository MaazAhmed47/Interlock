"""Tests for OIDC admin authentication."""
import json
import os
import sys
import tempfile
import time
from pathlib import Path

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

os.environ["PYTHON_DOTENV_DISABLED"] = "1"
os.environ.pop("DATABASE_URL", None)

TEST_DB = tempfile.mktemp(suffix="_admin_oidc_test.db")
os.environ["FIREWALL_DB_PATH"] = TEST_DB

from core import db
from core import admin

ISSUER = "https://idp.example.com/"
AUDIENCE = "interlock-admin"


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

    old_values = {
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

    admin.OIDC_ADMIN_ENABLED = True
    admin.OIDC_ISSUER = ISSUER
    admin.OIDC_AUDIENCE = AUDIENCE
    admin.OIDC_JWKS_URL = "https://idp.example.com/.well-known/jwks.json"
    admin.OIDC_GROUPS_CLAIM = "groups"
    admin.OIDC_ROLE_CLAIM = "interlock_role"
    admin.OIDC_EMAIL_CLAIM = "email"
    admin.OIDC_DEFAULT_ROLE = ""
    admin.OIDC_ADMIN_EMAIL_ALLOWLIST = ""
    admin.OIDC_ADMIN_DOMAIN_ALLOWLIST = ""
    admin.OIDC_ALLOWED_ALGS = ["RS256"]
    admin.OIDC_GROUP_ROLE_MAP_RAW = json.dumps({
        "interlock-owners": "owner",
        "interlock-operators": "operator",
        "interlock-security": "security_reviewer",
        "interlock-auditors": "auditor",
    })
    monkeypatch.setattr(admin, "_get_oidc_signing_key", lambda token: public_key)

    yield private_key

    for key, value in old_values.items():
        setattr(admin, key, value)


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
    token = jwt.encode(payload, private_key, algorithm="RS256", headers={"kid": "test-key"})
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
    good_token = make_token(oidc_keys, email="security@example.com", groups=["interlock-operators"])
    assert "keys" in admin.list_all_keys(authorization=f"Bearer {good_token}")

    bad_token = make_token(oidc_keys, email="intruder@example.com", groups=["interlock-operators"])
    with pytest.raises(HTTPException) as exc:
        admin.list_all_keys(authorization=f"Bearer {bad_token}")
    assert exc.value.status_code == 403


def test_oidc_domain_allowlist_allows_matching_domain(oidc_keys):
    admin.OIDC_ADMIN_EMAIL_ALLOWLIST = ""
    admin.OIDC_ADMIN_DOMAIN_ALLOWLIST = "example.com"
    token = make_token(oidc_keys, email="security@example.com", groups=["interlock-operators"])
    assert "keys" in admin.list_all_keys(authorization=f"Bearer {token}")
