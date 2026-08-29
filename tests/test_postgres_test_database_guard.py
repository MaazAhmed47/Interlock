import hashlib
from urllib.parse import quote

import pytest

from scripts.postgres_test_database import (
    CONFIRMATION_ENV,
    CONFIRMATION_VALUE,
    DATABASE_URL_ENV,
    RUN_ID_ENV,
    SESSION_TOKEN_ENV,
    DisposableDatabaseError,
    assert_disposable_database,
    main,
)


class FakeResult:
    def __init__(self, row):
        self._row = row

    def fetchone(self):
        return self._row


class FakeConnection:
    def __init__(
        self,
        *,
        database="interlock_test",
        user="interlock_test",
        address="127.0.0.1",
        marker=None,
    ):
        self.database = database
        self.user = user
        self.address = address
        self.marker = marker
        self.statements = []

    def execute(self, statement, params=()):
        self.statements.append((statement, params))
        if "current_database()" in statement:
            return FakeResult(
                {
                    "database_name": self.database,
                    "database_user": self.user,
                    "server_address": self.address,
                }
            )
        if "interlock_disposable_test_sessions" in statement:
            return FakeResult(self.marker)
        return FakeResult(None)


def _approved_env(**overrides):
    values = {
        CONFIRMATION_ENV: CONFIRMATION_VALUE,
        RUN_ID_ENV: "review-run-123",
        SESSION_TOKEN_ENV: "a" * 32,
    }
    values.update(overrides)
    return values


@pytest.mark.parametrize(
    "database_url",
    [
        "postgresql://interlock_test:pw@db.example.com/interlock_test",
        "postgresql://interlock_test:pw@127.0.0.1/production",
        "postgresql://interlock_test:pw@127.0.0.1/postgres",
        "postgresql://interlock_test:pw@127.0.0.1/defaultdb",
        "postgresql://interlock_test:pw@127.0.0.1/app",
        "postgresql://interlock_test:pw@127.0.0.1/interlock",
        "postgresql://interlock_test:pw@127.0.0.1/arbitrary_test_copy",
        "postgresql://interlock_test:pw@127.0.0.1/interlock_test?host=elsewhere",
        "postgresql://interlock_test:pw@127.0.0.1,localhost/interlock_test",
        "postgresql://interlock%5Ftest:pw@127.0.0.1/interlock_test",
        "postgresql:///interlock_test",
    ],
)
def test_rejects_unapproved_target_before_any_sql(database_url):
    conn = FakeConnection()

    with pytest.raises(DisposableDatabaseError):
        assert_disposable_database(conn, database_url=database_url, env=_approved_env())

    assert conn.statements == []


@pytest.mark.parametrize("confirmation", [None, "", "1", "true", "yes"])
def test_requires_exact_destructive_confirmation_before_any_sql(confirmation):
    conn = FakeConnection()
    env = _approved_env()
    if confirmation is None:
        env.pop(CONFIRMATION_ENV)
    else:
        env[CONFIRMATION_ENV] = confirmation

    with pytest.raises(DisposableDatabaseError):
        assert_disposable_database(
            conn,
            database_url="postgresql://interlock_test:pw@127.0.0.1/interlock_test",
            env=env,
        )

    assert conn.statements == []


def test_rejects_current_database_mismatch_without_destructive_sql():
    conn = FakeConnection(database="production")

    with pytest.raises(DisposableDatabaseError, match="identity"):
        assert_disposable_database(
            conn,
            database_url="postgresql://interlock_test:pw@127.0.0.1/interlock_test",
            env=_approved_env(),
        )

    assert all(
        not statement.lstrip().upper().startswith(("DROP", "TRUNCATE", "DELETE"))
        for statement, _params in conn.statements
    )


def test_rejects_current_user_mismatch_without_destructive_sql():
    conn = FakeConnection(user="application_owner")

    with pytest.raises(DisposableDatabaseError, match="identity"):
        assert_disposable_database(
            conn,
            database_url="postgresql://interlock_test:pw@127.0.0.1/interlock_test",
            env=_approved_env(),
        )

    assert all(
        not statement.lstrip().upper().startswith(("DROP", "TRUNCATE", "DELETE"))
        for statement, _params in conn.statements
    )


def test_rejects_missing_session_marker_without_disclosing_url():
    sentinel = "sentinel-" + "z" * 24
    conn = FakeConnection()
    database_url = (
        "postgresql://interlock_test:" + quote(sentinel) + "@127.0.0.1/interlock_test"
    )

    with pytest.raises(DisposableDatabaseError) as exc_info:
        assert_disposable_database(conn, database_url=database_url, env=_approved_env())

    assert sentinel not in str(exc_info.value)
    assert database_url not in str(exc_info.value)
    assert all(
        not statement.lstrip().upper().startswith(("DROP", "TRUNCATE", "DELETE"))
        for statement, _params in conn.statements
    )


def test_accepts_only_matching_live_identity_and_session_marker():
    env = _approved_env()
    conn = FakeConnection(
        marker={
            "run_id": env[RUN_ID_ENV],
            "token_sha256": hashlib.sha256(
                env[SESSION_TOKEN_ENV].encode("utf-8")
            ).hexdigest(),
            "database_name": "interlock_test",
            "database_user": "interlock_test",
            "format_version": 1,
        }
    )

    identity = assert_disposable_database(
        conn,
        database_url="postgresql://interlock_test:pw@127.0.0.1/interlock_test",
        env=env,
    )

    assert identity.database == "interlock_test"
    assert identity.user == "interlock_test"
    assert len(conn.statements) == 2


@pytest.mark.parametrize(
    ("address", "message"),
    [
        ("8.8.8.8", "server address"),
        ("100.64.0.1", "server address"),
        ("", "identity"),
    ],
)
def test_rejects_unapproved_connected_server_address(address, message):
    conn = FakeConnection(address=address)

    with pytest.raises(DisposableDatabaseError, match=message):
        assert_disposable_database(
            conn,
            database_url="postgresql://interlock_test:pw@127.0.0.1/interlock_test",
            env=_approved_env(),
        )

    assert all(
        not statement.lstrip().upper().startswith(("DROP", "TRUNCATE", "DELETE"))
        for statement, _params in conn.statements
    )


def test_cli_hides_target_and_connection_exception(monkeypatch, capsys):
    sentinel = "guard-sentinel-" + "x" * 24
    database_url = (
        "postgresql://interlock_test:" + sentinel + "@127.0.0.1:1/interlock_test"
    )
    for name, value in _approved_env().items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv(DATABASE_URL_ENV, database_url)

    def failed_connect(_database_url):
        raise RuntimeError(f"synthetic connection failure: {sentinel}")

    monkeypatch.setattr("scripts.postgres_test_database._connect", failed_connect)

    assert main(["prepare"]) == 1
    output = capsys.readouterr()
    rendered = output.out + output.err
    assert "failed safely" in rendered
    assert sentinel not in rendered
    assert database_url not in rendered
