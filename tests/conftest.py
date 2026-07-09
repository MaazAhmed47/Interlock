"""Shared pytest safety checks."""

import sys

import pytest


@pytest.fixture(autouse=True)
def fail_on_mcp_fixture_leaks():
    """Fail tests that leave disposable MCP registry rows behind."""
    yield

    db = sys.modules.get("core.db")
    if db is None:
        return
    try:
        servers = db.list_mcp_servers()
    except Exception:
        return

    leaks = sorted(
        server.get("server_id")
        for server in servers
        if server.get("registry_class") == "disposable_fixture"
    )
    if not leaks:
        return

    for server_id in leaks:
        try:
            db.unregister_mcp_server(server_id)
        except Exception:
            pass
    raise AssertionError(f"MCP fixture servers leaked after test: {leaks}")
