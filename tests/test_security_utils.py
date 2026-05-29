import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.security_utils import scrub_secrets


def test_scrub_api_key():
    d = {"api_key": "secret123", "safe_field": "hello"}
    result = scrub_secrets(d)
    assert result["api_key"] == "***"
    assert result["safe_field"] == "hello"


def test_scrub_nested():
    d = {"config": {"token": "tok_abc", "model": "gpt-4"}}
    result = scrub_secrets(d)
    assert result["config"]["token"] == "***"
    assert result["config"]["model"] == "gpt-4"


def test_scrub_x_api_key():
    d = {"x-api-key": "lf_free_abc", "data": "ok"}
    result = scrub_secrets(d)
    assert result["x-api-key"] == "***"


def test_scrub_leaves_non_secret_values():
    d = {"username": "alice", "role": "admin", "count": 42}
    result = scrub_secrets(d)
    assert result == {"username": "alice", "role": "admin", "count": 42}


def test_scrub_list_passthrough():
    data = [{"api_key": "s", "x": 1}, {"safe": "val"}]
    result = scrub_secrets(data)
    assert result[0]["api_key"] == "***"
    assert result[1]["safe"] == "val"
