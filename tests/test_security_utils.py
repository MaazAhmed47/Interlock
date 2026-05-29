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


def test_scrub_private_key():
    d = {"private_key": "BEGIN RSA PRIVATE KEY", "public_key": "not secret"}
    result = scrub_secrets(d)
    assert result["private_key"] == "***"
    assert result["public_key"] == "not secret"  # public_key is NOT a secret


def test_scrub_does_not_mask_max_tokens():
    d = {"max_tokens": 4096, "input_tokens": 100, "output_tokens": 50}
    result = scrub_secrets(d)
    assert result["max_tokens"] == 4096
    assert result["input_tokens"] == 100
    assert result["output_tokens"] == 50


def test_scrub_auth_token():
    d = {"auth_token": "tok123", "token_count": 42}
    result = scrub_secrets(d)
    assert result["auth_token"] == "***"
    assert result["token_count"] == 42  # NOT masked


def test_scrub_mutation_safety():
    original = {"api_key": "real_key", "safe": "val"}
    scrub_secrets(original)
    assert original["api_key"] == "real_key"  # original unchanged


def test_scrub_depth_limit():
    # Build a deeply nested dict (60 levels deep, exceeds _MAX_DEPTH=50)
    d: object = {"api_key": "deep_secret"}
    for _ in range(60):
        d = {"nested": d}
    # Should not raise RecursionError, returns without crashing
    result = scrub_secrets(d)
    assert result is not None


def test_scrub_bearer_and_authorization():
    d = {"authorization": "Bearer tok123", "bearer": "tok456"}
    result = scrub_secrets(d)
    assert result["authorization"] == "***"
    assert result["bearer"] == "***"
