"""Adversarial validation tests for the mock-only JWT/JWKS profile."""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import replace

import httpx
import jwt
import pytest

from tests.ema_test_support import MockRS256Issuer
from tests.test_ema_config import valid_raw_config


def _settings():
    from core.ema_config import load_experimental_ema_settings

    value = load_experimental_ema_settings(valid_raw_config())
    assert value is not None
    return value


class CountingJWKS:
    def __init__(self, body, *, status=200, headers=None):
        self.body = body
        self.status = status
        self.headers = headers or {}
        self.calls = 0

    def transport(self):
        async def handler(request):
            self.calls += 1
            content = (
                self.body
                if isinstance(self.body, bytes)
                else json.dumps(self.body).encode("utf-8")
            )
            return httpx.Response(
                self.status,
                headers=self.headers,
                content=content,
                request=request,
            )

        return httpx.MockTransport(handler)


def _validator(issuer, source, *, settings=None, monotonic=None):
    from core.ema_auth import EMAAccessTokenValidator, TrustedJWKSCache

    settings = settings or _settings()
    cache = TrustedJWKSCache(
        settings,
        transport=source.transport(),
        monotonic=monotonic or time.monotonic,
    )
    return EMAAccessTokenValidator(settings, cache=cache), cache


def _validate(validator, token):
    return asyncio.run(validator.validate_token(token))


def test_valid_mock_rs256_token_is_verified_and_normalized():
    issuer = MockRS256Issuer.create()
    source = CountingJWKS(issuer.jwks())
    validator, _ = _validator(issuer, source)

    authority = _validate(validator, issuer.token())
    assert authority.issuer == issuer.issuer
    assert authority.audiences == (issuer.resource,)
    assert authority.resource == issuer.resource
    assert authority.client_id == issuer.client_id
    assert authority.subject == issuer.subject
    assert authority.scopes == ("files:list", "files:read")
    assert source.calls == 1


@pytest.mark.parametrize(
    "header,code",
    [
        (None, "missing_authorization"),
        ("", "missing_authorization"),
        ("Basic abc", "invalid_authorization"),
        ("Bearer", "invalid_authorization"),
        ("Bearer one two", "invalid_authorization"),
        ("bearer token", "invalid_authorization"),
        ("Bearer token,Bearer other", "invalid_authorization"),
    ],
)
def test_authorization_header_requires_one_exact_bearer_value(header, code):
    from core.ema_auth import EMAAuthError, extract_bearer_token

    with pytest.raises(EMAAuthError) as captured:
        extract_bearer_token(header, _settings())
    assert captured.value.code == code
    assert str(captured.value) == code


def test_authorization_header_limit_is_checked_before_token_parsing():
    from core.ema_auth import EMAAuthError, extract_bearer_token

    settings = replace(_settings(), authorization_header_max_bytes=32)
    with pytest.raises(EMAAuthError) as captured:
        extract_bearer_token("Bearer " + ("x" * 40), settings)
    assert captured.value.code == "authorization_too_large"


@pytest.mark.parametrize(
    "claim,value,code",
    [
        ("iss", "https://other-issuer.example", "invalid_issuer"),
        ("aud", "https://other-resource.example/mcp", "invalid_audience"),
        ("resource", "https://other-resource.example/mcp", "invalid_resource"),
        ("exp", 1, "token_expired"),
        ("client_id", "unmapped-client", "client_unmapped"),
        ("scope", "", "invalid_scope"),
        ("scope", ["files:read"], "invalid_scope"),
        ("sub", "", "invalid_subject"),
        ("sub", ["employee"], "invalid_subject"),
    ],
)
def test_required_signed_claim_failures_are_bounded(claim, value, code):
    from core.ema_auth import EMAAuthError

    issuer = MockRS256Issuer.create()
    source = CountingJWKS(issuer.jwks())
    validator, _ = _validator(issuer, source)
    token = issuer.token(claims=issuer.claims(**{claim: value}))
    with pytest.raises(EMAAuthError) as captured:
        _validate(validator, token)
    assert captured.value.code == code
    assert issuer.client_id not in str(captured.value)
    assert issuer.subject not in str(captured.value)


@pytest.mark.parametrize(
    "missing,code",
    [
        ("iss", "missing_claim"),
        ("aud", "missing_claim"),
        ("resource", "missing_claim"),
        ("exp", "missing_claim"),
        ("client_id", "missing_claim"),
        ("scope", "missing_claim"),
        ("sub", "missing_claim"),
    ],
)
def test_every_profile_claim_is_required(missing, code):
    from core.ema_auth import EMAAuthError

    issuer = MockRS256Issuer.create()
    claims = issuer.claims()
    claims.pop(missing)
    validator, _ = _validator(issuer, CountingJWKS(issuer.jwks()))
    with pytest.raises(EMAAuthError) as captured:
        _validate(validator, issuer.token(claims=claims))
    assert captured.value.code == code


def test_wrong_signature_fails_without_claim_retention():
    from core.ema_auth import EMAAuthError

    trusted = MockRS256Issuer.create()
    attacker = MockRS256Issuer.create(kid=trusted.kid)
    validator, _ = _validator(trusted, CountingJWKS(trusted.jwks()))
    with pytest.raises(EMAAuthError) as captured:
        _validate(validator, attacker.token())
    assert captured.value.code == "invalid_signature"


@pytest.mark.parametrize(
    "headers,code",
    [
        ({"typ": "JWT"}, "invalid_typ"),
        ({"jku": "https://attacker.example/jwks"}, "prohibited_key_reference"),
        ({"x5u": "https://attacker.example/cert"}, "prohibited_key_reference"),
        ({"jwk": {"kty": "RSA"}}, "prohibited_key_reference"),
        ({"crit": ["custom"]}, "unsupported_critical_header"),
        ({"kid": ""}, "invalid_kid"),
    ],
)
def test_protected_header_profile_is_fail_closed_before_jwks_fetch(headers, code):
    from core.ema_auth import EMAAuthError

    issuer = MockRS256Issuer.create()
    source = CountingJWKS(issuer.jwks())
    validator, _ = _validator(issuer, source)
    with pytest.raises(EMAAuthError) as captured:
        _validate(validator, issuer.token(headers=headers))
    assert captured.value.code == code
    assert source.calls == 0


def test_alg_none_is_rejected_before_jwks_fetch():
    from core.ema_auth import EMAAuthError

    issuer = MockRS256Issuer.create()
    source = CountingJWKS(issuer.jwks())
    validator, _ = _validator(issuer, source)
    token = jwt.encode(
        issuer.claims(),
        key="",
        algorithm="none",
        headers={"kid": issuer.kid, "typ": "at+jwt"},
    )
    with pytest.raises(EMAAuthError) as captured:
        _validate(validator, token)
    assert captured.value.code == "invalid_algorithm"
    assert source.calls == 0


def test_hs256_is_rejected_before_jwks_fetch():
    from core.ema_auth import EMAAuthError

    issuer = MockRS256Issuer.create()
    source = CountingJWKS(issuer.jwks())
    validator, _ = _validator(issuer, source)
    token = jwt.encode(
        issuer.claims(),
        key=b"runtime-only-test-secret",
        algorithm="HS256",
        headers={"kid": issuer.kid, "typ": "at+jwt"},
    )
    with pytest.raises(EMAAuthError) as captured:
        _validate(validator, token)
    assert captured.value.code == "invalid_algorithm"
    assert source.calls == 0


def test_optional_nbf_and_iat_are_validated_when_present():
    from core.ema_auth import EMAAuthError

    issuer = MockRS256Issuer.create()
    validator, _ = _validator(issuer, CountingJWKS(issuer.jwks()))
    future = int(time.time()) + 600
    for claim, code in (("nbf", "token_not_yet_valid"), ("iat", "invalid_iat")):
        with pytest.raises(EMAAuthError) as captured:
            _validate(
                validator,
                issuer.token(claims=issuer.claims(**{claim: future})),
            )
        assert captured.value.code == code


def test_configured_nbf_iat_and_max_age_requirements():
    from core.ema_auth import EMAAuthError

    issuer = MockRS256Issuer.create()
    settings = replace(
        _settings(),
        require_nbf=True,
        require_iat=True,
        max_token_age_seconds=60,
    )
    validator, _ = _validator(
        issuer,
        CountingJWKS(issuer.jwks()),
        settings=settings,
    )
    now = int(time.time())

    missing_nbf = issuer.claims()
    missing_nbf.pop("iat")
    with pytest.raises(EMAAuthError) as captured:
        _validate(validator, issuer.token(claims=missing_nbf))
    assert captured.value.code == "missing_claim"

    with pytest.raises(EMAAuthError) as captured:
        _validate(
            validator,
            issuer.token(claims=issuer.claims(nbf=now - 120, iat=now - 120)),
        )
    assert captured.value.code == "token_too_old"


@pytest.mark.parametrize(
    "part,limit",
    [
        ("header", 8),
        ("payload", 16),
        ("signature", 16),
    ],
)
def test_compact_jwt_segment_limits_precede_jwks_fetch(part, limit):
    from core.ema_auth import EMAAuthError

    issuer = MockRS256Issuer.create()
    source = CountingJWKS(issuer.jwks())
    settings = _settings()
    changes = {
        "header": {"jwt_header_segment_max_bytes": limit},
        "payload": {"jwt_payload_segment_max_bytes": limit},
        "signature": {"jwt_signature_segment_max_bytes": limit},
    }[part]
    validator, _ = _validator(
        issuer,
        source,
        settings=replace(settings, **changes),
    )
    with pytest.raises(EMAAuthError) as captured:
        _validate(validator, issuer.token())
    assert captured.value.code == "token_too_large"
    assert source.calls == 0


def test_decoded_claim_limit_precedes_jwks_fetch():
    from core.ema_auth import EMAAuthError

    issuer = MockRS256Issuer.create()
    source = CountingJWKS(issuer.jwks())
    validator, _ = _validator(
        issuer,
        source,
        settings=replace(_settings(), decoded_claims_max_bytes=32),
    )
    with pytest.raises(EMAAuthError) as captured:
        _validate(validator, issuer.token())
    assert captured.value.code == "token_too_large"
    assert source.calls == 0


@pytest.mark.parametrize(
    "body,code",
    [
        (b"not-json", "jwks_unavailable"),
        ({"keys": "not-a-list"}, "jwks_unavailable"),
        ({"keys": []}, "unknown_kid"),
    ],
)
def test_malformed_or_empty_jwks_fails_closed(body, code):
    from core.ema_auth import EMAAuthError

    issuer = MockRS256Issuer.create()
    validator, _ = _validator(issuer, CountingJWKS(body))
    with pytest.raises(EMAAuthError) as captured:
        _validate(validator, issuer.token())
    assert captured.value.code == code


def test_jwks_redirect_is_not_followed():
    from core.ema_auth import EMAAuthError

    issuer = MockRS256Issuer.create()
    source = CountingJWKS(
        b"",
        status=302,
        headers={"location": "https://attacker.example/jwks"},
    )
    validator, _ = _validator(issuer, source)
    with pytest.raises(EMAAuthError) as captured:
        _validate(validator, issuer.token())
    assert captured.value.code == "jwks_unavailable"
    assert source.calls == 1


def test_oversized_jwks_is_rejected_from_content_length_and_stream():
    from core.ema_auth import EMAAuthError

    issuer = MockRS256Issuer.create()
    body = {"keys": [issuer.public_jwk()], "padding": "x" * 2048}
    settings = replace(_settings(), jwks_document_max_bytes=512)
    for headers in ({}, {"content-length": "4096"}):
        source = CountingJWKS(body, headers=headers)
        validator, _ = _validator(issuer, source, settings=settings)
        with pytest.raises(EMAAuthError) as captured:
            _validate(validator, issuer.token())
        assert captured.value.code == "jwks_unavailable"


def test_jwks_key_count_and_individual_key_size_are_bounded():
    from core.ema_auth import EMAAuthError

    issuer = MockRS256Issuer.create()
    settings = _settings()
    too_many = {"keys": [issuer.public_jwk(kid=f"k-{index}") for index in range(3)]}
    validator, _ = _validator(
        issuer,
        CountingJWKS(too_many),
        settings=replace(settings, jwks_key_count_max=2),
    )
    with pytest.raises(EMAAuthError) as captured:
        _validate(validator, issuer.token())
    assert captured.value.code == "jwks_unavailable"

    oversized = issuer.jwks(padding="x" * 2048)
    validator, _ = _validator(
        issuer,
        CountingJWKS(oversized),
        settings=replace(settings, jwk_max_bytes=512),
    )
    with pytest.raises(EMAAuthError) as captured:
        _validate(validator, issuer.token())
    assert captured.value.code == "jwks_unavailable"


def test_random_unknown_kid_storm_causes_one_single_flight_refresh():
    from core.ema_auth import EMAAuthError

    trusted = MockRS256Issuer.create()
    source = CountingJWKS(trusted.jwks())
    validator, cache = _validator(trusted, source)

    async def storm():
        tokens = [
            MockRS256Issuer.create(kid=f"random-{index}").token()
            for index in range(100)
        ]
        results = await asyncio.gather(
            *(validator.validate_token(token) for token in tokens),
            return_exceptions=True,
        )
        assert all(
            isinstance(result, EMAAuthError) and result.code == "unknown_kid"
            for result in results
        )

    asyncio.run(storm())
    assert source.calls == 1
    assert cache.negative_cache_size <= _settings().jwks_negative_cache_max_entries


def test_unknown_kid_negative_cache_and_global_cooldown_bound_fetches():
    from core.ema_auth import EMAAuthError

    now = [100.0]
    trusted = MockRS256Issuer.create()
    source = CountingJWKS(trusted.jwks())
    validator, _ = _validator(trusted, source, monotonic=lambda: now[0])
    missing = MockRS256Issuer.create(kid="missing-key").token()

    for _ in range(5):
        with pytest.raises(EMAAuthError):
            _validate(validator, missing)
    assert source.calls == 1

    now[0] += _settings().jwks_refresh_cooldown_seconds + 1
    other = MockRS256Issuer.create(kid="other-missing-key").token()
    with pytest.raises(EMAAuthError):
        _validate(validator, other)
    assert source.calls == 2
