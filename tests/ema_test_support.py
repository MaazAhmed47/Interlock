"""Mock-only runtime RSA issuer support for experimental validation tests.

This harness proves Interlock validation behavior only. It is not an EMA
authorization server and provides no ecosystem interoperability evidence.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm


@dataclass
class MockRS256Issuer:
    issuer: str
    resource: str
    client_id: str
    subject: str
    kid: str
    private_key: rsa.RSAPrivateKey

    @classmethod
    def create(
        cls,
        *,
        issuer: str = "https://issuer.example",
        resource: str = "https://interlock.example/experimental/mcp",
        client_id: str = "https://client.example/oauth/client.json",
        subject: str = "employee-subject",
        kid: str = "mock-rs256-key",
    ) -> "MockRS256Issuer":
        return cls(
            issuer=issuer,
            resource=resource,
            client_id=client_id,
            subject=subject,
            kid=kid,
            private_key=rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            ),
        )

    def public_jwk(self, **overrides: Any) -> dict[str, Any]:
        value = json.loads(RSAAlgorithm.to_jwk(self.private_key.public_key()))
        value.update({"kid": self.kid, "alg": "RS256", "use": "sig"})
        value.update(overrides)
        return value

    def jwks(self, **key_overrides: Any) -> dict[str, Any]:
        return {"keys": [self.public_jwk(**key_overrides)]}

    def claims(self, **overrides: Any) -> dict[str, Any]:
        now = int(time.time())
        value: dict[str, Any] = {
            "iss": self.issuer,
            "aud": self.resource,
            "resource": self.resource,
            "exp": now + 600,
            "iat": now,
            "client_id": self.client_id,
            "scope": "files:list files:read",
            "sub": self.subject,
        }
        value.update(overrides)
        return value

    def token(
        self,
        *,
        claims: dict[str, Any] | None = None,
        headers: dict[str, Any] | None = None,
    ) -> str:
        protected = {"kid": self.kid, "typ": "at+jwt"}
        protected.update(headers or {})
        return jwt.encode(
            claims or self.claims(),
            self.private_key,
            algorithm="RS256",
            headers=protected,
        )
