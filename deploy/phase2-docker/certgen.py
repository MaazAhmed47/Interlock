"""Generate ephemeral test PKI for the hermetic Phase 2 Docker profile."""

from __future__ import annotations

import base64
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def _b64url(value: int) -> str:
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def main() -> None:
    output = Path(sys.argv[1]).resolve()
    output.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = _name("Interlock Phase 2 ephemeral test CA")
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    origin_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    origin_name = _name("allowed.phase2.test")
    origin_cert = (
        x509.CertificateBuilder()
        .subject_name(origin_name)
        .issuer_name(ca_name)
        .public_key(origin_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=2))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("allowed.phase2.test")]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    (output / "ca.pem").write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    (output / "origin.pem").write_bytes(
        origin_cert.public_bytes(serialization.Encoding.PEM)
    )
    (output / "origin-key.pem").write_bytes(
        origin_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    numbers = origin_key.public_key().public_numbers()
    (output / "jwks.json").write_text(
        json.dumps(
            {
                "keys": [
                    {
                        "alg": "RS256",
                        "e": _b64url(numbers.e),
                        "kid": "phase2-key",
                        "kty": "RSA",
                        "n": _b64url(numbers.n),
                        "use": "sig",
                    }
                ]
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    os.chmod(output / "origin-key.pem", 0o644)


if __name__ == "__main__":
    main()
