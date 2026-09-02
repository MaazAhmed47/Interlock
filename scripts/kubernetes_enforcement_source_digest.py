"""Canonical source-text digests for Kubernetes enforcement evidence."""

from __future__ import annotations

import hashlib
from pathlib import Path


class CanonicalSourceDigestError(RuntimeError):
    """A digest-bound source file cannot be canonicalized safely."""


def canonical_source_bundle_sha256(paths: list[Path], *, root: Path) -> str:
    """Hash UTF-8 source files after only CRLF-to-LF normalization."""

    entries: list[tuple[str, Path]] = []
    for path in paths:
        try:
            relative = path.relative_to(root).as_posix()
        except ValueError:
            relative = None
        if relative is None:
            raise CanonicalSourceDigestError(
                "digest-bound source path is outside the repository root"
            )
        entries.append((relative, path))

    digest = hashlib.sha256()
    for relative, path in sorted(entries):
        try:
            raw = path.read_bytes()
        except OSError:
            raw = None
        if raw is None:
            raise CanonicalSourceDigestError("digest-bound source could not be read")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = None
        if text is None:
            raise CanonicalSourceDigestError("digest-bound source is not valid UTF-8")
        canonical_text = text.replace("\r\n", "\n")
        if "\r" in canonical_text:
            raise CanonicalSourceDigestError(
                "digest-bound source contains a bare CR line ending"
            ) from None
        canonical_body = canonical_text.encode("utf-8")
        relative_bytes = relative.encode("utf-8")
        digest.update(len(relative_bytes).to_bytes(4, "big"))
        digest.update(relative_bytes)
        digest.update(len(canonical_body).to_bytes(8, "big"))
        digest.update(canonical_body)
    return digest.hexdigest()
