"""Fail-closed CI source identity verification using only the standard library."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

SHA_PATTERN = re.compile(r"[0-9a-f]{40}")


class SourceVerificationError(Exception):
    """A bounded source-verification failure safe to print in CI."""


def _git(repo: Path, *args: str, failure: str) -> str:
    try:
        completed = subprocess.run(
            ["git", *args],
            cwd=repo,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
        )
    except (OSError, subprocess.CalledProcessError, UnicodeError) as exc:
        raise SourceVerificationError(failure) from exc
    return completed.stdout


def verify_source(expected: str, repo: Path) -> str:
    """Return HEAD only when it exactly matches a valid SHA and the tree is clean."""
    if SHA_PATTERN.fullmatch(expected) is None:
        raise SourceVerificationError("expected source SHA is invalid")

    head = _git(repo, "rev-parse", "HEAD", failure="unable to read source HEAD").strip()
    if SHA_PATTERN.fullmatch(head) is None:
        raise SourceVerificationError("source HEAD is invalid")
    if head != expected:
        raise SourceVerificationError("source HEAD does not match expected SHA")

    status = _git(
        repo,
        "status",
        "--porcelain",
        "--untracked-files=all",
        failure="unable to read source worktree status",
    )
    if status:
        raise SourceVerificationError("source worktree is not clean")
    return head


def _append_outputs(output: Path, sha: str) -> None:
    try:
        with output.open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(f"sha={sha}\nverified=true\n")
    except OSError as exc:
        raise SourceVerificationError("unable to emit verified source output") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected", required=True)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--github-output", type=Path)
    args = parser.parse_args(argv)

    try:
        sha = verify_source(args.expected, args.repo)
        if args.github_output is not None:
            _append_outputs(args.github_output, sha)
    except SourceVerificationError as exc:
        print(f"source verification failed: {exc}", file=sys.stderr)
        return 1

    print(sha)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
