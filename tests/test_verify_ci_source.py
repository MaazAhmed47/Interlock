from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from scripts import verify_ci_source

ROOT = Path(__file__).resolve().parents[1]
VERIFIER = ROOT / "scripts" / "verify_ci_source.py"


def _git(repo: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _clean_repo(tmp_path: Path) -> tuple[Path, str]:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init")
    _git(repo, "config", "user.name", "CI Contract")
    _git(repo, "config", "user.email", "ci-contract@example.invalid")
    (repo / "tracked.txt").write_text("verified\n", encoding="utf-8")
    _git(repo, "add", "tracked.txt")
    _git(repo, "commit", "-m", "fixture")
    return repo, _git(repo, "rev-parse", "HEAD")


def _run_verifier(
    repo: Path, expected: str, *, script: Path = VERIFIER, env: dict | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            "-I",
            str(script),
            "--expected",
            expected,
            "--repo",
            str(repo),
        ],
        cwd=repo,
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )


def test_verifier_succeeds_for_matching_clean_git_source(tmp_path):
    repo, head = _clean_repo(tmp_path)
    output = tmp_path / "github-output"
    completed = subprocess.run(
        [
            sys.executable,
            "-I",
            str(VERIFIER),
            "--expected",
            head,
            "--repo",
            str(repo),
            "--github-output",
            str(output),
        ],
        cwd=repo,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0
    assert completed.stdout == f"{head}\n"
    assert completed.stderr == ""
    assert output.read_text(encoding="utf-8") == f"sha={head}\nverified=true\n"


def test_verifier_rejects_wrong_or_malformed_expected_sha(tmp_path):
    repo, head = _clean_repo(tmp_path)

    wrong = _run_verifier(repo, "0" * 40)
    malformed = _run_verifier(repo, head.upper())

    assert wrong.returncode != 0
    assert wrong.stdout == ""
    assert wrong.stderr == (
        "source verification failed: source HEAD does not match expected SHA\n"
    )
    assert malformed.returncode != 0
    assert malformed.stdout == ""
    assert malformed.stderr == (
        "source verification failed: expected source SHA is invalid\n"
    )


def test_verifier_fails_when_git_rev_parse_fails(tmp_path):
    completed = _run_verifier(tmp_path, "0" * 40)

    assert completed.returncode != 0
    assert completed.stdout == ""
    assert completed.stderr == (
        "source verification failed: unable to read source HEAD\n"
    )


def test_verifier_fails_when_git_status_fails(monkeypatch, tmp_path):
    calls = 0

    def fake_run(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            return subprocess.CompletedProcess([], 0, stdout="a" * 40 + "\n")
        raise subprocess.CalledProcessError(2, ["git", "status"])

    monkeypatch.setattr(verify_ci_source.subprocess, "run", fake_run)

    with pytest.raises(
        verify_ci_source.SourceVerificationError,
        match="unable to read source worktree status",
    ):
        verify_ci_source.verify_source("a" * 40, tmp_path)


def test_verifier_rejects_dirty_worktree(tmp_path):
    repo, head = _clean_repo(tmp_path)
    (repo / "untracked-secret.txt").write_text("not logged\n", encoding="utf-8")

    completed = _run_verifier(repo, head)

    assert completed.returncode != 0
    assert completed.stdout == ""
    assert completed.stderr == (
        "source verification failed: source worktree is not clean\n"
    )
    assert "untracked-secret" not in completed.stderr


def test_contract_rejects_overwriting_actual_head_with_expected(tmp_path):
    repo, _head = _clean_repo(tmp_path)

    def assert_wrong_sha_is_rejected(script: Path) -> None:
        completed = _run_verifier(repo, "0" * 40, script=script)
        assert completed.returncode != 0

    assert_wrong_sha_is_rejected(VERIFIER)

    mutated = tmp_path / "verify_ci_source.py"
    source = VERIFIER.read_text(encoding="utf-8")
    old = 'head = _git(repo, "rev-parse", "HEAD", failure="unable to read source HEAD").strip()'
    assert old in source
    mutated.write_text(source.replace(old, "head = expected"), encoding="utf-8")

    with pytest.raises(AssertionError):
        assert_wrong_sha_is_rejected(mutated)


def test_isolated_python_and_mocked_git_failure_cannot_bypass_verification(tmp_path):
    repo, head = _clean_repo(tmp_path)
    shadow = tmp_path / "shadow"
    shadow.mkdir()
    (shadow / "subprocess.py").write_text("raise SystemExit(0)\n", encoding="utf-8")
    env = os.environ.copy()
    env["PYTHONPATH"] = str(shadow)

    isolated = _run_verifier(repo, head, env=env)

    assert isolated.returncode == 0
    assert isolated.stdout == f"{head}\n"

    def failed_git(*_args, **_kwargs):
        raise OSError("mocked git unavailable")

    original = verify_ci_source.subprocess.run
    try:
        verify_ci_source.subprocess.run = failed_git
        with pytest.raises(
            verify_ci_source.SourceVerificationError,
            match="unable to read source HEAD",
        ):
            verify_ci_source.verify_source(head, repo)
    finally:
        verify_ci_source.subprocess.run = original
