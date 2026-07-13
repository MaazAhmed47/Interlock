#!/usr/bin/env python3
"""Report new public MCP upstream releases against a reviewed local baseline."""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

GITHUB_API = "https://api.github.com"
USER_AGENT = "interlock-mcp-upstream-watch/1"


@dataclass(frozen=True)
class Release:
    tag: str
    url: str
    published_at: str
    prerelease: bool


def parse_releases(payload: list[dict[str, Any]]) -> list[Release]:
    releases = []
    for item in payload:
        tag = str(item.get("tag_name") or "").strip()
        if not tag or bool(item.get("draft")):
            continue
        releases.append(
            Release(
                tag=tag,
                url=str(item.get("html_url") or ""),
                published_at=str(item.get("published_at") or ""),
                prerelease=bool(item.get("prerelease")),
            )
        )
    return releases


def new_releases(
    releases: list[Release], known_tags: list[str], reviewed_through: str
) -> list[Release]:
    known = set(known_tags)
    return [
        release
        for release in releases
        if release.tag not in known and release.published_at > reviewed_through
    ]


def fetch_releases(repo: str) -> list[Release]:
    request = Request(
        f"{GITHUB_API}/repos/{repo}/releases?per_page=20",
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": USER_AGENT,
        },
    )
    with urlopen(
        request, timeout=20
    ) as response:  # nosec B310: fixed GitHub API origin
        payload = json.load(response)
    if not isinstance(payload, list):
        raise ValueError("GitHub releases response was not a list")
    return parse_releases(payload)


def build_report(baseline: dict[str, Any]) -> tuple[str, list[str], list[str]]:
    lines = [
        "# MCP upstream watch",
        "",
        "Public release check. This is a review signal, not an automatic compatibility claim.",
        "",
    ]
    markers: list[str] = []
    errors: list[str] = []

    for source in baseline["sources"]:
        source_id = source["id"]
        repo = source["repo"]
        lines.extend([f"## {source_id}", "", f"Focus: {source['focus']}", ""])
        reviewed_through = str(source.get("reviewed_through") or "")
        if not reviewed_through:
            errors.append(f"{source_id}: missing reviewed_through timestamp")
            lines.extend(["- Watch failed: missing reviewed-through timestamp.", ""])
            continue
        try:
            releases = fetch_releases(repo)
        except (
            HTTPError,
            URLError,
            TimeoutError,
            ValueError,
            json.JSONDecodeError,
        ) as exc:
            errors.append(f"{source_id}: {exc}")
            lines.extend([f"- Watch failed: `{exc}`", ""])
            continue

        changes = new_releases(
            releases, source.get("known_release_tags", []), reviewed_through
        )
        if not changes:
            lines.extend(["- No unreviewed releases.", ""])
            continue

        for release in changes:
            kind = "pre-release" if release.prerelease else "release"
            marker = f"{source_id}:{release.tag}"
            markers.append(marker)
            lines.append(
                f"- New {kind}: [{release.tag}]({release.url}) "
                f"published `{release.published_at}`. Marker: `{marker}`"
            )
        lines.append("")

    lines.extend(
        [
            "## Required review",
            "",
            "Classify each new item as `no action`, `test update`, `compatibility design`, or `supported behavior`. "
            "Only add a release tag and advance its reviewed-through timestamp in `docs/mcp-upstream-baseline.json` "
            "in the same reviewed change that records that decision.",
            "",
        ]
    )
    return "\n".join(lines), markers, errors


def write_github_output(path: Path, markers: list[str], errors: list[str]) -> None:
    with path.open("a", encoding="utf-8") as output:
        output.write(f"has_changes={'true' if markers else 'false'}\n")
        output.write(f"marker={','.join(markers)}\n")
        output.write(f"watch_errors={'true' if errors else 'false'}\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--baseline", type=Path, default=Path("docs/mcp-upstream-baseline.json")
    )
    parser.add_argument("--report", type=Path)
    parser.add_argument("--github-output", type=Path)
    args = parser.parse_args()

    baseline = json.loads(args.baseline.read_text(encoding="utf-8"))
    if baseline.get("schema_version") != 1 or not isinstance(
        baseline.get("sources"), list
    ):
        raise ValueError("Unsupported MCP upstream baseline format")

    report, markers, errors = build_report(baseline)
    if args.report:
        args.report.write_text(report + "\n", encoding="utf-8")
    else:
        print(report)
    if args.github_output:
        write_github_output(args.github_output, markers, errors)
    elif os.getenv("GITHUB_OUTPUT"):
        write_github_output(Path(os.environ["GITHUB_OUTPUT"]), markers, errors)

    if errors:
        print("MCP upstream watch completed with source errors.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
