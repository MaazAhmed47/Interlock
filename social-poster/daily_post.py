#!/usr/bin/env python3
"""Daily Interlock social posting runner.

Free mode:
- X/Twitter: opens a prefilled compose draft (manual final click + image attach).
- Reddit: fully posts through Reddit API/PRAW after credentials + subreddit are set.

The queue lives in series/interlock_build_story.json and advances after a successful run.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from post import ConfigError, post_bluesky, post_mastodon, post_reddit, validate_images

BASE = Path(__file__).resolve().parent
SERIES_FILE = BASE / "series" / "interlock_build_story.json"
STATE_FILE = BASE / "state" / "daily_post_state.json"
LOG_FILE = BASE / "logs" / "daily_post.log"
DEFAULT_PLATFORMS = "x,bluesky,reddit"

ALT_BY_NAME = {
    "interlock-dashboard.png": "Interlock dashboard showing usage, MCP servers, drift and quarantine status, shadow findings, quick actions, and demo prompt library.",
    "interlock-dashboard.jpg": "Interlock dashboard showing usage, MCP servers, drift and quarantine status, shadow findings, quick actions, and demo prompt library.",
    "interlock-demo.png": "Interlock integration demo showing Python, JavaScript, and API examples for routing AI requests through the gateway.",
    "interlock-demo.jpg": "Interlock integration demo showing Python, JavaScript, and API examples for routing AI requests through the gateway.",
}


def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def save_json(path: Path, value: Any) -> None:
    path.parent.mkdir(exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def log_line(message: str) -> None:
    LOG_FILE.parent.mkdir(exist_ok=True)
    stamp = dt.datetime.now().isoformat(timespec="seconds")
    LOG_FILE.write_text((LOG_FILE.read_text(encoding="utf-8") if LOG_FILE.exists() else "") + f"[{stamp}] {message}\n", encoding="utf-8")


def resolve_images(post: dict[str, Any]) -> list[Path]:
    return validate_images([str(BASE / item) for item in post.get("images", [])])


def post_to_x(post: dict[str, Any], images: list[Path], dry_run: bool) -> dict[str, Any]:
    text = post["x_text"]
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False, suffix=".txt") as handle:
        handle.write(text)
        temp_path = handle.name

    try:
        cmd = [sys.executable, str(BASE / "x_draft.py"), "--text-file", temp_path]
        for image in images:
            cmd.extend(["--image", str(image)])
        if dry_run:
            cmd.append("--dry-run")
        completed = subprocess.run(cmd, cwd=str(BASE), text=True, capture_output=True)
        if completed.returncode != 0:
            raise RuntimeError(completed.stderr.strip() or completed.stdout.strip() or "X draft failed")
        return {"platform": "x", "mode": "free-compose-draft", "ok": True, "output": completed.stdout.strip()}
    finally:
        Path(temp_path).unlink(missing_ok=True)


def image_alts(images: list[Path]) -> list[str]:
    return [ALT_BY_NAME.get(path.name, "") for path in images]


def post_to_bluesky(post: dict[str, Any], images: list[Path], dry_run: bool) -> dict[str, Any]:
    return post_bluesky(post["x_text"], images, image_alts(images), dry_run)


def post_to_mastodon(post: dict[str, Any], images: list[Path], dry_run: bool) -> dict[str, Any]:
    return post_mastodon(post["x_text"], images, image_alts(images), dry_run)


def is_placeholder(value: str | None) -> bool:
    if not value:
        return True
    lowered = value.lower()
    return lowered.startswith("your-") or lowered.startswith("xxxx") or "your_" in lowered or "your-" in lowered or lowered.startswith("your")


def post_to_reddit(post: dict[str, Any], images: list[Path], dry_run: bool, subreddit: str | None) -> dict[str, Any]:
    subreddit = subreddit or os.getenv("REDDIT_SUBREDDIT")
    required = {
        "REDDIT_CLIENT_ID": os.getenv("REDDIT_CLIENT_ID"),
        "REDDIT_CLIENT_SECRET": os.getenv("REDDIT_CLIENT_SECRET"),
        "REDDIT_USERNAME": os.getenv("REDDIT_USERNAME"),
        "REDDIT_PASSWORD": os.getenv("REDDIT_PASSWORD"),
        "REDDIT_USER_AGENT": os.getenv("REDDIT_USER_AGENT"),
        "REDDIT_SUBREDDIT": subreddit,
    }
    missing = [key for key, value in required.items() if is_placeholder(value)]
    if missing and not dry_run:
        raise ConfigError("Reddit is not configured yet. Fill these in social-poster/.env: " + ", ".join(missing))

    post_reddit.subreddit = subreddit
    return post_reddit(post["reddit_title"], post["reddit_text"], images, image_alts(images), dry_run)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the next daily Interlock social post")
    parser.add_argument("--platforms", default=os.getenv("DAILY_PLATFORMS", DEFAULT_PLATFORMS), help="Comma-separated: x,reddit")
    parser.add_argument("--subreddit", default=os.getenv("REDDIT_SUBREDDIT"), help="Target subreddit without r/")
    parser.add_argument("--index", type=int, help="Post a specific queue index instead of state next_index")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--no-advance", action="store_true", help="Do not advance queue state after a successful non-dry run")
    args = parser.parse_args()

    load_dotenv(BASE / ".env")
    series = load_json(SERIES_FILE, [])
    if not series:
        raise ConfigError(f"No post series found at {SERIES_FILE}")

    state = load_json(STATE_FILE, {"next_index": 0, "history": []})
    index = args.index if args.index is not None else int(state.get("next_index", 0))
    post = series[index % len(series)]
    images = resolve_images(post)
    platforms = [item.strip().lower() for item in args.platforms.split(",") if item.strip()]

    results = []
    failures = []
    for platform in platforms:
        try:
            if platform in {"x", "twitter"}:
                results.append(post_to_x(post, images, args.dry_run))
            elif platform == "bluesky":
                results.append(post_to_bluesky(post, images, args.dry_run))
            elif platform == "mastodon":
                results.append(post_to_mastodon(post, images, args.dry_run))
            elif platform == "reddit":
                results.append(post_to_reddit(post, images, args.dry_run, args.subreddit))
            else:
                raise ValueError(f"Unsupported daily platform: {platform}")
        except Exception as exc:
            failures.append({"platform": platform, "error": str(exc)})

    should_advance = bool(results) and not args.dry_run and not args.no_advance and args.index is None
    if should_advance:
        state["next_index"] = (index + 1) % len(series)
        state.setdefault("history", []).append({
            "id": post["id"],
            "index": index,
            "posted_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "platforms": platforms,
            "results": results,
            "failures": failures,
        })
        save_json(STATE_FILE, state)

    output = {
        "ok": bool(results) and not failures,
        "post_id": post["id"],
        "title": post["title"],
        "index": index,
        "advanced": should_advance,
        "results": results,
        "failures": failures,
    }
    log_line(json.dumps(output, ensure_ascii=True))
    print(json.dumps(output, indent=2))
    return 0 if results else 1


if __name__ == "__main__":
    raise SystemExit(main())
