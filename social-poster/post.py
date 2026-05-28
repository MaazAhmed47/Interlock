#!/usr/bin/env python3
"""Post text and photos to free-ish social APIs from the command line.

Supported:
- Bluesky: direct AT Protocol HTTP calls, text + up to 4 images.
- Mastodon: direct API calls, text + up to 4 media attachments.
- Reddit: PRAW, text/self posts or one image post.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import mimetypes
import os
import sys
import time
from pathlib import Path
from typing import Any

import requests
from dotenv import load_dotenv

BSKY_SERVICE = "https://bsky.social"
MAX_IMAGES = 4
MAX_BSKY_IMAGE_BYTES = 2 * 1024 * 1024


class ConfigError(RuntimeError):
    pass


def env(name: str, required: bool = True) -> str | None:
    value = os.getenv(name)
    if required and not value:
        raise ConfigError(f"Missing {name}. Add it to social-poster/.env")
    return value


def read_text(args: argparse.Namespace) -> str:
    if args.text_file:
        return Path(args.text_file).read_text(encoding="utf-8").strip()
    return (args.text or "").strip()


def validate_images(image_paths: list[str]) -> list[Path]:
    paths = [Path(p).expanduser().resolve() for p in image_paths]
    for path in paths:
        if not path.exists():
            raise FileNotFoundError(f"Image not found: {path}")
        if not path.is_file():
            raise FileNotFoundError(f"Not a file: {path}")
    return paths


def mime_for(path: Path) -> str:
    mime, _ = mimetypes.guess_type(path.name)
    if not mime or not mime.startswith("image/"):
        raise ValueError(f"Could not detect image MIME type for {path}")
    return mime


def alt_texts(alts: list[str], count: int) -> list[str]:
    if not alts:
        return [""] * count
    if len(alts) == 1 and count > 1:
        return alts * count
    if len(alts) != count:
        raise ValueError("Provide either one --alt value or one --alt per --image")
    return alts


def bsky_session() -> dict[str, Any]:
    identifier = env("BLUESKY_HANDLE")
    password = env("BLUESKY_APP_PASSWORD")
    response = requests.post(
        f"{BSKY_SERVICE}/xrpc/com.atproto.server.createSession",
        json={"identifier": identifier, "password": password},
        timeout=30,
    )
    response.raise_for_status()
    return response.json()


def post_bluesky(text: str, images: list[Path], alts: list[str], dry_run: bool = False) -> dict[str, Any]:
    if len(images) > MAX_IMAGES:
        raise ValueError("Bluesky supports up to 4 images per post")
    if len(text) > 300:
        raise ValueError("Bluesky text limit is 300 characters")
    for path in images:
        if path.stat().st_size > MAX_BSKY_IMAGE_BYTES:
            raise ValueError(f"Bluesky image must be <= 2MB: {path}")

    if dry_run:
        return {"platform": "bluesky", "dry_run": True, "text": text, "images": [str(p) for p in images]}

    session = bsky_session()
    token = session["accessJwt"]
    repo = session["did"]
    uploaded = []

    for path, alt in zip(images, alts):
        blob_response = requests.post(
            f"{BSKY_SERVICE}/xrpc/com.atproto.repo.uploadBlob",
            headers={"Authorization": f"Bearer {token}", "Content-Type": mime_for(path)},
            data=path.read_bytes(),
            timeout=150,
        )
        blob_response.raise_for_status()
        uploaded.append({"alt": alt, "image": blob_response.json()["blob"]})

    record: dict[str, Any] = {
        "$type": "app.bsky.feed.post",
        "text": text,
        "createdAt": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    if uploaded:
        record["embed"] = {"$type": "app.bsky.embed.images", "images": uploaded}

    post_response = requests.post(
        f"{BSKY_SERVICE}/xrpc/com.atproto.repo.createRecord",
        headers={"Authorization": f"Bearer {token}"},
        json={"repo": repo, "collection": "app.bsky.feed.post", "record": record},
        timeout=30,
    )
    post_response.raise_for_status()
    data = post_response.json()
    return {"platform": "bluesky", "uri": data.get("uri"), "cid": data.get("cid")}


def post_mastodon(text: str, images: list[Path], alts: list[str], dry_run: bool = False) -> dict[str, Any]:
    if len(images) > MAX_IMAGES:
        raise ValueError("Most Mastodon instances support up to 4 media attachments per status")

    if dry_run:
        return {"platform": "mastodon", "dry_run": True, "text": text, "images": [str(p) for p in images]}

    instance = (env("MASTODON_INSTANCE") or "").rstrip("/")
    token = env("MASTODON_ACCESS_TOKEN")
    headers = {"Authorization": f"Bearer {token}"}
    media_ids: list[str] = []
    for path, alt in zip(images, alts):
        with path.open("rb") as f:
            response = requests.post(
                f"{instance}/api/v2/media",
                headers=headers,
                files={"file": (path.name, f, mime_for(path))},
                data={"description": alt} if alt else None,
                timeout=90,
            )
        response.raise_for_status()
        attachment = response.json()
        media_id = attachment["id"]
        media_ids.append(media_id)

        # Large media can be async. Poll briefly so the status has a ready attachment.
        if response.status_code == 202:
            for _ in range(20):
                check = requests.get(f"{instance}/api/v1/media/{media_id}", headers=headers, timeout=15)
                check.raise_for_status()
                if check.json().get("url"):
                    break
                time.sleep(1)

    data: list[tuple[str, str]] = [("status", text)]
    for media_id in media_ids:
        data.append(("media_ids[]", media_id))

    response = requests.post(f"{instance}/api/v1/statuses", headers=headers, data=data, timeout=30)
    response.raise_for_status()
    status = response.json()
    return {"platform": "mastodon", "id": status.get("id"), "url": status.get("url")}


def post_reddit(title: str, text: str, images: list[Path], alts: list[str] | None = None, dry_run: bool = False) -> dict[str, Any]:
    subreddit = env("REDDIT_SUBREDDIT", required=False)
    # CLI value wins over env, assigned by main before calling this function.
    subreddit = getattr(post_reddit, "subreddit", None) or subreddit
    alts = alts or [""] * len(images)
    if not subreddit:
        raise ConfigError("Missing subreddit. Pass --subreddit or set REDDIT_SUBREDDIT")
    if not title:
        raise ValueError("Reddit requires --title")

    if dry_run:
        return {
            "platform": "reddit",
            "dry_run": True,
            "subreddit": subreddit,
            "title": title,
            "text": text,
            "images": [str(p) for p in images],
        }

    import praw

    reddit = praw.Reddit(
        client_id=env("REDDIT_CLIENT_ID"),
        client_secret=env("REDDIT_CLIENT_SECRET"),
        username=env("REDDIT_USERNAME"),
        password=env("REDDIT_PASSWORD"),
        user_agent=env("REDDIT_USER_AGENT"),
    )
    target = reddit.subreddit(subreddit)
    if len(images) > 1:
        gallery = []
        for path, alt in zip(images, alts):
            item = {"image_path": str(path)}
            if alt:
                item["caption"] = alt[:180]
            gallery.append(item)
        submission = target.submit_gallery(title=title, images=gallery)
    elif images:
        submission = target.submit_image(title=title, image_path=str(images[0]))
    else:
        submission = target.submit(title=title, selftext=text)
    return {"platform": "reddit", "id": submission.id, "url": submission.url}


def main() -> int:
    parser = argparse.ArgumentParser(description="Post text/photos to free social APIs")
    parser.add_argument("--platforms", required=True, help="Comma-separated: bluesky,mastodon,reddit")
    parser.add_argument("--text", help="Post text")
    parser.add_argument("--text-file", help="Read post text from a file")
    parser.add_argument("--image", action="append", default=[], help="Image path. Repeat for multiple images.")
    parser.add_argument("--alt", action="append", default=[], help="Alt text. Repeat per image or provide one value for all.")
    parser.add_argument("--title", default="", help="Required for Reddit")
    parser.add_argument("--subreddit", help="Reddit subreddit name without r/")
    parser.add_argument("--dry-run", action="store_true", help="Validate and print what would be posted")
    args = parser.parse_args()

    load_dotenv(Path(__file__).with_name(".env"))

    text = read_text(args)
    images = validate_images(args.image)
    alts = alt_texts(args.alt, len(images))
    platforms = [p.strip().lower() for p in args.platforms.split(",") if p.strip()]
    if not text and not images:
        raise ValueError("Provide --text, --text-file, or at least one --image")

    post_reddit.subreddit = args.subreddit
    results = []
    for platform in platforms:
        if platform == "bluesky":
            results.append(post_bluesky(text, images, alts, args.dry_run))
        elif platform == "mastodon":
            results.append(post_mastodon(text, images, alts, args.dry_run))
        elif platform == "reddit":
            results.append(post_reddit(args.title, text, images, alts, args.dry_run))
        elif platform in {"x", "twitter"}:
            raise ConfigError("X/Twitter posting is not set up because official posting API access is not reliably free.")
        else:
            raise ValueError(f"Unsupported platform: {platform}")

    print(json.dumps({"ok": True, "results": results}, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, indent=2), file=sys.stderr)
        raise SystemExit(1)
