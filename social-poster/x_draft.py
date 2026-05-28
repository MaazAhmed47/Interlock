#!/usr/bin/env python3
"""Free X/Twitter draft helper.

This uses official X Web Intent, which is free but requires a human click to post.
X Web Intent cannot attach local images automatically, so this opens the image folder
and copies the caption to your clipboard.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlencode


def read_text(args: argparse.Namespace) -> str:
    if args.text_file:
        return Path(args.text_file).read_text(encoding="utf-8").strip()
    return (args.text or "").strip()


def win_path(path: Path) -> str:
    try:
        return subprocess.check_output(["wslpath", "-w", str(path)], text=True).strip()
    except Exception:
        raw = str(path)
        if raw.startswith("/mnt/") and len(raw) > 6:
            drive = raw[5].upper()
            rest = raw[7:].replace("/", "\\")
            return f"{drive}:\\{rest}"
        return raw


def copy_clipboard(text: str) -> bool:
    try:
        subprocess.run(["clip.exe"], input=text, text=True, check=True)
        return True
    except Exception:
        return False


def open_url(url: str) -> bool:
    try:
        subprocess.run(["cmd.exe", "/c", "start", "", url], check=True)
        return True
    except Exception:
        return False


def reveal_image(path: Path) -> None:
    try:
        subprocess.run(["explorer.exe", "/select,", win_path(path)], check=False)
    except Exception:
        pass


def main() -> int:
    parser = argparse.ArgumentParser(description="Open a free X/Twitter draft with your caption")
    parser.add_argument("--text", help="Draft text")
    parser.add_argument("--text-file", help="Read draft text from a file")
    parser.add_argument("--image", action="append", default=[], help="Image to attach manually in X. Repeat for multiple images.")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    text = read_text(args)
    if not text:
        raise SystemExit("Provide --text or --text-file")
    if len(text) > 280:
        raise SystemExit(f"X draft is {len(text)} chars; keep it <= 280")

    images = [Path(p).expanduser().resolve() for p in args.image]
    missing = [str(p) for p in images if not p.exists()]
    if missing:
        raise SystemExit("Missing image(s): " + ", ".join(missing))

    url = "https://twitter.com/intent/tweet?" + urlencode({"text": text})

    if args.dry_run:
        print("X draft URL:", url)
        print("Images to attach manually:")
        for image in images:
            print("-", image)
        return 0

    copied = copy_clipboard(text)
    opened = open_url(url)
    if images:
        reveal_image(images[0])

    print("Opened X compose draft." if opened else "Could not open X compose automatically.")
    print("Caption copied to clipboard." if copied else "Could not copy caption to clipboard; paste it manually from the file.")
    if images:
        print("X Web Intent cannot auto-attach local images. Attach these manually:")
        for image in images:
            print("-", image)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
