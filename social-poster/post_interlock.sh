#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
python3 post.py \
  --platforms bluesky,mastodon \
  --text-file posts/interlock_caption_social.txt \
  --image assets/interlock-dashboard.png \
  --image assets/interlock-demo.png \
  --alt "$(cat posts/interlock_alt_dashboard.txt)" \
  --alt "$(cat posts/interlock_alt_demo.txt)"
