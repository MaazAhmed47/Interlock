#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
python3 x_draft.py \
  --text-file posts/interlock_caption_x.txt \
  --image assets/interlock-dashboard.png \
  --image assets/interlock-demo.png
