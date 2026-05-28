# Social Poster

Free local CLI for posting text and photos to platforms that still allow practical API posting.

Supported now:

- Bluesky: text + up to 4 images
- Mastodon: text + up to 4 images
- Reddit: text posts or single image posts through PRAW

X/Twitter full auto-posting is not enabled because posting through the official X API usually requires paid/approved access. A free X compose-draft helper is included.

## Setup

```bash
cd social-poster
python3 -m pip install --user -r requirements.txt
cp .env.example .env
```

Fill `.env` with credentials for the platforms you want.

## Post text only

```bash
python3 post.py --platforms bluesky,mastodon --text "Shipping Interlock updates from the command line."
```

## Post with a photo

```bash
python3 post.py --platforms bluesky,mastodon --text "Interlock demo screenshot" --image ./screenshot.png --alt "Interlock dashboard screenshot"
```

## Post to Reddit

Text/self post:

```bash
python3 post.py --platforms reddit --subreddit test --title "Interlock update" --text "Runtime security gateway for AI agents."
```

Image post:

```bash
python3 post.py --platforms reddit --subreddit test --title "Interlock screenshot" --image ./screenshot.png
```

## Dry run

```bash
python3 post.py --platforms bluesky,mastodon,reddit --subreddit test --title "Test" --text "Hello" --image ./screenshot.png --dry-run
```


## Prepared Interlock launch post

I prepared the dashboard/demo screenshots and captions here:

- `assets/interlock-dashboard.png`
- `assets/interlock-demo.png`
- `posts/interlock_caption_social.txt`
- `posts/interlock_caption_x.txt`
- `posts/interlock_reddit_title.txt`
- `posts/interlock_reddit_text.txt`

Post to Bluesky + Mastodon after `.env` is filled:

```bash
./post_interlock.sh
```

Dry-run it first:

```bash
python3 post.py \
  --platforms bluesky,mastodon \
  --text-file posts/interlock_caption_social.txt \
  --image assets/interlock-dashboard.png \
  --image assets/interlock-demo.png \
  --alt "$(cat posts/interlock_alt_dashboard.txt)" \
  --alt "$(cat posts/interlock_alt_demo.txt)" \
  --dry-run
```

Open a free X/Twitter compose draft:

```bash
./x_interlock_draft.sh
```

On Windows you can also run:

```bat
x_interlock_draft.bat
```

Important: X Web Intent is free but cannot attach local images automatically. The script opens the X compose box, copies the caption, and opens the image location so you can attach the screenshots manually. Fully automatic X image posting requires X API access, which is pay-per-usage.

Post to Reddit after `.env` is filled:

```bash
python3 post.py \
  --platforms reddit \
  --subreddit YOUR_SUBREDDIT \
  --title "$(cat posts/interlock_reddit_title.txt)" \
  --text-file posts/interlock_reddit_text.txt \
  --image assets/interlock-dashboard.png
```


## Daily automation

A Windows Task Scheduler job is installed:

- Name: `Interlock Daily Social Post`
- Time: 10:00 AM daily
- Command: `D:\llm-firewall\social-poster\daily_post.bat`

The daily queue lives here:

- `series/interlock_build_story.json`
- `state/daily_post_state.json`
- `logs/daily_post.log`

Run today's queued post manually:

```bash
python3 daily_post.py --platforms x,reddit
```

Preview without posting/opening anything permanent:

```bash
python3 daily_post.py --platforms x,reddit --subreddit test --dry-run
```

Reddit will only fully auto-post after `.env` contains real Reddit credentials and `REDDIT_SUBREDDIT`. X free mode opens a compose draft and copies the caption; you still attach images and click Post manually unless you pay for official X API access.
