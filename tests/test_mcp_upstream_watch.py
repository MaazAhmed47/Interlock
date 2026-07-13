import importlib.util
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "mcp_upstream_watch.py"
SPEC = importlib.util.spec_from_file_location("mcp_upstream_watch", SCRIPT)
watch = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
sys.modules[SPEC.name] = watch
SPEC.loader.exec_module(watch)


def test_parse_releases_skips_drafts_and_missing_tags():
    releases = watch.parse_releases(
        [
            {
                "tag_name": "v2.0.0",
                "html_url": "https://example/v2",
                "published_at": "2026-01-01T00:00:00Z",
            },
            {"tag_name": "v2.1.0-rc", "draft": True},
            {"tag_name": ""},
        ]
    )

    assert [release.tag for release in releases] == ["v2.0.0"]


def test_new_releases_preserves_unreviewed_recent_prereleases():
    releases = [
        watch.Release("v1.0.0", "https://example/v1", "2026-01-01T00:00:00Z", False),
        watch.Release("v2.0.0-rc", "https://example/rc", "2026-01-02T00:00:00Z", True),
    ]

    changes = watch.new_releases(releases, ["v1.0.0"], "2026-01-01T12:00:00Z")

    assert [release.tag for release in changes] == ["v2.0.0-rc"]
