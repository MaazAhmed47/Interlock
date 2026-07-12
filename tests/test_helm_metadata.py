"""Helm metadata must match the package and must not claim nonexistent assets."""

import tomllib
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_helm_metadata_matches_pyproject_and_real_repository():
    package = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    chart = yaml.safe_load((ROOT / "helm" / "Chart.yaml").read_text(encoding="utf-8"))
    values = yaml.safe_load((ROOT / "helm" / "values.yaml").read_text(encoding="utf-8"))
    version = package["project"]["version"]

    assert chart["version"] == version
    assert chart["appVersion"] == version
    assert chart["sources"] == ["https://github.com/MaazAhmed47/Interlock"]
    assert values["image"] == {
        "repository": "interlock",
        "tag": version,
        "pullPolicy": "IfNotPresent",
        "pullSecrets": [],
    }
    assert "getinterlock/interlock" not in (ROOT / "helm" / "values.yaml").read_text(
        encoding="utf-8"
    )
