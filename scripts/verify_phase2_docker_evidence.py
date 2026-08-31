"""Fail-closed verifier for retained Docker Phase 2 evidence."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

try:
    from scripts.phase2_topology_evidence import (
        TOPOLOGY_FILES,
        source_bundle_sha256,
        validate_topology_evidence,
    )
except ModuleNotFoundError:  # direct script execution
    from phase2_topology_evidence import (  # type: ignore[no-redef]
        TOPOLOGY_FILES,
        source_bundle_sha256,
        validate_topology_evidence,
    )

ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "deploy" / "phase2-docker"
sys.path.insert(0, str(PROFILE))
from phase2_cases import REQUIRED_CASES  # noqa: E402

SQUID_IMAGE = "ghcr.io/cybozu/squid:7.6.0.1@sha256:b5fff668ddbf5738a779ada37893569e6640d2a2ac384a834095ac443d12d60a"
SQUID_DIGEST = "sha256:b5fff668ddbf5738a779ada37893569e6640d2a2ac384a834095ac443d12d60a"
SAFE_PROJECT = re.compile(r"^interlock-p2-[a-f0-9]{12}$")
AUTHORIZATION_VALUE = re.compile(
    rb"(?:^|[\r\n,{])\s*[\"']?(?:proxy[-_])?authorization[\"']?\s*[:=]\s*[\"']?[^\s,\"'}]+",
    re.IGNORECASE,
)
CREDENTIAL_VALUE = re.compile(
    rb"(?:^|[\r\n,{;])\s*[\"']?(?:admin[-_]?token|api[-_]?key|access[-_]?token|client[-_]?secret|credential|password|passwd|refresh[-_]?token|secret)[\"']?\s*[:=]\s*[\"']?[^\s,;\"'}]+",
    re.IGNORECASE,
)
CREDENTIAL_BEARING_URL = re.compile(rb"https?://[^\s/\"']+:[^@\s/\"']+@", re.IGNORECASE)
DSN = re.compile(
    rb"\b(?:amqps?|cockroachdb|mariadb|mongodb(?:\+srv)?|mssql|mysql|oracle|postgres(?:ql)?|rediss?|snowflake|sqlserver)://",
    re.IGNORECASE,
)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def test_source_digest() -> str:
    paths = [
        PROFILE / name
        for name in (
            "Dockerfile",
            "acceptance.py",
            "certgen.py",
            "denied_sink.py",
            "dns_server.py",
            "healthcheck.py",
            "host_gateway_listener.py",
            "invalid-squid.conf",
            "origin.py",
            "phase2_cases.py",
            "topology_probe.py",
        )
    ] + [
        ROOT / "scripts" / "run_phase2_docker_acceptance.py",
        ROOT / "scripts" / "phase2_topology_evidence.py",
        Path(__file__).resolve(),
    ]
    return source_bundle_sha256(ROOT, paths)


def rendered_compose_digest(source_sha: str, project: str) -> str:
    environment = os.environ.copy()
    environment["INTERLOCK_SOURCE_SHA"] = source_sha
    rendered = subprocess.run(
        [
            "docker",
            "compose",
            "-p",
            project,
            "-f",
            str(PROFILE / "compose.yaml"),
            "config",
            "--format",
            "json",
        ],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=True,
    ).stdout
    return digest_bytes(rendered.encode("utf-8"))


def reject(condition: bool, message: str) -> None:
    if condition:
        raise ValueError(message)


def main() -> int:
    evidence = Path(sys.argv[1]).resolve()
    manifest_path = evidence / "manifest.json"
    results_path = evidence / "results.jsonl"
    junit_path = evidence / "junit.xml"
    manifest = json.loads(manifest_path.read_text("utf-8"))
    reject(
        manifest.get("schema") != "interlock.phase2-docker-evidence.v2",
        "wrong evidence schema",
    )
    reject(
        not re.fullmatch(r"[0-9a-f]{40}", str(manifest.get("source_sha", ""))),
        "malformed source SHA",
    )
    current_head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    reject(manifest.get("source_sha") != current_head, "evidence source is not HEAD")
    reject(
        manifest.get("source_dirty_development_run") is not False,
        "final evidence came from a dirty tree",
    )
    reject(manifest.get("squid_image") != SQUID_IMAGE, "wrong Squid image")
    reject(manifest.get("squid_image_digest") != SQUID_DIGEST, "wrong Squid digest")
    squid_config = PROFILE / "squid.conf"
    allowed_domains = PROFILE / "allowed-domains.txt"
    reject(
        manifest.get("squid_policy_sha256") != digest(squid_config),
        "Squid policy hash is stale",
    )
    reject(
        manifest.get("squid_allowed_domains_sha256") != digest(allowed_domains),
        "Squid allowlist hash is stale",
    )
    reject(
        manifest.get("squid_policy_bundle_sha256")
        != digest_bytes(squid_config.read_bytes() + allowed_domains.read_bytes()),
        "Squid policy bundle hash is stale",
    )
    reject(
        manifest.get("compose_source_sha256") != digest(PROFILE / "compose.yaml"),
        "Compose source hash is stale",
    )
    reject(
        not SAFE_PROJECT.fullmatch(str(manifest.get("compose_project_name", ""))),
        "unsafe Compose project identity",
    )
    reject(
        manifest.get("project_name_hash")
        != digest_bytes(manifest["compose_project_name"].encode("ascii")),
        "Compose project identity hash mismatch",
    )
    reject(
        manifest.get("compose_rendered_sha256")
        != rendered_compose_digest(
            manifest["source_sha"], manifest["compose_project_name"]
        ),
        "rendered Compose hash is stale",
    )
    reject(
        manifest.get("test_source_sha256") != test_source_digest(),
        "test source hash is stale",
    )
    sentinel_hashes = manifest.get("sentinel_sha256")
    reject(
        not isinstance(sentinel_hashes, dict)
        or set(sentinel_hashes) != {"authorization", "proxy_credential", "query"}
        or any(
            not re.fullmatch(r"[0-9a-f]{64}", str(value))
            for value in sentinel_hashes.values()
        ),
        "sentinel hash evidence is malformed",
    )
    reject(
        manifest.get("required_cases") != list(REQUIRED_CASES),
        "required case contract is stale",
    )
    reject(
        manifest.get("expected_case_count") != len(REQUIRED_CASES),
        "expected count mismatch",
    )
    lines = results_path.read_text("utf-8").splitlines()
    results = [json.loads(line) for line in lines]
    reject(len(results) != len(REQUIRED_CASES), "partial result set")
    reject(
        any(set(item) != {"case", "category", "outcome"} for item in results),
        "malformed result",
    )
    names = [item["case"] for item in results]
    reject(
        names != list(REQUIRED_CASES), "missing, extra, duplicate, or reordered cases"
    )
    reject(any(item["outcome"] != "passed" for item in results), "failed case retained")
    reject(
        manifest.get("executed_case_count") != len(results), "executed count mismatch"
    )
    reject(manifest.get("passed_case_count") != len(results), "passed count mismatch")
    reject(manifest.get("failed_case_count") != 0, "failure counter is nonzero")
    reject(
        manifest.get("results_sha256") != digest(results_path),
        "results digest mismatch",
    )

    suite = ET.parse(junit_path).getroot()
    reject(suite.tag != "testsuite", "malformed JUnit root")
    reject(
        int(suite.attrib.get("tests", "-1")) != len(results),
        "JUnit test count mismatch",
    )
    reject(
        any(
            int(suite.attrib.get(name, "-1")) != 0
            for name in ("failures", "errors", "skipped")
        ),
        "JUnit non-pass counter",
    )
    junit_names = [item.attrib.get("name") for item in suite.findall("testcase")]
    reject(junit_names != list(REQUIRED_CASES), "JUnit identity mismatch")
    reject(
        bool(
            suite.findall(".//failure")
            or suite.findall(".//error")
            or suite.findall(".//skipped")
        ),
        "JUnit contains non-pass nodes",
    )
    junit_text = junit_path.read_text("utf-8").lower()
    reject(
        "xfail" in junit_text or "xpass" in junit_text,
        "JUnit contains xfail/xpass evidence",
    )

    artifacts = manifest.get("artifact_sha256")
    reject(not isinstance(artifacts, dict), "artifact hash map missing")
    actual_files = {
        path.name
        for path in evidence.iterdir()
        if path.is_file() and path.name != "manifest.json"
    }
    reject(set(artifacts) != actual_files, "artifact inventory mismatch")
    for name, expected in artifacts.items():
        reject(
            not re.fullmatch(r"[0-9a-f]{64}", str(expected)),
            "malformed artifact digest",
        )
        reject(digest(evidence / name) != expected, "artifact digest mismatch")

    topology_hashes = manifest.get("topology_artifact_sha256")
    reject(not isinstance(topology_hashes, dict), "topology artifact hash map missing")
    reject(
        set(topology_hashes) != set(TOPOLOGY_FILES),
        "topology artifact inventory mismatch",
    )
    for name in TOPOLOGY_FILES:
        reject(
            topology_hashes.get(name) != artifacts.get(name),
            "topology artifact digest mismatch",
        )
    validate_topology_evidence(evidence)
    runtime = json.loads(
        (evidence / "topology-runtime-versions.json").read_text("utf-8")
    )
    reject(
        manifest.get("docker_client_version") != runtime["docker_client"]["version"],
        "Docker client version evidence mismatch",
    )
    reject(
        manifest.get("docker_server_version") != runtime["docker_server"]["version"],
        "Docker server version evidence mismatch",
    )
    reject(
        manifest.get("docker_server_os") != runtime["docker_server"]["os"],
        "Docker server OS evidence mismatch",
    )
    reject(
        manifest.get("compose_version") != runtime["compose"],
        "Compose version evidence mismatch",
    )

    retained_paths = [path for path in evidence.iterdir() if path.is_file()]
    retained = b"\n".join(path.read_bytes() for path in retained_paths).lower()
    disclosure_manifest = dict(manifest)
    disclosure_manifest.pop("sentinel_sha256", None)
    disclosure_retained = b"\n".join(
        (
            json.dumps(disclosure_manifest, sort_keys=True).encode("utf-8")
            if path == manifest_path
            else path.read_bytes()
        )
        for path in retained_paths
    ).lower()
    reject(
        any(prefix in retained for prefix in (b"p2q_", b"p2a_", b"p2c_")),
        "retained sentinel disclosure",
    )
    reject(
        AUTHORIZATION_VALUE.search(disclosure_retained) is not None,
        "retained authorization disclosure",
    )
    reject(
        CREDENTIAL_VALUE.search(disclosure_retained) is not None
        or CREDENTIAL_BEARING_URL.search(disclosure_retained) is not None
        or DSN.search(disclosure_retained) is not None
        or any(
            marker in disclosure_retained
            for marker in (
                b"http://squid:3128",
                b"phase2-postgres-only",
                b"phase2-admin-only",
                b"bearer ",
                b"basic ",
            )
        ),
        "retained credential or connection disclosure",
    )
    reject(
        re.search(rb"https?://[^\s\"']*\?", disclosure_retained) is not None,
        "retained URL query disclosure",
    )
    print(
        json.dumps(
            {
                "verified": True,
                "source_sha": manifest["source_sha"],
                "case_count": len(results),
                "results_sha256": manifest["results_sha256"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (
        OSError,
        subprocess.SubprocessError,
        ValueError,
        KeyError,
        TypeError,
        json.JSONDecodeError,
        ET.ParseError,
    ) as exc:
        print(f"Phase 2 evidence rejected: {type(exc).__name__}", file=sys.stderr)
        raise SystemExit(1)
