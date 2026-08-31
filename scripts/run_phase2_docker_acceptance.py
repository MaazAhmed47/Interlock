"""Run the uniquely-owned Docker Phase 2 profile and retain exact evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "deploy" / "phase2-docker"
COMPOSE = PROFILE / "compose.yaml"
SQUID_IMAGE = "ghcr.io/cybozu/squid:7.6.0.1@sha256:b5fff668ddbf5738a779ada37893569e6640d2a2ac384a834095ac443d12d60a"
SQUID_DIGEST = "sha256:b5fff668ddbf5738a779ada37893569e6640d2a2ac384a834095ac443d12d60a"
PROJECT_PREFIX = "interlock-p2-"
SAFE_PROJECT = re.compile(r"^interlock-p2-[a-f0-9]{12}$")

sys.path.insert(0, str(PROFILE))
from phase2_cases import REQUIRED_CASES  # noqa: E402


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def run(
    args: list[str],
    *,
    env: dict[str, str],
    check: bool = True,
    timeout: int = 1800,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        args,
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
    )
    if check and completed.returncode:
        raise RuntimeError(
            f"command failed safely: {args[0]} exit {completed.returncode}"
        )
    return completed


def compose(project: str, *args: str) -> list[str]:
    return ["docker", "compose", "-p", project, "-f", str(COMPOSE), *args]


def parse_results(output: str) -> list[dict[str, str]]:
    results: list[dict[str, str]] = []
    for line in output.splitlines():
        try:
            candidate = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(candidate, dict) and set(candidate) == {
            "case",
            "category",
            "outcome",
        }:
            results.append({key: str(value) for key, value in candidate.items()})
    return results


def inspect_json(args: list[str], env: dict[str, str]) -> Any:
    return json.loads(run(args, env=env).stdout)


def case(
    results: list[dict[str, str]], name: str, passed: bool, category: str = ""
) -> None:
    results.append(
        {
            "case": name,
            "category": category[:80],
            "outcome": "passed" if passed else "failed",
        }
    )


def write_junit(path: Path, results: list[dict[str, str]]) -> None:
    failures = sum(result["outcome"] != "passed" for result in results)
    suite = ET.Element(
        "testsuite",
        name="phase2_docker_acceptance",
        tests=str(len(results)),
        failures=str(failures),
        errors="0",
        skipped="0",
    )
    for result in results:
        item = ET.SubElement(
            suite, "testcase", classname="phase2.docker", name=result["case"]
        )
        if result["outcome"] != "passed":
            failure = ET.SubElement(
                item, "failure", message=result["category"] or "failed"
            )
            failure.text = "Phase 2 case failed; consult bounded category only."
    ET.ElementTree(suite).write(path, encoding="utf-8", xml_declaration=True)


def clean_text(value: str) -> str:
    lines = []
    for line in value.splitlines():
        if any(
            marker in line.lower()
            for marker in ("authorization:", "proxy-authorization:", "?")
        ):
            continue
        lines.append(line[:1000])
    return "\n".join(lines) + ("\n" if lines else "")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--allow-dirty-development-run", action="store_true")
    options = parser.parse_args()
    source_sha = options.source_sha.lower()
    if not re.fullmatch(r"[0-9a-f]{40}", source_sha):
        raise SystemExit("source SHA must be forty lowercase hexadecimal characters")
    head = run(["git", "rev-parse", "HEAD"], env=os.environ.copy()).stdout.strip()
    if head != source_sha:
        raise SystemExit("source SHA does not equal HEAD")
    dirty = bool(
        run(["git", "status", "--porcelain=v1"], env=os.environ.copy()).stdout.strip()
    )
    if dirty and not options.allow_dirty_development_run:
        raise SystemExit("final evidence requires a clean source worktree")
    output = options.output.resolve()
    if output.exists():
        raise SystemExit("evidence output must not already exist")
    output.mkdir(parents=True)
    project = PROJECT_PREFIX + uuid.uuid4().hex[:12]
    if not SAFE_PROJECT.fullmatch(project):
        raise SystemExit("unsafe generated Compose project name")
    env = os.environ.copy()
    env["INTERLOCK_SOURCE_SHA"] = source_sha
    sentinels = {
        "query": "p2q_" + uuid.uuid4().hex,
        "authorization": "p2a_" + uuid.uuid4().hex,
        "proxy_credential": "p2c_" + uuid.uuid4().hex,
    }
    sentinel_exec = [
        "-e",
        f"PHASE2_QUERY_SENTINEL={sentinels['query']}",
        "-e",
        f"PHASE2_AUTHORIZATION_SENTINEL={sentinels['authorization']}",
        "-e",
        f"PHASE2_PROXY_CREDENTIAL_SENTINEL={sentinels['proxy_credential']}",
    ]
    results: list[dict[str, str]] = []
    compose_rendered = ""
    docker_version: dict[str, Any] = {}
    compose_version = ""
    logs: dict[str, str] = {}
    started = time.time()
    try:
        docker_version = json.loads(
            run(["docker", "version", "--format", "{{json .}}"], env=env).stdout
        )
        compose_version = run(
            ["docker", "compose", "version", "--short"], env=env
        ).stdout.strip()
        compose_rendered = run(
            compose(project, "config", "--format", "json"), env=env
        ).stdout
        run(compose(project, "build", "--pull"), env=env, timeout=3600)
        run(
            compose(
                project, "pull", "--policy", "always", "postgres", "redis", "squid"
            ),
            env=env,
            timeout=1800,
        )
        run(
            compose(project, "up", "-d", "--wait", "--wait-timeout", "180"),
            env=env,
            timeout=600,
        )

        good_parse = run(
            compose(
                project,
                "exec",
                "-T",
                "squid",
                "squid",
                "-k",
                "parse",
                "-f",
                "/etc/squid/squid.conf",
            ),
            env=env,
            check=False,
        )
        bad_parse = run(
            compose(
                project,
                "exec",
                "-T",
                "squid",
                "squid",
                "-k",
                "parse",
                "-f",
                "/etc/squid/invalid-squid.conf",
            ),
            env=env,
            check=False,
        )
        case(results, "squid_policy_parses", good_parse.returncode == 0)
        malformed_policy_rejected = bad_parse.returncode != 0

        policy_text = (PROFILE / "squid.conf").read_text(encoding="utf-8").lower()
        case(
            results,
            "squid_no_tls_interception",
            "ssl_bump" not in policy_text and "https_port" not in policy_text,
        )
        case(results, "squid_via_enabled", "via off" not in policy_text)

        interlock_id = run(
            compose(project, "ps", "-q", "interlock"), env=env
        ).stdout.strip()
        squid_id = run(compose(project, "ps", "-q", "squid"), env=env).stdout.strip()
        interlock_inspect = inspect_json(["docker", "inspect", interlock_id], env)[0]
        squid_inspect = inspect_json(["docker", "inspect", squid_id], env)[0]
        interlock_networks = sorted(interlock_inspect["NetworkSettings"]["Networks"])
        squid_networks = sorted(squid_inspect["NetworkSettings"]["Networks"])
        case(
            results,
            "topology_interlock_app_network_only",
            len(interlock_networks) == 1 and interlock_networks[0].endswith("_app_net"),
        )
        case(
            results,
            "topology_proxy_only_upstream_bridge",
            len(squid_networks) == 3
            and any(name.endswith("_origin_net") for name in squid_networks)
            and any(name.endswith("_denied_net") for name in squid_networks),
        )
        network_ids = run(
            [
                "docker",
                "network",
                "ls",
                "--filter",
                f"label=com.docker.compose.project={project}",
                "--format",
                "{{.ID}}",
            ],
            env=env,
        ).stdout.split()
        network_data = [
            inspect_json(["docker", "network", "inspect", network_id], env)[0]
            for network_id in network_ids
        ]
        case(
            results,
            "topology_ipv6_enabled_all_networks",
            len(network_data) == 3
            and all(item.get("EnableIPv6") is True for item in network_data),
        )

        image_data = inspect_json(["docker", "image", "inspect", SQUID_IMAGE], env)[0]
        repo_digests = image_data.get("RepoDigests") or []
        case(
            results,
            "squid_image_digest_exact",
            any(value.endswith("@" + SQUID_DIGEST) for value in repo_digests),
        )

        direct = run(
            compose(
                project,
                "exec",
                "-T",
                *sentinel_exec,
                "-e",
                "PHASE2_CA_FILE=/tmp/not-used",
                "interlock",
                "python",
                "/app/deploy/phase2-docker/acceptance.py",
                "direct-only",
            ),
            env=env,
            check=False,
        )
        results.extend(parse_results(direct.stdout))

        acceptance = run(
            compose(
                project,
                "exec",
                "-T",
                *sentinel_exec,
                "acceptance",
                "python",
                "/app/deploy/phase2-docker/acceptance.py",
            ),
            env=env,
            check=False,
            timeout=900,
        )
        results.extend(parse_results(acceptance.stdout))

        run(compose(project, "stop", "squid"), env=env)
        proxy_down = run(
            compose(
                project,
                "exec",
                "-T",
                *sentinel_exec,
                "acceptance",
                "python",
                "/app/deploy/phase2-docker/acceptance.py",
                "proxy-down",
            ),
            env=env,
            check=False,
        )
        proxy_down_results = parse_results(proxy_down.stdout)
        results.extend(proxy_down_results)
        case(
            results,
            "squid_malformed_policy_rejected",
            malformed_policy_rejected
            and any(
                item["case"] == "proxy_unavailable_no_fallback"
                and item["outcome"] == "passed"
                for item in proxy_down_results
            ),
        )
        run(compose(project, "start", "squid"), env=env)

        for service in ("origin", "denied_sink", "dns", "squid", "interlock"):
            raw = run(
                compose(project, "logs", "--no-color", service), env=env, check=False
            ).stdout
            raw_lower = raw.lower()
            if any(value.lower() in raw_lower for value in sentinels.values()):
                raise RuntimeError("raw service log disclosed a run sentinel")
            if (
                "proxy-authorization:" in raw_lower
                or "authorization: bearer" in raw_lower
            ):
                raise RuntimeError("raw service log disclosed an authorization field")
            logs[service] = clean_text(raw)
            (output / f"{service}.log").write_text(
                logs[service], encoding="utf-8", newline="\n"
            )
        case(
            results,
            "denied_sink_zero_requests",
            "denied_connection" not in logs["denied_sink"],
        )
        case(
            results,
            "origin_safe_log_fields_only",
            all(
                term not in logs["origin"].lower()
                for term in ("query", 'authorization": "', "body")
            ),
        )
        case(
            results,
            "wrong_hostname_origin_zero_http_requests",
            '"route": "/wrong-host-proof"' not in logs["origin"],
        )
        case(
            results,
            "untrusted_ca_origin_zero_http_requests",
            '"route": "/untrusted-ca-proof"' not in logs["origin"],
        )
        case(
            results,
            "proxy_safe_log_fields_only",
            all(
                term not in logs["squid"].lower()
                for term in ("http://", "https://", "authorization", "?")
            ),
        )

        combined_logs = "\n".join(logs.values()).lower()
        case(
            results,
            "retained_logs_sentinel_free",
            not any(value.lower() in combined_logs for value in sentinels.values()),
        )
        case(results, "junit_sentinel_free", True)
        case(results, "manifest_sentinel_free", True)

        names = [item["case"] for item in results]
        unexpected = sorted(set(names) - set(REQUIRED_CASES))
        missing = sorted(set(REQUIRED_CASES) - set(names))
        duplicates = sorted({name for name in names if names.count(name) != 1})
        if unexpected or missing or duplicates:
            raise RuntimeError(
                "case contract mismatch: "
                f"missing={missing!r} unexpected={unexpected!r} duplicates={duplicates!r}"
            )
        results.sort(key=lambda item: REQUIRED_CASES.index(item["case"]))
        result_path = output / "results.jsonl"
        result_path.write_text(
            "".join(json.dumps(item, sort_keys=True) + "\n" for item in results),
            encoding="utf-8",
            newline="\n",
        )
        junit_path = output / "junit.xml"
        write_junit(junit_path, results)
        artifact_hashes = {
            path.name: sha256_file(path)
            for path in sorted(output.iterdir())
            if path.is_file() and path.name != "manifest.json"
        }
        test_sources = [
            PROFILE / name
            for name in (
                "Dockerfile",
                "acceptance.py",
                "certgen.py",
                "denied_sink.py",
                "dns_server.py",
                "healthcheck.py",
                "invalid-squid.conf",
                "origin.py",
                "phase2_cases.py",
            )
        ] + [
            Path(__file__).resolve(),
            ROOT / "scripts" / "verify_phase2_docker_evidence.py",
        ]
        test_source_hash = sha256_bytes(
            b"".join(
                path.read_bytes()
                for path in sorted(
                    test_sources,
                    key=lambda item: item.relative_to(ROOT).as_posix(),
                )
            )
        )
        manifest = {
            "schema": "interlock.phase2-docker-evidence.v1",
            "source_sha": source_sha,
            "source_dirty_development_run": dirty,
            "squid_image": SQUID_IMAGE,
            "squid_image_digest": SQUID_DIGEST,
            "squid_policy_sha256": sha256_file(PROFILE / "squid.conf"),
            "squid_allowed_domains_sha256": sha256_file(
                PROFILE / "allowed-domains.txt"
            ),
            "squid_policy_bundle_sha256": sha256_bytes(
                (PROFILE / "squid.conf").read_bytes()
                + (PROFILE / "allowed-domains.txt").read_bytes()
            ),
            "compose_source_sha256": sha256_file(COMPOSE),
            "compose_rendered_sha256": sha256_bytes(compose_rendered.encode("utf-8")),
            "test_source_sha256": test_source_hash,
            "docker_client_version": docker_version.get("Client", {}).get("Version"),
            "docker_server_version": docker_version.get("Server", {}).get("Version"),
            "docker_server_os": docker_version.get("Server", {}).get("Os"),
            "compose_version": compose_version,
            "compose_project_name": project,
            "project_name_hash": sha256_bytes(project.encode("ascii")),
            "expected_case_count": len(REQUIRED_CASES),
            "executed_case_count": len(results),
            "passed_case_count": sum(item["outcome"] == "passed" for item in results),
            "failed_case_count": sum(item["outcome"] != "passed" for item in results),
            "required_cases": list(REQUIRED_CASES),
            "results_sha256": sha256_file(result_path),
            "artifact_sha256": artifact_hashes,
            "sentinel_sha256": {
                name: sha256_bytes(value.encode("ascii"))
                for name, value in sorted(sentinels.items())
            },
            "duration_seconds": round(time.time() - started, 3),
        }
        (output / "manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        retained = b"\n".join(
            path.read_bytes() for path in output.iterdir() if path.is_file()
        )
        if any(value.encode("ascii") in retained for value in sentinels.values()):
            raise RuntimeError("retained Phase 2 evidence disclosed a run sentinel")
    finally:
        if SAFE_PROJECT.fullmatch(project):
            run(
                compose(
                    project, "down", "--volumes", "--remove-orphans", "--timeout", "10"
                ),
                env=env,
                check=False,
                timeout=180,
            )
    verifier = run(
        [
            sys.executable,
            str(ROOT / "scripts" / "verify_phase2_docker_evidence.py"),
            str(output),
        ],
        env=env,
        check=False,
    )
    sys.stdout.write(verifier.stdout)
    sys.stderr.write(verifier.stderr)
    return verifier.returncode


if __name__ == "__main__":
    raise SystemExit(main())
