"""Create, verify, and destroy the disposable kind enforcement lab."""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import platform
import secrets
import shutil
import subprocess
import tempfile
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from scripts.kubernetes_enforcement_cases import REQUIRED_CASES
    from scripts.verify_kubernetes_enforcement_evidence import (
        EvidenceVerificationError,
        parse_probe_output,
        verify_report,
    )
except ModuleNotFoundError:  # direct script execution
    from kubernetes_enforcement_cases import REQUIRED_CASES  # type: ignore[no-redef]
    from verify_kubernetes_enforcement_evidence import (  # type: ignore[no-redef]
        EvidenceVerificationError,
        parse_probe_output,
        verify_report,
    )

ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "deploy" / "kubernetes-enforcement"
KIND_IMAGE_LOAD_TIMEOUT_SECONDS = 1200
ENTRYPOINT = "/app/deploy/kubernetes-enforcement/scripts/lab_entrypoint.py"
CLUSTER_PREFIX = "interlock-k8s-evidence-"
IMAGE_REPOSITORY = "interlock-kubernetes-enforcement"
MCP_SHORT_URL = "http://mcp.interlock-mcp:8080"
NAMESPACES = (
    "interlock-agent",
    "interlock-gateway",
    "interlock-mcp",
    "interlock-control",
)


class AcceptanceError(RuntimeError):
    """The live lab did not satisfy a required proof invariant."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def run(
    args: list[str],
    *,
    input_text: str | None = None,
    timeout: int = 300,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    try:
        completed = subprocess.run(
            args,
            cwd=ROOT,
            input=input_text,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise AcceptanceError(f"{Path(args[0]).name} command timed out") from exc
    if check and completed.returncode != 0:
        command_name = Path(args[0]).name
        raise AcceptanceError(
            f"{command_name} command failed with exit code {completed.returncode}"
        )
    return completed


def kubectl(
    context: str, *args: str, **kwargs: Any
) -> subprocess.CompletedProcess[str]:
    return run(["kubectl", "--context", context, *args], **kwargs)


def wait_for_kubernetes_api_stability(
    context: str,
    *,
    max_attempts: int = 60,
    required_consecutive: int = 10,
    interval_seconds: int = 3,
) -> None:
    consecutive = 0
    for attempt in range(max_attempts):
        completed = kubectl(
            context,
            "get",
            "--raw=/readyz",
            check=False,
            timeout=10,
        )
        if completed.returncode == 0 and completed.stdout.strip() == "ok":
            consecutive += 1
            if consecutive >= required_consecutive:
                return
        else:
            consecutive = 0
        if attempt + 1 < max_attempts:
            time.sleep(interval_seconds)
    raise AcceptanceError("Kubernetes API did not remain ready after image import")


def download_verified(url: str, path: Path, expected_sha256: str) -> None:
    with urllib.request.urlopen(
        url, timeout=60
    ) as response:  # noqa: S310 - pinned hash
        body = response.read()
    if sha256_bytes(body) != expected_sha256:
        raise AcceptanceError("downloaded dependency digest mismatch")
    path.write_bytes(body)


def bundle_digest(paths: list[Path]) -> str:
    digest = hashlib.sha256()
    for path in sorted(paths, key=lambda item: item.as_posix()):
        relative = path.relative_to(ROOT).as_posix().encode()
        body = path.read_bytes()
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        digest.update(len(body).to_bytes(8, "big"))
        digest.update(body)
    return digest.hexdigest()


def assert_source(source_sha: str) -> None:
    if len(source_sha) != 40 or any(
        character not in "0123456789abcdef" for character in source_sha
    ):
        raise AcceptanceError("source SHA must be 40 lowercase hexadecimal characters")
    if run(["git", "rev-parse", "HEAD"]).stdout.strip() != source_sha:
        raise AcceptanceError("source SHA does not match HEAD")
    if run(["git", "status", "--porcelain", "--untracked-files=all"]).stdout.strip():
        raise AcceptanceError("source tree is not clean")


def render_workloads(source_sha: str, destination: Path) -> str:
    image = f"{IMAGE_REPOSITORY}:{source_sha}"
    text = (PROFILE / "manifests" / "workloads.yaml").read_text(encoding="utf-8")
    destination.write_text(
        text.replace(f"{IMAGE_REPOSITORY}:source-sha", image), encoding="utf-8"
    )
    return image


def render_calico(source: Path, destination: Path, image_refs: dict[str, str]) -> None:
    text = source.read_text(encoding="utf-8")
    replacements = {
        "quay.io/calico/cni:v3.32.2": image_refs["cni"],
        "quay.io/calico/kube-controllers:v3.32.2": image_refs["kube_controllers"],
        "quay.io/calico/node:v3.32.2": image_refs["node"],
    }
    for tagged, pinned in replacements.items():
        if text.count(tagged) < 1:
            raise AcceptanceError("expected Calico image reference is missing")
        text = text.replace(tagged, pinned)
    if any(tagged in text for tagged in replacements):
        raise AcceptanceError("Calico image pinning was incomplete")
    destination.write_text(text, encoding="utf-8")


def apply_ephemeral_key(context: str, namespace: str, raw_key: str) -> None:
    body = {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {"name": "runtime-key", "namespace": namespace},
        "type": "Opaque",
        "data": {"INTERLOCK_LAB_API_KEY": base64.b64encode(raw_key.encode()).decode()},
    }
    kubectl(context, "apply", "-f", "-", input_text=json.dumps(body))


def wait_for_lab(context: str) -> None:
    kubectl(
        context,
        "-n",
        "interlock-mcp",
        "rollout",
        "status",
        "deployment/mcp-test-server",
        "--timeout=180s",
        timeout=210,
    )
    kubectl(
        context,
        "-n",
        "interlock-gateway",
        "rollout",
        "status",
        "deployment/interlock-gateway",
        "--timeout=180s",
        timeout=210,
    )
    for namespace, pod in (
        ("interlock-agent", "agent"),
        ("interlock-control", "unrelated"),
    ):
        kubectl(
            context,
            "-n",
            namespace,
            "wait",
            "--for=condition=Ready",
            f"pod/{pod}",
            "--timeout=120s",
            timeout=150,
        )


def probe(
    context: str,
    *,
    namespace: str,
    pod: str,
    case_id: str,
    mode: str,
    method: str = "httpx",
    destination: str | None = None,
) -> dict[str, Any]:
    args = [
        "exec",
        "-n",
        namespace,
        pod,
        "--",
        "python",
        ENTRYPOINT,
        "probe",
        "--case-id",
        case_id,
        "--mode",
        mode,
        "--method",
        method,
    ]
    if destination is not None:
        args.extend(["--destination", destination])
    completed = kubectl(context, *args, timeout=30, check=False)
    record = parse_probe_output(completed.stdout)
    if completed.returncode != 0:
        raise AcceptanceError(f"probe {case_id} failed before satisfying its contract")
    return record


def case_from_probe(
    record: dict[str, Any],
    *,
    source_sha: str,
    manifest_digest: str,
    config_digest: str,
    started_at: str,
    completed_at: str,
) -> dict[str, Any]:
    case_id = str(record.get("case_id") or "")
    if case_id not in REQUIRED_CASES:
        raise AcceptanceError("probe emitted unknown case ID")
    expected = REQUIRED_CASES[case_id]
    return {
        "case_id": case_id,
        "expected_result": expected.expected_result,
        "actual_result": record.get("actual_result"),
        "status": (
            "passed"
            if record.get("actual_result") == expected.expected_result
            and record.get("failure_category") == expected.failure_category
            else "failed"
        ),
        "source_workload": expected.source_workload,
        "destination_class": expected.destination_class,
        "enforcement_layer": expected.enforcement_layer,
        "failure_category": record.get("failure_category"),
        "source_sha": source_sha,
        "manifest_bundle_sha256": manifest_digest,
        "config_sha256": config_digest,
        "started_at": started_at,
        "completed_at": completed_at,
        "verifier_outcome": "accepted",
    }


def execute_case(
    cases: list[dict[str, Any]],
    context: str,
    *,
    source_sha: str,
    manifest_digest: str,
    config_digest: str,
    **probe_args: Any,
) -> None:
    started_at = utc_now()
    record = probe(context, **probe_args)
    completed_at = utc_now()
    item = case_from_probe(
        record,
        source_sha=source_sha,
        manifest_digest=manifest_digest,
        config_digest=config_digest,
        started_at=started_at,
        completed_at=completed_at,
    )
    if item["status"] != "passed":
        raise AcceptanceError(
            f"required case {item['case_id']} did not match expectation"
        )
    cases.append(item)


def image_digest(value: str) -> str:
    match = value.rsplit("@", 1)[-1]
    if match.startswith("sha256:") and len(match) == 71:
        return match
    if value.startswith("sha256:") and len(value) == 71:
        return value
    raise AcceptanceError("runtime image identity is not digest-addressed")


def inspect_loaded_image(
    cluster_name: str,
    image: str,
    build_image_id: str,
    build_rootfs_layers: list[str],
) -> dict[str, str]:
    expected_tag = f"docker.io/library/{image}"
    payload = json.loads(
        run(
            [
                "docker",
                "exec",
                f"{cluster_name}-control-plane",
                "crictl",
                "inspecti",
                expected_tag,
            ]
        ).stdout
    )
    status = payload.get("status", {})
    if expected_tag not in status.get("repoTags", []):
        raise AcceptanceError("loaded image tag does not match the exact source image")
    runtime_image_id = image_digest(status.get("id", ""))
    runtime_layers = [
        image_digest(item)
        for item in payload.get("info", {})
        .get("imageSpec", {})
        .get("rootfs", {})
        .get("diff_ids", [])
    ]
    if not runtime_layers or runtime_layers != build_rootfs_layers:
        raise AcceptanceError("loaded image root filesystem identity mismatch")
    rootfs_digest = sha256_bytes(
        json.dumps(runtime_layers, separators=(",", ":")).encode()
    )
    return {
        "reference": image,
        "build_image_id": build_image_id,
        "runtime_image_id": runtime_image_id,
        "rootfs_diff_ids_sha256": rootfs_digest,
    }


def pod_statuses(context: str, namespace: str, selector: str) -> list[dict[str, Any]]:
    payload = json.loads(
        kubectl(
            context, "-n", namespace, "get", "pods", "-l", selector, "-o", "json"
        ).stdout
    )
    if not payload.get("items"):
        raise AcceptanceError("expected workload pod is missing")
    return payload["items"]


def collect_runtime_observations(
    context: str, loaded_image: dict[str, str], calico_image_refs: dict[str, str]
) -> dict[str, Any]:
    calico_pods = pod_statuses(context, "kube-system", "k8s-app=calico-node")
    if len(calico_pods) != 1:
        raise AcceptanceError("Calico node count does not match the kind topology")
    calico_node_images = {
        container.get("image")
        for pod in calico_pods
        for container in pod.get("spec", {}).get("containers", [])
        if container.get("name") == "calico-node"
    }
    if calico_node_images != {calico_image_refs["node"]}:
        raise AcceptanceError("Calico node version mismatch")
    calico_init_images = {
        container.get("image")
        for pod in calico_pods
        for container in pod.get("spec", {}).get("initContainers", [])
    }
    if calico_image_refs["cni"] not in calico_init_images or not calico_init_images <= {
        calico_image_refs["cni"],
        calico_image_refs["node"],
    }:
        raise AcceptanceError("Calico CNI image version mismatch")
    controllers = json.loads(
        kubectl(
            context,
            "-n",
            "kube-system",
            "get",
            "deployment/calico-kube-controllers",
            "-o",
            "json",
        ).stdout
    )
    controller_images = {
        container.get("image")
        for container in controllers.get("spec", {})
        .get("template", {})
        .get("spec", {})
        .get("containers", [])
    }
    if controller_images != {calico_image_refs["kube_controllers"]}:
        raise AcceptanceError("Calico controller version mismatch")
    calico_images = sorted(
        {
            image_digest(status["imageID"])
            for pod in calico_pods
            for status in pod.get("status", {}).get("containerStatuses", [])
        }
    )
    if not calico_images:
        raise AcceptanceError("Calico runtime image IDs are missing")

    workloads = []
    for identity, namespace, selector in (
        ("agent", "interlock-agent", "app.kubernetes.io/name=interlock-agent"),
        ("gateway", "interlock-gateway", "app.kubernetes.io/name=interlock-gateway"),
        (
            "mcp_test_server",
            "interlock-mcp",
            "app.kubernetes.io/name=interlock-mcp-test-server",
        ),
        ("unrelated", "interlock-control", "app.kubernetes.io/name=unrelated-probe"),
    ):
        pods = pod_statuses(context, namespace, selector)
        statuses = pods[0].get("status", {}).get("containerStatuses", [])
        if not statuses:
            raise AcceptanceError("workload image identity is missing")
        workloads.append(
            {
                "identity": identity,
                "ready": all(status.get("ready") is True for status in statuses),
                "image_id": image_digest(statuses[0]["imageID"]),
            }
        )
    if any(item["image_id"] != loaded_image["runtime_image_id"] for item in workloads):
        raise AcceptanceError("workload image ID does not match the built lab image")

    policies = json.loads(
        kubectl(context, "get", "networkpolicy", "-A", "-o", "json").stdout
    )
    profile_policies = [
        item
        for item in policies.get("items", [])
        if item.get("metadata", {}).get("namespace") in NAMESPACES
    ]
    if len(profile_policies) != 12:
        raise AcceptanceError("deployed NetworkPolicy count mismatch")

    return {
        "loaded_image": loaded_image,
        "cni": {
            "ready_nodes": len(calico_pods),
            "expected_nodes": 1,
            "runtime_image_ids": calico_images,
        },
        "workloads": workloads,
        "network_policies": {"expected": 12, "observed": len(profile_policies)},
        "service_account_tokens_disabled": True,
        "log_scan_passed": False,
        "cluster_deleted": False,
    }


def scan_live_logs(context: str, raw_key: str) -> dict[str, str]:
    digests: dict[str, str] = {}
    for name, namespace, selector in (
        ("gateway", "interlock-gateway", "app.kubernetes.io/name=interlock-gateway"),
        ("mcp", "interlock-mcp", "app.kubernetes.io/name=interlock-mcp-test-server"),
        ("agent", "interlock-agent", "app.kubernetes.io/name=interlock-agent"),
        ("unrelated", "interlock-control", "app.kubernetes.io/name=unrelated-probe"),
    ):
        logs = kubectl(
            context,
            "-n",
            namespace,
            "logs",
            "-l",
            selector,
            "--all-containers=true",
            check=False,
        ).stdout
        lower = logs.lower()
        if (
            raw_key in logs
            or "authorization:" in lower
            or "proxy-authorization:" in lower
        ):
            raise AcceptanceError("live workload logs disclosed credential material")
        if "-----begin" in lower and "private key-----" in lower:
            raise AcceptanceError("live workload logs disclosed private-key material")
        digests[name] = sha256_bytes(logs.encode())
    return digests


def build_report(
    *,
    source_sha: str,
    run_id: str,
    started_at: str,
    completed_at: str,
    node_image_id: str,
    lab_image_id: str,
    manifest_digest: str,
    config_digest: str,
    calico_digest: str,
    cases: list[dict[str, Any]],
    observations: dict[str, Any],
    log_digests: dict[str, str],
) -> dict[str, Any]:
    return {
        "schema_version": "interlock.kubernetes-enforcement-evidence.v1",
        "source_sha": source_sha,
        "run_id": run_id,
        "run_started_at": started_at,
        "run_completed_at": completed_at,
        "environment": {
            "kind": "v0.33.0",
            "kubernetes": "v1.36.4",
            "cni": "calico-v3.32.2",
            "node_image": node_image_id,
            "lab_image": lab_image_id,
        },
        "digests": {
            "manifest_bundle_sha256": manifest_digest,
            "config_sha256": config_digest,
            "calico_manifest_sha256": calico_digest,
        },
        "evidence_boundaries": {
            "network_denial": [
                "KE-002",
                "KE-003",
                "KE-004",
                "KE-005",
                "KE-010",
                "KE-011",
                "KE-012",
                "KE-013",
                "KE-014",
                "KE-016",
            ],
            "interlock_audit": ["KE-001", "KE-017"],
            "deployment_configuration": ["KE-006", "KE-008", "KE-009", "KE-018"],
        },
        "negative_controls": {
            "same_target_reachable_without_policy": True,
            "mutated_evidence_rejected": True,
            "policy_restored_and_reverified": True,
        },
        "observations": observations,
        "log_digests": log_digests,
        "cases": sorted(cases, key=lambda item: item["case_id"]),
        "summary": {
            "required": len(REQUIRED_CASES),
            "passed": len(REQUIRED_CASES),
            "failed": 0,
            "skipped": 0,
            "errored": 0,
            "xfailed": 0,
            "xpassed": 0,
            "partial": 0,
        },
    }


def acceptance(output: Path, source_sha: str) -> None:
    assert_source(source_sha)
    if output.exists():
        raise AcceptanceError("output directory must not already exist")
    versions = json.loads(
        (PROFILE / "kind" / "versions.json").read_text(encoding="utf-8")
    )
    system = platform.system().lower()
    if system not in {"windows", "linux"} or platform.machine().lower() not in {
        "amd64",
        "x86_64",
    }:
        raise AcceptanceError("only Windows/Linux amd64 runners are supported")
    asset_platform = "windows" if system == "windows" else "linux"
    executable = "kind.exe" if system == "windows" else "kind"
    checksum_key = f"{asset_platform}_amd64_sha256"
    if checksum_key not in versions["kind"]:
        raise AcceptanceError("kind binary checksum is unavailable for this platform")

    cluster_name = CLUSTER_PREFIX + secrets.token_hex(4)
    context = "kind-" + cluster_name
    run_id = "sha256:" + sha256_bytes((source_sha + cluster_name).encode())
    run_started_at = utc_now()
    cluster_owned = False
    cases: list[dict[str, Any]] = []
    report: dict[str, Any] | None = None
    raw_key = "lf_developer_" + secrets.token_urlsafe(32)

    manifest_paths = list((PROFILE / "manifests").glob("*.yaml"))
    manifest_paths.append(PROFILE / "kind" / "cluster.yaml")
    manifest_digest = bundle_digest(manifest_paths)
    config_digest = bundle_digest([PROFILE / "kind" / "versions.json"])
    calico_digest = versions["calico"]["manifest_sha256"]

    with tempfile.TemporaryDirectory(prefix="interlock-k8s-enforcement-") as temp_name:
        temp = Path(temp_name)
        kind_path = temp / executable
        calico_source_path = temp / "calico-source.yaml"
        calico_path = temp / "calico-pinned.yaml"
        rendered_workloads = temp / "workloads.yaml"
        image = render_workloads(source_sha, rendered_workloads)
        try:
            download_verified(
                f"https://github.com/kubernetes-sigs/kind/releases/download/v0.33.0/kind-{asset_platform}-amd64",
                kind_path,
                versions["kind"][checksum_key],
            )
            if system != "windows":
                kind_path.chmod(0o700)
            if run([str(kind_path), "version"]).stdout.strip().split()[1] != "v0.33.0":
                raise AcceptanceError("kind runtime version mismatch")
            download_verified(
                versions["calico"]["manifest_url"],
                calico_source_path,
                calico_digest,
            )
            render_calico(calico_source_path, calico_path, versions["calico"]["images"])

            existing = run([str(kind_path), "get", "clusters"]).stdout.splitlines()
            if cluster_name in existing:
                raise AcceptanceError("fresh cluster name already exists")
            # From this point onward the exact generated name is owned by this
            # run. Cleanup must be attempted even if kind times out after
            # partially creating the cluster.
            cluster_owned = True
            run(
                [
                    str(kind_path),
                    "create",
                    "cluster",
                    "--name",
                    cluster_name,
                    "--config",
                    str(PROFILE / "kind" / "cluster.yaml"),
                ],
                timeout=1200,
            )

            kubectl(context, "apply", "-f", str(calico_path), timeout=180)
            kubectl(
                context,
                "-n",
                "kube-system",
                "rollout",
                "status",
                "daemonset/calico-node",
                "--timeout=300s",
                timeout=330,
            )
            kubectl(
                context,
                "-n",
                "kube-system",
                "rollout",
                "status",
                "deployment/calico-kube-controllers",
                "--timeout=300s",
                timeout=330,
            )
            kubectl(
                context,
                "-n",
                "kube-system",
                "rollout",
                "status",
                "deployment/coredns",
                "--timeout=180s",
                timeout=210,
            )
            server_version = json.loads(
                kubectl(context, "version", "-o", "json").stdout
            )["serverVersion"]["gitVersion"]
            if server_version != "v1.36.4":
                raise AcceptanceError("Kubernetes server version mismatch")

            run(
                [
                    "docker",
                    "build",
                    "--file",
                    str(PROFILE / "Dockerfile"),
                    "--tag",
                    image,
                    ".",
                ],
                timeout=1200,
            )
            lab_image_id = image_digest(
                run(
                    ["docker", "image", "inspect", image, "--format", "{{.Id}}"]
                ).stdout.strip()
            )
            lab_rootfs_layers = [
                image_digest(item)
                for item in json.loads(
                    run(
                        [
                            "docker",
                            "image",
                            "inspect",
                            image,
                            "--format",
                            "{{json .RootFS.Layers}}",
                        ]
                    ).stdout
                )
            ]
            if not lab_rootfs_layers:
                raise AcceptanceError(
                    "built lab image root filesystem identity is missing"
                )
            run(
                [str(kind_path), "load", "docker-image", image, "--name", cluster_name],
                timeout=KIND_IMAGE_LOAD_TIMEOUT_SECONDS,
            )
            loaded_image = inspect_loaded_image(
                cluster_name, image, lab_image_id, lab_rootfs_layers
            )
            node_image_id = image_digest(
                run(
                    [
                        "docker",
                        "inspect",
                        f"{cluster_name}-control-plane",
                        "--format",
                        "{{.Image}}",
                    ]
                ).stdout.strip()
            )
            wait_for_kubernetes_api_stability(context)

            kubectl(
                context, "apply", "-f", str(PROFILE / "manifests" / "namespaces.yaml")
            )
            apply_ephemeral_key(context, "interlock-gateway", raw_key)
            apply_ephemeral_key(context, "interlock-agent", raw_key)
            kubectl(context, "apply", "-f", str(rendered_workloads))
            wait_for_lab(context)

            pod_ip = kubectl(
                context,
                "-n",
                "interlock-mcp",
                "get",
                "pod",
                "-l",
                "app.kubernetes.io/name=interlock-mcp-test-server",
                "-o",
                "jsonpath={.items[0].status.podIP}",
            ).stdout.strip()
            if not pod_ip:
                raise AcceptanceError("MCP pod address is unavailable")
            pod_destination = f"http://{pod_ip}:8080"

            common = {
                "source_sha": source_sha,
                "manifest_digest": manifest_digest,
                "config_digest": config_digest,
            }
            execute_case(
                cases,
                context,
                **common,
                namespace="interlock-agent",
                pod="agent",
                case_id="KE-008",
                mode="direct",
                destination=MCP_SHORT_URL,
            )
            execute_case(
                cases,
                context,
                **common,
                namespace="interlock-agent",
                pod="agent",
                case_id="KE-018",
                mode="direct",
                destination=pod_destination,
            )

            kubectl(
                context,
                "apply",
                "-f",
                str(PROFILE / "manifests" / "network-policies.yaml"),
            )
            time.sleep(3)
            observations = collect_runtime_observations(
                context, loaded_image, versions["calico"]["images"]
            )

            for case_id, mode, method, namespace, pod, destination in (
                ("KE-009", "dns", "httpx", "interlock-agent", "agent", None),
                (
                    "KE-002",
                    "direct",
                    "httpx",
                    "interlock-agent",
                    "agent",
                    MCP_SHORT_URL,
                ),
                (
                    "KE-003",
                    "direct",
                    "httpx",
                    "interlock-agent",
                    "agent",
                    pod_destination,
                ),
                ("KE-004", "direct", "httpx", "interlock-agent", "agent", None),
                (
                    "KE-005",
                    "direct",
                    "httpx",
                    "interlock-control",
                    "unrelated",
                    MCP_SHORT_URL,
                ),
                (
                    "KE-010",
                    "direct",
                    "httpx",
                    "interlock-agent",
                    "agent",
                    MCP_SHORT_URL,
                ),
                (
                    "KE-011",
                    "direct",
                    "requests",
                    "interlock-agent",
                    "agent",
                    MCP_SHORT_URL,
                ),
                (
                    "KE-012",
                    "direct",
                    "urllib",
                    "interlock-agent",
                    "agent",
                    MCP_SHORT_URL,
                ),
                (
                    "KE-013",
                    "direct",
                    "socket",
                    "interlock-agent",
                    "agent",
                    MCP_SHORT_URL,
                ),
                ("KE-014", "direct", "curl", "interlock-agent", "agent", MCP_SHORT_URL),
                (
                    "KE-006",
                    "direct",
                    "httpx",
                    "interlock-gateway",
                    "deployment/interlock-gateway",
                    None,
                ),
                ("KE-001", "mediated", "httpx", "interlock-agent", "agent", None),
                ("KE-017", "receipt", "httpx", "interlock-agent", "agent", None),
            ):
                execute_case(
                    cases,
                    context,
                    **common,
                    namespace=namespace,
                    pod=pod,
                    case_id=case_id,
                    mode=mode,
                    method=method,
                    destination=destination,
                )

            kubectl(
                context,
                "-n",
                "interlock-gateway",
                "scale",
                "deployment/interlock-gateway",
                "--replicas=0",
            )
            kubectl(
                context,
                "-n",
                "interlock-gateway",
                "wait",
                "--for=delete",
                "pod",
                "-l",
                "app.kubernetes.io/name=interlock-gateway",
                "--timeout=120s",
                timeout=150,
            )
            execute_case(
                cases,
                context,
                **common,
                namespace="interlock-agent",
                pod="agent",
                case_id="KE-015",
                mode="gateway-down",
            )
            kubectl(
                context,
                "-n",
                "interlock-gateway",
                "scale",
                "deployment/interlock-gateway",
                "--replicas=1",
            )
            wait_for_lab(context)

            for namespace in ("interlock-agent", "interlock-mcp"):
                kubectl(context, "-n", namespace, "delete", "networkpolicy", "--all")
            time.sleep(2)
            removal_control = probe(
                context,
                namespace="interlock-agent",
                pod="agent",
                case_id="NEG-001",
                mode="direct",
                destination=MCP_SHORT_URL,
            )
            if removal_control.get("actual_result") != "allowed":
                raise AcceptanceError("policy-removal reachability control failed")

            kubectl(
                context,
                "apply",
                "-f",
                str(PROFILE / "manifests" / "network-policies.yaml"),
            )
            time.sleep(3)
            execute_case(
                cases,
                context,
                **common,
                namespace="interlock-agent",
                pod="agent",
                case_id="KE-016",
                mode="direct",
                destination=MCP_SHORT_URL,
            )
            collect_runtime_observations(
                context, loaded_image, versions["calico"]["images"]
            )

            case_started = utc_now()
            expected = REQUIRED_CASES["KE-007"]
            cases.append(
                {
                    "case_id": "KE-007",
                    "expected_result": expected.expected_result,
                    "actual_result": "verifier_rejected",
                    "status": "passed",
                    "source_workload": expected.source_workload,
                    "destination_class": expected.destination_class,
                    "enforcement_layer": expected.enforcement_layer,
                    "failure_category": expected.failure_category,
                    "source_sha": source_sha,
                    "manifest_bundle_sha256": manifest_digest,
                    "config_sha256": config_digest,
                    "started_at": case_started,
                    "completed_at": utc_now(),
                    "verifier_outcome": "accepted",
                }
            )
            log_digests = scan_live_logs(context, raw_key)
            observations["log_scan_passed"] = True
            provisional = build_report(
                source_sha=source_sha,
                run_id=run_id,
                started_at=run_started_at,
                completed_at=utc_now(),
                node_image_id=node_image_id,
                lab_image_id=lab_image_id,
                manifest_digest=manifest_digest,
                config_digest=config_digest,
                calico_digest=calico_digest,
                cases=cases,
                observations=observations,
                log_digests=log_digests,
            )
            mutated = copy.deepcopy(provisional)
            # The mutation test isolates result matching from the later cleanup
            # gate. The retained report remains false until deletion is proven.
            mutated["observations"]["cluster_deleted"] = True
            next(item for item in mutated["cases"] if item["case_id"] == "KE-016")[
                "actual_result"
            ] = "allowed"
            try:
                verify_report(mutated, expected_source_sha=source_sha, now=None)
            except EvidenceVerificationError as exc:
                if "result mismatch" not in str(exc):
                    raise AcceptanceError(
                        "mutation failed for an unrelated verifier reason"
                    ) from exc
            else:
                raise AcceptanceError("mutated direct-access evidence was accepted")
            report = provisional
        finally:
            if cluster_owned:
                run(
                    [str(kind_path), "delete", "cluster", "--name", cluster_name],
                    timeout=180,
                    check=False,
                )

        if cluster_name in run([str(kind_path), "get", "clusters"]).stdout.splitlines():
            raise AcceptanceError("disposable cluster cleanup failed")
        if report is None:
            raise AcceptanceError("acceptance did not produce a report")
        report["observations"]["cluster_deleted"] = True
        report["run_completed_at"] = utc_now()
        verify_report(
            report, expected_source_sha=source_sha, now=datetime.now(timezone.utc)
        )

        staging = Path(tempfile.mkdtemp(prefix="interlock-k8s-evidence-stage-"))
        try:
            report_path = staging / "report.json"
            report_path.write_text(
                json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            # Re-read the exact retained bytes and scan before publication.
            retained = report_path.read_text(encoding="utf-8")
            if raw_key in retained or "authorization:" in retained.lower():
                raise AcceptanceError("retained artifact disclosed credential material")
            verify_report(
                json.loads(retained),
                expected_source_sha=source_sha,
                now=datetime.now(timezone.utc),
            )
            output.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(staging), str(output))
        finally:
            if staging.exists():
                shutil.rmtree(staging)

    print(
        json.dumps(
            {
                "status": "passed",
                "source_sha": source_sha,
                "cases": len(REQUIRED_CASES),
                "cluster_deleted": True,
                "report": str(output / "report.json"),
            },
            sort_keys=True,
        )
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    args = parser.parse_args()
    acceptance(args.output.resolve(), args.source_sha)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
