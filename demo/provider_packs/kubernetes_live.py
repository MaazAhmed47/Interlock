"""Credential-gated live Kubernetes/kubectl proof pack for Interlock.

This pack can run against an explicit sandbox Kubernetes context/namespace only
when INTERLOCK_ALLOW_LIVE_KUBERNETES_PROOFS=1 is set. It never uses the current
context implicitly, requires an ``interlock-`` namespace, and stores only hashes
and counts in the report.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Protocol

from core import db
from core import receipt as receipt_builder
from core.chain_drift import build_chain_profile, classify_chain_drift
from core.drift_evidence import canonical_json_bytes
from core.effect_readback import (
    build_readback_state_profile,
    classify_readback_effect_drift,
)

PROVIDER = "kubernetes"
MODE = "credential_gated_kubectl_sandbox"

REQUIREMENTS = [
    "Set INTERLOCK_ALLOW_LIVE_KUBERNETES_PROOFS=1.",
    "Set INTERLOCK_KUBERNETES_CONTEXT to an explicit sandbox context.",
    "Set INTERLOCK_KUBERNETES_NAMESPACE to a namespace starting with interlock-.",
    "Use only a local Docker Desktop/kind/minikube cluster or a tightly scoped sandbox cluster.",
]


class KubernetesExecutionError(RuntimeError):
    """Raised when kubectl fails before drift can be concluded."""


@dataclass(frozen=True)
class LiveKubernetesConfig:
    context: str
    namespace: str
    canary_label: str
    allow_live: bool = False
    kubectl_bin: str = "kubectl"


class LiveKubernetesClient(Protocol):
    provider_kind: str
    provider_name: str

    def prepare(self) -> Dict[str, Any]: ...

    def read_state(self) -> Dict[str, Any]: ...

    def server_dry_run(self, *, mode: str) -> Dict[str, Any]: ...

    def apply_canary(self, *, mode: str) -> Dict[str, Any]: ...

    def delete_canary(self, *, mode: str) -> Dict[str, Any]: ...

    def cleanup(self) -> None: ...


def run_kubernetes_live_proof_pack(
    *,
    client: Optional[LiveKubernetesClient] = None,
    config: Optional[LiveKubernetesConfig] = None,
    env: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Run live Kubernetes/kubectl proof scenarios or return a safe skip."""
    env = dict(os.environ if env is None else env)
    client, config, skip = _resolve_client(client=client, config=config, env=env)
    if skip is not None:
        return skip
    assert client is not None
    assert config is not None

    old_db_path = db.DB_PATH
    tmp_db = tempfile.mktemp(suffix="_kubernetes_live_proof_pack.db")
    db.DB_PATH = tmp_db
    try:
        db.init_db()
        try:
            client.prepare()
            scenarios = [
                _inventory_no_change_control(client, config),
                _server_dry_run_control(client, config),
                _hidden_apply_readback_drift(client, config),
                _expected_apply_allowed_control(client, config),
                _hidden_delete_readback_drift(client, config),
                _secret_read_to_exec_chain_drift(config),
                _inventory_to_delete_namespace_chain_drift(config),
            ]
        finally:
            client.cleanup()
        return {
            "provider": PROVIDER,
            "mode": MODE,
            "live_kubernetes": {
                "provider_kind": "kubernetes",
                "provider_name": "kubectl-sandbox",
                "context_hash": _digest(config.context),
                "namespace_hash": _digest(config.namespace),
                "canary_label_hash": _digest(config.canary_label),
            },
            "summary": {
                "executed": True,
                "status": "executed_live_kubectl_harness",
                "scenario_count": len(scenarios),
                "all_passed": all(bool(scenario.get("ok")) for scenario in scenarios),
            },
            "scenarios": scenarios,
            "requirements": REQUIREMENTS,
            "limitations": _limitations(),
        }
    finally:
        db.DB_PATH = old_db_path
        for suffix in ("", "-wal", "-shm"):
            try:
                os.unlink(tmp_db + suffix)
            except OSError:
                pass


def _resolve_client(
    *,
    client: Optional[LiveKubernetesClient],
    config: Optional[LiveKubernetesConfig],
    env: Dict[str, str],
) -> tuple[
    Optional[LiveKubernetesClient],
    Optional[LiveKubernetesConfig],
    Optional[Dict[str, Any]],
]:
    if client is not None:
        if config is None:
            config = LiveKubernetesConfig(
                context="injected-context",
                namespace="interlock-injected",
                canary_label=_canary_label(env),
                allow_live=True,
            )
        return client, config, None

    if env.get("INTERLOCK_ALLOW_LIVE_KUBERNETES_PROOFS") != "1":
        return None, None, _skip_report("skipped_missing_live_kubernetes_config")
    context = str(env.get("INTERLOCK_KUBERNETES_CONTEXT") or "").strip()
    namespace = str(env.get("INTERLOCK_KUBERNETES_NAMESPACE") or "").strip()
    if not context or not namespace:
        return None, None, _skip_report("skipped_missing_live_kubernetes_config")
    if not namespace.startswith("interlock-"):
        return None, None, _skip_report("skipped_unsafe_namespace")
    kubectl_bin = str(env.get("INTERLOCK_KUBECTL_BIN") or "kubectl").strip()
    kubectl_path = (
        shutil.which(kubectl_bin)
        if os.path.basename(kubectl_bin) == kubectl_bin
        else kubectl_bin
    )
    if not kubectl_path:
        return None, None, _skip_report("skipped_missing_kubectl")

    config = LiveKubernetesConfig(
        context=context,
        namespace=namespace,
        canary_label=_canary_label(env),
        allow_live=True,
        kubectl_bin=kubectl_path,
    )
    return KubectlSandboxClient(config=config), config, None


def _skip_report(status: str) -> Dict[str, Any]:
    return {
        "provider": PROVIDER,
        "mode": MODE,
        "summary": {"executed": False, "status": status, "all_passed": True},
        "scenarios": [],
        "requirements": REQUIREMENTS,
        "limitations": [
            "No Kubernetes cluster was contacted.",
            "No kubectl command was executed.",
            "Set explicit sandbox context/namespace credentials and INTERLOCK_ALLOW_LIVE_KUBERNETES_PROOFS=1 to run a live Kubernetes proof.",
        ],
    }


def _limitations() -> List[str]:
    return [
        "Credential-gated Kubernetes sandbox harness; only run with a local Docker Desktop/kind/minikube or tightly scoped sandbox cluster.",
        "The namespace must start with interlock- and the context must be explicitly configured; the current context is never used implicitly.",
        "Reports store context, namespace, canary labels, and Kubernetes object identities as hashes only.",
        "No kubeconfig contents, service-account token, cluster credential, raw object name, full manifest, or cloud credential is stored.",
        "This proves before/after kubectl readback behavior for the configured sandbox; it is not EKS/GKE/AKS certification and not production-cluster validation.",
        "No cloud provider API is contacted by this harness.",
    ]


def _inventory_no_change_control(
    client: LiveKubernetesClient, config: LiveKubernetesConfig
) -> Dict[str, Any]:
    name = "live_kubectl_inventory_no_change_control"
    try:
        before = build_readback_state_profile(client.read_state())
        after = build_readback_state_profile(client.read_state())
    except KubernetesExecutionError as exc:
        return _provider_error_scenario(name=name, exc=exc)
    decision = classify_readback_effect_drift(
        before_profile=before,
        after_profile=after,
        target_response={"read_only": True, "preview": True},
        expected_effect="no_change",
    )
    return _scenario(
        name=name,
        expected_ok=not decision["drift_detected"] and decision["action"] == "allow",
        decision=decision,
        receipt=None,
    )


def _server_dry_run_control(
    client: LiveKubernetesClient, config: LiveKubernetesConfig
) -> Dict[str, Any]:
    name = "live_kubectl_server_dry_run_control"
    try:
        before = build_readback_state_profile(client.read_state())
        target = client.server_dry_run(mode="server-dry-run")
        after = build_readback_state_profile(client.read_state())
    except KubernetesExecutionError as exc:
        return _provider_error_scenario(name=name, exc=exc)
    decision = classify_readback_effect_drift(
        before_profile=before,
        after_profile=after,
        target_response=target,
        expected_effect="no_change",
    )
    return _scenario(
        name=name,
        expected_ok=not decision["drift_detected"] and decision["action"] == "allow",
        decision=decision,
        receipt=None,
    )


def _hidden_apply_readback_drift(
    client: LiveKubernetesClient, config: LiveKubernetesConfig
) -> Dict[str, Any]:
    name = "live_kubectl_hidden_apply_readback_drift"
    try:
        before_state = client.read_state()
        before = build_readback_state_profile(before_state)
        client.apply_canary(mode="hidden-apply")
        after_state = client.read_state()
        after = build_readback_state_profile(after_state)
    except KubernetesExecutionError as exc:
        return _provider_error_scenario(name=name, exc=exc)
    decision = classify_readback_effect_drift(
        before_profile=before,
        after_profile=after,
        target_response={"dry_run": True, "preview": True, "would_apply": 1},
        expected_effect="no_change",
    )
    receipt = _readback_receipt(
        name=name,
        tool_name="kubectl_apply",
        decision=decision,
        before_hash=decision["before_state_hash"],
        after_hash=decision["after_state_hash"],
    )
    return _scenario(
        name=name,
        expected_ok=(
            decision["severity"] == "critical"
            and decision["action"] == "quarantine"
            and "silent_side_effect_drift" in decision["types"]
            and "effect_response_contradicted_by_readback" in decision["types"]
        ),
        decision=decision,
        receipt=receipt,
        readback=_readback_counts(before_state, after_state),
    )


def _expected_apply_allowed_control(
    client: LiveKubernetesClient, config: LiveKubernetesConfig
) -> Dict[str, Any]:
    name = "live_kubectl_expected_apply_allowed_control"
    try:
        before_state = client.read_state()
        before = build_readback_state_profile(before_state)
        target = client.apply_canary(mode="expected-apply")
        after_state = client.read_state()
        after = build_readback_state_profile(after_state)
    except KubernetesExecutionError as exc:
        return _provider_error_scenario(name=name, exc=exc)
    decision = classify_readback_effect_drift(
        before_profile=before,
        after_profile=after,
        target_response=target,
        expected_effect="change_allowed",
    )
    return _scenario(
        name=name,
        expected_ok=not decision["drift_detected"] and decision["action"] == "allow",
        decision=decision,
        receipt=None,
        readback=_readback_counts(before_state, after_state),
    )


def _hidden_delete_readback_drift(
    client: LiveKubernetesClient, config: LiveKubernetesConfig
) -> Dict[str, Any]:
    name = "live_kubectl_hidden_delete_readback_drift"
    try:
        if int(client.read_state().get("resource_count") or 0) == 0:
            client.apply_canary(mode="delete-seed")
        before_state = client.read_state()
        before = build_readback_state_profile(before_state)
        client.delete_canary(mode="hidden-delete")
        after_state = client.read_state()
        after = build_readback_state_profile(after_state)
    except KubernetesExecutionError as exc:
        return _provider_error_scenario(name=name, exc=exc)
    decision = classify_readback_effect_drift(
        before_profile=before,
        after_profile=after,
        target_response={"dry_run": True, "preview": True, "would_delete": 1},
        expected_effect="no_change",
    )
    receipt = _readback_receipt(
        name=name,
        tool_name="kubectl_delete",
        decision=decision,
        before_hash=decision["before_state_hash"],
        after_hash=decision["after_state_hash"],
    )
    return _scenario(
        name=name,
        expected_ok=(
            decision["severity"] == "critical"
            and decision["action"] == "quarantine"
            and "silent_side_effect_drift" in decision["types"]
        ),
        decision=decision,
        receipt=receipt,
        readback=_readback_counts(before_state, after_state),
    )


def _secret_read_to_exec_chain_drift(config: LiveKubernetesConfig) -> Dict[str, Any]:
    name = "live_kubectl_secret_read_to_exec_chain_drift"
    steps = [
        {
            "server_id": "kubernetes-live",
            "tool_name": "get_secret",
            "arguments": {"secret": "pod-token-secret"},
            "effects": ["read"],
            "data_classes": ["secret", "credential", "token"],
            "externality": "internal",
        },
        {
            "server_id": "kubernetes-live",
            "tool_name": "pod_exec",
            "arguments": {"pod": "pod-token-secret", "command": "cluster-admin-secret"},
            "effects": ["executed"],
            "data_classes": ["infra"],
            "externality": "internal",
        },
    ]
    profile = build_chain_profile(steps, chain_id="live-kubernetes-secret-to-exec")
    decision = classify_chain_drift(steps)
    receipt = _chain_receipt(name=name, decision=decision, profile=profile)
    return _scenario(
        name=name,
        expected_ok=(
            decision["severity"] == "critical"
            and decision["action"] == "deny"
            and "chain_secret_to_execution" in decision["types"]
        ),
        decision=decision,
        receipt=receipt,
    )


def _inventory_to_delete_namespace_chain_drift(
    config: LiveKubernetesConfig,
) -> Dict[str, Any]:
    name = "live_kubectl_inventory_to_delete_namespace_chain_drift"
    steps = [
        {
            "server_id": "kubernetes-live",
            "tool_name": "list_pods",
            "arguments": {"namespace": "prod-namespace-secret"},
            "effects": ["preview", "read"],
            "data_classes": ["infra"],
            "externality": "internal",
        },
        {
            "server_id": "kubernetes-live",
            "tool_name": "delete_namespace",
            "arguments": {"namespace": "prod-namespace-secret"},
            "effects": ["deleted", "destroyed"],
            "data_classes": ["infra"],
            "externality": "internal",
        },
    ]
    profile = build_chain_profile(steps, chain_id="live-kubernetes-inventory-delete")
    decision = classify_chain_drift(steps)
    receipt = _chain_receipt(name=name, decision=decision, profile=profile)
    return _scenario(
        name=name,
        expected_ok=(
            decision["severity"] == "critical"
            and decision["action"] == "deny"
            and "chain_preview_to_destructive" in decision["types"]
        ),
        decision=decision,
        receipt=receipt,
    )


def _provider_error_scenario(
    *, name: str, exc: KubernetesExecutionError
) -> Dict[str, Any]:
    return {
        "name": name,
        "ok": False,
        "drift_detected": False,
        "severity": "inconclusive",
        "decision": "monitor",
        "finding_types": ["provider_probe_error"],
        "reason": "Kubernetes provider call failed before drift could be concluded.",
        "provider_error": _safe_provider_error(exc),
    }


def _scenario(
    *,
    name: str,
    expected_ok: bool,
    decision: Dict[str, Any],
    receipt: Optional[Dict[str, Any]],
    readback: Optional[Dict[str, int]] = None,
) -> Dict[str, Any]:
    out = {
        "name": name,
        "ok": bool(expected_ok),
        "drift_detected": bool(decision.get("drift_detected")),
        "severity": decision.get("severity") or "none",
        "decision": decision.get("action") or "allow",
        "finding_types": list(decision.get("types") or []),
        "reason": decision.get("reason") or _first(decision.get("reasons") or []),
    }
    if "before_state_hash" in decision:
        out["before_state_hash"] = decision.get("before_state_hash") or ""
        out["after_state_hash"] = decision.get("after_state_hash") or ""
    if readback is not None:
        out["readback"] = readback
    if receipt is not None:
        out["receipt"] = receipt
    return out


def _readback_counts(before: Dict[str, Any], after: Dict[str, Any]) -> Dict[str, int]:
    return {
        "before_resource_count": int(before.get("resource_count") or 0),
        "after_resource_count": int(after.get("resource_count") or 0),
    }


def _readback_receipt(
    *,
    name: str,
    tool_name: str,
    decision: Dict[str, Any],
    before_hash: str,
    after_hash: str,
) -> Dict[str, Any]:
    row = db.log_mcp_audit_event(
        {
            "server_id": "kubernetes-live-proof-pack",
            "tool_name": tool_name,
            "role": "operator",
            "action": decision["action"],
            "matched_rule": "effect_readback_observer",
            "reason": decision["reason"],
            "verification_level": "live_kubectl_sandbox_readback",
            "confidence": 0.95,
            "warnings": ["kubernetes_live_provider_proof_pack", "kubectl_sandbox"],
            "argument_keys": [],
            "blocked_by": "effect_readback_observer",
            "probe_id": name,
            "argument_hash": "sha256:" + "6" * 64,
            "expected_outcome": "no_change",
            "observed_outcome": "state_changed",
            "drift_status": "readback_effect_drift",
            "drift_severity": decision["severity"],
            "drift_action": decision["action"],
            "drift_types": decision["types"],
            "drift_reasons": decision["reasons"],
            "drift_baseline_hash": before_hash,
            "drift_current_hash": after_hash,
        }
    )
    return receipt_builder.build_receipt(row, chain_verified=True)


def _chain_receipt(
    *, name: str, decision: Dict[str, Any], profile: Dict[str, Any]
) -> Dict[str, Any]:
    row = db.log_mcp_audit_event(
        {
            "server_id": "multi-step-chain",
            "tool_name": name,
            "role": "operator",
            "action": decision["action"],
            "matched_rule": "chain_drift",
            "reason": decision["reason"],
            "effects": profile["effect_classes"],
            "side_effect": "chain",
            "data_classes": profile["data_classes"],
            "externality": (
                "external" if "external" in profile["externalities"] else "internal"
            ),
            "verification_level": "live_kubectl_chain_analysis",
            "confidence": 0.95,
            "warnings": [
                "kubernetes_live_provider_proof_pack",
                "pre_execution_chain_analysis",
            ],
            "argument_keys": [],
            "blocked_by": "chain_drift",
            "probe_id": name,
            "argument_hash": profile["argument_hash"],
            "expected_outcome": "chain_allowed",
            "observed_outcome": "chain_denied",
            "drift_status": "chain_drift",
            "drift_severity": decision["severity"],
            "drift_action": decision["action"],
            "drift_types": decision["types"],
            "drift_reasons": decision["reasons"],
            "drift_current_hash": profile["profile_hash"],
        }
    )
    return receipt_builder.build_receipt(row, chain_verified=True)


class KubectlSandboxClient:
    provider_kind = "kubernetes"
    provider_name = "kubectl-sandbox"

    def __init__(self, *, config: LiveKubernetesConfig) -> None:
        self.config = config
        self.created_names: List[str] = []
        self.namespace_created = False

    def prepare(self) -> Dict[str, Any]:
        if (
            not self._run(
                ["get", "namespace", self.config.namespace], check=False
            ).returncode
            == 0
        ):
            self._run(["create", "namespace", self.config.namespace])
        return {"prepared": True, "namespace_hash": _digest(self.config.namespace)}

    def read_state(self) -> Dict[str, Any]:
        proc = self._run(
            [
                "get",
                "configmaps",
                "-n",
                self.config.namespace,
                "-l",
                "app.kubernetes.io/part-of=interlock-proof",
                "-o",
                "json",
            ]
        )
        try:
            payload = json.loads(proc.stdout or "{}")
        except json.JSONDecodeError as exc:
            raise KubernetesExecutionError("kubectl_json_decode_error") from exc
        items = list(payload.get("items") or [])
        item_material = []
        for item in items:
            metadata = dict(item.get("metadata") or {})
            item_material.append(
                {
                    "kind": item.get("kind") or "",
                    "name": metadata.get("name") or "",
                    "uid": metadata.get("uid") or "",
                    "resource_version": metadata.get("resourceVersion") or "",
                }
            )
        return {
            "resource_count": len(item_material),
            "objects": [{"digest": _digest(value)} for value in item_material],
        }

    def server_dry_run(self, *, mode: str) -> Dict[str, Any]:
        manifest = self._manifest(mode=mode)
        self._run(
            ["apply", "--dry-run=server", "-f", "-", "-o", "json"], stdin=manifest
        )
        return {"dry_run": True, "preview": True, "would_apply": 1}

    def apply_canary(self, *, mode: str) -> Dict[str, Any]:
        manifest = self._manifest(mode=mode)
        self._run(["apply", "-f", "-"], stdin=manifest)
        name = self._object_name(mode)
        if name not in self.created_names:
            self.created_names.append(name)
        return {"applied": True, "object_hash": _digest(name)}

    def delete_canary(self, *, mode: str) -> Dict[str, Any]:
        if self.created_names:
            name = self.created_names.pop()
            self._run(
                [
                    "delete",
                    "configmap",
                    name,
                    "-n",
                    self.config.namespace,
                    "--ignore-not-found=true",
                ]
            )
            return {"deleted": True, "object_hash": _digest(name)}
        self._run(
            [
                "delete",
                "configmap",
                "-l",
                "app.kubernetes.io/part-of=interlock-proof",
                "-n",
                self.config.namespace,
                "--ignore-not-found=true",
            ]
        )
        return {"deleted": True, "object_hash": _digest("label-delete")}

    def cleanup(self) -> None:
        try:
            self._run(
                [
                    "delete",
                    "configmap",
                    "-l",
                    "app.kubernetes.io/part-of=interlock-proof",
                    "-n",
                    self.config.namespace,
                    "--ignore-not-found=true",
                ],
                check=False,
            )
        except KubernetesExecutionError:
            pass
        if self.namespace_created:
            try:
                self._run(
                    [
                        "delete",
                        "namespace",
                        self.config.namespace,
                        "--ignore-not-found=true",
                    ],
                    check=False,
                )
            except KubernetesExecutionError:
                pass

    def _manifest(self, *, mode: str) -> str:
        name = self._object_name(mode)
        label = _safe_label_value(self.config.canary_label)
        return json.dumps(
            {
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": {
                    "name": name,
                    "namespace": self.config.namespace,
                    "labels": {
                        "app.kubernetes.io/part-of": "interlock-proof",
                        "interlock.dev/canary": label,
                    },
                },
                "data": {"proof": "interlock", "mode": mode},
            }
        )

    def _object_name(self, mode: str) -> str:
        safe_mode = _safe_k8s_name(mode)
        safe_label = _safe_k8s_name(self.config.canary_label)
        digest = _digest({"label": self.config.canary_label, "mode": mode})[-8:]
        return f"interlock-{safe_label[:20]}-{safe_mode[:18]}-{digest}"[:63].strip("-")

    def _run(
        self, args: List[str], *, stdin: Optional[str] = None, check: bool = True
    ) -> subprocess.CompletedProcess[str]:
        cmd = [
            self.config.kubectl_bin,
            "--context",
            self.config.context,
            *args,
        ]
        proc = subprocess.run(
            cmd,
            input=stdin,
            text=True,
            capture_output=True,
            check=False,
        )
        if check and proc.returncode != 0:
            raise KubernetesExecutionError(
                f"kubectl_error:{_safe_error_token(proc.stderr or proc.stdout)}"
            )
        return proc


def _canary_label(env: Dict[str, str]) -> str:
    return str(
        env.get("INTERLOCK_KUBERNETES_CANARY_LABEL")
        or f"interlock-k8s-canary-{int(time.time())}"
    )


def _safe_k8s_name(value: str) -> str:
    value = str(value or "interlock").lower()
    value = re.sub(r"[^a-z0-9-]+", "-", value).strip("-")
    return value or "interlock"


def _safe_label_value(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9_.-]+", "-", str(value or "interlock"))
    return value[:63].strip(".-_") or "interlock"


def _safe_error_token(value: str) -> str:
    value = str(value or "kubectl_error").strip().splitlines()[0][:120]
    allowed = set(
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_:-./ "
    )
    return "".join(ch if ch in allowed else "_" for ch in value) or "kubectl_error"


def _safe_provider_error(exc: KubernetesExecutionError) -> str:
    return _safe_error_token(str(exc))


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _first(values: List[str]) -> str:
    return values[0] if values else ""


def print_report(report: Dict[str, Any]) -> None:
    print(f"Kubernetes live proof pack ({report['mode']})")
    summary = report.get("summary") or {}
    if not summary.get("executed"):
        print(f"SKIP {summary.get('status')}")
        for item in report.get("limitations") or []:
            print(f"- {item}")
        return
    for scenario in report["scenarios"]:
        status = "PASS" if scenario["ok"] else "FAIL"
        findings = ",".join(scenario.get("finding_types") or []) or "none"
        provider_error = scenario.get("provider_error")
        suffix = f" provider_error={provider_error}" if provider_error else ""
        print(
            f"{status} {scenario['name']} severity={scenario['severity']} "
            f"decision={scenario['decision']} findings={findings}{suffix}"
        )
    print("Limitations:")
    for item in report["limitations"]:
        print(f"- {item}")


if __name__ == "__main__":  # pragma: no cover
    print_report(run_kubernetes_live_proof_pack())
